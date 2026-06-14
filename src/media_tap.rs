use protobuf::Enum;
use simplelog::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};

use crate::mitm::protos;
use crate::mitm::protos::{AudioStreamType, DisplayType, MediaCodecType};
use crate::mitm::{Packet, ProxyType, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};
use crate::mpegts::{MpegTsState, TsStreamKind};

/// Capacity (in queued MPEG-TS write buffers) of the per-client local write
/// queue. Decouples broadcast consumption from the TCP write to the client,
/// so a momentarily slow socket write doesn't cause this client to fall
/// behind on the shared broadcast channel and trigger a full resync.
const CLIENT_WRITE_QUEUE_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug)]
pub struct AudioStreamConfig {
    pub sample_rate: u32,
    pub channels: u32,
    pub bits: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum MediaStreamKind {
    Video {
        codec: MediaCodecType,
        display_type: DisplayType,
    },
    Audio {
        codec: MediaCodecType,
        audio_type: AudioStreamType,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct MediaStreamInfo {
    pub kind: MediaStreamKind,
    pub audio_config: Option<AudioStreamConfig>,
}

/// Broadcast-based sink for tapping a single media channel over TCP.
#[derive(Clone)]
pub struct MediaSink {
    /// Each broadcast item is `(pts_us, data)`. For codec-config frames the
    /// pts_us field is 0 and `codec_cfg` is also populated.
    tx: broadcast::Sender<Arc<(u64, Vec<u8>)>>,
    /// Cached codec config frame sent to every new client on connect.
    codec_cfg: Arc<tokio::sync::Mutex<Option<Arc<Vec<u8>>>>>,
    /// Most recently seen IDR access unit (pts_us, raw Annex-B data), used to
    /// bootstrap a client straight back into sync after a resync instead of
    /// waiting for the next naturally-occurring IDR.
    last_idr: Arc<tokio::sync::Mutex<Option<Arc<(u64, Vec<u8>)>>>>,
    /// Stream metadata learned from ServiceDiscovery.
    stream_info: Arc<tokio::sync::Mutex<Option<MediaStreamInfo>>>,
    /// Monotonic counter bumped each time a TCP client connects to this sink.
    client_connect_gen: Arc<AtomicU64>,
}

impl MediaSink {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            codec_cfg: Arc::new(tokio::sync::Mutex::new(None)),
            last_idr: Arc::new(tokio::sync::Mutex::new(None)),
            stream_info: Arc::new(tokio::sync::Mutex::new(None)),
            client_connect_gen: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn set_video_stream_info(&self, codec: MediaCodecType, display_type: DisplayType) {
        *self.stream_info.lock().await = Some(MediaStreamInfo {
            kind: MediaStreamKind::Video {
                codec,
                display_type,
            },
            audio_config: None,
        });
    }

    pub async fn set_audio_stream_info(
        &self,
        codec: MediaCodecType,
        audio_type: AudioStreamType,
        audio_config: Option<AudioStreamConfig>,
    ) {
        *self.stream_info.lock().await = Some(MediaStreamInfo {
            kind: MediaStreamKind::Audio { codec, audio_type },
            audio_config,
        });
    }

    pub async fn get_stream_info(&self) -> Option<MediaStreamInfo> {
        *self.stream_info.lock().await
    }

    pub async fn send_codec_config(&self, data: Vec<u8>) {
        let buf = Arc::new(data);
        *self.codec_cfg.lock().await = Some(buf.clone());
        let _ = self.tx.send(Arc::new((0u64, buf.as_ref().clone())));
    }

    pub async fn send_frame(&self, pts_us: u64, data: Vec<u8>) {
        let _ = self.tx.send(Arc::new((pts_us, data)));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<(u64, Vec<u8>)>> {
        self.tx.subscribe()
    }

    pub fn has_subscribers(&self) -> bool {
        self.tx.receiver_count() > 0
    }

    pub fn note_client_connected(&self) {
        self.client_connect_gen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn client_connect_generation(&self) -> u64 {
        self.client_connect_gen.load(Ordering::Relaxed)
    }

    pub async fn get_codec_cfg(&self) -> Option<Arc<Vec<u8>>> {
        self.codec_cfg.lock().await.clone()
    }

    pub async fn set_last_idr(&self, pts_us: u64, access_unit: Vec<u8>) {
        *self.last_idr.lock().await = Some(Arc::new((pts_us, access_unit)));
    }

    pub async fn get_last_idr(&self) -> Option<Arc<(u64, Vec<u8>)>> {
        self.last_idr.lock().await.clone()
    }
}

fn audio_codec_name(codec: MediaCodecType) -> &'static str {
    match codec {
        MediaCodecType::MEDIA_CODEC_AUDIO_PCM => "pcm",
        MediaCodecType::MEDIA_CODEC_AUDIO_AAC_LC => "aac-lc",
        MediaCodecType::MEDIA_CODEC_AUDIO_AAC_LC_ADTS => "aac-lc-adts",
        MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP => "h264",
        MediaCodecType::MEDIA_CODEC_VIDEO_VP9 => "vp9",
        MediaCodecType::MEDIA_CODEC_VIDEO_AV1 => "av1",
        MediaCodecType::MEDIA_CODEC_VIDEO_H265 => "h265",
    }
}

fn aac_sample_rate_index(sample_rate: u32) -> Option<u8> {
    match sample_rate {
        96000 => Some(0),
        88200 => Some(1),
        64000 => Some(2),
        48000 => Some(3),
        44100 => Some(4),
        32000 => Some(5),
        24000 => Some(6),
        22050 => Some(7),
        16000 => Some(8),
        12000 => Some(9),
        11025 => Some(10),
        8000 => Some(11),
        7350 => Some(12),
        _ => None,
    }
}

fn build_adts_header(frame_len: usize, sample_rate: u32, channels: u32) -> Option<[u8; 7]> {
    let sampling_frequency_index = aac_sample_rate_index(sample_rate)?;
    if channels > 7 {
        return None;
    }

    let full_len = frame_len + 7;
    if full_len > 0x1FFF {
        return None;
    }

    let profile = 1u8; // AAC LC => profile 2, encoded as profile - 1
    let channel_config = channels as u8;

    Some([
        0xFF,
        0xF1,
        (profile << 6) | (sampling_frequency_index << 2) | ((channel_config >> 2) & 0x01),
        ((channel_config & 0x03) << 6) | (((full_len >> 11) as u8) & 0x03),
        ((full_len >> 3) & 0xFF) as u8,
        (((full_len & 0x07) as u8) << 5) | 0x1F,
        0xFC,
    ])
}

fn dvd_lpcm_rate_code(sample_rate: u32) -> Option<u8> {
    match sample_rate {
        48_000 => Some(0x0),
        96_000 => Some(0x1),
        44_100 => Some(0x2),
        32_000 => Some(0x3),
        _ => None,
    }
}

fn dvd_lpcm_bits_code(bits: u32) -> Option<u8> {
    match bits {
        16 => Some(0x0),
        // 20/24-bit DVD LPCM use special packing which we do not currently emit.
        _ => None,
    }
}

/// Build a 6-byte DVD LPCM header expected by VLC's VOB LPCM parser.
fn build_dvd_lpcm_header(cfg: AudioStreamConfig) -> Option<[u8; 6]> {
    if cfg.channels == 0 || cfg.channels > 8 {
        return None;
    }
    let rate = dvd_lpcm_rate_code(cfg.sample_rate)?;
    let bits = dvd_lpcm_bits_code(cfg.bits)?;
    let chm1 = (cfg.channels - 1) as u8;
    let header4 = (bits << 6) | (rate << 4) | (chm1 & 0x07);
    Some([
        0x01, // number of frames in packet
        0x00, 0x00, 0x00, // no emphasis/mute/current-frame flags
        header4, 0x80, // required by VLC's VobHeader() frame-sync check
    ])
}

fn pcm_to_big_endian_samples(data: &[u8], bits: u32) -> Option<Vec<u8>> {
    match bits {
        16 => {
            if data.len() % 2 != 0 {
                return None;
            }
            Some(data.chunks_exact(2).flat_map(|c| [c[1], c[0]]).collect())
        }
        24 => {
            if data.len() % 3 != 0 {
                return None;
            }
            Some(
                data.chunks_exact(3)
                    .flat_map(|c| [c[2], c[1], c[0]])
                    .collect(),
            )
        }
        _ => None,
    }
}

/// Returns a player hint string for the given stream, suitable for logging.
fn audio_client_hint(stream_info: &MediaStreamInfo, port: u16) -> String {
    match stream_info.kind {
        MediaStreamKind::Audio {
            codec: MediaCodecType::MEDIA_CODEC_AUDIO_PCM,
            ..
        } => {
            format!(
                "ffplay tcp://127.0.0.1:{port}  (or: vlc --codec=lpcm_audio tcp://127.0.0.1:{port})"
            )
        }
        MediaStreamKind::Audio { .. } => {
            format!("vlc tcp://127.0.0.1:{port}  (or: ffplay tcp://127.0.0.1:{port})")
        }
        MediaStreamKind::Video { .. } => format!(
            "vlc --avcodec-hw=none --demux ts tcp://127.0.0.1:{port}  (or: ffplay tcp://127.0.0.1:{port})"
        ),
    }
}

/// Prepare audio payload data for MPEG-TS muxing.
///
/// - PCM: prepend a DVD LPCM header and convert samples to big-endian.
/// - AAC_LC_ADTS: pass through (already has ADTS framing).
/// - AAC_LC: prepend a synthesised ADTS header.
/// - Other: returns `None` (unsupported codec).
fn prepare_ts_audio_data(stream_info: &MediaStreamInfo, data: &[u8]) -> Option<Vec<u8>> {
    match stream_info.kind {
        MediaStreamKind::Audio {
            codec: MediaCodecType::MEDIA_CODEC_AUDIO_PCM,
            ..
        } => {
            let cfg = stream_info.audio_config?;
            let header = build_dvd_lpcm_header(cfg)?;
            let samples = pcm_to_big_endian_samples(data, cfg.bits)?;
            let mut out = Vec::with_capacity(header.len() + samples.len());
            out.extend_from_slice(&header);
            out.extend_from_slice(&samples);
            Some(out)
        }
        MediaStreamKind::Audio {
            codec: MediaCodecType::MEDIA_CODEC_AUDIO_AAC_LC_ADTS,
            ..
        } => Some(data.to_vec()),
        MediaStreamKind::Audio {
            codec: MediaCodecType::MEDIA_CODEC_AUDIO_AAC_LC,
            ..
        } => {
            let cfg = stream_info.audio_config?;
            let header = build_adts_header(data.len(), cfg.sample_rate, cfg.channels)?;
            let mut out = Vec::with_capacity(header.len() + data.len());
            out.extend_from_slice(&header);
            out.extend_from_slice(data);
            Some(out)
        }
        _ => None,
    }
}

/// TCP server for one media channel tap. Binds on `0.0.0.0:port`.
/// All streams (both audio and video) are delivered as MPEG-TS.
/// If ServiceDiscovery has not yet completed when a client connects, the server
/// keeps the connection alive with TS null packets until stream info arrives.
pub async fn media_tcp_server(port: u16, label: String, sink: MediaSink, _wait_for_live_idr: bool) {
    let listener = match TcpListener::bind(format!("0.0.0.0:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            error!("<red>media_tcp_server</>: failed to bind port {port} for {label}: {e}");
            return;
        }
    };
    info!(
        "<green>media_tcp_server</>: <b>{label}</> listening on port <b>{port}</>  →  vlc tcp://127.0.0.1:{port}  (or: ffplay tcp://127.0.0.1:{port})"
    );

    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                let sink = sink.clone();
                let label = label.clone();
                tokio::spawn(async move {
                    let connected_at = Instant::now();

                    // Dedicated writer task: all TCP writes to this client go
                    // through this queue, so a slow/blocking socket write
                    // never delays draining the broadcast channel.
                    let (tx_out, mut rx_out) = mpsc::channel::<Vec<u8>>(CLIENT_WRITE_QUEUE_CAPACITY);
                    let writer_addr = addr;
                    let writer_label = label.clone();
                    tokio::spawn(async move {
                        while let Some(buf) = rx_out.recv().await {
                            let write_started = Instant::now();
                            if stream.write_all(&buf).await.is_err() {
                                break;
                            }
                            let write_elapsed = write_started.elapsed();
                            if write_elapsed > Duration::from_millis(250) {
                                warn!(
                                    "media_tcp_server: {writer_addr} ({writer_label}) write_all took {}ms ({} bytes) - client read side may be stalled",
                                    write_elapsed.as_millis(),
                                    buf.len()
                                );
                            }
                        }
                    });

                    let stream_info = {
                        let mut info = sink.get_stream_info().await;
                        if info.is_none() {
                            let null_pkt = MpegTsState::null_packet().to_vec();
                            let mut ticker =
                                tokio::time::interval(std::time::Duration::from_millis(200));
                            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                            let deadline =
                                tokio::time::Instant::now() + std::time::Duration::from_secs(30);
                            loop {
                                ticker.tick().await;
                                if tx_out.send(null_pkt.clone()).await.is_err() {
                                    return;
                                }
                                info = sink.get_stream_info().await;
                                if info.is_some() {
                                    break;
                                }
                                if tokio::time::Instant::now() >= deadline {
                                    warn!(
                                        "<yellow>media_tcp_server</>: {addr} ({label}) timed out waiting for ServiceDiscovery"
                                    );
                                    return;
                                }
                            }
                        }
                        info.unwrap()
                    };

                    if let MediaStreamKind::Audio { codec, .. } = stream_info.kind {
                        sink.note_client_connected();
                        let ts_kind = match codec {
                            MediaCodecType::MEDIA_CODEC_AUDIO_PCM => TsStreamKind::AudioPcm,
                            _ => TsStreamKind::AudioAacAdts,
                        };
                        let mut ts = MpegTsState::new_for_kind(ts_kind);
                        info!(
                            "<green>media_tcp_server</>: client connected {addr} ({label}) as <b>{}</> (MPEG-TS)  →  {}",
                            audio_codec_name(codec),
                            audio_client_hint(&stream_info, port)
                        );
                        let psi = ts.pat_pmt();
                        if tx_out.send(psi).await.is_err() {
                            return;
                        }
                        let mut rx = sink.subscribe();
                        let mut first_audio_frame_at: Option<Instant> = None;
                        let mut lag_events: u64 = 0;
                        let mut lagged_frames: u64 = 0;
                        let mut write_lag_events: u64 = 0;
                        let mut psi_ticker =
                            tokio::time::interval(std::time::Duration::from_secs(2));
                        psi_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        psi_ticker.tick().await;
                        loop {
                            tokio::select! {
                                biased;
                                item = rx.recv() => {
                                    match item {
                                        Ok(item) => {
                                            let (pts_us, ref data) = *item;
                                            if pts_us == 0 {
                                                continue;
                                            }
                                            if first_audio_frame_at.is_none() {
                                                first_audio_frame_at = Some(Instant::now());
                                                info!(
                                                    "media_tcp_server: {addr} ({label}) first audio frame after {}ms",
                                                    connected_at.elapsed().as_millis()
                                                );
                                            }
                                            let Some(ts_data) = prepare_ts_audio_data(&stream_info, data) else {
                                                warn!(
                                                    "media_tcp_server: {addr} ({label}) missing audio config for codec {}",
                                                    audio_codec_name(codec)
                                                );
                                                continue;
                                            };
                                            let pkts = ts.audio_pes(pts_us, &ts_data);
                                            match tx_out.try_send(pkts) {
                                                Ok(()) => {}
                                                Err(mpsc::error::TrySendError::Full(_)) => {
                                                    write_lag_events = write_lag_events.saturating_add(1);
                                                    warn!(
                                                        "media_tcp_server: {addr} ({label}) write queue full, dropping audio frame (write_lag_events={write_lag_events})"
                                                    );
                                                }
                                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                                            }
                                        }
                                        Err(broadcast::error::RecvError::Lagged(n)) => {
                                            lag_events = lag_events.saturating_add(1);
                                            lagged_frames = lagged_frames.saturating_add(n as u64);
                                            warn!(
                                                "media_tcp_server: {addr} ({label}) lagged by {n} audio frames (events={}, total_frames={})",
                                                lag_events,
                                                lagged_frames
                                            );
                                        }
                                        Err(broadcast::error::RecvError::Closed) => break,
                                    }
                                }
                                _ = psi_ticker.tick() => {
                                    let psi = ts.pat_pmt();
                                    match tx_out.try_send(psi) {
                                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                                    }
                                }
                            }
                        }
                        info!(
                            "media_tcp_server: {addr} ({label}) audio summary: lived={}ms first_frame={}ms lag_events={} lagged_frames={} write_lag_events={}",
                            connected_at.elapsed().as_millis(),
                            first_audio_frame_at
                                .map(|t| t.duration_since(connected_at).as_millis().to_string())
                                .unwrap_or_else(|| "none".to_string()),
                            lag_events,
                            lagged_frames,
                            write_lag_events
                        );
                        info!("<green>media_tcp_server</>: client disconnected {addr} ({label})");
                        return;
                    }

                    sink.note_client_connected();
                    info!("<green>media_tcp_server</>: client connected {addr} ({label})");
                    let mut rx = sink.subscribe();
                    let mut ts = MpegTsState::new();
                    let mut pending_pts_us: Option<u64> = None;
                    let mut pending_au = Vec::new();
                    let mut first_video_frame_at: Option<Instant> = None;
                    let mut first_idr_seen_at: Option<Instant> = None;
                    let mut first_output_at: Option<Instant> = None;
                    let mut lag_events: u64 = 0;
                    let mut lagged_frames: u64 = 0;
                    let mut sync_resets: u64 = 0;
                    let mut unsynced_access_units: u64 = 0;
                    let mut write_lag_events: u64 = 0;
                    let mut missing_codec_cfg_warned = false;
                    let mut pending_resync_payload: Option<Vec<u8>> = None;

                    let initial_psi = ts.pat_pmt();
                    if tx_out.send(initial_psi).await.is_err() {
                        return;
                    }

                    // Gate output on the first live IDR.
                    // Without this, real video frames flow into VLC's probe phase. By the
                    // time VLC finishes probing and starts playing, those frames have PTS
                    // values that are now in the past on VLC's clock, causing them to be
                    // dropped as late. Null packets fill the probe window harmlessly.
                    // Non-IDR frames before an IDR cannot be decoded anyway.
                    let mut synced = false;
                    info!(
                        "media_tcp_server: {addr} ({label}) connected; waiting for first live IDR"
                    );

                    let null_pkt = MpegTsState::null_packet().to_vec();
                    let mut null_ticker =
                        tokio::time::interval(std::time::Duration::from_millis(100));
                    null_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                    loop {
                        tokio::select! {
                            biased;
                            item = rx.recv() => {
                                match item {
                                    Ok(item) => {
                                        let (pts_us, ref data) = *item;
                                        if pts_us == 0 {
                                            continue;
                                        }
                                            if first_video_frame_at.is_none() {
                                                first_video_frame_at = Some(Instant::now());
                                                info!(
                                                    "media_tcp_server: {addr} ({label}) first video frame after {}ms",
                                                    connected_at.elapsed().as_millis()
                                                );
                                            }
                                        if pending_pts_us == Some(pts_us) {
                                            pending_au.extend_from_slice(data);
                                        } else {
                                            if let Some(flush_pts_us) = pending_pts_us.replace(pts_us) {
                                                let access_unit = std::mem::take(&mut pending_au);
                                                let is_idr = is_idr_frame(&access_unit);

                                                if is_idr {
                                                    sink.set_last_idr(flush_pts_us, access_unit.clone()).await;
                                                    if first_idr_seen_at.is_none() {
                                                        first_idr_seen_at = Some(Instant::now());
                                                        info!(
                                                            "media_tcp_server: {addr} ({label}) first live IDR observed after {}ms",
                                                            connected_at.elapsed().as_millis()
                                                        );
                                                    }
                                                }

                                                if !synced {
                                                    if is_idr {
                                                        synced = true;
                                                        let codec_cfg_len = sink.get_codec_cfg().await.map(|cfg| cfg.len());
                                                        info!(
                                                            "media_tcp_server: {addr} ({label}) IDR sync'd after {}ms, streaming MPEG-TS (codec_cfg={}{}).",
                                                            connected_at.elapsed().as_millis(),
                                                            if codec_cfg_len.is_some() { "yes" } else { "no" },
                                                            codec_cfg_len
                                                                .map(|len| format!(", {} bytes", len))
                                                                .unwrap_or_default()
                                                        );
                                                        if codec_cfg_len.is_none() {
                                                            warn!(
                                                                "media_tcp_server: {addr} ({label}) no cached codec config at sync; decoder startup may stall until in-band SPS/PPS appears"
                                                            );
                                                            missing_codec_cfg_warned = true;
                                                        }
                                                    } else {
                                                        unsynced_access_units = unsynced_access_units.saturating_add(1);
                                                        if unsynced_access_units <= 4 || unsynced_access_units % 32 == 0 {
                                                            info!(
                                                                "media_tcp_server: {addr} ({label}) withholding unsynced AU #{} ({} bytes), waiting for IDR",
                                                                unsynced_access_units,
                                                                access_unit.len()
                                                            );
                                                        }
                                                    }
                                                }

                                                if synced {
                                                    let mut out = if is_idr {
                                                        ts.pat_pmt()
                                                    } else {
                                                        Vec::new()
                                                    };

                                                    if is_idr {
                                                        let idr_payload = if let Some(cfg) = sink.get_codec_cfg().await {
                                                            let mut v =
                                                                Vec::with_capacity(cfg.len() + access_unit.len());
                                                            v.extend_from_slice(&cfg);
                                                            v.extend_from_slice(&access_unit);
                                                            v
                                                        } else {
                                                            if !missing_codec_cfg_warned {
                                                                warn!(
                                                                    "media_tcp_server: {addr} ({label}) emitting IDR without codec config; decoder may stay black until SPS/PPS is seen"
                                                                );
                                                                missing_codec_cfg_warned = true;
                                                            }
                                                            access_unit
                                                        };
                                                        out.extend_from_slice(&ts.video_pes(flush_pts_us, &idr_payload, true));
                                                    } else {
                                                        out = ts.video_pes(flush_pts_us, &access_unit, false);
                                                    }

                                                    match tx_out.try_send(out) {
                                                        Ok(()) => {
                                                            if first_output_at.is_none() {
                                                                first_output_at = Some(Instant::now());
                                                                info!(
                                                                    "media_tcp_server: {addr} ({label}) first video output after {}ms",
                                                                    connected_at.elapsed().as_millis()
                                                                );
                                                            }
                                                        }
                                                        Err(mpsc::error::TrySendError::Full(_)) => {
                                                            write_lag_events = write_lag_events.saturating_add(1);
                                                            sync_resets = sync_resets.saturating_add(1);
                                                            warn!(
                                                                "media_tcp_server: {addr} ({label}) write queue full, dropping frame and re-syncing (write_lag_events={write_lag_events})"
                                                            );
                                                            synced = false;
                                                            ts = MpegTsState::new(); // reset PTS baseline on resync
                                                            pending_resync_payload = build_resync_payload(&sink, &mut ts).await;
                                                        }
                                                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                                                    }
                                                }
                                            }

                                            pending_au.extend_from_slice(data);
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                            lag_events = lag_events.saturating_add(1);
                                            lagged_frames = lagged_frames.saturating_add(n as u64);
                                        warn!(
                                            "media_tcp_server: client {addr} ({label}) lagged by {n} video frames, re-syncing (events={}, total_frames={}, lived={}ms)",
                                            lag_events,
                                            lagged_frames,
                                            connected_at.elapsed().as_millis()
                                        );
                                        sync_resets = sync_resets.saturating_add(1);
                                        synced = false;
                                        ts = MpegTsState::new(); // reset PTS baseline on resync
                                        pending_resync_payload = build_resync_payload(&sink, &mut ts).await;
                                        pending_pts_us = None;
                                        pending_au.clear();
                                    }
                                    Err(broadcast::error::RecvError::Closed) => break,
                                }
                            }
                            _ = null_ticker.tick(), if !synced => {
                                if let Some(payload) = pending_resync_payload.take() {
                                    match tx_out.try_send(payload) {
                                        Ok(()) => {
                                            synced = true;
                                            info!(
                                                "media_tcp_server: {addr} ({label}) resynced from cached IDR after {}ms",
                                                connected_at.elapsed().as_millis()
                                            );
                                        }
                                        Err(mpsc::error::TrySendError::Full(payload)) => {
                                            pending_resync_payload = Some(payload);
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                                    }
                                } else {
                                    match tx_out.try_send(null_pkt.clone()) {
                                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                                    }
                                }
                            }
                        }
                    }
                    info!(
                        "media_tcp_server: {addr} ({label}) video summary: lived={}ms first_frame={}ms first_live_idr={}ms first_output={}ms lag_events={} lagged_frames={} write_lag_events={} sync_resets={} unsynced_au={} wait_for_live_idr={}",
                        connected_at.elapsed().as_millis(),
                        first_video_frame_at
                            .map(|t| t.duration_since(connected_at).as_millis().to_string())
                            .unwrap_or_else(|| "none".to_string()),
                        first_idr_seen_at
                            .map(|t| t.duration_since(connected_at).as_millis().to_string())
                            .unwrap_or_else(|| "none".to_string()),
                        first_output_at
                            .map(|t| t.duration_since(connected_at).as_millis().to_string())
                            .unwrap_or_else(|| "none".to_string()),
                        lag_events,
                        lagged_frames,
                        write_lag_events,
                        sync_resets,
                        unsynced_access_units,
                        false
                    );
                    info!("<green>media_tcp_server</>: client disconnected {addr} ({label})");
                });
            }
            Err(e) => {
                error!("<red>media_tcp_server</>: accept error on port {port}: {e}");
            }
        }
    }
}

/// Build a PAT/PMT + codec_cfg + IDR payload from the sink's cached IDR, to
/// bootstrap a resyncing client back into sync immediately instead of
/// waiting for the next naturally-occurring IDR. Returns `None` if no IDR
/// has been cached yet (e.g. before the first live IDR on this sink).
async fn build_resync_payload(sink: &MediaSink, ts: &mut MpegTsState) -> Option<Vec<u8>> {
    let cached = sink.get_last_idr().await?;
    let (pts_us, ref au) = *cached;
    let mut out = ts.pat_pmt();
    let payload = if let Some(cfg) = sink.get_codec_cfg().await {
        let mut v = Vec::with_capacity(cfg.len() + au.len());
        v.extend_from_slice(&cfg);
        v.extend_from_slice(au);
        v
    } else {
        au.clone()
    };
    out.extend_from_slice(&ts.video_pes(pts_us, &payload, true));
    Some(out)
}

/// Scan all NAL units in an Annex-B buffer looking for IDR (type 5).
/// Returns true if any NAL unit in the buffer is an IDR slice.
/// Handles access units that begin with AUD (type 9) or SEI (type 6)
/// before the IDR, which is common in Android Auto H.264 streams.
pub(crate) fn is_idr_frame(data: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            let (sc_len, nal_off) = if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                (4usize, i + 4)
            } else if data[i + 2] == 1 {
                (3usize, i + 3)
            } else {
                i += 1;
                continue;
            };
            if nal_off >= data.len() {
                break;
            }
            let nal_type = data[nal_off] & 0x1F;
            match nal_type {
                5 => return true,
                1 => return false,
                _ => {}
            }
            i = nal_off + 1;
            let _ = sc_len;
        } else {
            i += 1;
        }
    }
    false
}

#[derive(Default)]
pub(crate) struct MediaFrameBuffer {
    pub(crate) expected_len: Option<usize>,
    pub(crate) data: Vec<u8>,
}

fn tap_name(proxy_type: ProxyType) -> &'static str {
    match proxy_type {
        ProxyType::HeadUnit => "mitm/HU",
        ProxyType::MobileDevice => "mitm/MD",
    }
}

pub(crate) fn reassemble_media_packet(
    media_fragments: &mut HashMap<u8, MediaFrameBuffer>,
    pkt: &Packet,
) -> Option<Vec<u8>> {
    match pkt.flags & FRAME_TYPE_MASK {
        flags if flags == (FRAME_TYPE_FIRST | FRAME_TYPE_LAST) => {
            // Do not drop an in-progress fragmented message when a standalone
            // packet appears on the same channel; AA can interleave control
            // packets and fragmented media payloads.
            Some(pkt.payload.clone())
        }
        flags if flags == FRAME_TYPE_FIRST => {
            if media_fragments
                .insert(
                    pkt.channel,
                    MediaFrameBuffer {
                        expected_len: pkt.final_length.map(|len| len as usize),
                        data: pkt.payload.clone(),
                    },
                )
                .is_some()
            {
                warn!(
                    "media tap: replacing incomplete fragmented frame on channel {:#04x}",
                    pkt.channel
                );
            }
            None
        }
        flags if flags == FRAME_TYPE_LAST => {
            let mut assembled = match media_fragments.remove(&pkt.channel) {
                Some(buffer) => buffer,
                None => {
                    warn!(
                        "media tap: dropping trailing fragment without start on channel {:#04x}",
                        pkt.channel
                    );
                    return None;
                }
            };
            assembled.data.extend_from_slice(&pkt.payload);
            if let Some(expected_len) = assembled.expected_len {
                if assembled.data.len() != expected_len {
                    warn!(
                        "media tap: dropping fragmented frame on channel {:#04x}, expected {} bytes but reassembled {}",
                        pkt.channel,
                        expected_len,
                        assembled.data.len()
                    );
                    return None;
                }
            }
            Some(assembled.data)
        }
        _ => {
            let Some(buffer) = media_fragments.get_mut(&pkt.channel) else {
                warn!(
                    "media tap: dropping middle fragment without start on channel {:#04x}",
                    pkt.channel
                );
                return None;
            };
            buffer.data.extend_from_slice(&pkt.payload);
            None
        }
    }
}

pub(crate) async fn tap_media_message(
    proxy_type: ProxyType,
    pkt: &Packet,
    sink: &MediaSink,
    frame_data: &[u8],
) {
    let message_id = ((frame_data[0] as u16) << 8 | frame_data[1] as u16) as i32;
    let stream_info = sink.get_stream_info().await;
    let is_audio = matches!(
        stream_info,
        Some(MediaStreamInfo {
            kind: MediaStreamKind::Audio { .. },
            ..
        })
    );
    let Some(media_message) = protos::MediaMessageId::from_i32(message_id) else {
        debug!(
            "{} media tap ignoring unknown media message id 0x{:04X} on ch {:#04x}",
            tap_name(proxy_type),
            message_id as u16,
            pkt.channel
        );
        return;
    };

    match media_message {
        protos::MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG => {
            if is_audio {
                debug!(
                    "{} media tap CODEC_CONFIG (audio Config proto) ch {:#04x}: {} bytes",
                    tap_name(proxy_type),
                    pkt.channel,
                    frame_data.len() - 2
                );
            } else {
                let codec_data = &frame_data[2..];
                info!(
                    "{} <blue>media tap CODEC_CONFIG</> ch {:#04x}: {} bytes, bytes: {:02X?}",
                    tap_name(proxy_type),
                    pkt.channel,
                    codec_data.len(),
                    &codec_data[..codec_data.len().min(32)]
                );
                sink.send_codec_config(codec_data.to_vec()).await;
            }
        }
        protos::MediaMessageId::MEDIA_MESSAGE_DATA => {
            const TIMESTAMP_HEADER: usize = 8;
            let payload = &frame_data[2..];
            if payload.len() > TIMESTAMP_HEADER {
                let pts_us = u64::from_be_bytes(payload[..TIMESTAMP_HEADER].try_into().unwrap());
                let media_data = &payload[TIMESTAMP_HEADER..];
                if is_audio {
                    debug!(
                        "{} audio tap DATA ch {:#04x}: pts={}us, {} bytes",
                        tap_name(proxy_type),
                        pkt.channel,
                        pts_us,
                        media_data.len()
                    );
                    sink.send_frame(pts_us, media_data.to_vec()).await;
                } else {
                    let idr = is_idr_frame(media_data);
                    if idr {
                        debug!(
                            "{} <blue>media tap:</> received IDR from phone on ch {:#04x}: pts={}us, {} nal bytes, first: {:02X?}",
                            tap_name(proxy_type),
                            pkt.channel,
                            pts_us,
                            media_data.len(),
                            &media_data[..media_data.len().min(16)]
                        );
                    } else {
                        debug!(
                            "{} media tap DATA ch {:#04x}: pts={}us, {}b, first: {:02X?}",
                            tap_name(proxy_type),
                            pkt.channel,
                            pts_us,
                            media_data.len(),
                            &media_data[..media_data.len().min(8)]
                        );
                    }
                    sink.send_frame(pts_us, media_data.to_vec()).await;
                }
            }
        }
        _ => {}
    }
}
