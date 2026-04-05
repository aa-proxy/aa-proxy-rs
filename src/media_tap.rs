use simplelog::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use protobuf::Enum;

use crate::mitm::protos;
use crate::mitm::protos::{AudioStreamType, DisplayType, MediaCodecType};
use crate::mitm::{Packet, ProxyType, FRAME_TYPE_FIRST, FRAME_TYPE_LAST, FRAME_TYPE_MASK};
use crate::mpegts::{MpegTsState, TsStreamKind};

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
    /// Cached video state used to serve a recent keyframe immediately to new clients.
    cached_video: Arc<tokio::sync::Mutex<CachedVideoState>>,
    /// Stream metadata learned from ServiceDiscovery.
    stream_info: Arc<tokio::sync::Mutex<Option<MediaStreamInfo>>>,
}

#[derive(Default)]
struct CachedVideoState {
    pending_pts_us: Option<u64>,
    pending_au: Vec<u8>,
    last_idr: Option<Arc<(u64, Vec<u8>)>>,
}

impl MediaSink {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            codec_cfg: Arc::new(tokio::sync::Mutex::new(None)),
            cached_video: Arc::new(tokio::sync::Mutex::new(CachedVideoState::default())),
            stream_info: Arc::new(tokio::sync::Mutex::new(None)),
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
        let is_video = matches!(
            self.get_stream_info().await,
            Some(MediaStreamInfo {
                kind: MediaStreamKind::Video { .. },
                ..
            })
        );

        if is_video {
            let mut cached = self.cached_video.lock().await;
            if cached.pending_pts_us == Some(pts_us) {
                cached.pending_au.extend_from_slice(&data);
            } else {
                if let Some(prev_pts_us) = cached.pending_pts_us.replace(pts_us) {
                    let au = std::mem::take(&mut cached.pending_au);
                    if is_idr_frame(&au) {
                        cached.last_idr = Some(Arc::new((prev_pts_us, au)));
                    }
                }
                cached.pending_au.extend_from_slice(&data);
            }
        }

        let _ = self.tx.send(Arc::new((pts_us, data)));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<(u64, Vec<u8>)>> {
        self.tx.subscribe()
    }

    pub async fn get_codec_cfg(&self) -> Option<Arc<Vec<u8>>> {
        self.codec_cfg.lock().await.clone()
    }

    pub async fn get_cached_idr(&self) -> Option<Arc<(u64, Vec<u8>)>> {
        self.cached_video.lock().await.last_idr.clone()
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
        0x00,
        0x00,
        0x00, // no emphasis/mute/current-frame flags
        header4,
        0x80, // required by VLC's VobHeader() frame-sync check
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
            Some(data.chunks_exact(3).flat_map(|c| [c[2], c[1], c[0]]).collect())
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
pub async fn media_tcp_server(
    port: u16,
    label: String,
    sink: MediaSink,
    wait_for_live_idr: bool,
) {
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
                    let stream_info = {
                        let mut info = sink.get_stream_info().await;
                        if info.is_none() {
                            let null_pkt = MpegTsState::null_packet();
                            let mut ticker = tokio::time::interval(
                                std::time::Duration::from_millis(200),
                            );
                            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                            let deadline = tokio::time::Instant::now()
                                + std::time::Duration::from_secs(30);
                            loop {
                                ticker.tick().await;
                                if stream.write_all(&null_pkt).await.is_err() {
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
                        if stream.write_all(&psi).await.is_err() {
                            return;
                        }
                        let mut rx = sink.subscribe();
                        let mut psi_ticker = tokio::time::interval(std::time::Duration::from_secs(2));
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
                                            let Some(ts_data) = prepare_ts_audio_data(&stream_info, data) else {
                                                warn!(
                                                    "media_tcp_server: {addr} ({label}) missing audio config for codec {}",
                                                    audio_codec_name(codec)
                                                );
                                                continue;
                                            };
                                            let pkts = ts.audio_pes(pts_us, &ts_data);
                                            if stream.write_all(&pkts).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(broadcast::error::RecvError::Lagged(n)) => {
                                            warn!(
                                                "media_tcp_server: {addr} ({label}) lagged by {n} frames"
                                            );
                                        }
                                        Err(broadcast::error::RecvError::Closed) => break,
                                    }
                                }
                                _ = psi_ticker.tick() => {
                                    let psi = ts.pat_pmt();
                                    if stream.write_all(&psi).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        info!("<green>media_tcp_server</>: client disconnected {addr} ({label})");
                        return;
                    }

                    info!("<green>media_tcp_server</>: client connected {addr} ({label})");
                    let mut rx = sink.subscribe();
                    let mut ts = MpegTsState::new();
                    let mut pending_pts_us: Option<u64> = None;
                    let mut pending_au = Vec::new();

                    let initial_psi = ts.pat_pmt();
                    if stream.write_all(&initial_psi).await.is_err() {
                        return;
                    }

                    let mut synced = false;
                    if let Some(cached_idr) = sink.get_cached_idr().await {
                        let (pts_us, idr_au) = &*cached_idr;
                        let idr_payload = if let Some(cfg) = sink.get_codec_cfg().await {
                            let mut v = Vec::with_capacity(cfg.len() + idr_au.len());
                            v.extend_from_slice(&cfg);
                            v.extend_from_slice(idr_au);
                            v
                        } else {
                            idr_au.clone()
                        };
                        let psi = ts.pat_pmt();
                        if stream.write_all(&psi).await.is_err() {
                            return;
                        }
                        let pkts = ts.video_pes(*pts_us, &idr_payload, true);
                        if stream.write_all(&pkts).await.is_err() {
                            return;
                        }
                        if wait_for_live_idr {
                            info!(
                                "media_tcp_server: {addr} ({label}) seeded from cached IDR preview, waiting for fresh live IDR"
                            );
                        } else {
                            synced = true;
                            info!(
                                "media_tcp_server: {addr} ({label}) seeded from cached IDR and starting in low-latency mode"
                            );
                        }
                    }

                    let null_pkt = MpegTsState::null_packet();
                    let mut null_ticker = tokio::time::interval(std::time::Duration::from_millis(100));
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
                                        if pending_pts_us == Some(pts_us) {
                                            pending_au.extend_from_slice(data);
                                        } else {
                                            if let Some(flush_pts_us) = pending_pts_us.replace(pts_us) {
                                                let access_unit = std::mem::take(&mut pending_au);
                                                let is_idr = is_idr_frame(&access_unit);
                                                if !synced && is_idr {
                                                    synced = true;
                                                    debug!(
                                                        "media_tcp_server: {addr} ({label}) IDR sync'd, streaming MPEG-TS"
                                                    );
                                                }

                                                if synced && is_idr {
                                                    let psi = ts.pat_pmt();
                                                    if stream.write_all(&psi).await.is_err() {
                                                        break;
                                                    }

                                                    let idr_payload = if let Some(cfg) = sink.get_codec_cfg().await {
                                                        let mut v = Vec::with_capacity(cfg.len() + access_unit.len());
                                                        v.extend_from_slice(&cfg);
                                                        v.extend_from_slice(&access_unit);
                                                        v
                                                    } else {
                                                        access_unit
                                                    };
                                                    let pkts = ts.video_pes(flush_pts_us, &idr_payload, true);
                                                    if stream.write_all(&pkts).await.is_err() {
                                                        break;
                                                    }
                                                } else if synced {
                                                    let pkts = ts.video_pes(flush_pts_us, &access_unit, false);
                                                    if stream.write_all(&pkts).await.is_err() {
                                                        break;
                                                    }
                                                }
                                            }

                                            pending_au.extend_from_slice(data);
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        warn!(
                                            "media_tcp_server: client {addr} ({label}) lagged by {n} frames, re-syncing"
                                        );
                                        synced = false;
                                        pending_pts_us = None;
                                        pending_au.clear();
                                    }
                                    Err(broadcast::error::RecvError::Closed) => break,
                                }
                            }
                            _ = null_ticker.tick(), if !synced => {
                                if stream.write_all(&null_pkt).await.is_err() {
                                    break;
                                }
                                let psi = ts.pat_pmt();
                                if stream.write_all(&psi).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    info!("<green>media_tcp_server</>: client disconnected {addr} ({label})");
                });
            }
            Err(e) => {
                error!("<red>media_tcp_server</>: accept error on port {port}: {e}");
            }
        }
    }
}

/// Scan all NAL units in an Annex-B buffer looking for IDR (type 5).
/// Returns true if any NAL unit in the buffer is an IDR slice.
/// Handles access units that begin with AUD (type 9) or SEI (type 6)
/// before the IDR, which is common in Android Auto H.264 streams.
pub(crate) fn is_idr_frame(data: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            let (sc_len, nal_off) = if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1
            {
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
                        info!(
                            "{} <blue>media tap IDR</> ch {:#04x}: pts={}us, {} nal bytes, first: {:02X?}",
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