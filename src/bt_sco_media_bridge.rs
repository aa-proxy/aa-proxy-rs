use crate::bt_sco;
use crate::config::BtScoMediaBridgeLimiter;
use crate::mitm::protos::{
    ChannelOpenResponse, Config as AudioConfig, MediaMessageId, Start, Stop,
};
use crate::mitm::{Packet, ENCRYPTED, FRAME_TYPE_FIRST, FRAME_TYPE_LAST};
use protobuf::Message;
use simplelog::*;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;

const NAME: &str = "<i><bright-black> bt-sco-media: </>";
const BRIDGE_THREAD_NAME: &str = "bt-sco-media-piggyback";
const IDLE_SLEEP: Duration = Duration::from_millis(5);
const NO_TARGET_SLEEP: Duration = Duration::from_millis(100);
const WAIT_LOG_INTERVAL: Duration = Duration::from_secs(10);
const MIC_REQUEST_LOG_INTERVAL: Duration = Duration::from_secs(5);
const MIC_REQUEST_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const SEND_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_SESSION_ID: i32 = 0x5343_4f02; // "SCO\x02"
const DEFAULT_FIXED_CADENCE_MS: u32 = 0; // 0 = pace by the audio duration of each packet
const DEFAULT_JITTER_BUFFER_MS: u32 = 60;
const DEFAULT_AUDIO_PEAK_THRESHOLD: u32 = 64;
const DEFAULT_START_TIMEOUT_MS: u32 = 1500;

/// bt_sco_media_bridge_start_on_timeout: when false, the bridge never sends MEDIA_MESSAGE_START just
/// because `start_timeout_ms` elapsed with a silent SCO downlink (e.g. voice recording, which opens
/// SCO but carries no far-end audio); it waits for real audio. Avoids hijacking the media channel
/// (music) with silence and a later STOP. Set once at startup from the config.
pub static START_ON_TIMEOUT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

struct Runtime {
    tx: Mutex<Option<Sender<Packet>>>,

    // Downlink: SCO call audio -> existing AA media sink DATA.
    target_channel: AtomicU8,
    target_epoch: AtomicU64,
    target_sample_rate: AtomicU32,
    target_channels: AtomicU32,
    target_bits: AtomicU32,
    output_gain_percent: AtomicU32,
    output_limiter: AtomicU8,
    fixed_cadence: AtomicBool,
    cadence_ms: AtomicU32,
    jitter_buffer_ms: AtomicU32,
    start_existing: AtomicBool,
    start_on_first_audio: AtomicBool,
    audio_peak_threshold: AtomicU32,
    start_timeout_ms: AtomicU32,
    stop_existing_on_disconnect: AtomicBool,
    config_channel: AtomicU8,
    config_epoch: AtomicU64,
    configuration_index: AtomicU32,
    max_unacked: AtomicU32,

    // Uplink: HU microphone media_source -> SCO socket.
    mic_channel: AtomicU8,
    mic_sample_rate: AtomicU32,
    mic_channels: AtomicU32,
    mic_bits: AtomicU32,
    mic_epoch: AtomicU64,
    mic_request_enabled: AtomicBool,
    mic_open_sco_generation: AtomicU64,
    mic_open: AtomicBool,
}

static RUNTIME: OnceLock<Arc<Runtime>> = OnceLock::new();

pub fn init_or_update(tx: Sender<Packet>) {
    if let Some(runtime) = RUNTIME.get() {
        *runtime.tx.lock().unwrap() = Some(tx);
        return;
    }

    let runtime = Arc::new(Runtime {
        tx: Mutex::new(Some(tx)),
        target_channel: AtomicU8::new(0),
        target_epoch: AtomicU64::new(0),
        target_sample_rate: AtomicU32::new(48_000),
        target_channels: AtomicU32::new(2),
        target_bits: AtomicU32::new(16),
        output_gain_percent: AtomicU32::new(100),
        output_limiter: AtomicU8::new(BtScoMediaBridgeLimiter::Off.as_u8()),
        fixed_cadence: AtomicBool::new(false),
        cadence_ms: AtomicU32::new(DEFAULT_FIXED_CADENCE_MS),
        jitter_buffer_ms: AtomicU32::new(DEFAULT_JITTER_BUFFER_MS),
        start_existing: AtomicBool::new(false),
        start_on_first_audio: AtomicBool::new(false),
        audio_peak_threshold: AtomicU32::new(DEFAULT_AUDIO_PEAK_THRESHOLD),
        start_timeout_ms: AtomicU32::new(DEFAULT_START_TIMEOUT_MS),
        stop_existing_on_disconnect: AtomicBool::new(false),
        config_channel: AtomicU8::new(0),
        config_epoch: AtomicU64::new(0),
        configuration_index: AtomicU32::new(0),
        max_unacked: AtomicU32::new(0),
        mic_channel: AtomicU8::new(0),
        mic_sample_rate: AtomicU32::new(0),
        mic_channels: AtomicU32::new(0),
        mic_bits: AtomicU32::new(0),
        mic_epoch: AtomicU64::new(0),
        mic_request_enabled: AtomicBool::new(false),
        mic_open_sco_generation: AtomicU64::new(0),
        mic_open: AtomicBool::new(false),
    });

    let thread_runtime = runtime.clone();
    match thread::Builder::new()
        .name(BRIDGE_THREAD_NAME.to_string())
        .spawn(move || bridge_loop(thread_runtime))
    {
        Ok(_) => info!("{} piggyback media bridge worker started", NAME),
        Err(e) => warn!(
            "{} failed to start piggyback media bridge worker: {}",
            NAME, e
        ),
    }

    let _ = RUNTIME.set(runtime);
}

pub fn set_target_channel(
    channel: u8,
    sample_rate: u32,
    channels: u32,
    bits: u32,
    gain_percent: u32,
    limiter: BtScoMediaBridgeLimiter,
    start_existing: bool,
    start_on_first_audio: bool,
    audio_peak_threshold: u32,
    start_timeout_ms: u32,
    stop_existing_on_disconnect: bool,
    fixed_cadence: bool,
    cadence_ms: u32,
    jitter_buffer_ms: u32,
) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };

    let previous = runtime.target_channel.swap(channel, Ordering::SeqCst);
    let epoch = runtime.target_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    runtime
        .target_sample_rate
        .store(sample_rate.max(1), Ordering::SeqCst);
    runtime
        .target_channels
        .store(channels.max(1), Ordering::SeqCst);
    runtime.target_bits.store(bits, Ordering::SeqCst);
    runtime
        .output_gain_percent
        .store(gain_percent.max(1), Ordering::SeqCst);
    runtime
        .output_limiter
        .store(limiter.as_u8(), Ordering::SeqCst);
    runtime
        .start_on_first_audio
        .store(start_on_first_audio, Ordering::SeqCst);
    runtime
        .audio_peak_threshold
        .store(audio_peak_threshold, Ordering::SeqCst);
    runtime
        .start_timeout_ms
        .store(start_timeout_ms.max(1), Ordering::SeqCst);
    runtime.fixed_cadence.store(fixed_cadence, Ordering::SeqCst);
    runtime.cadence_ms.store(cadence_ms, Ordering::SeqCst);
    runtime
        .jitter_buffer_ms
        .store(jitter_buffer_ms, Ordering::SeqCst);
    runtime
        .start_existing
        .store(start_existing, Ordering::SeqCst);
    runtime
        .stop_existing_on_disconnect
        .store(stop_existing_on_disconnect, Ordering::SeqCst);
    runtime.config_channel.store(0, Ordering::SeqCst);
    runtime.config_epoch.store(0, Ordering::SeqCst);
    runtime.configuration_index.store(0, Ordering::SeqCst);
    runtime.max_unacked.store(0, Ordering::SeqCst);

    if previous != channel {
        debug!(
            "{} selected existing AA PCM sink channel=<b>{:#04x}</>, {}Hz, {}ch, {}bit, gain={}%, limiter={}, start_existing={}, start_on_first_audio={}, peak_threshold={}, start_timeout={}ms, stop_on_disconnect={}, fixed_cadence={}ms/{}, jitter_buffer={}ms, epoch={}; will piggyback DATA only",
            NAME, channel, sample_rate, channels, bits, gain_percent, limiter, start_existing, start_on_first_audio, audio_peak_threshold, start_timeout_ms.max(1), stop_existing_on_disconnect, cadence_ms, fixed_cadence, jitter_buffer_ms, epoch
        );
    } else {
        debug!(
            "{} re-armed existing AA PCM sink channel=<b>{:#04x}</>, {}Hz, {}ch, {}bit, gain={}%, limiter={}, start_existing={}, start_on_first_audio={}, peak_threshold={}, start_timeout={}ms, stop_on_disconnect={}, fixed_cadence={}ms/{}, jitter_buffer={}ms, epoch={}; will piggyback DATA only",
            NAME, channel, sample_rate, channels, bits, gain_percent, limiter, start_existing, start_on_first_audio, audio_peak_threshold, start_timeout_ms.max(1), stop_existing_on_disconnect, cadence_ms, fixed_cadence, jitter_buffer_ms, epoch
        );
    }
}

pub fn set_microphone_source(
    channel: u8,
    sample_rate: u32,
    channels: u32,
    bits: u32,
    request_enabled: bool,
) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };

    let previous = runtime.mic_channel.swap(channel, Ordering::SeqCst);
    let epoch = runtime.mic_epoch.fetch_add(1, Ordering::SeqCst) + 1;
    runtime.mic_sample_rate.store(sample_rate, Ordering::SeqCst);
    runtime.mic_channels.store(channels, Ordering::SeqCst);
    runtime.mic_bits.store(bits, Ordering::SeqCst);
    runtime
        .mic_request_enabled
        .store(request_enabled, Ordering::SeqCst);
    runtime.mic_open_sco_generation.store(0, Ordering::SeqCst);
    runtime.mic_open.store(false, Ordering::SeqCst);
    bt_sco::clear_sco_uplink_queue();

    if previous != channel {
        debug!(
            "{} selected AA microphone source channel=<b>{:#04x}</>, {}Hz, {}ch, {}bit, epoch={}, request_enabled={}",
            NAME, channel, sample_rate, channels, bits, epoch, request_enabled
        );
    } else {
        debug!(
            "{} re-armed AA microphone source channel=<b>{:#04x}</>, {}Hz, {}ch, {}bit, epoch={}, request_enabled={}",
            NAME, channel, sample_rate, channels, bits, epoch, request_enabled
        );
    }
}

pub fn microphone_source_config(channel: u8) -> Option<(u32, u32, u32)> {
    let runtime = RUNTIME.get()?;
    if runtime.mic_channel.load(Ordering::SeqCst) != channel {
        return None;
    }

    let sample_rate = runtime.mic_sample_rate.load(Ordering::SeqCst);
    let channels = runtime.mic_channels.load(Ordering::SeqCst);
    let bits = runtime.mic_bits.load(Ordering::SeqCst);
    if sample_rate == 0 || channels == 0 || bits == 0 {
        None
    } else {
        Some((sample_rate, channels, bits))
    }
}

pub fn notify_media_config(channel: u8, cfg: &AudioConfig) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };

    let target = runtime.target_channel.load(Ordering::SeqCst);
    if target == 0 || target != channel {
        return;
    }

    let config_index = cfg.configuration_indices.first().copied().unwrap_or(0);
    let max_unacked = cfg.max_unacked();
    let epoch = runtime.target_epoch.load(Ordering::SeqCst);

    runtime
        .configuration_index
        .store(config_index, Ordering::SeqCst);
    runtime.max_unacked.store(max_unacked, Ordering::SeqCst);
    runtime.config_channel.store(channel, Ordering::SeqCst);
    runtime.config_epoch.store(epoch, Ordering::SeqCst);

    debug!(
        "{} existing HU media CONFIG seen for channel=<b>{:#04x}</>: status={:?}, config_index={}, max_unacked={}, epoch={}; bridge is ready for SCO DATA piggyback",
        NAME,
        channel,
        cfg.status(),
        config_index,
        max_unacked,
        epoch
    );
}

pub fn notify_microphone_response(channel: u8, payload: &[u8]) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };
    if runtime.mic_channel.load(Ordering::SeqCst) != channel {
        return;
    }

    debug!(
        "{} MICROPHONE_RESPONSE ch=<b>{:#04x}</> len={} hex={}",
        NAME,
        channel,
        payload.len(),
        hex::encode(&payload[..payload.len().min(32)])
    );
}

/// Kept for compatibility with the previous safe-open patch.
///
/// The piggyback bridge deliberately does not send CHANNEL_OPEN_REQUEST anymore, so
/// CHANNEL_OPEN_RESPONSE is not needed. Leaving this no-op lets this file compile
/// both against the previous mitm.rs and against the current one.
pub fn notify_channel_open_response(_resp: &ChannelOpenResponse) {}

fn bridge_loop(runtime: Arc<Runtime>) {
    let mut active_epoch = 0u64;
    let mut pts_us = 0u64;
    let mut data_packets = 0u64;
    let mut dropped_before_ready = 0u64;
    let mut last_data_log = Instant::now();
    let mut last_wait_log = Instant::now();
    let mut media_started_generation = 0u64;
    let mut pending_start_generation = 0u64;
    let mut pending_start_started_at: Option<Instant> = None;
    let mut silent_frames_before_start = 0u64;
    let mut next_cadence_send_at: Option<Instant> = None;
    let mut last_mic_wait_log = Instant::now();
    let mut mic_request_retry_at: Option<Instant> = None;
    let mut rate_adapter: Option<bt_sco::PcmResampler> = None;
    let mut rate_adapter_generation = 0u64;

    loop {
        handle_microphone_request_state(
            &runtime,
            &mut last_mic_wait_log,
            &mut mic_request_retry_at,
        );

        let channel = runtime.target_channel.load(Ordering::SeqCst);
        if channel == 0 {
            drop_stale_sco_frames();
            thread::sleep(NO_TARGET_SLEEP);
            continue;
        }

        let epoch = runtime.target_epoch.load(Ordering::SeqCst);
        if epoch != active_epoch {
            active_epoch = epoch;
            pts_us = 0;
            data_packets = 0;
            dropped_before_ready = 0;
            last_data_log = Instant::now();
            last_wait_log = Instant::now();
            media_started_generation = 0;
            pending_start_generation = 0;
            pending_start_started_at = None;
            silent_frames_before_start = 0;
            next_cadence_send_at = None;
            rate_adapter = None;
            debug!(
                "{} target channel=<b>{:#04x}</>, epoch={} armed; waiting for existing HU media CONFIG, no CHANNEL_OPEN/SETUP will be injected",
                NAME, channel, epoch
            );
        }

        let ready = runtime.config_channel.load(Ordering::SeqCst) == channel
            && runtime.config_epoch.load(Ordering::SeqCst) == epoch;

        if !ready {
            if bt_sco::pop_aa_pcm_frame().is_some() {
                dropped_before_ready += 1;
            } else {
                thread::sleep(IDLE_SLEEP);
            }

            if last_wait_log.elapsed() >= WAIT_LOG_INTERVAL {
                warn!(
                    "{} waiting for existing HU media CONFIG on channel=<b>{:#04x}</>, epoch={}, dropped_sco_frames_before_ready={}",
                    NAME, channel, epoch, dropped_before_ready
                );
                last_wait_log = Instant::now();
            }
            continue;
        }

        if handle_media_disconnected_state(
            &runtime,
            channel,
            &mut media_started_generation,
            &mut pending_start_generation,
            &mut pending_start_started_at,
            &mut silent_frames_before_start,
            &mut pts_us,
            &mut data_packets,
            &mut next_cadence_send_at,
        ) {
            thread::sleep(IDLE_SLEEP);
            continue;
        }

        if let Some(wait) = fixed_cadence_wait(&runtime, data_packets, &next_cadence_send_at) {
            thread::sleep(wait);
            continue;
        }

        let active_generation = bt_sco::sco_generation();
        let Some(frame) = bt_sco::pop_aa_pcm_frame_for_generation(active_generation) else {
            thread::sleep(IDLE_SLEEP);
            continue;
        };

        if frame.pcm.is_empty() {
            continue;
        }

        let packet_channel = runtime.target_channel.load(Ordering::SeqCst);
        let packet_epoch = runtime.target_epoch.load(Ordering::SeqCst);
        if packet_channel == 0 || packet_channel != channel || packet_epoch != epoch {
            continue;
        }

        let target_sample_rate = runtime.target_sample_rate.load(Ordering::SeqCst).max(1);
        let target_channels = runtime.target_channels.load(Ordering::SeqCst).max(1);
        let target_bits = runtime.target_bits.load(Ordering::SeqCst);
        let gain_percent = runtime.output_gain_percent.load(Ordering::SeqCst).max(1);
        let limiter =
            BtScoMediaBridgeLimiter::from_u8(runtime.output_limiter.load(Ordering::SeqCst));

        if target_bits != 16 {
            warn!(
                "{} target channel=<b>{:#04x}</> has unsupported PCM bit depth {}; dropping SCO frame",
                NAME, channel, target_bits
            );
            continue;
        }

        // The SCO reader emits 48kHz stereo s16le chunks. Adapt that to the
        // actual selected sink: MEDIA is usually 48kHz stereo, GUIDANCE is
        // often 16kHz mono.
        if frame.generation != rate_adapter_generation {
            rate_adapter = None;
            rate_adapter_generation = frame.generation;
        }
        let mut adapted = adapt_48k_stereo_s16le_to_target(
            &frame.pcm,
            target_sample_rate,
            target_channels,
            gain_percent,
            limiter,
            &mut rate_adapter,
        );
        let bytes_per_frame = target_channels as usize * 2;
        if bytes_per_frame == 0 || adapted.len() < bytes_per_frame {
            continue;
        }

        let frames = (adapted.len() / bytes_per_frame) as u64;
        let peak = peak_s16le(&adapted);

        if !ensure_media_started_for_frame(
            &runtime,
            channel,
            epoch,
            peak,
            &mut media_started_generation,
            &mut pending_start_generation,
            &mut pending_start_started_at,
            &mut silent_frames_before_start,
            &mut pts_us,
            &mut data_packets,
            &mut next_cadence_send_at,
        ) {
            continue;
        }

        let mut payload = Vec::with_capacity(2 + 8 + adapted.len());
        push_media_message_id(&mut payload, MediaMessageId::MEDIA_MESSAGE_DATA as u16);
        payload.extend_from_slice(&pts_us.to_be_bytes());
        payload.append(&mut adapted);

        let pkt = Packet {
            channel,
            flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
            final_length: None,
            payload,
        };

        if send_packet(&runtime, pkt, "DATA").is_ok() {
            data_packets += 1;
            let frame_us = frames * 1_000_000 / (target_sample_rate as u64);
            pts_us += frame_us;
            advance_fixed_cadence(
                &runtime,
                &mut next_cadence_send_at,
                Duration::from_micros(frame_us),
            );

            if data_packets <= 5 || last_data_log.elapsed() >= Duration::from_secs(5) {
                let config_index = runtime.configuration_index.load(Ordering::SeqCst);
                let max_unacked = runtime.max_unacked.load(Ordering::SeqCst);
                debug!(
                    "{} DATA piggyback ch=<b>{:#04x}</> packets={} pts={}us last_frames={} last_bytes={} peak={} config_index={} max_unacked={}",
                    NAME,
                    channel,
                    data_packets,
                    pts_us,
                    frames,
                    frames * bytes_per_frame as u64,
                    peak,
                    config_index,
                    max_unacked
                );
                last_data_log = Instant::now();
            }
        } else {
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Returns how long to wait before the next fixed-cadence DATA packet, or `None` when a packet
/// may be sent now.
fn fixed_cadence_wait(
    runtime: &Runtime,
    data_packets: u64,
    next_send_at: &Option<Instant>,
) -> Option<Duration> {
    if !runtime.fixed_cadence.load(Ordering::SeqCst) {
        return None;
    }

    let jitter_buffer_ms = runtime.jitter_buffer_ms.load(Ordering::SeqCst);

    if data_packets == 0 && jitter_buffer_ms > 0 {
        let generation = bt_sco::sco_generation();
        if generation == 0
            || bt_sco::aa_pcm_queued_ms_for_generation(generation) < jitter_buffer_ms as u64
        {
            return Some(IDLE_SLEEP);
        }
    }

    let next = (*next_send_at)?;
    let now = Instant::now();
    if now < next {
        Some((next - now).min(IDLE_SLEEP))
    } else {
        None
    }
}

/// Schedule the next fixed-cadence DATA packet. The deadline is advanced from the previous
/// deadline (not from "now"), so the scheduling latency of the loop does not accumulate and the
/// average send rate matches the real-time rate of the audio. `audio_duration` is the playback
/// time of the packet just sent; `cadence_ms = 0` (default) paces by it, a non-zero value forces
/// a fixed interval.
fn advance_fixed_cadence(
    runtime: &Runtime,
    next_send_at: &mut Option<Instant>,
    audio_duration: Duration,
) {
    if !runtime.fixed_cadence.load(Ordering::SeqCst) {
        *next_send_at = None;
        return;
    }

    let cadence_ms = runtime.cadence_ms.load(Ordering::SeqCst);
    let cadence = if cadence_ms == 0 {
        audio_duration
    } else {
        Duration::from_millis(cadence_ms as u64)
    };
    if cadence.is_zero() {
        *next_send_at = None;
        return;
    }

    let now = Instant::now();
    let next = match *next_send_at {
        // On schedule or slightly late: keep the grid, the next packet catches up.
        Some(previous) if now.saturating_duration_since(previous) < cadence * 2 => {
            previous + cadence
        }
        // First packet, or far behind (underrun / stall): restart the grid from now.
        _ => now + cadence,
    };
    *next_send_at = Some(next);
}

fn handle_media_disconnected_state(
    runtime: &Runtime,
    channel: u8,
    media_started_generation: &mut u64,
    pending_start_generation: &mut u64,
    pending_start_started_at: &mut Option<Instant>,
    silent_frames_before_start: &mut u64,
    pts_us: &mut u64,
    data_packets: &mut u64,
    next_cadence_send_at: &mut Option<Instant>,
) -> bool {
    if bt_sco::is_sco_connected() {
        return false;
    }

    if *media_started_generation != 0 {
        if runtime.stop_existing_on_disconnect.load(Ordering::SeqCst) {
            let _ = send_media_stop(runtime, channel);
        }
        debug!(
            "{} media bridge stopped for ch=<b>{:#04x}</>, sco_generation={}, packets_sent={}",
            NAME, channel, *media_started_generation, *data_packets
        );
    } else if *pending_start_generation != 0 {
        debug!(
            "{} media bridge pending start cleared for ch=<b>{:#04x}</>, sco_generation={}, silent_frames_before_start={}",
            NAME, channel, *pending_start_generation, *silent_frames_before_start
        );
    }

    *media_started_generation = 0;
    *pending_start_generation = 0;
    *pending_start_started_at = None;
    *silent_frames_before_start = 0;
    *pts_us = 0;
    *data_packets = 0;
    *next_cadence_send_at = None;
    drop_stale_sco_frames();
    true
}

fn ensure_media_started_for_frame(
    runtime: &Runtime,
    channel: u8,
    epoch: u64,
    frame_peak: i16,
    media_started_generation: &mut u64,
    pending_start_generation: &mut u64,
    pending_start_started_at: &mut Option<Instant>,
    silent_frames_before_start: &mut u64,
    pts_us: &mut u64,
    data_packets: &mut u64,
    next_cadence_send_at: &mut Option<Instant>,
) -> bool {
    let generation = bt_sco::sco_generation();
    if generation == 0 {
        return false;
    }

    if *media_started_generation == generation {
        return true;
    }

    if *media_started_generation != 0 && *media_started_generation != generation {
        if runtime.stop_existing_on_disconnect.load(Ordering::SeqCst) {
            let _ = send_media_stop(runtime, channel);
        }
        debug!(
            "{} media bridge generation switch: stopped previous ch=<b>{:#04x}</>, old_generation={}, new_generation={}, packets_sent={}",
            NAME,
            channel,
            *media_started_generation,
            generation,
            *data_packets
        );
        *media_started_generation = 0;
        *pts_us = 0;
        *data_packets = 0;
        *next_cadence_send_at = None;
    }

    if *pending_start_generation != generation {
        *pending_start_generation = generation;
        *pending_start_started_at = Some(Instant::now());
        *silent_frames_before_start = 0;
        *pts_us = 0;
        *data_packets = 0;
        *next_cadence_send_at = None;

        let start_on_first_audio = runtime.start_on_first_audio.load(Ordering::SeqCst);
        let threshold = runtime.audio_peak_threshold.load(Ordering::SeqCst);
        let timeout_ms = runtime.start_timeout_ms.load(Ordering::SeqCst).max(1);
        debug!(
            "{} media bridge pending START for ch=<b>{:#04x}</>, sco_generation={}, start_on_first_audio={}, peak_threshold={}, timeout={}ms",
            NAME, channel, generation, start_on_first_audio, threshold, timeout_ms
        );
    }

    let start_on_first_audio = runtime.start_on_first_audio.load(Ordering::SeqCst);
    let threshold = runtime
        .audio_peak_threshold
        .load(Ordering::SeqCst)
        .min(i16::MAX as u32) as i16;
    let timeout =
        Duration::from_millis(runtime.start_timeout_ms.load(Ordering::SeqCst).max(1) as u64);
    let elapsed = pending_start_started_at
        .map(|started| started.elapsed())
        .unwrap_or_default();

    let is_non_silent = frame_peak >= threshold;
    let timed_out = elapsed >= timeout;

    let allow_timeout_start = START_ON_TIMEOUT.load(Ordering::Relaxed);
    if start_on_first_audio && !is_non_silent && (!timed_out || !allow_timeout_start) {
        *silent_frames_before_start += 1;
        if *silent_frames_before_start <= 5 || *silent_frames_before_start % 100 == 0 {
            debug!(
                "{} waiting for first SCO downlink audio before START ch=<b>{:#04x}</>, sco_generation={}, silent_frames={}, peak={}, threshold={}, elapsed={}ms",
                NAME,
                channel,
                generation,
                *silent_frames_before_start,
                frame_peak,
                threshold,
                elapsed.as_millis()
            );
        }
        return false;
    }

    let reason = if !start_on_first_audio {
        "sco_connected"
    } else if is_non_silent {
        "first_non_silent_audio"
    } else {
        "start_timeout"
    };

    if runtime.start_existing.load(Ordering::SeqCst) {
        let config_index = runtime.configuration_index.load(Ordering::SeqCst);
        if send_media_start(runtime, channel, DEFAULT_SESSION_ID, config_index).is_ok() {
            debug!(
                "{} media bridge START sent for existing ch=<b>{:#04x}</>, session_id={}, config_index={}, sco_generation={}, epoch={}, reason={}, peak={}, threshold={}, silent_frames_before_start={}, elapsed={}ms",
                NAME,
                channel,
                DEFAULT_SESSION_ID,
                config_index,
                generation,
                epoch,
                reason,
                frame_peak,
                threshold,
                *silent_frames_before_start,
                elapsed.as_millis()
            );
        }
    } else {
        debug!(
            "{} media bridge using DATA-only mode for ch=<b>{:#04x}</>, sco_generation={}, reason={}, peak={}, threshold={}, silent_frames_before_start={}, elapsed={}ms",
            NAME,
            channel,
            generation,
            reason,
            frame_peak,
            threshold,
            *silent_frames_before_start,
            elapsed.as_millis()
        );
    }

    *media_started_generation = generation;
    *pending_start_generation = 0;
    *pending_start_started_at = None;
    *silent_frames_before_start = 0;
    *pts_us = 0;
    *data_packets = 0;
    *next_cadence_send_at = None;
    true
}

fn send_media_start(
    runtime: &Runtime,
    channel: u8,
    session_id: i32,
    configuration_index: u32,
) -> std::result::Result<(), ()> {
    let mut start = Start::new();
    start.set_session_id(session_id);
    start.set_configuration_index(configuration_index);

    let mut payload = start.write_to_bytes().unwrap_or_default();
    push_media_message_id(&mut payload, MediaMessageId::MEDIA_MESSAGE_START as u16);

    let pkt = Packet {
        channel,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };

    send_packet(runtime, pkt, "MEDIA_MESSAGE_START(existing)")
}

fn send_media_stop(runtime: &Runtime, channel: u8) -> std::result::Result<(), ()> {
    let stop = Stop::new();
    let mut payload = stop.write_to_bytes().unwrap_or_default();
    push_media_message_id(&mut payload, MediaMessageId::MEDIA_MESSAGE_STOP as u16);

    let pkt = Packet {
        channel,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };

    let result = send_packet(runtime, pkt, "MEDIA_MESSAGE_STOP(existing)");
    if result.is_ok() {
        debug!(
            "{} MEDIA_MESSAGE_STOP existing ch=<b>{:#04x}</>",
            NAME, channel
        );
    }
    result
}

fn handle_microphone_request_state(
    runtime: &Runtime,
    last_wait_log: &mut Instant,
    retry_at: &mut Option<Instant>,
) {
    let channel = runtime.mic_channel.load(Ordering::SeqCst);
    if channel == 0 || !runtime.mic_request_enabled.load(Ordering::SeqCst) {
        return;
    }

    let connected = bt_sco::is_sco_connected();
    let generation = bt_sco::sco_generation();
    let open_generation = runtime.mic_open_sco_generation.load(Ordering::SeqCst);

    if connected && generation != 0 && generation != open_generation {
        // A failed open request is retried every loop iteration (5 ms) otherwise.
        if retry_at.map(|t| Instant::now() < t).unwrap_or(false) {
            return;
        }
        if send_microphone_request(runtime, channel, true).is_err() {
            *retry_at = Some(Instant::now() + MIC_REQUEST_RETRY_INTERVAL);
        } else {
            *retry_at = None;
            runtime
                .mic_open_sco_generation
                .store(generation, Ordering::SeqCst);
            runtime.mic_open.store(true, Ordering::SeqCst);
            bt_sco::clear_sco_uplink_queue();
            debug!(
                "{} requested HU microphone open ch=<b>{:#04x}</>, sco_generation={}",
                NAME, channel, generation
            );
        }
        return;
    }

    if !connected && runtime.mic_open.swap(false, Ordering::SeqCst) {
        let _ = send_microphone_request(runtime, channel, false);
        runtime.mic_open_sco_generation.store(0, Ordering::SeqCst);
        bt_sco::clear_sco_uplink_queue();
        debug!(
            "{} requested HU microphone close ch=<b>{:#04x}</>",
            NAME, channel
        );
        return;
    }

    if connected && last_wait_log.elapsed() >= MIC_REQUEST_LOG_INTERVAL {
        debug!(
            "{} microphone source armed ch=<b>{:#04x}</>, sco_generation={}, open_generation={}",
            NAME, channel, generation, open_generation
        );
        *last_wait_log = Instant::now();
    }
}

fn send_microphone_request(
    runtime: &Runtime,
    channel: u8,
    open: bool,
) -> std::result::Result<(), ()> {
    let mut payload = build_microphone_request_payload(open);
    push_media_message_id(
        &mut payload,
        MediaMessageId::MEDIA_MESSAGE_MICROPHONE_REQUEST as u16,
    );

    let pkt = Packet {
        channel,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    };

    send_packet(
        runtime,
        pkt,
        if open {
            "MICROPHONE_REQUEST(open)"
        } else {
            "MICROPHONE_REQUEST(close)"
        },
    )
}

fn build_microphone_request_payload(open: bool) -> Vec<u8> {
    // Decompiled Gearhead sends an internal protobuf with these fields when
    // opening the car microphone:
    //   field 1: bool open = true
    //   field 2: bool unknown = false
    //   field 3: bool unknown = false
    //   field 4: int32 mode/source = 2
    // Close request only sets field 1 to false.
    let mut payload = vec![0x08, if open { 0x01 } else { 0x00 }];
    if open {
        payload.extend_from_slice(&[0x10, 0x00, 0x18, 0x00, 0x20, 0x02]);
    }
    payload
}

/// Sample rate of the PCM chunks produced by the SCO reader.
const SOURCE_SAMPLE_RATE_HZ: u32 = bt_sco::AA_MEDIA_PCM_SAMPLE_RATE_HZ;
/// Adapt one SCO reader chunk (48 kHz stereo s16le, L == R) to the selected sink format:
/// sample rate, channel count, gain and limiter.
fn adapt_48k_stereo_s16le_to_target(
    input: &[u8],
    target_sample_rate: u32,
    target_channels: u32,
    gain_percent: u32,
    limiter: BtScoMediaBridgeLimiter,
    rate_adapter: &mut Option<bt_sco::PcmResampler>,
) -> Vec<u8> {
    let gain = gain_percent.max(1) as i32;
    let target_channels = target_channels.max(1) as usize;

    // The source is a duplicated mono SCO signal, so taking the left channel is lossless.
    let mono = input
        .chunks_exact(4)
        .map(|frame| i16::from_le_bytes([frame[0], frame[1]]));

    let samples: Vec<i16> = if target_sample_rate == SOURCE_SAMPLE_RATE_HZ {
        *rate_adapter = None;
        mono.collect()
    } else {
        if rate_adapter
            .as_ref()
            .map(|a| a.out_rate() != target_sample_rate)
            .unwrap_or(true)
        {
            // The SCO voice band ends at 4 kHz, so that is the widest useful passband.
            *rate_adapter = Some(bt_sco::PcmResampler::new(
                SOURCE_SAMPLE_RATE_HZ,
                target_sample_rate,
                4_000,
            ));
        }
        let adapter = rate_adapter.as_mut().unwrap();
        let mut out = Vec::with_capacity(
            input.len() / 4 * target_sample_rate as usize / SOURCE_SAMPLE_RATE_HZ as usize + 2,
        );
        for sample in mono {
            adapter.push(sample, &mut out);
        }
        out
    };

    let mut out = Vec::with_capacity(samples.len() * target_channels * 2);
    for sample in samples {
        let bytes = apply_gain(sample, gain, limiter).to_le_bytes();
        for _ in 0..target_channels {
            out.extend_from_slice(&bytes);
        }
    }
    out
}

fn apply_gain(sample: i16, gain_percent: i32, limiter: BtScoMediaBridgeLimiter) -> i16 {
    let amplified = sample as i32 * gain_percent / 100;
    match limiter {
        BtScoMediaBridgeLimiter::Off => clamp_i16(amplified),
        BtScoMediaBridgeLimiter::Hard => amplified.clamp(-30_000, 30_000) as i16,
        BtScoMediaBridgeLimiter::Soft => soft_limit_i16(amplified),
    }
}

fn clamp_i16(sample: i32) -> i16 {
    sample.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

fn soft_limit_i16(sample: i32) -> i16 {
    const THRESHOLD: i32 = 24_000;
    const MAX: i32 = i16::MAX as i32;

    let sign = if sample < 0 { -1 } else { 1 };
    let abs = sample.abs();
    if abs <= THRESHOLD {
        return (sign * abs) as i16;
    }

    let excess = abs - THRESHOLD;
    let headroom = MAX - THRESHOLD;
    let compressed =
        THRESHOLD + ((headroom as i64 * excess as i64) / (excess as i64 + headroom as i64)) as i32;
    (sign * compressed.min(MAX)) as i16
}

fn peak_s16le(pcm: &[u8]) -> i16 {
    let mut peak: i32 = 0;
    for bytes in pcm.chunks_exact(2) {
        let sample = i16::from_le_bytes([bytes[0], bytes[1]]) as i32;
        peak = peak.max(sample.abs());
    }
    peak.min(i16::MAX as i32) as i16
}

fn drop_stale_sco_frames() {
    bt_sco::clear_aa_pcm_queue();
}

/// Send failures repeat on every loop iteration while the AA session is gone, so log the first
/// one and then at most one per interval with the number of suppressed failures.
fn warn_send_failure(label: &str, reason: &str) {
    static LAST: Mutex<(Option<Instant>, u64)> = Mutex::new((None, 0));
    let mut last = LAST.lock().unwrap();
    let now = Instant::now();
    if last
        .0
        .map(|t| now.duration_since(t) >= SEND_ERROR_LOG_INTERVAL)
        .unwrap_or(true)
    {
        warn!(
            "{} failed to send {}: {} (suppressed since last report: {})",
            NAME, label, reason, last.1
        );
        *last = (Some(now), 0);
    } else {
        last.1 += 1;
    }
}

fn send_packet(runtime: &Runtime, pkt: Packet, label: &str) -> std::result::Result<(), ()> {
    let tx = runtime.tx.lock().unwrap().clone();
    let Some(tx) = tx else {
        warn_send_failure(label, "AA tx is not available");
        return Err(());
    };

    match tx.blocking_send(pkt) {
        Ok(_) => Ok(()),
        Err(e) => {
            warn_send_failure(label, &e.to_string());
            Err(())
        }
    }
}

fn push_media_message_id(payload: &mut Vec<u8>, id: u16) {
    payload.insert(0, (id & 0xff) as u8);
    payload.insert(0, (id >> 8) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stereo_48k_sine(freq: f64, frames: usize, amplitude: f64) -> Vec<u8> {
        let mut out = Vec::with_capacity(frames * 4);
        for i in 0..frames {
            let v = (amplitude * (2.0 * std::f64::consts::PI * freq * i as f64 / 48_000.0).sin())
                as i16;
            out.extend_from_slice(&v.to_le_bytes());
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    #[test]
    fn adapt_keeps_48k_stereo_unchanged() {
        let input = stereo_48k_sine(1000.0, 1080, 8000.0);
        let mut adapter = None;
        let out = adapt_48k_stereo_s16le_to_target(
            &input,
            48_000,
            2,
            100,
            BtScoMediaBridgeLimiter::Off,
            &mut adapter,
        );
        assert_eq!(out, input);
        assert!(adapter.is_none());
    }

    #[test]
    fn adapt_48k_to_16k_mono_keeps_duration_and_level() {
        let mut adapter = None;
        let mut total = 0usize;
        let mut peak = 0i16;
        // 10 chunks of 22.5 ms, like the SCO reader produces.
        for chunk in 0..10 {
            let input = stereo_48k_sine(1000.0, 1080, 8000.0);
            let out = adapt_48k_stereo_s16le_to_target(
                &input,
                16_000,
                1,
                100,
                BtScoMediaBridgeLimiter::Off,
                &mut adapter,
            );
            total += out.len() / 2;
            if chunk > 0 {
                peak = peak.max(peak_s16le(&out));
            }
        }
        assert_eq!(total, 10 * 360);
        assert!((7000..=8200).contains(&peak), "peak={}", peak);
    }

    #[test]
    fn adapt_handles_non_integer_ratio() {
        let mut adapter = None;
        let mut total = 0usize;
        for _ in 0..100 {
            let input = stereo_48k_sine(500.0, 480, 8000.0);
            let out = adapt_48k_stereo_s16le_to_target(
                &input,
                44_100,
                2,
                100,
                BtScoMediaBridgeLimiter::Off,
                &mut adapter,
            );
            total += out.len() / 4;
        }
        // 1 s of input -> 44100 frames (+/- 1 for the fractional position).
        assert!((44_099..=44_101).contains(&total), "total={}", total);
    }
}
