use crate::bt_sco_echo::{self, BtScoEchoSettings};
use crate::config::BtScoMediaBridgeResampler;
use simplelog::*;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const NAME: &str = "<i><bright-black> bt-sco: </>";

// Linux Bluetooth constants. Keep them explicit because some cross libc headers do
// not expose all Bluetooth-specific names in Rust.
const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_SCO: libc::c_int = 2;
const SOL_SCO: libc::c_int = 17;
const SOL_BLUETOOTH: libc::c_int = 274;

const SCO_OPTIONS: libc::c_int = 0x01;
const SCO_CONNINFO: libc::c_int = 0x02;
const BT_VOICE: libc::c_int = 11;
const BT_SNDMTU: libc::c_int = 12;
const BT_RCVMTU: libc::c_int = 13;

/// Target size for bridge chunks: about 20ms of 48kHz stereo s16le PCM.
/// The SCO packet cadence produces 60-byte input packets, so actual chunks are
/// usually 22.5ms / 4320 bytes after the 6x stereo expansion.
pub const AA_MEDIA_PCM_TARGET_CHUNK_BYTES: usize = 48_000 * 2 * 2 / 50;
const DEFAULT_AA_PCM_RING_CAPACITY: usize = 128;
pub const SCO_UPLINK_PACKET_BYTES: usize = 60;
const DEFAULT_SCO_UPLINK_RING_CAPACITY: usize = 256;
const SCO_DOWNLINK_AUDIO_LOG_PEAK_THRESHOLD: i16 = 64;
/// Minimum interval between repeated error logs on per-packet paths.
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(5);
/// Uplink latency control: the HU microphone and the SCO link run on different clocks, so a
/// slightly faster microphone makes the uplink queue (and the latency heard by the far end)
/// grow during a call. The smallest queue length seen within a window is the standing latency
/// (microphone bursts do not count); when it exceeds the maximum, the oldest packets are dropped
/// down to the target.
const SCO_UPLINK_LATENCY_WINDOW: Duration = Duration::from_secs(1);
/// 16 x 3.75 ms = 60 ms
const SCO_UPLINK_MAX_STANDING_PACKETS: usize = 16;
/// 4 x 3.75 ms = 15 ms
const SCO_UPLINK_TARGET_STANDING_PACKETS: usize = 4;

#[derive(Debug, Clone)]
pub struct AaPcmFrame {
    pub generation: u64,
    pub pcm: Vec<u8>,
}

static AA_PCM_RING: OnceLock<Arc<Mutex<VecDeque<AaPcmFrame>>>> = OnceLock::new();
static SCO_UPLINK_RING: OnceLock<Arc<Mutex<VecDeque<Vec<u8>>>>> = OnceLock::new();
static SCO_UPLINK_PENDING: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
static SCO_UPLINK_RESAMPLER: Mutex<Option<(u32, PcmResampler)>> = Mutex::new(None);
/// Passband of the microphone path: the 8 kHz SCO uplink carries up to 4 kHz, keep a margin for
/// the anti-alias filter.
const SCO_UPLINK_CUTOFF_HZ: u32 = 3_500;
static SCO_CONNECTED: AtomicBool = AtomicBool::new(false);
static SCO_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct BtScoOptions {
    /// Convert the confirmed SCO downlink format (8kHz s16le mono) into
    /// AA-friendly media PCM (48kHz s16le stereo) and expose it through the
    /// in-process bridge ring buffer.
    pub bridge_aa_media_pcm: bool,
    /// Maximum number of converted AA PCM chunks held in the bridge ring.
    /// Old chunks are dropped first to keep latency bounded.
    pub bridge_ring_capacity: usize,
    /// SCO 8 kHz -> AA 48 kHz resampler used for downlink conversion.
    /// `Repeat` preserves the original proven behavior; `Linear` smooths the
    /// integer 6x upsampling and can reduce roughness/crackle.
    pub media_resampler: BtScoMediaBridgeResampler,
    /// Write HU microphone PCM frames back to the SCO/eSCO socket as uplink.
    /// When enabled, silence is written if no mic frame is available yet, so the
    /// phone keeps receiving a steady SCO uplink stream.
    pub bridge_sco_uplink_pcm: bool,
    /// Maximum number of 60-byte SCO uplink packets buffered for the microphone bridge.
    pub sco_uplink_ring_capacity: usize,
    /// Microphone echo handling settings for SCO uplink.
    pub echo_settings: BtScoEchoSettings,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BdAddr {
    b: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrSco {
    sco_family: libc::sa_family_t,
    sco_bdaddr: BdAddr,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct ScoOptions {
    mtu: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct ScoConnInfo {
    hci_handle: u16,
    dev_class: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct BtVoice {
    setting: u16,
}

#[derive(Debug, Default)]
struct ScoStats {
    packets: u64,
    bytes: u64,
    min_packet_len: usize,
    max_packet_len: usize,
    packet_len_histogram: BTreeMap<usize, u64>,
    first_packet_at: Option<Instant>,
    last_packet_at: Option<Instant>,
    min_interarrival_us: Option<u128>,
    max_interarrival_us: Option<u128>,
    interarrival_total_us: u128,
    interarrival_count: u64,
}

impl ScoStats {
    fn observe(&mut self, len: usize, now: Instant) {
        if self.packets == 0 {
            self.min_packet_len = len;
            self.max_packet_len = len;
            self.first_packet_at = Some(now);
        } else {
            self.min_packet_len = self.min_packet_len.min(len);
            self.max_packet_len = self.max_packet_len.max(len);

            if let Some(last) = self.last_packet_at {
                let delta_us = now.duration_since(last).as_micros();
                self.min_interarrival_us = Some(
                    self.min_interarrival_us
                        .map(|v| v.min(delta_us))
                        .unwrap_or(delta_us),
                );
                self.max_interarrival_us = Some(
                    self.max_interarrival_us
                        .map(|v| v.max(delta_us))
                        .unwrap_or(delta_us),
                );
                self.interarrival_total_us += delta_us;
                self.interarrival_count += 1;
            }
        }

        self.last_packet_at = Some(now);
        self.packets += 1;
        self.bytes += len as u64;
        *self.packet_len_histogram.entry(len).or_insert(0) += 1;
    }

    fn elapsed_secs(&self, fallback_started: Instant) -> f64 {
        match (self.first_packet_at, self.last_packet_at) {
            (Some(first), Some(last)) if last > first => last.duration_since(first).as_secs_f64(),
            _ => fallback_started.elapsed().as_secs_f64(),
        }
    }

    fn bytes_per_sec(&self, fallback_started: Instant) -> f64 {
        let elapsed = self.elapsed_secs(fallback_started);
        if elapsed > 0.0 {
            self.bytes as f64 / elapsed
        } else {
            0.0
        }
    }

    fn packets_per_sec(&self, fallback_started: Instant) -> f64 {
        let elapsed = self.elapsed_secs(fallback_started);
        if elapsed > 0.0 {
            self.packets as f64 / elapsed
        } else {
            0.0
        }
    }

    fn inferred_s16le_mono_hz(&self, fallback_started: Instant) -> f64 {
        self.bytes_per_sec(fallback_started) / 2.0
    }

    fn avg_interarrival_ms(&self) -> f64 {
        if self.interarrival_count == 0 {
            0.0
        } else {
            (self.interarrival_total_us as f64 / self.interarrival_count as f64) / 1000.0
        }
    }

    fn top_packet_lengths(&self) -> String {
        let mut items: Vec<(usize, u64)> = self
            .packet_len_histogram
            .iter()
            .map(|(len, count)| (*len, *count))
            .collect();
        items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        items
            .into_iter()
            .take(5)
            .map(|(len, count)| format!("{}B:{}", len, count))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn summary(&self, started: Instant) -> String {
        format!(
            "packets={}, bytes={}, packet_len[min/max/top]={}/{}/[{}], rate={:.1} pkt/s {:.1} B/s inferred_s16le_mono={:.1} Hz, iat_ms[min/avg/max]={:.3}/{:.3}/{:.3}",
            self.packets,
            self.bytes,
            self.min_packet_len,
            self.max_packet_len,
            self.top_packet_lengths(),
            self.packets_per_sec(started),
            self.bytes_per_sec(started),
            self.inferred_s16le_mono_hz(started),
            self.min_interarrival_us.unwrap_or(0) as f64 / 1000.0,
            self.avg_interarrival_ms(),
            self.max_interarrival_us.unwrap_or(0) as f64 / 1000.0,
        )
    }
}

/// Start the SCO/eSCO call-audio listener on a plain blocking thread.
///
/// This does not register any Bluetooth profile and is disabled by default.
/// It accepts the SCO/eSCO socket used by the phone call route and optionally
/// bridges downlink/uplink audio to Android Auto media/microphone channels.
pub fn spawn(options: BtScoOptions) -> io::Result<thread::JoinHandle<()>> {
    bt_sco_echo::configure(options.echo_settings.clone());

    if options.bridge_aa_media_pcm {
        enable_aa_pcm_ring();
    }
    if options.bridge_sco_uplink_pcm {
        enable_sco_uplink_ring();
    }

    thread::Builder::new()
        .name("bt-sco".to_string())
        .spawn(move || {
            if let Err(e) = run(options) {
                error!("{} stopped: {}", NAME, e);
            }
        })
}

fn run(options: BtScoOptions) -> io::Result<()> {
    let listener = create_sco_listener()?;

    debug!(
        "{} listening for incoming SCO/eSCO audio, bridge_aa_media_pcm={}, media_ring_capacity={}, bridge_sco_uplink_pcm={}, uplink_ring_capacity={}",
        NAME,
        options.bridge_aa_media_pcm,
        effective_ring_capacity(options.bridge_ring_capacity),
        options.bridge_sco_uplink_pcm,
        effective_sco_uplink_capacity(options.sco_uplink_ring_capacity)
    );

    loop {
        let mut peer: SockAddrSco = unsafe { mem::zeroed() };
        let mut peer_len = mem::size_of::<SockAddrSco>() as libc::socklen_t;

        let fd = unsafe {
            libc::accept(
                listener,
                &mut peer as *mut SockAddrSco as *mut libc::sockaddr,
                &mut peer_len as *mut libc::socklen_t,
            )
        };

        if fd < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }

            warn!("{} SCO accept error: {}", NAME, e);
            thread::sleep(Duration::from_millis(200));
            continue;
        }

        let generation = SCO_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        clear_aa_pcm_queue();
        SCO_CONNECTED.store(true, Ordering::SeqCst);
        clear_sco_uplink_queue();
        bt_sco_echo::reset_for_sco_generation(generation);

        debug!(
            "{} SCO/eSCO connected from {}, generation={}",
            NAME,
            format_bdaddr(peer.sco_bdaddr),
            generation
        );
        let voice_setting = log_sco_socket_info(fd);
        let linear_pcm = voice_setting.map(is_linear_pcm_voice).unwrap_or(true);
        if !linear_pcm {
            warn!(
                "{} SCO link uses transparent air coding (BT_VOICE=0x{:04x}, e.g. mSBC/LC3 wideband speech), not linear PCM; audio bridging and echo control are disabled for this connection",
                NAME,
                voice_setting.unwrap_or(0)
            );
        }

        handle_sco_connection(fd, &options, generation, linear_pcm);

        SCO_CONNECTED.store(false, Ordering::SeqCst);
        clear_aa_pcm_queue();
        clear_sco_uplink_queue();
    }
}

fn create_sco_listener() -> io::Result<RawFd> {
    let fd = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_SEQPACKET, BTPROTO_SCO) };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let addr = SockAddrSco {
        sco_family: AF_BLUETOOTH as libc::sa_family_t,
        sco_bdaddr: BdAddr { b: [0; 6] }, // BDADDR_ANY
    };

    let bind_result = unsafe {
        libc::bind(
            fd,
            &addr as *const SockAddrSco as *const libc::sockaddr,
            mem::size_of::<SockAddrSco>() as libc::socklen_t,
        )
    };

    if bind_result < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    let listen_result = unsafe { libc::listen(fd, 1) };

    if listen_result < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    Ok(fd)
}

/// `linear_pcm = false` means the socket carries encoded (transparent) data: the connection is
/// still drained so the link stays up, but nothing is bridged in either direction.
fn handle_sco_connection(fd: RawFd, options: &BtScoOptions, generation: u64, linear_pcm: bool) {
    let started = Instant::now();

    let mut buf = [0u8; 2048];
    let mut stats = ScoStats::default();
    let mut last_log = Instant::now();
    let mut aa_pcm_chunk: Vec<u8> = Vec::with_capacity(AA_MEDIA_PCM_TARGET_CHUNK_BYTES * 2);
    let mut downlink_resampler_state = DownlinkResamplerState::default();
    let mut audio_window_peak = 0i16;
    let mut audio_window_energy = 0u128;
    let mut audio_window_samples = 0u64;
    let mut audio_window_silent_packets = 0u64;
    let mut audio_window_non_silent_packets = 0u64;
    let mut first_non_silent_at: Option<Instant> = None;
    let mut first_non_silent_packet = 0u64;
    let mut uplink_written_packets = 0u64;
    let mut uplink_mic_packets = 0u64;
    let mut uplink_silence_packets = 0u64;
    let mut uplink_write_errors = 0u64;
    let mut uplink_latency = UplinkLatencyControl::new(Instant::now());
    let mut last_write_error_log: Option<Instant> = None;

    loop {
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
            )
        };
        let now = Instant::now();

        if n < 0 {
            let e = io::Error::last_os_error();
            warn!("{} SCO read error: {}", NAME, e);
            break;
        }

        if n == 0 {
            debug!("{} SCO EOF", NAME);
            break;
        }

        let n = n as usize;
        stats.observe(n, now);
        let (packet_peak, packet_energy, packet_samples, packet_rms) =
            audio_metrics_s16le(&buf[..n]);
        audio_window_peak = audio_window_peak.max(packet_peak);
        audio_window_energy = audio_window_energy.saturating_add(packet_energy);
        audio_window_samples = audio_window_samples.saturating_add(packet_samples);
        if packet_peak >= SCO_DOWNLINK_AUDIO_LOG_PEAK_THRESHOLD {
            audio_window_non_silent_packets += 1;
            if first_non_silent_at.is_none() {
                first_non_silent_at = Some(now);
                first_non_silent_packet = stats.packets;
                debug!(
                    "{} first non-silent SCO downlink packet: packet={}, after={}ms, peak={}, rms={:.1}, threshold={}",
                    NAME,
                    first_non_silent_packet,
                    now.duration_since(started).as_millis(),
                    packet_peak,
                    packet_rms,
                    SCO_DOWNLINK_AUDIO_LOG_PEAK_THRESHOLD
                );
            }
        } else {
            audio_window_silent_packets += 1;
        }

        if stats.packets <= 10 {
            debug!(
                "{} SCO packet #{} len={} hex={}",
                NAME,
                stats.packets,
                n,
                hex::encode(&buf[..n.min(64)])
            );
        }

        if linear_pcm {
            bt_sco_echo::observe_downlink_sco_8k_mono(&buf[..n]);
        }

        if options.bridge_aa_media_pcm && linear_pcm {
            sco_s16le_mono_8k_to_aa_pcm_s16le_stereo_48k(
                &buf[..n],
                &mut aa_pcm_chunk,
                options.media_resampler,
                &mut downlink_resampler_state,
            );
            if aa_pcm_chunk.len() >= AA_MEDIA_PCM_TARGET_CHUNK_BYTES {
                push_aa_pcm_frame(
                    std::mem::take(&mut aa_pcm_chunk),
                    options.bridge_ring_capacity,
                    generation,
                );
            }
        }

        if options.bridge_sco_uplink_pcm && linear_pcm {
            let (uplink, from_mic) = match pop_sco_uplink_frame(n) {
                Some(frame) => (frame, true),
                None => (vec![0u8; n], false),
            };
            if let Some(excess) = uplink_latency.observe(sco_uplink_queue_len(), now) {
                let dropped = drop_oldest_sco_uplink_packets(excess);
                debug!(
                    "{} mic-uplink latency control: standing queue above {} packets for {}ms, dropped {} oldest packets ({}ms), total_dropped={}",
                    NAME,
                    SCO_UPLINK_MAX_STANDING_PACKETS,
                    SCO_UPLINK_LATENCY_WINDOW.as_millis(),
                    dropped,
                    dropped as u64 * SCO_UPLINK_PACKET_BYTES as u64 / 16,
                    uplink_latency.dropped_total
                );
            }
            let written = unsafe {
                libc::write(
                    fd,
                    uplink.as_ptr() as *const libc::c_void,
                    uplink.len() as libc::size_t,
                )
            };

            if written < 0 {
                let e = io::Error::last_os_error();
                uplink_write_errors += 1;
                // One write per received packet (~267/s): log the first error, then at most
                // one summary per interval.
                if last_write_error_log
                    .map(|t| now.duration_since(t) >= ERROR_LOG_INTERVAL)
                    .unwrap_or(true)
                {
                    warn!(
                        "{} SCO mic-uplink write error: {} (write_errors={})",
                        NAME, e, uplink_write_errors
                    );
                    last_write_error_log = Some(now);
                }
            } else {
                uplink_written_packets += 1;
                if from_mic {
                    uplink_mic_packets += 1;
                } else {
                    uplink_silence_packets += 1;
                }
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            let window_rms = rms_from_energy(audio_window_energy, audio_window_samples);
            let first_audio_ms = first_non_silent_at
                .map(|t| t.duration_since(started).as_millis().to_string())
                .unwrap_or_else(|| "none".to_string());
            debug!(
                "{} SCO active: {}, audio_window[peak={}, rms={:.1}, non_silent_packets={}, silent_packets={}, first_audio_ms={}, first_audio_packet={}], uplink[written={}, mic_packets={}, silence_packets={}, write_errors={}, queued={}], elapsed={}s",
                NAME,
                stats.summary(started),
                audio_window_peak,
                window_rms,
                audio_window_non_silent_packets,
                audio_window_silent_packets,
                first_audio_ms,
                first_non_silent_packet,
                uplink_written_packets,
                uplink_mic_packets,
                uplink_silence_packets,
                uplink_write_errors,
                sco_uplink_queue_len(),
                started.elapsed().as_secs()
            );
            audio_window_peak = 0;
            audio_window_energy = 0;
            audio_window_samples = 0;
            audio_window_silent_packets = 0;
            audio_window_non_silent_packets = 0;
            last_log = Instant::now();
        }
    }

    if options.bridge_aa_media_pcm && !aa_pcm_chunk.is_empty() {
        debug!(
            "{} dropping trailing partial AA PCM chunk on SCO disconnect: generation={}, bytes={}",
            NAME,
            generation,
            aa_pcm_chunk.len()
        );
    }

    unsafe {
        libc::close(fd);
    }

    debug!(
        "{} SCO disconnected: {}, uplink[written={}, mic_packets={}, silence_packets={}, write_errors={}, queued={}], elapsed={}s",
        NAME,
        stats.summary(started),
        uplink_written_packets,
        uplink_mic_packets,
        uplink_silence_packets,
        uplink_write_errors,
        sco_uplink_queue_len(),
        started.elapsed().as_secs()
    );
}

fn enable_aa_pcm_ring() -> Arc<Mutex<VecDeque<AaPcmFrame>>> {
    AA_PCM_RING
        .get_or_init(|| Arc::new(Mutex::new(VecDeque::new())))
        .clone()
}

fn effective_ring_capacity(capacity: usize) -> usize {
    if capacity == 0 {
        DEFAULT_AA_PCM_RING_CAPACITY
    } else {
        capacity
    }
}

fn push_aa_pcm_frame(frame: Vec<u8>, capacity: usize, generation: u64) {
    if frame.is_empty() || generation == 0 {
        return;
    }

    let ring = enable_aa_pcm_ring();
    let mut q = ring.lock().unwrap();
    let capacity = effective_ring_capacity(capacity);
    while q.len() >= capacity {
        q.pop_front();
    }
    q.push_back(AaPcmFrame {
        generation,
        pcm: frame,
    });
}

pub fn pop_aa_pcm_frame() -> Option<AaPcmFrame> {
    let ring = AA_PCM_RING.get()?;
    ring.lock().unwrap().pop_front()
}

pub fn pop_aa_pcm_frame_for_generation(generation: u64) -> Option<AaPcmFrame> {
    let ring = AA_PCM_RING.get()?;
    let mut q = ring.lock().unwrap();

    while let Some(frame) = q.pop_front() {
        if frame.generation == generation {
            return Some(frame);
        }
        debug!(
            "{} discarding stale AA PCM frame: frame_generation={}, active_generation={}, bytes={}",
            NAME,
            frame.generation,
            generation,
            frame.pcm.len()
        );
    }

    None
}

/// Playback time (in ms) of the converted 48 kHz stereo s16le PCM queued for `generation`.
pub fn aa_pcm_queued_ms_for_generation(generation: u64) -> u64 {
    const BYTES_PER_MS: u64 =
        (AA_MEDIA_PCM_SAMPLE_RATE_HZ as u64 / 1000) * AA_MEDIA_PCM_CHANNELS as u64 * 2;
    AA_PCM_RING
        .get()
        .map(|ring| {
            ring.lock()
                .unwrap()
                .iter()
                .filter(|frame| frame.generation == generation)
                .map(|frame| frame.pcm.len() as u64)
                .sum::<u64>()
                / BYTES_PER_MS
        })
        .unwrap_or(0)
}

pub fn clear_aa_pcm_queue() {
    if let Some(ring) = AA_PCM_RING.get() {
        ring.lock().unwrap().clear();
    }
}

fn enable_sco_uplink_ring() -> Arc<Mutex<VecDeque<Vec<u8>>>> {
    SCO_UPLINK_RING
        .get_or_init(|| Arc::new(Mutex::new(VecDeque::new())))
        .clone()
}

fn enable_sco_uplink_pending() -> Arc<Mutex<Vec<u8>>> {
    SCO_UPLINK_PENDING
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone()
}

fn effective_sco_uplink_capacity(capacity: usize) -> usize {
    if capacity == 0 {
        DEFAULT_SCO_UPLINK_RING_CAPACITY
    } else {
        capacity
    }
}

pub fn is_sco_connected() -> bool {
    SCO_CONNECTED.load(Ordering::SeqCst)
}

pub fn sco_generation() -> u64 {
    SCO_GENERATION.load(Ordering::SeqCst)
}

pub fn clear_sco_uplink_queue() {
    if let Some(ring) = SCO_UPLINK_RING.get() {
        ring.lock().unwrap().clear();
    }
    if let Some(pending) = SCO_UPLINK_PENDING.get() {
        pending.lock().unwrap().clear();
    }
    *SCO_UPLINK_RESAMPLER.lock().unwrap() = None;
}

fn push_sco_uplink_packet(packet: Vec<u8>, capacity: usize) {
    if packet.is_empty() {
        return;
    }

    let ring = enable_sco_uplink_ring();
    let mut q = ring.lock().unwrap();
    let capacity = effective_sco_uplink_capacity(capacity);
    while q.len() >= capacity {
        q.pop_front();
    }
    q.push_back(packet);
}

fn pop_sco_uplink_frame(len: usize) -> Option<Vec<u8>> {
    let ring = SCO_UPLINK_RING.get()?;
    let mut q = ring.lock().unwrap();
    let mut frame = q.pop_front()?;

    if frame.len() == len {
        Some(frame)
    } else if frame.len() > len {
        let rest = frame.split_off(len);
        q.push_front(rest);
        Some(frame)
    } else {
        frame.resize(len, 0);
        Some(frame)
    }
}

fn drop_oldest_sco_uplink_packets(count: usize) -> usize {
    let Some(ring) = SCO_UPLINK_RING.get() else {
        return 0;
    };
    let mut q = ring.lock().unwrap();
    let count = count.min(q.len());
    q.drain(..count);
    count
}

struct UplinkLatencyControl {
    window_started: Instant,
    window_min: usize,
    dropped_total: u64,
}

impl UplinkLatencyControl {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            window_min: usize::MAX,
            dropped_total: 0,
        }
    }

    /// Feed the queue length after each uplink write. Returns how many of the oldest packets
    /// should be dropped once per window when the standing latency is too high.
    fn observe(&mut self, queued: usize, now: Instant) -> Option<usize> {
        self.window_min = self.window_min.min(queued);
        if now.duration_since(self.window_started) < SCO_UPLINK_LATENCY_WINDOW {
            return None;
        }

        let standing = self.window_min;
        self.window_started = now;
        self.window_min = usize::MAX;
        if standing > SCO_UPLINK_MAX_STANDING_PACKETS {
            let excess = standing - SCO_UPLINK_TARGET_STANDING_PACKETS;
            self.dropped_total += excess as u64;
            Some(excess)
        } else {
            None
        }
    }
}

fn sco_uplink_queue_len() -> usize {
    SCO_UPLINK_RING
        .get()
        .map(|ring| ring.lock().unwrap().len())
        .unwrap_or(0)
}

/// Convert Android Auto microphone/source PCM to the SCO uplink format observed on
/// the target setup: signed 16-bit little-endian, mono, 8 kHz, 60-byte packets.
///
/// Current HUs usually expose the mic source as 16 kHz mono PCM. Other rates are
/// converted with an anti-alias low-pass and a fractional resampler (state kept
/// across DATA packets), so neither aliasing nor a wrong speed for rates that are
/// not a multiple of 8 kHz (e.g. 44.1 kHz) occurs. 8 kHz sources pass through.
pub fn push_sco_uplink_pcm_from_aa_mic(
    input: &[u8],
    sample_rate: u32,
    channels: u32,
    bits: u32,
    capacity: usize,
) {
    if input.is_empty() {
        return;
    }

    if bits != 16 || channels == 0 || sample_rate == 0 {
        warn!(
            "{} unsupported AA mic format for SCO uplink: {}Hz, {}ch, {}bit, dropping {} bytes",
            NAME,
            sample_rate,
            channels,
            bits,
            input.len()
        );
        return;
    }

    let frame_bytes = channels as usize * 2;
    if frame_bytes == 0 || input.len() < frame_bytes {
        return;
    }

    // Use the first channel when the HU ever exposes stereo/dual-mic PCM.
    let first_channel = input
        .chunks_exact(frame_bytes)
        .map(|frame| i16::from_le_bytes([frame[0], frame[1]]));

    let mut samples_8k: Vec<i16> = if sample_rate == SCO_LINEAR_PCM_SAMPLE_RATE_HZ {
        first_channel.collect()
    } else {
        let frames = input.len() / frame_bytes;
        let mut out = Vec::with_capacity(
            frames * SCO_LINEAR_PCM_SAMPLE_RATE_HZ as usize / sample_rate as usize + 2,
        );
        let mut resampler = SCO_UPLINK_RESAMPLER.lock().unwrap();
        if resampler.as_ref().map(|(rate, _)| *rate) != Some(sample_rate) {
            *resampler = Some((
                sample_rate,
                PcmResampler::new(
                    sample_rate,
                    SCO_LINEAR_PCM_SAMPLE_RATE_HZ,
                    SCO_UPLINK_CUTOFF_HZ,
                ),
            ));
        }
        let (_, r) = resampler.as_mut().unwrap();
        for sample in first_channel {
            r.push(sample, &mut out);
        }
        out
    };

    bt_sco_echo::process_mic_8k_samples(&mut samples_8k);
    if samples_8k.is_empty() {
        return;
    }

    let pending_arc = enable_sco_uplink_pending();
    let mut pending = pending_arc.lock().unwrap();

    for sample in samples_8k {
        pending.extend_from_slice(&sample.to_le_bytes());

        while pending.len() >= SCO_UPLINK_PACKET_BYTES {
            let packet: Vec<u8> = pending.drain(..SCO_UPLINK_PACKET_BYTES).collect();
            drop(pending);
            push_sco_uplink_packet(packet, capacity);
            pending = pending_arc.lock().unwrap();
        }
    }
}

fn audio_metrics_s16le(input: &[u8]) -> (i16, u128, u64, f64) {
    let mut peak = 0i16;
    let mut energy = 0u128;
    let mut samples = 0u64;

    for chunk in input.chunks_exact(2) {
        let sample = i16::from_le_bytes([chunk[0], chunk[1]]) as i32;
        let abs = sample.unsigned_abs().min(i16::MAX as u32) as i16;
        peak = peak.max(abs);
        energy = energy.saturating_add((sample as i128 * sample as i128) as u128);
        samples += 1;
    }

    (peak, energy, samples, rms_from_energy(energy, samples))
}

fn rms_from_energy(energy: u128, samples: u64) -> f64 {
    if samples == 0 {
        0.0
    } else {
        ((energy as f64) / samples as f64).sqrt()
    }
}

/// Logs the SCO socket parameters and returns the BT_VOICE setting when available.
fn log_sco_socket_info(fd: RawFd) -> Option<u16> {
    match getsockopt_value::<ScoOptions>(fd, SOL_SCO, SCO_OPTIONS) {
        Ok(v) => debug!("{} SCO_OPTIONS mtu={}", NAME, v.mtu),
        Err(e) => debug!("{} SCO_OPTIONS unavailable: {}", NAME, e),
    }

    match getsockopt_value::<ScoConnInfo>(fd, SOL_SCO, SCO_CONNINFO) {
        Ok(v) => debug!(
            "{} SCO_CONNINFO hci_handle=0x{:04x} dev_class={:02x}:{:02x}:{:02x}",
            NAME, v.hci_handle, v.dev_class[0], v.dev_class[1], v.dev_class[2]
        ),
        Err(e) => debug!("{} SCO_CONNINFO unavailable: {}", NAME, e),
    }

    let voice_setting = match getsockopt_value::<BtVoice>(fd, SOL_BLUETOOTH, BT_VOICE) {
        Ok(v) => {
            debug!(
                "{} BT_VOICE setting=0x{:04x} ({})",
                NAME,
                v.setting,
                describe_bt_voice(v.setting)
            );
            Some(v.setting)
        }
        Err(e) => {
            debug!("{} BT_VOICE unavailable: {}", NAME, e);
            None
        }
    };

    match getsockopt_int(fd, SOL_BLUETOOTH, BT_RCVMTU) {
        Ok(v) => debug!("{} BT_RCVMTU={}", NAME, v),
        Err(e) => debug!("{} BT_RCVMTU unavailable: {}", NAME, e),
    }

    match getsockopt_int(fd, SOL_BLUETOOTH, BT_SNDMTU) {
        Ok(v) => debug!("{} BT_SNDMTU={}", NAME, v),
        Err(e) => debug!("{} BT_SNDMTU unavailable: {}", NAME, e),
    }

    voice_setting
}

fn getsockopt_value<T: Copy + Default>(
    fd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
) -> io::Result<T> {
    let mut value = T::default();
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            &mut value as *mut T as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };

    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

fn getsockopt_int(fd: RawFd, level: libc::c_int, optname: libc::c_int) -> io::Result<i32> {
    getsockopt_value::<libc::c_int>(fd, level, optname)
}

/// HCI voice setting: bits 0-1 are the air coding format (CVSD, u-law, A-law, transparent),
/// bits 8-9 the input coding (linear, u-law, A-law). Linux uses 0x0060 (CVSD, 16-bit linear PCM
/// input) by default and 0x0003 (transparent) for wideband speech.
fn describe_bt_voice(setting: u16) -> &'static str {
    match (setting & 0x0003, (setting >> 8) & 0x0003) {
        (0x0003, _) => "transparent air coding (encoded data, e.g. mSBC)",
        (0x0000, 0x0000) => "CVSD air coding, linear PCM input",
        (0x0001, 0x0000) => "u-law air coding, linear PCM input",
        (0x0002, 0x0000) => "A-law air coding, linear PCM input",
        (_, 0x0001) => "u-law input coding",
        (_, 0x0002) => "A-law input coding",
        _ => "unknown",
    }
}

/// True when the SCO socket carries 16-bit linear PCM (the only format the bridge handles).
fn is_linear_pcm_voice(setting: u16) -> bool {
    setting & 0x0003 != 0x0003 && (setting >> 8) & 0x0003 == 0
}

/// Confirmed format for the current HSP/SCO path seen on the target phone/HU setup.
///
/// Linux exposes this SCO socket as linear PCM (`BT_VOICE=0x0060`). Runtime
/// logs should still be trusted first, but the observed stream is stable:
/// 60-byte packets at ~266.7 packets/sec = ~16000 B/s = 8000 s16 mono samples/sec.
pub const SCO_LINEAR_PCM_SAMPLE_RATE_HZ: u32 = 8_000;
pub const SCO_LINEAR_PCM_CHANNELS: u16 = 1;
pub const SCO_LINEAR_PCM_BITS_PER_SAMPLE: u16 = 16;

/// Target format for the HU media sink that advertised PCM MEDIA:
/// 48 kHz, signed 16-bit, stereo.
pub const AA_MEDIA_PCM_SAMPLE_RATE_HZ: u32 = 48_000;
pub const AA_MEDIA_PCM_CHANNELS: u16 = 2;
pub const AA_MEDIA_PCM_BITS_PER_SAMPLE: u16 = 16;

#[derive(Debug, Default)]
pub struct DownlinkResamplerState {
    last_sample: Option<i16>,
    enhanced: Option<EnhancedVoice>,
}

/// Direct-form biquad (coefficients normalised by a0).
#[derive(Debug, Clone)]
struct Biquad {
    b0: f32,
    b1: f32,
    b2: f32,
    a1: f32,
    a2: f32,
    x1: f32,
    x2: f32,
    y1: f32,
    y2: f32,
}

impl Biquad {
    fn new(b0: f64, b1: f64, b2: f64, a0: f64, a1: f64, a2: f64) -> Self {
        Self {
            b0: (b0 / a0) as f32,
            b1: (b1 / a0) as f32,
            b2: (b2 / a0) as f32,
            a1: (a1 / a0) as f32,
            a2: (a2 / a0) as f32,
            x1: 0.0,
            x2: 0.0,
            y1: 0.0,
            y2: 0.0,
        }
    }

    fn lowpass(f: f64, fs: f64) -> Self {
        let w = 2.0 * std::f64::consts::PI * f / fs;
        let (c, a) = (w.cos(), w.sin() / 2f64.sqrt());
        Self::new(
            (1.0 - c) / 2.0,
            1.0 - c,
            (1.0 - c) / 2.0,
            1.0 + a,
            -2.0 * c,
            1.0 - a,
        )
    }

    fn highpass(f: f64, fs: f64) -> Self {
        let w = 2.0 * std::f64::consts::PI * f / fs;
        let (c, a) = (w.cos(), w.sin() / 2f64.sqrt());
        Self::new(
            (1.0 + c) / 2.0,
            -(1.0 + c),
            (1.0 + c) / 2.0,
            1.0 + a,
            -2.0 * c,
            1.0 - a,
        )
    }

    fn low_shelf(f: f64, gain_db: f64, fs: f64) -> Self {
        let a = 10f64.powf(gain_db / 40.0);
        let w = 2.0 * std::f64::consts::PI * f / fs;
        let (c, s) = (w.cos(), w.sin());
        let al = s / 2.0 * 2f64.sqrt();
        let sq = 2.0 * a.sqrt() * al;
        Self::new(
            a * ((a + 1.0) - (a - 1.0) * c + sq),
            2.0 * a * ((a - 1.0) - (a + 1.0) * c),
            a * ((a + 1.0) - (a - 1.0) * c - sq),
            (a + 1.0) + (a - 1.0) * c + sq,
            -2.0 * ((a - 1.0) + (a + 1.0) * c),
            (a + 1.0) + (a - 1.0) * c - sq,
        )
    }

    fn process(&mut self, v: f32) -> f32 {
        let o = self.b0 * v + self.b1 * self.x1 + self.b2 * self.x2
            - self.a1 * self.y1
            - self.a2 * self.y2;
        self.x2 = self.x1;
        self.x1 = v;
        self.y2 = self.y1;
        self.y1 = o;
        o
    }
}

const ENH_TAPS_PER_PHASE: usize = 24;
const ENH_FIR_LEN: usize = 6 * ENH_TAPS_PER_PHASE + 1;
/// Output scale that leaves headroom for the low-shelf boost and the exciter before the
/// bridge gain/limiter stage.
const ENH_OUT_SCALE: f32 = 0.85;

/// "Enhanced" call voice: causal polyphase windowed-sinc 6x upsampler (8 -> 48 kHz), +4 dB low
/// shelf at 350 Hz, and a soft exciter that adds harmonics above 3.8 kHz generated from the
/// 2-3.6 kHz band. State is kept across chunks. Tuned by ear with a Python simulation.
#[derive(Debug)]
struct EnhancedVoice {
    taps: Vec<f32>,
    hist: [f32; ENH_TAPS_PER_PHASE + 1],
    shelf: Biquad,
    ex_hp_lo: Biquad,
    ex_lp_hi: Biquad,
    ex_hp: Biquad,
}

impl EnhancedVoice {
    fn new() -> Self {
        let n = ENH_FIR_LEN;
        let (fc, fs) = (3900.0f64, 48000.0f64);
        let mut taps: Vec<f64> = (0..n)
            .map(|i| {
                let x = 2.0 * fc / fs * (i as f64 - (n as f64 - 1.0) / 2.0);
                let sinc = if x == 0.0 {
                    1.0
                } else {
                    (std::f64::consts::PI * x).sin() / (std::f64::consts::PI * x)
                };
                let m = (n - 1) as f64;
                let blackman = 0.42 - 0.5 * (2.0 * std::f64::consts::PI * i as f64 / m).cos()
                    + 0.08 * (4.0 * std::f64::consts::PI * i as f64 / m).cos();
                sinc * blackman
            })
            .collect();
        let sum: f64 = taps.iter().sum();
        for t in taps.iter_mut() {
            *t = *t / sum * 6.0;
        }
        Self {
            taps: taps.into_iter().map(|t| t as f32).collect(),
            hist: [0.0; ENH_TAPS_PER_PHASE + 1],
            shelf: Biquad::low_shelf(350.0, 4.0, 48000.0),
            ex_hp_lo: Biquad::highpass(2000.0, 48000.0),
            ex_lp_hi: Biquad::lowpass(3600.0, 48000.0),
            ex_hp: Biquad::highpass(3800.0, 48000.0),
        }
    }

    fn push_sample(&mut self, input: i16, output: &mut Vec<u8>) {
        for k in (1..self.hist.len()).rev() {
            self.hist[k] = self.hist[k - 1];
        }
        self.hist[0] = input as f32 / 32768.0;
        for p in 0..6 {
            let mut acc = 0.0f32;
            for k in 0..=ENH_TAPS_PER_PHASE {
                let idx = p + 6 * k;
                if idx < ENH_FIR_LEN {
                    acc += self.taps[idx] * self.hist[k];
                }
            }
            let s = self.shelf.process(acc);
            let band = self.ex_lp_hi.process(self.ex_hp_lo.process(s));
            let hf = self.ex_hp.process((3.0 * band).tanh());
            let y = ((s + 0.18 * hf) * ENH_OUT_SCALE * 32768.0).clamp(-32768.0, 32767.0) as i16;
            let b = y.to_le_bytes();
            output.extend_from_slice(&b);
            output.extend_from_slice(&b);
        }
    }
}

/// Convert one chunk of SCO linear PCM (`s16le`, mono, 8 kHz) into the
/// simplest AA media PCM shape (`s16le`, stereo, 48 kHz).
///
/// The default `Repeat` mode preserves the proven first implementation: each
/// 8 kHz sample becomes six identical 48 kHz stereo frames. `Linear` keeps the
/// same output size/timing but interpolates between adjacent samples, which can
/// reduce rough edges without pulling in a resampler dependency.
pub fn sco_s16le_mono_8k_to_aa_pcm_s16le_stereo_48k(
    input: &[u8],
    output: &mut Vec<u8>,
    resampler: BtScoMediaBridgeResampler,
    state: &mut DownlinkResamplerState,
) {
    let even_len = input.len() & !1;

    // Each input i16 sample becomes 6 stereo frames.
    // 2 input bytes -> 6 * 2 channels * 2 output bytes = 24 output bytes.
    output.reserve((even_len / 2) * 24);

    for sample in input[..even_len].chunks_exact(2) {
        let current = i16::from_le_bytes([sample[0], sample[1]]);
        match resampler {
            BtScoMediaBridgeResampler::Repeat => {
                push_stereo_repeated_sample(output, current);
            }
            BtScoMediaBridgeResampler::Linear => {
                let previous = state.last_sample.unwrap_or(current);
                push_stereo_linear_6x(output, previous, current);
            }
            BtScoMediaBridgeResampler::Enhanced => {
                state
                    .enhanced
                    .get_or_insert_with(EnhancedVoice::new)
                    .push_sample(current, output);
            }
        }
        state.last_sample = Some(current);
    }
}

fn push_stereo_repeated_sample(output: &mut Vec<u8>, sample: i16) {
    let bytes = sample.to_le_bytes();
    for _ in 0..6 {
        output.extend_from_slice(&bytes);
        output.extend_from_slice(&bytes);
    }
}

fn push_stereo_linear_6x(output: &mut Vec<u8>, previous: i16, current: i16) {
    let previous = previous as i32;
    let current = current as i32;
    let delta = current - previous;

    // Six output frames bridge the previous sample to the current sample.
    // step=6 lands exactly on `current`, preserving timing and chunk size.
    for step in 1..=6 {
        let interpolated = previous + (delta * step) / 6;
        let sample = interpolated.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        let bytes = sample.to_le_bytes();
        output.extend_from_slice(&bytes);
        output.extend_from_slice(&bytes);
    }
}

/// Streaming sample rate converter for mono s16 PCM: windowed-sinc (Blackman) low-pass at the
/// input rate followed by fractional linear interpolation. Used for downsampling (the low-pass is
/// the anti-alias filter) as well as for upsampling. The filter is only evaluated at the input
/// positions that an output sample needs. State is kept across calls, so a stream can be fed in
/// arbitrary chunks.
#[derive(Debug)]
pub struct PcmResampler {
    out_rate: u32,
    step: f64,
    taps: Vec<f32>,
    hist: Vec<f32>,
    hist_pos: usize,
    prev: f32,
    prev_valid: bool,
    pos: f64,
}

impl PcmResampler {
    /// `cutoff_hz` is the passband edge; it is capped below the Nyquist frequency of both rates.
    pub fn new(in_rate: u32, out_rate: u32, cutoff_hz: u32) -> Self {
        let in_rate = in_rate.max(1);
        let out_rate = out_rate.max(1);
        let cutoff = (cutoff_hz as f64)
            .min(0.45 * in_rate as f64)
            .min(0.45 * out_rate as f64)
            .max(1.0);
        // Blackman transition width is ~5.5 * fs / N; 8 * fs / cutoff keeps it below the cutoff.
        let n = (((8.0 * in_rate as f64 / cutoff) as usize) | 1).clamp(15, 129);
        let m = (n - 1) as f64;
        let mut taps: Vec<f64> = (0..n)
            .map(|i| {
                let x = 2.0 * cutoff / in_rate as f64 * (i as f64 - m / 2.0);
                let sinc = if x == 0.0 {
                    1.0
                } else {
                    (std::f64::consts::PI * x).sin() / (std::f64::consts::PI * x)
                };
                let blackman = 0.42 - 0.5 * (2.0 * std::f64::consts::PI * i as f64 / m).cos()
                    + 0.08 * (4.0 * std::f64::consts::PI * i as f64 / m).cos();
                sinc * blackman
            })
            .collect();
        let sum: f64 = taps.iter().sum();
        for t in taps.iter_mut() {
            *t /= sum;
        }

        Self {
            out_rate,
            step: in_rate as f64 / out_rate as f64,
            taps: taps.into_iter().map(|t| t as f32).collect(),
            hist: vec![0.0; n + 1],
            hist_pos: 0,
            prev: 0.0,
            prev_valid: true,
            pos: 0.0,
        }
    }

    pub fn out_rate(&self) -> u32 {
        self.out_rate
    }

    /// Low-pass output for the input sample `delay` samples before the newest one.
    fn filtered(&self, delay: usize) -> f32 {
        let len = self.hist.len();
        let newest = self.hist_pos + len - 1 - delay;
        self.taps
            .iter()
            .enumerate()
            .map(|(k, tap)| tap * self.hist[(newest - k) % len])
            .sum()
    }

    pub fn push(&mut self, input: i16, out: &mut Vec<i16>) {
        self.hist[self.hist_pos] = input as f32;
        self.hist_pos = (self.hist_pos + 1) % self.hist.len();

        if self.pos < 1.0 {
            // At least one output point lies between the previous input sample (0.0) and
            // this one (1.0).
            let cur = self.filtered(0);
            let prev = if self.prev_valid {
                self.prev
            } else {
                self.filtered(1)
            };
            while self.pos < 1.0 {
                let v = prev + (cur - prev) * self.pos as f32;
                out.push(v.round().clamp(i16::MIN as f32, i16::MAX as f32) as i16);
                self.pos += self.step;
            }
            self.prev = cur;
            self.prev_valid = true;
        } else {
            self.prev_valid = false;
        }
        self.pos -= 1.0;
    }
}

fn format_bdaddr(addr: BdAddr) -> String {
    let b = addr.b;
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[5], b[4], b[3], b[2], b[1], b[0]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sco_converter_expands_8k_mono_to_48k_stereo() {
        // Two input samples: 0x0001 and 0x0002.
        let input = [0x01, 0x00, 0x02, 0x00];
        let mut output = Vec::new();

        sco_s16le_mono_8k_to_aa_pcm_s16le_stereo_48k(
            &input,
            &mut output,
            BtScoMediaBridgeResampler::Repeat,
            &mut DownlinkResamplerState::default(),
        );

        // 2 mono samples * 6x upsample * 2 stereo channels * 2 bytes.
        assert_eq!(output.len(), 48);

        // First upsampled stereo frame should be L=sample1, R=sample1.
        assert_eq!(&output[0..4], &[0x01, 0x00, 0x01, 0x00]);

        // The seventh stereo frame starts the second input sample.
        let second_sample_offset = 6 * 2 * 2;
        assert_eq!(
            &output[second_sample_offset..second_sample_offset + 4],
            &[0x02, 0x00, 0x02, 0x00]
        );
    }

    fn sine(rate: u32, freq: f64, samples: usize, amplitude: f64) -> Vec<i16> {
        (0..samples)
            .map(|i| {
                (amplitude * (2.0 * std::f64::consts::PI * freq * i as f64 / rate as f64).sin())
                    as i16
            })
            .collect()
    }

    fn resample_all(r: &mut PcmResampler, input: &[i16]) -> Vec<i16> {
        let mut out = Vec::new();
        for &s in input {
            r.push(s, &mut out);
        }
        out
    }

    fn peak(samples: &[i16]) -> i32 {
        samples.iter().map(|s| (*s as i32).abs()).max().unwrap_or(0)
    }

    #[test]
    fn resampler_output_length_matches_ratio() {
        for (inr, outr) in [
            (48_000, 16_000),
            (16_000, 8_000),
            (44_100, 8_000),
            (8_000, 16_000),
        ] {
            let mut r = PcmResampler::new(inr, outr, 3_500);
            let out = resample_all(&mut r, &sine(inr, 500.0, inr as usize, 8000.0));
            let diff = (out.len() as i64 - outr as i64).abs();
            assert!(diff <= 1, "{}->{}: {} samples", inr, outr, out.len());
        }
    }

    #[test]
    fn resampler_passes_voice_and_rejects_alias() {
        // 1 kHz is in the voice band and must pass at ~full level.
        let mut r = PcmResampler::new(16_000, 8_000, 3_500);
        let out = resample_all(&mut r, &sine(16_000, 1_000.0, 16_000, 10_000.0));
        let p = peak(&out[100..]);
        assert!((9_000..=10_300).contains(&p), "passband peak={}", p);

        // 6 kHz would alias to 2 kHz with plain decimation; it must be strongly attenuated.
        let mut r = PcmResampler::new(16_000, 8_000, 3_500);
        let out = resample_all(&mut r, &sine(16_000, 6_000.0, 16_000, 10_000.0));
        let p = peak(&out[100..]);
        assert!(p < 500, "alias peak={}", p);
    }

    #[test]
    fn uplink_latency_control_ignores_bursts_and_trims_standing_queue() {
        let t0 = Instant::now();
        let ms = |v: u64| t0 + Duration::from_millis(v);

        // Bursty microphone: the queue drains to 0 between bursts -> nothing to drop.
        let mut c = UplinkLatencyControl::new(t0);
        for i in 0..200u64 {
            let queued = (20 - (i % 20)) as usize % 20;
            assert_eq!(c.observe(queued, ms(i * 7)), None);
        }

        // Standing queue of 30 packets for a whole window -> drop down to the target.
        let mut c = UplinkLatencyControl::new(t0);
        let mut dropped = None;
        for i in 0..150u64 {
            if let Some(n) = c.observe(30 + (i % 3) as usize, ms(i * 7 + 7)) {
                dropped = Some(n);
            }
        }
        assert_eq!(dropped, Some(30 - SCO_UPLINK_TARGET_STANDING_PACKETS));
    }

    #[test]
    fn bt_voice_linear_pcm_detection() {
        assert!(is_linear_pcm_voice(0x0060)); // Linux default: CVSD, 16-bit linear input
        assert!(!is_linear_pcm_voice(0x0003)); // transparent (mSBC / LC3)
        assert!(!is_linear_pcm_voice(0x0160)); // u-law input coding
    }

    #[test]
    fn sco_converter_ignores_trailing_odd_byte() {
        let input = [0x01, 0x00, 0xff];
        let mut output = Vec::new();

        sco_s16le_mono_8k_to_aa_pcm_s16le_stereo_48k(
            &input,
            &mut output,
            BtScoMediaBridgeResampler::Repeat,
            &mut DownlinkResamplerState::default(),
        );

        assert_eq!(output.len(), 24);
    }
}
