//! Pure-Rust H.264 video overlay for displaying live text (e.g. OBD values, sensor data, alerts) on Android Auto frames.
//!
//! Reads JSON (or plain text) from the path configured by `overlay_text_path` in `config.toml`
//! (default `/dev/shm/overlay.json`), splits carriage returns (`\r\n`, `\n`, `\r`) into
//! multiple lines, and renders a translucent box with text near the bottom-right corner of
//! decoded YUV420 (`I420`) video frames before re-encoding to H.264 Baseline Annex-B via `rusty_h264`.

use crate::config::DEFAULT_OVERLAY_TEXT_PATH;
use crate::mitm::protos::{
    DisplayType, MediaCodecType, MediaMessageId, ServiceDiscoveryResponse, VideoFocusMode,
    VideoFocusNotification, VideoFrameRateType,
};
use crate::packet_fragment::{
    fragment_plain_payload, openauto_continuation_fragment_payload_bytes,
    PlainPayloadFragmentOptions, DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES,
};
use protobuf::Message;
use rusty_h264::{Decoder, Encoder, EncoderConfig, YuvFrame};
use serde::{Deserialize, Serialize};
use simplelog::*;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// EASY-TO-ADJUST OVERLAY CONFIGURATION CONSTANTS
// ============================================================================

/// Minimum interval (in milliseconds) between filesystem reads of `overlay_text_path`.
pub const POLL_INTERVAL_MS: u64 = 250;

/// Opacity percentage of the overlay box background (`0` = fully transparent, `100` = fully opaque).
pub const BOX_OPACITY_PERCENT: u8 = 0;

/// Distance in pixels from the right edge of the video frame to the right edge of the box.
pub const BOX_MARGIN_RIGHT_PX: usize = 100;

/// Distance in pixels from the bottom edge of the video frame to the bottom edge of the box.
pub const BOX_MARGIN_BOTTOM_PX: usize = 9;

/// Horizontal internal padding (in pixels) between the box border and the text.
pub const BOX_PADDING_X_PX: usize = 12;

/// Vertical internal padding (in pixels) between the box border and the text.
pub const BOX_PADDING_Y_PX: usize = 9;

/// Border thickness in pixels around the overlay box (`0` disables the border).
pub const BOX_BORDER_PX: usize = 0;

/// Integer scaling factor for the built-in 8x8 bitmap font (`1` = 8x8, `2` = 16x16, `3` = 24x24).
pub const TEXT_SCALE: usize = 2;

/// Extra vertical spacing in pixels between consecutive lines of text.
pub const LINE_SPACING_PX: usize = 6;

/// Extra horizontal spacing in pixels between consecutive characters.
pub const CHAR_SPACING_PX: usize = 1;

/// Maximum number of lines to display inside the overlay box.
pub const MAX_DISPLAY_LINES: usize = 14;

/// Maximum number of characters per line before truncation.
pub const MAX_LINE_CHARS: usize = 42;

/// Background RGB color of the translucent box `(R, G, B)`.
pub const BOX_BG_RGB: (u8, u8, u8) = (16, 22, 32);

/// Border RGB color of the translucent box `(R, G, B)`.
pub const BOX_BORDER_RGB: (u8, u8, u8) = (0, 200, 255);

/// Foreground text RGB color `(R, G, B)`.
pub const TEXT_RGB: (u8, u8, u8) = (245, 250, 255);

/// Drop-shadow RGB color behind text characters for readability `(R, G, B)`.
pub const TEXT_SHADOW_RGB: (u8, u8, u8) = (0, 0, 0);

/// Fixed quantizer parameter (`QP`) for the pure-Rust H.264 Baseline encoder (`0..=51`, lower = higher quality).
pub const H264_ENCODER_QP: u8 = 26;

/// Group of Pictures (`GOP`) keyframe interval in frames for the H.264 encoder.
/// Kept large because keyframes are already forced on demand whenever the Phone sends an IDR
/// or a `VideoFocusNotification` arrives, avoiding unnecessary 70-120ms full I-frame spikes.
pub const H264_ENCODER_GOP: u32 = 600;

/// Only apply overlay to the main projection video channel (set `false` to apply to cluster/aux too).
pub const ONLY_MAIN_DISPLAY: bool = true;

/// Cap `VIDEO_FPS_60` (`16.67ms` per frame) to `VIDEO_FPS_30` (`33.33ms` per frame) in
/// `ServiceDiscoveryResponse` when the overlay is enabled ([`overlay_enabled`]).
/// When `overlay_enabled = false`, `ServiceDiscoveryResponse` and all video packets pass
/// through 100% untouched at native `VIDEO_FPS_60`.
pub const CAP_VIDEO_FPS_TO_30: bool = true;

// ============================================================================
// JSON SCHEMA FOR `/dev/shm/overlay.json`
// ============================================================================

fn deserialize_null_as_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

fn default_text_scale() -> usize {
    TEXT_SCALE
}

fn deserialize_text_scale<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ScaleRepr {
        Int(usize),
        Float(f64),
        Str(String),
    }

    match Option::<ScaleRepr>::deserialize(deserializer)? {
        None => Ok(TEXT_SCALE),
        Some(ScaleRepr::Int(i)) => Ok(i),
        Some(ScaleRepr::Float(f)) => Ok(f.round().max(1.0) as usize),
        Some(ScaleRepr::Str(s)) => s
            .trim()
            .parse::<f64>()
            .map(|f| f.round().max(1.0) as usize)
            .map_err(serde::de::Error::custom),
    }
}

/// Live JSON configuration and text loaded from [`OVERLAY_TEXT_PATH`] (`/dev/shm/overlay.json`).
///
/// Any omitted field automatically defaults to the corresponding constant from
/// `EASY-TO-ADJUST OVERLAY CONFIGURATION CONSTANTS` above. Both `snake_case` and
/// `UPPER_SNAKE_CASE` keys are accepted in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct OverlayConfig {
    #[serde(alias = "POLL_INTERVAL_MS")]
    pub poll_interval_ms: u64,
    #[serde(alias = "BOX_OPACITY_PERCENT")]
    pub box_opacity_percent: u8,
    #[serde(alias = "BOX_MARGIN_RIGHT_PX")]
    pub box_margin_right_px: usize,
    #[serde(alias = "BOX_MARGIN_BOTTOM_PX")]
    pub box_margin_bottom_px: usize,
    #[serde(alias = "BOX_PADDING_X_PX")]
    pub box_padding_x_px: usize,
    #[serde(alias = "BOX_PADDING_Y_PX")]
    pub box_padding_y_px: usize,
    #[serde(alias = "BOX_BORDER_PX")]
    pub box_border_px: usize,
    #[serde(
        default = "default_text_scale",
        alias = "TEXT_SCALE",
        deserialize_with = "deserialize_text_scale"
    )]
    pub text_scale: usize,
    #[serde(
        default,
        alias = "FONT_PATH",
        alias = "font_path",
        alias = "OVERLAY_FONT_PATH",
        deserialize_with = "deserialize_null_as_empty_string"
    )]
    pub font_path: String,
    #[serde(alias = "LINE_SPACING_PX")]
    pub line_spacing_px: usize,
    #[serde(alias = "CHAR_SPACING_PX")]
    pub char_spacing_px: usize,
    #[serde(alias = "MAX_DISPLAY_LINES")]
    pub max_display_lines: usize,
    #[serde(alias = "MAX_LINE_CHARS")]
    pub max_line_chars: usize,
    #[serde(alias = "BOX_BG_RGB")]
    pub box_bg_rgb: (u8, u8, u8),
    #[serde(alias = "BOX_BORDER_RGB")]
    pub box_border_rgb: (u8, u8, u8),
    #[serde(alias = "TEXT_RGB")]
    pub text_rgb: (u8, u8, u8),
    #[serde(alias = "TEXT_SHADOW_RGB")]
    pub text_shadow_rgb: (u8, u8, u8),
    #[serde(alias = "H264_ENCODER_QP")]
    pub h264_encoder_qp: u8,
    #[serde(alias = "H264_ENCODER_GOP")]
    pub h264_encoder_gop: u32,
    #[serde(alias = "ONLY_MAIN_DISPLAY")]
    pub only_main_display: bool,
    #[serde(alias = "CAP_VIDEO_FPS_TO_30")]
    pub cap_video_fps_to_30: bool,
    #[serde(
        default,
        alias = "TEXT",
        deserialize_with = "deserialize_null_as_empty_string"
    )]
    pub text: String,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: POLL_INTERVAL_MS,
            box_opacity_percent: BOX_OPACITY_PERCENT,
            box_margin_right_px: BOX_MARGIN_RIGHT_PX,
            box_margin_bottom_px: BOX_MARGIN_BOTTOM_PX,
            box_padding_x_px: BOX_PADDING_X_PX,
            box_padding_y_px: BOX_PADDING_Y_PX,
            box_border_px: BOX_BORDER_PX,
            text_scale: TEXT_SCALE,
            font_path: String::new(),
            line_spacing_px: LINE_SPACING_PX,
            char_spacing_px: CHAR_SPACING_PX,
            max_display_lines: MAX_DISPLAY_LINES,
            max_line_chars: MAX_LINE_CHARS,
            box_bg_rgb: BOX_BG_RGB,
            box_border_rgb: BOX_BORDER_RGB,
            text_rgb: TEXT_RGB,
            text_shadow_rgb: TEXT_SHADOW_RGB,
            h264_encoder_qp: H264_ENCODER_QP,
            h264_encoder_gop: H264_ENCODER_GOP,
            only_main_display: ONLY_MAIN_DISPLAY,
            cap_video_fps_to_30: CAP_VIDEO_FPS_TO_30,
            text: String::new(),
        }
    }
}

// ============================================================================
// INTERNAL STATE & LIVE TEXT CACHE
// ============================================================================

struct CachedOverlayText {
    path: PathBuf,
    last_check: Option<Instant>,
    config: OverlayConfig,
    lines: Vec<String>,
}

static OVERLAY_TEXT_CACHE: LazyLock<Mutex<CachedOverlayText>> = LazyLock::new(|| {
    Mutex::new(CachedOverlayText {
        path: PathBuf::from(DEFAULT_OVERLAY_TEXT_PATH),
        last_check: None,
        config: OverlayConfig::default(),
        lines: Vec::new(),
    })
});

/// Set at ServiceDiscoveryResponse time from `overlay_enabled`. While `false` every hook in
/// this module returns immediately (single relaxed atomic load: no locks, no file access), so the
/// default build behaves exactly like one without the overlay. Decided once per session on purpose:
/// toggling mid-session would switch between re-encoded and original H.264 streams.
static SESSION_ENABLED: AtomicBool = AtomicBool::new(false);

/// Resolves `path` to [`DEFAULT_OVERLAY_TEXT_PATH`] when empty or whitespace-only.
fn resolve_overlay_text_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    let trimmed = s.trim();
    if trimmed.is_empty() {
        PathBuf::from(DEFAULT_OVERLAY_TEXT_PATH)
    } else {
        PathBuf::from(trimmed)
    }
}

/// Updates the active `overlay_text_path` from `AppConfig` if it changed, falling back to
/// [`DEFAULT_OVERLAY_TEXT_PATH`] when `path` is empty.
pub fn set_overlay_text_path(path: &Path) {
    let resolved = resolve_overlay_text_path(path);
    if let Ok(mut cache) = OVERLAY_TEXT_CACHE.lock() {
        if cache.path != resolved {
            cache.path = resolved;
            cache.last_check = None;
        }
    }
}

/// Largest TTF font size (in pixels) the overlay will ever render. `text_scale` comes from a live,
/// user-writable file and this process is built with `panic = "abort"`, so absurd values must be
/// bounded (a 100000 px glyph bitmap alone needs ~14 GB).
const MAX_TTF_FONT_PX: f32 = 200.0;

/// Largest integer scale of the built-in 8x8 bitmap font (32 -> 256x256 px glyphs).
const MAX_BITMAP_TEXT_SCALE: usize = 32;

/// Minimum interval between checks of the TTF file (existence and modification time).
const FONT_CHECK_INTERVAL: Duration = Duration::from_millis(500);

/// TTF font size in pixels for a given `text_scale`: `1..=4` are presets (12/24/36/48 px, so the
/// default `2` gives 24 px), larger values are the size itself. Always bounded by [`MAX_TTF_FONT_PX`].
fn ttf_base_font_size(text_scale: usize) -> f32 {
    let px = if text_scale <= 4 {
        (text_scale.max(1) * 12) as f32
    } else {
        text_scale as f32
    };
    px.min(MAX_TTF_FONT_PX)
}

struct CachedOverlayFont {
    /// `overlay_font_path` from `config.toml`.
    config_path: PathBuf,
    /// `"font_path"` from the live JSON file; takes precedence over `config_path` when non-empty.
    json_path: PathBuf,
    /// Effective path currently loaded (`json_path` if set, otherwise `config_path`).
    path: PathBuf,
    last_check: Option<Instant>,
    /// Modification time seen by the last load attempt for `path` (`Some(None)` = mtime not
    /// available). `None` = no attempt yet. A failed attempt is not repeated until the file changes.
    attempted_mtime: Option<Option<std::time::SystemTime>>,
    font: Option<Arc<fontdue::Font>>,
}

impl CachedOverlayFont {
    fn refresh_effective_path(&mut self) {
        let effective = if self.json_path.as_os_str().is_empty() {
            self.config_path.clone()
        } else {
            self.json_path.clone()
        };
        if effective != self.path {
            self.path = effective;
            self.last_check = None;
            self.attempted_mtime = None;
            self.font = None;
        }
    }
}

static OVERLAY_FONT_CACHE: LazyLock<Mutex<CachedOverlayFont>> = LazyLock::new(|| {
    Mutex::new(CachedOverlayFont {
        config_path: PathBuf::new(),
        json_path: PathBuf::new(),
        path: PathBuf::new(),
        last_check: None,
        attempted_mtime: None,
        font: None,
    })
});

/// Number of font file read+parse attempts (used by tests to verify they are not repeated).
#[cfg(test)]
static FONT_LOAD_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

fn trimmed_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    PathBuf::from(s.trim())
}

/// Sets the TTF font path from `overlay_font_path` in `config.toml`. Empty or whitespace-only means
/// "no TTF font" (built-in bitmap font). A non-empty `"font_path"` in the live JSON file
/// ([`set_overlay_json_font_path`]) takes precedence over this value.
pub fn set_overlay_font_path(path: &Path) {
    let resolved = trimmed_path(path);
    if let Ok(mut cache) = OVERLAY_FONT_CACHE.lock() {
        if cache.config_path != resolved {
            cache.config_path = resolved;
            cache.refresh_effective_path();
        }
    }
}

/// Sets the TTF font path from `"font_path"` in the live JSON file (empty = not set).
pub fn set_overlay_json_font_path(path: &str) {
    let resolved = trimmed_path(Path::new(path));
    if let Ok(mut cache) = OVERLAY_FONT_CACHE.lock() {
        if cache.json_path != resolved {
            cache.json_path = resolved;
            cache.refresh_effective_path();
        }
    }
}

/// Retrieves the active TTF font if the effective font path exists, is non-empty, and parses
/// successfully. Returns `None` if the path is empty, does not exist, is an empty file (0 bytes),
/// or fails to parse, in which case text rendering falls back to the built-in bitmap font.
///
/// The font file is re-checked at most every [`FONT_CHECK_INTERVAL`] and (re)loaded only when its
/// modification time changes. Reading and parsing a font takes tens of milliseconds, so it is done
/// without holding the cache lock, which is also taken by the packet-handling thread.
pub fn get_cached_overlay_font() -> Option<Arc<fontdue::Font>> {
    let now = Instant::now();

    // Phase 1 (locked): decide whether the file has to be (re)loaded.
    let (path, mtime) = {
        let mut cache = OVERLAY_FONT_CACHE.lock().ok()?;
        if cache.path.as_os_str().is_empty() {
            cache.font = None;
            return None;
        }
        let due = cache
            .last_check
            .map(|last| now.duration_since(last) >= FONT_CHECK_INTERVAL)
            .unwrap_or(true);
        if !due {
            return cache.font.clone();
        }
        cache.last_check = Some(now);
        let path = cache.path.clone();
        match fs::metadata(&path) {
            Ok(meta) if meta.len() > 0 => {
                let mtime = meta.modified().ok();
                if cache.attempted_mtime == Some(mtime) {
                    return cache.font.clone();
                }
                (path, mtime)
            }
            _ => {
                // Missing or empty file: bitmap fallback; retry when it appears.
                cache.font = None;
                cache.attempted_mtime = None;
                return None;
            }
        }
    };

    // Phase 2 (unlocked): read and parse.
    #[cfg(test)]
    FONT_LOAD_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let loaded = match fs::read(&path) {
        Ok(bytes) if !bytes.is_empty() => {
            match fontdue::Font::from_bytes(bytes, fontdue::FontSettings::default()) {
                Ok(font) => {
                    info!("overlay: loaded TTF font from {}", path.display());
                    Some(Arc::new(font))
                }
                Err(err) => {
                    warn!(
                        "overlay: failed to parse TTF font {}: {:?}",
                        path.display(),
                        err
                    );
                    None
                }
            }
        }
        Ok(_) => None,
        Err(e) => {
            warn!(
                "overlay: failed to read TTF font {}: {:?}",
                path.display(),
                e
            );
            None
        }
    };

    // Phase 3 (locked): publish the result unless the path changed in the meantime.
    let mut cache = OVERLAY_FONT_CACHE.lock().ok()?;
    if cache.path == path {
        cache.attempted_mtime = Some(mtime);
        cache.font = loaded;
    }
    cache.font.clone()
}

/// Lightweight per-channel packet gate state locked on `from_stream` (Core 1) for <50ns.
/// Separated from [`VIDEO_DECODERS`] and [`VIDEO_ENCODERS`] so `from_stream` never blocks
/// waiting on background H.264 decode or encode operations.
struct ChannelGateState {
    active_for_current_frame: bool,
    pipeline_engaged: bool,
}

static SESSION_HW_ACCEL: Mutex<crate::config::OverlayHwAccel> =
    Mutex::new(crate::config::OverlayHwAccel::None);
static SESSION_V4L2_DEVICES: Mutex<Option<crate::v4l2_m2m::V4l2CodecDevices>> = Mutex::new(None);

pub enum DecoderBackend {
    Software(Decoder),
    V4l2(crate::v4l2_m2m::V4l2M2mDecoder),
}

pub enum EncoderBackend {
    Software(Encoder),
    V4l2(crate::v4l2_m2m::V4l2M2mEncoder),
}

/// Returns true if the channel currently decodes with the V4L2 hardware decoder.
fn channel_uses_v4l2_decoder(channel: u8) -> bool {
    VIDEO_DECODERS
        .lock()
        .map(|map| {
            map.get(&channel)
                .map(|st| matches!(st.backend, DecoderBackend::V4l2(_)))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Number of consecutive V4L2 encoder timeouts tolerated before falling back to software.
const V4L2_ENC_MAX_CONSECUTIVE_TIMEOUTS: u32 = 10;

/// Per-channel H.264 decoder state owned by the Stage-1 decoder worker (`ovl-h264-dec`, Core 2).
struct ChannelDecoderState {
    backend: DecoderBackend,
    phone_codec_config: Option<Vec<u8>>,
}

impl ChannelDecoderState {
    fn new(channel: u8) -> Self {
        let backend = if let Ok(guard) = SESSION_V4L2_DEVICES.lock() {
            if let Some(devs) = guard.as_ref() {
                match crate::v4l2_m2m::V4l2M2mDecoder::new(&devs.decoder_path) {
                    Ok(dec) => {
                        info!(
                            "overlay: ch {:#04x} initialized V4L2 M2M hardware decoder {}",
                            channel,
                            devs.decoder_path.display()
                        );
                        DecoderBackend::V4l2(dec)
                    }
                    Err(e) => {
                        warn!(
                            "overlay: ch {:#04x} failed to initialize V4L2 decoder ({}): {:?}, using pure-Rust software decoder",
                            channel,
                            devs.decoder_path.display(),
                            e
                        );
                        DecoderBackend::Software(Decoder::new())
                    }
                }
            } else {
                DecoderBackend::Software(Decoder::new())
            }
        } else {
            DecoderBackend::Software(Decoder::new())
        };

        Self {
            backend,
            phone_codec_config: None,
        }
    }

    fn reset_decoder(&mut self, channel: u8) {
        *self = Self::new(channel);
    }
}

/// Per-channel H.264 encoder state owned by the Stage-2 encoder worker (`ovl-h264-enc`, Core 3).
struct ChannelEncoderState {
    display_type: DisplayType,
    encoder: Option<EncoderBackend>,
    encoder_dims: Option<(usize, usize)>,
    encoder_qp_gop: Option<(u8, u32)>,
    emitted_encoder_codec_config: bool,
    force_next_keyframe: bool,
    frames_processed: u64,
    fast_skipped_in_window: u64,
    out_frame_num: u32,
    out_poc_lsb: u32,
    last_encoded_yuv: Option<YuvFrame>,
    last_encoded_lines: Vec<String>,
    last_encoded_cfg: Option<OverlayConfig>,
    hw_enc_timeouts: u32,
}

impl ChannelEncoderState {
    fn new(display_type: DisplayType) -> Self {
        Self {
            display_type,
            encoder: None,
            encoder_dims: None,
            encoder_qp_gop: None,
            emitted_encoder_codec_config: false,
            force_next_keyframe: false,
            frames_processed: 0,
            fast_skipped_in_window: 0,
            out_frame_num: 0,
            out_poc_lsb: 0,
            last_encoded_yuv: None,
            last_encoded_lines: Vec::new(),
            last_encoded_cfg: None,
            hw_enc_timeouts: 0,
        }
    }

    fn reset_encoder(&mut self) {
        self.encoder = None;
        self.encoder_dims = None;
        self.encoder_qp_gop = None;
        self.emitted_encoder_codec_config = false;
        self.force_next_keyframe = true;
        self.out_frame_num = 0;
        self.out_poc_lsb = 0;
        self.last_encoded_yuv = None;
        self.last_encoded_lines.clear();
        self.last_encoded_cfg = None;
    }

    fn ensure_encoder(
        &mut self,
        channel: u8,
        width: usize,
        height: usize,
        qp: u8,
        gop: u32,
    ) -> bool {
        let dims = (width, height);
        let qp_gop = (qp.clamp(0, 51), gop.max(1));
        if self.encoder.is_none()
            || self.encoder_dims != Some(dims)
            || self.encoder_qp_gop != Some(qp_gop)
        {
            let mut enc_backend = None;
            if let Ok(devices) = SESSION_V4L2_DEVICES.lock() {
                if let Some(devs) = devices.as_ref() {
                    match crate::v4l2_m2m::V4l2M2mEncoder::new(
                        &devs.encoder_path,
                        width,
                        height,
                        qp_gop.0,
                        qp_gop.1,
                    ) {
                        Ok(v4l2_enc) => {
                            info!(
                                "overlay: ch {:#04x} ({:?}) initialized V4L2 M2M hardware encoder {} ({}x{}, GOP={})",
                                channel, self.display_type, devs.encoder_path.display(), width, height, qp_gop.1
                            );
                            enc_backend = Some(EncoderBackend::V4l2(v4l2_enc));
                        }
                        Err(e) => {
                            warn!(
                                "overlay: ch {:#04x} failed to initialize V4L2 encoder ({}): {:?}, falling back to pure-Rust software encoder",
                                channel, devs.encoder_path.display(), e
                            );
                        }
                    }
                }
            }

            if enc_backend.is_none() {
                match create_baseline_encoder(width, height, qp_gop.0, qp_gop.1) {
                    Ok(enc) => {
                        debug!(
                            "overlay: ch {:#04x} ({:?}) initialized pure-Rust H.264 Constrained Baseline encoder {}x{} (qp={}, gop={}, weightp=false, zero-latency VUI)",
                            channel, self.display_type, width, height, qp_gop.0, qp_gop.1
                        );
                        enc_backend = Some(EncoderBackend::Software(enc));
                    }
                    Err(e) => {
                        warn!(
                            "overlay: ch {:#04x} failed to initialize H.264 software encoder {}x{}: {:?}",
                            channel, width, height, e
                        );
                        return false;
                    }
                }
            }

            let dims_changed = self.encoder_dims != Some(dims);
            self.encoder = enc_backend;
            self.encoder_dims = Some(dims);
            self.encoder_qp_gop = Some(qp_gop);
            if dims_changed {
                self.emitted_encoder_codec_config = false;
            }
            self.force_next_keyframe = true;
            self.out_frame_num = 0;
            self.out_poc_lsb = 0;
            self.last_encoded_yuv = None;
            self.last_encoded_lines.clear();
            self.last_encoded_cfg = None;
        }
        true
    }

    pub fn get_sps_pps(&self, qp: u8) -> Option<Vec<u8>> {
        let (w, h) = self.encoder_dims?;
        match &self.encoder {
            Some(EncoderBackend::V4l2(v4l2_enc)) => {
                let hdr = v4l2_enc.header_bytes();
                if !hdr.is_empty() {
                    Some(hdr.to_vec())
                } else {
                    // Never pair a software-built SPS/PPS with a hardware-encoded stream; the
                    // real headers are taken from the first hardware IDR access unit instead.
                    None
                }
            }
            Some(EncoderBackend::Software(_)) | None => {
                Some(build_car_hu_sps_pps_annex_b(w, h, qp.clamp(0, 51)))
            }
        }
    }
}

/// Builds a pure-Rust H.264 Constrained Baseline encoder tuned for strict Car Head Unit
/// hardware decoders and low-CPU single-pass encoding.
fn create_baseline_encoder(
    width: usize,
    height: usize,
    qp: u8,
    gop_size: u32,
) -> Result<Encoder, rusty_h264::EncodeError> {
    let mut enc_cfg = EncoderConfig::baseline(width, height);
    enc_cfg.qp = qp.clamp(0, 51);
    enc_cfg.gop_size = gop_size.max(1);
    enc_cfg.aq_strength = 0.0;
    // CRITICAL FIX for Car Head Unit hardware H.264 decoders:
    // `EncoderConfig::baseline()` inherits `weightp = true` from `EncoderConfig::defaults()`,
    // which emits `weighted_pred_flag = 1` in the PPS and `pred_weight_table()` in P-slices.
    // Per ITU-T H.264 Annex A.2.1, `weighted_pred_flag` MUST be 0 in Baseline Profile (66).
    // `desktop-head-unit` (FFmpeg software decoder) ignores this, whereas Car HU hardware
    // Baseline decoders reject P-frames or stall when `weighted_pred_flag = 1`.
    enc_cfg.weightp = false;
    // Disable extra multi-pass / SATD / RD / QP-cascade tools left on by `defaults()`:
    enc_cfg.i_qp_offset = 0;
    enc_cfg.tune_satd_q = 0.0;
    enc_cfg.coded_path_v2 = true;
    enc_cfg.tune_sub8x8_split = false;
    enc_cfg.tune_sub8_rd = false;
    enc_cfg.tune_intra_rd = false;
    enc_cfg.tune_shape_rd = false;
    enc_cfg.tune_rd_skip = false;
    enc_cfg.tune_intra_penalty = 1_000_000.0;
    enc_cfg.sub_8x8 = Some(false);
    enc_cfg.me_wide = Some(false);
    Encoder::new(enc_cfg)
}

static CHANNEL_GATES: LazyLock<Mutex<HashMap<u8, ChannelGateState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static VIDEO_DECODERS: LazyLock<Mutex<HashMap<u8, ChannelDecoderState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static VIDEO_ENCODERS: LazyLock<Mutex<HashMap<u8, ChannelEncoderState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Number of media messages currently in flight inside the 2-thread background pipeline.
static PIPELINE_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

// ============================================================================
// MULTI-CORE BACKGROUND PIPELINE (Core 2: `ovl-h264-dec`, Core 3: `ovl-h264-enc`)
// ============================================================================

struct Stage1Job {
    channel: u8,
    base_flags: u8,
    frame_data: Vec<u8>,
    out_tx: tokio::sync::mpsc::Sender<crate::mitm::Packet>,
}

enum Stage2Job {
    DecodedData {
        channel: u8,
        base_flags: u8,
        timestamp_bytes: [u8; 8],
        yuv: YuvFrame,
        in_len: usize,
        dec_dur: Duration,
        incoming_has_idr: bool,
        fallback_frame_data: Vec<u8>,
        out_tx: tokio::sync::mpsc::Sender<crate::mitm::Packet>,
    },
    CodecConfig {
        channel: u8,
        base_flags: u8,
        frame_data: Vec<u8>,
        parsed_dims: Option<(usize, usize)>,
        out_tx: tokio::sync::mpsc::Sender<crate::mitm::Packet>,
    },
    VideoFocus {
        channel: u8,
        base_flags: u8,
        frame_data: Vec<u8>,
        force_keyframe: bool,
        out_tx: tokio::sync::mpsc::Sender<crate::mitm::Packet>,
    },
    PassThrough {
        channel: u8,
        base_flags: u8,
        frame_data: Vec<u8>,
        out_tx: tokio::sync::mpsc::Sender<crate::mitm::Packet>,
    },
}

struct WorkerQueue<T> {
    queue: Mutex<VecDeque<T>>,
    cv: Condvar,
}

impl<T> WorkerQueue<T> {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(16)),
            cv: Condvar::new(),
        }
    }

    fn push(&self, item: T) {
        if let Ok(mut guard) = self.queue.lock() {
            guard.push_back(item);
            self.cv.notify_one();
        }
    }
}

struct MulticorePipeline {
    stage1: &'static WorkerQueue<Stage1Job>,
}

static STAGE1_QUEUE: LazyLock<WorkerQueue<Stage1Job>> = LazyLock::new(WorkerQueue::new);
static STAGE2_QUEUE: LazyLock<WorkerQueue<Stage2Job>> = LazyLock::new(WorkerQueue::new);

static MULTICORE_PIPELINE: LazyLock<MulticorePipeline> = LazyLock::new(|| {
    let stage1: &'static WorkerQueue<Stage1Job> = &STAGE1_QUEUE;
    let stage2: &'static WorkerQueue<Stage2Job> = &STAGE2_QUEUE;

    let _ = thread::Builder::new()
        .name("ovl-h264-dec".to_string())
        .spawn(move || stage1_decoder_worker_loop(stage1, stage2));

    let _ = thread::Builder::new()
        .name("ovl-h264-enc".to_string())
        .spawn(move || stage2_encoder_worker_loop(stage2));

    info!("overlay: started 2-thread multi-core H.264 pipeline (ovl-h264-dec + ovl-h264-enc)");
    MulticorePipeline { stage1 }
});

/// Enqueues a reassembled video media message from `from_stream` (Core 1) into the
/// multi-core H.264 pipeline (`ovl-h264-dec` on Core 2 -> `ovl-h264-enc` on Core 3 -> `from_file` on Core 4).
///
/// Never blocks `from_stream`, keeping Touch `InputReport` and `MEDIA_MESSAGE_ACK` latency at 0.00ms.
pub fn enqueue_video_media_message(
    channel: u8,
    base_flags: u8,
    frame_data: Vec<u8>,
    out_tx: tokio::sync::mpsc::Sender<crate::mitm::Packet>,
) {
    PIPELINE_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
    MULTICORE_PIPELINE.stage1.push(Stage1Job {
        channel,
        base_flags,
        frame_data,
        out_tx,
    });
}

fn stage1_decoder_worker_loop(
    stage1: &'static WorkerQueue<Stage1Job>,
    stage2: &'static WorkerQueue<Stage2Job>,
) {
    loop {
        let job = {
            let mut guard = match stage1.queue.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            while guard.is_empty() {
                guard = match stage1.cv.wait(guard) {
                    Ok(g) => g,
                    Err(_) => return,
                };
            }
            guard.pop_front().unwrap()
        };

        if job.frame_data.len() < 2 {
            stage2.push(Stage2Job::PassThrough {
                channel: job.channel,
                base_flags: job.base_flags,
                frame_data: job.frame_data,
                out_tx: job.out_tx,
            });
            continue;
        }

        let msg_id = u16::from_be_bytes([job.frame_data[0], job.frame_data[1]]) as i32;

        if msg_id == MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG as i32 {
            let annex_b = &job.frame_data[2..];
            let parsed_dims = parse_sps_dimensions_annex_b(annex_b);
            observe_codec_config_decoder_only(job.channel, annex_b);
            stage2.push(Stage2Job::CodecConfig {
                channel: job.channel,
                base_flags: job.base_flags,
                frame_data: job.frame_data,
                parsed_dims,
                out_tx: job.out_tx,
            });
            continue;
        }

        if msg_id == MediaMessageId::MEDIA_MESSAGE_VIDEO_FOCUS_NOTIFICATION as i32 {
            let force_keyframe = VideoFocusNotification::parse_from_bytes(&job.frame_data[2..])
                .map(|notif| {
                    matches!(
                        notif.focus(),
                        VideoFocusMode::VIDEO_FOCUS_PROJECTED
                            | VideoFocusMode::VIDEO_FOCUS_PROJECTED_NO_INPUT_FOCUS
                    )
                })
                .unwrap_or(false);
            stage2.push(Stage2Job::VideoFocus {
                channel: job.channel,
                base_flags: job.base_flags,
                frame_data: job.frame_data,
                force_keyframe,
                out_tx: job.out_tx,
            });
            continue;
        }

        if msg_id != MediaMessageId::MEDIA_MESSAGE_DATA as i32 || job.frame_data.len() <= 10 {
            stage2.push(Stage2Job::PassThrough {
                channel: job.channel,
                base_flags: job.base_flags,
                frame_data: job.frame_data,
                out_tx: job.out_tx,
            });
            continue;
        }

        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&job.frame_data[2..10]);
        let h264_au = &job.frame_data[10..];
        let in_len = h264_au.len();

        let hw_decoder = channel_uses_v4l2_decoder(job.channel);
        match decode_video_access_unit(job.channel, h264_au) {
            Some((yuv, dec_dur, incoming_has_idr)) => {
                stage2.push(Stage2Job::DecodedData {
                    channel: job.channel,
                    base_flags: job.base_flags,
                    timestamp_bytes,
                    yuv,
                    in_len,
                    dec_dur,
                    incoming_has_idr,
                    fallback_frame_data: job.frame_data,
                    out_tx: job.out_tx,
                });
            }
            None if hw_decoder => {
                // The V4L2 decoder is pipelined: no frame ready yet. Forwarding the phone's
                // original access unit would mix two different H.264 streams, so drop it.
                PIPELINE_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
            }
            None => {
                stage2.push(Stage2Job::PassThrough {
                    channel: job.channel,
                    base_flags: job.base_flags,
                    frame_data: job.frame_data,
                    out_tx: job.out_tx,
                });
            }
        }
    }
}

fn stage2_encoder_worker_loop(stage2: &'static WorkerQueue<Stage2Job>) {
    loop {
        let (job, has_newer_frame_in_queue) = {
            let mut guard = match stage2.queue.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            while guard.is_empty() {
                guard = match stage2.cv.wait(guard) {
                    Ok(g) => g,
                    Err(_) => return,
                };
            }
            let popped = guard.pop_front().unwrap();
            let has_newer = match &popped {
                Stage2Job::DecodedData { channel, .. } => guard.iter().any(
                    |item| matches!(item, Stage2Job::DecodedData { channel: ch, .. } if ch == channel),
                ),
                _ => false,
            };
            (popped, has_newer)
        };

        match job {
            Stage2Job::PassThrough {
                channel,
                base_flags,
                frame_data,
                out_tx,
            } => {
                send_media_messages_to_hu(channel, base_flags, &[frame_data], &out_tx);
            }
            Stage2Job::CodecConfig {
                channel,
                base_flags,
                frame_data,
                parsed_dims,
                out_tx,
            } => {
                observe_codec_config_encoder_only(channel, parsed_dims);
                let (out_msgs, _) = process_video_codec_config_in_place(channel, frame_data);
                send_media_messages_to_hu(channel, base_flags, &out_msgs, &out_tx);
            }
            Stage2Job::VideoFocus {
                channel,
                base_flags,
                frame_data,
                force_keyframe,
                out_tx,
            } => {
                if force_keyframe {
                    if let Ok(mut map) = VIDEO_ENCODERS.lock() {
                        if let Some(state) = map.get_mut(&channel) {
                            state.force_next_keyframe = true;
                        }
                    }
                }
                send_media_messages_to_hu(channel, base_flags, &[frame_data], &out_tx);
            }
            Stage2Job::DecodedData {
                channel,
                base_flags,
                timestamp_bytes,
                yuv,
                in_len,
                dec_dur,
                incoming_has_idr,
                fallback_frame_data,
                out_tx,
            } => {
                let (cfg, lines) = get_cached_overlay_config_and_lines();
                let (out_msgs, _) = encode_decoded_video_frame(
                    channel,
                    &timestamp_bytes,
                    yuv,
                    in_len,
                    dec_dur,
                    incoming_has_idr,
                    &lines,
                    &cfg,
                    has_newer_frame_in_queue,
                    fallback_frame_data,
                );
                send_media_messages_to_hu(channel, base_flags, &out_msgs, &out_tx);
            }
        }

        PIPELINE_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

fn send_media_messages_to_hu(
    channel: u8,
    base_flags: u8,
    out_frames: &[Vec<u8>],
    out_tx: &tokio::sync::mpsc::Sender<crate::mitm::Packet>,
) {
    let first_chunk = DEFAULT_FIRST_FRAGMENT_PAYLOAD_BYTES;
    let cont_chunk = openauto_continuation_fragment_payload_bytes(first_chunk);
    for out_frame in out_frames {
        let opts = PlainPayloadFragmentOptions {
            channel,
            base_flags,
            first_fragment_payload_bytes: first_chunk,
            continuation_fragment_payload_bytes: cont_chunk,
            first_final_length: u32::try_from(out_frame.len()).ok(),
        };
        for pkt in fragment_plain_payload(out_frame, opts) {
            if out_tx.blocking_send(pkt).is_err() {
                return;
            }
        }
    }
}

/// Returns `true` when the overlay is enabled for the current session (`overlay_enabled = true`).
pub fn overlay_enabled() -> bool {
    SESSION_ENABLED.load(Ordering::Relaxed)
}

/// Registers video media sink channels discovered in `ServiceDiscoveryResponse`.
///
/// When `enabled` (`overlay_enabled = true`), the overlay pipeline starts immediately for the
/// session using the configured `overlay_text_path` (or [`DEFAULT_OVERLAY_TEXT_PATH`] if empty) and
/// default [`OverlayConfig`] values if the file is missing/empty. Even if `"text"` is initially
/// empty, the H.264 pipeline engages from the start so text can be added or updated live at any time.
pub fn register_video_channels_from_sdr(
    sdr: &mut ServiceDiscoveryResponse,
    enabled: bool,
    overlay_text_path: &Path,
    overlay_font_path: &Path,
    hw_accel: crate::config::OverlayHwAccel,
    v4l2_decoder: &str,
    v4l2_encoder: &str,
) {
    SESSION_ENABLED.store(enabled, Ordering::Release);
    if let Ok(mut lock) = SESSION_HW_ACCEL.lock() {
        *lock = hw_accel;
    }
    if enabled && hw_accel != crate::config::OverlayHwAccel::None {
        let probed =
            crate::v4l2_m2m::probe_v4l2_codec_devices(Some(v4l2_decoder), Some(v4l2_encoder));
        if let Some(devs) = &probed {
            info!(
                "overlay: V4L2 M2M hardware acceleration enabled (decoder: {}, encoder: {})",
                devs.decoder_path.display(),
                devs.encoder_path.display()
            );
        } else {
            info!(
                "overlay: V4L2 M2M hardware codecs not found or not accessible, using pure-Rust software pipeline"
            );
        }
        if let Ok(mut lock) = SESSION_V4L2_DEVICES.lock() {
            *lock = probed;
        }
    } else {
        if let Ok(mut lock) = SESSION_V4L2_DEVICES.lock() {
            *lock = None;
        }
    }

    if !enabled {
        set_overlay_font_path(Path::new(""));
        set_overlay_json_font_path("");
        // Drop any state left over from a previous (enabled) session.
        if let (Ok(mut g), Ok(mut d), Ok(mut e)) = (
            CHANNEL_GATES.lock(),
            VIDEO_DECODERS.lock(),
            VIDEO_ENCODERS.lock(),
        ) {
            g.clear();
            d.clear();
            e.clear();
        }
        return;
    }
    let resolved_path = resolve_overlay_text_path(overlay_text_path);
    set_overlay_text_path(&resolved_path);
    set_overlay_font_path(overlay_font_path);
    let (cfg, _lines) = get_cached_overlay_config_and_lines();

    let mut gates = match CHANNEL_GATES.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let mut decoders = match VIDEO_DECODERS.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let mut encoders = match VIDEO_ENCODERS.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    gates.clear();
    decoders.clear();
    encoders.clear();

    for svc in &mut sdr.services {
        let Ok(ch) = u8::try_from(svc.id()) else {
            continue;
        };
        let Some(sink) = svc.media_sink_service.as_mut() else {
            continue;
        };
        let is_video = sink.available_type() == MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP
            || !sink.video_configs.is_empty();
        if !is_video {
            continue;
        }
        let display_type = sink.display_type();
        if cfg.only_main_display && display_type != DisplayType::DISPLAY_TYPE_MAIN {
            debug!(
                "overlay: skipping non-main video channel {:#04x} ({:?})",
                ch, display_type
            );
            continue;
        }

        if cfg.cap_video_fps_to_30 {
            let mut capped_count = 0usize;
            for vc in &mut sink.video_configs {
                if vc.frame_rate() == VideoFrameRateType::VIDEO_FPS_60 {
                    vc.set_frame_rate(VideoFrameRateType::VIDEO_FPS_30);
                    capped_count += 1;
                }
            }
            if capped_count > 0 {
                info!(
                    "overlay: capped ch {:#04x} ({:?}) video_configs frame_rate VIDEO_FPS_60 -> VIDEO_FPS_30 ({} config(s))",
                    ch, display_type, capped_count
                );
            }
        }

        info!(
            "overlay: registered video channel {:#04x} ({:?}) for text overlay from {}",
            ch,
            display_type,
            resolved_path.display()
        );
        gates.insert(
            ch,
            ChannelGateState {
                active_for_current_frame: true,
                pipeline_engaged: true,
            },
        );
        decoders.insert(ch, ChannelDecoderState::new(ch));
        encoders.insert(ch, ChannelEncoderState::new(display_type));
    }
}

/// Returns `true` if `channel` is a registered H.264 video channel.
pub fn is_registered_video_channel(channel: u8) -> bool {
    if !SESSION_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    CHANNEL_GATES
        .lock()
        .map(|map| map.contains_key(&channel))
        .unwrap_or(false)
}

/// Returns `true` if the overlay is currently enabled and engaged on `channel`.
pub fn is_active_for_channel(channel: u8) -> bool {
    if !SESSION_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    let overlay_now = overlay_enabled() || PIPELINE_IN_FLIGHT.load(Ordering::Acquire) > 0;
    CHANNEL_GATES
        .lock()
        .map(|map| {
            map.get(&channel)
                .map(|s| s.pipeline_engaged || overlay_now)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Evaluates whether the overlay is active for a specific packet on `channel`, latching the
/// decision on `FRAME_TYPE_FIRST` (`0x01`) so multi-fragment frames are never split mid-message.
///
/// When `overlay_enabled = true`, `pipeline_engaged` is `true` from the start of the session
/// even if `"text"` in `overlay_text_path` is initially empty, so text can be added or cleared live
/// at any point while maintaining a single continuous H.264 bitstream.
pub fn is_active_for_packet(
    channel: u8,
    flags: u8,
    overlay_text_path: &Path,
    overlay_font_path: &Path,
) -> bool {
    if !SESSION_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    let is_first_fragment = (flags & crate::mitm::FRAME_TYPE_FIRST) != 0;
    let overlay_now = if is_first_fragment {
        set_overlay_text_path(overlay_text_path);
        set_overlay_font_path(overlay_font_path);
        overlay_enabled()
    } else {
        false
    };
    let in_flight = if is_first_fragment {
        PIPELINE_IN_FLIGHT.load(Ordering::Acquire) > 0
    } else {
        false
    };

    let mut map = match CHANNEL_GATES.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };
    let Some(state) = map.get_mut(&channel) else {
        return false;
    };

    if is_first_fragment {
        if overlay_now {
            state.pipeline_engaged = true;
        }
        state.active_for_current_frame = state.pipeline_engaged || in_flight;
    }
    state.active_for_current_frame
}

fn observe_codec_config_decoder_only(channel: u8, annex_b: &[u8]) {
    if let Ok(mut map) = VIDEO_DECODERS.lock() {
        if let Some(state) = map.get_mut(&channel) {
            state.reset_decoder(channel);
            state.phone_codec_config = Some(annex_b.to_vec());
            match &mut state.backend {
                DecoderBackend::V4l2(v4l2_dec) => {
                    let _ = v4l2_dec.decode(annex_b);
                }
                DecoderBackend::Software(sw_dec) => {
                    if let Err(e) = sw_dec.decode(annex_b) {
                        warn!(
                            "overlay: ch {:#04x} failed to decode CODEC_CONFIG ({} bytes): {:?}",
                            channel,
                            annex_b.len(),
                            e
                        );
                    }
                }
            }
        }
    }
}

fn observe_codec_config_encoder_only(channel: u8, parsed_dims: Option<(usize, usize)>) {
    let (cfg, _) = get_cached_overlay_config_and_lines();
    if let Ok(mut map) = VIDEO_ENCODERS.lock() {
        if let Some(state) = map.get_mut(&channel) {
            state.reset_encoder();
            if let Some((w, h)) = parsed_dims {
                let _ =
                    state.ensure_encoder(channel, w, h, cfg.h264_encoder_qp, cfg.h264_encoder_gop);
            }
        }
    }
}

/// Records `MEDIA_MESSAGE_CODEC_CONFIG` (SPS/PPS) on registered video channels even while
/// `overlay_text_path` is empty so the H.264 decoder is ready whenever text is written.
pub fn observe_codec_config(channel: u8, frame_data: &[u8]) {
    if frame_data.len() <= 2 {
        return;
    }
    let msg_id = u16::from_be_bytes([frame_data[0], frame_data[1]]) as i32;
    if msg_id != MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG as i32 {
        return;
    }
    let annex_b = &frame_data[2..];
    let parsed_dims = parse_sps_dimensions_annex_b(annex_b);
    observe_codec_config_decoder_only(channel, annex_b);
    observe_codec_config_encoder_only(channel, parsed_dims);
}

/// Polls the configured `overlay_text_path` at most once every `poll_interval_ms` and returns `(config, lines)`.
pub fn get_cached_overlay_config_and_lines() -> (OverlayConfig, Vec<String>) {
    let now = Instant::now();

    let mut cache = match OVERLAY_TEXT_CACHE.lock() {
        Ok(guard) => guard,
        Err(_) => return (OverlayConfig::default(), Vec::new()),
    };

    let poll_interval = Duration::from_millis(cache.config.poll_interval_ms.max(20));
    let should_reload = cache
        .last_check
        .map(|last| now.duration_since(last) >= poll_interval)
        .unwrap_or(true);

    if should_reload {
        cache.last_check = Some(now);
        match fs::read_to_string(&cache.path) {
            Ok(raw) => {
                // Templates (`{{name}}`) are expanded on every poll, also when the file itself did
                // not change, because the live data behind them does.
                let (cfg, lines) = if raw.contains("{{") {
                    parse_overlay_payload_with(&raw, Some(&crate::overlay_vars::expand_current))
                } else {
                    parse_overlay_payload(&raw)
                };
                cache.config = cfg;
                cache.lines = lines;
            }
            Err(_) => {
                cache.config = OverlayConfig::default();
                cache.lines.clear();
            }
        }
        set_overlay_json_font_path(&cache.config.font_path);
    }

    (cache.config.clone(), cache.lines.clone())
}

/// Polls the configured `overlay_text_path` at most once every `poll_interval_ms` and returns the parsed lines.
pub fn get_cached_overlay_lines() -> Vec<String> {
    get_cached_overlay_config_and_lines().1
}

/// Parses the contents of `overlay_text_path` (default `/dev/shm/overlay.json`) as JSON
/// ([`OverlayConfig`], with fallback to plain text if not JSON) and splits the `"text"`
/// field on `\r\n`, `\n`, or `\r` into display lines.
pub fn parse_overlay_payload(raw: &str) -> (OverlayConfig, Vec<String>) {
    parse_overlay_payload_with(raw, None)
}

/// Same as [`parse_overlay_payload`], with an optional template expander applied to the text
/// before it is split into lines (see `overlay_vars`).
pub fn parse_overlay_payload_with(
    raw: &str,
    expand: Option<&dyn Fn(&str) -> String>,
) -> (OverlayConfig, Vec<String>) {
    let expand_text = |t: &str| -> String {
        match expand {
            Some(f) => f(t),
            None => t.to_string(),
        }
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (OverlayConfig::default(), Vec::new());
    }

    if trimmed.starts_with('{') {
        let parsed_json = serde_json::from_str::<OverlayConfig>(trimmed).or_else(|_| {
            let sanitized = escape_raw_newlines_in_json_strings(trimmed);
            serde_json::from_str::<OverlayConfig>(&sanitized)
        });
        match parsed_json {
            Ok(cfg) => {
                let lines = parse_overlay_text_lines_with_limits(
                    &expand_text(&cfg.text),
                    cfg.max_display_lines,
                    cfg.max_line_chars,
                );
                return (cfg, lines);
            }
            Err(e) => {
                warn!("overlay: failed to parse JSON payload: {:?}", e);
                return (OverlayConfig::default(), Vec::new());
            }
        }
    }

    let cfg = OverlayConfig::default();
    let lines = parse_overlay_text_lines_with_limits(
        &expand_text(raw),
        cfg.max_display_lines,
        cfg.max_line_chars,
    );
    (cfg, lines)
}

/// Sanitizes unescaped raw `\r` or `\n` control characters inside JSON string literals so
/// multiline shell heredocs written to `/dev/shm/overlay.json` still parse as valid JSON.
fn escape_raw_newlines_in_json_strings(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    let mut in_string = false;
    let mut escaped = false;

    for ch in input.chars() {
        if in_string {
            if escaped {
                escaped = false;
                out.push(ch);
            } else if ch == '\\' {
                escaped = true;
                out.push(ch);
            } else if ch == '"' {
                in_string = false;
                out.push(ch);
            } else if ch == '\r' {
                out.push_str("\\r");
            } else if ch == '\n' {
                out.push_str("\\n");
            } else {
                out.push(ch);
            }
        } else {
            if ch == '"' {
                in_string = true;
            }
            out.push(ch);
        }
    }
    out
}

/// Parses text into display lines using [`MAX_DISPLAY_LINES`] and [`MAX_LINE_CHARS`].
///
/// If `raw` is a JSON object (`{ ... }`), extracts and parses its `"text"` field;
/// otherwise parses `raw` directly.
///
/// Handles all carriage return / newline conventions:
/// - Windows CRLF (`\r\n` or `\\r\\n`)
/// - Unix LF (`\n` or `\\n`)
/// - Classic carriage return CR (`\r` or `\\r`)
pub fn parse_overlay_text_lines(raw: &str) -> Vec<String> {
    if raw.trim_start().starts_with('{') {
        return parse_overlay_payload(raw).1;
    }
    parse_overlay_text_lines_with_limits(raw, MAX_DISPLAY_LINES, MAX_LINE_CHARS)
}

fn normalize_html_breaks(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '<' {
            let mut tag = String::new();
            while let Some(&tc) = chars.peek() {
                chars.next();
                if tc == '>' {
                    break;
                }
                tag.push(tc);
            }
            let tag_lower = tag.trim().to_ascii_lowercase();
            if tag_lower == "br"
                || tag_lower == "br/"
                || tag_lower.starts_with("br ")
                || tag_lower == "/p"
                || tag_lower == "/div"
            {
                out.push('\n');
            } else {
                out.push('<');
                out.push_str(&tag);
                out.push('>');
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn truncate_line_respecting_html(s: &str, max_visible_chars: usize) -> String {
    if !s.contains('<') {
        return truncate_line(s, max_visible_chars);
    }
    let mut out = String::with_capacity(s.len());
    let mut visible_count = 0;
    let mut in_tag = false;
    for ch in s.chars() {
        if ch == '<' {
            in_tag = true;
            out.push(ch);
        } else if ch == '>' {
            in_tag = false;
            out.push(ch);
        } else if in_tag {
            out.push(ch);
        } else if visible_count < max_visible_chars {
            out.push(ch);
            visible_count += 1;
        }
    }
    out
}

fn parse_overlay_text_lines_with_limits(
    raw: &str,
    max_display_lines: usize,
    max_line_chars: usize,
) -> Vec<String> {
    if raw.trim().is_empty() {
        return Vec::new();
    }

    // Normalize both escaped sequences (\\r\\n, \\n, \\r) and raw characters (\r\n, \r, \n)
    let preprocessed = raw
        .replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n")
        .replace("\r\n", "\n")
        .replace('\r', "\n");

    let normalized = normalize_html_breaks(&preprocessed);

    let char_limit = max_line_chars.max(1);
    let mut lines: Vec<String> = normalized
        .split('\n')
        .map(|line| {
            let expanded = line.replace('\t', "  ");
            let trimmed_end = expanded.trim_end();
            truncate_line_respecting_html(trimmed_end, char_limit)
        })
        .collect();

    // Remove leading/trailing completely empty lines (e.g. trailing newline at EOF),
    // while preserving intentional blank lines between non-empty lines.
    while lines.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
        lines.remove(0);
    }
    while lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        lines.pop();
    }

    lines.truncate(max_display_lines.max(1));
    lines
}

fn truncate_line(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect()
    }
}

// ============================================================================
// H.264 MEDIA MESSAGE PROCESSOR
// ============================================================================

/// Processes a reassembled Android Auto media channel message on `channel`.
///
/// Returns `(out_messages, was_modified)`:
/// - `out_messages`: One or more complete media channel payloads (each starting with the 2-byte
///   big-endian `MediaMessageId`). When `MEDIA_MESSAGE_CODEC_CONFIG` arrives while the overlay is
///   active, it is replaced in-place (1-to-1) with the overlay encoder's Constrained Baseline
///   SPS+PPS so the Head Unit never sees two conflicting `CODEC_CONFIG` messages or extra packets.
/// - `was_modified`: `true` if the payload was re-encoded or rewritten.
pub fn process_video_media_message(channel: u8, frame_data: Vec<u8>) -> (Vec<Vec<u8>>, bool) {
    if frame_data.len() < 2 {
        return (vec![frame_data], false);
    }

    let msg_id = u16::from_be_bytes([frame_data[0], frame_data[1]]) as i32;

    if msg_id == MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG as i32 {
        observe_codec_config(channel, &frame_data);
        return process_video_codec_config_in_place(channel, frame_data);
    }

    if msg_id == MediaMessageId::MEDIA_MESSAGE_VIDEO_FOCUS_NOTIFICATION as i32 {
        if let Ok(notif) = VideoFocusNotification::parse_from_bytes(&frame_data[2..]) {
            if matches!(
                notif.focus(),
                VideoFocusMode::VIDEO_FOCUS_PROJECTED
                    | VideoFocusMode::VIDEO_FOCUS_PROJECTED_NO_INPUT_FOCUS
            ) {
                if let Ok(mut map) = VIDEO_ENCODERS.lock() {
                    if let Some(state) = map.get_mut(&channel) {
                        state.force_next_keyframe = true;
                    }
                }
            }
        }
        return (vec![frame_data], false);
    }

    if msg_id != MediaMessageId::MEDIA_MESSAGE_DATA as i32 || frame_data.len() <= 10 {
        return (vec![frame_data], false);
    }

    let (cfg, lines) = get_cached_overlay_config_and_lines();
    process_video_data_frame_with_config(channel, frame_data, &lines, &cfg)
}

/// Replaces `MEDIA_MESSAGE_CODEC_CONFIG` (`0x0001`) in-place (1 message in -> 1 message out)
/// with the overlay encoder's Car-HU-compliant Constrained Baseline SPS+PPS.
pub fn process_video_codec_config_in_place(
    channel: u8,
    frame_data: Vec<u8>,
) -> (Vec<Vec<u8>>, bool) {
    let (cfg, _) = get_cached_overlay_config_and_lines();
    if let Ok(mut map) = VIDEO_ENCODERS.lock() {
        if let Some(state) = map.get_mut(&channel) {
            if let Some(sps_pps) = state.get_sps_pps(cfg.h264_encoder_qp) {
                let codec_cfg_id =
                    (MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG as u16).to_be_bytes();
                let mut codec_msg = Vec::with_capacity(2 + sps_pps.len());
                codec_msg.extend_from_slice(&codec_cfg_id);
                codec_msg.extend_from_slice(&sps_pps);
                state.emitted_encoder_codec_config = true;
                return (vec![codec_msg], true);
            }
        }
    }
    (vec![frame_data], false)
}

/// Decodes a single H.264 access unit (`h264_au`) using the per-channel [`VIDEO_DECODERS`] state.
///
/// Only locks [`VIDEO_DECODERS`], allowing Stage-1 decode (`ovl-h264-dec`) and Stage-2 encode
/// (`ovl-h264-enc`) to execute simultaneously on separate CPU cores without lock contention.
fn decode_video_access_unit(channel: u8, h264_au: &[u8]) -> Option<(YuvFrame, Duration, bool)> {
    let mut map = VIDEO_DECODERS.lock().ok()?;
    let state = map.get_mut(&channel)?;

    let t_start = Instant::now();
    let decoded = match &mut state.backend {
        DecoderBackend::V4l2(v4l2_dec) => match v4l2_dec.decode(h264_au) {
            Ok(Some(yuv)) => yuv,
            Ok(None) => return None,
            Err(e) => {
                warn!(
                    "overlay: ch {:#04x} V4L2 decode error: {:?}, falling back to pure-Rust software decoder",
                    channel, e
                );
                let mut sw_dec = Decoder::new();
                if let Some(cfg_bytes) = state.phone_codec_config.clone() {
                    let _ = sw_dec.decode(&cfg_bytes);
                }
                let fallback_res = match sw_dec.decode(h264_au) {
                    Ok(Some(yuv)) => Some(yuv),
                    _ => None,
                };
                state.backend = DecoderBackend::Software(sw_dec);
                fallback_res?
            }
        },
        DecoderBackend::Software(sw_dec) => match sw_dec.decode(h264_au) {
            Ok(Some(yuv)) => yuv,
            Ok(None) => return None,
            Err(e) => {
                if let Some(cfg_bytes) = state.phone_codec_config.clone() {
                    let _ = sw_dec.decode(&cfg_bytes);
                    if let Ok(Some(yuv)) = sw_dec.decode(h264_au) {
                        yuv
                    } else {
                        debug!(
                            "overlay: ch {:#04x} H.264 decode error ({} bytes): {:?}",
                            channel,
                            h264_au.len(),
                            e
                        );
                        return None;
                    }
                } else {
                    debug!(
                        "overlay: ch {:#04x} H.264 decode error ({} bytes): {:?}",
                        channel,
                        h264_au.len(),
                        e
                    );
                    return None;
                }
            }
        },
    };
    let dec_dur = t_start.elapsed();
    let incoming_has_idr = annex_b_contains_idr(h264_au);
    Some((decoded, dec_dur, incoming_has_idr))
}

/// Draws the overlay box onto `yuv` and encodes (or fast-skips) the frame using [`VIDEO_ENCODERS`].
#[allow(clippy::too_many_arguments)]
fn encode_decoded_video_frame(
    channel: u8,
    timestamp_bytes: &[u8],
    mut yuv: YuvFrame,
    in_len: usize,
    dec_dur: Duration,
    incoming_has_idr: bool,
    lines: &[String],
    cfg: &OverlayConfig,
    has_newer_frame_in_queue: bool,
    fallback_frame_data: Vec<u8>,
) -> (Vec<Vec<u8>>, bool) {
    let mut map = match VIDEO_ENCODERS.lock() {
        Ok(guard) => guard,
        Err(_) => return (vec![fallback_frame_data], false),
    };

    let Some(state) = map.get_mut(&channel) else {
        return (vec![fallback_frame_data], false);
    };

    let frame_w = yuv.width;
    let frame_h = yuv.height;

    if !state.ensure_encoder(
        channel,
        frame_w,
        frame_h,
        cfg.h264_encoder_qp,
        cfg.h264_encoder_gop,
    ) {
        return (vec![fallback_frame_data], false);
    }

    let need_keyframe = state.force_next_keyframe
        || incoming_has_idr
        || !state.emitted_encoder_codec_config
        || state.last_encoded_yuv.is_none();
    let overlay_changed = state.last_encoded_lines.as_slice() != lines
        || state.last_encoded_cfg.as_ref() != Some(cfg);

    let is_v4l2 = matches!(state.encoder, Some(EncoderBackend::V4l2(_)));

    let t_draw_start = Instant::now();
    // For V4L2 hardware encoder, NEVER use fast_skip!
    // The hardware encoder encodes in ~2ms on the VPU and MUST receive every frame
    // so its internal reference picture stays 100% in sync with the car Head Unit.
    let (draw_dur, fast_skip) = if is_v4l2 {
        draw_overlay_box_yuv420_with_config(&mut yuv, lines, cfg);
        (t_draw_start.elapsed(), false)
    } else if !need_keyframe && !overlay_changed && has_newer_frame_in_queue {
        (Duration::ZERO, true)
    } else {
        draw_overlay_box_yuv420_with_config(&mut yuv, lines, cfg);
        let d_dur = t_draw_start.elapsed();
        let unchanged = !need_keyframe
            && !overlay_changed
            && state
                .last_encoded_yuv
                .as_ref()
                .map(|last_yuv| is_frame_effectively_unchanged(&yuv, last_yuv, in_len))
                .unwrap_or(false);
        (d_dur, unchanged)
    };

    let t_enc_start = Instant::now();
    let encoded_au = if fast_skip {
        let mb_count = (frame_w.div_ceil(16) * frame_h.div_ceil(16)) as u32;
        let skip_au =
            build_all_skip_p_slice_annex_b(mb_count, state.out_frame_num, state.out_poc_lsb);
        state.out_frame_num = (state.out_frame_num + 1) & 0x0F;
        state.out_poc_lsb = (state.out_poc_lsb + 2) & 0xFF;
        state.fast_skipped_in_window = state.fast_skipped_in_window.saturating_add(1);
        skip_au
    } else {
        let mut fell_back_to_sw = None;
        let (raw_encoded_au, emitted_by_v4l2) = match state
            .encoder
            .as_mut()
            .expect("encoder initialized above")
        {
            EncoderBackend::V4l2(v4l2_enc) => {
                if need_keyframe {
                    v4l2_enc.request_keyframe();
                    state.force_next_keyframe = false;
                }
                match v4l2_enc.encode(&yuv) {
                    Ok(bytes) if !bytes.is_empty() => {
                        state.hw_enc_timeouts = 0;
                        (bytes, true)
                    }
                    Ok(_) => return (Vec::new(), false),
                    Err(e)
                        if e.kind() == std::io::ErrorKind::TimedOut
                            && state.hw_enc_timeouts + 1 < V4L2_ENC_MAX_CONSECUTIVE_TIMEOUTS =>
                    {
                        // A single slow hardware frame is not a reason to give up on the
                        // hardware encoder: drop this frame and keep going.
                        state.hw_enc_timeouts += 1;
                        debug!(
                            "overlay: ch {:#04x} V4L2 encode timeout ({}/{})",
                            channel, state.hw_enc_timeouts, V4L2_ENC_MAX_CONSECUTIVE_TIMEOUTS
                        );
                        return (Vec::new(), false);
                    }
                    Err(e) => {
                        warn!(
                            "overlay: ch {:#04x} V4L2 encode error: {:?}, falling back to pure-Rust software encoder",
                            channel, e
                        );
                        let mut sw_enc = match create_baseline_encoder(
                            frame_w,
                            frame_h,
                            cfg.h264_encoder_qp,
                            cfg.h264_encoder_gop,
                        ) {
                            Ok(sw) => sw,
                            Err(_) => return (Vec::new(), false),
                        };
                        // The car HU has so far seen the hardware stream: start the software
                        // stream with an IDR and re-send SPS/PPS.
                        sw_enc.request_keyframe();
                        let res = match sw_enc.try_encode(&yuv) {
                            Ok(b) => b,
                            Err(_) => return (Vec::new(), false),
                        };
                        fell_back_to_sw = Some(sw_enc);
                        (res, false)
                    }
                }
            }
            EncoderBackend::Software(sw_enc) => {
                if need_keyframe {
                    sw_enc.request_keyframe();
                    state.force_next_keyframe = false;
                }

                match sw_enc.try_encode(&yuv) {
                    Ok(bytes) => (bytes, false),
                    Err(e) => {
                        warn!("overlay: ch {:#04x} H.264 encode error: {:?}", channel, e);
                        return (vec![fallback_frame_data], false);
                    }
                }
            }
        };

        if let Some(sw_enc) = fell_back_to_sw {
            state.encoder = Some(EncoderBackend::Software(sw_enc));
            state.hw_enc_timeouts = 0;
            state.force_next_keyframe = false;
            state.emitted_encoder_codec_config = false;
        }

        let emitted_idr = annex_b_contains_idr(&raw_encoded_au);
        let patched_au = if emitted_by_v4l2 {
            raw_encoded_au
        } else if emitted_idr {
            state.out_frame_num = 1;
            state.out_poc_lsb = 2;
            patch_annex_b_for_car_hu(raw_encoded_au)
        } else {
            let mut p_au = patch_annex_b_for_car_hu(raw_encoded_au);
            patch_p_slice_frame_num_and_poc(&mut p_au, state.out_frame_num, state.out_poc_lsb);
            state.out_frame_num = (state.out_frame_num + 1) & 0x0F;
            state.out_poc_lsb = (state.out_poc_lsb + 2) & 0xFF;
            p_au
        };

        state.last_encoded_yuv = Some(yuv);
        if overlay_changed {
            state.last_encoded_lines = lines.to_vec();
            state.last_encoded_cfg = Some(cfg.clone());
        }
        patched_au
    };

    let enc_dur = t_enc_start.elapsed();
    state.frames_processed = state.frames_processed.saturating_add(1);

    if state.frames_processed == 1 || state.frames_processed % 60 == 0 {
        let dec_ms = dec_dur.as_secs_f64() * 1000.0;
        let draw_ms = draw_dur.as_secs_f64() * 1000.0;
        let enc_ms = enc_dur.as_secs_f64() * 1000.0;
        let total_ms = (dec_dur + draw_dur + enc_dur).as_secs_f64() * 1000.0;
        let skipped = state.fast_skipped_in_window;
        state.fast_skipped_in_window = 0;
        debug!(
            "overlay: ch {:#04x} frame #{} ({}x{}, idr={}, fast_skip={}, skipped={}/60) in={}B out={}B | dec={:.2}ms draw={:.2}ms enc={:.2}ms total={:.2}ms",
            channel,
            state.frames_processed,
            frame_w,
            frame_h,
            incoming_has_idr,
            fast_skip,
            skipped,
            in_len,
            encoded_au.len(),
            dec_ms,
            draw_ms,
            enc_ms,
            total_ms
        );
    }

    let mut out_messages = Vec::with_capacity(2);

    // If `MEDIA_MESSAGE_CODEC_CONFIG` was not already rewritten in-place (for example, when
    // `/dev/shm/overlay.json` was created mid-session after initial connection), emit a synthetic
    // `MEDIA_MESSAGE_CODEC_CONFIG` once before the first re-encoded IDR frame.
    if !state.emitted_encoder_codec_config {
        let sps_pps = match &state.encoder {
            Some(EncoderBackend::V4l2(v4l2_enc)) if !v4l2_enc.header_bytes().is_empty() => {
                v4l2_enc.header_bytes().to_vec()
            }
            _ => extract_sps_pps_annex_b(&encoded_au),
        };
        if !sps_pps.is_empty() {
            let codec_cfg_id = (MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG as u16).to_be_bytes();
            let mut codec_msg = Vec::with_capacity(2 + sps_pps.len());
            codec_msg.extend_from_slice(&codec_cfg_id);
            codec_msg.extend_from_slice(&sps_pps);
            out_messages.push(codec_msg);
            state.emitted_encoder_codec_config = true;
        }
    }

    let data_id = (MediaMessageId::MEDIA_MESSAGE_DATA as u16).to_be_bytes();
    let mut new_data_msg = Vec::with_capacity(10 + encoded_au.len());
    new_data_msg.extend_from_slice(&data_id);
    new_data_msg.extend_from_slice(timestamp_bytes);
    new_data_msg.extend_from_slice(&encoded_au);
    out_messages.push(new_data_msg);

    (out_messages, true)
}

/// Core H.264 `MEDIA_MESSAGE_DATA` handler parameterized by `lines` and `cfg`.
pub fn process_video_data_frame_with_config(
    channel: u8,
    frame_data: Vec<u8>,
    lines: &[String],
    cfg: &OverlayConfig,
) -> (Vec<Vec<u8>>, bool) {
    if frame_data.len() <= 10 {
        return (vec![frame_data], false);
    }

    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&frame_data[2..10]);
    let h264_au = &frame_data[10..];
    let in_len = h264_au.len();

    let Some((yuv, dec_dur, incoming_has_idr)) = decode_video_access_unit(channel, h264_au) else {
        return (vec![frame_data], false);
    };

    encode_decoded_video_frame(
        channel,
        &timestamp_bytes,
        yuv,
        in_len,
        dec_dur,
        incoming_has_idr,
        lines,
        cfg,
        false,
        frame_data,
    )
}

/// Core H.264 `MEDIA_MESSAGE_DATA` handler parameterized by `lines` using default [`OverlayConfig`].
pub fn process_video_data_frame_with_lines(
    channel: u8,
    frame_data: Vec<u8>,
    lines: &[String],
) -> (Vec<Vec<u8>>, bool) {
    process_video_data_frame_with_config(channel, frame_data, lines, &OverlayConfig::default())
}

/// Fast check for whether the post-overlay `yuv` frame is visually unchanged compared to
/// `last_yuv`, avoiding a 16.3ms full `Encoder::try_encode` pass on static frames.
fn is_frame_effectively_unchanged(yuv: &YuvFrame, last_yuv: &YuvFrame, in_len: usize) -> bool {
    if yuv.width != last_yuv.width
        || yuv.height != last_yuv.height
        || yuv.y.len() != last_yuv.y.len()
        || yuv.u.len() != last_yuv.u.len()
        || yuv.v.len() != last_yuv.v.len()
    {
        return false;
    }

    // Exact byte-for-byte plane match (uses SIMD/NEON memcmp; exits immediately on first diff)
    if yuv.y == last_yuv.y && yuv.u == last_yuv.u && yuv.v == last_yuv.v {
        return true;
    }

    // When the incoming H.264 access unit from the Phone is > 600 bytes, real screen motion
    // is present, so only skip if the planes were byte-identical above.
    if in_len > 600 {
        return false;
    }

    // For tiny keepalive P-frames from the Phone (<= 600 bytes, e.g. 13B..404B),
    // check on a 2x2 luma grid whether any pixels changed beyond QP=26 quantization noise.
    let width = yuv.width;
    let height = yuv.height;
    let mut changed_samples = 0usize;
    let mut y = 0;
    while y < height {
        let row_off = y * width;
        let cur_row = &yuv.y[row_off..row_off + width];
        let last_row = &last_yuv.y[row_off..row_off + width];
        let mut x = 0;
        while x < width {
            if cur_row[x].abs_diff(last_row[x]) > 5 {
                changed_samples += 1;
                if changed_samples > 8 {
                    return false;
                }
            }
            x += 2;
        }
        y += 2;
    }

    true
}

/// Synthesizes a Constrained Baseline all-skip P-slice (`00 00 00 01 61 ...`, 11 bytes at 800x480)
/// matching `rusty_h264::Encoder`'s slice header syntax (`weightp = false`, `cabac = false`,
/// `num_ref_frames = 1`, `slice_qp_delta = 0`, `mb_skip_run = mb_count`).
fn build_all_skip_p_slice_annex_b(mb_count: u32, frame_num: u32, poc_lsb: u32) -> Vec<u8> {
    let mut w = SimpleBitWriter::new();
    w.write_ue(0); // first_mb_in_slice = 0
    w.write_ue(5); // slice_type = 5 (P_ALL)
    w.write_ue(0); // pic_parameter_set_id = 0
    w.write_bits(frame_num & 0x0F, 4); // frame_num (log2_max_frame_num = 4)
    w.write_bits(poc_lsb & 0xFF, 8); // pic_order_cnt_lsb (log2_max_pic_order_cnt_lsb = 8)
    w.write_bit(false); // num_ref_idx_active_override_flag = 0
    w.write_bit(false); // ref_pic_list_modification_flag_l0 = 0
    w.write_bit(false); // adaptive_ref_pic_marking_mode_flag = 0
    w.write_se(0); // slice_qp_delta = 0
    w.write_ue(0); // disable_deblocking_filter_idc = 0
    w.write_se(0); // slice_alpha_c0_offset_div2 = 0
    w.write_se(0); // slice_beta_offset_div2 = 0
    w.write_ue(mb_count); // mb_skip_run = all macroblocks in picture
    w.rbsp_trailing_bits();

    let rbsp = w.into_bytes();
    let mut out = Vec::with_capacity(5 + rbsp.len() + 2);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x61]);
    rbsp_escape_into(&rbsp, &mut out);
    out
}

/// Patches `frame_num` (bits 7..11 of RBSP) and `pic_order_cnt_lsb` (bits 11..19 of RBSP)
/// in-place inside a P-slice NAL (`00 00 00 01 61 ...`) emitted by `rusty_h264::Encoder` so
/// sequence numbers stay continuous across fast-skipped P-frames.
fn patch_p_slice_frame_num_and_poc(au: &mut [u8], frame_num: u32, poc_lsb: u32) {
    if au.len() >= 8 && au[0..4] == [0x00, 0x00, 0x00, 0x01] && (au[4] & 0x1F) == 1 {
        let fn4 = (frame_num & 0x0F) as u8;
        let poc8 = (poc_lsb & 0xFF) as u8;
        au[5] = 0x9A | ((fn4 >> 3) & 0x01);
        au[6] = ((fn4 & 0x07) << 5) | ((poc8 >> 3) & 0x1F);
        au[7] = (au[7] & 0x1F) | ((poc8 & 0x07) << 5);
    }
}

/// Checks whether an Annex-B buffer contains an H.264 IDR slice (`nal_unit_type == 5`).
fn annex_b_contains_idr(data: &[u8]) -> bool {
    for nal in split_annex_b_nals(data) {
        if let Some(&first) = nal.first() {
            if (first & 0x1F) == 5 {
                return true;
            }
        }
    }
    false
}

/// Extracts SPS (`7`) and PPS (`8`) NAL units from an Annex-B buffer with `00 00 00 01` start codes.
fn extract_sps_pps_annex_b(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for nal in split_annex_b_nals(data) {
        if let Some(&first) = nal.first() {
            let nal_type = first & 0x1F;
            if nal_type == 7 || nal_type == 8 {
                out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                out.extend_from_slice(nal);
            }
        }
    }
    out
}

/// Fast-path Annex-B patcher for Car Head Unit hardware decoders:
/// - On P-frames (`nal_unit_type == 1`), returns `encoded_au` directly with zero copy.
/// - On IDR access units (which start with `SPS + PPS`), patches the SPS NAL (`nal_unit_type == 7`)
///   to set strict Constrained Baseline flags (`0xC0`) and zero-latency VUI parameters
///   (`max_num_reorder_frames = 0`, `max_dec_frame_buffering = 1`).
fn patch_annex_b_for_car_hu(encoded_au: Vec<u8>) -> Vec<u8> {
    if encoded_au.len() > 4
        && encoded_au[0..4] == [0x00, 0x00, 0x00, 0x01]
        && (encoded_au[4] & 0x1F) == 1
    {
        return encoded_au;
    }

    let mut out = Vec::with_capacity(encoded_au.len() + 16);
    for nal in split_annex_b_nals(&encoded_au) {
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        if nal.first().map(|&b| b & 0x1F) == Some(7) {
            out.extend_from_slice(&patch_sps_nal_for_car_hu(nal));
        } else {
            out.extend_from_slice(nal);
        }
    }
    out
}

/// Patches an H.264 SPS NAL unit (`0x67 ...`) generated by `rusty_h264` so that:
/// 1. `constraint_set0_flag = 1` and `constraint_set1_flag = 1` (`0xC0`, strict Constrained Baseline).
/// 2. `vui_parameters_present_flag = 1` with `bitstream_restriction_flag = 1`,
///    `max_num_reorder_frames = 0`, and `max_dec_frame_buffering = 1` so Car Head Unit hardware
///    decoders output every frame immediately without DPB reorder buffering delay.
fn patch_sps_nal_for_car_hu(sps_nal: &[u8]) -> Vec<u8> {
    if sps_nal.len() < 4 {
        return sps_nal.to_vec();
    }
    let nal_header = sps_nal[0];
    let mut rbsp = rbsp_unescape(&sps_nal[1..]);
    if rbsp.len() < 4 {
        return sps_nal.to_vec();
    }
    // Enforce Constrained Baseline constraint_set0_flag | constraint_set1_flag (0xC0)
    rbsp[1] |= 0xC0;

    let Some(&last_byte) = rbsp.last() else {
        return sps_nal.to_vec();
    };
    if last_byte == 0 {
        return sps_nal.to_vec();
    }

    // Locate the RBSP stop bit ('1') at the lowest set bit of `last_byte`.
    // The bit immediately preceding the stop bit is `vui_parameters_present_flag = 0`.
    let stop_bit_from_lsb = last_byte.trailing_zeros() as usize;
    let total_bits_before_stop = rbsp.len() * 8 - 1 - stop_bit_from_lsb;
    if total_bits_before_stop < 25 {
        return sps_nal.to_vec();
    }
    let sps_body_bits = total_bits_before_stop - 1;

    let mut w = SimpleBitWriter::new();
    for bit_idx in 0..sps_body_bits {
        let byte = rbsp[bit_idx / 8];
        let bit = ((byte >> (7 - (bit_idx % 8))) & 1) != 0;
        w.write_bit(bit);
    }

    // Write `vui_parameters_present_flag = 1` + zero-latency `bitstream_restriction`
    write_zero_latency_vui(&mut w);
    w.rbsp_trailing_bits();

    let new_rbsp = w.into_bytes();
    let mut out = Vec::with_capacity(1 + new_rbsp.len() + 4);
    out.push(nal_header);
    rbsp_escape_into(&new_rbsp, &mut out);
    out
}

/// Generates an Annex-B `SPS + PPS` buffer matching `create_baseline_encoder(width, height)`
/// with strict Constrained Baseline (`0xC0`), `weighted_pred_flag = 0`, and zero-latency VUI.
fn build_car_hu_sps_pps_annex_b(width: usize, height: usize, qp: u8) -> Vec<u8> {
    let mb_w = width.div_ceil(16);
    let mb_h = height.div_ceil(16);
    let crop_right = (mb_w * 16 - width) / 2;
    let crop_bottom = (mb_h * 16 - height) / 2;
    let frame_mbs = (mb_w * mb_h) as u32;
    let dpb_mbs = frame_mbs; // max_num_ref_frames = 1

    const LEVEL_CAPS: &[(u8, u32, u32)] = &[
        (30, 1620, 8100),
        (31, 3600, 18000),
        (32, 5120, 20480),
        (40, 8192, 32768),
        (41, 8192, 32768),
        (42, 8704, 34816),
        (50, 22080, 110400),
        (51, 36864, 184320),
        (52, 36864, 184320),
    ];
    let level_idc = LEVEL_CAPS
        .iter()
        .find(|&&(_, max_fs, max_dpb)| max_fs >= frame_mbs && max_dpb >= dpb_mbs)
        .map(|&(l, _, _)| l)
        .unwrap_or(52);

    // 1. Build SPS RBSP
    let mut sps_w = SimpleBitWriter::new();
    sps_w.write_bits(66, 8); // profile_idc = 66 (Baseline)
    sps_w.write_bits(0xC0, 8); // constraint_set0_flag = 1, constraint_set1_flag = 1
    sps_w.write_bits(level_idc as u32, 8);
    sps_w.write_ue(0); // seq_parameter_set_id = 0
    sps_w.write_ue(0); // log2_max_frame_num_minus4 = 0
    sps_w.write_ue(0); // pic_order_cnt_type = 0
    sps_w.write_ue(4); // log2_max_pic_order_cnt_lsb_minus4 = 4
    sps_w.write_ue(1); // max_num_ref_frames = 1
    sps_w.write_bit(false); // gaps_in_frame_num_value_allowed_flag = 0
    sps_w.write_ue((mb_w - 1) as u32);
    sps_w.write_ue((mb_h - 1) as u32);
    sps_w.write_bit(true); // frame_mbs_only_flag = 1
    sps_w.write_bit(true); // direct_8x8_inference_flag = 1
    let cropping = crop_right != 0 || crop_bottom != 0;
    sps_w.write_bit(cropping);
    if cropping {
        sps_w.write_ue(0);
        sps_w.write_ue(crop_right as u32);
        sps_w.write_ue(0);
        sps_w.write_ue(crop_bottom as u32);
    }
    write_zero_latency_vui(&mut sps_w);
    sps_w.rbsp_trailing_bits();

    // 2. Build PPS RBSP (matching rusty_h264 Pps::write_rbsp with weightp = false, cabac = false)
    let mut pps_w = SimpleBitWriter::new();
    pps_w.write_ue(0); // pic_parameter_set_id = 0
    pps_w.write_ue(0); // seq_parameter_set_id = 0
    pps_w.write_bit(false); // entropy_coding_mode_flag = 0 (CAVLC)
    pps_w.write_bit(false); // bottom_field_pic_order_in_frame_present_flag = 0
    pps_w.write_ue(0); // num_slice_groups_minus1 = 0
    pps_w.write_ue(0); // num_ref_idx_l0_default_active_minus1 = 0
    pps_w.write_ue(0); // num_ref_idx_l1_default_active_minus1 = 0
    pps_w.write_bit(false); // weighted_pred_flag = 0 (strictly required for Baseline Profile!)
    pps_w.write_bits(0, 2); // weighted_bipred_idc = 0
    pps_w.write_se(qp as i32 - 26); // pic_init_qp_minus26
    pps_w.write_se(0); // pic_init_qs_minus26 = 0
    pps_w.write_se(0); // chroma_qp_index_offset = 0
    pps_w.write_bit(true); // deblocking_filter_control_present_flag = 1
    pps_w.write_bit(false); // constrained_intra_pred_flag = 0
    pps_w.write_bit(false); // redundant_pic_cnt_present_flag = 0
    pps_w.rbsp_trailing_bits();

    let sps_rbsp = sps_w.into_bytes();
    let pps_rbsp = pps_w.into_bytes();

    let mut out = Vec::with_capacity(sps_rbsp.len() + pps_rbsp.len() + 16);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67]);
    rbsp_escape_into(&sps_rbsp, &mut out);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x68]);
    rbsp_escape_into(&pps_rbsp, &mut out);
    out
}

fn write_zero_latency_vui(w: &mut SimpleBitWriter) {
    w.write_bit(true); // vui_parameters_present_flag = 1
    w.write_bit(false); // aspect_ratio_info_present_flag = 0
    w.write_bit(false); // overscan_info_present_flag = 0
    w.write_bit(false); // video_signal_type_present_flag = 0
    w.write_bit(false); // chroma_loc_info_present_flag = 0
    w.write_bit(false); // timing_info_present_flag = 0
    w.write_bit(false); // nal_hrd_parameters_present_flag = 0
    w.write_bit(false); // vcl_hrd_parameters_present_flag = 0
    w.write_bit(false); // pic_struct_present_flag = 0
    w.write_bit(true); // bitstream_restriction_flag = 1
    w.write_bit(true); // motion_vectors_over_pic_boundaries_flag = 1
    w.write_ue(0); // max_bytes_per_pic_denom = 0
    w.write_ue(0); // max_bits_per_mb_denom = 0
    w.write_ue(10); // log2_max_mv_length_horizontal = 10
    w.write_ue(10); // log2_max_mv_length_vertical = 10
    w.write_ue(0); // max_num_reorder_frames = 0 (zero reorder delay!)
    w.write_ue(1); // max_dec_frame_buffering = 1
}

/// Parses displayed `(width, height)` from the first SPS (`nal_unit_type == 7`) in an Annex-B buffer.
fn parse_sps_dimensions_annex_b(annex_b: &[u8]) -> Option<(usize, usize)> {
    for nal in split_annex_b_nals(annex_b) {
        if nal.first().map(|&b| b & 0x1F) == Some(7) && nal.len() > 4 {
            let rbsp = rbsp_unescape(&nal[1..]);
            if let Some(dims) = parse_sps_rbsp_dimensions(&rbsp) {
                return Some(dims);
            }
        }
    }
    None
}

fn parse_sps_rbsp_dimensions(rbsp: &[u8]) -> Option<(usize, usize)> {
    let mut r = SimpleBitReader::new(rbsp);
    let profile_idc = r.read_bits(8)? as u8;
    let _constraints = r.read_bits(8)?;
    let _level_idc = r.read_bits(8)?;
    let _sps_id = r.read_ue()?;

    let mut chroma_format_idc = 1u32;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        chroma_format_idc = r.read_ue()?;
        if chroma_format_idc == 3 {
            let _ = r.read_bit()?;
        }
        let _bit_depth_luma = r.read_ue()?;
        let _bit_depth_chroma = r.read_ue()?;
        let _transform_bypass = r.read_bit()?;
        let seq_scaling_matrix_present = r.read_bit()?;
        if seq_scaling_matrix_present {
            let count = if chroma_format_idc != 3 { 8 } else { 12 };
            for i in 0..count {
                if r.read_bit()? {
                    let size = if i < 6 { 16 } else { 64 };
                    let mut last_scale = 8i32;
                    let mut next_scale = 8i32;
                    for _ in 0..size {
                        if next_scale != 0 {
                            let delta = r.read_se()?;
                            next_scale = (last_scale + delta + 256).rem_euclid(256);
                        }
                        last_scale = if next_scale == 0 {
                            last_scale
                        } else {
                            next_scale
                        };
                    }
                }
            }
        }
    }

    let _log2_max_frame_num_minus4 = r.read_ue()?;
    let pic_order_cnt_type = r.read_ue()?;
    if pic_order_cnt_type == 0 {
        let _log2_max_poc_lsb_minus4 = r.read_ue()?;
    } else if pic_order_cnt_type == 1 {
        let _always_zero = r.read_bit()?;
        let _off_non_ref = r.read_se()?;
        let _off_top_bot = r.read_se()?;
        let n = r.read_ue()?;
        for _ in 0..n {
            let _ = r.read_se()?;
        }
    }
    let _max_num_ref_frames = r.read_ue()?;
    let _gaps_allowed = r.read_bit()?;
    let pic_width_in_mbs_minus1 = r.read_ue()? as usize;
    let pic_height_in_map_units_minus1 = r.read_ue()? as usize;
    let frame_mbs_only_flag = r.read_bit()?;
    if !frame_mbs_only_flag {
        let _mb_adaptive = r.read_bit()?;
    }
    let _direct_8x8 = r.read_bit()?;
    let frame_cropping_flag = r.read_bit()?;
    let (mut crop_l, mut crop_r, mut crop_t, mut crop_b) = (0usize, 0usize, 0usize, 0usize);
    if frame_cropping_flag {
        crop_l = r.read_ue()? as usize;
        crop_r = r.read_ue()? as usize;
        crop_t = r.read_ue()? as usize;
        crop_b = r.read_ue()? as usize;
    }

    let sub_w_c = if chroma_format_idc == 1 || chroma_format_idc == 2 {
        2usize
    } else {
        1usize
    };
    let sub_h_c = if chroma_format_idc == 1 {
        2usize
    } else {
        1usize
    };
    let frame_mbs_mult = if frame_mbs_only_flag { 1usize } else { 2usize };

    let coded_w = (pic_width_in_mbs_minus1 + 1) * 16;
    let coded_h = (pic_height_in_map_units_minus1 + 1) * 16 * frame_mbs_mult;
    let width = coded_w.checked_sub((crop_l + crop_r) * sub_w_c)?;
    let height = coded_h.checked_sub((crop_t + crop_b) * sub_h_c * frame_mbs_mult)?;
    if width == 0 || height == 0 {
        return None;
    }
    Some((width, height))
}

fn rbsp_unescape(escaped: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut zeros = 0u32;
    for &b in escaped {
        if zeros == 2 && b == 0x03 {
            zeros = 0;
            continue;
        }
        out.push(b);
        if b == 0 {
            zeros += 1;
        } else {
            zeros = 0;
        }
    }
    out
}

fn rbsp_escape_into(rbsp: &[u8], out: &mut Vec<u8>) {
    let mut zeros = 0u32;
    for &b in rbsp {
        if zeros == 2 && b <= 0x03 {
            out.push(0x03);
            zeros = 0;
        }
        out.push(b);
        if b == 0 {
            zeros += 1;
        } else {
            zeros = 0;
        }
    }
}

struct SimpleBitWriter {
    bytes: Vec<u8>,
    cur_byte: u8,
    bits_used: u8,
}

impl SimpleBitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(32),
            cur_byte: 0,
            bits_used: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        self.cur_byte = (self.cur_byte << 1) | u8::from(bit);
        self.bits_used += 1;
        if self.bits_used == 8 {
            self.bytes.push(self.cur_byte);
            self.cur_byte = 0;
            self.bits_used = 0;
        }
    }

    fn write_bits(&mut self, val: u32, count: u8) {
        for i in (0..count).rev() {
            self.write_bit(((val >> i) & 1) != 0);
        }
    }

    fn write_ue(&mut self, val: u32) {
        let code_num = val as u64 + 1;
        let leading_zeros = (63 - code_num.leading_zeros()) as u8;
        for _ in 0..leading_zeros {
            self.write_bit(false);
        }
        for i in (0..=leading_zeros).rev() {
            self.write_bit(((code_num >> i) & 1) != 0);
        }
    }

    fn write_se(&mut self, val: i32) {
        let code_num = if val <= 0 {
            (-2i64 * val as i64) as u32
        } else {
            (2i64 * val as i64 - 1) as u32
        };
        self.write_ue(code_num);
    }

    fn rbsp_trailing_bits(&mut self) {
        self.write_bit(true);
        while self.bits_used != 0 {
            self.write_bit(false);
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

struct SimpleBitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> SimpleBitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.bit_pos >= self.data.len() * 8 {
            return None;
        }
        let byte = self.data[self.bit_pos / 8];
        let bit = ((byte >> (7 - (self.bit_pos % 8))) & 1) != 0;
        self.bit_pos += 1;
        Some(bit)
    }

    fn read_bits(&mut self, count: u8) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..count {
            v = (v << 1) | u32::from(self.read_bit()?);
        }
        Some(v)
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut zeros = 0u8;
        while !self.read_bit()? {
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        if zeros == 0 {
            return Some(0);
        }
        let suffix = self.read_bits(zeros)?;
        Some((1u32 << zeros) - 1 + suffix)
    }

    fn read_se(&mut self) -> Option<i32> {
        let ue = self.read_ue()?;
        let abs = ((ue + 1) / 2) as i32;
        if ue % 2 == 1 {
            Some(abs)
        } else {
            Some(-abs)
        }
    }
}

fn split_annex_b_nals(data: &[u8]) -> Vec<&[u8]> {
    let mut nals = Vec::new();
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            if data[i + 2] == 1 {
                starts.push((i, i + 3));
                i += 3;
                continue;
            } else if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                starts.push((i, i + 4));
                i += 4;
                continue;
            }
        }
        i += 1;
    }

    for idx in 0..starts.len() {
        let payload_start = starts[idx].1;
        let payload_end = if idx + 1 < starts.len() {
            starts[idx + 1].0
        } else {
            data.len()
        };
        if payload_start < payload_end {
            nals.push(&data[payload_start..payload_end]);
        }
    }
    nals
}

// ============================================================================
// YUV420 (I420) TRANSLUCENT BOX & BITMAP FONT RENDERER
// ============================================================================

#[inline]
#[allow(non_snake_case)]
fn rgb_to_BT601_yuv(r: u8, g: u8, b: u8) -> (u8, u8, u8) {
    let r = r as i32;
    let g = g as i32;
    let b = b as i32;
    let y = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
    let u = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
    let v = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
    (
        y.clamp(0, 255) as u8,
        u.clamp(0, 255) as u8,
        v.clamp(0, 255) as u8,
    )
}

#[inline]
fn blend_channel(dst: u8, src: u8, alpha_255: u32) -> u8 {
    let inv = 255 - alpha_255;
    (((dst as u32) * inv + (src as u32) * alpha_255 + 127) / 255) as u8
}

// ============================================================================
// HTML & CSS STYLING FOR OVERLAY TEXT
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct StyledSpan {
    pub text: String,
    pub fg_color: (u8, u8, u8),
    pub bg_color: Option<(u8, u8, u8)>,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub font_size: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StyledLine {
    pub spans: Vec<StyledSpan>,
}

#[derive(Debug, Clone)]
struct StyleState {
    fg_color: (u8, u8, u8),
    bg_color: Option<(u8, u8, u8)>,
    bold: bool,
    italic: bool,
    underline: bool,
    font_size: f32,
}

/// Parses standard CSS color strings: `#rgb`, `#rrggbb`, `#rrggbbaa`, `rgb(...)`, or common web color names.
pub fn parse_css_color(s: &str) -> Option<(u8, u8, u8)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix('#') {
        let hex = hex.trim();
        // The slicing below is by byte; non-ASCII input would split a character and panic.
        if !hex.is_ascii() {
            return None;
        }
        match hex.len() {
            3 => {
                let r = u8::from_str_radix(&hex[0..1], 16).ok()?;
                let g = u8::from_str_radix(&hex[1..2], 16).ok()?;
                let b = u8::from_str_radix(&hex[2..3], 16).ok()?;
                return Some((r * 17, g * 17, b * 17));
            }
            6 | 8 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                return Some((r, g, b));
            }
            _ => return None,
        }
    }
    if s.starts_with("rgb(") || s.starts_with("rgba(") {
        let inside = s.split_once('(')?.1.strip_suffix(')')?;
        let parts: Vec<&str> = inside.split(',').map(|p| p.trim()).collect();
        if parts.len() >= 3 {
            let r: u8 = parts[0].parse().ok()?;
            let g: u8 = parts[1].parse().ok()?;
            let b: u8 = parts[2].parse().ok()?;
            return Some((r, g, b));
        }
    }
    match s.to_ascii_lowercase().as_str() {
        "white" => Some((255, 255, 255)),
        "black" => Some((0, 0, 0)),
        "red" => Some((255, 0, 0)),
        "green" => Some((0, 255, 0)),
        "lime" => Some((50, 205, 50)),
        "blue" => Some((0, 100, 255)),
        "yellow" => Some((255, 255, 0)),
        "cyan" | "aqua" => Some((0, 255, 255)),
        "magenta" | "fuchsia" => Some((255, 0, 255)),
        "orange" => Some((255, 165, 0)),
        "gray" | "grey" => Some((128, 128, 128)),
        "darkgray" | "darkgrey" => Some((64, 64, 64)),
        "lightgray" | "lightgrey" => Some((211, 211, 211)),
        "silver" => Some((192, 192, 192)),
        "maroon" => Some((128, 0, 0)),
        "olive" => Some((128, 128, 0)),
        "navy" => Some((0, 0, 128)),
        "purple" => Some((128, 0, 128)),
        "teal" => Some((0, 128, 128)),
        "gold" => Some((255, 215, 0)),
        "coral" => Some((255, 127, 80)),
        "tomato" => Some((255, 99, 71)),
        _ => None,
    }
}

fn parse_css_style_declarations(style_str: &str, state: &mut StyleState) {
    for decl in style_str.split(';') {
        let decl = decl.trim();
        if decl.is_empty() {
            continue;
        }
        if let Some((prop, val)) = decl.split_once(':') {
            let prop = prop.trim().to_ascii_lowercase();
            let val = val.trim();
            match prop.as_str() {
                "color" => {
                    if let Some(c) = parse_css_color(val) {
                        state.fg_color = c;
                    }
                }
                "background-color" | "background" => {
                    if val.eq_ignore_ascii_case("transparent") || val.eq_ignore_ascii_case("none") {
                        state.bg_color = None;
                    } else if let Some(c) = parse_css_color(val) {
                        state.bg_color = Some(c);
                    }
                }
                "font-weight" => {
                    let v_lower = val.to_ascii_lowercase();
                    if v_lower == "bold"
                        || v_lower == "bolder"
                        || v_lower == "700"
                        || v_lower == "800"
                        || v_lower == "900"
                    {
                        state.bold = true;
                    } else if v_lower == "normal" || v_lower == "lighter" || v_lower == "400" {
                        state.bold = false;
                    }
                }
                "font-style" => {
                    let v_lower = val.to_ascii_lowercase();
                    if v_lower == "italic" || v_lower == "oblique" {
                        state.italic = true;
                    } else if v_lower == "normal" {
                        state.italic = false;
                    }
                }
                "text-decoration" | "text-decoration-line" => {
                    let v_lower = val.to_ascii_lowercase();
                    if v_lower.contains("underline") {
                        state.underline = true;
                    } else if v_lower.contains("none") {
                        state.underline = false;
                    }
                }
                "font-size" => {
                    let num_part: String = val
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.')
                        .collect();
                    if let Ok(sz) = num_part.parse::<f32>() {
                        if (6.0..=120.0).contains(&sz) {
                            state.font_size = sz;
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn parse_tag_attributes(tag_body: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    let mut chars = tag_body.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            break;
        }
        chars.next();
    }
    while chars.peek().is_some() {
        while let Some(&c) = chars.peek() {
            if !c.is_whitespace() {
                break;
            }
            chars.next();
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c.is_whitespace() || c == '/' || c == '>' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if key.is_empty() {
            chars.next();
            continue;
        }
        while let Some(&c) = chars.peek() {
            if !c.is_whitespace() {
                break;
            }
            chars.next();
        }
        if chars.peek() == Some(&'=') {
            chars.next();
            while let Some(&c) = chars.peek() {
                if !c.is_whitespace() {
                    break;
                }
                chars.next();
            }
            let mut val = String::new();
            if let Some(&quote) = chars.peek() {
                if quote == '"' || quote == '\'' {
                    chars.next();
                    for c in chars.by_ref() {
                        if c == quote {
                            break;
                        }
                        val.push(c);
                    }
                } else {
                    while let Some(&c) = chars.peek() {
                        if c.is_whitespace() || c == '>' || c == '/' {
                            break;
                        }
                        val.push(c);
                        chars.next();
                    }
                }
            }
            attrs.insert(key.to_ascii_lowercase(), val);
        } else {
            attrs.insert(key.to_ascii_lowercase(), String::new());
        }
    }
    attrs
}

fn decode_html_entities(s: &str) -> String {
    s.replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&deg;", "°")
}

/// Strips all HTML `<...>` tags and decodes entities, producing clean plain text for the 8x8 bitmap font fallback.
pub fn strip_html_tags(s: &str) -> String {
    if !s.contains('<') && !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            out.push(ch);
        }
    }
    decode_html_entities(&out)
}

/// Parses an HTML-formatted line into styled spans with bold, italic, underline, fg color, and bg color.
pub fn parse_html_line(
    raw_line: &str,
    default_color: (u8, u8, u8),
    default_font_size: f32,
) -> StyledLine {
    let mut state_stack = vec![StyleState {
        fg_color: default_color,
        bg_color: None,
        bold: false,
        italic: false,
        underline: false,
        font_size: default_font_size,
    }];

    let mut spans = Vec::new();
    let mut cur_text = String::new();

    let mut chars = raw_line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '<' {
            let mut tag = String::new();
            while let Some(&tc) = chars.peek() {
                chars.next();
                if tc == '>' {
                    break;
                }
                tag.push(tc);
            }
            let trimmed_tag = tag.trim();
            if let Some(closing_tag) = trimmed_tag.strip_prefix('/') {
                let tag_name = closing_tag.trim().to_ascii_lowercase();
                if !cur_text.is_empty() {
                    let decoded = decode_html_entities(&cur_text);
                    if !decoded.is_empty() {
                        let top = state_stack.last().unwrap();
                        spans.push(StyledSpan {
                            text: decoded,
                            fg_color: top.fg_color,
                            bg_color: top.bg_color,
                            bold: top.bold,
                            italic: top.italic,
                            underline: top.underline,
                            font_size: top.font_size,
                        });
                    }
                    cur_text.clear();
                }
                if state_stack.len() > 1 {
                    match tag_name.as_str() {
                        "b" | "strong" | "i" | "em" | "u" | "font" | "span" | "mark" => {
                            state_stack.pop();
                        }
                        _ => {}
                    }
                }
            } else {
                if !cur_text.is_empty() {
                    let decoded = decode_html_entities(&cur_text);
                    if !decoded.is_empty() {
                        let top = state_stack.last().unwrap();
                        spans.push(StyledSpan {
                            text: decoded,
                            fg_color: top.fg_color,
                            bg_color: top.bg_color,
                            bold: top.bold,
                            italic: top.italic,
                            underline: top.underline,
                            font_size: top.font_size,
                        });
                    }
                    cur_text.clear();
                }

                let tag_name = trimmed_tag
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let attrs = parse_tag_attributes(trimmed_tag);
                let mut new_state = state_stack.last().unwrap().clone();

                match tag_name.as_str() {
                    "b" | "strong" => {
                        new_state.bold = true;
                        state_stack.push(new_state);
                    }
                    "i" | "em" => {
                        new_state.italic = true;
                        state_stack.push(new_state);
                    }
                    "u" => {
                        new_state.underline = true;
                        state_stack.push(new_state);
                    }
                    "mark" => {
                        new_state.bg_color = Some((255, 255, 0));
                        if let Some(style) = attrs.get("style") {
                            parse_css_style_declarations(style, &mut new_state);
                        }
                        state_stack.push(new_state);
                    }
                    "font" => {
                        if let Some(color_val) = attrs.get("color") {
                            if let Some(c) = parse_css_color(color_val) {
                                new_state.fg_color = c;
                            }
                        }
                        state_stack.push(new_state);
                    }
                    "span" => {
                        if let Some(style) = attrs.get("style") {
                            parse_css_style_declarations(style, &mut new_state);
                        }
                        state_stack.push(new_state);
                    }
                    _ => {}
                }
            }
        } else {
            cur_text.push(c);
        }
    }

    if !cur_text.is_empty() {
        let decoded = decode_html_entities(&cur_text);
        if !decoded.is_empty() {
            let top = state_stack.last().unwrap();
            spans.push(StyledSpan {
                text: decoded,
                fg_color: top.fg_color,
                bg_color: top.bg_color,
                bold: top.bold,
                italic: top.italic,
                underline: top.underline,
                font_size: top.font_size,
            });
        }
    }

    StyledLine { spans }
}

fn draw_colored_rect(
    frame: &mut YuvFrame,
    x0: usize,
    y0: usize,
    x1: usize,
    y1: usize,
    color_y: u8,
    color_u: u8,
    color_v: u8,
) {
    if x0 >= x1 || y0 >= y1 || x0 >= frame.width || y0 >= frame.height {
        return;
    }
    let x1 = x1.min(frame.width);
    let y1 = y1.min(frame.height);
    let stride_y = frame.width;
    let stride_uv = frame.width / 2;

    for y in y0..y1 {
        let row_off = y * stride_y;
        for x in x0..x1 {
            frame.y[row_off + x] = color_y;
        }
    }

    let uv_x0 = x0 / 2;
    let uv_x1 = x1.div_ceil(2).min(stride_uv);
    let uv_y0 = y0 / 2;
    let uv_y1 = y1.div_ceil(2).min(frame.height / 2);

    for uy in uv_y0..uv_y1 {
        let row_off = uy * stride_uv;
        for ux in uv_x0..uv_x1 {
            let idx = row_off + ux;
            frame.u[idx] = color_u;
            frame.v[idx] = color_v;
        }
    }
}

/// Draws a translucent box with multi-line text near the bottom-right corner of `frame`
/// using default [`OverlayConfig`].
pub fn draw_overlay_box_yuv420(frame: &mut YuvFrame, lines: &[String]) {
    draw_overlay_box_yuv420_with_config(frame, lines, &OverlayConfig::default());
}

/// Draws a translucent box with multi-line text on `frame` parameterized by [`OverlayConfig`].
/// If a TTF font is loaded (via `overlay_font_path`), it renders text using the TTF font with `text_scale`
/// as the font size in points/pixels. If no TTF font is loaded, it falls back to the built-in 8x8 bitmap font.
pub fn draw_overlay_box_yuv420_with_config(
    frame: &mut YuvFrame,
    lines: &[String],
    cfg: &OverlayConfig,
) {
    let font = get_cached_overlay_font();
    draw_overlay_box_yuv420_with_config_and_font(frame, lines, cfg, font.as_deref());
}

/// Draws a translucent box with multi-line text on `frame` with an explicit optional TTF font.
pub fn draw_overlay_box_yuv420_with_config_and_font(
    frame: &mut YuvFrame,
    lines: &[String],
    cfg: &OverlayConfig,
    font: Option<&fontdue::Font>,
) {
    if lines.is_empty() || frame.width < 32 || frame.height < 32 {
        return;
    }

    let total_pad_x = cfg.box_padding_x_px + cfg.box_border_px;
    let total_pad_y = cfg.box_padding_y_px + cfg.box_border_px;

    // Presets 1 -> 12px, 2 -> 24px (default), 3 -> 36px, 4 -> 48px; larger values are the size.
    let base_font_size = ttf_base_font_size(cfg.text_scale);

    let styled_lines: Vec<StyledLine> = lines
        .iter()
        .map(|l| parse_html_line(l, cfg.text_rgb, base_font_size))
        .collect();

    let clean_bitmap_lines: Vec<String> = lines.iter().map(|l| strip_html_tags(l)).collect();

    let (text_block_w, text_block_h) = if let Some(font) = font {
        let line_metrics = font.horizontal_line_metrics(base_font_size);
        let line_height = line_metrics
            .map(|m| m.new_line_size.ceil() as usize)
            .unwrap_or((base_font_size * 1.2).ceil() as usize)
            + cfg.line_spacing_px;

        let max_w = styled_lines
            .iter()
            .map(|line| {
                let mut line_w = 0.0f32;
                for span in &line.spans {
                    for ch in span.text.chars() {
                        let m = font.metrics(ch, span.font_size);
                        let bold_extra = if span.bold { 1.0 } else { 0.0 };
                        let italic_extra = if span.italic {
                            (span.font_size * 0.1).ceil()
                        } else {
                            0.0
                        };
                        line_w += m.advance_width
                            + bold_extra
                            + italic_extra
                            + cfg.char_spacing_px as f32;
                    }
                }
                if line_w > 0.0 {
                    line_w -= cfg.char_spacing_px as f32;
                }
                line_w.max(0.0).ceil() as usize
            })
            .max()
            .unwrap_or(0);

        let total_h = if styled_lines.is_empty() {
            0
        } else {
            styled_lines.len() * line_height
        };
        (max_w, total_h)
    } else {
        let scale = cfg.text_scale.clamp(1, MAX_BITMAP_TEXT_SCALE);
        let glyph_w = 8 * scale;
        let glyph_h = 8 * scale;
        let char_step_x = glyph_w + cfg.char_spacing_px * scale;
        let line_step_y = glyph_h + cfg.line_spacing_px;

        let max_chars = clean_bitmap_lines
            .iter()
            .map(|l| l.chars().count())
            .max()
            .unwrap_or(0);
        if max_chars == 0 {
            return;
        }

        let w = max_chars * char_step_x - (cfg.char_spacing_px * scale);
        let h = clean_bitmap_lines.len() * line_step_y - cfg.line_spacing_px;
        (w, h)
    };

    if text_block_w == 0 || text_block_h == 0 {
        return;
    }

    let box_w = (text_block_w + total_pad_x * 2).min(frame.width);
    let box_h = (text_block_h + total_pad_y * 2).min(frame.height);

    // Position near bottom-right corner using configured margins
    let box_x0 = frame.width.saturating_sub(box_w + cfg.box_margin_right_px);
    let box_y0 = frame
        .height
        .saturating_sub(box_h + cfg.box_margin_bottom_px);
    let box_x1 = (box_x0 + box_w).min(frame.width);
    let box_y1 = (box_y0 + box_h).min(frame.height);

    let alpha_255 = ((cfg.box_opacity_percent.min(100) as u32) * 255) / 100;

    // Fast path: when both box opacity and border are 0, skip blending background planes
    if alpha_255 > 0 || cfg.box_border_px > 0 {
        let (bg_y, bg_u, bg_v) =
            rgb_to_BT601_yuv(cfg.box_bg_rgb.0, cfg.box_bg_rgb.1, cfg.box_bg_rgb.2);
        let (bd_y, bd_u, bd_v) = rgb_to_BT601_yuv(
            cfg.box_border_rgb.0,
            cfg.box_border_rgb.1,
            cfg.box_border_rgb.2,
        );
        let border_alpha_255 = alpha_255.saturating_add(40).min(255);

        let stride_y = frame.width;
        let stride_uv = frame.width / 2;

        // 1. Blend box background + border onto Y plane
        for y in box_y0..box_y1 {
            let in_border_y = y < box_y0 + cfg.box_border_px || y + cfg.box_border_px >= box_y1;
            let row_offset = y * stride_y;
            for x in box_x0..box_x1 {
                let in_border_x = x < box_x0 + cfg.box_border_px || x + cfg.box_border_px >= box_x1;
                let idx = row_offset + x;
                if in_border_x || in_border_y {
                    frame.y[idx] = blend_channel(frame.y[idx], bd_y, border_alpha_255);
                } else if alpha_255 > 0 {
                    frame.y[idx] = blend_channel(frame.y[idx], bg_y, alpha_255);
                }
            }
        }

        // 2. Blend box background + border onto subsampled U/V planes (2x2 blocks)
        let uv_x0 = box_x0 / 2;
        let uv_x1 = box_x1.div_ceil(2).min(stride_uv);
        let uv_y0 = box_y0 / 2;
        let uv_y1 = box_y1.div_ceil(2).min(frame.height / 2);
        let border_uv = (cfg.box_border_px / 2).max(usize::from(cfg.box_border_px > 0));

        for uy in uv_y0..uv_y1 {
            let in_border_y =
                cfg.box_border_px > 0 && (uy < uv_y0 + border_uv || uy + border_uv >= uv_y1);
            let row_offset = uy * stride_uv;
            for ux in uv_x0..uv_x1 {
                let in_border_x =
                    cfg.box_border_px > 0 && (ux < uv_x0 + border_uv || ux + border_uv >= uv_x1);
                let idx = row_offset + ux;
                if in_border_x || in_border_y {
                    frame.u[idx] = blend_channel(frame.u[idx], bd_u, border_alpha_255);
                    frame.v[idx] = blend_channel(frame.v[idx], bd_v, border_alpha_255);
                } else if alpha_255 > 0 {
                    frame.u[idx] = blend_channel(frame.u[idx], bg_u, alpha_255);
                    frame.v[idx] = blend_channel(frame.v[idx], bg_v, alpha_255);
                }
            }
        }
    }

    // 3. Render multi-line text with drop shadow
    let (shd_y, _shd_u, _shd_v) = rgb_to_BT601_yuv(
        cfg.text_shadow_rgb.0,
        cfg.text_shadow_rgb.1,
        cfg.text_shadow_rgb.2,
    );

    let text_start_x = box_x0 + total_pad_x;
    let text_start_y = box_y0 + total_pad_y;

    if let Some(font) = font {
        let line_metrics = font.horizontal_line_metrics(base_font_size);
        let line_height = line_metrics
            .map(|m| m.new_line_size.ceil() as usize)
            .unwrap_or((base_font_size * 1.2).ceil() as usize)
            + cfg.line_spacing_px;
        let ascent = line_metrics
            .map(|m| m.ascent.ceil() as usize)
            .unwrap_or((base_font_size * 0.85).ceil() as usize);

        for (line_idx, line) in styled_lines.iter().enumerate() {
            let line_top_y = text_start_y + line_idx * line_height;
            if line_top_y >= box_y1 {
                break;
            }
            let baseline_y = line_top_y + ascent;
            let mut cursor_x = text_start_x as f32;

            // Pass A: Draw span background rectangles first
            let mut bg_cursor_x = cursor_x;
            for span in &line.spans {
                let mut span_w = 0.0f32;
                for ch in span.text.chars() {
                    let m = font.metrics(ch, span.font_size);
                    let bold_extra = if span.bold { 1.0 } else { 0.0 };
                    let italic_extra = if span.italic {
                        (span.font_size * 0.1).ceil()
                    } else {
                        0.0
                    };
                    span_w +=
                        m.advance_width + bold_extra + italic_extra + cfg.char_spacing_px as f32;
                }
                if let Some(bg_rgb) = span.bg_color {
                    let (bg_y, bg_u, bg_v) = rgb_to_BT601_yuv(bg_rgb.0, bg_rgb.1, bg_rgb.2);
                    let pad_x = 2usize;
                    let span_x0 = (bg_cursor_x.round() as usize)
                        .saturating_sub(pad_x)
                        .max(box_x0);
                    let span_x1 = ((bg_cursor_x + span_w).round() as usize + pad_x).min(box_x1);
                    let span_y0 = line_top_y.min(box_y1);
                    let span_y1 =
                        (line_top_y + line_height.saturating_sub(cfg.line_spacing_px)).min(box_y1);
                    draw_colored_rect(frame, span_x0, span_y0, span_x1, span_y1, bg_y, bg_u, bg_v);
                }
                bg_cursor_x += span_w;
            }

            // Pass B: Draw glyphs and underlines
            for span in &line.spans {
                let (span_txt_y, span_txt_u, span_txt_v) =
                    rgb_to_BT601_yuv(span.fg_color.0, span.fg_color.1, span.fg_color.2);
                let span_start_x = cursor_x;

                for ch in span.text.chars() {
                    if cursor_x as usize >= box_x1 {
                        break;
                    }
                    let (metrics, bitmap) = font.rasterize(ch, span.font_size);
                    let glyph_x0 = cursor_x.round() as isize + metrics.xmin as isize;
                    let glyph_y0 =
                        baseline_y as isize - (metrics.ymin + metrics.height as i32) as isize;

                    draw_ttf_glyph(
                        frame,
                        glyph_x0,
                        glyph_y0,
                        metrics.width,
                        metrics.height,
                        &bitmap,
                        (span_txt_y, span_txt_u, span_txt_v),
                        shd_y,
                        box_x1,
                        box_y1,
                        span.bold,
                        span.italic,
                    );

                    let bold_extra = if span.bold { 1.0 } else { 0.0 };
                    let italic_extra = if span.italic {
                        (span.font_size * 0.1).ceil()
                    } else {
                        0.0
                    };
                    cursor_x += metrics.advance_width
                        + bold_extra
                        + italic_extra
                        + cfg.char_spacing_px as f32;
                }

                if span.underline {
                    let u_x0 = (span_start_x.round() as usize).min(box_x1);
                    let u_x1 = (cursor_x.round() as usize).min(box_x1);
                    let u_y0 = (baseline_y + 2).min(box_y1);
                    let u_y1 = (u_y0 + 2).min(box_y1);
                    draw_colored_rect(
                        frame, u_x0, u_y0, u_x1, u_y1, span_txt_y, span_txt_u, span_txt_v,
                    );
                }
            }
        }
    } else {
        let (txt_y, txt_u, txt_v) =
            rgb_to_BT601_yuv(cfg.text_rgb.0, cfg.text_rgb.1, cfg.text_rgb.2);
        let scale = cfg.text_scale.clamp(1, MAX_BITMAP_TEXT_SCALE);
        let glyph_w = 8 * scale;
        let glyph_h = 8 * scale;
        let char_step_x = glyph_w + cfg.char_spacing_px * scale;
        let line_step_y = glyph_h + cfg.line_spacing_px;

        for (line_idx, line) in clean_bitmap_lines.iter().enumerate() {
            let line_y = text_start_y + line_idx * line_step_y;
            if line_y + glyph_h > box_y1 {
                break;
            }
            for (char_idx, ch) in line.chars().enumerate() {
                let char_x = text_start_x + char_idx * char_step_x;
                if char_x + glyph_w > box_x1 {
                    break;
                }
                let glyph = glyph_for_char(ch);
                draw_scaled_glyph(
                    frame,
                    char_x,
                    line_y,
                    scale,
                    &glyph,
                    (txt_y, txt_u, txt_v),
                    shd_y,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_ttf_glyph(
    frame: &mut YuvFrame,
    x0: isize,
    y0: isize,
    width: usize,
    height: usize,
    bitmap: &[u8],
    txt_yuv: (u8, u8, u8),
    shadow_y: u8,
    clip_x1: usize,
    clip_y1: usize,
    bold: bool,
    italic: bool,
) {
    if width == 0 || height == 0 || bitmap.is_empty() {
        return;
    }
    let frame_w = frame.width;
    let frame_h = frame.height;
    let stride_uv = frame_w / 2;
    let (txt_y, txt_u, txt_v) = txt_yuv;

    // 1. Drop shadow offset (+1px)
    let shadow_offset: isize = 1;
    let bold_passes = if bold { 2 } else { 1 };
    for pass in 0..bold_passes {
        for gy in 0..height {
            let row_off = gy * width;
            let shear = if italic {
                ((height.saturating_sub(gy)) as isize) / 4
            } else {
                0
            };
            for gx in 0..width {
                let alpha = bitmap[row_off + gx] as u32;
                if alpha == 0 {
                    continue;
                }
                let sx = x0 + gx as isize + pass as isize + shear + shadow_offset;
                let sy = y0 + gy as isize + shadow_offset;
                if sx >= 0
                    && (sx as usize) < clip_x1
                    && (sx as usize) < frame_w
                    && sy >= 0
                    && (sy as usize) < clip_y1
                    && (sy as usize) < frame_h
                {
                    let idx_y = (sy as usize) * frame_w + (sx as usize);
                    frame.y[idx_y] = blend_channel(frame.y[idx_y], shadow_y, alpha);
                }
            }
        }
    }

    // 2. Foreground antialiased glyph on Y and U/V planes
    for pass in 0..bold_passes {
        for gy in 0..height {
            let row_off = gy * width;
            let shear = if italic {
                ((height.saturating_sub(gy)) as isize) / 4
            } else {
                0
            };
            for gx in 0..width {
                let alpha = bitmap[row_off + gx] as u32;
                if alpha == 0 {
                    continue;
                }
                let fx = x0 + gx as isize + pass as isize + shear;
                let fy = y0 + gy as isize;
                if fx >= 0
                    && (fx as usize) < clip_x1
                    && (fx as usize) < frame_w
                    && fy >= 0
                    && (fy as usize) < clip_y1
                    && (fy as usize) < frame_h
                {
                    let px = fx as usize;
                    let py = fy as usize;
                    let idx_y = py * frame_w + px;
                    frame.y[idx_y] = blend_channel(frame.y[idx_y], txt_y, alpha);

                    let uv_x = px / 2;
                    let uv_y = py / 2;
                    if uv_x < stride_uv && uv_y < frame_h / 2 {
                        let idx_uv = uv_y * stride_uv + uv_x;
                        frame.u[idx_uv] = blend_channel(frame.u[idx_uv], txt_u, alpha);
                        frame.v[idx_uv] = blend_channel(frame.v[idx_uv], txt_v, alpha);
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_scaled_glyph(
    frame: &mut YuvFrame,
    x0: usize,
    y0: usize,
    scale: usize,
    glyph: &[u8; 8],
    txt_yuv: (u8, u8, u8),
    shadow_y: u8,
) {
    let (txt_y, txt_u, txt_v) = txt_yuv;
    let width = frame.width;
    let height = frame.height;
    let stride_uv = width / 2;

    // Pass 1: Draw drop shadow (+1..+scale px offset) on luma plane
    let shadow_offset = scale.min(2);
    for (row_idx, &row_bits) in glyph.iter().enumerate() {
        if row_bits == 0 {
            continue;
        }
        for col_idx in 0..8 {
            if (row_bits & (1 << col_idx)) == 0 {
                continue;
            }
            let px_start = x0 + col_idx * scale + shadow_offset;
            let py_start = y0 + row_idx * scale + shadow_offset;
            for dy in 0..scale {
                let py = py_start + dy;
                if py >= height {
                    continue;
                }
                let row_off = py * width;
                for dx in 0..scale {
                    let px = px_start + dx;
                    if px < width {
                        frame.y[row_off + px] = shadow_y;
                    }
                }
            }
        }
    }

    // Pass 2: Draw foreground glyph on Y and U/V planes
    for (row_idx, &row_bits) in glyph.iter().enumerate() {
        if row_bits == 0 {
            continue;
        }
        for col_idx in 0..8 {
            if (row_bits & (1 << col_idx)) == 0 {
                continue;
            }
            let px_start = x0 + col_idx * scale;
            let py_start = y0 + row_idx * scale;
            for dy in 0..scale {
                let py = py_start + dy;
                if py >= height {
                    continue;
                }
                let row_off = py * width;
                let uv_row_off = (py / 2) * stride_uv;
                for dx in 0..scale {
                    let px = px_start + dx;
                    if px < width {
                        frame.y[row_off + px] = txt_y;
                        let uv_idx = uv_row_off + (px / 2);
                        frame.u[uv_idx] = txt_u;
                        frame.v[uv_idx] = txt_v;
                    }
                }
            }
        }
    }
}

/// Returns an 8x8 bitmap glyph (LSB = left-most pixel of row) for ASCII and common Spanish chars.
fn glyph_for_char(ch: char) -> [u8; 8] {
    match ch {
        '°' | 'º' => [0x06, 0x09, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00],
        'ñ' => [0x36, 0x00, 0x16, 0x19, 0x11, 0x11, 0x11, 0x00],
        'Ñ' => [0x36, 0x00, 0x63, 0x67, 0x6F, 0x7B, 0x63, 0x00],
        'á' | 'à' | 'ä' | 'â' => FONT8X8_BASIC[b'a' as usize - 0x20],
        'é' | 'è' | 'ë' | 'ê' => FONT8X8_BASIC[b'e' as usize - 0x20],
        'í' | 'ì' | 'ï' | 'î' => FONT8X8_BASIC[b'i' as usize - 0x20],
        'ó' | 'ò' | 'ö' | 'ô' => FONT8X8_BASIC[b'o' as usize - 0x20],
        'ú' | 'ù' | 'ü' | 'û' => FONT8X8_BASIC[b'u' as usize - 0x20],
        'Á' | 'À' | 'Ä' | 'Â' => FONT8X8_BASIC[b'A' as usize - 0x20],
        'É' | 'È' | 'Ë' | 'Ê' => FONT8X8_BASIC[b'E' as usize - 0x20],
        'Í' | 'Ì' | 'Ï' | 'Î' => FONT8X8_BASIC[b'I' as usize - 0x20],
        'Ó' | 'Ò' | 'Ö' | 'Ô' => FONT8X8_BASIC[b'O' as usize - 0x20],
        'Ú' | 'Ù' | 'Ü' | 'Û' => FONT8X8_BASIC[b'U' as usize - 0x20],
        c if (' '..='~').contains(&c) => FONT8X8_BASIC[(c as usize) - 0x20],
        _ => FONT8X8_BASIC[(b'?' as usize) - 0x20],
    }
}

/// Public-domain 8x8 bitmap font for printable ASCII `0x20..=0x7E` (LSB = left-most pixel).
const FONT8X8_BASIC: [[u8; 8]; 95] = [
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // ' '
    [0x18, 0x3C, 0x3C, 0x18, 0x18, 0x00, 0x18, 0x00], // '!'
    [0x36, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // '"'
    [0x36, 0x36, 0x7F, 0x36, 0x7F, 0x36, 0x36, 0x00], // '#'
    [0x0C, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x0C, 0x00], // '$'
    [0x00, 0x63, 0x33, 0x18, 0x0C, 0x66, 0x63, 0x00], // '%'
    [0x1C, 0x36, 0x1C, 0x6E, 0x3B, 0x33, 0x6E, 0x00], // '&'
    [0x06, 0x06, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00], // '\''
    [0x18, 0x0C, 0x06, 0x06, 0x06, 0x0C, 0x18, 0x00], // '('
    [0x06, 0x0C, 0x18, 0x18, 0x18, 0x0C, 0x06, 0x00], // ')'
    [0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00], // '*'
    [0x00, 0x0C, 0x0C, 0x3F, 0x0C, 0x0C, 0x00, 0x00], // '+'
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x06], // ','
    [0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00], // '-'
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C, 0x00], // '.'
    [0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x01, 0x00], // '/'
    [0x3E, 0x63, 0x73, 0x7B, 0x6F, 0x67, 0x3E, 0x00], // '0'
    [0x0C, 0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x3F, 0x00], // '1'
    [0x1E, 0x33, 0x30, 0x1C, 0x06, 0x33, 0x3F, 0x00], // '2'
    [0x1E, 0x33, 0x30, 0x1C, 0x30, 0x33, 0x1E, 0x00], // '3'
    [0x38, 0x3C, 0x36, 0x33, 0x7F, 0x30, 0x78, 0x00], // '4'
    [0x3F, 0x03, 0x1F, 0x30, 0x30, 0x33, 0x1E, 0x00], // '5'
    [0x1C, 0x06, 0x03, 0x1F, 0x33, 0x33, 0x1E, 0x00], // '6'
    [0x3F, 0x33, 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x00], // '7'
    [0x1E, 0x33, 0x33, 0x1E, 0x33, 0x33, 0x1E, 0x00], // '8'
    [0x1E, 0x33, 0x33, 0x3E, 0x30, 0x18, 0x0E, 0x00], // '9'
    [0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x00], // ':'
    [0x00, 0x0C, 0x0C, 0x00, 0x00, 0x0C, 0x0C, 0x06], // ';'
    [0x18, 0x0C, 0x06, 0x03, 0x06, 0x0C, 0x18, 0x00], // '<'
    [0x00, 0x00, 0x3F, 0x00, 0x00, 0x3F, 0x00, 0x00], // '='
    [0x06, 0x0C, 0x18, 0x30, 0x18, 0x0C, 0x06, 0x00], // '>'
    [0x1E, 0x33, 0x30, 0x18, 0x0C, 0x00, 0x0C, 0x00], // '?'
    [0x3E, 0x63, 0x7B, 0x7B, 0x7B, 0x03, 0x1E, 0x00], // '@'
    [0x0C, 0x1E, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x00], // 'A'
    [0x3F, 0x66, 0x66, 0x3E, 0x66, 0x66, 0x3F, 0x00], // 'B'
    [0x3C, 0x66, 0x03, 0x03, 0x03, 0x66, 0x3C, 0x00], // 'C'
    [0x1F, 0x36, 0x66, 0x66, 0x66, 0x36, 0x1F, 0x00], // 'D'
    [0x7F, 0x46, 0x16, 0x1E, 0x16, 0x46, 0x7F, 0x00], // 'E'
    [0x7F, 0x46, 0x16, 0x1E, 0x16, 0x06, 0x0F, 0x00], // 'F'
    [0x3C, 0x66, 0x03, 0x03, 0x73, 0x66, 0x7C, 0x00], // 'G'
    [0x33, 0x33, 0x33, 0x3F, 0x33, 0x33, 0x33, 0x00], // 'H'
    [0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // 'I'
    [0x78, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E, 0x00], // 'J'
    [0x67, 0x66, 0x36, 0x1E, 0x36, 0x66, 0x67, 0x00], // 'K'
    [0x0F, 0x06, 0x06, 0x06, 0x46, 0x66, 0x7F, 0x00], // 'L'
    [0x63, 0x77, 0x7F, 0x7F, 0x6B, 0x63, 0x63, 0x00], // 'M'
    [0x63, 0x67, 0x6F, 0x7B, 0x73, 0x63, 0x63, 0x00], // 'N'
    [0x1C, 0x36, 0x63, 0x63, 0x63, 0x36, 0x1C, 0x00], // 'O'
    [0x3F, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x0F, 0x00], // 'P'
    [0x1E, 0x33, 0x33, 0x33, 0x3B, 0x1E, 0x38, 0x00], // 'Q'
    [0x3F, 0x66, 0x66, 0x3E, 0x36, 0x66, 0x67, 0x00], // 'R'
    [0x1E, 0x33, 0x07, 0x0E, 0x38, 0x33, 0x1E, 0x00], // 'S'
    [0x3F, 0x2D, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // 'T'
    [0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x3F, 0x00], // 'U'
    [0x33, 0x33, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00], // 'V'
    [0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00], // 'W'
    [0x63, 0x63, 0x36, 0x1C, 0x1C, 0x36, 0x63, 0x00], // 'X'
    [0x33, 0x33, 0x33, 0x1E, 0x0C, 0x0C, 0x1E, 0x00], // 'Y'
    [0x7F, 0x63, 0x31, 0x18, 0x4C, 0x66, 0x7F, 0x00], // 'Z'
    [0x1E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x1E, 0x00], // '['
    [0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00], // '\\'
    [0x1E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1E, 0x00], // ']'
    [0x08, 0x1C, 0x36, 0x63, 0x00, 0x00, 0x00, 0x00], // '^'
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF], // '_'
    [0x0C, 0x0C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00], // '`'
    [0x00, 0x00, 0x1E, 0x30, 0x3E, 0x33, 0x6E, 0x00], // 'a'
    [0x07, 0x06, 0x06, 0x3E, 0x66, 0x66, 0x3B, 0x00], // 'b'
    [0x00, 0x00, 0x1E, 0x33, 0x03, 0x33, 0x1E, 0x00], // 'c'
    [0x38, 0x30, 0x30, 0x3e, 0x33, 0x33, 0x6E, 0x00], // 'd'
    [0x00, 0x00, 0x1E, 0x33, 0x3f, 0x03, 0x1E, 0x00], // 'e'
    [0x1C, 0x36, 0x06, 0x0f, 0x06, 0x06, 0x0F, 0x00], // 'f'
    [0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x1F], // 'g'
    [0x07, 0x06, 0x36, 0x6E, 0x66, 0x66, 0x67, 0x00], // 'h'
    [0x0C, 0x00, 0x0E, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // 'i'
    [0x30, 0x00, 0x30, 0x30, 0x30, 0x33, 0x33, 0x1E], // 'j'
    [0x07, 0x06, 0x66, 0x36, 0x1E, 0x36, 0x67, 0x00], // 'k'
    [0x0E, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x1E, 0x00], // 'l'
    [0x00, 0x00, 0x33, 0x7F, 0x7F, 0x6B, 0x63, 0x00], // 'm'
    [0x00, 0x00, 0x1F, 0x33, 0x33, 0x33, 0x33, 0x00], // 'n'
    [0x00, 0x00, 0x1E, 0x33, 0x33, 0x33, 0x1E, 0x00], // 'o'
    [0x00, 0x00, 0x3B, 0x66, 0x66, 0x3E, 0x06, 0x0F], // 'p'
    [0x00, 0x00, 0x6E, 0x33, 0x33, 0x3E, 0x30, 0x78], // 'q'
    [0x00, 0x00, 0x3B, 0x6E, 0x66, 0x06, 0x0F, 0x00], // 'r'
    [0x00, 0x00, 0x3E, 0x03, 0x1E, 0x30, 0x1F, 0x00], // 's'
    [0x08, 0x0C, 0x3E, 0x0C, 0x0C, 0x2C, 0x18, 0x00], // 't'
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x33, 0x6E, 0x00], // 'u'
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x1E, 0x0C, 0x00], // 'v'
    [0x00, 0x00, 0x63, 0x6B, 0x7F, 0x7F, 0x36, 0x00], // 'w'
    [0x00, 0x00, 0x63, 0x36, 0x1C, 0x36, 0x63, 0x00], // 'x'
    [0x00, 0x00, 0x33, 0x33, 0x33, 0x3E, 0x30, 0x1F], // 'y'
    [0x00, 0x00, 0x3F, 0x19, 0x0C, 0x26, 0x3F, 0x00], // 'z'
    [0x38, 0x0C, 0x0C, 0x07, 0x0C, 0x0C, 0x38, 0x00], // '{'
    [0x18, 0x18, 0x18, 0x00, 0x18, 0x18, 0x18, 0x00], // '|'
    [0x07, 0x0C, 0x0C, 0x38, 0x0C, 0x0C, 0x07, 0x00], // '}'
    [0x6E, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // '~'
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_overlay_text_lines_carriage_returns_and_newlines() {
        // Standalone carriage returns (\r), CRLF (\r\n), and LF (\n)
        let raw_cr = "RPM: 2450\rSpeed: 88 km/h\rCoolant: 91°C\r";
        let lines_cr = parse_overlay_text_lines(raw_cr);
        assert_eq!(
            lines_cr,
            vec!["RPM: 2450", "Speed: 88 km/h", "Coolant: 91°C"]
        );

        let raw_crlf = "\r\nSOC: 78%\r\nBatt Temp: 24°C\r\nPower: -12.4 kW\r\n";
        let lines_crlf = parse_overlay_text_lines(raw_crlf);
        assert_eq!(
            lines_crlf,
            vec!["SOC: 78%", "Batt Temp: 24°C", "Power: -12.4 kW"]
        );

        assert!(parse_overlay_text_lines("   \r\n  ").is_empty());
    }

    #[test]
    fn test_parse_overlay_json_payload_with_constants_and_newlines() {
        let json_raw = r#"{
            "poll_interval_ms": 250,
            "box_opacity_percent": 35,
            "box_margin_right_px": 100,
            "box_margin_bottom_px": 9,
            "box_padding_x_px": 12,
            "box_padding_y_px": 9,
            "box_border_px": 0,
            "text_scale": 2,
            "line_spacing_px": 6,
            "char_spacing_px": 1,
            "max_display_lines": 14,
            "max_line_chars": 42,
            "box_bg_rgb": [16, 22, 32],
            "box_border_rgb": [0, 200, 255],
            "text_rgb": [245, 250, 255],
            "text_shadow_rgb": [0, 0, 0],
            "h264_encoder_qp": 26,
            "h264_encoder_gop": 600,
            "only_main_display": true,
            "cap_video_fps_to_30": true,
            "text": "RPM: 2450\r\nSpeed: 88 km/h\nCoolant: 91°C\rSOC: 82%"
        }"#;

        let (cfg, lines) = parse_overlay_payload(json_raw);
        assert_eq!(cfg.box_opacity_percent, 35);
        assert_eq!(cfg.box_margin_right_px, 100);
        assert_eq!(cfg.box_margin_bottom_px, 9);
        assert_eq!(cfg.text_scale, 2);
        assert_eq!(cfg.box_bg_rgb, (16, 22, 32));
        assert!(cfg.cap_video_fps_to_30);
        assert_eq!(
            lines,
            vec!["RPM: 2450", "Speed: 88 km/h", "Coolant: 91°C", "SOC: 82%"]
        );

        // Verify empty "text" disables the overlay
        let empty_json = r#"{"box_opacity_percent": 50, "text": "   \r\n  "}"#;
        let (_, empty_lines) = parse_overlay_payload(empty_json);
        assert!(empty_lines.is_empty());
    }

    #[test]
    fn test_draw_overlay_box_yuv420_modifies_bottom_right_region() {
        let width = 320;
        let height = 240;
        let mut frame = YuvFrame {
            width,
            height,
            y: vec![200u8; width * height],
            u: vec![128u8; (width / 2) * (height / 2)],
            v: vec![128u8; (width / 2) * (height / 2)],
        };

        let lines = vec!["RPM: 2500".to_string(), "SPEED: 90 km/h".to_string()];
        draw_overlay_box_yuv420(&mut frame, &lines);

        // Top-left pixel should be untouched
        assert_eq!(frame.y[0], 200);

        // Bottom half of the frame should contain modified pixels from the text/box
        let bottom_half = &frame.y[(height / 2) * width..];
        assert!(bottom_half.iter().any(|&px| px != 200));
    }

    #[test]
    fn test_example_json_is_valid_and_matches_defaults() {
        let raw = include_str!("../examples/overlay.json");
        let (cfg, lines) = parse_overlay_payload(raw);
        assert_eq!(
            lines,
            vec!["RPM: 2450".to_string(), "OIL: 90°C".to_string()]
        );
        assert_eq!(
            OverlayConfig {
                text: String::new(),
                ..cfg
            },
            OverlayConfig::default(),
            "examples/overlay.json must list the built-in defaults"
        );
    }

    static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn lock_test_state() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn register_test_channel(ch: u8) {
        SESSION_ENABLED.store(true, Ordering::Release);
        set_overlay_text_path(Path::new(DEFAULT_OVERLAY_TEXT_PATH));
        CHANNEL_GATES.lock().unwrap().insert(
            ch,
            ChannelGateState {
                active_for_current_frame: true,
                pipeline_engaged: true,
            },
        );
        VIDEO_DECODERS
            .lock()
            .unwrap()
            .insert(ch, ChannelDecoderState::new(ch));
        VIDEO_ENCODERS
            .lock()
            .unwrap()
            .insert(ch, ChannelEncoderState::new(DisplayType::DISPLAY_TYPE_MAIN));
    }

    #[test]
    fn test_h264_roundtrip_overlay_pipeline() {
        let _guard = lock_test_state();
        let ch: u8 = 0x77;
        register_test_channel(ch);

        let width = 320;
        let height = 192;
        let enc_cfg = EncoderConfig::baseline(width, height);
        let mut source_encoder = Encoder::new(enc_cfg).expect("source encoder init");
        let src_frame = YuvFrame::black(width, height);
        let annex_b = source_encoder.encode(&src_frame);

        // Build MEDIA_MESSAGE_DATA payload: [0x00, 0x00, 8-byte timestamp, annex_b...]
        let mut media_msg = vec![0x00, 0x00, 0, 0, 0, 0, 0, 1, 0xE2, 0x40];
        media_msg.extend_from_slice(&annex_b);

        let lines = vec!["RPM: 3100".to_string(), "TEMP: 89°C".to_string()];
        let (out_msgs, modified) = process_video_data_frame_with_lines(ch, media_msg, &lines);
        assert!(modified);
        // First encoded frame emits synthetic CODEC_CONFIG + MEDIA_MESSAGE_DATA
        assert_eq!(out_msgs.len(), 2);
        assert_eq!(&out_msgs[0][0..2], &[0x00, 0x01]);
        assert_eq!(&out_msgs[1][0..2], &[0x00, 0x00]);

        // Verify downstream H.264 decoder can decode the emitted CODEC_CONFIG + DATA
        let mut verify_decoder = Decoder::new();
        assert!(verify_decoder.decode(&out_msgs[0][2..]).unwrap().is_none());
        let decoded_out = verify_decoder
            .decode(&out_msgs[1][10..])
            .unwrap()
            .expect("expected decoded YuvFrame");
        assert_eq!(decoded_out.width, width);
        assert_eq!(decoded_out.height, height);
    }

    #[test]
    fn test_car_hu_codec_config_and_pframe_conformance() {
        let _guard = lock_test_state();
        let ch: u8 = 0x78;
        register_test_channel(ch);

        let width = 800;
        let height = 480;
        let mut enc_cfg = EncoderConfig::baseline(width, height);
        enc_cfg.weightp = false;
        let mut source_encoder = Encoder::new(enc_cfg).expect("source encoder init");

        // Frame 0 (IDR + SPS/PPS)
        let frame0 = YuvFrame::black(width, height);
        let annex_b0 = source_encoder.encode(&frame0);

        // Extract SPS+PPS as CODEC_CONFIG (0x0001) like the Phone sends first
        let mut codec_cfg_msg = vec![0x00, 0x01];
        for nal in split_annex_b_nals(&annex_b0) {
            let nt = nal[0] & 0x1F;
            if nt == 7 || nt == 8 {
                codec_cfg_msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                codec_cfg_msg.extend_from_slice(nal);
            }
        }
        observe_codec_config(ch, &codec_cfg_msg);

        // Verify in-place CODEC_CONFIG replacement (1 message in -> 1 message out)
        let lines = vec!["RPM: 2200".to_string(), "SPEED: 100 km/h".to_string()];
        let (cfg_out, cfg_mod) = process_video_codec_config_in_place(ch, codec_cfg_msg);
        assert!(cfg_mod);
        assert_eq!(cfg_out.len(), 1);
        assert_eq!(&cfg_out[0][0..2], &[0x00, 0x01]);

        // Check patched SPS has constraint_flags == 0xC0 (Constrained Baseline)
        let out_nals = split_annex_b_nals(&cfg_out[0][2..]);
        let sps_nal = out_nals.iter().find(|n| (n[0] & 0x1F) == 7).unwrap();
        assert_eq!(sps_nal[1], 66); // Baseline profile_idc
        assert_eq!(sps_nal[2], 0xC0); // constraint_set0_flag=1, constraint_set1_flag=1

        // Verify Frame 0 (IDR) produces exactly 1 MEDIA_MESSAGE_DATA (no duplicate CODEC_CONFIG)
        let mut media_msg0 = vec![0x00, 0x00, 0, 0, 0, 0, 0, 1, 0x00, 0x00];
        media_msg0.extend_from_slice(&annex_b0);
        let (data_out0, mod0) = process_video_data_frame_with_lines(ch, media_msg0, &lines);
        assert!(mod0);
        assert_eq!(data_out0.len(), 1);
        assert_eq!(&data_out0[0][0..2], &[0x00, 0x00]);

        // Verify Frame 1 (P-frame) produces 1 MEDIA_MESSAGE_DATA with P-slice (NAL type 1)
        let mut frame1 = YuvFrame::black(width, height);
        frame1.y[1000] = 220;
        let annex_b1 = source_encoder.encode(&frame1);
        let mut media_msg1 = vec![0x00, 0x00, 0, 0, 0, 0, 0, 1, 0x80, 0x00];
        media_msg1.extend_from_slice(&annex_b1);
        let (data_out1, mod1) = process_video_data_frame_with_lines(ch, media_msg1, &lines);
        assert!(mod1);
        assert_eq!(data_out1.len(), 1);
        let f1_nals = split_annex_b_nals(&data_out1[0][10..]);
        assert!(f1_nals.iter().any(|n| (n[0] & 0x1F) == 1)); // P-slice present

        // Verify CODEC_CONFIG SPS+PPS is byte-for-byte identical to the SPS+PPS inside IDR frames
        // so Car HU hardware decoders never trigger a parameter-set-change reset.
        assert_eq!(
            &cfg_out[0][2..],
            &extract_sps_pps_annex_b(&data_out0[0][10..])
        );

        // Verify both decoders (rusty_h264 and strict rust_h264 Baseline decoder) decode
        // CODEC_CONFIG + IDR + P-frame without errors!
        let mut dec_a = Decoder::new();
        assert!(dec_a.decode(&cfg_out[0][2..]).unwrap().is_none());
        assert!(dec_a.decode(&data_out0[0][10..]).unwrap().is_some());
        assert!(dec_a.decode(&data_out1[0][10..]).unwrap().is_some());

        let mut dec_b = rust_h264::decoder::Decoder::new();
        for nal in &rust_h264::nal::parse_annex_b(&cfg_out[0][2..]) {
            let _ = dec_b.decode_nal(nal).expect("strict decoder SPS/PPS");
        }
        for nal in &rust_h264::nal::parse_annex_b(&data_out0[0][10..]) {
            let _ = dec_b.decode_nal(nal).expect("strict decoder IDR");
        }
        let mut idr_flushed_on_p = false;
        for nal in &rust_h264::nal::parse_annex_b(&data_out1[0][10..]) {
            if dec_b
                .decode_nal(nal)
                .expect("strict decoder P-frame")
                .is_some()
            {
                idr_flushed_on_p = true;
            }
        }
        assert!(idr_flushed_on_p);
        let p_flushed = dec_b.flush().expect("strict decoder flush P-frame");
        assert_eq!(p_flushed.width as usize, width);
        assert_eq!(p_flushed.height as usize, height);
    }

    #[test]
    fn test_fast_skip_and_full_encode_interleaving_conformance() {
        let _guard = lock_test_state();
        let ch: u8 = 0x79;
        register_test_channel(ch);

        let width = 800;
        let height = 480;
        let mut enc_cfg = EncoderConfig::baseline(width, height);
        enc_cfg.weightp = false;
        let mut source_encoder = Encoder::new(enc_cfg).expect("source encoder init");

        let mut dec_a = Decoder::new();
        let mut dec_b = rust_h264::decoder::Decoder::new();

        // Frame 0: initial IDR
        let mut cur_frame = YuvFrame::black(width, height);
        let annex_b0 = source_encoder.encode(&cur_frame);
        let mut codec_cfg_msg = vec![0x00, 0x01];
        for nal in split_annex_b_nals(&annex_b0) {
            let nt = nal[0] & 0x1F;
            if nt == 7 || nt == 8 {
                codec_cfg_msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                codec_cfg_msg.extend_from_slice(nal);
            }
        }
        observe_codec_config(ch, &codec_cfg_msg);
        let (cfg_out, _) = process_video_codec_config_in_place(ch, codec_cfg_msg);
        assert!(dec_a.decode(&cfg_out[0][2..]).unwrap().is_none());
        for nal in &rust_h264::nal::parse_annex_b(&cfg_out[0][2..]) {
            let _ = dec_b.decode_nal(nal).expect("strict decoder SPS/PPS");
        }

        let mut lines = vec!["RPM: 2500".to_string(), "SPEED: 110 km/h".to_string()];
        let mut msg0 = vec![0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 1];
        msg0.extend_from_slice(&annex_b0);
        let (out0, _) = process_video_data_frame_with_lines(ch, msg0, &lines);
        assert!(dec_a.decode(&out0[0][10..]).unwrap().is_some());
        for nal in &rust_h264::nal::parse_annex_b(&out0[0][10..]) {
            let _ = dec_b.decode_nal(nal).expect("strict decoder IDR");
        }

        let mut fast_skip_count = 0usize;
        let mut full_encode_count = 0usize;

        // Run 22 frames (crossing the 4-bit frame_num wrap-around at 16) mixing static frames,
        // screen motion frames, and overlay text change frames.
        for idx in 1..=22usize {
            if idx == 6 || idx == 14 || idx == 19 {
                // Simulate a screen update (e.g. map motion / UI change)
                for y in 40..100 {
                    for x in 40..120 {
                        cur_frame.y[y * width + x] = ((idx * 35) & 0xFF) as u8;
                    }
                }
            }
            if idx == 10 {
                // Simulate an overlay text update on a static video background
                lines = vec!["RPM: 3200".to_string(), "SPEED: 125 km/h".to_string()];
            }
            if idx == 16 {
                // Simulate clearing "text": "" mid-session after overlay was active
                lines = Vec::new();
            }

            let annex_b = source_encoder.encode(&cur_frame);
            let mut msg = vec![0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, idx as u8];
            msg.extend_from_slice(&annex_b);
            let (out, modified) = process_video_data_frame_with_lines(ch, msg, &lines);
            assert!(modified);
            let au = &out[0][10..];
            if au.len() == 11 {
                fast_skip_count += 1;
            } else {
                full_encode_count += 1;
            }

            // Both decoders must decode every single frame without error!
            let f_a = dec_a.decode(au).unwrap().expect("dec_a frame");
            assert_eq!(f_a.width, width);
            for nal in &rust_h264::nal::parse_annex_b(au) {
                let _ = dec_b.decode_nal(nal).expect("strict decoder P-slice");
            }
        }

        assert!(
            fast_skip_count >= 14,
            "expected most static frames to take 11B fast-skip path, got {}",
            fast_skip_count
        );
        assert_eq!(
            full_encode_count, 5,
            "expected 5 changed frames (3 motion + 1 text update + 1 text clear) to run full encode"
        );
        let final_b = dec_b.flush().expect("strict decoder flush final");
        assert_eq!(final_b.width as usize, width);
        assert_eq!(final_b.height as usize, height);
    }

    #[test]
    fn test_starts_when_enabled_with_empty_path_or_empty_text_and_adds_text_later() {
        use crate::mitm::protos::{MediaSinkService, Service, VideoConfiguration};
        let _guard = lock_test_state();

        // 1. Empty overlay_text_path resolves to DEFAULT_OVERLAY_TEXT_PATH and takes default config values
        assert_eq!(
            resolve_overlay_text_path(Path::new("")),
            PathBuf::from(DEFAULT_OVERLAY_TEXT_PATH)
        );
        assert_eq!(
            resolve_overlay_text_path(Path::new("   ")),
            PathBuf::from(DEFAULT_OVERLAY_TEXT_PATH)
        );

        let (default_cfg, empty_lines) = parse_overlay_payload("");
        assert_eq!(default_cfg, OverlayConfig::default());
        assert!(empty_lines.is_empty());

        // 2. JSON with empty or null "text" preserves config values and does not fail
        let (json_empty_text_cfg, json_empty_lines) =
            parse_overlay_payload(r#"{"box_opacity_percent": 40, "text": ""}"#);
        assert_eq!(json_empty_text_cfg.box_opacity_percent, 40);
        assert!(json_empty_lines.is_empty());

        let (json_null_text_cfg, json_null_lines) =
            parse_overlay_payload(r#"{"box_opacity_percent": 45, "text": null}"#);
        assert_eq!(json_null_text_cfg.box_opacity_percent, 45);
        assert!(json_null_lines.is_empty());

        // 3. When overlay_enabled = true and JSON has "text": "", SDR registration
        //    immediately starts the functionality (caps FPS to 30 and engages packet gate)
        let tmp_json = std::env::temp_dir().join(format!(
            "aa_proxy_overlay_empty_start_{}.json",
            std::process::id()
        ));
        fs::write(
            &tmp_json,
            r#"{"poll_interval_ms": 20, "box_opacity_percent": 50, "text": ""}"#,
        )
        .expect("write initial empty-text JSON");

        let ch: u8 = 0x7A;
        let mut sdr = ServiceDiscoveryResponse::new();
        let mut svc = Service::new();
        svc.set_id(i32::from(ch));
        let mut sink = MediaSinkService::new();
        sink.set_available_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
        sink.set_display_type(DisplayType::DISPLAY_TYPE_MAIN);
        let mut vc = VideoConfiguration::new();
        vc.set_frame_rate(VideoFrameRateType::VIDEO_FPS_60);
        sink.video_configs.push(vc);
        svc.media_sink_service = protobuf::MessageField::some(sink);
        sdr.services.push(svc);

        register_video_channels_from_sdr(
            &mut sdr,
            true,
            &tmp_json,
            Path::new(""),
            crate::config::OverlayHwAccel::None,
            "",
            "",
        );
        assert!(overlay_enabled());
        assert_eq!(
            sdr.services[0]
                .media_sink_service
                .as_ref()
                .unwrap()
                .video_configs[0]
                .frame_rate(),
            VideoFrameRateType::VIDEO_FPS_30
        );
        assert!(is_active_for_packet(
            ch,
            crate::mitm::FRAME_TYPE_FIRST | crate::mitm::FRAME_TYPE_LAST,
            &tmp_json,
            Path::new(""),
        ));

        // 4. Stream starts with empty text: CODEC_CONFIG and Frame 0 are processed by the pipeline
        let width = 320;
        let height = 192;
        let mut enc_cfg = EncoderConfig::baseline(width, height);
        enc_cfg.weightp = false;
        let mut source_encoder = Encoder::new(enc_cfg).expect("source encoder init");
        let src_frame = YuvFrame {
            width,
            height,
            y: vec![200u8; width * height],
            u: vec![128u8; (width / 2) * (height / 2)],
            v: vec![128u8; (width / 2) * (height / 2)],
        };
        let annex_b0 = source_encoder.encode(&src_frame);

        let mut codec_cfg_msg = vec![0x00, 0x01];
        for nal in split_annex_b_nals(&annex_b0) {
            let nt = nal[0] & 0x1F;
            if nt == 7 || nt == 8 {
                codec_cfg_msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
                codec_cfg_msg.extend_from_slice(nal);
            }
        }
        let (cfg_out, cfg_mod) = process_video_media_message(ch, codec_cfg_msg);
        assert!(
            cfg_mod,
            "CODEC_CONFIG must be rewritten even when text is empty"
        );

        let mut msg0 = vec![0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 1];
        msg0.extend_from_slice(&annex_b0);
        let (out0, mod0) = process_video_media_message(ch, msg0);
        assert!(mod0, "Frame 0 must be processed even when text is empty");

        // 5. Now add text to the JSON file mid-session and verify the next frame renders it
        fs::write(
            &tmp_json,
            r#"{"poll_interval_ms": 20, "box_opacity_percent": 80, "text": "RPM: 3000\nSOC: 85%"}"#,
        )
        .expect("write updated text JSON");
        if let Ok(mut cache) = OVERLAY_TEXT_CACHE.lock() {
            cache.last_check = None;
        }

        let annex_b1 = source_encoder.encode(&src_frame);
        let mut msg1 = vec![0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 2];
        msg1.extend_from_slice(&annex_b1);
        let (out1, mod1) = process_video_media_message(ch, msg1);
        assert!(mod1);
        assert!(
            out1[0][10..].len() > 11,
            "Frame with newly added text must run full encode, not 11B skip"
        );

        let mut dec = Decoder::new();
        assert!(dec.decode(&cfg_out[0][2..]).unwrap().is_none());
        let decoded0 = dec.decode(&out0[0][10..]).unwrap().expect("decode frame 0");
        let decoded1 = dec.decode(&out1[0][10..]).unwrap().expect("decode frame 1");
        assert_ne!(
            decoded0.y, decoded1.y,
            "Decoded frame after adding text must differ from empty-text frame"
        );

        let _ = fs::remove_file(&tmp_json);
    }

    #[test]
    fn test_deserialize_text_scale_and_font_path() {
        let json_int = r#"{"text_scale": 24, "font_path": "/tmp/custom.ttf"}"#;
        let (cfg_int, _) = parse_overlay_payload(json_int);
        assert_eq!(cfg_int.text_scale, 24);
        assert_eq!(cfg_int.font_path, "/tmp/custom.ttf");

        let json_float = r#"{"text_scale": 28.4}"#;
        let (cfg_float, _) = parse_overlay_payload(json_float);
        assert_eq!(cfg_float.text_scale, 28);

        let json_str = r#"{"text_scale": "32"}"#;
        let (cfg_str, _) = parse_overlay_payload(json_str);
        assert_eq!(cfg_str.text_scale, 32);

        let json_default = r#"{}"#;
        let (cfg_def, _) = parse_overlay_payload(json_default);
        assert_eq!(cfg_def.text_scale, TEXT_SCALE);
        assert_eq!(cfg_def.font_path, "");
    }

    #[test]
    fn test_ttf_font_fallback_and_rendering() {
        let _guard = lock_test_state();

        // 1. Empty font path returns None -> fallback to bitmap font
        set_overlay_font_path(Path::new(""));
        assert!(get_cached_overlay_font().is_none());

        // Verify drawing works with None font (bitmap mode)
        let mut frame_bitmap = YuvFrame::black(640, 480);
        let lines = vec!["SPEED: 100 KM/H".to_string(), "RPM: 3500".to_string()];
        draw_overlay_box_yuv420(&mut frame_bitmap, &lines);
        let non_zero_y_bitmap = frame_bitmap.y.iter().filter(|&&y| y > 16).count();
        assert!(non_zero_y_bitmap > 0, "Bitmap rendering must modify pixels");

        // 2. Nonexistent font path returns None -> fallback to bitmap font
        set_overlay_font_path(Path::new("/tmp/nonexistent_font_12345.ttf"));
        assert!(get_cached_overlay_font().is_none());

        // 3. Empty font file (0 bytes) returns None -> fallback to bitmap font
        let tmp_empty = std::env::temp_dir().join(format!("empty_font_{}.ttf", std::process::id()));
        fs::write(&tmp_empty, b"").expect("write empty font file");
        set_overlay_font_path(&tmp_empty);
        assert!(get_cached_overlay_font().is_none());
        let _ = fs::remove_file(&tmp_empty);

        // 4. Invalid / corrupt font file returns None -> fallback to bitmap font
        let tmp_corrupt =
            std::env::temp_dir().join(format!("corrupt_font_{}.ttf", std::process::id()));
        fs::write(&tmp_corrupt, b"this is not a valid ttf file").expect("write corrupt font file");
        set_overlay_font_path(&tmp_corrupt);
        assert!(get_cached_overlay_font().is_none());
        let _ = fs::remove_file(&tmp_corrupt);

        // 5. If a real TTF font is available on the system, verify TTF rendering and text_scale
        let system_fonts = [
            Path::new("/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf"),
            Path::new("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path::new("/etc/aa-proxy-rs/FreeSans.ttf"),
        ];
        let found_font = system_fonts.iter().copied().find(|p| p.exists());
        if let Some(system_font) = found_font {
            set_overlay_font_path(system_font);
            let font = get_cached_overlay_font();
            assert!(font.is_some(), "Valid TTF font should parse successfully");

            let mut cfg_ttf = OverlayConfig {
                text_scale: 24, // Used as font size
                box_opacity_percent: 50,
                ..OverlayConfig::default()
            };

            let mut frame_ttf = YuvFrame::black(640, 480);
            draw_overlay_box_yuv420_with_config(&mut frame_ttf, &lines, &cfg_ttf);
            let non_zero_y_ttf = frame_ttf.y.iter().filter(|&&y| y > 16).count();
            assert!(
                non_zero_y_ttf > 0,
                "TTF font rendering must draw characters"
            );

            // Verify changing text_scale changes the rendered glyph size / layout
            cfg_ttf.text_scale = 36;
            let mut frame_ttf_larger = YuvFrame::black(640, 480);
            draw_overlay_box_yuv420_with_config(&mut frame_ttf_larger, &lines, &cfg_ttf);
            let non_zero_y_larger = frame_ttf_larger.y.iter().filter(|&&y| y > 16).count();
            assert_ne!(
                non_zero_y_ttf, non_zero_y_larger,
                "Larger text_scale font size must produce different pixel counts"
            );
        }

        // Reset font path back to empty after test
        set_overlay_font_path(Path::new(""));
    }

    #[test]
    fn test_parse_css_color() {
        assert_eq!(parse_css_color("#fff"), Some((255, 255, 255)));
        assert_eq!(parse_css_color("#000"), Some((0, 0, 0)));
        assert_eq!(parse_css_color("#ff0000"), Some((255, 0, 0)));
        assert_eq!(parse_css_color("#00ff00"), Some((0, 255, 0)));
        assert_eq!(parse_css_color("#0000ff"), Some((0, 0, 255)));
        assert_eq!(parse_css_color("rgb(255, 128, 0)"), Some((255, 128, 0)));
        assert_eq!(parse_css_color("red"), Some((255, 0, 0)));
        assert_eq!(parse_css_color("YELLOW"), Some((255, 255, 0)));
        assert_eq!(parse_css_color("blue"), Some((0, 100, 255)));
        assert_eq!(parse_css_color("invalid_color"), None);
    }

    #[test]
    fn test_html_breaks_and_line_limits() {
        let raw = "<b>RPM:</b> 2500<br><b>Speed:</b> 80 km/h<br/><b>Coolant:</b> 90°C";
        let lines = parse_overlay_text_lines(raw);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "<b>RPM:</b> 2500");
        assert_eq!(lines[1], "<b>Speed:</b> 80 km/h");
        assert_eq!(lines[2], "<b>Coolant:</b> 90°C");

        // Verify that long HTML tags do not truncate the visible text prematurely
        let long_tag_line =
            r#"<span style="color: #ff0000; background-color: #000022">RPM: 3500</span>"#;
        let parsed_long = parse_overlay_text_lines(long_tag_line);
        assert_eq!(parsed_long.len(), 1);
        assert!(parsed_long[0].contains("RPM: 3500"));
    }

    #[test]
    fn test_parse_html_line_styles() {
        let line = r##"<b>Bold</b> <i>Italic</i> <font color="#ff0000">Red</font> <span style="background-color: #0000ff; color: #ffff00">BlueBg YellowText</span>"##;
        let styled = parse_html_line(line, (255, 255, 255), 24.0);

        // Find bold span
        let bold_span = styled.spans.iter().find(|s| s.text == "Bold").unwrap();
        assert!(bold_span.bold);
        assert!(!bold_span.italic);

        // Find italic span
        let italic_span = styled.spans.iter().find(|s| s.text == "Italic").unwrap();
        assert!(!italic_span.bold);
        assert!(italic_span.italic);

        // Find red span
        let red_span = styled.spans.iter().find(|s| s.text == "Red").unwrap();
        assert_eq!(red_span.fg_color, (255, 0, 0));

        // Find span with bg and fg
        let span_both = styled
            .spans
            .iter()
            .find(|s| s.text == "BlueBg YellowText")
            .unwrap();
        assert_eq!(span_both.bg_color, Some((0, 0, 255)));
        assert_eq!(span_both.fg_color, (255, 255, 0));
    }

    #[test]
    fn test_strip_html_tags_for_bitmap() {
        let html = "<b>RPM:</b> <font color=\"#ff0000\">2500</font> &amp; <span style=\"color: yellow\">OK</span>";
        let stripped = strip_html_tags(html);
        assert_eq!(stripped, "RPM: 2500 & OK");
    }

    #[test]
    fn test_ttf_rendering_with_html_colors_and_styles() {
        let _guard = lock_test_state();

        let system_fonts = [
            Path::new("/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf"),
            Path::new("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path::new("/etc/aa-proxy-rs/FreeSans.ttf"),
        ];
        let found_font = system_fonts.iter().copied().find(|p| p.exists());
        if let Some(font_path) = found_font {
            set_overlay_font_path(font_path);
            let font = get_cached_overlay_font();
            assert!(font.is_some());

            let cfg = OverlayConfig {
                text_scale: 24,
                box_opacity_percent: 60,
                ..OverlayConfig::default()
            };

            let lines = vec![
                "<b>RPM:</b> <font color=\"#ff0000\">3200</font>".to_string(),
                "<span style=\"background-color: #0000ff; color: #ffff00\">SPEED: 95 KM/H</span>"
                    .to_string(),
            ];

            let mut frame = YuvFrame::black(640, 480);
            draw_overlay_box_yuv420_with_config(&mut frame, &lines, &cfg);

            // Verify pixels were written to Y and chroma planes U/V
            let non_zero_y = frame.y.iter().filter(|&&y| y > 16).count();
            let non_128_u = frame.u.iter().filter(|&&u| u != 128).count();
            let non_128_v = frame.v.iter().filter(|&&v| v != 128).count();

            assert!(non_zero_y > 0, "Y plane must be modified by text");
            assert!(
                non_128_u > 0,
                "U plane must be modified by colored text/background"
            );
            assert!(
                non_128_v > 0,
                "V plane must be modified by colored text/background"
            );
        }

        set_overlay_font_path(Path::new(""));
    }

    #[test]
    fn test_parse_css_color_non_ascii_does_not_panic() {
        // Byte-slicing a non-ASCII "#..." used to panic (and abort the whole process in release).
        for s in [
            "#é1", "#aéaaa", "#ł", "#日1", "#😀", "#aa😀a", "#°#", "#ff ła",
        ] {
            assert_eq!(parse_css_color(s), None, "{s:?}");
        }
        assert_eq!(parse_css_color("#0f0"), Some((0, 255, 0)));
    }

    #[test]
    fn test_html_and_text_parsers_never_panic_on_garbage() {
        let pieces = [
            "<",
            ">",
            "</",
            "/>",
            "<b>",
            "</b>",
            "<i>",
            "<u>",
            "<br>",
            "<span style=\"",
            "\">",
            "color:",
            "#",
            "é",
            "ą",
            "ł",
            "°",
            "日",
            "😀",
            "&amp;",
            "&",
            ";",
            "rgb(",
            ")",
            ",",
            "background-color:",
            "font-size:",
            "999",
            "-1",
            " ",
            "'",
            "=",
            "font",
            "mark",
            "a",
            "1",
            "ff",
            "\\n",
            "\n",
            "\r",
        ];
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let n = (next() % 14) as usize + 1;
            let mut s = String::new();
            for _ in 0..n {
                s.push_str(pieces[(next() % pieces.len() as u64) as usize]);
            }
            let _ = parse_css_color(&s);
            let _ = parse_html_line(&s, (255, 255, 255), 24.0);
            let _ = strip_html_tags(&s);
            let lines = parse_overlay_text_lines(&s);
            let mut frame = YuvFrame::black(160, 96);
            draw_overlay_box_yuv420_with_config_and_font(
                &mut frame,
                &lines,
                &OverlayConfig::default(),
                None,
            );
        }
    }

    #[test]
    fn test_text_scale_is_bounded() {
        assert_eq!(ttf_base_font_size(0), 12.0);
        assert_eq!(ttf_base_font_size(1), 12.0);
        assert_eq!(ttf_base_font_size(2), 24.0);
        assert_eq!(ttf_base_font_size(4), 48.0);
        assert_eq!(ttf_base_font_size(5), 5.0);
        assert_eq!(ttf_base_font_size(26), 26.0);
        assert_eq!(ttf_base_font_size(100_000), MAX_TTF_FONT_PX);
        assert_eq!(ttf_base_font_size(usize::MAX), MAX_TTF_FONT_PX);

        // The built-in font must not overflow or take forever with an absurd scale either.
        let cfg = OverlayConfig {
            text_scale: usize::MAX,
            ..OverlayConfig::default()
        };
        let mut frame = YuvFrame::black(320, 192);
        let t = Instant::now();
        draw_overlay_box_yuv420_with_config_and_font(
            &mut frame,
            &["RPM 2450".to_string()],
            &cfg,
            None,
        );
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn test_json_font_path_takes_precedence_and_is_not_overwritten_by_config() {
        let _guard = lock_test_state();
        let current = || OVERLAY_FONT_CACHE.lock().unwrap().path.clone();

        set_overlay_font_path(Path::new("/cfg/a.ttf"));
        assert_eq!(current(), PathBuf::from("/cfg/a.ttf"));

        set_overlay_json_font_path("/json/b.ttf");
        assert_eq!(current(), PathBuf::from("/json/b.ttf"));

        // The packet hook re-applies the config path on every frame; it must not undo the JSON one.
        for _ in 0..3 {
            set_overlay_font_path(Path::new("/cfg/a.ttf"));
            assert_eq!(current(), PathBuf::from("/json/b.ttf"));
        }

        // Removing "font_path" from the JSON falls back to the config path.
        set_overlay_json_font_path("");
        assert_eq!(current(), PathBuf::from("/cfg/a.ttf"));

        set_overlay_font_path(Path::new(""));
        assert_eq!(current(), PathBuf::new());
    }

    #[test]
    fn test_invalid_font_is_parsed_once_per_file_version() {
        let _guard = lock_test_state();
        let tmp = std::env::temp_dir().join(format!("overlay_bad_font_{}.ttf", std::process::id()));
        fs::write(&tmp, b"definitely not a font").unwrap();

        let force_check = || OVERLAY_FONT_CACHE.lock().unwrap().last_check = None;
        let before = FONT_LOAD_ATTEMPTS.load(Ordering::Relaxed);

        set_overlay_font_path(&tmp);
        for _ in 0..5 {
            force_check();
            assert!(get_cached_overlay_font().is_none());
        }
        assert_eq!(
            FONT_LOAD_ATTEMPTS.load(Ordering::Relaxed) - before,
            1,
            "an unparsable font must not be re-read and re-parsed on every check"
        );

        // A changed file (new modification time) is tried again.
        fs::write(&tmp, b"still not a font, but different").unwrap();
        let f = fs::OpenOptions::new().write(true).open(&tmp).unwrap();
        f.set_modified(std::time::SystemTime::now() + Duration::from_secs(10))
            .unwrap();
        drop(f);
        force_check();
        assert!(get_cached_overlay_font().is_none());
        assert_eq!(FONT_LOAD_ATTEMPTS.load(Ordering::Relaxed) - before, 2);

        set_overlay_font_path(Path::new(""));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_html_single_quoted_attributes() {
        let styled = parse_html_line(
            "<font color='#00ff00'>A</font><span style='color: red; background: #000033'>B</span>",
            (255, 255, 255),
            24.0,
        );
        assert_eq!(styled.spans[0].fg_color, (0, 255, 0));
        assert_eq!(styled.spans[1].fg_color, (255, 0, 0));
        assert_eq!(styled.spans[1].bg_color, Some((0, 0, 51)));
    }

    #[test]
    fn test_overlay_hw_accel_auto_fallback_to_software() {
        let _guard = lock_test_state();
        let mut sdr = ServiceDiscoveryResponse::new();
        let mut svc = crate::mitm::protos::Service::new();
        svc.set_id(0x03);
        let mut sink = crate::mitm::protos::MediaSinkService::new();
        sink.set_available_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
        sink.set_display_type(DisplayType::DISPLAY_TYPE_MAIN);
        svc.media_sink_service = protobuf::MessageField::some(sink);
        sdr.services.push(svc);

        register_video_channels_from_sdr(
            &mut sdr,
            true,
            Path::new("/dev/shm/overlay_test.json"),
            Path::new(""),
            crate::config::OverlayHwAccel::Auto,
            "",
            "",
        );
        assert!(overlay_enabled());
        assert!(is_registered_video_channel(0x03));

        // Decoder and encoder states must be created and ready
        assert!(VIDEO_DECODERS.lock().unwrap().contains_key(&0x03));
        assert!(VIDEO_ENCODERS.lock().unwrap().contains_key(&0x03));
    }

    #[test]
    fn test_overlay_hw_accel_v4l2_explicit_invalid_device_fallback() {
        let _guard = lock_test_state();
        let mut sdr = ServiceDiscoveryResponse::new();
        let mut svc = crate::mitm::protos::Service::new();
        svc.set_id(0x05);
        let mut sink = crate::mitm::protos::MediaSinkService::new();
        sink.set_available_type(MediaCodecType::MEDIA_CODEC_VIDEO_H264_BP);
        sink.set_display_type(DisplayType::DISPLAY_TYPE_MAIN);
        svc.media_sink_service = protobuf::MessageField::some(sink);
        sdr.services.push(svc);

        register_video_channels_from_sdr(
            &mut sdr,
            true,
            Path::new("/dev/shm/overlay_test.json"),
            Path::new(""),
            crate::config::OverlayHwAccel::V4l2,
            "/dev/nonexistent_v4l2_dec",
            "/dev/nonexistent_v4l2_enc",
        );
        assert!(overlay_enabled());
        assert!(is_registered_video_channel(0x05));

        // When invalid paths are passed, fallback to software ensures states exist and run
        assert!(VIDEO_DECODERS.lock().unwrap().contains_key(&0x05));
        assert!(VIDEO_ENCODERS.lock().unwrap().contains_key(&0x05));
    }
}
