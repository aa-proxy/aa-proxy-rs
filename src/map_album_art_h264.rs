use crate::config::AppConfig;
use crate::map_album_art::{global_album_art_store, validate_png, MapAlbumArtSource};
use log::{debug, info, warn};
use rust_h264::decoder::{Decoder, Frame};
use rust_h264::nal::parse_annex_b;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const MEDIA_MESSAGE_CODEC_CONFIG: u16 = 0x0001;
const MEDIA_MESSAGE_DATA: u16 = 0x0000;
const RUST_H264_SOURCE: &str = "rust_h264";
const DEFAULT_OUTPUT_SIZE: u32 = 256;
const MIN_OUTPUT_SIZE: u32 = 32;
const MAX_OUTPUT_SIZE: u32 = 1024;

#[derive(Clone, Debug)]
struct H264ArtOptions {
    capture_interval_ms: u64,
    output_size_px: u32,
    crop_enabled: bool,
    crop_mode: CropMode,
    crop_x: u32,
    crop_y: u32,
    crop_w: u32,
    crop_h: u32,
    max_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CropMode {
    Percent,
    Pixel,
}

impl CropMode {
    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "pixel" | "pixels" | "px" => Self::Pixel,
            _ => Self::Percent,
        }
    }
}

impl H264ArtOptions {
    fn from_config(cfg: &AppConfig) -> Self {
        Self {
            capture_interval_ms: cfg.map_album_art_capture_interval_ms,
            output_size_px: clamp_output_size(cfg.map_album_art_output_size_px),
            crop_enabled: cfg.map_album_art_crop_enabled,
            crop_mode: CropMode::parse(&cfg.map_album_art_crop_mode),
            crop_x: cfg.map_album_art_crop_x,
            crop_y: cfg.map_album_art_crop_y,
            crop_w: cfg.map_album_art_crop_w,
            crop_h: cfg.map_album_art_crop_h,
            max_bytes: cfg.map_album_art_max_bytes,
        }
    }
}

#[derive(Debug)]
struct CapturedPng {
    png: Vec<u8>,
    frame_width: usize,
    frame_height: usize,
    crop: CropRect,
    output_size: u32,
    nal_count: usize,
}

#[derive(Debug)]
enum H264ArtCommand {
    CodecConfig {
        data: Vec<u8>,
    },
    VideoFrame {
        data: Vec<u8>,
        options: H264ArtOptions,
        is_idr: bool,
    },
}

static H264_ART_TX: OnceLock<Sender<H264ArtCommand>> = OnceLock::new();

#[derive(Clone, Debug)]
struct SelectedInternalTap {
    display_id: String,
    channel: u8,
}

static SELECTED_INTERNAL_TAP: OnceLock<Mutex<Option<SelectedInternalTap>>> = OnceLock::new();

fn selected_internal_tap() -> &'static Mutex<Option<SelectedInternalTap>> {
    SELECTED_INTERNAL_TAP.get_or_init(|| Mutex::new(None))
}

pub(crate) fn set_internal_tap_channel(display_id: &str, channel: u8) {
    let mut guard = selected_internal_tap().lock().unwrap();
    let changed = guard
        .as_ref()
        .map(|tap| tap.display_id != display_id || tap.channel != channel)
        .unwrap_or(true);

    *guard = Some(SelectedInternalTap {
        display_id: display_id.to_string(),
        channel,
    });

    if changed {
        info!(
            "map album art h264: selected internal tap display={} ch={:#04x}",
            display_id, channel
        );
    }
}

pub(crate) fn clear_internal_tap_channel() {
    let mut guard = selected_internal_tap().lock().unwrap();
    if guard.take().is_some() {
        info!("map album art h264: cleared selected internal tap");
    }
}

fn internal_tap_matches(target_display_id: &str, channel: u8) -> Option<String> {
    let guard = selected_internal_tap().lock().unwrap();
    guard.as_ref().and_then(|tap| {
        if tap.display_id == target_display_id && tap.channel == channel {
            Some(tap.display_id.clone())
        } else {
            None
        }
    })
}

fn h264_art_tx() -> &'static Sender<H264ArtCommand> {
    H264_ART_TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<H264ArtCommand>();
        std::thread::Builder::new()
            .name("map-album-art-h264".to_string())
            .spawn(move || h264_worker(rx))
            .expect("failed to spawn map album art h264 worker");
        tx
    })
}

pub(crate) fn target_display_id<'a>(cfg: &'a AppConfig) -> Option<&'a str> {
    if !cfg.map_album_art_enabled
        || MapAlbumArtSource::parse(&cfg.map_album_art_source) != MapAlbumArtSource::RustH264
    {
        return None;
    }

    let id = cfg.map_album_art_video_display_id.trim();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

pub(crate) fn is_active(cfg: &AppConfig) -> bool {
    target_display_id(cfg).is_some()
}

pub(crate) fn maybe_feed_media_frame(
    cfg: &AppConfig,
    channel: u8,
    inject_display_id: Option<&str>,
    frame_data: &[u8],
) {
    if !is_active(cfg) {
        return;
    }

    let target_display_id = cfg.map_album_art_video_display_id.trim();
    let display_matches = inject_display_id
        .map(|id| id == target_display_id)
        .unwrap_or(false);
    let internal_match_display = internal_tap_matches(target_display_id, channel);

    if !display_matches && internal_match_display.is_none() {
        return;
    }

    if frame_data.len() < 2 {
        return;
    }

    let matched_display = inject_display_id
        .map(|id| id.to_string())
        .or(internal_match_display)
        .unwrap_or_else(|| target_display_id.to_string());
    let match_reason = if display_matches {
        "display_id"
    } else {
        "internal_tap"
    };

    let message_id = u16::from_be_bytes([frame_data[0], frame_data[1]]);
    match message_id {
        MEDIA_MESSAGE_CODEC_CONFIG => {
            let codec_data = &frame_data[2..];
            if codec_data.is_empty() {
                return;
            }
            if h264_art_tx()
                .send(H264ArtCommand::CodecConfig {
                    data: codec_data.to_vec(),
                })
                .is_ok()
            {
                info!(
                    "map album art h264: queued codec config from display={} ch={:#04x} match={} ({} bytes)",
                    matched_display,
                    channel,
                    match_reason,
                    codec_data.len()
                );
            }
        }
        MEDIA_MESSAGE_DATA => {
            const TIMESTAMP_HEADER: usize = 8;
            let payload = &frame_data[2..];
            if payload.len() <= TIMESTAMP_HEADER {
                return;
            }
            let media_data = &payload[TIMESTAMP_HEADER..];
            let is_idr = contains_idr_nal(media_data);
            let options = H264ArtOptions::from_config(cfg);
            if h264_art_tx()
                .send(H264ArtCommand::VideoFrame {
                    data: media_data.to_vec(),
                    options,
                    is_idr,
                })
                .is_ok()
                && is_idr
            {
                info!(
                    "map album art h264: queued IDR sync frame from display={} ch={:#04x} match={} ({} bytes)",
                    matched_display,
                    channel,
                    match_reason,
                    media_data.len()
                );
            }
        }
        _ => {}
    }
}

fn h264_worker(rx: Receiver<H264ArtCommand>) {
    let mut decoder = Decoder::new();
    let mut codec_config: Option<Vec<u8>> = None;
    let mut synced_to_idr = false;
    let mut last_emit_at: Option<Instant> = None;
    let mut last_warn_at: Option<Instant> = None;
    let mut last_status_log_at: Option<Instant> = None;
    let mut codec_config_received_at: Option<Instant> = None;
    let mut last_au_at: Option<Instant> = None;
    let mut last_idr_at: Option<Instant> = None;
    let mut last_decoded_at: Option<Instant> = None;
    let mut access_units_seen: u64 = 0;
    let mut decoded_frames_seen: u64 = 0;
    let mut idr_frames_seen: u64 = 0;

    loop {
        let cmd = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(cmd) => cmd,
            Err(RecvTimeoutError::Timeout) => {
                maybe_log_h264_status(
                    &mut last_status_log_at,
                    codec_config_received_at,
                    last_au_at,
                    last_idr_at,
                    last_decoded_at,
                    last_emit_at,
                    synced_to_idr,
                    access_units_seen,
                    idr_frames_seen,
                    decoded_frames_seen,
                );
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };

        match cmd {
            H264ArtCommand::CodecConfig { data } => {
                decoder = Decoder::new();
                synced_to_idr = false;
                access_units_seen = 0;
                decoded_frames_seen = 0;
                idr_frames_seen = 0;
                last_emit_at = None;
                codec_config_received_at = Some(Instant::now());
                last_au_at = None;
                last_idr_at = None;
                last_decoded_at = None;
                last_status_log_at = None;

                let nal_count = match feed_codec_config_to_decoder(&mut decoder, &data) {
                    Ok(nal_count) => nal_count,
                    Err(e) => {
                        decoder = Decoder::new();
                        throttle_warn(
                            &mut last_warn_at,
                            &format!("map album art h264: stored codec config but decoder rejected it: {}", e),
                        );
                        0
                    }
                };

                info!(
                    "map album art h264: stored codec config ({} bytes, nals={}); decoder reset, waiting for first IDR",
                    data.len(),
                    nal_count
                );
                codec_config = Some(data);
            }
            H264ArtCommand::VideoFrame {
                data,
                options,
                is_idr,
            } => {
                access_units_seen = access_units_seen.saturating_add(1);
                last_au_at = Some(Instant::now());
                if is_idr {
                    last_idr_at = last_au_at;
                }

                let Some(codec_config) = codec_config.as_ref() else {
                    throttle_warn(
                        &mut last_warn_at,
                        "map album art h264: DATA arrived before codec config; skipping",
                    );
                    continue;
                };

                if !synced_to_idr && !is_idr {
                    if access_units_seen == 1 || access_units_seen % 256 == 0 {
                        info!(
                            "map album art h264: waiting for first IDR before feeding P-frames (seen={} AUs, last_au_bytes={})",
                            access_units_seen,
                            data.len()
                        );
                    }
                    maybe_log_h264_status(
                        &mut last_status_log_at,
                        codec_config_received_at,
                        last_au_at,
                        last_idr_at,
                        last_decoded_at,
                        last_emit_at,
                        synced_to_idr,
                        access_units_seen,
                        idr_frames_seen,
                        decoded_frames_seen,
                    );
                    continue;
                }

                if is_idr {
                    idr_frames_seen = idr_frames_seen.saturating_add(1);

                    // IDR is a clean random-access point. Re-prime the decoder with
                    // the latest SPS/PPS before feeding this AU, then keep the same
                    // decoder alive for all following P/B frames.
                    decoder = Decoder::new();
                    if let Err(e) = feed_codec_config_to_decoder(&mut decoder, codec_config) {
                        decoder = Decoder::new();
                        throttle_warn(
                            &mut last_warn_at,
                            &format!("map album art h264: failed to prime decoder from codec config; trying IDR anyway: {}", e),
                        );
                    }

                    if synced_to_idr {
                        info!(
                            "map album art h264: IDR resync observed (idr_count={}, seen={} AUs, decoded={} frames)",
                            idr_frames_seen,
                            access_units_seen,
                            decoded_frames_seen
                        );
                    } else {
                        info!(
                            "map album art h264: first IDR sync observed after {} AUs; starting continuous decode",
                            access_units_seen
                        );
                    }
                    synced_to_idr = true;
                }

                let (decoded, nal_count) = match feed_access_unit_to_decoder(&mut decoder, &data) {
                    Ok(result) => result,
                    Err(e) => {
                        throttle_warn(
                            &mut last_warn_at,
                            &format!(
                                "map album art h264: decoder rejected AU (idr={}): {}",
                                is_idr, e
                            ),
                        );
                        if is_idr {
                            synced_to_idr = false;
                        }
                        continue;
                    }
                };

                let Some(frame) = decoded else {
                    maybe_log_h264_status(
                        &mut last_status_log_at,
                        codec_config_received_at,
                        last_au_at,
                        last_idr_at,
                        last_decoded_at,
                        last_emit_at,
                        synced_to_idr,
                        access_units_seen,
                        idr_frames_seen,
                        decoded_frames_seen,
                    );
                    continue;
                };
                decoded_frames_seen = decoded_frames_seen.saturating_add(1);
                last_decoded_at = Some(Instant::now());
                if decoded_frames_seen == 1 {
                    info!(
                        "map album art h264: first decoded frame ({}x{}, seen={} AUs, idrs={})",
                        frame.width, frame.height, access_units_seen, idr_frames_seen
                    );
                }

                let interval = Duration::from_millis(options.capture_interval_ms);
                if options.capture_interval_ms > 0 {
                    if let Some(last) = last_emit_at {
                        if last.elapsed() < interval {
                            continue;
                        }
                    }
                }

                match capture_frame_to_png(&frame, nal_count, &options) {
                    Ok(captured) => {
                        if let Err(e) = validate_png(&captured.png, options.max_bytes) {
                            throttle_warn(
                                &mut last_warn_at,
                                &format!("map album art h264: generated PNG rejected: {}", e),
                            );
                            continue;
                        }
                        let bytes = captured.png.len();
                        let version =
                            global_album_art_store().set_png(RUST_H264_SOURCE, captured.png);
                        last_emit_at = Some(Instant::now());
                        debug!(
                            "map album art h264: captured decoded frame as PNG ({} bytes, version={}, frame={}x{}, crop=x{} y{} w{} h{}, output={}x{}, nals={}, au_idr={}, seen={} AUs, decoded={} frames, idrs={})",
                            bytes,
                            version,
                            captured.frame_width,
                            captured.frame_height,
                            captured.crop.x,
                            captured.crop.y,
                            captured.crop.w,
                            captured.crop.h,
                            captured.output_size,
                            captured.output_size,
                            captured.nal_count,
                            is_idr,
                            access_units_seen,
                            decoded_frames_seen,
                            idr_frames_seen
                        );
                    }
                    Err(e) => {
                        throttle_warn(
                            &mut last_warn_at,
                            &format!("map album art h264: failed to capture decoded frame: {}", e),
                        );
                    }
                }
            }
        }
    }
}

fn maybe_log_h264_status(
    last_status_log_at: &mut Option<Instant>,
    codec_config_received_at: Option<Instant>,
    last_au_at: Option<Instant>,
    last_idr_at: Option<Instant>,
    last_decoded_at: Option<Instant>,
    last_emit_at: Option<Instant>,
    synced_to_idr: bool,
    access_units_seen: u64,
    idr_frames_seen: u64,
    decoded_frames_seen: u64,
) {
    let Some(codec_config_received_at) = codec_config_received_at else {
        return;
    };

    let should_log = last_status_log_at
        .map(|instant| instant.elapsed() >= Duration::from_secs(5))
        .unwrap_or(true);
    if !should_log {
        return;
    }

    let stream_stalled = synced_to_idr
        && last_au_at
            .map(|instant| instant.elapsed() >= Duration::from_secs(3))
            .unwrap_or(false);

    if stream_stalled {
        info!(
            "map album art h264: status synced={} stalled={} AUs={} idrs={} decoded={} codec_config_age={} last_au={} last_idr={} last_decoded={} last_png={}",
            synced_to_idr,
            stream_stalled,
            access_units_seen,
            idr_frames_seen,
            decoded_frames_seen,
            elapsed_label(Some(codec_config_received_at)),
            elapsed_label(last_au_at),
            elapsed_label(last_idr_at),
            elapsed_label(last_decoded_at),
            elapsed_label(last_emit_at)
        );
    } else {
        debug!(
            "map album art h264: status synced={} stalled={} AUs={} idrs={} decoded={} codec_config_age={} last_au={} last_idr={} last_decoded={} last_png={}",
            synced_to_idr,
            stream_stalled,
            access_units_seen,
            idr_frames_seen,
            decoded_frames_seen,
            elapsed_label(Some(codec_config_received_at)),
            elapsed_label(last_au_at),
            elapsed_label(last_idr_at),
            elapsed_label(last_decoded_at),
            elapsed_label(last_emit_at)
        );
    }
    *last_status_log_at = Some(Instant::now());
}

fn elapsed_label(instant: Option<Instant>) -> String {
    match instant {
        Some(instant) => format!("{}ms", instant.elapsed().as_millis()),
        None => "never".to_string(),
    }
}

fn throttle_warn(last_warn_at: &mut Option<Instant>, message: &str) {
    let should_log = last_warn_at
        .map(|instant| instant.elapsed() >= Duration::from_secs(5))
        .unwrap_or(true);
    if should_log {
        warn!("{}", message);
        *last_warn_at = Some(Instant::now());
    }
}

pub(crate) fn feed_codec_config_to_decoder(
    decoder: &mut Decoder,
    codec_config: &[u8],
) -> Result<usize, String> {
    let nals = parse_annex_b(codec_config);
    let nal_count = nals.len();

    for nal in &nals {
        decoder
            .decode_nal(nal)
            .map_err(|e| format!("codec config decoder error: {}", e))?;
    }
    Ok(nal_count)
}

pub(crate) fn feed_access_unit_to_decoder(
    decoder: &mut Decoder,
    data: &[u8],
) -> Result<(Option<Frame>, usize), String> {
    let nals = parse_annex_b(data);
    if nals.is_empty() {
        return Err("access unit contained no Annex-B NAL units".to_string());
    }
    let nal_count = nals.len();
    let mut decoded: Option<Frame> = None;

    for nal in &nals {
        match decoder.decode_nal(nal) {
            Ok(Some(frame)) => decoded = Some(frame),
            Ok(None) => {}
            Err(e) => return Err(format!("decoder error: {}", e)),
        }
    }

    Ok((decoded, nal_count))
}

fn capture_frame_to_png(
    frame: &Frame,
    nal_count: usize,
    options: &H264ArtOptions,
) -> Result<CapturedPng, String> {
    let (png, crop, output_size) = frame_to_png(frame, options)?;
    Ok(CapturedPng {
        png,
        frame_width: frame.width as usize,
        frame_height: frame.height as usize,
        crop,
        output_size,
        nal_count,
    })
}

fn frame_to_png(
    frame: &Frame,
    options: &H264ArtOptions,
) -> Result<(Vec<u8>, CropRect, u32), String> {
    let width = frame.width as usize;
    let height = frame.height as usize;
    if width == 0 || height == 0 {
        return Err("decoded frame has empty dimensions".to_string());
    }
    if frame.y.len() < width.saturating_mul(height) {
        return Err("decoded frame Y plane is shorter than expected".to_string());
    }

    let crop = compute_crop(width, height, options);
    let output_size = options.output_size_px as usize;
    let mut rgb = vec![0u8; output_size * output_size * 3];

    for oy in 0..output_size {
        let sy = crop.y + (oy * crop.h / output_size);
        for ox in 0..output_size {
            let sx = crop.x + (ox * crop.w / output_size);
            let (r, g, b) = yuv420_pixel_to_rgb(frame, width, height, sx, sy);
            let idx = (oy * output_size + ox) * 3;
            rgb[idx] = r;
            rgb[idx + 1] = g;
            rgb[idx + 2] = b;
        }
    }

    let png = encode_rgb_png(output_size as u32, output_size as u32, &rgb)?;
    Ok((png, crop, output_size as u32))
}

#[derive(Clone, Copy, Debug)]
struct CropRect {
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

fn compute_crop(width: usize, height: usize, options: &H264ArtOptions) -> CropRect {
    if !options.crop_enabled {
        return full_frame_crop(width, height);
    }

    match options.crop_mode {
        CropMode::Percent => compute_percent_crop(width, height, options),
        CropMode::Pixel => compute_pixel_crop(width, height, options),
    }
}

fn full_frame_crop(width: usize, height: usize) -> CropRect {
    CropRect {
        x: 0,
        y: 0,
        w: width.max(1),
        h: height.max(1),
    }
}

fn compute_percent_crop(width: usize, height: usize, options: &H264ArtOptions) -> CropRect {
    let crop_x_percent = options.crop_x.min(100) as usize;
    let crop_y_percent = options.crop_y.min(100) as usize;
    let crop_w_percent = options.crop_w.min(100);
    let crop_h_percent = options.crop_h.min(100);

    let crop_w = percent_size(width, crop_w_percent)
        .unwrap_or(width)
        .min(width)
        .max(1);
    let crop_h = percent_size(height, crop_h_percent)
        .unwrap_or(height)
        .min(height)
        .max(1);

    let max_x = width.saturating_sub(crop_w);
    let max_y = height.saturating_sub(crop_h);
    let x = (width.saturating_mul(crop_x_percent) / 100).min(max_x);
    let y = (height.saturating_mul(crop_y_percent) / 100).min(max_y);

    CropRect {
        x,
        y,
        w: crop_w,
        h: crop_h,
    }
}

fn compute_pixel_crop(width: usize, height: usize, options: &H264ArtOptions) -> CropRect {
    if width == 0 || height == 0 {
        return full_frame_crop(width, height);
    }

    let x = (options.crop_x as usize).min(width.saturating_sub(1));
    let y = (options.crop_y as usize).min(height.saturating_sub(1));
    let max_w = width.saturating_sub(x).max(1);
    let max_h = height.saturating_sub(y).max(1);

    let crop_w = if options.crop_w == 0 {
        max_w
    } else {
        (options.crop_w as usize).min(max_w).max(1)
    };
    let crop_h = if options.crop_h == 0 {
        max_h
    } else {
        (options.crop_h as usize).min(max_h).max(1)
    };

    CropRect {
        x,
        y,
        w: crop_w,
        h: crop_h,
    }
}

fn percent_size(total: usize, percent: u32) -> Option<usize> {
    if percent == 0 {
        None
    } else {
        Some((total.saturating_mul(percent as usize) / 100).max(1))
    }
}

pub(crate) fn yuv420_pixel_to_rgb(
    frame: &Frame,
    width: usize,
    height: usize,
    x: usize,
    y: usize,
) -> (u8, u8, u8) {
    let sx = x.min(width.saturating_sub(1));
    let sy = y.min(height.saturating_sub(1));
    let y_value = frame.y[sy * width + sx] as i32;

    let chroma_w = (width / 2).max(1);
    let chroma_h = (height / 2).max(1);
    let chroma_x = (sx / 2).min(chroma_w.saturating_sub(1));
    let chroma_y = (sy / 2).min(chroma_h.saturating_sub(1));
    let chroma_idx = chroma_y * chroma_w + chroma_x;

    let u_value = frame.u.get(chroma_idx).copied().unwrap_or(128) as i32;
    let v_value = frame.v.get(chroma_idx).copied().unwrap_or(128) as i32;

    // BT.601 limited-range YUV -> RGB, good enough for map preview artwork.
    let c = y_value - 16;
    let d = u_value - 128;
    let e = v_value - 128;

    let r = (298 * c + 409 * e + 128) >> 8;
    let g = (298 * c - 100 * d - 208 * e + 128) >> 8;
    let b = (298 * c + 516 * d + 128) >> 8;

    (clamp_u8(r), clamp_u8(g), clamp_u8(b))
}

fn clamp_u8(value: i32) -> u8 {
    value.clamp(0, 255) as u8
}

pub(crate) fn encode_rgb_png(width: u32, height: u32, rgb: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|e| format!("png write_header failed: {}", e))?;
        writer
            .write_image_data(rgb)
            .map_err(|e| format!("png write_image_data failed: {}", e))?;
    }
    Ok(out)
}

fn clamp_output_size(value: u32) -> u32 {
    let value = if value == 0 {
        DEFAULT_OUTPUT_SIZE
    } else {
        value
    };
    value.clamp(MIN_OUTPUT_SIZE, MAX_OUTPUT_SIZE)
}

fn contains_idr_nal(data: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            let start_code_len = if data.get(i + 2) == Some(&1) {
                3
            } else if data.get(i + 2) == Some(&0) && data.get(i + 3) == Some(&1) {
                4
            } else {
                i += 1;
                continue;
            };

            let nal_start = i + start_code_len;
            if let Some(&header) = data.get(nal_start) {
                if header & 0x1F == 5 {
                    return true;
                }
            }
            i = nal_start.saturating_add(1);
        } else {
            i += 1;
        }
    }
    false
}
