use crate::map_album_art_h264::{
    encode_rgb_png, feed_codec_config_to_decoder, yuv420_pixel_to_rgb,
};
use crate::media_tap::MediaSink;
use log::info;
use rust_h264::decoder::{Decoder, Frame};
use rust_h264::nal::parse_annex_b;
use std::time::{Duration, Instant};

/// Result of [`render_last_idr_burst_png`]: the rendered PNG plus how long
/// ago the burst's IDR was cached, so the caller can show an honest "this
/// frame is N seconds old" indicator instead of presenting it as live.
pub struct RenderedPreview {
    pub png: Vec<u8>,
    pub age: Duration,
    /// (first unit's pts_us, unit count) of the burst that was actually
    /// decoded -- lets the caller build an ETag that's guaranteed to match
    /// what's in `png`, even if the live burst grew further while this
    /// decode was running.
    pub burst_version: (u64, usize),
}

/// Decodes the given sink's current IDR burst (the cached IDR plus the short
/// contiguous run of access units captured right after it -- see
/// `MediaSink::get_idr_burst`) into a full-frame PNG (no crop, unlike the
/// square album-art thumbnail), scaled down to fit within `max_dimension` on
/// its longest side.
///
/// We deliberately decode the *whole* burst, not just the IDR: P-frames only
/// decode correctly as an unbroken chain from their reference frame, so this
/// gives a temporally coherent picture from up to ~2s past the keyframe,
/// without the gap-induced corruption that splicing in arbitrary later live
/// frames would cause. It's still a still frame refreshed on demand, not a
/// live feed, and its age (relative to the burst's IDR) is returned alongside
/// so the UI can be honest about how current it actually is.
///
/// The actual decode + pixel conversion is pure synchronous CPU work with no
/// `.await` points -- feeding a multi-second burst (hundreds of NAL units)
/// through it can take long enough to stall the tokio scheduler if run
/// directly on an async worker thread (observed as multi-second
/// scheduler-probe tick gaps, i.e. the whole proxy stalling while a preview
/// was requested). Runs on the blocking thread pool via spawn_blocking so it
/// can't starve the runtime regardless of how long it takes.
pub async fn render_last_idr_burst_png(
    sink: &MediaSink,
    channel: u8,
    max_dimension: u32,
) -> Result<RenderedPreview, String> {
    let codec_cfg = sink
        .get_codec_cfg()
        .await
        .ok_or_else(|| format!("ch {channel:#04x}: no codec config cached yet for this channel"))?;
    let (cached_at, units) = sink
        .get_idr_burst()
        .await
        .ok_or_else(|| format!("ch {channel:#04x}: no IDR frame cached yet for this channel"))?;
    if units.is_empty() {
        return Err(format!("ch {channel:#04x}: cached IDR burst was empty"));
    }
    let first_pts = units[0].0;
    let unit_count = units.len();
    let pts_span_us = units
        .last()
        .map(|(pts, _)| pts.saturating_sub(first_pts))
        .unwrap_or(0);
    info!(
        "sdr_ui_preview: ch {:#04x}: decode starting, burst has {} unit(s), pts span {:?}, IDR age {:?}",
        channel,
        unit_count,
        Duration::from_micros(pts_span_us),
        cached_at.elapsed()
    );

    let decode_started_at = Instant::now();
    let png =
        tokio::task::spawn_blocking(move || decode_burst_to_png(&codec_cfg, &units, max_dimension))
            .await
            .map_err(|e| format!("ch {channel:#04x}: preview decode task panicked: {e}"))??;
    info!(
        "sdr_ui_preview: ch {:#04x}: decode finished, {} unit(s) in {:?}",
        channel,
        unit_count,
        decode_started_at.elapsed()
    );

    Ok(RenderedPreview {
        png,
        age: cached_at.elapsed(),
        burst_version: (first_pts, unit_count),
    })
}

fn decode_burst_to_png(
    codec_cfg: &[u8],
    units: &[(u64, Vec<u8>)],
    max_dimension: u32,
) -> Result<Vec<u8>, String> {
    let mut decoder = Decoder::new();
    feed_codec_config_to_decoder(&mut decoder, codec_cfg)?;

    let mut frame = None;
    for (_, au) in units {
        let nals = parse_annex_b(au);
        for nal in &nals {
            match decoder.decode_nal(nal) {
                Ok(Some(f)) => frame = Some(f),
                Ok(None) => {}
                Err(e) => return Err(format!("decoder error: {}", e)),
            }
        }
    }
    // Whatever picture the last access unit started is still buffered as
    // "pending" -- flush() finalizes it since there's no following picture
    // in this burst to do so.
    if let Some(flushed) = decoder.flush() {
        frame = Some(flushed);
    }

    let frame = frame.ok_or_else(|| "cached IDR burst did not decode to a frame".to_string())?;
    frame_to_full_png(&frame, max_dimension)
}

fn frame_to_full_png(frame: &Frame, max_dimension: u32) -> Result<Vec<u8>, String> {
    let width = frame.width as usize;
    let height = frame.height as usize;
    if width == 0 || height == 0 {
        return Err("decoded frame has empty dimensions".to_string());
    }

    let longest = width.max(height) as f64;
    let scale = (max_dimension as f64 / longest).min(1.0);
    let out_w = ((width as f64 * scale).round() as usize).max(1);
    let out_h = ((height as f64 * scale).round() as usize).max(1);

    let mut rgb = vec![0u8; out_w * out_h * 3];
    for oy in 0..out_h {
        let sy = (oy * height / out_h).min(height - 1);
        for ox in 0..out_w {
            let sx = (ox * width / out_w).min(width - 1);
            let (r, g, b) = yuv420_pixel_to_rgb(frame, width, height, sx, sy);
            let idx = (oy * out_w + ox) * 3;
            rgb[idx] = r;
            rgb[idx + 1] = g;
            rgb[idx + 2] = b;
        }
    }

    encode_rgb_png(out_w as u32, out_h as u32, &rgb)
}
