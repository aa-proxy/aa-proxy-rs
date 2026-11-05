//! Hardware H.264 decoder/encoder for the Sophgo SG2000/SG2002 (Milk-V Duo S), used by the
//! video overlay (`overlay_hw_accel = "cvi"` or `"auto"`).
//!
//! The codec is **not** a V4L2 device: it is reached through the vendor `cvi_mpi` libraries
//! (`libsys`, `libvenc`, `libvdec`), which talk to `/dev/cvi_vc_enc<N>` / `/dev/cvi_vc_dec<N>`.
//! The calls are made by a thin C layer (`src/cvi/aap_cvi.c`, built by `build.rs` only with the
//! `cvi` cargo feature) so the Rust side does not have to mirror the big vendor structs.
//!
//! Without the `cvi` feature this module still compiles: [`probe`] returns `false` and the
//! constructors return [`std::io::ErrorKind::Unsupported`], so `overlay.rs` needs no `cfg`s.
//!
//! The public API mirrors [`crate::v4l2_m2m`] (`decode`, `encode`, `request_keyframe`,
//! `header_bytes`): `decode()` takes one H.264 access unit and returns at most one raw I420
//! frame, `encode()` takes one raw frame and returns one Annex-B access unit.
//!
//! Target requirements are described in the `milkv-duos-hwcodec-test` README (kernel modules
//! `cvi_vc_driver` & co, VPU firmware in `/usr/share/fw_vcodec`, `libsys`/`libvenc`/`libvdec`,
//! `libatomic`, BusyBox `devmem`). Tunables (environment variables, all optional):
//!
//! | variable                       | default | meaning                                          |
//! |--------------------------------|---------|--------------------------------------------------|
//! | `AA_PROXY_CVI_MAX_W`/`_MAX_H`  | 1920x1088 | largest picture the shared VB pool must hold   |
//! | `AA_PROXY_CVI_VB_BLOCKS`       | 12      | number of blocks in the shared VB pool           |
//! | `AA_PROXY_CVI_RC`              | fixed QP | `cbr` selects constant bitrate instead          |
//! | `AA_PROXY_CVI_QP`              | `h264_encoder_qp` (26 if 0) | fixed QP, clamped to 10..45  |
//! | `AA_PROXY_CVI_BITRATE_KBPS`    | 4000    | CBR bitrate (only with `AA_PROXY_CVI_RC=cbr`)    |
//! | `AA_PROXY_CVI_DISPLAY_FRAMES`  | 0       | decoder display queue (0..16), lower = less lag  |
//! | `AA_PROXY_CVI_PROFILE`         | 0       | encoder H.264 profile: 0 baseline, 1 main, 2 high |

use crate::v4l2_m2m::{extract_sps_pps_annex_b, split_annex_b_nals};
use log::{debug, info, warn};
use rusty_h264::YuvFrame;
use std::ffi::{c_char, c_int, c_uint, CStr};
use std::io;
use std::path::Path;

const ENC_DEVICE: &str = "/dev/cvi_vc_enc0";
const DEC_DEVICE: &str = "/dev/cvi_vc_dec0";

const DEFAULT_MAX_W: u32 = 1920;
const DEFAULT_MAX_H: u32 = 1088;
const DEFAULT_VB_BLOCKS: u32 = 12;
const DEFAULT_BITRATE_KBPS: u32 = 4000;
const DEFAULT_DISPLAY_FRAMES: u32 = 0;
const DEFAULT_PROFILE: u32 = 0; // baseline: what strict car head units expect
const ENC_FPS: u32 = 30;

/// Wait for the encoder in steady state (the V4L2 encoder uses 45 ms).
const ENC_TIMEOUT_MS: c_int = 150;
/// The very first frame of a channel can take much longer.
const ENC_WARMUP_TIMEOUT_MS: c_int = 1000;
const DEC_SEND_TIMEOUT_MS: c_int = 100;
/// Every access unit the proxy swallows is one the car never ACKs, and the phone only has a
/// handful of un-ACKed frames in flight (the first IDR alone can stall the whole session), so
/// the decoder is waited for generously: the first picture of a channel needs the VPU to boot.
const DEC_GET_FIRST_TIMEOUT_MS: c_int = 1000;
const DEC_GET_TIMEOUT_MS: c_int = 150;
/// The first few frames of each codec are logged at info level to diagnose bring-up problems.
const TRACE_FRAMES: u64 = 8;

const AAP_OK: c_int = 0;
const AAP_AGAIN: c_int = 1;
const AAP_TIMEOUT: c_int = -2;

// ============================================================================
// FFI
// ============================================================================

#[repr(C)]
pub struct AapEnc {
    _private: [u8; 0],
}

#[repr(C)]
pub struct AapDec {
    _private: [u8; 0],
}

#[cfg(feature = "cvi")]
mod ffi {
    use super::{AapDec, AapEnc};
    use std::ffi::{c_char, c_int, c_uint};

    extern "C" {
        pub fn aap_cvi_last_error() -> *const c_char;
        pub fn aap_cvi_sys_init(max_w: c_uint, max_h: c_uint, blk_cnt: c_uint) -> c_int;

        pub fn aap_cvi_enc_open(
            out: *mut *mut AapEnc,
            w: c_uint,
            h: c_uint,
            gop: c_uint,
            bitrate_kbps: c_uint,
            fps: c_uint,
            profile: c_uint,
            fixed_qp: c_uint,
        ) -> c_int;
        pub fn aap_cvi_enc_close(e: *mut AapEnc);
        pub fn aap_cvi_enc_request_idr(e: *mut AapEnc) -> c_int;
        pub fn aap_cvi_enc_encode(
            e: *mut AapEnc,
            y: *const u8,
            u: *const u8,
            v: *const u8,
            timeout_ms: c_int,
            out: *mut *const u8,
            out_len: *mut usize,
        ) -> c_int;

        pub fn aap_cvi_dec_open(
            out: *mut *mut AapDec,
            w: c_uint,
            h: c_uint,
            display_frames: c_uint,
        ) -> c_int;
        pub fn aap_cvi_dec_close(d: *mut AapDec);
        pub fn aap_cvi_dec_send(
            d: *mut AapDec,
            au: *const u8,
            len: usize,
            pts: u64,
            timeout_ms: c_int,
        ) -> c_int;
        pub fn aap_cvi_dec_get(
            d: *mut AapDec,
            timeout_ms: c_int,
            w: *mut c_uint,
            h: *mut c_uint,
        ) -> c_int;
        pub fn aap_cvi_dec_take(d: *mut AapDec, y: *mut u8, u: *mut u8, v: *mut u8) -> c_int;
        pub fn aap_cvi_dec_drop(d: *mut AapDec);
    }
}

/// Stand-ins used when the crate is built without the `cvi` feature: everything that could
/// create a codec fails, so no other function can ever be reached with a live handle.
#[cfg(not(feature = "cvi"))]
#[allow(clippy::missing_safety_doc)]
mod ffi {
    use super::{AapDec, AapEnc};
    use std::ffi::{c_char, c_int, c_uint};
    use std::ptr;

    pub unsafe fn aap_cvi_last_error() -> *const c_char {
        c"built without the `cvi` cargo feature".as_ptr()
    }
    pub unsafe fn aap_cvi_sys_init(_: c_uint, _: c_uint, _: c_uint) -> c_int {
        -1
    }
    pub unsafe fn aap_cvi_enc_open(
        out: *mut *mut AapEnc,
        _: c_uint,
        _: c_uint,
        _: c_uint,
        _: c_uint,
        _: c_uint,
        _: c_uint,
        _: c_uint,
    ) -> c_int {
        *out = ptr::null_mut();
        -1
    }
    pub unsafe fn aap_cvi_enc_close(_: *mut AapEnc) {}
    pub unsafe fn aap_cvi_enc_request_idr(_: *mut AapEnc) -> c_int {
        -1
    }
    pub unsafe fn aap_cvi_enc_encode(
        _: *mut AapEnc,
        _: *const u8,
        _: *const u8,
        _: *const u8,
        _: c_int,
        _: *mut *const u8,
        _: *mut usize,
    ) -> c_int {
        -1
    }
    pub unsafe fn aap_cvi_dec_open(
        out: *mut *mut AapDec,
        _: c_uint,
        _: c_uint,
        _: c_uint,
    ) -> c_int {
        *out = ptr::null_mut();
        -1
    }
    pub unsafe fn aap_cvi_dec_close(_: *mut AapDec) {}
    pub unsafe fn aap_cvi_dec_send(
        _: *mut AapDec,
        _: *const u8,
        _: usize,
        _: u64,
        _: c_int,
    ) -> c_int {
        -1
    }
    pub unsafe fn aap_cvi_dec_get(
        _: *mut AapDec,
        _: c_int,
        _: *mut c_uint,
        _: *mut c_uint,
    ) -> c_int {
        -1
    }
    pub unsafe fn aap_cvi_dec_take(_: *mut AapDec, _: *mut u8, _: *mut u8, _: *mut u8) -> c_int {
        -1
    }
    pub unsafe fn aap_cvi_dec_drop(_: *mut AapDec) {}
}

fn last_error() -> String {
    // SAFETY: returns a NUL-terminated thread-local buffer (or a static string).
    unsafe {
        let p: *const c_char = ffi::aap_cvi_last_error();
        if p.is_null() {
            "unknown CVI error".to_string()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

fn other_err(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{what}: {}", last_error()))
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

// ============================================================================
// Availability / SYS init
// ============================================================================

/// Returns true when the kernel exposes the CVI video codec device nodes
/// (`/dev/cvi_vc_enc0` and `/dev/cvi_vc_dec0`) and the crate was built with the `cvi` feature.
pub fn probe() -> bool {
    cfg!(feature = "cvi") && Path::new(ENC_DEVICE).exists() && Path::new(DEC_DEVICE).exists()
}

/// Initialises SYS/VB (once per process; later calls are no-ops in the C layer).
fn sys_init() -> io::Result<()> {
    let w = env_u32("AA_PROXY_CVI_MAX_W", DEFAULT_MAX_W);
    let h = env_u32("AA_PROXY_CVI_MAX_H", DEFAULT_MAX_H);
    let blocks = env_u32("AA_PROXY_CVI_VB_BLOCKS", DEFAULT_VB_BLOCKS);
    // SAFETY: plain call, no pointers.
    let r = unsafe { ffi::aap_cvi_sys_init(w as c_uint, h as c_uint, blocks as c_uint) };
    if r != AAP_OK {
        return Err(other_err("CVI SYS/VB init"));
    }
    Ok(())
}

// ============================================================================
// H.264 access unit helpers (pure, unit tested)
// ============================================================================

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
struct AuInfo {
    has_sps: bool,
    has_idr: bool,
    /// Contains a coded slice (nal_unit_type 1 or 5), i.e. it is not just SPS/PPS/SEI.
    has_slice: bool,
}

fn analyze_au(au: &[u8]) -> AuInfo {
    let mut info = AuInfo::default();
    for nal in split_annex_b_nals(au) {
        match nal.first().map(|b| b & 0x1F) {
            Some(7) => info.has_sps = true,
            Some(5) => {
                info.has_idr = true;
                info.has_slice = true;
            }
            Some(1) => info.has_slice = true,
            _ => {}
        }
    }
    info
}

/// Rounds a picture dimension up to the macroblock grid.
fn align16(v: usize) -> usize {
    (v + 15) & !15
}

/// Parses the picture size announced by the first SPS in `annex_b`, as the channel size
/// (macroblock aligned, because the decoder channel must hold the *coded* picture).
fn channel_dims(annex_b: &[u8]) -> Option<(usize, usize)> {
    let (w, h) = crate::overlay::parse_sps_dimensions_annex_b(annex_b)?;
    Some((align16(w), align16(h)))
}

// ============================================================================
// Decoder
// ============================================================================

pub struct CviDecoder {
    dec: *mut AapDec,
    /// Maximum picture size the current channel was created with.
    chn_dims: Option<(usize, usize)>,
    /// Last SPS/PPS seen (Annex-B). Re-sent in front of IDR frames that lack it.
    config: Vec<u8>,
    pts: u64,
    display_frames: u32,
    /// Access units sent / pictures returned since the channel was created.
    sent: u64,
    got: u64,
}

// SAFETY: the handle is only ever used through `&mut self`; the vendor library keeps
// per-channel state and is safe to use from whichever thread owns the decoder.
unsafe impl Send for CviDecoder {}

impl CviDecoder {
    /// Prepares the hardware decoder. The decoder channel itself is created lazily from the
    /// first SPS, because it needs the picture size.
    pub fn new() -> io::Result<Self> {
        if !cfg!(feature = "cvi") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "built without the `cvi` cargo feature",
            ));
        }
        if !Path::new(DEC_DEVICE).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{DEC_DEVICE} not found (cvi_vc_driver not loaded?)"),
            ));
        }
        sys_init()?;
        Ok(Self {
            dec: std::ptr::null_mut(),
            chn_dims: None,
            config: Vec::new(),
            pts: 0,
            sent: 0,
            got: 0,
            display_frames: env_u32("AA_PROXY_CVI_DISPLAY_FRAMES", DEFAULT_DISPLAY_FRAMES).min(16),
        })
    }

    fn close_channel(&mut self) {
        if !self.dec.is_null() {
            // SAFETY: `dec` came from aap_cvi_dec_open and is closed exactly once.
            unsafe { ffi::aap_cvi_dec_close(self.dec) };
            self.dec = std::ptr::null_mut();
        }
        self.chn_dims = None;
    }

    fn ensure_channel(&mut self, dims: (usize, usize)) -> io::Result<()> {
        if !self.dec.is_null() && self.chn_dims == Some(dims) {
            return Ok(());
        }
        self.close_channel();
        let mut dec: *mut AapDec = std::ptr::null_mut();
        // SAFETY: `dec` is a valid out-pointer.
        let r = unsafe {
            ffi::aap_cvi_dec_open(
                &mut dec,
                dims.0 as c_uint,
                dims.1 as c_uint,
                self.display_frames as c_uint,
            )
        };
        if r != AAP_OK || dec.is_null() {
            return Err(other_err("CVI decoder open"));
        }
        info!(
            "cvi: hardware H.264 decoder channel ready ({}x{}, display queue {})",
            dims.0, dims.1, self.display_frames
        );
        self.dec = dec;
        self.chn_dims = Some(dims);
        self.sent = 0;
        self.got = 0;
        Ok(())
    }

    /// Decodes one access unit. Returns `Ok(None)` when no picture is ready (the decoder is
    /// pipelined, or the unit only carried SPS/PPS).
    pub fn decode(&mut self, au: &[u8]) -> io::Result<Option<YuvFrame>> {
        let info = analyze_au(au);

        if info.has_sps {
            let cfg = extract_sps_pps_annex_b(au);
            if !cfg.is_empty() {
                self.config = cfg;
            }
            // New picture size: the channel has to be recreated.
            if let Some(dims) = channel_dims(&self.config) {
                if self.chn_dims.is_some() && self.chn_dims != Some(dims) {
                    debug!(
                        "cvi: SPS announces {:?}, recreating the decoder channel",
                        dims
                    );
                    self.close_channel();
                }
            }
        }
        if !info.has_slice {
            // SPS/PPS only: remembered above, sent in front of the next IDR.
            return Ok(None);
        }

        let dims = match self.chn_dims {
            Some(d) => d,
            None => channel_dims(&self.config).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no SPS seen before the first slice",
                )
            })?,
        };
        self.ensure_channel(dims)?;

        // Phone IDRs may arrive without in-band SPS/PPS (they travel in CODEC_CONFIG).
        let joined;
        let input: &[u8] = if info.has_idr && !info.has_sps && !self.config.is_empty() {
            let mut v = Vec::with_capacity(self.config.len() + au.len());
            v.extend_from_slice(&self.config);
            v.extend_from_slice(au);
            joined = v;
            &joined
        } else {
            au
        };

        self.pts = self.pts.wrapping_add(1);
        // SAFETY: `input` is valid for `len` bytes for the duration of the call.
        let r = unsafe {
            ffi::aap_cvi_dec_send(
                self.dec,
                input.as_ptr(),
                input.len(),
                self.pts,
                DEC_SEND_TIMEOUT_MS,
            )
        };
        if r != AAP_OK {
            return Err(other_err("CVI decoder send"));
        }
        self.sent += 1;

        let t0 = std::time::Instant::now();
        let res = self.fetch_frame()?;
        if res.is_some() {
            self.got += 1;
        }
        if self.sent <= TRACE_FRAMES || (res.is_none() && self.sent > self.got) {
            let lvl = if res.is_none() && self.sent > TRACE_FRAMES {
                log::Level::Warn
            } else {
                log::Level::Info
            };
            log::log!(
                lvl,
                "cvi: dec AU #{} {} B idr={} sps={} -> {} in {} ms (sent={} got={})",
                self.sent,
                input.len(),
                info.has_idr,
                info.has_sps,
                if res.is_some() {
                    "picture"
                } else {
                    "NO picture"
                },
                t0.elapsed().as_millis(),
                self.sent,
                self.got
            );
        }
        Ok(res)
    }

    /// Fetches the newest decoded picture, dropping stale ones so latency stays bounded.
    fn fetch_frame(&mut self) -> io::Result<Option<YuvFrame>> {
        let (mut w, mut h): (c_uint, c_uint) = (0, 0);
        // SAFETY: valid out-pointers; the frame is held inside the decoder until take/drop/next get.
        let timeout = if self.got == 0 {
            DEC_GET_FIRST_TIMEOUT_MS
        } else {
            DEC_GET_TIMEOUT_MS
        };
        let r = unsafe { ffi::aap_cvi_dec_get(self.dec, timeout, &mut w, &mut h) };
        if r == AAP_AGAIN {
            return Ok(None);
        }
        if r != AAP_OK {
            return Err(other_err("CVI decoder get"));
        }
        // More frames ready already? Keep only the newest (`get` releases the previous one).
        loop {
            let (mut w2, mut h2): (c_uint, c_uint) = (0, 0);
            // SAFETY: as above.
            let r2 = unsafe { ffi::aap_cvi_dec_get(self.dec, 0, &mut w2, &mut h2) };
            if r2 != AAP_OK {
                if r2 != AAP_AGAIN {
                    return Err(other_err("CVI decoder get"));
                }
                // Nothing newer: the frame fetched above is still held by the decoder.
                break;
            }
            w = w2;
            h = h2;
        }

        let (w, h) = (w as usize, h as usize);
        if w == 0 || h == 0 || w % 2 != 0 || h % 2 != 0 {
            // SAFETY: drops the frame held by the decoder.
            unsafe { ffi::aap_cvi_dec_drop(self.dec) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported decoded picture size {w}x{h}"),
            ));
        }
        let mut frame = YuvFrame {
            width: w,
            height: h,
            y: vec![0; w * h],
            u: vec![0; (w / 2) * (h / 2)],
            v: vec![0; (w / 2) * (h / 2)],
        };
        // SAFETY: the planes have exactly the sizes the C layer writes (w*h and (w/2)*(h/2)).
        let r = unsafe {
            ffi::aap_cvi_dec_take(
                self.dec,
                frame.y.as_mut_ptr(),
                frame.u.as_mut_ptr(),
                frame.v.as_mut_ptr(),
            )
        };
        if r != AAP_OK {
            return Err(other_err("CVI decoder take"));
        }
        Ok(Some(frame))
    }

    /// Size of the most recently created decoder channel (macroblock aligned).
    pub fn dimensions(&self) -> Option<(usize, usize)> {
        self.chn_dims
    }
}

impl Drop for CviDecoder {
    fn drop(&mut self) {
        self.close_channel();
    }
}

// ============================================================================
// Encoder
// ============================================================================

pub struct CviEncoder {
    enc: *mut AapEnc,
    width: usize,
    height: usize,
    header_bytes: Vec<u8>,
    frames: u64,
}

// SAFETY: see CviDecoder.
unsafe impl Send for CviEncoder {}

impl CviEncoder {
    /// Creates a baseline hardware encoder for `width`x`height` and a GOP of `gop` frames.
    /// Rate control is fixed QP by default (`qp`, overridable with `AA_PROXY_CVI_QP`); with
    /// `AA_PROXY_CVI_RC=cbr` it is constant bitrate and `qp` is ignored.
    pub fn new(width: usize, height: usize, qp: u8, gop: u32) -> io::Result<Self> {
        if !cfg!(feature = "cvi") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "built without the `cvi` cargo feature",
            ));
        }
        if width == 0 || height == 0 || width % 2 != 0 || height % 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported encoder size {width}x{height}"),
            ));
        }
        if !Path::new(ENC_DEVICE).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{ENC_DEVICE} not found (cvi_vc_driver not loaded?)"),
            ));
        }
        sys_init()?;

        let bitrate = env_u32("AA_PROXY_CVI_BITRATE_KBPS", DEFAULT_BITRATE_KBPS);
        let profile = env_u32("AA_PROXY_CVI_PROFILE", DEFAULT_PROFILE);
        // Fixed QP (constant quality) by default: UI content is mostly static and CBR left the
        // picture visibly smeared. `AA_PROXY_CVI_RC=cbr` restores constant bitrate.
        let fixed_qp =
            if std::env::var("AA_PROXY_CVI_RC").is_ok_and(|v| v.eq_ignore_ascii_case("cbr")) {
                0
            } else {
                let q = env_u32("AA_PROXY_CVI_QP", if qp == 0 { 26 } else { qp as u32 });
                q.clamp(10, 45)
            };
        let mut enc: *mut AapEnc = std::ptr::null_mut();
        // SAFETY: `enc` is a valid out-pointer.
        let r = unsafe {
            ffi::aap_cvi_enc_open(
                &mut enc,
                width as c_uint,
                height as c_uint,
                gop.max(1) as c_uint,
                bitrate as c_uint,
                ENC_FPS as c_uint,
                profile as c_uint,
                fixed_qp as c_uint,
            )
        };
        if r != AAP_OK || enc.is_null() {
            return Err(other_err("CVI encoder open"));
        }
        let mut encoder = Self {
            enc,
            width,
            height,
            header_bytes: Vec::new(),
            frames: 0,
        };

        // Warm up with a black frame to learn the genuine SPS/PPS (same approach as the V4L2
        // encoder), then force the first live frame to be an IDR.
        let blank = YuvFrame {
            width,
            height,
            y: vec![16; width * height],
            u: vec![128; (width / 2) * (height / 2)],
            v: vec![128; (width / 2) * (height / 2)],
        };
        match encoder.encode_with_timeout(&blank, ENC_WARMUP_TIMEOUT_MS) {
            Ok(first_au) => {
                let hdr = extract_sps_pps_annex_b(&first_au);
                if hdr.is_empty() {
                    warn!("cvi: warm-up access unit carried no SPS/PPS");
                } else {
                    info!(
                        "cvi: extracted {} bytes SPS+PPS from the hardware encoder: {:02X?}",
                        hdr.len(),
                        hdr
                    );
                    let patched = crate::overlay::patch_hw_annex_b_for_car_hu(&hdr);
                    info!("cvi: SPS+PPS sent to the car: {:02X?}", patched);
                    encoder.header_bytes = patched;
                }
            }
            Err(e) => warn!("cvi: encoder warm-up frame failed: {e}"),
        }
        encoder.request_keyframe();

        info!(
            "cvi: hardware H.264 encoder ready ({}x{}, GOP={}, {}, profile {})",
            width,
            height,
            gop,
            if fixed_qp == 0 {
                format!("{bitrate} kbit/s CBR")
            } else {
                format!("fixed QP {fixed_qp}")
            },
            profile
        );
        Ok(encoder)
    }

    /// Requests an IDR for the next encoded frame.
    pub fn request_keyframe(&mut self) {
        // SAFETY: `enc` is a live handle.
        let r = unsafe { ffi::aap_cvi_enc_request_idr(self.enc) };
        if r != AAP_OK {
            debug!("cvi: IDR request failed: {}", last_error());
        }
    }

    /// Encodes a raw frame into one Annex-B access unit.
    pub fn encode(&mut self, frame: &YuvFrame) -> io::Result<Vec<u8>> {
        let t0 = std::time::Instant::now();
        let res = self.encode_with_timeout(frame, ENC_TIMEOUT_MS);
        self.frames += 1;
        if self.frames <= TRACE_FRAMES {
            match &res {
                Ok(au) => {
                    let i = analyze_au(au);
                    info!(
                        "cvi: enc frame #{} -> {} B idr={} sps={} in {} ms",
                        self.frames,
                        au.len(),
                        i.has_idr,
                        i.has_sps,
                        t0.elapsed().as_millis()
                    );
                }
                Err(e) => info!("cvi: enc frame #{} -> {e}", self.frames),
            }
        }
        let mut au = res?;
        if analyze_au(&au).has_sps {
            au = crate::overlay::patch_hw_annex_b_for_car_hu(&au);
        }
        // Make every IDR self-contained even if the encoder only emits SPS/PPS once.
        if !self.header_bytes.is_empty() {
            let info = analyze_au(&au);
            if info.has_idr && !info.has_sps {
                let mut v = Vec::with_capacity(self.header_bytes.len() + au.len());
                v.extend_from_slice(&self.header_bytes);
                v.extend_from_slice(&au);
                au = v;
            }
        }
        Ok(au)
    }

    fn encode_with_timeout(&mut self, frame: &YuvFrame, timeout_ms: c_int) -> io::Result<Vec<u8>> {
        let (w, h) = (self.width, self.height);
        // Validate so the C layer can never read out of bounds.
        if frame.width != w
            || frame.height != h
            || frame.y.len() < w * h
            || frame.u.len() < (w / 2) * (h / 2)
            || frame.v.len() < (w / 2) * (h / 2)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame does not match CVI encoder dimensions",
            ));
        }
        let mut out: *const u8 = std::ptr::null();
        let mut out_len: usize = 0;
        // SAFETY: planes are valid for the sizes checked above; `out` points into encoder-owned
        // memory that stays valid until the next encode call, and is copied right away.
        let r = unsafe {
            ffi::aap_cvi_enc_encode(
                self.enc,
                frame.y.as_ptr(),
                frame.u.as_ptr(),
                frame.v.as_ptr(),
                timeout_ms,
                &mut out,
                &mut out_len,
            )
        };
        match r {
            AAP_OK if !out.is_null() => {
                // SAFETY: see above.
                Ok(unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec())
            }
            AAP_OK => Ok(Vec::new()),
            AAP_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "CVI encoder timeout waiting for hardware frame",
            )),
            _ => Err(other_err("CVI encode")),
        }
    }

    #[inline]
    pub fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    /// SPS+PPS (Annex-B) obtained from the hardware encoder, empty if it did not provide any.
    #[inline]
    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }
}

impl Drop for CviEncoder {
    fn drop(&mut self) {
        if !self.enc.is_null() {
            // SAFETY: `enc` came from aap_cvi_enc_open and is closed exactly once.
            unsafe { ffi::aap_cvi_enc_close(self.enc) };
            self.enc = std::ptr::null_mut();
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SPS: &[u8] = &[
        0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f, 0x95, 0xa8, 0x2c, 0x05, 0x01, 0xe9,
    ];
    const PPS: &[u8] = &[0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80];
    const IDR: &[u8] = &[0, 0, 0, 1, 0x65, 0x88, 0x84, 0x00];
    const P: &[u8] = &[0, 0, 1, 0x41, 0x9a, 0x00];

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.iter().flat_map(|p| p.iter().copied()).collect()
    }

    #[test]
    fn analyze_au_classifies_nals() {
        assert_eq!(
            analyze_au(&cat(&[SPS, PPS, IDR])),
            AuInfo {
                has_sps: true,
                has_idr: true,
                has_slice: true
            }
        );
        assert_eq!(
            analyze_au(&cat(&[SPS, PPS])),
            AuInfo {
                has_sps: true,
                has_idr: false,
                has_slice: false
            }
        );
        assert_eq!(
            analyze_au(IDR),
            AuInfo {
                has_sps: false,
                has_idr: true,
                has_slice: true
            }
        );
        assert_eq!(
            analyze_au(P),
            AuInfo {
                has_sps: false,
                has_idr: false,
                has_slice: true
            }
        );
        assert_eq!(analyze_au(&[]), AuInfo::default());
    }

    #[test]
    fn align16_rounds_up_to_macroblocks() {
        assert_eq!(align16(1280), 1280);
        assert_eq!(align16(720), 720);
        assert_eq!(align16(1080), 1088);
        assert_eq!(align16(1), 16);
    }

    #[test]
    fn without_cvi_feature_nothing_is_available() {
        if !cfg!(feature = "cvi") {
            assert!(!probe());
            assert_eq!(
                CviDecoder::new().err().map(|e| e.kind()),
                Some(io::ErrorKind::Unsupported)
            );
            assert_eq!(
                CviEncoder::new(1280, 720, 26, 30).err().map(|e| e.kind()),
                Some(io::ErrorKind::Unsupported)
            );
        }
    }
}
