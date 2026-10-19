//! Video4Linux2 (V4L2) Memory-to-Memory (M2M) hardware codec support.
//!
//! Provides hardware-accelerated H.264 decoding and encoding on Linux platforms
//! featuring V4L2 M2M stateful codec drivers (such as the Broadcom `bcm2835-codec`
//! on Raspberry Pi 3/4/Zero 2 W).
//!
//! Supports both Single-Planar (`V4L2_BUF_TYPE_VIDEO_*`) and Multi-Planar
//! (`V4L2_BUF_TYPE_VIDEO_*_MPLANE`) devices automatically. The Raspberry Pi
//! `bcm2835-codec` is a multi-planar device requiring `_MPLANE` buffer types.
//!
//! When available, decoding and encoding are offloaded to dedicated hardware
//! (e.g. `/dev/video10` for decode, `/dev/video11` for encode on Raspberry Pi),
//! dramatically reducing CPU load, lowering video latency, and preventing thermal
//! throttling inside enclosed automotive environments.

use log::{debug, info, warn};
use rusty_h264::YuvFrame;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ============================================================================
// LINUX V4L2 UAPI DEFINITIONS & CONSTANTS
// ============================================================================

pub const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
pub const V4L2_BUF_TYPE_VIDEO_OUTPUT: u32 = 2;
pub const V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE: u32 = 9;
pub const V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE: u32 = 10;

pub const V4L2_MEMORY_MMAP: u32 = 1;
pub const V4L2_MEMORY_USERPTR: u32 = 2;
pub const V4L2_MEMORY_DMABUF: u32 = 4;

pub const V4L2_FIELD_ANY: u32 = 0;
pub const V4L2_FIELD_NONE: u32 = 1;

pub const V4L2_CAP_VIDEO_CAPTURE: u32 = 0x00000001;
pub const V4L2_CAP_VIDEO_OUTPUT: u32 = 0x00000002;
pub const V4L2_CAP_VIDEO_CAPTURE_MPLANE: u32 = 0x00001000;
pub const V4L2_CAP_VIDEO_OUTPUT_MPLANE: u32 = 0x00002000;
pub const V4L2_CAP_VIDEO_M2M_MPLANE: u32 = 0x00004000;
pub const V4L2_CAP_VIDEO_M2M: u32 = 0x00008000;
pub const V4L2_CAP_STREAMING: u32 = 0x04000000;
pub const V4L2_CAP_DEVICE_CAPS: u32 = 0x80000000;

pub const VIDEO_MAX_PLANES: usize = 8;

/// Macro to build a FourCC code.
pub const fn v4l2_fourcc(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

pub const V4L2_PIX_FMT_H264: u32 = v4l2_fourcc(b'H', b'2', b'6', b'4');
pub const V4L2_PIX_FMT_YUV420: u32 = v4l2_fourcc(b'Y', b'U', b'1', b'2');
pub const V4L2_PIX_FMT_YVU420: u32 = v4l2_fourcc(b'Y', b'V', b'1', b'2');
pub const V4L2_PIX_FMT_NV12: u32 = v4l2_fourcc(b'N', b'V', b'1', b'2');
pub const V4L2_PIX_FMT_NV21: u32 = v4l2_fourcc(b'N', b'V', b'2', b'1');

pub const V4L2_EVENT_SOURCE_CHANGE: u32 = 5;
pub const V4L2_EVENT_SRC_CH_RESOLUTION: u32 = 1 << 0;

pub const V4L2_CID_CODEC_BASE: u32 = 0x00990000 | 0x900;
pub const V4L2_CID_MPEG_VIDEO_B_FRAMES: u32 = V4L2_CID_CODEC_BASE + 202;
pub const V4L2_CID_MPEG_VIDEO_BITRATE: u32 = V4L2_CID_CODEC_BASE + 207;
pub const V4L2_CID_MPEG_VIDEO_REPEAT_SEQ_HEADER: u32 = V4L2_CID_CODEC_BASE + 226;
pub const V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME: u32 = V4L2_CID_CODEC_BASE + 229;
pub const V4L2_CID_MPEG_VIDEO_H264_I_PERIOD: u32 = V4L2_CID_CODEC_BASE + 358;
pub const V4L2_CID_MPEG_VIDEO_H264_LEVEL: u32 = V4L2_CID_CODEC_BASE + 359;
pub const V4L2_CID_MPEG_VIDEO_H264_PROFILE: u32 = V4L2_CID_CODEC_BASE + 363;

pub const V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE: i32 = 0;
pub const V4L2_MPEG_VIDEO_H264_PROFILE_CONSTRAINED_BASELINE: i32 = 1;
pub const V4L2_MPEG_VIDEO_H264_PROFILE_MAIN: i32 = 2;
pub const V4L2_MPEG_VIDEO_H264_PROFILE_HIGH: i32 = 4;

pub const V4L2_MPEG_VIDEO_H264_LEVEL_3_1: i32 = 5;
pub const V4L2_MPEG_VIDEO_H264_LEVEL_4_0: i32 = 7;

// ============================================================================
// V4L2 STRUCTS (matching Linux kernel UAPI)
// ============================================================================

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct v4l2_capability {
    pub driver: [u8; 16],
    pub card: [u8; 32],
    pub bus_info: [u8; 32],
    pub version: u32,
    pub capabilities: u32,
    pub device_caps: u32,
    pub reserved: [u32; 3],
}

impl Default for v4l2_capability {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct v4l2_fmtdesc {
    pub index: u32,
    pub type_: u32,
    pub flags: u32,
    pub description: [u8; 32],
    pub pixelformat: u32,
    pub reserved: [u32; 4],
}

impl Default for v4l2_fmtdesc {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct v4l2_pix_format {
    pub width: u32,
    pub height: u32,
    pub pixelformat: u32,
    pub field: u32,
    pub bytesperline: u32,
    pub sizeimage: u32,
    pub colorspace: u32,
    pub priv_: u32,
    pub flags: u32,
    pub ycbcr_enc: u32,
    pub quantization: u32,
    pub xfer_func: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct v4l2_plane_pix_format {
    pub sizeimage: u32,
    pub bytesperline: u32,
    pub reserved: [u16; 6],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct v4l2_pix_format_mplane {
    pub width: u32,
    pub height: u32,
    pub pixelformat: u32,
    pub field: u32,
    pub colorspace: u32,
    pub plane_fmt: [v4l2_plane_pix_format; VIDEO_MAX_PLANES],
    pub num_planes: u8,
    pub flags: u8,
    pub ycbcr_enc: u8,
    pub quantization: u8,
    pub xfer_func: u8,
    pub reserved: [u8; 7],
}

impl Default for v4l2_pix_format_mplane {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// The kernel's `struct v4l2_format` union contains pointer members (`struct v4l2_window`), so its
/// alignment follows the pointer width: 8 bytes (size 208) on 64-bit, but only 4 bytes (size 204)
/// on 32-bit ARM. The zero-sized pointer array reproduces that; a hard-coded `align(8)` would give
/// wrong ioctl numbers (`ENOTTY`) on 32-bit userlands.
#[repr(C)]
#[derive(Copy, Clone)]
pub union v4l2_format_union {
    pub pix: v4l2_pix_format,
    pub pix_mp: v4l2_pix_format_mplane,
    pub raw_data: [u8; 200],
    _align: [*mut libc::c_void; 0],
}

impl Default for v4l2_format_union {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct v4l2_format {
    pub type_: u32,
    pub fmt: v4l2_format_union,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct v4l2_requestbuffers {
    pub count: u32,
    pub type_: u32,
    pub memory: u32,
    pub capabilities: u32,
    pub reserved: [u32; 1],
}

impl Default for v4l2_requestbuffers {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct v4l2_timecode {
    pub type_: u32,
    pub flags: u32,
    pub frames: u8,
    pub seconds: u8,
    pub minutes: u8,
    pub hours: u8,
    pub userbits: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union v4l2_plane_m {
    pub mem_offset: u32,
    pub userptr: usize,
    pub fd: i32,
}

impl Default for v4l2_plane_m {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct v4l2_plane {
    pub bytesused: u32,
    pub length: u32,
    pub m: v4l2_plane_m,
    pub data_offset: u32,
    pub reserved: [u32; 11],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union v4l2_buffer_m {
    pub offset: u32,
    pub userptr: usize,
    pub planes: *mut v4l2_plane,
    pub fd: i32,
}

impl Default for v4l2_buffer_m {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct v4l2_buffer {
    pub index: u32,
    pub type_: u32,
    pub bytesused: u32,
    pub flags: u32,
    pub field: u32,
    pub timestamp: libc::timeval,
    pub timecode: v4l2_timecode,
    pub sequence: u32,
    pub memory: u32,
    pub m: v4l2_buffer_m,
    pub length: u32,
    pub reserved2: u32,
    pub request_fd: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct v4l2_control {
    pub id: u32,
    pub value: i32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct v4l2_event_subscription {
    pub type_: u32,
    pub id: u32,
    pub flags: u32,
    pub reserved: [u32; 5],
}

impl Default for v4l2_event_subscription {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// The kernel union inside `struct v4l2_event` holds 64-bit members, hence 8-byte alignment
// (also on 32-bit ARM EABI).
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct v4l2_event {
    pub type_: u32,
    _pad: u32,
    pub u: [u8; 64],
    pub pending: u32,
    pub sequence: u32,
    pub timestamp: libc::timespec,
    pub id: u32,
    pub reserved: [u32; 8],
}

impl Default for v4l2_event {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// IOCTL macro calculation: _IOC(dir, type, nr, size)
const fn _ioc(dir: u32, type_: u8, nr: u32, size: usize) -> libc::c_ulong {
    (((dir & 3) << 30) | (((size as u32) & 0x3FFF) << 16) | ((type_ as u32) << 8) | (nr & 0xFF))
        as libc::c_ulong
}

const fn _ior<T>(type_: u8, nr: u32) -> libc::c_ulong {
    _ioc(2, type_, nr, std::mem::size_of::<T>())
}

const fn _iow<T>(type_: u8, nr: u32) -> libc::c_ulong {
    _ioc(1, type_, nr, std::mem::size_of::<T>())
}

const fn _iowr<T>(type_: u8, nr: u32) -> libc::c_ulong {
    _ioc(3, type_, nr, std::mem::size_of::<T>())
}

pub const VIDIOC_QUERYCAP: libc::c_ulong = _ior::<v4l2_capability>(b'V', 0);
pub const VIDIOC_ENUM_FMT: libc::c_ulong = _iowr::<v4l2_fmtdesc>(b'V', 2);
pub const VIDIOC_G_FMT: libc::c_ulong = _iowr::<v4l2_format>(b'V', 4);
pub const VIDIOC_S_FMT: libc::c_ulong = _iowr::<v4l2_format>(b'V', 5);
pub const VIDIOC_REQBUFS: libc::c_ulong = _iowr::<v4l2_requestbuffers>(b'V', 8);
pub const VIDIOC_QUERYBUF: libc::c_ulong = _iowr::<v4l2_buffer>(b'V', 9);
pub const VIDIOC_QBUF: libc::c_ulong = _iowr::<v4l2_buffer>(b'V', 15);
pub const VIDIOC_DQBUF: libc::c_ulong = _iowr::<v4l2_buffer>(b'V', 17);
pub const VIDIOC_STREAMON: libc::c_ulong = _iow::<libc::c_int>(b'V', 18);
pub const VIDIOC_STREAMOFF: libc::c_ulong = _iow::<libc::c_int>(b'V', 19);
pub const VIDIOC_S_CTRL: libc::c_ulong = _iowr::<v4l2_control>(b'V', 28);
pub const VIDIOC_DQEVENT: libc::c_ulong = _ior::<v4l2_event>(b'V', 89);
pub const VIDIOC_SUBSCRIBE_EVENT: libc::c_ulong = _iow::<v4l2_event_subscription>(b'V', 90);

// ============================================================================
// SAFE IOCTL WRAPPERS & BUFFER HELPERS
// ============================================================================

fn xioctl<T>(fd: RawFd, request: libc::c_ulong, arg: *mut T) -> libc::c_int {
    loop {
        let ret = unsafe { libc::ioctl(fd, request, arg) };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
        }
        return ret;
    }
}

fn set_format(
    fd: RawFd,
    buf_type: u32,
    is_multiplanar: bool,
    width: u32,
    height: u32,
    pixelformat: u32,
    sizeimage: u32,
    bytesperline: u32,
) -> Result<v4l2_format, std::io::Error> {
    let mut fmt = v4l2_format::default();
    fmt.type_ = buf_type;
    if is_multiplanar {
        unsafe {
            fmt.fmt.pix_mp.width = width;
            fmt.fmt.pix_mp.height = height;
            fmt.fmt.pix_mp.pixelformat = pixelformat;
            fmt.fmt.pix_mp.field = V4L2_FIELD_NONE;
            fmt.fmt.pix_mp.num_planes = 1;
            fmt.fmt.pix_mp.plane_fmt[0].sizeimage = sizeimage;
            fmt.fmt.pix_mp.plane_fmt[0].bytesperline = bytesperline;
        }
    } else {
        fmt.fmt.pix.width = width;
        fmt.fmt.pix.height = height;
        fmt.fmt.pix.pixelformat = pixelformat;
        fmt.fmt.pix.field = V4L2_FIELD_NONE;
        fmt.fmt.pix.sizeimage = sizeimage;
        fmt.fmt.pix.bytesperline = bytesperline;
    }
    if xioctl(fd, VIDIOC_S_FMT, &mut fmt) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fmt)
}

fn get_format(
    fd: RawFd,
    buf_type: u32,
    is_multiplanar: bool,
) -> Result<(u32, u32, u32, u32, u32), std::io::Error> {
    let mut fmt = v4l2_format::default();
    fmt.type_ = buf_type;
    if xioctl(fd, VIDIOC_G_FMT, &mut fmt) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if is_multiplanar {
        unsafe {
            let pix = &fmt.fmt.pix_mp;
            Ok((
                pix.width,
                pix.height,
                pix.pixelformat,
                pix.plane_fmt[0].sizeimage,
                pix.plane_fmt[0].bytesperline,
            ))
        }
    } else {
        unsafe {
            let pix = &fmt.fmt.pix;
            Ok((
                pix.width,
                pix.height,
                pix.pixelformat,
                pix.sizeimage,
                pix.bytesperline,
            ))
        }
    }
}

fn query_buffer_mmap(
    fd: RawFd,
    buf_type: u32,
    is_multiplanar: bool,
    index: u32,
) -> Result<MmapBuffer, std::io::Error> {
    let mut buf = v4l2_buffer::default();
    buf.type_ = buf_type;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = index;

    let (offset, length) = if is_multiplanar {
        let mut planes = [v4l2_plane::default(); 1];
        buf.length = 1;
        buf.m.planes = planes.as_mut_ptr();
        if xioctl(fd, VIDIOC_QUERYBUF, &mut buf) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        (unsafe { planes[0].m.mem_offset }, planes[0].length as usize)
    } else {
        if xioctl(fd, VIDIOC_QUERYBUF, &mut buf) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        (unsafe { buf.m.offset }, buf.length as usize)
    };

    MmapBuffer::new(fd, offset, length)
}

fn qbuf(
    fd: RawFd,
    buf_type: u32,
    is_multiplanar: bool,
    index: u32,
    bytes_used: u32,
    length: usize,
) -> Result<(), std::io::Error> {
    let mut buf = v4l2_buffer::default();
    buf.type_ = buf_type;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = index;

    if is_multiplanar {
        let mut planes = [v4l2_plane::default(); 1];
        buf.length = 1;
        planes[0].bytesused = bytes_used;
        planes[0].length = length as u32;
        buf.m.planes = planes.as_mut_ptr();
        if xioctl(fd, VIDIOC_QBUF, &mut buf) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    } else {
        buf.bytesused = bytes_used;
        buf.length = length as u32;
        if xioctl(fd, VIDIOC_QBUF, &mut buf) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn dqbuf(
    fd: RawFd,
    buf_type: u32,
    is_multiplanar: bool,
) -> Result<(u32, u32, u32), std::io::Error> {
    let mut buf = v4l2_buffer::default();
    buf.type_ = buf_type;
    buf.memory = V4L2_MEMORY_MMAP;

    if is_multiplanar {
        let mut planes = [v4l2_plane::default(); 1];
        buf.length = 1;
        buf.m.planes = planes.as_mut_ptr();
        if xioctl(fd, VIDIOC_DQBUF, &mut buf) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((buf.index, planes[0].bytesused, buf.flags))
    } else {
        if xioctl(fd, VIDIOC_DQBUF, &mut buf) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((buf.index, buf.bytesused, buf.flags))
    }
}

// ============================================================================
// MMAP BUFFER MANAGEMENT
// ============================================================================

struct MmapBuffer {
    ptr: *mut u8,
    length: usize,
}

unsafe impl Send for MmapBuffer {}
unsafe impl Sync for MmapBuffer {}

impl MmapBuffer {
    fn new(fd: RawFd, offset: u32, length: usize) -> Result<Self, std::io::Error> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                offset as libc::off_t,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            ptr: ptr as *mut u8,
            length,
        })
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.length) }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.length) }
    }
}

impl Drop for MmapBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.ptr != libc::MAP_FAILED as *mut u8 {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.length);
            }
        }
    }
}

// ============================================================================
// DEVICE PROBING & DISCOVERY
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4l2CodecDevices {
    pub decoder_path: PathBuf,
    pub encoder_path: PathBuf,
}

/// Probes the system for V4L2 M2M H.264 decoder and encoder devices.
///
/// Supports both single-plane and multi-plane M2M devices (such as `/dev/video10`
/// and `/dev/video11` on Raspberry Pi `bcm2835-codec`).
pub fn probe_v4l2_codec_devices(
    explicit_decoder: Option<&str>,
    explicit_encoder: Option<&str>,
) -> Option<V4l2CodecDevices> {
    let explicit_dec_set = explicit_decoder
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let explicit_enc_set = explicit_encoder
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    let mut decoder_path = explicit_decoder
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .filter(|p| p.exists());
    let mut encoder_path = explicit_encoder
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .filter(|p| p.exists());

    if explicit_dec_set && decoder_path.is_none() {
        warn!("v4l2_m2m: configured decoder path does not exist");
        return None;
    }
    if explicit_enc_set && encoder_path.is_none() {
        warn!("v4l2_m2m: configured encoder path does not exist");
        return None;
    }

    if let (Some(dec), Some(enc)) = (&decoder_path, &encoder_path) {
        return Some(V4l2CodecDevices {
            decoder_path: dec.clone(),
            encoder_path: enc.clone(),
        });
    }

    for idx in 0..64 {
        if decoder_path.is_some() && encoder_path.is_some() {
            break;
        }
        let dev_path = PathBuf::from(format!("/dev/video{}", idx));
        if !dev_path.exists() {
            continue;
        }

        let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&dev_path)
        else {
            continue;
        };

        let fd = file.as_raw_fd();
        let mut cap = v4l2_capability::default();
        if xioctl(fd, VIDIOC_QUERYCAP, &mut cap) != 0 {
            continue;
        }

        let caps = if (cap.capabilities & V4L2_CAP_DEVICE_CAPS) != 0 {
            cap.device_caps
        } else {
            cap.capabilities
        };

        // Check if device is M2M capable (single-planar or multi-planar)
        let is_m2m = (caps & (V4L2_CAP_VIDEO_M2M | V4L2_CAP_VIDEO_M2M_MPLANE)) != 0
            || ((caps & V4L2_CAP_VIDEO_CAPTURE != 0) && (caps & V4L2_CAP_VIDEO_OUTPUT != 0))
            || ((caps & V4L2_CAP_VIDEO_CAPTURE_MPLANE != 0)
                && (caps & V4L2_CAP_VIDEO_OUTPUT_MPLANE != 0));

        if !is_m2m {
            continue;
        }

        let is_multiplanar = (caps
            & (V4L2_CAP_VIDEO_CAPTURE_MPLANE
                | V4L2_CAP_VIDEO_OUTPUT_MPLANE
                | V4L2_CAP_VIDEO_M2M_MPLANE))
            != 0;
        let out_type = if is_multiplanar {
            V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE
        } else {
            V4L2_BUF_TYPE_VIDEO_OUTPUT
        };
        let cap_type = if is_multiplanar {
            V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
        } else {
            V4L2_BUF_TYPE_VIDEO_CAPTURE
        };

        let mut out_h264 = false;
        let mut cap_raw = false;
        let mut out_raw = false;
        let mut cap_h264 = false;

        // Check OUTPUT formats
        for f_idx in 0..32 {
            let mut fmtdesc = v4l2_fmtdesc::default();
            fmtdesc.index = f_idx;
            fmtdesc.type_ = out_type;
            if xioctl(fd, VIDIOC_ENUM_FMT, &mut fmtdesc) != 0 {
                break;
            }
            if fmtdesc.pixelformat == V4L2_PIX_FMT_H264 {
                out_h264 = true;
            } else if fmtdesc.pixelformat == V4L2_PIX_FMT_YUV420
                || fmtdesc.pixelformat == V4L2_PIX_FMT_NV12
                || fmtdesc.pixelformat == V4L2_PIX_FMT_YVU420
            {
                out_raw = true;
            }
        }

        // Check CAPTURE formats
        for f_idx in 0..32 {
            let mut fmtdesc = v4l2_fmtdesc::default();
            fmtdesc.index = f_idx;
            fmtdesc.type_ = cap_type;
            if xioctl(fd, VIDIOC_ENUM_FMT, &mut fmtdesc) != 0 {
                break;
            }
            if fmtdesc.pixelformat == V4L2_PIX_FMT_H264 {
                cap_h264 = true;
            } else if fmtdesc.pixelformat == V4L2_PIX_FMT_YUV420
                || fmtdesc.pixelformat == V4L2_PIX_FMT_NV12
                || fmtdesc.pixelformat == V4L2_PIX_FMT_YVU420
            {
                cap_raw = true;
            }
        }

        let driver_name = std::str::from_utf8(&cap.driver)
            .unwrap_or("")
            .trim_matches(char::from(0));
        let card_name = std::str::from_utf8(&cap.card)
            .unwrap_or("")
            .trim_matches(char::from(0));

        if decoder_path.is_none() && out_h264 && cap_raw {
            debug!(
                "v4l2_m2m: detected H.264 decoder on {} (driver: '{}', card: '{}', multiplanar: {})",
                dev_path.display(),
                driver_name,
                card_name,
                is_multiplanar
            );
            decoder_path = Some(dev_path.clone());
        } else if encoder_path.is_none() && out_raw && cap_h264 {
            debug!(
                "v4l2_m2m: detected H.264 encoder on {} (driver: '{}', card: '{}', multiplanar: {})",
                dev_path.display(),
                driver_name,
                card_name,
                is_multiplanar
            );
            encoder_path = Some(dev_path);
        }
    }

    match (decoder_path, encoder_path) {
        (Some(dec), Some(enc)) => Some(V4l2CodecDevices {
            decoder_path: dec,
            encoder_path: enc,
        }),
        _ => None,
    }
}

// ============================================================================
// V4L2 M2M STATEFUL H.264 DECODER
// ============================================================================

pub struct V4l2M2mDecoder {
    file: File,
    path: PathBuf,
    is_multiplanar: bool,
    output_type: u32,
    capture_type: u32,
    width: usize,
    height: usize,
    bytesperline: usize,
    pixelformat: u32,
    output_buffers: Vec<MmapBuffer>,
    capture_buffers: Vec<MmapBuffer>,
    available_output_indices: VecDeque<u32>,
    streaming: bool,
}

impl V4l2M2mDecoder {
    pub fn new(path: &Path) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;

        let fd = file.as_raw_fd();

        let mut cap = v4l2_capability::default();
        if xioctl(fd, VIDIOC_QUERYCAP, &mut cap) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let caps = if (cap.capabilities & V4L2_CAP_DEVICE_CAPS) != 0 {
            cap.device_caps
        } else {
            cap.capabilities
        };

        let is_multiplanar = (caps
            & (V4L2_CAP_VIDEO_CAPTURE_MPLANE
                | V4L2_CAP_VIDEO_OUTPUT_MPLANE
                | V4L2_CAP_VIDEO_M2M_MPLANE))
            != 0;
        let output_type = if is_multiplanar {
            V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE
        } else {
            V4L2_BUF_TYPE_VIDEO_OUTPUT
        };
        let capture_type = if is_multiplanar {
            V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
        } else {
            V4L2_BUF_TYPE_VIDEO_CAPTURE
        };

        // Subscribe to source change resolution events
        let mut sub = v4l2_event_subscription::default();
        sub.type_ = V4L2_EVENT_SOURCE_CHANGE;
        let _ = xioctl(fd, VIDIOC_SUBSCRIBE_EVENT, &mut sub);

        // Set OUTPUT format (compressed H.264 bitstream)
        let sizeimage = 1024 * 1024; // 1MB buffer for bitstream NALs
        set_format(
            fd,
            output_type,
            is_multiplanar,
            1280,
            720,
            V4L2_PIX_FMT_H264,
            sizeimage,
            0,
        )?;

        // Request OUTPUT buffers
        let mut req_out = v4l2_requestbuffers::default();
        req_out.count = 8;
        req_out.type_ = output_type;
        req_out.memory = V4L2_MEMORY_MMAP;
        if xioctl(fd, VIDIOC_REQBUFS, &mut req_out) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut output_buffers = Vec::with_capacity(req_out.count as usize);
        let mut available_output_indices = VecDeque::with_capacity(req_out.count as usize);

        for idx in 0..req_out.count {
            let mmap = query_buffer_mmap(fd, output_type, is_multiplanar, idx)?;
            output_buffers.push(mmap);
            available_output_indices.push_back(idx);
        }

        // Start OUTPUT stream
        let mut stream_type = output_type as libc::c_int;
        if xioctl(fd, VIDIOC_STREAMON, &mut stream_type) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            file,
            path: path.to_path_buf(),
            is_multiplanar,
            output_type,
            capture_type,
            width: 0,
            height: 0,
            bytesperline: 0,
            pixelformat: V4L2_PIX_FMT_YUV420,
            output_buffers,
            capture_buffers: Vec::new(),
            available_output_indices,
            streaming: false,
        })
    }

    fn check_source_change_and_setup_capture(&mut self) -> Result<bool, std::io::Error> {
        let fd = self.file.as_raw_fd();
        let mut ev = v4l2_event::default();
        let mut source_changed = false;

        while xioctl(fd, VIDIOC_DQEVENT, &mut ev) == 0 {
            if ev.type_ == V4L2_EVENT_SOURCE_CHANGE {
                source_changed = true;
            }
        }

        if !source_changed {
            if self.streaming {
                return Ok(false);
            }
            // Check if event is pending on first packet
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLPRI,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, 2) };
            if ret > 0 && (pfd.revents & libc::POLLPRI != 0) {
                while xioctl(fd, VIDIOC_DQEVENT, &mut ev) == 0 {
                    if ev.type_ == V4L2_EVENT_SOURCE_CHANGE {
                        source_changed = true;
                    }
                }
            }
            if !source_changed {
                return Ok(false);
            }
        }

        // Query current negotiated format from CAPTURE
        let (new_w, new_h, fmt_pix, sizeimage, mut bytesperline) =
            match get_format(fd, self.capture_type, self.is_multiplanar) {
                Ok(res) => res,
                Err(_) => return Ok(false),
            };

        if new_w == 0 || new_h == 0 {
            return Ok(false);
        }

        if self.streaming && self.width == (new_w as usize) && self.height == (new_h as usize) {
            return Ok(false);
        }

        info!(
            "v4l2_m2m: decoder {} source resolution detected: {}x{} (format: {:#010x}, multiplanar: {})",
            self.path.display(),
            new_w,
            new_h,
            fmt_pix,
            self.is_multiplanar
        );

        // If capture was already running with an older format, stop and release
        if self.streaming {
            let mut stream_type = self.capture_type as libc::c_int;
            let _ = xioctl(fd, VIDIOC_STREAMOFF, &mut stream_type);
            self.capture_buffers.clear();

            let mut req_cap = v4l2_requestbuffers::default();
            req_cap.count = 0;
            req_cap.type_ = self.capture_type;
            req_cap.memory = V4L2_MEMORY_MMAP;
            let _ = xioctl(fd, VIDIOC_REQBUFS, &mut req_cap);
        }

        // Negotiate CAPTURE format with driver
        if let Ok(negotiated) = set_format(
            fd,
            self.capture_type,
            self.is_multiplanar,
            new_w,
            new_h,
            fmt_pix,
            sizeimage,
            bytesperline,
        ) {
            if self.is_multiplanar {
                unsafe {
                    bytesperline = negotiated.fmt.pix_mp.plane_fmt[0].bytesperline;
                }
            } else {
                unsafe {
                    bytesperline = negotiated.fmt.pix.bytesperline;
                }
            }
        }

        // Request CAPTURE buffers
        let mut req_cap = v4l2_requestbuffers::default();
        req_cap.count = 8;
        req_cap.type_ = self.capture_type;
        req_cap.memory = V4L2_MEMORY_MMAP;
        if xioctl(fd, VIDIOC_REQBUFS, &mut req_cap) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut capture_buffers = Vec::with_capacity(req_cap.count as usize);
        for idx in 0..req_cap.count {
            let mmap = query_buffer_mmap(fd, self.capture_type, self.is_multiplanar, idx)?;
            let buf_len = mmap.length;
            capture_buffers.push(mmap);

            // Pre-queue buffer for output
            qbuf(fd, self.capture_type, self.is_multiplanar, idx, 0, buf_len)?;
        }

        // Start CAPTURE stream
        let mut stream_type = self.capture_type as libc::c_int;
        if xioctl(fd, VIDIOC_STREAMON, &mut stream_type) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.width = new_w as usize;
        self.height = new_h as usize;
        self.bytesperline = bytesperline as usize;
        self.pixelformat = fmt_pix;
        self.capture_buffers = capture_buffers;
        self.streaming = true;

        Ok(true)
    }

    /// Reclaims completed OUTPUT buffers so they can be reused for subsequent frames.
    fn drain_output_buffers(&mut self) {
        let fd = self.file.as_raw_fd();
        loop {
            match dqbuf(fd, self.output_type, self.is_multiplanar) {
                Ok((index, _, _)) => {
                    self.available_output_indices.push_back(index);
                }
                Err(_) => break,
            }
        }
    }

    /// Decodes an H.264 video NAL/slice into a [`YuvFrame`].
    pub fn decode(&mut self, h264_data: &[u8]) -> Result<Option<YuvFrame>, std::io::Error> {
        let fd = self.file.as_raw_fd();
        self.drain_output_buffers();

        // 1. Submit compressed NAL to OUTPUT queue
        if !h264_data.is_empty() {
            let out_idx = match self.available_output_indices.pop_front() {
                Some(idx) => Some(idx),
                None => {
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    unsafe { libc::poll(&mut pfd, 1, 10) };
                    self.drain_output_buffers();
                    self.available_output_indices.pop_front()
                }
            };

            if let Some(out_idx) = out_idx {
                let out_buf = &mut self.output_buffers[out_idx as usize];
                if h264_data.len() > out_buf.length {
                    // Never feed a truncated access unit to the hardware decoder.
                    self.available_output_indices.push_back(out_idx);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "access unit ({} bytes) larger than V4L2 OUTPUT buffer ({} bytes)",
                            h264_data.len(),
                            out_buf.length
                        ),
                    ));
                }
                let copy_len = h264_data.len();
                out_buf.as_mut_slice()[..copy_len].copy_from_slice(h264_data);

                if let Err(e) = qbuf(
                    fd,
                    self.output_type,
                    self.is_multiplanar,
                    out_idx,
                    copy_len as u32,
                    out_buf.length,
                ) {
                    self.available_output_indices.push_back(out_idx);
                    return Err(e);
                }
            }
        }

        // 2. Process source resolution changes / initial capture setup
        let _ = self.check_source_change_and_setup_capture()?;

        if !self.streaming {
            return Ok(None);
        }

        // 3. Dequeue a decoded frame from CAPTURE with brief polling
        let poll_start = Instant::now();
        let (cap_idx, _bytesused, _flags) = loop {
            match dqbuf(fd, self.capture_type, self.is_multiplanar) {
                Ok(res) => break (res.0 as usize, res.1 as usize, res.2),
                Err(err) => {
                    if err.raw_os_error() != Some(libc::EAGAIN) {
                        return Err(err);
                    }
                    if poll_start.elapsed() > Duration::from_millis(45) {
                        return Ok(None);
                    }
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe { libc::poll(&mut pfd, 1, 2) };
                }
            }
        };

        let w = self.width;
        let h = self.height;
        let bpl = if self.bytesperline >= w {
            self.bytesperline
        } else {
            w
        };

        let yuv_result = if cap_idx < self.capture_buffers.len() && w > 0 && h > 0 {
            let raw_bytes = self.capture_buffers[cap_idx].as_slice();
            let y_size = w * h;
            let uv_size = (w / 2) * (h / 2);

            if self.pixelformat == V4L2_PIX_FMT_YUV420 {
                if bpl == w && raw_bytes.len() >= y_size + uv_size * 2 {
                    let y = raw_bytes[..y_size].to_vec();
                    let u = raw_bytes[y_size..y_size + uv_size].to_vec();
                    let v = raw_bytes[y_size + uv_size..y_size + uv_size * 2].to_vec();
                    Some(YuvFrame {
                        width: w,
                        height: h,
                        y,
                        u,
                        v,
                    })
                } else if raw_bytes.len() >= bpl * h + (bpl / 2) * (h / 2) * 2 {
                    let mut y = Vec::with_capacity(y_size);
                    for row in 0..h {
                        let start = row * bpl;
                        y.extend_from_slice(&raw_bytes[start..start + w]);
                    }
                    let uv_bpl = bpl / 2;
                    let uv_w = w / 2;
                    let uv_h = h / 2;
                    let u_base = bpl * h;
                    let mut u = Vec::with_capacity(uv_size);
                    for row in 0..uv_h {
                        let start = u_base + row * uv_bpl;
                        u.extend_from_slice(&raw_bytes[start..start + uv_w]);
                    }
                    let v_base = u_base + uv_bpl * uv_h;
                    let mut v = Vec::with_capacity(uv_size);
                    for row in 0..uv_h {
                        let start = v_base + row * uv_bpl;
                        v.extend_from_slice(&raw_bytes[start..start + uv_w]);
                    }
                    Some(YuvFrame {
                        width: w,
                        height: h,
                        y,
                        u,
                        v,
                    })
                } else {
                    None
                }
            } else if self.pixelformat == V4L2_PIX_FMT_NV12 {
                let mut y = Vec::with_capacity(y_size);
                if bpl == w && raw_bytes.len() >= y_size + uv_size * 2 {
                    y.extend_from_slice(&raw_bytes[..y_size]);
                } else if raw_bytes.len() >= bpl * h + bpl * (h / 2) {
                    for row in 0..h {
                        let start = row * bpl;
                        y.extend_from_slice(&raw_bytes[start..start + w]);
                    }
                }
                let uv_base = bpl * h;
                let mut u = Vec::with_capacity(uv_size);
                let mut v = Vec::with_capacity(uv_size);
                for row in 0..(h / 2) {
                    let row_start = uv_base + row * bpl;
                    if row_start + w <= raw_bytes.len() {
                        for pair in raw_bytes[row_start..row_start + w].chunks_exact(2) {
                            u.push(pair[0]);
                            v.push(pair[1]);
                        }
                    }
                }
                if y.len() == y_size && u.len() == uv_size && v.len() == uv_size {
                    Some(YuvFrame {
                        width: w,
                        height: h,
                        y,
                        u,
                        v,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Re-queue the CAPTURE buffer for subsequent decodes
        let cap_buf_len = self.capture_buffers[cap_idx].length;
        let _ = qbuf(
            fd,
            self.capture_type,
            self.is_multiplanar,
            cap_idx as u32,
            0,
            cap_buf_len,
        );

        Ok(yuv_result)
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }
}

impl Drop for V4l2M2mDecoder {
    fn drop(&mut self) {
        let fd = self.file.as_raw_fd();
        let mut out_type = self.output_type as libc::c_int;
        let mut cap_type = self.capture_type as libc::c_int;
        let _ = xioctl(fd, VIDIOC_STREAMOFF, &mut out_type);
        let _ = xioctl(fd, VIDIOC_STREAMOFF, &mut cap_type);
    }
}

// ============================================================================
// V4L2 M2M STATEFUL H.264 ENCODER
// ============================================================================

pub struct V4l2M2mEncoder {
    file: File,
    path: PathBuf,
    is_multiplanar: bool,
    output_type: u32,
    capture_type: u32,
    width: usize,
    height: usize,
    bytesperline: usize,
    pixelformat: u32,
    output_buffers: Vec<MmapBuffer>,
    capture_buffers: Vec<MmapBuffer>,
    available_output_indices: VecDeque<u32>,
    header_bytes: Vec<u8>,
}

impl V4l2M2mEncoder {
    pub fn new(
        path: &Path,
        width: usize,
        height: usize,
        _qp: u8,
        gop: u32,
    ) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;

        let fd = file.as_raw_fd();

        let mut cap = v4l2_capability::default();
        if xioctl(fd, VIDIOC_QUERYCAP, &mut cap) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let caps = if (cap.capabilities & V4L2_CAP_DEVICE_CAPS) != 0 {
            cap.device_caps
        } else {
            cap.capabilities
        };

        let is_multiplanar = (caps
            & (V4L2_CAP_VIDEO_CAPTURE_MPLANE
                | V4L2_CAP_VIDEO_OUTPUT_MPLANE
                | V4L2_CAP_VIDEO_M2M_MPLANE))
            != 0;
        let output_type = if is_multiplanar {
            V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE
        } else {
            V4L2_BUF_TYPE_VIDEO_OUTPUT
        };
        let capture_type = if is_multiplanar {
            V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
        } else {
            V4L2_BUF_TYPE_VIDEO_CAPTURE
        };

        // 1. Set OUTPUT format (raw uncompressed YUV420 from overlay)
        let yuv_size = ((width * height * 3) / 2) as u32;
        let mut chosen_pixfmt = V4L2_PIX_FMT_YUV420;
        let negotiated_fmt = match set_format(
            fd,
            output_type,
            is_multiplanar,
            width as u32,
            height as u32,
            V4L2_PIX_FMT_YUV420,
            yuv_size,
            width as u32,
        ) {
            Ok(fmt) => fmt,
            Err(_) => {
                // Try NV12 if YUV420 is rejected
                chosen_pixfmt = V4L2_PIX_FMT_NV12;
                set_format(
                    fd,
                    output_type,
                    is_multiplanar,
                    width as u32,
                    height as u32,
                    V4L2_PIX_FMT_NV12,
                    yuv_size,
                    width as u32,
                )?
            }
        };

        let (bpl, _out_sizeimage) = if is_multiplanar {
            unsafe {
                (
                    negotiated_fmt.fmt.pix_mp.plane_fmt[0].bytesperline as usize,
                    negotiated_fmt.fmt.pix_mp.plane_fmt[0].sizeimage as usize,
                )
            }
        } else {
            unsafe {
                (
                    negotiated_fmt.fmt.pix.bytesperline as usize,
                    negotiated_fmt.fmt.pix.sizeimage as usize,
                )
            }
        };

        // 2. Set CAPTURE format (compressed H.264 Annex-B)
        set_format(
            fd,
            capture_type,
            is_multiplanar,
            width as u32,
            height as u32,
            V4L2_PIX_FMT_H264,
            512 * 1024,
            0,
        )?;

        // 3. Set H.264 encoding controls for Car Head Unit compatibility
        // Baseline profile
        let mut ctrl = v4l2_control {
            id: V4L2_CID_MPEG_VIDEO_H264_PROFILE,
            value: V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE,
        };
        let _ = xioctl(fd, VIDIOC_S_CTRL, &mut ctrl);

        // Zero B-frames (essential for live zero-latency projection)
        ctrl.id = V4L2_CID_MPEG_VIDEO_B_FRAMES;
        ctrl.value = 0;
        let _ = xioctl(fd, VIDIOC_S_CTRL, &mut ctrl);

        // GOP / Keyframe interval
        ctrl.id = V4L2_CID_MPEG_VIDEO_H264_I_PERIOD;
        ctrl.value = gop.max(1) as i32;
        let _ = xioctl(fd, VIDIOC_S_CTRL, &mut ctrl);

        // Repeat sequence headers (SPS/PPS before IDR)
        ctrl.id = V4L2_CID_MPEG_VIDEO_REPEAT_SEQ_HEADER;
        ctrl.value = 1;
        let _ = xioctl(fd, VIDIOC_S_CTRL, &mut ctrl);

        // Bitrate (default 4 Mbps for Android Auto)
        ctrl.id = V4L2_CID_MPEG_VIDEO_BITRATE;
        ctrl.value = 4_000_000;
        let _ = xioctl(fd, VIDIOC_S_CTRL, &mut ctrl);

        // 4. Request and map OUTPUT buffers
        let mut req_out = v4l2_requestbuffers::default();
        req_out.count = 6;
        req_out.type_ = output_type;
        req_out.memory = V4L2_MEMORY_MMAP;
        if xioctl(fd, VIDIOC_REQBUFS, &mut req_out) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut output_buffers = Vec::with_capacity(req_out.count as usize);
        let mut available_output_indices = VecDeque::with_capacity(req_out.count as usize);

        for idx in 0..req_out.count {
            let mmap = query_buffer_mmap(fd, output_type, is_multiplanar, idx)?;
            output_buffers.push(mmap);
            available_output_indices.push_back(idx);
        }

        // 5. Request and map CAPTURE buffers
        let mut req_cap = v4l2_requestbuffers::default();
        req_cap.count = 6;
        req_cap.type_ = capture_type;
        req_cap.memory = V4L2_MEMORY_MMAP;
        if xioctl(fd, VIDIOC_REQBUFS, &mut req_cap) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut capture_buffers = Vec::with_capacity(req_cap.count as usize);
        for idx in 0..req_cap.count {
            let mmap = query_buffer_mmap(fd, capture_type, is_multiplanar, idx)?;
            let buf_len = mmap.length;
            capture_buffers.push(mmap);

            // Queue buffer to receive encoded H.264
            qbuf(fd, capture_type, is_multiplanar, idx, 0, buf_len)?;
        }

        // 6. Start streaming on both queues
        let mut out_stream = output_type as libc::c_int;
        if xioctl(fd, VIDIOC_STREAMON, &mut out_stream) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut cap_stream = capture_type as libc::c_int;
        if xioctl(fd, VIDIOC_STREAMON, &mut cap_stream) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        info!(
            "v4l2_m2m: encoder {} initialized for {}x{} (GOP={}, Baseline, 0 B-frames, multiplanar: {})",
            path.display(),
            width,
            height,
            gop,
            is_multiplanar
        );

        let mut encoder = Self {
            file,
            path: path.to_path_buf(),
            is_multiplanar,
            output_type,
            capture_type,
            width,
            height,
            bytesperline: bpl,
            pixelformat: chosen_pixfmt,
            output_buffers,
            capture_buffers,
            available_output_indices,
            header_bytes: Vec::new(),
        };

        // Warm up the hardware encoder with a single blank frame to capture genuine SPS/PPS headers
        let dummy = YuvFrame {
            width,
            height,
            y: vec![16; width * height],
            u: vec![128; (width / 2) * (height / 2)],
            v: vec![128; (width / 2) * (height / 2)],
        };
        // The very first frame can take much longer than steady-state frames.
        match encoder.encode_with_timeout(&dummy, Duration::from_millis(1000)) {
            Ok(first_au) => {
                let sps_pps = extract_sps_pps_annex_b(&first_au);
                if !sps_pps.is_empty() {
                    info!(
                        "v4l2_m2m: extracted {} bytes SPS+PPS from hardware encoder {}",
                        sps_pps.len(),
                        encoder.path.display()
                    );
                    encoder.header_bytes = sps_pps;
                }
            }
            Err(e) => {
                warn!("v4l2_m2m: encoder warmup frame failed: {:?}", e);
            }
        }
        // Force the first live frame to also be an IDR keyframe
        encoder.request_keyframe();

        Ok(encoder)
    }

    /// Requests an immediate IDR keyframe from the hardware encoder.
    pub fn request_keyframe(&mut self) {
        let fd = self.file.as_raw_fd();
        let mut ctrl = v4l2_control {
            id: V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME,
            value: 1,
        };
        let _ = xioctl(fd, VIDIOC_S_CTRL, &mut ctrl);
    }

    /// Reclaims completed OUTPUT buffers so they can be reused for subsequent frames.
    fn drain_output_buffers(&mut self) {
        let fd = self.file.as_raw_fd();
        loop {
            match dqbuf(fd, self.output_type, self.is_multiplanar) {
                Ok((index, _, _)) => {
                    self.available_output_indices.push_back(index);
                }
                Err(_) => break,
            }
        }
    }

    /// Encodes a raw [`YuvFrame`] into H.264 Annex-B bytes.
    pub fn encode(&mut self, frame: &YuvFrame) -> Result<Vec<u8>, std::io::Error> {
        self.encode_with_timeout(frame, Duration::from_millis(45))
    }

    /// Same as [`Self::encode`] with an explicit limit for waiting for the hardware.
    fn encode_with_timeout(
        &mut self,
        frame: &YuvFrame,
        timeout: Duration,
    ) -> Result<Vec<u8>, std::io::Error> {
        let fd = self.file.as_raw_fd();

        // Validate the frame so the plane copies below can never panic (release builds abort).
        let (w, h) = (self.width, self.height);
        if frame.width != w
            || frame.height != h
            || frame.y.len() < w * h
            || frame.u.len() < (w / 2) * (h / 2)
            || frame.v.len() < (w / 2) * (h / 2)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "frame does not match V4L2 encoder dimensions",
            ));
        }

        self.drain_output_buffers();

        // 1. Get available OUTPUT buffer
        let out_idx = match self.available_output_indices.pop_front() {
            Some(idx) => idx,
            None => {
                // Wait briefly for a buffer to free up
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, 10) };
                self.drain_output_buffers();
                self.available_output_indices.pop_front().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::WouldBlock, "encoder OUTPUT queue full")
                })?
            }
        };

        // 2. Copy YUV planes into mapped buffer
        let out_buf = &mut self.output_buffers[out_idx as usize];
        let dst_len = out_buf.length;
        let dst = out_buf.as_mut_slice();
        let bpl = if self.bytesperline >= w {
            self.bytesperline
        } else {
            w
        };
        let bytes_used: usize;

        if self.pixelformat == V4L2_PIX_FMT_YUV420 {
            let y_size = w * h;
            let uv_size = (w / 2) * (h / 2);
            if bpl == w {
                bytes_used = y_size + uv_size * 2;
                if dst.len() >= bytes_used {
                    dst[..y_size].copy_from_slice(&frame.y);
                    dst[y_size..y_size + uv_size].copy_from_slice(&frame.u);
                    dst[y_size + uv_size..bytes_used].copy_from_slice(&frame.v);
                }
            } else {
                let uv_bpl = bpl / 2;
                let uv_w = w / 2;
                let uv_h = h / 2;
                let u_base = bpl * h;
                let v_base = u_base + uv_bpl * uv_h;
                bytes_used = v_base + uv_bpl * uv_h;

                if dst.len() >= bytes_used {
                    for row in 0..h {
                        let src_start = row * w;
                        let dst_start = row * bpl;
                        dst[dst_start..dst_start + w]
                            .copy_from_slice(&frame.y[src_start..src_start + w]);
                    }
                    for row in 0..uv_h {
                        let src_start = row * uv_w;
                        let dst_start = u_base + row * uv_bpl;
                        dst[dst_start..dst_start + uv_w]
                            .copy_from_slice(&frame.u[src_start..src_start + uv_w]);
                    }
                    for row in 0..uv_h {
                        let src_start = row * uv_w;
                        let dst_start = v_base + row * uv_bpl;
                        dst[dst_start..dst_start + uv_w]
                            .copy_from_slice(&frame.v[src_start..src_start + uv_w]);
                    }
                }
            }
        } else {
            // NV12
            let uv_w = w / 2;
            let uv_h = h / 2;
            let uv_base = bpl * h;
            bytes_used = uv_base + bpl * uv_h;

            if dst.len() >= bytes_used {
                for row in 0..h {
                    let src_start = row * w;
                    let dst_start = row * bpl;
                    dst[dst_start..dst_start + w]
                        .copy_from_slice(&frame.y[src_start..src_start + w]);
                }
                for row in 0..uv_h {
                    let dst_row_start = uv_base + row * bpl;
                    let src_uv_start = row * uv_w;
                    for col in 0..uv_w {
                        dst[dst_row_start + col * 2] = frame.u[src_uv_start + col];
                        dst[dst_row_start + col * 2 + 1] = frame.v[src_uv_start + col];
                    }
                }
            }
        }

        if dst_len < bytes_used {
            self.available_output_indices.push_back(out_idx);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "V4L2 encoder OUTPUT buffer too small for the frame",
            ));
        }

        if let Err(e) = qbuf(
            fd,
            self.output_type,
            self.is_multiplanar,
            out_idx,
            bytes_used as u32,
            out_buf.length,
        ) {
            self.available_output_indices.push_back(out_idx);
            return Err(e);
        }

        // 3. Dequeue encoded H.264 stream from CAPTURE
        let poll_start = Instant::now();
        let (cap_idx, encoded_len) = loop {
            match dqbuf(fd, self.capture_type, self.is_multiplanar) {
                Ok((idx, len, _flags)) => break (idx as usize, len as usize),
                Err(err) => {
                    if err.raw_os_error() != Some(libc::EAGAIN) {
                        return Err(err);
                    }
                    if poll_start.elapsed() > timeout {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "encoder timeout waiting for hardware frame",
                        ));
                    }
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe { libc::poll(&mut pfd, 1, 5) };
                }
            }
        };

        let encoded_bytes = if cap_idx < self.capture_buffers.len() && encoded_len > 0 {
            self.capture_buffers[cap_idx].as_slice()[..encoded_len].to_vec()
        } else {
            Vec::new()
        };

        // Re-queue the CAPTURE buffer for next frame
        let cap_buf_len = self.capture_buffers[cap_idx].length;
        let _ = qbuf(
            fd,
            self.capture_type,
            self.is_multiplanar,
            cap_idx as u32,
            0,
            cap_buf_len,
        );

        Ok(encoded_bytes)
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    #[inline]
    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }
}

impl Drop for V4l2M2mEncoder {
    fn drop(&mut self) {
        let fd = self.file.as_raw_fd();
        let mut out_type = self.output_type as libc::c_int;
        let mut cap_type = self.capture_type as libc::c_int;
        let _ = xioctl(fd, VIDIOC_STREAMOFF, &mut out_type);
        let _ = xioctl(fd, VIDIOC_STREAMOFF, &mut cap_type);
    }
}

/// Splits an Annex-B byte stream into individual NAL units (without start codes).
pub fn split_annex_b_nals(data: &[u8]) -> Vec<&[u8]> {
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

/// Extracts SPS (`7`) and PPS (`8`) NAL units from an Annex-B buffer with `00 00 00 01` start codes.
pub fn extract_sps_pps_annex_b(data: &[u8]) -> Vec<u8> {
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

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v4l2_struct_sizes() {
        assert_eq!(std::mem::size_of::<v4l2_capability>(), 104);
        assert_eq!(std::mem::size_of::<v4l2_fmtdesc>(), 64);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(std::mem::size_of::<v4l2_format>(), 208);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(std::mem::size_of::<v4l2_format>(), 204);
        assert_eq!(std::mem::size_of::<v4l2_plane_pix_format>(), 20);
        assert_eq!(std::mem::size_of::<v4l2_pix_format_mplane>(), 192);
        assert_eq!(std::mem::size_of::<v4l2_requestbuffers>(), 20);
        assert_eq!(std::mem::size_of::<v4l2_control>(), 8);
        assert_eq!(std::mem::size_of::<v4l2_event_subscription>(), 32);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(std::mem::size_of::<v4l2_event>(), 136);
            assert_eq!(std::mem::size_of::<v4l2_buffer>(), 88);
            assert_eq!(std::mem::size_of::<v4l2_plane>(), 64);
        }
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(std::mem::size_of::<v4l2_buffer>(), 68);
            assert_eq!(std::mem::size_of::<v4l2_plane>(), 60);
        }
    }

    #[test]
    fn test_v4l2_format_offsets() {
        let dummy = v4l2_format::default();
        let base = &dummy as *const _ as usize;
        let fmt_offset = std::ptr::addr_of!(dummy.fmt) as usize - base;
        let pix_w_offset = unsafe { std::ptr::addr_of!(dummy.fmt.pix.width) as usize } - base;
        let pix_mp_w_offset = unsafe { std::ptr::addr_of!(dummy.fmt.pix_mp.width) as usize } - base;

        let expected = std::mem::align_of::<usize>().max(4);
        assert_eq!(fmt_offset, expected);
        assert_eq!(pix_w_offset, expected);
        assert_eq!(pix_mp_w_offset, expected);
    }

    #[test]
    fn test_v4l2_ioctl_values() {
        assert_eq!(VIDIOC_QUERYCAP, 0x80685600);
        assert_eq!(VIDIOC_ENUM_FMT, 0xc0405602);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(VIDIOC_G_FMT, 0xc0d05604);
            assert_eq!(VIDIOC_S_FMT, 0xc0d05605);
        }
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(VIDIOC_G_FMT, 0xc0cc5604);
            assert_eq!(VIDIOC_S_FMT, 0xc0cc5605);
        }
        assert_eq!(VIDIOC_REQBUFS, 0xc0145608);
        assert_eq!(VIDIOC_STREAMON, 0x40045612);
        assert_eq!(VIDIOC_STREAMOFF, 0x40045613);
        assert_eq!(VIDIOC_S_CTRL, 0xc008561c);
        assert_eq!(VIDIOC_SUBSCRIBE_EVENT, 0x4020565a);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(VIDIOC_DQEVENT, 0x80885659);
            assert_eq!(VIDIOC_QUERYBUF, 0xc0585609);
            assert_eq!(VIDIOC_QBUF, 0xc058560f);
            assert_eq!(VIDIOC_DQBUF, 0xc0585611);
        }
        #[cfg(target_pointer_width = "32")]
        {
            assert_eq!(VIDIOC_QUERYBUF, 0xc0445609);
            assert_eq!(VIDIOC_QBUF, 0xc044560f);
            assert_eq!(VIDIOC_DQBUF, 0xc0445611);
        }
    }

    #[test]
    fn test_v4l2_fourcc_codes() {
        assert_eq!(V4L2_PIX_FMT_H264, 0x34363248);
        assert_eq!(V4L2_PIX_FMT_YUV420, 0x32315559);
        assert_eq!(V4L2_PIX_FMT_NV12, 0x3231564E);
    }

    #[test]
    fn test_probe_v4l2_codec_devices_handles_nonexistent() {
        let res = probe_v4l2_codec_devices(
            Some("/dev/nonexistent_video_dec"),
            Some("/dev/nonexistent_video_enc"),
        );
        assert!(res.is_none());
    }
}
