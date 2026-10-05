//! V4L2 `VIDIOC_*` ioctl surface and MMAP streaming buffers for
//! `/dev/video<N>`.
//!
//! This is the ioctl/mmap half of the camera bridge; the byte-stream
//! `read()` path lives in [`crate::devfs_bridge`]. Together they let real
//! userspace (libv4l / ffmpeg / gstreamer / Chrome) negotiate a format,
//! allocate `V4L2_MEMORY_MMAP` buffers, map them, and queue/dequeue frames.
//!
//! ## What is implemented
//!
//! - `VIDIOC_QUERYCAP` — capabilities (`VIDEO_CAPTURE | STREAMING | ...`).
//! - `VIDIOC_ENUM_FMT` / `ENUM_FRAMESIZES` / `ENUM_FRAMEINTERVALS`.
//! - `VIDIOC_G_FMT` / `S_FMT` / `TRY_FMT` (single-planar capture).
//! - `VIDIOC_REQBUFS` / `QUERYBUF` / `QBUF` / `DQBUF` (MMAP memory).
//! - `VIDIOC_STREAMON` / `STREAMOFF`.
//! - `VIDIOC_G_PARM` / `S_PARM` (capture frame interval).
//! - `VIDIOC_G_CTRL` / `S_CTRL` / `QUERYCTRL`.
//! - `VIDIOC_ENUMINPUT` / `G_INPUT` / `S_INPUT`.
//!
//! ## Linux reference (validated against `/usr/src/linux` v7.0.0-rc3)
//!
//! - `include/uapi/linux/videodev2.h` — ioctl numbers and struct layouts.
//! - `include/uapi/asm-generic/ioctl.h` — `_IOC` bit encoding.
//! - `drivers/media/v4l2-core/v4l2-ioctl.c::video_usercopy` — the
//!   copy-in / handle / copy-out flow and `_IOC_SIZE`-bounded copies that
//!   [`dispatch`] mirrors.
//! - `drivers/media/common/videobuf2/videobuf2-core.c` — REQBUFS/QBUF/DQBUF
//!   buffer-state machine and the "EBUSY while mapped" rule.
//! - `drivers/media/usb/uvc/uvc_v4l2.c` — the UVC capture ioctl semantics.
//!
//! ## Errno fidelity
//!
//! ioctl-level failures return a Linux errno as a negative value cast to
//! `u64` (the syscall return convention), matching the ALSA bridge
//! (`drivers/sound/src/alsa/control.rs`). Genuine user-pointer faults from
//! `ctx.read`/`ctx.write` propagate as [`FsError::BadAddress`] (→ `EFAULT`).
//! All errno numbers below are the `asm-generic` values Linux uses.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_filesystem::{FsError, FsFuture, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::frame::{alloc_frame, free_frame, PhysFrame};

use crate::devfs_bridge::VideoDevice;

// ── Linux errno values (asm-generic/errno-base.h, errno.h) ─────────────────

const EINTR: i64 = 4;
const EAGAIN: i64 = 11;
const EBUSY: i64 = 16;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const ENOSPC: i64 = 28;

/// Encode a negative errno as the `u64` ioctl return value.
#[inline]
fn errno(e: i64) -> u64 {
    (-e) as u64
}

// ── `_IOC` encoding (asm-generic/ioctl.h) ──────────────────────────────────

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

/// Direction bits: userspace writes (kernel copies in).
const IOC_WRITE: u32 = 1;
/// Direction bits: userspace reads (kernel copies out).
const IOC_READ: u32 = 2;

#[inline]
fn ioc_type(cmd: u32) -> u32 {
    (cmd >> IOC_TYPESHIFT) & ((1 << IOC_TYPEBITS) - 1)
}
#[inline]
fn ioc_nr(cmd: u32) -> u32 {
    (cmd >> IOC_NRSHIFT) & ((1 << IOC_NRBITS) - 1)
}
#[inline]
fn ioc_size(cmd: u32) -> usize {
    ((cmd >> IOC_SIZESHIFT) & ((1 << IOC_SIZEBITS) - 1)) as usize
}
#[inline]
fn ioc_dir(cmd: u32) -> u32 {
    (cmd >> IOC_DIRSHIFT) & 0x3
}

/// V4L2 ioctl magic: `'V'`.
const V4L2_IOC_MAGIC: u32 = b'V' as u32;

/// Upper bound on a single ioctl's kernel staging buffer. The largest V4L2
/// capture struct is `v4l2_format` at 208 bytes; 256 leaves headroom.
const MAX_IOCTL_BUF: usize = 256;

// ── VIDIOC_* numbers (videodev2.h) ─────────────────────────────────────────

const VIDIOC_QUERYCAP: u32 = 0;
const VIDIOC_ENUM_FMT: u32 = 2;
const VIDIOC_G_FMT: u32 = 4;
const VIDIOC_S_FMT: u32 = 5;
const VIDIOC_REQBUFS: u32 = 8;
const VIDIOC_QUERYBUF: u32 = 9;
const VIDIOC_QBUF: u32 = 15;
const VIDIOC_DQBUF: u32 = 17;
const VIDIOC_STREAMON: u32 = 18;
const VIDIOC_STREAMOFF: u32 = 19;
const VIDIOC_G_PARM: u32 = 21;
const VIDIOC_S_PARM: u32 = 22;
const VIDIOC_ENUMINPUT: u32 = 26;
const VIDIOC_G_CTRL: u32 = 27;
const VIDIOC_S_CTRL: u32 = 28;
const VIDIOC_QUERYCTRL: u32 = 36;
const VIDIOC_G_INPUT: u32 = 38;
const VIDIOC_S_INPUT: u32 = 39;
const VIDIOC_TRY_FMT: u32 = 64;
const VIDIOC_ENUM_FRAMESIZES: u32 = 74;
const VIDIOC_ENUM_FRAMEINTERVALS: u32 = 75;

// ── V4L2 enums / flags (videodev2.h) ───────────────────────────────────────

const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
const V4L2_MEMORY_MMAP: u32 = 1;
const V4L2_FIELD_NONE: u32 = 1;
const V4L2_COLORSPACE_SRGB: u32 = 8;

const V4L2_CAP_VIDEO_CAPTURE: u32 = 0x0000_0001;
const V4L2_CAP_READWRITE: u32 = 0x0100_0000;
const V4L2_CAP_STREAMING: u32 = 0x0400_0000;
const V4L2_CAP_EXT_PIX_FORMAT: u32 = 0x0020_0000;
const V4L2_CAP_DEVICE_CAPS: u32 = 0x8000_0000;

const V4L2_FMT_FLAG_COMPRESSED: u32 = 0x0001;

const V4L2_BUF_FLAG_MAPPED: u32 = 0x0000_0001;
const V4L2_BUF_FLAG_QUEUED: u32 = 0x0000_0002;
const V4L2_BUF_FLAG_DONE: u32 = 0x0000_0004;
const V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC: u32 = 0x0000_2000;

const V4L2_BUF_CAP_SUPPORTS_MMAP: u32 = 0x0000_0001;

/// `v4l2_captureparm.capability` — `V4L2_CAP_TIMEPERFRAME`.
const V4L2_CAP_TIMEPERFRAME: u32 = 0x1000;

const V4L2_FRMSIZE_TYPE_DISCRETE: u32 = 1;
const V4L2_FRMIVAL_TYPE_DISCRETE: u32 = 1;

const V4L2_INPUT_TYPE_CAMERA: u32 = 2;

const V4L2_CTRL_TYPE_INTEGER: u32 = 1;
const V4L2_CTRL_FLAG_NEXT_CTRL: u32 = 0x8000_0000;

// Control IDs (v4l2-controls.h): V4L2_CTRL_CLASS_USER | 0x900.
const V4L2_CID_BASE: u32 = 0x0098_0900;
const V4L2_CID_BRIGHTNESS: u32 = V4L2_CID_BASE;
const V4L2_CID_CONTRAST: u32 = V4L2_CID_BASE + 1;
const V4L2_CID_SATURATION: u32 = V4L2_CID_BASE + 2;
const V4L2_CID_GAIN: u32 = V4L2_CID_BASE + 19;

/// Linux `KERNEL_VERSION(a, b, c)` (Makefile): `(a << 16) + (b << 8) + c`.
const fn kernel_version(a: u32, b: u32, c: u32) -> u32 {
    (a << 16) + (b << 8) + c
}
/// `KERNEL_VERSION(7, 0, 0)` — reported in `v4l2_capability.version`.
const V4L2_VERSION: u32 = kernel_version(7, 0, 0);

// FourCCs (videodev2.h `v4l2_fourcc`).
const fn fourcc(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}
const V4L2_PIX_FMT_YUYV: u32 = fourcc(b'Y', b'U', b'Y', b'V');
const V4L2_PIX_FMT_MJPEG: u32 = fourcc(b'M', b'J', b'P', b'G');
const V4L2_PIX_FMT_NV12: u32 = fourcc(b'N', b'V', b'1', b'2');

/// Page size for buffer backing.
const PAGE: usize = 4096;

// ── Struct sizes (64-bit UAPI layout, videodev2.h) ─────────────────────────
//
// These are compile-time guards: if a layout assumption drifts from the
// Linux UAPI the build fails here rather than silently corrupting copies.
// `v4l2_format` / `v4l2_streamparm` carry a 200-byte union; the former rounds
// to 208 because `v4l2_window` (a union member) holds pointers and forces
// 8-byte alignment, pushing `fmt.pix` to offset 8.

const SZ_CAPABILITY: usize = 104;
const SZ_FMTDESC: usize = 64;
const SZ_FORMAT: usize = 208;
const SZ_REQUESTBUFFERS: usize = 20;
const SZ_BUFFER: usize = 88;
const SZ_STREAMPARM: usize = 204;
const SZ_FRMSIZEENUM: usize = 44;
const SZ_FRMIVALENUM: usize = 52;
const SZ_CONTROL: usize = 8;
const SZ_QUERYCTRL: usize = 68;
const SZ_INPUT: usize = 80;

const _: () = assert!(SZ_CAPABILITY == 104);
const _: () = assert!(SZ_FMTDESC == 64);
const _: () = assert!(SZ_FORMAT == 208);
const _: () = assert!(SZ_REQUESTBUFFERS == 20);
const _: () = assert!(SZ_BUFFER == 88);
const _: () = assert!(SZ_STREAMPARM == 204);
const _: () = assert!(SZ_FRMSIZEENUM == 44);
const _: () = assert!(SZ_FRMIVALENUM == 52);
const _: () = assert!(SZ_CONTROL == 8);
const _: () = assert!(SZ_QUERYCTRL == 68);
const _: () = assert!(SZ_INPUT == 80);

/// Kernel staging-buffer size for a given request number. The dispatcher
/// allocates `max(_IOC_SIZE(cmd), this)` so handlers can index their struct's
/// fixed offsets even if userspace declared a shorter (older-ABI) struct.
fn struct_size(nr: u32) -> usize {
    match nr {
        VIDIOC_QUERYCAP => SZ_CAPABILITY,
        VIDIOC_ENUM_FMT => SZ_FMTDESC,
        VIDIOC_G_FMT | VIDIOC_S_FMT | VIDIOC_TRY_FMT => SZ_FORMAT,
        VIDIOC_REQBUFS => SZ_REQUESTBUFFERS,
        VIDIOC_QUERYBUF | VIDIOC_QBUF | VIDIOC_DQBUF => SZ_BUFFER,
        VIDIOC_STREAMON | VIDIOC_STREAMOFF | VIDIOC_G_INPUT | VIDIOC_S_INPUT => 4,
        VIDIOC_G_PARM | VIDIOC_S_PARM => SZ_STREAMPARM,
        VIDIOC_G_CTRL | VIDIOC_S_CTRL => SZ_CONTROL,
        VIDIOC_QUERYCTRL => SZ_QUERYCTRL,
        VIDIOC_ENUMINPUT => SZ_INPUT,
        VIDIOC_ENUM_FRAMESIZES => SZ_FRMSIZEENUM,
        VIDIOC_ENUM_FRAMEINTERVALS => SZ_FRMIVALENUM,
        _ => 0,
    }
}

// ── Native-endian field accessors ──────────────────────────────────────────
//
// Userspace and kernel share the host arch, so V4L2 structs are native-endian
// (matching Linux, which copies them verbatim).

#[inline]
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[inline]
fn wr_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_ne_bytes());
}
#[inline]
fn wr_i32(b: &mut [u8], o: usize, v: i32) {
    b[o..o + 4].copy_from_slice(&v.to_ne_bytes());
}
#[inline]
fn wr_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_ne_bytes());
}
#[inline]
fn rd_i32(b: &[u8], o: usize) -> i32 {
    i32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
/// Write a NUL-terminated, NUL-padded fixed-width C string.
fn wr_cstr(b: &mut [u8], o: usize, cap: usize, s: &str) {
    for i in 0..cap {
        b[o + i] = 0;
    }
    let bytes = s.as_bytes();
    let n = bytes.len().min(cap - 1);
    b[o..o + n].copy_from_slice(&bytes[..n]);
}

// ── Device state types (embedded in VideoDevice) ───────────────────────────

/// Negotiated single-planar capture format (`v4l2_pix_format`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PixFormat {
    pub width: u32,
    pub height: u32,
    pub fourcc: u32,
}

impl PixFormat {
    /// Bytes per image line, 0 for compressed formats (`v4l2_pix_format`).
    pub fn bytesperline(&self) -> u32 {
        match self.fourcc {
            V4L2_PIX_FMT_YUYV => self.width * 2,
            V4L2_PIX_FMT_NV12 => self.width,
            _ => 0, // MJPEG and other compressed formats
        }
    }

    /// Maximum image size in bytes (`v4l2_pix_format.sizeimage`).
    pub fn sizeimage(&self) -> u32 {
        match self.fourcc {
            V4L2_PIX_FMT_YUYV => self.width * self.height * 2,
            V4L2_PIX_FMT_NV12 => self.width * self.height * 3 / 2,
            // Compressed: upper bound at 2 bytes/pixel.
            _ => self.width * self.height * 2,
        }
    }
}

/// A supported discrete resolution plus its frame intervals (seconds/frame).
#[derive(Clone, Debug)]
pub struct FrameSize {
    pub width: u32,
    pub height: u32,
    /// `(numerator, denominator)` seconds-per-frame, e.g. `(1, 30)` = 30 fps.
    pub intervals: Vec<(u32, u32)>,
}

/// A supported pixel format for `VIDIOC_ENUM_FMT`.
#[derive(Clone, Debug)]
pub struct FmtEntry {
    pub fourcc: u32,
    pub description: String,
    pub compressed: bool,
    pub sizes: Vec<FrameSize>,
}

/// A controllable parameter (`v4l2_queryctrl` + current value).
#[derive(Copy, Clone, Debug)]
pub struct ControlState {
    pub id: u32,
    pub name: &'static str,
    pub min: i32,
    pub max: i32,
    pub step: i32,
    pub default: i32,
    pub value: i32,
}

/// Queue state of one MMAP buffer (`videobuf2-core.c`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QState {
    /// Owned by userspace (`DQBUF`'d or freshly `REQBUFS`'d).
    Dequeued,
    /// Handed to the driver (`QBUF`'d), awaiting capture.
    Queued,
    /// Filled by the driver, awaiting `DQBUF`.
    Done,
}

/// One `V4L2_MEMORY_MMAP` capture buffer, backing a user mapping.
#[derive(Debug)]
pub struct V4l2Buffer {
    /// Physical frames backing this buffer, in order. Device-owned: freed on
    /// `REQBUFS(0)` / reset, never on `munmap`.
    pub frames: Vec<PhysFrame>,
    /// Usable byte length (page-rounded `sizeimage`).
    pub length: u32,
    /// `mmap()` offset cookie reported in `v4l2_buffer.m.offset`.
    pub mmap_offset: u32,
    /// Bytes filled by the last capture into this buffer.
    pub bytesused: u32,
    /// Capture sequence number stamped at DQBUF.
    pub sequence: u32,
    /// Queue state.
    pub state: QState,
    /// `true` while userspace holds a mapping (blocks `REQBUFS` reuse).
    pub mapped: bool,
}

impl V4l2Buffer {
    /// Copy up to `length` bytes of `data` into the buffer's physical frames.
    /// Returns the number of bytes written (`bytesused`).
    fn fill(&mut self, data: &[u8]) -> u32 {
        let mut remaining = data.len().min(self.length as usize);
        let total = remaining;
        let mut src = 0usize;
        for frame in &self.frames {
            if remaining == 0 {
                break;
            }
            let n = remaining.min(PAGE);
            let dst = frame.start_address().kernel_mut_ptr::<u8>();
            // SAFETY: `frame` is a 4 KiB frame this buffer owns; its direct-map
            // pointer is a valid, writable kernel VA for the whole page, and
            // `n <= PAGE`. Source and destination do not overlap.
            unsafe {
                core::ptr::copy_nonoverlapping(data[src..].as_ptr(), dst, n);
            }
            src += n;
            remaining -= n;
        }
        total as u32
    }
}

// ── Default device capabilities ────────────────────────────────────────────

/// Default format table for a camera that has not published real descriptors
/// yet: YUYV 640×480 / 1280×720 and MJPEG 1280×720 / 1920×1080, all at 30 fps.
pub fn default_formats() -> Vec<FmtEntry> {
    vec![
        FmtEntry {
            fourcc: V4L2_PIX_FMT_YUYV,
            description: String::from("YUYV 4:2:2"),
            compressed: false,
            sizes: vec![
                FrameSize {
                    width: 640,
                    height: 480,
                    intervals: vec![(1, 30), (1, 15)],
                },
                FrameSize {
                    width: 1280,
                    height: 720,
                    intervals: vec![(1, 30)],
                },
            ],
        },
        FmtEntry {
            fourcc: V4L2_PIX_FMT_MJPEG,
            description: String::from("Motion-JPEG"),
            compressed: true,
            sizes: vec![
                FrameSize {
                    width: 1280,
                    height: 720,
                    intervals: vec![(1, 30)],
                },
                FrameSize {
                    width: 1920,
                    height: 1080,
                    intervals: vec![(1, 30)],
                },
            ],
        },
    ]
}

/// Default user controls (brightness/contrast/saturation/gain).
pub fn default_controls() -> Vec<ControlState> {
    vec![
        ControlState {
            id: V4L2_CID_BRIGHTNESS,
            name: "Brightness",
            min: -64,
            max: 64,
            step: 1,
            default: 0,
            value: 0,
        },
        ControlState {
            id: V4L2_CID_CONTRAST,
            name: "Contrast",
            min: 0,
            max: 64,
            step: 1,
            default: 32,
            value: 32,
        },
        ControlState {
            id: V4L2_CID_SATURATION,
            name: "Saturation",
            min: 0,
            max: 128,
            step: 1,
            default: 64,
            value: 64,
        },
        ControlState {
            id: V4L2_CID_GAIN,
            name: "Gain",
            min: 0,
            max: 100,
            step: 1,
            default: 0,
            value: 0,
        },
    ]
}

/// Initial format: first size of the first default format (YUYV 640×480).
pub fn default_pix_format() -> PixFormat {
    PixFormat {
        width: 640,
        height: 480,
        fourcc: V4L2_PIX_FMT_YUYV,
    }
}

// ── mmap integration ───────────────────────────────────────────────────────

/// Resolve an `mmap()` offset cookie to the physical frames of the matching
/// buffer, marking it mapped. Returns one phys address per page.
///
/// Mirrors `vb2_mmap` → `__vb2_queue_alloc`: the offset selects the buffer and
/// the frames are aliased *borrowed* into the caller (never freed on munmap).
pub fn mmap_buffer_frames(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    offset: u64,
    len: usize,
) -> Result<Vec<u64>, FsError> {
    let mut g = dev.lock();
    let buf = g
        .buffers
        .iter_mut()
        .find(|b| b.mmap_offset as u64 == offset)
        .ok_or(FsError::InvalidData)?;
    if len > buf.frames.len() * PAGE {
        return Err(FsError::InvalidData);
    }
    buf.mapped = true;
    let pages = len.div_ceil(PAGE);
    Ok(buf
        .frames
        .iter()
        .take(pages)
        .map(|f| f.start_address().raw())
        .collect())
}

/// Free every buffer's frames and clear the pool. Called from `REQBUFS(0)` and
/// when the device is torn down.
pub fn free_buffer_pool(buffers: &mut Vec<V4l2Buffer>) {
    for buf in buffers.drain(..) {
        for frame in buf.frames {
            free_frame(frame);
        }
    }
}

// ── ioctl dispatch (video_usercopy model) ──────────────────────────────────

/// Handle one `VIDIOC_*` ioctl against `dev`.
///
/// Mirrors `video_usercopy`: copy the `_IOC_SIZE(cmd)` user struct into a
/// kernel staging buffer (when the command carries a write direction), run the
/// handler against it, then copy it back out (when the command carries a read
/// direction and the handler succeeded).
///
/// Returns `Ok(0)` on success, `Ok(-errno as u64)` for a V4L2-level failure,
/// or propagates [`FsError::BadAddress`] (→ `EFAULT`) on a user-pointer fault.
pub fn dispatch<'a>(
    dev: Arc<IrqSafeSpinLock<VideoDevice>>,
    cmd: u32,
    arg: u64,
    ctx: &'a dyn IoctlContext,
) -> FsFuture<'a, u64> {
    Box::pin(async move {
        if ioc_type(cmd) != V4L2_IOC_MAGIC {
            return Ok(errno(ENOTTY));
        }
        let nr = ioc_nr(cmd);
        let need = struct_size(nr);
        if need == 0 {
            // Known magic but unimplemented request → ENOTTY, as the v4l2 core
            // returns for an op the driver does not provide.
            return Ok(errno(ENOTTY));
        }

        // Stage buffer large enough for our fixed field offsets, but copy only
        // the user-declared `_IOC_SIZE` so an older/smaller ABI is not overrun.
        let csize = ioc_size(cmd).min(MAX_IOCTL_BUF);
        let dir = ioc_dir(cmd);
        let mut buf = vec![0u8; need.max(csize)];
        if dir & IOC_WRITE != 0 && csize > 0 {
            ctx.read(arg, &mut buf[..csize])?;
        }

        let ret = handle(&dev, nr, &mut buf, ctx.nonblocking()).await?;

        if ret == 0 && dir & IOC_READ != 0 && csize > 0 {
            ctx.write(arg, &buf[..csize])?;
        }
        Ok(ret)
    })
}

/// Run one request against the staging buffer `b`, which has already been
/// copied in (if the command carries a write direction). The handler fills `b`
/// in place for copy-out.
async fn handle(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    nr: u32,
    b: &mut [u8],
    nonblocking: bool,
) -> Result<u64, FsError> {
    Ok(match nr {
        VIDIOC_QUERYCAP => query_cap(dev, b),
        VIDIOC_ENUM_FMT => enum_fmt(dev, b),
        VIDIOC_G_FMT => g_fmt(dev, b),
        VIDIOC_S_FMT => s_fmt(dev, b, true),
        VIDIOC_TRY_FMT => s_fmt(dev, b, false),
        VIDIOC_ENUM_FRAMESIZES => enum_framesizes(dev, b),
        VIDIOC_ENUM_FRAMEINTERVALS => enum_frameintervals(dev, b),
        VIDIOC_REQBUFS => reqbufs(dev, b),
        VIDIOC_QUERYBUF => querybuf(dev, b),
        VIDIOC_QBUF => qbuf(dev, b),
        VIDIOC_DQBUF => dqbuf(dev, b, nonblocking).await,
        VIDIOC_STREAMON => streamon(dev, b, true),
        VIDIOC_STREAMOFF => streamon(dev, b, false),
        VIDIOC_G_PARM | VIDIOC_S_PARM => g_parm(dev, b),
        VIDIOC_G_CTRL => g_ctrl(dev, b),
        VIDIOC_S_CTRL => s_ctrl(dev, b),
        VIDIOC_QUERYCTRL => queryctrl(dev, b),
        VIDIOC_ENUMINPUT => enuminput(b),
        VIDIOC_G_INPUT => g_input(b),
        VIDIOC_S_INPUT => s_input(b),
        _ => errno(ENOTTY),
    })
}

fn query_cap(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let (name, idx) = {
        let g = dev.lock();
        (g.name.clone(), g.index)
    };
    wr_cstr(b, 0, 16, "narf-uvc"); // driver[16]
    wr_cstr(b, 16, 32, &name); // card[32]
    let bus = alloc::format!("usb-narf-{}", idx);
    wr_cstr(b, 48, 32, &bus); // bus_info[32]
    wr_u32(b, 80, V4L2_VERSION); // version
    let caps = V4L2_CAP_VIDEO_CAPTURE
        | V4L2_CAP_STREAMING
        | V4L2_CAP_READWRITE
        | V4L2_CAP_EXT_PIX_FORMAT
        | V4L2_CAP_DEVICE_CAPS;
    wr_u32(b, 84, caps); // capabilities
    wr_u32(b, 88, caps & !V4L2_CAP_DEVICE_CAPS); // device_caps
    0
}

fn enum_fmt(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let index = rd_u32(b, 0) as usize;
    if rd_u32(b, 4) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    let g = dev.lock();
    let Some(fmt) = g.formats.get(index) else {
        return errno(EINVAL);
    };
    wr_u32(
        b,
        8,
        if fmt.compressed {
            V4L2_FMT_FLAG_COMPRESSED
        } else {
            0
        },
    ); // flags
    wr_cstr(b, 12, 32, &fmt.description); // description[32]
    wr_u32(b, 44, fmt.fourcc); // pixelformat
    wr_u32(b, 48, 0); // mbus_code
    0
}

/// Write the `v4l2_pix_format` prefix of a `v4l2_format` buffer.
///
/// `fmt.pix` begins at **offset 8**, not 4: the `v4l2_format` union is
/// 8-byte aligned because `v4l2_window` (a union member) holds pointers, so
/// the `__u32 type` is followed by 4 bytes of padding.
fn write_pix_format(b: &mut [u8], fmt: &PixFormat) {
    wr_u32(b, 0, V4L2_BUF_TYPE_VIDEO_CAPTURE); // type
    wr_u32(b, 8, fmt.width); // pix.width
    wr_u32(b, 12, fmt.height); // pix.height
    wr_u32(b, 16, fmt.fourcc); // pix.pixelformat
    wr_u32(b, 20, V4L2_FIELD_NONE); // pix.field
    wr_u32(b, 24, fmt.bytesperline()); // pix.bytesperline
    wr_u32(b, 28, fmt.sizeimage()); // pix.sizeimage
    wr_u32(b, 32, V4L2_COLORSPACE_SRGB); // pix.colorspace
}

fn g_fmt(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    let fmt = dev.lock().format;
    for byte in b.iter_mut() {
        *byte = 0;
    }
    write_pix_format(b, &fmt);
    0
}

/// Resolve a requested (fourcc,w,h) to the closest supported format.
fn resolve_format(formats: &[FmtEntry], fourcc: u32, w: u32, h: u32) -> PixFormat {
    let entry = formats
        .iter()
        .find(|f| f.fourcc == fourcc)
        .or_else(|| formats.first());
    let Some(entry) = entry else {
        return PixFormat {
            width: w.max(1),
            height: h.max(1),
            fourcc,
        };
    };
    // Pick the discrete size with the smallest area distance to the request.
    let best = entry.sizes.iter().min_by_key(|s| {
        let dw = (s.width as i64 - w as i64).abs();
        let dh = (s.height as i64 - h as i64).abs();
        dw + dh
    });
    match best {
        Some(s) => PixFormat {
            width: s.width,
            height: s.height,
            fourcc: entry.fourcc,
        },
        None => PixFormat {
            width: w.max(1),
            height: h.max(1),
            fourcc: entry.fourcc,
        },
    }
}

fn s_fmt(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8], commit: bool) -> u64 {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    // pix fields begin at offset 8 (union is 8-byte aligned; see
    // `write_pix_format`).
    let req_w = rd_u32(b, 8);
    let req_h = rd_u32(b, 12);
    let req_fourcc = rd_u32(b, 16);
    let mut g = dev.lock();
    // S_FMT is not allowed while buffers are allocated (vb2: EBUSY).
    if commit && !g.buffers.is_empty() {
        return errno(EBUSY);
    }
    let adjusted = resolve_format(&g.formats, req_fourcc, req_w, req_h);
    if commit {
        g.format = adjusted;
    }
    drop(g);
    for byte in b.iter_mut() {
        *byte = 0;
    }
    write_pix_format(b, &adjusted);
    0
}

fn enum_framesizes(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let index = rd_u32(b, 0) as usize;
    let pixfmt = rd_u32(b, 4);
    let g = dev.lock();
    let Some(entry) = g.formats.iter().find(|f| f.fourcc == pixfmt) else {
        return errno(EINVAL);
    };
    let Some(size) = entry.sizes.get(index) else {
        return errno(EINVAL);
    };
    wr_u32(b, 8, V4L2_FRMSIZE_TYPE_DISCRETE); // type
    wr_u32(b, 12, size.width); // discrete.width
    wr_u32(b, 16, size.height); // discrete.height
    0
}

fn enum_frameintervals(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let index = rd_u32(b, 0) as usize;
    let pixfmt = rd_u32(b, 4);
    let w = rd_u32(b, 8);
    let h = rd_u32(b, 12);
    let g = dev.lock();
    let Some(entry) = g.formats.iter().find(|f| f.fourcc == pixfmt) else {
        return errno(EINVAL);
    };
    let Some(size) = entry.sizes.iter().find(|s| s.width == w && s.height == h) else {
        return errno(EINVAL);
    };
    let Some(&(num, den)) = size.intervals.get(index) else {
        return errno(EINVAL);
    };
    wr_u32(b, 16, V4L2_FRMIVAL_TYPE_DISCRETE); // type
    wr_u32(b, 20, num); // discrete.numerator
    wr_u32(b, 24, den); // discrete.denominator
    0
}

fn reqbufs(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let mut count = rd_u32(b, 0);
    let btype = rd_u32(b, 4);
    let memory = rd_u32(b, 8);
    if btype != V4L2_BUF_TYPE_VIDEO_CAPTURE || memory != V4L2_MEMORY_MMAP {
        return errno(EINVAL);
    }
    let mut g = dev.lock();
    // Cannot reconfigure while any buffer is still mapped (vb2: EBUSY).
    if g.buffers.iter().any(|buf| buf.mapped) {
        return errno(EBUSY);
    }
    free_buffer_pool(&mut g.buffers);
    g.streaming = false;

    if count > 0 {
        // Clamp to a sane maximum (vb2 caps at VB2_MAX_FRAME = 32).
        count = count.min(32);
        let sizeimage = g.format.sizeimage() as usize;
        let pages = sizeimage.div_ceil(PAGE).max(1);
        let buf_bytes = (pages * PAGE) as u32;
        for i in 0..count as usize {
            let mut frames = Vec::with_capacity(pages);
            for _ in 0..pages {
                match alloc_frame() {
                    Ok(f) => frames.push(f),
                    Err(_) => {
                        for f in frames {
                            free_frame(f);
                        }
                        free_buffer_pool(&mut g.buffers);
                        return errno(ENOSPC);
                    }
                }
            }
            g.buffers.push(V4l2Buffer {
                frames,
                length: buf_bytes,
                mmap_offset: (i as u32) * buf_bytes,
                bytesused: 0,
                sequence: 0,
                state: QState::Dequeued,
                mapped: false,
            });
        }
    }

    let actual = g.buffers.len() as u32;
    drop(g);
    wr_u32(b, 0, actual); // count
    wr_u32(b, 12, V4L2_BUF_CAP_SUPPORTS_MMAP); // capabilities
    b[16] = 0; // flags (__u8)
    0
}

/// Fill a `v4l2_buffer` (88 B) describing `buf` at `index`.
fn write_buffer_desc(b: &mut [u8], index: u32, buf: &V4l2Buffer) {
    for byte in b.iter_mut().take(SZ_BUFFER) {
        *byte = 0;
    }
    wr_u32(b, 0, index); // index
    wr_u32(b, 4, V4L2_BUF_TYPE_VIDEO_CAPTURE); // type
    wr_u32(b, 8, buf.bytesused); // bytesused
    let mut flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
    if buf.mapped {
        flags |= V4L2_BUF_FLAG_MAPPED;
    }
    match buf.state {
        QState::Queued => flags |= V4L2_BUF_FLAG_QUEUED,
        QState::Done => flags |= V4L2_BUF_FLAG_DONE,
        QState::Dequeued => {}
    }
    wr_u32(b, 12, flags); // flags
    wr_u32(b, 16, V4L2_FIELD_NONE); // field
    wr_u32(b, 56, buf.sequence); // sequence
    wr_u32(b, 60, V4L2_MEMORY_MMAP); // memory
    wr_u32(b, 64, buf.mmap_offset); // m.offset
    wr_u32(b, 72, buf.length); // length
}

fn querybuf(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let index = rd_u32(b, 0) as usize;
    if rd_u32(b, 4) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    let g = dev.lock();
    let Some(buf) = g.buffers.get(index) else {
        return errno(EINVAL);
    };
    write_buffer_desc(b, index as u32, buf);
    0
}

fn qbuf(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let index = rd_u32(b, 0) as usize;
    let btype = rd_u32(b, 4);
    let memory = rd_u32(b, 60);
    if btype != V4L2_BUF_TYPE_VIDEO_CAPTURE || memory != V4L2_MEMORY_MMAP {
        return errno(EINVAL);
    }
    let mut g = dev.lock();
    let Some(buf) = g.buffers.get_mut(index) else {
        return errno(EINVAL);
    };
    // Re-queuing an already-queued buffer is EINVAL (vb2: __vb2_qbuf).
    if buf.state == QState::Queued {
        return errno(EINVAL);
    }
    buf.state = QState::Queued;
    buf.bytesused = 0;
    write_buffer_desc(b, index as u32, buf);
    0
}

/// Try to complete one queued buffer from a pending captured frame. Returns the
/// index of a `Done` buffer ready for dequeue, if any.
fn try_complete_buffer(g: &mut VideoDevice) -> Option<usize> {
    // Already-done buffer? Return the oldest by sequence.
    if let Some((i, _)) = g
        .buffers
        .iter()
        .enumerate()
        .filter(|(_, b)| b.state == QState::Done)
        .min_by_key(|(_, b)| b.sequence)
    {
        return Some(i);
    }
    // Otherwise, pull a frame and fill the first queued buffer.
    let frame = g.pop_frame()?;
    let seq = g.sequence;
    let idx = g.buffers.iter().position(|b| b.state == QState::Queued)?;
    let buf = &mut g.buffers[idx];
    buf.bytesused = buf.fill(&frame.data);
    buf.sequence = seq;
    buf.state = QState::Done;
    g.sequence = g.sequence.wrapping_add(1);
    Some(idx)
}

async fn dqbuf(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8], nonblocking: bool) -> u64 {
    if rd_u32(b, 4) != V4L2_BUF_TYPE_VIDEO_CAPTURE || rd_u32(b, 60) != V4L2_MEMORY_MMAP {
        return errno(EINVAL);
    }
    // Streaming must be active and buffers queued (vb2: EINVAL otherwise).
    {
        let g = dev.lock();
        if !g.streaming || g.buffers.iter().all(|b| b.state == QState::Dequeued) {
            return errno(EINVAL);
        }
    }

    // Loop until a buffer completes. Non-blocking opens get EAGAIN immediately;
    // blocking opens park on the wheel and retry (matches vb2_dqbuf).
    loop {
        {
            let mut g = dev.lock();
            if let Some(idx) = try_complete_buffer(&mut g) {
                // Dequeued state → write_buffer_desc emits flags without
                // QUEUED/DONE (the buffer is now owned by userspace).
                g.buffers[idx].state = QState::Dequeued;
                let (ts_sec, ts_usec) = {
                    let ns = narf_time::monotonic_ns();
                    (ns / 1_000_000_000, (ns % 1_000_000_000) / 1_000)
                };
                write_buffer_desc(b, idx as u32, &g.buffers[idx]);
                wr_u64(b, 24, ts_sec); // timestamp.tv_sec
                wr_u64(b, 32, ts_usec); // timestamp.tv_usec
                return 0;
            }
        }
        if nonblocking {
            return errno(EAGAIN);
        }
        // Park ~2 ms then retry; a captured frame or STREAMOFF wakes progress.
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(2).as_instant()).await;
        if !dev.lock().streaming {
            return errno(EINTR);
        }
    }
}

fn streamon(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8], on: bool) -> u64 {
    // arg points to an `int` buf-type.
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    let mut g = dev.lock();
    if on {
        if g.buffers.is_empty() {
            return errno(EINVAL);
        }
        g.streaming = true;
    } else {
        g.streaming = false;
        // STREAMOFF returns all buffers to the dequeued state and drops any
        // pending captured frames (vb2_streamoff).
        for buf in g.buffers.iter_mut() {
            buf.state = QState::Dequeued;
            buf.bytesused = 0;
        }
        g.clear_frames();
    }
    0
}

fn g_parm(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    // parm.capture begins at offset 4 (union is 4-byte aligned).
    for byte in b.iter_mut() {
        *byte = 0;
    }
    wr_u32(b, 0, V4L2_BUF_TYPE_VIDEO_CAPTURE); // type
    wr_u32(b, 4, V4L2_CAP_TIMEPERFRAME); // capture.capability
    wr_u32(b, 8, 0); // capture.capturemode
    wr_u32(b, 12, 1); // timeperframe.numerator
    wr_u32(b, 16, 30); // timeperframe.denominator (30 fps)
    wr_u32(b, 24, 1); // readbuffers
    let _ = dev;
    0
}

fn g_ctrl(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let id = rd_u32(b, 0);
    let g = dev.lock();
    let Some(c) = g.controls.iter().find(|c| c.id == id) else {
        return errno(EINVAL);
    };
    wr_i32(b, 4, c.value);
    0
}

fn s_ctrl(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let id = rd_u32(b, 0);
    let mut val = rd_i32(b, 4);
    let mut g = dev.lock();
    let Some(c) = g.controls.iter_mut().find(|c| c.id == id) else {
        return errno(EINVAL);
    };
    // Clamp to [min, max] and snap to step, like v4l2 does.
    val = val.clamp(c.min, c.max);
    if c.step > 1 {
        val -= (val - c.min) % c.step;
    }
    c.value = val;
    wr_i32(b, 4, val); // report the clamped value back
    0
}

fn queryctrl(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let raw_id = rd_u32(b, 0);
    let next = raw_id & V4L2_CTRL_FLAG_NEXT_CTRL != 0;
    let id = raw_id & !V4L2_CTRL_FLAG_NEXT_CTRL;
    let g = dev.lock();
    let found = if next {
        // Smallest control id strictly greater than `id` (NEXT_CTRL walk).
        g.controls
            .iter()
            .filter(|c| c.id > id)
            .min_by_key(|c| c.id)
            .copied()
    } else {
        g.controls.iter().find(|c| c.id == id).copied()
    };
    drop(g);
    let Some(c) = found else {
        return errno(EINVAL);
    };
    wr_u32(b, 0, c.id); // id (resolved, for NEXT_CTRL)
    wr_u32(b, 4, V4L2_CTRL_TYPE_INTEGER); // type
    wr_cstr(b, 8, 32, c.name); // name[32]
    wr_i32(b, 40, c.min); // minimum
    wr_i32(b, 44, c.max); // maximum
    wr_i32(b, 48, c.step); // step
    wr_i32(b, 52, c.default); // default_value
    wr_u32(b, 56, 0); // flags
    0
}

fn enuminput(b: &mut [u8]) -> u64 {
    // Single camera input only.
    if rd_u32(b, 0) != 0 {
        return errno(EINVAL);
    }
    wr_cstr(b, 4, 32, "Camera"); // name[32]
    wr_u32(b, 36, V4L2_INPUT_TYPE_CAMERA); // type
    wr_u32(b, 40, 0); // audioset
    wr_u32(b, 44, 0); // tuner
    wr_u64(b, 48, 0); // std (v4l2_std_id)
    wr_u32(b, 56, 0); // status
    wr_u32(b, 60, 0); // capabilities
    0
}

fn g_input(b: &mut [u8]) -> u64 {
    // Current input index is always 0.
    wr_u32(b, 0, 0);
    0
}

fn s_input(b: &mut [u8]) -> u64 {
    if rd_u32(b, 0) != 0 {
        return errno(EINVAL);
    }
    0
}
