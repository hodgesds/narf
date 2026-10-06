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
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, IoctlContext, MmapLifetime, Mode, Stat,
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::frame::{alloc_frame, free_frame, PhysFrame};
use narf_memory::PhysAddr;

use crate::devfs_bridge::VideoDevice;

// ── Linux errno values (asm-generic/errno-base.h, errno.h) ─────────────────

const ENOENT: i64 = 2;
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
const VIDIOC_EXPBUF: u32 = 16;
const VIDIOC_DQBUF: u32 = 17;
const VIDIOC_STREAMON: u32 = 18;
const VIDIOC_STREAMOFF: u32 = 19;
const VIDIOC_G_PARM: u32 = 21;
const VIDIOC_S_PARM: u32 = 22;
const VIDIOC_ENUMINPUT: u32 = 26;
const VIDIOC_G_CTRL: u32 = 27;
const VIDIOC_S_CTRL: u32 = 28;
const VIDIOC_QUERYCTRL: u32 = 36;
const VIDIOC_G_EXT_CTRLS: u32 = 71;
const VIDIOC_S_EXT_CTRLS: u32 = 72;
const VIDIOC_TRY_EXT_CTRLS: u32 = 73;
const VIDIOC_CROPCAP: u32 = 58;
const VIDIOC_G_CROP: u32 = 59;
const VIDIOC_S_CROP: u32 = 60;
const VIDIOC_DQEVENT: u32 = 89;
const VIDIOC_SUBSCRIBE_EVENT: u32 = 90;
const VIDIOC_UNSUBSCRIBE_EVENT: u32 = 91;
const VIDIOC_G_SELECTION: u32 = 94;
const VIDIOC_S_SELECTION: u32 = 95;
const VIDIOC_G_INPUT: u32 = 38;
const VIDIOC_S_INPUT: u32 = 39;
const VIDIOC_TRY_FMT: u32 = 64;
const VIDIOC_ENUM_FRAMESIZES: u32 = 74;
const VIDIOC_ENUM_FRAMEINTERVALS: u32 = 75;

// ── V4L2 enums / flags (videodev2.h) ───────────────────────────────────────

const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
const V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE: u32 = 9;
const V4L2_MEMORY_MMAP: u32 = 1;
const V4L2_MEMORY_USERPTR: u32 = 2;
const V4L2_MEMORY_DMABUF: u32 = 4;
const V4L2_FIELD_NONE: u32 = 1;
const V4L2_COLORSPACE_SRGB: u32 = 8;

const V4L2_CAP_VIDEO_CAPTURE: u32 = 0x0000_0001;
const V4L2_CAP_VIDEO_CAPTURE_MPLANE: u32 = 0x0000_1000;
const V4L2_CAP_READWRITE: u32 = 0x0100_0000;
const V4L2_CAP_STREAMING: u32 = 0x0400_0000;
const V4L2_CAP_EXT_PIX_FORMAT: u32 = 0x0020_0000;
const V4L2_CAP_DEVICE_CAPS: u32 = 0x8000_0000;

const V4L2_FMT_FLAG_COMPRESSED: u32 = 0x0001;

const V4L2_BUF_FLAG_MAPPED: u32 = 0x0000_0001;
const V4L2_BUF_FLAG_QUEUED: u32 = 0x0000_0002;
const V4L2_BUF_FLAG_DONE: u32 = 0x0000_0004;
const V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC: u32 = 0x0000_2000;

const V4L2_BUF_CAP_SUPPORTS_MMAP: u32 = 1 << 0;
const V4L2_BUF_CAP_SUPPORTS_USERPTR: u32 = 1 << 1;
const V4L2_BUF_CAP_SUPPORTS_DMABUF: u32 = 1 << 2;

/// `v4l2_captureparm.capability` — `V4L2_CAP_TIMEPERFRAME`.
const V4L2_CAP_TIMEPERFRAME: u32 = 0x1000;

const V4L2_FRMSIZE_TYPE_DISCRETE: u32 = 1;
const V4L2_FRMIVAL_TYPE_DISCRETE: u32 = 1;

const V4L2_INPUT_TYPE_CAMERA: u32 = 2;

const V4L2_CTRL_TYPE_INTEGER: u32 = 1;
const V4L2_CTRL_FLAG_NEXT_CTRL: u32 = 0x8000_0000;
/// `v4l2_ext_controls.which`: current vs default value set (v4l2-controls.h).
const V4L2_CTRL_WHICH_CUR_VAL: u32 = 0;
const V4L2_CTRL_WHICH_DEF_VAL: u32 = 0x0f00_0000;

// Events (videodev2.h).
const V4L2_EVENT_ALL: u32 = 0;
const V4L2_EVENT_EOS: u32 = 2;
const V4L2_EVENT_CTRL: u32 = 3;
const V4L2_EVENT_CTRL_CH_VALUE: u32 = 1 << 0;
const V4L2_EVENT_SUB_FL_SEND_INITIAL: u32 = 1 << 0;

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

/// `O_CLOEXEC` (x86_64 `asm-generic`): `v4l2_exportbuffer.flags` may carry it.
const O_CLOEXEC: u32 = 0o2_000_000;

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
/// `v4l2_ext_controls` (64-bit): which/count/error_idx/request_fd/reserved then
/// an 8-byte-aligned `controls` pointer at offset 24.
const SZ_EXT_CONTROLS: usize = 32;
/// `v4l2_ext_control` is `__attribute__((packed))`: id/size/reserved2 + an
/// 8-byte union = 20 bytes, no tail padding.
const SZ_EXT_CONTROL: usize = 20;
/// `v4l2_event` (64-bit): type + (8-aligned) 64-byte `u` at offset 8 + pending/
/// sequence + 16-byte timespec at offset 80 + id + reserved[8].
const SZ_EVENT: usize = 136;
/// `v4l2_event_subscription`: type/id/flags/reserved[5].
const SZ_EVENT_SUBSCRIPTION: usize = 32;
/// `v4l2_cropcap`: type + bounds/defrect `v4l2_rect`(16) + pixelaspect fract(8).
const SZ_CROPCAP: usize = 44;
/// `v4l2_crop`: type + `v4l2_rect`.
const SZ_CROP: usize = 20;
/// `v4l2_selection`: type/target/flags + `v4l2_rect` + reserved[9].
const SZ_SELECTION: usize = 64;
/// `v4l2_exportbuffer`: type/index/plane/flags/fd + reserved[11].
const SZ_EXPORTBUFFER: usize = 64;
/// `v4l2_plane` (64-bit): bytesused/length + 8-byte `m` union + data_offset +
/// reserved[11].
const SZ_PLANE: usize = 64;

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
const _: () = assert!(SZ_EXT_CONTROLS == 32);
const _: () = assert!(SZ_EXT_CONTROL == 20);
const _: () = assert!(SZ_EVENT == 136);
const _: () = assert!(SZ_EVENT_SUBSCRIPTION == 32);
const _: () = assert!(SZ_CROPCAP == 44);
const _: () = assert!(SZ_CROP == 20);
const _: () = assert!(SZ_SELECTION == 64);
const _: () = assert!(SZ_EXPORTBUFFER == 64);
const _: () = assert!(SZ_PLANE == 64);

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
        VIDIOC_EXPBUF => SZ_EXPORTBUFFER,
        VIDIOC_STREAMON | VIDIOC_STREAMOFF | VIDIOC_G_INPUT | VIDIOC_S_INPUT => 4,
        VIDIOC_G_PARM | VIDIOC_S_PARM => SZ_STREAMPARM,
        VIDIOC_G_CTRL | VIDIOC_S_CTRL => SZ_CONTROL,
        VIDIOC_QUERYCTRL => SZ_QUERYCTRL,
        VIDIOC_G_EXT_CTRLS | VIDIOC_S_EXT_CTRLS | VIDIOC_TRY_EXT_CTRLS => SZ_EXT_CONTROLS,
        VIDIOC_DQEVENT => SZ_EVENT,
        VIDIOC_SUBSCRIBE_EVENT | VIDIOC_UNSUBSCRIBE_EVENT => SZ_EVENT_SUBSCRIPTION,
        VIDIOC_CROPCAP => SZ_CROPCAP,
        VIDIOC_G_CROP | VIDIOC_S_CROP => SZ_CROP,
        VIDIOC_G_SELECTION | VIDIOC_S_SELECTION => SZ_SELECTION,
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
#[inline]
fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_ne_bytes(a)
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

/// One queued V4L2 event: its type, matching id, running sequence, and the
/// 64-byte `u` payload already laid out for copy-out.
#[derive(Clone, Debug)]
struct EventRecord {
    ev_type: u32,
    id: u32,
    seq: u32,
    payload: [u8; 64],
}

/// Per-open-file event state (`VIDIOC_SUBSCRIBE_EVENT`/`DQEVENT`). Each open
/// file descriptor owns one of these (minted by
/// [`crate::devfs_bridge::VideoFile::open_instance_checked`]), matching Linux's
/// per-`v4l2_fh` event queues.
#[derive(Debug, Default)]
pub struct FdEvents {
    /// Active subscriptions as `(type, id)`.
    subs: Vec<(u32, u32)>,
    /// Pending events, oldest first; bounded to drop the oldest on overflow.
    queue: VecDeque<EventRecord>,
    /// Monotonic per-fd event sequence.
    seq: u32,
}

impl FdEvents {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when at least one event is queued (drives `POLL_PRI`).
    pub fn has_events(&self) -> bool {
        !self.queue.is_empty()
    }

    fn subscribed(&self, ev_type: u32, id: u32) -> bool {
        // CTRL subscriptions are per-control-id; others match on type alone.
        self.subs
            .iter()
            .any(|&(t, i)| t == ev_type && (t != V4L2_EVENT_CTRL || i == id))
    }

    fn enqueue(&mut self, ev_type: u32, id: u32, payload: [u8; 64]) {
        if !self.subscribed(ev_type, id) {
            return;
        }
        if self.queue.len() >= 64 {
            self.queue.pop_front();
        }
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        self.queue.push_back(EventRecord {
            ev_type,
            id,
            seq,
            payload,
        });
    }
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
    /// Capture sequence number stamped when the buffer is filled.
    pub sequence: u32,
    /// Monotonic capture timestamp in nanoseconds, stamped when filled.
    pub timestamp_ns: u64,
    /// Queue state.
    pub state: QState,
    /// `true` while userspace holds a mapping (blocks `REQBUFS` reuse).
    pub mapped: bool,
    /// Memory model: `V4L2_MEMORY_MMAP` / `USERPTR` / `DMABUF`.
    pub memory: u32,
    /// `true` when `frames` are device-owned (MMAP) and must be freed on
    /// teardown; `false` for borrowed DMABUF-import frames.
    pub owns_frames: bool,
    /// USERPTR target address supplied at `QBUF` (0 otherwise).
    pub userptr: u64,
    /// USERPTR capture staging: the pump copies here (it runs outside the
    /// caller's address space); `DQBUF` copies this to `userptr` via `ctx`.
    pub staged: Vec<u8>,
}

impl V4l2Buffer {
    /// Record a captured frame. For frame-backed buffers (MMAP / imported
    /// DMABUF) copy straight into the physical frames; for USERPTR stage the
    /// bytes until `DQBUF` can write them into the caller's address space.
    /// Returns the number of bytes recorded (`bytesused`).
    fn fill(&mut self, data: &[u8]) -> u32 {
        let total = data.len().min(self.length as usize);
        if self.frames.is_empty() {
            // USERPTR: stage for a later `ctx.write` at DQBUF time.
            self.staged.clear();
            self.staged.extend_from_slice(&data[..total]);
            return total as u32;
        }
        let mut remaining = total;
        let mut src = 0usize;
        for frame in &self.frames {
            if remaining == 0 {
                break;
            }
            let n = remaining.min(PAGE);
            let dst = frame.start_address().kernel_mut_ptr::<u8>();
            // SAFETY: `frame` is a 4 KiB frame backing this buffer; its
            // direct-map pointer is a valid, writable kernel VA for the whole
            // page, and `n <= PAGE`. Source and destination do not overlap.
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

/// Map a UVC `PixelFmt` to `(fourcc, description, compressed)`, or `None` for
/// formats with no V4L2 fourcc we expose.
fn pixelfmt_fourcc(p: crate::uvc::PixelFmt) -> Option<(u32, &'static str, bool)> {
    use crate::uvc::PixelFmt;
    Some(match p {
        PixelFmt::Yuyv => (V4L2_PIX_FMT_YUYV, "YUYV 4:2:2", false),
        PixelFmt::Nv12 => (V4L2_PIX_FMT_NV12, "NV12 4:2:0", false),
        PixelFmt::Mjpeg => (V4L2_PIX_FMT_MJPEG, "Motion-JPEG", true),
        PixelFmt::FrameBased => (fourcc(b'H', b'2', b'6', b'4'), "H.264", true),
        PixelFmt::Unknown => return None,
    })
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        a.max(1)
    } else {
        gcd(b, a % b)
    }
}

/// Convert a UVC frame interval (100 ns units per frame) to a reduced V4L2
/// `(numerator, denominator)` seconds-per-frame fraction. 0 → 30 fps.
fn interval_to_fract(interval_100ns: u32) -> (u32, u32) {
    if interval_100ns == 0 {
        return (1, 30);
    }
    let g = gcd(interval_100ns, 10_000_000);
    (interval_100ns / g, 10_000_000 / g)
}

/// Build a V4L2 `ENUM_FMT` table from parsed UVC streaming descriptors
/// (`uvc::parse_streaming_descriptors`). Formats with no mapped fourcc, or with
/// no frame sizes, are skipped. Returns an empty vec if nothing maps — callers
/// should fall back to [`default_formats`].
pub fn uvc_to_v4l2_formats(formats: &[crate::uvc::StreamFormat]) -> Vec<FmtEntry> {
    let mut out = Vec::new();
    for f in formats {
        let Some((fourcc_val, desc, compressed)) = pixelfmt_fourcc(f.pixel_fmt) else {
            continue;
        };
        let mut sizes = Vec::new();
        for fm in &f.frames {
            let mut intervals: Vec<(u32, u32)> = fm
                .frame_intervals
                .iter()
                .map(|&i| interval_to_fract(i))
                .collect();
            if intervals.is_empty() {
                // Continuous interval range — advertise the default rate.
                intervals.push(interval_to_fract(fm.default_frame_interval));
            }
            sizes.push(FrameSize {
                width: fm.width as u32,
                height: fm.height as u32,
                intervals,
            });
        }
        if sizes.is_empty() {
            continue;
        }
        out.push(FmtEntry {
            fourcc: fourcc_val,
            description: String::from(desc),
            compressed,
            sizes,
        });
    }
    out
}

/// Initial capture format for a device: the first format's first frame size, or
/// the library default when the table is empty.
pub fn pix_format_from(formats: &[FmtEntry]) -> PixFormat {
    match formats
        .first()
        .and_then(|f| f.sizes.first().map(|s| (f.fourcc, s)))
    {
        Some((fourcc_val, s)) => PixFormat {
            width: s.width,
            height: s.height,
            fourcc: fourcc_val,
        },
        None => default_pix_format(),
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
        // Only MMAP buffers own their frames; DMABUF-import frames are borrowed
        // from the exporting file and must not be freed here.
        if buf.owns_frames {
            for frame in buf.frames {
                free_frame(frame);
            }
        }
    }
}

// ── dma-buf export (VIDIOC_EXPBUF) ───────────────────────────────────────────

/// A dma-buf fd exported from an MMAP capture buffer. It aliases the same
/// device-owned physical frames (mapped *borrowed*, never freed on munmap) and
/// pins the device for its whole lifetime, so a GPU/other importer can map the
/// capture buffer directly. Model: the DRM dumb-buffer dma-buf in
/// `drivers/gpu/src/drm_devfs_bridge.rs`.
#[derive(Debug)]
struct VideoDmaBuf {
    frames: Vec<PhysFrame>,
    byte_len: usize,
    dev: Arc<IrqSafeSpinLock<VideoDevice>>,
}

impl FileOps for VideoDmaBuf {
    fn ino(&self) -> u64 {
        narf_filesystem::inode_id::anon_inode().ino
    }

    fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
        narf_filesystem::inode_id::anon_inode().attrs()
    }

    /// A dma-buf is not byte-readable; it is mmap'd. `read` → EOF.
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.byte_len as u64,
            blocks: (self.byte_len as u64).div_ceil(512),
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    /// Alias the capture buffer's frames into the importer's address space.
    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        let off = offset as usize;
        if off % PAGE != 0 || off + len > self.frames.len() * PAGE {
            return Err(FsError::InvalidData);
        }
        let start = off / PAGE;
        let pages = len.div_ceil(PAGE);
        Ok(self
            .frames
            .iter()
            .skip(start)
            .take(pages)
            .map(|f| f.start_address().raw())
            .collect())
    }

    /// Pin the owning device so its buffer pool's frames outlive this fd.
    fn mmap_lifetime(&self, _offset: u64, _len: usize) -> Option<Arc<dyn MmapLifetime>> {
        Some(self.dev.clone() as Arc<dyn MmapLifetime>)
    }
}

/// `VIDIOC_EXPBUF`: export MMAP buffer `index` as a dma-buf fd. The buffer is
/// flagged mapped so a later `REQBUFS` cannot free frames still referenced by
/// the exported fd (returns `EBUSY`, as vb2 does for in-use buffers).
fn expbuf(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    b: &mut [u8],
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return Ok(errno(EINVAL));
    }
    let index = rd_u32(b, 4) as usize;
    let flags = rd_u32(b, 12);
    let (frames, byte_len) = {
        let mut g = dev.lock();
        let Some(buf) = g.buffers.get_mut(index) else {
            return Ok(errno(EINVAL));
        };
        buf.mapped = true; // block REQBUFS reuse while the fd can alias frames
        (buf.frames.clone(), buf.length as usize)
    };
    let dmabuf = Arc::new(VideoDmaBuf {
        frames,
        byte_len,
        dev: dev.clone(),
    });
    let fd = ctx.install_file(dmabuf as Arc<dyn FileOps>, flags & O_CLOEXEC != 0)?;
    wr_i32(b, 16, fd); // v4l2_exportbuffer.fd
    Ok(0)
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
    events: Arc<IrqSafeSpinLock<FdEvents>>,
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

        let ret = handle(&dev, nr, &mut buf, arg, ctx, &events).await?;

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
    arg: u64,
    ctx: &dyn IoctlContext,
    events: &IrqSafeSpinLock<FdEvents>,
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
        VIDIOC_QUERYBUF => querybuf(dev, b, ctx)?,
        VIDIOC_QBUF => qbuf(dev, b, ctx)?,
        VIDIOC_EXPBUF => expbuf(dev, b, ctx)?,
        VIDIOC_DQBUF => dqbuf(dev, b, ctx).await?,
        VIDIOC_STREAMON => streamon(dev, b, true, events),
        VIDIOC_STREAMOFF => streamon(dev, b, false, events),
        VIDIOC_G_PARM | VIDIOC_S_PARM => g_parm(dev, b),
        VIDIOC_G_CTRL => g_ctrl(dev, b),
        VIDIOC_S_CTRL => s_ctrl(dev, b, events),
        VIDIOC_QUERYCTRL => queryctrl(dev, b),
        VIDIOC_G_EXT_CTRLS => ext_ctrls(dev, b, arg, ctx, ExtCtrlOp::Get, events)?,
        VIDIOC_S_EXT_CTRLS => ext_ctrls(dev, b, arg, ctx, ExtCtrlOp::Set, events)?,
        VIDIOC_TRY_EXT_CTRLS => ext_ctrls(dev, b, arg, ctx, ExtCtrlOp::Try, events)?,
        VIDIOC_SUBSCRIBE_EVENT => subscribe_event(dev, b, events),
        VIDIOC_UNSUBSCRIBE_EVENT => unsubscribe_event(b, events),
        VIDIOC_DQEVENT => dqevent(b, events),
        VIDIOC_CROPCAP => cropcap(dev, b),
        VIDIOC_G_CROP => g_crop(dev, b),
        VIDIOC_S_CROP => s_crop(b),
        VIDIOC_G_SELECTION => g_selection(dev, b),
        VIDIOC_S_SELECTION => s_selection(dev, b),
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
        | V4L2_CAP_VIDEO_CAPTURE_MPLANE
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

/// Write the `v4l2_pix_format_mplane` form of a `v4l2_format` buffer as a single
/// plane (UVC is single-planar). `pix_mp` begins at offset 8 like `pix`; its
/// `plane_fmt[0]` is at offset 28 (`sizeimage`,`bytesperline`) and `num_planes`
/// at offset 188.
fn write_pix_format_mplane(b: &mut [u8], fmt: &PixFormat) {
    wr_u32(b, 0, V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE); // type
    wr_u32(b, 8, fmt.width); // pix_mp.width
    wr_u32(b, 12, fmt.height); // pix_mp.height
    wr_u32(b, 16, fmt.fourcc); // pix_mp.pixelformat
    wr_u32(b, 20, V4L2_FIELD_NONE); // pix_mp.field
    wr_u32(b, 24, V4L2_COLORSPACE_SRGB); // pix_mp.colorspace
    wr_u32(b, 28, fmt.sizeimage()); // plane_fmt[0].sizeimage
    wr_u32(b, 32, fmt.bytesperline()); // plane_fmt[0].bytesperline
    b[188] = 1; // num_planes
}

/// `true` for the single-planar capture buf type, `false` for the multiplanar
/// one; any other buf type is rejected by the caller.
fn is_mplane(btype: u32) -> bool {
    btype == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
}

fn g_fmt(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    let btype = rd_u32(b, 0);
    if btype != V4L2_BUF_TYPE_VIDEO_CAPTURE && !is_mplane(btype) {
        return errno(EINVAL);
    }
    let fmt = dev.lock().format;
    for byte in b.iter_mut() {
        *byte = 0;
    }
    if is_mplane(btype) {
        write_pix_format_mplane(b, &fmt);
    } else {
        write_pix_format(b, &fmt);
    }
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
    let btype = rd_u32(b, 0);
    if btype != V4L2_BUF_TYPE_VIDEO_CAPTURE && !is_mplane(btype) {
        return errno(EINVAL);
    }
    // width/height/pixelformat live at offsets 8/12/16 for both `pix` and
    // `pix_mp` (their leading fields coincide).
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
    if is_mplane(btype) {
        write_pix_format_mplane(b, &adjusted);
    } else {
        write_pix_format(b, &adjusted);
    }
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
    if !matches!(
        btype,
        V4L2_BUF_TYPE_VIDEO_CAPTURE | V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
    ) || !matches!(
        memory,
        V4L2_MEMORY_MMAP | V4L2_MEMORY_USERPTR | V4L2_MEMORY_DMABUF
    ) {
        return errno(EINVAL);
    }
    let mmap = memory == V4L2_MEMORY_MMAP;
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
            // Only MMAP buffers are kernel-backed up front; USERPTR/DMABUF
            // buffers get their backing at QBUF time.
            let mut frames = Vec::new();
            if mmap {
                frames.reserve(pages);
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
            }
            g.buffers.push(V4l2Buffer {
                frames,
                length: buf_bytes,
                mmap_offset: (i as u32) * buf_bytes,
                bytesused: 0,
                sequence: 0,
                timestamp_ns: 0,
                state: QState::Dequeued,
                mapped: false,
                memory,
                owns_frames: mmap,
                userptr: 0,
                staged: Vec::new(),
            });
        }
    }

    let actual = g.buffers.len() as u32;
    drop(g);
    wr_u32(b, 0, actual); // count
                          // Advertise the supported memory models (vb2 sets these capability bits).
    wr_u32(
        b,
        12,
        V4L2_BUF_CAP_SUPPORTS_MMAP | V4L2_BUF_CAP_SUPPORTS_USERPTR | V4L2_BUF_CAP_SUPPORTS_DMABUF,
    );
    b[16] = 0; // flags (__u8)
    0
}

/// Fill the inline `v4l2_buffer` (88 B) describing `buf` at `index` for buf-type
/// `btype`. For single-planar buffers this also writes `m.offset`/`length`; for
/// multiplanar it writes `length = num_planes (1)` and leaves `m.planes`
/// untouched — the caller restores the user's plane pointer and writes the
/// `v4l2_plane` with [`write_plane`].
fn write_buffer_desc(b: &mut [u8], index: u32, buf: &V4l2Buffer, btype: u32) {
    for byte in b.iter_mut().take(SZ_BUFFER) {
        *byte = 0;
    }
    wr_u32(b, 0, index); // index
    wr_u32(b, 4, btype); // type
    wr_u32(b, 8, buf.bytesused); // bytesused (single-planar; 0 for mplane)
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
    wr_u32(b, 60, buf.memory); // memory
    if is_mplane(btype) {
        wr_u32(b, 8, 0); // bytesused lives in the plane for mplane
        wr_u32(b, 72, 1); // length = num_planes
    } else {
        wr_u32(b, 64, buf.mmap_offset); // m.offset
        wr_u32(b, 72, buf.length); // length
    }
}

/// Write a single `v4l2_plane` (64 B) at the user address `ptr` (MPLANE path).
fn write_plane(
    ctx: &dyn IoctlContext,
    ptr: u64,
    bytesused: u32,
    length: u32,
    mem_offset: u32,
) -> Result<(), FsError> {
    let mut p = [0u8; SZ_PLANE];
    wr_u32(&mut p, 0, bytesused);
    wr_u32(&mut p, 4, length);
    wr_u32(&mut p, 8, mem_offset); // m.mem_offset
    ctx.write(ptr, &p)
}

fn querybuf(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    b: &mut [u8],
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let index = rd_u32(b, 0) as usize;
    let btype = rd_u32(b, 4);
    if !matches!(
        btype,
        V4L2_BUF_TYPE_VIDEO_CAPTURE | V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
    ) {
        return Ok(errno(EINVAL));
    }
    // Preserve the user's plane-array pointer across the struct rewrite (mplane).
    let planes_ptr = rd_u64(b, 64);
    let g = dev.lock();
    let Some(buf) = g.buffers.get(index) else {
        return Ok(errno(EINVAL));
    };
    let (used, length, offset) = (buf.bytesused, buf.length, buf.mmap_offset);
    write_buffer_desc(b, index as u32, buf, btype);
    drop(g);
    if is_mplane(btype) {
        wr_u64(b, 64, planes_ptr); // restore m.planes
        write_plane(ctx, planes_ptr, used, length, offset)?;
    }
    Ok(0)
}

fn qbuf(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    b: &mut [u8],
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let index = rd_u32(b, 0) as usize;
    let btype = rd_u32(b, 4);
    let memory = rd_u32(b, 60);
    if !matches!(
        btype,
        V4L2_BUF_TYPE_VIDEO_CAPTURE | V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
    ) {
        return Ok(errno(EINVAL));
    }
    // The `m` union (fd / userptr) is inline for single-planar buffers and in
    // `plane[0]` for multiplanar.
    let planes_ptr = rd_u64(b, 64);
    let (fd_val, userptr_val) = if is_mplane(btype) {
        let mut p = [0u8; SZ_PLANE];
        ctx.read(planes_ptr, &mut p)?;
        (rd_i32(&p, 8), rd_u64(&p, 8))
    } else {
        (rd_i32(b, 64), rd_u64(b, 64))
    };
    // For DMABUF, resolve the imported file's frames before taking the lock.
    let imported = if memory == V4L2_MEMORY_DMABUF {
        let file = ctx.file(fd_val)?;
        let len = dev.lock().format.sizeimage() as usize;
        match file.mmap_frames(0, len.div_ceil(PAGE) * PAGE) {
            Ok(addrs) => Some(
                addrs
                    .into_iter()
                    .map(|a| PhysFrame::containing(PhysAddr::new(a)))
                    .collect::<Vec<_>>(),
            ),
            Err(_) => return Ok(errno(EINVAL)),
        }
    } else {
        None
    };
    let userptr = if memory == V4L2_MEMORY_USERPTR {
        userptr_val
    } else {
        0
    };

    let mut g = dev.lock();
    let Some(buf) = g.buffers.get_mut(index) else {
        return Ok(errno(EINVAL));
    };
    // The memory model must match what REQBUFS set up.
    if buf.memory != memory {
        return Ok(errno(EINVAL));
    }
    // Re-queuing an already-queued buffer is EINVAL (vb2: __vb2_qbuf).
    if buf.state == QState::Queued {
        return Ok(errno(EINVAL));
    }
    match memory {
        V4L2_MEMORY_USERPTR => buf.userptr = userptr,
        V4L2_MEMORY_DMABUF => {
            buf.frames = imported.unwrap_or_default();
            buf.owns_frames = false;
        }
        _ => {}
    }
    buf.state = QState::Queued;
    buf.bytesused = 0;
    let (length, offset) = (buf.length, buf.mmap_offset);
    write_buffer_desc(b, index as u32, buf, btype);
    drop(g);
    if is_mplane(btype) {
        wr_u64(b, 64, planes_ptr);
        write_plane(ctx, planes_ptr, 0, length, offset)?;
    }
    Ok(0)
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
    // Otherwise, pull a frame from the fallback queue and fill the first queued
    // buffer, stamping the timestamp now (less precise than the live
    // `fill_queued_buffer` path, used only when a frame arrived before QBUF).
    let frame = g.pop_frame()?;
    if fill_queued_buffer(g, &frame.data, narf_time::monotonic_ns()) {
        g.buffers.iter().position(|b| b.state == QState::Done)
    } else {
        None
    }
}

/// Fill the first `Queued` buffer with `data`, stamping `ts_ns` and the next
/// sequence number, and mark it `Done`. Returns `false` if no buffer is queued.
/// This is the *live* capture path: the driver calls it the moment a frame
/// completes, so the timestamp reflects capture time, not dequeue time.
pub fn fill_queued_buffer(dev: &mut VideoDevice, data: &[u8], ts_ns: u64) -> bool {
    let seq = dev.sequence;
    let Some(idx) = dev.buffers.iter().position(|b| b.state == QState::Queued) else {
        return false;
    };
    let buf = &mut dev.buffers[idx];
    buf.bytesused = buf.fill(data);
    buf.sequence = seq;
    buf.timestamp_ns = ts_ns;
    buf.state = QState::Done;
    dev.sequence = dev.sequence.wrapping_add(1);
    true
}

async fn dqbuf(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    b: &mut [u8],
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let btype = rd_u32(b, 4);
    let memory = rd_u32(b, 60);
    let planes_ptr = rd_u64(b, 64);
    if !matches!(
        btype,
        V4L2_BUF_TYPE_VIDEO_CAPTURE | V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
    ) || !matches!(
        memory,
        V4L2_MEMORY_MMAP | V4L2_MEMORY_USERPTR | V4L2_MEMORY_DMABUF
    ) {
        return Ok(errno(EINVAL));
    }
    // Streaming must be active and buffers queued (vb2: EINVAL otherwise).
    {
        let g = dev.lock();
        if !g.streaming || g.buffers.iter().all(|b| b.state == QState::Dequeued) {
            return Ok(errno(EINVAL));
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
                let ns = g.buffers[idx].timestamp_ns;
                // USERPTR: the capture pump staged the bytes in kernel memory;
                // copy them into the caller's address space now (we are in the
                // DQBUF syscall, so `ctx` targets the right process).
                let userptr_copy = if g.buffers[idx].memory == V4L2_MEMORY_USERPTR {
                    let used = g.buffers[idx].bytesused as usize;
                    Some((
                        g.buffers[idx].userptr,
                        g.buffers[idx].staged[..used].to_vec(),
                    ))
                } else {
                    None
                };
                let (used, length, offset) = (
                    g.buffers[idx].bytesused,
                    g.buffers[idx].length,
                    g.buffers[idx].mmap_offset,
                );
                write_buffer_desc(b, idx as u32, &g.buffers[idx], btype);
                if !is_mplane(btype) && g.buffers[idx].memory == V4L2_MEMORY_USERPTR {
                    wr_u64(b, 64, g.buffers[idx].userptr); // m.userptr echo
                }
                wr_u64(b, 24, ns / 1_000_000_000); // timestamp.tv_sec
                wr_u64(b, 32, (ns % 1_000_000_000) / 1_000); // timestamp.tv_usec
                g.refresh_readiness();
                drop(g);
                if is_mplane(btype) {
                    wr_u64(b, 64, planes_ptr); // restore m.planes
                    write_plane(ctx, planes_ptr, used, length, offset)?;
                }
                if let Some((addr, bytes)) = userptr_copy {
                    ctx.write(addr, &bytes)?;
                }
                return Ok(0);
            }
        }
        if ctx.nonblocking() {
            return Ok(errno(EAGAIN));
        }
        // Park ~2 ms then retry; a captured frame or STREAMOFF wakes progress.
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(2).as_instant()).await;
        if !dev.lock().streaming {
            return Ok(errno(EINTR));
        }
    }
}

fn streamon(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    b: &mut [u8],
    on: bool,
    events: &IrqSafeSpinLock<FdEvents>,
) -> u64 {
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
        g.refresh_readiness();
        drop(g);
        // Signal end-of-stream to subscribers (vb2 queues V4L2_EVENT_EOS).
        events.lock().enqueue(V4L2_EVENT_EOS, 0, [0u8; 64]);
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

fn s_ctrl(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    b: &mut [u8],
    events: &IrqSafeSpinLock<FdEvents>,
) -> u64 {
    let id = rd_u32(b, 0);
    let val_in = rd_i32(b, 4);
    let mut g = dev.lock();
    let Some(c) = g.controls.iter_mut().find(|c| c.id == id) else {
        return errno(EINVAL);
    };
    // Clamp to [min, max] and snap to step, like v4l2 does.
    let mut val = val_in.clamp(c.min, c.max);
    if c.step > 1 {
        val -= (val - c.min) % c.step;
    }
    c.value = val;
    let snapshot = *c;
    drop(g);
    wr_i32(b, 4, val); // report the clamped value back
    emit_ctrl_event(events, &snapshot);
    0
}

/// Queue a `V4L2_EVENT_CTRL` value-change event for a control. No-op unless the
/// fd has subscribed to that control id.
fn emit_ctrl_event(events: &IrqSafeSpinLock<FdEvents>, c: &ControlState) {
    // v4l2_event_ctrl laid out within the 64-byte `u` payload (offset 0 = `u`).
    let mut p = [0u8; 64];
    wr_u32(&mut p, 0, V4L2_EVENT_CTRL_CH_VALUE); // changes
    wr_u32(&mut p, 4, V4L2_CTRL_TYPE_INTEGER); // type
    wr_i32(&mut p, 8, c.value); // value (union @8)
    wr_u32(&mut p, 16, 0); // flags
    wr_i32(&mut p, 20, c.min); // minimum
    wr_i32(&mut p, 24, c.max); // maximum
    wr_i32(&mut p, 28, c.step); // step
    wr_i32(&mut p, 32, c.default); // default_value
    events.lock().enqueue(V4L2_EVENT_CTRL, c.id, p);
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

/// Which `VIDIOC_*_EXT_CTRLS` operation is being performed.
#[derive(Copy, Clone, PartialEq, Eq)]
enum ExtCtrlOp {
    Get,
    Set,
    Try,
}

/// Handle `VIDIOC_G/S/TRY_EXT_CTRLS`. The top `v4l2_ext_controls` struct is
/// already staged in `b`; the per-control array lives at the user pointer
/// `b[24]`, read/written one `v4l2_ext_control` at a time through `ctx`.
///
/// Only integer controls in the USER class are exposed, so each control's value
/// is the 32-bit `value` field at offset 12 of `v4l2_ext_control`. On an
/// unknown id (or an attempt to set the read-only default-value set) the
/// 1-based failing index is written to `error_idx` and `EINVAL` is returned, as
/// `v4l2-ioctl.c::v4l2_g/s_ext_ctrls` do.
fn ext_ctrls(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    b: &mut [u8],
    arg: u64,
    ctx: &dyn IoctlContext,
    op: ExtCtrlOp,
    events: &IrqSafeSpinLock<FdEvents>,
) -> Result<u64, FsError> {
    let which = rd_u32(b, 0);
    let count = rd_u32(b, 4);
    let ptr = rd_u64(b, 24);
    // error_idx == count signals "no error" on the success copy-out.
    wr_u32(b, 8, count);
    if which != V4L2_CTRL_WHICH_CUR_VAL && which != V4L2_CTRL_WHICH_DEF_VAL {
        return Ok(errno(EINVAL));
    }
    if count == 0 {
        return Ok(0);
    }
    let defaults = which == V4L2_CTRL_WHICH_DEF_VAL;

    // Write `error_idx` straight to the user struct and fail.
    let fail_at = |i: u32| -> Result<u64, FsError> {
        ctx.write(arg.wrapping_add(8), &i.to_ne_bytes())?;
        Ok(errno(EINVAL))
    };

    for i in 0..count {
        let entry = ptr
            .checked_add(u64::from(i) * SZ_EXT_CONTROL as u64)
            .ok_or(FsError::BadAddress)?;
        let mut e = [0u8; SZ_EXT_CONTROL];
        ctx.read(entry, &mut e)?;
        let id = rd_u32(&e, 0);

        let mut g = dev.lock();
        let Some(idx) = g.controls.iter().position(|c| c.id == id) else {
            drop(g);
            return fail_at(i);
        };
        match op {
            ExtCtrlOp::Get => {
                let v = if defaults {
                    g.controls[idx].default
                } else {
                    g.controls[idx].value
                };
                wr_i32(&mut e, 12, v);
            }
            ExtCtrlOp::Set | ExtCtrlOp::Try => {
                if defaults {
                    // The default-value set is read-only.
                    drop(g);
                    return fail_at(i);
                }
                let c = &mut g.controls[idx];
                let mut val = rd_i32(&e, 12).clamp(c.min, c.max);
                if c.step > 1 {
                    val -= (val - c.min) % c.step;
                }
                let snapshot = if op == ExtCtrlOp::Set {
                    c.value = val;
                    Some(*c)
                } else {
                    None
                };
                wr_i32(&mut e, 12, val);
                drop(g);
                if let Some(s) = snapshot {
                    emit_ctrl_event(events, &s);
                }
                ctx.write(entry, &e)?;
                continue;
            }
        }
        drop(g);
        ctx.write(entry, &e)?;
    }
    Ok(0)
}

/// `VIDIOC_SUBSCRIBE_EVENT`: record interest in `(type, id)`. If the caller
/// set `V4L2_EVENT_SUB_FL_SEND_INITIAL` for a control, queue its current value
/// immediately (Linux delivers the initial control state on subscribe).
fn subscribe_event(
    dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
    b: &mut [u8],
    events: &IrqSafeSpinLock<FdEvents>,
) -> u64 {
    let ev_type = rd_u32(b, 0);
    let id = rd_u32(b, 4);
    let flags = rd_u32(b, 8);
    {
        let mut ev = events.lock();
        if !ev.subs.iter().any(|&(t, i)| t == ev_type && i == id) {
            ev.subs.push((ev_type, id));
        }
    }
    if ev_type == V4L2_EVENT_CTRL && flags & V4L2_EVENT_SUB_FL_SEND_INITIAL != 0 {
        if let Some(c) = dev.lock().controls.iter().find(|c| c.id == id).copied() {
            emit_ctrl_event(events, &c);
        }
    }
    0
}

/// `VIDIOC_UNSUBSCRIBE_EVENT`: drop one subscription, or all when
/// `type == V4L2_EVENT_ALL`.
fn unsubscribe_event(b: &mut [u8], events: &IrqSafeSpinLock<FdEvents>) -> u64 {
    let ev_type = rd_u32(b, 0);
    let id = rd_u32(b, 4);
    let mut ev = events.lock();
    if ev_type == V4L2_EVENT_ALL {
        ev.subs.clear();
        ev.queue.clear();
    } else {
        ev.subs.retain(|&(t, i)| !(t == ev_type && i == id));
    }
    0
}

/// `VIDIOC_DQEVENT`: pop the oldest queued event into `b`, reporting how many
/// remain in `pending`. `ENOENT` when the queue is empty (vb2 semantics).
fn dqevent(b: &mut [u8], events: &IrqSafeSpinLock<FdEvents>) -> u64 {
    let (rec, pending) = {
        let mut ev = events.lock();
        let Some(rec) = ev.queue.pop_front() else {
            return errno(ENOENT);
        };
        (rec, ev.queue.len() as u32)
    };
    for byte in b.iter_mut().take(SZ_EVENT) {
        *byte = 0;
    }
    wr_u32(b, 0, rec.ev_type); // type
    b[8..8 + 64].copy_from_slice(&rec.payload); // u (64-byte payload) @8
    wr_u32(b, 72, pending); // pending
    wr_u32(b, 76, rec.seq); // sequence
    let ns = narf_time::monotonic_ns();
    wr_u64(b, 80, ns / 1_000_000_000); // timestamp.tv_sec
    wr_u64(b, 88, ns % 1_000_000_000); // timestamp.tv_nsec
    wr_u32(b, 96, rec.id); // id
    0
}

/// Write a `v4l2_rect` (left, top, width, height) at offset `o`.
fn wr_rect(b: &mut [u8], o: usize, left: i32, top: i32, w: u32, h: u32) {
    wr_i32(b, o, left);
    wr_i32(b, o + 4, top);
    wr_u32(b, o + 8, w);
    wr_u32(b, o + 12, h);
}

/// Current capture frame dimensions.
fn frame_dims(dev: &Arc<IrqSafeSpinLock<VideoDevice>>) -> (u32, u32) {
    let g = dev.lock();
    (g.format.width, g.format.height)
}

/// `VIDIOC_CROPCAP`: the camera does not crop, so `bounds == defrect ==` the
/// full frame and the pixel aspect ratio is 1:1.
fn cropcap(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    let (w, h) = frame_dims(dev);
    wr_rect(b, 4, 0, 0, w, h); // bounds
    wr_rect(b, 20, 0, 0, w, h); // defrect
    wr_u32(b, 36, 1); // pixelaspect.numerator
    wr_u32(b, 40, 1); // pixelaspect.denominator
    0
}

/// `VIDIOC_G_CROP`: the crop rectangle is always the full frame.
fn g_crop(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    let (w, h) = frame_dims(dev);
    wr_rect(b, 4, 0, 0, w, h);
    0
}

/// `VIDIOC_S_CROP`: accepted but a no-op (no hardware cropping).
fn s_crop(b: &[u8]) -> u64 {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    0
}

/// `VIDIOC_G_SELECTION`: every target resolves to the full frame.
fn g_selection(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    let (w, h) = frame_dims(dev);
    wr_rect(b, 12, 0, 0, w, h); // r
    0
}

/// `VIDIOC_S_SELECTION`: clamp to the full frame (no cropping) and echo it back.
fn s_selection(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, b: &mut [u8]) -> u64 {
    if rd_u32(b, 0) != V4L2_BUF_TYPE_VIDEO_CAPTURE {
        return errno(EINVAL);
    }
    let (w, h) = frame_dims(dev);
    wr_rect(b, 12, 0, 0, w, h);
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
