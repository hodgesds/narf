//! narf-drivers-video — Camera ISP driver scaffold.
//!
//! Stage-0/1: PCI probe, MMIO mapping, firmware-name resolution, and
//! V4L2-compatible buffer-queue types for:
//!
//! | IP             | PCI IDs                                  | Firmware blob                    |
//! |----------------|------------------------------------------|----------------------------------|
//! | Intel IPU3     | 8086:1919 (Skylake Y/U Pixel Visual Core)| *(no user-facing FW blob)*       |
//! | Intel IPU6     | 8086:9A19 (Tiger Lake)                   | intel/ipu/ipu6_fw.bin            |
//! |                | 8086:4E19 (Jasper Lake SE)               | intel/ipu/ipu6se_fw.bin          |
//! |                | 8086:465D (Alder Lake-P EP)              | intel/ipu/ipu6ep_fw.bin          |
//! |                | 8086:A75D (Raptor Lake-P EP)             | intel/ipu/ipu6ep_fw.bin          |
//! |                | 8086:462E (Alder Lake-N EP)              | intel/ipu/ipu6epadln_fw.bin      |
//! |                | 8086:7D19 (Meteor Lake EP)               | intel/ipu/ipu6epmtl_fw.bin       |
//! | AMD MP2 ISP    | 1022:15E4 / 1022:164A                   | amd/amdmp2.bin                   |
//!
//! ## References (Linux GPL, post 2026-05-20 relicense)
//!
//! - `linux/drivers/staging/media/ipu3/ipu3.c` — IPU3 PCI ID 0x1919.
//! - `linux/include/media/ipu6-pci-table.h` — IPU6 PCI IDs.
//! - `linux/drivers/media/pci/intel/ipu6/ipu6.h` — firmware names.
//! - `linux/drivers/hid/amd-sfh-hid/amd_sfh_common.h` — MP2 PCI IDs.
//!
//! ## Stage progression
//!
//! - **Stage 0 (this commit)** — Crate skeleton, PCI ID tables,
//!   firmware-name constants, buffer-queue types, pixel-format enum,
//!   MIPI-CSI sensor-driver trait. No MMIO programming.
//! - **Stage 1 (this commit)** — PCI probe registration + BAR mapping
//!   + firmware-name resolution + bound-driver record.
//! - **Stage 2+ (future)** — Firmware load via PSP / CSE paths,
//!   MIPI-CSI receiver bringup, per-sensor I2C configuration,
//!   DMA scatter-gather ring, V4L2 buffer dequeue path.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

// ── Per-vendor ISP modules ──────────────────────────────────────────
pub mod amd_mp2_isp;
pub mod intel_ipu3;
pub mod intel_ipu6;

// ── devfs / sysfs bridge ────────────────────────────────────────────
pub mod devfs_bridge;

// ── MIPI-CSI sensor interface ───────────────────────────────────────
pub mod sensor;

// ── Per-sensor drivers ──────────────────────────────────────────────
pub mod ov01a1s;
pub mod ov02c10;
pub mod ov05c10;

mod tests;

// ── USB Video Class (UVC) webcam driver ─────────────────────────────
pub mod uvc;

// ── V4L2-equivalent userspace surface ───────────────────────────────
pub mod v4l2;

mod uvc_tests;

// ── V4L2-compatible buffer-queue types ─────────────────────────────

/// Pixel format classification for camera buffers.
///
/// The encoding mirrors V4L2's `V4L2_PIX_FMT_*` taxonomy
/// (linux/include/uapi/linux/videodev2.h) but NARF only exposes
/// the small subset that the targeted ISPs (IPU6/MP2) actually
/// emit in their default output paths.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// Semi-planar YUV 4:2:0 — Y plane followed by interleaved
    /// UV plane. IPU6 and AMD ISP default output. V4L2 fourcc
    /// `NV12` (0x3231564E).
    Nv12,
    /// Motion-JPEG compressed frame. Some sensors emit this
    /// natively before the ISP. V4L2 fourcc `MJPG` (0x47504A4D).
    Mjpeg,
    /// Packed YUV 4:2:2 — Y0 U0 Y1 V0. V4L2 fourcc `YUYV`
    /// (0x56595559).
    Yuyv,
    /// Packed RGB565 — 5 red / 6 green / 5 blue in 16-bit LE.
    /// V4L2 fourcc `RGBP` (0x50424752).
    Rgb565,
}

impl PixelFormat {
    /// V4L2-compatible four-character code (little-endian u32).
    pub const fn fourcc(self) -> u32 {
        match self {
            PixelFormat::Nv12 => 0x3231_564E,
            PixelFormat::Mjpeg => 0x4750_4A4D,
            PixelFormat::Yuyv => 0x5659_5559,
            PixelFormat::Rgb565 => 0x5042_4752,
        }
    }
}

/// Buffer kind: distinguishes frame-data payloads from metadata
/// captures (embedded line, statistics).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BufferKind {
    /// A complete captured video frame.
    VideoCapture,
    /// Per-frame embedded metadata / statistics from the ISP.
    MetaCapture,
}

/// A single camera DMA buffer descriptor.
///
/// `phys` is the physical base address of a contiguous allocation.
/// Stage-1 does not attempt to enqueue these to real ISP hardware
/// rings — that happens in Stage-2 when the firmware-load path
/// and IOMMU mapping are in place.
#[derive(Copy, Clone, Debug)]
pub struct CameraBuffer {
    /// Physical base address of the DMA buffer.
    pub phys: u64,
    /// Byte length of the buffer.
    pub len: usize,
    /// Buffer kind.
    pub kind: BufferKind,
}

/// Fixed-capacity FIFO queue of `CameraBuffer` descriptors.
///
/// Modelled on V4L2's buffer-queue abstraction (VIDIOC_QBUF /
/// VIDIOC_DQBUF). The ISP driver enqueues physical buffers here;
/// the consumer (a userspace camera daemon via IPC) dequeues them
/// after the hardware signals completion.
///
/// Stage-1 capacity: at most 8 entries (avoids dynamic allocation
/// in the hot path; final sizing is a Stage-2 knob).
#[derive(Debug)]
pub struct BufferQueue {
    ring: [Option<CameraBuffer>; QUEUE_DEPTH],
    head: usize,
    tail: usize,
    count: usize,
}

const QUEUE_DEPTH: usize = 8;

impl BufferQueue {
    /// Construct an empty queue.
    pub const fn new() -> Self {
        BufferQueue {
            ring: [None; QUEUE_DEPTH],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push a buffer onto the queue.
    ///
    /// Returns `false` and leaves the queue unchanged if full.
    /// Returns `true` on success.
    pub fn enqueue(&mut self, buf: CameraBuffer) -> bool {
        if self.count == QUEUE_DEPTH {
            return false;
        }
        self.ring[self.tail] = Some(buf);
        self.tail = (self.tail + 1) % QUEUE_DEPTH;
        self.count += 1;
        true
    }

    /// Pop the oldest buffer from the queue.
    pub fn dequeue(&mut self) -> Option<CameraBuffer> {
        if self.count == 0 {
            return None;
        }
        let buf = self.ring[self.head].take();
        self.head = (self.head + 1) % QUEUE_DEPTH;
        self.count -= 1;
        buf
    }

    /// Number of buffers currently queued.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` if the queue holds no buffers.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for BufferQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for camera operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CameraError {
    /// Operation not yet implemented (Stage-0/1 stub).
    NotImplemented,
    /// Invalid pixel format or resolution for this ISP.
    InvalidFormat,
    /// Firmware not loaded; cannot start streaming.
    FirmwareNotLoaded,
    /// BAR mapping failed during probe.
    BarMapFailed,
    /// DMA buffer queue is full.
    QueueFull,
}

/// Result shorthand.
pub type Result<T> = core::result::Result<T, CameraError>;

/// Camera device abstraction.
///
/// Each ISP driver (IPU3, IPU6, AMD MP2) implements this trait.
/// Stage-1: `set_format` and `start_streaming` return
/// `Err(CameraError::NotImplemented)` — they become functional in
/// Stage-2 when firmware loading and MIPI-CSI bringup land.
pub trait Camera: core::fmt::Debug {
    /// Immutable access to the driver's buffer queue.
    fn buffer_queue(&self) -> &BufferQueue;

    /// Mutable access to the driver's buffer queue.
    fn buffer_queue_mut(&mut self) -> &mut BufferQueue;

    /// Set the capture pixel format and frame dimensions.
    fn set_format(&self, fmt: PixelFormat, w: u32, h: u32) -> Result<()>;

    /// Begin ISP streaming. Returns immediately; frames arrive in
    /// `buffer_queue` asynchronously once firmware is active.
    fn start_streaming(&self) -> Result<()>;

    /// Stop ISP streaming and drain any in-flight buffers.
    fn stop_streaming(&self) -> Result<()>;
}

/// Register initcalls for all video drivers.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    // Install devfs hooks so /dev/video<N> nodes resolve.
    // Linux ref: `drivers/media/v4l2-core/v4l2-dev.c:__video_register_device`.
    narf_init::register(Stage::Subsys, "video-devfs", || {
        narf_filesystem::devfs::install_video_hooks(
            devfs_bridge::lookup_video,
            devfs_bridge::enumerate_video,
        );
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "intel-ipu3-pci", || {
        intel_ipu3::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "intel-ipu6-pci", || {
        intel_ipu6::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "amd-mp2-isp-pci", || {
        amd_mp2_isp::register_pci_driver();
        InitResult::Ok
    });
}
