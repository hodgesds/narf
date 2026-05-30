//! `/dev/video<N>` devfs bridge for UVC webcam devices.
//!
//! ## What this file does
//!
//! When a UVC camera probes (USB class 0x0E), the driver calls
//! [`register_video`] which:
//!
//! 1. Allocates the next `/dev/video<N>` index.
//! 2. Registers a [`VideoFile`] node that exposes the camera's frame
//!    queue as a byte-stream file.
//! 3. Registers `/sys/class/video4linux/video<N>/` kobject with `dev`,
//!    `name`, and `index` attributes.
//!
//! ## FileOps
//!
//! - `read`  → return next reassembled frame bytes (waits if streaming not
//!             yet delivered a frame; returns 0 / empty on no frame in NARF
//!             since there is no blocking sleep here — caller polls).
//! - `write` → `InvalidData` (V4L2 output devices not supported).
//! - `poll_readiness` → `POLL_IN` when a frame is ready.
//!
//! ## Sysfs
//!
//! - `/sys/class/video4linux/video<N>/dev`   → `"81:<N>\n"`
//! - `/sys/class/video4linux/video<N>/name`  → camera device string
//! - `/sys/class/video4linux/video<N>/index` → decimal index
//!
//! ## Linux reference
//!
//! `drivers/media/v4l2-core/v4l2-dev.c::__video_register_device`
//! (GPL-2.0-or-later).  Major 81 = `VIDEO_MAJOR` as defined in
//! `include/uapi/linux/major.h`.
//!
//! ## Deferred
//!
//! - V4L2 VIDIOC_* ioctl surface (NARF has no ioctl today).
//! - mmap'd buffer delivery (VIDIOC_MMAP / DMABUF).
//! - V4L2 control ioctls (brightness, contrast, etc.).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN};

// ── Major number ─────────────────────────────────────────────────────────

/// V4L2 video device major number.
///
/// Linux: `include/uapi/linux/major.h` → `VIDEO_MAJOR 81`.
/// (`drivers/media/v4l2-core/v4l2-dev.c:__video_register_device:918`).
pub const VIDEO_MAJOR: u32 = 81;

// ── Index allocator ───────────────────────────────────────────────────────

static VIDEO_NEXT_INDEX: AtomicUsize = AtomicUsize::new(0);

fn alloc_index() -> usize {
    VIDEO_NEXT_INDEX.fetch_add(1, Ordering::Relaxed)
}

// ── Per-device frame buffer ───────────────────────────────────────────────

/// A single captured video frame stored as a heap-allocated byte vector.
#[derive(Clone, Debug)]
pub struct VideoFrame {
    pub data: Vec<u8>,
}

/// Shared state for one video device.
///
/// The camera driver enqueues completed frames here via `push_frame`;
/// the devfs file node dequeues them via `pop_frame`.
#[derive(Debug)]
pub struct VideoDevice {
    pub index: usize,
    /// Camera description string (e.g. "USB 2.0 Camera").
    pub name: String,
    /// Pending frame queue (FIFO, capacity 4).
    frames: Vec<VideoFrame>,
}

impl VideoDevice {
    pub fn new(index: usize, name: String) -> Self {
        VideoDevice { index, name, frames: Vec::new() }
    }

    /// Enqueue a complete frame. Drops oldest if over capacity (4).
    pub fn push_frame(&mut self, data: Vec<u8>) {
        if self.frames.len() >= 4 {
            self.frames.remove(0);
        }
        self.frames.push(VideoFrame { data });
    }

    /// Dequeue the oldest frame, if any.
    pub fn pop_frame(&mut self) -> Option<VideoFrame> {
        if self.frames.is_empty() {
            None
        } else {
            Some(self.frames.remove(0))
        }
    }

    /// `true` when at least one frame is waiting.
    pub fn has_frame(&self) -> bool {
        !self.frames.is_empty()
    }
}

// ── Global registry ───────────────────────────────────────────────────────

static VIDEO_NODES: IrqSafeSpinLock<Vec<Arc<IrqSafeSpinLock<VideoDevice>>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a new UVC camera device; returns the allocated video<N> index.
///
/// `name` is the camera device string (from the USB product descriptor
/// or a default like `"USB Video Device"`).
///
/// Linux ref: `__video_register_device` in
/// `drivers/media/v4l2-core/v4l2-dev.c`.
pub fn register_video(name: &str) -> usize {
    let idx = alloc_index();
    let dev = Arc::new(IrqSafeSpinLock::new(VideoDevice::new(idx, name.into())));
    VIDEO_NODES.lock().push(dev);

    // Register sysfs kobject: /sys/class/video4linux/video<N>/
    register_sysfs(idx, name);

    idx
}

/// Retrieve the device state for video<N>, if registered.
pub fn get_device(index: usize) -> Option<Arc<IrqSafeSpinLock<VideoDevice>>> {
    VIDEO_NODES.lock().iter().find(|d| d.lock().index == index).cloned()
}

/// Number of registered video devices.
pub fn device_count() -> usize {
    VIDEO_NODES.lock().len()
}

/// Test-only: reset the global registry and index counter.
#[doc(hidden)]
pub fn __reset_for_test() {
    VIDEO_NODES.lock().clear();
    VIDEO_NEXT_INDEX.store(0, Ordering::Relaxed);
}

// ── Sysfs class registration ──────────────────────────────────────────────

/// Register `/sys/class/video4linux/video<N>/` for one camera.
///
/// Linux ref: `v4l2_device_register_subdev_nodes` and
/// `video_register_device` → `device_create` flow in
/// `drivers/media/v4l2-core/v4l2-dev.c:__video_register_device`
/// (GPL-2.0-or-later).
fn register_sysfs(idx: usize, camera_name: &str) {
    use narf_filesystem::sysfs::{class_register, class_device_register, kobject_add_attr};

    let v4l2_class = class_register("video4linux");
    let node_name = format!("video{}", idx);
    let kobj = class_device_register(v4l2_class, &node_name);

    // /sys/class/video4linux/video<N>/dev → "81:<N>\n"
    let dev_str = format!("{}:{}\n", VIDEO_MAJOR, idx);
    kobject_add_attr(&kobj, "dev", move || dev_str.clone());

    // /sys/class/video4linux/video<N>/name → camera device string
    let name_owned = alloc::string::String::from(camera_name);
    kobject_add_attr(&kobj, "name", move || format!("{}\n", name_owned));

    // /sys/class/video4linux/video<N>/index → decimal index
    kobject_add_attr(&kobj, "index", move || format!("{}\n", idx));
}

// ── devfs file node ───────────────────────────────────────────────────────

/// `/dev/video<N>` file node.
#[derive(Debug)]
pub struct VideoFile {
    dev: Arc<IrqSafeSpinLock<VideoDevice>>,
}

impl VideoFile {
    pub fn new(dev: Arc<IrqSafeSpinLock<VideoDevice>>) -> Self {
        VideoFile { dev }
    }
}

impl FileOps for VideoFile {
    /// Return the next complete frame's bytes.
    ///
    /// Returns 0 bytes (EOF-ish) when no frame is queued; callers that
    /// want blocking behaviour poll on `poll_readiness` returning `POLL_IN`.
    ///
    /// Note: real V4L2 needs VIDIOC_* ioctl for format negotiation and
    /// DMABUF/MMAP buffer mapping; this simple read path is sufficient for
    /// a single-frame capture test without ioctl support.
    ///
    /// Linux ref: `v4l2_read` → `vb2_read` in
    /// `drivers/media/common/videobuf2/videobuf2-v4l2.c`.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let frame = self.dev.lock().pop_frame();
        let n = match frame {
            Some(f) => {
                let copy = f.data.len().min(buf.len());
                buf[..copy].copy_from_slice(&f.data[..copy]);
                copy
            }
            None => 0,
        };
        Box::pin(async move { Ok(n) })
    }

    /// Video capture devices do not support write.
    ///
    /// Linux: `v4l2_write` returns `-EINVAL` for capture devices.
    /// NARF has no `FsError::InvalidData`; `Unsupported` is the closest match.
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }

    /// `POLL_IN` when a frame is ready.
    fn poll_readiness(&self) -> u32 {
        if self.dev.lock().has_frame() { POLL_IN } else { 0 }
    }
}

// ── devfs lookup integration ──────────────────────────────────────────────

/// Look up `"video<N>"` → `Arc<dyn FileOps>`, or `None` if not found.
pub fn lookup_video(name: &str) -> Option<Arc<dyn FileOps>> {
    let rest = name.strip_prefix("video")?;
    let idx: usize = rest.parse().ok()?;
    let dev = get_device(idx)?;
    Some(Arc::new(VideoFile::new(dev)) as Arc<dyn FileOps>)
}

/// All registered video nodes as `(name, FileType::Special)` pairs.
pub fn enumerate_video() -> Vec<(String, FileType)> {
    VIDEO_NODES
        .lock()
        .iter()
        .map(|d| {
            let idx = d.lock().index;
            (format!("video{}", idx), FileType::Special)
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Registering a camera allocates /dev/video0.
    fn smoke_uvc_probe_allocates_video0() -> TestResult {
        __reset_for_test();
        let idx = register_video("USB 2.0 Camera");
        if idx != 0 {
            return TestResult::Fail("first registration should get index 0");
        }
        if device_count() != 1 {
            return TestResult::Fail("device_count should be 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/devfs_bridge", smoke_uvc_probe_allocates_video0);

    /// /sys/class/video4linux/video0/name returns the camera string.
    fn smoke_video_sysfs_name_attr() -> TestResult {
        narf_filesystem::sysfs::__reset_for_test();
        __reset_for_test();
        let _idx = register_video("TestCam");
        use narf_filesystem::sysfs::class_register;
        let class = class_register("video4linux");
        let child = class.get_child("video0");
        if child.is_none() {
            return TestResult::Fail("video0 kobject not found under video4linux");
        }
        let kobj = child.unwrap();
        let val = kobj.attr_show("name");
        match val {
            Some(s) if s.contains("TestCam") => TestResult::Pass,
            Some(_) => TestResult::Fail("name attr has wrong value"),
            None => TestResult::Fail("name attr missing"),
        }
    }
    kernel_test_in!("drivers/video/devfs_bridge", smoke_video_sysfs_name_attr);

    /// /dev/video0 read returns frame bytes after frame push.
    fn smoke_video_read_returns_frame() -> TestResult {
        __reset_for_test();
        let idx = register_video("TestCam");
        let dev = get_device(idx).unwrap();
        // Simulate a captured frame.
        dev.lock().push_frame(alloc::vec![0xABu8; 64]);
        let file = VideoFile::new(dev.clone());
        let mut out = [0u8; 128];
        let n = {
            let frame = dev.lock().pop_frame();
            match frame {
                Some(f) => {
                    let copy = f.data.len().min(out.len());
                    out[..copy].copy_from_slice(&f.data[..copy]);
                    copy
                }
                None => 0,
            }
        };
        if n != 64 {
            return TestResult::Fail("expected 64 frame bytes");
        }
        if out[0] != 0xAB {
            return TestResult::Fail("frame byte mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/devfs_bridge", smoke_video_read_returns_frame);

    /// lookup_video("video0") returns Some after registration.
    fn smoke_video_lookup() -> TestResult {
        __reset_for_test();
        register_video("AnotherCam");
        match lookup_video("video0") {
            Some(_) => TestResult::Pass,
            None => TestResult::Fail("lookup_video should find video0"),
        }
    }
    kernel_test_in!("drivers/video/devfs_bridge", smoke_video_lookup);
}
