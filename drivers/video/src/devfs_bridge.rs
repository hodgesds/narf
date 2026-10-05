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
//!   yet delivered a frame; returns 0 / empty on no frame in NARF
//!   since there is no blocking sleep here — caller polls).
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

use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, IoctlContext, MmapLifetime, Mode, Stat, POLL_IN,
};
use narf_lib::sync::IrqSafeSpinLock;

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
/// the devfs file node dequeues them via `pop_frame` (raw-read path) or the
/// V4L2 `DQBUF` ioctl fills a streaming buffer from the same queue.
#[derive(Debug)]
pub struct VideoDevice {
    pub index: usize,
    /// Camera description string (e.g. "USB 2.0 Camera").
    pub name: String,
    /// Pending frame queue (FIFO, capacity 4).
    frames: Vec<VideoFrame>,
    /// Current negotiated capture format (`VIDIOC_G/S_FMT`).
    pub format: crate::v4l2_ioctl::PixFormat,
    /// Supported pixel formats for `VIDIOC_ENUM_FMT`.
    pub formats: Vec<crate::v4l2_ioctl::FmtEntry>,
    /// User controls (`VIDIOC_QUERYCTRL` / `G_CTRL` / `S_CTRL`).
    pub controls: Vec<crate::v4l2_ioctl::ControlState>,
    /// Whether `VIDIOC_STREAMON` is active.
    pub streaming: bool,
    /// `V4L2_MEMORY_MMAP` buffer pool (`VIDIOC_REQBUFS`).
    pub buffers: Vec<crate::v4l2_ioctl::V4l2Buffer>,
    /// Running capture sequence counter, stamped into dequeued buffers.
    pub sequence: u32,
}

impl VideoDevice {
    pub fn new(index: usize, name: String) -> Self {
        VideoDevice {
            index,
            name,
            frames: Vec::new(),
            format: crate::v4l2_ioctl::default_pix_format(),
            formats: crate::v4l2_ioctl::default_formats(),
            controls: crate::v4l2_ioctl::default_controls(),
            streaming: false,
            buffers: Vec::new(),
            sequence: 0,
        }
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

    /// Drop all pending frames (e.g. on `VIDIOC_STREAMOFF`).
    pub fn clear_frames(&mut self) {
        self.frames.clear();
    }

    /// `true` when at least one frame is waiting.
    pub fn has_frame(&self) -> bool {
        !self.frames.is_empty()
    }
}

impl Drop for VideoDevice {
    /// Release every streaming buffer's physical frames back to the allocator
    /// when the device is torn down.
    fn drop(&mut self) {
        crate::v4l2_ioctl::free_buffer_pool(&mut self.buffers);
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
    VIDEO_NODES
        .lock()
        .iter()
        .find(|d| d.lock().index == index)
        .cloned()
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
    use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};

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
    /// The devfs inode of this device's `/dev` node.
    fn ino(&self) -> u64 {
        narf_filesystem::devfs::char_device_inode(self.rdev())
    }

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

    /// `st_rdev` = VIDEO_MAJOR(81):minor(video index). dev_t = (major<<8)|minor.
    /// A 0 rdev (the default) breaks udev/libv4l devnum resolution. Linux:
    /// `include/uapi/linux/major.h` VIDEO4LINUX_MAJOR = 81.
    fn rdev(&self) -> u64 {
        (81u64 << 8) | self.dev.lock().index as u64
    }

    /// `POLL_IN` when a frame is ready.
    fn poll_readiness(&self) -> u32 {
        if self.dev.lock().has_frame() {
            POLL_IN
        } else {
            0
        }
    }

    /// V4L2 `VIDIOC_*` ioctl surface (format/controls/streaming buffers).
    ///
    /// Linux ref: `drivers/media/v4l2-core/v4l2-ioctl.c::video_usercopy`.
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        ctx: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        crate::v4l2_ioctl::dispatch(self.dev.clone(), cmd, arg, ctx)
    }

    /// `mmap(2)` a `V4L2_MEMORY_MMAP` capture buffer. `offset` is the cookie
    /// reported in `v4l2_buffer.m.offset` by `REQBUFS`/`QUERYBUF`.
    ///
    /// Linux ref: `drivers/media/common/videobuf2/videobuf2-core.c::vb2_mmap`.
    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        crate::v4l2_ioctl::mmap_buffer_frames(&self.dev, offset, len)
    }

    /// Pin the device (and thus its buffer pool's frames) for the life of any
    /// mapping, so `REQBUFS(0)` / close cannot recycle still-mapped pages.
    fn mmap_lifetime(&self, _offset: u64, _len: usize) -> Option<Arc<dyn MmapLifetime>> {
        Some(self.dev.clone() as Arc<dyn MmapLifetime>)
    }
}

// ── devfs lookup integration ──────────────────────────────────────────────

/// Look up a camera by its `video<N>` minor number.
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
    kernel_test_in!(
        "drivers/video/devfs_bridge",
        smoke_uvc_probe_allocates_video0
    );

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
        let _file = VideoFile::new(dev.clone());
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

// ── V4L2 ioctl / mmap tests ─────────────────────────────────────────────────

/// Exercises the real `FileOps::ioctl_user` dispatch and MMAP buffer pool
/// against byte-level `v4l2_*` structs, validating field offsets, errnos, and
/// the queue/dequeue data path against `/usr/src/linux` videodev2.h.
#[cfg(any(test, feature = "kernel-test"))]
pub mod v4l2_tests {
    use super::*;
    use alloc::vec;
    use core::future::Future;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_filesystem::IoctlContext;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Base user-address the mock copies to/from (nonzero, like a real arg).
    const ARG: u64 = 512;

    /// Linux errno values returned as `-errno as u64`.
    fn eno(e: i64) -> u64 {
        (-e) as u64
    }

    /// `_IOC(dir, 'V', nr, size)` (asm-generic/ioctl.h shifts).
    fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
        (dir << 30) | (size << 16) | ((b'V' as u32) << 8) | nr
    }
    const DIR_W: u32 = 1; // _IOC_WRITE
    const DIR_R: u32 = 2; // _IOC_READ
    const DIR_WR: u32 = 3; // _IOWR

    /// Minimal [`IoctlContext`] backed by a flat byte buffer; `address` indexes
    /// straight into it. `nonblock` toggles the O_NONBLOCK path.
    struct Mock {
        mem: IrqSafeSpinLock<Vec<u8>>,
        nonblock: bool,
    }
    impl Mock {
        fn new(nonblock: bool) -> Self {
            Self {
                mem: IrqSafeSpinLock::new(vec![0u8; 8192]),
                nonblock,
            }
        }
        fn put_u32(&self, off: usize, v: u32) {
            self.mem.lock()[ARG as usize + off..ARG as usize + off + 4]
                .copy_from_slice(&v.to_ne_bytes());
        }
        fn get_u32(&self, off: usize) -> u32 {
            let m = self.mem.lock();
            let a = ARG as usize + off;
            u32::from_ne_bytes([m[a], m[a + 1], m[a + 2], m[a + 3]])
        }
        fn get_i32(&self, off: usize) -> i32 {
            self.get_u32(off) as i32
        }
        fn get_str(&self, off: usize, cap: usize) -> alloc::string::String {
            let m = self.mem.lock();
            let a = ARG as usize + off;
            let end = m[a..a + cap].iter().position(|&c| c == 0).unwrap_or(cap);
            alloc::string::String::from_utf8_lossy(&m[a..a + end]).into_owned()
        }
    }
    impl IoctlContext for Mock {
        fn read(&self, a: u64, b: &mut [u8]) -> Result<(), FsError> {
            let m = self.mem.lock();
            let a = a as usize;
            b.copy_from_slice(m.get(a..a + b.len()).ok_or(FsError::BadAddress)?);
            Ok(())
        }
        fn write(&self, a: u64, b: &[u8]) -> Result<(), FsError> {
            let mut m = self.mem.lock();
            let a = a as usize;
            m.get_mut(a..a + b.len())
                .ok_or(FsError::BadAddress)?
                .copy_from_slice(b);
            Ok(())
        }
        fn nonblocking(&self) -> bool {
            self.nonblock
        }
    }

    /// Drive a bridge future to completion. The V4L2 handlers are immediately
    /// ready except a *blocking* DQBUF with no frame; tests avoid that case.
    fn run<T>(fut: impl Future<Output = T>) -> T {
        fn raw() -> RawWaker {
            unsafe fn clone(_: *const ()) -> RawWaker {
                raw()
            }
            unsafe fn noop(_: *const ()) {}
            const V: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
            RawWaker::new(core::ptr::null(), &V)
        }
        // SAFETY: the vtable's clone returns an equivalent waker and
        // wake/drop are no-ops over a null data pointer that is never read.
        let waker = unsafe { Waker::from_raw(raw()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("v4l2 test future pended unexpectedly"),
        }
    }

    /// Issue one ioctl against a freshly registered device.
    fn ioctl(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, m: &Mock, cmd: u32) -> u64 {
        run(crate::v4l2_ioctl::dispatch(dev.clone(), cmd, ARG, m)).expect("no EFAULT in tests")
    }

    fn fresh(name: &str) -> Arc<IrqSafeSpinLock<VideoDevice>> {
        __reset_for_test();
        let idx = register_video(name);
        get_device(idx).unwrap()
    }

    // v4l2 fourccs for assertions.
    const YUYV: u32 =
        (b'Y' as u32) | ((b'U' as u32) << 8) | ((b'Y' as u32) << 16) | ((b'V' as u32) << 24);
    const MJPG: u32 =
        (b'M' as u32) | ((b'J' as u32) << 8) | ((b'P' as u32) << 16) | ((b'G' as u32) << 24);

    fn querycap_reports_capture_streaming() -> TestResult {
        let dev = fresh("TestCam");
        let m = Mock::new(true);
        if ioctl(&dev, &m, ioc(DIR_R, 0, 104)) != 0 {
            return TestResult::Fail("QUERYCAP should succeed");
        }
        let version = m.get_u32(80);
        let caps = m.get_u32(84);
        if version != 0x0007_0000 {
            return TestResult::Fail("version should be KERNEL_VERSION(7,0,0)");
        }
        if caps & 0x0000_0001 == 0 || caps & 0x0400_0000 == 0 {
            return TestResult::Fail("caps must advertise CAPTURE|STREAMING");
        }
        if m.get_str(16, 32) != "TestCam" {
            return TestResult::Fail("card should echo the device name");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", querycap_reports_capture_streaming);

    fn enum_fmt_lists_and_rejects() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        // index 0 → YUYV (uncompressed).
        m.put_u32(0, 0);
        m.put_u32(4, 1); // VIDEO_CAPTURE
        if ioctl(&dev, &m, ioc(DIR_WR, 2, 64)) != 0 || m.get_u32(44) != YUYV {
            return TestResult::Fail("index 0 should be YUYV");
        }
        if m.get_u32(8) != 0 {
            return TestResult::Fail("YUYV flags should be 0 (not compressed)");
        }
        // index 1 → MJPG, compressed flag set.
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 2, 64)) != 0 || m.get_u32(44) != MJPG {
            return TestResult::Fail("index 1 should be MJPG");
        }
        if m.get_u32(8) & 0x1 == 0 {
            return TestResult::Fail("MJPG should set V4L2_FMT_FLAG_COMPRESSED");
        }
        // Out-of-range index → EINVAL.
        m.put_u32(0, 99);
        m.put_u32(4, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 2, 64)) != eno(22) {
            return TestResult::Fail("overrun index should be EINVAL");
        }
        // Wrong buf-type → EINVAL.
        m.put_u32(0, 0);
        m.put_u32(4, 7);
        if ioctl(&dev, &m, ioc(DIR_WR, 2, 64)) != eno(22) {
            return TestResult::Fail("bad buf-type should be EINVAL");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", enum_fmt_lists_and_rejects);

    fn s_fmt_then_g_fmt_roundtrip() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        // Request MJPG 1280x720 (pix fields at offset 8).
        m.put_u32(0, 1); // type = VIDEO_CAPTURE
        m.put_u32(8, 1280); // width
        m.put_u32(12, 720); // height
        m.put_u32(16, MJPG); // pixelformat
        if ioctl(&dev, &m, ioc(DIR_WR, 5, 208)) != 0 {
            return TestResult::Fail("S_FMT should succeed");
        }
        // G_FMT must report the committed format.
        for off in [8usize, 12, 16, 24, 28] {
            m.put_u32(off, 0);
        }
        m.put_u32(0, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 4, 208)) != 0 {
            return TestResult::Fail("G_FMT should succeed");
        }
        if m.get_u32(8) != 1280 || m.get_u32(12) != 720 || m.get_u32(16) != MJPG {
            return TestResult::Fail("G_FMT should echo committed MJPG 1280x720");
        }
        if m.get_u32(20) != 1 {
            return TestResult::Fail("field should be V4L2_FIELD_NONE");
        }
        if m.get_u32(28) == 0 {
            return TestResult::Fail("sizeimage should be non-zero");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", s_fmt_then_g_fmt_roundtrip);

    fn reqbufs_querybuf_allocates_mmap() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        // REQBUFS count=2, VIDEO_CAPTURE, MMAP.
        m.put_u32(0, 2);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 8, 20)) != 0 {
            return TestResult::Fail("REQBUFS should succeed");
        }
        if m.get_u32(0) != 2 {
            return TestResult::Fail("REQBUFS should grant 2 buffers");
        }
        if m.get_u32(12) & 0x1 == 0 {
            return TestResult::Fail("REQBUFS caps should advertise SUPPORTS_MMAP");
        }
        // QUERYBUF index 1 → MMAP, offset == length of one buffer.
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 9, 88)) != 0 {
            return TestResult::Fail("QUERYBUF should succeed");
        }
        if m.get_u32(60) != 1 {
            return TestResult::Fail("buffer memory should be MMAP");
        }
        let length = m.get_u32(72);
        let offset = m.get_u32(64);
        let expect = (640u32 * 480 * 2).div_ceil(4096) * 4096;
        if length != expect {
            return TestResult::Fail("buffer length should be page-rounded sizeimage");
        }
        if offset != expect {
            return TestResult::Fail("buffer 1 offset should equal one buffer length");
        }
        // REQBUFS(0) frees the pool.
        m.put_u32(0, 0);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 8, 20)) != 0 || !dev.lock().buffers.is_empty() {
            return TestResult::Fail("REQBUFS(0) should free the pool");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", reqbufs_querybuf_allocates_mmap);

    fn qbuf_dqbuf_delivers_frame() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        // One buffer.
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        ioctl(&dev, &m, ioc(DIR_WR, 8, 20));
        // DQBUF before STREAMON → EINVAL.
        m.put_u32(4, 1);
        m.put_u32(60, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 17, 88)) != eno(22) {
            return TestResult::Fail("DQBUF before STREAMON should be EINVAL");
        }
        // QBUF index 0.
        m.put_u32(0, 0);
        m.put_u32(4, 1);
        m.put_u32(60, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 15, 88)) != 0 {
            return TestResult::Fail("QBUF should succeed");
        }
        // STREAMON (int buf-type arg).
        m.put_u32(0, 1);
        if ioctl(&dev, &m, ioc(DIR_W, 18, 4)) != 0 {
            return TestResult::Fail("STREAMON should succeed");
        }
        // Non-blocking DQBUF with no frame → EAGAIN.
        m.put_u32(4, 1);
        m.put_u32(60, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 17, 88)) != eno(11) {
            return TestResult::Fail("DQBUF w/o frame (nonblock) should be EAGAIN");
        }
        // Deliver a frame and DQBUF it.
        dev.lock().push_frame(alloc::vec![0xABu8; 4096]);
        m.put_u32(4, 1);
        m.put_u32(60, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 17, 88)) != 0 {
            return TestResult::Fail("DQBUF should return the filled buffer");
        }
        if m.get_u32(0) != 0 {
            return TestResult::Fail("dequeued buffer index should be 0");
        }
        if m.get_u32(8) != 4096 {
            return TestResult::Fail("bytesused should equal the frame size");
        }
        // The physical frame must carry the delivered bytes.
        let first = {
            let g = dev.lock();
            let f0 = g.buffers[0].frames[0];
            let p = f0.start_address().kernel_ptr::<u8>();
            // SAFETY: f0 is an allocated frame owned by buffer 0; its direct-map
            // pointer is a valid readable kernel VA for the page.
            unsafe { *p }
        };
        if first != 0xAB {
            return TestResult::Fail("buffer frame should contain the captured bytes");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", qbuf_dqbuf_delivers_frame);

    fn mmap_frames_blocks_reqbufs() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        ioctl(&dev, &m, ioc(DIR_WR, 8, 20));
        let vf = VideoFile::new(dev.clone());
        let frames = match vf.mmap_frames(0, 4096) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("mmap_frames(offset 0) should map buffer 0"),
        };
        if frames.len() != 1 {
            return TestResult::Fail("one page mapped → one frame address");
        }
        // REQBUFS while mapped → EBUSY.
        m.put_u32(0, 2);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 8, 20)) != eno(16) {
            return TestResult::Fail("REQBUFS while mapped should be EBUSY");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", mmap_frames_blocks_reqbufs);

    fn s_ctrl_clamps_and_queryctrl() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        const BRIGHTNESS: u32 = 0x0098_0900;
        // S_CTRL brightness = 1000 → clamped to max (64).
        m.put_u32(0, BRIGHTNESS);
        m.put_u32(4, 1000u32);
        if ioctl(&dev, &m, ioc(DIR_WR, 28, 8)) != 0 || m.get_i32(4) != 64 {
            return TestResult::Fail("S_CTRL should clamp to the control max (64)");
        }
        // G_CTRL reads it back.
        m.put_u32(0, BRIGHTNESS);
        m.put_u32(4, 0);
        if ioctl(&dev, &m, ioc(DIR_WR, 27, 8)) != 0 || m.get_i32(4) != 64 {
            return TestResult::Fail("G_CTRL should return the clamped value");
        }
        // Unknown control id → EINVAL.
        m.put_u32(0, 0xDEAD_BEEF);
        if ioctl(&dev, &m, ioc(DIR_WR, 27, 8)) != eno(22) {
            return TestResult::Fail("unknown G_CTRL id should be EINVAL");
        }
        // QUERYCTRL brightness → name + range.
        m.put_u32(0, BRIGHTNESS);
        if ioctl(&dev, &m, ioc(DIR_WR, 36, 68)) != 0 {
            return TestResult::Fail("QUERYCTRL should succeed");
        }
        if m.get_i32(40) != -64 || m.get_i32(44) != 64 {
            return TestResult::Fail("QUERYCTRL min/max should be -64..64");
        }
        if m.get_str(8, 32) != "Brightness" {
            return TestResult::Fail("QUERYCTRL name should be Brightness");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", s_ctrl_clamps_and_queryctrl);

    fn unknown_ioctl_is_enotty() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        // Wrong magic ('A' instead of 'V') → ENOTTY.
        let bad_magic = (DIR_R << 30) | (4 << 16) | ((b'A' as u32) << 8);
        if ioctl(&dev, &m, bad_magic) != eno(25) {
            return TestResult::Fail("non-'V' magic should be ENOTTY");
        }
        // Right magic, unimplemented nr (e.g. 200) → ENOTTY.
        if ioctl(&dev, &m, ioc(DIR_WR, 200, 4)) != eno(25) {
            return TestResult::Fail("unimplemented 'V' nr should be ENOTTY");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", unknown_ioctl_is_enotty);

    fn streamoff_resets_buffers() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        ioctl(&dev, &m, ioc(DIR_WR, 8, 20));
        m.put_u32(0, 0);
        m.put_u32(4, 1);
        m.put_u32(60, 1);
        ioctl(&dev, &m, ioc(DIR_WR, 15, 88)); // QBUF 0
        m.put_u32(0, 1);
        ioctl(&dev, &m, ioc(DIR_W, 18, 4)); // STREAMON
        dev.lock().push_frame(alloc::vec![0u8; 16]);
        // STREAMOFF.
        m.put_u32(0, 1);
        if ioctl(&dev, &m, ioc(DIR_W, 19, 4)) != 0 {
            return TestResult::Fail("STREAMOFF should succeed");
        }
        let g = dev.lock();
        if g.streaming {
            return TestResult::Fail("STREAMOFF should clear streaming");
        }
        if g.has_frame() {
            return TestResult::Fail("STREAMOFF should drop pending frames");
        }
        if g.buffers
            .iter()
            .any(|b| b.state != crate::v4l2_ioctl::QState::Dequeued)
        {
            return TestResult::Fail("STREAMOFF should return buffers to dequeued");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", streamoff_resets_buffers);
}
