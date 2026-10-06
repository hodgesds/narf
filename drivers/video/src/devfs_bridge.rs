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
    FileOps, FileType, FsError, FsFuture, IoctlContext, MmapLifetime, Mode, Stat, POLL_IN, POLL_PRI,
};
use narf_lib::readiness::Readiness;
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
    /// Poll/epoll readiness cell. `POLL_IN` is raised when a frame is ready
    /// (a `Done` MMAP buffer or a queued raw-read frame) and cleared when
    /// drained. Shared (`Arc`) with every [`VideoFile`] so `FileOps::readiness`
    /// can borrow it without taking the device lock.
    pub readiness: Arc<Readiness>,
}

impl VideoDevice {
    pub fn new(index: usize, name: String) -> Self {
        Self::with_formats(index, name, crate::v4l2_ioctl::default_formats())
    }

    /// Construct a device advertising `formats` (from the UVC descriptor walk).
    /// The initial capture format is the first format's first frame size.
    pub fn with_formats(
        index: usize,
        name: String,
        formats: Vec<crate::v4l2_ioctl::FmtEntry>,
    ) -> Self {
        let format = crate::v4l2_ioctl::pix_format_from(&formats);
        VideoDevice {
            index,
            name,
            frames: Vec::new(),
            format,
            formats,
            controls: crate::v4l2_ioctl::default_controls(),
            streaming: false,
            buffers: Vec::new(),
            sequence: 0,
            readiness: Arc::new(Readiness::new(0)),
        }
    }

    /// Enqueue a complete frame. Drops oldest if over capacity (4).
    pub fn push_frame(&mut self, data: Vec<u8>) {
        if self.frames.len() >= 4 {
            self.frames.remove(0);
        }
        self.frames.push(VideoFrame { data });
    }

    /// Deliver a freshly captured frame from the driver's capture pump.
    ///
    /// While streaming with a queued MMAP buffer, the frame is copied straight
    /// into that buffer and stamped with a monotonic capture timestamp (the
    /// live `DQBUF` path). Otherwise it falls back to the raw-read FIFO. Either
    /// way `POLL_IN` is raised so blocked `poll`/`select`/`epoll`/`DQBUF`
    /// waiters wake.
    pub fn deliver_frame(&mut self, data: Vec<u8>) {
        let ts = narf_time::monotonic_ns();
        if self.streaming && crate::v4l2_ioctl::fill_queued_buffer(self, &data, ts) {
            self.refresh_readiness();
            return;
        }
        self.push_frame(data);
        self.refresh_readiness();
    }

    /// Recompute the `POLL_IN` readiness level from the current frame/buffer
    /// state. Called after every produce/consume transition.
    pub fn refresh_readiness(&self) {
        let ready = !self.frames.is_empty()
            || self
                .buffers
                .iter()
                .any(|b| b.state == crate::v4l2_ioctl::QState::Done);
        if ready {
            self.readiness.set(POLL_IN, 0);
        } else {
            self.readiness.set(0, POLL_IN);
        }
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

/// Register a camera advertising a real format table parsed from its UVC
/// streaming descriptors (see [`crate::v4l2_ioctl::uvc_to_v4l2_formats`]).
/// An empty `formats` falls back to [`crate::v4l2_ioctl::default_formats`], so
/// a parse failure still yields a usable node.
pub fn register_video_with_formats(name: &str, formats: Vec<crate::v4l2_ioctl::FmtEntry>) -> usize {
    let idx = alloc_index();
    let formats = if formats.is_empty() {
        crate::v4l2_ioctl::default_formats()
    } else {
        formats
    };
    let dev = Arc::new(IrqSafeSpinLock::new(VideoDevice::with_formats(
        idx,
        name.into(),
        formats,
    )));
    VIDEO_NODES.lock().push(dev);
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
    /// Shared readiness cell (cloned from the device) so `readiness()` can
    /// return a borrow without taking the device lock.
    readiness: Arc<Readiness>,
    /// Per-open-file V4L2 event state (`SUBSCRIBE_EVENT`/`DQEVENT`). Minted
    /// fresh per `open` by [`VideoFile::open_instance_checked`].
    events: Arc<IrqSafeSpinLock<crate::v4l2_ioctl::FdEvents>>,
}

impl VideoFile {
    pub fn new(dev: Arc<IrqSafeSpinLock<VideoDevice>>) -> Self {
        let readiness = dev.lock().readiness.clone();
        VideoFile {
            dev,
            readiness,
            events: Arc::new(IrqSafeSpinLock::new(crate::v4l2_ioctl::FdEvents::new())),
        }
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
        let n = {
            let mut dev = self.dev.lock();
            let frame = dev.pop_frame();
            let n = match frame {
                Some(f) => {
                    let copy = f.data.len().min(buf.len());
                    buf[..copy].copy_from_slice(&f.data[..copy]);
                    copy
                }
                None => 0,
            };
            dev.refresh_readiness();
            n
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

    /// Current readiness level: `POLL_IN` when a captured frame is ready
    /// (a `Done` MMAP buffer or a queued raw-read frame), plus `POLL_PRI` when
    /// a V4L2 event is pending for this fd (`DQEVENT`).
    fn poll_readiness(&self) -> u32 {
        let mut mask = self.readiness.mask();
        if self.events.lock().has_events() {
            mask |= POLL_PRI;
        }
        mask
    }

    /// Durable readiness cell so the VFS poll/epoll layer parks on and is woken
    /// by the capture pump's `deliver_frame` rather than busy-polling.
    fn readiness(&self) -> Option<&Readiness> {
        Some(&self.readiness)
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
        crate::v4l2_ioctl::dispatch(self.dev.clone(), cmd, arg, ctx, self.events.clone())
    }

    /// Mint a fresh per-open instance so each descriptor gets its own V4L2
    /// event subscription queue (`v4l2_fh`), while sharing the device and its
    /// readiness cell.
    ///
    /// Linux ref: `v4l2_open` → `v4l2_fh_init` per `struct file`.
    fn open_instance_checked(&self, _write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        Ok(Some(
            Arc::new(VideoFile::new(self.dev.clone())) as Arc<dyn FileOps>
        ))
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
        /// Files "installed" via `install_file`, indexed by returned fd.
        installed: IrqSafeSpinLock<Vec<Arc<dyn FileOps>>>,
    }
    impl Mock {
        fn new(nonblock: bool) -> Self {
            Self {
                mem: IrqSafeSpinLock::new(vec![0u8; 8192]),
                nonblock,
                installed: IrqSafeSpinLock::new(Vec::new()),
            }
        }
        fn installed_file(&self, fd: i32) -> Arc<dyn FileOps> {
            self.installed.lock()[fd as usize].clone()
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
        fn install_file(&self, file: Arc<dyn FileOps>, _cloexec: bool) -> Result<i32, FsError> {
            let mut t = self.installed.lock();
            let fd = t.len() as i32;
            t.push(file);
            Ok(fd)
        }
        fn file(&self, fd: i32) -> Result<Arc<dyn FileOps>, FsError> {
            self.installed
                .lock()
                .get(fd as usize)
                .cloned()
                .ok_or(FsError::BadFd)
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

    /// Issue one ioctl against a freshly registered device with a throwaway
    /// per-fd event queue (fine for everything but the event tests).
    fn ioctl(dev: &Arc<IrqSafeSpinLock<VideoDevice>>, m: &Mock, cmd: u32) -> u64 {
        let events = Arc::new(IrqSafeSpinLock::new(crate::v4l2_ioctl::FdEvents::new()));
        ioctl_ev(dev, m, cmd, &events)
    }

    /// Issue one ioctl against a device with an explicit (persistent) per-fd
    /// event queue, so subscribe → change → DQEVENT can be exercised.
    fn ioctl_ev(
        dev: &Arc<IrqSafeSpinLock<VideoDevice>>,
        m: &Mock,
        cmd: u32,
        events: &Arc<IrqSafeSpinLock<crate::v4l2_ioctl::FdEvents>>,
    ) -> u64 {
        run(crate::v4l2_ioctl::dispatch(
            dev.clone(),
            cmd,
            ARG,
            m,
            events.clone(),
        ))
        .expect("no EFAULT in tests")
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

    /// A device registered from parsed UVC descriptors advertises those real
    /// formats/resolutions (not the synthetic default table).
    fn register_with_formats_advertises_real() -> TestResult {
        use crate::uvc::{FrameMode, PixelFmt, StreamFormat};
        __reset_for_test();
        let uvc = alloc::vec![StreamFormat {
            format_index: 1,
            pixel_fmt: PixelFmt::Mjpeg,
            default_frame_index: 1,
            frames: alloc::vec![FrameMode {
                frame_index: 1,
                width: 1920,
                height: 1080,
                frame_intervals: alloc::vec![333_333], // 30 fps in 100 ns units
                continuous_min: None,
                continuous_max: None,
                continuous_step: None,
                default_frame_interval: 333_333,
            }],
        }];
        let table = crate::v4l2_ioctl::uvc_to_v4l2_formats(&uvc);
        let idx = register_video_with_formats("RealCam", table);
        let dev = get_device(idx).unwrap();
        let m = Mock::new(true);
        // ENUM_FMT index 0 → MJPG.
        m.put_u32(0, 0);
        m.put_u32(4, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 2, 64)) != 0 || m.get_u32(44) != MJPG {
            return TestResult::Fail("ENUM_FMT[0] should be the descriptor's MJPG");
        }
        // ENUM_FRAMESIZES[0] for MJPG → 1920x1080 (discrete).
        for off in 0..11 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(0, 0);
        m.put_u32(4, MJPG);
        if ioctl(&dev, &m, ioc(DIR_WR, 74, 44)) != 0
            || m.get_u32(12) != 1920
            || m.get_u32(16) != 1080
        {
            return TestResult::Fail("ENUM_FRAMESIZES should report 1920x1080");
        }
        // Initial G_FMT should be the first real format (MJPG 1920x1080).
        for off in [8usize, 12, 16] {
            m.put_u32(off, 0);
        }
        m.put_u32(0, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 4, 208)) != 0
            || m.get_u32(16) != MJPG
            || m.get_u32(8) != 1920
            || m.get_u32(12) != 1080
        {
            return TestResult::Fail("initial G_FMT should match the first real format");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", register_with_formats_advertises_real);

    /// deliver_frame fills a queued buffer, raises POLL_IN, stamps a capture
    /// timestamp, and the readiness clears once the buffer is dequeued.
    fn deliver_frame_readiness_and_timestamp() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        // One MMAP buffer, queued, streaming.
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        ioctl(&dev, &m, ioc(DIR_WR, 8, 20)); // REQBUFS
        m.put_u32(0, 0);
        m.put_u32(4, 1);
        m.put_u32(60, 1);
        ioctl(&dev, &m, ioc(DIR_WR, 15, 88)); // QBUF 0
        m.put_u32(0, 1);
        ioctl(&dev, &m, ioc(DIR_W, 18, 4)); // STREAMON

        if dev.lock().readiness.mask() & POLL_IN != 0 {
            return TestResult::Fail("no frame yet → POLL_IN must be clear");
        }
        // Live delivery from the capture pump.
        dev.lock().deliver_frame(alloc::vec![0xCDu8; 4096]);
        if dev.lock().readiness.mask() & POLL_IN == 0 {
            return TestResult::Fail("deliver_frame should raise POLL_IN");
        }
        // Non-blocking DQBUF returns the live buffer with a capture timestamp.
        m.put_u32(4, 1);
        m.put_u32(60, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 17, 88)) != 0 {
            return TestResult::Fail("DQBUF should return the delivered buffer");
        }
        if m.get_u32(8) != 4096 {
            return TestResult::Fail("bytesused should be the frame length");
        }
        // timestamp.tv_sec (@24) | tv_usec (@32) must be non-zero (monotonic).
        if m.get_u32(24) | m.get_u32(28) | m.get_u32(32) | m.get_u32(36) == 0 {
            return TestResult::Fail("DQBUF should carry a monotonic timestamp");
        }
        // Buffer consumed → readiness clears.
        if dev.lock().readiness.mask() & POLL_IN != 0 {
            return TestResult::Fail("POLL_IN should clear after the last DQBUF");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", deliver_frame_readiness_and_timestamp);

    /// EXT_CTRLS: set/get via the pointed-to control array, with clamping and
    /// an error_idx on an unknown id.
    fn ext_ctrls_get_set_clamp() -> TestResult {
        const BRIGHTNESS: u32 = 0x0098_0900;
        let dev = fresh("c");
        let m = Mock::new(true);
        // The v4l2_ext_control array lives at ARG + 256 (a distinct user ptr).
        let ctrl_off = 256usize;
        let ctrl_addr = ARG + ctrl_off as u64;
        let setup = |which: u32| {
            m.put_u32(0, which); // which
            m.put_u32(4, 1); // count
            m.put_u32(8, 0); // error_idx
            m.put_u32(12, 0); // request_fd
            m.put_u32(16, 0); // reserved
            m.put_u32(24, ctrl_addr as u32); // controls ptr (low)
            m.put_u32(28, (ctrl_addr >> 32) as u32); // controls ptr (high)
            m.put_u32(ctrl_off, BRIGHTNESS); // v4l2_ext_control.id
            m.put_u32(ctrl_off + 4, 0); // size
            m.put_u32(ctrl_off + 8, 0); // reserved2
        };
        // S_EXT_CTRLS brightness = 50 (within [-64,64]).
        setup(0);
        m.put_u32(ctrl_off + 12, 50);
        if ioctl(&dev, &m, ioc(DIR_WR, 72, 32)) != 0 || m.get_i32(ctrl_off + 12) != 50 {
            return TestResult::Fail("S_EXT_CTRLS should set brightness to 50");
        }
        // G_EXT_CTRLS reads it back.
        setup(0);
        m.put_u32(ctrl_off + 12, 0);
        if ioctl(&dev, &m, ioc(DIR_WR, 71, 32)) != 0 || m.get_i32(ctrl_off + 12) != 50 {
            return TestResult::Fail("G_EXT_CTRLS should return 50");
        }
        // S_EXT_CTRLS brightness = 1000 → clamped to max (64).
        setup(0);
        m.put_u32(ctrl_off + 12, 1000);
        if ioctl(&dev, &m, ioc(DIR_WR, 72, 32)) != 0 || m.get_i32(ctrl_off + 12) != 64 {
            return TestResult::Fail("S_EXT_CTRLS should clamp to 64");
        }
        // Unknown id → EINVAL with error_idx = 0.
        setup(0);
        m.put_u32(ctrl_off, 0xDEAD_BEEF);
        if ioctl(&dev, &m, ioc(DIR_WR, 71, 32)) != eno(22) || m.get_u32(8) != 0 {
            return TestResult::Fail("unknown id should be EINVAL with error_idx 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", ext_ctrls_get_set_clamp);

    /// Subscribe to a control's events, change it, and dequeue the resulting
    /// V4L2_EVENT_CTRL; the queue then reports ENOENT.
    fn events_subscribe_ctrl_dqevent() -> TestResult {
        const BRIGHTNESS: u32 = 0x0098_0900;
        let dev = fresh("c");
        let m = Mock::new(true);
        let events = Arc::new(IrqSafeSpinLock::new(crate::v4l2_ioctl::FdEvents::new()));

        // SUBSCRIBE_EVENT(V4L2_EVENT_CTRL, brightness).
        m.put_u32(0, 3);
        m.put_u32(4, BRIGHTNESS);
        m.put_u32(8, 0);
        if ioctl_ev(&dev, &m, ioc(DIR_W, 90, 32), &events) != 0 {
            return TestResult::Fail("SUBSCRIBE_EVENT should succeed");
        }
        // Nothing queued yet → DQEVENT is ENOENT.
        if ioctl_ev(&dev, &m, ioc(DIR_R, 89, 136), &events) != eno(2) {
            return TestResult::Fail("empty DQEVENT should be ENOENT");
        }
        // S_CTRL brightness = 10 emits a control-change event.
        m.put_u32(0, BRIGHTNESS);
        m.put_u32(4, 10);
        if ioctl_ev(&dev, &m, ioc(DIR_WR, 28, 8), &events) != 0 {
            return TestResult::Fail("S_CTRL should succeed");
        }
        if !events.lock().has_events() {
            return TestResult::Fail("S_CTRL should queue a CTRL event");
        }
        // DQEVENT returns it: type@0, changes@8 (payload+0), value@16 (payload+8),
        // id@96.
        for off in 0..34 {
            m.put_u32(off * 4, 0);
        }
        if ioctl_ev(&dev, &m, ioc(DIR_R, 89, 136), &events) != 0 {
            return TestResult::Fail("DQEVENT should return the event");
        }
        if m.get_u32(0) != 3 || m.get_u32(96) != BRIGHTNESS {
            return TestResult::Fail("event type/id mismatch");
        }
        if m.get_u32(8) != 1 || m.get_i32(16) != 10 {
            return TestResult::Fail("event payload should carry CH_VALUE + value 10");
        }
        // Drained.
        if ioctl_ev(&dev, &m, ioc(DIR_R, 89, 136), &events) != eno(2) {
            return TestResult::Fail("DQEVENT should be ENOENT after draining");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", events_subscribe_ctrl_dqevent);

    /// CROPCAP/G_SELECTION/G_CROP all report the full (uncropped) frame.
    fn selection_reports_full_frame() -> TestResult {
        let dev = fresh("c"); // default YUYV 640x480
        let m = Mock::new(true);
        // CROPCAP.
        m.put_u32(0, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 58, 44)) != 0 {
            return TestResult::Fail("CROPCAP should succeed");
        }
        if m.get_u32(12) != 640 || m.get_u32(16) != 480 {
            return TestResult::Fail("CROPCAP bounds should be the full frame");
        }
        if m.get_u32(36) != 1 || m.get_u32(40) != 1 {
            return TestResult::Fail("pixelaspect should be 1:1");
        }
        // G_SELECTION target CROP.
        for off in 0..16 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(0, 1); // type
        m.put_u32(4, 0); // V4L2_SEL_TGT_CROP
        if ioctl(&dev, &m, ioc(DIR_WR, 94, 64)) != 0 {
            return TestResult::Fail("G_SELECTION should succeed");
        }
        if m.get_u32(20) != 640 || m.get_u32(24) != 480 {
            return TestResult::Fail("G_SELECTION r should be the full frame");
        }
        // G_CROP.
        m.put_u32(0, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 59, 20)) != 0 {
            return TestResult::Fail("G_CROP should succeed");
        }
        if m.get_u32(12) != 640 || m.get_u32(16) != 480 {
            return TestResult::Fail("G_CROP c should be the full frame");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", selection_reports_full_frame);

    /// EXPBUF exports a dma-buf fd that mmaps the same physical frame as the
    /// capture buffer, and blocks a subsequent REQBUFS reuse (EBUSY).
    fn expbuf_exports_dmabuf() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        // One MMAP buffer.
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        ioctl(&dev, &m, ioc(DIR_WR, 8, 20)); // REQBUFS
                                             // The buffer's first physical frame address.
        let want = dev.lock().buffers[0].frames[0].start_address().raw();
        // EXPBUF index 0.
        for off in 0..16 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(0, 1); // type
        m.put_u32(4, 0); // index
        if ioctl(&dev, &m, ioc(DIR_WR, 16, 64)) != 0 {
            return TestResult::Fail("EXPBUF should succeed");
        }
        let fd = m.get_i32(16);
        if fd < 0 {
            return TestResult::Fail("EXPBUF should return a valid fd");
        }
        // The exported fd mmaps the same frame.
        let dmabuf = m.installed_file(fd);
        match dmabuf.mmap_frames(0, 4096) {
            Ok(frames) if frames.first() == Some(&want) => {}
            _ => return TestResult::Fail("dma-buf should alias the buffer's frame"),
        }
        // REQBUFS reuse is now blocked (frames still referenced).
        m.put_u32(0, 2);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 8, 20)) != eno(16) {
            return TestResult::Fail("REQBUFS after EXPBUF should be EBUSY");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", expbuf_exports_dmabuf);

    /// USERPTR: QBUF a user address, deliver a frame, and DQBUF copies the
    /// captured bytes into that address.
    fn userptr_qbuf_dqbuf_roundtrip() -> TestResult {
        let dev = fresh("c");
        let m = Mock::new(true);
        // REQBUFS 1 USERPTR.
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        m.put_u32(8, 2); // V4L2_MEMORY_USERPTR
        if ioctl(&dev, &m, ioc(DIR_WR, 8, 20)) != 0 || m.get_u32(0) != 1 {
            return TestResult::Fail("REQBUFS USERPTR should grant 1");
        }
        if m.get_u32(12) & (1 << 1) == 0 {
            return TestResult::Fail("caps should advertise SUPPORTS_USERPTR");
        }
        // QBUF 0 with a user pointer at ARG + 1024, length 64.
        let uptr = ARG + 1024;
        for off in 0..22 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(4, 1); // type
        m.put_u32(60, 2); // memory USERPTR
        m.put_u32(64, uptr as u32);
        m.put_u32(68, (uptr >> 32) as u32);
        m.put_u32(72, 64); // length
        if ioctl(&dev, &m, ioc(DIR_WR, 15, 88)) != 0 {
            return TestResult::Fail("QBUF USERPTR should succeed");
        }
        // STREAMON, deliver a frame, DQBUF.
        m.put_u32(0, 1);
        ioctl(&dev, &m, ioc(DIR_W, 18, 4));
        dev.lock().deliver_frame(alloc::vec![0x5Au8; 64]);
        for off in 0..22 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(4, 1);
        m.put_u32(60, 2);
        if ioctl(&dev, &m, ioc(DIR_WR, 17, 88)) != 0 {
            return TestResult::Fail("DQBUF USERPTR should succeed");
        }
        if m.get_u32(8) != 64 {
            return TestResult::Fail("bytesused should be 64");
        }
        if m.get_u32(1024) != 0x5A5A_5A5A {
            return TestResult::Fail("captured bytes should land in the user pointer");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", userptr_qbuf_dqbuf_roundtrip);

    /// DMABUF import: export an MMAP buffer from one device and QBUF it (by fd)
    /// into a second device's DMABUF pool; a delivered frame lands in the shared
    /// physical frame.
    fn dmabuf_import_qbuf() -> TestResult {
        __reset_for_test();
        let exporter = get_device(register_video("exp")).unwrap();
        let importer = get_device(register_video("imp")).unwrap();
        let m = Mock::new(true);
        // Exporter: REQBUFS MMAP 1, EXPBUF 0 → dma-buf fd.
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        m.put_u32(8, 1);
        ioctl(&exporter, &m, ioc(DIR_WR, 8, 20));
        for off in 0..16 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(0, 1);
        ioctl(&exporter, &m, ioc(DIR_WR, 16, 64)); // EXPBUF index 0
        let fd = m.get_i32(16);
        let want = exporter.lock().buffers[0].frames[0].start_address().raw();
        // Importer: REQBUFS DMABUF 1, QBUF 0 referencing the fd.
        m.put_u32(0, 1);
        m.put_u32(4, 1);
        m.put_u32(8, 4); // V4L2_MEMORY_DMABUF
        if ioctl(&importer, &m, ioc(DIR_WR, 8, 20)) != 0 {
            return TestResult::Fail("REQBUFS DMABUF should succeed");
        }
        for off in 0..22 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(4, 1);
        m.put_u32(60, 4); // memory DMABUF
        m.put_u32(64, fd as u32); // m.fd
        if ioctl(&importer, &m, ioc(DIR_WR, 15, 88)) != 0 {
            return TestResult::Fail("QBUF DMABUF should succeed");
        }
        // The importer buffer now borrows the exporter's frame.
        let got = importer.lock().buffers[0].frames.first().copied();
        if got.map(|f| f.start_address().raw()) != Some(want) {
            return TestResult::Fail("DMABUF QBUF should import the exporter's frame");
        }
        if importer.lock().buffers[0].owns_frames {
            return TestResult::Fail("imported frames must not be owned");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", dmabuf_import_qbuf);

    /// Multiplanar: QUERYCAP advertises MPLANE, S_FMT/G_FMT negotiate a
    /// single-plane pix_mp, and QUERYBUF fills the plane array.
    fn mplane_format_and_querybuf() -> TestResult {
        const MPLANE: u32 = 9;
        const YUYV: u32 =
            (b'Y' as u32) | ((b'U' as u32) << 8) | ((b'Y' as u32) << 16) | ((b'V' as u32) << 24);
        let dev = fresh("c"); // YUYV 640x480
        let m = Mock::new(true);
        // QUERYCAP advertises the MPLANE capability.
        if ioctl(&dev, &m, ioc(DIR_R, 0, 104)) != 0 || m.get_u32(84) & 0x1000 == 0 {
            return TestResult::Fail("QUERYCAP should advertise CAPTURE_MPLANE");
        }
        // S_FMT MPLANE YUYV 640x480.
        for off in 0..52 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(0, MPLANE);
        m.put_u32(8, 640);
        m.put_u32(12, 480);
        m.put_u32(16, YUYV);
        if ioctl(&dev, &m, ioc(DIR_WR, 5, 208)) != 0 {
            return TestResult::Fail("S_FMT MPLANE should succeed");
        }
        if m.get_u32(188) & 0xff != 1 {
            return TestResult::Fail("num_planes should be 1");
        }
        if m.get_u32(28) != 640 * 480 * 2 {
            return TestResult::Fail("plane_fmt[0].sizeimage mismatch");
        }
        // REQBUFS MPLANE MMAP 1.
        for off in 0..5 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(0, 1);
        m.put_u32(4, MPLANE);
        m.put_u32(8, 1);
        if ioctl(&dev, &m, ioc(DIR_WR, 8, 20)) != 0 || m.get_u32(0) != 1 {
            return TestResult::Fail("REQBUFS MPLANE should grant 1");
        }
        // QUERYBUF MPLANE with a plane array at ARG + 512.
        let planes = ARG + 512;
        for off in 0..22 {
            m.put_u32(off * 4, 0);
        }
        m.put_u32(4, MPLANE);
        m.put_u32(64, planes as u32);
        m.put_u32(68, (planes >> 32) as u32);
        if ioctl(&dev, &m, ioc(DIR_WR, 9, 88)) != 0 {
            return TestResult::Fail("QUERYBUF MPLANE should succeed");
        }
        if m.get_u32(512 + 4) != 640 * 480 * 2 {
            return TestResult::Fail("plane[0].length mismatch");
        }
        if m.get_u32(512 + 8) != 0 {
            return TestResult::Fail("plane[0].m.mem_offset should be buffer 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/video/v4l2", mplane_format_and_querybuf);
}
