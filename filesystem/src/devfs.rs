//! `DevFs` — Linux-compatible writable `devtmpfs` surface.
//!
//! Real C programs reach for these almost universally — discarding
//! debug output via `> /dev/null`, zero-filling buffers via `dd
//! if=/dev/zero`, etc. Without them user programs that mention the
//! paths in a never-taken branch still need them to *exist* (or
//! the open call surfaces a NotFound that the caller doesn't
//! distinguish from a real failure).
//!
//! `DevFs::new()` returns an `FsInstance` named `devtmpfs`. Its root contains
//! the standard NARF device nodes, driver-installed nodes, Unix98 PTYs, block
//! device aliases, and a writable runtime tree for udev-created device nodes,
//! directories, and symlinks.
//!
//! Semantics:
//!   - `/dev/null`: read returns 0 (immediate EOF); write returns
//!     the requested length (bytes silently discarded).
//!   - `/dev/zero`: read fills the user buffer with zeros and
//!     returns the requested length; write discards.
//!
//! Character and block devices report distinct `FileType::Special` and
//! `FileType::Block` values so Linux `stat` and `getdents` consumers see
//! `S_IFCHR`/`DT_CHR` and `S_IFBLK`/`DT_BLK` respectively.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, FsInstance, Mode, Stat, POLL_OUT,
};

// ── mknod-created device nodes ────────────────────────────────────────
//
// udev's coldplug creates /dev nodes with `mknod(path, S_IFCHR|mode, dev_t)`
// (and `mknodat`). NARF's built-in /dev entries are static, but a device udev
// discovers via a coldplug uevent that has no built-in node still needs one to
// EXIST and `stat` as the right char/block device with the right `st_rdev`, or
// `udevadm test` / a driver's open() fails. These dynamically-created nodes
// live in a small in-memory registry keyed by name; `DevDir::lookup`/
// `enumerate` surface them alongside the static entries. Linux ref:
// `drivers/base/devtmpfs.c` (the kernel's own devtmpfs mknod bookkeeping).

/// Linux's compact dev_t encoding for majors below 4096. The high minor bits
/// occupy bits 20+, matching `new_encode_dev()`.
pub(crate) const fn linux_makedev(major: u32, minor: u32) -> u64 {
    ((minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)) as u64
}

fn device_inode(rdev: u64, kind: u64) -> u64 {
    0xd000_0000_0000_0000 | (kind << 48) | rdev.wrapping_add(1)
}

fn named_inode(name: &str, kind: u64) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64 ^ kind;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash | (1 << 63)
}

#[derive(Copy, Clone)]
struct MknodMetadata {
    file_type: FileType,
    rdev: u64,
    perms: u16,
    uid: u32,
    gid: u32,
}

struct MknodNode {
    inode: u64,
    metadata: IrqSafeSpinLock<MknodMetadata>,
}

#[derive(Clone)]
enum DynamicNode {
    Device(Arc<MknodNode>),
    Symlink { target: String, inode: u64 },
    Directory(Arc<DynamicDirectory>),
}

type DynamicMap = alloc::collections::BTreeMap<String, DynamicNode>;

struct DynamicDirectory {
    inode: u64,
    perms: IrqSafeSpinLock<u16>,
    entries: IrqSafeSpinLock<DynamicMap>,
}

/// Runtime-created devtmpfs entries. Keeping devices and symlinks in one map
/// makes name creation, replacement, rename, and unlink atomic across types.
static DYNAMIC_NODES: IrqSafeSpinLock<DynamicMap> =
    IrqSafeSpinLock::new(alloc::collections::BTreeMap::new());

static NEXT_DYNAMIC_INO: AtomicU64 = AtomicU64::new(0x1000);

/// FileOps for a `mknod`-created char/block node.
struct MknodFile {
    node: Arc<MknodNode>,
}

impl FileOps for MknodFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // No backing driver: read returns EOF (like an unclaimed node).
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }
    fn stat(&self) -> Stat {
        let metadata = *self.node.metadata.lock();
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: metadata.file_type,
                perms: metadata.perms,
            },
            mtime_cycles: 0,
        }
    }
    fn rdev(&self) -> u64 {
        self.node.metadata.lock().rdev
    }
    fn ino(&self) -> u64 {
        self.node.inode
    }
    fn owners(&self) -> (u32, u32) {
        let metadata = *self.node.metadata.lock();
        (metadata.uid, metadata.gid)
    }
    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        let mut metadata = self.node.metadata.lock();
        metadata.uid = uid;
        metadata.gid = gid;
        Box::pin(async { Ok(()) })
    }
    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        self.node.metadata.lock().perms = perms & 0o7777;
        Box::pin(async { Ok(()) })
    }
}

fn mknod_register(
    nodes: &IrqSafeSpinLock<DynamicMap>,
    name: &str,
    file_type: FileType,
    rdev: u64,
    perms: u16,
) -> Result<Arc<MknodNode>, FsError> {
    if !valid_leaf_name(name) {
        return Err(FsError::InvalidPath);
    }
    let mut nodes = nodes.lock();
    if nodes.contains_key(name) {
        return Err(FsError::Busy);
    }
    let node = Arc::new(MknodNode {
        inode: NEXT_DYNAMIC_INO.fetch_add(1, Ordering::Relaxed),
        metadata: IrqSafeSpinLock::new(MknodMetadata {
            file_type,
            rdev,
            perms,
            uid: 0,
            gid: 0,
        }),
    });
    nodes.insert(name.into(), DynamicNode::Device(node.clone()));
    Ok(node)
}

/// Reset the dynamic-node registry (test isolation).
#[doc(hidden)]
pub fn __reset_mknod_for_test() {
    DYNAMIC_NODES.lock().clear();
    NEXT_DYNAMIC_INO.store(0x1000, Ordering::Relaxed);
}

/// `/dev/null` — read = EOF, write = discard.
struct DevNull;

impl FileOps for DevNull {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }
    fn rdev(&self) -> u64 {
        linux_makedev(1, 3)
    }
    fn ino(&self) -> u64 {
        device_inode(self.rdev(), 1)
    }
}

/// `/dev/random` and `/dev/urandom` — ChaCha20-based CSPRNG.
///
/// Post-Linux-5.18 semantics: both files are identical — both deliver
/// bytes from the same ChaCha20 CSPRNG seeded from hardware entropy
/// (RDSEED → RDRAND → TSC-fallback on x86_64).  Neither blocks once the
/// pool is seeded; the pool is always seeded synchronously during kernel
/// init via `csprng::init_csprng()`.
///
/// Write = discard (matching `/dev/null` semantics for the write path).
/// A write-to-stir-the-pool extension is deferred (Linux ref:
/// `drivers/char/random.c::write_pool`).
///
/// Linux ref: `drivers/char/random.c::extract_crng`.
struct DevRandom;

impl FileOps for DevRandom {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        crate::csprng::fill(buf);
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    /// RNG-pool management ioctls. NARF's CSPRNG is always seeded (see
    /// the struct doc), so there is no entropy pool to fill or drain:
    /// the count ioctls report a full pool and the mutating ioctls are
    /// accepted no-ops. `systemd-random-seed` credits saved seed bytes
    /// via `RNDADDENTROPY` on shutdown/boot; answering 0 (instead of the
    /// default `ENOTTY`) lets that unit complete cleanly.
    ///
    /// Linux ref: `drivers/char/random.c::random_ioctl`.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        // _IOC(dir, 'R', nr, size) — the RNG ioctls all use type 'R'
        // (0x52). Match on the type+nr and ignore dir/size so a 32- vs
        // 64-bit caller (RNDADDENTROPY size differs) hits the same arm.
        const RND_TYPE: u32 = 0x52;
        let ioc_type = (cmd >> 8) & 0xFF;
        let nr = cmd & 0xFF;
        if ioc_type != RND_TYPE {
            return Err(FsError::Unsupported);
        }
        match nr {
            // RNDGETENTCNT — bits of entropy available. Report a full
            // pool (4096 bits, Linux's `POOL_BITS`) so callers that gate
            // on a threshold proceed.
            0x00 => {
                // SAFETY: `arg` is the caller's `int*`; write_user_i32
                // range-checks and SMAP-brackets the store.
                unsafe { crate::devfs_pty::write_user_i32(arg, 4096)? };
                Ok(0)
            }
            // RNDADDTOENTCNT (0x01), RNDADDENTROPY (0x03),
            // RNDZAPENTCNT (0x04), RNDCLEARPOOL (0x06),
            // RNDRESEEDCRNG (0x07) — accepted no-ops.
            0x01 | 0x03 | 0x04 | 0x06 | 0x07 => Ok(0),
            _ => Err(FsError::Unsupported),
        }
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        linux_makedev(1, 9)
    }

    fn ino(&self) -> u64 {
        device_inode(self.rdev(), 1)
    }
}

/// `/dev/random` has the same CSPRNG behavior as urandom after Linux 5.18,
/// but retains its historical device identity (1:8).
struct DevBlockingRandom;

impl FileOps for DevBlockingRandom {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        DevRandom.read(offset, buf)
    }
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        DevRandom.write(offset, buf)
    }
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        DevRandom.ioctl(cmd, arg)
    }
    fn stat(&self) -> Stat {
        DevRandom.stat()
    }
    fn rdev(&self) -> u64 {
        linux_makedev(1, 8)
    }
    fn ino(&self) -> u64 {
        device_inode(self.rdev(), 1)
    }
}

/// `/dev/zero` — read = zero-fill the buffer, write = discard.
struct DevZero;

impl FileOps for DevZero {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        // Zero-fill happens here so the future body owns the slice
        // mutation; the async-block move keeps `buf` borrowed for
        // the future's lifetime.
        for slot in buf.iter_mut() {
            *slot = 0;
        }
        Box::pin(async move { Ok(len) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o666,
            },
            mtime_cycles: 0,
        }
    }
    fn rdev(&self) -> u64 {
        linux_makedev(1, 5)
    }
    fn ino(&self) -> u64 {
        device_inode(self.rdev(), 1)
    }
}

/// `/dev/kmsg` — read-only snapshot of the kernel log ring.
///
/// Mirrors Linux's `/dev/kmsg` (the canonical surface `dmesg` reads
/// from). Each read returns a slice of the live klog snapshot
/// starting at `offset` (caller-tracked, oldest-byte-first). On
/// large logs the caller calls multiple times until the read
/// returns 0. Writes are accepted (a no-op) so a userspace tool
/// can pipe to `> /dev/kmsg` without erroring; the actual kmsg
/// "inject" facility from Linux isn't implemented (write-discard).
///
/// The snapshot is computed PER READ — between reads, more bytes
/// may have been recorded by `console::write_str → klog::record`.
/// Callers wanting a stable view should fetch in a single large
/// read; callers wanting tail-style updates can just keep reading
/// past EOF (offset = current_len) on each iteration.
/// Extract the human-readable message from a `/dev/kmsg` write. Linux's kmsg
/// injection format is "<priority>,<seq>,<timestamp>,<flags>[,...];message":
/// comma-separated numeric metadata, a ';', then the message. Strip the
/// metadata prefix (only when it is exactly that shape) and the trailing
/// newline; anything else is passed through verbatim so a bare
/// `echo foo > /dev/kmsg` still shows "foo".
fn kmsg_visible_message(buf: &[u8]) -> &str {
    let text = core::str::from_utf8(buf).unwrap_or("");
    // The record header is "<priority>,<seq>,<timestamp>,<flags>;" — the flags
    // field can be non-numeric (e.g. "-" or "c"), so only require the FIRST
    // comma-separated field (priority) to be all digits and the header to be
    // comma-separated. That distinguishes a real record from a bare
    // `echo foo;bar > /dev/kmsg`, which is passed through untouched.
    let msg = match text.split_once(';') {
        Some((meta, rest))
            if meta.contains(',')
                && meta
                    .split(',')
                    .next()
                    .is_some_and(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit())) =>
        {
            rest
        }
        _ => text,
    };
    msg.trim_end_matches('\n')
}

struct DevKmsg;

impl FileOps for DevKmsg {
    fn poll_readiness_at(&self, offset: u64) -> u32 {
        // Use the O(1) length, not `snapshot().len()`: epoll re-polls this on
        // every wait iteration, and a snapshot here reallocates the whole klog
        // ring each time — enough allocator churn to peg the CPU and starve
        // the rest of boot (journald drains /dev/kmsg via epoll).
        let readable = (offset as usize) < narf_console::klog::live_len();
        if readable {
            crate::POLL_IN | crate::POLL_OUT
        } else {
            crate::POLL_OUT
        }
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Copy only the requested window straight from the ring (no full-log
        // Vec snapshot per read — see poll_readiness_at).
        let n = narf_console::klog::read_at(offset as usize, buf);
        Box::pin(async move { Ok(n) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Forward the message to the console (which also records into klog, so
        // a later /dev/kmsg read reflects it). systemd's kmsg log target — used
        // by PID 1 and, crucially, by sd-executor for pre-exec failures like the
        // mount-namespace error path — writes here; echoing surfaces those on
        // the serial capture. The Linux kmsg record format is
        // "<priority>,<seq>,<ts>,<flags>;message"; strip the leading metadata up
        // to the first ';' so the human-readable message is what's shown.
        let len = buf.len();
        let msg = kmsg_visible_message(buf);
        if !msg.is_empty() {
            use core::fmt::Write as _;
            let _ = writeln!(narf_console::Writer, "kmsg: {msg}");
        }
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        Stat {
            // Character devices have no seekable file size even though the
            // underlying ring currently contains bytes.
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }
    fn rdev(&self) -> u64 {
        linux_makedev(1, 11)
    }
    fn ino(&self) -> u64 {
        device_inode(self.rdev(), 1)
    }
}

/// Stable `/dev/fuse` path inode. Each successful open clones a fresh daemon
/// connection; lookup/stat alone must not allocate one.
struct DevFuseNode;

impl FileOps for DevFuseNode {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }
    fn rdev(&self) -> u64 {
        linux_makedev(10, 229)
    }
    fn ino(&self) -> u64 {
        device_inode(self.rdev(), 1)
    }
    fn open_instance(&self) -> Option<Arc<dyn FileOps>> {
        Some(crate::fuse_conn::DevFuse::open_new())
    }
}

// ── /dev/fp0 ─────────────────────────────────────────────────────────

/// Optional `FileOps` delegate for `/dev/fp0`. Installed by the USB
/// fingerprint driver when a reader is bound. Reads/writes from
/// `/dev/fp0` route to the raw bulk/interrupt-IN endpoint of the
/// device.
///
/// Stored as a global so the USB crate can register the node without a
/// direct dependency between devfs and the USB crate.
static FP_NODE: IrqSafeSpinLock<Option<Arc<dyn FileOps>>> = IrqSafeSpinLock::new(None);

/// Register (or replace) the `/dev/fp0` file node.  Called by the USB
/// fingerprint driver after a device is successfully bound.
pub fn register_fp(node: Arc<dyn FileOps>) {
    *FP_NODE.lock() = Some(node);
}

/// Unregister the `/dev/fp0` node (device detached).
pub fn unregister_fp() {
    *FP_NODE.lock() = None;
}

// ── /dev/fb0 ─────────────────────────────────────────────────────────

/// Optional `FileOps` delegate for `/dev/fb0`. Installed by the FB
/// initcall when a scanout is active. Exposes the active framebuffer
/// as a Linux-compatible character device.
static FB0_NODE: IrqSafeSpinLock<Option<Arc<dyn FileOps>>> = IrqSafeSpinLock::new(None);

/// Register the `/dev/fb0` file node. Called from the `fb-devfs`
/// initcall after the scanout-picker confirms a backend is active.
pub fn register_fb0(node: Arc<dyn FileOps>) {
    *FB0_NODE.lock() = Some(node);
}

// ── /dev/rfcomm<N> hook ───────────────────────────────────────────────────
// Linux ref: `net/bluetooth/rfcomm/tty.c:318` — rfcomm_dev_add.

static RFCOMM_LOOKUP_HOOK: AtomicUsize = AtomicUsize::new(0);
static RFCOMM_ENUM_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn install_rfcomm_hooks(
    lookup: fn(&str) -> Option<Arc<dyn FileOps>>,
    enumerate: fn() -> Vec<(String, FileType)>,
) {
    RFCOMM_LOOKUP_HOOK.store(lookup as usize, Ordering::Release);
    RFCOMM_ENUM_HOOK.store(enumerate as usize, Ordering::Release);
}

fn rfcomm_lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let ptr = RFCOMM_LOOKUP_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return None;
    }
    // SAFETY: `ptr` is non-zero (checked above) and was produced by
    // `install_rfcomm_hooks` storing a `fn(&str) -> Option<Arc<dyn FileOps>>`
    // via `as usize`. A function-pointer round-trip through `usize` is valid
    // because they have identical size/alignment, and we transmute back to the
    // exact same signature, so the resulting `f` points at a live function.
    // SAFETY: Valid memory or trusted environment
    let f: fn(&str) -> Option<Arc<dyn FileOps>> = unsafe { core::mem::transmute(ptr) };
    f(name)
}

fn rfcomm_enumerate() -> Vec<(String, FileType)> {
    let ptr = RFCOMM_ENUM_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return Vec::new();
    }
    // SAFETY: `ptr` is non-zero (checked above) and was produced by
    // `install_rfcomm_hooks` storing a `fn() -> Vec<(String, FileType)>` via
    // `as usize`. The transmute back to the identical signature is valid: a
    // `fn` pointer and `usize` share size/alignment and the value names a live
    // function.
    // SAFETY: Valid memory or trusted environment
    let f: fn() -> Vec<(String, FileType)> = unsafe { core::mem::transmute(ptr) };
    f()
}

// ── /dev/ttyUSB<N> hook ───────────────────────────────────────────────────
// Linux ref: `drivers/usb/serial/usb-serial.c:tty_port_register_device`.

static TTY_USB_LOOKUP_HOOK: AtomicUsize = AtomicUsize::new(0);
static TTY_USB_ENUM_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn install_tty_usb_hooks(
    lookup: fn(&str) -> Option<Arc<dyn FileOps>>,
    enumerate: fn() -> Vec<(String, FileType)>,
) {
    TTY_USB_LOOKUP_HOOK.store(lookup as usize, Ordering::Release);
    TTY_USB_ENUM_HOOK.store(enumerate as usize, Ordering::Release);
}

fn tty_usb_lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let ptr = TTY_USB_LOOKUP_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return None;
    }
    // SAFETY: `ptr` is non-zero (checked above) and was produced by
    // `install_tty_usb_hooks` storing a `fn(&str) -> Option<Arc<dyn FileOps>>`
    // via `as usize`. Transmuting back to the identical signature is valid
    // because `fn` pointers and `usize` share size/alignment and the value
    // names a live function.
    // SAFETY: Valid memory or trusted environment
    let f: fn(&str) -> Option<Arc<dyn FileOps>> = unsafe { core::mem::transmute(ptr) };
    f(name)
}

fn tty_usb_enumerate() -> Vec<(String, FileType)> {
    let ptr = TTY_USB_ENUM_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return Vec::new();
    }
    // SAFETY: `ptr` is non-zero (checked above) and was produced by
    // `install_tty_usb_hooks` storing a `fn() -> Vec<(String, FileType)>` via
    // `as usize`. Transmuting back to the identical signature is valid because
    // `fn` pointers and `usize` share size/alignment and the value names a live
    // function.
    // SAFETY: Valid memory or trusted environment
    let f: fn() -> Vec<(String, FileType)> = unsafe { core::mem::transmute(ptr) };
    f()
}

// ── /dev/video<N> hook ────────────────────────────────────────────────────
// Linux ref: `drivers/media/v4l2-core/v4l2-dev.c:__video_register_device`.

static VIDEO_LOOKUP_HOOK: AtomicUsize = AtomicUsize::new(0);
static VIDEO_ENUM_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn install_video_hooks(
    lookup: fn(&str) -> Option<Arc<dyn FileOps>>,
    enumerate: fn() -> Vec<(String, FileType)>,
) {
    VIDEO_LOOKUP_HOOK.store(lookup as usize, Ordering::Release);
    VIDEO_ENUM_HOOK.store(enumerate as usize, Ordering::Release);
}

fn video_lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let ptr = VIDEO_LOOKUP_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return None;
    }
    // SAFETY: `ptr` is non-zero (checked above) and was produced by
    // `install_video_hooks` storing a `fn(&str) -> Option<Arc<dyn FileOps>>`
    // via `as usize`. Transmuting back to the identical signature is valid
    // because `fn` pointers and `usize` share size/alignment and the value
    // names a live function.
    // SAFETY: Valid memory or trusted environment
    let f: fn(&str) -> Option<Arc<dyn FileOps>> = unsafe { core::mem::transmute(ptr) };
    f(name)
}

fn video_enumerate() -> Vec<(String, FileType)> {
    let ptr = VIDEO_ENUM_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return Vec::new();
    }
    // SAFETY: `ptr` is non-zero (checked above) and was produced by
    // `install_video_hooks` storing a `fn() -> Vec<(String, FileType)>` via
    // `as usize`. Transmuting back to the identical signature is valid because
    // `fn` pointers and `usize` share size/alignment and the value names a live
    // function.
    // SAFETY: Valid memory or trusted environment
    let f: fn() -> Vec<(String, FileType)> = unsafe { core::mem::transmute(ptr) };
    f()
}

// ── /dev/dri/ delegate ────────────────────────────────────────────────

/// Delegate for `/dev/dri/*`, installed by the DRM GPU driver bridge.
///
/// Provides `/dev/dri/card<N>` and `/dev/dri/renderD<N+128>` entries.
/// Same hook/delegate pattern as `SND_DIR` (sound subsystem) to avoid a
/// circular dependency between `narf-filesystem` and `narf-drivers-gpu`.
///
/// Linux ref: `drivers/gpu/drm/drm_drv.c::drm_dev_register` — minor allocation.
static DRI_DIR: IrqSafeSpinLock<Option<Arc<dyn DirOps>>> = IrqSafeSpinLock::new(None);

/// Register (or replace) the `/dev/dri/` directory delegate.
///
/// Called once from `narf_drivers_gpu::drm_devfs_bridge::install_dri_dir()`.
/// Idempotent.
///
/// Linux ref: `drm_dev_register` (drivers/gpu/drm/drm_drv.c).
pub fn register_dri_dir(dir: Arc<dyn DirOps>) {
    *DRI_DIR.lock() = Some(dir);
}

// ── /dev/snd/ delegate ────────────────────────────────────────────────

/// Delegate for `/dev/snd/*`, installed by the sound driver.
///
/// Same hook/delegate pattern as `FP_NODE` (fingerprint) to avoid a
/// circular dependency between `narf-filesystem` and `narf-drivers-sound`.
static SND_DIR: IrqSafeSpinLock<Option<Arc<dyn DirOps>>> = IrqSafeSpinLock::new(None);

/// Register (or replace) the `/dev/snd/` directory delegate.
///
/// Called once from `narf_drivers_sound::sound_fs_initcall()` after the
/// first card is probed.  Idempotent.
pub fn register_snd_dir(dir: Arc<dyn DirOps>) {
    *SND_DIR.lock() = Some(dir);
}

/// `/dev/fp0` — proxy to whatever `Arc<dyn FileOps>` the USB
/// fingerprint driver installed.
struct DevFp;

impl FileOps for DevFp {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let node = FP_NODE.lock().clone();
        Box::pin(async move {
            match node {
                Some(n) => n.read(offset, buf).await,
                None => Err(FsError::Io(narf_block::BlockError::IOError)),
            }
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let node = FP_NODE.lock().clone();
        Box::pin(async move {
            match node {
                Some(n) => n.write(offset, buf).await,
                None => Err(FsError::Io(narf_block::BlockError::IOError)),
            }
        })
    }

    fn stat(&self) -> Stat {
        FP_NODE
            .lock()
            .as_ref()
            .map(|node| node.stat())
            .unwrap_or(Stat {
                size: 0,
                blocks: 0,
                mode: Mode {
                    file_type: FileType::Special,
                    perms: 0o660,
                },
                mtime_cycles: 0,
            })
    }
    fn rdev(&self) -> u64 {
        FP_NODE.lock().as_ref().map(|node| node.rdev()).unwrap_or(0)
    }
    fn ino(&self) -> u64 {
        named_inode("fp0", 1)
    }
    fn owners(&self) -> (u32, u32) {
        FP_NODE
            .lock()
            .as_ref()
            .map(|node| node.owners())
            .unwrap_or((0, 0))
    }
}

/// `/dev/fb0` — proxy to the installed FB FileOps.
struct DevFb0Proxy;

impl FileOps for DevFb0Proxy {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let node = FB0_NODE.lock().clone();
        Box::pin(async move {
            match node {
                Some(n) => n.read(offset, buf).await,
                None => Ok(0),
            }
        })
    }
    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let node = FB0_NODE.lock().clone();
        Box::pin(async move {
            match node {
                Some(n) => n.write(offset, buf).await,
                None => Ok(0),
            }
        })
    }
    fn stat(&self) -> Stat {
        FB0_NODE
            .lock()
            .as_ref()
            .map(|n| n.stat())
            .unwrap_or_else(|| Stat {
                size: 0,
                blocks: 0,
                mode: Mode {
                    file_type: FileType::Special,
                    perms: 0o660,
                },
                mtime_cycles: 0,
            })
    }
    fn mmap_frames(&self, offset: u64, len: usize) -> Result<alloc::vec::Vec<u64>, FsError> {
        match FB0_NODE.lock().clone() {
            Some(n) => n.mmap_frames(offset, len),
            None => Err(FsError::Unsupported),
        }
    }
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match FB0_NODE.lock().clone() {
            Some(n) => n.ioctl(cmd, arg),
            None => Err(FsError::Unsupported),
        }
    }
    fn rdev(&self) -> u64 {
        FB0_NODE
            .lock()
            .as_ref()
            .map(|node| node.rdev())
            .unwrap_or(0)
    }
    fn ino(&self) -> u64 {
        named_inode("fb0", 1)
    }
    fn owners(&self) -> (u32, u32) {
        FB0_NODE
            .lock()
            .as_ref()
            .map(|node| node.owners())
            .unwrap_or((0, 0))
    }
}

// ── /dev/tpm0 + /dev/tpmrm0 ──────────────────────────────────────────

/// Optional `FileOps` delegate for `/dev/tpm0`.  Installed by the TPM
/// driver after the CRB/TIS transport is probed.  Reads/writes from
/// `/dev/tpm0` route to the TPM2 command/response path.
///
/// Linux ref: `drivers/char/tpm/tpm-dev.c` — per-fd buffer model.
static TPM0_NODE: IrqSafeSpinLock<Option<Arc<dyn FileOps>>> = IrqSafeSpinLock::new(None);

/// Optional `FileOps` delegate for `/dev/tpmrm0`.  Tracks transient
/// handles and flushes them on close.
static TPMRM0_NODE: IrqSafeSpinLock<Option<Arc<dyn FileOps>>> = IrqSafeSpinLock::new(None);

/// Register both TPM device nodes at once.  Called by `tpm::devfs_bridge::register_dev_nodes()`.
pub fn register_tpm(tpm0: Arc<dyn FileOps>, tpmrm0: Arc<dyn FileOps>) {
    *TPM0_NODE.lock() = Some(tpm0);
    *TPMRM0_NODE.lock() = Some(tpmrm0);
}

/// Unregister both TPM device nodes (driver tear-down / test reset).
pub fn unregister_tpm() {
    *TPM0_NODE.lock() = None;
    *TPMRM0_NODE.lock() = None;
}

/// `/dev/tpm0` — proxy to the installed TPM FileOps.
struct DevTpm0Proxy;

impl FileOps for DevTpm0Proxy {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let node = TPM0_NODE.lock().clone();
        Box::pin(async move {
            match node {
                Some(n) => n.read(offset, buf).await,
                None => Err(FsError::Io(narf_block::BlockError::IOError)),
            }
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let node = TPM0_NODE.lock().clone();
        Box::pin(async move {
            match node {
                Some(n) => n.write(offset, buf).await,
                None => Err(FsError::Io(narf_block::BlockError::IOError)),
            }
        })
    }

    fn stat(&self) -> Stat {
        TPM0_NODE
            .lock()
            .as_ref()
            .map(|node| node.stat())
            .unwrap_or(Stat {
                size: 0,
                blocks: 0,
                mode: Mode {
                    file_type: FileType::Special,
                    perms: 0o600,
                },
                mtime_cycles: 0,
            })
    }

    fn poll_readiness(&self) -> u32 {
        let node = TPM0_NODE.lock().clone();
        match node {
            Some(n) => n.poll_readiness(),
            None => POLL_OUT,
        }
    }
    fn rdev(&self) -> u64 {
        TPM0_NODE
            .lock()
            .as_ref()
            .map(|node| node.rdev())
            .unwrap_or(0)
    }
    fn ino(&self) -> u64 {
        named_inode("tpm0", 1)
    }
}

/// `/dev/tpmrm0` — proxy to the installed TPM resource-manager FileOps.
struct DevTpmRm0Proxy;

impl FileOps for DevTpmRm0Proxy {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let node = TPMRM0_NODE.lock().clone();
        Box::pin(async move {
            match node {
                Some(n) => n.read(offset, buf).await,
                None => Err(FsError::Io(narf_block::BlockError::IOError)),
            }
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let node = TPMRM0_NODE.lock().clone();
        Box::pin(async move {
            match node {
                Some(n) => n.write(offset, buf).await,
                None => Err(FsError::Io(narf_block::BlockError::IOError)),
            }
        })
    }

    fn stat(&self) -> Stat {
        TPMRM0_NODE
            .lock()
            .as_ref()
            .map(|node| node.stat())
            .unwrap_or(Stat {
                size: 0,
                blocks: 0,
                mode: Mode {
                    file_type: FileType::Special,
                    perms: 0o600,
                },
                mtime_cycles: 0,
            })
    }

    fn poll_readiness(&self) -> u32 {
        let node = TPMRM0_NODE.lock().clone();
        match node {
            Some(n) => n.poll_readiness(),
            None => POLL_OUT,
        }
    }
    fn rdev(&self) -> u64 {
        TPMRM0_NODE
            .lock()
            .as_ref()
            .map(|node| node.rdev())
            .unwrap_or(0)
    }
    fn ino(&self) -> u64 {
        named_inode("tpmrm0", 1)
    }
}

/// `/dev/console` — typed-byte stream backed by `narf_input`.
///
/// Reads pull pending key-press events off `narf_input`'s global
/// ring, translate them into ASCII bytes (printable keys, Enter
/// → `\n`, Backspace → `0x7F`), and copy into the user buffer.
/// Releases / modifier keys / non-translatable codes are
/// dropped silently. Returns 0 immediately when nothing is queued
/// (non-blocking semantics — callers that want blocking reads
/// poll-and-yield in user space until the next key arrives).
///
/// Writes go to the kernel console (UART + framebuffer if
/// installed) so user code can `write(open("/dev/console"))` for
/// stdout-equivalent output without an explicit fd-table lookup
/// against fd 1/2.
#[derive(Copy, Clone)]
enum ConsoleNodeKind {
    Console,
    CurrentTty,
    Virtual(u32),
}

struct DevConsole {
    kind: ConsoleNodeKind,
}

/// Install the console's signal-character hook. Compatibility shim —
/// the hook now lives in the unified `console_tty` module (one console,
/// one hook); this forwards there so existing boot wiring keeps working.
/// Pass a `fn(u8) -> bool` returning `true` iff the byte was consumed as
/// a signal (and should NOT appear in the read buffer).
pub fn install_console_signal_hook(hook: fn(u8) -> bool) {
    crate::console_tty::install_signal_hook(hook);
}

/// Translate one `KeyCode` (with live modifier state) into one
/// printable ASCII byte. Returns `None` for non-translatable keys
/// (modifiers, function keys, navigation cluster). The shift map
/// matches a US-QWERTY layout — internationalisation is a follow-up
/// (real systems consult `/etc/keymaps`).
pub(crate) fn key_to_ascii(code: narf_input::KeyCode, mods: narf_input::Modifiers) -> Option<u8> {
    use narf_input::{KeyCode as K, Modifiers as M};
    let shift = mods.contains(M::SHIFT) ^ mods.contains(M::CAPS_LOCK);
    let base = match code {
        K::A => b'a',
        K::B => b'b',
        K::C => b'c',
        K::D => b'd',
        K::E => b'e',
        K::F => b'f',
        K::G => b'g',
        K::H => b'h',
        K::I => b'i',
        K::J => b'j',
        K::K => b'k',
        K::L => b'l',
        K::M => b'm',
        K::N => b'n',
        K::O => b'o',
        K::P => b'p',
        K::Q => b'q',
        K::R => b'r',
        K::S => b's',
        K::T => b't',
        K::U => b'u',
        K::V => b'v',
        K::W => b'w',
        K::X => b'x',
        K::Y => b'y',
        K::Z => b'z',
        K::Key0 => return Some(if shift { b')' } else { b'0' }),
        K::Key1 => return Some(if shift { b'!' } else { b'1' }),
        K::Key2 => return Some(if shift { b'@' } else { b'2' }),
        K::Key3 => return Some(if shift { b'#' } else { b'3' }),
        K::Key4 => return Some(if shift { b'$' } else { b'4' }),
        K::Key5 => return Some(if shift { b'%' } else { b'5' }),
        K::Key6 => return Some(if shift { b'^' } else { b'6' }),
        K::Key7 => return Some(if shift { b'&' } else { b'7' }),
        K::Key8 => return Some(if shift { b'*' } else { b'8' }),
        K::Key9 => return Some(if shift { b'(' } else { b'9' }),
        K::Space => return Some(b' '),
        K::Enter | K::KpEnter => return Some(b'\n'),
        K::Tab => return Some(b'\t'),
        K::Backspace => return Some(0x7F),
        K::Escape => return Some(0x1B),
        K::Minus => return Some(if shift { b'_' } else { b'-' }),
        K::Equal => return Some(if shift { b'+' } else { b'=' }),
        K::LeftBrace => return Some(if shift { b'{' } else { b'[' }),
        K::RightBrace => return Some(if shift { b'}' } else { b']' }),
        K::Backslash => return Some(if shift { b'|' } else { b'\\' }),
        K::Semicolon => return Some(if shift { b':' } else { b';' }),
        K::Apostrophe => return Some(if shift { b'"' } else { b'\'' }),
        K::Grave => return Some(if shift { b'~' } else { b'`' }),
        K::Comma => return Some(if shift { b'<' } else { b',' }),
        K::Dot => return Some(if shift { b'>' } else { b'.' }),
        K::Slash => return Some(if shift { b'?' } else { b'/' }),
        _ => return None,
    };
    Some(if shift {
        base.to_ascii_uppercase()
    } else {
        base
    })
}

impl FileOps for DevConsole {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // Route through the single shared console line discipline
        // (`console_tty`), which owns the termios + cooked/raw mode +
        // the ^C/^\/^Z signal hook and drains both input rings (serial
        // bytes + translated keys). fd 0/1/2's `ConsoleFile` reads the
        // exact same stream, so there is one console, one termios.
        let written = crate::console_tty::read_into(buf);
        Box::pin(async move { Ok(written) })
    }

    /// Park an empty `/dev/console` read on the input waker rather than
    /// returning a spurious 0 (EOF). Mirrors fd-0 `ConsoleFile`; true
    /// when the line discipline has no completed input buffered.
    fn block_on_input(&self) -> bool {
        crate::console_tty::block_on_input()
    }

    /// Job control: `/dev/console` is the boot console — same tty id,
    /// foreground pgrp, and TOSTOP as fd 0 (all singleton `console_tty`
    /// state), so a background process reading `/dev/console` is sent
    /// SIGTTIN just like one reading fd 0.
    fn tty_id(&self) -> Option<u32> {
        Some(crate::TTY_ID_CONSOLE)
    }
    fn tty_fg_pgrp(&self) -> Option<u64> {
        Some(crate::console_tty::fg_pgrp())
    }
    fn tty_tostop(&self) -> bool {
        crate::console_tty::tostop()
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Same path as `sys_write` to fd 1/2: forward to the kernel
        // console (UART + framebuffer hook if installed). Treat
        // non-UTF-8 input as best-effort lossy by way of
        // `from_utf8_lossy` — `write_str` is the only public sink.
        let n = buf.len();
        if let Ok(s) = core::str::from_utf8(buf) {
            narf_console::write_str(s);
        } else {
            // Slow path: emit bytes one-by-one as `?` substitutes
            // for invalid UTF-8 — matches the standard library's
            // handling and keeps the byte count truthful.
            for &b in buf {
                if b.is_ascii() {
                    // SAFETY: `b.is_ascii()` is true here, so the single-byte
                    // slice `from_ref(&b)` contains one byte < 0x80, which is
                    // always valid UTF-8; `from_utf8_unchecked` therefore has no
                    // invalid sequence to misinterpret.
                    // SAFETY: Valid memory or trusted environment
                    narf_console::write_str(unsafe {
                        core::str::from_utf8_unchecked(core::slice::from_ref(&b))
                    });
                } else {
                    narf_console::write_str("?");
                }
            }
        }
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        let perms = match self.kind {
            ConsoleNodeKind::Console => 0o600,
            ConsoleNodeKind::CurrentTty => 0o666,
            ConsoleNodeKind::Virtual(_) => 0o620,
        };
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        match self.kind {
            ConsoleNodeKind::Console => linux_makedev(5, 1),
            ConsoleNodeKind::CurrentTty => linux_makedev(5, 0),
            ConsoleNodeKind::Virtual(index) => linux_makedev(4, index),
        }
    }

    fn ino(&self) -> u64 {
        device_inode(self.rdev(), 1)
    }

    fn owners(&self) -> (u32, u32) {
        match self.kind {
            ConsoleNodeKind::Virtual(_) => (0, 5), // root:tty
            _ => (0, 0),
        }
    }

    /// Terminal ioctls so `/dev/console` looks like a real tty: a
    /// successful `TCGETS` (returning a cooked-mode termios) makes
    /// `isatty(0)` true, which is what flips a shell into interactive
    /// mode. `TCSETS*` round-trips the caller's termios (so a program
    /// can switch raw/cooked); `TIOCGWINSZ` reports the window size.
    /// Other requests fall through to `-ENOTTY`.
    #[cfg(feature = "linux-compat")]
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, crate::FsError> {
        use crate::devfs_pty::{
            read_user_i32, read_user_termios, read_user_termios2, read_user_winsize,
            write_user_i32, write_user_termios, write_user_termios2, write_user_winsize,
            WireWinsize, FIONREAD, KDGETMODE, KDGKBMODE, KDSIGACCEPT, KDSKBMODE, TCFLSH, TCGETS,
            TCGETS2, TCSBRK, TCSETS, TCSETS2, TCSETSF, TCSETSF2, TCSETSW, TCSETSW2, TCXONC,
            TIOCGPGRP, TIOCGSID, TIOCGWINSZ, TIOCNOTTY, TIOCSCTTY, TIOCSPGRP, TIOCSWINSZ,
            VT_ACTIVATE, VT_GETMODE, VT_GETSTATE, VT_OPENQRY, VT_WAITACTIVE,
        };
        // Termios + winsize + foreground pgrp are owned by the unified
        // `console_tty` so a TCSETS / tcsetpgrp on /dev/console is visible
        // to fd 0 and vice versa.
        match cmd {
            TCGETS => {
                let raw = crate::console_tty::termios();
                // SAFETY: `arg` is the user `struct termios *` the ioctl
                // syscall path validated before dispatch.
                unsafe { write_user_termios(arg, &raw)? };
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                // SAFETY: `arg` is the validated user `struct termios *`.
                let raw = unsafe { read_user_termios(arg)? };
                crate::console_tty::set_termios(raw);
                Ok(0)
            }
            TCGETS2 => {
                let raw = crate::console_tty::termios();
                // SAFETY: `arg` is the validated user `struct termios2 *`.
                unsafe { write_user_termios2(arg, &raw)? };
                Ok(0)
            }
            TCSETS2 | TCSETSW2 | TCSETSF2 => {
                // SAFETY: `arg` is the validated user `struct termios2 *`.
                let raw = unsafe { read_user_termios2(arg)? };
                crate::console_tty::set_termios(raw);
                Ok(0)
            }
            TIOCGWINSZ => {
                let (rows, cols) = crate::console_tty::winsize();
                let ws = WireWinsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                // SAFETY: `arg` is the validated user `struct winsize *`.
                unsafe { write_user_winsize(arg, ws)? };
                Ok(0)
            }
            TIOCSWINSZ => {
                // SAFETY: `arg` is the validated user `struct winsize *`.
                let ws = unsafe { read_user_winsize(arg)? };
                crate::console_tty::set_winsize(ws.ws_row, ws.ws_col);
                Ok(0)
            }
            TIOCGPGRP => {
                // tcgetpgrp on /dev/console — the singleton fg pgrp. No
                // auto-install here (the caller's pgrp isn't reachable from
                // this crate); fd 0's TIOCGPGRP handles that fallback, and
                // getty sets the fg pgrp explicitly via tcsetpgrp.
                let pgrp = crate::console_tty::fg_pgrp() as i32;
                // SAFETY: `arg` is the validated user `pid_t *`.
                unsafe { write_user_i32(arg, pgrp)? };
                Ok(0)
            }
            TIOCSPGRP => {
                // SAFETY: `arg` is the validated user `pid_t *`.
                let pgrp = unsafe { read_user_i32(arg)? };
                if pgrp < 0 {
                    return Err(crate::FsError::InvalidData);
                }
                crate::console_tty::set_fg_pgrp(pgrp as u64);
                Ok(0)
            }
            TIOCSCTTY => {
                // Make /dev/console the caller's controlling terminal. The
                // per-task ctty table lives in userspace; reach it via the
                // hook installed at boot (see `install_ctty_hooks`).
                let _ = arg;
                crate::console_tty::tiocsctty();
                Ok(0)
            }
            TIOCNOTTY => {
                // Give up the controlling terminal (login's pre-claim reset).
                let _ = arg;
                crate::console_tty::tiocnotty();
                Ok(0)
            }
            TIOCGSID => {
                // tcgetsid(3): the tty session's leader sid (visible-pid).
                let sid = crate::console_tty::tiocgsid() as i32;
                // SAFETY: `arg` is the validated user `pid_t *`.
                unsafe { write_user_i32(arg, sid)? };
                Ok(0)
            }
            FIONREAD => {
                let n = crate::console_tty::readable_bytes() as i32;
                // SAFETY: `arg` is the validated user `int *`.
                unsafe { write_user_i32(arg, n)? };
                Ok(0)
            }
            TCSBRK | TCXONC | TCFLSH => {
                // Unbuffered output, no hardware BREAK / flow control on the
                // singleton console — drain/flush/flow have nothing to do.
                Ok(0)
            }
            KDGKBMODE | KDGETMODE => {
                // No VT layer: report the default (`K_XLATE` / `KD_TEXT` = 0).
                // SAFETY: `arg` is the validated user `int *`.
                unsafe { write_user_i32(arg, 0)? };
                Ok(0)
            }
            KDSKBMODE | KDSIGACCEPT => {
                // No VT keyboard/kbrequest state to change — accept + no-op.
                Ok(0)
            }
            VT_OPENQRY | VT_GETMODE | VT_GETSTATE | VT_ACTIVATE | VT_WAITACTIVE => {
                // No VT layer; ENOTTY lets a VT-aware agetty degrade to a
                // plain serial console instead of aborting.
                Err(crate::FsError::Unsupported)
            }
            _ => Err(crate::FsError::Unsupported),
        }
    }
}

// ── /dev/fd + /dev/stdin /dev/stdout /dev/stderr ─────────────────────
//
// Linux models these as symlinks that tools like `bash -c 'cat /dev/fd/0'`
// and musl `fopen("/dev/stdin", …)` rely on.  They point into /proc/self:
//
//   /dev/fd      → /proc/self/fd          (directory symlink)
//   /dev/stdin   → /proc/self/fd/0        (character-device symlink)
//   /dev/stdout  → /proc/self/fd/1
//   /dev/stderr  → /proc/self/fd/2
//
// Linux ref: `init/do_mounts.c` — the /dev/fd symlink is created by the
// devtmpfs init path; /dev/stdin etc. live in glibc's `/lib/udev/rules.d`
// or are created by `mknod` in the distro's initrd.  In any case the
// standard targets are /proc/self/fd/*.
//
// [[devfs-symlinks]] The VFS walker in `resolve_async` follows any node
// whose stat() reports `FileType::Symlink` by reading its target and
// re-resolving, so a simple readable node with the right stat suffices.

/// A symlink inside /dev — stat() is S_IFLNK, read() returns the
/// target string verbatim (the shape sys_readlink and resolve_async use).
#[derive(Debug)]
struct DevSymlink {
    /// Symlink target (absolute path).
    target: String,
    inode: u64,
}

pub(crate) fn symlink_file(name: &str, target: String) -> Arc<dyn FileOps> {
    Arc::new(DevSymlink {
        target,
        inode: named_inode(name, 2),
    })
}

impl FileOps for DevSymlink {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let bytes = self.target.as_bytes();
        let start = offset as usize;
        let n = if start >= bytes.len() {
            0
        } else {
            let avail = bytes.len() - start;
            let n = avail.min(buf.len());
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            n
        };
        Box::pin(async move { Ok(n) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        // size MUST equal the target length: sys_readlink sizes its
        // staging buffer from st.size so size:0 makes readlink return
        // an empty string.  See the same note in ProcFdFile::stat.
        Stat {
            size: self.target.len() as u64,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Symlink,
                perms: 0o777,
            },
            mtime_cycles: 0,
        }
    }
    fn ino(&self) -> u64 {
        self.inode
    }
}

/// An empty directory node used purely as a **mountpoint stub** under
/// `/dev` (e.g. `/dev/shm`, `/dev/mqueue`, `/dev/hugepages`). An init
/// system `open()`s these O_PATH|O_DIRECTORY to get a target fd and then
/// mounts tmpfs / mqueue / hugetlbfs over them; the mount is tracked by the
/// registry at that path, so this stub's (empty) contents are shadowed and
/// never observed once mounted.
struct DevEmptyDir {
    inode: u64,
}

impl DirOps for DevEmptyDir {
    fn ino(&self) -> u64 {
        self.inode
    }
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }
    fn iter(&self) -> Box<dyn Iterator<Item = crate::DirEntry> + '_> {
        Box::new(core::iter::empty())
    }
    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }
    fn symlink<'a>(&'a self, _name: &'a str, _target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }
}

fn valid_leaf_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

fn dynamic_lookup_file(
    nodes: &IrqSafeSpinLock<DynamicMap>,
    name: &str,
) -> Option<Arc<dyn FileOps>> {
    match nodes.lock().get(name).cloned()? {
        DynamicNode::Device(node) => Some(Arc::new(MknodFile { node }) as Arc<dyn FileOps>),
        DynamicNode::Symlink { target, inode } => {
            Some(Arc::new(DevSymlink { target, inode }) as Arc<dyn FileOps>)
        }
        DynamicNode::Directory(_) => None,
    }
}

fn dynamic_lookup_dir(nodes: &IrqSafeSpinLock<DynamicMap>, name: &str) -> Option<Arc<dyn DirOps>> {
    match nodes.lock().get(name).cloned()? {
        DynamicNode::Directory(dir) => Some(dir as Arc<dyn DirOps>),
        DynamicNode::Device(_) | DynamicNode::Symlink { .. } => None,
    }
}

fn dynamic_enumerate(nodes: &IrqSafeSpinLock<DynamicMap>) -> Vec<(String, FileType)> {
    nodes
        .lock()
        .iter()
        .map(|(name, node)| {
            let file_type = match node {
                DynamicNode::Device(node) => node.metadata.lock().file_type,
                DynamicNode::Symlink { .. } => FileType::Symlink,
                DynamicNode::Directory(_) => FileType::Dir,
            };
            (name.clone(), file_type)
        })
        .collect()
}

fn dynamic_symlink(
    nodes: &IrqSafeSpinLock<DynamicMap>,
    name: &str,
    target: &str,
) -> Result<Arc<dyn FileOps>, FsError> {
    if !valid_leaf_name(name) {
        return Err(FsError::InvalidPath);
    }
    let mut entries = nodes.lock();
    if entries.contains_key(name) {
        return Err(FsError::Busy);
    }
    let inode = NEXT_DYNAMIC_INO.fetch_add(1, Ordering::Relaxed);
    entries.insert(
        name.into(),
        DynamicNode::Symlink {
            target: target.into(),
            inode,
        },
    );
    Ok(Arc::new(DevSymlink {
        target: target.into(),
        inode,
    }) as Arc<dyn FileOps>)
}

fn dynamic_mkdir(
    nodes: &IrqSafeSpinLock<DynamicMap>,
    name: &str,
    perms: u16,
) -> Result<Arc<dyn DirOps>, FsError> {
    if !valid_leaf_name(name) {
        return Err(FsError::InvalidPath);
    }
    let mut entries = nodes.lock();
    if entries.contains_key(name) {
        return Err(FsError::Busy);
    }
    let dir = Arc::new(DynamicDirectory {
        inode: NEXT_DYNAMIC_INO.fetch_add(1, Ordering::Relaxed),
        perms: IrqSafeSpinLock::new(perms & 0o7777),
        entries: IrqSafeSpinLock::new(alloc::collections::BTreeMap::new()),
    });
    entries.insert(name.into(), DynamicNode::Directory(dir.clone()));
    Ok(dir as Arc<dyn DirOps>)
}

fn dynamic_unlink(nodes: &IrqSafeSpinLock<DynamicMap>, name: &str) -> Result<(), FsError> {
    let mut entries = nodes.lock();
    match entries.get(name) {
        Some(DynamicNode::Directory(_)) => Err(FsError::Busy),
        Some(_) => {
            entries.remove(name);
            Ok(())
        }
        None => Err(FsError::NotFound),
    }
}

fn dynamic_rmdir(nodes: &IrqSafeSpinLock<DynamicMap>, name: &str) -> Result<(), FsError> {
    let mut entries = nodes.lock();
    match entries.get(name) {
        Some(DynamicNode::Directory(dir)) if dir.entries.lock().is_empty() => {
            entries.remove(name);
            Ok(())
        }
        Some(DynamicNode::Directory(_)) => Err(FsError::Busy),
        Some(_) => Err(FsError::InvalidPath),
        None => Err(FsError::NotFound),
    }
}

fn dynamic_rename(
    nodes: &IrqSafeSpinLock<DynamicMap>,
    old_name: &str,
    new_name: &str,
) -> Result<(), FsError> {
    if !valid_leaf_name(new_name) {
        return Err(FsError::InvalidPath);
    }
    let mut entries = nodes.lock();
    if old_name == new_name {
        return if entries.contains_key(old_name) {
            Ok(())
        } else {
            Err(FsError::NotFound)
        };
    }
    let source = entries.get(old_name).cloned().ok_or(FsError::NotFound)?;
    if let Some(target) = entries.get(new_name) {
        let source_is_dir = matches!(source, DynamicNode::Directory(_));
        let target_is_dir = matches!(target, DynamicNode::Directory(_));
        if source_is_dir != target_is_dir {
            return Err(FsError::Busy);
        }
        if let DynamicNode::Directory(dir) = target {
            if !dir.entries.lock().is_empty() {
                return Err(FsError::Busy);
            }
        }
    }
    entries.remove(old_name);
    entries.insert(new_name.into(), source);
    Ok(())
}

impl DirOps for DynamicDirectory {
    fn ino(&self) -> u64 {
        self.inode
    }

    fn dir_mode(&self) -> u16 {
        *self.perms.lock()
    }

    fn set_dir_mode(&self, perms: u16) {
        *self.perms.lock() = perms & 0o7777;
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        dynamic_lookup_file(&self.entries, name)
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        dynamic_lookup_dir(&self.entries, name)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = DirEntry> + '_> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        dynamic_enumerate(&self.entries)
            .into_iter()
            .skip(cursor)
            .take(max)
            .collect()
    }

    fn mknod<'a>(
        &'a self,
        name: &'a str,
        file_type: FileType,
        rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            if !matches!(file_type, FileType::Special | FileType::Block) {
                return Err(FsError::Unsupported);
            }
            let node = mknod_register(&self.entries, name, file_type, rdev, 0o600)?;
            Ok(Arc::new(MknodFile { node }) as Arc<dyn FileOps>)
        })
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        let result = dynamic_symlink(&self.entries, name, target);
        Box::pin(async move { result })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        let result = dynamic_mkdir(&self.entries, name, 0o755);
        Box::pin(async move { result })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let result = dynamic_unlink(&self.entries, name);
        Box::pin(async move { result })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let result = dynamic_rmdir(&self.entries, name);
        Box::pin(async move { result })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        let result = dynamic_rename(&self.entries, old_name, new_name);
        Box::pin(async move { result })
    }
}

fn static_entry_type(name: &str) -> Option<FileType> {
    match name {
        "fd" | "stdin" | "stdout" | "stderr" | "rtc" | "ptmx" => Some(FileType::Symlink),
        "null" | "zero" | "full" | "random" | "urandom" | "kmsg" | "console" | "tty" | "tty0"
        | "tty1" | "uinput" | "fuse" | "fp0" | "fb0" | "tpm0" | "tpmrm0" | "rtc0" => {
            Some(FileType::Special)
        }
        "pts" | "shm" | "mqueue" | "hugepages" | "disk" | "input" | "snd" | "dri" => {
            Some(FileType::Dir)
        }
        _ => None,
    }
}

fn static_entry_visible(name: &str) -> bool {
    match name {
        "fp0" => FP_NODE.lock().is_some(),
        "fb0" => FB0_NODE.lock().is_some(),
        "tpm0" => TPM0_NODE.lock().is_some(),
        "tpmrm0" => TPMRM0_NODE.lock().is_some(),
        "snd" => SND_DIR.lock().is_some(),
        "dri" => DRI_DIR.lock().is_some(),
        _ => true,
    }
}

/// `DevFs` root directory. Static device paths have precedence, while the
/// runtime tree accepts udev-style device nodes, directories, and symlinks.
struct DevDir;

impl DirOps for DevDir {
    fn ino(&self) -> u64 {
        2
    }

    fn symlink<'a>(&'a self, name: &'a str, target: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        if !valid_leaf_name(name) || static_entry_type(name).is_some() {
            return Box::pin(async move { Err(FsError::Busy) });
        }
        let result = dynamic_symlink(&DYNAMIC_NODES, name, target);
        Box::pin(async move { result })
    }

    fn unlink<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        let result = dynamic_unlink(&DYNAMIC_NODES, name);
        Box::pin(async move { result })
    }

    fn rename<'a>(&'a self, old_name: &'a str, new_name: &'a str) -> FsFuture<'a, ()> {
        if !valid_leaf_name(new_name) || static_entry_type(new_name).is_some() {
            return Box::pin(async { Err(FsError::Busy) });
        }
        let result = dynamic_rename(&DYNAMIC_NODES, old_name, new_name);
        Box::pin(async move { result })
    }

    fn mkdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        if !valid_leaf_name(name) || static_entry_type(name).is_some() {
            return Box::pin(async { Err(FsError::Busy) });
        }
        let result = dynamic_mkdir(&DYNAMIC_NODES, name, 0o755);
        Box::pin(async move { result })
    }

    fn rmdir<'a>(&'a self, name: &'a str) -> FsFuture<'a, ()> {
        if static_entry_type(name).is_some() {
            return Box::pin(async { Err(FsError::Busy) });
        }
        let result = dynamic_rmdir(&DYNAMIC_NODES, name);
        Box::pin(async move { result })
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            // Static symlinks [[devfs-symlinks]].
            "fd" => Some(Arc::new(DevSymlink {
                target: "/proc/self/fd".into(),
                inode: named_inode("fd", 2),
            }) as Arc<dyn FileOps>),
            "stdin" => Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/0".into(),
                inode: named_inode("stdin", 2),
            }) as Arc<dyn FileOps>),
            "stdout" => Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/1".into(),
                inode: named_inode("stdout", 2),
            }) as Arc<dyn FileOps>),
            "stderr" => Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/2".into(),
                inode: named_inode("stderr", 2),
            }) as Arc<dyn FileOps>),
            "null" => Some(Arc::new(DevNull) as Arc<dyn FileOps>),
            "zero" => Some(Arc::new(DevZero) as Arc<dyn FileOps>),
            "full" => Some(Arc::new(crate::devfs_misc::DevFull) as Arc<dyn FileOps>),
            "random" => Some(Arc::new(DevBlockingRandom) as Arc<dyn FileOps>),
            "urandom" => Some(Arc::new(DevRandom) as Arc<dyn FileOps>),
            "kmsg" => Some(Arc::new(DevKmsg) as Arc<dyn FileOps>),
            // `tty1` is the conventional first VT node — `getty@tty1.service`
            // (and login on it) opens it. NARF has one console, so it and the
            // `tty0`/`console` aliases all resolve to the same singleton tty.
            "console" => Some(Arc::new(DevConsole {
                kind: ConsoleNodeKind::Console,
            }) as Arc<dyn FileOps>),
            "tty" => Some(Arc::new(DevConsole {
                kind: ConsoleNodeKind::CurrentTty,
            }) as Arc<dyn FileOps>),
            "tty0" => Some(Arc::new(DevConsole {
                kind: ConsoleNodeKind::Virtual(0),
            }) as Arc<dyn FileOps>),
            "tty1" => Some(Arc::new(DevConsole {
                kind: ConsoleNodeKind::Virtual(1),
            }) as Arc<dyn FileOps>),
            "ptmx" => Some(symlink_file("ptmx", "pts/ptmx".into())),
            "fb0" if FB0_NODE.lock().is_some() => Some(Arc::new(DevFb0Proxy) as Arc<dyn FileOps>),
            // Userspace input-injection control device.
            // Linux ref: `drivers/input/misc/uinput.c`.
            "uinput" => {
                Some(Arc::new(crate::devfs_input::UinputControlFile::new()) as Arc<dyn FileOps>)
            }
            // FUSE control device: each open mints a fresh connection.
            // Linux ref: `fs/fuse/dev.c` — /dev/fuse (misc char, minor 229).
            "fuse" => Some(Arc::new(DevFuseNode) as Arc<dyn FileOps>),
            "fp0" if FP_NODE.lock().is_some() => Some(Arc::new(DevFp) as Arc<dyn FileOps>),
            "tpm0" if TPM0_NODE.lock().is_some() => {
                Some(Arc::new(DevTpm0Proxy) as Arc<dyn FileOps>)
            }
            "tpmrm0" if TPMRM0_NODE.lock().is_some() => {
                Some(Arc::new(DevTpmRm0Proxy) as Arc<dyn FileOps>)
            }
            // Real-time clock char device. `hwclock --show` reads it via
            // ioctl(RTC_RD_TIME). Linux ref: `drivers/rtc/dev.c`. `/dev/rtc`
            // is the conventional first-RTC alias — a symlink to rtc0 (this
            // devfs has a DevSymlink node type [[devfs-symlinks]]).
            "rtc0" => Some(Arc::new(crate::devfs_rtc::DevRtc) as Arc<dyn FileOps>),
            "rtc" => Some(Arc::new(DevSymlink {
                target: "/dev/rtc0".into(),
                inode: named_inode("rtc", 2),
            }) as Arc<dyn FileOps>),
            // Dynamic: ttyUSB<N> USB-to-serial ports.
            // Linux ref: `drivers/usb/serial/usb-serial.c:tty_port_register_device`.
            name if name.starts_with("ttyUSB") && name[6..].chars().all(|c| c.is_ascii_digit()) => {
                tty_usb_lookup(name)
            }
            // Dynamic: video<N> V4L2 camera nodes.
            // Linux ref: `drivers/media/v4l2-core/v4l2-dev.c:__video_register_device`.
            name if name.starts_with("video") && name[5..].chars().all(|c| c.is_ascii_digit()) => {
                video_lookup(name)
            }
            // Dynamic: rfcomm<N> Bluetooth serial ports.
            // Linux ref: `net/bluetooth/rfcomm/tty.c:318` — rfcomm_dev_add.
            name if name.starts_with("rfcomm") && name[6..].chars().all(|c| c.is_ascii_digit()) => {
                rfcomm_lookup(name)
            }
            // Dynamic: query the block-device registry after static names miss.
            // Covers registered names like "nvme0", "sata0p1", "vblk0", etc.
            _ => crate::devfs_block::lookup_block_file(name)
                // Then any node or symlink created in the writable devtmpfs.
                .or_else(|| dynamic_lookup_file(&DYNAMIC_NODES, name)),
        }
    }

    /// Look up a subdirectory.
    /// - `/dev/pts`   → `DevPts` (pseudoterminal slave nodes)
    /// - `/dev/disk`  → `DevDiskDir` (by-label / by-partuuid lookups)
    /// - `/dev/input` → `DevInputDir` (evdev event nodes, Wave 12 bridge)
    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        match name {
            "pts" => Some(Arc::new(crate::devfs_pty::DevPts) as Arc<dyn DirOps>),
            // Mountpoint stubs: an init mounts tmpfs/mqueue/hugetlbfs over
            // these; they only need to exist so the O_PATH target open works.
            "shm" => Some(Arc::new(DevEmptyDir { inode: 4 }) as Arc<dyn DirOps>),
            "mqueue" => Some(Arc::new(DevEmptyDir { inode: 5 }) as Arc<dyn DirOps>),
            "hugepages" => Some(Arc::new(DevEmptyDir { inode: 6 }) as Arc<dyn DirOps>),
            "disk" => Some(Arc::new(crate::devfs_block::DevDiskDir) as Arc<dyn DirOps>),
            "input" => Some(Arc::new(crate::devfs_input::DevInputDir) as Arc<dyn DirOps>),
            // Sound subsystem — delegate installed by narf-drivers-sound.
            "snd" => SND_DIR.lock().clone(),
            // DRM/DRI subsystem — delegate installed by narf-drivers-gpu.
            // Linux ref: `drivers/gpu/drm/drm_drv.c::drm_dev_register`.
            "dri" => DRI_DIR.lock().clone(),
            _ => dynamic_lookup_dir(&DYNAMIC_NODES, name),
        }
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    /// `mknod(/dev/<name>, S_IFCHR|S_IFBLK, dev_t)` — udev's coldplug node
    /// creation. Registers a dynamic node that `stat`s as the right special
    /// device with `st_rdev == rdev`; the node is then visible via `lookup`
    /// and `enumerate`. A static name of the same basename wins on lookup, so
    /// a re-mknod of e.g. "null" is inert. Linux ref: `devtmpfs`'s mknod path.
    fn mknod<'a>(
        &'a self,
        name: &'a str,
        file_type: FileType,
        rdev: u64,
    ) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            // Char/block only — a FIFO/socket/regular mknod under /dev is not a
            // device node; reject so the caller falls back to a plain file.
            if !matches!(file_type, FileType::Special | FileType::Block) {
                return Err(FsError::Unsupported);
            }
            if !valid_leaf_name(name) || static_entry_type(name).is_some() {
                return Err(FsError::Busy);
            }
            // mknod_common immediately applies the caller's mode and owners;
            // use Linux devtmpfs's conservative initial root-owned mode.
            let node = mknod_register(&DYNAMIC_NODES, name, file_type, rdev, 0o600)?;
            Ok(Arc::new(MknodFile { node }) as Arc<dyn FileOps>)
        })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // Static entries only — dynamic block-device names don't
        // satisfy `&'static str` so they don't appear here; use
        // `enumerate()` for a full readdir listing.
        const ENTRIES: &[DirEntry] = &[
            // Symlinks [[devfs-symlinks]].
            DirEntry {
                name: "fd",
                file_type: FileType::Symlink,
            },
            DirEntry {
                name: "stdin",
                file_type: FileType::Symlink,
            },
            DirEntry {
                name: "stdout",
                file_type: FileType::Symlink,
            },
            DirEntry {
                name: "stderr",
                file_type: FileType::Symlink,
            },
            DirEntry {
                name: "null",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "zero",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "full",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "random",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "urandom",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "kmsg",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "console",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "tty",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "tty0",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "tty1",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "ptmx",
                file_type: FileType::Symlink,
            },
            DirEntry {
                name: "fb0",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "uinput",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "fuse",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "fp0",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "tpm0",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "tpmrm0",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "rtc0",
                file_type: FileType::Special,
            },
            DirEntry {
                name: "rtc",
                file_type: FileType::Symlink,
            },
            DirEntry {
                name: "pts",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "shm",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "mqueue",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "hugepages",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "disk",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "input",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "snd",
                file_type: FileType::Dir,
            },
            DirEntry {
                name: "dri",
                file_type: FileType::Dir,
            },
        ];
        Box::new(
            ENTRIES
                .iter()
                .copied()
                .filter(|entry| static_entry_visible(entry.name)),
        )
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        // Static entries plus all registered block devices. Block
        // devices that share a name with a static entry are skipped
        // (static entry wins, matching Linux's static-node precedence).
        let static_entries: &[(&str, FileType)] = &[
            // Symlinks [[devfs-symlinks]].
            ("fd", FileType::Symlink),
            ("stdin", FileType::Symlink),
            ("stdout", FileType::Symlink),
            ("stderr", FileType::Symlink),
            ("null", FileType::Special),
            ("zero", FileType::Special),
            ("full", FileType::Special),
            ("random", FileType::Special),
            ("urandom", FileType::Special),
            ("kmsg", FileType::Special),
            ("console", FileType::Special),
            ("tty", FileType::Special),
            ("tty0", FileType::Special),
            ("tty1", FileType::Special),
            ("ptmx", FileType::Symlink),
            ("fb0", FileType::Special),
            ("uinput", FileType::Special),
            ("fuse", FileType::Special),
            ("fp0", FileType::Special),
            ("tpm0", FileType::Special),
            ("tpmrm0", FileType::Special),
            ("rtc0", FileType::Special),
            ("rtc", FileType::Symlink),
            ("pts", FileType::Dir),
            ("shm", FileType::Dir),
            ("mqueue", FileType::Dir),
            ("hugepages", FileType::Dir),
            ("disk", FileType::Dir),
            ("input", FileType::Dir),
            ("snd", FileType::Dir),
            ("dri", FileType::Dir),
        ];
        let static_names: Vec<String> = static_entries.iter().map(|(n, _)| (*n).into()).collect();
        let block_extras: Vec<(String, FileType)> = crate::devfs_block::enumerate_block_devices()
            .into_iter()
            .filter(|(name, _)| !static_names.iter().any(|s| s == name))
            .collect();

        let rfcomm_extras = rfcomm_enumerate();
        let tty_usb_extras = tty_usb_enumerate();
        let video_extras = video_enumerate();
        // Runtime-created files, symlinks, and directories that don't collide
        // with a static name.
        let dynamic_extras: Vec<(String, FileType)> = dynamic_enumerate(&DYNAMIC_NODES)
            .into_iter()
            .filter(|(name, _)| !static_names.iter().any(|s| s == name))
            .collect();

        static_entries
            .iter()
            .filter(|(name, _)| static_entry_visible(name))
            .map(|(n, t)| ((*n).into(), *t))
            .chain(block_extras)
            .chain(rfcomm_extras)
            .chain(tty_usb_extras)
            .chain(video_extras)
            .chain(dynamic_extras)
            .skip(cursor)
            .take(max)
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        let v = self.enumerate(cursor, max);
        Box::pin(async move { Ok(v) })
    }
}

/// Mountable handle. `DevFs::new()` returns one suitable for
/// `registry().mount("/dev", DevFs::new())`.
#[derive(Debug)]
pub struct DevFs {
    name: String,
}

impl DevFs {
    pub fn new() -> Self {
        Self {
            name: "devtmpfs".into(),
        }
    }
}

impl Default for DevFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FsInstance for DevFs {
    fn root(&self) -> Arc<dyn DirOps> {
        Arc::new(DevDir)
    }
    fn name(&self) -> &str {
        &self.name
    }
}

/// Boot helper: mount DevFs at `/dev` if no FS is already mounted
/// there. Idempotent — re-running silently no-ops on `Busy`.
/// Use during kernel init to give every user task /dev/null,
/// /dev/zero, /dev/random, /dev/urandom out of the box.
pub fn mount_default() {
    let auth = crate::bootstrap_mount_authority();
    let _ = crate::registry().mount(&auth, "/dev", DevFs::new());
}

// ── DevSymlink + /dev/fd smokes ───────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Poll one future exactly once using a no-op waker (same helper
/// pattern as `procfs::poll_once`, duplicated here to avoid an
/// inter-module `pub(crate)` dependency).
fn poll_once_devfs<F: core::future::Future>(fut: F) -> Option<F::Output> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(|data| RawWaker::new(data, &VTABLE), |_| {}, |_| {}, |_| {});
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    // SAFETY: VTABLE is a valid no-op vtable; the waker never outlives this stack frame.
    let waker = unsafe { Waker::from_raw(raw) };
    let mut cx = Context::from_waker(&waker);
    let mut pinned = core::pin::pin!(fut);
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Smoke: /dev/fd lookup returns a Symlink-typed node.
fn smoke_dev_fd_is_symlink() -> TestResult {
    let dir = DevDir;
    match dir.lookup("fd") {
        Some(f) if f.stat().mode.file_type == FileType::Symlink => TestResult::Pass,
        Some(_) => TestResult::Fail("/dev/fd not reported as a symlink"),
        None => TestResult::Fail("/dev/fd lookup returned None"),
    }
}
kernel_test_in!("filesystem/devfs", smoke_dev_fd_is_symlink);

/// `/dev/kmsg` writes strip the Linux "<pri>,<seq>,<ts>,<flags>;" metadata
/// prefix so the human-readable message is what gets echoed, while non-record
/// text (a bare `echo`) and malformed prefixes pass through unchanged.
fn smoke_dev_kmsg_visible_message_strips_meta() -> TestResult {
    // Canonical systemd record: metadata, ';', message, trailing newline.
    if kmsg_visible_message(b"6,42,12345,-;hello udev\n") != "hello udev" {
        return TestResult::Fail("kmsg metadata prefix not stripped");
    }
    // Bare echo (no ';'): passed through verbatim (minus trailing newline).
    if kmsg_visible_message(b"just a line\n") != "just a line" {
        return TestResult::Fail("bare kmsg line not preserved");
    }
    // A ';' whose left side isn't pure numeric metadata must NOT be stripped.
    if kmsg_visible_message(b"key=val;more") != "key=val;more" {
        return TestResult::Fail("non-metadata prefix wrongly stripped");
    }
    // Empty write yields an empty message (nothing echoed).
    if !kmsg_visible_message(b"").is_empty() {
        return TestResult::Fail("empty kmsg write not empty");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs",
    smoke_dev_kmsg_visible_message_strips_meta
);

/// devtmpfs is writable for runtime aliases such as journald's `/dev/log`.
fn smoke_dev_runtime_symlink_create_lookup_unlink() -> TestResult {
    let dir = DevDir;
    let name = "log-test";
    let target = "/run/systemd/journal/dev-log";
    let created = poll_once_devfs(dir.symlink(name, target));
    match created {
        Some(Ok(file)) if file.stat().mode.file_type == FileType::Symlink => {}
        _ => return TestResult::Fail("devfs runtime symlink create failed"),
    }
    match dir.lookup(name) {
        Some(file) if file.stat().size == target.len() as u64 => {}
        _ => return TestResult::Fail("devfs runtime symlink lookup failed"),
    }
    if !matches!(poll_once_devfs(dir.unlink(name)), Some(Ok(()))) {
        return TestResult::Fail("devfs runtime symlink unlink failed");
    }
    if dir.lookup(name).is_some() {
        return TestResult::Fail("devfs runtime symlink survived unlink");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs",
    smoke_dev_runtime_symlink_create_lookup_unlink
);

/// Smoke: /dev/{shm,mqueue,hugepages} exist as (empty) mountpoint-stub
/// directories that an init O_PATH-opens to mount tmpfs / mqueue /
/// hugetlbfs over.
fn smoke_dev_mountpoint_stub_dirs() -> TestResult {
    let dir = DevDir;
    for name in ["shm", "mqueue", "hugepages"] {
        match dir.lookup_dir(name) {
            Some(d) => {
                if !d.enumerate(0, 8).is_empty() {
                    return TestResult::Fail("mountpoint stub dir should be empty");
                }
            }
            None => return TestResult::Fail("/dev mountpoint stub dir missing"),
        }
    }
    // And they must appear in the /dev enumeration so `ls /dev` shows them.
    let listed = DevDir.enumerate(0, 256);
    for name in ["shm", "mqueue", "hugepages"] {
        if !listed.iter().any(|(n, t)| n == name && *t == FileType::Dir) {
            return TestResult::Fail("mountpoint stub dir not enumerated");
        }
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs", smoke_dev_mountpoint_stub_dirs);

/// Smoke: `mknod` of a char node on devfs succeeds and the node then stats
/// as a char device (`FileType::Special`) with the requested `st_rdev`, and is
/// enumerated. This is the udev-coldplug `/dev/<name>` creation path. Never a
/// bare -1: `mknod` returns a usable FileOps.
fn smoke_dev_mknod_char_node() -> TestResult {
    __reset_mknod_for_test();
    let dir = DevDir;
    // dev_t for a char device, e.g. major 10 / minor 200 → (10<<8)|200.
    let rdev: u64 = (10u64 << 8) | 200;
    let node = match poll_once_devfs(dir.mknod("coldplug-char0", FileType::Special, rdev)) {
        Some(Ok(n)) => n,
        Some(Err(_)) => return TestResult::Fail("mknod char node returned an error"),
        None => return TestResult::Fail("mknod char node future did not resolve"),
    };
    // The returned node stats as a char device with the right rdev.
    if node.stat().mode.file_type != FileType::Special {
        return TestResult::Fail("mknod char node does not stat as Special (S_IFCHR)");
    }
    if node.rdev() != rdev {
        return TestResult::Fail("mknod char node st_rdev != requested dev_t");
    }
    // It is now discoverable via lookup and enumerate.
    match dir.lookup("coldplug-char0") {
        Some(n) if n.stat().mode.file_type == FileType::Special => {}
        Some(_) => return TestResult::Fail("looked-up mknod node not a char device"),
        None => return TestResult::Fail("mknod node not found via lookup"),
    }
    let listed = dir.enumerate(0, 512);
    if !listed
        .iter()
        .any(|(n, t)| n == "coldplug-char0" && *t == FileType::Special)
    {
        return TestResult::Fail("mknod node not enumerated");
    }
    __reset_mknod_for_test();
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs", smoke_dev_mknod_char_node);

/// Linux devtmpfs keeps char/block identity, `st_rdev`, ownership, mode, and
/// inode identity on dynamically-created device nodes. It also applies the
/// usual single-directory rename/unlink rules atomically.
fn smoke_dev_mknod_linux_metadata_and_mutation() -> TestResult {
    __reset_mknod_for_test();
    let dir = DevDir;
    let rdev = linux_makedev(259, 513);
    let node = match poll_once_devfs(dir.mknod("coldplug-block0", FileType::Block, rdev)) {
        Some(Ok(node)) => node,
        _ => return TestResult::Fail("mknod block node failed"),
    };
    if node.stat().mode.file_type != FileType::Block || node.rdev() != rdev || node.ino() == 0 {
        return TestResult::Fail("block node identity is not Linux-shaped");
    }
    if !matches!(poll_once_devfs(node.set_perms(0o640)), Some(Ok(())))
        || !matches!(poll_once_devfs(node.set_owners(12, 34)), Some(Ok(())))
    {
        return TestResult::Fail("block node metadata update failed");
    }
    let inode = node.ino();
    let looked_up = match dir.lookup("coldplug-block0") {
        Some(node) => node,
        None => return TestResult::Fail("block node disappeared after metadata update"),
    };
    if looked_up.stat().mode.perms != 0o640
        || looked_up.owners() != (12, 34)
        || looked_up.ino() != inode
    {
        return TestResult::Fail("block node metadata did not persist across lookup");
    }
    if !matches!(
        poll_once_devfs(dir.mknod("coldplug-block0", FileType::Block, rdev)),
        Some(Err(FsError::Busy))
    ) {
        return TestResult::Fail("duplicate mknod did not report EEXIST/Busy");
    }
    if !matches!(
        poll_once_devfs(dir.rename("coldplug-block0", "coldplug-block1")),
        Some(Ok(()))
    ) || dir.lookup("coldplug-block0").is_some()
    {
        return TestResult::Fail("dynamic device rename failed");
    }
    match dir.lookup("coldplug-block1") {
        Some(node) if node.ino() == inode && node.stat().mode.file_type == FileType::Block => {}
        _ => return TestResult::Fail("renamed block node lost identity"),
    }
    if !matches!(poll_once_devfs(dir.unlink("coldplug-block1")), Some(Ok(())))
        || dir.lookup("coldplug-block1").is_some()
    {
        return TestResult::Fail("dynamic device unlink failed");
    }
    __reset_mknod_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs",
    smoke_dev_mknod_linux_metadata_and_mutation
);

/// udev creates hierarchy such as `/dev/{char,block}/MAJOR:MINOR` at runtime.
/// Pin nested mkdir, symlink, readdir, non-empty-rmdir, and cleanup behavior.
fn smoke_dev_dynamic_directory_tree() -> TestResult {
    __reset_mknod_for_test();
    let root = DevDir;
    let char_dir = match poll_once_devfs(root.mkdir("char-test")) {
        Some(Ok(dir)) => dir,
        _ => return TestResult::Fail("devtmpfs mkdir failed"),
    };
    if char_dir.ino() == 0 || char_dir.dir_mode() != 0o755 {
        return TestResult::Fail("dynamic directory metadata mismatch");
    }
    match poll_once_devfs(char_dir.symlink("1:3", "../null")) {
        Some(Ok(link)) if link.stat().mode.file_type == FileType::Symlink => {}
        _ => return TestResult::Fail("nested devtmpfs symlink failed"),
    }
    if !char_dir
        .enumerate(0, 16)
        .iter()
        .any(|(name, ty)| name == "1:3" && *ty == FileType::Symlink)
    {
        return TestResult::Fail("nested devtmpfs entry not enumerated");
    }
    if !matches!(
        poll_once_devfs(root.rmdir("char-test")),
        Some(Err(FsError::Busy))
    ) {
        return TestResult::Fail("non-empty dynamic directory was removed");
    }
    if !matches!(poll_once_devfs(char_dir.unlink("1:3")), Some(Ok(())))
        || !matches!(poll_once_devfs(root.rmdir("char-test")), Some(Ok(())))
        || root.lookup_dir("char-test").is_some()
    {
        return TestResult::Fail("dynamic directory cleanup failed");
    }
    __reset_mknod_for_test();
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs", smoke_dev_dynamic_directory_tree);

/// Pin the Linux device identities and stable path inodes used by libc,
/// udev, and init-system probes.
fn smoke_dev_static_linux_metadata() -> TestResult {
    let dir = DevDir;
    let expected = [
        ("null", linux_makedev(1, 3), 0o666),
        ("zero", linux_makedev(1, 5), 0o666),
        ("full", linux_makedev(1, 7), 0o666),
        ("random", linux_makedev(1, 8), 0o666),
        ("urandom", linux_makedev(1, 9), 0o666),
        ("kmsg", linux_makedev(1, 11), 0o600),
        ("console", linux_makedev(5, 1), 0o600),
        ("tty", linux_makedev(5, 0), 0o666),
        ("uinput", linux_makedev(10, 223), 0o660),
        ("fuse", linux_makedev(10, 229), 0o600),
    ];
    for (name, rdev, perms) in expected {
        let node = match dir.lookup(name) {
            Some(node) => node,
            None => return TestResult::Fail("required static /dev node missing"),
        };
        let stat = node.stat();
        if stat.mode.file_type != FileType::Special
            || stat.mode.perms != perms
            || node.rdev() != rdev
            || node.ino() == 0
        {
            return TestResult::Fail("static /dev node metadata mismatch");
        }
    }
    if dir.lookup("random").unwrap().rdev() == dir.lookup("urandom").unwrap().rdev() {
        return TestResult::Fail("random and urandom share st_rdev");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs", smoke_dev_static_linux_metadata);

/// Readdir must agree with lookup and must not advertise optional hardware
/// nodes until their driver has actually registered a backing object.
fn smoke_dev_enumeration_has_no_phantom_nodes() -> TestResult {
    let dir = DevDir;
    let entries = dir.enumerate(0, 512);
    for required in ["kmsg", "pts", "shm", "mqueue", "hugepages"] {
        if !entries.iter().any(|(name, _)| name == required) {
            return TestResult::Fail("required devtmpfs entry absent from readdir");
        }
    }
    for optional in ["fb0", "fp0", "tpm0", "tpmrm0", "snd", "dri"] {
        let advertised = entries.iter().any(|(name, _)| name == optional);
        let present = dir.lookup(optional).is_some() || dir.lookup_dir(optional).is_some();
        if advertised != present {
            return TestResult::Fail("optional devtmpfs entry disagrees with lookup");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/devfs",
    smoke_dev_enumeration_has_no_phantom_nodes
);

fn smoke_devfs_reports_devtmpfs_name() -> TestResult {
    if DevFs::new().name() == "devtmpfs" {
        TestResult::Pass
    } else {
        TestResult::Fail("DevFs does not identify as Linux devtmpfs")
    }
}
kernel_test_in!("filesystem/devfs", smoke_devfs_reports_devtmpfs_name);

/// Smoke: /dev/stdin resolves to /proc/self/fd/0.
fn smoke_dev_stdin_target() -> TestResult {
    let dir = DevDir;
    let node = match dir.lookup("stdin") {
        Some(n) => n,
        None => return TestResult::Fail("/dev/stdin lookup returned None"),
    };
    if node.stat().mode.file_type != FileType::Symlink {
        return TestResult::Fail("/dev/stdin not a symlink");
    }
    let mut buf = [0u8; 64];
    match poll_once_devfs(node.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s == "/proc/self/fd/0" {
                TestResult::Pass
            } else {
                TestResult::Fail("/dev/stdin target is not /proc/self/fd/0")
            }
        }
        _ => TestResult::Fail("/dev/stdin read failed"),
    }
}
kernel_test_in!("filesystem/devfs", smoke_dev_stdin_target);

/// Smoke: /dev/stdout resolves to /proc/self/fd/1.
fn smoke_dev_stdout_target() -> TestResult {
    let dir = DevDir;
    let node = match dir.lookup("stdout") {
        Some(n) => n,
        None => return TestResult::Fail("/dev/stdout lookup returned None"),
    };
    let mut buf = [0u8; 64];
    match poll_once_devfs(node.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s == "/proc/self/fd/1" {
                TestResult::Pass
            } else {
                TestResult::Fail("/dev/stdout target is not /proc/self/fd/1")
            }
        }
        _ => TestResult::Fail("/dev/stdout read failed"),
    }
}
kernel_test_in!("filesystem/devfs", smoke_dev_stdout_target);

/// Smoke: /dev/stderr resolves to /proc/self/fd/2.
fn smoke_dev_stderr_target() -> TestResult {
    let dir = DevDir;
    let node = match dir.lookup("stderr") {
        Some(n) => n,
        None => return TestResult::Fail("/dev/stderr lookup returned None"),
    };
    let mut buf = [0u8; 64];
    match poll_once_devfs(node.read(0, &mut buf)) {
        Some(Ok(n)) if n > 0 => {
            let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
            if s == "/proc/self/fd/2" {
                TestResult::Pass
            } else {
                TestResult::Fail("/dev/stderr target is not /proc/self/fd/2")
            }
        }
        _ => TestResult::Fail("/dev/stderr read failed"),
    }
}
kernel_test_in!("filesystem/devfs", smoke_dev_stderr_target);

/// Smoke: /dev/fd stat().size == len("/proc/self/fd") = 13.
fn smoke_dev_fd_stat_size() -> TestResult {
    let dir = DevDir;
    let node = match dir.lookup("fd") {
        Some(n) => n,
        None => return TestResult::Fail("/dev/fd lookup returned None"),
    };
    let expected = "/proc/self/fd".len() as u64;
    let actual = node.stat().size;
    if actual == expected {
        TestResult::Pass
    } else {
        TestResult::Fail("/dev/fd stat().size does not match target length")
    }
}
kernel_test_in!("filesystem/devfs", smoke_dev_fd_stat_size);

/// Smoke: iter() lists fd/stdin/stdout/stderr as Symlink entries.
fn smoke_dev_dir_iter_contains_symlinks() -> TestResult {
    let dir = DevDir;
    let mut found_fd = false;
    let mut found_stdin = false;
    let mut found_stdout = false;
    let mut found_stderr = false;
    for entry in dir.iter() {
        if entry.file_type != FileType::Symlink {
            continue;
        }
        match entry.name {
            "fd" => found_fd = true,
            "stdin" => found_stdin = true,
            "stdout" => found_stdout = true,
            "stderr" => found_stderr = true,
            _ => {}
        }
    }
    if found_fd && found_stdin && found_stdout && found_stderr {
        TestResult::Pass
    } else {
        TestResult::Fail("iter() missing one or more of fd/stdin/stdout/stderr symlinks")
    }
}
kernel_test_in!("filesystem/devfs", smoke_dev_dir_iter_contains_symlinks);

/// Smoke: the RNG-pool credit ioctls on /dev/urandom succeed (0)
/// instead of the default `ENOTTY`, so `systemd-random-seed`'s
/// `RNDADDENTROPY` completes cleanly. The arg-free arms are exercised
/// here (RNDGETENTCNT needs a live user pointer, covered at boot).
fn smoke_dev_random_rnd_ioctls_ok() -> TestResult {
    let dev = DevRandom;
    // RNDADDTOENTCNT (_IOW('R', 0x01, int)) = 0x40045201.
    if dev.ioctl(0x4004_5201, 0) != Ok(0) {
        return TestResult::Fail("RNDADDTOENTCNT should be an accepted no-op (0)");
    }
    // RNDADDENTROPY (_IOW('R', 0x03, ...)) = 0x40085203 — the one
    // systemd-random-seed issues to credit the saved seed.
    if dev.ioctl(0x4008_5203, 0) != Ok(0) {
        return TestResult::Fail("RNDADDENTROPY should be an accepted no-op (0)");
    }
    // RNDRESEEDCRNG (_IO('R', 0x07)) = 0x5207.
    if dev.ioctl(0x0000_5207, 0) != Ok(0) {
        return TestResult::Fail("RNDRESEEDCRNG should be an accepted no-op (0)");
    }
    // A non-'R' ioctl still falls through to Unsupported (→ ENOTTY).
    if dev.ioctl(0x0000_1234, 0) != Err(FsError::Unsupported) {
        return TestResult::Fail("non-RNG ioctl should stay Unsupported");
    }
    // An unknown 'R' nr is also Unsupported.
    if dev.ioctl(0x0000_5299, 0) != Err(FsError::Unsupported) {
        return TestResult::Fail("unknown RNG ioctl nr should stay Unsupported");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs", smoke_dev_random_rnd_ioctls_ok);

/// `/dev/kmsg`'s poll/read fast-path (`klog::live_len` + `klog::read_at`)
/// must agree byte-for-byte with the allocating `klog::snapshot()` it
/// replaces. This guards the hot path that epoll/journald hammer: a
/// regression back to `snapshot()` per poll/read reintroduces the
/// whole-ring reallocation that starved the desktop boot.
fn smoke_kmsg_read_at_matches_snapshot() -> TestResult {
    // Seed a known record so the live region is non-empty and spans a wrap
    // boundary in content terms; operate read-only against the live ring.
    narf_console::klog::record("kmsg-fastpath-probe\n");
    let snap = narf_console::klog::snapshot();
    if narf_console::klog::live_len() != snap.len() {
        return TestResult::Fail("live_len() disagrees with snapshot().len()");
    }
    let mut buf = [0u8; 512];
    // Full-window, mid-window, and boundary reads must equal the snapshot slice.
    let offsets = [
        0usize,
        snap.len() / 2,
        snap.len().saturating_sub(7),
        snap.len(),
    ];
    for &off in &offsets {
        if off > snap.len() {
            continue;
        }
        let cap = buf.len().min(snap.len().saturating_sub(off));
        let n = narf_console::klog::read_at(off, &mut buf[..cap.max(1)]);
        let expect = &snap[off..off + cap];
        if n != expect.len() || buf[..n] != *expect {
            return TestResult::Fail("read_at() window differs from snapshot()");
        }
    }
    // At or past the end yields 0 (no readable bytes).
    if narf_console::klog::read_at(snap.len(), &mut buf) != 0 {
        return TestResult::Fail("read_at() at end should return 0");
    }
    if narf_console::klog::read_at(snap.len() + 4096, &mut buf) != 0 {
        return TestResult::Fail("read_at() past end should return 0");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/devfs", smoke_kmsg_read_at_matches_snapshot);
