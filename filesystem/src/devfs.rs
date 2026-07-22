//! `DevFs` — minimal `/dev/null` + `/dev/zero` virtual filesystem.
//!
//! Real C programs reach for these almost universally — discarding
//! debug output via `> /dev/null`, zero-filling buffers via `dd
//! if=/dev/zero`, etc. Without them user programs that mention the
//! paths in a never-taken branch still need them to *exist* (or
//! the open call surfaces a NotFound that the caller doesn't
//! distinguish from a real failure).
//!
//! Layout: a single `DevFs::new()` returns an `FsInstance` whose
//! root holds two read-only special files.
//!
//! Semantics:
//!   - `/dev/null`: read returns 0 (immediate EOF); write returns
//!     the requested length (bytes silently discarded).
//!   - `/dev/zero`: read fills the user buffer with zeros and
//!     returns the requested length; write discards.
//!
//! Stat reports `FileType::Special` so `S_ISCHR(...)` consumers see
//! the right shape.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
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

/// One `mknod`-created device node: a char/block special with a fixed
/// `dev_t`. Read/write are no-ops (there is no backing driver — the node
/// exists so `stat`/`open` behave), which matches how a bare `mknod` node
/// with no registered driver behaves until a driver claims the major.
#[derive(Clone)]
struct MknodEntry {
    file_type: FileType,
    rdev: u64,
    perms: u16,
}

static MKNOD_NODES: IrqSafeSpinLock<alloc::collections::BTreeMap<String, MknodEntry>> =
    IrqSafeSpinLock::new(alloc::collections::BTreeMap::new());

/// FileOps for a `mknod`-created char/block node.
struct MknodFile {
    entry: MknodEntry,
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
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: self.entry.file_type,
                perms: self.entry.perms,
            },
            mtime_cycles: 0,
        }
    }
    fn rdev(&self) -> u64 {
        self.entry.rdev
    }
}

/// Register a `mknod`-created node. `file_type` is `Special` (char) or
/// `Socket`/etc; only char/block are meaningful here. Overwrites any prior
/// dynamic node of the same name (a caller is expected to have unlink'd first,
/// but tolerating a re-mknod keeps udev's re-trigger idempotent).
fn mknod_register(name: &str, file_type: FileType, rdev: u64, perms: u16) {
    MKNOD_NODES.lock().insert(
        name.into(),
        MknodEntry {
            file_type,
            rdev,
            perms,
        },
    );
}

/// Look up a `mknod`-created node by name.
fn mknod_lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let entry = MKNOD_NODES.lock().get(name).cloned()?;
    Some(Arc::new(MknodFile { entry }) as Arc<dyn FileOps>)
}

/// Snapshot the dynamic-node names for `enumerate`.
fn mknod_enumerate() -> Vec<(String, FileType)> {
    MKNOD_NODES
        .lock()
        .iter()
        .map(|(n, e)| (n.clone(), e.file_type))
        .collect()
}

/// Reset the dynamic-node registry (test isolation).
#[doc(hidden)]
pub fn __reset_mknod_for_test() {
    MKNOD_NODES.lock().clear();
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
struct DevKmsg;

impl FileOps for DevKmsg {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let snap = narf_console::klog::snapshot();
        let off = offset as usize;
        let n = if off >= snap.len() {
            0
        } else {
            let avail = snap.len() - off;
            let n = avail.min(buf.len());
            buf[..n].copy_from_slice(&snap[off..off + n]);
            n
        };
        Box::pin(async move { Ok(n) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        // Accept-and-discard so `echo foo > /dev/kmsg` doesn't error.
        let len = buf.len();
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        let len = narf_console::klog::snapshot().len();
        Stat {
            size: len as u64,
            blocks: len.div_ceil(512) as u64,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o444,
            },
            mtime_cycles: 0,
        }
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
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
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

    fn poll_readiness(&self) -> u32 {
        let node = TPM0_NODE.lock().clone();
        match node {
            Some(n) => n.poll_readiness(),
            None => POLL_OUT,
        }
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

    fn poll_readiness(&self) -> u32 {
        let node = TPMRM0_NODE.lock().clone();
        match node {
            Some(n) => n.poll_readiness(),
            None => POLL_OUT,
        }
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
struct DevConsole;

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

    /// Terminal ioctls so `/dev/console` looks like a real tty: a
    /// successful `TCGETS` (returning a cooked-mode termios) makes
    /// `isatty(0)` true, which is what flips a shell into interactive
    /// mode. `TCSETS*` round-trips the caller's termios (so a program
    /// can switch raw/cooked); `TIOCGWINSZ` reports the window size.
    /// Other requests fall through to `-ENOTTY`.
    #[cfg(feature = "linux-compat")]
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, crate::FsError> {
        use crate::devfs_pty::{
            read_user_i32, read_user_termios, read_user_winsize, write_user_i32,
            write_user_termios, write_user_winsize, WireWinsize, FIONREAD, KDGETMODE, KDGKBMODE,
            KDSIGACCEPT, KDSKBMODE, TCFLSH, TCGETS, TCSBRK, TCSETS, TCSETSF, TCSETSW, TCXONC,
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

/// A static symlink inside /dev — stat() is S_IFLNK, read() returns the
/// target string verbatim (the shape sys_readlink and resolve_async use).
#[derive(Debug)]
struct DevSymlink {
    /// Symlink target (absolute path).
    target: &'static str,
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
}

/// An empty directory node used purely as a **mountpoint stub** under
/// `/dev` (e.g. `/dev/shm`, `/dev/mqueue`, `/dev/hugepages`). An init
/// system `open()`s these O_PATH|O_DIRECTORY to get a target fd and then
/// mounts tmpfs / mqueue / hugetlbfs over them; the mount is tracked by the
/// registry at that path, so this stub's (empty) contents are shadowed and
/// never observed once mounted.
struct DevEmptyDir;

impl DirOps for DevEmptyDir {
    fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
        None
    }
    fn iter(&self) -> Box<dyn Iterator<Item = crate::DirEntry> + '_> {
        Box::new(core::iter::empty())
    }
    fn enumerate(&self, _cursor: usize, _max: usize) -> Vec<(String, FileType)> {
        Vec::new()
    }
}

/// `DevFs` root directory — exposes `null` and `zero` as fixed
/// children. No mutation surface (the trait defaults return
/// `Unsupported` on every override-able method).
struct DevDir;

impl DirOps for DevDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        match name {
            // Static symlinks [[devfs-symlinks]].
            "fd" => Some(Arc::new(DevSymlink {
                target: "/proc/self/fd",
            }) as Arc<dyn FileOps>),
            "stdin" => Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/0",
            }) as Arc<dyn FileOps>),
            "stdout" => Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/1",
            }) as Arc<dyn FileOps>),
            "stderr" => Some(Arc::new(DevSymlink {
                target: "/proc/self/fd/2",
            }) as Arc<dyn FileOps>),
            "null" => Some(Arc::new(DevNull) as Arc<dyn FileOps>),
            "zero" => Some(Arc::new(DevZero) as Arc<dyn FileOps>),
            "full" => Some(Arc::new(crate::devfs_misc::DevFull) as Arc<dyn FileOps>),
            "random" => Some(Arc::new(DevRandom) as Arc<dyn FileOps>),
            "urandom" => Some(Arc::new(DevRandom) as Arc<dyn FileOps>),
            "kmsg" => Some(Arc::new(DevKmsg) as Arc<dyn FileOps>),
            // `tty1` is the conventional first VT node — `getty@tty1.service`
            // (and login on it) opens it. NARF has one console, so it and the
            // `tty0`/`console` aliases all resolve to the same singleton tty.
            "console" | "tty" | "tty0" | "tty1" => Some(Arc::new(DevConsole) as Arc<dyn FileOps>),
            "ptmx" => Some(Arc::new(crate::devfs_pty::DevPtmx) as Arc<dyn FileOps>),
            "fb0" => Some(Arc::new(DevFb0Proxy) as Arc<dyn FileOps>),
            // Userspace input-injection control device.
            // Linux ref: `drivers/input/misc/uinput.c`.
            "uinput" => {
                Some(Arc::new(crate::devfs_input::UinputControlFile::new()) as Arc<dyn FileOps>)
            }
            // FUSE control device: each open mints a fresh connection.
            // Linux ref: `fs/fuse/dev.c` — /dev/fuse (misc char, minor 229).
            "fuse" => Some(crate::fuse_conn::DevFuse::open_new()),
            "fp0" => Some(Arc::new(DevFp) as Arc<dyn FileOps>),
            "tpm0" => Some(Arc::new(DevTpm0Proxy) as Arc<dyn FileOps>),
            "tpmrm0" => Some(Arc::new(DevTpmRm0Proxy) as Arc<dyn FileOps>),
            // Real-time clock char device. `hwclock --show` reads it via
            // ioctl(RTC_RD_TIME). Linux ref: `drivers/rtc/dev.c`. `/dev/rtc`
            // is the conventional first-RTC alias — a symlink to rtc0 (this
            // devfs has a DevSymlink node type [[devfs-symlinks]]).
            "rtc0" => Some(Arc::new(crate::devfs_rtc::DevRtc) as Arc<dyn FileOps>),
            "rtc" => Some(Arc::new(DevSymlink {
                target: "/dev/rtc0",
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
                // Then any node udev created via mknod (coldplug /dev nodes).
                .or_else(|| mknod_lookup(name)),
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
            "shm" | "mqueue" | "hugepages" => Some(Arc::new(DevEmptyDir) as Arc<dyn DirOps>),
            "disk" => Some(Arc::new(crate::devfs_block::DevDiskDir) as Arc<dyn DirOps>),
            "input" => Some(Arc::new(crate::devfs_input::DevInputDir) as Arc<dyn DirOps>),
            // Sound subsystem — delegate installed by narf-drivers-sound.
            "snd" => SND_DIR.lock().clone(),
            // DRM/DRI subsystem — delegate installed by narf-drivers-gpu.
            // Linux ref: `drivers/gpu/drm/drm_drv.c::drm_dev_register`.
            "dri" => DRI_DIR.lock().clone(),
            _ => None,
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
            if !matches!(file_type, FileType::Special) {
                return Err(FsError::Unsupported);
            }
            // 0o660 (root:disk-style) is the conventional device-node mode.
            mknod_register(name, file_type, rdev, 0o660);
            mknod_lookup(name).ok_or(FsError::Io(narf_block::BlockError::IOError))
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
                file_type: FileType::Special,
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
        Box::new(ENTRIES.iter().copied())
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
            ("console", FileType::Special),
            ("tty", FileType::Special),
            ("tty0", FileType::Special),
            ("tty1", FileType::Special),
            ("ptmx", FileType::Special),
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
        // mknod-created nodes that don't collide with a static name.
        let mknod_extras: Vec<(String, FileType)> = mknod_enumerate()
            .into_iter()
            .filter(|(name, _)| !static_names.iter().any(|s| s == name))
            .collect();

        static_entries
            .iter()
            .map(|(n, t)| ((*n).into(), *t))
            .chain(block_extras)
            .chain(rfcomm_extras)
            .chain(tty_usb_extras)
            .chain(video_extras)
            .chain(mknod_extras)
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
            name: "devfs".into(),
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
