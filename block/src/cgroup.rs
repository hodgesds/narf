//! cgroup-v2 `io` controller seam (feature `cgroup`).
//!
//! Exposes a single fn-pointer hook the cgroupfs `io` controller
//! installs once at boot (`narf_filesystem::cgroupfs::io`). When a
//! block request is submitted through an accounted path, the block
//! layer reads the submitting task id from the scheduler and invokes
//! the hook with `(pid, dev, bytes, is_write)`; the controller charges
//! the request to the task's cgroup chain.
//!
//! NARF hook pattern: identical to `filesystem/src/devfs.rs`
//! `install_*_hook` — a fn-pointer round-tripped through an
//! `AtomicUsize` so no boot wiring (initcall ordering, static `Arc`)
//! is needed; the consumer installs lazily on first `new_state`.
//!
//! ## Attribution model
//!
//! `pid` is `narf_scheduler::current_task_id()` read in the
//! *synchronous prologue* of the submit path — i.e. before the
//! returned future is `.await`ed. Every in-tree `BlockDevice::submit`
//! (`SyncBlock`, `RamBlockDevice`) performs its actual transfer in
//! that synchronous prologue (the `async move { … }` only wraps the
//! pre-computed `BlockCompletion`), so the current task at hook time
//! is the task that issued the I/O. There is no per-request submitter
//! field on `BlockRequest`, so the running task is the only available
//! attribution source — this is correct for synchronous transports
//! and is the documented limitation for any future fully-async driver
//! that defers the transfer past the first poll.
//!
//! ## `dev` (MAJ:MIN)
//!
//! The block layer has no `dev_t` registry; `BlockDeviceSync` devices
//! are named by `&'static str`, not numbered. Accounted submit paths
//! pass a `dev` id derived from the device's stable identity (its
//! `Arc<dyn BlockDeviceSync>` data-pointer address, folded to a
//! 32-bit MAJ:MIN by [`dev_id_from_ptr`]). This is stable for the
//! lifetime of a device registration and unique across concurrently
//! registered devices; it is NOT the Linux `dev_t` of the backing
//! hardware. `io.stat` therefore reports a synthetic but stable
//! MAJ:MIN per device. Wiring a real `dev_t` needs a numbering scheme
//! in the registry (out of scope here; would touch `registry.rs`).

use core::sync::atomic::{AtomicUsize, Ordering};

/// Installed cgroup-io charge hook, as a `fn` pointer round-tripped
/// through `usize` (`0` = not installed).
static IO_CGROUP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Hook signature: `(pid, dev, bytes, is_write)`.
pub type IoCgroupHook = fn(pid: u64, dev: u64, bytes: u64, is_write: bool);

/// Install the cgroup-v2 `io` accounting hook. Called once at boot by
/// the cgroupfs `io` controller (lazily, from its first `new_state`).
/// Last writer wins; storing the same pointer twice is harmless.
pub fn install_cgroup_io_hook(h: IoCgroupHook) {
    IO_CGROUP_HOOK.store(h as usize, Ordering::Release);
}

/// Charge a completed (or about-to-complete) transfer to the current
/// task's cgroup, if a hook is installed and a task is running.
///
/// `pid` is taken from `narf_scheduler::current_task_id()`; a
/// `TaskId::NONE` (kernel/background context with no owning task) is
/// not charged, matching Linux's "root cgroup absorbs unattributed
/// I/O" by simply skipping the charge.
pub(crate) fn charge_io(dev: u64, bytes: u64, is_write: bool) {
    let ptr = IO_CGROUP_HOOK.load(Ordering::Acquire);
    if ptr == 0 || bytes == 0 {
        return;
    }
    let pid = narf_scheduler::current_task_id().0;
    if pid == 0 {
        // No owning task (between polls / kernel-internal I/O).
        return;
    }
    // SAFETY: `ptr` is non-zero (checked) and was produced by
    // `install_cgroup_io_hook` storing an `IoCgroupHook` via `as
    // usize`. A function-pointer round-trip through `usize` preserves
    // size/alignment, and we transmute back to the exact same
    // signature, so `f` points at a live function.
    let f: IoCgroupHook = unsafe { core::mem::transmute::<usize, IoCgroupHook>(ptr) };
    f(pid, dev, bytes, is_write);
}

/// Fold a device's stable data-pointer identity into a synthetic
/// 32-bit MAJ:MIN `dev` id (`(maj << 20) | min`, the Linux `dev_t`
/// packing the cgroupfs `io.stat` renderer expects). See module docs
/// for why this is synthetic-but-stable rather than a real `dev_t`.
pub fn dev_id_from_ptr(ptr: *const ()) -> u64 {
    // Drop the low alloc-alignment bits (always zero), then split the
    // remaining entropy into a 12-bit major and 20-bit minor.
    let raw = (ptr as usize as u64) >> 4;
    let maj = (raw >> 20) & 0xfff;
    let min = raw & 0xf_ffff;
    (maj << 20) | min
}
