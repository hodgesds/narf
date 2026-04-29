//! Per-process FbRing registry.
//!
//! Each userspace process that wants to draw gets its own DrawRing
//! page minted by `attach(pid)`. The ring's phys is registered on
//! the kernel-userspace mmap-phys allowlist; userspace then calls
//! SYS_MMAP_PHYS to map it into its VA. The kernel-side drain task
//! walks every registered ring on its tick.
//!
//! Storage is an `IrqSafeSpinLock<Vec<Entry>>`. The entry list is
//! tiny (one per drawing process); a linear scan is fine.

use alloc::vec::Vec;

use narf_ipc::shared_ring::SharedConsumer;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

use crate::cmd_ring::{self, DrawCmd, DrawRing, RING_DEPTH};
use crate::{FbWriter, Rect};
use core::sync::atomic::Ordering;

/// One registered ring: the backing phys (identity-mapped in the
/// kernel, mapped into userspace via SYS_MMAP_PHYS), the consumer
/// half, and the owning process id.
pub struct Entry {
    pub pid:      u64,
    pub phys:     u64,
    pub consumer: SharedConsumer<DrawCmd, RING_DEPTH>,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("pid",  &self.pid)
            .field("phys", &format_args!("{:#x}", self.phys))
            .finish_non_exhaustive()
    }
}

static REGISTRY: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

/// Errors from `attach`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttachError {
    OutOfMemory,
    AlreadyAttached,
}

/// Allocate a fresh DrawRing for `pid`, init it, register the
/// consumer half, and return the backing phys. The phys is also
/// pushed onto `narf_userspace::mmap_phys`'s allowlist so a
/// matching SYS_MMAP_PHYS from the same process succeeds.
///
/// Idempotent on `pid` — re-attaching the same pid returns
/// `AlreadyAttached`. Caller can `detach(pid)` first if it wants
/// to recreate.
pub fn attach(pid: u64) -> Result<PhysAddr, AttachError> {
    {
        let g = REGISTRY.lock();
        if g.iter().any(|e| e.pid == pid) {
            return Err(AttachError::AlreadyAttached);
        }
    }
    // One 4 KiB frame holds a SharedRing<DrawCmd, 16> with room to
    // spare (16 × 32-byte slots + 64-byte header = 576 bytes).
    let frame = narf_memory::alloc_frame().map_err(|_| AttachError::OutOfMemory)?;
    let phys  = frame.start_address();

    // The frame is identity-mapped in the kernel's low-4-GiB map,
    // so `phys.raw()` is a usable pointer for the kernel.
    let ring_ptr = phys.raw() as *mut DrawRing;
    // SAFETY: identity-mapped 4 KiB region; zeroed by the
    // allocator's policy + we additionally zero to be sure.
    unsafe {
        core::ptr::write_bytes(ring_ptr as *mut u8, 0, 4096);
        cmd_ring::init_in(ring_ptr);
    }
    // SAFETY: SPSC contract — only one consumer + one producer
    // per ring. The producer half lives in userspace once
    // mmap_phys lands; we don't materialise a kernel-side
    // producer here.
    let (_prod, consumer) = unsafe { cmd_ring::split(ring_ptr) };

    // Allowlist the phys so the userspace SYS_MMAP_PHYS will
    // succeed. We deliberately drop `_prod` — userspace owns the
    // producer side once it mmap's the page.
    narf_userspace::mmap_phys::allow(
        phys.raw(), 4096,
        narf_userspace::mmap_phys::MapPerms::ReadWrite,
    );

    REGISTRY.lock().push(Entry { pid, phys: phys.raw(), consumer });
    Ok(phys)
}

/// Tear down a process's ring. Removes the consumer + the
/// allowlist entry. The page itself isn't freed yet — that's the
/// frame allocator's job once a `free_frame` plumbing for known
/// allocations lands.
pub fn detach(pid: u64) {
    let mut g = REGISTRY.lock();
    if let Some(idx) = g.iter().position(|e| e.pid == pid) {
        let e = g.remove(idx);
        narf_userspace::mmap_phys::revoke(e.phys, 4096);
    }
}

/// Walk every registered ring; drain each through the supplied
/// FbWriter. Returns `(executed, errors)` summed across rings.
pub fn drain_all(writer: &FbWriter) -> (u32, u32) {
    let mut total_ok  = 0u32;
    let mut total_err = 0u32;
    let mut g = REGISTRY.lock();
    for e in g.iter_mut() {
        let (ok, err) = cmd_ring::drain(&mut e.consumer, writer);
        total_ok  += ok;
        total_err += err;
    }
    let _ = (Rect::new(0, 0, 0, 0), Ordering::Relaxed); // silence unused
    (total_ok, total_err)
}

/// Number of registered rings — for diagnostics + tests.
pub fn count() -> usize { REGISTRY.lock().len() }

/// Look up a registered ring by pid. Returns `(phys, queued)`.
/// `queued` is informational and approximate; another CPU might
/// drain or enqueue between the snapshot and the caller's read.
pub fn lookup(pid: u64) -> Option<u64> {
    REGISTRY.lock().iter().find(|e| e.pid == pid).map(|e| e.phys)
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    let mut g = REGISTRY.lock();
    for e in g.drain(..) {
        narf_userspace::mmap_phys::revoke(e.phys, 4096);
    }
}
