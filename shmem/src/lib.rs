//! narf-shmem — userspace-mappable shared-memory handles.
//!
//! Each `Shmem` is a kernel-allocated, page-aligned, contiguous-VA
//! region of N coherent frames, owned by a specific process pid.
//! The handle is the public name; userspace maps the region into
//! its VA via `SYS_SHMEM_MAP`. Kernel-side consumers (audio's tx
//! ring, fb's blit source) read pixel/PCM data through the same
//! frames via the identity map.
//!
//! Surface mirrors `narf-fb`'s registry pattern: a static
//! `Vec<Entry>`, a monotonic id allocator, and an exit-observer
//! reaper hooked into `narf-userspace`.
//!
//! Today's per-handle limit is 256 frames (1 MiB). Audio playback
//! buffers (~64-128 KiB), small blit sources (icons, glyph
//! atlases), and ring-shaped command queues all fit comfortably.
//! Larger consumers (full-screen blit, gpu command buffers) lift
//! the cap once a real use case materialises.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{Cap, CapKind, CapType, Read, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

/// Cap-typed authority over a shmem region. `Read` = mappable
/// read-only; `Write` = read+write. The handle id is the public
/// name; the cap is the gate.
#[derive(Copy, Clone, Debug)]
pub struct ShmemCap;

impl CapType for ShmemCap {
    const KIND: CapKind = CapKind::DmaBuffer;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShmemError {
    OutOfMemory,
    BadLen,
    NotFound,
    NotOwner,
}

const PAGE: u64 = 4096;
const MAX_PAGES_PER_HANDLE: usize = 256; // 1 MiB

/// One live shared-memory region.
pub struct Entry {
    pub handle:  u64,
    pub pid:     u64,
    pub frames:  Vec<u64>,   // phys addrs, page-sized
    pub len:     u64,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("handle", &self.handle)
            .field("pid",    &self.pid)
            .field("len",    &self.len)
            .field("frames", &self.frames.len())
            .finish_non_exhaustive()
    }
}

static REGISTRY:    IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh shared-memory region of `len` bytes (rounded
/// up to a page). Returns the new handle id (>0).
pub fn create(pid: u64, len: u64) -> Result<u64, ShmemError> {
    if len == 0 { return Err(ShmemError::BadLen); }
    let len_pg = (len + PAGE - 1) & !(PAGE - 1);
    let pages  = (len_pg / PAGE) as usize;
    if pages > MAX_PAGES_PER_HANDLE {
        return Err(ShmemError::BadLen);
    }
    let mut frames = Vec::with_capacity(pages);
    for _ in 0..pages {
        let frame = match narf_memory::alloc_frame() {
            Ok(f) => f,
            Err(_) => {
                // Roll back: the frames we already grabbed leak
                // until the frame allocator gets a free path
                // (matches fb registry's no-op detach today).
                return Err(ShmemError::OutOfMemory);
            }
        };
        let phys = frame.start_address().raw();
        // Zero each frame so a fresh shmem doesn't surface stale
        // kernel data.
        // SAFETY: identity-mapped low-RAM frame; owned by us.
        unsafe { core::ptr::write_bytes(phys as *mut u8, 0, PAGE as usize); }
        frames.push(phys);
    }
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    REGISTRY.lock().push(Entry { handle, pid, frames, len: len_pg });
    Ok(handle)
}

/// Phys addr at `byte_offset` into the region. Used by kernel-
/// side consumers (audio submit, fb blit) to translate a
/// (handle, offset) pair into a phys for DMA. Returns `None` on
/// bad handle or out-of-range offset.
pub fn phys_at(handle: u64, byte_offset: u64) -> Option<u64> {
    let g = REGISTRY.lock();
    let e = g.iter().find(|e| e.handle == handle)?;
    if byte_offset >= e.len { return None; }
    let page_idx = (byte_offset / PAGE) as usize;
    let intra    = byte_offset & (PAGE - 1);
    Some(e.frames[page_idx] + intra)
}

/// Scatter-gather descriptor: one physically-contiguous run within
/// a shmem region. Drivers iterate these to build per-segment
/// device-side descriptors (virtio chained desc, NVMe PRP/SGL,
/// GPU command-buffer entries).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SgEntry {
    pub phys: u64,
    pub len:  u32,
}

/// Walk a `(handle, byte_offset, byte_len)` slice as scatter-
/// gather entries. Each entry is bounded above by `byte_len`,
/// the page boundary, and the region's end. Returns `None` if
/// the handle is unknown or `(byte_offset + byte_len)` exceeds
/// the region.
///
/// # Example
/// A 7000-byte slice starting at offset 100 of a 2-page region
/// yields two entries:
/// - `(frame0 + 100, 4096 - 100 = 3996)`
/// - `(frame1, 7000 - 3996 = 3004)`
pub fn sg_iter(
    handle:      u64,
    byte_offset: u64,
    byte_len:    u64,
) -> Option<SgIter> {
    let g = REGISTRY.lock();
    let e = g.iter().find(|e| e.handle == handle)?;
    let end = byte_offset.checked_add(byte_len)?;
    if end > e.len { return None; }
    Some(SgIter {
        frames:    e.frames.clone(),
        cursor:    byte_offset,
        remaining: byte_len,
    })
}

/// Iterator returned by [`sg_iter`]. `Iterator::Item` is one
/// `SgEntry` per contiguous page-bounded run.
#[derive(Debug)]
pub struct SgIter {
    frames:    Vec<u64>,
    cursor:    u64,
    remaining: u64,
}

impl Iterator for SgIter {
    type Item = SgEntry;
    fn next(&mut self) -> Option<SgEntry> {
        if self.remaining == 0 { return None; }
        let page_idx = (self.cursor / PAGE) as usize;
        let intra    = self.cursor & (PAGE - 1);
        let in_page  = PAGE - intra;
        let take     = in_page.min(self.remaining);
        let phys     = self.frames[page_idx] + intra;
        self.cursor    += take;
        self.remaining -= take;
        Some(SgEntry { phys, len: take as u32 })
    }
}

/// Snapshot of the per-page phys list, for the syscall handler
/// that installs the user-VA mapping.
pub fn frames_of(handle: u64) -> Option<Vec<PhysAddr>> {
    let g = REGISTRY.lock();
    let e = g.iter().find(|e| e.handle == handle)?;
    Some(e.frames.iter().copied().map(PhysAddr::new).collect())
}

/// Total length (page-rounded) of the region.
pub fn len_of(handle: u64) -> Option<u64> {
    REGISTRY.lock().iter().find(|e| e.handle == handle).map(|e| e.len)
}

/// Owner pid of the region.
pub fn pid_of(handle: u64) -> Option<u64> {
    REGISTRY.lock().iter().find(|e| e.handle == handle).map(|e| e.pid)
}

/// Tear down a region. The backing frames stay leaked until the
/// frame allocator grows a free path (matches the fb registry's
/// today). Returns `true` on success.
pub fn destroy(handle: u64) -> bool {
    let mut g = REGISTRY.lock();
    if let Some(idx) = g.iter().position(|e| e.handle == handle) {
        g.remove(idx);
        true
    } else {
        false
    }
}

/// Destroy every region owned by `pid`. Called from the process-
/// exit observer wired in `register_initcalls`.
pub fn destroy_all_for_pid(pid: u64) -> u32 {
    let mut g = REGISTRY.lock();
    let before = g.len();
    g.retain(|e| e.pid != pid);
    (before - g.len()) as u32
}

/// Number of live regions — for diagnostics + tests.
pub fn count() -> usize { REGISTRY.lock().len() }

#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
    NEXT_HANDLE.store(1, Ordering::Relaxed);
}

// ── Syscall vtable ──────────────────────────────────────────────────

/// Vtable installed in `narf_userspace::handlers`. Same shape as
/// the FB vtable: each fn pointer is the kernel-side
/// implementation of one syscall.
pub fn syscall_vtable() -> &'static narf_userspace::handlers::ShmemSyscallVtable {
    use narf_userspace::handlers::ShmemSyscallVtable;
    static V: ShmemSyscallVtable = ShmemSyscallVtable {
        create:  vt_create,
        len_of:  vt_len_of,
        frames:  vt_frames,
        destroy: vt_destroy,
        pid_of:  vt_pid_of,
    };
    &V
}

fn vt_create(pid: u64, len: u64) -> u64 {
    create(pid, len).unwrap_or(0)
}

fn vt_len_of(handle: u64) -> u64 {
    len_of(handle).unwrap_or(0)
}

fn vt_frames(handle: u64, out: &mut Vec<u64>) -> bool {
    let frames = match frames_of(handle) {
        Some(f) => f,
        None    => return false,
    };
    out.clear();
    for p in frames {
        out.push(p.raw());
    }
    true
}

fn vt_destroy(handle: u64) -> bool {
    destroy(handle)
}

fn vt_pid_of(handle: u64) -> u64 {
    pid_of(handle).unwrap_or(0)
}

// ── Init wiring ─────────────────────────────────────────────────────

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "shmem-syscall-vtable", || {
        narf_userspace::handlers::install_shmem_syscall_vtable(syscall_vtable());
        InitResult::Ok
    });
    // Process-exit observer: reap any shmem the dying process held.
    narf_init::register(Stage::Subsys, "shmem-exit-observer", || {
        narf_userspace::user_task::register_exit_observer(|pid| {
            let _ = destroy_all_for_pid(pid);
        });
        InitResult::Ok
    });
}

// Read-cap stub for future audit smokes.
#[allow(dead_code)]
fn _read_cap_demo(_c: Cap<ShmemCap, Read>) {}
#[allow(dead_code)]
fn _write_cap_demo(_c: Cap<ShmemCap, Write>) {}

// Per-crate smoke tests register against `narf-kernel-test` and
// land in the same `narf.tests` ELF section as the rest of the
// suite.
mod tests;
