//! `bpf_arena` — the BPF program heap.
//!
//! Spec: `bpf/specification/spec.md` §3.3, §4.1, §5; design rationale in the
//! plan §1.4.
//!
//! Linux's arena (`kernel/bpf/arena.c`) is the right primitive arrived at
//! late, and its limits are artefacts of when it arrived: 4 GiB maximum, one
//! arena per program, and — the worst one — **every process must `mmap` the
//! arena at the same user VA**, because the in-program pointer is a truncated
//! absolute *user* address (`arena.c:16-42`; `arena_map_mmap` returns `-EBUSY`
//! otherwise).
//!
//! Here the in-program pointer is a **base-relative offset** into one shared
//! kernel window, not a truncated address. Three of Linux's limits fall out:
//!
//! * The user mapping may be at any address — userspace adds its own base.
//! * Multiple arenas per program are free: they are sub-ranges of the same
//!   window, so one pinned register serves all of them.
//! * The 4 GiB cap is a policy choice, not an encoding one.
//!
//! ## Guards
//!
//! Linux derives its guard size from the ISA (`arena.c:45`):
//!
//! ```text
//! GUARD_SZ = round_up(1ull << sizeof_field(struct bpf_insn, off) * 8, PAGE_SIZE << 1)
//! ```
//!
//! — i.e. 64 KiB, because the largest displacement an instruction can name is
//! the signed 16-bit `off` field, so a guard that big makes an escape by
//! immediate displacement land on unmapped memory.
//!
//! We take the same derivation to its structural conclusion: the arena window
//! is a whole PML4 slot and the slots on **both** sides
//! (`bpf_text::BPF_ARENA_PML4_SLOT ± 1`) are never mapped by anything. That is
//! 512 GiB of guard against a 64 KiB requirement, so the escape is impossible
//! by construction rather than by arithmetic — and the check is a static
//! assertion about slot numbers instead of a runtime bound.
//!
//! ## Userspace visibility (open question §8.2 — read this before using it)
//!
//! `FileOps::mmap_frames` is **eager and snapshot-based**: it returns the list
//! of physical frames at `mmap` time and the syscall layer maps them SHARED.
//! A page that the *program* populates later therefore does not appear in the
//! userspace mapping at all. [`Arena::snapshot_frames`] exists for the
//! pre-populated case and [`Arena::populate`] deliberately refuses to grow an
//! arena that has already been snapshotted, so the failure is a typed error at
//! the point of the mistake rather than a silently missing page in userspace.
//!
//! The real fix is the `mmap_fault(offset)` hook §8.2 proposes, routed from
//! the demand-paging arm of the trap handler; that is a filesystem-layer
//! change and is not in this module's scope.

extern crate alloc as alloc_crate;

use alloc_crate::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::bpf_text::{BPF_ARENA_BASE, BPF_ARENA_PML4_SLOT, BPF_TEXT_PML4_SLOT, SLOT_SPAN};
use crate::{PhysAddr, VirtAddr};

/// Authority to create or grow a BPF arena. `CapKind::BpfArena` (0x0303).
#[derive(Copy, Clone, Debug)]
pub struct BpfArena;

impl CapType for BpfArena {
    const KIND: CapKind = CapKind::BpfArena;
}

/// Convenience alias for the granting form.
pub type ArenaCap = narf_capabilities::Cap<BpfArena, Grant>;

/// Maximum bytes one arena may reserve. 4 GiB, matching Linux's cap — not
/// because the encoding forces it (ours does not) but because the in-program
/// pointer stays a 32-bit value, which keeps the JIT's `[base + reg + off16]`
/// addressing one `mov eax, eax` away from the fast path. Lifting it is the
/// §8.1 open question.
pub const ARENA_MAX_BYTES: u64 = 4u64 << 30;

/// Every arena is placed on this alignment inside the window, so a program's
/// base-relative pointer can be recovered from an absolute one by masking.
pub const ARENA_ALIGN: u64 = 4u64 << 30;

// The guards are the neighbouring PML4 slots. Assert here rather than
// commenting, so a future edit to the slot constants breaks the build.
const _: () = assert!(
    BPF_ARENA_PML4_SLOT >= BPF_TEXT_PML4_SLOT + 2,
    "slot below the arena must be an unmapped guard, not the text window"
);
const _: () = assert!(
    ARENA_MAX_BYTES <= SLOT_SPAN,
    "an arena must fit inside its PML4 slot"
);

/// Failure modes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArenaError {
    /// `bpf_text::reserve_kernel_slots` has not run — see §4.1.
    SlotsUnreserved,
    /// Zero pages, or more than [`ARENA_MAX_BYTES`].
    BadSize,
    /// The arena window is full.
    WindowExhausted,
    /// Page index past the arena's declared maximum.
    OutOfRange,
    /// Frame allocator exhausted.
    NoFrame,
    /// A page-table walk failed.
    MapFailed,
    /// The capability was revoked between grant and use.
    CapRevoked,
    /// The arena's frame list has already been snapshotted for a userspace
    /// mapping, so a newly populated page would be invisible there. See the
    /// module docs on §8.2.
    SnapshotTaken,
}

/// Bump cursor over the arena window. Arena VA is never recycled: the window
/// holds 128 maximally-sized arenas and reuse would buy a class of stale-TLB
/// bug for nothing.
static NEXT_ARENA_VA: AtomicU64 = AtomicU64::new(BPF_ARENA_BASE);

/// Free-space tracking for one arena: a sorted list of half-open
/// `[start, end)` page runs that are still unpopulated.
///
/// A range tree rather than a bitmap because arenas are sparse by design —
/// a 4 GiB arena is a million pages, and the common shape is a handful of
/// large contiguous runs, which a range list represents in a few entries
/// instead of 128 KiB of bitmap.
#[derive(Debug, Default)]
struct FreeRanges {
    runs: Vec<(u64, u64)>,
}

impl FreeRanges {
    fn new(pages: u64) -> Self {
        Self {
            runs: alloc_crate::vec![(0, pages)],
        }
    }

    /// Is `page` still free?
    fn is_free(&self, page: u64) -> bool {
        self.runs
            .binary_search_by(|&(s, e)| {
                if page < s {
                    core::cmp::Ordering::Greater
                } else if page >= e {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Mark `page` used, splitting the containing run.
    fn take(&mut self, page: u64) -> bool {
        let Ok(i) = self.runs.binary_search_by(|&(s, e)| {
            if page < s {
                core::cmp::Ordering::Greater
            } else if page >= e {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        }) else {
            return false;
        };
        let (s, e) = self.runs[i];
        match (page == s, page + 1 == e) {
            (true, true) => {
                self.runs.remove(i);
            }
            (true, false) => self.runs[i] = (s + 1, e),
            (false, true) => self.runs[i] = (s, e - 1),
            (false, false) => {
                self.runs[i] = (s, page);
                self.runs.insert(i + 1, (page + 1, e));
            }
        }
        true
    }

    /// First free page at or after `from`.
    fn first_free_from(&self, from: u64) -> Option<u64> {
        for &(s, e) in &self.runs {
            if e <= from {
                continue;
            }
            return Some(s.max(from));
        }
        None
    }

    fn free_pages(&self) -> u64 {
        self.runs.iter().map(|&(s, e)| e - s).sum()
    }
}

#[derive(Debug)]
struct Inner {
    free: FreeRanges,
    /// Populated pages, in population order. Indexed by nothing in
    /// particular — this is the backing store, `free` is the index.
    frames: Vec<(u64, crate::frame::PhysFrame)>,
    /// Set once `snapshot_frames` has handed a frame list to the mmap layer.
    snapshotted: bool,
}

/// A BPF arena: a stable kernel VA window with demand-populated pages.
#[derive(Debug)]
pub struct Arena {
    /// Kernel VA base. Stable for the arena's whole life — that is the
    /// contract the JIT's pinned base register depends on.
    kva: u64,
    /// Declared maximum, in pages.
    max_pages: u64,
    inner: IrqSafeSpinLock<Inner>,
}

impl Arena {
    /// Reserve a new arena.
    ///
    /// Reserves VA and free-space bookkeeping only — no page is backed until
    /// [`populate`](Self::populate).
    pub fn new(cap: &ArenaCap, max_pages: usize) -> Result<Arena, ArenaError> {
        cap.check_live().map_err(|_| ArenaError::CapRevoked)?;
        if crate::bpf_text::kernel_root_for_mapping().is_none() {
            return Err(ArenaError::SlotsUnreserved);
        }
        let max_pages = max_pages as u64;
        if max_pages == 0 || max_pages * 4096 > ARENA_MAX_BYTES {
            return Err(ArenaError::BadSize);
        }
        let kva = NEXT_ARENA_VA.fetch_add(ARENA_ALIGN, Ordering::Relaxed);
        if kva + ARENA_ALIGN > BPF_ARENA_BASE + SLOT_SPAN {
            return Err(ArenaError::WindowExhausted);
        }
        Ok(Arena {
            kva,
            max_pages,
            inner: IrqSafeSpinLock::new(Inner {
                free: FreeRanges::new(max_pages),
                frames: Vec::new(),
                snapshotted: false,
            }),
        })
    }

    /// Stable kernel VA of the arena's first byte.
    ///
    /// The JIT pins a register to this and emits `[base + reg + off16]`, the
    /// same shape as Linux's `r12`.
    #[inline]
    pub fn kva(&self) -> u64 {
        self.kva
    }

    /// Offset of `kva` within the arena window — the value a program's
    /// base-relative pointers are expressed against.
    #[inline]
    pub fn window_offset(&self) -> u64 {
        self.kva - BPF_ARENA_BASE
    }

    /// Declared maximum size in pages.
    #[inline]
    pub fn max_pages(&self) -> u64 {
        self.max_pages
    }

    /// Back page `page` and return its kernel VA.
    ///
    /// Idempotent: populating an already-populated page returns its VA
    /// without allocating.
    pub fn populate(&self, page: usize) -> Result<u64, ArenaError> {
        let page = page as u64;
        if page >= self.max_pages {
            return Err(ArenaError::OutOfRange);
        }
        let va = self.kva + page * 4096;

        let mut inner = self.inner.lock();
        if !inner.free.is_free(page) {
            return Ok(va);
        }
        // §8.2: once the frame list has been handed to `mmap_frames`, a page
        // populated afterwards is invisible in the userspace mapping. Refuse
        // loudly instead of producing a hole nobody can explain later.
        if inner.snapshotted {
            return Err(ArenaError::SnapshotTaken);
        }
        let frame = crate::frame::alloc_frame().map_err(|_| ArenaError::NoFrame)?;
        // Zero on populate: arena memory is program-visible and must not leak
        // whatever the previous owner of the frame left behind.
        // SAFETY: freshly-allocated frame, reachable through the kernel RAM
        // accessor, exclusively ours until mapped below.
        unsafe {
            core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0, 4096);
        }
        // SAFETY: `va` is a fresh page-aligned VA inside the arena window,
        // whose top-level table `reserve_kernel_slots` installed at boot.
        if let Err(e) = unsafe { map_arena_page(va, frame.start_address()) } {
            crate::frame::free_frame(frame);
            return Err(e);
        }
        inner.free.take(page);
        inner.frames.push((page, frame));
        Ok(va)
    }

    /// Populate `count` pages starting at `from`. Convenience for the
    /// pre-populated shape that `mmap_frames` can actually serve.
    pub fn populate_range(&self, from: usize, count: usize) -> Result<(), ArenaError> {
        for i in 0..count {
            self.populate(from + i)?;
        }
        Ok(())
    }

    /// First page that is still unpopulated at or after `from`.
    pub fn first_unpopulated(&self, from: usize) -> Option<usize> {
        self.inner
            .lock()
            .free
            .first_free_from(from as u64)
            .map(|p| p as usize)
    }

    /// Populated pages.
    pub fn populated_pages(&self) -> usize {
        self.inner.lock().frames.len()
    }

    /// Unpopulated pages remaining.
    pub fn free_pages(&self) -> u64 {
        self.inner.lock().free.free_pages()
    }

    /// Snapshot the backing frames, in page order, for `FileOps::mmap_frames`.
    ///
    /// **Freezes the arena.** `mmap_frames` is eager and snapshot-based, so
    /// after this call a newly populated page would never appear in the
    /// userspace mapping; [`populate`](Self::populate) therefore returns
    /// [`ArenaError::SnapshotTaken`] from here on. Populate everything the
    /// program and userspace will share *before* calling this.
    ///
    /// The precise limitation, and the `mmap_fault(offset)` hook that would
    /// lift it, are open question §8.2.
    pub fn snapshot_frames(&self) -> Vec<PhysAddr> {
        let mut inner = self.inner.lock();
        inner.snapshotted = true;
        let mut v: Vec<(u64, PhysAddr)> = inner
            .frames
            .iter()
            .map(|(p, f)| (*p, f.start_address()))
            .collect();
        v.sort_unstable_by_key(|(p, _)| *p);
        v.into_iter().map(|(_, a)| a).collect()
    }

    /// Convert a program-visible base-relative offset to a kernel VA, or
    /// `None` if it falls outside this arena.
    ///
    /// Bounds-checking here is belt-and-braces: the *structural* guarantee is
    /// the unmapped guard slots, which catch a runaway displacement even when
    /// no software check runs. This exists for the kfunc path, where a helper
    /// wants to reject rather than fault.
    #[inline]
    pub fn resolve(&self, offset: u64) -> Option<u64> {
        if offset >= self.max_pages * 4096 {
            return None;
        }
        Some(self.kva + offset)
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        for (page, frame) in core::mem::take(&mut inner.frames) {
            let va = self.kva + page * 4096;
            // SAFETY: the arena is being destroyed, so no program holds a
            // pointer into it; the VA is never reissued (bump cursor), so a
            // stale TLB entry on a peer CPU cannot alias a later mapping.
            unsafe { unmap_arena_page(va) };
            crate::frame::free_frame(frame);
        }
    }
}

// ── Mapping ────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn map_arena_page(va: u64, phys: PhysAddr) -> Result<(), ArenaError> {
    use crate::x86_64::paging::{map_4kb, PtFlags};
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(ArenaError::SlotsUnreserved)?;
    // RW, never executable, GLOBAL — arena contents are identical under every
    // CR3 because the top-level entry is snapshot-copied into every AS.
    // Never `USER`: userspace reaches arena pages through its own SHARED
    // mapping of the same frames, not through this window.
    let flags = PtFlags::WRITABLE | PtFlags::NO_EXEC | PtFlags::GLOBAL;
    // SAFETY: `root` is the recorded kernel root whose arena top-level entry
    // exists; `va` is fresh, page-aligned VA inside that window.
    unsafe { map_4kb(root, VirtAddr::new(va), phys, flags).map_err(|_| ArenaError::MapFailed) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn unmap_arena_page(va: u64) {
    let Some(root) = crate::bpf_text::kernel_root_for_mapping() else {
        return;
    };
    // SAFETY: caller guarantees the page is no longer reachable by any
    // program.
    unsafe {
        let _ = crate::x86_64::paging::unmap_4kb(root, VirtAddr::new(va));
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn map_arena_page(va: u64, phys: PhysAddr) -> Result<(), ArenaError> {
    use crate::aarch64::paging::{map_4kb, PtFlags};
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(ArenaError::SlotsUnreserved)?;
    let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;
    // SAFETY: same as the x86_64 arm.
    unsafe { map_4kb(root, VirtAddr::new(va), phys, flags).map_err(|_| ArenaError::MapFailed) }
}

#[cfg(target_arch = "aarch64")]
unsafe fn unmap_arena_page(va: u64) {
    let Some(root) = crate::bpf_text::kernel_root_for_mapping() else {
        return;
    };
    // SAFETY: caller guarantees the page is no longer reachable.
    unsafe {
        let _ = crate::aarch64::paging::unmap_4kb(root, VirtAddr::new(va));
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn map_arena_page(_va: u64, _phys: PhysAddr) -> Result<(), ArenaError> {
    Err(ArenaError::MapFailed)
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn unmap_arena_page(_va: u64) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_ranges_split_and_report() {
        let mut f = FreeRanges::new(8);
        assert_eq!(f.free_pages(), 8);
        assert!(f.is_free(4));
        assert!(f.take(4));
        assert!(!f.is_free(4));
        assert_eq!(f.free_pages(), 7);
        assert_eq!(f.runs, alloc_crate::vec![(0, 4), (5, 8)]);
        // Taking an already-taken page is a no-op failure, not a corruption.
        assert!(!f.take(4));
        // Head and tail cases.
        assert!(f.take(0));
        assert_eq!(f.runs, alloc_crate::vec![(1, 4), (5, 8)]);
        assert!(f.take(7));
        assert_eq!(f.runs, alloc_crate::vec![(1, 4), (5, 7)]);
    }

    #[test]
    fn first_free_skips_taken_pages() {
        let mut f = FreeRanges::new(8);
        f.take(0);
        f.take(1);
        assert_eq!(f.first_free_from(0), Some(2));
        assert_eq!(f.first_free_from(5), Some(5));
        for p in 2..8 {
            f.take(p);
        }
        assert_eq!(f.first_free_from(0), None);
    }

    #[test]
    fn window_and_guards_are_where_we_think() {
        // The arena window and its two guard slots.
        assert_eq!(
            ((BPF_ARENA_BASE >> 39) & 0x1FF) as usize,
            BPF_ARENA_PML4_SLOT
        );
        // 512 GiB of guard on each side vastly exceeds Linux's ISA-derived
        // 64 KiB (`arena.c:45`: round_up(1 << 16, 8192)).
        assert!(SLOT_SPAN > (1u64 << 16));
    }
}
