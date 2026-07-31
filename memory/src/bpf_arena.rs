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
//! kernel window, not a truncated address. Two of Linux's limits fall out:
//!
//! * The user mapping may be at any address — userspace adds its own base.
//! * The 4 GiB cap is a policy choice, not an encoding one.
//!
//! ## The window is divided into slots, and why the stride is twice the reach
//!
//! An in-program handle is relative to an [`ArenaSlot`], not to the window:
//! the window is carved into [`ARENA_SLOT_STRIDE`]-sized slots, one per
//! *program*, and every arena a single program can address lives inside its
//! own slot. That is what makes one pinned base register reach all of them,
//! which is the whole point of a base-relative handle.
//!
//! The stride is **8 GiB while only the low 4 GiB is usable**
//! ([`ARENA_USABLE_BYTES`]), and the gap is load-bearing rather than slack.
//! `narf-bpf-verifier`'s `ARENA_WINDOW_BYTES` bounds a *displacement from the
//! handle the program was given* at 4 GiB. A program's handle base is
//! [`ARENA_NULL_GUARD_BYTES`], so the furthest slot offset a verified access
//! can name is `4 GiB + ARENA_NULL_GUARD_BYTES + 8`, i.e. just past the usable
//! region. Nothing maps that tail, so an escape past the end of a program's own
//! arenas cannot reach the *next program's* slot — the bound the verifier
//! already enforces becomes a cross-program isolation guarantee, with no
//! per-program extent for it to be told about. A 4 GiB stride would have let a
//! verified access land in a neighbour's arena.
//!
//! `narf-memory` cannot depend on `narf-bpf-verifier` (the dependency graph
//! runs the other way), so the equality between [`ARENA_USABLE_BYTES`] and that
//! constant is asserted where both are nameable: `bpf/src/arena.rs`.
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
//! Inside a slot there are two more guards, both permanently unmapped:
//!
//! * `[0, ARENA_NULL_GUARD_BYTES)` — so handle `0` is never a valid arena
//!   address. That is what makes "null is the zero register" sound for
//!   `Option<ArenaPtr<T>>`: without it, the first byte of the first arena in a
//!   slot would be indistinguishable from `None`.
//! * `[ARENA_USABLE_BYTES, ARENA_SLOT_STRIDE)` — the tail guard described
//!   above.
//!
//! ## Multiple arenas per program
//!
//! Supported by the *addressing*: several arenas are placed in one slot by
//! [`Arena::new_in`], and one pinned base register reaches all of them, so
//! Linux's one-arena-per-program limit is not inherited. What is not yet
//! plumbed is a way for a program to *learn* the base handle of the second
//! one — `bpf/src/arena.rs`'s `narf_arena_base()` names the first, and the
//! program would have to read the rest from a kernel-published directory. Until
//! that exists, treat multi-arena as a layout property rather than a program
//! -visible feature.
//!
//! ## Userspace visibility
//!
//! A userspace `MAP_SHARED` mapping of an arena **tracks** the arena rather
//! than snapshotting it: a page populated *after* the `mmap` still appears,
//! on the first user access to it. That works because the mapping is
//! demand-paged through `FileOps::mmap_fault` — see `bpf/src/arena.rs` — and
//! not through `FileOps::mmap_frames`, which is answered once at `mmap` time
//! and so could only ever expose what was already there.
//!
//! Two things went away with that change and are worth naming, because
//! comments elsewhere in the tree referred to them: `Arena::snapshot_frames`,
//! which froze the arena so a later [`populate`](Arena::populate) could not
//! produce a page userspace would never see, and the `SnapshotTaken` error it
//! produced. There is no longer a hole for them to guard.
//!
//! The frames stay alive under a live mapping because the mapping owns a
//! reference to the file — see [`Arena::drop`], which says exactly where.

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

/// Bytes of a slot a program may actually address: the reach of an in-program
/// handle.
///
/// 4 GiB, matching Linux's cap — not because the encoding forces it (ours does
/// not) but because the in-program pointer stays a 32-bit value, which keeps
/// the JIT's `[base + reg + off16]` addressing one `mov eax, eax` away from the
/// fast path. Lifting it is the §8.1 open question, and it is *also* the
/// verifier's `ARENA_WINDOW_BYTES`, whose own doc comment explains why widening
/// it needs the 32-bit ALU path to zero-extend first.
pub const ARENA_USABLE_BYTES: u64 = 4u64 << 30;

/// Distance between the bases of two adjacent slots.
///
/// Twice [`ARENA_USABLE_BYTES`], so the tail no arena occupies absorbs the
/// furthest displacement a verified access can name. See the module docs — this
/// is what turns the verifier's fixed 4 GiB bound into cross-program isolation.
pub const ARENA_SLOT_STRIDE: u64 = 2 * ARENA_USABLE_BYTES;

/// Bytes at the base of every slot that no arena is ever placed in, so that
/// handle `0` is never a valid arena address.
pub const ARENA_NULL_GUARD_BYTES: u64 = 4096;

/// Maximum bytes one arena may reserve: the usable region less the null guard,
/// which is the largest arena that can start at [`ARENA_NULL_GUARD_BYTES`] and
/// still end inside the usable region.
pub const ARENA_MAX_BYTES: u64 = ARENA_USABLE_BYTES - ARENA_NULL_GUARD_BYTES;

// The guards are the neighbouring PML4 slots. Assert here rather than
// commenting, so a future edit to the slot constants breaks the build.
const _: () = assert!(
    BPF_ARENA_PML4_SLOT >= BPF_TEXT_PML4_SLOT + 2,
    "slot below the arena must be an unmapped guard, not the text window"
);
const _: () = assert!(
    ARENA_SLOT_STRIDE <= SLOT_SPAN,
    "an arena slot must fit inside its PML4 slot"
);
// The tail guard is what makes the verifier's fixed displacement bound a
// cross-program isolation property, so its existence is asserted rather than
// only described. `+ 8` is the widest single access.
const _: () = assert!(
    ARENA_NULL_GUARD_BYTES + ARENA_USABLE_BYTES + 8 <= ARENA_SLOT_STRIDE,
    "the furthest verified displacement from a slot's base handle must stay \
     inside that slot, or it lands in the next program's arenas"
);
// The window must hold a whole number of slots, or the last one runs off the
// end of the PML4 slot into whatever the next one is.
const _: () = assert!(
    SLOT_SPAN % ARENA_SLOT_STRIDE == 0,
    "the arena window must divide evenly into slots"
);
const _: () = assert!(
    BPF_ARENA_BASE % ARENA_SLOT_STRIDE == 0,
    "the window base must be slot-aligned, or every slot is misaligned"
);

/// Failure modes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArenaError {
    /// `bpf_text::reserve_kernel_slots` has not run — see §4.1.
    SlotsUnreserved,
    /// Zero pages, or more than [`ARENA_MAX_BYTES`].
    BadSize,
    /// The arena window has no unreserved slot left.
    WindowExhausted,
    /// The slot has no room left for another arena.
    SlotExhausted,
    /// Page index past the arena's declared maximum.
    OutOfRange,
    /// Frame allocator exhausted.
    NoFrame,
    /// A page-table walk failed.
    MapFailed,
    /// The capability was revoked between grant and use.
    CapRevoked,
}

/// Bump cursor over the arena window, in slot units. Arena VA is never
/// recycled: the window holds 64 slots and reuse would buy a class of stale-TLB
/// bug for nothing.
static NEXT_SLOT_VA: AtomicU64 = AtomicU64::new(BPF_ARENA_BASE);

/// One program's addressable region of the arena window.
///
/// Handing out a slot rather than a bare VA is what lets several arenas share
/// one pinned base register: every arena placed here has its handles measured
/// from [`ArenaSlot::base`], so a program holding one base reaches all of them
/// and nothing outside the slot (see the module docs on the tail guard).
///
/// Deliberately has **no `Drop`**. Slot VA is never returned to
/// [`NEXT_SLOT_VA`], and neither is the intra-slot cursor rewound when an
/// [`Arena`] placed here is dropped, so a VA this slot handed out is never
/// handed out again. That is the premise `Arena::drop`'s "a stale TLB entry on a
/// peer CPU cannot alias a later mapping" rests on; recycling either cursor
/// would remove it.
#[derive(Debug)]
pub struct ArenaSlot {
    base: u64,
    /// Offset of the next arena within the slot. Starts past the null guard.
    next: AtomicU64,
}

impl ArenaSlot {
    /// Reserve a fresh slot.
    ///
    /// # Errors
    ///
    /// [`ArenaError::CapRevoked`], [`ArenaError::SlotsUnreserved`], or
    /// [`ArenaError::WindowExhausted`].
    pub fn reserve(cap: &ArenaCap) -> Result<ArenaSlot, ArenaError> {
        cap.check_live().map_err(|_| ArenaError::CapRevoked)?;
        if crate::bpf_text::kernel_root_for_mapping().is_none() {
            return Err(ArenaError::SlotsUnreserved);
        }
        let base = NEXT_SLOT_VA.fetch_add(ARENA_SLOT_STRIDE, Ordering::Relaxed);
        // `>` not `>=`: `base + STRIDE` is the *end* of this slot, and a slot
        // ending exactly at the window's end is the last legal one.
        if base + ARENA_SLOT_STRIDE > BPF_ARENA_BASE + SLOT_SPAN {
            return Err(ArenaError::WindowExhausted);
        }
        Ok(ArenaSlot {
            base,
            next: AtomicU64::new(ARENA_NULL_GUARD_BYTES),
        })
    }

    /// Kernel VA of the slot's first byte — the address a JIT would pin.
    ///
    /// Note that this byte is inside the null guard and is never mapped.
    #[inline]
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Carve `bytes` (rounded up to a page) out of the slot, returning the
    /// slot-relative offset of the region.
    fn carve(&self, bytes: u64) -> Result<u64, ArenaError> {
        let pages = bytes.div_ceil(4096) * 4096;
        // A CAS loop rather than `fetch_add`, because a failed bound check must
        // not consume the space: a slot that refused a 3 GiB arena has to still
        // be able to satisfy a 1 MiB one.
        let mut cur = self.next.load(Ordering::Relaxed);
        loop {
            let end = cur.checked_add(pages).ok_or(ArenaError::SlotExhausted)?;
            if end > ARENA_USABLE_BYTES {
                return Err(ArenaError::SlotExhausted);
            }
            match self
                .next
                .compare_exchange_weak(cur, end, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Ok(cur),
                Err(observed) => cur = observed,
            }
        }
    }
}

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
}

/// A populated arena page: where the kernel sees it, and which frame is under
/// it.
///
/// Both facts have exactly one consumer each — the kernel VA is what a program
/// dereferences, the frame is what a userspace mapping aliases — and returning
/// them together is what keeps [`Arena::populate`] a single idempotent entry
/// point rather than two that could disagree about which page was backed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ArenaPage {
    /// Kernel VA of the page's first byte.
    pub kva: u64,
    /// The frame backing it.
    pub phys: PhysAddr,
}

/// A BPF arena: a stable kernel VA window with demand-populated pages.
#[derive(Debug)]
pub struct Arena {
    /// Kernel VA base. Stable for the arena's whole life — that is the
    /// contract the JIT's pinned base register depends on.
    kva: u64,
    /// Kernel VA of the enclosing slot's base, i.e. what an in-program handle
    /// is measured from.
    slot_base: u64,
    /// Declared maximum, in pages.
    max_pages: u64,
    inner: IrqSafeSpinLock<Inner>,
}

impl Arena {
    /// Reserve a new arena in a slot of its own.
    ///
    /// Reserves VA and free-space bookkeeping only — no page is backed until
    /// [`populate`](Self::populate).
    ///
    /// # Errors
    ///
    /// See [`ArenaError`].
    pub fn new(cap: &ArenaCap, max_pages: usize) -> Result<Arena, ArenaError> {
        // The slot is dropped at the end of this call and that is deliberate:
        // `ArenaSlot` has no `Drop`, so neither its VA nor its intra-slot
        // cursor is ever recycled, and the arena keeps the only thing it needs
        // from the slot — its base — by value.
        let slot = ArenaSlot::reserve(cap)?;
        Arena::new_in(cap, &slot, max_pages)
    }

    /// Reserve a new arena inside an existing slot, so that one pinned base
    /// register reaches it *and* every other arena in the same slot.
    ///
    /// # Errors
    ///
    /// See [`ArenaError`]; [`ArenaError::SlotExhausted`] if the slot's usable
    /// region cannot fit the request.
    pub fn new_in(cap: &ArenaCap, slot: &ArenaSlot, max_pages: usize) -> Result<Arena, ArenaError> {
        cap.check_live().map_err(|_| ArenaError::CapRevoked)?;
        if crate::bpf_text::kernel_root_for_mapping().is_none() {
            return Err(ArenaError::SlotsUnreserved);
        }
        let max_pages = max_pages as u64;
        let bytes = max_pages.checked_mul(4096).ok_or(ArenaError::BadSize)?;
        if max_pages == 0 || bytes > ARENA_MAX_BYTES {
            return Err(ArenaError::BadSize);
        }
        let off = slot.carve(bytes)?;
        Ok(Arena {
            kva: slot.base + off,
            slot_base: slot.base,
            max_pages,
            inner: IrqSafeSpinLock::new(Inner {
                free: FreeRanges::new(max_pages),
                frames: Vec::new(),
            }),
        })
    }

    /// Stable kernel VA of the arena's first byte.
    ///
    /// The JIT pins a register to the *slot* base and emits
    /// `[slot_base + handle + off16]`, the same shape as Linux's `r12`; this is
    /// that base plus [`base_offset`](Self::base_offset).
    #[inline]
    pub fn kva(&self) -> u64 {
        self.kva
    }

    /// The in-program handle of the arena's first byte: its offset within the
    /// enclosing slot.
    ///
    /// Never zero — the slot's first [`ARENA_NULL_GUARD_BYTES`] are an unmapped
    /// null guard, which is what lets `Option<ArenaPtr<T>>` spell `None` as the
    /// zero register.
    #[inline]
    pub fn base_offset(&self) -> u64 {
        self.kva - self.slot_base
    }

    /// Kernel VA of the enclosing slot's base.
    #[inline]
    pub fn slot_base(&self) -> u64 {
        self.slot_base
    }

    /// Declared maximum size in pages.
    #[inline]
    pub fn max_pages(&self) -> u64 {
        self.max_pages
    }

    /// Back page `page`, returning where the kernel sees it and which frame is
    /// under it.
    ///
    /// Idempotent: populating an already-populated page returns the same
    /// answer without allocating. The demand-paging path relies on that —
    /// `FileOps::mmap_fault` may be asked for one page by two CPUs at once,
    /// and the address space keeps whichever answer it records first.
    ///
    /// **Allocates**, so it is illegal on the program-run path (spec §4.6).
    /// The callers are `bpf(2)`, arena creation, and the demand-fault path,
    /// none of which is one.
    pub fn populate(&self, page: usize) -> Result<ArenaPage, ArenaError> {
        let page = page as u64;
        if page >= self.max_pages {
            return Err(ArenaError::OutOfRange);
        }
        let kva = self.kva + page * 4096;

        let mut inner = self.inner.lock();
        if !inner.free.is_free(page) {
            let phys = inner
                .frames
                .iter()
                .find(|(p, _)| *p == page)
                .map(|(_, f)| f.start_address())
                // A page that is not free must be in `frames`: `take` and the
                // push below happen under this one lock, and nothing else
                // writes either. Surfacing it as a typed error rather than an
                // `expect` keeps a bookkeeping bug from panicking the kernel
                // from a page-fault handler.
                .ok_or(ArenaError::OutOfRange)?;
            return Ok(ArenaPage { kva, phys });
        }
        let frame = crate::frame::alloc_frame().map_err(|_| ArenaError::NoFrame)?;
        // Zero on populate: arena memory is program-visible and must not leak
        // whatever the previous owner of the frame left behind.
        // SAFETY: freshly-allocated frame, reachable through the kernel RAM
        // accessor, exclusively ours until mapped below.
        unsafe {
            core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0, 4096);
        }
        // SAFETY: `kva` is a fresh page-aligned VA inside the arena window,
        // whose top-level table `reserve_kernel_slots` installed at boot.
        if let Err(e) = unsafe { map_arena_page(kva, frame.start_address()) } {
            crate::frame::free_frame(frame);
            return Err(e);
        }
        let phys = frame.start_address();
        inner.free.take(page);
        inner.frames.push((page, frame));
        Ok(ArenaPage { kva, phys })
    }

    /// Populate `count` pages starting at `from`.
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

    /// The frame backing `page`, or `None` if it is not populated.
    ///
    /// Read-only, so unlike [`populate`](Self::populate) it never allocates —
    /// which is what makes it usable from a caller that only wants to *check*
    /// whether a page is backed.
    pub fn frame_at(&self, page: usize) -> Option<PhysAddr> {
        let page = page as u64;
        self.inner
            .lock()
            .frames
            .iter()
            .find(|(p, _)| *p == page)
            .map(|(_, f)| f.start_address())
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
        // Every frame goes back to the buddy, including frames a userspace
        // `MAP_SHARED` mapping aliased — and the reason that is safe is **not
        // local to this module**, so it is spelled out rather than assumed.
        //
        // A userspace mapping of an arena owns an `Arc<dyn FileOps>` for as
        // long as the mapping exists: `sys_mmap` hands it to
        // `mapped_file::register_current`, `sys_munmap` and process exit are
        // what release it. That `Arc` is an `ArenaFile`, which owns an
        // `Arc<ProgArena>`, which owns this `Arena`. So a live mapping makes
        // this drop unreachable, and reaching it means no mapping remains.
        //
        // This used to leak the frames instead, because that reasoning was
        // false at the time: nothing kept the file alive, so `munmap`-less
        // teardown could return user-mapped frames to the buddy — a
        // userspace-writable window onto whatever was allocated next. Arenas
        // were the first `mmap_frames` user where it mattered (`/dev/fb0`
        // hands out device memory that is never in the buddy; perf's ring
        // lives as long as the task), which is why the contract had never
        // been stressed.
        //
        // A cross-crate invariant stated in a comment on one side of the seam
        // is exactly the defect class spec §9 records four of, so this one is
        // a test and not only a paragraph:
        // `sys_mmap.rs`'s `smoke_bpf_arena_mapping_keeps_frames_alive_until_munmap`
        // drops every kernel-side handle under a live mapping and measures the
        // free-frame count, then measures it again across the `munmap`.
        for (page, frame) in core::mem::take(&mut inner.frames) {
            let va = self.kva + page * 4096;
            // SAFETY: the arena is being destroyed, so no program and no
            // userspace mapping holds a pointer into it (see above), and the
            // VA is never reissued (bump cursor), so a stale TLB entry on a
            // peer CPU cannot alias a later mapping.
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

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Demand population works, the kernel VA is stable, and a populated page
/// actually reads back what a program wrote — the live-MMU half of the arena
/// that no host test can reach.
fn smoke_bpf_arena_populate_and_roundtrip() -> TestResult {
    let cap = ArenaCap::bootstrap();
    let arena = match Arena::new(&cap, 64) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("Arena::new failed"),
    };
    if arena.kva() < BPF_ARENA_BASE || arena.kva() >= BPF_ARENA_BASE + SLOT_SPAN {
        return TestResult::Fail("arena landed outside the arena window");
    }
    if arena.populated_pages() != 0 {
        return TestResult::Fail("a fresh arena should have no backed pages");
    }
    let page = match arena.populate(3) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("populate failed"),
    };
    let va = page.kva;
    if va != arena.kva() + 3 * 4096 {
        return TestResult::Fail("populate returned the wrong VA");
    }
    // The frame it reports is what a userspace mapping will alias, so it must
    // be the frame actually under that VA — not merely *a* frame.
    if arena.frame_at(3) != Some(page.phys) {
        return TestResult::Fail("populate and frame_at disagree about the backing frame");
    }
    if arena.frame_at(4).is_some() {
        return TestResult::Fail("frame_at reported a frame for an unpopulated page");
    }
    // Freshly populated pages must be zeroed — arena memory is
    // program-visible and must never leak the previous owner's bytes.
    // SAFETY: `va` names a page this call just mapped RW.
    unsafe {
        let p = va as *mut u64;
        if p.read_volatile() != 0 {
            return TestResult::Fail("populated page was not zeroed");
        }
        p.write_volatile(0xDEAD_BEEF_CAFE_F00D);
        if p.read_volatile() != 0xDEAD_BEEF_CAFE_F00D {
            return TestResult::Fail("arena page did not read back what was written");
        }
    }
    // Idempotent, in both fields: the demand-fault path can be entered twice
    // for one page by two CPUs, and a second frame would be a second view of
    // the same arena byte.
    if arena.populate(3) != Ok(page) {
        return TestResult::Fail("re-populating a backed page changed its VA or frame");
    }
    if arena.populated_pages() != 1 {
        return TestResult::Fail("re-populating a backed page allocated a second frame");
    }
    if arena.first_unpopulated(0) != Some(0) || arena.first_unpopulated(3) != Some(4) {
        return TestResult::Fail("free-range tracking disagrees with the populated set");
    }
    if arena.populate(64).is_ok() {
        return TestResult::Fail("populate accepted a page past max_pages");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_bpf_arena_populate_and_roundtrip);

/// An arena grows *after* its frames have been handed out, and every frame it
/// hands out afterwards is the live one.
///
/// This is the property `ArenaError::SnapshotTaken` used to exist to refuse.
/// `FileOps::mmap_frames` was answered once at `mmap` time, so a page populated
/// later could never appear in userspace and the least-bad answer was to refuse
/// the growth. `FileOps::mmap_fault` is answered per page at first touch, so
/// growth is now ordinary — and this test is what would go red if population
/// were ever frozen again.
fn smoke_bpf_arena_grows_after_its_frames_are_exposed() -> TestResult {
    let cap = ArenaCap::bootstrap();
    let arena = match Arena::new(&cap, 8) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("Arena::new failed"),
    };
    if arena.populate_range(0, 4).is_err() {
        return TestResult::Fail("populate_range failed");
    }
    // What a mapping of the first four pages would have aliased.
    let exposed: Vec<PhysAddr> = (0..4).filter_map(|p| arena.frame_at(p)).collect();
    if exposed.len() != 4 {
        return TestResult::Fail("frame_at did not report one frame per populated page");
    }
    // Grow past them. Under the old contract this was `SnapshotTaken`.
    let grown = match arena.populate(5) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("an arena whose frames were exposed refused to grow"),
    };
    if arena.populated_pages() != 5 {
        return TestResult::Fail("the grown page was not recorded");
    }
    if grown.kva != arena.kva() + 5 * 4096 {
        return TestResult::Fail("the grown page landed at the wrong kernel VA");
    }
    // The new page must be a *new* frame, not an alias of an exposed one —
    // otherwise growth would silently corrupt what userspace already maps.
    if exposed.contains(&grown.phys) {
        return TestResult::Fail("a grown page aliased a frame already handed out");
    }
    // And the already-exposed pages still report the same frames, so a mapping
    // taken before the growth still names live memory.
    for (page, phys) in exposed.iter().enumerate() {
        if arena.frame_at(page) != Some(*phys) {
            return TestResult::Fail("growing the arena moved an already-exposed page's frame");
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_bpf_arena_grows_after_its_frames_are_exposed);

/// Several arenas share one slot, at disjoint handle ranges, and every handle
/// clears the null guard.
///
/// This is the property that makes one pinned base register enough: Linux needs
/// one arena per program precisely because its handle is an absolute address.
fn smoke_bpf_arena_slot_packs_several_arenas() -> TestResult {
    let cap = ArenaCap::bootstrap();
    let slot = match ArenaSlot::reserve(&cap) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("ArenaSlot::reserve failed"),
    };
    let a = match Arena::new_in(&cap, &slot, 4) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("first Arena::new_in failed"),
    };
    let b = match Arena::new_in(&cap, &slot, 2) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("second Arena::new_in failed"),
    };
    if a.base_offset() != ARENA_NULL_GUARD_BYTES {
        return TestResult::Fail("the first arena in a slot must start past the null guard");
    }
    if b.base_offset() != ARENA_NULL_GUARD_BYTES + 4 * 4096 {
        return TestResult::Fail("the second arena must start where the first ended");
    }
    if a.slot_base() != slot.base() || b.slot_base() != slot.base() {
        return TestResult::Fail("both arenas must measure handles from the same slot base");
    }
    if a.base_offset() == 0 || b.base_offset() == 0 {
        return TestResult::Fail("handle 0 must never name a real arena byte");
    }
    // Both are reachable from the one base, and they do not alias: write
    // through each and read back through the other's VA.
    if a.populate(0).is_err() || b.populate(0).is_err() {
        return TestResult::Fail("populate failed");
    }
    // SAFETY: both pages were just mapped RW by `populate`.
    unsafe {
        (a.kva() as *mut u64).write_volatile(0xAAAA_AAAA_AAAA_AAAA);
        (b.kva() as *mut u64).write_volatile(0xBBBB_BBBB_BBBB_BBBB);
        if (a.kva() as *const u64).read_volatile() != 0xAAAA_AAAA_AAAA_AAAA {
            return TestResult::Fail("the second arena's write aliased the first's page");
        }
        if (b.kva() as *const u64).read_volatile() != 0xBBBB_BBBB_BBBB_BBBB {
            return TestResult::Fail("the arenas alias each other");
        }
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_bpf_arena_slot_packs_several_arenas);

/// A slot refuses an arena that would run past its usable region, and a refusal
/// does not consume the space it declined.
fn smoke_bpf_arena_slot_refuses_oversize_without_consuming() -> TestResult {
    let cap = ArenaCap::bootstrap();
    let slot = match ArenaSlot::reserve(&cap) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("ArenaSlot::reserve failed"),
    };
    // `ARENA_MAX_BYTES` is exactly what fits between the null guard and the end of
    // the usable region, so on a fresh slot the maximum is accepted and lands
    // flush against the tail guard. Population is not attempted here — this is
    // the VA reservation only — so a 4 GiB request costs nothing but arithmetic.
    let max_pages = (ARENA_MAX_BYTES / 4096) as usize;
    let full = match Arena::new_in(&cap, &slot, max_pages) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("a fresh slot refused an ARENA_MAX_BYTES arena"),
    };
    if full.base_offset() != ARENA_NULL_GUARD_BYTES {
        return TestResult::Fail("the maximal arena did not start at the null-guard boundary");
    }
    if full.base_offset() + ARENA_MAX_BYTES != ARENA_USABLE_BYTES {
        return TestResult::Fail("the maximal arena does not end flush against the tail guard");
    }
    // And now there is no room for anything, not even one page.
    match Arena::new_in(&cap, &slot, 1) {
        Err(ArenaError::SlotExhausted) => {}
        Ok(_) => return TestResult::Fail("a full slot accepted another arena"),
        Err(_) => return TestResult::Fail("a full slot refused for the wrong reason"),
    }

    // A second slot, to check that a *refusal* does not consume the space it
    // declined — otherwise a program that asked for too much would shrink the
    // arena the retry could get.
    let fresh = match ArenaSlot::reserve(&cap) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("reserving a second slot failed"),
    };
    if Arena::new_in(&cap, &fresh, 1).is_err() {
        return TestResult::Fail("the second slot refused its first arena");
    }
    // One page in, so the maximum no longer fits: this is `SlotExhausted` rather
    // than `BadSize`, because the size itself is legal.
    match Arena::new_in(&cap, &fresh, max_pages) {
        Err(ArenaError::SlotExhausted) => {}
        Ok(_) => {
            return TestResult::Fail("a slot accepted an arena that overruns its usable region")
        }
        Err(_) => return TestResult::Fail("oversize arena failed for the wrong reason"),
    }
    // Past `ARENA_MAX_BYTES` the size itself is bad, before the slot is even
    // consulted — a distinct error so the caller can tell "too big to exist" from
    // "too big for this slot".
    match Arena::new_in(&cap, &fresh, max_pages + 1) {
        Err(ArenaError::BadSize) => {}
        _ => return TestResult::Fail("an arena past ARENA_MAX_BYTES must be BadSize"),
    }
    // Neither refusal advanced the cursor: the next arena still starts where the
    // first one ended.
    match Arena::new_in(&cap, &fresh, 1) {
        Ok(a) if a.base_offset() == ARENA_NULL_GUARD_BYTES + 4096 => TestResult::Pass,
        Ok(_) => TestResult::Fail("a refused reservation consumed slot space anyway"),
        Err(_) => TestResult::Fail("a small arena failed after two refusals"),
    }
}
kernel_test_in!(
    "memory",
    smoke_bpf_arena_slot_refuses_oversize_without_consuming
);

/// A revoked `Cap<BpfArena, Grant>` cannot create an arena — invariant #5.
fn smoke_bpf_arena_revoked_cap_cannot_create() -> TestResult {
    let cap = ArenaCap::bootstrap();
    if Arena::new(&cap, 4).is_err() {
        return TestResult::Fail("Arena::new failed with a live cap");
    }
    // A live slot, taken before revocation, so that the `new_in` arm below
    // exercises the capability check rather than slot reservation.
    let slot = match ArenaSlot::reserve(&cap) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("ArenaSlot::reserve failed with a live cap"),
    };
    cap.revoke();
    match Arena::new(&cap, 4) {
        Err(ArenaError::CapRevoked) => {}
        Ok(_) => return TestResult::Fail("revoked cap still created an arena"),
        Err(_) => return TestResult::Fail("revoked cap failed for the wrong reason"),
    }
    // Every entry point that takes the cap must check it, not just the one that
    // happens to be tested — placing into an existing slot is a second grant of
    // the same authority.
    match Arena::new_in(&cap, &slot, 4) {
        Err(ArenaError::CapRevoked) => {}
        Ok(_) => return TestResult::Fail("revoked cap still placed an arena in a slot"),
        Err(_) => return TestResult::Fail("new_in with a revoked cap failed for the wrong reason"),
    }
    match ArenaSlot::reserve(&cap) {
        Err(ArenaError::CapRevoked) => TestResult::Pass,
        Ok(_) => TestResult::Fail("revoked cap still reserved a slot"),
        Err(_) => {
            TestResult::Fail("slot reservation with a revoked cap failed for the wrong reason")
        }
    }
}
kernel_test_in!("memory", smoke_bpf_arena_revoked_cap_cannot_create);

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

    // There is deliberately *no* host test restating the tail-guard arithmetic.
    // The `const` assertion above it already is that test — verified by
    // shrinking `ARENA_SLOT_STRIDE` to `ARENA_USABLE_BYTES`, which fails the
    // build with the assertion's own message — and a `#[test]` asserting the
    // same inequality could never go red on its own, since the build would stop
    // first. What *is* tested here and below is the behaviour the constants are
    // supposed to produce: that `carve` never returns handle 0 and never lets an
    // arena end past the usable region.

    /// `carve` is the intra-slot allocator; check the layout it produces without
    /// needing an MMU.
    #[test]
    fn carve_packs_page_aligned_and_refuses_overrun() {
        let slot = ArenaSlot {
            base: BPF_ARENA_BASE,
            next: AtomicU64::new(ARENA_NULL_GUARD_BYTES),
        };
        assert_eq!(slot.carve(1).expect("first"), ARENA_NULL_GUARD_BYTES);
        // Rounded up to a page, so the next arena is page-aligned even after a
        // one-byte request.
        assert_eq!(
            slot.carve(4096).expect("second"),
            ARENA_NULL_GUARD_BYTES + 4096
        );
        assert_eq!(
            slot.carve(4097).expect("third"),
            ARENA_NULL_GUARD_BYTES + 2 * 4096
        );
        // Overrun refused, and the refusal leaves the cursor alone.
        assert_eq!(
            slot.carve(ARENA_USABLE_BYTES),
            Err(ArenaError::SlotExhausted)
        );
        assert_eq!(
            slot.carve(8).expect("after a refusal"),
            ARENA_NULL_GUARD_BYTES + 4 * 4096
        );
    }

    /// The null guard, as a property of every offset `carve` can return.
    #[test]
    fn carve_never_returns_handle_zero() {
        let slot = ArenaSlot {
            base: BPF_ARENA_BASE,
            next: AtomicU64::new(ARENA_NULL_GUARD_BYTES),
        };
        for _ in 0..64 {
            let off = slot.carve(4096).expect("room for 64 pages");
            assert_ne!(
                off, 0,
                "handle 0 must stay reserved for `None` in Option<ArenaPtr<T>>"
            );
            assert!(off >= ARENA_NULL_GUARD_BYTES);
        }
    }
}

/// Dropping an arena returns **every** frame it populated to the buddy,
/// including frames it had already handed out to a mapping.
///
/// This replaces `smoke_bpf_arena_exposed_frames_are_not_returned_to_the_buddy`,
/// which asserted the opposite because a userspace mapping used to keep nothing
/// alive: freeing here would have handed userspace a writable window onto
/// whatever the buddy allocated next, so the frames were leaked instead. The
/// mapping now owns an `Arc<dyn FileOps>` (see [`Arena::drop`]), so reaching
/// this drop *means* no mapping remains and the leak has been deleted rather
/// than kept as belt-and-braces.
///
/// The half of "exactly when no mapping remains" that needs a real mapping —
/// that a live one keeps the frames out of the buddy — cannot be written here:
/// this crate is below both the syscall layer and `narf-bpf`. It lives in
/// `userspace/src/handlers/sys_mmap.rs` as
/// `smoke_bpf_arena_mapping_keeps_frames_alive_until_munmap`, and neither half
/// is sufficient alone: this one passes for an implementation that frees
/// unconditionally, that one passes for an implementation that never frees.
///
/// Measured across the **drop alone**. An earlier version sampled the free
/// count before allocating and expected it to rise afterwards, which is wrong
/// arithmetic — allocate-then-free returns to the original count. Bracketing
/// the drop is what makes the delta mean "frames this drop returned".
fn smoke_bpf_arena_drop_returns_frames_to_the_buddy() -> TestResult {
    let cap = ArenaCap::bootstrap();
    let mut arena = match Arena::new(&cap, 4) {
        Ok(a) => Some(a),
        Err(_) => return TestResult::Fail("Arena::new failed"),
    };
    let Some(a) = arena.as_ref() else {
        return TestResult::Fail("arena setup failed");
    };
    if a.populate_range(0, 4).is_err() {
        return TestResult::Fail("populate_range failed");
    }
    // Hand the frames out, exactly as a `MAP_SHARED` mapping's first faults
    // would: the old contract made *this* the point of no return.
    let exposed: Vec<PhysAddr> = (0..4).filter_map(|p| a.frame_at(p)).collect();
    if exposed.len() != 4 {
        return TestResult::Fail("frame_at did not report one frame per populated page");
    }
    let before = crate::frame::stats().free;
    drop(arena.take());
    let returned = crate::frame::stats().free.saturating_sub(before);
    if returned < 4 {
        return TestResult::Fail("dropping an arena did not return its frames to the buddy");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_bpf_arena_drop_returns_frames_to_the_buddy);
