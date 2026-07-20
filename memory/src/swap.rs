//! Batched swap / page-out subsystem.
//!
//! # Why this exists (and what makes it NARF-shaped)
//!
//! Wave C landed the `Pager` *seam* (`crate::pager`): a trait that can
//! say "stash these 4 KiB somewhere and hand me a token back", plus a
//! `ReclaimOutcome::DeferToPager` variant. What it did *not* ship was a
//! live swap: the reclaim loop logged the page-out result and left the
//! frame in place (see the Wave-C scope notes in `reclaim.rs` /
//! `pager.rs`). This module is that live swap — and it is built around
//! a deliberate departure from the classic Linux design.
//!
//! Linux's historical reclaim/writeback unit is essentially per-folio:
//! `shrink_folio_list` walks the LRU one folio at a time and each
//! victim is written to its own swap slot with its own submission.
//! Large-folio support widened the folio, but the *scheduling* unit is
//! still one folio per pageout call. NARF instead reclaims a **run of N
//! victim pages in a single batched operation**: the pageout entry
//! point (`swap_out_batch`) selects up to `swap_batch_pages()` cold
//! victims, allocates a **contiguous run of swap slots** for them, and
//! writes the whole run to the backing store in one `write_batch` call
//! (one submission for the batch, not N). Fault-in reads a single page
//! back on demand, with an optional `read_batch` readahead of the run's
//! neighbours (they were written adjacently, so they're the natural
//! readahead set).
//!
//! Designing around the batch from the start is the point: the slot
//! allocator hands out contiguous runs, the backend's primary write
//! path is `write_batch`, and the swap-entry PTE encoding records
//! enough to find the neighbouring slots for readahead.
//!
//! # Backend choice: compressed-RAM
//!
//! v1 targets a **compressed-RAM** backend (`ZramBackend`) built on the
//! existing `crate::zpool::Zpool` (LZ4 via `crate::compress`), *not* a
//! VFS swap-file. Rationale:
//!
//!   * `memory/` already owns `Zpool` + the LZ4 codec; a compressed-RAM
//!     backend keeps the whole feature inside this crate with zero new
//!     cross-crate coupling (a swap-*file* would pull the VFS + a block
//!     device into the memory crate's dependency surface).
//!   * `Zpool::store`/`load`/`free` already give us the exact
//!     put-bytes / get-bytes / release-slot primitives a backend needs.
//!   * It exercises the *interesting* half of the design (batched slot
//!     allocation + batched write + fault-in round-trip) without a
//!     disk. A real swap-*file* `SwapBackend` is a drop-in later: the
//!     trait is written so a block-backed impl slots in behind the same
//!     `SwapSlot` run interface.
//!
//! The `SwapBackend` trait is the seam; `ZramBackend` is the concrete
//! v1. A future `SwapFileBackend` implements the same trait.
//!
//! # PTE swap-entry encoding
//!
//! A swapped-out page's PTE is **non-present** (bit 0 = 0, so the MMU
//! faults on touch) but carries a `SWAP_MARKER` bit plus a packed
//! `(swap_type, offset)` in the software-available bits. The
//! page-fault handler distinguishes "swapped out" (marker set) from
//! "never mapped" (all-zero PTE) and routes the former to
//! `swap_in_pte`. See `SwapPte` for the exact bit layout and its
//! round-trip unit test.
//!
//! # cgroup swap accounting
//!
//! Every successful batched page-out calls `cgroup_charge` for the run
//! (positive `memory.swap.*` delta); every page-in / discard uncharges.
//! Under the `cgroup` feature this drives the real hook; without it the
//! calls compile to a no-op counter so the seam stays clean.
//!
//! # Clean-room provenance
//!
//! Design references (cited; no Linux/BSD source consulted):
//!
//!   - Tanenbaum, A. S. & Bos, H. (2014). *Modern Operating Systems*
//!     (4th ed.), §3.6 — paging to a backing store, the page-fault
//!     round-trip. Pearson.
//!   - Gorman, M. (2004). *Understanding the Linux Virtual Memory
//!     Manager*, ch. 11 (swap management) — read for the *shape* of
//!     swap-slot allocation and swap-PTE encoding, implemented here
//!     independently.

extern crate alloc as alloc_crate;

use alloc_crate::boxed::Box;
use alloc_crate::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::zpool::{Zpool, ZpoolHandle, ZPAGE_SIZE};
use crate::PhysAddr;

/// A single swap slot — one 4 KiB page's worth of backing store.
///
/// The wire format is an opaque `u64`; callers must not assume any
/// structure beyond `Copy + Eq`. Internally it is a monotonic index
/// into the slot allocator's table, but that is an implementation
/// detail the PTE encoder and the backend agree on privately.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SwapSlot(pub u64);

impl SwapSlot {
    /// Sentinel meaning "no slot".
    pub const NONE: SwapSlot = SwapSlot(u64::MAX);

    /// Raw index, for the PTE encoder and diagnostics.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Errors from swap operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SwapError {
    /// The slot allocator has no free run of the requested length.
    NoSlots,
    /// The backing store refused (out of memory / compression failure).
    BackendFull,
    /// `swap_in` / `discard` given a slot that was never allocated (or
    /// was already freed). Callers may legitimately race a stale slot.
    SlotNotFound,
    /// A page-table walk / frame alloc failed while faulting a page in.
    MapFailed,
    /// The cgroup `memory.swap.max` limit would be exceeded by this
    /// page-out. The batch is rolled back and the caller keeps the
    /// frames resident.
    SwapLimit,
}

// ── Batch-size knob (the headline tunable) ─────────────────────────

/// Default number of pages coalesced into one batched swap-out. The
/// pageout path selects up to this many cold victims and writes them
/// to a contiguous slot run in a single backend `write_batch` call.
///
/// 16 pages = 64 KiB per submission: large enough that the per-batch
/// bookkeeping (slot-run alloc, one backend call, one TLB range
/// shootdown) amortises well against the per-page work, small enough
/// that a batch's transient double-residency (frames still live +
/// their compressed copies) is bounded. Tunable at runtime via
/// `set_swap_batch_pages`.
pub const SWAP_BATCH_PAGES_DEFAULT: usize = 16;

/// Hard ceiling on the batch knob — bounds the on-stack `Vec`s the
/// pageout path builds per batch and keeps a slot run addressable.
pub const SWAP_BATCH_PAGES_MAX: usize = 512;

/// Runtime-tunable batch size (the "sysctl-ish knob"). Stored as an
/// atomic so it can be adjusted without the swap lock; reads are
/// `Relaxed` because a torn read merely picks last-or-next batch size,
/// never a wrong one.
static SWAP_BATCH_PAGES: AtomicUsize = AtomicUsize::new(SWAP_BATCH_PAGES_DEFAULT);

/// Current batch size. Clamped to `[1, SWAP_BATCH_PAGES_MAX]`.
#[inline]
pub fn swap_batch_pages() -> usize {
    SWAP_BATCH_PAGES
        .load(Ordering::Relaxed)
        .clamp(1, SWAP_BATCH_PAGES_MAX)
}

/// Set the batch size knob. Clamped to `[1, SWAP_BATCH_PAGES_MAX]`.
/// Returns the value actually stored after clamping.
pub fn set_swap_batch_pages(n: usize) -> usize {
    let clamped = n.clamp(1, SWAP_BATCH_PAGES_MAX);
    SWAP_BATCH_PAGES.store(clamped, Ordering::Relaxed);
    clamped
}

// ── Swap-entry PTE encoding ────────────────────────────────────────

/// A swapped-out page's PTE, decoded.
///
/// # Bit layout (x86_64 non-present PTE, software-available bits)
///
/// When bit 0 (PRESENT) is clear the CPU ignores every other bit —
/// the whole 63-bit remainder is software-defined. We use:
///
/// ```text
///   bit  0        : PRESENT = 0            (always — non-present)
///   bit  1        : SWAP_MARKER = 1        (distinguishes swap from a
///                                           genuinely-empty PTE=0)
///   bits 2..=6    : swap_type (5 bits)     (which swap area, 0..=31)
///   bits 7..=57   : offset   (51 bits)     (slot index within the area)
///   bits 58..=63  : reserved (0)
/// ```
///
/// A PTE of all zeroes has `SWAP_MARKER = 0`, so `decode` returns
/// `None` and the fault handler treats it as a normal not-present
/// fault (demand-zero / SIGSEGV), exactly as before. The 51-bit offset
/// dwarfs any plausible swap-area size; 5 type bits leaves room for 32
/// swap areas, mirroring Linux's classic `MAX_SWAPFILES`-class budget.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SwapPte {
    /// Which swap area (0..=31). v1 uses a single area (type 0), but the
    /// field is carried so a multi-area allocator drops in unchanged.
    pub swap_type: u8,
    /// Slot index within the area.
    pub offset: u64,
}

/// PRESENT bit — clear in a swap PTE (the CPU faults on touch).
const PTE_PRESENT: u64 = 1 << 0;
/// SWAP_MARKER — set in a swap PTE, clear in an empty PTE.
const SWAP_MARKER: u64 = 1 << 1;
const SWAP_TYPE_SHIFT: u64 = 2;
const SWAP_TYPE_BITS: u64 = 5;
const SWAP_TYPE_MASK: u64 = (1 << SWAP_TYPE_BITS) - 1;
const SWAP_OFFSET_SHIFT: u64 = 7;
const SWAP_OFFSET_BITS: u64 = 51;
const SWAP_OFFSET_MASK: u64 = (1 << SWAP_OFFSET_BITS) - 1;

impl SwapPte {
    /// Largest offset representable in the PTE encoding.
    pub const MAX_OFFSET: u64 = SWAP_OFFSET_MASK;
    /// Largest swap-type representable in the PTE encoding.
    pub const MAX_TYPE: u8 = SWAP_TYPE_MASK as u8;

    /// Encode into a raw non-present PTE value. Bits outside the
    /// documented fields are zero; PRESENT is guaranteed clear.
    ///
    /// `swap_type` above `MAX_TYPE` and `offset` above `MAX_OFFSET` are
    /// masked to their field width — callers that could overflow must
    /// check `MAX_OFFSET` first (the slot allocator does).
    #[inline]
    pub const fn encode(self) -> u64 {
        let ty = (self.swap_type as u64 & SWAP_TYPE_MASK) << SWAP_TYPE_SHIFT;
        let off = (self.offset & SWAP_OFFSET_MASK) << SWAP_OFFSET_SHIFT;
        SWAP_MARKER | ty | off
    }

    /// Decode a raw PTE. Returns `Some` iff the PTE is a swap entry
    /// (non-present with `SWAP_MARKER` set); `None` for a present PTE
    /// or an empty (all-zero-ish) non-present PTE.
    #[inline]
    pub const fn decode(raw: u64) -> Option<SwapPte> {
        if raw & PTE_PRESENT != 0 {
            return None; // present — a normal mapping, not swapped out
        }
        if raw & SWAP_MARKER == 0 {
            return None; // empty PTE — never-mapped / demand-zero
        }
        let swap_type = ((raw >> SWAP_TYPE_SHIFT) & SWAP_TYPE_MASK) as u8;
        let offset = (raw >> SWAP_OFFSET_SHIFT) & SWAP_OFFSET_MASK;
        Some(SwapPte { swap_type, offset })
    }

    /// True iff `raw` decodes as a swap entry. Cheap predicate for the
    /// fault dispatcher's hot path.
    #[inline]
    pub const fn is_swap_pte(raw: u64) -> bool {
        (raw & PTE_PRESENT == 0) && (raw & SWAP_MARKER != 0)
    }
}

// ── Backend abstraction ────────────────────────────────────────────

/// A swap backing store.
///
/// The backend owns *bytes*: it stashes the contents of one or more
/// 4 KiB pages and answers reads by slot. The primary write path is
/// **batched** (`write_batch`) — the whole design pushes N pages
/// through one call. `read` faults a single page back; `read_batch`
/// is an optional readahead that pulls a contiguous run.
///
/// The kernel (this module) owns *frames* and *page tables*; the
/// backend never touches a PTE or a `PhysFrame`.
pub trait SwapBackend: Send + Sync + 'static {
    /// Backend name (`"zram"`, `"swapfile"`, …) for diagnostics/tests.
    fn name(&self) -> &'static str;

    /// Write a batch of pages to a **contiguous run of slots** in one
    /// operation. `slots` and `pages` are parallel and equal-length;
    /// `slots` is guaranteed contiguous and ascending by the slot
    /// allocator. Each `pages[i]` is the physical frame whose 4 KiB
    /// contents must be preserved under `slots[i]`.
    ///
    /// On `Err`, the backend must leave *no* slot populated (all-or-
    /// nothing) so the caller can roll the run back cleanly.
    fn write_batch(&self, slots: &[SwapSlot], pages: &[PhysAddr]) -> Result<(), SwapError>;

    /// Read one page back into `out`. Used on the fault-in fast path.
    fn read(&self, slot: SwapSlot, out: &mut [u8; ZPAGE_SIZE]) -> Result<(), SwapError>;

    /// Read a contiguous run back in one call. Default = per-slot
    /// `read`; a block-backed impl overrides with one coalesced I/O.
    /// `outs[i]` receives `slots[i]`.
    fn read_batch(
        &self,
        slots: &[SwapSlot],
        outs: &mut [[u8; ZPAGE_SIZE]],
    ) -> Result<(), SwapError> {
        debug_assert_eq!(slots.len(), outs.len());
        for (s, o) in slots.iter().zip(outs.iter_mut()) {
            self.read(*s, o)?;
        }
        Ok(())
    }

    /// Release a slot's backing (the page was faulted in or the mapping
    /// was torn down). Idempotent on already-freed slots.
    fn discard(&self, slot: SwapSlot);
}

/// Compressed-RAM swap backend (zram-like): LZ4 into a global
/// `Zpool`, keyed by slot index.
///
/// `write_batch` compresses + stores each page and records the
/// resulting `ZpoolHandle` under the slot's index; `read` decompresses
/// back into the caller's buffer; `discard` frees the zpool entry. The
/// batch is all-or-nothing: a mid-batch store failure rolls back the
/// zpool handles committed so far before returning `BackendFull`.
#[derive(Debug)]
pub struct ZramBackend {
    inner: IrqSafeSpinLock<ZramInner>,
}

#[derive(Debug)]
struct ZramInner {
    pool: Zpool,
    /// `slot index → live zpool handle`. `None` = slot unpopulated.
    /// Grows on demand; indices match `SwapSlot::raw()`.
    handles: Vec<Option<ZpoolHandle>>,
}

impl ZramBackend {
    /// A fresh, empty compressed-RAM backend.
    pub const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(ZramInner {
                pool: Zpool::new(),
                handles: Vec::new(),
            }),
        }
    }
}

impl Default for ZramBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ZramInner {
    /// Ensure `handles` is long enough to index `slot`.
    fn ensure_slot(&mut self, slot: usize) {
        if slot >= self.handles.len() {
            self.handles.resize(slot + 1, None);
        }
    }
}

impl SwapBackend for ZramBackend {
    fn name(&self) -> &'static str {
        "zram"
    }

    fn write_batch(&self, slots: &[SwapSlot], pages: &[PhysAddr]) -> Result<(), SwapError> {
        debug_assert_eq!(slots.len(), pages.len());
        let mut inner = self.inner.lock();

        // Commit each page; on any failure roll back what we stored so
        // the run is all-or-nothing (the SwapBackend contract).
        let mut committed: Vec<(usize, ZpoolHandle)> = Vec::with_capacity(slots.len());
        for (slot, phys) in slots.iter().zip(pages.iter()) {
            let idx = slot.raw() as usize;
            // Read the 4 KiB frame contents through the kernel's RAM
            // window (identity on x86_64; direct-map offset for high
            // frames). The frame is still live — the caller unmaps it
            // only after a successful write.
            let src = phys.kernel_ptr::<u8>();
            // SAFETY: `phys` is a live, exclusively-borrowed 4 KiB frame
            // for the duration of this batched write; `kernel_ptr`
            // yields a mapping valid for a 4 KiB read.
            let page: &[u8; ZPAGE_SIZE] = unsafe { &*(src as *const [u8; ZPAGE_SIZE]) };
            match inner.pool.store(page) {
                Ok(h) => committed.push((idx, h)),
                Err(_) => {
                    // Roll back: free every handle stored this batch.
                    for (_, h) in committed.drain(..) {
                        inner.pool.free(h);
                    }
                    return Err(SwapError::BackendFull);
                }
            }
        }
        // All stores succeeded — publish the handles.
        for (idx, h) in committed {
            inner.ensure_slot(idx);
            // A live handle already here would be a double-write to the
            // same slot — free it first to avoid leaking the old copy.
            if let Some(old) = inner.handles[idx].replace(h) {
                inner.pool.free(old);
            }
        }
        Ok(())
    }

    fn read(&self, slot: SwapSlot, out: &mut [u8; ZPAGE_SIZE]) -> Result<(), SwapError> {
        let inner = self.inner.lock();
        let idx = slot.raw() as usize;
        let handle = inner
            .handles
            .get(idx)
            .copied()
            .flatten()
            .ok_or(SwapError::SlotNotFound)?;
        inner
            .pool
            .load(handle, out)
            .map_err(|_| SwapError::SlotNotFound)
    }

    fn discard(&self, slot: SwapSlot) {
        let mut inner = self.inner.lock();
        let idx = slot.raw() as usize;
        if let Some(slot_mut) = inner.handles.get_mut(idx) {
            if let Some(h) = slot_mut.take() {
                inner.pool.free(h);
            }
        }
    }
}

// ── Swap slot allocator (contiguous runs) ──────────────────────────

/// Allocates **contiguous runs** of swap slots for batched write-out.
///
/// Slots are a linear index space `[0, high_water)`. A run of `n`
/// slots is `[base, base+n)` with all `n` free. Freed slots return to
/// a free set and are re-coalesced into runs by a first-fit scan, so a
/// later batch can reuse them. This is deliberately simple (first-fit
/// over a sorted free list) — the batch sizes are small (tens of
/// slots) and swap traffic is a cold path; a buddy-style run allocator
/// is the follow-up if fragmentation ever bites.
#[derive(Debug)]
struct SlotAllocator {
    /// Next never-yet-allocated slot index. Slots `>= high_water` are
    /// implicitly free.
    high_water: u64,
    /// Freed slots below `high_water`, kept sorted ascending so the
    /// first-fit run scan can coalesce adjacent runs.
    free: Vec<u64>,
}

impl SlotAllocator {
    const fn new() -> Self {
        Self {
            high_water: 0,
            free: Vec::new(),
        }
    }

    /// Allocate a contiguous run of `n` slots. Prefers reusing a
    /// coalescible run from the free list; else bumps `high_water`.
    /// Returns the run's base slot index.
    fn alloc_run(&mut self, n: usize) -> Result<u64, SwapError> {
        if n == 0 {
            return Ok(self.high_water); // empty run — degenerate but valid
        }
        // First-fit over the sorted free list: find `n` consecutive
        // indices `base, base+1, …, base+n-1` all present in `free`.
        if !self.free.is_empty() {
            self.free.sort_unstable();
            let mut i = 0;
            while i + n <= self.free.len() {
                let base = self.free[i];
                let mut run = 1;
                while run < n && self.free[i + run] == base + run as u64 {
                    run += 1;
                }
                if run == n {
                    // Remove the run from the free list.
                    self.free.drain(i..i + n);
                    return Ok(base);
                }
                // Skip past the (shorter-than-n) run we just scanned.
                i += run;
            }
        }
        // No reusable run — bump the high-water mark. Guard the PTE
        // offset budget so every slot in the run is encodable.
        let base = self.high_water;
        let top = base.checked_add(n as u64).ok_or(SwapError::NoSlots)?;
        if top > SwapPte::MAX_OFFSET {
            return Err(SwapError::NoSlots);
        }
        self.high_water = top;
        Ok(base)
    }

    /// Return a single slot to the free set. Idempotent-ish: a
    /// double-free just re-inserts a duplicate, which the run scan
    /// tolerates (it never allocates the same index twice because a
    /// successful `alloc_run` drains the matched indices).
    fn free_slot(&mut self, slot: u64) {
        if slot < self.high_water && !self.free.contains(&slot) {
            self.free.push(slot);
        }
    }

    fn stats(&self) -> (u64, usize) {
        (self.high_water, self.free.len())
    }
}

// ── Global swap state ──────────────────────────────────────────────

/// The kernel-wide swap device: one backend + one slot allocator.
struct SwapDevice {
    backend: Option<Box<dyn SwapBackend>>,
    slots: SlotAllocator,
    /// Swap area id this device answers for. v1 = 0 (single area).
    /// Consumed by the x86_64 pageout path when stamping swap PTEs;
    /// aarch64 paging is a stub, so it's read only under x86_64.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    swap_type: u8,
    /// Live paged-out page count, for `swap_stats`.
    resident: u64,
    /// Total pages ever paged out, for `swap_stats`.
    pages_out: u64,
    /// Total pages ever faulted back in, for `swap_stats`.
    pages_in: u64,
}

impl SwapDevice {
    const fn new() -> Self {
        Self {
            backend: None,
            slots: SlotAllocator::new(),
            swap_type: 0,
            resident: 0,
            pages_out: 0,
            pages_in: 0,
        }
    }
}

static SWAP: IrqSafeSpinLock<SwapDevice> = IrqSafeSpinLock::new(SwapDevice::new());

/// Snapshot of swap counters for `/proc`-style diagnostics + tests.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SwapStats {
    /// Pages currently resident in swap (paged out, not yet faulted in).
    pub resident: u64,
    /// Slots ever handed out (high-water mark of the allocator).
    pub slots_high_water: u64,
    /// Slots currently on the free list (reusable).
    pub slots_free: usize,
    /// Total page-out events since boot.
    pub pages_out: u64,
    /// Total page-in events since boot.
    pub pages_in: u64,
    /// Configured batch size at snapshot time.
    pub batch_pages: usize,
}

/// Install the swap backend. Idempotent-safe to call once at boot;
/// replaces any prior backend (whose live slots become unrecoverable,
/// so only swap at well-defined boundaries — boot / test setup).
pub fn install_backend<B: SwapBackend>(backend: B) {
    let mut dev = SWAP.lock();
    dev.backend = Some(Box::new(backend));
}

/// Install the default compressed-RAM backend if none is set yet.
/// Called from the pageout path so callers never hit a missing
/// backend. Idempotent.
pub fn install_default_if_unset() {
    let mut dev = SWAP.lock();
    if dev.backend.is_none() {
        dev.backend = Some(Box::new(ZramBackend::new()));
    }
}

/// Name of the installed backend, or `None` if unset.
pub fn backend_name() -> Option<&'static str> {
    SWAP.lock().backend.as_ref().map(|b| b.name())
}

/// Swap counter snapshot.
pub fn swap_stats() -> SwapStats {
    let dev = SWAP.lock();
    let (hw, free) = dev.slots.stats();
    SwapStats {
        resident: dev.resident,
        slots_high_water: hw,
        slots_free: free,
        pages_out: dev.pages_out,
        pages_in: dev.pages_in,
        batch_pages: swap_batch_pages(),
    }
}

// ── cgroup swap accounting seam ────────────────────────────────────
//
// Charge `memory.swap.*` for a run of pages on page-out; uncharge on
// page-in / discard. Under the `cgroup` feature this drives the real
// installed hook; without it the calls vanish. A denied charge fails
// the whole batch (the caller keeps the frames resident).

// These are consumed by the x86_64 batched-pageout path (`swap_out_batch`
// / `swap_in_pte` / `swap_discard`). aarch64 paging is a stub, so on that
// arch only `swap_discard` reaches `swap_uncharge` — silence the rest.
#[cfg(feature = "cgroup")]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
#[must_use]
fn swap_charge(pages: u64) -> bool {
    crate::cgroup_charge::try_charge(pages * ZPAGE_SIZE as u64)
}
#[cfg(not(feature = "cgroup"))]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
#[must_use]
fn swap_charge(_pages: u64) -> bool {
    true
}

#[cfg(feature = "cgroup")]
fn swap_uncharge(pages: u64) {
    crate::cgroup_charge::uncharge(pages * ZPAGE_SIZE as u64);
}
#[cfg(not(feature = "cgroup"))]
fn swap_uncharge(_pages: u64) {}

// ── Batched page-out entry point ───────────────────────────────────

/// One victim page selected for batched page-out: the address space it
/// lives in (its PML4 root) and the virtual address to unmap.
///
/// The pageout path resolves each victim's physical frame itself (via
/// `translate`) so the caller only has to name *which* mappings are
/// cold — it does not have to pre-walk the page tables.
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SwapVictim {
    /// Physical base of the owning address space's PML4.
    pub pml4_phys: PhysAddr,
    /// Virtual address of the page to swap out (4 KiB-aligned).
    pub virt: crate::VirtAddr,
}

/// Swap out a **batch** of victim pages in a single backend operation.
///
/// This is the headline entry point. Given up to `swap_batch_pages()`
/// cold victims (the caller — typically `reclaim.rs` — selects them),
/// it:
///
///   1. Resolves each victim's live physical frame (`translate`).
///   2. Allocates a **contiguous run** of swap slots for the batch.
///   3. Charges the cgroup swap counter for the whole run (roll back
///      + bail if over `memory.swap.max`).
///   4. Writes every frame to its slot in **one** `write_batch` call.
///   5. Replaces each victim PTE with a non-present swap entry
///      (`SwapPte::encode`) via `unmap_4kb` + a direct swap-PTE write,
///      issuing a single batched TLB range shootdown intent per AS.
///   6. Frees the now-evicted physical frames back to the buddy.
///
/// Returns the number of pages actually paged out (0 if the batch was
/// empty or every victim was already unmapped). On a mid-batch backend
/// failure the whole run is rolled back and `Err` is returned with no
/// frames freed and no PTEs disturbed.
///
/// The caller keeps the returned `SwapSlot` run out of band only if it
/// wants explicit readahead; the swap entries themselves live in the
/// PTEs, so a plain fault-in needs no side-table.
#[cfg(target_arch = "x86_64")]
pub fn swap_out_batch(victims: &[SwapVictim]) -> Result<usize, SwapError> {
    use crate::paging::{translate, unmap_4kb};

    if victims.is_empty() {
        return Ok(0);
    }
    install_default_if_unset();

    // Cap the batch at the knob so an oversized caller list still
    // writes in bounded chunks. (We take the first `batch` here; the
    // caller loops if it has more.)
    let batch = victims.len().min(swap_batch_pages());
    let victims = &victims[..batch];

    // ── 1. Resolve live frames. Skip victims that aren't currently
    //       mapped to a 4 KiB page (already unmapped / huge). ──
    let mut resolved: Vec<(SwapVictim, PhysAddr)> = Vec::with_capacity(batch);
    for v in victims {
        // SAFETY: `pml4_phys` is a live, identity-reachable AS root
        // (the caller owns it); `translate` only reads the tables.
        if let Some(phys) = unsafe { translate(v.pml4_phys, v.virt) } {
            resolved.push((*v, phys));
        }
    }
    if resolved.is_empty() {
        return Ok(0);
    }
    let n = resolved.len();

    // ── 2. Allocate a contiguous slot run + build the slot list. ──
    let (base, swap_type, slot_run) = {
        let mut dev = SWAP.lock();
        let base = dev.slots.alloc_run(n)?;
        let ty = dev.swap_type;
        let run: Vec<SwapSlot> = (0..n as u64).map(|k| SwapSlot(base + k)).collect();
        (base, ty, run)
    };

    // ── 3. cgroup swap charge for the whole run. ──
    if !swap_charge(n as u64) {
        // Return the slots we reserved and bail — frames stay resident.
        let mut dev = SWAP.lock();
        for k in 0..n as u64 {
            dev.slots.free_slot(base + k);
        }
        return Err(SwapError::SwapLimit);
    }

    // ── 4. One batched backend write. ──
    let frames: Vec<PhysAddr> = resolved.iter().map(|(_, p)| *p).collect();
    {
        let dev = SWAP.lock();
        let backend = dev.backend.as_ref().expect("backend installed above");
        if let Err(e) = backend.write_batch(&slot_run, &frames) {
            drop(dev);
            // Roll back: uncharge + return the slots. No PTE touched yet.
            swap_uncharge(n as u64);
            let mut dev = SWAP.lock();
            for k in 0..n as u64 {
                dev.slots.free_slot(base + k);
            }
            return Err(e);
        }
    }

    // ── 5 + 6. Install swap PTEs + free the frames. ──
    //
    // For each victim: unmap the present PTE (this issues the TLB
    // invalidation / cross-CPU shootdown via `unmap_4kb`'s
    // `invlpg_global`), then write the non-present swap entry directly
    // into the leaf PTE slot, then return the frame to the buddy.
    let mut done = 0usize;
    for (k, (v, phys)) in resolved.iter().enumerate() {
        let slot = SwapSlot(base + k as u64);
        // SAFETY: caller-owned AS root; the page was resolved present
        // just above and no other CPU mutates this leaf under us (the
        // paging lock inside `unmap_4kb` serialises same-root walks).
        let removed = unsafe { unmap_4kb(v.pml4_phys, v.virt) };
        if removed.is_err() {
            // Raced away between translate and unmap — skip; its slot
            // is dead weight but the backend copy is harmless. Free the
            // slot back so it can be reused.
            let mut dev = SWAP.lock();
            dev.slots.free_slot(base + k as u64);
            // Discard the now-orphaned backend copy.
            if let Some(backend) = dev.backend.as_ref() {
                backend.discard(slot);
            }
            swap_uncharge(1);
            continue;
        }
        // Install the swap entry directly into the leaf PTE slot.
        let pte = SwapPte {
            swap_type,
            offset: slot.raw(),
        }
        .encode();
        // SAFETY: same AS-root ownership; `write_swap_pte` walks to the
        // existing leaf (present until the unmap above cleared it, so
        // every intermediate table exists) and writes the non-present
        // entry. Non-present ⇒ no INVLPG needed (unmap already flushed).
        if unsafe { write_swap_pte(v.pml4_phys, v.virt, pte) }.is_err() {
            // Extremely unlikely (tables were just walked). Restore
            // sanity: discard the backend copy + free the slot. The
            // page's contents are lost, but that page was already
            // unmapped; leaving the PTE empty makes it demand-zero.
            let mut dev = SWAP.lock();
            dev.slots.free_slot(base + k as u64);
            if let Some(backend) = dev.backend.as_ref() {
                backend.discard(slot);
            }
            swap_uncharge(1);
            continue;
        }
        // Return the evicted frame to the buddy.
        crate::frame::free_frame(crate::frame::PhysFrame::new(*phys));
        done += 1;
    }

    {
        let mut dev = SWAP.lock();
        dev.resident += done as u64;
        dev.pages_out += done as u64;
    }
    Ok(done)
}

/// Fault a single swapped-out page back in.
///
/// Called by the page-fault handler when it decodes a `SwapPte` at the
/// faulting address. Allocates a fresh frame, reads the page back from
/// the backend, installs a present PTE pointing at the new frame,
/// frees the swap slot, and uncharges the cgroup swap counter.
///
/// `flags` are the PT flags to (re)install (WRITABLE / USER / NO_EXEC
/// as the region demands); the caller reconstructs them from the VMA.
/// On success the faulting instruction can be resumed — the byte
/// contents match what was paged out.
///
/// If `readahead` is true, the neighbouring slots of the batch are
/// *not* automatically mapped (that needs the neighbours' VAs, which
/// live in other PTEs) but the backend's `read_batch` warm-up is a
/// future hook; v1 faults exactly the touched page.
#[cfg(target_arch = "x86_64")]
pub fn swap_in_pte(
    pml4_phys: PhysAddr,
    virt: crate::VirtAddr,
    flags: crate::paging::PtFlags,
) -> Result<PhysAddr, SwapError> {
    use crate::paging::{map_4kb, PtFlags};

    // Read the current leaf PTE to recover the swap slot.
    let raw = read_leaf_pte(pml4_phys, virt).ok_or(SwapError::SlotNotFound)?;
    let entry = SwapPte::decode(raw).ok_or(SwapError::SlotNotFound)?;
    let slot = SwapSlot(entry.offset);

    // Allocate a fresh frame for the restored page.
    let frame = crate::frame::alloc_frame().map_err(|_| SwapError::MapFailed)?;
    let phys = frame.start_address();

    // Read the page back from the backend into the fresh frame.
    {
        let dev = SWAP.lock();
        let backend = dev.backend.as_ref().ok_or(SwapError::SlotNotFound)?;
        // SAFETY: `phys` is a freshly-allocated, exclusively-owned 4 KiB
        // frame; `kernel_mut_ptr` yields a mapping valid for a 4 KiB
        // write. We cast to a fixed-size array for the backend buffer.
        let dst = phys.kernel_mut_ptr::<[u8; ZPAGE_SIZE]>();
        // SAFETY: `dst` is derived from a freshly-allocated, exclusively-
        // owned 4 KiB frame via `kernel_mut_ptr`; it is non-null, aligned
        // for `[u8; ZPAGE_SIZE]`, and valid for the write the backend does.
        let out: &mut [u8; ZPAGE_SIZE] = unsafe { &mut *dst };
        if let Err(e) = backend.read(slot, out) {
            drop(dev);
            crate::frame::free_frame(frame);
            return Err(e);
        }
    }

    // The swap PTE is non-present, so the leaf slot currently holds the
    // encoded entry — `map_4kb` refuses to overwrite a *present* PTE
    // but our entry is non-present, so we must clear it first. Write an
    // empty PTE, then map the fresh frame.
    // SAFETY: caller-owned AS root; clears the non-present swap entry.
    unsafe {
        write_swap_pte(pml4_phys, virt, 0).map_err(|_| SwapError::MapFailed)?;
    }
    // SAFETY: caller-owned AS root; the leaf is now empty so map_4kb
    // installs a fresh present mapping.
    if unsafe { map_4kb(pml4_phys, virt, phys, flags | PtFlags::PRESENT) }.is_err() {
        crate::frame::free_frame(frame);
        return Err(SwapError::MapFailed);
    }

    // Release the swap slot + backend copy, uncharge, bump counters.
    {
        let mut dev = SWAP.lock();
        if let Some(backend) = dev.backend.as_ref() {
            backend.discard(slot);
        }
        dev.slots.free_slot(slot.raw());
        dev.resident = dev.resident.saturating_sub(1);
        dev.pages_in += 1;
    }
    swap_uncharge(1);
    Ok(phys)
}

/// Drop a swapped-out page's backing without faulting it in. Called
/// when a mapping carrying a swap PTE is torn down (munmap / process
/// exit): the owner has already cleared/abandoned the PTE, so we only
/// release the slot + backend copy + cgroup charge.
pub fn swap_discard(entry: SwapPte) {
    let slot = SwapSlot(entry.offset);
    let mut dev = SWAP.lock();
    if let Some(backend) = dev.backend.as_ref() {
        backend.discard(slot);
    }
    dev.slots.free_slot(slot.raw());
    dev.resident = dev.resident.saturating_sub(1);
    drop(dev);
    swap_uncharge(1);
}

// ── Leaf-PTE helpers (x86_64) ──────────────────────────────────────
//
// The paging module's `map_4kb`/`unmap_4kb`/`translate` operate on
// *present* mappings. Swap needs to read and write the *non-present*
// leaf PTE directly (to install/clear a swap entry without the CPU
// interpreting it as a mapping). These helpers walk to the existing
// leaf slot and read/write its raw u64. They never allocate
// intermediate tables — a swap PTE only ever replaces a leaf that was
// present (so its whole table chain already exists) or is read back on
// fault (same chain).

#[cfg(target_arch = "x86_64")]
fn walk_to_leaf(pml4_phys: PhysAddr, virt: crate::VirtAddr) -> Option<*mut u64> {
    use crate::paging::{PtFlags, WalkIndices};
    let idx = WalkIndices::from_virt(virt);
    // SAFETY: `pml4_phys` is an identity-reachable AS root (caller
    // contract); each level pointer is derived from a present entry's
    // frame address, which is likewise identity-mapped.
    unsafe {
        let pml4 = &*pml4_phys.as_ptr::<crate::paging::PageTable>();
        let e = pml4.entries[idx.pml4];
        if !e.is_present() {
            return None;
        }
        let pdpt = &*e.addr().as_ptr::<crate::paging::PageTable>();
        let e = pdpt.entries[idx.pdpt];
        if !e.is_present() || e.flags().contains(PtFlags::HUGE_PAGE) {
            return None;
        }
        let pd = &*e.addr().as_ptr::<crate::paging::PageTable>();
        let e = pd.entries[idx.pd];
        if !e.is_present() || e.flags().contains(PtFlags::HUGE_PAGE) {
            return None;
        }
        let pt_phys = e.addr();
        // The leaf slot's address within the PT page.
        let leaf = (pt_phys.raw() + (idx.pt as u64) * 8) as *mut u64;
        Some(leaf)
    }
}

/// Read the raw leaf PTE value at `virt`, or `None` if any intermediate
/// level is missing (so there is no leaf slot).
#[cfg(target_arch = "x86_64")]
fn read_leaf_pte(pml4_phys: PhysAddr, virt: crate::VirtAddr) -> Option<u64> {
    let leaf = walk_to_leaf(pml4_phys, virt)?;
    // SAFETY: `walk_to_leaf` returns a pointer into a live, identity-
    // mapped PT page, aligned for a `u64` read.
    Some(unsafe { core::ptr::read_volatile(leaf) })
}

/// Write `raw` into the leaf PTE slot at `virt`. `raw` must be a
/// non-present value (a swap entry or 0) — writing a present PTE this
/// way would bypass `map_4kb`'s INVLPG. Fails if the leaf chain is
/// absent.
///
/// # Safety
/// `pml4_phys` must be a caller-owned, identity-reachable AS root, and
/// no other CPU may be mutating this leaf concurrently.
#[cfg(target_arch = "x86_64")]
unsafe fn write_swap_pte(
    pml4_phys: PhysAddr,
    virt: crate::VirtAddr,
    raw: u64,
) -> Result<(), SwapError> {
    debug_assert_eq!(raw & PTE_PRESENT, 0, "swap PTE must be non-present");
    let leaf = walk_to_leaf(pml4_phys, virt).ok_or(SwapError::MapFailed)?;
    // SAFETY: per the function contract — live, identity-mapped, u64-
    // aligned leaf slot with no concurrent mutation.
    unsafe {
        core::ptr::write_volatile(leaf, raw);
    }
    Ok(())
}

// Test-only: reset all global swap state so each test starts clean.
// Not `#[cfg(test)]` — the kernel-test suite compiles the tests below
// into the boot image (they register into the `narf.tests` ELF
// section), so this reset helper must be present in that build too.
// Prefixed `__` + `#[doc(hidden)]` to signal "internal / test-only".
#[doc(hidden)]
pub fn __reset_for_test() {
    let mut dev = SWAP.lock();
    *dev = SwapDevice::new();
    drop(dev);
    set_swap_batch_pages(SWAP_BATCH_PAGES_DEFAULT);
}

// In-kernel smoke tests. Registered unconditionally (matching
// `memory/src/tests.rs`) so `cargo xtask test` runs them from the boot
// image; a plain `cargo test` on the host also picks them up.
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── 1. swap-entry PTE encode/decode round-trip ───────────────

    fn smoke_swap_pte_roundtrip() -> TestResult {
        // A spread of (type, offset) pairs including the field edges.
        let cases = [
            (0u8, 0u64),
            (1, 1),
            (7, 0x1234),
            (31, SwapPte::MAX_OFFSET),
            (0, SwapPte::MAX_OFFSET),
            (31, 0),
        ];
        for (ty, off) in cases {
            let e = SwapPte {
                swap_type: ty,
                offset: off,
            };
            let raw = e.encode();
            // Must be non-present (PRESENT bit clear).
            if raw & 1 != 0 {
                return TestResult::Fail("encoded swap PTE has PRESENT set");
            }
            // Must be recognised as a swap PTE.
            if !SwapPte::is_swap_pte(raw) {
                return TestResult::Fail("is_swap_pte false on an encoded swap entry");
            }
            match SwapPte::decode(raw) {
                Some(d) if d == e => {}
                Some(_) => return TestResult::Fail("decode returned wrong fields"),
                None => return TestResult::Fail("decode returned None on a swap entry"),
            }
        }
        // An all-zero PTE is NOT a swap entry (demand-zero / unmapped).
        if SwapPte::decode(0).is_some() {
            return TestResult::Fail("empty PTE decoded as a swap entry");
        }
        if SwapPte::is_swap_pte(0) {
            return TestResult::Fail("is_swap_pte true on empty PTE");
        }
        // A present PTE is NOT a swap entry, even with marker bits set.
        let present = 0x1234_0000u64 | 1 /*PRESENT*/ | SWAP_MARKER;
        if SwapPte::decode(present).is_some() {
            return TestResult::Fail("present PTE decoded as swap entry");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/swap", smoke_swap_pte_roundtrip);

    // ── 2. slot-run batch allocation / free ──────────────────────

    fn smoke_swap_slot_run_alloc_free() -> TestResult {
        let mut a = SlotAllocator::new();
        // First run of 4 → [0,4).
        let b0 = match a.alloc_run(4) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("alloc_run(4) failed"),
        };
        if b0 != 0 {
            return TestResult::Fail("first run didn't start at 0");
        }
        // Second run of 3 → [4,7).
        let b1 = match a.alloc_run(3) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("alloc_run(3) failed"),
        };
        if b1 != 4 {
            return TestResult::Fail("second run didn't start at high-water");
        }
        let (hw, free) = a.stats();
        if hw != 7 || free != 0 {
            return TestResult::Fail("high-water/free wrong after two runs");
        }
        // Free the whole first run → 4 free slots [0,4).
        for s in 0..4 {
            a.free_slot(s);
        }
        if a.stats().1 != 4 {
            return TestResult::Fail("free list didn't gain 4 slots");
        }
        // A run of 4 must reuse the freed contiguous run, not bump HW.
        let b2 = match a.alloc_run(4) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("reuse alloc_run(4) failed"),
        };
        if b2 != 0 {
            return TestResult::Fail("reused run didn't start at freed base 0");
        }
        if a.stats().0 != 7 {
            return TestResult::Fail("high-water grew despite a reusable run");
        }
        if a.stats().1 != 0 {
            return TestResult::Fail("freed run not consumed by reuse");
        }
        // A run larger than any contiguous free block bumps HW.
        for s in 0..4 {
            a.free_slot(s);
        }
        let b3 = match a.alloc_run(5) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("alloc_run(5) failed"),
        };
        // Only 4 contiguous free (0..4); 5 doesn't fit → bump to HW=7.
        if b3 != 7 {
            return TestResult::Fail("oversized run didn't bump past free block");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/swap", smoke_swap_slot_run_alloc_free);

    // ── 3. ZramBackend batched write + read round-trip ───────────

    fn smoke_zram_backend_batch_roundtrip() -> TestResult {
        let backend = ZramBackend::new();

        // Allocate a few frames, fill each with a distinct pattern,
        // write the whole run in one batch, then read each back and
        // compare. This is the backend-level analogue of the full
        // end-to-end test but without page tables.
        const N: usize = 4;
        let mut frames = alloc_crate::vec::Vec::with_capacity(N);
        for _ in 0..N {
            match crate::alloc_frame() {
                Ok(f) => frames.push(f),
                Err(_) => {
                    for f in frames.drain(..) {
                        crate::free_frame(f);
                    }
                    return TestResult::Skip("frame allocator not initialised");
                }
            }
        }
        // Fill each frame with byte = (index+1) repeated.
        for (i, f) in frames.iter().enumerate() {
            let p = f.start_address().kernel_mut_ptr::<u8>();
            // SAFETY: fresh exclusive frame, 4 KiB writable.
            unsafe {
                core::ptr::write_bytes(p, (i as u8) + 1, ZPAGE_SIZE);
            }
        }
        let slots: alloc_crate::vec::Vec<SwapSlot> = (0..N as u64).map(SwapSlot).collect();
        let phys: alloc_crate::vec::Vec<PhysAddr> =
            frames.iter().map(|f| f.start_address()).collect();

        let result = (|| {
            if backend.write_batch(&slots, &phys).is_err() {
                return TestResult::Fail("write_batch failed");
            }
            // Read each slot back and verify contents.
            for (i, slot) in slots.iter().enumerate() {
                let mut out = [0u8; ZPAGE_SIZE];
                if backend.read(*slot, &mut out).is_err() {
                    return TestResult::Fail("read failed");
                }
                let want = (i as u8) + 1;
                if out.iter().any(|&b| b != want) {
                    return TestResult::Fail("read-back bytes don't match written page");
                }
            }
            // read_batch (default impl) should agree.
            let mut outs = alloc_crate::vec![[0u8; ZPAGE_SIZE]; N];
            if backend.read_batch(&slots, &mut outs).is_err() {
                return TestResult::Fail("read_batch failed");
            }
            for (i, o) in outs.iter().enumerate() {
                if o.iter().any(|&b| b != (i as u8) + 1) {
                    return TestResult::Fail("read_batch bytes don't match");
                }
            }
            // Discard frees the backing; a subsequent read must fail.
            backend.discard(slots[0]);
            let mut out = [0u8; ZPAGE_SIZE];
            if backend.read(slots[0], &mut out).is_ok() {
                return TestResult::Fail("read succeeded after discard");
            }
            TestResult::Pass
        })();

        for f in frames.drain(..) {
            crate::free_frame(f);
        }
        result
    }
    kernel_test_in!("memory/swap", smoke_zram_backend_batch_roundtrip);

    // ── 4. End-to-end: map → write → batched swap-out → fault-in ──

    #[cfg(target_arch = "x86_64")]
    fn smoke_swap_end_to_end_batch() -> TestResult {
        use crate::paging::{map_4kb, translate, PageTable, PtFlags};
        use crate::{alloc_frame, free_frame, VirtAddr};

        __reset_for_test();
        install_backend(ZramBackend::new());

        // Build an isolated PML4 for the test (as the paging smokes do).
        let pml4 = match alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => return TestResult::Skip("frame allocator not initialised"),
        };
        PageTable::zero_at(pml4.as_mut_ptr::<PageTable>());

        // Map N pages at distinct VAs, each frame filled with a known
        // byte pattern derived from its index. Use VAs in the empty
        // user-reserved range (PML4[2], 1 TiB) so map_4kb builds real
        // 4 KiB leaves.
        const N: usize = 5;
        let base_va = 0x0000_0100_0000_0000u64; // 1 TiB
        let flags = PtFlags::WRITABLE | PtFlags::USER;

        let mut victims = alloc_crate::vec::Vec::with_capacity(N);
        let mut patterns = [0u8; N];
        for (i, pat_slot) in patterns.iter_mut().enumerate() {
            let frame = match alloc_frame() {
                Ok(f) => f,
                Err(_) => return TestResult::Fail("alloc_frame (page) failed"),
            };
            let phys = frame.start_address();
            let va = VirtAddr::new(base_va + (i as u64) * 0x1000);
            // SAFETY: isolated PML4 owned by this test.
            if unsafe { map_4kb(pml4, va, phys, flags) }.is_err() {
                free_frame(frame);
                return TestResult::Fail("map_4kb failed");
            }
            // Write a distinguishable pattern into the mapped page via
            // the kernel window (the test AS isn't the active CR3).
            let pat = 0x40u8 + i as u8;
            *pat_slot = pat;
            let p = phys.kernel_mut_ptr::<u8>();
            // SAFETY: fresh exclusive frame, 4 KiB writable.
            unsafe {
                core::ptr::write_bytes(p, pat, ZPAGE_SIZE);
            }
            victims.push(SwapVictim {
                pml4_phys: pml4,
                virt: va,
            });
        }

        // ── Batched swap-out of the whole run. ──
        let out = match swap_out_batch(&victims) {
            Ok(n) => n,
            Err(_) => return TestResult::Fail("swap_out_batch returned Err"),
        };
        if out != N {
            return TestResult::Fail("swap_out_batch didn't page out every victim");
        }

        // Assert every PTE is now a non-present swap entry and the
        // frames are gone (translate returns None).
        for v in &victims {
            // SAFETY: test-owned root.
            if unsafe { translate(pml4, v.virt) }.is_some() {
                return TestResult::Fail("PTE still present after swap-out");
            }
            let raw = match read_leaf_pte(pml4, v.virt) {
                Some(r) => r,
                None => return TestResult::Fail("leaf PTE vanished after swap-out"),
            };
            if !SwapPte::is_swap_pte(raw) {
                return TestResult::Fail("leaf PTE is not a swap entry after swap-out");
            }
        }

        // Stats should reflect N resident.
        if swap_stats().resident != N as u64 {
            return TestResult::Fail("swap_stats.resident wrong after swap-out");
        }

        // ── Fault each page back in and verify the bytes survived. ──
        for (i, v) in victims.iter().enumerate() {
            let phys = match swap_in_pte(pml4, v.virt, flags) {
                Ok(p) => p,
                Err(_) => return TestResult::Fail("swap_in_pte returned Err"),
            };
            // PTE must be present again and translate to the new frame.
            // SAFETY: test-owned root.
            match unsafe { translate(pml4, v.virt) } {
                Some(t) if t == phys => {}
                _ => return TestResult::Fail("translate wrong after swap-in"),
            }
            // Every byte must equal the original pattern.
            let p = phys.kernel_ptr::<u8>();
            // SAFETY: freshly restored, exclusively-owned frame.
            let ok = unsafe {
                (0..ZPAGE_SIZE).all(|k| core::ptr::read_volatile(p.add(k)) == patterns[i])
            };
            if !ok {
                return TestResult::Fail("faulted-in page bytes don't match original");
            }
            // Release the restored frame (test cleanup).
            free_frame(crate::frame::PhysFrame::new(phys));
        }

        if swap_stats().resident != 0 {
            return TestResult::Fail("swap_stats.resident not drained after swap-in");
        }
        if swap_stats().pages_in != N as u64 || swap_stats().pages_out != N as u64 {
            return TestResult::Fail("pages_in / pages_out counters wrong");
        }

        __reset_for_test();
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("memory/swap", smoke_swap_end_to_end_batch);

    // ── 5. Batch knob clamps + round-trips ───────────────────────

    fn smoke_swap_batch_knob() -> TestResult {
        let saved = swap_batch_pages();
        if set_swap_batch_pages(8) != 8 {
            return TestResult::Fail("set_swap_batch_pages(8) didn't stick");
        }
        if swap_batch_pages() != 8 {
            return TestResult::Fail("swap_batch_pages didn't read back 8");
        }
        // Clamp to [1, MAX].
        if set_swap_batch_pages(0) != 1 {
            return TestResult::Fail("0 didn't clamp to 1");
        }
        if set_swap_batch_pages(usize::MAX) != SWAP_BATCH_PAGES_MAX {
            return TestResult::Fail("huge didn't clamp to MAX");
        }
        set_swap_batch_pages(saved);
        TestResult::Pass
    }
    kernel_test_in!("memory/swap", smoke_swap_batch_knob);
}
