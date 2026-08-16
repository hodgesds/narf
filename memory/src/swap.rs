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
//! (one submission for the batch, not N). Fault-in is symmetric:
//! `swap_in_batch` restores a same-address-space run with one backend read
//! and one page-table transaction; `swap_in_pte` is only its compatibility
//! wrapper for a single fault.
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
//! "never mapped" (all-zero PTE). The AddressSpace fault path gathers the
//! fault plus consecutive swapped leaves and routes the vector through
//! `swap_in_batch`; `swap_in_pte` remains the one-page compatibility wrapper.
//! See `SwapPte` for the exact bit layout and its round-trip unit test.
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

use alloc_crate::sync::Arc;
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
    /// A batch mixed address-space roots, repeated a virtual address, exceeded
    /// the configured maximum, or otherwise could not be committed atomically.
    InvalidBatch,
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
/// through one call. Scalar `read`/`discard` are compatibility primitives;
/// `read_batch_into`/`discard_batch` let zram or block backends lock/submit
/// once for the vector.
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

    /// Read a slot run directly into a scatter list of physical frames. This
    /// is the primary page-in interface: a block backend can issue one vectored
    /// request and zram can take its index lock once for the complete batch.
    /// The default preserves compatibility for simple backends while keeping
    /// publication transactional: callers do not install any PTE until this
    /// method has returned `Ok(())` for the complete run.
    fn read_batch_into(&self, slots: &[SwapSlot], pages: &[PhysAddr]) -> Result<(), SwapError> {
        if slots.len() != pages.len() {
            return Err(SwapError::InvalidBatch);
        }
        for (slot, phys) in slots.iter().zip(pages.iter()) {
            // SAFETY: the batch caller supplies fresh, exclusively-owned
            // frames and does not publish them until the complete read wins.
            let out = unsafe { &mut *phys.kernel_mut_ptr::<[u8; ZPAGE_SIZE]>() };
            self.read(*slot, out)?;
        }
        Ok(())
    }

    /// Release a slot's backing (the page was faulted in or the mapping
    /// was torn down). Idempotent on already-freed slots.
    fn discard(&self, slot: SwapSlot);

    /// Release a complete slot run. Backends should override this when a
    /// single lock acquisition or one storage discard command can cover it.
    fn discard_batch(&self, slots: &[SwapSlot]) {
        for slot in slots {
            self.discard(*slot);
        }
    }
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

    fn read_batch_into(&self, slots: &[SwapSlot], pages: &[PhysAddr]) -> Result<(), SwapError> {
        if slots.len() != pages.len() {
            return Err(SwapError::InvalidBatch);
        }
        let inner = self.inner.lock();
        for (slot, phys) in slots.iter().zip(pages.iter()) {
            let handle = inner
                .handles
                .get(slot.raw() as usize)
                .copied()
                .flatten()
                .ok_or(SwapError::SlotNotFound)?;
            // SAFETY: the swap-in batch owns each fresh destination frame
            // exclusively until every backend read succeeds.
            let out = unsafe { &mut *phys.kernel_mut_ptr::<[u8; ZPAGE_SIZE]>() };
            inner
                .pool
                .load(handle, out)
                .map_err(|_| SwapError::SlotNotFound)?;
        }
        Ok(())
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

    fn discard_batch(&self, slots: &[SwapSlot]) {
        let mut inner = self.inner.lock();
        for slot in slots {
            if let Some(slot_mut) = inner.handles.get_mut(slot.raw() as usize) {
                if let Some(handle) = slot_mut.take() {
                    inner.pool.free(handle);
                }
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
    backend: Option<Arc<dyn SwapBackend>>,
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
    dev.backend = Some(Arc::new(backend));
}

/// Install the default compressed-RAM backend if none is set yet.
/// Called from the pageout path so callers never hit a missing
/// backend. Idempotent.
pub fn install_default_if_unset() {
    let mut dev = SWAP.lock();
    if dev.backend.is_none() {
        dev.backend = Some(Arc::new(ZramBackend::new()));
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
// / `swap_in_batch` / `swap_discard_batch`). aarch64 swap-PTE integration is
// not implemented, so only discard accounting is architecture-independent.
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

/// One requested page in a first-class batched page-in operation.
///
/// Every entry in a call to [`swap_in_batch`] must name the same page-table
/// root. Virtual addresses may be non-contiguous, but must be unique. The
/// returned physical-frame vector preserves request order.
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SwapInRequest {
    /// Physical base of the owning address space's PML4.
    pub pml4_phys: PhysAddr,
    /// Virtual address whose non-present leaf contains a [`SwapPte`].
    pub virt: crate::VirtAddr,
    /// Permissions to install on the restored present leaf.
    pub flags: crate::paging::PtFlags,
}

/// Progress from executing a PSS-sized reclaim plan.
///
/// A plan may span address spaces, so it is split into same-root submissions
/// while retaining range-level batching inside each submission. If a later
/// submission fails, earlier ones remain validly swapped out and `error`
/// reports why execution stopped; callers never lose partial-progress data.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SwapBatchReport {
    /// Pages present in the policy plan.
    pub planned_pages: usize,
    /// Pages handed to the low-level swap transaction before it stopped.
    pub attempted_pages: usize,
    /// Pages whose PTE/backing transition completed.
    pub swapped_pages: usize,
    /// Backend/PTE batch submissions issued.
    pub submissions: usize,
    /// First terminal error, if execution stopped early.
    pub error: Option<SwapError>,
}

#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
struct SwapOutCommit {
    virt: crate::VirtAddr,
    expected_phys: PhysAddr,
    raw: u64,
}

#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
struct SwapInCommit {
    virt: crate::VirtAddr,
    expected_raw: u64,
    phys: PhysAddr,
    flags: crate::paging::PtFlags,
}

/// Atomically replace a same-root set of present 4 KiB leaves with
/// non-present swap entries under one page-table lock acquisition.
///
/// The first pass validates every expected physical frame; only then does the
/// second pass publish any swap entry. TLB invalidation is deliberately left
/// to the caller, which performs one full/range batch before freeing backing.
#[cfg(target_arch = "x86_64")]
unsafe fn commit_swap_out_batch(
    pml4_phys: PhysAddr,
    entries: &[SwapOutCommit],
) -> Result<(), SwapError> {
    use crate::paging::PageTableEntry;

    let _guard = crate::paging::pt_lock_for(pml4_phys).lock();
    for entry in entries {
        let leaf = walk_to_leaf(pml4_phys, entry.virt).ok_or(SwapError::MapFailed)?;
        // SAFETY: the root lock is held and walk_to_leaf returned a live slot.
        let current = PageTableEntry::from_raw(unsafe { core::ptr::read_volatile(leaf) });
        if !current.is_present() || current.addr() != entry.expected_phys {
            return Err(SwapError::MapFailed);
        }
    }
    for entry in entries {
        let leaf = walk_to_leaf(pml4_phys, entry.virt).ok_or(SwapError::MapFailed)?;
        // SAFETY: the validation pass proved the leaf exists and the root lock
        // prevents replacement between validation and this commit pass.
        unsafe { core::ptr::write_volatile(leaf, entry.raw) };
    }
    Ok(())
}

/// Atomically replace a same-root set of expected swap leaves with restored
/// present mappings under one page-table lock acquisition.
#[cfg(target_arch = "x86_64")]
unsafe fn commit_swap_in_batch(
    pml4_phys: PhysAddr,
    entries: &[SwapInCommit],
) -> Result<(), SwapError> {
    use crate::paging::{PageTableEntry, PtFlags};

    let _guard = crate::paging::pt_lock_for(pml4_phys).lock();
    for entry in entries {
        let leaf = walk_to_leaf(pml4_phys, entry.virt).ok_or(SwapError::MapFailed)?;
        // SAFETY: the root lock is held and walk_to_leaf returned a live slot.
        let current = unsafe { core::ptr::read_volatile(leaf) };
        if current != entry.expected_raw || SwapPte::decode(current).is_none() {
            return Err(SwapError::MapFailed);
        }
    }
    for entry in entries {
        let leaf = walk_to_leaf(pml4_phys, entry.virt).ok_or(SwapError::MapFailed)?;
        let present = PageTableEntry::new(entry.phys, entry.flags | PtFlags::PRESENT).raw();
        // SAFETY: validation proved the expected swap entry is still present
        // and the root lock prevents a concurrent fault from winning midway.
        unsafe { core::ptr::write_volatile(leaf, present) };
    }
    // A not-present -> present transition needs no remote shootdown, but this
    // CPU may retain negative paging-structure-cache state. Retire the batch
    // locally with one full non-global flush for a large run, or INVLPG each
    // requested VA for a small one.
    const LOCAL_FULL_FLUSH_THRESHOLD: usize = 32;
    if entries.len() >= LOCAL_FULL_FLUSH_THRESHOLD {
        // SAFETY: CPL=0 and every leaf above is already committed.
        unsafe { crate::paging::flush_user_tlb_local() };
    } else {
        for entry in entries {
            // SAFETY: every request VA was validated by walk_to_leaf.
            unsafe { crate::paging::invlpg(entry.virt) };
        }
    }
    Ok(())
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
///   5. Replaces every victim PTE with a non-present swap entry in one
///      same-root page-table transaction.
///   6. Issues one TLB invalidation for the complete batch.
///   7. Frees the now-evicted physical frames back to the buddy.
///
/// Returns the number of pages actually paged out (0 if the batch was
/// empty or every victim was already unmapped). On a mid-batch backend
/// failure the whole run is rolled back and `Err` is returned with no
/// frames freed and no PTEs disturbed.
///
/// The caller keeps the returned `SwapSlot` run out of band only if it
/// wants explicit readahead; the swap entries themselves live in the
/// PTEs, so a plain fault-in needs no side-table.
///
/// # Safety
///
/// The caller must atomically remove each resolved frame from its owning
/// metadata before it can be reclaimed again. In particular, calling this
/// directly on an [`crate::AddressSpace`] region without clearing its
/// `Region::phys` slots would make address-space teardown free the frames a
/// second time. Live reclaim must use the ownership-integrated AddressSpace
/// path; this primitive exists for that transaction and isolated page-table
/// tests.
#[cfg(target_arch = "x86_64")]
pub unsafe fn swap_out_batch(victims: &[SwapVictim]) -> Result<usize, SwapError> {
    // SAFETY: forwarded from the public primitive's ownership contract. The
    // no-op publisher is correct only because that contract requires the
    // caller to have detached ownership metadata itself.
    unsafe { swap_out_batch_owned(victims, |_| {}) }
}

/// Ownership-integrated implementation used by `AddressSpace` reclaim.
/// `publish` runs after every swap PTE is committed but before the one TLB
/// retirement and before any victim frame is freed.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn swap_out_batch_owned(
    victims: &[SwapVictim],
    publish: impl FnOnce(&[(SwapVictim, PhysAddr)]),
) -> Result<usize, SwapError> {
    use crate::paging::translate;

    if victims.is_empty() {
        return Ok(0);
    }
    install_default_if_unset();

    // Cap the batch at the knob so an oversized caller list still
    // writes in bounded chunks. (We take the first `batch` here; the
    // caller loops if it has more.)
    let batch = victims.len().min(swap_batch_pages());
    let victims = &victims[..batch];
    let root = victims[0].pml4_phys;
    if victims.iter().any(|victim| {
        victim.pml4_phys != root || victim.virt.as_u64() & (ZPAGE_SIZE as u64 - 1) != 0
    }) {
        return Err(SwapError::InvalidBatch);
    }

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
    resolved.sort_unstable_by_key(|(victim, _)| victim.virt.as_u64());
    if resolved
        .windows(2)
        .any(|pair| pair[0].0.virt == pair[1].0.virt)
    {
        return Err(SwapError::InvalidBatch);
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
        let backend = SWAP
            .lock()
            .backend
            .as_ref()
            .expect("backend installed above")
            .clone();
        if let Err(e) = backend.write_batch(&slot_run, &frames) {
            // Roll back: uncharge + return the slots. No PTE touched yet.
            swap_uncharge(n as u64);
            let mut dev = SWAP.lock();
            for k in 0..n as u64 {
                dev.slots.free_slot(base + k);
            }
            return Err(e);
        }
    }

    // ── 5. Atomically stamp the complete same-root PTE batch. ──
    let commits: Vec<SwapOutCommit> = resolved
        .iter()
        .enumerate()
        .map(|(index, (victim, phys))| SwapOutCommit {
            virt: victim.virt,
            expected_phys: *phys,
            raw: SwapPte {
                swap_type,
                offset: base + index as u64,
            }
            .encode(),
        })
        .collect();
    // SAFETY: every commit names the one validated root, unique aligned VAs,
    // and the expected frames resolved immediately above.
    if unsafe { commit_swap_out_batch(root, &commits) }.is_err() {
        let backend = SWAP
            .lock()
            .backend
            .as_ref()
            .expect("backend remains installed")
            .clone();
        backend.discard_batch(&slot_run);
        let mut dev = SWAP.lock();
        for slot in &slot_run {
            dev.slots.free_slot(slot.raw());
        }
        drop(dev);
        swap_uncharge(n as u64);
        return Err(SwapError::MapFailed);
    }

    // Publish VMA/backing ownership while every old frame is still allocated.
    // The AddressSpace transition table blocks concurrent teardown and faults
    // until this callback changes Evicting -> Swapped.
    publish(&resolved);

    // ONE local + peer invalidation for the entire batch, before any old
    // frame can return to the allocator. This replaces the former one
    // broadcast-and-ack round trip per page.
    // SAFETY: every present leaf in the batch was replaced above.
    unsafe { crate::paging::flush_user_tlb_all_cpus() };

    // ── 6. Only after the batch flush, free all evicted frames. ──
    for (_, phys) in &resolved {
        crate::frame::free_frame(crate::frame::PhysFrame::new(*phys));
    }
    let done = resolved.len();

    {
        let mut dev = SWAP.lock();
        dev.resident += done as u64;
        dev.pages_out += done as u64;
    }
    Ok(done)
}

/// Execute the selected virtual runs of a reclaim plan as bounded swap
/// submissions, preserving explicit partial progress.
///
/// Each contiguous plan range is chunked by [`swap_batch_pages`], so slot
/// allocation, backend I/O, page-table replacement, and TLB retirement stay
/// first-class batch operations even when the watermark target is large.
///
/// # Safety
///
/// This has the same backing-ownership precondition as [`swap_out_batch`] for
/// every selected page. It is a low-level bridge for the AddressSpace reclaim
/// transaction, not a safe way to evict arbitrary live VMAs.
#[cfg(target_arch = "x86_64")]
pub unsafe fn swap_out_plan(plan: &crate::reclaim::ReclaimBatchPlan) -> SwapBatchReport {
    let mut report = SwapBatchReport {
        planned_pages: plan
            .ranges
            .iter()
            .fold(0usize, |sum, range| sum.saturating_add(range.pages)),
        ..SwapBatchReport::default()
    };
    let batch_pages = swap_batch_pages();
    for range in &plan.ranges {
        let mut offset = 0usize;
        while offset < range.pages {
            let pages = (range.pages - offset).min(batch_pages);
            let mut victims = Vec::with_capacity(pages);
            for page in 0..pages {
                let page_index = match offset.checked_add(page) {
                    Some(index) => index,
                    None => {
                        report.error = Some(SwapError::InvalidBatch);
                        return report;
                    }
                };
                let byte_offset = match (page_index as u64).checked_mul(ZPAGE_SIZE as u64) {
                    Some(offset) => offset,
                    None => {
                        report.error = Some(SwapError::InvalidBatch);
                        return report;
                    }
                };
                let virt = match range.base.as_u64().checked_add(byte_offset) {
                    Some(virt) => crate::VirtAddr::new(virt),
                    None => {
                        report.error = Some(SwapError::InvalidBatch);
                        return report;
                    }
                };
                victims.push(SwapVictim {
                    pml4_phys: range.address_space_root,
                    virt,
                });
            }
            report.attempted_pages = report.attempted_pages.saturating_add(pages);
            report.submissions = report.submissions.saturating_add(1);
            // SAFETY: inherited from this function's caller for the plan's
            // complete selected backing set.
            match unsafe { swap_out_batch(&victims) } {
                Ok(done) => report.swapped_pages = report.swapped_pages.saturating_add(done),
                Err(error) => {
                    report.error = Some(error);
                    return report;
                }
            }
            offset += pages;
        }
    }
    report
}

/// Fault a batch of swapped-out pages back in with one backend operation and
/// one page-table critical section.
///
/// Requests must name one address-space root and unique, page-aligned virtual
/// addresses. The function validates every swap PTE, allocates all destination
/// frames, performs one [`SwapBackend::read_batch_into`], and only then
/// publishes every present PTE atomically with respect to same-root mutation.
/// If validation, allocation, or I/O fails, no PTE or swap slot is changed.
/// Returned physical addresses preserve request order.
#[cfg(target_arch = "x86_64")]
pub fn swap_in_batch(requests: &[SwapInRequest]) -> Result<Vec<PhysAddr>, SwapError> {
    swap_in_batch_owned(requests, |_| {})
}

/// Ownership-integrated implementation used by the AddressSpace fault path.
/// `publish` runs after present PTEs are committed but before swap slots are
/// discarded, so region backing becomes authoritative before the transaction
/// can complete.
#[cfg(target_arch = "x86_64")]
pub(crate) fn swap_in_batch_owned(
    requests: &[SwapInRequest],
    publish: impl FnOnce(&[PhysAddr]),
) -> Result<Vec<PhysAddr>, SwapError> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    if requests.len() > swap_batch_pages() {
        return Err(SwapError::InvalidBatch);
    }
    let root = requests[0].pml4_phys;
    for (index, request) in requests.iter().enumerate() {
        if request.pml4_phys != root || request.virt.as_u64() & (ZPAGE_SIZE as u64 - 1) != 0 {
            return Err(SwapError::InvalidBatch);
        }
        if requests[..index]
            .iter()
            .any(|prior| prior.virt == request.virt)
        {
            return Err(SwapError::InvalidBatch);
        }
    }

    // Snapshot all expected swap entries under the same root mutation lock.
    // A later commit pass revalidates the raw values, so a competing fault can
    // win safely while backend I/O runs without any page-table lock held.
    let expected: Vec<(u64, SwapSlot)> = {
        let _guard = crate::paging::pt_lock_for(root).lock();
        let mut entries = Vec::with_capacity(requests.len());
        for request in requests {
            let raw = read_leaf_pte(root, request.virt).ok_or(SwapError::SlotNotFound)?;
            let entry = SwapPte::decode(raw).ok_or(SwapError::SlotNotFound)?;
            entries.push((raw, SwapSlot(entry.offset)));
        }
        entries
    };
    let slots: Vec<SwapSlot> = expected.iter().map(|(_, slot)| *slot).collect();

    // Duplicate slot aliases would let a malformed batch discard the same
    // backing twice. Legitimate swap PTEs are one-slot-per-leaf.
    for (index, slot) in slots.iter().enumerate() {
        if slots[..index].contains(slot) {
            return Err(SwapError::InvalidBatch);
        }
    }

    let mut frames = Vec::with_capacity(requests.len());
    for _ in requests {
        match crate::frame::alloc_frame() {
            Ok(frame) => frames.push(frame),
            Err(_) => {
                for frame in frames {
                    crate::frame::free_frame(frame);
                }
                return Err(SwapError::MapFailed);
            }
        }
    }
    let phys: Vec<PhysAddr> = frames.iter().map(|frame| frame.start_address()).collect();
    let backend = SWAP
        .lock()
        .backend
        .as_ref()
        .ok_or(SwapError::SlotNotFound)?
        .clone();
    if let Err(error) = backend.read_batch_into(&slots, &phys) {
        for frame in frames {
            crate::frame::free_frame(frame);
        }
        return Err(error);
    }

    let commits: Vec<SwapInCommit> = requests
        .iter()
        .zip(expected.iter())
        .zip(phys.iter())
        .map(|((request, (raw, _)), phys)| SwapInCommit {
            virt: request.virt,
            expected_raw: *raw,
            phys: *phys,
            flags: request.flags,
        })
        .collect();
    // SAFETY: all requests name the validated root and unique aligned leaves;
    // fresh frames remain exclusively owned until this all-or-nothing commit.
    if unsafe { commit_swap_in_batch(root, &commits) }.is_err() {
        for frame in frames {
            crate::frame::free_frame(frame);
        }
        return Err(SwapError::MapFailed);
    }

    publish(&phys);

    backend.discard_batch(&slots);
    {
        let mut dev = SWAP.lock();
        for slot in &slots {
            dev.slots.free_slot(slot.raw());
        }
        dev.resident = dev.resident.saturating_sub(requests.len() as u64);
        dev.pages_in += requests.len() as u64;
    }
    swap_uncharge(requests.len() as u64);
    Ok(phys)
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
/// AddressSpace faults normally use [`swap_in_batch`] directly to restore the
/// touched leaf plus consecutive swapped leaves. This wrapper intentionally
/// restores exactly one page for compatibility and isolated callers.
#[cfg(target_arch = "x86_64")]
pub fn swap_in_pte(
    pml4_phys: PhysAddr,
    virt: crate::VirtAddr,
    flags: crate::paging::PtFlags,
) -> Result<PhysAddr, SwapError> {
    let restored = swap_in_batch(&[SwapInRequest {
        pml4_phys,
        virt,
        flags,
    }])?;
    restored.first().copied().ok_or(SwapError::MapFailed)
}

/// Drop a swapped-out page's backing without faulting it in. Called
/// when a mapping carrying a swap PTE is torn down (munmap / process
/// exit): the owner has already cleared/abandoned the PTE, so we only
/// release the slot + backend copy + cgroup charge.
pub fn swap_discard(entry: SwapPte) {
    swap_discard_batch(&[entry]);
}

/// Release a vector of swapped-out pages without faulting them in.
///
/// Teardown paths use this after clearing a VMA's swap PTEs. The backend is
/// called once and without the global swap-device lock held; slot/accounting
/// retirement is then committed under one lock acquisition.
pub fn swap_discard_batch(entries: &[SwapPte]) {
    if entries.is_empty() {
        return;
    }
    let mut slots: Vec<SwapSlot> = entries.iter().map(|entry| SwapSlot(entry.offset)).collect();
    slots.sort_unstable_by_key(|slot| slot.raw());
    slots.dedup_by_key(|slot| slot.raw());
    let backend = SWAP.lock().backend.as_ref().cloned();
    if let Some(backend) = backend {
        backend.discard_batch(&slots);
    }
    let mut dev = SWAP.lock();
    for slot in &slots {
        dev.slots.free_slot(slot.raw());
    }
    dev.resident = dev.resident.saturating_sub(slots.len() as u64);
    drop(dev);
    swap_uncharge(slots.len() as u64);
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

/// Atomically validate and clear a same-root vector of swap leaves for VMA
/// teardown, returning the entries whose backend slots must be discarded.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn take_swap_entries(
    pml4_phys: PhysAddr,
    pages: &[crate::VirtAddr],
) -> Result<Vec<SwapPte>, SwapError> {
    let _guard = crate::paging::pt_lock_for(pml4_phys).lock();
    let mut entries = Vec::with_capacity(pages.len());
    for (index, virt) in pages.iter().enumerate() {
        if virt.as_u64() & (ZPAGE_SIZE as u64 - 1) != 0 || pages[..index].contains(virt) {
            return Err(SwapError::InvalidBatch);
        }
        let raw = read_leaf_pte(pml4_phys, *virt).ok_or(SwapError::SlotNotFound)?;
        entries.push(SwapPte::decode(raw).ok_or(SwapError::SlotNotFound)?);
    }
    for virt in pages {
        let leaf = walk_to_leaf(pml4_phys, *virt).ok_or(SwapError::SlotNotFound)?;
        // SAFETY: every leaf was validated under this still-held root lock.
        unsafe { core::ptr::write_volatile(leaf, 0) };
    }
    const LOCAL_FULL_FLUSH_THRESHOLD: usize = 32;
    if pages.len() >= LOCAL_FULL_FLUSH_THRESHOLD {
        // SAFETY: all swap leaves are clear and user PTEs are non-global.
        unsafe { crate::paging::flush_user_tlb_local() };
    } else {
        for virt in pages {
            // SAFETY: aligned validated user leaf.
            unsafe { crate::paging::invlpg(*virt) };
        }
    }
    Ok(entries)
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
        use crate::reclaim::{PlannedReclaimRange, ReclaimBatchPlan, PSS_UNITS_PER_PAGE};
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

        // ── Execute the planner's whole contiguous run. ──
        let plan = ReclaimBatchPlan {
            ranges: alloc_crate::vec![PlannedReclaimRange {
                address_space_root: pml4,
                base: VirtAddr::new(base_va),
                pages: N,
                mapcount: 1,
                estimated_pss_units: N as u64 * PSS_UNITS_PER_PAGE,
                expected_free_pages: N,
            }],
            target_free_pages: N,
            target_pss_units: N as u64 * PSS_UNITS_PER_PAGE,
            selected_pss_units: N as u64 * PSS_UNITS_PER_PAGE,
            expected_free_pages: N,
            scanned_pages: N,
        };
        // SAFETY: this isolated test page table is the sole owner of every
        // frame and has no Region metadata that could free them again.
        let report = unsafe { swap_out_plan(&plan) };
        if report.error.is_some()
            || report.swapped_pages != N
            || report.attempted_pages != N
            || report.submissions != 1
        {
            return TestResult::Fail("swap_out_plan did not complete in one batch");
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

        // ── Fault the whole run back in with one backend/page-table batch. ──
        let requests: Vec<SwapInRequest> = victims
            .iter()
            .map(|victim| SwapInRequest {
                pml4_phys: pml4,
                virt: victim.virt,
                flags,
            })
            .collect();
        let restored = match swap_in_batch(&requests) {
            Ok(pages) if pages.len() == N => pages,
            Ok(_) => return TestResult::Fail("swap_in_batch restored the wrong page count"),
            Err(_) => return TestResult::Fail("swap_in_batch returned Err"),
        };
        for (i, (v, phys)) in victims.iter().zip(restored.iter().copied()).enumerate() {
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
