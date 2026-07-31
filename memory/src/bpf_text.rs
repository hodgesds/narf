//! `bpf_text` — the executable-text allocator for JIT-compiled BPF programs.
//!
//! Spec: `bpf/specification/spec.md` §3.3, §4.1–§4.3, §5.
//!
//! Three things live here, in decreasing order of how badly they can hurt:
//!
//! 1. [`reserve_kernel_slots`] — allocates the *top-level* page tables for the
//!    two BPF kernel-VA windows at boot, before the first user address space
//!    exists. Invariant §4.1. See the long comment on that function.
//! 2. The **prog pack**: one 2 MiB hugepage per pack, chunked at 64-byte
//!    granularity and bitmap-allocated, so hundreds of small programs share a
//!    single iTLB entry instead of burning one each. Linux states the rationale
//!    verbatim at `kernel/bpf/core.c:863`.
//! 3. The RW→RX **publish** ([`seal`]).
//!
//! ## Why there is still no temporary-alias mechanism here
//!
//! Linux's prog pack keeps its text RO+X from creation and publishes through
//! `text_poke_copy`, because Linux's direct map is RO as well as NX and there
//! is therefore no writable alias of the pack's frames at all. NARF is now
//! half of the way there and it is worth being exact about which half.
//!
//! Every kernel window `mmu::init_mmu` builds is **NX** apart from the kernel's
//! own text and the AP trampoline (see `memory/src/x86_64/mmu.rs`, and
//! `frame/src/aarch64/boot.S` for the PXN|UXN twin). So the pack's frames are
//! aliased **RW+NX**, not RWX: nothing outside `BPF_TEXT_BASE` can execute
//! them, and no kernel data anywhere can be executed at all. [`write`] still
//! goes through that alias, which is why no publish primitive was needed.
//!
//! The half that remains, stated plainly rather than papered over (spec §4.2):
//! the alias is still **writable**. An attacker with an arbitrary kernel write
//! cannot manufacture new executable memory any more, but can still overwrite
//! *these* bytes, which are executable at the pack's own VA. Strict W^X — no
//! byte writable through any mapping while executable through another —
//! therefore does **not** hold for JIT text yet. Closing it needs two more
//! things, tracked as `bpf/specification/spec.md` §8.6:
//!
//!   1. `seal` must demote the identity/direct-map leaf covering the pack's
//!      physical range and flip it read-only. That is a split of a **live**
//!      mapping, unlike the boot-time demotion `init_mmu` performs, so it
//!      needs the shootdown discipline in `tlb_shootdown.rs` and Linux's
//!      `__split_large_page` argument for why replacing a huge leaf with an
//!      identically-translating table is safe without break-before-make.
//!   2. A `text_poke_copy` equivalent, because [`write`] into an
//!      already-sealed pack (every allocation after the first) would then have
//!      no writable address to use.
//!
//! ## Reclamation
//!
//! [`free`] does **not** immediately hand chunks back: a CPU may be executing
//! the program right now. Freed allocations go to a quarantine list and are
//! released by [`reclaim`], which the owning subsystem calls after an RCU grace
//! period. `narf-memory` cannot depend on `narf-rcu` (the dep graph runs
//! `rcu → time → console → memory`, so that would be a cycle), so the grace
//! period arrives through the [`install_reclaim_hook`] seam — the same shape as
//! `install_pager` / `install_frame_alloc` elsewhere in this crate.

extern crate alloc as alloc_crate;

use alloc_crate::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use narf_capabilities::{CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{PhysAddr, VirtAddr};

// ── VA layout ──────────────────────────────────────────────────────────
//
// Both windows are picked by arithmetic, not by reading comments. A PML4 /
// L0 slot `n` spans `n << 39` bytes, so slot `n`'s canonical base is
// `0xFFFF_0000_0000_0000 | (n << 39)` for `n >= 256`, and
// `(base >> 39) & 0x1FF` recovers `n`. The `debug_assert`s in
// `reserve_kernel_slots` do exactly that check at boot.
//
// Occupied slots on x86_64 (verified against the tree, not assumed):
//   0          low identity map, 0..512 GiB       (`mmu.rs` `init_mmu`)
//   1          high MMIO 512 GiB..1 TiB + the user binary PDPT[0]
//   2..=255    user address space
//   256..=271  per-domain private PCID slots      (`x86_64/domain.rs`)
//   272        vmalloc, 0xFFFF_8800_0000_0000     (`vmalloc.rs` — note that
//              file's "273" comment is wrong; 0xFFFF_8800_0000_0000 >> 39
//              is 0x110 = 272)
//   384..=510  kernel direct map                  (`addr.rs`)
//   511        kernel image (-2 GiB)              (`mmu.rs`)
//
// So 273..=383 is free. We take four consecutive slots:
//
//   273  BPF text        0xFFFF_8880_0000_0000    (0x111 << 39)
//   274  guard, never mapped
//   275  BPF arena       0xFFFF_8980_0000_0000    (0x113 << 39)
//   276  guard, never mapped
//
// The guards are the ISA-derived bound from `kernel/bpf/arena.c:45`, taken to
// its structural conclusion: Linux sizes its guard at
// `round_up(1 << 16, PAGE_SIZE << 1)` = 64 KiB, because the largest
// displacement an instruction can name is the signed 16-bit `off` field. A
// whole unmapped 512 GiB slot on each side is 8388608× that, so an escape by
// immediate displacement from anywhere inside the arena window cannot reach a
// mapped page — it is impossible by construction rather than by arithmetic.
//
// On aarch64 the same numbers work unchanged: TTBR1 is configured with
// `T1SZ = 16` (`frame/src/aarch64/boot.S:150`), i.e. a 48-bit high half whose
// L0 index is also VA[47:39], and 0xFFFF_8880_0000_0000 is inside it. aarch64
// does not have the §4.1 propagation hazard at all (user space lives in TTBR0,
// the kernel in TTBR1, separate roots), but keeping one set of constants
// avoids a second mental model.

/// PML4 (x86_64) / L0 (aarch64) slot holding the BPF text window.
pub const BPF_TEXT_PML4_SLOT: usize = 273;
/// Base kernel VA of the BPF text window.
pub const BPF_TEXT_BASE: u64 = 0xFFFF_8880_0000_0000;

/// PML4 / L0 slot holding the BPF arena window. See `bpf_arena.rs`.
pub const BPF_ARENA_PML4_SLOT: usize = 275;
/// Base kernel VA of the BPF arena window.
pub const BPF_ARENA_BASE: u64 = 0xFFFF_8980_0000_0000;

/// Bytes covered by one PML4 / L0 slot.
pub const SLOT_SPAN: u64 = 1u64 << 39;

/// Usable prefix of the text window. A slot is 512 GiB; we only ever hand out
/// the low 1 GiB of it, which is 512 hugepage packs — far more JIT text than
/// any plausible workload, and it keeps the pack index arithmetic in a `u32`.
pub const BPF_TEXT_USABLE: u64 = 1u64 << 30;

/// Hugepage-backed pack size. One 2 MiB page ⇒ one PMD entry ⇒ **one** iTLB
/// entry for every program in the pack. That is the entire point of the pack
/// allocator (`kernel/bpf/core.c:863`).
pub const PACK_HUGE_BYTES: u64 = 2 * 1024 * 1024;

/// Fallback pack size when the hugepage pool is empty. `hugepage.rs` documents
/// that 2 MiB allocations do **not** fall back to the buddy — if the boot
/// reservation didn't capture enough contiguous memory, `alloc_hugepage_2m`
/// returns `Err(Empty)` by design. Failing a program load on that would be
/// wrong, so we build a smaller pack out of ordinary 4 KiB frames and accept
/// the iTLB cost. Real on the bring-up laptops, where boot-time fragmentation
/// is not hypothetical.
pub const PACK_SMALL_BYTES: u64 = 64 * 1024;

/// Allocation granularity inside a pack. Matches Linux's
/// `BPF_PROG_CHUNK_SIZE` — small enough that a 40-byte program doesn't waste a
/// page, large enough that the bitmap stays tiny.
pub const CHUNK_BYTES: usize = 64;

/// Byte that fills every unallocated chunk, so a stray jump into dead pack
/// space traps instead of executing whatever was there before.
#[cfg(target_arch = "x86_64")]
const TRAP_FILL: [u8; 4] = [0xCC, 0xCC, 0xCC, 0xCC]; // int3
#[cfg(target_arch = "aarch64")]
const TRAP_FILL: [u8; 4] = [0x00, 0x00, 0x20, 0xD4]; // brk #0, little-endian
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const TRAP_FILL: [u8; 4] = [0, 0, 0, 0];

// ── Capability ─────────────────────────────────────────────────────────

/// Authority to create executable kernel text.
///
/// `memory/src/wx.rs` has described this capability since it was written —
/// *"expressed as a capability not a per-process bit, so the privilege is
/// named and revocable"* — but until now no `CapKind` backed it and nothing
/// checked it. `CapKind::Jit` (0x0053) closes that.
#[derive(Copy, Clone, Debug)]
pub struct Jit;

impl CapType for Jit {
    const KIND: CapKind = CapKind::Jit;
}

/// Convenience alias for the granting form of the JIT capability.
pub type JitCap = narf_capabilities::Cap<Jit, Grant>;

// ── Errors ─────────────────────────────────────────────────────────────

/// Failure modes of the text allocator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TextError {
    /// `seal` was called on an image with no registered exception table.
    /// See spec §4.3 — registration must precede execution.
    ExtableMissing,
    /// [`reserve_kernel_slots`] has not run (or failed). Every other entry
    /// point refuses rather than populating a slot the live user address
    /// spaces do not have — see §4.1.
    SlotsUnreserved,
    /// Zero-length, or larger than a single pack can hold.
    BadLen,
    /// No pack has a free run of the requested size and no new pack could be
    /// created (neither hugepage pool nor buddy had memory).
    Exhausted,
    /// Frame allocator failed while building a pack or a page table.
    NoFrame,
    /// A page-table walk failed. Carries nothing — the underlying `MapError`
    /// is arch-specific and this crate's callers cannot act on it.
    MapFailed,
    /// The capability was revoked between grant and use (invariant #5:
    /// holding a `Cap` proves prior grant, only a live check proves current
    /// validity).
    CapRevoked,
    /// The allocation does not belong to any live pack — a double free, or a
    /// handle that outlived [`reclaim`].
    Stale,
    /// Write past the end of the allocation.
    OutOfBounds,
}

// ── Boot reservation ───────────────────────────────────────────────────

/// Set once [`reserve_kernel_slots`] has installed both top-level tables.
static SLOTS_RESERVED: AtomicBool = AtomicBool::new(false);

/// The page-table root the BPF windows were installed into: the kernel PML4 on
/// x86_64, the TTBR1 L0 on aarch64. Recorded at reservation time so every
/// later map walks a deterministic root instead of whatever CR3 happens to
/// hold. Both windows live at PML4[256..511], which `new_user_pml4_on`
/// snapshot-copies into every address space, so populating the *shared*
/// sub-tables through this root is visible everywhere.
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

/// `true` once the BPF top-level tables exist in the kernel root.
///
/// `new_user_pml4_on` `debug_assert`s on this: see §4.1.
#[inline]
pub fn slots_reserved() -> bool {
    SLOTS_RESERVED.load(Ordering::Acquire)
}

/// The page-table root the BPF windows were installed into, for other
/// modules that map inside the same reserved slot (`bpf_stack`, `bpf_arena`).
///
/// Returns `None` before [`reserve_kernel_slots`] — mapping into an
/// unreserved slot would create a top-level entry that live address spaces
/// have already snapshot-copied *without*, which is precisely the §4.1
/// triple-fault.
#[inline]
pub fn kernel_root_for_mapping() -> Option<PhysAddr> {
    kernel_root().ok()
}

#[inline]
fn kernel_root() -> Result<PhysAddr, TextError> {
    if !slots_reserved() {
        return Err(TextError::SlotsUnreserved);
    }
    Ok(PhysAddr::new(KERNEL_ROOT.load(Ordering::Acquire) as u64))
}

/// Allocate the top-level page tables for both BPF kernel-VA windows.
///
/// **This is the highest-risk function in the BPF memory path, and it must run
/// as a direct call from `frame/src/bare_main.rs` — right after the MMU
/// handoff and before the first `new_user_pml4` — not as a staged initcall.**
///
/// The reason is `new_user_pml4_on` (`memory/src/x86_64/paging.rs`):
///
/// ```text
/// for i in 256u64..512 {
///     ptr::write_volatile(dst, ptr::read_volatile(src));   // by value, once
/// }
/// ```
///
/// PML4[256..511] is snapshot-copied **by value** at address-space creation and
/// nothing propagates later changes. If a BPF slot is first populated after a
/// user address space exists, that address space's CR3 holds a zero entry for
/// it, and the first BPF text fetch or arena access taken while that task is
/// current is a page fault on a not-present PML4 entry inside the fault
/// handler's own working set — i.e. a triple fault, on a machine with no
/// diagnostic left to print.
///
/// Populating the slots *before* the first snapshot makes every later address
/// space inherit the same PDPT frame by pointer, so all sub-PML4 population
/// (PDPT/PD/PT entries installed by `alloc`, `seal`, arena `populate`) is
/// automatically shared. Only the PML4 level is copied by value; everything
/// below it is shared structure.
///
/// Idempotent — a second call is a no-op.
pub fn reserve_kernel_slots() -> Result<(), TextError> {
    // Arithmetic self-check on the two window bases. If someone edits a
    // constant, this fires at boot instead of silently colliding with vmalloc
    // (272) or the direct map (384).
    debug_assert_eq!(
        ((BPF_TEXT_BASE >> 39) & 0x1FF) as usize,
        BPF_TEXT_PML4_SLOT,
        "BPF_TEXT_BASE does not decode to BPF_TEXT_PML4_SLOT"
    );
    debug_assert_eq!(
        ((BPF_ARENA_BASE >> 39) & 0x1FF) as usize,
        BPF_ARENA_PML4_SLOT,
        "BPF_ARENA_BASE does not decode to BPF_ARENA_PML4_SLOT"
    );

    if slots_reserved() {
        return Ok(());
    }

    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: CR3 is readable at CPL=0 and, at the call site (immediately
        // after `init_mmu`'s CR3 swap, on the BSP, with interrupts masked),
        // names the final kernel PML4.
        let root = unsafe { crate::x86_64::paging::read_cr3() };
        if root.raw() == 0 {
            return Err(TextError::NoFrame);
        }
        for slot in [BPF_TEXT_PML4_SLOT, BPF_ARENA_PML4_SLOT] {
            // SAFETY: `root` is the live kernel PML4, identity-reachable
            // (page tables live in low RAM), and we are single-threaded on the
            // BSP with interrupts masked, so the read-modify-write of one
            // entry cannot race.
            unsafe { reserve_slot_x86(root, slot)? };
        }
        KERNEL_ROOT.store(root.raw() as usize, Ordering::Release);
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: `MRS .., TTBR1_EL1` is defined at EL1 with no precondition.
        let root = unsafe { crate::aarch64::paging::read_ttbr1_el1() };
        if root.raw() == 0 {
            return Err(TextError::NoFrame);
        }
        for slot in [BPF_TEXT_PML4_SLOT, BPF_ARENA_PML4_SLOT] {
            // SAFETY: same as x86_64 — live kernel root, single-threaded BSP.
            unsafe { reserve_slot_aarch64(root, slot)? };
        }
        KERNEL_ROOT.store(root.raw() as usize, Ordering::Release);
    }

    SLOTS_RESERVED.store(true, Ordering::Release);
    Ok(())
}

/// Install a present, kernel-only, writable next-level table at `root[slot]`
/// if one is not already there.
///
/// # Safety
/// `root` must be a live, identity-reachable PML4 and the caller must have
/// exclusive access to it (boot BSP, interrupts masked).
#[cfg(target_arch = "x86_64")]
unsafe fn reserve_slot_x86(root: PhysAddr, slot: usize) -> Result<(), TextError> {
    use crate::x86_64::paging::{PageTable, PageTableEntry, PtFlags};

    // SAFETY: caller guarantees `root` is a live, identity-reachable PML4.
    let pml4 = unsafe { &mut *root.as_mut_ptr::<PageTable>() };
    if pml4.entries[slot].is_present() {
        return Ok(());
    }
    let frame = crate::frame::alloc_frame().map_err(|_| TextError::NoFrame)?;
    let phys = frame.start_address();
    crate::frame::__pagetable_register(phys.raw());
    // SAFETY: a freshly-allocated frame; reachable through the kernel RAM
    // accessor and exclusively ours until we publish the entry below.
    unsafe {
        core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
    }
    // No `USER`: both windows are kernel-only. No `NO_EXEC` either — the text
    // window has to be executable, and the CPU OR's NX down the walk, so an NX
    // PML4 entry would make the whole subtree non-executable.
    pml4.entries[slot] = PageTableEntry::new(phys, PtFlags::PRESENT | PtFlags::WRITABLE);
    Ok(())
}

/// aarch64 equivalent of [`reserve_slot_x86`]: install an L1 table descriptor
/// under the TTBR1 L0.
///
/// # Safety
/// Same contract as [`reserve_slot_x86`].
#[cfg(target_arch = "aarch64")]
unsafe fn reserve_slot_aarch64(root: PhysAddr, slot: usize) -> Result<(), TextError> {
    use crate::aarch64::paging::PageTable;

    // SAFETY: caller guarantees `root` is the live TTBR1 L0 table.
    let l0 = unsafe { &mut *root.kernel_mut_ptr::<PageTable>() };
    if l0.entries[slot].is_valid() {
        return Ok(());
    }
    let frame = crate::frame::alloc_frame().map_err(|_| TextError::NoFrame)?;
    let phys = frame.start_address();
    // SAFETY: freshly-allocated frame, exclusively ours until published.
    unsafe {
        core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
    }
    // Table descriptor: bits[1:0] = 0b11 (valid + table). Attributes on a
    // table descriptor are permission *restrictions*; leaving them clear means
    // "no restriction", which is what we want — the leaf entries carry the
    // real permissions.
    l0.entries[slot] = crate::aarch64::paging::PageTableEntry::from_raw(phys.raw() | 0b11);
    Ok(())
}

// ── Packs ──────────────────────────────────────────────────────────────

/// How a pack's memory was obtained.
#[derive(Debug)]
enum Backing {
    /// One 2 MiB hugepage, mapped by a single PMD entry.
    Huge(crate::hugepage::HugeFrame),
    /// `PACK_SMALL_BYTES / 4096` ordinary frames, mapped by individual PTEs.
    /// The fallback path; see [`PACK_SMALL_BYTES`].
    Small(Vec<crate::frame::PhysFrame>),
}

#[derive(Debug)]
struct Pack {
    /// Kernel VA base of the pack. Always `PACK_HUGE_BYTES`-aligned so a
    /// hugepage-backed pack can use a PMD leaf.
    base: u64,
    /// Bytes covered.
    len: u64,
    backing: Backing,
    /// One bit per [`CHUNK_BYTES`] chunk; set = allocated.
    bitmap: Vec<u64>,
    /// Chunks currently allocated (including quarantined ones).
    used: usize,
    /// `true` once the leaf mapping has been flipped to RX by [`seal`].
    sealed: bool,
}

impl Pack {
    #[inline]
    fn chunks(&self) -> usize {
        (self.len as usize) / CHUNK_BYTES
    }

    #[inline]
    fn bit(&self, i: usize) -> bool {
        (self.bitmap[i / 64] >> (i % 64)) & 1 == 1
    }

    #[inline]
    fn set_range(&mut self, start: usize, n: usize, on: bool) {
        for i in start..start + n {
            if on {
                self.bitmap[i / 64] |= 1u64 << (i % 64);
            } else {
                self.bitmap[i / 64] &= !(1u64 << (i % 64));
            }
        }
    }

    /// First-fit run of `n` free chunks.
    fn find_run(&self, n: usize) -> Option<usize> {
        let total = self.chunks();
        let mut i = 0;
        while i + n <= total {
            let mut j = 0;
            while j < n && !self.bit(i + j) {
                j += 1;
            }
            if j == n {
                return Some(i);
            }
            // `i + j` is allocated (or we ran off the run); resume past it.
            i += j + 1;
        }
        None
    }

    /// Kernel-writable alias of the byte at pack offset `off`.
    ///
    /// This is the identity (or direct-map) alias of the underlying physical
    /// frame — deliberately *not* the pack's own VA, which is NX-then-RX. See
    /// the module docs on why that is legitimate here and why it is not yet a
    /// W^X boundary.
    fn alias_at(&self, off: u64) -> *mut u8 {
        match &self.backing {
            Backing::Huge(h) => PhysAddr::new(h.phys() + off).kernel_mut_ptr::<u8>(),
            Backing::Small(frames) => {
                let idx = (off / 4096) as usize;
                let within = off % 4096;
                PhysAddr::new(frames[idx].start_address().raw() + within).kernel_mut_ptr::<u8>()
            }
        }
    }

    /// Bytes from `off` to the end of the physically-contiguous run containing
    /// it. 2 MiB for a hugepage pack; whatever remains of the 4 KiB page for a
    /// small pack.
    fn contig_from(&self, off: u64) -> u64 {
        match &self.backing {
            Backing::Huge(_) => self.len - off,
            Backing::Small(_) => 4096 - (off % 4096),
        }
    }
}

/// Registry of live packs. Not a hot path — every entry point here runs at
/// program load, attach, or teardown, never inside a running program.
static PACKS: IrqSafeSpinLock<Vec<Pack>> = IrqSafeSpinLock::new(Vec::new());

/// Next pack VA to hand out. Bump-only; a pack's VA is never recycled, which
/// costs nothing (the window is 512 GiB) and removes a whole class of
/// stale-TLB bug.
static NEXT_PACK_VA: AtomicUsize = AtomicUsize::new(BPF_TEXT_BASE as usize);

// ── Allocation handle ──────────────────────────────────────────────────

/// A run of chunks inside one pack.
///
/// `Copy` on purpose: [`free`] hands this across an RCU grace period, and
/// nothing in the reclaim path may allocate.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TextAlloc {
    /// Kernel VA of the first byte. This is the address the JIT computes
    /// displacements against and the address the program is entered at.
    pub va: u64,
    /// Bytes requested by the caller (not the rounded-up chunk span).
    pub len: usize,
    /// Pack base VA — the key [`free`] / [`seal`] use to find the pack again.
    pack_base: u64,
    /// First chunk index within the pack.
    chunk: usize,
    /// Chunk count.
    chunks: usize,
}

impl TextAlloc {
    /// Entry pointer for the compiled program.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.va as *const u8
    }
}

// ── Public API ─────────────────────────────────────────────────────────

/// Reserve `len` bytes of kernel text.
///
/// The bytes come back **writable through the identity alias and not yet
/// executable at `va`** — write with [`write`], register every faulting
/// instruction's extable entry (invariant §4.3), then [`seal`].
///
/// `node` steers the hugepage allocation; pass the NUMA node the program will
/// mostly run on.
pub fn alloc(cap: &JitCap, len: usize, node: usize) -> Result<TextAlloc, TextError> {
    cap.check_live().map_err(|_| TextError::CapRevoked)?;
    let root = kernel_root()?;
    if len == 0 || len as u64 > PACK_HUGE_BYTES {
        return Err(TextError::BadLen);
    }
    let want = len.div_ceil(CHUNK_BYTES);

    let mut packs = PACKS.lock();

    // First fit across existing packs.
    for p in packs.iter_mut() {
        if let Some(start) = p.find_run(want) {
            p.set_range(start, want, true);
            p.used += want;
            return Ok(TextAlloc {
                va: p.base + (start * CHUNK_BYTES) as u64,
                len,
                pack_base: p.base,
                chunk: start,
                chunks: want,
            });
        }
    }

    // No room — build a new pack. Try a hugepage first; fall back to 4 KiB
    // frames rather than failing the load (`hugepage.rs`: 2 MiB allocations
    // never spill to the buddy).
    // SAFETY: `root` is the recorded kernel root and both windows' top-level
    // entries were installed by `reserve_kernel_slots`, so the walk cannot
    // create a PML4 entry that a live address space is missing.
    let mut pack = unsafe { new_pack(root, node, len as u64)? };
    let Some(start) = pack.find_run(want) else {
        // The fallback pack is smaller than a hugepage pack; a program larger
        // than it and larger than the hugepage pool can supply has nowhere to
        // go. Tear the mapping down before releasing the frames — freeing a
        // frame that is still mapped at a kernel VA leaves a dangling window
        // onto whatever the buddy hands out next.
        // SAFETY: the pack was just created and has no allocations, so nothing
        // can be executing out of it.
        unsafe { unmap_pack(&pack) };
        release_pack_backing(&mut pack);
        return Err(TextError::Exhausted);
    };
    pack.set_range(start, want, true);
    pack.used += want;
    let out = TextAlloc {
        va: pack.base + (start * CHUNK_BYTES) as u64,
        len,
        pack_base: pack.base,
        chunk: start,
        chunks: want,
    };
    packs.push(pack);
    Ok(out)
}

/// Copy `bytes` into the allocation at `off`, through the identity alias.
///
/// Legal both before and after [`seal`] — see the module docs. After a seal
/// the caller is responsible for a fresh `seal` (or an arch icache flush) if
/// the bytes may already have been fetched.
pub fn write(a: &TextAlloc, off: usize, bytes: &[u8]) -> Result<(), TextError> {
    if off.saturating_add(bytes.len()) > a.len {
        return Err(TextError::OutOfBounds);
    }
    let packs = PACKS.lock();
    let p = packs
        .iter()
        .find(|p| p.base == a.pack_base)
        .ok_or(TextError::Stale)?;

    // §4.3 is enforced *here* too, not only in `seal`, and this is the case
    // that made the difference.
    //
    // `alloc` first-fits into packs that are already sealed, and a pack's
    // permissions are whole-pack (one PMD leaf for a hugepage pack, and there is
    // no huge-page demotion helper — see the plan's finding 0.2). So for every
    // allocation *after the first* in a given pack, the returned VA is already
    // RX the moment `alloc` returns: before `write`, before registration, before
    // `seal`. `seal` returning `ExtableMissing` at that point cannot un-publish
    // anything.
    //
    // Until `write`, the range holds trap bytes, so the exposure is a
    // diagnosable fault rather than execution of anything. The hazard begins the
    // instant formed instructions land at an executable VA — which is exactly
    // this call. Refusing it unless the extable is already registered turns
    // "no path to executable text without registration" from a claim about
    // `seal` into a property of the only function that can create the situation.
    //
    // Conditional on `p.sealed` deliberately: an unsealed pack is RW+NX, so
    // there is no executable VA yet and no failure the check would prevent.
    // Requiring it there would be a rule guarding nothing, which is the shape
    // this review keeps finding.
    if p.sealed && !crate::bpf_extable::image_covers(a.va, a.va + a.len as u64) {
        return Err(TextError::ExtableMissing);
    }

    let mut pack_off = (a.chunk * CHUNK_BYTES) as u64 + off as u64;
    let mut done = 0usize;
    while done < bytes.len() {
        let run = p.contig_from(pack_off).min((bytes.len() - done) as u64) as usize;
        let dst = p.alias_at(pack_off);
        // SAFETY: `pack_off + run` stays inside the pack (bounds-checked
        // against `a.len` above, and the allocation lies inside the pack), and
        // `alias_at` returns the kernel-reachable alias of that physical byte.
        // `run` never crosses a physical discontinuity — `contig_from` is what
        // caps it.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes[done..].as_ptr(), dst, run);
        }
        done += run;
        pack_off += run as u64;
    }
    Ok(())
}

/// Publish: flip the containing pack's leaf mapping from RW+NX to RX and make
/// the new bytes visible to instruction fetch.
///
/// Idempotent per pack. The permission flip happens once — the first program
/// sealed in a pack seals the whole pack, exactly as Linux's prog pack is
/// RO+X from creation with the unallocated remainder full of trap bytes. Later
/// allocations in the same pack still write through the identity alias, so
/// nothing needs to un-seal.
///
/// **A consequence worth stating plainly:** because the flip is per *pack*, an
/// allocation after the first in a given pack is executable from `alloc`
/// onwards, so this function is not the first line of defence for §4.3 — it
/// cannot be, since by the time it runs the code has been executable for the
/// whole of `write`. [`write`] carries the same check for exactly that reason.
/// This one remains because it is the last point before the caller is permitted
/// to *enter* the code, and because it is the only check that covers the
/// first-in-pack case.
///
/// Invariant §4.3: every faulting instruction in `a` must already have an
/// extable entry registered. This function cannot check that (it does not know
/// the instruction stream) — the caller must not reorder it.
pub fn seal(cap: &JitCap, a: &TextAlloc) -> Result<(), TextError> {
    cap.check_live().map_err(|_| TextError::CapRevoked)?;
    // Spec §4.3, as a mechanism rather than a comment: every faulting
    // instruction in this image must already have an exception-table entry,
    // because a fault with no entry is fatal. This is the last moment the
    // obligation is checkable — one instruction later the code can run.
    //
    // The verifier hands the JIT a `fault_sites` list precisely so it can
    // build those entries; nothing was consuming it, so "Ok from the verifier"
    // silently meant "safe *provided* someone registers the extable", with no
    // one doing so and nothing noticing.
    if !crate::bpf_extable::image_covers(a.va, a.va + a.len as u64) {
        return Err(TextError::ExtableMissing);
    }
    let root = kernel_root()?;
    let mut packs = PACKS.lock();
    let p = packs
        .iter_mut()
        .find(|p| p.base == a.pack_base)
        .ok_or(TextError::Stale)?;

    if !p.sealed {
        // SAFETY: `root` is the recorded kernel root; the pack's mapping was
        // installed through the same root by `new_pack`, so every level of the
        // walk exists and the leaf is ours to rewrite.
        unsafe { seal_mapping(root, p)? };
        p.sealed = true;
    }

    // Make the freshly-written bytes fetchable even when the pack was already
    // sealed. Scoped to *this allocation*, not the whole pack: on aarch64 the
    // barrier is a per-cache-line `dc cvau` / `ic ivau` sweep, and doing 2 MiB
    // of it per program load would be thousands of pointless maintenance ops.
    //
    // On x86_64 this is a serialising instruction on this CPU. Cross-modifying
    // code on peer CPUs is not a concern: a program is never entered before
    // its `seal` returns, and the pack's unallocated remainder holds trap
    // bytes, so a peer that somehow lands mid-pack faults rather than
    // executing something stale.
    serialize_after_publish(a.va, (a.chunks * CHUNK_BYTES) as u64);
    Ok(())
}

/// Retire an allocation.
///
/// The chunks are **not** returned to the pack immediately — a CPU may be
/// executing this program right now. The handle goes to a quarantine list and
/// is released by [`reclaim`] after a grace period. If a reclaim hook has been
/// installed ([`install_reclaim_hook`]), it is invoked with the handle so the
/// owner can defer through RCU; otherwise the handle sits in quarantine until
/// someone calls [`reclaim`].
pub fn free(a: TextAlloc) {
    // Poison the body so a stale entry into a freed program traps rather than
    // running whatever the next program writes there. Best-effort: a failure
    // here means the pack is already gone.
    let _ = fill_traps(&a);

    if let Some(hook) = RECLAIM_HOOK.lock().as_ref().copied() {
        hook(a);
        return;
    }
    QUARANTINE.lock().push(a);
}

/// Actually release a quarantined allocation's chunks.
///
/// Call only after a grace period during which no CPU can have been executing
/// the program — that is the whole contract. Releasing the last allocation in
/// a pack frees the pack's backing memory too.
pub fn reclaim(a: TextAlloc) {
    let mut packs = PACKS.lock();
    let Some(idx) = packs.iter().position(|p| p.base == a.pack_base) else {
        return;
    };
    {
        let p = &mut packs[idx];
        p.set_range(a.chunk, a.chunks, false);
        p.used = p.used.saturating_sub(a.chunks);
        if p.used != 0 {
            return;
        }
    }
    // Pack is empty — give the memory back. The VA is *not* recycled (see
    // `NEXT_PACK_VA`), so no peer CPU can land on it through a stale TLB entry
    // and find someone else's text.
    let mut pack = packs.swap_remove(idx);
    // SAFETY: the pack has no live allocations and its VA is never reissued,
    // so unmapping the leaves cannot pull the ground out from under a running
    // program.
    unsafe { unmap_pack(&pack) };
    release_pack_backing(&mut pack);
}

/// Drain the quarantine. Same contract as [`reclaim`].
pub fn reclaim_all_quarantined() {
    let pending = core::mem::take(&mut *QUARANTINE.lock());
    for a in pending {
        reclaim(a);
    }
}

/// Hook the owning subsystem installs so [`free`] can defer through RCU.
///
/// `narf-memory` cannot depend on `narf-rcu` — the dependency graph already
/// runs `rcu → time → console → memory`, so the edge would be a cycle. The
/// hook is the same seam shape as `install_pager` / `install_frame_alloc`.
/// The installed function must arrange for [`reclaim`] to be called after a
/// grace period, and must not block.
pub type ReclaimHook = fn(TextAlloc);

static RECLAIM_HOOK: IrqSafeSpinLock<Option<ReclaimHook>> = IrqSafeSpinLock::new(None);
static QUARANTINE: IrqSafeSpinLock<Vec<TextAlloc>> = IrqSafeSpinLock::new(Vec::new());

/// Install the deferred-reclaim hook. Last writer wins.
pub fn install_reclaim_hook(h: ReclaimHook) -> Option<ReclaimHook> {
    RECLAIM_HOOK.lock().replace(h)
}

/// Remove the reclaim hook, returning it.
///
/// Exists so the quarantine fallback can be tested deterministically. Once a
/// hook is installed, `free` routes everything through it and the quarantine
/// is never exercised — so a test of the fallback has to be able to take the
/// hook away and put it back, rather than being written to tolerate whichever
/// path happens to be wired.
pub fn take_reclaim_hook() -> Option<ReclaimHook> {
    RECLAIM_HOOK.lock().take()
}

/// Diagnostics: (live packs, allocated chunks, quarantined allocations).
pub fn stats() -> (usize, usize, usize) {
    // Deliberately not holding both locks at once. `reclaim_all_quarantined`
    // takes `QUARANTINE` then `PACKS`; holding them in the opposite order here
    // would be a lock cycle waiting for someone to make one of them outlive a
    // statement.
    let (packs, used) = {
        let p = PACKS.lock();
        (p.len(), p.iter().map(|p| p.used).sum())
    };
    let quarantined = QUARANTINE.lock().len();
    (packs, used, quarantined)
}

// ── Internals ──────────────────────────────────────────────────────────

fn fill_traps(a: &TextAlloc) -> Result<(), TextError> {
    let packs = PACKS.lock();
    let p = packs
        .iter()
        .find(|p| p.base == a.pack_base)
        .ok_or(TextError::Stale)?;
    let start = (a.chunk * CHUNK_BYTES) as u64;
    let span = (a.chunks * CHUNK_BYTES) as u64;
    fill_traps_raw(p, start, span);
    Ok(())
}

fn fill_traps_raw(p: &Pack, start: u64, span: u64) {
    let mut off = start;
    let end = start + span;
    while off < end {
        let run = p.contig_from(off).min(end - off) as usize;
        let dst = p.alias_at(off);
        // SAFETY: `[off, off + run)` lies inside the pack and does not cross a
        // physical discontinuity (`contig_from`); `alias_at` gives the
        // kernel-reachable alias of the first byte.
        unsafe {
            for i in 0..run {
                dst.add(i).write_volatile(TRAP_FILL[i % TRAP_FILL.len()]);
            }
        }
        off += run as u64;
    }
}

/// Build a pack big enough for `need` bytes and map it into the text window.
///
/// # Safety
/// `root` must be the kernel page-table root recorded by
/// [`reserve_kernel_slots`], and its BPF text top-level entry must be present.
unsafe fn new_pack(root: PhysAddr, node: usize, need: u64) -> Result<Pack, TextError> {
    // Pack VAs are always 2 MiB-aligned so a hugepage pack can take a PMD
    // leaf. Small packs waste the remainder of their 2 MiB slot of VA; the
    // window is 512 GiB, so that is free.
    let base = NEXT_PACK_VA.fetch_add(PACK_HUGE_BYTES as usize, Ordering::Relaxed) as u64;
    if base + PACK_HUGE_BYTES > BPF_TEXT_BASE + BPF_TEXT_USABLE {
        return Err(TextError::Exhausted);
    }

    match crate::hugepage::alloc_hugepage_2m_on(node) {
        Ok(h) => {
            // SAFETY: caller's root contract; `base` is a fresh 2 MiB-aligned
            // VA inside the reserved window, and `h.phys()` is a naturally
            // aligned 2 MiB frame the pool just handed us exclusively.
            unsafe { map_pack_huge(root, base, h.phys())? };
            let p = Pack {
                base,
                len: PACK_HUGE_BYTES,
                backing: Backing::Huge(h),
                bitmap: alloc_crate::vec![0u64; (PACK_HUGE_BYTES as usize / CHUNK_BYTES).div_ceil(64)],
                used: 0,
                sealed: false,
            };
            fill_traps_raw(&p, 0, p.len);
            Ok(p)
        }
        Err(_) => {
            // Hugepage pool empty. `hugepage.rs` documents that this does not
            // fall back to the buddy, and failing a program load on boot-time
            // fragmentation would be the wrong answer, so build a smaller pack
            // out of ordinary frames and accept the iTLB cost.
            if need > PACK_SMALL_BYTES {
                return Err(TextError::Exhausted);
            }
            let pages = (PACK_SMALL_BYTES / 4096) as usize;
            let mut frames = Vec::with_capacity(pages);
            for _ in 0..pages {
                match crate::frame::alloc_frame_on(node) {
                    Ok(f) => frames.push(f),
                    Err(_) => {
                        for f in frames {
                            crate::frame::free_frame(f);
                        }
                        return Err(TextError::NoFrame);
                    }
                }
            }
            for (i, f) in frames.iter().enumerate() {
                // SAFETY: caller's root contract; `base + i*4096` is fresh VA
                // inside the reserved window and `f` is exclusively ours.
                let mapped =
                    unsafe { map_pack_page(root, base + (i as u64) * 4096, f.start_address()) };
                if let Err(e) = mapped {
                    // Unmap what we already installed *before* releasing the
                    // frames. This used to free all of them while pages
                    // `0..i` were still mapped RW+NX at their kernel VA —
                    // leaving a writable kernel window onto whatever the buddy
                    // handed out next, for the life of the boot. The sibling
                    // failure path in `alloc` names this exact hazard and gets
                    // the order right; this one did not.
                    //
                    // The VA is never reissued (the pack base comes off a bump
                    // cursor), so nothing re-maps *there* — but that is an
                    // argument about the VA, and the danger is to the *frame*,
                    // which is very much reused.
                    for j in 0..i {
                        // SAFETY: `base + j*4096` was mapped by this loop on a
                        // previous iteration through the same root.
                        unsafe {
                            let _ = unmap_pack_page(root, base + (j as u64) * 4096);
                        }
                    }
                    for f in frames {
                        crate::frame::free_frame(f);
                    }
                    return Err(e);
                }
            }
            let p = Pack {
                base,
                len: PACK_SMALL_BYTES,
                backing: Backing::Small(frames),
                bitmap: alloc_crate::vec![
                    0u64;
                    (PACK_SMALL_BYTES as usize / CHUNK_BYTES).div_ceil(64)
                ],
                used: 0,
                sealed: false,
            };
            fill_traps_raw(&p, 0, p.len);
            Ok(p)
        }
    }
}

fn release_pack_backing(p: &mut Pack) {
    match core::mem::replace(&mut p.backing, Backing::Small(Vec::new())) {
        Backing::Huge(h) => crate::hugepage::free_hugepage(h),
        Backing::Small(frames) => {
            for f in frames {
                crate::frame::free_frame(f);
            }
        }
    }
}

// ── Arch-specific mapping ──────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn map_pack_huge(root: PhysAddr, va: u64, phys: u64) -> Result<(), TextError> {
    use crate::x86_64::paging::{map_2mb, PtFlags};
    // Created RW + NX: the JIT never writes through this VA (it uses the
    // identity alias), but leaving it non-executable until `seal` means a
    // half-built program is not reachable by instruction fetch at its final
    // address.
    let flags = PtFlags::WRITABLE | PtFlags::NO_EXEC;
    // SAFETY: caller's root contract; `va` is fresh and 2 MiB-aligned.
    unsafe {
        map_2mb(root, VirtAddr::new(va), PhysAddr::new(phys), flags)
            .map_err(|_| TextError::MapFailed)
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn map_pack_page(root: PhysAddr, va: u64, phys: PhysAddr) -> Result<(), TextError> {
    use crate::x86_64::paging::{map_4kb, PtFlags};
    let flags = PtFlags::WRITABLE | PtFlags::NO_EXEC;
    // SAFETY: caller's root contract; `va` is fresh and page-aligned.
    unsafe { map_4kb(root, VirtAddr::new(va), phys, flags).map_err(|_| TextError::MapFailed) }
}

/// Rewrite the pack's leaf entries: drop `WRITABLE`, drop `NO_EXEC`, add
/// `GLOBAL`, then **one** ranged shootdown for the whole pack.
///
/// `GLOBAL` is correct and worth having: BPF text is at the same VA with the
/// same contents under every CR3 (the top-level entry is snapshot-copied into
/// every address space), so there is nothing for a CR3 switch to invalidate.
///
/// One `invlpg_global_range` rather than 512 individual shootdown IPIs — the
/// range hook exists precisely for this shape.
///
/// # Safety
/// `root` must be the recorded kernel root and `p`'s mapping must have been
/// installed through it.
#[cfg(target_arch = "x86_64")]
unsafe fn seal_mapping(root: PhysAddr, p: &Pack) -> Result<(), TextError> {
    use crate::x86_64::paging::{
        invlpg_global_range, PageTable, PageTableEntry, PtFlags, WalkIndices,
    };

    let rewrite = |va: u64, huge: bool| -> Result<(), TextError> {
        let idx = WalkIndices::from_virt(VirtAddr::new(va));
        // SAFETY: `root` is live and identity-reachable; every level below it
        // was created by `map_2mb`/`map_4kb` through this same root.
        unsafe {
            let pml4 = &mut *root.as_mut_ptr::<PageTable>();
            let e = pml4.entries[idx.pml4];
            if !e.is_present() {
                return Err(TextError::MapFailed);
            }
            let pdpt = &mut *e.addr().as_mut_ptr::<PageTable>();
            let e = pdpt.entries[idx.pdpt];
            if !e.is_present() || e.flags().contains(PtFlags::HUGE_PAGE) {
                return Err(TextError::MapFailed);
            }
            let pd = &mut *e.addr().as_mut_ptr::<PageTable>();
            let leaf_slot: &mut PageTableEntry = if huge {
                &mut pd.entries[idx.pd]
            } else {
                let e = pd.entries[idx.pd];
                if !e.is_present() || e.flags().contains(PtFlags::HUGE_PAGE) {
                    return Err(TextError::MapFailed);
                }
                let pt = &mut *e.addr().as_mut_ptr::<PageTable>();
                &mut pt.entries[idx.pt]
            };
            if !leaf_slot.is_present() {
                return Err(TextError::MapFailed);
            }
            // Preserve the physical address and PS bit; rewrite permissions.
            const KEEP: u64 = 0x000f_ffff_ffff_f000 | (1 << 7);
            let kept = leaf_slot.raw() & KEEP;
            *leaf_slot =
                PageTableEntry::from_raw(kept | (PtFlags::PRESENT | PtFlags::GLOBAL).bits());
            Ok(())
        }
    };

    match p.backing {
        Backing::Huge(_) => rewrite(p.base, true)?,
        Backing::Small(_) => {
            for i in 0..(p.len / 4096) {
                rewrite(p.base + i * 4096, false)?;
            }
        }
    }

    // ONE ranged shootdown for the whole pack. `invlpg_global_range` walks the
    // page count locally and broadcasts a single range request; 512 separate
    // `invlpg_global` calls would be 512 IPI round-trips.
    // SAFETY: INVLPG (and the range broadcast) is always legal at CPL=0.
    unsafe {
        invlpg_global_range(VirtAddr::new(p.base), p.len / 4096);
    }
    Ok(())
}

/// x86_64 requires a serialising instruction on a processor before it executes
/// bytes that were written after its last serialisation (SDM Vol 3
/// §8.1.3 — self-modifying code). `CPUID` is the canonical choice.
///
/// Cross-modifying code (a *peer* CPU already fetching these bytes) is not a
/// concern here: a program is never entered before its `seal` returns, and the
/// pack's unallocated remainder holds trap bytes, so a peer that somehow lands
/// mid-pack faults rather than executing stale bytes.
#[cfg(target_arch = "x86_64")]
fn serialize_after_publish(_base: u64, _len: u64) {
    // Delegated to `narf_arch`'s wrapper rather than hand-rolled, because the
    // obvious hand-rolled form is a known NARF bug: `push rbx; cpuid; pop rbx`
    // under `options(nostack)` is a lie to the compiler, which then keeps live
    // data in the red zone that the `push` clobbers. That silently corrupted
    // CPUID results in release builds once already (`arch/src/x86_64/cpuid.rs`
    // carries the post-mortem); the wrapper preserves rbx through a scratch
    // register instead, so `nostack` is truthful.
    // SAFETY: CPUID is always legal at CPL=0.
    let _ = unsafe { narf_arch::x86_64::cpuid::cpuid(0, 0) };
}

/// Remove one 4 KiB pack page. Used by the fallback pack's partial-failure
/// unwind, which must unmap before it frees.
///
/// # Safety
/// `va` must be a page this module mapped through `root`.
#[cfg(target_arch = "x86_64")]
unsafe fn unmap_pack_page(root: PhysAddr, va: u64) -> Result<(), TextError> {
    // SAFETY: per the fn contract, `va` was mapped by `map_pack_page` through
    // this same root.
    unsafe {
        crate::x86_64::paging::unmap_4kb(root, VirtAddr::new(va))
            .map(|_| ())
            .map_err(|_| TextError::MapFailed)
    }
}

/// aarch64 twin of the above.
///
/// # Safety
/// `va` must be a page this module mapped through `root`.
#[cfg(target_arch = "aarch64")]
unsafe fn unmap_pack_page(root: PhysAddr, va: u64) -> Result<(), TextError> {
    // SAFETY: as the x86_64 twin.
    unsafe {
        crate::aarch64::paging::unmap_4kb(root, VirtAddr::new(va))
            .map(|_| ())
            .map_err(|_| TextError::MapFailed)
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn unmap_pack(p: &Pack) {
    use crate::x86_64::paging::{unmap_2mb, unmap_4kb};
    // SAFETY: the pack has no live allocations; its VA is never reissued.
    unsafe {
        match p.backing {
            Backing::Huge(_) => {
                let _ = unmap_2mb(
                    PhysAddr::new(KERNEL_ROOT.load(Ordering::Acquire) as u64),
                    VirtAddr::new(p.base),
                );
            }
            Backing::Small(_) => {
                for i in 0..(p.len / 4096) {
                    let _ = unmap_4kb(
                        PhysAddr::new(KERNEL_ROOT.load(Ordering::Acquire) as u64),
                        VirtAddr::new(p.base + i * 4096),
                    );
                }
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn map_pack_huge(root: PhysAddr, va: u64, phys: u64) -> Result<(), TextError> {
    use crate::aarch64::paging::{map_2mb, PtFlags};
    // RW at EL1, never executable at EL0, and PXN until `seal`.
    let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;
    // SAFETY: caller's root contract; `va` is fresh and 2 MiB-aligned.
    unsafe {
        map_2mb(root, VirtAddr::new(va), PhysAddr::new(phys), flags)
            .map_err(|_| TextError::MapFailed)
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn map_pack_page(root: PhysAddr, va: u64, phys: PhysAddr) -> Result<(), TextError> {
    use crate::aarch64::paging::{map_4kb, PtFlags};
    let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;
    // SAFETY: caller's root contract; `va` is fresh and page-aligned.
    unsafe { map_4kb(root, VirtAddr::new(va), phys, flags).map_err(|_| TextError::MapFailed) }
}

/// aarch64 seal: read-only at EL1 (`AP_RO_EL1`), still `UXN`, and **clear**
/// `PXN` so EL1 may fetch instructions from it.
///
/// No IPI plumbing: `tlbi vae1is` is inner-shareable and self-broadcasts. That
/// asymmetry with x86_64 is worth remembering — the arch does the shootdown
/// for us.
///
/// That was true of the *instruction named here* and false of the code: this
/// called `tlb_invalidate_vae1`, the non-shareable form, which invalidates on
/// the issuing PE only. So on SMP a peer CPU could keep the pre-flip leaf —
/// PXN still set (instruction fetch at the entry faults at a PC with no
/// extable entry) and AP=RW (a writable alias of live text). The primitive now
/// issues `vae1is`, so the comment describes what runs.
///
/// # Safety
/// Same contract as the x86_64 arm.
#[cfg(target_arch = "aarch64")]
unsafe fn seal_mapping(root: PhysAddr, p: &Pack) -> Result<(), TextError> {
    use crate::aarch64::paging::{tlb_invalidate_vae1is, PageTable, PageTableEntry, PtFlags};

    // AP[2:1] occupy bits 7:6; UXN is 54, PXN is 53. Clear the AP field and
    // PXN, then set RO-at-EL1 + UXN.
    const AP_MASK: u64 = 0b11 << 6;
    const PXN: u64 = 1 << 53;

    let rewrite = |va: u64, block_level: usize| -> Result<(), TextError> {
        let raw = va;
        let i0 = ((raw >> 39) & 0x1FF) as usize;
        let i1 = ((raw >> 30) & 0x1FF) as usize;
        let i2 = ((raw >> 21) & 0x1FF) as usize;
        let i3 = ((raw >> 12) & 0x1FF) as usize;
        // SAFETY: `root` is the live TTBR1 L0; every level below it was
        // created by `map_2mb`/`map_4kb` through this same root, and the
        // kernel RAM accessor reaches page-table frames.
        unsafe {
            let l0 = &mut *root.kernel_mut_ptr::<PageTable>();
            let e = l0.entries[i0];
            if !e.is_valid() {
                return Err(TextError::MapFailed);
            }
            let l1 = &mut *e.addr().kernel_mut_ptr::<PageTable>();
            let e = l1.entries[i1];
            if !e.is_valid() {
                return Err(TextError::MapFailed);
            }
            let l2 = &mut *e.addr().kernel_mut_ptr::<PageTable>();
            let leaf: &mut PageTableEntry = if block_level == 2 {
                &mut l2.entries[i2]
            } else {
                let e = l2.entries[i2];
                if !e.is_valid() {
                    return Err(TextError::MapFailed);
                }
                let l3 = &mut *e.addr().kernel_mut_ptr::<PageTable>();
                &mut l3.entries[i3]
            };
            if !leaf.is_valid() {
                return Err(TextError::MapFailed);
            }
            let v = (leaf.raw() & !(AP_MASK | PXN)) | PtFlags::AP_RO_EL1.bits();
            *leaf = PageTableEntry::from_raw(v);
            Ok(())
        }
    };

    match p.backing {
        Backing::Huge(_) => rewrite(p.base, 2)?,
        Backing::Small(_) => {
            for i in 0..(p.len / 4096) {
                rewrite(p.base + i * 4096, 3)?;
            }
        }
    }

    // `tlbi vae1is` is inner-shareable; the hardware broadcasts it. Issue one
    // per 4 KiB page of the pack — for a 2 MiB pack that is 512 `tlbi`s, but
    // they are cheap local instructions, not IPI round-trips.
    for i in 0..(p.len / 4096) {
        // SAFETY: TLB invalidation is always legal at EL1.
        unsafe {
            tlb_invalidate_vae1is(VirtAddr::new(p.base + i * 4096));
        }
    }
    Ok(())
}

/// aarch64 publish barrier.
///
/// The architecture requires, for every line of newly-written instruction
/// memory: clean the D-cache to the point of unification (`dc cvau`), `dsb
/// ish`, invalidate the I-cache (`ic ivau`), `dsb ish`, `isb`. Delegated to
/// `narf_arch::aarch64::flush_icache_range`, which is the same primitive
/// `patch_word` uses.
#[cfg(target_arch = "aarch64")]
fn serialize_after_publish(base: u64, len: u64) {
    // SAFETY: cache-maintenance-by-VA on a mapped, readable kernel range. The
    // pack is mapped for the whole call.
    unsafe {
        narf_arch::aarch64::asm::flush_icache_range(base, len);
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn unmap_pack(p: &Pack) {
    use crate::aarch64::paging::{unmap_2mb, unmap_4kb};
    let root = PhysAddr::new(KERNEL_ROOT.load(Ordering::Acquire) as u64);
    // SAFETY: the pack has no live allocations; its VA is never reissued.
    unsafe {
        match p.backing {
            Backing::Huge(_) => {
                let _ = unmap_2mb(root, VirtAddr::new(p.base));
            }
            Backing::Small(_) => {
                for i in 0..(p.len / 4096) {
                    let _ = unmap_4kb(root, VirtAddr::new(p.base + i * 4096));
                }
            }
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod stub_arch {
    use super::*;
    pub(super) unsafe fn map_pack_huge(_: PhysAddr, _: u64, _: u64) -> Result<(), TextError> {
        Err(TextError::MapFailed)
    }
    pub(super) unsafe fn map_pack_page(_: PhysAddr, _: u64, _: PhysAddr) -> Result<(), TextError> {
        Err(TextError::MapFailed)
    }
    pub(super) unsafe fn seal_mapping(_: PhysAddr, _: &Pack) -> Result<(), TextError> {
        Err(TextError::MapFailed)
    }
    pub(super) fn serialize_after_publish(_: u64, _: u64) {}
    pub(super) unsafe fn unmap_pack(_: &Pack) {}
    pub(super) unsafe fn unmap_pack_page(_: PhysAddr, _: u64) -> Result<(), TextError> {
        Err(TextError::MapFailed)
    }
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use stub_arch::*;

// ── In-kernel smokes ───────────────────────────────────────────────────
//
// These are the tests that matter: the host tests below can only check
// arithmetic, and every genuinely dangerous thing here — the boot-order
// propagation, the RW→RX flip, the fault recovery — is only observable on a
// live MMU.

use narf_kernel_test::{kernel_test_in, TestResult};

/// §4.1 regression test, and the reason this file exists.
///
/// `reserve_kernel_slots` must have run *before* the first user address
/// space, so the BPF top-level entries are present in the **currently active**
/// page-table root — not merely in the boot PML4 we installed them into. If a
/// future edit moves the reservation after `setup_pcid_domains`, the entry is
/// absent here and this fails; without the test the same mistake is a triple
/// fault with nothing on the wire.
#[cfg(target_arch = "x86_64")]
fn smoke_bpf_text_slots_present_in_active_root() -> TestResult {
    if !slots_reserved() {
        return TestResult::Fail("bpf_text::reserve_kernel_slots() never ran");
    }
    // SAFETY: CR3 is readable at CPL=0 and names the live root; the PML4 is in
    // identity-reachable low RAM.
    let live = unsafe { crate::x86_64::paging::read_cr3() };
    // SAFETY: `live` is the active PML4, identity-reachable.
    let pml4 = unsafe { &*live.as_ptr::<crate::x86_64::paging::PageTable>() };
    if !pml4.entries[BPF_TEXT_PML4_SLOT].is_present() {
        return TestResult::Fail("BPF text PML4 slot absent from the active root");
    }
    if !pml4.entries[BPF_ARENA_PML4_SLOT].is_present() {
        return TestResult::Fail("BPF arena PML4 slot absent from the active root");
    }
    // The guard slots on either side of the arena must stay empty — that is
    // what makes an escape by immediate displacement structurally impossible
    // rather than merely improbable.
    for guard in [BPF_ARENA_PML4_SLOT - 1, BPF_ARENA_PML4_SLOT + 1] {
        if pml4.entries[guard].is_present() {
            return TestResult::Fail("an arena guard slot is mapped");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_bpf_text_slots_present_in_active_root);

#[cfg(target_arch = "aarch64")]
fn smoke_bpf_text_slots_present_in_active_root() -> TestResult {
    if !slots_reserved() {
        return TestResult::Fail("bpf_text::reserve_kernel_slots() never ran");
    }
    // SAFETY: `MRS .., TTBR1_EL1` is defined at EL1; the L0 table is reachable
    // through the kernel RAM accessor.
    let live = unsafe { crate::aarch64::paging::read_ttbr1_el1() };
    // SAFETY: `live` is the active TTBR1 L0 table.
    let l0 = unsafe { &*live.kernel_ptr::<crate::aarch64::paging::PageTable>() };
    if !l0.entries[BPF_TEXT_PML4_SLOT].is_valid() {
        return TestResult::Fail("BPF text L0 slot absent from TTBR1");
    }
    if !l0.entries[BPF_ARENA_PML4_SLOT].is_valid() {
        return TestResult::Fail("BPF arena L0 slot absent from TTBR1");
    }
    for guard in [BPF_ARENA_PML4_SLOT - 1, BPF_ARENA_PML4_SLOT + 1] {
        if l0.entries[guard].is_valid() {
            return TestResult::Fail("an arena guard slot is mapped");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("memory", smoke_bpf_text_slots_present_in_active_root);

/// A stub that returns 42, hand-assembled so the test needs no JIT.
///
/// x86_64: `b8 2a 00 00 00` (`mov eax, 42`) + `c3` (`ret`).
/// aarch64: `52800540` (`mov w0, #42`) + `d65f03c0` (`ret`), little-endian.
#[cfg(target_arch = "x86_64")]
const RET42: &[u8] = &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
#[cfg(target_arch = "aarch64")]
const RET42: &[u8] = &[0x40, 0x05, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];

/// End-to-end: reserve → map → write through the identity alias → seal →
/// **execute**.
///
/// The execution is the point. Everything up to `seal` could be wrong in a
/// way that only shows up as an instruction fetch on a page the CPU thinks is
/// NX, or as stale bytes in the I-cache — neither of which any amount of
/// checking the return values would catch.
fn smoke_bpf_text_seal_refuses_undeclared_image() -> TestResult {
    // The negative half of spec §4.3: an image with no registered exception
    // table must not become executable. Before this, `Ok` from the verifier
    // meant "safe *provided* someone registers the extable" and nobody did —
    // the obligation existed only in prose.
    //
    // Asserted as "write *or* seal refuses", not "seal refuses", because which
    // one fires depends on whether this allocation landed in a pack that is
    // already sealed — and that depends on what ran before us. Pinning it to
    // `seal` made the test order-dependent: in a fresh pack `write` succeeds and
    // `seal` refuses, but in a sealed pack the VA is executable from `alloc`, so
    // `write` is the check that must refuse. Both are the same invariant; only
    // one can be the *first* to enforce it.
    let cap = JitCap::bootstrap();
    let Ok(a) = alloc(&cap, RET42.len(), 0) else {
        return TestResult::Fail("bpf_text::alloc failed");
    };
    let write_refused = matches!(write(&a, 0, RET42), Err(TextError::ExtableMissing));
    let seal_refused = matches!(seal(&cap, &a), Err(TextError::ExtableMissing));
    free(a);
    if write_refused || seal_refused {
        TestResult::Pass
    } else {
        TestResult::Fail("an unregistered image was allowed to become executable")
    }
}
kernel_test_in!("memory", smoke_bpf_text_seal_refuses_undeclared_image);

/// The second allocation in an already-sealed pack is executable from `alloc`,
/// so registration must be enforced at **write** — `seal` is too late.
///
/// This is the case §4.3's enforcement used to miss entirely. A pack's
/// permissions are whole-pack (one PMD leaf, and there is no huge-page demotion
/// helper), so once any program in it is sealed the whole pack is RX. `alloc`
/// first-fits into such packs, so allocation 2..n came back already executable:
/// `write` laid formed instructions into executable memory with no extable
/// coverage, and `seal` refusing afterwards could not un-publish them.
fn smoke_bpf_text_write_into_sealed_pack_needs_extable() -> TestResult {
    let cap = JitCap::bootstrap();
    // First allocation: register + seal, which seals the whole pack.
    let Ok(first) = alloc(&cap, RET42.len(), 0) else {
        return TestResult::Fail("first alloc failed");
    };
    let token = first.va;
    if crate::bpf_extable::register_image(token, first.va, first.va + first.len as u64, Vec::new())
        .is_err()
    {
        free(first);
        return TestResult::Fail("register_image failed");
    }
    if write(&first, 0, RET42).is_err() {
        crate::bpf_extable::unregister_image(token);
        free(first);
        return TestResult::Fail("first write failed");
    }
    if seal(&cap, &first).is_err() {
        crate::bpf_extable::unregister_image(token);
        free(first);
        return TestResult::Fail("first seal failed");
    }

    // Second allocation. If it landed in the pack we just sealed, its VA is
    // already executable and an unregistered `write` must be refused.
    let Ok(second) = alloc(&cap, RET42.len(), 0) else {
        crate::bpf_extable::unregister_image(token);
        free(first);
        return TestResult::Fail("second alloc failed");
    };
    let same_pack = second.pack_base == first.pack_base;
    let refused = matches!(write(&second, 0, RET42), Err(TextError::ExtableMissing));
    free(second);
    crate::bpf_extable::unregister_image(token);
    free(first);

    if !same_pack {
        // Not a pass by luck: if the allocator did not reuse the pack there is
        // nothing to assert, and claiming otherwise would be a vacuous pass.
        return TestResult::Skip("second allocation did not land in the sealed pack");
    }
    if refused {
        TestResult::Pass
    } else {
        TestResult::Fail("write into a sealed pack accepted an unregistered image")
    }
}
kernel_test_in!(
    "memory",
    smoke_bpf_text_write_into_sealed_pack_needs_extable
);

fn smoke_bpf_text_alloc_seal_execute() -> TestResult {
    let cap = JitCap::bootstrap();
    let a = match alloc(&cap, RET42.len(), 0) {
        Ok(a) => a,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("bpf_text::alloc failed");
        }
    };
    if a.va < BPF_TEXT_BASE || a.va >= BPF_TEXT_BASE + BPF_TEXT_USABLE {
        free(a);
        return TestResult::Fail("allocation landed outside the text window");
    }
    // Declare the (empty) exception table before **writing**. Neither `write`
    // nor `seal` can tell whether an image contains faulting instructions, so
    // the only safe rule is that the producer must always say — an image with no
    // fault sites registers an empty list. Spec §4.3.
    //
    // Before `write` rather than before `seal`: an allocation landing in a pack
    // that is already sealed is executable from `alloc`, so `write` is the first
    // moment formed instructions exist at an executable VA.
    let token = a.va;
    if crate::bpf_extable::register_image(token, a.va, a.va + a.len as u64, Vec::new()).is_err() {
        free(a);
        return TestResult::Fail("bpf_extable::register_image failed");
    }
    if write(&a, 0, RET42).is_err() {
        crate::bpf_extable::unregister_image(token);
        free(a);
        return TestResult::Fail("bpf_text::write failed");
    }
    if seal(&cap, &a).is_err() {
        crate::bpf_extable::unregister_image(token);
        free(a);
        return TestResult::Fail("bpf_text::seal failed");
    }
    // SAFETY: `a.va` holds a sealed, executable, `extern "C"` stub that takes
    // no arguments, clobbers only the return register, and returns.
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute::<u64, _>(a.va) };
    let got = f();
    crate::bpf_extable::unregister_image(token);
    free(a);
    if got != 42 {
        return TestResult::Fail("sealed BPF text returned the wrong value");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_bpf_text_alloc_seal_execute);

/// A stub whose first instruction is a load through its argument, so the
/// caller can choose whether it faults.
///
/// x86_64: `48 8b 07` (`mov rax, [rdi]`) + `c3` (`ret`) — fault at +0, fixup
/// at +3, destination register 0 (`rax`).
/// aarch64: `f9400000` (`ldr x0, [x0]`) + `d65f03c0` (`ret`) — fault at +0,
/// fixup at +4, destination register 0 (`x0`).
#[cfg(target_arch = "x86_64")]
const PROBE_LOAD: (&[u8], u64, u8) = (&[0x48, 0x8B, 0x07, 0xC3], 3, 0);
#[cfg(target_arch = "aarch64")]
const PROBE_LOAD: (&[u8], u64, u8) = (&[0x00, 0x00, 0x40, 0xF9, 0xC0, 0x03, 0x5F, 0xD6], 4, 0);

/// The fault-recoverable probe load, end to end: a real page fault inside
/// sealed BPF text, recovered by the extable, with the destination register
/// zeroed and execution resumed — instead of a dead kernel.
///
/// The address dereferenced is the base of the **guard slot** between the text
/// and arena windows, which nothing ever maps. That is deliberate: it proves
/// the guard is genuinely unmapped at the same time as it proves the recovery
/// works.
fn smoke_bpf_text_extable_recovers_probe_fault() -> TestResult {
    use crate::bpf_extable::{self, ExEntry, GpReg};

    let (code, fixup_off, dst) = PROBE_LOAD;
    let cap = JitCap::bootstrap();
    let a = match alloc(&cap, code.len(), 0) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("bpf_text::alloc failed"),
    };
    // Invariant §4.3: registration precedes **`write`**, not merely `seal`.
    //
    // This test used to write first. That was legal when `seal` was the only
    // enforcement point, and wrong for the same reason the production path was:
    // if this allocation lands in a pack another program already sealed, the VA
    // is executable from `alloc`, so writing first put formed instructions into
    // executable memory with no extable coverage. `write` now refuses that, so
    // the order here is enforced rather than merely conventional.
    let token = a.va;
    if bpf_extable::register_image(
        token,
        a.va,
        a.va + code.len() as u64,
        alloc_crate::vec![ExEntry {
            fault_pc: a.va,
            fixup_pc: a.va + fixup_off,
            dst: GpReg(dst),
        }],
    )
    .is_err()
    {
        free(a);
        return TestResult::Fail("extable registration failed");
    }
    if write(&a, 0, code).is_err() {
        bpf_extable::unregister_image(token);
        free(a);
        return TestResult::Fail("bpf_text::write failed");
    }
    if seal(&cap, &a).is_err() {
        bpf_extable::unregister_image(token);
        free(a);
        return TestResult::Fail("bpf_text::seal failed");
    }

    // The guard slot between the two BPF windows. Canonical, kernel-half,
    // and never mapped by anything.
    let unmapped = BPF_TEXT_BASE + SLOT_SPAN;
    // SAFETY: `a.va` holds a sealed `extern "C"` stub taking one pointer-sized
    // argument. Its single load is registered in the extable, so a fault at it
    // is recovered by the trap handler rather than being fatal.
    let f: extern "C" fn(u64) -> u64 = unsafe { core::mem::transmute::<u64, _>(a.va) };

    // Control: a load that does *not* fault must return the real value, so a
    // pass here can't be an artefact of the stub always returning zero.
    let witness: u64 = 0x5EED_5EED_5EED_5EED;
    let good = f(&witness as *const u64 as u64);

    // The recovered case.
    let recovered = f(unmapped);

    bpf_extable::unregister_image(token);
    free(a);

    if good != witness {
        return TestResult::Fail("non-faulting probe load returned the wrong value");
    }
    if recovered != 0 {
        return TestResult::Fail("recovered probe load did not zero its destination");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_bpf_text_extable_recovers_probe_fault);

/// A fault inside BPF text at an address with **no** extable entry must stay
/// fatal — §4.3 says so explicitly, and a recovery that fired on unregistered
/// addresses would turn a JIT bug into a silently corrupted register.
///
/// Checked at the table level rather than by actually faulting, because the
/// alternative is a test that kills the kernel when it passes.
fn smoke_bpf_text_unregistered_fault_is_not_recoverable() -> TestResult {
    use crate::bpf_extable;

    let cap = JitCap::bootstrap();
    let a = match alloc(&cap, 64, 0) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("bpf_text::alloc failed"),
    };
    let hit = bpf_extable::try_recover(a.va).is_some();
    free(a);
    if hit {
        return TestResult::Fail("extable claimed a recovery for an unregistered address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory",
    smoke_bpf_text_unregistered_fault_is_not_recoverable
);

/// Freed chunks come back only through `reclaim`, and a freed program's body
/// is trap-filled so a stale entry into it faults rather than running whatever
/// the next allocation writes there.
fn smoke_bpf_text_free_quarantines_then_reclaims() -> TestResult {
    let cap = JitCap::bootstrap();
    // Exercise the *fallback* path explicitly. `narf-bpf` installs a reclaim
    // hook at boot which routes `free` straight to RCU, so with it in place
    // the quarantine is never touched and this test would be asserting a code
    // path the kernel no longer takes. Take the hook away for the duration and
    // put it back, so both paths stay covered rather than whichever one
    // happens to be wired.
    let saved = take_reclaim_hook();
    let outcome = free_quarantine_fallback(&cap);
    if let Some(h) = saved {
        install_reclaim_hook(h);
    }
    outcome
}

fn free_quarantine_fallback(cap: &JitCap) -> TestResult {
    // Start from a drained quarantine: sibling smokes in this subsystem also
    // alloc and free, and their still-quarantined chunks would otherwise be
    // counted in `used_before` and released by our own `reclaim_all` — making
    // the result depend on test order.
    reclaim_all_quarantined();
    let (_, used_before, q_before) = stats();
    if q_before != 0 {
        return TestResult::Fail("quarantine not empty after a full drain");
    }
    let a = match alloc(cap, 128, 0) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("bpf_text::alloc failed"),
    };
    let (_, used_alloced, _) = stats();
    if used_alloced != used_before + 2 {
        return TestResult::Fail("128 bytes should claim exactly two 64-byte chunks");
    }
    free(a);
    let (_, used_freed, q) = stats();
    if used_freed != used_alloced {
        return TestResult::Fail("free() released chunks before the grace period");
    }
    if q == 0 {
        return TestResult::Fail("free() did not quarantine the allocation");
    }
    reclaim_all_quarantined();
    let (_, used_after, q_after) = stats();
    if q_after != 0 {
        return TestResult::Fail("quarantine not drained");
    }
    if used_after != used_before {
        return TestResult::Fail("reclaim did not return the chunks");
    }
    TestResult::Pass
}
kernel_test_in!("memory", smoke_bpf_text_free_quarantines_then_reclaims);

/// A revoked capability must stop working immediately — invariant #5: holding
/// a `Cap` proves *prior* grant; only the live check proves current validity.
fn smoke_bpf_text_revoked_cap_cannot_allocate() -> TestResult {
    let cap = JitCap::bootstrap();
    if alloc(&cap, 64, 0).map(free).is_err() {
        return TestResult::Fail("alloc failed with a live cap");
    }
    cap.revoke();
    match alloc(&cap, 64, 0) {
        Err(TextError::CapRevoked) => TestResult::Pass,
        Ok(a) => {
            free(a);
            TestResult::Fail("revoked cap still allocated executable text")
        }
        Err(_) => TestResult::Fail("revoked cap failed for the wrong reason"),
    }
}
kernel_test_in!("memory", smoke_bpf_text_revoked_cap_cannot_allocate);

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_base_decodes_to_its_slot() {
        assert_eq!(((BPF_TEXT_BASE >> 39) & 0x1FF) as usize, BPF_TEXT_PML4_SLOT);
        assert_eq!(
            ((BPF_ARENA_BASE >> 39) & 0x1FF) as usize,
            BPF_ARENA_PML4_SLOT
        );
    }

    #[test]
    fn windows_avoid_every_claimed_slot() {
        // 0 identity, 1 high MMIO, 2..=255 user, 256..=271 per-domain PCID,
        // 272 vmalloc, 384..=510 direct map, 511 kernel image.
        for slot in [BPF_TEXT_PML4_SLOT, BPF_ARENA_PML4_SLOT] {
            assert!(slot > 272, "collides with vmalloc or lower");
            assert!(slot < 384, "collides with the kernel direct map");
        }
    }

    #[test]
    fn a_guard_slot_separates_the_windows() {
        assert!(BPF_ARENA_PML4_SLOT >= BPF_TEXT_PML4_SLOT + 2);
    }
}
