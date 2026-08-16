//! `text_poke` — the W^X half that the boot-time NX work does not reach.
//!
//! Spec: `bpf/specification/spec.md` §8.6.
//!
//! `mmu::init_mmu` (x86_64) and `frame/src/aarch64/boot.S` already build every
//! kernel window NX / `PXN|UXN` outside the kernel's own text and the AP
//! trampoline, so an arbitrary kernel write can no longer *manufacture*
//! executable memory. What it could still do is overwrite the bytes of a BPF
//! prog pack, because those frames stayed aliased **RW**+NX in the kernel's
//! linear window while being executable at `BPF_TEXT_BASE`.
//!
//! This module closes that, and pays the price that closing it creates:
//!
//! 1. [`protect_ro`] drops `WRITABLE` (x86_64) / sets `AP_RO_EL1` (aarch64) on
//!    every kernel window that aliases a physical range, demoting huge leaves
//!    as required. [`protect_rw`] puts it back — mandatory before the frames
//!    return to the buddy, or the next owner of the frame inherits a read-only
//!    alias.
//! 2. [`poke_copy`] / [`poke_fill`] are the `text_poke_copy` equivalent: a
//!    **transient, per-CPU** RW+NX alias of one 4 KiB frame at a scratch kernel
//!    VA, torn down before the call returns. Without it, step 1 would make
//!    every allocation after the first in a sealed pack unwritable and break
//!    program loading.
//!
//! ## Why splitting a live huge leaf is safe here
//!
//! A pack's frames can be anywhere in RAM, so [`protect_ro`] must sometimes
//! replace a **live** 1 GiB (or 2 MiB) identity leaf with a table. Unlike the
//! boot-time demotion in `init_mmu`, there is no "before the CR3 handoff"
//! escape hatch: APs are running and the BSP may be standing on the very leaf
//! being split.
//!
//! Linux does exactly this in `__split_large_page`
//! (`arch/x86/mm/pageattr.c`, today `arch/x86/mm/pat/set_memory.c:1121`) and
//! the argument is quoted in its own comment. Intel's TLB application note
//! makes processor behaviour undefined when the TLB holds both a large-page
//! and a 4 KiB translation for the same linear range **and the two differ with
//! respect to page frame or attributes**. So the split itself is safe: the
//! table Linux installs is filled, entry by entry, with translations that are
//! *identical* to the huge leaf it replaces — same output frames in order,
//! same attribute bits — and the swap is one naturally-aligned 8-byte store,
//! so no CPU ever sees a half-built entry. A CPU holding the stale huge entry
//! and a CPU walking the fresh table compute the same answer, so there is
//! nothing to break-before-make against.
//!
//! What is *not* safe is changing the attributes while a stale huge entry can
//! still exist. Linux's ordering is therefore **split → `flush_tlb_all()` →
//! only then change the PTE**, and the flush is inside the lock so no other
//! CPU can start a permission change against a leaf whose huge parent is still
//! cached. [`split_leaf`] mirrors that: it ends with
//! `flush_user_tlb_all_cpus()`, which is synchronous — it INVPCID/CR3-flushes
//! locally and then broadcasts through `shoot_full`, which spins for every
//! peer's ack before returning. The permission store happens after that call
//! returns, on the next turn of the walk loop. Every writer here holds
//! `bpf_text`'s `PACKS` lock for the whole sequence, which is this tree's
//! stand-in for `cpa_lock`.
//!
//! Changing an attribute needs its own invalidation too, and that one is *not*
//! the split's: [`set_range_writable`] ends with a synchronous
//! `invlpg_global_range` over the range it rewrote. The split's flush happens
//! before the permission store, and when no split was needed it does not happen
//! at all — which left the protection correct in the page tables and inert in
//! the TLB. `smoke_text_poke_protect_round_trip` is what found that.
//!
//! `PACKS` is also the whole of the serialisation argument, so it is worth
//! being explicit about what it does *not* cover. `paging.rs` guards
//! `map_4kb` / `unmap_4kb` with a per-root shard lock (`pt_lock_for`), and
//! [`set_leaf_writable`] does not take it — it walks the tables directly. The
//! two cannot collide: `map_4kb` refuses to descend through a huge leaf
//! (`EncounteredHugePage`) and only installs tables under *absent* entries,
//! whereas this module only rewrites *present* ones; and nothing in the tree
//! `map_4kb`s into the low identity map, the higher-half kernel window, or the
//! direct map, which are the only subtrees rewritten here. The one VA range
//! this module does hand to `map_4kb` — the poke window — lives in the BPF text
//! slot, disjoint from all three. Lock order is `PACKS` → `pt_lock`, never the
//! reverse.
//!
//! On aarch64 the same reasoning does **not** apply, and this module does not
//! pretend otherwise. ARMv8 requires break-before-make when a translation's
//! block size changes, and a BBM on the linear map would unmap live kernel
//! memory on every other CPU for the duration. Linux arm64 refuses the same
//! thing — it does not split the linear map, it boots it page-mapped when it
//! knows it will need to change permissions (`rodata_full` /
//! `can_set_direct_map()`). NARF's aarch64 kernel window is built at **2 MiB**
//! granularity by `boot.S`, so a hugepage-backed pack — 2 MiB, naturally
//! aligned — is exactly one block descriptor and needs only a *permission*
//! change, which ARM permits without BBM. Anything finer would need a split,
//! so [`can_protect`] refuses it and the caller keeps the writable alias
//! rather than corrupting the machine. See §8.6 for what that leaves open.
//!
//! ## x86_64 needs `CR0.WP`
//!
//! At CPL=0 a store to a read-only page only faults when `CR0.WP` is set;
//! with `WP=0` supervisor writes ignore the R/W bit entirely (Intel SDM Vol 3
//! §4.6.1) and a read-only alias would be decoration. NARF's boot path set
//! `CR0.PG` and nothing else, so [`enable_write_protect`] sets `WP` explicitly
//! on the BSP and on every AP, and [`write_protect_enabled`] gates
//! [`protect_ro`] — if the bit is not set the request is refused as
//! [`PokeError::Unsupported`] rather than silently claiming a boundary that
//! does not exist.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::PhysAddr;
#[allow(unused_imports)]
use crate::VirtAddr;

/// Failure modes of alias protection and the poke window.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PokeError {
    /// The frame allocator could not supply a page-table page for a split.
    NoFrame,
    /// A page-table walk hit a missing or malformed entry. The kernel windows
    /// this module touches are built by `init_mmu` / `boot.S` and are always
    /// present, so this means the layout assumptions here have drifted from
    /// the ones there.
    Walk,
    /// The request cannot be satisfied on this arch/configuration without
    /// doing something unsafe — an aarch64 sub-block split (which would need
    /// break-before-make on a live linear mapping), an x86_64 leaf with a
    /// non-default memory type, or `CR0.WP` left clear.
    Unsupported,
    /// The BPF kernel VA slot has not been reserved, so the poke window has
    /// nowhere to live. See `bpf_text::reserve_kernel_slots`.
    NotReserved,
}

/// Bytes covered by one 2 MiB leaf.
const TWO_MB: u64 = 2 * 1024 * 1024;
/// Bytes covered by one 4 KiB leaf.
const FOUR_KB: u64 = 4096;

// ── CR0.WP ─────────────────────────────────────────────────────────────

/// Set `CR0.WP` so that supervisor stores honour the read-only bit.
///
/// Idempotent, and safe to call on every CPU: `WP` is per-CPU state, so an AP
/// that never runs this keeps ignoring read-only kernel pages.
///
/// # Safety
/// Must run at CPL=0. Enabling `WP` turns any pre-existing supervisor write
/// through a read-only mapping from a silent success into a `#PF` — which is
/// the point, but it means this must be called from the boot path where a
/// resulting fault is diagnosable, not from an arbitrary context.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_write_protect() {
    // SAFETY: CR0 read/write at CPL=0 is always legal; we only set bit 16.
    unsafe {
        let mut cr0: u64;
        core::arch::asm!("mov {0}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 |= 1 << 16;
        core::arch::asm!("mov cr0, {0}", in(reg) cr0, options(nomem, nostack, preserves_flags));
    }
}

/// aarch64 has no `CR0.WP` analogue — `AP_RO_EL1` already faults EL1 stores.
///
/// # Safety
/// Trivially safe; the signature matches the x86_64 arm so the boot path has
/// one call site.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn enable_write_protect() {}

/// Whether supervisor stores on **this CPU** respect read-only mappings.
#[cfg(target_arch = "x86_64")]
pub fn write_protect_enabled() -> bool {
    let cr0: u64;
    // SAFETY: reading CR0 at CPL=0 is always legal and side-effect free.
    unsafe {
        core::arch::asm!("mov {0}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    }
    cr0 & (1 << 16) != 0
}

/// aarch64: `AP_RO_EL1` is unconditional, so this is always true.
#[cfg(not(target_arch = "x86_64"))]
pub fn write_protect_enabled() -> bool {
    true
}

// ── Alias protection ───────────────────────────────────────────────────

/// Can `[phys, phys + len)` have its kernel alias made read-only on this
/// arch and configuration?
///
/// Callers must consult this rather than treating an error from
/// [`protect_ro`] as fatal: on aarch64 a sub-2-MiB range is a permanent,
/// architectural "no", not a transient failure.
pub fn can_protect(phys: u64, len: u64) -> bool {
    if len == 0 {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        write_protect_enabled() && phys % FOUR_KB == 0 && len % FOUR_KB == 0
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Block granularity only — see the module docs on break-before-make.
        phys % TWO_MB == 0 && len % TWO_MB == 0
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (phys, len);
        false
    }
}

/// Make every writable kernel alias of `[phys, phys + len)` read-only.
///
/// # Safety
/// - `[phys, phys + len)` must be memory the caller owns exclusively; nothing
///   else may be writing through a kernel pointer to it.
/// - The caller must serialise against every other user of this module (in
///   practice: hold `bpf_text::PACKS`).
/// - [`protect_rw`] must run before the frames are released.
pub unsafe fn protect_ro(phys: u64, len: u64) -> Result<(), PokeError> {
    // SAFETY: forwarded caller contract.
    unsafe { set_alias_writable(phys, len, false) }
}

/// Undo [`protect_ro`].
///
/// # Safety
/// Same contract as [`protect_ro`]. Failing to call this before handing the
/// frames back to the buddy leaves a read-only alias on memory whose next
/// owner expects to be able to write it.
pub unsafe fn protect_rw(phys: u64, len: u64) -> Result<(), PokeError> {
    // SAFETY: forwarded caller contract.
    unsafe { set_alias_writable(phys, len, true) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn set_alias_writable(phys: u64, len: u64, writable: bool) -> Result<(), PokeError> {
    if !can_protect(phys, len) {
        return Err(PokeError::Unsupported);
    }
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(PokeError::NotReserved)?;
    let (vas, n) = alias_vas(phys);
    for va in vas.iter().take(n) {
        // SAFETY: `root` is the recorded kernel root; each `va` is a window
        // `init_mmu` built, so the walk terminates in a present leaf.
        unsafe { set_range_writable(root, *va, len, writable)? };
    }
    Ok(())
}

/// Every kernel VA at which `phys` is reachable, derived from the same rules
/// `init_mmu` builds the windows by rather than from a guess:
///
/// * `phys` itself — PML4[0] identity-maps 0..512 GiB unconditionally.
/// * `KERNEL_VIRT_BASE + phys` — PML4[511]/PDPT[510] aliases phys 0..1 GiB,
///   which is where a small-RAM boot does all of its buddy allocation. Closing
///   only the identity map would leave this as a complete replacement for it;
///   `mmu.rs` says so in as many words.
/// * `KERNEL_DIRECT_MAP_BASE | phys` — only built on machines with more than
///   512 GiB of RAM, hence gated on `direct_map_live()`.
///
/// PML4[1] (512 GiB..1 TiB) is the high-MMIO identity window and never maps
/// RAM, so it is not a candidate.
#[cfg(target_arch = "x86_64")]
fn alias_vas(phys: u64) -> ([u64; 3], usize) {
    const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
    const KERNEL_WINDOW_SPAN: u64 = 1 << 30;
    let mut out = [0u64; 3];
    let mut n = 0;
    if phys < crate::addr::LOW_IDENTITY_LIMIT {
        out[n] = phys;
        n += 1;
    }
    if phys < KERNEL_WINDOW_SPAN {
        out[n] = KERNEL_VIRT_BASE.wrapping_add(phys);
        n += 1;
    }
    if crate::addr::direct_map_live() {
        out[n] = phys | crate::addr::KERNEL_DIRECT_MAP_BASE;
        n += 1;
    }
    (out, n)
}

/// Is `phys` writable through **any** kernel window?
///
/// `None` means the walk could not answer (no reserved root, or a window this
/// module does not model). The all-windows quantifier is the point: a pack
/// whose identity alias is read-only but which is still writable at
/// `KERNEL_VIRT_BASE + phys` has no W^X boundary at all, and a per-window
/// answer would report success anyway.
pub fn alias_is_writable(phys: u64) -> Option<bool> {
    let root = crate::bpf_text::kernel_root_for_mapping()?;
    #[cfg(target_arch = "x86_64")]
    {
        let (vas, n) = alias_vas(phys);
        if n == 0 {
            return None;
        }
        let mut any = false;
        for va in vas.iter().take(n) {
            // SAFETY: `root` is the recorded kernel root and `va` is a window
            // `init_mmu` built; the walk only reads.
            match unsafe { leaf_is_writable(root, *va) } {
                Some(w) => any |= w,
                None => return None,
            }
        }
        Some(any)
    }
    #[cfg(target_arch = "aarch64")]
    {
        use crate::aarch64::paging::PageTable;
        let va = phys | crate::KERNEL_PHYS_OFFSET;
        let i0 = ((va >> 39) & 0x1FF) as usize;
        let i1 = ((va >> 30) & 0x1FF) as usize;
        let i2 = ((va >> 21) & 0x1FF) as usize;
        // SAFETY: read-only walk of the live TTBR1 tree.
        unsafe {
            let l0 = &*root.kernel_ptr::<PageTable>();
            let e = l0.entries[i0];
            if !e.is_valid() {
                return None;
            }
            let l1 = &*e.addr().kernel_ptr::<PageTable>();
            let e = l1.entries[i1];
            if !e.is_valid() {
                return None;
            }
            let l2 = &*e.addr().kernel_ptr::<PageTable>();
            let leaf = l2.entries[i2];
            if !leaf.is_valid() || leaf.raw() & 0b10 != 0 {
                return None;
            }
            // AP[2] (bit 7) set = read-only.
            Some(leaf.raw() & (1 << 7) == 0)
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (root, phys);
        None
    }
}

/// Read-only twin of the walk in [`set_leaf_writable`].
#[cfg(target_arch = "x86_64")]
unsafe fn leaf_is_writable(root: PhysAddr, va: u64) -> Option<bool> {
    use crate::x86_64::paging::{PageTable, PtFlags, WalkIndices};
    let idx = WalkIndices::from_virt(VirtAddr::new(va));
    // SAFETY: read-only walk of live, identity-reachable page tables.
    unsafe {
        let pml4 = &*root.as_ptr::<PageTable>();
        let e = pml4.entries[idx.pml4];
        if !e.is_present() {
            return None;
        }
        let pdpt = &*e.addr().as_ptr::<PageTable>();
        let pe = pdpt.entries[idx.pdpt];
        if !pe.is_present() {
            return None;
        }
        if pe.flags().contains(PtFlags::HUGE_PAGE) {
            return Some(pe.flags().contains(PtFlags::WRITABLE));
        }
        let pd = &*pe.addr().as_ptr::<PageTable>();
        let de = pd.entries[idx.pd];
        if !de.is_present() {
            return None;
        }
        if de.flags().contains(PtFlags::HUGE_PAGE) {
            return Some(de.flags().contains(PtFlags::WRITABLE));
        }
        let pt = &*de.addr().as_ptr::<PageTable>();
        let te = pt.entries[idx.pt];
        if !te.is_present() {
            return None;
        }
        Some(te.flags().contains(PtFlags::WRITABLE))
    }
}

/// The scratch VA a given CPU pokes through. Test-visible so a smoke can
/// prove the window is gone once the copy returns.
#[doc(hidden)]
pub fn __poke_va_for_test(cpu: usize) -> u64 {
    poke_va(cpu)
}

#[cfg(target_arch = "x86_64")]
unsafe fn set_range_writable(
    root: PhysAddr,
    va_base: u64,
    len: u64,
    writable: bool,
) -> Result<(), PokeError> {
    let end = va_base + len;
    let mut va = va_base;
    while va < end {
        // Take a 2 MiB leaf whenever the whole block lies inside the request;
        // a hugepage-backed pack is exactly one such block, so the common case
        // touches one entry per window and needs at most one 1 GiB split.
        let allow_2m = va % TWO_MB == 0 && end - va >= TWO_MB;
        // SAFETY: forwarded caller contract.
        let step = unsafe { set_leaf_writable(root, va, allow_2m, writable)? };
        va += step;
    }

    // Invalidate the range we just rewrote, locally and on every peer.
    //
    // The flush inside `split_leaf` does **not** cover this. That one exists to
    // satisfy Linux's split → flush → change ordering and happens *before* the
    // permission store; and when no split was needed — the leaf was already the
    // right size, which is the common case once some earlier call demoted the
    // enclosing 1 GiB leaf — it does not happen at all. Without this, a CPU
    // that had touched the alias kept its writable entry and the protection was
    // silently inert. `smoke_text_poke_protect_round_trip` found exactly that:
    // `alias_is_writable` reported `false` (the page tables were right) while
    // the store still landed (the TLB was not).
    //
    // `invlpg_global_range` is synchronous — the range hook lands in
    // `shoot_range`, which spins for every peer's ack — so the alias is
    // unwritable everywhere by the time this returns, which is what `seal`'s
    // caller is entitled to assume.
    // SAFETY: every page in the range is a mapped kernel VA; INVLPG is always
    // legal at CPL=0.
    unsafe {
        crate::x86_64::paging::invlpg_global_range(VirtAddr::new(va_base), len.div_ceil(FOUR_KB));
    }
    Ok(())
}

/// Walk to the leaf covering `va`, demoting on the way down until the leaf is
/// no coarser than the caller can accept, then rewrite its `WRITABLE` bit.
/// Returns the size of the leaf that was touched.
#[cfg(target_arch = "x86_64")]
unsafe fn set_leaf_writable(
    root: PhysAddr,
    va: u64,
    allow_2m: bool,
    writable: bool,
) -> Result<u64, PokeError> {
    use crate::x86_64::paging::{PageTable, PageTableEntry, PtFlags, WalkIndices};

    // At most two demotions (1 GiB → 2 MiB → 4 KiB), so this cannot spin.
    loop {
        let idx = WalkIndices::from_virt(VirtAddr::new(va));
        // SAFETY: `root` is the live kernel root; page tables live in
        // identity-reachable RAM and every level below the top was built by
        // `init_mmu` or by `split_leaf` below.
        unsafe {
            let pml4 = &mut *root.as_mut_ptr::<PageTable>();
            let e = pml4.entries[idx.pml4];
            if !e.is_present() {
                return Err(PokeError::Walk);
            }
            let pdpt = &mut *e.addr().as_mut_ptr::<PageTable>();
            let pe = pdpt.entries[idx.pdpt];
            if !pe.is_present() {
                return Err(PokeError::Walk);
            }
            if pe.flags().contains(PtFlags::HUGE_PAGE) {
                split_leaf(&mut pdpt.entries[idx.pdpt], true)?;
                continue;
            }
            let pd = &mut *pe.addr().as_mut_ptr::<PageTable>();
            let de = pd.entries[idx.pd];
            if !de.is_present() {
                return Err(PokeError::Walk);
            }
            if de.flags().contains(PtFlags::HUGE_PAGE) {
                if allow_2m {
                    apply_writable(&mut pd.entries[idx.pd], writable);
                    return Ok(TWO_MB);
                }
                split_leaf(&mut pd.entries[idx.pd], false)?;
                continue;
            }
            let pt = &mut *de.addr().as_mut_ptr::<PageTable>();
            if !pt.entries[idx.pt].is_present() {
                return Err(PokeError::Walk);
            }
            apply_writable(&mut pt.entries[idx.pt], writable);
            let _ = PageTableEntry::EMPTY;
            return Ok(FOUR_KB);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn apply_writable(slot: &mut crate::x86_64::paging::PageTableEntry, writable: bool) {
    use crate::x86_64::paging::{PageTableEntry, PtFlags};
    let raw = slot.raw();
    let next = if writable {
        raw | PtFlags::WRITABLE.bits()
    } else {
        raw & !PtFlags::WRITABLE.bits()
    };
    *slot = PageTableEntry::from_raw(next);
}

/// Replace a huge leaf with a table whose 512 entries translate **identically**
/// to it, then flush every CPU before anybody changes an attribute.
///
/// This is `__split_large_page`. The identical-translation property is what
/// makes the swap legal without break-before-make (Intel's TLB application
/// note only makes behaviour undefined when the large and small translations
/// *differ*), and the synchronous flush at the end is what makes it legal for
/// the caller to change an attribute afterwards.
#[cfg(target_arch = "x86_64")]
unsafe fn split_leaf(
    slot: &mut crate::x86_64::paging::PageTableEntry,
    from_1g: bool,
) -> Result<(), PokeError> {
    use crate::x86_64::paging::{flush_user_tlb_all_cpus, PageTable, PageTableEntry, PtFlags};

    const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
    /// PAT bit position in a huge (PS=1) leaf. In a 4 KiB PTE the PAT bit
    /// moves to bit 7, so a leaf with a non-default memory type would need the
    /// bit relocated; every window this module splits is plain write-back, so
    /// refuse rather than silently changing the memory type of 512 children.
    const HUGE_PAT: u64 = 1 << 12;

    let old = slot.raw();
    if old & HUGE_PAT != 0 {
        return Err(PokeError::Unsupported);
    }
    let base = old & ADDR_MASK;
    let flags = old & !ADDR_MASK;

    let frame = crate::frame::alloc_frame().map_err(|_| PokeError::NoFrame)?;
    let table = frame.start_address();
    crate::frame::__pagetable_register(table.raw());

    let step = if from_1g { TWO_MB } else { FOUR_KB };
    // A 1 GiB leaf splits into 2 MiB leaves, which keep PS. A 2 MiB leaf
    // splits into 4 KiB PTEs, where bit 7 is PAT rather than PS and must be
    // clear (checked above via HUGE_PAT: the source leaf is write-back, so the
    // children are too).
    let child_flags = if from_1g {
        flags
    } else {
        flags & !PtFlags::HUGE_PAGE.bits()
    };

    // SAFETY: a frame the buddy just handed us exclusively, identity-reachable
    // like every other page table in this tree.
    unsafe {
        let t = &mut *table.as_mut_ptr::<PageTable>();
        for (i, slot) in t.entries.iter_mut().enumerate() {
            *slot = PageTableEntry::from_raw((base + (i as u64) * step) | child_flags);
        }
    }

    // One naturally-aligned 8-byte store: no CPU can observe a half-built
    // entry, and what it observes before and after translates the same.
    // Intermediate entries carry `PRESENT | WRITABLE` and nothing else —
    // x86 ANDs R/W and U/S down the walk and ORs NX up it, so the real
    // permissions stay where they belong, on the leaves. This is Linux's
    // `_KERNPG_TABLE`.
    *slot = PageTableEntry::new(table, PtFlags::PRESENT | PtFlags::WRITABLE);

    // "Do a global flush tlb after splitting the large page and before we do
    // the actual change page attribute in the PTE." — `__split_large_page`.
    // Synchronous: local INVPCID/CR3 flush, then `shoot_full`, which waits for
    // every peer's ack.
    // SAFETY: CPL=0.
    unsafe {
        flush_user_tlb_all_cpus();
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
unsafe fn set_alias_writable(phys: u64, len: u64, writable: bool) -> Result<(), PokeError> {
    use crate::aarch64::paging::{
        tlb_invalidate_va_all_asids_inner_shareable, PageTable, PageTableEntry, PtFlags,
    };

    if !can_protect(phys, len) {
        return Err(PokeError::Unsupported);
    }
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(PokeError::NotReserved)?;

    // AP[2:1] live in bits 7:6. `AP_RW_EL1` is 0b00, `AP_RO_EL1` is 0b10.
    const AP_MASK: u64 = 0b11 << 6;

    let mut off = 0u64;
    while off < len {
        let va = (phys + off) | crate::KERNEL_PHYS_OFFSET;
        let i0 = ((va >> 39) & 0x1FF) as usize;
        let i1 = ((va >> 30) & 0x1FF) as usize;
        let i2 = ((va >> 21) & 0x1FF) as usize;
        // SAFETY: `root` is the live TTBR1 L0; `boot.S` built L1[1] as a table
        // of 2 MiB blocks covering the whole RAM window.
        unsafe {
            let l0 = &mut *root.kernel_mut_ptr::<PageTable>();
            let e = l0.entries[i0];
            if !e.is_valid() {
                return Err(PokeError::Walk);
            }
            let l1 = &mut *e.addr().kernel_mut_ptr::<PageTable>();
            let e = l1.entries[i1];
            if !e.is_valid() {
                return Err(PokeError::Walk);
            }
            let l2 = &mut *e.addr().kernel_mut_ptr::<PageTable>();
            let leaf = l2.entries[i2];
            if !leaf.is_valid() {
                return Err(PokeError::Walk);
            }
            // Bit 1 clear at L2 means "block", set means "table". A table here
            // would mean somebody already split this block; this module never
            // does, and rewriting AP on a table descriptor would restrict the
            // whole subtree rather than one block.
            if leaf.raw() & 0b10 != 0 {
                return Err(PokeError::Unsupported);
            }
            let ap = if writable {
                PtFlags::AP_RW_EL1.bits()
            } else {
                PtFlags::AP_RO_EL1.bits()
            };
            l2.entries[i2] = PageTableEntry::from_raw((leaf.raw() & !AP_MASK) | ap);
        }
        // `tlbi vaae1is` is inner-shareable and covers every ASID — the hardware
        // broadcasts it — and the primitive brackets it with `dsb ishst` /
        // `dsb ish; isb`, so the
        // descriptor store is visible before the invalidation and the
        // invalidation has completed everywhere before we return. No IPI, and
        // no break-before-make: only AP changed, which ARM permits.
        for page in 0..(TWO_MB / FOUR_KB) {
            // SAFETY: TLB invalidation is always legal at EL1.
            unsafe {
                tlb_invalidate_va_all_asids_inner_shareable(VirtAddr::new(
                    ((phys + off) | crate::KERNEL_PHYS_OFFSET) + page * FOUR_KB,
                ));
            }
        }
        off += TWO_MB;
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn set_alias_writable(_phys: u64, _len: u64, _writable: bool) -> Result<(), PokeError> {
    Err(PokeError::Unsupported)
}

// ── The poke window ────────────────────────────────────────────────────
//
// One 4 KiB scratch VA per CPU, carved out of the BPF text slot above the
// 1 GiB `bpf_text` hands out packs from. The slot's top-level entry is already
// present in every address space (`reserve_kernel_slots`, §4.1), so mapping
// here needs no new PML4/L0 entry and is visible under whatever root is
// current.
//
// Per-CPU rather than one global scratch VA on purpose. A single shared VA
// would need a cross-CPU shootdown on every teardown, because a peer that used
// it earlier could hold a stale translation to a *different* frame. With one
// VA per CPU only its owner ever forms a translation for it, so a local INVLPG
// after each map and each unmap is exactly sufficient — which is also why
// Linux's `text_poke` uses a per-CPU fixmap slot rather than a global one.
//
// Each slot is two pages apart so an off-by-one page never lands in a peer's
// window; the odd page is never mapped.

/// Base of the poke window: immediately above the pack region.
const POKE_VA_BASE: u64 = crate::bpf_text::BPF_TEXT_BASE + crate::bpf_text::BPF_TEXT_USABLE;

/// Scratch VA owned by `cpu`.
fn poke_va(cpu: usize) -> u64 {
    let i = cpu.min(narf_lib::percpu::MAX_CPUS - 1) as u64;
    POKE_VA_BASE + i * 2 * FOUR_KB
}

/// Set once a poke has actually run, so a smoke can tell "the poke path is
/// wired" from "the poke path exists but nothing ever took it".
static POKE_USED: AtomicBool = AtomicBool::new(false);

/// Whether [`poke_copy`] / [`poke_fill`] have ever run.
pub fn poke_used() -> bool {
    POKE_USED.load(Ordering::Acquire)
}

/// Copy `src` into physical memory starting at `dst_phys`, through a transient
/// per-CPU RW+NX alias.
///
/// The write window is **one 4 KiB frame at a time**, mapped immediately
/// before the `copy_nonoverlapping` and unmapped immediately after, at a VA no
/// other CPU can reach.
///
/// # Safety
/// - `[dst_phys, dst_phys + src.len())` must be memory the caller owns.
/// - Interrupts must be masked for the duration (in practice: the caller holds
///   an `IrqSafeSpinLock`). The scratch VA is per-CPU state; an interrupt that
///   migrated or re-entered this path would map a peer's frame into this
///   CPU's slot.
pub unsafe fn poke_copy(dst_phys: u64, src: &[u8]) -> Result<(), PokeError> {
    // SAFETY: forwarded caller contract; `fill` is `None` so the source drives.
    unsafe { poke_run(dst_phys, src.len(), Some(src), None) }
}

/// Fill `[dst_phys, dst_phys + len)` with `pattern` repeated, through the same
/// window. Used for the trap-fill of freed program bodies, which has to work
/// on a pack whose alias is already read-only.
///
/// # Safety
/// Same contract as [`poke_copy`].
pub unsafe fn poke_fill(dst_phys: u64, len: usize, pattern: [u8; 4]) -> Result<(), PokeError> {
    // SAFETY: forwarded caller contract.
    unsafe { poke_run(dst_phys, len, None, Some(pattern)) }
}

unsafe fn poke_run(
    dst_phys: u64,
    len: usize,
    src: Option<&[u8]>,
    pattern: Option<[u8; 4]>,
) -> Result<(), PokeError> {
    if len == 0 {
        return Ok(());
    }
    let root = crate::bpf_text::kernel_root_for_mapping().ok_or(PokeError::NotReserved)?;
    let va = poke_va(narf_lib::percpu::current_cpu());

    let mut done = 0usize;
    while done < len {
        let p = dst_phys + done as u64;
        let page = p & !(FOUR_KB - 1);
        let off = (p & (FOUR_KB - 1)) as usize;
        let run = core::cmp::min(FOUR_KB as usize - off, len - done);

        // Tear down anything left here first. `map_4kb` refuses a present leaf
        // (`AlreadyMapped`), so a single leaked window — an `unmap` that failed
        // on some earlier call — would otherwise wedge every subsequent poke on
        // this CPU *and* leave a permanently writable alias of whatever it last
        // pointed at. Self-healing is cheap; the failure it prevents is not.
        // SAFETY: unmapping this CPU's own scratch VA; the error case (nothing
        // was mapped) is the expected one and is discarded.
        unsafe {
            let _ = unmap_poke_page(root, va);
        }
        // SAFETY: `va` is this CPU's private scratch page inside the reserved
        // BPF text slot; nothing else maps it. `map_4kb` INVLPGs locally, and
        // a fresh mapping needs nothing more — no peer has a translation for
        // this VA to invalidate.
        unsafe { map_poke_page(root, va, PhysAddr::new(page))? };

        // SAFETY: the whole 4 KiB page is mapped RW+NX and `off + run <= 4096`.
        unsafe {
            let dst = (va as *mut u8).add(off);
            match (src, pattern) {
                (Some(s), _) => core::ptr::copy_nonoverlapping(s[done..].as_ptr(), dst, run),
                (None, Some(pat)) => {
                    for i in 0..run {
                        dst.add(i).write_volatile(pat[(done + i) % pat.len()]);
                    }
                }
                (None, None) => {}
            }
        }

        // Tear the window down before returning to the caller, and before the
        // next page's map, so at most one frame is writable at a time.
        // SAFETY: `va` was mapped by `map_poke_page` immediately above.
        unsafe { unmap_poke_page(root, va)? };

        done += run;
    }
    POKE_USED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn map_poke_page(root: PhysAddr, va: u64, phys: PhysAddr) -> Result<(), PokeError> {
    use crate::x86_64::paging::{map_4kb, PtFlags};
    // NO_EXEC explicitly: the BPF text slot's top-level entry deliberately
    // carries no NX (the pack VAs have to be executable), so a leaf that
    // forgot it would be a fresh RWX kernel window.
    let flags = PtFlags::WRITABLE | PtFlags::NO_EXEC;
    // SAFETY: `root` is the recorded kernel root and `va` is this CPU's
    // scratch page, which is unmapped on entry.
    unsafe {
        map_4kb(root, VirtAddr::new(va), phys, flags).map_err(|_| PokeError::Walk)?;
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
unsafe fn unmap_poke_page(root: PhysAddr, va: u64) -> Result<(), PokeError> {
    use crate::x86_64::paging::unmap_4kb_local;
    // `_local`: only this CPU can have a translation for this VA, so the
    // cross-CPU broadcast `unmap_4kb` would do is pure cost. The frame is not
    // being freed — it stays owned by the pack — so the "broadcast before
    // reuse" clause of `unmap_4kb_local`'s contract does not apply.
    // SAFETY: `va` was mapped through this root immediately above.
    unsafe {
        unmap_4kb_local(root, VirtAddr::new(va)).map_err(|_| PokeError::Walk)?;
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
unsafe fn map_poke_page(root: PhysAddr, va: u64, phys: PhysAddr) -> Result<(), PokeError> {
    use crate::aarch64::paging::{map_4kb, PtFlags};
    let flags = PtFlags::AP_RW_EL1 | PtFlags::UXN | PtFlags::PXN;
    // SAFETY: `root` is the recorded TTBR1 root and `va` is this CPU's
    // scratch page, unmapped on entry.
    unsafe {
        map_4kb(root, VirtAddr::new(va), phys, flags).map_err(|_| PokeError::Walk)?;
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
unsafe fn unmap_poke_page(root: PhysAddr, va: u64) -> Result<(), PokeError> {
    use crate::aarch64::paging::unmap_4kb;
    // SAFETY: `va` was mapped through this root immediately above.
    unsafe {
        unmap_4kb(root, VirtAddr::new(va)).map_err(|_| PokeError::Walk)?;
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn map_poke_page(_root: PhysAddr, _va: u64, _phys: PhysAddr) -> Result<(), PokeError> {
    Err(PokeError::Unsupported)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn unmap_poke_page(_root: PhysAddr, _va: u64) -> Result<(), PokeError> {
    Err(PokeError::Unsupported)
}

// ── In-kernel smokes ───────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Without `CR0.WP` every read-only kernel mapping in the tree — this
/// module's alias protection included — is advisory, because supervisor
/// stores ignore the R/W bit (Intel SDM Vol 3 §4.6.1).
///
/// Measured `CR0` on this kernel before the change was `0x80000011`: `PG` and
/// nothing else. This pins the fix rather than the intent, and it pins it on
/// whichever CPU the runner picks — `WP` is per-CPU state, so the AP path in
/// `_ap_start_rust` is as load-bearing as the BSP's.
#[cfg(target_arch = "x86_64")]
fn smoke_text_poke_write_protect_is_on() -> TestResult {
    if write_protect_enabled() {
        TestResult::Pass
    } else {
        TestResult::Fail("CR0.WP is clear — supervisor stores ignore read-only pages")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_text_poke_write_protect_is_on);

/// The poke window must (a) actually reach the target frame and (b) be gone by
/// the time the call returns.
///
/// (b) is the security-relevant half: a scratch RW alias that outlived the
/// copy would be a permanently writable alias of whatever it last pointed at,
/// which is the thing this module exists to remove. Checked by faulting on it,
/// not by reading a flag.
#[cfg(target_arch = "x86_64")]
fn smoke_text_poke_window_is_transient() -> TestResult {
    use core::arch::asm;
    use narf_arch::x86_64::probe;

    if crate::bpf_text::kernel_root_for_mapping().is_none() {
        return TestResult::Skip("BPF kernel VA slots not reserved");
    }
    let frame = match crate::frame::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Skip("frame allocator not initialised"),
    };
    let phys = frame.start_address();
    // SAFETY: a frame the buddy just handed us exclusively; zero it so the
    // read-back below cannot pass on stale contents.
    unsafe {
        core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
    }

    let payload: [u8; 8] = [0xA5; 8];
    // SAFETY: `phys` is ours, and kernel tests run with interrupts enabled but
    // no other user of this CPU's poke slot — `poke_run` maps and unmaps
    // within the call.
    let wrote = unsafe { poke_copy(phys.raw() + 16, &payload) };

    // SAFETY: the frame is mapped RW through the linear map (it is an ordinary
    // buddy frame, not a protected pack).
    let seen = unsafe {
        let base = phys.kernel_ptr::<u8>();
        [
            core::ptr::read_volatile(base.add(15)),
            core::ptr::read_volatile(base.add(16)),
            core::ptr::read_volatile(base.add(23)),
            core::ptr::read_volatile(base.add(24)),
        ]
    };

    let va = poke_va(narf_lib::percpu::current_cpu());
    let recovery: u64;
    // SAFETY: LEA of a local label.
    unsafe {
        asm!(
            "lea {r}, [66f + rip]",
            r = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);
    // SAFETY: expected to #PF on a not-present page; the probe redirects.
    unsafe {
        asm!(
            "mov {t}, qword ptr [{p}]",
            "66:",
            t = out(reg) _,
            p = in(reg) va,
            options(nostack),
        );
    }
    let caught = probe::disarm();

    crate::frame::free_frame(frame);

    if wrote.is_err() {
        return TestResult::Fail("poke_copy failed");
    }
    // Exactly the eight bytes asked for, and neither neighbour.
    if seen[1] != 0xA5 || seen[2] != 0xA5 {
        return TestResult::Fail("poke_copy did not reach the target frame");
    }
    if seen[0] != 0 || seen[3] != 0 {
        return TestResult::Fail("poke_copy wrote outside the requested range");
    }
    match caught.vector {
        Some(14) => TestResult::Pass,
        Some(_) => TestResult::Fail("wrong vector caught (not #PF)"),
        None => TestResult::Fail("the poke window is still mapped after the copy returned"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_text_poke_window_is_transient);

/// The `protect_ro` → `protect_rw` round trip, on a frame this test owns.
///
/// Deliberately **not** routed through `bpf_text`: a pack-level test depends on
/// the hugepage pool having a spare page and on no sibling smoke holding an
/// allocation in the same pack, so it skips on a busy boot and proves nothing.
/// A plain buddy frame is always available, and on any machine with more than
/// 1 GiB of RAM it lands inside a 1 GiB identity leaf — so protecting it
/// exercises the `__split_large_page` demotion twice over (1 GiB → 2 MiB →
/// 4 KiB) rather than merely flipping a bit on a leaf that was already the
/// right size.
///
/// Three assertions, in the order that makes each one mean something: the
/// alias reports unwritable, a store to it faults, and after `protect_rw` a
/// store to it succeeds. The last is the one that matters for the rest of the
/// kernel — `bpf_text::reclaim` calls `protect_rw` before frames go back to
/// the buddy, and a frame released still read-only is a fault in whichever
/// subsystem draws it next.
#[cfg(target_arch = "x86_64")]
fn smoke_text_poke_protect_round_trip() -> TestResult {
    use core::arch::asm;
    use narf_arch::x86_64::probe;

    if crate::bpf_text::kernel_root_for_mapping().is_none() {
        return TestResult::Skip("BPF kernel VA slots not reserved");
    }
    if !write_protect_enabled() {
        return TestResult::Fail("CR0.WP is clear — read-only kernel mappings are advisory");
    }
    let frame = match crate::frame::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Skip("frame allocator not initialised"),
    };
    let phys = frame.start_address();
    let ptr = phys.kernel_mut_ptr::<u8>();
    // SAFETY: an ordinary buddy frame we own, currently writable.
    unsafe { core::ptr::write_volatile(ptr, 0x11) };

    // SAFETY: the frame is ours; nothing else holds a kernel pointer to it.
    if unsafe { protect_ro(phys.raw(), 4096) }.is_err() {
        crate::frame::free_frame(frame);
        return TestResult::Fail("protect_ro failed");
    }
    let ro_reported = alias_is_writable(phys.raw());

    let mut recovery: u64;
    // SAFETY: LEA of a local label.
    unsafe {
        asm!("lea {r}, [44f + rip]", r = out(reg) recovery, options(nostack, preserves_flags));
    }
    probe::arm(recovery);
    // SAFETY: expected to #PF; the armed probe redirects to `44:`.
    unsafe {
        asm!(
            "mov byte ptr [{p}], 0x22",
            "44:",
            p = in(reg) ptr,
            options(nostack),
        );
    }
    let caught = probe::disarm();
    // SAFETY: still mapped, still readable.
    let after_blocked = unsafe { core::ptr::read_volatile(ptr) };

    // SAFETY: same range this test just protected.
    let restored = unsafe { protect_rw(phys.raw(), 4096) };
    let rw_reported = alias_is_writable(phys.raw());

    // The store that must now succeed. Armed anyway so a regression is a red
    // test rather than a dead kernel.
    // SAFETY: LEA of a local label.
    unsafe {
        asm!("lea {r}, [45f + rip]", r = out(reg) recovery, options(nostack, preserves_flags));
    }
    probe::arm(recovery);
    // SAFETY: the alias has just been restored to writable.
    unsafe {
        asm!(
            "mov byte ptr [{p}], 0x33",
            "45:",
            p = in(reg) ptr,
            options(nostack),
        );
    }
    let refaulted = probe::disarm().vector.is_some();
    // SAFETY: mapped for the whole test.
    let after_restored = unsafe { core::ptr::read_volatile(ptr) };

    crate::frame::free_frame(frame);

    if ro_reported != Some(false) {
        return TestResult::Fail("protect_ro returned Ok but the alias still reports writable");
    }
    match caught.vector {
        None => return TestResult::Fail("a store through a protected alias was allowed"),
        Some(14) => {}
        Some(_) => return TestResult::Fail("wrong vector caught (not #PF)"),
    }
    if caught.error_code & 0b11 != 0b11 {
        return TestResult::Fail("faulted, but not as a write to a present page");
    }
    if after_blocked != 0x11 {
        return TestResult::Fail("the blocked store landed anyway");
    }
    if restored.is_err() {
        return TestResult::Fail("protect_rw failed");
    }
    if rw_reported != Some(true) {
        return TestResult::Fail("protect_rw returned Ok but the alias still reports read-only");
    }
    if refaulted {
        return TestResult::Fail("a store faulted after protect_rw restored the alias");
    }
    if after_restored != 0x33 {
        return TestResult::Fail("the post-restore store did not land");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("memory", smoke_text_poke_protect_round_trip);

/// aarch64 twin of the round trip. No fault probe on this arch, so the check
/// is the reported permission plus an actual store landing after the restore —
/// and it needs a 2 MiB-aligned extent, because `can_protect` refuses anything
/// finer here (break-before-make; see the module docs).
#[cfg(target_arch = "aarch64")]
fn smoke_text_poke_protect_round_trip() -> TestResult {
    if crate::bpf_text::kernel_root_for_mapping().is_none() {
        return TestResult::Skip("BPF kernel VA slots not reserved");
    }
    // A buddy order-9 block, not the hugepage pool: the pool is only populated
    // by `hugepages_2m=` on the cmdline, which the test runner does not pass,
    // so a pool-based test would skip on every run and prove nothing. Buddy
    // blocks are naturally aligned, which is what `can_protect` requires here.
    const ORDER_2M: u8 = 9;
    let block = match crate::frame::alloc_pages_on(0, ORDER_2M) {
        Ok(f) => f,
        Err(_) => return TestResult::Skip("no contiguous 2 MiB block to protect"),
    };
    let phys = block.start_address().raw();
    if phys % TWO_MB != 0 {
        crate::frame::free_pages(block, ORDER_2M);
        return TestResult::Skip("buddy block was not 2 MiB-aligned");
    }
    let ptr = PhysAddr::new(phys).kernel_mut_ptr::<u8>();
    // SAFETY: a hugepage the pool just handed us exclusively.
    unsafe { core::ptr::write_volatile(ptr, 0x11) };

    // SAFETY: the extent is ours and is exactly one 2 MiB block descriptor, so
    // this is a permission-only change — no block split, no BBM.
    let ro = unsafe { protect_ro(phys, TWO_MB) };
    let ro_reported = alias_is_writable(phys);
    // SAFETY: same extent.
    let rw = unsafe { protect_rw(phys, TWO_MB) };
    let rw_reported = alias_is_writable(phys);
    // SAFETY: the alias has just been restored to writable.
    unsafe { core::ptr::write_volatile(ptr, 0x33) };
    // SAFETY: mapped throughout.
    let seen = unsafe { core::ptr::read_volatile(ptr) };

    crate::frame::free_pages(block, ORDER_2M);

    if ro.is_err() {
        return TestResult::Fail("protect_ro failed");
    }
    if ro_reported != Some(false) {
        return TestResult::Fail("protect_ro returned Ok but the alias still reports writable");
    }
    if rw.is_err() {
        return TestResult::Fail("protect_rw failed");
    }
    if rw_reported != Some(true) {
        return TestResult::Fail("protect_rw returned Ok but the alias still reports read-only");
    }
    if seen != 0x33 {
        return TestResult::Fail("the post-restore store did not land");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("memory", smoke_text_poke_protect_round_trip);

/// aarch64 twin of the reachability half. There is no fault probe on this
/// arch, so the teardown half is not checkable here; what is checkable is that
/// the copy lands where it was asked to and nowhere else.
#[cfg(target_arch = "aarch64")]
fn smoke_text_poke_window_reaches_the_frame() -> TestResult {
    if crate::bpf_text::kernel_root_for_mapping().is_none() {
        return TestResult::Skip("BPF kernel VA slots not reserved");
    }
    let frame = match crate::frame::alloc_frame() {
        Ok(f) => f,
        Err(_) => return TestResult::Skip("frame allocator not initialised"),
    };
    let phys = frame.start_address();
    // SAFETY: a frame the buddy just handed us exclusively.
    unsafe {
        core::ptr::write_bytes(phys.kernel_mut_ptr::<u8>(), 0, 4096);
    }
    let payload: [u8; 8] = [0xA5; 8];
    // SAFETY: `phys` is ours for the duration.
    let wrote = unsafe { poke_copy(phys.raw() + 16, &payload) };
    // SAFETY: ordinary buddy frame, readable through the linear map.
    let seen = unsafe {
        let base = phys.kernel_ptr::<u8>();
        [
            core::ptr::read_volatile(base.add(15)),
            core::ptr::read_volatile(base.add(16)),
            core::ptr::read_volatile(base.add(23)),
            core::ptr::read_volatile(base.add(24)),
        ]
    };
    crate::frame::free_frame(frame);
    if wrote.is_err() {
        return TestResult::Fail("poke_copy failed");
    }
    if seen[1] != 0xA5 || seen[2] != 0xA5 {
        return TestResult::Fail("poke_copy did not reach the target frame");
    }
    if seen[0] != 0 || seen[3] != 0 {
        return TestResult::Fail("poke_copy wrote outside the requested range");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("memory", smoke_text_poke_window_reaches_the_frame);

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poke_window_sits_above_the_pack_region() {
        // A poke slot that overlapped the pack region would map a scratch
        // frame on top of live JIT text. POKE_VA_BASE is defined at the exact
        // end of that region; this test checks the far endpoint.
        let last = poke_va(narf_lib::percpu::MAX_CPUS - 1);
        assert!(last < crate::bpf_text::BPF_TEXT_BASE + crate::bpf_text::SLOT_SPAN);
    }

    #[test]
    fn poke_slots_do_not_collide() {
        for cpu in 1..narf_lib::percpu::MAX_CPUS {
            assert!(poke_va(cpu) >= poke_va(cpu - 1) + 2 * FOUR_KB);
        }
    }

    #[test]
    fn can_protect_rejects_empty_ranges() {
        assert!(!can_protect(0x1000, 0));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_refuses_sub_block_granularity() {
        // The break-before-make refusal, as a property rather than a comment.
        assert!(!can_protect(TWO_MB, FOUR_KB));
        assert!(!can_protect(TWO_MB + FOUR_KB, TWO_MB));
        assert!(can_protect(TWO_MB, TWO_MB));
    }
}
