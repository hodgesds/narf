//! Per-domain private VA mappings under the PCID enforcer.
//!
//! Each of the 16 NARF driver domains reserves one upper-half PML4
//! slot for its private VA range:
//!
//!   `PRIVATE_PML4_BASE + domain` ∈ {256..=271}
//!
//! At boot on AMD silicon (PCID path), after `pcid::set_domain_pml4`
//! registers 16 byte-cloned PML4s, we allocate a fresh private PDPT
//! per domain and install it ONLY in that domain's PML4 at the
//! corresponding slot. The other 15 PML4s have a not-present PML4E
//! at that slot, so an access from any other domain to a VA in
//! domain D's range #PFs at the very first level of the walk.
//!
//! Layout (each PML4 slot covers 512 GiB):
//!
//!   domain 0  → PML4[256] → 0xFFFF_8000_0000_0000 .. 0xFFFF_8080_0000_0000
//!   domain 1  → PML4[257] → 0xFFFF_8080_0000_0000 .. 0xFFFF_8100_0000_0000
//!   ...
//!   domain 15 → PML4[271] → 0xFFFF_8780_0000_0000 .. 0xFFFF_8800_0000_0000
//!
//! These slots were chosen because the bootstrap (mmu::init_mmu)
//! populates only PML4[0] and PML4[511]; everything in between is
//! free. Picking a contiguous block keeps the `va_in_domain_range`
//! check trivial and leaves slots 272..=510 for future use.
//!
//! ## Why this gives strict isolation
//!
//! When `enter_domain(0, D)` swaps CR3 to PML4[D], a load to a VA
//! in domain D's range walks through D's private PDPT/PD/PT subtree
//! — all of those tables are owned exclusively by D, so changes are
//! visible only when CR3 points at PML4[D]. When the same load
//! happens with CR3 pointing at any other PML4[D' != D], PML4[D']'s
//! entry at slot 256+D is zero (not present) and the CPU faults
//! before touching any downstream table. No software check, no race
//! window — a hardware #PF.
//!
//! ## What this does NOT do
//!
//!   * Mapping changes outside the per-domain range still go through
//!     the shared downstream tables (KAISER-style fan-out from the
//!     parent commit). That's the right behaviour for kernel-shared
//!     surfaces (frame allocator, IDT, kernel heap).
//!   * Cross-domain TLB shootdown isn't wired — single-CPU writes
//!     at boot are the only mutations today. Multi-CPU support
//!     comes with the IPI surface in a follow-up.
//!   * The aarch64 mirror (per-ASID TTBR0 with private subtree) is
//!     a future port; aarch64 with MTE doesn't need it because MTE
//!     enforces at the load instruction.

#![cfg(target_arch = "x86_64")]

use crate::paging::{map_4kb, MapError, PageTable, PageTableEntry, PtFlags};
use crate::{alloc_frame, FrameAllocError, PhysAddr, VirtAddr};

use narf_arch::x86_64::pcid;

/// PML4 slot reserved for domain 0's private VA range. Subsequent
/// domains use `PRIVATE_PML4_BASE + D`.
pub const PRIVATE_PML4_BASE: usize = 256;

/// Number of domains (matches `pcid::NUM_DOMAINS`, kept local to
/// avoid leaking the constant from `arch/`).
const NUM_DOMAINS: u8 = 16;

/// 512 GiB per PML4 slot.
const PML4_SLOT_SIZE: u64 = 1u64 << 39;

/// Errors from `init_per_domain_pdpts` / `map_domain_private`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DomainMapError {
    /// `domain` was outside 0..=15.
    BadDomain,
    /// `va` does not fall in `domain`'s private PML4 slot.
    AddressOutsideDomainRange,
    /// The named domain has no registered PML4 (boot did not run, or
    /// PCID enforcer is not active on this CPU).
    NoPml4Registered,
    /// `domain`'s private PDPT slot in the PML4 is empty —
    /// `init_per_domain_pdpts` has not been called for this domain.
    PdptNotInstalled,
    /// Frame allocator could not satisfy a fresh PDPT/PD/PT alloc.
    FrameExhausted,
    /// Underlying `map_4kb` rejected the call.
    Map(MapError),
}

impl From<FrameAllocError> for DomainMapError {
    fn from(_: FrameAllocError) -> Self {
        DomainMapError::FrameExhausted
    }
}

impl From<MapError> for DomainMapError {
    fn from(e: MapError) -> Self {
        DomainMapError::Map(e)
    }
}

/// Compute the start of `domain`'s private VA range. Returns `None`
/// for an out-of-range domain id.
pub const fn domain_va_base(domain: u8) -> Option<u64> {
    if domain >= NUM_DOMAINS {
        return None;
    }
    // Sign-extend bit 47 to bits 63..=48 to keep the address canonical.
    // (PRIVATE_PML4_BASE + D) << 39, with bit 47 set (since 256 = bit 47).
    let slot = (PRIVATE_PML4_BASE as u64) + (domain as u64);
    Some(0xFFFF_0000_0000_0000 | (slot << 39))
}

/// True if `va` falls inside `domain`'s 512 GiB private range.
pub fn va_in_domain_range(domain: u8, va: VirtAddr) -> bool {
    match domain_va_base(domain) {
        Some(base) => va.raw() >= base && va.raw() < base.wrapping_add(PML4_SLOT_SIZE),
        None => false,
    }
}

/// Install a fresh private PDPT into every registered domain's PML4
/// at the domain-specific slot. After this returns, each domain's
/// private VA range is reachable *only* through that domain's PML4.
///
/// Idempotent: if a domain's PDPT slot is already populated, it is
/// left alone (so re-running this function — e.g. from a
/// re-initialisation path — does not double-allocate).
///
/// # Safety
/// - Must be called after `narf_arch::x86_64::pcid::init` and after
///   `set_domain_pml4` has registered all 16 domains.
/// - Identity map must still cover the freshly-allocated PDPT frames
///   (Stage-1 boot PML4 covers the low 4 GiB, which is sufficient).
/// - BSP-only at the time of call; no APs racing through `enter_domain`.
pub unsafe fn init_per_domain_pdpts() -> Result<u8, DomainMapError> {
    let mut installed = 0u8;
    for domain in 0..NUM_DOMAINS {
        let pml4_phys = pcid::get_domain_pml4(domain);
        if pml4_phys == 0 {
            // PCID enforcer not configured for this domain; skip.
            continue;
        }
        let slot_idx = PRIVATE_PML4_BASE + domain as usize;

        // SAFETY: the PML4 page is reached through the direct map.
        let pml4 = unsafe { &mut *PhysAddr::new(pml4_phys).kernel_mut_ptr::<PageTable>() };
        if pml4.entries[slot_idx].is_present() {
            // Already installed — count it for the boot banner.
            installed += 1;
            continue;
        }

        // Allocate + zero a fresh PDPT for this domain.
        let pdpt_frame = alloc_frame()?;
        let pdpt_addr = pdpt_frame.start_address();
        // The 4 KiB identity-map covers `pdpt_addr`, so the raw
        // pointer is valid for `PageTable`-sized writes.
        PageTable::zero_at(pdpt_addr.kernel_mut_ptr::<PageTable>());

        // Install the private PDPT in this domain's PML4 only.
        let entry = PageTableEntry::new(pdpt_addr, PtFlags::PRESENT | PtFlags::WRITABLE);
        pml4.entries[slot_idx] = entry;
        installed += 1;
    }
    Ok(installed)
}

/// Map a 4 KiB physical frame into `domain`'s private VA range. The
/// virtual address must fall inside `domain`'s 512-GiB private slot;
/// the underlying page-table walk happens against `domain`'s PML4.
///
/// Subsequent `enter_domain(_, domain)` calls expose the mapping;
/// any other domain accessing `va` will fault on the missing PML4E
/// at slot 256+domain.
///
/// # Safety
/// - PCID enforcer must be active and `init_per_domain_pdpts` must
///   have run.
/// - Same identity-map preconditions as the underlying `map_4kb`
///   (Stage 1 boot PML4 covers the low 4 GiB).
pub unsafe fn map_domain_private(
    domain: u8,
    va: VirtAddr,
    pa: PhysAddr,
    flags: PtFlags,
) -> Result<(), DomainMapError> {
    if domain >= NUM_DOMAINS {
        return Err(DomainMapError::BadDomain);
    }
    if !va_in_domain_range(domain, va) {
        return Err(DomainMapError::AddressOutsideDomainRange);
    }
    let pml4_phys = pcid::get_domain_pml4(domain);
    if pml4_phys == 0 {
        return Err(DomainMapError::NoPml4Registered);
    }

    // SAFETY: pml4_phys is identity-mapped; we just verified the VA
    // lies in this domain's slot, so the walk will hit the
    // domain-private PDPT subtree.
    // SAFETY: Valid memory or trusted environment
    let pml4 = unsafe { &*PhysAddr::new(pml4_phys).kernel_ptr::<PageTable>() };
    let slot_idx = PRIVATE_PML4_BASE + domain as usize;
    if !pml4.entries[slot_idx].is_present() {
        return Err(DomainMapError::PdptNotInstalled);
    }

    // SAFETY: per the function contract above; map_4kb walks the
    // PML4 at pml4_phys, which has the private PDPT installed for
    // this domain only, so any new PD/PT pages allocated below
    // inherit the privacy.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        map_4kb(PhysAddr::new(pml4_phys), va, pa, flags)?;
    }
    Ok(())
}

/// Look at every registered domain's PML4 and report whether slot
/// 256+domain is present. Used by smoke tests.
pub fn private_slot_status() -> [(u8, bool); NUM_DOMAINS as usize] {
    let mut out = [(0u8, false); NUM_DOMAINS as usize];
    for d in 0..NUM_DOMAINS {
        let pml4_phys = pcid::get_domain_pml4(d);
        let present = if pml4_phys != 0 {
            // SAFETY: pml4_phys identity-mapped; read-only.
            let pml4 = unsafe { &*PhysAddr::new(pml4_phys).kernel_ptr::<PageTable>() };
            pml4.entries[PRIVATE_PML4_BASE + d as usize].is_present()
        } else {
            false
        };
        out[d as usize] = (d, present);
    }
    out
}

/// Look up the PML4E for `domain`'s private slot in `inspector`'s
/// PML4 — used by smoke tests to verify cross-domain isolation
/// (the inspector's view should be `not present` for any other
/// domain's slot).
pub fn cross_domain_slot_present(inspector: u8, target_domain: u8) -> Option<bool> {
    if inspector >= NUM_DOMAINS || target_domain >= NUM_DOMAINS {
        return None;
    }
    let pml4_phys = pcid::get_domain_pml4(inspector);
    if pml4_phys == 0 {
        return None;
    }
    // SAFETY: pml4_phys identity-mapped; read-only.
    let pml4 = unsafe { &*PhysAddr::new(pml4_phys).kernel_ptr::<PageTable>() };
    Some(pml4.entries[PRIVATE_PML4_BASE + target_domain as usize].is_present())
}

// ---------------------------------------------------------------------------
// Confining shared upper-half slots
// ---------------------------------------------------------------------------
//
// `init_per_domain_pdpts` above confines slots 256..=271: domain D's slot is
// present only in D's own clone. Everything else in PML4[256..511] is copied
// BY VALUE by `new_user_pml4_on` and is therefore present, and permitted, in
// all sixteen clones. For most of that range that is exactly right — the frame
// allocator, the IDT and the kernel heap have to be reachable from whatever
// CR3 is current.
//
// It is not right for BPF. `bpf_text::reserve_kernel_slots` deliberately runs
// BEFORE the clones are built (see the ordering comment at its call site in
// `bare_main`) so that the BPF PML4 entries are captured by the snapshot,
// which leaves JIT'd text, the per-program stacks and the arena reachable from
// every domain. Under the PKS backend those same regions are confined by their
// PTE keys; PCID has no per-page equivalent, so the confinement has to happen
// at the only granularity PCID has — PML4 slot presence.
//
// The policy is a table rather than an open-coded check in the boot path
// because the same "which domains may see this region" question is answered
// independently by PKS (via `PtFlags::pk`) and by PCID (via slot presence).
// Two mechanisms, one intent: keeping the PCID half declarative at least makes
// the drift visible in one place instead of spread across a boot sequence.
//
// Why FRAME keeps them: FRAME is the TCB. The loader, the JIT and the verifier
// run on a task CR3 or under domain 0 and write BPF text before it is sealed;
// removing the slots from FRAME's clone would break loading, not harden it.
// Why BPF keeps them: `bpf::domain::enter` switches CR3 to the BPF clone
// around every program run (`bpf/src/prog.rs`), so that is the CR3 that must
// have the regions mapped.
//
// This deliberately does NOT touch task address spaces. They snapshot the same
// range, and the boot-path comment warns that a task CR3 holding a zero BPF
// entry triple-faults on the first BPF access. Kernel-side BPF work — map
// updates from syscalls, JIT writes, perf ring reads — runs on a task CR3 and
// must keep working. Only the sixteen domain clones are narrowed.

/// One confined shared slot: a PML4 slot that lives outside the private
/// range but must still be restricted to a named set of domains.
#[derive(Debug)]
pub struct ConfinedSlot {
    /// The upper-half PML4 slot index.
    pub slot: usize,
    /// Domains whose clone keeps the entry. Every other clone gets a zero.
    pub owners: &'static [u8],
}

/// The confined shared slots. Both BPF windows are owned by `FRAME` (the
/// TCB, which loads and JITs) and `BPF` (the CR3 that is current while a
/// program runs).
///
/// Each slot here has exactly one tenant, which is what makes the table
/// reviewable: `text_poke`'s per-CPU scratch windows used to live inside
/// `BPF_TEXT_PML4_SLOT` and were moved to `text_poke::POKE_PML4_SLOT` so
/// that confining a slot named for BPF does not silently also confine the
/// kernel's text-patching window. Anything added here later should get the
/// same treatment: confine a slot only when its whole span belongs to the
/// domains listed.
pub const CONFINED_SLOTS: &[ConfinedSlot] = &[
    ConfinedSlot {
        slot: crate::bpf_text::BPF_TEXT_PML4_SLOT,
        owners: &[0, 14], // DomainId::FRAME, DomainId::BPF
    },
    ConfinedSlot {
        slot: crate::bpf_text::BPF_ARENA_PML4_SLOT,
        owners: &[0, 14],
    },
];

/// Does `domain`'s clone keep the entry at `slot`?
///
/// True for every slot the table does not mention, which is the whole point:
/// the default stays "shared", and confinement is opt-in per slot.
pub const fn clone_keeps_slot(domain: u8, slot: usize) -> bool {
    let mut i = 0;
    while i < CONFINED_SLOTS.len() {
        let c = &CONFINED_SLOTS[i];
        if c.slot == slot {
            let mut j = 0;
            while j < c.owners.len() {
                if c.owners[j] == domain {
                    return true;
                }
                j += 1;
            }
            return false;
        }
        i += 1;
    }
    true
}

/// Apply [`CONFINED_SLOTS`] to every registered domain clone, zeroing each
/// entry the policy does not grant. Returns the number of entries cleared.
///
/// Idempotent: a slot already zero stays zero and is not counted twice.
///
/// # Safety
/// `pcid::set_domain_pml4` must have registered the clones, and this must
/// run on the BSP before any CPU can switch to a clone.
pub unsafe fn confine_shared_slots() -> u32 {
    let mut cleared = 0u32;
    for domain in 0..NUM_DOMAINS {
        let pml4_phys = pcid::get_domain_pml4(domain);
        if pml4_phys == 0 {
            continue;
        }
        // SAFETY: the PML4 page is reached through the direct map.
        let pml4 = unsafe { &mut *PhysAddr::new(pml4_phys).kernel_mut_ptr::<PageTable>() };
        for c in CONFINED_SLOTS {
            if clone_keeps_slot(domain, c.slot) {
                continue;
            }
            if pml4.entries[c.slot].is_present() {
                pml4.entries[c.slot] = PageTableEntry::EMPTY;
                cleared += 1;
            }
        }
    }
    cleared
}

/// Is the entry at `slot` present in `inspector`'s clone? `None` when
/// `inspector` is out of range or has no registered PML4.
///
/// The sibling of [`cross_domain_slot_present`] for slots outside the
/// private range; the kernel test uses it to assert the policy landed.
pub fn shared_slot_present(inspector: u8, slot: usize) -> Option<bool> {
    if inspector >= NUM_DOMAINS || slot >= 512 {
        return None;
    }
    let pml4_phys = pcid::get_domain_pml4(inspector);
    if pml4_phys == 0 {
        return None;
    }
    // SAFETY: pml4_phys reached through the direct map; read-only.
    let pml4 = unsafe { &*PhysAddr::new(pml4_phys).kernel_ptr::<PageTable>() };
    Some(pml4.entries[slot].is_present())
}
