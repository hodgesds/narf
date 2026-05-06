//! PCID-based domain enforcer — x86_64 fallback when CR4.PKS is
//! unavailable (AMD silicon, pre-SPR Intel).
//!
//! ## Model
//!
//! Each of the 16 NARF driver domains is mapped to a hardware PCID:
//!
//!   `PCID(domain) = domain + 1`
//!
//! PCID 0 stays as the "no-PCID-active" default that pre-PCIDE code
//! observed; we never assign it to a domain. Domain 0 (`FRAME`) gets
//! PCID 1, domain 15 gets PCID 16. The architecture allows up to 4096
//! PCIDs; capping at 16 keeps the map 1-to-1 with our domain count and
//! makes CR3 inspection trivial.
//!
//! Each domain *can* have its own PML4. The registry is sparse: when
//! a domain has no registered PML4, `enter_domain` falls back to the
//! bootstrap PML4. This keeps the CR3-swap path correct (no fault, no
//! divergent VAs) while the per-domain page-table allocator (a
//! `memory/`-side change) catches up. Once divergent PML4s are
//! registered, the same `enter_domain` call enforces real isolation
//! without any further wiring on this side.
//!
//! ## CR3 layout under PCIDE
//!
//! ```text
//!   bit 63           noflush — preserve previous PCID's TLB on write
//!   bits 51..=12     PML4 physical base (4 KiB-aligned)
//!   bits 11..=0      PCID (0..=4095)
//! ```
//!
//! `enter_domain` reads CR3, saves it, writes
//! `(target_pml4 & PML4_MASK) | (pcid as u64) | NOFLUSH`. `exit_domain`
//! writes the saved value back, again with `NOFLUSH` so the inner
//! domain's TLB stays warm for a re-entry.
//!
//! ## Open work (not in this commit)
//!
//!   * `memory/` does not yet allocate per-domain PML4s. Until it does,
//!     the registry is empty and every domain crossing lands back on
//!     the bootstrap PML4 — the CR3 swap is real (PCID changes, TLB
//!     tagging takes effect) but the *mappings* are identical, so
//!     spatial isolation is nominal. Capability + cap-table
//!     enforcement is unaffected.
//!   * IPI-coordinated TLB shootdown for cross-domain mapping changes
//!     is not yet implemented; today's framekernel makes mapping
//!     changes only at boot.
//!   * AP bring-up must call `enable_pcide` per CPU (CR4 is per-CPU).

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::cr;

const PML4_MASK: u64 = 0x000F_FFFF_FFFF_F000; // bits 51..=12
const PCID_MASK: u64 = 0x0000_0000_0000_0FFF; // bits 11..=0
const NOFLUSH: u64 = 1u64 << 63;

const NUM_DOMAINS: usize = 16;

/// "Active" flag — set by `init` once the bootstrap PML4 has been
/// recorded. Until then, `enter_domain` / `save` / `restore` behave as
/// no-ops (returning a sentinel) so very-early-boot code is safe to
/// link against the trait.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Bootstrap PML4 physical address (PML4_MASK bits only). Set by
/// `init`. Used as the fallback when a domain has no registered PML4.
static BOOTSTRAP_PML4: AtomicU64 = AtomicU64::new(0);

/// Per-domain PML4 registry. Zero = "no per-domain PML4; fall back to
/// bootstrap." Populated lazily by `set_domain_pml4` once `memory/`
/// can hand back cloned PML4s.
static PER_DOMAIN_PML4: [AtomicU64; NUM_DOMAINS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Saved enforcer state — opaque CR3 snapshot.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct SavedPcid(pub u64);

/// Per-domain rights, mirroring the PKS shape so trait users see the
/// same surface regardless of backend. The rights vocabulary maps to
/// per-PTE flags in the per-domain PML4 once divergent PTs land; today
/// the registry is empty, so rights are observed as ALLOW_ALL.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct DomainRights {
    pub no_write: bool,
    pub no_access: bool,
}

impl DomainRights {
    pub const ALLOW_ALL: Self = Self {
        no_write: false,
        no_access: false,
    };
    pub const READ_ONLY: Self = Self {
        no_write: true,
        no_access: false,
    };
    pub const DENY_ALL: Self = Self {
        no_write: true,
        no_access: true,
    };
}

impl fmt::Display for DomainRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.no_access, self.no_write) {
            (true, _) => f.write_str("deny"),
            (false, true) => f.write_str("r-"),
            (false, false) => f.write_str("rw"),
        }
    }
}

/// Enable CR4.PCIDE on the current CPU. Must be called exactly once
/// per CPU before any `enter_domain`/`exit_domain` call on that CPU,
/// and only after CR3 has been written with PCID = 0 (CR4.PCIDE=1
/// while CR3.PCID != 0 is a `#GP`).
///
/// # Safety
/// CPU must support PCID (Intel: CPUID.(EAX=1).ECX[17] = 1; AMD: same
/// bit, exposed since Zen). Caller must have ensured the current CR3
/// has PCID = 0 in its low 12 bits.
pub unsafe fn enable_pcide() {
    // SAFETY: BSP boot path; caller verified PCID support and CR3 PCID=0.
    unsafe {
        let cr4 = cr::read_cr4();
        cr::write_cr4(cr4 | cr::CR4_PCIDE);
    }
}

/// Record the bootstrap PML4 phys address (the one CR3 currently
/// references) and arm the enforcer. After this call, `enter_domain`
/// performs a real CR3 swap.
///
/// # Safety
/// Must be called once on the BSP after `enable_pcide` and before any
/// `enter_domain` use. The CR3 read here captures the current PML4 as
/// the fallback for unregistered domains.
pub unsafe fn init() {
    // SAFETY: caller ordering above.
    let cr3 = unsafe { cr::read_cr3() };
    BOOTSTRAP_PML4.store(cr3 & PML4_MASK, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Release);
}

/// Register a per-domain PML4. The address is masked to its 4 KiB
/// frame; the PCID for the domain is implicit (`domain + 1`). Pass
/// `0` to clear the registry slot back to "fall back to bootstrap."
///
/// # Safety
/// `pml4_phys` must be the physical base of a valid 4 KiB-aligned
/// PML4 page mapped writable in the current address space, and its
/// lower-half entries (kernel-shared mappings) must remain
/// bit-identical to the bootstrap PML4 for the same-VA invariant to
/// hold. `domain` must be in 0..=15.
pub unsafe fn set_domain_pml4(domain: u8, pml4_phys: u64) {
    debug_assert!((domain as usize) < NUM_DOMAINS);
    PER_DOMAIN_PML4[domain as usize].store(pml4_phys & PML4_MASK, Ordering::Relaxed);
}

/// Read back the registered PML4 for a domain (0 if unregistered).
/// Used by tests and diagnostics.
pub fn get_domain_pml4(domain: u8) -> u64 {
    debug_assert!((domain as usize) < NUM_DOMAINS);
    PER_DOMAIN_PML4[domain as usize].load(Ordering::Relaxed)
}

/// True after `init()` has run. Tests and the Pks-delegation path
/// consult this to decide whether the swap machinery is live.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Compute the CR3 value that points the current CPU at `domain`'s
/// page tables with the matching PCID and the noflush bit set.
fn cr3_for_domain(domain: u8) -> u64 {
    let pml4 = {
        let registered = PER_DOMAIN_PML4[domain as usize].load(Ordering::Relaxed);
        if registered != 0 {
            registered
        } else {
            BOOTSTRAP_PML4.load(Ordering::Relaxed)
        }
    };
    let pcid = (domain as u64 + 1) & PCID_MASK;
    (pml4 & PML4_MASK) | pcid | NOFLUSH
}

/// Snapshot CR3 for later restore.
///
/// # Safety
/// CPL=0; if PCID is enabled, the value will carry the live PCID and
/// the saved value can be written back via `restore`.
#[inline]
pub unsafe fn save() -> SavedPcid {
    if !is_active() {
        return SavedPcid(0);
    }
    // SAFETY: CR3 read at CPL=0.
    SavedPcid(unsafe { cr::read_cr3() })
}

/// Restore a previously-saved CR3. The noflush bit is added so the
/// destination PCID's TLB entries are preserved.
///
/// # Safety
/// `s` must originate from `save` on this CPU during the same CR4.PCIDE
/// epoch (i.e. PCIDE has not been toggled off + on between save and
/// restore).
#[inline]
pub unsafe fn restore(s: SavedPcid) {
    if !is_active() || s.0 == 0 {
        return;
    }
    // SAFETY: write back the snapshot CR3 with NOFLUSH set so the
    // outer domain's TLB does not get nuked.
    unsafe {
        cr::write_cr3(s.0 | NOFLUSH);
    }
}

/// Rights probe. Until per-domain PML4 divergence lands, every domain
/// reads as ALLOW_ALL.
#[inline]
pub unsafe fn get_rights(domain: u8) -> DomainRights {
    debug_assert!((domain as usize) < NUM_DOMAINS);
    DomainRights::ALLOW_ALL
}

/// Rights mutation. Land-site for the future "tighten PTEs in domain N's
/// PML4" path. Today: no-op.
#[inline]
pub unsafe fn set_rights(domain: u8, _rights: DomainRights) {
    debug_assert!((domain as usize) < NUM_DOMAINS);
}

/// Enter a domain scope: swap CR3 to the target domain's PML4 + PCID.
/// Returns the saved CR3 for `exit_domain`.
///
/// `kernel_domain` is currently advisory — under PCID, only one CR3
/// is live at a time, so the kernel's (FRAME) view is whatever the
/// driver's PML4 inherits in its lower half. Once divergent PML4s land
/// the kernel-domain hint will pick which lower-half template to use.
///
/// # Safety
/// CPL=0; CR4.PCIDE must be enabled (`init` was called). Both domain
/// numbers must be in 0..=15.
#[inline]
pub unsafe fn enter_domain(kernel_domain: u8, driver_domain: u8) -> SavedPcid {
    debug_assert!((kernel_domain as usize) < NUM_DOMAINS);
    debug_assert!((driver_domain as usize) < NUM_DOMAINS);
    if !is_active() {
        return SavedPcid(0);
    }
    // SAFETY: CR3 read+write at CPL=0; PCIDE on; PML4 phys mapped.
    let saved = unsafe { cr::read_cr3() };
    let next = cr3_for_domain(driver_domain);
    // SAFETY: see above; NOFLUSH set inside cr3_for_domain.
    unsafe {
        cr::write_cr3(next);
    }
    SavedPcid(saved)
}

/// Exit a domain scope; restore the CR3 captured by `enter_domain`.
///
/// # Safety
/// Same epoch as the matching `enter_domain`.
#[inline]
pub unsafe fn exit_domain(saved: SavedPcid) {
    // SAFETY: see restore.
    unsafe {
        restore(saved);
    }
}

// ── INVPCID instruction wrappers ───────────────────────────────────
//
// Spec: `memory/specification/asid-pcid-isolation.md` §3.1.
//
// Per SDM Vol 2 INVPCID layout: INVPCID r64, m128 — RAX is the
// type field, XMM/m128 carries (PCID in low 12 bits, linear
// address in next 64 bits).

#[repr(C, align(16))]
struct InvpcidDescriptor {
    pcid: u64,
    addr: u64,
}

#[inline]
unsafe fn invpcid_raw(typ: u64, desc: &InvpcidDescriptor) {
    // SAFETY: caller-asserted CPL=0 + INVPCID supported (CPUID(7).EBX[10]).
    unsafe {
        core::arch::asm!(
            "invpcid {t}, [{d}]",
            t = in(reg) typ,
            d = in(reg) desc,
            options(nostack, preserves_flags),
        );
    }
}

/// Type 0: invalidate the TLB entry for `addr` tagged with `pcid`.
///
/// # Safety
/// CPL = 0; INVPCID supported.
#[inline]
pub unsafe fn invpcid_addr(pcid: u16, addr: u64) {
    let d = InvpcidDescriptor {
        pcid: pcid as u64 & 0xFFF,
        addr,
    };
    // SAFETY: caller-asserted.
    unsafe {
        invpcid_raw(0, &d);
    }
}

/// Type 1: invalidate every TLB entry tagged with `pcid` on this CPU.
///
/// # Safety
/// CPL = 0; INVPCID supported.
#[inline]
pub unsafe fn invpcid_single(pcid: u16) {
    let d = InvpcidDescriptor {
        pcid: pcid as u64 & 0xFFF,
        addr: 0,
    };
    // SAFETY: caller-asserted.
    unsafe {
        invpcid_raw(1, &d);
    }
}

/// Type 2: invalidate every TLB entry on this CPU including globals.
///
/// # Safety
/// CPL = 0; INVPCID supported.
#[inline]
pub unsafe fn invpcid_all_with_globals() {
    let d = InvpcidDescriptor { pcid: 0, addr: 0 };
    // SAFETY: caller-asserted.
    unsafe {
        invpcid_raw(2, &d);
    }
}

/// Type 3: invalidate every TLB entry on this CPU excluding globals.
///
/// # Safety
/// CPL = 0; INVPCID supported.
#[inline]
pub unsafe fn invpcid_all_without_globals() {
    let d = InvpcidDescriptor { pcid: 0, addr: 0 };
    // SAFETY: caller-asserted.
    unsafe {
        invpcid_raw(3, &d);
    }
}

/// `true` iff the CPU supports the INVPCID instruction
/// (CPUID(7, 0).EBX[10]).
pub fn invpcid_supported() -> bool {
    // SAFETY: leaf 7 always defined.
    let (_, ebx, _, _) = unsafe { crate::x86_64::cpuid::cpuid(7, 0) };
    ebx & (1 << 10) != 0
}
