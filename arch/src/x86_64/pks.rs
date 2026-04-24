//! Protection Keys for Supervisor — x86_64 backend for `arch/` spec's
//! `DomainPrimitive` trait.
//!
//! PKS gates supervisor accesses through IA32_PKRS: each of the 16
//! protection-key domains has a 2-bit rights field (bit 2n = WD, bit
//! 2n+1 = AD). A PTE's PK field (bits 59–62) selects which domain a
//! page belongs to; the PKRS rights for that domain determine whether
//! the access is allowed.
//!
//! Stage 2 invariants this module upholds:
//!   - CR4.PKS is set (the caller verified CPUID first and flipped the
//!     bit; see `frame/` boot path).
//!   - `save` / `restore` take a `u64` snapshot of IA32_PKRS. The
//!     scheduler calls these around context switches so each task sees
//!     its own rights view — see `scheduler/` §4 invariants.
//!   - `set_rights` mutates one domain's 2 bits without touching the
//!     other 15 domains' rights.

use core::fmt;

use crate::x86_64::msr::{rdmsr, wrmsr, IA32_PKRS};

/// Saved PKRS value. `Copy` per `DomainPrimitive::SavedState`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct SavedPkrs(pub u64);

/// Per-domain supervisor rights. Both flags false = "access allowed".
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct DomainRights {
    /// Write-Disable: writes to pages tagged with this domain fault.
    pub no_write: bool,
    /// Access-Disable: reads *and* writes to pages tagged with this
    /// domain fault. If both `no_access` and `no_write` are set, the
    /// stronger (no_access) wins — hardware already behaves this way.
    pub no_access: bool,
}

impl DomainRights {
    pub const ALLOW_ALL: Self = Self { no_write: false, no_access: false };
    pub const READ_ONLY: Self = Self { no_write: true,  no_access: false };
    pub const DENY_ALL:  Self = Self { no_write: true,  no_access: true  };

    const fn encode(self) -> u64 {
        (self.no_write  as u64)      |
        ((self.no_access as u64) << 1)
    }

    const fn decode(bits: u64) -> Self {
        Self {
            no_write:  bits & 0b01 != 0,
            no_access: bits & 0b10 != 0,
        }
    }
}

impl fmt::Display for DomainRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.no_access, self.no_write) {
            (true,  _)     => f.write_str("deny"),
            (false, true)  => f.write_str("r-"),
            (false, false) => f.write_str("rw"),
        }
    }
}

/// Snapshot the live PKRS into `SavedPkrs`.
///
/// # Safety
/// CR4.PKS must be set (otherwise RDMSR(IA32_PKRS) raises #GP).
#[inline]
pub unsafe fn save() -> SavedPkrs {
    // SAFETY: caller confirmed CR4.PKS=1.
    SavedPkrs(unsafe { rdmsr(IA32_PKRS) })
}

/// Restore a previously-saved PKRS value.
///
/// # Safety
/// Same CR4.PKS precondition as `save`.
#[inline]
pub unsafe fn restore(s: SavedPkrs) {
    // SAFETY: see save; also writing an arbitrary 32-bit bitmap to
    // the defined field of IA32_PKRS is always well-defined.
    unsafe { wrmsr(IA32_PKRS, s.0); }
}

/// Get rights for a single domain.
///
/// # Safety
/// Same CR4.PKS precondition. `domain` must be in 0..=15.
#[inline]
pub unsafe fn get_rights(domain: u8) -> DomainRights {
    debug_assert!(domain < 16, "domain must be in 0..=15");
    // SAFETY: PKS is enabled.
    let pkrs = unsafe { rdmsr(IA32_PKRS) };
    DomainRights::decode((pkrs >> (2 * domain as u32)) & 0b11)
}

/// Set rights for a single domain without touching the other 15. Reads
/// IA32_PKRS, masks the target domain's 2 bits, or-s in the encoded
/// value, writes back.
///
/// # Safety
/// Same CR4.PKS precondition. `domain` must be in 0..=15. On SMP this
/// must serialise with the scheduler's save/restore around context
/// switches — Stage 2 BSP-only callers are fine.
#[inline]
pub unsafe fn set_rights(domain: u8, rights: DomainRights) {
    debug_assert!(domain < 16, "domain must be in 0..=15");
    let shift = 2 * domain as u32;
    let mask  = !(0b11u64 << shift);
    // SAFETY: PKS is enabled.
    let current = unsafe { rdmsr(IA32_PKRS) };
    let next = (current & mask) | (rights.encode() << shift);
    unsafe { wrmsr(IA32_PKRS, next); }
}

/// Enter a domain scope: save the current PKRS, then write a new
/// PKRS that DENIES access to every domain except the two passed in.
/// Returns the saved state for restoration by `exit_domain`.
///
/// This is the canonical "I'm about to run driver code / touch driver
/// memory" call: the kernel's FRAME domain (0) stays reachable so
/// the caller can still access its own stack, globals, and the IDT;
/// the target driver's domain is allowed so its heap / buffers work;
/// every other domain faults.
///
/// Order matches `save() + set_rights(...)` but does it in a single
/// MSR write (atomic vs. IRQs arriving mid-sequence).
///
/// # Safety
/// CR4.PKS must be enabled. `kernel_domain` and `driver_domain` must
/// each be in 0..=15.
#[inline]
pub unsafe fn enter_domain(kernel_domain: u8, driver_domain: u8) -> SavedPkrs {
    debug_assert!(kernel_domain < 16 && driver_domain < 16);
    // SAFETY: CR4.PKS is on.
    let saved = unsafe { rdmsr(IA32_PKRS) };
    // Deny every domain (all 16 × AD|WD = 11) then clear the two we
    // want to allow. 0x5555_5555 would be "WD set for all"; we want
    // AD+WD (all bits) for every domain except the two.
    let mut new_pkrs: u64 = 0xFFFF_FFFF;
    new_pkrs &= !(0b11u64 << (2 * kernel_domain as u32));
    new_pkrs &= !(0b11u64 << (2 * driver_domain as u32));
    // SAFETY: see save.
    unsafe { wrmsr(IA32_PKRS, new_pkrs); }
    SavedPkrs(saved)
}

/// Exit a domain scope; restore the PKRS value captured by
/// `enter_domain`. Alias for `restore`, named for call-site symmetry.
#[inline]
pub unsafe fn exit_domain(saved: SavedPkrs) {
    // SAFETY: same as restore.
    unsafe { restore(saved); }
}
