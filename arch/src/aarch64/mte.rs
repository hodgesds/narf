//! aarch64 MTE (Memory Tagging Extension) implementation.
//!
//! aarch64 MTE implements domain isolation via pointer tags and granule
//! tags. The `DomainPrimitive` trait on aarch64 manages the Tag Check
//! Fault (TCF) mode and TBI/ATA configuration.

use core::fmt;
use crate::aarch64::sysreg;

/// Saved MTE state. Stage-2 scope: just `SCTLR_EL1` (the TCF mode +
/// ATA bit live here and are universally accessible at EL1). Adding
/// `GCR_EL1` requires `-machine virt,mte=on` on QEMU + MTE level ≥ 2,
/// which isn't wired in our CI flow today — that's a Stage-3 follow-on.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct SavedMteState {
    pub sctlr: u64,
}

/// Per-domain access rights. On aarch64 MTE, "rights" are enforced via
/// page-table AP bits for R/W vs RO, and tag-match for access-deny.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct DomainRights {
    pub no_write:  bool,
    pub no_access: bool,
}

impl DomainRights {
    pub const ALLOW_ALL: Self = Self { no_write: false, no_access: false };
    pub const READ_ONLY: Self = Self { no_write: true,  no_access: false };
    pub const DENY_ALL:  Self = Self { no_write: true,  no_access: true  };
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

/// aarch64's concrete `DomainPrimitive` type.
#[derive(Debug)]
pub struct Mte;

impl crate::DomainPrimitive for Mte {
    const BACKEND: crate::DomainBackend = crate::DomainBackend::Mte;
    type SavedState = SavedMteState;
    type Rights     = DomainRights;

    const ALLOW_ALL: DomainRights = DomainRights::ALLOW_ALL;
    const READ_ONLY: DomainRights = DomainRights::READ_ONLY;
    const DENY_ALL:  DomainRights = DomainRights::DENY_ALL;

    #[inline]
    unsafe fn save() -> Self::SavedState {
        // SAFETY: MRS SCTLR_EL1 always legal at EL1.
        unsafe { SavedMteState { sctlr: sysreg::read_sctlr_el1() } }
    }

    #[inline]
    unsafe fn restore(s: Self::SavedState) {
        // SAFETY: MSR SCTLR_EL1 always legal at EL1.
        unsafe { sysreg::write_sctlr_el1(s.sctlr); }
    }

    #[inline]
    unsafe fn get_rights(_domain: u8) -> Self::Rights {
        // MTE doesn't have a per-tag rights register. DomainRights are
        // established at mapping time via AP bits.
        DomainRights::ALLOW_ALL
    }

    #[inline]
    unsafe fn set_rights(_domain: u8, _rights: Self::Rights) {
        // No-op on aarch64 MTE; see design notes.
    }

    #[inline]
    unsafe fn enter_domain(_kernel_domain: u8, _driver_domain: u8)
        -> Self::SavedState {
        // Stage-2 scope: structural save only.
        //
        // A real MTE "enter scope" would flip SCTLR_EL1.TCF from
        // Ignore to Sync so tag mismatches fault, but that requires
        // the kernel's live tag storage and tagged pointers to already
        // be consistent — otherwise every memory access after the
        // flip tag-faults, recurses into the fault handler (which
        // also tag-faults), and we loop. Tag storage bring-up is a
        // Stage-3 task that pairs with the MTE-tag-aware allocator.
        //
        // SAFETY: pure MRS of SCTLR_EL1 — always legal at EL1.
        unsafe { Self::save() }
    }

    #[inline]
    unsafe fn exit_domain(saved: Self::SavedState) {
        // SAFETY: restore previous SCTLR_EL1.
        unsafe { Self::restore(saved); }
    }
}
