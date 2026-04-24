//! aarch64 MTE (Memory Tagging Extension) stub.
//!
//! Structural parity with x86_64's `pks` module. Real implementation
//! lands alongside aarch64 QEMU bring-up (needs `qemu-system-aarch64`
//! + `-cpu max,mte=on` for testing). Until then every method panics
//! via `unimplemented!` — calling them on a live aarch64 kernel would
//! be a bug anyway, because `frame/main.rs` gates the MTE enable on
//! CPUID-equivalent detection that isn't wired yet.

use core::fmt;

/// Saved MTE state (placeholder). Will wrap a snapshot of
/// `SCTLR_EL1.TCF` + whatever else the real impl needs.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct SavedMteState(pub u64);

/// Per-domain access rights. Matches the `DomainRights` shape on
/// x86_64 so the trait surface is uniform.
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

#[allow(unused_variables)]
mod stubs {
    use super::{DomainRights, SavedMteState};
    pub(super) unsafe fn save() -> SavedMteState {
        unimplemented!("aarch64 MTE: save not yet implemented")
    }
    pub(super) unsafe fn restore(_s: SavedMteState) {
        unimplemented!("aarch64 MTE: restore not yet implemented")
    }
    pub(super) unsafe fn get_rights(_d: u8) -> DomainRights {
        unimplemented!("aarch64 MTE: get_rights not yet implemented")
    }
    pub(super) unsafe fn set_rights(_d: u8, _r: DomainRights) {
        unimplemented!("aarch64 MTE: set_rights not yet implemented")
    }
    pub(super) unsafe fn enter_domain(_k: u8, _d: u8) -> SavedMteState {
        unimplemented!("aarch64 MTE: enter_domain not yet implemented")
    }
    pub(super) unsafe fn exit_domain(_s: SavedMteState) {
        unimplemented!("aarch64 MTE: exit_domain not yet implemented")
    }
}

/// aarch64's concrete `DomainPrimitive` type. Stub today; methods
/// panic via `unimplemented!`. When MTE enable lands, replace the
/// bodies with real implementations against `SCTLR_EL1.TCF` and tag
/// storage.
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
        // SAFETY: stub delegates to unimplemented!.
        unsafe { stubs::save() }
    }

    #[inline]
    unsafe fn restore(s: Self::SavedState) {
        // SAFETY: stub delegates to unimplemented!.
        unsafe { stubs::restore(s); }
    }

    #[inline]
    unsafe fn get_rights(domain: u8) -> Self::Rights {
        // SAFETY: stub delegates to unimplemented!.
        unsafe { stubs::get_rights(domain) }
    }

    #[inline]
    unsafe fn set_rights(domain: u8, rights: Self::Rights) {
        // SAFETY: stub delegates to unimplemented!.
        unsafe { stubs::set_rights(domain, rights); }
    }

    #[inline]
    unsafe fn enter_domain(kernel_domain: u8, driver_domain: u8)
        -> Self::SavedState {
        // SAFETY: stub delegates to unimplemented!.
        unsafe { stubs::enter_domain(kernel_domain, driver_domain) }
    }

    #[inline]
    unsafe fn exit_domain(saved: Self::SavedState) {
        // SAFETY: stub delegates to unimplemented!.
        unsafe { stubs::exit_domain(saved); }
    }
}
