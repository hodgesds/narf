//! x86_64 arch backend.

pub mod asm;
pub mod cpuid;
pub mod cr;
pub mod io_port;
pub mod msr;
pub mod pks;
pub mod probe;
pub mod user_mode;

pub use asm::{halt_forever, disable_interrupts, enable_interrupts, cas128, patch_word};
pub use cpuid::Features;
pub use user_mode::{
    enter_user_mode, enter_user_mode_resume, longjmp, setjmp, JmpBuf,
    UserState, USER_RFLAGS,
};

/// x86_64's concrete `DomainPrimitive` type. All methods forward to
/// the free functions in `pks` — the trait is just a way to let
/// arch-agnostic code name a single type.
#[derive(Debug)]
pub struct Pks;

impl crate::DomainPrimitive for Pks {
    const BACKEND: crate::DomainBackend = crate::DomainBackend::Pks;
    type SavedState = pks::SavedPkrs;
    type Rights     = pks::DomainRights;

    const ALLOW_ALL: pks::DomainRights = pks::DomainRights::ALLOW_ALL;
    const READ_ONLY: pks::DomainRights = pks::DomainRights::READ_ONLY;
    const DENY_ALL:  pks::DomainRights = pks::DomainRights::DENY_ALL;

    #[inline]
    unsafe fn save() -> Self::SavedState {
        // SAFETY: trait contract delegated.
        unsafe { pks::save() }
    }

    #[inline]
    unsafe fn restore(s: Self::SavedState) {
        // SAFETY: trait contract delegated.
        unsafe { pks::restore(s); }
    }

    #[inline]
    unsafe fn get_rights(domain: u8) -> Self::Rights {
        // SAFETY: trait contract delegated.
        unsafe { pks::get_rights(domain) }
    }

    #[inline]
    unsafe fn set_rights(domain: u8, rights: Self::Rights) {
        // SAFETY: trait contract delegated.
        unsafe { pks::set_rights(domain, rights); }
    }

    #[inline]
    unsafe fn enter_domain(kernel_domain: u8, driver_domain: u8)
        -> Self::SavedState {
        // SAFETY: trait contract delegated.
        unsafe { pks::enter_domain(kernel_domain, driver_domain) }
    }

    #[inline]
    unsafe fn exit_domain(saved: Self::SavedState) {
        // SAFETY: trait contract delegated.
        unsafe { pks::exit_domain(saved); }
    }
}

/// Exit QEMU cleanly via the `isa-debug-exit` device (I/O port 0xF4).
/// QEMU computes its exit status as `(code << 1) | 1`, so `exit_qemu(0)`
/// gives exit status 1 and `exit_qemu(16)` gives status 33 — xtask /
/// verification harnesses interpret the mapping.
///
/// If `isa-debug-exit` isn't wired up (real hardware, non-QEMU VMMs),
/// this falls back to `halt_forever`.
///
/// # Safety
/// Arbitrary I/O-port writes are always unsafe; port 0xF4 is specifically
/// QEMU's debug-exit device and has no side effect elsewhere.
pub unsafe fn exit_qemu(code: u32) -> ! {
    // SAFETY: OUT to 0xF4 is benign if the device isn't attached, and
    // exits cleanly if it is. Either way we fall into halt_forever.
    unsafe { io_port::outb(0xF4, code as u8); }
    halt_forever()
}
