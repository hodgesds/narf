//! x86_64 arch backend.

pub mod acpi;
pub mod asm;
pub mod avx10;
pub mod cache;
pub mod cet;
pub mod confidential;
pub mod cpu;
pub mod cpu_validate;
pub mod cpuid;
pub mod cr;
pub mod errata;
pub mod fred;
pub mod hfi;
pub mod hypervisor;
pub mod ident;
pub mod invlpgb;
pub mod io_port;
pub mod keylocker;
pub mod lam;
pub mod lass;
pub mod lbr;
pub mod mce;
pub mod microcode;
pub mod movdir;
pub mod msr;
pub mod mtrr;
pub mod pcid;
pub mod pebs;
pub mod pit;
pub mod pks;
pub mod pmi;
pub mod pmu;
pub mod probe;
pub mod pt;
pub mod rdpru;
pub mod rdt;
pub mod rtc;
pub mod sgx;
pub mod smca;
pub mod smp;
pub mod spec_ctrl;
pub mod svm;
pub mod topology;
pub mod tsc;
pub mod uintr;
pub mod user_mode;
pub mod vmx;
pub mod waitpkg;
pub mod wrmsrns;
pub mod xsave;

pub use asm::{halt_forever, disable_interrupts, enable_interrupts, cas128, patch_word};
pub use cpuid::Features;
pub use user_mode::{
    enter_user_mode, enter_user_mode_resume, longjmp, set_user_fs_base,
    setjmp, JmpBuf, UserState, IA32_FS_BASE, USER_RFLAGS,
};

/// x86_64's concrete `DomainPrimitive` type. All methods forward to
/// the free functions in `pks` — the trait is just a way to let
/// arch-agnostic code name a single type.
#[derive(Debug)]
pub struct Pks;

impl crate::DomainPrimitive for Pks {
    const BACKEND: crate::DomainBackend = crate::DomainBackend::Pks;
    // SavedState carries either a PKRS value (when PKS is live) or a
    // CR3 value (when delegating to PCID). The wrapping `SavedPkrs(u64)`
    // is opaque to callers; the impl tags meaning by reading
    // `pks::is_active()` at the same call site that produced it.
    type SavedState = pks::SavedPkrs;
    type Rights     = pks::DomainRights;

    const ALLOW_ALL: pks::DomainRights = pks::DomainRights::ALLOW_ALL;
    const READ_ONLY: pks::DomainRights = pks::DomainRights::READ_ONLY;
    const DENY_ALL:  pks::DomainRights = pks::DomainRights::DENY_ALL;

    #[inline]
    unsafe fn save() -> Self::SavedState {
        if pks::is_active() {
            // SAFETY: CR4.PKS is on.
            unsafe { pks::save() }
        } else {
            // SAFETY: PCID path; tolerates the inactive state too.
            let pcid_saved = unsafe { pcid::save() };
            pks::SavedPkrs(pcid_saved.0)
        }
    }

    #[inline]
    unsafe fn restore(s: Self::SavedState) {
        if pks::is_active() {
            // SAFETY: CR4.PKS is on.
            unsafe { pks::restore(s); }
        } else {
            // SAFETY: PCID path.
            unsafe { pcid::restore(pcid::SavedPcid(s.0)); }
        }
    }

    #[inline]
    unsafe fn get_rights(domain: u8) -> Self::Rights {
        if pks::is_active() {
            // SAFETY: CR4.PKS is on.
            unsafe { pks::get_rights(domain) }
        } else {
            // SAFETY: trivial no-op.
            let r = unsafe { pcid::get_rights(domain) };
            // pcid::DomainRights and pks::DomainRights are structurally
            // identical; round-trip via the bool fields.
            pks::DomainRights { no_write: r.no_write, no_access: r.no_access }
        }
    }

    #[inline]
    unsafe fn set_rights(domain: u8, rights: Self::Rights) {
        if pks::is_active() {
            // SAFETY: CR4.PKS is on.
            unsafe { pks::set_rights(domain, rights); }
        } else {
            // SAFETY: trivial no-op.
            unsafe {
                pcid::set_rights(
                    domain,
                    pcid::DomainRights {
                        no_write:  rights.no_write,
                        no_access: rights.no_access,
                    },
                );
            }
        }
    }

    #[inline]
    unsafe fn enter_domain(kernel_domain: u8, driver_domain: u8)
        -> Self::SavedState {
        if pks::is_active() {
            // SAFETY: CR4.PKS is on.
            unsafe { pks::enter_domain(kernel_domain, driver_domain) }
        } else {
            // SAFETY: PCID path; safe pre-init too (returns sentinel).
            let s = unsafe { pcid::enter_domain(kernel_domain, driver_domain) };
            pks::SavedPkrs(s.0)
        }
    }

    #[inline]
    unsafe fn exit_domain(saved: Self::SavedState) {
        if pks::is_active() {
            // SAFETY: CR4.PKS is on.
            unsafe { pks::exit_domain(saved); }
        } else {
            // SAFETY: PCID path.
            unsafe { pcid::exit_domain(pcid::SavedPcid(saved.0)); }
        }
    }
}

/// PCID-based domain enforcer for AMD x86_64 / pre-SPR Intel.
///
/// **Skeleton.** Implements the trait so boot-time backend selection
/// can name `Pcid` and so test code can exercise the surface, but the
/// methods are no-ops; real per-domain page tables land in a follow-up.
/// See `pcid.rs` for the open-work list.
#[derive(Debug)]
pub struct Pcid;

impl crate::DomainPrimitive for Pcid {
    const BACKEND: crate::DomainBackend = crate::DomainBackend::Pcid;
    type SavedState = pcid::SavedPcid;
    type Rights     = pcid::DomainRights;

    const ALLOW_ALL: pcid::DomainRights = pcid::DomainRights::ALLOW_ALL;
    const READ_ONLY: pcid::DomainRights = pcid::DomainRights::READ_ONLY;
    const DENY_ALL:  pcid::DomainRights = pcid::DomainRights::DENY_ALL;

    #[inline]
    unsafe fn save() -> Self::SavedState {
        // SAFETY: skeleton no-op.
        unsafe { pcid::save() }
    }

    #[inline]
    unsafe fn restore(s: Self::SavedState) {
        // SAFETY: skeleton no-op.
        unsafe { pcid::restore(s); }
    }

    #[inline]
    unsafe fn get_rights(domain: u8) -> Self::Rights {
        // SAFETY: skeleton no-op.
        unsafe { pcid::get_rights(domain) }
    }

    #[inline]
    unsafe fn set_rights(domain: u8, rights: Self::Rights) {
        // SAFETY: skeleton no-op.
        unsafe { pcid::set_rights(domain, rights); }
    }

    #[inline]
    unsafe fn enter_domain(kernel_domain: u8, driver_domain: u8)
        -> Self::SavedState {
        // SAFETY: skeleton no-op.
        unsafe { pcid::enter_domain(kernel_domain, driver_domain) }
    }

    #[inline]
    unsafe fn exit_domain(saved: Self::SavedState) {
        // SAFETY: skeleton no-op.
        unsafe { pcid::exit_domain(saved); }
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
