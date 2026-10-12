//! User protection-key (PKU) control.
//!
//! `CR4.PKE` makes the architectural `RDPKRU` and `WRPKRU` instructions
//! available at CPL3.  PKRU is independent of PKS/PKRS: the former constrains
//! user mappings and is task state, while the latter constrains supervisor
//! domains and remains owned by the framekernel domain machinery.

use core::sync::atomic::{compiler_fence, Ordering};

use super::{cpuid::Features, cr};

/// Whether the current CPU advertises user protection keys.
#[inline]
pub fn supported() -> bool {
    // SAFETY: CPUID is legal at CPL0 and this helper is only called by kernel
    // CPU bring-up or scheduler paths.
    unsafe { Features::probe().pku }
}

/// Whether this CPU has enabled architectural PKRU access.
#[inline]
pub fn enabled() -> bool {
    cr::cached_cr4() & cr::CR4_PKE != 0
}

/// Enable PKU on the current CPU and establish the permissive initial PKRU.
///
/// This is deliberately current-CPU scoped: CR4 is per-logical-processor, so
/// BSP bring-up and every AP must call it before that CPU can run userspace.
///
/// Returns `false` without changing architectural state when CPUID does not
/// advertise PKU.
///
/// # Safety
/// CPL0; call before untrusted userspace executes on this CPU.
pub unsafe fn enable_current_cpu() -> bool {
    if !supported() {
        return false;
    }
    // SAFETY: caller guarantees CPL0 and CPUID confirmed CR4.PKE support.
    unsafe {
        let value = cr::read_cr4();
        cr::write_cr4(value | cr::CR4_PKE);
        // A reset or freshly brought-up CPU starts permissive. Make that
        // contract explicit rather than inheriting stale virtual-CPU state.
        write(0);
    }
    true
}

/// Read the current CPU's user PKRU value.
///
/// # Safety
/// CPL0 and [`enabled`] must be true on this CPU.
#[inline]
pub unsafe fn read() -> u32 {
    debug_assert!(enabled(), "RDPKRU requires CR4.PKE");
    let value: u32;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller establishes CR4.PKE. RDPKRU requires ECX=0.
    unsafe {
        core::arch::asm!(
            "rdpkru",
            in("ecx") 0u32,
            out("eax") value,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    value
}

/// Write the current CPU's user PKRU value.
///
/// # Safety
/// CPL0 and [`enabled`] must be true on this CPU. The caller must make the
/// value task-local before another user task can resume on this CPU.
#[inline]
pub unsafe fn write(value: u32) {
    debug_assert!(enabled(), "WRPKRU requires CR4.PKE");
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller establishes CR4.PKE. WRPKRU requires ECX=EDX=0.
    unsafe {
        core::arch::asm!(
            "wrpkru",
            in("eax") value,
            in("ecx") 0u32,
            in("edx") 0u32,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}
