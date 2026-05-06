//! CPU-identity primitive.
//!
//! `current_cpu()` returns the executing logical-CPU index in the
//! range `[0, MAX_CPUS)`. Used as the index into `PerCpu<T>` arrays.
//!
//! Implementation strategy:
//!
//! - **x86_64 with RDPID** (Intel Ice Lake / AMD Zen 2+): single
//!   one-byte read of the IA32_TSC_AUX MSR's low 32 bits.
//! - **x86_64 with RDTSCP** (universal since Nehalem / Bulldozer):
//!   reads TSC + IA32_TSC_AUX in one instruction; we discard the
//!   TSC and keep the aux. The aux MSR is loaded by the boot path
//!   with the CPU's logical id when the AP comes up — until then
//!   it reads zero, which is the BSP-only correct answer.
//! - **Pre-RDTSCP fallback**: read CPUID.01h:EBX[31:24] for the
//!   initial APIC id. Slow (CPUID is serializing); only used as a
//!   compile-time-disabled fallback.
//!
//! Today the kernel is single-CPU; `current_cpu()` always returns 0
//! because IA32_TSC_AUX is zero on the BSP and we haven't enabled
//! RDPID feature gating yet. The plumbing is in place so AP
//! bring-up just needs to write each AP's id into its own
//! IA32_TSC_AUX after entering long mode.

use core::arch::asm;

/// Maximum number of logical CPUs the kernel ever supports. Sized
/// for high-end commodity hardware (sapphire-rapids tops out at
/// 60 hyperthreads / socket; we leave room for dual-socket plus
/// aarch64 server parts).
pub const MAX_CPUS: usize = 64;

/// Return the executing CPU's logical index. Single-CPU today; once
/// AP bring-up populates IA32_TSC_AUX per CPU, this picks up the
/// right value automatically.
///
/// # Safety
/// Reading TSC_AUX is always defined at CPL=0; the function is safe
/// to call from any context.
#[inline]
pub fn current_cpu() -> u32 {
    let mut aux: u32;
    let mut _hi: u32;
    let mut _lo: u32;
    // SAFETY: RDTSCP reads TSC + IA32_TSC_AUX. Available since
    // Nehalem (2008) / Bulldozer (2011) — universal on hardware
    // we target. Today the AUX MSR is zero on the BSP; AP bring-up
    // will write each AP's index in.
    unsafe {
        asm!(
            "rdtscp",
            out("eax") _lo,
            out("edx") _hi,
            out("ecx") aux,
            options(nomem, nostack, preserves_flags),
        );
    }
    aux
}

/// Set the calling CPU's id (low 32 bits of IA32_TSC_AUX).
///
/// # Safety
/// Must run on the CPU whose id is being set, exactly once during
/// AP bring-up. The kernel reads TSC_AUX as the per-CPU index and
/// must never see stale or duplicate values.
#[inline]
pub unsafe fn set_current_cpu(id: u32) {
    use crate::x86_64::msr::wrmsr;
    // IA32_TSC_AUX = 0xC0000103.
    // SAFETY: caller asserts this is the post-AP-startup write
    // for the executing CPU.
    unsafe {
        wrmsr(0xC000_0103, id as u64);
    }
}
