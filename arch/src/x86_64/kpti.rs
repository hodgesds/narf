//! KPTI — Kernel Page Table Isolation gate.
//!
//! KPTI is the dual-page-table mitigation for Meltdown (CVE-2017-5754):
//! while a task runs in user mode, the kernel half of the address
//! space is unmapped, so a speculative load via the Meltdown side
//! channel can't read kernel memory.
//!
//! The cost is real: every syscall and IRQ entry must do
//! `MOV CR3` twice (swap to kernel PT on entry, swap back on exit),
//! which Linux's PTI patch series measured at 5–30% on workloads
//! that syscall heavily.
//!
//! NARF stance: **detect per-CPU and skip on immune parts**. Both
//! Renoir (Zen2) and Phoenix (Zen4) are immune to Meltdown by design;
//! AMD never had the bug. Intel parts pre-Coffee-Lake are vulnerable
//! and need the dual-table dance. We pay the cost only where the
//! silicon actually leaks.
//!
//! Detection priority:
//!
//!   1. AMD / Hygon vendor → immune, return [`Posture::Native`].
//!   2. Intel CPUID(7, 0).EDX[29] (ARCH_CAPABILITIES) set
//!      and IA32_ARCH_CAPABILITIES[0] (RDCL_NO) set → immune.
//!   3. Otherwise vulnerable → return [`Posture::Isolate`].
//!
//! The dual-table machinery itself is a separate module (this file is
//! just the gate). [`Posture::Isolate`] is what the
//! page-table-setup code keys off; on [`Posture::Native`] the kernel
//! installs the kernel half in user PT and skips the CR3 swap.
//!
//! References:
//!   * Linux `Documentation/x86/pti.rst`.
//!   * Linux `arch/x86/include/asm/cpufeatures.h` X86_FEATURE_PTI /
//!     X86_BUG_CPU_MELTDOWN.
//!   * Intel "Software Techniques for Managing Speculation on AMD
//!     Processors" — confirms AMD parts unaffected.
//!   * AMD "Indirect Branch Control Extension" whitepaper.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::ident::{self, Vendor};
use crate::x86_64::msr::rdmsr;

/// IA32_ARCH_CAPABILITIES (Intel only; AMD doesn't define this MSR but
/// neither does it advertise CPUID.7.0.EDX[29], so we never read it
/// on AMD).
const MSR_IA32_ARCH_CAPABILITIES: u32 = 0x10A;
/// IA32_ARCH_CAPABILITIES[0] — "RDCL_NO". When set, the part is not
/// affected by Rogue Data Cache Load / Meltdown.
const ARCH_CAP_RDCL_NO: u64 = 1 << 0;

/// Decision the security-init initcall reaches per CPU.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Posture {
    /// Single page table for kernel + user. Renoir / Phoenix / any
    /// Intel with RDCL_NO. Free at runtime.
    Native,
    /// Dual page tables — kernel half stripped from user PT, restored
    /// on syscall/IRQ entry. Required for older Intel cores.
    Isolate,
}

/// Inspect this CPU and decide whether KPTI is needed.
#[inline]
pub fn detect() -> Posture {
    let id = ident::read();
    match id.vendor {
        Vendor::Amd | Vendor::Hygon => return Posture::Native,
        _ => {}
    }

    // Intel and friends: check IA32_ARCH_CAPABILITIES if exposed.
    // SAFETY: CPUID always legal.
    let (max, _, _, _) = unsafe { cpuid(0, 0) };
    if max >= 7 {
        // SAFETY: leaf 7 sub 0 valid because max >= 7.
        let (_, _, _, edx) = unsafe { cpuid(7, 0) };
        if edx & (1 << 29) != 0 {
            // ARCH_CAPABILITIES MSR is present. SAFETY: RDMSR 0x10A is
            // architectural on parts that advertise CPUID.7.0.EDX[29].
            let caps = unsafe { rdmsr(MSR_IA32_ARCH_CAPABILITIES) };
            if caps & ARCH_CAP_RDCL_NO != 0 {
                return Posture::Native;
            }
        }
    }

    // Unknown vendor or pre-architectural-capabilities Intel: assume
    // worst case. Coffee Lake-R and newer mostly set RDCL_NO; if the
    // MSR doesn't exist we're on an old enough part that Meltdown is
    // a known issue.
    Posture::Isolate
}

/// `true` iff [`detect`] would return [`Posture::Native`].
///
/// Convenience for the boot-time logging path that just wants to print
/// "PTI: not needed".
#[inline]
pub fn native_safe() -> bool {
    detect() == Posture::Native
}
