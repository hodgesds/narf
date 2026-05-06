//! Boot CPU validation.
//!
//! Spec: `arch/specification/security-hardening.md` §3.
//!
//! Probes CPUID + the architectural control registers for the
//! features NARF assumes at runtime. Hard requirements raise an
//! error; recommended-but-not-required misses surface as boolean
//! fields on `CpuValidation` so the caller can decide whether
//! to log a warning.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::rdmsr;

const MSR_IA32_EFER: u32 = 0xC000_0080;
const EFER_LME: u64 = 1 << 8;
const EFER_NXE: u64 = 1 << 11;

const CR4_PAE: u64 = 1 << 5;
const CR4_PGE: u64 = 1 << 7;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_FSGSBASE: u64 = 1 << 16;
const CR4_OSXSAVE: u64 = 1 << 18;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
const CR4_UMIP: u64 = 1 << 11;

#[derive(Copy, Clone, Debug, Default)]
pub struct CpuValidation {
    // Capability bits (CPUID).
    pub long_mode: bool,
    pub rdtscp: bool,
    pub invariant_tsc: bool,
    pub nx: bool,
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
    pub wrgsbase: bool,
    pub pcid: bool,
    pub x2apic: bool,
    pub xsave: bool,
    // CR4 / EFER actually-on bits.
    pub cr4_pae_on: bool,
    pub cr4_pge_on: bool,
    pub cr4_osfxsr_on: bool,
    pub cr4_osxsave_on: bool,
    pub cr4_smep_on: bool,
    pub cr4_smap_on: bool,
    pub cr4_umip_on: bool,
    pub cr4_fsgsbase_on: bool,
    pub efer_lme_on: bool,
    pub efer_nxe_on: bool,
}

#[inline]
fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: CR4 read at CPL=0 always defined.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Probe CPUID + control registers, return the validation
/// snapshot.
///
/// # Safety
/// CPL = 0.
pub unsafe fn validate() -> CpuValidation {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };

    // Standard leaf 1.
    // SAFETY: leaf 1 always defined.
    let (_, _, ecx_1, _) = unsafe { cpuid(1, 0) };
    let pcid = ecx_1 & (1 << 17) != 0;
    let x2apic = ecx_1 & (1 << 21) != 0;
    let xsave = ecx_1 & (1 << 26) != 0;

    // Leaf 7 sub-leaf 0.
    let (smep, smap, umip, wrgsbase) = if max >= 7 {
        // SAFETY: leaf 7 valid.
        let (_, ebx, ecx, _) = unsafe { cpuid(7, 0) };
        (
            ebx & (1 << 7) != 0,
            ebx & (1 << 20) != 0,
            ecx & (1 << 2) != 0,
            ebx & (1 << 0) != 0,
        )
    } else {
        (false, false, false, false)
    };

    // Extended leaf 0x80000001.
    // SAFETY: leaf 0x80000000 always defined.
    let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
    let (long_mode, rdtscp, nx) = if max_ext >= 0x8000_0001 {
        // SAFETY: extended leaf 1 valid.
        let (_, _, _, edx) = unsafe { cpuid(0x8000_0001, 0) };
        (
            edx & (1 << 29) != 0,
            edx & (1 << 27) != 0,
            edx & (1 << 20) != 0,
        )
    } else {
        (false, false, false)
    };

    // Extended leaf 0x80000007 (invariant TSC bit).
    let invariant_tsc = if max_ext >= 0x8000_0007 {
        // SAFETY: extended leaf 7 valid.
        let (_, _, _, edx) = unsafe { cpuid(0x8000_0007, 0) };
        edx & (1 << 8) != 0
    } else {
        false
    };

    // Control registers.
    let cr4 = read_cr4();
    // SAFETY: caller-asserted.
    let efer = unsafe { rdmsr(MSR_IA32_EFER) };

    CpuValidation {
        long_mode,
        rdtscp,
        invariant_tsc,
        nx,
        smep,
        smap,
        umip,
        wrgsbase,
        pcid,
        x2apic,
        xsave,
        cr4_pae_on: cr4 & CR4_PAE != 0,
        cr4_pge_on: cr4 & CR4_PGE != 0,
        cr4_osfxsr_on: cr4 & CR4_OSFXSR != 0,
        cr4_osxsave_on: cr4 & CR4_OSXSAVE != 0,
        cr4_smep_on: cr4 & CR4_SMEP != 0,
        cr4_smap_on: cr4 & CR4_SMAP != 0,
        cr4_umip_on: cr4 & CR4_UMIP != 0,
        cr4_fsgsbase_on: cr4 & CR4_FSGSBASE != 0,
        efer_lme_on: efer & EFER_LME != 0,
        efer_nxe_on: efer & EFER_NXE != 0,
    }
}

/// Hard-baseline check. Returns `Err(reason)` for the first
/// missing required capability or unset enable bit.
pub fn baseline_ok(v: &CpuValidation) -> Result<(), &'static str> {
    if !v.long_mode {
        return Err("Long Mode missing");
    }
    if !v.rdtscp {
        return Err("RDTSCP missing");
    }
    if !v.invariant_tsc {
        return Err("Invariant TSC missing");
    }
    if !v.nx {
        return Err("NX missing");
    }
    if !v.smep {
        return Err("SMEP missing");
    }
    if !v.smap {
        return Err("SMAP missing");
    }
    if !v.wrgsbase {
        return Err("FSGSBASE missing");
    }
    if !v.xsave {
        return Err("XSAVE missing");
    }
    if !v.efer_lme_on {
        return Err("EFER.LME not enabled");
    }
    if !v.efer_nxe_on {
        return Err("EFER.NXE not enabled");
    }
    if !v.cr4_pae_on {
        return Err("CR4.PAE not enabled");
    }
    if !v.cr4_osfxsr_on {
        return Err("CR4.OSFXSR not enabled");
    }
    if !v.cr4_osxsave_on {
        return Err("CR4.OSXSAVE not enabled");
    }
    Ok(())
}
