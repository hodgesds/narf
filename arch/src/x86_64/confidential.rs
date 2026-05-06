//! Confidential-computing guest detection — TDX (Intel) +
//! SEV / SEV-ES / SEV-SNP (AMD).
//!
//! Spec: `arch/specification/virt-confidential.md` §4.
//!
//! Detection-only: NARF doesn't yet *implement* TDX guest entry
//! or SEV-SNP page validation, but a CPUID-only signal lets the
//! kernel branch on the host environment (e.g. avoid mapping
//! pages in cleartext when SNP is active).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::rdmsr;

/// Intel TDX guest CPUID-vendor signature at leaf 0x21.
const TDX_VENDOR_BYTES: &[u8; 12] = b"IntelTDX    ";

pub const MSR_AMD64_SEV: u32 = 0xC001_0131;
const SEV_BIT: u64 = 1 << 0;
const SEV_ES_BIT: u64 = 1 << 1;
const SEV_SNP_BIT: u64 = 1 << 2;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfidentialEnvironment {
    Bare,
    TdxGuest,
    SevGuest,
    SevEsGuest,
    SevSnpGuest,
}

fn vendor_intel() -> bool {
    // SAFETY: leaf 0 always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    ebx == 0x756E_6547 && edx == 0x4965_6E69 && ecx == 0x6C65_746E
}

fn vendor_amd() -> bool {
    // SAFETY: leaf 0 always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    ebx == 0x6874_7541 && edx == 0x6974_6E65 && ecx == 0x444D_4163
}

fn tdx_guest() -> bool {
    // CPUID(0x21, 0) — TDX vendor leaf. Returns the 12-byte
    // signature spread EBX/EDX/ECX (legacy CPUID-vendor encoding).
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x21 {
        return false;
    }
    // SAFETY: leaf 0x21 valid.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0x21, 0) };
    let mut s = [0u8; 12];
    s[0..4].copy_from_slice(&ebx.to_le_bytes());
    s[4..8].copy_from_slice(&edx.to_le_bytes());
    s[8..12].copy_from_slice(&ecx.to_le_bytes());
    &s == TDX_VENDOR_BYTES
}

fn sev_msr_bits() -> Option<u64> {
    if !vendor_amd() {
        return None;
    }
    // CPUID(0x80000000) max + 0x8000001F existence gate.
    // SAFETY: leaf 0x80000000 always defined.
    let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
    if max_ext < 0x8000_001F {
        return None;
    }
    // SAFETY: leaf valid.
    let (eax, _, _, _) = unsafe { cpuid(0x8000_001F, 0) };
    if eax & (1 << 1) == 0 {
        return None;
    } // SEV not supported
      // MSR_AMD64_SEV reads 0 outside of an active SEV guest; on host
      // CPUs without SEV it would #GP — gate kept us safe.
      // SAFETY: caller is at CPL=0; SEV-supported path.
    Some(unsafe { rdmsr(MSR_AMD64_SEV) })
}

/// Classify the running environment. Inside a SEV-SNP guest
/// returns `SevSnpGuest`; SEV-ES → `SevEsGuest`; SEV → `SevGuest`;
/// TDX → `TdxGuest`; otherwise `Bare`.
pub fn detect_environment() -> ConfidentialEnvironment {
    if vendor_intel() && tdx_guest() {
        return ConfidentialEnvironment::TdxGuest;
    }
    if let Some(bits) = sev_msr_bits() {
        if bits & SEV_SNP_BIT != 0 {
            return ConfidentialEnvironment::SevSnpGuest;
        }
        if bits & SEV_ES_BIT != 0 {
            return ConfidentialEnvironment::SevEsGuest;
        }
        if bits & SEV_BIT != 0 {
            return ConfidentialEnvironment::SevGuest;
        }
    }
    ConfidentialEnvironment::Bare
}

/// `true` iff the host CPU (we may be the host) advertises SME.
pub fn host_supports_sme() -> bool {
    if !vendor_amd() {
        return false;
    }
    // SAFETY: leaf 0x80000000 always defined.
    let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
    if max_ext < 0x8000_001F {
        return false;
    }
    // SAFETY: leaf valid.
    let (eax, _, _, _) = unsafe { cpuid(0x8000_001F, 0) };
    eax & (1 << 0) != 0
}

/// `true` iff the host CPU advertises SEV.
pub fn host_supports_sev() -> bool {
    if !vendor_amd() {
        return false;
    }
    // SAFETY: leaf 0x80000000 always defined.
    let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
    if max_ext < 0x8000_001F {
        return false;
    }
    // SAFETY: leaf valid.
    let (eax, _, _, _) = unsafe { cpuid(0x8000_001F, 0) };
    eax & (1 << 1) != 0
}
