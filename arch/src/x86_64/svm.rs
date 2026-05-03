//! SVM feature detection (AMD).
//!
//! Spec: `arch/specification/virt-confidential.md` §2.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::rdmsr;

pub const MSR_VM_CR: u32 = 0xC001_0114;
const VM_CR_SVMDIS: u64 = 1 << 4;

#[derive(Copy, Clone, Debug, Default)]
pub struct SvmCaps {
    pub supported:        bool,
    pub disabled:         bool,
    pub revision:         u8,
    pub n_asids:          u32,
    pub np:               bool,
    pub lbr_virt:         bool,
    pub svm_lock:         bool,
    pub nrip_save:        bool,
    pub tsc_rate_msr:     bool,
    pub vmcb_clean:       bool,
    pub flush_by_asid:    bool,
    pub decode_assists:   bool,
    pub pause_filter:     bool,
}

pub fn caps() -> SvmCaps {
    // SAFETY: leaf 0x80000000 always defined.
    let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
    if max_ext < 0x8000_0001 { return SvmCaps::default(); }
    // SAFETY: extended leaf 1 valid.
    let (_, _, ecx, _) = unsafe { cpuid(0x8000_0001, 0) };
    let supported = ecx & (1 << 2) != 0;
    if !supported { return SvmCaps::default(); }

    // MSR_VM_CR is AMD-specific; CPL=0 + SVM-supported guarantees
    // it exists.
    // SAFETY: caller-asserted.
    let vm_cr = unsafe { rdmsr(MSR_VM_CR) };
    let disabled = vm_cr & VM_CR_SVMDIS != 0;

    if max_ext < 0x8000_000A {
        return SvmCaps { supported, disabled, ..SvmCaps::default() };
    }
    // SAFETY: extended leaf A valid.
    let (eax, ebx, _, edx) = unsafe { cpuid(0x8000_000A, 0) };
    SvmCaps {
        supported, disabled,
        revision:        (eax & 0xFF) as u8,
        n_asids:         ebx,
        np:              edx & (1 << 0)  != 0,
        lbr_virt:        edx & (1 << 1)  != 0,
        svm_lock:        edx & (1 << 2)  != 0,
        nrip_save:       edx & (1 << 3)  != 0,
        tsc_rate_msr:    edx & (1 << 4)  != 0,
        vmcb_clean:      edx & (1 << 5)  != 0,
        flush_by_asid:   edx & (1 << 6)  != 0,
        decode_assists:  edx & (1 << 7)  != 0,
        pause_filter:    edx & (1 << 10) != 0,
    }
}
