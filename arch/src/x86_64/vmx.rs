//! VMX feature detection (Intel).
//!
//! Spec: `arch/specification/virt-confidential.md` §1.
//!
//! Surfaces the capability MSRs read-only — VMXON / VMCS
//! construction is out of scope for v0.1.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::rdmsr;

pub const MSR_IA32_FEATURE_CONTROL: u32 = 0x3A;
pub const MSR_IA32_VMX_BASIC: u32 = 0x480;
pub const MSR_IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
pub const MSR_IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;

const FEATURE_CONTROL_LOCK: u64 = 1 << 0;
const FEATURE_CONTROL_VMXON_OUTSIDE_SMX: u64 = 1 << 2;

#[derive(Copy, Clone, Debug, Default)]
pub struct VmxBasic {
    pub revision_id: u32,
    pub vmcs_region_size: u16,
    pub physaddr_32bit: bool,
    pub memory_type: u8,
    pub true_ctls: bool,
}

impl VmxBasic {
    fn decode(raw: u64) -> Self {
        Self {
            revision_id: (raw & 0x7FFF_FFFF) as u32,
            vmcs_region_size: ((raw >> 32) & 0x1FFF) as u16,
            physaddr_32bit: raw & (1 << 48) != 0,
            memory_type: ((raw >> 50) & 0xF) as u8,
            true_ctls: raw & (1 << 55) != 0,
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct VmxCaps {
    pub supported: bool,
    pub feature_locked: bool,
    pub vmxon_outside_smx: bool,
    pub basic: VmxBasic,
    pub ept_supported: bool,
    pub vpid_supported: bool,
    pub unrestricted_guest: bool,
    pub apicv: bool,
    pub vmcs_shadowing: bool,
}

pub fn caps() -> VmxCaps {
    // SAFETY: leaf 1 always defined.
    let (_, _, ecx, _) = unsafe { cpuid(1, 0) };
    let supported = ecx & (1 << 5) != 0;
    if !supported {
        return VmxCaps::default();
    }

    // SAFETY: caller is at CPL=0; FEATURE_CONTROL is architectural.
    let fc = unsafe { rdmsr(MSR_IA32_FEATURE_CONTROL) };
    let feature_locked = fc & FEATURE_CONTROL_LOCK != 0;
    let vmxon_outside_smx = fc & FEATURE_CONTROL_VMXON_OUTSIDE_SMX != 0;

    // VMX MSRs only legal once VMXON is permitted. If feature isn't
    // locked or VMXON outside SMX isn't enabled, RDMSR may #GP —
    // return the supported-but-locked snapshot to the caller.
    if !feature_locked || !vmxon_outside_smx {
        return VmxCaps {
            supported,
            feature_locked,
            vmxon_outside_smx,
            ..VmxCaps::default()
        };
    }

    // SAFETY: feature lock + VMXON-outside-SMX guarantee these MSRs
    // exist.
    let basic_raw = unsafe { rdmsr(MSR_IA32_VMX_BASIC) };
    let basic = VmxBasic::decode(basic_raw);

    // SAFETY: same.
    let proc2 = unsafe { rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2) };
    // The "allowed-1" bits live in the high half (bits 32..63).
    let allowed_1 = (proc2 >> 32) as u32;
    let ept_supported = allowed_1 & (1 << 1) != 0;
    let vpid_supported = allowed_1 & (1 << 5) != 0;
    let unrestricted_guest = allowed_1 & (1 << 7) != 0;
    let apicv = allowed_1 & (1 << 8) != 0;
    let vmcs_shadowing = allowed_1 & (1 << 14) != 0;

    VmxCaps {
        supported,
        feature_locked,
        vmxon_outside_smx,
        basic,
        ept_supported,
        vpid_supported,
        unrestricted_guest,
        apicv,
        vmcs_shadowing,
    }
}

/// Read `IA32_VMX_BASIC`.
///
/// # Safety
/// CPL = 0; VMX is supported and `IA32_FEATURE_CONTROL.lock = 1`.
pub unsafe fn read_basic() -> VmxBasic {
    // SAFETY: caller-asserted.
    VmxBasic::decode(unsafe { rdmsr(MSR_IA32_VMX_BASIC) })
}
