//! Hypervisor detection.
//!
//! Spec: `arch/specification/modern-cpu.md` §1.
//!
//! `CPUID(1).ECX[31]` advertises hypervisor presence;
//! `CPUID(0x40000000)` returns the 12-byte vendor signature in
//! `EBX/ECX/EDX` (legacy CPUID-vendor encoding). Sub-leaves at
//! `0x40000000 + i` carry hypervisor-specific capability bits;
//! NARF v0.1 surfaces just the vendor classification + the most
//! commonly consumed feature bits (KVM features, Hyper-V
//! recommendations).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Hypervisor {
    None,
    Kvm,
    HyperV,
    Xen,
    VMware,
    QemuTcg,
    Bhyve,
    Parallels,
    Other([u8; 12]),
}

const KVM_SIG:        &[u8; 12] = b"KVMKVMKVM\0\0\0";
const HYPERV_SIG:     &[u8; 12] = b"Microsoft Hv";
const XEN_SIG:        &[u8; 12] = b"XenVMMXenVMM";
const VMWARE_SIG:     &[u8; 12] = b"VMwareVMware";
const TCG_SIG:        &[u8; 12] = b"TCGTCGTCGTCG";
const BHYVE_SIG:      &[u8; 12] = b"bhyve bhyve ";
const PARALLELS_SIG:  &[u8; 12] = b"prl hyperv  ";

/// `true` iff `CPUID(1).ECX[31]` is set.
fn hv_present() -> bool {
    // SAFETY: leaf 1 always defined.
    let (_, _, ecx, _) = unsafe { cpuid(1, 0) };
    ecx & (1 << 31) != 0
}

/// Read the 12-byte hypervisor signature (EBX|ECX|EDX in
/// CPUID-vendor encoding). Returns `None` if no hypervisor is
/// advertised.
pub fn signature() -> Option<[u8; 12]> {
    if !hv_present() { return None; }
    // SAFETY: leaf 0x40000000 is defined when CPUID(1).ECX[31] is set.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0x4000_0000, 0) };
    let mut s = [0u8; 12];
    s[0..4].copy_from_slice(&ebx.to_le_bytes());
    s[4..8].copy_from_slice(&ecx.to_le_bytes());
    s[8..12].copy_from_slice(&edx.to_le_bytes());
    Some(s)
}

/// Classify the running hypervisor from its CPUID signature.
pub fn detect() -> Hypervisor {
    let sig = match signature() {
        Some(s) => s,
        None    => return Hypervisor::None,
    };
    match &sig {
        s if s == KVM_SIG       => Hypervisor::Kvm,
        s if s == HYPERV_SIG    => Hypervisor::HyperV,
        s if s == XEN_SIG       => Hypervisor::Xen,
        s if s == VMWARE_SIG    => Hypervisor::VMware,
        s if s == TCG_SIG       => Hypervisor::QemuTcg,
        s if s == BHYVE_SIG     => Hypervisor::Bhyve,
        s if s == PARALLELS_SIG => Hypervisor::Parallels,
        _                       => Hypervisor::Other(sig),
    }
}

/// KVM paravirt feature bitmap from `CPUID(0x40000001).EAX`.
/// Returns 0 when the host isn't KVM.
pub fn kvm_features() -> u32 {
    if detect() != Hypervisor::Kvm { return 0; }
    // SAFETY: CPUID 0x40000001 only meaningful on KVM; vendor check above.
    let (eax, _, _, _) = unsafe { cpuid(0x4000_0001, 0) };
    eax
}

/// Hyper-V recommendations bitmap from `CPUID(0x40000004).EAX`.
/// Returns 0 when the host isn't Hyper-V.
pub fn hyperv_recommendations() -> u32 {
    if detect() != Hypervisor::HyperV { return 0; }
    // SAFETY: CPUID 0x40000004 only meaningful on Hyper-V.
    let (eax, _, _, _) = unsafe { cpuid(0x4000_0004, 0) };
    eax
}

/// `(major, minor)` Hyper-V version from `CPUID(0x40000002).EBX`
/// upper / lower halves. `(0, 0)` when not Hyper-V.
pub fn hyperv_version() -> (u16, u16) {
    if detect() != Hypervisor::HyperV { return (0, 0); }
    // SAFETY: same.
    let (_, ebx, _, _) = unsafe { cpuid(0x4000_0002, 0) };
    (((ebx >> 16) & 0xFFFF) as u16, (ebx & 0xFFFF) as u16)
}

// ── Common KVM feature bits (CPUID(0x40000001).EAX) ────────────────

pub const KVM_FEATURE_CLOCKSOURCE:       u32 = 1 << 0;
pub const KVM_FEATURE_NOP_IO_DELAY:      u32 = 1 << 1;
pub const KVM_FEATURE_MMU_OP:            u32 = 1 << 2;
pub const KVM_FEATURE_CLOCKSOURCE2:      u32 = 1 << 3;
pub const KVM_FEATURE_ASYNC_PF:          u32 = 1 << 4;
pub const KVM_FEATURE_STEAL_TIME:        u32 = 1 << 5;
pub const KVM_FEATURE_PV_EOI:            u32 = 1 << 6;
pub const KVM_FEATURE_PV_UNHALT:         u32 = 1 << 7;
pub const KVM_FEATURE_PV_TLB_FLUSH:      u32 = 1 << 9;
pub const KVM_FEATURE_PV_SEND_IPI:       u32 = 1 << 11;
pub const KVM_FEATURE_PV_POLL_CONTROL:   u32 = 1 << 12;
pub const KVM_FEATURE_PV_SCHED_YIELD:    u32 = 1 << 13;
