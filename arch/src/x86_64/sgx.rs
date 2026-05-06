//! SGX (Software Guard Extensions) detection.
//!
//! Spec: `arch/specification/virt-confidential.md` §3.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

#[derive(Copy, Clone, Debug, Default)]
pub struct EpcSection {
    pub base: u64,
    pub size_bytes: u64,
    pub valid: bool,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SgxCaps {
    pub instruction_supported: bool,
    pub sgx1: bool,
    pub sgx2: bool,
    pub miscselect: u32,
    pub max_size_64: u8,
    pub max_size_32: u8,
    pub epc_sections: [Option<EpcSection>; 4],
}

pub fn caps() -> SgxCaps {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return SgxCaps::default();
    }
    // SAFETY: leaf 7 valid.
    let (_, ebx_7, _, _) = unsafe { cpuid(7, 0) };
    let instruction_supported = ebx_7 & (1 << 2) != 0;
    if !instruction_supported || max < 0x12 {
        return SgxCaps {
            instruction_supported,
            ..SgxCaps::default()
        };
    }
    // SAFETY: leaf 0x12 valid.
    let (eax_0, ebx_0, _, edx_0) = unsafe { cpuid(0x12, 0) };
    let sgx1 = eax_0 & (1 << 0) != 0;
    let sgx2 = eax_0 & (1 << 1) != 0;
    let miscselect = ebx_0;
    let max_size_32 = (edx_0 & 0xFF) as u8;
    let max_size_64 = ((edx_0 >> 8) & 0xFF) as u8;

    // EPC sections at sub-leaves 2..N. Sub-leaf type encoded in
    // EAX[3:0]: 0 = invalid (end), 1 = EPC section.
    let mut sections: [Option<EpcSection>; 4] = [None, None, None, None];
    for sub in 2u32..6 {
        // SAFETY: leaf 0x12 valid, sub-leaf walk allowed.
        let (eax, ebx, ecx, edx) = unsafe { cpuid(0x12, sub) };
        let typ = eax & 0xF;
        if typ == 0 {
            break;
        }
        if typ == 1 {
            // Base = (EAX & 0xFFFFF000) | ((EBX & 0xFFFFF) << 32)
            // Size = (ECX & 0xFFFFF000) | ((EDX & 0xFFFFF) << 32)
            let base = (eax as u64 & 0xFFFF_F000) | ((ebx as u64 & 0xFFFFF) << 32);
            let size = (ecx as u64 & 0xFFFF_F000) | ((edx as u64 & 0xFFFFF) << 32);
            let idx = (sub - 2) as usize;
            if idx < sections.len() {
                sections[idx] = Some(EpcSection {
                    base,
                    size_bytes: size,
                    valid: true,
                });
            }
        }
    }

    SgxCaps {
        instruction_supported,
        sgx1,
        sgx2,
        miscselect,
        max_size_32,
        max_size_64,
        epc_sections: sections,
    }
}
