//! x86_64 cache topology — CPUID(4) / CPUID(0x8000_001D).
//!
//! Spec: `arch/specification/irq-cache-numa.md` §4.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::ident::{self, Vendor};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CacheKind {
    Data,
    Instruction,
    Unified,
}

#[derive(Copy, Clone, Debug)]
pub struct CacheLevel {
    pub level: u8,
    pub kind: CacheKind,
    pub line_bytes: u16,
    pub partitions: u16,
    pub ways: u16,
    pub sets: u32,
    pub size_bytes: u32,
    pub fully_assoc: bool,
    pub apic_ids_sharing: u16,
}

fn decode(eax: u32, ebx: u32, ecx: u32) -> Option<CacheLevel> {
    let kind = match eax & 0x1F {
        0 => return None,
        1 => CacheKind::Data,
        2 => CacheKind::Instruction,
        3 => CacheKind::Unified,
        _ => return None,
    };
    let level = ((eax >> 5) & 0x7) as u8;
    let fully_assoc = eax & (1 << 9) != 0;
    let sharing = (((eax >> 14) & 0xFFF) + 1) as u16;
    let line = ((ebx & 0xFFF) + 1) as u16;
    let parts = (((ebx >> 12) & 0x3FF) + 1) as u16;
    let ways = (((ebx >> 22) & 0x3FF) + 1) as u16;
    let sets = ecx + 1;
    let size = (line as u32) * (parts as u32) * (ways as u32) * sets;
    Some(CacheLevel {
        level,
        kind,
        line_bytes: line,
        partitions: parts,
        ways,
        sets,
        size_bytes: size,
        fully_assoc,
        apic_ids_sharing: sharing,
    })
}

/// Iterate cache levels until the sentinel sub-leaf (cache type = 0).
pub fn levels<F: FnMut(CacheLevel)>(mut f: F) {
    let leaf = match ident::read().vendor {
        Vendor::Amd | Vendor::Hygon => 0x8000_001Du32,
        _ => 4u32,
    };
    let mut sub = 0u32;
    loop {
        // SAFETY: leaf 0 / 0x8000_0000 always defined; valid
        // sub-leaves stop at the first cache-type-0 sentinel.
        // SAFETY: Valid memory or trusted environment
        let (eax, ebx, ecx, _) = unsafe { cpuid(leaf, sub) };
        match decode(eax, ebx, ecx) {
            Some(c) => f(c),
            None => break,
        }
        sub += 1;
        if sub > 16 {
            break;
        } // architectural soft cap
    }
}
