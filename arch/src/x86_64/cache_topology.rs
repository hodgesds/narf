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

/// True if this CPU actually implements the cache-topology CPUID leaf
/// that [`levels`] reads — Intel leaf `4`, AMD/Hygon leaf
/// `0x8000_001D` (the latter gated on CPUID.8000_0001:ECX[22],
/// TopologyExtensions). QEMU's `qemu64` TCG model (what GitHub Actions'
/// runner exposes) implements neither, so cache enumeration there
/// legitimately yields zero levels. Callers use this to tell "the CPU
/// has no cache-topology leaf" (skip) apart from "the leaf exists but
/// enumerated nothing" (a real fault).
pub fn leaf_supported() -> bool {
    match ident::read().vendor {
        Vendor::Amd | Vendor::Hygon => {
            // SAFETY: extended leaf 0x8000_0000 is always defined; it
            // reports the highest supported extended leaf in EAX.
            let (max_ext, _, _, _) = unsafe { cpuid(0x8000_0000, 0) };
            if max_ext < 0x8000_001D {
                return false;
            }
            // SAFETY: 0x8000_0001 is defined (max_ext ≥ 0x8000_001D).
            let (_, _, ecx, _) = unsafe { cpuid(0x8000_0001, 0) };
            ecx & (1 << 22) != 0 // TopologyExtensions
        }
        _ => {
            // SAFETY: leaf 0 is always defined; EAX = highest basic leaf.
            let (max_basic, _, _, _) = unsafe { cpuid(0, 0) };
            max_basic >= 4
        }
    }
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

/// Opaque identity of this CPU's last data/unified cache, for boot-time
/// topology publication. Equal identities mean a shared cache; None means
/// the platform does not describe one reliably. Never infer LLC from NUMA.
pub fn current_llc_id() -> Option<u64> {
    if !leaf_supported() {
        return None;
    }
    let ident = ident::read();
    if !matches!(ident.vendor, Vendor::Intel | Vendor::Amd)
        || (ident.vendor == Vendor::Amd && ident.family < 0x17)
    {
        return None;
    }
    let mut last: Option<CacheLevel> = None;
    levels(|cache| {
        if cache.kind != CacheKind::Instruction
            && last.is_none_or(|previous| cache.level > previous.level)
        {
            last = Some(cache);
        }
    });
    let last = last?;
    // Prefer an extended APIC ID. Legacy leaf 1 is only an eight-bit fallback.
    // SAFETY: CPUID leaf 0 and the maximum-extended-leaf query are unconditional.
    let (max_basic, _, _, _) = unsafe { cpuid(0, 0) };
    // SAFETY: the maximum-extended-leaf query is unconditional.
    let (max_ext, _, _, _) = unsafe { cpuid(0x8000_0000, 0) };
    let mut apic = None;
    for leaf in [0x1f, 0x0b] {
        if max_basic >= leaf {
            // SAFETY: the maximum basic leaf covers this topology leaf.
            let (_, logical, _, id) = unsafe { cpuid(leaf, 0) };
            if logical != 0 {
                apic = Some(id);
                break;
            }
        }
    }
    if apic.is_none() && ident.vendor == Vendor::Amd && max_ext >= 0x8000_001e {
        // SAFETY: AMD topology extensions were checked by leaf_supported.
        apic = Some(unsafe { cpuid(0x8000_001e, 0) }.0);
    }
    let apic = apic.unwrap_or_else(|| {
        // SAFETY: leaf 1 exists on supported Intel/AMD CPUs.
        unsafe { cpuid(1, 0) }.1 >> 24
    });
    // Linux cacheinfo uses ceil(log2(threads sharing)). Early Zen has the
    // documented four-core CCX topology regardless of the generic sharing field.
    let shift = if last.level == 3
        && ident.vendor == Vendor::Amd
        && ident.family == 0x17
        && ident.model <= 0x1f
    {
        3
    } else {
        u16::BITS - last.apic_ids_sharing.saturating_sub(1).leading_zeros()
    };
    Some((u64::from(last.level) << 56) | (u64::from(shift) << 48) | u64::from(apic >> shift))
}
