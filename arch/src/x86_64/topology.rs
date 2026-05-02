//! CPU topology + cache geometry decoder.
//!
//! Spec: `arch/specification/smp-topology.md` §1. CPUID leaves:
//!
//!   - **0x1F** (V2 extended topology) — preferred when present.
//!   - **0x0B** (extended topology) — Skylake+.
//!   - **0x04** (deterministic cache parameters) — every CPU.
//!   - **0x1A** (hybrid information) — Alder Lake+.
//!   - **CPUID(7, 0).EDX[15]** — hybrid flag.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LevelKind {
    Invalid,
    Smt,
    Core,
    Module,
    Tile,
    Die,
    Domain,
    Package,
}

impl LevelKind {
    fn from_raw(b: u8) -> Self {
        match b {
            0 => Self::Invalid,
            1 => Self::Smt,
            2 => Self::Core,
            3 => Self::Module,
            4 => Self::Tile,
            5 => Self::Die,
            6 => Self::Domain,
            _ => Self::Invalid,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LevelInfo {
    pub kind:                  LevelKind,
    /// Bits to right-shift the APIC id to compute the next-level id.
    pub apic_shift:            u8,
    /// Logical processors at this level (cumulative, per SDM).
    pub logical_at_this_level: u32,
}

#[derive(Debug, Default)]
pub struct Topology {
    pub levels:        [Option<LevelInfo>; 6],
    pub n_levels:      u8,
    pub package_count: u32,
    pub core_count:    u32,
    pub thread_count:  u32,
    pub hybrid:        bool,
    /// `core_type` byte from CPUID(0x1A) on hybrid CPUs:
    /// `0x20 = Atom (E-core)`, `0x40 = Core (P-core)`.
    pub core_type:     u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CacheKind { Null, Data, Instr, Unified }

impl CacheKind {
    fn from_raw(b: u8) -> Self {
        match b {
            1 => Self::Data,
            2 => Self::Instr,
            3 => Self::Unified,
            _ => Self::Null,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct CacheLevelInfo {
    pub level:                u8,
    pub kind:                 CacheKind,
    pub bytes:                u64,
    pub line_size:            u16,
    pub ways:                 u16,
    pub partitions:           u16,
    pub sets:                 u32,
    pub max_threads_sharing:  u32,
    pub fully_associative:    bool,
}

fn cpuid_max() -> u32 {
    // SAFETY: leaf 0 always defined.
    unsafe { cpuid(0, 0).0 }
}

fn extended_topo_leaf() -> Option<u32> {
    let max = cpuid_max();
    if max >= 0x1F {
        // SAFETY: leaf 0x1F valid.
        let (_, ebx, _, _) = unsafe { cpuid(0x1F, 0) };
        if ebx != 0 { return Some(0x1F); }
    }
    if max >= 0x0B {
        // SAFETY: leaf 0xB valid.
        let (_, ebx, _, _) = unsafe { cpuid(0x0B, 0) };
        if ebx != 0 { return Some(0x0B); }
    }
    None
}

fn hybrid_flag() -> bool {
    if cpuid_max() < 7 { return false; }
    // SAFETY: leaf 7 valid.
    let (_, _, _, edx) = unsafe { cpuid(7, 0) };
    edx & (1 << 15) != 0
}

fn core_type_byte() -> u8 {
    if cpuid_max() < 0x1A { return 0; }
    // SAFETY: leaf 0x1A valid.
    let (eax, _, _, _) = unsafe { cpuid(0x1A, 0) };
    ((eax >> 24) & 0xFF) as u8
}

pub fn discover() -> Topology {
    let mut t = Topology::default();
    t.hybrid = hybrid_flag();
    t.core_type = core_type_byte();

    if let Some(leaf) = extended_topo_leaf() {
        // Walk sub-leaves until EAX = 0 + ECX[15:8] = 0.
        for sub in 0u32..6 {
            // SAFETY: leaf already validated as available.
            let (eax, ebx, ecx, _) = unsafe { cpuid(leaf, sub) };
            let kind_raw = ((ecx >> 8) & 0xFF) as u8;
            if ebx == 0 && kind_raw == 0 { break; }
            let info = LevelInfo {
                kind: LevelKind::from_raw(kind_raw),
                apic_shift: (eax & 0x1F) as u8,
                logical_at_this_level: ebx & 0xFFFF,
            };
            t.levels[sub as usize] = Some(info);
            t.n_levels = (sub as u8) + 1;
        }
        // Derived counts: SMT level → threads-per-core; Core
        // level → cores-per-package.
        let mut threads_per_core = 1u32;
        let mut cores_per_pkg    = 1u32;
        for l in t.levels.iter().flatten() {
            match l.kind {
                LevelKind::Smt  => threads_per_core = l.logical_at_this_level.max(1),
                LevelKind::Core => cores_per_pkg    = l.logical_at_this_level.max(1),
                _ => {}
            }
        }
        // The Core level's logical-processors is total threads
        // across all cores in the package, so cores = that / threads.
        let cores = (cores_per_pkg / threads_per_core).max(1);
        t.thread_count = cores_per_pkg.max(threads_per_core);
        t.core_count   = cores;
        t.package_count = 1; // Best-effort; needs APIC id walk.
    } else {
        // Legacy path: CPUID(1).EBX[23:16] is logical-processors.
        // SAFETY: leaf 1 always defined.
        let (_, ebx, _, _) = unsafe { cpuid(1, 0) };
        let logical = ((ebx >> 16) & 0xFF) as u32;
        t.thread_count = logical.max(1);
        t.core_count   = 1;
        t.package_count = 1;
    }
    t
}

pub fn discover_caches() -> [Option<CacheLevelInfo>; 4] {
    let mut out: [Option<CacheLevelInfo>; 4] = [None, None, None, None];
    if cpuid_max() < 4 { return out; }
    for sub in 0u32..4 {
        // SAFETY: leaf 4 valid (every modern CPU).
        let (eax, ebx, ecx, _) = unsafe { cpuid(4, sub) };
        let kind = CacheKind::from_raw((eax & 0x1F) as u8);
        if kind == CacheKind::Null { break; }
        let level = ((eax >> 5) & 0x7) as u8;
        let max_threads_sharing = (((eax >> 14) & 0xFFF) + 1) as u32;
        let line_size = ((ebx & 0xFFF) + 1) as u16;
        let partitions = (((ebx >> 12) & 0x3FF) + 1) as u16;
        let ways = (((ebx >> 22) & 0x3FF) + 1) as u16;
        let sets = ecx + 1;
        let bytes = line_size as u64 * partitions as u64 * ways as u64 * sets as u64;
        let fa = eax & (1 << 9) != 0;
        out[sub as usize] = Some(CacheLevelInfo {
            level, kind, bytes, line_size, ways, partitions, sets,
            max_threads_sharing,
            fully_associative: fa,
        });
    }
    out
}
