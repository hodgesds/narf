//! aarch64 cache topology — CLIDR_EL1 + CCSIDR_EL1 enumeration.
//!
//! Spec: `arch/specification/irq-cache-numa.md` §5.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CacheKind {
    Data,
    Instruction,
    Unified,
}

#[derive(Copy, Clone, Debug)]
pub struct CacheLevel {
    pub level:       u8,
    pub kind:        CacheKind,
    pub line_bytes:  u16,
    pub ways:        u16,
    pub sets:        u32,
    pub size_bytes:  u32,
}

fn read_clidr() -> u64 {
    let v: u64;
    // SAFETY: CLIDR_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, clidr_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

fn read_ccsidr() -> u64 {
    let v: u64;
    // SAFETY: CCSIDR_EL1 readable after CSSELR_EL1 is set.
    unsafe {
        asm!("mrs {}, ccsidr_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

unsafe fn select(level: u8, instr: bool) {
    let val = ((level as u64 - 1) << 1) | (instr as u64);
    // SAFETY: caller picks a valid level; CSSELR_EL1 is RW EL1.
    unsafe {
        asm!(
            "msr csselr_el1, {}",
            "isb",
            in(reg) val,
            options(nostack, preserves_flags),
        );
    }
}

fn decode_ccsidr(level: u8, kind: CacheKind, ccsidr: u64) -> CacheLevel {
    let line  = 4u16 << (ccsidr & 0x7);                          // bits[2:0] = log2(line / 4)
    let ways  = (((ccsidr >> 3) & 0x3FF) + 1) as u16;            // bits[12:3] = ways - 1
    let sets  = (((ccsidr >> 13) & 0x7FFF) + 1) as u32;          // bits[27:13] = sets - 1
    let size  = (line as u32) * (ways as u32) * sets;
    CacheLevel { level, kind, line_bytes: line, ways, sets, size_bytes: size }
}

pub fn levels<F: FnMut(CacheLevel)>(mut f: F) {
    let clidr = read_clidr();
    for lvl in 1..=7u8 {
        let field = ((clidr >> (3 * (lvl as u64 - 1))) & 0x7) as u8;
        if field == 0 { break; }
        let mut emit = |kind: CacheKind, instr: bool| {
            // SAFETY: level + side selected per ARM ARM.
            unsafe { select(lvl, instr); }
            let cc = read_ccsidr();
            f(decode_ccsidr(lvl, kind, cc));
        };
        match field {
            1 => emit(CacheKind::Instruction, true),
            2 => emit(CacheKind::Data, false),
            3 => {
                emit(CacheKind::Instruction, true);
                emit(CacheKind::Data, false);
            }
            4 => emit(CacheKind::Unified, false),
            _ => {} // reserved
        }
    }
}
