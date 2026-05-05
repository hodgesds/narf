//! aarch64 cache geometry from CTR_EL0.
//!
//! Spec: `arch/specification/cpu-info-errata.md` §5.2.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

#[derive(Copy, Clone, Debug, Default)]
pub struct AarchCacheCaps {
    pub iline_bytes: u16,
    pub dline_bytes: u16,
    pub cwg_bytes:   u16,
}

fn read_ctr_el0() -> u64 {
    let v: u64;
    // SAFETY: CTR_EL0 readable at EL1 / EL0 (subject to SCTLR.UCT).
    unsafe {
        asm!("mrs {}, ctr_el0", out(reg) v, options(nomem, nostack));
    }
    v
}

pub fn caps() -> AarchCacheCaps {
    let ctr = read_ctr_el0();
    let imin = (ctr & 0xF) as u16;
    let dmin = ((ctr >> 16) & 0xF) as u16;
    let cwg  = ((ctr >> 24) & 0xF) as u16;
    AarchCacheCaps {
        iline_bytes: 4u16 << imin,
        dline_bytes: 4u16 << dmin,
        cwg_bytes:   if cwg == 0 { 0 } else { 4u16 << cwg },
    }
}
