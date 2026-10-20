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
    pub cwg_bytes: u16,
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
    let cwg = ((ctr >> 24) & 0xF) as u16;
    AarchCacheCaps {
        iline_bytes: 4u16 << imin,
        dline_bytes: 4u16 << dmin,
        cwg_bytes: if cwg == 0 { 0 } else { 4u16 << cwg },
    }
}

/// Clean and invalidate `[va, va + len)` to the point of coherency
/// (`DC CIVAC` per D-cache line, then `DSB SY`).
///
/// For memory a non-coherent observer reads with its own attributes, e.g.
/// GIC ITS / redistributor tables when the GIC reports non-shareable
/// (Linux `gic_flush_dcache_to_poc`).
///
/// # Safety
/// `[va, va + len)` must be mapped kernel memory.
pub unsafe fn clean_inval_to_poc(va: usize, len: usize) {
    if len == 0 {
        return;
    }
    let line = caps().dline_bytes.max(4) as usize;
    let mut p = va & !(line - 1);
    let end = va + len;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    while p < end {
        // SAFETY: caller guarantees the range is mapped.
        unsafe {
            asm!("dc civac, {a}", a = in(reg) p, options(nostack, preserves_flags));
        }
        p += line;
    }
    // SAFETY: barrier only.
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// `DSB ISHST`: order earlier normal-memory stores before a following MMIO
/// write (Linux `its_flush_cmd` on a coherent command queue).
#[inline]
pub fn dsb_ishst() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: barrier only.
    unsafe {
        asm!("dsb ishst", options(nostack, preserves_flags));
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
