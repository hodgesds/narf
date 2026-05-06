//! aarch64 FEAT_E0PD — privileged-only data on TTBR0/TTBR1.
//!
//! Spec: `arch/specification/cpu-mem-encrypt-virt.md` §5.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64mmfr2() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64MMFR2_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64mmfr2_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Raw `ID_AA64MMFR2_EL1.E0PD` field (bits[63:60]).
pub fn caps() -> u8 {
    ((id_aa64mmfr2() >> 60) & 0xF) as u8
}

pub fn supported() -> bool {
    caps() >= 1
}

const TCR_E0PD0: u64 = 1 << 55;
const TCR_E0PD1: u64 = 1 << 56;

fn read_tcr_el1() -> u64 {
    let v: u64;
    // SAFETY: TCR_EL1 RW at EL1.
    unsafe {
        asm!("mrs {}, tcr_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

fn write_tcr_el1(v: u64) {
    // SAFETY: TCR_EL1 RW at EL1.
    unsafe {
        asm!(
            "msr tcr_el1, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// Set `TCR_EL1.E0PD1` — make EL0 accesses to TTBR1 (kernel
/// half) translate-fault before walking.
///
/// # Safety
/// EL1; FEAT_E0PD supported.
pub unsafe fn enable_kernel_half() {
    write_tcr_el1(read_tcr_el1() | TCR_E0PD1);
}

/// Clear the bit. Restores legacy behaviour.
///
/// # Safety
/// EL1.
pub unsafe fn disable_kernel_half() {
    write_tcr_el1(read_tcr_el1() & !TCR_E0PD1);
}
