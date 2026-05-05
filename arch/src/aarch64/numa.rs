//! aarch64 NUMA primitives — MPIDR_EL1 cluster decode.
//!
//! Spec: `arch/specification/irq-cache-numa.md` §6.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

/// Read the per-CPU MPIDR_EL1.
fn read_mpidr_el1() -> u64 {
    let v: u64;
    // SAFETY: MPIDR_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Pure helper: extract Aff2 from a packed `MPIDR_EL1` value.
/// Aff2 is bits[23:16] and is the de-facto "cluster" / NUMA
/// domain on most aarch64 SoCs.
pub fn cluster_id(mpidr: u64) -> u8 {
    ((mpidr >> 16) & 0xFF) as u8
}

/// NUMA domain for the calling CPU.
pub fn domain_for_current_cpu() -> u8 {
    cluster_id(read_mpidr_el1())
}
