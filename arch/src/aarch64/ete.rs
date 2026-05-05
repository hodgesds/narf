//! aarch64 ETE — Embedded Trace Extension.
//!
//! Spec: `arch/specification/cpu-arch-extensions.md` §2.
//!
//! ETE is the in-core trace generator that pairs with TRBE.
//! v0.1 surfaces only the gating + start/stop bits; the full
//! ETMv4-shaped configuration register set lands when narf-tracing
//! grows an ETE backend.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64dfr0() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64DFR0_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64dfr0_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// `true` iff `ID_AA64DFR0_EL1.TraceVer` (bits[7:4]) ≥ 1.
pub fn supported() -> bool {
    ((id_aa64dfr0() >> 4) & 0xF) != 0
}

/// `TRCPRGCTLR` raw `S2_1_C0_C1_0`. Bit 0 = EN.
fn read_prgctlr() -> u64 {
    let v: u64;
    // SAFETY: TRCPRGCTLR readable when ETE present.
    unsafe {
        asm!("mrs {}, S2_1_C0_C1_0", out(reg) v, options(nomem, nostack));
    }
    v
}

fn write_prgctlr(v: u64) {
    // SAFETY: TRCPRGCTLR writable at EL1 when ETE present.
    unsafe {
        asm!(
            "msr S2_1_C0_C1_0, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

const TRCPRGCTLR_EN: u64 = 1 << 0;

/// Enable trace generation.
///
/// # Safety
/// EL1; ETE supported; trace owner has been claimed.
pub unsafe fn enable() {
    write_prgctlr(read_prgctlr() | TRCPRGCTLR_EN);
}

/// Disable trace generation.
///
/// # Safety
/// EL1; ETE supported.
pub unsafe fn disable() {
    write_prgctlr(read_prgctlr() & !TRCPRGCTLR_EN);
}

/// Read `TRCSTATR` (`S2_1_C0_C3_0`).
///
/// # Safety
/// EL1; ETE supported.
pub unsafe fn read_status() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S2_1_C0_C3_0", out(reg) v, options(nomem, nostack));
    }
    v
}
