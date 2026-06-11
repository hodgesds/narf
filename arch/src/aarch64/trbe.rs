//! aarch64 TRBE — Trace Buffer Extension.
//!
//! Spec: `arch/specification/cpu-telemetry-qos.md` §4.
//!
//! TRBE pairs with the SoC's trace generator (ETE) to write a
//! linear stream of trace bytes into a memory buffer the OS
//! supplies via `TRBBASER_EL1` / `TRBLIMITR_EL1`. v0.1 lands the
//! caps + buffer-programming surface; the consumer-side decoder
//! is out of scope.

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

/// `true` iff `ID_AA64DFR0_EL1.TraceBuffer` (bits[47:44]) ≥ 1.
pub fn supported() -> bool {
    ((id_aa64dfr0() >> 44) & 0xF) != 0
}

/// `TRBIDR_EL1` raw encoding `S3_0_C9_C11_7`.
///
/// # Safety
/// EL1; TRBE supported.
pub unsafe fn read_trbidr() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C9_C11_7", out(reg) v, options(nomem, nostack));
    }
    v
}

/// `TRBLIMITR_EL1` raw encoding `S3_0_C9_C11_0`.
///
/// # Safety
/// EL1; TRBE supported.
pub unsafe fn read_trblimitr() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C9_C11_0", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Write `TRBLIMITR_EL1` (`S3_0_C9_C11_0`).
///
/// # Safety
/// EL1; TRBE supported. Writes a privileged `MSR` controlling the trace
/// buffer limit and enable bit.
pub unsafe fn write_trblimitr(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C9_C11_0, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// Program the buffer base + limit. `base` must be page-aligned;
/// `limit` is the inclusive byte limit (`base + size - 1`).
///
/// # Safety
/// EL1; TRBE supported; the buffer is at least `limit - base + 1`
/// bytes of contiguous physical memory the trace generator may
/// write to.
pub unsafe fn write_base(base: u64, limit: u64) {
    // SAFETY: caller-asserted. TRBBASER_EL1 = S3_0_C9_C11_2.
    unsafe {
        asm!("msr S3_0_C9_C11_2, {}", in(reg) base, options(nostack, preserves_flags));
    }
    // SAFETY: caller-asserted. TRBPTR_EL1 = S3_0_C9_C11_1.
    unsafe {
        asm!("msr S3_0_C9_C11_1, {}", in(reg) base, options(nostack, preserves_flags));
    }
    // SAFETY: caller-asserted. TRBLIMITR controls limit + enable.
    let prev = unsafe { read_trblimitr() } & 0xFFF; // preserve low control bits
                                                    // SAFETY: caller-asserted EL1 + TRBE; writes the new limit preserving
                                                    // the existing low control bits.
    unsafe {
        write_trblimitr((limit & !0xFFF) | prev);
    }
}

const TRBLIMITR_E: u64 = 1 << 0;

/// Enable the trace buffer (`TRBLIMITR.E`).
///
/// # Safety
/// EL1; TRBE supported; `write_base` called previously.
pub unsafe fn enable() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_trblimitr() } | TRBLIMITR_E;
    // SAFETY: caller-asserted EL1 + TRBE; sets the enable bit.
    unsafe {
        write_trblimitr(v);
    }
}

/// Disable the trace buffer (clear `TRBLIMITR.E`).
///
/// # Safety
/// EL1; TRBE supported.
pub unsafe fn disable() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_trblimitr() } & !TRBLIMITR_E;
    // SAFETY: caller-asserted EL1 + TRBE; clears the enable bit.
    unsafe {
        write_trblimitr(v);
    }
}
