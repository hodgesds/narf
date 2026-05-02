//! Intel PT (Processor Trace) — full-fidelity instruction trace.
//!
//! Spec: `observability/specification/perfmon.md` §3.
//!
//! PT streams encoded packets into an OS-supplied physical
//! buffer described by a Table of Physical Addresses (ToPA).
//! NARF v0.1 wires the MSR + ToPA registration surface so the
//! tracing recorder can claim a buffer + the kernel can flush
//! and consume the stream. Decoder is out of scope (lives in
//! userspace tooling).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

// ── MSR map ────────────────────────────────────────────────────────

pub const MSR_IA32_RTIT_CTL:              u32 = 0x570;
pub const MSR_IA32_RTIT_STATUS:           u32 = 0x571;
pub const MSR_IA32_RTIT_OUTPUT_BASE:      u32 = 0x560;
pub const MSR_IA32_RTIT_OUTPUT_MASK_PTRS: u32 = 0x561;
pub const MSR_IA32_RTIT_CR3_MATCH:        u32 = 0x572;
pub const MSR_IA32_RTIT_ADDR0_A:          u32 = 0x580;

// CTL bits.
const CTL_TRACE_EN:    u64 = 1 << 0;
const CTL_OS:          u64 = 1 << 2;
const CTL_USER:        u64 = 1 << 3;
const CTL_CR3_FILTER:  u64 = 1 << 7;
const CTL_TOPA:        u64 = 1 << 8;
const CTL_DIS_RETC:    u64 = 1 << 11;
const CTL_BRANCH_EN:   u64 = 1 << 13;

#[derive(Copy, Clone, Debug, Default)]
pub struct PtCaps {
    pub supported:        bool,
    pub topa:             bool,
    pub multi_topa:       bool,
    pub branch_filter:    bool,
}

pub fn caps() -> PtCaps {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x14 { return PtCaps::default(); }
    // SAFETY: leaf 0x14 valid.
    let (eax, _, ecx, _) = unsafe { cpuid(0x14, 0) };
    if eax == 0 {
        return PtCaps::default();
    }
    PtCaps {
        supported:     true,
        topa:          ecx & (1 << 0) != 0,
        multi_topa:    ecx & (1 << 1) != 0,
        branch_filter: false, // CPUID(0x14, 0).EBX[2]; bit-decoded
                              // separately by callers that need it.
    }
}

// ── ToPA entry encoding ────────────────────────────────────────────

/// Build a ToPA entry per SDM Vol 3 §35.2.6.2:
///
///   bits[63:12] = base phys
///   bits[5]     = END (last entry — wraps to base of ToPA)
///   bits[4]     = INT (raise PMI when filled)
///   bits[2:0]   = size (0=4K, 1=8K, 2=16K, 3=32K, ...)
pub const fn topa_entry(base_phys: u64, size_log2: u8, end: bool, int: bool) -> u64 {
    let mut v = base_phys & 0xFFFF_FFFF_FFFF_F000;
    let size_field = (size_log2 - 12) as u64; // 0=4K, 1=8K, ...
    v |= size_field & 0x7;
    if int { v |= 1 << 4; }
    if end { v |= 1 << 5; }
    v
}

/// Install a single-entry ToPA. The ToPA itself is stored at
/// `topa_phys`: 8-byte entry (the ring buffer) followed by an
/// END entry that loops back to the start.
///
/// `ring_phys` is the trace buffer (must be a power of two, ≥ 4 KiB,
/// ≤ 128 MiB). `ring_size_log2` is `log2(size)`; e.g. 12 for 4 KiB.
///
/// # Safety
/// CPL = 0; ToPA support advertised; the caller-provided
/// `topa_phys` + `ring_phys` are coherent + identity-mapped.
pub unsafe fn install_topa(
    topa_phys:      u64,
    ring_phys:      u64,
    ring_size_log2: u8,
) {
    // SAFETY: caller-asserted.
    unsafe {
        // Entry 0: ring buffer.
        core::ptr::write_volatile(
            topa_phys as *mut u64,
            topa_entry(ring_phys, ring_size_log2, false, false),
        );
        // Entry 1: END pointer back to topa_phys.
        core::ptr::write_volatile(
            (topa_phys + 8) as *mut u64,
            topa_entry(topa_phys, 12, true, false),
        );
    }
    // SAFETY: same.
    unsafe { wrmsr(MSR_IA32_RTIT_OUTPUT_BASE, topa_phys); }
    // OUTPUT_MASK_PTRS = 0 (start at the head of the ring + ToPA
    // index = 0 — the CPU advances both during tracing).
    // SAFETY: same.
    unsafe { wrmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0); }
}

/// Enable PT recording. `os` / `usr` ring filters; ToPA always on.
///
/// # Safety
/// CPL = 0; `install_topa` was called; PT supported.
pub unsafe fn enable(os: bool, usr: bool) {
    let mut v = CTL_TRACE_EN | CTL_TOPA | CTL_BRANCH_EN;
    if os  { v |= CTL_OS; }
    if usr { v |= CTL_USER; }
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_RTIT_CTL, v); }
}

/// Disable PT recording (clears `IA32_RTIT_CTL.TraceEn`).
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable() {
    // SAFETY: caller-asserted.
    let cur = unsafe { rdmsr(MSR_IA32_RTIT_CTL) };
    // SAFETY: same.
    unsafe { wrmsr(MSR_IA32_RTIT_CTL, cur & !CTL_TRACE_EN); }
}

/// Current write offset within the ring (low 32 bits of
/// `IA32_RTIT_OUTPUT_MASK_PTRS`).
///
/// # Safety
/// CPL = 0.
pub unsafe fn output_offset() -> u32 {
    // SAFETY: caller-asserted.
    (unsafe { rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS) } >> 32) as u32
}

/// Read raw `IA32_RTIT_STATUS` for diagnostics.
///
/// # Safety
/// CPL = 0.
pub unsafe fn status() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_RTIT_STATUS) }
}
