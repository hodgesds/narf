//! C-state idle entry — MWAIT / HLT.
//!
//! Spec: `power/specification/cpu-power.md` §2. Wraps
//! MONITOR/MWAIT for deep idle; falls back to STI;HLT when MWAIT
//! isn't available.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU8, Ordering};

use narf_arch::x86_64::cpuid::cpuid;

#[derive(Copy, Clone, Debug, Default)]
pub struct MwaitCaps {
    pub supported: bool,
    pub interrupt_break: bool,
    /// CPUID(5).EDX as-is — sub-state count nibbles per C-state.
    pub sub_states: u32,
    /// Architectural C-states the CPU supports (capped at 8 for
    /// the C0..C7 nibble layout in CPUID(5).EDX).
    pub max_cstate: u8,
}

fn probe() -> MwaitCaps {
    // CPUID(1).ECX[3] = MONITOR/MWAIT.
    // SAFETY: leaf 1 always defined.
    let (_, _, ecx, _) = unsafe { cpuid(1, 0) };
    if ecx & (1 << 3) == 0 {
        return MwaitCaps::default();
    }
    // SAFETY: leaf 5 only defined when MONITOR/MWAIT is set; we
    // just verified that.
    let (_, _, ecx5, edx5) = unsafe { cpuid(5, 0) };
    let interrupt_break = ecx5 & (1 << 1) != 0;
    // Count populated nibbles in EDX = max C-state with at least
    // one sub-state.
    let mut max_cstate = 0u8;
    for i in 0..8 {
        if (edx5 >> (i * 4)) & 0xF != 0 {
            max_cstate = i as u8;
        }
    }
    MwaitCaps {
        supported: true,
        interrupt_break,
        sub_states: edx5,
        max_cstate,
    }
}

static CAPS_RAW: AtomicU8 = AtomicU8::new(0xFF);
static MAX_DEPTH: AtomicU8 = AtomicU8::new(0);
static SUPPORTED: AtomicU8 = AtomicU8::new(0);

/// Probe + cache MWAIT capabilities.
pub fn caps() -> MwaitCaps {
    if CAPS_RAW.load(Ordering::Acquire) != 0xFF {
        return MwaitCaps {
            supported: SUPPORTED.load(Ordering::Acquire) != 0,
            interrupt_break: CAPS_RAW.load(Ordering::Acquire) & 1 != 0,
            sub_states: 0, // Not cached; CPUID is fast enough.
            max_cstate: MAX_DEPTH.load(Ordering::Acquire),
        };
    }
    let c = probe();
    CAPS_RAW.store(c.interrupt_break as u8, Ordering::Release);
    SUPPORTED.store(c.supported as u8, Ordering::Release);
    MAX_DEPTH.store(c.max_cstate, Ordering::Release);
    c
}

/// Encode a C-state depth as the `MWAIT EAX` hint per Intel's
/// documented table (C1=0x00, C1E=0x01, C2=0x10, C3=0x20,
/// C6=0x40, C7=0x50).
pub const fn encode_cstate(depth: u8) -> u32 {
    match depth {
        0 => 0x00, // C0 (active) — won't be passed
        1 => 0x00, // C1
        2 => 0x10, // C2
        3 => 0x20, // C3
        4 => 0x30, // C4
        6 => 0x40, // C6
        7 => 0x50, // C7
        _ => 0x00,
    }
}

/// Enter `MWAIT` at the requested C-state depth. Re-armed
/// MONITOR/MWAIT on a per-CPU dummy address; any IRQ wakes.
///
/// # Safety
/// CPL = 0; caps().supported is true.
pub unsafe fn mwait(depth: u8) {
    static IDLE_DUMMY: AtomicU8 = AtomicU8::new(0);
    let addr = IDLE_DUMMY.as_ptr() as u64;
    let hint = encode_cstate(depth);
    let ext = caps().interrupt_break as u32;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            "monitor",
            in("rax") addr,
            in("rcx") 0u32,
            in("rdx") 0u32,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "mwait",
            in("rax") hint,
            in("rcx") ext,
            options(nomem, nostack),
        );
    }
}

/// Canonical kernel idle entry. Picks the deepest supported
/// C-state when MWAIT is available; falls back to STI;HLT.
///
/// # Safety
/// CPL = 0; called from the idle task's body with interrupts in
/// the standard "ready to be enabled" state.
pub unsafe fn idle() {
    let c = caps();
    if c.supported && c.max_cstate > 0 {
        // SAFETY: caller-asserted; caps() validated.
        unsafe {
            mwait(c.max_cstate);
        }
    } else {
        // SAFETY: STI;HLT canonical idle pair.
        unsafe {
            core::arch::asm!("sti", "hlt", options(nomem, nostack));
        }
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    CAPS_RAW.store(0xFF, Ordering::Release);
    SUPPORTED.store(0, Ordering::Release);
    MAX_DEPTH.store(0, Ordering::Release);
}
