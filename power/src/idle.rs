//! C-state idle entry — MWAIT / HLT.
//!
//! Spec: `power/specification/cpu-power.md` §2. Wraps
//! MONITOR/MWAIT for deep idle; falls back to STI;HLT when MWAIT
//! isn't available.

#![allow(dead_code)]

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

/// Probe the current CPU; capabilities are not shared across heterogeneous CPUs.
pub fn caps() -> MwaitCaps {
    let caps = narf_power_core::x86::CpuIdleCaps::probe();
    let max_cstate = (0..8)
        .rev()
        .find(|i| (caps.sub_states >> (i * 4)) & 0xf != 0)
        .unwrap_or(0);
    MwaitCaps {
        supported: caps.mwait,
        interrupt_break: caps.interrupt_break,
        sub_states: caps.sub_states,
        max_cstate: max_cstate as u8,
    }
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

/// Enter a platform-approved legacy depth. New callers use the firmware's exact
/// hint through `IdlePlan` instead of translating ACPI state numbers.
///
/// # Safety
/// CPL=0, IRQs masked, final wake check complete, no locks held. The caller
/// must have validated the firmware state and its latency against the deadline.
/// Returns with IRQs masked.
pub unsafe fn mwait(depth: u8) {
    let entry = narf_power_core::IdleEntry::Mwait {
        hint: encode_cstate(depth),
    };
    let caps = narf_power_core::x86::CpuIdleCaps::probe();
    // SAFETY: caller supplies the firmware/deadline validation and wake handshake.
    unsafe {
        if caps.supports(entry) {
            narf_power_core::x86::enter(entry);
        } else {
            narf_arch::idle_halt_then_disable();
        }
    }
}

/// Enter the installed governor's selected idle state.
///
/// # Safety
/// CPL=0, IRQs masked, final wake check complete, no locks held, deadlines armed.
/// Returns with IRQs masked.
pub unsafe fn idle() {
    let plan = narf_power_core::executor::prepare_idle(narf_power_core::IdleHints {
        cpu: narf_lib::percpu::current_cpu(),
        now_cycles: narf_time::now_cycles(),
        next_deadline_cycles: narf_time::hrtimer::next_event_cycles_local(),
    });
    // SAFETY: caller owns IRQ state and the wake handshake.
    unsafe { narf_power_core::executor::enter_idle(plan) };
}

#[doc(hidden)]
pub fn __reset_for_test() {}
