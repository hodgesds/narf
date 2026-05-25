//! Execution-context tracking — IRQ depth.
//!
//! Tracks whether the calling CPU is currently servicing an IRQ.
//! `enter_irq()` / `exit_irq()` are called by the arch IRQ
//! dispatcher around the body of each interrupt; `in_irq()`
//! returns true while the per-CPU depth counter is non-zero.
//!
//! Higher-level predicates (`is_sleepable()` etc.) compose this
//! with arch-side reads of RFLAGS.IF / DAIF.I; those live in
//! crates that can depend on `narf-arch` (e.g. `narf-memory`),
//! since `narf-lib` is below the arch crate in the dep graph.
//!
//! Per-CPU counters are `AtomicU32`s indexed by `current_cpu()`.
//! Only the owning CPU writes; cross-CPU reads (diagnostics)
//! observe `Acquire`-ordered loads.

use core::sync::atomic::{AtomicU32, Ordering};

const N_CPUS: usize = crate::percpu::MAX_CPUS;

/// Per-CPU IRQ-depth counters. Indexed by `current_cpu()`.
/// Only the owning CPU writes; cross-CPU reads (diagnostics)
/// observe `Acquire`-ordered loads.
static COUNTERS: [AtomicU32; N_CPUS] = {
    const ZERO_COUNTER: AtomicU32 = AtomicU32::new(0);
    [ZERO_COUNTER; N_CPUS]
};

/// Per-CPU "currently handling IRQ vector + 1". 0 = not in IRQ.
/// Diagnostic surface so allocator-context-check failures can
/// identify which ISR triggered them.
static CURRENT_IRQ_VECTOR: [AtomicU32; N_CPUS] = {
    const ZERO: AtomicU32 = AtomicU32::new(0);
    [ZERO; N_CPUS]
};

/// Set when an IRQ vector enters its handler. 0 means not in IRQ.
/// Called by `enter_irq_vector` from `dispatch::on_irq`.
#[inline]
pub fn set_current_irq_vector(vector: u8) {
    let cpu = crate::percpu::current_cpu();
    let cpu = if cpu < N_CPUS { cpu } else { 0 };
    CURRENT_IRQ_VECTOR[cpu].store((vector as u32) + 1, Ordering::Release);
}

#[inline]
pub fn clear_current_irq_vector() {
    let cpu = crate::percpu::current_cpu();
    let cpu = if cpu < N_CPUS { cpu } else { 0 };
    CURRENT_IRQ_VECTOR[cpu].store(0, Ordering::Release);
}

/// Read the currently-handling IRQ vector on this CPU. Returns
/// `None` if not in IRQ context. Diagnostic-only.
#[inline]
pub fn current_irq_vector() -> Option<u8> {
    let cpu = crate::percpu::current_cpu();
    let cpu = if cpu < N_CPUS { cpu } else { 0 };
    match CURRENT_IRQ_VECTOR[cpu].load(Ordering::Acquire) {
        0 => None,
        v => Some((v - 1) as u8),
    }
}

#[inline]
fn cpu_counter() -> &'static AtomicU32 {
    let id = crate::percpu::current_cpu();
    // current_cpu's hook clamps id < MAX_CPUS.
    &COUNTERS[id]
}

/// Increment this CPU's IRQ-depth counter. Called by the
/// arch-specific IRQ dispatcher on entry.
#[inline]
pub fn enter_irq() {
    cpu_counter().fetch_add(1, Ordering::Acquire);
}

/// Decrement this CPU's IRQ-depth counter. Called by the
/// arch-specific IRQ dispatcher on exit. Saturates at 0 to keep
/// a missing exit (programmer error) from corrupting future
/// `in_irq` reads — preferring quiet under-counting over
/// silent over-counting that would leak "in IRQ" forever.
#[inline]
pub fn exit_irq() {
    let c = cpu_counter();
    let cur = c.load(Ordering::Acquire);
    if cur > 0 {
        c.fetch_sub(1, Ordering::Release);
    }
}

/// True iff the calling CPU is currently servicing an IRQ
/// (enter_irq was called more times than exit_irq).
#[inline]
pub fn in_irq() -> bool {
    cpu_counter().load(Ordering::Acquire) > 0
}

/// Per-CPU "we're inside the trap dispatcher" flag. Set by the
/// arch trap entry (`frame::x86_64::trap::dispatch_trap` /
/// `frame::aarch64::trap::handle_irq`) and cleared on exit.
/// Distinct from `in_irq()`: `in_irq` is a depth counter set by
/// the dispatch layer regardless of caller (a smoke-test that
/// calls `on_irq` directly bumps the counter too). `in_trap_handler`
/// is true ONLY when execution actually reached us via a CPU
/// interrupt-gate vector — i.e. when sleepable allocator ops
/// must be deferred.
static IN_TRAP_HANDLER: [AtomicU32; N_CPUS] = {
    const ZERO: AtomicU32 = AtomicU32::new(0);
    [ZERO; N_CPUS]
};

/// Mark this CPU as inside a real trap-handler frame. Called by
/// the arch trap entry, NOT by `on_irq` callers.
#[inline]
pub fn enter_trap_handler() {
    let cpu = crate::percpu::current_cpu();
    let cpu = if cpu < N_CPUS { cpu } else { 0 };
    IN_TRAP_HANDLER[cpu].fetch_add(1, Ordering::Acquire);
}

/// Mark this CPU as leaving a trap-handler frame. Saturates at 0
/// to keep a stray `exit` from corrupting future reads.
#[inline]
pub fn exit_trap_handler() {
    let cpu = crate::percpu::current_cpu();
    let cpu = if cpu < N_CPUS { cpu } else { 0 };
    let c = &IN_TRAP_HANDLER[cpu];
    if c.load(Ordering::Acquire) > 0 {
        c.fetch_sub(1, Ordering::Release);
    }
}

/// True iff this CPU is currently inside a real trap-handler
/// frame (entered via a CPU interrupt-gate vector). Used by
/// `narf_interrupts::on_irq` to decide whether to defer wake
/// calls (real trap, IF=0 implied) or wake directly (synchronous
/// call, e.g. smoke tests).
#[inline]
pub fn in_trap_handler() -> bool {
    let cpu = crate::percpu::current_cpu();
    let cpu = if cpu < N_CPUS { cpu } else { 0 };
    IN_TRAP_HANDLER[cpu].load(Ordering::Acquire) > 0
}

// `irqs_enabled()` and `is_sleepable()` live higher up the
// crate stack — narf-lib can't depend on narf-arch (circular).
// Crates that need the combined predicate compose `in_irq()`
// here with their own arch read of RFLAGS.IF / DAIF.I.
