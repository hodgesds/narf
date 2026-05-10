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

// `irqs_enabled()` and `is_sleepable()` live higher up the
// crate stack — narf-lib can't depend on narf-arch (circular).
// Crates that need the combined predicate compose `in_irq()`
// here with their own arch read of RFLAGS.IF / DAIF.I.
