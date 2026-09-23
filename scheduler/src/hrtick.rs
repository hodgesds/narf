//! High-resolution tick (Linux `CONFIG_SCHED_HRTICK`): a per-task one-shot
//! slice timer, so a running task is preempted PRECISELY when its slice is
//! exhausted instead of at the next coarse periodic tick.
//!
//! At each slice start ([`crate::stackful::stamp_slice_start`]) the running
//! task's slice deadline (`tsc_started + slice_cycles`) is armed in the global
//! [`narf_time::timer_wheel`] via a **per-CPU one-shot entry**. Cancelling the
//! previous entry before registering the new one bounds it to a single entry per
//! CPU (no accumulation across non-firing yields). The wheel programs the LAPIC
//! TSC-deadline; when it fires — on the tick vector — `fire_due` runs this
//! entry's waker, which reschedules the entry's OWN CPU (the wheel is global, so
//! a fired waker may run on whichever CPU drains it), and `try_preempt` in that
//! IRQ's tail preempts.
//!
//! Feature-gated (`hrtick`): none of this compiles into the default kernel, so
//! the default build is byte-identical. Allocation-free: fixed wheel slots and a
//! static-vtable waker (no `Arc`, so `fire_due`'s IRQ-dealloc concern does not
//! apply).

use core::task::{RawWaker, RawWakerVTable, Waker};

use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::timer_wheel::{self, SleepHandle};

/// Per-CPU armed hrtick entry. Only the owning CPU arms/disarms its own slot
/// (the waker never touches it), so the lock is effectively uncontended — it is
/// present for IRQ-safety, not cross-CPU arbitration.
static HRTICK_HANDLE: [IrqSafeSpinLock<Option<SleepHandle>>; MAX_CPUS] =
    [const { IrqSafeSpinLock::new(None) }; MAX_CPUS];

/// A slice at or above this is treated as "infinite" (non-preemptible tasks set
/// `u64::MAX / 2`); arming a timer ~quarter-of-forever out is pointless, so we
/// skip it and disarm any stale entry instead.
const INFINITE_SLICE: u64 = u64::MAX / 4;

/// (Re)arm the running task's one-shot slice timer on `cpu`. Called from the
/// single slice-start choke point. `now` is the freshly stamped `tsc_started`;
/// `slice` is the task's `slice_cycles`. Both are TSC cycles, as are wheel
/// deadlines, so no unit conversion is needed.
pub(crate) fn arm(cpu: usize, now: u64, slice: u64) {
    if cpu >= MAX_CPUS {
        return;
    }
    if slice >= INFINITE_SLICE {
        // Non-preemptible / infinite-slice task: no slice timer, and drop any
        // stale entry so the wheel slot is not leaked.
        disarm(cpu);
        return;
    }
    let deadline = now.saturating_add(slice);
    let waker = make_waker(cpu as u32);
    let mut slot = HRTICK_HANDLE[cpu].lock();
    if let Some(old) = slot.take() {
        // Cancel the previous slice's entry (it did not fire, or fired and is
        // stale — cancel is a no-op on a stale generation either way).
        timer_wheel::cancel(old);
    }
    // Wheel full → this slice silently falls back to the coarse periodic-tick
    // slice poll; correctness is preserved, only precision is lost.
    if let Ok(handle) = timer_wheel::register(deadline, waker) {
        *slot = Some(handle);
    }
}

/// Drop this CPU's armed slice timer, if any (voluntary path / infinite slice).
pub(crate) fn disarm(cpu: usize) {
    if cpu >= MAX_CPUS {
        return;
    }
    if let Some(old) = HRTICK_HANDLE[cpu].lock().take() {
        timer_wheel::cancel(old);
    }
}

/// Whether `cpu` currently holds an armed slice timer (test support).
pub(crate) fn is_armed(cpu: usize) -> bool {
    cpu < MAX_CPUS && HRTICK_HANDLE[cpu].lock().is_some()
}

/// Reschedule the CPU an hrtick entry was armed for. The global wheel means the
/// waker may run on a different CPU than the target, so route by identity: the
/// local CPU just publishes `NEED_RESCHED` (its `try_preempt` runs in this same
/// tick-IRQ tail); a remote — necessarily running its slice, i.e. not halted —
/// gets a forced reschedule IPI so it preempts promptly rather than at its next
/// periodic tick.
fn reschedule(cpu: u32) {
    if cpu as usize >= MAX_CPUS {
        return;
    }
    if cpu == narf_lib::percpu::current_cpu() as u32 {
        crate::resched_current();
    } else {
        crate::resched_remote_force(cpu);
    }
}

// ── Static-vtable waker (no allocation) ──────────────────────────────────────
//
// The RawWaker's `data` pointer carries the target CPU index as an integer — it
// is never dereferenced. `clone` reproduces the same (data, vtable); both wake
// entrypoints reschedule that CPU; `drop` owns nothing.

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, wake_waker, wake_waker, drop_waker);

fn make_waker(cpu: u32) -> Waker {
    // SAFETY: `VTABLE` is 'static and its fns treat `data` purely as the CPU
    // index (never dereferenced); `clone` yields an equivalent RawWaker and
    // `drop` frees nothing, so the contract of `Waker::from_raw` holds.
    unsafe { Waker::from_raw(RawWaker::new(cpu as usize as *const (), &VTABLE)) }
}

fn clone_waker(data: *const ()) -> RawWaker {
    RawWaker::new(data, &VTABLE)
}

fn wake_waker(data: *const ()) {
    reschedule(data as usize as u32);
}

fn drop_waker(_data: *const ()) {}
