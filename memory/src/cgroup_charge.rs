//! cgroup-v2 memory-controller charge seam (feature `cgroup`).
//!
//! The page/frame allocator has no per-task identity of its own (it is
//! driven from per-CPU context, not per-PID — see `narf_lib::percpu`),
//! so charging is wired through two installed fn-pointer hooks, exactly
//! like the devfs `install_*_hook` indirection:
//!
//!   * a **PID provider** — `fn() -> Option<u64>` — that answers "which
//!     task is allocating right now" (installed by whichever crate owns
//!     the current-task register; absent until then ⇒ charges are
//!     no-ops, so early-boot allocations are simply unattributed);
//!   * a **charge hook** — `fn(pid, delta_bytes: i64) -> bool` — that
//!     the cgroupfs `memory` controller installs at boot. A positive
//!     delta charges, a negative delta uncharges. The bool return is
//!     the enforcement signal: `false` means the charge would push some
//!     level over `memory.max`, so the allocator must fail the
//!     allocation.
//!
//! Linux ref: `mm/memcontrol.c` (`try_charge` / `mem_cgroup_uncharge`).

use core::sync::atomic::{AtomicUsize, Ordering};

/// `fn(pid: u64, delta_bytes: i64) -> bool`, installed by the cgroupfs
/// `memory` controller. Returns `false` to deny (over `memory.max`).
static CHARGE_HOOK: AtomicUsize = AtomicUsize::new(0);

/// `fn() -> Option<u64>`, installed by the current-task owner. Resolves
/// the PID to charge. `None` ⇒ no attributable task (charge is skipped).
static PID_PROVIDER: AtomicUsize = AtomicUsize::new(0);

/// Install the cgroup memory charge hook. `h` is called on every
/// user-facing frame allocation with a positive byte delta and on every
/// free with a negative delta. It must return `false` iff the (positive)
/// charge would exceed a `memory.max` on the task's cgroup chain, in
/// which case the allocator fails the allocation. A `0` pointer (never
/// installed) disables charging.
pub fn install_cgroup_charge_hook(h: fn(pid: u64, delta_bytes: i64) -> bool) {
    CHARGE_HOOK.store(h as usize, Ordering::Release);
}

/// Install the current-charge-PID provider. The allocator has no
/// per-task context of its own; this hook lets the task/scheduler layer
/// supply "the PID to charge for the in-flight allocation". Until
/// installed, allocations are unattributed (charging is a no-op).
pub fn install_cgroup_pid_provider(p: fn() -> Option<u64>) {
    PID_PROVIDER.store(p as usize, Ordering::Release);
}

/// Test-only: invoke the installed charge-PID provider directly, so a
/// sibling crate (the scheduler, which installs it) can assert the
/// wiring resolves the current task without driving a real allocation.
#[doc(hidden)]
pub fn __charge_pid_for_test() -> Option<u64> {
    current_charge_pid()
}

/// Resolve the PID to charge for the current allocation, if any.
fn current_charge_pid() -> Option<u64> {
    let ptr = PID_PROVIDER.load(Ordering::Acquire);
    if ptr == 0 {
        return None;
    }
    // SAFETY: `ptr` is non-zero (checked) and was produced by
    // `install_cgroup_pid_provider` storing a `fn() -> Option<u64>` via
    // `as usize`. A function-pointer round-trip through `usize` is valid
    // (identical size/alignment) and we transmute back to the exact same
    // signature, so `f` names a live function.
    let f: fn() -> Option<u64> = unsafe { core::mem::transmute(ptr) };
    f()
}

/// Invoke the installed charge hook with `delta_bytes` for `pid`.
/// Returns `true` if the charge is allowed (or no hook is installed),
/// `false` if the hook denies it (over `memory.max`).
fn invoke(pid: u64, delta_bytes: i64) -> bool {
    let ptr = CHARGE_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return true;
    }
    // SAFETY: `ptr` is non-zero (checked) and was produced by
    // `install_cgroup_charge_hook` storing a `fn(u64, i64) -> bool` via
    // `as usize`; the transmute back to the identical signature is valid
    // and names a live function.
    let f: fn(u64, i64) -> bool = unsafe { core::mem::transmute(ptr) };
    f(pid, delta_bytes)
}

/// Charge `bytes` to the current task's cgroup chain before an
/// allocation commits. Returns `false` iff some level is over its
/// `memory.max` and the allocation must be denied. Unattributed
/// allocations (no PID provider, or `None` PID — e.g. early boot and
/// kernel-internal allocs) are always allowed and not accounted.
///
/// `pub` rather than `pub(crate)` because not every accountable
/// allocation goes through the frame allocator. A BPF map is a
/// heap-backed object whose whole size is chosen by a `bpf(2)`
/// argument (`bpf/src/map.rs`), so it has to charge for itself; the
/// alternative is an fd that pins unbounded kernel memory outside any
/// `memory.max`. Callers outside this crate own the pairing: every
/// successful `try_charge` needs exactly one [`uncharge`] on the
/// object's teardown path *and* on the failure path in between.
#[must_use]
pub fn try_charge(bytes: u64) -> bool {
    let Some(pid) = current_charge_pid() else {
        return true;
    };
    invoke(pid, bytes as i64)
}

/// Uncharge `bytes` from the current task's cgroup chain on free. Best
/// effort: a free can race the task's exit/detach, and unattributed
/// frees are simply ignored. The hook's return is irrelevant for an
/// uncharge (a negative delta never denies).
///
/// `pub` for the same reason [`try_charge`] is.
pub fn uncharge(bytes: u64) {
    if let Some(pid) = current_charge_pid() {
        let _ = invoke(pid, -(bytes as i64));
    }
}
