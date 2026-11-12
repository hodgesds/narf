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
    let charged = invoke(pid, bytes as i64);
    if !charged {
        DENIALS.fetch_add(1, Ordering::Relaxed);
        LAST_DENIED_PID.store(pid as usize, Ordering::Relaxed);
    }
    charged
}

static DENIALS: AtomicUsize = AtomicUsize::new(0);
static LAST_DENIED_PID: AtomicUsize = AtomicUsize::new(0);

/// `(charges refused since boot, pid of the last refused charge)`. An
/// allocation refused here fails although the frame allocator has memory, so
/// the allocation-failure report prints it.
pub fn denials() -> (usize, usize) {
    (
        DENIALS.load(Ordering::Relaxed),
        LAST_DENIED_PID.load(Ordering::Relaxed),
    )
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

// ── Per-page charging (Linux `mem_cgroup_charge` / `folio->memcg_data`) ──
//
// User pages — anonymous memory, file pages a task brings into the page
// cache, shmem/tmpfs pages — are charged to the memory cgroup of the task
// that allocates them, and the allocator records WHICH memory cgroup on the
// frame itself (`frame::set_frame_memcg`). The free path uncharges that
// recorded cgroup, not whoever happens to be running when the last owner
// drops the page. Kernel memory (the heap, page tables, driver and
// filesystem buffers) is not charged at all, as in Linux without
// `__GFP_ACCOUNT`; nothing in the kernel heap path can be refused by a cgroup.
//
// A memory cgroup is named by a `MemcgId` (Linux `mem_cgroup_id`, 1..=65535;
// 0 = no cgroup). The cgroupfs memory controller owns the ids and keeps a
// removed cgroup's id (and its counters) alive until every page charged to it
// has been uncharged, so a late uncharge always lands where the charge went.

/// A memory cgroup's id; 0 means "not charged to any cgroup".
pub type MemcgId = u32;

/// `fn(pid, bytes, force) -> Result<MemcgId, MemcgId>`: charge `bytes` to
/// `pid`'s memory cgroup chain. `Ok(0)` = nothing charged (no memory cgroup,
/// or a nested charge from inside the controller); `Ok(id)` = charged,
/// uncharge later with that id; `Err(id)` = refused because cgroup `id` is at
/// its `memory.max` (the scope for a memcg OOM kill). With `force` the hook
/// charges past `memory.max` instead of refusing (Linux `__GFP_NOFAIL`) and
/// returns `Ok`.
static PAGE_CHARGE_HOOK: AtomicUsize = AtomicUsize::new(0);
/// `fn(MemcgId, bytes)`: uncharge `bytes` from `id` and its ancestors.
static PAGE_UNCHARGE_HOOK: AtomicUsize = AtomicUsize::new(0);
/// `fn(MemcgId, pid) -> bool`: run a memory-cgroup OOM kill for `id`, from a
/// context with no allocator or address-space lock held (the OOM reaper).
static MEMCG_OOM_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the per-page charge hooks. Called once by the cgroupfs memory
/// controller, before any memory cgroup can be charged.
pub fn install_page_charge_hooks(
    charge: fn(u64, u64, bool) -> Result<MemcgId, MemcgId>,
    uncharge: fn(MemcgId, u64),
    oom: fn(MemcgId, u64) -> bool,
) {
    PAGE_UNCHARGE_HOOK.store(uncharge as usize, Ordering::Release);
    MEMCG_OOM_HOOK.store(oom as usize, Ordering::Release);
    PAGE_CHARGE_HOOK.store(charge as usize, Ordering::Release);
}

/// Charge `bytes` of user memory to the current task's memory cgroup and
/// return `(memcg, pid)`; `memcg` 0 when there is no task or no memory cgroup.
/// A refusal returns the cgroup at its limit. With `force`, a charge past the
/// limit is taken anyway and returned as `Ok`, and the breach is reported to
/// nobody: a forced charge is for an allocation that must not fail (a
/// copy-on-write break of a page the task already owns).
pub(crate) fn charge_current(bytes: u64, force: bool) -> Result<(MemcgId, u64), (MemcgId, u64)> {
    let Some(pid) = current_charge_pid() else {
        return Ok((0, 0));
    };
    let ptr = PAGE_CHARGE_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return Ok((0, pid));
    }
    // SAFETY: only `install_page_charge_hooks` stores this word, from a
    // `fn(u64, u64, bool) -> Result<MemcgId, MemcgId>`; the round trip
    // through `usize` preserves the function pointer.
    let f: fn(u64, u64, bool) -> Result<MemcgId, MemcgId> = unsafe { core::mem::transmute(ptr) };
    match f(pid, bytes, force) {
        Ok(id) => {
            if id != 0 {
                USER_CHARGED_BYTES.fetch_add(bytes, Ordering::Relaxed);
            }
            Ok((id, pid))
        }
        Err(id) => {
            DENIALS.fetch_add(1, Ordering::Relaxed);
            LAST_DENIED_PID.store(pid as usize, Ordering::Relaxed);
            Err((id, pid))
        }
    }
}

/// Uncharge `bytes` from memory cgroup `id` (and its ancestors). No-op for 0.
/// Allocation-free; callable from any frame-free path.
pub(crate) fn uncharge_memcg(id: MemcgId, bytes: u64) {
    if id == 0 || bytes == 0 {
        return;
    }
    let ptr = PAGE_UNCHARGE_HOOK.load(Ordering::Acquire);
    if ptr == 0 {
        return;
    }
    // SAFETY: stored only by `install_page_charge_hooks` from a
    // `fn(MemcgId, u64)`.
    let f: fn(MemcgId, u64) = unsafe { core::mem::transmute(ptr) };
    f(id, bytes);
    USER_CHARGED_BYTES.fetch_sub(bytes, Ordering::Relaxed);
}

/// User memory (anonymous and file pages) currently charged to some memory
/// cgroup, through the page-charge hooks. The memory-cgroup view of
/// `AnonPages + Cached`; 0 without memory cgroups.
static USER_CHARGED_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Bytes of user memory charged to memory cgroups right now.
pub fn user_charged_bytes() -> u64 {
    USER_CHARGED_BYTES.load(Ordering::Relaxed)
}

/// One pending memory-cgroup OOM request: `(memcg id, faulting pid)`. Linux
/// records the OOM in the faulting task and runs it once the fault has
/// dropped its locks (`mem_cgroup_oom_synchronize`); NARF hands it to the OOM
/// reaper, which runs with no lock held, and the faulting task waits on a
/// reclaim ticket meanwhile.
const MEMCG_OOM_SLOTS: usize = 16;
static MEMCG_OOM_PENDING: [core::sync::atomic::AtomicU64; MEMCG_OOM_SLOTS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MEMCG_OOM_SLOTS];
static MEMCG_OOM_REQUESTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Queue a memory-cgroup OOM for `id` on behalf of `pid` and wake the reaper.
/// Duplicate requests for the same cgroup coalesce; a full table drops the
/// request (the next refused charge queues it again). Allocation-free.
pub(crate) fn request_memcg_oom(id: MemcgId, pid: u64) {
    if id == 0 {
        return;
    }
    let word = (u64::from(id) << 40) | (pid & ((1 << 40) - 1));
    for slot in &MEMCG_OOM_PENDING {
        let current = slot.load(Ordering::Acquire);
        if current >> 40 == u64::from(id) {
            break;
        }
        if current == 0
            && slot
                .compare_exchange(0, word, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            MEMCG_OOM_REQUESTS.fetch_add(1, Ordering::Relaxed);
            break;
        }
    }
    crate::oom::wake_reaper();
}

/// Run every queued memory-cgroup OOM. Called by the OOM reaper, which holds
/// no allocator or address-space lock; the hook may allocate. Returns the
/// number of requests processed.
pub(crate) fn run_memcg_oom() -> usize {
    let ptr = MEMCG_OOM_HOOK.load(Ordering::Acquire);
    let mut processed = 0;
    for slot in &MEMCG_OOM_PENDING {
        let word = slot.swap(0, Ordering::AcqRel);
        if word == 0 {
            continue;
        }
        processed += 1;
        if ptr == 0 {
            continue;
        }
        // SAFETY: stored only by `install_page_charge_hooks` from a
        // `fn(MemcgId, u64) -> bool`.
        let f: fn(MemcgId, u64) -> bool = unsafe { core::mem::transmute(ptr) };
        let _ = f((word >> 40) as MemcgId, word & ((1 << 40) - 1));
    }
    processed
}

/// Run queued memory-cgroup OOMs now. Kernel tests have no OOM reaper task;
/// production runs them from the reaper.
#[doc(hidden)]
pub fn __run_memcg_oom_for_test() -> usize {
    run_memcg_oom()
}

/// Memory-cgroup OOM requests queued since boot (diagnostic).
pub fn memcg_oom_requests() -> u64 {
    MEMCG_OOM_REQUESTS.load(Ordering::Relaxed)
}
