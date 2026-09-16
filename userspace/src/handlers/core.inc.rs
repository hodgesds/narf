// ── Signal wakers ───────────────────────────────────────────────────

const SIGNAL_WAKE_SHARDS: usize = 64;

#[repr(align(64))]
struct SignalWakerBucket {
    values: narf_lib::sync::IrqSafeSpinLock<
        Option<alloc::collections::BTreeMap<u64, core::task::Waker>>,
    >,
}

impl SignalWakerBucket {
    const fn new() -> Self {
        Self {
            values: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
}

static SIGNAL_WAKERS: [SignalWakerBucket; SIGNAL_WAKE_SHARDS] =
    [const { SignalWakerBucket::new() }; SIGNAL_WAKE_SHARDS];

#[inline]
fn signal_waker_shard(task_id: u64) -> usize {
    task_id as usize & (SIGNAL_WAKE_SHARDS - 1)
}

#[doc(hidden)]
pub fn __test_signal_waker_bucket_index(task_id: u64) -> usize {
    signal_waker_shard(task_id)
}

pub fn signal_waker_init() {
    for bucket in &SIGNAL_WAKERS {
        *bucket.values.lock() = Some(alloc::collections::BTreeMap::new());
    }
}

pub fn register_signal_waker(task_id: u64, waker: core::task::Waker) {
    let mut g = SIGNAL_WAKERS[signal_waker_shard(task_id)].values.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task_id, waker);
    }
}

pub fn wake_signal(task_id: u64) {
    // Deref the ctx UNDER the registry lock (see `with_user_task_ctx`) so a
    // concurrent task-exit + box-drop on another CPU can't free it mid-deref.
    crate::user_task::with_user_task_ctx(task_id, |uctx| {
        // Clear the park deadline so the woken task re-executes its syscall (and
        // re-checks the signal) NOW instead of sleeping to the ~1-tick wheel
        // backstop. Two cases, mirroring the io-waiter wake `wake_one`:
        //   * an infinite wait (pause / sigwaitinfo(NULL) / epoll_wait) — always;
        //   * a task parked in sigwait with a FINITE timeout (rt_sigtimedwait,
        //     sigwait_set != 0) — a just-queued in-set signal must complete the
        //     wait immediately (Linux signal_wake_up), not at the timeout.
        // A finite deadline on a NON-sigwait sleeper (nanosleep) is left intact:
        // a blocked/ignored signal must not cut a timed sleep short (Linux only
        // interrupts on a *deliverable* signal, handled on the re-executed
        // syscall's return, not here).
        let deadline = uctx.sleep_deadline_ns.load(Ordering::Acquire);
        if deadline == u64::MAX || uctx.sigwait_set.load(Ordering::Acquire) != 0 {
            uctx.sleep_deadline_ns.store(0, Ordering::Release);
        }
    });
    let waker = {
        let mut g = SIGNAL_WAKERS[signal_waker_shard(task_id)].values.lock();
        g.as_mut().and_then(|m| m.remove(&task_id))
    };
    if let Some(w) = waker {
        w.wake();
    }
}

pub fn drop_signal_waker(task_id: u64) {
    let mut g = SIGNAL_WAKERS[signal_waker_shard(task_id)].values.lock();
    if let Some(m) = g.as_mut() {
        m.remove(&task_id);
    }
}

/// Diagnostic (stall-watchdog): does `task_id` currently have a registered
/// signal waker? A task parked with a pending, deliverable signal but NO
/// signal waker cannot be roused by `wake_signal` — it strands until an
/// unrelated wake (backstop IPI, timer) happens to re-poll it. Distinguishing
/// that from an ordinary interruptible park is the whole question for the
/// SMP signal-wake lost-wakeup.
pub fn dbg_has_signal_waker(task_id: u64) -> bool {
    let g = SIGNAL_WAKERS[signal_waker_shard(task_id)].values.lock();
    g.as_ref().is_some_and(|m| m.contains_key(&task_id))
}

// ── Net I/O readiness wakers (epoll/poll) ───────────────────────────
//
// Tasks parked in `epoll_wait`/`poll` register their waker here while
// blocked. When inbound TCP data lands, the net stack calls
// `crate::readiness::notify` → `wake_io_waiters` (installed at boot),
// which clears each waiter's sleep deadline and fires its waker so it
// re-polls readiness immediately. Without this, a parked epoll task
// only re-checks at its next wheel deadline — redis's ~100 ms
// serverCron tick — turning a sub-ms round-trip into ~80 ms.

/// Number of wake-path shards (power of two). `IO_WAKERS` is touched on the
/// RX forwarder per inbound segment (targeted wake of the owning task) AND
/// by every worker that parks/unparks in epoll — a single global lock there
/// serialized the forwarder against all workers. `TCB_OWNER` likewise. Both
/// are keyed by id (task id / tcb id), so sharding decouples the forwarder's
/// per-segment touch (the owner's shard) from unrelated workers' park shards.
const WAKE_SHARDS: usize = 32;

#[inline]
fn io_waker_shard(task_id: u64) -> usize {
    (task_id as usize) & (WAKE_SHARDS - 1)
}

#[inline]
fn tcb_owner_shard(tcb_id: u32) -> usize {
    (tcb_id as usize) & (WAKE_SHARDS - 1)
}

/// Per-shard io-waker state: the parked wakers keyed by task id, plus a
/// pending-wake LATCH. A targeted wake (`wake_io_owner`) for a task with no
/// registered waiter — one still between its readiness check and
/// `register_io_waiter`, or simply not parked — records the task id in `pending`
/// instead of dropping the wake. The next `register_io_waiter` consumes the
/// latch and re-executes instead of parking, closing the scan→register lost-wake
/// race precisely (no periodic backstop, no global-generation spurious re-exec).
/// `wake_all_io_waiters` (the untargeted broadcast fallback) does NOT latch — it
/// has no single target; that rarer race stays covered by the bounded io-wait
/// backstop in `park_fire_deadline_ns`.
struct WakerShard {
    wakers: alloc::collections::BTreeMap<u64, core::task::Waker>,
    pending: alloc::collections::BTreeSet<u64>,
}

static IO_WAKERS: [narf_lib::sync::IrqSafeSpinLock<Option<WakerShard>>; WAKE_SHARDS] =
    [const { narf_lib::sync::IrqSafeSpinLock::new(None) }; WAKE_SHARDS];

pub fn io_waker_init() {
    for shard in IO_WAKERS.iter() {
        *shard.lock() = Some(WakerShard {
            wakers: alloc::collections::BTreeMap::new(),
            pending: alloc::collections::BTreeSet::new(),
        });
    }
}

// ── Targeted-wake ownership: TCB id → owning task ───────────────────
//
// Each kernel TCP socket (a listener, set at `listen`; a connection, set
// at `accept`) is owned by the task that created it — which, for the
// servers we run (SO_REUSEPORT workers, redis, netserve), is also the
// task that `epoll_wait`s on it. The net stack notifies readiness keyed
// by TCB id, so `wake_io_waiters` can wake ONLY that owner instead of
// every parked waiter — killing the thundering herd (and, under SMP, the
// cross-core IPI storm of waking workers on other cores). An untracked
// key falls back to wake-all; the lost-wakeup gen guard
// (`epoll_park_gen`) covers the check→park race, so targeting can't
// strand a parked task.
#[allow(clippy::type_complexity)]
static TCB_OWNER: [narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u32, u64>>,
>; WAKE_SHARDS] = [const { narf_lib::sync::IrqSafeSpinLock::new(None) }; WAKE_SHARDS];

/// Record that `task_id` owns the socket backed by kernel `tcb_id`.
pub fn set_tcb_owner(tcb_id: u32, task_id: u64) {
    let mut g = TCB_OWNER[tcb_owner_shard(tcb_id)].lock();
    g.get_or_insert_with(alloc::collections::BTreeMap::new)
        .insert(tcb_id, task_id);
}

/// Drop the ownership record for `tcb_id` (socket closed / TCB gone).
pub fn clear_tcb_owner(tcb_id: u32) {
    {
        let mut g = TCB_OWNER[tcb_owner_shard(tcb_id)].lock();
        if let Some(m) = g.as_mut() {
            m.remove(&tcb_id);
        }
    }
    // Tear down the durable readiness cell too. Latch POLL_IN|POLL_HUP first so
    // any waiter still armed on it wakes (a closed socket is readable → EOF).
    let mut g = TCB_CELL[tcb_owner_shard(tcb_id)].lock();
    if let Some(m) = g.as_mut() {
        if let Some(cell) = m.remove(&tcb_id) {
            cell.set(
                narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
                0,
            );
            // Linux wait-queue: fire the close/EOF edge unconditionally.
            cell.notify(narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP);
        }
    }
}

fn tcb_owner(tcb_id: u32) -> Option<u64> {
    let g = TCB_OWNER[tcb_owner_shard(tcb_id)].lock();
    g.as_ref().and_then(|m| m.get(&tcb_id).copied())
}

/// tcb_id → durable readiness cell for `InetWired` (kernel-TCP-over-NIC)
/// sockets. Parallels [`TCB_OWNER`]: the TCP RX / close wake path sets edges
/// here so an epoll/poll waiter armed on the cell wakes event-driven (Linux
/// wait-queue + `ep_poll_callback`) instead of forcing an O(N) interest rescan.
/// Populated lazily by [`tcb_cell`] the first time a socket arms/polls; dropped
/// by [`clear_tcb_owner`].
#[allow(clippy::type_complexity)]
static TCB_CELL: [narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u32, alloc::sync::Arc<narf_lib::readiness::Readiness>>>,
>; WAKE_SHARDS] = [const { narf_lib::sync::IrqSafeSpinLock::new(None) }; WAKE_SHARDS];

/// Get-or-create the durable readiness cell for `tcb_id`. A fresh cell starts
/// `POLL_OUT` (a kernel-TCP socket is always sendable — the stack queues and
/// flow-controls the send side), matching `poll_readiness`'s `InetWired` level.
pub fn tcb_cell(tcb_id: u32) -> alloc::sync::Arc<narf_lib::readiness::Readiness> {
    let mut g = TCB_CELL[tcb_owner_shard(tcb_id)].lock();
    g.get_or_insert_with(alloc::collections::BTreeMap::new)
        .entry(tcb_id)
        .or_insert_with(|| {
            alloc::sync::Arc::new(narf_lib::readiness::Readiness::new(
                narf_filesystem::POLL_OUT,
            ))
        })
        .clone()
}

/// Look up an existing cell without creating one (the wake / poll hot path).
pub fn tcb_cell_lookup(tcb_id: u32) -> Option<alloc::sync::Arc<narf_lib::readiness::Readiness>> {
    let g = TCB_CELL[tcb_owner_shard(tcb_id)].lock();
    g.as_ref().and_then(|m| m.get(&tcb_id).cloned())
}

/// Remove `task_id`'s waiter from `tcb_id`'s cell, if the cell exists. No-op
/// otherwise. Called by the socket's `disarm_readiness` for `InetWired`.
pub fn tcb_cell_disarm(tcb_id: u32, task_id: u64) {
    if let Some(cell) = tcb_cell_lookup(tcb_id) {
        cell.disarm(task_id);
    }
}

/// Register `task_id`'s waker as parked on net I/O readiness, and report whether
/// a targeted wake was already latched for it: `true` means a `wake_io_owner`
/// landed in the scan→register window, so the caller must NOT park — re-execute
/// the syscall instead (it re-scans and finds the readiness). Called from the
/// user-task poll routine while a task blocks in epoll/poll.
pub fn register_io_waiter(task_id: u64, waker: core::task::Waker) -> bool {
    let mut g = IO_WAKERS[io_waker_shard(task_id)].lock();
    if let Some(s) = g.as_mut() {
        if s.pending.remove(&task_id) {
            // A targeted wake raced us and was latched — consume it, do not park.
            return true;
        }
        s.wakers.insert(task_id, waker);
    }
    false
}

/// Remove `task_id`'s I/O waker without firing it (the task woke for
/// another reason / is returning from the syscall). Also clears any latched
/// pending wake so a stale latch can't spuriously skip the task's next park.
pub fn drop_io_waiter(task_id: u64) {
    let mut g = IO_WAKERS[io_waker_shard(task_id)].lock();
    if let Some(s) = g.as_mut() {
        s.wakers.remove(&task_id);
        s.pending.remove(&task_id);
    }
}

/// Wake every task parked on net I/O readiness. Installed as the
/// `narf_net::readiness` hook at boot; invoked from the TCP receive
/// path when a socket becomes readable. Clears each task's finite
/// sleep deadline so its re-poll falls through to re-check readiness
/// instead of re-parking on the stale deadline.
/// Clear a task's finite sleep deadline (so its re-poll re-checks
/// readiness) and fire its waker.
fn wake_one_inner(task_id: u64, w: core::task::Waker, urgent_handoff: bool) {
    // Deref under the registry lock (see `with_user_task_ctx`) so a concurrent
    // task-exit + box-drop can't free the ctx mid-deref.
    crate::user_task::with_user_task_ctx(task_id, |uctx| {
        uctx.sleep_deadline_ns.store(0, Ordering::Release);
    });
    w.wake();
    // Wake-preemption (Linux `wakeup_preempt`): this readiness/futex/IPC wake
    // just made `task_id` runnable, so ask the running task to cede at its next
    // syscall exit and let the wakee run promptly instead of after a fair
    // quantum. Gated by the `wake_preempt` feature and self-wake-filtered inside;
    // a no-op (one gated atomic load) when the feature is off.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if urgent_handoff {
        narf_scheduler::stackful::note_urgent_wake_preempt(task_id);
    } else {
        narf_scheduler::stackful::note_wake_preempt(task_id);
    }
}

pub(crate) fn wake_one(task_id: u64, w: core::task::Waker) {
    wake_one_inner(task_id, w, false);
}

/// Wake a task as the direct consumer of the current syscall's successful
/// synchronous handoff. The scheduler may bypass its ordinary batching window
/// when local work is runnable; a remote wakee does not force an empty yield.
pub(crate) fn wake_one_urgent(task_id: u64, w: core::task::Waker) {
    wake_one_inner(task_id, w, true);
}

/// The net readiness hook. `key` is the kernel TCB id of the socket that
/// became ready (a connection's id for data, the listener's id for an
/// accept), or 0 for "unknown". When the key has a known owner task that
/// is currently parked, wake ONLY it (no thundering herd / cross-core
/// wake storm). If the owner is known but not parked it needs no wake —
/// it will re-scan readiness on its next `epoll_wait` (the gen guard
/// covers the race). Untracked keys fall back to waking everyone.
pub fn wake_io_waiters(key: u64) {
    if key != 0 {
        // Event-driven edge: mark this socket's durable cell readable so a
        // waiter armed on the cell (epoll's per-fd ready-list linkage) wakes
        // carrying the fd, rather than rescanning the whole interest set. The
        // cell's own `set` fires its armed wakers; the owner wake below remains
        // for the legacy (non-cell-armed) path and is harmless otherwise.
        if let Some(cell) = tcb_cell_lookup(key as u32) {
            cell.set(narf_filesystem::POLL_IN, 0);
            // Linux wait-queue: fire on every RX event, even more data at the
            // same readable level (the token used to cover this edge).
            cell.notify(narf_filesystem::POLL_IN);
        }
        if let Some(owner) = tcb_owner(key as u32) {
            // Owner known: targeted wake iff it's parked.
            wake_io_owner(owner);
            return;
        }
        // Untracked key → fall through to wake-all (safety net).
    }
    wake_all_io_waiters();
}

/// Wake ONLY `owner`'s parked I/O waker, if it is parked. The targeted-wake
/// primitive: used by the TCB-keyed net path AND directly by AF_UNIX sends,
/// which are point-to-point and know their peer's reader (the `RingBuf` owner),
/// so they must wake that one task — never the whole parked-poller herd. The
/// waker lives in the owner's shard (keyed by task id). A wrong/absent owner is
/// safe: the readiness generation guard makes the real reader re-poll.
pub(crate) fn wake_io_owner(owner: u64) {
    let waker = {
        let mut g = IO_WAKERS[io_waker_shard(owner)].lock();
        if let Some(s) = g.as_mut() {
            match s.wakers.remove(&owner) {
                w @ Some(_) => w,
                None => {
                    // Owner not parked yet (still between its readiness check and
                    // `register_io_waiter`, or simply running): LATCH the wake so
                    // its next register consumes it instead of dropping it — this
                    // is what closes the scan→register lost-wake race. Idempotent
                    // (a set); a stale latch on a running owner costs at most one
                    // spurious re-exec (re-scan → nothing → re-park).
                    s.pending.insert(owner);
                    None
                }
            }
        } else {
            None
        }
    };
    if let Some(w) = waker {
        // Narrow directed wake (boot flag `io_next`, default off): name this
        // just-woken I/O owner its CPU's next-buddy so the executor dispatches
        // it ahead of the maintenance tasks queued in front of it, cutting the
        // non-halted round-robin ordering tail. Scoped to the targeted I/O wake
        // — never the generic every-wake path that thrashes the executor.
        narf_scheduler::hint_io_next(owner);
        wake_one(owner, w);
    }
}

/// Evdev dispatch wake bridge: bump the readiness generation + wake all
/// io-waiters so a `read`/`poll`/`epoll` parked on /dev/input/event*
/// resumes when an input driver dispatches an event. Installed into
/// `narf_input::evdev` at boot. `notify(0)` = wake-all (input events
/// aren't keyed by a TCB id).
fn evdev_dispatch_wake() {
    narf_net::readiness::notify(0);
}

/// Wake every task parked on net I/O readiness (the conservative
/// fallback for untracked keys — loopback / unix / not-yet-owned).
fn wake_all_io_waiters() {
    // Snapshot + clear EVERY shard under its own lock, then wake outside the
    // locks (wake() may re-enter scheduling / drop an Arc).
    let mut wakers: alloc::vec::Vec<(u64, core::task::Waker)> = alloc::vec::Vec::new();
    for shard in IO_WAKERS.iter() {
        let mut g = shard.lock();
        if let Some(s) = g.as_mut() {
            wakers.extend(core::mem::take(&mut s.wakers));
        }
    }
    for (task_id, w) in wakers {
        wake_one(task_id, w);
    }
}

// ── Current-task lookup shim ───────────────────────────────────────
//
// Same shape as `AS_LOOKUP` — wired in by the kernel boot to
// resolve "what task is running this syscall" without a direct
// `narf_userspace → narf_scheduler` dep cycle.

type TaskIdLookupFn = fn() -> u64;

// Installed during boot and only replaced by sequential kernel tests. An
// atomic callback slot keeps the syscall hot path to one acquire load; the old
// global IRQ-safe lock bounced one cache line between every CPU and masked
// local interrupts around every current-task lookup.
static TASK_LOOKUP: AtomicUsize = AtomicUsize::new(0);

/// Install the function that returns the current task's raw id.
/// Boot wires `|| scheduler::current_task_id().raw()` here.
pub fn install_task_id_lookup(lookup: TaskIdLookupFn) {
    TASK_LOOKUP.store(lookup as usize, Ordering::Release);
}

/// Test hook: drop any installed current-task lookup so
/// `current_task_id()` falls back to 0. The in-kernel smoke tests
/// share one boot, and `TASK_LOOKUP` is a process-global — without a
/// reset, a test that installs a fixed-id lookup leaks it into later
/// tests that assume the default (e.g. signalfd / per-tty pgrp tests).
pub fn __test_reset_task_id_lookup() {
    TASK_LOOKUP.store(0, Ordering::Release);
}

#[inline]
pub fn current_task_id() -> u64 {
    let raw = TASK_LOOKUP.load(Ordering::Acquire);
    if raw == 0 {
        return 0;
    }
    // SAFETY: the only non-zero values stored in TASK_LOOKUP are complete
    // TaskIdLookupFn pointers. Acquire pairs with the installing release.
    let lookup: TaskIdLookupFn = unsafe { core::mem::transmute(raw) };
    lookup()
}

// ── Sync poll-once helper ──────────────────────────────────────────
//
// Stage-4 syscall handlers run in trap context — they can't `.await`.
// Every Stage-3 in-memory FS (initramfs) returns `Ready` on the
// first poll, so we use a no-op waker + a single `poll`. Disk-backed
// FSes that yield will need a different shape; this is the
// quick-path Stage-4 needs to hook real reads from initramfs.

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    // SAFETY: vtable holds null-pointer-clean stubs; the waker is
    // never woken (poll_once expects Ready on the first poll).
    // SAFETY: Valid memory or trusted environment
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut ctx = Context::from_waker(&waker);
    // SAFETY: we own `fut` by value; pinning to a stack temporary
    // is the standard "block_on of a !Unpin future".
    // SAFETY: Valid memory or trusted environment
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut ctx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

fn raw_waker() -> RawWaker {
    unsafe fn no_clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    unsafe fn no_op(_: *const ()) {}
    const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
    RawWaker::new(core::ptr::null(), &VTAB)
}

/// Sleep the current stackful syscall task after its future reports `Pending`.
///
/// The future was polled with this task's executor waker, so its completion
/// source is responsible for making the task runnable again. The executor's
/// durable `awake` bit closes the classic register-waker -> sleep race: a wake
/// between `poll()` and `yield_current_stackful()` remains set and causes an
/// immediate re-poll. This is the same waitqueue shape Linux uses for
/// synchronous filesystem I/O, rather than a busy-poll or repeated self-yield.
///
/// Returns `false` only outside a stackful user task (principally kernel-test
/// contexts and architectures which have not enabled own-stack user tasks).
#[inline]
fn park_pending_future() -> bool {
    sleep_pumps::run();
    let Some(uctx) = crate::user_task::current_user_task() else {
        return false;
    };
    if narf_scheduler::stackful::current_stackful_waker().is_none() {
        return false;
    }

    // SAFETY: this is the in-flight task's poller-pinned UserTaskCtx. The
    // continuation stays on this task's private kernel stack while asleep.
    let uc = unsafe { &*uctx };
    crate::handlers::close_kernel_span(uc, current_task_id());
    uc.parked_in_syscall
        .store(true, core::sync::atomic::Ordering::Release);
    // SAFETY: a current stackful task and its executor context were verified
    // above; the future's waker is the only path which makes it runnable.
    unsafe { narf_scheduler::stackful::yield_current_stackful() };

    // A stackful resume continues here without re-entering UserTaskFuture::poll,
    // so restore the publication another task may have replaced while we slept.
    crate::user_task::install_current(uctx);
    crate::handlers::open_kernel_span(uc);
    true
}

/// Drive a filesystem Future to completion inside a synchronous syscall.
/// `Pending` parks a stackful user task until the future's registered waker
/// fires. Outside that execution model, retain a bounded spin-pump solely for
/// kernel tests and early fallback contexts.
pub(crate) fn poll_blocking<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    let task_waker = narf_scheduler::stackful::current_stackful_waker();
    // SAFETY: fallback only; the no-op raw waker obeys the RawWaker lifetime
    // contract and never escapes this function.
    let fallback_waker = unsafe { Waker::from_raw(raw_waker()) };
    let waker = task_waker.as_ref().unwrap_or(&fallback_waker);
    let mut ctx = Context::from_waker(waker);
    // SAFETY: we own `fut` by value; pin to the stack temporary.
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
    let mut fallback_polls = 0u64;
    loop {
        match pinned.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return Some(v),
            Poll::Pending if task_waker.is_some() => {
                if !park_pending_future() {
                    return None;
                }
            }
            Poll::Pending => {
                sleep_pumps::run();
                core::hint::spin_loop();
                fallback_polls += 1;
                if fallback_polls == 4_000_000 {
                    return None;
                }
            }
        }
    }
}

/// Drive block-backed filesystem I/O to completion while keeping the same
/// future (and therefore its DMA ownership) alive for the whole sleep. The
/// runtime path has no polling ceiling: completion or cancellation must wake
/// it. Only the non-stackful test fallback retains a finite wedge detector.
pub(crate) fn poll_io_to_completion<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    let task_waker = narf_scheduler::stackful::current_stackful_waker();
    // SAFETY: fallback only; see poll_blocking.
    let fallback_waker = unsafe { Waker::from_raw(raw_waker()) };
    let waker = task_waker.as_ref().unwrap_or(&fallback_waker);
    let mut ctx = Context::from_waker(waker);
    // SAFETY: we own `fut` by value; pin to the stack temporary.
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
    let mut fallback_polls = 0u64;
    loop {
        match pinned.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return Some(v),
            Poll::Pending if task_waker.is_some() => {
                if !park_pending_future() {
                    return None;
                }
            }
            Poll::Pending => {
                sleep_pumps::run();
                core::hint::spin_loop();
                fallback_polls += 1;
                if fallback_polls == 2_000_000_000 {
                    return None;
                }
            }
        }
    }
}

// ── Per-task AS lookup shim ────────────────────────────────────────
//
// Handlers need the current task's AddressSpace. `scheduler` is
// a peer crate (we can't depend on it directly — creates a cycle
// via narf-userspace → narf-scheduler → userspace for the AS).
// The kernel wires a lookup function at boot via
// `install_address_space_lookup`.

type AsLookupFn = fn() -> Option<Arc<AddressSpace>>;
type AllAsLookupFn = fn() -> alloc::vec::Vec<Arc<AddressSpace>>;

// Like TASK_LOOKUP, this callback is immutable after boot outside sequential
// tests. Keep address-space-heavy syscalls and private futex operations off a
// global IRQ-disabling callback lock.
static AS_LOOKUP: AtomicUsize = AtomicUsize::new(0);
static ALL_AS_LOOKUP: narf_lib::sync::IrqSafeSpinLock<Option<AllAsLookupFn>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Install the function that resolves "what's the currently-
/// polling task's address space?". The kernel boot code registers
/// `|| scheduler::address_space_of(scheduler::current_task_id())`
/// here; handlers below call through. Absent registration,
/// `current_address_space()` returns `None` and AS-dependent
/// handlers return `InvalidOp`.
pub fn install_address_space_lookup(lookup: AsLookupFn) {
    AS_LOOKUP.store(lookup as usize, Ordering::Release);
}

/// Install the scheduler bridge used by shared-page migration to snapshot all
/// live aliases without introducing a userspace↔scheduler crate cycle.
pub fn install_all_address_spaces_lookup(lookup: AllAsLookupFn) {
    *ALL_AS_LOOKUP.lock() = Some(lookup);
}

fn all_address_spaces() -> alloc::vec::Vec<Arc<AddressSpace>> {
    (*ALL_AS_LOOKUP.lock())
        .map(|lookup| lookup())
        .unwrap_or_default()
}

/// Snapshot the currently-installed AS lookup (for save/restore around a
/// test that temporarily swaps in its own). `None` if none is installed.
pub fn address_space_lookup() -> Option<AsLookupFn> {
    let raw = AS_LOOKUP.load(Ordering::Acquire);
    if raw == 0 {
        None
    } else {
        // SAFETY: every non-zero AS_LOOKUP value was stored from AsLookupFn.
        Some(unsafe { core::mem::transmute::<usize, AsLookupFn>(raw) })
    }
}

/// Restore (or clear) the AS lookup — the counterpart to
/// `install_address_space_lookup` that also accepts `None`.
pub fn restore_address_space_lookup(lookup: Option<AsLookupFn>) {
    AS_LOOKUP.store(lookup.map(|f| f as usize).unwrap_or(0), Ordering::Release);
}

fn current_address_space() -> Option<Arc<AddressSpace>> {
    address_space_lookup().and_then(|lookup| lookup())
}

/// Public re-export of the per-task AS lookup. Used by external
/// subsystems (currently `narf_compat_win`) that need to bound-check
/// user pointers handed to thunks before dereferencing them.
pub fn active_user_as() -> Option<Arc<AddressSpace>> {
    current_address_space()
}

/// Snapshot of the registered kernel-side `(rip, rsp)` exit landing
/// — the same pair `set_exit_landing` writes and `sys_exit_task`
/// reads. Returns `None` when no landing has been registered.
///
/// Win32 `ExitProcess` (now a userspace `compat-win-rt` thunk) calls
/// the native `Syscall::ExitTask` directly — there is no Win32-
/// specific exit path needing to consult this; the helper is left
/// as a public read-only accessor for any future kernel-side
/// component that wants to know the registered landing.
pub fn exit_landing() -> Option<(u64, u64)> {
    let rip = EXIT_LANDING_RIP.load(Ordering::Acquire);
    let rsp = EXIT_LANDING_RSP.load(Ordering::Acquire);
    if rip == 0 { None } else { Some((rip, rsp)) }
}

// ── Exit-landing registration ──────────────────────────────────────

static EXIT_LANDING_RIP: AtomicU64 = AtomicU64::new(0);
static EXIT_LANDING_RSP: AtomicU64 = AtomicU64::new(0);

/// The kernel registers a (rip, rsp) pair via `set_exit_landing`
/// that the `ExitTask` handler redirects the trap frame to. After
/// the trap `iretq` lands at `rip` with `rsp` as the live stack,
/// the kernel can clean up, unmap the user AS, and move on.
pub fn set_exit_landing(rip: u64, rsp: u64) {
    EXIT_LANDING_RIP.store(rip, Ordering::Release);
    EXIT_LANDING_RSP.store(rsp, Ordering::Release);
}

/// Clear the exit landing.
pub fn clear_exit_landing() {
    EXIT_LANDING_RIP.store(0, Ordering::Release);
    EXIT_LANDING_RSP.store(0, Ordering::Release);
}

// ── Bootstrap — slow-path entry mint per-task config page ──────────
//
// Spec: `abi/specification/spec.md` §3.1. The full Stage-4
// bootstrap mints SubmissionQueue + CompletionQueue ring caps + a
// read-only config page cap. The minimum useful first cut is the
// config-page side: allocate a 4 KiB page in the caller's AS, map
// it R+U, write a header with task-id + ABI version + per-task
// fixed magic so the user library can verify the kernel handed it
// the page. Returns the user virt address.
//
// Future revision will return SQ + CQ caps too via the inline
// result words; today we just return the page pointer. The shape
// is `arg0..=arg5` ignored on entry; on success `value` =
// config-page user vaddr.

const ABI_BOOTSTRAP_MAGIC: u32 = 0x4E_41_52_46; // "NARF" LE
const ABI_BOOTSTRAP_VERSION: u32 = 3;
/// Ring depth for the kernel-only Arc<Ring> pair. Powers-of-two only.
const BOOTSTRAP_RING_DEPTH: u64 = 64;
/// Ring depth for the user-mappable SharedRing pair. Powers-of-two
/// only. Each SharedRing must fit in a single 4 KiB page; 16 entries
/// keeps `SharedRing<Submission, 16>` (2368 bytes) and
/// `SharedRing<Completion, 16>` (1088 bytes) well within budget.
pub const BOOTSTRAP_SHARED_RING_DEPTH: usize = 16;

#[repr(C)]
struct BootstrapHeader {
    magic: u32,
    version: u32,
    task_id: u64,
    /// Capslot ids the user runtime invokes against. They name
    /// the SQ producer / CQ consumer the kernel-side dispatcher
    /// is bound to.
    sq_cap: u64,
    cq_cap: u64,
    /// Ring depths the kernel chose for this task.
    sq_depth: u32,
    cq_depth: u32,
    /// User vaddr of the shared SubmissionRing page. The user
    /// builds a `SharedProducer<Submission, 16>` against this.
    shared_sq_vaddr: u64,
    /// User vaddr of the shared CompletionRing page. The user
    /// builds a `SharedConsumer<Completion, 16>` against this.
    shared_cq_vaddr: u64,
    /// Depth for the SharedRing pair (must equal
    /// `BOOTSTRAP_SHARED_RING_DEPTH`; carried in the header so the
    /// user runtime can verify rather than hard-code).
    shared_depth: u32,
    _pad: u32,
}

// ── Per-task SQ/CQ store ──────────────────────────────────────────
//
// Bootstrap stores the kernel-side ring halves so the dispatcher
// task (when wired) can pull from the SQ drain + push to the CQ
// producer. Storage is the kernel-side ends only — the user-side
// halves are pointed at by capslot ids written into the config
// page.

use alloc::collections::BTreeMap;
use narf_abi::{
    Completion, CompletionDrain, CompletionQueue, SharedRing, Submission, SubmissionDrain,
    SubmissionQueue, completion_channel, submission_channel,
};
use narf_memory::PhysAddr;

/// Kernel-side keep of the ring pair Bootstrap minted for a task.
/// Stored under the task id; SMP-safe via the outer lock.
pub struct TaskRings {
    pub sq_drain: SubmissionDrain<64>,
    pub cq_prod: CompletionQueue<64>,
}

impl core::fmt::Debug for TaskRings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TaskRings").finish_non_exhaustive()
    }
}

/// User-side handles paired with the kernel-side ones above. Stored
/// here too so the kernel can still talk to user-side endpoints
/// before the user picks them up via cap (the cap slot id is just
/// a stable opaque key Stage-4 callers exchange).
pub struct UserRingEnds {
    pub sq_prod: SubmissionQueue<64>,
    pub cq_drain: CompletionDrain<64>,
}

impl core::fmt::Debug for UserRingEnds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserRingEnds").finish_non_exhaustive()
    }
}

/// Kernel-side handles to the user-mappable shared rings. The
/// physical bases identify the backing pages; the kernel reaches
/// them through the low-4-GiB identity map. `SharedProducer` /
/// `SharedConsumer` are constructed on demand in `sys_ring_kick`.
#[derive(Copy, Clone, Debug)]
pub struct SharedRingPair {
    /// Phys base of the SubmissionRing page (kernel reads).
    pub sq_phys: PhysAddr,
    /// Phys base of the CompletionRing page (kernel writes).
    pub cq_phys: PhysAddr,
    /// User vaddrs of the same pages (where the user binds its
    /// own SharedProducer / SharedConsumer halves).
    pub sq_user_vaddr: u64,
    pub cq_user_vaddr: u64,
}

#[derive(Debug)]
#[allow(dead_code)] // fields read by the future dispatcher integration
struct PerTaskBootstrap {
    kernel: TaskRings,
    user: UserRingEnds,
    shared: Option<SharedRingPair>,
    sq_cap_id: u64,
    cq_cap_id: u64,
}

static BOOTSTRAP_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, PerTaskBootstrap>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task bootstrap registry. Boot calls this
/// once before any user task can issue `Syscall::Bootstrap`.
pub fn bootstrap_init() {
    *BOOTSTRAP_TABLE.lock() = Some(BTreeMap::new());
}

/// Initialise every per-task state table the new syscalls depend
/// on — convenient single-call wiring for boot paths and test
/// fixtures so they don't have to enumerate every init helper.
/// Idempotent: each underlying init is a `*lock = Some(BTreeMap::new())`
/// or similar, safe to re-run.
///
/// This wires:
///   - bootstrap (per-task SQ/CQ rings)
///   - cwd
///   - brk
///   - sigaction + signal
///   - uid/gid + hostname + rlimit + nice + umask + prctl
///
/// The fd table store needs no counterpart here — its shards are
/// const-initialised and materialise a task's table on first touch
/// (see `crate::fd::with_table`).
/// The `end` argument `fs/file.c::alloc_fd` measures descriptor allocation
/// against: a task's RLIMIT_NOFILE soft limit, or the boot default before the
/// task has rlimits of its own.
fn task_nofile_limit(task: u64) -> u64 {
    read_rlimit(task, RLIMIT_NOFILE_RESOURCE)
        .map(|limit| limit.cur)
        .unwrap_or_else(|| default_rlimits()[RLIMIT_NOFILE_RESOURCE].cur)
}

pub fn init_per_task_state() {
    bootstrap_init();
    // Publish the descriptor-allocation bound to the fd table. Until this is
    // installed every table is unbounded, which is what the boot path needs
    // while it seeds stdio into tables whose tasks do not exist yet.
    crate::fd::install_nofile_limit_lookup(task_nofile_limit);
    cwd_init();
    sigaction_init();
    signal_init();
    uidgid_init();
    hostname_init();
    rlimit_init();
    nice_init();
    umask_init();
    prctl_init();
    sched_param_init();
    // W^X JIT grants. `memory/src/wx.rs` has described this capability since
    // it was written; `CapKind::Jit` and `wx::jit_mprotect` are what finally
    // implement it. Swept per-task by `release_task_tables`.
    narf_memory::wx::jit_grants_init();
    pgid_init();
    sid_init();
    caps_init();
    ioprio_init();
    wait_init();
    pkey_init();
    narf_filesystem::fuse_conn::install_request_context_provider(fuse_request_context);
    {
        ctty_init();
        // Wave-76: route PtySlave::ioctl(TIOCSCTTY) into our per-task
        // CTTY table. Hook is global; filesystem crate calls back through
        // a fn pointer to avoid a userspace→filesystem dep cycle.
        narf_filesystem::devfs_pty::set_controlling_tty_hook(set_controlling_tty);
        // Route /dev/console TIOCSCTTY / TIOCNOTTY / TIOCGSID into the same
        // per-task CTTY + session tables so getty/login can claim the console
        // as their session's controlling terminal via /dev/console (or
        // /dev/tty1), not only via a PTY slave.
        narf_filesystem::console_tty::install_ctty_hooks(
            console_tiocsctty,
            console_tiocnotty,
            console_tiocgsid,
        );
    }
}

/// Reset the registry — test hook; drops every per-task ring set.
#[doc(hidden)]
pub fn __test_bootstrap_reset() {
    *BOOTSTRAP_TABLE.lock() = Some(BTreeMap::new());
}

/// Diagnostic: number of tasks that have called Bootstrap.
pub fn bootstrap_live_count() -> usize {
    BOOTSTRAP_TABLE
        .lock()
        .as_ref()
        .map(|m| m.len())
        .unwrap_or(0)
}

/// Pull this task's user-side ring ends out of the registry,
/// transferring ownership to the caller. Used by the test
/// harness (and a future relibc shim) to drive the rings from
/// the user side.
pub fn take_user_ends(task: u64) -> Option<UserRingEnds> {
    let mut g = BOOTSTRAP_TABLE.lock();
    let map = g.as_mut()?;
    let entry = map.remove(&task)?;
    // Re-insert just the kernel side so the dispatcher still has
    // it. Replace the user side with one we can never pop again
    // (a fresh ownerless pair so the table stays consistent).
    let placeholder_user = {
        let (_dead_sq, _drop_sq_drain) = submission_channel::<64>();
        let (_drop_cq_prod, _dead_cq) = completion_channel::<64>();
        UserRingEnds {
            sq_prod: _dead_sq,
            cq_drain: _dead_cq,
        }
    };
    map.insert(
        task,
        PerTaskBootstrap {
            kernel: entry.kernel,
            user: placeholder_user,
            shared: entry.shared,
            sq_cap_id: entry.sq_cap_id,
            cq_cap_id: entry.cq_cap_id,
        },
    );
    Some(entry.user)
}

/// Pull this task's kernel-side ring ends out for the dispatcher
/// task to drive. Returns `None` if Bootstrap hasn't run for
/// `task`. Once taken, only one dispatcher can serve the task —
/// re-taking returns the placeholder set the prior take left
/// behind.
pub fn take_kernel_ends(task: u64) -> Option<TaskRings> {
    let mut g = BOOTSTRAP_TABLE.lock();
    let map = g.as_mut()?;
    let entry = map.remove(&task)?;
    let placeholder_kernel = {
        let (_drop_sq_prod, dead_sq_drain) = submission_channel::<64>();
        let (dead_cq_prod, _drop_cq_drain) = completion_channel::<64>();
        TaskRings {
            sq_drain: dead_sq_drain,
            cq_prod: dead_cq_prod,
        }
    };
    map.insert(
        task,
        PerTaskBootstrap {
            kernel: placeholder_kernel,
            user: entry.user,
            shared: entry.shared,
            sq_cap_id: entry.sq_cap_id,
            cq_cap_id: entry.cq_cap_id,
        },
    );
    Some(entry.kernel)
}

/// Look up the shared ring pair Bootstrap minted for `task`.
/// Returns the kernel-side phys addresses + user vaddrs so the
/// dispatcher (or `sys_ring_kick`) can attach to the same backing
/// the user binds against. Idempotent.
pub fn shared_rings_for(task: u64) -> Option<SharedRingPair> {
    let g = BOOTSTRAP_TABLE.lock();
    g.as_ref()?.get(&task)?.shared
}

/// Monotonic capslot allocator for the SQ/CQ pair. Stage-4
/// structural — Stage-5 routes through the real `capabilities/`
/// table so revoke + transfer work.
static NEXT_CAP_ID: AtomicU64 = AtomicU64::new(0x4000_0000);

/// Allocate two phys pages, init a SharedRing in each, map both
/// into `as_ref` at successive vaddrs from the MMAP cursor, and
/// return the kernel-side phys + user vaddr handles.
unsafe fn mint_shared_ring_pair(
    as_ref: &alloc::sync::Arc<AddressSpace>,
) -> Result<SharedRingPair, ()> {
    type SqRing = SharedRing<Submission, BOOTSTRAP_SHARED_RING_DEPTH>;
    type CqRing = SharedRing<Completion, BOOTSTRAP_SHARED_RING_DEPTH>;
    const _: () = assert!(core::mem::size_of::<SqRing>() <= 4096);
    const _: () = assert!(core::mem::size_of::<CqRing>() <= 4096);

    let sq_phys = narf_memory::alloc_frame().map_err(|_| ())?.start_address();
    let cq_phys = narf_memory::alloc_frame().map_err(|_| ())?.start_address();
    // SAFETY: identity-mapped low 4 GiB + page-aligned phys.
    unsafe {
        core::ptr::write_bytes(sq_phys.kernel_mut_ptr::<u8>(), 0, 4096);
        core::ptr::write_bytes(cq_phys.kernel_mut_ptr::<u8>(), 0, 4096);
        SqRing::init_in(sq_phys.kernel_mut_ptr::<SqRing>());
        CqRing::init_in(cq_phys.kernel_mut_ptr::<CqRing>());
    }

    let sq_vaddr = MMAP_CURSOR.fetch_add(0x1000, Ordering::Relaxed);
    let cq_vaddr = MMAP_CURSOR.fetch_add(0x1000, Ordering::Relaxed);

    as_ref
        .map_region(Region {
            base: VirtAddr::new(sq_vaddr),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![sq_phys],
        })
        .map_err(|_| ())?;
    as_ref
        .map_region(Region {
            base: VirtAddr::new(cq_vaddr),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE | RegionPerms::LOCK_EXEMPT,
            phys: alloc::vec![cq_phys],
        })
        .map_err(|_| ())?;
    // SAFETY: `as_ref` has a valid root and the two SharedRing regions were just
    // registered above; materialize installs PTEs only for those regions.
    // SAFETY: Valid memory or trusted environment
    unsafe { as_ref.materialize() }.map_err(|_| ())?;

    Ok(SharedRingPair {
        sq_phys,
        cq_phys,
        sq_user_vaddr: sq_vaddr,
        cq_user_vaddr: cq_vaddr,
    })
}

// ── Open — arg0=path-ptr, arg1=path-len, arg2=mount-path-ptr,
//          arg3=mount-path-len ───────────────────────────────────────
//
// Stage-4 minimum: the user supplies (mount, path-under-mount) as
// two separate strings rather than the POSIX absolute-path
// convention. Resolves the mount, calls `filesystem::resolve` on
// it, installs the resulting `FileOps` in the calling task's fd
// table, returns the new fd. POSIX-shaped path parsing (split a
// single absolute path into mount + relative) lands when the VFS
// has a mount-point matcher.

/// `O_CREAT` — create the file if missing. Bit 6 to match Linux's
/// numeric convention so a libc consumer's `<fcntl.h>` lines up.
pub const O_CREAT: u64 = 0o100;

/// Shared open path. Resolves `path_owned_raw` (relative paths against the
/// task cwd + chroot in the absolute-mount form) and installs the fd. Split
/// out of `sys_open` so `sys_openat` can prepend a directory-fd's path and
/// reuse the exact same resolution / permission / O_CREAT / directory-fd /
/// inotify logic — a real `dirfd` is what sd-device's `chase_symlinks` (behind
/// libudev / elogind seat enumeration) walks with, one `openat` per component.
#[cfg(feature = "container")]
fn proc_namespace_fd_from_path(
    caller: u64,
    path: &str,
    proc_prefix: &str,
) -> Option<alloc::sync::Arc<crate::namespaces::NsFd>> {
    use crate::namespaces::NsFlavour;

    let relative = path.strip_prefix(proc_prefix)?.strip_prefix('/')?;
    let mut components = relative.split('/');
    let process = components.next()?;
    if components.next()? != "ns" {
        return None;
    }
    let flavour = match components.next()? {
        "uts" => NsFlavour::Uts,
        "net" => NsFlavour::Net,
        "ipc" => NsFlavour::Ipc,
        "pid" => NsFlavour::Pid,
        "mnt" => NsFlavour::Mnt,
        "cgroup" => NsFlavour::Cgroup,
        "user" => NsFlavour::User,
        _ => return None,
    };
    if components.next().is_some() {
        return None;
    }
    let target_task = match process {
        "self" | "thread-self" => caller,
        visible => {
            let inner = visible.parse::<u64>().ok()?;
            let outer = accept_pid_from(caller, inner)?;
            pid_to_task_raw(outer)?
        }
    };
    namespace_fd_for_task(target_task, flavour)
}

fn open_impl(
    ctx: &mut dyn TrapContext,
    path_owned_raw: alloc::string::String,
    flags: u64,
    mnt_ptr: u64,
    mnt_len: usize,
    create_mode: u32,
) {
    // FIFO open-peer rendezvous re-entry: a blocking FIFO `open()` installed
    // its fd and parked waiting for the peer direction (see `open_fifo`); the
    // park RIP-rewound and re-executed this syscall. Resume the peer-check for
    // the already-installed fd instead of re-resolving the path (which would
    // install a second fd and drop the first handle's open count).
    if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: `uctx` is the live per-task ctx; single-threaded syscall.
        let pending = unsafe {
            (*uctx)
                .fifo_open_pending_fd
                .load(core::sync::atomic::Ordering::Acquire)
        };
        if pending != 0 {
            resume_fifo_open(ctx, (pending - 1) as u32);
            return;
        }
    }
    // Record the access mode (O_RDONLY/O_WRONLY/O_RDWR), O_PATH identity, and
    // the settable status flags (O_NONBLOCK | O_APPEND | O_DIRECT) on the fd, so
    // `fcntl(F_GETFL)` reports both. glibc's `fdopen(fd, "w")` reads the
    // access mode via F_GETFL and rejects the stream with EINVAL if it
    // doesn't match the requested mode — systemd fdopens a `cgroup.procs`
    // it opened O_WRONLY, so a dropped access mode failed that check.
    // (O_NONBLOCK matters on its own for libinput's evdev nodes — see
    // `InputEventFile::nonblock_read_eagain`.)
    let open_status_flags =
        (flags as u32) & (crate::fd::O_ACCMODE | crate::fd::O_SETFL_MASK | crate::fd::O_PATH);
    // O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2. Bits 0..1 of flags.
    let access_mode = flags & 0o3;
    let want_r = access_mode == 0 || access_mode == 2;
    let want_w = access_mode == 1 || access_mode == 2;
    let task = current_task_id();
    // Linux open/openat reject an empty pathname with ENOENT. Do this before
    // cwd normalization: `resolve_cwd_path(task, "")` otherwise collapses to
    // the cwd itself and accidentally opens a directory. dbus-broker probes an
    // optional empty path this way; opening cwd produced a regular fd that it
    // added to epoll, yielding an infinite readable-at-EOF loop.
    if path_owned_raw.is_empty() {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
        return;
    }
    // Resolve relative paths against the task's cwd and collapse
    // `.`/`..` (absolute-mount form only; the explicit-mount form below
    // keeps its already-relative-to-the-mount path). This is what makes
    // `ls` (which opens ".") and any relative open work from a shell.
    let path_owned = if mnt_len == 0 {
        resolve_cwd_path_owned(task, path_owned_raw)
    } else {
        path_owned_raw
    };
    // Filesystem-local resolution restarts an absolute symlink at the root of
    // the filesystem containing that link. Linux instead restarts at the
    // task's VFS root, which may cross a mount boundary (for example a distro
    // unit masked by `/etc/systemd/system/foo.service -> /dev/null`). Expand
    // those links through the current mount table before the final lookup.
    // O_NOFOLLOW still preserves a final link, while intermediate links must
    // always be traversed.
    let proc_magic_path = chroot_path_matches(task, &path_owned, "/proc", true);
    let mut fast_create = if mnt_len == 0
        && !proc_magic_path
        && flags & O_CREAT != 0
        && flags & 0o400000 == 0
    {
        resolve_create_fast(&path_owned)
    } else {
        None
    };
    let fast_create_mount_id = fast_create.as_ref().map(FastCreateResolution::mount_id);
    let path_owned = if fast_create.is_some() {
        path_owned
    } else if mnt_len == 0 && !proc_magic_path {
        resolve_vfs_symlink_path(&path_owned, flags & 0o400000 == 0).unwrap_or(path_owned)
    } else {
        path_owned
    };
    let path: &str = &path_owned;

    // RLIMIT_NOFILE is enforced by the fd table itself now, so every
    // allocation site reports -EMFILE the same way. The pre-check that used
    // to live here counted OPEN descriptors, but `alloc_fd` bounds the
    // descriptor NUMBER: `if (fd >= end) error = -EMFILE`. With a sparse
    // table the two disagree — a task holding fds 0-2 and 900 is nowhere near
    // its 1024 limit by count, yet Linux lets it keep opening until the
    // lowest free number reaches 1024, and this check would have stopped it
    // at an unrelated point. Positional is the rule; the table applies it.

    // Following a proc namespace magic link yields an nsfs-like fd whose
    // held namespace can be consumed by setns(2). O_PATH|O_NOFOLLOW must
    // still open the symlink itself, so leave that case to the nofollow path.
    #[cfg(feature = "container")]
    if mnt_len == 0 && flags & 0o400000 == 0 {
        let proc_prefix = apply_chroot("/proc");
        if let Some(nsfd) = proc_namespace_fd_from_path(task, path, &proc_prefix) {
            let ops: Arc<dyn narf_filesystem::FileOps> = nsfd;
            let new_fd = fd::install(task, crate::fd::FdEntry {
                    ops,
                    offset: 0,
                    flags: 0,
                    status_flags: open_status_flags,
                });
            match new_fd {
                Some(n) => {
                    crate::mqueue::register_fd_path(task, n, path, current_mount_id_at(path));
                    ctx.set_return(SyscallReturn::ok(n as u64));
                }
                None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
            }
            return;
        }
    }

    // O_TMPFILE: create an unnamed (nameless) regular inode inside the
    // directory named by `path`, and hand back a normal read/write fd to
    // it. The inode has no name until `linkat(fd, "", …, AT_EMPTY_PATH)`
    // materialises it (see `sys_linkat`). It lives on the SAME tmpfs/memfs
    // that backs the target directory, so `link_node` can file it in
    // later. If the directory's filesystem can't hold such a node
    // (`supports_tmpfile()` is false — ext2 / a read-only backing), report
    // -EOPNOTSUPP so callers (systemd, Qt QSaveFile, libc tmpfile) fall
    // back to a named temp + rename. Linux ref: `vfs_tmpfile` →
    // `shmem_tmpfile`. `__O_TMPFILE` is set with O_DIRECTORY in the full
    // `O_TMPFILE` value; the directory arg is not itself opened.
    const O_TMPFILE_BIT: u64 = 0o20_000_000; // __O_TMPFILE (x86_64)
    if flags & O_TMPFILE_BIT != 0 && mnt_len == 0 {
        match resolve_dir_absolute(path) {
            Some(dir) if dir.supports_tmpfile() => {
                let node = match poll_blocking(dir.tmpfile(0o600)) {
                    Some(Ok(node)) => node,
                    Some(Err(narf_filesystem::FsError::Unsupported)) => {
                        // memfs predates the generic tmpfile hook and can
                        // safely accept the anonymous in-memory node.
                        narf_filesystem::new_anon_memfile()
                    }
                    _ => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                        return;
                    }
                };
                let new_fd = fd::install(task, crate::fd::FdEntry {
                        ops: node,
                        offset: 0,
                        flags: 0,
                        status_flags: open_status_flags,
                    });
                match new_fd {
                    Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
                    None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
                }
            }
            // Directory resolves but its FS can't hold an anonymous inode,
            // or the path doesn't name a directory at all: EOPNOTSUPP so
            // the caller falls back rather than treating it as fatal.
            _ => ctx.set_return(SyscallReturn::ok((-95i64) as u64)), // -EOPNOTSUPP
        }
        return;
    }

    // O_NOFOLLOW: don't follow a final-component symlink. With O_PATH this
    // opens the symlink node ITSELF (the caller then readlink()s it); without
    // O_PATH, POSIX open(O_NOFOLLOW) on a symlink is -ELOOP. sd-device's
    // chase_symlinks opens each component O_PATH|O_NOFOLLOW, fstat()s it, and
    // readlinkat()s any symlink to resolve it to its target — following it
    // here instead reported the pre-resolution path (`/sys/dev/char/226:0`),
    // which sd-device then rejects as "outside of sysfs". Resolve the parent
    // (following symlinks) and look the leaf up WITHOUT following it.
    const O_NOFOLLOW: u64 = 0o400000;
    const O_PATH: u64 = 0o10000000;
    if flags & O_NOFOLLOW != 0 && mnt_len == 0 {
        // Look the leaf up WITHOUT following a trailing symlink, driving the
        // ASYNC resolver: on a disk-backed rootfs (ext2) the sync `lookup`
        // is stubbed (block reads can't run synchronously), so a sync
        // parent-lookup never sees an on-disk symlink and every
        // O_NOFOLLOW|O_PATH open silently followed it. That broke
        // `chase_symlinks`/`open_os_release_at` (systemd, sd-device), which
        // walk a path one `openat(…, O_NOFOLLOW|O_PATH)` per component and
        // `readlinkat()` each symlink — following the final component here
        // handed them the target instead of the link. `resolve_async_nofollow`
        // follows intermediate symlinks but returns a final symlink as-is.
        let leaf = current_resolve_absolute(path, |fs, rel| {
            poll_blocking(narf_filesystem::resolve_async_nofollow(fs.root(), rel))
                .and_then(|r| r.ok())
        })
        .flatten();
        if let Some(lops) = leaf {
            if lops.stat().mode.file_type == narf_filesystem::FileType::Symlink {
                if flags & O_PATH == 0 {
                    ctx.set_return(SyscallReturn::ok((-40i64) as u64)); // -ELOOP
                    return;
                }
                let new_fd = fd::install(task, crate::fd::FdEntry {
                        ops: lops,
                        offset: 0,
                        flags: 0,
                        status_flags: open_status_flags,
                    });
                match new_fd {
                    Some(n) => {
                        crate::mqueue::register_fd_path(task, n, path, current_mount_id_at(path));
                        ctx.set_return(SyscallReturn::ok(n as u64));
                    }
                    None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
                }
                return;
            }
            // Not a symlink (a regular file leaf) — fall through to the normal
            // resolve; O_NOFOLLOW only constrains symlinks.
        }
        // Leaf absent via parent-lookup (a directory-only node, or O_CREAT) —
        // fall through to the directory / O_CREAT handling below.
    }

    // Two shapes:
    // - Absolute: arg2/arg3 = (0, 0). The path itself is `/foo/bar`;
    //   the registry finds the longest-matching mount.
    // - Explicit-mount: arg2/arg3 = (ptr, len). The path is relative.
    //   Useful when the caller already knows the mount.
    let ops = if let Some(FastCreateResolution::Existing { node, .. }) = fast_create.as_ref() {
        Some(Arc::clone(node))
    } else if fast_create.is_some() {
        None
    } else if mnt_len == 0 {
        current_resolve_absolute(path, |fs, rel| {
            if rel.is_empty() {
                // A file-rooted mount (mount --bind of a file) resolves to the
                // file at its own path; a directory-rooted mount yields None
                // here and is handled by the directory branch below.
                fs.root_file()
            } else {
                poll_blocking(narf_filesystem::resolve_async(fs.root(), rel)).and_then(|r| r.ok())
            }
        })
        .flatten()
    } else {
        let mount_owned = match copy_user_path(mnt_ptr, mnt_len) {
            Some(s) => s,
            None => {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
                return;
            }
        };
        narf_filesystem::registry()
            .with_mount(&mount_owned, |fs| {
                poll_blocking(narf_filesystem::resolve_async(fs.root(), path)).and_then(|r| r.ok())
            })
            .flatten()
    };

    // Directory open: hand back a directory fd (a `DirFdFile` carrying the
    // `DirOps`) when the path names a directory, either because it didn't
    // resolve to a `FileOps` at all or because it resolved to a
    // directory-typed node. `opendir`/`getdents64`/`ls` depend on this, and
    // it runs before the O_CREAT branch so `open(dir, O_RDONLY)` succeeds.
    //
    // `resolved_is_dir` covers a synthetic FS that returns a subdirectory
    // (e.g. `/proc/<pid>/fd`) from `lookup()` as a directory-typed `FileOps`
    // marker so the path resolver can descend into it: route it through
    // `resolve_dir_absolute` to get a real `DirFdFile` whose `as_dir()` is
    // `Some`, rather than opening the marker as a plain file.
    let resolved_is_dir = ops
        .as_ref()
        .map(|o| o.stat().mode.file_type == narf_filesystem::FileType::Dir)
        .unwrap_or(false);
    if fast_create.is_none() && (ops.is_none() || resolved_is_dir) && mnt_len == 0 {
        if let Some(dirops) = resolve_dir_absolute(path) {
            let new_fd = fd::install(task, crate::fd::FdEntry {
                    ops: alloc::sync::Arc::new(DirFdFile { dir: dirops }),
                    offset: 0,
                    flags: 0,
                    status_flags: open_status_flags,
                });
            match new_fd {
                Some(n) => {
                    // Record the backing path so /proc/<pid>/fd/<n> readlinks
                    // to it (musl realpath, lsof, opendir-on-fd). See fd_path_of.
                    crate::mqueue::register_fd_path(task, n, path, current_mount_id_at(path));
                    ctx.set_return(SyscallReturn::ok(n as u64));
                }
                None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
            }
            return;
        }
    }

    // O_CREAT path: when the lookup misses and the caller asked for
    // creation, route through the parent directory's `create()`. The
    // explicit-mount form is rare on the create path and not yet
    // wired; absolute paths are the supported entry.
    let mut created = false;
    let ops = match ops {
        Some(o) => o,
        None if (flags & O_CREAT) != 0 && mnt_len == 0 => {
            // Linux checks path-based LSM policy before publishing a new
            // inode. The old order created the file and only then let
            // Landlock reject the open, leaving a forbidden side effect.
            if let Err(denied) =
                crate::landlock::landlock_check_open(task, path, want_r, want_w)
            {
                ctx.set_return(denied);
                return;
            }
            let accessor = current_accessor(task);
            // `open(O_CREAT)` -> `vfs_create` -> `shmem_create` ->
            // `simple_acl_create`. A parent with a default ACL replaces the
            // umask with it, so `permissions` cannot be computed until the
            // parent is known — see `inherit_acls_from_parent`.
            //
            // The mode mask is `S_IALLUGO` (07777), not 0777:
            // `vfs_create` passes the caller's set-user-ID and set-group-ID
            // bits through. That is safe because the new file is owned by
            // the CREATOR, so setuid-to-yourself confers nothing, and the
            // dangerous half — a group-executable set-group-ID file in a
            // setgid directory whose group the creator is not in — is what
            // `mode_strip_sgid` removes. Masking the bits off instead
            // meant `open(path, O_CREAT, 02755)` silently produced a
            // non-setgid file and `mode_strip_sgid` had nothing to guard.
            let mut inherited_access: Option<alloc::vec::Vec<u8>> = None;
            let mut permissions = (create_mode & !current_umask() & 0o777) as u16;
            // `inode_init_owner` hands the new file the parent's group when
            // the parent is setgid; without a parent in hand the creating
            // task's own ids are the answer.
            let mut owner = (accessor.uid, accessor.gid);
            // Async parent resolution so O_CREAT works in subdirectories of
            // a disk-backed (ext2) rootfs, not just sync-resolvable mounts.
            let create_result = fast_create
                .take()
                .and_then(|resolution| match resolution {
                    FastCreateResolution::Missing { parent, leaf, .. } => Some((parent, leaf)),
                    FastCreateResolution::Existing { .. } => None,
                })
                .map(|(parent, leaf)| {
                    // `path_openat` -> `open_last_lookups` -> `may_create`:
                    // write+exec on the directory the new name lands in.
                    // Without it any task could plant a file in any
                    // directory. Checked against the parent this path has
                    // ALREADY resolved — a second walk here would put a
                    // whole path lookup on every O_CREAT.
                    // `PermissionDenied` is the refusal the create-result
                    // match below already maps to EACCES, which is the
                    // errno `may_create` produces.
                    if may_create_in(&*parent, task).is_err() {
                        return Some(Err(narf_filesystem::FsError::PermissionDenied));
                    }
                    let inherited =
                        inherit_acls_from_parent(&*parent, (create_mode & 0o7777) as u16, false);
                    permissions = inherited.mode;
                    inherited_access = inherited.access;
                    owner = (inherited.uid, inherited.gid);
                    poll_blocking(parent.create_with_attrs(&leaf, permissions, owner.0, owner.1))
                })
                .or_else(|| {
                    resolve_parent_dir_async(path).map(|(parent, leaf)| {
                        if may_create_in(&*parent, task).is_err() {
                            return Some(Err(narf_filesystem::FsError::PermissionDenied));
                        }
                        let inherited =
                            inherit_acls_from_parent(&*parent, (create_mode & 0o7777) as u16, false);
                        permissions = inherited.mode;
                        inherited_access = inherited.access;
                        owner = (inherited.uid, inherited.gid);
                        poll_blocking(parent.create_with_attrs(&leaf, permissions, owner.0, owner.1))
                    })
                });
            match create_result {
                Some(Some(Ok(o))) => {
                    {
                        created = true;
                    }
                    // An inherited access ACL goes on before the fd is
                    // published: a file briefly visible without the ACL it
                    // should have been born with is a permission hole.
                    if let Some(blob) = inherited_access.as_ref() {
                        let _ = poll_blocking(o.set_xattr(
                            narf_filesystem::AclType::Access.xattr_name(),
                            blob,
                            0,
                        ));
                    }
                    o
                }
                Some(Some(Err(narf_filesystem::FsError::NoSpace))) => {
                    ctx.set_return(SyscallReturn::ok((-28i64) as u64));
                    return;
                }
                Some(Some(Err(narf_filesystem::FsError::QuotaExceeded))) => {
                    ctx.set_return(SyscallReturn::ok((-122i64) as u64));
                    return;
                }
                Some(Some(Err(error))) => {
                    let errno = match error {
                        narf_filesystem::FsError::NotFound => 2,          // ENOENT
                        narf_filesystem::FsError::PermissionDenied => 13, // EACCES
                        narf_filesystem::FsError::OperationNotPermitted => 1, // EPERM
                        narf_filesystem::FsError::Io(_) => 5,             // EIO
                        narf_filesystem::FsError::InvalidPath
                        | narf_filesystem::FsError::InvalidData => 22, // EINVAL
                        narf_filesystem::FsError::SymlinkLoop => 40,   // ELOOP
                        narf_filesystem::FsError::CrossDevice => 18,      // EXDEV
                        narf_filesystem::FsError::Busy => 16,             // EBUSY
                        narf_filesystem::FsError::ReadOnly => 30,         // EROFS
                        narf_filesystem::FsError::Unsupported => 95,      // EOPNOTSUPP
                        narf_filesystem::FsError::BrokenPipe => 32,       // EPIPE
                        narf_filesystem::FsError::BadFd => 9,             // EBADF
                        narf_filesystem::FsError::WouldBlock => 11,       // EAGAIN
                        narf_filesystem::FsError::NoSpace => 28,
                        narf_filesystem::FsError::QuotaExceeded => 122,
                        // ENOTCONN. No `open` path produces it today — it is
                        // the qgroup ioctls' answer for "quotas are off" — but
                        // translating it truthfully costs nothing and is
                        // better than folding it into EINVAL if one ever does.
                        narf_filesystem::FsError::NotConnected => 107,
                    };
                    ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                    return;
                }
                None | Some(None) => {
                    ctx.set_return(SyscallReturn::ok((-5i64) as u64)); // -EIO
                    return;
                }
            }
        }
        None => {
            // Missing file (no O_CREAT): report -ENOENT, not the generic
            // -1 sentinel. musl maps the raw return to -errno, so a
            // daemon that opens an optional file (e.g. redis probing for
            // dump.rdb) sees ENOENT and continues instead of treating it
            // as a fatal EPERM. Native callers detect the negative range.
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
            return;
        }
    };

    // O_PATH: install a bare path-reference fd. Per Linux `do_dentry_open`,
    // an O_PATH open resolves the node but invokes NO file operation — no
    // FIFO peer-rendezvous, no /dev/ptmx clone, no device `open`, and no
    // read/write permission check on the file itself (O_PATH needs only
    // search permission on the path components, already enforced by
    // resolution). The resulting fd is usable for fstat / as an `openat`
    // dirfd base / readlinkat, which is exactly what a walker needs. Without
    // this, `systemd-tmpfiles-setup-dev` and sd-device — which scan /dev with
    // `openat(…, O_PATH|O_NOFOLLOW)` purely to stat each node — parked forever
    // the moment they reached a FIFO with no writer. Directories still wrap in
    // `DirFdFile` so `openat`-relative descent and getdents work.
    if flags & O_PATH != 0 {
        let ops = if let Some(dirops) = ops.as_dir() {
            alloc::sync::Arc::new(DirFdFile { dir: dirops }) as Arc<dyn narf_filesystem::FileOps>
        } else {
            ops
        };
        let new_fd = fd::install(task, crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: open_status_flags,
            });
        match new_fd {
            Some(n) => {
                crate::mqueue::register_fd_path(task, n, path, current_mount_id_at(path));
                ctx.set_return(SyscallReturn::ok(n as u64));
            }
            None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
        }
        return;
    }

    // `/dev/tty` is the calling process's controlling terminal, not an alias
    // for the system console. Preserve O_PATH's side-effect-free path inode
    // above; a real open selects the console or live PTY slave recorded by
    // TIOCSCTTY. A session with no controlling terminal gets Linux ENXIO.
    let ops = if mnt_len == 0 && chroot_path_matches(task, path, "/dev/tty", false) {
        let selected: Arc<dyn narf_filesystem::FileOps> = match task_ctty(task) {
            Some(CTTY_CONSOLE) => ops.clone(),
            Some(index) => match narf_filesystem::devfs_pty::pts_lookup(index) {
                Some(pty) => Arc::new(narf_filesystem::devfs_pty::PtySlave::new(pty)),
                None => {
                    ctx.set_return(SyscallReturn::ok((-6i64) as u64)); // -ENXIO
                    return;
                }
            },
            None => {
                ctx.set_return(SyscallReturn::ok((-6i64) as u64)); // -ENXIO
                return;
            }
        };
        Arc::new(CurrentTtyFile {
            inner: selected,
            inode: ops.ino(),
        }) as Arc<dyn narf_filesystem::FileOps>
    } else {
        ops
    };

    // POSIX-2017 permission check. The accessor's UID/GID come from
    // the per-task uidgid table; the file's owners + perms come from
    // its FileOps trait. UID 0 (root) shortcuts; non-root must own
    // a matching r/w bit per POSIX `open(2)` description. Today most
    // FSes report (uid=0, gid=0, perms=0o666) so non-root tasks see
    // the "other" triplet's rw bits and pass; the gate is structural
    // until ext2/minix start surfacing real owners.
    let (stat, file_uid, file_gid) = if created {
        // Linux's may_open() permission check applies to an existing inode.
        // A newly created file is already open under the creation intent;
        // checking its just-created mode could reject `open(O_CREAT, 000)`
        // after the pathname had become visible.
        (None, 0, 0)
    } else {
        let stat = ops.stat();
        let (file_uid, file_gid) = ops.owners();
        (Some(stat), file_uid, file_gid)
    };
    if let Some(stat) = stat {
        let wanted = u16::from(want_r) * 0o4 + u16::from(want_w) * 0o2;
        let owner = current_host_fsuid(task) == file_uid;
        // Linux tests inode ownership before `check_acl`: ACL_USER_OBJ is
        // already mirrored into the mode's owner triplet, and no named ACL
        // entry may override it. The overwhelmingly common open-by-owner can
        // therefore finish from lock-free inode metadata without allocating
        // an xattr future or reading groups/capabilities.
        let owner_mode_grants = owner && ((stat.mode.perms >> 6) & wanted) == wanted;
        if !owner_mode_grants {
            // `may_open` reaches `check_acl` only after the owner branch. A
            // non-owner must still consult the ACCESS ACL; an owner denied by
            // its mode skips it but may receive a capability override below.
            let acl = if owner {
                None
            } else {
                match poll_blocking(narf_filesystem::acl_of_file(
                    ops.as_ref(),
                    narf_filesystem::AclType::Access,
                )) {
                    Some(Ok(acl)) => acl,
                    // A stored ACL that does not decode is NOT a fallback to
                    // mode bits: check_acl returns the decode error unchanged.
                    Some(Err(narf_filesystem::FsError::Unsupported)) => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                        return;
                    }
                    Some(Err(_)) => {
                        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                        return;
                    }
                    None => None,
                }
            };
            // SECURITY: build the Accessor through the single translation
            // funnel so user-namespace ids and inode-scoped capability
            // overrides retain their existing host-id semantics.
            if !narf_filesystem::posix_access_ok_with_acl(
                narf_filesystem::FileOwner {
                    uid: file_uid,
                    gid: file_gid,
                    perms: stat.mode.perms,
                    is_dir: stat.mode.file_type == narf_filesystem::FileType::Dir,
                },
                &accessor_for_inode(task, file_uid, file_gid),
                narf_filesystem::AccessRequest {
                    read: want_r,
                    write: want_w,
                    exec: false,
                },
                acl.as_ref(),
            ) {
                // -EACCES, not the generic `fail` (-1/-EPERM). Linux open(2)
                // reserves EPERM for a different class of failure.
                ctx.set_return(SyscallReturn::ok((-13i64) as u64));
                return;
            }
        }
    }

    // `fs/namei.c::may_open`:
    //
    //     if (path->mnt->mnt_flags & MNT_NODEV && (S_ISBLK || S_ISCHR)) ...
    //     ...
    //     error = mnt_want_write(path->mnt);   /* for write intent */
    //
    // A write-intent open of anything on a read-only mount is EROFS, and a
    // device node on a `nodev` mount cannot be opened at all. Both are
    // properties of the MOUNT, so they hold even for root — which is the
    // point: a sandbox mounts `nodev` precisely so a privileged process
    // inside it still cannot reach a device.
    if narf_filesystem::any_restricted_mounts() {
        let mnt = current_mount_flags_at(path);
        if want_w && mnt & narf_filesystem::mnt_flags::READONLY != 0 {
            ctx.set_return(SyscallReturn::ok((-30i64) as u64)); // -EROFS
            return;
        }
        if mnt & narf_filesystem::mnt_flags::NODEV != 0 {
            let kind = ops.stat().mode.file_type;
            if matches!(
                kind,
                narf_filesystem::FileType::Special | narf_filesystem::FileType::Block
            ) {
                // `may_open`'s device arm is -EACCES, not EPERM.
                ctx.set_return(SyscallReturn::ok((-13i64) as u64));
                return;
            }
        }
    }

    // `inode_permission`'s "Nobody gets write access to an immutable
    // file", plus `may_open`'s append-only arm:
    //
    //     if (IS_APPEND(inode)) {
    //             if ((flag & O_ACCMODE) != O_RDONLY && !(flag & O_APPEND))
    //                     return -EPERM;
    //             if (flag & O_TRUNC)
    //                     return -EPERM;
    //     }
    {
        const O_APPEND: u64 = 0o2000;
        const O_TRUNC: u64 = 0o1000;
        let iflags = ops.inode_flags();
        if want_w && iflags & narf_filesystem::FS_IMMUTABLE_FL != 0 {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
            return;
        }
        if iflags & narf_filesystem::FS_APPEND_FL != 0
            && ((want_w && flags & O_APPEND == 0) || flags & O_TRUNC != 0)
        {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
            return;
        }
    }

    // Landlock: a self-restricted task's open must be permitted by its
    // active rulesets, else EACCES.
    if !created {
        if let Err(denied) = crate::landlock::landlock_check_open(task, path, want_r, want_w) {
            ctx.set_return(denied);
            return;
        }
    }

    // Clone devices keep path lookup/stat side-effect free and allocate their
    // per-open state only here after permissions have passed. This covers
    // PTY masters and independent FUSE daemon connections.
    let ops = if let Some(instance) = ops.open_instance() {
        instance
    } else {
        ops
    };

    // Directory fd: a real fs directory resolves to its raw node, whose
    // read() yields 0 and whose poll_readiness() is the always-ready default.
    // A program that opens a directory and adds it to epoll (dbus-daemon
    // watching its service dirs) then busy-spins: epoll always reports it
    // ready, read returns 0, loop. Wrap it in DirFdFile so the fd behaves
    // like a directory — read/write are rejected, getdents64 rides `as_dir`,
    // and poll reports NOT readable (so epoll never spuriously wakes on it).
    let ops = if let Some(dirops) = ops.as_dir() {
        alloc::sync::Arc::new(DirFdFile { dir: dirops }) as Arc<dyn narf_filesystem::FileOps>
    } else {
        ops
    };

    // Named pipe (FIFO): the resolved node is a FIFO inode. Build a per-open
    // directional handle bound to the node's shared buffer (all openers of the
    // path rendezvous on it), apply the fifo(7) open-peer blocking semantics,
    // and install THAT — not the bare node. `open_fifo` may park (releasing
    // every lock first) and set the return itself.
    if let Some(shared) = ops.fifo_shared() {
        let node_ino = ops.ino();
        let perms = ops.stat().mode.perms;
        let (fifo_uid, fifo_gid) = ops.owners();
        let nonblock = flags & (crate::fd::O_NONBLOCK as u64) != 0;
        open_fifo(
            ctx,
            shared,
            Arc::clone(&ops),
            node_ino,
            perms,
            fifo_uid,
            fifo_gid,
            access_mode,
            nonblock,
            path,
        );
        return;
    }

    let new_fd = match fd::install(task, crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: open_status_flags,
        }) {
        Some(n) => n,
        None => {
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    };
    // Inotify: emit IN_CREATE (new file) + IN_OPEN against any matching
    // watch, then move the normalized pathname into the fd identity table.
    // All three publications finish before the syscall returns; moving avoids
    // cloning the path only to free the original immediately afterwards.
    {
        let fd_mount_id = fast_create_mount_id.or_else(|| current_mount_id_at(path));
        if created {
            crate::mqueue::notify_create(path, false);
        }
        crate::mqueue::notify_open(path);
        crate::mqueue::register_fd_path_owned(task, new_fd, path_owned, fd_mount_id);
    }
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

/// Open a named pipe (FIFO), applying the fifo(7) peer-rendezvous rules.
///
/// `access_mode` is the low-2-bit O_RDONLY/O_WRONLY/O_RDWR selector; `shared`
/// is the FIFO node's shared buffer (every opener of the path shares one).
/// A per-open [`narf_filesystem::fifo::FifoHandle`] carrying the direction is
/// installed as the fd — its open-count registration is what a peer waits on:
///
/// * O_RDWR: opens without blocking (Linux extension), counts as both ends.
/// * O_RDONLY: readable end; if a writer is already open, returns at once.
///   Otherwise O_NONBLOCK returns the fd immediately; a blocking open PARKS
///   until a writer appears.
/// * O_WRONLY: writable end; if a reader is already open, returns at once.
///   Otherwise O_NONBLOCK returns -ENXIO; a blocking open PARKS until a
///   reader appears.
///
/// The fd is installed BEFORE any park so its open count persists across the
/// RIP-rewind re-execution (`resume_fifo_open` handles re-entry). All
/// filesystem/fd-table locks are dropped before the park — a FIFO open that
/// blocked with a lock held would wedge the kernel.
#[allow(clippy::too_many_arguments)]
fn open_fifo(
    ctx: &mut dyn TrapContext,
    shared: Arc<narf_filesystem::fifo::FifoShared>,
    inode_owner: Arc<dyn narf_filesystem::FileOps>,
    node_ino: u64,
    perms: u16,
    uid: u32,
    gid: u32,
    access_mode: u64,
    nonblock: bool,
    _path: &str,
) {
    let task = current_task_id();
    let can_read = access_mode == 0 || access_mode == 2; // O_RDONLY | O_RDWR
    let can_write = access_mode == 1 || access_mode == 2; // O_WRONLY | O_RDWR
    let rdwr = access_mode == 2;

    // O_WRONLY | O_NONBLOCK with no reader present is -ENXIO (fifo(7)) — and
    // must NOT register a writer (that would be observable to a later reader
    // as a phantom peer). Checked before building the handle.
    if can_write && !can_read && nonblock && shared.reader_count() == 0 {
        ctx.set_return(SyscallReturn::ok((-6i64) as u64)); // -ENXIO
        return;
    }

    // Build + install the per-open handle. This registers the direction's
    // open count, which is exactly what the peer rendezvous observes.
    let handle = Arc::new(narf_filesystem::fifo::FifoHandle::open_owned(
        shared.clone(),
        inode_owner,
        node_ino,
        perms,
        uid,
        gid,
        can_read,
        can_write,
    )) as Arc<dyn narf_filesystem::FileOps>;
    let status_flags = access_mode as u32 | if nonblock { crate::fd::O_NONBLOCK } else { 0 };
    let new_fd = match fd::install(task, crate::fd::FdEntry {
            ops: handle,
            offset: 0,
            flags: 0,
            status_flags,
        }) {
        Some(n) => n,
        None => {
            // `fs/namei.c::do_open` allocates the descriptor with
            // `get_unused_fd_flags`, so a table at RLIMIT_NOFILE is -EMFILE.
            // `!0u64` is the `-1` sentinel in disguise and reached userspace
            // as EPERM — which for a FIFO open reads as "you may not open
            // this pipe", a permission problem the caller cannot retry.
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    };

    // Opening either direction changes the FIFO peer condition. Blocking
    // openers use the normal deduplicated I/O-waker registry below; publish
    // the transition only after the handle/open-count is visible. The shared
    // readiness generation closes the notify-before-register race.
    narf_net::readiness::notify(0);

    // Peer already present (or O_RDWR / O_NONBLOCK) → return the fd now.
    let peer_ready = rdwr
        || nonblock
        || (can_read && shared.writer_count() > 0)
        || (can_write && shared.reader_count() > 0);
    if peer_ready {
        crate::mqueue::register_fd_path(task, new_fd, _path, current_mount_id_at(_path));
        ctx.set_return(SyscallReturn::ok(new_fd as u64));
        return;
    }

    // Blocking open with no peer yet: stash the fd and park until the peer
    // opens (or the ~1ms wheel backstop re-checks). The handle stays installed
    // so its open count is visible to the peer across the park.
    if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: live per-task ctx; single-threaded syscall.
        unsafe {
            (*uctx)
                .fifo_open_pending_fd
                .store(new_fd as u64 + 1, core::sync::atomic::Ordering::Release);
        }
    }
    fifo_park_or_finish(ctx, new_fd);
}

/// Re-entry after a FIFO-open park: re-check whether the peer has appeared for
/// the already-installed `fd`. Returns the fd (clearing the pending slot) once
/// the peer is present, else parks again on the ~1ms backstop.
fn resume_fifo_open(ctx: &mut dyn TrapContext, fd: u32) {
    let task = current_task_id();
    // The handle retains the counterpart edge observed before it published
    // itself, so a peer open+close is not lost merely because its level is
    // already clear when this task runs again.
    let ready = fd::with_table(task, |t| {
        t.get(fd).and_then(|e| {
            e.ops
                .as_any()
                .and_then(|any| any.downcast_ref::<narf_filesystem::fifo::FifoHandle>())
                .map(narf_filesystem::fifo::FifoHandle::peer_ready_or_seen)
        })
    })
    .flatten()
    .unwrap_or(true); // fd vanished (closed under us) → stop parking.

    if ready {
        if let Some(uctx) = crate::user_task::current_user_task() {
            // SAFETY: live per-task ctx; single-threaded syscall.
            unsafe {
                (*uctx)
                    .fifo_open_pending_fd
                    .store(0, core::sync::atomic::Ordering::Release);
            }
        }
        ctx.set_return(SyscallReturn::ok(fd as u64));
        return;
    }
    fifo_park_or_finish(ctx, fd);
}

/// Park the current task on the shared I/O-waker registry and RIP-rewind so
/// the syscall re-executes (and `resume_fifo_open` re-checks the peer). The
/// timer wheel remains only a ~1ms lost-wake backstop. Falls back to returning
/// the fd in a non-executor (kernel-test) context.
fn fifo_park_or_finish(ctx: &mut dyn TrapContext, fd: u32) {
    let task = current_task_id();
    let ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten();
    if let Some(ops) = ops {
        if let Some(handle) = ops
            .as_any()
            .and_then(|any| any.downcast_ref::<narf_filesystem::fifo::FifoHandle>())
        {
            if let Some(waker) = narf_scheduler::stackful::current_stackful_waker() {
                match handle.arm_peer(task, &waker) {
                    Poll::Ready(()) => {
                        if let Some(uctx) = crate::user_task::current_user_task() {
                            // SAFETY: live per-task ctx; single-threaded syscall.
                            unsafe {
                                (*uctx)
                                    .fifo_open_pending_fd
                                    .store(0, core::sync::atomic::Ordering::Release);
                            }
                        }
                        ctx.set_return(SyscallReturn::ok(fd as u64));
                        return;
                    }
                    Poll::Pending => {
                        let parked = park_reexecute_on_io(ctx);
                        handle.disarm_peer(task);
                        if parked {
                            return;
                        }
                    }
                }
            } else if park_reexecute_on_io(ctx) {
                return;
            }
        } else if park_reexecute_on_io(ctx) {
            return;
        }
    } else if park_reexecute_on_io(ctx) {
        return;
    }
    // No executor (kernel-test): can't park; hand back the fd so the round
    // trip still completes (the peer-rendezvous blocking is only exercised
    // under a live scheduler).
    if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: live per-task ctx.
        unsafe {
            (*uctx)
                .fifo_open_pending_fd
                .store(0, core::sync::atomic::Ordering::Release);
        }
    }
    ctx.set_return(SyscallReturn::ok(fd as u64));
}

// ── Write — arg0=fd, arg1=buf, arg2=len ────────────────────────────
//
// fd 1 / fd 2: console (stdout/stderr) — direct path so user code
// without an explicit Open of stdio still works.
// Other fds: routed through the per-task fd table.

// ── Read — arg0=fd, arg1=buf, arg2=len ─────────────────────────────

/// Drain fanotify events and copy their metadata transactionally with respect
/// to object-fd publication. Linux removes the event even when copy_to_user
/// faults, but reserves and installs the embedded fd only after all event data
/// copied successfully; an EFAULT must not leak a reachable descriptor.
fn fanotify_read_to_user(
    task: u64,
    gid: u64,
    max: usize,
    copy: impl FnOnce(&[u8]) -> Result<(), u64>,
) -> Result<usize, u64> {
    let cap = max / crate::mqueue::FAN_EVENT_METADATA_LEN;
    if cap == 0 {
        return Ok(0);
    }
    let events = crate::mqueue::fanotify_drain(gid, cap);
    let mut resolved = alloc::vec::Vec::with_capacity(events.len());
    let mut fd_count = 0usize;
    for (path, mask, pid) in events {
        let ops = fanotify_resolve_object(&path);
        fd_count += usize::from(ops.is_some());
        resolved.push((ops, mask, pid));
    }
    // Reserving the batch is `get_unused_fd_flags` repeated: if the task's
    // RLIMIT_NOFILE cannot cover every object in this drain, the read fails
    // -EMFILE and the queue keeps its events, rather than delivering metadata
    // that names descriptors which were never installed.
    let Some(reserved) = fd::with_table_alloc(task, |table| table.reserve_fds(fd_count)).flatten() else {
        return Err(24); // -EMFILE
    };
    if reserved.len() != fd_count {
        let _ = fd::with_table(task, |table| table.release_reserved(&reserved));
        return Err(EFAULT);
    }
    let mut reserved_iter = reserved.iter().copied();
    let mut installs = alloc::vec::Vec::with_capacity(fd_count);
    let mut staging = alloc::vec::Vec::with_capacity(resolved.len() * crate::mqueue::FAN_EVENT_METADATA_LEN);
    for (ops, mask, pid) in resolved {
        let fd = match ops {
            Some(ops) => {
                let fd = reserved_iter.next().expect("one reservation per resolved fanotify object");
                installs.push((fd, ops));
                fd as i32
            }
            None => -1,
        };
        let meta = crate::mqueue::build_fan_metadata(mask, fd, pid);
        staging.extend_from_slice(&meta);
    }
    if let Err(errno) = copy(&staging) {
        let _ = fd::with_table(task, |table| table.release_reserved(&reserved));
        return Err(errno);
    }
    let installed = fd::with_table(task, |table| {
        let entries = installs
            .into_iter()
            .map(|(fd, ops)| {
                (
                    fd,
                    fd::FdEntry {
                    ops,
                    offset: 0,
                    flags: 0,
                    status_flags: crate::fd::O_RDONLY,
                    },
                )
            })
            .collect();
        table.install_reserved_batch(entries)
    });
    if installed != Some(true) {
        let _ = fd::with_table(task, |table| table.release_reserved(&reserved));
        return Err(EFAULT);
    }
    Ok(staging.len())
}

/// Require every page in a fanotify metadata destination to belong to the
/// active user address space before entering the guarded copy. x86 keeps a
/// supervisor-only low-memory identity map live while user CR3 is active;
/// STAC disables SMAP, so a shape-valid low pointer with no user VMA could
/// otherwise write that supervisor mapping without faulting. Linux's user
/// page tables have no such alias and `copy_to_user` returns EFAULT.
///
/// This check runs from the copy closure, after fanotify selected/removed the
/// event and reserved its embedded fd number, preserving Linux's event
/// consumption ordering. Publication still happens only after the guarded
/// copy succeeds.
fn validate_fanotify_copy_range(ptr: u64, len: usize) -> Result<(), u64> {
    if len == 0 {
        return Ok(());
    }
    validate_user_range(ptr, len)?;
    if let Some(aspace) = current_address_space() {
        let last = ptr + len as u64 - 1;
        let mut page = ptr & !0xfff;
        let last_page = last & !0xfff;
        loop {
            if !aspace.contains_address(VirtAddr::new(page)) {
                return Err(EFAULT);
            }
            if page == last_page {
                return Ok(());
            }
            page += 0x1000;
        }
    }

    // ABI kernel tests have no active user AS and deliberately use kernel
    // scratch buffers under an explicit scope. Preserve that test-only bridge,
    // but never let a lower-half address fall through to x86's identity map.
    #[cfg(feature = "kernel-test")]
    if kernel_buf_scope::active() && !in_user_half(ptr) {
        return Ok(());
    }
    Err(EFAULT)
}

fn fanotify_resolve_object(abs: &str) -> Option<Arc<dyn narf_filesystem::FileOps>> {
    let root_rel = narf_filesystem::registry()
        .resolve_absolute(abs, |fs, rel| (fs.root(), alloc::string::String::from(rel)));
    let (root, rel) = root_rel?;
    poll_blocking(narf_filesystem::resolve_async(root, &rel))?.ok()
}

/// Resolve `abs` and install a fresh read fd for open_by_handle_at.
fn fanotify_open_object(task: u64, abs: &str) -> i32 {
    let Some(ops) = fanotify_resolve_object(abs) else {
        return -1;
    };
    match fd::install(task, fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: crate::fd::O_RDONLY,
        }) {
        Some(n) => n as i32,
        None => -1,
    }
}

// ── File handles: name_to_handle_at / open_by_handle_at ─────────────
//
// Linux file handles are an opaque, FS-defined encoding of a file's
// identity that `open_by_handle_at` later resolves. NARF's Stat carries no
// inode number, so instead of an inode/fid encoding we store the file's
// absolute path directly in `f_handle[]` — a self-contained, stateless
// handle that round-trips through both syscalls. `handle_type` carries a
// NARF marker so a foreign handle is rejected with ESTALE.

const NARF_HANDLE_TYPE: i32 = 0x4e41; // "NA"

// ── Dup family + fcntl ─────────────────────────────────────────────
//
// Stage-4 round 2: the dup'd fd is a *clone* of the source FdEntry —
// `ops` Arc shared, `offset` reset to 0 on the duplicate. Real POSIX
// `dup` shares the open-file description (so reads on either fd
// advance the same offset); NARF's fd table is currently a flat
// `FdEntry`-per-slot rather than the POSIX two-tier (fd → OFD →
// inode) layout. The simplification is sound for Stage-4 callers
// (relibc's `dup` is used to redirect stdio post-fork, not to share
// a cursor) and is documented here so the Stage-5 OFD work can lift
// the offset into a separate Arc without touching the syscall ABI.

// ── fcntl command constants (Linux numbering) ──────────────────────
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_GETLK: u64 = 5;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;
const F_DUPFD_CLOEXEC: u64 = 1030;
/// Linux fcntl `F_ADD_SEALS` (1033) — add seal bits to a memfd.
const F_ADD_SEALS: u64 = 1033;
/// Linux fcntl `F_GET_SEALS` (1034) — read the seal word.
const F_GET_SEALS: u64 = 1034;

/// Linux EAGAIN value (11).
const EAGAIN_CODE: u64 = 11;
/// Linux EPERM (1) — returned as the value of the failed syscall
/// (sign-flipped at libc; we follow the existing -1 convention).
const _EPERM: u64 = 1;

/// Wire-stable `struct flock` (Linux x86_64 / aarch64 layout).
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
struct UFlock {
    l_type: i16,
    l_whence: i16,
    _pad: [u8; 4],
    l_start: i64,
    l_len: i64,
    l_pid: i32,
    _pad2: [u8; 4],
}

fn flock_size() -> usize {
    core::mem::size_of::<UFlock>()
}

/// Clear the current task's F_SETLKW park routing (uctx.flock_key).
/// Every fcntl lock-path exit calls this so a stale key can't make a
/// later unrelated park register on the flock waiter queue.
fn clear_flock_routing() {
    if let Some(u) = crate::user_task::current_user_task() {
        // SAFETY: in-flight task's poller-pinned UserTaskCtx.
        unsafe {
            (*u).flock_key
                .store(0, core::sync::atomic::Ordering::Release);
        }
    }
}

// ── ioctl(2) ───────────────────────────────────────────────────────
//
// Generic ioctl dispatcher. `cmd` is the Linux-shaped `_IOC` encoded
// request word (dir|size|type|nr); `arg` is the raw user-pointer
// argument the caller passed in RDX (on x86_64). Every per-fd
// `FileOps` impl decides which `cmd` values it recognises, validates
// the user pointer with the `copy_from_user` / `copy_to_user`
// helpers, and returns a non-negative i64 on success or
// `FsError::Unsupported` (→ ENOTTY) for an unknown number.
//
// EBADF on closed fd; ENOTTY on a FileOps without an `ioctl` impl
// or on an unrecognised cmd — mirrors Linux's `do_vfs_ioctl`.

/// Linux ENOTTY value (25 — "inappropriate ioctl for device").
const ENOTTY: u64 = 25;
/// Linux EBADF value (9).
const EBADF: u64 = 9;

// ── Stat / Fstat ───────────────────────────────────────────────────
//
// `StatBuf` is the kernel-user wire-stable shape NARF surfaces today.
// It mirrors `narf_filesystem::Stat` minus the `Mode` enum (collapsed
// to a `u32` so the user side doesn't need to import `narf_filesystem`
// to read the result). This is *not* POSIX `struct stat`; the relibc
// shim translates as needed when a real POSIX `stat()` lands.

/// Wire-stable stat output. `mode` carries the FileType in the high
/// bits (POSIX-shaped: `0o100000` = file, `0o040000` = dir) and the
/// 9 perm bits in the low end, giving a consumer one word that
/// reads like a POSIX `st_mode`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StatBuf {
    pub size: u64,
    pub blocks: u64,
    pub mode: u32,
    pub _pad: u32,
    pub mtime_cycles: u64,
}

// ── Ftruncate — arg0=fd, arg1=len ──────────────────────────────────
//
// Resize the file backing `fd` to exactly `len` bytes. Routes
// through `FileOps::truncate` — read-only filesystems return
// `Unsupported`, which we surface as the wire `-1` sentinel.

// ── Pread / Pwrite — positional I/O without per-fd offset ─────────
//
// FileOps::read / write already take an offset arg; the regular
// sys_read / sys_write handlers walk through the per-fd cursor on
// top. pread / pwrite skip the cursor mutation — POSIX guarantees
// the per-fd offset is unchanged after these calls.

// ── Fallocate — preallocate file space ─────────────────────────────
//
// Linux fallocate(2) modes we honour:
//   - 0 (default)              : ensure file is >= offset + len.
//   - FALLOC_FL_ZERO_RANGE 0x10: zero the given range; extend
//                                the file if it ends before
//                                offset + len.
// Other modes (KEEP_SIZE, PUNCH_HOLE, COLLAPSE_RANGE, ...) are
// rejected — MemFs has no hole-tracking and the validate harness
// doesn't exercise them.

const FALLOC_FL_ZERO_RANGE: u64 = 0x10;

// ── CopyFileRange — chunked file→file copy ─────────────────────────
//
// Linux copy_file_range(2): in-kernel copy without bouncing the
// data through user memory. Real consumers (cp, rsync, GNU cat,
// container runtimes) prefer this over the read/write loop. NARF's
// MemFs has no special "copy without unmapping pages" path; we just
// read into a stack chunk and write it out.
//
// ABI (Linux, x86_64):
//   copy_file_range(int fd_in, loff_t *off_in,
//                   int fd_out, loff_t *off_out,
//                   size_t len, unsigned int flags)
// The offsets are POINTERS. NULL means "start at this fd's file
// offset and advance it by the copied count"; a non-NULL pointer
// means "start at *off, write back *off + copied, and leave the fd
// cursor alone". Getting this wrong is not subtle: glibc's `cat`
// issues `copy_file_range(3, NULL, 1, NULL, huge, 0)`, and reading
// the args in the old NARF-native `(fd_in, fd_out, off_in, off_out)`
// order decoded that as "read fd 3 from offset 1, write to fd 0",
// which dropped the first byte, sent the copy to stdin's device, and
// never advanced either offset — so `cat` looped forever.

// ── Truncate — path-based file resize ──────────────────────────────
//
// Linux truncate(2). Equivalent to open + ftruncate + close in one
// syscall. Resolves the absolute path to a FileOps and calls
// `truncate(len)` directly — no fd-table involvement. Routes to the
// same trait method that backs SYS_FTRUNCATE.

// ── unlinkat / mkdirat / renameat — *at-keyed FS mutation ─────────
//
// Each ignores dirfd, requires absolute paths, and routes through
// the existing SYS_UNLINK / SYS_RMDIR / SYS_MKDIR / SYS_RENAME
// handler bodies via the same Reshape proxy pattern as openat.
//
// unlinkat honours AT_REMOVEDIR (0x200) — when set, route to rmdir.

const AT_REMOVEDIR: u64 = 0x200;

/// Shared node-creation used by both `mknod` and `mknodat`. `S_IFDIR` creates
/// a directory; `S_IFCHR`/`S_IFBLK` create a device node via the directory's
/// `mknod` (devfs materialises a real char/block special with `st_rdev == dev`
/// — the udev-coldplug `/dev/<name>` path), falling back to a regular file on
/// filesystems without device-node support; everything else is a regular file
/// (see `sys_mknodat` docs). Never returns a bare -1 for a supported node type.
fn mknod_common(raw_path: &str, mode: u64, dev: u64) -> SyscallReturn {
    const S_IFMT: u64 = 0o170000;
    const S_IFCHR: u64 = 0o020000;
    const S_IFBLK: u64 = 0o060000;
    const S_IFIFO: u64 = 0o010000;
    // `fs/namei.c::may_mknod` screens the node type BEFORE `filename_create`
    // looks the path up, so a mode mknod cannot create outranks a bad path:
    //
    //     case S_IFREG: case S_IFCHR: case S_IFBLK:
    //     case S_IFIFO: case S_IFSOCK: case 0:  return 0;
    //     case S_IFDIR:                         return -EPERM;
    //     default:                              return -EINVAL;
    //
    // A directory is EPERM — mkdir(2) is the only way to make one, and glibc
    // relies on that to decide whether to fall back. NARF used to accept
    // S_IFDIR here and create the directory, which is a NARF-only extension
    // no portable caller can use, and reported every other malformed mode as
    // the `-1` sentinel (EPERM) — colliding with the one mode that really is
    // EPERM and hiding the EINVAL that says "this node type does not exist".
    {
        const S_IFREG: u64 = 0o100000;
        const S_IFCHR_M: u64 = 0o020000;
        const S_IFBLK_M: u64 = 0o060000;
        const S_IFIFO_M: u64 = 0o010000;
        const S_IFSOCK: u64 = 0o140000;
        const S_IFDIR_M: u64 = 0o040000;
        match mode & S_IFMT {
            0 | S_IFREG | S_IFCHR_M | S_IFBLK_M | S_IFIFO_M | S_IFSOCK => {}
            S_IFDIR_M => return SyscallReturn::ok((-1i64) as u64), // -EPERM
            _ => return SyscallReturn::ok((-22i64) as u64),        // -EINVAL
        }
    }
    // `raw_path` is already the caller's path string; `sys_mknodat` has
    // applied its dirfd so a relative path is resolved against the dirfd's
    // directory, not the cwd. `resolve_cwd_path` then only normalises a
    // cwd-relative `mknod(2)` path (absolute inputs pass through unchanged).
    let path = resolve_cwd_path(current_task_id(), raw_path);
    let path_ref = {
        let t = path.trim_end_matches('/');
        if t.is_empty() {
            // No LOOKUP_EMPTY on this path, so `getname()` rejects "" with
            // -ENOENT rather than the sentinel's EPERM.
            return SyscallReturn::ok((-2i64) as u64);
        }
        t
    };
    let (parent, leaf) = match resolve_parent_dir_async(path_ref) {
        Some(p) => p,
        None => {
            return SyscallReturn::ok((-2i64) as u64); // -ENOENT
        }
    };
    if let Err(errno) = mnt_want_write(path_ref) {
        return SyscallReturn::ok(errno as u64);
    }
    // `do_mknodat` -> `filename_create` -> `may_create(dir, ..)`: write+exec
    // on the directory gaining the node. CAP_MKNOD for a device node is a
    // separate gate (`may_mknod` above screened the TYPE, not the
    // privilege) and is not modelled here.
    if let Err(errno) = may_create_in(&*parent, current_task_id()) {
        return SyscallReturn::ok(errno as u64);
    }
    let fmt = mode & S_IFMT;
    // `vfs_mknod`:
    //
    //     if ((S_ISCHR(mode) || S_ISBLK(mode)) && !is_whiteout &&
    //         !capable(CAP_MKNOD))
    //             return -EPERM;
    //
    // A device node is a direct handle on a driver, so creating one is a
    // privileged act however permissive the directory is: an unprivileged
    // task that could mknod its own `/dev/sda` would read the disk past
    // every file permission on it. FIFOs and sockets are NOT covered —
    // they carry no such authority, which is why the check names only the
    // two device types.
    if (fmt == S_IFCHR || fmt == S_IFBLK) && !capable(CAP_MKNOD) {
        return SyscallReturn::ok((-1i64) as u64); // -EPERM
    }
    // Already exists → -EEXIST (Linux mknod semantics).
    if let Some(Ok(entry)) = poll_blocking(parent.lookup_async(&leaf)) {
        if (fmt == S_IFIFO || fmt == S_IFCHR || fmt == S_IFBLK)
            && entry.stat().mode.file_type == narf_filesystem::FileType::File
            && entry.stat().size == 0
        {
            let _ = poll_blocking(parent.unlink(&leaf));
        } else {
            return SyscallReturn::ok((-17i64) as u64); // -EEXIST
        }
    }
    // S_IFDIR never reaches here: `may_mknod` rejected it with -EPERM above,
    // as Linux does. mkdir(2) is the only way to create a directory.
    // The created node handle, so the requested mode can be persisted below.
    let node: Option<Arc<dyn narf_filesystem::FileOps>> = if fmt == S_IFCHR || fmt == S_IFBLK {
        // A char/block device node (udev coldplug creating /dev/<name>). Route
        // to the directory's `mknod` so a devfs parent materialises a node that
        // stats as the right special device with st_rdev == dev. Filesystems
        // that don't support device nodes fall back to a plain file so the node
        // at least EXISTS (matching the old behaviour for the elogind sandbox
        // nodes). `dev` is the Linux dev_t as passed by userspace.
        let file_type = if fmt == S_IFBLK {
            narf_filesystem::FileType::Block
        } else {
            narf_filesystem::FileType::Special
        };
        match poll_blocking(parent.mknod(&leaf, file_type, dev)) {
            Some(Ok(n)) => Some(n),
            _ => poll_blocking(parent.create(&leaf)).and_then(|r| r.ok()),
        }
    } else if fmt == S_IFIFO {
        // A named pipe (musl `mkfifo` → `mknodat(S_IFIFO|mode, 0)`). Route to
        // the directory's `mknod` so a tmpfs parent (`/run`, `/tmp`) creates a
        // real FIFO inode whose later `open()` connects to a shared pipe
        // buffer keyed by the node identity — NOT a plain file. No device-node
        // fallback: a FIFO on a filesystem without FIFO support is a hard
        // failure, not a degraded regular file.
        poll_blocking(parent.mknod(&leaf, narf_filesystem::FileType::Fifo, 0)).and_then(|r| r.ok())
    } else {
        poll_blocking(parent.create(&leaf)).and_then(|r| r.ok())
    };
    match node {
        Some(n) => {
            // Linux mknod(2)/mkfifo(3): the new node is owned by the creating
            // task's filesystem uid/gid and carries the permission bits from
            // `mode` (the caller already folded in its umask). Persist both so
            // a later stat reports them — systemd's `fifo_address_create()`
            // rejects `/run/initctl` unless the FIFO is BOTH owned by the
            // caller (`st_uid == getuid()`) AND has the exact `socket_mode`
            // (`st_mode & 0777 == 0600`) it created it with; and the DAC open
            // check needs the owner set so the non-root creator can reopen its
            // own 0600 pipe.
            // `shmem_mknod` -> `shmem_get_inode` -> `inode_init_owner`: a
            // setgid parent hands down its group. A device node or FIFO in
            // a shared group directory has to land in that group like
            // anything else.
            let inherited = inherit_acls_from_parent(&*parent, (mode & 0o7777) as u16, false);
            let _ = poll_blocking(n.set_owners(inherited.uid, inherited.gid));
            let _ = poll_blocking(n.set_perms(inherited.mode));
            if let Some(blob) = inherited.access.as_ref() {
                let _ = poll_blocking(n.set_xattr(
                    narf_filesystem::AclType::Access.xattr_name(),
                    blob,
                    0,
                ));
            }
            SyscallReturn::ok(0)
        }
        // The parent resolved and the type is one mknod can make, so a failure
        // to create the node is the filesystem's own — `vfs_mknod` surfaces
        // that rather than a blanket error. The sentinel reached userspace as
        // EPERM, colliding with the one genuine EPERM this syscall has
        // (S_IFDIR, screened above).
        None => SyscallReturn::ok((-5i64) as u64), // -EIO
    }
}

/// Materialise the S_IFSOCK filesystem node for a pathname AF_UNIX
/// `bind()` (Linux creates a real socket inode at the path). Best-effort:
/// abstract-namespace sockets (leading NUL) get no node, and a filesystem
/// that can't hold a socket inode just leaves the path invisible — bind
/// still succeeds either way (connection routing is the LISTENERS
/// registry, independent of this node). Makes `stat`/`[ -S ]`/`ls`/
/// `unlink`/`chmod` on the bound path behave like Linux — wayland, dbus,
/// and shells all probe the socket path this way.
pub(crate) fn create_unix_socket_node(path: &str) {
    // Abstract namespace (sun_path[0] == '\0') has no filesystem presence.
    if path.is_empty() || path.starts_with('\0') {
        return;
    }
    let abs = resolve_cwd_path(current_task_id(), path);
    let path_ref = abs.trim_end_matches('/');
    if path_ref.is_empty() {
        return;
    }
    if let Some((parent, leaf)) = resolve_parent_dir_async(path_ref) {
        // 0o755: the socket node's mode; apps chmod it afterwards. If a
        // stale node already occupies the name the app should have
        // unlink'd it first — ignore the collision (bind already vetted
        // the address via LISTENERS).
        let _ = poll_blocking(parent.create_socket(&leaf, 0o755));
    }
}

// ── symlinkat / readlinkat — *at-keyed symlink ops ─────────────────
//
// Both forward via Reshape proxies. dirfd ignored; path args are
// absolute. The symlink handler reads (target_ptr, target_len,
// link_ptr, link_len) from arg0..=arg3; readlink reads
// (path_ptr, path_len, buf_ptr, buf_len) from arg0..=arg3.

// ── access / chmod / chown — legacy entry points ───────────────────
//
// Linux access(path, mode), chmod(path, mode), chown(path, uid, gid)
// — pre-*at calls that take a relative-or-absolute path with no
// directory fd. NARF treats them as faccessat / fchmodat / fchownat
// with `dirfd = AT_FDCWD` and forwards into the shared
// `sys_fchmodat_or_fchownat` body, which already enforces the
// "path must be absolute, mode/uid/gid bits ignored" contract.

// ── newfstatat — *at-keyed stat ────────────────────────────────────
//
// Linux newfstatat(dirfd, path, statbuf, flags). Same dirfd-
// ignored / path-must-be-absolute simplification. Re-shape args
// to the SYS_STAT signature (path_ptr, path_len, stat_out) and
// reuse sys_stat's body.

// ── statx — Linux statx(2) wire-shape ─────────────────────────────
//
// statx(dirfd, path, flags, mask, statxbuf). 256-byte struct with
// 64-bit ns-precision timestamps and a request mask. The mask is
// advisory — Linux fills more than asked when cheap, fills less
// when the field isn't available, and reports what was filled in
// `stx_mask`. NARF's filesystem layer only carries size/blocks/
// mode/mtime_cycles, so we fill those plus type/ino, and set
// `stx_mask` to STATX_BASIC_STATS minus the fields we cannot
// produce (atime/ctime/uid/gid/nlink).
//
// Gated behind `linux-compat` so a NARF-only userspace doesn't
// pay the size cost of the layout assertion or pull in the
// Linux-shaped constants.

pub mod linux_compat {
    //! Linux x86_64 ABI shapes for stat / statx. Layout-checked
    //! against the upstream uapi at compile time via const asserts.

    use core::mem::{align_of, size_of};

    // ── stat (Linux x86_64) — 144 bytes ──────────────────────────
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default)]
    pub struct Timespec {
        pub tv_sec: i64,
        pub tv_nsec: i64,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default)]
    pub struct Stat {
        pub st_dev: u64,
        pub st_ino: u64,
        pub st_nlink: u64,
        pub st_mode: u32,
        pub st_uid: u32,
        pub st_gid: u32,
        pub __pad0: u32,
        pub st_rdev: u64,
        pub st_size: i64,
        pub st_blksize: i64,
        pub st_blocks: i64,
        pub st_atim: Timespec,
        pub st_mtim: Timespec,
        pub st_ctim: Timespec,
        pub __unused: [i64; 3],
    }

    const _: () = assert!(size_of::<Stat>() == 144);
    const _: () = assert!(align_of::<Stat>() == 8);

    // ── statx (kernel uapi) — 256 bytes ──────────────────────────
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default)]
    pub struct StatxTimestamp {
        pub tv_sec: i64,
        pub tv_nsec: u32,
        pub __reserved: i32,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default)]
    pub struct Statx {
        pub stx_mask: u32,
        pub stx_blksize: u32,
        pub stx_attributes: u64,
        pub stx_nlink: u32,
        pub stx_uid: u32,
        pub stx_gid: u32,
        pub stx_mode: u16,
        pub __spare0: [u16; 1],
        pub stx_ino: u64,
        pub stx_size: u64,
        pub stx_blocks: u64,
        pub stx_attributes_mask: u64,
        pub stx_atime: StatxTimestamp,
        pub stx_btime: StatxTimestamp,
        pub stx_ctime: StatxTimestamp,
        pub stx_mtime: StatxTimestamp,
        pub stx_rdev_major: u32,
        pub stx_rdev_minor: u32,
        pub stx_dev_major: u32,
        pub stx_dev_minor: u32,
        pub stx_mnt_id: u64,
        pub stx_dio_mem_align: u32,
        pub stx_dio_offset_align: u32,
        pub __spare3: [u64; 12],
    }

    const _: () = assert!(size_of::<Statx>() == 256);
    const _: () = assert!(align_of::<Statx>() == 8);

    // ── Mask bits (linux/stat.h) ─────────────────────────────────
    pub const STATX_TYPE: u32 = 0x0001;
    pub const STATX_MODE: u32 = 0x0002;
    pub const STATX_NLINK: u32 = 0x0004;
    pub const STATX_UID: u32 = 0x0008;
    pub const STATX_GID: u32 = 0x0010;
    pub const STATX_ATIME: u32 = 0x0020;
    pub const STATX_MTIME: u32 = 0x0040;
    pub const STATX_CTIME: u32 = 0x0080;
    pub const STATX_INO: u32 = 0x0100;
    pub const STATX_SIZE: u32 = 0x0200;
    pub const STATX_BLOCKS: u32 = 0x0400;
    pub const STATX_BASIC_STATS: u32 = 0x07ff;
    pub const STATX_BTIME: u32 = 0x0800;
    pub const STATX_MNT_ID: u32 = 0x1000;

    // Linux 6.6+ uses this attribute for the cheap mount-point probe that
    // systemd runs before attempting to mount its API filesystems.
    pub const STATX_ATTR_MOUNT_ROOT: u64 = 0x0000_2000;

    // ── Flag bits (fcntl.h AT_*) ─────────────────────────────────
    pub const AT_FDCWD: i32 = -100;
    pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
    pub const AT_NO_AUTOMOUNT: u32 = 0x800;
    pub const AT_EMPTY_PATH: u32 = 0x1000;
    pub const AT_STATX_SYNC_TYPE: u32 = 0x6000;
}

// Build a Linux-shaped struct stat from a `narf_filesystem::Stat` plus the
// fields it does not carry (`narf_filesystem::InodeAttrs`).
//
// `attrs` is `Default` for a filesystem that models none of them, and each
// field then falls back to what this reported before the attrs existed:
// `st_nlink = 1`, `st_dev = 0`, and mtime standing in for atime and ctime.
fn linux_stat_from_fs(
    s: narf_filesystem::Stat,
    uid: u32,
    gid: u32,
    rdev: u64,
    ino: u64,
    attrs: narf_filesystem::InodeAttrs,
) -> linux_compat::Stat {
    let ftype_bits: u32 = match s.mode.file_type {
        narf_filesystem::FileType::File => 0o100000,
        narf_filesystem::FileType::Dir => 0o040000,
        narf_filesystem::FileType::Symlink => 0o120000,
        narf_filesystem::FileType::Special => 0o020000,
        narf_filesystem::FileType::Block => 0o060000,
        narf_filesystem::FileType::Socket => 0o140000,
        narf_filesystem::FileType::Fifo => 0o010000,
    };
    let mode_word: u32 = ftype_bits | (s.mode.perms as u32 & 0o7777);
    let mtime_ns = narf_time::cycles_to_ns(s.mtime_cycles);
    let timespec = |ns: u64| linux_compat::Timespec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    };
    let mtime = timespec(mtime_ns);
    // A filesystem that tracks atime/ctime separately gets them reported
    // separately: `chmod` must move ctime without moving mtime, or `tar`,
    // `rsync` and incremental-backup tooling cannot tell a re-permissioned
    // file from a rewritten one.
    let atime = timespec(if attrs.atime_ns != 0 {
        attrs.atime_ns
    } else {
        mtime_ns
    });
    let ctime = timespec(if attrs.ctime_ns != 0 {
        attrs.ctime_ns
    } else {
        mtime_ns
    });
    linux_compat::Stat {
        st_dev: attrs.dev,
        // Prefer the filesystem's real inode (distinct per file). Only fall
        // back to the size/mtime hash for synthetic filesystems that report
        // no inode (ino == 0) — and never for disk files, whose same-size
        // libraries would otherwise alias and break musl's DSO dedup.
        st_ino: if ino != 0 {
            ino
        } else {
            (s.mtime_cycles ^ (s.size << 1)) & 0x0fff_ffff_ffff_ffff
        },
        // `tracked` and not `nlink != 0` is the test on purpose: an
        // `O_TMPFILE` inode really does have zero links until `linkat`
        // gives it a name, and that zero is how userspace tells an
        // unlinked temporary from a named file.
        st_nlink: if attrs.tracked { attrs.nlink as u64 } else { 1 },
        st_mode: mode_word,
        st_uid: uid,
        st_gid: gid,
        __pad0: 0,
        st_rdev: rdev,
        st_size: s.size as i64,
        st_blksize: 4096,
        st_blocks: s.blocks as i64,
        st_atim: atime,
        st_mtim: mtime,
        st_ctim: ctime,
        __unused: [0; 3],
    }
}

// Linux-ABI sys_stat: writes a 144-byte `struct stat`. Same path-
// resolution as the NARF-shape sys_stat, only the wire layout
// changes.

/// Shared body for the Linux path-stat family. `follow_final` selects
/// whether a trailing symlink is followed (plain `stat`/`fstatat`) or
/// stat'd as the link itself (`lstat` / `fstatat(AT_SYMLINK_NOFOLLOW)`).
fn stat_linux_common(ctx: &mut dyn TrapContext, path_ptr: u64, out_arg: u64, follow_final: bool) {
    // The previous shape matched NARF's `(path_ptr, path_len, out_ptr)`
    // triplet which is unreachable from musl: musl passes the statbuf in
    // arg1, we read it as `path_len`, copy_from_user bails on the "huge
    // length", every stat returns -1, errno = EPERM, busybox sh prints
    // "Operation not permitted" for every PATH-search candidate, and
    // every pipeline that touches an exec dies.
    // NOTE the ORDER. `SYSCALL_DEFINE2(newstat)` is
    //
    //     error = vfs_stat(filename, &stat);
    //     if (unlikely(error)) return error;
    //     return cp_new_stat(&stat, statbuf);
    //
    // so the pathname is copied and RESOLVED before `statbuf` is touched at
    // all. Checking the output pointer first — which this did — reported
    // -EFAULT for `stat("/does/not/exist", NULL)` where Linux reports
    // -ENOENT, and hid every path error behind the destination check. The
    // null test now lives in `stat_linux_path`, after resolution.
    // `getname()`: -EFAULT for an unreadable pointer, -ENAMETOOLONG for a
    // path that reaches PATH_MAX with no terminator. Folding both into
    // -EFAULT told a caller its POINTER was bad when the pointer was fine.
    let raw = match copy_user_cstr_checked(path_ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    stat_linux_path(ctx, &raw, out_arg, follow_final);
}

/// Write a Linux `struct stat` for a path in the caller's visible namespace.
/// `raw` may be absolute or relative to the caller's cwd; callers of
/// `newfstatat(2)` first join its relative pathname to the supplied dirfd.
fn stat_linux_path(ctx: &mut dyn TrapContext, raw: &str, out_arg: u64, follow_final: bool) {
    let out_ptr = out_arg as *mut linux_compat::Stat;
    // Resolve relative paths (e.g. `ls`'s `lstat(".")`) against the
    // caller's cwd before chroot, so the stat family works from any
    // working directory — not just absolute paths.
    // resolve_cwd_path already re-roots under the task's chroot — do
    // not apply_chroot again or the prefix is composed twice.
    let path_owned = resolve_cwd_path(current_task_id(), raw);
    let _ = (); // silence unused-binding lint when both arms drop the value
    let path: &str = &path_owned;
    // `resolve_absolute` splits an absolute path into (mount, rel).
    // For a path that IS the mount point itself (`/bin`, `/dev`,
    // `/tmp`, …) rel is empty and `resolve(_, "")` rejects with
    // InvalidPath. busybox `ls /bin` lands here, so synthesise a
    // directory-shaped stat for the mount root.
    let (s, ino, rdev, uid, gid, attrs) = match stat_ino_path_dir_aware_ext(path, follow_final) {
        Some(tuple) => tuple,
        None => {
            // Missing file → ENOENT, not the bare -1 (musl → EPERM). Probes
            // like libwayland's wl_socket_lock require the real errno.
            //
            // `filename_lookup` also yields -ENOTDIR when a NON-FINAL
            // component is not a directory, which is a different answer for
            // the caller: ENOENT invites it to create the path, ENOTDIR says
            // a prefix is a file and creating it never will work. The
            // resolver reports no reason, so the walk is re-classified on
            // this failure path — see `path_lookup_errno`.
            ctx.set_return(SyscallReturn::ok((-path_lookup_errno(path)) as u64));
            return;
        }
    };
    // `cp_new_stat(&stat, statbuf)` — the destination is inspected only now
    // that the path has resolved, so a bad path outranks a bad statbuf.
    if out_ptr.is_null() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // Report the device node's rdev (major:minor) for PATH stat too: seatd /
    // libudev validate a device's type from a path stat before opening it, so
    // a 0 rdev makes them reject evdev nodes (weston input never opens).
    let out = linux_stat_from_fs(s, uid, gid, rdev, ino, attrs);
    // SAFETY: `out` is a live repr(C) Stat; the slice spans exactly its size
    // and borrows it for the duration of the copy below.
    // SAFETY: Valid memory or trusted environment
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &out as *const linux_compat::Stat as *const u8,
            core::mem::size_of::<linux_compat::Stat>(),
        )
    };
    // SAFETY: `out_ptr` is the user Stat pointer (null-checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// newfstatat under linux-compat: reshape args then delegate.

// ── openat — *at-keyed open ────────────────────────────────────────
//
// Linux openat(dirfd, path, flags, mode) — modern replacement for
// open. dirfd is ignored (NARF has no directory-fd type); path
// must be absolute. The body re-shapes args into the SYS_OPEN
// signature (path_ptr, path_len, mount_ptr=0, mount_len=0, flags)
// and routes through the existing sys_open handler so the open
// path is identical.

// ── fchmodat / fchownat — *at-keyed mode/owner ─────────────────────
//
// NARF doesn't support directory fds, so the dirfd arg is
// ignored. Path must be absolute; if it resolves we report
// success (mode/uid/gid bits are structural-only state we don't
// enforce). Relative paths are rejected with -1 to keep the
// consumer's error-checking honest.

// ── fchmod / fchown — accept-and-ignore on known fd ───────────────
//
// NARF has no per-file permission bits or owner; the kernel
// surface exists so consumers (tar, cp, install) can round-trip
// the values without breaking. Both succeed for any open fd, fail
// (-1) for a closed/unknown fd.

// ── memfd_create — anonymous in-memory file ────────────────────────
//
// Linux memfd_create(2): mint a fresh in-memory file backed by a
// fresh (no directory entry) MemFile, install it in the caller's
// fd table, return the fd. The name is recorded for debug-only
// introspection; we don't preserve it in NARF today (no
// /proc-style listing). Real consumers (sandboxes, IPC, tmpfile)
// rely on the surface alone.

// ── Wave-70 MemFdFile side table ───────────────────────────────────
static MEMFD_ARCS: ArcShardTable<crate::linux_compat::MemFdFile> =
    [const { ArcShard::new() }; ARC_SHARDS];

fn memfd_arc_register(arc: &alloc::sync::Arc<crate::linux_compat::MemFdFile>) {
    arc_shard_register(&MEMFD_ARCS, arc);
}

pub(crate) fn memfd_arc_from_fd(
    task: u64,
    fd: u32,
) -> Option<alloc::sync::Arc<crate::linux_compat::MemFdFile>> {
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    arc_shard_get(&MEMFD_ARCS, raw)
}

// ── Fsync / Fdatasync — flush stubs ────────────────────────────────
//
// NARF's filesystems are in-memory; there's nothing to flush. We
// surface success for any open fd so consumer code that error-
// checks fsync sees a sane return, and -1 for an unknown fd so
// the contract still distinguishes "valid handle" from "stale".

// ── Pipe ────────────────────────────────────────────────────────────
//
// Allocates a fresh `PipeRead`/`PipeWrite` pair, installs them into
// the calling task's fd table at the next two free slots, then
// writes the two i32 fds back to the user-supplied output pointer
// in `[read, write]` order (matching POSIX `int pipefd[2]`).

// ── Pipe2 — pipe + atomic flag set ─────────────────────────────────
//
// Linux pipe2(2): same as pipe but the second arg sets per-fd
// flags atomically with the install. We honour O_CLOEXEC by
// stamping FD_CLOEXEC on both halves; O_NONBLOCK is accepted and
// ignored (NARF pipe reads short-return on empty already, no
// blocking model to toggle).

const O_CLOEXEC_BIT: u64 = 0x80000;

// ── Lseek — arg0=fd, arg1=offset(i64), arg2=whence ─────────────────
//
// Updates the per-fd offset and returns the new value. SEEK_CUR /
// SEEK_END are computed against the current offset / current size
// reported by the FileOps `stat()`. Negative resulting offsets are
// rejected with `InvalidOp` so callers don't get a wraparound u64.

const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const SEEK_END: u64 = 2;

// ── Unlink — arg0=path_ptr, arg1=path_len ──────────────────────────
//
// Splits the absolute path at the last `/`, walks the parent dir via
// the VFS registry, and dispatches to that DirOps's `unlink(leaf)`.
// FSes that haven't overridden the trait default surface
// `FsError::Unsupported`, which we translate to `InvalidOp` on the
// wire (no errno channel today).

/// Map an `FsError` from a delete-family op to the errno `unlink(2)` reports.
///
/// The arms come from `fs/namei.c::vfs_unlink` and the `may_delete_dentry`
/// it opens with. Everything the latter rejects has its own errno, and the
/// filesystem's own `->unlink` supplies the rest — btrfs starts a transaction
/// to unlink, so ENOSPC and EDQUOT are ordinary answers there, not exotic
/// ones.
///
/// The catch-all stays EPERM because that is what `vfs_unlink` returns for
/// the conditions it names last (a swapfile, a filesystem with no `->unlink`),
/// but it is now a genuine default rather than somewhere unmapped errors go
/// to be flattened. Every arm below used to land on it, which told a caller
/// "you may not do this" when the truth was a full disk, a failing device, or
/// a directory it lacked write permission on.
fn unlink_errno(e: narf_filesystem::FsError) -> u64 {
    use narf_filesystem::FsError;
    let code: i64 = match e {
        FsError::NotFound => -2,     // -ENOENT  may_delete_dentry: d_is_negative
        FsError::InvalidPath => -21, // -EISDIR  may_delete_dentry: d_is_dir(victim)
        // `inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC)`, whose two
        // failures are these: sb_permission gives EROFS, the mode check EACCES.
        FsError::ReadOnly => -30,         // -EROFS
        FsError::PermissionDenied => -13, // -EACCES
        // may_delete_dentry: IS_APPEND / check_sticky / IS_IMMUTABLE.
        FsError::OperationNotPermitted => -1, // -EPERM
        FsError::Busy => -16,                 // -EBUSY   is_local_mountpoint
        FsError::SymlinkLoop => -40,          // -ELOOP   path walk
        // From `dir->i_op->unlink` itself.
        FsError::NoSpace => -28,        // -ENOSPC
        FsError::QuotaExceeded => -122, // -EDQUOT
        FsError::Io(_) => -5,           // -EIO
        _ => -1,                        // -EPERM  `if (!dir->i_op->unlink)`
    };
    code as u64
}

/// Map an `FsError` from `DirOps::rmdir` to the Linux errno userspace
/// expects. `NotFound` → ENOENT (no such name), `Busy` → ENOTEMPTY (the
/// directory still has children — MemFs flags a non-empty rmdir this way),
/// `InvalidPath` → ENOTDIR (the target is a file/symlink, not a dir),
/// `ReadOnly` → EROFS, `Unsupported` → EPERM. Never a bare -1 → systemd's
/// mount-teardown does `rmdir("/run/systemd/propagate/<unit>")` and treats
/// ENOENT (already gone) as success; a bare -1 → EPERM aborted the teardown
/// with "Unable to remove propagation dir … Operation not permitted".
/// Map an `FsError` from a bind mount to the errno `do_loopback`
/// (fs/namespace.c) would report.
///
/// `kern_path` on an unresolvable source is -ENOENT; everything else
/// do_loopback rejects — a namespace loop, a source outside the caller's
/// namespace — falls through its `err = -EINVAL` default. A revoked mount
/// authority has no Linux counterpart (the capability is TCB-minted, not
/// something a caller holds), so it takes -EPERM, which is what
/// `may_mount()` failing reports.
fn bind_errno(e: narf_filesystem::FsError) -> u64 {
    use narf_filesystem::FsError;
    let code: i64 = match e {
        // `kern_path(old_name, ...)` could not resolve the source.
        FsError::NotFound => -2, // -ENOENT
        FsError::PermissionDenied => -1, // -EPERM
        FsError::ReadOnly => -30, // -EROFS
        FsError::Busy => -16,    // -EBUSY
        // do_loopback's `err = -EINVAL` default: a source that resolves but
        // may not be bound.
        _ => -22, // -EINVAL
    };
    code as u64
}

/// Map an `FsError` from `rmdir(2)`, per `fs/namei.c::vfs_rmdir` and the
/// `may_delete_dentry(..., isdir = true)` it opens with.
fn rmdir_errno(e: narf_filesystem::FsError) -> u64 {
    use narf_filesystem::FsError;
    let code: i64 = match e {
        FsError::NotFound => -2, // -ENOENT
        // ENOTEMPTY rather than the EBUSY `vfs_rmdir` uses for a mountpoint:
        // NARF's directory backends signal a non-empty victim as `Busy`, and
        // that is overwhelmingly the case a caller of rmdir is in. The
        // mountpoint case is caught before the filesystem is reached.
        FsError::Busy => -39,        // -ENOTEMPTY  from ->rmdir
        FsError::InvalidPath => -20, // -ENOTDIR    may_delete_dentry: !d_is_dir
        FsError::ReadOnly => -30,    // -EROFS      inode_permission
        FsError::PermissionDenied => -13, // -EACCES     inode_permission
        FsError::OperationNotPermitted => -1, // -EPERM      sticky / immutable
        FsError::NoSpace => -28,              // -ENOSPC     from ->rmdir
        FsError::QuotaExceeded => -122,       // -EDQUOT     ditto
        FsError::Io(_) => -5,                 // -EIO
        FsError::Unsupported => -1,           // -EPERM      `if (!dir->i_op->rmdir)`
        _ => -1,                              // -EPERM
    };
    code as u64
}

/// Map an `FsError` from `DirOps::rename` to the Linux errno userspace
/// expects. `NotFound` → ENOENT (source is gone), `Busy` → EEXIST,
/// `InvalidPath` → EINVAL, `CrossDevice` → EXDEV, `ReadOnly` → EROFS,
/// everything else → EPERM.
/// Never a bare -1 → systemd renames propagation dirs during mount
/// teardown and a spurious EPERM there aborts the whole unit.
fn rename_errno(e: narf_filesystem::FsError) -> u64 {
    use narf_filesystem::FsError;
    let code: i64 = match e {
        FsError::NotFound => -2,        // -ENOENT
        FsError::Busy => -17,           // -EEXIST
        FsError::InvalidPath => -22,    // -EINVAL
        FsError::CrossDevice => -18,    // -EXDEV
        FsError::ReadOnly => -30,       // -EROFS   inode_permission
        FsError::QuotaExceeded => -122, // -EDQUOT
        // `vfs_rename` reaches both `may_delete_dentry` and
        // `may_create_dentry`, so the same inode_permission failures apply,
        // and the filesystem's own ->rename supplies the rest.
        FsError::PermissionDenied => -13, // -EACCES
        FsError::OperationNotPermitted => -1, // -EPERM
        FsError::SymlinkLoop => -40,          // -ELOOP
        FsError::NoSpace => -28,              // -ENOSPC
        FsError::Io(_) => -5,                 // -EIO
        _ => -1,
    };
    code as u64
}

// ── Mkdir / Rmdir / Rename — Tier-3b directory mutation ────────────
//
// All three follow the unlink shape: resolve the parent through the
// VFS registry, dispatch to the relevant `DirOps` method, return
// POSIX-style 0 / -1. Mode argument on mkdir is accepted and ignored
// — NARF doesn't model POSIX permission bits at the FS layer.

/// Resolve the parent directory of an absolute path to a `DirOps`,
/// driving the ASYNC resolver. The sync `resolve_parent_absolute` walks
/// via `lookup_dir`, which disk-backed filesystems (ext2) stub because
/// block reads can't run synchronously — so creating a file or directory
/// under a subdirectory of a mounted ext2 rootfs (e.g. udevd's
/// `mkdir("/run/udev")`) resolved no parent and returned a bare -1 →
/// musl EPERM. Same fix shape as the stat-async path. Returns
/// `(parent_dir, leaf_name)`.
pub(crate) fn resolve_parent_dir_async(
    abs: &str,
) -> Option<(
    alloc::sync::Arc<dyn narf_filesystem::DirOps>,
    alloc::string::String,
)> {
    let last = abs.rfind('/')?;
    let leaf = &abs[last + 1..];
    if leaf.is_empty() {
        return None;
    }
    let parent_path = if last == 0 { "/" } else { &abs[..last] };
    let dir = current_resolve_absolute(parent_path, |fs, rel| {
        // Walk `rel` segment-by-segment as DIRECTORIES. We can't use
        // `resolve_async` here: it resolves to a FileOps and returns
        // NotFound for a directory-only final component (e.g. a MemFs
        // subdir, whose `lookup` yields None for Dir entries), so the
        // parent of a nested create never resolved → EPERM. Prefer the
        // async dir-lookup (ext2 needs block reads); fall back to the
        // sync `lookup_dir` for filesystems that stub the async form.
        let mut dir = fs.root();
        for seg in rel.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                return None;
            }
            let next = match poll_blocking(dir.lookup_dir_async(seg)) {
                Some(Ok(d)) => d,
                Some(Err(narf_filesystem::FsError::Unsupported)) | None => dir.lookup_dir(seg)?,
                Some(Err(_)) => return None,
            };
            dir = next;
        }
        Some(dir)
    })
    .flatten()?;
    Some((dir, alloc::string::String::from(leaf)))
}

/// Build the VFS key for a pathname AF_UNIX socket. The preferred identity is
/// `(backing filesystem, socket inode)`: a file bind gets the source
/// filesystem identity and exposes that exact inode at its mount root, so the
/// two spellings alias. A pathname not yet materialised as a filesystem node
/// falls back to `(backing filesystem, parent inode, leaf)`; that is the
/// identity needed while `bind(2)` creates the socket node. The legacy
/// initramfs reports inode zero, so it falls back to the parent spelling within
/// the stable backing filesystem.
pub(crate) fn unix_socket_path_key(
    path: &str,
    follow_final: bool,
) -> Option<(
    usize,
    u64,
    Option<alloc::string::String>,
    alloc::string::String,
)> {
    unix_socket_path_key_depth(path, follow_final, 0)
}

/// If `path_ref`'s final component is a symlink, return its target string
/// verbatim (absolute or relative) so the caller can re-resolve it in the
/// GLOBAL namespace. Resolves the node NOFOLLOW (tmpfs sync path + async
/// fallback), then reads the link target. `None` if the final component is
/// not a symlink or does not resolve.
fn resolve_final_symlink_target(path_ref: &str) -> Option<alloc::string::String> {
    current_resolve_absolute(path_ref, |fs, rel| {
        let file = if rel.is_empty() {
            fs.root_file()
        } else {
            narf_filesystem::resolve(fs.root(), rel).ok().or_else(|| {
                poll_blocking(narf_filesystem::resolve_async_nofollow(fs.root(), rel))
                    .and_then(|result| result.ok())
            })
        };
        file.and_then(|file| {
            if file.stat().mode.file_type != narf_filesystem::FileType::Symlink {
                return None;
            }
            let mut buf = alloc::vec![0u8; 4096];
            let n = poll_blocking(file.read(0, &mut buf)).and_then(|r| r.ok())?;
            core::str::from_utf8(&buf[..n])
                .ok()
                .map(alloc::string::String::from)
        })
    })
    .flatten()
}

fn unix_socket_path_key_depth(
    path: &str,
    follow_final: bool,
    depth: usize,
) -> Option<(
    usize,
    u64,
    Option<alloc::string::String>,
    alloc::string::String,
)> {
    if path.is_empty() || path.starts_with('\0') {
        return None;
    }
    let abs = resolve_cwd_path(current_task_id(), path);
    let path_ref = abs.trim_end_matches('/');
    // CONNECT (follow_final) follows a FINAL symlink at the GLOBAL namespace
    // level so a symlinked socket alias keys by the TARGET listener's identity.
    // systemd socket units publish aliases this way (systemd-userdbd.socket
    // `Symlinks=` makes io.systemd.DropIn / io.systemd.NameServiceSwitch
    // symlinks to io.systemd.Multiplexer, with an ABSOLUTE target). Following
    // here (not inside resolve_async) is required because resolve_async
    // restarts an absolute symlink target from the CURRENT fs root — wrong when
    // the socket dir is its own mount (/run tmpfs) → /run/run/... NotFound.
    // resolve_cwd_path re-roots the target across mounts + chroot, then we
    // recurse. Keying a connect by the symlink's own inode found no listener
    // and returned ECONNREFUSED, wedging nss_systemd's userdb group lookup and
    // failing user@<uid>'s PAM session (EXIT_PAM). bind() must NOT follow (it
    // names the literal path), so this is gated per-caller.
    if follow_final && depth < 40 {
        if let Some(target) = resolve_final_symlink_target(path_ref) {
            let target_abs = if target.starts_with('/') {
                target
            } else {
                let parent = path_ref.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                alloc::format!("{parent}/{target}")
            };
            return unix_socket_path_key_depth(&target_abs, true, depth + 1);
        }
    }
    // Linux pathname AF_UNIX sockets are named by their dentry/inode.  This
    // also covers a `mount --bind <socket-file> <target-file>`: the target is
    // a file-rooted mount (`rel` is empty) whose `root_file()` is the original
    // socket node.  Do this before the parent fallback so a private overmount
    // cannot split a service's `$NOTIFY_SOCKET` from PID 1's endpoint.
    if let Some(Some(key)) = current_resolve_absolute(path_ref, |fs, rel| {
        let file = if rel.is_empty() {
            fs.root_file()
        } else {
            // Socket nodes on tmpfs/memfs are intentionally lightweight and
            // expose the synchronous DirOps path; block-backed filesystems
            // need the async resolver.  Use each according to the backing's
            // capability so this identity path never makes an in-memory
            // S_IFSOCK node disappear. (A final symlink was already followed by
            // the follow_final preamble above; here `rel` is the real node.)
            narf_filesystem::resolve(fs.root(), rel).ok().or_else(|| {
                poll_blocking(narf_filesystem::resolve_async_nofollow(fs.root(), rel))
                    .and_then(|result| result.ok())
            })
        };
        file.and_then(|file| {
            let ino = file.ino();
            (ino != 0).then(|| {
                (
                    fs.backing_identity(),
                    ino,
                    None,
                    alloc::string::String::new(),
                )
            })
        })
    }) {
        return Some(key);
    }
    let last = path_ref.rfind('/')?;
    let parent_path = if last == 0 { "/" } else { &path_ref[..last] };
    let (parent, leaf) = resolve_parent_dir_async(path_ref)?;
    let name = leaf;
    current_resolve_absolute(parent_path, |fs, rel| {
        let parent_ino = parent.ino();
        let fallback_parent_path = (parent_ino == 0).then(|| alloc::string::String::from(rel));
        (
            fs.backing_identity(),
            parent_ino,
            fallback_parent_path,
            name,
        )
    })
}

/// Whether an AF_UNIX pathname's FINAL node currently exists in the VFS,
/// following a final symlink the way `connect(2)`/`sendto(2)` do (Linux
/// `unix_find_bsd` uses `kern_path(..., LOOKUP_FOLLOW, ...)`). Used to tell
/// ENOENT ("path absent") from ECONNREFUSED ("node present but no live
/// listener") on a FAILED AF_UNIX connect/sendto: Linux returns -ENOENT when
/// `kern_path` fails and -ECONNREFUSED when the node exists but is not a live
/// socket. Unlike [`unix_socket_path_key`], this deliberately does NOT fall
/// back to the parent directory — an absent leaf must read as absent.
pub(crate) fn unix_path_final_node_exists(path: &str) -> bool {
    unix_path_final_node_exists_depth(path, 0)
}
fn unix_path_final_node_exists_depth(path: &str, depth: usize) -> bool {
    if path.is_empty() || path.starts_with('\0') {
        return false;
    }
    let abs = resolve_cwd_path(current_task_id(), path);
    let path_ref = abs.trim_end_matches('/');
    // Follow a final symlink (LOOKUP_FOLLOW) exactly as the key computation
    // does, so a symlinked socket alias resolves to its target's existence.
    if depth < 40 {
        if let Some(target) = resolve_final_symlink_target(path_ref) {
            let target_abs = if target.starts_with('/') {
                target
            } else {
                let parent = path_ref.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                alloc::format!("{parent}/{target}")
            };
            return unix_path_final_node_exists_depth(&target_abs, depth + 1);
        }
    }
    // Resolve ONLY the final node (mirrors the primary block of
    // `unix_socket_path_key_depth`); a present node of any type → exists.
    current_resolve_absolute(path_ref, |fs, rel| {
        let file = if rel.is_empty() {
            fs.root_file()
        } else {
            narf_filesystem::resolve(fs.root(), rel).ok().or_else(|| {
                poll_blocking(narf_filesystem::resolve_async_nofollow(fs.root(), rel))
                    .and_then(|result| result.ok())
            })
        };
        file.map(|file| file.ino() != 0).unwrap_or(false)
    })
    .unwrap_or(false)
}

/// Move `old_abs` to `new_abs` when the two live in DIFFERENT parent
/// directories. Returns the raw syscall value: `0` on success, or a
/// negative errno.
///
/// `DirOps::rename` is a single-directory operation (it renames a name
/// within one directory), so a cross-directory move is expressed with
/// the primitives that do span directories: look the node up in the old
/// parent, `link_node` it into the new parent, then unlink the old name.
/// The node `Arc` is aliased, not copied, so open fds and the new name
/// keep referring to one inode — which is what makes the "write a temp
/// file, rename it into place" pattern behave.
///
/// Restricted to a single mount (`resolve_two_parents_absolute` enforces
/// it); a move across mounts is a genuine `EXDEV` and every caller falls
/// back to copy+unlink on it.
fn cross_dir_rename(old_abs: &str, new_abs: &str) -> u64 {
    const EXDEV: i64 = -18;
    const ENOENT: i64 = -2;
    const EISDIR: i64 = -21;
    let res = current_resolve_two_parents_absolute(
        old_abs,
        new_abs,
        |_fs, old_dir, old_leaf, new_dir, new_leaf| {
            match poll_blocking(old_dir.rename_to(old_leaf, &*new_dir, new_leaf, 0)) {
                Some(Ok(())) => return 0,
                Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
                Some(Err(e)) => return rename_errno(e) as i64,
            }
            // Directories would need a DirOps-shaped `link_node` the
            // trait doesn't have yet; report EXDEV so callers fall back
            // to a recursive copy rather than silently doing nothing.
            if old_dir.lookup_dir(old_leaf).is_some() {
                return EISDIR;
            }
            let node = match poll_blocking(old_dir.lookup_async(old_leaf)) {
                Some(Ok(n)) => n,
                _ => return ENOENT,
            };
            // POSIX rename REPLACES an existing destination; `link_node`
            // refuses to (linkat never clobbers), so clear the target
            // first. Best-effort: if it isn't there, the unlink fails
            // harmlessly and link_node succeeds.
            let _ = poll_blocking(new_dir.unlink(new_leaf));
            match poll_blocking(new_dir.link_node(new_leaf, node)) {
                Some(Ok(())) => {}
                // A filesystem that can't adopt a foreign node (read-only
                // or block-backed) still owes the caller EXDEV so it
                // copy+unlinks instead.
                _ => return EXDEV,
            }
            match poll_blocking(old_dir.unlink(old_leaf)) {
                Some(Ok(())) => 0,
                // The new name is live but the old one wouldn't go away.
                // Undo the link so the move is all-or-nothing rather than
                // leaving the file visible under both names.
                _ => {
                    let _ = poll_blocking(new_dir.unlink(new_leaf));
                    EXDEV
                }
            }
        },
    );
    // `None` ⇒ unresolvable path or genuinely different mounts.
    res.unwrap_or(EXDEV) as u64
}

// ── link / linkat — hard links ─────────────────────────────────────
//
// Cross-parent links are routed through `DirOps::link_to` when both
// parents belong to one filesystem; different mounts return EXDEV.

/// Shared body: both paths already read from user memory, still raw
/// (cwd-relative allowed). Resolves, enforces same-parent, calls the
/// parent's `DirOps::link`, and maps `FsError` to the Linux errno the
/// caller's libc expects.
fn link_impl(ctx: &mut dyn TrapContext, old_raw: &str, new_raw: &str) {
    let task = current_task_id();
    let old_path = resolve_cwd_path(task, old_raw);
    let new_path = resolve_cwd_path(task, new_raw);
    // Only the directory GAINING a name is written, so only that mount
    // needs to be writable — a hard link from a read-only mount into a
    // writable one is legal.
    if let Err(errno) = mnt_want_write(&new_path) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // `vfs_link`: `if (IS_APPEND(inode) || IS_IMMUTABLE(inode)) return
    // -EPERM;` — a new NAME for an immutable inode is a change to it.
    if path_inode_flags(&old_path) & narf_filesystem::FS_PRIVILEGED_FL != 0 {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }
    // `do_linkat` -> `filename_create` -> `may_create(new_dir, ..)`. The
    // OLD name is only read, so it needs no directory write permission —
    // only the directory gaining a name does.
    if let Err(errno) = check_may_create(&new_path) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let (Some(old_split), Some(new_split)) = (old_path.rfind('/'), new_path.rfind('/')) else {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    };
    if old_path[..old_split] != new_path[..new_split] {
        let outcome = narf_filesystem::registry().resolve_two_parents_absolute(
            &old_path,
            &new_path,
            |_fs, old_dir, old_leaf, new_dir, new_leaf| {
                poll_blocking(old_dir.link_to(old_leaf, &*new_dir, new_leaf))
            },
        );
        match outcome {
            Some(Some(Ok(()))) => {
                crate::mqueue::notify_create(&new_path, false);
                ctx.set_return(SyscallReturn::ok(0));
            }
            Some(Some(Err(narf_filesystem::FsError::NotFound))) => {
                ctx.set_return(SyscallReturn::ok((-2i64) as u64))
            }
            Some(Some(Err(narf_filesystem::FsError::Busy))) => {
                ctx.set_return(SyscallReturn::ok((-17i64) as u64))
            }
            Some(Some(Err(narf_filesystem::FsError::QuotaExceeded))) => {
                ctx.set_return(SyscallReturn::ok((-122i64) as u64))
            }
            _ => ctx.set_return(SyscallReturn::ok((-18i64) as u64)),
        }
        return;
    }
    let new_leaf = alloc::string::String::from(&new_path[new_split + 1..]);
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(&old_path, |_fs, parent, old_leaf| {
            poll_blocking(parent.link(old_leaf, &new_leaf))
        });
    match outcome {
        Some(Some(Ok(()))) => {
            crate::mqueue::notify_create(&new_path, false);
            ctx.set_return(SyscallReturn::ok(0));
        }
        // link(2) errno map: missing source → ENOENT, existing dest →
        // EEXIST, directory source / no-hard-link fs → EPERM.
        Some(Some(Err(narf_filesystem::FsError::NotFound))) => {
            ctx.set_return(SyscallReturn::ok((-2i64) as u64))
        }
        Some(Some(Err(narf_filesystem::FsError::Busy))) => {
            ctx.set_return(SyscallReturn::ok((-17i64) as u64))
        }
        Some(Some(Err(narf_filesystem::FsError::QuotaExceeded))) => {
            ctx.set_return(SyscallReturn::ok((-122i64) as u64))
        }
        // `fs/namei.c::vfs_link` surfaces the filesystem's own error rather
        // than a blanket one; the `-1` sentinel here reached userspace as
        // EPERM, which link(2) also returns legitimately (a directory source,
        // or an immutable inode), so a caller could not tell the two apart.
        Some(Some(Err(error))) => {
            ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64))
        }
        _ => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
    }
}

/// Materialise the anonymous inode held by `src_fd` at the absolute path
/// `new_path`, i.e. give an `O_TMPFILE` inode its first name. The fd keeps
/// its own reference; the new name aliases the same inode via the target
/// directory's `DirOps::link_node`. Returns the Linux errno / 0 the caller
/// should hand back. Used for both `linkat(fd,"",…,AT_EMPTY_PATH)` and the
/// `linkat(AT_FDCWD,"/proc/self/fd/N",…,AT_SYMLINK_FOLLOW)` form systemd
/// uses to publish its O_TMPFILE-staged files.
fn link_fd_node_impl(task: u64, src_fd: u32, new_path: &str) -> i64 {
    // Pull the fd's backing node out of the table (keeping its Arc alive).
    let node = fd::with_table(task, |t| t.get(src_fd).map(|e| e.ops.clone())).flatten();
    let Some(node) = node else {
        return -9; // -EBADF: no such fd
    };
    let Some(split) = new_path.rfind('/') else {
        return -22; // -EINVAL: newpath has no directory component
    };
    let new_leaf = alloc::string::String::from(&new_path[split + 1..]);
    if new_leaf.is_empty() {
        return -22; // -EINVAL
    }
    let dir_path = if split == 0 { "/" } else { &new_path[..split] };
    let Some(dir) = resolve_dir_absolute(dir_path) else {
        return -2; // -ENOENT: target directory doesn't exist
    };
    match poll_blocking(dir.link_node(&new_leaf, node)) {
        Some(Ok(())) => {
            crate::mqueue::notify_create(new_path, false);
            0
        }
        // `fs/namei.c::vfs_link`, and `may_create_dentry` before it.
        // Name already taken — linkat never replaces (EEXIST).
        Some(Err(narf_filesystem::FsError::Busy)) => -17, // -EEXIST
        Some(Err(narf_filesystem::FsError::QuotaExceeded)) => -122, // -EDQUOT
        // `vfs_link`: `if (!dir->i_op->link) return -EPERM;`. A filesystem
        // with no link operation is EPERM, not EOPNOTSUPP — `link(2)` lists
        // EPERM for exactly this ("the filesystem does not support the
        // creation of hard links") and does not list EOPNOTSUPP at all, so a
        // caller matching the documented set never saw this answer.
        Some(Err(narf_filesystem::FsError::Unsupported)) => -1, // -EPERM
        // `vfs_link`'s `if (dir->i_sb != inode->i_sb) return -EXDEV;`. The
        // comparison happens in the backend, which is the only place that
        // knows which filesystem an `Arc<dyn FileOps>` belongs to; it reports
        // the mismatch as `CrossDevice` and this turns it into the errno `cp`
        // and `mv` look for before falling back to a copy.
        Some(Err(narf_filesystem::FsError::CrossDevice)) => -18, // -EXDEV
        Some(Err(narf_filesystem::FsError::NotFound)) => -2,     // -ENOENT
        Some(Err(narf_filesystem::FsError::ReadOnly)) => -30,    // -EROFS
        Some(Err(narf_filesystem::FsError::PermissionDenied)) => -13, // -EACCES
        Some(Err(narf_filesystem::FsError::NoSpace)) => -28,     // -ENOSPC
        Some(Err(narf_filesystem::FsError::Io(_))) => -5,        // -EIO
        _ => -1,                                                 // -EPERM
    }
}

// ── Readlink / Symlink — MemFs-backed symlink read + create ───────
//
// MemFs grew an `Entry::Symlink(MemSymlink)` variant: the symlink
// target lives as an immutable String exposed through `FileOps::read`,
// and `DirOps::symlink` mints fresh entries. These two handlers are
// the path-based bridges to that surface — readlink reads the bytes,
// symlink installs the entry. Both operate over absolute paths via
// the registry's resolve_parent_absolute helper, mirroring the shape
// of sys_unlink / sys_mkdir / sys_rmdir.

/// Shared readlink path. Split out of `sys_readlink` so `sys_readlinkat` can
/// prepend a directory-fd's path: sd-device's `chase_symlinks` readlinkat()s
/// a symlink relative to its parent-directory fd, so ignoring the dirfd made
/// the symlink chase fail.
fn readlink_impl(
    ctx: &mut dyn TrapContext,
    raw: alloc::string::String,
    buf_ptr: *mut u8,
    buf_len: i64,
) {
    // `fs/stat.c::do_readlinkat` opens with `if (bufsiz <= 0) return -EINVAL;`
    // — BEFORE the path is looked up, so a bad size outranks a missing file.
    // A null destination is NOT rejected here: Linux only discovers it when
    // `vfs_readlink` copies out, which is -EFAULT. Collapsing the two into one
    // `-1` told a caller "Operation not permitted" for what is either a
    // malformed size or a bad pointer — and sd-device's `chase_symlinks`
    // branches on exactly this errno (`if (errno != EINVAL) return 0;`), so
    // the wrong one aborts a device walk instead of continuing it.
    if buf_len <= 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let buf_len = buf_len as usize;
    // resolve_cwd_path already re-roots under the task's chroot — do
    // not apply_chroot again or the prefix is composed twice.
    let path = resolve_cwd_path(current_task_id(), &raw);
    // Resolve the leaf via the ASYNC path in NoFollow mode. The sync
    // `DirOps::lookup` returns None for ext2 (lookups are async there),
    // so the old resolve_parent_absolute(lookup) path reported EINVAL for
    // every ext2-backed symlink; the async walker returns the real node.
    // NoFollow so we obtain the symlink itself and can read its target,
    // rather than following it to (a copy of) the target's contents.
    // Resolve through the caller's PRIVATE mount namespace, not the global
    // registry: a systemd service sandbox unshare(NEWNS)s, binds the API
    // filesystems (sysfs at /sys especially) into its `/run/systemd/mount-
    // rootfs` staging root, and pivot_roots into it. In the GLOBAL registry
    // that staging path is just the tmpfs skeleton, so a global readlink of
    // `/sys/dev/char/226:0` from inside logind's namespace hits tmpfs and
    // EINVALs — which fails sd-device's `sd_device_new_from_devnum`, then
    // `session_device_verify()` → `TakeDevice` over D-Bus → kwin "Failed to
    // open /dev/dri/card0 device (Invalid argument)". The open/stat path
    // already resolves namespace-aware (current_resolve_absolute); readlink
    // must match or a pivoted service cannot readlink its own /sys symlinks.
    let root_rel = current_resolve_absolute(&path, |fs, rel| {
        (fs.root(), alloc::string::String::from(rel))
    });
    let file = match root_rel {
        Some((root, rel)) => {
            match poll_blocking(narf_filesystem::resolve_async_nofollow(root, &rel)) {
                Some(Ok(o)) => Some(o),
                _ => None,
            }
        }
        None => None,
    };
    // POSIX errno discipline matters here: musl's realpath() walks a path by
    // readlink()-ing each prefix and treats any failure other than EINVAL as
    // fatal (`if (errno != EINVAL) return 0;`). A non-symlink that exists must
    // therefore report EINVAL (not the generic -1 → EPERM, which aborted
    // realpath at the first directory component); a path that names nothing
    // reports ENOENT.
    let einval = SyscallReturn::ok((-22i64) as u64); // -EINVAL: exists, not a symlink
    let enoent = SyscallReturn::ok((-2i64) as u64); // -ENOENT: nothing here
    let file = match file {
        Some(f) => f,
        None => {
            // Not a file. Directories and mount roots exist but aren't
            // symlinks → EINVAL; a truly absent path → ENOENT.
            if stat_path_dir_aware(&path).is_some() {
                ctx.set_return(einval);
            } else {
                ctx.set_return(enoent);
            }
            return;
        }
    };
    // Refuse non-symlinks — POSIX readlink returns EINVAL for those.
    let st = file.stat();
    if st.mode.file_type != narf_filesystem::FileType::Symlink {
        ctx.set_return(einval);
        return;
    }
    // `st_size` is only a hint for symlinks and is deliberately zero for
    // Linux procfs magic links such as /proc/self and /proc/<pid>/ns/mnt.
    // readlink(2) is defined by the caller's buffer length, so read directly
    // into a buffer of that size and let FileOps return the actual byte count.
    let mut staging = alloc::vec![0u8; buf_len];
    let n = match poll_blocking(file.read(0, &mut staging)) {
        Some(Ok(n)) => n,
        // The node resolved and IS a symlink, so a failure to read its target
        // is the filesystem's own error, not a caller mistake.
        Some(Err(error)) => {
            ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64));
            return;
        }
        None => {
            ctx.set_return(SyscallReturn::ok((-5i64) as u64)); // -EIO
            return;
        }
    };
    // Copy result into user buffer under SMAP bracket. This is where Linux
    // discovers a null or unmapped destination — `vfs_readlink`'s copy_to_user
    // — so it is -EFAULT, reached only after the size and the symlink checks.
    // SAFETY: buf_ptr is a user VA; copy_to_user range-validates it; n <= buf_len.
    if unsafe { copy_to_user(buf_ptr as u64, &staging[..n]) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(n as u64));
}

// ── Listdir — arg0=path, arg1=path_len, arg2=cursor,
//             arg3=out_buf, arg4=out_buf_len ────────────────────────
//
// Path-based readdir. Resolves the absolute path to a directory,
// snapshots the entry list via DirOps::enumerate, and serialises
// the cursor-th entry into the user's buffer in
// `[name_len: u32][file_type: u32][name bytes...]` format. The
// libc shim (opendir / readdir / closedir) drives this with a
// monotonically-increasing cursor; the kernel re-snapshots each
// call rather than holding state per-fd. This is racy under
// concurrent mutation but Stage-4 user mode is single-threaded
// and the typical caller iterates a stable directory.
//
// Returns:
//   `value` = bytes_written (8 + name_len) on success
//   `value` = 0              on end-of-directory (cursor past end)
//   `value` = -1             on bad input / lookup failure / buf
//                            too small to hold the header + name.
//
// Returning the FileType as the second u32 lets the libc fill in
// `dirent.d_type` directly without a follow-on stat.

// ── Getdents64 — fd-based batched directory read (linux_dirent64) ──
//
// Linux ABI: `getdents64(unsigned int fd, void *dirp, unsigned int
// count)`. arg0 = directory fd (from `open(path, O_DIRECTORY)` →
// DirFdFile), arg1 = user buffer, arg2 = buffer size. The read cursor
// lives in the fd's `offset` field, advanced across successive calls.
//
// linux_dirent64 wire layout:
//   d_ino:    u64
//   d_off:    u64    — cursor of the *next* entry
//   d_reclen: u16    — total record length, 8-byte aligned
//   d_type:   u8
//   d_name:  [u8]    — NUL-terminated, padded to alignment
//
// Total record size: round_up_8(19 + name_len + 1).
//
// Continues writing entries until either the directory is
// exhausted or the next record won't fit. Returns the total
// bytes written; 0 on end-of-directory.

// ── Getdents — legacy fd-based directory read (linux_dirent) ───────
//
// Linux ABI: `getdents(unsigned int fd, void *dirp, unsigned int
// count)` — x86_64 78. The aarch64 / generic ABI does NOT expose the
// legacy `getdents` (only `getdents64`, 61), so there is no aarch64
// wire number for it; libc on that arch always issues getdents64.
//
// This is the pre-largefile twin of [[sys_getdents64]] — same
// directory-resolution + enumerate + cursor logic, only the per-record
// serialisation differs. The legacy `struct linux_dirent`:
//   d_ino:    unsigned long (u64 on LP64)
//   d_off:    unsigned long (u64) — cursor of the *next* entry
//   d_reclen: unsigned short (u16) — total record length, 8-byte aligned
//   d_name:  [u8]                  — NUL-terminated
//   <zero pad>
//   d_type:   u8                   — stored at the LAST byte (reclen-1)
//
// Note the d_type placement: unlike getdents64 (which has an explicit
// d_type field at offset 18), the legacy record hides d_type in the pad
// byte at `buf[offset + d_reclen - 1]`, and there is always a NUL after
// the name before that pad/d_type byte. Total record size therefore
// rounds up `18 (header) + name_len + 1 (NUL) + 1 (d_type)` to 8.
//
// EBADF / ENOTDIR / return-bytes semantics match sys_getdents64.

// ── Close — arg0=fd ────────────────────────────────────────────────

// ── Mmap — arg0=hint, arg1=len, arg2=flags ─────────────────────────

// Mmap virt cursor: starts at PML4[129] = 64.5 TiB, well outside
// the kernel's identity-map PML4[0] (which lacks the USER bit on
// its PML4 entry — putting user mappings under it would deny user
// access at the PML4 walk level even with USER set on every level
// below).
// Legacy global mmap cursor — kept until every internal caller of
// `MMAP_CURSOR.fetch_add(...)` (FB shmem ring, NVMe queue maps, etc.
// inside this crate) is migrated to the per-AS variant. New code
// should always use `as_ref.reserve_mmap_va(...)` for the active
// AS.
static MMAP_CURSOR: AtomicU64 = AtomicU64::new(0x0000_4080_0000_0000);

/// Translate POSIX `PROT_*` bits into NARF region perms. `PROT_NONE`
/// (a bare reservation) maps to a present READ region — NARF has no
/// no-access mapping, and the reservation is typically overwritten by a
/// later MAP_FIXED segment anyway.
fn perms_of_prot(prot: u32) -> RegionPerms {
    const PROT_READ: u32 = 0x1;
    const PROT_WRITE: u32 = 0x2;
    const PROT_EXEC: u32 = 0x4;
    let mut p = RegionPerms::default();
    if prot & PROT_READ != 0 {
        p = p | RegionPerms::READ;
    }
    if prot & PROT_WRITE != 0 {
        p = p | RegionPerms::WRITE;
    }
    if prot & PROT_EXEC != 0 {
        p = p | RegionPerms::EXEC;
    }
    if !p.contains(RegionPerms::READ)
        && !p.contains(RegionPerms::WRITE)
        && !p.contains(RegionPerms::EXEC)
    {
        p = RegionPerms::READ;
    }
    p
}

/// `sendfile(out_fd, in_fd, off*, count)` — copy up to `count` bytes
/// from `in_fd` to `out_fd` entirely in the kernel (no user buffer).
/// If `off` is non-NULL it is a pread-style start offset that is
/// updated and does NOT advance `in_fd`'s own file offset; NULL uses
/// and advances the fd offset. Returns the number of bytes copied.
/// Shared core for `sendfile(2)` / `splice(2)`: copy up to `count`
/// bytes from `in_fd` to `out_fd` entirely in the kernel via the fd
/// table's FileOps. When `in_off_ptr` is non-zero it is a user
/// pread-style offset pointer (read from, updated, and the fd's own
/// offset is left untouched); zero uses and advances the fd offset.
/// Returns the accepted byte count or the first filesystem error before any
/// progress. Syscall-specific fd, offset-uaccess, and errno ordering stays in
/// the sendfile/splice entry modules.
enum CopyFdError {
    Fs(narf_filesystem::FsError),
}

/// One fd-table snapshot held across a sendfile/splice transfer.  Linux's
/// `fdget()` pins the open file while the syscall runs; cloning the FileOps
/// Arc gives NARF the same lifetime even if a CLONE_FILES peer closes the
/// numeric descriptor concurrently. The captured description similarly pins
/// f_pos and receives every commit directly, so close+numeric-fd reuse cannot
/// redirect an update to an unrelated file.
#[derive(Clone)]
struct CopyFdEndpoint {
    ops: Arc<dyn narf_filesystem::FileOps>,
    description: crate::fd::Description,
    status_flags: u32,
}

impl CopyFdEndpoint {
    fn readable(&self) -> bool {
        self.status_flags & crate::fd::O_PATH == 0
            && self.status_flags & crate::fd::O_ACCMODE != crate::fd::O_WRONLY
    }

    fn writable(&self) -> bool {
        self.status_flags & crate::fd::O_PATH == 0
            && self.status_flags & crate::fd::O_ACCMODE != crate::fd::O_RDONLY
    }

    fn nonblocking(&self) -> bool {
        self.status_flags & crate::fd::O_NONBLOCK != 0
    }

    fn append(&self) -> bool {
        self.status_flags & crate::fd::O_APPEND != 0
    }

    fn is_pipe(&self) -> bool {
        self.ops.stat().mode.file_type == narf_filesystem::FileType::Fifo
    }
}

fn copy_fs_errno(error: narf_filesystem::FsError) -> i64 {
    match error {
        narf_filesystem::FsError::NotFound => 2,
        narf_filesystem::FsError::PermissionDenied => 13,
        narf_filesystem::FsError::OperationNotPermitted => 1,
        narf_filesystem::FsError::Io(_) => 5,
        narf_filesystem::FsError::InvalidPath
        | narf_filesystem::FsError::InvalidData
        | narf_filesystem::FsError::Unsupported => 22,
        // `fs/namei.c`: a walk that exhausts MAXSYMLINKS is -ELOOP, not the
        // -EINVAL a malformed path gets. Folding it into InvalidPath told
        // callers the path was syntactically wrong when it was structurally
        // circular.
        narf_filesystem::FsError::SymlinkLoop => 40,
        narf_filesystem::FsError::CrossDevice => 18,
        narf_filesystem::FsError::Busy => 16,
        narf_filesystem::FsError::ReadOnly => 30,
        narf_filesystem::FsError::NoSpace => 28,
        narf_filesystem::FsError::QuotaExceeded => 122,
        // ENOTCONN — see `FsError::NotConnected`.
        narf_filesystem::FsError::NotConnected => 107,
        narf_filesystem::FsError::BrokenPipe => 32,
        narf_filesystem::FsError::BadFd => 9,
        narf_filesystem::FsError::WouldBlock => EAGAIN_CODE as i64,
    }
}

const LINUX_MAX_RW_COUNT: usize = 0x7fff_f000;
const LINUX_IOV_MAX: usize = 1024;

/// Linux `access_ok()` shape for read/write buffers, without NARF's generic
/// 16-MiB single-copy allocation cap. Large I/O is staged in bounded chunks;
/// range validation must still cover the caller's original count before fd
/// state or a destructive stream is touched.
fn validate_rw_user_range(ptr: u64, len: usize) -> Result<(), u64> {
    // access_ok(NULL, 0) succeeds, while a zero-length address outside the
    // user half still fails. The generic helper deliberately rejects NULL for
    // pointer-bearing structures, so preserve this syscall-specific rule.
    if len == 0 && ptr == 0 {
        return Ok(());
    }
    let Some(end) = ptr.checked_add(len as u64) else {
        return Err(EFAULT);
    };
    let last = if len == 0 { ptr } else { end - 1 };
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        if !in_user_half(ptr) || !in_user_half(last) {
            #[cfg(feature = "kernel-test")]
            if kernel_buf_scope::active()
                && canonical(ptr)
                && canonical(last)
                && (ptr >> 63) == (last >> 63)
            {
                return Ok(());
            }
            return Err(EFAULT);
        }
    }
    Ok(())
}

#[derive(Copy, Clone)]
struct ImportedRwIovec {
    base: u64,
    len: usize,
}

fn import_rw_iovecs(iov_ptr: u64, iovcnt: usize) -> Result<alloc::vec::Vec<ImportedRwIovec>, u64> {
    if iovcnt == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    if iovcnt > LINUX_IOV_MAX {
        return Err(22); // EINVAL
    }
    // SAFETY: 1024 native iovecs occupy 16 KiB, below MAX_USER_COPY.
    let raw = unsafe { copy_from_user_vec(iov_ptr, iovcnt * 16) }?;
    let mut out = alloc::vec::Vec::with_capacity(iovcnt);
    let mut remaining = LINUX_MAX_RW_COUNT;
    for slot in raw.chunks_exact(16) {
        let base = u64::from_ne_bytes(slot[..8].try_into().unwrap());
        let requested = u64::from_ne_bytes(slot[8..].try_into().unwrap()) as usize;
        validate_rw_user_range(base, requested)?;
        let len = core::cmp::min(requested, remaining);
        remaining -= len;
        out.push(ImportedRwIovec { base, len });
    }
    Ok(out)
}

fn copy_fd_endpoint(task: u64, fd_num: u32) -> Option<CopyFdEndpoint> {
    fd::with_table(task, |table| {
        copy_fd_endpoint_from_table(table, fd_num)
    })
    .flatten()
}

fn copy_fd_endpoint_from_table(
    table: &crate::fd::FdTable,
    fd_num: u32,
) -> Option<CopyFdEndpoint> {
    let entry = table.get(fd_num)?;
    Some(CopyFdEndpoint {
        ops: entry.ops.clone(),
        description: table.description(fd_num)?,
        status_flags: table.status_flags(fd_num)?,
    })
}

/// Snapshot two descriptors under one fd-table acquisition. Linux resolves
/// the input first and does not inspect the output after an input EBADF; the
/// `?` ordering below keeps that precedence while avoiding a second shard-map
/// lookup, Arc clone, IRQ-disable section, and table lock on two-fd syscalls.
fn copy_fd_endpoints(
    task: u64,
    first_fd: u32,
    second_fd: u32,
) -> Option<(CopyFdEndpoint, CopyFdEndpoint)> {
    fd::with_table(task, |table| {
        let first = copy_fd_endpoint_from_table(table, first_fd)?;
        if first_fd == second_fd {
            return Some((first.clone(), first));
        }
        let second = copy_fd_endpoint_from_table(table, second_fd)?;
        Some((first, second))
    })
    .flatten()
}

fn copy_fd_to_fd(
    input: &CopyFdEndpoint,
    output: &CopyFdEndpoint,
    explicit_in_off: Option<u64>,
    explicit_out_off: Option<u64>,
    count: usize,
) -> Result<usize, CopyFdError> {
    let use_off_ptr = explicit_in_off.is_some();
    let use_out_off_ptr = explicit_out_off.is_some();
    let same_description = Arc::ptr_eq(&input.description, &output.description);
    // Pipes and other streams have no f_pos. Their syscall modules reject an
    // explicit offset before reaching this core, and an implicit transfer must
    // neither serialize nor mutate the otherwise-unused description cursor.
    let track_input_position = !use_off_ptr && !input.ops.is_stream();
    let track_output_position = !use_out_off_ptr && !output.ops.is_stream();

    // Linux locks each seekable `struct file::f_pos` across the complete
    // positioned transfer. Acquire distinct descriptions by stable address
    // order so two opposite-direction copies cannot ABBA deadlock; aliases
    // lock once.
    let mut input_position_guard = None;
    let mut output_position_guard = None;
    if track_input_position && track_output_position && !same_description {
        let input_key = Arc::as_ptr(&input.description) as usize;
        let output_key = Arc::as_ptr(&output.description) as usize;
        if input_key < output_key {
            input_position_guard = poll_blocking(input.description.position_lock.lock());
            if input_position_guard.is_some() {
                output_position_guard = poll_blocking(output.description.position_lock.lock());
            }
        } else {
            output_position_guard = poll_blocking(output.description.position_lock.lock());
            if output_position_guard.is_some() {
                input_position_guard = poll_blocking(input.description.position_lock.lock());
            }
        }
        if input_position_guard.is_none() || output_position_guard.is_none() {
            return Err(CopyFdError::Fs(narf_filesystem::FsError::Busy));
        }
    } else if (track_input_position || track_output_position) && same_description {
        input_position_guard = poll_blocking(input.description.position_lock.lock());
        if input_position_guard.is_none() {
            return Err(CopyFdError::Fs(narf_filesystem::FsError::Busy));
        }
    } else {
        if track_input_position {
            input_position_guard = poll_blocking(input.description.position_lock.lock());
            if input_position_guard.is_none() {
                return Err(CopyFdError::Fs(narf_filesystem::FsError::Busy));
            }
        }
        if track_output_position {
            output_position_guard = poll_blocking(output.description.position_lock.lock());
            if output_position_guard.is_none() {
                return Err(CopyFdError::Fs(narf_filesystem::FsError::Busy));
            }
        }
    }

    // Snapshot implicit positions only after their serialization lock is held.
    // Explicit-offset and stream sides neither read nor modify the cursor.
    let mut in_off = explicit_in_off.unwrap_or_else(|| {
        if track_input_position {
            input.description.offset()
        } else {
            0
        }
    });
    let mut out_off = explicit_out_off.unwrap_or_else(|| {
        if track_output_position {
            output.description.offset()
        } else {
            0
        }
    });
    let input_ops = &input.ops;
    let output_ops = &output.ops;

    let mut total = 0usize;
    // Transfer granularity for splice/sendfile/copy_file_range. Sized to a
    // whole default pipe buffer (64 KiB) so a full-pipe splice completes in a
    // single read+write pair — one heap Vec and two `fd::with_table` lock
    // acquisitions — instead of 16 four-KiB round trips.
    const CHUNK: usize = 65536;
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        let step_out_off = out_off;
        let moved = if let Some(pipe_in) = input_ops
            .as_any()
            .and_then(|any| any.downcast_ref::<crate::pipe::PipeRead>())
        {
            if let Some(pipe_out) = output_ops
                .as_any()
                .and_then(|any| any.downcast_ref::<crate::pipe::PipeWrite>())
            {
                pipe_in.splice_to_pipe(pipe_out, want)
            } else {
                let mut sink_off = step_out_off;
                pipe_in.splice_to_sink(want, |bytes| {
                    // The source queue is locked until the accepted prefix is
                    // committed. Never park while its IRQ-safe lock is held.
                    let result = poll_once(output_ops.write(sink_off, bytes))
                        .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
                    if let Ok(written) = result {
                        sink_off = sink_off.saturating_add(written as u64);
                    }
                    result
                })
            }
        } else {
            let mut kbuf = alloc::vec![0u8; want];
            let n = match poll_blocking(input_ops.read(in_off, &mut kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::WouldBlock))
            {
                Ok(n) => n,
                Err(error) => {
                    if total == 0 {
                        return Err(CopyFdError::Fs(error));
                    }
                    break;
                }
            };
            kbuf.truncate(n);
            if n == 0 {
                break;
            }
            match poll_blocking(output_ops.write(step_out_off, &kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::WouldBlock))
            {
                Ok(written) if written <= n => Ok(written),
                Ok(_) => Err(narf_filesystem::FsError::InvalidData),
                Err(error) => Err(error),
            }
        };

        let moved = match moved {
            Ok(moved) => moved,
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                return Err(CopyFdError::Fs(narf_filesystem::FsError::WouldBlock));
            }
            Err(error) if total == 0 => return Err(CopyFdError::Fs(error)),
            Err(_) => break,
        };

        // Commit to the pinned descriptions, never by numeric fd. A concurrent
        // close+reuse cannot redirect cursor updates to an unrelated file.
        if track_input_position || track_output_position {
            if same_description && track_input_position && track_output_position {
                // Both local cursors started together and advanced by the same
                // accepted prefix; one shared f_pos is advanced once.
                input
                    .description
                    .set_offset(in_off.saturating_add(moved as u64));
            } else {
                if track_input_position {
                    input
                        .description
                        .set_offset(in_off.saturating_add(moved as u64));
                }
                if track_output_position {
                    output
                        .description
                        .set_offset(out_off.saturating_add(moved as u64));
                }
            }
        }
        total += moved;
        in_off = in_off.saturating_add(moved as u64);
        out_off = out_off.saturating_add(moved as u64);
        if moved < want {
            break;
        }
    }

    Ok(total)
}

/// Per-task robust-futex list head (`set_robust_list` / `get_robust_list`).
/// Stored verbatim — NARF is single-threaded so there is no robust-list
/// walk on thread exit, but the pointers round-trip faithfully.
static ROBUST_LIST_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, (u64, u64)>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Is `uaddr` backed by a PRESENT page in `as_ref`'s hardware page
/// tables? This is the correct precondition for a fixup-less
/// `copy_from_user`: region (VMA) membership does not imply a present
/// page, so probing the page tables — exactly the translation the CPU's
/// read will perform — is what keeps a bogus-but-canonical user pointer
/// (robust_smoke's head=0x1234abcd0000) from faulting the kernel fatally.
#[cfg(target_arch = "x86_64")]
fn user_page_present(as_ref: &AddressSpace, uaddr: u64) -> bool {
    // SAFETY: called from the dying task's own exit context with its AS
    // active, so `root` is the live, identity-reachable PML4; `translate`
    // only reads page-table memory reachable from that root.
    unsafe { narf_memory::x86_64::paging::translate(as_ref.root, VirtAddr::new(uaddr)).is_some() }
}

#[cfg(target_arch = "aarch64")]
fn user_page_present(as_ref: &AddressSpace, uaddr: u64) -> bool {
    // SAFETY: same invariant as the x86_64 walk above. The aarch64 walker
    // follows valid table descriptors from the live TTBR0 root and returns
    // None for lazy/PROT_NONE regions with no leaf descriptor.
    unsafe { narf_memory::aarch64::paging::translate(as_ref.root, VirtAddr::new(uaddr)).is_some() }
}

/// Exit-time robust-futex walk (Linux `exit_robust_list`). Runs in the
/// DYING task's own syscall/trap context — the user AS is still active,
/// so plain `copy_from_user`/`copy_to_user` resolve the list — before
/// the exit bookkeeping tears anything down.
///
/// For every lock in the thread's registered robust list whose owner
/// field matches the dying tid: set FUTEX_OWNER_DIED (preserving
/// FUTEX_WAITERS), bump the wake generation, and wake one waiter — so
/// a peer blocked on a robust pthread_mutex held by a dying thread
/// recovers with EOWNERDEAD instead of deadlocking forever.
///
/// Layout (uapi <linux/futex.h>, x86_64):
///   struct robust_list       { struct robust_list *next; }        // +0
///   struct robust_list_head  { struct robust_list list;           // +0
///                               long futex_offset;                // +8
///                               struct robust_list *list_op_pending } // +16
pub(crate) fn robust_list_exit_walk(tid: u64) {
    const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;
    const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
    const FUTEX_WAITERS_BIT: u32 = 0x8000_0000;
    /// Linux ROBUST_LIST_LIMIT — bounds a malicious/corrupt circular list.
    const ROBUST_LIST_LIMIT: usize = 2048;

    let head = {
        let g = ROBUST_LIST_TABLE.lock();
        match g.as_ref().and_then(|m| m.get(&tid)) {
            Some(&(head, _len)) if head != 0 => head,
            _ => return,
        }
    };

    // The robust-list head and every node/lock pointer are fully
    // user-controlled and may be bogus (robust_smoke deliberately registers
    // head = 0x1234abcd0000). `copy_from_user` range-validates canonicality
    // but has no page-fault fixup, so a raw read of an unmapped-but-canonical
    // address faults the kernel fatally. Probe the current address space first
    // — an unmapped address ends the walk instead of crashing. (Linux's
    // exit_robust_list relies on get_user fault fixup for the same safety.)
    //
    // The probe MUST match what the raw read actually hits: the hardware
    // PAGE TABLES, not the region (VMA) list. Region membership does not
    // imply a present page — a reserved / PROT_NONE / not-yet-faulted
    // region, or a stale/corrupt region entry, false-positives, and the
    // fixup-less read then faults fatally anyway. `user_page_present`
    // walks the page tables (exactly the CPU's translation), so it says
    // "no" for head=0x1234abcd0000 regardless of the region list.
    let user_mapped = |uaddr: u64| -> bool {
        current_address_space()
            .map(|as_ref| user_page_present(&as_ref, uaddr))
            .unwrap_or(false)
    };

    let read_u64 = |uaddr: u64| -> Option<u64> {
        if !user_mapped(uaddr) {
            return None;
        }
        let mut b = [0u8; 8];
        // SAFETY: mapping-probed above; copy_from_user range-validates +
        // SMAP-brackets the read.
        unsafe { copy_from_user(&mut b, uaddr).ok()? };
        Some(u64::from_le_bytes(b))
    };

    let futex_offset = match read_u64(head.wrapping_add(8)) {
        Some(v) => v as i64,
        None => return,
    };
    let pending = read_u64(head.wrapping_add(16)).unwrap_or(0);

    let handle_lock = |entry: u64| {
        let uaddr = entry.wrapping_add(futex_offset as u64);
        if uaddr == 0 || uaddr & 3 != 0 {
            return;
        }
        // Same defense as the list walk: the futex word address derives from
        // user-controlled pointers + offset and may be unmapped.
        if !user_mapped(uaddr) {
            return;
        }
        let mut b = [0u8; 4];
        // SAFETY: mapping-probed above; copy_from_user range-validates +
        // SMAP-brackets the read.
        if unsafe { copy_from_user(&mut b, uaddr) }.is_err() {
            return;
        }
        let word = u32::from_le_bytes(b);
        if u64::from(word & FUTEX_TID_MASK) != tid {
            return;
        }
        let new = (word & FUTEX_WAITERS_BIT) | FUTEX_OWNER_DIED;
        // SAFETY: copy_to_user range-validates + SMAP-brackets the write.
        let _ = unsafe { copy_to_user(uaddr, &new.to_le_bytes()) };
        futex_bump_counter(uaddr);
        futex_wake_waiters(uaddr, 1);
    };

    // Walk the list. Termination: `next == head` (the head's own list
    // node is the sentinel); 0/unreadable ends the walk defensively.
    let mut entry = match read_u64(head) {
        Some(e) => e,
        None => return,
    };
    let mut steps = 0usize;
    while entry != head && entry != 0 && steps < ROBUST_LIST_LIMIT {
        // The pending lock (mid acquire/release) is handled once,
        // below, per Linux semantics — skip it during the walk.
        if entry != pending {
            handle_lock(entry);
        }
        entry = match read_u64(entry) {
            Some(e) => e,
            None => break,
        };
        steps += 1;
    }
    if pending != 0 {
        handle_lock(pending);
    }
}

// ── capget / capset ──────────────────────────────────────────────────
//
// Linux capability sets, stored per-task as three 64-bit masks
// (effective / permitted / inheritable). NARF does not *enforce*
// capabilities — there is no privilege separation in the microkernel
// yet — but it round-trips them faithfully so libcap-style code works.
//
//   struct __user_cap_header_struct { __u32 version; int pid; };
//   struct __user_cap_data_struct   { __u32 effective, permitted, inheritable; };
//
// Versions: _LINUX_CAPABILITY_VERSION_1 (1 data element, 32-bit caps),
// _2 / _3 (2 data elements, 64-bit caps split lo/hi across the array).

const CAP_VERSION_1: u32 = 0x1998_0330;
const CAP_VERSION_2: u32 = 0x2007_1026;
const CAP_VERSION_3: u32 = 0x2008_0522;

// ── POSIX capability credentials ───────────────────────────────────
//
// Linux capability numbers, `include/uapi/linux/capability.h`. Only the
// ones NARF actually consults are named; the rest still round-trip
// through capget/capset as opaque bits.
//
// NOTE these are the LINUX ambient-authority capabilities (CAP_SETUID and
// friends), which are a completely different mechanism from NARF's own
// object capabilities in the `capabilities/` crate (`CapKind::MountPoint`,
// unforgeable references minted by the TCB). The two share a word and
// nothing else; do not route one through the other.
// Only the capabilities actually CONSULTED are named. The rest still
// round-trip through capget/capset as opaque bits — naming one before
// something enforces it would advertise a check that does not exist.
pub(crate) const CAP_DAC_OVERRIDE: u32 = 1;
pub(crate) const CAP_DAC_READ_SEARCH: u32 = 2;
pub(crate) const CAP_SETGID: u32 = 6;
pub(crate) const CAP_SETUID: u32 = 7;
pub(crate) const CAP_SYS_MODULE: u32 = 16;
pub(crate) const CAP_SYS_CHROOT: u32 = 18;
pub(crate) const CAP_SYS_NICE: u32 = 23;
pub(crate) const CAP_SYS_ADMIN: u32 = 21;
pub(crate) const CAP_SYS_TIME: u32 = 25;
/// Linux checkpoint/restore authority accepted by clone3(set_tid), alongside
/// CAP_SYS_ADMIN.
pub(crate) const CAP_CHECKPOINT_RESTORE: u32 = 40;

/// `CAP_FULL_SET` — every capability up to and including `CAP_LAST_CAP`
/// (`include/linux/capability.h`: `CAP_VALID_MASK`).
const CAP_FULL_SET: u64 = if CAP_LAST_CAP >= 63 {
    u64::MAX
} else {
    (1u64 << (CAP_LAST_CAP + 1)) - 1
};

/// Linux's five per-task capability sets (`struct cred`, include/linux/cred.h:
/// `cap_effective`, `cap_permitted`, `cap_inheritable`, `cap_bset`,
/// `cap_ambient`).
///
/// The previous store was a bare `[u64; 3]` holding only the first three,
/// which is exactly the ABI shape capget/capset exchange — fine as a
/// round-trip buffer, but a bounding set is what makes a drop irreversible,
/// so without it there was nothing for `cap_capset` to check a raise
/// against.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct Caps {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
}

impl Caps {
    /// The credential a task has before anything narrows it: everything
    /// permitted and effective, the full bounding set, nothing inheritable
    /// or ambient. This is what Linux gives init (`kernel/cred.c`'s
    /// `init_cred` uses `CAP_FULL_SET` for permitted/effective/bset).
    const fn boot() -> Self {
        Self {
            effective: CAP_FULL_SET,
            permitted: CAP_FULL_SET,
            inheritable: 0,
            bounding: CAP_FULL_SET,
            ambient: 0,
        }
    }
}

/// `PR_SET_MDWE` bits, per task — Linux keeps them as `MMF_HAS_MDWE` /
/// `MMF_HAS_MDWE_NO_INHERIT` on the mm.
///
/// Absent means MDWE is off, which is every task until one asks for it.
static MDWE_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, u64>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// `PR_MDWE_REFUSE_EXEC_GAIN` — refuse mappings that gain execute.
pub(crate) const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1;
/// `PR_MDWE_NO_INHERIT` — do not carry the setting across execve.
pub(crate) const PR_MDWE_NO_INHERIT: u64 = 2;

/// `get_current_mdwe()` for an explicit task.
pub(crate) fn task_mdwe(task: u64) -> u64 {
    MDWE_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&process_state_key(task)).copied())
        .unwrap_or(0)
}

/// Test hook — MDWE is one-way by design, so a test that sets it would
/// otherwise leave every later mprotect in the shared kernel image refusing to
/// grant execute. Same class of leak as the namespace tables reset alongside
/// it, and the same fix: clear it in the harness rather than per test.
#[doc(hidden)]
pub fn __test_mdwe_reset() {
    *MDWE_TABLE.lock() = Some(alloc::collections::BTreeMap::new());
}

pub(crate) fn set_task_mdwe(task: u64, bits: u64) {
    let mut guard = MDWE_TABLE.lock();
    let map = guard.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(process_state_key(task), bits);
}

/// `include/linux/mman.h::map_deny_write_exec` — would this permission change
/// gain execute in a way MDWE refuses?
///
/// ```text
/// if (!mm_flags_test(MMF_HAS_MDWE, current->mm))  return false;
/// if (!(new & VM_EXEC))                           return false;
/// if (new & VM_WRITE)                             return true;
/// if (!(old & VM_EXEC))                           return true;
/// return false;
/// ```
///
/// The two `true` arms are different attacks. The first is the obvious one —
/// a mapping that is writable and executable at once. The second is the one
/// that makes the feature worth having: a process may not take a page it
/// already wrote and turn it executable afterwards, which is exactly the
/// shape a JIT-spraying exploit needs. Denying only W+X would leave that
/// path open while looking like it was closed.
///
/// A mapping that is already executable may stay executable — otherwise
/// mprotect could never drop WRITE from a W+X region inherited from before
/// MDWE was set, and a process could not even make itself safer.
pub(crate) fn mdwe_denies(task: u64, old: narf_memory::RegionPerms, new: narf_memory::RegionPerms) -> bool {
    if task_mdwe(task) & PR_MDWE_REFUSE_EXEC_GAIN == 0 {
        return false;
    }
    if !new.contains(narf_memory::RegionPerms::EXEC) {
        return false;
    }
    if new.contains(narf_memory::RegionPerms::WRITE) {
        return true;
    }
    !old.contains(narf_memory::RegionPerms::EXEC)
}

/// Per-task capability credential.
static CAP_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, Caps>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Read a task's credential, defaulting to [`Caps::boot`].
///
/// The default is deliberately the FULL set rather than the empty one, and
/// the reason is worth stating because the opposite instinct is the usual
/// one for a security default.
///
/// NARF has no single "spawn init" moment in `userspace/` to seed a row at
/// — init is created by the boot path — so a fail-closed default would
/// leave the very first task with no capabilities and nothing able to grant
/// it any, breaking boot outright. Every task that is FORKED gets an
/// explicit row (see `cap_fork`), so the default applies only to the boot
/// task, whose Linux counterpart holds exactly this credential. The result
/// is that enforcement can only ever RESTRICT relative to today's
/// behaviour, never grant something that was previously refused.
fn read_caps(task: u64) -> Caps {
    let g = CAP_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&process_state_key(task)).copied())
        .unwrap_or_else(Caps::boot)
}

fn write_caps(task: u64, caps: Caps) {
    let mut g = CAP_TABLE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert(process_state_key(task), caps);
}

/// `kernel/capability.c::capable(cap)` — does the CURRENT task hold `cap`
/// in its effective set?
///
/// This is `ns_capable(&init_user_ns, cap)`: authority over the HOST. A
/// resource that lives in a namespace must ask [`task_ns_capable`] against
/// that namespace's owning user namespace instead, or an unprivileged
/// container owner is refused inside its own namespace.
pub(crate) fn capable(cap: u32) -> bool {
    task_capable(current_task_id(), cap)
}

/// `security/commoncap.c::cap_capable` — does `task` hold `cap` with respect
/// to the user namespace `target`?
///
/// ```text
/// struct user_namespace *ns = targ_ns;
/// for (;;) {
///         if (likely(ns == cred->user_ns))
///                 return cap_raised(cred->cap_effective, cap) ? 0 : -EPERM;
///         if (ns == &init_user_ns)
///                 return -EPERM;
///         if ((ns->level > cred->user_ns->level) && uid_eq(ns->owner, cred->euid))
///                 return 0;
///         ns = ns->parent;
/// }
/// ```
///
/// Two rules, and both matter. Reaching the caller's OWN namespace decides on
/// the effective set, exactly as [`task_capable`] does — so a host-privileged
/// task is unaffected by any of this. Otherwise, a namespace strictly BENEATH
/// the caller's whose owner uid is the caller's euid grants every capability
/// inside it: that is what makes `unshare -Ur --uts hostname foo` work for a
/// user with no host privilege at all.
///
/// The depth comparison is not redundant with the walk. Without it a
/// namespace on an unrelated branch that happens to share an owner uid would
/// grant authority there too — privilege leaking sideways between sibling
/// containers owned by the same user, which is precisely what a user
/// namespace is supposed to prevent.
///
/// Walking upward terminates at the initial namespace, so an unprivileged
/// task can never acquire authority over the host by nesting.
#[cfg(feature = "container")]
pub(crate) fn task_ns_capable(
    task: u64,
    target: &crate::namespaces::UserNamespace,
    cap: u32,
) -> bool {
    if u64::from(cap) > CAP_LAST_CAP {
        return false;
    }
    let cred_ns = crate::namespaces::current_user_ns(task);
    let cred_level = cred_ns.level();
    // Host-absolute effective uid — `cred->euid` is a host id, and
    // `ns->owner` was recorded as one at creation.
    let cred_euid = read_uidgid(task).euid;
    let mut cursor: Option<&crate::namespaces::UserNamespace> = Some(target);
    while let Some(ns) = cursor {
        if ns.id() == cred_ns.id() {
            // The question is about the caller's own namespace, so the
            // effective set answers it directly. Recursing through
            // `task_capable` here would ask the HOST question instead and
            // deny every namespaced task.
            return cap_effective(task, cap);
        }
        if ns.is_initial() {
            return false;
        }
        if ns.level() > cred_level && ns.owner_uid() == cred_euid {
            return true;
        }
        cursor = ns.parent().map(|parent| &**parent);
    }
    false
}

/// [`task_ns_capable`] for the current task.
#[cfg(feature = "container")]
#[allow(dead_code)]
pub(crate) fn ns_capable(target: &crate::namespaces::UserNamespace, cap: u32) -> bool {
    task_ns_capable(current_task_id(), target, cap)
}

/// CAP_SYS_ADMIN with respect to `task`'s UTS namespace — the check
/// `sethostname`/`setdomainname` actually require
/// (`ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN)`).
///
/// Without the `container` feature there are no namespaces, so every resource
/// is the host's and the question collapses to plain `capable()`.
pub(crate) fn uts_admin(task: u64) -> bool {
    #[cfg(feature = "container")]
    {
        task_ns_capable(
            task,
            &crate::namespaces::current_uts_ns(task).owner_user_ns(),
            CAP_SYS_ADMIN,
        )
    }
    #[cfg(not(feature = "container"))]
    {
        task_capable(task, CAP_SYS_ADMIN)
    }
}

/// What `setns(2)`'s per-flavour `install` hook decided.
#[cfg(feature = "container")]
pub(crate) enum SetnsVerdict {
    Ok,
    Einval,
    Eperm,
}

/// The `install` preconditions for joining `held` — `kernel/nsproxy.c`'s
/// `validate_ns` dispatching to `utsns_install`, `ipcns_install`,
/// `netns_install`, `pidns_install`, `mntns_install` or `userns_install`.
///
/// Every flavour but user asks the SAME pair:
///
///     if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
///         !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN))
///             return -EPERM;
///
/// Both halves matter. The first is authority over the namespace being
/// JOINED — without it any task could walk into a container by opening its
/// /proc/<pid>/ns file. The second is authority in the caller's own
/// namespace, which is what stops a task that has dropped into an
/// unprivileged user namespace from using a namespace fd it still holds as a
/// way back out.
///
/// Two flavours differ, and both differences are load-bearing:
///
/// - mount adds `!ns_capable(user_ns, CAP_SYS_CHROOT)`. Joining a mount
///   namespace relocates the caller's root, so it demands the capability that
///   governs exactly that, not just CAP_SYS_ADMIN.
/// - user has no caller-namespace check at all, and instead rejects
///   re-entering the namespace it is already in:
///
///       /* Don't allow gaining capabilities by reentering
///        * the same user namespace.
///        */
///       if (user_ns == current_user_ns())
///               return -EINVAL;
///
///   That EINVAL is a security rule, not a tidiness one. `userns_install`
///   ends in `set_cred_user_ns`, which grants a FULL capability set; without
///   this check a task that had dropped its capabilities could re-enter its
///   own namespace to get them all back.
#[cfg(feature = "container")]
pub(crate) fn setns_install_check(caller: u64, held: &crate::namespaces::HeldNs) -> SetnsVerdict {
    use crate::namespaces::HeldNs;
    // `ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN)` — the caller's own.
    let own_admin = task_capable_in_own_ns(caller, CAP_SYS_ADMIN);
    // Authority over the namespace being joined. The `*Global` variants are
    // the initial namespaces, owned by the initial user namespace, so the
    // question there is the host one.
    let target_admin = match held {
        HeldNs::Uts(ns) => task_ns_capable(caller, &ns.owner_user_ns(), CAP_SYS_ADMIN),
        HeldNs::Net(ns) => task_ns_capable(caller, &ns.owner_user_ns(), CAP_SYS_ADMIN),
        HeldNs::Ipc(ns) => task_ns_capable(caller, &ns.owner_user_ns(), CAP_SYS_ADMIN),
        HeldNs::Pid(ns) => task_ns_capable(caller, &ns.owner_user_ns(), CAP_SYS_ADMIN),
        HeldNs::Mnt(ns) => match ns
            .owner()
            .and_then(|owner| {
                owner
                    .as_any()
                    .downcast_ref::<crate::namespaces::UserNamespace>()
            }) {
            Some(user_ns) => task_ns_capable(caller, user_ns, CAP_SYS_ADMIN),
            None => task_capable(caller, CAP_SYS_ADMIN),
        },
        HeldNs::User(ns) => task_ns_capable(caller, ns, CAP_SYS_ADMIN),
        #[cfg(feature = "cgroup")]
        HeldNs::Cgroup(ns) => match ns.owner().and_then(|owner| {
            owner
                .as_any()
                .downcast_ref::<crate::namespaces::UserNamespace>()
        }) {
            Some(user_ns) => task_ns_capable(caller, user_ns, CAP_SYS_ADMIN),
            None => task_capable(caller, CAP_SYS_ADMIN),
        },
        HeldNs::NetGlobal(_)
        | HeldNs::IpcGlobal(_)
        | HeldNs::PidGlobal(_)
        | HeldNs::MntGlobal(_) => task_capable(caller, CAP_SYS_ADMIN),
    };

    if let HeldNs::User(ns) = held {
        // `if (user_ns == current_user_ns()) return -EINVAL;`
        if ns.id() == crate::namespaces::current_user_ns(caller).id() {
            return SetnsVerdict::Einval;
        }
        // `if (!thread_group_empty(current)) return -EINVAL;` — a thread
        // group must share one user namespace.
        if !thread_group_empty(caller) {
            return SetnsVerdict::Einval;
        }
        // No caller-namespace check for this flavour.
        return if target_admin {
            SetnsVerdict::Ok
        } else {
            SetnsVerdict::Eperm
        };
    }

    let extra = match held {
        // `!ns_capable(user_ns, CAP_SYS_CHROOT)` — mount only.
        HeldNs::Mnt(_) | HeldNs::MntGlobal(_) => {
            task_capable_in_own_ns(caller, CAP_SYS_CHROOT)
        }
        _ => true,
    };
    if target_admin && own_admin && extra {
        // `pidns_install` performs this after both capability checks: a task
        // may select only its active PID namespace or a descendant for future
        // children. Joining a parent/sibling would let descendants escape.
        let pid_relation_ok = match held {
            HeldNs::Pid(ns) => crate::pid_ns::may_setns_for_children(caller, Some(ns)),
            HeldNs::PidGlobal(_) => crate::pid_ns::may_setns_for_children(caller, None),
            _ => true,
        };
        if !pid_relation_ok {
            return SetnsVerdict::Einval;
        }
        SetnsVerdict::Ok
    } else {
        SetnsVerdict::Eperm
    }
}

/// `ns_capable(__task_cred(p)->user_ns, cap)` — authority over ANOTHER task,
/// measured in THAT task's user namespace.
///
/// `kernel/sys.c::set_one_prio_perm` and `sched_setaffinity` both use this
/// shape, and the comment above the former says so outright: "or has
/// CAP_SYS_NICE to p's user_ns". Asking the host question instead would let
/// a host-privileged task renice a process inside a container it has no
/// authority over, and refuse a container's own root over its own processes.
pub(crate) fn capable_over_task(target: u64, cap: u32) -> bool {
    #[cfg(feature = "container")]
    {
        task_ns_capable(
            current_task_id(),
            &crate::namespaces::current_user_ns(target),
            cap,
        )
    }
    #[cfg(not(feature = "container"))]
    {
        let _ = target;
        task_capable(current_task_id(), cap)
    }
}

/// CAP_SYS_ADMIN with respect to `task`'s MOUNT namespace — the check
/// `mount(2)` requires (`fs/namespace.c::may_mount`):
///
///     return ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN);
///
/// A task that unshared a user namespace and then a mount namespace owns the
/// result and may mount inside it. A task in a user namespace still using the
/// HOST mount namespace may not — its owner is the initial user namespace,
/// which the walk refuses to reach.
pub(crate) fn mount_admin(task: u64) -> bool {
    #[cfg(feature = "container")]
    {
        let ns = current_mount_namespace();
        let owned = ns.as_ref().and_then(|ns| ns.owner()).and_then(|owner| {
            owner
                .as_any()
                .downcast_ref::<crate::namespaces::UserNamespace>()
        });
        match owned {
            Some(user_ns) => task_ns_capable(task, user_ns, CAP_SYS_ADMIN),
            // No recorded owner is the initial user namespace, which is
            // exactly the host question.
            None => task_capable(task, CAP_SYS_ADMIN),
        }
    }
    #[cfg(not(feature = "container"))]
    {
        task_capable(task, CAP_SYS_ADMIN)
    }
}

/// `capable()` for an explicit task — authority over the HOST.
///
/// `capable(cap)` is `ns_capable(&init_user_ns, cap)`, and `cap_capable`
/// walking to the initial namespace answers:
///
///     if (ns == &init_user_ns)
///             return -EPERM;
///
/// So a task in ANY non-initial user namespace has no host authority,
/// whatever its effective set says. That is what makes the full capability
/// set `unshare(CLONE_NEWUSER)` grants safe to hold: the caps are real, but
/// they buy nothing outside the namespace they are bound to. Testing the
/// effective set alone here would turn that grant into a host privilege
/// escalation available to any unprivileged process.
pub(crate) fn task_capable(task: u64, cap: u32) -> bool {
    #[cfg(feature = "container")]
    {
        if !crate::namespaces::current_user_ns(task).is_initial() {
            return false;
        }
    }
    cap_effective(task, cap)
}

/// The raw `cap_raised(cred->cap_effective, cap)` test, with no namespace
/// scoping. Only the two functions that have ALREADY established which
/// namespace the question is about may use it.
fn cap_effective(task: u64, cap: u32) -> bool {
    if u64::from(cap) > CAP_LAST_CAP {
        return false;
    }
    read_caps(task).effective & (1u64 << cap) != 0
}

/// `ns_capable(current_user_ns(), cap)` for an explicit task — authority over
/// resources the task's OWN user namespace governs (its credentials, its
/// root directory, the namespaces it unshares).
///
/// The walk matches at its first arm, so this is the effective set — but it
/// is the effective set for a reason that survives `capable()` becoming
/// host-scoped, which the bare test would not.
pub(crate) fn task_capable_in_own_ns(task: u64, cap: u32) -> bool {
    #[cfg(feature = "container")]
    {
        task_ns_capable(task, &crate::namespaces::current_user_ns(task), cap)
    }
    #[cfg(not(feature = "container"))]
    {
        cap_effective(task, cap)
    }
}

/// [`task_capable_in_own_ns`] for the current task.
pub(crate) fn capable_in_own_ns(cap: u32) -> bool {
    task_capable_in_own_ns(current_task_id(), cap)
}

/// `security/commoncap.c::cap_emulate_setxuid` — make the capability sets
/// follow a uid change.
///
/// ```text
/// if ((old->uid == 0 || old->euid == 0 || old->suid == 0) &&
///     (new->uid != 0 && new->euid != 0 && new->suid != 0)) {
///         if (!issecure(SECURE_KEEP_CAPS)) {
///                 cap_clear(new->cap_permitted);
///                 cap_clear(new->cap_effective);
///         }
///         cap_clear(new->cap_ambient);
/// }
/// if (old->euid == 0 && new->euid != 0)  cap_clear(new->cap_effective);
/// if (old->euid != 0 && new->euid == 0)  new->cap_effective = new->cap_permitted;
/// ```
///
/// This is what makes "drop to an unprivileged uid" actually drop
/// privilege, and it became load-bearing the moment DAC stopped testing
/// `uid == 0` and started testing CAP_DAC_OVERRIDE. Without it a service
/// that called `setuid(1000)` would keep every capability it held and so
/// keep bypassing DAC — the old code got the right ANSWER here for the
/// wrong reason, because uid was the only thing it looked at.
///
/// Note the last clause is a RAISE: returning the effective euid to 0
/// restores effective from permitted, which is how a set-uid-root helper
/// regains its powers after temporarily dropping them.
///
/// `SECURE_KEEP_CAPS` is honored through the per-task `keep_caps` flag that
/// `PR_SET_KEEPCAPS` maintains: a task that asked to keep its capabilities
/// across a uid change retains its permitted/effective sets, exactly as
/// `!issecure(SECURE_KEEP_CAPS)` gates the clear in Linux. Ambient is
/// cleared regardless, matching `cap_clear(new->cap_ambient)` which sits
/// OUTSIDE the securebit test.
///
/// This is the privilege-drop dance a launcher like `dbus-broker-launch`
/// runs — `PR_SET_KEEPCAPS(1); capset; setresuid(nonroot);
/// PR_SET_KEEPCAPS(0); capset` — to hand the broker a single retained
/// capability (CAP_AUDIT_WRITE under `--audit`). Without the gate the
/// second `capset` saw an emptied permitted set and returned EPERM, so the
/// broker child aborted, the system bus never came up, and logind
/// fail-looped — no graphical session.
///
/// LINUX-GAP: `SECURE_NO_SETUID_FIXUP` (which suppresses this fixup
/// entirely) is not modelled; it defaults off, so the fixup still runs.
fn cap_emulate_setxuid(task: u64, old: UidGid, new: UidGid) {
    let was_root = old.uid == 0 || old.euid == 0 || old.suid == 0;
    let is_root = new.uid == 0 || new.euid == 0 || new.suid == 0;
    let mut caps = read_caps(task);
    let mut changed = false;
    if was_root && !is_root {
        if !read_prctl(task).keep_caps {
            caps.permitted = 0;
            caps.effective = 0;
        }
        caps.ambient = 0;
        changed = true;
    }
    if old.euid == 0 && new.euid != 0 {
        caps.effective = 0;
        changed = true;
    }
    if old.euid != 0 && new.euid == 0 {
        caps.effective = caps.permitted;
        changed = true;
    }
    if changed {
        write_caps(task, caps);
    }
}

/// `security/commoncap.c::handle_privileged_root` — the half of
/// `cap_bprm_creds_from_file` that makes a set-user-ID-**root** binary
/// actually privileged.
///
/// Without it a setuid-root exec would move euid to 0 and stop there, and
/// on a task that had already dropped root the permitted set is empty, so
/// the new program would be "root" with no capabilities — the one state
/// Linux never leaves a process in.
///
/// ```text
/// if (__is_eff(root_uid, new) || __is_real(root_uid, new)) {
///         /* pP' = (cap_bset & ~0) | (pI & ~0) */
///         new->cap_permitted = cap_combine(old->cap_bset, old->cap_inheritable);
/// }
/// if (__is_eff(root_uid, new))
///         *effective = true;
/// ```
///
/// The permitted set is REGENERATED from the bounding set rather than
/// inherited, which is what lets an unprivileged caller gain privilege
/// through a setuid-root binary at all. The effective set follows only
/// when the EFFECTIVE uid is root: a binary that merely leaves the real
/// uid at 0 gets the permissions but must raise them itself.
fn cap_exec_privileged_root(task: u64, new_ids: UidGid) {
    if new_ids.euid != 0 && new_ids.uid != 0 {
        return;
    }
    let mut caps = read_caps(task);
    caps.permitted = caps.bounding | caps.inheritable;
    if new_ids.euid == 0 {
        caps.effective = caps.permitted;
    }
    write_caps(task, caps);
}

/// `fs/exec.c::bprm_fill_uid` — the set-user-ID / set-group-ID transition
/// an `execve` of a privileged binary performs.
///
/// Every guard here is load-bearing, because this is the one place in the
/// tree where an unprivileged task can gain privilege:
///
///   * `mnt_may_suid` — a `nosuid` mount confers nothing. That is what
///     the flag is FOR, and until this existed there was nothing for it
///     to suppress.
///   * `task_no_new_privs` — a task that asked to be unable to gain
///     privilege does not gain it. One-way, so a sandbox cannot be
///     talked out of it.
///   * the execute permission is re-checked (`inode_permission(MAY_EXEC)`)
///     so a binary that lost its exec bit between the open and here
///     confers nothing.
///   * S_ISGID alone does nothing; Linux requires `S_ISGID | S_IXGRP`
///     together, because S_ISGID without group-execute is the mandatory
///     file-locking marker, not a privilege request.
///
/// Returns the new credential when a transition happened.
fn bprm_fill_uid(task: u64, path: &str, from_script: bool) -> Option<UidGid> {
    // Linux ignores the set-user-ID bits on a `#!` script: the kernel
    // executes the INTERPRETER, and honouring the script's bits would hand
    // its privilege to an interpreter that was never audited for it. NARF
    // resolves the shebang itself, so the equivalent is to confer nothing
    // once a shebang has been followed.
    if from_script {
        return None;
    }
    if narf_filesystem::any_restricted_mounts()
        && current_mount_flags_at(path) & narf_filesystem::mnt_flags::NOSUID != 0
    {
        return None;
    }
    if read_prctl(task).no_new_privs {
        return None;
    }
    let file = resolve_file_absolute_ext(path, true)?;
    let stat = file.stat();
    let mode = stat.mode.perms;
    if mode & 0o6000 == 0 {
        return None;
    }
    let (file_uid, file_gid) = file.owners();
    // "Did the exec bit vanish out from under us? Give up."
    let permitted = narf_filesystem::posix_access_ok(
        narf_filesystem::FileOwner {
            uid: file_uid,
            gid: file_gid,
            perms: mode,
            is_dir: false,
        },
        &accessor_for_inode(task, file_uid, file_gid),
        narf_filesystem::AccessRequest {
            read: false,
            write: false,
            exec: true,
        },
    );
    if !permitted {
        return None;
    }
    let old = read_uidgid(task);
    let mut new = old;
    if mode & 0o4000 != 0 {
        new.euid = file_uid;
    }
    // `(mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)`.
    if mode & 0o2010 == 0o2010 {
        new.egid = file_gid;
    }
    if new.euid == old.euid && new.egid == old.egid {
        return None;
    }
    // `commit_creds` keeps the filesystem ids in step with the effective
    // ones; every DAC decision reads fsuid/fsgid, so leaving them behind
    // would grant the privilege for `access()` and deny it for `open()`.
    new.fsuid = new.euid;
    new.fsgid = new.egid;
    // The saved set-ids record where the privilege came from, which is how
    // a setuid program drops and regains it (`seteuid` back to `suid`).
    new.suid = new.euid;
    new.sgid = new.egid;
    write_uidgid(task, |e| *e = new);
    cap_exec_privileged_root(task, new);
    Some(new)
}

/// Linux `CAP_FSETID` — "don't clear set-user-ID and set-group-ID mode
/// bits when a file is modified".
pub(crate) const CAP_FSETID: u32 = 4;

/// Linux `CAP_MKNOD` — "create special files using mknod(2)".
pub(crate) const CAP_MKNOD: u32 = 27;

/// Linux `CAP_LINUX_IMMUTABLE` — "set the FS_APPEND_FL and
/// FS_IMMUTABLE_FL inode flags".
pub(crate) const CAP_LINUX_IMMUTABLE: u32 = 9;

/// The immutable / append-only refusals the VFS makes on an inode's
/// `chattr` flags, in one place because Linux asks the same question from
/// six different call sites (`inode_permission`, `may_delete`,
/// `may_setattr`, `may_write_xattr`, `vfs_link`, `do_truncate`).
///
/// `write` selects `inode_permission`'s rule — "Nobody gets write access
/// to an immutable file" — which holds for root as well; that is the
/// whole point of `chattr +i`. Append-only is the weaker form: the data
/// may grow but never be rewritten, so a non-appending write is refused
/// while an appending one is not.
fn immutable_check(flags: u32, write: bool, appending: bool) -> Result<(), i64> {
    if flags & narf_filesystem::FS_IMMUTABLE_FL != 0 {
        return Err(-1); // -EPERM
    }
    if write && !appending && flags & narf_filesystem::FS_APPEND_FL != 0 {
        return Err(-1);
    }
    Ok(())
}

/// The `chattr` flags of the inode at `path`, or 0 when nothing there
/// models them.
fn path_inode_flags(path: &str) -> u32 {
    resolve_file_absolute_ext(path, true)
        .map(|file| file.inode_flags())
        .unwrap_or(0)
}

/// `fs/attr.c::setattr_should_drop_suidgid`, applied by
/// `file_remove_privs` on every write and by `do_truncate`:
///
/// ```text
/// /* suid always must be killed */
/// if (unlikely(mode & S_ISUID))
///         kill = ATTR_KILL_SUID;
/// kill |= setattr_should_drop_sgid(idmap, inode);
/// if (unlikely(kill && !capable(CAP_FSETID) && S_ISREG(mode)))
///         return kill;
/// ```
///
/// and `setattr_should_drop_sgid`, which spares an S_ISGID that is the
/// mandatory-locking marker (no group-execute) held by someone in the
/// file's own group:
///
/// ```text
/// if (!(mode & S_ISGID))  return 0;
/// if (mode & S_IXGRP)     return ATTR_KILL_SGID;
/// if (!in_group_or_capable(idmap, inode, i_gid_into_vfsgid(idmap, inode)))
///                         return ATTR_KILL_SGID;
/// return 0;
/// ```
///
/// This became load-bearing the moment set-user-ID execution started
/// working: without it, anyone who can write a set-user-ID-root binary
/// keeps it set-user-ID-root, which turns "can modify this file" into
/// "can become root".
fn file_remove_privs(file: &dyn narf_filesystem::FileOps, task: u64) {
    let stat = file.stat();
    // "!S_ISREG(inode->i_mode)" — only regular files carry these as
    // privilege, and only they are stripped.
    if stat.mode.file_type != narf_filesystem::FileType::File {
        return;
    }
    let mode = stat.mode.perms;
    if mode & 0o6000 == 0 {
        return;
    }
    let (uid, gid) = file.owners();
    let mut kill = 0u16;
    if mode & 0o4000 != 0 {
        kill |= 0o4000;
    }
    if mode & 0o2000 != 0 && (mode & 0o010 != 0 || !in_group_or_capable(task, uid, gid)) {
        kill |= 0o2000;
    }
    if kill == 0 {
        return;
    }
    // A CAP_FSETID holder keeps the bits — that is the capability's entire
    // definition.
    if capable_wrt_inode(task, uid, gid, CAP_FSETID) {
        return;
    }
    let _ = poll_blocking(file.set_perms(mode & !kill));
}

/// `fs/inode.c::in_group_or_capable` — is the caller in the file's group,
/// or privileged enough over it to act as if it were?
///
/// ```text
/// if (vfsgid_in_group_p(vfsgid)) return true;
/// if (capable_wrt_inode_uidgid(idmap, inode, CAP_FSETID)) return true;
/// return false;
/// ```
/// [`in_group_or_capable`] for callers outside this file.
pub(crate) fn task_in_group_or_capable(task: u64, file_uid: u32, file_gid: u32) -> bool {
    in_group_or_capable(task, file_uid, file_gid)
}

fn in_group_or_capable(task: u64, file_uid: u32, file_gid: u32) -> bool {
    let ids = read_uidgid(task);
    if ids.fsgid == file_gid || read_groups(task).contains(&file_gid) {
        return true;
    }
    capable_wrt_inode(task, file_uid, file_gid, CAP_FSETID)
}

/// Test window onto [`bprm_fill_uid`]. A full `execve` needs a loadable
/// image and a task switch, neither of which the ABI harness can stage, so
/// the smoke drives the DECISION — which is the part that decides whether
/// privilege is granted — directly.
///
/// Returns `(euid, egid, fsuid, effective caps)` after the call, so a test
/// can assert both the credential transition and the capability
/// regeneration a setuid-root binary depends on.
#[doc(hidden)]
pub fn __test_bprm_fill_uid(task: u64, path: &str, from_script: bool) -> (u32, u32, u32, u64) {
    let _ = bprm_fill_uid(task, path, from_script);
    let ids = read_uidgid(task);
    (ids.euid, ids.egid, ids.fsuid, read_caps(task).effective)
}

/// Fork inherits all five sets unchanged (`kernel/fork.c` copies the
/// parent's `struct cred` wholesale; capabilities are transformed at
/// EXECVE, not at fork).
fn cap_fork(parent: u64, child: u64) {
    let inherited = read_caps(parent);
    write_caps(child, inherited);
}

/// `security/commoncap.c::cap_capset` — the rules that make a capability
/// credential trustworthy rather than merely stored.
///
/// ```text
/// if (!cap_issubset(*inheritable, cap_combine(old->cap_inheritable,
///                                             old->cap_permitted)))
///         return -EPERM;          /* (when cap_inh_is_capped()) */
/// if (!cap_issubset(*inheritable, cap_combine(old->cap_inheritable,
///                                             old->cap_bset)))
///         return -EPERM;          /* no new pI outside the bounding set */
/// if (!cap_issubset(*permitted, old->cap_permitted))
///         return -EPERM;          /* pP may only ever SHRINK */
/// if (!cap_issubset(*effective, *permitted))
///         return -EPERM;          /* pE must be within the new pP */
/// new->cap_ambient = cap_intersect(new->cap_ambient,
///                                  cap_intersect(*permitted, *inheritable));
/// ```
///
/// `!cap_issubset(*permitted, old->cap_permitted)` is the load-bearing
/// line. Without it a task can hand itself any capability it likes, so
/// gating a syscall on `capable()` would be defeated by calling
/// `capset` first — enforcement that looks real and is not, which is
/// strictly worse than an honest unenforced note.
///
/// Returns the new credential, or `Err(EPERM)`.
fn cap_capset(old: Caps, effective: u64, permitted: u64, inheritable: u64) -> Result<Caps, i64> {
    const EPERM: i64 = 1;
    let subset = |a: u64, b: u64| a & !b == 0;
    // `cap_inh_is_capped()` is 1 on any kernel without SECURE_NO_CAP_AMBIENT
    // relaxation, which is the configuration NARF models.
    if !subset(inheritable, old.inheritable | old.permitted) {
        return Err(EPERM);
    }
    if !subset(inheritable, old.inheritable | old.bounding) {
        return Err(EPERM);
    }
    if !subset(permitted, old.permitted) {
        return Err(EPERM);
    }
    if !subset(effective, permitted) {
        return Err(EPERM);
    }
    Ok(Caps {
        effective,
        permitted,
        inheritable,
        bounding: old.bounding,
        ambient: old.ambient & permitted & inheritable,
    })
}

/// Initialise the per-task capability registry. An empty map means every
/// task reads [`Caps::boot`], which is the boot task's credential — see
/// `read_caps` for why the default is the full set rather than the empty
/// one.
pub fn caps_init() {
    *CAP_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
pub fn __test_caps_reset() {
    *CAP_TABLE.lock() = Some(BTreeMap::new());
}

/// Test-only: move a task's EFFECTIVE uid, so a case can exercise the
/// "not your process" arm of `set_one_prio_perm` without a second live
/// credential context.
#[doc(hidden)]
pub fn __test_set_uidgid_euid(task: u64, euid: u32) {
    let _ = write_uidgid(task, |e| {
        e.uid = euid;
        e.euid = euid;
    });
}

/// Test-only: run the fork credential inheritance directly, without
/// spawning a task.
#[doc(hidden)]
pub fn __test_cap_fork(parent: u64, child: u64) {
    cap_fork(parent, child);
}

/// Test-only: run the setuid capability fixup with explicit `(uid, euid,
/// suid)` old/new credentials. A real `setresuid` would strand FAKE_TASK
/// at a non-root uid for every later test; this drives the fixup directly
/// (it only writes the caps table) so the KEEP_CAPS retention path is
/// exercisable in isolation.
#[doc(hidden)]
pub fn __test_cap_emulate_setxuid(task: u64, old: (u32, u32, u32), new: (u32, u32, u32)) {
    let mk = |t: (u32, u32, u32)| UidGid {
        uid: t.0,
        euid: t.1,
        suid: t.2,
        ..Default::default()
    };
    cap_emulate_setxuid(task, mk(old), mk(new));
}

/// Test-only: [`task_capable`] for an explicit task.
#[doc(hidden)]
pub fn __test_task_capable(task: u64, cap: u32) -> bool {
    task_capable(task, cap)
}

/// Test-only: [`task_ns_capable`] for an explicit task and target user ns.
#[doc(hidden)]
#[cfg(feature = "container")]
pub fn __test_task_ns_capable(
    task: u64,
    target: &crate::namespaces::UserNamespace,
    cap: u32,
) -> bool {
    task_ns_capable(task, target, cap)
}

/// Test-only: [`uts_admin`] for an explicit task.
#[doc(hidden)]
pub fn __test_uts_admin(task: u64) -> bool {
    uts_admin(task)
}

/// `kernel/user_namespace.c::set_cred_user_ns` — rebind `task`'s credentials
/// to a freshly created user namespace.
///
/// ```text
/// cred->securebits = SECUREBITS_DEFAULT;
/// cred->cap_inheritable = CAP_EMPTY_SET;
/// cred->cap_permitted = CAP_FULL_SET;
/// cred->cap_effective = CAP_FULL_SET;
/// cred->cap_ambient = CAP_EMPTY_SET;
/// cred->cap_bset = CAP_FULL_SET;
/// ```
///
/// The comment above it in Linux — "Start with the same capabilities as init
/// but useless for doing anything as the capabilities are bound to the new
/// user namespace" — is the whole design. THIS is what makes an unprivileged
/// `unshare -Ur` able to administer what it creates; the owner rule in
/// `cap_capable` covers a different case (a task looking at a namespace
/// beneath its own).
///
/// The grant is only sound because [`task_capable`] is host-scoped: these
/// capabilities are real inside the new namespace and worth nothing outside
/// it. Inheritable and ambient are deliberately CLEARED — a full set that
/// survived an execve into a setuid-root binary would carry namespace-bound
/// authority somewhere it was never meant to reach.
#[cfg(feature = "container")]
fn set_cred_user_ns_caps(task: u64) {
    write_caps(
        task,
        Caps {
            effective: CAP_FULL_SET,
            permitted: CAP_FULL_SET,
            inheritable: 0,
            bounding: CAP_FULL_SET,
            ambient: 0,
        },
    );
}

/// Test-only: install an explicit credential for `task`, so a case can
/// exercise an UNPRIVILEGED path (the default is [`Caps::boot`]).
#[doc(hidden)]
pub fn __test_set_caps(task: u64, effective: u64, permitted: u64) {
    write_caps(
        task,
        Caps {
            effective,
            permitted,
            inheritable: 0,
            bounding: CAP_FULL_SET,
            ambient: 0,
        },
    );
}

/// Data-element count for a capability version; None if unsupported.
fn cap_ndata(version: u32) -> Option<usize> {
    match version {
        CAP_VERSION_1 => Some(1),
        CAP_VERSION_2 | CAP_VERSION_3 => Some(2),
        _ => None,
    }
}

// ── setxattr / getxattr / listxattr ──────────────────────────────────
//
// Extended attributes, stored in a side table keyed by (resolved path,
// attribute name). NARF's in-memory FSes have no on-disk xattr store,
// so this gives a faithful round-trip without touching the inodes.

/// `(path, name) -> value` extended-attribute store.
#[allow(clippy::type_complexity)]
static XATTR_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<
        alloc::collections::BTreeMap<
            (alloc::string::String, alloc::string::String),
            alloc::vec::Vec<u8>,
        >,
    >,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

const XATTR_CREATE: u64 = 1;
const XATTR_REPLACE: u64 = 2;

/// Resolve the fd argument of an `f*xattr` syscall to a side-table key.
/// NARF has no fd→pathname cache yet, so `fd_path_of` returns a stable
/// per-fd `anon_inode:[Type]` placeholder: `f*xattr` calls round-trip
/// against each other on the same fd, but do NOT share storage with the
/// path-keyed `*xattr` family (a documented limitation).
fn xattr_fd_key(fd: u32) -> Option<alloc::string::String> {
    fd_path_string_of(current_task_id(), fd)
}

/// `AT_*` bits the xattr `*at` syscalls accept.
const XATTR_AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const XATTR_AT_EMPTY_PATH: u32 = 0x1000;
const XATTR_AT_FDCWD: i64 = -100;

/// The `(dfd, pathname, at_flags)` prologue shared by all four xattr `*at`
/// syscalls, and by the twelve legacy entry points that are presets of them.
///
/// `fs/xattr.c::path_setxattrat` and its three siblings all open the same
/// way:
///
/// ```text
/// if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
///         return -EINVAL;
/// if (!(at_flags & AT_SYMLINK_NOFOLLOW))
///         lookup_flags = LOOKUP_FOLLOW;
/// CLASS(filename_maybe_null, filename)(pathname, at_flags);
/// if (!filename && dfd >= 0) { ... file_setxattr(fd_file(f), &ctx); }
/// else { ... filename_setxattr(dfd, filename, lookup_flags, &ctx); }
/// ```
///
/// `filename_maybe_null` is what makes a NULL pathname legal, and only with
/// AT_EMPTY_PATH; the `dfd >= 0` guard is why `AT_FDCWD` with a NULL path
/// still takes the path branch (and fails there) rather than silently
/// operating on the cwd.
///
/// Returns the resolved absolute path (or the `f*xattr` fd key) together
/// with the `follow_final` the caller must hand to the core.
fn xattr_at_path(dfd: i64, path_ptr: u64, at_flags: u32) -> Result<(alloc::string::String, bool), i64> {
    if at_flags & !(XATTR_AT_SYMLINK_NOFOLLOW | XATTR_AT_EMPTY_PATH) != 0 {
        return Err(XE_INVAL);
    }
    let follow = at_flags & XATTR_AT_SYMLINK_NOFOLLOW == 0;
    // A NULL pathname is `filename_maybe_null` returning NULL, which is only
    // legal with AT_EMPTY_PATH; an empty STRING reaches the same arm because
    // `getname_flags` maps "" + AT_EMPTY_PATH to it too.
    let empty = if path_ptr == 0 {
        if at_flags & XATTR_AT_EMPTY_PATH == 0 {
            // `getname` on a NULL pointer is -EFAULT.
            return Err(XE_FAULT);
        }
        true
    } else {
        let raw = copy_user_cstr(path_ptr, 4096).ok_or(XE_FAULT)?;
        if raw.is_empty() {
            if at_flags & XATTR_AT_EMPTY_PATH == 0 {
                // `getname` rejects "" without AT_EMPTY_PATH: -ENOENT.
                return Err(-2);
            }
            true
        } else {
            let task = current_task_id();
            let anchored = apply_chroot(&resolve_at_path(task, dfd, &raw)?);
            // The VFS-level symlink walk, exactly as `open` runs it:
            //
            //   resolve_vfs_symlink_path(&path_owned, flags & O_NOFOLLOW == 0)
            //
            // This is where LOOKUP_FOLLOW actually lives. It has the mount
            // table, so it can follow an ABSOLUTE symlink target out of the
            // filesystem the link sits on — which the in-filesystem resolver
            // cannot, since it restarts such a target at its own mount root.
            // Every absolute target (`/usr/bin/awk` -> `/etc/alternatives/awk`,
            // and every `/lib` -> `/usr/lib` merge) depends on that.
            //
            // `unwrap_or` keeps a path the walk could not resolve: the xattr
            // core reports the real errno for a missing name, and swallowing
            // it here would turn every ENOENT into a resolution failure.
            let resolved = resolve_vfs_symlink_path(&anchored, follow).unwrap_or(anchored);
            return Ok((resolved, follow));
        }
    };
    debug_assert!(empty);
    // The fd branch. `dfd >= 0` is Linux's guard: AT_FDCWD here is not a
    // descriptor, so it cannot name a file and falls through to the path
    // branch, which has no path — -EBADF.
    if dfd < 0 || dfd == XATTR_AT_FDCWD {
        return Err(XE_BADF);
    }
    // Same side-table key the `f*xattr` family uses, so an AT_EMPTY_PATH
    // call and an `f*xattr` call on the same descriptor address the same
    // attributes. (Both are separate from the path-keyed family — see
    // `xattr_fd_key`.)
    xattr_fd_key(dfd as u32)
        .map(|key| (key, follow))
        .ok_or(XE_BADF)
}

/// `struct xattr_args` (`include/uapi/linux/xattr.h`), read with
/// `copy_struct_from_user`'s extensible-struct rules.
///
/// ```text
/// struct xattr_args { __aligned_u64 value; __u32 size; __u32 flags; };
/// #define XATTR_ARGS_SIZE_VER0 16
/// ```
///
/// `setxattrat`/`getxattrat` take this rather than a flat argument list so
/// the struct can grow. The size handling is the part worth getting right,
/// because it is what lets an OLD kernel refuse a NEW caller safely:
///
/// ```text
/// if (unlikely(usize < XATTR_ARGS_SIZE_VER0)) return -EINVAL;
/// if (usize > PAGE_SIZE)                      return -E2BIG;
/// error = copy_struct_from_user(&args, sizeof(args), uargs, usize);
/// ```
///
/// and `copy_struct_from_user` itself requires every byte PAST the struct
/// this kernel knows to be zero, answering -E2BIG when it is not. That is
/// the safety property: a caller who sets a field this kernel would ignore
/// is told so instead of having it silently dropped.
fn xattr_args_from_user(uargs: u64, usize_bytes: u64) -> Result<(u64, u32, u32), i64> {
    const VER0: u64 = 16;
    const PAGE: u64 = 4096;
    if usize_bytes < VER0 {
        return Err(XE_INVAL);
    }
    if usize_bytes > PAGE {
        return Err(XE_2BIG);
    }
    let mut buf = [0u8; VER0 as usize];
    // SAFETY: `copy_from_user` range-validates `uargs` and brackets the
    // 16-byte read; the buffer is exactly VER0 bytes.
    if unsafe { copy_from_user(&mut buf, uargs) }.is_err() {
        return Err(XE_FAULT);
    }
    // `check_zeroed_user` over the tail this kernel does not know about.
    if usize_bytes > VER0 {
        let rest = (usize_bytes - VER0) as usize;
        // SAFETY: the tail lies inside the caller-declared struct, which
        // `copy_from_user_vec` range-validates before reading.
        let tail = match unsafe { copy_from_user_vec(uargs + VER0, rest) } {
            Ok(v) => v,
            Err(_) => return Err(XE_FAULT),
        };
        if tail.iter().any(|&b| b != 0) {
            return Err(XE_2BIG);
        }
    }
    let value = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
    let size = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
    let flags = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
    Ok((value, size, flags))
}

// ── VFS-level xattr checks (fs/xattr.c) ──────────────────────────────
//
// These run BEFORE the filesystem is consulted, and in Linux's order, so
// the errno a caller sees does not depend on which filesystem the path
// landed on.

/// `XATTR_NAME_MAX + 1` — the `struct xattr_name` buffer `import_xattr_name`
/// copies into.
const XATTR_NAME_BUF: usize = 256;
/// `XATTR_SIZE_MAX` (include/uapi/linux/limits.h).
const XATTR_SIZE_MAX: usize = 65536;

/// `fs/xattr.c::import_xattr_name`.
///
/// `strncpy_from_user` into a 256-byte buffer, then:
///
/// ```text
/// if (error == 0 || error == sizeof(kname->name))
///         return -ERANGE;
/// ```
///
/// So an EMPTY name and a name that fills the buffer are both **ERANGE**,
/// not EINVAL — `getfattr -n ''` gets "Numerical result out of range", and
/// a caller testing for ERANGE to grow a buffer must not be told EINVAL.
fn xattr_import_name(ptr: u64) -> Result<alloc::string::String, i64> {
    // `copy_user_cstr_checked` keeps the two failures apart the way
    // `strncpy_from_user` does: a bad pointer is EFAULT (14), a string that
    // fills the buffer with no terminator is "too long" (36). Only the
    // latter is `error == sizeof(kname->name)`, and an xattr name reports
    // it as ERANGE rather than the ENAMETOOLONG a pathname would.
    const TOO_LONG: i64 = 36;
    match copy_user_cstr_checked(ptr, XATTR_NAME_BUF) {
        Ok(name) if !name.is_empty() => Ok(name),
        Ok(_) | Err(TOO_LONG) => Err(XE_RANGE),
        Err(_) => Err(XE_FAULT),
    }
}

/// `fs/xattr.c::xattr_resolve_name` + `xattr_permission`, for the handler
/// set every NARF filesystem with xattrs presents (`security`, `trusted`,
/// `user`, and `system` for the two POSIX ACL names).
///
/// `write` selects Linux's asymmetry: a namespace the caller may not touch
/// answers `-EPERM` to a set/remove and `-ENODATA` to a get, so a
/// `getxattr` can never be used to probe for the existence of an attribute
/// the caller is not allowed to read.
fn xattr_namespace_ok(name: &str, write: bool) -> Result<(), i64> {
    if name.starts_with("security.") {
        return Ok(());
    }
    // `xattr_permission` waves `system.*` through to the filesystem, but on
    // every filesystem NARF has the only `system.*` handlers are the two
    // POSIX ACL names; anything else fails to resolve to a handler, which
    // is `xattr_resolve_name`'s -EOPNOTSUPP.
    if name.starts_with("system.") {
        return if is_acl_xattr(name) {
            Ok(())
        } else {
            Err(XE_OPNOTSUPP)
        };
    }
    if name.starts_with("trusted.") {
        // "The trusted.* namespace can only be accessed by privileged
        // users."
        if !capable(CAP_SYS_ADMIN) {
            return Err(if write { XE_PERM } else { XE_NODATA });
        }
        return Ok(());
    }
    if name.starts_with("user.") {
        return Ok(());
    }
    // No handler for this prefix: `xattr_resolve_name` returns -EOPNOTSUPP.
    Err(XE_OPNOTSUPP)
}

// Negative errno values for the xattr family, as the syscall return
// convention wants them. Prefixed so they cannot be confused with the
// positive-errno constants elsewhere in this file.
const XE_RANGE: i64 = -34;
const XE_NODATA: i64 = -61;
const XE_OPNOTSUPP: i64 = -95;
const XE_PERM: i64 = -1;
const XE_2BIG: i64 = -7;
const XE_EXIST: i64 = -17;
const XE_INVAL: i64 = -22;
const XE_FAULT: i64 = -14;
const XE_ACCES: i64 = -13;
const XE_NOSPC: i64 = -28;
const XE_DQUOT: i64 = -122;
const XE_IO: i64 = -5;
const XE_BADF: i64 = -9;

/// Map an `FsError` from an xattr operation onto Linux's errno.
///
/// `Unsupported` is the one that must NOT be translated here: it means the
/// backing filesystem has no xattr store, and the caller falls through to
/// the generic side table instead.
fn xattr_errno(error: narf_filesystem::FsError) -> Option<i64> {
    use narf_filesystem::FsError;
    Some(match error {
        FsError::Unsupported => return None,
        // `simple_xattr_set`: XATTR_CREATE on an existing attribute.
        FsError::Busy => XE_EXIST,
        FsError::NotFound => XE_NODATA,
        // `xattr_permission`: `user.*` on an inode that is neither a
        // regular file nor a directory.
        FsError::OperationNotPermitted => XE_PERM,
        FsError::PermissionDenied => XE_ACCES,
        // `shmem_xattr_handler_set` when the mount's inode space is gone.
        FsError::NoSpace => XE_NOSPC,
        FsError::QuotaExceeded => XE_DQUOT,
        FsError::InvalidData => XE_INVAL,
        _ => XE_IO,
    })
}

/// `fs/inode.c::inode_owner_or_capable`:
///
/// ```text
/// if (vfsuid_eq_kuid(i_uid_into_vfsuid(idmap, inode), current_fsuid()))
///         return true;
/// ns = current_user_ns();
/// if (vfsuid_has_mapping(ns, vfsuid) && ns_capable(ns, CAP_FOWNER))
///         return true;
/// return false;
/// ```
///
/// "You own it, or you hold CAP_FOWNER over it." This is the gate on
/// changing an inode's ACL, and NARF had none: any task that could reach
/// an inode could rewrite its access ACL — and with it, since
/// `posix_acl_update_mode` writes the mode back, its permission bits.
fn inode_owner_or_capable(task: u64, file_uid: u32, file_gid: u32) -> bool {
    if current_host_fsuid(task) == file_uid {
        return true;
    }
    capable_wrt_inode(task, file_uid, file_gid, CAP_FOWNER)
}

/// The inode an xattr call names. A directory is an inode with extended
/// attributes, but path resolution hands back `DirOps` for one, so the
/// `FileOps` form alone can never see it.
pub(crate) enum XattrTarget {
    File(alloc::sync::Arc<dyn narf_filesystem::FileOps>),
    Dir(alloc::sync::Arc<dyn narf_filesystem::DirOps>),
}

impl XattrTarget {
    /// `(uid, gid, perms, is_dir)` — everything `xattr_permission` needs.
    fn meta(&self) -> (u32, u32, u16, bool) {
        match self {
            Self::File(file) => {
                let (uid, gid) = file.owners();
                (uid, gid, file.stat().mode.perms, false)
            }
            Self::Dir(dir) => {
                let (uid, gid) = dir.dir_owners();
                (uid, gid, dir.dir_mode(), true)
            }
        }
    }

    fn access_acl(&self) -> Option<narf_filesystem::PosixAcl> {
        let fetched = match self {
            Self::File(file) => poll_blocking(narf_filesystem::acl_of_file(
                file.as_ref(),
                narf_filesystem::AclType::Access,
            )),
            Self::Dir(dir) => poll_blocking(narf_filesystem::acl_of_dir(
                dir.as_ref(),
                narf_filesystem::AclType::Access,
            )),
        };
        fetched.and_then(|r| r.ok()).flatten()
    }
}

/// Resolve `path` to the inode an xattr call should act on, file or
/// directory, in ONE walk.
fn xattr_target(path: &str) -> Option<XattrTarget> {
    if let Some(file) = xattr_file(path) {
        return Some(XattrTarget::File(file));
    }
    resolve_dir_absolute(path).map(XattrTarget::Dir)
}

/// The permission gate for one xattr operation on one inode.
///
/// The two name classes take different routes in Linux, and conflating
/// them gets the answer wrong in both directions. `do_setxattr` sends the
/// POSIX ACL names to `do_set_acl` -> `vfs_set_acl` -> `set_posix_acl`,
/// whose only check is `inode_owner_or_capable` (EPERM) — write permission
/// on the inode is neither required nor sufficient. Everything else goes
/// through `vfs_setxattr` -> `xattr_permission`, which ends at
/// `inode_permission(idmap, inode, mask)`.
///
/// Reading an ACL has no check at all (`vfs_get_acl` performs none), which
/// matches the mode bits being world-readable through `stat`.
fn xattr_permission_check(
    target: &XattrTarget,
    name: &str,
    write: bool,
    task: u64,
) -> Result<(), i64> {
    // `fs/xattr.c::may_write_xattr` comes first, before any namespace or
    // ownership question: "we can never set or remove an extended
    // attribute on a read-only filesystem or on an immutable /
    // append-only inode".
    if write {
        let iflags = match target {
            XattrTarget::File(file) => file.inode_flags(),
            XattrTarget::Dir(_) => 0,
        };
        if iflags & narf_filesystem::FS_PRIVILEGED_FL != 0 {
            return Err(XE_PERM);
        }
    }
    let (uid, gid, perms, is_dir) = target.meta();
    if is_acl_xattr(name) {
        if !write {
            return Ok(());
        }
        // `set_posix_acl` tests the DEFAULT-on-a-non-directory case FIRST
        // and answers `acl ? -EACCES : 0` without ever consulting the
        // owner. Leaving that arm to the filesystem keeps Linux's
        // precedence, which putting EPERM in front of it would invert.
        let default_on_file =
            !is_dir && name == narf_filesystem::AclType::Default.xattr_name();
        if !default_on_file && !inode_owner_or_capable(task, uid, gid) {
            return Err(XE_PERM);
        }
        return Ok(());
    }
    // The rest of `xattr_permission`. The sticky-directory rule first: on
    // a directory with S_ISVTX, `user.*` may only be WRITTEN by someone who
    // passes `inode_owner_or_capable`, so a shared `/tmp` cannot have its
    // entries relabelled by passers-by.
    if write
        && is_dir
        && perms & 0o1000 != 0
        && name.starts_with("user.")
        && !inode_owner_or_capable(task, uid, gid)
    {
        return Err(XE_PERM);
    }
    // ...ending at `inode_permission(idmap, inode, mask)`: setting an
    // attribute needs WRITE on the inode, reading one needs READ. Nothing
    // enforced that, so a file's `security.*` label could be rewritten by
    // anyone who could name it.
    let permitted = narf_filesystem::posix_access_ok_with_acl(
        narf_filesystem::FileOwner {
            uid,
            gid,
            perms,
            is_dir,
        },
        &accessor_for_inode(task, uid, gid),
        narf_filesystem::AccessRequest {
            read: !write,
            write,
            exec: false,
        },
        target.access_acl().as_ref(),
    );
    if permitted {
        Ok(())
    } else {
        Err(XE_ACCES)
    }
}

/// Resolve the file an xattr operation names.
///
/// Deliberately NOT following the final symlink: by the time a path reaches
/// here it has already been through `resolve_vfs_symlink_path`, which did
/// the following (or did not) according to the caller's `at_flags`. Doing it
/// again here would follow a link the `l` forms asked to keep.
///
/// That split is the same one `open` uses, and it is the one that matters
/// for ABSOLUTE symlink targets: only the VFS-level walk can leave the
/// filesystem the link lives on, because only it holds the mount table. The
/// in-filesystem resolver restarts an absolute target at its own mount root,
/// which is correct for what it can see and wrong for anything else.
fn xattr_file(path: &str) -> Option<alloc::sync::Arc<dyn narf_filesystem::FileOps>> {
    let (root, rel) = narf_filesystem::registry().resolve_absolute(path, |fs, rel| {
        (fs.root(), alloc::string::String::from(rel))
    })?;
    match poll_blocking(narf_filesystem::resolve_async_nofollow(root, &rel)) {
        Some(Ok(file)) => Some(file),
        _ => None,
    }
}

/// `setxattr` / `lsetxattr` / `fsetxattr` core (name/value/size/flags at
/// arg1..arg4; the key path is resolved by the caller).
/// Is `name` one of the two POSIX ACL xattrs?
///
/// Used only to disambiguate `FsError::Unsupported`, which means "no xattr
/// store here" for an ordinary name but "unsupported ACL version" for
/// these two.
fn is_acl_xattr(name: &str) -> bool {
    name == narf_filesystem::AclType::Access.xattr_name()
        || name == narf_filesystem::AclType::Default.xattr_name()
}

fn xattr_set_core(path: alloc::string::String, ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let size = a.arg3 as usize;
    let flags = a.arg4;
    // `setxattr_copy` order: flags, then the name, then the value size.
    // Only the two documented bits are legal; note that CREATE|REPLACE
    // TOGETHER is not rejected here — `simple_xattr_set` fails it with
    // EEXIST or ENODATA depending on whether the attribute exists.
    if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        ctx.set_return(SyscallReturn::ok(XE_INVAL as u64));
        return;
    }
    let name = match xattr_import_name(a.arg1) {
        Ok(name) => name,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    if size > XATTR_SIZE_MAX {
        ctx.set_return(SyscallReturn::ok(XE_2BIG as u64));
        return;
    }
    if let Err(errno) = xattr_namespace_ok(&name, true) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let value = if size == 0 {
        alloc::vec::Vec::new()
    } else {
        // SAFETY: size != 0; copy_from_user_vec range-validates a.arg2.
        match unsafe { copy_from_user_vec(a.arg2, size) } {
            Ok(v) => v,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok(XE_FAULT as u64));
                return;
            }
        }
    };
    // `setxattr` -> `mnt_want_write` before anything else touches the
    // inode: an attribute is state on the filesystem like any other.
    if let Err(errno) = mnt_want_write(&path) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // A path can name a file or a directory; both are inodes with xattrs.
    let target = xattr_target(&path);
    if let Some(target) = target.as_ref() {
        if let Err(errno) = xattr_permission_check(target, &name, true, current_task_id()) {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    }
    let stored = match target {
        Some(XattrTarget::File(file)) => poll_blocking(file.set_xattr(&name, &value, flags as u32)),
        Some(XattrTarget::Dir(dir)) => poll_blocking(dir.set_xattr(&name, &value, flags as u32)),
        None => None,
    };
    match stored {
        Some(Ok(())) => {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        // `Unsupported` is ambiguous and the two readings need different
        // answers. For an ORDINARY xattr it means "this filesystem has no
        // xattr store", and falling through to the generic table below is
        // right. For an ACL name it is `posix_acl_fix_xattr_common`'s
        // `a_version != POSIX_ACL_XATTR_VERSION` -> -EOPNOTSUPP, and
        // falling through would STORE the rejected bytes raw — worse than
        // any errno, because a later read would hand back an ACL the
        // kernel refused.
        Some(Err(narf_filesystem::FsError::Unsupported)) if is_acl_xattr(&name) => {
            ctx.set_return(SyscallReturn::ok(XE_OPNOTSUPP as u64));
            return;
        }
        Some(Err(error)) => {
            if let Some(errno) = xattr_errno(error) {
                ctx.set_return(SyscallReturn::ok(errno as u64));
                return;
            }
        }
        None => {}
    }
    let key = (path, name);
    let mut g = XATTR_TABLE.lock();
    let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    let exists = m.contains_key(&key);
    if flags & XATTR_CREATE != 0 && exists {
        ctx.set_return(SyscallReturn::ok(XE_EXIST as u64));
        return;
    }
    if flags & XATTR_REPLACE != 0 && !exists {
        ctx.set_return(SyscallReturn::ok(XE_NODATA as u64));
        return;
    }
    m.insert(key, value);
    ctx.set_return(SyscallReturn::ok(0));
}

/// `getxattr` / `lgetxattr` / `fgetxattr` core (name at arg1, value at
/// arg2, size at arg3).
fn xattr_get_core(path: alloc::string::String, ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let name = match xattr_import_name(a.arg1) {
        Ok(name) => name,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    if let Err(errno) = xattr_namespace_ok(&name, false) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let size = a.arg3 as usize;
    let target = xattr_target(&path);
    if let Some(target) = target.as_ref() {
        if let Err(errno) = xattr_permission_check(target, &name, false, current_task_id()) {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    }
    let fetched = match target {
        Some(XattrTarget::File(file)) => poll_blocking(file.get_xattr(&name)),
        Some(XattrTarget::Dir(dir)) => poll_blocking(dir.get_xattr(&name)),
        None => None,
    };
    match fetched {
        Some(Ok(value)) => {
            return xattr_copy_value(ctx, a.arg2, size, &value);
        }
        Some(Err(error)) => {
            if let Some(errno) = xattr_errno(error) {
                ctx.set_return(SyscallReturn::ok(errno as u64));
                return;
            }
        }
        None => {}
    }
    let value = {
        let g = XATTR_TABLE.lock();
        match g.as_ref().and_then(|m| m.get(&(path, name)).cloned()) {
            Some(v) => v,
            None => {
                ctx.set_return(SyscallReturn::ok(XE_NODATA as u64));
                return;
            }
        }
    };
    xattr_copy_value(ctx, a.arg2, size, &value);
}

fn xattr_copy_value(ctx: &mut dyn TrapContext, ptr: u64, size: usize, value: &[u8]) {
    if size == 0 {
        ctx.set_return(SyscallReturn::ok(value.len() as u64));
    } else if size < value.len() {
        ctx.set_return(SyscallReturn::ok((-34i64) as u64));
    // SAFETY: `ptr` is the caller's output buffer; `copy_to_user`
    // range-validates and SMAP-brackets the write.
    } else if unsafe { copy_to_user(ptr, value) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
    } else {
        ctx.set_return(SyscallReturn::ok(value.len() as u64));
    }
}

/// `listxattr` / `llistxattr` / `flistxattr` core (list at arg1, size at arg2).
fn xattr_list_core(path: alloc::string::String, ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let size = a.arg2 as usize;
    let target = xattr_target(&path);
    if let Some(target) = target.as_ref() {
        // `listxattr` needs READ on the inode, like any other read of its
        // metadata. The empty name is the whole-inode form, so there is no
        // namespace to resolve.
        if let Err(errno) = xattr_permission_check(target, "", false, current_task_id()) {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    }
    let listed = match target {
        Some(XattrTarget::File(file)) => poll_blocking(file.list_xattr()),
        Some(XattrTarget::Dir(dir)) => poll_blocking(dir.list_xattr()),
        None => None,
    };
    match listed {
        Some(Ok(names)) => {
            return xattr_copy_value(ctx, a.arg1, size, &names);
        }
        Some(Err(error)) => {
            if let Some(errno) = xattr_errno(error) {
                ctx.set_return(SyscallReturn::ok(errno as u64));
                return;
            }
        }
        None => {}
    }
    let mut names: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    {
        let g = XATTR_TABLE.lock();
        if let Some(m) = g.as_ref() {
            for (p, n) in m.keys() {
                if *p == path {
                    names.extend_from_slice(n.as_bytes());
                    names.push(0);
                }
            }
        }
    }
    if size == 0 {
        ctx.set_return(SyscallReturn::ok(names.len() as u64));
        return;
    }
    if size < names.len() {
        ctx.set_return(SyscallReturn::ok((-34i64) as u64)); // ERANGE
        return;
    }
    // SAFETY: a.arg1 is the user list buffer; copy_to_user range-validates it.
    if !names.is_empty() && unsafe { copy_to_user(a.arg1, &names) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(names.len() as u64));
}

/// `removexattr` / `lremovexattr` / `fremovexattr` core (name at arg1).
fn xattr_remove_core(path: alloc::string::String, ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let name = match xattr_import_name(a.arg1) {
        Ok(name) => name,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    if let Err(errno) = xattr_namespace_ok(&name, true) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    if let Err(errno) = mnt_want_write(&path) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let target = xattr_target(&path);
    if let Some(target) = target.as_ref() {
        if let Err(errno) = xattr_permission_check(target, &name, true, current_task_id()) {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    }
    let removed = match target {
        Some(XattrTarget::File(file)) => poll_blocking(file.remove_xattr(&name)),
        Some(XattrTarget::Dir(dir)) => poll_blocking(dir.remove_xattr(&name)),
        None => None,
    };
    match removed {
        Some(Ok(())) => {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        Some(Err(error)) => {
            if let Some(errno) = xattr_errno(error) {
                ctx.set_return(SyscallReturn::ok(errno as u64));
                return;
            }
        }
        None => {}
    }
    let removed = {
        let mut g = XATTR_TABLE.lock();
        g.as_mut().map(|m| m.remove(&(path, name)).is_some())
    };
    if removed == Some(true) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok(XE_NODATA as u64));
    }
}

// ── utime / utimes / futimesat / utimensat — real mtime updates ─────
//
// Backed by `FileOps::set_times` (wall-ns since epoch; MemFs stores and
// round-trips it through stat). Filesystems without the method — the
// synthetic ones — keep the old lenient behavior: the path is validated
// and the timestamp silently accepted, so `touch /dev/null`-style
// scripts don't regress. tar -x, cp -p, and make's newer-than checks
// are the consumers that need the real store.

/// Wall-clock now as ns since the epoch (the UTIME_NOW value).
fn wall_now_ns() -> u64 {
    let w = narf_scheduler::narf_time::now_wall();
    (w.secs.max(0) as u64).saturating_mul(1_000_000_000) + w.nanos as u64
}

/// Apply `set_times` to an absolute (already cwd/chroot-resolved) path.
/// Returns the Linux result: 0, -ENOENT, or 0 for a resolvable node
/// whose FS doesn't track times (lenient legacy behavior, incl. dirs —
/// resolve_async only yields files, so directories take the
/// stat-dir-aware fallback).
fn set_path_times(path: &str, atime_ns: Option<u64>, mtime_ns: Option<u64>) -> i64 {
    // `do_utimes` -> `mnt_want_write`: stamping a timestamp is a write.
    if let Err(errno) = mnt_want_write(path) {
        return errno;
    }
    let ops = narf_filesystem::registry().resolve_absolute(path, |fs, rel| {
        poll_blocking(narf_filesystem::resolve_async(fs.root(), rel))
    });
    match ops {
        Some(Some(Ok(o))) => {
            // Unsupported → lenient 0 (see module comment above).
            let _ = o.set_times(atime_ns, mtime_ns);
            0
        }
        _ => {
            // Not a plain file — a directory still validates (0), a
            // missing path is -ENOENT, matching the old stubs.
            if stat_path_dir_aware(path).is_some() {
                0
            } else {
                -2
            }
        }
    }
}

/// Shared utimes body: `timeval[2]` (sec + USEC) at `tv_ptr`, NULL =
/// both now. Used by utimes(235) and futimesat(261).
fn utimes_common(ctx: &mut dyn TrapContext, raw_path: &str, tv_ptr: u64) {
    let (at, mt) = if tv_ptr == 0 {
        let now = wall_now_ns();
        (now, now)
    } else {
        let mut buf = [0u8; 32];
        // SAFETY: non-zero user timeval[2] pointer; copy_from_user
        // range-validates and SMAP-brackets the 32-byte read.
        if unsafe { copy_from_user(&mut buf, tv_ptr) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
        let tv = |o: usize| -> u64 {
            let sec = i64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
            let usec = i64::from_ne_bytes(buf[o + 8..o + 16].try_into().unwrap());
            (sec.max(0) as u64).saturating_mul(1_000_000_000) + (usec.max(0) as u64) * 1_000
        };
        (tv(0), tv(16))
    };
    let path = resolve_cwd_path(current_task_id(), raw_path);
    let r = set_path_times(&path, Some(at), Some(mt));
    ctx.set_return(SyscallReturn::ok(r as u64));
}

// ── pkey_alloc / pkey_free / pkey_mprotect ───────────────────────────
//
// Memory-protection keys. NARF tracks an allocation bitmap per task
// (keys 1..=15; key 0 is the always-present default) so alloc/free
// round-trip and pkey_mprotect can validate its key argument, but the
// keys are not enforced in hardware (no PKRU wiring yet) — pkey_mprotect
// applies the requested prot exactly like mprotect.

/// Per-task allocated-pkey bitmap (bit k set ⇒ key k is allocated).
static PKEY_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<alloc::collections::BTreeMap<u64, u16>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Reset the per-task pkey bitmaps. Called from `init_per_task_state`
/// (i.e. on every ABI-test `setup()`) so the table starts clean — without
/// it, the `pkey_alloc_exhaust` test leaves FAKE_TASK's 15-key bitmap full
/// and the positive alloc/free tests that run later in the same boot see
/// -ENOSPC. Matches the per-subsystem reset discipline of every other
/// per-task global.
pub fn pkey_init() {
    *PKEY_TABLE.lock() = None;
}

// ── process_vm_readv / process_vm_writev ─────────────────────────────
//
// Bulk gather/scatter copy between the caller and a target process's
// address space. NARF has no cross-address-space copy primitive yet, so
// this supports transfers where the target resolves to the *same*
// address space as the caller (pid == self, or a CLONE_VM thread) —
// which still fully exercises the iovec machinery and is a valid Linux
// self-copy. A different address space returns EPERM.

const PROCESS_VM_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Read `count` `struct iovec { void *base; size_t len; }` (16 B each).
fn read_iovecs(arr_ptr: u64, count: usize) -> Option<alloc::vec::Vec<(u64, u64)>> {
    let mut out = alloc::vec::Vec::with_capacity(count);
    for i in 0..count {
        let entry = arr_ptr.checked_add((i as u64) * 16)?;
        let mut buf = [0u8; 16];
        // SAFETY: copy_from_user range-validates `entry` and SMAP-brackets
        // the 16-byte iovec read in the caller's address space.
        unsafe { copy_from_user(&mut buf, entry) }.ok()?;
        let base = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        out.push((base, len));
    }
    Some(out)
}

/// Shared core for process_vm_readv / process_vm_writev. `is_write`
/// selects the direction: false copies remote→local (readv), true
/// copies local→remote (writev). Both sides live in the same AS here.
fn process_vm_transfer(ctx: &mut dyn TrapContext, is_write: bool) {
    let a = *ctx.args();
    #[allow(unused_mut)]
    let mut pid = a.arg0;
    // The target pid is in the CALLER's pid namespace (Linux
    // find_get_task_by_vpid, mm/process_vm_access.c). Translate inner ->
    // outer before the self/AS checks below: untranslated, a containerized
    // process probing its own inner pid took the cross-AS path and failed,
    // and a foreign inner pid resolved to whatever host task owned the same
    // number — a host address-space identity oracle. Unmapped inner -> ESRCH.
    #[cfg(feature = "container")]
    {
        match accept_pid_from(current_task_id(), pid) {
            Some(outer) => pid = outer,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    }
    let local_ptr = a.arg1;
    let liovcnt = a.arg2 as usize;
    let remote_ptr = a.arg3;
    let riovcnt = a.arg4 as usize;
    let flags = a.arg5;
    if flags != 0 || liovcnt > 1024 || riovcnt > 1024 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    // Require the target to resolve to the caller's own address space
    // (cross-AS copy is not yet supported). The running task's AS is the
    // active one — `current_address_space()` — but it is not necessarily
    // registered under its tid in `address_space_of`, so resolve self
    // directly rather than via the registry. getpid() returns the raw
    // task id in a non-container build; pid_to_task_raw only tracks
    // forked tasks, so a self target compares against current_task_id().
    let cur_as = match current_address_space() {
        Some(c) => c,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    // Detect a self-target across BOTH id spaces: `pid` here is whatever the
    // caller passed, and getpid() returns the VISIBLE ProcessId
    // (task_to_pid_raw), not the raw scheduler TaskId. Comparing only against
    // current_task_id() misfires for any task whose visible pid differs from
    // its tid — it then takes the cross-AS path and fails on address_space_of
    // returning None → ESRCH (observed as pvm_smoke `pvm-fail: readv`).
    let self_pid = task_to_pid_raw(current_task_id()).unwrap_or_else(current_task_id);
    if pid != current_task_id() && pid != self_pid {
        match pid_to_task_raw(pid) {
            Some(tid) => match narf_scheduler::address_space_of(narf_scheduler::TaskId(tid)) {
                Some(r) if Arc::ptr_eq(&r, &cur_as) => {}
                Some(_) => {
                    ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM (cross-AS)
                    return;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                    return;
                }
            },
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    }

    let local = match read_iovecs(local_ptr, liovcnt) {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let remote = match read_iovecs(remote_ptr, riovcnt) {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let (src, dst) = if is_write {
        (&local, &remote)
    } else {
        (&remote, &local)
    };

    let src_total: u64 = src.iter().map(|(_, l)| *l).sum();
    let dst_total: u64 = dst.iter().map(|(_, l)| *l).sum();
    let xfer = src_total.min(dst_total).min(PROCESS_VM_MAX_BYTES as u64) as usize;

    // Gather `xfer` bytes from the source segments.
    let mut buf = alloc::vec::Vec::with_capacity(xfer);
    let mut remaining = xfer;
    for &(base, len) in src {
        if remaining == 0 {
            break;
        }
        let take = (len as usize).min(remaining);
        // SAFETY: `base` is a user address in the (current) AS; copy_from_user_vec
        // range-validates and SMAP-brackets the read.
        match unsafe { copy_from_user_vec(base, take) } {
            Ok(chunk) => buf.extend_from_slice(&chunk),
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
        }
        remaining -= take;
    }

    // Scatter into the destination segments.
    let mut off = 0usize;
    for &(base, len) in dst {
        if off >= buf.len() {
            break;
        }
        let take = (len as usize).min(buf.len() - off);
        // SAFETY: `base` is a user address in the (current) AS; copy_to_user
        // range-validates and SMAP-brackets the write.
        if unsafe { copy_to_user(base, &buf[off..off + take]) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
        off += take;
    }
    ctx.set_return(SyscallReturn::ok(off as u64));
}

// ── NUMA memory policy: set_mempolicy / get_mempolicy / mbind ─────────
//
// Memory policy is *enforced*: the per-task default policy and per-range
// (mbind) policies are stored here, and the page-fault path publishes
// the policy in force for the faulting address into
// `narf_memory::mempolicy` so the per-node buddy allocator steers the
// fresh frame to the chosen node (see `publish_mempolicy_for_fault`).
// The mode's low bits select the policy; the high bits carry MPOL_F_*
// flags which we preserve in the stored value so get_mempolicy reflects
// them, but they don't affect allocation steering.

const MPOL_PREFERRED_MANY: u32 = 5;
const MPOL_WEIGHTED_INTERLEAVE: u32 = 6;
const MPOL_F_RELATIVE_NODES: u32 = 1 << 14;
const MPOL_F_STATIC_NODES: u32 = 1 << 15;
const MPOL_F_NUMA_BALANCING: u32 = 1 << 13;
const MPOL_MODE_FLAGS: u32 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;

// Online NUMA node count via a weak hook (userspace avoids a direct
// narf-acpi dep to keep the kernel image under lld's orphan-placement
// threshold — see filesystem/src/sysfs.rs). `narf-frame` provides it.
extern "Rust" {
    fn narf_numa_node_count() -> u32;
    fn narf_cpu_to_node(cpu: u32) -> u32;
    fn narf_phys_to_node(addr: u64) -> u32;
}

#[inline]
fn numa_node_count() -> u32 {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    unsafe { narf_numa_node_count() }.max(1)
}

#[inline]
fn numa_node_for_cpu(cpu: u32) -> u32 {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    unsafe { narf_cpu_to_node(cpu) }
}

#[inline]
fn numa_node_for_phys(phys: u64) -> u32 {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    unsafe { narf_phys_to_node(phys) }
}

fn mapped_phys(as_ref: &AddressSpace, va: u64) -> Option<u64> {
    let page = VirtAddr::new(va & !0xFFF);
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the live AddressSpace owns `root`; this is a read-only walk.
        unsafe { narf_memory::x86_64::paging::translate(as_ref.root, page) }.map(|p| p.as_u64())
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: the live AddressSpace owns `root`; this is a read-only walk.
        unsafe { narf_memory::aarch64::paging::translate(as_ref.root, page) }.map(|p| p.as_u64())
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (as_ref, page);
        None
    }
}

// get_mempolicy `flags` bits (uapi/linux/mempolicy.h).
const MPOL_F_NODE: u32 = 1 << 0; // return the node id, not the mode
const MPOL_F_ADDR: u32 = 1 << 1; // query the policy at `addr`
const MPOL_F_MEMS_ALLOWED: u32 = 1 << 2; // return the allowed-nodes mask

/// One stored policy: mode (with flags), first-word nodemask, and optional
/// BIND distance anchor installed by set_mempolicy_home_node(2).
#[derive(Copy, Clone)]
struct StoredPolicy {
    mode: u32,
    nodemask: u64,
    home_node: u32,
}

impl StoredPolicy {
    const DEFAULT: Self = Self {
        mode: 0,
        nodemask: 0,
        home_node: u32::MAX,
    };
}

/// Per-task default policy (set_mempolicy).
static MEMPOLICY_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, StoredPolicy>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Per-task range policies (mbind), keyed by (task, range-start); each
/// entry covers `[start, start+len)`.
#[allow(clippy::type_complexity)]
static MBIND_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::vec::Vec<(u64, u64, StoredPolicy)>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Monotonic fault-path gate. False proves both policy tables have always been
/// empty/default, letting ordinary anonymous faults avoid two IRQ-safe global
/// lock acquisitions. Writers publish true before inserting policy state.
static CUSTOM_MEMPOLICY_POSSIBLE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Linux keeps `il_prev`/`il_weight` in task state. NARF stores the equivalent
/// monotonically increasing sequence position by task ID so CPU migration
/// cannot restart or duplicate an interleave cycle.
static INTERLEAVE_INDEX_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, u64>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

#[derive(Copy, Clone)]
struct NumaBalanceState {
    ticks: u16,
    cursor: u64,
}

static NUMA_BALANCE_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, NumaBalanceState>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn ensure_numa_balance_state(task: u64) {
    NUMA_BALANCE_TABLE
        .lock()
        .get_or_insert_with(alloc::collections::BTreeMap::new)
        .insert(
            task,
            NumaBalanceState {
                ticks: 255,
                cursor: AddressSpace::USER_FIXED_FLOOR,
            },
        );
}

fn start_numa_balance_range(task: u64, cursor: u64) {
    ensure_numa_balance_state(task);
    if let Some(state) = NUMA_BALANCE_TABLE
        .lock()
        .as_mut()
        .and_then(|states| states.get_mut(&task))
    {
        state.cursor = cursor & !0xFFF;
    }
}

fn task_interleave_index(task: u64, advance: bool) -> u64 {
    let mut table = INTERLEAVE_INDEX_TABLE.lock();
    let index = table
        .get_or_insert_with(alloc::collections::BTreeMap::new)
        .entry(task)
        .or_insert(0);
    let current = *index;
    if advance {
        *index = index.wrapping_add(1);
    }
    current
}

fn mpol_mode_valid(mode: u32) -> bool {
    matches!(mode & !MPOL_MODE_FLAGS, 0..=MPOL_WEIGHTED_INTERLEAVE)
}

fn mpol_policy_shape_valid(mode: u32, nodemask: u64) -> bool {
    let flags = mode & MPOL_MODE_FLAGS;
    if flags == (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) {
        return false;
    }
    let base = mode & !MPOL_MODE_FLAGS;
    if flags & MPOL_F_NUMA_BALANCING != 0
        && !matches!(base, narf_memory::MPOL_BIND | MPOL_PREFERRED_MANY)
    {
        return false;
    }
    match base {
        narf_memory::MPOL_DEFAULT | narf_memory::MPOL_LOCAL => nodemask == 0 && flags == 0,
        narf_memory::MPOL_PREFERRED => nodemask != 0 || flags == 0,
        narf_memory::MPOL_BIND
        | narf_memory::MPOL_INTERLEAVE
        | MPOL_PREFERRED_MANY
        | MPOL_WEIGHTED_INTERLEAVE => nodemask != 0,
        _ => false,
    }
}

/// Resolve a sampled NUMA hint fault. The backing remains owned while its
/// leaf is absent; this either migrates it to the accessing CPU's allowed
/// node or restores the original mapping.
pub fn handle_numa_hint_fault(va: u64) -> bool {
    let Some(as_ref) = active_user_as() else {
        return false;
    };
    let page = VirtAddr::new(va & !0xFFF);
    if !as_ref.take_numa_hint(page) {
        return false;
    }
    let task = current_task_id();
    let policy = resolve_policy(task, va);
    let allowed = narf_scheduler::task_mems_allowed(task);
    let targets = mpol_effective_nodemask(policy, allowed);
    let local = numa_node_for_cpu(narf_lib::percpu::current_cpu() as u32) as usize;
    if policy.mode & MPOL_F_NUMA_BALANCING != 0 && (targets >> local) & 1 != 0 {
        // SAFETY: the sampled page belongs to the active address space and
        // remains resident/owned while its leaf is temporarily absent.
        let _ = unsafe { as_ref.migrate_page_to_node(page, local) };
    }
    // migrate_page_to_node's already-local fast path intentionally does not
    // rewrite a leaf. Always remap, also providing rollback after ENOMEM.
    // SAFETY: the hint record proves this active AS retains the page backing.
    unsafe { as_ref.remap_page(page) }.is_ok()
}

/// Allocation-free periodic sampler called on timer return to user mode.
/// One page is protected per 256 ticks and the scan cursor advances across
/// VMAs, bounding both IRQ work and hint-fault frequency.
pub fn numa_balance_tick() {
    // This is the existing cross-architecture user-mode timer hook. Keep perf
    // multiplexing ahead of NUMA's optional per-task state lookup so tasks
    // without automatic NUMA balancing still rotate oversubscribed counters.
    crate::perf_event::on_multiplex_tick(current_task_id());

    const SCAN_TICKS: u16 = 256;
    const SEARCH_BUDGET: usize = 16;
    let task = current_task_id();
    let cursor = {
        let mut table = NUMA_BALANCE_TABLE.lock();
        let Some(state) = table.as_mut().and_then(|states| states.get_mut(&task)) else {
            return;
        };
        state.ticks = state.ticks.saturating_add(1);
        if state.ticks < SCAN_TICKS {
            return;
        }
        state.ticks = 0;
        state.cursor
    };
    let Some(as_ref) = active_user_as() else {
        return;
    };
    let mut next = cursor;
    for _ in 0..SEARCH_BUDGET {
        let candidate = as_ref
            .next_numa_hint_candidate(VirtAddr::new(next))
            .or_else(|| {
                as_ref.next_numa_hint_candidate(VirtAddr::new(AddressSpace::USER_FIXED_FLOOR))
            });
        let Some(candidate) = candidate else {
            return;
        };
        next = candidate.as_u64().saturating_add(4096);
        let policy = resolve_policy(task, candidate.as_u64());
        if policy.mode & MPOL_F_NUMA_BALANCING == 0 {
            continue;
        }
        // SAFETY: candidate was obtained from this live AS's resident table;
        // the method revalidates it under the region lock.
        if unsafe { as_ref.protect_numa_hint_page(candidate) }.unwrap_or(false) {
            if let Some(state) = NUMA_BALANCE_TABLE
                .lock()
                .as_mut()
                .and_then(|states| states.get_mut(&task))
            {
                state.cursor = next;
            }
            return;
        }
    }
    if let Some(state) = NUMA_BALANCE_TABLE
        .lock()
        .as_mut()
        .and_then(|states| states.get_mut(&task))
    {
        state.cursor = next;
        // Continue the bounded walk on the next tick until it reaches an
        // eligible policy range; the long interval begins only after a page
        // has actually been sampled.
        state.ticks = SCAN_TICKS - 1;
    }
}

/// Resolve a user nodemask against the task's current cpuset constraint.
///
/// STATIC keeps physical node identities. RELATIVE treats each set bit as
/// an ordinal into the allowed-node set, folding ordinals modulo its weight
/// like Linux `nodes_fold` + `nodes_onto`. An empty result after a cpuset
/// rebind falls back to the allowed set.
fn mpol_effective_nodemask(policy: StoredPolicy, allowed: u64) -> u64 {
    let allowed = allowed & ((1u64 << narf_memory::FRAME_MAX_NUMA_NODES) - 1);
    if allowed == 0 || policy.nodemask == 0 {
        return policy.nodemask & allowed;
    }
    let flags = policy.mode & MPOL_MODE_FLAGS;
    let effective = if flags & MPOL_F_RELATIVE_NODES != 0 {
        let weight = allowed.count_ones();
        let mut ordinals = 0u64;
        for bit in 0..64u32 {
            if (policy.nodemask >> bit) & 1 != 0 {
                ordinals |= 1u64 << (bit % weight);
            }
        }
        let mut mapped = 0u64;
        let mut ordinal = 0u32;
        for node in 0..narf_memory::FRAME_MAX_NUMA_NODES as u32 {
            if (allowed >> node) & 1 == 0 {
                continue;
            }
            if (ordinals >> ordinal) & 1 != 0 {
                mapped |= 1u64 << node;
            }
            ordinal += 1;
        }
        mapped
    } else {
        policy.nodemask & allowed
    };
    if effective == 0 { allowed } else { effective }
}

fn mpol_initial_nodemask_valid(mode: u32, nodemask: u64, allowed: u64) -> bool {
    nodemask == 0 || mode & MPOL_F_RELATIVE_NODES != 0 || nodemask & allowed != 0
}

/// Resolve the policy in force for `task` at user address `va`: a
/// covering mbind range wins, else the task default, else DEFAULT.
fn resolve_policy(task: u64, va: u64) -> StoredPolicy {
    if !CUSTOM_MEMPOLICY_POSSIBLE.load(core::sync::atomic::Ordering::Acquire) {
        return StoredPolicy::DEFAULT;
    }
    if let Some(ranges) = MBIND_TABLE.lock().as_ref().and_then(|m| m.get(&task)) {
        for &(start, len, pol) in ranges.iter() {
            if va >= start && va < start.saturating_add(len) {
                return pol;
            }
        }
    }
    MEMPOLICY_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(StoredPolicy::DEFAULT)
}

/// Publish the current task's mempolicy for the faulting address `va`
/// into the memory crate's per-CPU active slot, so the demand-paging
/// allocator steers the fresh frame. Called by the #PF handler right
/// before `demand_alloc_page`. Returns nothing; the slot is cleared by
/// `clear_mempolicy_for_fault` afterward.
pub fn publish_mempolicy_for_fault(va: u64) {
    let task = current_task_id();
    let policy = resolve_policy(task, va);
    let allowed = narf_scheduler::task_mems_allowed(task);
    let mode = policy.mode & !MPOL_MODE_FLAGS;
    let interleave_index = if matches!(
        mode,
        narf_memory::MPOL_INTERLEAVE | narf_memory::MPOL_WEIGHTED_INTERLEAVE
    ) {
        task_interleave_index(task, true)
    } else {
        0
    };
    narf_memory::mempolicy_set(narf_memory::Mempolicy {
        mode,
        nodemask: mpol_effective_nodemask(policy, allowed),
        allowed,
        home_node: policy.home_node,
        interleave_index,
    });
}

/// Clear the per-CPU active mempolicy after a fault is serviced.
pub fn clear_mempolicy_for_fault() {
    narf_memory::mempolicy_clear();
}

// ── sched_setattr / sched_getattr ────────────────────────────────────
//
// Extended scheduling attributes. NARF's scheduler doesn't honour the
// deadline params, but the whole `struct sched_attr` round-trips through
// a per-task side table so getattr reflects setattr.

/// `SCHED_ATTR_SIZE_VER0` — the smallest valid `struct sched_attr`.
const SCHED_ATTR_SIZE: usize = 48;

static SCHED_ATTR_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, [u8; SCHED_ATTR_SIZE]>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

// ── adjtimex / clock_adjtime ─────────────────────────────────────────
//
// Kernel clock-discipline interface. NARF runs no NTP discipline, so a
// query (`modes == 0`) reports a steady, synchronised clock: TIME_OK with
// the default tick (10000 µs ⇒ 100 Hz) and zero frequency offset.

// `struct timex` field byte offsets (LP64, shared x86_64/aarch64).
const TIMEX_OFF_MODES: u64 = 0;
const TIMEX_OFF_FREQ: u64 = 16;
const TIMEX_OFF_STATUS: u64 = 40;
const TIMEX_OFF_TICK: u64 = 88;
const TIME_OK: u64 = 0;
const DEFAULT_TICK_US: i64 = 10_000;

/// Shared core: read `modes`, and for a read-only query fill the steady
/// state fields. Returns the clock state (TIME_OK) or a negative errno.
fn adjtimex_core(timex_ptr: u64) -> i64 {
    if timex_ptr == 0 {
        return -14; // EFAULT
    }
    let modes = read_user_u32(timex_ptr.wrapping_add(TIMEX_OFF_MODES));
    // We accept any modes word but apply nothing; report the steady state.
    let _ = modes;
    // freq = 0, status = 0 (synchronised), tick = default.
    // SAFETY: timex_ptr is non-zero; each copy_to_user validates the field
    // write against the user struct (well within sizeof(struct timex)).
    unsafe {
        if copy_to_user(timex_ptr.wrapping_add(TIMEX_OFF_FREQ), &0i64.to_le_bytes()).is_err()
            || copy_to_user(
                timex_ptr.wrapping_add(TIMEX_OFF_STATUS),
                &0i32.to_le_bytes(),
            )
            .is_err()
            || copy_to_user(
                timex_ptr.wrapping_add(TIMEX_OFF_TICK),
                &DEFAULT_TICK_US.to_le_bytes(),
            )
            .is_err()
        {
            return -14; // EFAULT
        }
    }
    TIME_OK as i64
}

// ── pidfd_getfd / kcmp ───────────────────────────────────────────────

/// Minimal `TrapContext` proxy that overrides the argument tuple and
/// forwards everything else to the inner context (reshape-and-delegate
/// handlers like openat2).
struct ReshapeArgs<'a> {
    inner: &'a mut dyn TrapContext,
    args: SyscallArgs,
}
impl TrapContext for ReshapeArgs<'_> {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, ret: SyscallReturn) {
        self.inner.set_return(ret);
    }
    fn user_rsp(&self) -> u64 {
        self.inner.user_rsp()
    }
    fn rip(&self) -> u64 {
        0
    }
    fn set_rip(&mut self, _rip: u64) {}
    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
        self.inner.redirect_to_kernel(rip, rsp)
    }
}

/// `TrapContext` proxy that captures the sub-handler's return value
/// instead of forwarding it (sendmmsg/recvmmsg loop a single
/// sendmsg/recvmsg per message and read each result).
struct CaptureCtx<'a> {
    inner: &'a mut dyn TrapContext,
    args: SyscallArgs,
    ret_value: u64,
}
impl TrapContext for CaptureCtx<'_> {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, ret: SyscallReturn) {
        self.ret_value = ret.value;
    }
    fn user_rsp(&self) -> u64 {
        self.inner.user_rsp()
    }
    fn rip(&self) -> u64 {
        0
    }
    fn set_rip(&mut self, _rip: u64) {}
    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
        self.inner.redirect_to_kernel(rip, rsp)
    }
}

/// `struct mmsghdr { struct msghdr msg_hdr; unsigned msg_len; }` is 64
/// bytes on LP64 (msghdr is 56); msg_len sits at offset 56.
const MMSGHDR_SZ: u64 = 64;
const MMSGHDR_MSGLEN_OFF: u64 = 56;

/// Shared core for `preadv`/`pwritev`/`preadv2`/`pwritev2`.
///
/// `fs/read_write.c::do_preadv` / `do_pwritev` ordering:
///
/// ```text
///   if (pos < 0) return -EINVAL;
///   f = fdget(fd); if (!fd_file(f)) return -EBADF;
///   ret = -ESPIPE; if (f->f_mode & FMODE_PREAD) ret = vfs_readv(...);
/// ```
///
/// `pos == -1` is the preadv2/pwritev2 escape hatch that
/// `SYSCALL_DEFINE6(preadv2)` routes to plain `do_readv`/`do_writev`: it uses
/// and advances the shared file position instead of an explicit offset.
/// Delegating keeps a single implementation of the position lock, MAX_RW_COUNT
/// cap, blocking/EAGAIN and partial-progress rules — the previous code read at
/// literal offset `u64::MAX`, so a `preadv2(regular_fd, .., -1, ..)` reported
/// a spurious EOF.
///
/// Every failure now carries the errno Linux would return. The old code
/// collapsed bad fds, faulting iovecs and filesystem errors into a single `-1`,
/// which userspace decodes as EPERM.
fn preadv_pwritev(ctx: &mut dyn TrapContext, is_write: bool, v2: bool) {
    let a = *ctx.args();
    let fd = a.arg0 as u32;
    let iov_ptr = a.arg1;
    let iovcnt = a.arg2 as usize;
    let pos = a.arg3;

    // `pos == -1` is the preadv2/pwritev2 escape hatch that
    // `SYSCALL_DEFINE6(preadv2)` routes to plain `do_readv`/`do_writev`: it
    // uses and advances the shared file position instead of an explicit
    // offset. `preadv`/`pwritev` have no such case, so a negative offset is
    // simply -EINVAL there.
    let use_current_pos = v2 && pos == u64::MAX;

    if !use_current_pos && (pos as i64) < 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    let task = current_task_id();
    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    // Positioned I/O on a pipe/FIFO/socket is -ESPIPE: streams never carry
    // FMODE_PREAD/FMODE_PWRITE, so consuming their bytes "at an offset" (the
    // old behaviour) silently corrupted the stream position. The `pos == -1`
    // form is exempt — it IS readv/writev, which pipes support.
    if !use_current_pos {
        use narf_filesystem::FileType;
        let ty = endpoint.ops.stat().mode.file_type;
        if ty == FileType::Fifo || ty == FileType::Socket {
            ctx.set_return(SyscallReturn::ok((-29i64) as u64)); // -ESPIPE
            return;
        }
    }
    let permitted = if is_write {
        endpoint.writable()
    } else {
        endpoint.readable()
    };
    if !permitted {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    }

    // import_rw_iovecs applies IOV_MAX (-EINVAL), access_ok (-EFAULT) and the
    // MAX_RW_COUNT cap to the complete vector before any I/O starts.
    let iovecs = match import_rw_iovecs(iov_ptr, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
            return;
        }
    };
    let count: usize = iovecs.iter().map(|iov| iov.len).sum();
    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Only now does the flag word matter. `vfs_readv`/`vfs_writev` reach
    // `kiocb_set_rw_flags` (via do_iter_readv_writev) AFTER the FMODE check,
    // after `import_iovec`, and after the `if (!tot_len) goto out;`
    // short-circuit — so a bad descriptor outranks a bad flag, and an empty
    // vector returns 0 without the flags ever being looked at. Validating the
    // word first, as this handler briefly did, reported -EOPNOTSUPP where
    // Linux reports -EBADF or success.
    if v2 {
        const RWF_HIPRI: u64 = 0x01;
        const RWF_DSYNC: u64 = 0x02;
        const RWF_SYNC: u64 = 0x04;
        const RWF_NOWAIT: u64 = 0x08;
        const RWF_APPEND: u64 = 0x10;
        const RWF_NOAPPEND: u64 = 0x20;
        const RWF_ATOMIC: u64 = 0x40;
        const RWF_DONTCACHE: u64 = 0x80;
        const RWF_NOSIGNAL: u64 = 0x100;
        const RWF_SUPPORTED: u64 = RWF_HIPRI
            | RWF_DSYNC
            | RWF_SYNC
            | RWF_NOWAIT
            | RWF_APPEND
            | RWF_NOAPPEND
            | RWF_ATOMIC
            | RWF_DONTCACHE
            | RWF_NOSIGNAL;
        // arg4 is pos_h, arg5 the rwf_t flag word (`int`, so 32 bits).
        let flags = a.arg5 & 0xffff_ffff;
        if flags != 0 {
            if flags & !RWF_SUPPORTED != 0 {
                ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // -EOPNOTSUPP
                return;
            }
            if flags & RWF_APPEND != 0 && flags & RWF_NOAPPEND != 0 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
                return;
            }
            // NARF has no FMODE_NOWAIT, no atomic-write support and no
            // per-I/O cache-drop, and the kernel answers each of those with
            // -EOPNOTSUPP on a file that cannot provide them. RWF_NOWAIT is
            // not even a gap: tmpfs does not set FMODE_NOWAIT either, so
            // Linux gives -EOPNOTSUPP for the same call on the same kind of
            // memory-backed file.
            if flags & (RWF_NOWAIT | RWF_ATOMIC | RWF_DONTCACHE) != 0 {
                ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // -EOPNOTSUPP
                return;
            }
            // LINUX-GAP, and deliberately loud. These three change where the
            // bytes land or whether a signal is raised, and NARF cannot
            // express any of them on this path:
            //
            //   RWF_APPEND   `generic_write_checks_count` does
            //                `iocb->ki_pos = i_size_read(inode)`, so the flag
            //                OVERRIDES the explicit offset and writes at EOF.
            //                Accepting it and writing at `pos` anyway puts the
            //                caller's bytes somewhere else entirely.
            //   RWF_NOAPPEND negates the description's O_APPEND for this one
            //                I/O; the `pos == -1` path below delegates to
            //                writev, which honours O_APPEND and cannot be
            //                told not to.
            //   RWF_NOSIGNAL sets IOCB_NOSIGNAL, which is what suppresses the
            //                `send_sig(SIGPIPE, ...)` in `pipe_write` and
            //                `sock_sendmsg`. Ignoring it delivers a signal the
            //                caller explicitly asked to be spared — and the
            //                default action for SIGPIPE kills the process.
            //
            // Silently ignoring any of them is a data-placement or
            // signal-delivery divergence that surfaces far from its cause.
            // -EOPNOTSUPP is a documented answer for a file that cannot honour
            // an RWF_ bit, and callers already branch on it.
            if flags & (RWF_APPEND | RWF_NOAPPEND | RWF_NOSIGNAL) != 0 {
                ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // -EOPNOTSUPP
                return;
            }
            // What remains is honourable as-is: RWF_DSYNC / RWF_SYNC promise
            // the write reaches stable storage before returning, which an
            // in-memory coherent filesystem already satisfies, and RWF_HIPRI
            // is a scheduling hint.
        }
    }

    if use_current_pos {
        // Hand the whole call to readv/writev, which own the position lock,
        // the blocking/EAGAIN rules and partial-progress reporting. They
        // repeat the descriptor and iovec checks above; that is cheap next to
        // the I/O and keeps one implementation of those rules.
        if is_write {
            handler_sys_writev::sys_writev(ctx);
        } else {
            handler_sys_readv::sys_readv(ctx);
        }
        return;
    }

    // Bounded staging, as in readv/writev: `import_rw_iovecs` caps the whole
    // vector at MAX_RW_COUNT, but a SINGLE iovec may still be far larger than
    // NARF's 16-MiB copy limit, so each one is transferred a chunk at a time.
    const CHUNK: usize = 64 * 1024;
    let mut off = pos;
    let mut total = 0usize;
    let mut pending: alloc::vec::Vec<ImportedRwIovec> = alloc::vec::Vec::new();
    for iovec in &iovecs {
        let mut remaining = *iovec;
        while remaining.len != 0 {
            let step = core::cmp::min(CHUNK, remaining.len);
            pending.push(ImportedRwIovec {
                base: remaining.base,
                len: step,
            });
            remaining.base += step as u64;
            remaining.len -= step;
        }
    }
    // Every entry is now at most CHUNK bytes, so each staging buffer and each
    // guarded copy stays inside the 16-MiB limit.
    for iovec in &pending {
        let outcome = if is_write {
            // SAFETY: import_rw_iovecs validated this source range; the
            // guarded copy still catches a protection change racing it.
            let payload = match unsafe { copy_from_user_vec(iovec.base, iovec.len) } {
                Ok(payload) => payload,
                Err(errno) => {
                    if total == 0 {
                        ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                        return;
                    }
                    break;
                }
            };
            poll_blocking(endpoint.ops.write(off, &payload))
                .unwrap_or(Err(narf_filesystem::FsError::WouldBlock))
        } else {
            let mut staging = alloc::vec![0u8; iovec.len];
            let read = poll_blocking(endpoint.ops.read(off, &mut staging))
                .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
            match read {
                Ok(n) if n <= staging.len() => {
                    // SAFETY: validated destination; guarded against a racing
                    // unmap between import and copy.
                    match unsafe { copy_to_user(iovec.base, &staging[..n]) } {
                        Ok(()) => Ok(n),
                        Err(errno) => {
                            if total == 0 {
                                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                                return;
                            }
                            break;
                        }
                    }
                }
                other => other,
            }
        };
        match outcome {
            Ok(0) => break,
            Ok(n) if n <= iovec.len => {
                total += n;
                off = off.saturating_add(n as u64);
                if n < iovec.len {
                    break; // short transfer / EOF
                }
            }
            // A FileOps reporting more bytes than the buffer holds is a driver
            // bug; Linux's iterators can never exceed the iov length.
            Ok(_) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                return;
            }
            Err(narf_filesystem::FsError::BrokenPipe) => {
                raise_signal_pending(task, 13); // SIGPIPE even after a prefix
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-32i64) as u64));
                    return;
                }
                break;
            }
            Err(error) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64));
                    return;
                }
                break;
            }
        }
    }

    if is_write && total != 0 {
        crate::mqueue::notify_modify_fd(task, fd);
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}

// ── FB syscalls ────────────────────────────────────────────────────
//
// Five syscalls (Connect/Info/RingMap/FlushWait/Disconnect) form the
// userspace framebuffer surface. The kernel-side narf-fb crate
// installs a vtable here at boot; without it, all five calls return
// InvalidOp. This indirection keeps narf-userspace independent of
// narf-fb's transitive dependencies (graphics drivers).

/// Vtable installed by narf-fb. Each fn pointer is the kernel-side
/// implementation of one syscall.
///
/// Contract:
/// - `connect(pid, scanout_id) -> Option<handle>` — `0` is reserved as
///   "invalid handle" so `Option<NonZeroU64>` shape is encoded as
///   `0 = None, n = Some(n)` on the wire.
/// - `info(handle, out: &mut [u32; 6])` — fills `width, height,
///   stride_bytes, format, scanout_id, _resv`. Returns `false` on
///   bad handle.
/// - `ring_map(handle) -> Option<phys>` — kernel returns the ring's
///   phys, the syscall handler does the user-VA mapping.
/// - `flush_wait(handle) -> Option<u64>` — drain count snapshot, or
///   `None` on bad handle.
/// - `disconnect(handle) -> bool` — `true` on success.
#[derive(Copy, Clone)]
pub struct FbSyscallVtable {
    pub connect: fn(pid: u64, scanout_id: u64) -> u64,
    pub info: fn(handle: u64, out: &mut [u32; 6]) -> bool,
    pub ring_map: fn(handle: u64) -> u64,
    pub flush_wait: fn(handle: u64) -> u64,
    pub disconnect: fn(handle: u64) -> bool,
}

impl core::fmt::Debug for FbSyscallVtable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FbSyscallVtable").finish_non_exhaustive()
    }
}

static FB_VTABLE: core::sync::atomic::AtomicPtr<FbSyscallVtable> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Install the narf-fb-supplied syscall vtable. Idempotent — last
/// install wins. The static lives for the kernel's lifetime, so
/// callers should pass a `&'static FbSyscallVtable`.
pub fn install_fb_syscall_vtable(v: &'static FbSyscallVtable) {
    FB_VTABLE.store(
        v as *const FbSyscallVtable as *mut FbSyscallVtable,
        core::sync::atomic::Ordering::Release,
    );
}

#[doc(hidden)]
pub fn __fb_vtable_for_test() -> Option<&'static FbSyscallVtable> {
    let p = FB_VTABLE.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: install_fb_syscall_vtable requires a 'static input.
        Some(unsafe { &*p })
    }
}

fn fb_vtable() -> Option<&'static FbSyscallVtable> {
    let p = FB_VTABLE.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: install_fb_syscall_vtable requires a 'static input.
        Some(unsafe { &*p })
    }
}

/// Kernel-FB-console ownership tracker. First Connect detaches
/// the console hook (saving the prior); last Disconnect restores
/// it. Refcount is the count of live FB handles seen by the
/// syscall layer — sub-handle reaping (e.g. the FB driver
/// silently expiring a handle) doesn't decrement it; a
/// Disconnect syscall does. That mirrors the userspace-driven
/// connect/disconnect lifecycle.
mod fb_console_owner {
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Saved FB hook value (the `usize` returned by
    /// `narf_console::take_fb_hook`). Only meaningful when the
    /// refcount is non-zero.
    static SAVED: AtomicUsize = AtomicUsize::new(0);
    /// Active FB-handle count.
    static REFS: AtomicUsize = AtomicUsize::new(0);

    pub fn on_connect() {
        // Refcount transition 0 → 1 takes the hook. fetch_add
        // returns the prior value; only the thread that observed
        // a 0 may swap the hook out, ensuring exactly one save
        // per take/restore pair.
        if REFS.fetch_add(1, Ordering::AcqRel) == 0 {
            let prior = narf_console::take_fb_hook();
            SAVED.store(prior, Ordering::Release);
        }
    }

    pub fn on_disconnect() {
        // Refcount transition 1 → 0 restores the hook. fetch_sub
        // returns the prior value; only the 1 → 0 thread reads
        // SAVED. Defend against unbalanced calls by saturating
        // at 0 — never underflow.
        let prev = REFS.load(Ordering::Acquire);
        if prev == 0 {
            return;
        }
        if REFS.fetch_sub(1, Ordering::AcqRel) == 1 {
            let saved = SAVED.swap(0, Ordering::AcqRel);
            narf_console::restore_fb_hook(saved);
        }
    }
}

// ── Shmem syscalls ─────────────────────────────────────────────────
//
// Three syscalls (Create / Map / Destroy) form the shared-memory
// surface. The narf-shmem crate installs a vtable here at boot;
// without it, all three calls return InvalidOp.

#[derive(Copy, Clone)]
pub struct ShmemSyscallVtable {
    pub create: fn(pid: u64, len: u64) -> u64,
    /// Create an unnamed MAP_SHARED object. Returned frames each carry one
    /// creator reference which the caller releases after VMA publication.
    pub create_anonymous: fn(len: u64, out: &mut alloc::vec::Vec<u64>) -> bool,
    /// Largest supported handle, used for SysV SHMMAX/SHMALL reporting.
    pub max_len: fn() -> u64,
    pub len_of: fn(handle: u64) -> u64,
    pub frames: fn(handle: u64, out: &mut alloc::vec::Vec<u64>) -> bool,
    pub destroy: fn(handle: u64) -> bool,
    pub pid_of: fn(handle: u64) -> u64,
    /// True only for registry-owned movable RAM, never device/DMA mappings.
    pub owns_frame: fn(phys: u64) -> bool,
    /// True when SHM_LOCK has made this registry frame unevictable.
    pub frame_locked: fn(phys: u64) -> bool,
    /// Charge and lock a whole handle, enforcing the caller's per-user limit.
    pub lock:
        fn(handle: u64, user_ns: u64, uid: u32, limit: u64, bypass: bool) -> Result<(), ShmemLockError>,
    /// Unlock a whole handle and release its stored user charge.
    pub unlock: fn(handle: u64) -> bool,
    /// Atomically replace one registry backing entry after all aliases moved.
    pub replace_frame: fn(old_phys: u64, new_phys: u64) -> bool,
    /// Retain one mapping reference, returning false when this registry does
    /// not own the frame.
    pub retain_frame: fn(phys: u64) -> bool,
    /// Release one mapping reference, returning false when this registry does
    /// not own the frame.
    pub release_frame: fn(phys: u64) -> bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShmemLockError {
    NotFound,
    Limit,
}

impl core::fmt::Debug for ShmemSyscallVtable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShmemSyscallVtable").finish_non_exhaustive()
    }
}

static SHMEM_VTABLE: core::sync::atomic::AtomicPtr<ShmemSyscallVtable> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

pub fn install_shmem_syscall_vtable(v: &'static ShmemSyscallVtable) {
    SHMEM_VTABLE.store(
        v as *const ShmemSyscallVtable as *mut ShmemSyscallVtable,
        core::sync::atomic::Ordering::Release,
    );
}

/// Test hook — swap the installed shmem vtable, returning the previous one
/// so a case can put it back.
///
/// The "no shmem backend" arms of `shmget`/`shmat`/`shmctl` are unreachable
/// in a booted kernel, where `install_shmem_syscall_vtable` runs at init.
/// They are still worth answering correctly — each used to return
/// `invalid_op()`, i.e. 0 in the register the Linux ABI reads, so `shmget`
/// reported segment id 0 and `shmat` reported an attach at address 0 — and
/// an arm nothing can reach is an arm nothing can check. This makes them
/// reachable from a test and nowhere else.
#[doc(hidden)]
pub fn __test_swap_shmem_vtable(
    next: Option<&'static ShmemSyscallVtable>,
) -> Option<&'static ShmemSyscallVtable> {
    let raw = match next {
        Some(v) => v as *const ShmemSyscallVtable as *mut ShmemSyscallVtable,
        None => core::ptr::null_mut(),
    };
    let prev = SHMEM_VTABLE.swap(raw, core::sync::atomic::Ordering::AcqRel);
    if prev.is_null() {
        None
    } else {
        // SAFETY: only ever stored from a `&'static` input, by
        // `install_shmem_syscall_vtable` or this function.
        Some(unsafe { &*prev })
    }
}

fn shmem_vtable() -> Option<&'static ShmemSyscallVtable> {
    let p = SHMEM_VTABLE.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: install_shmem_syscall_vtable requires a 'static input.
        Some(unsafe { &*p })
    }
}

pub fn retain_external_shared_frame(phys: u64) {
    if let Some(vtable) = shmem_vtable() {
        if (vtable.retain_frame)(phys) {
            return;
        }
    }
    let _ = crate::mapped_file::retain_shared_file_page(phys);
}

pub fn release_external_shared_frame(phys: u64) {
    if let Some(vtable) = shmem_vtable() {
        if (vtable.release_frame)(phys) {
            return;
        }
    }
    let _ = crate::mapped_file::release_shared_file_page(phys);
}

// ── FirmwareInstall — arg0=name_ptr, arg1=name_len,
//                       arg2=bytes_ptr, arg3=bytes_len ──────────────
//
// Install (or replace) a firmware blob at `BlobSource::HotInstall`
// priority. The userspace daemon shape mirrors `sys_shmem_*`:
// the kernel holds the registry-authority cap; the syscall is
// implicitly cap-gated through `trusted_loader_authority()` which
// returns `None` until the kernel boot path stages it. Until the
// per-task firmware-loader cap-table lands (Stage-7 follow-up),
// any task can call this — the trailer signature check inside
// `firmware::sys_install` is the actual gate (production builds
// without `firmware-allow-unsigned` reject anything that isn't
// signed by a trusted firmware signer).

// ── Munmap — arg0=base, arg1=len ───────────────────────────────────

// ── Batch 18: address-space-wide locking, secret memory, NUMA ────────

/// Shared core for `mprotect(2)` and `pkey_mprotect(2)`: translate the
/// POSIX `prot` bits to `RegionPerms` and apply them to `[base, base+len)`.
///
/// POSIX prot bit layout (mirrored from narf-libc::sys):
///   PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4.
/// PROT_NONE (`prot == 0`) is NOT coerced to READ — Linux installs an
/// unreadable region that faults on access; `materialize` keys off
/// `prot_only().0 == 0` to leave PTEs absent.
/// Apply a protection change to `[base, base+len)`.
///
/// On failure returns the POSIX-positive errno the caller should negate for
/// userspace (Linux parity, so glibc/malloc can branch on the exact code):
///   - **ENOMEM (12)** — the request covers an empty or gapped range
///     (`mprotect_range`/`jit_mprotect`/`change_perms_range`'s error).
///   - **EACCES (13)** — a W^X denial (`DenyWX`/`DenyXtoWX`) or a
///     JIT-gated RW→RX flip the caller has no JIT capability for.
fn mprotect_core(
    as_ref: &Arc<AddressSpace>,
    base: VirtAddr,
    len: u64,
    prot: u32,
) -> Result<(), i64> {
    let mut perms = RegionPerms(0);
    if prot & 0b001 != 0 {
        perms = perms | RegionPerms::READ;
    }
    if prot & 0b010 != 0 {
        perms = perms | RegionPerms::WRITE;
    }
    if prot & 0b100 != 0 {
        perms = perms | RegionPerms::EXEC;
    }
    // Wave-66: the linux-compat `mprotect_range` rejects W|X and splits a
    // region cleanly when the request covers only a slice; the legacy
    // `change_perms_range` is whole-region only.
    {
        // W^X. `CapKind::Jit` gates the **RW → RX flip** — the transition
        // `wx.rs` has described as the JIT exception since it was written —
        // and *nothing* grants a W|X end state.
        //
        // This used to be the other way round: the cap was demanded only when
        // the request contained W|X, which made `CAP_JIT` a licence to create
        // a genuinely RWX mapping (something NARF had previously made
        // impossible) while leaving the flip it exists for ungated. Since a
        // task that can write a page and then make it executable has the same
        // power as one holding RWX, gating the flip is what actually buys
        // anything.
        //
        // Classified before any mutation so a capability-gated request is
        // never partially applied by the ungated path first.
        //
        // Classified over *every* intersecting region, not a single covering
        // one. Requiring one region to span the whole request narrowed
        // `mprotect(2)` to single-region ranges: a range crossing two adjacent
        // mappings, or one an earlier `mprotect` had already split, returned
        // `Err` where it used to succeed. The fold takes the strictest verdict
        // any region produces, so a request that would flip even one RW region
        // to RX needs the capability and one that would produce W|X anywhere is
        // refused — while an all-`Allow` range behaves exactly as before.
        //
        // An empty set means nothing is mapped in the range; that is
        // `mprotect_range`'s error to report, and routing it there keeps the
        // pre-existing errno rather than inventing one here.
        let intersecting = as_ref.perms_intersecting(base, len);
        // `mm/mprotect.c`, inside the per-VMA loop and before any change is
        // applied:
        //
        //     if (map_deny_write_exec(vma->vm_flags, newflags)) {
        //             error = -EACCES;
        //             break;
        //     }
        //
        // MDWE sits ABOVE the W^X policy below rather than duplicating it.
        // NARF already refuses a W|X end state outright, which is stricter
        // than Linux, so the only thing MDWE adds here is the second denial
        // arm: a mapping that is not currently executable may not BECOME
        // executable, even via the CAP_JIT-gated RW->RX flip that policy
        // otherwise permits. That is the arm the feature exists for — a
        // process that can write a page and then mark it executable has the
        // same power as one holding RWX, so a sandbox that asked for MDWE and
        // still got the flip was told it was protected when it was not.
        //
        // Checked over every intersecting region, like the classification
        // below, so a range crossing one already-executable and one
        // non-executable mapping is refused rather than half-applied.
        let task = current_task_id();
        if intersecting
            .iter()
            .any(|old| mdwe_denies(task, *old, perms.prot_only()))
        {
            return Err(13); // EACCES
        }
        let transition = narf_memory::wx::classify_mprotect_range(
            intersecting.into_iter(),
            perms.prot_only(),
        );
        match transition {
            // W^X refusals, whatever the caller holds → EACCES.
            narf_memory::wx::WxTransition::DenyWX | narf_memory::wx::WxTransition::DenyXtoWX => {
                Err(13)
            }
            narf_memory::wx::WxTransition::NeedsCapJit => {
                let Some(cap) = narf_memory::wx::jit_cap_default_policy(current_task_id()) else {
                    // No JIT capability for the RW→RX flip → EACCES.
                    return Err(13);
                };
                // Underlying range error (empty/gapped) → ENOMEM.
                narf_memory::wx::jit_mprotect(&cap, as_ref, base, len, perms).map_err(|_| 12)
            }
            narf_memory::wx::WxTransition::Allow => {
                // Empty/gapped range → ENOMEM.
                as_ref.mprotect_range(base, len, perms).map_err(|_| 12)
            }
        }
    }
}

// ── Signal-induced termination ────────────────────────────────────
//
// Counterpart to `sys_exit_task`: stages a WIFSIGNALED-shaped wstatus
// for the parent's wait4 to observe, then drives the same exit path
// `sys_exit_task` uses. Called from `default_signal_delivery` and
// `default_sync_signal_delivery` when a pending signal has no installed
// user handler and the POSIX default action is Terminate / CoreDump.
//
// Behaviour:
//   - When a UserTaskFuture is in flight (the normal user-mode case),
//     save user state, mark EXIT_REASON_EXITED, tail-call the exit hook
//     → longjmps back into UserTaskFuture::poll → fans out exit
//     observers → on_child_exit drains the staged wstatus into the
//     parent's pending-exits queue.
//   - Without a polling future installed (kernel-only test contexts),
//     the staged wstatus is still recorded and we mark the syscall's
//     return as Ok(0); test harnesses fire `notify_task_exited`
//     manually.
/// The answer a memory syscall gives when it finds no address space to
/// operate on.
///
/// Every one of `mmap`/`munmap`/`mprotect`/`mremap`/`madvise`/`mlock*`/
/// `munlock*`/`mincore`/`mbind`/`migrate_pages`/`move_pages`/
/// `pkey_mprotect`/`process_madvise` used to answer this with
/// `SyscallReturn::invalid_op()`, whose `value` — the register the Linux ABI
/// returns — is 0. Every one of them therefore reported that an operation
/// which did not happen had succeeded. For most that is merely a lie; for
/// `mmap` and `mremap` it is a lie shaped like an address, since 0 is a
/// plausible mapping result and libc only screens for MAP_FAILED.
///
/// -ENOMEM is what Linux documents for these calls when the address range
/// cannot be served: "addresses in the specified range are not currently
/// mapped" (`madvise`, `mincore`, `mprotect`), "some of the specified
/// address range does not correspond to mapped pages" (`mlock`), and
/// ENOMEM generally for `mmap`/`mremap`.
///
/// Linux has no equivalent state — a task running a syscall always has an
/// `mm` — so this is not a path a booted NARF reaches either; it is the
/// kernel-test harness, which deliberately establishes a no-AS baseline.
/// That makes the arm unreachable in production and permanently reachable in
/// tests, which is the combination that lets a wrong answer sit unnoticed.
fn no_address_space() -> SyscallReturn {
    SyscallReturn::ok((-12i64) as u64) // -ENOMEM
}

pub(crate) fn terminate_current_task(
    ctx: &mut dyn TrapContext,
    task: u64,
    signum: u32,
    core_dumped: bool,
) {
    let pid = task_to_pid_raw(task).unwrap_or(task);
    #[cfg(feature = "syscall-trace")]
    if crate::syscall::syscall_trace_target_task() {
        use core::fmt::Write;
        let comm = proc_comm_of(pid).unwrap_or_else(|| alloc::string::String::from("?"));
        let _ = writeln!(
            narf_console::Writer,
            "[process-exit] kind=signal tid={} pid={} comm={} signal={} core_dumped={} ip={:x}",
            task,
            pid,
            comm,
            signum,
            core_dumped,
            ctx.rip()
        );
    }
    // [PROBE] Light (cgevt_trace-gated) twin of the above for the systemd
    // session-bringup investigation: if `systemd --user` (or an "(sd-*)" helper)
    // is killed by a signal rather than exit_group()ing, record WHICH signal —
    // pairs with the USEREXIT line in sys_exit_group so a flapping user@N.service
    // reports its cause on the console without the syscall-trace firehose.
    #[cfg(feature = "cgroup")]
    if narf_filesystem::cgroupfs::cgevt_trace_enabled() {
        let comm = proc_comm_of(pid).unwrap_or_default();
        let cg = narf_filesystem::cgroupfs::cgroup_path_of(pid);
        if comm == "systemd" || comm.starts_with("(sd") || cg.contains("user-957") {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "USEREXIT pid={} tid={} comm={} killed_by_signal={} core_dumped={} ip={:x} cg={}",
                pid,
                task,
                comm,
                signum,
                core_dumped,
                ctx.rip(),
                cg
            );
        }
    }
    stage_pending_termination(pid, encode_signaled_status(signum, core_dumped));
    // Robust-futex owner-died walk — must run HERE, in the dying task's
    // own trap context (its user AS is still active for the user-memory
    // reads/writes), before any teardown.
    robust_list_exit_walk(task);
    // wait4 rusage snapshot — same in-context requirement (EXIT_RUSAGE).
    record_exit_rusage(task, pid);
    // A fatal (default Terminate/CoreDump) signal kills the ENTIRE thread
    // group in Linux (get_signal -> do_group_exit), not just the faulting
    // thread. Zap every live sibling so a fault in ONE worker thread of a
    // multithreaded process (e.g. a Qt/kwin render thread dereferencing bad
    // memory) tears the whole process down instead of leaving the leader a
    // hung zombie that `kill -0` still reports alive.
    zap_thread_group(task, pid);

    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::exit_hook(),
    ) {
        // SAFETY: same contract as sys_exit_task — uctx is valid for
        // the lifetime of the in-flight polling routine on this CPU,
        // and the hook never returns.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            if core_dumped {
                crate::coredump::write_coredump(task, signum, &*uc.state.get());
            }
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_EXITED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                // own-stack: the poll's EXIT_REASON_EXITED trap-back half is
                // dead, so run its exit bookkeeping HERE before we diverge:
                // flip the refcounted task to ZOMBIE (it stays resolvable,
                // carrying its exit status, until the parent reaps) and fan
                // out exit observers — `on_child_exit` drains the staged
                // wstatus and WAKES a wait4-parked parent. Without this the
                // parent never wakes (the lost-wakeup idle-halt). Then mark
                // complete + kernel_switch out.
                crate::task::mark_zombie(task);
                crate::user_task::notify_task_exited(pid, task);
                narf_scheduler::stackful::exit_current_stackful();
            }
            hook(uctx);
        }
        // unreachable
    }

    if core_dumped {
        if let Some(uctx) = crate::user_task::current_user_task() {
            // SAFETY: uctx is valid.
            unsafe {
                let uc = &*uctx;
                ctx.save_user_state(uc.state.get() as *mut u8);
                crate::coredump::write_coredump(task, signum, &*uc.state.get());
            }
        }
    }
    // Test / no-polling-future path: caller (the signal hook) is
    // responsible for not re-entering user mode. Smokes drive
    // `notify_task_exited` directly to verify the status threading.
}

// ── ExitTask — redirect to a kernel-registered landing ─────────────

/// `exit_group(2)` — terminate the whole thread group (Linux
/// `do_group_exit`). Zap every OTHER live thread in the caller's group
/// (SIGKILL pending + wake; they self-terminate on their next delivery
/// point — trap return worst case) and set the group-exiting flag so
/// wait4 reports the group's exit code, then fall through to exit the
/// caller. For a single-threaded process this is exactly `exit`.
/// Tear down the whole thread group of `tid` (visible `pid`): flag it
/// group-exiting and zap every OTHER live CLONE_THREAD sibling with a
/// pending SIGKILL + wake (they self-terminate on their next delivery
/// point — trap return worst case). Shared by `exit_group(2)` and the
/// fatal-signal path: in Linux a default Terminate/CoreDump signal kills
/// the ENTIRE thread group (`get_signal` -> `do_group_exit`), not just
/// the faulting thread.
pub(crate) fn zap_thread_group(tid: u64, pid: u64) {
    if let Some(t) = crate::task::task_get(tid) {
        t.group_exiting
            .store(true, core::sync::atomic::Ordering::Release);
    }
    // Find live CLONE_THREAD siblings sharing this visible pid.
    let siblings: alloc::vec::Vec<u64> = task_pid_snapshot()
        .into_iter()
        .filter(|&(task, process)| process == pid && task != tid)
        .map(|(task, _)| task)
        .filter(|&task| {
            crate::task::task_get(task).is_some_and(|task| {
                task.state.load(core::sync::atomic::Ordering::Acquire)
                    == crate::task::TASK_RUNNING
            })
        })
        .collect();
    for s in siblings {
        raise_signal_pending(s, 9); // SIGKILL
        wake_signal(s);
    }
}

fn maybe_deliver_signal_before_yield(ctx: &mut dyn TrapContext, syscall_no: u32) -> bool {
    let task = current_task_id();
    let pending = signal_bits_get(&SIGNAL_PENDING, task);
    let mask = signal_mask_of(task);
    if (pending & !mask) != 0 {
        if let Some(hook) = signal_delivery_hook() {
            // EINTR
            ctx.set_return(SyscallReturn::ok((-4i64) as u64));
            hook(ctx, syscall_no);
            return true;
        }
    }
    false
}

// ── Yield — cooperative scheduler hand-back ────────────────────────

// ── restart_syscall — kernel-injected syscall continuation ─────────
//
// Linux ABI: `restart_syscall(void)` — x86_64 219 / aarch64 128. It is
// NOT meant to be called by userspace directly; the kernel injects it
// (rewriting the trap's syscall number) to resume a blocking syscall
// that was interrupted by a signal whose handler ran, when that syscall
// needs an *absolute* rearm point that a plain SA_RESTART RIP-rewind
// would corrupt (e.g. a relative `nanosleep` that must resume with the
// remaining, not the original, timeout). Linux backs this with a
// per-task `restart_block` (`current->restart_block.fn`) that points at
// the specific resume routine; when nothing set one, the block points
// at `do_no_restart_syscall`, which simply returns -EINTR.
//
// NARF's restart model has NO per-task restart_block. SA_RESTART is
// implemented purely by REWINDING the user RIP by 2 (the `syscall`
// instruction width) in `deliver_signal_into_state`
// (`state.rip.wrapping_sub(2)` — see syscall.rs), so an interrupted
// restartable syscall simply re-executes its original trap from scratch;
// the blocking syscalls that must not re-arm from scratch (nanosleep,
// clock_nanosleep, ...) are excluded from the restartable set in
// `is_restartable_syscall` and instead surface -EINTR / an abbreviated
// result to userspace. There is therefore no saved syscall to
// re-invoke here.
//
// We faithfully mirror Linux's no-restart-block case: `restart_syscall`
// with nothing pending returns -EINTR (errno 4), exactly as
// `do_no_restart_syscall` does. This keeps the wire number dispatchable
// (so a libc that emits it, or a trace replay, sees the canonical
// result) without inventing a restart-block subsystem that NARF's
// RIP-rewind model does not need.

// ── RingKick — drain the shared SQ, post completions to the CQ ────
//
// Slow-path counterpart to a UIPI/UMWAIT-driven async dispatcher.
// User code submits + calls `RingKick` + spins on the CQ until the
// real wake side-channel lands.

// ── GetPid / GetPpid — POSIX-shaped task-id surface ────────────────

// ── clone3(2) + set_tid_address — pthread bring-up surface ─────────
//
// Wave-65. Gated behind the `linux-compat` crate feature so non-
// Linux-shaped consumers (the testbin runner, kernel-internal task
// shapes) don't pull in the per-thread bookkeeping below.
//
// clone3(2) takes a single user pointer to `struct clone_args`
// (Linux kernel uapi/linux/sched.h). The kernel reads the flags +
// stack + tls + tid-pointer fields and routes:
//
//   - CLONE_VM       child shares parent's Arc<AddressSpace>.
//   - CLONE_THREAD   child joins the parent's thread group; its
//                    user-visible TGID is the parent's, while its
//                    TID is a fresh scheduler TaskId. Without this
//                    bit the child is treated as a process (fresh
//                    ProcessId allocation).
//   - CLONE_FS       cwd table shared (skip cwd_fork).
//   - CLONE_FILES    fd table shared (skip fd::fork).
//   - CLONE_SIGHAND  sigaction table shared (skip sigaction_fork).
//   - CLONE_SETTLS   args.tls programmed into the architecture's user TLS
//                    register on first dispatch (IA32_FS_BASE / TPIDR_EL0).
//   - CLONE_PARENT_SETTID writes the child TID into *args.parent_tid.
//   - CLONE_CHILD_CLEARTID stashes args.child_tid in a per-task slot;
//                    on thread exit, the kernel writes 0 there and
//                    FUTEX_WAKEs one waiter.
//
// Namespace flags are applied in the clone inheritance section below.
//
// set_tid_address(tidptr) sets the calling task's CLOSE_CHILD_CLEARTID
// slot in the same per-task table; returns the caller's TID.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_VM: u64 = 0x0000_0100;
/// `CLONE_VFORK`: the parent is suspended until the child `execve`s or exits.
/// glibc/musl `posix_spawn` and `vfork()` set this (with CLONE_VM) and run the
/// child on a caller-provided stack while sharing the parent's address space;
/// the parent MUST NOT resume — and thus must not mutate/free that shared AS
/// (e.g. munmap the child's stack) — until the child releases the mm. Linux
/// keeps the parent in TASK_KILLABLE across this window.
const CLONE_VFORK: u64 = 0x0000_4000;
/// `CLONE_PIDFD`: mint a pidfd on the child, installed in the PARENT's fd
/// table (the child does not inherit it — Linux allocates it after
/// `copy_files`), number written through `clone_args.pidfd`. glibc's
/// `pidfd_spawn` — the ONLY executor-spawn path systemd 258 uses — sets it.
const CLONE_PIDFD: u64 = 0x0000_1000;
/// `CLONE_CLEAR_SIGHAND` (clone3-only): the child starts with every signal
/// disposition SIG_DFL instead of a copy of the parent's table. glibc's
/// `posix_spawn`/`pidfd_spawn` passes it unconditionally (2.38+).
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
/// `CLONE_INTO_CGROUP` (clone3-only): `clone_args.cgroup` is an O_PATH
/// directory fd on cgroupfs; the child starts life in that cgroup instead
/// of inheriting the parent's. glibc `posix_spawn` with
/// `POSIX_SPAWN_SETCGROUP` (systemd's per-service spawn) sets it.
/// Consumed only under the `cgroup` feature (accepted-and-inherit otherwise).
#[cfg_attr(not(feature = "cgroup"), allow(dead_code))]
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Place a `clone3(CLONE_INTO_CGROUP)` child in the cgroup named by the O_PATH
/// directory fd `cgroup_fd` in `parent_task`'s fd table (systemd opens it with
/// `open(cgroup, O_PATH|O_DIRECTORY|O_CLOEXEC)` for pidfd_spawn /
/// POSIX_SPAWN_SETCGROUP). Resolves the fd to its recorded open path, strips the
/// live cgroupfs mount prefix, and attaches `child_pid`.
///
/// The result is a positive Linux errno. Invalid/non-cgroup descriptors are
/// EBADF; a cgroup removed after open is ENODEV; permission/controller vetoes
/// retain their corresponding errno. The clone caller aborts and rolls back
/// the allocated PID and any reserved pidfd on error, like
/// cgroup_css_set_fork() before wake_up_new_task().
#[cfg(feature = "cgroup")]
fn place_clone_into_cgroup(
    parent_task: u64,
    cgroup_fd: u32,
    child_linux_id: u64,
    thread: bool,
) -> Result<(), u64> {
    let full = crate::mqueue::fd_path(parent_task, cgroup_fd).ok_or(9u64)?; // EBADF
    let rel = cgroup_rel_path(&full).ok_or(9u64)?; // not a cgroupfs fd
    let result = if thread {
        let parent_tgid = task_to_pid_raw(parent_task).unwrap_or(parent_task);
        let parent_tid = task_to_linux_tid_raw(parent_task).unwrap_or(parent_tgid);
        narf_filesystem::cgroupfs::attach_thread_by_path(
            &rel,
            parent_tid,
            parent_tgid,
            child_linux_id,
        )
    } else {
        narf_filesystem::cgroupfs::attach_by_path(&rel, child_linux_id)
    }
    .map_err(|error| {
        match error {
            narf_filesystem::FsError::NotFound => 19,          // ENODEV
            narf_filesystem::FsError::PermissionDenied => 13, // EACCES
            narf_filesystem::FsError::Busy => 16,             // EBUSY
            narf_filesystem::FsError::BadFd => 9,              // EBADF
            narf_filesystem::FsError::Unsupported => 95,       // EOPNOTSUPP
            _ => 22,                                           // EINVAL
        }
    });
    if narf_filesystem::cgroupfs::cgevt_trace_enabled() {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "CGATTACH pid={} full={} rel={} result={:?}",
            child_linux_id,
            full,
            rel,
            result
        );
    }
    result
}

/// Resolve an absolute path that lands inside a mounted cgroup2/cgroupfs to its
/// cgroup-relative path (everything below the cgroupfs mount point).
///
/// cgroup2 is NOT fixed at `/sys/fs/cgroup`: it can be mounted anywhere, more
/// than once, and — under a chroot — the recorded path is host-view
/// (`/mnt/sys/fs/cgroup/...`). So this consults the live mount table and strips
/// the LONGEST matching `cgroup2`/`cgroupfs` mount prefix rather than assuming a
/// literal path. Returns `None` when `abs` is not under any cgroupfs mount (the
/// clone caller reports EBADF). The mount table is in the caller's mount
/// namespace, which is the space the cgroup fd was opened in.
#[cfg(feature = "cgroup")]
pub(crate) fn cgroup_rel_path(abs: &str) -> Option<alloc::string::String> {
    current_mount_list_with_names()
        .into_iter()
        .filter(|(mnt, name)| {
            (name.as_str() == "cgroup2" || name.as_str() == "cgroupfs")
                && (abs == mnt.as_str()
                    || (abs.starts_with(mnt.as_str())
                        && abs.as_bytes().get(mnt.len()) == Some(&b'/')))
        })
        .max_by_key(|(mnt, _)| mnt.len())
        .map(|(mnt, _)| {
            let rel = &abs[mnt.len()..];
            if rel.is_empty() {
                alloc::string::String::from("/")
            } else {
                alloc::string::String::from(rel)
            }
        })
}

/// Test seam for [`place_clone_into_cgroup`] — exercises the clone3
/// CLONE_INTO_CGROUP placement without spawning a real user task.
#[cfg(feature = "cgroup")]
#[doc(hidden)]
pub fn place_clone_into_cgroup_for_test(parent_task: u64, cgroup_fd: u32, child_pid: u64) -> bool {
    place_clone_into_cgroup(parent_task, cgroup_fd, child_pid, false).is_ok()
}
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_PARENT: u64 = 0x0000_8000;
const CLONE_FS: u64 = 0x0000_0200;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_FILES: u64 = 0x0000_0400;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_SIGHAND: u64 = 0x0000_0800;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_THREAD: u64 = 0x0001_0000;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_SYSVSEM: u64 = 0x0004_0000;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_SETTLS: u64 = 0x0008_0000;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

// Per-task CLONE_CHILD_CLEARTID slot. Keyed by scheduler TaskId raw
// — the consumer (`fire_clear_child_tid_on_exit`) is invoked from
// the exit-observer fan-out which receives the dying task's pid (=
// TaskId for a CLONE_THREAD child, = ProcessId for a fork()'d
// process; both cases route through `notify_task_exited(pid_raw)`
// which uses `this.process.pid.raw()`).
//
// `register_pid_task_mapping` already records the (ProcessId,
// TaskId) bindings sys_fork installs; for CLONE_THREAD children
// the kernel records the same TaskId on both sides so the lookup
// from exit-side `pid_raw` to "is there a clear_child_tid?" works
// uniformly.
/// Per-task clear_child_tid entry: user address, address-space root phys, and
/// private-futex namespace. Stashing both address-space identities at
/// registration time lets the exit observer write the word and wake the exact
/// `FUTEX_PRIVATE` queue after the scheduler has reaped the task's slot.
#[derive(Copy, Clone)]
struct ClearChildTidEntry {
    uaddr: u64,
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    as_root: narf_memory::PhysAddr,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    futex_namespace: u64,
}

static CLEAR_CHILD_TID: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, ClearChildTidEntry>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the clear_child_tid table. Called once at boot
/// alongside the other per-task state tables; idempotent.
pub fn clear_child_tid_init() {
    let mut g = CLEAR_CHILD_TID.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

fn set_clear_child_tid(task_id_raw: u64, uaddr: u64) {
    let (as_root, futex_namespace) = current_address_space()
        .map(|space| (space.root, futex_namespace_for_address_space(&space)))
        .unwrap_or((narf_memory::PhysAddr::new(0), 0));
    set_clear_child_tid_with_as(task_id_raw, uaddr, as_root, futex_namespace);
}

fn set_clear_child_tid_with_as(
    task_id_raw: u64,
    uaddr: u64,
    as_root: narf_memory::PhysAddr,
    futex_namespace: u64,
) {
    let mut g = CLEAR_CHILD_TID.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
    if let Some(m) = g.as_mut() {
        if uaddr == 0 {
            m.remove(&task_id_raw);
        } else {
            m.insert(
                task_id_raw,
                ClearChildTidEntry {
                    uaddr,
                    as_root,
                    futex_namespace,
                },
            );
        }
    }
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn take_clear_child_tid(task_id_raw: u64) -> Option<ClearChildTidEntry> {
    let mut g = CLEAR_CHILD_TID.lock();
    g.as_mut().and_then(|m| m.remove(&task_id_raw))
}

/// Test-only: install a clear_child_tid entry with an explicit private-futex
/// namespace and no AS root (the exit path then skips the word write but still
/// fires the wake), modelling a real thread whose private namespace is a live
/// AddressSpace Arc pointer (always nonzero in production).
#[doc(hidden)]
pub fn __test_set_clear_child_tid_scoped(task_id_raw: u64, uaddr: u64, futex_namespace: u64) {
    set_clear_child_tid_with_as(
        task_id_raw,
        uaddr,
        narf_memory::PhysAddr::new(0),
        futex_namespace,
    );
}

/// Diagnostic / test-only — inspect a task's clear_child_tid slot
/// without consuming it. Returns just the uaddr; AS root is
/// internal bookkeeping.
#[doc(hidden)]
pub fn __test_peek_clear_child_tid(task_id_raw: u64) -> Option<u64> {
    let g = CLEAR_CHILD_TID.lock();
    g.as_ref()
        .and_then(|m| m.get(&task_id_raw).map(|e| e.uaddr))
}

/// Force-clear the entire clear_child_tid table for test isolation.
#[doc(hidden)]
pub fn __test_reset_clear_child_tid() {
    *CLEAR_CHILD_TID.lock() = Some(BTreeMap::new());
}

/// Exit-observer body invoked from `notify_task_exited` for every
/// dying user task. If the task registered a clear_child_tid (via
/// `set_tid_address` or `clone3(CLONE_CHILD_CLEARTID)`), zero the
/// user word and fire FUTEX_WAKE on it so any pthread_join sleeper
/// observes the exit.
///
/// Called inside the polling future's exit fan-out, AFTER the user
/// state's longjmp has popped us back to kernel context but BEFORE
/// the AS Arc is dropped — for CLONE_THREAD children, the AS Arc is
/// shared with the parent so it stays mapped. The writes use the
/// kernel-side identity map via `paging::translate` to avoid
/// requiring an `activate()` (the user task's AS was active at longjmp and the
/// trap-exit path restored the kernel address-space context before reaching us;
/// we don't want to switch user roots again
/// just for one qword write).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn fire_clear_child_tid_on_exit(_pid_raw: u64, tid_raw: u64) {
    // The clear_child_tid table is keyed by TaskId (= tid_raw),
    // NOT by visible pid. For CLONE_THREAD children, pid_raw is
    // the parent's pid (shared via the thread group) while tid_raw
    // is the child's unique scheduler TaskId — which is what
    // `set_clear_child_tid_with_as` recorded.
    let entry = match take_clear_child_tid(tid_raw) {
        Some(e) if e.uaddr != 0 => e,
        _ => return,
    };
    let uaddr = entry.uaddr;
    // ORDER IS LOAD-BEARING: write the child-tid word to 0 BEFORE bumping the
    // futex counter + waking waiters. pthread_join FUTEX_WAITs while
    // `*child_tid == old_tid`; when we wake it, it re-reads the word and must
    // already see 0, or it re-parks and only the ~10 ms wheel fallback rescues
    // it (a lost-wake-shaped join stall). This mirrors a mutex unlock (write
    // the word, THEN wake) — the reverse of the previous order here.
    //
    // Write zero into *uaddr via the page tables of the AS the task ran in
    // (its PML4 phys was stashed at clone time, so this works even after the
    // scheduler reaps the slot). Best-effort: if the AS was already torn down
    // (or the word crosses a page / doesn't resolve), skip the write but still
    // fire the wake below — the counter bump covers any waiter on this uaddr.
    let root = entry.as_root;
    if root.as_u64() != 0 {
        let page = uaddr & !0xFFFu64;
        let off = uaddr & 0xFFFu64;
        // A 4-byte futex word crossing a page boundary is structurally invalid
        // (futex words must be naturally aligned) — skip the write only.
        if off + 4 <= 4096 {
            // SAFETY: `root` is the exited task's recorded page-table root
            // (non-zero, checked above); `translate` walks it read-only to
            // resolve the page-aligned user `page` to its current phys frame.
            // SAFETY: Valid memory or trusted environment
            #[cfg(target_arch = "x86_64")]
            let translated = unsafe {
                narf_memory::x86_64::paging::translate(root, narf_memory::VirtAddr::new(page))
            };
            #[cfg(target_arch = "aarch64")]
            // SAFETY: same live recorded root and read-only translation walk as
            // the x86_64 branch above.
            let translated = unsafe {
                narf_memory::aarch64::paging::translate(root, narf_memory::VirtAddr::new(page))
            };
            if let Some(phys) = translated {
                // SAFETY: the AS Arc keeps the backing frame alive. Use the
                // kernel direct-map accessor so this remains valid through
                // TTBR0 changes on aarch64 and for high RAM on x86_64.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    *narf_memory::PhysAddr::new(phys.as_u64() + off).kernel_mut_ptr::<u32>() = 0;
                }
            }
        }
    }

    // NOW bump the counter (lost-wakeup gen guard) AND fire every parked waiter
    // on this uaddr — AFTER the word write above, so a joiner's wake→re-read
    // observes the cleared (0) word and proceeds instead of re-parking.
    //
    // Wake BOTH namespaces. Linux's mm_release fires the exit wake as
    // `do_futex(tidptr, FUTEX_WAKE, 1, ...)` with NO FUTEX_PRIVATE_FLAG
    // (kernel/fork.c) — i.e. SHARED (namespace 0) — and glibc's pthread_join
    // (`lll_futex_wait` on `__default_pthread_attr`-cleared child_tid) and
    // musl's `__tl_lock` both wait SHARED on that word. Waking only the
    // recorded private namespace therefore missed every glibc/musl joiner and
    // degraded each join to the ~10 ms timer backstop (a lost-wake-shaped
    // stall). Keep the private wake too so any private waiter on the word is
    // still served; over-waking a namespace with no waiter is a cheap no-op.
    let key = futex_key(entry.futex_namespace, uaddr);
    futex_bump_counter_key(key);
    futex_wake_waiters_key(key, u32::MAX);
    if entry.futex_namespace != 0 {
        let shared_key = futex_key(0, uaddr);
        futex_bump_counter_key(shared_key);
        futex_wake_waiters_key(shared_key, u32::MAX);
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn fire_clear_child_tid_on_exit(_pid_raw: u64, _tid_raw: u64) {
    // Other arches do not yet have a user-task clone path.
}

/// Register the clear_child_tid observer (THREAD-scoped: fires per
/// exiting thread — pthread_join waits on the per-`tid` clear_child_tid
/// futex). Idempotent and safe to call before `clear_child_tid_init`
/// (the observer no-ops on an unpopulated table).
pub fn install_clear_child_tid_observer() {
    crate::user_task::register_thread_exit_observer(fire_clear_child_tid_on_exit);
}

/// Linux `struct clone_args` — uapi shape from <linux/sched.h>.
/// All fields are u64 on the wire; the kernel reads only the
/// subset we honour.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    // Linux CLONE_ARGS_SIZE_VER1 (set_tid) + VER2 (cgroup) tail. We copy
    // only as many bytes as the user provided (the second arg to clone3
    // is the struct size), so a VER0 (64-byte) caller leaves these zero.
    /// `set_tid` array pointer — requested PIDs, innermost namespace first.
    set_tid: u64,
    /// `set_tid` array length.
    set_tid_size: u64,
    /// CLONE_INTO_CGROUP target: an O_PATH dir fd on cgroupfs.
    cgroup: u64,
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_ARGS_MIN: usize = core::mem::size_of::<CloneArgs>();

// ── CLONE_VFORK: parent suspended until the child execs or exits ──────
//
// Maps a live vfork child's visible pid → the parent task id parked in the
// clone syscall. The parent installs an entry before parking; the child's
// `execve`/exit path calls `vfork_child_release`, which drops the entry and
// wakes the parent. While an entry is present the parent stays parked, so it
// cannot resume and mutate the shared address space (e.g. munmap the child's
// stack) out from under a still-running CLONE_VM child — the race that SIGSEGV'd
// every glibc `posix_spawn` service child under systemd.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
static VFORK_WAIT: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn vfork_wait_register(child_pid: u64, parent_task: u64) {
    let mut g = VFORK_WAIT.lock();
    g.get_or_insert_with(BTreeMap::new)
        .insert(child_pid, parent_task);
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn vfork_is_pending(child_pid: u64) -> bool {
    VFORK_WAIT
        .lock()
        .as_ref()
        .is_some_and(|m| m.contains_key(&child_pid))
}

/// Called from the child's `execve` and exit paths: if this child had a vfork
/// parent parked on it, drop the entry and wake the parent. `child_pid` is the
/// child's visible pid. Idempotent (only the first exec/exit releases).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn vfork_child_release(child_pid: u64) {
    let parent = {
        let mut g = VFORK_WAIT.lock();
        g.as_mut().and_then(|m| m.remove(&child_pid))
    };
    if let Some(parent_task) = parent {
        wake_signal(parent_task);
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn current_user_tls_base() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    let value = {
        // SAFETY: IA32_FS_BASE is architectural and readable at CPL0.
        unsafe { narf_arch::x86_64::msr::rdmsr(narf_arch::x86_64::IA32_FS_BASE) }
    };
    #[cfg(target_arch = "aarch64")]
    let value = {
        let value: u64;
        // SAFETY: TPIDR_EL0 is the live EL0 thread pointer and is readable
        // from EL1 without changing architectural state.
        unsafe {
            core::arch::asm!(
                "mrs {value}, TPIDR_EL0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    };
    #[cfg(target_arch = "x86_64")]
    return (value != 0).then_some(value);
    #[cfg(target_arch = "aarch64")]
    Some(value)
}

/// Validate the Linux-visible clone contract before allocating or publishing
/// any child state. The returned value is a positive errno number.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn validate_clone_args(ca: &CloneArgs, legacy: bool, requested_tids: &[i32]) -> Result<(), u64> {
    const EINVAL: u64 = 22;
    const CLONE_DETACHED: u64 = 0x0040_0000;
    const CLONE_PARENT: u64 = 0x0000_8000;
    const CLONE_NEWNS: u64 = 0x0002_0000;
    const CLONE_NEWIPC: u64 = 0x0800_0000;
    const CLONE_NEWUSER: u64 = 0x1000_0000;
    const CLONE_NEWPID: u64 = 0x2000_0000;

    if !legacy && ca.exit_signal > 64 {
        return Err(EINVAL);
    }
    if ca.set_tid_size > 32
        || (ca.set_tid == 0 && ca.set_tid_size != 0)
        || (ca.set_tid != 0 && ca.set_tid_size == 0)
    {
        return Err(EINVAL);
    }
    if ca.flags & CLONE_INTO_CGROUP != 0 && ca.cgroup > i32::MAX as u64 {
        return Err(EINVAL);
    }
    if !legacy {
        // clone3 reserves the low signal bits (the signal lives in
        // exit_signal) and currently defines only bits 0..=33.
        const CLONE3_KNOWN_FLAG_BITS: u64 = (1u64 << 34) - 1;
        if ca.flags & (0x7f | CLONE_DETACHED) != 0 || ca.flags & !CLONE3_KNOWN_FLAG_BITS != 0 {
            return Err(EINVAL);
        }
        if (ca.stack == 0) != (ca.stack_size == 0) {
            return Err(EINVAL);
        }
    }
    if ca.stack.checked_add(ca.stack_size).is_none() {
        return Err(EINVAL);
    }
    if !legacy && ca.stack != 0 && ca.stack + ca.stack_size > crate::handlers::USER_VA_LIMIT {
        // Linux clone3 reports a failed access_ok(stack, stack_size) as
        // EINVAL, not EFAULT.
        return Err(EINVAL);
    }
    if ca.flags & CLONE_THREAD != 0 && ca.flags & CLONE_SIGHAND == 0 {
        return Err(EINVAL);
    }
    if ca.flags & CLONE_SIGHAND != 0 && ca.flags & CLONE_VM == 0 {
        return Err(EINVAL);
    }
    if ca.flags & CLONE_FS != 0 && ca.flags & (CLONE_NEWNS | CLONE_NEWUSER) != 0 {
        return Err(EINVAL);
    }
    if ca.flags & CLONE_NEWIPC != 0 && ca.flags & CLONE_SYSVSEM != 0 {
        return Err(EINVAL);
    }
    if ca.flags & CLONE_THREAD != 0 && ca.flags & (CLONE_NEWUSER | CLONE_NEWPID) != 0 {
        return Err(EINVAL);
    }
    #[cfg(feature = "container")]
    if ca.flags & CLONE_THREAD != 0
        && !crate::pid_ns::active_matches_for_children(current_task_id())
    {
        return Err(EINVAL);
    }
    if ca.flags & CLONE_SIGHAND != 0 && ca.flags & CLONE_CLEAR_SIGHAND != 0 {
        return Err(EINVAL);
    }
    if !legacy && ca.flags & (CLONE_THREAD | CLONE_PARENT) != 0 && ca.exit_signal != 0 {
        return Err(EINVAL);
    }
    if ca.flags & CLONE_PIDFD != 0
        && ca.flags & CLONE_PARENT_SETTID != 0
        && ca.pidfd == ca.parent_tid
    {
        return Err(EINVAL);
    }
    if ca.flags & CLONE_PIDFD != 0 && ca.flags & CLONE_DETACHED != 0 {
        return Err(EINVAL);
    }
    if requested_tids.len() != ca.set_tid_size as usize {
        return Err(EINVAL);
    }
    #[cfg(feature = "container")]
    {
        let levels = crate::pid_ns::clone_pid_levels(
            current_task_id(),
            ca.flags & CLONE_NEWPID != 0,
        )?;
        if requested_tids.len() > levels {
            return Err(EINVAL);
        }
    }
    #[cfg(not(feature = "container"))]
    if requested_tids.len() > 1 {
        return Err(EINVAL);
    }
    if requested_tids
        .iter()
        .any(|&tid| tid <= 0 || tid as u64 > crate::PID_MAX)
    {
        return Err(EINVAL);
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn clone_parent_link(parent_task: u64, flags: u64, requested_signal: u8) -> Result<ChildLink, u64> {
    if flags & CLONE_PARENT == 0 {
        return Ok(ChildLink {
            parent: parent_task,
            exit_signal: requested_signal,
        });
    }

    // Linux copy_process reuses current->real_parent and inherits the
    // caller's group-leader exit_signal. A namespace init has no reusable
    // parent and Linux rejects CLONE_PARENT with EINVAL.
    let parent_pid = task_to_pid_raw(parent_task).unwrap_or(parent_task);
    child_link_get(parent_pid).ok_or(22)
}

#[doc(hidden)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn __test_clone_parent_link(
    parent_task: u64,
    flags: u64,
    requested_signal: u8,
) -> Result<(u64, u8), u64> {
    clone_parent_link(parent_task, flags, requested_signal)
        .map(|link| (link.parent, link.exit_signal))
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn do_clone3(ctx: &mut dyn TrapContext, ca: CloneArgs, legacy: bool, requested_tids: &[i32]) {
    use crate::process::DEFAULT_USER_STACK_BYTES;
    let flags = ca.flags;
    if let Err(errno) = validate_clone_args(&ca, legacy, requested_tids) {
        ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
        return;
    }
    if (flags & CLONE_PIDFD != 0
        && validate_user_range(ca.pidfd, core::mem::size_of::<i32>()).is_err())
        || (flags & CLONE_PARENT_SETTID != 0
            && validate_user_range(ca.parent_tid, core::mem::size_of::<i32>()).is_err())
    {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    let parent_pid = current_task_id();
    let child_wait_link = if flags & CLONE_THREAD == 0 {
        match clone_parent_link(parent_pid, flags, ca.exit_signal as u8) {
            Ok(link) => Some(link),
            Err(errno) => {
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
        }
    } else {
        None
    };

    let parent_as = match current_address_space() {
        Some(a) => a,
        None => {
            // A Linux process cannot clone without an mm/task context. Treat
            // failure to resolve that context like task-state allocation.
            ctx.set_return(SyscallReturn::ok((-12i64) as u64));
            return;
        }
    };

    // Fork-bomb guard (also covers pthread/thread storms — every clone mints a
    // user task). EAGAIN at the live-task cap, matching clone(2)/fork(2).
    if !narf_scheduler::user_nproc_available() {
        ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        return;
    }

    // CLONE_VM: share AS via Arc::clone. Without it, this would be a
    // full fork — but pthread always passes CLONE_VM so the no-VM
    // path is uncommon. We support both: no-VM falls back to
    // `clone_for_fork` (sys_fork's path).
    let share_vm = (flags & CLONE_VM) != 0;
    let share_thread = (flags & CLONE_THREAD) != 0;
    let share_fs = (flags & CLONE_FS) != 0;
    let _share_files = (flags & CLONE_FILES) != 0;
    let share_sighand = (flags & CLONE_SIGHAND) != 0;
    let share_sysvsem = (flags & CLONE_SYSVSEM) != 0;
    // No-VM (fork-shaped) path: redirect to sys_fork's machinery.
    // The clone_args fields not consumed by fork are accepted-and-
    // ignored on this branch (Linux behaviour: clone3 without
    // CLONE_VM produces a process, not a thread, and TLS / tid
    // pointers are still honoured but in a separate AS).
    let child_as = if share_vm {
        // The AS is now (potentially) resident on several CPUs at once —
        // PTE mutations must broadcast cross-CPU TLB shootdowns from here
        // on (single-threaded ASes skip them; see `vm_shared`'s docs).
        parent_as.mark_vm_shared();
        parent_as.clone()
    } else {
        // SAFETY: paging is live and `parent_as` is the caller's current
        // AddressSpace; clone_for_fork duplicates its region table for the child.
        // SAFETY: Valid memory or trusted environment
        let dup = match unsafe { parent_as.clone_for_fork() } {
            Ok(a) => a,
            Err(_) => {
                // COW dup allocation failed → ENOMEM.
                ctx.set_return(SyscallReturn::ok((-12i64) as u64));
                return;
            }
        };
        // Leave ordinary child leaves uninstalled, matching `sys_fork`'s lazy
        // COW path. The first child access demand-faults the already-retained
        // `Region::phys` frame as read-only and a later write splits it. This is
        // especially important for clone callers with large resident mappings:
        // constructing page tables for untouched child pages made clone cost
        // proportional to the parent's resident set. Private huge mappings are
        // still copied and installed eagerly by `clone_for_fork` because they
        // have no base-page demand-fault path.
        // `clone_for_fork` has already write-protected only the present parent
        // leaves whose backing became newly shared.
        alloc::sync::Arc::new(dup)
    };
    // Reserve the pidfd number before allocating a PID or publishing child
    // state. Linux pidfd_prepare makes descriptor exhaustion fail the entire
    // clone with EMFILE, and put_user failure aborts with EFAULT. A reservation
    // also closes the CLONE_FILES sibling race between a free-fd probe and the
    // eventual install.
    let reserved_pidfd = if flags & CLONE_PIDFD != 0 {
        let reserved = crate::fd::with_table_alloc(parent_pid, |table| table.reserve_fds(1))
            .flatten();
        let Some(fd) = reserved.and_then(|fds| fds.first().copied()) else {
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // EMFILE
            return;
        };
        let fd_bytes = (fd as i32).to_ne_bytes();
        // SAFETY: the output range passed the structural check above; the
        // guarded copy detects an actually unmapped page.
        if unsafe { copy_to_user(ca.pidfd, &fd_bytes) }.is_err() {
            let _ = crate::fd::with_table(parent_pid, |table| {
                table.release_reserved(&[fd]);
            });
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
        Some(fd)
    } else {
        None
    };
    // Stack: for `clone3(2)`, `ca.stack` points at the LOW end
    // of the user-provided stack region and `ca.stack_size` is
    // the byte length; the child's initial SP is the top
    // (`stack + stack_size`). For the legacy `clone(2)` syscall
    // (sys_clone synthesises a CloneArgs), `ca.stack` is ALREADY
    // the top and `ca.stack_size` is 0 — `stack + 0` recovers
    // the top. The combined check is therefore just "stack
    // pointer is non-zero".
    // A THREAD (CLONE_VM: shares the parent's address space) must bring
    // its own stack — reusing the parent's would collide. A fork-shaped
    // clone (no CLONE_VM) instead COW-copies the whole AS, so `stack == 0`
    // is valid and means "resume the child on the (COW) parent stack at
    // the parent's SP" — exactly what glibc's fork() passes
    // (`clone(SIGCHLD|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID, stack=0)`).
    let rsp = if ca.stack != 0 {
        // Overflow was rejected by validate_clone_args.
        ca.stack + ca.stack_size
    } else {
        // Fork: inherit the parent's user SP (child runs on its COW copy).
        ctx.user_rsp()
    };

    // Entry: clone3 doesn't carry an explicit entry PC in
    // clone_args. The child resumes at the parent's saved trap-
    // frame PC (the instruction after the clone3 syscall) with
    // a rewritten return value of 0 — same shape as fork(). User code
    // dispatches "am I the child? if so, call my start_routine"
    // off the zero return value (relibc's pthread_create does
    // exactly this).
    let child_state: Option<crate::user_task::UserState> = {
        use core::mem::MaybeUninit;
        let mut s = MaybeUninit::<crate::user_task::UserState>::zeroed();
        // SAFETY: `s` is a zeroed UserState-sized buffer; save_user_state writes a
        // full UserState trap-frame snapshot into it, fully initializing the bytes.
        // SAFETY: Valid memory or trusted environment
        let ok = unsafe { ctx.save_user_state(s.as_mut_ptr() as *mut u8) };
        if ok {
            // SAFETY: save_user_state returned true above, so `s` holds a fully
            // initialized UserState.
            // SAFETY: Valid memory or trusted environment
            let mut snap = unsafe { s.assume_init() };
            #[cfg(target_arch = "x86_64")]
            {
                snap.rax = 0;
            }
            #[cfg(target_arch = "aarch64")]
            {
                snap.x[0] = 0;
                snap.x[1] = 0;
            }
            // Plant the user-supplied SP. The parent's trap-frame
            // SP stays in the parent's snapshot (its set_return
            // path writes its own return register later); the
            // child's snapshot gets the freshly-allocated thread
            // stack.
            #[cfg(target_arch = "x86_64")]
            {
                snap.rsp = rsp;
            }
            #[cfg(target_arch = "aarch64")]
            {
                snap.sp = rsp;
            }
            Some(snap)
        } else {
            None
        }
    };

    #[cfg(feature = "container")]
    let prepared_user_ns = if flags & crate::namespaces::CLONE_NEWUSER != 0 {
        Some(crate::namespaces::UserNamespace::new_child(
            crate::namespaces::current_user_ns(parent_pid),
            read_uidgid(parent_pid).euid,
        ))
    } else {
        None
    };
    #[cfg(feature = "container")]
    let pid_plan = {
        let new_pid = flags & crate::namespaces::CLONE_NEWPID != 0;
        let pid_owner = new_pid.then(|| {
            prepared_user_ns
                .clone()
                .unwrap_or_else(|| crate::namespaces::current_user_ns(parent_pid))
        });
        match crate::pid_ns::prepare_clone(parent_pid, requested_tids, new_pid, pid_owner) {
            Ok(plan) => plan,
            Err(errno) => {
                if let Some(fd) = reserved_pidfd {
                    let _ = crate::fd::with_table(parent_pid, |table| {
                        table.release_reserved(&[fd]);
                    });
                }
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
        }
    };

    #[cfg(feature = "container")]
    let allocated_linux_id = pid_plan.outer();
    #[cfg(feature = "container")]
    let child_ns_pid = pid_plan.parent_visible();

    #[cfg(not(feature = "container"))]
    let allocated_linux_id = {
        // Linux performs the set_tid capability check from alloc_pid(), after
        // copy_mm(). Keep it beside PID allocation so an earlier address-space
        // allocation failure retains Linux's ENOMEM precedence.
        if !requested_tids.is_empty()
            && !capable(CAP_CHECKPOINT_RESTORE)
            && !capable(CAP_SYS_ADMIN)
        {
            if let Some(fd) = reserved_pidfd {
                let _ = crate::fd::with_table(parent_pid, |table| {
                    table.release_reserved(&[fd]);
                });
            }
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        let allocated = match requested_tids.first().copied() {
            Some(requested) => crate::alloc_pid_specific(requested as u64).map(|pid| pid.raw()),
            None => {
                let pid = crate::alloc_pid().raw();
                if pid == 0 {
                    Err(EAGAIN_CODE)
                } else {
                    Ok(pid)
                }
            }
        };
        match allocated {
            Ok(pid) => pid,
            Err(errno) => {
                if let Some(fd) = reserved_pidfd {
                    let _ = crate::fd::with_table(parent_pid, |table| {
                        table.release_reserved(&[fd]);
                    });
                }
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
        }
    };

    let child_visible_pid = if share_thread {
        // Parent's getpid() lookup — fall back to parent_pid if unregistered.
        task_to_pid_raw(parent_pid).unwrap_or(parent_pid)
    } else {
        allocated_linux_id
    };
    // Linux resolves and authorizes CLONE_INTO_CGROUP before publishing the
    // child. Do the same immediately after PID allocation: on failure the PID
    // and pre-reserved pidfd are still private and can be rolled back exactly.
    #[cfg(feature = "cgroup")]
    let clone_into_cgroup_placed = if flags & CLONE_INTO_CGROUP != 0 {
        match place_clone_into_cgroup(
            parent_pid,
            ca.cgroup as u32,
            allocated_linux_id,
            share_thread,
        ) {
            Ok(()) => true,
            Err(errno) => {
                #[cfg(feature = "container")]
                pid_plan.rollback();
                #[cfg(not(feature = "container"))]
                crate::release_pid(crate::ProcessId(allocated_linux_id));
                if let Some(fd) = reserved_pidfd {
                    let _ = crate::fd::with_table(parent_pid, |table| {
                        table.release_reserved(&[fd]);
                    });
                }
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
        }
    } else {
        false
    };
    if !share_thread {
        crate::sysvipc::clone_sem_undo(
            task_to_pid_raw(parent_pid).unwrap_or(parent_pid),
            child_visible_pid,
            share_sysvsem,
        );
    }

    // Parent-of bookkeeping MUST be published BEFORE the child is spawned (a
    // new *process*; threads are not waitpid-reapable). `spawn_user_process*`
    // makes the child runnable, and under SMP it can run `ptrace(TRACEME)` on
    // another CPU before this handler finishes — TRACEME reads this same
    // PARENT_OF map and returns EINVAL (registering no tracer) if the row is
    // absent, degrading the child's `raise(SIGSTOP)` to a job-control stop that
    // a plain waitpid never reaps (the SMP strace_smoke flake). Publishing here
    // closes the window (was previously set only after all the inheritance work
    // below, well past the point the spawned child could already be running).
    if !share_thread {
        let link = child_wait_link.expect("non-thread clone must have a wait-parent link");
        parent_of_set_with_signal(
            child_visible_pid,
            link.parent,
            link.exit_signal,
        );
    }

    // CLONE_VFORK: register the parent as suspended on this child BEFORE the
    // child is spawned/made runnable. Under SMP (or an immediate exec) the
    // child can run and release before this handler reaches the park below;
    // publishing here means the park's `vfork_is_pending` check either finds
    // the entry (child not yet done → park) or finds it already dropped (child
    // released → proceed) — no lost-wake window either way.
    if flags & CLONE_VFORK != 0 {
        vfork_wait_register(child_visible_pid, parent_pid);
    }
    // Publish inherited mapping owners before the child becomes runnable.
    // Otherwise an immediate child exit can race the late copy and leave an
    // owner reference keyed to a process that has already been reaped.
    if !share_vm {
        crate::mapped_file::fork_address_space(parent_as.identity(), child_as.identity());
    }

    // CLONE_PIDFD: mint the shared exit-state BEFORE the child is spawned.
    // `pidfd::notify_exit` only flips entries that already exist in the
    // table — under SMP (or an exec-then-crash child) the child can exit
    // before this handler finishes, and a late mint would never observe
    // that exit (POLLIN never fires; systemd would supervise a ghost).
    // The fd itself is installed after the child's fd-table fork below.
    let pidfd_state = if reserved_pidfd.is_some() {
        // tid=0: the child task does not exist yet (this mints BEFORE the
        // spawn, on purpose). `set_tid` publishes the leader TaskId once the
        // child is spawned below; until then the `exited` flag alone drives
        // readiness, which the tiny mint→spawn window can only ever set true.
        Some(crate::pidfd::mint_for(child_visible_pid, 0, true))
    } else {
        None
    };
    // Diagnostic: pid the CLONE_PIDFD pidfd is minted under. Compare with the
    // PIDFD-EXIT line for the same process's exit — a mismatch (or a
    // pidfd_found=false there) is the reap-hang root cause.
    #[cfg(feature = "cgroup")]
    if narf_filesystem::cgroupfs::cgevt_trace_enabled() && flags & CLONE_PIDFD != 0 && ca.pidfd != 0
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "PIDFD-MINT child_visible_pid={}",
            child_visible_pid
        );
    }

    let proc = crate::UserProcess {
        pid: crate::ProcessId(child_visible_pid),
        address_space: child_as.clone(),
        entry: crate::EntryPoint(narf_memory::VirtAddr::new(0)),
        stack_top: narf_memory::VirtAddr::new(rsp),
        fs_base: if (flags & CLONE_SETTLS) != 0 {
            Some(ca.tls)
        } else {
            // Inherit the live architecture TLS register (FS_BASE or
            // TPIDR_EL0); the user-task poller restores it before EL0 entry.
            current_user_tls_base()
        },
        entry_arg: None,
        loaded_mappings: alloc::vec::Vec::new(),
    };
    let _ = DEFAULT_USER_STACK_BYTES;

    // Snapshot the AS root phys before the Arc is moved into the
    // scheduler — needed by the exit-observer to write the
    // clear_child_tid futex word after the slot is reaped.
    let child_as_root = child_as.root;
    let child_futex_namespace = futex_namespace_for_address_space(&child_as);
    // A new thread joins the group — bump `signal->live` BEFORE the
    // child is spawned/enqueued. Under SMP another CPU can pick up and
    // EXIT the child the instant it's runnable; a not-yet-counted first
    // sibling would then `dec` from absent→group_dead and reap the whole
    // still-live process out from under its main thread. Linux
    // increments in copy_process under tasklist_lock, pre-wake. No
    // fallible step separates this from the spawn, so it can't leak.
    if share_thread {
        thread_group_live_inc(child_visible_pid);
    }
    // Reserve and register the child now, but do not enqueue it until all
    // inherited state below has been installed.  A vfork/posix_spawn child may
    // execute its first `execveat(AT_EMPTY_PATH)` immediately, so publishing
    // it before `fd::fork` is an SMP-visible ENOENT race.
    let mut child_spec = narf_scheduler::TaskSpec::user_task();
    if share_thread {
        // `CLONE_THREAD` shares the parent's mm and usually its hottest data.
        // Keep Linux's clone wake-affinity shape: start the sibling on the
        // creating CPU instead of consuming the global new-process round-robin
        // preference. This is only a soft hint (`allowed` remains unchanged),
        // so an idle CPU can still steal the thread when that is beneficial.
        let parent_cpu = narf_scheduler::CpuId(narf_lib::percpu::current_cpu() as u32);
        if child_spec.affinity.allowed.contains(parent_cpu) {
            child_spec.affinity.preferred = Some(parent_cpu);
        }
    }
    let mut pending_child = match child_state {
        Some(state) => crate::user_task::prepare_user_process_resume(
            proc,
            state,
            child_spec,
        ),
        None => crate::user_task::prepare_user_process_initial(proc, child_spec),
    };
    let child_tid = pending_child.task_id();
    #[cfg(feature = "container")]
    pid_plan.install(child_tid.raw());
    proc_identity_fork(parent_pid, child_tid.raw());
    // Publish the pidfd's target leader TaskId now that the child task exists.
    // Linux records set_child_tid in copy_process and performs the best-effort
    // put_user from schedule_tail, after switching to the child's mm and before
    // its first return to userspace. Arm the prepared future before publication
    // so its first poll can do the same in the active child address space.
    if flags & CLONE_CHILD_SETTID != 0 && ca.child_tid != 0 {
        pending_child.set_child_tid(ca.child_tid);
    }
    // Only for a real process clone: for CLONE_THREAD the pidfd tracks the
    // existing process leader, not this new thread, so leave it unresolved and
    // let the `exited` cache drive it (unchanged from before pidfds grew a tid).
    if !share_thread {
        if let Some(st) = &pidfd_state {
            st.set_tid(child_tid.raw());
        }
    }

    // Register the (visible-pid → TaskId) binding. For
    // CLONE_THREAD children visible_pid == parent's pid, so the
    // mapping is "child TaskId → parent's PID" — gettid returns
    // the TaskId raw, getpid translates TaskId → PID.
    if share_thread {
        #[cfg(feature = "cgroup")]
        if !clone_into_cgroup_placed {
            let parent_tgid = task_to_pid_raw(parent_pid).unwrap_or(parent_pid);
            let parent_tid = task_to_linux_tid_raw(parent_pid).unwrap_or(parent_tgid);
            narf_filesystem::cgroupfs::fork_thread_inherit(
                parent_tid,
                parent_tgid,
                allocated_linux_id,
            );
        }
        register_thread_task_mapping(allocated_linux_id, child_tid.raw(), child_visible_pid);
    } else {
        register_pid_task_mapping(child_visible_pid, child_tid.raw());
        // A clone() that creates a new process (not a thread) joins
        // the parent's cgroup. Threads share the process's membership
        // and are never placed individually in the base feature.
        //
        // CLONE_INTO_CGROUP was resolved and committed before any child state
        // became visible. Ordinary clones inherit here; explicitly placed
        // children retain the already-committed target membership.
        #[cfg(feature = "cgroup")]
        if !clone_into_cgroup_placed {
            // cgroup membership is keyed by ProcessId — look the parent up by
            // its ProcessId, not the raw TaskId (see sys_fork).
            narf_filesystem::cgroupfs::fork_inherit(
                task_to_pid_raw(parent_pid).unwrap_or(parent_pid),
                child_visible_pid,
            );
        }
        // cgroup-namespace inheritance, and CLONE_NEWCGROUP → the child
        // gets a fresh cgroup-ns rooted at its current cgroup.
        #[cfg(all(feature = "cgroup", feature = "container"))]
        {
            const CLONE_NEWCGROUP: u64 = 0x0200_0000;
            narf_filesystem::cgroupfs::fork_inherit_ns(parent_pid, child_visible_pid);
            if flags & CLONE_NEWCGROUP != 0 {
                // The owner is the CREATING task's user namespace — the
                // parent's, since `copy_cgroup_ns` runs with the parent's
                // credentials before the child is running.
                narf_filesystem::cgroupfs::unshare_cgroup_ns_owned_by(
                    child_visible_pid,
                    ns_owner_for(current_task_id()),
                );
            }
        }
    }

    // Rlimits are process/TGID state (shared by CLONE_THREAD, copied by a real
    // process clone); capabilities remain per-thread credentials and copy in
    // both cases.
    rlimit_fork(parent_pid, child_tid.raw());
    cap_fork(parent_pid, child_tid.raw());
    // Linux copy_io(): CLONE_IO shares the caller's existing io_context;
    // otherwise a present context is copied. This includes ioprio state.
    const CLONE_IO: u64 = 0x8000_0000;
    ioprio_fork(parent_pid, child_tid.raw(), flags & CLONE_IO != 0);

    // fd table: CLONE_FILES (every pthread) SHARES one table with the parent —
    // an fd opened by any thread is visible to all, and close/dup affect all
    // (Linux semantics weston's worker threads rely on). Without CLONE_FILES
    // (fork) the child gets an independent COPY.
    if _share_files {
        crate::fd::share(parent_pid, child_tid.raw());
    } else {
        crate::fd::fork(parent_pid, child_tid.raw());
    }
    crate::mqueue::fork_fd_paths(parent_pid, child_tid.raw());

    // CLONE_PIDFD: publish the already-reserved descriptor only after the
    // child's fd-table copy. A non-CLONE_FILES child therefore cannot inherit
    // it; a CLONE_FILES child sees it through the intentionally shared table,
    // matching Linux copy_files followed by pidfd_prepare.
    if let (Some(st), Some(reserved_fd)) = (pidfd_state, reserved_pidfd) {
        let file: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
            alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(st));
        let installed = crate::fd::with_table(parent_pid, |table| {
            table.install_reserved_batch(alloc::vec![(
                reserved_fd,
                crate::fd::FdEntry {
                    ops: file,
                    offset: 0,
                    flags: crate::fd::FD_CLOEXEC,
                    status_flags: 0,
                },
            )])
        }) == Some(true);
        assert!(installed, "reserved clone pidfd slot disappeared");
    }

    // A child (process or thread) inherits its parent's process group,
    // session, and controlling terminal (POSIX). pgid inheritance is what
    // keeps a forked foreground job in the terminal's foreground pgrp so
    // it does NOT trip the SIGTTIN/SIGTTOU background-access check on its
    // first console read; a job-control shell moves it out via setpgid.
    pgid_fork(parent_pid, child_tid.raw());
    sid_fork(parent_pid, child_tid.raw());
    ctty_fork(parent_pid, child_tid.raw());

    if !share_fs {
        cwd_fork(parent_pid, child_tid.raw());
    }
    // chroot: a child inherits the parent's root directory (Linux copies
    // fs->root on fork). Without this, a process exec'd inside a chroot
    // can't fork+exec further binaries from the chrooted rootfs — the
    // child resolves the host root instead, breaking containers.
    root_dir_fork(parent_pid, child_tid.raw());
    // Credentials (uid/gid/euid/...) are copied to the child so a parent
    // that dropped privilege stays dropped across fork/clone; a root
    // parent stays root. Keyed by task id, so copy unconditionally.
    uidgid_fork(parent_pid, child_tid.raw());

    // Namespace inheritance + CLONE_NEW* layering. A child — thread OR
    // process — shares the parent's namespaces (Linux copy_*ns), unless
    // clone3 requested a fresh one via CLONE_NEW*. The per-task NS
    // tables are keyed per task id; threads share the process's ns.
    //
    // Mount namespaces are part of the Linux-compat syscall surface even
    // without the optional container feature. A fork/clone child inherits the
    // parent's current mount namespace by reference, just as Linux's
    // copy_mnt_ns() does. This must happen for threads too: the per-task map
    // needs an entry even though the namespace object itself is shared.
    mount_ns_inherit(parent_pid, child_tid.raw());

    // CLONE_NEWNS is not contingent on the optional container bundle: systemd
    // uses clone(CLONE_NEWNS|SIGCHLD) to construct its generator and service
    // sandboxes. It receives a distinct snapshot, while a regular clone keeps
    // the inherited Arc above.
    const CLONE_NEWNS: u64 = 0x0002_0000;
    if !share_thread && flags & CLONE_NEWNS != 0 {
        install_mount_namespace(child_tid.raw(), snapshot_current_mount_namespace());
    }

    #[cfg(feature = "container")]
    {
        let child = child_tid.raw();
        let parent_task = current_task_id();
        // UTS / NET / IPC / User: shared by ref, then CLONE_NEW* mints
        // a fresh one for the child.
        crate::namespaces::inherit_into_child(parent_task, child);
        if flags & crate::namespaces::CLONE_NEWUSER != 0 {
            crate::namespaces::setns_user(
                child,
                prepared_user_ns
                    .clone()
                    .expect("CLONE_NEWUSER prepared a child user namespace"),
            );
            set_cred_user_ns_caps(child);
            let _ = write_uidgid(child, |e| {
                e.uid = 0;
                e.gid = 0;
                e.euid = 0;
                e.egid = 0;
                e.fsuid = 0;
                e.fsgid = 0;
            });
        }
        if flags & crate::namespaces::CLONE_NEWUTS != 0 {
            crate::namespaces::unshare_uts(child);
        }
        if flags & crate::namespaces::CLONE_NEWNET != 0 {
            crate::namespaces::unshare_net(child);
        }
        if flags & crate::namespaces::CLONE_NEWIPC != 0 {
            crate::namespaces::unshare_ipc(child);
        }
    }

    // The program break is ADDRESS-SPACE state: a real fork inherits it in
    // `clone_for_fork`, and CLONE_VM threads share it because they share the AS.
    // No per-task copy is needed or wanted (per-task keying let a fresh thread
    // answer brk(0) with the arena base and poison glibc's __curbrk).
    // Signal-handler table: CLONE_SIGHAND (mandatory for CLONE_THREAD)
    // SHARES the parent's live sighand — a handler installed by any
    // thread is visible to the whole group (Linux sighand_struct
    // semantics; musl's setxid/cancellation machinery depends on it —
    // before this, a pthread had an EMPTY handler table and any signal
    // sent to it took the default action and killed it). Everything
    // else deep-copies (fork semantics).
    if (flags & CLONE_CLEAR_SIGHAND) != 0 && !share_sighand && !share_thread {
        // clone3 CLONE_CLEAR_SIGHAND: the child starts with every
        // disposition SIG_DFL. Simply don't copy the parent's table —
        // an absent SIGACTION_TABLE entry IS the all-default table
        // (delivery falls back to default actions; sys_rt_sigaction
        // lazily allocates on first write). glibc posix_spawn passes
        // this on every spawn to close the handler-inheritance race.
    } else if share_sighand || share_thread {
        sigaction_share(parent_pid, child_tid.raw());
    } else {
        sigaction_fork(parent_pid, child_tid.raw());
    }
    // The signal MASK is inherited by every clone flavour (Linux
    // copy_process copies blocked unconditionally). A new thread that
    // started with an empty mask would take signals its creator had
    // deliberately blocked.
    signal_mask_fork(parent_pid, child_tid.raw());

    // CLONE_PARENT_SETTID: write child TID to *parent_tid in the
    // parent's AS (still active here — we haven't returned to the
    // user yet, so the parent's CR3 is in place from before the
    // trap entry).
    if (flags & CLONE_PARENT_SETTID) != 0 && ca.parent_tid != 0 {
        #[cfg(feature = "container")]
        let parent_tid_value = child_ns_pid;
        #[cfg(not(feature = "container"))]
        let parent_tid_value = allocated_linux_id;
        let tid_bytes = (parent_tid_value as u32).to_ne_bytes();
        // SAFETY: `ca.parent_tid` is the user *parent_tid pointer (non-zero, checked);
        // the parent's CR3 is still active here. copy_to_user range-validates it and
        // SMAP-brackets the 4-byte write.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { copy_to_user(ca.parent_tid, &tid_bytes) };
    }


    // CLONE_CHILD_CLEARTID: stash for the exit-observer to consume.
    // Pass the child's AS root phys so the observer can write the
    // futex word even after the scheduler reaps the slot — by then
    // `address_space_of` returns None, but the Arc we hold in
    // `child_as` keeps the page tables alive.
    if (flags & CLONE_CHILD_CLEARTID) != 0 && ca.child_tid != 0 {
        set_clear_child_tid_with_as(
            child_tid.raw(),
            ca.child_tid,
            child_as_root,
            child_futex_namespace,
        );
    }

    // Parent-of bookkeeping for wait4 was published above, BEFORE the spawn.
    // Threads are not waitpid-reapable, but perf inheritance still observes
    // them as tasks in the parent's process.
    let parent_visible_pid = task_to_pid_raw(parent_pid).unwrap_or(parent_pid);
    crate::perf_event::on_fork(
        parent_visible_pid,
        if share_thread {
            parent_visible_pid
        } else {
            child_visible_pid
        },
        parent_pid,
        child_tid.raw(),
    );

    // Return: parent sees child TID (== visible-pid for !THREAD,
    // == TaskId.raw() for THREAD where TID and PID diverge). For a new
    // process the pid is translated into the parent's namespace
    // (`child_ns_pid`); in the root namespace that equals the outer pid.
    #[cfg(feature = "container")]
    let ret_val = child_ns_pid;
    #[cfg(not(feature = "container"))]
    let ret_val = if share_thread {
        allocated_linux_id
    } else {
        child_visible_pid
    };
    // This is the publication point for the child. Everything keyed by its
    // TaskId, including the copied fd table used by the immediate executor
    // fexecve, has been installed above.
    if !share_thread {
        shm_fork_process(&parent_as, &child_as, child_visible_pid, share_vm);
    }
    pending_child.spawn();
    ctx.set_return(SyscallReturn::ok(ret_val));

    // CLONE_VFORK: suspend the parent here until the child execs or exits
    // (Linux TASK_KILLABLE). The child holds the shared address space; letting
    // the parent resume now would let it mutate/free that AS (e.g. munmap the
    // child's stack) out from under the still-running child. The entry was
    // registered pre-spawn, so if the child already released we fall straight
    // through. Own-stack park: infinite deadline, woken by `vfork_child_release`
    // → `wake_signal`; SIGKILL (pending bit 9) still breaks the wait.
    if flags & CLONE_VFORK != 0 {
        if let Some(uctx) = crate::user_task::current_user_task() {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            if narf_scheduler::stackful::user_own_stack_enabled() {
                // SAFETY: the in-flight parent task's poller-pinned UserTaskCtx;
                // single-CPU cooperative execution — no concurrent &mut.
                let uc = unsafe { &*uctx };
                // SAFETY: `uc.state` is this task's poller-pinned save area and
                // `uc.exit_reason` its resume-disposition cell; single-CPU
                // cooperative execution means no concurrent access.
                unsafe {
                    ctx.save_user_state(uc.state.get() as *mut u8);
                    *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                }
                loop {
                    // Arm the park before testing the wait-table predicate.
                    // vfork_child_release removes the row before clearing this
                    // deadline, closing the final check-to-sleep race.
                    uc.sleep_deadline_ns
                        .store(u64::MAX, core::sync::atomic::Ordering::Release);
                    if !vfork_is_pending(child_visible_pid) {
                        break;
                    }
                    if (signal_pending_bits(parent_pid) & (1 << 9)) != 0 {
                        // SIGKILL pending: abandon the wait; drop the stale entry
                        // so a later reuse of this pid can't wake a dead parent.
                        VFORK_WAIT
                            .lock()
                            .as_mut()
                            .map(|m| m.remove(&child_visible_pid));
                        break;
                    }
                    crate::user_task::own_stack_park();
                }
                uc.sleep_deadline_ns
                    .store(0, core::sync::atomic::Ordering::Release);
            }
            #[cfg(target_arch = "aarch64")]
            if !narf_scheduler::stackful::user_own_stack_enabled() {
                if let Some(hook) = crate::user_task::yield_hook() {
                    // aarch64 uses the polling-future path: keep the parent's
                    // saved syscall return parked until vfork_child_release calls
                    // wake_signal and clears this infinite deadline.
                    // SAFETY: uctx is the live poller-owned context and hook
                    // longjmps back through its installed JmpBuf.
                    let uc = unsafe { &*uctx };
                    uc.sleep_deadline_ns
                        .store(u64::MAX, core::sync::atomic::Ordering::Release);
                    if vfork_is_pending(child_visible_pid) {
                        // SAFETY: `uc` and the legacy JmpBuf remain live for this
                        // poll; the hook diverges back to that saved continuation.
                        unsafe {
                            ctx.save_user_state(uc.state.get() as *mut u8);
                            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                            hook(uctx);
                        }
                    }
                    uc.sleep_deadline_ns
                        .store(0, core::sync::atomic::Ordering::Release);
                }
            }
        }
    }
}

// ── arch_prctl(2) — x86_64 thread-pointer install ──────────────────
//
// musl's `__init_libc` calls `arch_prctl(ARCH_SET_FS, tls_self_ptr)`
// near the top of process startup; without a real handler it returns
// ENOSYS, musl `a_crash()`es via `ud2`, and the binary dies before
// `main`. Sub-codes per `arch/x86/include/uapi/asm/prctl.h`:
//
//   ARCH_SET_GS = 0x1001    (not yet wired — return EINVAL)
//   ARCH_SET_FS = 0x1002    (WRMSR IA32_FS_BASE)
//   ARCH_GET_FS = 0x1003    (RDMSR + copy_to_user the u64)
//   ARCH_GET_GS = 0x1004    (not yet wired — return EINVAL)
//
// SET_FS persistence across preemption: this writes the live MSR
// only. The polling future at `user_task.rs:815` re-asserts
// `process.fs_base` on every `Initial`-state poll, so a task that
// gets preempted across timer ticks would have its arch_prctl-set
// FS_BASE clobbered. For a short-lived binary (hello_musl) this
// isn't observable; a longer-running one needs a per-task slot the
// poll path consults — wired alongside thread support.

// ── fork(2) — duplicate-process counterpart to sys_clone ───────────
//
// Where sys_clone shares the parent's `Arc<AddressSpace>` so a new
// task runs alongside in the same memory map (POSIX threads),
// sys_fork allocates a fresh AS, copies every region's pages by
// value via `AddressSpace::clone_for_fork`, and spawns the child
// against the duplicate. The child's first poll calls
// `enter_user_mode_resume` against a snapshot of the parent's
// trap frame with `rax = 0`, so the child wakes up at the
// instruction *after* its `int 0x80` and reads the POSIX "child
// got 0 from fork()" return value. Returns the child's tid to
// the parent.
//
// Inheritance: AS (copied), fd table (copied via `fd::fork`), cwd
// (copied via `cwd_fork`), brk (inherited on the AS by `clone_for_fork`), sigaction
// handlers (copied via `sigaction_fork`), trap-frame state (copied
// via `TrapContext::save_user_state`, with rax mutated to 0 in
// the child).
//
// COW: `clone_for_fork` shares the parent's frames with the
// child via `narf_memory::frame::cow::inc_ref` and strips WRITE
// on both regions. The first user-mode write faults; the trap
// handler in `frame::<arch>::trap` calls `cow_split_on_write` +
// `remap_page` to allocate a private frame, memcpy the bytes,
// and restore WRITE on the faulting AS. Large brk heaps no
// longer pay an up-front memcpy at fork time.

/// FIFO wake bridge. A named-pipe read or write changes the buffer state, and
/// a blocked peer — a reader on an empty buffer, a writer on a full one — may be
/// own-stack parked on the io-waiter registry. `Readiness::set` already fired
/// that peer's per-fd waker, but for a task switched out of the poll rotation
/// that only stores an awake bit nothing re-scans, so without this the peer
/// sleeps to the ~1 ms lost-wake backstop (an anonymous pipe self-notifies; a
/// FIFO's `FileOps` live in the fs crate, which can't reach the net readiness
/// layer). Bumping the io-waiter generation re-enqueues the parked peer now.
///
/// Downcast-gated to FIFOs, so sockets / pipes / regular files pay only a
/// vtable type check.
pub(crate) fn wake_fifo_io_waiters(ops: &dyn narf_filesystem::FileOps) {
    if ops
        .as_any()
        .and_then(|any| any.downcast_ref::<narf_filesystem::fifo::FifoHandle>())
        .is_some()
    {
        narf_net::readiness::notify(0);
    }
}

// ── waitpid / wait4 — parent observes child exit status ────────────
//
// POSIX wait4(pid, &status, options, &rusage):
//   pid  > 0  → wait for that specific child
//   pid == -1 → any child
//   pid == 0  → any child in same process group (we map to -1)
//   pid < -1  → any child in pgid -pid (we map to -1)
// options bit 0 = WNOHANG (return 0 immediately if no exited
// child rather than blocking).
//
// Wire shape (`Syscall::Wait4 = 180`, four args):
//   arg0 = pid (signed, fits in u64 via wrap)
//   arg1 = status user-pointer (may be 0 to discard)
//   arg2 = options (low bit = WNOHANG)
//   arg3 = rusage user-pointer (zeroed today, no per-process
//          resource accounting)
//
// Return value:
//   ok(child_pid)  on a successful reap
//   ok(0)          on WNOHANG with no exited child
//   invalid_op     on no children to wait for (POSIX ECHILD;
//                  we don't have multiple errno values yet)

/// child_pid → parent_pid lookup. Set by fork; consumed by the
/// exit observer to find the parent's pending-exits queue.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ChildLink {
    parent: u64,
    exit_signal: u8,
}

static PARENT_OF: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, ChildLink>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
/// Number of unreaped children owned by each parent TaskId. Linux keeps an
/// intrusive children list on every task; this compact companion index gives
/// NARF the same O(1) "no children" exit test without duplicating ChildLink.
/// It is updated under PARENT_OF's lock, so a published child link and its
/// parent count become visible as one transaction.
static PARENT_CHILD_COUNTS: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// parent_pid → list of (child_pid, status) pairs not yet reaped.
/// status is the POSIX-shaped 32-bit value:
///   - Normal exit (WIFEXITED): low 7 bits == 0, byte 1 holds the
///     exit code → `status = exit_code << 8`.
///   - Signal-killed (WIFSIGNALED): low 7 bits hold the signum
///     (non-zero, not 0x7f), bit 7 is WCOREDUMP →
///     `status = signum | (core ? 0x80 : 0)`.
///
/// task_pid → queued `(child_pid, wstatus)` exit records awaiting wait4.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct PendingExit {
    child_pid: u64,
    status: i32,
    exit_signal: u8,
    ptraced: bool,
}

type PendingExitMap = BTreeMap<u64, alloc::vec::Vec<PendingExit>>;
static PENDING_EXITS: narf_lib::sync::IrqSafeSpinLock<Option<PendingExitMap>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

// ── Job control: stop / continue ───────────────────────────────────
//
// A task hit by a STOP-class signal (SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU)
// whose default action is `Stop` parks itself (sleep_deadline_ns =
// u64::MAX) and records its TaskId here with the stop signum. The
// `UserTaskFuture::poll` loop consults `is_task_stopped` and keeps a
// stopped task parked — never re-entering user mode — until SIGCONT
// clears the entry and wakes it (SIGKILL also breaks through).
//
// `TASK_STOPPED`: TaskId → stop signum (for WSTOPSIG in the parent's
// wait4 status word).
static TASK_STOPPED: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// parent_pid → queued job-control notifications consumed by
/// `wait4`/`waitid` when WUNTRACED/WCONTINUED is set. Unlike
/// PENDING_EXITS these do NOT release the child PID — the child is
/// alive, merely stopped or continued. Entries: `(child_pid, wstatus,
/// is_continued)`; `wstatus` is `(sig << 8) | 0x7f` for a stop
/// (WIFSTOPPED) or `0xffff` for a continue (WIFCONTINUED).
type StopContMap = BTreeMap<u64, alloc::vec::Vec<(u64, i32, bool)>>;
static PENDING_STOPCONT: narf_lib::sync::IrqSafeSpinLock<Option<StopContMap>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// wait4/waitid `options` bits (Linux uapi).
const WUNTRACED: u32 = 2;
const WCONTINUED: u32 = 8;
const WEXITED: u32 = 4;
const WNOWAIT: u32 = 0x0100_0000;
const __WNOTHREAD: u32 = 0x2000_0000;
const __WALL: u32 = 0x4000_0000;
const __WCLONE: u32 = 0x8000_0000;
const SIGCHLD: u8 = 17;


/// True if `task` is currently job-control stopped.
pub fn is_task_stopped(task: u64) -> bool {
    let job_stopped = TASK_STOPPED
        .lock()
        .as_ref()
        .map(|m| m.contains_key(&task))
        .unwrap_or(false);
    let ptrace_stopped = crate::ptrace::is_task_ptrace_stopped(task);
    job_stopped || ptrace_stopped
}

/// Raw pending-signal bitmask for `task` (no mask applied). Used by
/// the poll loop to let SIGKILL break a job-control stop.
pub fn signal_pending_bits(task: u64) -> u64 {
    signal_bits_get(&SIGNAL_PENDING, task)
}

/// AND-out the given signal bits from `task`'s pending set.
pub(crate) fn clear_pending_signal_bits(task: u64, mask: u64) {
    let _ = pending_signal_bits_update_existing(task, |slot| *slot &= !mask);
}

/// WIFSTOPPED-shaped wstatus carrying `sig` as WSTOPSIG.
fn stopped_wstatus(sig: u32) -> i32 {
    ((sig as i32) << 8) | 0x7f
}

/// WIFCONTINUED-shaped wstatus.
const CONTINUED_WSTATUS: i32 = 0xffff;

#[inline]
fn get_wait_recipient(child_pid: u64) -> Option<u64> {
    {
        crate::ptrace::get_wait_recipient(child_pid)
    }
}

/// Queue a stop/continue notification to `child_task`'s parent and
/// nudge it: stage SIGCHLD and wake any blocking wait4. Does NOT
/// release the child PID — the child is still alive.
pub(crate) fn push_stopcont_report(child_task: u64, wstatus: i32, is_continued: bool) {
    let child_pid = task_to_pid_raw(child_task).unwrap_or(child_task);
    push_stopcont_report_as(child_pid, wstatus, is_continued);
}

fn push_stopcont_report_as(child_pid: u64, wstatus: i32, is_continued: bool) {
    let parent = match get_wait_recipient(child_pid) {
        Some(p) => p,
        None => return,
    };
    {
        let mut g = PENDING_STOPCONT.lock();
        if let Some(m) = g.as_mut() {
            m.entry(parent).or_insert_with(alloc::vec::Vec::new).push((
                child_pid,
                wstatus,
                is_continued,
            ));
        }
    }
    // Linux notifies the parent with SIGCHLD on stop/continue too.
    let _ = pending_signal_bits_update(parent, |slot| *slot |= sig_bit(17));
    wake_wait_child_group(parent);
}

/// Pop a matching stop/continue notification for `parent`, honouring
/// the wait `options` (WUNTRACED selects stops, WCONTINUED selects
/// continues) and the `want` pid filter. Returns `(child_pid,
/// wstatus)` WITHOUT releasing the PID.
/// Does an exited/candidate child `child_pid` (an outer ProcessId) satisfy a
/// wait request? `want_pgid` != 0 selects a PROCESS-GROUP-scoped wait
/// (`waitpid(0)` / `waitpid(-pgid)` / `waitid(P_PGID)`): the child matches iff
/// its process group (its still-live PGID_TABLE entry — cleared only by
/// `release_reaped_task` at the real reap) equals the TASK-space `want_pgid`.
/// Otherwise `want_pid` decides: > 0 a specific outer pid, <= 0 any child.
/// Linux `kernel/exit.c` `eligible_pid` / `__WNOTHREAD` filtering. (#29)
fn wait_child_matches(
    child_pid: u64,
    want_pid: i64,
    want_pgid: u64,
    exit_signal: u8,
    ptraced: bool,
    options: u32,
) -> bool {
    if want_pgid != 0 {
        let child_task = pid_to_task_raw(child_pid).unwrap_or(child_pid);
        if read_pgid(child_task) != want_pgid {
            return false;
        }
    } else if want_pid > 0 && child_pid != want_pid as u64 {
        return false;
    }

    // Linux kernel/exit.c::eligible_child: a tracer and __WALL see both
    // classes. Otherwise __WCLONE selects children whose termination signal
    // is not SIGCHLD, while an ordinary wait selects only SIGCHLD children.
    if ptraced || options & __WALL != 0 {
        return true;
    }
    (exit_signal != SIGCHLD) == (options & __WCLONE != 0)
}

/// Task IDs whose child lists are visible to the waiter. Linux walks every
/// thread in the caller's thread group unless __WNOTHREAD is set.
fn wait_parent_ids(waiter: u64, options: u32) -> alloc::vec::Vec<u64> {
    let mut parents = alloc::vec![waiter];
    if options & __WNOTHREAD != 0 {
        return parents;
    }
    let waiter_tgid = task_to_pid_raw(waiter).unwrap_or(waiter);
    // Single-threaded parents are overwhelmingly common (including the
    // stress-ng fork/clone workers); keep their reap path O(1).
    if thread_group_live_count(waiter_tgid) <= 1 {
        return parents;
    }
    for (task, tgid) in task_pid_snapshot() {
        if tgid == waiter_tgid && task != waiter {
            parents.push(task);
        }
    }
    parents
}
/// Wake every thread that may legally consume this parent's child event.
fn wake_wait_child_group(parent: u64) {
    for waiter in wait_parent_ids(parent, 0) {
        crate::user_task::wake_wait_child(waiter);
    }
}

/// Select (or peek) one exited child from any child list visible to the
/// caller's thread group. Keeping the creator TaskId as the queue key retains
/// exact __WNOTHREAD behavior while the default path matches Linux's
/// group-wide wait.
fn reap_pending_exit(
    waiter: u64,
    want_pid: i64,
    want_pgid: u64,
    options: u32,
    peek: bool,
) -> Option<PendingExit> {
    let parents = wait_parent_ids(waiter, options);
    let mut g = PENDING_EXITS.lock();
    let m = g.as_mut()?;
    for parent in parents {
        let Some(q) = m.get_mut(&parent) else {
            continue;
        };
        let Some(idx) = q.iter().position(|entry| {
            wait_child_matches(
                entry.child_pid,
                want_pid,
                want_pgid,
                entry.exit_signal,
                entry.ptraced,
                options,
            )
        }) else {
            continue;
        };
        return if peek { Some(q[idx]) } else { Some(q.remove(idx)) };
    }
    None
}

fn reap_stopcont(parent: u64, want: i64, want_pgid: u64, options: u32) -> Option<(u64, i32)> {
    let want_stop = options & WUNTRACED != 0;
    let want_cont = options & WCONTINUED != 0;
    let parents = wait_parent_ids(parent, options);
    let mut g = PENDING_STOPCONT.lock();
    let m = g.as_mut()?;
    for owner in parents {
        let Some(q) = m.get_mut(&owner) else {
            continue;
        };
        let Some(idx) = q.iter().position(|&(p, _w, cont)| {
            let ptraced = crate::ptrace::is_ptrace_stop_recipient(owner, p);
            let exit_signal = child_link_get(p).map_or(SIGCHLD, |link| link.exit_signal);
            if !wait_child_matches(p, want, want_pgid, exit_signal, ptraced, options) {
                return false;
            }
            if cont {
                return want_cont;
            }
            // A ptrace-stop is reported to the tracer's wait4
            // unconditionally; WUNTRACED gates ordinary job-control stops.
            want_stop || ptraced
        }) else {
            continue;
        };
        let (pid, w, _) = q.remove(idx);
        return Some((pid, w));
    }
    None
}

/// Stop/continue mutual-cancellation and SIGCONT resume. Call
/// whenever `signum` is about to become pending on `task`.
///
/// - SIGCONT (18): discards any pending stop signals, and if `task`
///   is currently stopped, clears the stopped state, reports
///   WIFCONTINUED to the parent, and un-parks the task.
/// - A stop signal (19..=22): discards a pending SIGCONT.
fn signal_stopcont_interaction(task: u64, signum: u32) {
    match signum {
        18 => {
            // SIGCONT cancels pending stops (19..=22).
            clear_pending_signal_bits(task, 0b1111u64 << 18); // stop signals 19-22
            let was_stopped = TASK_STOPPED
                .lock()
                .as_mut()
                .and_then(|m| m.remove(&task))
                .is_some();
            if was_stopped {
                push_stopcont_report(task, CONTINUED_WSTATUS, true);
                // Un-park the stopped UserTaskFuture: wake_signal clears
                // a u64::MAX deadline and fires the registered waker, so
                // the poll loop re-runs, sees the task no longer stopped,
                // and re-enters user mode.
                wake_signal(task);
            }
        }
        19..=22 => {
            // A stop signal cancels a pending SIGCONT.
            clear_pending_signal_bits(task, sig_bit(18)); // SIGCONT
        }
        _ => {}
    }
}

/// Put the current task into the job-control stopped state and park it
/// until SIGCONT. Records the stop signum (for WSTOPSIG), cancels any
/// pending SIGCONT, notifies the parent (wait4 WUNTRACED + SIGCHLD),
/// then — mirroring sys_pause — stashes an infinite deadline, saves the
/// user frame, and longjmps back to the executor via the yield hook.
/// The poll loop keeps the task parked (is_task_stopped) until SIGCONT
/// clears the entry and wakes it; the interrupted syscall then resumes
/// returning 0. With no executor wired (kernel-test context) it returns
/// without parking so the caller can consume the signal.
fn enter_stopped(ctx: &mut dyn TrapContext, task: u64, signum: u32) {
    clear_pending_signal_bits(task, sig_bit(signum));
    if let Some(m) = TASK_STOPPED.lock().as_mut() {
        m.insert(task, signum);
    }
    clear_pending_signal_bits(task, sig_bit(18)); // SIGCONT
    push_stopcont_report(task, stopped_wstatus(signum), false);
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: `uctx` is the live per-task UserTaskCtx from
        // current_user_task(); we hold the only reference while stashing
        // the deadline and saving CPU state, then the yield hook hands the
        // task to the executor (never returns).
        unsafe {
            let uc = &*uctx;
            ctx.set_return(SyscallReturn::ok(0));
            uc.sleep_deadline_ns
                .store(u64::MAX, core::sync::atomic::Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
        // unreachable
    }
}

/// Narrow signal delivery for the `syscall`-instruction return path:
/// deliver ONLY a pending, unmasked, un-handled STOP-class signal
/// (SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU) by stopping the task now.
///
/// NARF delivers ordinary (handled) signals lazily, at explicit yield
/// points; the signal model and existing smokes rely on that timing, so
/// this deliberately leaves handled signals alone. A STOP with no
/// handler is different — a process cannot meaningfully defer being
/// stopped — so it must take effect on syscall return, like Linux. The
/// int 0x80 path already stops promptly via `default_signal_delivery`;
/// this brings the `syscall` path (the one musl uses) to parity for the
/// stop case only. May longjmp out via `enter_stopped` (never returns).
pub fn deliver_pending_stop(ctx: &mut dyn TrapContext, _syscall_no: u32) -> bool {
    if !ctx.returning_to_user() {
        return false;
    }
    let task = current_task_id();
    let mask = signal_mask_of(task);
    let stop_bits = (0b1111u64 << 18) & signal_pending_bits(task) & !mask;
    if stop_bits == 0 {
        return false;
    }
    let signum = sig_from_bit(stop_bits);
    // SIGSTOP can never be caught, but SIGTSTP/SIGTTIN/SIGTTOU can — if a
    // user handler is installed, leave delivery to the normal lazy path.
    if sigaction_lookup_full(task, signum as usize).is_some() {
        return false;
    }
    enter_stopped(ctx, task, signum);
    true
}

/// task_pid → wstatus staged by the signal-delivery path when a
/// signal with a Terminate/CoreDump default action is about to kill
/// the task. The exit observer (`on_child_exit`) drains this and
/// pushes the encoded status into PENDING_EXITS so wait4 sees
/// `WIFSIGNALED + WTERMSIG(signum)`.
///
/// Absent entry → on_child_exit records `0` (normal exit), which is
/// what sys_exit_task callers want today (exit-code threading is a
/// separate follow-on).
static PENDING_TERMINATION: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, i32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn wait_init() {
    *PARENT_OF.lock() = Some(BTreeMap::new());
    *PARENT_CHILD_COUNTS.lock() = Some(BTreeMap::new());
    crate::ptrace::ptrace_init();
    *PENDING_EXITS.lock() = Some(BTreeMap::new());
    *TASK_STOPPED.lock() = Some(BTreeMap::new());
    *PENDING_STOPCONT.lock() = Some(BTreeMap::new());
    *PENDING_TERMINATION.lock() = Some(BTreeMap::new());
    pid_task_map_init();
    // THREAD-scoped (every thread exit): release this thread's fd-table
    // ref + job-control state, then sweep its per-task tables and
    // orphanize its children. Both key on `tid`; the reap below keys on
    // `pid`, so they're independent of ordering.
    crate::user_task::register_thread_exit_observer(on_thread_exit);
    // Perf snapshots final user + kernel software-clock time before the master
    // table sweep removes TASK_KERN_NS. Register it ahead of that sweep; the
    // retired total then remains readable after every inherited task exits.
    crate::user_task::register_thread_exit_observer(crate::perf_event::on_thread_exit);
    crate::user_task::register_thread_exit_observer(task_tables_exit_observer);
    // PROCESS-scoped (last thread of the group only): hand the process
    // to its parent (wait4 reap + SIGCHLD + waker) or auto-release if
    // orphaned. Gated on `group_dead` so a multi-threaded exit_group
    // reaps the pid exactly once (was per-thread → double `release_pid`,
    // the OCI teardown #UD).
    crate::user_task::register_process_exit_observer(crate::perf_event::on_process_exit);
    crate::user_task::register_process_exit_observer(shm_process_exit);
    crate::user_task::register_process_exit_observer(on_child_exit);
    crate::user_task::register_wait_child_check(wait_child_check_fn);
    crate::user_task::wait_child_waker_init();
    // Abnormal slot drops (budget kill / revoked cap) must run the same
    // exit teardown as a normal exit — without this hook the dropped
    // task's refcounted `Task` would stay RUNNING forever and its exit
    // observers (fd teardown, SIGCHLD, parent wake) would never fire.
    narf_scheduler::set_slot_reap_hook(crate::task::slot_reap_handler);
    signal_waker_init();
    io_waker_init();
    // Wake epoll/poll waiters the instant inbound TCP data lands,
    // rather than at their next wheel deadline. Latency-only; safe to
    // install unconditionally (no-op until a task parks on net I/O).
    narf_net::readiness::set_hook(wake_io_waiters);
    // Same wake, for evdev: a `read`/`poll`/`epoll` on /dev/input/event*
    // parks on the net readiness system, but an input driver dispatching an
    // event only wakes its async `Reader` slots. Bridge the two so a
    // compositor (weston/libinput) actually receives input it's parked on.
    narf_input::evdev::set_dispatch_wake_hook(evdev_dispatch_wake);
    crate::pidfd::init();
    // Wave-65: clone3 CLONE_CHILD_CLEARTID + set_tid_address(2)
    // bookkeeping. The table holds per-task user-pointer slots;
    // the exit observer reads them on thread exit and fires the
    // pthread_join futex wake. Gated so a no-linux-compat build
    // doesn't carry the observer.
    {
        clear_child_tid_init();
        install_clear_child_tid_observer();
    }
    // cgroup-v2: drop a process's membership when it exits so the
    // `populated` state of its cgroup chain can fall to 0 — the edge
    // an init system's empty-cgroup notification keys on. Also wire the
    // freeze/kill hooks so cgroup.freeze / cgroup.kill deliver real
    // signals through the signal subsystem.
    #[cfg(feature = "cgroup")]
    {
        crate::user_task::register_process_exit_observer(cgroup_exit_observer);
        narf_filesystem::cgroupfs::install_kill_hook(cgroup_kill_hook);
        narf_filesystem::cgroupfs::install_freeze_hook(cgroup_freeze_hook);
    }
    // Share the process-global NsId counter with the filesystem crate so
    // a MountNamespace minted there (snapshot_global) draws an id from
    // the same space as every other namespace flavour.
    #[cfg(feature = "container")]
    narf_filesystem::install_ns_id_alloc_hook(crate::namespaces::alloc_ns_id);
}

/// Exit-observer that removes an exiting *process* from its cgroup.
/// Fires for every task, but only acts on the process leader (when the
/// dying TaskId is the one bound to the pid) so a short-lived worker
/// thread exiting doesn't prematurely vacate the whole process's
/// membership.
#[cfg(feature = "cgroup")]
fn cgroup_exit_observer(pid: u64, _tid: u64) {
    // PROCESS-scoped: fires once, on `group_dead`. No leader-guard —
    // the group-dead gate already ensures a single call, and the last
    // thread of the group need not be the registered leader (a
    // `pid_to_task_raw(pid) == tid` check would then wrongly skip it).
    narf_filesystem::cgroupfs::task_exited(pid);
}

/// `cgroup.kill` hook — SIGKILL (9) the named process.
#[cfg(feature = "cgroup")]
fn cgroup_kill_hook(pid: u64) {
    if let Some(task) = pid_to_task_raw(pid) {
        raise_signal_pending(task, 9);
    }
}

/// `cgroup.freeze` hook — SIGSTOP (19) to freeze, SIGCONT (18) to thaw.
/// Real freezing relies on the scheduler honouring the SIGSTOP default
/// action (Stop); thaw resumes via SIGCONT.
#[cfg(feature = "cgroup")]
fn cgroup_freeze_hook(pid: u64, freeze: bool) {
    if let Some(task) = pid_to_task_raw(pid) {
        raise_signal_pending(task, if freeze { 19 } else { 18 });
    }
}

#[doc(hidden)]
pub fn __test_wait_reset() {
    *PARENT_OF.lock() = Some(BTreeMap::new());
    *PARENT_CHILD_COUNTS.lock() = Some(BTreeMap::new());
    *PENDING_EXITS.lock() = Some(BTreeMap::new());
    *TASK_STOPPED.lock() = Some(BTreeMap::new());
    *PENDING_STOPCONT.lock() = Some(BTreeMap::new());
    *PENDING_TERMINATION.lock() = Some(BTreeMap::new());
    pid_task_map_init();
    crate::user_task::__test_wait_child_waker_reset();
}

/// Encode a POSIX wstatus for a signal-induced termination.
/// Low 7 bits = signum, bit 7 = WCOREDUMP.
#[inline]
pub fn encode_signaled_status(signum: u32, core_dumped: bool) -> i32 {
    let lo = (signum & 0x7f) as i32;
    let core = if core_dumped { 0x80 } else { 0 };
    lo | core
}

/// Stage a signal-induced termination status for `task`. The exit
/// observer drains this when the task transitions to Exited and
/// uses it as the wstatus reported to wait4. Idempotent: if a
/// status is already staged (e.g. SIGSEGV racing SIGTERM), the
/// first one wins — that's the signal that actually killed the
/// task.
pub fn stage_pending_termination(task: u64, status: i32) {
    // A CLONE_VFORK child that exits WITHOUT exec'ing (e.g. posix_spawn's child
    // _exit on exec failure, or a kill) must still release the parent suspended
    // in do_clone3's vfork park — otherwise the parent waits forever. `task` is
    // the visible pid here (every caller passes a pid). Idempotent with the
    // execve release. No-op when the pid isn't a vfork child.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    vfork_child_release(task);
    let mut g = PENDING_TERMINATION.lock();
    if let Some(m) = g.as_mut() {
        m.entry(task).or_insert(status);
    }
}

fn take_pending_termination(task: u64) -> Option<i32> {
    let mut g = PENDING_TERMINATION.lock();
    g.as_mut().and_then(|m| m.remove(&task))
}

/// Stage a SIGKILL wstatus for a task the SCHEDULER destroyed without
/// running its exit path (budget kill / revoked cap — the abnormal
/// slot-drop). Called by `crate::task::slot_reap_handler` so wait4
/// reports the abrupt death like a kill(2) would.
pub(crate) fn stage_killed_termination(pid: u64) {
    stage_pending_termination(pid, encode_signaled_status(9, false));
}

/// Callback invoked by `UserTaskFuture::poll` when `wait_child_pending`
/// is set: tries to drain one matching entry from the parent's pending-
/// exits queue.
///
/// Returns the reaped child pid (> 0) on success, or 0 if the queue
/// holds no matching entry.  If `status_ptr != 0`, writes the POSIX
/// wstatus into the user-space pointer (same as `sys_wait4` does on the
/// fast path).
fn wait_child_check_fn(parent_id: u64, want_pid: i64, options: u32, out_status: *mut i32) -> i64 {
    // A process-group-scoped blocking wait (waitpid(0)/(-pgid)/P_PGID) stored
    // its TASK-space target pgid on the parked task's UserTaskCtx; the sync
    // paths pass it as an argument, but this poll-side reap re-derives it from
    // the same task. 0 = no pgid filter (specific-pid / any-child wait). (#29)
    let want_pgid = crate::user_task::current_user_task()
        .map(|u| {
            // SAFETY: the poll routine holds the parked task's UserTaskCtx
            // pinned; we only read one atomic field.
            unsafe { (*u).wait_child_want_pgid.load(Ordering::Acquire) }
        })
        .unwrap_or(0);
    // Job-control stop/continue notification FIRST. Linux reaps a child's
    // state changes in order — a stop or continue is reported before the
    // child's later exit — so a `waitpid(WCONTINUED)` after `kill(SIGCONT)`
    // must see the continue even if the child has since run to exit (which
    // it can do quickly now that signals are delivered on every syscall
    // return). reap_stopcont only matches when WUNTRACED/WCONTINUED is set
    // and a report is queued, so a plain wait falls straight through to the
    // exit reap below. These do NOT release the PID: the child is alive (or
    // its exit is still queued for the next wait).
    if let Some((child_pid, status)) = reap_stopcont(parent_id, want_pid, want_pgid, options) {
        if !out_status.is_null() {
            // SAFETY: `out_status` is a kernel-side `i32` slot owned by the
            // poll routine's stack frame for the duration of this call.
            unsafe {
                *out_status = status;
            }
        }
        return child_pid as i64;
    }
    // Real exit reap (releases the child PID) — unless the parked waitid
    // asked WNOWAIT, which only PEEKS: the entry stays queued so a later
    // real wait can reap it (same semantics as the sys_waitid fast path).
    let peek = options & WNOWAIT != 0;
    let entry = reap_pending_exit(parent_id, want_pid, want_pgid, options, peek);
    if let Some(entry) = entry {
        let child_pid = entry.child_pid;
        let status = entry.status;
        // Hand the raw wstatus back to the caller (the poll routine),
        // which writes either the wait4 wstatus `int` or the waitid
        // `siginfo_t` into user space depending on which syscall parked.
        if !out_status.is_null() {
            // SAFETY: `out_status` is a kernel-side `i32` slot owned by the
            // poll routine's stack frame for the duration of this call.
            unsafe {
                *out_status = status;
            }
        }
        if peek {
            // WNOWAIT: reported without consuming — no accounting, no
            // task/pid release; those belong to the eventual real reap.
            return child_pid as i64;
        }
        // Charge the reaped child's CPU time to the parent (RUSAGE_CHILDREN
        // / tms.cutime). Same fold as the synchronous reap path in sys_wait4;
        // this covers the blocking wait4 + waitid path.
        let _ = account_reaped_child(parent_id, child_pid);
        // Reaped — release the refcounted Task, return the PID to the
        // free pool, and drop the parent record so wait4's ECHILD check
        // is accurate.
        release_reaped_task(child_pid);
        crate::release_pid(crate::ProcessId(child_pid));
        parent_of_remove(child_pid);
        return child_pid as i64;
    }
    0
}

/// Write the result of a completed child reap into user space and
/// return the value the syscall should place in the result register.
/// For `wait4` this writes the wstatus `int` to `status_ptr` and
/// returns the reaped pid; for `waitid` it writes a `siginfo_t` and
/// returns 0. Called from the poll routine (which owns the saved
/// register frame) for the blocking path.
pub(crate) fn finish_wait_child(status_ptr: u64, is_waitid: bool, reaped: i64, status: i32) -> u64 {
    // Blocking wait4's rusage out-param: this runs AS THE PARENT on both
    // reap routes (the UserTaskFuture poll and own_stack_wait_child), so
    // the staged pointer + the child's exit-time snapshot meet here.
    // Both are consumed unconditionally so nothing goes stale.
    let parent = current_task_id();
    let rusage_ptr = take_wait_rusage_ptr(parent);
    // `reaped` is the outer ProcessId — keep it for the ProcessId-keyed rusage
    // snapshot, but report the child in the PARENT's namespace view to
    // userspace (si_pid / wait4 rax).
    let snap = take_exit_rusage(reaped as u64);
    let reaped_visible = report_pid_to(parent, reaped as u64) as i64;
    if rusage_ptr != 0 {
        let (ns, kb) = snap.unwrap_or((0, 0));
        write_rusage_utime(rusage_ptr, ns, kb);
    }
    if status_ptr != 0 {
        if is_waitid {
            let si = encode_waitid_siginfo(reaped_visible, status);
            // SAFETY: `status_ptr` is the user `siginfo_t*` (non-zero);
            // copy_to_user range-validates the 128-byte write.
            let _ = unsafe { copy_to_user(status_ptr, &si) };
        } else {
            // SAFETY: `status_ptr` is the user wstatus `int*` (non-zero);
            // copy_to_user range-validates the 4-byte write.
            let _ = unsafe { copy_to_user(status_ptr, &status.to_ne_bytes()) };
        }
    }
    if is_waitid { 0 } else { reaped_visible as u64 }
}

/// Per-task-own-stack blocking wait4/waitid: reap-or-park loop that returns the
/// reaped result via `set_return` (NOT a re-execute — wait can't pre-bake its
/// result). Reads its args from the UserTaskCtx (stored by the caller before the
/// park), registers the slot-waker so `on_child_exit` re-polls us, and
/// `kernel_switch`es out via `yield_current_stackful` until a child is reapable.
/// The own-stack analog of `UserTaskFuture::poll`'s wait_child arm.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn own_stack_wait_child(ctx: &mut dyn TrapContext) {
    let parent = current_task_id();
    let uctx = match crate::user_task::current_user_task() {
        Some(u) => u,
        None => {
            // No task context means this is a kernel-test/non-executor call,
            // not a completed wait. Returning success leaves userspace with a
            // zeroed siginfo_t, which systemd interprets as an unknown child
            // state. Linux reports ECHILD when no eligible child exists.
            ctx.set_return(SyscallReturn::ok((-10i64) as u64)); // ECHILD
            return;
        }
    };
    // SAFETY: in-flight task's poller-pinned UserTaskCtx; single-CPU access.
    let uc = unsafe { &*uctx };
    let want_pid = uc
        .wait_child_want_pid
        .load(core::sync::atomic::Ordering::Acquire);
    let options = uc
        .wait_child_options
        .load(core::sync::atomic::Ordering::Acquire);
    let status_ptr = uc
        .wait_child_status_ptr
        .load(core::sync::atomic::Ordering::Acquire);
    let is_waitid = uc
        .wait_child_is_waitid
        .load(core::sync::atomic::Ordering::Acquire);
    loop {
        let mut status = 0i32;
        let reaped =
            crate::user_task::call_wait_child_check(parent, want_pid, options, &mut status);
        if reaped > 0 {
            let rax = finish_wait_child(status_ptr, is_waitid, reaped, status);
            uc.wait_child_pending
                .store(false, core::sync::atomic::Ordering::Release);
            ctx.set_return(SyscallReturn::ok(rax));
            return;
        }
        let waker = match narf_scheduler::stackful::current_stackful_waker() {
            Some(w) => w,
            None => {
                // No executor (kernel-test harness) — degrade to one proceed,
                // and CLEAR the routing flag: the uctx lives on the refcounted
                // registry entry, which in the harness OUTLIVES this syscall
                // (setup() reuses the existing task 99 entry), so a flag left
                // set here misroutes the task's NEXT blocking syscall — e.g.
                // `own_stack_block` sent a later `pause(2)` down this wait4
                // path, where this arm overwrote pause's baked -EINTR with 0.
                // Every real-executor exit from this loop already clears it.
                // Drop the staged rusage pointer too (same staleness class).
                let _ = take_wait_rusage_ptr(parent);
                uc.wait_child_pending
                    .store(false, core::sync::atomic::Ordering::Release);
                ctx.set_return(SyscallReturn::ok((-10i64) as u64)); // ECHILD
                return;
            }
        };
        crate::user_task::register_wait_child_waker(parent, waker.clone());
        // wait4 is signal-interruptible (Linux). Register a SIGNAL waker too so
        // an asynchronously-raised signal — e.g. the parent's own ITIMER_REAL
        // SIGALRM that stops its CPU-bound workers, fired from the timer tick
        // (`timer_tick_raise_due_signals`) while we block here — wakes this
        // loop even though no child has exited. Without it the owner of a
        // setitimer(ITIMER_REAL) blocked in wait4 never takes its SIGALRM: the
        // kernel cause of the SMP chroot_run / stress-ng hang.
        crate::handlers::register_signal_waker(parent, waker);
        // Re-check after registering (a child may have exited in the window).
        let mut status2 = 0i32;
        let reaped2 =
            crate::user_task::call_wait_child_check(parent, want_pid, options, &mut status2);
        if reaped2 > 0 {
            crate::user_task::drop_wait_child_waker(parent);
            let rax = finish_wait_child(status_ptr, is_waitid, reaped2, status2);
            uc.wait_child_pending
                .store(false, core::sync::atomic::Ordering::Release);
            ctx.set_return(SyscallReturn::ok(rax));
            return;
        }
        // A deliverable signal is pending — abandon the wait with EINTR. The
        // syscall-return path (the caller returns straight after this) runs
        // the signal-delivery hook, so the handler executes and the syscall
        // returns -EINTR; musl's waitpid loop then re-issues the wait.
        if has_interrupting_signal(parent) {
            crate::user_task::drop_wait_child_waker(parent);
            // Abandoning the wait — drop the staged rusage pointer so a
            // later wait4/pause can't consume a stale one.
            let _ = take_wait_rusage_ptr(parent);
            uc.wait_child_pending
                .store(false, core::sync::atomic::Ordering::Release);
            // Deliver the pending signal NOW. The own-stack syscall return
            // (`dispatch_syscall` + its sysret asm) runs NO delivery hook, so
            // unlike the trap-return paths we must set up the handler frame
            // here: `maybe_deliver_signal_before_yield` bakes -EINTR into the
            // saved state and invokes the signal-delivery hook, so the handler
            // runs on this sysret and the syscall returns -EINTR (musl's
            // waitpid loop then re-issues the wait). If no hook is installed
            // (test contexts) fall back to a bare -EINTR.
            if !maybe_deliver_signal_before_yield(ctx, SYSCALL_NUM_NONE) {
                ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // -EINTR
            }
            return;
        }
        // SAFETY: CPL0 on our own kernel stack, a stackful task is current.
        unsafe {
            // Mark the park so the kernel-time bracket skips this
            // syscall's fold (see UserTaskCtx::parked_in_syscall).
            (*uctx)
                .parked_in_syscall
                .store(true, core::sync::atomic::Ordering::Release);
            narf_scheduler::stackful::yield_current_stackful();
        }
    }
}

/// Per-task-own-stack dispatch for a blocking-syscall park site (the own-stack
/// replacement for the `yield_hook()` longjmp). Routes wait4/waitid to the
/// reap-or-park loop and every other park (sleep/nanosleep/pause/console/futex/
/// net-I/O/job-stop) to `own_stack_park`, which registers the slot-waker and
/// `kernel_switch`es out. Returns when the condition clears; the caller then
/// `return`s and the sysret tail either re-executes the syscall (rewound RIP)
/// or returns the baked/reaped result.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn own_stack_block(ctx: &mut dyn TrapContext) {
    let is_wait = crate::user_task::current_user_task().is_some_and(|uctx| {
        // SAFETY: in-flight task's poller-pinned UserTaskCtx; single-CPU access.
        unsafe {
            (*uctx)
                .wait_child_pending
                .load(core::sync::atomic::Ordering::Acquire)
        }
    });
    if is_wait {
        own_stack_wait_child(ctx);
    } else {
        crate::user_task::own_stack_park();
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn own_stack_block(_ctx: &mut dyn TrapContext) {
    unreachable!("own-stack is not supported on this architecture");
}

/// Park the current task on net-I/O readiness (with the legacy 1 ms
/// timer-wheel backstop) and RIP-rewind so the in-flight syscall RE-EXECUTES
/// with its original arguments on resume.
///
/// Returns `true` when the task parked — the caller must `return` WITHOUT
/// setting a return value (the syscall has not completed; it will re-run).
/// Returns `false` when there is no executor (kernel-test context) and the
/// caller must fall back to a synchronous result.
pub(crate) fn park_reexecute_on_io(ctx: &mut dyn TrapContext) -> bool {
    let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
    park_reexecute_on_io_until(ctx, deadline, false)
}

/// Common net-I/O park setup. A durable per-fd [`Readiness`] arm passes
/// `u64::MAX` with `durable_io_wait`: its arm-vs-set lock closes the lost-wake
/// window, so a periodic retry would only create timer interrupts and spurious
/// syscall re-execution. Providers without such a cell retain
/// [`park_reexecute_on_io`]'s bounded backstop.
fn park_reexecute_on_io_until(
    ctx: &mut dyn TrapContext,
    deadline: u64,
    durable_io_wait: bool,
) -> bool {
    use core::sync::atomic::Ordering;
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // Rewind past the architecture's syscall instruction so re-entry
        // re-runs this syscall with its original args (`syscall`/`int 0x80`
        // are 2 bytes; AArch64 `svc` is one fixed-width 4-byte instruction).
        #[cfg(target_arch = "x86_64")]
        const SYSCALL_INSN_LEN: u64 = 2;
        #[cfg(target_arch = "aarch64")]
        const SYSCALL_INSN_LEN: u64 = 4;
        let resume_rip = ctx.rip().wrapping_sub(SYSCALL_INSN_LEN);
        ctx.set_rip(resume_rip);
        // SAFETY: `uctx` is the live per-task UserTaskCtx from
        // current_user_task(); we hold the only reference while setting the
        // deadline + saving the RIP-rewound CPU state before the yield hook
        // hands the task to the executor.
        unsafe {
            let uc = &*uctx;
            uc.sleep_deadline_ns.store(deadline, Ordering::Release);
            // Clear a stale futex_uaddr so this park can't mis-route into
            // the futex branch; snapshot the readiness generation for the
            // check→park lost-wake guard.
            uc.futex_uaddr.store(0, Ordering::Release);
            uc.net_io_wait.store(true, Ordering::Release);
            uc.durable_io_wait
                .store(durable_io_wait, Ordering::Release);
            uc.epoll_park_gen
                .store(narf_net::readiness::generation(), Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                // `own_stack_block` returns only after the park has ended. It
                // normally clears the marker itself; cover the arm-raced-ready
                // path too so a later generic I/O wait cannot inherit it.
                uc.durable_io_wait.store(false, Ordering::Release);
                return true;
            }
            hook(uctx);
        }
        // unreachable — hook() longjmps to the executor
    }
    false
}

/// Park a blocking syscall on one descriptor's durable readiness cell, then
/// re-execute the syscall from its original user arguments.  The readiness arm
/// happens before the task becomes unrunnable, so a peer that frees space in
/// that window cannot lose the wake.  Descriptors that have not migrated to a
/// durable cell retain the existing generation-guarded I/O park.
pub(crate) fn park_reexecute_on_fd(
    ctx: &mut dyn TrapContext,
    ops: &dyn narf_filesystem::FileOps,
    interest: u32,
) -> bool {
    // CaptureCtx deliberately reports RIP 0 for a nested sendmsg used by
    // sendmmsg.  The outer handler must decide whether re-execution is safe
    // after accounting for any messages it already transmitted.
    if ctx.rip() == 0 {
        return false;
    }
    let task = current_task_id();
    let Some(waker) = narf_scheduler::stackful::current_stackful_waker() else {
        // Legacy longjmp execution has no stackful waker, but it does have the
        // generation-guarded park path. Preserve blocking semantics there;
        // returning false would make a blocking stream send spuriously surface
        // EAGAIN whenever own-stack mode is disabled.
        return park_reexecute_on_io(ctx);
    };
    match ops.arm_readiness_exclusive(task, interest, &waker) {
        Some(Poll::Ready(_)) => {
            ops.disarm_readiness(task);
            #[cfg(target_arch = "x86_64")]
            const SYSCALL_INSN_LEN: u64 = 2;
            #[cfg(target_arch = "aarch64")]
            const SYSCALL_INSN_LEN: u64 = 4;
            ctx.set_rip(ctx.rip().wrapping_sub(SYSCALL_INSN_LEN));
            true
        }
        Some(Poll::Pending) => {
            // The provider checked the level and installed this task's waker
            // under the same per-fd lock used by `Readiness::set`.
            // There is no lost-wake window to poll with a 1 ms timer.
            let parked = park_reexecute_on_io_until(ctx, u64::MAX, true);
            ops.disarm_readiness(task);
            parked
        }
        None => park_reexecute_on_io(ctx),
    }
}

/// Encode a `siginfo_t` (128 bytes, x86_64/aarch64 layout) describing a
/// child state change for `waitid(2)`. Fills si_signo = SIGCHLD,
/// si_code (CLD_EXITED / CLD_KILLED / CLD_DUMPED), si_pid, si_uid (0),
/// and si_status decoded from the POSIX wstatus.
fn encode_waitid_siginfo(child_pid: i64, wstatus: i32) -> [u8; 128] {
    const SIGCHLD: i32 = 17;
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    const CLD_STOPPED: i32 = 5;
    const CLD_CONTINUED: i32 = 6;
    let mut si = [0u8; 128];
    let (code, code_status) = if wstatus == CONTINUED_WSTATUS {
        // WIFCONTINUED: 0xffff. si_status = SIGCONT.
        (CLD_CONTINUED, 18)
    } else if wstatus & 0xff == 0x7f {
        // WIFSTOPPED: low byte 0x7f, WSTOPSIG in bits 8..16.
        (CLD_STOPPED, (wstatus >> 8) & 0xff)
    } else if wstatus & 0x7f == 0 {
        // WIFEXITED: low 7 bits zero; exit code in bits 8..16.
        (CLD_EXITED, (wstatus >> 8) & 0xff)
    } else {
        // WIFSIGNALED: low 7 bits = signum, bit 7 = core-dumped.
        let signum = wstatus & 0x7f;
        let code = if wstatus & 0x80 != 0 {
            CLD_DUMPED
        } else {
            CLD_KILLED
        };
        (code, signum)
    };
    // si_signo @0, si_errno @4 (0), si_code @8, then the union: si_pid
    // @16, si_uid @20, si_status @24 on the LP64 siginfo layout.
    si[0..4].copy_from_slice(&SIGCHLD.to_ne_bytes());
    si[8..12].copy_from_slice(&code.to_ne_bytes());
    si[16..20].copy_from_slice(&(child_pid as i32).to_ne_bytes());
    si[24..28].copy_from_slice(&code_status.to_ne_bytes());
    si
}

/// Test hook: directly register a parent-of relationship without going
/// through `sys_fork`.  Used by smokes that verify wait4 routing against
/// synthetic task IDs that never ran through the scheduler.
#[doc(hidden)]
pub fn __test_inject_parent_of(child: u64, parent: u64) {
    // Initialise the tables if they haven't been yet (test may call
    // this before wait_init — initialise on demand).
    {
        let mut g = PARENT_OF.lock();
        if g.is_none() {
            *g = Some(BTreeMap::new());
        }
    }
    parent_of_set(child, parent);
    {
        let mut g = PENDING_EXITS.lock();
        if g.is_none() {
            *g = Some(BTreeMap::new());
        }
    }
}

/// Test hook: stage an exited-child entry in `parent`'s pending-exits
/// queue without running a real task exit — what `on_child_exit` does
/// when a child terminates. Lets waitid/wait4 smokes exercise the reap
/// (and WNOWAIT peek) paths against a synthetic zombie.
#[doc(hidden)]
pub fn __test_stage_pending_exit(parent: u64, child: u64, status: i32) {
    let exit_signal = child_link_get(child).map_or(SIGCHLD, |link| link.exit_signal);
    __test_stage_pending_exit_with_signal(parent, child, status, exit_signal);
}

#[doc(hidden)]
pub fn __test_stage_pending_exit_with_signal(
    parent: u64,
    child: u64,
    status: i32,
    exit_signal: u8,
) {
    let mut g = PENDING_EXITS.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
    if let Some(m) = g.as_mut() {
        m.entry(parent)
            .or_insert_with(alloc::vec::Vec::new)
            .push(PendingExit {
                child_pid: child,
                status,
                exit_signal,
                ptraced: false,
            });
    }
}

/// Drop every staged pending-exit for `parent`. Teardown counterpart to
/// `__test_stage_pending_exit` for tests whose asserted path (e.g. an ECHILD
/// early-return) intentionally does NOT reap the entry it staged.
pub fn __test_clear_pending_exits(parent: u64) {
    let mut g = PENDING_EXITS.lock();
    if let Some(m) = g.as_mut() {
        m.remove(&parent);
    }
}

fn adjust_parent_child_count(old_parent: Option<u64>, new_parent: Option<u64>) {
    if old_parent == new_parent {
        return;
    }
    let mut counts = PARENT_CHILD_COUNTS.lock();
    let m = counts.get_or_insert_with(BTreeMap::new);
    if let Some(parent) = old_parent {
        let remove = if let Some(count) = m.get_mut(&parent) {
            if *count <= 1 {
                true
            } else {
                *count -= 1;
                false
            }
        } else {
            false
        };
        if remove {
            m.remove(&parent);
        }
    }
    if let Some(parent) = new_parent {
        let count = m.entry(parent).or_insert(0);
        *count = count.saturating_add(1);
    }
}

#[inline]
fn parent_child_count(parent: u64) -> u32 {
    PARENT_CHILD_COUNTS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&parent).copied())
        .unwrap_or(0)
}
fn parent_of_set(child: u64, parent: u64) {
    parent_of_set_with_signal(child, parent, SIGCHLD);
}

fn parent_of_set_with_signal(child: u64, parent: u64, exit_signal: u8) {
    let mut links = PARENT_OF.lock();
    if let Some(m) = links.as_mut() {
        let old = m.insert(
            child,
            ChildLink {
                parent,
                exit_signal,
            },
        );
        adjust_parent_child_count(old.map(|link| link.parent), Some(parent));
    }
}

#[inline]
fn child_link_get(child: u64) -> Option<ChildLink> {
    PARENT_OF
        .lock()
        .as_ref()
        .and_then(|m| m.get(&child).copied())
}

pub(crate) fn parent_of_get(child: u64) -> Option<u64> {
    child_link_get(child).map(|link| link.parent)
}

/// `parent_of_get` for the timer trap, which can interrupt a CPU already
/// holding `PARENT_OF`. Returns `None` on contention rather than
/// deadlocking the machine under observation.
#[cfg(feature = "unix-latency-trace")]
pub(crate) fn parent_of_get_try(child: u64) -> Option<u64> {
    let g = PARENT_OF.try_lock()?;
    g.as_ref()
        .and_then(|m| m.get(&child).map(|link| link.parent))
}

#[doc(hidden)]
pub fn __test_parent_link(child: u64) -> Option<(u64, u8)> {
    child_link_get(child).map(|link| (link.parent, link.exit_signal))
}

#[doc(hidden)]
pub fn __test_parent_of_set_with_signal(child: u64, parent: u64, exit_signal: u8) {
    parent_of_set_with_signal(child, parent, exit_signal);
}

/// Drop the child→parent record once the child has been reaped (or is an
/// orphan being auto-released). Lets `has_living_child` correctly report
/// ECHILD after the last child is reaped — without this, stale entries make
/// `wait4` think children still exist and block forever.
fn parent_of_remove(child: u64) {
    let mut links = PARENT_OF.lock();
    if let Some(m) = links.as_mut() {
        if let Some(old) = m.remove(&child) {
            adjust_parent_child_count(Some(old.parent), None);
        }
    }
}

/// `release_task()` half of a reap: drop the task-registry reference for
/// the reaped child so the `Arc<Task>` (and its `UserTaskCtx`) can free
/// once the executor slot's ref is gone too. Called from every path that
/// fully reaps a child pid (sync wait4/waitid, the blocking reap check,
/// and the orphan auto-release). Resolves pid→tid through the fork-time
/// mapping — still intact at reap time because nothing removes it before
/// this point.
pub(crate) fn release_reaped_task(child_pid: u64) {
    if let Some(tid) = pid_to_task_raw(child_pid) {
        // Only release a task that actually ran its exit path. A
        // CLONE_THREAD sibling's exit stages a reap entry under the
        // SHARED tgid, and `pid_to_task_raw(tgid)` resolves to the
        // group LEADER — releasing the leader while it still runs
        // would strand every self-lookup it makes afterwards.
        if let Some(t) = crate::task::task_get(tid) {
            if t.state.load(Ordering::Acquire) == crate::task::TASK_ZOMBIE {
                // A zombie remains addressable by its PID in every namespace
                // until wait4/waitid reaps it. Releasing this binding in
                // on_child_exit made systemd's later waitid(P_PID, inner_pid)
                // unable to translate the inner PID to `child_pid`, so the
                // queued exit was never consumed. Drop the namespace slot at
                // the same reap boundary as PID_TO_TASK/TASK_TO_PID.
                #[cfg(feature = "container")]
                {
                    if let Some(ns) = crate::pid_ns::ns_of(tid) {
                        ns.release_outer(child_pid);
                    }
                    crate::pid_ns::clear_ns(tid);
                }
                // Serialize rlimit-row removal with prlimit64's retained-task
                // revalidation. Both paths take RLIMIT_TABLE before TASKS:
                // prlimit either completes its transaction first, or observes
                // that reap already removed the registry entry. No permanent
                // TaskId tombstone is needed (TaskIds are never reused).
                {
                    let mut rlimits = RLIMIT_TABLE.lock();
                    if let Some(state) = rlimits.as_mut() {
                        if state.rows.remove(&tid).is_some() {
                            RLIMIT_CUSTOM_ROWS
                                .fetch_sub(1, core::sync::atomic::Ordering::Release);
                        }
                    }
                    crate::task::release_task(tid);
                }
                // Reap-time pid↔tid unbinding. PIDs are recycled
                // (lowest-free), so a surviving PID_TO_TASK row would
                // point the pid's NEXT owner-lookup at this dead tid —
                // signals/waits misrouted to a corpse — and the stale
                // TASK_TO_PID row would translate this dead tid to a
                // pid someone else now owns. Removed only at reap:
                // the zombie window still needs both directions
                // (kill(pid) on a zombie, wstatus threading).
                {
                    let _mutation = PID_TASK_MUTATION.lock();
                    if let Some(m) = PID_TO_TASK[pid_task_shard(child_pid)].map.lock().as_mut() {
                        if m.get(&child_pid) == Some(&tid) {
                            m.remove(&child_pid);
                        }
                    }
                    if let Some(m) = TASK_TO_PID[pid_task_shard(tid)].map.lock().as_mut() {
                        m.remove(&tid);
                    }
                }
            }
        }
    }
}

// ── Exit-time per-task table sweep (release_task_tables) ────────────
//
// One master teardown for every tid-keyed table, run from the exit-
// observer fan-out. Before this existed, cleanup was bolted on
// table-by-table and ~40 tables were missed entirely — every exited
// task leaked its signal state, credentials, cwd, scheduling params,
// wakers, and timers forever (tids are monotonic, so nothing ever
// overwrote the stale rows), and pid-keyed leftovers were actively
// dangerous once the pid recycled.
//
// Tables deliberately NOT swept here:
//   - CLEAR_CHILD_TID       — `fire_clear_child_tid_on_exit` takes it
//                             (observer order must not matter),
//   - TASK_STOPPED          — on_child_exit already removes it,
//   - PENDING_TERMINATION   — drained by on_child_exit (wstatus),
//   - TASK_CPU_NS/CHILD     — needed at reap (account_reaped_child),
//   - PID_TO_TASK/TASK_TO_PID — needed through the zombie window,
//                             removed at reap (release_reaped_task),
//   - fd table              — fd::detach (on_child_exit) owns it.
fn release_task_tables(tid: u64) {
    #[cfg(feature = "container")]
    crate::namespaces::release_task(tid);
    // JIT (W^X) grant. Revoking bumps the object's epoch, so any capability
    // copy that escaped this table fails its next `check_live` — the grant
    // cannot outlive the task that was given it.
    narf_memory::wx::revoke_jit(tid);
    // Signal state.
    pending_signal_bits_remove(tid);
    signal_bits_remove(&SIGNAL_READABLE_GEN, tid);
    signal_bits_remove(&SIGNAL_RAISE_GEN, tid);
    signal_bits_remove(&SIGNAL_MASK, tid);
    task_map_remove(&SIGACTION_TABLE, tid);
    if let Some(m) = SIG_ALTSTACK.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SIGQUEUE_INFO[sigqueue_bucket(tid)].values.lock().as_mut() {
        m.retain(|&(t, _), _| t != tid);
    }
    if let Some(m) = SIGRETURN_STACK.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SUSPEND_SAVED_MASK.lock().as_mut() {
        m.remove(&tid);
    }

    // Parked-waker registrations. All wakers are Arc<WakeCell>, so a
    // stale entry is "only" a leak + a spurious wake — but under task
    // churn (threads dying while parked) the growth is unbounded.
    drop_signal_waker(tid);
    drop_io_waiter(tid);
    crate::user_task::drop_wait_child_waker(tid);
    futex_drop_task_waiters(tid);
    for shard in TCB_OWNER.iter() {
        if let Some(m) = shard.lock().as_mut() {
            m.retain(|_, owner| *owner != tid);
        }
    }

    // Identity / credentials / per-task knobs.
    let credential_shard = credential_shard(tid);
    if let Some(m) = CREDENTIAL_TABLES[credential_shard].uidgid.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = CREDENTIAL_TABLES[credential_shard].groups.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = CAP_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = PGID_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SID_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = CTTY_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = PRCTL_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = NICE_TABLE.lock().as_mut() {
        if m.remove(&tid).is_some() {
            NICE_CUSTOM_ROWS.fetch_sub(1, Ordering::Release);
        }
    }
    if let Some(m) = SCHED_PARAM_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SCHED_ATTR_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = UMASK_TABLE.lock().as_mut() {
        m.remove(&tid);
    }

    // Filesystem view.
    task_map_remove(&CWD_TABLE, tid);
    remove_root_dir(tid);
    remove_mount_namespace(tid);
    crate::mqueue::release_task_fd_paths(tid);

    // Memory policy.
    if let Some(m) = MEMPOLICY_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = MBIND_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = INTERLEAVE_INDEX_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = NUMA_BALANCE_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    narf_scheduler::clear_task_mems_allowed(tid);
    if let Some(m) = PKEY_TABLE.lock().as_mut() {
        m.remove(&tid);
    }

    // /proc mirrors.
    if let Some(m) = PROC_ARGV.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = PROC_COMM.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = PROC_EXE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = TASK_START_NS.lock().as_mut() {
        m.remove(&tid);
    }
    task_account_remove(&TASK_KERN_NS, tid);
    ioprio_release(tid);
    // POSIX record locks: normally already drained (fd::detach runs
    // first in exit-observer order and wakes the waiters); this second
    // pass is the backstop for any path that tears down tables without
    // detaching fds. Also retire this task's own waiter entries (it
    // may die while parked on someone else's lock).
    {
        for key in crate::fd::locks::release_owner(tid) {
            for (waiter, w) in crate::fd::locks::drain_waiters(key) {
                wake_one(waiter, w);
            }
        }
        crate::fd::locks::drop_waiter_owner(tid);
    }
    if let Some(m) = PROC_ENVIRON.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = PROC_AUXV.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = PROC_OOM_ADJ.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = PROC_COREDUMP_FILTER.lock().as_mut() {
        m.remove(&tid);
    }

    // Terminal + locks + misc.
    if let Some(m) = TASK_TERMIOS.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = FLOCK_TABLE.lock().as_mut() {
        // flock(2) exclusive locks die with their owner. Shared holds
        // are an anonymous count and can't be attributed — left to the
        // fd-close path (pre-existing behaviour).
        for e in m.values_mut() {
            if e.exclusive_owner == tid {
                e.exclusive_owner = 0;
            }
        }
    }
    if let Some(m) = BOOTSTRAP_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = ROBUST_LIST_TABLE.lock().as_mut() {
        // The owner-died walk already ran in the task's own exit
        // context (robust_list_exit_walk); this is just the row.
        m.remove(&tid);
    }

    // Timers: a post-mortem expiry must not raise a phantom signal.
    // POSIX timers only exist in the linux-compat build.
    crate::posix_timer::release_task_timers(tid);

    // Linux kernel-AIO contexts: drop any io_setup'd contexts the task
    // never io_destroy'd, so a forgetful process doesn't leak them.
    aio::release_task_aio(tid);

    // Console signal routing: if the dying task was the recorded
    // foreground reader, ^C/^Z must stop resolving to its corpse.
    let _ = FOREGROUND_TASK.compare_exchange(
        tid,
        0,
        core::sync::atomic::Ordering::AcqRel,
        core::sync::atomic::Ordering::Relaxed,
    );
}

/// Orphan-handling half of exit: the dying task's children lose their
/// parent. NARF's pid-1 is a stub that never waits, so Linux-style
/// reparent-to-init would accumulate zombies forever; instead children
/// are ORPHANIZED — their PARENT_OF rows drop, so their own exits take
/// on_child_exit's no-parent branch and auto-release (equivalent to
/// init running with SA_NOCLDWAIT). Children that ALREADY exited and
/// sit unreaped in the dying parent's PENDING_EXITS queue are released
/// here — before this existed they leaked their pid + Task forever and
/// a parent-of-a-dead-parent chain could strand a wait4 sleeper.
/// Nearest live ancestor of `dying` that volunteered as a child
/// subreaper (PR_SET_CHILD_SUBREAPER) — the process that inherits the
/// dying task's orphans, Linux `find_new_reaper` minus the init
/// fallback (NARF has no reaping init; no subreaper = auto-release,
/// the pre-subreaper behavior). Bounded walk: PARENT_OF chains are
/// fork-depth, but a corrupt cycle must not wedge the exit path.
fn find_child_subreaper(dying: u64) -> Option<u64> {
    let mut cur_pid = task_to_pid_raw(dying).unwrap_or(dying);
    for _ in 0..64 {
        let parent = parent_of_get(cur_pid)?;
        let parent_tid = pid_to_task_raw(parent).unwrap_or(parent);
        if read_prctl(parent_tid).child_subreaper && signal_target_exists(parent_tid) {
            return Some(parent_tid);
        }
        cur_pid = task_to_pid_raw(parent_tid).unwrap_or(parent_tid);
    }
    // Fall back to PID 1 (init / systemd) if alive and not dying itself
    if signal_target_exists(1) && dying != 1 {
        Some(1)
    } else {
        None
    }
}

/// Test hook: run the orphanize pass for a synthetic parent without
/// going through a real task exit.
#[doc(hidden)]
pub fn __test_orphanize_children_of(parent_tid: u64) {
    orphanize_children_of(parent_tid);
}

/// Prefer another live thread in the dying task's thread group as the
/// reparent target. Linux find_new_reaper does this before consulting
/// subreapers or namespace init.
fn find_thread_group_reaper(dying: u64) -> Option<u64> {
    let tgid = task_to_pid_raw(dying)?;
    if let Some(leader) = pid_to_task_raw(tgid) {
        if leader != dying && signal_target_exists(leader) {
            return Some(leader);
        }
    }
    task_pid_snapshot().into_iter().find_map(|(task, pid)| {
        (pid == tgid && task != dying && signal_target_exists(task)).then_some(task)
    })
}

fn orphanize_children_of(parent_tid: u64) {
    // A short-lived leaf is the dominant fork/clone case. Without this index
    // every exit scanned the global ChildLink map; stress-ng queues thousands
    // of clones before reaping, making teardown O(n²).
    if parent_child_count(parent_tid) == 0 {
        return;
    }
    let thread_reaper = find_thread_group_reaper(parent_tid);
    let reaper = thread_reaper.or_else(|| find_child_subreaper(parent_tid));
    let reset_exit_signal = thread_reaper.is_none();

    // Already-exited, never-reaped children move to the selected reaper. A
    // same-thread-group transfer preserves the clone exit signal; an external
    // reparent resets it to SIGCHLD, exactly like Linux reparent_leader.
    let mut stale: alloc::vec::Vec<PendingExit> = {
        let mut g = PENDING_EXITS.lock();
        g.as_mut()
            .and_then(|m| m.remove(&parent_tid))
            .unwrap_or_default()
    };
    match reaper {
        Some(r) if !stale.is_empty() => {
            for entry in &mut stale {
                if reset_exit_signal {
                    entry.exit_signal = SIGCHLD;
                }
                entry.ptraced = false;
                parent_of_set_with_signal(entry.child_pid, r, entry.exit_signal);
            }
            if let Some(m) = PENDING_EXITS.lock().as_mut() {
                m.entry(r).or_default().extend(stale.iter().copied());
            }
            // Threaded reparenting stays inside the same wait domain and does
            // not generate a second SIGCHLD. External reapers are notified.
            if reset_exit_signal {
                raise_signal_pending(r, 17);
            }
            wake_wait_child_group(r);
        }
        _ => {
            for entry in stale {
                release_reaped_task(entry.child_pid);
                crate::release_pid(crate::ProcessId(entry.child_pid));
                parent_of_remove(entry.child_pid);
            }
        }
    }

    // Preserve queued stop/continue reports across reparenting too.
    let stopcont = PENDING_STOPCONT
        .lock()
        .as_mut()
        .and_then(|m| m.remove(&parent_tid))
        .unwrap_or_default();
    if let Some(r) = reaper {
        if !stopcont.is_empty() {
            if let Some(m) = PENDING_STOPCONT.lock().as_mut() {
                m.entry(r).or_default().extend(stopcont);
            }
            wake_wait_child_group(r);
        }
    }

    // Still-running children: deliver each one's PR_SET_PDEATHSIG before the
    // rows move, then retarget them to the selected reaper.
    let children: alloc::vec::Vec<u64> = {
        let g = PARENT_OF.lock();
        g.as_ref()
            .map(|m| {
                m.iter()
                    .filter(|(_, link)| link.parent == parent_tid)
                    .map(|(&c, _)| c)
                    .collect()
            })
            .unwrap_or_default()
    };
    for child_pid in &children {
        let child_tid = pid_to_task_raw(*child_pid).unwrap_or(*child_pid);
        let sig = read_prctl(child_tid).pdeathsig;
        if sig != 0 {
            raise_signal_pending(child_tid, sig);
        }
    }
    match reaper {
        Some(r) => {
            for child_pid in children {
                if let Some(link) = child_link_get(child_pid) {
                    parent_of_set_with_signal(
                        child_pid,
                        r,
                        if reset_exit_signal {
                            SIGCHLD
                        } else {
                            link.exit_signal
                        },
                    );
                }
            }
        }
        None => {
            for child_pid in children {
                parent_of_remove(child_pid);
            }
        }
    }
}

/// Exit observer running AFTER `on_child_exit` (parent notification
/// must see the dying task's pgid/sid intact): the master per-task
/// teardown. `_pid` is the visible pid; all swept tables key on tid.
fn task_tables_exit_observer(_pid: u64, tid: u64) {
    release_task_tables(tid);
    orphanize_children_of(tid);
}

/// Test-only: run the AIO-context exit sweep for `tid` (the
/// `release_task_tables` path a real task exit triggers), so a smoke can
/// verify a process that skips `io_destroy` has its contexts reclaimed.
#[doc(hidden)]
pub fn __test_release_task_aio(tid: u64) {
    aio::release_task_aio(tid);
}

/// Test-only: bitmask of per-task tables still holding rows for `tid`.
/// Bit assignments documented inline; 0 = fully swept.
#[doc(hidden)]
pub fn __test_task_table_residue(tid: u64) -> u32 {
    let mut r = 0u32;
    let has = |present: bool, bit: u32| if present { bit } else { 0 };
    r |= has(signal_bits_contains(&SIGNAL_PENDING, tid), 1 << 0);
    r |= has(signal_bits_contains(&SIGNAL_MASK, tid), 1 << 1);
    r |= has(task_map_get(&SIGACTION_TABLE, tid).is_some(), 1 << 2);
    r |= has(
        SIGNAL_WAKERS[signal_waker_shard(tid)]
            .values
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 3,
    );
    r |= has(
        IO_WAKERS[io_waker_shard(tid)]
            .lock()
            .as_ref()
            .is_some_and(|s| s.wakers.contains_key(&tid)),
        1 << 4,
    );
    r |= has(futex_has_task_waiter(tid), 1 << 5);
    r |= has(
        PROC_ARGV
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 6,
    );
    r |= has(
        PROC_COMM
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 7,
    );
    r |= has(
        PARENT_OF
            .lock()
            .as_ref()
            .is_some_and(|m| m.values().any(|link| link.parent == tid)),
        1 << 8,
    );
    r |= has(
        PENDING_STOPCONT
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 9,
    );
    r |= has(FOREGROUND_TASK.load(Ordering::Acquire) == tid, 1 << 10);
    r |= has(
        ROBUST_LIST_TABLE
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 11,
    );
    r |= has(crate::mqueue::task_has_fd_paths(tid), 1 << 12);
    r
}

/// Test-only: `parent_of_set` passthrough (the real fn is file-private).
#[doc(hidden)]
pub fn __test_parent_of_set(child: u64, parent: u64) {
    parent_of_set(child, parent);
}

/// Test-only: seed a robust-list head for `tid` without a TrapContext.
#[doc(hidden)]
pub fn __test_set_robust_list(tid: u64, head: u64, len: u64) {
    let mut g = ROBUST_LIST_TABLE.lock();
    g.get_or_insert_with(alloc::collections::BTreeMap::new)
        .insert(tid, (head, len));
}

/// Test-only: run the exit-time robust walk directly.
#[doc(hidden)]
pub fn __test_robust_walk(tid: u64) {
    robust_list_exit_walk(tid);
}

/// Test-only: expose the robust-walk's page-presence gate so a test can
/// prove region (VMA) membership is NOT mistaken for a present page.
#[doc(hidden)]
pub fn __test_user_page_present(as_ref: &AddressSpace, uaddr: u64) -> bool {
    user_page_present(as_ref, uaddr)
}

/// Test-only: set the console foreground task slot.
#[doc(hidden)]
pub fn __test_set_foreground_task(tid: u64) {
    FOREGROUND_TASK.store(tid, Ordering::Release);
}

/// Does `parent` still have at least one unreaped LIVING child matching
/// `want` (>0 = that exact visible pid; <=0 = any child)? Zombies are handled
/// by the `PENDING_EXITS` reap path, so this only gates the block-vs-ECHILD
/// decision once no matching exit is queued: a true result means "a child is
/// still running, block for it"; false means "no such child — return ECHILD".
fn has_living_child(parent: u64, want: i64, want_pgid: u64, options: u32) -> bool {
    let parents = wait_parent_ids(parent, options);
    let g = PARENT_OF.lock();
    let is_parent = g.as_ref().is_some_and(|m| {
        m.iter().any(|(&child, link)| {
            parents.contains(&link.parent)
                && wait_child_matches(
                    child,
                    want,
                    want_pgid,
                    link.exit_signal,
                    false,
                    options,
                )
        })
    });
    if is_parent {
        return true;
    }
    parents
        .into_iter()
        .any(|candidate| crate::ptrace::is_tracer_of_any(candidate, want))
}

// ── ProcessId ↔ TaskId translation ────────────────────────────────
//
// `sys_fork` mints a fresh ProcessId (from `alloc_pid()`) and a fresh
// TaskId (from `spawn_user()`). Any code that receives a ProcessId
// (e.g. a user-visible fork return value or a /proc path) but needs
// the internal TaskId (e.g. scheduler lookups, fd-table accesses) must
// translate through this table.

const PID_TASK_SHARDS: usize = 32;

#[repr(align(64))]
struct PidTaskMapShard {
    map: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>>,
}

impl PidTaskMapShard {
    const fn new() -> Self {
        Self {
            map: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
}

/// ProcessId.raw() → TaskId.raw(), sharded by ProcessId.
static PID_TO_TASK: [PidTaskMapShard; PID_TASK_SHARDS] =
    [const { PidTaskMapShard::new() }; PID_TASK_SHARDS];

/// TaskId.raw() → ProcessId.raw(), sharded by TaskId.
static TASK_TO_PID: [PidTaskMapShard; PID_TASK_SHARDS] =
    [const { PidTaskMapShard::new() }; PID_TASK_SHARDS];
/// Scheduler TaskId -> Linux TID for non-leader threads.
static TASK_TO_LINUX_TID: [PidTaskMapShard; PID_TASK_SHARDS] =
    [const { PidTaskMapShard::new() }; PID_TASK_SHARDS];
/// Linux TID -> scheduler TaskId for non-leader threads.
static LINUX_TID_TO_TASK: [PidTaskMapShard; PID_TASK_SHARDS] =
    [const { PidTaskMapShard::new() }; PID_TASK_SHARDS];
/// Serializes the cold registration/removal paths with whole-registry
/// snapshots. Point lookups intentionally bypass it and take one shard only.
static PID_TASK_MUTATION: narf_lib::sync::IrqSafeSpinLock<()> =
    narf_lib::sync::IrqSafeSpinLock::new(());

#[inline]
fn pid_task_shard(id: u64) -> usize {
    (id as usize) & (PID_TASK_SHARDS - 1)
}

/// Snapshot all process mappings while holding every shard in ascending
/// order. Group-wide signal and /proc walks need one coherent registry view;
/// point lookups and mutations take only their key's shard.
fn pid_task_snapshot() -> alloc::vec::Vec<(u64, u64)> {
    let _mutation = PID_TASK_MUTATION.lock();
    let mut snapshot = alloc::vec::Vec::new();
    for shard in PID_TO_TASK.iter() {
        if let Some(map) = shard.map.lock().as_ref() {
            snapshot.extend(map.iter().map(|(&pid, &task)| (pid, task)));
        }
    }
    snapshot.sort_unstable_by_key(|&(pid, _)| pid);
    snapshot
}

/// Task-keyed counterpart to [`pid_task_snapshot`].
fn task_pid_snapshot() -> alloc::vec::Vec<(u64, u64)> {
    let _mutation = PID_TASK_MUTATION.lock();
    let mut snapshot = alloc::vec::Vec::new();
    for shard in TASK_TO_PID.iter() {
        if let Some(map) = shard.map.lock().as_ref() {
            snapshot.extend(map.iter().map(|(&task, &pid)| (task, pid)));
        }
    }
    snapshot.sort_unstable_by_key(|&(task, _)| task);
    snapshot
}

pub fn pid_task_map_init() {
    for shard in PID_TO_TASK.iter() {
        *shard.map.lock() = Some(BTreeMap::new());
    }
    for shard in TASK_TO_PID.iter() {
        *shard.map.lock() = Some(BTreeMap::new());
    }
    for shard in TASK_TO_LINUX_TID.iter() {
        *shard.map.lock() = Some(BTreeMap::new());
    }
    for shard in LINUX_TID_TO_TASK.iter() {
        *shard.map.lock() = Some(BTreeMap::new());
    }
}

pub fn pid_task_map_reset() {
    for shard in PID_TO_TASK.iter() {
        *shard.map.lock() = None;
    }
    for shard in TASK_TO_PID.iter() {
        *shard.map.lock() = None;
    }
    for shard in TASK_TO_LINUX_TID.iter() {
        *shard.map.lock() = None;
    }
    for shard in LINUX_TID_TO_TASK.iter() {
        *shard.map.lock() = None;
    }
}

/// Register a (ProcessId → TaskId) mapping. Called by `sys_fork` and
/// boot spawn_one for every user task that gets a user-visible ProcessId.
/// Records both directions simultaneously so all translations are O(1).
pub fn register_pid_task_mapping(pid_raw: u64, task_raw: u64) {
    let _mutation = PID_TASK_MUTATION.lock();
    TASK_TO_PID[pid_task_shard(task_raw)]
        .map
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(task_raw, pid_raw);
    // Self-initialize: the map may be `None` if `wait_init` hasn't run
    // yet (early boot, or the kernel-test harness which boots straight
    // into the smoke runner). Without this a `fork` registration would
    // silently no-op and every later pid→task translation would miss.
    PID_TO_TASK[pid_task_shard(pid_raw)]
        .map
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(pid_raw, task_raw);
}

pub fn register_task_to_pid(task_raw: u64, pid_raw: u64) {
    let _mutation = PID_TASK_MUTATION.lock();
    TASK_TO_PID[pid_task_shard(task_raw)]
        .map
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(task_raw, pid_raw);
}


/// Register all Linux identity views for a non-leader thread. Linux TIDs and
/// process IDs share one allocator; TaskId remains scheduler-private.
fn register_thread_task_mapping(tid_raw: u64, task_raw: u64, tgid_raw: u64) {
    let _mutation = PID_TASK_MUTATION.lock();
    TASK_TO_PID[pid_task_shard(task_raw)]
        .map
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(task_raw, tgid_raw);
    TASK_TO_LINUX_TID[pid_task_shard(task_raw)]
        .map
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(task_raw, tid_raw);
    LINUX_TID_TO_TASK[pid_task_shard(tid_raw)]
        .map
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(tid_raw, task_raw);
}

pub(crate) fn task_to_linux_tid_raw(task_raw: u64) -> Option<u64> {
    TASK_TO_LINUX_TID[pid_task_shard(task_raw)]
        .map
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task_raw).copied())
}

pub(crate) fn linux_tid_to_task_raw(tid_raw: u64) -> Option<u64> {
    LINUX_TID_TO_TASK[pid_task_shard(tid_raw)]
        .map
        .lock()
        .as_ref()
        .and_then(|m| m.get(&tid_raw).copied())
}
/// Release a finished non-leader thread from the task registry. Linux does
/// not expose CLONE_THREAD siblings as wait4-reapable zombies; retaining them
/// until the process exits leaks one Task/TCB allocation per pthread and makes
/// sustained thread churn progressively slower.
pub(crate) fn release_exited_thread_task(pid: u64, tid: u64) {
    let Some(leader_tid) = pid_to_task_raw(pid) else {
        return;
    };
    if leader_tid == tid {
        return;
    }
    crate::task::release_task(tid);
    let _mutation = PID_TASK_MUTATION.lock();
    let linux_tid = TASK_TO_LINUX_TID[pid_task_shard(tid)]
        .map
        .lock()
        .as_mut()
        .and_then(|m| m.remove(&tid));
    if let Some(linux_tid) = linux_tid {
        #[cfg(feature = "cgroup")]
        narf_filesystem::cgroupfs::thread_exited(linux_tid);
        if let Some(m) = LINUX_TID_TO_TASK[pid_task_shard(linux_tid)].map.lock().as_mut() {
            if m.get(&linux_tid) == Some(&tid) {
                m.remove(&linux_tid);
            }
        }
        #[cfg(feature = "container")]
        {
            if let Some(ns) = crate::pid_ns::ns_of(tid) {
                ns.release_outer(linux_tid);
            }
            crate::pid_ns::clear_ns(tid);
        }
        crate::release_pid(crate::ProcessId(linux_tid));
    }
    if let Some(m) = TASK_TO_PID[pid_task_shard(tid)].map.lock().as_mut() {
        m.remove(&tid);
    }
}

/// Linux `signal->live`: per-thread-group (per-`pid`) count of live
/// threads. Only ever holds entries for MULTI-threaded groups — a
/// single-threaded process is never inserted (its implicit count is 1)
/// and reports `group_dead` on its sole exit. The last thread to
/// decrement to zero is `group_dead` and runs the process-scoped exit
/// observers exactly once (see `user_task::notify_task_exited`).
static THREAD_GROUP_LIVE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// A `CLONE_THREAD` child joined thread-group `pid`. The group's
/// implicit main thread counts as 1, so the first extra thread makes
/// the tracked count 2; each subsequent thread adds one.
pub fn thread_group_live_inc(pid: u64) {
    let mut g = THREAD_GROUP_LIVE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    let e = m.entry(pid).or_insert(1);
    *e = e.saturating_add(1);
}

/// A thread of group `pid` exited. Returns `true` iff it was the LAST
/// live thread (`group_dead`) — the caller then runs process-scoped
/// teardown exactly once. An untracked group (single-threaded, never
/// `inc`'d) is implicitly its own last thread and returns `true`.
/// Decrement the live count and also report whether this pid belonged to a
/// tracked multi-threaded group. The second result lets exit cleanup avoid a
/// process-registry lookup for ordinary single-threaded fork children.
pub(crate) fn thread_group_live_dec_state(pid: u64) -> (bool, bool) {
    let mut g = THREAD_GROUP_LIVE.lock();
    let Some(m) = g.as_mut() else {
        return (true, false);
    };
    match m.get_mut(&pid) {
        None => (true, false),
        Some(n) if *n <= 1 => {
            m.remove(&pid);
            (true, true)
        }
        Some(n) => {
            *n -= 1;
            (false, true)
        }
    }
}

pub fn thread_group_live_dec(pid: u64) -> bool {
    thread_group_live_dec_state(pid).0
}

/// Live-thread count of thread-group `pid`. Single-threaded groups are
/// never tracked (their implicit count is 1), so an absent entry reads as
/// 1. Backs /proc/[pid]/status `Threads:` and stat field 20.
pub fn thread_group_live_count(pid: u64) -> u64 {
    let g = THREAD_GROUP_LIVE.lock();
    g.as_ref()
        .and_then(|m| m.get(&pid).copied())
        .map(|n| n as u64)
        .unwrap_or(1)
        .max(1)
}

/// Test-only: reset the live-thread accounting.
#[doc(hidden)]
pub fn __test_thread_group_live_reset() {
    *THREAD_GROUP_LIVE.lock() = Some(BTreeMap::new());
}

/// Translate a user-visible ProcessId to the scheduler TaskId. Returns
/// `None` when the pid was never registered (kernel-internal tasks,
/// boot tasks spawned before the table was inited, etc.).
pub fn pid_to_task_raw(pid_raw: u64) -> Option<u64> {
    PID_TO_TASK[pid_task_shard(pid_raw)]
        .map
        .lock()
        .as_ref()
        .and_then(|m| m.get(&pid_raw).copied())
}

/// Translate a scheduler TaskId to the user-visible ProcessId registered
/// at fork/spawn time. Returns `None` when the task has no registered
/// ProcessId (kernel-only tasks, test stubs).
pub fn task_to_pid_raw(task_raw: u64) -> Option<u64> {
    TASK_TO_PID[pid_task_shard(task_raw)]
        .map
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task_raw).copied())
}

/// Exit observer registered by `wait_init`. Called when a polled
/// user task transitions to Exited:
///
///   1. Pushes (child_pid, status) onto the parent's pending-exits
///      queue so a future wait4 can reap it.
///   2. Sets SIGCHLD (17) pending on the parent so the parent's
///      signal handler (if installed) is invoked on the next trap
///      return.  POSIX 2017 §2.4.3: "If a process is stopped or
///      terminated by a signal, SIGCHLD shall be generated for its
///      parent process."
///
/// Status: the user-supplied exit code from sys_exit_task is not yet
/// threaded through EXIT_REASON_EXITED to here — normal exits record
/// 0 (WIFEXITED with WEXITSTATUS=0). Signal-induced exits go through
/// `stage_pending_termination` (set by `default_signal_delivery` /
/// `default_sync_signal_delivery` when no handler is installed and
/// the default action is Terminate/CoreDump); we drain it here and
/// publish the WIFSIGNALED-shaped wstatus to wait4.
/// THREAD-scoped exit observer: per-`tid` teardown that runs for EVERY
/// exiting thread (not just the group's last). Keyed on the scheduler
/// TaskId, so a `CLONE_THREAD` sibling releases its OWN fd-table ref
/// and job-control state; the shared fd table (one `Arc` per thread)
/// frees when the last sibling detaches.
fn on_thread_exit(_pid: u64, tid: u64) {
    // Release the exiting thread's fd-table ref so every FileOps `Arc`
    // it held drops. This is what lets a pipe's write end actually close
    // when its last writer exits — without it `writer_closed` never
    // flips and a reader (a shell's `$(...)` capture) never sees EOF.
    // Also frees file/socket handles so they don't leak.
    crate::fd::detach(tid);
    // Job control: a task that dies while stopped (e.g. SIGKILL'd) must
    // not leave a stale TASK_STOPPED entry — the TaskId could later be
    // recycled.
    if let Some(m) = TASK_STOPPED.lock().as_mut() {
        m.remove(&tid);
    }
}

/// Translate an outer ProcessId into `observer_task`'s PID-namespace view for
/// REPORTING to userspace — clone/fork/wait return values, `si_pid`, getppid,
/// `/proc/<pid>/stat` PPid, pidfd fdinfo, cgroup.procs, SO_PEERCRED. Identity
/// in the root namespace (and, cheaply, in non-`container` builds where the
/// namespace tables are never populated). Centralises the `cfg` gate so the
/// dozens of reporting sites stay uncluttered and can't drift apart.
#[inline]
pub(crate) fn report_pid_to(observer_task: u64, outer: u64) -> u64 {
    #[cfg(feature = "container")]
    {
        crate::pid_ns::self_inner_pid(observer_task, outer)
    }
    #[cfg(not(feature = "container"))]
    {
        let _ = observer_task;
        outer
    }
}

/// Translate a pid ARRIVING from userspace (wait `want_pid`, kill/tgkill
/// target, pidfd_open arg) from `caller_task`'s namespace view into the outer
/// ProcessId the kernel keys on. `None` means the inner pid is not bound in the
/// caller's namespace (→ ESRCH/ECHILD). Identity (`Some(inner)`) in the root
/// namespace / non-`container` builds.
#[inline]
pub(crate) fn accept_pid_from(caller_task: u64, inner: u64) -> Option<u64> {
    #[cfg(feature = "container")]
    {
        crate::pid_ns::resolve_inner_pid(caller_task, inner)
    }
    #[cfg(not(feature = "container"))]
    {
        let _ = caller_task;
        Some(inner)
    }
}

/// Resolve an outer ProcessId — the identity `ProcPidDir` and every per-pid
/// `/proc` hook are handed — to the scheduler TaskId that TaskId-keyed per-task
/// state (fd table, comm, argv, exe, cwd, root, environ/auxv) is stored under.
/// Identity when `pid` is not a registered process id (already a TaskId, a
/// thread tid, or a bare number). ProcessId-keyed tables (PARENT_OF,
/// thread-group counts, brk) use the ProcessId directly and must NOT go through
/// this. Mirrors the `tid = pid_to_task_raw(pid)` step in `proc_task_info`.
#[inline]
pub(crate) fn proc_pid_to_tid(pid: u64) -> u64 {
    pid_to_task_raw(pid).unwrap_or(pid)
}

/// PROCESS-scoped exit observer: per-`pid` reap that runs EXACTLY ONCE,
/// on the group's last thread (`group_dead`). Notifies pidfd watchers,
/// and hands the zombie process to its parent
/// (wait4 reap entry + SIGCHLD + waker) — or, if orphaned, releases the
/// task and returns the PID. Running this per thread double-freed the
/// PID pool and the parent's reap queue (the OCI teardown #UD).
fn on_child_exit(child_pid: u64, child_tid: u64) {
    // `child_tid` is consumed only by the cgroup-gated PIDFD-EXIT probe
    // below; keep it live for the no-cgroup build.
    #[cfg(not(feature = "cgroup"))]
    let _ = child_tid;
    // Capture ptrace routing before release_process removes the tracee row.
    // Linux reports a traced zombie to its tracer first, irrespective of its
    // clone-child exit-signal class.
    let natural_link = child_link_get(child_pid);
    let ptraced = crate::ptrace::is_task_traced(child_pid);
    let wait_recipient = get_wait_recipient(child_pid);
    // Namespace and pid↔task cleanup is deferred to release_reaped_task so a
    // zombie's inner PID remains resolvable until wait4/waitid consumes it.
    crate::ptrace::release_process(child_pid);

    // Wave-61: notify any pidfd_open()'d watchers that the target
    // exited, regardless of whether a parent reaps it.
    let _pidfd_found = crate::pidfd::notify_exit(child_pid);
    // Diagnostic: does the exiting process's pid match a minted pidfd? A
    // `pidfd_found=false` for a comm that systemd pidfd_spawn'd (e.g.
    // systemd-user-ru) means the pidfd was minted under a DIFFERENT pid than
    // the one the exit path reports — so its POLLIN-on-exit never fires and
    // systemd supervises a ghost (start job hangs "running"). Pair with the
    // PIDFD-MINT line at the CLONE_PIDFD site.
    #[cfg(feature = "cgroup")]
    if narf_filesystem::cgroupfs::cgevt_trace_enabled() {
        use core::fmt::Write as _;
        let comm = proc_comm_of_task(child_tid).unwrap_or_else(|| alloc::string::String::from("?"));
        let _ = writeln!(
            narf_console::Writer,
            "PIDFD-EXIT child_pid={} child_tid={} comm={} pidfd_found={}",
            child_pid,
            child_tid,
            comm,
            _pidfd_found
        );
    }

    let parent = match wait_recipient {
        Some(p) => p,
        None => {
            // No registered parent — orphan. Drain the staged status
            // so a re-used pid doesn't see stale state, release the
            // refcounted Task, and return the PID to the pool
            // immediately since no one will reap it.
            let _ = take_pending_termination(child_pid);
            release_reaped_task(child_pid);
            crate::release_pid(crate::ProcessId(child_pid));
            return;
        }
    };
    // A ptrace recipient gets SIGCHLD and can wait on either child class.
    // Otherwise preserve the signal recorded at fork/clone publication.
    let exit_signal = if ptraced {
        SIGCHLD
    } else {
        natural_link.map_or(SIGCHLD, |link| link.exit_signal)
    };
    let status = take_pending_termination(child_pid).unwrap_or(0);
    // (1) Reap entry — for wait4.
    {
        let mut g = PENDING_EXITS.lock();
        if let Some(m) = g.as_mut() {
            m.entry(parent)
                .or_insert_with(alloc::vec::Vec::new)
                .push(PendingExit {
                    child_pid,
                    status,
                    exit_signal,
                    ptraced,
                });
        }
    }
    // (2) Deliver the clone-selected parent signal. An exit_signal of zero
    // deliberately sends no signal, while the zombie remains waitable via
    // __WCLONE. Linux do_notify_parent follows the same rule.
    if exit_signal != 0 {
        let signum = u32::from(exit_signal);
        let _ = pending_signal_bits_update(parent, |slot| *slot |= sig_bit(signum));
        const CLD_EXITED: i32 = 1;
        const CLD_KILLED: i32 = 2;
        const CLD_DUMPED: i32 = 3;
        let si_code = if status & 0x7f == 0 {
            CLD_EXITED
        } else if status & 0x80 != 0 {
            CLD_DUMPED
        } else {
            CLD_KILLED
        };
        let child_in_parent_ns = report_pid_to(parent, child_pid) as u32;
        let _ = store_sigqueue_info(parent, signum, si_code, 0, child_in_parent_ns);
        // Wake signal/signalfd waiters only after the pending bit and siginfo
        // are visible; pidfd readiness was published earlier.
        wake_signal(parent);
        narf_net::readiness::notify(0);
    }
    // (3) Wake any parent task parked in a blocking wait4.  The waker
    // was stored by `UserTaskFuture::poll` when it found the pending-
    // exits queue empty.  Now that we've pushed an entry, fire the waker
    // so the executor re-polls the parent and it can reap.
    wake_wait_child_group(parent);
}

// ── Per-task pgid table ────────────────────────────────────────────
//
// POSIX setpgid / getpgid manage process-group ids. NARF doesn't
// schedule per-process-group (no session leader semantics today),
// but consumer code (job-control shells, init systems) calls
// setpgid(0, 0) early to become a group leader and expects the
// value to round-trip across getpgid.
//
// Default pgid = pid (each task is its own group leader). Setting
// pgid = 0 in setpgid means "use the target's pid" per POSIX —
// we resolve that in the handler.

static PGID_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn pgid_init() {
    *PGID_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
pub fn __test_pgid_reset() {
    *PGID_TABLE.lock() = Some(BTreeMap::new());
    crate::task::__test_reset_process_group_ids();
}

/// Test-only: map `task` into process group `pgid` directly (bypassing
/// the setpgid syscall plumbing) so a test can assemble a multi-member
/// foreground group.
#[doc(hidden)]
pub fn __test_set_pgid(task: u64, pgid: u64) {
    let mut g = PGID_TABLE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert(task, pgid);
    crate::task::set_process_group_id(process_state_key(task), pgid);
}

fn read_pgid(target: u64) -> u64 {
    let g = PGID_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&target).copied())
        .unwrap_or(target) // default: pgid == pid
}

// ── pid-space translation at the pgid/sid/tty userspace boundary ───
//
// The kernel keeps pgid/sid/tty-foreground state in TASK-ID space
// (PGID_TABLE, SID_TABLE, console_tty::fg_pgrp are all keyed by /
// valued in TaskId). But `getpid()` reports the *visible* pid
// (task→ProcessId, then PID-namespace translation) — see `sys_getpid`.
// So when a process does `tcsetpgrp(getpid())` / `setpgid` / reads
// `getpgrp()`, the userspace value is a visible pid while the kernel
// table is a task id. Under the `container` feature those two spaces
// diverge (e.g. getty task 14 ↔ visible pid 2), and the mismatch makes
// `tty_background_access` see a foreground leader as "background" and
// SIGTTIN-stop it — which hung getty at the login read.
//
// These two helpers translate at the syscall boundary so the internal
// tables stay task-id-keyed while userspace consistently sees visible
// pids. In the non-container build the two spaces coincide and both are
// the identity (getpid returns the task id), so behaviour is unchanged.
#[cfg(feature = "container")]
pub(crate) fn pgid_to_user(task_space_id: u64) -> u64 {
    if task_space_id == 0 {
        return 0;
    }
    let outer = task_to_pid_raw(task_space_id).unwrap_or(task_space_id);
    report_pid_to(current_task_id(), outer)
}
#[cfg(not(feature = "container"))]
#[inline]
pub(crate) fn pgid_to_user(task_space_id: u64) -> u64 {
    // Non-container: visible pid == ProcessId. Translate the internal TaskId
    // table value to the visible pid (identity for tasks with no registered
    // pid, e.g. kernel-internal). Keeps the pgid/sid/tty boundary consistent
    // with getpid(), which also reports the visible ProcessId.
    if task_space_id == 0 {
        return 0;
    }
    task_to_pid_raw(task_space_id).unwrap_or(task_space_id)
}

#[cfg(feature = "container")]
pub(crate) fn pgid_from_user(user_pid: u64) -> u64 {
    if user_pid == 0 {
        return 0;
    }
    // `user_pid` is a pid/pgid in the CALLER's pid namespace (Linux resolves
    // both setpgid/getpgid/kill(-pgid)/TIOCSPGRP arguments via
    // find_task_by_vpid — a virtual lookup). The pgid/sid/tty tables key on
    // TaskId, reached through the OUTER ProcessId, so translate inner -> outer
    // FIRST. Skipping this (the old `pid_to_task_raw(inner)`) resolved an
    // in-namespace pgid to whatever ROOT-namespace process owned the same
    // number — which for job control means signalling a host process group.
    // An inner pid not bound in the caller's namespace has no valid target;
    // return 0 (matches no real task) so delivery fails safe rather than
    // aliasing a same-numbered host task.
    match accept_pid_from(current_task_id(), user_pid) {
        Some(outer) => pid_to_task_raw(outer).unwrap_or(outer),
        None => 0,
    }
}
#[cfg(not(feature = "container"))]
#[inline]
pub(crate) fn pgid_from_user(user_pid: u64) -> u64 {
    // Non-container: visible pid == ProcessId. Translate the user-supplied
    // visible pid to the internal TaskId the pgid/sid/tty tables key on
    // (identity when unregistered).
    if user_pid == 0 {
        return 0;
    }
    pid_to_task_raw(user_pid).unwrap_or(user_pid)
}

/// Process-group id of the currently-polling task. Returns the
/// task's own TaskId when no explicit `setpgid` mapping exists
/// (Linux semantics: a process's pgid defaults to its pid until
/// the process or its parent calls `setpgid`). Returns 0 only
/// when no task is currently scheduled (boot / kernel context).
pub fn current_task_pgid() -> u64 {
    if let Some(pgid) = crate::task::current_process_group_id() {
        return pgid;
    }
    let me = current_task_id();
    if me == 0 {
        return 0;
    }
    read_pgid(me)
}

// ── Per-task session-id table ──────────────────────────────────────
//
// POSIX setsid creates a new session with the caller as the
// leader. NARF doesn't model sessions for scheduling but the
// state round-trips so init/job-control consumers see the
// expected behaviour.

static SID_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn sid_init() {
    *SID_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
pub fn __test_sid_reset() {
    *SID_TABLE.lock() = Some(BTreeMap::new());
}

fn read_sid(target: u64) -> u64 {
    let g = SID_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&target).copied())
        .unwrap_or(target) // default: sid == pid
}

/// Linux `p->signal->leader` — set ONLY by `setsid()`, never by fork.
///
/// This must not go through [`read_sid`], whose `unwrap_or(target)` default
/// ("sid == pid") is a convenience for readers and cannot tell a real session
/// leader apart from a task that has simply never appeared in the table.
/// `sys_setsid` publishes an EXPLICIT `sid_rows.insert(task, task)` row, so a
/// leader is exactly "has a row, and that row names itself". Using the
/// defaulted reader here would have made `setpgid` report -EPERM for every
/// task that never called setsid — the opposite of the intended check.
fn is_session_leader(target: u64) -> bool {
    let g = SID_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&target).copied())
        .is_some_and(|sid| sid == target)
}

/// Linux `session_of_pgrp`: resolve an internal process-group id to the
/// session of one live member. The current task is checked explicitly because
/// syscall-unit fixtures need not populate the scheduler task registry.
fn session_of_pgrp(pgrp: u64) -> Option<u64> {
    let current = process_state_key(current_task_id());
    if current != 0 && read_pgid(current) == pgrp {
        return Some(read_sid(current));
    }

    let members: alloc::vec::Vec<u64> = PGID_TABLE
        .lock()
        .as_ref()
        .map(|m| {
            m.iter()
                .filter_map(|(&task, &group)| (group == pgrp).then_some(task))
                .collect()
        })
        .unwrap_or_default();
    members
        .into_iter()
        .find(|&task| crate::task::task_get(task).is_some())
        .map(read_sid)
        .or_else(|| {
            (crate::task::task_get(pgrp).is_some() && read_pgid(pgrp) == pgrp)
                .then(|| read_sid(pgrp))
        })
}

/// The session id of the current task, in the visible-pid space userspace
/// sees. Backs the `TIOCGSID` console ioctl (`tcgetsid(3)`), which getty
/// and login use to confirm they own the tty's session after `TIOCSCTTY`.
pub fn current_task_sid_user() -> u64 {
    pgid_to_user(read_sid(process_state_key(current_task_id())))
}

/// The current task's process-group id in the visible-pid space — exactly
/// what `getpgrp()` reports (see `sys_getpgrp`). Use this, never the raw
/// [`current_task_pgid`], for any value handed to userspace or compared
/// against a userspace-supplied pgrp; see the number-space note above
/// `pgid_to_user`.
pub fn current_task_pgid_user() -> u64 {
    pgid_to_user(current_task_pgid())
}

/// Child inherits the parent's process-group id (POSIX fork semantics).
/// Without this a forked child defaults to pgid == its own pid, which
/// would place a shell-launched foreground job in a *different* group than
/// the terminal's foreground pgrp and spuriously trip SIGTTIN on its first
/// console read. A job-control shell still moves the child into a new
/// group explicitly via setpgid.
pub fn pgid_fork(parent: u64, child: u64) {
    // Keep the authoritative index and the child's lock-free cache coherent
    // under the same writer lock. The child is registered but not runnable,
    // so it cannot observe the pre-inheritance default.
    let mut pgids = PGID_TABLE.lock();
    let pg = pgids
        .as_ref()
        .and_then(|m| m.get(&parent).copied())
        .unwrap_or(parent);
    crate::task::inherit_process_group_id(parent, child, pg);
    pgids.get_or_insert_with(BTreeMap::new).insert(child, pg);
}

/// Child inherits the parent's session id (POSIX fork semantics).
pub fn sid_fork(parent: u64, child: u64) {
    let sid = read_sid(parent);
    if let Some(m) = SID_TABLE.lock().as_mut() {
        m.insert(child, sid);
    }
}

// ── Per-task controlling-tty table (Wave-76) ───────────────────────
//
// `TIOCSCTTY` on a PTY slave records the slave's PTY index here.
// `setsid()` clears the slot (a new session has no controlling tty).
// Close-of-master would normally deliver SIGHUP to every task in
// the slave's session; that wiring is deferred — the slot is read
// only by the controlling-tty smoke test for now.

static CTTY_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// CTTY_TABLE sentinel: the boot console (`/dev/console`). Equals
/// `narf_filesystem::TTY_ID_CONSOLE` so a task's ctty value can be
/// compared directly against a FileOps `tty_id()`. PTY entries store the
/// small `/dev/pts/<N>` index, which never collides with this.
pub const CTTY_CONSOLE: u32 = narf_filesystem::TTY_ID_CONSOLE;

/// CTTY_TABLE sentinel: explicitly no controlling tty (a session leader
/// detached via setsid). Distinct from an absent entry, which means "the
/// boot-console default".
pub const CTTY_DETACHED: u32 = 0xFFFF_FFFF;

/// The controlling terminal of `task`, resolved against the boot default:
/// absent → the boot console (every task starts attached to it);
/// `CTTY_DETACHED` → none (setsid'd, not yet re-acquired); `CTTY_CONSOLE`
/// → the console; any other value → that PTY index. `None` means the task
/// has no controlling terminal.
pub fn task_ctty(task: u64) -> Option<u32> {
    let task = process_state_key(task);
    match CTTY_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
    {
        None => Some(CTTY_CONSOLE),
        Some(CTTY_DETACHED) => None,
        Some(v) => Some(v),
    }
}

/// Record the boot console as `task`'s controlling terminal — the console
/// `TIOCSCTTY` path (mirrors `set_controlling_tty` for PTY slaves).
pub fn set_controlling_tty_console(task: u64) {
    let task = process_state_key(task);
    if let Some(m) = CTTY_TABLE.lock().as_mut() {
        m.insert(task, CTTY_CONSOLE);
    }
}

/// Detach `task` from its controlling terminal — the `TIOCNOTTY` path.
/// Marks the slot `CTTY_DETACHED` (a distinct state from the boot-console
/// default) so `task_ctty` resolves to "no controlling terminal", matching
/// what `setsid()` does. A subsequent `open` without `O_NOCTTY` or an
/// explicit `TIOCSCTTY` re-acquires one.
pub fn detach_controlling_tty(task: u64) {
    let task = process_state_key(task);
    if let Some(m) = CTTY_TABLE.lock().as_mut() {
        m.insert(task, CTTY_DETACHED);
    }
}

/// Child inherits the parent's controlling terminal (POSIX fork). Only an
/// explicit entry needs copying — absence already resolves to the console
/// default for both parent and child.
pub fn ctty_fork(parent: u64, child: u64) {
    let parent = process_state_key(parent);
    let child = process_state_key(child);
    let raw = CTTY_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&parent).copied());
    if let Some(v) = raw {
        if let Some(m) = CTTY_TABLE.lock().as_mut() {
            m.insert(child, v);
        }
    }
}

pub fn ctty_init() {
    *CTTY_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
pub fn __test_ctty_reset() {
    *CTTY_TABLE.lock() = Some(BTreeMap::new());
}

/// Look up the controlling tty for `task`. Returns the PTY index or
/// `None` if the task has no controlling tty.
pub fn ctty_for(task: u64) -> Option<u32> {
    let task = process_state_key(task);
    CTTY_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
}

/// Hook installed by `bare_main` so `PtySlave::ioctl(TIOCSCTTY)` can validate
/// and record the caller's controlling tty without depending on this crate.
///
/// `tty_sid` is the tty's current owning session in internal task-id space and
/// `arg` is the Linux TIOCSCTTY argument. Linux permits acquisition only by a
/// session leader without a controlling tty. Repeating the operation for the
/// leader of the tty's existing session succeeds. Stealing another session's
/// tty requires `arg == 1` and trusted `CAP_SYS_ADMIN`; NARF currently exposes
/// no ambient trusted POSIX capability, so that branch is denied with EPERM.
///
/// The returned session and process-group IDs remain in task-id space. The
/// querying syscall translates them into its caller's PID namespace, matching
/// Linux's `pid_vnr()` at query time rather than acquisition time.
pub fn set_controlling_tty(
    pty_index: u32,
    tty_sid: u64,
    arg: usize,
    readable: bool,
) -> Result<(u64, u64), narf_filesystem::FsError> {
    let task = process_state_key(current_task_id());
    let sid = read_sid(task);
    let pgid = read_pgid(task);
    let session_leader = sid == task;

    // Linux checks this idempotent case before rejecting a leader that
    // already has a controlling terminal.
    if session_leader && tty_sid == sid {
        if let Some(m) = CTTY_TABLE.lock().as_mut() {
            m.insert(task, pty_index);
        }
        return Ok((sid, pgid));
    }

    if !session_leader || task_ctty(task).is_some() {
        return Err(narf_filesystem::FsError::OperationNotPermitted);
    }

    if tty_sid != 0 {
        // `arg == 1` is necessary but not sufficient: Linux also requires
        // CAP_SYS_ADMIN. The emulated capget/capset masks are explicitly not
        // trusted authority, so no NARF caller can currently steal a tty.
        let _ = arg;
        return Err(narf_filesystem::FsError::OperationNotPermitted);
    }

    // Linux performs this after the session/ownership checks. There is no
    // authenticated CAP_SYS_ADMIN bridge to bypass FMODE_READ in NARF.
    if !readable {
        return Err(narf_filesystem::FsError::OperationNotPermitted);
    }

    if let Some(m) = CTTY_TABLE.lock().as_mut() {
        m.insert(task, pty_index);
    }
    Ok((sid, pgid))
}

/// `TIOCSCTTY`-on-console hook (installed in `boot_init`): record the boot
/// console as the calling task's controlling terminal.
fn console_tiocsctty() {
    set_controlling_tty_console(current_task_id());
}

/// `TIOCNOTTY`-on-console hook: detach the calling task's controlling tty.
fn console_tiocnotty() {
    detach_controlling_tty(current_task_id());
}

/// `TIOCGSID`-on-console hook: the caller's session id (visible-pid space).
fn console_tiocgsid() -> u64 {
    current_task_sid_user()
}

// ── Per-task uid/gid table ─────────────────────────────────────────
//
// NARF's authority model is capabilities, not POSIX uids — but
// real C programs (libstdc++, glibc init paths, some test
// fixtures) check uid/gid early and refuse to run as root, or
// require a specific gid before opening a privileged code path.
// We honour the POSIX surface so those programs behave; the
// values are kernel-side state with no security implication
// (capabilities still gate everything that matters).
//
// Storage is sharded by task ID so unrelated processes do not serialize
// credential reads on the open/stat/access hot paths.
// Default identity is (uid=0, gid=0) — matches what the prior
// noop_ok stubs returned, so consumers that didn't touch
// setuid/setgid see no change.

#[derive(Copy, Clone, Default, PartialEq, Eq)]
struct UidGid {
    /// Real uid/gid.
    uid: u32,
    gid: u32,
    /// Effective uid/gid (geteuid/getegid).
    euid: u32,
    egid: u32,
    /// Saved set-user-ID / set-group-ID (`struct cred`'s `suid`/`sgid`).
    ///
    /// This is not bookkeeping for `getresuid` alone — it is an INPUT to
    /// the permission rule. `kernel/sys.c::__sys_setuid` lets a caller
    /// WITHOUT CAP_SETUID switch only to `old->uid` or `new->suid`, which
    /// is precisely how a set-uid program drops privilege and later
    /// regains it. Reporting the effective id in this slot (the previous
    /// behaviour) made that rule unstatable.
    suid: u32,
    sgid: u32,
    /// Filesystem uid/gid (setfsuid/setfsgid). Tracks the effective id
    /// unless overridden by setfs*id.
    fsuid: u32,
    fsgid: u32,
}

const CREDENTIAL_SHARDS: usize = 32;

#[repr(align(64))]
struct CredentialShard {
    uidgid: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, UidGid>>>,
    groups:
        narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, alloc::vec::Vec<u32>>>>,
}

impl CredentialShard {
    const fn new() -> Self {
        Self {
            uidgid: narf_lib::sync::IrqSafeSpinLock::new(None),
            groups: narf_lib::sync::IrqSafeSpinLock::new(None),
        }
    }
}

static CREDENTIAL_TABLES: [CredentialShard; CREDENTIAL_SHARDS] =
    [const { CredentialShard::new() }; CREDENTIAL_SHARDS];

#[inline]
fn credential_shard(task: u64) -> usize {
    (task as usize) & (CREDENTIAL_SHARDS - 1)
}

/// Initialise the per-task uid/gid registry. Call once at boot
/// before any user task issues `setuid` / `getuid`.
pub fn uidgid_init() {
    for shard in CREDENTIAL_TABLES.iter() {
        *shard.uidgid.lock() = Some(BTreeMap::new());
        *shard.groups.lock() = Some(BTreeMap::new());
    }
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_uidgid_reset() {
    uidgid_init();
}

/// Set a task's (fsuid, fsgid) — test hook for the DAC security smoke.
#[doc(hidden)]
pub fn __test_set_fsids(task: u64, fsuid: u32, fsgid: u32) {
    let _ = write_uidgid(task, |e| {
        e.uid = fsuid;
        e.gid = fsgid;
        e.euid = fsuid;
        e.egid = fsgid;
        e.fsuid = fsuid;
        e.fsgid = fsgid;
    });
}

fn read_uidgid(task: u64) -> UidGid {
    let g = CREDENTIAL_TABLES[credential_shard(task)].uidgid.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or_default()
}

/// Whether the calling task may reach BPF at all.
///
/// Spec §4.10 is "one privilege regime": there is no unprivileged BPF mode and
/// no second set of limits, so *every* entry point that can load, attach, or
/// cause a program to run asks this one question.
///
/// It lives here rather than in `sys_bpf.rs` because `bpf(2)` is not the only
/// such entry point — `PERF_EVENT_IOC_SET_BPF` installs a program on a perf
/// event and the drain then runs it — and a gate that each entry point restates
/// for itself is a gate one of them will forget. `perf_event_open` needs no
/// credential of its own, so this is where the regime is enforced for that path.
pub(crate) fn task_may_use_bpf() -> bool {
    read_uidgid(current_task_id()).euid == 0
}

/// Filesystem identity used when creating Linux-visible inodes outside the
/// generic open path (notably POSIX message queues).
pub(crate) fn current_fs_ids() -> (u32, u32) {
    let ids = read_uidgid(current_task_id());
    (ids.fsuid, ids.fsgid)
}

/// Filesystem identity for a new pseudoterminal slave node, installed as
/// `narf_filesystem::devfs_pty`'s credentials hook.
///
/// Linux stamps `current_fsuid()`/`current_fsgid()` on the `/dev/pts/<N>`
/// inode when `/dev/ptmx` is opened (`fs/devpts/inode.c::devpts_pty_new`),
/// and the node is mode 0620 — so these are what let a non-root session
/// open its own terminal.
pub fn pty_open_fs_ids() -> (u32, u32) {
    let ids = read_uidgid(current_task_id());
    (ids.fsuid, ids.fsgid)
}

/// The calling task's socket credentials (`struct ucred` shape): its
/// visible pid plus effective uid/gid. Stamped onto every socket end at
/// creation so `SO_PEERCRED` / `SCM_CREDENTIALS` report a real identity.
pub fn current_ucred() -> crate::socket::Ucred {
    let task = current_task_id();
    let ids = read_uidgid(task);
    #[cfg(feature = "container")]
    let (uid, gid) = {
        let ns = crate::namespaces::current_user_ns(task);
        if ns.is_initial() {
            (ids.euid, ids.egid)
        } else {
            (
                ns.translate_uid_to_host(ids.euid),
                ns.translate_gid_to_host(ids.egid),
            )
        }
    };
    #[cfg(not(feature = "container"))]
    let (uid, gid) = (ids.euid, ids.egid);
    crate::socket::Ucred {
        pid: task_to_pid_raw(task).unwrap_or(task) as u32,
        uid,
        gid,
    }
}

/// Calling task's supplementary groups in host-absolute form, suitable for
/// capture in a Unix socket peer-credential snapshot.
pub fn current_groups() -> alloc::vec::Vec<u32> {
    let task = current_task_id();
    let groups = read_groups(task);
    #[cfg(feature = "container")]
    {
        let ns = crate::namespaces::current_user_ns(task);
        if !ns.is_initial() {
            return groups
                .into_iter()
                .map(|gid| ns.translate_gid_to_host(gid))
                .collect();
        }
    }
    groups
}

/// Translate host-absolute supplementary groups into the reader's user
/// namespace. Groups not mapped into that namespace are omitted, matching
/// Linux's peer-group visibility rules without aliasing them to overflow IDs.
pub fn report_groups_to(_reader: u64, groups: &[u32]) -> alloc::vec::Vec<u32> {
    #[cfg(feature = "container")]
    {
        let ns = crate::namespaces::current_user_ns(_reader);
        if !ns.is_initial() {
            return groups
                .iter()
                .filter_map(|gid| ns.translate_gid_from_host(*gid))
                .collect();
        }
    }
    groups.to_vec()
}

/// Translate host-absolute socket credentials into `reader`'s PID and user
/// namespace views. Unmapped uid/gid values surface as the Linux overflow id
/// instead of aliasing a privileged in-namespace identity.
pub fn report_ucred_to(reader: u64, mut cred: crate::socket::Ucred) -> crate::socket::Ucred {
    cred.pid = report_pid_to(reader, cred.pid as u64) as u32;
    #[cfg(feature = "container")]
    {
        let ns = crate::namespaces::current_user_ns(reader);
        if !ns.is_initial() {
            cred.uid = ns
                .translate_uid_from_host(cred.uid)
                .unwrap_or(crate::namespaces::OVERFLOW_ID);
            cred.gid = ns
                .translate_gid_from_host(cred.gid)
                .unwrap_or(crate::namespaces::OVERFLOW_ID);
        }
    }
    cred
}

/// SECURITY-CRITICAL single funnel for every filesystem `Accessor`.
///
/// `posix_access_ok` treats `uid == 0` as omnipotent host-root. With
/// user namespaces, a task's stored fsuid/fsgid are *in-namespace*
/// ids: inner uid 0 is host-root ONLY if the user-ns maps inner-0 to
/// host-0. So before the FS sees the accessor we translate the task's
/// in-ns fsuid/fsgid to HOST-absolute ids through its user-ns map. An
/// unmapped id becomes the overflow id (65534), which owns nothing —
/// the safe default. File owners are kept host-absolute everywhere, so
/// this is the only translation needed.
///
/// EVERY production code path that builds a `narf_filesystem::Accessor`
/// for a real syscall MUST go through here. (Verified by grep: the
/// open path is the sole call site; the only other `Accessor {…}`
/// literals are in `tests.rs`.)
/// NOTE: the DAC capability flags this returns are NOT safe to pair with
/// an arbitrary inode — see [`accessor_for_inode`], which clears them for
/// a file whose owners are unmapped in the caller's user namespace. Use
/// this directly only when no inode is involved (e.g. building a FUSE
/// request context, which needs the ids alone).
fn current_accessor(task: u64) -> narf_filesystem::Accessor {
    let acc = read_uidgid(task);
    // Supplementary groups are part of the identity, not an extra. Linux's
    // group triplet test is in_group_p(), which matches the fsgid OR any
    // group from setgroups(2). Dropping them here demotes the process to the
    // "other" triplet for every file owned by a group it holds only
    // supplementarily — which is precisely how kwin lost /dev/dri/card0
    // (crw-rw---- root:video) despite narf being in `video`, and with it the
    // whole Plasma session.
    let groups = read_groups(task);
    // One immutable credential snapshot answers both DAC capability bits.
    // Besides avoiding duplicate registry/PID-translation walks on every
    // open, this makes the pair coherent if another thread changes the
    // process credential concurrently.
    let effective_caps = read_caps(task).effective;
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial() {
            // File owners are host-absolute, so the supplementary list has to
            // be translated exactly like fsgid or it would compare in-ns ids
            // against host ids and match by coincidence.
            return narf_filesystem::Accessor {
                uid: uns.translate_uid_to_host(acc.fsuid),
                gid: uns.translate_gid_to_host(acc.fsgid),
                groups: groups
                    .iter()
                    .map(|g| uns.translate_gid_to_host(*g))
                    .collect(),
                // A task in a non-initial user namespace has no authority
                // over host-owned inodes, irrespective of its in-namespace
                // effective capability set.
                dac_override: false,
                dac_read_search: false,
            };
        }
    }
    // Root (host) user-ns, or container feature off: identity.
    narf_filesystem::Accessor {
        uid: acc.fsuid,
        gid: acc.fsgid,
        groups,
        // The DAC overrides come from the EFFECTIVE capability set, not
        // from `uid == 0`. Those are different questions: a uid-0 service
        // that dropped CAP_DAC_OVERRIDE to sandbox itself was still
        // omnipotent under the old test, and a non-root task granted the
        // capability was still locked out.
        dac_override: effective_caps & (1u64 << CAP_DAC_OVERRIDE) != 0,
        dac_read_search: effective_caps & (1u64 << CAP_DAC_READ_SEARCH) != 0,
    }
}

/// Calling task's fsuid in the host inode-id space, without materialising the
/// supplementary groups or capability snapshot needed only by a full DAC
/// decision. This is the Linux owner-first `acl_permission_check` fast path.
fn current_host_fsuid(task: u64) -> u32 {
    let fsuid = read_uidgid(task).fsuid;
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if uns.is_initial() {
            fsuid
        } else {
            uns.translate_uid_to_host(fsuid)
        }
    }
    #[cfg(not(feature = "container"))]
    {
        fsuid
    }
}

fn fuse_request_context() -> narf_filesystem::fuse_conn::FuseRequestContext {
    let task = current_task_id();
    let accessor = current_accessor(task);
    narf_filesystem::fuse_conn::FuseRequestContext {
        uid: accessor.uid,
        gid: accessor.gid,
        pid: task_to_pid_raw(task).unwrap_or(task) as u32,
    }
}

/// Test-only window onto the DAC funnel so the security smoke can
/// assert the exact host-id translation `sys_open` would use.
#[cfg(feature = "container")]
#[doc(hidden)]
pub fn __test_current_accessor(task: u64) -> narf_filesystem::Accessor {
    current_accessor(task)
}

/// Copy the parent's credential entry (uid/gid/euid/egid/fsuid/fsgid)
/// to the child on fork/clone. Mirrors [`cwd_fork`]. If the parent has
/// no explicit entry it is the default (all zero = root), so the child
/// also defaults to root and we can skip the insert. This makes a
/// dropped uid survive fork while leaving root parents as root.
pub fn uidgid_fork(parent: u64, child: u64) {
    let uidgid = read_uidgid(parent);
    if uidgid != UidGid::default() {
        let _ = write_uidgid(child, |entry| *entry = uidgid);
    }
    let groups = read_groups(parent);
    if !groups.is_empty() {
        let _ = write_groups(child, groups);
    }
}

// ── DAC: path-walk search permission ───────────────────────────────
//
// `narf_filesystem::posix_access_ok` is the discretionary check on a
// single inode, and `sys_open` / `access(2)` already use it. What was
// missing is Linux's check on the PATH: `link_path_walk` requires
// MAY_EXEC (search) on every directory it traverses, which is what makes
// a 0700 directory actually hide its contents from other users. Without
// it, a caller who could not open the directory could still stat straight
// through it to a file inside.

/// Does `task` hold search (MAY_EXEC) permission on the directory at
/// `path`? Built on the same `posix_access_ok` the open path uses, so
/// there is one DAC algorithm in the tree rather than two.
/// `kernel/capability.c::capable_wrt_inode_uidgid` — a DAC override
/// applies only to an inode whose owners are MAPPED in the caller's user
/// namespace:
///
/// ```text
/// return ns_capable(ns, cap) && privileged_wrt_inode_uidgid(ns, idmap, inode);
/// /* ... which is kuid_has_mapping(ns, i_uid) && kgid_has_mapping(ns, i_gid) */
/// ```
///
/// This is not a refinement, it is the whole containment property. A task
/// that is root INSIDE a user namespace holds the full capability set
/// there; without the mapping test that capability would also override DAC
/// on HOST files the namespace has no view of, and unprivileged user
/// namespaces would be a way to read /etc/shadow. The previous `uid == 0`
/// check got this right by accident, because an unmapped in-ns root
/// translates to OVERFLOW_ID rather than 0.
fn accessor_for_inode(task: u64, file_uid: u32, file_gid: u32) -> narf_filesystem::Accessor {
    #[allow(unused_mut)]
    let mut acc = current_accessor(task);
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial()
            && (uns.translate_uid_from_host(file_uid).is_none()
                || uns.translate_gid_from_host(file_gid).is_none())
        {
            acc.dac_override = false;
            acc.dac_read_search = false;
        }
    }
    let _ = (file_uid, file_gid);
    acc
}

/// Test hook for [`accessor_for_inode`] — the per-inode form is the only
/// safe one, so tests must exercise it rather than pairing a bare
/// `current_accessor` with an arbitrary file.
#[doc(hidden)]
pub fn __test_accessor_for_inode(
    task: u64,
    file_uid: u32,
    file_gid: u32,
) -> narf_filesystem::Accessor {
    accessor_for_inode(task, file_uid, file_gid)
}

// ── fs/namei.c: may_create / may_delete ──────────────────────────────
//
// Linux runs a permission check on the PARENT DIRECTORY before any
// namespace-changing operation, and nothing here did: `unlink`, `rmdir`,
// `rename`, `link`, `symlink` and `mknod` all went straight to the
// filesystem. On a world-writable directory that is the whole of `/tmp`'s
// security model — the sticky bit exists precisely so one user cannot
// delete another's file there, and without the check it had no effect at
// all.

/// Linux `CAP_FOWNER` — "bypass permission checks on operations that
/// normally require the filesystem UID of the process to match the UID of
/// the file".
pub(crate) const CAP_FOWNER: u32 = 3;

/// `inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC)` on a parent
/// directory, ACL included.
fn dir_write_permitted(dir: &dyn narf_filesystem::DirOps, task: u64) -> bool {
    let (uid, gid) = dir.dir_owners();
    // Mode-only fast path, for the same reason `open` has
    // `current_host_fsuid`: this now runs on every create and every
    // delete, and the full decision materialises a supplementary-group
    // list and a capability snapshot that the common case never needs.
    //
    // It can only ever GRANT — anything it cannot settle falls through to
    // the full check — and it mirrors `acl_permission_check`'s structure
    // exactly, including the rule that makes each triplet EXCLUSIVE:
    //
    //   * the caller IS the owner: the user triplet alone decides, so
    //     user-wx is a grant (and user-deny still has to fall through,
    //     because CAP_DAC_OVERRIDE may yet allow it);
    //   * the caller is NOT the owner: whichever of group/other applies,
    //     both granting wx means the answer is yes either way — which is
    //     the 0777 and 01777 directories that most creates land in.
    //
    // Only taken when the directory can cheaply say it has no ACL; an ACL
    // replaces the group triplet, so the shortcut would not be sound.
    if dir.access_acl_present() == Some(false) {
        let mode = dir.dir_mode();
        if current_host_fsuid(task) == uid {
            if mode & 0o300 == 0o300 {
                return true;
            }
        } else if mode & 0o033 == 0o033 {
            return true;
        }
    }
    // A directory's ACL is the case that matters most here: `setfacl -m
    // g:staff:rwx /srv/shared` is how a shared directory is built, and
    // checking the mode alone would refuse every member of that group.
    let acl = match poll_blocking(narf_filesystem::acl_of_dir(
        dir,
        narf_filesystem::AclType::Access,
    )) {
        Some(Ok(acl)) => acl,
        // `check_acl` propagates a decode failure rather than falling back
        // to the mode bits; refusing is the safe reading of the same rule.
        Some(Err(_)) => return false,
        None => None,
    };
    narf_filesystem::posix_access_ok_with_acl(
        narf_filesystem::FileOwner {
            uid,
            gid,
            perms: dir.dir_mode(),
            is_dir: true,
        },
        &accessor_for_inode(task, uid, gid),
        narf_filesystem::AccessRequest {
            read: false,
            write: true,
            exec: true,
        },
        acl.as_ref(),
    )
}

/// `fs/namei.c::may_create` — the check every create-like operation makes
/// on the directory it is about to add a name to:
///
/// ```text
/// return inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC);
/// ```
///
/// -EACCES when it fails.
pub(crate) fn may_create_in(dir: &dyn narf_filesystem::DirOps, task: u64) -> Result<(), i64> {
    if dir_write_permitted(dir, task) {
        Ok(())
    } else {
        Err(-13) // -EACCES
    }
}

/// `capable_wrt_inode_uidgid(idmap, inode, cap)` — the capability must be
/// held in a user namespace that maps the inode's owner, so a namespaced
/// root cannot use it to reach an inode owned outside its namespace.
fn capable_wrt_inode(task: u64, file_uid: u32, file_gid: u32, cap: u32) -> bool {
    if !task_capable(task, cap) {
        return false;
    }
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial()
            && (uns.translate_uid_from_host(file_uid).is_none()
                || uns.translate_gid_from_host(file_gid).is_none())
        {
            return false;
        }
    }
    let _ = (file_uid, file_gid);
    true
}

/// `fs/namei.c::__check_sticky`:
///
/// ```text
/// if (vfsuid_eq_kuid(i_uid_into_vfsuid(idmap, inode), fsuid)) return 0;
/// if (vfsuid_eq_kuid(i_uid_into_vfsuid(idmap, dir), fsuid)) return 0;
/// return !capable_wrt_inode_uidgid(idmap, inode, CAP_FOWNER);
/// ```
///
/// Only consulted when the directory carries `S_ISVTX`. `/tmp` is 01777,
/// so this is the rule that stops one user removing another's file there;
/// the owner of the directory and the owner of the victim may both do it,
/// and so may CAP_FOWNER.
fn sticky_permits_removal(dir_uid: u32, victim_uid: u32, victim_gid: u32, task: u64) -> bool {
    let fsuid = read_uidgid(task).fsuid;
    if victim_uid == fsuid || dir_uid == fsuid {
        return true;
    }
    capable_wrt_inode(task, victim_uid, victim_gid, CAP_FOWNER)
}

/// `fs/namei.c::may_delete` — what `unlink`, `rmdir` and the destination
/// side of `rename` require before a name can be removed from `dir`:
/// write+exec on the directory, plus the sticky rule when `S_ISVTX` is set.
///
/// The two failures are deliberately different errnos, as Linux's are: the
/// permission check is -EACCES, the sticky refusal is -EPERM.
pub(crate) fn may_delete_in(
    dir: &dyn narf_filesystem::DirOps,
    victim_uid: u32,
    victim_gid: u32,
    task: u64,
) -> Result<(), i64> {
    may_create_in(dir, task)?;
    let (dir_uid, _) = dir.dir_owners();
    if dir.dir_mode() & 0o1000 != 0 && !sticky_permits_removal(dir_uid, victim_uid, victim_gid, task)
    {
        return Err(-1); // -EPERM
    }
    Ok(())
}

/// The owner of the name `leaf` inside `dir`, for [`may_delete_in`].
///
/// A name that resolves to nothing yields `None`; the caller then reports
/// the ENOENT it would have reported anyway rather than inventing a
/// permission answer about a victim that does not exist.
pub(crate) fn entry_owner(dir: &dyn narf_filesystem::DirOps, leaf: &str) -> Option<(u32, u32)> {
    if let Some(file) = dir.lookup(leaf) {
        return Some(file.owners());
    }
    if let Some(sub) = dir.lookup_dir(leaf) {
        return Some(sub.dir_owners());
    }
    poll_blocking(dir.lookup_async(leaf))
        .and_then(|r| r.ok())
        .map(|file| file.owners())
}

/// [`may_create_in`] for a path whose parent has not been resolved yet.
///
/// A parent that does not resolve is left to the caller: it reports the
/// ENOENT it would have reported anyway, rather than inventing a
/// permission answer about a directory that is not there.
pub(crate) fn check_may_create(path: &str) -> Result<(), i64> {
    let task = current_task_id();
    current_resolve_parent_absolute(path, |_fs, parent, _leaf| may_create_in(&*parent, task))
        .unwrap_or(Ok(()))
}

fn dir_search_permitted(path: &str, task: u64) -> bool {
    let Some(dir) = resolve_dir_absolute(path) else {
        // Nothing to search; the caller reports ENOENT/ENOTDIR itself.
        return true;
    };
    let (uid, gid) = dir.dir_owners();
    narf_filesystem::posix_access_ok(
        narf_filesystem::FileOwner {
            uid,
            gid,
            perms: dir.dir_mode(),
            is_dir: true,
        },
        &accessor_for_inode(task, uid, gid),
        narf_filesystem::AccessRequest {
            read: false,
            write: false,
            exec: true,
        },
    )
}

pub(crate) fn read_groups(task: u64) -> alloc::vec::Vec<u32> {
    CREDENTIAL_TABLES[credential_shard(task)]
        .groups
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).cloned())
        .unwrap_or_default()
}

pub(crate) fn write_groups(task: u64, groups: alloc::vec::Vec<u32>) -> bool {
    let mut table = CREDENTIAL_TABLES[credential_shard(task)].groups.lock();
    let Some(map) = table.as_mut() else {
        return false;
    };
    if groups.is_empty() {
        map.remove(&task);
    } else {
        map.insert(task, groups);
    }
    true
}

fn write_uidgid<F: FnOnce(&mut UidGid)>(task: u64, f: F) -> bool {
    let mut g = CREDENTIAL_TABLES[credential_shard(task)].uidgid.lock();
    let Some(m) = g.as_mut() else {
        return false;
    };
    let entry = m.entry(task).or_default();
    f(entry);
    true
}

/// Write `val` into each of the (up to three) user `u32` out-pointers
/// `p0/p1/p2`, skipping NULLs. Returns 0 on success, -1 (EFAULT shape)
/// if any copy_to_user fails. Shared by getresuid / getresgid.
fn write_res_ids(ctx: &mut dyn TrapContext, p0: u64, p1: u64, p2: u64, vals: [u32; 3]) {
    for (p, val) in [p0, p1, p2].into_iter().zip(vals) {
        let buf = val.to_ne_bytes();
        if p != 0 {
            // SAFETY: `p` is a user `uid_t*`/`gid_t*` out-pointer;
            // copy_to_user range-validates the 4-byte write.
            if unsafe { copy_to_user(p, &buf) }.is_err() {
                // `kernel/sys.c::SYSCALL_DEFINE3(getresuid)` is three chained
                // `put_user`s and returns their result, so an unwritable
                // out-pointer is -EFAULT. The sentinel said EPERM, which for
                // a credential query reads as "you may not ask" rather than
                // "your pointer is bad".
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
                return;
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Per-process rlimit table ───────────────────────────────────────
//
// POSIX getrlimit / setrlimit query and update per-resource soft
// (`rlim_cur`) and hard (`rlim_max`) limits, stored per task. Most limits
// are structural state that round-trips through get/setrlimit; RLIMIT_NOFILE
// is additionally enforced — the open path returns EMFILE once a task holds
// its soft limit of descriptors. (Other authority is capability-based, and
// task resource budgets live in the scheduler's BudgetAccount path.)
//
// Defaults match what real Linux distros surface to a normal user:
//   RLIMIT_CPU     = INFINITY
//   RLIMIT_FSIZE   = INFINITY
//   RLIMIT_DATA    = INFINITY
//   RLIMIT_STACK   = (8 MiB cur, INFINITY max)
//   RLIMIT_CORE    = (0 cur, INFINITY max)
//   RLIMIT_NOFILE  = (1024 cur, 4096 max)
//   RLIMIT_AS      = INFINITY

const RLIMIT_COUNT: usize = 16;

/// `RLIMIT_NOFILE` — the resource index the descriptor-allocation bound comes
/// from. Named because it is consulted from several syscalls that each used a
/// bare `7`.
const RLIMIT_NOFILE_RESOURCE: usize = 7;

/// Wire-shape pair: rlim_cur followed by rlim_max. Matches the
/// glibc layout the libc shim already exposes.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct RLimitPair {
    cur: u64,
    max: u64,
}

const RLIM_INFINITY: u64 = !0;

fn default_rlimits() -> [RLimitPair; RLIMIT_COUNT] {
    let mut t = [RLimitPair {
        cur: RLIM_INFINITY,
        max: RLIM_INFINITY,
    }; RLIMIT_COUNT];
    // RLIMIT_STACK = 3.
    t[3] = RLimitPair {
        cur: 8 * 1024 * 1024,
        max: RLIM_INFINITY,
    };
    // RLIMIT_NICE = 13. Linux's default is 0, NOT infinity
    // (`include/asm-generic/resource.h`: `[RLIMIT_NICE] = { 0, 0 }`), and
    // the value is a CEILING ON PRIVILEGE, not on consumption: `can_nice`
    // permits a nice REDUCTION only while `20 - nice <= RLIMIT_NICE`, so a
    // limit of 0 means "may not lower nice at all without CAP_SYS_NICE".
    //
    // Defaulting it to infinity let any task renice itself to -20 and made
    // setpriority's -EACCES arm unreachable by construction — the same
    // everything-is-privileged shape as the capability gaps this branch
    // closes, wearing an rlimit's clothes.
    t[13] = RLimitPair { cur: 0, max: 0 };
    // RLIMIT_CORE = 4.
    t[4] = RLimitPair {
        cur: 0,
        max: RLIM_INFINITY,
    };
    // RLIMIT_NOFILE = 7. Soft 1024 / hard 4096, matching a typical Linux
    // default; the soft limit is enforced by the open path (EMFILE) and a
    // process raises it via setrlimit up to the hard cap.
    t[7] = RLimitPair {
        cur: 1024,
        max: 4096,
    };
    // Linux INIT_RLIMITS uses MLOCK_LIMIT (8 MiB) for both soft and hard
    // RLIMIT_MEMLOCK. Keeping infinity here made all new admission paths
    // vacuous until a process explicitly lowered its own limit.
    t[8] = RLimitPair {
        cur: 8 * 1024 * 1024,
        max: 8 * 1024 * 1024,
    };
    t
}

struct RlimitState {
    /// Rows are keyed by the monotonic thread-group leader TaskId. ProcessIds
    /// are recycled and therefore cannot safely own lifetime-bearing state.
    rows: BTreeMap<u64, [RLimitPair; RLIMIT_COUNT]>,
}

impl RlimitState {
    fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
        }
    }
}

static RLIMIT_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<RlimitState>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
static RLIMIT_CUSTOM_ROWS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub fn rlimit_init() {
    *RLIMIT_TABLE.lock() = Some(RlimitState::new());
    RLIMIT_CUSTOM_ROWS.store(0, core::sync::atomic::Ordering::Release);
}

#[doc(hidden)]
pub fn __test_rlimit_reset() {
    *RLIMIT_TABLE.lock() = Some(RlimitState::new());
    RLIMIT_CUSTOM_ROWS.store(0, core::sync::atomic::Ordering::Release);
}

/// Test-only count of every lifetime-bearing record in the rlimit store.
#[doc(hidden)]
pub fn __test_rlimit_storage_len() -> usize {
    RLIMIT_TABLE
        .lock()
        .as_ref()
        .map_or(0, |state| state.rows.len())
}

/// Resolve any thread in a group to the leader's never-reused TaskId.
fn process_state_key(task: u64) -> u64 {
    task_to_pid_raw(task)
        .and_then(pid_to_task_raw)
        .unwrap_or(task)
}

fn read_rlimit(task: u64, resource: usize) -> Option<RLimitPair> {
    if resource >= RLIMIT_COUNT {
        return None;
    }
    // Rows are sparse: an absent process has exactly `default_rlimits()`.
    // Most tasks never call setrlimit, so avoid task→pid→leader translation
    // and the global table lock while no custom row exists anywhere.
    if RLIMIT_CUSTOM_ROWS.load(core::sync::atomic::Ordering::Acquire) == 0 {
        return Some(default_rlimits()[resource]);
    }
    let key = process_state_key(task);
    let g = RLIMIT_TABLE.lock();
    let state = g.as_ref()?;
    let row = state
        .rows
        .get(&key)
        .copied()
        .unwrap_or_else(default_rlimits);
    Some(row[resource])
}

const RLIMIT_NICE: usize = 13;
const RLIMIT_DATA: usize = 2;
const RLIMIT_STACK: usize = 3;
const RLIMIT_MEMLOCK: usize = 8;
const RLIMIT_AS: usize = 9;

#[derive(Copy, Clone)]
struct MlockAuthority {
    limit_bytes: u64,
    bypass_limit: bool,
}

/// Resolve Linux prlimit's pid argument to a live task. A non-container build
/// must still reject unregistered numeric IDs rather than manufacturing a
/// default rlimit row for a phantom process.
struct PrlimitTarget {
    tid: u64,
    /// Mirrors Linux's get_task_struct reference for cross-task operations.
    /// The exact current task cannot disappear during its own syscall, and
    /// some kernel-test shims intentionally have no registered Task object.
    owner: Option<alloc::sync::Arc<crate::task::Task>>,
}

fn current_mlock_authority() -> MlockAuthority {
    let task = current_task_id();
    let limit_bytes = read_rlimit(task, RLIMIT_MEMLOCK)
        .map(|limit| limit.cur)
        .unwrap_or(0);
    // CAP_TABLE is currently an ABI round-trip store, not trusted capability
    // authority: capset may synthesize bits. Do not turn those emulated bits
    // into a memory-limit bypass. Once capability-core supplies authenticated
    // credentials this becomes its effective CAP_IPC_LOCK query.
    MlockAuthority {
        limit_bytes,
        bypass_limit: false,
    }
}

/// Current task's process-shared Linux limits for automatic stack growth in
/// the architecture trap handlers.
pub fn current_stack_growth_limits() -> narf_memory::StackGrowthLimits {
    let task = current_task_id();
    let authority = current_mlock_authority();
    let defaults = default_rlimits();
    narf_memory::StackGrowthLimits {
        stack_bytes: read_rlimit(task, RLIMIT_STACK)
            .unwrap_or(defaults[RLIMIT_STACK])
            .cur,
        memlock_bytes: authority.limit_bytes,
        address_space_bytes: read_rlimit(task, RLIMIT_AS)
            .unwrap_or(defaults[RLIMIT_AS])
            .cur,
        bypass_memlock: authority.bypass_limit,
    }
}

fn can_do_mlock(authority: MlockAuthority) -> bool {
    authority.limit_bytes != 0 || authority.bypass_limit
}

/// Atomically snapshot and optionally replace one process-shared rlimit.
/// Validation against the previous hard limit occurs under the same table
/// lock as publication, matching Linux's group-leader task lock and preventing
/// two CLONE_THREAD callers from raising a hard limit through stale snapshots.
fn update_rlimit_atomic(
    task: u64,
    owner: Option<&alloc::sync::Arc<crate::task::Task>>,
    resource: usize,
    new_value: Option<RLimitPair>,
) -> Result<RLimitPair, i64> {
    if resource >= RLIMIT_COUNT {
        return Err(22); // EINVAL
    }
    let key = process_state_key(task);
    let mut g = RLIMIT_TABLE.lock();
    let state = g.as_mut().ok_or(22i64)?;
    if let Some(owner) = owner {
        // Revalidate while holding RLIMIT_TABLE. Reap takes this lock before
        // removing the task-registry entry, so it cannot slip between this
        // check and the row transaction. This replaces the old unbounded set
        // of every TaskId ever reaped without allowing a retained Arc<Task>
        // from a raced prlimit64 to recreate the dead process's row.
        let registered = crate::task::task_get(task).ok_or(3i64)?;
        if !alloc::sync::Arc::ptr_eq(owner, &registered) {
            return Err(3); // ESRCH
        }
    }
    let prior = state
        .rows
        .get(&key)
        .copied()
        .unwrap_or_else(default_rlimits)[resource];
    if let Some(value) = new_value {
        if value.cur > value.max {
            return Err(22); // EINVAL
        }
        if value.max > prior.max {
            // No authenticated CAP_SYS_RESOURCE authority exists yet.
            return Err(1); // EPERM
        }
        let new_row = !state.rows.contains_key(&key);
        let row = state.rows.entry(key).or_insert_with(default_rlimits);
        row[resource] = value;
        if new_row {
            RLIMIT_CUSTOM_ROWS.fetch_add(1, core::sync::atomic::Ordering::Release);
        }
    }
    Ok(prior)
}

fn prlimit_target_task(caller: u64, pid: u64) -> Option<PrlimitTarget> {
    if pid == 0 {
        return Some(PrlimitTarget {
            tid: caller,
            owner: crate::task::task_get(caller),
        });
    }
    let outer = accept_pid_from(caller, pid)?;
    let task = pid_to_task_raw(outer).or_else(|| task_to_pid_raw(outer).map(|_| outer))?;
    Some(PrlimitTarget {
        tid: task,
        owner: Some(crate::task::task_get(task)?),
    })
}

/// Linux permits cross-task prlimit when the caller's real uid/gid matches all
/// of the target's real/effective/saved IDs. NARF reports saved as effective,
/// so these are the complete representable checks. Only the exact current task
/// bypasses them; same-thread-group membership alone does not. A future
/// authenticated CAP_SYS_RESOURCE query can provide the namespace bypass.
fn prlimit_permission(caller: u64, target: u64) -> bool {
    if caller == target {
        return true;
    }
    let caller_ids = read_uidgid(caller);
    let target_ids = read_uidgid(target);
    caller_ids.uid == target_ids.uid
        && caller_ids.uid == target_ids.euid
        && caller_ids.gid == target_ids.gid
        && caller_ids.gid == target_ids.egid
}

fn rlimit_fork(parent: u64, child: u64) {
    let parent_key = process_state_key(parent);
    let child_key = process_state_key(child);
    if parent_key == child_key {
        return;
    }
    let mut g = RLIMIT_TABLE.lock();
    let state = g.get_or_insert_with(RlimitState::new);
    // Absence means the complete default table, so default-only parents need
    // no child row. Preserve only an actually materialised custom snapshot.
    if let Some(inherited) = state.rows.get(&parent_key).copied() {
        if state.rows.insert(child_key, inherited).is_none() {
            RLIMIT_CUSTOM_ROWS.fetch_add(1, core::sync::atomic::Ordering::Release);
        }
    }
}

// ── prctl — per-task settings switchboard ──────────────────────────
//
// Linux prctl(2) is a swiss-army-knife for per-task knobs. We
// honour the most-reached-for subops (PR_SET_NAME / PR_GET_NAME
// for the task-name slot; PR_*_DUMPABLE and PR_*_NO_NEW_PRIVS
// as round-trip booleans). The 16-byte name limit matches Linux's
// TASK_COMM_LEN.

const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;
const PR_SET_DUMPABLE: u64 = 4;
const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;
const PR_SET_PDEATHSIG: u64 = 1;
const PR_GET_PDEATHSIG: u64 = 2;
const PR_GET_KEEPCAPS: u64 = 7;
const PR_SET_KEEPCAPS: u64 = 8;
const PR_SET_CHILD_SUBREAPER: u64 = 36;
const PR_GET_CHILD_SUBREAPER: u64 = 37;
// PR_CAP_AMBIENT reads/mutates the per-task ambient capability set. The
// operation is selected by arg_a; arg_b names the capability (0..=63)
// for RAISE/LOWER/IS_SET. NARF's authority is capability-object based,
// so the ambient set is POSIX surface state (like the uid/gid table):
// tracked so a libc consumer round-trips, not consulted for enforcement.
const PR_CAP_AMBIENT: u64 = 47;
/// PR_CAPBSET_READ / PR_CAPBSET_DROP — capability bounding set probes.
/// NARF doesn't model a bounding set (privilege = uid/gid), so READ
/// reports every valid capability as present and DROP accepts-and-
/// ignores. systemd's `capability_bounding_set_drop()` iterates all caps
/// with these; a bare -1 made every service with CapabilityBoundingSet=
/// exit 218/EXIT_CAPABILITIES.
const PR_CAPBSET_READ: u64 = 23;
const PR_CAPBSET_DROP: u64 = 24;
/// PR_GET/SET_SECUREBITS — see `PrctlState::securebits`.
const PR_SET_SECUREBITS: u64 = 28;
const PR_GET_SECUREBITS: u64 = 27;
const PR_CAP_AMBIENT_IS_SET: u64 = 1;
const PR_CAP_AMBIENT_RAISE: u64 = 2;
const PR_CAP_AMBIENT_LOWER: u64 = 3;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
// Highest capability number Linux defines today (CAP_CHECKPOINT_RESTORE
// = 40). RAISE/LOWER/IS_SET of a larger value is EINVAL.
const CAP_LAST_CAP: u64 = 40;
const TASK_COMM_LEN: usize = 16;

#[derive(Copy, Clone)]
struct PrctlState {
    name: [u8; TASK_COMM_LEN],
    dumpable: bool,
    no_new_privs: bool,
    /// PR_SET_PDEATHSIG: signal delivered to THIS task when its parent
    /// dies (0 = none). Not inherited by fork children — PRCTL_TABLE
    /// entries aren't fork-copied, which matches Linux's clear-on-fork.
    pdeathsig: u32,
    /// PR_SET_CHILD_SUBREAPER: this task volunteers to absorb the
    /// orphans of its descendants (instead of them going unreaped).
    child_subreaper: bool,
    /// Linux capability-retention compatibility state. NARF authority is
    /// capability-object based, so this round-trips for consumers such as
    /// dbus-broker but does not grant or retain NARF capabilities.
    keep_caps: bool,
    /// Ambient capability set as a bitmask (bit N ⇒ capability N raised).
    ambient_caps: u64,
    /// PR_SET_SECUREBITS value. Stored-not-enforced (NARF's privilege
    /// model is uid/gid only); PR_GET_SECUREBITS must round-trip it so
    /// systemd's executor `if (prctl(PR_GET_SECUREBITS) != secure_bits)`
    /// check sees the default 0 and skips the (privileged) SET — an
    /// unimplemented GET returned -1, forcing a doomed SET on every
    /// service start (exit 213/EXIT_SECUREBITS).
    securebits: u64,
    seccomp_mode: u32,
}

impl Default for PrctlState {
    fn default() -> Self {
        Self {
            name: [0; TASK_COMM_LEN],
            dumpable: true, // Linux default
            no_new_privs: false,
            pdeathsig: 0,
            child_subreaper: false,
            keep_caps: false,
            ambient_caps: 0, // empty ambient set at exec, per Linux
            securebits: 0,   // SECBIT_* all clear, per Linux default
            seccomp_mode: 0,
        }
    }
}

static PRCTL_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, PrctlState>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn prctl_init() {
    *PRCTL_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
pub fn __test_prctl_reset() {
    *PRCTL_TABLE.lock() = Some(BTreeMap::new());
}

fn read_prctl(task: u64) -> PrctlState {
    let g = PRCTL_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or_default()
}

fn modify_prctl<F: FnOnce(&mut PrctlState)>(task: u64, f: F) -> bool {
    let mut g = PRCTL_TABLE.lock();
    let Some(m) = g.as_mut() else {
        return false;
    };
    let entry = m.entry(task).or_default();
    f(entry);
    true
}

// ── sched_get_priority_max / min + getparam / setparam ────────────
//
// Linux exposes a small policy-shaped surface: each scheduling
// policy has a (min, max) priority range, and each task has a
// `sched_param { int sched_priority }` slot. NARF's scheduler
// uses the cap-gated CpuBudget surface for actual routing; the
// POSIX surface here is structural only — it round-trips so a
// libc consumer that asserts `sched_get_priority_min(SCHED_RR) <=
// param.sched_priority <= sched_get_priority_max(SCHED_RR)` sees
// a coherent answer.

const SCHED_OTHER: i32 = 0;
const SCHED_FIFO: i32 = 1;
const SCHED_RR: i32 = 2;
const SCHED_BATCH: i32 = 3;
const SCHED_IDLE: i32 = 5;
/// `include/uapi/linux/sched.h`. Neither policy is admissible through
/// `sched_setscheduler` (Linux routes SCHED_DEADLINE via `sched_setattr`,
/// SCHED_EXT via a loaded BPF scheduler), but both are still *recognised*
/// policy numbers for the priority-range query below.
const SCHED_DEADLINE: i32 = 6;
const SCHED_EXT: i32 = 7;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE1(sched_get_priority_max)`.
///
/// ```text
/// int ret = -EINVAL;
/// switch (policy) {
/// case SCHED_FIFO: case SCHED_RR:  ret = MAX_RT_PRIO-1; break;   /* 99 */
/// case SCHED_DEADLINE: case SCHED_NORMAL: case SCHED_BATCH:
/// case SCHED_IDLE: case SCHED_EXT: ret = 0; break;
/// }
/// return ret;
/// ```
///
/// Linux's version is a bare switch with NO capability or admission check,
/// so SCHED_DEADLINE/SCHED_EXT report a range here even though
/// `sched_setscheduler` refuses them. Reporting EINVAL for those two made
/// a libc probing the range before choosing a policy conclude the kernel
/// was too old to know the constant at all.
fn priority_max_for_policy(policy: i32) -> Option<i64> {
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE | SCHED_EXT => Some(0),
        SCHED_FIFO | SCHED_RR => Some(99),
        _ => None,
    }
}

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE1(sched_get_priority_min)` — the
/// same switch, returning 1 for the two real-time policies.
fn priority_min_for_policy(policy: i32) -> Option<i64> {
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE | SCHED_EXT => Some(0),
        SCHED_FIFO | SCHED_RR => Some(1),
        _ => None,
    }
}

// Per-task sched_param slot. Single i32 (sched_priority).
static SCHED_PARAM_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, i32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn sched_param_init() {
    *SCHED_PARAM_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
/// Test-only: seed a task's stored `sched_priority` directly.
///
/// `sched_setparam` only accepts 0 for a SCHED_OTHER task (Linux's
/// `rt_policy(policy) != (attr->sched_priority != 0)` rule), so a test that
/// needs a DISTINGUISHABLE value — to prove which task's slot was written,
/// say — cannot get one through the syscall. Seeding here keeps those
/// tests testing what they are about (pid-namespace translation) instead
/// of the priority validation.
#[doc(hidden)]
pub fn __test_set_sched_param(task: u64, val: i32) {
    let mut g = SCHED_PARAM_TABLE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert(task, val);
}

pub fn __test_sched_param_reset() {
    *SCHED_PARAM_TABLE.lock() = Some(BTreeMap::new());
}

// ── Sched_get/setaffinity — CPU bitmap ─────────────────────────────
//
// The split handlers resolve namespace-visible ProcessIds to scheduler
// TaskIds, report the live allowed∩online bitmap, and publish hard-mask
// changes to the scheduler's cooperative migration path.

// ── Getcpu — current CPU + NUMA node query ─────────────────────────
//
// Linux getcpu(2): real logical CPU + SRAT NUMA node lookup. Library
// code (libnuma, RT performance probes) queries this at startup, so
// returning the BSP unconditionally breaks placement decisions after
// a task migrates.

// ── Per-task umask ──────────────────────────────────────────────────
//
// POSIX umask(2) sets the file-creation mask: bits set in the
// mask are *cleared* in the mode passed to open(O_CREAT) /
// mkdir / etc. NARF doesn't enforce mode bits today, so the
// mask is structural state only. The round-trip is what
// consumers care about — `umask(0o077)` followed by `umask(0o022)`
// expects the second call to return the prior 0o077.

static UMASK_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn umask_init() {
    *UMASK_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
pub fn __test_umask_reset() {
    *UMASK_TABLE.lock() = Some(BTreeMap::new());
}

/// Current task's file-creation mask, including Linux's default 0022.
pub(crate) fn current_umask() -> u32 {
    UMASK_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&current_task_id()).copied())
        .unwrap_or(UMASK_DEFAULT)
}

const UMASK_DEFAULT: u32 = 0o022;

// ── Per-task nice / priority table ─────────────────────────────────
//
// POSIX getpriority / setpriority manage a task's nice value
// (-20..=19, lower is more favoured). NARF's scheduler doesn't
// use this for routing today (capability-gated CpuBudget caps and
// the ResourceBudget surface own that), but real Linux programs
// often setpriority(PRIO_PROCESS, 0, 10) to be polite when
// running batch work. Honouring the round-trip lets that pattern
// stick.

/// Which set of tasks a `(which, who)` argument pair names.
///
/// `getpriority`, `setpriority`, `ioprio_get` and `ioprio_set` all take
/// this shape and all four had PGRP/USER unimplemented. They differ only
/// in the NUMBERS they use for the three cases — PRIO_* counts from 0 and
/// IOPRIO_WHO_* from 1 — so the selection logic is shared and each caller
/// maps its own constants onto this.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum WhoScope {
    Process,
    Pgrp,
    User,
}

/// Resolve `(which, who)` to the tasks it names, following Linux's
/// `find_task_by_vpid` / `do_each_pid_thread(PIDTYPE_PGID)` /
/// `for_each_process_thread` selection.
///
/// Returns an EMPTY vector rather than an error when nothing matches:
/// every one of these syscalls starts its result at `-ESRCH` and lets a
/// successful visit overwrite it, so "no such target" and "no tasks in
/// that set" are the same answer and the caller expresses it once.
///
/// `who == 0` means the caller's own process, process group, or REAL uid
/// depending on the scope — note it is `cred->uid`, not euid, for the user
/// case (kernel/sys.c: `if (!who) uid = cred->uid;`).
/// `thread_group_empty(current)` — is the caller the ONLY live thread in
/// its thread group?
///
/// NARF models a thread by mapping its TaskId onto its leader's process
/// key (see `process_state_key`), so the group is every live task sharing
/// the caller's key.
pub(crate) fn thread_group_empty(task: u64) -> bool {
    let me = process_state_key(task);
    !crate::task::task_ids()
        .into_iter()
        .any(|t| t != task && process_state_key(t) == me)
}

pub(crate) fn resolve_who_targets(scope: WhoScope, who: i32, caller: u64) -> alloc::vec::Vec<u64> {
    let mut out = alloc::vec::Vec::new();
    match scope {
        WhoScope::Process => {
            if who == 0 {
                out.push(process_state_key(caller));
                return out;
            }
            let Some(outer) = accept_pid_from(caller, who as u64) else {
                return out;
            };
            let t = process_state_key(proc_pid_to_tid(outer));
            // `find_task_by_vpid` returning NULL is the empty set —
            // `proc_pid_to_tid` falls back to identity for an unregistered
            // pid, so an existence check is what implements that.
            if t == process_state_key(caller) || crate::task::task_get(t).is_some() {
                out.push(t);
            }
        }
        WhoScope::Pgrp => {
            let target = if who == 0 {
                read_pgid(process_state_key(caller))
            } else {
                let g = pgid_from_user(who as u64);
                if g == 0 {
                    return out;
                }
                process_state_key(g)
            };
            // The caller is checked explicitly because syscall-unit
            // fixtures need not populate the scheduler task registry.
            let me = process_state_key(caller);
            if read_pgid(me) == target {
                out.push(me);
            }
            for t in crate::task::task_ids() {
                let key = process_state_key(t);
                if key != me && read_pgid(key) == target && !out.contains(&key) {
                    out.push(key);
                }
            }
        }
        WhoScope::User => {
            let me = process_state_key(caller);
            let target_uid = if who == 0 {
                read_uidgid(me).uid
            } else {
                who as u32
            };
            if read_uidgid(me).uid == target_uid {
                out.push(me);
            }
            for t in crate::task::task_ids() {
                let key = process_state_key(t);
                if key != me && read_uidgid(key).uid == target_uid && !out.contains(&key) {
                    out.push(key);
                }
            }
        }
    }
    out
}


static NICE_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, i32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
// Linux keeps nice in each task's scheduler state, so the common
// `getpriority(PRIO_PROCESS, 0)` path never contends on one system-wide lock.
// NARF's compatibility state is sparse instead: an absent row means nice 0.
// Keep an exact count so the overwhelmingly common all-default case can avoid
// the IRQ-disabling BTreeMap lock (and its cache-line bounce) entirely.
static NICE_CUSTOM_ROWS: AtomicUsize = AtomicUsize::new(0);

pub fn nice_init() {
    *NICE_TABLE.lock() = Some(BTreeMap::new());
    NICE_CUSTOM_ROWS.store(0, Ordering::Release);
}

#[doc(hidden)]
pub fn __test_nice_reset() {
    *NICE_TABLE.lock() = Some(BTreeMap::new());
    NICE_CUSTOM_ROWS.store(0, Ordering::Release);
}

#[doc(hidden)]
pub fn __test_nice_storage_len() -> usize {
    NICE_TABLE.lock().as_ref().map_or(0, BTreeMap::len)
}

fn read_nice(task: u64) -> i32 {
    // A setter publishes the row before its release increment. A reader that
    // observes a non-zero count acquires that publication; a reader racing
    // before publication may linearize before the setter and return the old
    // default. Once the last row is removed, zero remains the exact default.
    if NICE_CUSTOM_ROWS.load(Ordering::Acquire) == 0 {
        return 0;
    }
    let g = NICE_TABLE.lock();
    g.as_ref().and_then(|m| m.get(&task).copied()).unwrap_or(0)
}

#[inline]
fn read_current_nice() -> i32 {
    // Match Linux's `p = current; task_nice(p)` fast branch. When the sparse
    // store is empty, the current task's process key cannot affect the answer,
    // so avoid both task↔pid map lookups as well as NICE_TABLE itself.
    if NICE_CUSTOM_ROWS.load(Ordering::Acquire) == 0 {
        return 0;
    }
    read_nice(process_state_key(current_task_id()))
}
fn write_nice(task: u64, prio: i32) -> bool {
    let mut g = NICE_TABLE.lock();
    let Some(m) = g.as_mut() else {
        return false;
    };
    if prio == 0 {
        // Preserve the sparse representation: nice 0 is the implicit default.
        if m.remove(&task).is_some() {
            NICE_CUSTOM_ROWS.fetch_sub(1, Ordering::Release);
        }
    } else if m.insert(task, prio).is_none() {
        // Publish the map row before allowing lock-free readers to skip their
        // default return and consult it.
        NICE_CUSTOM_ROWS.fetch_add(1, Ordering::Release);
    }
    true
}
/// Test-only raw state mutation. This deliberately bypasses setpriority's
/// Linux permission checks so sparse default-row removal can be verified.
#[doc(hidden)]
pub fn __test_write_current_nice(prio: i32) -> bool {
    write_nice(process_state_key(current_task_id()), prio)
}


// ── Times — POSIX process CPU times ───────────────────────────────
//
// times(2) writes a `struct tms { utime, stime, cutime, cstime }`
// in clock ticks (CLK_TCK = 100Hz, so 10 ms per tick). NARF
// doesn't track per-task user/system splits yet — we synthesise
// `utime = wall ticks since boot` and zero the rest — but the
// returned wall-clock value is real and lets a consumer
// calibrate `clock(3)` against the elapsed wall.
//
// The function returns the wall-clock ticks via the syscall
// `value`; `tms_out` receives the same shape glibc / POSIX
// expects. Caller-side libc translates negative-on-overflow
// per the POSIX clock_t bound.

const CLK_TCK_HZ: u64 = 100;

// ── Getrusage — populate the glibc rusage struct ──────────────────
//
// Linux's `struct rusage` is 16 fields after the leading two
// timevals (each timeval is two i64s on x86_64), totaling 18 i64s
// = 144 bytes. We populate ru_utime from monotonic_ns and zero
// the rest — same accounting story as sys_times. The two-field
// timeval layout matches what glibc's <sys/time.h> exposes.

const RUSAGE_TIMEVAL_FIELDS: usize = 4; // ru_utime + ru_stime
const RUSAGE_TAIL_FIELDS: usize = 14; // ru_maxrss .. ru_nivcsw
const RUSAGE_TOTAL_I64S: usize = RUSAGE_TIMEVAL_FIELDS + RUSAGE_TAIL_FIELDS;

// ── Hostname (kernel-wide) ─────────────────────────────────────────
//
// One global string behind an IrqSafeSpinLock, initialised to
// "narf" so a get-before-set call has something sensible to read.
// Bound at 64 bytes to fit POSIX HOST_NAME_MAX (Linux's
// __NEW_UTS_LEN is 64). Stage-4 simplification: any task can set
// the hostname; the cap gate lands alongside a wider settable-
// state surface in a follow-up.

const HOSTNAME_MAX: usize = 64;

static HOSTNAME: narf_lib::sync::IrqSafeSpinLock<alloc::string::String> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::string::String::new());

/// Global NIS/UTS domain name (set_domainname / read by uname). Empty
/// by default (Linux reports "(none)"). Only the non-container path uses this
/// flat global — with the `container` feature both setdomainname and uname go
/// through the per-task `current_uts_ns`, so the static is dead there.
#[cfg(not(feature = "container"))]
static DOMAINNAME: narf_lib::sync::IrqSafeSpinLock<alloc::string::String> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::string::String::new());

/// Initialise the hostname slot to `"narf"`. Idempotent so the
/// boot path can call this without coordination.
pub fn hostname_init() {
    let mut g = HOSTNAME.lock();
    if g.is_empty() {
        g.push_str("narf");
    }
}

/// Test hook: clear the hostname back to the boot default.
#[doc(hidden)]
pub fn __test_hostname_reset() {
    let mut g = HOSTNAME.lock();
    g.clear();
    g.push_str("narf");
}

// ── Wave-72 — uname(2), setdomainname(2), SysV IPC get-by-key ─────
//
// `struct utsname` is six 65-byte fixed-length fields (NUL-terminated)
// per Linux. Total 390 bytes. NARF cap matches Linux __NEW_UTS_LEN=64
// plus the trailing NUL byte → 65.

const UTSNAME_FIELD_LEN: usize = 65;
const UTSNAME_STRUCT_LEN: usize = UTSNAME_FIELD_LEN * 6;

fn pack_utsname_field(dst: &mut [u8], src: &str) {
    let n = core::cmp::min(src.len(), UTSNAME_FIELD_LEN - 1);
    dst[..n].copy_from_slice(&src.as_bytes()[..n]);
    // remaining bytes already zeroed by caller
}

// ── System V shared memory (linux-compat) ────────────────────────────
//
// Real shared segments backed by the narf-shmem frame registry (reached
// through the syscall vtable). `shmat` maps a segment's physical frames
// into the caller's address space; a second attach of the same id maps
// the same frames, so writes through one attachment are visible through
// the other — genuine sharing, exactly like Linux. Supersedes the
// container id-by-key `shmget` in a linux-compat build.

struct ShmSegment {
    handle: u64,
    key: u32,
    len: u64,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    /// Creator's OUTER ProcessId (shmid_ds.shm_cpid), set at shmget.
    cpid: u64,
    /// OUTER ProcessId of the last shmat (shmid_ds.shm_lpid); 0 until the
    /// first attach. Rendered — translated into the reader's ns — by shmctl
    /// IPC_STAT. shmdt unmaps by address (no shmid in hand) so it is not
    /// tracked as a last-op here.
    lpid: u64,
    atime: i64,
    dtime: i64,
    ctime: i64,
    nattch: u64,
    /// Linux SHM_LOCKED state. Backing is eagerly resident; the shmem vtable
    /// additionally blocks explicit frame migration while this is set.
    locked: bool,
    /// `IPC_RMID` removes the id/key immediately but retains the backing and
    /// metadata until the last live (or in-progress) attachment is gone.
    removed: bool,
}

#[derive(Clone)]
struct ShmAttachment {
    ipc_ns: u64,
    shmid: u64,
    /// Original address passed to `shmdt`. `SHM_REMAP` may punch this mapping
    /// into fragments, which remain one logical attachment.
    base: u64,
    fragments: alloc::vec::Vec<(u64, u64)>,
    /// A destination record prepared before a shared `MREMAP_DONTUNMAP`
    /// transaction mutates page tables. The per-address-space SysV mapping
    /// transaction keeps this record private until commit; fixed-target punch
    /// accounting must preserve it while retiring the previous destination.
    pending_mremap: Option<u64>,
}

type ShmAttachmentKey = (u64, u64); // (address-space incarnation, detach base)

/// Sorted attachment index with fallible preparation for insertion.
///
/// BTreeMap has no stable fallible entry API: inserting a post-mremap
/// destination could therefore invoke the kernel allocation-error handler
/// after page tables had already changed. This compact index retains O(log n)
/// exact lookup through binary search while allowing callers to reserve both
/// the outer key slot and inner attachment slot before mutation. Insertion and
/// removal shift O(n) records, which is acceptable for low-frequency SysV
/// topology changes and does not affect normal `shmdt` lookup complexity.
#[derive(Default)]
struct ShmAttachmentRegistry {
    entries: alloc::vec::Vec<(ShmAttachmentKey, alloc::vec::Vec<ShmAttachment>)>,
}

impl ShmAttachmentRegistry {
    fn new() -> Self {
        Self::default()
    }

    fn search(&self, key: ShmAttachmentKey) -> Result<usize, usize> {
        self.entries
            .binary_search_by_key(&key, |(entry_key, _)| *entry_key)
    }

    fn get(&self, key: &ShmAttachmentKey) -> Option<&alloc::vec::Vec<ShmAttachment>> {
        self.search(*key)
            .ok()
            .map(|index| &self.entries[index].1)
    }

    fn get_mut(
        &mut self,
        key: &ShmAttachmentKey,
    ) -> Option<&mut alloc::vec::Vec<ShmAttachment>> {
        self.search(*key)
            .ok()
            .map(|index| &mut self.entries[index].1)
    }

    fn contains_key(&self, key: &ShmAttachmentKey) -> bool {
        self.search(*key).is_ok()
    }

    fn as_bounds(&self, as_key: u64) -> core::ops::Range<usize> {
        let start = self
            .entries
            .partition_point(|((entry_as, _), _)| *entry_as < as_key);
        let end = self
            .entries
            .partition_point(|((entry_as, _), _)| *entry_as <= as_key);
        start..end
    }

    fn as_slice(
        &self,
        as_key: u64,
    ) -> &[(ShmAttachmentKey, alloc::vec::Vec<ShmAttachment>)] {
        let bounds = self.as_bounds(as_key);
        &self.entries[bounds]
    }

    fn as_slice_mut(
        &mut self,
        as_key: u64,
    ) -> &mut [(ShmAttachmentKey, alloc::vec::Vec<ShmAttachment>)] {
        let bounds = self.as_bounds(as_key);
        &mut self.entries[bounds]
    }

    /// Ensure a key exists and its value Vec can accept `additional` records.
    /// Both allocations complete before the empty key is published.
    fn try_reserve_key(
        &mut self,
        key: ShmAttachmentKey,
        additional: usize,
    ) -> Result<(), ()> {
        match self.search(key) {
            Ok(index) => self.entries[index]
                .1
                .try_reserve_exact(additional)
                .map_err(|_| ()),
            Err(index) => {
                let mut values = alloc::vec::Vec::new();
                values.try_reserve_exact(additional).map_err(|_| ())?;
                self.entries.try_reserve_exact(1).map_err(|_| ())?;
                self.entries.insert(index, (key, values));
                Ok(())
            }
        }
    }

    /// Push after [`Self::try_reserve_key`], without allocation.
    fn push_reserved(&mut self, key: ShmAttachmentKey, attachment: ShmAttachment) {
        let index = self
            .search(key)
            .expect("reserved SysV attachment key disappeared");
        debug_assert!(self.entries[index].1.len() < self.entries[index].1.capacity());
        self.entries[index].1.push(attachment);
    }

    fn try_push(
        &mut self,
        key: ShmAttachmentKey,
        attachment: ShmAttachment,
    ) -> Result<(), ShmAttachment> {
        if self.try_reserve_key(key, 1).is_err() {
            return Err(attachment);
        }
        self.push_reserved(key, attachment);
        Ok(())
    }

    fn remove(&mut self, key: &ShmAttachmentKey) -> Option<alloc::vec::Vec<ShmAttachment>> {
        self.search(*key)
            .ok()
            .map(|index| self.entries.remove(index).1)
    }

    fn retain(
        &mut self,
        mut keep: impl FnMut(&ShmAttachmentKey, &mut alloc::vec::Vec<ShmAttachment>) -> bool,
    ) {
        self.entries
            .retain_mut(|(key, entries)| keep(key, entries));
    }
}
type ShmAddressSpaceOwners =
    alloc::collections::BTreeMap<u64, alloc::collections::BTreeSet<u64>>;
type ShmObjectKey = (u64, u64); // (IPC namespace id, namespace-local shmid)

static SHM_SEGMENTS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<ShmObjectKey, ShmSegment>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);
static SHM_ATTACHMENTS: narf_lib::sync::IrqSafeSpinLock<
    Option<ShmAttachmentRegistry>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);
static SHM_AS_OWNERS: narf_lib::sync::IrqSafeSpinLock<
    Option<ShmAddressSpaceOwners>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);
type ShmMappingTransactions = alloc::collections::BTreeMap<
    u64,
    alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<()>>,
>;
static SHM_MAPPING_TRANSACTIONS: narf_lib::sync::IrqSafeSpinLock<
    Option<ShmMappingTransactions>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);
static SHM_NEXT_MREMAP_PREPARATION: AtomicU64 = AtomicU64::new(1);
#[cfg(not(feature = "container"))]
static SHM_NEXT_ID: AtomicU64 = AtomicU64::new(1);

const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_EXEC: u64 = 0o100000;
const SHMLBA: u64 = 4096;

fn shm_now_seconds() -> i64 {
    narf_scheduler::narf_time::now_wall().secs
}

fn shm_as_key(as_ref: &Arc<AddressSpace>) -> u64 {
    shm_as_key_ref(as_ref)
}

fn shm_as_key_ref(as_ref: &AddressSpace) -> u64 {
    let root = as_ref.root.as_u64();
    if root != 0 {
        root
    } else {
        as_ref as *const AddressSpace as usize as u64
    }
}

#[cfg(feature = "container")]
fn current_shm_ipc_ns() -> alloc::sync::Arc<crate::namespaces::IpcNamespace> {
    crate::namespaces::current_ipc_namespace(current_task_id())
}

#[cfg(not(feature = "container"))]
fn current_shm_ipc_ns_id() -> u64 {
    0
}

fn shm_register_as_owner(as_key: u64, pid: u64) {
    SHM_AS_OWNERS
        .lock()
        .get_or_insert_with(alloc::collections::BTreeMap::new)
        .entry(as_key)
        .or_default()
        .insert(pid);
}

fn shm_mapping_transaction(
    as_key: u64,
) -> alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<()>> {
    SHM_MAPPING_TRANSACTIONS
        .lock()
        .get_or_insert_with(alloc::collections::BTreeMap::new)
        .entry(as_key)
        .or_insert_with(|| alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(())))
        .clone()
}

/// Mirror Linux `shm_open` across fork. A separate address space gets one
/// additional logical attachment for every inherited mapping; `CLONE_VM`
/// merely adds another process owner of the same mm and does not change
/// `shm_nattch`.
fn shm_fork_process(
    parent_as: &Arc<AddressSpace>,
    child_as: &Arc<AddressSpace>,
    child_pid: u64,
    share_vm: bool,
) {
    let parent_key = shm_as_key(parent_as);
    let child_key = shm_as_key(child_as);
    let parent_tracked = SHM_AS_OWNERS
        .lock()
        .as_ref()
        .is_some_and(|owners| owners.contains_key(&parent_key));
    if !parent_tracked {
        return;
    }
    let mapping_transaction = shm_mapping_transaction(parent_key);
    let _mapping_guard = mapping_transaction.lock();
    shm_register_as_owner(child_key, child_pid);
    if share_vm {
        return;
    }

    let inherited = {
        let mut attachments = SHM_ATTACHMENTS.lock();
        let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
        let inherited: alloc::vec::Vec<_> = map
            .as_slice(parent_key)
            .iter()
            .flat_map(|((_, base), entries)| {
                entries
                    .iter()
                    .cloned()
                    .map(|entry| (*base, entry))
                    .collect::<alloc::vec::Vec<_>>()
            })
            .collect();
        for (base, entry) in &inherited {
            if map
                .try_push((child_key, *base), entry.clone())
                .is_err()
            {
                panic!("could not reserve inherited SysV attachment registry entry");
            }
        }
        inherited
    };
    let mut segments = SHM_SEGMENTS.lock();
    let map = segments.get_or_insert_with(alloc::collections::BTreeMap::new);
    for (_, attachment) in inherited {
        if let Some(seg) = map.get_mut(&(attachment.ipc_ns, attachment.shmid)) {
            seg.nattch = seg.nattch.saturating_add(1);
        }
    }
}

/// Process-exit half of Linux `exit_shm`: only the final process sharing an
/// address space closes its inherited logical attachments.
pub(crate) fn shm_process_exit(pid: u64, _tid: u64) {
    let closing_keys = {
        let mut owners = SHM_AS_OWNERS.lock();
        let map = owners.get_or_insert_with(alloc::collections::BTreeMap::new);
        let mut closing = alloc::vec::Vec::new();
        let keys: alloc::vec::Vec<_> = map.keys().copied().collect();
        for key in keys {
            let remove = map.get_mut(&key).is_some_and(|pids| {
                pids.remove(&pid);
                pids.is_empty()
            });
            if remove {
                map.remove(&key);
                closing.push(key);
            }
        }
        closing
    };
    if closing_keys.is_empty() {
        return;
    }
    // `closing_keys` follows BTreeMap key order, giving multi-mm teardown a
    // stable lock order even for synthetic tests that associate one pid with
    // more than one address space.
    let mapping_transactions: alloc::vec::Vec<_> = closing_keys
        .iter()
        .map(|key| shm_mapping_transaction(*key))
        .collect();
    let mapping_guards: alloc::vec::Vec<_> = mapping_transactions
        .iter()
        .map(|transaction| transaction.lock())
        .collect();
    let detached = {
        let mut attachments = SHM_ATTACHMENTS.lock();
        let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
        let keys: alloc::vec::Vec<_> = map
            .entries
            .iter()
            .map(|(key, _)| *key)
            .filter(|(as_key, _)| closing_keys.contains(as_key))
            .collect();
        keys.into_iter()
            .flat_map(|key| map.remove(&key).unwrap_or_default())
            .map(|attachment| (attachment.ipc_ns, attachment.shmid))
            .collect::<alloc::vec::Vec<_>>()
    };
    let now = shm_now_seconds();
    let mut destroy = alloc::vec::Vec::new();
    {
        let mut segments = SHM_SEGMENTS.lock();
        let map = segments.get_or_insert_with(alloc::collections::BTreeMap::new);
        for object in detached {
            let Some(seg) = map.get_mut(&object) else {
                continue;
            };
            seg.nattch = seg.nattch.saturating_sub(1);
            seg.lpid = pid;
            seg.dtime = now;
            if seg.removed && seg.nattch == 0 {
                if let Some(seg) = map.remove(&object) {
                    destroy.push(seg.handle);
                }
            }
        }
    }
    if let Some(vtable) = shmem_vtable() {
        for handle in destroy {
            if handle != 0 {
                (vtable.destroy)(handle);
            }
        }
    }
    drop(mapping_guards);
    let mut transactions = SHM_MAPPING_TRANSACTIONS.lock();
    if let Some(map) = transactions.as_mut() {
        for key in closing_keys {
            map.remove(&key);
        }
    }
}

fn shm_ipc_allowed(seg: &ShmSegment, request: u32) -> bool {
    // Linux ipcperms collapses owner/group/other request bits into one rwx
    // mask before comparing it with the caller-selected permission class.
    let request = ((request >> 6) | (request >> 3) | request) & 0o7;
    let cred = current_ucred();
    if cred.uid == 0 {
        return true;
    }
    let groups = current_groups();
    let granted = if cred.uid == seg.uid || cred.uid == seg.cuid {
        (seg.mode >> 6) & 0o7
    } else if cred.gid == seg.gid
        || cred.gid == seg.cgid
        || groups.contains(&seg.gid)
        || groups.contains(&seg.cgid)
    {
        (seg.mode >> 3) & 0o7
    } else {
        seg.mode & 0o7
    };
    granted & request == request
}

fn shm_ipc_owner(seg: &ShmSegment) -> bool {
    let uid = current_ucred().uid;
    uid == 0 || uid == seg.uid || uid == seg.cuid
}

/// Drop an in-progress attach reservation. If `IPC_RMID` raced the mapping,
/// the final reservation owns destruction of the now-unreachable backing.
fn shm_cancel_attach(object: ShmObjectKey) {
    let destroy = {
        let mut segments = SHM_SEGMENTS.lock();
        let map = segments.get_or_insert_with(alloc::collections::BTreeMap::new);
        let Some(seg) = map.get_mut(&object) else {
            return;
        };
        seg.nattch = seg.nattch.saturating_sub(1);
        if seg.removed && seg.nattch == 0 {
            map.remove(&object).map(|seg| seg.handle)
        } else {
            None
        }
    };
    if let (Some(handle), Some(vtable)) = (destroy, shmem_vtable()) {
        if handle != 0 {
            (vtable.destroy)(handle);
        }
    }
}

/// A registry-side failure while preparing a shared `mremap` alias.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ShmMremapPrepareError {
    InvalidRange,
    PartialSysvSource,
    AmbiguousSysvSource,
    SegmentMissing,
    PreparationConflict,
    AllocationFailed,
    TokenExhausted,
}

/// Registry transaction prepared before a shared `MREMAP_DONTUNMAP` page-table
/// operation. A SysV source installs one hidden destination attachment up
/// front, so commit performs no attachment allocation after memory has changed.
/// Non-SysV shared sources still carry fixed-target punch accounting.
///
/// The caller must keep `shm_mapping_transaction(as_key)` locked from prepare
/// through commit/abort. Dropping this value rolls back only the hidden SysV
/// destination; use [`Self::abort`] when memory already punched a fixed target.
#[must_use = "dropping the preparation rolls back its pending SysV alias"]
pub(crate) struct PreparedShmMremapAlias {
    as_key: u64,
    new_base: u64,
    len: u64,
    lpid: u64,
    pending: Option<(u64, ShmObjectKey)>,
    /// Capacity is reserved before memory mutation for every removed segment
    /// handle that a fixed target punch can make destroyable.
    destroy_after_punch: alloc::vec::Vec<u64>,
}

fn shm_attachment_covers(attachment: &ShmAttachment, lo: u64, hi: u64) -> bool {
    let mut cursor = lo;
    for &(base, len) in &attachment.fragments {
        let end = base.saturating_add(len);
        if end <= cursor {
            continue;
        }
        if base > cursor {
            return false;
        }
        cursor = core::cmp::min(end, hi);
        if cursor == hi {
            return true;
        }
    }
    false
}

fn shm_attachment_intersects(attachment: &ShmAttachment, lo: u64, hi: u64) -> bool {
    attachment.fragments.iter().any(|&(base, len)| {
        let end = base.saturating_add(len);
        base < hi && lo < end
    })
}

/// Reserve every Vec growth needed to clip the fixed target in place. The
/// address-space mapping transaction makes these capacities stable until the
/// prepared operation commits or aborts.
fn shm_prepare_punch_capacity(
    as_key: u64,
    ranges: &[(u64, u64)],
) -> Result<alloc::vec::Vec<u64>, ShmMremapPrepareError> {
    let mut attachments = SHM_ATTACHMENTS.lock();
    let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
    let mut detach_bound = 0usize;
    for ((key, _), entries) in map.as_slice_mut(as_key) {
        if *key != as_key {
            continue;
        }
        for attachment in entries {
            if attachment.pending_mremap.is_some() {
                continue;
            }
            let intersects = ranges
                .iter()
                .any(|&(lo, hi)| shm_attachment_intersects(attachment, lo, hi));
            if !intersects {
                continue;
            }
            detach_bound = detach_bound.saturating_add(1);
            let splits = ranges
                .iter()
                .map(|&(lo, hi)| {
                    attachment
                        .fragments
                        .iter()
                        .filter(|&&(base, len)| {
                            let end = base.saturating_add(len);
                            base < lo && end > hi
                        })
                        .count()
                })
                .fold(0usize, usize::saturating_add);
            attachment
                .fragments
                .try_reserve_exact(splits)
                .map_err(|_| ShmMremapPrepareError::AllocationFailed)?;
        }
    }
    let mut destroy = alloc::vec::Vec::new();
    destroy
        .try_reserve_exact(detach_bound)
        .map_err(|_| ShmMremapPrepareError::AllocationFailed)?;
    Ok(destroy)
}

fn shm_prepare_fixed_punch_capacity(
    as_key: u64,
    lo: u64,
    hi: u64,
) -> Result<alloc::vec::Vec<u64>, ShmMremapPrepareError> {
    shm_prepare_punch_capacity(as_key, &[(lo, hi)])
}

fn shm_clip_attachment_prepared(attachment: &mut ShmAttachment, lo: u64, hi: u64) {
    let mut index = 0usize;
    while index < attachment.fragments.len() {
        let (base, len) = attachment.fragments[index];
        let end = base.saturating_add(len);
        if end <= lo || base >= hi {
            index += 1;
        } else if base < lo && end > hi {
            // Capacity for this one additional suffix was reserved by
            // shm_prepare_fixed_punch_capacity before memory mutation.
            attachment.fragments[index] = (base, lo - base);
            attachment.fragments.insert(index + 1, (hi, end - hi));
            index += 2;
        } else if base < lo {
            attachment.fragments[index] = (base, lo - base);
            index += 1;
        } else if end > hi {
            attachment.fragments[index] = (hi, end - hi);
            index += 1;
        } else {
            attachment.fragments.remove(index);
        }
    }
}

/// Prepare the SysV attachment half of a shared `MREMAP_DONTUNMAP` operation.
/// `Ok` with no pending object means the source is shared but not SysV-backed;
/// the returned plan must still finish fixed-target punch accounting.
///
/// # Safety
/// The caller must hold the per-address-space lock returned by
/// [`shm_mapping_transaction`] for `as_key` until the returned plan is consumed
/// or dropped. `old_base..old_base+len` and `new_base..new_base+len` must name
/// the already-validated source and prospective destination of the same memory
/// transaction.
pub(crate) unsafe fn shm_prepare_mremap_shared_alias_locked(
    as_key: u64,
    old_base: u64,
    len: u64,
    new_base: u64,
    lpid: u64,
) -> Result<PreparedShmMremapAlias, ShmMremapPrepareError> {
    // SAFETY: forwards the caller's transaction/range contract.
    unsafe {
        shm_prepare_mremap_shared_destination_locked(
            as_key, old_base, len, new_base, len, lpid, false,
        )
    }
}

/// Prepare the owner transfer for an ordinary nonzero shared move. The hidden
/// destination is published only on success; failure methods can commit the
/// fixed-target punch and Linux's separately observable source-tail shrink.
pub(crate) unsafe fn shm_prepare_mremap_shared_relocation_locked(
    as_key: u64,
    old_base: u64,
    old_len: u64,
    new_base: u64,
    new_len: u64,
    lpid: u64,
) -> Result<PreparedShmMremapAlias, ShmMremapPrepareError> {
    // SAFETY: forwards the caller's transaction/range contract.
    unsafe {
        shm_prepare_mremap_shared_destination_locked(
            as_key, old_base, old_len, new_base, new_len, lpid, true,
        )
    }
}

/// Prepare a source-tail ownership punch for an in-place shared shrink.
///
/// # Safety
/// The caller holds `shm_mapping_transaction(as_key)` through plan commit/drop.
pub(crate) unsafe fn shm_prepare_mremap_punch_locked(
    as_key: u64,
    base: u64,
    len: u64,
    lpid: u64,
) -> Result<PreparedShmMremapAlias, ShmMremapPrepareError> {
    let hi = base
        .checked_add(len)
        .ok_or(ShmMremapPrepareError::InvalidRange)?;
    if len == 0 || base & 0xfff != 0 {
        return Err(ShmMremapPrepareError::InvalidRange);
    }
    Ok(PreparedShmMremapAlias {
        as_key,
        new_base: base,
        len,
        lpid,
        pending: None,
        destroy_after_punch: shm_prepare_fixed_punch_capacity(as_key, base, hi)?,
    })
}

#[allow(clippy::too_many_arguments)]
unsafe fn shm_prepare_mremap_shared_destination_locked(
    as_key: u64,
    old_base: u64,
    old_len: u64,
    new_base: u64,
    new_len: u64,
    lpid: u64,
    relocation: bool,
) -> Result<PreparedShmMremapAlias, ShmMremapPrepareError> {
    if old_len == 0 || new_len == 0 || old_base & 0xFFF != 0 || new_base & 0xFFF != 0 {
        return Err(ShmMremapPrepareError::InvalidRange);
    }
    let old_hi = old_base
        .checked_add(old_len)
        .ok_or(ShmMremapPrepareError::InvalidRange)?;
    let new_hi = new_base
        .checked_add(new_len)
        .ok_or(ShmMremapPrepareError::InvalidRange)?;
    if old_base < new_hi && new_base < old_hi {
        return Err(ShmMremapPrepareError::InvalidRange);
    }
    let source_tail = old_base
        .checked_add(core::cmp::min(old_len, new_len))
        .ok_or(ShmMremapPrepareError::InvalidRange)?;
    let relocation_ranges = [
        (new_base, new_hi),
        (old_base, old_hi),
        (source_tail, old_hi),
    ];
    let destroy_after_punch = if relocation {
        shm_prepare_punch_capacity(as_key, &relocation_ranges)?
    } else {
        shm_prepare_fixed_punch_capacity(as_key, new_base, new_hi)?
    };

    let source = {
        let attachments = SHM_ATTACHMENTS.lock();
        let mut source = None;
        let mut saw_partial = false;
        if let Some(map) = attachments.as_ref() {
            for ((key, _), entries) in map.as_slice(as_key) {
                if *key != as_key {
                    continue;
                }
                for attachment in entries {
                    if attachment.pending_mremap.is_some()
                        || !shm_attachment_intersects(attachment, old_base, old_hi)
                    {
                        continue;
                    }
                    if !shm_attachment_covers(attachment, old_base, old_hi) {
                        saw_partial = true;
                        continue;
                    }
                    let object = (attachment.ipc_ns, attachment.shmid);
                    if source.replace(object).is_some() {
                        return Err(ShmMremapPrepareError::AmbiguousSysvSource);
                    }
                }
            }
        }
        if source.is_none() && saw_partial {
            return Err(ShmMremapPrepareError::PartialSysvSource);
        }
        source
    };

    let Some(object) = source else {
        return Ok(PreparedShmMremapAlias {
            as_key,
            new_base,
            len: new_len,
            lpid,
            pending: None,
            destroy_after_punch,
        });
    };
    if !SHM_SEGMENTS
        .lock()
        .as_ref()
        .is_some_and(|segments| segments.contains_key(&object))
    {
        return Err(ShmMremapPrepareError::SegmentMissing);
    }

    let token = SHM_NEXT_MREMAP_PREPARATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| ShmMremapPrepareError::TokenExhausted)?;
    let mut fragments = alloc::vec::Vec::new();
    fragments
        .try_reserve_exact(1)
        .map_err(|_| ShmMremapPrepareError::AllocationFailed)?;
    fragments.push((new_base, new_len));

    {
        let mut attachments = SHM_ATTACHMENTS.lock();
        let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
        map.try_reserve_key((as_key, new_base), 1)
            .map_err(|_| ShmMremapPrepareError::AllocationFailed)?;
        let entries = map
            .get(&(as_key, new_base))
            .expect("reserved SysV mremap destination key disappeared");
        if entries
            .iter()
            .any(|attachment| attachment.pending_mremap.is_some())
        {
            return Err(ShmMremapPrepareError::PreparationConflict);
        }
        map.push_reserved((as_key, new_base), ShmAttachment {
            ipc_ns: object.0,
            shmid: object.1,
            base: new_base,
            fragments,
            pending_mremap: Some(token),
        });
    }
    Ok(PreparedShmMremapAlias {
        as_key,
        new_base,
        len: new_len,
        lpid,
        pending: Some((token, object)),
        destroy_after_punch,
    })
}

impl PreparedShmMremapAlias {
    fn remove_pending(&mut self) {
        let Some((token, _)) = self.pending.take() else {
            return;
        };
        let mut attachments = SHM_ATTACHMENTS.lock();
        let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
        let key = (self.as_key, self.new_base);
        let remove_key = if let Some(entries) = map.get_mut(&key) {
            if let Some(index) = entries
                .iter()
                .position(|attachment| attachment.pending_mremap == Some(token))
            {
                entries.remove(index);
            }
            entries.is_empty()
        } else {
            false
        };
        if remove_key {
            map.remove(&key);
        }
    }

    /// Apply the target outcome using only capacities reserved at prepare time.
    /// Unlike the legacy generic punch helper, this performs no Vec growth or
    /// BTree insertion after memory has destructively replaced the target.
    fn apply_prepared_punch(&mut self, lo: u64, hi: u64) {
        let now = shm_now_seconds();
        let mut attachments = SHM_ATTACHMENTS.lock();
        let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
        let mut segments = SHM_SEGMENTS.lock();
        let segment_map = segments.get_or_insert_with(alloc::collections::BTreeMap::new);
        map.retain(|(as_key, _), entries| {
            if *as_key != self.as_key {
                return true;
            }
            entries.retain_mut(|attachment| {
                if attachment.pending_mremap.is_some()
                    || !shm_attachment_intersects(attachment, lo, hi)
                {
                    return true;
                }
                shm_clip_attachment_prepared(attachment, lo, hi);
                if !attachment.fragments.is_empty() {
                    return true;
                }
                let object = (attachment.ipc_ns, attachment.shmid);
                let Some(segment) = segment_map.get_mut(&object) else {
                    return false;
                };
                segment.nattch = segment.nattch.saturating_sub(1);
                segment.lpid = self.lpid;
                segment.dtime = now;
                if segment.removed && segment.nattch == 0 {
                    if let Some(segment) = segment_map.remove(&object) {
                        // Capacity was reserved for every possibly detached
                        // attachment, an upper bound on destroyed segments.
                        self.destroy_after_punch.push(segment.handle);
                    }
                }
                false
            });
            !entries.is_empty()
        });
        drop(segments);
        drop(attachments);
        if let Some(vtable) = shmem_vtable() {
            for handle in self.destroy_after_punch.drain(..) {
                if handle != 0 {
                    (vtable.destroy)(handle);
                }
            }
        }
    }

    /// Publish a successful alias and mirror any fixed destination retirement.
    /// The pending destination becomes one independent logical attachment, so
    /// Linux `shm_open` accounting increments `nattch` and updates atime/lpid.
    pub(crate) fn commit(mut self, target_punched: bool) {
        if target_punched {
            self.apply_prepared_punch(self.new_base, self.new_base + self.len);
        }
        self.commit_pending();
    }

    fn commit_pending(&mut self) {
        let Some((token, object)) = self.pending else {
            return;
        };
        let now = shm_now_seconds();
        {
            let mut attachments = SHM_ATTACHMENTS.lock();
            let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
            let attachment = map
                .get_mut(&(self.as_key, self.new_base))
                .and_then(|entries| {
                    entries
                        .iter_mut()
                        .find(|attachment| attachment.pending_mremap == Some(token))
                })
                .expect("prepared SysV mremap alias disappeared under its transaction");
            let mut segments = SHM_SEGMENTS.lock();
            let segment = segments
                .as_mut()
                .and_then(|segments| segments.get_mut(&object))
                .expect("live SysV mremap source lost its backing segment");
            segment.nattch = segment.nattch.saturating_add(1);
            segment.lpid = self.lpid;
            segment.atime = now;
            attachment.pending_mremap = None;
        }
        self.pending = None;
    }

    /// Commit an ordinary move: fixed-target retirement, complete source
    /// transfer, then publication of the prepared destination attachment.
    pub(crate) fn commit_relocation(
        mut self,
        old_base: u64,
        old_len: u64,
        target_punched: bool,
    ) {
        if target_punched {
            self.apply_prepared_punch(self.new_base, self.new_base + self.len);
        }
        self.commit_pending();
        self.apply_prepared_punch(old_base, old_base + old_len);
    }

    /// Roll back the prepared alias and, when memory already performed a fixed
    /// target punch, retire exactly those displaced destination attachments.
    pub(crate) fn abort(mut self, target_punched: bool) {
        if target_punched {
            self.apply_prepared_punch(self.new_base, self.new_base + self.len);
        }
        self.remove_pending();
    }

    /// Apply the destructive prefix of a failed ordinary fixed move. Linux can
    /// expose target retirement alone or target retirement plus source-tail
    /// truncation before a later move error.
    pub(crate) fn abort_relocation(
        mut self,
        old_base: u64,
        old_len: u64,
        new_len: u64,
        target_punched: bool,
        source_shrunk: bool,
    ) {
        if target_punched {
            self.apply_prepared_punch(self.new_base, self.new_base + self.len);
        }
        if source_shrunk && old_len > new_len {
            self.apply_prepared_punch(old_base + new_len, old_base + old_len);
        }
        self.remove_pending();
    }

    pub(crate) fn commit_punch(mut self) {
        self.apply_prepared_punch(self.new_base, self.new_base + self.len);
    }
}

impl Drop for PreparedShmMremapAlias {
    fn drop(&mut self) {
        self.remove_pending();
    }
}

/// Account for mappings displaced by `SHM_REMAP`. Fully covered logical
/// attachments detach; partially covered ones retain the surviving fragments
/// so a later `shmdt(original_base)` still finds and removes them.
fn shm_record_fixed_punch(as_key: u64, lo: u64, hi: u64, lpid: u64) {
    let mut detached_ids = alloc::vec::Vec::new();
    {
        let mut attachments = SHM_ATTACHMENTS.lock();
        let map = attachments.get_or_insert_with(ShmAttachmentRegistry::new);
        for (_, entries) in map.as_slice_mut(as_key) {
            let mut surviving = alloc::vec::Vec::new();
            for mut attachment in core::mem::take(entries) {
                // A prepared mremap alias occupies its destination slot before
                // memory changes so commit cannot allocate. It is not part of
                // the old fixed target and must survive that target's punch.
                if attachment.pending_mremap.is_some() {
                    surviving.push(attachment);
                    continue;
                }
                let mut kept = alloc::vec::Vec::new();
                for &(base, len) in &attachment.fragments {
                    let end = base.saturating_add(len);
                    if end <= lo || base >= hi {
                        kept.push((base, len));
                        continue;
                    }
                    if base < lo {
                        kept.push((base, lo - base));
                    }
                    if end > hi {
                        kept.push((hi, end - hi));
                    }
                }
                attachment.fragments = kept;
                if attachment.fragments.is_empty() {
                    detached_ids.push((attachment.ipc_ns, attachment.shmid));
                } else {
                    surviving.push(attachment);
                }
            }
            *entries = surviving;
        }
        map.retain(|_, entries| !entries.is_empty());
    }
    if detached_ids.is_empty() {
        return;
    }
    let now = shm_now_seconds();
    let mut destroy = alloc::vec::Vec::new();
    {
        let mut segments = SHM_SEGMENTS.lock();
        let map = segments.get_or_insert_with(alloc::collections::BTreeMap::new);
        for object in detached_ids {
            let Some(seg) = map.get_mut(&object) else {
                continue;
            };
            seg.nattch = seg.nattch.saturating_sub(1);
            seg.lpid = lpid;
            seg.dtime = now;
            if seg.removed && seg.nattch == 0 {
                if let Some(seg) = map.remove(&object) {
                    destroy.push(seg.handle);
                }
            }
        }
    }
    if let Some(vtable) = shmem_vtable() {
        for handle in destroy {
            if handle != 0 {
                (vtable.destroy)(handle);
            }
        }
    }
}

mod shm_mremap_registry_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const AS_KEY: u64 = u64::MAX - 0x1000;
    const SOURCE: u64 = 0x6200_0000;
    const TARGET: u64 = 0x6300_0000;
    const SOURCE_OBJECT: ShmObjectKey = (u64::MAX - 0x2000, u64::MAX - 0x3000);
    const TARGET_OBJECT: ShmObjectKey = (u64::MAX - 0x2000, u64::MAX - 0x3001);

    fn insert_segment(object: ShmObjectKey, nattch: u64) {
        SHM_SEGMENTS
            .lock()
            .get_or_insert_with(alloc::collections::BTreeMap::new)
            .insert(
                object,
                ShmSegment {
                    handle: 0,
                    key: 0,
                    len: 0x2000,
                    uid: 0,
                    gid: 0,
                    cuid: 0,
                    cgid: 0,
                    mode: 0o600,
                    cpid: 1,
                    lpid: 0,
                    atime: 0,
                    dtime: 0,
                    ctime: 0,
                    nattch,
                    locked: false,
                    removed: false,
                },
            );
    }

    fn insert_attachment(
        object: ShmObjectKey,
        base: u64,
        fragments: alloc::vec::Vec<(u64, u64)>,
    ) {
        let attachment = ShmAttachment {
                ipc_ns: object.0,
                shmid: object.1,
                base,
                fragments,
                pending_mremap: None,
            };
        if SHM_ATTACHMENTS
            .lock()
            .get_or_insert_with(ShmAttachmentRegistry::new)
            .try_push((AS_KEY, base), attachment)
            .is_err()
        {
            panic!("test could not reserve synthetic SysV attachment");
        }
    }

    fn cleanup() {
        if let Some(map) = SHM_ATTACHMENTS.lock().as_mut() {
            map.retain(|(as_key, _), _| *as_key != AS_KEY);
        }
        if let Some(map) = SHM_SEGMENTS.lock().as_mut() {
            map.remove(&SOURCE_OBJECT);
            map.remove(&TARGET_OBJECT);
        }
        if let Some(map) = SHM_MAPPING_TRANSACTIONS.lock().as_mut() {
            map.remove(&AS_KEY);
        }
    }

    fn smoke_shm_mremap_alias_commit_accounts_one_attachment() -> TestResult {
        cleanup();
        insert_segment(SOURCE_OBJECT, 1);
        insert_attachment(
            SOURCE_OBJECT,
            SOURCE,
            alloc::vec![(SOURCE, 0x1000), (SOURCE + 0x1000, 0x1000)],
        );
        let transaction = shm_mapping_transaction(AS_KEY);
        let guard = transaction.lock();
        let result = (|| {
            // SAFETY: this test holds the synthetic AS mapping transaction
            // across preparation and commit.
            let prepared = unsafe {
                shm_prepare_mremap_shared_alias_locked(AS_KEY, SOURCE, 0x2000, TARGET, 77)
            }
            .map_err(|_| "prepare rejected a contiguous fragmented source")?;
            let pending = SHM_ATTACHMENTS
                .lock()
                .as_ref()
                .and_then(|map| map.get(&(AS_KEY, TARGET)))
                .is_some_and(|entries| {
                    entries.len() == 1 && entries[0].pending_mremap.is_some()
                });
            let before = SHM_SEGMENTS
                .lock()
                .as_ref()
                .and_then(|map| map.get(&SOURCE_OBJECT))
                .map(|segment| segment.nattch);
            if !pending || before != Some(1) {
                return Err("prepare published or counted its hidden alias early");
            }
            prepared.commit(false);
            let committed = SHM_ATTACHMENTS
                .lock()
                .as_ref()
                .and_then(|map| map.get(&(AS_KEY, TARGET)))
                .is_some_and(|entries| {
                    entries.len() == 1
                        && entries[0].base == TARGET
                        && entries[0].fragments == alloc::vec![(TARGET, 0x2000)]
                        && entries[0].pending_mremap.is_none()
                });
            let accounted = SHM_SEGMENTS
                .lock()
                .as_ref()
                .and_then(|map| map.get(&SOURCE_OBJECT))
                .is_some_and(|segment| segment.nattch == 2 && segment.lpid == 77);
            if !committed || !accounted {
                return Err("commit did not publish and account one destination attachment");
            }
            Ok(())
        })();
        drop(guard);
        cleanup();
        match result {
            Ok(()) => TestResult::Pass,
            Err(message) => TestResult::Fail(message),
        }
    }
    kernel_test_in!(
        "userspace/sysv_registry",
        smoke_shm_mremap_alias_commit_accounts_one_attachment
    );

    fn smoke_shm_mremap_alias_abort_preserves_pending_during_fixed_punch() -> TestResult {
        cleanup();
        insert_segment(SOURCE_OBJECT, 1);
        insert_segment(TARGET_OBJECT, 1);
        insert_attachment(SOURCE_OBJECT, SOURCE, alloc::vec![(SOURCE, 0x1000)]);
        insert_attachment(TARGET_OBJECT, TARGET, alloc::vec![(TARGET, 0x1000)]);
        let transaction = shm_mapping_transaction(AS_KEY);
        let guard = transaction.lock();
        let result = (|| {
            // SAFETY: the synthetic AS mapping transaction remains held.
            let prepared = unsafe {
                shm_prepare_mremap_shared_alias_locked(AS_KEY, SOURCE, 0x1000, TARGET, 88)
            }
            .map_err(|_| "prepare failed")?;
            prepared.abort(true);
            if SHM_ATTACHMENTS
                .lock()
                .as_ref()
                .is_some_and(|map| map.contains_key(&(AS_KEY, TARGET)))
            {
                return Err("fixed failure left a target or pending attachment");
            }
            let segments = SHM_SEGMENTS.lock();
            let map = segments.as_ref().ok_or("segment table disappeared")?;
            if map.get(&SOURCE_OBJECT).map(|segment| segment.nattch) != Some(1) {
                return Err("rollback changed the source attachment count");
            }
            if !map
                .get(&TARGET_OBJECT)
                .is_some_and(|segment| segment.nattch == 0 && segment.lpid == 88)
            {
                return Err("fixed failure did not account the displaced target");
            }
            Ok(())
        })();
        drop(guard);
        cleanup();
        match result {
            Ok(()) => TestResult::Pass,
            Err(message) => TestResult::Fail(message),
        }
    }
    kernel_test_in!(
        "userspace/sysv_registry",
        smoke_shm_mremap_alias_abort_preserves_pending_during_fixed_punch
    );

    fn smoke_shm_mremap_relocation_mirrors_fixed_progress() -> TestResult {
        cleanup();
        insert_segment(SOURCE_OBJECT, 1);
        insert_segment(TARGET_OBJECT, 1);
        insert_attachment(SOURCE_OBJECT, SOURCE, alloc::vec![(SOURCE, 0x2000)]);
        insert_attachment(TARGET_OBJECT, TARGET, alloc::vec![(TARGET, 0x1000)]);
        let transaction = shm_mapping_transaction(AS_KEY);
        let guard = transaction.lock();
        let result = (|| {
            // SAFETY: the synthetic AS mapping transaction remains held.
            let prepared = unsafe {
                shm_prepare_mremap_shared_relocation_locked(
                    AS_KEY, SOURCE, 0x2000, TARGET, 0x1000, 101,
                )
            }
            .map_err(|_| "relocation prepare failed")?;
            prepared.abort_relocation(SOURCE, 0x2000, 0x1000, true, true);
            let attachments = SHM_ATTACHMENTS.lock();
            let map = attachments
                .as_ref()
                .ok_or("attachment table disappeared")?;
            if map.contains_key(&(AS_KEY, TARGET))
                || map
                    .get(&(AS_KEY, SOURCE))
                    .is_none_or(|entries| {
                        entries.len() != 1
                            || entries[0].fragments != alloc::vec![(SOURCE, 0x1000)]
                    })
            {
                return Err("failed fixed move did not mirror target+source shrink");
            }
            drop(attachments);
            let segments = SHM_SEGMENTS.lock();
            let map = segments.as_ref().ok_or("segment table disappeared")?;
            if map.get(&SOURCE_OBJECT).map(|segment| segment.nattch) != Some(1)
                || !map
                    .get(&TARGET_OBJECT)
                    .is_some_and(|segment| segment.nattch == 0 && segment.lpid == 101)
            {
                return Err("failed fixed move changed SysV attachment counts incorrectly");
            }
            Ok(())
        })();
        drop(guard);
        cleanup();
        match result {
            Ok(()) => TestResult::Pass,
            Err(message) => TestResult::Fail(message),
        }
    }
    kernel_test_in!(
        "userspace/sysv_registry",
        smoke_shm_mremap_relocation_mirrors_fixed_progress
    );

    fn smoke_shm_mremap_alias_fixed_commit_replaces_target_then_opens_source() -> TestResult {
        cleanup();
        insert_segment(SOURCE_OBJECT, 1);
        insert_segment(TARGET_OBJECT, 1);
        insert_attachment(SOURCE_OBJECT, SOURCE, alloc::vec![(SOURCE, 0x1000)]);
        insert_attachment(TARGET_OBJECT, TARGET, alloc::vec![(TARGET, 0x1000)]);
        let transaction = shm_mapping_transaction(AS_KEY);
        let guard = transaction.lock();
        let result = (|| {
            // SAFETY: the synthetic AS mapping transaction remains held.
            let prepared = unsafe {
                shm_prepare_mremap_shared_alias_locked(AS_KEY, SOURCE, 0x1000, TARGET, 99)
            }
            .map_err(|_| "prepare failed")?;
            prepared.commit(true);
            let entries = SHM_ATTACHMENTS.lock();
            let target = entries
                .as_ref()
                .and_then(|map| map.get(&(AS_KEY, TARGET)))
                .ok_or("committed destination disappeared")?;
            if target.len() != 1
                || (target[0].ipc_ns, target[0].shmid) != SOURCE_OBJECT
                || target[0].pending_mremap.is_some()
            {
                return Err("fixed commit punched the prepared alias or retained its target");
            }
            drop(entries);
            let segments = SHM_SEGMENTS.lock();
            let map = segments.as_ref().ok_or("segment table disappeared")?;
            if !map
                .get(&SOURCE_OBJECT)
                .is_some_and(|segment| segment.nattch == 2 && segment.lpid == 99)
                || !map
                    .get(&TARGET_OBJECT)
                    .is_some_and(|segment| segment.nattch == 0 && segment.lpid == 99)
            {
                return Err("fixed commit produced incorrect source/target nattch accounting");
            }
            Ok(())
        })();
        drop(guard);
        cleanup();
        match result {
            Ok(()) => TestResult::Pass,
            Err(message) => TestResult::Fail(message),
        }
    }
    kernel_test_in!(
        "userspace/sysv_registry",
        smoke_shm_mremap_alias_fixed_commit_replaces_target_then_opens_source
    );

    fn smoke_shm_mremap_alias_rejects_partial_sysv_source() -> TestResult {
        cleanup();
        insert_segment(SOURCE_OBJECT, 1);
        insert_attachment(SOURCE_OBJECT, SOURCE, alloc::vec![(SOURCE, 0x1000)]);
        let transaction = shm_mapping_transaction(AS_KEY);
        let guard = transaction.lock();
        // SAFETY: the synthetic AS mapping transaction remains held.
        let result = unsafe {
            shm_prepare_mremap_shared_alias_locked(AS_KEY, SOURCE, 0x2000, TARGET, 111)
        };
        let passed = matches!(result, Err(ShmMremapPrepareError::PartialSysvSource))
            && !SHM_ATTACHMENTS
                .lock()
                .as_ref()
                .is_some_and(|map| map.contains_key(&(AS_KEY, TARGET)));
        drop(guard);
        cleanup();
        if passed {
            TestResult::Pass
        } else {
            TestResult::Fail("partial SysV source prepared a destination alias")
        }
    }
    kernel_test_in!(
        "userspace/sysv_registry",
        smoke_shm_mremap_alias_rejects_partial_sysv_source
    );
}

/// Final `ipc_namespace` teardown removes every public id immediately. SHM
/// mappings survive exactly as Linux VMAs do; their namespace-qualified
/// attachment records retain the backing until final detach/process exit.
#[cfg(feature = "container")]
pub(crate) fn shm_ipc_namespace_drop(ipc_ns: u64) {
    let mut destroy = alloc::vec::Vec::new();
    {
        let mut segments = SHM_SEGMENTS.lock();
        let map = segments.get_or_insert_with(alloc::collections::BTreeMap::new);
        let objects: alloc::vec::Vec<_> = map
            .keys()
            .filter(|(namespace, _)| *namespace == ipc_ns)
            .copied()
            .collect();
        for object in objects {
            let Some(seg) = map.get_mut(&object) else {
                continue;
            };
            seg.removed = true;
            seg.key = 0;
            if seg.nattch == 0 {
                if let Some(seg) = map.remove(&object) {
                    destroy.push(seg.handle);
                }
            }
        }
    }
    if let Some(vtable) = shmem_vtable() {
        for handle in destroy {
            if handle != 0 {
                (vtable.destroy)(handle);
            }
        }
    }
}

// ── Yield / Sleep — Ok ─────────────────────────────────────────────

// ── Sleep ─────────────────────────────────────────────────────────
//
// `Syscall::Sleep` carries the requested sleep in nanoseconds in
// `arg0`. Two paths:
//
//   1. Polling-future path (the normal case for `UserTaskFuture`-
//      driven user tasks): stash an absolute deadline on the
//      current `UserTaskCtx`, mark the saved RAX = 0, save the
//      user state, and longjmp back into the polling routine
//      with `EXIT_REASON_YIELDED`. The next poll observes the
//      deadline, returns `Pending` until it expires, and only
//      then re-enters user mode at the post-syscall instruction.
//      This frees the executor to round-robin other ready tasks
//      while the sleeper is parked.
//   2. Fallback busy-wait (test trampolines / pre-polling-future
//      contexts): spin until monotonic_ns advances past the
//      deadline, ticking registered sleep_pumps so background
//      kernel work makes forward progress.
// ── GetRandom — arg0=buf, arg1=len, arg2=flags(ignored) ─────────────
//
// Fill the caller's user-mode buffer with random bytes. Stage-4
// backing is a Park-Miller LCG seeded from monotonic_ns() — NOT
// cryptographically secure (matches `crypto::per_task_rng`'s seed
// quality, which carries the same caveat). When `arch/` exposes a
// HW entropy probe (RDSEED on x86_64, RNDR on aarch64), the seed
// path here gets replaced.
//
// Single-threaded user mode lets the static state work without a
// lock; when SMP user tasks land this should grow per-task storage.
//
// Output bytes are written via `write_volatile` to stay safe against
// LLVM eliding the loop on `&mut [u8]` views into user memory.

/// Park-Miller minimal-standard LCG state. Initialised lazily on
/// first call from `monotonic_ns()`. The value lives in an
/// `AtomicU64` so a future SMP rework can keep the same shape.
static GETRANDOM_STATE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// CPUID feature cache: bit 0 = RDRAND probed, bit 1 = RDRAND
/// available, bit 2 = RDSEED probed, bit 3 = RDSEED available.
/// Computed lazily on first use; subsequent calls bit-test.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
static RNG_FEATURES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(target_arch = "x86_64")]
fn cpu_has_rdrand() -> bool {
    use core::sync::atomic::Ordering;
    let f = RNG_FEATURES.load(Ordering::Acquire);
    if f & 1 != 0 {
        return f & 2 != 0;
    }
    // CPUID leaf 1: ECX bit 30 = RDRAND. RBX is reserved by LLVM
    // so we save/restore it manually around the cpuid.
    let ecx: u32;
    // SAFETY: `cpuid` is unprivileged and always available on x86_64; we
    // save/restore `rbx` (LLVM-reserved) around it and read leaf 1's ECX.
    // No memory operands, so no aliasing concerns.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") _,
            options(preserves_flags),
        );
    }
    let avail = (ecx >> 30) & 1 != 0;
    let new = f | 1 | if avail { 2 } else { 0 };
    RNG_FEATURES.store(new, Ordering::Release);
    avail
}

#[cfg(target_arch = "x86_64")]
fn cpu_has_rdseed() -> bool {
    use core::sync::atomic::Ordering;
    let f = RNG_FEATURES.load(Ordering::Acquire);
    if f & 4 != 0 {
        return f & 8 != 0;
    }
    // CPUID leaf 7 sub-leaf 0: EBX bit 18 = RDSEED. Save/restore
    // rbx through r9 since LLVM owns rbx.
    let ebx: u32;
    // SAFETY: `cpuid` is unprivileged and always available on x86_64; we
    // save/restore `rbx` (LLVM-reserved) and shuttle its result through `r9d`
    // to read leaf 7 sub-leaf 0's EBX. No memory operands.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov r9d, ebx",
            "pop rbx",
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => _,
            out("edx") _,
            out("r9d") ebx,
            options(preserves_flags),
        );
    }
    let avail = (ebx >> 18) & 1 != 0;
    let new = f | 4 | if avail { 8 } else { 0 };
    RNG_FEATURES.store(new, Ordering::Release);
    avail
}

#[cfg(target_arch = "x86_64")]
fn rdrand_u64() -> Option<u64> {
    if !cpu_has_rdrand() {
        return None;
    }
    // RDRAND can fail (carry-flag clear); retry up to 10 times per
    // Intel's recommendation in the SDM.
    for _ in 0..10 {
        let v: u64;
        let cf: u8;
        // SAFETY: `rdrand` is gated by `cpu_has_rdrand()` above; it writes a random
        // value to `v` and the carry flag (success) captured into `cf`. No memory operands.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc {cf}",
                v = out(reg) v,
                cf = out(reg_byte) cf,
                options(nostack, preserves_flags),
            );
        }
        if cf != 0 {
            return Some(v);
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn rdseed_u64() -> Option<u64> {
    if !cpu_has_rdseed() {
        return None;
    }
    // RDSEED is true entropy and may take many retries on
    // contention; SDM recommends ~32 attempts before bailing.
    for _ in 0..32 {
        let v: u64;
        let cf: u8;
        // SAFETY: `rdseed` is gated by `cpu_has_rdseed()` above; it writes a random
        // value to `v` and the carry flag (success) captured into `cf`. No memory operands.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::arch::asm!(
                "rdseed {v}",
                "setc {cf}",
                v = out(reg) v,
                cf = out(reg_byte) cf,
                options(nostack, preserves_flags),
            );
        }
        if cf != 0 {
            return Some(v);
        }
    }
    None
}

#[cfg(not(target_arch = "x86_64"))]
fn rdrand_u64() -> Option<u64> {
    None
}
#[cfg(not(target_arch = "x86_64"))]
fn rdseed_u64() -> Option<u64> {
    None
}

fn next_random_u32() -> u32 {
    use core::sync::atomic::Ordering;
    // Cryptographic-grade entropy first: prefer RDSEED (true
    // entropy from an on-die ring oscillator per Intel DRNG §3),
    // fall back to RDRAND (PRNG seeded from RDSEED), fall back to
    // the LCG only when neither instruction is available.
    if let Some(v) = rdseed_u64() {
        return (v >> 32) as u32 ^ v as u32;
    }
    if let Some(v) = rdrand_u64() {
        return (v >> 32) as u32 ^ v as u32;
    }
    let mut s = GETRANDOM_STATE.load(Ordering::Relaxed);
    if s == 0 {
        // Lazy seed from monotonic_ns mixed with the cycle counter
        // so two boots see different streams.
        let ns = narf_scheduler::narf_time::monotonic_ns();
        let cy = narf_scheduler::narf_time::now_cycles();
        s = (ns ^ cy.wrapping_mul(0x9E37_79B9_7F4A_7C15)) & 0x7FFF_FFFF;
        if s == 0 {
            s = 1;
        }
    }
    // x' = x * 48271 mod (2^31 - 1)
    s = (s.wrapping_mul(48271)) % 0x7FFF_FFFF;
    GETRANDOM_STATE.store(s, Ordering::Relaxed);
    s as u32
}

/// Registry of "background-work" callbacks that run inside the
/// `sys_sleep` busy-wait. Subsystems whose forward progress is
/// gated on the scheduler's polling tick — chiefly the FB drain
/// task — register a pump here at boot so their work continues
/// even while a user task is sleeping.
///
/// Re-export of the canonical sleep-pump registry, which lives in
/// narf-scheduler so driver crates can call `run()` from sync spin
/// loops without depending on narf-userspace. Existing call sites
/// (`sys_sleep`'s busy-wait + the FB drain pump registration)
/// continue to use `narf_userspace::handlers::sleep_pumps`.
pub use narf_scheduler::sleep_pumps;
