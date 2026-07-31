// ── Signal wakers ───────────────────────────────────────────────────

static SIGNAL_WAKERS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, core::task::Waker>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn signal_waker_init() {
    *SIGNAL_WAKERS.lock() = Some(alloc::collections::BTreeMap::new());
}

pub fn register_signal_waker(task_id: u64, waker: core::task::Waker) {
    let mut g = SIGNAL_WAKERS.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task_id, waker);
    }
}

pub fn wake_signal(task_id: u64) {
    // Deref the ctx UNDER the registry lock (see `with_user_task_ctx`) so a
    // concurrent task-exit + box-drop on another CPU can't free it mid-deref.
    crate::user_task::with_user_task_ctx(task_id, |uctx| {
        // If the task is blocked in an infinite wait (pause, epoll_wait),
        // clear the deadline to wake it.
        if uctx.sleep_deadline_ns.load(Ordering::Acquire) == u64::MAX {
            uctx.sleep_deadline_ns.store(0, Ordering::Release);
        }
    });
    let waker = {
        let mut g = SIGNAL_WAKERS.lock();
        g.as_mut().and_then(|m| m.remove(&task_id))
    };
    if let Some(w) = waker {
        w.wake();
    }
}

pub fn drop_signal_waker(task_id: u64) {
    let mut g = SIGNAL_WAKERS.lock();
    if let Some(m) = g.as_mut() {
        m.remove(&task_id);
    }
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

#[allow(clippy::type_complexity)]
static IO_WAKERS: [narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, core::task::Waker>>,
>; WAKE_SHARDS] = [const { narf_lib::sync::IrqSafeSpinLock::new(None) }; WAKE_SHARDS];

pub fn io_waker_init() {
    for shard in IO_WAKERS.iter() {
        *shard.lock() = Some(alloc::collections::BTreeMap::new());
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
    let mut g = TCB_OWNER[tcb_owner_shard(tcb_id)].lock();
    if let Some(m) = g.as_mut() {
        m.remove(&tcb_id);
    }
}

fn tcb_owner(tcb_id: u32) -> Option<u64> {
    let g = TCB_OWNER[tcb_owner_shard(tcb_id)].lock();
    g.as_ref().and_then(|m| m.get(&tcb_id).copied())
}

/// Register `task_id`'s waker as parked on net I/O readiness. Called
/// from the user-task poll routine while a task blocks in epoll/poll.
pub fn register_io_waiter(task_id: u64, waker: core::task::Waker) {
    let mut g = IO_WAKERS[io_waker_shard(task_id)].lock();
    if let Some(m) = g.as_mut() {
        m.insert(task_id, waker);
    }
}

/// Remove `task_id`'s I/O waker without firing it (the task woke for
/// another reason / is returning from the syscall).
pub fn drop_io_waiter(task_id: u64) {
    let mut g = IO_WAKERS[io_waker_shard(task_id)].lock();
    if let Some(m) = g.as_mut() {
        m.remove(&task_id);
    }
}

/// Wake every task parked on net I/O readiness. Installed as the
/// `narf_net::readiness` hook at boot; invoked from the TCP receive
/// path when a socket becomes readable. Clears each task's finite
/// sleep deadline so its re-poll falls through to re-check readiness
/// instead of re-parking on the stale deadline.
/// Clear a task's finite sleep deadline (so its re-poll re-checks
/// readiness) and fire its waker.
pub(crate) fn wake_one(task_id: u64, w: core::task::Waker) {
    // Deref under the registry lock (see `with_user_task_ctx`) so a concurrent
    // task-exit + box-drop can't free the ctx mid-deref.
    crate::user_task::with_user_task_ctx(task_id, |uctx| {
        uctx.sleep_deadline_ns.store(0, Ordering::Release);
    });
    w.wake();
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
        if let Some(owner) = tcb_owner(key as u32) {
            // Owner known: targeted wake iff it's parked. Its waker lives in
            // the owner's shard (keyed by task id).
            let waker = {
                let mut g = IO_WAKERS[io_waker_shard(owner)].lock();
                g.as_mut().and_then(|m| m.remove(&owner))
            };
            if let Some(w) = waker {
                wake_one(owner, w);
            }
            return;
        }
        // Untracked key → fall through to wake-all (safety net).
    }
    wake_all_io_waiters();
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
        if let Some(m) = g.as_mut() {
            wakers.extend(core::mem::take(m));
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

static TASK_LOOKUP: narf_lib::sync::IrqSafeSpinLock<Option<TaskIdLookupFn>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Install the function that returns the current task's raw id.
/// Boot wires `|| scheduler::current_task_id().raw()` here.
pub fn install_task_id_lookup(lookup: TaskIdLookupFn) {
    *TASK_LOOKUP.lock() = Some(lookup);
}

/// Test hook: drop any installed current-task lookup so
/// `current_task_id()` falls back to 0. The in-kernel smoke tests
/// share one boot, and `TASK_LOOKUP` is a process-global — without a
/// reset, a test that installs a fixed-id lookup leaks it into later
/// tests that assume the default (e.g. signalfd / per-tty pgrp tests).
pub fn __test_reset_task_id_lookup() {
    *TASK_LOOKUP.lock() = None;
}

pub fn current_task_id() -> u64 {
    let f = *TASK_LOOKUP.lock();
    f.map(|lookup| lookup()).unwrap_or(0)
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

/// Spin-pump a Future to completion inside a syscall. Caller must
/// guarantee the future makes progress without external wakeups (the
/// kernel's block-device drivers — NVMe in particular — are
/// internally polled, so async FS futures complete after at most a
/// handful of re-polls). Bounded to 65 536 iterations as a hard
/// safety cap; returns `None` on overrun (caller surfaces EIO).
pub(crate) fn poll_blocking<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    // SAFETY: same waker as poll_once; never delivers wake events.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut ctx = Context::from_waker(&waker);
    // SAFETY: we own `fut` by value; pin to the stack temporary.
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
    // Busy-poll budget. This must be generous enough to cover a future that is
    // legitimately *waiting* — not stuck — for a long time. The worst case is
    // contended block I/O: two execve loads on different CPUs serialise on the
    // ext2 volume's scratch DMA buffer, so the loser busy-spins here while the
    // winner streams a whole ~1 MiB binary block-by-block. A small budget made
    // the loser time out → read returns None → execve EINVALs (the "concurrent
    // pipe stages fail" bug). The bound still exists only as a backstop against
    // a genuinely wedged future.
    for _ in 0..4_000_000u64 {
        match pinned.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return Some(v),
            Poll::Pending => continue,
        }
    }
    None
}

/// Poll a block-I/O future to completion, keeping the SAME future alive for the
/// entire wait. Unlike `poll_blocking`'s small budget, this uses a huge backstop
/// so a merely-contended read (KDE launching dozens of procs at once, all
/// streaming binaries off ext2) completes rather than timing out. Crucially it
/// NEVER drops the future mid-flight: a dropped read leaves its in-flight
/// virtio-blk request DMA'ing into a scratch buffer that has been returned to
/// the pool and reused → corruption. Only a genuinely-wedged device reaches the
/// ceiling (returns None); callers that must not truncate treat that as a hard
/// stop, not EOF.
pub(crate) fn poll_io_to_completion<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    // SAFETY: same no-op waker as poll_blocking; the block-completion IRQ / pump
    // advances the future's readiness, which the re-poll observes.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut ctx = Context::from_waker(&waker);
    // SAFETY: we own `fut` by value; pin to the stack temporary.
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
    for _ in 0..2_000_000_000u64 {
        match pinned.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return Some(v),
            Poll::Pending => continue,
        }
    }
    None
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

static AS_LOOKUP: narf_lib::sync::IrqSafeSpinLock<Option<AsLookupFn>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
static ALL_AS_LOOKUP: narf_lib::sync::IrqSafeSpinLock<Option<AllAsLookupFn>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Install the function that resolves "what's the currently-
/// polling task's address space?". The kernel boot code registers
/// `|| scheduler::address_space_of(scheduler::current_task_id())`
/// here; handlers below call through. Absent registration,
/// `current_address_space()` returns `None` and AS-dependent
/// handlers return `InvalidOp`.
pub fn install_address_space_lookup(lookup: AsLookupFn) {
    *AS_LOOKUP.lock() = Some(lookup);
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
    *AS_LOOKUP.lock()
}

/// Restore (or clear) the AS lookup — the counterpart to
/// `install_address_space_lookup` that also accepts `None`.
pub fn restore_address_space_lookup(lookup: Option<AsLookupFn>) {
    *AS_LOOKUP.lock() = lookup;
}

fn current_address_space() -> Option<Arc<AddressSpace>> {
    let f = *AS_LOOKUP.lock();
    f.and_then(|lookup| lookup())
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
    if rip == 0 {
        None
    } else {
        Some((rip, rsp))
    }
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
    completion_channel, submission_channel, Completion, CompletionDrain, CompletionQueue,
    SharedRing, Submission, SubmissionDrain, SubmissionQueue,
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
pub fn init_per_task_state() {
    bootstrap_init();
    cwd_init();
    brk_init();
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
    wait_init();
    pkey_init();
    narf_filesystem::fuse_conn::install_request_context_provider(fuse_request_context);
    #[cfg(feature = "linux-compat")]
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
        core::ptr::write_bytes(sq_phys.raw() as *mut u8, 0, 4096);
        core::ptr::write_bytes(cq_phys.raw() as *mut u8, 0, 4096);
        SqRing::init_in(sq_phys.raw() as *mut SqRing);
        CqRing::init_in(cq_phys.raw() as *mut CqRing);
    }

    let sq_vaddr = MMAP_CURSOR.fetch_add(0x1000, Ordering::Relaxed);
    let cq_vaddr = MMAP_CURSOR.fetch_add(0x1000, Ordering::Relaxed);

    as_ref
        .map_region(Region {
            base: VirtAddr::new(sq_vaddr),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![sq_phys],
        })
        .map_err(|_| ())?;
    as_ref
        .map_region(Region {
            base: VirtAddr::new(cq_vaddr),
            len: 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
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
    // Record the access mode (O_RDONLY/O_WRONLY/O_RDWR) plus the settable
    // status flags (O_NONBLOCK | O_APPEND | O_DIRECT) on the fd, so
    // `fcntl(F_GETFL)` reports both. glibc's `fdopen(fd, "w")` reads the
    // access mode via F_GETFL and rejects the stream with EINVAL if it
    // doesn't match the requested mode — systemd fdopens a `cgroup.procs`
    // it opened O_WRONLY, so a dropped access mode failed that check.
    // (O_NONBLOCK matters on its own for libinput's evdev nodes — see
    // `InputEventFile::nonblock_read_eagain`.)
    let open_status_flags = (flags as u32) & (crate::fd::O_ACCMODE | crate::fd::O_SETFL_MASK);
    // user-runtime's `open` wrapper checks `r == !0u64` for failure
    // (the asm wrapper observes only the value register, not the
    // status word), so the kernel must mirror that sentinel rather
    // than the generic `invalid_op` shape.
    let fail = SyscallReturn::ok(!0u64);
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
        resolve_cwd_path(task, &path_owned_raw)
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
    let proc_prefix = apply_chroot("/proc");
    let proc_magic_path = path_owned == proc_prefix
        || (path_owned.starts_with(proc_prefix.as_str())
            && path_owned.as_bytes().get(proc_prefix.len()) == Some(&b'/'));
    let path_owned = if mnt_len == 0 && !proc_magic_path {
        resolve_vfs_symlink_path(&path_owned, flags & 0o400000 == 0).unwrap_or(path_owned)
    } else {
        path_owned
    };
    let path: &str = &path_owned;

    // RLIMIT_NOFILE enforcement: a task may not exceed its soft limit of
    // open descriptors. Linux returns EMFILE from the fd-creating call.
    // RLIMIT_NOFILE is index 7; `.0` is the soft (current) limit.
    {
        let nofile_cur = rlimits_of(task)[7].0;
        if crate::fd::open_fds(task).len() as u64 >= nofile_cur {
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    }

    // Following a proc namespace magic link yields an nsfs-like fd whose
    // held namespace can be consumed by setns(2). O_PATH|O_NOFOLLOW must
    // still open the symlink itself, so leave that case to the nofollow path.
    #[cfg(feature = "container")]
    if mnt_len == 0 && flags & 0o400000 == 0 {
        if let Some(nsfd) = proc_namespace_fd_from_path(task, path, &proc_prefix) {
            let ops: Arc<dyn narf_filesystem::FileOps> = nsfd;
            let new_fd = fd::with_table(task, |table| {
                table.open(crate::fd::FdEntry {
                    ops,
                    offset: 0,
                    flags: 0,
                    status_flags: open_status_flags,
                })
            });
            match new_fd {
                Some(n) => {
                    #[cfg(feature = "linux-compat")]
                    crate::mqueue::register_fd_path(task, n, path, current_mount_id_at(path));
                    ctx.set_return(SyscallReturn::ok(n as u64));
                }
                None => ctx.set_return(fail),
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
                let new_fd = fd::with_table(task, |t| {
                    t.open(crate::fd::FdEntry {
                        ops: node,
                        offset: 0,
                        flags: 0,
                        status_flags: open_status_flags,
                    })
                });
                match new_fd {
                    Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
                    None => ctx.set_return(fail),
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
                let new_fd = fd::with_table(task, |t| {
                    t.open(crate::fd::FdEntry {
                        ops: lops,
                        offset: 0,
                        flags: 0,
                        status_flags: open_status_flags,
                    })
                });
                match new_fd {
                    Some(n) => {
                        #[cfg(feature = "linux-compat")]
                        crate::mqueue::register_fd_path(task, n, path, current_mount_id_at(path));
                        ctx.set_return(SyscallReturn::ok(n as u64));
                    }
                    None => ctx.set_return(fail),
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
    let ops = if mnt_len == 0 {
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
                ctx.set_return(fail);
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
    if (ops.is_none() || resolved_is_dir) && mnt_len == 0 {
        if let Some(dirops) = resolve_dir_absolute(path) {
            let new_fd = fd::with_table(task, |t| {
                t.open(crate::fd::FdEntry {
                    ops: alloc::sync::Arc::new(DirFdFile { dir: dirops }),
                    offset: 0,
                    flags: 0,
                    status_flags: 0,
                })
            });
            match new_fd {
                Some(n) => {
                    // Record the backing path so /proc/<pid>/fd/<n> readlinks
                    // to it (musl realpath, lsof, opendir-on-fd). See fd_path_of.
                    #[cfg(feature = "linux-compat")]
                    crate::mqueue::register_fd_path(task, n, path, current_mount_id_at(path));
                    ctx.set_return(SyscallReturn::ok(n as u64));
                }
                None => ctx.set_return(fail),
            }
            return;
        }
    }

    // O_CREAT path: when the lookup misses and the caller asked for
    // creation, route through the parent directory's `create()`. The
    // explicit-mount form is rare on the create path and not yet
    // wired; absolute paths are the supported entry.
    #[cfg(feature = "linux-compat")]
    let mut created = false;
    let ops = match ops {
        Some(o) => o,
        None if (flags & O_CREAT) != 0 && mnt_len == 0 => {
            // Async parent resolution so O_CREAT works in subdirectories of
            // a disk-backed (ext2) rootfs, not just sync-resolvable mounts.
            match resolve_parent_dir_async(path)
                .map(|(parent, leaf)| poll_blocking(parent.create(&leaf)))
            {
                Some(Some(Ok(o))) => {
                    #[cfg(feature = "linux-compat")]
                    {
                        created = true;
                    }
                    o
                }
                _ => {
                    ctx.set_return(fail);
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
        let new_fd = fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: open_status_flags,
            })
        });
        match new_fd {
            Some(n) => {
                #[cfg(feature = "linux-compat")]
                crate::mqueue::register_fd_path(task, n, path, current_mount_id_at(path));
                ctx.set_return(SyscallReturn::ok(n as u64));
            }
            None => ctx.set_return(fail),
        }
        return;
    }

    // POSIX-2017 permission check. The accessor's UID/GID come from
    // the per-task uidgid table; the file's owners + perms come from
    // its FileOps trait. UID 0 (root) shortcuts; non-root must own
    // a matching r/w bit per POSIX `open(2)` description. Today most
    // FSes report (uid=0, gid=0, perms=0o666) so non-root tasks see
    // the "other" triplet's rw bits and pass; the gate is structural
    // until ext2/minix start surfacing real owners.
    let stat = ops.stat();
    let (file_uid, file_gid) = ops.owners();
    // O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2. Bits 0..1 of flags.
    let access_mode = flags & 0o3;
    let want_r = access_mode == 0 || access_mode == 2;
    let want_w = access_mode == 1 || access_mode == 2;
    // SECURITY: build the Accessor through the single translation
    // funnel so a task inside a user-ns has its in-ns fsuid/fsgid mapped
    // to HOST-absolute ids before posix_access_ok (which treats uid==0
    // as host-root). File owners stay host-absolute. See current_accessor.
    if !narf_filesystem::posix_access_ok(
        narf_filesystem::FileOwner {
            uid: file_uid,
            gid: file_gid,
            perms: stat.mode.perms,
        },
        current_accessor(task),
        narf_filesystem::AccessRequest {
            read: want_r,
            write: want_w,
            exec: false,
        },
    ) {
        ctx.set_return(fail);
        return;
    }

    // Landlock: a self-restricted task's open must be permitted by its
    // active rulesets, else EACCES.
    #[cfg(feature = "linux-compat")]
    if let Err(denied) = crate::landlock::landlock_check_open(task, path, want_r, want_w) {
        ctx.set_return(denied);
        return;
    }

    // PTY clone-on-open: `/dev/ptmx` is a singleton FileOps that exists
    // only to be a lookup target; each `open()` allocates a fresh `Pty`
    // pair via `open_ptmx()` and installs the master here. Linux:
    // `drivers/tty/pty.c::ptmx_open`. The `is_ptmx_clone()` trait hook
    // keeps the filesystem crate free of any fd-table awareness.
    let ops = if ops.is_ptmx_clone() {
        let master = narf_filesystem::devfs_pty::open_ptmx();
        master as Arc<dyn narf_filesystem::FileOps>
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
        let perms = stat.mode.perms;
        let (fifo_uid, fifo_gid) = ops.owners();
        let nonblock = flags & (crate::fd::O_NONBLOCK as u64) != 0;
        open_fifo(
            ctx,
            shared,
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

    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: open_status_flags,
        })
    }) {
        Some(n) => n,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // inotify: record the fd's path (so a later write can fire IN_MODIFY)
    // and emit IN_CREATE (new file) + IN_OPEN against any matching watch.
    #[cfg(feature = "linux-compat")]
    {
        crate::mqueue::register_fd_path(task, new_fd, path, current_mount_id_at(path));
        if created {
            crate::mqueue::notify_create(path, false);
        }
        crate::mqueue::notify_open(path);
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
    let handle = Arc::new(narf_filesystem::fifo::FifoHandle::open(
        shared.clone(),
        node_ino,
        perms,
        uid,
        gid,
        can_read,
        can_write,
    )) as Arc<dyn narf_filesystem::FileOps>;
    let status_flags = access_mode as u32 | if nonblock { crate::fd::O_NONBLOCK } else { 0 };
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: handle,
            offset: 0,
            flags: 0,
            status_flags,
        })
    }) {
        Some(n) => n,
        None => {
            ctx.set_return(SyscallReturn::ok(!0u64));
            return;
        }
    };

    // Peer already present (or O_RDWR / O_NONBLOCK) → return the fd now.
    let peer_ready = rdwr
        || nonblock
        || (can_read && shared.writer_count() > 0)
        || (can_write && shared.reader_count() > 0);
    if peer_ready {
        #[cfg(feature = "linux-compat")]
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
    // Read the handle's direction + peer counts through its shared buffer.
    let ready = fd::with_table(task, |t| {
        t.get(fd).and_then(|e| {
            let am = e.status_flags & crate::fd::O_ACCMODE;
            e.ops.fifo_shared().map(|shared| {
                // The pending open was, by construction, a single-direction
                // blocking open: O_RDONLY waits for a writer, O_WRONLY for a
                // reader. Its own handle is counted in exactly one of the peer
                // totals, so "peer present" is "the OTHER side has >= 1".
                if am == crate::fd::O_WRONLY {
                    shared.reader_count() > 0
                } else {
                    shared.writer_count() > 0
                }
            })
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

/// Park the current task on the ~1ms timer wheel and RIP-rewind so the `open`
/// syscall re-executes (and `resume_fifo_open` re-checks the peer). Falls back
/// to returning the fd in a non-executor (kernel-test) context, where no
/// scheduler can drive the re-check.
fn fifo_park_or_finish(ctx: &mut dyn TrapContext, fd: u32) {
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
        let resume_rip = ctx.rip().wrapping_sub(2);
        ctx.set_rip(resume_rip);
        // SAFETY: `uctx` is the live per-task ctx; we hold the only reference
        // while setting the deadline + saving the RIP-rewound CPU state before
        // the yield hook hands the task to the executor.
        unsafe {
            let uc = &*uctx;
            uc.sleep_deadline_ns
                .store(dl, core::sync::atomic::Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
        // unreachable — hook() longjmps to the executor
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

/// Drain a fanotify group's queued events into `buf` as
/// `struct fanotify_event_metadata` records, opening a fresh fd to each
/// affected object in `task`'s fd table. Called from sys_read with NO
/// fd-table lock held (the install below needs it).
#[cfg(feature = "linux-compat")]
fn fanotify_read_into(task: u64, gid: u64, buf: &mut [u8]) -> usize {
    let cap = buf.len() / crate::mqueue::FAN_EVENT_METADATA_LEN;
    if cap == 0 {
        return 0;
    }
    let events = crate::mqueue::fanotify_drain(gid, cap);
    let mut written = 0usize;
    for (path, mask, pid) in events {
        let fd = fanotify_open_object(task, &path);
        let meta = crate::mqueue::build_fan_metadata(mask, fd, pid);
        buf[written..written + crate::mqueue::FAN_EVENT_METADATA_LEN].copy_from_slice(&meta);
        written += crate::mqueue::FAN_EVENT_METADATA_LEN;
    }
    written
}

/// Resolve `abs` and install a fresh read fd for it in `task`'s table;
/// returns the fd number, or FAN_NOFD (-1) on failure.
#[cfg(feature = "linux-compat")]
fn fanotify_open_object(task: u64, abs: &str) -> i32 {
    let root_rel = narf_filesystem::registry()
        .resolve_absolute(abs, |fs, rel| (fs.root(), alloc::string::String::from(rel)));
    let (root, rel) = match root_rel {
        Some(x) => x,
        None => return -1,
    };
    let ops = match poll_blocking(narf_filesystem::resolve_async(root, &rel)) {
        Some(Ok(o)) => o,
        _ => return -1,
    };
    match fd::with_table(task, |t| {
        t.open(fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
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

#[cfg(feature = "linux-compat")]
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
#[cfg(feature = "linux-compat")]
const F_DUPFD_CLOEXEC: u64 = 1030;
/// Linux fcntl `F_ADD_SEALS` (1033) — add seal bits to a memfd.
const F_ADD_SEALS: u64 = 1033;
/// Linux fcntl `F_GET_SEALS` (1034) — read the seal word.
const F_GET_SEALS: u64 = 1034;

/// Linux EAGAIN value (11).
const EAGAIN_CODE: u64 = 11;
/// Linux EPERM (1) — returned as the value of the failed syscall
/// (sign-flipped at libc; we follow the existing -1 convention).
#[cfg(feature = "linux-compat")]
const _EPERM: u64 = 1;

/// Wire-stable `struct flock` (Linux x86_64 / aarch64 layout).
#[cfg(feature = "linux-compat")]
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

#[cfg(feature = "linux-compat")]
fn flock_size() -> usize {
    core::mem::size_of::<UFlock>()
}

/// Clear the current task's F_SETLKW park routing (uctx.flock_key).
/// Every fcntl lock-path exit calls this so a stale key can't make a
/// later unrelated park register on the flock waiter queue.
#[cfg(feature = "linux-compat")]
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

impl StatBuf {
    fn from_stat(s: narf_filesystem::Stat) -> Self {
        let ftype_bits: u32 = match s.mode.file_type {
            narf_filesystem::FileType::File => 0o100000,
            narf_filesystem::FileType::Dir => 0o040000,
            narf_filesystem::FileType::Symlink => 0o120000,
            narf_filesystem::FileType::Special => 0o020000,
            narf_filesystem::FileType::Socket => 0o140000,
            narf_filesystem::FileType::Fifo => 0o010000,
        };
        Self {
            size: s.size,
            blocks: s.blocks,
            mode: ftype_bits | (s.mode.perms as u32),
            _pad: 0,
            mtime_cycles: s.mtime_cycles,
        }
    }
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
fn mknod_common(path_uptr: u64, mode: u64, dev: u64) -> SyscallReturn {
    let fail = SyscallReturn::ok((-1i64) as u64);
    const S_IFMT: u64 = 0o170000;
    const S_IFDIR: u64 = 0o040000;
    const S_IFCHR: u64 = 0o020000;
    const S_IFBLK: u64 = 0o060000;
    const S_IFIFO: u64 = 0o010000;
    let path = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => return fail,
    };
    let path = resolve_cwd_path(current_task_id(), &path);
    let path_ref = {
        let t = path.trim_end_matches('/');
        if t.is_empty() {
            return fail;
        }
        t
    };
    let (parent, leaf) = match resolve_parent_dir_async(path_ref) {
        Some(p) => p,
        None => {
            return SyscallReturn::ok((-2i64) as u64); // -ENOENT
        }
    };
    let fmt = mode & S_IFMT;
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
    // A directory carries its permission bits on the DirOps side; `mkdir` has
    // no FileOps handle to persist a mode through here.
    if fmt == S_IFDIR {
        return if poll_blocking(parent.mkdir(&leaf)).map(|r| r.is_ok()) == Some(true) {
            SyscallReturn::ok(0)
        } else {
            fail
        };
    }
    // The created node handle, so the requested mode can be persisted below.
    let node: Option<Arc<dyn narf_filesystem::FileOps>> = if fmt == S_IFCHR || fmt == S_IFBLK {
        // A char/block device node (udev coldplug creating /dev/<name>). Route
        // to the directory's `mknod` so a devfs parent materialises a node that
        // stats as the right special device with st_rdev == dev. Filesystems
        // that don't support device nodes fall back to a plain file so the node
        // at least EXISTS (matching the old behaviour for the elogind sandbox
        // nodes). `dev` is the Linux dev_t as passed by userspace.
        match poll_blocking(parent.mknod(&leaf, narf_filesystem::FileType::Special, dev)) {
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
            let acc = current_accessor(current_task_id());
            let _ = poll_blocking(n.set_owners(acc.uid, acc.gid));
            let _ = poll_blocking(n.set_perms((mode & 0o777) as u16));
            SyscallReturn::ok(0)
        }
        None => fail,
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

#[cfg(feature = "linux-compat")]
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

    // ── Flag bits (fcntl.h AT_*) ─────────────────────────────────
    pub const AT_FDCWD: i32 = -100;
    pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
    pub const AT_NO_AUTOMOUNT: u32 = 0x800;
    pub const AT_EMPTY_PATH: u32 = 0x1000;
    pub const AT_STATX_SYNC_TYPE: u32 = 0x6000;
}

// Build a Linux-shaped struct stat from a `narf_filesystem::Stat`.
// Same conventions as sys_statx (uid/gid/atime not tracked).
#[cfg(feature = "linux-compat")]
fn linux_stat_from_fs(
    s: narf_filesystem::Stat,
    uid: u32,
    gid: u32,
    rdev: u64,
    ino: u64,
) -> linux_compat::Stat {
    let ftype_bits: u32 = match s.mode.file_type {
        narf_filesystem::FileType::File => 0o100000,
        narf_filesystem::FileType::Dir => 0o040000,
        narf_filesystem::FileType::Symlink => 0o120000,
        narf_filesystem::FileType::Special => 0o020000,
        narf_filesystem::FileType::Socket => 0o140000,
        narf_filesystem::FileType::Fifo => 0o010000,
    };
    let mode_word: u32 = ftype_bits | (s.mode.perms as u32 & 0o7777);
    let cpns = narf_time::cycles_per_ns().max(1) as u64;
    let mtime_ns = s.mtime_cycles / cpns;
    let mtime = linux_compat::Timespec {
        tv_sec: (mtime_ns / 1_000_000_000) as i64,
        tv_nsec: (mtime_ns % 1_000_000_000) as i64,
    };
    linux_compat::Stat {
        st_dev: 0,
        // Prefer the filesystem's real inode (distinct per file). Only fall
        // back to the size/mtime hash for synthetic filesystems that report
        // no inode (ino == 0) — and never for disk files, whose same-size
        // libraries would otherwise alias and break musl's DSO dedup.
        st_ino: if ino != 0 {
            ino
        } else {
            (s.mtime_cycles ^ (s.size << 1)) & 0x0fff_ffff_ffff_ffff
        },
        st_nlink: 1,
        st_mode: mode_word,
        st_uid: uid,
        st_gid: gid,
        __pad0: 0,
        st_rdev: rdev,
        st_size: s.size as i64,
        st_blksize: 4096,
        st_blocks: s.blocks as i64,
        st_atim: mtime,
        st_mtim: mtime,
        st_ctim: mtime,
        __unused: [0; 3],
    }
}

// Linux-ABI sys_stat: writes a 144-byte `struct stat`. Same path-
// resolution as the NARF-shape sys_stat, only the wire layout
// changes.

/// Shared body for the Linux path-stat family. `follow_final` selects
/// whether a trailing symlink is followed (plain `stat`/`fstatat`) or
/// stat'd as the link itself (`lstat` / `fstatat(AT_SYMLINK_NOFOLLOW)`).
#[cfg(feature = "linux-compat")]
fn stat_linux_common(ctx: &mut dyn TrapContext, path_ptr: u64, out_arg: u64, follow_final: bool) {
    // The previous shape matched NARF's `(path_ptr, path_len, out_ptr)`
    // triplet which is unreachable from musl: musl passes the statbuf in
    // arg1, we read it as `path_len`, copy_from_user bails on the "huge
    // length", every stat returns -1, errno = EPERM, busybox sh prints
    // "Operation not permitted" for every PATH-search candidate, and
    // every pipeline that touches an exec dies.
    let out_ptr = out_arg as *mut linux_compat::Stat;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let raw = match copy_user_cstr(path_ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    stat_linux_path(ctx, &raw, out_arg, follow_final);
}

/// Write a Linux `struct stat` for a path in the caller's visible namespace.
/// `raw` may be absolute or relative to the caller's cwd; callers of
/// `newfstatat(2)` first join its relative pathname to the supplied dirfd.
#[cfg(feature = "linux-compat")]
fn stat_linux_path(ctx: &mut dyn TrapContext, raw: &str, out_arg: u64, follow_final: bool) {
    let out_ptr = out_arg as *mut linux_compat::Stat;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
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
    let (s, ino, rdev) = match stat_ino_path_dir_aware_ext(path, follow_final) {
        Some(triple) => triple,
        None => {
            // Missing file → ENOENT, not the bare -1 (musl → EPERM). Probes
            // like libwayland's wl_socket_lock require the real errno.
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
            return;
        }
    };
    // Report the device node's rdev (major:minor) for PATH stat too: seatd /
    // libudev validate a device's type from a path stat before opening it, so
    // a 0 rdev makes them reject evdev nodes (weston input never opens).
    // Path stat has no fd handle to read owners from; owners default to root.
    let out = linux_stat_from_fs(s, 0, 0, rdev, ino);
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
        ctx.set_return(fail);
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
#[cfg(feature = "linux-compat")]
static MEMFD_ARCS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<usize, alloc::sync::Weak<crate::linux_compat::MemFdFile>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

#[cfg(feature = "linux-compat")]
fn memfd_arc_register(arc: &alloc::sync::Arc<crate::linux_compat::MemFdFile>) {
    let key = alloc::sync::Arc::as_ptr(arc) as usize;
    let mut g = MEMFD_ARCS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(key, alloc::sync::Arc::downgrade(arc));
}

#[cfg(feature = "linux-compat")]
pub(crate) fn memfd_arc_from_fd(
    task: u64,
    fd: u32,
) -> Option<alloc::sync::Arc<crate::linux_compat::MemFdFile>> {
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let mut g = MEMFD_ARCS.lock();
    let map = g.as_mut()?;
    let arc = map.get(&raw)?.upgrade();
    if arc.is_none() {
        map.remove(&raw);
    }
    arc
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

/// Map an `FsError` from a delete-family op to the Linux errno userspace
/// expects. `NotFound` → ENOENT (the missing-name case), a directory
/// target → EISDIR (MemFs flags that as `InvalidPath`), a read-only mount
/// → EROFS; everything else keeps the generic -1 sentinel (musl EPERM).
fn unlink_errno(e: narf_filesystem::FsError) -> u64 {
    use narf_filesystem::FsError;
    let code: i64 = match e {
        FsError::NotFound => -2,     // -ENOENT
        FsError::InvalidPath => -21, // -EISDIR
        FsError::ReadOnly => -30,    // -EROFS
        _ => -1,
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
fn rmdir_errno(e: narf_filesystem::FsError) -> u64 {
    use narf_filesystem::FsError;
    let code: i64 = match e {
        FsError::NotFound => -2,     // -ENOENT
        FsError::Busy => -39,        // -ENOTEMPTY
        FsError::InvalidPath => -20, // -ENOTDIR
        FsError::ReadOnly => -30,    // -EROFS
        FsError::Unsupported => -1,  // -EPERM (fs can't rmdir)
        _ => -1,
    };
    code as u64
}

/// Map an `FsError` from `DirOps::rename` to the Linux errno userspace
/// expects. `NotFound` → ENOENT (source is gone), `Busy` → EEXIST,
/// `InvalidPath` → EINVAL, `ReadOnly` → EROFS, everything else → EPERM.
/// Never a bare -1 → systemd renames propagation dirs during mount
/// teardown and a spurious EPERM there aborts the whole unit.
fn rename_errno(e: narf_filesystem::FsError) -> u64 {
    use narf_filesystem::FsError;
    let code: i64 = match e {
        FsError::NotFound => -2,     // -ENOENT
        FsError::Busy => -17,        // -EEXIST
        FsError::InvalidPath => -22, // -EINVAL
        FsError::ReadOnly => -30,    // -EROFS
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
            // S_IFSOCK node disappear.
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
    let res = narf_filesystem::registry().resolve_two_parents_absolute(
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
                #[cfg(feature = "linux-compat")]
                crate::mqueue::notify_create(&new_path, false);
                ctx.set_return(SyscallReturn::ok(0));
            }
            Some(Some(Err(narf_filesystem::FsError::NotFound))) => {
                ctx.set_return(SyscallReturn::ok((-2i64) as u64))
            }
            Some(Some(Err(narf_filesystem::FsError::Busy))) => {
                ctx.set_return(SyscallReturn::ok((-17i64) as u64))
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
            #[cfg(feature = "linux-compat")]
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
        _ => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
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
            #[cfg(feature = "linux-compat")]
            crate::mqueue::notify_create(new_path, false);
            0
        }
        // Name already taken — linkat never replaces (EEXIST).
        Some(Err(narf_filesystem::FsError::Busy)) => -17,
        // The FS can't hold an externally-minted node (link_node default).
        Some(Err(narf_filesystem::FsError::Unsupported)) => -95, // -EOPNOTSUPP
        _ => -1,
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
    buf_len: usize,
) {
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf_ptr.is_null() || buf_len == 0 {
        ctx.set_return(fail);
        return;
    }
    // resolve_cwd_path already re-roots under the task's chroot — do
    // not apply_chroot again or the prefix is composed twice.
    let path = resolve_cwd_path(current_task_id(), &raw);
    // Resolve the leaf via the ASYNC path in NoFollow mode. The sync
    // `DirOps::lookup` returns None for ext2 (lookups are async there),
    // so the old resolve_parent_absolute(lookup) path reported EINVAL for
    // every ext2-backed symlink; the async walker returns the real node.
    // NoFollow so we obtain the symlink itself and can read its target,
    // rather than following it to (a copy of) the target's contents.
    let root_rel = narf_filesystem::registry().resolve_absolute(&path, |fs, rel| {
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
        _ => {
            ctx.set_return(fail);
            return;
        }
    };
    // Copy result into user buffer under SMAP bracket.
    // SAFETY: buf_ptr is a user VA validated above; n <= buf_len.
    if unsafe { copy_to_user(buf_ptr as u64, &staging[..n]) }.is_err() {
        ctx.set_return(fail);
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
/// Returns the bytes copied, or `None` on a bad fd / fault.
fn copy_fd_to_fd(
    task: u64,
    in_fd: u32,
    out_fd: u32,
    in_off_ptr: u64,
    count: usize,
) -> Option<usize> {
    let use_off_ptr = in_off_ptr != 0;
    let mut in_off: u64 = if use_off_ptr {
        // SAFETY: `in_off_ptr` is a user `off_t*` in-pointer; copy_from_user_vec
        // range-validates the 8-byte read.
        let b = unsafe { copy_from_user_vec(in_off_ptr, 8) }.ok()?;
        u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        0
    };

    let mut total = 0usize;
    const CHUNK: usize = 4096;
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        let kbuf: alloc::vec::Vec<u8> = fd::with_table(task, |t| {
            let entry = t.get_mut(in_fd)?;
            let off = if use_off_ptr { in_off } else { entry.offset };
            let mut kbuf = alloc::vec![0u8; want];
            let n = match poll_blocking(entry.ops.read(off, &mut kbuf)) {
                Some(Ok(n)) => n,
                _ => 0,
            };
            kbuf.truncate(n);
            if !use_off_ptr {
                entry.offset = off.saturating_add(n as u64);
            }
            Some(kbuf)
        })
        .flatten()?;
        if kbuf.is_empty() {
            break; // EOF on in_fd
        }
        in_off = in_off.saturating_add(kbuf.len() as u64);
        let w: usize = fd::with_table(task, |t| {
            let entry = t.get_mut(out_fd)?;
            let off = entry.offset;
            let w = match poll_blocking(entry.ops.write(off, &kbuf)) {
                Some(Ok(w)) => w,
                _ => 0,
            };
            entry.offset = off.saturating_add(w as u64);
            Some(w)
        })
        .flatten()?;
        total += w;
        if w < kbuf.len() {
            break; // short write (e.g. pipe full) — stop here
        }
    }

    if use_off_ptr {
        // SAFETY: `in_off_ptr` is the user `off_t*` (non-zero); copy_to_user
        // range-validates the 8-byte write-back of the advanced offset.
        let _ = unsafe { copy_to_user(in_off_ptr, &in_off.to_ne_bytes()) };
    }
    Some(total)
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

/// Per-task [effective, permitted, inheritable] capability masks.
static CAP_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, [u64; 3]>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

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

/// Resolve a bare NUL-terminated user path pointer (no length arg) the
/// same way the FS path syscalls do: copy the C string, then apply the
/// chroot rewrite so the xattr key matches the file's canonical path.
fn xattr_user_path(ptr: u64) -> Option<alloc::string::String> {
    copy_user_cstr(ptr, 4096).map(|s| apply_chroot(&s))
}

/// Resolve the fd argument of an `f*xattr` syscall to a side-table key.
/// NARF has no fd→pathname cache yet, so `fd_path_of` returns a stable
/// per-fd `anon_inode:[Type]` placeholder: `f*xattr` calls round-trip
/// against each other on the same fd, but do NOT share storage with the
/// path-keyed `*xattr` family (a documented limitation).
fn xattr_fd_key(fd: u32) -> Option<alloc::string::String> {
    fd_path_string_of(current_task_id(), fd)
}

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
fn xattr_set_core(path: alloc::string::String, ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let name = match copy_user_cstr(a.arg1, 256) {
        Some(n) if !n.is_empty() => n,
        _ => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    };
    let size = a.arg3 as usize;
    let value = if size == 0 {
        alloc::vec::Vec::new()
    } else {
        // SAFETY: size != 0; copy_from_user_vec range-validates a.arg2.
        match unsafe { copy_from_user_vec(a.arg2, size) } {
            Ok(v) => v,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
        }
    };
    let flags = a.arg4;
    if let Some(file) = xattr_file(&path) {
        match poll_blocking(file.set_xattr(&name, &value, flags as u32)) {
            Some(Ok(())) => {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
            Some(Err(narf_filesystem::FsError::Busy)) => {
                ctx.set_return(SyscallReturn::ok((-17i64) as u64));
                return;
            }
            Some(Err(narf_filesystem::FsError::NotFound)) => {
                ctx.set_return(SyscallReturn::ok((-61i64) as u64));
                return;
            }
            _ => {
                ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                return;
            }
        }
    }
    let key = (path, name);
    let mut g = XATTR_TABLE.lock();
    let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    let exists = m.contains_key(&key);
    if flags & XATTR_CREATE != 0 && exists {
        ctx.set_return(SyscallReturn::ok((-17i64) as u64)); // EEXIST
        return;
    }
    if flags & XATTR_REPLACE != 0 && !exists {
        ctx.set_return(SyscallReturn::ok((-61i64) as u64)); // ENODATA
        return;
    }
    m.insert(key, value);
    ctx.set_return(SyscallReturn::ok(0));
}

/// `getxattr` / `lgetxattr` / `fgetxattr` core (name at arg1, value at
/// arg2, size at arg3).
fn xattr_get_core(path: alloc::string::String, ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let name = match copy_user_cstr(a.arg1, 256) {
        Some(n) if !n.is_empty() => n,
        _ => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    };
    let size = a.arg3 as usize;
    if let Some(file) = xattr_file(&path) {
        match poll_blocking(file.get_xattr(&name)) {
            Some(Ok(value)) => {
                return xattr_copy_value(ctx, a.arg2, size, &value);
            }
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
            Some(Err(narf_filesystem::FsError::NotFound)) => {
                ctx.set_return(SyscallReturn::ok((-61i64) as u64));
                return;
            }
            _ => {
                ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                return;
            }
        }
    }
    let value = {
        let g = XATTR_TABLE.lock();
        match g.as_ref().and_then(|m| m.get(&(path, name)).cloned()) {
            Some(v) => v,
            None => {
                ctx.set_return(SyscallReturn::ok((-61i64) as u64)); // ENODATA
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
    if let Some(file) = xattr_file(&path) {
        match poll_blocking(file.list_xattr()) {
            Some(Ok(names)) => {
                return xattr_copy_value(ctx, a.arg1, size, &names);
            }
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
            _ => {
                ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                return;
            }
        }
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
    let name = match copy_user_cstr(a.arg1, 256) {
        Some(n) if !n.is_empty() => n,
        _ => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    };
    if let Some(file) = xattr_file(&path) {
        match poll_blocking(file.remove_xattr(&name)) {
            Some(Ok(())) => {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
            Some(Err(narf_filesystem::FsError::NotFound)) => {
                ctx.set_return(SyscallReturn::ok((-61i64) as u64));
                return;
            }
            _ => {
                ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                return;
            }
        }
    }
    let removed = {
        let mut g = XATTR_TABLE.lock();
        g.as_mut().map(|m| m.remove(&(path, name)).is_some())
    };
    if removed == Some(true) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-61i64) as u64)); // ENODATA
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
    let pid = a.arg0;
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
    #[cfg(feature = "linux-compat")]
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
    if effective == 0 {
        allowed
    } else {
        effective
    }
}

fn mpol_initial_nodemask_valid(mode: u32, nodemask: u64, allowed: u64) -> bool {
    nodemask == 0 || mode & MPOL_F_RELATIVE_NODES != 0 || nodemask & allowed != 0
}

/// Resolve the policy in force for `task` at user address `va`: a
/// covering mbind range wins, else the task default, else DEFAULT.
fn resolve_policy(task: u64, va: u64) -> StoredPolicy {
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

/// Shared core for `preadv(2)` / `pwritev(2)` — vectored I/O at an
/// explicit offset that does NOT advance the fd's own offset.
fn preadv_pwritev(ctx: &mut dyn TrapContext, is_write: bool) {
    let a = *ctx.args();
    let fd = a.arg0 as u32;
    let iov_ptr = a.arg1;
    let iovcnt = a.arg2 as usize;
    let mut off = a.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    const IOV_MAX: usize = 1024;
    if iovcnt > IOV_MAX {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // SAFETY: single-threaded syscall; the AS is active. copy_from_user_vec
    // range-validates the iovec array.
    let iov_buf = match unsafe { copy_from_user_vec(iov_ptr, iovcnt.saturating_mul(16)) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };
    let task = current_task_id();
    let mut total = 0usize;
    for i in 0..iovcnt {
        let o = i * 16;
        let base = u64::from_le_bytes(iov_buf[o..o + 8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(iov_buf[o + 8..o + 16].try_into().unwrap_or([0; 8])) as usize;
        if len == 0 {
            continue;
        }
        if is_write {
            // SAFETY: `base` is a user VA; copy_from_user_vec validates it.
            let kbuf = match unsafe { copy_from_user_vec(base, len) } {
                Ok(b) => b,
                Err(_) => {
                    if total == 0 {
                        ctx.set_return(fail);
                        return;
                    }
                    break;
                }
            };
            let w = fd::with_table(task, |t| {
                let entry = t.get_mut(fd).ok_or(())?;
                poll_blocking(entry.ops.write(off, &kbuf))
                    .unwrap_or(Err(narf_filesystem::FsError::ReadOnly))
                    .map_err(|_| ())
            });
            match w {
                Some(Ok(written)) => {
                    total += written;
                    off = off.saturating_add(written as u64);
                    if written < len {
                        break;
                    }
                }
                _ => {
                    if total == 0 {
                        ctx.set_return(fail);
                        return;
                    }
                    break;
                }
            }
        } else {
            let mut kbuf = alloc::vec![0u8; len];
            let r = fd::with_table(task, |t| {
                let entry = t.get_mut(fd).ok_or(())?;
                poll_blocking(entry.ops.read(off, &mut kbuf))
                    .unwrap_or(Ok(0))
                    .map_err(|_| ())
            });
            match r {
                Some(Ok(n)) => {
                    // SAFETY: `base` is the user iovec destination; copy_to_user
                    // validates the `n`-byte write.
                    let _ = unsafe { copy_to_user(base, &kbuf[..n]) };
                    total += n;
                    off = off.saturating_add(n as u64);
                    if n < len {
                        break; // short read / EOF
                    }
                }
                _ => {
                    if total == 0 {
                        ctx.set_return(fail);
                        return;
                    }
                    break;
                }
            }
        }
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
    pub len_of: fn(handle: u64) -> u64,
    pub frames: fn(handle: u64, out: &mut alloc::vec::Vec<u64>) -> bool,
    pub destroy: fn(handle: u64) -> bool,
    pub pid_of: fn(handle: u64) -> u64,
    /// True only for registry-owned movable RAM, never device/DMA mappings.
    pub owns_frame: fn(phys: u64) -> bool,
    /// Atomically replace one registry backing entry after all aliases moved.
    pub replace_frame: fn(old_phys: u64, new_phys: u64) -> bool,
    pub retain_frame: fn(phys: u64),
    pub release_frame: fn(phys: u64),
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
    if crate::mapped_file::retain_shared_file_page(phys) {
        return;
    }
    if let Some(vtable) = shmem_vtable() {
        (vtable.retain_frame)(phys);
    }
}

pub fn release_external_shared_frame(phys: u64) {
    if crate::mapped_file::release_shared_file_page(phys) {
        return;
    }
    if let Some(vtable) = shmem_vtable() {
        (vtable.release_frame)(phys);
    }
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

// ── Munmap — arg0=base ─────────────────────────────────────────────

// ── Batch 18: address-space-wide locking, secret memory, NUMA ────────

/// Shared core for `mprotect(2)` and `pkey_mprotect(2)`: translate the
/// POSIX `prot` bits to `RegionPerms` and apply them to `[base, base+len)`.
///
/// POSIX prot bit layout (mirrored from narf-libc::sys):
///   PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4.
/// PROT_NONE (`prot == 0`) is NOT coerced to READ — Linux installs an
/// unreadable region that faults on access; `materialize` keys off
/// `prot_only().0 == 0` to leave PTEs absent.
fn mprotect_core(
    as_ref: &Arc<AddressSpace>,
    base: VirtAddr,
    len: u64,
    prot: u32,
) -> Result<(), ()> {
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
    #[cfg(feature = "linux-compat")]
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
        let transition = narf_memory::wx::classify_mprotect_range(
            as_ref.perms_intersecting(base, len).into_iter(),
            perms.prot_only(),
        );
        match transition {
            // Refusals, whatever the caller holds.
            narf_memory::wx::WxTransition::DenyWX | narf_memory::wx::WxTransition::DenyXtoWX => {
                Err(())
            }
            narf_memory::wx::WxTransition::NeedsCapJit => {
                let Some(cap) = narf_memory::wx::jit_cap_default_policy(current_task_id())
                else {
                    return Err(());
                };
                narf_memory::wx::jit_mprotect(&cap, as_ref, base, len, perms).map_err(|_| ())
            }
            narf_memory::wx::WxTransition::Allow => {
                as_ref.mprotect_range(base, len, perms).map_err(|_| ())
            }
        }
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        as_ref.change_perms_range(base, len, perms).map_err(|_| ())
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
    let siblings: alloc::vec::Vec<u64> = {
        let g = TASK_TO_PID.lock();
        g.as_ref()
            .map(|m| {
                m.iter()
                    .filter(|&(&t, &p)| p == pid && t != tid)
                    .map(|(&t, _)| t)
                    .filter(|&t| {
                        crate::task::task_get(t).is_some_and(|t| {
                            t.state.load(core::sync::atomic::Ordering::Acquire)
                                == crate::task::TASK_RUNNING
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    for s in siblings {
        raise_signal_pending(s, 9); // SIGKILL
        wake_signal(s);
    }
}

fn maybe_deliver_signal_before_yield(ctx: &mut dyn TrapContext, syscall_no: u32) -> bool {
    let task = current_task_id();
    let pending = {
        let g = SIGNAL_PENDING.lock();
        g.as_ref().and_then(|m| m.get(&task).copied()).unwrap_or(0)
    };
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
//   - CLONE_SETTLS   args.tls programmed into IA32_FS_BASE on first
//                    dispatch (per-thread TLS thread-pointer).
//   - CLONE_PARENT_SETTID writes the child TID into *args.parent_tid.
//   - CLONE_CHILD_CLEARTID stashes args.child_tid in a per-task slot;
//                    on thread exit, the kernel writes 0 there and
//                    FUTEX_WAKEs one waiter.
//
// Namespace flags are applied in the clone inheritance section below.
//
// set_tid_address(tidptr) sets the calling task's CLOSE_CHILD_CLEARTID
// slot in the same per-task table; returns the caller's TID.
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_VM: u64 = 0x0000_0100;
/// `CLONE_VFORK`: the parent is suspended until the child `execve`s or exits.
/// glibc/musl `posix_spawn` and `vfork()` set this (with CLONE_VM) and run the
/// child on a caller-provided stack while sharing the parent's address space;
/// the parent MUST NOT resume — and thus must not mutate/free that shared AS
/// (e.g. munmap the child's stack) — until the child releases the mm. Linux
/// keeps the parent in TASK_KILLABLE across this window. Consumed only by the
/// x86_64 `do_clone3`; other arches stub clone until the EL0 user-task pipeline.
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
const CLONE_VFORK: u64 = 0x0000_4000;
/// `CLONE_PIDFD`: mint a pidfd on the child, installed in the PARENT's fd
/// table (the child does not inherit it — Linux allocates it after
/// `copy_files`), number written through `clone_args.pidfd`. glibc's
/// `pidfd_spawn` — the ONLY executor-spawn path systemd 258 uses — sets it.
#[cfg(feature = "linux-compat")]
const CLONE_PIDFD: u64 = 0x0000_1000;
/// `CLONE_CLEAR_SIGHAND` (clone3-only): the child starts with every signal
/// disposition SIG_DFL instead of a copy of the parent's table. glibc's
/// `posix_spawn`/`pidfd_spawn` passes it unconditionally (2.38+).
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
/// `CLONE_INTO_CGROUP` (clone3-only): `clone_args.cgroup` is an O_PATH
/// directory fd on cgroupfs; the child starts life in that cgroup instead
/// of inheriting the parent's. glibc `posix_spawn` with
/// `POSIX_SPAWN_SETCGROUP` (systemd's per-service spawn) sets it.
/// Consumed only under the `cgroup` feature (accepted-and-inherit otherwise).
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
#[cfg_attr(not(feature = "cgroup"), allow(dead_code))]
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Place a `clone3(CLONE_INTO_CGROUP)` child in the cgroup named by the O_PATH
/// directory fd `cgroup_fd` in `parent_task`'s fd table (systemd opens it with
/// `open(cgroup, O_PATH|O_DIRECTORY|O_CLOEXEC)` for pidfd_spawn /
/// POSIX_SPAWN_SETCGROUP). Resolves the fd to its recorded open path, strips the
/// `/sys/fs/cgroup` mount prefix (present chroot-prefixed or not), and attaches
/// `child_pid`. Returns true iff the child was placed; the caller falls back to
/// parent-cgroup inheritance on false (the spawn itself must not fail).
///
/// `cgroup_of(child_pid)` — and hence `/proc/<child_pid>/cgroup` — reflects the
/// placement, which is how PID 1 attributes a service's sd_notify(READY=1)
/// datagram back to its unit (`manager_get_unit_by_pidref_cgroup`).
#[cfg(all(feature = "cgroup", feature = "linux-compat"))]
fn place_clone_into_cgroup(parent_task: u64, cgroup_fd: u32, child_pid: u64) -> bool {
    let full = match crate::mqueue::fd_path(parent_task, cgroup_fd) {
        Some(f) => f,
        None => return false,
    };
    match cgroup_rel_path(&full) {
        Some(rel) => narf_filesystem::cgroupfs::attach_by_path(&rel, child_pid).is_ok(),
        None => false,
    }
}

/// Resolve an absolute path that lands inside a mounted cgroup2/cgroupfs to its
/// cgroup-relative path (everything below the cgroupfs mount point).
///
/// cgroup2 is NOT fixed at `/sys/fs/cgroup`: it can be mounted anywhere, more
/// than once, and — under a chroot — the recorded path is host-view
/// (`/mnt/sys/fs/cgroup/...`). So this consults the live mount table and strips
/// the LONGEST matching `cgroup2`/`cgroupfs` mount prefix rather than assuming a
/// literal path. Returns `None` when `abs` is not under any cgroupfs mount (the
/// caller then falls back to parent-cgroup inheritance). The mount table is in
/// the caller's mount namespace, which is the space the cgroup fd was opened in.
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
#[cfg(all(feature = "cgroup", feature = "linux-compat"))]
#[doc(hidden)]
pub fn place_clone_into_cgroup_for_test(parent_task: u64, cgroup_fd: u32, child_pid: u64) -> bool {
    place_clone_into_cgroup(parent_task, cgroup_fd, child_pid)
}
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_FS: u64 = 0x0000_0200;
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_FILES: u64 = 0x0000_0400;
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_SIGHAND: u64 = 0x0000_0800;
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_THREAD: u64 = 0x0001_0000;
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_SYSVSEM: u64 = 0x0004_0000;
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_SETTLS: u64 = 0x0008_0000;
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
#[cfg(feature = "linux-compat")]
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
/// Per-task clear_child_tid entry: (uaddr, address-space root
/// phys). Stashing the root phys at registration time means the
/// exit-observer can write the futex word even after the
/// scheduler has already reaped the task's slot.
#[derive(Copy, Clone)]
struct ClearChildTidEntry {
    uaddr: u64,
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    as_root: narf_memory::PhysAddr,
}

#[cfg(feature = "linux-compat")]
static CLEAR_CHILD_TID: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, ClearChildTidEntry>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the clear_child_tid table. Called once at boot
/// alongside the other per-task state tables; idempotent.
#[cfg(feature = "linux-compat")]
pub fn clear_child_tid_init() {
    let mut g = CLEAR_CHILD_TID.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

#[cfg(feature = "linux-compat")]
fn set_clear_child_tid(task_id_raw: u64, uaddr: u64) {
    set_clear_child_tid_with_as(task_id_raw, uaddr, narf_memory::PhysAddr::new(0));
}

#[cfg(feature = "linux-compat")]
fn set_clear_child_tid_with_as(task_id_raw: u64, uaddr: u64, as_root: narf_memory::PhysAddr) {
    let mut g = CLEAR_CHILD_TID.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
    if let Some(m) = g.as_mut() {
        if uaddr == 0 {
            m.remove(&task_id_raw);
        } else {
            m.insert(task_id_raw, ClearChildTidEntry { uaddr, as_root });
        }
    }
}

#[cfg(feature = "linux-compat")]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn take_clear_child_tid(task_id_raw: u64) -> Option<ClearChildTidEntry> {
    let mut g = CLEAR_CHILD_TID.lock();
    g.as_mut().and_then(|m| m.remove(&task_id_raw))
}

/// Diagnostic / test-only — inspect a task's clear_child_tid slot
/// without consuming it. Returns just the uaddr; AS root is
/// internal bookkeeping.
#[cfg(feature = "linux-compat")]
#[doc(hidden)]
pub fn __test_peek_clear_child_tid(task_id_raw: u64) -> Option<u64> {
    let g = CLEAR_CHILD_TID.lock();
    g.as_ref()
        .and_then(|m| m.get(&task_id_raw).map(|e| e.uaddr))
}

/// Force-clear the entire clear_child_tid table for test isolation.
#[cfg(feature = "linux-compat")]
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
/// requiring an `activate()` (the user task's AS was the active CR3
/// at the moment of longjmp and the trap-exit path restored the
/// kernel CR3 before reaching us; we don't want to bounce CR3 again
/// just for one qword write).
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
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
            if let Some(phys) = unsafe {
                narf_memory::x86_64::paging::translate(root, narf_memory::VirtAddr::new(page))
            } {
                // SAFETY: identity-mapped low RAM; the AS Arc keeps the backing
                // frame alive across this write.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    *((phys.as_u64() + off) as *mut u32) = 0;
                }
            }
        }
    }

    // NOW bump the counter (lost-wakeup gen guard) AND fire every parked waiter
    // on the real wait queue — AFTER the word write above, so a joiner's
    // wake→re-read observes the cleared (0) word and proceeds instead of
    // re-parking. `futex_bump_counter` takes the counter lock (release); the
    // joiner's next FUTEX_WAIT gen-snapshot (acquire) then sees the prior write.
    futex_bump_counter(uaddr);
    futex_wake_waiters(uaddr, u32::MAX);
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
fn fire_clear_child_tid_on_exit(_pid_raw: u64, _tid_raw: u64) {
    // aarch64 / other arches: clone3 path is x86_64-gated below;
    // the table never gets populated, so this is a no-op.
}

/// Register the clear_child_tid observer (THREAD-scoped: fires per
/// exiting thread — pthread_join waits on the per-`tid` clear_child_tid
/// futex). Idempotent and safe to call before `clear_child_tid_init`
/// (the observer no-ops on an unpopulated table).
#[cfg(feature = "linux-compat")]
pub fn install_clear_child_tid_observer() {
    crate::user_task::register_thread_exit_observer(fire_clear_child_tid_on_exit);
}

/// Linux `struct clone_args` — uapi shape from <linux/sched.h>.
/// All fields are u64 on the wire; the kernel reads only the
/// subset we honour.
#[cfg(feature = "linux-compat")]
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
    /// `set_tid` array pointer — accepted-and-ignored (checkpoint/restore).
    set_tid: u64,
    /// `set_tid` array length — accepted-and-ignored.
    set_tid_size: u64,
    /// CLONE_INTO_CGROUP target: an O_PATH dir fd on cgroupfs.
    cgroup: u64,
}

#[cfg(feature = "linux-compat")]
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
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
static VFORK_WAIT: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
pub(crate) fn vfork_wait_register(child_pid: u64, parent_task: u64) {
    let mut g = VFORK_WAIT.lock();
    g.get_or_insert_with(BTreeMap::new)
        .insert(child_pid, parent_task);
}

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
pub(crate) fn vfork_is_pending(child_pid: u64) -> bool {
    VFORK_WAIT
        .lock()
        .as_ref()
        .is_some_and(|m| m.contains_key(&child_pid))
}

/// Called from the child's `execve` and exit paths: if this child had a vfork
/// parent parked on it, drop the entry and wake the parent. `child_pid` is the
/// child's visible pid. Idempotent (only the first exec/exit releases).
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
pub(crate) fn vfork_child_release(child_pid: u64) {
    let parent = {
        let mut g = VFORK_WAIT.lock();
        g.as_mut().and_then(|m| m.remove(&child_pid))
    };
    if let Some(parent_task) = parent {
        wake_signal(parent_task);
    }
}

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
fn do_clone3(ctx: &mut dyn TrapContext, ca: CloneArgs) {
    use crate::process::DEFAULT_USER_STACK_BYTES;
    let flags = ca.flags;
    let parent_as = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
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
    let _share_sysvsem = (flags & CLONE_SYSVSEM) != 0;

    // CLONE_THREAD requires CLONE_VM + CLONE_SIGHAND in Linux.
    // We enforce CLONE_VM (without a shared AS the child can't
    // observe the parent's memory); CLONE_SIGHAND shares the live
    // sigaction table below.
    if share_thread && !share_vm {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

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
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        };
        // SAFETY: `dup` is the freshly-built child AddressSpace with a valid root
        // and the regions cloned above; materialize installs only those PTEs.
        // SAFETY: Valid memory or trusted environment
        if unsafe { dup.materialize() }.is_err() {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
        // SAFETY: `parent_as` is the live caller AddressSpace; rematerialize rewrites
        // its existing PTEs to match the WRITE-stripped (COW) region perms set by clone_for_fork.
        // SAFETY: Valid memory or trusted environment
        if unsafe { parent_as.as_ref().rematerialize() }.is_err() {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
        alloc::sync::Arc::new(dup)
    };

    // Stack: for `clone3(2)`, `ca.stack` points at the LOW end
    // of the user-provided stack region and `ca.stack_size` is
    // the byte length; the child's initial RSP is the top
    // (`stack + stack_size`). For the legacy `clone(2)` syscall
    // (sys_clone synthesises a CloneArgs), `ca.stack` is ALREADY
    // the top and `ca.stack_size` is 0 — `stack + 0` recovers
    // the top. The combined check is therefore just "stack
    // pointer is non-zero".
    // A THREAD (CLONE_VM: shares the parent's address space) must bring
    // its own stack — reusing the parent's would collide. A fork-shaped
    // clone (no CLONE_VM) instead COW-copies the whole AS, so `stack == 0`
    // is valid and means "resume the child on the (COW) parent stack at
    // the parent's RSP" — exactly what glibc's fork() passes
    // (`clone(SIGCHLD|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID, stack=0)`).
    if share_vm && ca.stack == 0 {
        #[cfg(feature = "syscall-trace")]
        narf_console::write_str(&alloc::format!(
            "[CLONE3_FAIL share_vm stack==0 flags={:#x}]\n",
            flags
        ));
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let rsp = if ca.stack != 0 {
        ca.stack.saturating_add(ca.stack_size)
    } else {
        // Fork: inherit the parent's user RSP (child runs on its COW copy).
        ctx.user_rsp()
    };

    // Entry: clone3 doesn't carry an explicit entry RIP in
    // clone_args. The child resumes at the parent's saved trap-
    // frame RIP (the instruction after the clone3 syscall) with
    // a rewritten RAX = 0 — same shape as fork(). User code
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
            snap.rax = 0;
            // Plant the user-supplied RSP. The parent's trap-frame
            // RSP stays in the parent's snapshot (its set_return
            // path writes its own rax = child_tid later); the
            // child's snapshot gets the freshly-allocated thread
            // stack.
            snap.rsp = rsp;
            Some(snap)
        } else {
            None
        }
    };

    let parent_pid = current_task_id();

    // Allocate identifiers. Two cases:
    //   - CLONE_THREAD: child shares the parent's user-visible PID
    //                   (its TGID). Its scheduler TaskId is fresh
    //                   (spawn_user mints it). Record both → same
    //                   TaskId in TASK_TO_PID so getpid() returns
    //                   the parent's PID and gettid() returns the
    //                   TaskId.
    //   - else:         fresh ProcessId via alloc_pid(), same as
    //                   sys_fork.
    let child_visible_pid = if share_thread {
        // Parent's getpid() lookup — fall back to parent_pid if no
        // mapping was registered (e.g., the parent is init).
        task_to_pid_raw(parent_pid).unwrap_or(parent_pid)
    } else {
        crate::alloc_pid().raw()
    };

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
        parent_of_set(child_visible_pid, parent_pid);
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
    if !share_thread {
        crate::mapped_file::fork_process(
            task_to_pid_raw(parent_pid).unwrap_or(parent_pid),
            child_visible_pid,
        );
    }

    // CLONE_PIDFD: mint the shared exit-state BEFORE the child is spawned.
    // `pidfd::notify_exit` only flips entries that already exist in the
    // table — under SMP (or an exec-then-crash child) the child can exit
    // before this handler finishes, and a late mint would never observe
    // that exit (POLLIN never fires; systemd would supervise a ghost).
    // The fd itself is installed after the child's fd-table fork below.
    let pidfd_state = if flags & CLONE_PIDFD != 0 && ca.pidfd != 0 {
        Some(crate::pidfd::mint_for(child_visible_pid, true))
    } else {
        None
    };

    let proc = crate::UserProcess {
        pid: crate::ProcessId(child_visible_pid),
        address_space: child_as.clone(),
        entry: crate::EntryPoint(narf_memory::VirtAddr::new(0)),
        stack_top: narf_memory::VirtAddr::new(rsp),
        fs_base: if (flags & CLONE_SETTLS) != 0 && ca.tls != 0 {
            Some(ca.tls)
        } else {
            // Inherit parent's FS_BASE — read the live MSR.
            let lo: u32;
            let hi: u32;
            const IA32_FS_BASE: u32 = 0xC000_0100;
            // SAFETY: `rdmsr` reads MSR `ecx`=IA32_FS_BASE into edx:eax. The MSR is
            // architectural and always readable at CPL0 (kernel); operands name the
            // ABI registers and the instruction has no memory side effects.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") IA32_FS_BASE,
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, preserves_flags),
                );
            }
            let v = (lo as u64) | ((hi as u64) << 32);
            if v == 0 {
                None
            } else {
                Some(v)
            }
        },
        entry_arg: None,
        loaded_mappings: alloc::vec::Vec::new(),
    };
    let _ = DEFAULT_USER_STACK_BYTES;

    // Snapshot the AS root phys before the Arc is moved into the
    // scheduler — needed by the exit-observer to write the
    // clear_child_tid futex word after the slot is reaped.
    let child_as_root = child_as.root;
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
    let pending_child = match child_state {
        Some(state) => crate::user_task::prepare_user_process_resume(
            proc,
            state,
            narf_scheduler::TaskSpec::user_task(),
        ),
        None => crate::user_task::prepare_user_process_initial(
            proc,
            narf_scheduler::TaskSpec::user_task(),
        ),
    };
    let child_tid = pending_child.task_id();
    proc_identity_fork(parent_pid, child_tid.raw());

    // Register the (visible-pid → TaskId) binding. For
    // CLONE_THREAD children visible_pid == parent's pid, so the
    // mapping is "child TaskId → parent's PID" — gettid returns
    // the TaskId raw, getpid translates TaskId → PID.
    if share_thread {
        register_task_to_pid(child_tid.raw(), child_visible_pid);
    } else {
        register_pid_task_mapping(child_visible_pid, child_tid.raw());
        // A clone() that creates a new process (not a thread) joins
        // the parent's cgroup. Threads share the process's membership
        // and are never placed individually in the base feature.
        //
        // CLONE_INTO_CGROUP instead starts the child directly in the
        // cgroup named by `clone_args.cgroup` — an O_PATH dir fd on
        // cgroupfs (glibc pidfd_spawn with POSIX_SPAWN_SETCGROUP; how
        // systemd 258 spawns every service executor). Resolve the fd to
        // its recorded open path, strip everything up to the cgroupfs
        // mount ("/sys/fs/cgroup", chroot-prefixed or not), and attach.
        // On any resolution/veto failure fall back to parent inheritance
        // rather than failing the clone — the spawn itself must succeed;
        // systemd migrates stragglers via cgroup.procs anyway.
        #[cfg(feature = "cgroup")]
        {
            let placed = flags & CLONE_INTO_CGROUP != 0
                && place_clone_into_cgroup(parent_pid, ca.cgroup as u32, child_visible_pid);
            if !placed {
                // cgroup membership is keyed by ProcessId — look the parent up
                // by its ProcessId, not the raw TaskId (see sys_fork).
                narf_filesystem::cgroupfs::fork_inherit(
                    task_to_pid_raw(parent_pid).unwrap_or(parent_pid),
                    child_visible_pid,
                );
            }
        }
        // cgroup-namespace inheritance, and CLONE_NEWCGROUP → the child
        // gets a fresh cgroup-ns rooted at its current cgroup.
        #[cfg(all(feature = "cgroup", feature = "container"))]
        {
            const CLONE_NEWCGROUP: u64 = 0x0200_0000;
            narf_filesystem::cgroupfs::fork_inherit_ns(parent_pid, child_visible_pid);
            if flags & CLONE_NEWCGROUP != 0 {
                narf_filesystem::cgroupfs::unshare_cgroup_ns(child_visible_pid);
            }
        }
    }

    // fd table: CLONE_FILES (every pthread) SHARES one table with the parent —
    // an fd opened by any thread is visible to all, and close/dup affect all
    // (Linux semantics weston's worker threads rely on). Without CLONE_FILES
    // (fork) the child gets an independent COPY.
    if _share_files {
        crate::fd::share(parent_pid, child_tid.raw());
    } else {
        crate::fd::fork(parent_pid, child_tid.raw());
    }
    #[cfg(feature = "linux-compat")]
    crate::mqueue::fork_fd_paths(parent_pid, child_tid.raw());

    // CLONE_PIDFD: install the pidfd in the PARENT's table only, AFTER the
    // child's fd-table fork above so the child doesn't inherit it (Linux
    // allocates it after copy_files; pidfd_prepare mints it O_CLOEXEC).
    // Write the fd number through *clone_args.pidfd — the parent's AS is
    // still the active CR3 here (same shape as CLONE_PARENT_SETTID below).
    if let Some(st) = pidfd_state {
        let file: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
            alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(st));
        let newfd = fd::with_table(parent_pid, |t| {
            t.open(crate::fd::FdEntry {
                ops: file,
                offset: 0,
                flags: crate::fd::FD_CLOEXEC,
                status_flags: 0,
            })
        });
        if let Some(n) = newfd {
            let fd_bytes = (n as i32).to_ne_bytes();
            // SAFETY: `ca.pidfd` is the user out-pointer (non-zero, checked at
            // mint time); copy_to_user range-validates and SMAP-brackets the
            // 4-byte write through the parent's still-active address space.
            // SAFETY: Valid memory or trusted environment
            let _ = unsafe { copy_to_user(ca.pidfd, &fd_bytes) };
        }
    }

    // A child (process or thread) inherits its parent's process group,
    // session, and controlling terminal (POSIX). pgid inheritance is what
    // keeps a forked foreground job in the terminal's foreground pgrp so
    // it does NOT trip the SIGTTIN/SIGTTOU background-access check on its
    // first console read; a job-control shell moves it out via setpgid.
    pgid_fork(parent_pid, child_tid.raw());
    sid_fork(parent_pid, child_tid.raw());
    #[cfg(feature = "linux-compat")]
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
    // `child_ns_pid` is the value clone(2) hands back to the PARENT: the
    // child's pid in the parent's namespace, which must agree with the child's
    // own getpid() (see project_pidns_flow_model — these are coupled). Defaults
    // to the outer ProcessId; the fork-inherit below fills in the inner pid
    // when the parent is namespaced.
    #[cfg(feature = "container")]
    let mut child_ns_pid = child_visible_pid;
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
        // PID + mount namespaces (only meaningful for a new process).
        if !share_thread {
            // Binds the child into the parent's pid namespace (keyed by the
            // child's TaskId) and yields the inner pid the parent should see;
            // None in the root namespace leaves the outer pid unchanged.
            if let Some(inner) =
                crate::pid_ns::inherit_into_child(parent_task, child, child_visible_pid)
            {
                child_ns_pid = inner;
            }
            const CLONE_NEWPID: u64 = 0x20000000;
            if flags & CLONE_NEWPID != 0 {
                let _ = crate::pid_ns::unshare_pid_ns(child, child_visible_pid);
            }
        }
        // UTS / NET / IPC / User: shared by ref, then CLONE_NEW* mints
        // a fresh one for the child.
        crate::namespaces::inherit_into_child(parent_task, child);
        if flags & crate::namespaces::CLONE_NEWUSER != 0 {
            let host_uid = read_uidgid(parent_task).euid;
            let _ = crate::namespaces::unshare_user(child, host_uid);
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

    if !share_vm {
        // brk maps onto AS state; only meaningful for a non-VM clone
        // (a true fork).
        brk_fork(parent_pid, child_tid.raw());
    }
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
        let tid_bytes = (child_tid.raw() as u32).to_ne_bytes();
        // SAFETY: `ca.parent_tid` is the user *parent_tid pointer (non-zero, checked);
        // the parent's CR3 is still active here. copy_to_user range-validates it and
        // SMAP-brackets the 4-byte write.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { copy_to_user(ca.parent_tid, &tid_bytes) };
    }

    // CLONE_CHILD_SETTID: write child TID to *child_tid in the
    // child's AS. For CLONE_VM, parent and child share the AS so
    // we can write through the live CR3 immediately; for non-VM
    // we'd need to bounce CR3, which we don't support today on
    // this branch (rare path: clone3 without CLONE_VM but with
    // CHILD_SETTID is structurally weird).
    if (flags & CLONE_CHILD_SETTID) != 0 && ca.child_tid != 0 && share_vm {
        let tid_bytes = (child_tid.raw() as u32).to_ne_bytes();
        // SAFETY: CLONE_VM means parent and child share the AS, so the live CR3 maps
        // `ca.child_tid` (non-zero, checked). copy_to_user range-validates it and
        // SMAP-brackets the 4-byte write.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { copy_to_user(ca.child_tid, &tid_bytes) };
    }

    // CLONE_CHILD_CLEARTID: stash for the exit-observer to consume.
    // Pass the child's AS root phys so the observer can write the
    // futex word even after the scheduler reaps the slot — by then
    // `address_space_of` returns None, but the Arc we hold in
    // `child_as` keeps the page tables alive.
    if (flags & CLONE_CHILD_CLEARTID) != 0 && ca.child_tid != 0 {
        set_clear_child_tid_with_as(child_tid.raw(), ca.child_tid, child_as_root);
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
    let ret_val = if share_thread {
        child_tid.raw()
    } else {
        child_ns_pid
    };
    #[cfg(not(feature = "container"))]
    let ret_val = if share_thread {
        child_tid.raw()
    } else {
        child_visible_pid
    };
    // This is the publication point for the child. Everything keyed by its
    // TaskId, including the copied fd table used by the immediate executor
    // fexecve, has been installed above.
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
                while vfork_is_pending(child_visible_pid) {
                    if (signal_pending_bits(parent_pid) & (1 << 9)) != 0 {
                        // SIGKILL pending: abandon the wait; drop the stale entry
                        // so a later reuse of this pid can't wake a dead parent.
                        VFORK_WAIT
                            .lock()
                            .as_mut()
                            .map(|m| m.remove(&child_visible_pid));
                        break;
                    }
                    uc.sleep_deadline_ns
                        .store(u64::MAX, core::sync::atomic::Ordering::Release);
                    crate::user_task::own_stack_park();
                }
                uc.sleep_deadline_ns
                    .store(0, core::sync::atomic::Ordering::Release);
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
// (copied via `cwd_fork`), brk (copied via `brk_fork`), sigaction
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
static PARENT_OF: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
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
type PendingExitMap = BTreeMap<u64, alloc::vec::Vec<(u64, i32)>>;
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

/// True if `task` is currently job-control stopped.
pub fn is_task_stopped(task: u64) -> bool {
    let job_stopped = TASK_STOPPED
        .lock()
        .as_ref()
        .map(|m| m.contains_key(&task))
        .unwrap_or(false);
    #[cfg(feature = "linux-compat")]
    let ptrace_stopped = crate::ptrace::is_task_ptrace_stopped(task);
    #[cfg(not(feature = "linux-compat"))]
    let ptrace_stopped = false;
    job_stopped || ptrace_stopped
}

/// Raw pending-signal bitmask for `task` (no mask applied). Used by
/// the poll loop to let SIGKILL break a job-control stop.
pub fn signal_pending_bits(task: u64) -> u64 {
    SIGNAL_PENDING
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

/// AND-out the given signal bits from `task`'s pending set.
pub(crate) fn clear_pending_signal_bits(task: u64, mask: u64) {
    if let Some(m) = SIGNAL_PENDING.lock().as_mut() {
        if let Some(slot) = m.get_mut(&task) {
            *slot &= !mask;
        }
    }
}

/// WIFSTOPPED-shaped wstatus carrying `sig` as WSTOPSIG.
fn stopped_wstatus(sig: u32) -> i32 {
    ((sig as i32) << 8) | 0x7f
}

/// WIFCONTINUED-shaped wstatus.
const CONTINUED_WSTATUS: i32 = 0xffff;

#[inline]
fn get_wait_recipient(child_pid: u64) -> Option<u64> {
    #[cfg(feature = "linux-compat")]
    {
        crate::ptrace::get_wait_recipient(child_pid)
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        parent_of_get(child_pid)
    }
}

/// Queue a stop/continue notification to `child_task`'s parent and
/// nudge it: stage SIGCHLD and wake any blocking wait4. Does NOT
/// release the child PID — the child is still alive.
pub(crate) fn push_stopcont_report(child_task: u64, wstatus: i32, is_continued: bool) {
    let child_pid = task_to_pid_raw(child_task).unwrap_or(child_task);
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
    {
        let mut g = SIGNAL_PENDING.lock();
        if let Some(m) = g.as_mut() {
            *m.entry(parent).or_insert(0) |= sig_bit(17); // SIGCHLD
        }
    }
    crate::user_task::wake_wait_child(parent);
}

/// Pop a matching stop/continue notification for `parent`, honouring
/// the wait `options` (WUNTRACED selects stops, WCONTINUED selects
/// continues) and the `want` pid filter. Returns `(child_pid,
/// wstatus)` WITHOUT releasing the PID.
fn reap_stopcont(parent: u64, want: i64, options: u32) -> Option<(u64, i32)> {
    let want_stop = options & WUNTRACED != 0;
    let want_cont = options & WCONTINUED != 0;
    let mut g = PENDING_STOPCONT.lock();
    let q = g.as_mut()?.get_mut(&parent)?;
    let idx = q.iter().position(|&(p, _w, cont)| {
        if want > 0 && p != want as u64 {
            return false;
        }
        if cont {
            return want_cont;
        }
        // A ptrace-stop is reported to the tracer's wait4 unconditionally;
        // a job-control stop of a non-traced child needs WUNTRACED.
        #[cfg(feature = "linux-compat")]
        {
            want_stop || crate::ptrace::is_ptrace_stop_recipient(parent, p)
        }
        #[cfg(not(feature = "linux-compat"))]
        {
            want_stop
        }
    })?;
    let (pid, w, _) = q.remove(idx);
    Some((pid, w))
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
    #[cfg(feature = "linux-compat")]
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
    crate::user_task::register_thread_exit_observer(task_tables_exit_observer);
    #[cfg(feature = "linux-compat")]
    crate::user_task::register_thread_exit_observer(crate::perf_event::on_thread_exit);
    // PROCESS-scoped (last thread of the group only): hand the process
    // to its parent (wait4 reap + SIGCHLD + waker) or auto-release if
    // orphaned. Gated on `group_dead` so a multi-threaded exit_group
    // reaps the pid exactly once (was per-thread → double `release_pid`,
    // the OCI teardown #UD).
    #[cfg(feature = "linux-compat")]
    crate::user_task::register_process_exit_observer(crate::perf_event::on_process_exit);
    crate::user_task::register_process_exit_observer(on_child_exit);
    crate::user_task::register_process_exit_observer(crate::mapped_file::process_exit);
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
    #[cfg(feature = "linux-compat")]
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
    #[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
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
    // Job-control stop/continue notification FIRST. Linux reaps a child's
    // state changes in order — a stop or continue is reported before the
    // child's later exit — so a `waitpid(WCONTINUED)` after `kill(SIGCONT)`
    // must see the continue even if the child has since run to exit (which
    // it can do quickly now that signals are delivered on every syscall
    // return). reap_stopcont only matches when WUNTRACED/WCONTINUED is set
    // and a report is queued, so a plain wait falls straight through to the
    // exit reap below. These do NOT release the PID: the child is alive (or
    // its exit is still queued for the next wait).
    if let Some((child_pid, status)) = reap_stopcont(parent_id, want_pid, options) {
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
    const WNOWAIT: u32 = 0x0100_0000;
    let peek = options & WNOWAIT != 0;
    let entry = {
        let mut g = PENDING_EXITS.lock();
        let reaped = g.as_mut().and_then(|m| {
            let q = m.get_mut(&parent_id)?;
            let idx = if want_pid > 0 {
                q.iter().position(|&(p, _)| p == want_pid as u64)?
            } else {
                if q.is_empty() {
                    return None;
                }
                0
            };
            if peek {
                Some(q[idx])
            } else {
                Some(q.remove(idx))
            }
        });
        reaped
    };
    if let Some((child_pid, status)) = entry {
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
    if is_waitid {
        0
    } else {
        reaped_visible as u64
    }
}

/// Per-task-own-stack blocking wait4/waitid: reap-or-park loop that returns the
/// reaped result via `set_return` (NOT a re-execute — wait can't pre-bake its
/// result). Reads its args from the UserTaskCtx (stored by the caller before the
/// park), registers the slot-waker so `on_child_exit` re-polls us, and
/// `kernel_switch`es out via `yield_current_stackful` until a child is reapable.
/// The own-stack analog of `UserTaskFuture::poll`'s wait_child arm.
#[cfg(target_arch = "x86_64")]
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
        if is_signal_pending(parent) {
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
#[cfg(target_arch = "x86_64")]
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

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn own_stack_block(_ctx: &mut dyn TrapContext) {
    unreachable!("own-stack is not supported on non-x86_64 architectures");
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
        if let Some(m) = g.as_mut() {
            m.insert(child, parent);
        }
    }
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
    let mut g = PENDING_EXITS.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
    if let Some(m) = g.as_mut() {
        m.entry(parent)
            .or_insert_with(alloc::vec::Vec::new)
            .push((child, status));
    }
}

fn parent_of_set(child: u64, parent: u64) {
    let mut g = PARENT_OF.lock();
    if let Some(m) = g.as_mut() {
        m.insert(child, parent);
    }
}

pub(crate) fn parent_of_get(child: u64) -> Option<u64> {
    let g = PARENT_OF.lock();
    g.as_ref().and_then(|m| m.get(&child).copied())
}

/// Drop the child→parent record once the child has been reaped (or is an
/// orphan being auto-released). Lets `has_living_child` correctly report
/// ECHILD after the last child is reaped — without this, stale entries make
/// `wait4` think children still exist and block forever.
fn parent_of_remove(child: u64) {
    let mut g = PARENT_OF.lock();
    if let Some(m) = g.as_mut() {
        m.remove(&child);
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
                crate::task::release_task(tid);
                // Reap-time pid↔tid unbinding. PIDs are recycled
                // (lowest-free), so a surviving PID_TO_TASK row would
                // point the pid's NEXT owner-lookup at this dead tid —
                // signals/waits misrouted to a corpse — and the stale
                // TASK_TO_PID row would translate this dead tid to a
                // pid someone else now owns. Removed only at reap:
                // the zombie window still needs both directions
                // (kill(pid) on a zombie, wstatus threading).
                if let Some(m) = PID_TO_TASK.lock().as_mut() {
                    if m.get(&child_pid) == Some(&tid) {
                        m.remove(&child_pid);
                    }
                }
                if let Some(m) = TASK_TO_PID.lock().as_mut() {
                    m.remove(&tid);
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
    if let Some(m) = SIGNAL_PENDING.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SIGNAL_MASK.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SIGACTION_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SIG_ALTSTACK.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SIGQUEUE_INFO.lock().as_mut() {
        m.retain(|&(t, _), _| t != tid);
    }
    if let Some(m) = SIGRETURN_USE_RSP.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SIGRETURN_IS_RT.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = SIGRETURN_SAVED_MASK.lock().as_mut() {
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
    if let Some(m) = FUTEX_WAITERS.lock().as_mut() {
        m.retain(|_, waiters| {
            waiters.remove(&tid);
            !waiters.is_empty()
        });
    }
    for shard in TCB_OWNER.iter() {
        if let Some(m) = shard.lock().as_mut() {
            m.retain(|_, owner| *owner != tid);
        }
    }

    // Identity / credentials / per-task knobs.
    if let Some(m) = UIDGID_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = GROUPS_TABLE.lock().as_mut() {
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
    #[cfg(feature = "linux-compat")]
    if let Some(m) = CTTY_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = RLIMIT_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = PRCTL_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = NICE_TABLE.lock().as_mut() {
        m.remove(&tid);
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
    if let Some(m) = CWD_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    #[cfg(feature = "linux-compat")]
    if let Some(m) = ROOT_DIR_TABLE.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = TASK_MOUNT_NS.lock().as_mut() {
        m.remove(&tid);
    }
    if let Some(m) = BRK_TABLE.lock().as_mut() {
        m.remove(&tid);
    }

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
    if let Some(m) = TASK_KERN_NS.lock().as_mut() {
        m.remove(&tid);
    }
    // POSIX record locks: normally already drained (fd::detach runs
    // first in exit-observer order and wakes the waiters); this second
    // pass is the backstop for any path that tears down tables without
    // detaching fds. Also retire this task's own waiter entries (it
    // may die while parked on someone else's lock).
    #[cfg(feature = "linux-compat")]
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
    #[cfg(feature = "linux-compat")]
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

fn orphanize_children_of(parent_tid: u64) {
    let reaper = find_child_subreaper(parent_tid);
    // Already-exited, never-reaped children: hand them to the subreaper
    // (it can wait4 them like its own) or release when there is none.
    let stale: alloc::vec::Vec<(u64, i32)> = {
        let mut g = PENDING_EXITS.lock();
        g.as_mut()
            .and_then(|m| m.remove(&parent_tid))
            .unwrap_or_default()
    };
    match reaper {
        Some(r) if !stale.is_empty() => {
            {
                let mut g = PENDING_EXITS.lock();
                if let Some(m) = g.as_mut() {
                    m.entry(r).or_default().extend(stale.iter().copied());
                }
            }
            for (child_pid, _) in &stale {
                parent_of_set(*child_pid, r);
            }
            // The subreaper learns about its inherited zombies the same
            // way a real parent would: SIGCHLD + a wait4 wake.
            raise_signal_pending(r, 17);
            crate::user_task::wake_wait_child(r);
        }
        _ => {
            for (child_pid, _status) in stale {
                release_reaped_task(child_pid);
                crate::release_pid(crate::ProcessId(child_pid));
                parent_of_remove(child_pid);
            }
        }
    }
    // Queued stop/continue job-control reports die with the waiter.
    if let Some(m) = PENDING_STOPCONT.lock().as_mut() {
        m.remove(&parent_tid);
    }
    // Still-running children: deliver each one's PR_SET_PDEATHSIG (the
    // runc/supervisor "kill me when my parent dies" contract) BEFORE the
    // rows move, then reparent to the subreaper or drop the rows so an
    // orphan's eventual exit takes the auto-release branch.
    let children: alloc::vec::Vec<u64> = {
        let g = PARENT_OF.lock();
        g.as_ref()
            .map(|m| {
                m.iter()
                    .filter(|&(_, p)| *p == parent_tid)
                    .map(|(&c, _)| c)
                    .collect()
            })
            .unwrap_or_default()
    };
    for child_pid in &children {
        let child_tid = pid_to_task_raw(*child_pid).unwrap_or(*child_pid);
        let sig = read_prctl(child_tid).pdeathsig;
        if sig != 0 {
            // raise_signal_pending wakes a parked target itself.
            raise_signal_pending(child_tid, sig);
        }
    }
    if let Some(m) = PARENT_OF.lock().as_mut() {
        match reaper {
            Some(r) => {
                for (_, parent) in m.iter_mut().filter(|(_, p)| **p == parent_tid) {
                    *parent = r;
                }
            }
            None => m.retain(|_, parent| *parent != parent_tid),
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
    r |= has(
        SIGNAL_PENDING
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 0,
    );
    r |= has(
        SIGNAL_MASK
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 1,
    );
    r |= has(
        SIGACTION_TABLE
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 2,
    );
    r |= has(
        SIGNAL_WAKERS
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 3,
    );
    r |= has(
        IO_WAKERS[io_waker_shard(tid)]
            .lock()
            .as_ref()
            .is_some_and(|m| m.contains_key(&tid)),
        1 << 4,
    );
    r |= has(
        FUTEX_WAITERS
            .lock()
            .as_ref()
            .is_some_and(|m| m.values().any(|w| w.contains_key(&tid))),
        1 << 5,
    );
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
            .is_some_and(|m| m.values().any(|&p| p == tid)),
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
fn has_living_child(parent: u64, want: i64) -> bool {
    let g = PARENT_OF.lock();
    let is_parent = match g.as_ref() {
        Some(m) if want > 0 => m.get(&(want as u64)).copied() == Some(parent),
        Some(m) => m.values().any(|&p| p == parent),
        None => false,
    };
    if is_parent {
        return true;
    }
    #[cfg(feature = "linux-compat")]
    {
        crate::ptrace::is_tracer_of_any(parent, want)
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        false
    }
}

// ── ProcessId ↔ TaskId translation ────────────────────────────────
//
// `sys_fork` mints a fresh ProcessId (from `alloc_pid()`) and a fresh
// TaskId (from `spawn_user()`). Any code that receives a ProcessId
// (e.g. a user-visible fork return value or a /proc path) but needs
// the internal TaskId (e.g. scheduler lookups, fd-table accesses) must
// translate through this table.

/// ProcessId.raw() → TaskId.raw()
static PID_TO_TASK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// TaskId.raw() → ProcessId.raw()
static TASK_TO_PID: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn pid_task_map_init() {
    *PID_TO_TASK.lock() = Some(BTreeMap::new());
    *TASK_TO_PID.lock() = Some(BTreeMap::new());
}

pub fn pid_task_map_reset() {
    *PID_TO_TASK.lock() = None;
    *TASK_TO_PID.lock() = None;
}

/// Register a (ProcessId → TaskId) mapping. Called by `sys_fork` and
/// boot spawn_one for every user task that gets a user-visible ProcessId.
/// Records both directions simultaneously so all translations are O(1).
pub fn register_pid_task_mapping(pid_raw: u64, task_raw: u64) {
    register_task_to_pid(task_raw, pid_raw);
    // Self-initialize: the map may be `None` if `wait_init` hasn't run
    // yet (early boot, or the kernel-test harness which boots straight
    // into the smoke runner). Without this a `fork` registration would
    // silently no-op and every later pid→task translation would miss.
    PID_TO_TASK
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(pid_raw, task_raw);
}

pub fn register_task_to_pid(task_raw: u64, pid_raw: u64) {
    TASK_TO_PID
        .lock()
        .get_or_insert_with(BTreeMap::new)
        .insert(task_raw, pid_raw);
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
pub fn thread_group_live_dec(pid: u64) -> bool {
    let mut g = THREAD_GROUP_LIVE.lock();
    let Some(m) = g.as_mut() else { return true };
    match m.get_mut(&pid) {
        None => true,
        Some(n) if *n <= 1 => {
            m.remove(&pid);
            true
        }
        Some(n) => {
            *n -= 1;
            false
        }
    }
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
    PID_TO_TASK
        .lock()
        .as_ref()
        .and_then(|m| m.get(&pid_raw).copied())
}

/// Translate a scheduler TaskId to the user-visible ProcessId registered
/// at fork/spawn time. Returns `None` when the task has no registered
/// ProcessId (kernel-only tasks, test stubs).
pub fn task_to_pid_raw(task_raw: u64) -> Option<u64> {
    TASK_TO_PID
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
    // Namespace and pid↔task cleanup is deferred to release_reaped_task so a
    // zombie's inner PID remains resolvable until wait4/waitid consumes it.
    let _ = child_tid;
    #[cfg(feature = "linux-compat")]
    crate::ptrace::release_process(child_pid);

    // Wave-61: notify any pidfd_open()'d watchers that the target
    // exited, regardless of whether a parent reaps it.
    crate::pidfd::notify_exit(child_pid);

    let parent = match get_wait_recipient(child_pid) {
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
    let status = take_pending_termination(child_pid).unwrap_or(0);
    // (1) Reap entry — for wait4.
    {
        let mut g = PENDING_EXITS.lock();
        if let Some(m) = g.as_mut() {
            m.entry(parent)
                .or_insert_with(alloc::vec::Vec::new)
                .push((child_pid, status));
        }
    }
    // (2) SIGCHLD delivery — for the parent's sigaction(SIGCHLD) handler.
    // Linux: kernel/signal.c::do_notify_parent sets SIGCHLD pending.
    // SIGCHLD = 17; bypass the mask (SIGCHLD is never masked by default).
    const SIGCHLD: u32 = 17;
    {
        let mut g = SIGNAL_PENDING.lock();
        if let Some(m) = g.as_mut() {
            let slot = m.entry(parent).or_insert(0);
            *slot |= sig_bit(SIGCHLD);
        }
    }
    // A parent may be parked in epoll_wait on its signalfd rather than in
    // wait4. Publishing SIGCHLD without firing the signal waker leaves that
    // task asleep indefinitely: the earlier pidfd readiness notification can
    // race before SIGNAL_PENDING is set, so its re-scan observes neither
    // source. Wake after the pending bit is visible, matching every other
    // signal-delivery path.
    wake_signal(parent);
    // signalfd exposes blocked pending signals through poll/epoll readiness.
    // `pidfd::notify_exit` ran before SIGCHLD was published, so its readiness
    // wake can legitimately re-scan too early and re-park. Notify again after
    // the bit is visible so an epoll waiter observes either its pidfd or
    // signalfd as ready.
    narf_net::readiness::notify(0);
    // (3) Wake any parent task parked in a blocking wait4.  The waker
    // was stored by `UserTaskFuture::poll` when it found the pending-
    // exits queue empty.  Now that we've pushed an entry, fire the waker
    // so the executor re-polls the parent and it can reap.
    crate::user_task::wake_wait_child(parent);
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
}

/// Test-only: map `task` into process group `pgid` directly (bypassing
/// the setpgid syscall plumbing) so a test can assemble a multi-member
/// foreground group.
#[doc(hidden)]
pub fn __test_set_pgid(task: u64, pgid: u64) {
    let mut g = PGID_TABLE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert(task, pgid);
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
    pid_to_task_raw(user_pid).unwrap_or(user_pid)
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

/// The session id of the current task, in the visible-pid space userspace
/// sees. Backs the `TIOCGSID` console ioctl (`tcgetsid(3)`), which getty
/// and login use to confirm they own the tty's session after `TIOCSCTTY`.
#[cfg(feature = "linux-compat")]
pub fn current_task_sid_user() -> u64 {
    pgid_to_user(read_sid(current_task_id()))
}

/// Child inherits the parent's process-group id (POSIX fork semantics).
/// Without this a forked child defaults to pgid == its own pid, which
/// would place a shell-launched foreground job in a *different* group than
/// the terminal's foreground pgrp and spuriously trip SIGTTIN on its first
/// console read. A job-control shell still moves the child into a new
/// group explicitly via setpgid.
pub fn pgid_fork(parent: u64, child: u64) {
    let pg = read_pgid(parent);
    if let Some(m) = PGID_TABLE.lock().as_mut() {
        m.insert(child, pg);
    }
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

#[cfg(feature = "linux-compat")]
static CTTY_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// CTTY_TABLE sentinel: the boot console (`/dev/console`). Equals
/// `narf_filesystem::TTY_ID_CONSOLE` so a task's ctty value can be
/// compared directly against a FileOps `tty_id()`. PTY entries store the
/// small `/dev/pts/<N>` index, which never collides with this.
#[cfg(feature = "linux-compat")]
pub const CTTY_CONSOLE: u32 = narf_filesystem::TTY_ID_CONSOLE;

/// CTTY_TABLE sentinel: explicitly no controlling tty (a session leader
/// detached via setsid). Distinct from an absent entry, which means "the
/// boot-console default".
#[cfg(feature = "linux-compat")]
pub const CTTY_DETACHED: u32 = 0xFFFF_FFFF;

/// The controlling terminal of `task`, resolved against the boot default:
/// absent → the boot console (every task starts attached to it);
/// `CTTY_DETACHED` → none (setsid'd, not yet re-acquired); `CTTY_CONSOLE`
/// → the console; any other value → that PTY index. `None` means the task
/// has no controlling terminal.
#[cfg(feature = "linux-compat")]
pub fn task_ctty(task: u64) -> Option<u32> {
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
#[cfg(feature = "linux-compat")]
pub fn set_controlling_tty_console(task: u64) {
    if let Some(m) = CTTY_TABLE.lock().as_mut() {
        m.insert(task, CTTY_CONSOLE);
    }
}

/// Detach `task` from its controlling terminal — the `TIOCNOTTY` path.
/// Marks the slot `CTTY_DETACHED` (a distinct state from the boot-console
/// default) so `task_ctty` resolves to "no controlling terminal", matching
/// what `setsid()` does. A subsequent `open` without `O_NOCTTY` or an
/// explicit `TIOCSCTTY` re-acquires one.
#[cfg(feature = "linux-compat")]
pub fn detach_controlling_tty(task: u64) {
    if let Some(m) = CTTY_TABLE.lock().as_mut() {
        m.insert(task, CTTY_DETACHED);
    }
}

/// Child inherits the parent's controlling terminal (POSIX fork). Only an
/// explicit entry needs copying — absence already resolves to the console
/// default for both parent and child.
#[cfg(feature = "linux-compat")]
pub fn ctty_fork(parent: u64, child: u64) {
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

#[cfg(feature = "linux-compat")]
pub fn ctty_init() {
    *CTTY_TABLE.lock() = Some(BTreeMap::new());
}

#[cfg(feature = "linux-compat")]
#[doc(hidden)]
pub fn __test_ctty_reset() {
    *CTTY_TABLE.lock() = Some(BTreeMap::new());
}

/// Look up the controlling tty for `task`. Returns the PTY index or
/// `None` if the task has no controlling tty.
#[cfg(feature = "linux-compat")]
pub fn ctty_for(task: u64) -> Option<u32> {
    CTTY_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
}

/// Hook installed by `bare_main` so `PtySlave::ioctl(TIOCSCTTY)` can
/// record the caller's controlling tty without depending on this crate.
#[cfg(feature = "linux-compat")]
pub fn set_controlling_tty(pty_index: u32) {
    let task = current_task_id();
    let mut g = CTTY_TABLE.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task, pty_index);
    }
}

/// `TIOCSCTTY`-on-console hook (installed in `boot_init`): record the boot
/// console as the calling task's controlling terminal.
#[cfg(feature = "linux-compat")]
fn console_tiocsctty() {
    set_controlling_tty_console(current_task_id());
}

/// `TIOCNOTTY`-on-console hook: detach the calling task's controlling tty.
#[cfg(feature = "linux-compat")]
fn console_tiocnotty() {
    detach_controlling_tty(current_task_id());
}

/// `TIOCGSID`-on-console hook: the caller's session id (visible-pid space).
#[cfg(feature = "linux-compat")]
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
// Storage shape mirrors the cwd table (BTreeMap<task_id, _>
// behind an IrqSafeSpinLock); same init / test-reset hooks.
// Default identity is (uid=0, gid=0) — matches what the prior
// noop_ok stubs returned, so consumers that didn't touch
// setuid/setgid see no change.

#[derive(Copy, Clone, Default)]
struct UidGid {
    /// Real uid/gid.
    uid: u32,
    gid: u32,
    /// Effective uid/gid (geteuid/getegid). No separate saved-id is
    /// tracked; getres*id reports the effective id as the saved id too.
    euid: u32,
    egid: u32,
    /// Filesystem uid/gid (setfsuid/setfsgid). Tracks the effective id
    /// unless overridden by setfs*id.
    fsuid: u32,
    fsgid: u32,
}

static UIDGID_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, UidGid>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
static GROUPS_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, alloc::vec::Vec<u32>>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task uid/gid registry. Call once at boot
/// before any user task issues `setuid` / `getuid`.
pub fn uidgid_init() {
    *UIDGID_TABLE.lock() = Some(BTreeMap::new());
    *GROUPS_TABLE.lock() = Some(BTreeMap::new());
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_uidgid_reset() {
    *UIDGID_TABLE.lock() = Some(BTreeMap::new());
    *GROUPS_TABLE.lock() = Some(BTreeMap::new());
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
    let g = UIDGID_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or_default()
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
fn current_accessor(task: u64) -> narf_filesystem::Accessor {
    let acc = read_uidgid(task);
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial() {
            return narf_filesystem::Accessor {
                uid: uns.translate_uid_to_host(acc.fsuid),
                gid: uns.translate_gid_to_host(acc.fsgid),
            };
        }
    }
    // Root (host) user-ns, or container feature off: identity.
    narf_filesystem::Accessor {
        uid: acc.fsuid,
        gid: acc.fsgid,
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
    let mut g = UIDGID_TABLE.lock();
    if let Some(map) = g.as_mut() {
        if let Some(v) = map.get(&parent).copied() {
            map.insert(child, v);
        }
    }
    drop(g);
    let mut groups = GROUPS_TABLE.lock();
    if let Some(map) = groups.as_mut() {
        if let Some(v) = map.get(&parent).cloned() {
            map.insert(child, v);
        }
    }
}

pub(crate) fn read_groups(task: u64) -> alloc::vec::Vec<u32> {
    GROUPS_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).cloned())
        .unwrap_or_default()
}

pub(crate) fn write_groups(task: u64, groups: alloc::vec::Vec<u32>) -> bool {
    let mut table = GROUPS_TABLE.lock();
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
    let mut g = UIDGID_TABLE.lock();
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
fn write_res_ids(ctx: &mut dyn TrapContext, p0: u64, p1: u64, p2: u64, val: u32) {
    let buf = val.to_ne_bytes();
    for p in [p0, p1, p2] {
        if p != 0 {
            // SAFETY: `p` is a user `uid_t*`/`gid_t*` out-pointer;
            // copy_to_user range-validates the 4-byte write.
            if unsafe { copy_to_user(p, &buf) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                return;
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Per-task rlimit table ──────────────────────────────────────────
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
    t
}

static RLIMIT_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<BTreeMap<u64, [RLimitPair; RLIMIT_COUNT]>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn rlimit_init() {
    *RLIMIT_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
pub fn __test_rlimit_reset() {
    *RLIMIT_TABLE.lock() = Some(BTreeMap::new());
}

fn read_rlimit(task: u64, resource: usize) -> Option<RLimitPair> {
    if resource >= RLIMIT_COUNT {
        return None;
    }
    let g = RLIMIT_TABLE.lock();
    let m = g.as_ref()?;
    let row = m.get(&task).copied().unwrap_or_else(default_rlimits);
    Some(row[resource])
}

fn write_rlimit(task: u64, resource: usize, val: RLimitPair) -> bool {
    if resource >= RLIMIT_COUNT {
        return false;
    }
    let mut g = RLIMIT_TABLE.lock();
    let Some(m) = g.as_mut() else {
        return false;
    };
    let row = m.entry(task).or_insert_with(default_rlimits);
    row[resource] = val;
    true
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

const SCHED_OTHER: u64 = 0;
const SCHED_FIFO: u64 = 1;
const SCHED_RR: u64 = 2;
const SCHED_BATCH: u64 = 3;
const SCHED_IDLE: u64 = 5;

fn priority_max_for_policy(policy: u64) -> Option<i64> {
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => Some(0),
        SCHED_FIFO | SCHED_RR => Some(99),
        _ => None,
    }
}

fn priority_min_for_policy(policy: u64) -> Option<i64> {
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => Some(0),
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

const PRIO_PROCESS_VAL: i64 = 0;

static NICE_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, i32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn nice_init() {
    *NICE_TABLE.lock() = Some(BTreeMap::new());
}

#[doc(hidden)]
pub fn __test_nice_reset() {
    *NICE_TABLE.lock() = Some(BTreeMap::new());
}

fn read_nice(task: u64) -> i32 {
    let g = NICE_TABLE.lock();
    g.as_ref().and_then(|m| m.get(&task).copied()).unwrap_or(0)
}

fn write_nice(task: u64, prio: i32) -> bool {
    let mut g = NICE_TABLE.lock();
    let Some(m) = g.as_mut() else {
        return false;
    };
    m.insert(task, prio);
    true
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

#[cfg(feature = "container")]
fn current_or_default_ipc_ns(task: u64) -> alloc::sync::Arc<crate::namespaces::IpcNamespace> {
    if let Some(ns) = crate::namespaces::current_ipc_ns(task) {
        return ns;
    }
    // Lazy-install a per-task IPC NS so the get-by-key family has a
    // stable id space even for tasks that never unshared. Matches the
    // shape Linux uses (every task is always in some IPC NS).
    crate::namespaces::unshare_ipc(task);
    crate::namespaces::current_ipc_ns(task).expect("unshare_ipc just installed an entry")
}

// ── System V shared memory (linux-compat) ────────────────────────────
//
// Real shared segments backed by the narf-shmem frame registry (reached
// through the syscall vtable). `shmat` maps a segment's physical frames
// into the caller's address space; a second attach of the same id maps
// the same frames, so writes through one attachment are visible through
// the other — genuine sharing, exactly like Linux. Supersedes the
// container id-by-key `shmget` in a linux-compat build.

#[cfg(feature = "linux-compat")]
struct ShmSegment {
    handle: u64,
    key: u32,
    len: u64,
}

#[cfg(feature = "linux-compat")]
static SHM_SEGMENTS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, ShmSegment>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);
#[cfg(feature = "linux-compat")]
static SHM_NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "linux-compat")]
const IPC_CREAT: u64 = 0o1000;
#[cfg(feature = "linux-compat")]
const IPC_EXCL: u64 = 0o2000;
#[cfg(feature = "linux-compat")]
const IPC_RMID: u64 = 0;
#[cfg(feature = "linux-compat")]
const IPC_64: u64 = 0x100;
#[cfg(feature = "linux-compat")]
const SHM_RDONLY: u64 = 0o10000;

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
