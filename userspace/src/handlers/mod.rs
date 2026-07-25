//! Core syscall handler bodies.
//!
//! POSIX-shaped syscall implementations behind the `Syscall` enum.
//! Each handler runs in trap context after the arch trap stub has
//! saved user registers and the `TrapContext` bridge is constructed.
//!
//! - `Open` — resolves an absolute or per-mount path through the
//!   VFS registry, allocates a new fd in the calling task's
//!   `FdTable`, returns the fd.
//! - `Read` / `Write` — look up the fd in the per-task table,
//!   poll the resulting `FileOps::{read,write}` to completion via
//!   `poll_once` (Stage-4 in-memory FSes resolve on first poll),
//!   advance the per-fd offset, return bytes transferred. fd 1/2
//!   bypass the table and write directly to the kernel console.
//! - `Close` / `Dup` / `Dup2` / `Fcntl` — direct fd-table operations.
//! - `Mmap` / `Munmap` — manipulate the calling task's `AddressSpace`.
//! - `ExitTask` — rewrites the trap frame (via
//!   `redirect_to_kernel`) to a landing pad the kernel publishes
//!   through `set_exit_landing`.
//! - `Yield` / `Sleep` — no-op Ok.
//!
//! `install_core_syscalls(table)` drops every handler above into a
//! freshly-built `SyscallTable` so kernels that want the common
//! set don't each have to wire every slot.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};

use crate::{
    fd, RawFnHandler, SigDeliveryParams, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
    TrapContext,
};

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

static AS_LOOKUP: narf_lib::sync::IrqSafeSpinLock<Option<AsLookupFn>> =
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
/// fd::init is kept separate (different module) but consumers
/// almost always call it alongside.
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
    pgid_init();
    sid_init();
    wait_init();
    pkey_init();
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
    // Resolve relative paths against the task's cwd and collapse
    // `.`/`..` (absolute-mount form only; the explicit-mount form below
    // keeps its already-relative-to-the-mount path). This is what makes
    // `ls` (which opens ".") and any relative open work from a shell.
    let path_owned = if mnt_len == 0 {
        resolve_cwd_path(task, &path_owned_raw)
    } else {
        path_owned_raw
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
                let node = narf_filesystem::new_anon_memfile();
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
        let leaf = narf_filesystem::registry()
            .resolve_absolute(path, |fs, rel| {
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
                        crate::mqueue::register_fd_path(task, n, path);
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
        narf_filesystem::registry()
            .resolve_absolute(path, |fs, rel| {
                poll_blocking(narf_filesystem::resolve_async(fs.root(), rel)).and_then(|r| r.ok())
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
                    crate::mqueue::register_fd_path(task, n, path);
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
                    created = true;
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
        crate::mqueue::register_fd_path(task, new_fd, path);
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
        crate::mqueue::register_fd_path(task, new_fd, _path);
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
    // Resolve relative paths (e.g. `ls`'s `lstat(".")`) against the
    // caller's cwd before chroot, so the stat family works from any
    // working directory — not just absolute paths.
    // resolve_cwd_path already re-roots under the task's chroot — do
    // not apply_chroot again or the prefix is composed twice.
    let path_owned = resolve_cwd_path(current_task_id(), &raw);
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
    Option<alloc::collections::BTreeMap<usize, alloc::sync::Arc<crate::linux_compat::MemFdFile>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

#[cfg(feature = "linux-compat")]
fn memfd_arc_register(arc: &alloc::sync::Arc<crate::linux_compat::MemFdFile>) {
    let key = alloc::sync::Arc::as_ptr(arc) as usize;
    let mut g = MEMFD_ARCS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(key, arc.clone());
}

#[cfg(feature = "linux-compat")]
pub(crate) fn memfd_arc_from_fd(
    task: u64,
    fd: u32,
) -> Option<alloc::sync::Arc<crate::linux_compat::MemFdFile>> {
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let g = MEMFD_ARCS.lock();
    g.as_ref()?.get(&raw).cloned()
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
    let dir = narf_filesystem::registry()
        .resolve_absolute(parent_path, |fs, rel| {
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
                    Some(Err(narf_filesystem::FsError::Unsupported)) | None => {
                        dir.lookup_dir(seg)?
                    }
                    Some(Err(_)) => return None,
                };
                dir = next;
            }
            Some(dir)
        })
        .flatten()?;
    Some((dir, alloc::string::String::from(leaf)))
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
// Same-parent only, mirroring sys_rename's restriction (the DirOps
// surface has no registry-aware two-parent lock). A cross-directory
// link surfaces as -EXDEV, which every `ln`/libc caller already
// handles (it is the normal cross-filesystem answer on Linux, and
// cp/install fall back to a copy on it).

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
        ctx.set_return(SyscallReturn::ok((-18i64) as u64)); // EXDEV
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
    // Allocate staging buffer at min(buf_len, target_len). MemSymlink
    // reads the target verbatim from offset 0; n is the byte count.
    let target_len = st.size as usize;
    let len = core::cmp::min(buf_len, target_len);
    let mut staging = alloc::vec![0u8; len];
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

#[cfg(not(target_arch = "x86_64"))]
fn user_page_present(as_ref: &AddressSpace, uaddr: u64) -> bool {
    // aarch64 `paging::translate` isn't wired at this tier (same story as
    // the loader's `user_vaddr_to_kernel_ptr`); userspace is a stub on
    // aarch64 regardless, so fall back to region membership.
    as_ref.lookup(VirtAddr::new(uaddr)).is_some()
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
    fd_path_of(current_task_id(), fd)
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
    if size == 0 {
        ctx.set_return(SyscallReturn::ok(value.len() as u64));
        return;
    }
    if size < value.len() {
        ctx.set_return(SyscallReturn::ok((-34i64) as u64)); // ERANGE
        return;
    }
    // SAFETY: a.arg2 is the user buffer; copy_to_user range-validates the write.
    if unsafe { copy_to_user(a.arg2, &value) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(value.len() as u64));
}

/// `listxattr` / `llistxattr` / `flistxattr` core (list at arg1, size at arg2).
fn xattr_list_core(path: alloc::string::String, ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let size = a.arg2 as usize;
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

const MPOL_MAX: u32 = 5; // DEFAULT/PREFERRED/BIND/INTERLEAVE/LOCAL
const MPOL_MODE_FLAGS: u32 = 0xc000_0000; // MPOL_F_STATIC_NODES | _RELATIVE_NODES

// Online NUMA node count via a weak hook (userspace avoids a direct
// narf-acpi dep to keep the kernel image under lld's orphan-placement
// threshold — see filesystem/src/sysfs.rs). `narf-frame` provides it.
extern "Rust" {
    fn narf_numa_node_count() -> u32;
}

#[inline]
fn numa_node_count() -> u32 {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    unsafe { narf_numa_node_count() }.max(1)
}

// get_mempolicy `flags` bits (uapi/linux/mempolicy.h).
const MPOL_F_NODE: u32 = 1 << 0; // return the node id, not the mode
const MPOL_F_ADDR: u32 = 1 << 1; // query the policy at `addr`
const MPOL_F_MEMS_ALLOWED: u32 = 1 << 2; // return the allowed-nodes mask

/// One stored policy: mode (with flags) + first-word nodemask.
type StoredPolicy = (u32, u64);

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

fn mpol_mode_valid(mode: u32) -> bool {
    (mode & !MPOL_MODE_FLAGS) < MPOL_MAX
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
        .unwrap_or((0, 0))
}

/// Publish the current task's mempolicy for the faulting address `va`
/// into the memory crate's per-CPU active slot, so the demand-paging
/// allocator steers the fresh frame. Called by the #PF handler right
/// before `demand_alloc_page`. Returns nothing; the slot is cleared by
/// `clear_mempolicy_for_fault` afterward.
pub fn publish_mempolicy_for_fault(va: u64) {
    let task = current_task_id();
    let (mode, nodemask) = resolve_policy(task, va);
    narf_memory::mempolicy_set(narf_memory::Mempolicy {
        mode: mode & !MPOL_MODE_FLAGS,
        nodemask,
    });
}

/// Clear the per-CPU active mempolicy after a fault is serviced.
pub fn clear_mempolicy_for_fault() {
    narf_memory::mempolicy_clear();
}

/// The node a fresh page under `pol` would be allocated from (used by
/// get_mempolicy's MPOL_F_NODE|MPOL_F_ADDR query). Mirrors the
/// allocator's preference resolution without actually allocating.
fn mempolicy_resolved_node(pol: narf_memory::Mempolicy) -> u32 {
    match pol.mode {
        x if x == narf_memory::MPOL_BIND || x == narf_memory::MPOL_PREFERRED => {
            if pol.nodemask != 0 {
                pol.nodemask.trailing_zeros()
            } else {
                narf_memory::frame::local_node() as u32
            }
        }
        x if x == narf_memory::MPOL_INTERLEAVE => {
            if pol.nodemask != 0 {
                pol.nodemask.trailing_zeros()
            } else {
                0
            }
        }
        // DEFAULT / LOCAL
        _ => narf_memory::frame::local_node() as u32,
    }
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
        as_ref.mprotect_range(base, len, perms).map_err(|_| ())
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
    let comm = proc_comm_of(pid).unwrap_or_else(|| alloc::string::String::from("?"));
    #[cfg(feature = "syscall-trace")]
    {
        use core::fmt::Write;
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
// CLONE_NEWPID / CLONE_NEWNS / etc are accepted-and-ignored — the
// container surface is a separate wave.
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
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
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
    let child_tid = match child_state {
        Some(state) => crate::user_task::spawn_user_process_resume(
            proc,
            state,
            narf_scheduler::TaskSpec::user_task(),
        ),
        None => crate::user_task::spawn_user_process(proc, narf_scheduler::TaskSpec::user_task()),
    };

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
            let mut placed = false;
            if flags & CLONE_INTO_CGROUP != 0 {
                let full = crate::mqueue::fd_path(parent_pid, ca.cgroup as u32);
                if let Some(full) = &full {
                    const CG_MNT: &str = "/sys/fs/cgroup";
                    if let Some(i) = full.find(CG_MNT) {
                        let rel = &full[i + CG_MNT.len()..];
                        placed = narf_filesystem::cgroupfs::attach_by_path(rel, child_visible_pid)
                            .is_ok();
                    }
                }
                #[cfg(feature = "syscall-trace")]
                if !placed {
                    narf_console::write_str(&alloc::format!(
                        "[CLONE3 INTO_CGROUP unresolved fd={} path={:?}]\n",
                        ca.cgroup,
                        full
                    ));
                }
            }
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
    #[cfg(feature = "container")]
    {
        let child = child_tid.raw();
        // PID + mount namespaces (only meaningful for a new process).
        if !share_thread {
            // Binds the child into the parent's pid namespace (keyed by the
            // child's TaskId) and yields the inner pid the parent should see;
            // None in the root namespace leaves the outer pid unchanged.
            if let Some(inner) =
                crate::pid_ns::inherit_into_child(parent_pid, child, child_visible_pid)
            {
                child_ns_pid = inner;
            }
            mount_ns_inherit(parent_pid, child);
            const CLONE_NEWNS: u64 = 0x00020000;
            const CLONE_NEWPID: u64 = 0x20000000;
            if flags & CLONE_NEWNS != 0 {
                task_mount_ns_init();
                let snap = narf_filesystem::MountNamespace::snapshot_global();
                install_mount_namespace(child, snap);
            }
            if flags & CLONE_NEWPID != 0 {
                let _ = crate::pid_ns::unshare_pid_ns(child, child_visible_pid);
            }
        }
        // UTS / NET / IPC / User: shared by ref, then CLONE_NEW* mints
        // a fresh one for the child.
        crate::namespaces::inherit_into_child(parent_pid, child);
        if flags & crate::namespaces::CLONE_NEWUSER != 0 {
            let host_uid = read_uidgid(parent_pid).euid;
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

    // Parent-of bookkeeping for wait4 was published above, BEFORE the spawn,
    // to close the SMP TRACEME race (see the comment at that call site). A
    // thread (CLONE_THREAD) is not waitpid-reapable; pthread_join uses the
    // futex on clear_child_tid instead — so nothing to publish for it.

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
    // PROCESS-scoped (last thread of the group only): hand the process
    // to its parent (wait4 reap + SIGCHLD + waker) or auto-release if
    // orphaned. Gated on `group_dead` so a multi-threaded exit_group
    // reaps the pid exactly once (was per-thread → double `release_pid`,
    // the OCI teardown #UD).
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
            ctx.set_return(SyscallReturn::ok(0));
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
                ctx.set_return(SyscallReturn::ok(0));
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
    crate::pid_ns::self_inner_pid(task_space_id, outer)
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

/// Initialise the per-task uid/gid registry. Call once at boot
/// before any user task issues `setuid` / `getuid`.
pub fn uidgid_init() {
    *UIDGID_TABLE.lock() = Some(BTreeMap::new());
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_uidgid_reset() {
    *UIDGID_TABLE.lock() = Some(BTreeMap::new());
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
    crate::socket::Ucred {
        pid: task_to_pid_raw(task).unwrap_or(task) as u32,
        uid: ids.euid,
        gid: ids.egid,
    }
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
    /// Ambient capability set as a bitmask (bit N ⇒ capability N raised).
    ambient_caps: u64,
    /// PR_SET_SECUREBITS value. Stored-not-enforced (NARF's privilege
    /// model is uid/gid only); PR_GET_SECUREBITS must round-trip it so
    /// systemd's executor `if (prctl(PR_GET_SECUREBITS) != secure_bits)`
    /// check sees the default 0 and skips the (privileged) SET — an
    /// unimplemented GET returned -1, forcing a doomed SET on every
    /// service start (exit 213/EXIT_SECUREBITS).
    securebits: u64,
}

impl Default for PrctlState {
    fn default() -> Self {
        Self {
            name: [0; TASK_COMM_LEN],
            dumpable: true, // Linux default
            no_new_privs: false,
            pdeathsig: 0,
            child_subreaper: false,
            ambient_caps: 0, // empty ambient set at exec, per Linux
            securebits: 0,   // SECBIT_* all clear, per Linux default
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
// NARF user mode is single-CPU; the affinity bitmap is structural
// state only. getaffinity always reports a 1-bit mask (CPU 0 set);
// setaffinity reads the supplied bitmap and discards it (no
// pinning to perform). Surface exists so pthread / libnuma
// probes succeed at startup.

// ── Getcpu — current CPU + NUMA node query ─────────────────────────
//
// Linux getcpu(2): real CPU + NUMA node lookup. NARF user mode is
// single-CPU and single-node today — both return 0 — but library
// code (libnuma, RT performance probes) queries this at startup
// and the entry must exist.

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

// ── Per-task cwd state ────────────────────────────────────────────
//
// Storage shape mirrors the other per-task tables in this file:
// a `BTreeMap<task_id, String>` behind an `IrqSafeSpinLock` with
// an explicit init hook + a test-reset hook. Lifecycle is
// independent of the fd table — agent B owns fd-table extensions
// in `fd.rs`; this state lives in handlers.rs to keep the
// ownership boundary clean.
//
// Default cwd is `/`. Stage-4 first cut: absolute paths only.
// Relative-path resolution + the `*at(2)` family land later;
// today the kernel just records the string the user supplied.

static CWD_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, alloc::string::String>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task cwd registry. Boot calls this once
/// before any user task can issue `Syscall::Chdir` / `Getcwd`.
pub fn cwd_init() {
    *CWD_TABLE.lock() = Some(BTreeMap::new());
}

/// Reset the registry — test hook. Drops every per-task entry.
#[doc(hidden)]
pub fn __test_cwd_reset() {
    *CWD_TABLE.lock() = Some(BTreeMap::new());
}

/// fork(2) inheritance: copy `parent`'s cwd to `child`. No-op
/// if the registry isn't up or the parent has no entry (child
/// inherits the default `/`).
pub fn cwd_fork(parent: u64, child: u64) {
    let mut g = CWD_TABLE.lock();
    if let Some(map) = g.as_mut() {
        if let Some(v) = map.get(&parent).cloned() {
            map.insert(child, v);
        }
    }
}

/// Diagnostic: peek the recorded cwd for `task`. Returns the
/// default `"/"` if `task` has never called Chdir.
pub fn cwd_of(task: u64) -> alloc::string::String {
    let g = CWD_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).cloned())
        .unwrap_or_else(|| alloc::string::String::from("/"))
}

/// Collapse `.`/`..`/empty segments into a clean absolute path.
/// `normalize_abs("/a/./b/../c")` → `/c`; an empty result is `/`.
fn normalize_abs(p: &str) -> alloc::string::String {
    let mut out: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut r = alloc::string::String::from("/");
    r.push_str(&out.join("/"));
    r
}

/// Turn a user-supplied path (absolute or relative to `task`'s cwd)
/// into a normalized absolute path. Relative paths are joined onto the
/// task's current working directory; `.`/`..` are collapsed.
pub(crate) fn resolve_cwd_path(task: u64, path: &str) -> alloc::string::String {
    let normalized = resolve_cwd_path_user(task, path);
    // Re-root under the task's chroot (if any) so a chrooted process —
    // e.g. a container — resolves paths against the chrooted rootfs, not
    // the host root. No-op for tasks without a chroot.
    #[cfg(feature = "linux-compat")]
    {
        apply_chroot(&normalized)
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        normalized
    }
}

/// The join-and-normalize half of [`resolve_cwd_path`] — the USER-VIEW
/// absolute path, before the chroot prefix. This is what CWD_TABLE must
/// store: chdir used to store the post-chroot result, so a chrooted
/// task's next RELATIVE open re-applied the prefix (`cd /proc` in the
/// alpine chroot → cwd "/mnt/proc" → open("stat") resolved
/// "/mnt/mnt/proc/stat" → busybox top's "can't open 'stat'"), and
/// getcwd leaked the host-side prefix into the container.
pub(crate) fn resolve_cwd_path_user(task: u64, path: &str) -> alloc::string::String {
    if path.starts_with('/') {
        normalize_abs(path)
    } else {
        let mut joined = cwd_of(task);
        if !joined.ends_with('/') {
            joined.push('/');
        }
        joined.push_str(path);
        normalize_abs(&joined)
    }
}

/// Resolve an absolute path to a [`DirOps`] if (and only if) it names a
/// directory. Mirrors the segment-walk in `sys_getdents64` /
/// `sys_readdir`: pick the longest-matching mount, then descend by
/// `lookup_dir_async` per path component.
/// True if `path` is a proper ancestor directory of an existing mount
/// point (e.g. `/sys/fs` when `/sys/fs/cgroup` is mounted). In NARF's flat
/// mount model such an intermediate component has no real node in the
/// underlying filesystem, but it must resolve and stat as a directory:
/// systemd's `mkdir_parents_safe` mkdir()s each path component then
/// `newfstatat()`s it to confirm it is a directory, and cg_create fails
/// (ENOENT/EEXIST mismatch) if mkdir and stat disagree. Both `sys_mkdir`
/// (→ EEXIST) and the dir-aware stat resolver (→ synthetic S_IFDIR) use
/// this so the two views stay consistent.
fn path_is_mount_ancestor(path: &str) -> bool {
    let p = path.trim_end_matches('/');
    if p.is_empty() {
        return false;
    }
    narf_filesystem::registry()
        .list()
        .iter()
        .any(|m| m.len() > p.len() && m.starts_with(p) && m.as_bytes()[p.len()] == b'/')
}

fn resolve_dir_absolute(path: &str) -> Option<alloc::sync::Arc<dyn narf_filesystem::DirOps>> {
    narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            let dir: alloc::sync::Arc<dyn narf_filesystem::DirOps> = if rel.is_empty() {
                fs.root()
            } else {
                let mut cur = fs.root();
                for seg in rel.split('/').filter(|s| !s.is_empty()) {
                    cur = poll_blocking(cur.lookup_dir_async(seg)).and_then(|r| r.ok())?;
                }
                cur
            };
            Some(dir)
        })
        .flatten()
}

/// Stat an absolute path, handling both files and directories.
/// Files come from the FileOps `stat()`; directories (mount roots and
/// sub-directories alike) synthesise a `DIR_RW`-shaped stat so callers
/// see `S_IFDIR`. Returns `None` only when the path names nothing.
fn stat_path_dir_aware(path: &str) -> Option<narf_filesystem::Stat> {
    stat_ino_path_dir_aware(path).map(|(s, _ino, _rdev)| s)
}

// Same resolution as `stat_path_dir_aware`, but also returns the file's
// real inode number (0 for synthetic FS / dir-root synthesis). Used by
// the stat/statx handlers so the Linux `st_ino` is a stable per-file id
// rather than a size-derived hash that aliases same-size DSOs.
fn stat_ino_path_dir_aware(path: &str) -> Option<(narf_filesystem::Stat, u64, u64)> {
    stat_ino_path_dir_aware_ext(path, true)
}

/// Like [`stat_ino_path_dir_aware`] but `follow_final` selects whether a
/// trailing symlink is followed. `lstat(2)` /
/// `fstatat(AT_SYMLINK_NOFOLLOW)` pass `false` so the returned stat
/// describes the symlink itself (S_IFLNK, st_size = target length)
/// rather than its target; plain `stat`/`fstatat` pass `true`.
fn stat_ino_path_dir_aware_ext(
    path: &str,
    follow_final: bool,
) -> Option<(narf_filesystem::Stat, u64, u64)> {
    let file = narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            if rel.is_empty() {
                None // mount root → treated as a directory below
            } else {
                // Drive the ASYNC resolver (same as the open/execve path):
                // on-disk filesystems like ext2 implement `lookup_async` but
                // stub the sync `lookup` (block reads can't run synchronously),
                // so the old `narf_filesystem::resolve` always missed real
                // files — `stat("/mnt/bin/busybox")` failed while
                // `open`/`execve` of the same path succeeded. That made every
                // PATH probe (busybox/ash search applets via stat) report
                // "not found" inside a mounted distro rootfs.
                poll_blocking(narf_filesystem::resolve_async_ext(
                    fs.root(),
                    rel,
                    follow_final,
                ))
                .and_then(|r| r.ok())
                // rdev() is needed by seatd/libudev, which validate a
                // device node's type via the MAJOR:MINOR from a PATH
                // stat (not just fstat) — a 0 rdev reads as "not an
                // evdev/drm device" and they refuse to open it.
                .map(|ops| (ops.stat(), ops.ino(), ops.rdev()))
            }
        })
        .flatten();
    if file.is_some() {
        return file;
    }
    if let Some(dir) = resolve_dir_absolute(path) {
        // Report the directory's real (chmod-settable) mode, not a
        // hardcoded 0o777 — dbus/systemd reject XDG_RUNTIME_DIR unless
        // it is not group/other-writable, so `chmod 0700` must show.
        // Thread the directory's real inode (0 for filesystems with no
        // stable id) so a dir is distinguishable from its parent —
        // systemd's rm_rf root-guard aborts ("Attempted to remove entire
        // root file system") when a dir and its parent share st_ino.
        return Some((
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode {
                    file_type: narf_filesystem::FileType::Dir,
                    perms: dir.dir_mode(),
                },
                mtime_cycles: 0,
            },
            dir.ino(),
            0,
        ));
    }
    // A path that is an ancestor of a mount point (e.g. /sys/fs when
    // /sys/fs/cgroup is mounted) has no real node in the underlying fs but
    // is logically a directory — synthesize an S_IFDIR stat so it agrees
    // with mkdir's EEXIST (see `path_is_mount_ancestor`). A path-derived
    // pseudo-inode keeps it distinct from its parent (rm_rf root-guard).
    if path_is_mount_ancestor(path) {
        let mut ino: u64 = 0xcabb_a6e0_0000_0000;
        for b in path.trim_end_matches('/').bytes() {
            ino = ino.wrapping_mul(1099511628211).wrapping_add(b as u64);
        }
        return Some((
            narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode {
                    file_type: narf_filesystem::FileType::Dir,
                    perms: 0o755,
                },
                mtime_cycles: 0,
            },
            ino,
            0,
        ));
    }
    None
}

/// `FileOps` backing an open *directory* fd (from `open(path,
/// O_DIRECTORY)` or opening a path that resolves to a directory).
/// Read/write fail; `stat` reports a directory so `fstat(2)` sees
/// `S_IFDIR`; `as_dir` hands the `DirOps` to `getdents64(2)`. The read
/// cursor lives in the fd's `offset` field.
struct DirFdFile {
    dir: alloc::sync::Arc<dyn narf_filesystem::DirOps>,
}

impl narf_filesystem::FileOps for DirFdFile {
    fn ino(&self) -> u64 {
        // Forward the backing directory's real inode so fstat(2) on an
        // open dir fd matches a path-based stat of the same directory —
        // and stays distinct from the parent (systemd's rm_rf root-guard).
        self.dir.ino()
    }

    fn read<'a>(
        &'a self,
        _offset: u64,
        _buf: &'a mut [u8],
    ) -> narf_filesystem::FsFuture<'a, usize> {
        // EISDIR — a directory fd can't be read(2), only getdents64'd.
        alloc::boxed::Box::pin(async move { Err(narf_filesystem::FsError::InvalidPath) })
    }
    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Err(narf_filesystem::FsError::InvalidPath) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        // Report the directory's real (chmod-settable) mode. A hardcoded
        // 0o777 made dbus/systemd reject XDG_RUNTIME_DIR as group/other-
        // writable even after `chmod 0700`.
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode {
                file_type: narf_filesystem::FileType::Dir,
                perms: self.dir.dir_mode(),
            },
            mtime_cycles: 0,
        }
    }
    fn as_dir(&self) -> Option<alloc::sync::Arc<dyn narf_filesystem::DirOps>> {
        Some(self.dir.clone())
    }
    /// A directory fd has no readable/writable stream (read/write are
    /// EISDIR; enumeration is getdents64). Report NOT ready so a poll/epoll
    /// consumer never spuriously wakes on it — the always-ready FileOps
    /// default made dbus-daemon busy-spin on an epoll'd service directory.
    fn poll_readiness(&self) -> u32 {
        0
    }
}

/// Test-only: install a directory fd for `path` in `task`'s fd table
/// and return it. Mirrors `sys_open`'s directory-fd fallback without
/// going through the open syscall (whose native-vs-linux ABI differs by
/// build feature). Returns `None` if `path` is not a directory or the
/// fd table is unavailable.
#[doc(hidden)]
pub fn __test_open_dir_fd(task: u64, path: &str) -> Option<u32> {
    let dirops = resolve_dir_absolute(path)?;
    fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: alloc::sync::Arc::new(DirFdFile { dir: dirops }),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
}

// ── Brk — per-task heap break ──────────────────────────────────────
//
// POSIX `brk(2)` shape: arg0 carries the requested new break, or 0
// to query. The per-task break starts at a fixed default well above
// the mmap cursor (`MMAP_CURSOR` starts at 0x4080..) and below the
// user stack (`DEFAULT_USER_STACK_BASE = 0x7FFF_FFFC_0000`). Growing
// the heap allocates frames + maps them R+W. Shrinking walks the
// per-grow Region list and calls `unmap_region` on every Region whose
// base falls in [new_break_aligned, cur_aligned) — the PTE walk inside
// `unmap_region` frees each physical page back to the allocator, so a
// task that drops back to its base on `brk(0)` doesn't leak pages
// until exit. Regions that straddle `new_break` are left intact
// (partial unmap would need a region-split primitive). POSIX brk's
// failure contract is "return the unchanged break", so allocation /
// mapping failure is silent: we just hand back the current value.
// Reference: Linux `mm/mmap.c:do_munmap` does the same "find the
// VMAs covered by the range and unmap them" walk; the partial-VMA
// case there is handled by `__split_vma` which NARF will add when a
// real workload demands it.

/// Default per-task heap base. Lives in the gap between the program image
/// (`PROGRAM_DYN_BASE = 0x0000_0080_…`) and the interpreter bias
/// (`INTERP_BIAS = 0x0000_4000_…`), and grows UP toward `BRK_ARENA_TOP`.
///
/// INVARIANT (load-bearing): the brk arena `[BRK_DEFAULT_BASE, BRK_ARENA_TOP)`
/// is DISJOINT from the anonymous mmap window
/// `[MMAP_CURSOR_BASE, MMAP_WINDOW_TOP) = [0x4080_…, 0x7F00_…)`. When brk
/// overlapped that window (the old base `0x0000_5000_…` sat inside it), a
/// `brk` grow dragged the shared `mmap_cursor` up to the heap top, so a
/// subsequent anonymous `mmap` (e.g. glibc's per-child `posix_spawn` stack)
/// was handed a VA just above the heap; its region collided with / was never
/// registered against the brk arena, and the cloned child faulted on a stack
/// with no VMA (unserviceable #PF → SIGSEGV). Keeping the arenas disjoint is
/// what Linux does (brk follows the executable, never inside the mmap region).
/// Must also stay clear of `crate::vdso::VDSO_MAP_BASE`.
const BRK_DEFAULT_BASE: u64 = 0x0000_1000_0000_0000;
/// Hard ceiling for brk growth — keeps the heap below the interpreter bias so
/// the arena can never climb into the interpreter or the mmap window.
const BRK_ARENA_TOP: u64 = 0x0000_4000_0000_0000;
const _: () = assert!(BRK_DEFAULT_BASE != crate::vdso::VDSO_MAP_BASE);
const _: () = assert!(BRK_DEFAULT_BASE < BRK_ARENA_TOP);
// The whole arena must sit below the anon mmap window so brk and mmap can
// never alias (the bug this base was moved to fix).
const _: () = assert!(BRK_ARENA_TOP <= narf_memory::AddressSpace::MMAP_CURSOR_BASE);

static BRK_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task brk registry. Boot calls this once before
/// any user task can issue `Syscall::Brk`.
pub fn brk_init() {
    *BRK_TABLE.lock() = Some(BTreeMap::new());
}

/// fork(2) inheritance: copy `parent`'s brk top to `child`.
pub fn brk_fork(parent: u64, child: u64) {
    let mut g = BRK_TABLE.lock();
    if let Some(map) = g.as_mut() {
        if let Some(&v) = map.get(&parent) {
            map.insert(child, v);
        }
    }
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_brk_reset() {
    *BRK_TABLE.lock() = Some(BTreeMap::new());
}

// ── execve — re-image the current task ─────────────────────────────
//
// POSIX execve(2) replaces the calling task's executable image
// (text + data + heap + stack) with a freshly-loaded program
// while preserving the task id, fd table, brk top, sigaction
// table, and other per-pid bookkeeping. NARF's wire shape is
// six args:
//
//   arg0 = elf bytes pointer (user vaddr)
//   arg1 = elf bytes length
//   arg2 = argv pack pointer (user vaddr) — concatenated
//          NUL-separated strings, terminated by an extra NUL
//   arg3 = argv pack length
//   arg4 = envp pack pointer (same shape)
//   arg5 = envp pack length
//
// The user-side libc shim is responsible for opening the program
// file, reading the bytes into a buffer, and packing argv/envp
// into the wire format — the syscall path doesn't open files
// because the kernel-side VFS surface is async and the syscall
// handler can't safely block_on (it runs from inside the
// executor's poll body for the calling task).
//
// Implementation flow:
//   1. Validate args (non-null pointers, sane lengths).
//   2. Copy ELF bytes from user memory into a kernel-owned Vec
//      (the user buffer is about to be unmapped when we activate
//      the new AS — must capture before that point).
//   3. Parse argv + envp from packs into kernel-owned Vec<String>.
//   4. Call `load_user_process_with(elf, argv, envp, &[])` which
//      builds a fresh AddressSpace, materialises page tables,
//      lays out the SysV startup contract on the stack, and
//      returns a UserProcess.
//   5. Replace the scheduler slot's `addr_space` so future polls
//      activate the new AS.
//   6. Box an ExecRequest carrying the new AS + entry + stack;
//      publish via `ctx.pending_exec`.
//   7. Set `exit_reason = EXIT_REASON_EXECVE`.
//   8. Save user state (the polling routine reads it but the
//      EXECVE branch ignores the saved RIP — the new image
//      starts at its own entry).
//   9. Call the EXECVE hook → longjmps into the polling
//      routine. The polling routine sees EXIT_REASON_EXECVE,
//      consumes pending_exec, swaps the future's UserProcess,
//      and re-polls. The next iteration enters user mode at
//      the new entry with a fresh GPR file and zeroed RFLAGS.
//
// POSIX preserve list (unchanged across execve): pid, ppid,
// fd table (close-on-exec scrubbing is a future refinement),
// brk top, working directory, sigaction handlers (SIG_IGN +
// SIG_DFL stay as-is; user-installed handlers reset to SIG_DFL
// per POSIX §8.5.4 — we don't enforce that yet, future fix).

/// Shared execve body: `path_owned` is the already-resolved (kernel-side)
/// pathname of the image; `argv_uptr`/`envp_uptr` are the user vectors.
/// `image_override`, when `Some`, supplies the ELF bytes directly (skipping
/// path resolution + shebang) — used by `execveat(fd,"",AT_EMPTY_PATH)` on a
/// pathless fd (a memfd; systemd fexecve's its sd-executor from a sealed
/// memfd copy). `path_owned` is then just the /proc/self/exe label.
/// `sys_execve` (path from user) and `sys_execveat` (dirfd/AT_EMPTY_PATH)
/// funnel through here.
fn do_execve_resolved(
    ctx: &mut dyn TrapContext,
    mut path_owned: alloc::string::String,
    argv_uptr: u64,
    envp_uptr: u64,
    mut image_override: Option<alloc::vec::Vec<u8>>,
) {
    // fexecve via the /proc/self/fd/N (or /proc/<pid>/fd/N) magic symlink:
    // glibc's fexecve and systemd 257's sd-executor spawn open the binary
    // O_PATH then execve("/proc/self/fd/<N>"). Resolve N to the fd's real
    // filesystem path (on-disk binary) or, failing that, its bytes (memfd).
    if image_override.is_none() {
        if let Some(n) = parse_proc_self_fd(&path_owned) {
            let t = current_task_id();
            // Only an ABSOLUTE filesystem path is exec'able by re-reading the FS.
            // A pathless/anonymous fd (a memfd — systemd seals its sd-executor
            // into a memfd and fexecve's /proc/self/fd/N — whose recorded "path"
            // is the "anon_inode:[FileOps]" placeholder) must be exec'd from the
            // fd's own bytes instead.
            let fs_path = fd_path_of(t, n).filter(|p| p.starts_with('/'));
            if let Some(real) = fs_path {
                path_owned = real;
            } else if let Some(bytes) = read_fd_image(t, n) {
                image_override = Some(bytes);
            }
        }
    }
    let path: &str = &path_owned;

    #[cfg(feature = "syscall-trace")]
    {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "EXECVE path={}", path);
    }

    // Step 2: copy argv + envp — each a NUL-terminated array of
    // user-mode `char *`, walked until the first null pointer.
    let argv_strs = match copy_user_strarr(argv_uptr, 1024) {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let envp_strs = match copy_user_strarr(envp_uptr, 4096) {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let envp_refs: alloc::vec::Vec<&str> = envp_strs.iter().map(|s| s.as_str()).collect();

    // Resolve a path under the caller's chroot (containers/distros exec
    // `/bin/sh` expecting the chrooted rootfs) and slurp its bytes, capped at
    // 64 MiB. Returns the bytes, or a negative errno on failure. The errno
    // distinction is load-bearing: `execvp(3)` PATH-searches by execve'ing
    // each candidate and treating -ENOENT as "try the next dir" but -EINVAL/
    // -EIO as fatal. Returning EINVAL for a not-found path (the old behaviour)
    // aborted the search on the first miss, so any binary not in the first
    // PATH entry (e.g. weston in /usr/bin while PATH starts with /bin) was
    // "can't execute: Invalid argument" even though it existed.
    let read_exec = |p: &str| -> Result<alloc::vec::Vec<u8>, i64> {
        let ep = apply_chroot(p);
        let ops = match narf_filesystem::registry().resolve_absolute(&ep, |fs, rel| {
            poll_blocking(narf_filesystem::resolve_async(fs.root(), rel))
        }) {
            Some(Some(Ok(o))) => o,
            // Not found (or no mount) → ENOENT so execvp keeps searching PATH.
            None | Some(Some(Err(narf_filesystem::FsError::NotFound))) => return Err(-2),
            // poll_blocking overran, or a real FS error → EIO.
            Some(None) | Some(Some(Err(_))) => return Err(-5),
        };
        let file_size = ops.stat().size as usize;
        if file_size == 0 {
            return Err(-8); // ENOEXEC — empty file is not an executable
        }
        if file_size > 64 * 1024 * 1024 {
            return Err(-7); // E2BIG
        }
        let mut buf = alloc::vec![0u8; file_size];
        let mut off = 0usize;
        while off < file_size {
            match poll_blocking(ops.read(off as u64, &mut buf[off..])) {
                Some(Ok(0)) => break, // short read at EOF
                Some(Ok(n)) => off += n,
                _ => return Err(-5), // EIO
            }
        }
        buf.truncate(off);
        Ok(buf)
    };

    // Step 3: read the image. A leading `#!` is an interpreter directive
    // (Linux fs/binfmt_script.c): re-target exec at the named interpreter
    // with the script path spliced into argv as
    //   [interp, optional-arg, scriptpath, original-argv[1..]]
    // Follow nested shebangs up to a small depth so a script interpreting a
    // script still terminates. Without this, every `#!`-script execve EINVALs.
    let mut cur_path = alloc::string::String::from(path);
    let mut cur_argv: alloc::vec::Vec<alloc::string::String> = argv_strs.clone();
    let elf_buf;
    // fexecve fast path: the bytes are already in hand (a memfd fd with no
    // filesystem path). Skip path resolution + shebang — a fexecve'd image is
    // a real binary, and argv[0] is whatever the caller passed.
    if let Some(bytes) = image_override {
        if bytes.len() < 64 {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
        elf_buf = bytes;
    } else {
        let mut depth = 0u32;
        loop {
            let buf = match read_exec(&cur_path) {
                Ok(b) => b,
                Err(code) => {
                    ctx.set_return(SyscallReturn::ok(code as u64));
                    return;
                }
            };
            if buf.len() >= 2 && &buf[..2] == b"#!" {
                if depth >= 4 {
                    ctx.set_return(SyscallReturn::ok((-40i64) as u64)); // -ELOOP
                    return;
                }
                depth += 1;
                let line_end = buf.iter().position(|&c| c == b'\n').unwrap_or(buf.len());
                let line = core::str::from_utf8(&buf[2..line_end]).unwrap_or("").trim();
                // interpreter = first whitespace-delimited token; the remainder
                // (trimmed) is a SINGLE optional argument (Linux semantics).
                let (interp, optarg) = match line.find([' ', '\t']) {
                    Some(i) => {
                        let rest = line[i..].trim();
                        (&line[..i], if rest.is_empty() { None } else { Some(rest) })
                    }
                    None => (line, None),
                };
                if interp.is_empty() {
                    ctx.set_return(SyscallReturn::invalid_op());
                    return;
                }
                let mut new_argv: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
                new_argv.push(interp.into());
                if let Some(a) = optarg {
                    new_argv.push(a.into());
                }
                new_argv.push(cur_path.clone());
                new_argv.extend(cur_argv.iter().skip(1).cloned());
                cur_path = interp.into();
                cur_argv = new_argv;
                continue;
            }
            if buf.len() < 64 {
                // Too small for a valid ELF and not a shebang.
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
            elf_buf = buf;
            break;
        }
    }
    let argv_refs: alloc::vec::Vec<&str> = cur_argv.iter().map(|s| s.as_str()).collect();

    // Step 4: load the new image. SAFETY: load_user_process_with's
    // contract — identity-mapped low 4 GiB, frame allocator
    // initialised. Both hold by the time any user task is running.
    // SAFETY: Valid memory or trusted environment
    let new_proc = match unsafe {
        crate::process::load_user_process_with(&elf_buf, &argv_refs, &envp_refs, &[])
    } {
        Ok(p) => p,
        Err(_) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    let task = current_task_id();

    // CLONE_VFORK release: this child is now replacing its image, so it no
    // longer needs the shared address space — wake a parent suspended in
    // do_clone3's vfork park. (Load succeeded above, so the exec is committed.)
    #[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
    vfork_child_release(task_to_pid_raw(task).unwrap_or(task));

    // POSIX execve: reset caught signal handlers to SIG_DFL — their code
    // addresses belong to the old image. (Inherited e.g. via fork from a shell
    // that handles SIGCHLD; without this the next SIGCHLD branches to the stale
    // handler vaddr in the new image and crashes.) Mask + pending are kept.
    sigaction_exec_reset(task);
    // The alternate signal stack, robust-list head, and clear_child_tid
    // uaddr all point into the OLD image's address space — Linux clears
    // all three on exec. A surviving sigaltstack sp would have the next
    // SA_ONSTACK delivery build a frame at an address the new image
    // repurposed (wild user-stack write); a surviving clear_child_tid
    // would zero an arbitrary word in the new image on exit.
    if let Some(m) = SIG_ALTSTACK.lock().as_mut() {
        m.remove(&task);
    }
    if let Some(m) = ROBUST_LIST_TABLE.lock().as_mut() {
        m.remove(&task);
    }
    // clear_child_tid tracking is a linux-compat-only path.
    #[cfg(feature = "linux-compat")]
    let _ = take_clear_child_tid(task);
    // FD_CLOEXEC sweep: close every fd marked close-on-exec (Linux
    // does this in the exec path). Without it, O_CLOEXEC fds leak
    // across exec — an fd-table leak that is also a sandbox-escape
    // vector (a descriptor the new image was never meant to inherit).
    crate::fd::close_cloexec(task);

    // /proc/[pid]/cmdline + comm: preserve argv as NUL-separated
    // bytes, derive comm from argv[0]'s basename (Linux convention).
    set_proc_argv(task, &argv_refs);
    if let Some(first) = argv_refs.first() {
        let basename = first.rsplit('/').next().unwrap_or(first);
        set_proc_comm(task, basename);
    }
    // /proc/[pid]/exe: `cur_path` survived the shebang loop, so it names
    // the binary actually being mapped (the interpreter for scripts).
    set_proc_exe(task, &cur_path);

    // Step 5: swap the scheduler slot's AS Arc. Without this the
    // poll path's later activate() would still target the old AS
    // until the future's process.address_space update lands.
    let _prev_slot_as = narf_scheduler::replace_address_space(
        narf_scheduler::TaskId(task),
        new_proc.address_space.clone(),
    );

    // Own-stack model: there is no poll trap-back half to apply a staged
    // ExecRequest after a longjmp. Apply the new image inline — activate the new
    // AS + TLS, then enter the new entry at the TOP of this task's own kernel
    // stack (abandoning the execve syscall frames), which DIVERGES.
    #[cfg(target_arch = "x86_64")]
    if narf_scheduler::stackful::user_own_stack_enabled() {
        let entry = new_proc.entry.0.as_u64();
        let rsp = new_proc.stack_top.as_u64();
        let _ = new_proc.address_space.activate();
        // Publish the new CR3 so a later preempt/park resume re-activates the
        // post-execve AS (not the pre-execve one) — see set_current_user_cr3.
        {
            let cr3: u64;
            // SAFETY: Reading the current CPU's CR3 register has no side-effects.
            unsafe {
                core::arch::asm!("mov {v}, cr3", v = out(reg) cr3,
                    options(nostack, nomem, preserves_flags));
            }
            narf_scheduler::stackful::set_current_user_cr3(cr3);
        }
        if let Some(fb) = new_proc.fs_base {
            // SAFETY: canonical user vaddr from the new image's TLS staging.
            unsafe { narf_scheduler::set_user_fs_base(fb) };
        }
        let top = narf_scheduler::stackful::current_stackful_stack_top();
        // SAFETY: new AS active; entry/rsp mapped by the loader; resets RSP to
        // this task's own kernel-stack top and iretq's into the new image.
        unsafe { narf_scheduler::enter_user_mode_at_top(entry, rsp, top) };
    }

    // Step 6: package the new image into an ExecRequest and
    // publish via the calling task's UserTaskCtx so the polling
    // routine can apply it after the longjmp returns.
    let req = alloc::boxed::Box::new(crate::user_task::ExecRequest {
        new_as: new_proc.address_space.clone(),
        entry: new_proc.entry.0.as_u64(),
        stack_top: new_proc.stack_top.as_u64(),
        fs_base: new_proc.fs_base,
    });
    let uctx_ptr = match crate::user_task::current_user_task() {
        Some(p) => p,
        None => {
            // No active user-task ctx — execve called outside a
            // polling future (e.g. from a kernel-test stub). Roll
            // back the slot AS swap and bail.
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // SAFETY: uctx_ptr is valid for the duration of the polling
    // routine's user-mode round-trip (the routine pinned it).
    // SAFETY: Valid memory or trusted environment
    unsafe {
        let prev = (*uctx_ptr)
            .pending_exec
            .swap(alloc::boxed::Box::into_raw(req), Ordering::AcqRel);
        if !prev.is_null() {
            // Another execve was queued and never consumed — drop it
            // so the frame doesn't leak.
            let _ = alloc::boxed::Box::from_raw(prev);
        }
    }

    // Step 7-9: longjmp into the polling routine via the EXECVE
    // hook. save_user_state populates the slot for invariant; the
    // EXECVE branch ignores the saved RIP/RSP since the new image
    // has its own entry.
    if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: same — uctx is live throughout the round-trip.
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_EXECVE;
        }
    }
    let hook = crate::user_task::execve_hook();
    if let Some(h) = hook {
        // SAFETY: hook is a fn ptr installed at boot; uctx is live.
        unsafe { h(uctx_ptr) };
        // longjmp doesn't return; if it does (no jmp buf installed),
        // surface a clean error.
    }
    // Fallback path — execve not wired (e.g. early boot or test).
    ctx.set_return(SyscallReturn::invalid_op());
}

/// A `TrapContext` proxy that overrides the syscall args while forwarding
/// the return + control-flow hooks to the wrapped context. Used by the
/// `*at`/`*at2` reshapers to call an existing handler with a different
/// argument layout.
struct ArgReshape<'a> {
    inner: &'a mut dyn TrapContext,
    args: SyscallArgs,
}
impl<'a> TrapContext for ArgReshape<'a> {
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

/// Parse `/proc/self/fd/<N>` or `/proc/<pid>/fd/<N>` → the fd number `N`.
/// These are the magic symlinks glibc's fexecve / systemd's spawn execve.
pub(crate) fn parse_proc_self_fd(path: &str) -> Option<u32> {
    let rest = if let Some(r) = path.strip_prefix("/proc/self/fd/") {
        r
    } else {
        let r = path.strip_prefix("/proc/")?;
        let (pid, tail) = r.split_once("/fd/")?;
        if pid.parse::<u64>().is_err() {
            return None;
        }
        tail
    };
    // Reject a trailing sub-path (e.g. /proc/self/fd/3/foo) — only the bare fd.
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    rest.parse::<u32>().ok()
}

/// Read an entire open fd's contents into a Vec (for `execveat(fd,"",
/// AT_EMPTY_PATH)` on a pathless fd such as a memfd). Returns None if the fd
/// isn't open, isn't readable, or is empty.
fn read_fd_image(task: u64, fd: u32) -> Option<alloc::vec::Vec<u8>> {
    let ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let size = ops.stat().size as usize;
    if size == 0 || size > 64 * 1024 * 1024 {
        return None;
    }
    let mut buf = alloc::vec![0u8; size];
    let mut off = 0usize;
    while off < size {
        match poll_blocking(ops.read(off as u64, &mut buf[off..])) {
            Some(Ok(0)) => break,
            Some(Ok(n)) => off += n,
            _ => return None,
        }
    }
    buf.truncate(off);
    if buf.len() < 64 {
        None
    } else {
        Some(buf)
    }
}

/// Parse a NUL-separated user-supplied string pack into a Vec of
/// kernel-owned `String`s. Returns Err on any UTF-8 violation,
/// pointer issue, or pack-too-long-without-terminator condition.
///
/// Pack format: zero or more strings, each terminated by a NUL
/// byte. The pack itself is `len` bytes long; we read until we
/// see len bytes total. An empty pack (len == 0) returns an
/// empty Vec (legal — `execve` with no argv).
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn copy_user_pack(
    ptr: *const u8,
    len: usize,
) -> Result<alloc::vec::Vec<alloc::string::String>, ()> {
    if len == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    if ptr.is_null() || len > 64 * 1024 {
        return Err(());
    }
    // Copy the whole pack into a kernel Vec under the SMAP bracket first,
    // then parse without touching user memory again.
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: ptr is a user VA; SMAP bracket inside copy_from_user.
    unsafe { copy_from_user(&mut buf, ptr as u64) }.map_err(|_| ())?;
    // Split on NUL boundaries.
    let mut out = alloc::vec::Vec::new();
    let mut start = 0usize;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            if start < i {
                let s = core::str::from_utf8(&buf[start..i]).map_err(|_| ())?;
                out.push(alloc::string::String::from(s));
            }
            start = i + 1;
        }
    }
    Ok(out)
}

// ── mount / umount2 / statfs / fstatfs ─────────────────────────────
//
// POSIX-2017 mount-control surface. The kernel's `narf_filesystem`
// crate already exposes a cap-gated VfsRegistry; these handlers wire
// userspace through to it. The cap-mint (a `Cap<MountPoint, Grant>`)
// is TCB-only — userspace cannot forge one — so the syscall itself
// is the privilege boundary. Today we accept any caller; once UID/
// GID land we'll gate on UID==0 (root) per POSIX `mount(2)`.

#[allow(dead_code)]
fn copy_user_str(ptr: *const u8, len: usize, cap: usize) -> Result<alloc::string::String, ()> {
    if len == 0 || ptr.is_null() || len > cap {
        return Err(());
    }
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: ptr is a user VA; SMAP bracket inside copy_from_user.
    unsafe { copy_from_user(&mut buf, ptr as u64) }.map_err(|_| ())?;
    core::str::from_utf8(&buf)
        .map(alloc::string::String::from)
        .map_err(|_| ())
}

/// Copy a path string from userspace into a kernel-owned `String`.
///
/// - `ptr`: raw userspace pointer (u64 — already cast from *const u8)
/// - `len`: byte length of the path string
///
/// Uses [`copy_from_user`] for the SMAP-bracketed copy, then validates
/// as UTF-8.  Returns `None` on null pointer, zero length, length > 4 KiB,
/// copy failure, or UTF-8 violation.
///
/// Under `linux-compat`, absolute paths are rewritten through the
/// calling task's chroot prefix (if any) so every path-resolving
/// syscall transparently respects chroot(2) / pivot_root(2). Use
/// `copy_user_path_raw` to bypass the chroot rewrite (the chroot
/// syscalls themselves want the literal user string).
fn copy_user_path(ptr: u64, len: usize) -> Option<alloc::string::String> {
    let raw = copy_user_path_raw(ptr, len)?;
    Some(apply_chroot(&raw))
}

/// Copy a NUL-terminated C string from user memory. Reads up to
/// `max_len` bytes (defensive cap) and stops at the first NUL.
/// Returns `None` on any of: null ptr, copy fault, non-UTF-8,
/// no NUL within `max_len`.
///
/// Used by execve(2), stat(2), and friends — Linux-shape syscalls
/// whose path arg is just a bare user pointer with no length, and
/// the kernel finds the end at the NUL.
pub(crate) fn copy_user_cstr(ptr: u64, max_len: usize) -> Option<alloc::string::String> {
    if ptr == 0 || max_len == 0 || max_len > 65536 {
        return None;
    }
    // Bulk-reading `max_len` blindly would walk past the NUL into
    // pages that may not be mapped (a path string that ends near a
    // page boundary). Read in page-sized chunks until we find the
    // NUL or hit `max_len`.
    let mut out = alloc::vec::Vec::with_capacity(64);
    let mut cursor = ptr;
    let end_cap = ptr.saturating_add(max_len as u64);
    while cursor < end_cap {
        // Read up to the next page boundary, capped at the remaining
        // budget.
        let next_page = (cursor + 0x1000) & !0xFFF;
        let chunk_end = next_page.min(end_cap);
        let chunk_len = (chunk_end - cursor) as usize;
        let mut chunk = alloc::vec![0u8; chunk_len];
        // SAFETY: SMAP bracket inside copy_from_user; pointer
        // validated against canonical range there.
        // SAFETY: Valid memory or trusted environment
        unsafe { copy_from_user(&mut chunk, cursor) }.ok()?;
        if let Some(nul_pos) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul_pos]);
            return alloc::string::String::from_utf8(out).ok();
        }
        out.extend_from_slice(&chunk);
        cursor = chunk_end;
    }
    // Never found NUL within max_len.
    None
}

/// Walk a NULL-terminated user array of `char *` (e.g. argv or
/// envp). Each element points to a C string copied via
/// [`copy_user_cstr`]. Returns `None` on any copy fault or if
/// the array doesn't terminate within `max_entries`.
fn copy_user_strarr(
    arr_ptr: u64,
    max_entries: usize,
) -> Option<alloc::vec::Vec<alloc::string::String>> {
    if arr_ptr == 0 {
        // POSIX permits argv=NULL to mean "no args"; envp=NULL
        // similarly. Treat as empty rather than rejecting.
        return Some(alloc::vec::Vec::new());
    }
    let mut out = alloc::vec::Vec::new();
    for i in 0..max_entries {
        let slot_ptr = arr_ptr.checked_add((i as u64) * 8)?;
        let mut slot_bytes = [0u8; 8];
        // SAFETY: SMAP bracket inside copy_from_user.
        unsafe { copy_from_user(&mut slot_bytes, slot_ptr) }.ok()?;
        let element_ptr = u64::from_le_bytes(slot_bytes);
        if element_ptr == 0 {
            // NULL terminator → end of array.
            return Some(out);
        }
        out.push(copy_user_cstr(element_ptr, 4096)?);
    }
    // Array didn't terminate — reject rather than truncate silently.
    None
}

/// Like `copy_user_path` but never applies the chroot rewrite. Used
/// by chroot(2) / pivot_root(2) themselves so the kernel sees the
/// literal target the caller typed.
fn copy_user_path_raw(ptr: u64, len: usize) -> Option<alloc::string::String> {
    if len == 0 || ptr == 0 || len > 4096 {
        return None;
    }
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: ptr is a user VA; SMAP bracket inside copy_from_user.
    unsafe { copy_from_user(&mut buf, ptr) }.ok()?;
    core::str::from_utf8(&buf)
        .map(alloc::string::String::from)
        .ok()
}

// ── SMAP-safe user-memory copy helpers ────────────────────────────
//
// Linux analogues: `arch/x86/include/asm/uaccess.h` `copy_from_user`
// / `copy_to_user`, which open a `user_access_begin` / `user_access_end`
// (STAC/CLAC) window around the actual memory transfer.
//
// NARF stance: the bulk transfers below go through
// `narf_arch::x86_64::smap::copy_user_guarded`, which brackets the
// copy with STAC/CLAC *and* arms the per-CPU recoverable probe so an
// unrecoverable fault mid-copy (#GP on a non-canonical address, #PF
// on a range a sibling thread munmap'd after validation) returns
// -EFAULT instead of panicking the kernel — Linux's exception-table
// fixup semantics. `smap::with_user_access` remains the sanctioned
// bracket for the small fixed-size accesses elsewhere. On non-x86_64
// targets the helpers degrade to a plain volatile copy because those
// architectures have no SMAP equivalent (and no probe wiring yet).
//
// Maximum single-call transfer: 16 MiB.  Larger requests are rejected
// with EINVAL (-22) so a malicious/buggy userspace cannot force a
// multi-gigabyte kernel allocation.

/// Linux EFAULT errno value (14).
const EFAULT: u64 = 14;
/// Linux EINVAL errno value (22).
const EINVAL_CODE: u64 = 22;
/// 16 MiB per-call cap.
const MAX_USER_COPY: usize = 16 * 1024 * 1024;

/// Validate that `[ptr, ptr + len)` is a plausible pointer.
///
/// Rejects:
/// - `ptr == 0` (null) → EFAULT
/// - `len > MAX_USER_COPY` → EINVAL
/// - Integer overflow of `ptr + len` → EFAULT
/// - A non-canonical FIRST or LAST byte address (bits 47–63 partial —
///   neither all-zero for user-space nor all-one for kernel-space),
///   or a range whose ends sit in different halves → EFAULT.
///   Checking the last byte matters: a canonical user-half base whose
///   `len` pushes the range across 0x0000_8000_0000_0000 would walk
///   the kernel copy into the canonical hole — a mid-`rep movsb`
///   **#GP**, not #PF, because non-canonical linear addresses are the
///   one data-access fault x86_64 reports as #GP (stress-ng --vma's
///   randomized write() buffers hit exactly this).
///
/// Note: canonical kernel-half addresses (≥ 0xFFFF_8000_0000_0000)
/// are intentionally *not* rejected here.  In production the hardware
/// SMAP bit enforces the user/kernel boundary (kernel pages have
/// PTE.U=0 so the STAC bracket opens silently and the copy succeeds);
/// kernel-test code legitimately passes kernel-heap pointers through
/// this path.  A future hardening pass can add a strict user-only
/// range assertion once the test infrastructure maps every test buffer
/// into a user AddressSpace.
///
/// Linux analogue: `access_ok()` in `arch/x86/include/asm/uaccess.h`
/// which similarly trusts the user-range upper bound and the HW
/// enforcement rather than hard-checking the kernel half at this layer.
#[inline]
pub(crate) fn validate_user_range(ptr: u64, len: usize) -> Result<(), u64> {
    if len > MAX_USER_COPY {
        return Err(EINVAL_CODE);
    }
    if ptr == 0 {
        return Err(EFAULT);
    }
    // Reject integer overflow of the range end.
    if ptr.checked_add(len as u64).is_none() {
        return Err(EFAULT);
    }
    // Reject non-canonical addresses (x86_64/aarch64 require bits 48–63
    // to be the sign-extension of bit 47).
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        // Canonical 48-bit VA: bits 47..=63 all-zero (user half) or
        // all-one (kernel half). Bit 63 and bit 47 are PART of the
        // rule — a previous version of this check masked bit 63 out
        // and only examined bits 48..=62, so the non-canonical shapes
        //   0x8000_0000_0000_0000 (bit 63 set, middle bits clear) and
        //   0x7FFF_8000_0000_0000 (bit 63 clear, middle bits set)
        // slipped through and the copy took a kernel #GP.
        #[inline]
        fn canonical(a: u64) -> bool {
            let top = a >> 47; // bits 47..=63, 17 bits
            top == 0 || top == 0x1_FFFF
        }
        if !canonical(ptr) {
            return Err(EFAULT);
        }
        // The LAST byte must be canonical too, and in the same half:
        // a range must not span the canonical hole (see the doc
        // comment). `ptr + len` can't overflow — checked above — so
        // `ptr + len - 1` can't either for len > 0.
        if len > 0 {
            let last = ptr + (len as u64 - 1);
            if !canonical(last) || (last >> 63) != (ptr >> 63) {
                return Err(EFAULT);
            }
        }
    }
    Ok(())
}

/// Copy `len` bytes from userspace address `src_uptr` into the
/// kernel-owned slice `dst`.
///
/// Opens the SMAP window (`STAC`) for the duration of the transfer,
/// then closes it (`CLAC`). On non-x86_64 targets the bracket is a
/// no-op.
///
/// Returns `Ok(())` on success or `Err(errno)` on validation failure.
/// The caller converts the errno to a negative `SyscallReturn::ok` value.
///
/// # Safety
/// - The caller's address space must match the AS that mapped `src_uptr`.
/// - Must not be called from IRQ context.
pub(crate) unsafe fn copy_from_user(dst: &mut [u8], src_uptr: u64) -> Result<(), u64> {
    validate_user_range(src_uptr, dst.len())?;
    let src = src_uptr as *const u8;
    // SAFETY: dst is a live kernel slice; src is range-validated; the
    // guarded copy opens the SMAP bracket itself and catches any
    // unrecoverable fault (#GP non-canonical, #PF on an address a
    // racing munmap just removed from the AS) as Err instead of a
    // kernel panic — Linux's extable-fixup -EFAULT semantics.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::x86_64::smap::copy_user_guarded(dst.as_mut_ptr(), src, dst.len())
            .map_err(|_remaining| EFAULT)?;
    }
    // SAFETY: range-validated above; no SMAP on non-x86_64, so a plain
    // volatile read of each in-range user byte is the access path.
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        for (i, b) in dst.iter_mut().enumerate() {
            *b = core::ptr::read_volatile(src.add(i));
        }
    }
    Ok(())
}

/// Allocate a kernel `Vec<u8>` of `len` bytes and fill it from userspace
/// address `src_uptr`.
///
/// Validates `len <= MAX_USER_COPY` (EINVAL) and pointer canonicality
/// (EFAULT) *before* the allocation, so an oversized user-supplied length
/// never reaches the heap allocator.  This is the correct helper to use
/// whenever a syscall would otherwise `vec![0u8; len]` and then call
/// `copy_from_user` — the two steps are merged here so the ordering
/// cannot be violated per call site.
///
/// # Safety
/// Same as `copy_from_user`.
pub(crate) unsafe fn copy_from_user_vec(
    src_uptr: u64,
    len: usize,
) -> Result<alloc::vec::Vec<u8>, u64> {
    validate_user_range(src_uptr, len)?;
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: validated above; SMAP bracket inside copy_from_user.
    unsafe { copy_from_user(&mut buf, src_uptr) }?;
    Ok(buf)
}

/// Copy `len` bytes from the kernel-owned slice `src` into userspace
/// address `dst_uptr`.
///
/// Mirror of [`copy_from_user`] for the write direction.
///
/// # Safety
/// Same as `copy_from_user`.
pub(crate) unsafe fn copy_to_user(dst_uptr: u64, src: &[u8]) -> Result<(), u64> {
    validate_user_range(dst_uptr, src.len())?;
    let dst = dst_uptr as *mut u8;
    // SAFETY: src is a live kernel slice; dst is range-validated; the
    // guarded copy opens the SMAP bracket itself and catches any
    // unrecoverable fault as Err — see copy_from_user.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        narf_arch::x86_64::smap::copy_user_guarded(dst, src.as_ptr(), src.len())
            .map_err(|_remaining| EFAULT)?;
    }
    // SAFETY: range-validated above; no SMAP on non-x86_64, so a plain
    // volatile write of each in-range user byte is the access path.
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: Valid memory or trusted environment
    unsafe {
        for (i, b) in src.iter().enumerate() {
            core::ptr::write_volatile(dst.add(i), *b);
        }
    }
    Ok(())
}

// Wave-71: Linux MS_* flag bits — userspace passes them in arg5.
// Only the bits NARF acts on are documented here; the rest are
// accepted but currently a no-op (relatime, nosuid, nodev, noexec,
// ro modulate read-only state — they're parked until the FsInstance
// trait grows a per-mount option vector).
const MS_RDONLY: u64 = 1 << 0;
const MS_NOSUID: u64 = 1 << 1;
const MS_NODEV: u64 = 1 << 2;
const MS_NOEXEC: u64 = 1 << 3;
const MS_REMOUNT: u64 = 1 << 5;
const MS_BIND: u64 = 1 << 12;
const MS_MOVE: u64 = 1 << 13;
const MS_REC: u64 = 1 << 14;
// Mount-propagation flags. When any of these is set, Linux `mount(2)` ONLY
// changes the propagation type of the mount already at `target` — source,
// fstype and data are ignored and nothing new is mounted. NARF does not model
// propagation (all mounts are effectively private), so honouring these as a
// no-op success is the correct behaviour. systemd's generator/service sandbox
// does `mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL)` right after
// `clone(CLONE_NEWNS)`; failing it aborted the sandbox fork ("Protocol error")
// and left an empty generator dir that tripped systemd's rm_rf root-guard.
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const MS_PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;
const MS_RELATIME: u64 = 1 << 21;

// Wave-71: Linux MNT_* flags for umount2(2).
const MNT_FORCE: u64 = 1 << 0;
const MNT_DETACH: u64 = 1 << 1;
const MNT_EXPIRE: u64 = 1 << 2;
const UMOUNT_NOFOLLOW: u64 = 1 << 3;

/// Linux x86_64 `struct statfs` (fs/statfs). The FIRST field is `f_type`,
/// the filesystem super-magic — programs like elogind statfs a path and check
/// `f_type == CGROUP2_SUPER_MAGIC` to detect an already-mounted cgroup2. The
/// previous shape here was a `statvfs` (started with `f_bsize`), so `f_type`
/// read back as a block size and every magic check failed. 15 × u64 = 120 B.
#[repr(C)]
#[derive(Default)]
struct StatfsBuf {
    f_type: u64,    // filesystem super-magic
    f_bsize: u64,   // block size in bytes
    f_blocks: u64,  // total blocks
    f_bfree: u64,   // free blocks
    f_bavail: u64,  // free blocks available to non-root
    f_files: u64,   // total inodes
    f_ffree: u64,   // free inodes
    f_fsid: u64,    // fs id (two int32; unused → 0)
    f_namelen: u64, // max filename length
    f_frsize: u64,  // fragment size
    f_flags: u64,   // mount flags (unused)
    f_spare0: u64,
    f_spare1: u64,
    f_spare2: u64,
    f_spare3: u64,
}

// Linux super-magics (include/uapi/linux/magic.h) userspace probes for.
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const EXT2_SUPER_MAGIC: u64 = 0xEF53;

fn fill_statfs_for_path(path: &str, buf_ptr: u64) -> bool {
    if buf_ptr == 0 {
        return false;
    }
    // Map the filesystem covering `path` to its Linux super-magic so callers
    // detect the fs type (elogind → CGROUP2_SUPER_MAGIC at /sys/fs/cgroup).
    let fs_name = narf_filesystem::registry()
        .resolve_absolute(path, |fs, _rel| alloc::string::String::from(fs.name()));
    let f_type = match fs_name.as_deref() {
        Some("cgroup2") | Some("cgroup") => CGROUP2_SUPER_MAGIC,
        Some("sysfs") => SYSFS_MAGIC,
        Some("procfs") | Some("proc") => PROC_SUPER_MAGIC,
        Some(n) if n.starts_with("ext") => EXT2_SUPER_MAGIC,
        Some(_) => TMPFS_MAGIC, // tmpfs / devtmpfs / shm / other memfs-backed
        None => return false,   // no mount covers the path
    };
    let stat = StatfsBuf {
        f_type,
        f_bsize: 4096,
        f_namelen: 255,
        f_frsize: 4096,
        ..Default::default()
    };
    // Copy the statfs struct to user space under the SMAP bracket.
    // SAFETY: StatfsBuf is repr(C) of fifteen u64s with no padding; transmuting
    // it to a `[u8; size_of::<StatfsBuf>()]` reinterprets its bytes 1:1.
    let bytes: [u8; core::mem::size_of::<StatfsBuf>()] = unsafe { core::mem::transmute(stat) };
    // SAFETY: `buf_ptr` is the user statfs buffer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `bytes`.
    unsafe { copy_to_user(buf_ptr, &bytes) }.is_ok()
}

// Per-task mount namespace table. Entries appear here when a task
// calls unshare(CLONE_NEWNS); absent entries fall back to the
// global VfsRegistry. Today every mount-touching syscall still
// consults the global registry — the per-task lookup wires in
// once a multi-namespace workload (a la container) needs it.
static TASK_MOUNT_NS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::sync::Arc<narf_filesystem::MountNamespace>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn task_mount_ns_init() {
    let mut g = TASK_MOUNT_NS.lock();
    if g.is_none() {
        *g = Some(alloc::collections::BTreeMap::new());
    }
}

/// Look up the calling task's mount namespace. None means the task
/// shares the global registry (the default).
pub fn current_mount_namespace() -> Option<alloc::sync::Arc<narf_filesystem::MountNamespace>> {
    let task = current_task_id();
    let g = TASK_MOUNT_NS.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// Look up the mount namespace of an arbitrary task by id.
#[cfg(feature = "container")]
pub fn mount_namespace_of(task: u64) -> Option<alloc::sync::Arc<narf_filesystem::MountNamespace>> {
    let g = TASK_MOUNT_NS.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// Wave-67 — install a private mount namespace for `task`. Replaces
/// any existing entry. Used by `setns` and the fork-inheritance
/// path.
#[cfg(feature = "container")]
pub fn install_mount_namespace(task: u64, ns: alloc::sync::Arc<narf_filesystem::MountNamespace>) {
    task_mount_ns_init();
    let mut g = TASK_MOUNT_NS.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task, ns);
    }
}

/// Wave-67 — child inherits the parent's mount namespace by Arc
/// share (no deep clone — they keep the same view until one calls
/// unshare(CLONE_NEWNS) again). A parent in the root-global view
/// leaves the child in the same root-global view.
#[cfg(feature = "container")]
fn mount_ns_inherit(parent_task: u64, child_task: u64) {
    let parent_ns = {
        let g = TASK_MOUNT_NS.lock();
        g.as_ref().and_then(|m| m.get(&parent_task).cloned())
    };
    if let Some(ns) = parent_ns {
        install_mount_namespace(child_task, ns);
    }
}

// ── procfs /proc/<pid>/ns/* + uid_map/gid_map + mountinfo hooks ──
//
// Installed via `narf_filesystem::procfs::install_ns_proc_hooks` at
// boot so procfs can render namespace state without depending on the
// namespaces module. All take an OUTER pid (what /proc/<pid> names)
// and resolve it to a TaskId.

/// `/proc/<pid>/ns/<flavour>` readlink text, e.g. "uts:[42]".
#[cfg(all(feature = "container", feature = "linux-compat"))]
pub fn proc_ns_readlink(pid: u64, tag: u8) -> Option<alloc::string::String> {
    use narf_filesystem::procfs::ns_tag;
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    let (label, id) = match tag {
        ns_tag::UTS => ("uts", crate::namespaces::current_uts_ns(task).id()),
        ns_tag::NET => ("net", crate::namespaces::current_net_ns(task)?.id()),
        ns_tag::IPC => ("ipc", crate::namespaces::current_ipc_ns(task)?.id()),
        ns_tag::PID => ("pid", crate::pid_ns::ns_of(task)?.id()),
        ns_tag::MNT => ("mnt", mount_namespace_of(task)?.id()),
        ns_tag::USER => ("user", crate::namespaces::current_user_ns(task).id()),
        ns_tag::CGROUP => return None,
        _ => return None,
    };
    let mut s = alloc::string::String::new();
    use core::fmt::Write as _;
    let _ = write!(s, "{}:[{}]", label, id);
    Some(s)
}

/// `/proc/<pid>/mountinfo` per-ns view — None when the task rides the
/// global mount registry (procfs then renders the global view).
#[cfg(all(feature = "container", feature = "linux-compat"))]
pub fn proc_ns_mountinfo(pid: u64) -> Option<alloc::string::String> {
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    let ns = mount_namespace_of(task)?;
    let mut s = alloc::string::String::new();
    use core::fmt::Write as _;
    for (path, name) in ns.list_with_names() {
        let _ = writeln!(s, "{}\t{}", path, name);
    }
    Some(s)
}

/// `/proc/<pid>/{uid,gid}_map` render.
#[cfg(all(feature = "container", feature = "linux-compat"))]
pub fn proc_ns_idmap_render(pid: u64, is_uid: bool) -> Option<alloc::string::String> {
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    Some(crate::namespaces::current_user_ns(task).render_map(is_uid))
}

/// `/proc/<pid>/{uid,gid}_map` write — parses the Linux triple lines
/// `inner outer count` and applies them under the one-shot rule.
#[cfg(all(feature = "container", feature = "linux-compat"))]
pub fn proc_ns_idmap_write(
    pid: u64,
    is_uid: bool,
    bytes: &[u8],
) -> Result<usize, narf_filesystem::FsError> {
    let task = pid_to_task_raw(pid).unwrap_or(pid);
    let text = core::str::from_utf8(bytes).map_err(|_| narf_filesystem::FsError::InvalidData)?;
    let mut entries = alloc::vec::Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let inner: u32 = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(narf_filesystem::FsError::InvalidData)?;
        let outer: u32 = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(narf_filesystem::FsError::InvalidData)?;
        let count: u32 = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(narf_filesystem::FsError::InvalidData)?;
        if it.next().is_some() || count == 0 {
            return Err(narf_filesystem::FsError::InvalidData);
        }
        entries.push(crate::namespaces::IdMapEntry {
            inner_start: inner,
            outer_start: outer,
            count,
        });
    }
    let uns = crate::namespaces::current_user_ns(task);
    let r = if is_uid {
        uns.write_uid_map(entries)
    } else {
        uns.write_gid_map(entries)
    };
    r.map(|_| bytes.len())
        .map_err(|_| narf_filesystem::FsError::InvalidData)
}

// ── Wave-67: setns(target, nstype) ─────────────────────────────────
//
// Linux setns takes a fd referring to /proc/[pid]/ns/<type>. NARF
// doesn't yet expose those symlinks; the interim NARF surface
// accepts `target` as the outer TaskId / outer ProcessId of a task
// whose namespace family we want to join. Once /proc/[pid]/ns/* is
// plumbed, we'll add an inner branch that resolves the fd via the
// fd table.

// ── Wave-71: Per-task chroot table ────────────────────────────────
//
// Tracks each task's chroot-overridden notion of `/`. Absent entries
// mean the task sees the global root; present entries cause every
// absolute path the task hands to a path-resolving syscall to be
// rewritten under the stored prefix before resolution.
//
// pivot_root atomically replaces the entry; chroot installs it
// directly. fork inherits parent's entry; exec preserves it.
// Stored under linux-compat because chroot(2) is the entry point;
// pivot_root reuses the same slot.

#[cfg(feature = "linux-compat")]
static ROOT_DIR_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::string::String>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

#[cfg(feature = "linux-compat")]
fn root_dir_init_if_needed() {
    let mut g = ROOT_DIR_TABLE.lock();
    if g.is_none() {
        *g = Some(alloc::collections::BTreeMap::new());
    }
}

/// Diagnostic: read the chroot prefix for `task`, or `None` if the
/// task sees the global root. Used by tests + procfs.
#[cfg(feature = "linux-compat")]
pub fn root_dir_of(task: u64) -> Option<alloc::string::String> {
    let g = ROOT_DIR_TABLE.lock();
    g.as_ref().and_then(|m| m.get(&task).cloned())
}

/// fork(2) inheritance — child inherits parent's chroot.
#[cfg(feature = "linux-compat")]
pub fn root_dir_fork(parent: u64, child: u64) {
    let mut g = ROOT_DIR_TABLE.lock();
    if let Some(map) = g.as_mut() {
        if let Some(v) = map.get(&parent).cloned() {
            map.insert(child, v);
        }
    }
}

/// Test hook — drop every per-task entry.
#[cfg(feature = "linux-compat")]
#[doc(hidden)]
pub fn __test_root_dir_reset() {
    *ROOT_DIR_TABLE.lock() = Some(alloc::collections::BTreeMap::new());
}

/// Rewrite `path` under the calling task's chroot, if any. Absolute
/// paths get the chroot prefix prepended; relative paths pass
/// through unchanged. Joining strips a leading `/` from `path` so
/// the result has no double-slash.
#[cfg(feature = "linux-compat")]
pub(crate) fn apply_chroot(path: &str) -> alloc::string::String {
    let task = current_task_id();
    let prefix = {
        let g = ROOT_DIR_TABLE.lock();
        match g.as_ref().and_then(|m| m.get(&task).cloned()) {
            Some(p) => p,
            None => return alloc::string::String::from(path),
        }
    };
    if !path.starts_with('/') {
        return alloc::string::String::from(path);
    }
    // Compose prefix + path; prefix has no trailing `/` (except when
    // it equals `/`), path starts with `/`.
    let mut out = alloc::string::String::with_capacity(prefix.len() + path.len());
    if prefix != "/" {
        out.push_str(&prefix);
    }
    out.push_str(path);
    out
}

#[cfg(not(feature = "linux-compat"))]
#[inline]
pub(crate) fn apply_chroot(path: &str) -> alloc::string::String {
    alloc::string::String::from(path)
}

// ── Wave-71: chroot(2) ────────────────────────────────────────────

// ── Wave-71: pivot_root(2) ────────────────────────────────────────
//
// Linux semantics: the calling task's old root becomes accessible at
// `put_old` (an absolute path under `new_root`), and `new_root`
// becomes the new `/`. NARF approximation: register `put_old`
// (resolved under the new root) as a bind mount of the previous
// root path, then install the new chroot.

// ── Wave-71 test hooks ────────────────────────────────────────────
//
// Smokes in `mount_e2e_tests` drive the syscall handlers through a
// synthetic TrapContext + kernel-heap path buffers. These thin
// wrappers expose the file-private handlers without re-exporting
// the entire `sys_*` family.

#[doc(hidden)]
pub fn apply_chroot_for_test(p: &str) -> alloc::string::String {
    apply_chroot(p)
}

// ── ClockGetTime — write timespec to user buffer ──────────────────
//
// arg0 = clock id (POSIX-shaped):
//   0 = CLOCK_REALTIME   — wall time via `time::now_wall()`,
//                          driven by `set_wall_offset` / leap-smear.
//   1 = CLOCK_MONOTONIC  — `narf_time::monotonic_ns()`.
//   Anything else → InvalidOp (no boot-time / process-cpu clocks yet).
//
// arg1 is the user vaddr of a `timespec { i64 tv_sec; i64 tv_nsec; }`.
// Handlers run in the calling task's CR3 / TTBR so the user pointer
// resolves directly.
//
// The wall offset starts at 0 (the kernel's "epoch" coincides with
// boot-time monotonic 0), and a future userspace `settimeofday`
// surface will drive `set_wall_offset` to push it onto Unix time.
// Until then a CLOCK_REALTIME read just looks like a monotonic
// counter — which still satisfies the documented C99 "monotonic
// non-decreasing" contract that `clock_gettime` consumers check.

const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
// Wave-73: CLOCK_MONOTONIC_RAW skips NTP slew (we have no NTP, so
// RAW == MONOTONIC for now). CLOCK_BOOTTIME counts wall time across
// suspend (no suspend support → same as MONOTONIC).
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_BOOTTIME: u64 = 7;

// ── I/O Priority (ioprio_set / ioprio_get) ─────────────────────────
//
// Store I/O priority per (which, who) tuple. ioprio_get returns the
// stored value or a Linux default.

static IOPRIO_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<(i32, u64), u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

// ── Signal delivery: pending + mask + delivery hook ────────────────
//
// Stage-4 round 2: kill / sigprocmask + a hook on the trap-return
// path that, for any int-0x80 from user mode, picks the lowest
// pending unmasked signal, looks up its handler in the SIGACTION
// table, and rewrites the trap frame so iretq lands at the user
// handler with `[saved_rip, signum]` synthesised on the user
// stack. The handler signature is `extern "C" fn(u32)` — `signum`
// is in `rdi` (SysV first integer arg), and a `ret` pops the
// saved_rip we pushed and resumes the trapped code.
//
// Storage shape mirrors SIGACTION_TABLE: BTreeMap<task_id, u64
// bitmask>. Two tables: pending signals (set by `kill`) and the
// per-task block mask (modified by `sigprocmask`). Linux _NSIG = 64.
// NARF stores signal N at bit N-1 — IDENTICAL to the userspace
// `sigset_t` convention — so a u64 holds the full valid range 1..=64
// (SIGRTMAX = 64 included, which stress-ng --sigrt installs handlers
// for). Because the internal and ABI layouts match, the sigset ABI
// boundaries copy the mask through verbatim: no `<<1`/`>>1` shim, and
// no "bit 0 is the null signal" hazard — signal 0 simply has no bit.
// Use `sig_bit`/`sig_from_bit` at every conversion so the mapping
// lives in exactly one place.

/// Bit mask for `signum` in the NARF pending/mask u64 (signal N → bit
/// N-1). `signum` must be in 1..=64; out-of-range yields 0 (no bit).
#[inline]
pub(crate) fn sig_bit(signum: u32) -> u64 {
    if signum == 0 || signum > 64 {
        0
    } else {
        1u64 << (signum - 1)
    }
}

/// Signal number of the lowest set bit in `bits` (bit N-1 → signal N),
/// or 0 when `bits` is empty. Inverse of `sig_bit` for the low bit.
#[inline]
pub(crate) fn sig_from_bit(bits: u64) -> u32 {
    if bits == 0 {
        0
    } else {
        bits.trailing_zeros() + 1
    }
}

pub(crate) static SIGNAL_PENDING: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

// ── Per-task CPU-time accounting (getrusage / times) ────────────────
//
// NARF previously reported `monotonic_ns()` (wall-clock uptime since
// boot) as every process's user CPU time — so getrusage(RUSAGE_SELF)
// / times() returned the same huge, ever-growing value for every
// task, inflating e.g. stress-ng's per-stressor usr-time ~17x. These
// two tables instead track REAL consumed CPU time, keyed by TaskId
// (tid) — the same key getrusage/times resolve via current_task_id().
//
// `TASK_CPU_NS`: nanoseconds this task itself has spent executing in
// user mode, summed over every user run-slice (accumulated by the
// UserTaskFuture poll boundary in user_task.rs: it brackets each
// enter-user-mode → trap-return slice and folds the delta in here).
//
// `TASK_CHILD_CPU_NS`: nanoseconds of CPU time charged to this task's
// REAPED children (RUSAGE_CHILDREN / tms.cutime), folded in by wait4 /
// waitid when a zombie is collected (Linux charges child time at reap,
// not at exit).
static TASK_CPU_NS: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Task creation timestamp (monotonic ns) — /proc/[pid]/stat field 22
/// (starttime, in USER_HZ ticks since boot). Recorded by
/// `Task::new_registered`, swept with the other per-task tables.
static TASK_START_NS: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Record `tid`'s creation time. Called from `Task::new_registered`.
pub(crate) fn record_task_start_ns(tid: u64) {
    let now = narf_scheduler::narf_time::monotonic_ns();
    let mut g = TASK_START_NS.lock();
    g.get_or_insert_with(BTreeMap::new)
        .entry(tid)
        .or_insert(now);
}

fn task_start_ns(tid: u64) -> u64 {
    TASK_START_NS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&tid).copied())
        .unwrap_or(0)
}
static TASK_CHILD_CPU_NS: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Fold a completed user run-slice (`delta_ns` of on-CPU user time) into
/// the currently-running task's accumulated CPU time. Called from the
/// UserTaskFuture poll on every trap-return. Alloc-free on the hot path
/// once the task's slot exists; IRQ-safe (the poll runs with IF=0 around
/// the trap boundary).
pub fn account_user_cpu_ns(delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    let task = current_task_id();
    if task == 0 {
        return;
    }
    let mut g = TASK_CPU_NS.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    let e = m.entry(task).or_insert(0);
    *e = e.saturating_add(delta_ns);
}

/// Time this task has spent inside syscall handlers (ns) — the
/// ru_stime / tms_stime / stat-field-15 source. Folded by
/// `kernel_syscall_entry`'s dispatch bracket; same shape and cost as
/// the user-time fold above (one map lock per syscall).
static TASK_KERN_NS: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Fold a completed syscall's handler duration into the current task's
/// kernel-time accumulator. Called from `kernel_syscall_entry`.
pub fn account_kernel_cpu_ns(delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    let task = current_task_id();
    if task == 0 {
        return;
    }
    let mut g = TASK_KERN_NS.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    let e = m.entry(task).or_insert(0);
    *e = e.saturating_add(delta_ns);
}

/// This task's accumulated in-syscall (kernel) CPU time (ns).
pub fn kern_time_ns_of(task: u64) -> u64 {
    TASK_KERN_NS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

/// Test hook: clear the current task's accumulated in-syscall (kernel) CPU
/// time. The kernel-test harness runs every test as ONE shared task, so every
/// prior test's `kernel_syscall_entry` bracket accumulates here; under slow
/// (TCG) execution that cumulative time crosses one tick and flaps the `times`
/// stime==0 assertion. The times test resets it first so it measures a fresh
/// task, which is what the assertion means.
#[doc(hidden)]
pub fn __test_reset_kernel_time() {
    let task = current_task_id();
    if let Some(m) = TASK_KERN_NS.lock().as_mut() {
        m.remove(&task);
    }
}

/// Test hook: account `delta_ns` to an arbitrary task (the production
/// path only ever charges the currently-running task). Lets the ABI test
/// seed a stand-in child's CPU time to exercise the RUSAGE_CHILDREN fold.
#[doc(hidden)]
pub fn __test_account_cpu_ns(task: u64, delta_ns: u64) {
    let mut g = TASK_CPU_NS.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    let e = m.entry(task).or_insert(0);
    *e = e.saturating_add(delta_ns);
}

/// This task's own accumulated user CPU time (ns).
pub fn cpu_time_ns_of(task: u64) -> u64 {
    TASK_CPU_NS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

/// Accumulated CPU time (ns) of `task`'s reaped children.
fn child_cpu_time_ns_of(task: u64) -> u64 {
    TASK_CHILD_CPU_NS
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

// Exit-time rusage snapshot: `(cpu_ns, vm_kb)` captured in the DYING
// task's own context — the only point where its address space is still
// resolvable (`current_address_space`); by reap time the scheduler slot
// that owned the AS Arc is long dropped, so a reap-time
// `task_vm_bytes(child)` reads 0. Consumed (removed) at reap by both
// the synchronous wait4 path and `finish_wait_child`; an orphan that is
// never reaped leaks one small entry, same lifetime class as its
// PENDING_EXITS record.
static EXIT_RUSAGE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, (u64, u64)>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Snapshot the current (dying) task's rusage numbers for its parent's
/// wait4. MUST run in the exiting task's own trap context. Keyed by the
/// VISIBLE pid — the key wait4 reaps with — while the CPU tables are
/// read by tid (fork mints ProcessId and TaskId separately).
pub(crate) fn record_exit_rusage(tid: u64, pid: u64) {
    // Include the CURRENT (never-to-be-yielded) slice: the dying task is
    // mid-slice right now and exit_current_stackful switches away without
    // folding it.
    let cpu = cpu_time_ns_of(tid)
        .saturating_add(child_cpu_time_ns_of(tid))
        .saturating_add(narf_scheduler::stackful::current_slice_elapsed_ns());
    let vm_kb = task_vm_bytes(tid) / 1024;
    let mut g = EXIT_RUSAGE.lock();
    g.get_or_insert_with(BTreeMap::new)
        .insert(pid, (cpu, vm_kb));
}

fn take_exit_rusage(tid: u64) -> Option<(u64, u64)> {
    let mut g = EXIT_RUSAGE.lock();
    g.as_mut().and_then(|m| m.remove(&tid))
}

// The user `struct rusage*` of the parent's IN-FLIGHT blocking wait4,
// keyed by parent tid. `finish_wait_child` runs as the parent (both the
// poll route and own_stack_wait_child) but only receives the status
// pointer, so the rusage pointer travels through this table. Every
// blocking wait entry (wait4 AND waitid) overwrites its slot — waitid
// with 0 — so a stale pointer from an aborted wait can never be written
// through by a later one.
static WAIT_RUSAGE_PTR: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_wait_rusage_ptr(parent: u64, ptr: u64) {
    let mut g = WAIT_RUSAGE_PTR.lock();
    g.get_or_insert_with(BTreeMap::new).insert(parent, ptr);
}

fn take_wait_rusage_ptr(parent: u64) -> u64 {
    let mut g = WAIT_RUSAGE_PTR.lock();
    g.as_mut().and_then(|m| m.remove(&parent)).unwrap_or(0)
}

/// Reaping `child` from `parent`: charge the child's total CPU time (its
/// own + whatever it had already accumulated from its own reaped
/// grandchildren, per POSIX) to the parent's child-time accumulator, then
/// drop the child's rows. Returns the child's total CPU ns so wait4 can
/// also fill its `struct rusage` out-param. Idempotent-safe: a second
/// reap of an already-dropped child contributes 0.
pub fn account_reaped_child(parent: u64, child: u64) -> u64 {
    // `child` is the VISIBLE pid (wait4's reap key); the CPU tables key
    // on TaskId (folds run under current_task_id()). Fork mints the two
    // separately, so an untranslated lookup read 0 for every forked
    // child — `time`'s user column showed 0.00 for a 5 s burn (alpine
    // probe). Translate first, like proc_task_info does.
    let child_tid = pid_to_task_raw(child).unwrap_or(child);
    let child_total = cpu_time_ns_of(child_tid).saturating_add(child_cpu_time_ns_of(child_tid));
    if parent != 0 {
        let mut g = TASK_CHILD_CPU_NS.lock();
        let m = g.get_or_insert_with(BTreeMap::new);
        let e = m.entry(parent).or_insert(0);
        *e = e.saturating_add(child_total);
    }
    if let Some(m) = TASK_CPU_NS.lock().as_mut() {
        m.remove(&child_tid);
    }
    if let Some(m) = TASK_CHILD_CPU_NS.lock().as_mut() {
        m.remove(&child_tid);
    }
    child_total
}

/// Write a glibc `struct rusage` (18 i64s = 144 bytes) into user memory
/// with `ru_utime` set from `ns` and every other field zero. Best-effort
/// (a failed copy is swallowed — wait4 still succeeds). Shared by wait4's
/// rusage out-param.
fn write_rusage_utime(out_ptr: u64, ns: u64, maxrss_kb: u64) {
    let mut kbuf = [0u8; 18 * 8];
    let sec = (ns / 1_000_000_000) as i64;
    let usec = ((ns % 1_000_000_000) / 1_000) as i64;
    kbuf[..8].copy_from_slice(&sec.to_ne_bytes()); // ru_utime.tv_sec
    kbuf[8..16].copy_from_slice(&usec.to_ne_bytes()); // ru_utime.tv_usec
                                                      // ru_stime (16..32) stays 0 — NARF doesn't split kernel time out.
    kbuf[32..40].copy_from_slice(&(maxrss_kb as i64).to_ne_bytes()); // ru_maxrss (KB)
                                                                     // SAFETY: `out_ptr` is the user `struct rusage` pointer (non-zero,
                                                                     // checked by the caller); copy_to_user range-validates and
                                                                     // SMAP-brackets the 144-byte write.
    let _ = unsafe { copy_to_user(out_ptr, &kbuf) };
}

/// Total mapped bytes of `pid`'s address space (region-span sum) —
/// the `ru_maxrss` source. NARF has no per-page RSS or peak tracking,
/// so this reports the CURRENT (for a zombie: final) VM footprint,
/// an honest lower-noise stand-in for "peak resident" that gives
/// `time -v`-style consumers a real number instead of 0.
fn task_vm_bytes(pid: u64) -> u64 {
    let as_arc = narf_scheduler::address_space_of(narf_scheduler::TaskId(pid)).or_else(|| {
        if pid == current_task_id() {
            narf_scheduler::current_address_space()
        } else {
            None
        }
    });
    match as_arc {
        Some(a) => a.regions_snapshot().iter().map(|r| r.len).sum(),
        None => 0,
    }
}

/// Queued-siginfo payloads for signals raised via rt_sigqueueinfo /
/// sigqueue: `(task, signum) -> FIFO of (si_code, si_value)`.
///
/// Linux semantics (signal(7)): STANDARD signals (1..=31) do not queue —
/// duplicates coalesce, so their slot holds at most ONE payload (the
/// latest wins, matching the collapsed pending bit). REALTIME signals
/// (32..=64) DO queue: each sigqueue(2) is an independent delivery with
/// its own `si_value`, delivered in FIFO order. The pending bitmask in
/// `SIGNAL_PENDING` still carries one bit per signum; consumers re-arm
/// the bit after draining one instance while more remain queued
/// (`rearm_pending_if_queued`), so N queued RT signals produce N
/// deliveries instead of collapsing to one.
///
/// Drained on delivery (`default_signal_delivery`), by `rt_sigtimedwait`,
/// or by a `signalfd` read so a stale payload never attaches to a later
/// instance.
type SigqueueMap = BTreeMap<(u64, u32), alloc::collections::VecDeque<(i32, u64, u32)>>;
static SIGQUEUE_INFO: narf_lib::sync::IrqSafeSpinLock<Option<SigqueueMap>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// First realtime signal at the KERNEL level (libc reserves the first few
/// for its own use, but queueing is a property of the kernel range).
const SIGRT_QUEUE_MIN: u32 = 32;

/// Per-task cap on TOTAL queued signal payloads — the RLIMIT_SIGPENDING
/// analogue (Linux defaults to a few thousand). Without a cap, a
/// CPU-bound sigqueue(2) loop against a slower consumer (exactly
/// stress-ng --sigrt's parent hammering 30 parked children) grows the
/// kernel-heap FIFOs without bound; Linux callers already handle the
/// EAGAIN this overflow produces.
const SIGQUEUE_MAX_PER_TASK: usize = 4096;

/// Record the `si_code` + `si_value` + sender `si_pid` carried by a
/// queued signal. RT signals append (true queueing); standard signals
/// replace (coalesce, latest payload wins — their pending bit collapses
/// anyway). Returns `false` when the target's queue is at
/// `SIGQUEUE_MAX_PER_TASK` (→ the sender surfaces -EAGAIN, Linux
/// RLIMIT_SIGPENDING semantics); coalescing standard signals never fail.
pub(crate) fn store_sigqueue_info(
    task: u64,
    signum: u32,
    si_code: i32,
    si_value: u64,
    si_pid: u32,
) -> bool {
    let mut g = SIGQUEUE_INFO.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    if signum >= SIGRT_QUEUE_MIN {
        // Cap check across ALL of the target's queues (the per-process
        // pending budget, like Linux's ucounts sigpending charge).
        let queued: usize = m.range((task, 0)..=(task, 64)).map(|(_, q)| q.len()).sum();
        if queued >= SIGQUEUE_MAX_PER_TASK {
            return false;
        }
    }
    let q = m.entry((task, signum)).or_default();
    if signum < SIGRT_QUEUE_MIN {
        q.clear();
    }
    q.push_back((si_code, si_value, si_pid));
    true
}

/// Total queued rt_sigqueueinfo payloads pending for `task` across every
/// signum — the sender-side back-pressure probe (see `sys_rt_sigqueueinfo`).
/// Only consulted on the x86_64 own-stack resched path.
#[cfg(target_arch = "x86_64")]
pub(crate) fn sigqueue_depth(task: u64) -> usize {
    let g = SIGQUEUE_INFO.lock();
    g.as_ref()
        .map(|m| m.range((task, 0)..=(task, 64)).map(|(_, q)| q.len()).sum())
        .unwrap_or(0)
}

/// Threshold above which a signal sender is asked to yield at syscall exit:
/// the target is this many payloads behind, so the producer has outrun the
/// consumer and should donate its CPU (stress-ng --sigrt's parent flooding
/// its 30 sigwaitinfo children; the graceful-shutdown `sival=0` marker must
/// find the children DRAINED and parked, or the nop-handler sigreturn chain
/// can consume it and the run never terminates). Linux gets the equivalent
/// pacing from preemptive multi-CPU scheduling; this is the cooperative
/// analogue, and it only triggers on genuinely backlogged floods.
#[cfg(target_arch = "x86_64")]
pub(crate) const SIGQUEUE_BACKPRESSURE_DEPTH: usize = 4;

/// Pop and return the OLDEST queued `(si_code, si_value, si_pid)` for
/// `(task, signum)`, if any. FIFO order preserves rt_sigqueueinfo
/// submission order for RT signals; standard signals hold at most one.
pub(crate) fn take_sigqueue_info(task: u64, signum: u32) -> Option<(i32, u64, u32)> {
    let mut g = SIGQUEUE_INFO.lock();
    let m = g.as_mut()?;
    let q = m.get_mut(&(task, signum))?;
    let v = q.pop_front();
    if q.is_empty() {
        m.remove(&(task, signum));
    }
    v
}

/// True when more queued instances of `(task, signum)` remain after a
/// `take_sigqueue_info` pop.
pub(crate) fn sigqueue_more_queued(task: u64, signum: u32) -> bool {
    SIGQUEUE_INFO
        .lock()
        .as_ref()
        .is_some_and(|m| m.get(&(task, signum)).is_some_and(|q| !q.is_empty()))
}

/// Re-set the pending bit for `signum` when more queued instances remain
/// — the RT-queue drain step every consumer (handler delivery,
/// rt_sigtimedwait, signalfd) runs after clearing the bit, so the NEXT
/// return-to-user / wait delivers the next instance with its own payload.
pub(crate) fn rearm_pending_if_queued(task: u64, signum: u32) {
    if !sigqueue_more_queued(task, signum) {
        return;
    }
    if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
        if let Some(slot) = map.get_mut(&task) {
            *slot |= sig_bit(signum);
        }
    }
}

/// Drop every queued payload for `(task, signum)` — used when the signal
/// is consumed by an ignoring disposition (SIG_IGN / default-Ignore):
/// Linux "delivers" each queued ignored instance by discarding it, which
/// collapses to discarding the whole queue.
pub(crate) fn purge_sigqueue(task: u64, signum: u32) {
    if let Some(m) = SIGQUEUE_INFO.lock().as_mut() {
        m.remove(&(task, signum));
    }
}

/// Wake condition for a task parked in `rt_sigtimedwait` on userspace
/// sigset `set` (bit N-1 = signal N — identical to `SIGNAL_PENDING`'s
/// layout). True when a signal IN the set is pending (block mask
/// deliberately ignored: sigwait consumes blocked signals — callers
/// block the set first, per sigwaitinfo(2)) or any OTHER deliverable
/// signal is pending (the re-executed syscall returns -EINTR and the
/// return-to-user hook delivers it).
pub(crate) fn sigwait_should_wake(task: u64, set: u64) -> bool {
    let pending = signal_pending_of(task);
    (pending & set) != 0 || (pending & !signal_mask_of(task)) != 0
}

pub fn is_signal_pending(task_id: u64) -> bool {
    let pending = {
        let g = SIGNAL_PENDING.lock();
        g.as_ref()
            .and_then(|m| m.get(&task_id).copied())
            .unwrap_or(0)
    };
    let mask = signal_mask_of(task_id);
    (pending & !mask) != 0
}

static SIGNAL_MASK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// fork/clone inheritance of the signal mask (Linux `copy_process`
/// copies `blocked` unconditionally, for threads and forks alike).
/// Without it a new thread starts with an EMPTY mask and takes
/// signals its creator had deliberately blocked.
pub(crate) fn signal_mask_fork(parent: u64, child: u64) {
    let mut g = SIGNAL_MASK.lock();
    if let Some(m) = g.as_mut() {
        // Fork-ordering hazard: `do_clone3`/`sys_fork` spawn the child (making
        // it runnable) BEFORE this inheritance runs. musl always calls fork/
        // clone from inside its `__block_all_sigs` window, so `parent`'s LIVE
        // mask here is the transient all-blocked value — NOT the process's real
        // mask. The child's own `__restore_sigs` (which runs the instant it is
        // scheduled) sets the correct pre-fork mask. If we unconditionally
        // copied `parent`'s mask we would clobber that restore with all-blocked,
        // leaving the exec'd image with every application signal masked (SIGALRM
        // handlers never fire — the stress-ng --sigrt hang). So only SEED a
        // child that has not yet established a mask of its own: a raw clone that
        // never restores still inherits correctly, while a musl child that has
        // already restored keeps its authoritative value.
        if !m.contains_key(&child) {
            if let Some(mask) = m.get(&parent).copied() {
                m.insert(child, mask);
            }
        }
    }
}

/// SIGKILL(9)/SIGSTOP(19) can never be blocked — Linux silently strips
/// them from every mask install (`sigdelsetmask(&blocked, sigmask(
/// SIGKILL) | sigmask(SIGSTOP))`). NARF masks store signal N at bit N.
// SIGKILL(9)=bit 8, SIGSTOP(19)=bit 18 in the N-1 convention.
const UNBLOCKABLE_MASK: u64 = (1 << 8) | (1 << 18);

// Per-task flag recording whether the most recently delivered signal
// frame is the Linux `rt_sigframe` (restorer-based) layout. The Linux
// `rt_sigreturn` (x86_64 #15) takes no argument — the frame is found
// at the user RSP. NARF's own libc trampoline instead forwards the
// SigContext vaddr in arg0. We can't tell them apart at sigreturn time
// from registers alone (a restorer leaves arbitrary garbage in RDI),
// so we remember the delivery style here. `true` ⇒ resolve the frame
// from RSP; `false` ⇒ trust arg0.
static SIGRETURN_USE_RSP: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, bool>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_sigreturn_use_rsp(task: u64, use_rsp: bool) {
    let mut g = SIGRETURN_USE_RSP.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert(task, use_rsp);
}

fn sigreturn_use_rsp(task: u64) -> bool {
    SIGRETURN_USE_RSP
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(false)
}

// Per-task record of the LAST delivered signal frame's layout: `true` ⇒ the
// kernel laid out an rt_sigframe (McContext at sc_vaddr+168), `false` ⇒ a legacy
// SigContext. `sys_sigreturn` reads this and hands it to `perform_sigreturn` so
// the restore reads RIP from the correct offset. Previously the arch code GUESSED
// rt-vs-legacy by sniffing the user `si_signo` word — a wrong guess (e.g. user
// data in (0,64) over a legacy frame) read RIP from the rt offset, which lands on
// the frame's `cs`/`ss` selector fields → control transfer to a tiny RPL-3 address
// (#UD). The kernel BUILT the frame, so it must record the layout, not re-derive it.
// `is_rt` mirrors deliver_signal's `want_siginfo || force_rt` decision exactly.
static SIGRETURN_IS_RT: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, bool>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_sigreturn_is_rt(task: u64, is_rt: bool) {
    let mut g = SIGRETURN_IS_RT.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert(task, is_rt);
}

fn sigreturn_is_rt(task: u64) -> bool {
    SIGRETURN_IS_RT
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        // Default true: modern (rt_sigaction + SA_SIGINFO/restorer) is the
        // overwhelming case; a missing record means rt.
        .unwrap_or(true)
}

// Pre-handler signal mask, saved when a signal is delivered so `sys_sigreturn`
// can restore it. POSIX: on return from a handler the signal mask in effect
// just before the handler ran is restored — crucially undoing the auto-block of
// the delivered signal. Without this the auto-blocked signal stays masked
// forever, so a SECOND occurrence is never delivered (observed: a second
// setitimer(ITIMER_REAL)/raise SIGALRM never firing after the first handler ran
// — whichever alarm phase ran second hung). Single-slot per task, matching the
// SIGRETURN_IS_RT / SIGRETURN_USE_RSP records (nested handlers share NARF's
// existing single-record limitation). Only the async delivery path records here
// (it is the one that auto-blocks); a `None` on return leaves the mask alone.
static SIGRETURN_SAVED_MASK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_sigreturn_saved_mask(task: u64, mask: u64) {
    let mut g = SIGRETURN_SAVED_MASK.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert(task, mask);
}

fn take_sigreturn_saved_mask(task: u64) -> Option<u64> {
    let mut g = SIGRETURN_SAVED_MASK.lock();
    g.as_mut().and_then(|m| m.remove(&task))
}

// Pre-`rt_sigsuspend` signal mask, saved when sigsuspend installs its
// temporary wait mask. POSIX (and Linux's TIF_RESTORE_SIGMASK): the mask
// restored by the interrupting handler's sigreturn must be the mask in
// effect BEFORE sigsuspend replaced it — NOT the temporary suspend mask.
// Without this record, `default_signal_delivery` captured the live (=
// suspend) mask into SIGRETURN_SAVED_MASK, so the temporary mask survived
// the handler return and the process ran on the suspend mask forever.
// Consumed (take) by the first delivery after the suspend; a record left
// by an aborted suspend is dropped by the next explicit sigprocmask
// install (the user retook control of the mask) and swept on task exit.
static SUSPEND_SAVED_MASK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn set_suspend_saved_mask(task: u64, mask: u64) {
    let mut g = SUSPEND_SAVED_MASK.lock();
    g.get_or_insert_with(BTreeMap::new).insert(task, mask);
}

fn take_suspend_saved_mask(task: u64) -> Option<u64> {
    let mut g = SUSPEND_SAVED_MASK.lock();
    g.as_mut().and_then(|m| m.remove(&task))
}

/// Initialise the per-task pending+mask+altstack registries.
/// Pair with `sigaction_init` at boot.
pub fn signal_init() {
    *SIGNAL_PENDING.lock() = Some(BTreeMap::new());
    *SIGNAL_MASK.lock() = Some(BTreeMap::new());
    *SIG_ALTSTACK.lock() = Some(BTreeMap::new());
}

/// Reset the registries — test hook. Drops every per-task entry.
#[doc(hidden)]
pub fn __test_signal_reset() {
    *SIGNAL_PENDING.lock() = Some(BTreeMap::new());
    *SIGNAL_MASK.lock() = Some(BTreeMap::new());
    *SIG_ALTSTACK.lock() = Some(BTreeMap::new());
    *SIGQUEUE_INFO.lock() = Some(BTreeMap::new());
    *SUSPEND_SAVED_MASK.lock() = Some(BTreeMap::new());
}

/// Diagnostic: peek the pending bitmap for `task`.
pub fn signal_pending_of(task: u64) -> u64 {
    SIGNAL_PENDING
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

/// POSIX default action for a signal when no handler is installed.
/// Mirrors the table in `signal(7)`. Used by the kernel to decide
/// what to do when a signal is pending + deliverable but the task
/// has no sigaction registered: terminate it, terminate + dump,
/// stop it, continue it, or ignore it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// Default action is "terminate the process" (POSIX `Term`).
    Terminate,
    /// Default action is "terminate + core dump" (POSIX `Core`).
    CoreDump,
    /// Default action is "stop the process" (POSIX `Stop`).
    Stop,
    /// Default action is "continue the process if stopped" (POSIX `Cont`).
    Continue,
    /// Default action is "ignore the signal" (POSIX `Ign`).
    Ignore,
}

/// Look up the POSIX-default action for `signum`. Reference table:
/// `signal(7)`, Linux's `kernel/signal.c::sig_kernel_*` family.
/// Signals not assigned in the standard table fall through to
/// `Terminate` — Linux uses the same fallback.
pub fn default_signal_action(signum: u32) -> DefaultAction {
    match signum {
        1 => DefaultAction::Terminate,  // SIGHUP
        2 => DefaultAction::Terminate,  // SIGINT
        3 => DefaultAction::CoreDump,   // SIGQUIT
        4 => DefaultAction::CoreDump,   // SIGILL
        5 => DefaultAction::CoreDump,   // SIGTRAP
        6 => DefaultAction::CoreDump,   // SIGABRT / SIGIOT
        7 => DefaultAction::CoreDump,   // SIGBUS
        8 => DefaultAction::CoreDump,   // SIGFPE
        9 => DefaultAction::Terminate,  // SIGKILL (cannot be caught)
        10 => DefaultAction::Terminate, // SIGUSR1
        11 => DefaultAction::CoreDump,  // SIGSEGV
        12 => DefaultAction::Terminate, // SIGUSR2
        13 => DefaultAction::Terminate, // SIGPIPE
        14 => DefaultAction::Terminate, // SIGALRM
        15 => DefaultAction::Terminate, // SIGTERM
        16 => DefaultAction::Terminate, // SIGSTKFLT (Linux-specific)
        17 => DefaultAction::Ignore,    // SIGCHLD
        18 => DefaultAction::Continue,  // SIGCONT
        19 => DefaultAction::Stop,      // SIGSTOP (cannot be caught)
        20 => DefaultAction::Stop,      // SIGTSTP
        21 => DefaultAction::Stop,      // SIGTTIN
        22 => DefaultAction::Stop,      // SIGTTOU
        23 => DefaultAction::Ignore,    // SIGURG
        24 => DefaultAction::CoreDump,  // SIGXCPU
        25 => DefaultAction::CoreDump,  // SIGXFSZ
        26 => DefaultAction::Terminate, // SIGVTALRM
        27 => DefaultAction::Terminate, // SIGPROF
        28 => DefaultAction::Ignore,    // SIGWINCH
        29 => DefaultAction::Terminate, // SIGIO / SIGPOLL
        30 => DefaultAction::Terminate, // SIGPWR
        31 => DefaultAction::CoreDump,  // SIGSYS
        _ => DefaultAction::Terminate,
    }
}

// ── /proc/[pid]/{cmdline,comm} backing tables ───────────────────
//
// Both are populated at task-creation time (boot init, sys_execve)
// and queried by the proc_task_info hook below. The comm name is
// also writable through prctl(PR_SET_NAME).

static PROC_ARGV: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::vec::Vec<u8>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

static PROC_COMM: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::string::String>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

// /proc/[pid]/exe target: the absolute path of the last successfully
// exec'd image (for a `#!` script, the interpreter — Linux points the
// exe link at whatever binary is actually mapped). Recorded by
// sys_execve next to the argv/comm publish; a fork child has no entry
// until it execs (the procfs hook then renders an empty target).
static PROC_EXE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::string::String>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Record the exec'd binary path for `/proc/[pid]/exe`. A relative
/// exec path is resolved against the caller's cwd so the link is
/// always absolute (Linux renders a resolved path here, never `./x`).
pub fn set_proc_exe(pid: u64, path: &str) {
    let abs = if path.starts_with('/') {
        alloc::string::String::from(path)
    } else {
        let mut s = cwd_of(pid);
        if !s.ends_with('/') {
            s.push('/');
        }
        s.push_str(path);
        s
    };
    let mut g = PROC_EXE.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, abs);
}

/// `/proc/[pid]/exe` hook — None until the task has exec'd.
pub fn proc_exe_path(pid: u64) -> Option<alloc::string::String> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_EXE.lock();
    g.as_ref().and_then(|m| m.get(&tid).cloned())
}

/// `/proc/[pid]/cwd` hook — `cwd_of` defaults to `/` for a task that
/// never chdir'd, which is also the Linux boot-task answer.
pub fn proc_cwd_path(pid: u64) -> Option<alloc::string::String> {
    Some(cwd_of(proc_pid_to_tid(pid)))
}

/// `/proc/[pid]/root` hook — the chroot prefix, or None (procfs falls
/// back to `/`) when the task never chroot'd or the build has no
/// linux-compat chroot support.
pub fn proc_root_path(pid: u64) -> Option<alloc::string::String> {
    #[cfg(feature = "linux-compat")]
    {
        let tid = proc_pid_to_tid(pid);
        let g = ROOT_DIR_TABLE.lock();
        g.as_ref().and_then(|m| m.get(&tid).cloned())
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        let _ = pid;
        None
    }
}

/// Store NUL-separated argv bytes for a task. /proc/[pid]/cmdline
/// reads this exact byte stream — Linux's shape is `argv[0]\0argv[1]\0...`.
pub fn set_proc_argv(pid: u64, argv: &[&str]) {
    let mut packed = alloc::vec::Vec::new();
    for s in argv {
        packed.extend_from_slice(s.as_bytes());
        packed.push(0);
    }
    let mut g = PROC_ARGV.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, packed);
}

/// Pre-packed variant — the caller already owns the NUL-separated bytes.
pub fn set_proc_argv_packed(pid: u64, packed: alloc::vec::Vec<u8>) {
    let mut g = PROC_ARGV.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, packed);
}

/// Set the per-task comm name. Truncated to 15 bytes per Linux's
/// PR_SET_NAME (TASK_COMM_LEN = 16 including NUL).
pub fn set_proc_comm(pid: u64, name: &str) {
    let trimmed: alloc::string::String = name.chars().take(15).collect();
    let mut g = PROC_COMM.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, trimmed);
}

/// Read-only accessor for the NUL-separated argv pack recorded
/// against `pid`. Used by `/proc/[pid]/cmdline` and by the execve
/// smoke tests to verify the post-load argv publish step.
pub fn proc_argv_of(pid: u64) -> alloc::vec::Vec<u8> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_ARGV.lock();
    g.as_ref()
        .and_then(|m| m.get(&tid).cloned())
        .unwrap_or_default()
}

/// Read-only accessor for the comm name recorded against `pid`. Used
/// by `/proc/[pid]/comm` and by the execve smoke tests to confirm
/// the comm-from-argv[0]-basename step ran.
pub fn proc_comm_of(pid: u64) -> Option<alloc::string::String> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_COMM.lock();
    g.as_ref().and_then(|m| m.get(&tid).cloned())
}

// ── /proc/[pid]/comm writable hook ─────────────────────────────

/// Update comm from a procfs write. Linux ref: `comm_write` in
/// `fs/proc/base.c`. Truncates to 15 chars; returns `Ok(())`.
pub fn proc_set_comm(pid: u64, name: &str) -> Result<(), narf_filesystem::FsError> {
    // PROC_COMM is TaskId-keyed (see proc_comm_of); write under the TaskId so a
    // subsequent /proc/<pid>/comm read matches.
    set_proc_comm(proc_pid_to_tid(pid), name);
    Ok(())
}

// ── /proc/[pid]/oom_score_adj ───────────────────────────────────

static PROC_OOM_ADJ: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, i16>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return the oom_score_adj for `pid`. Default 0.
pub fn proc_oom_adj_of(pid: u64) -> i16 {
    let g = PROC_OOM_ADJ.lock();
    g.as_ref().and_then(|m| m.get(&pid).copied()).unwrap_or(0)
}

/// Set the oom_score_adj for `pid`. Range is validated by the caller.
pub fn proc_set_oom_adj(pid: u64, val: i16) -> Result<(), narf_filesystem::FsError> {
    let mut g = PROC_OOM_ADJ.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, val);
    Ok(())
}

/// Compute a 0..1000 oom_score for `pid`.
///
/// Stub formula: `clamp(rss_pages * 1000 / total_pages + adj, 0, 1000)`.
/// Linux ref: `oom_badness` in `mm/oom_kill.c`.
pub fn proc_oom_score_of(pid: u64) -> i32 {
    let stats = narf_memory::frame::stats();
    // RSS is approximated as the task's VMA pages. NARF tracks
    // VMAs but not resident pages yet — use vma_count as a proxy.
    let rss_pages = {
        // Address spaces are keyed by TaskId; resolve the outer ProcessId first.
        let task = narf_scheduler::address_space_of(narf_scheduler::TaskId(proc_pid_to_tid(pid)));
        task.map(|as_arc| {
            let regions = as_arc.regions_snapshot();
            regions.iter().map(|r| (r.len / 4096).max(1)).sum::<u64>()
        })
        .unwrap_or(0)
    };
    let total = stats.total.max(1);
    let base = (rss_pages as i64 * 1000 / total as i64) as i32;
    let adj = proc_oom_adj_of(pid) as i32;
    (base + adj).clamp(0, 1000)
}

// ── /proc/[pid]/coredump_filter ────────────────────────────────

/// Default coredump_filter: anonymous + anonymous-huge + ELF headers.
/// Linux ref: `DEFAULT_MAP_WINDOW` macros + `PR_SET_DUMPABLE` handler.
const DEFAULT_COREDUMP_FILTER: u32 = 0x33;

static PROC_COREDUMP_FILTER: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, u32>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return the coredump_filter bitmap for `pid`. Default 0x33.
pub fn proc_coredump_filter_of(pid: u64) -> u32 {
    let g = PROC_COREDUMP_FILTER.lock();
    g.as_ref()
        .and_then(|m| m.get(&pid).copied())
        .unwrap_or(DEFAULT_COREDUMP_FILTER)
}

/// Set the coredump_filter bitmap for `pid`.
pub fn proc_set_coredump_filter(pid: u64, bits: u32) -> Result<(), narf_filesystem::FsError> {
    let mut g = PROC_COREDUMP_FILTER.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, bits);
    Ok(())
}

/// /proc/self readlink hook — the calling process's pid in ITS OWN namespace
/// view (== `getpid()`), so `readlink(/proc/self)` yields a number the caller
/// can re-open. (Was the raw TaskId, a third number space that matched neither
/// getpid nor the /proc path numbers.)
pub fn proc_current_pid() -> u64 {
    let task = current_task_id();
    let outer = task_to_pid_raw(task).unwrap_or(task);
    report_pid_to(task, outer)
}

/// /proc/self + /proc/thread-self DIRECTORY-resolution hook — the caller's
/// OUTER ProcessId. `ProcPidDir` keys on the outer pid (that is what every
/// per-pid `/proc` renderer expects), so the "self" magic dirs resolve to the
/// same space the numeric `/proc/<N>` resolver produces.
pub fn proc_current_outer_pid() -> u64 {
    let task = current_task_id();
    task_to_pid_raw(task).unwrap_or(task)
}

/// `/proc/<N>` numeric-resolution hook. `N` is a pid in the READER's PID
/// namespace; return the outer ProcessId the kernel keys on, or `None` when
/// the reader is namespaced and `N` names no process in its namespace (so
/// `/proc/<N>` is invisible — namespace isolation). Identity in the root
/// namespace, where every ProcessId (and, via the caller's identity fallback,
/// every TaskId) resolves to itself.
pub fn proc_pid_resolve(reader_view_pid: u64) -> Option<u64> {
    accept_pid_from(current_task_id(), reader_view_pid)
}

/// Translate an outer ProcessId into the CURRENT reader's namespace view for
/// listing surfaces (cgroup.procs), returning `None` when the process is not
/// visible in the reader's namespace so the caller drops it. Identity in the
/// root namespace / non-`container` builds.
pub fn proc_pid_report(outer: u64) -> Option<u64> {
    #[cfg(feature = "container")]
    {
        crate::pid_ns::ns_visible_inner(current_task_id(), outer)
    }
    #[cfg(not(feature = "container"))]
    {
        Some(outer)
    }
}

/// /proc enumerator — every live PROCESS (thread-group leader, keyed in
/// `PID_TO_TASK` by its outer ProcessId) that is visible in the READER's PID
/// namespace, reported as the reader's inner pid. A namespaced reader sees
/// only its own namespace; the root namespace sees every process by its outer
/// pid. (Was every raw TaskId — threads included, un-namespaced.)
pub fn proc_list_pids() -> alloc::vec::Vec<u64> {
    let reader = current_task_id();
    let outers: alloc::vec::Vec<u64> = PID_TO_TASK
        .lock()
        .as_ref()
        .map(|m| m.keys().copied().collect())
        .unwrap_or_default();
    #[cfg(feature = "container")]
    {
        outers
            .into_iter()
            .filter_map(|outer| crate::pid_ns::ns_visible_inner(reader, outer))
            .collect()
    }
    #[cfg(not(feature = "container"))]
    {
        let _ = reader;
        outers
    }
}

/// /proc/[pid]/* metadata accessor.
#[cfg(feature = "linux-compat")]
pub fn proc_task_info(pid: u64) -> Option<narf_filesystem::procfs::ProcTaskInfo> {
    use narf_filesystem::procfs::ProcTaskInfo;
    // Don't gate on "is on a ready queue" — the currently-running
    // task has been popped from its queue for polling and would
    // fail that check while it's the very task asking. Treat any
    // pid that matches the caller OR a queued task as live.
    let current = current_task_id();
    // `pid` is the outer ProcessId: the procfs `/proc/<N>` resolver already
    // translated the reader's namespace-local path number into the outer pid
    // (see `proc_pid_resolve`), so every kernel-state lookup below keys on it
    // directly and no hook double-translates. The reported pid field is
    // rendered back into the READER's namespace view (`visible_pid`); identity
    // in the root namespace.
    let visible_pid = report_pid_to(current, pid);
    // Visible PID → scheduler TaskId. NARF allocates process ids and
    // scheduler task ids from separate spaces (a process's pid is NOT its
    // tid), so every liveness / address-space probe below goes through the
    // pid→tid map rather than using `TaskId(pid)` directly (which is only
    // correct when the two coincide).
    let mapped_tid = pid_to_task_raw(pid);
    let tid = mapped_tid.unwrap_or(pid);
    // The task registry is the /proc-visibility window (Linux semantics):
    // it holds every task from spawn registration to reap, so a pid whose
    // pid→tid binding resolves to a registered Task is /proc-visible in
    // EVERY state — running on any CPU, parked, or an exited-but-unreaped
    // zombie (reported as state Z with its real PPid until the parent
    // reaps). The ready-queue scans below can NOT stand in for this: the
    // executor pops a slot off its per-CPU queue for the whole time it
    // polls the task, so a child actively running on another CPU is
    // invisible to both `all_task_ids` and `address_space_of` — exactly
    // the window in which systemd PID 1 forks a service and immediately
    // reads /proc/<child>/stat's PPid ("is process N my child"); a miss
    // there surfaces as ESRCH. Gating on `mapped_tid` keeps a recycled-
    // but-unmapped pid from resolving through a numerically-coincident
    // live tid. systemd's child tracking also depends on the zombie arm:
    // it peeks waitid(..., WNOWAIT) and then reads /proc/<pid>/stat's
    // PPid BEFORE the real reap.
    let task = crate::task::task_get(tid);
    let zombie = task
        .as_ref()
        .map(|t| t.state.load(Ordering::Acquire) == crate::task::TASK_ZOMBIE)
        .unwrap_or(false);
    // Liveness: a registered Task under a real pid→tid binding, or (for
    // contexts that never register a Task — boot init, test harnesses)
    // the caller itself (the running task is popped off its ready queue
    // while polling, so it wouldn't match the queue scan), a ready-queue
    // entry, or a registered address space (covers parked/sleeping
    // processes like init).
    let live = zombie
        || (mapped_tid.is_some() && task.is_some())
        || tid == current
        || narf_scheduler::all_task_ids().iter().any(|t| t.0 == tid)
        || narf_scheduler::address_space_of(narf_scheduler::TaskId(tid)).is_some();
    if !live {
        return None;
    }
    // brk top — pull from the per-task BRK_TABLE, which (like fd/cwd/comm) is
    // keyed by TaskId, so use `tid`, not the outer ProcessId `pid`.
    let brk_top = {
        let g = BRK_TABLE.lock();
        g.as_ref().and_then(|m| m.get(&tid).copied()).unwrap_or(0)
    };
    // Stack top — the exclusive high end of the user-stack region.
    // Stage-1 just reports the standard fixed top.
    let stack_top = crate::process::DEFAULT_USER_STACK_TOP;
    // Comm name — from the PROC_COMM table (written at exec time
    // or via prctl(PR_SET_NAME)). Falls back to a "task-N"
    // default when no name has been set.
    let comm = proc_comm_of(pid).unwrap_or_else(|| {
        if pid == 0 {
            alloc::string::String::from("kernel")
        } else {
            alloc::format!("task-{}", pid)
        }
    });
    // cmdline — argv preserved at exec time. Empty for bare-spawn
    // tasks (initramfs init / shell) until their argv is recorded.
    let cmdline = proc_argv_of(pid);
    // VMAs — walk the task's AS regions table. Linux's
    // /proc/[pid]/maps tags certain ranges with brackets ([heap],
    // [stack]); we apply the same labels by matching base address.
    use narf_filesystem::procfs::ProcVma;
    use narf_memory::RegionPerms;
    let mut vmas = alloc::vec::Vec::new();
    if let Some(as_arc) =
        narf_scheduler::address_space_of(narf_scheduler::TaskId(tid)).or_else(|| {
            // Currently-polling task isn't in the queue scan;
            // fall back to the active-AS slot.
            if tid == current_task_id() {
                narf_scheduler::current_address_space()
            } else {
                None
            }
        })
    {
        for r in as_arc.regions_snapshot() {
            let base = r.base.as_u64();
            let end = base + r.len;
            let prot = r.perms.prot_only();
            let label: &'static str = if base == crate::process::DEFAULT_USER_STACK_BASE {
                "[stack]"
            } else if base == 0x8000_0000_0000_u64
                || (base & 0xffff_ff00_0000_0000) == 0x8000_0000_0000
            {
                "[text]"
            } else if brk_top != 0 && base <= brk_top && brk_top <= end {
                "[heap]"
            } else {
                ""
            };
            vmas.push(ProcVma {
                start: base,
                end,
                readable: prot.contains(RegionPerms::READ),
                writable: prot.contains(RegionPerms::WRITE),
                executable: prot.contains(RegionPerms::EXEC),
                // From the UN-stripped perms — prot_only() drops the
                // SHARED bit. Feeds maps' s/p column + statm's shared.
                shared: r.perms.contains(RegionPerms::SHARED),
                label,
            });
        }
    }
    // stat fields 4-6, 14, 22: parentage + CPU + start time. `tid` (hoisted
    // above) resolves the accounting tables (they key on TaskId); PARENT_OF
    // keys on the visible pid. USER_HZ = 100 → 10ms per tick.
    const NS_PER_TICK: u64 = 10_000_000;
    Some(ProcTaskInfo {
        // Report the pid the reader asked for (its namespace view), not the
        // outer ProcessId — stat field 1 must echo /proc/<N>.
        pid: visible_pid,
        comm,
        state: if zombie { 'Z' } else { 'R' },
        brk_top,
        stack_top,
        cmdline,
        vmas,
        // PARENT_OF values are parent TaskIds — translate to the parent's
        // outer ProcessId, then into the READER's namespace view. This is the
        // field systemd's `pidref_is_my_child` compares against its own
        // getpid()==1: rendering it in outer space made every service log
        // "Supervising process N which is not our child" (project_pidns_flow_model).
        ppid: parent_of_get(pid)
            .map(|t| report_pid_to(current, task_to_pid_raw(t).unwrap_or(t)))
            .unwrap_or(0),
        // pgrp/session are held in TaskId space; render them in the reader's
        // visible-pid + namespace view (same boundary getpgid()/getsid() use).
        pgrp: pgid_to_user(read_pgid(tid)),
        session: pgid_to_user(read_sid(tid)),
        utime_ticks: cpu_time_ns_of(tid) / NS_PER_TICK,
        stime_ticks: kern_time_ns_of(tid) / NS_PER_TICK,
        starttime_ticks: task_start_ns(tid) / NS_PER_TICK,
        // Effective uid/gid from the per-task credential table — surfaced as
        // the status Uid:/Gid: lines. Defaults to 0/0 (root) for tasks that
        // never called setuid/setgid, matching NARF's default identity.
        uid: {
            let c = read_uidgid(tid);
            c.euid
        },
        gid: {
            let c = read_uidgid(tid);
            c.egid
        },
        // Live thread count of this thread-group (visible pid keys the table).
        num_threads: thread_group_live_count(pid),
    })
}

// ── Extended /proc/[pid]/* public accessors ────────────────────────
//
// Called by `narf_filesystem::procfs::pid_ext` via fn-pointer hooks
// wired in `cross_crate_init::install_proc_ext_hooks`.

/// Return the full rlimit table for `pid` as `[(cur, max); 16]`.
/// Indices follow RLIMIT_* numbering (0=CPU, 3=STACK, 7=NOFILE, …).
pub fn rlimits_of(pid: u64) -> [(u64, u64); 16] {
    // RLIMIT_TABLE is keyed by TaskId (prlimit's self form stores under
    // current_task_id()); resolve the outer ProcessId → TaskId.
    let tid = proc_pid_to_tid(pid);
    let row = {
        let g = RLIMIT_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&tid).copied())
            .unwrap_or_else(default_rlimits)
    };
    let mut out = [(0u64, 0u64); 16];
    for (i, p) in row.iter().enumerate() {
        out[i] = (p.cur, p.max);
    }
    out
}

/// Return the nice value for `pid`. Default 0.
pub fn nice_of(pid: u64) -> i32 {
    // NICE_TABLE is keyed by TaskId (read_nice's param is a task id).
    read_nice(proc_pid_to_tid(pid))
}

/// Return the environ block for `pid` (NUL-separated key=value bytes).
/// Returns empty Vec when no environ has been recorded.
pub fn proc_environ_of(pid: u64) -> alloc::vec::Vec<u8> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_ENVIRON.lock();
    g.as_ref()
        .and_then(|m| m.get(&tid).cloned())
        .unwrap_or_default()
}

/// Return the packed ELF auxv bytes for `pid`.  Each entry is two
/// little-endian u64s (key, value).  AT_NULL (0, 0) terminates.
pub fn proc_auxv_of(pid: u64) -> alloc::vec::Vec<u8> {
    let tid = proc_pid_to_tid(pid);
    let g = PROC_AUXV.lock();
    g.as_ref()
        .and_then(|m| m.get(&tid).cloned())
        .unwrap_or_else(|| alloc::vec![0u8; 16])
}

/// Record NUL-separated environ for a task at execve time.
pub fn set_proc_environ(pid: u64, envp: &[&str]) {
    let mut packed = alloc::vec::Vec::new();
    for s in envp {
        packed.extend_from_slice(s.as_bytes());
        packed.push(0);
    }
    let mut g = PROC_ENVIRON.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, packed);
}

/// Record packed auxv (key, value) pairs for a task at execve time.
/// AT_NULL is appended automatically.
pub fn set_proc_auxv_pairs(pid: u64, aux: &[(u64, u64)]) {
    let mut packed: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity((aux.len() + 1) * 16);
    for (key, val) in aux {
        packed.extend_from_slice(&key.to_le_bytes());
        packed.extend_from_slice(&val.to_le_bytes());
    }
    packed.extend_from_slice(&0u64.to_le_bytes());
    packed.extend_from_slice(&0u64.to_le_bytes());
    let mut g = PROC_AUXV.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(pid, packed);
}

/// Return the backing description for fd `n` of `pid`.  Shaped like
/// a Linux `/proc/[pid]/fd/<n>` symlink target.  Returns `None` when
/// the fd or task doesn't exist.
/// The open fd numbers for `pid`, ascending — backs `/proc/<pid>/fd`
/// enumeration. Keyed the same way as [`fd_path_of`] so a per-fd lookup
/// and the directory listing agree.
pub fn proc_fd_list(pid: u64) -> alloc::vec::Vec<u32> {
    crate::fd::open_fds(proc_pid_to_tid(pid))
}

/// `Some(target_pid)` iff fd `n` of `pid` is a pidfd — backs the
/// `Pid:`/`NSpid:` lines of `/proc/<pid>/fdinfo/<n>` (Linux
/// `fs/pidfs.c::pidfd_show_fdinfo`). systemd 258's `pidfd_get_pid()`
/// parses the `Pid:` line to resolve a `pidfd_spawn`-minted pidfd when
/// pidfs/PIDFD_GET_INFO is unavailable; without it every service spawn
/// fails ENOTTY.
pub fn proc_fd_pidfd_pid(pid: u64, n: u32) -> Option<u64> {
    // `pid` is the outer ProcessId of the /proc/<pid> owner; the fd table is
    // keyed by TaskId, so resolve pid→tid first (proc_pid_to_tid). The stored
    // pidfd target is an outer ProcessId; the fdinfo `Pid:` line is the
    // target's pid in the READER's namespace (Linux fs/pidfs.c) so systemd's
    // pidfd_get_pid() fallback sees a number consistent with the pid it holds.
    let tid = proc_pid_to_tid(pid);
    crate::fd::with_table(tid, |t| t.get(n).and_then(|e| e.ops.pidfd_target_pid()))
        .flatten()
        .map(|outer| report_pid_to(current_task_id(), outer))
}

pub fn fd_path_of(pid: u64, n: u32) -> Option<alloc::string::String> {
    // `pid` is the outer ProcessId; the fd/path tables key on TaskId, so
    // resolve pid→tid. Getting this wrong made /proc/self/fd/<n> unresolvable —
    // systemd execs its executor via `execve("/proc/self/fd/N")`, so an empty
    // resolution turned every service spawn into EBADF (project_pidns_flow_model).
    let tid = proc_pid_to_tid(pid);
    // Preferred: the real backing path recorded at open() time (the same
    // fd→path table inotify/landlock use). This is what /proc/<pid>/fd/<n>
    // readlinks to — musl's realpath() opens O_PATH then readlinks here.
    // Report it chroot-relative so a chrooted process (e.g. udev in a
    // distro chroot) can re-open the link target in its own namespace.
    #[cfg(feature = "linux-compat")]
    if let Some(p) = crate::mqueue::fd_path(tid, n) {
        return Some(strip_chroot_prefix(tid, &p));
    }
    crate::fd::with_table(tid, |t| {
        let entry = t.get(n)?;
        // Use the type_name as a fallback for fds with no path (pipes,
        // sockets, eventfd, …) until FileOps grows a path() method.
        let name = core::any::type_name_of_val(&*entry.ops);
        // Extract the last component (e.g. "PipeRead" from "crate::pipe::PipeRead").
        let short = name.rsplit("::").next().unwrap_or(name);
        Some(alloc::format!("anon_inode:[{}]", short))
    })
    .flatten()
}

/// Strip the task's chroot prefix from a host-absolute path, yielding the
/// path as the (possibly chrooted) task sees it. No-op for un-chrooted
/// tasks. Used so `/proc/<pid>/fd/<n>` and similar surfaces report paths a
/// chrooted process can actually re-open.
#[cfg(feature = "linux-compat")]
fn strip_chroot_prefix(task: u64, path: &str) -> alloc::string::String {
    let g = ROOT_DIR_TABLE.lock();
    if let Some(prefix) = g.as_ref().and_then(|m| m.get(&task)) {
        if prefix != "/" {
            if let Some(rest) = path.strip_prefix(prefix.as_str()) {
                if rest.is_empty() {
                    return alloc::string::String::from("/");
                }
                if rest.starts_with('/') {
                    return alloc::string::String::from(rest);
                }
            }
        }
    }
    alloc::string::String::from(path)
}

// Per-task environ and auxv byte stores.
static PROC_ENVIRON: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::vec::Vec<u8>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

static PROC_AUXV: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::vec::Vec<u8>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Set the pending bit for `signum` on `task`. Used by Wave-73
/// POSIX timer expiries to queue a signal without going through
/// `sys_kill` (which expects a syscall trap frame). Mirrors the
/// `*slot |= 1 << signum` step inside `sys_kill`.
pub fn raise_signal_pending(task: u64, signum: u32) {
    // Reject signal 0: it's the POSIX null signal (existence probe), never a
    // real signal. Setting pending bit 0 would later be taken by the delivery
    // loop as a Terminate-default "signal 0". Bit-N-=-signal-N caps the
    // representable range at 63 (see SIGNAL_PENDING).
    if signum == 0 || signum > 64 {
        return;
    }
    // Job-control stop/continue bookkeeping (SIGCONT resume + stop/cont
    // mutual cancellation) runs before the pending bit is set.
    signal_stopcont_interaction(task, signum);
    let mut g = SIGNAL_PENDING.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => return,
    };
    let slot = map.entry(task).or_insert(0);
    *slot |= sig_bit(signum);
    drop(g);
    // Wake the task if it is parked (sleep/pause) so an asynchronously
    // raised signal — e.g. SIGALRM from an interval timer — is taken
    // promptly rather than only at the next self-driven re-poll.
    wake_signal(task);
}

/// Deliver `signum` to every task in process group `pgrp` (job-control
/// terminal signals: ^C/^\/^Z → SIGINT/SIGQUIT/SIGTSTP go to the whole
/// foreground group, not just one process). Members are the tasks mapped
/// to `pgrp` in `PGID_TABLE` plus the group leader (`pid == pgrp`) when it
/// has no divergent mapping. Returns true if at least one task was
/// targeted. Syscall context only (allocates).
pub fn deliver_signal_to_pgrp(pgrp: u64, signum: u32) -> bool {
    if pgrp == 0 || signum > 64 {
        return false;
    }
    let mut targets: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    {
        let g = PGID_TABLE.lock();
        if let Some(m) = g.as_ref() {
            for (&task, &pg) in m.iter() {
                if pg == pgrp {
                    targets.push(task);
                }
            }
        }
    }
    // The leader (pid == pgrp) defaults to pgid == pid when unmapped;
    // include it unless it was explicitly moved to another group.
    if !targets.contains(&pgrp) && read_pgid(pgrp) == pgrp {
        targets.push(pgrp);
    }
    if targets.is_empty() {
        return false;
    }
    for t in targets {
        signal_stopcont_interaction(t, signum);
        raise_signal_pending(t, signum);
        // Kick parked targets — without the wake a pgrp SIGTERM to a
        // blocked task waits out its wheel-fallback deadline.
        wake_signal(t);
    }
    true
}

/// Job-control check for a read/write on a controlling terminal by a
/// process in a *background* process group (POSIX):
///   - a background READ of the controlling tty → SIGTTIN
///   - a background WRITE, only when TOSTOP is set → SIGTTOU
///
/// If the generating signal is blocked or ignored by the caller the I/O
/// fails with EIO instead (an un-stoppable process can't be made to wait);
/// otherwise the signal goes to the caller's whole pgrp (default action:
/// stop) and the syscall is interrupted with EINTR. Returns `Some(neg
/// errno)` when the caller should abort the syscall with that value, or
/// `None` to proceed with the I/O. The fd's tty identity / fg pgrp / TOSTOP
/// are read in one short fd-table borrow; signal delivery happens after it
/// is released (no fd-table reentrancy).
#[cfg(feature = "linux-compat")]
fn tty_background_access(task: u64, fd: u32, is_write: bool) -> Option<i64> {
    let (tty_id, fg, tostop) = crate::fd::with_table(task, |t| {
        t.get(fd).and_then(|e| {
            e.ops
                .tty_id()
                .map(|id| (id, e.ops.tty_fg_pgrp().unwrap_or(0), e.ops.tty_tostop()))
        })
    })??;

    if fg == 0 {
        return None; // no job control configured on this tty
    }
    let caller_pgrp = read_pgid(task);
    if caller_pgrp == 0 || caller_pgrp == fg {
        return None; // foreground process group — proceed
    }
    if task_ctty(task) != Some(tty_id) {
        return None; // not this process's controlling terminal — proceed
    }
    if is_write && !tostop {
        return None; // background writes are allowed unless TOSTOP
    }

    let signum: u32 = if is_write { 22 } else { 21 }; // SIGTTOU / SIGTTIN
    let blocked = (signal_mask_of(task) & (sig_bit(signum))) != 0;
    let ignored = sigaction_lookup_full(task, signum as usize).is_some_and(|sa| sa.handler == 1);
    if blocked || ignored {
        return Some(-5); // -EIO: signal can't stop the process
    }
    deliver_signal_to_pgrp(caller_pgrp, signum);
    Some(-4) // -EINTR: the stopped pgrp restarts the read/write on continue
}

/// Pre-create `task`'s `SIGNAL_PENDING` entry (bits = 0) so a later
/// IRQ-context raise can be alloc-free. Called from syscall context
/// (e.g. arming an interval timer), where allocation is allowed. No-op
/// if the entry already exists or the table is uninitialised.
pub fn ensure_signal_pending_slot(task: u64) {
    if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
        map.entry(task).or_insert(0);
    }
}

/// Alloc-free, IRQ-safe variant of `raise_signal_pending`: OR the
/// `signum` bit into an *existing* `SIGNAL_PENDING` entry. Returns false
/// (signal dropped) if `task` has no entry yet — callers that need this
/// path must have pre-created the slot via `ensure_signal_pending_slot`.
///
/// Unlike `raise_signal_pending` it deliberately does NOT run
/// `signal_stopcont_interaction` or `wake_signal` — both can allocate /
/// take further locks, neither is needed for the timer-IRQ case (the
/// interrupted task is running, not parked, and SIGALRM is not a
/// stop/cont signal). The signal is taken on the same trap's
/// return-to-user via the preemptive delivery hook.
pub fn raise_signal_pending_irq(task: u64, signum: u32) -> bool {
    // Signal 0 is the null signal — never deliverable (see raise_signal_pending).
    if signum == 0 || signum > 64 {
        return false;
    }
    let mut g = SIGNAL_PENDING.lock();
    if let Some(map) = g.as_mut() {
        if let Some(slot) = map.get_mut(&task) {
            *slot |= sig_bit(signum);
            return true;
        }
    }
    false
}

/// Timer-tick hook (called from the arch timer ISR). Raises any signal
/// whose timer has expired for the *currently running* task, so a
/// CPU-bound task that never parks still receives e.g. SIGALRM from
/// `alarm()` / `setitimer(ITIMER_REAL)`. Alloc-free — safe to call with
/// interrupts disabled from the trap handler. The raised signal is then
/// delivered by `signal_delivery_hook` on the same trap's return to user.
pub fn timer_tick_raise_due_signals() {
    #[cfg(feature = "linux-compat")]
    {
        let now = narf_scheduler::narf_time::monotonic_ns();
        // Scan EVERY armed ITIMER_REAL slot, not just the interrupted task's.
        // The owner of a `setitimer(ITIMER_REAL)` is frequently PARKED (e.g.
        // blocked in waitpid while CPU-bound children spin) — so it's never
        // the interrupted task, and the sleep-pump that would catch it
        // starves under that load. Without this scan the parked owner's
        // SIGALRM never fires (the kernel cause of the SMP chroot_run /
        // stress-ng hang, where a parent stops its workers via an alarm).
        //
        // O(1)-stack drain: take one due owner at a time, then raise + wake it
        // OUTSIDE the ITIMERS lock. We MUST NOT collect the owners into a large
        // on-stack `[u64; N]` buffer here: this runs in the timer ISR on the
        // *user task's own kernel stack* (per-task-own-stack model), and a
        // ~512 B array on that IRQ-path frame deterministically smashed this
        // handler's return chain (`rip=0x3` #UD) under stress-ng fork/exec churn
        // — the same "no big on-stack array in IRQ context" hazard the timer
        // wheel documents (`timer_wheel::drain_due_to_deferred`).
        let mut after: Option<u64> = None;
        while let Some(t) = crate::posix_timer::itimer_real_take_one_due_irq(now, after) {
            after = Some(t);
            // SIGALRM (14). Slot was pre-created when the timer was armed, so
            // this only sets a bit in an existing entry (never allocates).
            let _ = raise_signal_pending_irq(t, 14);
            // Wake the owner if it's parked so waitpid/pause returns EINTR and
            // SIGALRM is delivered on its return-to-user. For the currently
            // running owner (the original CPU-bound case) this is a harmless
            // no-op — it has no parked waker and takes the signal on this
            // trap's return. Every lock `wake_signal` touches is an
            // `IrqSafeSpinLock`, so this is safe from the timer ISR.
            wake_signal(t);
        }
    }
}

/// Preemptive time-slice: hand a CPU-bound user task back to the
/// cooperative executor from the timer ISR so sibling tasks make
/// progress instead of being monopolized. Mirrors `sys_yield`'s
/// polling-executor path exactly — save the interrupted register state
/// into the task's `UserTaskCtx` and longjmp to the executor via the
/// yield hook — but driven by the timer instead of an explicit syscall.
///
/// Why this is enough (no executor changes needed): a parked user task's
/// sleep is *self-driven* — its `poll` re-checks `sleep_deadline_ns`,
/// `wake_by_ref`s, and returns `Pending`, so it's re-polled every round.
/// Without preemption a CPU-bound sibling never returns from its own
/// `poll` (no syscall, no yield), so the executor never completes the
/// round and never re-polls the sleeper. Yielding here lets the round
/// finish, the sleeper's deadline fire on time, and other runnable tasks
/// run.
///
/// Does NOT return when it preempts (the yield hook longjmps; the task
/// resumes later via `enter_user_mode_resume`). Returns normally — a
/// no-op — when no polling executor is wired or no user task is current
/// (e.g. the in-kernel test harness), so those contexts are unaffected.
///
/// The caller MUST gate on returning-to-user (CPL=3): a task interrupted
/// inside a syscall is at CPL=0 and must not be yanked mid-kernel.
pub fn timer_preempt_user_task(ctx: &mut dyn TrapContext) {
    // Only hand a CPU-bound task back to the cooperative executor if something
    // else actually needs the CPU. With a 1000 Hz tick, yielding on EVERY tick
    // made a task that never parks spend almost all its wall-clock in the
    // yield -> executor-round -> resume cycle (measured ~25-94x slower than
    // native). When nothing else is runnable that round-trip just resumes the
    // same task, so skip it and let the task keep running; it still takes the
    // timer IRQ each tick (signal delivery, the alarm SIGALRM that stops it,
    // wheel arming), so fairness/liveness are preserved the moment any peer
    // wakes. Voluntary yields (syscall/park) don't come through here.
    if !narf_scheduler::has_other_runnable_work(current_task_id()) {
        return;
    }
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: identical contract to sys_yield's hook path — `uctx` is
        // the live per-task `UserTaskCtx` published by the executor before
        // it entered user mode; we save the interrupted CPU state into
        // `uc.state` and hand the task back to the executor via the yield
        // hook, which longjmps to the executor's `setjmp` and does not
        // return. The timer ISR has already EOI'd and exited the trap
        // handler frame, so abandoning the IRQ frame here is clean (same
        // as sys_yield abandoning its syscall frame).
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
        // unreachable when preempted
    }
}

/// Clear the pending bit for `signum` on `task`. Used by signalfd
/// after delivering the signal through the fd path.
pub fn clear_signal_pending(task: u64, signum: u32) {
    if signum > 64 {
        return;
    }
    let mut g = SIGNAL_PENDING.lock();
    if let Some(map) = g.as_mut() {
        if let Some(slot) = map.get_mut(&task) {
            *slot &= !(sig_bit(signum));
        }
    }
}

/// Diagnostic: peek the block mask for `task`.
pub fn signal_mask_of(task: u64) -> u64 {
    SIGNAL_MASK
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

pub(crate) fn set_signal_mask_for_task(task: u64, mask: u64) -> u64 {
    let mut g = SIGNAL_MASK.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    // SIGKILL/SIGSTOP can never be blocked, whichever install path the
    // mask arrives through (sigsuspend / ppoll / epoll_pwait / sigreturn
    // restore all funnel here) — same strip sys_sigprocmask applies.
    map.insert(task, mask & !UNBLOCKABLE_MASK).unwrap_or(0)
}

/// Send `signum` to the single process named by outer pid `pid`.
/// Resolves the group leader; if the leader is already a zombie the
/// signal still "succeeds" (Linux: signalling a zombie is a no-op
/// success), and if the leader tid is dead but live CLONE_THREAD
/// siblings remain, one of them takes delivery. A fatal SIGKILL fans
/// out to every live thread in the group (Linux group-kill).
/// Returns false when no such process exists (→ ESRCH).
fn kill_process(pid: u64, signum: u32) -> bool {
    let Some(leader_tid) = pid_to_task_raw(pid) else {
        return false;
    };
    let Some(leader) = crate::task::task_get(leader_tid) else {
        return false;
    };
    // Collect group member tids (leader + CLONE_THREAD tids mapping to
    // the same visible pid) under the TASK_TO_PID lock, THEN filter by
    // liveness — `task_get` takes the TASKS lock, which must never be
    // acquired while holding TASK_TO_PID (lock-order discipline).
    let candidates: alloc::vec::Vec<u64> = {
        let g = TASK_TO_PID.lock();
        g.as_ref()
            .map(|m| {
                m.iter()
                    .filter(|&(_, &p)| p == pid)
                    .map(|(&t, _)| t)
                    .collect()
            })
            .unwrap_or_default()
    };
    let members: alloc::vec::Vec<u64> = candidates
        .into_iter()
        .filter(|&t| {
            crate::task::task_get(t)
                .is_some_and(|t| t.state.load(Ordering::Acquire) == crate::task::TASK_RUNNING)
        })
        .collect();
    if members.is_empty() {
        // Whole group already exited (zombie awaiting reap): success,
        // signal discarded.
        return leader.state.load(Ordering::Acquire) == crate::task::TASK_ZOMBIE;
    }
    if signum == 9 {
        // Fatal group kill: every live thread dies.
        for t in members {
            signal_stopcont_interaction(t, signum);
            raise_signal_pending(t, signum);
            wake_signal(t);
        }
        return true;
    }
    // Process-directed: deliver to the leader if alive, else the first
    // live sibling. (Full shared-pending "any thread with it unblocked
    // may dequeue" semantics are a follow-up; see the redesign doc.)
    let target = if members.contains(&leader_tid) {
        leader_tid
    } else {
        members[0]
    };
    signal_stopcont_interaction(target, signum);
    raise_signal_pending(target, signum);
    wake_signal(target);
    true
}

/// Does a signal target tid exist? A live task satisfies at least one
/// of: the refcounted registry (real spawned tasks), the tid→pid map
/// (also true for real tasks and for boot-init tasks that predate the
/// registry), or being the caller itself (self is always alive). A
/// truly unknown tid satisfies none → the caller gets ESRCH, instead
/// of the old behaviour of setting a pending bit on a phantom key.
fn signal_target_exists(tid: u64) -> bool {
    if crate::task::task_get(tid).is_some() || tid == current_task_id() {
        return true;
    }
    TASK_TO_PID
        .lock()
        .as_ref()
        .is_some_and(|m| m.contains_key(&tid))
}

/// Copy `si_code` (offset 8), `si_pid` (offset 16) and `si_value` (the
/// sigval union, offset 24) out of a user `siginfo_t` and stash them for
/// delivery / sigtimedwait / signalfd. Returns `false` only when the
/// target's queue is full (RLIMIT_SIGPENDING shape → sender returns
/// -EAGAIN); a NULL/unreadable info queues nothing but "succeeds" (the
/// bare signal still delivers, like a payload-less kill).
fn capture_queued_siginfo(target: u64, sig: u32, info_ptr: u64) -> bool {
    if info_ptr == 0 {
        return true;
    }
    // SAFETY: info_ptr is non-zero; copy_from_user_vec range-validates the
    // 32-byte read covering si_signo..si_value.
    if let Ok(b) = unsafe { copy_from_user_vec(info_ptr, 32) } {
        let si_code = i32::from_le_bytes(b[8..12].try_into().unwrap());
        // si_pid (offset 16 in the rt union) — musl/glibc `sigqueue` fill
        // getpid() here, and consumers reply to it (stress-ng --sigrt's
        // child does `sigqueue(info.si_pid, ...)`).
        let si_pid = u32::from_le_bytes(b[16..20].try_into().unwrap());
        let si_value = u64::from_le_bytes(b[24..32].try_into().unwrap());
        return store_sigqueue_info(target, sig, si_code, si_value, si_pid);
    }
    true
}

// ── futex — minimal scaffold ────────────────────────────────────────
//
// Linux futex(2) is the kernel-side primitive backing pthread
// mutexes / condvars / once-init. Even a no-op handler lets
// libstdc++ + glibc thread fixtures load. NARF is single-
// threaded; there are no waiters to wake or block.
//
// Honoured ops (after stripping the FUTEX_PRIVATE / FUTEX_CLOCK_
// REALTIME bits):
//   FUTEX_WAIT (0): would block until the futex word is woken
//                   or the timeout fires. Single-threaded NARF
//                   has no other task to do the wake, so we
//                   return 0 (the spec permits spurious wakes
//                   so the caller will re-check the condition).
//   FUTEX_WAKE (1): would wake up to `val` waiters. We have
//                   none; return 0.
//
// Anything else returns -1 with the libc shim setting
// errno = ENOSYS.

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
/// `FUTEX_REQUEUE` (3) / `FUTEX_CMP_REQUEUE` (4): wake up to `val` waiters
/// on `uaddr`, then MOVE up to `val2` more onto `uaddr2`'s wait queue
/// WITHOUT waking them (they wake on a later `FUTEX_WAKE` of `uaddr2`).
/// CMP additionally fails with -EAGAIN unless `*uaddr == val3`.
///
/// musl's condvar depends on this: `pthread_cond_broadcast` wakes only the
/// oldest waiter directly; each woken waiter then hands off to the next via
/// `unlock_requeue(&node.prev->barrier, &m->_m_lock, ...)`, which zeroes
/// the next waiter's barrier word and REQUEUES its (still-parked) kernel
/// wait onto the mutex so the eventual mutex unlock wakes it. Returning a
/// non-ENOSYS error here made musl treat the requeue as done — the waiter
/// stayed parked on a barrier word nobody would ever wake again (musl's
/// `unlock()` only wakes when the swap saw 2, and the word was already 0)
/// — a permanent, deterministic strand of any broadcast to >= 2 parked
/// waiters. That is the `condbcast_smoke` hang and the mechanism behind
/// the "SMP scheduler-resume strand" class of wedges.
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_CMP_REQUEUE: u64 = 4;
/// `FUTEX_WAKE_OP` (5): atomically RMW a second futex word, wake `val`
/// waiters on `uaddr`, and — if the pre-RMW value satisfies an encoded
/// comparison — wake `val2` waiters on `uaddr2`. glibc's (and Qt's)
/// pthread_cond_signal/broadcast use this to wake a condvar waiter while
/// bumping the condvar's internal sequence word in one call. Without it,
/// a Qt6 worker thread's wake of the main thread was dropped and the app
/// deadlocked at startup (the kcalc QtWayland-init hang).
const FUTEX_WAKE_OP: u64 = 5;
/// `FUTEX_WAIT_BITSET` (9) / `FUTEX_WAKE_BITSET` (10): wait/wake gated by
/// a 32-bit bitmask. NARF's wait queue is per-uaddr (not per-bit), so we
/// treat them as plain WAIT/WAKE — a superset wake is always safe, and
/// the common musl/glibc callers pass FUTEX_BITSET_MATCH_ANY.
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_PRIVATE: u64 = 0x80;
const FUTEX_CLOCK_REALTIME: u64 = 0x100;
const FUTEX_OP_MASK: u64 = !(FUTEX_PRIVATE | FUTEX_CLOCK_REALTIME);

/// Perform `FUTEX_WAKE_OP` (Linux `kernel/futex/core.c::futex_wake_op`).
/// `nr_wake`/`nr_wake2` = arg2/arg3, `uaddr2` = arg4, `encoded_op` = arg5.
/// Returns the syscall result (total woken, or a negative errno).
fn futex_wake_op(uaddr: u64, nr_wake: u32, nr_wake2: u32, uaddr2: u64, encoded_op: u32) -> i64 {
    const EFAULT: i64 = 14;
    if uaddr2 == 0 {
        return -EFAULT;
    }
    // Decode the op word: [31:28]=op (bit 0x8 = OPARG_SHIFT), [27:24]=cmp,
    // [23:12]=oparg (12b), [11:0]=cmparg (12b).
    let op_raw = (encoded_op >> 28) & 0xF;
    let oparg_shift = op_raw & 0x8 != 0;
    let op = op_raw & 0x7;
    let cmp = (encoded_op >> 24) & 0xF;
    let mut oparg = (encoded_op >> 12) & 0xFFF;
    let cmparg = (encoded_op & 0xFFF) as i32;
    if oparg_shift {
        oparg = 1u32 << (oparg & 31);
    }
    // Atomically-ish RMW *uaddr2 (single-CPU cooperative for the handler;
    // matches NARF's other user-word futex accesses).
    let mut b = [0u8; 4];
    // SAFETY: copy_from_user range-validates uaddr2 + SMAP-brackets the read.
    if unsafe { copy_from_user(&mut b, uaddr2) }.is_err() {
        return -EFAULT;
    }
    let oldval = u32::from_ne_bytes(b);
    let newval = match op {
        0 => oparg,                      // FUTEX_OP_SET
        1 => oldval.wrapping_add(oparg), // FUTEX_OP_ADD
        2 => oldval | oparg,             // FUTEX_OP_OR
        3 => oldval & !oparg,            // FUTEX_OP_ANDN
        4 => oldval ^ oparg,             // FUTEX_OP_XOR
        _ => return -22,                 // EINVAL — unknown op
    };
    // SAFETY: copy_to_user range-validates uaddr2 + SMAP-brackets the write.
    if unsafe { copy_to_user(uaddr2, &newval.to_ne_bytes()) }.is_err() {
        return -EFAULT;
    }
    // Wake `nr_wake` on uaddr unconditionally.
    futex_bump_counter(uaddr);
    let mut woken = futex_wake_waiters(uaddr, nr_wake) as i64;
    // Conditionally wake `nr_wake2` on uaddr2 if (oldval CMP cmparg).
    let ov = oldval as i32;
    let cond = match cmp {
        0 => ov == cmparg, // FUTEX_OP_CMP_EQ
        1 => ov != cmparg, // NE
        2 => ov < cmparg,  // LT
        3 => ov <= cmparg, // LE
        4 => ov > cmparg,  // GT
        5 => ov >= cmparg, // GE
        _ => return -22,   // EINVAL
    };
    if cond {
        futex_bump_counter(uaddr2);
        woken += futex_wake_waiters(uaddr2, nr_wake2) as i64;
    }
    woken
}

/// Per-uaddr wait counter. FUTEX_WAKE bumps it; FUTEX_WAIT samples
/// it before parking and re-samples on every poll iteration —
/// progress means a wake landed. Futex semantics aren't strictly
/// "queue + dequeue" — Linux models them as "tagged wakeup events",
/// and the counter gives us that without per-task ownership, which
/// keeps the implementation lock-free except for the table mutation.
static FUTEX_WAKE_COUNTERS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, u64>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn futex_table_init() {
    let mut g = FUTEX_WAKE_COUNTERS.lock();
    if g.is_none() {
        *g = Some(alloc::collections::BTreeMap::new());
    }
}

fn futex_wake_counter(uaddr: u64) -> u64 {
    futex_table_init();
    let g = FUTEX_WAKE_COUNTERS.lock();
    g.as_ref().and_then(|m| m.get(&uaddr).copied()).unwrap_or(0)
}

fn futex_bump_counter(uaddr: u64) {
    futex_table_init();
    let mut g = FUTEX_WAKE_COUNTERS.lock();
    if let Some(m) = g.as_mut() {
        let slot = m.entry(uaddr).or_insert(0);
        *slot = slot.wrapping_add(1);
    }
}

/// Live per-uaddr `FUTEX_WAKE` generation. The user-task poll routine
/// snapshots this (`futex_park_gen`) before parking and re-reads it after
/// registering the waker — a change means a wake raced the registration
/// (lost-wakeup guard). Public mirror of `futex_wake_counter`.
pub fn futex_gen(uaddr: u64) -> u64 {
    futex_wake_counter(uaddr)
}

/// `FUTEX_WAIT` seqlock read: sample the per-uaddr wake generation FIRST,
/// then read the futex word. This ORDER is load-bearing. The generation is a
/// seqlock the waiter reads as "sample gen → read value → (at park) recheck
/// gen": a `FUTEX_WAKE` that races between the word read and the park
/// registration bumps the generation PAST this snapshot, so the park guard
/// (`futex_gen(uaddr) != futex_park_gen`) detects it and the waiter re-checks
/// instead of parking. Sampling the generation AFTER the word read loses that
/// wake — the waiter captures the post-bump generation, parks, and the guard
/// sees "no change": the classic futex lost-wakeup that deadlocks a contended
/// pthread mutex/condvar under SMP (invisible at SMP=1, where no waker can run
/// between the read and the park). Returns `(gen, *uaddr)`, or `None` if
/// `read_word` reports a fault. `read_word` is a closure so the exact
/// user-memory read (or, in tests, an injected racing bump) is the caller's.
pub(crate) fn futex_wait_seqlock_read(
    uaddr: u64,
    read_word: impl FnOnce() -> Option<u32>,
) -> Option<(u64, u32)> {
    let gen = futex_wake_counter(uaddr);
    let current = read_word()?;
    Some((gen, current))
}

/// Test-only: bump a uaddr's wake generation (models a `FUTEX_WAKE`), so a
/// seqlock-ordering test can inject a wake that races the futex-word read.
#[doc(hidden)]
pub fn __test_futex_bump_counter(uaddr: u64) {
    futex_bump_counter(uaddr);
}

/// Per-uaddr blocking-futex wait queue: futex word → (task id → Waker).
/// `FUTEX_WAIT` registers the caller's waker here (via the user-task poll
/// routine) and truly parks; `FUTEX_WAKE` pops up to `val` wakers and fires
/// them. This is what makes the futex a REAL blocking primitive instead of
/// the old fixed-1ms nanosleep park: under contention musl's `__wait` spin
/// loop otherwise re-parks every ~1ms (no early wake), so a contended pthread
/// lock handoff cost ~1ms. Keyed by task id so a re-registering waiter
/// overwrites its own slot (bounded) and `futex_drop_waiter` can remove it.
#[allow(clippy::type_complexity)]
static FUTEX_WAITERS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, alloc::collections::BTreeMap<u64, core::task::Waker>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Register `task_id`'s waker as parked on futex word `uaddr`. Called from
/// the user-task poll routine while a task blocks in `FUTEX_WAIT`.
pub fn futex_register_waiter(uaddr: u64, task_id: u64, waker: core::task::Waker) {
    let mut g = FUTEX_WAITERS.lock();
    let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    m.entry(uaddr).or_default().insert(task_id, waker);
}

/// Remove `task_id`'s futex waker on `uaddr` without firing it (the task
/// woke for another reason — lost-wakeup re-poll, timeout, or exit).
pub fn futex_drop_waiter(uaddr: u64, task_id: u64) {
    let mut g = FUTEX_WAITERS.lock();
    if let Some(m) = g.as_mut() {
        if let Some(set) = m.get_mut(&uaddr) {
            set.remove(&task_id);
            if set.is_empty() {
                m.remove(&uaddr);
            }
        }
    }
}

/// Wake up to `n` tasks parked on futex word `uaddr`. Returns the count
/// woken. Drains the wakers under the table lock, then fires them after
/// dropping it (wake() may re-enter the scheduler). Mirrors `wake_one`:
/// clears each woken task's finite sleep deadline so its re-poll falls
/// through to re-enter user mode (where musl re-checks the futex word).
fn futex_wake_waiters(uaddr: u64, n: u32) -> usize {
    let drained: alloc::vec::Vec<(u64, core::task::Waker)> = {
        let mut g = FUTEX_WAITERS.lock();
        let Some(m) = g.as_mut() else {
            return 0;
        };
        let Some(set) = m.get_mut(&uaddr) else {
            return 0;
        };
        // BTreeMap has no pop; collect the first `n` keys then remove them.
        let take: alloc::vec::Vec<u64> = set.keys().take(n as usize).copied().collect();
        let mut out = alloc::vec::Vec::with_capacity(take.len());
        for tid in take {
            if let Some(w) = set.remove(&tid) {
                out.push((tid, w));
            }
        }
        if set.is_empty() {
            m.remove(&uaddr);
        }
        out
    };
    let count = drained.len();
    for (tid, w) in drained {
        wake_one(tid, w);
    }
    count
}

/// `FUTEX_REQUEUE`/`FUTEX_CMP_REQUEUE` core: wake up to `n_wake` waiters on
/// `uaddr`, then MOVE up to `n_move` of the remaining waiters onto
/// `uaddr2`'s wait queue without firing their wakers (Linux
/// `futex_requeue`). Returns `(woken, moved)`.
///
/// The queue move happens under the single `FUTEX_WAITERS` table lock
/// (both per-uaddr queues live in one map under one lock, so there is no
/// two-queue lock-ordering hazard). After the move — with the table lock
/// DROPPED — each mover's park state is retargeted to the destination
/// word: `futex_park_gen` is set to a destination-generation snapshot
/// taken BEFORE the queue move (so a `FUTEX_WAKE(uaddr2)` racing the move
/// bumps past the snapshot and the waiter's gen guard fires), then
/// `futex_uaddr`/`futex_val` flip to the destination word and `new_val`
/// (the caller-sampled current `*uaddr2`). A backstop re-poll that
/// interleaves anywhere in this window is caught by the park loop's word
/// re-validation (`futex_park_should_stay`): the source word was already
/// rewritten by the userspace caller (musl stores the barrier word before
/// issuing the requeue), so a stale-state re-check proceeds to userspace
/// and re-evaluates there — a bounded spurious wake, never a lost one.
fn futex_requeue_waiters(
    uaddr: u64,
    uaddr2: u64,
    n_wake: u32,
    n_move: u32,
    new_val: u32,
) -> (usize, usize) {
    // Wake side first, exactly like FUTEX_WAKE: bump the source generation
    // (so a waiter racing its park registration re-checks), then pop + fire.
    futex_bump_counter(uaddr);
    let woken = futex_wake_waiters(uaddr, n_wake);
    if n_move == 0 {
        return (woken, 0);
    }
    // Destination-generation snapshot BEFORE the queue move (see above).
    let gen2 = futex_wake_counter(uaddr2);
    let moved: alloc::vec::Vec<u64> = {
        let mut g = FUTEX_WAITERS.lock();
        let Some(m) = g.as_mut() else {
            return (woken, 0);
        };
        let Some(set) = m.get_mut(&uaddr) else {
            return (woken, 0);
        };
        let take: alloc::vec::Vec<u64> = set.keys().take(n_move as usize).copied().collect();
        let mut movers: alloc::vec::Vec<(u64, core::task::Waker)> =
            alloc::vec::Vec::with_capacity(take.len());
        for tid in take {
            if let Some(w) = set.remove(&tid) {
                movers.push((tid, w));
            }
        }
        if set.is_empty() {
            m.remove(&uaddr);
        }
        let dst = m.entry(uaddr2).or_default();
        let mut tids = alloc::vec::Vec::with_capacity(movers.len());
        for (tid, w) in movers {
            dst.insert(tid, w);
            tids.push(tid);
        }
        tids
    };
    // Retarget each mover's park state OUTSIDE the table lock (the task
    // registry lock in with_user_task_ctx must never nest inside it).
    for tid in &moved {
        crate::user_task::with_user_task_ctx(*tid, |uc| {
            uc.futex_park_gen.store(gen2, Ordering::Release);
            uc.futex_val.store(new_val, Ordering::Release);
            uc.futex_uaddr.store(uaddr2, Ordering::Release);
        });
    }
    (woken, moved.len())
}

/// Read the 4-byte futex word at user address `uaddr` in the CURRENT
/// address space. `None` on fault/unmapped. Used by `FUTEX_CMP_REQUEUE`'s
/// `*uaddr == val3` check and by the park loop's word re-validation.
pub(crate) fn futex_read_user_word(uaddr: u64) -> Option<u32> {
    if uaddr == 0 {
        return None;
    }
    let mut b = [0u8; 4];
    // SAFETY: copy_from_user range-validates the user pointer and
    // SMAP-brackets the read.
    if unsafe { copy_from_user(&mut b, uaddr) }.is_ok() {
        Some(u32::from_ne_bytes(b))
    } else {
        None
    }
}

/// Decide whether a parked `FUTEX_WAIT` should STAY parked on its next
/// park-loop re-check (the ~10 ms wheel-backstop re-poll): only while BOTH
/// no `FUTEX_WAKE` generation has landed on the word (`gen_now ==
/// park_gen`) AND the futex word itself still holds the value the waiter
/// parked on (`word_now == Some(expected)`).
///
/// The word re-validation is the load-bearing half. Futex protocols may
/// change the word WITHOUT a wake on the old word — musl's
/// `unlock_requeue` stores the barrier word and then only requeues; a
/// robust-futex owner death rewrites the word; any PI/handoff scheme does
/// the same — and Linux waiters tolerate that because every spurious
/// return re-checks the word in userspace. NARF's own-stack park loop
/// swallows the backstop wake INSIDE the kernel, so before this check a
/// silently-rewritten word meant the waiter re-parked forever on a word
/// nobody would ever wake again — the permanent variant of the SMP strand
/// (`condbcast_smoke`). An unreadable word (`None` — AS torn down,
/// unmapped) also proceeds: never re-park on memory we cannot re-check.
pub(crate) fn futex_park_should_stay(
    gen_now: u64,
    park_gen: u64,
    word_now: Option<u32>,
    expected: u32,
) -> bool {
    gen_now == park_gen && word_now == Some(expected)
}

/// Test-only accessor for the futex wake counter — Wave-65 smokes
/// observe CLONE_CHILD_CLEARTID's exit-side futex wake by reading
/// this counter before/after the exit notification.
#[doc(hidden)]
pub fn __test_futex_wake_counter(uaddr: u64) -> u64 {
    futex_wake_counter(uaddr)
}

/// Test-only: register a waiter / requeue / count parked waiters, so the
/// kernel-test suite can pin the FUTEX_REQUEUE queue-move semantics
/// without a user address space.
#[doc(hidden)]
pub fn __test_futex_requeue(uaddr: u64, uaddr2: u64, n_wake: u32, n_move: u32) -> (usize, usize) {
    futex_requeue_waiters(uaddr, uaddr2, n_wake, n_move, 0)
}

#[doc(hidden)]
pub fn __test_futex_waiter_count(uaddr: u64) -> usize {
    let g = FUTEX_WAITERS.lock();
    g.as_ref()
        .and_then(|m| m.get(&uaddr).map(|s| s.len()))
        .unwrap_or(0)
}

/// Test-only FUTEX_WAKE equivalent (gen bump + pop-and-fire), so tests can
/// drive the wake side of the wait queue without a TrapContext.
#[doc(hidden)]
pub fn futex_wake_waiters_for_test(uaddr: u64, n: u32) -> usize {
    futex_bump_counter(uaddr);
    futex_wake_waiters(uaddr, n)
}

/// Shared FUTEX_WAIT core for both the classic `futex(2)` FUTEX_WAIT op
/// and the futex2 `futex_wait(2)` syscall. Implements the same real
/// cooperative wait NARF's pthreads already rely on:
///
///  - `*uaddr != val` ⇒ the wait condition no longer holds; return
///    `-EAGAIN` (Linux's contract — the caller's fast path observes the
///    change and proceeds without sleeping).
///  - `*uaddr == val` ⇒ park the caller via a bounded yield back to the
///    executor (the deadline branch of `UserTaskFuture::poll` keeps it
///    off-CPU until the park expires or a wake bumps the per-uaddr
///    counter), then resume with `0`. The libc-side recheck loop re-arms
///    the wait until the condition is satisfied, so a `futex_wake` on the
///    same word makes the waiter progress.
///
/// `uaddr == 0` is treated as an immediate (POSIX-permitted) spurious
/// wake so wake-path smokes can run without a backing mapping.
fn futex_wait_core(ctx: &mut dyn TrapContext, uaddr: u64, val: u32, park_cap_ns: u64) {
    const EAGAIN: i64 = 11;
    const EFAULT: i64 = 14;
    if uaddr == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Seqlock read: sample the wake generation BEFORE reading `*uaddr` (see
    // `futex_wait_seqlock_read` — sampling after the read loses a racing
    // FUTEX_WAKE and deadlocks a contended mutex/condvar under SMP).
    let (gen, current) = match futex_wait_seqlock_read(uaddr, || {
        let mut buf4 = [0u8; 4];
        // SAFETY: copy_from_user range-validates `uaddr` + SMAP-brackets the read.
        if unsafe { copy_from_user(&mut buf4, uaddr) }.is_ok() {
            Some(u32::from_ne_bytes(buf4))
        } else {
            None
        }
    }) {
        Some(x) => x,
        None => {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
    };
    if current != val {
        ctx.set_return(SyscallReturn::ok((-EAGAIN) as u64));
        return;
    }
    // REAL blocking park, same wait queue + per-uaddr wake counter as the
    // classic `sys_futex` FUTEX_WAIT (Linux futex2 and classic futex operate
    // on the SAME words — a FUTEX_WAKE must wake either). Register happens in
    // the poll routine; here we publish the uaddr + counter snapshot + an
    // infinite (or timeout-bounded) deadline and yield.
    let deadline = if park_cap_ns == 0 {
        u64::MAX
    } else {
        narf_scheduler::narf_time::monotonic_ns().saturating_add(park_cap_ns)
    };
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        ctx.set_return(SyscallReturn::ok(0));
        // SAFETY: uctx is live for the trap round-trip.
        unsafe {
            let uc = &*uctx;
            uc.futex_park_gen.store(gen, Ordering::Release);
            // Park-loop word re-validation snapshot (see sys_futex).
            uc.futex_val.store(val, Ordering::Release);
            uc.futex_uaddr.store(uaddr, Ordering::Release);
            uc.sleep_deadline_ns.store(deadline, Ordering::Release);
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
    // Test/no-future fallback: synchronous success.
    ctx.set_return(SyscallReturn::ok(0));
}

/// Bounded cooperative-park cap for the futex2 wait ops. Unlike the classic
/// `sys_futex` FUTEX_WAIT — whose no-timeout park is infinite (`u64::MAX`) and
/// only ever resumed by a FUTEX_WAKE waker (matching Linux block-until-woken) —
/// the futex2 `futex_wait`/`futex_waitv` are documented (and smoke-tested) to
/// park via a *bounded* yield and resume with 0, letting the caller's recheck
/// loop re-arm. Passing 0 here would map to an infinite deadline that the poll
/// routine's one-tick fallback re-parks forever (never resuming to user mode),
/// so a self-directed wait with no concurrent waker hangs. A finite cap makes
/// the park expire → resume 0 (POSIX-permitted spurious wake); a real waker
/// still fires promptly through the per-uaddr wait queue well before the cap.
const FUTEX2_PARK_CAP_NS: u64 = 50_000_000; // 50 ms

const SIG_BLOCK: u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

// ── Phase-2 signal gap-fills ────────────────────────────────────────
//
// Six more Linux signal-surface syscalls needed for relibc to bind
// directly: sigaltstack, rt_sigtimedwait, tkill, rt_sigsuspend,
// rt_sigpending. Each follows the same per-task BTreeMap storage
// shape as SIGNAL_PENDING / SIGNAL_MASK so the test reset hook
// drops all of it on `__test_signal_reset`.

/// Per-task alternate signal stack registration (Linux `stack_t`
/// shape: sp + flags + size). A signal whose handler has
/// `SA_ONSTACK` builds its sigframe on the alt stack instead of
/// the regular user RSP. `flags = SS_DISABLE (2)` means "no alt
/// stack active"; the entry stays in the table for round-trip
/// query semantics but no rewrite happens.
#[derive(Copy, Clone, Debug, Default)]
pub struct SigAltStack {
    pub sp: u64,
    pub flags: u32,
    pub size: u64,
}

/// `stack_t` flag bits Linux honours.
const SS_DISABLE: u32 = 2;
const SS_ONSTACK: u32 = 1;
/// Minimum altstack size — Linux MINSIGSTKSZ on x86_64 is 2048;
/// we honour the same lower bound.
const MIN_SIGSTKSZ: u64 = 2048;

static SIG_ALTSTACK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, SigAltStack>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn sigaltstack_table_init() {
    let mut g = SIG_ALTSTACK.lock();
    if g.is_none() {
        *g = Some(BTreeMap::new());
    }
}

/// Read the alternate signal stack for `task`. Returns the
/// registered slot or a zero-initialised `SigAltStack` with
/// `flags = SS_DISABLE` if the task never installed one.
pub fn sigaltstack_of(task: u64) -> SigAltStack {
    let g = SIG_ALTSTACK.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(SigAltStack {
            sp: 0,
            flags: SS_DISABLE,
            size: 0,
        })
}

/// Atomically consume the LOWEST pending signal in `set` for `task`:
/// clear its bit under the `SIGNAL_PENDING` lock and return the signum,
/// or `None` when nothing in `set` is pending. The single-lock
/// check-and-clear is what makes two racing consumers (e.g. the
/// return-to-user delivery hook vs a re-executed `rt_sigtimedwait`)
/// unable to both take the same instance.
fn sigwait_consume(task: u64, set: u64) -> Option<u32> {
    let mut g = SIGNAL_PENDING.lock();
    let slot = g.as_mut()?.get_mut(&task)?;
    let candidates = *slot & set;
    if candidates == 0 {
        return None;
    }
    let signum = sig_from_bit(candidates);
    *slot &= !(sig_bit(signum));
    Some(signum)
}

// Function-pointer hook: arch trap dispatcher invokes this on
// every int-0x80 / syscall trap-return that's heading back to
// user mode, just before the asm tail iretq's. The arch passes
// the raw syscall number the user trapped on so SA_RESTART can
// consult the restartable-syscall table; a non-syscall caller
// (e.g. a future trap-after-IRQ delivery point) would pass
// `SYSCALL_NUM_NONE` and the restart path would short-circuit.
//
// Same shape as `install_address_space_lookup` so the trap path
// doesn't need a direct dep on this crate's signal internals.
pub type SignalDeliveryHook = fn(&mut dyn TrapContext, u32) -> bool;

static SIGNAL_DELIVERY_HOOK: narf_lib::sync::IrqSafeSpinLock<Option<SignalDeliveryHook>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Install the function the arch trap path calls on every
/// user-bound int-0x80 trap-return. `install_core_syscalls`
/// auto-installs `default_signal_delivery`.
pub fn install_signal_delivery_hook(hook: SignalDeliveryHook) {
    *SIGNAL_DELIVERY_HOOK.lock() = Some(hook);
}

/// Look up the currently-installed delivery hook, if any. The
/// arch trap dispatcher calls this on its way back to user.
pub fn signal_delivery_hook() -> Option<SignalDeliveryHook> {
    *SIGNAL_DELIVERY_HOOK.lock()
}

/// Sentinel passed by callers that aren't on a syscall trap path.
/// Today only int 0x80 invokes the hook, but the constant exists
/// so future call sites (e.g. on-IRQ delivery) can reach the hook
/// without faking a syscall number — `is_restartable_syscall`
/// short-circuits to `false` on this value.
pub const SYSCALL_NUM_NONE: u32 = u32::MAX;

/// Subset of syscalls that observe Linux's "automatic restart on
/// SA_RESTART" semantics. POSIX-2017 §2.4 lists the not-restartable
/// set (the timeout/sleep/wait family); everything outside that set
/// is restartable when SA_RESTART is set.
///
/// NARF round 1: most syscalls are non-blocking today, so the
/// "interrupted by signal" return only fires from the explicitly
/// blocking ones. Of those, the timeout family is NOT restarted;
/// the rest ARE.
///
/// Returns `true` if the named syscall is in the "auto-restart on
/// SA_RESTART" set. The check is keyed on `Syscall::from_raw` so a
/// versioned wire number (top byte = version) still resolves to the
/// canonical syscall.
fn is_restartable_syscall(raw: u32) -> bool {
    if raw == SYSCALL_NUM_NONE {
        return false;
    }
    // Strip the version byte (top 8 bits) — restartability is a
    // property of the canonical syscall, not its versioned variant.
    let canonical = crate::syscall::syscall_number(raw);
    let n = match crate::syscall::Syscall::from_raw(canonical) {
        Some(s) => s,
        None => return false,
    };
    // Linux: signal-targeted timeout variants (nanosleep,
    // clock_nanosleep, rt_sigtimedwait, rt_sigsuspend, poll/
    // epoll_wait with a timeout, ...) are NEVER auto-restarted
    // regardless of SA_RESTART. The kernel returns
    // ERESTART_RESTARTBLOCK / EINTR and the user sees the
    // abbreviated sleep. See arch/x86/kernel/signal.c
    // §handle_signal.
    !matches!(
        n,
        crate::syscall::Syscall::Sleep
            | crate::syscall::Syscall::Nanosleep
            | crate::syscall::Syscall::ClockNanosleep
            | crate::syscall::Syscall::RtSigtimedwait
            | crate::syscall::Syscall::RtSigsuspend
            | crate::syscall::Syscall::Poll
            | crate::syscall::Syscall::EpollWait
    )
}

/// Build the `SigDeliveryParams` for `(task, action, signum,
/// syscall_no)`. Consults the per-task altstack registry + the
/// restartable-syscall table so the arch `deliver_signal` impl
/// has every signal-delivery decision pre-computed.
// A siginfo carries several independent scalars (code/addr/value/pid) plus the
// delivery context; bundling them would just move the same fields behind a
// struct the two call sites fill inline.
#[allow(clippy::too_many_arguments)]
fn build_delivery_params(
    task: u64,
    action: SigAction,
    signum: u32,
    syscall_no: u32,
    si_code: i32,
    si_addr: u64,
    si_value: u64,
    si_pid: u32,
) -> SigDeliveryParams {
    // Altstack: only honour if SA_ONSTACK is set AND the slot is
    // installed AND it's not SS_DISABLE. A misconfigured altstack
    // (size below MIN_SIGSTKSZ) was already rejected at install
    // time by `sys_sigaltstack`.
    let altstack = sigaltstack_of(task);
    let altstack_valid = (action.flags & SA_ONSTACK) != 0
        && (altstack.flags & SS_DISABLE) == 0
        && altstack.sp != 0
        && altstack.size != 0;
    SigDeliveryParams {
        handler: action.handler,
        restorer: action.restorer,
        signum,
        flags: action.flags,
        altstack_sp: if altstack_valid { altstack.sp } else { 0 },
        altstack_size: if altstack_valid { altstack.size } else { 0 },
        restartable_syscall: is_restartable_syscall(syscall_no),
        si_code,
        si_addr,
        si_value,
        si_pid,
    }
}

/// Default delivery hook: pick the lowest pending unmasked
/// signal, look up its handler, ask the trap context to rewrite
/// itself to deliver. Fast path — when nothing's pending it
/// takes a single lock + a single bitmap read and returns.
///
/// `syscall_no` is the raw wire number of the syscall the trap
/// is returning from (or `SYSCALL_NUM_NONE` if the hook is being
/// driven from a non-syscall path). Consulted only for the
/// `SA_RESTART` decision.
///
/// SA flag handling:
/// - SA_NODEFER (0x4000_0000): if set, don't auto-block the
///   delivered signal during handler execution. Default Linux
///   behaviour adds the delivered signal to the mask for the
///   duration of the handler; SA_NODEFER opts out so the handler
///   can recursively re-enter on the same signal (used by stack
///   traces, dump-and-die handlers).
/// - SA_RESETHAND (0x8000_0000): clear the handler after delivery
///   so the next occurrence falls through to the default action.
/// - SA_ONSTACK / SA_SIGINFO / SA_RESTART: passed through to the
///   arch `deliver_signal` via the `SigDeliveryParams` so the
///   arch can lay out the frame on the altstack (SA_ONSTACK),
///   push the 3-arg siginfo_t+ucontext frame (SA_SIGINFO), and
///   rewind RIP for re-execution (SA_RESTART).
pub fn default_signal_delivery(ctx: &mut dyn TrapContext, syscall_no: u32) -> bool {
    // u64::MAX = no restriction: consider every deliverable signal. The
    // timer-IRQ preemptive path calls the restricted form with a narrower
    // mask (eager / fatal-unhandled only).
    default_signal_delivery_restricted(ctx, syscall_no, u64::MAX)
}

/// Body of `default_signal_delivery`, but only signals whose bit is set in
/// `restrict` are eligible. Picks the lowest eligible deliverable signal
/// (`pending & !mask & restrict`) and delivers it through the same handler
/// / default-action path.
pub(crate) fn default_signal_delivery_restricted(
    ctx: &mut dyn TrapContext,
    syscall_no: u32,
    restrict: u64,
) -> bool {
    if !ctx.returning_to_user() {
        return false;
    }
    let task = current_task_id();

    let pending = {
        let g = SIGNAL_PENDING.lock();
        match g.as_ref().and_then(|m| m.get(&task).copied()) {
            Some(p) if p != 0 => p,
            _ => return false,
        }
    };
    let mask = SIGNAL_MASK
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0);
    // `& !1`: bit 0 is the POSIX null signal and is NEVER deliverable. Send
    // paths already refuse to set it (kill/tkill/tgkill/sigqueue treat sig 0
    // as an existence probe), but mask it here too so a stray bit-0 raise can
    // never be taken as "signal 0" → default-action Terminate.
    // No null-signal bit in the N-1 convention (signal 0 has no bit),
    // so no `& !1` guard is needed — every set bit is a real signal.
    // Linux `do_sigtimedwait` `real_blocked` semantics: while this task is
    // parked in / re-executing `rt_sigtimedwait` (`sigwait_set` armed), signals
    // in the waited set belong to the WAITER — `sigwait_consume` dequeues them
    // on the re-execution — and must NOT be delivered to a handler here even
    // when they are unblocked. stress-ng --sigrt waits on RT signals it leaves
    // UNBLOCKED with nop handlers installed; without this reservation the nop
    // handler steals the graceful-shutdown `sigqueue(sival=0)` and the child
    // parks in `sigwaitinfo` forever (the --sigrt hang).
    // Both the live park routing (`sigwait_set`) AND the sticky reservation
    // (`sigwait_reserve`, armed by every rt_sigtimedwait and released at the
    // task's next non-sigwait park) — the latter covers the processing gap
    // BETWEEN consecutive sigtimedwaits, where the nop-handler sigreturn
    // chain would otherwise drain the waiter's queue (and eat stress-ng
    // --sigrt's shutdown marker).
    let sigwait_reserved = crate::user_task::current_user_task()
        .map(|u| {
            // SAFETY: in-flight task's poller-pinned UserTaskCtx; atomic load only.
            unsafe {
                (*u).sigwait_set.load(Ordering::Acquire)
                    | (*u).sigwait_reserve.load(Ordering::Acquire)
            }
        })
        .unwrap_or(0);
    let deliverable = pending & !mask & restrict & !sigwait_reserved;
    if deliverable == 0 {
        return false;
    }
    let signum = sig_from_bit(deliverable);
    #[cfg(feature = "linux-compat")]
    if crate::ptrace::ptrace_intercept_signal(ctx, signum) {
        return true;
    }

    let action = match sigaction_lookup_full(task, signum as usize) {
        Some(a) => a,
        None => {
            // No user handler installed → POSIX default action.
            // Clear the pending bit before applying the action so a
            // retry trap doesn't re-fire the same signal.
            if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
                if let Some(slot) = map.get_mut(&task) {
                    *slot &= !(sig_bit(signum));
                }
            }
            match default_signal_action(signum) {
                DefaultAction::Ignore => {
                    // Silently consumed (existing behaviour). Discard any
                    // queued RT payloads too — each queued ignored instance
                    // is "delivered" by being dropped (signal(7)).
                    purge_sigqueue(task, signum);
                }
                DefaultAction::Terminate => {
                    terminate_current_task(ctx, task, signum, false);
                    // unreachable when a UserTaskFuture is in flight.
                }
                DefaultAction::CoreDump => {
                    terminate_current_task(ctx, task, signum, true);
                    // unreachable when a UserTaskFuture is in flight.
                }
                DefaultAction::Stop => {
                    // Job control: actually stop the task (the pending bit
                    // was cleared above). enter_stopped records the stopped
                    // state, notifies the parent, and parks until SIGCONT.
                    enter_stopped(ctx, task, signum);
                    // No executor wired (kernel-test context): enter_stopped
                    // returns without parking — fall through and consume.
                }
                DefaultAction::Continue => {
                    // A SIGCONT with no handler. The actual resume of a
                    // stopped task happens eagerly in the raise path
                    // (signal_stopcont_interaction); here there is just
                    // nothing left to do — consume it.
                }
            }
            return true;
        }
    };
    // SIG_IGN (handler == 1) is NOT a real handler: silently consume the
    // pending signal instead of building a frame and "delivering" it. The old
    // code passed handler==1 straight to deliver_signal, which set the user
    // RIP to 1 and returned there → an immediate user fault. SIG_DFL (0) is
    // stored as `None`, so it never reaches here (the None arm above applies
    // the default action); a SIG_IGN slot is the only `handler <= 1` case.
    if action.handler <= 1 {
        if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
            if let Some(slot) = map.get_mut(&task) {
                *slot &= !(sig_bit(signum));
            }
        }
        // SIG_IGN consumes every queued RT instance with the bit.
        purge_sigqueue(task, signum);
        return true;
    }
    // Async signals: si_code = SI_USER (0), si_addr = 0 — unless this
    // instance was queued by rt_sigqueueinfo/sigqueue, in which case
    // honour its si_code (SI_QUEUE) + si_value (the sigval payload).
    let (si_code, si_value, si_pid) = take_sigqueue_info(task, signum).unwrap_or((0, 0, 0));
    let params = build_delivery_params(
        task, action, signum, syscall_no, si_code, 0, si_value, si_pid,
    );
    if !ctx.deliver_signal(&params) {
        return false;
    }
    // If this task is parked in rt_sigtimedwait, this handler-bound signal
    // (necessarily OUT of the sigwait set — in-set signals are blocked and
    // consumed by sigwait_consume, never delivered here) is interrupting
    // the wait. Mark it so the re-executed rt_sigtimedwait returns -EINTR
    // even though this delivery is about to clear the pending bit before
    // the re-execution can observe it. Without this a SIGALRM (stress-ng
    // --sigrt's timeout) is delivered but the syscall re-parks forever.
    if let Some(u) = crate::user_task::current_user_task() {
        // SAFETY: the in-flight task's poller-pinned UserTaskCtx; atomics only.
        unsafe {
            let sw = (*u).sigwait_set.load(Ordering::Acquire);
            if sw != 0 && (sw & sig_bit(signum)) == 0 {
                (*u).sigwait_interrupted.store(true, Ordering::Release);
            }
        }
    }
    // Remember whether this frame is the restorer-based Linux
    // rt_sigframe so `sys_sigreturn` resolves it from RSP.
    set_sigreturn_use_rsp(task, params.restorer != 0);
    // Record the frame layout we just built so sys_sigreturn restores from the
    // right offsets — must match deliver_signal's `want_siginfo || force_rt`
    // (SA_SIGINFO=0x4, see syscall.rs). Never re-derive the layout from user memory.
    set_sigreturn_is_rt(task, (params.flags & 0x4) != 0 || params.restorer != 0);
    // Clear only after the rewrite succeeded — a failed
    // delivery (e.g. arch returns false) should leave pending
    // alone so the next trap retries.
    if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
        if let Some(slot) = map.get_mut(&task) {
            *slot &= !(sig_bit(signum));
        }
    }
    // RT queueing: this delivery drained ONE queued instance (the take
    // above); if more remain, re-arm the bit so the next return-to-user
    // delivers the next instance with its own si_value.
    rearm_pending_if_queued(task, signum);
    // Save the pre-handler mask so `sys_sigreturn` restores it (POSIX),
    // undoing the auto-block below. Captured BEFORE the SA_NODEFER OR so the
    // restored value is the mask in effect when the handler was entered.
    // A pending `rt_sigsuspend` record takes precedence: the mask this
    // handler's sigreturn must restore is the PRE-SUSPEND mask, not the
    // temporary suspend mask the wait installed (Linux TIF_RESTORE_SIGMASK).
    {
        let cur = take_suspend_saved_mask(task).unwrap_or_else(|| {
            SIGNAL_MASK
                .lock()
                .as_ref()
                .and_then(|m| m.get(&task).copied())
                .unwrap_or(0)
        });
        set_sigreturn_saved_mask(task, cur);
    }
    // SA_NODEFER: skip the auto-block. Default: add the delivered
    // signal to the mask so the handler runs without re-entrancy.
    if (action.flags & SA_NODEFER) == 0 {
        if let Some(map) = SIGNAL_MASK.lock().as_mut() {
            let slot = map.entry(task).or_insert(0);
            *slot |= sig_bit(signum);
        }
    }
    // SA_RESETHAND: one-shot — clear the handler so the next
    // occurrence falls through to the default action. Cleared in the
    // (possibly shared) live sighand, per Linux thread-group semantics.
    if (action.flags & SA_RESETHAND) != 0 {
        let h = {
            let g = SIGACTION_TABLE.lock();
            g.as_ref().and_then(|m| m.get(&task).cloned())
        };
        if let Some(h) = h {
            h.lock()[signum as usize] = None;
        }
    }
    true
}

// ── Synchronous-signal delivery for CPU exceptions ────────────────
//
// Counterpart to the async hook above. The async path runs on
// every int-0x80 trap-return and consumes the per-task pending
// bitmap (the work `kill(2)` leaves behind). The synchronous path
// runs from `rust_trap_handler` for vectors 0..31 (CPU exceptions)
// when the trap came from user mode AND a sigaction handler is
// registered for the matching signal. It rewrites the trap frame
// to deliver the signal at user mode, mirroring the async hook's
// `deliver_signal` path so the frame layout the handler observes
// is identical.
//
// Strict gating on `frame.cs.RPL == 3` (caller's responsibility)
// keeps kernel-mode CPU exceptions on the existing probe-catch /
// panic path: probes are for kernel-issued recovery (test
// infrastructure), user-mode crashes are this new path. The two
// don't overlap.

/// POSIX signal numbers we map to. Stage-4 first cut: the
/// minimum set the synchronous-signal path can possibly raise.
/// The full table is `[1..=31]`, but only these can come from
/// CPU exceptions on x86_64 today.
const SIGILL: u32 = 4;
const SIGTRAP: u32 = 5;
const SIGBUS: u32 = 7;
const SIGFPE: u32 = 8;
const SIGSEGV: u32 = 11;

/// Map an x86_64 CPU-exception vector to the POSIX signal a
/// synchronous-delivery handler should observe. Returns `None`
/// for vectors that aren't user-recoverable through a signal
/// handler (the trap path falls back to its existing panic
/// surface for those).
///
/// References: AMD APM Vol 2 §8.2 (vector → exception map),
/// SUSv5 `<signal.h>` for the signal-number table.
pub fn vector_to_signum(vector: u64) -> Option<u32> {
    match vector {
        0 => Some(SIGFPE),   // #DE divide-by-zero / div overflow
        1 => Some(SIGTRAP),  // #DB debug / single step
        3 => Some(SIGTRAP),  // #BP breakpoint
        4 => Some(SIGFPE),   // #OF overflow
        6 => Some(SIGILL),   // #UD undefined opcode
        13 => Some(SIGSEGV), // #GP general protection
        14 => Some(SIGSEGV), // #PF page fault
        17 => Some(SIGBUS),  // #AC alignment check
        _ => None,
    }
}

/// Per-fault payload the arch trap path hands to the sync-signal
/// hook. Wave-58: `addr` is the faulting address (CR2 on x86_64
/// #PF, FAR_EL1 on aarch64 sync EL0 aborts). 0 for vectors that
/// don't have one (#UD/#DE/#OF/#BP — the hook substitutes RIP).
#[derive(Copy, Clone, Debug, Default)]
pub struct SyncFaultInfo {
    /// Faulting address (CR2 / FAR_EL1). 0 when N/A.
    pub addr: u64,
}

/// Function-pointer hook the arch trap dispatcher calls for
/// every CPU exception (vectors 0..31) that originated in user
/// mode. Returns `true` if the trap frame was rewritten to
/// deliver a signal — the trap dispatcher should then return
/// directly so `iretq` lands at the rewritten user RIP.
/// Returns `false` if no handler was installed (or the vector
/// has no signal mapping); the caller falls through to the
/// existing panic / probe-catch path.
type SyncSignalHook = fn(&mut dyn TrapContext, u64, SyncFaultInfo) -> bool;

static SYNC_SIGNAL_HOOK: narf_lib::sync::IrqSafeSpinLock<Option<SyncSignalHook>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Install the function the arch trap path calls on user-mode
/// CPU exceptions. `install_core_syscalls` auto-installs
/// `default_sync_signal_delivery`.
pub fn install_sync_signal_hook(hook: SyncSignalHook) {
    *SYNC_SIGNAL_HOOK.lock() = Some(hook);
}

/// Look up the currently-installed sync-signal hook, if any.
pub fn sync_signal_hook() -> Option<SyncSignalHook> {
    *SYNC_SIGNAL_HOOK.lock()
}

/// Default sync-signal hook: map vector → signum, look up the
/// calling task's handler, rewrite the trap frame.
///
/// Returns `false` (no rewrite) when:
///   - the vector has no signal mapping (e.g. #NMI)
///   - the arch's `deliver_signal` rejects the rewrite
///
/// Returns `true` when:
///   - a sigaction handler was installed and the frame was rewritten
///     to deliver it, OR
///   - no handler was installed and the POSIX default action for the
///     signal was Terminate / CoreDump — in which case the task is
///     retired through the same exit hook `sys_exit_task` uses, with
///     wstatus pre-staged so wait4 sees `WIFSIGNALED + WTERMSIG`.
///     The trap dispatcher must NOT fall through to its panic path.
///
/// SA_RESTART is intentionally a no-op on this path: a CPU
/// exception is not a syscall trap (`restartable_syscall =
/// false`), so the arch never rewinds RIP. SA_ONSTACK and
/// SA_SIGINFO are honoured the same way as the async path.
///
/// For SA_SIGINFO synchronous signals, the arch stamps an
/// architecture-specific `si_code` and the faulting address into
/// the user-visible `siginfo_t`. Mapping per
/// `arch/x86/include/uapi/asm/siginfo.h`:
///   #PF (vector 14) → SIGSEGV, si_code = SEGV_ACCERR (2) /
///                                 SEGV_MAPERR (1) depending on
///                                 PF error-code bit 0 (present).
///                                 si_addr = CR2.
///   #GP (13)        → SIGSEGV, si_code = SI_KERNEL (0x80),
///                                 si_addr = 0.
///   #UD (6)         → SIGILL,  si_code = ILL_ILLOPC (1),
///                                 si_addr = trapping RIP.
///   #AC (17)        → SIGBUS,  si_code = BUS_ADRALN (1),
///                                 si_addr = trapping RIP.
///   #DE/#OF         → SIGFPE,  si_code = FPE_INTDIV (1) for #DE,
///                                            FPE_INTOVF (2) for #OF,
///                                 si_addr = trapping RIP.
///   #BP (3)         → SIGTRAP, si_code = TRAP_BRKPT (1),
///                                 si_addr = trapping RIP.
pub fn default_sync_signal_delivery(
    ctx: &mut dyn TrapContext,
    vector: u64,
    info: SyncFaultInfo,
) -> bool {
    let signum = match vector_to_signum(vector) {
        Some(s) => s,
        None => return false,
    };
    #[cfg(feature = "linux-compat")]
    if crate::ptrace::ptrace_intercept_signal(ctx, signum) {
        return true;
    }
    let task = current_task_id();
    let action = match sigaction_lookup_full(task, signum as usize) {
        Some(a) => a,
        None => {
            // No user handler → POSIX default action. CPU exceptions
            // map to Terminate or CoreDump only; Ignore/Stop/Continue
            // never appear in this table. Anything that's neither is
            // a kernel bug — fall through to the panic surface.
            // Diagnostic: a fatal CPU fault with no user handler. Log the
            // cause vector + faulting VA alongside the terminate line so a
            // crash can be symbolized against the process's mmap layout —
            // RIP alone is ambiguous across the many shared libraries a
            // desktop app maps (kwin, Qt, Mesa, glibc/musl, ...).
            {
                use core::fmt::Write;
                let cause = match vector {
                    6 => "#UD",
                    13 => "#GP",
                    14 => "#PF",
                    17 => "#AC",
                    0 => "#DE",
                    _ => "fault",
                };
                let _ = writeln!(
                    narf_console::Writer,
                    "fatal-fault: task={} sig={} {} vec={} faultva={:x} rip={:x}",
                    task,
                    signum,
                    cause,
                    vector,
                    info.addr,
                    ctx.rip()
                );
                // Dump the GP register file — a faulting instruction's
                // operands (e.g. a corrupted heap/meta pointer in r13/r15)
                // pin whether the fault is a slightly-off pointer (adjacent
                // overwrite / stale TLB) or a wild value (deeper corruption).
                ctx.dump_gprs();
                // Dump plausible return addresses off the faulting stack so
                // the CALLER can be symbolized (a leaf like strlen faults with
                // [rsp] == its caller's return address). Print only words that
                // land in an executable window — the ld-musl interp bias
                // (0x4000_0000_0000) or the mmap DSO arena (0x4080_.. up).
                let rsp = ctx.user_rsp();
                for i in 0..32u64 {
                    let mut w = [0u8; 8];
                    // SAFETY: copy_from_user range-validates the source VA and
                    // SMAP-brackets the read; a bad slot just errors out.
                    if unsafe { copy_from_user(&mut w, rsp.wrapping_add(i * 8)) }.is_err() {
                        break;
                    }
                    let v = u64::from_le_bytes(w);
                    if (0x0000_4000_0000_0000..0x0000_7F00_0000_0000).contains(&v) {
                        let _ = writeln!(narf_console::Writer, "  stk[{}]={:x}", i, v);
                    }
                }
            }
            match default_signal_action(signum) {
                DefaultAction::Terminate => {
                    terminate_current_task(ctx, task, signum, false);
                    // Caller treats `true` as "we handled it, don't panic."
                    return true;
                }
                DefaultAction::CoreDump => {
                    terminate_current_task(ctx, task, signum, true);
                    return true;
                }
                _ => return false,
            }
        }
    };
    // Wave-58: arch trap forwards the faulting address (CR2 / FAR_EL1)
    // via `info.addr`. For #PF that becomes si_addr verbatim. For
    // RIP-flavoured vectors (#UD/#DE/#OF/#BP/#AC) the arch passes
    // RIP through the same field.
    let (si_code, si_addr) = match vector {
        1 => (2 /* TRAP_TRACE */, info.addr),
        14 => (2 /* SEGV_ACCERR */, info.addr),
        13 => (0x80 /* SI_KERNEL */, info.addr),
        6 => (1 /* ILL_ILLOPC */, info.addr),
        17 => (1 /* BUS_ADRALN */, info.addr),
        0 => (1 /* FPE_INTDIV */, info.addr),
        4 => (2 /* FPE_INTOVF */, info.addr),
        3 => (1 /* TRAP_BRKPT */, info.addr),
        // SI_KERNEL (0x80), not 0: a fault must keep a POSITIVE si_code so the
        // arch siginfo builder writes `si_addr` at the union offset 16 (a
        // non-positive code there means "user/queue-origin" → si_pid instead).
        _ => (0x80, info.addr),
    };
    // Synchronous: not a syscall trap, so restartable_syscall =
    // false (passed via SYSCALL_NUM_NONE to is_restartable_syscall).
    // Synchronous faults carry si_addr, not a sigqueue sigval.
    let params = build_delivery_params(
        task,
        action,
        signum,
        SYSCALL_NUM_NONE,
        si_code,
        si_addr,
        0,
        0,
    );
    let delivered = ctx.deliver_signal(&params);
    if delivered {
        set_sigreturn_use_rsp(task, params.restorer != 0);
        // Record the frame layout we just built so sys_sigreturn restores from the
        // right offsets — must match deliver_signal's `want_siginfo || force_rt`
        // (SA_SIGINFO=0x4, see syscall.rs). Never re-derive the layout from user memory.
        set_sigreturn_is_rt(task, (params.flags & 0x4) != 0 || params.restorer != 0);
        return true;
    }
    // The handler's signal frame couldn't be placed — `deliver_signal` only
    // fails here when the target user stack is unwritable, i.e. it overflowed
    // during delivery (classically a SIGSEGV handler that itself faults,
    // walking the stack down one rt_sigframe at a time). Linux's response is
    // `force_sigsegv`: reset the disposition to default and apply it. Returning
    // `false` would instead fall through to the kernel panic surface — taking
    // the whole system down for one runaway user task. Terminate the task so
    // the kernel survives.
    terminate_current_task(ctx, task, signum, false);
    true
}

// ── Sigaction — record a per-task handler vaddr ────────────────────
//
// Stage-4 round 2: the recorded handler is fired on the trap
// return path of any subsequent int-0x80 from the same task that
// observes a pending signal not blocked by SIGNAL_MASK. See
// `default_signal_delivery` above. Cross-task delivery happens
// when another task calls `Kill` to set a bit in this task's
// pending bitmap.

// Linux _NSIG = 64. The per-task handler array is indexed by signum
// directly (bit-N-=-signal-N, like SIGNAL_PENDING), so slot 0 is the
// never-deliverable null signal and 1..=63 are real signals — RT
// signals (musl SIGRTMIN=35..) included.
// _NSIG = 64 real signals; the handler array is indexed by signum
// directly (slot 0 = the never-delivered null signal), so it needs
// 65 slots to address signal 64.
const NSIG: usize = 65;

/// Linux `sa_flags` bits NARF honours.
pub const SA_NODEFER: u32 = 0x40_00_00_00;
pub const SA_RESTART: u32 = 0x10_00_00_00;
pub const SA_SIGINFO: u32 = 0x00_00_00_04;
pub const SA_ONSTACK: u32 = 0x08_00_00_00;
pub const SA_RESETHAND: u32 = 0x80_00_00_00;

/// Per-task per-signal action: (handler_vaddr, sa_flags). Stored
/// as a single struct so a single atomic write covers both fields.
#[derive(Copy, Clone, Debug, Default)]
pub struct SigAction {
    /// User vaddr of the handler. `None` slot ⇒ no handler installed.
    pub handler: u64,
    /// User vaddr of the restorer trampoline (for Linux ABI).
    pub restorer: u64,
    /// Linux `sa_flags` (SA_*).
    pub flags: u32,
}

/// A thread group's shared signal-handler table — Linux
/// `sighand_struct`. Held by `Arc` so CLONE_SIGHAND/CLONE_THREAD
/// children observe the LIVE table (a handler installed by any thread
/// is instantly visible to all siblings), while plain fork deep-copies.
pub type SigHand = alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<[Option<SigAction>; NSIG]>>;

fn new_sighand() -> SigHand {
    alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new([None; NSIG]))
}

static SIGACTION_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, SigHand>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Get (or create) `task`'s sighand reference. The `Arc` clone lets
/// callers operate on the table after the registry lock is released;
/// lock ordering is always SIGACTION_TABLE → inner sighand.
fn sighand_of(task: u64) -> Option<SigHand> {
    let mut g = SIGACTION_TABLE.lock();
    let map = g.as_mut()?;
    Some(map.entry(task).or_insert_with(new_sighand).clone())
}

/// Initialise the per-task sigaction registry. Boot calls this once
/// before any user task can issue `Syscall::Sigaction`.
pub fn sigaction_init() {
    *SIGACTION_TABLE.lock() = Some(BTreeMap::new());
}

/// fork(2) inheritance: DEEP-copy `parent`'s handler table to `child`
/// (a post-fork sigaction() in one process must not affect the other).
/// POSIX: handlers are inherited; pending signals are not.
pub fn sigaction_fork(parent: u64, child: u64) {
    let snapshot = {
        let g = SIGACTION_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&parent).cloned())
            .map(|h| *h.lock())
    };
    if let Some(v) = snapshot {
        let mut g = SIGACTION_TABLE.lock();
        if let Some(map) = g.as_mut() {
            map.insert(
                child,
                alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(v)),
            );
        }
    }
}

/// CLONE_SIGHAND / CLONE_THREAD inheritance: `child` SHARES `parent`'s
/// live handler table (Linux `sighand_struct` refcount semantics). A
/// handler installed by either is immediately visible to both — what
/// pthreads rely on (musl installs its setxid/cancel handlers once,
/// from one thread, for the whole group).
pub fn sigaction_share(parent: u64, child: u64) {
    let mut g = SIGACTION_TABLE.lock();
    if let Some(map) = g.as_mut() {
        let h = map.entry(parent).or_insert_with(new_sighand).clone();
        map.insert(child, h);
    }
}

/// execve(2) handler reset (POSIX §2.4.3): a successful exec resets every
/// CAUGHT signal (one with a real handler function) to SIG_DFL, because the
/// handler's code address belonged to the OLD image and is meaningless — often
/// unmapped — in the new one. Signals set to SIG_IGN stay ignored; SIG_DFL
/// (a `None` slot) stays default. The signal MASK and pending set are NOT
/// touched (POSIX preserves them across exec).
///
/// Without this, a child that inherited a handler across fork (e.g. busybox
/// `sh`'s SIGCHLD handler) and then exec'd a different binary would, on the
/// next delivery of that signal, jump to the stale handler vaddr — a wild
/// branch into whatever (if anything) is mapped there in the new image.
///
/// Also UNSHARES the table (fresh `Arc`), mirroring Linux's
/// `unshare_sighand` in execve: the post-exec image must not keep a
/// live handler table shared with pre-exec CLONE_SIGHAND siblings.
pub fn sigaction_exec_reset(task: u64) {
    let snapshot = {
        let g = SIGACTION_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).cloned())
            .map(|h| *h.lock())
    };
    if let Some(mut v) = snapshot {
        for slot in v.iter_mut() {
            // handler > 1 ⇒ a real caught handler (0 = SIG_DFL, 1 = SIG_IGN).
            if matches!(slot, Some(a) if a.handler > 1) {
                *slot = None;
            }
        }
        let mut g = SIGACTION_TABLE.lock();
        if let Some(map) = g.as_mut() {
            map.insert(
                task,
                alloc::sync::Arc::new(narf_lib::sync::IrqSafeSpinLock::new(v)),
            );
        }
    }
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_sigaction_reset() {
    *SIGACTION_TABLE.lock() = Some(BTreeMap::new());
}

/// Test hook: install a handler vaddr for `(task, signum)` directly,
/// through the same shared-sighand path a real `rt_sigaction` uses.
#[doc(hidden)]
pub fn __test_set_sigaction(task: u64, signum: usize, handler: u64) {
    if let Some(h) = sighand_of(task) {
        h.lock()[signum] = Some(SigAction {
            handler,
            restorer: 0,
            flags: 0,
        });
    }
}

/// Diagnostic: peek the recorded handler vaddr for `(task, signum)`.
/// Returns `None` if no handler is registered.
pub fn sigaction_lookup(task: u64, signum: usize) -> Option<u64> {
    sigaction_lookup_full(task, signum).map(|a| a.handler)
}

/// Diagnostic: peek the full `SigAction` for `(task, signum)` —
/// handler + flags. Used by the signal delivery path to know
/// whether to honour SA_ONSTACK / SA_SIGINFO / SA_NODEFER.
pub fn sigaction_lookup_full(task: u64, signum: usize) -> Option<SigAction> {
    if signum >= NSIG {
        return None;
    }
    let h = {
        let g = SIGACTION_TABLE.lock();
        g.as_ref()?.get(&task)?.clone()
    };
    let slot = h.lock()[signum];
    slot
}

// ── Sockets — POSIX shims over the SocketOp dispatcher ───────────
//
// Both POSIX-shaped syscalls (sys_socket / sys_bind / ...) and the
// future ZC ring opcodes call into `socket::SocketFile::dispatch_op`.
// Per the design doc: kernel surface stays small, libc translates
// POSIX sockaddr_* unions in/out, the dispatcher owns per-family
// state.

fn current_socket(fd: u32) -> Option<alloc::sync::Arc<crate::socket::SocketFile>> {
    let task = current_task_id();
    fd::with_table(task, |t| t.get(fd).cloned())
        .flatten()
        .and_then(|entry| {
            // Downcast Arc<dyn FileOps> → Arc<SocketFile>. Manual
            // because Arc downcast for trait objects isn't in core;
            // we identify a SocketFile by raw-pointer comparison
            // through a marker — but simpler: try downcast via
            // unsafe transmute is risky. Use a manual pattern: keep
            // a side table mapping fd → Arc<SocketFile>.
            let raw = alloc::sync::Arc::as_ptr(&entry.ops) as *const ();
            socket_arc_lookup(raw)
        })
}

/// Install the kernel-held admin authority returned by a successful stack
/// attach onto one of the calling task's route-netlink sockets.
///
/// This is deliberately an internal launcher/attach bridge, not a Linux
/// syscall: no raw capability representation crosses userspace, and fd lookup
/// is confined to the current task's table.
pub fn delegate_stack_admin_to_route_socket(
    fd: u32,
    reply: &narf_net::StackAttachReply,
) -> Result<(), crate::socket::SockError> {
    let task = current_task_id();
    let entry = fd::with_table(task, |table| table.get(fd).cloned())
        .flatten()
        .ok_or(crate::socket::SockError::BadFd)?;
    let socket = entry
        .ops
        .as_any()
        .and_then(|ops| ops.downcast_ref::<crate::socket::SocketFile>())
        .ok_or(crate::socket::SockError::BadFd)?;
    socket.delegate_netlink_admin(reply.admin.clone())
}

// Side table to enable Arc<dyn FileOps> -> Arc<SocketFile> recovery.
// `fd::FdEntry` stores Arc<dyn FileOps>; `dyn FileOps` is not
// `Any`, so a downcast isn't possible. Stage-1: register the
// concrete Arc when the socket is created; look it up by the same
// raw pointer the FdEntry holds.
// fd → SocketFile resolver. Holds a `Weak`, NOT a strong `Arc`: the SocketFile
// is kept alive by its fd-table entries (and, for a listener, the LISTENERS
// map), so the resolver entry must follow that liveness rather than pin it.
// A strong ref here made `sys_close` remove the entry to avoid a leak — which
// broke socketpair-across-fork (weston's helper launch): the parent's close
// deleted the entry while the child still held an fd to the same SocketFile.
// With a Weak, a surviving fd keeps the entry resolvable and the entry
// self-invalidates only when the final fd drops (pruned lazily on lookup).
static SOCKET_ARCS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<usize, alloc::sync::Weak<crate::socket::SocketFile>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn socket_arc_register(arc: &alloc::sync::Arc<crate::socket::SocketFile>) {
    let key = alloc::sync::Arc::as_ptr(arc) as usize;
    let mut g = SOCKET_ARCS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(key, alloc::sync::Arc::downgrade(arc));
}

fn socket_arc_lookup(raw: *const ()) -> Option<alloc::sync::Arc<crate::socket::SocketFile>> {
    let mut g = SOCKET_ARCS.lock();
    let map = g.as_mut()?;
    match map.get(&(raw as usize)) {
        Some(weak) => match weak.upgrade() {
            Some(arc) => Some(arc),
            None => {
                // Last fd dropped: the allocation may have been freed (or
                // reused). Prune the dead entry so the map can't grow without
                // bound and a reused address can't resolve to a stale socket.
                map.remove(&(raw as usize));
                None
            }
        },
        None => None,
    }
}

fn copy_user_addr(ptr: u64, len: u64) -> Option<crate::socket::SockAddr> {
    if ptr == 0 || !(2..=110).contains(&len) {
        return None;
    }
    // Copy the whole sockaddr struct into a kernel buffer under SMAP bracket,
    // then parse it — no raw volatile access after this point.
    let total = len as usize;
    let mut buf = alloc::vec![0u8; total];
    // SAFETY: ptr validated (non-null, reasonable length) above.
    unsafe { copy_from_user(&mut buf, ptr) }.ok()?;
    // Family is the first u16 (little-endian on x86_64).
    let family = u16::from_le_bytes([buf[0], buf[1]]);
    let body = buf[2..].to_vec();
    Some(crate::socket::SockAddr { family, body })
}

fn accept_common(ctx: &mut dyn TrapContext, flags: u32) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let _addr_out = args.arg1;
    let _addr_len_out = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Single-shot: pop pending if any, else WouldBlock-style yield
    // mirroring sys_futex. Caller (libc accept) loops.
    match sock.dispatch_op(crate::socket::SocketOp::Accept) {
        crate::socket::SocketOpResult::Accepted { socket, .. } => {
            // accept4 flag bits: SOCK_NONBLOCK marks the new endpoint
            // non-blocking; SOCK_CLOEXEC sets FD_CLOEXEC on the slot.
            let nonblock = flags & crate::fd::O_NONBLOCK != 0;
            if nonblock {
                socket.set_nonblock(true);
            }
            let fd_flags = if flags & crate::fd::O_CLOEXEC != 0 {
                crate::fd::FD_CLOEXEC
            } else {
                0
            };
            let status_flags = if nonblock { crate::fd::O_NONBLOCK } else { 0 };
            socket_arc_register(&socket);
            let task = current_task_id();
            let new_fd = match fd::with_table(task, |t| {
                t.open(crate::fd::FdEntry {
                    ops: socket,
                    offset: 0,
                    flags: fd_flags,
                    status_flags,
                })
            }) {
                Some(n) => n,
                None => {
                    ctx.set_return(fail);
                    return;
                }
            };
            ctx.set_return(SyscallReturn::ok(new_fd as u64));
        }
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            // No pending connection. A NON-blocking listen fd gets
            // -EAGAIN immediately; a BLOCKING one must truly block until
            // a peer connects — musl's `accept()` does NOT retry -EAGAIN
            // on a blocking fd, so returning it here would make every
            // real server fail its first accept (only a loopback client
            // that races in before the syscall wins). Block the same way
            // blocking console/pipe reads do: park ~1 ms and REWIND RIP
            // so the `syscall` instruction re-executes on resume (no
            // return value set), looping in-kernel until `Accepted`.
            let task = current_task_id();
            let listen_nonblock = fd::with_table(task, |t| {
                t.get(fd)
                    .map(|e| e.status_flags & crate::fd::O_NONBLOCK != 0)
            })
            .flatten()
            .unwrap_or(false);
            if listen_nonblock {
                ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN
                return;
            }
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                // Rewind past the 2-byte `syscall` instruction so the
                // resumed task re-issues accept; do NOT set a return value.
                let resume_rip = ctx.rip().wrapping_sub(2);
                ctx.set_rip(resume_rip);
                let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                // SAFETY: `uctx` is the live per-task UserTaskCtx from current_user_task();
                // we hold the only reference while setting the deadline and saving the
                // RIP-rewound CPU state into `uc.state` before the yield hook hands the
                // task to the executor.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    let uc = &*uctx;
                    uc.sleep_deadline_ns.store(deadline, Ordering::Release);
                    // Park on NET-I/O READINESS (the TCP stack `readiness::notify`s
                    // the listener when a connection becomes accept-ready, and a
                    // socket when data arrives) with the ~1ms deadline as a mere
                    // backstop. Without net_io_wait the park only re-polled every
                    // ~1ms off the timer wheel — and under own-stack cooperative
                    // scheduling with other busy tasks (redis bg threads) that
                    // wheel service is delayed enough that the connection/data
                    // sits ACK'd-but-unread past the client's deadline (net-smoke
                    // echo flake). Snapshot the readiness generation for the
                    // check→park lost-wake guard (park_should_block re-executes if
                    // it moved). Clear a stale `futex_uaddr` so this can't be
                    // mis-routed into the futex branch.
                    uc.futex_uaddr.store(0, Ordering::Release);
                    uc.net_io_wait.store(true, Ordering::Release);
                    uc.epoll_park_gen
                        .store(narf_net::readiness::generation(), Ordering::Release);
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
            // No executor (kernel-test context): surface EAGAIN.
            ctx.set_return(SyscallReturn::ok((-11i64) as u64));
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(fail),
    }
}

/// Parse a `msg_control` buffer for an `SOL_SOCKET` / `SCM_RIGHTS` cmsg and
/// resolve each passed int fd to its file object in the *sender's* fd table.
/// Returns an empty vec when there's no fd ancillary data.
fn parse_scm_rights_fds(
    ctrl_ptr: u64,
    ctrl_len: usize,
) -> alloc::vec::Vec<alloc::sync::Arc<dyn narf_filesystem::FileOps>> {
    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    // struct cmsghdr { u64 cmsg_len; i32 cmsg_level; i32 cmsg_type; } = 16 B.
    let mut out = alloc::vec::Vec::new();
    if ctrl_ptr == 0 || !(16..=MAX_USER_COPY).contains(&ctrl_len) {
        return out;
    }
    let mut ctrl = alloc::vec![0u8; ctrl_len];
    // SAFETY: ctrl sized to ctrl_len; copy_from_user range-validates + SMAP.
    if unsafe { copy_from_user(&mut ctrl, ctrl_ptr) }.is_err() {
        return out;
    }
    let task = current_task_id();
    // Walk cmsg records (8-byte aligned).
    let mut off = 0usize;
    while off + 16 <= ctrl_len {
        let cmsg_len = u64::from_le_bytes(ctrl[off..off + 8].try_into().unwrap()) as usize;
        let level = i32::from_le_bytes(ctrl[off + 8..off + 12].try_into().unwrap());
        let ctype = i32::from_le_bytes(ctrl[off + 12..off + 16].try_into().unwrap());
        if cmsg_len < 16 || off + cmsg_len > ctrl_len {
            break;
        }
        if level == SOL_SOCKET && ctype == SCM_RIGHTS {
            let nfds = (cmsg_len - 16) / 4;
            for i in 0..nfds {
                let fpos = off + 16 + i * 4;
                let fd = i32::from_le_bytes(ctrl[fpos..fpos + 4].try_into().unwrap());
                if fd < 0 {
                    continue;
                }
                if let Some(ops) =
                    fd::with_table(task, |t| t.get(fd as u32).map(|e| e.ops.clone())).flatten()
                {
                    out.push(ops);
                }
            }
        }
        // Advance to the next cmsg (CMSG_ALIGN to 8 bytes).
        off += (cmsg_len + 7) & !7;
    }
    out
}

/// Write an `SOL_SOCKET` / `SCM_CREDENTIALS` control message into
/// `msg_control` naming the KERNEL as the message sender
/// (`struct ucred { pid=0, uid=0, gid=0 }`). Required for netlink uevent
/// recvmsg: systemd's libudev sets `SO_PASSCRED` and rejects any uevent
/// whose recvmsg lacks credentials with uid 0. `msg_controllen` is set to
/// the bytes written, or 0 when the user control buffer is absent/too small.
fn install_netlink_creds(msg_ptr: u64) {
    const SOL_SOCKET: i32 = 1;
    const SCM_CREDENTIALS: i32 = 2;
    let ctrl_ptr = read_user_u64(msg_ptr + 32);
    let ctrl_len = read_user_u64(msg_ptr + 40) as usize;
    // cmsghdr(16) + struct ucred{pid,uid,gid}(12).
    let cmsg_len = 16 + 12usize;
    if ctrl_ptr == 0 || ctrl_len < cmsg_len {
        // SAFETY: 8-byte write to msg_controllen; copy_to_user range-checks + SMAP.
        let _ = unsafe { copy_to_user(msg_ptr + 40, &0u64.to_le_bytes()) };
        return;
    }
    let mut cmsg = alloc::vec![0u8; cmsg_len];
    cmsg[0..8].copy_from_slice(&(cmsg_len as u64).to_le_bytes());
    cmsg[8..12].copy_from_slice(&SOL_SOCKET.to_le_bytes());
    cmsg[12..16].copy_from_slice(&SCM_CREDENTIALS.to_le_bytes());
    // struct ucred { pid=0, uid=0, gid=0 } — bytes 16..28 already zero.
    // SAFETY: ctrl_ptr is the user msg_control buffer, len-checked above.
    let _ = unsafe { copy_to_user(ctrl_ptr, &cmsg) };
    // SAFETY: 8-byte write to msg_controllen at msg_ptr+40.
    let _ = unsafe { copy_to_user(msg_ptr + 40, &(cmsg_len as u64).to_le_bytes()) };
}

/// Install received AF_UNIX ancillary data into the calling task's
/// `msg_control` buffer: an `SCM_RIGHTS` control message (any passed fds,
/// each dup'd into a fresh fd in this task's table) and, when
/// `cred` is `Some` (SO_PASSCRED set), an `SCM_CREDENTIALS` control message
/// naming the message sender. Sets `msg_controllen` to the bytes written
/// (0 when there's no ancillary data or the user control buffer is absent).
fn install_recv_ancillary(
    msg_ptr: u64,
    fds: alloc::vec::Vec<alloc::sync::Arc<dyn narf_filesystem::FileOps>>,
    cred: Option<crate::socket::Ucred>,
) {
    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    const SCM_CREDENTIALS: i32 = 2;
    let ctrl_ptr = read_user_u64(msg_ptr + 32);
    let ctrl_len = read_user_u64(msg_ptr + 40) as usize;
    if fds.is_empty() && cred.is_none() {
        // No ancillary data — report an empty control buffer.
        // SAFETY: writing 8 bytes to the `msg_controllen` field at `msg_ptr + 40`;
        // `copy_to_user` range-validates the user address and SMAP-brackets the
        // write, so a bad pointer returns Err rather than faulting the kernel.
        let _ = unsafe { copy_to_user(msg_ptr + 40, &0u64.to_le_bytes()) };
        return;
    }
    // Install each received file object at a fresh fd (SCM_RIGHTS semantics:
    // the fds are consumed even if the control buffer can't report them).
    let task = current_task_id();
    let mut new_fds: alloc::vec::Vec<i32> = alloc::vec::Vec::new();
    for ops in fds {
        let entry = fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: 0,
        };
        if let Some(newfd) = fd::with_table(task, |t| t.open(entry)) {
            new_fds.push(newfd as i32);
        }
    }
    // Build the control buffer: each cmsg is cmsghdr(16) + data, padded to
    // an 8-byte (CMSG_ALIGN) boundary before the next record.
    let mut ctrl: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let push_cmsg = |ctrl: &mut alloc::vec::Vec<u8>, ctype: i32, data: &[u8]| {
        let cmsg_len = 16 + data.len();
        let mut hdr = [0u8; 16];
        hdr[0..8].copy_from_slice(&(cmsg_len as u64).to_le_bytes());
        hdr[8..12].copy_from_slice(&SOL_SOCKET.to_le_bytes());
        hdr[12..16].copy_from_slice(&ctype.to_le_bytes());
        ctrl.extend_from_slice(&hdr);
        ctrl.extend_from_slice(data);
        // CMSG_ALIGN the running length to the next 8-byte boundary.
        while ctrl.len() % 8 != 0 {
            ctrl.push(0);
        }
    };
    if !new_fds.is_empty() {
        let mut data = alloc::vec::Vec::with_capacity(new_fds.len() * 4);
        for &nfd in &new_fds {
            data.extend_from_slice(&nfd.to_le_bytes());
        }
        push_cmsg(&mut ctrl, SCM_RIGHTS, &data);
    }
    if let Some(c) = cred {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(&c.pid.to_le_bytes());
        data[4..8].copy_from_slice(&c.uid.to_le_bytes());
        data[8..12].copy_from_slice(&c.gid.to_le_bytes());
        push_cmsg(&mut ctrl, SCM_CREDENTIALS, &data);
    }
    if ctrl_ptr == 0 || ctrl_len < ctrl.len() {
        // No room for the control data — any fds are still installed but the
        // numbers can't be reported (Linux would set MSG_CTRUNC here).
        // SAFETY: 8-byte write to `msg_controllen` at `msg_ptr + 40`.
        let _ = unsafe { copy_to_user(msg_ptr + 40, &0u64.to_le_bytes()) };
        return;
    }
    // SAFETY: ctrl_ptr is the user msg_control buffer, len-checked above.
    let _ = unsafe { copy_to_user(ctrl_ptr, &ctrl) };
    // SAFETY: 8-byte write to `msg_controllen` at `msg_ptr + 40`.
    let _ = unsafe { copy_to_user(msg_ptr + 40, &(ctrl.len() as u64).to_le_bytes()) };
}

#[inline]
fn read_user_u32(ptr: u64) -> u32 {
    let mut b = [0u8; 4];
    // SAFETY: caller guarantees ptr is a valid user address; SMAP bracket
    // guards the access.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { copy_from_user(&mut b, ptr) };
    u32::from_ne_bytes(b)
}

#[inline]
fn read_user_u64(ptr: u64) -> u64 {
    let mut b = [0u8; 8];
    // SAFETY: same contract as read_user_u32.
    let _ = unsafe { copy_from_user(&mut b, ptr) };
    u64::from_ne_bytes(b)
}

/// Write a u64 to a user address (helper for `copy_file_range`'s
/// `loff_t *off_in` / `*off_out` write-back, etc.)
#[inline]
fn write_user_u64(ptr: u64, val: u64) {
    let b = val.to_ne_bytes();
    // SAFETY: caller range-validated `ptr` for 8 bytes; copy_to_user
    // re-checks and SMAP-brackets the write.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { copy_to_user(ptr, &b) };
}

/// Write a u32 to a user address (helper for getsockopt length field, etc.)
#[inline]
fn write_user_u32(ptr: u64, val: u32) {
    let b = val.to_ne_bytes();
    // SAFETY: caller guarantees ptr is a valid user address; SMAP bracket
    // guards the access.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { copy_to_user(ptr, &b) };
}

/// Write a u16 to a user address.
#[inline]
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn write_user_u16(ptr: u64, val: u16) {
    let b = val.to_le_bytes();
    // SAFETY: caller guarantees `ptr` is a valid user address; copy_to_user
    // range-validates it and SMAP-brackets the 2-byte write.
    // SAFETY: Valid memory or trusted environment
    let _ = unsafe { copy_to_user(ptr, &b) };
}

// ── flock(2) — advisory file locking ────────────────────────────
//
// Per-file lock state keyed by the FdEntry's Arc<dyn FileOps>
// raw pointer (so dup'd fds share a lock; distinct files get
// distinct locks). Stage-1: shared (LOCK_SH = N readers) /
// exclusive (LOCK_EX = single writer) / unlock (LOCK_UN). Lock
// owner tracking lets a future LOCK_EX acquire detect "this
// task already holds an exclusive lock" and return success.

const LOCK_SH: u32 = 1;
const LOCK_EX: u32 = 2;
const LOCK_NB: u32 = 4;
const LOCK_UN: u32 = 8;

#[derive(Default, Debug)]
struct FlockEntry {
    /// Number of shared (read) holders. > 0 means SH-locked.
    shared_count: u32,
    /// Task id holding an exclusive lock; 0 means no exclusive.
    exclusive_owner: u64,
}

static FLOCK_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<usize, FlockEntry>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn flock_try(file_ptr: usize, op: u32, task: u64) -> Result<(), ()> {
    let mut g = FLOCK_TABLE.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    let e = map.entry(file_ptr).or_default();
    if op & LOCK_UN != 0 {
        if e.exclusive_owner == task {
            e.exclusive_owner = 0;
        } else if e.shared_count > 0 {
            e.shared_count -= 1;
        }
        return Ok(());
    }
    if op & LOCK_EX != 0 {
        // Exclusive: succeed iff no shared, no other exclusive.
        if e.exclusive_owner == task {
            return Ok(());
        }
        if e.shared_count == 0 && e.exclusive_owner == 0 {
            e.exclusive_owner = task;
            return Ok(());
        }
        return Err(());
    }
    if op & LOCK_SH != 0 {
        // Shared: succeed iff no exclusive (or we hold it).
        if e.exclusive_owner == 0 || e.exclusive_owner == task {
            e.shared_count += 1;
            return Ok(());
        }
        return Err(());
    }
    Err(())
}

// ── Terminal attributes (termios) ───────────────────────────────
//
// Per-task kernel-side termios store. tcgetattr/tcsetattr round
// trip through this so consumers (libreadline, password prompts,
// Rust's Stdin::lock) see the values they wrote. The console
// driver consults the same storage to decide whether to deliver
// ^C as SIGINT (ISIG bit), echo input (ECHO bit), buffer until
// newline (ICANON bit).
//
// The c_lflag bits that matter here:
const ICANON: u32 = 0x0002;
const ECHO_FLAG: u32 = 0x0008;
const ISIG: u32 = 0x0001;

/// Wire-stable termios image. 60 bytes — matches glibc's shape on
/// x86_64 (4*tcflag + 1 line-disc + 32 cc + 2 speed).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KTermios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub _pad: [u8; 3],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl KTermios {
    pub const fn cooked() -> Self {
        Self {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0x0080, // CREAD
            c_lflag: ICANON | ECHO_FLAG | ISIG,
            c_line: 0,
            c_cc: [0; 32],
            _pad: [0; 3],
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }
}

static TASK_TERMIOS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<u64, KTermios>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn termios_of_task(task: u64) -> KTermios {
    let g = TASK_TERMIOS.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(KTermios::cooked())
}

pub fn set_termios_of_task(task: u64, t: KTermios) {
    let mut g = TASK_TERMIOS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(task, t);
}

/// Most recent task to read from the console. Tracked so the
/// console driver knows which task to deliver SIGINT to when ^C
/// is read. Updated on each console read.
static FOREGROUND_TASK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn note_console_reader(task: u64) {
    FOREGROUND_TASK.store(task, Ordering::Release);
}

pub fn foreground_task() -> u64 {
    FOREGROUND_TASK.load(Ordering::Acquire)
}

/// Console line-discipline hook: invoked by `console_tty` when ISIG is
/// set on the console termios and an input byte matches a signal-
/// generating control char. ^C → SIGINT (2), ^\ → SIGQUIT (3),
/// ^Z → SIGTSTP (20). The signal goes to the entire FOREGROUND PROCESS
/// GROUP (proper job control), which is the group of the task currently
/// reading the console. Returns true iff the byte was consumed as a
/// signal (so it is NOT returned through read).
///
/// ISIG gating + c_cc matching already happened in `console_tty`; this
/// only maps the byte to a signal and fans it out to the pgrp. The
/// trap-return signal-delivery hook takes it on each member's next
/// return to user mode.
pub fn maybe_deliver_signal_for_input(byte: u8) -> bool {
    let signum = match byte {
        0x03 => 2,  // SIGINT  (^C)
        0x1C => 3,  // SIGQUIT (^\)
        0x1A => 20, // SIGTSTP (^Z)
        _ => return false,
    };
    let task = foreground_task();
    if task == 0 {
        return false;
    }
    let pgrp = read_pgid(task);
    if deliver_signal_to_pgrp(pgrp, signum) {
        return true;
    }
    // Fallback: no pgrp members resolved — deliver to the reader itself.
    raise_signal_pending(task, signum);
    true
}

// ── I/O multiplexing — poll / epoll / eventfd / timerfd / signalfd ──

const EPOLL_CTL_ADD: u32 = 1;
const EPOLL_CTL_DEL: u32 = 2;
const EPOLL_CTL_MOD: u32 = 3;

// EpollFile recovery from FdEntry — same shape as the SocketFile
// side table since Arc<dyn FileOps> can't be downcast generically.
static EPOLL_ARCS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<usize, alloc::sync::Arc<crate::io_mux::EpollFile>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn epoll_arc_register(arc: &alloc::sync::Arc<crate::io_mux::EpollFile>) {
    let key = alloc::sync::Arc::as_ptr(arc) as usize;
    let mut g = EPOLL_ARCS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(key, arc.clone());
}

fn epoll_arc_from_fd(task: u64, fd: u32) -> Option<alloc::sync::Arc<crate::io_mux::EpollFile>> {
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let g = EPOLL_ARCS.lock();
    g.as_ref()?.get(&raw).cloned()
}

// Wave-61: pidfd_open(pid, flags) → fd that signals POLLIN on exit.
// Linux x86_64 number 434. flags is currently ignored — PIDFD_NONBLOCK
// (0x0800) is the only documented bit and our pidfd reads return
// immediately anyway.

// Wave-64: `timerfd_gettime(fd, &curr_value)` — snapshot the
// currently-armed timer. Writes `itimerspec` (16 B interval +
// 16 B value-remaining; absolute time stripped because the read
// view is the relative gap from `now` to the next fire). Returns
// 0 on success or -1 on a bad fd / NULL out ptr.
//
// Linux ref: `fs/timerfd.c`:SYSCALL_DEFINE2(timerfd_gettime, …)
// (GPL-2.0-or-later, kernel.org).

static TIMERFD_ARCS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<usize, alloc::sync::Arc<crate::io_mux::TimerFd>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn timerfd_arc_register(arc: &alloc::sync::Arc<crate::io_mux::TimerFd>) {
    let key = alloc::sync::Arc::as_ptr(arc) as usize;
    let mut g = TIMERFD_ARCS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(key, arc.clone());
}

fn timerfd_arc_from_fd(task: u64, fd: u32) -> Option<alloc::sync::Arc<crate::io_mux::TimerFd>> {
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let g = TIMERFD_ARCS.lock();
    g.as_ref()?.get(&raw).cloned()
}

// ── Wave-70 SignalFdFile side table ────────────────────────────────
// Same shape as the EpollFile / SocketFile / TimerFd Arc maps: a raw-
// pointer-keyed Arc map lets us recover the concrete type from the
// `dyn FileOps` we stored in the fd table.
#[cfg(feature = "linux-compat")]
static SIGNALFD_ARCS: narf_lib::sync::IrqSafeSpinLock<
    Option<
        alloc::collections::BTreeMap<usize, alloc::sync::Arc<crate::linux_compat::SignalFdFile>>,
    >,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

#[cfg(feature = "linux-compat")]
fn signalfd_arc_register(arc: &alloc::sync::Arc<crate::linux_compat::SignalFdFile>) {
    let key = alloc::sync::Arc::as_ptr(arc) as usize;
    let mut g = SIGNALFD_ARCS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(key, arc.clone());
}

#[cfg(feature = "linux-compat")]
pub(crate) fn signalfd_arc_from_fd(
    task: u64,
    fd: u32,
) -> Option<alloc::sync::Arc<crate::linux_compat::SignalFdFile>> {
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()?;
    let raw = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let g = SIGNALFD_ARCS.lock();
    g.as_ref()?.get(&raw).cloned()
}

// ── Installer ──────────────────────────────────────────────────────

/// Bridge fn boot installs into `narf_abi::install_file_op_bridge`.
/// Routes ring-submitted file ops through the same `SyscallTable`
/// the int-0x80 / svc gate uses. The `cx` cancel context is the
/// per-inflight token the dispatcher hands us — we check it before
/// dispatching the (synchronous) syscall body so a parallel
/// `OpCode::Cancel` lands cleanly.
pub fn abi_file_op_bridge(
    kind: narf_abi::FileOpKind,
    args: &narf_abi::FileOpArgs,
    cx: &narf_abi::CancelCtx<'_>,
) -> narf_abi::FileOpReturn {
    if cx.is_cancel_requested() {
        // Signal Cancelled to the dispatcher (status=2 mirrors
        // NarfStatus::Cancelled). The dispatcher converts to
        // Cancelled / CancelRequested based on CANCELLABLE.
        return narf_abi::FileOpReturn {
            status: 2,
            value: 0,
        };
    }
    let num: u32 = match kind {
        narf_abi::FileOpKind::Open => Syscall::OpenFile.raw(),
        narf_abi::FileOpKind::Read => Syscall::Read.raw(),
        narf_abi::FileOpKind::Write => Syscall::Write.raw(),
        narf_abi::FileOpKind::Close => Syscall::Close.raw(),
        narf_abi::FileOpKind::Mmap => Syscall::Mmap.raw(),
        narf_abi::FileOpKind::Munmap => Syscall::Munmap.raw(),
    };
    let sargs = crate::SyscallArgs {
        arg0: args.a0,
        arg1: args.a1,
        arg2: args.a2,
        arg3: args.a3,
        arg4: args.a4,
        arg5: args.a5,
    };
    // Plain entry only fires plain handlers; our file ops are
    // raw. Build a synthetic `TrapContext` whose
    // `redirect_to_kernel` returns false (so handlers that would
    // unwind fall back to `set_return`), then route through
    // `kernel_syscall_entry`.
    struct BridgeCtx {
        args: crate::SyscallArgs,
        ret: crate::SyscallReturn,
    }
    impl crate::TrapContext for BridgeCtx {
        fn args(&self) -> &crate::SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: crate::SyscallReturn) {
            self.ret = r;
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
    }
    let mut ctx = BridgeCtx {
        args: sargs,
        ret: crate::SyscallReturn::invalid_op(),
    };
    crate::kernel_syscall_entry(num, &mut ctx);
    narf_abi::FileOpReturn {
        status: ctx.ret.status as u32,
        value: ctx.ret.value,
    }
}

// ── Dispatcher spawn helper ────────────────────────────────────────
//
// After Bootstrap mints the ring pair, the kernel-side ends sit in
// the per-task table waiting for somebody to drive them. The boot
// path (or a test fixture) calls `spawn_dispatcher_for(task_id)` to
// transfer ownership of the kernel ends to a freshly-spawned async
// task running `Dispatcher::run`. Returns the dispatcher's
// scheduler `TaskId`, or `None` if Bootstrap hasn't run for `task_id`
// (or its kernel ends were already taken).

/// Spawn an `abi::Dispatcher` task to drive the ring pair Bootstrap
/// minted for `task_id`. Returns the scheduler TaskId of the new
/// dispatcher task, or `None` if there's nothing to drive.
pub fn spawn_dispatcher_for(task_id: u64) -> Option<narf_scheduler::TaskId> {
    let ends = take_kernel_ends(task_id)?;
    Some(narf_scheduler::spawn(async move {
        let mut d = narf_abi::Dispatcher::new(ends.sq_drain, ends.cq_prod);
        d.run().await;
    }))
}

// ── Loadable kernel modules ─────────────────────────────────────────
//
// `init_module(2)` and `finit_module(2)` take an in-memory image of
// a relocatable ELF and link it into the running kernel via the
// `narf-modules` crate. `delete_module(2)` removes a loaded module
// by name. All three accept user pointers; we copy the image into
// kernel space before parsing so the user can't race the parser.

/// Map a module-loader outcome to a Linux return value. A foreign
/// image (a real Linux `.ko`, or anything lacking NARF's module
/// contract) becomes a success no-op: NARF is monolithic, so the
/// drivers `modprobe`/`systemd-modules-load` ask for are already
/// built in or genuinely absent — Linux answers builtin loads with
/// `EEXIST`, which modprobe treats as success. Returning 0 lets those
/// oneshot units complete instead of failing (and blocking dependents
/// past the systemd job timeout). Genuine NARF-module failures and
/// argument errors keep their real errno.
fn init_module_result(
    r: Result<alloc::sync::Arc<narf_modules::Module>, narf_modules::syscalls::ModuleSyscallError>,
) -> u64 {
    match r {
        Ok(_) => 0,
        Err(e) if e.is_foreign_image() => 0,
        Err(e) => (e.to_errno() as i64) as u64,
    }
}

/// Drop the core set of handlers into `table`. Idempotent — later
/// subsystems can install richer handlers over the same slots
/// (e.g. a real file-descriptor-backed `Read`).
pub fn install_core_syscalls(table: &mut SyscallTable) {
    table.install_raw(Syscall::Bootstrap, "bootstrap", RawFnHandler(sys_bootstrap));
    table.install_raw(Syscall::OpenFile, "open", RawFnHandler(sys_open));
    table.install_raw(Syscall::Write, "write", RawFnHandler(sys_write));
    table.install_raw(Syscall::Writev, "writev", RawFnHandler(sys_writev));
    table.install_raw(Syscall::Read, "read", RawFnHandler(sys_read));
    table.install_raw(Syscall::Close, "close", RawFnHandler(sys_close));
    table.install_raw(Syscall::Stat, "stat", RawFnHandler(sys_stat));
    table.install_raw(Syscall::Fstat, "fstat", RawFnHandler(sys_fstat));
    table.install_raw(Syscall::Lstat, "lstat", RawFnHandler(sys_stat));
    table.install_raw(
        Syscall::Newfstatat,
        "newfstatat",
        RawFnHandler(sys_newfstatat),
    );
    table.install_raw(Syscall::Mmap, "mmap", RawFnHandler(sys_mmap));
    table.install_raw(Syscall::Munmap, "munmap", RawFnHandler(sys_munmap));
    table.install_raw(Syscall::Mremap, "mremap", RawFnHandler(sys_mremap));
    table.install_raw(Syscall::Sendfile, "sendfile", RawFnHandler(sys_sendfile));
    table.install_raw(Syscall::MProtect, "mprotect", RawFnHandler(sys_mprotect));
    table.install_raw(Syscall::MLock, "mlock", RawFnHandler(sys_mlock));
    table.install_raw(Syscall::MUnlock, "munlock", RawFnHandler(sys_munlock));
    #[cfg(feature = "linux-compat")]
    table.install_raw(Syscall::Madvise, "madvise", RawFnHandler(sys_madvise));
    // Batch 18: AS-wide locking, secret memory, NUMA placement.
    table.install_raw(Syscall::Mlockall, "mlockall", RawFnHandler(sys_mlockall));
    table.install_raw(
        Syscall::Munlockall,
        "munlockall",
        RawFnHandler(sys_munlockall),
    );
    table.install_raw(
        Syscall::MemfdSecret,
        "memfd_secret",
        RawFnHandler(sys_memfd_secret),
    );
    table.install_raw(
        Syscall::ProcessMadvise,
        "process_madvise",
        RawFnHandler(sys_process_madvise),
    );
    table.install_raw(
        Syscall::MovePages,
        "move_pages",
        RawFnHandler(sys_move_pages),
    );
    table.install_raw(
        Syscall::SetMempolicyHomeNode,
        "set_mempolicy_home_node",
        RawFnHandler(sys_set_mempolicy_home_node),
    );
    table.install_raw(
        Syscall::MigratePages,
        "migrate_pages",
        RawFnHandler(sys_migrate_pages),
    );
    table.install_raw(Syscall::Execve, "execve", RawFnHandler(sys_execve));
    // Batch 19: process & scheduling.
    table.install_raw(Syscall::Vfork, "vfork", RawFnHandler(sys_fork));
    table.install_raw(Syscall::Execveat, "execveat", RawFnHandler(sys_execveat));
    table.install_raw(Syscall::Rseq, "rseq", RawFnHandler(sys_rseq));
    table.install_raw(
        Syscall::Faccessat2,
        "faccessat2",
        RawFnHandler(sys_at2_reshape),
    );
    table.install_raw(
        Syscall::Fchmodat2,
        "fchmodat2",
        RawFnHandler(sys_at2_reshape),
    );
    table.install_raw(
        Syscall::FutexWaitv,
        "futex_waitv",
        RawFnHandler(sys_futex_waitv),
    );
    table.install_raw(
        Syscall::FutexWake,
        "futex_wake",
        RawFnHandler(sys_futex_wake),
    );
    table.install_raw(
        Syscall::FutexWait,
        "futex_wait",
        RawFnHandler(sys_futex_wait),
    );
    table.install_raw(
        Syscall::FutexRequeue,
        "futex_requeue",
        RawFnHandler(sys_futex_requeue),
    );
    table.install_raw(Syscall::Wait4, "wait4", RawFnHandler(sys_wait4));
    table.install_raw(Syscall::Waitid, "waitid", RawFnHandler(sys_waitid));
    table.install_raw(Syscall::Mount, "mount", RawFnHandler(sys_mount));
    table.install_raw(Syscall::Umount2, "umount2", RawFnHandler(sys_umount2));
    table.install_raw(Syscall::Statfs, "statfs", RawFnHandler(sys_statfs));
    table.install_raw(Syscall::Fstatfs, "fstatfs", RawFnHandler(sys_fstatfs));
    table.install_raw(Syscall::Unshare, "unshare", RawFnHandler(sys_unshare));
    table.install_raw(Syscall::Setns, "setns", RawFnHandler(sys_setns));
    #[cfg(feature = "linux-compat")]
    table.install_raw(Syscall::Chroot, "chroot", RawFnHandler(sys_chroot));
    #[cfg(all(feature = "linux-compat", feature = "container"))]
    table.install_raw(
        Syscall::PivotRoot,
        "pivot_root",
        RawFnHandler(sys_pivot_root),
    );
    table.install_raw(Syscall::Sigreturn, "sigreturn", RawFnHandler(sys_sigreturn));
    table.install_raw(Syscall::SocketOpen, "socket", RawFnHandler(sys_socket));
    table.install_raw(Syscall::SocketBind, "bind", RawFnHandler(sys_socket_bind));
    table.install_raw(
        Syscall::SocketListen,
        "listen",
        RawFnHandler(sys_socket_listen),
    );
    table.install_raw(
        Syscall::SocketAccept,
        "accept",
        RawFnHandler(sys_socket_accept),
    );
    table.install_raw(
        Syscall::SocketAccept4,
        "accept4",
        RawFnHandler(sys_socket_accept4),
    );
    table.install_raw(
        Syscall::SocketPair,
        "socketpair",
        RawFnHandler(sys_socketpair),
    );
    table.install_raw(
        Syscall::SocketConnect,
        "connect",
        RawFnHandler(sys_socket_connect),
    );
    table.install_raw(Syscall::SocketSend, "send", RawFnHandler(sys_socket_send));
    table.install_raw(Syscall::SocketRecv, "recv", RawFnHandler(sys_socket_recv));
    table.install_raw(
        Syscall::SocketShutdown,
        "shutdown",
        RawFnHandler(sys_socket_shutdown),
    );
    table.install_raw(
        Syscall::SocketGetSockOpt,
        "getsockopt",
        RawFnHandler(sys_socket_getsockopt),
    );
    table.install_raw(
        Syscall::SocketSetSockOpt,
        "setsockopt",
        RawFnHandler(sys_socket_setsockopt),
    );
    table.install_raw(
        Syscall::SocketGetSockName,
        "getsockname",
        RawFnHandler(sys_socket_getsockname),
    );
    table.install_raw(
        Syscall::SocketGetPeerName,
        "getpeername",
        RawFnHandler(sys_socket_getpeername),
    );
    table.install_raw(
        Syscall::SocketSendMsg,
        "sendmsg",
        RawFnHandler(sys_socket_sendmsg),
    );
    table.install_raw(
        Syscall::SocketRecvMsg,
        "recvmsg",
        RawFnHandler(sys_socket_recvmsg),
    );
    table.install_raw(
        Syscall::SockRegisterBuf,
        "sock_register_buf",
        RawFnHandler(sys_sock_register_buf),
    );
    table.install_raw(
        Syscall::SockSendZc,
        "sock_send_zc",
        RawFnHandler(sys_sock_send_zc),
    );
    table.install_raw(Syscall::Poll, "poll", RawFnHandler(sys_poll));
    table.install_raw(
        Syscall::EpollCreate,
        "epoll_create",
        RawFnHandler(sys_epoll_create),
    );
    table.install_raw(Syscall::EpollCtl, "epoll_ctl", RawFnHandler(sys_epoll_ctl));
    table.install_raw(
        Syscall::EpollWait,
        "epoll_wait",
        RawFnHandler(sys_epoll_wait),
    );
    table.install_raw(Syscall::Eventfd, "eventfd", RawFnHandler(sys_eventfd));
    table.install_raw(
        Syscall::PidfdOpen,
        "pidfd_open",
        RawFnHandler(sys_pidfd_open),
    );
    table.install_raw(
        Syscall::TimerfdCreate,
        "timerfd_create",
        RawFnHandler(sys_timerfd_create),
    );
    table.install_raw(
        Syscall::TimerfdSettime,
        "timerfd_settime",
        RawFnHandler(sys_timerfd_settime),
    );
    #[cfg(feature = "linux-compat")]
    table.install_raw(
        Syscall::TimerfdGettime,
        "timerfd_gettime",
        RawFnHandler(sys_timerfd_gettime),
    );
    table.install_raw(Syscall::Signalfd, "signalfd", RawFnHandler(sys_signalfd));
    table.install_raw(Syscall::Tcgetattr, "tcgetattr", RawFnHandler(sys_tcgetattr));
    table.install_raw(Syscall::Tcsetattr, "tcsetattr", RawFnHandler(sys_tcsetattr));
    table.install_raw(Syscall::Flock, "flock", RawFnHandler(sys_flock));
    table.install_raw(
        Syscall::FbConnect,
        "fb_connect",
        RawFnHandler(sys_fb_connect),
    );
    table.install_raw(Syscall::FbInfo, "fb_info", RawFnHandler(sys_fb_info));
    table.install_raw(
        Syscall::FbRingMap,
        "fb_ring_map",
        RawFnHandler(sys_fb_ring_map),
    );
    table.install_raw(
        Syscall::FbFlushWait,
        "fb_flush_wait",
        RawFnHandler(sys_fb_flush_wait),
    );
    table.install_raw(
        Syscall::FbDisconnect,
        "fb_disconnect",
        RawFnHandler(sys_fb_disconnect),
    );
    table.install_raw(
        Syscall::ShmemCreate,
        "shmem_create",
        RawFnHandler(sys_shmem_create),
    );
    table.install_raw(Syscall::ShmemMap, "shmem_map", RawFnHandler(sys_shmem_map));
    table.install_raw(
        Syscall::ShmemDestroy,
        "shmem_destroy",
        RawFnHandler(sys_shmem_destroy),
    );
    table.install_raw(
        Syscall::FirmwareInstall,
        "firmware_install",
        RawFnHandler(sys_firmware_install),
    );
    table.install_raw(Syscall::RingKick, "ringkick", RawFnHandler(sys_ring_kick));
    table.install_raw(Syscall::GetPid, "getpid", RawFnHandler(sys_getpid));
    table.install_raw(Syscall::GetPpid, "getppid", RawFnHandler(sys_getppid));
    table.install_raw(Syscall::Gettid, "gettid", RawFnHandler(sys_gettid));
    table.install_raw(Syscall::Clone, "clone", RawFnHandler(sys_clone));
    table.install_raw(Syscall::Fork, "fork", RawFnHandler(sys_fork));
    #[cfg(feature = "linux-compat")]
    {
        table.install_raw(Syscall::Clone3, "clone3", RawFnHandler(sys_clone3));
        table.install_raw(
            Syscall::SetTidAddress,
            "set_tid_address",
            RawFnHandler(sys_set_tid_address),
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        table.install_raw(
            Syscall::ArchPrctl,
            "arch_prctl",
            RawFnHandler(sys_arch_prctl),
        );
    }
    table.install_raw(Syscall::GetUid, "getuid", RawFnHandler(sys_getuid));
    table.install_raw(Syscall::GetGid, "getgid", RawFnHandler(sys_getgid));
    table.install_raw(Syscall::SetUid, "setuid", RawFnHandler(sys_setuid));
    table.install_raw(Syscall::SetGid, "setgid", RawFnHandler(sys_setgid));
    table.install_raw(Syscall::Getresuid, "getresuid", RawFnHandler(sys_getresuid));
    table.install_raw(Syscall::Setresuid, "setresuid", RawFnHandler(sys_setresuid));
    table.install_raw(Syscall::Getresgid, "getresgid", RawFnHandler(sys_getresgid));
    table.install_raw(Syscall::Setresgid, "setresgid", RawFnHandler(sys_setresgid));
    table.install_raw(Syscall::Getgroups, "getgroups", RawFnHandler(sys_getgroups));
    table.install_raw(Syscall::Setgroups, "setgroups", RawFnHandler(sys_setgroups));
    table.install_raw(Syscall::Getpgid, "getpgid", RawFnHandler(sys_getpgid));
    table.install_raw(Syscall::Setpgid, "setpgid", RawFnHandler(sys_setpgid));
    table.install_raw(Syscall::Getsid, "getsid", RawFnHandler(sys_getsid));
    table.install_raw(Syscall::Setsid, "setsid", RawFnHandler(sys_setsid));
    table.install_raw(Syscall::Vhangup, "vhangup", RawFnHandler(sys_vhangup));
    table.install_raw(
        Syscall::GetHostname,
        "gethostname",
        RawFnHandler(sys_gethostname),
    );
    table.install_raw(
        Syscall::SetHostname,
        "sethostname",
        RawFnHandler(sys_sethostname),
    );
    // POSIX uname(2) — always present. Reads the UTS struct only;
    // doesn't depend on per-task UTS-namespace infrastructure.
    table.install_raw(Syscall::Uname, "uname", RawFnHandler(sys_uname));
    table.install_raw(
        Syscall::Setdomainname,
        "setdomainname",
        RawFnHandler(sys_setdomainname),
    );
    #[cfg(feature = "container")]
    {
        table.install_raw(Syscall::Shmget, "shmget", RawFnHandler(sys_shmget));
        // The self-contained sysvipc module supersedes the id-by-key
        // semget/msgget in any linux-compat build; only register the
        // container-namespace versions when linux-compat is absent.
        #[cfg(not(feature = "linux-compat"))]
        {
            table.install_raw(Syscall::Semget, "semget", RawFnHandler(sys_semget));
            table.install_raw(Syscall::Msgget, "msgget", RawFnHandler(sys_msgget));
        }
    }
    table.install_raw(Syscall::Getrlimit, "getrlimit", RawFnHandler(sys_getrlimit));
    table.install_raw(Syscall::Setrlimit, "setrlimit", RawFnHandler(sys_setrlimit));
    table.install_raw(Syscall::Prlimit64, "prlimit64", RawFnHandler(sys_prlimit64));
    table.install_raw(Syscall::Umask, "umask", RawFnHandler(sys_umask));
    table.install_raw(Syscall::Getcpu, "getcpu", RawFnHandler(sys_getcpu));
    table.install_raw(
        Syscall::SchedGetaffinity,
        "sched_getaffinity",
        RawFnHandler(sys_sched_getaffinity),
    );
    table.install_raw(
        Syscall::SchedSetaffinity,
        "sched_setaffinity",
        RawFnHandler(sys_sched_setaffinity),
    );
    table.install_raw(
        Syscall::SchedGetPriorityMax,
        "sched_get_priority_max",
        RawFnHandler(sys_sched_get_priority_max),
    );
    table.install_raw(
        Syscall::SchedGetPriorityMin,
        "sched_get_priority_min",
        RawFnHandler(sys_sched_get_priority_min),
    );
    table.install_raw(
        Syscall::SchedGetparam,
        "sched_getparam",
        RawFnHandler(sys_sched_getparam),
    );
    table.install_raw(
        Syscall::SchedSetparam,
        "sched_setparam",
        RawFnHandler(sys_sched_setparam),
    );
    table.install_raw(Syscall::Prctl, "prctl", RawFnHandler(sys_prctl));
    table.install_raw(
        Syscall::Getpriority,
        "getpriority",
        RawFnHandler(sys_getpriority),
    );
    table.install_raw(
        Syscall::Setpriority,
        "setpriority",
        RawFnHandler(sys_setpriority),
    );
    table.install_raw(Syscall::Times, "times", RawFnHandler(sys_times));
    table.install_raw(Syscall::Getrusage, "getrusage", RawFnHandler(sys_getrusage));
    table.install_raw(Syscall::ExitTask, "exit", RawFnHandler(sys_exit_task));
    table.install_raw(
        Syscall::ExitGroup,
        "exit_group",
        RawFnHandler(sys_exit_group),
    );
    table.install_raw(Syscall::Yield, "yield", RawFnHandler(sys_yield));
    table.install_raw(Syscall::Sleep, "sleep", RawFnHandler(sys_sleep));
    table.install_raw(Syscall::Brk, "brk", RawFnHandler(sys_brk));
    table.install_raw(
        Syscall::ClockGetTime,
        "clock_gettime",
        RawFnHandler(sys_clock_gettime),
    );
    table.install_raw(
        Syscall::ClockSetTime,
        "clock_settime",
        RawFnHandler(sys_clock_settime),
    );
    #[cfg(feature = "linux-compat")]
    {
        table.install_raw(
            Syscall::Gettimeofday,
            "gettimeofday",
            RawFnHandler(sys_gettimeofday),
        );
        table.install_raw(
            Syscall::Settimeofday,
            "settimeofday",
            RawFnHandler(sys_settimeofday),
        );
        table.install_raw(Syscall::Time, "time", RawFnHandler(sys_time));
        table.install_raw(
            Syscall::IoprioSet,
            "ioprio_set",
            RawFnHandler(sys_ioprio_set),
        );
        table.install_raw(
            Syscall::IoprioGet,
            "ioprio_get",
            RawFnHandler(sys_ioprio_get),
        );
    }
    #[cfg(feature = "linux-compat")]
    {
        // Wave-73: POSIX per-process timers + clock_nanosleep.
        table.install_raw(
            Syscall::TimerCreate,
            "timer_create",
            RawFnHandler(crate::posix_timer::sys_timer_create),
        );
        table.install_raw(
            Syscall::TimerSettime,
            "timer_settime",
            RawFnHandler(crate::posix_timer::sys_timer_settime),
        );
        table.install_raw(
            Syscall::TimerGettime,
            "timer_gettime",
            RawFnHandler(crate::posix_timer::sys_timer_gettime),
        );
        table.install_raw(
            Syscall::TimerDelete,
            "timer_delete",
            RawFnHandler(crate::posix_timer::sys_timer_delete),
        );
        table.install_raw(
            Syscall::ClockNanosleep,
            "clock_nanosleep",
            RawFnHandler(crate::posix_timer::sys_clock_nanosleep),
        );
        table.install_raw(
            Syscall::Nanosleep,
            "nanosleep",
            RawFnHandler(crate::posix_timer::sys_nanosleep),
        );
        // Batch 7: BSD interval timers (ITIMER_REAL → SIGALRM) + alarm.
        table.install_raw(
            Syscall::Setitimer,
            "setitimer",
            RawFnHandler(crate::posix_timer::sys_setitimer),
        );
        table.install_raw(
            Syscall::Getitimer,
            "getitimer",
            RawFnHandler(crate::posix_timer::sys_getitimer),
        );
        table.install_raw(
            Syscall::Alarm,
            "alarm",
            RawFnHandler(crate::posix_timer::sys_alarm),
        );
        // Batch 8: POSIX message queues + inotify.
        table.install_raw(
            Syscall::MqOpen,
            "mq_open",
            RawFnHandler(crate::mqueue::sys_mq_open),
        );
        table.install_raw(
            Syscall::MqUnlink,
            "mq_unlink",
            RawFnHandler(crate::mqueue::sys_mq_unlink),
        );
        table.install_raw(
            Syscall::MqTimedsend,
            "mq_timedsend",
            RawFnHandler(crate::mqueue::sys_mq_timedsend),
        );
        table.install_raw(
            Syscall::MqTimedreceive,
            "mq_timedreceive",
            RawFnHandler(crate::mqueue::sys_mq_timedreceive),
        );
        table.install_raw(
            Syscall::MqGetsetattr,
            "mq_getsetattr",
            RawFnHandler(crate::mqueue::sys_mq_getsetattr),
        );
        table.install_raw(
            Syscall::InotifyInit1,
            "inotify_init1",
            RawFnHandler(crate::mqueue::sys_inotify_init1),
        );
        table.install_raw(
            Syscall::InotifyInit,
            "inotify_init",
            RawFnHandler(crate::mqueue::sys_inotify_init_no_flags),
        );
        table.install_raw(
            Syscall::InotifyAddWatch,
            "inotify_add_watch",
            RawFnHandler(crate::mqueue::sys_inotify_add_watch),
        );
        table.install_raw(
            Syscall::InotifyRmWatch,
            "inotify_rm_watch",
            RawFnHandler(crate::mqueue::sys_inotify_rm_watch),
        );
        // Batch 23: fanotify — events delivered through the same fs_notify
        // dispatch as inotify, each carrying an open fd to the object.
        table.install_raw(
            Syscall::FanotifyInit,
            "fanotify_init",
            RawFnHandler(crate::mqueue::sys_fanotify_init),
        );
        table.install_raw(
            Syscall::FanotifyMark,
            "fanotify_mark",
            RawFnHandler(crate::mqueue::sys_fanotify_mark),
        );
        // Batch 24: Landlock — path-based access control, enforced at open.
        table.install_raw(
            Syscall::LandlockCreateRuleset,
            "landlock_create_ruleset",
            RawFnHandler(crate::landlock::sys_landlock_create_ruleset),
        );
        table.install_raw(
            Syscall::LandlockAddRule,
            "landlock_add_rule",
            RawFnHandler(crate::landlock::sys_landlock_add_rule),
        );
        table.install_raw(
            Syscall::LandlockRestrictSelf,
            "landlock_restrict_self",
            RawFnHandler(crate::landlock::sys_landlock_restrict_self),
        );
        // Batch 25: generic LSM self-attribute syscalls.
        table.install_raw(
            Syscall::LsmGetSelfAttr,
            "lsm_get_self_attr",
            RawFnHandler(crate::lsm::sys_lsm_get_self_attr),
        );
        table.install_raw(
            Syscall::LsmSetSelfAttr,
            "lsm_set_self_attr",
            RawFnHandler(crate::lsm::sys_lsm_set_self_attr),
        );
        table.install_raw(
            Syscall::LsmListModules,
            "lsm_list_modules",
            RawFnHandler(crate::lsm::sys_lsm_list_modules),
        );
        // New mount API round 1: file handles.
        table.install_raw(
            Syscall::NameToHandleAt,
            "name_to_handle_at",
            RawFnHandler(sys_name_to_handle_at),
        );
        table.install_raw(
            Syscall::OpenByHandleAt,
            "open_by_handle_at",
            RawFnHandler(sys_open_by_handle_at),
        );
        // New mount API round 2: fsopen/fsconfig/fsmount/move_mount/...
        table.install_raw(
            Syscall::Fsopen,
            "fsopen",
            RawFnHandler(crate::mount_api::sys_fsopen),
        );
        table.install_raw(
            Syscall::Fsconfig,
            "fsconfig",
            RawFnHandler(crate::mount_api::sys_fsconfig),
        );
        table.install_raw(
            Syscall::Fsmount,
            "fsmount",
            RawFnHandler(crate::mount_api::sys_fsmount),
        );
        table.install_raw(
            Syscall::MoveMount,
            "move_mount",
            RawFnHandler(crate::mount_api::sys_move_mount),
        );
        table.install_raw(
            Syscall::OpenTree,
            "open_tree",
            RawFnHandler(crate::mount_api::sys_open_tree),
        );
        table.install_raw(
            Syscall::Fspick,
            "fspick",
            RawFnHandler(crate::mount_api::sys_fspick),
        );
        table.install_raw(
            Syscall::MountSetattr,
            "mount_setattr",
            RawFnHandler(crate::mount_api::sys_mount_setattr),
        );
        // Batch 21: keyrings — a real in-kernel key store.
        table.install_raw(
            Syscall::AddKey,
            "add_key",
            RawFnHandler(crate::keyring::sys_add_key),
        );
        table.install_raw(
            Syscall::RequestKey,
            "request_key",
            RawFnHandler(crate::keyring::sys_request_key),
        );
        table.install_raw(
            Syscall::Keyctl,
            "keyctl",
            RawFnHandler(crate::keyring::sys_keyctl),
        );
        // Batch 11: System V semaphores + message queues. These override
        // the container-only id-by-key `semget`/`msgget` (registered
        // earlier) with self-contained backing that works without the
        // container feature.
        table.install_raw(
            Syscall::Semget,
            "semget",
            RawFnHandler(crate::sysvipc::sys_semget),
        );
        table.install_raw(
            Syscall::Semop,
            "semop",
            RawFnHandler(crate::sysvipc::sys_semop),
        );
        table.install_raw(
            Syscall::Semctl,
            "semctl",
            RawFnHandler(crate::sysvipc::sys_semctl),
        );
        table.install_raw(
            Syscall::Semtimedop,
            "semtimedop",
            RawFnHandler(crate::sysvipc::sys_semtimedop),
        );
        table.install_raw(
            Syscall::Msgget,
            "msgget",
            RawFnHandler(crate::sysvipc::sys_msgget),
        );
        table.install_raw(
            Syscall::Msgsnd,
            "msgsnd",
            RawFnHandler(crate::sysvipc::sys_msgsnd),
        );
        table.install_raw(
            Syscall::Msgrcv,
            "msgrcv",
            RawFnHandler(crate::sysvipc::sys_msgrcv),
        );
        table.install_raw(
            Syscall::Msgctl,
            "msgctl",
            RawFnHandler(crate::sysvipc::sys_msgctl),
        );
        // Batch 12: System V shared memory with real frame backing. The
        // linux-compat shmget supersedes the container id-by-key version.
        table.install_raw(Syscall::Shmget, "shmget", RawFnHandler(sys_shmget_compat));
        table.install_raw(Syscall::Shmat, "shmat", RawFnHandler(sys_shmat));
        table.install_raw(Syscall::Shmdt, "shmdt", RawFnHandler(sys_shmdt));
        table.install_raw(Syscall::Shmctl, "shmctl", RawFnHandler(sys_shmctl));
    }
    table.install_raw(Syscall::Sigaction, "sigaction", RawFnHandler(sys_sigaction));
    table.install_raw(
        Syscall::RtSigaction,
        "rt_sigaction",
        RawFnHandler(sys_rt_sigaction),
    );
    table.install_raw(Syscall::Kill, "kill", RawFnHandler(sys_kill));
    table.install_raw(Syscall::Pause, "pause", RawFnHandler(sys_pause));
    table.install_raw(Syscall::Tgkill, "tgkill", RawFnHandler(sys_tgkill));
    table.install_raw(Syscall::Tkill, "tkill", RawFnHandler(sys_tkill));
    // Batch 16: signal queueing with siginfo (delivered via the pending
    // bitmask; the siginfo payload isn't preserved yet).
    table.install_raw(
        Syscall::RtSigqueueinfo,
        "rt_sigqueueinfo",
        RawFnHandler(sys_rt_sigqueueinfo),
    );
    table.install_raw(
        Syscall::RtTgsigqueueinfo,
        "rt_tgsigqueueinfo",
        RawFnHandler(sys_rt_tgsigqueueinfo),
    );
    table.install_raw(Syscall::Ptrace, "ptrace", RawFnHandler(sys_ptrace));
    table.install_raw(Syscall::Futex, "futex", RawFnHandler(sys_futex));
    table.install_raw(
        Syscall::Sigprocmask,
        "sigprocmask",
        RawFnHandler(sys_sigprocmask),
    );
    table.install_raw(
        Syscall::Sigaltstack,
        "sigaltstack",
        RawFnHandler(sys_sigaltstack),
    );
    table.install_raw(
        Syscall::RtSigpending,
        "rt_sigpending",
        RawFnHandler(sys_rt_sigpending),
    );
    table.install_raw(
        Syscall::RtSigsuspend,
        "rt_sigsuspend",
        RawFnHandler(sys_rt_sigsuspend),
    );
    table.install_raw(
        Syscall::RtSigtimedwait,
        "rt_sigtimedwait",
        RawFnHandler(sys_rt_sigtimedwait),
    );
    // restart_syscall — kernel-injected continuation. NARF has no
    // restart_block, so (like Linux's do_no_restart_syscall) it returns
    // -EINTR. See sys_restart_syscall's comment for the restart model.
    table.install_raw(
        Syscall::RestartSyscall,
        "restart_syscall",
        RawFnHandler(sys_restart_syscall),
    );

    // Tier-2 fd-table breadth + path-resolution + pipe(2).
    table.install_raw(Syscall::Dup, "dup", RawFnHandler(sys_dup));
    table.install_raw(Syscall::Dup2, "dup2", RawFnHandler(sys_dup2));
    table.install_raw(Syscall::Dup3, "dup3", RawFnHandler(sys_dup3));
    table.install_raw(Syscall::Fcntl, "fcntl", RawFnHandler(sys_fcntl));
    table.install_raw(Syscall::Ioctl, "ioctl", RawFnHandler(sys_ioctl));
    #[cfg(not(feature = "linux-compat"))]
    {
        table.install_raw(Syscall::Stat, "stat", RawFnHandler(sys_stat));
        table.install_raw(Syscall::Lstat, "lstat", RawFnHandler(sys_stat));
        table.install_raw(Syscall::Fstat, "fstat", RawFnHandler(sys_fstat));
    }
    #[cfg(feature = "linux-compat")]
    {
        table.install_raw(Syscall::Stat, "stat", RawFnHandler(sys_stat_linux));
        table.install_raw(Syscall::Lstat, "lstat", RawFnHandler(sys_lstat_linux));
        table.install_raw(Syscall::Fstat, "fstat", RawFnHandler(sys_fstat_linux));
        table.install_raw(Syscall::OpenFile, "open", RawFnHandler(sys_open_linux));
    }
    table.install_raw(Syscall::Pipe, "pipe", RawFnHandler(sys_pipe));
    table.install_raw(Syscall::Ftruncate, "ftruncate", RawFnHandler(sys_ftruncate));
    table.install_raw(Syscall::Truncate, "truncate", RawFnHandler(sys_truncate));
    table.install_raw(Syscall::Pread64, "pread64", RawFnHandler(sys_pread64));
    table.install_raw(Syscall::Pwrite64, "pwrite64", RawFnHandler(sys_pwrite64));
    table.install_raw(Syscall::Fsync, "fsync", RawFnHandler(sys_fsync));
    // Fdatasync shares fsync's body — both are structural no-ops.
    table.install_raw(Syscall::Fdatasync, "fdatasync", RawFnHandler(sys_fsync));
    table.install_raw(Syscall::Pipe2, "pipe2", RawFnHandler(sys_pipe2));
    table.install_raw(Syscall::Fallocate, "fallocate", RawFnHandler(sys_fallocate));
    table.install_raw(
        Syscall::CopyFileRange,
        "copy_file_range",
        RawFnHandler(sys_copy_file_range),
    );
    table.install_raw(
        Syscall::MemfdCreate,
        "memfd_create",
        RawFnHandler(sys_memfd_create),
    );
    table.install_raw(
        Syscall::Fchmod,
        "fchmod",
        RawFnHandler(sys_fchmod_or_fchown),
    );
    table.install_raw(
        Syscall::Fchown,
        "fchown",
        RawFnHandler(sys_fchmod_or_fchown),
    );
    table.install_raw(Syscall::Fchmodat, "fchmodat", RawFnHandler(sys_fchmodat));
    table.install_raw(
        Syscall::Fchownat,
        "fchownat",
        RawFnHandler(sys_fchmodat_or_fchownat),
    );
    table.install_raw(
        Syscall::Faccessat,
        "faccessat",
        RawFnHandler(sys_fchmodat_or_fchownat),
    );
    table.install_raw(Syscall::Openat, "openat", RawFnHandler(sys_openat));
    #[cfg(not(feature = "linux-compat"))]
    table.install_raw(
        Syscall::Newfstatat,
        "newfstatat",
        RawFnHandler(sys_newfstatat),
    );
    #[cfg(feature = "linux-compat")]
    table.install_raw(
        Syscall::Newfstatat,
        "newfstatat",
        RawFnHandler(sys_newfstatat_linux),
    );
    #[cfg(feature = "linux-compat")]
    table.install_raw(Syscall::Statx, "statx", RawFnHandler(sys_statx));
    table.install_raw(Syscall::Unlinkat, "unlinkat", RawFnHandler(sys_unlinkat));
    table.install_raw(Syscall::Mkdirat, "mkdirat", RawFnHandler(sys_mkdirat));
    table.install_raw(Syscall::Mknodat, "mknodat", RawFnHandler(sys_mknodat));
    table.install_raw(Syscall::Mknod, "mknod", RawFnHandler(sys_mknod));
    table.install_raw(Syscall::Renameat, "renameat", RawFnHandler(sys_renameat));
    table.install_raw(Syscall::Symlinkat, "symlinkat", RawFnHandler(sys_symlinkat));
    table.install_raw(
        Syscall::Readlinkat,
        "readlinkat",
        RawFnHandler(sys_readlinkat),
    );
    table.install_raw(
        Syscall::Access,
        "access",
        RawFnHandler(sys_access_chmod_chown),
    );
    table.install_raw(Syscall::Chmod, "chmod", RawFnHandler(sys_chmod));
    table.install_raw(
        Syscall::Chown,
        "chown",
        RawFnHandler(sys_access_chmod_chown),
    );

    // Tier-2 cwd state + nanosleep wired into the table. Sleep
    // already replaced the noop_ok stub above.
    table.install_raw(Syscall::Chdir, "chdir", RawFnHandler(sys_chdir));
    table.install_raw(Syscall::Getcwd, "getcwd", RawFnHandler(sys_getcwd));
    table.install_raw(Syscall::Lseek, "lseek", RawFnHandler(sys_lseek));
    table.install_raw(Syscall::Unlink, "unlink", RawFnHandler(sys_unlink));
    table.install_raw(Syscall::Mkdir, "mkdir", RawFnHandler(sys_mkdir));
    table.install_raw(Syscall::Rmdir, "rmdir", RawFnHandler(sys_rmdir));
    table.install_raw(Syscall::Rename, "rename", RawFnHandler(sys_rename));
    table.install_raw(Syscall::Link, "link", RawFnHandler(sys_link));
    table.install_raw(Syscall::Linkat, "linkat", RawFnHandler(sys_linkat));
    table.install_raw(Syscall::Fchdir, "fchdir", RawFnHandler(sys_fchdir));
    table.install_raw(Syscall::Readlink, "readlink", RawFnHandler(sys_readlink));
    table.install_raw(Syscall::Symlink, "symlink", RawFnHandler(sys_symlink));
    table.install_raw(Syscall::Listdir, "listdir", RawFnHandler(sys_listdir));
    table.install_raw(
        Syscall::Getdents64,
        "getdents64",
        RawFnHandler(sys_getdents64),
    );
    // Legacy 32-bit-offset getdents (x86_64 78; no aarch64 wire number).
    table.install_raw(Syscall::Getdents, "getdents", RawFnHandler(sys_getdents));

    // Tier-3z entropy.
    table.install_raw(Syscall::GetRandom, "getrandom", RawFnHandler(sys_getrandom));

    // I/O multiplexing: poll / select / pselect6 / epoll.
    table.install_raw(Syscall::Poll, "poll", RawFnHandler(crate::poll::sys_poll));
    table.install_raw(
        Syscall::Ppoll,
        "ppoll",
        RawFnHandler(crate::poll::sys_ppoll),
    );
    table.install_raw(Syscall::Sysinfo, "sysinfo", RawFnHandler(sys_sysinfo));
    table.install_raw(Syscall::Splice, "splice", RawFnHandler(sys_splice));
    table.install_raw(
        Syscall::Membarrier,
        "membarrier",
        RawFnHandler(sys_membarrier),
    );
    table.install_raw(
        Syscall::ClockGetres,
        "clock_getres",
        RawFnHandler(sys_clock_getres),
    );
    table.install_raw(
        Syscall::CloseRange,
        "close_range",
        RawFnHandler(sys_close_range),
    );
    table.install_raw(
        Syscall::SchedGetScheduler,
        "sched_getscheduler",
        RawFnHandler(sys_sched_getscheduler),
    );
    table.install_raw(
        Syscall::SchedSetScheduler,
        "sched_setscheduler",
        RawFnHandler(sys_sched_setscheduler),
    );
    table.install_raw(
        Syscall::SchedRrGetInterval,
        "sched_rr_get_interval",
        RawFnHandler(sys_sched_rr_get_interval),
    );
    table.install_raw(Syscall::Msync, "msync", RawFnHandler(sys_msync));
    table.install_raw(Syscall::Mincore, "mincore", RawFnHandler(sys_mincore));
    table.install_raw(Syscall::Sync, "sync", RawFnHandler(sys_sync));
    table.install_raw(Syscall::Syncfs, "syncfs", RawFnHandler(sys_syncfs));
    table.install_raw(
        Syscall::Personality,
        "personality",
        RawFnHandler(sys_personality),
    );
    table.install_raw(Syscall::Fadvise64, "fadvise64", RawFnHandler(sys_fadvise64));
    table.install_raw(Syscall::Mlock2, "mlock2", RawFnHandler(sys_mlock2));
    table.install_raw(
        Syscall::SetRobustList,
        "set_robust_list",
        RawFnHandler(sys_set_robust_list),
    );
    table.install_raw(
        Syscall::GetRobustList,
        "get_robust_list",
        RawFnHandler(sys_get_robust_list),
    );
    table.install_raw(Syscall::Renameat2, "renameat2", RawFnHandler(sys_renameat2));
    table.install_raw(
        Syscall::PidfdSendSignal,
        "pidfd_send_signal",
        RawFnHandler(sys_pidfd_send_signal),
    );
    table.install_raw(
        Syscall::Sendmmsg,
        "sendmmsg",
        RawFnHandler(sys_socket_sendmmsg),
    );
    table.install_raw(
        Syscall::Recvmmsg,
        "recvmmsg",
        RawFnHandler(sys_socket_recvmmsg),
    );
    table.install_raw(Syscall::Openat2, "openat2", RawFnHandler(sys_openat2));
    table.install_raw(Syscall::Preadv, "preadv", RawFnHandler(sys_preadv));
    table.install_raw(Syscall::Pwritev, "pwritev", RawFnHandler(sys_pwritev));
    // Batch 7: capabilities, extended attributes, file-range hints.
    table.install_raw(Syscall::Capget, "capget", RawFnHandler(sys_capget));
    table.install_raw(Syscall::Capset, "capset", RawFnHandler(sys_capset));
    table.install_raw(Syscall::Setxattr, "setxattr", RawFnHandler(sys_setxattr));
    table.install_raw(Syscall::Getxattr, "getxattr", RawFnHandler(sys_getxattr));
    table.install_raw(Syscall::Listxattr, "listxattr", RawFnHandler(sys_listxattr));
    // Batch 13: xattr l*/f*/remove variants. NARF has no symlink-follow
    // distinction, so the l* variants alias the path handlers.
    table.install_raw(Syscall::Lsetxattr, "lsetxattr", RawFnHandler(sys_setxattr));
    table.install_raw(Syscall::Lgetxattr, "lgetxattr", RawFnHandler(sys_getxattr));
    table.install_raw(
        Syscall::Llistxattr,
        "llistxattr",
        RawFnHandler(sys_listxattr),
    );
    table.install_raw(
        Syscall::Removexattr,
        "removexattr",
        RawFnHandler(sys_removexattr),
    );
    table.install_raw(
        Syscall::Lremovexattr,
        "lremovexattr",
        RawFnHandler(sys_removexattr),
    );
    table.install_raw(Syscall::Fsetxattr, "fsetxattr", RawFnHandler(sys_fsetxattr));
    table.install_raw(Syscall::Fgetxattr, "fgetxattr", RawFnHandler(sys_fgetxattr));
    table.install_raw(
        Syscall::Flistxattr,
        "flistxattr",
        RawFnHandler(sys_flistxattr),
    );
    table.install_raw(
        Syscall::Fremovexattr,
        "fremovexattr",
        RawFnHandler(sys_fremovexattr),
    );
    // Batch 14: filesystem misc (legacy x86_64-only entries).
    table.install_raw(Syscall::Creat, "creat", RawFnHandler(sys_creat));
    // lchown shares the chmod/chown path handler (no symlink-follow
    // distinction in NARF).
    table.install_raw(
        Syscall::Lchown,
        "lchown",
        RawFnHandler(sys_access_chmod_chown),
    );
    table.install_raw(Syscall::Utime, "utime", RawFnHandler(sys_utime));
    table.install_raw(Syscall::Utimes, "utimes", RawFnHandler(sys_utimes));
    table.install_raw(Syscall::Futimesat, "futimesat", RawFnHandler(sys_futimesat));
    table.install_raw(Syscall::Reboot, "reboot", RawFnHandler(sys_reboot));
    table.install_raw(Syscall::Utimensat, "utimensat", RawFnHandler(sys_utimensat));
    // Batch 15: credential gaps (real/effective/fs uid+gid).
    table.install_raw(Syscall::Geteuid, "geteuid", RawFnHandler(sys_geteuid));
    table.install_raw(Syscall::Getegid, "getegid", RawFnHandler(sys_getegid));
    table.install_raw(Syscall::Getpgrp, "getpgrp", RawFnHandler(sys_getpgrp));
    table.install_raw(Syscall::Setreuid, "setreuid", RawFnHandler(sys_setreuid));
    table.install_raw(Syscall::Setregid, "setregid", RawFnHandler(sys_setregid));
    table.install_raw(Syscall::Setfsuid, "setfsuid", RawFnHandler(sys_setfsuid));
    table.install_raw(Syscall::Setfsgid, "setfsgid", RawFnHandler(sys_setfsgid));
    table.install_raw(Syscall::Readahead, "readahead", RawFnHandler(sys_readahead));
    table.install_raw(
        Syscall::SyncFileRange,
        "sync_file_range",
        RawFnHandler(sys_sync_file_range),
    );
    // Batch 8: protection keys + cross-AS bulk copy.
    table.install_raw(
        Syscall::PkeyAlloc,
        "pkey_alloc",
        RawFnHandler(sys_pkey_alloc),
    );
    table.install_raw(Syscall::PkeyFree, "pkey_free", RawFnHandler(sys_pkey_free));
    table.install_raw(
        Syscall::PkeyMprotect,
        "pkey_mprotect",
        RawFnHandler(sys_pkey_mprotect),
    );
    table.install_raw(
        Syscall::ProcessVmReadv,
        "process_vm_readv",
        RawFnHandler(sys_process_vm_readv),
    );
    table.install_raw(
        Syscall::ProcessVmWritev,
        "process_vm_writev",
        RawFnHandler(sys_process_vm_writev),
    );
    // Batch 9: NUMA mempolicy, extended scheduling, clock adjust, introspection.
    table.install_raw(Syscall::Mbind, "mbind", RawFnHandler(sys_mbind));
    table.install_raw(
        Syscall::SetMempolicy,
        "set_mempolicy",
        RawFnHandler(sys_set_mempolicy),
    );
    table.install_raw(
        Syscall::GetMempolicy,
        "get_mempolicy",
        RawFnHandler(sys_get_mempolicy),
    );
    table.install_raw(
        Syscall::SchedSetattr,
        "sched_setattr",
        RawFnHandler(sys_sched_setattr),
    );
    table.install_raw(
        Syscall::SchedGetattr,
        "sched_getattr",
        RawFnHandler(sys_sched_getattr),
    );
    table.install_raw(Syscall::Adjtimex, "adjtimex", RawFnHandler(sys_adjtimex));
    table.install_raw(
        Syscall::ClockAdjtime,
        "clock_adjtime",
        RawFnHandler(sys_clock_adjtime),
    );
    table.install_raw(
        Syscall::PidfdGetfd,
        "pidfd_getfd",
        RawFnHandler(sys_pidfd_getfd),
    );
    table.install_raw(Syscall::Kcmp, "kcmp", RawFnHandler(sys_kcmp));
    // Batch 10: vectored + extended I/O.
    table.install_raw(Syscall::Readv, "readv", RawFnHandler(sys_readv));
    table.install_raw(Syscall::Preadv2, "preadv2", RawFnHandler(sys_preadv2));
    table.install_raw(Syscall::Pwritev2, "pwritev2", RawFnHandler(sys_pwritev2));
    table.install_raw(Syscall::Tee, "tee", RawFnHandler(sys_tee));
    table.install_raw(Syscall::Vmsplice, "vmsplice", RawFnHandler(sys_vmsplice));
    table.install_raw(
        Syscall::Select,
        "select",
        RawFnHandler(crate::select::sys_select),
    );
    table.install_raw(
        Syscall::Pselect6,
        "pselect6",
        RawFnHandler(crate::select::sys_pselect6),
    );
    table.install_raw(
        Syscall::EpollCreate,
        "epoll_create1",
        RawFnHandler(crate::epoll::sys_epoll_create1),
    );
    table.install_raw(
        Syscall::EpollCtl,
        "epoll_ctl",
        RawFnHandler(crate::epoll::sys_epoll_ctl),
    );
    table.install_raw(
        Syscall::EpollWait,
        "epoll_wait",
        RawFnHandler(crate::epoll::sys_epoll_wait),
    );
    table.install_raw(
        Syscall::EpollPwait,
        "epoll_pwait",
        RawFnHandler(crate::epoll::sys_epoll_wait),
    );
    table.install_raw(
        Syscall::EpollPwait2,
        "epoll_pwait2",
        RawFnHandler(crate::epoll::sys_epoll_pwait2),
    );
    #[cfg(feature = "linux-compat")]
    table.install_raw(
        Syscall::PerfEventOpen,
        "perf_event_open",
        RawFnHandler(crate::perf_event::sys_perf_event_open),
    );

    // Loadable kernel modules.
    table.install_raw(
        Syscall::InitModule,
        "init_module",
        RawFnHandler(sys_init_module),
    );
    table.install_raw(
        Syscall::FinitModule,
        "finit_module",
        RawFnHandler(sys_finit_module),
    );
    table.install_raw(
        Syscall::DeleteModule,
        "delete_module",
        RawFnHandler(sys_delete_module),
    );

    // Linux kernel-AIO (libaio) — synchronous backend. See the `aio`
    // module below and [[narf-libaio-sync-backend]].
    table.install_raw(
        Syscall::IoSetup,
        "io_setup",
        RawFnHandler(aio::sys_io_setup),
    );
    table.install_raw(
        Syscall::IoDestroy,
        "io_destroy",
        RawFnHandler(aio::sys_io_destroy),
    );
    table.install_raw(
        Syscall::IoSubmit,
        "io_submit",
        RawFnHandler(aio::sys_io_submit),
    );
    table.install_raw(
        Syscall::IoGetevents,
        "io_getevents",
        RawFnHandler(aio::sys_io_getevents),
    );
    table.install_raw(
        Syscall::IoCancel,
        "io_cancel",
        RawFnHandler(aio::sys_io_cancel),
    );

    // Auto-wire both delivery hooks so any kernel that uses
    // `install_core_syscalls` gets the async + sync signal paths
    // on for free. Idempotent.
    install_signal_delivery_hook(default_signal_delivery);
    install_sync_signal_hook(default_sync_signal_delivery);
}

// ══════════════════════════════════════════════════════════════════════
// Linux kernel-AIO (libaio) — synchronous backend
// See [[narf-libaio-sync-backend]].
//
// NARF's filesystems are in-memory/fast and the executor is cooperative,
// so a real async DMA/threadpool engine buys nothing. Instead each
// submitted `iocb` is executed *synchronously* at `io_submit` time and
// its `io_event` is queued immediately; `io_getevents` just drains the
// queue. glibc/libaio callers (submit → reap) are correct against this
// backend: they never observe an in-flight request.
//
// The per-task `io_context` table mirrors the shape of the other
// tid-keyed tables in this file (an `IrqSafeSpinLock<Option<BTreeMap>>`
// installed lazily, swept in `release_task_tables`).
//
// SMAP RIGOUR: every user-pointer access here — the `iocb *` array, each
// 64-byte `iocb` body, the `io_event` output array, the `aio_context_t`
// out/in words — goes through `copy_from_user` / `copy_to_user`, which
// bracket the transfer with STAC/CLAC. A raw deref of a user VA #PFs
// under SMAP; there are deliberately no raw user derefs below.
// ══════════════════════════════════════════════════════════════════════
mod aio {
    use super::{
        copy_from_user, copy_to_user, current_task_id, fd, poll_blocking, validate_user_range,
        SyscallReturn, TrapContext,
    };
    use alloc::collections::{BTreeMap, VecDeque};
    use alloc::vec::Vec;
    use narf_lib::sync::IrqSafeSpinLock;

    // ── errno constants (negated on return, Linux convention) ────────
    const EINVAL: i64 = -22;
    const EBADF: i64 = -9;
    const EFAULT: i64 = -14;

    // ── Linux <uapi/linux/aio_abi.h> opcodes ─────────────────────────
    const IOCB_CMD_PREAD: u16 = 0;
    const IOCB_CMD_PWRITE: u16 = 1;
    const IOCB_CMD_FSYNC: u16 = 2;
    const IOCB_CMD_FDSYNC: u16 = 3;
    const IOCB_CMD_NOOP: u16 = 6;
    const IOCB_CMD_PREADV: u16 = 7;
    const IOCB_CMD_PWRITEV: u16 = 8;

    // aio_flags bits.
    const IOCB_FLAG_RESFD: u32 = 1 << 0;

    // Struct sizes (repr(C), LP64) — verified against aio_abi.h.
    const IOCB_SIZE: usize = 64;
    const IO_EVENT_SIZE: usize = 32;

    // Cap a single io_submit batch so a bogus `nr` can't drive an
    // unbounded loop / allocation.
    const AIO_RING_MAX: i64 = 65536;

    /// A decoded `struct iocb` (Linux <uapi/linux/aio_abi.h>, 64 bytes).
    /// Field order + offsets are load-bearing; see `decode_iocb`.
    struct Iocb {
        aio_data: u64,       // off 0  — echoed into io_event.data
        aio_lio_opcode: u16, // off 16
        aio_fildes: u32,     // off 20
        aio_buf: u64,        // off 24
        aio_nbytes: u64,     // off 32
        aio_offset: i64,     // off 40
        aio_flags: u32,      // off 56
        aio_resfd: u32,      // off 60
    }

    /// Decode a 64-byte `iocb` from a kernel buffer previously filled by
    /// `copy_from_user`. Offsets per aio_abi.h:
    ///   0  u64 aio_data
    ///   8  u32 aio_key
    ///   12 u32 aio_rw_flags
    ///   16 u16 aio_lio_opcode
    ///   18 s16 aio_reqprio
    ///   20 u32 aio_fildes
    ///   24 u64 aio_buf
    ///   32 u64 aio_nbytes
    ///   40 s64 aio_offset
    ///   48 u64 aio_reserved2
    ///   56 u32 aio_flags
    ///   60 u32 aio_resfd
    fn decode_iocb(b: &[u8; IOCB_SIZE]) -> Iocb {
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        Iocb {
            aio_data: u64_at(0),
            aio_lio_opcode: u16::from_le_bytes(b[16..18].try_into().unwrap()),
            aio_fildes: u32_at(20),
            aio_buf: u64_at(24),
            aio_nbytes: u64_at(32),
            aio_offset: i64::from_le_bytes(b[40..48].try_into().unwrap()),
            aio_flags: u32_at(56),
            aio_resfd: u32_at(60),
        }
    }

    /// Encode a `struct io_event` (32 bytes): data, obj, res, res2.
    fn encode_event(data: u64, obj: u64, res: i64, res2: i64) -> [u8; IO_EVENT_SIZE] {
        let mut out = [0u8; IO_EVENT_SIZE];
        out[0..8].copy_from_slice(&data.to_le_bytes());
        out[8..16].copy_from_slice(&obj.to_le_bytes());
        out[16..24].copy_from_slice(&res.to_le_bytes());
        out[24..32].copy_from_slice(&res2.to_le_bytes());
        out
    }

    /// A completed AIO request, staged for `io_getevents`.
    #[derive(Clone, Copy)]
    struct Completion {
        data: u64, // echoes iocb.aio_data
        obj: u64,  // the user `iocb *` pointer
        res: i64,  // bytes transferred, or -errno
    }

    /// One AIO context: a bounded completion queue. `nr_events` is the
    /// caller's sizing hint (Linux uses it to size the mmap ring; we only
    /// keep it for bookkeeping / validation).
    struct AioContext {
        _nr_events: u32,
        completions: VecDeque<Completion>,
    }

    /// Per-task context table: tid → (ctx_id → AioContext). Context ids
    /// are minted from a global monotonic counter so they never alias
    /// across tasks (Linux hands back an opaque `aio_context_t`; callers
    /// only round-trip it, so any unique non-zero token is valid).
    static AIO_CONTEXTS: IrqSafeSpinLock<Option<BTreeMap<u64, BTreeMap<u64, AioContext>>>> =
        IrqSafeSpinLock::new(None);

    /// Monotonic context-id source. Starts at 1 so a freshly minted id is
    /// always non-zero (Linux requires the caller's `*ctx_idp` to be zero
    /// on entry and writes a non-zero id).
    static NEXT_CTX_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

    fn mint_ctx_id() -> u64 {
        NEXT_CTX_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    }

    /// Run `f` with the calling task's context map, creating the outer
    /// table + per-task entry lazily.
    fn with_task_ctxs<R>(tid: u64, f: impl FnOnce(&mut BTreeMap<u64, AioContext>) -> R) -> R {
        let mut g = AIO_CONTEXTS.lock();
        let outer = g.get_or_insert_with(BTreeMap::new);
        let inner = outer.entry(tid).or_default();
        f(inner)
    }

    /// Exit-time sweep: drop every context (and its queued completions)
    /// owned by `tid`. Called from `release_task_tables` so a process that
    /// forgets `io_destroy` doesn't leak. See [[narf-libaio-sync-backend]].
    pub(super) fn release_task_aio(tid: u64) {
        if let Some(outer) = AIO_CONTEXTS.lock().as_mut() {
            outer.remove(&tid);
        }
    }

    // ── io_setup(nr_events, aio_context_t *ctx_idp) ──────────────────
    pub(super) fn sys_io_setup(ctx: &mut dyn TrapContext) {
        let args = *ctx.args();
        let nr_events = args.arg0 as u32;
        let ctx_idp = args.arg1;

        // Linux rejects nr_events == 0 and requires *ctx_idp be zero on
        // entry. We validate the out-pointer and mint an id.
        if ctx_idp == 0 || validate_user_range(ctx_idp, 8).is_err() {
            ctx.set_return(SyscallReturn::ok(EFAULT as u64));
            return;
        }
        if nr_events == 0 {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }

        let id = mint_ctx_id();
        let tid = current_task_id();
        with_task_ctxs(tid, |m| {
            m.insert(
                id,
                AioContext {
                    _nr_events: nr_events,
                    completions: VecDeque::new(),
                },
            );
        });

        // SAFETY: `ctx_idp` range-validated above; copy_to_user brackets
        // the 8-byte write with STAC/CLAC.
        if unsafe { copy_to_user(ctx_idp, &id.to_le_bytes()) }.is_err() {
            // Roll back the context we just minted so it doesn't leak.
            with_task_ctxs(tid, |m| {
                m.remove(&id);
            });
            ctx.set_return(SyscallReturn::ok(EFAULT as u64));
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
    }

    // ── io_destroy(aio_context_t ctx) ────────────────────────────────
    pub(super) fn sys_io_destroy(ctx: &mut dyn TrapContext) {
        let ctx_id = ctx.args().arg0;
        let tid = current_task_id();
        let removed = with_task_ctxs(tid, |m| m.remove(&ctx_id).is_some());
        if removed {
            ctx.set_return(SyscallReturn::ok(0));
        } else {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
        }
    }

    // ── io_cancel(ctx, iocb *, io_event *result) ─────────────────────
    // Synchronous completions are already done → never cancellable.
    pub(super) fn sys_io_cancel(ctx: &mut dyn TrapContext) {
        ctx.set_return(SyscallReturn::ok(EINVAL as u64));
    }

    /// Positioned read: resolve `fd`, read `len` bytes at `offset` into a
    /// kernel buffer, then copy them to the user `buf`. Reuses the same
    /// fd-resolution + `FileOps::read` path as `sys_pread64`. Returns
    /// bytes read or -errno.
    fn do_pread(tid: u64, fd_no: u32, buf: u64, len: usize, offset: u64) -> i64 {
        if len == 0 {
            return 0;
        }
        if validate_user_range(buf, len).is_err() {
            return EFAULT;
        }
        if !fd::with_table(tid, |t| t.get(fd_no).is_some()).unwrap_or(false) {
            return EBADF;
        }
        let mut kbuf = alloc::vec![0u8; len];
        let outcome = fd::with_table(tid, |t| {
            let entry = t.get(fd_no)?;
            let ops = entry.ops.clone();
            poll_blocking(ops.read(offset, &mut kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::ReadOnly))
                .ok()
        });
        match outcome {
            Some(Some(n)) => {
                // SAFETY: `buf` range-validated above; copy_to_user brackets it.
                if unsafe { copy_to_user(buf, &kbuf[..n]) }.is_err() {
                    EFAULT
                } else {
                    n as i64
                }
            }
            _ => EINVAL,
        }
    }

    /// Positioned write: reuses the `sys_pwrite64` fd-resolution +
    /// `FileOps::write` path. Returns bytes written or -errno.
    fn do_pwrite(tid: u64, fd_no: u32, buf: u64, len: usize, offset: u64) -> i64 {
        if len == 0 {
            return 0;
        }
        // SAFETY: single-threaded syscall; AS active. copy_from_user_vec
        // range-validates + brackets the read of the user source buffer.
        let kbuf = match unsafe { super::copy_from_user_vec(buf, len) } {
            Ok(b) => b,
            Err(_) => return EFAULT,
        };
        if !fd::with_table(tid, |t| t.get(fd_no).is_some()).unwrap_or(false) {
            return EBADF;
        }
        let outcome = fd::with_table(tid, |t| {
            let entry = t.get(fd_no)?;
            let ops = entry.ops.clone();
            poll_blocking(ops.write(offset, &kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::ReadOnly))
                .ok()
        });
        match outcome {
            Some(Some(n)) => n as i64,
            _ => EINVAL,
        }
    }

    /// Vectored positioned read/write over a user iovec array. Mirrors the
    /// `preadv_pwritev` loop but drives it off explicit args (the AIO iocb
    /// carries the iovec base in `aio_buf` and the count in `aio_nbytes`).
    fn do_preadv_pwritev(
        tid: u64,
        fd_no: u32,
        iov_ptr: u64,
        iovcnt: usize,
        mut off: u64,
        is_write: bool,
    ) -> i64 {
        const IOV_MAX: usize = 1024;
        if iovcnt > IOV_MAX {
            return EINVAL;
        }
        if iovcnt == 0 {
            return 0;
        }
        if !fd::with_table(tid, |t| t.get(fd_no).is_some()).unwrap_or(false) {
            return EBADF;
        }
        // SAFETY: single-threaded syscall; copy_from_user_vec validates
        // + brackets the iovec array (16 bytes each).
        let iov_buf = match unsafe { super::copy_from_user_vec(iov_ptr, iovcnt.saturating_mul(16)) }
        {
            Ok(b) => b,
            Err(_) => return EFAULT,
        };
        let mut total: usize = 0;
        for i in 0..iovcnt {
            let o = i * 16;
            let base = u64::from_le_bytes(iov_buf[o..o + 8].try_into().unwrap());
            let len = u64::from_le_bytes(iov_buf[o + 8..o + 16].try_into().unwrap()) as usize;
            if len == 0 {
                continue;
            }
            let done = if is_write {
                do_pwrite(tid, fd_no, base, len, off)
            } else {
                do_pread(tid, fd_no, base, len, off)
            };
            if done < 0 {
                if total == 0 {
                    return done;
                }
                break;
            }
            let n = done as usize;
            total = total.saturating_add(n);
            off = off.saturating_add(n as u64);
            if n < len {
                break; // short transfer / EOF
            }
        }
        total as i64
    }

    /// If the iocb requested eventfd completion notification
    /// (`IOCB_FLAG_RESFD`), bump the `aio_resfd` eventfd by 1 by writing an
    /// 8-byte counter increment through its `FileOps::write` — the same
    /// path a userspace `write(efd, &1u64, 8)` takes. Silently ignored if
    /// the fd isn't open.
    fn signal_resfd(tid: u64, iocb: &Iocb) {
        if iocb.aio_flags & IOCB_FLAG_RESFD == 0 {
            return;
        }
        let one = 1u64.to_le_bytes();
        let _ = fd::with_table(tid, |t| {
            let entry = t.get(iocb.aio_resfd)?;
            let ops = entry.ops.clone();
            poll_blocking(ops.write(0, &one))
        });
    }

    /// Execute one decoded iocb synchronously; return its `res` (bytes or
    /// -errno). NOOP/FSYNC/FDSYNC succeed (in-memory FS has nothing to
    /// flush; the fd is still validated for FSYNC/FDSYNC).
    fn execute_iocb(tid: u64, iocb: &Iocb) -> i64 {
        match iocb.aio_lio_opcode {
            IOCB_CMD_PREAD => do_pread(
                tid,
                iocb.aio_fildes,
                iocb.aio_buf,
                iocb.aio_nbytes as usize,
                iocb.aio_offset as u64,
            ),
            IOCB_CMD_PWRITE => do_pwrite(
                tid,
                iocb.aio_fildes,
                iocb.aio_buf,
                iocb.aio_nbytes as usize,
                iocb.aio_offset as u64,
            ),
            IOCB_CMD_PREADV => do_preadv_pwritev(
                tid,
                iocb.aio_fildes,
                iocb.aio_buf,
                iocb.aio_nbytes as usize,
                iocb.aio_offset as u64,
                false,
            ),
            IOCB_CMD_PWRITEV => do_preadv_pwritev(
                tid,
                iocb.aio_fildes,
                iocb.aio_buf,
                iocb.aio_nbytes as usize,
                iocb.aio_offset as u64,
                true,
            ),
            IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => {
                // In-memory FS: nothing to flush. Success for a valid fd,
                // -EBADF otherwise (matches sys_fsync).
                if fd::with_table(tid, |t| t.get(iocb.aio_fildes).is_some()).unwrap_or(false) {
                    0
                } else {
                    EBADF
                }
            }
            IOCB_CMD_NOOP => 0,
            _ => EINVAL,
        }
    }

    // ── io_submit(ctx, long nr, iocb **iocbpp) ───────────────────────
    pub(super) fn sys_io_submit(ctx: &mut dyn TrapContext) {
        let args = *ctx.args();
        let ctx_id = args.arg0;
        let nr = args.arg1 as i64;
        let iocbpp = args.arg2;
        let tid = current_task_id();

        // Unknown context → -EINVAL.
        let known = with_task_ctxs(tid, |m| m.contains_key(&ctx_id));
        if !known {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }
        if !(0..=AIO_RING_MAX).contains(&nr) {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }
        if nr == 0 {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }

        // The user pointer array is `nr` little-endian u64 pointers.
        // SAFETY: copy_from_user_vec validates + brackets the array read.
        let ptr_bytes = match unsafe { super::copy_from_user_vec(iocbpp, (nr as usize) * 8) } {
            Ok(b) => b,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok(EFAULT as u64));
                return;
            }
        };

        let mut submitted: i64 = 0;
        let mut pending: Vec<Completion> = Vec::new();
        for i in 0..(nr as usize) {
            let uptr = u64::from_le_bytes(ptr_bytes[i * 8..i * 8 + 8].try_into().unwrap());

            // Read the 64-byte iocb body.
            let mut iocb_bytes = [0u8; IOCB_SIZE];
            // SAFETY: copy_from_user range-validates `uptr` + brackets the read.
            if unsafe { copy_from_user(&mut iocb_bytes, uptr) }.is_err() {
                // Linux: return the count submitted so far, or -errno if
                // the very first iocb fails.
                if submitted == 0 {
                    ctx.set_return(SyscallReturn::ok(EFAULT as u64));
                    return;
                }
                break;
            }
            let iocb = decode_iocb(&iocb_bytes);

            // Execute synchronously; a bad fd is NOT a syscall error — it
            // surfaces as io_event.res = -EBADF.
            let res = execute_iocb(tid, &iocb);
            signal_resfd(tid, &iocb);

            pending.push(Completion {
                data: iocb.aio_data,
                obj: uptr,
                res,
            });
            submitted += 1;
        }

        // Stage all completions on the context queue.
        with_task_ctxs(tid, |m| {
            if let Some(c) = m.get_mut(&ctx_id) {
                for comp in pending {
                    c.completions.push_back(comp);
                }
            }
        });

        ctx.set_return(SyscallReturn::ok(submitted as u64));
    }

    // ── io_getevents(ctx, min_nr, nr, io_event *events, timespec *) ──
    pub(super) fn sys_io_getevents(ctx: &mut dyn TrapContext) {
        let args = *ctx.args();
        let ctx_id = args.arg0;
        let _min_nr = args.arg1 as i64;
        let nr = args.arg2 as i64;
        let events_ptr = args.arg3;
        // arg4 = timespec* timeout — ignored: completions are synchronous
        // so events are already queued; we never need to block. This is the
        // documented cooperative simplification (return available count).
        let tid = current_task_id();

        // Unknown context → -EINVAL.
        let known = with_task_ctxs(tid, |m| m.contains_key(&ctx_id));
        if !known {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }
        if nr < 0 {
            ctx.set_return(SyscallReturn::ok(EINVAL as u64));
            return;
        }
        if nr == 0 {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        if events_ptr == 0
            || validate_user_range(events_ptr, (nr as usize) * IO_EVENT_SIZE).is_err()
        {
            ctx.set_return(SyscallReturn::ok(EFAULT as u64));
            return;
        }

        // Drain up to `nr` completions. We copy each 32-byte io_event out
        // individually so a mid-array EFAULT only loses that event.
        let mut count: i64 = 0;
        for slot in 0..(nr as usize) {
            let comp = with_task_ctxs(tid, |m| {
                m.get_mut(&ctx_id).and_then(|c| c.completions.pop_front())
            });
            let comp = match comp {
                Some(c) => c,
                None => break, // queue drained
            };
            let ev = encode_event(comp.data, comp.obj, comp.res, 0);
            let dst = events_ptr + (slot as u64) * IO_EVENT_SIZE as u64;
            // SAFETY: `events_ptr` range-validated above for the whole
            // array; copy_to_user brackets each 32-byte write.
            if unsafe { copy_to_user(dst, &ev) }.is_err() {
                // Re-queue the popped completion at the front so it isn't
                // lost, then stop.
                with_task_ctxs(tid, |m| {
                    if let Some(c) = m.get_mut(&ctx_id) {
                        c.completions.push_front(comp);
                    }
                });
                break;
            }
            count += 1;
        }
        ctx.set_return(SyscallReturn::ok(count as u64));
    }
}

// ── per-syscall handlers (auto-split from handlers.rs) ──
#[path = "sys_access_chmod_chown.rs"]
mod handler_sys_access_chmod_chown;
#[path = "sys_adjtimex.rs"]
mod handler_sys_adjtimex;
#[path = "sys_arch_prctl.rs"]
mod handler_sys_arch_prctl;
#[path = "sys_at2_reshape.rs"]
mod handler_sys_at2_reshape;
#[path = "sys_bootstrap.rs"]
mod handler_sys_bootstrap;
#[path = "sys_brk.rs"]
mod handler_sys_brk;
#[path = "sys_capget.rs"]
mod handler_sys_capget;
#[path = "sys_capset.rs"]
mod handler_sys_capset;
#[path = "sys_chdir.rs"]
mod handler_sys_chdir;
#[path = "sys_chmod.rs"]
mod handler_sys_chmod;
#[path = "sys_chroot.rs"]
mod handler_sys_chroot;
#[path = "sys_chroot_for_test.rs"]
mod handler_sys_chroot_for_test;
#[path = "sys_clock_adjtime.rs"]
mod handler_sys_clock_adjtime;
#[path = "sys_clock_getres.rs"]
mod handler_sys_clock_getres;
#[path = "sys_clock_gettime.rs"]
mod handler_sys_clock_gettime;
#[path = "sys_clock_settime.rs"]
mod handler_sys_clock_settime;
#[path = "sys_clone.rs"]
mod handler_sys_clone;
#[path = "sys_clone3.rs"]
mod handler_sys_clone3;
#[path = "sys_close.rs"]
mod handler_sys_close;
#[path = "sys_close_range.rs"]
mod handler_sys_close_range;
#[path = "sys_copy_file_range.rs"]
mod handler_sys_copy_file_range;
#[path = "sys_creat.rs"]
mod handler_sys_creat;
#[path = "sys_delete_module.rs"]
mod handler_sys_delete_module;
#[path = "sys_dup.rs"]
mod handler_sys_dup;
#[path = "sys_dup2.rs"]
mod handler_sys_dup2;
#[path = "sys_dup3.rs"]
mod handler_sys_dup3;
#[path = "sys_epoll_create.rs"]
mod handler_sys_epoll_create;
#[path = "sys_epoll_ctl.rs"]
mod handler_sys_epoll_ctl;
#[path = "sys_epoll_wait.rs"]
mod handler_sys_epoll_wait;
#[path = "sys_eventfd.rs"]
mod handler_sys_eventfd;
#[path = "sys_execve.rs"]
mod handler_sys_execve;
#[path = "sys_execveat.rs"]
mod handler_sys_execveat;
#[path = "sys_exit_group.rs"]
mod handler_sys_exit_group;
#[path = "sys_exit_task.rs"]
mod handler_sys_exit_task;
#[path = "sys_fadvise64.rs"]
mod handler_sys_fadvise64;
#[path = "sys_fallocate.rs"]
mod handler_sys_fallocate;
#[path = "sys_fb_connect.rs"]
mod handler_sys_fb_connect;
#[path = "sys_fb_disconnect.rs"]
mod handler_sys_fb_disconnect;
#[path = "sys_fb_flush_wait.rs"]
mod handler_sys_fb_flush_wait;
#[path = "sys_fb_info.rs"]
mod handler_sys_fb_info;
#[path = "sys_fb_ring_map.rs"]
mod handler_sys_fb_ring_map;
#[path = "sys_fchdir.rs"]
mod handler_sys_fchdir;
#[path = "sys_fchmod_or_fchown.rs"]
mod handler_sys_fchmod_or_fchown;
#[path = "sys_fchmodat.rs"]
mod handler_sys_fchmodat;
#[path = "sys_fchmodat_or_fchownat.rs"]
mod handler_sys_fchmodat_or_fchownat;
#[path = "sys_fcntl.rs"]
mod handler_sys_fcntl;
#[path = "sys_fgetxattr.rs"]
mod handler_sys_fgetxattr;
#[path = "sys_finit_module.rs"]
mod handler_sys_finit_module;
#[path = "sys_firmware_install.rs"]
mod handler_sys_firmware_install;
#[path = "sys_flistxattr.rs"]
mod handler_sys_flistxattr;
#[path = "sys_flock.rs"]
mod handler_sys_flock;
#[path = "sys_fork.rs"]
mod handler_sys_fork;
#[path = "sys_fremovexattr.rs"]
mod handler_sys_fremovexattr;
#[path = "sys_fsetxattr.rs"]
mod handler_sys_fsetxattr;
#[path = "sys_fstat.rs"]
mod handler_sys_fstat;
#[path = "sys_fstat_linux.rs"]
mod handler_sys_fstat_linux;
#[path = "sys_fstatfs.rs"]
mod handler_sys_fstatfs;
#[path = "sys_fsync.rs"]
mod handler_sys_fsync;
#[path = "sys_ftruncate.rs"]
mod handler_sys_ftruncate;
#[path = "sys_futex.rs"]
mod handler_sys_futex;
#[path = "sys_futex_requeue.rs"]
mod handler_sys_futex_requeue;
#[path = "sys_futex_wait.rs"]
mod handler_sys_futex_wait;
#[path = "sys_futex_waitv.rs"]
mod handler_sys_futex_waitv;
#[path = "sys_futex_wake.rs"]
mod handler_sys_futex_wake;
#[path = "sys_futimesat.rs"]
mod handler_sys_futimesat;
#[path = "sys_get_mempolicy.rs"]
mod handler_sys_get_mempolicy;
#[path = "sys_get_robust_list.rs"]
mod handler_sys_get_robust_list;
#[path = "sys_getcpu.rs"]
mod handler_sys_getcpu;
#[path = "sys_getcwd.rs"]
mod handler_sys_getcwd;
#[path = "sys_getdents.rs"]
mod handler_sys_getdents;
#[path = "sys_getdents64.rs"]
mod handler_sys_getdents64;
#[path = "sys_getegid.rs"]
mod handler_sys_getegid;
#[path = "sys_geteuid.rs"]
mod handler_sys_geteuid;
#[path = "sys_getgid.rs"]
mod handler_sys_getgid;
#[path = "sys_getgroups.rs"]
mod handler_sys_getgroups;
#[path = "sys_gethostname.rs"]
mod handler_sys_gethostname;
#[path = "sys_getpgid.rs"]
mod handler_sys_getpgid;
#[path = "sys_getpgrp.rs"]
mod handler_sys_getpgrp;
#[path = "sys_getpid.rs"]
mod handler_sys_getpid;
#[path = "sys_getppid.rs"]
mod handler_sys_getppid;
#[path = "sys_getpriority.rs"]
mod handler_sys_getpriority;
#[path = "sys_getrandom.rs"]
mod handler_sys_getrandom;
#[path = "sys_getresgid.rs"]
mod handler_sys_getresgid;
#[path = "sys_getresuid.rs"]
mod handler_sys_getresuid;
#[path = "sys_getrlimit.rs"]
mod handler_sys_getrlimit;
#[path = "sys_getrusage.rs"]
mod handler_sys_getrusage;
#[path = "sys_getsid.rs"]
mod handler_sys_getsid;
#[path = "sys_gettid.rs"]
mod handler_sys_gettid;
#[path = "sys_gettimeofday.rs"]
mod handler_sys_gettimeofday;
#[path = "sys_getuid.rs"]
mod handler_sys_getuid;
#[path = "sys_getxattr.rs"]
mod handler_sys_getxattr;
#[path = "sys_init_module.rs"]
mod handler_sys_init_module;
#[path = "sys_ioctl.rs"]
mod handler_sys_ioctl;
#[path = "sys_ioprio_get.rs"]
mod handler_sys_ioprio_get;
#[path = "sys_ioprio_set.rs"]
mod handler_sys_ioprio_set;
#[path = "sys_kcmp.rs"]
mod handler_sys_kcmp;
#[path = "sys_kill.rs"]
mod handler_sys_kill;
#[path = "sys_link.rs"]
mod handler_sys_link;
#[path = "sys_linkat.rs"]
mod handler_sys_linkat;
#[path = "sys_listdir.rs"]
mod handler_sys_listdir;
#[path = "sys_listxattr.rs"]
mod handler_sys_listxattr;
#[path = "sys_lseek.rs"]
mod handler_sys_lseek;
#[path = "sys_lstat_linux.rs"]
mod handler_sys_lstat_linux;
#[path = "sys_madvise.rs"]
mod handler_sys_madvise;
#[path = "sys_mbind.rs"]
mod handler_sys_mbind;
#[path = "sys_membarrier.rs"]
mod handler_sys_membarrier;
#[path = "sys_memfd_create.rs"]
mod handler_sys_memfd_create;
#[path = "sys_memfd_secret.rs"]
mod handler_sys_memfd_secret;
#[path = "sys_migrate_pages.rs"]
mod handler_sys_migrate_pages;
#[path = "sys_mincore.rs"]
mod handler_sys_mincore;
#[path = "sys_mkdir.rs"]
mod handler_sys_mkdir;
#[path = "sys_mkdirat.rs"]
mod handler_sys_mkdirat;
#[path = "sys_mknod.rs"]
mod handler_sys_mknod;
#[path = "sys_mknodat.rs"]
mod handler_sys_mknodat;
#[path = "sys_mlock.rs"]
mod handler_sys_mlock;
#[path = "sys_mlock2.rs"]
mod handler_sys_mlock2;
#[path = "sys_mlockall.rs"]
mod handler_sys_mlockall;
#[path = "sys_mmap.rs"]
mod handler_sys_mmap;
#[path = "sys_mount.rs"]
mod handler_sys_mount;
#[path = "sys_mount_for_test.rs"]
mod handler_sys_mount_for_test;
#[path = "sys_move_pages.rs"]
mod handler_sys_move_pages;
#[path = "sys_mprotect.rs"]
mod handler_sys_mprotect;
#[path = "sys_mremap.rs"]
mod handler_sys_mremap;
#[path = "sys_msgget.rs"]
mod handler_sys_msgget;
#[path = "sys_msync.rs"]
mod handler_sys_msync;
#[path = "sys_munlock.rs"]
mod handler_sys_munlock;
#[path = "sys_munlockall.rs"]
mod handler_sys_munlockall;
#[path = "sys_munmap.rs"]
mod handler_sys_munmap;
#[path = "sys_name_to_handle_at.rs"]
mod handler_sys_name_to_handle_at;
#[path = "sys_newfstatat.rs"]
mod handler_sys_newfstatat;
#[path = "sys_newfstatat_linux.rs"]
mod handler_sys_newfstatat_linux;
#[path = "sys_noop_ok.rs"]
mod handler_sys_noop_ok;
#[path = "sys_open.rs"]
mod handler_sys_open;
#[path = "sys_open_by_handle_at.rs"]
mod handler_sys_open_by_handle_at;
#[path = "sys_open_linux.rs"]
mod handler_sys_open_linux;
#[path = "sys_openat.rs"]
mod handler_sys_openat;
#[path = "sys_openat2.rs"]
mod handler_sys_openat2;
#[path = "sys_pause.rs"]
mod handler_sys_pause;
#[path = "sys_personality.rs"]
mod handler_sys_personality;
#[path = "sys_pidfd_getfd.rs"]
mod handler_sys_pidfd_getfd;
#[path = "sys_pidfd_open.rs"]
mod handler_sys_pidfd_open;
#[path = "sys_pidfd_send_signal.rs"]
mod handler_sys_pidfd_send_signal;
#[path = "sys_pipe.rs"]
mod handler_sys_pipe;
#[path = "sys_pipe2.rs"]
mod handler_sys_pipe2;
#[path = "sys_pivot_root.rs"]
mod handler_sys_pivot_root;
#[path = "sys_pivot_root_for_test.rs"]
mod handler_sys_pivot_root_for_test;
#[path = "sys_pkey_alloc.rs"]
mod handler_sys_pkey_alloc;
#[path = "sys_pkey_free.rs"]
mod handler_sys_pkey_free;
#[path = "sys_pkey_mprotect.rs"]
mod handler_sys_pkey_mprotect;
#[path = "sys_poll.rs"]
mod handler_sys_poll;
#[path = "sys_prctl.rs"]
mod handler_sys_prctl;
#[path = "sys_pread64.rs"]
mod handler_sys_pread64;
#[path = "sys_preadv.rs"]
mod handler_sys_preadv;
#[path = "sys_preadv2.rs"]
mod handler_sys_preadv2;
#[path = "sys_prlimit64.rs"]
mod handler_sys_prlimit64;
#[path = "sys_process_madvise.rs"]
mod handler_sys_process_madvise;
#[path = "sys_process_vm_readv.rs"]
mod handler_sys_process_vm_readv;
#[path = "sys_process_vm_writev.rs"]
mod handler_sys_process_vm_writev;
#[path = "sys_ptrace.rs"]
mod handler_sys_ptrace;
#[path = "sys_pwrite64.rs"]
mod handler_sys_pwrite64;
#[path = "sys_pwritev.rs"]
mod handler_sys_pwritev;
#[path = "sys_pwritev2.rs"]
mod handler_sys_pwritev2;
#[path = "sys_read.rs"]
mod handler_sys_read;
#[path = "sys_readahead.rs"]
mod handler_sys_readahead;
#[path = "sys_readlink.rs"]
mod handler_sys_readlink;
#[path = "sys_readlinkat.rs"]
mod handler_sys_readlinkat;
#[path = "sys_readv.rs"]
mod handler_sys_readv;
#[path = "sys_reboot.rs"]
mod handler_sys_reboot;
#[path = "sys_removexattr.rs"]
mod handler_sys_removexattr;
#[path = "sys_rename.rs"]
mod handler_sys_rename;
#[path = "sys_renameat.rs"]
mod handler_sys_renameat;
#[path = "sys_renameat2.rs"]
mod handler_sys_renameat2;
#[path = "sys_restart_syscall.rs"]
mod handler_sys_restart_syscall;
#[path = "sys_ring_kick.rs"]
mod handler_sys_ring_kick;
#[path = "sys_rmdir.rs"]
mod handler_sys_rmdir;
#[path = "sys_rseq.rs"]
mod handler_sys_rseq;
#[path = "sys_rt_sigaction.rs"]
mod handler_sys_rt_sigaction;
#[path = "sys_rt_sigpending.rs"]
mod handler_sys_rt_sigpending;
#[path = "sys_rt_sigqueueinfo.rs"]
mod handler_sys_rt_sigqueueinfo;
#[path = "sys_rt_sigsuspend.rs"]
mod handler_sys_rt_sigsuspend;
#[path = "sys_rt_sigtimedwait.rs"]
mod handler_sys_rt_sigtimedwait;
#[path = "sys_rt_tgsigqueueinfo.rs"]
mod handler_sys_rt_tgsigqueueinfo;
#[path = "sys_sched_get_priority_max.rs"]
mod handler_sys_sched_get_priority_max;
#[path = "sys_sched_get_priority_min.rs"]
mod handler_sys_sched_get_priority_min;
#[path = "sys_sched_getaffinity.rs"]
mod handler_sys_sched_getaffinity;
#[path = "sys_sched_getattr.rs"]
mod handler_sys_sched_getattr;
#[path = "sys_sched_getparam.rs"]
mod handler_sys_sched_getparam;
#[path = "sys_sched_getscheduler.rs"]
mod handler_sys_sched_getscheduler;
#[path = "sys_sched_rr_get_interval.rs"]
mod handler_sys_sched_rr_get_interval;
#[path = "sys_sched_setaffinity.rs"]
mod handler_sys_sched_setaffinity;
#[path = "sys_sched_setattr.rs"]
mod handler_sys_sched_setattr;
#[path = "sys_sched_setparam.rs"]
mod handler_sys_sched_setparam;
#[path = "sys_sched_setscheduler.rs"]
mod handler_sys_sched_setscheduler;
#[path = "sys_semget.rs"]
mod handler_sys_semget;
#[path = "sys_sendfile.rs"]
mod handler_sys_sendfile;
#[path = "sys_set_mempolicy.rs"]
mod handler_sys_set_mempolicy;
#[path = "sys_set_mempolicy_home_node.rs"]
mod handler_sys_set_mempolicy_home_node;
#[path = "sys_set_robust_list.rs"]
mod handler_sys_set_robust_list;
#[path = "sys_set_tid_address.rs"]
mod handler_sys_set_tid_address;
#[path = "sys_setdomainname.rs"]
mod handler_sys_setdomainname;
#[path = "sys_setfsgid.rs"]
mod handler_sys_setfsgid;
#[path = "sys_setfsuid.rs"]
mod handler_sys_setfsuid;
#[path = "sys_setgid.rs"]
mod handler_sys_setgid;
#[path = "sys_setgroups.rs"]
mod handler_sys_setgroups;
#[path = "sys_sethostname.rs"]
mod handler_sys_sethostname;
#[path = "sys_setns.rs"]
mod handler_sys_setns;
#[path = "sys_setpgid.rs"]
mod handler_sys_setpgid;
#[path = "sys_setpriority.rs"]
mod handler_sys_setpriority;
#[path = "sys_setregid.rs"]
mod handler_sys_setregid;
#[path = "sys_setresgid.rs"]
mod handler_sys_setresgid;
#[path = "sys_setresuid.rs"]
mod handler_sys_setresuid;
#[path = "sys_setreuid.rs"]
mod handler_sys_setreuid;
#[path = "sys_setrlimit.rs"]
mod handler_sys_setrlimit;
#[path = "sys_setsid.rs"]
mod handler_sys_setsid;
#[path = "sys_settimeofday.rs"]
mod handler_sys_settimeofday;
#[path = "sys_setuid.rs"]
mod handler_sys_setuid;
#[path = "sys_setxattr.rs"]
mod handler_sys_setxattr;
#[path = "sys_shmat.rs"]
mod handler_sys_shmat;
#[path = "sys_shmctl.rs"]
mod handler_sys_shmctl;
#[path = "sys_shmdt.rs"]
mod handler_sys_shmdt;
#[path = "sys_shmem_create.rs"]
mod handler_sys_shmem_create;
#[path = "sys_shmem_destroy.rs"]
mod handler_sys_shmem_destroy;
#[path = "sys_shmem_map.rs"]
mod handler_sys_shmem_map;
#[path = "sys_shmget.rs"]
mod handler_sys_shmget;
#[path = "sys_shmget_compat.rs"]
mod handler_sys_shmget_compat;
#[path = "sys_sigaction.rs"]
mod handler_sys_sigaction;
#[path = "sys_sigaltstack.rs"]
mod handler_sys_sigaltstack;
#[path = "sys_signalfd.rs"]
mod handler_sys_signalfd;
#[path = "sys_sigprocmask.rs"]
mod handler_sys_sigprocmask;
#[path = "sys_sigreturn.rs"]
mod handler_sys_sigreturn;
#[path = "sys_sleep.rs"]
mod handler_sys_sleep;
#[path = "sys_sock_register_buf.rs"]
mod handler_sys_sock_register_buf;
#[path = "sys_sock_send_zc.rs"]
mod handler_sys_sock_send_zc;
#[path = "sys_socket.rs"]
mod handler_sys_socket;
#[path = "sys_socket_accept.rs"]
mod handler_sys_socket_accept;
#[path = "sys_socket_accept4.rs"]
mod handler_sys_socket_accept4;
#[path = "sys_socket_bind.rs"]
mod handler_sys_socket_bind;
#[path = "sys_socket_connect.rs"]
mod handler_sys_socket_connect;
#[path = "sys_socket_get_addr.rs"]
mod handler_sys_socket_get_addr;
#[path = "sys_socket_getpeername.rs"]
mod handler_sys_socket_getpeername;
#[path = "sys_socket_getsockname.rs"]
mod handler_sys_socket_getsockname;
#[path = "sys_socket_getsockopt.rs"]
mod handler_sys_socket_getsockopt;
#[path = "sys_socket_listen.rs"]
mod handler_sys_socket_listen;
#[path = "sys_socket_recv.rs"]
mod handler_sys_socket_recv;
#[path = "sys_socket_recvmmsg.rs"]
mod handler_sys_socket_recvmmsg;
#[path = "sys_socket_recvmsg.rs"]
mod handler_sys_socket_recvmsg;
#[path = "sys_socket_send.rs"]
mod handler_sys_socket_send;
#[path = "sys_socket_sendmmsg.rs"]
mod handler_sys_socket_sendmmsg;
#[path = "sys_socket_sendmsg.rs"]
mod handler_sys_socket_sendmsg;
#[path = "sys_socket_setsockopt.rs"]
mod handler_sys_socket_setsockopt;
#[path = "sys_socket_shutdown.rs"]
mod handler_sys_socket_shutdown;
#[path = "sys_socketpair.rs"]
mod handler_sys_socketpair;
#[path = "sys_splice.rs"]
mod handler_sys_splice;
#[path = "sys_stat.rs"]
mod handler_sys_stat;
#[path = "sys_stat_linux.rs"]
mod handler_sys_stat_linux;
#[path = "sys_statfs.rs"]
mod handler_sys_statfs;
#[path = "sys_statx.rs"]
mod handler_sys_statx;
#[path = "sys_symlink.rs"]
mod handler_sys_symlink;
#[path = "sys_symlinkat.rs"]
mod handler_sys_symlinkat;
#[path = "sys_sync.rs"]
mod handler_sys_sync;
#[path = "sys_sync_file_range.rs"]
mod handler_sys_sync_file_range;
#[path = "sys_syncfs.rs"]
mod handler_sys_syncfs;
#[path = "sys_sysinfo.rs"]
mod handler_sys_sysinfo;
#[path = "sys_tcgetattr.rs"]
mod handler_sys_tcgetattr;
#[path = "sys_tcsetattr.rs"]
mod handler_sys_tcsetattr;
#[path = "sys_tee.rs"]
mod handler_sys_tee;
#[path = "sys_tgkill.rs"]
mod handler_sys_tgkill;
#[path = "sys_time.rs"]
mod handler_sys_time;
#[path = "sys_timerfd_create.rs"]
mod handler_sys_timerfd_create;
#[path = "sys_timerfd_gettime.rs"]
mod handler_sys_timerfd_gettime;
#[path = "sys_timerfd_settime.rs"]
mod handler_sys_timerfd_settime;
#[path = "sys_times.rs"]
mod handler_sys_times;
#[path = "sys_tkill.rs"]
mod handler_sys_tkill;
#[path = "sys_truncate.rs"]
mod handler_sys_truncate;
#[path = "sys_umask.rs"]
mod handler_sys_umask;
#[path = "sys_umount2.rs"]
mod handler_sys_umount2;
#[path = "sys_umount2_for_test.rs"]
mod handler_sys_umount2_for_test;
#[path = "sys_uname.rs"]
mod handler_sys_uname;
#[path = "sys_unlink.rs"]
mod handler_sys_unlink;
#[path = "sys_unlinkat.rs"]
mod handler_sys_unlinkat;
#[path = "sys_unshare.rs"]
mod handler_sys_unshare;
#[path = "sys_utime.rs"]
mod handler_sys_utime;
#[path = "sys_utimensat.rs"]
mod handler_sys_utimensat;
#[path = "sys_utimes.rs"]
mod handler_sys_utimes;
#[path = "sys_vhangup.rs"]
mod handler_sys_vhangup;
#[path = "sys_vmsplice.rs"]
mod handler_sys_vmsplice;
#[path = "sys_wait4.rs"]
mod handler_sys_wait4;
#[path = "sys_waitid.rs"]
mod handler_sys_waitid;
#[path = "sys_write.rs"]
mod handler_sys_write;
#[path = "sys_writev.rs"]
mod handler_sys_writev;
#[path = "sys_yield.rs"]
mod handler_sys_yield;

#[allow(unused_imports)]
pub(crate) use handler_sys_arch_prctl::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_chroot::*;
#[allow(unused_imports)]
pub use handler_sys_chroot_for_test::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_clone::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_clone3::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_fstat_linux::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_lstat_linux::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_madvise::*;
#[allow(unused_imports)]
pub use handler_sys_mount_for_test::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_msgget::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_name_to_handle_at::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_newfstatat_linux::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_open_by_handle_at::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_pivot_root::*;
#[allow(unused_imports)]
pub use handler_sys_pivot_root_for_test::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_semget::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_set_tid_address::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmat::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmctl::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmdt::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmget::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_shmget_compat::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_stat_linux::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_statx::*;
#[allow(unused_imports)]
pub(crate) use handler_sys_timerfd_gettime::*;
#[allow(unused_imports)]
pub use handler_sys_umount2_for_test::*;
#[allow(unused_imports)]
pub(crate) use {
    handler_sys_access_chmod_chown::sys_access_chmod_chown, handler_sys_adjtimex::sys_adjtimex,
    handler_sys_at2_reshape::sys_at2_reshape, handler_sys_bootstrap::sys_bootstrap,
    handler_sys_brk::sys_brk, handler_sys_capget::sys_capget, handler_sys_capset::sys_capset,
    handler_sys_chdir::sys_chdir, handler_sys_chmod::sys_chmod,
    handler_sys_clock_adjtime::sys_clock_adjtime, handler_sys_clock_getres::sys_clock_getres,
    handler_sys_clock_gettime::sys_clock_gettime, handler_sys_clock_settime::sys_clock_settime,
    handler_sys_close::sys_close, handler_sys_close_range::sys_close_range,
    handler_sys_copy_file_range::sys_copy_file_range, handler_sys_creat::sys_creat,
    handler_sys_delete_module::sys_delete_module, handler_sys_dup::sys_dup,
    handler_sys_dup2::sys_dup2, handler_sys_dup3::sys_dup3,
    handler_sys_epoll_create::sys_epoll_create, handler_sys_epoll_ctl::sys_epoll_ctl,
    handler_sys_epoll_wait::sys_epoll_wait, handler_sys_eventfd::sys_eventfd,
    handler_sys_execve::sys_execve, handler_sys_execveat::sys_execveat,
    handler_sys_exit_group::sys_exit_group, handler_sys_exit_task::sys_exit_task,
    handler_sys_fadvise64::sys_fadvise64, handler_sys_fallocate::sys_fallocate,
    handler_sys_fb_connect::sys_fb_connect, handler_sys_fb_disconnect::sys_fb_disconnect,
    handler_sys_fb_flush_wait::sys_fb_flush_wait, handler_sys_fb_info::sys_fb_info,
    handler_sys_fb_ring_map::sys_fb_ring_map, handler_sys_fchdir::sys_fchdir,
    handler_sys_fchmod_or_fchown::sys_fchmod_or_fchown, handler_sys_fchmodat::sys_fchmodat,
    handler_sys_fchmodat_or_fchownat::sys_fchmodat_or_fchownat, handler_sys_fcntl::sys_fcntl,
    handler_sys_fgetxattr::sys_fgetxattr, handler_sys_finit_module::sys_finit_module,
    handler_sys_firmware_install::sys_firmware_install, handler_sys_flistxattr::sys_flistxattr,
    handler_sys_flock::sys_flock, handler_sys_fork::sys_fork,
    handler_sys_fremovexattr::sys_fremovexattr, handler_sys_fsetxattr::sys_fsetxattr,
    handler_sys_fstat::sys_fstat, handler_sys_fstatfs::sys_fstatfs, handler_sys_fsync::sys_fsync,
    handler_sys_ftruncate::sys_ftruncate, handler_sys_futex::sys_futex,
    handler_sys_futex_requeue::sys_futex_requeue, handler_sys_futex_wait::sys_futex_wait,
    handler_sys_futex_waitv::sys_futex_waitv, handler_sys_futex_wake::sys_futex_wake,
    handler_sys_futimesat::sys_futimesat, handler_sys_get_mempolicy::sys_get_mempolicy,
    handler_sys_get_robust_list::sys_get_robust_list, handler_sys_getcpu::sys_getcpu,
    handler_sys_getcwd::sys_getcwd, handler_sys_getdents::sys_getdents,
    handler_sys_getdents64::sys_getdents64, handler_sys_getegid::sys_getegid,
    handler_sys_geteuid::sys_geteuid, handler_sys_getgid::sys_getgid,
    handler_sys_getgroups::sys_getgroups, handler_sys_gethostname::sys_gethostname,
    handler_sys_getpgid::sys_getpgid, handler_sys_getpgrp::sys_getpgrp,
    handler_sys_getpid::sys_getpid, handler_sys_getppid::sys_getppid,
    handler_sys_getpriority::sys_getpriority, handler_sys_getrandom::sys_getrandom,
    handler_sys_getresgid::sys_getresgid, handler_sys_getresuid::sys_getresuid,
    handler_sys_getrlimit::sys_getrlimit, handler_sys_getrusage::sys_getrusage,
    handler_sys_getsid::sys_getsid, handler_sys_gettid::sys_gettid,
    handler_sys_gettimeofday::sys_gettimeofday, handler_sys_getuid::sys_getuid,
    handler_sys_getxattr::sys_getxattr, handler_sys_init_module::sys_init_module,
    handler_sys_ioctl::sys_ioctl, handler_sys_ioprio_get::sys_ioprio_get,
    handler_sys_ioprio_set::sys_ioprio_set, handler_sys_kcmp::sys_kcmp, handler_sys_kill::sys_kill,
    handler_sys_link::sys_link, handler_sys_linkat::sys_linkat, handler_sys_listdir::sys_listdir,
    handler_sys_listxattr::sys_listxattr, handler_sys_lseek::sys_lseek,
    handler_sys_mbind::sys_mbind, handler_sys_membarrier::sys_membarrier,
    handler_sys_memfd_create::sys_memfd_create, handler_sys_memfd_secret::sys_memfd_secret,
    handler_sys_migrate_pages::sys_migrate_pages, handler_sys_mincore::sys_mincore,
    handler_sys_mkdir::sys_mkdir, handler_sys_mkdirat::sys_mkdirat, handler_sys_mknod::sys_mknod,
    handler_sys_mknodat::sys_mknodat, handler_sys_mlock::sys_mlock, handler_sys_mlock2::sys_mlock2,
    handler_sys_mlockall::sys_mlockall, handler_sys_mmap::sys_mmap, handler_sys_mount::sys_mount,
    handler_sys_move_pages::sys_move_pages, handler_sys_mprotect::sys_mprotect,
    handler_sys_mremap::sys_mremap, handler_sys_msync::sys_msync, handler_sys_munlock::sys_munlock,
    handler_sys_munlockall::sys_munlockall, handler_sys_munmap::sys_munmap,
    handler_sys_newfstatat::sys_newfstatat, handler_sys_noop_ok::sys_noop_ok,
    handler_sys_open::sys_open, handler_sys_open_linux::sys_open_linux,
    handler_sys_openat::sys_openat, handler_sys_openat2::sys_openat2, handler_sys_pause::sys_pause,
    handler_sys_personality::sys_personality, handler_sys_pidfd_getfd::sys_pidfd_getfd,
    handler_sys_pidfd_open::sys_pidfd_open, handler_sys_pidfd_send_signal::sys_pidfd_send_signal,
    handler_sys_pipe::sys_pipe, handler_sys_pipe2::sys_pipe2,
    handler_sys_pkey_alloc::sys_pkey_alloc, handler_sys_pkey_free::sys_pkey_free,
    handler_sys_pkey_mprotect::sys_pkey_mprotect, handler_sys_poll::sys_poll,
    handler_sys_prctl::sys_prctl, handler_sys_pread64::sys_pread64, handler_sys_preadv::sys_preadv,
    handler_sys_preadv2::sys_preadv2, handler_sys_prlimit64::sys_prlimit64,
    handler_sys_process_madvise::sys_process_madvise,
    handler_sys_process_vm_readv::sys_process_vm_readv,
    handler_sys_process_vm_writev::sys_process_vm_writev, handler_sys_ptrace::sys_ptrace,
    handler_sys_pwrite64::sys_pwrite64, handler_sys_pwritev::sys_pwritev,
    handler_sys_pwritev2::sys_pwritev2, handler_sys_read::sys_read,
    handler_sys_readahead::sys_readahead, handler_sys_readlink::sys_readlink,
    handler_sys_readlinkat::sys_readlinkat, handler_sys_readv::sys_readv,
    handler_sys_reboot::sys_reboot, handler_sys_removexattr::sys_removexattr,
    handler_sys_rename::sys_rename, handler_sys_renameat::sys_renameat,
    handler_sys_renameat2::sys_renameat2, handler_sys_restart_syscall::sys_restart_syscall,
    handler_sys_ring_kick::sys_ring_kick, handler_sys_rmdir::sys_rmdir, handler_sys_rseq::sys_rseq,
    handler_sys_rt_sigaction::sys_rt_sigaction, handler_sys_rt_sigpending::sys_rt_sigpending,
    handler_sys_rt_sigqueueinfo::sys_rt_sigqueueinfo, handler_sys_rt_sigsuspend::sys_rt_sigsuspend,
    handler_sys_rt_sigtimedwait::sys_rt_sigtimedwait,
    handler_sys_rt_tgsigqueueinfo::sys_rt_tgsigqueueinfo,
    handler_sys_sched_get_priority_max::sys_sched_get_priority_max,
    handler_sys_sched_get_priority_min::sys_sched_get_priority_min,
    handler_sys_sched_getaffinity::sys_sched_getaffinity,
    handler_sys_sched_getattr::sys_sched_getattr, handler_sys_sched_getparam::sys_sched_getparam,
    handler_sys_sched_getscheduler::sys_sched_getscheduler,
    handler_sys_sched_rr_get_interval::sys_sched_rr_get_interval,
    handler_sys_sched_setaffinity::sys_sched_setaffinity,
    handler_sys_sched_setattr::sys_sched_setattr, handler_sys_sched_setparam::sys_sched_setparam,
    handler_sys_sched_setscheduler::sys_sched_setscheduler, handler_sys_sendfile::sys_sendfile,
    handler_sys_set_mempolicy::sys_set_mempolicy,
    handler_sys_set_mempolicy_home_node::sys_set_mempolicy_home_node,
    handler_sys_set_robust_list::sys_set_robust_list, handler_sys_setdomainname::sys_setdomainname,
    handler_sys_setfsgid::sys_setfsgid, handler_sys_setfsuid::sys_setfsuid,
    handler_sys_setgid::sys_setgid, handler_sys_setgroups::sys_setgroups,
    handler_sys_sethostname::sys_sethostname, handler_sys_setns::sys_setns,
    handler_sys_setpgid::sys_setpgid, handler_sys_setpriority::sys_setpriority,
    handler_sys_setregid::sys_setregid, handler_sys_setresgid::sys_setresgid,
    handler_sys_setresuid::sys_setresuid, handler_sys_setreuid::sys_setreuid,
    handler_sys_setrlimit::sys_setrlimit, handler_sys_setsid::sys_setsid,
    handler_sys_settimeofday::sys_settimeofday, handler_sys_setuid::sys_setuid,
    handler_sys_setxattr::sys_setxattr, handler_sys_shmem_create::sys_shmem_create,
    handler_sys_shmem_destroy::sys_shmem_destroy, handler_sys_shmem_map::sys_shmem_map,
    handler_sys_sigaction::sys_sigaction, handler_sys_sigaltstack::sys_sigaltstack,
    handler_sys_signalfd::sys_signalfd, handler_sys_sigprocmask::sys_sigprocmask,
    handler_sys_sigreturn::sys_sigreturn, handler_sys_sleep::sys_sleep,
    handler_sys_sock_register_buf::sys_sock_register_buf,
    handler_sys_sock_send_zc::sys_sock_send_zc, handler_sys_socket::sys_socket,
    handler_sys_socket_accept::sys_socket_accept, handler_sys_socket_accept4::sys_socket_accept4,
    handler_sys_socket_bind::sys_socket_bind, handler_sys_socket_connect::sys_socket_connect,
    handler_sys_socket_get_addr::sys_socket_get_addr,
    handler_sys_socket_getpeername::sys_socket_getpeername,
    handler_sys_socket_getsockname::sys_socket_getsockname,
    handler_sys_socket_getsockopt::sys_socket_getsockopt,
    handler_sys_socket_listen::sys_socket_listen, handler_sys_socket_recv::sys_socket_recv,
    handler_sys_socket_recvmmsg::sys_socket_recvmmsg,
    handler_sys_socket_recvmsg::sys_socket_recvmsg, handler_sys_socket_send::sys_socket_send,
    handler_sys_socket_sendmmsg::sys_socket_sendmmsg,
    handler_sys_socket_sendmsg::sys_socket_sendmsg,
    handler_sys_socket_setsockopt::sys_socket_setsockopt,
    handler_sys_socket_shutdown::sys_socket_shutdown, handler_sys_socketpair::sys_socketpair,
    handler_sys_splice::sys_splice, handler_sys_stat::sys_stat, handler_sys_statfs::sys_statfs,
    handler_sys_symlink::sys_symlink, handler_sys_symlinkat::sys_symlinkat,
    handler_sys_sync::sys_sync, handler_sys_sync_file_range::sys_sync_file_range,
    handler_sys_syncfs::sys_syncfs, handler_sys_sysinfo::sys_sysinfo,
    handler_sys_tcgetattr::sys_tcgetattr, handler_sys_tcsetattr::sys_tcsetattr,
    handler_sys_tee::sys_tee, handler_sys_tgkill::sys_tgkill, handler_sys_time::sys_time,
    handler_sys_timerfd_create::sys_timerfd_create,
    handler_sys_timerfd_settime::sys_timerfd_settime, handler_sys_times::sys_times,
    handler_sys_tkill::sys_tkill, handler_sys_truncate::sys_truncate, handler_sys_umask::sys_umask,
    handler_sys_umount2::sys_umount2, handler_sys_uname::sys_uname, handler_sys_unlink::sys_unlink,
    handler_sys_unlinkat::sys_unlinkat, handler_sys_unshare::sys_unshare,
    handler_sys_utime::sys_utime, handler_sys_utimensat::sys_utimensat,
    handler_sys_utimes::sys_utimes, handler_sys_vhangup::sys_vhangup,
    handler_sys_vmsplice::sys_vmsplice, handler_sys_wait4::sys_wait4,
    handler_sys_waitid::sys_waitid, handler_sys_write::sys_write, handler_sys_writev::sys_writev,
    handler_sys_yield::sys_yield,
};
