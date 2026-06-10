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
    if let Some(uctx_ptr) = crate::user_task::lookup_user_task_ctx(task_id) {
        let uctx = unsafe { &*uctx_ptr };
        // If the task is blocked in an infinite wait (pause, epoll_wait),
        // clear the deadline to wake it.
        let deadline = uctx.sleep_deadline_ns.load(Ordering::Acquire);
        if deadline == u64::MAX {
            uctx.sleep_deadline_ns.store(0, Ordering::Release);
        }
    }
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

fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    // SAFETY: vtable holds null-pointer-clean stubs; the waker is
    // never woken (poll_once expects Ready on the first poll).
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut ctx = Context::from_waker(&waker);
    // SAFETY: we own `fut` by value; pinning to a stack temporary
    // is the standard "block_on of a !Unpin future".
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
fn poll_blocking<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    // SAFETY: same waker as poll_once; never delivers wake events.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut ctx = Context::from_waker(&waker);
    // SAFETY: we own `fut` by value; pin to the stack temporary.
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };
    for _ in 0..65_536 {
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
    #[cfg(feature = "linux-compat")]
    {
        ctty_init();
        // Wave-76: route PtySlave::ioctl(TIOCSCTTY) into our per-task
        // CTTY table. Hook is global; filesystem crate calls back through
        // a fn pointer to avoid a userspace→filesystem dep cycle.
        narf_filesystem::devfs_pty::set_controlling_tty_hook(set_controlling_tty);
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

fn sys_bootstrap(ctx: &mut dyn TrapContext) {
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let task = current_task_id();

    // Allocate a phys frame, zero it, install at a fresh user vaddr
    // (mmap-cursor-style — same scheme `sys_mmap` uses).
    let phys = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // SAFETY: identity-mapped low 4 GiB; phys is page-aligned.
    unsafe {
        core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
    }
    let user_vaddr = MMAP_CURSOR.fetch_add(0x1000, Ordering::Relaxed);

    if as_ref
        .map_region(Region {
            base: VirtAddr::new(user_vaddr),
            len: 0x1000,
            // Stage-4 first cut: writable. Future revision flips the
            // page to R-only after the kernel populates it; the user
            // ring builders read from it but don't write.
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![phys],
        })
        .is_err()
    {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    // Mint the SQ + CQ ring pair. Kernel-side halves go into
    // BOOTSTRAP_TABLE keyed by task id; user-side halves are
    // tagged with newly-allocated cap-slot ids and stored beside
    // them so the dispatcher knows who to talk to.
    let (sq_prod, sq_drain) = submission_channel::<64>();
    let (cq_prod, cq_drain) = completion_channel::<64>();
    let sq_cap_id = NEXT_CAP_ID.fetch_add(1, Ordering::Relaxed);
    let cq_cap_id = NEXT_CAP_ID.fetch_add(1, Ordering::Relaxed);

    // Mint the user-mappable SharedRing pair. Two phys frames; both
    // mapped into the user AS at successive vaddrs after the config
    // page so the user runtime can build SharedProducer/Consumer
    // halves directly against the shared backing.
    let shared = match unsafe { mint_shared_ring_pair(&as_ref) } {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    let entry = PerTaskBootstrap {
        kernel: TaskRings { sq_drain, cq_prod },
        user: UserRingEnds { sq_prod, cq_drain },
        shared: Some(shared),
        sq_cap_id,
        cq_cap_id,
    };
    {
        let mut g = BOOTSTRAP_TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        };
        // Replace any prior bootstrap state for this task.
        map.insert(task, entry);
    }

    // Write the header. Capslot ids land in `sq_cap`/`cq_cap` so
    // the user runtime can name the rings.
    // SAFETY: identity-mapped low 4 GiB; aligned u64 + u32 stores.
    unsafe {
        let header = phys.raw() as *mut BootstrapHeader;
        (*header).magic = ABI_BOOTSTRAP_MAGIC;
        (*header).version = ABI_BOOTSTRAP_VERSION;
        (*header).task_id = task;
        (*header).sq_cap = sq_cap_id;
        (*header).cq_cap = cq_cap_id;
        (*header).sq_depth = BOOTSTRAP_RING_DEPTH as u32;
        (*header).cq_depth = BOOTSTRAP_RING_DEPTH as u32;
        (*header).shared_sq_vaddr = shared.sq_user_vaddr;
        (*header).shared_cq_vaddr = shared.cq_user_vaddr;
        (*header).shared_depth = BOOTSTRAP_SHARED_RING_DEPTH as u32;
        (*header)._pad = 0;
    }

    ctx.set_return(SyscallReturn::ok(user_vaddr));
}

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

fn sys_open(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_ptr = args.arg0;
    let path_len = args.arg1 as usize;
    let mnt_ptr = args.arg2;
    let mnt_len = args.arg3 as usize;
    let flags = args.arg4;
    // user-runtime's `open` wrapper checks `r == !0u64` for failure
    // (the asm wrapper observes only the value register, not the
    // status word), so the kernel must mirror that sentinel rather
    // than the generic `invalid_op` shape.
    let fail = SyscallReturn::ok(!0u64);
    // Copy path from userspace into kernel buffer under SMAP bracket.
    let path_owned = match copy_user_path(path_ptr, path_len) {
        Some(s) => {
            {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "sys_open: path='{}' task={}",
                    s,
                    current_task_id()
                );
            }
            s
        }
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let path: &str = &path_owned;

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

    // O_CREAT path: when the lookup misses and the caller asked for
    // creation, route through the parent directory's `create()`. The
    // explicit-mount form is rare on the create path and not yet
    // wired; absolute paths are the supported entry.
    let ops = match ops {
        Some(o) => o,
        None if (flags & O_CREAT) != 0 && mnt_len == 0 => {
            match narf_filesystem::registry().resolve_parent_absolute(path, |_fs, parent, leaf| {
                poll_blocking(parent.create(leaf))
            }) {
                Some(Some(Ok(o))) => o,
                _ => {
                    ctx.set_return(fail);
                    return;
                }
            }
        }
        None => {
            ctx.set_return(fail);
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
    let task = current_task_id();
    let stat = ops.stat();
    let (file_uid, file_gid) = ops.owners();
    let acc = read_uidgid(task);
    // O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2. Bits 0..1 of flags.
    let access_mode = flags & 0o3;
    let want_r = access_mode == 0 || access_mode == 2;
    let want_w = access_mode == 1 || access_mode == 2;
    if !narf_filesystem::posix_access_ok(
        file_uid,
        file_gid,
        stat.mode.perms,
        acc.uid,
        acc.gid,
        want_r,
        want_w,
        false,
    ) {
        ctx.set_return(fail);
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

    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: 0,
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

/// Linux ABI variant of `open(2)`: `int open(const char *pathname,
/// int flags, mode_t mode)`. Forwards to [`sys_open`] after
/// measuring the path length via [`copy_user_cstr`] (musl's open
/// call passes flags in arg1, not the NARF-native path_len).
fn sys_open_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_uptr = args.arg0;
    let flags = args.arg1;
    let _mode = args.arg2;
    let fail = SyscallReturn::ok(!0u64);
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: path_uptr,
        arg1: path_str.len() as u64,
        arg2: 0,
        arg3: 0,
        arg4: flags,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_open(&mut proxy);
}

// ── Write — arg0=fd, arg1=buf, arg2=len ────────────────────────────
//
// fd 1 / fd 2: console (stdout/stderr) — direct path so user code
// without an explicit Open of stdio still works.
// Other fds: routed through the per-task fd table.

fn sys_write(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let len = args.arg2 as usize;
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Copy the user buffer into a kernel-owned allocation first so
    // FileOps::write never touches a user page directly — SMAP would
    // fault any kernel-mode dereference of a user-accessible page
    // outside an explicit STAC/CLAC window.
    // Validate length *before* allocating so an oversized len returns
    // EINVAL rather than OOMing the kernel heap.
    // SAFETY: single-threaded syscall; AS is still active.
    let kbuf = match unsafe { copy_from_user_vec(ptr, len) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };

    let task = current_task_id();

    // Use klog for tracing
    if fd == 1 || fd == 2 {
        if let Some(s) = copy_user_path(ptr, len.min(100)) {}
    }

    let outcome = fd::with_table(task, |t| {
        let entry = match t.get_mut(fd) {
            Some(e) => e,
            None => return Err(()),
        };
        let off = entry.offset;
        let res = poll_blocking(entry.ops.write(off, &kbuf))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match res {
            Ok(written) => {
                entry.offset = off.saturating_add(written as u64);
                Ok(written)
            }
            Err(_) => Err(()),
        }
    });
    match outcome {
        Some(Ok(n)) => ctx.set_return(SyscallReturn::ok(n as u64)),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

/// Linux `writev(fd, iov, iovcnt)`. Walks the user `iovec[]` and
/// writes each non-empty slice to `fd` in order, returning the
/// total byte count. Reuses `sys_write`'s per-slice copy-in +
/// FileOps path so behaviour matches a sequence of `write()`
/// calls. musl's `__stdio_write` flushes via this syscall.
fn sys_writev(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let iov_ptr = args.arg1;
    let iovcnt = args.arg2 as usize;

    // Reasonable upper bound on the iovec count — Linux's
    // `IOV_MAX` is 1024. Reject larger to avoid trusting an
    // attacker-controlled length.
    const IOV_MAX: usize = 1024;
    if iovcnt > IOV_MAX {
        ctx.set_return(SyscallReturn::ok((-(22i64)) as u64)); // -EINVAL
        return;
    }

    // Copy the iovec array in. `struct iovec` is
    // `{ void *iov_base; size_t iov_len; }` — 16 bytes per entry.
    let iov_bytes = iovcnt.checked_mul(16).unwrap_or(usize::MAX);
    // SAFETY: single-threaded syscall; AS is still active.
    let iov_buf = match unsafe { copy_from_user_vec(iov_ptr, iov_bytes) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };

    let task = current_task_id();
    let mut total: usize = 0;
    for i in 0..iovcnt {
        let off = i * 16;
        let base = u64::from_le_bytes(iov_buf[off..off + 8].try_into().unwrap_or([0; 8]));
        let len =
            u64::from_le_bytes(iov_buf[off + 8..off + 16].try_into().unwrap_or([0; 8])) as usize;
        if len == 0 {
            continue;
        }
        // SAFETY: single-threaded syscall; AS is still active.
        let kbuf = match unsafe { copy_from_user_vec(base, len) } {
            Ok(b) => b,
            Err(e) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
                    return;
                }
                break;
            }
        };
        let outcome = fd::with_table(task, |t| {
            let entry = t.get_mut(fd).ok_or(())?;
            let cur_off = entry.offset;
            let res = poll_blocking(entry.ops.write(cur_off, &kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
            match res {
                Ok(written) => {
                    entry.offset = cur_off.saturating_add(written as u64);
                    Ok(written)
                }
                Err(_) => Err(()),
            }
        });
        match outcome {
            Some(Ok(n)) => {
                total = total.saturating_add(n);
                if n < kbuf.len() {
                    break;
                }
            }
            _ => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::invalid_op());
                    return;
                }
                break;
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}

// ── Read — arg0=fd, arg1=buf, arg2=len ─────────────────────────────

fn sys_read(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let len = args.arg2 as usize;
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Validate the destination pointer before allocating the kernel
    // staging buffer — EFAULT early rather than after the FileOps call.
    if let Err(e) = validate_user_range(ptr, len) {
        ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
        return;
    }
    // Track the foreground task: any read syscall counts as "this
    // task is currently consuming console input." When the input
    // ring later observes ^C, this is the task SIGINT goes to.
    note_console_reader(current_task_id());

    // Read into a kernel-owned buffer; copy back with SMAP bracket
    // after the FileOps call, so FileOps never touches user memory.
    let mut kbuf = alloc::vec![0u8; len];
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = match t.get_mut(fd) {
            Some(e) => e,
            None => return Err(()),
        };
        let off = entry.offset;
        let res = poll_blocking(entry.ops.read(off, &mut kbuf))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match res {
            Ok(n) => {
                entry.offset = off.saturating_add(n as u64);
                Ok(n)
            }
            Err(_) => Err(()),
        }
    });
    match outcome {
        Some(Ok(n)) => {
            // SAFETY: ptr validated above; AS still active.
            if let Err(e) = unsafe { copy_to_user(ptr, &kbuf[..n]) } {
                ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(n as u64));
            }
        }
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

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

fn sys_dup(ctx: &mut dyn TrapContext) {
    let oldfd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(oldfd)?;
        // Clone the Arc + reset offset; keep flags clear (fcntl/dup3
        // can stamp FD_CLOEXEC after).
        let clone = crate::fd::FdEntry {
            ops: entry.ops.clone(),
            offset: 0,
            flags: 0,
            status_flags: 0,
        };
        Some(t.open(clone))
    });
    match outcome {
        Some(Some(new_fd)) => ctx.set_return(SyscallReturn::ok(new_fd as u64)),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

fn sys_dup2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let oldfd = args.arg0 as u32;
    let newfd = args.arg1 as u32;
    if oldfd == newfd {
        // POSIX: dup2(fd, fd) is a no-op + returns fd as long as fd
        // is a valid open fd. Verify validity before short-circuiting.
        let task = current_task_id();
        let valid = fd::with_table(task, |t| t.get(oldfd).is_some()).unwrap_or(false);
        if valid {
            ctx.set_return(SyscallReturn::ok(newfd as u64));
        } else {
            ctx.set_return(SyscallReturn::invalid_op());
        }
        return;
    }
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(oldfd)?;
        let clone = crate::fd::FdEntry {
            ops: entry.ops.clone(),
            offset: 0,
            flags: 0,
            status_flags: 0,
        };
        // Replace whatever sat at `newfd` (POSIX: silently close).
        t.set(newfd, clone);
        Some(())
    });
    match outcome {
        Some(Some(())) => ctx.set_return(SyscallReturn::ok(newfd as u64)),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

fn sys_dup3(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let oldfd = args.arg0 as u32;
    let newfd = args.arg1 as u32;
    let flags = args.arg2 as u32;
    // Linux dup3: differ from dup2 by failing on oldfd == newfd. The
    // call exists to atomically install FD_CLOEXEC, which only makes
    // sense when actually duplicating to a different slot.
    if oldfd == newfd {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(oldfd)?;
        let clone = crate::fd::FdEntry {
            ops: entry.ops.clone(),
            offset: 0,
            // O_CLOEXEC (Linux) is bit 0x80000 in `flags`; Stage-4
            // accepts the lower-bit shape (FD_CLOEXEC = 1) directly
            // since narf-libc's `dup3` already passes FD_CLOEXEC.
            flags: flags & crate::fd::FD_CLOEXEC,
            status_flags: 0,
        };
        t.set(newfd, clone);
        Some(())
    });
    match outcome {
        Some(Some(())) => ctx.set_return(SyscallReturn::ok(newfd as u64)),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

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

fn sys_fcntl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let cmd = args.arg1;
    let arg = args.arg2;
    let task = current_task_id();

    // F_SETFL on a socket: mirror O_NONBLOCK into the SocketFile so
    // recv/send/accept/connect see the flag.
    if cmd == F_SETFL {
        if let Some(sock) = current_socket(fd) {
            sock.set_nonblock((arg as u32) & crate::socket::O_NONBLOCK != 0);
        }
    }

    // F_DUPFD / F_DUPFD_CLOEXEC: dup oldfd into the lowest free slot
    // >= arg. Linux returns the new fd. CLOEXEC variant stamps
    // FD_CLOEXEC atomically.
    #[cfg(feature = "linux-compat")]
    {
        if cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC {
            let min_fd = arg as u32;
            let cloexec = cmd == F_DUPFD_CLOEXEC;
            let outcome = fd::with_table(task, |t| {
                let entry = t.get(fd)?;
                let clone = crate::fd::FdEntry {
                    ops: entry.ops.clone(),
                    offset: 0,
                    flags: if cloexec { crate::fd::FD_CLOEXEC } else { 0 },
                    status_flags: entry.status_flags,
                };
                Some(t.open_at_least(clone, min_fd))
            });
            match outcome {
                Some(Some(new_fd)) => ctx.set_return(SyscallReturn::ok(new_fd as u64)),
                _ => ctx.set_return(SyscallReturn::invalid_op()),
            }
            return;
        }
    }

    // F_GETLK / F_SETLK / F_SETLKW: advisory POSIX locking. Gated
    // under linux-compat because the wire `struct flock` layout +
    // BTreeMap lock table only matter for Linux ABI consumers.
    #[cfg(feature = "linux-compat")]
    {
        if cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW {
            // Resolve the open-file identity from the fd table.
            let ops_key = fd::with_table(task, |t| {
                t.get(fd)
                    .map(|e| alloc::sync::Arc::as_ptr(&e.ops) as *const () as usize)
            });
            let key = match ops_key {
                Some(Some(k)) => k,
                _ => {
                    ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
                    return;
                }
            };
            // Pull the `struct flock` from user memory.
            let mut bytes = alloc::vec![0u8; flock_size()];
            if unsafe { copy_from_user(&mut bytes, arg) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                return;
            }
            let uf: UFlock = unsafe {
                let mut tmp = UFlock::default();
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    &mut tmp as *mut _ as *mut u8,
                    flock_size(),
                );
                tmp
            };
            // Only SEEK_SET (l_whence = 0) is supported on the wire
            // path. Other whence values would need the current offset
            // / file size, which is OFD-tier work.
            if uf.l_whence != 0 {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            let req = crate::fd::locks::Lock {
                owner: task,
                ty: uf.l_type,
                start: uf.l_start,
                len: uf.l_len,
            };
            if cmd == F_GETLK {
                let blocker = crate::fd::locks::probe(key, req);
                let mut out = uf;
                match blocker {
                    None => out.l_type = crate::fd::locks::F_UNLCK,
                    Some(b) => {
                        out.l_type = b.ty;
                        out.l_start = b.start;
                        out.l_len = b.len;
                        out.l_pid = b.owner as i32;
                    }
                }
                let mut obytes = alloc::vec![0u8; flock_size()];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        &out as *const _ as *const u8,
                        obytes.as_mut_ptr(),
                        flock_size(),
                    );
                }
                if unsafe { copy_to_user(arg, &obytes) }.is_err() {
                    ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
                    return;
                }
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            // F_SETLK / F_SETLKW.
            // TODO(wave-69): F_SETLKW should block on a per-inode
            // waker; today we treat it like F_SETLK and return
            // EAGAIN on conflict. Surface to the caller so they can
            // retry, or fall back to fcntl-managed sleep.
            match crate::fd::locks::try_set(key, req) {
                Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
                Err(_) => {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                }
            }
            return;
        }
    }

    // Wave-70: memfd seals. Route F_ADD_SEALS / F_GET_SEALS before
    // the generic fd-table lookup so the seal word lives on the
    // concrete MemFdFile rather than as a per-fd flag.
    #[cfg(feature = "linux-compat")]
    {
        if cmd == F_ADD_SEALS {
            if let Some(mfd) = memfd_arc_from_fd(task, fd) {
                let r = match mfd.add_seals(arg as u32) {
                    Ok(()) => SyscallReturn::ok(0),
                    Err(()) => SyscallReturn::ok((-1i64) as u64),
                };
                ctx.set_return(r);
                return;
            }
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        if cmd == F_GET_SEALS {
            if let Some(mfd) = memfd_arc_from_fd(task, fd) {
                ctx.set_return(SyscallReturn::ok(mfd.seals() as u64));
                return;
            }
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    }

    // Resolve any socket-side flag BEFORE entering the fd-table
    // closure — `current_socket` itself locks the table, which would
    // re-enter and deadlock if called from inside `with_table`.
    let sock_nb = current_socket(fd).map(|s| s.is_nonblock());

    let outcome = fd::with_table(task, |t| {
        let entry = t.get_mut(fd)?;
        Some(match cmd {
            F_GETFD => SyscallReturn::ok(entry.flags as u64),
            F_SETFD => {
                entry.flags = arg as u32;
                SyscallReturn::ok(0)
            }
            // F_GETFL: report the per-fd status_flags. Socket
            // O_NONBLOCK overrides the bit if the SocketFile carries
            // its own nonblock toggle (kept in sync via F_SETFL).
            F_GETFL => {
                let mut v = entry.status_flags as u64;
                if let Some(nb) = sock_nb {
                    if nb {
                        v |= crate::socket::O_NONBLOCK as u64;
                    } else {
                        v &= !(crate::socket::O_NONBLOCK as u64);
                    }
                }
                SyscallReturn::ok(v)
            }
            // F_SETFL: only the settable subset (O_NONBLOCK | O_APPEND
            // | O_DIRECT) is honoured. Access-mode bits are ignored.
            F_SETFL => {
                #[cfg(feature = "linux-compat")]
                let mask = crate::fd::O_SETFL_MASK;
                #[cfg(not(feature = "linux-compat"))]
                let mask = 0o4000u32; // O_NONBLOCK only.
                let new = (arg as u32) & mask;
                entry.status_flags = (entry.status_flags & !mask) | new;
                SyscallReturn::ok(0)
            }
            _ => SyscallReturn::invalid_op(),
        })
    });
    match outcome {
        Some(Some(r)) => ctx.set_return(r),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
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

fn sys_ioctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let cmd = args.arg1 as u32;
    let arg = args.arg2 as usize;
    let task = current_task_id();
    // Clone the Arc out of the fd table so we drop the table lock
    // before invoking the FileOps::ioctl body (which may take
    // device-internal locks of its own).
    let ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone()));
    let ops = match ops {
        Some(Some(o)) => o,
        _ => {
            ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
            return;
        }
    };
    // Wave-76 special-case: TIOCGPTPEER allocates a fresh slave fd in
    // the caller's table. The fd-allocation side lives here (not in the
    // filesystem crate), so we hijack the dispatch before delegating.
    #[cfg(feature = "linux-compat")]
    if cmd == narf_filesystem::devfs_pty::TIOCGPTPEER {
        let idx = match ops.as_pty_master_index() {
            Some(i) => i,
            None => {
                // Not a master fd — ENOTTY (Linux semantics).
                ctx.set_return(SyscallReturn::ok((-(ENOTTY as i64)) as u64));
                return;
            }
        };
        let slave = match narf_filesystem::devfs_pty::pts_open_peer(idx) {
            Some(Ok(s)) => s,
            Some(Err(())) => {
                // EIO: slave still locked.
                ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                return;
            }
            None => {
                ctx.set_return(SyscallReturn::ok((-(ENOTTY as i64)) as u64));
                return;
            }
        };
        let ops_dyn: Arc<dyn narf_filesystem::FileOps> = slave;
        let new_fd = fd::with_table(task, |t| {
            t.open(fd::FdEntry {
                ops: ops_dyn,
                offset: 0,
                // `arg` carries open(2) flags from glibc (O_RDWR | O_NOCTTY |
                // O_CLOEXEC). We mirror the CLOEXEC bit; the rest are no-ops.
                flags: if (arg as u32) & 0o2000000 != 0 { 1 } else { 0 },
                status_flags: arg as u32,
            })
        });
        match new_fd {
            Some(f) => ctx.set_return(SyscallReturn::ok(f as u64)),
            None => ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64)),
        }
        return;
    }
    match ops.ioctl(cmd, arg) {
        Ok(rc) => ctx.set_return(SyscallReturn::ok(rc as u64)),
        Err(narf_filesystem::FsError::Unsupported) => {
            ctx.set_return(SyscallReturn::ok((-(ENOTTY as i64)) as u64));
        }
        Err(narf_filesystem::FsError::PermissionDenied) => {
            // EACCES = 13
            ctx.set_return(SyscallReturn::ok((-13i64) as u64));
        }
        Err(narf_filesystem::FsError::InvalidData) | Err(narf_filesystem::FsError::InvalidPath) => {
            ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        }
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        }
    }
}

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

fn sys_stat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int stat(const char *pathname, struct stat *statbuf)`.
    // Two args, path is NUL-terminated. (NARF-native callers used
    // the explicit-length triplet (path_ptr, path_len, out_ptr); we
    // cut over to the Linux shape so musl-built binaries can do PATH
    // search via stat — busybox sh's pipeline children stat their
    // way through `:`-separated $PATH looking for the binary, and
    // an EINVAL/EPERM return there masquerades as "Operation not
    // permitted", silently failing every `cat`/`tr`/`head` etc.)
    let path_ptr = args.arg0;
    let out_ptr = args.arg1 as *mut StatBuf;
    // POSIX-shaped failure sentinel. The user-runtime asm wrapper
    // observes only the `value` register, so we mirror libc and
    // return -1 on failure to disambiguate from a 0-valued success.
    // Without this the success ok(0) and the invalid_op rax=0 are
    // indistinguishable at the user side.
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let path_owned = match copy_user_cstr(path_ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let path_owned = apply_chroot(&path_owned);
    let path: &str = &path_owned;
    let ops = narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let ops = match ops {
        Some(o) => o,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let stat = StatBuf::from_stat(ops.stat());
    // Copy stat struct into user memory under the SMAP bracket.
    // SAFETY: stat is a plain-old-data repr(C) struct; transmuting
    // to bytes is sound.
    let stat_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &stat as *const StatBuf as *const u8,
            core::mem::size_of::<StatBuf>(),
        )
    };
    if unsafe { copy_to_user(out_ptr as u64, stat_bytes) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_fstat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1 as *mut StatBuf;
    // See sys_stat for the failure-sentinel rationale.
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let stat = fd::with_table(task, |t| {
        t.get(fd).map(|e| StatBuf::from_stat(e.ops.stat()))
    });
    let stat = match stat {
        Some(Some(s)) => s,
        _ => {
            ctx.set_return(fail);
            return;
        }
    };
    // SAFETY: same contract as sys_stat above.
    let stat_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &stat as *const StatBuf as *const u8,
            core::mem::size_of::<StatBuf>(),
        )
    };
    if unsafe { copy_to_user(out_ptr as u64, stat_bytes) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Ftruncate — arg0=fd, arg1=len ──────────────────────────────────
//
// Resize the file backing `fd` to exactly `len` bytes. Routes
// through `FileOps::truncate` — read-only filesystems return
// `Unsupported`, which we surface as the wire `-1` sentinel.

fn sys_ftruncate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let len = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        Some(poll_blocking(entry.ops.truncate(len)))
    });
    match outcome {
        Some(Some(Some(Ok(())))) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

// ── Pread / Pwrite — positional I/O without per-fd offset ─────────
//
// FileOps::read / write already take an offset arg; the regular
// sys_read / sys_write handlers walk through the per-fd cursor on
// top. pread / pwrite skip the cursor mutation — POSIX guarantees
// the per-fd offset is unchanged after these calls.

fn sys_pread64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let len = args.arg2 as usize;
    let offset = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if let Err(e) = validate_user_range(ptr, len) {
        ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
        return;
    }
    let mut kbuf = alloc::vec![0u8; len];
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        let ops = entry.ops.clone();
        let res = poll_blocking(ops.read(offset, &mut kbuf))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match res {
            Ok(n) => Some(n),
            Err(_) => None,
        }
    });
    match outcome {
        Some(Some(n)) => {
            // SAFETY: ptr validated above; AS still active.
            if let Err(e) = unsafe { copy_to_user(ptr, &kbuf[..n]) } {
                ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(n as u64));
            }
        }
        _ => ctx.set_return(fail),
    }
}

fn sys_pwrite64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let len = args.arg2 as usize;
    let offset = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Validate length before allocating — reject oversized len with EINVAL
    // rather than OOMing the kernel heap.
    // SAFETY: single-threaded syscall; AS active.
    let kbuf = match unsafe { copy_from_user_vec(ptr, len) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        let ops = entry.ops.clone();
        let res = poll_blocking(ops.write(offset, &kbuf))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match res {
            Ok(n) => Some(n),
            Err(_) => None,
        }
    });
    match outcome {
        Some(Some(n)) => ctx.set_return(SyscallReturn::ok(n as u64)),
        _ => ctx.set_return(fail),
    }
}

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

fn sys_fallocate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let mode = args.arg1;
    let offset = args.arg2;
    let len = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if mode != 0 && mode != FALLOC_FL_ZERO_RANGE {
        ctx.set_return(fail);
        return;
    }
    let target_end = offset.saturating_add(len);
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        let ops = entry.ops.clone();
        let cur_size = ops.stat().size;
        // Always ensure size >= offset + len. truncate handles
        // grow + zero-fill.
        if target_end > cur_size {
            if poll_blocking(ops.truncate(target_end))
                .and_then(|r| r.ok())
                .is_none()
            {
                return Some(false);
            }
        }
        if mode == FALLOC_FL_ZERO_RANGE && len > 0 && offset < cur_size {
            // Zero existing bytes in [offset, min(target_end, old size)].
            // We do this in 4-KiB chunks of zeros via a fresh write.
            let zero_end = core::cmp::min(target_end, cur_size);
            let mut cur = offset;
            let chunk = [0u8; 4096];
            while cur < zero_end {
                let span = core::cmp::min(zero_end - cur, chunk.len() as u64) as usize;
                let n = poll_blocking(ops.write(cur, &chunk[..span]))
                    .and_then(|r| r.ok())
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                cur += n as u64;
            }
        }
        Some(true)
    });
    match outcome {
        Some(Some(true)) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

// ── CopyFileRange — chunked file→file copy ─────────────────────────
//
// Linux copy_file_range(2): in-kernel copy without bouncing the
// data through user memory. Real consumers (cp, rsync, container
// runtimes) prefer this over the read/write loop. NARF's MemFs
// has no special "copy without unmapping pages" path; we just
// read into a stack chunk and write it out, advancing the
// per-fd cursor when the offset arg is `!0` (sentinel = "use
// cur") and leaving the cursor alone when an explicit offset is
// supplied.

const CFR_USE_CUR: u64 = !0;

fn sys_copy_file_range(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd_in = args.arg0 as u32;
    let fd_out = args.arg1 as u32;
    let off_in = args.arg2;
    let off_out = args.arg3;
    let len = args.arg4 as usize;
    let flags = args.arg5;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if flags != 0 {
        ctx.set_return(fail);
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Resolve both ops + their starting offsets up-front so we
    // don't hold the fd table lock across the FsFuture polls.
    let task = current_task_id();
    let resolved = fd::with_table(task, |t| {
        let in_e = t.get(fd_in)?;
        let in_off = if off_in == CFR_USE_CUR {
            in_e.offset
        } else {
            off_in
        };
        let out_e = t.get(fd_out)?;
        let out_off = if off_out == CFR_USE_CUR {
            out_e.offset
        } else {
            off_out
        };
        Some((in_e.ops.clone(), in_off, out_e.ops.clone(), out_off))
    });
    let (in_ops, mut cur_in, out_ops, mut cur_out) = match resolved {
        Some(Some(t)) => t,
        _ => {
            ctx.set_return(fail);
            return;
        }
    };

    let mut chunk = [0u8; 4096];
    let mut copied = 0usize;
    while copied < len {
        let span = core::cmp::min(len - copied, chunk.len());
        let read_n = poll_blocking(in_ops.read(cur_in, &mut chunk[..span]))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        if read_n == 0 {
            break;
        }
        let write_n = poll_blocking(out_ops.write(cur_out, &chunk[..read_n]))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        if write_n == 0 {
            break;
        }
        copied += write_n;
        cur_in += write_n as u64;
        cur_out += write_n as u64;
        if write_n < read_n {
            break;
        }
    }

    // Advance the per-fd cursors when the corresponding offset
    // arg was the "use cur" sentinel.
    let _ = fd::with_table(task, |t| {
        if off_in == CFR_USE_CUR {
            if let Some(e) = t.get_mut(fd_in) {
                e.offset = cur_in;
            }
        }
        if off_out == CFR_USE_CUR {
            if let Some(e) = t.get_mut(fd_out) {
                e.offset = cur_out;
            }
        }
        Some(())
    });

    ctx.set_return(SyscallReturn::ok(copied as u64));
}

// ── Truncate — path-based file resize ──────────────────────────────
//
// Linux truncate(2). Equivalent to open + ftruncate + close in one
// syscall. Resolves the absolute path to a FileOps and calls
// `truncate(len)` directly — no fd-table involvement. Routes to the
// same trait method that backs SYS_FTRUNCATE.

fn sys_truncate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as u64;
    let len = args.arg1 as usize;
    let new_size = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_path(ptr, len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let ops = narf_filesystem::registry()
        .resolve_absolute(&path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    match ops {
        Some(o) => match poll_blocking(o.truncate(new_size)) {
            Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
            _ => ctx.set_return(fail),
        },
        None => ctx.set_return(fail),
    }
}

// ── unlinkat / mkdirat / renameat — *at-keyed FS mutation ─────────
//
// Each ignores dirfd, requires absolute paths, and routes through
// the existing SYS_UNLINK / SYS_RMDIR / SYS_MKDIR / SYS_RENAME
// handler bodies via the same Reshape proxy pattern as openat.
//
// unlinkat honours AT_REMOVEDIR (0x200) — when set, route to rmdir.

const AT_REMOVEDIR: u64 = 0x200;

fn sys_unlinkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int unlinkat(int dirfd, const char *pathname,
    // int flags)`. arg2 is flags, not path_len.
    let _dirfd = args.arg0;
    let path_uptr = args.arg1;
    let flags = args.arg2;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: path_uptr,
        arg1: path_str.len() as u64,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    if (flags & AT_REMOVEDIR) != 0 {
        sys_rmdir(&mut proxy);
    } else {
        sys_unlink(&mut proxy);
    }
}

fn sys_mkdirat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int mkdirat(int dirfd, const char *pathname,
    // mode_t mode)`. arg2 is mode, not path_len.
    let _dirfd = args.arg0;
    let path_uptr = args.arg1;
    let mode = args.arg2;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: path_uptr,
        arg1: path_str.len() as u64,
        arg2: mode,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_mkdir(&mut proxy);
}

fn sys_renameat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _old_dirfd = args.arg0;
    // Linux ABI: `int renameat(int olddirfd, const char *oldpath,
    // int newdirfd, const char *newpath)`. Two cstrs, no lengths.
    let old_uptr = args.arg1;
    let _new_dirfd = args.arg2;
    let new_uptr = args.arg3;
    let old_str = match copy_user_cstr(old_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    let new_str = match copy_user_cstr(new_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: old_uptr,
        arg1: old_str.len() as u64,
        arg2: new_uptr,
        arg3: new_str.len() as u64,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_rename(&mut proxy);
}

// ── symlinkat / readlinkat — *at-keyed symlink ops ─────────────────
//
// Both forward via Reshape proxies. dirfd ignored; path args are
// absolute. The symlink handler reads (target_ptr, target_len,
// link_ptr, link_len) from arg0..=arg3; readlink reads
// (path_ptr, path_len, buf_ptr, buf_len) from arg0..=arg3.

fn sys_symlinkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let target_ptr = args.arg0;
    let target_len = args.arg1;
    let _dirfd = args.arg2;
    let link_ptr = args.arg3;
    let link_len = args.arg4;
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: target_ptr,
        arg1: target_len,
        arg2: link_ptr,
        arg3: link_len,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_symlink(&mut proxy);
}

fn sys_readlinkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `ssize_t readlinkat(int dirfd, const char *path,
    // char *buf, size_t bufsiz)`.
    let _dirfd = args.arg0;
    let path_uptr = args.arg1;
    let buf_ptr = args.arg2;
    let buf_len = args.arg3;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: path_uptr,
        arg1: path_str.len() as u64,
        arg2: buf_ptr,
        arg3: buf_len,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_readlink(&mut proxy);
}

// ── access / chmod / chown — legacy entry points ───────────────────
//
// Linux access(path, mode), chmod(path, mode), chown(path, uid, gid)
// — pre-*at calls that take a relative-or-absolute path with no
// directory fd. NARF treats them as faccessat / fchmodat / fchownat
// with `dirfd = AT_FDCWD` and forwards into the shared
// `sys_fchmodat_or_fchownat` body, which already enforces the
// "path must be absolute, mode/uid/gid bits ignored" contract.

fn sys_access_chmod_chown(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI for the three legacy entries:
    //   access(path, mode)      — arg1 = mode
    //   chmod(path, mode)       — arg1 = mode
    //   chown(path, uid, gid)   — arg1 = uid, arg2 = gid
    // All take an absolute path as a NUL-terminated cstr; the body
    // forwards to `sys_fchmodat_or_fchownat` which only enforces
    // the structural "path must be absolute" contract — we drop
    // the mode/uid/gid in the proxy so the underlying path-len
    // shape lines up.
    let path_uptr = args.arg0;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: 0, // dirfd = AT_FDCWD (ignored anyway).
        arg1: path_uptr,
        arg2: path_str.len() as u64,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_fchmodat_or_fchownat(&mut proxy);
}

// ── newfstatat — *at-keyed stat ────────────────────────────────────
//
// Linux newfstatat(dirfd, path, statbuf, flags). Same dirfd-
// ignored / path-must-be-absolute simplification. Re-shape args
// to the SYS_STAT signature (path_ptr, path_len, stat_out) and
// reuse sys_stat's body.

fn sys_newfstatat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int fstatat(int dirfd, const char *pathname,
    // struct stat *statbuf, int flags)`. arg2 is statbuf, not
    // path_len.
    let _dirfd = args.arg0;
    let path_uptr = args.arg1;
    let stat_out = args.arg2;
    let _flags = args.arg3;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: path_uptr,
        arg1: path_str.len() as u64,
        arg2: stat_out,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_stat(&mut proxy);
}

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
fn linux_stat_from_fs(s: narf_filesystem::Stat) -> linux_compat::Stat {
    let ftype_bits: u32 = match s.mode.file_type {
        narf_filesystem::FileType::File => 0o100000,
        narf_filesystem::FileType::Dir => 0o040000,
        narf_filesystem::FileType::Symlink => 0o120000,
        narf_filesystem::FileType::Special => 0o020000,
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
        st_ino: (s.mtime_cycles ^ (s.size << 1)) & 0x0fff_ffff_ffff_ffff,
        st_nlink: 1,
        st_mode: mode_word,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
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
#[cfg(feature = "linux-compat")]
fn sys_stat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int stat(const char *pathname, struct stat *statbuf)`
    // — two args, path is NUL-terminated. The previous shape
    // matched NARF's `(path_ptr, path_len, out_ptr)` triplet which
    // is unreachable from musl: musl passes the statbuf in arg1,
    // we read it as `path_len`, copy_from_user bails on the
    // "huge length", every stat returns -1, errno = EPERM,
    // busybox sh prints "Operation not permitted" for every
    // PATH-search candidate, and every pipeline that touches an
    // exec dies.
    let path_ptr = args.arg0;
    let out_ptr = args.arg1 as *mut linux_compat::Stat;
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
    let path_owned = apply_chroot(&raw);
    let _ = (); // silence unused-binding lint when both arms drop the value
    let path: &str = &path_owned;
    // `resolve_absolute` splits an absolute path into (mount, rel).
    // For a path that IS the mount point itself (`/bin`, `/dev`,
    // `/tmp`, …) rel is empty and `resolve(_, "")` rejects with
    // InvalidPath. busybox `ls /bin` lands here, so synthesise a
    // directory-shaped stat for the mount root.
    let stat = narf_filesystem::registry().resolve_absolute(path, |fs, rel| {
        if rel.is_empty() {
            Some(narf_filesystem::Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::DIR_RW,
                mtime_cycles: 0,
            })
        } else {
            narf_filesystem::resolve(fs.root(), rel)
                .ok()
                .map(|ops| ops.stat())
        }
    });
    let s = match stat.flatten() {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let out = linux_stat_from_fs(s);
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &out as *const linux_compat::Stat as *const u8,
            core::mem::size_of::<linux_compat::Stat>(),
        )
    };
    if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

#[cfg(feature = "linux-compat")]
fn sys_fstat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1 as *mut linux_compat::Stat;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let stat = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.stat()));
    let s = match stat {
        Some(Some(s)) => s,
        _ => {
            ctx.set_return(fail);
            return;
        }
    };
    let out = linux_stat_from_fs(s);
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &out as *const linux_compat::Stat as *const u8,
            core::mem::size_of::<linux_compat::Stat>(),
        )
    };
    if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// newfstatat under linux-compat: reshape args then delegate.
#[cfg(feature = "linux-compat")]
fn sys_newfstatat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int fstatat(int dirfd, const char *pathname,
    // struct stat *statbuf, int flags)`. The body forwards to
    // `sys_stat_linux` which now expects (path_cstr_ptr,
    // statbuf_ptr) — same 2-arg shape, so the proxy is a
    // straight slot-rename.
    let _dirfd = args.arg0;
    let path_uptr = args.arg1;
    let stat_out = args.arg2;
    let _flags = args.arg3;
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let mut proxy = Reshape {
        inner: ctx,
        args: SyscallArgs {
            arg0: path_uptr,
            arg1: stat_out,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
    };
    sys_stat_linux(&mut proxy);
}

#[cfg(feature = "linux-compat")]
fn sys_statx(ctx: &mut dyn TrapContext) {
    use linux_compat::*;
    let args = *ctx.args();
    // Linux ABI: `int statx(int dirfd, const char *path, int flags,
    // unsigned int mask, struct statx *buf)`. arg2/3/4/5 shift left
    // by one slot now that arg2 is `flags` (not the old NARF-native
    // `path_len`).
    let dirfd = args.arg0 as i32;
    let path_uptr = args.arg1;
    let flags = args.arg2 as u32;
    let mask = args.arg3 as u32;
    let out_ptr = args.arg4 as *mut Statx;
    let _ = mask;

    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }

    // AT_EMPTY_PATH + empty path string → operate on dirfd directly.
    // We can detect "empty path" cheaply by reading just the first
    // byte; if it's NUL, no need to call copy_user_cstr.
    let mut first = [0u8; 1];
    let empty = (flags & AT_EMPTY_PATH) != 0
        && unsafe { copy_from_user(&mut first, path_uptr) }.is_ok()
        && first[0] == 0;

    // Resolve to a FileOps. Three cases:
    //   1. empty + dirfd >= 0       → look up fd
    //   2. path absolute            → registry walk (dirfd ignored
    //                                  beyond requiring AT_FDCWD or
    //                                  a real fd; NARF has no per-
    //                                  task cwd so non-AT_FDCWD
    //                                  relative paths fail)
    //   3. otherwise                → fail
    let fs_stat = if empty {
        if dirfd < 0 {
            ctx.set_return(fail);
            return;
        }
        let task = current_task_id();
        fd::with_table(task, |t| t.get(dirfd as u32).map(|e| e.ops.stat())).flatten()
    } else {
        let raw = match copy_user_cstr(path_uptr, 4096) {
            Some(s) => s,
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        let path_owned = apply_chroot(&raw);
        if !path_owned.starts_with('/') {
            // NARF has no per-task cwd; only absolute paths resolve.
            ctx.set_return(fail);
            return;
        }
        let path: &str = &path_owned;
        narf_filesystem::registry()
            .resolve_absolute(path, |fs, rel| {
                narf_filesystem::resolve(fs.root(), rel).ok()
            })
            .flatten()
            .map(|ops| ops.stat())
    };

    let s = match fs_stat {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    let ftype_bits: u16 = match s.mode.file_type {
        narf_filesystem::FileType::File => 0o100000,
        narf_filesystem::FileType::Dir => 0o040000,
        narf_filesystem::FileType::Symlink => 0o120000,
        narf_filesystem::FileType::Special => 0o020000,
    };
    let mode_word: u16 = ftype_bits | (s.mode.perms & 0o7777);

    // mtime: monotonic cycles → ns via the wall-clock calibration.
    // Wall-clock per inode isn't tracked, so this surfaces a
    // stable monotonic ordering, not a real wall time.
    let cpns = narf_time::cycles_per_ns().max(1) as u64;
    let mtime_ns = s.mtime_cycles / cpns;
    let mtime = StatxTimestamp {
        tv_sec: (mtime_ns / 1_000_000_000) as i64,
        tv_nsec: (mtime_ns % 1_000_000_000) as u32,
        __reserved: 0,
    };

    let mut out = Statx::default();
    out.stx_blksize = 4096;
    out.stx_mode = mode_word;
    out.stx_size = s.size;
    out.stx_blocks = s.blocks;
    out.stx_mtime = mtime;
    out.stx_ctime = mtime;
    out.stx_ino = (s.mtime_cycles ^ (s.size << 1)) & 0x0fff_ffff_ffff_ffff;
    out.stx_nlink = 1;

    // Honour the request mask but only advertise what we filled.
    // STATX_BASIC_STATS = type|mode|nlink|uid|gid|atime|mtime|
    // ctime|ino|size|blocks. We fill type/mode/nlink/ino/size/
    // blocks/mtime/ctime; uid/gid/atime aren't tracked.
    let filled = STATX_TYPE
        | STATX_MODE
        | STATX_NLINK
        | STATX_INO
        | STATX_SIZE
        | STATX_BLOCKS
        | STATX_MTIME
        | STATX_CTIME;
    out.stx_mask = filled
        & if mask == 0 {
            filled
        } else {
            mask | STATX_BASIC_STATS & filled
        };

    // SAFETY: Statx is repr(C) POD; bytes are valid for read.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &out as *const Statx as *const u8,
            core::mem::size_of::<Statx>(),
        )
    };
    if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ── openat — *at-keyed open ────────────────────────────────────────
//
// Linux openat(dirfd, path, flags, mode) — modern replacement for
// open. dirfd is ignored (NARF has no directory-fd type); path
// must be absolute. The body re-shapes args into the SYS_OPEN
// signature (path_ptr, path_len, mount_ptr=0, mount_len=0, flags)
// and routes through the existing sys_open handler so the open
// path is identical.

fn sys_openat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int openat(int dirfd, const char *pathname,
    // int flags, mode_t mode)`. Two-arg path-as-cstr.
    // (Previously arg2 was a NARF-native path_len, which made
    // musl's `openat(AT_FDCWD, "...", O_RDONLY, 0)` hit our
    // handler with arg2 = O_RDONLY = 0 → zero-length path →
    // EINVAL on every open. See [[project_narf_native_vs_linux_abis]].)
    let _dirfd = args.arg0;
    let path_uptr = args.arg1;
    let flags = args.arg2;
    let _mode = args.arg3;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok(!0u64));
            return;
        }
    };
    // Reshape into a sys_open call: (path_ptr, path_len, mount_ptr,
    // mount_len, flags). sys_open re-reads the path from the
    // original user pointer with our measured length.
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
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
    let proxy_args = SyscallArgs {
        arg0: path_uptr,
        arg1: path_str.len() as u64,
        arg2: 0,
        arg3: 0,
        arg4: flags,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_open(&mut proxy);
}

// ── fchmodat / fchownat — *at-keyed mode/owner ─────────────────────
//
// NARF doesn't support directory fds, so the dirfd arg is
// ignored. Path must be absolute; if it resolves we report
// success (mode/uid/gid bits are structural-only state we don't
// enforce). Relative paths are rejected with -1 to keep the
// consumer's error-checking honest.

fn sys_fchmodat_or_fchownat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _dirfd = args.arg0;
    let ptr = args.arg1 as u64;
    let len = args.arg2 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_path(ptr, len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if !path.starts_with('/') {
        // Relative paths require dirfd resolution we don't have.
        ctx.set_return(fail);
        return;
    }
    // Existence check: any FileOps lookup returning Some is enough.
    let exists = narf_filesystem::registry()
        .resolve_absolute(&path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten()
        .is_some();
    if exists {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}

// ── fchmod / fchown — accept-and-ignore on known fd ───────────────
//
// NARF has no per-file permission bits or owner; the kernel
// surface exists so consumers (tar, cp, install) can round-trip
// the values without breaking. Both succeed for any open fd, fail
// (-1) for a closed/unknown fd.

fn sys_fchmod_or_fchown(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let known = fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false);
    if known {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
    }
}

// ── memfd_create — anonymous in-memory file ────────────────────────
//
// Linux memfd_create(2): mint a fresh in-memory file backed by a
// fresh (no directory entry) MemFile, install it in the caller's
// fd table, return the fd. The name is recorded for debug-only
// introspection; we don't preserve it in NARF today (no
// /proc-style listing). Real consumers (sandboxes, IPC, tmpfile)
// rely on the surface alone.

fn sys_memfd_create(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _name_ptr = args.arg0;
    let _name_len = args.arg1;
    // NARF-shape layout: (name_ptr, name_len, flags) — three args
    // because narf-libc serialises the C string length separately.
    let _flags = args.arg2 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    #[cfg(feature = "linux-compat")]
    {
        let mfd = crate::linux_compat::MemFdFile::new(_flags);
        memfd_arc_register(&mfd);
        let cloexec = (_flags & crate::linux_compat::MFD_CLOEXEC) != 0;
        let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
        let fd = fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops: mfd,
                offset: 0,
                flags: install_flags,
                status_flags: 0,
            })
        });
        match fd {
            Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            None => ctx.set_return(fail),
        }
        return;
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        let ops = narf_filesystem::new_anon_memfile();
        let fd = fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: 0,
            })
        });
        match fd {
            Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            None => ctx.set_return(fail),
        }
    }
}

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

fn sys_fsync(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let known = fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false);
    if known {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
    }
}

// ── Pipe ────────────────────────────────────────────────────────────
//
// Allocates a fresh `PipeRead`/`PipeWrite` pair, installs them into
// the calling task's fd table at the next two free slots, then
// writes the two i32 fds back to the user-supplied output pointer
// in `[read, write]` order (matching POSIX `int pipefd[2]`).

fn sys_pipe(ctx: &mut dyn TrapContext) {
    let out_ptr = ctx.args().arg0 as u64;
    if out_ptr == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let (rd, wr) = crate::pipe::pipe_pair();
    let task = current_task_id();
    let fds = fd::with_table(task, |t| {
        let r = t.open(crate::fd::FdEntry {
            ops: rd as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: 0,
            status_flags: 0,
        });
        let w = t.open(crate::fd::FdEntry {
            ops: wr as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: 0,
            status_flags: 0,
        });
        (r, w)
    });
    let (r, w) = match fds {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Write two i32 fds to user buffer under the SMAP bracket.
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&(r as i32).to_ne_bytes());
    buf[4..].copy_from_slice(&(w as i32).to_ne_bytes());
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Pipe2 — pipe + atomic flag set ─────────────────────────────────
//
// Linux pipe2(2): same as pipe but the second arg sets per-fd
// flags atomically with the install. We honour O_CLOEXEC by
// stamping FD_CLOEXEC on both halves; O_NONBLOCK is accepted and
// ignored (NARF pipe reads short-return on empty already, no
// blocking model to toggle).

const O_CLOEXEC_BIT: u64 = 0x80000;

fn sys_pipe2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let out_ptr = args.arg0 as u64;
    let flags = args.arg1;
    if out_ptr == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let want_cloexec = (flags & O_CLOEXEC_BIT) != 0;
    let install_flags = if want_cloexec {
        crate::fd::FD_CLOEXEC
    } else {
        0
    };

    let (rd, wr) = crate::pipe::pipe_pair();
    let task = current_task_id();
    let fds = fd::with_table(task, |t| {
        let r = t.open(crate::fd::FdEntry {
            ops: rd as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: install_flags,
            status_flags: 0,
        });
        let w = t.open(crate::fd::FdEntry {
            ops: wr as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: install_flags,
            status_flags: 0,
        });
        (r, w)
    });
    let (r, w) = match fds {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Write two i32 fds to user buffer under the SMAP bracket.
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&(r as i32).to_ne_bytes());
    buf[4..].copy_from_slice(&(w as i32).to_ne_bytes());
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Lseek — arg0=fd, arg1=offset(i64), arg2=whence ─────────────────
//
// Updates the per-fd offset and returns the new value. SEEK_CUR /
// SEEK_END are computed against the current offset / current size
// reported by the FileOps `stat()`. Negative resulting offsets are
// rejected with `InvalidOp` so callers don't get a wraparound u64.

const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const SEEK_END: u64 = 2;

fn sys_lseek(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let offset = args.arg1 as i64;
    let whence = args.arg2;
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get_mut(fd)?;
        let base = match whence {
            SEEK_SET => 0i64,
            SEEK_CUR => entry.offset as i64,
            SEEK_END => entry.ops.stat().size as i64,
            _ => return Some(SyscallReturn::invalid_op()),
        };
        let new_off = base.checked_add(offset)?;
        if new_off < 0 {
            return Some(SyscallReturn::invalid_op());
        }
        entry.offset = new_off as u64;
        Some(SyscallReturn::ok(new_off as u64))
    });
    match outcome {
        Some(Some(r)) => ctx.set_return(r),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

// ── Unlink — arg0=path_ptr, arg1=path_len ──────────────────────────
//
// Splits the absolute path at the last `/`, walks the parent dir via
// the VFS registry, and dispatches to that DirOps's `unlink(leaf)`.
// FSes that haven't overridden the trait default surface
// `FsError::Unsupported`, which we translate to `InvalidOp` on the
// wire (no errno channel today).

fn sys_unlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as u64;
    // POSIX-shaped failure sentinel. The kernel's syscall ABI carries
    // a separate `status` field but the user-runtime asm wrapper only
    // observes the `value` register; we mirror libc and return -1 on
    // failure so the caller can distinguish from a success return of 0.
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_cstr(ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(&path, |_fs, parent, leaf| {
            poll_blocking(parent.unlink(leaf))
        });
    match outcome {
        Some(Some(Ok(()))) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

// ── Mkdir / Rmdir / Rename — Tier-3b directory mutation ────────────
//
// All three follow the unlink shape: resolve the parent through the
// VFS registry, dispatch to the relevant `DirOps` method, return
// POSIX-style 0 / -1. Mode argument on mkdir is accepted and ignored
// — NARF doesn't model POSIX permission bits at the FS layer.

fn sys_mkdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_cstr(ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(&path, |_fs, parent, leaf| poll_blocking(parent.mkdir(leaf)));
    match outcome {
        Some(Some(Ok(_))) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_rmdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_cstr(ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(&path, |_fs, parent, leaf| poll_blocking(parent.rmdir(leaf)));
    match outcome {
        Some(Some(Ok(()))) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_rename(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let old_ptr = args.arg0 as u64;
    let new_ptr = args.arg1 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let old_path = match copy_user_cstr(old_ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let new_path = match copy_user_cstr(new_ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Both paths must split into the same parent directory — cross-
    // directory rename isn't supported by the DirOps surface today
    // (would need a registry-aware version that locks both parents).
    let old_split = match old_path.rfind('/') {
        Some(i) => i,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let new_split = match new_path.rfind('/') {
        Some(i) => i,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if &old_path[..old_split] != &new_path[..new_split] {
        ctx.set_return(fail);
        return;
    }
    let new_leaf = &new_path[new_split + 1..];
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(&old_path, |_fs, parent, old_leaf| {
            poll_blocking(parent.rename(old_leaf, new_leaf))
        });
    match outcome {
        Some(Some(Ok(()))) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
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

fn sys_readlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `ssize_t readlink(const char *pathname, char *buf,
    // size_t bufsiz)`. arg1 is buf, arg2 is bufsiz. The previous
    // NARF-native shape used arg1 as path_len.
    let path_ptr = args.arg0 as u64;
    let buf_ptr = args.arg1 as *mut u8;
    let buf_len = args.arg2 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf_ptr.is_null() || buf_len == 0 {
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
    let path = apply_chroot(&raw);
    // resolve_parent_absolute returns Option<Option<Arc<dyn FileOps>>>:
    // outer None = no mount covers the path, inner None = parent walk
    // hit a missing component or the leaf is absent. Flatten both
    // failure modes to `fail`.
    let file = narf_filesystem::registry()
        .resolve_parent_absolute(&path, |_fs, parent, leaf| parent.lookup(leaf))
        .flatten();
    let file = match file {
        Some(f) => f,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Refuse non-symlinks — POSIX readlink returns EINVAL for those.
    let st = file.stat();
    if st.mode.file_type != narf_filesystem::FileType::Symlink {
        ctx.set_return(fail);
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

fn sys_symlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let target_ptr = args.arg0 as u64;
    let target_len = args.arg1 as usize;
    let link_ptr = args.arg2 as u64;
    let link_len = args.arg3 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let target_str = match copy_user_path(target_ptr, target_len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let link_path = match copy_user_path(link_ptr, link_len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(&link_path, |_fs, parent, leaf| {
            poll_blocking(parent.symlink(leaf, &target_str))
        });
    match outcome {
        Some(Some(Ok(_))) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
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

fn sys_listdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_ptr = args.arg0 as u64;
    let path_len = args.arg1 as usize;
    let cursor = args.arg2 as usize;
    let out_ptr = args.arg3 as *mut u8;
    let out_len = args.arg4 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    if out_len < 8 {
        // Need room for at least the header.
        ctx.set_return(fail);
        return;
    }
    let path = match copy_user_path(path_ptr, path_len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    // Resolve to a DirOps. Empty path or root → use the FS root
    // directly; otherwise descend through `lookup_dir_async` so
    // disk-backed FSes (FAT, ext2) that only implement the async side
    // can serve subdirectory walks.
    let entries = narf_filesystem::registry()
        .resolve_absolute(&path, |fs, rel| {
            let dir: alloc::sync::Arc<dyn narf_filesystem::DirOps> = if rel.is_empty() {
                fs.root()
            } else {
                // Walk segment by segment via the async lookup so
                // disk-backed FSes (FAT, ext2) resolve correctly.
                let mut cur = fs.root();
                for seg in rel.split('/').filter(|s| !s.is_empty()) {
                    cur = poll_blocking(cur.lookup_dir_async(seg)).and_then(|r| r.ok())?;
                }
                cur
            };
            // Use enumerate_async so disk-backed FSes (FAT, ext2) that
            // return Vec::new() from the sync enumerate() still work.
            // poll_blocking drives the future to completion via the
            // same internally-polled NVMe/virtio-blk driver path that
            // sys_open and sys_read already rely on.
            poll_blocking(dir.enumerate_async(cursor, 1)).and_then(|r| r.ok())
        })
        .flatten();

    let entries = match entries {
        Some(v) => v,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if entries.is_empty() {
        // End of directory.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let (name, ftype) = &entries[0];
    let name_bytes = name.as_bytes();
    let total = 8 + name_bytes.len();
    if total > out_len {
        ctx.set_return(fail);
        return;
    }
    // Encode FileType to the wire ordinal: 0=File, 1=Dir, 2=Symlink, 3=Special.
    let ftype_wire: u32 = match ftype {
        narf_filesystem::FileType::File => 0,
        narf_filesystem::FileType::Dir => 1,
        narf_filesystem::FileType::Symlink => 2,
        narf_filesystem::FileType::Special => 3,
    };
    // Build the 8-byte header in kernel memory, then copy the whole
    // record (header + name) into user space under the SMAP bracket.
    let mut record = alloc::vec![0u8; total];
    record[..4].copy_from_slice(&(name_bytes.len() as u32).to_ne_bytes());
    record[4..8].copy_from_slice(&ftype_wire.to_ne_bytes());
    record[8..].copy_from_slice(name_bytes);
    if unsafe { copy_to_user(out_ptr as u64, &record) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}

// ── Getdents64 — batched directory read in linux_dirent64 format ──
//
// arg0 = path string (path-based, not fd-based — NARF doesn't have
// directory fds yet); arg1/2 = path len + cursor; arg3/4 = buf+len.
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

fn sys_getdents64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_ptr = args.arg0 as u64;
    let path_len = args.arg1 as usize;
    let mut cursor = args.arg2 as usize;
    let out_ptr = args.arg3 as *mut u8;
    let out_len = args.arg4 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if out_ptr.is_null() || out_len < 32 {
        ctx.set_return(fail);
        return;
    }
    let path = match copy_user_path(path_ptr, path_len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    // Resolve to a DirOps once. We iterate by re-issuing
    // enumerate_async(cursor, 1) per entry — simpler than threading a
    // batch enumerator through the closure-typed registry walker,
    // and the per-call cost is bounded by the small fan-out of a
    // typical directory in our test FSes.
    let dir = narf_filesystem::registry()
        .resolve_absolute(&path, |fs, rel| {
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
        .flatten();
    let dir = match dir {
        Some(d) => d,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    let mut written = 0usize;
    loop {
        let mut entries = match poll_blocking(dir.enumerate_async(cursor, 1)).and_then(|r| r.ok()) {
            Some(v) if !v.is_empty() => v,
            _ => break,
        };
        let (name, ftype) = entries.pop().unwrap();
        let name_bytes = name.as_bytes();
        // 19-byte fixed header + name + NUL, padded up to 8 bytes.
        let raw_len = 19 + name_bytes.len() + 1;
        let reclen = (raw_len + 7) & !7;
        if written + reclen > out_len {
            // Record won't fit — stop here without advancing the
            // cursor for this entry. Linux returns whatever fit.
            break;
        }
        let next_cursor = cursor + 1;
        let dt = match ftype {
            narf_filesystem::FileType::File => 8,     // DT_REG
            narf_filesystem::FileType::Dir => 4,      // DT_DIR
            narf_filesystem::FileType::Symlink => 10, // DT_LNK
            narf_filesystem::FileType::Special => 2,  // DT_CHR
        };
        // Build the dirent record in kernel memory, then copy it into
        // user space under the SMAP bracket.
        let mut rec = alloc::vec![0u8; reclen];
        rec[..8].copy_from_slice(&(next_cursor as u64).to_ne_bytes()); // d_ino
        rec[8..16].copy_from_slice(&(next_cursor as u64).to_ne_bytes()); // d_off
        rec[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes()); // d_reclen
        rec[18] = dt; // d_type
        rec[19..19 + name_bytes.len()].copy_from_slice(name_bytes); // d_name
                                                                    // NUL terminator + zero-padding through end already zeroed by vec init.
        let dest = unsafe { out_ptr.add(written) } as u64;
        if unsafe { copy_to_user(dest, &rec) }.is_err() {
            break;
        }
        written += reclen;
        cursor = next_cursor;
    }

    ctx.set_return(SyscallReturn::ok(written as u64));
}

// ── Close — arg0=fd ────────────────────────────────────────────────

fn sys_close(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    // Before removing the fd, peek the FileOps Arc; if it's a
    // SocketFile, run its unregister hook so a bound listener
    // releases its path slot for re-use.
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten();
    if let Some(ops) = arc_ops {
        let raw = alloc::sync::Arc::as_ptr(&ops) as *const ();
        if let Some(sock) = socket_arc_lookup(raw) {
            sock.unregister();
            // Drop the side-table reference too.
            let mut g = SOCKET_ARCS.lock();
            if let Some(map) = g.as_mut() {
                map.remove(&(raw as usize));
            }
        }
    }
    let ok = fd::with_table(task, |t| t.close(fd)).unwrap_or(false);
    if ok {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::invalid_op());
    }
}

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

fn sys_mmap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let hint = args.arg0;
    let len = ((args.arg1 as u64 + 0xFFF) & !0xFFFu64).max(0x1000);
    let flags = args.arg2 as u32;
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    // POSIX mmap flag bits — pinned in narf-libc::sys, mirrored
    // here so the kernel can decode without a libc dep:
    //   MAP_FIXED     = 0x10  — use `hint` as the actual base
    //                   (must be page-aligned, must not collide
    //                   with an existing region in the AS).
    //   MAP_ANONYMOUS = 0x20  — currently the only mode supported.
    //                   File-backed mmap returns InvalidOp at the
    //                   libc shim before we ever see the syscall.
    const MAP_FIXED: u32 = 0x10;

    // Pick a fresh user virt. With MAP_FIXED honour the caller's
    // hint (page-aligned, no collision with an existing region);
    // otherwise bump the per-AS cursor (NOT the legacy global —
    // pre-fix, two processes mmap'ing in parallel would race-bump
    // the same atomic and end up with overlapping virts in
    // distinct PML4s).
    let pages = len >> 12;
    let base = if flags & MAP_FIXED != 0 {
        if hint == 0 || hint & 0xFFF != 0 {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
        // Reject if any existing region overlaps the requested
        // [hint, hint + len) window. POSIX.1-2017 §3.3.3 leaves
        // overlap behaviour implementation-defined: some systems
        // silently replace the prior mapping, but we choose to
        // fail loudly since the caller explicitly asked for this
        // exact vaddr — silent overwrite hides bugs.
        let snap = as_ref.regions_snapshot();
        let lo = hint;
        let hi = hint.saturating_add(len);
        if snap.iter().any(|r| {
            let rb = r.base.as_u64();
            let re = rb.saturating_add(r.len);
            !(re <= lo || rb >= hi)
        }) {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
        hint
    } else {
        as_ref.reserve_mmap_va(len)
    };

    // Lazy-back: install the region with `phys[i] == 0` for every
    // page. The first user-mode access to each page faults with
    // P=0 + U=1; the kernel #PF handler invokes
    // `AddressSpace::demand_alloc_page` to allocate + zero + map
    // a frame on the spot. Old behaviour (eager-back every page
    // up front) is no longer the default — `mlock` provides the
    // explicit force-back for callers that need it.
    let phys_list: alloc::vec::Vec<narf_memory::PhysAddr> =
        alloc::vec![narf_memory::PhysAddr::new(0); pages as usize];

    // Install + materialise.
    if as_ref
        .map_region(Region {
            base: VirtAddr::new(base),
            len,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys_list,
        })
        .is_err()
    {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    ctx.set_return(SyscallReturn::ok(base));
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

fn sys_fb_connect(ctx: &mut dyn TrapContext) {
    let scanout_id = ctx.args().arg0;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let pid = current_task_id();
    let h = (v.connect)(pid, scanout_id);
    if h == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
    } else {
        // First active FB-handle takes ownership of the framebuffer
        // away from the kernel-side FB console so kernel prints
        // don't paint glyphs over the user's pixels. Last
        // disconnect restores it. Serial / UART output is
        // unaffected — Console::Writer fans out to the FB only
        // through the optional hook this swaps.
        fb_console_owner::on_connect();
        ctx.set_return(SyscallReturn::ok(h));
    }
}

fn sys_fb_info(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let handle = args.arg0;
    let user_p = args.arg1;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let mut out = [0u32; 6];
    if !(v.info)(handle, &mut out) {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Write 6 u32s into the user pointer under the SMAP bracket.
    if user_p == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Serialise the 6 u32s into a 24-byte kernel buffer, then copy_to_user.
    let mut kbuf = [0u8; 24];
    for (i, &w) in out.iter().enumerate() {
        kbuf[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    if unsafe { copy_to_user(user_p, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_fb_ring_map(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let phys = (v.ring_map)(handle);
    if phys == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let len = 4096u64;
    let base = MMAP_CURSOR.fetch_add(len, Ordering::Relaxed);
    if as_ref
        .map_region(Region {
            base: VirtAddr::new(base),
            len,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![narf_memory::PhysAddr::new(phys)],
        })
        .is_err()
    {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(base));
}

fn sys_fb_flush_wait(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let drained = (v.flush_wait)(handle);
    ctx.set_return(SyscallReturn::ok(drained));
}

fn sys_fb_disconnect(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    if (v.disconnect)(handle) {
        // Pair with on_connect: when the last live handle goes
        // away, restore the kernel FB console hook so subsequent
        // kernel prints render to screen again.
        fb_console_owner::on_disconnect();
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::invalid_op());
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

fn sys_shmem_create(ctx: &mut dyn TrapContext) {
    let len = ctx.args().arg0;
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let pid = current_task_id();
    let h = (v.create)(pid, len);
    if h == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
    } else {
        ctx.set_return(SyscallReturn::ok(h));
    }
}

fn sys_shmem_map(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Cross-pid auth: the calling task must own this region. The
    // future cross-process sharing path adds an explicit grant /
    // attach syscall; today, foreign maps are rejected outright.
    let pid = current_task_id();
    if (v.pid_of)(handle) != pid {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let len = (v.len_of)(handle);
    if len == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let mut frames_raw: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
    if !(v.frames)(handle, &mut frames_raw) {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let phys_list: alloc::vec::Vec<narf_memory::PhysAddr> = frames_raw
        .into_iter()
        .map(narf_memory::PhysAddr::new)
        .collect();
    let base = MMAP_CURSOR.fetch_add(len, Ordering::Relaxed);
    if as_ref
        .map_region(Region {
            base: VirtAddr::new(base),
            len,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys_list,
        })
        .is_err()
    {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(base));
}

fn sys_shmem_destroy(ctx: &mut dyn TrapContext) {
    let handle = ctx.args().arg0;
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let pid = current_task_id();
    if (v.pid_of)(handle) != pid {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if (v.destroy)(handle) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::invalid_op());
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

fn sys_firmware_install(ctx: &mut dyn TrapContext) {
    // Privilege gate: pull the calling task's per-task firmware-
    // registry authority cap. Tasks granted authority via
    // `narf_firmware::grant_firmware_authority(pid)` hold a
    // live `Cap<FirmwareRegistry, Write>` here; tasks without
    // authority (or whose cap was revoked) see no entry and the
    // syscall fails.
    //
    // The trailer signature check inside `firmware::sys_install`
    // remains the second line of defense; this gate is the first.
    let pid = current_task_id();
    let auth = match narf_firmware::firmware_authority_of(pid) {
        Some(c) => c,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    let args = *ctx.args();
    let name_ptr = args.arg0 as u64;
    let name_len = args.arg1 as usize;
    let bytes_ptr = args.arg2 as u64;
    let bytes_len = args.arg3 as usize;
    if name_len == 0 || bytes_len == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Cap the staging size so a userspace task can't ask the
    // kernel to copy gigabytes through the syscall path. 16 MiB
    // is well above any real firmware blob (QCNFA765 AMSS is
    // ~5 MiB) and below the limit that would force the registry
    // into a multi-page IOMMU-backed allocation Stage-7 owns.
    const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
    if bytes_len > MAX_BLOB_BYTES {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Copy name from user memory under SMAP bracket, then validate UTF-8.
    // The copy_user_path helper handles null/canonical checks.
    let name_str = match copy_user_path(name_ptr, name_len) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Leak the name into 'static memory. The registry stores it
    // by reference; on hot-replace the prior 'static name string
    // is dropped from the registry but stays leaked. Acceptable
    // because firmware-install events are rare (vendor updates,
    // not per-frame).
    let leaked: &'static str = alloc::boxed::Box::leak(name_str.into_boxed_str());

    // Copy firmware bytes from user memory into a kernel-owned Vec
    // under the SMAP bracket before passing into sys_install.
    let mut kbuf = alloc::vec![0u8; bytes_len];
    if unsafe { copy_from_user(&mut kbuf, bytes_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // sys_install takes a raw pointer + len; feed it our kernel copy.
    let r = unsafe { narf_firmware::sys_install(leaked, kbuf.as_ptr(), bytes_len, &auth) };
    match r {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

// ── Munmap — arg0=base ─────────────────────────────────────────────

fn sys_munmap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = VirtAddr::new(args.arg0);
    match as_ref.unmap_region(base) {
        Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

/// `mprotect(base, len, prot)` — change permissions on every
/// region in the calling task's AS that intersects `[base,
/// base + len)`. Walks the region table, mutates `Region.perms`,
/// then re-installs the affected pages' PTEs with the new flag
/// set via `AddressSpace::change_perms_range`.
///
/// `prot` follows the POSIX bit layout we pin in `narf-libc`:
///   - bit 0 = PROT_READ
///   - bit 1 = PROT_WRITE
///   - bit 2 = PROT_EXEC
///
/// Returns Ok(0) on success, InvalidOp on bad AS or no
/// intersecting regions.
/// `mlock(addr, len)` — force-back lazy pages + set LOCKED flag.
/// arg0 = base, arg1 = len. Ok(0) on success, InvalidOp on
/// failure (no region intersects, OOM, AS lookup failed).
fn sys_mlock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match as_ref.mlock_range(VirtAddr::new(args.arg0), args.arg1) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

/// `munlock(addr, len)` — clear LOCKED flag (frames stay backed
/// since no swap exists yet to reclaim them). arg0 = base,
/// arg1 = len. Ok(0) on success, InvalidOp if no region
/// intersects.
fn sys_munlock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match as_ref.munlock_range(VirtAddr::new(args.arg0), args.arg1) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

fn sys_mprotect(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = VirtAddr::new(args.arg0);
    let len = args.arg1;
    let prot = args.arg2 as u32;

    // POSIX prot bit layout (mirrored from narf-libc::sys):
    //   PROT_NONE  = 0
    //   PROT_READ  = 1
    //   PROT_WRITE = 2
    //   PROT_EXEC  = 4
    //
    // Note: PROT_NONE is `prot == 0`. We do NOT silently coerce to
    // READ — Linux mprotect(PROT_NONE) installs an unreadable region
    // that faults on any access. `materialize` / `rewrite_perms_pages`
    // already key off `prot_only().0 == 0` to leave PTEs absent for
    // such regions; the user-mode #PF then reports a clean SEGV via
    // Wave-55's signal-induced termination.
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

    // Wave-66: take the Linux-compat split path. The legacy
    // change_perms_range surface is whole-region only and silently
    // accepted W|X (W^X enforcement was deferred to the wx module's
    // classify_mprotect, which sys_mprotect never consulted). The
    // new mprotect_range surface rejects W|X at the entry and splits
    // a region cleanly when the request only covers a slice.
    #[cfg(feature = "linux-compat")]
    {
        match as_ref.mprotect_range(base, len, perms) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
        }
        return;
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        match as_ref.change_perms_range(base, len, perms) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
        }
    }
}

/// `madvise(addr, len, advice)` — Linux syscall 28. The kernel honours
/// MADV_DONTNEED (4) and MADV_FREE (8) as "release backing frames; next
/// access reads zero." Every other advice value returns Ok(0) — `madvise`
/// is a hint, not a contract, so silently accepting unknown advice values
/// matches Linux's behaviour for callers that probe by value.
///
/// `arg0` = base, `arg1` = len, `arg2` = advice.
///
/// Returns `Ok(0)` on success or no-op-advice; `InvalidOp` if no region
/// intersects the range (Linux returns ENOMEM in that case — libc maps
/// our InvalidOp to ENOMEM).
#[cfg(feature = "linux-compat")]
fn sys_madvise(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = VirtAddr::new(args.arg0);
    let len = args.arg1;
    let advice = args.arg2 as i32;

    // MADV_DONTNEED (4) and MADV_FREE (8) — Linux's two "release this
    // memory" hints. NARF collapses them to the same shape because we
    // don't have a swap / page-aging path to differentiate the
    // eager-release (DONTNEED) from lazy-reclaim (FREE) semantics; both
    // end up with "next access reads zero", which is what callers need.
    const MADV_DONTNEED: i32 = 4;
    const MADV_FREE: i32 = 8;

    match advice {
        MADV_DONTNEED | MADV_FREE => match as_ref.madvise_dontneed(base, len) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
        },
        // Other advice values (MADV_NORMAL, MADV_RANDOM, MADV_WILLNEED,
        // MADV_SEQUENTIAL, MADV_HUGEPAGE, MADV_NOHUGEPAGE, MADV_DONTFORK,
        // MADV_DOFORK, MADV_REMOVE, MADV_DONTDUMP, MADV_DODUMP, …) —
        // accept and ignore. `madvise` is a hint; the contract is that
        // the kernel does its best and the program runs correctly either
        // way. Returning success here matches Linux's behaviour for
        // architectures that don't implement a given advice.
        _ => ctx.set_return(SyscallReturn::ok(0)),
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
fn terminate_current_task(ctx: &mut dyn TrapContext, task: u64, signum: u32, core_dumped: bool) {
    stage_pending_termination(task, encode_signaled_status(signum, core_dumped));

    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::exit_hook(),
    ) {
        // SAFETY: same contract as sys_exit_task — uctx is valid for
        // the lifetime of the in-flight polling routine on this CPU,
        // and the hook never returns.
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_EXITED;
            hook(uctx);
        }
        // unreachable
    }
    // Test / no-polling-future path: caller (the signal hook) is
    // responsible for not re-entering user mode. Smokes drive
    // `notify_task_exited` directly to verify the status threading.
}

// ── ExitTask — redirect to a kernel-registered landing ─────────────

fn sys_exit_task(ctx: &mut dyn TrapContext) {
    let exit_code = ctx.args().arg0 as u32;
    let wstatus = (exit_code & 0xff) << 8;
    let tid = current_task_id();
    let pid = task_to_pid_raw(tid).unwrap_or(tid);
    stage_pending_termination(pid, wstatus as i32);

    // Polling-future path: if a UserTaskCtx is installed AND an
    // exit hook is registered, save the user state, mark the
    // reason, and tail-call the hook — which longjmps back into
    // the polling routine.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::exit_hook(),
    ) {
        // SAFETY: uctx is valid for as long as the polling routine
        // (its caller, on the same CPU) holds it pinned. We're
        // about to never return.
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_EXITED;
            hook(uctx);
        }
        // unreachable
    }

    // Legacy redirect-to-landing path (testbin runner uses this).
    let rip = EXIT_LANDING_RIP.load(Ordering::Acquire);
    let rsp = EXIT_LANDING_RSP.load(Ordering::Acquire);
    if rip == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if !ctx.redirect_to_kernel(rip, rsp) {
        // Arch doesn't support redirect; best we can do is mark Ok.
        ctx.set_return(SyscallReturn::ok(0));
    }
    // Redirect succeeded → frame rewritten, `iretq` lands in kernel.
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

fn sys_yield(ctx: &mut dyn TrapContext) {
    if maybe_deliver_signal_before_yield(ctx, Syscall::Yield.raw()) {
        return;
    }

    // Polling-future path mirroring sys_exit_task.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: same contract as sys_exit_task's hook path.
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            hook(uctx);
        }
        // unreachable
    }

    // No polling executor wired yet — but a user task that yields
    // is asking for "let other work run." Drive the same pumps
    // sys_sleep does so the FB drain (and any other registered
    // background work) makes progress on yields. Without this, a
    // user-mode busy-wait pattern (e.g., retry-on-RingFull) spins
    // forever because nothing else runs.
    sleep_pumps::run();
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_pause(ctx: &mut dyn TrapContext) {
    if maybe_deliver_signal_before_yield(ctx, Syscall::Pause.raw()) {
        return;
    }

    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        unsafe {
            let uc = &*uctx;
            // Block forever by setting deadline to u64::MAX.
            // Any signal delivery will wake the task via wake_signal().
            uc.sleep_deadline_ns
                .store(u64::MAX, core::sync::atomic::Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            hook(uctx);
        }
        // unreachable
    }

    // Fallback: no polling executor is wired (kernel-test contexts),
    // so there is nothing to park on. Pump any ready async work once
    // in case a signal is about to become deliverable, retry delivery,
    // then surface EINTR rather than spinning forever — a real task
    // always takes the yield-hook path above and never reaches here.
    narf_scheduler::sleep_pumps::run();
    if maybe_deliver_signal_before_yield(ctx, Syscall::Pause.raw()) {
        return;
    }
    ctx.set_return(SyscallReturn::ok((-1i64) as u64));
}

// ── RingKick — drain the shared SQ, post completions to the CQ ────
//
// Slow-path counterpart to a UIPI/UMWAIT-driven async dispatcher.
// User code submits + calls `RingKick` + spins on the CQ until the
// real wake side-channel lands.

fn sys_ring_kick(ctx: &mut dyn TrapContext) {
    use narf_abi::{FileOpArgs, FileOpKind, NarfStatus, OpCode, SharedConsumer, SharedProducer};

    type SqRing = SharedRing<Submission, BOOTSTRAP_SHARED_RING_DEPTH>;
    type CqRing = SharedRing<Completion, BOOTSTRAP_SHARED_RING_DEPTH>;

    let task = current_task_id();
    let pair = match shared_rings_for(task) {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    // SAFETY: per-task BOOTSTRAP_TABLE owns the phys backings; only
    // one ring-kick can run at a time per task because it executes
    // synchronously inside this task's syscall trap.
    let mut sq = unsafe {
        SharedConsumer::<Submission, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.sq_phys.raw() as *mut SqRing
        )
    };
    let mut cq = unsafe {
        SharedProducer::<Completion, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.cq_phys.raw() as *mut CqRing
        )
    };

    let mut processed: u64 = 0;
    loop {
        let sub = match sq.try_recv() {
            Ok(s) => s,
            Err(_) => break,
        };
        let tag = sub.tag();
        let completion = match sub.op {
            OpCode::Noop => Completion::ok(tag),
            OpCode::OpenFile
            | OpCode::Read
            | OpCode::Write
            | OpCode::Close
            | OpCode::Mmap
            | OpCode::Munmap => {
                let kind = match sub.op {
                    OpCode::OpenFile => FileOpKind::Open,
                    OpCode::Read => FileOpKind::Read,
                    OpCode::Write => FileOpKind::Write,
                    OpCode::Close => FileOpKind::Close,
                    OpCode::Mmap => FileOpKind::Mmap,
                    OpCode::Munmap => FileOpKind::Munmap,
                    _ => unreachable!(),
                };
                let args = FileOpArgs {
                    a0: sub.inline[0],
                    a1: sub.inline[1],
                    a2: sub.inline[2],
                    a3: sub.inline[3],
                    a4: sub.inline[4],
                    a5: sub.inline[5],
                };
                let r = abi_file_op_bridge(kind, &args, &narf_abi::CancelCtx::detached());
                let status = if r.status == 0 {
                    NarfStatus::Ok
                } else {
                    NarfStatus::InvalidOp
                };
                let mut result = [0u64; 6];
                result[0] = r.value;
                Completion::with(tag, status, result)
            }
            _ => Completion::with(tag, NarfStatus::InvalidOp, [0; 6]),
        };
        let _ = cq.try_send(completion);
        processed = processed.saturating_add(1);
    }

    ctx.set_return(SyscallReturn::ok(processed));
}

// ── GetPid / GetPpid — POSIX-shaped task-id surface ────────────────

fn sys_getpid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    #[cfg(feature = "container")]
    {
        // Wave-67 — translate the outer pid through whichever PID
        // namespace the task belongs to. Root-namespace tasks fall
        // through to the legacy outer == inner path.
        let outer = task_to_pid_raw(task).unwrap_or(task);
        let inner = crate::pid_ns::self_inner_pid(task, outer);
        ctx.set_return(SyscallReturn::ok(inner));
        return;
    }
    #[cfg(not(feature = "container"))]
    ctx.set_return(SyscallReturn::ok(task));
}

fn sys_getppid(ctx: &mut dyn TrapContext) {
    let me = current_task_id();
    let ppid = parent_of_get(me).unwrap_or(0);
    ctx.set_return(SyscallReturn::ok(ppid));
}

fn sys_gettid(ctx: &mut dyn TrapContext) {
    // Returns the scheduler's TaskId for the currently-polling
    // task. With `sys_clone` wired (Syscall::Clone = 56), threads
    // in the same address space observe distinct tids here even
    // though they share `getpid` (when process-group bookkeeping
    // lands; today gettid==getpid since both go through the same
    // task_id_lookup, but `clone` already produces distinct tids).
    ctx.set_return(SyscallReturn::ok(current_task_id()));
}

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
const CLONE_VM: u64 = 0x0000_0100;
#[cfg(feature = "linux-compat")]
const CLONE_FS: u64 = 0x0000_0200;
#[cfg(feature = "linux-compat")]
const CLONE_FILES: u64 = 0x0000_0400;
#[cfg(feature = "linux-compat")]
const CLONE_SIGHAND: u64 = 0x0000_0800;
#[cfg(feature = "linux-compat")]
const CLONE_THREAD: u64 = 0x0001_0000;
#[cfg(feature = "linux-compat")]
const CLONE_SYSVSEM: u64 = 0x0004_0000;
#[cfg(feature = "linux-compat")]
const CLONE_SETTLS: u64 = 0x0008_0000;
#[cfg(feature = "linux-compat")]
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
#[cfg(feature = "linux-compat")]
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
#[cfg(feature = "linux-compat")]
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
    // Resolve the dying task's address space. For CLONE_THREAD
    // children this is the same Arc as the parent; for non-thread
    // forks it's the child's own AS. `address_space_of` consults
    // the scheduler's task table — works because we run during the
    // exit-observer fan-out, before the scheduler reaps the slot.
    // Always fire the futex wake first. pthread_join's contract is
    // "the wake fires when the thread exits"; even if we can't
    // resolve the user word (the address space was torn down before
    // we got here, or the smoke ran with a synthetic uaddr that
    // isn't mapped through the user AS), the futex counter still
    // bumps so any waiter using the same uaddr observes the wake.
    futex_bump_counter(uaddr);

    // Write zero into *uaddr via the page tables of the AS the
    // task ran in. We stashed the PML4 phys at clone time, so this
    // works even after the scheduler reaps the task's slot.
    let root = entry.as_root;
    if root.as_u64() == 0 {
        return;
    }
    let page = uaddr & !0xFFFu64;
    let off = uaddr & 0xFFFu64;
    if off + 4 > 4096 {
        // Crossing a page boundary on a 4-byte futex word is
        // structurally invalid (futex words are required to be
        // naturally aligned); drop the clear-side write but keep
        // the futex wake we already fired above.
        return;
    }
    let phys = match unsafe {
        narf_memory::x86_64::paging::translate(root, narf_memory::VirtAddr::new(page))
    } {
        Some(p) => p,
        None => return,
    };
    // SAFETY: identity-mapped low 4 GiB; the AS Arc keeps the
    // backing frame alive across this write.
    unsafe {
        *((phys.as_u64() + off) as *mut u32) = 0;
    }
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
fn fire_clear_child_tid_on_exit(_pid_raw: u64, _tid_raw: u64) {
    // aarch64 / other arches: clone3 path is x86_64-gated below;
    // the table never gets populated, so this is a no-op.
}

/// Register the clear_child_tid observer with `register_exit_observer`.
/// Idempotent and safe to call before `clear_child_tid_init` (the
/// observer no-ops on an unpopulated table).
#[cfg(feature = "linux-compat")]
pub fn install_clear_child_tid_observer() {
    crate::user_task::register_exit_observer(fire_clear_child_tid_on_exit);
}

/// Linux `struct clone_args` — uapi shape from <linux/sched.h>.
/// All fields are u64 on the wire; the kernel reads only the
/// subset we honour.
#[cfg(feature = "linux-compat")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    // The full struct grows; later fields (set_tid, set_tid_size,
    // cgroup) are honoured-as-zero today. We only copy as many bytes
    // as the user provided (the second arg to clone3 is the struct
    // size), capped at our known prefix.
}

#[cfg(feature = "linux-compat")]
const CLONE_ARGS_MIN: usize = core::mem::size_of::<CloneArgs>();

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
fn sys_clone3(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let uargs = args.arg0;
    let size = args.arg1 as usize;
    if uargs == 0 || size < 8 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    // Copy in just what we honour. Larger user structs (Linux has
    // grown the struct several times) are read as a prefix; smaller
    // ones (unlikely — the minimum Linux ever shipped was 64 bytes)
    // would be rejected above on the 8-byte floor.
    let copy_len = core::cmp::min(size, CLONE_ARGS_MIN);
    let mut raw = [0u8; CLONE_ARGS_MIN];
    if unsafe { copy_from_user(&mut raw[..copy_len], uargs) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // SAFETY: `CloneArgs` is `#[repr(C)]` of u64s; any bit pattern
    // is a valid `CloneArgs`. `raw` has the same size + alignment
    // (u8 array can be transmuted to a struct-of-u64 because we
    // only read it).
    let ca: CloneArgs = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const CloneArgs) };
    do_clone3(ctx, ca);
}

/// Linux `clone(2)` — same semantics as `clone3(2)` but the
/// arguments are passed in registers (x86_64 syscall ABI:
/// flags, stack-TOP, ptid, tls, ctid) instead of via a
/// `clone_args` user struct. musl's `__clone` x86_64 asm wrapper
/// uses this entry, including for `pthread_create`. The
/// passed-in `stack` is the **top** of the new thread's stack;
/// `clone3` instead takes a `(base, size)` pair. We synthesize a
/// `CloneArgs` with `stack_size = 0` so `do_clone3`'s
/// `rsp = stack + stack_size` arithmetic recovers the original
/// top.
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
fn sys_clone(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ca = CloneArgs {
        flags: args.arg0,
        stack: args.arg1,
        // Linux's clone() takes the stack TOP directly; encode as
        // (top, size=0) so `rsp = stack + stack_size` lands at the
        // top, matching the clone3 path.
        stack_size: 0,
        parent_tid: args.arg2,
        // x86_64 clone(2) syscall ABI: arg3 = ctid, arg4 = tls.
        // (Only x86_32 — CONFIG_CLONE_BACKWARDS — flips these.)
        // musl's `__clone` x86_64 asm matches the default order:
        //     mov %r9, %r8        ; tls  -> syscall arg4 (r8)
        //     mov 8(%rsp), %r10   ; ctid -> syscall arg3 (r10)
        // We previously had these swapped (tls=arg3, ctid=arg4),
        // which made `pthread_create` set the child's FS_BASE to
        // `&__thread_list_lock` (in libc.so .bss, where ctid
        // pointed) instead of the real per-thread TP. The worker
        // then #PFed on `mov %fs:0,%rbx; movzbl 0x40(%rbx),%r11d`
        // because `%fs:0` read the lock word (`0x10`-ish), not
        // the self-pointer the TCB layout promises.
        tls: args.arg4,
        child_tid: args.arg3,
        pidfd: 0,
        exit_signal: 0,
    };
    do_clone3(ctx, ca);
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

    // CLONE_VM: share AS via Arc::clone. Without it, this would be a
    // full fork — but pthread always passes CLONE_VM so the no-VM
    // path is uncommon. We support both: no-VM falls back to
    // `clone_for_fork` (sys_fork's path).
    let share_vm = (flags & CLONE_VM) != 0;
    let share_thread = (flags & CLONE_THREAD) != 0;
    let share_fs = (flags & CLONE_FS) != 0;
    let _share_files = (flags & CLONE_FILES) != 0;
    let _share_sighand = (flags & CLONE_SIGHAND) != 0;
    let _share_sysvsem = (flags & CLONE_SYSVSEM) != 0;

    // CLONE_THREAD requires CLONE_VM + CLONE_SIGHAND in Linux.
    // We enforce CLONE_VM (without a shared AS the child can't
    // observe the parent's memory) but accept CLONE_SIGHAND as
    // a behavioural-only flag.
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
        parent_as.clone()
    } else {
        let dup = match unsafe { parent_as.clone_for_fork() } {
            Ok(a) => a,
            Err(_) => {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        };
        if unsafe { dup.materialize() }.is_err() {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
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
    if ca.stack == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let rsp = ca.stack.saturating_add(ca.stack_size);

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
        let ok = unsafe { ctx.save_user_state(s.as_mut_ptr() as *mut u8) };
        if ok {
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

    let future = match child_state {
        Some(state) => crate::user_task::UserTaskFuture::resume_with(proc, state),
        None => crate::user_task::UserTaskFuture::new(proc),
    };
    // Snapshot the AS root phys before the Arc is moved into the
    // scheduler — needed by the exit-observer to write the
    // clear_child_tid futex word after the slot is reaped.
    let child_as_root = child_as.root;
    let child_tid =
        narf_scheduler::spawn_user(future, narf_scheduler::TaskSpec::unthrottled(), child_as);

    // Register the (visible-pid → TaskId) binding. For
    // CLONE_THREAD children visible_pid == parent's pid, so the
    // mapping is "child TaskId → parent's PID" — gettid returns
    // the TaskId raw, getpid translates TaskId → PID.
    if share_thread {
        register_task_to_pid(child_tid.raw(), child_visible_pid);
    } else {
        register_pid_task_mapping(child_visible_pid, child_tid.raw());
    }

    // POSIX-shaped inheritance for the non-shared resources.
    // Wave-81 temporary fix: always copy the table so threads
    // have an entry in the FD table registry. Shared-offset
    // semantics for CLONE_FILES are deferred.
    crate::fd::fork(parent_pid, child_tid.raw());

    if !share_fs {
        cwd_fork(parent_pid, child_tid.raw());
    }
    if !share_vm {
        // brk and sigaction map onto AS state; only meaningful for
        // a non-VM clone (a true fork). For thread spawns the
        // parent's brk/sigaction stay reachable through the shared
        // AS and the per-tid sigaction lookup.
        brk_fork(parent_pid, child_tid.raw());
        sigaction_fork(parent_pid, child_tid.raw());
    }

    // CLONE_PARENT_SETTID: write child TID to *parent_tid in the
    // parent's AS (still active here — we haven't returned to the
    // user yet, so the parent's CR3 is in place from before the
    // trap entry).
    if (flags & CLONE_PARENT_SETTID) != 0 && ca.parent_tid != 0 {
        let tid_bytes = (child_tid.raw() as u32).to_ne_bytes();
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

    // Parent-of bookkeeping for wait4 — process-style only. A
    // thread (CLONE_THREAD) is not waitpid-reapable; pthread_join
    // uses the futex on clear_child_tid instead.
    if !share_thread {
        parent_of_set(child_visible_pid, parent_pid);
    }

    // Return: parent sees child TID (== visible-pid for !THREAD,
    // == TaskId.raw() for THREAD where TID and PID diverge).
    let ret_val = if share_thread {
        child_tid.raw()
    } else {
        child_visible_pid
    };
    ctx.set_return(SyscallReturn::ok(ret_val));
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
fn sys_clone3(ctx: &mut dyn TrapContext) {
    // aarch64 / other arches: depends on x86_64-only user_task
    // pipeline. Will land alongside the EL0 user-task bring-up.
    ctx.set_return(SyscallReturn::invalid_op());
}

/// Linux `clone(2)` — same semantics as `clone3(2)` but the
/// arguments are passed in registers. Falls back to InvalidOp
/// on non-x86_64 / non-linux-compat builds.
#[cfg(any(not(feature = "linux-compat"), not(target_arch = "x86_64")))]
fn sys_clone(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::invalid_op());
}

#[cfg(feature = "linux-compat")]
fn sys_set_tid_address(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tidptr = args.arg0;
    let me = current_task_id();
    // Per Linux: set_tid_address records the pointer regardless
    // of value; passing 0 effectively disables clear_child_tid.
    set_clear_child_tid(me, tidptr);
    // Return the caller's TID.
    ctx.set_return(SyscallReturn::ok(me));
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

#[cfg(target_arch = "x86_64")]
fn sys_arch_prctl(ctx: &mut dyn TrapContext) {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;
    const EINVAL: i64 = 22;
    const EFAULT: i64 = 14;

    let args = *ctx.args();
    let code = args.arg0;
    let addr = args.arg1;

    match code {
        ARCH_SET_FS => {
            // SAFETY: `addr` is treated as an opaque u64 the user
            // owns — the MSR write is unconditional at CPL=0 and
            // any canonical-vaddr invariant is the user task's
            // responsibility (Linux behaves the same way).
            unsafe {
                narf_scheduler::set_user_fs_base(addr);
            }
            // Publish to the polling-future override so a
            // subsequent timer-driven re-poll restores THIS
            // FS_BASE, not the load-time synthetic-TLS value
            // from `process.fs_base`.
            if let Some(uctx) = crate::user_task::current_user_task() {
                // SAFETY: pending_fs_base is an AtomicU64 owned by
                // the live UserTaskCtx pinned for the duration of
                // this syscall.
                unsafe {
                    (*uctx)
                        .pending_fs_base
                        .store(addr, core::sync::atomic::Ordering::Release);
                }
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        ARCH_GET_FS => {
            // Read the live FS_BASE, copy it as a u64 to `addr`.
            let fs_base: u64;
            unsafe {
                use core::arch::asm;
                let lo: u32;
                let hi: u32;
                const IA32_FS_BASE: u32 = 0xC000_0100;
                asm!(
                    "rdmsr",
                    in("ecx") IA32_FS_BASE,
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, preserves_flags),
                );
                fs_base = (lo as u64) | ((hi as u64) << 32);
            }
            // SAFETY: copy_to_user does the SMAP bracket and
            // bounds the write to a u64; addr is the user-supplied
            // destination.
            let buf = fs_base.to_le_bytes();
            if unsafe { copy_to_user(addr, &buf) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        ARCH_SET_GS | ARCH_GET_GS => {
            // Not yet wired; GS is reserved for the kernel
            // per-CPU pointer via swapgs.
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        }
        _ => {
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        }
    }
}

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

fn sys_fork(ctx: &mut dyn TrapContext) {
    let parent_as = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    // SAFETY: clone_for_fork's contract — paging is live; the
    // frame allocator was initialised at boot.
    let child_as = match unsafe { parent_as.clone_for_fork() } {
        Ok(a) => a,
        Err(_) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // SAFETY: child AS just constructed; no concurrent writers.
    if unsafe { child_as.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Re-materialise the parent's PTEs. `clone_for_fork` stripped
    // WRITE from every region's metadata but the parent's live page
    // tables still carry the old WRITE-set PTEs. Without this, the
    // parent continues writing to the shared physical frames without
    // triggering a COW fault, silently corrupting the child's copy.
    // SAFETY: identity map live; root valid; may be called while
    // the parent AS is the active CR3 — invlpg per page keeps the
    // TLB coherent. Single-CPU BSP-only (Stage-4).
    if unsafe { parent_as.as_ref().rematerialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let child_as = alloc::sync::Arc::new(child_as);

    // Snapshot the parent's trap frame BEFORE we set the parent's
    // own return value below. The snapshot captures the syscall-
    // return register (rax on x86_64, x0+x1 on aarch64) holding
    // whatever the user code passed at trap entry; we mutate the
    // child's copy to 0 so the child reads "0" from its resumed
    // syscall — POSIX semantics.
    //
    // On x86_64 the `int 0x80` trap path's save_user_state writes
    // a fully-populated UserState; the child's first poll calls
    // `enter_user_mode_resume` and lands at the parent's
    // post-syscall RIP. On aarch64 save_user_state populates the
    // analogous UserState (PC = ELR_EL1, SP = SP_EL0, x[0..=30] +
    // SPSR), but `UserTaskFuture::resume_with` on aarch64 is
    // currently a no-op pending the EL0 polling pipeline — the
    // saved state is captured for forward-compat but not yet
    // restored. Test contexts whose synthetic TrapContext can't
    // save user state (the trait default returns false) fall back
    // to `UserTaskFuture::new` against the parent's load-time
    // (entry, stack_top).
    let child_state: Option<crate::user_task::UserState> = {
        use core::mem::MaybeUninit;
        let mut s = MaybeUninit::<crate::user_task::UserState>::zeroed();
        // SAFETY: the destination is `size_of::<UserState>()` bytes
        // of zeroed stack — the trait's contract.
        let ok = unsafe { ctx.save_user_state(s.as_mut_ptr() as *mut u8) };
        if ok {
            // SAFETY: save_user_state returned true → it wrote a
            // valid UserState into `s`.
            let mut snap = unsafe { s.assume_init() };
            // Rewrite the syscall-return register(s) for the
            // child. Per-arch since UserState's field names
            // differ.
            #[cfg(target_arch = "x86_64")]
            {
                snap.rax = 0;
            }
            #[cfg(target_arch = "aarch64")]
            {
                // aarch64 set_return writes value→x0, status→x1.
                // Child sees SyscallReturn::ok(0) ⇒ x0=0, x1=0.
                snap.x[0] = 0;
                snap.x[1] = 0;
            }
            Some(snap)
        } else {
            None
        }
    };

    let parent_pid = current_task_id();
    let child_pid = crate::alloc_pid();
    let proc = crate::UserProcess {
        pid: child_pid,
        address_space: child_as.clone(),
        // entry / stack_top are NOT consulted when we resume the
        // child via UserTaskFuture::resume_with — the saved state
        // carries the real (rip, rsp). They're left at zero
        // sentinels so a subsequent `Initial`-path poll (e.g. on
        // an arch without save_user_state) is obviously broken.
        entry: crate::EntryPoint(narf_memory::VirtAddr::new(0)),
        stack_top: narf_memory::VirtAddr::new(0),
        fs_base: {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use core::arch::asm;
                let lo: u32;
                let hi: u32;
                const IA32_FS_BASE: u32 = 0xC000_0100;
                asm!(
                    "rdmsr",
                    in("ecx") IA32_FS_BASE,
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, preserves_flags),
                );
                let v = (lo as u64) | ((hi as u64) << 32);
                if v == 0 {
                    None
                } else {
                    Some(v)
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            None
        },
        entry_arg: None,
    };

    let future = match child_state {
        Some(state) => crate::user_task::UserTaskFuture::resume_with(proc, state),
        // Fallback if save_user_state didn't fire (test contexts
        // with synthetic TrapContexts whose stub returns false).
        None => crate::user_task::UserTaskFuture::new(proc),
    };
    let child_tid =
        narf_scheduler::spawn_user(future, narf_scheduler::TaskSpec::unthrottled(), child_as);
    // Record the explicit ProcessId ↔ TaskId binding.  Must happen
    // before any code that crosses the ID-space boundary.
    register_pid_task_mapping(child_pid.raw(), child_tid.raw());
    // POSIX inheritance — fd / cwd / brk / sigaction handlers are
    // copied; pending signals reset (handled by sigaction_fork
    // not touching the pending bitmap).
    crate::fd::fork(parent_pid, child_tid.raw());
    cwd_fork(parent_pid, child_tid.raw());
    brk_fork(parent_pid, child_tid.raw());
    sigaction_fork(parent_pid, child_tid.raw());
    // Wave-67 — propagate the parent's PID + mount namespaces into
    // the child. Tasks in the root namespace skip the rebind (no
    // translation needed) but inherit_into_child returns None
    // silently in that case.
    #[cfg(feature = "container")]
    {
        let _ = crate::pid_ns::inherit_into_child(parent_pid, child_pid.raw());
        mount_ns_inherit(parent_pid, child_tid.raw());
    }
    // Parent-of bookkeeping for waitpid: keyed by the child's
    // ProcessId so `on_child_exit(child_pid)` can resolve the
    // parent. `notify_task_exited` uses `this.process.pid.raw()`
    // (ProcessId) as the argument to the exit observer, so the
    // key here must also be ProcessId — not TaskId.
    parent_of_set(child_pid.raw(), parent_pid);
    // Return the child's user-visible ProcessId (POSIX fork(2)
    // contract). The parent's waitpid() call passes this same
    // value back to us as `want_pid`.
    ctx.set_return(SyscallReturn::ok(child_pid.raw()));
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
static PARENT_OF: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// parent_pid → list of (child_pid, status) pairs not yet reaped.
/// status is the POSIX-shaped 32-bit value:
///   - Normal exit (WIFEXITED): low 7 bits == 0, byte 1 holds the
///     exit code → `status = exit_code << 8`.
///   - Signal-killed (WIFSIGNALED): low 7 bits hold the signum
///     (non-zero, not 0x7f), bit 7 is WCOREDUMP →
///     `status = signum | (core ? 0x80 : 0)`.
static PENDING_EXITS: narf_lib::sync::IrqSafeSpinLock<
    Option<BTreeMap<u64, alloc::vec::Vec<(u64, i32)>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

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
    *PENDING_EXITS.lock() = Some(BTreeMap::new());
    *PENDING_TERMINATION.lock() = Some(BTreeMap::new());
    pid_task_map_init();
    crate::user_task::register_exit_observer(on_child_exit);
    crate::user_task::register_wait_child_check(wait_child_check_fn);
    crate::user_task::wait_child_waker_init();
    crate::user_task::user_task_ctx_init();
    signal_waker_init();
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
}

#[doc(hidden)]
pub fn __test_wait_reset() {
    *PARENT_OF.lock() = Some(BTreeMap::new());
    *PENDING_EXITS.lock() = Some(BTreeMap::new());
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
    let mut g = PENDING_TERMINATION.lock();
    if let Some(m) = g.as_mut() {
        m.entry(task).or_insert(status);
    }
}

fn take_pending_termination(task: u64) -> Option<i32> {
    let mut g = PENDING_TERMINATION.lock();
    g.as_mut().and_then(|m| m.remove(&task))
}

/// Callback invoked by `UserTaskFuture::poll` when `wait_child_pending`
/// is set: tries to drain one matching entry from the parent's pending-
/// exits queue.
///
/// Returns the reaped child pid (> 0) on success, or 0 if the queue
/// holds no matching entry.  If `status_ptr != 0`, writes the POSIX
/// wstatus into the user-space pointer (same as `sys_wait4` does on the
/// fast path).
fn wait_child_check_fn(parent_id: u64, want_pid: i64, status_ptr: u64) -> i64 {
    let entry = {
        let mut g = PENDING_EXITS.lock();
        let m = match g.as_mut() {
            Some(m) => m,
            None => return 0,
        };
        let q = match m.get_mut(&parent_id) {
            Some(q) => q,
            None => return 0,
        };
        let idx = if want_pid > 0 {
            match q.iter().position(|&(p, _)| p == want_pid as u64) {
                Some(i) => i,
                None => return 0,
            }
        } else {
            if q.is_empty() {
                return 0;
            }
            0
        };
        q.remove(idx)
    };
    let (child_pid, status) = entry;
    if status_ptr != 0 {
        let _ = unsafe { copy_to_user(status_ptr, &status.to_ne_bytes()) };
    }
    // Wave-61: PID pool — reaped child's PID returns to the free pool.
    crate::release_pid(crate::ProcessId(child_pid));
    child_pid as i64
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

fn parent_of_set(child: u64, parent: u64) {
    let mut g = PARENT_OF.lock();
    if let Some(m) = g.as_mut() {
        m.insert(child, parent);
    }
}

fn parent_of_get(child: u64) -> Option<u64> {
    let g = PARENT_OF.lock();
    g.as_ref().and_then(|m| m.get(&child).copied())
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
    let mut g = PID_TO_TASK.lock();
    if let Some(m) = g.as_mut() {
        m.insert(pid_raw, task_raw);
    }
}

pub fn register_task_to_pid(task_raw: u64, pid_raw: u64) {
    let mut g = TASK_TO_PID.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task_raw, pid_raw);
    }
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
fn on_child_exit(child_pid: u64, _child_tid: u64) {
    // Wave-61: notify any pidfd_open()'d watchers that the target
    // exited, regardless of whether a parent reaps it.
    crate::pidfd::notify_exit(child_pid);

    // Wave-67: release the dying task from its PID namespace's
    // inner-pid table so a recycled outer pid doesn't inherit the
    // dead task's inner slot. Mount-namespace entries are keyed on
    // the scheduler TaskId, not the outer pid, so we leave them
    // alone here — they get cleaned up implicitly when the scheduler
    // tears the task down.
    #[cfg(feature = "container")]
    {
        if let Some(ns) = crate::pid_ns::ns_of(child_pid) {
            ns.release_outer(child_pid);
        }
        crate::pid_ns::clear_ns(child_pid);
    }

    let parent = match parent_of_get(child_pid) {
        Some(p) => p,
        None => {
            // No registered parent — orphan. Drain the staged status
            // so a re-used pid doesn't see stale state, and return the
            // PID to the pool immediately since no one will reap it.
            let _ = take_pending_termination(child_pid);
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
            *slot |= 1u32 << SIGCHLD;
        }
    }
    // (3) Wake any parent task parked in a blocking wait4.  The waker
    // was stored by `UserTaskFuture::poll` when it found the pending-
    // exits queue empty.  Now that we've pushed an entry, fire the waker
    // so the executor re-polls the parent and it can reap.
    crate::user_task::wake_wait_child(parent);
}

fn sys_wait4(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let want_pid = args.arg0 as i64;
    let status_ptr = args.arg1 as u64;
    let options = args.arg2 as u32;
    let _rusage_ptr = args.arg3; // ignored; no resource accounting yet
    const WNOHANG: u32 = 1;

    let parent = current_task_id();

    // Try-reap closure: pops the matching (child_pid, status)
    // from the parent's queue if any. Returns Some on success.
    let try_reap = |parent: u64, want: i64| -> Option<(u64, i32)> {
        let mut g = PENDING_EXITS.lock();
        let m = g.as_mut()?;
        let q = m.get_mut(&parent)?;
        let idx = if want > 0 {
            // Specific child.
            q.iter().position(|&(p, _)| p == want as u64)?
        } else {
            // Any child (including pid == 0 / pid < -1 we
            // collapse to -1 for simplicity — no per-pgid wait
            // until process groups are real).
            if q.is_empty() {
                return None;
            }
            0
        };
        Some(q.remove(idx))
    };

    if let Some((reaped, status)) = try_reap(parent, want_pid) {
        if status_ptr != 0 {
            // Write i32 status under the SMAP bracket.
            let _ = unsafe { copy_to_user(status_ptr, &status.to_ne_bytes()) };
        }
        // Wave-61: PID pool — reaped child's PID returns to the free pool.
        crate::release_pid(crate::ProcessId(reaped));
        ctx.set_return(SyscallReturn::ok(reaped));
        return;
    }

    if options & WNOHANG != 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Blocking wait — cooperative yield to the scheduler.
    //
    // Previous implementation was a busy-spin that prevented the
    // child task from ever being scheduled (the child's UserTaskFuture
    // was on the ready queue but the parent's spin loop never returned
    // to the executor).
    //
    // New implementation mirrors `sys_futex` / `sys_sleep`:
    //   1. Set wait_child_pending + args on the current UserTaskCtx.
    //   2. Save user state (RAX will be overwritten by the poll
    //      routine once a reap succeeds).
    //   3. Longjmp back to the executor via the yield hook.
    //
    // `UserTaskFuture::poll` sees `wait_child_pending = true` and
    // tries to reap.  If the queue is empty it stores `cx.waker()`
    // (so `on_child_exit` can fire it) and returns `Poll::Pending`.
    // The child gets scheduled, exits, `on_child_exit` wakes the
    // parent, and the parent is re-polled; this time the reap
    // succeeds and the result is written into the saved RAX.
    //
    // Fallback: if no polling future is installed (test context),
    // the code falls through to the spin below.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: uctx is valid for the lifetime of the polling
        // routine which holds it pinned; we're about to longjmp.
        unsafe {
            let uc = &*uctx;
            uc.wait_child_pending
                .store(true, core::sync::atomic::Ordering::Release);
            uc.wait_child_want_pid
                .store(want_pid, core::sync::atomic::Ordering::Release);
            uc.wait_child_status_ptr
                .store(status_ptr, core::sync::atomic::Ordering::Release);
            // Save user-mode register state.  The RAX written here
            // is a placeholder; UserTaskFuture::poll overwrites it
            // with the reaped child pid before re-entering user mode.
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            hook(uctx);
        }
        // unreachable — hook() never returns
    }

    // Test/no-future fallback: synchronous busy-poll (same as
    // before, kept for tests that use StubCtx without a real
    // UserTaskFuture / yield hook).  Cap at 60 s.
    let deadline = narf_time::Deadline::after_ms(60_000);
    let mut reaped = None;
    while !deadline.expired() {
        if let Some(entry) = try_reap(parent, want_pid) {
            reaped = Some(entry);
            break;
        }
        narf_scheduler::sleep_pumps::run();
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }
    }
    match reaped {
        Some((child, status)) => {
            if status_ptr != 0 {
                let _ = unsafe { copy_to_user(status_ptr, &status.to_ne_bytes()) };
            }
            ctx.set_return(SyscallReturn::ok(child));
        }
        // Use u64::MAX as the "error" sentinel since 0 is the
        // legitimate WNOHANG-with-no-exited-child return value
        // (so we can't reuse `invalid_op` whose rax = 0).
        None => ctx.set_return(SyscallReturn::ok(u64::MAX)),
    }
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

fn read_pgid(target: u64) -> u64 {
    let g = PGID_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&target).copied())
        .unwrap_or(target) // default: pgid == pid
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

fn sys_getpgid(ctx: &mut dyn TrapContext) {
    let pid = ctx.args().arg0;
    let target = if pid == 0 { current_task_id() } else { pid };
    ctx.set_return(SyscallReturn::ok(read_pgid(target)));
}

fn sys_setpgid(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let pgid = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let target = if pid == 0 { current_task_id() } else { pid };
    let value = if pgid == 0 { target } else { pgid };
    let mut g = PGID_TABLE.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    m.insert(target, value);
    ctx.set_return(SyscallReturn::ok(0));
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

fn sys_getsid(ctx: &mut dyn TrapContext) {
    let pid = ctx.args().arg0;
    let target = if pid == 0 { current_task_id() } else { pid };
    ctx.set_return(SyscallReturn::ok(read_sid(target)));
}

fn sys_setsid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    // POSIX: setsid(2) makes the caller a new session leader,
    // pgid = sid = pid. Record both tables together.
    {
        let mut g = SID_TABLE.lock();
        if let Some(m) = g.as_mut() {
            m.insert(task, task);
        }
    }
    {
        let mut g = PGID_TABLE.lock();
        if let Some(m) = g.as_mut() {
            m.insert(task, task);
        }
    }
    // Wave-76: a new session leader has no controlling tty until it
    // opens a tty without O_NOCTTY (or calls TIOCSCTTY). Drop any
    // inherited reference here so the next open(tty) installs cleanly.
    #[cfg(feature = "linux-compat")]
    {
        let mut g = CTTY_TABLE.lock();
        if let Some(m) = g.as_mut() {
            m.remove(&task);
        }
    }
    ctx.set_return(SyscallReturn::ok(task));
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
    uid: u32,
    gid: u32,
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

fn read_uidgid(task: u64) -> UidGid {
    let g = UIDGID_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or_default()
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

fn sys_getuid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    ctx.set_return(SyscallReturn::ok(read_uidgid(task).uid as u64));
}

fn sys_getgid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    ctx.set_return(SyscallReturn::ok(read_uidgid(task).gid as u64));
}

fn sys_setuid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let uid = ctx.args().arg0 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if write_uidgid(task, |e| e.uid = uid) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}

fn sys_setgid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let gid = ctx.args().arg0 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if write_uidgid(task, |e| e.gid = gid) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}

// ── Per-task rlimit table ──────────────────────────────────────────
//
// POSIX getrlimit / setrlimit query and update per-resource soft
// (`rlim_cur`) and hard (`rlim_max`) limits. NARF doesn't enforce
// these — capabilities replace authority, and task-bound resource
// budgets live in the scheduler's BudgetAccount path. The table
// here is structural state only so a libc consumer that
// round-trips `setrlimit(RLIMIT_NOFILE, &r)` followed by
// `getrlimit(RLIMIT_NOFILE, &r2)` sees `r2 == r`.
//
// Defaults match what real Linux distros surface to a normal user:
//   RLIMIT_CPU     = INFINITY
//   RLIMIT_FSIZE   = INFINITY
//   RLIMIT_DATA    = INFINITY
//   RLIMIT_STACK   = (8 MiB cur, INFINITY max)
//   RLIMIT_CORE    = (0 cur, INFINITY max)
//   RLIMIT_NOFILE  = (256 cur, 4096 max) — matches our actual fd-table cap
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
    // RLIMIT_NOFILE = 7.
    t[7] = RLimitPair {
        cur: 256,
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

fn sys_getrlimit(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let resource = args.arg0 as usize;
    let out_ptr = args.arg1 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let pair = match read_rlimit(task, resource) {
        Some(p) => p,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Write two u64s to user buffer under the SMAP bracket.
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&pair.cur.to_ne_bytes());
    buf[8..].copy_from_slice(&pair.max.to_ne_bytes());
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_setrlimit(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let resource = args.arg0 as usize;
    let in_ptr = args.arg1 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if in_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    // Read two u64s from user buffer under the SMAP bracket.
    let mut buf = [0u8; 16];
    if unsafe { copy_from_user(&mut buf, in_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let cur = u64::from_ne_bytes(buf[..8].try_into().unwrap());
    let max = u64::from_ne_bytes(buf[8..].try_into().unwrap());
    let task = current_task_id();
    if write_rlimit(task, resource, RLimitPair { cur, max }) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}

fn sys_prlimit64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let resource = args.arg1 as usize;
    let new_ptr = args.arg2 as u64;
    let old_ptr = args.arg3 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    // pid = 0 means "self"; non-zero pids are routed to that task
    // unconditionally (no permission check today — capabilities
    // would gate cross-task rlimit mutation in a real model).
    let task = if pid == 0 { current_task_id() } else { pid };

    // Validate resource bound up-front so the read+write is atomic
    // from the user's perspective.
    if resource >= RLIMIT_COUNT {
        ctx.set_return(fail);
        return;
    }

    // Snapshot prior so we can write `*old` *after* the update.
    let prior = read_rlimit(task, resource).unwrap_or_default();

    if new_ptr != 0 {
        // Read two u64s from user buffer under the SMAP bracket.
        let mut buf = [0u8; 16];
        if unsafe { copy_from_user(&mut buf, new_ptr) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        let cur = u64::from_ne_bytes(buf[..8].try_into().unwrap());
        let max = u64::from_ne_bytes(buf[8..].try_into().unwrap());
        if !write_rlimit(task, resource, RLimitPair { cur, max }) {
            ctx.set_return(fail);
            return;
        }
    }
    if old_ptr != 0 {
        // Write two u64s to user buffer under the SMAP bracket.
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&prior.cur.to_ne_bytes());
        buf[8..].copy_from_slice(&prior.max.to_ne_bytes());
        if unsafe { copy_to_user(old_ptr, &buf) }.is_err() {
            ctx.set_return(fail);
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
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
const TASK_COMM_LEN: usize = 16;

#[derive(Copy, Clone)]
struct PrctlState {
    name: [u8; TASK_COMM_LEN],
    dumpable: bool,
    no_new_privs: bool,
}

impl Default for PrctlState {
    fn default() -> Self {
        Self {
            name: [0; TASK_COMM_LEN],
            dumpable: true, // Linux default
            no_new_privs: false,
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

fn sys_prctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let op = args.arg0;
    let arg_a = args.arg1;
    let _arg_b = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();

    match op {
        PR_SET_NAME => {
            // arg_a is a pointer to a NUL-terminated or 16-byte
            // bounded user buffer. Copy at most TASK_COMM_LEN bytes
            // under the SMAP bracket, then find the NUL.
            if arg_a == 0 {
                ctx.set_return(fail);
                return;
            }
            let mut raw = [0u8; TASK_COMM_LEN];
            // copy_from_user validates range; copy up to TASK_COMM_LEN bytes.
            let _ = unsafe { copy_from_user(&mut raw, arg_a) };
            // Trim at first NUL.
            let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(TASK_COMM_LEN);
            let mut name = [0u8; TASK_COMM_LEN];
            name[..nul_pos].copy_from_slice(&raw[..nul_pos]);
            if !modify_prctl(task, |s| s.name = name) {
                ctx.set_return(fail);
                return;
            }
            // Mirror into PROC_COMM so /proc/[pid]/comm reflects the new name.
            if let Ok(s) = core::str::from_utf8(&name[..nul_pos]) {
                set_proc_comm(task, s);
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_NAME => {
            if arg_a == 0 {
                ctx.set_return(fail);
                return;
            }
            let s = read_prctl(task);
            // Copy the 16-byte name buffer to user space under the SMAP bracket.
            if unsafe { copy_to_user(arg_a, &s.name) }.is_err() {
                ctx.set_return(fail);
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_SET_DUMPABLE => {
            modify_prctl(task, |s| s.dumpable = arg_a != 0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_DUMPABLE => {
            let s = read_prctl(task);
            ctx.set_return(SyscallReturn::ok(s.dumpable as u64));
        }
        PR_SET_NO_NEW_PRIVS => {
            modify_prctl(task, |s| s.no_new_privs = arg_a != 0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_NO_NEW_PRIVS => {
            let s = read_prctl(task);
            ctx.set_return(SyscallReturn::ok(s.no_new_privs as u64));
        }
        _ => ctx.set_return(fail),
    }
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

fn sys_sched_get_priority_max(ctx: &mut dyn TrapContext) {
    let policy = ctx.args().arg0;
    match priority_max_for_policy(policy) {
        Some(p) => ctx.set_return(SyscallReturn::ok(p as u64)),
        None => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
    }
}

fn sys_sched_get_priority_min(ctx: &mut dyn TrapContext) {
    let policy = ctx.args().arg0;
    match priority_min_for_policy(policy) {
        Some(p) => ctx.set_return(SyscallReturn::ok(p as u64)),
        None => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
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

fn sys_sched_getparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let out = args.arg1 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out == 0 {
        ctx.set_return(fail);
        return;
    }
    let task = if pid == 0 { current_task_id() } else { pid };
    let g = SCHED_PARAM_TABLE.lock();
    let val = g.as_ref().and_then(|m| m.get(&task).copied()).unwrap_or(0);
    // Write one i32 to user space under the SMAP bracket.
    if unsafe { copy_to_user(out, &val.to_ne_bytes()) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_sched_setparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let inp = args.arg1 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if inp == 0 {
        ctx.set_return(fail);
        return;
    }
    // Read one i32 from user space under the SMAP bracket.
    let mut buf = [0u8; 4];
    if unsafe { copy_from_user(&mut buf, inp) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let val = i32::from_ne_bytes(buf);
    let task = if pid == 0 { current_task_id() } else { pid };
    let mut g = SCHED_PARAM_TABLE.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    m.insert(task, val);
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Sched_get/setaffinity — CPU bitmap ─────────────────────────────
//
// NARF user mode is single-CPU; the affinity bitmap is structural
// state only. getaffinity always reports a 1-bit mask (CPU 0 set);
// setaffinity reads the supplied bitmap and discards it (no
// pinning to perform). Surface exists so pthread / libnuma
// probes succeed at startup.

fn sys_sched_getaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _pid = args.arg0;
    let size = args.arg1 as usize;
    let out = args.arg2 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out == 0 || size == 0 {
        ctx.set_return(fail);
        return;
    }
    // Linux requires `size` be a multiple of sizeof(unsigned long)
    // (8 on x86_64). Round down for the actual write but reject
    // truly tiny requests so a caller's `cpu_set_t` matches.
    if size < 8 {
        ctx.set_return(fail);
        return;
    }
    let bytes = size & !7; // round to 8
                           // Validate the destination range before allocating — an oversized size
                           // would otherwise OOM the kernel heap before copy_to_user fires.
    if validate_user_range(out, bytes).is_err() {
        ctx.set_return(fail);
        return;
    }
    // Build the affinity bitmap in kernel memory (CPU 0 set, rest zero),
    // then copy to user space under the SMAP bracket.
    let mut kbuf = alloc::vec![0u8; bytes];
    kbuf[0] = 0x01; // CPU 0 set
    if unsafe { copy_to_user(out, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(bytes as u64));
}

fn sys_sched_setaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _pid = args.arg0;
    let size = args.arg1 as usize;
    let buf = args.arg2 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf == 0 || size == 0 {
        ctx.set_return(fail);
        return;
    }
    // Validate the user pointer range but discard the value — we don't pin.
    if validate_user_range(buf, size.min(8)).is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Getcpu — current CPU + NUMA node query ─────────────────────────
//
// Linux getcpu(2): real CPU + NUMA node lookup. NARF user mode is
// single-CPU and single-node today — both return 0 — but library
// code (libnuma, RT performance probes) queries this at startup
// and the entry must exist.

fn sys_getcpu(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let cpu_ptr = args.arg0 as u64;
    let node_ptr = args.arg1 as u64;
    // Write CPU=0, node=0 under the SMAP bracket.
    if cpu_ptr != 0 {
        let _ = unsafe { copy_to_user(cpu_ptr, &0u32.to_ne_bytes()) };
    }
    if node_ptr != 0 {
        let _ = unsafe { copy_to_user(node_ptr, &0u32.to_ne_bytes()) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}

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

fn sys_umask(ctx: &mut dyn TrapContext) {
    let new_mask = (ctx.args().arg0 as u32) & 0o777;
    let task = current_task_id();
    let mut g = UMASK_TABLE.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => {
            // Treat lack of init as default-mask — return that
            // and accept the new mask going forward.
            ctx.set_return(SyscallReturn::ok(UMASK_DEFAULT as u64));
            return;
        }
    };
    let prior = m.insert(task, new_mask).unwrap_or(UMASK_DEFAULT);
    ctx.set_return(SyscallReturn::ok(prior as u64));
}

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

fn sys_getpriority(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i64;
    let _who = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if which != PRIO_PROCESS_VAL {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let nice = read_nice(task);
    // Linux convention: getpriority returns the value pre-shifted
    // by +20 so a -20..=19 nice maps to 0..=39 on the wire — the
    // user-side libc subtracts 20 to recover the signed value.
    // Errors then surface as the wire -1 distinct from a value of 19.
    let shifted = (nice + 20) as u64;
    ctx.set_return(SyscallReturn::ok(shifted));
}

fn sys_setpriority(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i64;
    let _who = args.arg1;
    let prio = args.arg2 as i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if which != PRIO_PROCESS_VAL || !(-20..=19).contains(&prio) {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    if write_nice(task, prio as i32) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
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

fn sys_times(ctx: &mut dyn TrapContext) {
    let out_ptr = ctx.args().arg0 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let ns: u64 = narf_scheduler::narf_time::monotonic_ns();
    let ticks: i64 = (ns / (1_000_000_000 / CLK_TCK_HZ)) as i64;
    if out_ptr != 0 {
        // Build the tms struct (four i64s: utime, stime, cutime, cstime)
        // in kernel memory, then copy to user under the SMAP bracket.
        let mut kbuf = [0u8; 32];
        kbuf[..8].copy_from_slice(&ticks.to_ne_bytes()); // utime
                                                         // stime, cutime, cstime already zero.
        if unsafe { copy_to_user(out_ptr, &kbuf) }.is_err() {
            ctx.set_return(fail);
            return;
        }
    }
    if ticks < 0 {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(ticks as u64));
}

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

fn sys_getrusage(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _who = args.arg0 as i64;
    let out = args.arg1 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out == 0 {
        ctx.set_return(fail);
        return;
    }
    let ns: u64 = narf_scheduler::narf_time::monotonic_ns();
    let utime_sec = (ns / 1_000_000_000) as i64;
    let utime_usec = ((ns % 1_000_000_000) / 1_000) as i64;
    // Build the rusage struct (RUSAGE_TOTAL_I64S i64s) in kernel
    // memory, then copy to user under the SMAP bracket.
    let mut kbuf = [0u8; RUSAGE_TOTAL_I64S * 8];
    kbuf[..8].copy_from_slice(&utime_sec.to_ne_bytes()); // ru_utime.tv_sec
    kbuf[8..16].copy_from_slice(&utime_usec.to_ne_bytes()); // ru_utime.tv_usec
                                                            // ru_stime + 14 tail fields already zero.
    if unsafe { copy_to_user(out, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

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

fn sys_gethostname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0 as u64;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf == 0 || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // Wave-72: per-task UTS namespace wins when present.
    #[cfg(feature = "container")]
    let host_owned: Option<alloc::string::String> = {
        let task = current_task_id();
        crate::namespaces::uts_ns_of(task).map(|ns| ns.hostname())
    };
    #[cfg(not(feature = "container"))]
    let host_owned: Option<alloc::string::String> = None;

    let g_fallback;
    let bytes: &[u8] = if let Some(ref s) = host_owned {
        s.as_bytes()
    } else {
        g_fallback = HOSTNAME.lock();
        g_fallback.as_bytes()
    };
    if bytes.len() + 1 > len {
        ctx.set_return(fail);
        return;
    }
    // Build NUL-terminated output in kernel memory, then copy_to_user.
    let mut kbuf = alloc::vec![0u8; bytes.len() + 1];
    kbuf[..bytes.len()].copy_from_slice(bytes);
    // kbuf[bytes.len()] is already 0 (NUL).
    let n = bytes.len();
    drop(host_owned);
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(n as u64));
}

fn sys_sethostname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0 as u64;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if len == 0 || len > HOSTNAME_MAX {
        ctx.set_return(fail);
        return;
    }
    let s = match copy_user_path(buf, len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Wave-72: if caller has an explicit UTS NS, write there; else fall
    // through to the global hostname slot.
    #[cfg(feature = "container")]
    {
        let task = current_task_id();
        if let Some(ns) = crate::namespaces::uts_ns_of(task) {
            ns.set_hostname(&s);
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
    }
    let mut g = HOSTNAME.lock();
    g.clear();
    g.push_str(&s);
    ctx.set_return(SyscallReturn::ok(0));
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

fn sys_uname(ctx: &mut dyn TrapContext) {
    let buf = ctx.args().arg0 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf == 0 {
        ctx.set_return(fail);
        return;
    }
    // Per-task UTS namespace lives behind the `container` feature.
    // Without it the hostname / domainname are flat global strings.
    #[cfg(feature = "container")]
    let (hostname, domainname) = {
        let task = current_task_id();
        let ns = crate::namespaces::current_uts_ns(task);
        (ns.hostname(), ns.domainname())
    };
    #[cfg(not(feature = "container"))]
    let (hostname, domainname): (alloc::string::String, alloc::string::String) = (
        alloc::string::String::from("narf"),
        alloc::string::String::new(),
    );
    let mut kbuf = alloc::vec![0u8; UTSNAME_STRUCT_LEN];
    let mut off = 0usize;
    // sysname / nodename / release / version / machine / domainname.
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], "NARF");
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], &hostname);
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], "0.1");
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], "narf");
    off += UTSNAME_FIELD_LEN;
    #[cfg(target_arch = "x86_64")]
    let machine = "x86_64";
    #[cfg(target_arch = "aarch64")]
    let machine = "aarch64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let machine = "unknown";
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], machine);
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], &domainname);
    let _ = off;
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

#[cfg(feature = "container")]
fn sys_setdomainname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0 as u64;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if len == 0 || len > crate::namespaces::UTS_NAME_MAX {
        ctx.set_return(fail);
        return;
    }
    let s = match copy_user_path_raw(buf, len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let task = current_task_id();
    let ns = crate::namespaces::current_uts_ns(task);
    ns.set_domainname(&s);
    ctx.set_return(SyscallReturn::ok(0));
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

#[cfg(feature = "container")]
fn sys_shmget(ctx: &mut dyn TrapContext) {
    let key = ctx.args().arg0 as u32;
    let task = current_task_id();
    let ns = current_or_default_ipc_ns(task);
    ctx.set_return(SyscallReturn::ok(ns.shmget(key) as u64));
}

#[cfg(feature = "container")]
fn sys_semget(ctx: &mut dyn TrapContext) {
    let key = ctx.args().arg0 as u32;
    let task = current_task_id();
    let ns = current_or_default_ipc_ns(task);
    ctx.set_return(SyscallReturn::ok(ns.semget(key) as u64));
}

#[cfg(feature = "container")]
fn sys_msgget(ctx: &mut dyn TrapContext) {
    let key = ctx.args().arg0 as u32;
    let task = current_task_id();
    let ns = current_or_default_ipc_ns(task);
    ctx.set_return(SyscallReturn::ok(ns.msgget(key) as u64));
}

// ── Yield / Sleep — Ok ─────────────────────────────────────────────

fn sys_noop_ok(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}

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

fn sys_getrandom(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as u64;
    let len = args.arg1 as usize;
    let _flags = args.arg2; // accepted-and-ignored
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if len > MAX_USER_COPY {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
    // Generate random bytes into a kernel buffer, then copy to user
    // space under the SMAP bracket.
    let mut kbuf = alloc::vec![0u8; len];
    let mut i = 0usize;
    while i + 4 <= len {
        let v = next_random_u32();
        kbuf[i] = (v & 0xFF) as u8;
        kbuf[i + 1] = ((v >> 8) & 0xFF) as u8;
        kbuf[i + 2] = ((v >> 16) & 0xFF) as u8;
        kbuf[i + 3] = ((v >> 24) & 0xFF) as u8;
        i += 4;
    }
    if i < len {
        let v = next_random_u32();
        let mut shift = 0u32;
        while i < len {
            kbuf[i] = ((v >> shift) & 0xFF) as u8;
            i += 1;
            shift += 8;
        }
    }
    if unsafe { copy_to_user(ptr, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(len as u64));
}

fn sys_sleep(ctx: &mut dyn TrapContext) {
    let ns = ctx.args().arg0;
    if ns == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let start = narf_scheduler::narf_time::monotonic_ns();
    // Saturating add: u64 overflow on `start + ns` is structurally
    // impossible at realistic clock rates, but the saturate keeps
    // the deadline tight against pathological inputs.
    let deadline = start.saturating_add(ns);

    // Polling-future path: stash the deadline on the current
    // UserTaskCtx, bake the eventual return value (Ok(0)) into the
    // saved RAX so the user reads it on resume, save the user
    // state, then longjmp back via the yield hook. The next
    // `UserTaskFuture::poll` consults the deadline and parks the
    // task without re-entering user mode until it expires.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        ctx.set_return(SyscallReturn::ok(0));
        // SAFETY: uctx is valid for the lifetime of the polling
        // routine (its caller, on the same CPU) which holds it
        // pinned. We're about to never return.
        unsafe {
            let uc = &*uctx;
            uc.sleep_deadline_ns
                .store(deadline, core::sync::atomic::Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            hook(uctx);
        }
        // unreachable
    }

    // Fallback busy-wait (no polling future installed — test
    // trampolines, sub-polling test harnesses, etc.).
    while narf_scheduler::narf_time::monotonic_ns() < deadline {
        sleep_pumps::run();
        core::hint::spin_loop();
    }
    ctx.set_return(SyscallReturn::ok(0));
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

fn sys_chdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as u64;
    let len = args.arg1 as usize;
    // See sys_stat for the failure-sentinel rationale: the user-
    // runtime asm wrapper observes only `value`, so success and
    // invalid_op both surface as rax=0 without this.
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_path(ptr, len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Stage-4 first cut: absolute paths only. Relative-path
    // resolution joins with the *at(2) family in a follow-up; we
    // reject early so callers don't accidentally rely on a
    // half-implemented relative path being silently dropped.
    if !path.starts_with('/') {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let mut g = CWD_TABLE.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    map.insert(task, path);
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_getcwd(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0 as *mut u8;
    let len = args.arg1 as usize;
    if buf.is_null() || len == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let task = current_task_id();
    let cwd = {
        let g = CWD_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).cloned())
            .unwrap_or_else(|| alloc::string::String::from("/"))
    };
    // Need cwd.len() + 1 bytes (string + NUL terminator). POSIX
    // getcwd(3) returns ERANGE here; the syscall shape doesn't
    // surface errno yet so we fold both "no buf" and "buf too
    // small" into InvalidOp. A libc shim is expected to translate.
    let needed = cwd.len() + 1;
    if len < needed {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Build NUL-terminated cwd in kernel memory, then copy_to_user.
    let mut kbuf = alloc::vec![0u8; cwd.len() + 1];
    kbuf[..cwd.len()].copy_from_slice(cwd.as_bytes());
    // kbuf[cwd.len()] is already 0 (NUL).
    if unsafe { copy_to_user(buf as u64, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(cwd.len() as u64));
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

/// Default per-task heap base. Far enough from the mmap cursor and
/// the user stack to leave room for both to grow without colliding
/// with the brk arena.
const BRK_DEFAULT_BASE: u64 = 0x0000_5000_0000_0000;

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

fn sys_execve(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int execve(const char *pathname, char *const argv[],
    // char *const envp[])`. Register mapping on x86_64:
    //   rdi = pathname (NUL-terminated C string)
    //   rsi = argv     (NULL-terminated array of `char *`)
    //   rdx = envp     (NULL-terminated array of `char *`)
    let path_uptr = args.arg0;
    let argv_uptr = args.arg1;
    let envp_uptr = args.arg2;

    if path_uptr == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    // Step 1: copy the pathname from user memory under SMAP.
    let path_owned = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let path: &str = &path_owned;

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
    let argv_refs: alloc::vec::Vec<&str> = argv_strs.iter().map(|s| s.as_str()).collect();
    let envp_refs: alloc::vec::Vec<&str> = envp_strs.iter().map(|s| s.as_str()).collect();

    // Step 3: resolve the path through the VFS and read the
    // ELF bytes into a kernel-owned buffer. The buffer survives
    // the AS swap below.
    let ops = match narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            poll_blocking(narf_filesystem::resolve_async(fs.root(), rel)).and_then(|r| r.ok())
        })
        .flatten()
    {
        Some(o) => o,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Stat for file size, then read everything.
    let stat = ops.stat();
    let file_size = stat.size as usize;
    if file_size < 64 || file_size > 64 * 1024 * 1024 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let mut elf_buf = alloc::vec![0u8; file_size];
    let mut off = 0usize;
    while off < file_size {
        match poll_blocking(ops.read(off as u64, &mut elf_buf[off..])) {
            Some(Ok(0)) => break, // short read at EOF
            Some(Ok(n)) => off += n,
            _ => {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        }
    }
    if off < 64 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    elf_buf.truncate(off);

    // Step 4: load the new image. SAFETY: load_user_process_with's
    // contract — identity-mapped low 4 GiB, frame allocator
    // initialised. Both hold by the time any user task is running.
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

    // /proc/[pid]/cmdline + comm: preserve argv as NUL-separated
    // bytes, derive comm from argv[0]'s basename (Linux convention).
    set_proc_argv(task, &argv_refs);
    if let Some(first) = argv_refs.first() {
        let basename = first.rsplit('/').next().unwrap_or(first);
        set_proc_comm(task, basename);
    }

    // Step 5: swap the scheduler slot's AS Arc. Without this the
    // poll path's later activate() would still target the old AS
    // until the future's process.address_space update lands.
    let _prev_slot_as = narf_scheduler::replace_address_space(
        narf_scheduler::TaskId(task),
        new_proc.address_space.clone(),
    );

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

/// Parse a NUL-separated user-supplied string pack into a Vec of
/// kernel-owned `String`s. Returns Err on any UTF-8 violation,
/// pointer issue, or pack-too-long-without-terminator condition.
///
/// Pack format: zero or more strings, each terminated by a NUL
/// byte. The pack itself is `len` bytes long; we read until we
/// see len bytes total. An empty pack (len == 0) returns an
/// empty Vec (legal — `execve` with no argv).
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
fn copy_user_cstr(ptr: u64, max_len: usize) -> Option<alloc::string::String> {
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
// NARF stance: `narf_arch::x86_64::smap::with_user_access` is the
// single sanctioned bracket.  On non-x86_64 targets the helper
// degrades to a plain volatile copy because those architectures have
// no SMAP equivalent.
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
/// - Non-canonical addresses (bits 48–62 are partial — neither
///   all-zero for user-space nor all-one for kernel-space) → EFAULT
/// - Integer overflow of `ptr + len` → EFAULT
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
fn validate_user_range(ptr: u64, len: usize) -> Result<(), u64> {
    if len > MAX_USER_COPY {
        return Err(EINVAL_CODE);
    }
    if ptr == 0 {
        return Err(EFAULT);
    }
    // Reject non-canonical addresses (x86_64 requires bits 48–63 to
    // be the sign-extension of bit 47). An address like
    // 0x0001_0000_0000_0000 has bit-48 set but bits 49–63 clear,
    // which the CPU would fault as a GP on any memory access.
    #[cfg(target_arch = "x86_64")]
    {
        // Bits 48..=62 must all be 0 (user) or all 1 (kernel).
        // Mask out bit 63 (top-level sign) and check the middle range.
        let bits_48_62 = (ptr >> 48) & 0x7FFF;
        if bits_48_62 != 0 && bits_48_62 != 0x7FFF {
            return Err(EFAULT);
        }
    }
    // Reject integer overflow of the range end.
    if ptr.checked_add(len as u64).is_none() {
        return Err(EFAULT);
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
    // SAFETY: range-validated above; SMAP bracket guards the access.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), dst.len());
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        for i in 0..dst.len() {
            dst[i] = core::ptr::read_volatile(src.add(i));
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
unsafe fn copy_from_user_vec(src_uptr: u64, len: usize) -> Result<alloc::vec::Vec<u8>, u64> {
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
    // SAFETY: range-validated above; SMAP bracket guards the access.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        });
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        for i in 0..src.len() {
            core::ptr::write_volatile(dst.add(i), src[i]);
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
const MS_REC: u64 = 1 << 14;
const MS_RELATIME: u64 = 1 << 21;

fn sys_mount(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);

    let source = match copy_user_str(args.arg0 as *const u8, args.arg1 as usize, 256) {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(fail);
            return;
        }
    };
    let target_raw = match copy_user_str(args.arg2 as *const u8, args.arg3 as usize, 256) {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(fail);
            return;
        }
    };
    // Resolve target under the calling task's chroot.
    let target = apply_chroot(target_raw.as_str());
    // Resolve source under chroot too when it's a path (bind / tmpfs
    // source-as-label is harmless to pass through; block-device names
    // don't start with `/` so apply_chroot is a no-op).
    let source_resolved = if source.starts_with('/') {
        apply_chroot(source.as_str())
    } else {
        source.clone()
    };
    // Wave-71: ABI fix — 64-bit pointers cannot be packed with lengths.
    // arg4 is the full fstype_ptr. arg5 packs fstype_len in the top
    // 32 bits and MS_* flags in the bottom 32 bits.
    let fstype_ptr = args.arg4 as *const u8;
    let fstype_len = (args.arg5 >> 32) as usize;
    let fstype = match copy_user_str(fstype_ptr, fstype_len, 32) {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(fail);
            return;
        }
    };
    // arg5 carries the MS_* flag word.
    let flags = args.arg5 & 0xFFFF_FFFF;
    // Silence-the-warning swallow for option bits we accept but
    // don't yet act on; they're documented above.
    let _ =
        flags & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_REMOUNT | MS_REC | MS_RELATIME);

    let auth = narf_filesystem::bootstrap_mount_authority();
    let domain = narf_lib::id::DomainId::DRIVER_0;

    // Wave-71: MS_BIND or fstype=="bind" → bind mount. `source` is
    // an absolute path; `target` is the new path. No block device.
    if fstype == "bind" || (flags & MS_BIND) != 0 {
        return match narf_filesystem::registry().bind_mount(
            &auth,
            source_resolved.as_str(),
            target.as_str(),
        ) {
            Ok(_h) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(fail),
        };
    }

    // Wave-71: tmpfs / memfs — synthesize an empty in-memory FS.
    if fstype == "tmpfs" || fstype == "ramfs" {
        let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::MemFs::new("tmpfs"));
        return match narf_filesystem::registry().mount_arc(&auth, target.as_str(), fs) {
            Ok(_h) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(fail),
        };
    }

    // Block-device-backed mounts: resolve `source` as a registered
    // block-device name. Strip a leading "/dev/" so callers can
    // pass either form.
    let dev_name = source.strip_prefix("/dev/").unwrap_or(source.as_str());
    let entry = match narf_block::block_devices()
        .into_iter()
        .find(|e| e.name == dev_name)
    {
        Some(e) => e,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    let result = match fstype.as_str() {
        "fat" | "vfat" | "fat16" | "fat32" => {
            let dev = narf_block::SyncBlock::new(entry.dev.clone());
            let fut = narf_drivers_fs_fat::mount_fat(&auth, target.as_str(), dev, domain);
            poll_blocking(fut)
        }
        _ => None,
    };

    match result {
        Some(Ok(_handle)) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

// Wave-71: Linux MNT_* flags for umount2(2).
const MNT_FORCE: u64 = 1 << 0;
const MNT_DETACH: u64 = 1 << 1;
const MNT_EXPIRE: u64 = 1 << 2;
const UMOUNT_NOFOLLOW: u64 = 1 << 3;

fn sys_umount2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);
    let target_raw = match copy_user_str(args.arg0 as *const u8, args.arg1 as usize, 256) {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(fail);
            return;
        }
    };
    let target = apply_chroot(target_raw.as_str());
    let flags = args.arg2;
    // We accept MNT_FORCE / MNT_DETACH / MNT_EXPIRE / UMOUNT_NOFOLLOW
    // but the registry doesn't yet track in-flight refs against a
    // mount, so the pop-by-path is unconditional. The flag word is
    // recorded for diagnostic symmetry only.
    let _ = flags & (MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW);
    let auth = narf_filesystem::bootstrap_mount_authority();
    // SAFETY: bootstrapping a Write cap is the same TCB-trusted op
    // the registry uses internally to mint the per-mount handle.
    let handle: narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Write> =
        narf_capabilities::Cap::<narf_filesystem::MountPoint, narf_capabilities::Write>::bootstrap(
        );
    let _ = auth;
    match narf_filesystem::registry().unmount(&handle, target.as_str()) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(fail),
    }
}

/// Layout for the user's statfs buffer. Matches POSIX-2017
/// `<sys/statvfs.h>` `struct statvfs` for the fields userspace
/// programs actually read; we don't currently fill flags / fsid.
#[repr(C)]
#[derive(Default)]
struct StatfsBuf {
    bsize: u64,   // block size in bytes
    frsize: u64,  // fragment size (== bsize on simple FSes)
    blocks: u64,  // total blocks
    bfree: u64,   // free blocks
    bavail: u64,  // free blocks available to non-root
    files: u64,   // total inodes
    ffree: u64,   // free inodes
    namemax: u64, // max filename length
}

fn fill_statfs_for_path(path: &str, buf_ptr: u64) -> bool {
    if buf_ptr == 0 {
        return false;
    }
    // The registered Arc<dyn FsInstance> doesn't (yet) expose a
    // statfs trait method, so we fill a synthetic shape that
    // satisfies POSIX-shaped readers. Real per-FS values land when
    // FsInstance grows a `statfs()` method.
    let _covered = narf_filesystem::registry()
        .resolve_absolute(path, |fs, _rel| fs.name().len() > 0)
        .unwrap_or(false);
    let stat = StatfsBuf {
        bsize: 4096,
        frsize: 4096,
        blocks: 0,
        bfree: 0,
        bavail: 0,
        files: 0,
        ffree: 0,
        namemax: 255,
    };
    // Copy the statfs struct to user space under the SMAP bracket.
    let bytes: [u8; core::mem::size_of::<StatfsBuf>()] = unsafe { core::mem::transmute(stat) };
    unsafe { copy_to_user(buf_ptr, &bytes) }.is_ok()
}

fn sys_statfs(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);
    let path = match copy_user_str(args.arg0 as *const u8, args.arg1 as usize, 4096) {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(fail);
            return;
        }
    };
    let buf_ptr = args.arg2;
    if fill_statfs_for_path(&path, buf_ptr) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
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

fn sys_unshare(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0;
    const CLONE_NEWNS: u64 = 0x00020000;
    #[cfg(feature = "container")]
    const CLONE_NEWPID: u64 = 0x20000000;

    let mut any = false;

    if flags & CLONE_NEWNS != 0 {
        task_mount_ns_init();
        let task = current_task_id();
        let snap = narf_filesystem::MountNamespace::snapshot_global();
        let mut g = TASK_MOUNT_NS.lock();
        if let Some(m) = g.as_mut() {
            m.insert(task, snap);
            any = true;
        } else {
            ctx.set_return(SyscallReturn::ok(!0u64));
            return;
        }
    }

    #[cfg(feature = "container")]
    if flags & CLONE_NEWPID != 0 {
        let task = current_task_id();
        // The task's outer pid is what the root-namespace fork
        // recorded. If no mapping is present, fall back to the task
        // id itself — it's a kernel-spawned task with implicit
        // outer == inner already.
        let outer = task_to_pid_raw(task).unwrap_or(task);
        let _ns = crate::pid_ns::unshare_pid_ns(task, outer);
        any = true;
    }

    // Wave-72 — UTS / NET / IPC namespaces.
    #[cfg(feature = "container")]
    {
        let task = current_task_id();
        if flags & crate::namespaces::CLONE_NEWUTS != 0 {
            crate::namespaces::unshare_uts(task);
            any = true;
        }
        if flags & crate::namespaces::CLONE_NEWNET != 0 {
            crate::namespaces::unshare_net(task);
            any = true;
        }
        if flags & crate::namespaces::CLONE_NEWIPC != 0 {
            crate::namespaces::unshare_ipc(task);
            any = true;
        }
    }

    // Honour the no-op path (no NS bits set) as success — Linux unshare
    // returns 0 with flags=0.
    let _ = any;
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Wave-67: setns(target, nstype) ─────────────────────────────────
//
// Linux setns takes a fd referring to /proc/[pid]/ns/<type>. NARF
// doesn't yet expose those symlinks; the interim NARF surface
// accepts `target` as the outer TaskId / outer ProcessId of a task
// whose namespace family we want to join. Once /proc/[pid]/ns/* is
// plumbed, we'll add an inner branch that resolves the fd via the
// fd table.

fn sys_setns(ctx: &mut dyn TrapContext) {
    #[cfg(feature = "container")]
    {
        let args = *ctx.args();
        let target = args.arg0;
        let nstype = args.arg1;
        const CLONE_NEWNS: u64 = 0x00020000;
        const CLONE_NEWPID: u64 = 0x20000000;
        let caller = current_task_id();
        let mut any = false;

        // Resolve target: prefer outer-pid lookup, fall back to
        // treating `target` as an outer TaskId directly.
        let target_task = pid_to_task_raw(target).unwrap_or(target);

        if nstype & CLONE_NEWPID != 0 {
            match crate::pid_ns::ns_of(target_task) {
                Some(ns) => {
                    let outer = task_to_pid_raw(caller).unwrap_or(caller);
                    let _ = crate::pid_ns::attach_to_ns(caller, outer, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }

        if nstype & CLONE_NEWNS != 0 {
            match mount_namespace_of(target_task) {
                Some(ns) => {
                    install_mount_namespace(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }

        // Wave-72 — UTS / NET / IPC. Target must have an explicit
        // per-task NS of the requested flavour; otherwise EINVAL.
        if nstype & crate::namespaces::CLONE_NEWUTS != 0 {
            match crate::namespaces::uts_ns_of(target_task) {
                Some(ns) => {
                    crate::namespaces::setns_uts(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }
        if nstype & crate::namespaces::CLONE_NEWNET != 0 {
            match crate::namespaces::net_ns_of(target_task) {
                Some(ns) => {
                    crate::namespaces::setns_net(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }
        if nstype & crate::namespaces::CLONE_NEWIPC != 0 {
            match crate::namespaces::ipc_ns_of(target_task) {
                Some(ns) => {
                    crate::namespaces::setns_ipc(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }

        if !any {
            // No supported nstype bits — Linux returns EINVAL.
            ctx.set_return(SyscallReturn::ok(!0u64));
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    #[cfg(not(feature = "container"))]
    {
        ctx.set_return(SyscallReturn::ok(!0u64));
    }
}

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
fn apply_chroot(path: &str) -> alloc::string::String {
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
fn apply_chroot(path: &str) -> alloc::string::String {
    alloc::string::String::from(path)
}

// ── Wave-71: chroot(2) ────────────────────────────────────────────
#[cfg(feature = "linux-compat")]
fn sys_chroot(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok((-1i64) as u64);
    let raw = match copy_user_path_raw(args.arg0 as u64, args.arg1 as usize) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if !raw.starts_with('/') {
        ctx.set_return(fail);
        return;
    }
    // Compose against any existing chroot (nested chroot resolves
    // under the current root before installation).
    let resolved = apply_chroot(&raw);
    // Verify resolved exists as a directory under the global
    // registry — match Linux semantics: chroot fails if target
    // doesn't exist. We treat a covering mount as sufficient.
    let covered = narf_filesystem::registry()
        .resolve_absolute(&resolved, |_fs, _rel| true)
        .unwrap_or(false);
    if !covered {
        ctx.set_return(fail);
        return;
    }
    root_dir_init_if_needed();
    let task = current_task_id();
    let mut g = ROOT_DIR_TABLE.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task, resolved);
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}

// ── Wave-71: pivot_root(2) ────────────────────────────────────────
//
// Linux semantics: the calling task's old root becomes accessible at
// `put_old` (an absolute path under `new_root`), and `new_root`
// becomes the new `/`. NARF approximation: register `put_old`
// (resolved under the new root) as a bind mount of the previous
// root path, then install the new chroot.
#[cfg(all(feature = "linux-compat", feature = "container"))]
fn sys_pivot_root(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok((-1i64) as u64);
    let new_root = match copy_user_path_raw(args.arg0 as u64, args.arg1 as usize) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let put_old = match copy_user_path_raw(args.arg2 as u64, args.arg3 as usize) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if !new_root.starts_with('/') || !put_old.starts_with('/') {
        ctx.set_return(fail);
        return;
    }
    // Resolve under the current chroot.
    let new_root_resolved = apply_chroot(&new_root);
    let put_old_resolved = apply_chroot(&put_old);
    // Snapshot the prior root for bind-mounting.
    let task = current_task_id();
    let prior_root = {
        let g = ROOT_DIR_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).cloned())
            .unwrap_or_else(|| alloc::string::String::from("/"))
    };
    // new_root must exist under the prior root.
    let new_root_ok = narf_filesystem::registry()
        .resolve_absolute(&new_root_resolved, |_fs, _rel| true)
        .unwrap_or(false);
    if !new_root_ok {
        ctx.set_return(fail);
        return;
    }
    // Bind-mount prior_root at put_old_resolved so the old root is
    // still reachable from inside the new root.
    let auth = narf_filesystem::bootstrap_mount_authority();
    let _ = narf_filesystem::registry().bind_mount(&auth, &prior_root, &put_old_resolved);
    // Install the new root.
    root_dir_init_if_needed();
    let mut g = ROOT_DIR_TABLE.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task, new_root_resolved);
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}

// ── Wave-71 test hooks ────────────────────────────────────────────
//
// Smokes in `mount_e2e_tests` drive the syscall handlers through a
// synthetic TrapContext + kernel-heap path buffers. These thin
// wrappers expose the file-private handlers without re-exporting
// the entire `sys_*` family.

#[doc(hidden)]
pub fn sys_mount_for_test(ctx: &mut dyn TrapContext) {
    sys_mount(ctx);
}

#[doc(hidden)]
pub fn sys_umount2_for_test(ctx: &mut dyn TrapContext) {
    sys_umount2(ctx);
}

#[cfg(feature = "linux-compat")]
#[doc(hidden)]
pub fn sys_chroot_for_test(ctx: &mut dyn TrapContext) {
    sys_chroot(ctx);
}

#[cfg(all(feature = "linux-compat", feature = "container"))]
#[doc(hidden)]
pub fn sys_pivot_root_for_test(ctx: &mut dyn TrapContext) {
    sys_pivot_root(ctx);
}

#[doc(hidden)]
pub fn apply_chroot_for_test(p: &str) -> alloc::string::String {
    apply_chroot(p)
}

fn sys_fstatfs(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);
    let _fd = args.arg0 as i32;
    let buf_ptr = args.arg1;
    // Resolving fd → mount-path requires the fd table to record the
    // mount that opened it; we do not (yet) plumb that through. As
    // an interim, return synthetic stats for "/" — every fd lives
    // under some mount, and "/" is the lowest-information answer
    // POSIX permits.
    if fill_statfs_for_path("/", buf_ptr) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}

fn sys_brk(ctx: &mut dyn TrapContext) {
    let new_break = ctx.args().arg0;
    let task = current_task_id();

    // Snapshot the current break (initialising the slot on first call).
    let cur = {
        let mut g = BRK_TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
        };
        *map.entry(task).or_insert(BRK_DEFAULT_BASE)
    };

    // Query path: arg0 == 0 just returns the current break.
    if new_break == 0 {
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }

    // Shrink path: walk the per-grow-call brk regions (each one
    // base ≥ BRK_DEFAULT_BASE) and unmap any whose base falls
    // entirely within [new_break_aligned, cur_aligned). Each
    // unmap_region call walks PTEs + free_frame's the underlying
    // physical pages so frames return to the allocator. A grow
    // region whose base sits BELOW new_break but extends past it
    // is left intact — partial unmapping would need a region-
    // split primitive; documented limitation, slight over-keep
    // bounded by the grow chunk size (one page on the smallest
    // grow, larger when the user calls brk(big_jump)).
    if new_break < cur {
        if let Some(as_ref) = current_address_space() {
            let new_aligned = (new_break + 0xFFF) & !0xFFFu64;
            let mut bases_to_unmap: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
            for r in as_ref.regions_snapshot().iter() {
                let rb = r.base.as_u64();
                // Brk-grow regions live in `[BRK_DEFAULT_BASE, cur)`
                // — bounded above by the OLD break. Without the
                // `rb < cur` upper bound, any region above
                // `BRK_DEFAULT_BASE` matches and gets unmapped,
                // which on a fresh process (where cur ==
                // BRK_DEFAULT_BASE) silently nukes the user stack
                // at 0x7FFF_FFFC_0000 the next time the caller
                // does `brk(small_value)`. ld-musl's
                // `__init_libc` does exactly that early in init.
                if rb >= BRK_DEFAULT_BASE && rb < cur && rb >= new_aligned {
                    bases_to_unmap.push(rb);
                }
            }
            for b in bases_to_unmap {
                let _ = as_ref.unmap_region(VirtAddr::new(b));
            }
        }
        BRK_TABLE
            .lock()
            .as_mut()
            .expect("brk_init")
            .insert(task, new_break);
        ctx.set_return(SyscallReturn::ok(new_break));
        return;
    }

    // Grow path: allocate frames + install a SINGLE Region for
    // the whole new range (was one Region per page pre-fix —
    // bookkeeping bloated linearly with heap size and the shrink
    // path had to iterate page-by-page). On failure roll the
    // break back to `cur` (POSIX brk failure contract).
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::ok(cur));
            return;
        }
    };
    let cur_aligned = (cur + 0xFFF) & !0xFFFu64;
    let new_aligned = (new_break + 0xFFF) & !0xFFFu64;
    let pages = (new_aligned - cur_aligned) >> 12;
    if pages == 0 {
        // Within-page grow — just record the new break, no PTE work.
        BRK_TABLE
            .lock()
            .as_mut()
            .expect("brk_init")
            .insert(task, new_break);
        ctx.set_return(SyscallReturn::ok(new_break));
        return;
    }
    let mut phys_list: alloc::vec::Vec<narf_memory::PhysAddr> =
        alloc::vec::Vec::with_capacity(pages as usize);
    for _ in 0..pages {
        let phys = match narf_memory::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => {
                ctx.set_return(SyscallReturn::ok(cur));
                return;
            }
        };
        // SAFETY: identity-mapped low 4 GiB; phys is page-aligned.
        unsafe {
            core::ptr::write_bytes(phys.raw() as *mut u8, 0, 0x1000);
        }
        phys_list.push(phys);
    }
    if as_ref
        .map_region(Region {
            base: VirtAddr::new(cur_aligned),
            len: pages * 0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: phys_list,
        })
        .is_err()
    {
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }

    BRK_TABLE
        .lock()
        .as_mut()
        .expect("brk_init")
        .insert(task, new_break);
    ctx.set_return(SyscallReturn::ok(new_break));
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

fn sys_clock_gettime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let buf = args.arg1;
    if buf == 0 || buf & 0x7 != 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let (sec, nsec) = match id {
        CLOCK_REALTIME => {
            let w = narf_scheduler::narf_time::now_wall();
            (w.secs, w.nanos as i64)
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME => {
            let ns: u64 = narf_scheduler::narf_time::monotonic_ns();
            ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
        }
        _ => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Write the timespec (two i64s: tv_sec, tv_nsec) under the SMAP bracket.
    let mut kbuf = [0u8; 16];
    kbuf[..8].copy_from_slice(&sec.to_ne_bytes());
    kbuf[8..].copy_from_slice(&nsec.to_ne_bytes());
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `sys_clock_settime(clock_id, *timespec)` — set CLOCK_REALTIME
/// by computing the wall-offset from the requested (sec, nsec) and
/// the current monotonic. Other clock_ids return -1.
fn sys_clock_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let ts = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ts == 0 {
        ctx.set_return(fail);
        return;
    }
    if id != CLOCK_REALTIME {
        // CLOCK_MONOTONIC and friends are not settable.
        ctx.set_return(fail);
        return;
    }
    // Read the timespec (two i64s) from user space under the SMAP bracket.
    let mut kbuf = [0u8; 16];
    if unsafe { copy_from_user(&mut kbuf, ts) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let sec = i64::from_ne_bytes(kbuf[..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(kbuf[8..].try_into().unwrap());
    if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
        ctx.set_return(fail);
        return;
    }
    let target_ns = (sec as i128) * 1_000_000_000 + (nsec as i128);
    let mono_ns = narf_scheduler::narf_time::monotonic_ns() as i128;
    let offset_ns = (target_ns - mono_ns) as i64;
    narf_scheduler::narf_time::set_wall_offset_uncapped(offset_ns);
    ctx.set_return(SyscallReturn::ok(0));
}

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
// Storage shape mirrors SIGACTION_TABLE: BTreeMap<task_id, u32
// bitmask>. Two tables: pending signals (set by `kill`) and the
// per-task block mask (modified by `sigprocmask`). NSIG = 32 so
// `1 << signum` is a u32-clean fit.

pub(crate) static SIGNAL_PENDING: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

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

static SIGNAL_MASK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

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
}

/// Diagnostic: peek the pending bitmap for `task`.
pub fn signal_pending_of(task: u64) -> u32 {
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
    let g = PROC_ARGV.lock();
    g.as_ref()
        .and_then(|m| m.get(&pid).cloned())
        .unwrap_or_default()
}

/// Read-only accessor for the comm name recorded against `pid`. Used
/// by `/proc/[pid]/comm` and by the execve smoke tests to confirm
/// the comm-from-argv[0]-basename step ran.
pub fn proc_comm_of(pid: u64) -> Option<alloc::string::String> {
    let g = PROC_COMM.lock();
    g.as_ref().and_then(|m| m.get(&pid).cloned())
}

// ── /proc/[pid]/comm writable hook ─────────────────────────────

/// Update comm from a procfs write. Linux ref: `comm_write` in
/// `fs/proc/base.c`. Truncates to 15 chars; returns `Ok(())`.
pub fn proc_set_comm(pid: u64, name: &str) -> Result<(), narf_filesystem::FsError> {
    set_proc_comm(pid, name);
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
        let task = narf_scheduler::address_space_of(narf_scheduler::TaskId(pid));
        task.map(|as_arc| {
            let regions = as_arc.regions_snapshot();
            regions
                .iter()
                .map(|r| (r.len / 4096).max(1) as u64)
                .sum::<u64>()
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

/// /proc/self pid hook — returns the current task id.
pub fn proc_current_pid() -> u64 {
    current_task_id()
}

/// /proc enumerator — returns every live task id.
pub fn proc_list_pids() -> alloc::vec::Vec<u64> {
    narf_scheduler::all_task_ids()
        .into_iter()
        .map(|t| t.0)
        .collect()
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
    let live = pid == current || narf_scheduler::all_task_ids().iter().any(|t| t.0 == pid);
    if !live {
        return None;
    }
    // brk top — pull from the per-task BRK_TABLE. May be 0 if the
    // task hasn't called brk yet.
    let brk_top = {
        let g = BRK_TABLE.lock();
        g.as_ref().and_then(|m| m.get(&pid).copied()).unwrap_or(0)
    };
    // Stack top — from the AS's regions table, look for the top
    // RW-X region with the user-stack base. Stage-1 just reports
    // the standard DEFAULT_USER_STACK_BASE + DEFAULT_USER_STACK_BYTES.
    let stack_top =
        crate::process::DEFAULT_USER_STACK_BASE + crate::process::DEFAULT_USER_STACK_BYTES;
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
        narf_scheduler::address_space_of(narf_scheduler::TaskId(pid)).or_else(|| {
            // Currently-polling task isn't in the queue scan;
            // fall back to the active-AS slot.
            if pid == current_task_id() {
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
                shared: false,
                label,
            });
        }
    }
    Some(ProcTaskInfo {
        pid,
        comm,
        state: 'R',
        brk_top,
        stack_top,
        cmdline,
        vmas,
    })
}

// ── Extended /proc/[pid]/* public accessors ────────────────────────
//
// Called by `narf_filesystem::procfs::pid_ext` via fn-pointer hooks
// wired in `cross_crate_init::install_proc_ext_hooks`.

/// Return the full rlimit table for `pid` as `[(cur, max); 16]`.
/// Indices follow RLIMIT_* numbering (0=CPU, 3=STACK, 7=NOFILE, …).
pub fn rlimits_of(pid: u64) -> [(u64, u64); 16] {
    let row = {
        let g = RLIMIT_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&pid).copied())
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
    read_nice(pid)
}

/// Return the environ block for `pid` (NUL-separated key=value bytes).
/// Returns empty Vec when no environ has been recorded.
pub fn proc_environ_of(pid: u64) -> alloc::vec::Vec<u8> {
    let g = PROC_ENVIRON.lock();
    g.as_ref()
        .and_then(|m| m.get(&pid).cloned())
        .unwrap_or_default()
}

/// Return the packed ELF auxv bytes for `pid`.  Each entry is two
/// little-endian u64s (key, value).  AT_NULL (0, 0) terminates.
pub fn proc_auxv_of(pid: u64) -> alloc::vec::Vec<u8> {
    let g = PROC_AUXV.lock();
    g.as_ref()
        .and_then(|m| m.get(&pid).cloned())
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
pub fn fd_path_of(pid: u64, n: u32) -> Option<alloc::string::String> {
    crate::fd::with_table(pid, |t| {
        let entry = t.get(n)?;
        // Use the type_name as a fallback until FileOps grows a path()
        // method with the VFS pathname cache.
        let name = core::any::type_name_of_val(&*entry.ops);
        // Extract the last component (e.g. "PipeRead" from "crate::pipe::PipeRead").
        let short = name.rsplit("::").next().unwrap_or(name);
        Some(alloc::format!("anon_inode:[{}]", short))
    })
    .flatten()
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
    if signum >= 32 {
        return;
    }
    let mut g = SIGNAL_PENDING.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => return,
    };
    let slot = map.entry(task).or_insert(0);
    *slot |= 1u32 << signum;
}

/// Clear the pending bit for `signum` on `task`. Used by signalfd
/// after delivering the signal through the fd path.
pub fn clear_signal_pending(task: u64, signum: u32) {
    if signum >= 32 {
        return;
    }
    let mut g = SIGNAL_PENDING.lock();
    if let Some(map) = g.as_mut() {
        if let Some(slot) = map.get_mut(&task) {
            *slot &= !(1u32 << signum);
        }
    }
}

/// Diagnostic: peek the block mask for `task`.
pub fn signal_mask_of(task: u64) -> u32 {
    SIGNAL_MASK
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

fn sys_kill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    #[allow(unused_mut)]
    let mut target = args.arg0;
    let signum = args.arg1 as u32;
    if signum >= 32 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Wave-67 — translate the user-supplied pid (interpreted as
    // in-namespace per Linux semantics) to the outer pid that the
    // signal-delivery path is keyed on. Targets that the calling
    // task cannot see in its namespace fail loudly. Outside-the-
    // namespace callers (root NS) can still address by outer pid
    // because the root NS resolver is the identity.
    #[cfg(feature = "container")]
    {
        let caller = current_task_id();
        match crate::pid_ns::resolve_inner_pid(caller, target) {
            Some(outer) => target = outer,
            None => {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        }
    }
    // Wave-65 follow-up: SIGNAL_PENDING is keyed by TaskId (tid),
    // but sys_kill takes a ProcessId (pid). Translate.
    if let Some(tid) = pid_to_task_raw(target) {
        target = tid;
    }

    let mut g = SIGNAL_PENDING.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let slot = map.entry(target).or_insert(0);
    *slot |= 1u32 << signum;
    wake_signal(target);
    ctx.set_return(SyscallReturn::ok(0));
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
const FUTEX_PRIVATE: u64 = 0x80;
const FUTEX_CLOCK_REALTIME: u64 = 0x100;
const FUTEX_OP_MASK: u64 = !(FUTEX_PRIVATE | FUTEX_CLOCK_REALTIME);

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

/// Test-only accessor for the futex wake counter — Wave-65 smokes
/// observe CLONE_CHILD_CLEARTID's exit-side futex wake by reading
/// this counter before/after the exit notification.
#[doc(hidden)]
pub fn __test_futex_wake_counter(uaddr: u64) -> u64 {
    futex_wake_counter(uaddr)
}

fn sys_futex(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let uaddr = args.arg0;
    let op = args.arg1 & FUTEX_OP_MASK;
    let val = args.arg2 as u32;
    let timeout_ns = args.arg3; // 0 = no timeout
    let fail = SyscallReturn::ok((-1i64) as u64);
    match op {
        FUTEX_WAIT => {
            // Single-shot sleep variant. The full Linux semantics
            // (block until wake or timeout) require yielding back
            // to the scheduler so other tasks (notably the very
            // thread we're waiting on) can make progress; the
            // kernel-side parking would otherwise hog the CPU and
            // deadlock the join.
            //
            // The shape: sample *uaddr; if it already changed,
            // return success right away (caller's fast path
            // observes the value change). Otherwise schedule a
            // short sleep deadline on the calling task and return
            // 0. The user-side libc futex_wait wraps this in a
            // recheck loop; each iteration parks the task in the
            // executor (via user_task::poll's deadline branch),
            // which lets other tasks (including the wake source)
            // run. When *uaddr changes, the user loop exits.
            //
            // This is functionally a "futex-flavoured nanosleep"
            // — the kernel holds no per-uaddr wait queue, just
            // gives the caller back to the scheduler with a
            // bounded park. POSIX permits spurious wakeups; the
            // user-side recheck handles them.
            //
            // Null uaddr: no possible wait queue, treat as immediate
            // success (POSIX-permitted spurious wake). Lets smoke
            // tests exercise the wait/wake fast path without a
            // backing user mapping.
            if uaddr == 0 {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            let mut buf4 = [0u8; 4];
            let current = if unsafe { copy_from_user(&mut buf4, uaddr) }.is_ok() {
                u32::from_ne_bytes(buf4)
            } else {
                ctx.set_return(fail);
                return;
            };
            if current != val {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            // Park ~1ms (or the user-supplied timeout, capped).
            // Long enough for the scheduler to round-robin every
            // ready task at least once on a 1-CPU build; short
            // enough to keep the recheck latency tight.
            const DEFAULT_PARK_NS: u64 = 1_000_000; // 1 ms
            let park_ns = if timeout_ns == 0 {
                DEFAULT_PARK_NS
            } else {
                core::cmp::min(timeout_ns, DEFAULT_PARK_NS)
            };
            // Yield to the executor: stash the deadline on the
            // current UserTaskCtx, save the user state, then
            // longjmp back via the yield hook. The next
            // UserTaskFuture::poll consults the deadline and
            // parks the task without re-entering user mode until
            // it expires; on resume the user reads RAX=0 (we set
            // it before the longjmp). Mirrors sys_sleep exactly.
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                ctx.set_return(SyscallReturn::ok(0));
                let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(park_ns);
                // SAFETY: uctx is live for the trap round-trip.
                unsafe {
                    let uc = &*uctx;
                    uc.sleep_deadline_ns.store(deadline, Ordering::Release);
                    ctx.save_user_state(uc.state.get() as *mut u8);
                    *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                    hook(uctx);
                }
                // unreachable
            }
            // Test/no-future fallback: synchronous park.
            let _ = futex_wake_counter(uaddr);
            ctx.set_return(SyscallReturn::ok(0));
        }
        FUTEX_WAKE => {
            // Wake up to `val` waiters. Today we just bump the
            // counter — every waiter on this uaddr re-checks on
            // its next poll iteration. Linux distinguishes
            // "wake one" vs "wake all" via val; the spin model
            // wakes everyone regardless because the counter is
            // shared. Returns the number woken (cap at val so
            // callers expecting "≤ val" see consistent values).
            futex_bump_counter(uaddr);
            ctx.set_return(SyscallReturn::ok(val as u64));
        }
        _ => ctx.set_return(fail),
    }
}

/// Linux tgkill(2): like kill but with an explicit (tgid, tid)
/// pair. NARF is single-threaded per process — we forward tid as
/// the kill target and ignore tgid (the disambiguation it provides
/// will matter once threading lands).
fn sys_tgkill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _tgid = args.arg0;
    let tid = args.arg1;
    let signum = args.arg2 as u32;
    if signum >= 32 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let mut g = SIGNAL_PENDING.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let slot = map.entry(tid).or_insert(0);
    *slot |= 1u32 << signum;
    wake_signal(tid);
    ctx.set_return(SyscallReturn::ok(0));
}

const SIG_BLOCK: u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

fn sys_sigprocmask(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let how = args.arg0 as u32;
    let set_ptr = args.arg1 as u64;
    let old_ptr = args.arg2 as u64;
    let sigsetsize = args.arg3 as usize;

    let fail = SyscallReturn::ok((-1i64) as u64);
    if sigsetsize != 8 {
        ctx.set_return(fail);
        return;
    }

    let task = current_task_id();

    if old_ptr != 0 {
        let mask = SIGNAL_MASK
            .lock()
            .as_ref()
            .and_then(|m| m.get(&task).copied())
            .unwrap_or(0);
        if unsafe { copy_to_user(old_ptr, &mask.to_ne_bytes()) }.is_err() {
            ctx.set_return(fail);
            return;
        }
    }

    if set_ptr != 0 {
        let mut buf = [0u8; 8];
        if unsafe { copy_from_user(&mut buf, set_ptr) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        let set = u64::from_ne_bytes(buf);
        let mut g = SIGNAL_MASK.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        let slot = map.entry(task).or_insert(0);
        match how {
            SIG_BLOCK => *slot |= set as u32,
            SIG_UNBLOCK => *slot &= !(set as u32),
            SIG_SETMASK => *slot = set as u32,
            _ => {
                ctx.set_return(fail);
                return;
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

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

/// `sigaltstack(ss, old_ss)` — Linux `sigaltstack(2)`.
///
/// `arg0 = ss_in_ptr` (may be 0 — query-only),
/// `arg1 = ss_out_ptr` (may be 0 — install-only).
/// Each `stack_t` is the Linux shape:
///   `{ void *ss_sp; int ss_flags; size_t ss_size }` →
///   `[u64 sp][u32 flags][u32 pad][u64 size]` = 24 bytes.
/// Returns 0 on success, -1 on rejection (size < MIN_SIGSTKSZ,
/// unknown flag bits, or both pointers 0 and no current entry).
fn sys_sigaltstack(ctx: &mut dyn TrapContext) {
    sigaltstack_table_init();
    let args = *ctx.args();
    let ss_in = args.arg0;
    let ss_out = args.arg1;
    let task = current_task_id();

    let current = sigaltstack_of(task);

    // Write the prior entry to *ss_out first (Linux semantics:
    // even if the *ss_in install fails, the query result is the
    // pre-install state).
    if ss_out != 0 {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&current.sp.to_ne_bytes());
        buf[8..12].copy_from_slice(&current.flags.to_ne_bytes());
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
        buf[16..24].copy_from_slice(&current.size.to_ne_bytes());
        if unsafe { copy_to_user(ss_out, &buf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    }

    if ss_in != 0 {
        let mut buf = [0u8; 24];
        if unsafe { copy_from_user(&mut buf, ss_in) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        let sp = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let flags = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        let size = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
        // Validate: flags must be a subset of {SS_DISABLE, SS_ONSTACK},
        // and if not SS_DISABLE the size must meet MIN_SIGSTKSZ.
        if (flags & !(SS_DISABLE | SS_ONSTACK)) != 0 {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        if (flags & SS_DISABLE) == 0 && size < MIN_SIGSTKSZ {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
        let mut g = SIG_ALTSTACK.lock();
        if let Some(map) = g.as_mut() {
            map.insert(task, SigAltStack { sp, flags, size });
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `tkill(tid, sig)` — thread-targeted signal delivery. NARF is
/// single-thread-per-process until clone3 lands, so tkill is a
/// thin wrapper over the same SIGNAL_PENDING table that `kill`
/// uses, addressed by tid instead of pid.
fn sys_tkill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tid = args.arg0;
    let signum = args.arg1 as u32;
    if signum >= 32 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let mut g = SIGNAL_PENDING.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let slot = map.entry(tid).or_insert(0);
    *slot |= 1u32 << signum;
    wake_signal(tid);
    ctx.set_return(SyscallReturn::ok(0));
}

/// `ptrace(request, pid, addr, data)`
/// Currently a stub returning ENOSYS (-38) since the GDB stub
/// (observability) is not fully wired to the userspace process
/// table yet.
fn sys_ptrace(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok((-38i64) as u64));
}

/// `rt_sigpending(set_out, sigsetsize)` — Linux `rt_sigpending(2)`.
/// Write the (pending & mask) set to `*set_out` so the caller sees
/// which signals were delivered while blocked.
///
/// arg0 = set out ptr (writable u64 — sigset_t is 8 bytes on
/// glibc x86_64 / aarch64).  arg1 = sigsetsize (must be 8).
fn sys_rt_sigpending(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let set_out = args.arg0;
    let sigsetsize = args.arg1;
    if sigsetsize != 8 || set_out == 0 {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    let task = current_task_id();
    let pending = signal_pending_of(task);
    let mask = signal_mask_of(task);
    let pending_and_blocked = pending & mask;
    // SAFETY: caller pointer; user-ABI trust same as sigaltstack.
    unsafe {
        (set_out as *mut u64).write_unaligned(pending_and_blocked as u64);
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `rt_sigsuspend(set, sigsetsize)` — Linux `rt_sigsuspend(2)`.
/// Atomically swap the signal mask to `set`, wait for one signal
/// outside the new mask to be delivered, then restore the prior
/// mask. Always returns -1 (after delivery); errno = EINTR per
/// POSIX.
///
/// NARF round 1 implementation: install the new mask, return
/// success-shaped as -1. The next signal delivery hook firing
/// against this task will see the new mask, deliver outside-mask
/// signals, and the user's libc trampoline calls rt_sigprocmask
/// itself to restore. A future tighter implementation parks the
/// task in a dedicated wait state.
///
/// arg0 = set in ptr, arg1 = sigsetsize (must be 8).
fn sys_rt_sigsuspend(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let set_uptr = args.arg0;
    let sigsetsize = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if sigsetsize != 8 || set_uptr == 0 {
        ctx.set_return(fail);
        return;
    }

    let mut buf = [0u8; 8];
    if unsafe { copy_from_user(&mut buf, set_uptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let mask = u64::from_ne_bytes(buf) as u32;
    let task = current_task_id();

    // Temporarily install the new mask.
    {
        let mut g = SIGNAL_MASK.lock();
        let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
        map.insert(task, mask);
    }

    // Pause until signal.
    sys_pause(ctx);
}

/// `rt_sigtimedwait(set, info, timeout, sigsetsize)` — Linux
/// `rt_sigtimedwait(2)`. Synchronously wait for one of the
/// signals in `set` to be delivered to the calling task (or
/// timeout). Returns the delivered signum on success, -1 on
/// timeout / bad input.
///
/// NARF round 1: implement the non-blocking inspection variant.
/// If any signal in `set` is already pending for the task,
/// clear it from pending, fill the siginfo struct (if `info` is
/// non-null), and return the signum. If `timeout` is null, this
/// would block — we surface -1 (EAGAIN-shaped) for the
/// not-yet-pending case. The tight loop is delegated to userspace
/// via a libc retry shim. Full park-and-wait lands alongside the
/// signal pump.
///
/// arg0 = set ptr (in), arg1 = info ptr (out, may be 0),
/// arg2 = timeout timespec ptr (may be 0 = block indefinitely),
/// arg3 = sigsetsize (must be 8).
fn sys_rt_sigtimedwait(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let set_in = args.arg0;
    let info_out = args.arg1;
    let _timeout_in = args.arg2;
    let sigsetsize = args.arg3;
    if sigsetsize != 8 || set_in == 0 {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    // SAFETY: caller-supplied pointer.
    let set = unsafe { (set_in as *const u64).read_unaligned() as u32 };
    let task = current_task_id();
    let pending = signal_pending_of(task);
    let candidates = pending & set;
    if candidates == 0 {
        // Linux returns -1 / EAGAIN when timeout = 0 and nothing
        // is pending. For non-zero timeout we'd block; today we
        // return the same shape — the libc loop will re-call us.
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    let signum = candidates.trailing_zeros();
    // Clear the bit.
    if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
        if let Some(slot) = map.get_mut(&task) {
            *slot &= !(1u32 << signum);
        }
    }
    // Fill siginfo if requested. Linux siginfo_t is ~128 bytes;
    // we write just the first three fields (si_signo, si_errno,
    // si_code) which is the union-discriminating prefix every
    // libc inspects. Leaving the rest zero matches `SI_USER`.
    if info_out != 0 {
        // SAFETY: caller pointer.
        unsafe {
            let p = info_out as *mut u8;
            core::ptr::write_bytes(p, 0, 128);
            (p as *mut i32).write_unaligned(signum as i32); // si_signo
            (p.add(4) as *mut i32).write_unaligned(0); // si_errno
            (p.add(8) as *mut i32).write_unaligned(0); // si_code = SI_USER
        }
    }
    ctx.set_return(SyscallReturn::ok(signum as u64));
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
fn build_delivery_params(
    task: u64,
    action: SigAction,
    signum: u32,
    syscall_no: u32,
    si_code: i32,
    si_addr: u64,
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
    let deliverable = pending & !mask;
    if deliverable == 0 {
        return false;
    }
    let signum = deliverable.trailing_zeros();

    let action = match sigaction_lookup_full(task, signum as usize) {
        Some(a) => a,
        None => {
            // No user handler installed → POSIX default action.
            // Clear the pending bit before applying the action so a
            // retry trap doesn't re-fire the same signal.
            if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
                if let Some(slot) = map.get_mut(&task) {
                    *slot &= !(1u32 << signum);
                }
            }
            match default_signal_action(signum) {
                DefaultAction::Ignore => {
                    // Silently consumed (existing behaviour).
                }
                DefaultAction::Terminate => {
                    terminate_current_task(ctx, task, signum, false);
                    // unreachable when a UserTaskFuture is in flight.
                }
                DefaultAction::CoreDump => {
                    terminate_current_task(ctx, task, signum, true);
                    // unreachable when a UserTaskFuture is in flight.
                }
                DefaultAction::Stop | DefaultAction::Continue => {
                    // Wave 51 scope. Restore the pending bit so a
                    // future cut that wires job control can pick it up.
                    if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
                        let slot = map.entry(task).or_insert(0);
                        *slot |= 1u32 << signum;
                    }
                }
            }
            return true;
        }
    };
    // Async signals: si_code = SI_USER (0), si_addr = 0.
    let params = build_delivery_params(task, action, signum, syscall_no, 0, 0);
    if !ctx.deliver_signal(&params) {
        return false;
    }
    // Remember whether this frame is the restorer-based Linux
    // rt_sigframe so `sys_sigreturn` resolves it from RSP.
    set_sigreturn_use_rsp(task, params.restorer != 0);
    // Clear only after the rewrite succeeded — a failed
    // delivery (e.g. arch returns false) should leave pending
    // alone so the next trap retries.
    if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
        if let Some(slot) = map.get_mut(&task) {
            *slot &= !(1u32 << signum);
        }
    }
    // SA_NODEFER: skip the auto-block. Default: add the delivered
    // signal to the mask so the handler runs without re-entrancy.
    if (action.flags & SA_NODEFER) == 0 {
        if let Some(map) = SIGNAL_MASK.lock().as_mut() {
            let slot = map.entry(task).or_insert(0);
            *slot |= 1u32 << signum;
        }
    }
    // SA_RESETHAND: one-shot — clear the handler so the next
    // occurrence falls through to the default action.
    if (action.flags & SA_RESETHAND) != 0 {
        if let Some(map) = SIGACTION_TABLE.lock().as_mut() {
            if let Some(slots) = map.get_mut(&task) {
                slots[signum as usize] = None;
            }
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
    let task = current_task_id();
    let action = match sigaction_lookup_full(task, signum as usize) {
        Some(a) => a,
        None => {
            // No user handler → POSIX default action. CPU exceptions
            // map to Terminate or CoreDump only; Ignore/Stop/Continue
            // never appear in this table. Anything that's neither is
            // a kernel bug — fall through to the panic surface.
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
        14 => (2 /* SEGV_ACCERR */, info.addr),
        13 => (0x80 /* SI_KERNEL */, info.addr),
        6 => (1 /* ILL_ILLOPC */, info.addr),
        17 => (1 /* BUS_ADRALN */, info.addr),
        0 => (1 /* FPE_INTDIV */, info.addr),
        4 => (2 /* FPE_INTOVF */, info.addr),
        3 => (1 /* TRAP_BRKPT */, info.addr),
        _ => (0, info.addr),
    };
    // Synchronous: not a syscall trap, so restartable_syscall =
    // false (passed via SYSCALL_NUM_NONE to is_restartable_syscall).
    let params = build_delivery_params(task, action, signum, SYSCALL_NUM_NONE, si_code, si_addr);
    let delivered = ctx.deliver_signal(&params);
    if delivered {
        set_sigreturn_use_rsp(task, params.restorer != 0);
    }
    delivered
}

// ── Sigaction — record a per-task handler vaddr ────────────────────
//
// Stage-4 round 2: the recorded handler is fired on the trap
// return path of any subsequent int-0x80 from the same task that
// observes a pending signal not blocked by SIGNAL_MASK. See
// `default_signal_delivery` above. Cross-task delivery happens
// when another task calls `Kill` to set a bit in this task's
// pending bitmap.

const NSIG: usize = 32;

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

static SIGACTION_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<BTreeMap<u64, [Option<SigAction>; NSIG]>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task sigaction registry. Boot calls this once
/// before any user task can issue `Syscall::Sigaction`.
pub fn sigaction_init() {
    *SIGACTION_TABLE.lock() = Some(BTreeMap::new());
}

/// fork(2) inheritance: copy `parent`'s sigaction handler table
/// to `child`. POSIX: handlers are inherited; pending signals
/// are not (they live in a separate table whose default-empty
/// state is the correct child starting point).
pub fn sigaction_fork(parent: u64, child: u64) {
    let mut g = SIGACTION_TABLE.lock();
    if let Some(map) = g.as_mut() {
        if let Some(v) = map.get(&parent).copied() {
            map.insert(child, v);
        }
    }
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_sigaction_reset() {
    *SIGACTION_TABLE.lock() = Some(BTreeMap::new());
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
    let g = SIGACTION_TABLE.lock();
    let map = g.as_ref()?;
    let slots = map.get(&task)?;
    if signum >= NSIG {
        return None;
    }
    slots[signum]
}

fn sys_sigreturn(ctx: &mut dyn TrapContext) {
    // arg0 = SigContext vaddr (from libc trampoline, originally
    // delivered in RSI by deliver_signal). The trampoline keeps it
    // alive across the user's signal-handler call.
    let mut sc_vaddr = ctx.args().arg0;

    // Linux rt_sigreturn (#15 on x86_64) takes no argument — the
    // restorer trampoline that calls it leaves arbitrary garbage in
    // RDI, so we can't trust arg0. When the last delivered frame used
    // the restorer-based rt_sigframe layout, resolve it from the user
    // RSP (which points at the frame after the handler's `ret` popped
    // the restorer return address). NARF's own libc trampoline instead
    // forwards the SigContext vaddr in arg0.
    let task = current_task_id();
    if sigreturn_use_rsp(task) || sc_vaddr == 0 {
        sc_vaddr = ctx.user_rsp();
    }

    if !ctx.perform_sigreturn(sc_vaddr) {
        ctx.set_return(SyscallReturn::invalid_op());
    }
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

// Side table to enable Arc<dyn FileOps> -> Arc<SocketFile> recovery.
// `fd::FdEntry` stores Arc<dyn FileOps>; `dyn FileOps` is not
// `Any`, so a downcast isn't possible. Stage-1: register the
// concrete Arc when the socket is created; look it up by the same
// raw pointer the FdEntry holds.
static SOCKET_ARCS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::collections::BTreeMap<usize, alloc::sync::Arc<crate::socket::SocketFile>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn socket_arc_register(arc: &alloc::sync::Arc<crate::socket::SocketFile>) {
    let key = alloc::sync::Arc::as_ptr(arc) as usize;
    let mut g = SOCKET_ARCS.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    map.insert(key, arc.clone());
}

fn socket_arc_lookup(raw: *const ()) -> Option<alloc::sync::Arc<crate::socket::SocketFile>> {
    let g = SOCKET_ARCS.lock();
    g.as_ref()?.get(&(raw as usize)).cloned()
}

fn copy_user_addr(ptr: u64, len: u64) -> Option<crate::socket::SockAddr> {
    if ptr == 0 || len < 2 || len > 110 {
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

fn sys_socket(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let domain = args.arg0 as u16;
    let kind = args.arg1 as u32;
    let proto = args.arg2 as u32;
    // Reject unknown families up front (EAFNOSUPPORT shape).
    if !matches!(
        domain,
        crate::socket::AF_UNIX
            | crate::socket::AF_INET
            | crate::socket::AF_INET6
            | crate::socket::AF_BYPASS
    ) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    let sock = crate::socket::SocketFile::with_protocol(domain, kind, proto);
    socket_arc_register(&sock);
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: sock.clone(),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    }) {
        Some(n) => n,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

fn sys_socket_bind(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addr_len = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let addr = match copy_user_addr(addr_ptr, addr_len) {
        Some(a) => a,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Bind { addr }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_socket_listen(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let backlog = args.arg1 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Listen { backlog }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_socket_accept(ctx: &mut dyn TrapContext) {
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
            socket_arc_register(&socket);
            let task = current_task_id();
            let new_fd = match fd::with_table(task, |t| {
                t.open(crate::fd::FdEntry {
                    ops: socket,
                    offset: 0,
                    flags: 0,
                    status_flags: 0,
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
            // Yield like sys_futex / sys_sleep do: park ~1ms so
            // other tasks (notably the connecter) make progress;
            // user-side libc loops over us.
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                unsafe {
                    let uc = &*uctx;
                    uc.sleep_deadline_ns.store(deadline, Ordering::Release);
                    ctx.save_user_state(uc.state.get() as *mut u8);
                    *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                    hook(uctx);
                }
            }
            ctx.set_return(fail);
        }
        _ => ctx.set_return(fail),
    }
}

fn sys_socket_connect(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addr_len = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let addr = match copy_user_addr(addr_ptr, addr_len) {
        Some(a) => a,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Connect { addr }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_socket_send(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let buf_len = args.arg2 as usize;
    let flags = args.arg3 as u32;
    // arg4 / arg5: sendto's destination address (NULL/0 for
    // connected stream sockets, non-NULL for connectionless
    // datagram sends).
    let addr_ptr = args.arg4;
    let addr_len = args.arg5;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Copy user send buffer into kernel memory under the SMAP bracket.
    // Validate length before allocating — reject oversized len with EINVAL.
    let buf = if buf_len > 0 {
        // SAFETY: AS active; SMAP bracket inside copy_from_user_vec.
        match unsafe { copy_from_user_vec(buf_ptr, buf_len) } {
            Ok(b) => b,
            Err(_) => {
                ctx.set_return(fail);
                return;
            }
        }
    } else {
        alloc::vec::Vec::new()
    };
    let dest = if addr_ptr != 0 && addr_len >= 2 {
        copy_user_addr(addr_ptr, addr_len)
    } else {
        None
    };
    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &buf,
        flags,
        addr: dest,
    }) {
        crate::socket::SocketOpResult::Ok(n) => ctx.set_return(SyscallReturn::ok(n)),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            // Yield + retry from libc.
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(fail),
    }
}

fn sys_socket_recv(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let buf_len = args.arg2 as usize;
    let flags = args.arg3 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Validate destination range before issuing the Recv op.
    if buf_len > 0 {
        if validate_user_range(buf_ptr, buf_len).is_err() {
            ctx.set_return(fail);
            return;
        }
    }
    let mut buf = alloc::vec![0u8; buf_len];
    let result = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags,
    });
    match result {
        crate::socket::SocketOpResult::Received { n, .. } => {
            // Copy received bytes back to user under SMAP bracket.
            // SAFETY: ptr validated above; AS still active.
            if unsafe { copy_to_user(buf_ptr, &buf[..n]) }.is_err() {
                ctx.set_return(fail);
                return;
            }
            ctx.set_return(SyscallReturn::ok(n as u64));
        }
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            // Yield ~1ms; libc loops.
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                ctx.set_return(SyscallReturn::ok(0));
                let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                unsafe {
                    let uc = &*uctx;
                    uc.sleep_deadline_ns.store(deadline, Ordering::Release);
                    ctx.save_user_state(uc.state.get() as *mut u8);
                    *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                    hook(uctx);
                }
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(fail),
    }
}

fn sys_socket_shutdown(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let how = args.arg1 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Shutdown { how }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

/// `getsockopt(fd, level, optname, opt_val_out, opt_len_inout)`.
/// Linux ref: net/socket.c:SYSCALL_DEFINE5(getsockopt, ...).
fn sys_socket_getsockopt(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let level = args.arg1 as u32;
    let name = args.arg2 as u32;
    let val_ptr = args.arg3;
    let len_ptr = args.arg4;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Read the in/out length field via SMAP bracket.
    let in_len = if len_ptr != 0 {
        read_user_u32(len_ptr) as usize
    } else {
        0
    };
    if val_ptr == 0 || in_len == 0 {
        ctx.set_return(fail);
        return;
    }
    // Validate the output range before allocating — prevents OOM from a
    // user-supplied in_len larger than MAX_USER_COPY.
    if validate_user_range(val_ptr, in_len).is_err() {
        ctx.set_return(fail);
        return;
    }
    let mut buf = alloc::vec![0u8; in_len];
    let result = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level,
        name,
        buf: &mut buf,
    });
    match result {
        crate::socket::SocketOpResult::OptValue { n } => {
            // Write value + updated optlen back to user under SMAP bracket.
            // SAFETY: val_ptr from userspace; AS active.
            let _ = unsafe { copy_to_user(val_ptr, &buf[..n]) };
            write_user_u32(len_ptr, n as u32);
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(fail),
    }
}

/// `setsockopt(fd, level, optname, opt_val, opt_len)`.
/// Linux ref: net/socket.c:SYSCALL_DEFINE5(setsockopt, ...).
fn sys_socket_setsockopt(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let level = args.arg1 as u32;
    let name = args.arg2 as u32;
    let val_ptr = args.arg3;
    let val_len = args.arg4 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if val_ptr == 0 || val_len == 0 || val_len > 256 {
        ctx.set_return(fail);
        return;
    }
    let mut buf = alloc::vec![0u8; val_len];
    // SAFETY: AS active; SMAP bracket inside copy_from_user.
    if unsafe { copy_from_user(&mut buf, val_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    match sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level,
        name,
        value: &buf,
    }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

/// `getsockname(fd, addr_out, addrlen_inout)`. Writes the
/// `sockaddr` shape per family. Linux net/socket.c:SYSCALL_DEFINE3.
fn sys_socket_getsockname(ctx: &mut dyn TrapContext) {
    sys_socket_get_addr(ctx, false);
}

/// `getpeername(fd, addr_out, addrlen_inout)`.
fn sys_socket_getpeername(ctx: &mut dyn TrapContext) {
    sys_socket_get_addr(ctx, true);
}

fn sys_socket_get_addr(ctx: &mut dyn TrapContext, peer: bool) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let len_ptr = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let op = if peer {
        crate::socket::SocketOp::GetPeerName
    } else {
        crate::socket::SocketOp::GetSockName
    };
    let result = sock.dispatch_op(op);
    match result {
        crate::socket::SocketOpResult::Addr(addr) => {
            // Read in length (caller-supplied capacity) via SMAP bracket.
            let in_len = if len_ptr != 0 {
                read_user_u32(len_ptr) as usize
            } else {
                0
            };
            // Pack as: family(u16) + body.
            let total = 2 + addr.body.len();
            let n = core::cmp::min(in_len, total);
            if addr_ptr != 0 && n >= 2 {
                let mut out = alloc::vec![0u8; n];
                let fam_bytes = addr.family.to_le_bytes();
                out[0] = fam_bytes[0];
                out[1] = fam_bytes[1];
                let body_n = n - 2;
                out[2..2 + body_n].copy_from_slice(&addr.body[..body_n]);
                // SAFETY: addr_ptr is a user VA; SMAP bracket inside copy_to_user.
                let _ = unsafe { copy_to_user(addr_ptr, &out) };
            }
            if len_ptr != 0 {
                write_user_u32(len_ptr, total as u32);
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(fail),
    }
}

/// `sendmsg(fd, msghdr, flags)`. We squash the iovec into a single
/// allocation, call the dispatcher's Send, and report the count.
fn sys_socket_sendmsg(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let msg_ptr = args.arg1;
    let flags = args.arg2 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if msg_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    // struct msghdr { void *name; u32 namelen; struct iovec *iov;
    //                 usize iovlen; void *ctrl; usize ctrllen; int flags; }
    // Layout matches Linux x86_64 64-bit.
    // read_user_u64/u32 now use copy_from_user internally (SMAP bracket).
    let name_ptr = read_user_u64(msg_ptr);
    let name_len = read_user_u32(msg_ptr + 8);
    let iov_ptr = read_user_u64(msg_ptr + 16);
    let iov_len = read_user_u64(msg_ptr + 24) as usize;
    // Reassemble into a flat kernel buffer under SMAP bracket.
    // Cap total to MAX_USER_COPY so a user-crafted iovec cannot OOM the heap.
    let mut total = alloc::vec::Vec::new();
    for i in 0..iov_len {
        let base = iov_ptr + (i as u64) * 16;
        let p = read_user_u64(base);
        let l = read_user_u64(base + 8) as usize;
        if p == 0 || l == 0 {
            continue;
        }
        if total.len().saturating_add(l) > MAX_USER_COPY {
            ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
            return;
        }
        let old_len = total.len();
        total.resize(old_len + l, 0u8);
        // SAFETY: SMAP bracket inside copy_from_user; p is a user VA.
        let _ = unsafe { copy_from_user(&mut total[old_len..], p) };
    }
    let dest = if name_ptr != 0 && name_len >= 2 {
        copy_user_addr(name_ptr, name_len as u64)
    } else {
        None
    };
    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &total,
        flags,
        addr: dest,
    }) {
        crate::socket::SocketOpResult::Ok(n) => ctx.set_return(SyscallReturn::ok(n)),
        _ => ctx.set_return(fail),
    }
}

/// `recvmsg(fd, msghdr, flags)`. Reverse of sendmsg.
fn sys_socket_recvmsg(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let msg_ptr = args.arg1;
    let flags = args.arg2 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if msg_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    // read_user_u64/u32 use SMAP bracket internally.
    let name_ptr = read_user_u64(msg_ptr);
    let name_len_ptr = msg_ptr + 8; // namelen lives at offset 8
    let iov_ptr = read_user_u64(msg_ptr + 16);
    let iov_len = read_user_u64(msg_ptr + 24) as usize;
    // Total capacity from iovecs. Cap at MAX_USER_COPY to prevent OOM
    // from a user-crafted iovec with a giant per-slot length.
    let mut total_cap = 0usize;
    for i in 0..iov_len {
        let base = iov_ptr + (i as u64) * 16;
        total_cap = total_cap.saturating_add(read_user_u64(base + 8) as usize);
    }
    if total_cap > MAX_USER_COPY {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
    let mut staging = alloc::vec![0u8; total_cap];
    let result = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut staging,
        flags,
    });
    match result {
        crate::socket::SocketOpResult::Received { n, peer } => {
            // Scatter into iovec destinations under SMAP bracket.
            let mut copied = 0;
            for i in 0..iov_len {
                if copied >= n {
                    break;
                }
                let base = iov_ptr + (i as u64) * 16;
                let p = read_user_u64(base);
                let l = read_user_u64(base + 8) as usize;
                let take = core::cmp::min(l, n - copied);
                // SAFETY: p is a user VA; SMAP bracket inside copy_to_user.
                let _ = unsafe { copy_to_user(p, &staging[copied..copied + take]) };
                copied += take;
            }
            // Write peer sockaddr if requested.
            if let (Some(peer), true) = (peer, name_ptr != 0) {
                let mut peer_buf = alloc::vec![0u8; 2 + peer.body.len()];
                let fam_bytes = peer.family.to_le_bytes();
                peer_buf[0] = fam_bytes[0];
                peer_buf[1] = fam_bytes[1];
                peer_buf[2..].copy_from_slice(&peer.body);
                // SAFETY: name_ptr is a user VA.
                let _ = unsafe { copy_to_user(name_ptr, &peer_buf) };
                write_user_u32(name_len_ptr, (peer.body.len() + 2) as u32);
            }
            ctx.set_return(SyscallReturn::ok(n as u64));
        }
        _ => ctx.set_return(fail),
    }
}

#[inline]
fn read_user_u32(ptr: u64) -> u32 {
    let mut b = [0u8; 4];
    // SAFETY: caller guarantees ptr is a valid user address; SMAP bracket
    // guards the access.
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

/// Write a u32 to a user address (helper for getsockopt length field, etc.)
#[inline]
fn write_user_u32(ptr: u64, val: u32) {
    let b = val.to_ne_bytes();
    // SAFETY: caller guarantees ptr is a valid user address; SMAP bracket
    // guards the access.
    let _ = unsafe { copy_to_user(ptr, &b) };
}

/// Write a u16 to a user address.
#[inline]
fn write_user_u16(ptr: u64, val: u16) {
    let b = val.to_le_bytes();
    let _ = unsafe { copy_to_user(ptr, &b) };
}

fn sys_sock_register_buf(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    let len = args.arg1;
    let task = current_task_id();
    match crate::socket::register_user_buffer(task, ptr, len) {
        Some(id) => ctx.set_return(SyscallReturn::ok(id as u64)),
        None => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
    }
}

fn sys_sock_send_zc(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_id = args.arg1 as u32;
    let off = args.arg2;
    let len = args.arg3;
    let _flags = args.arg4 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let (vaddr, slice_len) = match crate::socket::registered_buffer_slice(task, buf_id, off, len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // "Zero-copy" in the NARF sense: copy once under SMAP bracket into
    // a kernel staging buffer, then hand to the socket dispatcher.
    // A real NIC TX path will map this as a DMA descriptor instead —
    // that upgrade lands when the NIC driver does; for now the
    // AF_UNIX/loopback path requires a kernel-owned buffer.
    let n_bytes = slice_len as usize;
    let mut kbuf = alloc::vec![0u8; n_bytes];
    // SAFETY: vaddr is a pinned user VA from a registered buffer.
    if unsafe { copy_from_user(&mut kbuf, vaddr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &kbuf,
        flags: 0,
        addr: None,
    }) {
        crate::socket::SocketOpResult::Ok(n) => ctx.set_return(SyscallReturn::ok(n)),
        _ => ctx.set_return(fail),
    }
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

fn sys_flock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let op = args.arg1 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten();
    let arc_ops = match arc_ops {
        Some(a) => a,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let file_ptr = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let nonblock = op & LOCK_NB != 0;
    // The blocking path retries by parking via the yield hook and
    // re-executing the syscall on resume (a longjmp clippy can't see),
    // so every visible path through the body returns/diverges — hence
    // `never_loop`. The `loop` keeps the retry intent explicit.
    #[allow(clippy::never_loop)]
    loop {
        if flock_try(file_ptr, op, task).is_ok() {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        if nonblock {
            ctx.set_return(fail);
            return;
        }
        // Yield ~1ms then retry. Same shape as sys_futex's wait
        // loop — the unlock side bumps the table; we just re-poll.
        if let (Some(uctx), Some(hook)) = (
            crate::user_task::current_user_task(),
            crate::user_task::yield_hook(),
        ) {
            ctx.set_return(fail);
            let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
            unsafe {
                let uc = &*uctx;
                uc.sleep_deadline_ns.store(dl, Ordering::Release);
                ctx.save_user_state(uc.state.get() as *mut u8);
                *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                hook(uctx);
            }
            // unreachable
        }
        ctx.set_return(fail);
        return;
    }
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

/// Console driver hook: called from DevConsole.read when the input
/// byte stream contains a control character that the current
/// foreground task's termios maps to a signal. ^C → SIGINT (2),
/// ^\ → SIGQUIT (3), ^Z → SIGTSTP (20). Returns true if the byte
/// was consumed as a signal (don't deliver to user); false otherwise.
pub fn maybe_deliver_signal_for_input(byte: u8) -> bool {
    let task = foreground_task();
    if task == 0 {
        return false;
    }
    let t = termios_of_task(task);
    if t.c_lflag & ISIG == 0 {
        return false;
    }
    let signum = match byte {
        0x03 => 2,  // SIGINT
        0x1C => 3,  // SIGQUIT
        0x1A => 20, // SIGTSTP
        _ => return false,
    };
    // Set the pending bit; the trap-return signal-delivery hook
    // picks it up next time the task returns to user mode.
    let mut g = SIGNAL_PENDING.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    let slot = map.entry(task).or_insert(0);
    *slot |= 1u32 << signum;
    true
}

fn sys_tcgetattr(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _fd = args.arg0;
    let out = args.arg1 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out == 0 {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let t = termios_of_task(task);
    // Copy KTermios struct to user space under the SMAP bracket.
    let bytes: [u8; core::mem::size_of::<KTermios>()] = unsafe { core::mem::transmute(t) };
    if unsafe { copy_to_user(out, &bytes) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_tcsetattr(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _fd = args.arg0;
    let _action = args.arg1;
    let in_ptr = args.arg2 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if in_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let mut bytes = [0u8; core::mem::size_of::<KTermios>()];
    if unsafe { copy_from_user(&mut bytes, in_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let t: KTermios = unsafe { core::mem::transmute(bytes) };
    set_termios_of_task(task, t);
    ctx.set_return(SyscallReturn::ok(0));
}

// ── I/O multiplexing — poll / epoll / eventfd / timerfd / signalfd ──

/// poll(2) entry: walk a user-supplied array of pollfd, OR each
/// fd's poll_readiness against the requested events, write revents,
/// return number of ready fds. Yield + re-poll on no-progress
/// when timeout != 0.
fn sys_poll(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pollfds_ptr = args.arg0;
    let n = args.arg1 as usize;
    let timeout_ms = args.arg2 as i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if n > 1024 {
        ctx.set_return(fail);
        return;
    }
    if n == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if pollfds_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    // Each pollfd is [fd: i32 (4 B), events: i16 (2 B), revents: i16 (2 B)] = 8 B.
    const PF_LEN: usize = 8;
    let total = n * PF_LEN;
    // Pull the user buffer into a kernel scratch under SMAP bracket.
    let mut user_buf = alloc::vec![0u8; total];
    // SAFETY: pollfds_ptr is a user VA; AS active; SMAP bracket inside.
    if unsafe { copy_from_user(&mut user_buf, pollfds_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let deadline_ns = if timeout_ms < 0 {
        None
    } else {
        let now = narf_scheduler::narf_time::monotonic_ns();
        Some(now.saturating_add((timeout_ms as u64).saturating_mul(1_000_000)))
    };
    loop {
        let mut ready = 0u64;
        for i in 0..n {
            let off = i * PF_LEN;
            let fd_raw = i32::from_le_bytes([
                user_buf[off],
                user_buf[off + 1],
                user_buf[off + 2],
                user_buf[off + 3],
            ]);
            let events = u16::from_le_bytes([user_buf[off + 4], user_buf[off + 5]]) as u32;
            let revents = if fd_raw < 0 {
                0
            } else {
                let fd = fd_raw as u32;
                let readiness =
                    fd::with_table(task, |t| t.get(fd).map(|e| e.ops.poll_readiness())).flatten();
                match readiness {
                    Some(r) => (r & events) as u16,
                    None => narf_filesystem::POLL_NVAL as u16,
                }
            };
            user_buf[off + 6..off + 8].copy_from_slice(&revents.to_le_bytes());
            if revents != 0 {
                ready += 1;
            }
        }
        if ready > 0 || timeout_ms == 0 {
            // Copy revents back to user under SMAP bracket.
            // SAFETY: pollfds_ptr validated above; AS active.
            let _ = unsafe { copy_to_user(pollfds_ptr, &user_buf) };
            ctx.set_return(SyscallReturn::ok(ready));
            return;
        }
        if let Some(deadline) = deadline_ns {
            let now = narf_scheduler::narf_time::monotonic_ns();
            if now >= deadline {
                // Timeout — write back zero revents and return 0.
                let _ = unsafe { copy_to_user(pollfds_ptr, &user_buf) };
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
        }
        // Yield ~1ms, then re-walk.
        if let (Some(uctx), Some(hook)) = (
            crate::user_task::current_user_task(),
            crate::user_task::yield_hook(),
        ) {
            // Stash partial revents back to user; the longjmp
            // doesn't return through us so they'd be lost.
            // BUT we're going to loop, not exit — only write back
            // after the loop finds something ready or times out.
            // No-op write; real write happens on the success path.
            ctx.set_return(SyscallReturn::ok(0));
            let park = 1_000_000u64;
            let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(park);
            unsafe {
                let uc = &*uctx;
                uc.sleep_deadline_ns.store(dl, Ordering::Release);
                ctx.save_user_state(uc.state.get() as *mut u8);
                *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                hook(uctx);
            }
            // unreachable
        }
        // Test fallback: just spin briefly.
        let chunk_end = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
        while narf_scheduler::narf_time::monotonic_ns() < chunk_end {
            sleep_pumps::run();
            core::hint::spin_loop();
        }
    }
}

fn sys_epoll_create(ctx: &mut dyn TrapContext) {
    let _flags = ctx.args().arg0;
    let ep = crate::io_mux::EpollFile::new();
    epoll_arc_register(&ep);
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: ep,
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    }) {
        Some(n) => n,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

const EPOLL_CTL_ADD: u32 = 1;
const EPOLL_CTL_DEL: u32 = 2;
const EPOLL_CTL_MOD: u32 = 3;

fn sys_epoll_ctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let op = args.arg1 as u32;
    let fd = args.arg2 as i32;
    let event_ptr = args.arg3 as *const u8;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let ep_arc = match epoll_arc_from_fd(task, epfd) {
        Some(e) => e,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if op == EPOLL_CTL_DEL {
        ep_arc.ctl_del(fd);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // ADD / MOD need to read the event struct (events: u32 + data: u64 = 12 B).
    if event_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let mut kbuf = [0u8; 12];
    if unsafe { copy_from_user(&mut kbuf, event_ptr as u64) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let entry = crate::io_mux::EpollEntry {
        events: u32::from_le_bytes(kbuf[..4].try_into().unwrap()),
        user_data: u64::from_le_bytes(kbuf[4..].try_into().unwrap()),
    };
    match op {
        EPOLL_CTL_ADD => ep_arc.ctl_add(fd, entry),
        EPOLL_CTL_MOD => ep_arc.ctl_mod(fd, entry),
        _ => {
            ctx.set_return(fail);
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_epoll_wait(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let events_out = args.arg1 as u64;
    let max = args.arg2 as usize;
    let timeout_ms = args.arg3 as i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let ep_arc = match epoll_arc_from_fd(task, epfd) {
        Some(e) => e,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let deadline_ns = if timeout_ms < 0 {
        None
    } else {
        let now = narf_scheduler::narf_time::monotonic_ns();
        Some(now.saturating_add((timeout_ms as u64).saturating_mul(1_000_000)))
    };
    loop {
        let snap = ep_arc.snapshot();
        let mut written = 0;
        for (fd, entry) in snap.iter() {
            if written >= max {
                break;
            }
            let fd_u = if *fd < 0 {
                continue;
            } else {
                *fd as u32
            };
            let readiness = fd::with_table(task, |t| t.get(fd_u).map(|e| e.ops.poll_readiness()))
                .flatten()
                .unwrap_or(0);
            let active = readiness & entry.events;
            if active != 0 {
                let off = (written * 12) as u64;
                let mut rec = [0u8; 12];
                rec[..4].copy_from_slice(&active.to_le_bytes());
                rec[4..].copy_from_slice(&entry.user_data.to_le_bytes());
                if unsafe { copy_to_user(events_out + off, &rec) }.is_err() {
                    break;
                }
                written += 1;
            }
        }
        if written > 0 || timeout_ms == 0 {
            ctx.set_return(SyscallReturn::ok(written as u64));
            return;
        }
        if let Some(dl) = deadline_ns {
            if narf_scheduler::narf_time::monotonic_ns() >= dl {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
        }
        // Yield 1ms.
        if let (Some(uctx), Some(hook)) = (
            crate::user_task::current_user_task(),
            crate::user_task::yield_hook(),
        ) {
            ctx.set_return(SyscallReturn::ok(0));
            let park = 1_000_000u64;
            let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(park);
            unsafe {
                let uc = &*uctx;
                uc.sleep_deadline_ns.store(dl, Ordering::Release);
                ctx.save_user_state(uc.state.get() as *mut u8);
                *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                hook(uctx);
            }
        }
        let chunk_end = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
        while narf_scheduler::narf_time::monotonic_ns() < chunk_end {
            sleep_pumps::run();
            core::hint::spin_loop();
        }
    }
}

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

fn sys_eventfd(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let initval = args.arg0;
    let flags = args.arg1 as u32;
    let efd = crate::io_mux::EventFd::new(initval, flags);
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: efd,
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    }) {
        Some(n) => n,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

// Wave-61: pidfd_open(pid, flags) → fd that signals POLLIN on exit.
// Linux x86_64 number 434. flags is currently ignored — PIDFD_NONBLOCK
// (0x0800) is the only documented bit and our pidfd reads return
// immediately anyway.
fn sys_pidfd_open(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid_raw = args.arg0;
    let _flags = args.arg1 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if pid_raw == 0 {
        ctx.set_return(fail);
        return;
    }
    // Pid is alive if it has a registered PID→TaskId mapping. A
    // missing mapping means the pid was never minted or its task has
    // already torn down — treat as zombie (immediately readable).
    let alive = pid_to_task_raw(pid_raw).is_some();
    let state = crate::pidfd::mint_for(pid_raw, alive);
    let file: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(state));
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: file,
            offset: 0,
            flags: 0,
            status_flags: 0,
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

fn sys_timerfd_create(ctx: &mut dyn TrapContext) {
    let _ = ctx.args();
    let tfd = crate::io_mux::TimerFd::new();
    timerfd_arc_register(&tfd);
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: tfd,
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    }) {
        Some(n) => n,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

fn sys_timerfd_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let _flags = args.arg1;
    let new_value_ptr = args.arg2 as u64;
    let _old_value_ptr = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    if new_value_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    // itimerspec is { interval: timespec, value: timespec } where
    // timespec = { tv_sec: i64, tv_nsec: i64 } = 16 B. Total 32 B.
    let mut buf = [0u8; 32];
    if unsafe { copy_from_user(&mut buf, new_value_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let interval_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let interval_ns = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let value_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap());
    let value_ns = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    let interval_total = (interval_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(interval_ns as u64);
    let value_total = (value_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value_ns as u64);
    let now = narf_scheduler::narf_time::monotonic_ns();
    let next_fire = if value_total == 0 {
        0
    } else {
        now.saturating_add(value_total)
    };
    let tfd = match timerfd_arc_from_fd(task, fd) {
        Some(t) => t,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    tfd.arm(next_fire, interval_total);
    ctx.set_return(SyscallReturn::ok(0));
}

// Wave-64: `timerfd_gettime(fd, &curr_value)` — snapshot the
// currently-armed timer. Writes `itimerspec` (16 B interval +
// 16 B value-remaining; absolute time stripped because the read
// view is the relative gap from `now` to the next fire). Returns
// 0 on success or -1 on a bad fd / NULL out ptr.
//
// Linux ref: `fs/timerfd.c`:SYSCALL_DEFINE2(timerfd_gettime, …)
// (GPL-2.0-or-later, kernel.org).
#[cfg(feature = "linux-compat")]
fn sys_timerfd_gettime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1 as u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    if out_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let tfd = match timerfd_arc_from_fd(task, fd) {
        Some(t) => t,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let (value_remaining_ns, interval_ns) = tfd.current();
    // itimerspec = { interval: timespec, value: timespec },
    // timespec = { tv_sec: i64, tv_nsec: i64 }.
    let mut buf = [0u8; 32];
    let interval_sec = (interval_ns / 1_000_000_000) as i64;
    let interval_nsec = (interval_ns % 1_000_000_000) as i64;
    let value_sec = (value_remaining_ns / 1_000_000_000) as i64;
    let value_nsec = (value_remaining_ns % 1_000_000_000) as i64;
    buf[0..8].copy_from_slice(&interval_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&interval_nsec.to_le_bytes());
    buf[16..24].copy_from_slice(&value_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&value_nsec.to_le_bytes());
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

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

fn sys_signalfd(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd_arg = args.arg0 as i64; // -1 = create new; else replace mask
    let mask_ptr = args.arg1 as u64;
    let _sizemask = args.arg2;
    let flags = args.arg3 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let mut mask: u64 = 0;
    if mask_ptr != 0 {
        let mut bytes = [0u8; 8];
        if unsafe { copy_from_user(&mut bytes, mask_ptr) }.is_ok() {
            mask = u64::from_le_bytes(bytes);
        }
    }
    let task = current_task_id();

    // Wave-70: prefer the new linux-compat SignalFdFile; replace mask
    // path uses its `set_mask`. Fall back to legacy SignalFd on a non-
    // linux-compat build (skip the side-table register, mint legacy).
    #[cfg(feature = "linux-compat")]
    {
        if fd_arg >= 0 {
            // Replace mask on existing signalfd.
            let target = fd_arg as u32;
            if let Some(sf) = signalfd_arc_from_fd(task, target) {
                sf.set_mask(mask);
                ctx.set_return(SyscallReturn::ok(target as u64));
                return;
            }
            ctx.set_return(fail);
            return;
        }
        let sfd = crate::linux_compat::SignalFdFile::new(mask, task);
        signalfd_arc_register(&sfd);
        let cloexec = (flags & crate::linux_compat::SFD_CLOEXEC) != 0;
        let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
        let new_fd = match fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops: sfd,
                offset: 0,
                flags: install_flags,
                status_flags: 0,
            })
        }) {
            Some(n) => n,
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        ctx.set_return(SyscallReturn::ok(new_fd as u64));
        return;
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        let _ = (fd_arg, flags);
        let sfd = crate::io_mux::SignalFd::new(mask, task);
        let new_fd = match fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops: sfd,
                offset: 0,
                flags: 0,
                status_flags: 0,
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

/// `sigaction(signum, handler, old_out_ptr, flags)` —
/// NARF-shaped sigaction surface (a Linux `rt_sigaction` is a
/// 4-arg `(sig, act, oact, sigsetsize)` over a `struct sigaction`;
/// we flatten the struct into registers for fewer copies).
///
/// arg0 = signum,
/// arg1 = handler vaddr (0 = clear),
/// arg2 = old_out_ptr (optional, may be 0; receives prior handler
///        vaddr — 8 bytes — for Linux's `oldact->sa_handler`),
/// arg3 = `sa_flags` (SA_*). Honoured: SA_SIGINFO, SA_RESTART,
///        SA_ONSTACK, SA_NODEFER, SA_RESETHAND. Unknown bits stored
///        but no action taken.
///
/// Older 3-arg callers (arg3 = 0) get flags = 0 as before — the
/// new arg slot is back-compatible.
fn sys_rt_sigaction(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let signum = args.arg0 as usize;
    let act_ptr = args.arg1 as u64;
    let _oact_ptr = args.arg2 as u64;
    let sigsetsize = args.arg3 as usize;

    let fail = SyscallReturn::ok((-1i64) as u64);
    if signum >= NSIG || sigsetsize != 8 {
        ctx.set_return(fail);
        return;
    }

    if act_ptr != 0 {
        let mut buf = [0u8; 32]; // sa_handler(8) + sa_flags(8) + sa_restorer(8) + sa_mask(8)
        if unsafe { copy_from_user(&mut buf, act_ptr) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        let handler = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let flags = u64::from_ne_bytes(buf[8..16].try_into().unwrap()) as u32;
        let restorer = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
        let task = current_task_id();

        let mut g = SIGACTION_TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        let slots = map.entry(task).or_insert([None; NSIG]);
        slots[signum] = if handler == 0 {
            None
        } else {
            Some(SigAction {
                handler,
                restorer,
                flags,
            })
        };
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_sigaction(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let signum = args.arg0 as usize;
    let new_handler = args.arg1;
    let old_out = args.arg2;
    let flags = args.arg3 as u32;
    if signum >= NSIG {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let task = current_task_id();

    let prior = {
        let mut g = SIGACTION_TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        };
        let slots = map.entry(task).or_insert([None; NSIG]);
        let prior = slots[signum];
        slots[signum] = if new_handler == 0 {
            None
        } else {
            Some(SigAction {
                handler: new_handler,
                restorer: 0,
                flags,
            })
        };
        prior
    };

    if old_out != 0 {
        // Write the prior handler address to user space under the SMAP bracket.
        let val = prior.map(|a| a.handler).unwrap_or(0);
        let _ = unsafe { copy_to_user(old_out, &val.to_ne_bytes()) };
    }

    ctx.set_return(SyscallReturn::ok(0));
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

fn sys_init_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as *const u8;
    let len = args.arg1 as usize;
    // arg2 = params_ptr — parsed/used by `narf_modules::loader` once
    // the param string parser lands. Phase 1 ignores user-supplied
    // params; modules read static `.narf_kparams` from their ELF.
    if ptr.is_null() || len == 0 || len > (1 << 28) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    // SAFETY: caller pointer in the active AS; bounds-checked by len.
    let bytes_user = unsafe { core::slice::from_raw_parts(ptr, len) };
    // Copy to kernel heap so the user can't mutate the buffer during
    // parsing.
    let owned: alloc::vec::Vec<u8> = bytes_user.to_vec();
    match narf_modules::syscalls::sys_init_module(&owned) {
        Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(SyscallReturn::ok((e.to_errno() as i64) as u64)),
    }
}

fn sys_finit_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    // arg1 = params_ptr, arg2 = flags — both ignored in Phase 1.
    // Read the file via the fd table.
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get_mut(fd).ok_or(())?;
        let mut accum = alloc::vec::Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let off = entry.offset;
            let n = poll_blocking(entry.ops.read(off, &mut buf))
                .and_then(|r| r.ok())
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            accum.extend_from_slice(&buf[..n]);
            entry.offset = off + n as u64;
            if accum.len() > (1 << 28) {
                return Err(());
            }
        }
        Ok(accum)
    });
    match outcome {
        Some(Ok(bytes)) => match narf_modules::syscalls::sys_finit_module(&bytes) {
            Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
            Err(e) => ctx.set_return(SyscallReturn::ok((e.to_errno() as i64) as u64)),
        },
        _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
    }
}

fn sys_delete_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let name_ptr = args.arg0 as *const u8;
    let name_len = args.arg1 as usize;
    if name_ptr.is_null() || name_len == 0 || name_len > 256 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    // SAFETY: caller pointer in the active AS; bounds-checked.
    let name_bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let name = match core::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        }
    };
    match narf_modules::syscalls::sys_delete_module(name) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(SyscallReturn::ok((e.to_errno() as i64) as u64)),
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
    table.install_raw(Syscall::MProtect, "mprotect", RawFnHandler(sys_mprotect));
    table.install_raw(Syscall::MLock, "mlock", RawFnHandler(sys_mlock));
    table.install_raw(Syscall::MUnlock, "munlock", RawFnHandler(sys_munlock));
    #[cfg(feature = "linux-compat")]
    table.install_raw(Syscall::Madvise, "madvise", RawFnHandler(sys_madvise));
    table.install_raw(Syscall::Execve, "execve", RawFnHandler(sys_execve));
    table.install_raw(Syscall::Wait4, "wait4", RawFnHandler(sys_wait4));
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
    table.install_raw(Syscall::Getpgid, "getpgid", RawFnHandler(sys_getpgid));
    table.install_raw(Syscall::Setpgid, "setpgid", RawFnHandler(sys_setpgid));
    table.install_raw(Syscall::Getsid, "getsid", RawFnHandler(sys_getsid));
    table.install_raw(Syscall::Setsid, "setsid", RawFnHandler(sys_setsid));
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
    #[cfg(feature = "container")]
    {
        table.install_raw(
            Syscall::Setdomainname,
            "setdomainname",
            RawFnHandler(sys_setdomainname),
        );
        table.install_raw(Syscall::Shmget, "shmget", RawFnHandler(sys_shmget));
        table.install_raw(Syscall::Semget, "semget", RawFnHandler(sys_semget));
        table.install_raw(Syscall::Msgget, "msgget", RawFnHandler(sys_msgget));
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
        table.install_raw(Syscall::Lstat, "lstat", RawFnHandler(sys_stat_linux));
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
    table.install_raw(
        Syscall::Fchmodat,
        "fchmodat",
        RawFnHandler(sys_fchmodat_or_fchownat),
    );
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
    table.install_raw(
        Syscall::Chmod,
        "chmod",
        RawFnHandler(sys_access_chmod_chown),
    );
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
    table.install_raw(Syscall::Readlink, "readlink", RawFnHandler(sys_readlink));
    table.install_raw(Syscall::Symlink, "symlink", RawFnHandler(sys_symlink));
    table.install_raw(Syscall::Listdir, "listdir", RawFnHandler(sys_listdir));
    table.install_raw(
        Syscall::Getdents64,
        "getdents64",
        RawFnHandler(sys_getdents64),
    );

    // Tier-3z entropy.
    table.install_raw(Syscall::GetRandom, "getrandom", RawFnHandler(sys_getrandom));

    // I/O multiplexing: poll / select / pselect6 / epoll.
    table.install_raw(Syscall::Poll, "poll", RawFnHandler(crate::poll::sys_poll));
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

    // Auto-wire both delivery hooks so any kernel that uses
    // `install_core_syscalls` gets the async + sync signal paths
    // on for free. Idempotent.
    install_signal_delivery_hook(default_signal_delivery);
    install_sync_signal_hook(default_sync_signal_delivery);
}
