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

use crate::{fd, RawFnHandler, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext};

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

fn current_task_id() -> u64 {
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
}

/// Reset the registry — test hook; drops every per-task ring set.
#[doc(hidden)]
pub fn __test_bootstrap_reset() {
    *BOOTSTRAP_TABLE.lock() = None;
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
    let path_ptr = args.arg0 as *const u8;
    let path_len = args.arg1 as usize;
    let mnt_ptr = args.arg2 as *const u8;
    let mnt_len = args.arg3 as usize;
    let flags = args.arg4;
    // user-runtime's `open` wrapper checks `r == !0u64` for failure
    // (the asm wrapper observes only the value register, not the
    // status word), so the kernel must mirror that sentinel rather
    // than the generic `invalid_op` shape.
    let fail = SyscallReturn::ok(!0u64);
    if path_ptr.is_null() || path_len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user pointers in active AS, length-bounded.
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };

    // Two shapes:
    // - Absolute: arg2/arg3 = (0, 0). The path itself is `/foo/bar`;
    //   the registry finds the longest-matching mount.
    // - Explicit-mount: arg2/arg3 = (ptr, len). The path is relative.
    //   Useful when the caller already knows the mount.
    let ops = if mnt_len == 0 {
        narf_filesystem::registry()
            .resolve_absolute(path, |fs, rel| {
                poll_blocking(narf_filesystem::resolve_async(fs.root(), rel))
                    .and_then(|r| r.ok())
            })
            .flatten()
    } else {
        let mnt_bytes = unsafe { core::slice::from_raw_parts(mnt_ptr, mnt_len) };
        let mount = match core::str::from_utf8(mnt_bytes) {
            Ok(s) => s,
            Err(_) => {
                ctx.set_return(fail);
                return;
            }
        };
        narf_filesystem::registry()
            .with_mount(mount, |fs| {
                poll_blocking(narf_filesystem::resolve_async(fs.root(), path))
                    .and_then(|r| r.ok())
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
            match narf_filesystem::registry()
                .resolve_parent_absolute(path, |_fs, parent, leaf| poll_blocking(parent.create(leaf)))
            {
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

    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
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

// ── Write — arg0=fd, arg1=buf, arg2=len ────────────────────────────
//
// fd 1 / fd 2: console (stdout/stderr) — direct path so user code
// without an explicit Open of stdio still works.
// Other fds: routed through the per-task fd table.

fn sys_write(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1 as *const u8;
    let len = args.arg2 as usize;
    if ptr.is_null() || len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // SAFETY: `ptr` is a user-mode virt address; the current AS is
    // still active (trap didn't swap CR3) so the walk resolves.
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };

    // Stdio (fd 0/1/2) is auto-installed in fresh fd tables by
    // `fd::with_table`, so all fds — including stdio — route
    // through the same per-task table path.
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = match t.get_mut(fd) {
            Some(e) => e,
            None => return Err(()),
        };
        let off = entry.offset;
        let written = poll_blocking(entry.ops.write(off, slice))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        entry.offset = off.saturating_add(written as u64);
        Ok(written)
    });
    match outcome {
        Some(Ok(n)) => ctx.set_return(SyscallReturn::ok(n as u64)),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

// ── Read — arg0=fd, arg1=buf, arg2=len ─────────────────────────────

fn sys_read(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1 as *mut u8;
    let len = args.arg2 as usize;
    if ptr.is_null() || len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Track the foreground task: any read syscall counts as "this
    // task is currently consuming console input." When the input
    // ring later observes ^C, this is the task SIGINT goes to.
    note_console_reader(current_task_id());
    // SAFETY: same contract as `sys_write` — user pointer in the
    // active AS, length-bounded.
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = match t.get_mut(fd) {
            Some(e) => e,
            None => return Err(()),
        };
        let off = entry.offset;
        let read = poll_blocking(entry.ops.read(off, slice))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        entry.offset = off.saturating_add(read as u64);
        Ok(read)
    });
    match outcome {
        Some(Ok(n)) => ctx.set_return(SyscallReturn::ok(n as u64)),
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
        };
        t.set(newfd, clone);
        Some(())
    });
    match outcome {
        Some(Some(())) => ctx.set_return(SyscallReturn::ok(newfd as u64)),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;

fn sys_fcntl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let cmd = args.arg1;
    let arg = args.arg2;
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get_mut(fd)?;
        Some(match cmd {
            F_GETFD => SyscallReturn::ok(entry.flags as u64),
            F_SETFD => {
                entry.flags = arg as u32;
                SyscallReturn::ok(0)
            }
            // F_GETFL / F_SETFL: NARF doesn't model O_RDONLY / O_WRONLY
            // / O_NONBLOCK at the fd-table layer yet (every fd is
            // implicitly read+write — the FileOps impl is what
            // refuses unsupported sides). Return 0 so callers that
            // probe the flag set don't see a spurious error.
            F_GETFL => SyscallReturn::ok(0),
            F_SETFL => SyscallReturn::ok(0),
            _ => SyscallReturn::invalid_op(),
        })
    });
    match outcome {
        Some(Some(r)) => ctx.set_return(r),
        _ => ctx.set_return(SyscallReturn::invalid_op()),
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
    let path_ptr = args.arg0 as *const u8;
    let path_len = args.arg1 as usize;
    let out_ptr = args.arg2 as *mut StatBuf;
    // POSIX-shaped failure sentinel. The user-runtime asm wrapper
    // observes only the `value` register, so we mirror libc and
    // return -1 on failure to disambiguate from a 0-valued success.
    // Without this the success ok(0) and the invalid_op rax=0 are
    // indistinguishable at the user side.
    let fail = SyscallReturn::ok((-1i64) as u64);
    if path_ptr.is_null() || path_len == 0 || out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user-mode pointer in the active AS, length-bounded.
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
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
    // SAFETY: caller supplied a writable user vaddr; if the address
    // is bad the user faults into its own handler, not ours.
    unsafe {
        core::ptr::write_volatile(out_ptr, stat);
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
    // SAFETY: same contract as `sys_stat`.
    unsafe {
        core::ptr::write_volatile(out_ptr, stat);
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
    let ptr = args.arg1 as *mut u8;
    let len = args.arg2 as usize;
    let offset = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // SAFETY: caller-supplied user pointer in the active AS.
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        let ops = entry.ops.clone();
        let n = poll_blocking(ops.read(offset, slice))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        Some(n)
    });
    match outcome {
        Some(Some(n)) => ctx.set_return(SyscallReturn::ok(n as u64)),
        _ => ctx.set_return(fail),
    }
}

fn sys_pwrite64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1 as *const u8;
    let len = args.arg2 as usize;
    let offset = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // SAFETY: caller-supplied user pointer in the active AS.
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        let ops = entry.ops.clone();
        let n = poll_blocking(ops.write(offset, slice))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        Some(n)
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
            if poll_blocking(ops.truncate(target_end)).and_then(|r| r.ok()).is_none() {
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
    let ptr = args.arg0 as *const u8;
    let len = args.arg1 as usize;
    let new_size = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied user pointer in active AS.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let path = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let ops = narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
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
    let _dirfd = args.arg0;
    let path_ptr = args.arg1;
    let path_len = args.arg2;
    let flags = args.arg3;
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.inner.set_return(r);
        }
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: path_ptr,
        arg1: path_len,
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
    let _dirfd = args.arg0;
    let path_ptr = args.arg1;
    let path_len = args.arg2;
    let mode = args.arg3;
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.inner.set_return(r);
        }
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: path_ptr,
        arg1: path_len,
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
    let old_ptr = args.arg1;
    let old_len = args.arg2;
    let _new_dirfd = args.arg3;
    let new_ptr = args.arg4;
    let new_len = args.arg5;
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.inner.set_return(r);
        }
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: old_ptr,
        arg1: old_len,
        arg2: new_ptr,
        arg3: new_len,
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
        fn set_return(&mut self, r: SyscallReturn) {
            self.inner.set_return(r);
        }
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
    let _dirfd = args.arg0;
    let path_ptr = args.arg1;
    let path_len = args.arg2;
    let buf_ptr = args.arg3;
    let buf_len = args.arg4;
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.inner.set_return(r);
        }
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: path_ptr,
        arg1: path_len,
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
    let path_ptr = args.arg0;
    let path_len = args.arg1;
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.inner.set_return(r);
        }
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: 0, // dirfd = AT_FDCWD (ignored anyway).
        arg1: path_ptr,
        arg2: path_len,
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
    let _dirfd = args.arg0;
    let path_ptr = args.arg1;
    let path_len = args.arg2;
    let stat_out = args.arg3;
    let _flags = args.arg4;
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.inner.set_return(r);
        }
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: path_ptr,
        arg1: path_len,
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
    let _dirfd = args.arg0;
    let path_ptr = args.arg1;
    let path_len = args.arg2;
    let flags = args.arg3;
    let _mode = args.arg4;
    // Reshape into a SYS_OPEN-compatible context: arg0 = path_ptr,
    // arg1 = path_len, arg2 = 0 (mount_ptr), arg3 = 0 (mount_len),
    // arg4 = flags. We can't construct a fresh TrapContext here —
    // we wrap in an inline struct that proxies the args.
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.inner.set_return(r);
        }
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: path_ptr,
        arg1: path_len,
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
    let ptr = args.arg1 as *const u8;
    let len = args.arg2 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied user pointer in active AS.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let path = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
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
        .resolve_absolute(path, |fs, rel| {
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
    let _flags = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);

    let ops = narf_filesystem::new_anon_memfile();
    let task = current_task_id();
    let fd = fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
        })
    });
    // `with_table` returns `Option<u32>` (the fd or None on
    // exhaustion); the outer Option signals "no fd table for the
    // task". Both must be Some(Some(n)) for success.
    match fd {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        None => ctx.set_return(fail),
    }
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
    let out_ptr = ctx.args().arg0 as *mut i32;
    if out_ptr.is_null() {
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
        });
        let w = t.open(crate::fd::FdEntry {
            ops: wr as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: 0,
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
    // SAFETY: caller-supplied user vaddr; we write two i32s. The
    // kernel runs in the calling task's AS so the write resolves.
    unsafe {
        core::ptr::write_volatile(out_ptr, r as i32);
        core::ptr::write_volatile(out_ptr.add(1), w as i32);
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
    let out_ptr = args.arg0 as *mut i32;
    let flags = args.arg1;
    if out_ptr.is_null() {
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
        });
        let w = t.open(crate::fd::FdEntry {
            ops: wr as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: install_flags,
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
    // SAFETY: caller-supplied user vaddr; we write two i32s.
    unsafe {
        core::ptr::write_volatile(out_ptr, r as i32);
        core::ptr::write_volatile(out_ptr.add(1), w as i32);
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
    let ptr = args.arg0 as *const u8;
    let len = args.arg1 as usize;
    // POSIX-shaped failure sentinel. The kernel's syscall ABI carries
    // a separate `status` field but the user-runtime asm wrapper only
    // observes the `value` register; we mirror libc and return -1 on
    // failure so the caller can distinguish from a success return of 0.
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user pointer in active AS, length-bounded.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let path = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(path, |_fs, parent, leaf| poll_blocking(parent.unlink(leaf)));
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
    let ptr = args.arg0 as *const u8;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user pointer in active AS, length-bounded.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let path = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(path, |_fs, parent, leaf| poll_blocking(parent.mkdir(leaf)));
    match outcome {
        Some(Some(Ok(_))) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_rmdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as *const u8;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user pointer in active AS, length-bounded.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let path = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(path, |_fs, parent, leaf| poll_blocking(parent.rmdir(leaf)));
    match outcome {
        Some(Some(Ok(()))) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_rename(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let old_ptr = args.arg0 as *const u8;
    let old_len = args.arg1 as usize;
    let new_ptr = args.arg2 as *const u8;
    let new_len = args.arg3 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if old_ptr.is_null() || new_ptr.is_null() || old_len == 0 || new_len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user pointers in active AS, length-bounded.
    let old_bytes = unsafe { core::slice::from_raw_parts(old_ptr, old_len) };
    let new_bytes = unsafe { core::slice::from_raw_parts(new_ptr, new_len) };
    let old_path = match core::str::from_utf8(old_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let new_path = match core::str::from_utf8(new_bytes) {
        Ok(s) => s,
        Err(_) => {
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
        .resolve_parent_absolute(old_path, |_fs, parent, old_leaf| {
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
    let path_ptr = args.arg0 as *const u8;
    let path_len = args.arg1 as usize;
    let buf_ptr = args.arg2 as *mut u8;
    let buf_len = args.arg3 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if path_ptr.is_null() || path_len == 0 || buf_ptr.is_null() || buf_len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied user pointer in the active AS, length-
    // bounded.
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    // resolve_parent_absolute returns Option<Option<Arc<dyn FileOps>>>:
    // outer None = no mount covers the path, inner None = parent walk
    // hit a missing component or the leaf is absent. Flatten both
    // failure modes to `fail`.
    let file = narf_filesystem::registry()
        .resolve_parent_absolute(path, |_fs, parent, leaf| parent.lookup(leaf))
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
    // Copy out volatile so the user's view is not subject to compiler
    // reordering across the syscall return.
    // SAFETY: caller-supplied writable region of `buf_len` bytes;
    // `n <= len <= buf_len` by construction.
    unsafe {
        for i in 0..n {
            core::ptr::write_volatile(buf_ptr.add(i), staging[i]);
        }
    }
    ctx.set_return(SyscallReturn::ok(n as u64));
}

fn sys_symlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let target_ptr = args.arg0 as *const u8;
    let target_len = args.arg1 as usize;
    let link_ptr = args.arg2 as *const u8;
    let link_len = args.arg3 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if target_ptr.is_null() || target_len == 0 || link_ptr.is_null() || link_len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied user pointers in the active AS, length-
    // bounded.
    let target_bytes = unsafe { core::slice::from_raw_parts(target_ptr, target_len) };
    let link_bytes = unsafe { core::slice::from_raw_parts(link_ptr, link_len) };
    let target_str = match core::str::from_utf8(target_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let link_path = match core::str::from_utf8(link_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(link_path, |_fs, parent, leaf| {
            poll_blocking(parent.symlink(leaf, target_str))
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
    let path_ptr = args.arg0 as *const u8;
    let path_len = args.arg1 as usize;
    let cursor = args.arg2 as usize;
    let out_ptr = args.arg3 as *mut u8;
    let out_len = args.arg4 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if path_ptr.is_null() || path_len == 0 || out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    if out_len < 8 {
        // Need room for at least the header.
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied user pointer in the active AS.
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };

    // Resolve to a DirOps. Empty path or root → use the FS root
    // directly; otherwise descend through `lookup_dir`.
    let entries = narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            let dir: alloc::sync::Arc<dyn narf_filesystem::DirOps> = if rel.is_empty() {
                fs.root()
            } else {
                // Walk segment by segment so we follow `lookup_dir`.
                let mut cur = fs.root();
                for seg in rel.split('/').filter(|s| !s.is_empty()) {
                    cur = cur.lookup_dir(seg)?;
                }
                cur
            };
            // Bound the snapshot at usize::MAX entries — practically
            // walks every entry, but `enumerate` already takes a `max`
            // so the contract is in our hands.
            Some(dir.enumerate(cursor, 1))
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
    // SAFETY: out_ptr is a user-supplied writable region of `out_len`
    // bytes; `total <= out_len` per the bounds check above. Use
    // write_unaligned because user buffers may not be u32-aligned.
    unsafe {
        core::ptr::write_unaligned(out_ptr as *mut u32, name_bytes.len() as u32);
        core::ptr::write_unaligned(out_ptr.add(4) as *mut u32, ftype_wire);
        core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), out_ptr.add(8), name_bytes.len());
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
    let path_ptr = args.arg0 as *const u8;
    let path_len = args.arg1 as usize;
    let mut cursor = args.arg2 as usize;
    let out_ptr = args.arg3 as *mut u8;
    let out_len = args.arg4 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if path_ptr.is_null() || path_len == 0 || out_ptr.is_null() || out_len < 32 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied user pointer, length-bounded.
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };

    // Resolve to a DirOps once. We iterate by re-issuing
    // enumerate(cursor, 1) per entry — simpler than threading a
    // batch enumerator through the closure-typed registry walker,
    // and the per-call cost is bounded by the small fan-out of a
    // typical directory in our test FSes.
    let dir = narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            let dir: alloc::sync::Arc<dyn narf_filesystem::DirOps> = if rel.is_empty() {
                fs.root()
            } else {
                let mut cur = fs.root();
                for seg in rel.split('/').filter(|s| !s.is_empty()) {
                    cur = cur.lookup_dir(seg)?;
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
        let mut entries = dir.enumerate(cursor, 1);
        if entries.is_empty() {
            break;
        }
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
        // SAFETY: caller-supplied writable region; we bound the
        // writes by `reclen <= remaining capacity`.
        unsafe {
            let base = out_ptr.add(written);
            core::ptr::write_unaligned(base as *mut u64, next_cursor as u64); // d_ino
            core::ptr::write_unaligned(base.add(8) as *mut u64, next_cursor as u64); // d_off
            core::ptr::write_unaligned(base.add(16) as *mut u16, reclen as u16); // d_reclen
            core::ptr::write_volatile(base.add(18), dt); // d_type
                                                         // d_name follows at offset 19.
            for (i, &b) in name_bytes.iter().enumerate() {
                core::ptr::write_volatile(base.add(19 + i), b);
            }
            // NUL terminator + zero-padding through the rec end.
            for i in (19 + name_bytes.len())..reclen {
                core::ptr::write_volatile(base.add(i), 0);
            }
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
    // Write 6 u32s into the user pointer. The address space's
    // page tables already gate writability — a bad pointer faults
    // back into the trap path and the caller's process gets the
    // page fault, which is the right blast radius.
    if user_p == 0 || (user_p & 0x3) != 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // SAFETY: caller-supplied user VA; alignment checked above.
    // A fault here is the caller's responsibility.
    unsafe {
        for (i, w) in out.iter().enumerate() {
            core::ptr::write_volatile((user_p as *mut u32).add(i), *w);
        }
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
    let name_ptr = args.arg0 as *const u8;
    let name_len = args.arg1 as usize;
    let bytes_ptr = args.arg2 as *const u8;
    let bytes_len = args.arg3 as usize;
    if name_ptr.is_null() || bytes_ptr.is_null() || name_len == 0 || bytes_len == 0 {
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
    // SAFETY: `name_ptr` + `name_len` are user-mode virt addresses
    // in the calling task's AS; the trap didn't swap CR3 so the
    // walk resolves. We immediately copy the name into a kernel-
    // owned `String` so the canonical-name lifetime in the
    // registry isn't pinned to user memory.
    let name_bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let name_str = match core::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Leak the name into 'static memory. The registry stores it
    // by reference; on hot-replace the prior 'static name string
    // is dropped from the registry but stays leaked. Acceptable
    // because firmware-install events are rare (vendor updates,
    // not per-frame).
    let leaked: &'static str =
        alloc::boxed::Box::leak(alloc::string::String::from(name_str).into_boxed_str());

    // SAFETY: `bytes_ptr` + `bytes_len` are user-mode addresses in
    // the calling task's AS; the trap didn't swap CR3. The kernel
    // path inside `firmware::sys_install` copies bytes into a
    // DMA-coherent page before returning, so the user pointer's
    // lifetime is bounded by this call.
    let r = unsafe { narf_firmware::sys_install(leaked, bytes_ptr, bytes_len, &auth) };
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
    let mut perms = RegionPerms::READ;
    if prot & 0b010 != 0 {
        perms = perms | RegionPerms::WRITE;
    }
    if prot & 0b100 != 0 {
        perms = perms | RegionPerms::EXEC;
    }
    match as_ref.change_perms_range(base, len, perms) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

// ── ExitTask — redirect to a kernel-registered landing ─────────────

fn sys_exit_task(ctx: &mut dyn TrapContext) {
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

// ── Yield — cooperative scheduler hand-back ────────────────────────

fn sys_yield(ctx: &mut dyn TrapContext) {
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
    ctx.set_return(SyscallReturn::ok(current_task_id()));
}

fn sys_getppid(ctx: &mut dyn TrapContext) {
    // Stage-4 stub: scheduler doesn't track parentage yet.
    ctx.set_return(SyscallReturn::ok(0));
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

// ── clone(2): minimal-viable thread spawn ──────────────────────────
//
// See the Syscall::Clone doc-comment for the four-argument shape.
// The handler resolves the caller's address space through the
// installed AS lookup (the same one `current_address_space` uses
// for fd handlers), clones the `Arc<AddressSpace>`, and spawns a
// new `UserTaskFuture` that begins execution at the user-supplied
// (entry_pc, stack_top) pair. The child's TaskId is returned to
// the parent; the child observes a fresh TaskId via `gettid`.

fn sys_clone(ctx: &mut dyn TrapContext) {
    use crate::process::DEFAULT_USER_STACK_BYTES;

    let args = *ctx.args();
    let entry_pc = args.arg0;
    let stack_top = args.arg1;
    let entry_arg = args.arg2; // delivered as RDI to the new thread
    let fs_base_arg = args.arg3;

    // Reject obviously-bad inputs early. Zero entry/stack means
    // the user didn't bother to fill in their args; reject.
    if entry_pc == 0 || stack_top == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    // Resolve the parent's address space. If no AS lookup has been
    // installed, this is being called outside a real userspace boot
    // (e.g. a unit test that forgot the wiring) — fail loudly.
    let parent_as = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    // Build a UserProcess that shares `address_space` with the
    // parent. Each thread still gets its own PID for now (the
    // scheduler tracks tasks individually; thread-group / `getpid`-
    // returns-tgid semantics will land alongside futex / clone3).
    let proc = crate::UserProcess {
        pid: crate::alloc_pid(),
        address_space: parent_as.clone(),
        entry: crate::EntryPoint(narf_memory::VirtAddr::new(entry_pc)),
        stack_top: narf_memory::VirtAddr::new(stack_top),
        fs_base: if fs_base_arg != 0 {
            Some(fs_base_arg)
        } else {
            // Inherit parent's FS_BASE. The current task's
            // `UserProcess.fs_base` isn't directly reachable from
            // the trap path, but the IA32_FS_BASE MSR holds the
            // active value at this moment — the user_task poll
            // wrote it. Reading it back is x86_64-specific.
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
        entry_arg: Some(entry_arg),
    };
    let _ = DEFAULT_USER_STACK_BYTES;

    // Spawn the child on the scheduler. The same address-space Arc
    // is attached so `address_space_of(child_tid)` returns it; the
    // child's first poll will MOV CR3 to the shared root and iretq
    // to (entry_pc, stack_top).
    let address_space = proc.address_space.clone();
    #[cfg(target_arch = "x86_64")]
    {
        let child_tid = narf_scheduler::spawn_user(
            crate::user_task::UserTaskFuture::new(proc),
            narf_scheduler::TaskSpec::unthrottled(),
            address_space,
        );
        ctx.set_return(SyscallReturn::ok(child_tid.raw()));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // aarch64 user_task::UserTaskFuture is x86_64-gated today.
        let _ = (proc, address_space);
        ctx.set_return(SyscallReturn::invalid_op());
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
                if v == 0 { None } else { Some(v) }
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
    let child_tid = narf_scheduler::spawn_user(
        future,
        narf_scheduler::TaskSpec::unthrottled(),
        child_as,
    );
    // POSIX inheritance — fd / cwd / brk / sigaction handlers are
    // copied; pending signals reset (handled by sigaction_fork
    // not touching the pending bitmap).
    crate::fd::fork(parent_pid, child_tid.raw());
    cwd_fork(parent_pid, child_tid.raw());
    brk_fork(parent_pid, child_tid.raw());
    sigaction_fork(parent_pid, child_tid.raw());
    // Parent-of bookkeeping for waitpid: the child's exit fires
    // an observer that uses this to find the parent's pending-
    // exits queue. Without it, the parent's wait4 has no way to
    // see the child's exit status.
    parent_of_set(child_tid.raw(), parent_pid);
    let _ = child_pid; // tid != pid distinction lands with thread-group bookkeeping
    ctx.set_return(SyscallReturn::ok(child_tid.raw()));
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
/// status is the POSIX-shaped 32-bit value: low 8 bits hold the
/// signal that killed the child (or 0 for normal exit), bits
/// 8..16 hold the exit code from sys_exit_task. Pre-fix, no
/// signals are tracked; status == (exit_code << 8).
static PENDING_EXITS: narf_lib::sync::IrqSafeSpinLock<
    Option<BTreeMap<u64, alloc::vec::Vec<(u64, i32)>>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

pub fn wait_init() {
    *PARENT_OF.lock() = Some(BTreeMap::new());
    *PENDING_EXITS.lock() = Some(BTreeMap::new());
    crate::user_task::register_exit_observer(on_child_exit);
}

#[doc(hidden)]
pub fn __test_wait_reset() {
    *PARENT_OF.lock() = None;
    *PENDING_EXITS.lock() = None;
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

/// Exit observer registered by `wait_init`. Called when a polled
/// user task transitions to Exited; pushes (child_pid, status)
/// onto the parent's pending-exits queue so a future wait4 can
/// reap it. Status: today we don't carry the user-supplied exit
/// code through the polling routine, so this records 0. Future
/// fix: thread the sys_exit_task `arg0` exit code through
/// `EXIT_REASON_EXITED` to here.
fn on_child_exit(child_pid: u64) {
    let parent = match parent_of_get(child_pid) {
        Some(p) => p,
        None => return, // No registered parent — orphan; nothing to reap.
    };
    let mut g = PENDING_EXITS.lock();
    if let Some(m) = g.as_mut() {
        m.entry(parent)
            .or_insert_with(alloc::vec::Vec::new)
            .push((child_pid, 0));
    }
}

fn sys_wait4(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let want_pid = args.arg0 as i64;
    let status_ptr = args.arg1 as *mut i32;
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
        if !status_ptr.is_null() {
            // SAFETY: user-provided pointer; if bogus we fault and
            // the trap path handles it. We're still in the user AS
            // because the syscall handler hasn't swapped CR3.
            unsafe {
                core::ptr::write_volatile(status_ptr, status);
            }
        }
        ctx.set_return(SyscallReturn::ok(reaped));
        return;
    }

    if options & WNOHANG != 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Blocking wait — busy-poll with sleep_pumps so kernel async
    // tasks (FB drain, cursor pump, IRQ wakers) keep making
    // progress. Cap at 60 s to bound a wedged child + missing
    // exit observer wiring.
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
            if !status_ptr.is_null() {
                // SAFETY: see above.
                unsafe { core::ptr::write_volatile(status_ptr, status); }
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
    *PGID_TABLE.lock() = None;
}

fn read_pgid(target: u64) -> u64 {
    let g = PGID_TABLE.lock();
    g.as_ref()
        .and_then(|m| m.get(&target).copied())
        .unwrap_or(target) // default: pgid == pid
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
    *SID_TABLE.lock() = None;
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
    ctx.set_return(SyscallReturn::ok(task));
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
    *UIDGID_TABLE.lock() = None;
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
    *RLIMIT_TABLE.lock() = None;
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
    let out_ptr = args.arg1 as *mut u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
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
    // SAFETY: caller-supplied writable user vaddr; we write two u64s.
    unsafe {
        core::ptr::write_volatile(out_ptr, pair.cur);
        core::ptr::write_volatile(out_ptr.add(1), pair.max);
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_setrlimit(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let resource = args.arg0 as usize;
    let in_ptr = args.arg1 as *const u64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if in_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied readable user vaddr; we read two u64s.
    let cur = unsafe { core::ptr::read_volatile(in_ptr) };
    let max = unsafe { core::ptr::read_volatile(in_ptr.add(1)) };
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
    let new_ptr = args.arg2 as *const u64;
    let old_ptr = args.arg3 as *mut u64;
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

    if !new_ptr.is_null() {
        // SAFETY: caller-supplied readable region.
        let cur = unsafe { core::ptr::read_volatile(new_ptr) };
        let max = unsafe { core::ptr::read_volatile(new_ptr.add(1)) };
        if !write_rlimit(task, resource, RLimitPair { cur, max }) {
            ctx.set_return(fail);
            return;
        }
    }
    if !old_ptr.is_null() {
        // SAFETY: caller-supplied writable region.
        unsafe {
            core::ptr::write_volatile(old_ptr, prior.cur);
            core::ptr::write_volatile(old_ptr.add(1), prior.max);
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
    *PRCTL_TABLE.lock() = None;
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
            // bounded user buffer. Copy at most 15 bytes (leave
            // room for the NUL).
            let ptr = arg_a as *const u8;
            if ptr.is_null() {
                ctx.set_return(fail);
                return;
            }
            let mut name = [0u8; TASK_COMM_LEN];
            // SAFETY: caller-supplied user pointer; we read up to
            // 15 bytes or the first NUL.
            unsafe {
                for i in 0..(TASK_COMM_LEN - 1) {
                    let b = core::ptr::read_volatile(ptr.add(i));
                    if b == 0 {
                        break;
                    }
                    name[i] = b;
                }
            }
            if !modify_prctl(task, |s| s.name = name) {
                ctx.set_return(fail);
                return;
            }
            // Mirror into PROC_COMM so /proc/[pid]/comm reflects
            // the new name. The byte buffer is NUL-padded; trim
            // before storing.
            let nul_pos = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            if let Ok(s) = core::str::from_utf8(&name[..nul_pos]) {
                set_proc_comm(task, s);
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_NAME => {
            let out = arg_a as *mut u8;
            if out.is_null() {
                ctx.set_return(fail);
                return;
            }
            let s = read_prctl(task);
            // SAFETY: caller-supplied 16-byte writable region.
            unsafe {
                for i in 0..TASK_COMM_LEN {
                    core::ptr::write_volatile(out.add(i), s.name[i]);
                }
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
    *SCHED_PARAM_TABLE.lock() = None;
}

fn sys_sched_getparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let out = args.arg1 as *mut i32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out.is_null() {
        ctx.set_return(fail);
        return;
    }
    let task = if pid == 0 { current_task_id() } else { pid };
    let g = SCHED_PARAM_TABLE.lock();
    let val = g.as_ref().and_then(|m| m.get(&task).copied()).unwrap_or(0);
    // SAFETY: caller-supplied writable user vaddr; one i32.
    unsafe {
        core::ptr::write_volatile(out, val);
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_sched_setparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let inp = args.arg1 as *const i32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if inp.is_null() {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied readable user vaddr.
    let val = unsafe { core::ptr::read_volatile(inp) };
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
    let out = args.arg2 as *mut u8;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out.is_null() || size == 0 {
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
                           // SAFETY: caller-supplied user vaddr; we write `bytes` bytes,
                           // first byte = 0x01 (CPU 0 set), rest zero.
    unsafe {
        core::ptr::write_volatile(out, 0x01);
        for i in 1..bytes {
            core::ptr::write_volatile(out.add(i), 0);
        }
    }
    ctx.set_return(SyscallReturn::ok(bytes as u64));
}

fn sys_sched_setaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _pid = args.arg0;
    let size = args.arg1 as usize;
    let buf = args.arg2 as *const u8;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf.is_null() || size == 0 {
        ctx.set_return(fail);
        return;
    }
    // Read but discard — we don't pin. Read the first byte to
    // surface a fault on a truly bad pointer.
    // SAFETY: caller-supplied readable region.
    let _ = unsafe { core::ptr::read_volatile(buf) };
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
    let cpu_ptr = args.arg0 as *mut u32;
    let node_ptr = args.arg1 as *mut u32;
    // SAFETY: caller-supplied user vaddrs in the active AS; we
    // only write through them when they're non-null.
    if !cpu_ptr.is_null() {
        unsafe {
            core::ptr::write_volatile(cpu_ptr, 0);
        }
    }
    if !node_ptr.is_null() {
        unsafe {
            core::ptr::write_volatile(node_ptr, 0);
        }
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
    *UMASK_TABLE.lock() = None;
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
    *NICE_TABLE.lock() = None;
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
    let out_ptr = ctx.args().arg0 as *mut i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let ns: u64 = narf_scheduler::narf_time::monotonic_ns();
    let ticks: i64 = (ns / (1_000_000_000 / CLK_TCK_HZ)) as i64;
    if !out_ptr.is_null() {
        // SAFETY: caller-supplied user vaddr in the active AS;
        // we write four i64s. Bad pointer faults the user.
        unsafe {
            core::ptr::write_volatile(out_ptr, ticks); // utime
            core::ptr::write_volatile(out_ptr.add(1), 0); // stime
            core::ptr::write_volatile(out_ptr.add(2), 0); // cutime
            core::ptr::write_volatile(out_ptr.add(3), 0); // cstime
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
    let out = args.arg1 as *mut i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out.is_null() {
        ctx.set_return(fail);
        return;
    }
    let ns: u64 = narf_scheduler::narf_time::monotonic_ns();
    let utime_sec = (ns / 1_000_000_000) as i64;
    let utime_usec = ((ns % 1_000_000_000) / 1_000) as i64;
    // SAFETY: caller-supplied user vaddr in the active AS; we
    // write 18 i64s. Bad pointer faults the user.
    unsafe {
        // ru_utime
        core::ptr::write_volatile(out, utime_sec);
        core::ptr::write_volatile(out.add(1), utime_usec);
        // ru_stime + 14 tail fields all zero.
        for i in 2..RUSAGE_TOTAL_I64S {
            core::ptr::write_volatile(out.add(i), 0);
        }
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
    let buf = args.arg0 as *mut u8;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    let g = HOSTNAME.lock();
    let bytes = g.as_bytes();
    if bytes.len() + 1 > len {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied user pointer in the active AS;
    // length-bounded; bad pointer faults the user, not us.
    unsafe {
        for (i, &b) in bytes.iter().enumerate() {
            core::ptr::write_volatile(buf.add(i), b);
        }
        core::ptr::write_volatile(buf.add(bytes.len()), 0);
    }
    ctx.set_return(SyscallReturn::ok(bytes.len() as u64));
}

fn sys_sethostname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0 as *const u8;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf.is_null() || len == 0 || len > HOSTNAME_MAX {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user-mode pointer in the active AS, length-bounded.
    let bytes = unsafe { core::slice::from_raw_parts(buf, len) };
    let s = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let mut g = HOSTNAME.lock();
    g.clear();
    g.push_str(s);
    ctx.set_return(SyscallReturn::ok(0));
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
static RNG_FEATURES: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

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
fn rdrand_u64() -> Option<u64> { None }
#[cfg(not(target_arch = "x86_64"))]
fn rdseed_u64() -> Option<u64> { None }

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
    let ptr = args.arg0 as *mut u8;
    let len = args.arg1 as usize;
    let _flags = args.arg2; // accepted-and-ignored
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Walk the buffer in 4-byte chunks via volatile writes — a Rust
    // `&mut [u8]` over user memory + LLVM optimisations could
    // otherwise drop the writes if the compiler proves they're
    // dead from the kernel's perspective.
    // SAFETY: caller-supplied user pointer in the active AS;
    // length-bounded; bad pointer faults the user, not us.
    unsafe {
        let mut i = 0usize;
        while i + 4 <= len {
            let v = next_random_u32();
            core::ptr::write_volatile(ptr.add(i), (v & 0xFF) as u8);
            core::ptr::write_volatile(ptr.add(i + 1), ((v >> 8) & 0xFF) as u8);
            core::ptr::write_volatile(ptr.add(i + 2), ((v >> 16) & 0xFF) as u8);
            core::ptr::write_volatile(ptr.add(i + 3), ((v >> 24) & 0xFF) as u8);
            i += 4;
        }
        // Tail bytes (0..3 of them).
        if i < len {
            let v = next_random_u32();
            let mut shift = 0u32;
            while i < len {
                core::ptr::write_volatile(ptr.add(i), ((v >> shift) & 0xFF) as u8);
                i += 1;
                shift += 8;
            }
        }
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
    *CWD_TABLE.lock() = None;
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
    let ptr = args.arg0 as *const u8;
    let len = args.arg1 as usize;
    // See sys_stat for the failure-sentinel rationale: the user-
    // runtime asm wrapper observes only `value`, so success and
    // invalid_op both surface as rax=0 without this.
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied user pointer in the active AS,
    // length-bounded. A bad pointer faults the user into its own
    // #PF, not ours.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let path = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
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
    map.insert(task, alloc::string::String::from(path));
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
    // SAFETY: user-supplied buf is in the active AS; len was
    // bounds-checked against `needed`. We write `cwd.len()` bytes
    // followed by a NUL — never past `len`.
    unsafe {
        core::ptr::copy_nonoverlapping(cwd.as_ptr(), buf, cwd.len());
        core::ptr::write(buf.add(cwd.len()), 0);
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
    *BRK_TABLE.lock() = None;
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
    let elf_ptr = args.arg0 as *const u8;
    let elf_len = args.arg1 as usize;
    let argv_ptr = args.arg2 as *const u8;
    let argv_len = args.arg3 as usize;
    let envp_ptr = args.arg4 as *const u8;
    let envp_len = args.arg5 as usize;

    // Reject obvious bad args. ELF must be at least Elf64 header
    // (64 bytes) and < 64 MiB (defensive cap; real images are
    // far smaller).
    if elf_ptr.is_null() || elf_len < 64 || elf_len > 64 * 1024 * 1024 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    // Step 2: copy ELF bytes from user memory while the calling
    // AS is still active (we haven't swapped CR3 yet — sys handler
    // runs in the user task's AS). The copied bytes live in a
    // kernel Vec that survives across the AS swap.
    // SAFETY: user-pointer dereference; if the pointer is bogus
    // we'll fault inside the copy loop and the trap handler will
    // panic — same risk every other read-from-user syscall takes.
    let mut elf_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(elf_len);
    unsafe {
        for i in 0..elf_len {
            elf_buf.push(core::ptr::read_volatile(elf_ptr.add(i)));
        }
    }

    // Step 3: copy + parse argv + envp packs.
    let argv_strs = match copy_user_pack(argv_ptr, argv_len) {
        Ok(v) => v,
        Err(()) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let envp_strs = match copy_user_pack(envp_ptr, envp_len) {
        Ok(v) => v,
        Err(()) => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let argv_refs: alloc::vec::Vec<&str> =
        argv_strs.iter().map(|s| s.as_str()).collect();
    let envp_refs: alloc::vec::Vec<&str> =
        envp_strs.iter().map(|s| s.as_str()).collect();

    // Step 4: load the new image. SAFETY: load_user_process_with's
    // contract — identity-mapped low 4 GiB, frame allocator
    // initialised. Both hold by the time any user task is running.
    let new_proc = match unsafe {
        crate::process::load_user_process_with(
            &elf_buf,
            &argv_refs,
            &envp_refs,
            &[],
        )
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
    // Copy the whole pack into a kernel Vec first.
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(len);
    // SAFETY: same risk as the ELF-buf copy above — a bogus user
    // pointer faults in the read.
    unsafe {
        for i in 0..len {
            buf.push(core::ptr::read_volatile(ptr.add(i)));
        }
    }
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

fn copy_user_str(
    ptr: *const u8,
    len: usize,
    cap: usize,
) -> Result<alloc::string::String, ()> {
    if len == 0 || ptr.is_null() || len > cap {
        return Err(());
    }
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(len);
    // SAFETY: user pointer; faulting reads land in the trap handler.
    unsafe {
        for i in 0..len {
            buf.push(core::ptr::read_volatile(ptr.add(i)));
        }
    }
    core::str::from_utf8(&buf)
        .map(alloc::string::String::from)
        .map_err(|_| ())
}

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
    let target = match copy_user_str(args.arg2 as *const u8, args.arg3 as usize, 256) {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(fail);
            return;
        }
    };
    // arg4 packs (fstype_ptr<<32 | fstype_len) — fstype is short
    // (< 32 chars in practice) so 32 bits each is plenty.
    let fstype_ptr = (args.arg4 >> 32) as *const u8;
    let fstype_len = (args.arg4 & 0xFFFF_FFFF) as usize;
    let fstype = match copy_user_str(fstype_ptr, fstype_len, 32) {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(fail);
            return;
        }
    };

    let auth = narf_filesystem::bootstrap_mount_authority();
    let domain = narf_lib::id::DomainId::DRIVER_0;

    // Bind mount: `source` is an absolute path to an existing mount;
    // `target` is the new path. No block device involved.
    if fstype == "bind" {
        return match narf_filesystem::registry()
            .bind_mount(&auth, source.as_str(), target.as_str())
        {
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

fn sys_umount2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);
    let target = match copy_user_str(args.arg0 as *const u8, args.arg1 as usize, 256) {
        Ok(s) => s,
        Err(()) => {
            ctx.set_return(fail);
            return;
        }
    };
    // We need the per-mount handle to call unmount(). Today the
    // registry doesn't expose that lookup — every mount returned its
    // handle to the original caller and we never stored it. As a
    // pragmatic interim, mint a fresh authority and let the registry
    // pop by path. Cap-side perfection lands once the per-task mount
    // namespace work in task #93 wires per-process mount tables.
    let _ = args.arg2; // flags ignored (MNT_FORCE / MNT_DETACH not yet wired)
    let auth = narf_filesystem::bootstrap_mount_authority();
    // SAFETY: bootstrapping a Write cap is the same TCB-trusted op
    // the registry uses internally to mint the per-mount handle.
    let handle: narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Write> =
        narf_capabilities::Cap::<narf_filesystem::MountPoint, narf_capabilities::Write>::bootstrap();
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
    bsize: u64,    // block size in bytes
    frsize: u64,   // fragment size (== bsize on simple FSes)
    blocks: u64,   // total blocks
    bfree: u64,    // free blocks
    bavail: u64,   // free blocks available to non-root
    files: u64,    // total inodes
    ffree: u64,    // free inodes
    namemax: u64,  // max filename length
}

fn fill_statfs_for_path(path: &str, buf_ptr: *mut u8) -> bool {
    if buf_ptr.is_null() {
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
    // SAFETY: buf_ptr came from user; per-byte volatile write is
    // serviced by the demand-paging branch in the #PF handler.
    unsafe {
        let bytes: [u8; core::mem::size_of::<StatfsBuf>()] =
            core::mem::transmute(stat);
        for (i, &b) in bytes.iter().enumerate() {
            core::ptr::write_volatile(buf_ptr.add(i), b);
        }
    }
    true
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
    let buf_ptr = args.arg2 as *mut u8;
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

fn sys_unshare(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0;
    const CLONE_NEWNS: u64 = 0x00020000;
    if flags & CLONE_NEWNS == 0 {
        // No-op for non-NS flags today.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    task_mount_ns_init();
    let task = current_task_id();
    let snap = narf_filesystem::MountNamespace::snapshot_global();
    let mut g = TASK_MOUNT_NS.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task, snap);
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok(!0u64));
    }
}

fn sys_fstatfs(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);
    let _fd = args.arg0 as i32;
    let buf_ptr = args.arg1 as *mut u8;
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
                if rb >= BRK_DEFAULT_BASE && rb >= new_aligned {
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
        CLOCK_MONOTONIC => {
            let ns: u64 = narf_scheduler::narf_time::monotonic_ns();
            ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
        }
        _ => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // SAFETY: caller provides a writable user vaddr in the active AS.
    // We've checked alignment above; a bad pointer is the user's
    // problem (faulted access lands in their handler, not ours).
    unsafe {
        core::ptr::write_volatile(buf as *mut i64, sec);
        core::ptr::write_volatile((buf + 8) as *mut i64, nsec);
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `sys_clock_settime(clock_id, *timespec)` — set CLOCK_REALTIME
/// by computing the wall-offset from the requested (sec, nsec) and
/// the current monotonic. Other clock_ids return -1.
fn sys_clock_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let ts = args.arg1 as *const i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ts.is_null() || (ts as u64) & 0x7 != 0 {
        ctx.set_return(fail);
        return;
    }
    if id != CLOCK_REALTIME {
        // CLOCK_MONOTONIC and friends are not settable.
        ctx.set_return(fail);
        return;
    }
    // SAFETY: caller-supplied readable `timespec`.
    let sec = unsafe { core::ptr::read_volatile(ts) };
    let nsec = unsafe { core::ptr::read_volatile(ts.add(1)) };
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

static SIGNAL_PENDING: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

static SIGNAL_MASK: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task pending+mask registries. Pair with
/// `sigaction_init` at boot.
pub fn signal_init() {
    *SIGNAL_PENDING.lock() = Some(BTreeMap::new());
    *SIGNAL_MASK.lock() = Some(BTreeMap::new());
}

/// Reset the registries — test hook. Drops every per-task entry.
#[doc(hidden)]
pub fn __test_signal_reset() {
    *SIGNAL_PENDING.lock() = None;
    *SIGNAL_MASK.lock() = None;
}

/// Diagnostic: peek the pending bitmap for `task`.
pub fn signal_pending_of(task: u64) -> u32 {
    SIGNAL_PENDING
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
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
    let trimmed: alloc::string::String =
        name.chars().take(15).collect();
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
pub fn proc_task_info(pid: u64) -> Option<narf_filesystem::procfs::ProcTaskInfo> {
    use narf_filesystem::procfs::ProcTaskInfo;
    // Don't gate on "is on a ready queue" — the currently-running
    // task has been popped from its queue for polling and would
    // fail that check while it's the very task asking. Treat any
    // pid that matches the caller OR a queued task as live.
    let current = current_task_id();
    let live = pid == current
        || narf_scheduler::all_task_ids().iter().any(|t| t.0 == pid);
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
    let stack_top = crate::process::DEFAULT_USER_STACK_BASE
        + crate::process::DEFAULT_USER_STACK_BYTES;
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
    if let Some(as_arc) = narf_scheduler::address_space_of(narf_scheduler::TaskId(pid))
        .or_else(|| {
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
            let label: &'static str =
                if base == crate::process::DEFAULT_USER_STACK_BASE {
                    "[stack]"
                } else if base == 0x8000_0000_0000_u64 || (base & 0xffff_ffff_0000_0000) == 0x8000_0000 {
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
    let target = args.arg0;
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
    let slot = map.entry(target).or_insert(0);
    *slot |= 1u32 << signum;
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
    g.as_ref()
        .and_then(|m| m.get(&uaddr).copied())
        .unwrap_or(0)
}

fn futex_bump_counter(uaddr: u64) {
    futex_table_init();
    let mut g = FUTEX_WAKE_COUNTERS.lock();
    if let Some(m) = g.as_mut() {
        let slot = m.entry(uaddr).or_insert(0);
        *slot = slot.wrapping_add(1);
    }
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
            let current = unsafe { core::ptr::read_volatile(uaddr as *const u32) };
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
                let deadline = narf_scheduler::narf_time::monotonic_ns()
                    .saturating_add(park_ns);
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
    ctx.set_return(SyscallReturn::ok(0));
}

const SIG_BLOCK: u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

fn sys_sigprocmask(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let how = args.arg0 as u32;
    let set = args.arg1 as u32;
    let task = current_task_id();
    let mut g = SIGNAL_MASK.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let slot = map.entry(task).or_insert(0);
    let prior = *slot;
    *slot = match how {
        SIG_BLOCK => prior | set,
        SIG_UNBLOCK => prior & !set,
        SIG_SETMASK => set,
        _ => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(prior as u64));
}

// Function-pointer hook: arch trap dispatcher invokes this on
// every int-0x80 trap-return that's heading back to user mode,
// just before the asm tail iretq's. Same shape as
// `install_address_space_lookup` so the trap path doesn't need
// a direct dep on this crate's signal internals.
type SignalDeliveryHook = fn(&mut dyn TrapContext);

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

/// Default delivery hook: pick the lowest pending unmasked
/// signal, look up its handler, ask the trap context to rewrite
/// itself to deliver. Fast path — when nothing's pending it
/// takes a single lock + a single bitmap read and returns.
pub fn default_signal_delivery(ctx: &mut dyn TrapContext) {
    if !ctx.returning_to_user() {
        return;
    }
    let task = current_task_id();
    // Single lock acquire on the fast path: peek pending+mask
    // under one lock each, decide whether there's anything to
    // do, then re-lock briefly to clear the chosen bit. The
    // common case (nothing pending) falls out after the first
    // peek with no work.
    let pending = {
        let g = SIGNAL_PENDING.lock();
        match g.as_ref().and_then(|m| m.get(&task).copied()) {
            Some(p) if p != 0 => p,
            _ => return,
        }
    };
    let mask = SIGNAL_MASK
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0);
    let deliverable = pending & !mask;
    if deliverable == 0 {
        return;
    }
    let signum = deliverable.trailing_zeros();
    let handler = match sigaction_lookup(task, signum as usize) {
        Some(h) => h,
        None => return,
    };
    if !ctx.deliver_signal(handler, signum) {
        return;
    }
    // Clear only after the rewrite succeeded — a failed
    // delivery (e.g. arch returns false) should leave pending
    // alone so the next trap retries.
    if let Some(map) = SIGNAL_PENDING.lock().as_mut() {
        if let Some(slot) = map.get_mut(&task) {
            *slot &= !(1u32 << signum);
        }
    }
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

/// Function-pointer hook the arch trap dispatcher calls for
/// every CPU exception (vectors 0..31) that originated in user
/// mode. Returns `true` if the trap frame was rewritten to
/// deliver a signal — the trap dispatcher should then return
/// directly so `iretq` lands at the rewritten user RIP.
/// Returns `false` if no handler was installed (or the vector
/// has no signal mapping); the caller falls through to the
/// existing panic / probe-catch path.
type SyncSignalHook = fn(&mut dyn TrapContext, u64) -> bool;

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
///   - no sigaction handler is registered for that signum
///   - the arch's `deliver_signal` rejects the rewrite
///
/// In all three cases the caller falls through to the existing
/// panic surface, which is the right behaviour: a userland that
/// hasn't installed a handler for SIGSEGV genuinely deserves
/// the kernel-side crash dump.
pub fn default_sync_signal_delivery(ctx: &mut dyn TrapContext, vector: u64) -> bool {
    let signum = match vector_to_signum(vector) {
        Some(s) => s,
        None => return false,
    };
    let task = current_task_id();
    let handler = match sigaction_lookup(task, signum as usize) {
        Some(h) => h,
        None => return false,
    };
    ctx.deliver_signal(handler, signum)
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

static SIGACTION_TABLE: narf_lib::sync::IrqSafeSpinLock<
    Option<BTreeMap<u64, [Option<u64>; NSIG]>>,
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
    *SIGACTION_TABLE.lock() = None;
}

/// Diagnostic: peek the recorded handler for `(task, signum)`.
pub fn sigaction_lookup(task: u64, signum: usize) -> Option<u64> {
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
    let sc_vaddr = ctx.args().arg0;
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

fn socket_arc_lookup(
    raw: *const (),
) -> Option<alloc::sync::Arc<crate::socket::SocketFile>> {
    let g = SOCKET_ARCS.lock();
    g.as_ref()?.get(&(raw as usize)).cloned()
}

fn copy_user_addr(ptr: u64, len: u64) -> Option<crate::socket::SockAddr> {
    if ptr == 0 || len < 2 || len > 110 {
        return None;
    }
    // Family is the first u16 (host byte order). Body is the rest.
    let mut family_bytes = [0u8; 2];
    unsafe {
        family_bytes[0] = core::ptr::read_volatile(ptr as *const u8);
        family_bytes[1] = core::ptr::read_volatile((ptr + 1) as *const u8);
    }
    let family = u16::from_le_bytes(family_bytes);
    let body_len = (len - 2) as usize;
    let mut body = alloc::vec![0u8; body_len];
    unsafe {
        for i in 0..body_len {
            body[i] = core::ptr::read_volatile((ptr + 2 + i as u64) as *const u8);
        }
    }
    Some(crate::socket::SockAddr { family, body })
}

fn sys_socket(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let domain = args.arg0 as u16;
    let kind = args.arg1 as u32;
    let _proto = args.arg2;
    let sock = crate::socket::SocketFile::new(domain, kind);
    socket_arc_register(&sock);
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: sock.clone(),
            offset: 0,
            flags: 0,
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
        None => { ctx.set_return(fail); return; }
    };
    let addr = match copy_user_addr(addr_ptr, addr_len) {
        Some(a) => a,
        None => { ctx.set_return(fail); return; }
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
        None => { ctx.set_return(fail); return; }
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
        None => { ctx.set_return(fail); return; }
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
                let deadline = narf_scheduler::narf_time::monotonic_ns()
                    .saturating_add(1_000_000);
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
        None => { ctx.set_return(fail); return; }
    };
    let addr = match copy_user_addr(addr_ptr, addr_len) {
        Some(a) => a,
        None => { ctx.set_return(fail); return; }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Connect { addr }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_socket_send(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1 as *const u8;
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
        None => { ctx.set_return(fail); return; }
    };
    if buf_ptr.is_null() && buf_len != 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: per-byte read through identity-mapped active AS;
    // bad pointer faults user-side.
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(buf_len);
    unsafe {
        for i in 0..buf_len {
            buf.push(core::ptr::read_volatile(buf_ptr.add(i)));
        }
    }
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
    let buf_ptr = args.arg1 as *mut u8;
    let buf_len = args.arg2 as usize;
    let flags = args.arg3 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => { ctx.set_return(fail); return; }
    };
    if buf_ptr.is_null() && buf_len != 0 {
        ctx.set_return(fail);
        return;
    }
    let mut buf = alloc::vec![0u8; buf_len];
    let result = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags,
    });
    match result {
        crate::socket::SocketOpResult::Received { n, .. } => {
            // Copy back into user.
            unsafe {
                for i in 0..n {
                    core::ptr::write_volatile(buf_ptr.add(i), buf[i]);
                }
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
                let deadline = narf_scheduler::narf_time::monotonic_ns()
                    .saturating_add(1_000_000);
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
        None => { ctx.set_return(fail); return; }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Shutdown { how }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}

fn sys_socket_getsockopt(ctx: &mut dyn TrapContext) {
    // Stage-1: every getsockopt returns success with len=0 to keep
    // libc happy. Real per-option storage lands once a consumer
    // (TCP) needs it.
    let _ = ctx.args();
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_socket_setsockopt(ctx: &mut dyn TrapContext) {
    // Stage-1: accept and ignore. Real setsockopt routing lands
    // alongside TCP.
    let _ = ctx.args();
    ctx.set_return(SyscallReturn::ok(0));
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
        None => { ctx.set_return(fail); return; }
    };
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => { ctx.set_return(fail); return; }
    };
    // Zero-copy contract: the kernel reads directly from the
    // pinned user vaddr. For AF_UNIX SOCK_STREAM the destination
    // is an in-kernel ring, so "zero-copy" still means a single
    // memcpy — once the NIC TX path lands, this becomes a real
    // descriptor enqueue with no copy.
    let buf: &[u8] = unsafe {
        core::slice::from_raw_parts(vaddr as *const u8, slice_len as usize)
    };
    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf,
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
        if e.exclusive_owner == task { return Ok(()); }
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
        None => { ctx.set_return(fail); return; }
    };
    let file_ptr = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let nonblock = op & LOCK_NB != 0;
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
            let dl = narf_scheduler::narf_time::monotonic_ns()
                .saturating_add(1_000_000);
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
static FOREGROUND_TASK: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

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
    let out = args.arg1 as *mut u8;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out.is_null() {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let t = termios_of_task(task);
    // SAFETY: user out pointer; per-byte volatile write is serviced
    // by demand-paging if the page is fresh.
    unsafe {
        let bytes: [u8; core::mem::size_of::<KTermios>()] = core::mem::transmute(t);
        for (i, &b) in bytes.iter().enumerate() {
            core::ptr::write_volatile(out.add(i), b);
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_tcsetattr(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _fd = args.arg0;
    let _action = args.arg1;
    let in_ptr = args.arg2 as *const u8;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if in_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let mut bytes = [0u8; core::mem::size_of::<KTermios>()];
    unsafe {
        for i in 0..bytes.len() {
            bytes[i] = core::ptr::read_volatile(in_ptr.add(i));
        }
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
    let pollfds_ptr = args.arg0 as *mut u8;
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
    if pollfds_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    // Each pollfd is [fd: i32 (4 B), events: i16 (2 B), revents: i16 (2 B)] = 8 B.
    const PF_LEN: usize = 8;
    let total = n * PF_LEN;
    // Pull the user buffer into a kernel scratch.
    let mut user_buf = alloc::vec![0u8; total];
    unsafe {
        for i in 0..total {
            user_buf[i] = core::ptr::read_volatile(pollfds_ptr.add(i));
        }
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
                let readiness = fd::with_table(task, |t| {
                    t.get(fd).map(|e| e.ops.poll_readiness())
                })
                .flatten();
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
            // Copy revents back to user.
            unsafe {
                for i in 0..total {
                    core::ptr::write_volatile(pollfds_ptr.add(i), user_buf[i]);
                }
            }
            ctx.set_return(SyscallReturn::ok(ready));
            return;
        }
        if let Some(deadline) = deadline_ns {
            let now = narf_scheduler::narf_time::monotonic_ns();
            if now >= deadline {
                // Timeout — write back zero revents (already done)
                // and return 0.
                unsafe {
                    for i in 0..total {
                        core::ptr::write_volatile(pollfds_ptr.add(i), user_buf[i]);
                    }
                }
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
        t.open(crate::fd::FdEntry { ops: ep, offset: 0, flags: 0 })
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
        None => { ctx.set_return(fail); return; }
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
    let mut events_bytes = [0u8; 4];
    let mut data_bytes = [0u8; 8];
    unsafe {
        for i in 0..4 {
            events_bytes[i] = core::ptr::read_volatile(event_ptr.add(i));
        }
        for i in 0..8 {
            data_bytes[i] = core::ptr::read_volatile(event_ptr.add(4 + i));
        }
    }
    let entry = crate::io_mux::EpollEntry {
        events: u32::from_le_bytes(events_bytes),
        user_data: u64::from_le_bytes(data_bytes),
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
    let events_out = args.arg1 as *mut u8;
    let max = args.arg2 as usize;
    let timeout_ms = args.arg3 as i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let ep_arc = match epoll_arc_from_fd(task, epfd) {
        Some(e) => e,
        None => { ctx.set_return(fail); return; }
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
            let fd_u = if *fd < 0 { continue; } else { *fd as u32 };
            let readiness = fd::with_table(task, |t| {
                t.get(fd_u).map(|e| e.ops.poll_readiness())
            })
            .flatten()
            .unwrap_or(0);
            let active = readiness & entry.events;
            if active != 0 {
                let off = written * 12;
                unsafe {
                    let bytes = active.to_le_bytes();
                    for i in 0..4 {
                        core::ptr::write_volatile(events_out.add(off + i), bytes[i]);
                    }
                    let dbytes = entry.user_data.to_le_bytes();
                    for i in 0..8 {
                        core::ptr::write_volatile(events_out.add(off + 4 + i), dbytes[i]);
                    }
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
        t.open(crate::fd::FdEntry { ops: efd, offset: 0, flags: 0 })
    }) {
        Some(n) => n,
        None => { ctx.set_return(SyscallReturn::ok((-1i64) as u64)); return; }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

fn sys_timerfd_create(ctx: &mut dyn TrapContext) {
    let _ = ctx.args();
    let tfd = crate::io_mux::TimerFd::new();
    timerfd_arc_register(&tfd);
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry { ops: tfd, offset: 0, flags: 0 })
    }) {
        Some(n) => n,
        None => { ctx.set_return(SyscallReturn::ok((-1i64) as u64)); return; }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

fn sys_timerfd_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let _flags = args.arg1;
    let new_value_ptr = args.arg2 as *const u8;
    let _old_value_ptr = args.arg3 as *mut u8;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    if new_value_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    // itimerspec is { interval: timespec, value: timespec } where
    // timespec = { tv_sec: i64, tv_nsec: i64 } = 16 B. Total 32 B.
    let mut buf = [0u8; 32];
    unsafe {
        for i in 0..32 {
            buf[i] = core::ptr::read_volatile(new_value_ptr.add(i));
        }
    }
    let interval_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let interval_ns = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let value_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap());
    let value_ns = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    let interval_total = (interval_sec as u64).saturating_mul(1_000_000_000)
        .saturating_add(interval_ns as u64);
    let value_total = (value_sec as u64).saturating_mul(1_000_000_000)
        .saturating_add(value_ns as u64);
    let now = narf_scheduler::narf_time::monotonic_ns();
    let next_fire = if value_total == 0 { 0 } else { now.saturating_add(value_total) };
    let tfd = match timerfd_arc_from_fd(task, fd) {
        Some(t) => t,
        None => { ctx.set_return(fail); return; }
    };
    tfd.arm(next_fire, interval_total);
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
    let _fd_arg = args.arg0 as i64; // -1 = create new
    let mask_ptr = args.arg1 as *const u8;
    let _sizemask = args.arg2;
    let _flags = args.arg3;
    let mut mask: u64 = 0;
    if !mask_ptr.is_null() {
        unsafe {
            let mut bytes = [0u8; 8];
            for i in 0..8 {
                bytes[i] = core::ptr::read_volatile(mask_ptr.add(i));
            }
            mask = u64::from_le_bytes(bytes);
        }
    }
    let task = current_task_id();
    let sfd = crate::io_mux::SignalFd::new(mask, task);
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry { ops: sfd, offset: 0, flags: 0 })
    }) {
        Some(n) => n,
        None => { ctx.set_return(SyscallReturn::ok((-1i64) as u64)); return; }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

fn sys_sigaction(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let signum = args.arg0 as usize;
    let new_handler = args.arg1;
    let old_out = args.arg2;
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
            Some(new_handler)
        };
        prior
    };

    if old_out != 0 {
        // SAFETY: caller-supplied user vaddr in the active AS. We
        // require natural u64 alignment; a misaligned pointer faults
        // into the user's own handler, not ours.
        if old_out & 0x7 == 0 {
            unsafe {
                core::ptr::write_volatile(old_out as *mut u64, prior.unwrap_or(0));
            }
        }
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
        return narf_abi::FileOpReturn { status: 2, value: 0 };
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
        status: ctx.ret.status,
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

/// Drop the core set of handlers into `table`. Idempotent — later
/// subsystems can install richer handlers over the same slots
/// (e.g. a real file-descriptor-backed `Read`).
pub fn install_core_syscalls(table: &mut SyscallTable) {
    table.install_raw(Syscall::Bootstrap, "bootstrap", RawFnHandler(sys_bootstrap));
    table.install_raw(Syscall::OpenFile, "open", RawFnHandler(sys_open));
    table.install_raw(Syscall::Write, "write", RawFnHandler(sys_write));
    table.install_raw(Syscall::Read, "read", RawFnHandler(sys_read));
    table.install_raw(Syscall::Close, "close", RawFnHandler(sys_close));
    table.install_raw(Syscall::Mmap, "mmap", RawFnHandler(sys_mmap));
    table.install_raw(Syscall::Munmap, "munmap", RawFnHandler(sys_munmap));
    table.install_raw(Syscall::MProtect, "mprotect", RawFnHandler(sys_mprotect));
    table.install_raw(Syscall::MLock, "mlock", RawFnHandler(sys_mlock));
    table.install_raw(Syscall::MUnlock, "munlock", RawFnHandler(sys_munlock));
    table.install_raw(Syscall::Execve, "execve", RawFnHandler(sys_execve));
    table.install_raw(Syscall::Wait4, "wait4", RawFnHandler(sys_wait4));
    table.install_raw(Syscall::Mount, "mount", RawFnHandler(sys_mount));
    table.install_raw(Syscall::Umount2, "umount2", RawFnHandler(sys_umount2));
    table.install_raw(Syscall::Statfs, "statfs", RawFnHandler(sys_statfs));
    table.install_raw(Syscall::Fstatfs, "fstatfs", RawFnHandler(sys_fstatfs));
    table.install_raw(Syscall::Unshare, "unshare", RawFnHandler(sys_unshare));
    table.install_raw(Syscall::Sigreturn, "sigreturn", RawFnHandler(sys_sigreturn));
    table.install_raw(Syscall::SocketOpen, "socket", RawFnHandler(sys_socket));
    table.install_raw(Syscall::SocketBind, "bind", RawFnHandler(sys_socket_bind));
    table.install_raw(Syscall::SocketListen, "listen", RawFnHandler(sys_socket_listen));
    table.install_raw(Syscall::SocketAccept, "accept", RawFnHandler(sys_socket_accept));
    table.install_raw(Syscall::SocketConnect, "connect", RawFnHandler(sys_socket_connect));
    table.install_raw(Syscall::SocketSend, "send", RawFnHandler(sys_socket_send));
    table.install_raw(Syscall::SocketRecv, "recv", RawFnHandler(sys_socket_recv));
    table.install_raw(Syscall::SocketShutdown, "shutdown", RawFnHandler(sys_socket_shutdown));
    table.install_raw(Syscall::SocketGetSockOpt, "getsockopt", RawFnHandler(sys_socket_getsockopt));
    table.install_raw(Syscall::SocketSetSockOpt, "setsockopt", RawFnHandler(sys_socket_setsockopt));
    table.install_raw(Syscall::SockRegisterBuf, "sock_register_buf", RawFnHandler(sys_sock_register_buf));
    table.install_raw(Syscall::SockSendZc, "sock_send_zc", RawFnHandler(sys_sock_send_zc));
    table.install_raw(Syscall::Poll, "poll", RawFnHandler(sys_poll));
    table.install_raw(Syscall::EpollCreate, "epoll_create", RawFnHandler(sys_epoll_create));
    table.install_raw(Syscall::EpollCtl, "epoll_ctl", RawFnHandler(sys_epoll_ctl));
    table.install_raw(Syscall::EpollWait, "epoll_wait", RawFnHandler(sys_epoll_wait));
    table.install_raw(Syscall::Eventfd, "eventfd", RawFnHandler(sys_eventfd));
    table.install_raw(Syscall::TimerfdCreate, "timerfd_create", RawFnHandler(sys_timerfd_create));
    table.install_raw(Syscall::TimerfdSettime, "timerfd_settime", RawFnHandler(sys_timerfd_settime));
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
    table.install_raw(Syscall::Sigaction, "sigaction", RawFnHandler(sys_sigaction));
    table.install_raw(Syscall::Kill, "kill", RawFnHandler(sys_kill));
    table.install_raw(Syscall::Tgkill, "tgkill", RawFnHandler(sys_tgkill));
    table.install_raw(Syscall::Futex, "futex", RawFnHandler(sys_futex));
    table.install_raw(
        Syscall::Sigprocmask,
        "sigprocmask",
        RawFnHandler(sys_sigprocmask),
    );

    // Tier-2 fd-table breadth + path-resolution + pipe(2).
    table.install_raw(Syscall::Dup, "dup", RawFnHandler(sys_dup));
    table.install_raw(Syscall::Dup2, "dup2", RawFnHandler(sys_dup2));
    table.install_raw(Syscall::Dup3, "dup3", RawFnHandler(sys_dup3));
    table.install_raw(Syscall::Fcntl, "fcntl", RawFnHandler(sys_fcntl));
    table.install_raw(Syscall::Stat, "stat", RawFnHandler(sys_stat));
    table.install_raw(Syscall::Lstat, "lstat", RawFnHandler(sys_stat));
    table.install_raw(Syscall::Fstat, "fstat", RawFnHandler(sys_fstat));
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
    table.install_raw(
        Syscall::Newfstatat,
        "newfstatat",
        RawFnHandler(sys_newfstatat),
    );
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

    // Auto-wire both delivery hooks so any kernel that uses
    // `install_core_syscalls` gets the async + sync signal paths
    // on for free. Idempotent.
    install_signal_delivery_hook(default_signal_delivery);
    install_sync_signal_hook(default_sync_signal_delivery);
}
