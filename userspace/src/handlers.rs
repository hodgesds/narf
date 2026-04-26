//! Core syscall handler bodies.
//!
//! Stage-4 first-cut implementations of the POSIX-shaped syscalls
//! the `Syscall` enum pinned earlier. These run in trap context
//! after the arch trap stub has saved user registers and the
//! `TrapContext` bridge is constructed. They don't yet carry the
//! per-file-descriptor table or VFS open-file machinery real I/O
//! needs — today's handlers are deliberate minimums:
//!
//! - `Write` — writes `len` bytes from user virt `buf` to the
//!   kernel console. Ignores `fd`. Returns bytes written.
//! - `Read`  — returns 0 (EOF). Stage-4 will wire to the VFS.
//! - `Close` — returns Ok. Stage-4 will look up a per-task fd table.
//! - `Mmap`  — allocates one or more physical frames, installs an
//!   R+W+U mapping in the calling task's AS, returns the virt addr.
//! - `Munmap` — removes a region from the calling task's AS.
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
    fd, RawFnHandler, Syscall, SyscallReturn, SyscallTable, TrapContext,
};

// ── Current-task lookup shim ───────────────────────────────────────
//
// Same shape as `AS_LOOKUP` — wired in by the kernel boot to
// resolve "what task is running this syscall" without a direct
// `narf_userspace → narf_scheduler` dep cycle.

type TaskIdLookupFn = fn() -> u64;

static TASK_LOOKUP: narf_lib::sync::IrqSafeSpinLock<Option<TaskIdLookupFn>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

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
    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker { raw_waker() }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    // SAFETY: vtable holds null-pointer-clean stubs; the waker is
    // never woken (poll_once expects Ready on the first poll).
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut ctx = Context::from_waker(&waker);
    // SAFETY: we own `fut` by value; pinning to a stack temporary
    // is the standard "block_on of a !Unpin future".
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut ctx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending  => None,
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

static AS_LOOKUP: narf_lib::sync::IrqSafeSpinLock<Option<AsLookupFn>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

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

const ABI_BOOTSTRAP_MAGIC: u32 = 0x4E_41_52_46;  // "NARF" LE
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
    magic:    u32,
    version:  u32,
    task_id:  u64,
    /// Capslot ids the user runtime invokes against. They name
    /// the SQ producer / CQ consumer the kernel-side dispatcher
    /// is bound to.
    sq_cap:   u64,
    cq_cap:   u64,
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
    completion_channel, submission_channel, Completion, CompletionDrain,
    CompletionQueue, SharedRing, Submission, SubmissionDrain,
    SubmissionQueue,
};
use narf_memory::PhysAddr;

/// Kernel-side keep of the ring pair Bootstrap minted for a task.
/// Stored under the task id; SMP-safe via the outer lock.
pub struct TaskRings {
    pub sq_drain: SubmissionDrain<64>,
    pub cq_prod:  CompletionQueue<64>,
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
    pub sq_prod:  SubmissionQueue<64>,
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
#[allow(dead_code)]  // fields read by the future dispatcher integration
struct PerTaskBootstrap {
    kernel:     TaskRings,
    user:       UserRingEnds,
    shared:     Option<SharedRingPair>,
    sq_cap_id:  u64,
    cq_cap_id:  u64,
}

static BOOTSTRAP_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, PerTaskBootstrap>>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task bootstrap registry. Boot calls this
/// once before any user task can issue `Syscall::Bootstrap`.
pub fn bootstrap_init() {
    *BOOTSTRAP_TABLE.lock() = Some(BTreeMap::new());
}

/// Reset the registry — test hook; drops every per-task ring set.
#[doc(hidden)]
pub fn __test_bootstrap_reset() { *BOOTSTRAP_TABLE.lock() = None; }

/// Diagnostic: number of tasks that have called Bootstrap.
pub fn bootstrap_live_count() -> usize {
    BOOTSTRAP_TABLE.lock().as_ref().map(|m| m.len()).unwrap_or(0)
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
            sq_prod:  _dead_sq,
            cq_drain: _dead_cq,
        }
    };
    map.insert(task, PerTaskBootstrap {
        kernel: entry.kernel,
        user:   placeholder_user,
        shared: entry.shared,
        sq_cap_id: entry.sq_cap_id,
        cq_cap_id: entry.cq_cap_id,
    });
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
            cq_prod:  dead_cq_prod,
        }
    };
    map.insert(task, PerTaskBootstrap {
        kernel: placeholder_kernel,
        user:   entry.user,
        shared: entry.shared,
        sq_cap_id: entry.sq_cap_id,
        cq_cap_id: entry.cq_cap_id,
    });
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
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    let task = current_task_id();

    // Allocate a phys frame, zero it, install at a fresh user vaddr
    // (mmap-cursor-style — same scheme `sys_mmap` uses).
    let phys = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    // SAFETY: identity-mapped low 4 GiB; phys is page-aligned.
    unsafe {
        core::ptr::write_bytes(phys.raw() as *mut u8, 0, 4096);
    }
    let user_vaddr = MMAP_CURSOR.fetch_add(0x1000, Ordering::Relaxed);

    if as_ref.map_region(Region {
        base:  VirtAddr::new(user_vaddr),
        len:   0x1000,
        // Stage-4 first cut: writable. Future revision flips the
        // page to R-only after the kernel populates it; the user
        // ring builders read from it but don't write.
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  alloc::vec![phys],
    }).is_err() {
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
        Err(()) => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };

    let entry = PerTaskBootstrap {
        kernel: TaskRings { sq_drain, cq_prod },
        user:   UserRingEnds { sq_prod, cq_drain },
        shared: Some(shared),
        sq_cap_id, cq_cap_id,
    };
    {
        let mut g = BOOTSTRAP_TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None    => {
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
        (*header).magic    = ABI_BOOTSTRAP_MAGIC;
        (*header).version  = ABI_BOOTSTRAP_VERSION;
        (*header).task_id  = task;
        (*header).sq_cap   = sq_cap_id;
        (*header).cq_cap   = cq_cap_id;
        (*header).sq_depth = BOOTSTRAP_RING_DEPTH as u32;
        (*header).cq_depth = BOOTSTRAP_RING_DEPTH as u32;
        (*header).shared_sq_vaddr = shared.sq_user_vaddr;
        (*header).shared_cq_vaddr = shared.cq_user_vaddr;
        (*header).shared_depth    = BOOTSTRAP_SHARED_RING_DEPTH as u32;
        (*header)._pad            = 0;
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

    as_ref.map_region(Region {
        base:  VirtAddr::new(sq_vaddr), len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  alloc::vec![sq_phys],
    }).map_err(|_| ())?;
    as_ref.map_region(Region {
        base:  VirtAddr::new(cq_vaddr), len: 0x1000,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  alloc::vec![cq_phys],
    }).map_err(|_| ())?;
    unsafe { as_ref.materialize() }.map_err(|_| ())?;

    Ok(SharedRingPair {
        sq_phys, cq_phys,
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
    let mnt_ptr  = args.arg2 as *const u8;
    let mnt_len  = args.arg3 as usize;
    let flags    = args.arg4;
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
        Err(_) => { ctx.set_return(fail); return; }
    };

    // Two shapes:
    // - Absolute: arg2/arg3 = (0, 0). The path itself is `/foo/bar`;
    //   the registry finds the longest-matching mount.
    // - Explicit-mount: arg2/arg3 = (ptr, len). The path is relative.
    //   Useful when the caller already knows the mount.
    let ops = if mnt_len == 0 {
        narf_filesystem::registry().resolve_absolute(path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        }).flatten()
    } else {
        let mnt_bytes = unsafe { core::slice::from_raw_parts(mnt_ptr, mnt_len) };
        let mount = match core::str::from_utf8(mnt_bytes) {
            Ok(s) => s,
            Err(_) => { ctx.set_return(fail); return; }
        };
        narf_filesystem::registry().with_mount(mount, |fs| {
            narf_filesystem::resolve(fs.root(), path).ok()
        }).flatten()
    };

    // O_CREAT path: when the lookup misses and the caller asked for
    // creation, route through the parent directory's `create()`. The
    // explicit-mount form is rare on the create path and not yet
    // wired; absolute paths are the supported entry.
    let ops = match ops {
        Some(o) => o,
        None if (flags & O_CREAT) != 0 && mnt_len == 0 => {
            match narf_filesystem::registry()
                .resolve_parent_absolute(path, |_fs, parent, leaf| parent.create(leaf))
            {
                Some(Ok(o)) => o,
                _ => { ctx.set_return(fail); return; }
            }
        }
        None => { ctx.set_return(fail); return; }
    };

    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry { ops, offset: 0, flags: 0 })
    }) {
        Some(n) => n,
        None    => { ctx.set_return(fail); return; }
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
            None    => return Err(()),
        };
        let off = entry.offset;
        let written = poll_once(entry.ops.write(off, slice))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        entry.offset = off.saturating_add(written as u64);
        Ok(written)
    });
    match outcome {
        Some(Ok(n))   => ctx.set_return(SyscallReturn::ok(n as u64)),
        _             => ctx.set_return(SyscallReturn::invalid_op()),
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
    // SAFETY: same contract as `sys_write` — user pointer in the
    // active AS, length-bounded.
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };

    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = match t.get_mut(fd) {
            Some(e) => e,
            None    => return Err(()),
        };
        let off = entry.offset;
        let read = poll_once(entry.ops.read(off, slice))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        entry.offset = off.saturating_add(read as u64);
        Ok(read)
    });
    match outcome {
        Some(Ok(n))   => ctx.set_return(SyscallReturn::ok(n as u64)),
        _             => ctx.set_return(SyscallReturn::invalid_op()),
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
            ops:    entry.ops.clone(),
            offset: 0,
            flags:  0,
        };
        Some(t.open(clone))
    });
    match outcome {
        Some(Some(new_fd)) => ctx.set_return(SyscallReturn::ok(new_fd as u64)),
        _                  => ctx.set_return(SyscallReturn::invalid_op()),
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
            ops:    entry.ops.clone(),
            offset: 0,
            flags:  0,
        };
        // Replace whatever sat at `newfd` (POSIX: silently close).
        t.set(newfd, clone);
        Some(())
    });
    match outcome {
        Some(Some(())) => ctx.set_return(SyscallReturn::ok(newfd as u64)),
        _              => ctx.set_return(SyscallReturn::invalid_op()),
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
            ops:    entry.ops.clone(),
            offset: 0,
            // O_CLOEXEC (Linux) is bit 0x80000 in `flags`; Stage-4
            // accepts the lower-bit shape (FD_CLOEXEC = 1) directly
            // since narf-libc's `dup3` already passes FD_CLOEXEC.
            flags:  flags & crate::fd::FD_CLOEXEC,
        };
        t.set(newfd, clone);
        Some(())
    });
    match outcome {
        Some(Some(())) => ctx.set_return(SyscallReturn::ok(newfd as u64)),
        _              => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;

fn sys_fcntl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd  = args.arg0 as u32;
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
        _             => ctx.set_return(SyscallReturn::invalid_op()),
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
    pub size:         u64,
    pub blocks:       u64,
    pub mode:         u32,
    pub _pad:         u32,
    pub mtime_cycles: u64,
}

impl StatBuf {
    fn from_stat(s: narf_filesystem::Stat) -> Self {
        let ftype_bits: u32 = match s.mode.file_type {
            narf_filesystem::FileType::File    => 0o100000,
            narf_filesystem::FileType::Dir     => 0o040000,
            narf_filesystem::FileType::Symlink => 0o120000,
            narf_filesystem::FileType::Special => 0o020000,
        };
        Self {
            size:         s.size,
            blocks:       s.blocks,
            mode:         ftype_bits | (s.mode.perms as u32),
            _pad:         0,
            mtime_cycles: s.mtime_cycles,
        }
    }
}

fn sys_stat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_ptr = args.arg0 as *const u8;
    let path_len = args.arg1 as usize;
    let out_ptr  = args.arg2 as *mut StatBuf;
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
        Err(_) => { ctx.set_return(fail); return; }
    };
    let ops = narf_filesystem::registry().resolve_absolute(path, |fs, rel| {
        narf_filesystem::resolve(fs.root(), rel).ok()
    }).flatten();
    let ops = match ops {
        Some(o) => o,
        None    => { ctx.set_return(fail); return; }
    };
    let stat = StatBuf::from_stat(ops.stat());
    // SAFETY: caller supplied a writable user vaddr; if the address
    // is bad the user faults into its own handler, not ours.
    unsafe { core::ptr::write_volatile(out_ptr, stat); }
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
        _             => { ctx.set_return(fail); return; }
    };
    // SAFETY: same contract as `sys_stat`.
    unsafe { core::ptr::write_volatile(out_ptr, stat); }
    ctx.set_return(SyscallReturn::ok(0));
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
            offset: 0, flags: 0,
        });
        let w = t.open(crate::fd::FdEntry {
            ops: wr as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0, flags: 0,
        });
        (r, w)
    });
    let (r, w) = match fds {
        Some(p) => p,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    // SAFETY: caller-supplied user vaddr; we write two i32s. The
    // kernel runs in the calling task's AS so the write resolves.
    unsafe {
        core::ptr::write_volatile(out_ptr,             r as i32);
        core::ptr::write_volatile(out_ptr.add(1),      w as i32);
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
    let fd     = args.arg0 as u32;
    let offset = args.arg1 as i64;
    let whence = args.arg2;
    let task   = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get_mut(fd)?;
        let base = match whence {
            SEEK_SET => 0i64,
            SEEK_CUR => entry.offset as i64,
            SEEK_END => entry.ops.stat().size as i64,
            _        => return Some(SyscallReturn::invalid_op()),
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
        _             => ctx.set_return(SyscallReturn::invalid_op()),
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
    let ptr  = args.arg0 as *const u8;
    let len  = args.arg1 as usize;
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
        Err(_) => { ctx.set_return(fail); return; }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(path, |_fs, parent, leaf| parent.unlink(leaf));
    match outcome {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        _            => ctx.set_return(fail),
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
    let ptr  = args.arg0 as *const u8;
    let len  = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user pointer in active AS, length-bounded.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let path = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => { ctx.set_return(fail); return; }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(path, |_fs, parent, leaf| parent.mkdir(leaf));
    match outcome {
        Some(Ok(_)) => ctx.set_return(SyscallReturn::ok(0)),
        _           => ctx.set_return(fail),
    }
}

fn sys_rmdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr  = args.arg0 as *const u8;
    let len  = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr.is_null() || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: user pointer in active AS, length-bounded.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let path = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => { ctx.set_return(fail); return; }
    };
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(path, |_fs, parent, leaf| parent.rmdir(leaf));
    match outcome {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        _            => ctx.set_return(fail),
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
        Err(_) => { ctx.set_return(fail); return; }
    };
    let new_path = match core::str::from_utf8(new_bytes) {
        Ok(s) => s,
        Err(_) => { ctx.set_return(fail); return; }
    };
    // Both paths must split into the same parent directory — cross-
    // directory rename isn't supported by the DirOps surface today
    // (would need a registry-aware version that locks both parents).
    let old_split = match old_path.rfind('/') {
        Some(i) => i,
        None    => { ctx.set_return(fail); return; }
    };
    let new_split = match new_path.rfind('/') {
        Some(i) => i,
        None    => { ctx.set_return(fail); return; }
    };
    if &old_path[..old_split] != &new_path[..new_split] {
        ctx.set_return(fail);
        return;
    }
    let new_leaf = &new_path[new_split + 1..];
    let outcome = narf_filesystem::registry()
        .resolve_parent_absolute(old_path, |_fs, parent, old_leaf| {
            parent.rename(old_leaf, new_leaf)
        });
    match outcome {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        _            => ctx.set_return(fail),
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
    let path_ptr  = args.arg0 as *const u8;
    let path_len  = args.arg1 as usize;
    let cursor    = args.arg2 as usize;
    let out_ptr   = args.arg3 as *mut u8;
    let out_len   = args.arg4 as usize;
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
        Err(_) => { ctx.set_return(fail); return; }
    };

    // Resolve to a DirOps. Empty path or root → use the FS root
    // directly; otherwise descend through `lookup_dir`.
    let entries = narf_filesystem::registry().resolve_absolute(path, |fs, rel| {
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
    }).flatten();

    let entries = match entries {
        Some(v) => v,
        None    => { ctx.set_return(fail); return; }
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
        narf_filesystem::FileType::File    => 0,
        narf_filesystem::FileType::Dir     => 1,
        narf_filesystem::FileType::Symlink => 2,
        narf_filesystem::FileType::Special => 3,
    };
    // SAFETY: out_ptr is a user-supplied writable region of `out_len`
    // bytes; `total <= out_len` per the bounds check above. Use
    // write_unaligned because user buffers may not be u32-aligned.
    unsafe {
        core::ptr::write_unaligned(out_ptr as *mut u32, name_bytes.len() as u32);
        core::ptr::write_unaligned(out_ptr.add(4) as *mut u32, ftype_wire);
        core::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            out_ptr.add(8),
            name_bytes.len(),
        );
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}

// ── Close — arg0=fd ────────────────────────────────────────────────

fn sys_close(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
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
static MMAP_CURSOR: AtomicU64 = AtomicU64::new(0x0000_4080_0000_0000);

fn sys_mmap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let len  = ((args.arg1 as u64 + 0xFFF) & !0xFFFu64).max(0x1000);
    let as_ref = match current_address_space() {
        Some(a) => a,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };

    // Pick a fresh user virt by bumping the cursor.
    let pages = len >> 12;
    let base  = MMAP_CURSOR.fetch_add(len, Ordering::Relaxed);

    // Allocate one frame per page and zero each. The freelist returns
    // frames out of order so we collect into a per-page scatter list.
    let mut phys_list: alloc::vec::Vec<narf_memory::PhysAddr> =
        alloc::vec::Vec::with_capacity(pages as usize);
    for _ in 0..pages {
        let p = match narf_memory::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => { ctx.set_return(SyscallReturn::invalid_op()); return; }
        };
        // SAFETY: identity-mapped in low 4 GiB; phys is page-aligned.
        unsafe { core::ptr::write_bytes(p.raw() as *mut u8, 0, 4096); }
        phys_list.push(p);
    }

    // Install + materialise.
    if as_ref.map_region(Region {
        base:  VirtAddr::new(base),
        len,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  phys_list,
    }).is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    ctx.set_return(SyscallReturn::ok(base));
}

// ── Munmap — arg0=base ─────────────────────────────────────────────

fn sys_munmap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    let base = VirtAddr::new(args.arg0);
    match as_ref.unmap_region(base) {
        Ok(_)  => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}

// ── ExitTask — redirect to a kernel-registered landing ─────────────

fn sys_exit_task(ctx: &mut dyn TrapContext) {
    // Polling-future path: if a UserTaskCtx is installed AND an
    // exit hook is registered, save the user state, mark the
    // reason, and tail-call the hook — which longjmps back into
    // the polling routine.
    if let (Some(uctx), Some(hook)) =
        (crate::user_task::current_user_task(), crate::user_task::exit_hook())
    {
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
    if let (Some(uctx), Some(hook)) =
        (crate::user_task::current_user_task(), crate::user_task::yield_hook())
    {
        // SAFETY: same contract as sys_exit_task's hook path.
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            hook(uctx);
        }
        // unreachable
    }
    // Legacy: no polling executor wired yet — Yield is a no-op Ok.
    ctx.set_return(SyscallReturn::ok(0));
}

// ── RingKick — drain the shared SQ, post completions to the CQ ────
//
// Slow-path counterpart to a UIPI/UMWAIT-driven async dispatcher.
// User code submits + calls `RingKick` + spins on the CQ until the
// real wake side-channel lands.

fn sys_ring_kick(ctx: &mut dyn TrapContext) {
    use narf_abi::{
        FileOpArgs, FileOpKind, NarfStatus, OpCode, SharedConsumer,
        SharedProducer,
    };

    type SqRing = SharedRing<Submission, BOOTSTRAP_SHARED_RING_DEPTH>;
    type CqRing = SharedRing<Completion, BOOTSTRAP_SHARED_RING_DEPTH>;

    let task = current_task_id();
    let pair = match shared_rings_for(task) {
        Some(p) => p,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };

    // SAFETY: per-task BOOTSTRAP_TABLE owns the phys backings; only
    // one ring-kick can run at a time per task because it executes
    // synchronously inside this task's syscall trap.
    let mut sq = unsafe {
        SharedConsumer::<Submission, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.sq_phys.raw() as *mut SqRing,
        )
    };
    let mut cq = unsafe {
        SharedProducer::<Completion, BOOTSTRAP_SHARED_RING_DEPTH>::from_raw(
            pair.cq_phys.raw() as *mut CqRing,
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
            OpCode::OpenFile | OpCode::Read | OpCode::Write
                | OpCode::Close | OpCode::Mmap | OpCode::Munmap => {
                let kind = match sub.op {
                    OpCode::OpenFile => FileOpKind::Open,
                    OpCode::Read     => FileOpKind::Read,
                    OpCode::Write    => FileOpKind::Write,
                    OpCode::Close    => FileOpKind::Close,
                    OpCode::Mmap     => FileOpKind::Mmap,
                    OpCode::Munmap   => FileOpKind::Munmap,
                    _ => unreachable!(),
                };
                let args = FileOpArgs {
                    a0: sub.inline[0], a1: sub.inline[1], a2: sub.inline[2],
                    a3: sub.inline[3], a4: sub.inline[4], a5: sub.inline[5],
                };
                let r = abi_file_op_bridge(kind, &args);
                let status = if r.status == 0 { NarfStatus::Ok } else { NarfStatus::InvalidOp };
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

// ── Yield / Sleep — Ok ─────────────────────────────────────────────

fn sys_noop_ok(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Sleep — spin-wait until monotonic_ns advances by arg0 ─────────
//
// `Syscall::Sleep` carries the requested sleep in nanoseconds in
// `arg0`. Stage-4 first cut: spin on `core::hint::spin_loop()` until
// the kernel's monotonic clock has advanced by at least the requested
// span. Why a spin and not a Future:
//
//   - Syscall handlers run inside a CPU trap, not as a scheduler
//     task, so there's no `.await` we can use to yield. The trap
//     context has a single linear flow ending in `iretq` back to user.
//   - A real `nanosleep` would suspend the calling task on a timer
//     wheel and let the scheduler park the CPU. That requires the
//     polling-future "trap-as-future" model from c85cb9f to be live
//     for arbitrary user tasks, not just the testbin/validate
//     trampolines. Until that lands every sleep handler fundamentally
//     blocks the calling CPU.
//
// The handler is correct for now (it does sleep for the requested
// duration) but pessimal for throughput. The follow-up is to route
// Sleep through `narf_time::sleep_cycles` once every user task is
// itself a polling future.
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
static GETRANDOM_STATE: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0);

fn next_random_u32() -> u32 {
    use core::sync::atomic::Ordering;
    let mut s = GETRANDOM_STATE.load(Ordering::Relaxed);
    if s == 0 {
        // Lazy seed from monotonic_ns mixed with the cycle counter
        // so two boots see different streams.
        let ns = narf_scheduler::narf_time::monotonic_ns();
        let cy = narf_scheduler::narf_time::now_cycles();
        s = (ns ^ cy.wrapping_mul(0x9E37_79B9_7F4A_7C15)) & 0x7FFF_FFFF;
        if s == 0 { s = 1; }
    }
    // x' = x * 48271 mod (2^31 - 1)
    s = (s.wrapping_mul(48271)) % 0x7FFF_FFFF;
    GETRANDOM_STATE.store(s, Ordering::Relaxed);
    s as u32
}

fn sys_getrandom(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr  = args.arg0 as *mut u8;
    let len  = args.arg1 as usize;
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
            core::ptr::write_volatile(ptr.add(i)     , (v        & 0xFF) as u8);
            core::ptr::write_volatile(ptr.add(i + 1), ((v >> 8)  & 0xFF) as u8);
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
    // Saturating add: a u64 overflow on `start + ns` is structurally
    // impossible at realistic clock rates, but the saturate keeps
    // the loop bound tight against pathological inputs.
    let deadline = start.saturating_add(ns);
    while narf_scheduler::narf_time::monotonic_ns() < deadline {
        core::hint::spin_loop();
    }
    ctx.set_return(SyscallReturn::ok(0));
}

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

static CWD_TABLE:
    narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, alloc::string::String>>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task cwd registry. Boot calls this once
/// before any user task can issue `Syscall::Chdir` / `Getcwd`.
pub fn cwd_init() {
    *CWD_TABLE.lock() = Some(BTreeMap::new());
}

/// Reset the registry — test hook. Drops every per-task entry.
#[doc(hidden)]
pub fn __test_cwd_reset() { *CWD_TABLE.lock() = None; }

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
    let ptr  = args.arg0 as *const u8;
    let len  = args.arg1 as usize;
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
        Err(_) => { ctx.set_return(fail); return; }
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
        None    => { ctx.set_return(fail); return; }
    };
    map.insert(task, alloc::string::String::from(path));
    ctx.set_return(SyscallReturn::ok(0));
}

fn sys_getcwd(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf  = args.arg0 as *mut u8;
    let len  = args.arg1 as usize;
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
// the heap allocates frames + maps them R+W; shrinking is a Stage-4
// TODO — we just lower the recorded break without unmapping so the
// physical pages leak until the task exits. POSIX brk's failure
// contract is "return the unchanged break", so allocation/mapping
// failure is silent: we just hand back the current value.

/// Default per-task heap base. Far enough from the mmap cursor and
/// the user stack to leave room for both to grow without colliding
/// with the brk arena.
const BRK_DEFAULT_BASE: u64 = 0x0000_5000_0000_0000;

static BRK_TABLE: narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u64>>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task brk registry. Boot calls this once before
/// any user task can issue `Syscall::Brk`.
pub fn brk_init() {
    *BRK_TABLE.lock() = Some(BTreeMap::new());
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_brk_reset() { *BRK_TABLE.lock() = None; }

fn sys_brk(ctx: &mut dyn TrapContext) {
    let new_break = ctx.args().arg0;
    let task = current_task_id();

    // Snapshot the current break (initialising the slot on first call).
    let cur = {
        let mut g = BRK_TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None    => { ctx.set_return(SyscallReturn::ok(0)); return; }
        };
        *map.entry(task).or_insert(BRK_DEFAULT_BASE)
    };

    // Query path: arg0 == 0 just returns the current break.
    if new_break == 0 {
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }

    // Shrink path: lower the recorded break without unmapping. TODO:
    // Stage-4 follow-up to actually unmap shrunken pages so the phys
    // frames return to the allocator.
    if new_break < cur {
        BRK_TABLE.lock().as_mut().expect("brk_init").insert(task, new_break);
        ctx.set_return(SyscallReturn::ok(new_break));
        return;
    }

    // Grow path: page-align both ends, allocate + map every fresh page
    // R+W into the calling task's AS. Any failure rolls the break
    // back to `cur` (POSIX brk failure contract).
    let as_ref = match current_address_space() {
        Some(a) => a,
        None    => { ctx.set_return(SyscallReturn::ok(cur)); return; }
    };
    let cur_aligned = (cur + 0xFFF) & !0xFFFu64;
    let new_aligned = (new_break + 0xFFF) & !0xFFFu64;
    let mut va = cur_aligned;
    while va < new_aligned {
        let phys = match narf_memory::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => {
                ctx.set_return(SyscallReturn::ok(cur));
                return;
            }
        };
        // SAFETY: identity-mapped low 4 GiB; phys is page-aligned.
        unsafe { core::ptr::write_bytes(phys.raw() as *mut u8, 0, 0x1000); }
        if as_ref.map_region(Region {
            base:  VirtAddr::new(va),
            len:   0x1000,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys:  alloc::vec![phys],
        }).is_err() {
            ctx.set_return(SyscallReturn::ok(cur));
            return;
        }
        va += 0x1000;
    }
    if unsafe { as_ref.materialize() }.is_err() {
        ctx.set_return(SyscallReturn::ok(cur));
        return;
    }

    BRK_TABLE.lock().as_mut().expect("brk_init").insert(task, new_break);
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

const CLOCK_REALTIME:  u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;

fn sys_clock_gettime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id   = args.arg0;
    let buf  = args.arg1;
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

static SIGNAL_PENDING:
    narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

static SIGNAL_MASK:
    narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, u32>>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task pending+mask registries. Pair with
/// `sigaction_init` at boot.
pub fn signal_init() {
    *SIGNAL_PENDING.lock() = Some(BTreeMap::new());
    *SIGNAL_MASK.lock()    = Some(BTreeMap::new());
}

/// Reset the registries — test hook. Drops every per-task entry.
#[doc(hidden)]
pub fn __test_signal_reset() {
    *SIGNAL_PENDING.lock() = None;
    *SIGNAL_MASK.lock()    = None;
}

/// Diagnostic: peek the pending bitmap for `task`.
pub fn signal_pending_of(task: u64) -> u32 {
    SIGNAL_PENDING.lock().as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or(0)
}

/// Diagnostic: peek the block mask for `task`.
pub fn signal_mask_of(task: u64) -> u32 {
    SIGNAL_MASK.lock().as_ref()
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
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    let slot = map.entry(target).or_insert(0);
    *slot |= 1u32 << signum;
    ctx.set_return(SyscallReturn::ok(0));
}

const SIG_BLOCK:   u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

fn sys_sigprocmask(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let how  = args.arg0 as u32;
    let set  = args.arg1 as u32;
    let task = current_task_id();
    let mut g = SIGNAL_MASK.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    let slot = map.entry(task).or_insert(0);
    let prior = *slot;
    *slot = match how {
        SIG_BLOCK   => prior | set,
        SIG_UNBLOCK => prior & !set,
        SIG_SETMASK => set,
        _           => {
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

static SIGNAL_DELIVERY_HOOK:
    narf_lib::sync::IrqSafeSpinLock<Option<SignalDeliveryHook>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

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
    if !ctx.returning_to_user() { return; }
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
    let mask = SIGNAL_MASK.lock().as_ref()
        .and_then(|m| m.get(&task).copied()).unwrap_or(0);
    let deliverable = pending & !mask;
    if deliverable == 0 { return; }
    let signum = deliverable.trailing_zeros();
    let handler = match sigaction_lookup(task, signum as usize) {
        Some(h) => h,
        None    => return,
    };
    if !ctx.deliver_signal(handler, signum) { return; }
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
const SIGILL:  u32 = 4;
const SIGTRAP: u32 = 5;
const SIGBUS:  u32 = 7;
const SIGFPE:  u32 = 8;
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
        0  => Some(SIGFPE),  // #DE divide-by-zero / div overflow
        3  => Some(SIGTRAP), // #BP breakpoint
        4  => Some(SIGFPE),  // #OF overflow
        6  => Some(SIGILL),  // #UD undefined opcode
        13 => Some(SIGSEGV), // #GP general protection
        14 => Some(SIGSEGV), // #PF page fault
        17 => Some(SIGBUS),  // #AC alignment check
        _  => None,
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

static SYNC_SIGNAL_HOOK:
    narf_lib::sync::IrqSafeSpinLock<Option<SyncSignalHook>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

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
        None    => return false,
    };
    let task = current_task_id();
    let handler = match sigaction_lookup(task, signum as usize) {
        Some(h) => h,
        None    => return false,
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

static SIGACTION_TABLE:
    narf_lib::sync::IrqSafeSpinLock<Option<BTreeMap<u64, [Option<u64>; NSIG]>>>
    = narf_lib::sync::IrqSafeSpinLock::new(None);

/// Initialise the per-task sigaction registry. Boot calls this once
/// before any user task can issue `Syscall::Sigaction`.
pub fn sigaction_init() {
    *SIGACTION_TABLE.lock() = Some(BTreeMap::new());
}

/// Reset the registry — test hook.
#[doc(hidden)]
pub fn __test_sigaction_reset() { *SIGACTION_TABLE.lock() = None; }

/// Diagnostic: peek the recorded handler for `(task, signum)`.
pub fn sigaction_lookup(task: u64, signum: usize) -> Option<u64> {
    let g = SIGACTION_TABLE.lock();
    let map = g.as_ref()?;
    let slots = map.get(&task)?;
    if signum >= NSIG { return None; }
    slots[signum]
}

fn sys_sigaction(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let signum     = args.arg0 as usize;
    let new_handler = args.arg1;
    let old_out    = args.arg2;
    if signum >= NSIG {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let task = current_task_id();

    let prior = {
        let mut g = SIGACTION_TABLE.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
        };
        let slots = map.entry(task).or_insert([None; NSIG]);
        let prior = slots[signum];
        slots[signum] = if new_handler == 0 { None } else { Some(new_handler) };
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
/// the int-0x80 / svc gate uses.
pub fn abi_file_op_bridge(
    kind: narf_abi::FileOpKind,
    args: &narf_abi::FileOpArgs,
) -> narf_abi::FileOpReturn {
    let num: u32 = match kind {
        narf_abi::FileOpKind::Open   => Syscall::OpenFile.raw(),
        narf_abi::FileOpKind::Read   => Syscall::Read.raw(),
        narf_abi::FileOpKind::Write  => Syscall::Write.raw(),
        narf_abi::FileOpKind::Close  => Syscall::Close.raw(),
        narf_abi::FileOpKind::Mmap   => Syscall::Mmap.raw(),
        narf_abi::FileOpKind::Munmap => Syscall::Munmap.raw(),
    };
    let sargs = crate::SyscallArgs {
        arg0: args.a0, arg1: args.a1, arg2: args.a2,
        arg3: args.a3, arg4: args.a4, arg5: args.a5,
    };
    // Plain entry only fires plain handlers; our file ops are
    // raw. Build a synthetic `TrapContext` whose
    // `redirect_to_kernel` returns false (so handlers that would
    // unwind fall back to `set_return`), then route through
    // `kernel_syscall_entry`.
    struct BridgeCtx { args: crate::SyscallArgs, ret: crate::SyscallReturn }
    impl crate::TrapContext for BridgeCtx {
        fn args(&self) -> &crate::SyscallArgs { &self.args }
        fn set_return(&mut self, r: crate::SyscallReturn) { self.ret = r; }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool { false }
    }
    let mut ctx = BridgeCtx { args: sargs, ret: crate::SyscallReturn::invalid_op() };
    crate::kernel_syscall_entry(num, &mut ctx);
    narf_abi::FileOpReturn { status: ctx.ret.status, value: ctx.ret.value }
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
    table.install_raw(Syscall::OpenFile, "open",     RawFnHandler(sys_open));
    table.install_raw(Syscall::Write,    "write",    RawFnHandler(sys_write));
    table.install_raw(Syscall::Read,     "read",     RawFnHandler(sys_read));
    table.install_raw(Syscall::Close,    "close",    RawFnHandler(sys_close));
    table.install_raw(Syscall::Mmap,     "mmap",     RawFnHandler(sys_mmap));
    table.install_raw(Syscall::Munmap,   "munmap",   RawFnHandler(sys_munmap));
    table.install_raw(Syscall::RingKick, "ringkick", RawFnHandler(sys_ring_kick));
    table.install_raw(Syscall::GetPid,   "getpid",   RawFnHandler(sys_getpid));
    table.install_raw(Syscall::GetPpid,  "getppid",  RawFnHandler(sys_getppid));
    table.install_raw(Syscall::GetUid,   "getuid",   RawFnHandler(sys_noop_ok));
    table.install_raw(Syscall::GetGid,   "getgid",   RawFnHandler(sys_noop_ok));
    table.install_raw(Syscall::ExitTask, "exit",     RawFnHandler(sys_exit_task));
    table.install_raw(Syscall::Yield,    "yield",    RawFnHandler(sys_yield));
    table.install_raw(Syscall::Sleep,    "sleep",    RawFnHandler(sys_sleep));
    table.install_raw(Syscall::Brk,          "brk",           RawFnHandler(sys_brk));
    table.install_raw(Syscall::ClockGetTime, "clock_gettime", RawFnHandler(sys_clock_gettime));
    table.install_raw(Syscall::Sigaction,    "sigaction",     RawFnHandler(sys_sigaction));
    table.install_raw(Syscall::Kill,         "kill",          RawFnHandler(sys_kill));
    table.install_raw(Syscall::Sigprocmask,  "sigprocmask",   RawFnHandler(sys_sigprocmask));

    // Tier-2 fd-table breadth + path-resolution + pipe(2).
    table.install_raw(Syscall::Dup,    "dup",    RawFnHandler(sys_dup));
    table.install_raw(Syscall::Dup2,   "dup2",   RawFnHandler(sys_dup2));
    table.install_raw(Syscall::Dup3,   "dup3",   RawFnHandler(sys_dup3));
    table.install_raw(Syscall::Fcntl,  "fcntl",  RawFnHandler(sys_fcntl));
    table.install_raw(Syscall::Stat,   "stat",   RawFnHandler(sys_stat));
    table.install_raw(Syscall::Fstat,  "fstat",  RawFnHandler(sys_fstat));
    table.install_raw(Syscall::Pipe,   "pipe",   RawFnHandler(sys_pipe));

    // Tier-2 cwd state + nanosleep wired into the table. Sleep
    // already replaced the noop_ok stub above.
    table.install_raw(Syscall::Chdir,  "chdir",  RawFnHandler(sys_chdir));
    table.install_raw(Syscall::Getcwd, "getcwd", RawFnHandler(sys_getcwd));
    table.install_raw(Syscall::Lseek,  "lseek",  RawFnHandler(sys_lseek));
    table.install_raw(Syscall::Unlink, "unlink", RawFnHandler(sys_unlink));
    table.install_raw(Syscall::Mkdir,  "mkdir",  RawFnHandler(sys_mkdir));
    table.install_raw(Syscall::Rmdir,  "rmdir",  RawFnHandler(sys_rmdir));
    table.install_raw(Syscall::Rename, "rename", RawFnHandler(sys_rename));
    table.install_raw(Syscall::Listdir, "listdir", RawFnHandler(sys_listdir));

    // Tier-3z entropy.
    table.install_raw(Syscall::GetRandom, "getrandom", RawFnHandler(sys_getrandom));

    // Auto-wire both delivery hooks so any kernel that uses
    // `install_core_syscalls` gets the async + sync signal paths
    // on for free. Idempotent.
    install_signal_delivery_hook(default_signal_delivery);
    install_sync_signal_hook(default_sync_signal_delivery);
}
