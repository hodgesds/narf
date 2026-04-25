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

use narf_console::Writer;
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
const ABI_BOOTSTRAP_VERSION: u32 = 2;
/// Ring depth NARF bootstraps. Powers-of-two only per `narf-ipc`.
/// 64 mirrors what the existing dispatcher tests use.
const BOOTSTRAP_RING_DEPTH: u64 = 64;

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
    completion_channel, submission_channel, CompletionDrain, CompletionQueue,
    SubmissionDrain, SubmissionQueue,
};

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

#[derive(Debug)]
#[allow(dead_code)]  // fields read by the future dispatcher integration
struct PerTaskBootstrap {
    kernel:     TaskRings,
    user:       UserRingEnds,
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
        sq_cap_id: entry.sq_cap_id,
        cq_cap_id: entry.cq_cap_id,
    });
    Some(entry.kernel)
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
        phys,
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

    let entry = PerTaskBootstrap {
        kernel: TaskRings { sq_drain, cq_prod },
        user:   UserRingEnds { sq_prod, cq_drain },
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
    }

    ctx.set_return(SyscallReturn::ok(user_vaddr));
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

fn sys_open(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_ptr = args.arg0 as *const u8;
    let path_len = args.arg1 as usize;
    let mnt_ptr  = args.arg2 as *const u8;
    let mnt_len  = args.arg3 as usize;
    if path_ptr.is_null() || path_len == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // SAFETY: user pointers in active AS, length-bounded.
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => { ctx.set_return(SyscallReturn::invalid_op()); return; }
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
            Err(_) => { ctx.set_return(SyscallReturn::invalid_op()); return; }
        };
        narf_filesystem::registry().with_mount(mount, |fs| {
            narf_filesystem::resolve(fs.root(), path).ok()
        }).flatten()
    };

    let ops = match ops {
        Some(o) => o,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };

    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry { ops, offset: 0 })
    }) {
        Some(n) => n,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
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

    if fd == 1 || fd == 2 {
        use core::fmt::Write as _;
        let mut w = Writer;
        for &b in slice {
            let _ = w.write_char(b as char);
        }
        ctx.set_return(SyscallReturn::ok(len as u64));
        return;
    }

    // Look up the fd in the calling task's table, advance the
    // offset, return bytes-written.
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

    // Allocate contiguous frames (Stage-4 simplification; real
    // Mmap uses scattered pages with demand-paging).
    let first_phys = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    for _ in 1..pages {
        if narf_memory::alloc_frame().is_err() {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    }

    // Zero the allocated region.
    // SAFETY: identity-mapped in low 4 GiB.
    unsafe {
        core::ptr::write_bytes(first_phys.raw() as *mut u8, 0, len as usize);
    }

    // Install + materialise.
    if as_ref.map_region(Region {
        base:  VirtAddr::new(base),
        len,
        perms: RegionPerms::READ | RegionPerms::WRITE,
        phys:  first_phys,
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

// ── Yield / Sleep — Ok ─────────────────────────────────────────────

fn sys_noop_ok(ctx: &mut dyn TrapContext) {
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
    table.install_raw(Syscall::ExitTask, "exit",     RawFnHandler(sys_exit_task));
    table.install_raw(Syscall::Yield,    "yield",    RawFnHandler(sys_noop_ok));
    table.install_raw(Syscall::Sleep,    "sleep",    RawFnHandler(sys_noop_ok));
}
