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

use narf_console::Writer;
use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};

use crate::{
    RawFnHandler, Syscall, SyscallReturn, SyscallTable, TrapContext,
};

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

// ── Write — arg0=fd, arg1=buf, arg2=len ────────────────────────────

fn sys_write(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg1 as *const u8;
    let len = args.arg2 as usize;
    if ptr.is_null() || len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // SAFETY: `ptr` is a user-mode virt address; the current AS is
    // still active (trap didn't swap CR3) so the walk resolves. We
    // read length-bounded. The user could racily unmap via another
    // thread, but we don't have multi-threaded user tasks yet.
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    use core::fmt::Write as _;
    let mut w = Writer;
    for &b in slice {
        let _ = w.write_char(b as char);
    }
    ctx.set_return(SyscallReturn::ok(len as u64));
}

// ── Read — noop ────────────────────────────────────────────────────

fn sys_read(ctx: &mut dyn TrapContext) {
    // Stage-4+ wires to VFS; for now EOF.
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Close — noop ───────────────────────────────────────────────────

fn sys_close(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}

// ── Mmap — arg0=hint, arg1=len, arg2=flags ─────────────────────────

static MMAP_CURSOR: AtomicU64 = AtomicU64::new(0x0000_0050_0000_0000);

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

/// Drop the core set of handlers into `table`. Idempotent — later
/// subsystems can install richer handlers over the same slots
/// (e.g. a real file-descriptor-backed `Read`).
pub fn install_core_syscalls(table: &mut SyscallTable) {
    table.install_raw(Syscall::Write,    "write",    RawFnHandler(sys_write));
    table.install_raw(Syscall::Read,     "read",     RawFnHandler(sys_read));
    table.install_raw(Syscall::Close,    "close",    RawFnHandler(sys_close));
    table.install_raw(Syscall::Mmap,     "mmap",     RawFnHandler(sys_mmap));
    table.install_raw(Syscall::Munmap,   "munmap",   RawFnHandler(sys_munmap));
    table.install_raw(Syscall::ExitTask, "exit",     RawFnHandler(sys_exit_task));
    table.install_raw(Syscall::Yield,    "yield",    RawFnHandler(sys_noop_ok));
    table.install_raw(Syscall::Sleep,    "sleep",    RawFnHandler(sys_noop_ok));
}
