//! In-kernel tests of the Reverie backend (subsystem `reverie-narf`).
//!
//! Each test runs one real x86_64 Linux guest ELF as a scheduled user task
//! under Narf's live syscall dispatcher with an interceptor installed, and
//! inspects what the hosted Tool and the kernel reported once every task of
//! the guest has been reaped.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use narf_console::Writer;
use narf_filesystem::{FileOps, FsError, FsFuture, Stat};
use narf_kernel_test::{KernelTest, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, PhysAddr, RegionPerms};
use narf_scheduler::{Affinity, CpuId, TaskSpec};
use narf_userspace::handlers::tool_view;
use narf_userspace::syscall::{
    NativeSyscallOriginalError, NativeSyscallOutcome, NativeSyscallRequest,
    NativeSyscallTransition, SyscallInterception, SyscallInterceptor, SyscallInvocation,
    SyscallReturn,
};
use reverie::syscalls::{Addr, MemoryAccess, Sysno};
use reverie::{Pid, Tool};
use reverie_narf_core::{KernelServices, NarfSyscallOutcome, OriginalSyscallError};
use reverie_narf_tools::canonical::CanonicalTrace;
use reverie_narf_tools::chaos;
use reverie_narf_tools::counter1::CounterLocal;
use reverie_narf_tools::counter2;
use reverie_narf_tools::passthrough::PassThrough;
use reverie_narf_tools::probe::Probe;
use reverie_narf_tools::strace;

use crate::interceptor::{ConsoleSink, ReverieInterceptor, TaskExitRecord};
use crate::services::{map_native_outcome, NarfKernelServices};

static CANONICAL_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_CANONICAL"));
static PROBE_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_PROBE"));
static FORK_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_FORK"));
static PIPE_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_PIPE"));
static EXEC_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_EXEC"));
static VFORK_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_VFORK"));
static RING_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_RING"));
static BADFRAME_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_BADFRAME"));
static REAPER_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_REAPER"));
static VDSO_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_VDSO"));
static MTEXIT_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_MTEXIT"));

/// The single argument every guest is started with, as Linux starts a program
/// with `argv[0]`. A non-empty argv makes the loader lay out the full SysV
/// startup stack, auxiliary vector included.
const GUEST_ARGV: [&str; 1] = ["reverie-narf-guest"];

/// Address of the canonical guest's 16-byte message (its `.rodata`).
const CANONICAL_MESSAGE_ADDR: u64 = 0x0000_0080_0000_3000;
const CANONICAL_MESSAGE: &[u8; 16] = b"narf-hermit-poc\n";
/// The canonical guest's text segment.
const CANONICAL_TEXT: core::ops::Range<u64> = 0x0000_0080_0000_2000..0x0000_0080_0000_3000;
const LINUX_WRITE: u32 = 1;

/// About 10 s at 3 GHz, as in the neighbouring scheduled-user smokes.
const WAITER_BUDGET_CYCLES: u64 = 30_000_000_000;

/// The run's root task.
#[derive(Clone, Copy)]
struct Root {
    task_id: u64,
    pid: u64,
}

/// Linux `SIGCHLD`, the exit signal a `fork` child raises in its parent. The
/// root of a reaped run is published as the reaping parent's child with it, so
/// that parent's plain `wait4(-1, &status, 0, NULL)` reaps it.
const LINUX_SIGCHLD: u8 = 17;
/// Linux `__WALL`: wait for a child whatever its exit signal. Used by the
/// post-run check that the reaping parent has no reapable child left.
const LINUX_WALL: u32 = 0x4000_0000;
/// Linux `ECHILD`.
const LINUX_ECHILD: i64 = 10;
/// The reaping-parent guest stores this in its status word before `wait4`.
const REAPER_STATUS_SENTINEL: i32 = 0xdead_beef_u32 as i32;
/// Length of the reaping-parent guest's report (see `guests/reaper_x86_64.S`).
const REAPER_REPORT_LEN: usize = 16;

/// How the run's root ended, as its reaping parent saw it.
///
/// The parent is a second guest process, `REAPER_GUEST`, which the Tool does
/// not host. It reaps the root with the kernel's own `wait4`, and the kernel
/// copies the wait status into the parent's memory; the parent then writes
/// what it received to its fd 1, which a capture-only [`StdoutTap`] records.
#[derive(Clone, Copy)]
struct RootReap {
    /// The reaping parent's identity.
    parent: Root,
    /// What the parent's `wait4(-1, &status, 0, NULL)` returned.
    reaped_pid: i64,
    /// The status word that `wait4` stored in the parent's memory.
    wstatus: i32,
    /// What the parent's second `wait4` returned: `-ECHILD` once its only
    /// child has been reaped.
    second_wait: i64,
    /// The termination status staged for the root when its exit was
    /// announced, read without consuming it; `None` if nothing was staged.
    staged: Option<i32>,
    /// The same for the reaping parent's own exit.
    parent_staged: Option<i32>,
}

impl RootReap {
    /// The root's wait status, once the reaping parent's report shows that its
    /// `wait4` reaped the root and stored a status, that nothing else was left
    /// to reap, that the parent itself exited 0, and that the status equals
    /// the termination staged at the root's exit.
    ///
    /// The canonical-trace cell makes the same checks inline, interleaved
    /// with the lines it prints for the external comparator.
    fn root_wstatus(&self, root: Root) -> Result<i32, &'static str> {
        if self.reaped_pid != root.pid as i64 {
            let _ = writeln!(
                Writer,
                "    reaping parent's wait4 returned {}",
                self.reaped_pid
            );
            return Err("the reaping parent's wait4 did not return the root's pid");
        }
        if self.wstatus == REAPER_STATUS_SENTINEL {
            return Err("the reaping parent's wait4 reaped the root but stored no status");
        }
        if self.second_wait != -LINUX_ECHILD {
            let _ = writeln!(Writer, "    second wait4 returned {}", self.second_wait);
            return Err("the reaping parent's second wait4 did not report ECHILD");
        }
        if self.parent_staged != Some(0) {
            let _ = writeln!(Writer, "    reaping parent staged {:?}", self.parent_staged);
            return Err("the reaping parent did not exit 0");
        }
        if self.parent.pid == root.pid {
            return Err("the reaping parent and the root share a pid");
        }
        if self.staged != Some(self.wstatus) {
            let _ = writeln!(Writer, "    staged termination {:?}", self.staged);
            return Err("the reaped wait status differs from the termination staged at exit");
        }
        Ok(self.wstatus)
    }
}

/// Sentinels for the staged-termination slots, outside the `i32` range.
const NOT_SEEN: i64 = i64::MIN;
const NOTHING_STAGED: i64 = i64::MIN + 2;
/// The pids whose staged terminations [`record_staged_terminations`] reads.
static ROOT_WATCH: AtomicU64 = AtomicU64::new(0);
static ROOT_STAGED: AtomicI64 = AtomicI64::new(NOT_SEEN);
static PARENT_WATCH: AtomicU64 = AtomicU64::new(0);
static PARENT_STAGED: AtomicI64 = AtomicI64::new(NOT_SEEN);

/// Checks and removes what the reaping parent left once the run is over.
///
/// The parent's reap drops the root's link and the parent's child count, and
/// charges the root's CPU time to the parent's child-CPU row. Returns the
/// nanoseconds that row held.
fn release_reaping_parent(parent_task: u64, root_pid: u64) -> Result<u64, &'static str> {
    use narf_userspace::handlers::{
        __test_clear_pending_exits, __test_parent_link, account_reaped_child,
    };
    let linked = __test_parent_link(root_pid).is_some();
    let mut status = 0i32;
    let queued =
        narf_userspace::user_task::call_wait_child_check(parent_task, -1, LINUX_WALL, &mut status);
    __test_clear_pending_exits(parent_task);
    // With parent 0 this charges nobody; it drops the row's own CPU entries.
    let charged = account_reaped_child(0, parent_task);
    if linked {
        return Err("the root's link to its reaping parent survived the run");
    }
    if queued != 0 {
        return Err("the reaping parent still had a reapable child after the run");
    }
    if account_reaped_child(0, parent_task) != 0 {
        return Err("the reaping parent's child-CPU row survived teardown");
    }
    Ok(charged)
}

/// Thread-exit observer: reads the staged termination status of the root and
/// of its reaping parent. Thread observers run before the process observer
/// that consumes it for the reap.
fn record_staged_terminations(pid: u64, _tid: u64) {
    for (watch, slot) in [(&ROOT_WATCH, &ROOT_STAGED), (&PARENT_WATCH, &PARENT_STAGED)] {
        if pid == 0 || pid != watch.load(Ordering::Acquire) {
            continue;
        }
        let staged = narf_userspace::handlers::peek_pending_termination(pid)
            .map_or(NOTHING_STAGED, i64::from);
        let _ = slot.compare_exchange(NOT_SEEN, staged, Ordering::AcqRel, Ordering::Acquire);
    }
}

fn staged_of(slot: &AtomicI64, missing: &'static str) -> Result<Option<i32>, &'static str> {
    match slot.load(Ordering::Acquire) {
        NOT_SEEN => Err(missing),
        NOTHING_STAGED => Ok(None),
        status => Ok(Some(status as i32)),
    }
}

/// Wall-clock budget for reclaiming one run after its tasks were reaped.
///
/// Reclaiming a task takes a grace period, and the address-space destructor
/// it runs may retire more, which a later one reclaims. With the guest's
/// tasks on several CPUs, a peer CPU may also be running one of those
/// destructors at the moment this CPU checks: a space's `Weak` count reads 0
/// as soon as its `Drop` starts, and the COW counts of its frames fall while
/// `Drop` runs. So the budget is time, not a count of grace periods, which
/// complete immediately when every peer is idle.
const RECLAIM_BUDGET_NS: u64 = 4_000_000_000;
/// Budget for one grace period.
const RECLAIM_GRACE_PERIOD_NS: u64 = 1_000_000_000;

/// Every distinct address space a task of the current run exited from: the
/// root's and each forked or vforked child's.
static EXITED_SPACES: IrqSafeSpinLock<Vec<Weak<AddressSpace>>> = IrqSafeSpinLock::new(Vec::new());

/// Kernel re-entries (a syscall run by kernel code on a task's behalf while
/// that task's own syscall is still in its interceptor call) the next
/// [`run_guest_with`] expects its guest to make. Every other guest makes
/// none, so any entry that finds its task already holding a spawn hold means
/// a hold outlived its interceptor call. Taken (reset to 0) at the start of
/// each run.
static EXPECTED_KERNEL_REENTRIES: AtomicU64 = AtomicU64::new(0);

/// The CPUs the current run's tasks exited on, one bit per CPU, printed
/// after each run as evidence of where [`ProductionPlacement`] put them.
static EXIT_CPUS: AtomicU64 = AtomicU64::new(0);

/// Thread-exit observer: records the exiting task's address space, which is
/// still the active one while its exit fans out, and the CPU it exits on.
fn record_exiting_space(_pid: u64, _tid: u64) {
    let cpu = narf_lib::percpu::current_cpu();
    if cpu < 64 {
        EXIT_CPUS.fetch_or(1 << cpu, Ordering::AcqRel);
    }
    let Some(space) = narf_scheduler::current_address_space() else {
        return;
    };
    let mut spaces = EXITED_SPACES.lock();
    if !spaces
        .iter()
        .any(|seen| seen.as_ptr() == Arc::as_ptr(&space))
    {
        spaces.push(Arc::downgrade(&space));
    }
}

/// Set by a test whose root execs: its exit then reports the exec'd space, and
/// the loaded image's space is reclaimed without an exit from it.
static ROOT_EXECS: AtomicBool = AtomicBool::new(false);

/// How many distinct address spaces the last successful [`run_guest`] saw
/// tasks exit from, all of which it proved reclaimed.
static RECLAIMED_SPACES: AtomicU64 = AtomicU64::new(0);

fn exited_space_count() -> u64 {
    RECLAIMED_SPACES.load(Ordering::Acquire)
}

/// Waits until nothing of a finished run is left: every address space its
/// tasks exited from has been dropped, and no frame of the root image still
/// has a recorded COW owner.
///
/// A reaped task is not yet reclaimed. The scheduler retires its stackful
/// continuation through RCU, and that continuation owns the future holding the
/// task's address space, so the space outlives the task by one grace period.
/// In the kernel the executor keeps running and its per-round
/// `advance_epoch_if_pending` ends that grace period. `run_until_empty`
/// returns as soon as the run queue drains, so the grace period must be driven
/// here; otherwise the spaces survive into the next test, still sharing COW
/// frames, and any reset of the COW table in between turns their eventual
/// frees into double frees.
fn reclaim_run(spaces: &[Weak<AddressSpace>], frames: &[PhysAddr]) -> Result<(), &'static str> {
    let reclaimed = || {
        spaces.iter().all(|space| space.strong_count() == 0)
            && frames
                .iter()
                .all(|frame| narf_memory::frame::cow::count(*frame) == 0)
    };
    let budget_end = narf_time::monotonic_ns().saturating_add(RECLAIM_BUDGET_NS);
    while !reclaimed() {
        let now = narf_time::monotonic_ns();
        if now >= budget_end {
            return Err(
                "the guest's address spaces or COW frames outlived the reclaim budget after its tasks were reaped",
            );
        }
        let deadline = now.saturating_add(RECLAIM_GRACE_PERIOD_NS).min(budget_end);
        if !narf_rcu::sync_until(deadline) && narf_time::monotonic_ns() < budget_end {
            return Err(
                "an RCU grace period did not elapse within 1 s while reclaiming the guest's address spaces",
            );
        }
    }
    Ok(())
}

/// User-task placement as a production boot sets it up, for the length of
/// one guest run.
///
/// A production boot with application processors online turns on work
/// stealing and user-task SMP (`frame/src/bare_main.rs`, the
/// `enable_work_stealing` / `enable_user_task_smp` block); a kernel-test boot
/// turns on neither, so without this every guest task would run pinned to
/// the boot CPU. With both on, [`TaskSpec::user_task`] prefers the
/// application processors for a new process (either CPU on a two-CPU
/// machine), a fork child goes where `fork_cpu` puts it
/// (`sys_fork.rs`: a fresh `TaskSpec::user_task()`, not the parent's
/// affinity), and idle CPUs steal runnable user tasks. Dropping this puts
/// both switches back as they were, after the run's last task was reaped.
struct ProductionPlacement {
    user_task_smp: bool,
    work_stealing: bool,
}

impl ProductionPlacement {
    fn enable() -> Self {
        let work_stealing = narf_scheduler::work_stealing_enabled();
        narf_scheduler::enable_work_stealing();
        let user_task_smp = narf_scheduler::__test_set_user_task_smp(true);
        Self {
            user_task_smp,
            work_stealing,
        }
    }
}

impl Drop for ProductionPlacement {
    fn drop(&mut self) {
        narf_scheduler::__test_set_user_task_smp(self.user_task_smp);
        if !self.work_stealing {
            narf_scheduler::disable_work_stealing();
        }
    }
}

/// Runs `elf` as a fresh scheduled user process with `interceptor` installed
/// in the live syscall table, until every task it created has been reaped.
/// The guest's tasks are placed as in production ([`ProductionPlacement`]),
/// so they run on any online CPU.
///
/// `register` runs after the root task has its Linux identity and before it
/// is runnable. The root is an orphan, which the kernel releases at exit.
fn run_guest(
    elf: &[u8],
    interceptor: Box<dyn SyscallInterceptor>,
    register: impl FnOnce(Root) -> Result<(), &'static str>,
) -> Result<Root, &'static str> {
    run_guest_with(elf, interceptor, register, None).map(|(root, _)| root)
}

/// [`run_guest`], optionally with a reaping parent.
///
/// With `reaper`, that ELF is loaded as a second process, which the
/// interceptor does not host, and the root is published as its child with
/// exit signal `SIGCHLD` before either runs. The root's exit then queues a
/// wait status for that parent instead of releasing the root, and the parent
/// reaps it with its own `wait4`; the harness only watches both exit. The
/// parent's fd 1 is a capture-only [`StdoutTap`], and what the parent wrote
/// there is decoded into the returned [`RootReap`].
fn run_guest_with(
    elf: &[u8],
    interceptor: Box<dyn SyscallInterceptor>,
    register: impl FnOnce(Root) -> Result<(), &'static str>,
    reaper: Option<&[u8]>,
) -> Result<(Root, Option<RootReap>), &'static str> {
    use narf_userspace::syscall::__verification_clear_global as clear_global;
    use narf_userspace::{install_core_syscalls, install_global, install_task_id_lookup};

    let expected_reentries = EXPECTED_KERNEL_REENTRIES.swap(0, Ordering::AcqRel);
    let cpu = narf_lib::percpu::current_cpu();
    let original_cr3: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe {
        core::arch::asm!("mov {v}, cr3", v = out(reg) original_cr3,
            options(nostack, preserves_flags));
    }
    clear_global();
    narf_userspace::user_task::__test_clear_hooks();
    // Kernel-test boots skip the boot-time userspace init, so install the
    // pieces a forking, reaping guest needs, as the boot path does: the
    // wait/exit bookkeeping (which stages each exit's wait status) with its
    // exit observers, and the current task's address-space lookup.
    narf_userspace::user_task::__test_clear_exit_observers();
    narf_userspace::handlers::__test_wait_reset();
    narf_userspace::handlers::wait_init();
    EXITED_SPACES.lock().clear();
    EXIT_CPUS.store(0, Ordering::Release);
    RECLAIMED_SPACES.store(0, Ordering::Release);
    narf_userspace::user_task::register_thread_exit_observer(record_exiting_space);
    ROOT_WATCH.store(0, Ordering::Release);
    ROOT_STAGED.store(NOT_SEEN, Ordering::Release);
    PARENT_WATCH.store(0, Ordering::Release);
    PARENT_STAGED.store(NOT_SEEN, Ordering::Release);
    if reaper.is_some() {
        narf_userspace::user_task::register_thread_exit_observer(record_staged_terminations);
    }
    let original_as_lookup = narf_userspace::address_space_lookup();
    narf_userspace::install_address_space_lookup(|| {
        narf_scheduler::current_address_space()
            .or_else(|| narf_scheduler::address_space_of(narf_scheduler::current_task_id()))
    });

    let mut table = narf_userspace::SyscallTable::new();
    install_core_syscalls(&mut table);
    if table.install_interceptor(interceptor).is_err() {
        return Err("a fresh syscall table already had an interceptor");
    }
    install_global(table);
    install_task_id_lookup(|| narf_scheduler::current_task_id().raw());
    narf_scheduler::__reset_queues_for_test();
    narf_userspace::install_user_task_hooks();

    let teardown = |original_cr3: u64| {
        // SAFETY: restore the kernel CR3 and kernel-GS state after the user
        // tasks have exited, matching the neighbouring scheduled-user smokes.
        unsafe {
            core::arch::asm!("mov cr3, {value}", value = in(reg) original_cr3,
                options(nostack, preserves_flags));
            const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_KERNEL_GS_BASE,
                in("eax") 0u32,
                in("edx") 0u32,
                options(nostack, preserves_flags),
            );
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        narf_userspace::user_task::__test_clear_hooks();
        narf_userspace::handlers::__test_reset_task_id_lookup();
        narf_userspace::restore_address_space_lookup(original_as_lookup);
        narf_userspace::user_task::__test_clear_exit_observers();
        narf_userspace::handlers::__test_wait_reset();
        clear_global();
    };

    // SAFETY: paging and the frame allocator are live in the kernel-test
    // environment; the image is a complete static ELF.
    let process =
        match unsafe { narf_userspace::load_user_process_with(elf, &GUEST_ARGV, &[], &[]) } {
            Ok(process) => process,
            Err(_) => {
                teardown(original_cr3);
                return Err("the guest ELF failed to load");
            }
        };
    let pid = process.pid.raw();
    let root_space = Arc::downgrade(&process.address_space);
    let root_frames = process
        .address_space
        .regions_snapshot()
        .into_iter()
        .filter(|region| !region.perms.contains(RegionPerms::SHARED))
        // The vDSO code page is a private COW mapping whose masters hold a
        // permanent COW reference (`narf_userspace::vdso`), so its frames
        // never reach a zero count and are not the guest's to reclaim.
        .filter(|region| region.base.as_u64() < narf_userspace::vdso::VDSO_MAP_BASE)
        .flat_map(|region| region.phys)
        .filter(|frame| frame.raw() != 0)
        .collect::<Vec<_>>();
    let live_before = narf_scheduler::live_user_task_count();
    let reentries_before = narf_userspace::user_task::__test_kernel_reentries();
    // Held until the function returns, which is after the run's last task
    // was reaped.
    let _placement = ProductionPlacement::enable();
    let pending =
        narf_userspace::user_task::prepare_user_process_initial(process, TaskSpec::user_task());
    let task_id = pending.task_id().raw();
    narf_userspace::handlers::register_pid_task_mapping(pid, task_id);
    let root = Root { task_id, pid };
    if let Err(reason) = register(root) {
        let _ = narf_userspace::task::release_task(task_id);
        teardown(original_cr3);
        return Err(reason);
    }
    let mut parent = None;
    if let Some(reaper_elf) = reaper {
        // SAFETY: as for the root image above.
        let process = match unsafe {
            narf_userspace::load_user_process_with(reaper_elf, &GUEST_ARGV, &[], &[])
        } {
            Ok(process) => process,
            Err(_) => {
                let _ = narf_userspace::task::release_task(task_id);
                teardown(original_cr3);
                return Err("the reaping-parent guest ELF failed to load");
            }
        };
        let parent_pid = process.pid.raw();
        let parent_pending =
            narf_userspace::user_task::prepare_user_process_initial(process, TaskSpec::user_task());
        let parent_task = parent_pending.task_id().raw();
        narf_userspace::handlers::register_pid_task_mapping(parent_pid, parent_task);
        let tap = match tap_console(parent_task, false) {
            Ok(tap) => tap,
            Err(reason) => {
                let _ = narf_userspace::task::release_task(parent_task);
                let _ = narf_userspace::task::release_task(task_id);
                teardown(original_cr3);
                return Err(reason);
            }
        };
        ROOT_WATCH.store(pid, Ordering::Release);
        PARENT_WATCH.store(parent_pid, Ordering::Release);
        narf_userspace::handlers::__test_parent_of_set_with_signal(pid, parent_task, LINUX_SIGCHLD);
        parent = Some((
            Root {
                task_id: parent_task,
                pid: parent_pid,
            },
            tap,
        ));
        // The parent runs first, so its wait4 finds a living child and blocks.
        parent_pending.spawn();
    }
    pending.spawn();

    static WAITER_TIMED_OUT: AtomicU64 = AtomicU64::new(0);
    WAITER_TIMED_OUT.store(0, Ordering::Release);
    let deadline = narf_time::Instant::now().plus_cycles(WAITER_BUDGET_CYCLES);
    // The waiter stays on this CPU, whose `run_until_empty` below returns
    // only once the waiter has seen every guest task reaped.
    let mut waiter = TaskSpec::unthrottled();
    waiter.affinity = Affinity::pinned(CpuId(cpu as u32));
    narf_scheduler::spawn_with_spec(
        async move {
            loop {
                if narf_scheduler::live_user_task_count() <= live_before {
                    return;
                }
                if narf_time::Instant::now() >= deadline {
                    WAITER_TIMED_OUT.store(1, Ordering::Release);
                    return;
                }
                // A panic on another CPU halts that CPU with the guest's
                // tasks still held; stop waiting on them (see
                // `narf_console::panic_reported`).
                if narf_console::panic_reported() {
                    WAITER_TIMED_OUT.store(2, Ordering::Release);
                    return;
                }
                narf_scheduler::yield_now().await;
            }
        },
        waiter,
    );
    narf_scheduler::run_until_empty();
    // Before `teardown`, whose wait-table reset would hide a leftover link.
    let released = parent
        .as_ref()
        .map(|(parent, _)| release_reaping_parent(parent.task_id, pid));
    teardown(original_cr3);

    match WAITER_TIMED_OUT.load(Ordering::Acquire) {
        0 => {}
        2 => return Err("a CPU panicked while the guest ran (KERNEL PANIC above)"),
        _ => return Err("the guest's tasks were not reaped within the budget"),
    }
    let reentries = narf_userspace::user_task::__test_kernel_reentries() - reentries_before;
    if reentries != expected_reentries {
        let _ = writeln!(
            Writer,
            "    {reentries} syscall entries ran without interception under an open spawn hold; the guest makes {expected_reentries} kernel re-entries"
        );
        return Err(
            "syscall entries bypassed interception under an already open spawn hold, other than the guest's kernel re-entries",
        );
    }
    let reap = match parent {
        None => None,
        Some((parent, tap)) => {
            let report = tap.captured.lock().clone();
            if report.len() != REAPER_REPORT_LEN {
                let _ = writeln!(Writer, "    reaping parent wrote {} bytes", report.len());
                return Err("the reaping parent did not write its 16-byte wait4 report");
            }
            let word = |range: core::ops::Range<usize>| {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&report[range]);
                i32::from_le_bytes(bytes)
            };
            let mut pid_bytes = [0u8; 8];
            pid_bytes.copy_from_slice(&report[0..8]);
            let staged = staged_of(
                &ROOT_STAGED,
                "the root's exit never reached the thread-exit observers",
            )?;
            let parent_staged = staged_of(
                &PARENT_STAGED,
                "the reaping parent's exit never reached the thread-exit observers",
            )?;
            let charged = released.ok_or("the reaping parent was never released")??;
            let _ = writeln!(
                Writer,
                "    reaping parent released; child-CPU row held {charged} ns"
            );
            Some(RootReap {
                parent,
                reaped_pid: i64::from_le_bytes(pid_bytes),
                wstatus: word(8..12),
                second_wait: i64::from(word(12..16)),
                staged,
                parent_staged,
            })
        }
    };
    let _ = writeln!(
        Writer,
        "    guest tasks exited on CPUs {:#x} (harness CPU {cpu})",
        EXIT_CPUS.load(Ordering::Acquire)
    );
    let mut spaces = core::mem::take(&mut *EXITED_SPACES.lock());
    let root_exited_in_image = spaces.iter().any(|space| space.ptr_eq(&root_space));
    if ROOT_EXECS.load(Ordering::Acquire) {
        // The root replaced its image, so it exited from the new space; the
        // loaded one must still be reclaimed.
        if root_exited_in_image {
            return Err("the root task exited from its loaded image although it had exec'd");
        }
        spaces.push(root_space);
    } else if !root_exited_in_image {
        return Err("the root task's exit did not report its address space");
    }
    reclaim_run(&spaces, &root_frames)?;
    RECLAIMED_SPACES.store(spaces.len() as u64, Ordering::Release);
    Ok((root, reap))
}

/// Runs `elf` with Tool `T` hosted for the whole process tree.
fn run_hosted<T: Tool + 'static>(
    elf: &[u8],
    config: <T::GlobalState as reverie::GlobalTool>::Config,
) -> Result<(ReverieInterceptor<T>, Root), &'static str> {
    let interceptor = match ReverieInterceptor::<T>::new(config) {
        Ok(interceptor) => interceptor,
        Err(_) => return Err("NarfToolHost::new refused the Tool"),
    };
    let root = run_guest(elf, interceptor.boxed(), |root| {
        interceptor
            .host_root(root.task_id)
            .map_err(|_| "register_root refused the root task")
    })?;
    Ok((interceptor, root))
}

/// The checks every hosted run must pass: the root was reaped with
/// `root_status`, every hosted task's exit reached the host exactly once, and
/// the host tore every task down.
///
/// The root's status is checked before the exit count, so a run whose root
/// ended with the wrong status fails on that, whatever else went wrong.
fn check_teardown<T: Tool + 'static>(
    interceptor: &ReverieInterceptor<T>,
    root: Root,
    expected_exits: usize,
    root_status: i32,
) -> Result<Vec<TaskExitRecord>, &'static str> {
    let exits = interceptor.exits();
    let root_exit = exits.iter().find(|exit| exit.task_id == root.task_id);
    if let Some(root_exit) = root_exit {
        if root_exit.tid != Pid::from_raw(root.pid as i32) {
            return Err("the root's exit was reported under a tid other than its Linux pid");
        }
        if root_exit.wstatus != root_status {
            let _ = writeln!(Writer, "    root wstatus {:#x}", root_exit.wstatus);
            return Err("the root exited with an unexpected status");
        }
    }
    if exits.len() != expected_exits {
        let _ = writeln!(
            Writer,
            "    expected {expected_exits} task exits, host saw {}",
            exits.len()
        );
        let _ = writeln!(
            Writer,
            "    host live threads {} processes {}, interceptor hosts {}",
            interceptor.host().live_threads(),
            interceptor.host().live_processes(),
            interceptor.hosted_tasks()
        );
        for exit in &exits {
            let _ = writeln!(
                Writer,
                "    exit task {} tid {} wstatus {:#x} process_exited {}",
                exit.task_id,
                exit.tid.as_raw(),
                exit.wstatus,
                exit.process_exited
            );
        }
        return Err("the host did not see every task exit exactly once");
    }
    if root_exit.is_none() {
        return Err("the root task's exit never reached the host");
    }
    if interceptor.host().live_threads() != 0 || interceptor.host().live_processes() != 0 {
        return Err("the host still tracks tasks after every task exited");
    }
    if interceptor.hosted_tasks() != 0 {
        return Err("the interceptor still forwards for a reaped task");
    }
    Ok(exits)
}

fn result_of(outcome: Result<TestResult, &'static str>) -> TestResult {
    match outcome {
        Ok(result) => result,
        Err(reason) => TestResult::Fail(reason),
    }
}

// ── Global state a test must leave as it found it ────────────────────

/// The kernel-global switches that a reverie-narf test may change while it
/// runs, and must restore before the next test: the signal tables
/// (`narf_userspace::signal_init` and `sigaction_init`), the vDSO clock
/// routing, the vDSO image registration, and user-task SMP placement with
/// work stealing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct GlobalSwitches {
    signal_tables: narf_userspace::handlers::SignalTablesState,
    clocks_route_through_syscalls: bool,
    vdso_registered: bool,
    user_task_smp: bool,
    work_stealing: bool,
}

impl GlobalSwitches {
    fn read() -> Self {
        Self {
            signal_tables: narf_userspace::handlers::__test_signal_tables_state(),
            clocks_route_through_syscalls: narf_userspace::vdso::clocks_route_through_syscalls(),
            vdso_registered: narf_userspace::vdso::vdso_registered(),
            user_task_smp: narf_scheduler::user_task_smp_enabled(),
            work_stealing: narf_scheduler::work_stealing_enabled(),
        }
    }
}

/// Runs one registered reverie-narf test and fails it by name if it left any
/// [`GlobalSwitches`] changed, whatever the test itself returned. A leaked
/// switch changes what every later test in the boot exercises, so the leak
/// is reported even when the test passed.
fn leak_checked(test: fn() -> TestResult) -> TestResult {
    let before = GlobalSwitches::read();
    let result = test();
    let after = GlobalSwitches::read();
    if after.signal_tables != before.signal_tables {
        let _ = writeln!(
            Writer,
            "    leak check: signal tables {:?} -> {:?}",
            before.signal_tables, after.signal_tables
        );
        return TestResult::Fail("the test left the signal tables set up");
    }
    if after.clocks_route_through_syscalls != before.clocks_route_through_syscalls {
        return TestResult::Fail("the test left the vDSO clock routing changed");
    }
    if after.vdso_registered != before.vdso_registered {
        return TestResult::Fail("the test left the vDSO image registered");
    }
    if after.user_task_smp != before.user_task_smp {
        return TestResult::Fail("the test left user-task SMP placement changed");
    }
    if after.work_stealing != before.work_stealing {
        return TestResult::Fail("the test left work stealing changed");
    }
    result
}

/// Registers a reverie-narf test under [`leak_checked`].
macro_rules! reverie_narf_test {
    ($name:ident) => {
        const _: () = {
            fn run() -> TestResult {
                leak_checked($name)
            }
            #[used]
            #[link_section = "narf.tests"]
            static ENTRY: KernelTest = KernelTest {
                name: stringify!($name),
                subsystem: "reverie-narf",
                run,
            };
        };
    };
}

// ── Identity, registers, memory and the one-shot original ────────────────

static PROBE_TASK: AtomicU64 = AtomicU64::new(0);
static SEEN_WRITES: AtomicU64 = AtomicU64::new(0);
/// Bitmask of failed identity/register/memory checks; 0 when all held.
static VIEW_FAILURES: AtomicU64 = AtomicU64::new(0);
static FIRST_ORIGINAL: AtomicI64 = AtomicI64::new(i64::MIN);
/// 1 = `Ok(Returned(_))`, 2 = `Err(AlreadyExecuted)`, 3 = `Err(ContextManaged)`,
/// 4 = `Ok(ContextManaged)`.
static SECOND_ORIGINAL: AtomicU64 = AtomicU64::new(0);
static PROBE_EXIT: AtomicI64 = AtomicI64::new(i64::MIN);

/// Linux auxiliary-vector tags the services view is checked against.
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_RANDOM: u64 = 25;

fn read_word(memory: &impl MemoryAccess, addr: u64) -> Option<u64> {
    let mut word = [0u8; 8];
    let at = Addr::<u8>::from_raw(addr as usize)?;
    memory.read_exact(at, &mut word).ok()?;
    Some(u64::from_le_bytes(word))
}

/// The `(key, value)` pairs of the auxiliary vector on a SysV startup stack
/// whose `argc` is at `rsp`: `argc`, `argv[]`, NULL, `envp[]`, NULL, then the
/// pairs up to `AT_NULL`. `None` if the stack does not parse.
fn startup_auxv(memory: &impl MemoryAccess, rsp: u64) -> Option<Vec<(u64, u64)>> {
    let argc = read_word(memory, rsp)?;
    if argc > 64 {
        return None;
    }
    let mut at = rsp + 8 + (argc + 1) * 8;
    let mut envc = 0;
    while read_word(memory, at)? != 0 {
        envc += 1;
        if envc > 64 {
            return None;
        }
        at += 8;
    }
    at += 8;
    let mut pairs = Vec::new();
    loop {
        let key = read_word(memory, at)?;
        if key == 0 {
            return Some(pairs);
        }
        pairs.push((key, read_word(memory, at + 8)?));
        if pairs.len() > 64 {
            return None;
        }
        at += 16;
    }
}

/// Compares the auxiliary vector the services report with the one on the
/// guest's startup stack (the canonical guest's `rsp` is still its initial
/// value at its `write`). Bit 8: the kernel's recorded vector or the
/// services' `auxv()` differs from the stack's. Bit 9: the stack holds no
/// full vector, so the comparison would prove nothing.
fn check_auxv(kernel: &NarfKernelServices<'_>, pid: u64, rsp: u64) -> u64 {
    let Some(on_stack) = startup_auxv(&kernel.memory(), rsp) else {
        return 1 << 9;
    };
    let value = |tag: u64| {
        on_stack
            .iter()
            .find(|&&(key, _)| key == tag)
            .map(|&(_, value)| value)
    };
    let mut failures = 0;
    if value(AT_RANDOM).is_none() || value(AT_UID).is_none() {
        failures |= 1 << 9;
    }
    if tool_view::auxv_pairs(pid) != on_stack {
        failures |= 1 << 8;
    }
    let auxv = kernel.auxv();
    if auxv.len() != on_stack.len()
        || auxv.at_random().map(|addr| addr.as_raw() as u64) != value(AT_RANDOM)
        || auxv.at_uid().map(u64::from) != value(AT_UID)
        || auxv.at_euid().map(u64::from) != value(AT_EUID)
        || auxv.at_gid().map(u64::from) != value(AT_GID)
        || auxv.at_egid().map(u64::from) != value(AT_EGID)
    {
        failures |= 1 << 8;
    }
    failures
}

/// Drives [`NarfKernelServices`] directly from the guest's `write`: checks
/// the Linux view it presents, then asks for the original twice.
struct ServicesProbe;

impl SyscallInterceptor for ServicesProbe {
    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        let task_id = invocation.task_id;
        if task_id != PROBE_TASK.load(Ordering::Acquire)
            || invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK != LINUX_WRITE
        {
            return SyscallInterception::Continue;
        }
        SEEN_WRITES.fetch_add(1, Ordering::AcqRel);
        let Some(ids) = tool_view::linux_task_ids(task_id) else {
            VIEW_FAILURES.fetch_or(1, Ordering::AcqRel);
            return SyscallInterception::Continue;
        };
        let mut kernel = NarfKernelServices::new(native, task_id, ids, Some(invocation.raw_number));

        let mut failures = 0u64;
        let pid = Pid::from_raw(ids.pid as i32);
        // A thread-group leader's tid is its pid, and neither is the
        // scheduler's task id.
        if kernel.tid() != pid || kernel.pid() != pid {
            failures |= 1 << 1;
        }
        if kernel.tid().as_raw() as u64 == task_id {
            failures |= 1 << 2;
        }
        if kernel.ppid().is_some() {
            failures |= 1 << 3;
        }
        let regs = kernel.regs();
        if regs.orig_rax != u64::from(LINUX_WRITE) || regs.rax != (-38i64) as u64 {
            failures |= 1 << 4;
        }
        if regs.rdi != 1 || regs.rsi != CANONICAL_MESSAGE_ADDR || regs.rdx != 16 {
            failures |= 1 << 5;
        }
        if !CANONICAL_TEXT.contains(&regs.rip) || regs.cs != 0x33 || regs.ss != 0x2b {
            failures |= 1 << 6;
        }
        let mut message = [0u8; 16];
        let read = Addr::<u8>::from_raw(regs.rsi as usize)
            .ok_or(reverie::syscalls::Errno::EFAULT)
            .and_then(|addr| kernel.memory().read_exact(addr, &mut message));
        if read.is_err() || &message != CANONICAL_MESSAGE {
            failures |= 1 << 7;
        }
        failures |= check_auxv(&kernel, ids.pid, regs.rsp);
        VIEW_FAILURES.fetch_or(failures, Ordering::AcqRel);

        match kernel.execute_original() {
            Ok(NarfSyscallOutcome::Returned(value)) => {
                FIRST_ORIGINAL.store(value, Ordering::Release)
            }
            _ => FIRST_ORIGINAL.store(i64::MIN + 1, Ordering::Release),
        }
        let second = match kernel.execute_original() {
            Ok(NarfSyscallOutcome::Returned(_)) => 1,
            Err(OriginalSyscallError::AlreadyExecuted) => 2,
            Err(OriginalSyscallError::ContextManaged) => 3,
            Ok(NarfSyscallOutcome::ContextManaged) => 4,
        };
        SECOND_ORIGINAL.store(second, Ordering::Release);
        SyscallInterception::Continue
    }

    fn on_task_exit(&self, task_id: u64, _pid: u64, wstatus: i32, _process_wstatus: i32) {
        if task_id == PROBE_TASK.load(Ordering::Acquire) {
            PROBE_EXIT.store(i64::from(wstatus), Ordering::Release);
        }
    }
}

/// The services a Tool callback gets report the task's root-namespace Linux
/// identity (not its scheduler id), Linux entry registers with `orig_rax`
/// set to the syscall number, the task's memory, and the auxiliary vector the
/// loader wrote on the task's startup stack; and the kernel runs the original
/// syscall at most once however often it is asked.
fn reverie_narf_services_view_and_one_shot_original() -> TestResult {
    PROBE_TASK.store(0, Ordering::Release);
    SEEN_WRITES.store(0, Ordering::Release);
    VIEW_FAILURES.store(0, Ordering::Release);
    FIRST_ORIGINAL.store(i64::MIN, Ordering::Release);
    SECOND_ORIGINAL.store(0, Ordering::Release);
    PROBE_EXIT.store(i64::MIN, Ordering::Release);
    result_of((|| {
        run_guest(CANONICAL_GUEST, Box::new(ServicesProbe), |root| {
            PROBE_TASK.store(root.task_id, Ordering::Release);
            Ok(())
        })?;
        if SEEN_WRITES.load(Ordering::Acquire) != 1 {
            return Err("the guest's write did not reach the interceptor exactly once");
        }
        let failures = VIEW_FAILURES.load(Ordering::Acquire);
        if failures != 0 {
            let _ = writeln!(Writer, "    services view failures {failures:#x}");
            return Err("the services' identity, registers or memory were wrong");
        }
        if FIRST_ORIGINAL.load(Ordering::Acquire) != 16 {
            return Err("the first execute_original did not return write's 16");
        }
        match SECOND_ORIGINAL.load(Ordering::Acquire) {
            2 => {}
            1 => return Err("the kernel executed the original syscall twice"),
            _ => return Err("the second execute_original did not report AlreadyExecuted"),
        }
        if PROBE_EXIT.load(Ordering::Acquire) != 0 {
            return Err("the guest did not exit 0 after the one-shot original");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_services_view_and_one_shot_original);

// ── Unmodified Tools ──────────────────────────────────────────────────────

/// counter1, unmodified from reverie-examples, counts the canonical guest's
/// two syscalls (write, exit) through its global state, and the task's exit
/// tears its state down in the host exactly once.
fn reverie_narf_counter1_counts_and_tears_down() -> TestResult {
    result_of((|| {
        let (interceptor, root) = run_hosted::<CounterLocal>(CANONICAL_GUEST, ())?;
        let exits = check_teardown(&interceptor, root, 1, 0)?;
        if !exits[0].process_exited {
            return Err("the root's exit did not end its process in the host");
        }
        let total = interceptor.host().global().total();
        if total != 2 {
            let _ = writeln!(Writer, "    counter1 total {total}");
            return Err("counter1 did not count exactly write and exit");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_counter1_counts_and_tears_down);

/// counter1 follows a process tree: fork and vfork children are registered
/// before their first instruction, their syscalls reach the Tool, and every
/// task's exit reaches the host once. The guest checks each child's wait
/// status itself and exits 0 only if both are right.
fn reverie_narf_counter1_follows_fork_and_vfork() -> TestResult {
    result_of((|| {
        let (interceptor, root) = run_hosted::<CounterLocal>(FORK_GUEST, ())?;
        let exits = check_teardown(&interceptor, root, 3, 0)?;
        if exits.iter().filter(|exit| exit.process_exited).count() != 3 {
            return Err("each of the three processes did not end exactly once");
        }
        // Narf implements vfork as a copy, so the tree has three address
        // spaces, and run_guest proved each one reclaimed.
        if exited_space_count() != 3 {
            let _ = writeln!(Writer, "    exited address spaces {}", exited_space_count());
            return Err(
                "the run did not reclaim the parent's, fork child's and vfork child's address spaces",
            );
        }
        let children = exits
            .iter()
            .filter(|exit| exit.task_id != root.task_id)
            .map(|exit| exit.wstatus)
            .collect::<Vec<_>>();
        if children != [0x0700, 0x0900] {
            let _ = writeln!(Writer, "    child wstatus {children:x?}");
            return Err("the children did not exit 7 (fork) then 9 (vfork)");
        }
        // Parent: fork, wait4, vfork, wait4, exit; each child: exit.
        let total = interceptor.host().global().total();
        if total != 7 {
            let _ = writeln!(Writer, "    counter1 total {total}");
            return Err("counter1 did not count the tree's seven syscalls");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_counter1_follows_fork_and_vfork);

/// Probe returns `getpid() + 5` from a non-tail inject, which the guest
/// checks against `gettid()`; its per-thread state persists across the
/// thread's three syscalls and its RPCs reach the global state directly.
fn reverie_narf_probe_inject_and_thread_state() -> TestResult {
    result_of((|| {
        let (interceptor, root) = run_hosted::<Probe>(PROBE_GUEST, ())?;
        check_teardown(&interceptor, root, 1, 0)?;
        let global = interceptor.host().global();
        if global.events() != 3 || global.thread_state_sum() != 1 + 2 + 3 {
            let _ = writeln!(
                Writer,
                "    probe events {} thread-state sum {}",
                global.events(),
                global.thread_state_sum()
            );
            return Err("Probe's global state did not see getpid, gettid and exit in order");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_probe_inject_and_thread_state);

/// PassThrough tail-injects every syscall; the guest's own check that
/// write returned 16 is what makes it exit 0.
fn reverie_narf_passthrough_runs_guest_unchanged() -> TestResult {
    result_of((|| {
        let (interceptor, root) = run_hosted::<PassThrough>(CANONICAL_GUEST, ())?;
        check_teardown(&interceptor, root, 1, 0)?;
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_passthrough_runs_guest_unchanged);

/// Wraps the root's fd-1 console file: forwards every call to it unchanged and
/// keeps a copy of the bytes its `write` accepted.
///
/// The serial line is not byte evidence of the guest's output: the console
/// writer emits each byte as a `char`, so a byte above 0x7f leaves as two, and
/// the line interleaves the guest's bytes with everything else the kernel
/// prints. The copy is taken where the guest's `write` hands its bytes to the
/// console file.
///
/// A capture-only tap (`forward == false`) accepts every byte without passing
/// it on, for output that is binary and must not reach the serial line.
struct StdoutTap {
    console: Arc<dyn FileOps>,
    forward: bool,
    captured: IrqSafeSpinLock<Vec<u8>>,
}

impl FileOps for StdoutTap {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        self.console.read(offset, buf)
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        if !self.forward {
            self.captured.lock().extend_from_slice(buf);
            return Box::pin(async move { Ok(buf.len()) });
        }
        let accepted = self.console.write(offset, buf);
        Box::pin(async move {
            let n = accepted.await?;
            self.captured.lock().extend_from_slice(&buf[..n]);
            Ok(n)
        })
    }

    fn stat(&self) -> Stat {
        self.console.stat()
    }

    fn block_on_input(&self) -> bool {
        self.console.block_on_input()
    }

    fn poll_readiness(&self) -> u32 {
        self.console.poll_readiness()
    }

    fn tty_id(&self) -> Option<u32> {
        self.console.tty_id()
    }

    fn tty_fg_pgrp(&self) -> Option<u64> {
        self.console.tty_fg_pgrp()
    }

    fn tty_tostop(&self) -> bool {
        self.console.tty_tostop()
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        self.console.ioctl(cmd, arg)
    }
}

/// Puts a forwarding [`StdoutTap`] in front of `task_id`'s fd 1.
fn tap_stdout(task_id: u64) -> Result<Arc<StdoutTap>, &'static str> {
    tap_console(task_id, true)
}

/// Puts a [`StdoutTap`] in front of `task_id`'s fd 1, which must still be the
/// console file of a fresh descriptor table: one object behind fds 1 and 2,
/// a character device, the boot console's tty.
fn tap_console(task_id: u64, forward: bool) -> Result<Arc<StdoutTap>, &'static str> {
    narf_userspace::fd::with_table(task_id, |table| {
        let (Some(stdout), Some(stderr)) = (table.get(1), table.get(2)) else {
            return Err("the root's descriptor table has no fd 1 or fd 2");
        };
        if !Arc::ptr_eq(&stdout.ops, &stderr.ops)
            || stdout.ops.stat().mode.file_type != narf_filesystem::FileType::Special
            || stdout.ops.tty_id() != Some(narf_filesystem::TTY_ID_CONSOLE)
        {
            return Err("the root's fd 1 is not the fresh table's console file");
        }
        let mut entry = stdout.clone();
        let tap = Arc::new(StdoutTap {
            console: entry.ops.clone(),
            forward,
            captured: IrqSafeSpinLock::new(Vec::new()),
        });
        entry.ops = tap.clone();
        table.set(1, entry);
        Ok(tap)
    })
    .ok_or("the root's descriptor table was unavailable")?
}

/// The N cell of the Linux/Narf parity comparison: the shared canonical-trace
/// Tool, unchanged, writes its records to the kernel console. This is the
/// only test that emits canonical records.
///
/// It also prints the cell's other two observables, each exactly once, for
/// the external comparator: the bytes the guest wrote to fd 1, captured by a
/// [`StdoutTap`], and the root's wait status as its reaping parent, a real
/// guest process, received it from its own `wait4`. Their expected values
/// live in the comparator, not here. The records lie between the
/// [`CELL_BEGIN`] and [`CELL_RECORDS_END`] lines, which the comparator uses
/// to reject records printed by anything else.
fn reverie_narf_canonical_trace_cell() -> TestResult {
    let _ = writeln!(Writer, "{CELL_BEGIN}");
    result_of((|| {
        let interceptor = ReverieInterceptor::<CanonicalTrace<ConsoleSink>>::new(())
            .map_err(|_| "NarfToolHost::new refused the Tool")?;
        let mut tap = None;
        let (root, reap) = run_guest_with(
            CANONICAL_GUEST,
            interceptor.boxed(),
            |root| {
                tap = Some(tap_stdout(root.task_id)?);
                interceptor
                    .host_root(root.task_id)
                    .map_err(|_| "register_root refused the root task")
            },
            Some(REAPER_GUEST),
        )?;
        let _ = writeln!(Writer, "{CELL_RECORDS_END}");
        let tap = tap.ok_or("the root's fd 1 was never tapped")?;
        let reap = reap.ok_or("the run did not reap its root")?;
        if reap.reaped_pid != root.pid as i64 {
            let _ = writeln!(
                Writer,
                "    reaping parent's wait4 returned {}",
                reap.reaped_pid
            );
            return Err("the reaping parent's wait4 did not return the root's pid");
        }
        if reap.wstatus == REAPER_STATUS_SENTINEL {
            return Err("the reaping parent's wait4 reaped the root but stored no status");
        }
        if reap.second_wait != -LINUX_ECHILD {
            let _ = writeln!(Writer, "    second wait4 returned {}", reap.second_wait);
            return Err("the reaping parent's second wait4 did not report ECHILD");
        }
        if reap.parent_staged != Some(0) {
            let _ = writeln!(Writer, "    reaping parent staged {:?}", reap.parent_staged);
            return Err("the reaping parent did not exit 0");
        }
        if reap.parent.pid == root.pid {
            return Err("the reaping parent and the root share a pid");
        }
        if reap.staged != Some(reap.wstatus) {
            let _ = writeln!(Writer, "    staged termination {:?}", reap.staged);
            return Err("the reaped wait status differs from the termination staged at exit");
        }
        let exits = check_teardown(&interceptor, root, 1, reap.wstatus)?;
        if exits.len() != 1 || !exits[0].process_exited {
            return Err("the root's exit did not end its process in the host");
        }
        // The observable lines come only after every in-kernel check above
        // has passed, so a cell whose run failed those checks has no stdout
        // or exit line for the comparator to extract. The exit value itself
        // is the comparator's to judge, so it is printed before the value
        // check below.
        let captured = tap.captured.lock().clone();
        let mut line = alloc::string::String::new();
        for byte in &captured {
            let _ = write!(line, "{byte:02x}");
        }
        let _ = writeln!(
            Writer,
            "NARF-CELL stdout-capture=fd1-tap bytes={} hex={line}",
            captured.len()
        );
        let _ = writeln!(
            Writer,
            "NARF-CELL exit wstatus={:#06x} source=guest-parent-wait4",
            reap.wstatus
        );
        if reap.wstatus != 0 {
            return Err("the root did not exit 0");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_canonical_trace_cell);

/// Marks where the cell's canonical records may begin on the console.
const CELL_BEGIN: &str = "NARF-CELL begin test=reverie_narf_canonical_trace_cell";
/// Printed once the cell's run is over; every record precedes it.
const CELL_RECORDS_END: &str = "NARF-CELL records-end";

// ── Park re-execution ─────────────────────────────────────────────────────

/// The pipe guest's data-pipe write end and gate-pipe write end
/// (guests/pipe_x86_64.S fixes both).
const PIPE_DATA_WRITE_FD: u64 = 4;
const PIPE_GATE_WRITE_FD: u32 = 6;

static PARK_ENTRIES: AtomicU64 = AtomicU64::new(0);
/// Entries the dispatcher flagged as re-executions of a parked syscall.
static PARK_FLAGGED: AtomicU64 = AtomicU64::new(0);
/// Of those, re-executions of the child's one-byte write to the full pipe.
static PARK_FLAGGED_EXTRA_WRITE: AtomicU64 = AtomicU64::new(0);
/// 0: gate closed; 1: opened; 2: the gate write failed.
static PARK_GATE: AtomicU64 = AtomicU64::new(0);
/// The task that entered the child's one-byte write, or 0.
static PARK_WRITER: AtomicU64 = AtomicU64::new(0);

/// The pipe guest child's `write(4, buf, 1)` to its full data pipe.
fn is_extra_byte_write(invocation: &SyscallInvocation) -> bool {
    invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK == LINUX_WRITE
        && invocation.args.arg0 == PIPE_DATA_WRITE_FD
        && invocation.args.arg2 == 1
}

/// Writes the gate byte through task `task_id`'s gate-pipe write end, which
/// wakes the guest parent blocked reading the gate. A one-byte write to the
/// empty gate pipe completes on its first poll.
fn open_gate(task_id: u64) -> bool {
    let Some(Some(ops)) = narf_userspace::fd::with_table(task_id, |table| {
        table.get(PIPE_GATE_WRITE_FD).map(|entry| entry.ops.clone())
    }) else {
        return false;
    };
    let mut write = ops.write(0, b"g");
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    matches!(write.as_mut().poll(&mut cx), core::task::Poll::Ready(Ok(1)))
}

/// Counts every syscall entry and every re-execution entry, forwards all
/// calls to the Reverie interceptor it wraps, and remembers which task
/// entered the pipe guest child's one-byte write, so that [`GateOnPark`]
/// opens the gate when that write parks.
///
/// The ordering is by blocking, with no polling or sleeping, and does not
/// depend on where the tasks run. The parent reads the data pipe only after
/// the gate opens. The Tool's inject (a tail inject for counter1, a non-tail
/// one for the canonical-trace Tool) runs the write on the kernel's native
/// transition, which blocks inside the callback until the write can be
/// re-executed, so the gate cannot be opened from this interceptor: before
/// the call nothing has checked the pipe, and after it the wait is over. The
/// kernel's descriptor-park observer runs in between, once the write has
/// found the pipe full and armed its waker and before the task stops
/// running; however soon the parent then drains the pipe, on this CPU or
/// another, the wake reaches the armed waker and the write is re-executed.
/// If the write never parks, the gate stays closed, the child's exit closes
/// the gate's only write end (the parent closed its own), and the parent's
/// gate read ends with EOF (exit 126, guests/pipe_x86_64.S).
struct ParkWatch {
    inner: Box<dyn SyscallInterceptor>,
}

impl SyscallInterceptor for ParkWatch {
    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        PARK_ENTRIES.fetch_add(1, Ordering::AcqRel);
        if invocation.park_reexecution {
            PARK_FLAGGED.fetch_add(1, Ordering::AcqRel);
            if is_extra_byte_write(invocation) {
                PARK_FLAGGED_EXTRA_WRITE.fetch_add(1, Ordering::AcqRel);
            }
        } else if is_extra_byte_write(invocation) {
            PARK_WRITER.store(invocation.task_id, Ordering::Release);
        }
        self.inner.on_syscall_enter(invocation, native)
    }

    fn on_syscall_return(
        &self,
        invocation: &SyscallInvocation,
        result: SyscallReturn,
    ) -> SyscallReturn {
        self.inner.on_syscall_return(invocation, result)
    }

    fn on_syscall_context_managed(&self, invocation: &SyscallInvocation) {
        self.inner.on_syscall_context_managed(invocation);
    }

    fn on_task_start(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        self.inner.on_task_start(task_id, native);
    }

    fn on_task_exec(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        self.inner.on_task_exec(task_id, native);
    }

    fn on_task_exit(&self, task_id: u64, pid: u64, wstatus: i32, process_wstatus: i32) {
        self.inner
            .on_task_exit(task_id, pid, wstatus, process_wstatus);
    }
}

/// Installs the kernel's descriptor-park observer for one pipe-guest run,
/// and restores the previous observer when dropped.
///
/// The observer opens the gate once, when the task [`ParkWatch`] saw enter
/// the child's one-byte write parks on the full data pipe. It runs on that
/// task's kernel path after its waker was armed
/// (`narf_userspace::handlers::__verification_swap_fd_park_observer`).
struct GateOnPark(Option<fn(u64)>);

impl GateOnPark {
    fn install() -> Self {
        PARK_WRITER.store(0, Ordering::Release);
        PARK_GATE.store(0, Ordering::Release);
        Self(
            narf_userspace::handlers::__verification_swap_fd_park_observer(Some(open_gate_on_park)),
        )
    }
}

impl Drop for GateOnPark {
    fn drop(&mut self) {
        narf_userspace::handlers::__verification_swap_fd_park_observer(self.0);
    }
}

fn open_gate_on_park(task_id: u64) {
    if task_id == 0 || task_id != PARK_WRITER.load(Ordering::Acquire) {
        return;
    }
    if PARK_GATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
        && !open_gate(task_id)
    {
        PARK_GATE.store(2, Ordering::Release);
    }
}

/// A syscall that parks and is re-executed once its wait ends reaches the
/// Tool once, not once per execution: the dispatcher flags the re-execution
/// (`PARK_RECORDS` / `take_park_reexecution`) and the host completes the
/// parked request without a second Tool event. counter1 counts one event per
/// syscall it is handed, so its total must be the entries minus the flagged
/// re-executions, and the child's one-byte write to its full pipe must be
/// among them.
fn reverie_narf_park_reexecution_reaches_the_tool_once() -> TestResult {
    PARK_ENTRIES.store(0, Ordering::Release);
    PARK_FLAGGED.store(0, Ordering::Release);
    PARK_FLAGGED_EXTRA_WRITE.store(0, Ordering::Release);
    PARK_GATE.store(0, Ordering::Release);
    result_of((|| {
        let interceptor = ReverieInterceptor::<CounterLocal>::new(())
            .map_err(|_| "NarfToolHost::new refused the Tool")?;
        let watch = ParkWatch {
            inner: interceptor.boxed(),
        };
        let gate = GateOnPark::install();
        let root = run_guest(PIPE_GUEST, Box::new(watch), |root| {
            interceptor
                .host_root(root.task_id)
                .map_err(|_| "register_root refused the root task")
        })?;
        drop(gate);
        match PARK_GATE.load(Ordering::Acquire) {
            1 => {}
            0 => return Err("the child's one-byte write never parked on the full pipe"),
            _ => return Err("the gate byte could not be written"),
        }
        check_teardown(&interceptor, root, 2, 0)?;
        let entries = PARK_ENTRIES.load(Ordering::Acquire);
        let flagged = PARK_FLAGGED.load(Ordering::Acquire);
        let total = interceptor.host().global().total();
        let _ = writeln!(
            Writer,
            "    entries {entries} re-executions {flagged} counter1 total {total}"
        );
        if PARK_FLAGGED_EXTRA_WRITE.load(Ordering::Acquire) != 1 {
            return Err(
                "the parked one-byte write was not flagged as a park re-execution exactly once",
            );
        }
        if total != entries - flagged {
            return Err("a park re-execution reached the Tool as a new syscall event");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_park_reexecution_reaches_the_tool_once);

/// Canonical records the continuation test's Tool emitted, in order.
static CONTINUATION_RECORDS: IrqSafeSpinLock<Vec<alloc::string::String>> =
    IrqSafeSpinLock::new(Vec::new());

/// Collects canonical records instead of printing them as they happen.
#[derive(Debug)]
struct CaptureSink;

impl reverie_narf_tools::LineSink for CaptureSink {
    fn emit(line: &str) {
        CONTINUATION_RECORDS.lock().push(line.into());
    }
}

/// FNV-1a over the records, each followed by a newline.
fn records_digest(records: &[alloc::string::String]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in records
        .iter()
        .flat_map(|record| record.bytes().chain(Some(b'\n')))
    {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A Tool whose non-tail inject parks the task keeps its callback across the
/// park and resumes it at the kernel's re-execution with the parked
/// syscall's result.
///
/// The canonical-trace Tool runs every `write` as `guest.inject(..).await`
/// and records the result. The pipe guest's child writes one byte to its
/// full pipe; that inject parks until the parent drains the pipe, which the
/// parent does only after [`ParkWatch`] opens the gate once that write has
/// parked (ordering by blocking, see [`ParkWatch`]). The Tool must record the
/// write's result, 1, after the re-execution, and the run must end with both
/// tasks exiting 0. The records are printed with a digest so repeated runs
/// can be compared.
fn reverie_narf_parked_inject_resumes_the_tool() -> TestResult {
    PARK_ENTRIES.store(0, Ordering::Release);
    PARK_FLAGGED.store(0, Ordering::Release);
    PARK_FLAGGED_EXTRA_WRITE.store(0, Ordering::Release);
    PARK_GATE.store(0, Ordering::Release);
    CONTINUATION_RECORDS.lock().clear();
    result_of((|| {
        let interceptor = ReverieInterceptor::<CanonicalTrace<CaptureSink>>::new(())
            .map_err(|_| "NarfToolHost::new refused the Tool")?;
        let watch = ParkWatch {
            inner: interceptor.boxed(),
        };
        let gate = GateOnPark::install();
        let root = run_guest(PIPE_GUEST, Box::new(watch), |root| {
            interceptor
                .host_root(root.task_id)
                .map_err(|_| "register_root refused the root task")
        })?;
        drop(gate);
        let records = core::mem::take(&mut *CONTINUATION_RECORDS.lock());
        // Printed without the canonical prefix: only the two parity cells may
        // put that prefix on the console, between their begin and
        // records-end lines, because the comparator extracts every prefixed
        // line as a cell record.
        let prefix = reverie_narf_tools::canonical::PREFIX;
        for record in &records {
            let body = record.strip_prefix(prefix).unwrap_or(record);
            let _ = writeln!(Writer, "    record {body}");
        }
        let _ = writeln!(
            Writer,
            "    records {} digest {:#018x}",
            records.len(),
            records_digest(&records)
        );
        match PARK_GATE.load(Ordering::Acquire) {
            1 => {}
            0 => return Err("the child's one-byte write never parked on the full pipe"),
            _ => return Err("the gate byte could not be written"),
        }
        if PARK_FLAGGED_EXTRA_WRITE.load(Ordering::Acquire) != 1 {
            return Err("the parked one-byte write was not re-executed exactly once");
        }
        check_teardown(&interceptor, root, 2, 0)?;
        let enter = records.iter().position(|record| {
            record.starts_with(prefix)
                && record.contains(" phase=enter nr=1 a0=4 ")
                && record.ends_with(" a2=1")
        });
        let Some(enter) = enter else {
            return Err("the Tool never recorded the child's one-byte write");
        };
        let seq = records[enter]
            .strip_prefix(prefix)
            .and_then(|rest| rest.split(' ').next())
            .ok_or("the one-byte write's record has no seq")?;
        let expected = alloc::format!("{prefix}{seq} phase=return result=1");
        if !records[enter + 1..].contains(&expected) {
            return Err("the Tool did not resume with the parked write's result 1");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_parked_inject_resumes_the_tool);

// ── Exec ──────────────────────────────────────────────────────────────────

/// Where the exec tests mount their targets: the canonical guest for
/// guests/exec_x86_64.S, and the failed-exec targets for
/// guests/execfail_x86_64.S.
const EXEC_MOUNT: &str = "/rn-exec";
/// Recorded by [`ExecWatch::handle_post_exec`].
const POST_EXEC_MARK: u64 = u64::MAX;
static EXEC_LOG: IrqSafeSpinLock<Vec<u64>> = IrqSafeSpinLock::new(Vec::new());
/// 0: the new image's `write` was not seen; 1: its auxiliary vector matched;
/// 2: it did not (see [`ExecWatch::handle_syscall_event`]).
static EXEC_AUXV: AtomicU64 = AtomicU64::new(0);

/// Records the number of every syscall it is handed and a mark for every
/// post-exec callback, and tail-injects each syscall.
#[derive(Debug, Default, Clone, Copy)]
struct ExecWatch;

#[reverie::tool]
impl Tool for ExecWatch {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_post_exec<T: reverie::Guest<Self>>(
        &self,
        _guest: &mut T,
    ) -> Result<(), reverie::Errno> {
        EXEC_LOG.lock().push(POST_EXEC_MARK);
        Ok(())
    }

    async fn handle_syscall_event<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        use reverie::syscalls::SyscallInfo as _;
        let number = syscall.number().id() as u64;
        EXEC_LOG.lock().push(number);
        if number == u64::from(LINUX_WRITE) {
            // The exec'd canonical guest's `rsp` is still its initial value
            // at its `write`, so the vector the new image's loader wrote is
            // on the stack there. The kernel's recorded vector (and the
            // Tool's `auxv()`) must be that one, not the pre-exec image's.
            let rsp = guest.regs().await.rsp;
            let pid = guest.pid().as_raw() as u64;
            let matched = match startup_auxv(&guest.memory(), rsp) {
                Some(on_stack) if !on_stack.is_empty() => {
                    let random = on_stack
                        .iter()
                        .find(|&&(key, _)| key == AT_RANDOM)
                        .map(|&(_, value)| value);
                    let view = guest.auxv();
                    tool_view::auxv_pairs(pid) == on_stack
                        && view.len() == on_stack.len()
                        && view.at_random().map(|addr| addr.as_raw() as u64) == random
                }
                _ => false,
            };
            EXEC_AUXV.store(if matched { 1 } else { 2 }, Ordering::Release);
        }
        guest.tail_inject(syscall).await
    }
}

static DEFER_ROOT: AtomicU64 = AtomicU64::new(0);
/// The task whose execve callback is running, 0 outside it.
static DEFER_IN_CALLBACK: AtomicU64 = AtomicU64::new(0);
/// Bit 0: `on_task_exec` arrived inside the execve callback; bit 1: after it
/// returned; bit 2: the callback's `execute_original` was not
/// `Ok(ContextManaged)`.
static DEFER_SEEN: AtomicU64 = AtomicU64::new(0);

/// A raw interceptor that runs the exec guest's execve from inside its
/// callback and records whether the new image replaced the old one before the
/// callback returned. It never enters the Reverie host, whose re-entry guard
/// would panic the kernel if the dispatcher replaced the image inside the
/// callback.
struct ExecDeferralProbe;

impl SyscallInterceptor for ExecDeferralProbe {
    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        let number = invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK;
        let task_id = invocation.task_id;
        if number != 59 || task_id != DEFER_ROOT.load(Ordering::Acquire) {
            return SyscallInterception::Continue;
        }
        DEFER_IN_CALLBACK.store(task_id, Ordering::Release);
        let outcome = native.execute_original();
        DEFER_IN_CALLBACK.store(0, Ordering::Release);
        if outcome != Ok(NativeSyscallOutcome::ContextManaged) {
            DEFER_SEEN.fetch_or(1 << 2, Ordering::AcqRel);
        }
        SyscallInterception::Continue
    }

    fn on_task_exec(&self, task_id: u64, _native: &mut dyn NativeSyscallTransition) {
        if task_id != DEFER_ROOT.load(Ordering::Acquire) {
            return;
        }
        let bit = if DEFER_IN_CALLBACK.load(Ordering::Acquire) == task_id {
            1 << 0
        } else {
            1 << 1
        };
        DEFER_SEEN.fetch_or(bit, Ordering::AcqRel);
    }
}

/// [`run_hosted`] on the exec guest, after checking with
/// [`ExecDeferralProbe`] that the image replacement of an execve an
/// interceptor callback runs is deferred until the callback has returned. A
/// dispatcher that replaced the image inside the callback would otherwise
/// surface only as a kernel panic. The caller mounts the exec target and sets
/// [`ROOT_EXECS`].
fn run_hosted_exec<T: Tool + 'static>(
    config: <T::GlobalState as reverie::GlobalTool>::Config,
) -> Result<(ReverieInterceptor<T>, Root), &'static str> {
    DEFER_ROOT.store(0, Ordering::Release);
    DEFER_IN_CALLBACK.store(0, Ordering::Release);
    DEFER_SEEN.store(0, Ordering::Release);
    let run = run_guest(EXEC_GUEST, Box::new(ExecDeferralProbe), |root| {
        DEFER_ROOT.store(root.task_id, Ordering::Release);
        Ok(())
    });
    // Checked before the run's own result: an exec run inside the callback
    // may also break the run's teardown checks.
    let seen = DEFER_SEEN.load(Ordering::Acquire);
    if seen & 1 != 0 {
        return Err("execve ran inside the interceptor callback instead of after it returned");
    }
    run?;
    if seen != 1 << 1 {
        let _ = writeln!(Writer, "    exec deferral probe saw {seen:#x}");
        return Err("the deferred execve did not reach on_task_exec once, after the callback");
    }
    run_hosted::<T>(EXEC_GUEST, config)
}

/// A hosted task's successful execve replaces its image after the Tool
/// callback that requested it has returned (the dispatcher's deferred commit),
/// the Tool then gets its post-exec callback in the new image
/// (`on_task_exec`), and the new image's syscalls reach the Tool: execve,
/// post-exec, write, exit.
/// The new image's auxiliary vector replaces the old one in the kernel's
/// record and the Tool's view. The deferral itself is checked first, by a
/// raw interceptor ([`run_hosted_exec`]).
fn reverie_narf_exec_defers_and_reaches_post_exec() -> TestResult {
    EXEC_LOG.lock().clear();
    EXEC_AUXV.store(0, Ordering::Release);
    let auth = narf_filesystem::bootstrap_mount_authority();
    let Ok(mounted) = narf_filesystem::registry().mount(
        &auth,
        EXEC_MOUNT,
        narf_filesystem::MemFs::with_seeds("rn-exec", &[("prog", CANONICAL_GUEST)]),
    ) else {
        return TestResult::Fail("mounting the exec target failed");
    };
    ROOT_EXECS.store(true, Ordering::Release);
    let outcome = (|| {
        let (interceptor, root) = run_hosted_exec::<ExecWatch>(())?;
        let exits = check_teardown(&interceptor, root, 1, 0)?;
        if !exits[0].process_exited {
            return Err("the root's exit did not end its process in the host");
        }
        let log = core::mem::take(&mut *EXEC_LOG.lock());
        if log != [59, POST_EXEC_MARK, 1, 60] {
            let _ = writeln!(Writer, "    exec log {log:x?}");
            return Err("the Tool did not see execve, post-exec, write, exit in order");
        }
        if EXEC_AUXV.load(Ordering::Acquire) != 1 {
            return Err("the exec'd image's auxiliary vector is not the one its loader wrote");
        }
        Ok(TestResult::Pass)
    })();
    ROOT_EXECS.store(false, Ordering::Release);
    let _ = narf_filesystem::registry().unmount(&mounted, EXEC_MOUNT);
    result_of(outcome)
}
reverie_narf_test!(reverie_narf_exec_defers_and_reaches_post_exec);

// ── A failed exec ─────────────────────────────────────────────────────────

static EXECFAIL_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_EXECFAIL"));
static NOINTERP_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_NOINTERP"));
/// The failed-exec guest's "junk" target: long enough to be read as an ELF,
/// with no ELF magic.
const EXECFAIL_JUNK: &[u8] = &[0x41; 64];
const LINUX_ENOENT: i64 = 2;
const LINUX_ENOEXEC: i64 = 8;
/// What the failed-exec guest's three execve calls return, in order.
const EXECFAIL_RETURNS: [i64; 3] = [-LINUX_ENOENT, -LINUX_ENOEXEC, -LINUX_ENOENT];

static EXECFAIL_ROOT: AtomicU64 = AtomicU64::new(0);
/// What `execute_original` returned in each of the root's execve callbacks.
static EXECFAIL_ORIGINALS: IrqSafeSpinLock<
    Vec<Result<NativeSyscallOutcome, NativeSyscallOriginalError>>,
> = IrqSafeSpinLock::new(Vec::new());
/// How many times the root reached `on_task_exec`.
static EXECFAIL_EXECS: AtomicU64 = AtomicU64::new(0);
/// The root's wait status, -1 until its exit.
static EXECFAIL_WSTATUS: AtomicI64 = AtomicI64::new(-1);

/// A raw interceptor that runs each of the failed-exec guest's execve calls
/// from inside its callback and records what `execute_original` returned. It
/// also records whether the root reached `on_task_exec`, and its wait status.
struct ExecFailureProbe;

impl SyscallInterceptor for ExecFailureProbe {
    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        let number = invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK;
        if number != 59 || invocation.task_id != EXECFAIL_ROOT.load(Ordering::Acquire) {
            return SyscallInterception::Continue;
        }
        let outcome = native.execute_original();
        EXECFAIL_ORIGINALS.lock().push(outcome);
        SyscallInterception::Continue
    }

    fn on_task_exec(&self, task_id: u64, _native: &mut dyn NativeSyscallTransition) {
        if task_id == EXECFAIL_ROOT.load(Ordering::Acquire) {
            EXECFAIL_EXECS.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn on_task_exit(&self, task_id: u64, _pid: u64, wstatus: i32, _process_wstatus: i32) {
        if task_id == EXECFAIL_ROOT.load(Ordering::Acquire) {
            EXECFAIL_WSTATUS.store(i64::from(wstatus), Ordering::Release);
        }
    }
}

/// What each execve [`ExecFailWatch`] injected returned to it, as a Linux
/// return value.
static EXECFAIL_INJECTS: IrqSafeSpinLock<Vec<i64>> = IrqSafeSpinLock::new(Vec::new());

/// Injects each execve without a tail, records what the inject returned, and
/// returns that to the guest. Tail-injects every other syscall.
#[derive(Debug, Default, Clone, Copy)]
struct ExecFailWatch;

#[reverie::tool]
impl Tool for ExecFailWatch {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        use reverie::syscalls::SyscallInfo as _;
        if syscall.number() != Sysno::execve {
            guest.tail_inject(syscall).await
        }
        let result = guest.inject(syscall).await;
        EXECFAIL_INJECTS.lock().push(match result {
            Ok(value) => value,
            Err(errno) => -i64::from(errno.into_raw()),
        });
        Ok(result?)
    }
}

/// The failed-exec guest under [`ExecFailureProbe`]: each execve run inside
/// the callback returns its errno there, none reaches `on_task_exec`, and the
/// guest exits 0.
fn execfail_under_probe() -> Result<(), &'static str> {
    EXECFAIL_ROOT.store(0, Ordering::Release);
    EXECFAIL_ORIGINALS.lock().clear();
    EXECFAIL_EXECS.store(0, Ordering::Release);
    EXECFAIL_WSTATUS.store(-1, Ordering::Release);
    run_guest(EXECFAIL_GUEST, Box::new(ExecFailureProbe), |root| {
        EXECFAIL_ROOT.store(root.task_id, Ordering::Release);
        Ok(())
    })?;
    let originals = core::mem::take(&mut *EXECFAIL_ORIGINALS.lock());
    let returned: Vec<Option<i64>> = originals
        .iter()
        .map(|outcome| match outcome {
            Ok(NativeSyscallOutcome::Returned(result)) => Some(result.linux_abi_result()),
            _ => None,
        })
        .collect();
    if returned != EXECFAIL_RETURNS.map(Some) {
        let _ = writeln!(Writer, "    execute_original returned {originals:?}");
        return Err("an execve run inside the callback did not return its errno there");
    }
    if EXECFAIL_EXECS.load(Ordering::Acquire) != 0 {
        return Err("a failed execve reached on_task_exec");
    }
    let wstatus = EXECFAIL_WSTATUS.load(Ordering::Acquire);
    if wstatus != 0 {
        let _ = writeln!(Writer, "    root wstatus {wstatus:#x}");
        return Err("the guest did not get each execve's errno");
    }
    Ok(())
}

/// The failed-exec guest hosting [`ExecFailWatch`]: each execve the Tool
/// injects returns its errno to the Tool, and the guest gets it.
fn execfail_hosted() -> Result<(), &'static str> {
    EXECFAIL_INJECTS.lock().clear();
    let (interceptor, root) = run_hosted::<ExecFailWatch>(EXECFAIL_GUEST, ())?;
    check_teardown(&interceptor, root, 1, 0)?;
    let injects = core::mem::take(&mut *EXECFAIL_INJECTS.lock());
    if injects != EXECFAIL_RETURNS {
        let _ = writeln!(Writer, "    execve injects returned {injects:?}");
        return Err("a Tool's inject of a failing execve did not return its errno");
    }
    Ok(())
}

/// The failed-exec guest hosting strace: after each execve line, strace
/// prints the line it prints for an inject that failed, with that execve's
/// errno, and then the exit and the thread's and process's exit lines.
fn execfail_under_strace() -> Result<(), &'static str> {
    STRACE_LINES.lock().clear();
    reverie_narf_tools::set_eprintln_sink(record_strace_line);
    let interceptor = ReverieInterceptor::<strace::Strace>::with_tool_constructor(
        strace::Config::default(),
        <strace::Strace as Tool>::new,
    )
    .map_err(|_| "NarfToolHost::new refused the Tool")?;
    let root = run_guest(EXECFAIL_GUEST, interceptor.boxed(), |root| {
        interceptor
            .host_root(root.task_id)
            .map_err(|_| "register_root refused the root task")
    })?;
    let root_pid = root.pid as i32;
    check_teardown(&interceptor, root, 1, 0)?;
    let lines = core::mem::take(&mut *STRACE_LINES.lock());
    for line in &lines {
        let _ = writeln!(Writer, "    strace: {line}");
    }
    let prefix = alloc::format!("[pid {root_pid}] ");
    let calls: Vec<&str> = lines
        .iter()
        .map_while(|line| line.strip_prefix(prefix.as_str()))
        .collect();
    for (at, (path, errno)) in [
        ("missing", "ENOENT"),
        ("junk", "ENOEXEC"),
        ("nointerp", "ENOENT"),
    ]
    .into_iter()
    .enumerate()
    {
        let quoted = alloc::format!("\"/rn-exec/{path}\"");
        if !calls
            .get(2 * at)
            .is_some_and(|call| call.starts_with("execve(") && call.contains(quoted.as_str()))
        {
            return Err("strace's execve lines do not name the guest's paths in order");
        }
        if calls.get(2 * at + 1).copied() != Some(alloc::format!("(execve) = {errno}").as_str()) {
            return Err("strace did not print a failed execve's errno right after its execve line");
        }
    }
    if calls[6..] != ["exit(0) = ?"] {
        return Err("strace's last syscall line is not the guest's exit(0)");
    }
    if lines[calls.len()..]
        != [
            alloc::format!("Thread {root_pid} exited with status Exited(0)"),
            alloc::format!("Process {root_pid} exited with status Exited(0)"),
        ]
    {
        return Err("strace's exit lines do not follow the syscall lines with Exited(0)");
    }
    Ok(())
}

/// A hosted task's failed execve returns its errno to whoever ran it, and
/// the task goes on in its old image. The failed-exec guest
/// (guests/execfail_x86_64.S) execs a missing file, a file that is not an
/// ELF and an ELF whose interpreter is missing, and exits 0 only if the calls
/// return -ENOENT, -ENOEXEC and -ENOENT. It runs three times: under a raw
/// interceptor that runs each execve inside its callback
/// ([`execfail_under_probe`]), hosting a Tool that injects each
/// ([`execfail_hosted`]), and hosting unmodified strace
/// ([`execfail_under_strace`]). Each run is checked whatever the others
/// found.
fn reverie_narf_failed_exec_returns_its_errno() -> TestResult {
    let auth = narf_filesystem::bootstrap_mount_authority();
    let Ok(mounted) = narf_filesystem::registry().mount(
        &auth,
        EXEC_MOUNT,
        narf_filesystem::MemFs::with_seeds(
            "rn-exec",
            &[("junk", EXECFAIL_JUNK), ("nointerp", NOINTERP_GUEST)],
        ),
    ) else {
        return TestResult::Fail("mounting the failed-exec targets failed");
    };
    let outcomes = [
        ("raw interceptor", execfail_under_probe()),
        ("recording Tool", execfail_hosted()),
        ("strace", execfail_under_strace()),
    ];
    let _ = narf_filesystem::registry().unmount(&mounted, EXEC_MOUNT);
    let mut failure = None;
    for (run, outcome) in outcomes {
        if let Err(reason) = outcome {
            let _ = writeln!(Writer, "    failed exec, {run}: {reason}");
            failure.get_or_insert(reason);
        }
    }
    match failure {
        Some(reason) => TestResult::Fail(reason),
        None => TestResult::Pass,
    }
}
reverie_narf_test!(reverie_narf_failed_exec_returns_its_errno);

/// strace over the exec guest, whose execve succeeds: the root's execve line
/// names the exec target and no `(execve) = ` line follows it, since the
/// inject of an exec that succeeds does not return. The exec'd canonical
/// guest's write and exit follow under the same pid, then the thread's and
/// the process's exit lines. strace prints the execve line before it injects
/// the call, because an exec that succeeds replaces the memory the line
/// reads.
fn reverie_narf_strace_prints_a_successful_exec() -> TestResult {
    let auth = narf_filesystem::bootstrap_mount_authority();
    let Ok(mounted) = narf_filesystem::registry().mount(
        &auth,
        EXEC_MOUNT,
        narf_filesystem::MemFs::with_seeds("rn-exec", &[("prog", CANONICAL_GUEST)]),
    ) else {
        return TestResult::Fail("mounting the exec target failed");
    };
    ROOT_EXECS.store(true, Ordering::Release);
    let outcome = (|| {
        STRACE_LINES.lock().clear();
        reverie_narf_tools::set_eprintln_sink(record_strace_line);
        let interceptor = ReverieInterceptor::<strace::Strace>::with_tool_constructor(
            strace::Config::default(),
            <strace::Strace as Tool>::new,
        )
        .map_err(|_| "NarfToolHost::new refused the Tool")?;
        let root = run_guest(EXEC_GUEST, interceptor.boxed(), |root| {
            interceptor
                .host_root(root.task_id)
                .map_err(|_| "register_root refused the root task")
        })?;
        let root_pid = root.pid as i32;
        check_teardown(&interceptor, root, 1, 0)?;
        let lines = core::mem::take(&mut *STRACE_LINES.lock());
        for line in &lines {
            let _ = writeln!(Writer, "    strace: {line}");
        }
        let prefix = alloc::format!("[pid {root_pid}] ");
        let calls: Vec<&str> = lines
            .iter()
            .map_while(|line| line.strip_prefix(prefix.as_str()))
            .collect();
        if !calls
            .first()
            .is_some_and(|call| call.starts_with("execve(") && call.contains("\"/rn-exec/prog\""))
        {
            return Err("strace's first line is not an execve line naming the exec target");
        }
        let write = alloc::format!("write(1, {CANONICAL_MESSAGE_ADDR:#x}, 16) = 16");
        if calls[1..] != [write.as_str(), "exit(0) = ?"] {
            return Err(
                "strace's lines after the execve are not the new image's write and exit(0)",
            );
        }
        if lines[calls.len()..]
            != [
                alloc::format!("Thread {root_pid} exited with status Exited(0)"),
                alloc::format!("Process {root_pid} exited with status Exited(0)"),
            ]
        {
            return Err("strace's exit lines do not follow the syscall lines with Exited(0)");
        }
        Ok(TestResult::Pass)
    })();
    ROOT_EXECS.store(false, Ordering::Release);
    let _ = narf_filesystem::registry().unmount(&mounted, EXEC_MOUNT);
    result_of(outcome)
}
reverie_narf_test!(reverie_narf_strace_prints_a_successful_exec);

// ── Spawn holds and the vfork wait ────────────────────────────────────────

const LINUX_CLONE: u32 = 56;
const LINUX_FORK: u32 = 57;
const LINUX_WAIT4: u32 = 61;
const LINUX_EXIT: u32 = 60;
const CLONE_VFORK: u64 = 0x4000;

static HOLD_ROOT: AtomicU64 = AtomicU64::new(0);
/// Fork-family entries the probe ran the original of.
static HOLD_SPAWNS: AtomicU64 = AtomicU64::new(0);
/// Task id of the vfork child, once the vfork has created it.
static HOLD_VFORK_CHILD: AtomicU64 = AtomicU64::new(0);
static HOLD_VFORK_CHILD_EXITED: AtomicU64 = AtomicU64::new(0);
/// Bitmask of failed checks; 0 when all held.
static HOLD_FAILURES: AtomicU64 = AtomicU64::new(0);

/// A raw interceptor on the fork guest. For each fork and vfork it runs the
/// original inside the callback and checks the child is held back from the
/// scheduler and reported with its identity (the spawn hold). It also checks
/// that the vfork parent runs nothing until its child has exited (the vfork
/// wait the dispatcher performs after the callback), and that each child
/// inherits its parent's auxiliary vector.
struct HoldProbe;

impl SyscallInterceptor for HoldProbe {
    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        let number = invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK;
        let task_id = invocation.task_id;
        let root = HOLD_ROOT.load(Ordering::Acquire);
        let vfork_child = HOLD_VFORK_CHILD.load(Ordering::Acquire);
        if number == LINUX_EXIT && vfork_child != 0 && task_id == vfork_child {
            HOLD_VFORK_CHILD_EXITED.store(1, Ordering::Release);
        }
        // The parent's first syscall after vfork: its child must be gone.
        if number == LINUX_WAIT4
            && task_id == root
            && vfork_child != 0
            && HOLD_VFORK_CHILD_EXITED.load(Ordering::Acquire) == 0
        {
            HOLD_FAILURES.fetch_or(1 << 4, Ordering::AcqRel);
        }
        let vfork = number == LINUX_CLONE && invocation.args.arg0 & CLONE_VFORK != 0;
        if task_id != root || (number != LINUX_FORK && !vfork) {
            return SyscallInterception::Continue;
        }
        HOLD_SPAWNS.fetch_add(1, Ordering::AcqRel);
        let admitted = narf_scheduler::user_tasks_admitted();
        let child = match native.execute_original() {
            Ok(NativeSyscallOutcome::Returned(result)) => result.linux_abi_result(),
            _ => {
                HOLD_FAILURES.fetch_or(1 << 0, Ordering::AcqRel);
                return SyscallInterception::Continue;
            }
        };
        if narf_scheduler::user_tasks_admitted() != admitted {
            HOLD_FAILURES.fetch_or(1 << 1, Ordering::AcqRel);
        }
        match native.take_created_task() {
            Some(created) if created.linux_pid as i64 == child && !created.thread => {
                if vfork {
                    HOLD_VFORK_CHILD.store(created.task_id, Ordering::Release);
                }
                // The new process inherits its parent's auxiliary vector.
                let parent = tool_view::linux_task_ids(task_id)
                    .map(|ids| tool_view::auxv_pairs(ids.pid))
                    .unwrap_or_default();
                if parent.is_empty() || tool_view::auxv_pairs(created.linux_pid) != parent {
                    HOLD_FAILURES.fetch_or(1 << 5, Ordering::AcqRel);
                }
            }
            _ => {
                HOLD_FAILURES.fetch_or(1 << 2, Ordering::AcqRel);
            }
        }
        if native.take_created_task().is_some() {
            HOLD_FAILURES.fetch_or(1 << 3, Ordering::AcqRel);
        }
        SyscallInterception::Continue
    }
}

/// A child created inside an interceptor callback is held back from the
/// scheduler and reported to the interceptor exactly once, with its Linux
/// pid; and a vfork parent does not resume until its child has exited, even
/// though the vfork ran inside the callback (the dispatcher's deferred
/// `vfork_parent_wait`). The guest's clone-vfork child spins before its exit
/// so a parent released early would reach its `wait4` first; this half of
/// the test is a timing widener, not a schedule-independent proof.
fn reverie_narf_spawn_hold_and_vfork_wait() -> TestResult {
    HOLD_ROOT.store(0, Ordering::Release);
    HOLD_SPAWNS.store(0, Ordering::Release);
    HOLD_VFORK_CHILD.store(0, Ordering::Release);
    HOLD_VFORK_CHILD_EXITED.store(0, Ordering::Release);
    HOLD_FAILURES.store(0, Ordering::Release);
    result_of((|| {
        let (root, reap) = run_guest_with(
            VFORK_GUEST,
            Box::new(HoldProbe),
            |root| {
                HOLD_ROOT.store(root.task_id, Ordering::Release);
                Ok(())
            },
            Some(REAPER_GUEST),
        )?;
        let wstatus = reap
            .ok_or("the run did not reap its root")?
            .root_wstatus(root)?;
        let failures = HOLD_FAILURES.load(Ordering::Acquire);
        if failures != 0 {
            let _ = writeln!(Writer, "    spawn-hold failures {failures:#x}");
        }
        if failures & 0b111 != 0 {
            return Err(
                "a child created inside the callback was published early or not reported with its pid",
            );
        }
        if failures & (1 << 3) != 0 {
            return Err("a created child was reported twice");
        }
        if failures & (1 << 4) != 0 {
            return Err("the vfork parent resumed before its child exited");
        }
        if failures & (1 << 5) != 0 {
            return Err("a forked child did not inherit its parent's auxiliary vector");
        }
        if HOLD_SPAWNS.load(Ordering::Acquire) != 2
            || HOLD_VFORK_CHILD_EXITED.load(Ordering::Acquire) != 1
        {
            return Err(
                "the probe did not see the fork, the clone-vfork and the vfork child's exit",
            );
        }
        if wstatus != 0 {
            let _ = writeln!(Writer, "    root wstatus {wstatus:#x}");
            return Err("the vfork guest did not exit 0");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_spawn_hold_and_vfork_wait);

// ── Kernel-internal re-entry ──────────────────────────────────────────────

/// Narf's ring bootstrap and ring kick (guests/ring_x86_64.S).
const NARF_BOOTSTRAP: u32 = 0x4001;
const NARF_RING_KICK: u32 = 0x4003;
const LINUX_PIPE2: u32 = 293;
const LINUX_READ: u32 = 0;

static RING_ROOT: AtomicU64 = AtomicU64::new(0);
static RING_LOG: IrqSafeSpinLock<Vec<u32>> = IrqSafeSpinLock::new(Vec::new());

/// Records the number of every syscall the ring guest's task is intercepted
/// for, and runs each natively.
struct RingWatch;

impl SyscallInterceptor for RingWatch {
    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        _native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        if invocation.task_id == RING_ROOT.load(Ordering::Acquire) {
            RING_LOG
                .lock()
                .push(invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK);
        }
        SyscallInterception::Continue
    }
}

/// A syscall the kernel performs on a task's behalf, re-entering the syscall
/// dispatcher while the task's own intercepted syscall is still in its
/// interceptor call, is not intercepted: the ring kick's bridged pipe write
/// runs natively and completes, and the interceptor sees only the guest's own
/// syscalls (Linux reports no syscall stop for io_uring's work either). The
/// guest checks the completion and the bytes it reads back.
fn reverie_narf_kernel_reentry_is_not_intercepted() -> TestResult {
    RING_ROOT.store(0, Ordering::Release);
    RING_LOG.lock().clear();
    // Kernel-test boots skip the boot-time userspace init that creates the
    // bootstrap registry (bare_main.rs calls `bootstrap_init` only on a real
    // boot); the userspace ring tests create it the same way.
    narf_userspace::bootstrap_init();
    let rings_before = narf_userspace::handlers::bootstrap_live_count();
    result_of((|| {
        // The kick bridges exactly one submission, the pipe write.
        EXPECTED_KERNEL_REENTRIES.store(1, Ordering::Release);
        let (root, reap) = run_guest_with(
            RING_GUEST,
            Box::new(RingWatch),
            |root| {
                RING_ROOT.store(root.task_id, Ordering::Release);
                Ok(())
            },
            Some(REAPER_GUEST),
        )?;
        let log = core::mem::take(&mut *RING_LOG.lock());
        let wstatus = reap
            .ok_or("the run did not reap its root")?
            .root_wstatus(root)?;
        if wstatus != 0 {
            let _ = writeln!(Writer, "    root wstatus {wstatus:#x} log {log:x?}");
            return Err("the ring guest did not exit 0: its kernel-performed write failed a check");
        }
        if log
            != [
                LINUX_PIPE2,
                NARF_BOOTSTRAP,
                NARF_RING_KICK,
                LINUX_READ,
                LINUX_EXIT,
            ]
        {
            let _ = writeln!(Writer, "    ring log {log:x?}");
            return Err("the interceptor did not see exactly the guest's own syscalls");
        }
        if narf_userspace::handlers::bootstrap_live_count() != rings_before {
            return Err("the ring guest's bootstrap rings outlived it");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_kernel_reentry_is_not_intercepted);

// ── Termination inside an interceptor call ────────────────────────────────

const LINUX_RT_SIGRETURN: u32 = 15;
const LINUX_SIGSEGV: i32 = 11;
/// What the bad-frame guest's fork child exits with.
const BADFRAME_CHILD_CODE: u64 = 42;

static BADFRAME_ROOT: AtomicU64 = AtomicU64::new(0);
/// Task id of the child forked inside the rt_sigreturn callback.
static BADFRAME_CHILD: AtomicU64 = AtomicU64::new(0);
/// The exit code the child passed to `exit`, once it ran.
static BADFRAME_CHILD_EXIT: AtomicI64 = AtomicI64::new(NOT_SEEN);
/// The child's wait status as its exit reached the interceptor.
static BADFRAME_CHILD_WSTATUS: AtomicI64 = AtomicI64::new(NOT_SEEN);
/// Bitmask of failed checks inside the callback; 0 when all held.
static BADFRAME_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Forks from inside the bad-frame guest's rt_sigreturn callback, then lets
/// the original run: it forces SIGSEGV on the task while the callback's
/// spawn hold is open and holding the child.
struct BadFrameProbe;

impl SyscallInterceptor for BadFrameProbe {
    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        let number = invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK;
        let task_id = invocation.task_id;
        if number == LINUX_EXIT && task_id == BADFRAME_CHILD.load(Ordering::Acquire) {
            BADFRAME_CHILD_EXIT.store(invocation.args.arg0 as i64, Ordering::Release);
        }
        if number != LINUX_RT_SIGRETURN || task_id != BADFRAME_ROOT.load(Ordering::Acquire) {
            return SyscallInterception::Continue;
        }
        let fork = NativeSyscallRequest::new(LINUX_FORK, Default::default());
        match native.execute_injected(fork) {
            NativeSyscallOutcome::Returned(result) if result.linux_abi_result() > 0 => {}
            _ => {
                BADFRAME_FAILURES.fetch_or(1 << 0, Ordering::AcqRel);
                return SyscallInterception::Continue;
            }
        }
        match native.take_created_task() {
            Some(created) if !created.thread => {
                BADFRAME_CHILD.store(created.task_id, Ordering::Release)
            }
            _ => {
                BADFRAME_FAILURES.fetch_or(1 << 1, Ordering::AcqRel);
            }
        }
        // The original: a sigreturn whose frame cannot be read.
        SyscallInterception::Continue
    }

    fn on_task_exit(&self, task_id: u64, _pid: u64, wstatus: i32, _process_wstatus: i32) {
        if task_id != 0 && task_id == BADFRAME_CHILD.load(Ordering::Acquire) {
            BADFRAME_CHILD_WSTATUS.store(i64::from(wstatus), Ordering::Release);
        }
    }
}

/// A task terminated by a native syscall its interceptor callback ran (a
/// sigreturn bad frame forcing SIGSEGV) terminates after the callback has
/// returned, with its spawn hold released: the hold table and count are
/// clear, the child the callback forked is published and runs to its own
/// exit, and the task dies of SIGSEGV without returning to user mode.
fn reverie_narf_termination_inside_callback_releases_the_hold() -> TestResult {
    BADFRAME_ROOT.store(0, Ordering::Release);
    BADFRAME_CHILD.store(0, Ordering::Release);
    BADFRAME_CHILD_EXIT.store(NOT_SEEN, Ordering::Release);
    BADFRAME_CHILD_WSTATUS.store(NOT_SEEN, Ordering::Release);
    BADFRAME_FAILURES.store(0, Ordering::Release);
    let holds_before = narf_userspace::user_task::__test_open_spawn_holds();
    result_of((|| {
        if holds_before != (0, 0) {
            return Err("a spawn hold was open before the run");
        }
        let run = run_guest_with(
            BADFRAME_GUEST,
            Box::new(BadFrameProbe),
            |root| {
                BADFRAME_ROOT.store(root.task_id, Ordering::Release);
                Ok(())
            },
            Some(REAPER_GUEST),
        );
        // Checked before the run's own result: a leaked hold also strands the
        // held child, which the harness then reports only as unreclaimed
        // memory.
        let holds = narf_userspace::user_task::__test_open_spawn_holds();
        if holds != (0, 0) {
            let _ = writeln!(Writer, "    open spawn holds (count, entries) {holds:?}");
            return Err("the spawn hold outlived the task terminated inside its callback");
        }
        let (root, reap) = run?;
        let wstatus = reap
            .ok_or("the run did not reap its root")?
            .root_wstatus(root)?;
        let failures = BADFRAME_FAILURES.load(Ordering::Acquire);
        if failures != 0 {
            let _ = writeln!(Writer, "    bad-frame failures {failures:#x}");
            return Err("the callback's fork did not create and report a child");
        }
        let child_exit = BADFRAME_CHILD_EXIT.load(Ordering::Acquire);
        let child_wstatus = BADFRAME_CHILD_WSTATUS.load(Ordering::Acquire);
        if child_exit != BADFRAME_CHILD_CODE as i64
            || child_wstatus != (BADFRAME_CHILD_CODE as i64) << 8
        {
            let _ = writeln!(
                Writer,
                "    child exit arg {child_exit:#x} wstatus {child_wstatus:#x}"
            );
            return Err("the child forked inside the terminating callback never ran to its exit");
        }
        if wstatus & 0x7f != LINUX_SIGSEGV {
            let _ = writeln!(Writer, "    root wstatus {wstatus:#x}");
            return Err("the task did not die of SIGSEGV");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_termination_inside_callback_releases_the_hold);

// ── Signals raised inside a Tool callback ─────────────────────────────────

const LINUX_SIGKILL: i32 = 9;
const LINUX_SIGTERM: i32 = 15;
/// `ERESTARTSYS`, which the kernel never returns to user mode.
const LINUX_ERESTARTSYS: i64 = 512;

/// The signal tables, created as the boot path does and put back as they
/// were when this is dropped, on every exit path of the test.
///
/// Kernel-test boots skip the boot-time userspace init, and without the
/// tables a raise finds no pending-bit map and is dropped: the guest's own
/// `kill` returns 0 and nothing is pending. Only the tests that raise a
/// signal need them. Other subsystems' tests may already have created them,
/// in which case they stay; tables this guard created are removed again, so
/// the next test sees what it would have seen without this one.
struct SignalTables(narf_userspace::handlers::SignalTablesState);

impl SignalTables {
    fn init() -> Self {
        let before = narf_userspace::handlers::__test_signal_tables_state();
        narf_userspace::signal_init();
        Self(before)
    }

    /// As [`Self::init`], and also creates the per-task handler tables
    /// (`narf_userspace::sigaction_init`), for a guest that installs a
    /// handler: without them its `rt_sigaction` fails with `EINVAL`. Tables
    /// that already exist are kept as they are.
    fn init_with_handlers() -> Self {
        let tables = Self::init();
        if !tables.0.sigactions {
            narf_userspace::sigaction_init();
        }
        tables
    }
}

impl Drop for SignalTables {
    fn drop(&mut self) {
        narf_userspace::handlers::__test_restore_signal_tables(self.0);
    }
}

/// A Tool's inject result as the raw Linux return value.
fn raw_result(result: Result<i64, reverie::Errno>) -> i64 {
    match result {
        Ok(value) => value,
        Err(errno) => -i64::from(errno.into_raw()),
    }
}

/// The guest's pid as the Tool saw it, and what each inject of
/// [`SigtermInCallback`] returned ([`NOT_SEEN`] until it returned).
static SIGTERM_PID: AtomicI64 = AtomicI64::new(NOT_SEEN);
static SIGTERM_KILL: AtomicI64 = AtomicI64::new(NOT_SEEN);
static SIGTERM_POLL: AtomicI64 = AtomicI64::new(NOT_SEEN);
static SIGTERM_GETPID: AtomicI64 = AtomicI64::new(NOT_SEEN);

/// At the canonical guest's `write`, sends the guest `SIGTERM` with an
/// injected `kill`, then injects a `poll` with no descriptors and a 100 ms
/// timeout, then `getpid`, then tail-injects the `write`.
#[derive(Debug, Default, Clone, Copy)]
struct SigtermInCallback;

#[reverie::tool]
impl Tool for SigtermInCallback {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        use reverie::syscalls::SyscallInfo as _;
        if syscall.number().id() as u32 == LINUX_WRITE {
            let pid = guest.pid().as_raw();
            SIGTERM_PID.store(i64::from(pid), Ordering::Release);
            let kill = reverie::syscalls::Kill::new()
                .with_pid(pid)
                .with_sig(LINUX_SIGTERM);
            SIGTERM_KILL.store(raw_result(guest.inject(kill).await), Ordering::Release);
            let poll = reverie::syscalls::Poll::new()
                .with_fds(None)
                .with_nfds(0)
                .with_timeout(100);
            SIGTERM_POLL.store(raw_result(guest.inject(poll).await), Ordering::Release);
            let getpid = reverie::syscalls::Getpid::new();
            SIGTERM_GETPID.store(raw_result(guest.inject(getpid).await), Ordering::Release);
        }
        guest.tail_inject(syscall).await
    }
}

/// A catchable signal with a terminating default action, raised against the
/// task inside its Tool callback, behaves as under reverie-ptrace
/// (`reverie-ptrace/tests/inject_signal_parity.rs`, the `kill(self,
/// SIGTERM)` case): the `kill` returns 0, the next inject returns
/// `-ERESTARTSYS` without running, the inject after that runs (`getpid`
/// returns the pid), and the task dies of the signal only after the callback
/// has returned, with its spawn hold released.
fn reverie_narf_sigterm_in_callback_matches_ptrace() -> TestResult {
    for slot in [&SIGTERM_PID, &SIGTERM_KILL, &SIGTERM_POLL, &SIGTERM_GETPID] {
        slot.store(NOT_SEEN, Ordering::Release);
    }
    let _signal_tables = SignalTables::init();
    result_of((|| {
        let (interceptor, root) = run_hosted::<SigtermInCallback>(CANONICAL_GUEST, ())?;
        let holds = narf_userspace::user_task::__test_open_spawn_holds();
        let pid = SIGTERM_PID.load(Ordering::Acquire);
        let kill = SIGTERM_KILL.load(Ordering::Acquire);
        let poll = SIGTERM_POLL.load(Ordering::Acquire);
        let getpid = SIGTERM_GETPID.load(Ordering::Acquire);
        let _ = writeln!(
            Writer,
            "    pid {pid} kill {kill} poll {poll} getpid {getpid} holds {holds:?}"
        );
        if holds != (0, 0) {
            return Err("a spawn hold outlived the callback");
        }
        if pid <= 0 || kill != 0 {
            return Err("the injected kill(self, SIGTERM) did not return 0");
        }
        if poll != -LINUX_ERESTARTSYS {
            return Err("the inject after the kill did not return -ERESTARTSYS");
        }
        if getpid == NOT_SEEN {
            return Err("getpid did not run: a later inject was refused");
        }
        if getpid != pid {
            return Err("the later getpid inject did not return the pid");
        }
        check_teardown(&interceptor, root, 1, LINUX_SIGTERM)?;
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_sigterm_in_callback_matches_ptrace);

/// What each inject of [`SigtermThenExitGroup`] returned ([`NOT_SEEN`] until
/// it returned), and the guest's pid as the Tool saw it.
static EXIT_GROUP_PID: AtomicI64 = AtomicI64::new(NOT_SEEN);
static EXIT_GROUP_KILL: AtomicI64 = AtomicI64::new(NOT_SEEN);
static EXIT_GROUP_EXIT: AtomicI64 = AtomicI64::new(NOT_SEEN);
static EXIT_GROUP_GETPID: AtomicI64 = AtomicI64::new(NOT_SEEN);

/// At the canonical guest's `write`, sends the guest `SIGTERM` with an
/// injected `kill`, then injects `exit_group(7)`, then `getpid`.
#[derive(Debug, Default, Clone, Copy)]
struct SigtermThenExitGroup;

#[reverie::tool]
impl Tool for SigtermThenExitGroup {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        use reverie::syscalls::SyscallInfo as _;
        if syscall.number().id() as u32 == LINUX_WRITE {
            let pid = guest.pid().as_raw();
            EXIT_GROUP_PID.store(i64::from(pid), Ordering::Release);
            let kill = reverie::syscalls::Kill::new()
                .with_pid(pid)
                .with_sig(LINUX_SIGTERM);
            EXIT_GROUP_KILL.store(raw_result(guest.inject(kill).await), Ordering::Release);
            let exit = reverie::syscalls::ExitGroup::new().with_status(7);
            EXIT_GROUP_EXIT.store(raw_result(guest.inject(exit).await), Ordering::Release);
            let getpid = reverie::syscalls::Getpid::new();
            EXIT_GROUP_GETPID.store(raw_result(guest.inject(getpid).await), Ordering::Release);
        }
        guest.tail_inject(syscall).await
    }
}

/// An `exit_group` requested while a terminating signal is pending is where
/// Narf and reverie-ptrace differ (backend contract, signal difference 8).
/// Under ptrace (`reverie-ptrace/tests/inject_signal_parity.rs`,
/// `exit_group_injected_while_sigterm_is_pending_returns_erestartsys_and_does_not_run`)
/// the `exit_group` returns `-ERESTARTSYS` without running, the `getpid`
/// after it runs, and the task dies of `SIGTERM`. Narf never withholds a
/// context-ending transition, so here the `exit_group` runs: it does not
/// return to the Tool, nothing after it runs, and the task exits with
/// code 7.
fn reverie_narf_exit_group_with_sigterm_pending_runs() -> TestResult {
    for slot in [
        &EXIT_GROUP_PID,
        &EXIT_GROUP_KILL,
        &EXIT_GROUP_EXIT,
        &EXIT_GROUP_GETPID,
    ] {
        slot.store(NOT_SEEN, Ordering::Release);
    }
    let _signal_tables = SignalTables::init();
    result_of((|| {
        let (interceptor, root) = run_hosted::<SigtermThenExitGroup>(CANONICAL_GUEST, ())?;
        let holds = narf_userspace::user_task::__test_open_spawn_holds();
        let pid = EXIT_GROUP_PID.load(Ordering::Acquire);
        let kill = EXIT_GROUP_KILL.load(Ordering::Acquire);
        let exit = EXIT_GROUP_EXIT.load(Ordering::Acquire);
        let getpid = EXIT_GROUP_GETPID.load(Ordering::Acquire);
        let _ = writeln!(
            Writer,
            "    pid {pid} kill {kill} exit_group {exit} getpid {getpid} holds {holds:?}"
        );
        if holds != (0, 0) {
            return Err("a spawn hold outlived the callback");
        }
        if pid <= 0 || kill != 0 {
            return Err("the injected kill(self, SIGTERM) did not return 0");
        }
        if exit != NOT_SEEN {
            return Err("the injected exit_group returned to the Tool");
        }
        if getpid != NOT_SEEN {
            return Err("an inject after the exit_group ran");
        }
        check_teardown(&interceptor, root, 1, 7 << 8)?;
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_exit_group_with_sigterm_pending_runs);

/// The guest's pid, whether the kill inject was issued, how many steps of
/// [`SigkillInCallback`] ran after it, and how often its callback future was
/// dropped.
static SIGKILL_PID: AtomicI64 = AtomicI64::new(NOT_SEEN);
static SIGKILL_REACHED: AtomicU64 = AtomicU64::new(0);
static SIGKILL_AFTER: AtomicU64 = AtomicU64::new(0);
static SIGKILL_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Counts one drop of the callback future that owns it.
struct DropMark;

impl Drop for DropMark {
    fn drop(&mut self) {
        SIGKILL_DROPPED.fetch_add(1, Ordering::AcqRel);
    }
}

/// At the canonical guest's `write`, kills the guest with an injected
/// `kill(self, SIGKILL)`, then counts every step that runs after it: the
/// kill's return, a `getpid` inject, and the tail-injected `write`.
#[derive(Debug, Default, Clone, Copy)]
struct SigkillInCallback;

#[reverie::tool]
impl Tool for SigkillInCallback {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        use reverie::syscalls::SyscallInfo as _;
        if syscall.number().id() as u32 == LINUX_WRITE {
            let _mark = DropMark;
            let pid = guest.pid().as_raw();
            SIGKILL_PID.store(i64::from(pid), Ordering::Release);
            SIGKILL_REACHED.fetch_add(1, Ordering::AcqRel);
            let kill = reverie::syscalls::Kill::new()
                .with_pid(pid)
                .with_sig(LINUX_SIGKILL);
            let _ = guest.inject(kill).await;
            SIGKILL_AFTER.fetch_add(1, Ordering::AcqRel);
            let _ = guest.inject(reverie::syscalls::Getpid::new()).await;
            SIGKILL_AFTER.fetch_add(1, Ordering::AcqRel);
            guest.tail_inject(syscall).await
        }
        guest.tail_inject(syscall).await
    }
}

/// A task killed inside its Tool callback runs nothing more, as under
/// reverie-ptrace (`reverie-ptrace/tests/inject_signal_parity.rs`, the
/// `kill(self, SIGKILL)` case): the injected `kill(self, SIGKILL)` never
/// returns to the Tool, no later step runs, the callback's future is dropped
/// exactly once at the task's exit, and the task dies of SIGKILL with its
/// spawn hold released.
fn reverie_narf_sigkill_in_callback_matches_ptrace() -> TestResult {
    SIGKILL_PID.store(NOT_SEEN, Ordering::Release);
    SIGKILL_REACHED.store(0, Ordering::Release);
    SIGKILL_AFTER.store(0, Ordering::Release);
    SIGKILL_DROPPED.store(0, Ordering::Release);
    let _signal_tables = SignalTables::init();
    result_of((|| {
        let (interceptor, root) = run_hosted::<SigkillInCallback>(CANONICAL_GUEST, ())?;
        let holds = narf_userspace::user_task::__test_open_spawn_holds();
        let reached = SIGKILL_REACHED.load(Ordering::Acquire);
        let after = SIGKILL_AFTER.load(Ordering::Acquire);
        let dropped = SIGKILL_DROPPED.load(Ordering::Acquire);
        let _ = writeln!(
            Writer,
            "    reached {reached} steps after kill {after} dropped {dropped} holds {holds:?}"
        );
        if holds != (0, 0) {
            return Err("a spawn hold outlived the callback");
        }
        if reached != 1 || SIGKILL_PID.load(Ordering::Acquire) <= 0 {
            return Err("the Tool never issued its kill(self, SIGKILL)");
        }
        if after != 0 {
            return Err("an inject ran after the task was killed");
        }
        if dropped != 1 {
            return Err("the killed task's callback future was not dropped exactly once");
        }
        check_teardown(&interceptor, root, 1, LINUX_SIGKILL)?;
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_sigkill_in_callback_matches_ptrace);

// ── vDSO calls reach the Tool ─────────────────────────────────────────────

const LINUX_CLOCK_GETTIME: u32 = 228;
const LINUX_GETTIMEOFDAY: u32 = 96;
const LINUX_TIME: u32 = 201;
const LINUX_GETCPU: u32 = 309;
/// What [`VdsoCalls`] returns for `time`; the vDSO guest exits 0 only if its
/// `__vdso_time` call returned it.
const VDSO_TIME_FROM_TOOL: i64 = 4242;

/// The vDSO syscalls [`VdsoCalls`] saw, in order (numbers, 0 past the end),
/// and the first argument of the first `clock_gettime`.
static VDSO_SEEN: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
static VDSO_SEEN_COUNT: AtomicU64 = AtomicU64::new(0);
static VDSO_CLOCK_ID: AtomicU64 = AtomicU64::new(u64::MAX);

/// Records every `clock_gettime`, `gettimeofday`, `time` and `getcpu` the
/// guest makes, answers `time` with [`VDSO_TIME_FROM_TOOL`], and runs every
/// other syscall unchanged.
#[derive(Debug, Default, Clone, Copy)]
struct VdsoCalls;

#[reverie::tool]
impl Tool for VdsoCalls {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        use reverie::syscalls::SyscallInfo as _;
        let (sysno, args) = syscall.into_parts();
        let number = sysno.id() as u32;
        if [
            LINUX_CLOCK_GETTIME,
            LINUX_GETTIMEOFDAY,
            LINUX_TIME,
            LINUX_GETCPU,
        ]
        .contains(&number)
        {
            let index = VDSO_SEEN_COUNT.fetch_add(1, Ordering::AcqRel) as usize;
            if let Some(slot) = VDSO_SEEN.get(index) {
                slot.store(u64::from(number), Ordering::Release);
            }
            if number == LINUX_CLOCK_GETTIME {
                let _ = VDSO_CLOCK_ID.compare_exchange(
                    u64::MAX,
                    args.arg0 as u64,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
            if number == LINUX_TIME {
                return Ok(VDSO_TIME_FROM_TOOL);
            }
        }
        guest.tail_inject(syscall).await
    }
}

/// Registers the vDSO image for one test and, if this guard is what
/// registered it, unregisters it again on every return path. Kernel-test
/// boots skip the boot-time registration, and while an image is registered
/// every process the loader builds maps the vDSO and gets `AT_SYSINFO_EHDR`,
/// which changes the stack and region layout that later loader tests check
/// (`smoke_userspace_load_user_process_builds_runnable_image` and
/// `smoke_userspace_load_user_process_with_interp`).
struct VdsoRegistration {
    registered_here: bool,
}

impl VdsoRegistration {
    fn register() -> Self {
        let before = narf_userspace::vdso::vdso_registered();
        narf_userspace::vdso::register_vdso_image(
            narf_verification::NARF_VDSO_ELF,
            narf_scheduler::narf_time::cycles_per_ns(),
        );
        Self {
            registered_here: !before,
        }
    }
}

impl Drop for VdsoRegistration {
    fn drop(&mut self) {
        if !self.registered_here {
            return;
        }
        // A refusal leaves the image registered, which `leak_checked`
        // then reports by name.
        if let Err(why) = narf_userspace::vdso::__verification_unregister_vdso_image() {
            let _ = writeln!(Writer, "    vDSO unregistration refused: {why}");
        }
    }
}

/// With a Reverie interceptor installed for a Tool subscribed to the vDSO's
/// syscalls, a guest that calls the vDSO's `clock_gettime`, `gettimeofday`,
/// `time` and `getcpu` (found through `AT_SYSINFO_EHDR`, as a libc finds
/// them) makes those syscalls, the Tool sees each once and in order, and the
/// Tool's `time` result is what the guest's vDSO call returns. This is
/// reverie-ptrace's behaviour, which rewrites the subscribed vDSO entry points
/// into syscalls (`reverie-ptrace/src/vdso.rs`). The harness's reset of the
/// syscall table afterwards restores the counter fast path.
fn reverie_narf_vdso_calls_reach_the_tool() -> TestResult {
    for slot in &VDSO_SEEN {
        slot.store(0, Ordering::Release);
    }
    VDSO_SEEN_COUNT.store(0, Ordering::Release);
    VDSO_CLOCK_ID.store(u64::MAX, Ordering::Release);
    if narf_verification::NARF_VDSO_ELF.is_empty() {
        return TestResult::Fail("the kernel was built without a vDSO image");
    }
    // Kernel-test boots skip the boot-time vDSO registration.
    let _vdso = VdsoRegistration::register();
    result_of((|| {
        if narf_userspace::vdso::clocks_route_through_syscalls() {
            return Err("vDSO clocks already used syscalls before the interceptor");
        }
        let (interceptor, root) = run_hosted::<VdsoCalls>(VDSO_GUEST, ())?;
        let count = VDSO_SEEN_COUNT.load(Ordering::Acquire);
        let seen: Vec<u64> = VDSO_SEEN
            .iter()
            .map(|slot| slot.load(Ordering::Acquire))
            .collect();
        let clock_id = VDSO_CLOCK_ID.load(Ordering::Acquire);
        let _ = writeln!(
            Writer,
            "    vdso syscalls seen {count} {seen:?} clock id {clock_id:#x}"
        );
        if count == 0 {
            return Err("the Tool saw none of the guest's vDSO calls");
        }
        let expected = [
            LINUX_CLOCK_GETTIME,
            LINUX_GETTIMEOFDAY,
            LINUX_TIME,
            LINUX_GETCPU,
        ];
        if count != expected.len() as u64
            || seen
                .iter()
                .zip(expected.iter())
                .any(|(&seen, &want)| seen != u64::from(want))
        {
            return Err("the Tool did not see each vDSO call exactly once, in order");
        }
        if clock_id != 1 {
            return Err("the Tool's clock_gettime did not carry CLOCK_MONOTONIC");
        }
        let exits = check_teardown(&interceptor, root, 1, 0);
        if narf_userspace::vdso::clocks_route_through_syscalls() {
            return Err("the syscall table reset did not restore the vDSO counter path");
        }
        exits?;
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_vdso_calls_reach_the_tool);

// ── Thread and process exit statuses ─────────────────────────────────────

/// Every exit hook [`ExitStatuses`] saw: `(is_thread, tid or pid, raw wait
/// status)`, in the order the host delivered them.
static EXIT_STATUS_LOG: IrqSafeSpinLock<Vec<(bool, i32, i32)>> = IrqSafeSpinLock::new(Vec::new());

/// Records the status each `on_exit_thread` and `on_exit_process` receives
/// and runs every syscall unchanged.
#[derive(Debug, Default, Clone, Copy)]
struct ExitStatuses;

#[reverie::tool]
impl Tool for ExitStatuses {
    type GlobalState = ();
    type ThreadState = ();

    async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        _global_state: &G,
        _thread_state: Self::ThreadState,
        exit_status: reverie::ExitStatus,
    ) -> Result<(), reverie::Error> {
        EXIT_STATUS_LOG
            .lock()
            .push((true, tid.as_raw(), exit_status.into_raw()));
        Ok(())
    }

    async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        _global_state: &G,
        exit_status: reverie::ExitStatus,
    ) -> Result<(), reverie::Error> {
        EXIT_STATUS_LOG
            .lock()
            .push((false, pid.as_raw(), exit_status.into_raw()));
        Ok(())
    }
}

/// `on_exit_thread` receives the thread's own exit status and
/// `on_exit_process` the status `wait4` reports for the process, as
/// reverie-ptrace delivers them (each thread's own `waitpid` status, and the
/// leader's for the process). The guest (`guests/mtexit_x86_64.S`) forks a
/// child whose leader calls `exit(3)` before its thread calls `exit(5)`, so
/// the child's status is 5, the last thread's code (the parent checks this
/// with `wait4`); then the root's thread calls `exit(6)` before the root calls
/// `exit_group(7)`, so the root process's status is 7.
fn reverie_narf_thread_and_process_exit_statuses() -> TestResult {
    EXIT_STATUS_LOG.lock().clear();
    result_of((|| {
        let (interceptor, root) = run_hosted::<ExitStatuses>(MTEXIT_GUEST, ())?;
        let log = EXIT_STATUS_LOG.lock().clone();
        for (thread, id, status) in &log {
            let kind = if *thread { "thread" } else { "process" };
            let _ = writeln!(Writer, "    on_exit_{kind} {id} status {status:#x}");
        }
        let root_pid = root.pid as i32;
        let exits = check_teardown(&interceptor, root, 4, 0x700)?;
        let threads: Vec<(usize, i32, i32)> = log
            .iter()
            .enumerate()
            .filter(|(_, (thread, _, _))| *thread)
            .map(|(at, (_, id, status))| (at, *id, *status))
            .collect();
        let processes: Vec<(usize, i32, i32)> = log
            .iter()
            .enumerate()
            .filter(|(_, (thread, _, _))| !*thread)
            .map(|(at, (_, id, status))| (at, *id, *status))
            .collect();
        if threads.len() != 4 || processes.len() != 2 {
            return Err("the Tool did not see four thread exits and two process exits");
        }
        let thread_with = |status: i32| threads.iter().find(|entry| entry.2 == status).copied();
        let (Some(child_leader), Some(child_thread), Some(root_thread), Some(root_leader)) = (
            thread_with(0x300),
            thread_with(0x500),
            thread_with(0x600),
            thread_with(0x700),
        ) else {
            return Err("a thread's on_exit_thread did not carry its own exit code");
        };
        if root_leader.1 != root_pid {
            return Err("the root's exit_group(7) reached a thread other than the root");
        }
        let Some(child_process) = processes.iter().find(|entry| entry.1 == child_leader.1) else {
            return Err("the child process's exit never reached on_exit_process");
        };
        if child_process.2 != 0x500 {
            return Err(
                "on_exit_process did not carry the child's wait4 status (its last thread's 5)",
            );
        }
        let Some(root_process) = processes.iter().find(|entry| entry.1 == root_pid) else {
            return Err("the root process's exit never reached on_exit_process");
        };
        if root_process.2 != 0x700 {
            return Err("on_exit_process did not carry the root's exit_group status");
        }
        if child_process.0 < child_leader.0.max(child_thread.0)
            || root_process.0 < root_thread.0.max(root_leader.0)
        {
            return Err("a process's exit reached the Tool before one of its threads' exits");
        }
        // The interceptor's records bind the same (tid, status) pairs the
        // Tool saw; Linux tids are reused once reaped, so compare as sets.
        let mut recorded: Vec<(i32, i32)> = exits
            .iter()
            .map(|exit| (exit.tid.as_raw(), exit.wstatus))
            .collect();
        let mut seen: Vec<(i32, i32)> = threads.iter().map(|entry| (entry.1, entry.2)).collect();
        recorded.sort_unstable();
        seen.sort_unstable();
        if recorded != seen {
            return Err("the interceptor recorded thread statuses the Tool did not see");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_thread_and_process_exit_statuses);

// ── counter2: per-thread and per-process counts ──────────────────────────

const LINUX_FUTEX: u32 = 202;
const LINUX_SET_TID_ADDRESS: u32 = 218;
const LINUX_EXIT_GROUP: u32 = 231;

/// Every new (not re-executed) syscall entry [`EntryWatch`] saw, as
/// `(scheduler task id, Linux syscall number)`, in order.
static WATCHED_ENTRIES: IrqSafeSpinLock<Vec<(u64, u32)>> = IrqSafeSpinLock::new(Vec::new());
/// A task exit [`EntryWatch`] saw: the scheduler task id, and the Linux
/// thread and process IDs as the exit began, if the kernel still had them.
type WatchedExit = (u64, Option<(i32, i32)>);
/// Every task exit [`EntryWatch`] saw, in order.
static WATCHED_EXITS: IrqSafeSpinLock<Vec<WatchedExit>> = IrqSafeSpinLock::new(Vec::new());
/// Every report counter2's thread-exit reporter received, as `(thread ID,
/// syscall count)`.
static COUNTER2_REPORTS: IrqSafeSpinLock<Vec<(i32, u64)>> = IrqSafeSpinLock::new(Vec::new());

fn record_counter2_thread_exit(tid: Pid, syscalls: u64) {
    COUNTER2_REPORTS.lock().push((tid.as_raw(), syscalls));
}

/// Records every new syscall entry and every task exit at the dispatcher,
/// outside the Reverie interceptor it wraps, and forwards every call to it.
struct EntryWatch {
    inner: Box<dyn SyscallInterceptor>,
}

impl SyscallInterceptor for EntryWatch {
    fn intercepts_vdso_calls(&self) -> bool {
        self.inner.intercepts_vdso_calls()
    }

    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        if !invocation.park_reexecution {
            WATCHED_ENTRIES.lock().push((
                invocation.task_id,
                invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK,
            ));
        }
        self.inner.on_syscall_enter(invocation, native)
    }

    fn on_syscall_return(
        &self,
        invocation: &SyscallInvocation,
        result: SyscallReturn,
    ) -> SyscallReturn {
        self.inner.on_syscall_return(invocation, result)
    }

    fn on_syscall_context_managed(&self, invocation: &SyscallInvocation) {
        self.inner.on_syscall_context_managed(invocation);
    }

    fn on_task_start(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        self.inner.on_task_start(task_id, native);
    }

    fn on_task_exec(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        self.inner.on_task_exec(task_id, native);
    }

    fn on_task_exit(&self, task_id: u64, pid: u64, wstatus: i32, process_wstatus: i32) {
        let ids = tool_view::linux_task_ids(task_id).map(|ids| (ids.tid as i32, ids.pid as i32));
        self.inner
            .on_task_exit(task_id, pid, wstatus, process_wstatus);
        WATCHED_EXITS.lock().push((task_id, ids));
    }
}

/// Whether `numbers` is `before`, then zero or more futex calls, then
/// `after`.
fn with_futex_waits(numbers: &[u32], before: &[u32], after: &[u32]) -> bool {
    numbers.len() >= before.len() + after.len()
        && numbers.starts_with(before)
        && numbers.ends_with(after)
        && numbers[before.len()..numbers.len() - after.len()]
            .iter()
            .all(|&number| number == LINUX_FUTEX)
}

/// counter2, unmodified from reverie-examples, keeps a count per thread and
/// one per process, and reaches its global totals only through its exit
/// hooks. Over the thread exit-status guest (`guests/mtexit_x86_64.S`: two
/// processes of two threads each), the count each thread reports at its exit
/// is the number of syscalls that thread made, and the totals are their sum,
/// 2 processes and 4 threads.
///
/// What each thread makes is read off the assembly and checked against a
/// watch outside the Reverie interceptor: the root's leader makes fork,
/// wait4, clone, some futex waits and exit_group, and its thread exit; the
/// child's leader makes set_tid_address, clone and exit, and its thread some
/// futex waits and exit. A futex wait that blocks is re-executed when woken,
/// which the dispatcher flags and counter2 sees as the one event already in
/// flight, so the watch leaves re-executions out.
fn reverie_narf_counter2_thread_and_process_counts() -> TestResult {
    WATCHED_ENTRIES.lock().clear();
    WATCHED_EXITS.lock().clear();
    COUNTER2_REPORTS.lock().clear();
    result_of((|| {
        let interceptor = ReverieInterceptor::<counter2::CounterLocal>::with_tool_constructor(
            (),
            |pid, config| {
                <counter2::CounterLocal as Tool>::new(pid, config)
                    .with_thread_exit_reporter(record_counter2_thread_exit)
            },
        )
        .map_err(|_| "NarfToolHost::new refused the Tool")?;
        let root = run_guest(
            MTEXIT_GUEST,
            Box::new(EntryWatch {
                inner: interceptor.boxed(),
            }),
            |root| {
                interceptor
                    .host_root(root.task_id)
                    .map_err(|_| "register_root refused the root task")
            },
        )?;
        let root_pid = root.pid as i32;
        check_teardown(&interceptor, root, 4, 0x700)?;
        let entries = core::mem::take(&mut *WATCHED_ENTRIES.lock());
        let exits = core::mem::take(&mut *WATCHED_EXITS.lock());
        let reports = core::mem::take(&mut *COUNTER2_REPORTS.lock());
        // Each exited task's thread ID, process ID and syscalls, in order;
        // the scheduler never reuses a task id.
        let mut tasks: Vec<(i32, i32, Vec<u32>)> = Vec::new();
        for (task_id, ids) in &exits {
            let Some((tid, pid)) = *ids else {
                return Err("a task's Linux IDs were gone when its exit began");
            };
            let numbers = entries
                .iter()
                .filter(|(task, _)| task == task_id)
                .map(|(_, number)| *number)
                .collect();
            tasks.push((tid, pid, numbers));
        }
        for (tid, pid, numbers) in &tasks {
            let _ = writeln!(
                Writer,
                "    thread {tid} of process {pid}: syscalls {numbers:?}"
            );
        }
        for (tid, count) in &reports {
            let _ = writeln!(Writer, "    counter2-local thread={tid} syscalls={count}");
        }
        if tasks.len() != 4 {
            return Err("the watch did not see four task exits");
        }
        // Which of the root's leader, the root's thread, the child's leader
        // and the child's thread each task was.
        let mut roles = [0usize; 4];
        for (tid, pid, numbers) in &tasks {
            let (role, matches) = match (*pid == root_pid, tid == pid) {
                (true, true) => (
                    0,
                    with_futex_waits(
                        numbers,
                        &[LINUX_FORK, LINUX_WAIT4, LINUX_CLONE],
                        &[LINUX_EXIT_GROUP],
                    ),
                ),
                (true, false) => (1, numbers[..] == [LINUX_EXIT]),
                (false, true) => (
                    2,
                    numbers[..] == [LINUX_SET_TID_ADDRESS, LINUX_CLONE, LINUX_EXIT],
                ),
                (false, false) => (3, with_futex_waits(numbers, &[], &[LINUX_EXIT])),
            };
            if !matches {
                return Err("a thread's syscalls are not the ones the guest's assembly makes");
            }
            roles[role] += 1;
        }
        if roles != [1, 1, 1, 1] {
            return Err("the tree was not a leader and a thread in each of two processes");
        }
        if reports.len() != 4 {
            return Err("counter2's thread-exit reporter did not report each of the four threads");
        }
        // Linux thread IDs are reused once reaped, so compare as multisets.
        let mut reported = reports;
        let mut made: Vec<(i32, u64)> = tasks
            .iter()
            .map(|(tid, _, numbers)| (*tid, numbers.len() as u64))
            .collect();
        reported.sort_unstable();
        made.sort_unstable();
        if reported != made {
            return Err("counter2's per-thread counts are not the threads' syscall counts");
        }
        let made_total: u64 = made.iter().map(|(_, count)| count).sum();
        let totals = interceptor.host().global().totals();
        if totals != (made_total, 2, 4) {
            let _ = writeln!(
                Writer,
                "    counter2 totals {totals:?}, expected ({made_total}, 2, 4)"
            );
            return Err("counter2's totals are not the tree's syscalls, 2 processes and 4 threads");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_counter2_thread_and_process_counts);

// ── strace: a line per syscall event and per exit ────────────────────────

/// Every line strace printed, in order.
static STRACE_LINES: IrqSafeSpinLock<Vec<alloc::string::String>> = IrqSafeSpinLock::new(Vec::new());

fn record_strace_line(line: &str) {
    STRACE_LINES.lock().push(alloc::string::String::from(line));
}

/// A thread strace printed an exit line for: its thread ID, its syscall
/// lines, the exit line's status, and the exit line's index among the thread
/// exit lines.
type StraceThread<'a> = (i32, Vec<&'a str>, &'a str, usize);

/// strace, compiled from the source files reverie-examples builds its Linux
/// binary from, prints a line for each syscall event and one at each
/// thread's and each process's exit. Over the thread exit-status guest
/// (`guests/mtexit_x86_64.S`), each thread's lines up to its exit line name,
/// in order, the syscalls the watch outside the Reverie interceptor saw that
/// thread make, which are the ones the assembly makes; the lines for fork,
/// wait4, set_tid_address and clone carry the thread IDs those calls return,
/// and each exit and exit_group line its code. Each thread's exit line
/// carries its own status, and each process's line follows both of its
/// threads' lines and carries the status wait4 reports for it.
fn reverie_narf_strace_prints_each_event_and_exit() -> TestResult {
    WATCHED_ENTRIES.lock().clear();
    WATCHED_EXITS.lock().clear();
    STRACE_LINES.lock().clear();
    reverie_narf_tools::set_eprintln_sink(record_strace_line);
    result_of((|| {
        let interceptor = ReverieInterceptor::<strace::Strace>::with_tool_constructor(
            strace::Config::default(),
            <strace::Strace as Tool>::new,
        )
        .map_err(|_| "NarfToolHost::new refused the Tool")?;
        let root = run_guest(
            MTEXIT_GUEST,
            Box::new(EntryWatch {
                inner: interceptor.boxed(),
            }),
            |root| {
                interceptor
                    .host_root(root.task_id)
                    .map_err(|_| "register_root refused the root task")
            },
        )?;
        let root_pid = root.pid as i32;
        check_teardown(&interceptor, root, 4, 0x700)?;
        let entries = core::mem::take(&mut *WATCHED_ENTRIES.lock());
        let exits = core::mem::take(&mut *WATCHED_EXITS.lock());
        let lines = core::mem::take(&mut *STRACE_LINES.lock());
        for line in &lines {
            let _ = writeln!(Writer, "    strace: {line}");
        }
        // Each thread ID's syscall lines since its last exit line. At each
        // thread exit line, (thread ID, those lines, status); at each process
        // exit line, (thread exit lines before it, pid, status).
        let mut open = alloc::collections::BTreeMap::<i32, Vec<&str>>::new();
        let mut threads: Vec<(i32, Vec<&str>, &str)> = Vec::new();
        let mut processes: Vec<(usize, i32, &str)> = Vec::new();
        let id = |text: &str| {
            text.parse::<i32>()
                .map_err(|_| "strace printed a malformed ID")
        };
        for line in &lines {
            if let Some(rest) = line.strip_prefix("[pid ") {
                let (tid, call) = rest
                    .split_once("] ")
                    .ok_or("strace printed a malformed syscall line")?;
                open.entry(id(tid)?).or_default().push(call);
                continue;
            }
            let (kind, id_text, status) = line
                .split_once(' ')
                .and_then(|(kind, rest)| {
                    let (id_text, status) = rest.split_once(" exited with status ")?;
                    Some((kind, id_text, status))
                })
                .ok_or("strace printed a line of no form it prints")?;
            match kind {
                "Thread" => {
                    let tid = id(id_text)?;
                    threads.push((tid, open.remove(&tid).unwrap_or_default(), status));
                }
                "Process" => processes.push((threads.len(), id(id_text)?, status)),
                _ => return Err("strace printed a line of no form it prints"),
            }
        }
        if open.values().any(|calls| !calls.is_empty()) {
            return Err("strace printed a syscall line after its thread's exit line");
        }
        if threads.len() != 4 || exits.len() != 4 || processes.len() != 2 {
            return Err("strace did not print four thread exits and two process exits");
        }
        // Each role's thread: the root's leader and thread, the child's
        // leader and thread. A thread ID is reused only once its thread has
        // exited, so the k-th task with a given thread ID to exit has the
        // k-th exit line with that ID.
        let mut used = [false; 4];
        let mut roles: [Option<StraceThread<'_>>; 4] = Default::default();
        for (task_id, ids) in &exits {
            let Some((tid, pid)) = *ids else {
                return Err("a task's Linux IDs were gone when its exit began");
            };
            let Some(at) = (0..threads.len()).find(|&at| !used[at] && threads[at].0 == tid) else {
                return Err("strace printed no exit line for a task that exited");
            };
            used[at] = true;
            let (_, calls, status) = &threads[at];
            let numbers: Vec<u32> = entries
                .iter()
                .filter(|(task, _)| task == task_id)
                .map(|(_, number)| *number)
                .collect();
            if calls.len() != numbers.len() {
                return Err("a thread's syscall lines are not one per syscall it made");
            }
            for (call, number) in calls.iter().zip(&numbers) {
                let named = Sysno::new(*number as usize).is_some_and(|sysno| {
                    call.strip_prefix(sysno.name())
                        .is_some_and(|rest| rest.starts_with('('))
                });
                if !named {
                    return Err("a syscall line does not name the syscall the thread made");
                }
            }
            let (role, made) = match (pid == root_pid, tid == pid) {
                (true, true) => (
                    0,
                    with_futex_waits(
                        &numbers,
                        &[LINUX_FORK, LINUX_WAIT4, LINUX_CLONE],
                        &[LINUX_EXIT_GROUP],
                    ),
                ),
                (true, false) => (1, numbers[..] == [LINUX_EXIT]),
                (false, true) => (
                    2,
                    numbers[..] == [LINUX_SET_TID_ADDRESS, LINUX_CLONE, LINUX_EXIT],
                ),
                (false, false) => (3, with_futex_waits(&numbers, &[], &[LINUX_EXIT])),
            };
            if !made {
                return Err("a thread's syscalls are not the ones the guest's assembly makes");
            }
            if roles[role]
                .replace((tid, calls.clone(), *status, at))
                .is_some()
            {
                return Err("the tree was not a leader and a thread in each of two processes");
            }
        }
        let [Some(root_leader), Some(root_thread), Some(child_leader), Some(child_thread)] = roles
        else {
            return Err("the tree was not a leader and a thread in each of two processes");
        };
        let value = |call: &str| {
            call.rsplit_once(" = ")
                .and_then(|(_, value)| value.parse::<i64>().ok())
        };
        let child = i64::from(child_leader.0);
        let (root_calls, child_calls) = (&root_leader.1, &child_leader.1);
        if value(root_calls[0]) != Some(child)
            || value(root_calls[1]) != Some(child)
            || value(root_calls[2]) != Some(i64::from(root_thread.0))
            || root_calls.last() != Some(&"exit_group(7) = ?")
        {
            return Err(
                "the root's lines do not carry fork's, wait4's and clone's results and \
                 exit_group(7)",
            );
        }
        if value(child_calls[0]) != Some(child)
            || value(child_calls[1]) != Some(i64::from(child_thread.0))
            || child_calls[2] != "exit(3) = ?"
        {
            return Err(
                "the child's lines do not carry set_tid_address's and clone's results and \
                 exit(3)",
            );
        }
        if root_thread.1[..] != ["exit(6) = ?"] || child_thread.1.last() != Some(&"exit(5) = ?") {
            return Err("a thread's exit line does not carry its exit code");
        }
        if [
            (&root_leader, "Exited(7)"),
            (&root_thread, "Exited(6)"),
            (&child_leader, "Exited(3)"),
            (&child_thread, "Exited(5)"),
        ]
        .iter()
        .any(|(thread, status)| thread.2 != *status)
        {
            return Err("a thread's exit line does not carry its own status");
        }
        for (last_thread, pid, status) in [
            (
                child_leader.3.max(child_thread.3),
                child_leader.0,
                "Exited(5)",
            ),
            (root_leader.3.max(root_thread.3), root_pid, "Exited(7)"),
        ] {
            let Some(&(after, _, printed)) = processes.iter().find(|entry| entry.1 == pid) else {
                return Err("strace printed no exit line for a process");
            };
            if after <= last_thread || printed != status {
                return Err(
                    "a process's exit line does not follow its threads' lines or carry the \
                     status wait4 reports for it",
                );
            }
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_strace_prints_each_event_and_exit);

// ── chaos: reads failed with EINTR or cut to one byte ────────────────────

static CHAOS_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_CHAOS"));

const LINUX_CLOSE: u32 = 3;
const LINUX_RECVFROM: u32 = 45;
const LINUX_SOCKETPAIR: u32 = 53;
/// The chaos guest's pipe-T read end and write end (guests/chaos_x86_64.S
/// fixes both).
const CHAOS_T_READ_FD: u64 = 7;
const CHAOS_T_WRITE_FD: u32 = 8;

/// Every line chaos printed, in order, with the scheduler task that printed
/// it.
static CHAOS_LINES: IrqSafeSpinLock<Vec<(u64, alloc::string::String)>> =
    IrqSafeSpinLock::new(Vec::new());
/// The task that entered a read of pipe T, or 0.
static CHAOS_T_READER: AtomicU64 = AtomicU64::new(0);
/// Entries the dispatcher flagged as re-executions of a read of pipe T.
static CHAOS_T_REEXECUTIONS: AtomicU64 = AtomicU64::new(0);
/// 0: pipe T not written; 1: written; 2: the write failed.
static CHAOS_T_FILL: AtomicU64 = AtomicU64::new(0);

fn record_chaos_line(line: &str) {
    let task = narf_scheduler::current_task_id().raw();
    CHAOS_LINES
        .lock()
        .push((task, alloc::string::String::from(line)));
}

/// Writes "tu" through task `task_id`'s pipe-T write end, which wakes the
/// chaos guest's thread blocked reading pipe T. A two-byte write to the empty
/// pipe completes on its first poll.
fn fill_chaos_pipe(task_id: u64) -> bool {
    let Some(Some(ops)) = narf_userspace::fd::with_table(task_id, |table| {
        table.get(CHAOS_T_WRITE_FD).map(|entry| entry.ops.clone())
    }) else {
        return false;
    };
    let mut write = ops.write(0, b"tu");
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    matches!(write.as_mut().poll(&mut cx), core::task::Poll::Ready(Ok(2)))
}

/// Remembers which task entered a read of the chaos guest's pipe T, counts
/// the re-executions of those reads, and forwards every call to the
/// interceptor it wraps.
///
/// The thread's second read finds pipe T empty. chaos injects it cut to one
/// byte, and the kernel parks the thread with chaos's call suspended at that
/// inject. The kernel's descriptor-park observer runs once the read has armed
/// its waker and before the thread stops running, and [`FillOnPark`] then
/// writes "tu" into the pipe on the thread's own kernel path. The wake that
/// write causes reaches the armed waker before the thread switches away, and
/// the read is re-executed: the host runs the read chaos injected again and
/// hands chaos its value.
struct ChaosWatch {
    inner: Box<dyn SyscallInterceptor>,
}

impl SyscallInterceptor for ChaosWatch {
    fn intercepts_vdso_calls(&self) -> bool {
        self.inner.intercepts_vdso_calls()
    }

    fn on_syscall_enter(
        &self,
        invocation: &SyscallInvocation,
        native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        if invocation.raw_number & reverie_narf_core::NARF_SYSCALL_NUMBER_MASK == LINUX_READ
            && invocation.args.arg0 == CHAOS_T_READ_FD
        {
            if invocation.park_reexecution {
                CHAOS_T_REEXECUTIONS.fetch_add(1, Ordering::AcqRel);
            } else {
                CHAOS_T_READER.store(invocation.task_id, Ordering::Release);
            }
        }
        self.inner.on_syscall_enter(invocation, native)
    }

    fn on_syscall_return(
        &self,
        invocation: &SyscallInvocation,
        result: SyscallReturn,
    ) -> SyscallReturn {
        self.inner.on_syscall_return(invocation, result)
    }

    fn on_syscall_context_managed(&self, invocation: &SyscallInvocation) {
        self.inner.on_syscall_context_managed(invocation);
    }

    fn on_task_start(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        self.inner.on_task_start(task_id, native);
    }

    fn on_task_exec(&self, task_id: u64, native: &mut dyn NativeSyscallTransition) {
        self.inner.on_task_exec(task_id, native);
    }

    fn on_task_exit(&self, task_id: u64, pid: u64, wstatus: i32, process_wstatus: i32) {
        self.inner
            .on_task_exit(task_id, pid, wstatus, process_wstatus);
    }
}

/// Installs the kernel's descriptor-park observer for one chaos-guest run,
/// and restores the previous observer when dropped. The observer writes "tu"
/// into pipe T once, when the task [`ChaosWatch`] saw enter a read of pipe T
/// parks (`narf_userspace::handlers::__verification_swap_fd_park_observer`).
struct FillOnPark(Option<fn(u64)>);

impl FillOnPark {
    fn install() -> Self {
        CHAOS_T_READER.store(0, Ordering::Release);
        CHAOS_T_FILL.store(0, Ordering::Release);
        Self(narf_userspace::handlers::__verification_swap_fd_park_observer(Some(fill_on_park)))
    }
}

impl Drop for FillOnPark {
    fn drop(&mut self) {
        narf_userspace::handlers::__verification_swap_fd_park_observer(self.0);
    }
}

fn fill_on_park(task_id: u64) {
    if task_id == 0 || task_id != CHAOS_T_READER.load(Ordering::Acquire) {
        return;
    }
    if CHAOS_T_FILL
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
        && !fill_chaos_pipe(task_id)
    {
        CHAOS_T_FILL.store(2, Ordering::Release);
    }
}

/// A chaos line split into its process ID, its event number and the syscall
/// as printed: `[pid=<pid>, n=<n>] <syscall>`. With the default options chaos
/// prints no `SKIPPED` line, so that form is refused too.
fn chaos_line(line: &str) -> Option<(i32, u64, &str)> {
    let (pid, rest) = line.strip_prefix("[pid=")?.split_once(", n=")?;
    let (n, call) = rest.split_once("] ")?;
    Some((pid.parse().ok()?, n.parse().ok()?, call))
}

/// How chaos's line ends for a two-byte read it fails with EINTR, for one it
/// cuts to one byte, and for the chaos guest's two-byte
/// `recvfrom(fd, buf, 2, MSG_PEEK, NULL, NULL)` cut to one byte.
const CHAOS_EINTR: &str = ", 2) = -4";
const CHAOS_CUT: &str = ", 1) = 1";
const CHAOS_PEEK_CUT: &str = ", 1, 2, NULL, NULL) = 1";

/// The calls the chaos guest's root, thread and child make that chaos prints
/// a value for, in order: each call's name and descriptor, and how its line
/// ends.
const CHAOS_ROOT_HANDLED: [(&str, u64, &str); 10] = [
    ("read", 3, CHAOS_EINTR),
    ("read", 3, CHAOS_CUT),
    ("read", 3, CHAOS_EINTR),
    ("read", 3, CHAOS_CUT),
    ("read", 4, CHAOS_EINTR),
    ("recvfrom", 4, CHAOS_PEEK_CUT),
    ("read", 4, CHAOS_EINTR),
    ("read", 4, CHAOS_CUT),
    ("read", 4, CHAOS_EINTR),
    ("read", 4, CHAOS_CUT),
];
const CHAOS_THREAD_HANDLED: [(&str, u64, &str); 4] = [
    ("read", 7, CHAOS_EINTR),
    ("read", 7, CHAOS_CUT),
    ("read", 7, CHAOS_EINTR),
    ("read", 7, CHAOS_CUT),
];
const CHAOS_CHILD_HANDLED: [(&str, u64, &str); 2] =
    [("read", 5, CHAOS_EINTR), ("read", 5, CHAOS_CUT)];

/// chaos, compiled from the source file reverie-examples builds its Linux
/// binary from, fails the first read of each thread, and every other read
/// after it, with EINTR without running it, cuts the reads in between and
/// every recvfrom to one byte, and prints one line per syscall event. A
/// recvfrom it cuts makes the thread's next read fail. Over the chaos guest
/// (`guests/chaos_x86_64.S`), whose root, thread and forked child exit 0 only
/// if each of their reads and the root's recvfrom returned what chaos makes
/// of it:
///
/// * each task's lines name, in order, the syscalls the watch outside the
///   Reverie interceptor saw the task make, which are the ones its assembly
///   makes, one line each;
/// * the lines with a value are, in order, each task's reads and the root's
///   recvfrom. The reads alternate from each task's first between the read
///   as made, with ` = -4`, and the read cut to one byte, with ` = 1`, and
///   the recvfrom takes the place of a cut read: cut to one byte with its
///   MSG_PEEK and null address arguments kept, with ` = 1`. The root reads
///   fd 3 four times, then fd 4 once before its recvfrom of fd 4 and four
///   times after it; the thread reads fd 7 four times and the child fd 5
///   twice. The thread and the child start after a read of the root's that
///   chaos failed, so their first reads fail only if chaos keeps a flag per
///   thread and starts each new one clear. The guest also requires the cut
///   read after the recvfrom to return the byte the recvfrom returned, which
///   the socket still holds only if the call chaos ran kept the guest's
///   MSG_PEEK;
/// * the event numbers of each process's lines are 0 up to its number of
///   events, each once: the root and its thread share one count, and the
///   child, whose Tool is its own, starts from 0;
/// * the thread's cut read of the empty pipe parked, and its one
///   re-execution returned one byte although the pipe then held two, so the
///   re-execution ran the read chaos cut, not the read the thread made.
fn reverie_narf_chaos_interrupts_and_cuts_reads() -> TestResult {
    WATCHED_ENTRIES.lock().clear();
    WATCHED_EXITS.lock().clear();
    CHAOS_LINES.lock().clear();
    CHAOS_T_REEXECUTIONS.store(0, Ordering::Release);
    reverie_narf_tools::set_eprintln_sink(record_chaos_line);
    result_of((|| {
        let interceptor = ReverieInterceptor::<chaos::ChaosTool>::new(chaos::ChaosOpts::default())
            .map_err(|_| "NarfToolHost::new refused the Tool")?;
        let watch = ChaosWatch {
            inner: Box::new(EntryWatch {
                inner: interceptor.boxed(),
            }),
        };
        let fill = FillOnPark::install();
        let root = run_guest(CHAOS_GUEST, Box::new(watch), |root| {
            interceptor
                .host_root(root.task_id)
                .map_err(|_| "register_root refused the root task")
        })?;
        drop(fill);
        let (root_task, root_pid) = (root.task_id, root.pid as i32);
        let lines = core::mem::take(&mut *CHAOS_LINES.lock());
        for (task, line) in &lines {
            let _ = writeln!(Writer, "    chaos: task {task}: {line}");
        }
        let exited = check_teardown(&interceptor, root, 3, 0)?;
        if exited.iter().any(|exit| exit.wstatus != 0) {
            return Err("a task of the chaos guest did not exit 0");
        }
        match CHAOS_T_FILL.load(Ordering::Acquire) {
            1 => {}
            0 => return Err("the thread's read of the empty pipe never parked"),
            _ => return Err("the bytes could not be written into the thread's pipe"),
        }
        if CHAOS_T_REEXECUTIONS.load(Ordering::Acquire) != 1 {
            return Err("the thread's parked read was not re-executed exactly once");
        }
        let entries = core::mem::take(&mut *WATCHED_ENTRIES.lock());
        let exits = core::mem::take(&mut *WATCHED_EXITS.lock());
        let mut parsed = Vec::with_capacity(lines.len());
        for (task, line) in &lines {
            let (pid, n, call) = chaos_line(line)
                .ok_or("chaos printed a line not of the form [pid=<pid>, n=<n>] <syscall>")?;
            parsed.push((*task, pid, n, call));
        }
        let mut child_pid = None;
        for (task_id, ids) in &exits {
            let Some((tid, pid)) = *ids else {
                return Err("a task's Linux IDs were gone when its exit began");
            };
            // Each role: the calls chaos prints a value for, and whether its
            // syscalls are the ones its assembly makes.
            let numbers: Vec<u32> = entries
                .iter()
                .filter(|(task, _)| task == task_id)
                .map(|(_, number)| *number)
                .collect();
            let (handled, made): (&[(&str, u64, &str)], bool) = if *task_id == root_task {
                (
                    &CHAOS_ROOT_HANDLED,
                    with_futex_waits(
                        &numbers,
                        &[
                            LINUX_PIPE2,
                            LINUX_PIPE2,
                            LINUX_PIPE2,
                            LINUX_WRITE,
                            LINUX_WRITE,
                            LINUX_CLOSE,
                            LINUX_CLOSE,
                            LINUX_READ,
                            LINUX_CLONE,
                        ],
                        &[
                            LINUX_FORK,
                            LINUX_WAIT4,
                            LINUX_READ,
                            LINUX_READ,
                            LINUX_READ,
                            LINUX_SOCKETPAIR,
                            LINUX_WRITE,
                            LINUX_READ,
                            LINUX_RECVFROM,
                            LINUX_READ,
                            LINUX_READ,
                            LINUX_READ,
                            LINUX_READ,
                            LINUX_EXIT_GROUP,
                        ],
                    ),
                )
            } else if pid == root_pid && tid != pid {
                (
                    &CHAOS_THREAD_HANDLED,
                    numbers[..] == [LINUX_READ, LINUX_READ, LINUX_READ, LINUX_READ, LINUX_EXIT],
                )
            } else if pid != root_pid && tid == pid && child_pid.replace(pid).is_none() {
                (
                    &CHAOS_CHILD_HANDLED,
                    numbers[..] == [LINUX_READ, LINUX_READ, LINUX_EXIT_GROUP],
                )
            } else {
                return Err("the tree was not a root, a thread of it and a forked child");
            };
            if !made {
                return Err("a task's syscalls are not the ones the guest's assembly makes");
            }
            let own: Vec<(i32, &str)> = parsed
                .iter()
                .filter(|(task, ..)| task == task_id)
                .map(|&(_, pid, _, call)| (pid, call))
                .collect();
            if own.len() != numbers.len() {
                return Err("a task's chaos lines are not one per syscall it made");
            }
            for ((line_pid, call), number) in own.iter().zip(&numbers) {
                let named = Sysno::new(*number as usize).is_some_and(|sysno| {
                    call.strip_prefix(sysno.name())
                        .is_some_and(|rest| rest.starts_with('('))
                });
                if *line_pid != pid || !named {
                    return Err("a chaos line does not name its process and the syscall made");
                }
            }
            let valued: Vec<&str> = own
                .iter()
                .map(|&(_, call)| call)
                .filter(|call| !call.ends_with(')'))
                .collect();
            let as_handled = valued.len() == handled.len()
                && valued.iter().zip(handled).all(|(call, (name, fd, end))| {
                    call.starts_with(&alloc::format!("{name}({fd}, ")) && call.ends_with(end)
                });
            if !as_handled {
                return Err(
                    "a task's lines with values are not its reads and recvfrom as chaos makes them",
                );
            }
        }
        let Some(child_pid) = child_pid else {
            return Err("the tree was not a root, a thread of it and a forked child");
        };
        for pid in [root_pid, child_pid] {
            let mut numbers: Vec<u64> = parsed
                .iter()
                .filter(|&&(_, line_pid, ..)| line_pid == pid)
                .map(|&(_, _, n, _)| n)
                .collect();
            numbers.sort_unstable();
            if !numbers.iter().copied().eq(0..numbers.len() as u64) {
                return Err("a process's event numbers are not 0 up to its events, each once");
            }
        }
        if parsed.len() != entries.len() {
            return Err("chaos printed a line for a task outside the guest's tree");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_chaos_interrupts_and_cuts_reads);

/// `reverie_tool=chaos:<options>` gives chaos the Linux binary's flags
/// (`boot::chaos_options`): each accepted spelling yields exactly the
/// `ChaosOpts` the binary builds from the same flags, and every other one is
/// refused with its reason, before anything is installed.
fn reverie_narf_boot_chaos_options() -> TestResult {
    use crate::boot::chaos_options;
    let opts = |skip, no_read, no_recv, no_interrupt| chaos::ChaosOpts {
        skip,
        no_read,
        no_recv,
        no_interrupt,
    };
    let accepted = [
        (None, opts(0, false, false, false)),
        (Some("no-interrupt"), opts(0, false, false, true)),
        (Some("no-read"), opts(0, true, false, false)),
        (Some("no-recv"), opts(0, false, true, false)),
        (Some("skip=0"), opts(0, false, false, false)),
        (Some("skip=3,no-interrupt"), opts(3, false, false, true)),
        (
            Some("no-recv,no-interrupt,skip=12,no-read"),
            opts(12, true, true, true),
        ),
        (
            Some("skip=18446744073709551615"),
            opts(u64::MAX, false, false, false),
        ),
    ];
    for (options, expected) in accepted {
        if chaos_options(options).as_ref() != Ok(&expected) {
            let _ = writeln!(
                Writer,
                "    options {options:?}: {:?}",
                chaos_options(options)
            );
            return TestResult::Fail("chaos options were not the ones the flags name");
        }
    }
    // Each spelling refused as naming no option, with the word refused.
    let unknown = [
        ("", ""),
        ("no-read,", ""),
        (",no-read", ""),
        ("skip", "skip"),
        ("skip=", "skip="),
        ("skip=+3", "skip=+3"),
        ("skip=-1", "skip=-1"),
        ("skip=0x10", "skip=0x10"),
        ("no-read=1", "no-read=1"),
        ("No-Read", "No-Read"),
        ("interrupt", "interrupt"),
    ];
    let refused = unknown
        .map(|(options, word)| {
            let reason = alloc::format!(
                "no chaos option {word:?} (known: skip=<N>, no-read, no-recv, no-interrupt)"
            );
            (options, reason)
        })
        .into_iter()
        .chain(
            [
                (
                    "skip=18446744073709551616",
                    "chaos option skip=18446744073709551616 is out of range",
                ),
                ("no-read,no-read", "chaos option no-read given twice"),
                ("skip=1,no-recv,skip=1", "chaos option skip given twice"),
            ]
            .map(|(options, reason)| (options, alloc::string::String::from(reason))),
        );
    for (options, reason) in refused {
        if chaos_options(Some(options)) != Err(reason) {
            let _ = writeln!(
                Writer,
                "    options {options:?}: {:?}",
                chaos_options(Some(options))
            );
            return TestResult::Fail("chaos options were accepted or refused for another reason");
        }
    }
    TestResult::Pass
}
reverie_narf_test!(reverie_narf_boot_chaos_options);

// ── Task creation from lifecycle callbacks ───────────────────────────────

/// Phase marks in [`LIFECYCLE_SPAWN_LOG`].
const THREAD_START_MARK: i64 = 1000;
const POST_EXEC_SPAWN_MARK: i64 = 2000;
const LINUX_ENOSYS: i64 = 38;

/// A phase mark followed by what each of the phase's fork, vfork, clone
/// and clone3 injects returned.
static LIFECYCLE_SPAWN_LOG: IrqSafeSpinLock<Vec<i64>> = IrqSafeSpinLock::new(Vec::new());

/// Injects every task-creating syscall from its thread-start and post-exec
/// callbacks, and runs every syscall unchanged.
#[derive(Debug, Default, Clone, Copy)]
struct LifecycleSpawns;

impl LifecycleSpawns {
    async fn spawn_all<T: reverie::Guest<Self>>(guest: &mut T, mark: i64) {
        let fork = raw_result(guest.inject(reverie::syscalls::Fork::new()).await);
        let vfork = raw_result(guest.inject(reverie::syscalls::Vfork::new()).await);
        let clone = raw_result(guest.inject(reverie::syscalls::Clone::new()).await);
        let clone3 = raw_result(guest.inject(reverie::syscalls::Clone3::new()).await);
        LIFECYCLE_SPAWN_LOG
            .lock()
            .extend([mark, fork, vfork, clone, clone3]);
    }
}

#[reverie::tool]
impl Tool for LifecycleSpawns {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_thread_start<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::Error> {
        Self::spawn_all(guest, THREAD_START_MARK).await;
        Ok(())
    }

    async fn handle_post_exec<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::Errno> {
        Self::spawn_all(guest, POST_EXEC_SPAWN_MARK).await;
        Ok(())
    }
}

/// A task-creating syscall a Tool injects from `handle_thread_start` or
/// `handle_post_exec` is refused with `ENOSYS` without running: the task has
/// no user frame there for a child to start from, so the kernel creates no
/// task, the Tool gets the errno back, and the guest runs on unchanged
/// (execve, then the new image's write and exit, reaped with status 0 and
/// no other task).
fn reverie_narf_lifecycle_spawn_is_refused() -> TestResult {
    LIFECYCLE_SPAWN_LOG.lock().clear();
    let auth = narf_filesystem::bootstrap_mount_authority();
    let Ok(mounted) = narf_filesystem::registry().mount(
        &auth,
        EXEC_MOUNT,
        narf_filesystem::MemFs::with_seeds("rn-exec", &[("prog", CANONICAL_GUEST)]),
    ) else {
        return TestResult::Fail("mounting the exec target failed");
    };
    ROOT_EXECS.store(true, Ordering::Release);
    let outcome = (|| {
        let (interceptor, root) = run_hosted_exec::<LifecycleSpawns>(())?;
        let log = core::mem::take(&mut *LIFECYCLE_SPAWN_LOG.lock());
        let _ = writeln!(Writer, "    lifecycle spawn log {log:?}");
        check_teardown(&interceptor, root, 1, 0)?;
        let refused = -LINUX_ENOSYS;
        let expected = [
            THREAD_START_MARK,
            refused,
            refused,
            refused,
            refused,
            POST_EXEC_SPAWN_MARK,
            refused,
            refused,
            refused,
            refused,
        ];
        if log != expected {
            return Err("a lifecycle callback's task-creating inject was not refused with ENOSYS");
        }
        Ok(TestResult::Pass)
    })();
    ROOT_EXECS.store(false, Ordering::Release);
    let _ = narf_filesystem::registry().unmount(&mounted, EXEC_MOUNT);
    result_of(outcome)
}
reverie_narf_test!(reverie_narf_lifecycle_spawn_is_refused);

// ── Contained fatals abort the hosted tree ───────────────────────────────

/// How many tasks [`ParkInThreadStart`] saw start, and what its setup
/// injects in the second one returned ([`NOT_SEEN`] until they returned).
static PARK_START_COUNT: AtomicU64 = AtomicU64::new(0);
static PARK_START_MMAP: AtomicI64 = AtomicI64::new(NOT_SEEN);
static PARK_START_PIPE: AtomicI64 = AtomicI64::new(NOT_SEEN);
/// Set if the Tool's blocking `poll` ever returned to it.
static PARK_START_POLL_RETURNED: AtomicBool = AtomicBool::new(false);

const LINUX_PROT_READ_WRITE: usize = 0x3;
const LINUX_MAP_PRIVATE_ANONYMOUS: usize = 0x22;
const LINUX_POLLIN: i16 = 0x1;

/// A raw x86_64 syscall for a Tool to inject.
fn raw_syscall(nr: reverie::syscalls::Sysno, args: [usize; 6]) -> reverie::syscalls::Syscall {
    use reverie::syscalls::{Syscall, SyscallArgs};
    Syscall::from_raw(
        nr,
        SyscallArgs::new(args[0], args[1], args[2], args[3], args[4], args[5]),
    )
}

/// In the second task's `handle_thread_start` (the fork guest's child),
/// creates a pipe and injects a non-tail `poll` on its empty read end, which
/// blocks. A lifecycle callback has no syscall to park, so the host reports
/// `NarfFatal::InjectParked`.
#[derive(Debug, Default, Clone, Copy)]
struct ParkInThreadStart;

impl ParkInThreadStart {
    async fn park<T: reverie::Guest<Self>>(guest: &mut T) {
        let mmap = [
            0,
            4096,
            LINUX_PROT_READ_WRITE,
            LINUX_MAP_PRIVATE_ANONYMOUS,
            usize::MAX,
            0,
        ];
        let page = raw_result(
            guest
                .inject(raw_syscall(reverie::syscalls::Sysno::mmap, mmap))
                .await,
        );
        PARK_START_MMAP.store(page, Ordering::Release);
        if page <= 0 {
            return;
        }
        let page = page as usize;
        let pipe2 = [page, 0, 0, 0, 0, 0];
        let pipe = raw_result(
            guest
                .inject(raw_syscall(reverie::syscalls::Sysno::pipe2, pipe2))
                .await,
        );
        PARK_START_PIPE.store(pipe, Ordering::Release);
        if pipe != 0 {
            return;
        }
        let mut memory = guest.memory();
        let mut fds = [0u8; 8];
        let Some(fds_at) = Addr::<u8>::from_raw(page) else {
            return;
        };
        if memory.read_exact(fds_at, &mut fds).is_err() {
            return;
        }
        let read_end = i32::from_ne_bytes([fds[0], fds[1], fds[2], fds[3]]);
        // struct pollfd { int fd; short events; short revents; }
        let mut pollfd = [0u8; 8];
        pollfd[..4].copy_from_slice(&read_end.to_ne_bytes());
        pollfd[4..6].copy_from_slice(&LINUX_POLLIN.to_ne_bytes());
        let Some(pollfd_at) = reverie::syscalls::AddrMut::<u8>::from_raw(page + 8) else {
            return;
        };
        if memory.write_exact(pollfd_at, &pollfd).is_err() {
            return;
        }
        let poll = [page + 8, 1, 20, 0, 0, 0];
        let _ = guest
            .inject(raw_syscall(reverie::syscalls::Sysno::poll, poll))
            .await;
        PARK_START_POLL_RETURNED.store(true, Ordering::Release);
    }
}

#[reverie::tool]
impl Tool for ParkInThreadStart {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_thread_start<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
    ) -> Result<(), reverie::Error> {
        if PARK_START_COUNT.fetch_add(1, Ordering::AcqRel) == 1 {
            Self::park(guest).await;
        }
        Ok(())
    }
}

/// A Tool fatal in a lifecycle callback stops only the hosted process tree,
/// as Linux kills a tracee whose tracer dies (`PTRACE_O_EXITKILL`): a
/// blocking inject from the fork guest child's `handle_thread_start` makes
/// the host report `InjectParked`, the interceptor logs that reason and kills
/// every hosted process with `SIGKILL`, so the root (in `wait4`) and the
/// child both die of signal 9 and every exit still reaches the host. The
/// kernel keeps running: a second hosted run afterwards completes normally.
fn reverie_narf_parked_inject_in_thread_start_aborts_the_tree() -> TestResult {
    PARK_START_COUNT.store(0, Ordering::Release);
    PARK_START_MMAP.store(NOT_SEEN, Ordering::Release);
    PARK_START_PIPE.store(NOT_SEEN, Ordering::Release);
    PARK_START_POLL_RETURNED.store(false, Ordering::Release);
    let _signal_tables = SignalTables::init();
    result_of((|| {
        let (interceptor, root) = run_hosted::<ParkInThreadStart>(FORK_GUEST, ())?;
        let reason = interceptor.abort_reason();
        let _ = writeln!(
            Writer,
            "    starts {} mmap {:#x} pipe2 {} poll returned {} abort reason {reason:?}",
            PARK_START_COUNT.load(Ordering::Acquire),
            PARK_START_MMAP.load(Ordering::Acquire),
            PARK_START_PIPE.load(Ordering::Acquire),
            PARK_START_POLL_RETURNED.load(Ordering::Acquire),
        );
        if PARK_START_MMAP.load(Ordering::Acquire) <= 0
            || PARK_START_PIPE.load(Ordering::Acquire) != 0
        {
            return Err("the Tool's setup injects in handle_thread_start failed");
        }
        if PARK_START_POLL_RETURNED.load(Ordering::Acquire) {
            return Err("the blocking inject returned to the Tool");
        }
        let named = reason.as_deref().is_some_and(|reason| {
            reason.contains("handle_thread_start") && reason.contains("InjectParked")
        });
        if !named {
            return Err("the run was not aborted with the InjectParked reason");
        }
        let exits = check_teardown(&interceptor, root, 2, LINUX_SIGKILL)?;
        if exits
            .iter()
            .any(|exit| exit.task_id != root.task_id && exit.wstatus != LINUX_SIGKILL)
        {
            return Err("the child did not die of SIGKILL");
        }
        check_kernel_still_hosts()?;
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_parked_inject_in_thread_start_aborts_the_tree);

/// After an aborted run, the kernel still hosts a Tool: the canonical guest
/// runs under [`PassThrough`] and exits 0.
fn check_kernel_still_hosts() -> Result<(), &'static str> {
    let (interceptor, root) = run_hosted::<PassThrough>(CANONICAL_GUEST, ())?;
    if interceptor.abort_reason().is_some() {
        return Err("a run after the abort was aborted too");
    }
    check_teardown(&interceptor, root, 1, 0)?;
    Ok(())
}

static SIGPARK_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_SIGPARK"));

const LINUX_SIGUSR1: u32 = 10;

/// How many `read`s [`InjectAfterInterruption`] saw, what its parked inject
/// returned ([`NOT_SEEN`] until it returned), and whether the inject after
/// it ever returned.
static SIGPARK_READS: AtomicU64 = AtomicU64::new(0);
static SIGPARK_INTERRUPTED: AtomicI64 = AtomicI64::new(NOT_SEEN);
static SIGPARK_AFTER_RETURNED: AtomicBool = AtomicBool::new(false);
/// Armed by the Tool just before its blocking inject; the park observer
/// disarms it and raises `SIGUSR1` once.
static SIGPARK_ARMED: AtomicBool = AtomicBool::new(false);
static SIGPARK_RAISED: AtomicU64 = AtomicU64::new(0);
/// Every syscall number [`InjectAfterInterruption`] was handed, in order.
static SIGPARK_SEEN: IrqSafeSpinLock<Vec<i32>> = IrqSafeSpinLock::new(Vec::new());

/// At the sigpark guest's blocking `read`, runs the read as a non-tail inject,
/// which parks; [`RaiseOnPark`] sends the guest `SIGUSR1` while it is parked.
/// The guest's handler enters `getpid`, so the inject returns `ERESTARTSYS`,
/// and the Tool then injects `getpid`: a transition after the interruption.
#[derive(Debug, Default, Clone, Copy)]
struct InjectAfterInterruption;

#[reverie::tool]
impl Tool for InjectAfterInterruption {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: reverie::Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        use reverie::syscalls::SyscallInfo as _;
        SIGPARK_SEEN.lock().push(syscall.number().id());
        if syscall.number() == reverie::syscalls::Sysno::read
            && SIGPARK_READS.fetch_add(1, Ordering::AcqRel) == 0
        {
            SIGPARK_ARMED.store(true, Ordering::Release);
            let parked = raw_result(guest.inject(syscall).await);
            SIGPARK_INTERRUPTED.store(parked, Ordering::Release);
            let _ = guest.inject(reverie::syscalls::Getpid::new()).await;
            SIGPARK_AFTER_RETURNED.store(true, Ordering::Release);
        }
        guest.tail_inject(syscall).await
    }
}

/// Installs the kernel's descriptor-park observer so that the task whose
/// inject [`InjectAfterInterruption`] armed gets `SIGUSR1` once, on its own
/// kernel path after its waker is armed and before it stops running
/// (`narf_userspace::handlers::__verification_swap_fd_park_observer`). The
/// previous observer is restored when this is dropped.
struct RaiseOnPark(Option<fn(u64)>);

impl RaiseOnPark {
    fn install() -> Self {
        SIGPARK_ARMED.store(false, Ordering::Release);
        SIGPARK_RAISED.store(0, Ordering::Release);
        Self(
            narf_userspace::handlers::__verification_swap_fd_park_observer(Some(
                raise_sigusr1_on_park,
            )),
        )
    }
}

impl Drop for RaiseOnPark {
    fn drop(&mut self) {
        narf_userspace::handlers::__verification_swap_fd_park_observer(self.0);
    }
}

fn raise_sigusr1_on_park(task_id: u64) {
    if task_id == 0 || !SIGPARK_ARMED.swap(false, Ordering::AcqRel) {
        return;
    }
    narf_userspace::handlers::raise_signal_pending(task_id, LINUX_SIGUSR1);
    narf_userspace::handlers::wake_signal(task_id);
    SIGPARK_RAISED.fetch_add(1, Ordering::AcqRel);
}

/// A Tool that runs another syscall after a signal interrupted its parked
/// inject stops only the hosted process tree: the host reports
/// `TransitionAfterInterruption`, the interceptor logs that reason and kills
/// the guest with `SIGKILL`, and the guest dies of signal 9 inside its
/// handler instead of completing its `read` and exiting 0. The kernel keeps
/// running: a second hosted run afterwards completes normally.
fn reverie_narf_transition_after_interruption_aborts_the_tree() -> TestResult {
    SIGPARK_READS.store(0, Ordering::Release);
    SIGPARK_INTERRUPTED.store(NOT_SEEN, Ordering::Release);
    SIGPARK_AFTER_RETURNED.store(false, Ordering::Release);
    SIGPARK_SEEN.lock().clear();
    let _signal_tables = SignalTables::init_with_handlers();
    let observer = RaiseOnPark::install();
    let outcome = run_hosted::<InjectAfterInterruption>(SIGPARK_GUEST, ());
    drop(observer);
    result_of((|| {
        let (interceptor, root) = outcome?;
        let reason = interceptor.abort_reason();
        let _ = writeln!(
            Writer,
            "    seen {:?} reads {} raised {} interrupted inject {} inject after {} abort reason {reason:?}",
            SIGPARK_SEEN.lock().clone(),
            SIGPARK_READS.load(Ordering::Acquire),
            SIGPARK_RAISED.load(Ordering::Acquire),
            SIGPARK_INTERRUPTED.load(Ordering::Acquire),
            SIGPARK_AFTER_RETURNED.load(Ordering::Acquire),
        );
        for exit in interceptor.exits() {
            let _ = writeln!(
                Writer,
                "    exit tid {} wstatus {:#x}",
                exit.tid.as_raw(),
                exit.wstatus
            );
        }
        if SIGPARK_RAISED.load(Ordering::Acquire) != 1 {
            return Err("the Tool's inject never parked on the pipe");
        }
        if SIGPARK_INTERRUPTED.load(Ordering::Acquire) != -LINUX_ERESTARTSYS {
            return Err("the interrupted inject did not return -ERESTARTSYS");
        }
        if SIGPARK_AFTER_RETURNED.load(Ordering::Acquire) {
            return Err("the inject after the interruption returned to the Tool");
        }
        let named = reason.as_deref().is_some_and(|reason| {
            reason.contains("handle_syscall") && reason.contains("TransitionAfterInterruption")
        });
        if !named {
            return Err("the run was not aborted with the TransitionAfterInterruption reason");
        }
        check_teardown(&interceptor, root, 1, LINUX_SIGKILL)?;
        check_kernel_still_hosts()?;
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_transition_after_interruption_aborts_the_tree);

// ── Return mapping ────────────────────────────────────────────────────────

/// A native result reaches the Tool as the value the guest would observe:
/// Narf's typed status is folded exactly as the syscall return path folds it.
fn reverie_narf_native_outcome_uses_linux_abi_fold() -> TestResult {
    let cases = [
        (SyscallReturn::ok(16), 16),
        (SyscallReturn::ok((-9i64) as u64), -9),
        // An unimplemented number keeps Linux's -ENOSYS in its value half.
        (SyscallReturn::not_implemented(), -38),
        // A failure status whose value is no errno folds to -EINVAL.
        (SyscallReturn::invalid_op(), -22),
    ];
    for (native, expected) in cases {
        if native.linux_abi_result() != expected {
            return TestResult::Fail("linux_abi_result changed its fold");
        }
        if map_native_outcome(NativeSyscallOutcome::Returned(native))
            != NarfSyscallOutcome::Returned(expected)
        {
            return TestResult::Fail("map_native_outcome diverged from the Linux-ABI fold");
        }
    }
    if map_native_outcome(NativeSyscallOutcome::ContextManaged)
        != NarfSyscallOutcome::ContextManaged
    {
        return TestResult::Fail("a context-managed outcome was not preserved");
    }
    TestResult::Pass
}
reverie_narf_test!(reverie_narf_native_outcome_uses_linux_abi_fold);

// ── Rich parity cell ──────────────────────────────────────────────────────

/// The rich parity guest (guests/rich_x86_64.S): a fixed-address mapping,
/// error returns, `sched_yield`, `mprotect` and `munmap`, each result
/// reflected into a traced write.
static RICH_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_RICH"));

/// Marks where the rich cell's canonical records may begin on the console.
/// Its lines use their own `NARF-CELL-RICH` tag so that neither cell's
/// extraction mistakes the other's observable lines for its own.
const RICH_CELL_BEGIN: &str = "NARF-CELL-RICH begin test=reverie_narf_rich_trace_cell";
/// Printed once the rich cell's run is over; every record precedes it.
const RICH_CELL_RECORDS_END: &str = "NARF-CELL-RICH records-end";

/// The rich N cell of the Linux/Narf parity comparison. It runs the rich
/// guest under the same shared canonical-trace Tool and the same reaping
/// parent as [`reverie_narf_canonical_trace_cell`], and prints the same three
/// observables between its own markers. It is the second test that emits
/// canonical records; the comparator skips each cell's records when deriving
/// the other's. The expected values live in the comparator, not here.
fn reverie_narf_rich_trace_cell() -> TestResult {
    let _ = writeln!(Writer, "{RICH_CELL_BEGIN}");
    result_of((|| {
        let interceptor = ReverieInterceptor::<CanonicalTrace<ConsoleSink>>::new(())
            .map_err(|_| "NarfToolHost::new refused the Tool")?;
        let mut tap = None;
        let (root, reap) = run_guest_with(
            RICH_GUEST,
            interceptor.boxed(),
            |root| {
                tap = Some(tap_stdout(root.task_id)?);
                interceptor
                    .host_root(root.task_id)
                    .map_err(|_| "register_root refused the root task")
            },
            Some(REAPER_GUEST),
        )?;
        let _ = writeln!(Writer, "{RICH_CELL_RECORDS_END}");
        let tap = tap.ok_or("the root's fd 1 was never tapped")?;
        let reap = reap.ok_or("the run did not reap its root")?;
        if reap.reaped_pid != root.pid as i64 {
            let _ = writeln!(
                Writer,
                "    reaping parent's wait4 returned {}",
                reap.reaped_pid
            );
            return Err("the reaping parent's wait4 did not return the root's pid");
        }
        if reap.wstatus == REAPER_STATUS_SENTINEL {
            return Err("the reaping parent's wait4 reaped the root but stored no status");
        }
        if reap.second_wait != -LINUX_ECHILD {
            let _ = writeln!(Writer, "    second wait4 returned {}", reap.second_wait);
            return Err("the reaping parent's second wait4 did not report ECHILD");
        }
        if reap.parent_staged != Some(0) {
            let _ = writeln!(Writer, "    reaping parent staged {:?}", reap.parent_staged);
            return Err("the reaping parent did not exit 0");
        }
        if reap.parent.pid == root.pid {
            return Err("the reaping parent and the root share a pid");
        }
        if reap.staged != Some(reap.wstatus) {
            let _ = writeln!(Writer, "    staged termination {:?}", reap.staged);
            return Err("the reaped wait status differs from the termination staged at exit");
        }
        let exits = check_teardown(&interceptor, root, 1, reap.wstatus)?;
        if exits.len() != 1 || !exits[0].process_exited {
            return Err("the root's exit did not end its process in the host");
        }
        // The observable lines come only after every in-kernel check above
        // has passed, so a cell whose run failed those checks has no stdout
        // or exit line for the comparator to extract. The exit value itself
        // is the comparator's to judge, so it is printed before the value
        // check below.
        let captured = tap.captured.lock().clone();
        let mut line = alloc::string::String::new();
        for byte in &captured {
            let _ = write!(line, "{byte:02x}");
        }
        let _ = writeln!(
            Writer,
            "NARF-CELL-RICH stdout-capture=fd1-tap bytes={} hex={line}",
            captured.len()
        );
        let _ = writeln!(
            Writer,
            "NARF-CELL-RICH exit wstatus={:#06x} source=guest-parent-wait4",
            reap.wstatus
        );
        if reap.wstatus != 0 {
            return Err("the root did not exit 0");
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_rich_trace_cell);

// ── The PML4[1] window ────────────────────────────────────────────────────

/// The window guest (guests/window_x86_64.S): unmapped-address copies and a
/// fixed mapping in the user half above 0x80_4000_0000, each result reported
/// as one word on fd 1.
static WINDOW_GUEST: &[u8] = include_bytes!(env!("REVERIE_NARF_GUEST_WINDOW"));

/// What the window guest reports on Linux, word by word (see the guest's
/// table): the unmapped probe address faults both ways without consuming the
/// queued bytes, and the fixed mapping at 0x81_0000_0000 is created, holds
/// user stores, is readable by the kernel, is private to the parent across
/// fork, and faults again once unmapped.
const WINDOW_EXPECTED: [i64; 12] = [-14, -14, 16, 1, 0x81_0000_0000, 1, 16, 1, 1, 0, 0, -14];

/// Runs every syscall natively; the window test observes only the guest.
struct Untouched;

impl SyscallInterceptor for Untouched {
    fn on_syscall_enter(
        &self,
        _invocation: &SyscallInvocation,
        _native: &mut dyn NativeSyscallTransition,
    ) -> SyscallInterception {
        SyscallInterception::Continue
    }
}

/// The user half between 0x80_4000_0000 and 0x100_0000_0000 is ordinary
/// user address space: nothing the kernel maps for itself is reachable
/// there. `read(2)` and `write(2)` on an unmapped window address fail with
/// `EFAULT` instead of copying physical memory, and a fixed mapping there
/// works for user stores and kernel copies alike and is not shared with a
/// forked child, as on Linux.
fn reverie_narf_pml4_1_window_is_user_address_space() -> TestResult {
    result_of((|| {
        let mut tap = None;
        let (root, reap) = run_guest_with(
            WINDOW_GUEST,
            Box::new(Untouched),
            |root| {
                tap = Some(tap_console(root.task_id, false)?);
                Ok(())
            },
            Some(REAPER_GUEST),
        )?;
        let captured = tap
            .ok_or("the root's fd 1 was never tapped")?
            .captured
            .lock()
            .clone();
        let words: Vec<i64> = captured
            .chunks_exact(8)
            .map(|word| i64::from_le_bytes(word.try_into().unwrap()))
            .collect();
        let wstatus = reap
            .ok_or("the run did not reap its root")?
            .root_wstatus(root)?;
        let _ = writeln!(
            Writer,
            "    window guest wstatus {wstatus:#06x} bytes {} words {words:?}",
            captured.len()
        );
        if wstatus != 0 {
            return Err("the window guest did not exit 0");
        }
        if captured.len() != WINDOW_EXPECTED.len() * 8 {
            return Err("the window guest did not report every word");
        }
        for (index, (got, want)) in words.iter().zip(WINDOW_EXPECTED).enumerate() {
            if *got != want {
                let _ = writeln!(Writer, "    word {index}: got {got:#x}, Linux {want:#x}");
                return Err("a window observation differs from Linux");
            }
        }
        Ok(TestResult::Pass)
    })())
}
reverie_narf_test!(reverie_narf_pml4_1_window_is_user_address_space);
