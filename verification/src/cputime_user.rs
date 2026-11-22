//! Ring-3 CPU-time accounting (`verification/cputime`).
//!
//! Real user code through the real boundaries the accounting hooks sit on:
//! the SYSCALL entry/SYSRET tail and the interrupt-gate `common_trap`
//! (x86_64), the EL0 synchronous and IRQ vectors (aarch64), and the
//! executor dispatch and own-stack switches around them. Each program is a
//! few hand-assembled instructions in a fresh address space:
//!
//! * a pure user-mode loop must be charged to `utime` and the CPUs' `user`
//!   column;
//! * a loop of `getppid` system calls must be charged mostly to `stime` and
//!   the `system` column;
//! * the user loop under a fast timer must leave the timer's interrupt time
//!   in the `irq` column and out of the task;
//! * a reaped child's times must land in its parent's `cutime`/`cstime`.
//!
//! The per-task numbers are checked against the CPU columns, which are
//! accounted independently on every CPU.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::{AddressSpace, Region, RegionPerms, VirtAddr};
use narf_scheduler::{CpuTimes, TaskTimes};
use narf_userspace::{install_core_syscalls, install_global, Syscall, SyscallTable, UserProcess};

const CODE_VADDR: u64 = 0x0040_0000;
const STACK_VADDR: u64 = 0x0041_0000;
const PAGE_BYTES: u64 = 4096;
const MS: u64 = 1_000_000;

/// What one program's run accounted.
struct Run {
    task: TaskTimes,
    /// Change of the CPU columns, summed over every online CPU.
    cpus: CpuTimes,
    wall_ns: u64,
    switches: u64,
    pid: u64,
    tid: u64,
}

impl Run {
    /// Print what the run accounted (µs), so a failure says by how much and
    /// a pass records the split.
    fn report(&self, label: &str) {
        use core::fmt::Write as _;
        let us = |ns: u64| ns / 1_000;
        let _ = writeln!(
            narf_console::Writer,
            "cputime[{label}]: task utime={}us stime={}us wall={}us; cpus user={}us \
             system={}us irq={}us softirq={}us idle={}us; ctxt +{}",
            us(self.task.utime_ns),
            us(self.task.stime_ns),
            us(self.wall_ns),
            us(self.cpus.user),
            us(self.cpus.system),
            us(self.cpus.irq),
            us(self.cpus.softirq),
            us(self.cpus.idle),
            self.switches,
        );
    }
}

fn sum_cpus() -> CpuTimes {
    let mut sum = CpuTimes::default();
    for cpu in 0..narf_lib::percpu::MAX_CPUS {
        if !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        let t = narf_scheduler::cpu_times(cpu);
        sum.user += t.user;
        sum.nice += t.nice;
        sum.system += t.system;
        sum.idle += t.idle;
        sum.iowait += t.iowait;
        sum.irq += t.irq;
        sum.softirq += t.softirq;
        sum.steal += t.steal;
    }
    sum
}

fn delta(after: CpuTimes, before: CpuTimes) -> CpuTimes {
    CpuTimes {
        user: after.user.saturating_sub(before.user),
        nice: after.nice.saturating_sub(before.nice),
        system: after.system.saturating_sub(before.system),
        idle: after.idle.saturating_sub(before.idle),
        iowait: after.iowait.saturating_sub(before.iowait),
        irq: after.irq.saturating_sub(before.irq),
        softirq: after.softirq.saturating_sub(before.softirq),
        steal: after.steal.saturating_sub(before.steal),
    }
}

pub(crate) fn alloc_page() -> Result<narf_memory::PhysAddr, &'static str> {
    narf_memory::alloc_frame()
        .map(|frame| frame.start_address())
        .map_err(|_| "alloc frame")
}

fn build_process(code: &[u8]) -> Result<UserProcess, &'static str> {
    let code_phys = alloc_page()?;
    let stack_phys = alloc_page()?;
    // SAFETY: fresh 4 KiB frames, written through the kernel direct map; the
    // program is far smaller than a page.
    unsafe {
        core::ptr::write_bytes(code_phys.kernel_mut_ptr::<u8>(), 0, PAGE_BYTES as usize);
        core::ptr::copy_nonoverlapping(code.as_ptr(), code_phys.kernel_mut_ptr::<u8>(), code.len());
        #[cfg(target_arch = "aarch64")]
        narf_arch::aarch64::asm::flush_icache_range(
            code_phys.kernel_ptr::<u8>() as u64,
            code.len() as u64,
        );
    }
    // SAFETY: paging and the frame allocator are live in the kernel-test boot.
    let address_space = unsafe { AddressSpace::new_for_user() }.map_err(|_| "new_for_user")?;
    address_space
        .map_region(Region {
            base: VirtAddr::new(CODE_VADDR),
            len: PAGE_BYTES,
            perms: RegionPerms::READ | RegionPerms::EXEC,
            phys: alloc::vec![code_phys].into(),
        })
        .map_err(|_| "map code")?;
    address_space
        .map_region(Region {
            base: VirtAddr::new(STACK_VADDR),
            len: PAGE_BYTES,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![stack_phys].into(),
        })
        .map_err(|_| "map stack")?;
    // SAFETY: the inactive root owns every mapped frame above.
    unsafe { address_space.materialize() }.map_err(|_| "materialize")?;
    Ok(UserProcess {
        pid: narf_userspace::alloc_pid(),
        address_space: Arc::new(address_space),
        entry: narf_userspace::EntryPoint(VirtAddr::new(CODE_VADDR)),
        stack_top: VirtAddr::new(STACK_VADDR + PAGE_BYTES),
        fs_base: None,
        gs_base: 0,
        entry_arg: None,
        loaded_mappings: Vec::new(),
        program_bias: 0,
        page_in_plan: Vec::new(),
        ia32: false,
        segs: narf_userspace::UserSegments::default(),
    })
}

/// A fast periodic timer for the duration of a run, so the user loop is
/// interrupted (and preempted) many times.
pub(crate) struct FastTimer {
    irqs_were_enabled: bool,
}

impl FastTimer {
    pub(crate) fn start() -> Self {
        let irqs_were_enabled = narf_arch::interrupts_enabled();
        // SAFETY: the interrupt controller and timer are initialized before
        // kernel tests run, and no IRQ-unsafe lock is held here.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            narf_interrupts::x86_64::apic::start_timer(narf_interrupts::VECTOR_TIMER, 10_000);
            #[cfg(target_arch = "aarch64")]
            narf_interrupts::aarch64::timer::start_timer(20_000);
            narf_arch::enable_interrupts();
        }
        Self { irqs_were_enabled }
    }
}

impl Drop for FastTimer {
    fn drop(&mut self) {
        // SAFETY: this guard armed the timer; restore the harness's IRQ state.
        unsafe {
            narf_arch::disable_interrupts();
            #[cfg(target_arch = "x86_64")]
            narf_interrupts::x86_64::apic::stop_timer();
            #[cfg(target_arch = "aarch64")]
            narf_interrupts::aarch64::timer::stop_timer();
            if self.irqs_were_enabled {
                narf_arch::enable_interrupts();
            }
        }
    }
}

/// Spawn `code` as a fresh process, run the executor until it exits, and
/// report what was accounted. With a `parent` (a registered stand-in TaskId)
/// the exited process stays a zombie for that parent to reap; the caller then
/// releases `Run::tid`. Without one it is an orphan and released at exit.
fn run_program(code: &[u8], fast_timer: bool, parent: Option<u64>) -> Result<Run, &'static str> {
    // SAFETY: privileged harness context; the root stays live throughout.
    #[cfg(target_arch = "x86_64")]
    let original_root = unsafe { narf_arch::x86_64::cr::read_cr3() };
    // SAFETY: as above, at EL1.
    #[cfg(target_arch = "aarch64")]
    let original_root = unsafe { narf_arch::aarch64::sysreg::read_ttbr0_el1() };
    narf_userspace::syscall::__test_clear_global();
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::user_task::__test_clear_execve_hook();
    narf_userspace::handlers::__test_reset_task_id_lookup();
    narf_userspace::handlers::__test_wait_reset();
    narf_userspace::handlers::__test_signal_reset();
    narf_userspace::handlers::__test_sigaction_reset();
    narf_userspace::handlers::init_per_task_state();
    narf_scheduler::__reset_queues_for_test();

    let process = build_process(code)?;
    let mut table = SyscallTable::new();
    install_core_syscalls(&mut table);
    install_global(table);
    let previous_as_lookup = narf_userspace::handlers::address_space_lookup();
    narf_userspace::install_address_space_lookup(narf_scheduler::current_address_space);
    narf_userspace::install_task_id_lookup(|| narf_scheduler::current_task_id().raw());
    narf_userspace::install_user_task_hooks();
    let pid = process.pid.raw();
    let pending = narf_userspace::user_task::prepare_user_process_initial(
        process,
        narf_scheduler::TaskSpec::unthrottled(),
    );
    let id = pending.task_id();
    narf_userspace::handlers::register_pid_task_mapping(pid, id.raw());
    if let Some(parent) = parent {
        narf_userspace::handlers::__test_parent_of_set(pid, parent);
    }
    // The task's accumulator outlives its Task: an orphan is released at
    // exit, before this harness can look it up.
    let cputime =
        narf_scheduler::user_task_cputime(id).ok_or("user task has no CPU-time accumulator")?;

    let before = sum_cpus();
    let switches = narf_scheduler::nr_context_switches();
    let t0 = narf_time::monotonic_ns();
    {
        let _timer = fast_timer.then(FastTimer::start);
        pending.spawn();
        narf_scheduler::run_until_empty();
    }
    let wall_ns = narf_time::monotonic_ns() - t0;
    let after = sum_cpus();
    let switches = narf_scheduler::nr_context_switches() - switches;

    // SAFETY: restore the live harness root before user mappings go.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        narf_arch::x86_64::cr::write_cr3(original_root);
    }
    // SAFETY: as above.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        narf_arch::aarch64::sysreg::write_ttbr0_el1(original_root);
    }
    let exited = narf_userspace::task::task_has_exited(id.raw());
    let task = cputime.sample();
    narf_scheduler::__test_clear_published_address_space(id);
    narf_scheduler::__reset_queues_for_test();
    if let Some(parent) = parent {
        narf_userspace::handlers::__test_clear_pending_exits(parent);
    } else {
        narf_userspace::task::release_task(id.raw());
    }
    narf_userspace::handlers::__test_wait_reset();
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::user_task::__test_clear_execve_hook();
    narf_userspace::syscall::__test_clear_global();
    narf_userspace::handlers::restore_address_space_lookup(previous_as_lookup);
    narf_userspace::handlers::__test_reset_task_id_lookup();
    if !exited {
        return Err("user program did not exit");
    }
    Ok(Run {
        task,
        cpus: delta(after, before),
        wall_ns,
        switches,
        pid,
        tid: id.raw(),
    })
}

// ── Programs ────────────────────────────────────────────────────────

const USER_LOOP_ITERATIONS: u32 = 200_000_000;
const SYSCALL_LOOP_ITERATIONS: u32 = 200_000;

#[cfg(target_arch = "x86_64")]
fn user_loop(iterations: u32) -> Vec<u8> {
    let n = iterations.to_le_bytes();
    let exit = Syscall::ExitTask.raw().to_le_bytes();
    alloc::vec![
        0xB9, n[0], n[1], n[2], n[3], // mov ecx, n
        0xFF, 0xC9, // 1: dec ecx
        0x75, 0xFC, // jnz 1b
        0x48, 0xC7, 0xC0, exit[0], exit[1], exit[2], exit[3], // mov rax, exit
        0x0F, 0x05, // syscall
        0xEB, 0xFE, // jmp $
    ]
}

#[cfg(target_arch = "x86_64")]
fn syscall_loop(iterations: u32) -> Vec<u8> {
    let n = iterations.to_le_bytes();
    let getppid = Syscall::GetPpid.raw().to_le_bytes();
    let exit = Syscall::ExitTask.raw().to_le_bytes();
    alloc::vec![
        0xBB, n[0], n[1], n[2], n[3], // mov ebx, n
        0xB8, getppid[0], getppid[1], getppid[2], getppid[3], // 1: mov eax, getppid
        0x0F, 0x05, // syscall
        0xFF, 0xCB, // dec ebx
        0x75, 0xF5, // jnz 1b
        0x48, 0xC7, 0xC0, exit[0], exit[1], exit[2], exit[3], // mov rax, exit
        0x0F, 0x05, // syscall
        0xEB, 0xFE, // jmp $
    ]
}

#[cfg(target_arch = "aarch64")]
pub(crate) mod a64 {
    use alloc::vec::Vec;

    pub fn movz(rd: u32, imm: u16, shift: u32) -> u32 {
        0xd280_0000 | ((shift / 16) << 21) | (u32::from(imm) << 5) | rd
    }

    pub fn movk(rd: u32, imm: u16, shift: u32) -> u32 {
        0xf280_0000 | ((shift / 16) << 21) | (u32::from(imm) << 5) | rd
    }

    pub fn load_u64(code: &mut Vec<u32>, rd: u32, value: u64) {
        code.push(movz(rd, value as u16, 0));
        code.push(movk(rd, (value >> 16) as u16, 16));
        code.push(movk(rd, (value >> 32) as u16, 32));
        code.push(movk(rd, (value >> 48) as u16, 48));
    }

    /// `subs xN, xN, #1`.
    pub fn subs_one(rd: u32) -> u32 {
        0xf100_0400 | (rd << 5) | rd
    }

    /// `b.ne` to `delta` instructions from this one.
    pub fn b_ne(delta: i32) -> u32 {
        0x5400_0001 | (((delta as u32) & 0x7_ffff) << 5)
    }

    pub const SVC0: u32 = 0xd400_0001;
    pub const B_SELF: u32 = 0x1400_0000;

    pub fn bytes(code: &[u32]) -> Vec<u8> {
        code.iter().flat_map(|insn| insn.to_le_bytes()).collect()
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn emit_exit(code: &mut Vec<u32>) {
    a64::load_u64(code, 8, u64::from(Syscall::ExitTask.raw()));
    code.push(a64::movz(0, 0, 0));
    code.push(a64::SVC0);
    code.push(a64::B_SELF);
}

#[cfg(target_arch = "aarch64")]
fn user_loop(iterations: u32) -> Vec<u8> {
    let mut code = Vec::new();
    a64::load_u64(&mut code, 0, u64::from(iterations));
    code.push(a64::subs_one(0));
    code.push(a64::b_ne(-1));
    emit_exit(&mut code);
    a64::bytes(&code)
}

#[cfg(target_arch = "aarch64")]
fn syscall_loop(iterations: u32) -> Vec<u8> {
    let mut code = Vec::new();
    a64::load_u64(&mut code, 19, u64::from(iterations));
    let top = code.len();
    a64::load_u64(&mut code, 8, u64::from(Syscall::GetPpid.raw()));
    code.push(a64::SVC0);
    code.push(a64::subs_one(19));
    let here = code.len();
    code.push(a64::b_ne(top as i32 - here as i32));
    emit_exit(&mut code);
    a64::bytes(&code)
}

// ── Tests ───────────────────────────────────────────────────────────

fn smoke_cputime_user_loop_is_user_time() -> TestResult {
    let run = match run_program(&user_loop(USER_LOOP_ITERATIONS), false, None) {
        Ok(run) => run,
        Err(why) => return TestResult::Fail(why),
    };
    run.report("user-loop");
    let total = run.task.total_ns();
    if total == 0 || run.task.utime_ns * 10 < total * 9 {
        return TestResult::Fail("a user-mode busy loop was not charged to utime");
    }
    // Only this task runs user code: the CPUs' user columns grew by its
    // utime, and nothing of it is system time.
    if run.cpus.user + MS < run.task.utime_ns || run.cpus.user > run.task.utime_ns + MS {
        return TestResult::Fail("CPU user column disagrees with the task's utime");
    }
    if run.task.total_ns() > run.wall_ns + MS {
        return TestResult::Fail("a task was charged more CPU time than elapsed");
    }
    if run.switches == 0 {
        return TestResult::Fail("dispatching the user task did not count a context switch");
    }
    TestResult::Pass
}
kernel_test_in!("verification/cputime", smoke_cputime_user_loop_is_user_time);

fn smoke_cputime_syscall_loop_is_system_time() -> TestResult {
    let run = match run_program(&syscall_loop(SYSCALL_LOOP_ITERATIONS), false, None) {
        Ok(run) => run,
        Err(why) => return TestResult::Fail(why),
    };
    run.report("syscall-loop");
    let total = run.task.total_ns();
    // The handler is system time; the loop's own instructions and the
    // architecture entry/exit stubs that run before the CPU-time hook (the
    // register save, the domain/MTE prologue) are user time, as the entry
    // code before `vtime_user_exit` is on Linux. That share depends on the
    // CPU — under QEMU/KVM x86_64 the split is ~2:1 system, under TCG
    // aarch64's emulated exception entry it is ~1:1 — so require a large
    // system share rather than a majority. A pure user loop's is ~0.1%.
    if total == 0 || run.task.stime_ns * 4 < total {
        return TestResult::Fail("a getppid loop's kernel time was not charged to stime");
    }
    if run.task.utime_ns == 0 {
        return TestResult::Fail("the loop's user instructions were not charged to utime");
    }
    if run.cpus.system + MS < run.task.stime_ns {
        return TestResult::Fail("CPU system column is missing the task's stime");
    }
    if run.cpus.user + MS < run.task.utime_ns || run.cpus.user > run.task.utime_ns + MS {
        return TestResult::Fail("CPU user column disagrees with the task's utime");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/cputime",
    smoke_cputime_syscall_loop_is_system_time
);

fn smoke_cputime_timer_irqs_are_irq_time() -> TestResult {
    let run = match run_program(&user_loop(USER_LOOP_ITERATIONS), true, None) {
        Ok(run) => run,
        Err(why) => return TestResult::Fail(why),
    };
    run.report("timer-irq");
    if run.cpus.irq < 50_000 {
        return TestResult::Fail("timer interrupts during the loop left no irq time");
    }
    // IRQ_TIME_ACCOUNTING: the handler's time is removed from the task it
    // interrupted. Charging it as well would make the task's time plus the
    // interrupt time exceed the wall time the run took.
    if run.task.total_ns() + run.cpus.irq > run.wall_ns + run.wall_ns / 20 + 2 * MS {
        return TestResult::Fail("interrupt time was also charged to the interrupted task");
    }
    if run.task.utime_ns * 2 < run.wall_ns.saturating_sub(run.cpus.irq) {
        return TestResult::Fail("an interrupted user loop lost its user time");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/cputime",
    smoke_cputime_timer_irqs_are_irq_time
);

fn smoke_cputime_reaped_child_folds_into_cutime_cstime() -> TestResult {
    const PARENT_TID: u64 = 0x5450_4152_0001;
    const PARENT_PID: u64 = 0x5450_4152_0002;
    let parent = narf_userspace::task::Task::new_registered(PARENT_TID, PARENT_PID);
    let run = match run_program(
        &syscall_loop(SYSCALL_LOOP_ITERATIONS / 4),
        false,
        Some(PARENT_TID),
    ) {
        Ok(run) => run,
        Err(why) => {
            narf_userspace::task::release_task(PARENT_TID);
            return TestResult::Fail(why);
        }
    };
    run.report("reaped-child");
    // The run's harness reset dropped the zombie's pid binding; wait4 reaps
    // through it.
    narf_userspace::handlers::register_pid_task_mapping(run.pid, run.tid);
    let reaped = narf_userspace::handlers::account_reaped_child(PARENT_TID, run.pid);
    let children = narf_userspace::handlers::children_cpu_times(PARENT_TID);
    let own = narf_userspace::handlers::process_cpu_times(PARENT_TID);
    narf_userspace::task::release_task(run.tid);
    narf_userspace::task::release_task(PARENT_TID);
    drop(parent);
    if reaped != run.task || reaped.utime_ns == 0 || reaped.stime_ns == 0 {
        return TestResult::Fail("wait's rusage is not the reaped child's utime/stime");
    }
    if children != reaped {
        return TestResult::Fail("a reaped child's times did not land in cutime/cstime");
    }
    if own != TaskTimes::default() {
        return TestResult::Fail("a reaped child's times were added to the parent's own");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/cputime",
    smoke_cputime_reaped_child_folds_into_cutime_cstime
);
