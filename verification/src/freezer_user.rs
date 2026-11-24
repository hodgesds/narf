//! The task freezer against a real user task (`verification/freezer`).
//!
//! A user program counts in a data page until the kernel sets a flag
//! there. A kernel task freezes it in the middle of that loop, in user
//! mode, which only the timer tick can interrupt. It then checks that the
//! count holds still while frozen and moves again after the thaw. That
//! covers the user-mode tick's freeze point (`freeze_on_user_tick`) and the
//! own-stack park loop's on each arch.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};
use narf_power::freezer;
use narf_userspace::{install_core_syscalls, install_global, SyscallTable, UserProcess};

use crate::cputime_user::{alloc_page, FastTimer};

const CODE_VADDR: u64 = 0x0040_0000;
const STACK_VADDR: u64 = 0x0041_0000;
/// `[0]`: the stop flag the kernel sets; `[8]`: the program's count.
const DATA_VADDR: u64 = 0x0042_0000;
const PAGE_BYTES: u64 = 4096;
const MS: u64 = 1_000_000;

/// Count `[DATA + 8]` until `[DATA]` is non-zero, then exit.
#[cfg(target_arch = "x86_64")]
fn counting_loop() -> Vec<u8> {
    let exit = narf_userspace::Syscall::ExitTask.raw().to_le_bytes();
    alloc::vec![
        0x48, 0xFF, 0x04, 0x25, 0x08, 0x00, 0x42, 0x00, // 1: inc qword [DATA + 8]
        0x83, 0x3C, 0x25, 0x00, 0x00, 0x42, 0x00, 0x00, // cmp dword [DATA], 0
        0x74, 0xEE, // je 1b
        0x48, 0xC7, 0xC0, exit[0], exit[1], exit[2], exit[3], // mov rax, exit
        0xCD, 0x80, // int 0x80
        0xEB, 0xFE, // jmp $
    ]
}

/// Count `[DATA + 8]` until `[DATA]` is non-zero, then exit.
#[cfg(target_arch = "aarch64")]
fn counting_loop() -> Vec<u8> {
    use crate::cputime_user::a64;
    let mut code = Vec::new();
    a64::load_u64(&mut code, 1, DATA_VADDR);
    code.push(0xF940_0422); // 1: ldr x2, [x1, #8]
    code.push(0x9100_0442); // add x2, x2, #1
    code.push(0xF900_0422); // str x2, [x1, #8]
    code.push(0xF940_0023); // ldr x3, [x1]
    code.push(0xB4FF_FF83); // cbz x3, 1b
    crate::cputime_user::emit_exit(&mut code);
    a64::bytes(&code)
}

/// The program's address space: code, stack and the shared data page.
fn build_process(code: &[u8]) -> Result<(UserProcess, PhysAddr), &'static str> {
    let code_phys = alloc_page()?;
    let stack_phys = alloc_page()?;
    let data_phys = alloc_page()?;
    // SAFETY: fresh 4 KiB frames, written through the kernel direct map; the
    // program is far smaller than a page.
    unsafe {
        core::ptr::write_bytes(code_phys.kernel_mut_ptr::<u8>(), 0, PAGE_BYTES as usize);
        core::ptr::write_bytes(data_phys.kernel_mut_ptr::<u8>(), 0, PAGE_BYTES as usize);
        core::ptr::copy_nonoverlapping(code.as_ptr(), code_phys.kernel_mut_ptr::<u8>(), code.len());
        #[cfg(target_arch = "aarch64")]
        narf_arch::aarch64::asm::flush_icache_range(
            code_phys.kernel_ptr::<u8>() as u64,
            code.len() as u64,
        );
    }
    // SAFETY: paging and the frame allocator are live in the kernel-test boot.
    let address_space = unsafe { AddressSpace::new_for_user() }.map_err(|_| "new_for_user")?;
    for (base, perms, phys) in [
        (CODE_VADDR, RegionPerms::READ | RegionPerms::EXEC, code_phys),
        (
            STACK_VADDR,
            RegionPerms::READ | RegionPerms::WRITE,
            stack_phys,
        ),
        (
            DATA_VADDR,
            RegionPerms::READ | RegionPerms::WRITE,
            data_phys,
        ),
    ] {
        address_space
            .map_region(Region {
                base: VirtAddr::new(base),
                len: PAGE_BYTES,
                perms,
                phys: alloc::vec![phys].into(),
            })
            .map_err(|_| "map region")?;
    }
    // SAFETY: the inactive root owns every mapped frame above.
    unsafe { address_space.materialize() }.map_err(|_| "materialize")?;
    let process = UserProcess {
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
    };
    Ok((process, data_phys))
}

/// The data page's word `index`, through the kernel direct map.
fn word(data: PhysAddr, index: usize) -> *mut u64 {
    // SAFETY: `data` is the program's 4 KiB data frame; index 0 or 1.
    unsafe { data.kernel_mut_ptr::<u64>().add(index) }
}
fn count(data: PhysAddr) -> u64 {
    // SAFETY: an aligned word of a frame this test owns; the program writes
    // it concurrently, so read it volatile.
    unsafe { core::ptr::read_volatile(word(data, 1)) }
}

/// The program's task: the only task this test's freeze covers. The task
/// registry can hold fixture tasks from other tests that have no future to
/// reach a freeze point.
static TASK: AtomicU64 = AtomicU64::new(0);
fn this_task() -> Vec<u64> {
    alloc::vec![TASK.load(Ordering::Acquire)]
}

#[derive(Debug)]
struct Outcome {
    started: bool,
    froze: Result<(), freezer::FreezeError>,
    held: bool,
    while_frozen: (u64, u64),
    after_thaw: u64,
}
static OUTCOME: IrqSafeSpinLock<Option<Outcome>> = IrqSafeSpinLock::new(None);

/// Spin-yield until `done` or `limit_ns` passes.
async fn wait_until(limit_ns: u64, done: impl Fn() -> bool) -> bool {
    let start = narf_time::monotonic_ns();
    while !done() {
        if narf_time::monotonic_ns().saturating_sub(start) > limit_ns {
            return false;
        }
        narf_scheduler::yield_now().await;
    }
    true
}

async fn drive(data: PhysAddr) {
    let task = TASK.load(Ordering::Acquire);
    let started = wait_until(2_000 * MS, || count(data) != 0).await;
    let froze = freezer::freeze_processes_within(2_000 * MS).await;
    let held = freezer::frozen(task);
    let first = count(data);
    wait_until(20 * MS, || false).await;
    let second = count(data);
    freezer::thaw_processes();
    wait_until(2_000 * MS, || count(data) != second).await;
    let after_thaw = count(data);
    // SAFETY: the flag word of the data frame; the program only reads it.
    unsafe { core::ptr::write_volatile(word(data, 0), 1) };
    *OUTCOME.lock() = Some(Outcome {
        started,
        froze,
        held,
        while_frozen: (first, second),
        after_thaw,
    });
}

fn smoke_freezer_holds_a_running_user_task() -> TestResult {
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
    *OUTCOME.lock() = None;

    let (process, data) = match build_process(&counting_loop()) {
        Ok(built) => built,
        Err(why) => return TestResult::Fail(why),
    };
    let mut table = SyscallTable::new();
    install_core_syscalls(&mut table);
    install_global(table);
    let previous_as_lookup = narf_userspace::handlers::address_space_lookup();
    narf_userspace::install_address_space_lookup(narf_scheduler::current_address_space);
    narf_userspace::install_task_id_lookup(|| narf_scheduler::current_task_id().raw());
    narf_userspace::install_user_task_hooks();
    let previous_freezer = freezer::install(freezer::Hooks {
        live: this_task,
        kick: narf_userspace::handlers::wake_signal,
    });
    let pid = process.pid.raw();
    let pending = narf_userspace::user_task::prepare_user_process_initial(
        process,
        narf_scheduler::TaskSpec::unthrottled(),
    );
    let id = pending.task_id();
    TASK.store(id.raw(), Ordering::Release);
    narf_userspace::handlers::register_pid_task_mapping(pid, id.raw());
    {
        let _timer = FastTimer::start();
        pending.spawn();
        narf_scheduler::spawn(drive(data));
        narf_scheduler::run_until_empty();
    }

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
    // A failure must not leave the system frozen for the tests after it.
    freezer::thaw_processes();
    if let Some(hooks) = previous_freezer {
        freezer::install(hooks);
    }
    let exited = narf_userspace::task::task_has_exited(id.raw());
    narf_scheduler::__test_clear_published_address_space(id);
    narf_scheduler::__reset_queues_for_test();
    narf_userspace::task::release_task(id.raw());
    narf_userspace::handlers::__test_wait_reset();
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::user_task::__test_clear_execve_hook();
    narf_userspace::syscall::__test_clear_global();
    narf_userspace::handlers::restore_address_space_lookup(previous_as_lookup);
    narf_userspace::handlers::__test_reset_task_id_lookup();

    let Some(outcome) = OUTCOME.lock().take() else {
        return TestResult::Fail("the freezer task did not finish");
    };
    {
        use core::fmt::Write as _;
        let _ = writeln!(narf_console::Writer, "freezer[user-loop]: {outcome:?}");
    }
    if !outcome.started {
        return TestResult::Fail("the user program never ran");
    }
    if outcome.froze.is_err() || !outcome.held {
        return TestResult::Fail("a user task in user mode did not freeze");
    }
    let (first, second) = outcome.while_frozen;
    if first != second {
        return TestResult::Fail("the user task kept running while frozen");
    }
    if outcome.after_thaw == second {
        return TestResult::Fail("the user task did not run after the thaw");
    }
    if !exited {
        return TestResult::Fail("the user program did not exit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/freezer",
    smoke_freezer_holds_a_running_user_task
);
