//! Real userspace Linux-ABI pipe assertions, shared with the host Linux oracle.
use narf_kernel_test::{kernel_test_in, TestResult};

const ELF: &[u8] = include_bytes!(env!("NARF_PIPE_TEST_ELF"));

struct Cleanup<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for Cleanup<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() {
            cleanup();
        }
    }
}

fn smoke_pipe_linux_abi_userspace() -> TestResult {
    use narf_userspace::{install_core_syscalls, install_global, SyscallTable};
    // SAFETY: privileged harness context; retain its translation root until
    // every user future and address-space owner has been retired.
    #[cfg(target_arch = "x86_64")]
    let original_root = unsafe { narf_arch::x86_64::cr::read_cr3() };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the harness runs at EL1 and retains this root throughout the test.
    let original_root = unsafe { narf_arch::aarch64::sysreg::read_ttbr0_el1() };
    narf_userspace::syscall::__test_clear_global();
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::user_task::__test_clear_execve_hook();
    narf_userspace::handlers::__test_reset_task_id_lookup();
    narf_userspace::handlers::__test_wait_reset();
    narf_userspace::handlers::__test_signal_reset();
    narf_userspace::handlers::__test_sigaction_reset();
    narf_userspace::handlers::init_per_task_state();
    narf_userspace::fd::__test_reset();
    narf_scheduler::__reset_queues_for_test();
    let auth = narf_filesystem::bootstrap_mount_authority();
    let mount = match narf_filesystem::registry().mount(
        &auth,
        "/tmp",
        narf_filesystem::MemFs::with_seeds("pipe-abi", &[]),
    ) {
        Ok(mount) => mount,
        Err(_) => return TestResult::Fail("pipe fixture mount failed"),
    };
    let _mount_cleanup = Cleanup(Some(|| {
        let _ = narf_filesystem::registry().unmount(&mount, "/tmp");
    }));
    // SAFETY: the booted harness initialized the allocator and paging. The
    // embedded, build-generated ELF has no interpreter or external files.
    let process =
        match unsafe { narf_userspace::load_user_process_with(ELF, &["pipe-abi"], &[], &[]) } {
            Ok(process) => process,
            Err(_) => return TestResult::Fail("pipe fixture ELF load failed"),
        };
    let result = match narf_memory::alloc_frame() {
        Ok(frame) => frame.start_address(),
        Err(_) => return TestResult::Fail("pipe result page allocation failed"),
    };
    // SAFETY: fresh live frame, initialized before the user process can run.
    unsafe { core::ptr::write_bytes(result.kernel_mut_ptr::<u8>(), 0, 4096) };
    let address_space = process.address_space.clone();
    if address_space
        .map_region(narf_memory::Region {
            base: narf_memory::VirtAddr::new(0x0000_5001_0000_0000),
            len: 4096,
            perms: narf_memory::RegionPerms::READ | narf_memory::RegionPerms::WRITE,
            phys: alloc::vec![result].into(),
        })
        .is_err()
    {
        narf_memory::free_frame(narf_memory::PhysFrame::new(result));
        return TestResult::Fail("pipe result mapping failed");
    }
    // SAFETY: the inactive process owns the root and all of its backing.
    if unsafe { address_space.materialize() }.is_err() {
        return TestResult::Fail("pipe result materialization failed");
    }
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
    pending.spawn();
    narf_scheduler::run_until_empty();
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the harness root remains live throughout this smoke.
    unsafe {
        narf_arch::x86_64::cr::write_cr3(original_root);
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: restore the live harness root before releasing user mappings.
    unsafe {
        narf_arch::aarch64::sysreg::write_ttbr0_el1(original_root);
    }
    let exited = narf_userspace::task::task_has_exited(id.raw());
    let result = address_space
        .lookup(narf_memory::VirtAddr::new(0x0000_5001_0000_0000))
        .expect("result mapping remains live")
        .backing_at(0);
    // SAFETY: address_space retains the current (possibly COW-split) result
    // frame after the task exits.
    // Only the fixture's final success path writes this marker. An early
    // exit, signal, assertion, or panic cannot be mistaken for success.
    let completed = unsafe { result.kernel_ptr::<u64>().read_volatile() };
    narf_scheduler::__test_clear_published_address_space(id);
    narf_scheduler::__reset_queues_for_test();
    narf_userspace::task::release_task(id.raw());
    narf_userspace::handlers::__test_wait_reset();
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::user_task::__test_clear_execve_hook();
    narf_userspace::syscall::__test_clear_global();
    narf_userspace::handlers::restore_address_space_lookup(previous_as_lookup);
    narf_userspace::handlers::__test_reset_task_id_lookup();
    if !exited {
        TestResult::Fail("pipe userspace fixture did not exit")
    } else if completed != 0x5049_5045_5041_5353 {
        TestResult::Fail("pipe userspace fixture failed (see pipe-abi FAIL)")
    } else {
        TestResult::Pass
    }
}
kernel_test_in!("verification/pipe-abi", smoke_pipe_linux_abi_userspace);
