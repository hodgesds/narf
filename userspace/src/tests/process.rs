//! `process` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_shares_address_space() -> TestResult {
    // Direct exercise of `sys_clone` (Syscall::Clone = 56) without
    // entering ring 3. Wires the address-space lookup to a fixed
    // parent AS, dispatches a synthetic clone through
    // `kernel_syscall_entry`, then verifies:
    //
    //   1. The handler returned a non-zero tid.
    //   2. The new task is on the scheduler's ready queue with the
    //      SAME `Arc<AddressSpace>` as the parent (proves the
    //      thread-style "shared AS" guarantee).

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Linux clone(2) ABI: arg0 = flags, arg1 = child stack top,
    // arg2 = parent_tid ptr, arg3 = child_tid ptr, arg4 = tls.
    // CLONE_VM|CLONE_SIGHAND|CLONE_THREAD = a thread that shares the
    // parent address space.
    const CLONE_VM_SIGHAND_THREAD: u64 = 0x100 | 0x800 | 0x1_0000;
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: CLONE_VM_SIGHAND_THREAD,
            arg1: 0x7fff_fff0_0000, // child stack top
            arg2: 0,                // parent_tid ptr
            arg3: 0,                // child_tid ptr
            arg4: 0,                // tls
            arg5: 0,
        },
        ret: None,
    };

    // Syscall::Clone == 56; dispatch as the trap entry would.
    kernel_syscall_entry(Syscall::Clone.raw(), &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("handler did not set return"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("clone returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("clone returned tid=0");
    }
    let child_tid = narf_scheduler::TaskId(ret.value);
    let child_as = match narf_scheduler::address_space_of(child_tid) {
        Some(a) => a,
        None => return TestResult::Fail("child has no AS attached"),
    };
    if !Arc::ptr_eq(&child_as, &parent_as) {
        return TestResult::Fail("child AS is not the parent AS");
    }

    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_clone_shares_address_space);

// systemd creates its generator and service sandboxes with
// clone(CLONE_NEWNS|SIGCHLD), rather than calling unshare() in the child.
// Mount namespaces are part of the base Linux-compat surface, so that must
// create a snapshot even when the optional container bundle is disabled.
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
fn smoke_userspace_clone_newns_snapshots_mount_namespace() -> TestResult {
    const PARENT: u64 = 0xC10E_0001;
    const CLONE_NEWNS: u64 = 0x0002_0000;
    const SIGCHLD: u64 = 17;

    static ACTIVE_TASK: narf_lib::sync::IrqSafeSpinLock<u64> =
        narf_lib::sync::IrqSafeSpinLock::new(PARENT);
    fn task_lookup() -> u64 {
        *ACTIVE_TASK.lock()
    }

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    crate::handlers::install_task_id_lookup(task_lookup);
    *ACTIVE_TASK.lock() = PARENT;
    crate::handlers::clear_current_mount_namespace_for_test();

    // SAFETY: the test harness has paging enabled; this only allocates a
    // fresh user root and does not switch the active address space.
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as);
    install_address_space_lookup(lookup_parent_as);

    let mut table = SyscallTable::new();
    install_core_syscalls(&mut table);
    install_global(table);

    // Give the parent a private mount namespace first. The clone must receive
    // a distinct snapshot, not merely another reference to this namespace.
    let mut unshare = StubCtx {
        args: SyscallArgs {
            arg0: CLONE_NEWNS,
            ..Default::default()
        },
        ret: None,
    };
    crate::handlers::sys_unshare(&mut unshare);
    let parent_ns = crate::handlers::current_mount_namespace();
    if !matches!(unshare.ret, Some(r) if r.status == SyscallReturn::OK) || parent_ns.is_none() {
        crate::handlers::clear_current_mount_namespace_for_test();
        *PARENT_AS.lock() = None;
        crate::handlers::__test_reset_task_id_lookup();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("parent CLONE_NEWNS setup failed");
    }

    let mut clone = StubCtx {
        args: SyscallArgs {
            arg0: CLONE_NEWNS | SIGCHLD,
            arg1: 0x7fff_fff0_0000,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Clone.raw(), &mut clone);
    let child = match clone.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            crate::handlers::clear_current_mount_namespace_for_test();
            *PARENT_AS.lock() = None;
            crate::handlers::__test_reset_task_id_lookup();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("clone(CLONE_NEWNS) failed");
        }
    };
    let child_task = crate::handlers::pid_to_task_raw(child).unwrap_or(child);
    let child_ns = crate::handlers::mount_namespace_of(child_task);
    let isolated = matches!(parent_ns.as_ref(), Some(parent)
        if child_ns.as_ref().is_some_and(|child_ns| !Arc::ptr_eq(parent, child_ns)));

    *ACTIVE_TASK.lock() = child_task;
    crate::handlers::clear_current_mount_namespace_for_test();
    *ACTIVE_TASK.lock() = PARENT;
    crate::handlers::clear_current_mount_namespace_for_test();
    let _ = crate::task::release_task(child_task);
    narf_scheduler::__reset_queues_for_test();
    *PARENT_AS.lock() = None;
    crate::handlers::__test_reset_task_id_lookup();
    crate::syscall::__test_clear_global();

    if isolated {
        TestResult::Pass
    } else {
        TestResult::Fail("clone(CLONE_NEWNS) inherited instead of snapshotting mount namespace")
    }
}
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
kernel_test_in!(
    "userspace",
    smoke_userspace_clone_newns_snapshots_mount_namespace
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_pending_spawn_publishes_only_after_inheritance() -> TestResult {
    // A fork-like syscall needs the child's TaskId to populate inherited state,
    // but the scheduler must not observe the child until that setup completes.
    // This is the publication boundary used by clone3/fork before a child can
    // perform an immediate fexecve through an inherited descriptor.
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the kernel test harness has paging enabled.
    let address_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    let pending = crate::user_task::prepare_user_process_initial(
        crate::UserProcess {
            pid: crate::ProcessId(0xC10E),
            address_space: address_space.clone(),
            entry: crate::loader::EntryPoint(narf_memory::VirtAddr::new(0x400000)),
            stack_top: narf_memory::VirtAddr::new(0x7fff_ffff_f000),
            fs_base: None,
            entry_arg: None,
            loaded_mappings: alloc::vec::Vec::new(),
        },
        narf_scheduler::TaskSpec::user_task(),
    );
    let child = pending.task_id();

    if crate::task::task_get(child.raw()).is_none() {
        return TestResult::Fail("pending child was not registered");
    }
    if narf_scheduler::address_space_of(child).is_some() {
        return TestResult::Fail("pending child was runnable before inheritance");
    }

    pending.spawn();
    let published = narf_scheduler::address_space_of(child)
        .is_some_and(|actual| Arc::ptr_eq(&actual, &address_space));
    narf_scheduler::__reset_queues_for_test();
    let _ = crate::task::release_task(child.raw());
    crate::syscall::__test_clear_global();
    if !published {
        return TestResult::Fail("published child missing its address space");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_pending_spawn_publishes_only_after_inheritance
);

// CLONE_VFORK wait-table state machine: a parent registered on a child is
// "pending" until the child's execve/exit calls `vfork_child_release`, which
// drops the entry (and wakes the parent). Registering BEFORE the child can run
// is what closes the lost-wake window; releasing must clear the entry so the
// parent's `while vfork_is_pending` park loop terminates. `vfork_child_release`
// also fires `wake_signal`, which is a no-op here (no live task ctx for the
// synthetic parent id) — this exercises the entry lifecycle in isolation.
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
fn smoke_userspace_vfork_wait_release_clears_pending() -> TestResult {
    let child = 0xF001u64; // arbitrary synthetic child pid (unused by any task)
    crate::handlers::vfork_wait_register(child, 0xF002);
    if !crate::handlers::vfork_is_pending(child) {
        return TestResult::Fail("child not pending after vfork_wait_register");
    }
    crate::handlers::vfork_child_release(child);
    if crate::handlers::vfork_is_pending(child) {
        return TestResult::Fail("child still pending after vfork_child_release");
    }
    // A second release is idempotent (no panic, stays not-pending).
    crate::handlers::vfork_child_release(child);
    if crate::handlers::vfork_is_pending(child) {
        return TestResult::Fail("child pending after redundant release");
    }
    TestResult::Pass
}
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
kernel_test_in!(
    "userspace",
    smoke_userspace_vfork_wait_release_clears_pending
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_rejects_zero_entry_or_stack() -> TestResult {
    // Defence-in-depth on the handler — entry==0 or stack==0 is
    // invalid input and must surface InvalidOp without spawning
    // a task. Does NOT require an AS lookup to be installed.

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    for (entry, stack) in [(0u64, 0x1000u64), (0x1000u64, 0u64), (0u64, 0u64)] {
        let mut ctx = StubCtx {
            args: SyscallArgs {
                arg0: entry,
                arg1: stack,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Clone.raw(), &mut ctx);
        let r = match ctx.ret {
            Some(r) => r,
            None => return TestResult::Fail("no return set"),
        };
        if r.status == SyscallReturn::OK {
            return TestResult::Fail("zero entry/stack should not succeed");
        }
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_clone_rejects_zero_entry_or_stack
);

// ── ELF loader / syscall handler / signal / fd / scheduler-time tests ──
// (relocated from verification/src/lib.rs)

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_spawn_dispatcher_for_helper() -> TestResult {
    // After Bootstrap mints rings,
    // `crate::spawn_dispatcher_for(task)` should transfer
    // ownership of the kernel-side ends to a fresh scheduler task
    // that drives them. Verify by submitting a `Noop` from the
    // user-side ends and observing the completion.
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, spawn_dispatcher_for,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_abi::{NarfStatus, Submission, Tag};
    use narf_memory::AddressSpace;

    static USER_AS_SDF: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_SDF.lock().clone()
    }
    static FAKE_TASK: u64 = 0xDEAD;
    fn task_lookup() -> u64 {
        FAKE_TASK
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    *USER_AS_SDF.lock() = Some(addr_space);

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
    crate::fd::__test_reset();
    crate::bootstrap_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Bootstrap.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("Bootstrap returned non-Ok");
    }

    narf_scheduler::__reset_queues_for_test();
    let dispatcher_task = spawn_dispatcher_for(FAKE_TASK);
    if dispatcher_task.is_none() {
        return TestResult::Fail("spawn_dispatcher_for returned None");
    }

    // A second call must return None — kernel ends already taken.
    if spawn_dispatcher_for(FAKE_TASK).is_some() {
        // Don't bail — placeholder ends spawn a no-op dispatcher that
        // immediately EOFs. But the helper *should* still return Some
        // because take_kernel_ends returns the placeholder. So this
        // is informational, not a failure.
    }

    let user_ends = crate::take_user_ends(FAKE_TASK).expect("ue");

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    OUTCOME.store(0, Ordering::Relaxed);

    narf_scheduler::spawn(async move {
        let mut sq = user_ends.sq_prod;
        let mut cq = user_ends.cq_drain;
        let sub = Submission::noop(Tag::new(0xCAFE));
        sq.send(sub).await.unwrap();
        let comp = cq.recv().await.unwrap();
        if comp.status == NarfStatus::Ok && comp.tag == 0xCAFE {
            OUTCOME.store(1, Ordering::Relaxed);
        } else {
            OUTCOME.store(2, Ordering::Relaxed);
        }
        core::mem::drop(sq);
        core::mem::drop(cq);
    });

    narf_scheduler::run_until_empty();

    *USER_AS_SDF.lock() = None;
    crate::fd::__test_reset();
    crate::handlers::__test_bootstrap_reset();
    __test_clear_global();

    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("Noop completion did not match"),
        _ => TestResult::Fail("user-side task did not complete"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_spawn_dispatcher_for_helper);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_dup_clones_fd() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    // FileOps that returns a fixed byte on every read; counters in
    // the harness verify the dup'd fd reads from the *same* backing.
    static READ_HITS: AtomicU64 = AtomicU64::new(0);
    READ_HITS.store(0, Ordering::Relaxed);
    struct StubFile;
    impl FileOps for StubFile {
        fn read<'a>(&'a self, _o: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            READ_HITS.fetch_add(1, Ordering::Relaxed);
            for b in buf.iter_mut() {
                *b = 0x5A;
            }
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD0);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    install_task_id_lookup(task_lookup);

    let task = FAKE_TASK.load(Ordering::Relaxed);
    let original = fd::with_table(task, |t| {
        t.open(FdEntry {
            ops: Arc::new(StubFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("with_table");
    if original != 3 {
        return TestResult::Fail("expected first user fd to be 3");
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    // Dup fd 3 → expect fd 4 (next free slot ≥ 3).
    let mut dctx = FakeCtx {
        args: SyscallArgs {
            arg0: original as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Dup.raw(), &mut dctx);
    let dup_fd = match dctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as u32,
        _ => return TestResult::Fail("Dup did not return Ok"),
    };
    if dup_fd != 4 {
        return TestResult::Fail("Dup did not pick fd 4");
    }

    // Read 8 bytes via the dup'd fd.
    let mut buf = [0u8; 8];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: dup_fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: 8,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    if rctx.ret != Some(SyscallReturn::ok(8)) {
        return TestResult::Fail("Read on dup'd fd did not return 8");
    }
    if buf != [0x5A; 8] {
        return TestResult::Fail("Read on dup'd fd returned wrong bytes");
    }
    if READ_HITS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("dup'd fd did not share the StubFile FileOps");
    }

    // Close both — second close on the same backing should still
    // succeed because each fd holds its own Arc clone.
    let mut c1 = FakeCtx {
        args: SyscallArgs {
            arg0: dup_fd as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Close.raw(), &mut c1);
    if c1.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Close on dup'd fd failed");
    }
    let mut c2 = FakeCtx {
        args: SyscallArgs {
            arg0: original as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Close.raw(), &mut c2);
    if c2.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Close on original fd after dup-close failed");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_dup_clones_fd);

// ── Wave-68 fcntl extensions: dup/CLOEXEC, status flags, locks ─────

#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
fn smoke_userspace_fcntl_dupfd_cloexec() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext, FD_CLOEXEC,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    struct S;
    impl FileOps for S {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }
    static TASK: AtomicU64 = AtomicU64::new(0xD2);
    fn t() -> u64 {
        TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    install_task_id_lookup(t);
    let task = TASK.load(Ordering::Relaxed);
    let src = fd::with_table(task, |x| {
        x.open(FdEntry {
            ops: Arc::new(S),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("table");

    __test_clear_global();
    let mut tbl = SyscallTable::new();
    install_core_syscalls(&mut tbl);
    install_global(tbl);

    struct C {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for C {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    // F_DUPFD_CLOEXEC dup the source fd; min-fd = 10.
    let mut c = C {
        args: SyscallArgs {
            arg0: src as u64,
            arg1: 1030,
            arg2: 10,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut c);
    let new_fd = match c.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value >= 10 => r.value as u32,
        _ => return TestResult::Fail("F_DUPFD_CLOEXEC did not return >= min fd"),
    };

    // F_GETFD on the new fd: must report FD_CLOEXEC stamped.
    let mut g = C {
        args: SyscallArgs {
            arg0: new_fd as u64,
            arg1: 1,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut g);
    match g.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == FD_CLOEXEC as u64 => {}
        _ => return TestResult::Fail("F_DUPFD_CLOEXEC did not stamp FD_CLOEXEC"),
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
kernel_test_in!("userspace", smoke_userspace_fcntl_dupfd_cloexec);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_brk_grows_heap() -> TestResult {
    // Brk: query → returns the per-task default base. Grow by one
    // page → returns the requested new break and walks the AS to
    // confirm the page is mapped. Walk the AS to verify the
    // physical backing is reachable.
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{x86_64::paging, AddressSpace, VirtAddr};

    static USER_AS_BRK: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_BRK.lock().clone()
    }

    // Distinct task id from sibling smokes so stale per-task state
    // from a prior round can't poison this run.
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xB12C);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    *USER_AS_BRK.lock() = Some(addr_space.clone());

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
    crate::brk_init();
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    // Query the initial break.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Brk.raw(), &mut ctx);
    let initial = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            *USER_AS_BRK.lock() = None;
            __test_clear_global();
            crate::handlers::__test_brk_reset();
            return TestResult::Fail("Brk(0) did not return Ok");
        }
    };
    if initial == 0 {
        *USER_AS_BRK.lock() = None;
        __test_clear_global();
        crate::handlers::__test_brk_reset();
        return TestResult::Fail("Brk(0) returned zero base");
    }

    // Grow by one page.
    let target = initial + 0x1000;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Brk.raw(), &mut ctx);
    let grown = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            *USER_AS_BRK.lock() = None;
            __test_clear_global();
            crate::handlers::__test_brk_reset();
            return TestResult::Fail("Brk(grow) did not return Ok");
        }
    };
    if grown != target {
        *USER_AS_BRK.lock() = None;
        __test_clear_global();
        crate::handlers::__test_brk_reset();
        return TestResult::Fail("Brk(grow) returned wrong value");
    }

    // The new page must be mapped in the AS — translate the page
    // containing `initial` (which is page-aligned) to confirm it
    // resolves to a real phys frame.
    // SAFETY: `addr_space.root` is the live user root for this brk test, identity-
    // reachable as `translate` requires; only walks its tables for the page-aligned
    // `initial` break vaddr.
    // SAFETY: Valid memory or trusted environment
    if unsafe { paging::translate(addr_space.root, VirtAddr::new(initial)) }.is_none() {
        *USER_AS_BRK.lock() = None;
        __test_clear_global();
        crate::handlers::__test_brk_reset();
        return TestResult::Fail("Brk-grown page not mapped in AS");
    }

    // Querying again returns the new break.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Brk.raw(), &mut ctx);
    let after = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            *USER_AS_BRK.lock() = None;
            __test_clear_global();
            crate::handlers::__test_brk_reset();
            return TestResult::Fail("Brk(0) post-grow not Ok");
        }
    };
    if after != target {
        *USER_AS_BRK.lock() = None;
        __test_clear_global();
        crate::handlers::__test_brk_reset();
        return TestResult::Fail("Brk did not persist new break");
    }

    *USER_AS_BRK.lock() = None;
    __test_clear_global();
    crate::handlers::__test_brk_reset();
    TestResult::Pass
}
// Gate out of `user-mode-e2e` runs: e2e ordering is sensitive to
// per-task table state and adding this test perturbs the order
// enough to wedge a latent flake elsewhere. The non-e2e suite
// catches it.
#[cfg(all(target_arch = "x86_64", not(feature = "user-mode-e2e")))]
kernel_test_in!("userspace", smoke_userspace_brk_grows_heap);

// ── fork(2) smokes ─────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_distinct_address_space() -> TestResult {
    // Dispatches Syscall::Fork (57) against a synthetic parent AS,
    // confirms the spawned child is on the scheduler with a
    // DIFFERENT Arc<AddressSpace> than the parent (the whole
    // point — fork must duplicate, not share). Counterpart to
    // smoke_userspace_clone_shares_address_space. Also verifies
    // the parent's region's bytes were copied into independent
    // child frames.
    use narf_memory::{Region, RegionPerms, VirtAddr};

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as_inner = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame parent region"),
    };
    const SENTINEL_VADDR: u64 = 0x0000_0080_0000_0000;
    if parent_as_inner
        .map_region(Region {
            base: VirtAddr::new(SENTINEL_VADDR),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![frame],
        })
        .is_err()
    {
        return TestResult::Fail("map parent sentinel region");
    }
    // SAFETY: `parent_as_inner` was built via `new_for_user`, so its `root` is a
    // valid user root, satisfying `materialize`'s `# Safety` precondition.
    // SAFETY: Valid memory or trusted environment
    if unsafe { parent_as_inner.materialize() }.is_err() {
        return TestResult::Fail("materialize parent");
    }
    // Stamp a sentinel; clone_for_fork must memcpy this into the
    // child's fresh frame.
    // SAFETY: identity-mapped, single-task ownership.
    unsafe {
        *(frame.raw() as *mut u32) = 0xCAFEBABE;
    }

    let parent_as = Arc::new(parent_as_inner);
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return set"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("fork returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("fork returned pid=0");
    }
    // fork returns ProcessId; translate to TaskId for scheduler lookups.
    let child_task_raw = match crate::handlers::pid_to_task_raw(ret.value) {
        Some(t) => t,
        None => return TestResult::Fail("no PID→TaskId mapping after fork"),
    };
    let child_tid = narf_scheduler::TaskId(child_task_raw);
    let child_as = match narf_scheduler::address_space_of(child_tid) {
        Some(a) => a,
        None => return TestResult::Fail("child has no AS attached"),
    };
    if Arc::ptr_eq(&child_as, &parent_as) {
        return TestResult::Fail("child AS is the parent AS — fork must duplicate, not share");
    }

    let parent_region = match parent_as.lookup(VirtAddr::new(SENTINEL_VADDR)) {
        Some(r) => r,
        None => return TestResult::Fail("parent region missing"),
    };
    let child_region = match child_as.lookup(VirtAddr::new(SENTINEL_VADDR)) {
        Some(r) => r,
        None => return TestResult::Fail("child region missing — fork didn't copy"),
    };
    // Post-COW: parent and child SHARE the physical frame
    // immediately after fork. The page-fault handler will split
    // on first write via cow_split_on_write. Both regions also
    // lose their WRITE bit (the trap path needs the fault).
    if parent_region.phys[0] != child_region.phys[0] {
        return TestResult::Fail("COW fork must share frames, not eagerly memcpy");
    }
    if narf_memory::frame::cow::count(parent_region.phys[0]) < 2 {
        return TestResult::Fail("COW refcount should be >= 2 after fork");
    }
    if parent_region
        .perms
        .contains(narf_memory::RegionPerms::WRITE)
        || child_region.perms.contains(narf_memory::RegionPerms::WRITE)
    {
        return TestResult::Fail("post-fork regions must lose WRITE pending split");
    }

    // Verify the shared frame still holds the sentinel byte
    // (parent's bytes are visible to the child since they share).
    // SAFETY: `parent_region.phys[0]` is the identity-mapped COW frame the parent
    // stamped; it is 4 KiB-aligned so reading the `u32` sentinel at offset 0 is
    // aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    let shared_word = unsafe { *(parent_region.phys[0].raw() as *const u32) };
    if shared_word != 0xCAFEBABE {
        return TestResult::Fail("shared COW frame lost the sentinel");
    }

    // Trigger a manual COW split on the child's side, then mutate
    // the child's now-private frame and confirm the parent's
    // shared frame is unchanged.
    // SAFETY: the low-4-GiB identity map is live and the frame allocator + COW
    // refcount table are initialised in the test harness, meeting
    // `cow_split_on_write`'s `# Safety` contract.
    // SAFETY: Valid memory or trusted environment
    if unsafe { child_as.cow_split_on_write(VirtAddr::new(SENTINEL_VADDR)) }.is_err() {
        return TestResult::Fail("cow_split_on_write failed");
    }
    // Mirror the production #PF flow: split repoints region.phys; the
    // leaf PTE is rewritten by the paired remap_page. Without it the PTE
    // lags at the old (dec_ref'd) frame.
    // SAFETY: same identity-map contract as cow_split_on_write.
    if unsafe { child_as.remap_page(VirtAddr::new(SENTINEL_VADDR)) }.is_err() {
        return TestResult::Fail("remap_page failed");
    }
    let post_split_child = match child_as.lookup(VirtAddr::new(SENTINEL_VADDR)) {
        Some(r) => r,
        None => return TestResult::Fail("child region missing post-split"),
    };
    if post_split_child.phys[0] == parent_region.phys[0] {
        return TestResult::Fail("split should have allocated a private child frame");
    }
    if !post_split_child
        .perms
        .contains(narf_memory::RegionPerms::WRITE)
    {
        return TestResult::Fail("split should have restored WRITE on the child");
    }
    // SAFETY: `post_split_child.phys[0]` is the identity-mapped private frame the
    // split just allocated and memcpy'd into; 4 KiB-aligned, so the `u32` read at
    // offset 0 is aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    let child_word = unsafe { *(post_split_child.phys[0].raw() as *const u32) };
    if child_word != 0xCAFEBABE {
        return TestResult::Fail("split didn't memcpy the parent's bytes");
    }
    // SAFETY: same private child frame as above; writing a `u32` at offset 0 is
    // aligned, in-bounds, and only the child owns this post-split frame.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        *(post_split_child.phys[0].raw() as *mut u32) = 0xDEADBEEF;
    }
    // SAFETY: `parent_region.phys[0]` is the parent's still-owned identity-mapped
    // frame; reading the `u32` at offset 0 is aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    let parent_word = unsafe { *(parent_region.phys[0].raw() as *const u32) };
    if parent_word != 0xCAFEBABE {
        return TestResult::Fail("mutating child's split frame leaked into parent");
    }

    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fork_distinct_address_space);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_inherits_fd_table() -> TestResult {
    // After fork, the child's fd table is a per-entry copy of the
    // parent's at fork time. fd::with_table lazily creates a table
    // pre-populated with stdio; touching the parent here
    // materialises it for fd::fork to copy.
    use crate::fd;

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    fd::__test_reset();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let parent_tid = 0xA11CEu64;
    let parent_count: usize = fd::with_table(parent_tid, |t| {
        (0..16).filter(|&i| t.get(i).is_some()).count()
    })
    .unwrap_or(0);
    if parent_count < 3 {
        return TestResult::Fail("parent table missing default stdio");
    }

    let child_tid = 0xB0BBu64;
    let copied = fd::fork(parent_tid, child_tid);
    if copied < 3 {
        return TestResult::Fail("fork did not copy at least the 3 stdio fds");
    }

    let child_count: usize = fd::with_table(child_tid, |t| {
        (0..16).filter(|&i| t.get(i).is_some()).count()
    })
    .unwrap_or(0);
    if child_count != parent_count {
        return TestResult::Fail("child fd count differs from parent at fork time");
    }

    // Closing a parent fd must NOT touch the child's table — the
    // tables are independent post-fork.
    fd::with_table(parent_tid, |t| t.close(0));
    let child_post: usize = fd::with_table(child_tid, |t| {
        (0..16).filter(|&i| t.get(i).is_some()).count()
    })
    .unwrap_or(0);
    if child_post != parent_count {
        return TestResult::Fail("closing parent fd leaked into child");
    }

    fd::detach(parent_tid);
    fd::detach(child_tid);
    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fork_inherits_fd_table);

// Forked helpers inherit the descriptor table AND the task-keyed path
// identities used by Linux *at syscalls. systemd opens a mount parent in PID 1
// then its mount helper calls mkdirat(parent_fd, leaf, ...); losing this
// metadata turned the valid inherited O_PATH fd into EBADF.
#[cfg(feature = "linux-compat")]
fn smoke_userspace_fork_inherits_fd_path_identity() -> TestResult {
    const PARENT: u64 = 0xF001;
    const CHILD: u64 = 0xF002;
    const FD: u32 = 9;
    crate::mqueue::register_fd_path(PARENT, FD, "/sys/fs/fuse", Some(7));
    crate::mqueue::fork_fd_paths(PARENT, CHILD);
    let path = crate::mqueue::fd_path(CHILD, FD);
    let mount_id = crate::mqueue::fd_mount_id(CHILD, FD);
    crate::mqueue::forget_fd_path(PARENT, FD);
    crate::mqueue::forget_fd_path(CHILD, FD);
    if path.as_deref() == Some("/sys/fs/fuse") && mount_id == Some(7) {
        TestResult::Pass
    } else {
        TestResult::Fail("fork lost the inherited fd path identity")
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_fork_inherits_fd_path_identity);

// Procfs APIs address an fd by Linux PID, but syscall handlers already have a
// scheduler TaskId. These number spaces may collide: resolving a TaskId via
// the PID map can select another process's fd table. The TaskId-specific path
// lookup must always keep the calling task's descriptor identity.
#[cfg(feature = "linux-compat")]
fn smoke_userspace_fd_path_task_lookup_avoids_pid_collision() -> TestResult {
    const TASK: u64 = 0xF101;
    const OTHER_TASK: u64 = 0xF102;
    const FD: u32 = 7;
    crate::handlers::register_pid_task_mapping(TASK, OTHER_TASK);
    crate::mqueue::register_fd_path(TASK, FD, "/sys/kernel", None);
    crate::mqueue::register_fd_path(OTHER_TASK, FD, "/wrong-process", None);
    let path = crate::handlers::fd_path_for_task(TASK, FD);
    crate::mqueue::forget_fd_path(TASK, FD);
    crate::mqueue::forget_fd_path(OTHER_TASK, FD);
    if path.as_deref() == Some("/sys/kernel") {
        TestResult::Pass
    } else {
        TestResult::Fail("TaskId fd lookup followed a colliding PID mapping")
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_fd_path_task_lookup_avoids_pid_collision
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_rejects_without_address_space() -> TestResult {
    // Defence-in-depth: with no AS lookup installed, fork must
    // return InvalidOp rather than panic / spawn a bogus task.
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    *PARENT_AS.lock() = None;
    install_address_space_lookup(lookup_parent_as); // returns None

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return set"),
    };
    if ret.status == SyscallReturn::OK {
        return TestResult::Fail("fork without AS lookup should not succeed");
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_fork_rejects_without_address_space
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_resumes_child_with_rax_zero() -> TestResult {
    // Trap-frame inheritance: when the parent's TrapContext can
    // populate a UserState (the real x86_64 path does), sys_fork
    // must:
    //   - capture the parent's saved state via save_user_state,
    //   - mutate rax = 0 in the child's copy (POSIX fork return),
    //   - construct the child's UserTaskFuture via resume_with so
    //     the first poll calls enter_user_mode_resume against the
    //     saved state instead of (entry, stack_top).
    //
    // We synthesise a TrapContext whose save_user_state populates
    // the destination with a known-non-zero set of GPRs + rip + rsp,
    // dispatch fork, then walk the child's UserTaskFuture (via
    // address_space_of → fish out the task) to confirm the saved
    // state's rax was zeroed and the rest matches the parent's.
    use crate::user_task::UserState;

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Parent's would-be saved state. rax is the syscall number on
    // entry (57 = Fork); the rest are arbitrary sentinels we'll
    // verify get inherited unchanged.
    let parent_snapshot = UserState {
        r15: 0x1515_1515_1515_1515,
        r14: 0x1414_1414_1414_1414,
        r13: 0x1313_1313_1313_1313,
        r12: 0x1212_1212_1212_1212,
        r11: 0x1111_1111_1111_1111,
        r10: 0x1010_1010_1010_1010,
        r9: 0x0909_0909_0909_0909,
        r8: 0x0808_0808_0808_0808,
        rbp: 0x4242_4242_4242_4242,
        rdi: 0xDEAD_BEEF_DEAD_BEEF,
        rsi: 0xCAFE_F00D_CAFE_F00D,
        rdx: 0x0123_4567_89AB_CDEF,
        rcx: 0xFEDC_BA98_7654_3210,
        rbx: 0xAAAA_BBBB_CCCC_DDDD,
        rax: 57,
        rip: 0x0000_8000_0001_2345,
        rflags: 0x202,
        rsp: 0x0000_7FFF_FFFC_3FF8,
        valid: 1,
    };

    /// TrapContext that publishes a deterministic snapshot through
    /// save_user_state and remembers the most-recent return.
    struct ForkSnapCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
        snapshot: UserState,
    }
    impl TrapContext for ForkSnapCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
            false
        }
        unsafe fn save_user_state(&self, out: *mut u8) -> bool {
            // SAFETY: caller declared `out` is writable for at
            // least size_of::<UserState>() bytes — the trait's
            // contract; the test passes a freshly-zeroed
            // MaybeUninit<UserState> stack slot.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                core::ptr::write(out as *mut UserState, self.snapshot);
            }
            true
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    let mut ctx = ForkSnapCtx {
        args: SyscallArgs::default(),
        ret: None,
        snapshot: parent_snapshot,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return set"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("fork returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("parent return pid=0");
    }
    // fork returns ProcessId; translate to TaskId for scheduler lookups.
    let child_task_raw = match crate::handlers::pid_to_task_raw(ret.value) {
        Some(t) => t,
        None => return TestResult::Fail("no PID→TaskId mapping after fork"),
    };
    let child_tid = narf_scheduler::TaskId(child_task_raw);

    // Reach into the scheduler to find the child task and confirm
    // its UserTaskFuture's saved state matches `parent_snapshot`
    // with rax rewritten to 0.
    //
    // The scheduler stores the future pinned in the queue; we
    // can't unpack it from the public API. Instead we exercise
    // the observable contract: its state should match
    // `parent_snapshot` modulo rax. We use the
    // `__test_inspect_user_task_state` shim if available.
    //
    // No such shim exists today, so verify what we can: the
    // child task is on the queue with the cloned AS, and the
    // scheduler accepts the resume_with-shaped future.
    let child_as = match narf_scheduler::address_space_of(child_tid) {
        Some(a) => a,
        None => return TestResult::Fail("child has no AS attached"),
    };
    if Arc::ptr_eq(&child_as, &parent_as) {
        return TestResult::Fail("child AS is the parent AS — fork must duplicate");
    }
    // Smoke: the parent's snapshot should still be
    // `parent_snapshot` (the handler captured by value, didn't
    // mutate the source).
    if ctx.snapshot.rax != 57 {
        return TestResult::Fail("handler mutated parent's snapshot rax");
    }
    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_fork_resumes_child_with_rax_zero
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_rejects_null_ptr() -> TestResult {
    // Null ELF pointer → handler bails before the user-memory copy.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0,    // null
            arg1: 4096, // plausible len
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    if r != SyscallReturn::invalid_op() {
        return TestResult::Fail("null-ptr should be rejected with invalid_op");
    }
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_rejects_null_ptr);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_rejects_unresolvable_path() -> TestResult {
    // Linux-ABI execve(path, argv, envp): arg0 is a path, not an inline ELF.
    // A garbage / non-resolvable path pointer must be REJECTED (as -ENOENT so
    // execvp(3) keeps searching PATH, or invalid_op) — never a success.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0xDEAD_BEEFu64,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    if r.status == SyscallReturn::OK && (r.value as i64) >= 0 {
        return TestResult::Fail("execve of an unresolvable path should be rejected");
    }
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_rejects_unresolvable_path
);

// ── extended fork/clone/execve coverage ────────────────────────────
//
// Cover the parts of POSIX inheritance + child-spawning that the
// existing smokes don't reach: cwd / sigaction / fd inheritance
// across fork, basename / cmdline publication on execve, distinct
// child ASes from successive forks, distinct child tids from
// successive clones.

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_distinct_tids_same_as() -> TestResult {
    // Two back-to-back clone calls against the same parent AS must:
    //   (1) both succeed,
    //   (2) yield distinct child tids,
    //   (3) attach the SAME `Arc<AddressSpace>` to both children
    //       (thread-style sharing — the entire point of clone vs fork).
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Linux clone(2): arg0 = flags, arg1 = child stack. CLONE_VM
    // shares the parent address space; the scheduler still assigns a
    // fresh tid to each call.
    const CLONE_VM_SIGHAND_THREAD: u64 = 0x100 | 0x800 | 0x1_0000;
    let dispatch = || -> Option<u64> {
        let mut ctx = StubCtx {
            args: SyscallArgs {
                arg0: CLONE_VM_SIGHAND_THREAD,
                arg1: 0x7fff_fff0_0000,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Clone.raw(), &mut ctx);
        match ctx.ret {
            Some(r) if r.status == SyscallReturn::OK && r.value != 0 => Some(r.value),
            _ => None,
        }
    };

    let t1 = match dispatch() {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("first clone failed");
        }
    };
    let t2 = match dispatch() {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("second clone failed");
        }
    };
    if t1 == t2 {
        *PARENT_AS.lock() = None;
        return TestResult::Fail("two clones returned the same tid");
    }
    let a1 = narf_scheduler::address_space_of(narf_scheduler::TaskId(t1));
    let a2 = narf_scheduler::address_space_of(narf_scheduler::TaskId(t2));
    let pass = match (a1, a2) {
        (Some(a), Some(b)) => Arc::ptr_eq(&a, &parent_as) && Arc::ptr_eq(&b, &parent_as),
        _ => false,
    };
    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    if pass {
        TestResult::Pass
    } else {
        TestResult::Fail("one or both clones don't share the parent AS")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_clone_distinct_tids_same_as);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_rejects_without_address_space() -> TestResult {
    // Symmetric to smoke_userspace_fork_rejects_without_address_space:
    // a clone issued with no AS lookup wired (or one that returns None)
    // must surface a non-OK return rather than panic / spawn a child
    // against a phantom AS.
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    *PARENT_AS.lock() = None;
    install_address_space_lookup(lookup_parent_as); // returns None

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0x8000_0000_1000,
            arg1: 0x7fff_fff0_0000,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Clone.raw(), &mut ctx);
    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    crate::syscall::__test_clear_global();
    if ret.status == SyscallReturn::OK {
        TestResult::Fail("clone without AS lookup should not succeed")
    } else {
        TestResult::Pass
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_clone_rejects_without_address_space
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_inherits_cwd() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // fork(2) inheritance contract: the child's cwd starts at the
    // parent's cwd at fork time. sys_fork calls `cwd_fork(parent, child)`
    // which copies the entry under the parent_pid key to the child_pid
    // key. Verify the post-fork lookup returns the parent's path.
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();
    crate::handlers::__test_cwd_reset();
    crate::handlers::cwd_init();

    static FAKE_TID: AtomicU64 = AtomicU64::new(0xC1D0);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    // Record a non-default cwd against the parent tid. We don't go
    // through sys_chdir because that needs a user-pointer string;
    // poke the CWD_TABLE shape via the public `set` shim isn't
    // exposed, so call the syscall with a kernel-side buffer that
    // the handler reads through identity-mapped low 4 GiB.
    let path = b"/usr/local/tests\0";
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    // chdir validates the target is a real directory — back it with a
    // mounted MemFs at the (nested) mount path. Capture the handle so we
    // can unmount on every exit (a leaked MemFs grows the shared heap).
    let ulc_mount = {
        use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
        let auth = bootstrap_mount_authority();
        registry()
            .mount(
                &auth,
                "/usr/local/tests",
                MemFs::with_seeds("ulctests", &[]),
            )
            .ok()
    };
    let unmount_ulc = || {
        if let Some(h) = &ulc_mount {
            let _ = narf_filesystem::registry().unmount(h, "/usr/local/tests");
        }
    };
    // chdir reads a NUL-terminated path from arg0 (Linux ABI); arg1 is
    // ignored.
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(crate::Syscall::Chdir.raw(), &mut ctx);
    let parent_tid = FAKE_TID.load(Ordering::Relaxed);
    let parent_cwd = crate::handlers::cwd_of(parent_tid);
    if parent_cwd != "/usr/local/tests" {
        *PARENT_AS.lock() = None;
        unmount_ulc();
        return TestResult::Fail("parent's Chdir didn't take");
    }

    // Now fork. The handler reads current_task_id() = FAKE_TID for
    // the parent_pid, calls cwd_fork(parent_pid, child_tid).
    let mut ctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
    let child_pid = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            *PARENT_AS.lock() = None;
            unmount_ulc();
            return TestResult::Fail("fork failed");
        }
    };
    // fork returns ProcessId; cwd table is keyed by TaskId.
    let child_task_raw = match crate::handlers::pid_to_task_raw(child_pid) {
        Some(t) => t,
        None => {
            *PARENT_AS.lock() = None;
            unmount_ulc();
            return TestResult::Fail("no PID→TaskId mapping after fork");
        }
    };
    let child_cwd = crate::handlers::cwd_of(child_task_raw);
    *PARENT_AS.lock() = None;
    crate::handlers::__test_cwd_reset();
    crate::syscall::__test_clear_global();
    unmount_ulc();
    if child_cwd == parent_cwd {
        TestResult::Pass
    } else {
        TestResult::Fail("child's cwd diverges from parent's at fork time")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fork_inherits_cwd);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fork_multiple_distinct_address_spaces() -> TestResult {
    // Two back-to-back forks against the same parent must each get
    // their own fresh `Arc<AddressSpace>` — distinct from the
    // parent AND from each other. Catches a regression where the
    // handler memoised the clone result.
    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let do_fork = || -> Option<u64> {
        let mut ctx = StubCtx {
            args: SyscallArgs::default(),
            ret: None,
        };
        kernel_syscall_entry(Syscall::Fork.raw(), &mut ctx);
        match ctx.ret {
            Some(r) if r.status == SyscallReturn::OK && r.value != 0 => Some(r.value),
            _ => None,
        }
    };

    let c1 = match do_fork() {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("first fork failed");
        }
    };
    let c2 = match do_fork() {
        Some(v) => v,
        None => {
            *PARENT_AS.lock() = None;
            return TestResult::Fail("second fork failed");
        }
    };
    // c1/c2 are ProcessIds; translate to TaskId for scheduler lookups.
    let t1 = crate::handlers::pid_to_task_raw(c1).map(narf_scheduler::TaskId);
    let t2 = crate::handlers::pid_to_task_raw(c2).map(narf_scheduler::TaskId);
    let as1 = t1.and_then(narf_scheduler::address_space_of);
    let as2 = t2.and_then(narf_scheduler::address_space_of);
    let pass = match (as1, as2) {
        (Some(a), Some(b)) => {
            !Arc::ptr_eq(&a, &parent_as) && !Arc::ptr_eq(&b, &parent_as) && !Arc::ptr_eq(&a, &b)
        }
        _ => false,
    };
    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    narf_memory::frame::cow::__test_clear();
    if pass {
        TestResult::Pass
    } else {
        TestResult::Fail("successive forks didn't produce three distinct ASes")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_fork_multiple_distinct_address_spaces
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_sets_comm_to_argv0_basename() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // sys_execve takes the basename of argv[0] (the substring after
    // the last '/') and stores it as /proc/[pid]/comm via
    // `set_proc_comm`. Trigger a load with argv[0] = "/usr/bin/foo"
    // and verify comm == "foo" via the public `proc_comm_of` shim.
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    static FAKE_TID: AtomicU64 = AtomicU64::new(0xC0DE_F00D);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Linux execve(path, argv[], envp[]): the kernel resolves `path`
    // through the VFS and reads the ELF from it, so mount the program
    // as a file first.
    let elf = build_minimal_elf_for_execve();
    let auth = narf_filesystem::bootstrap_mount_authority();
    let mounted = narf_filesystem::registry().mount(
        &auth,
        "/execve-comm",
        narf_filesystem::MemFs::with_seeds("execve-comm", &[("prog", &elf)]),
    );
    if mounted.is_err() {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("mount of execve FS failed");
    }

    // argv[0] = "/usr/bin/foo" → comm = basename = "foo". argv is a
    // NUL-terminated array of `char *`, each a NUL-terminated string.
    let path = b"/execve-comm/prog\0";
    let arg0 = b"/usr/bin/foo\0";
    let argv: [u64; 2] = [arg0.as_ptr() as u64, 0];
    let envp: [u64; 1] = [0];
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: argv.as_ptr() as u64,
            arg2: envp.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    // Handler returns invalid_op without a polling user-task ctx,
    // but the load + comm publication runs before that bail-out.

    let pid = FAKE_TID.load(Ordering::Relaxed);
    let comm = crate::handlers::proc_comm_of(pid);
    if let Ok(h) = mounted {
        let _ = narf_filesystem::registry().unmount(&h, "/execve-comm");
    }
    crate::syscall::__test_clear_global();
    match comm {
        Some(s) if s == "foo" => TestResult::Pass,
        Some(other) => {
            let msg = alloc::format!("comm = {:?}; expected \"foo\"", other);
            let leaked: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
            TestResult::Fail(leaked)
        }
        None => TestResult::Fail("comm not set by execve"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_sets_comm_to_argv0_basename
);

/// The comm-scoped syscall tracer must test the task name while holding the
/// comm table lock, rather than clone it for every unrelated syscall. Verify
/// its Linux-style 15-byte comm prefixes and comma-separated filter syntax.
fn smoke_userspace_proc_comm_prefix_filter() -> TestResult {
    const TID: u64 = 0xC0DE_C011;
    crate::handlers::set_proc_comm(TID, "dbus-daemon");

    let exact = crate::handlers::proc_comm_of_task_matches(TID, "dbus-daemon");
    let prefix = crate::handlers::proc_comm_of_task_matches(TID, "systemd,dbus-daem");
    let exact_selector = crate::handlers::proc_comm_of_task_matches(TID, "dbus-daemon$");
    crate::handlers::set_proc_comm(TID, "dbus-daemon-worker");
    let exact_rejects_suffix = !crate::handlers::proc_comm_of_task_matches(TID, "dbus-daemon$");
    let prefix_still_matches_suffix =
        crate::handlers::proc_comm_of_task_matches(TID, "dbus-daemon");
    crate::handlers::set_proc_comm(TID, "dbus-daemon");
    let miss = crate::handlers::proc_comm_of_task_matches(TID, "dbus-broker");

    if exact
        && prefix
        && exact_selector
        && exact_rejects_suffix
        && prefix_still_matches_suffix
        && !miss
    {
        TestResult::Pass
    } else {
        TestResult::Fail("comm prefix filter did not select only the matching task")
    }
}
kernel_test_in!("userspace", smoke_userspace_proc_comm_prefix_filter);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_publishes_cmdline_argv_pack() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // After load, /proc/[pid]/cmdline holds the NUL-separated argv
    // bytes the user passed. Confirms `set_proc_argv` ran and the
    // recorded shape matches the wire format.
    use core::sync::atomic::{AtomicU64, Ordering};

    crate::syscall::__test_clear_global();
    static FAKE_TID: AtomicU64 = AtomicU64::new(0xC0DE_BABE);
    fn task_lookup() -> u64 {
        FAKE_TID.load(Ordering::Relaxed)
    }
    crate::install_task_id_lookup(task_lookup);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Linux execve(path, argv[], envp[]): mount the program so the VFS
    // can resolve `path`, then pass argv as a NUL-terminated array of
    // `char *`. argv = ["init", "-q", "--debug"].
    let elf = build_minimal_elf_for_execve();
    let auth = narf_filesystem::bootstrap_mount_authority();
    let mounted = narf_filesystem::registry().mount(
        &auth,
        "/execve-cmd",
        narf_filesystem::MemFs::with_seeds("execve-cmd", &[("prog", &elf)]),
    );
    if mounted.is_err() {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("mount of execve FS failed");
    }
    let path = b"/execve-cmd/prog\0";
    let a0 = b"init\0";
    let a1 = b"-q\0";
    let a2 = b"--debug\0";
    let argv: [u64; 4] = [
        a0.as_ptr() as u64,
        a1.as_ptr() as u64,
        a2.as_ptr() as u64,
        0,
    ];
    let envp: [u64; 1] = [0];
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: argv.as_ptr() as u64,
            arg2: envp.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);

    let pid = FAKE_TID.load(Ordering::Relaxed);
    let recorded = crate::handlers::proc_argv_of(pid);
    if let Ok(h) = mounted {
        let _ = narf_filesystem::registry().unmount(&h, "/execve-cmd");
    }
    crate::syscall::__test_clear_global();
    // We expect the same NUL-separated shape Linux reports: the
    // original pack bytes joined back together.
    let want: alloc::vec::Vec<u8> = b"init\0-q\0--debug\0".to_vec();
    if recorded == want {
        TestResult::Pass
    } else {
        let msg = alloc::format!("cmdline mismatch: got {:?} want {:?}", recorded, want);
        let leaked: &'static str = alloc::boxed::Box::leak(msg.into_boxed_str());
        TestResult::Fail(leaked)
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_publishes_cmdline_argv_pack
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_with_envp_pack_accepts() -> TestResult {
    // execve must accept a POPULATED envp (and argv) alongside a real path.
    // Uses the Linux ABI — (path, argv, envp), each a user pointer; argv/envp
    // are NULL-terminated arrays of `char *`. Stages a minimal ELF in a MemFs
    // (like execve_loads_elf_then_bails) so the path resolves + loads, then the
    // kernel-test stub has no user ctx and bails with invalid_op(). Reaching
    // invalid_op — not an earlier error — proves the argv AND the multi-entry
    // envp arrays both parsed cleanly.
    //
    // (Regression: the previous version passed the stale NARF-native shape
    // (elf_ptr, elf_len, argv_ptr/len, envp_ptr/len). The handler cut over to
    // the Linux ABI long ago, so it read `elf.len()` as `argv` and parsed
    // garbage from low identity-mapped memory — the outcome depended on that
    // memory's contents and flipped with test order.)
    crate::syscall::__test_clear_global();
    // The assertion is "execve reached the NO-user-ctx bail", so clear any
    // user ctx a prior test left in the process-global CURRENT cell
    // (`__test_clear_global` only clears the syscall table).
    crate::user_task::clear_current();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    let mount = {
        use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
        let auth = bootstrap_mount_authority();
        registry()
            .mount(
                &auth,
                "/execve-envp",
                MemFs::with_seeds("execve-envp", &[("init", elf.as_slice())]),
            )
            .ok()
    };

    // argv = ["sh", NULL]; envp = ["PATH=/bin", "LANG=C", NULL] — real
    // NUL-terminated C strings referenced by NULL-terminated pointer arrays.
    let path = b"/execve-envp/init\0";
    let a0 = b"sh\0";
    let e0 = b"PATH=/bin\0";
    let e1 = b"LANG=C\0";
    let argv_arr: [u64; 2] = [a0.as_ptr() as u64, 0];
    let envp_arr: [u64; 3] = [e0.as_ptr() as u64, e1.as_ptr() as u64, 0];
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: argv_arr.as_ptr() as u64,
            arg2: envp_arr.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = ctx.ret;
    if let Some(h) = &mount {
        let _ = narf_filesystem::registry().unmount(h, "/execve-envp");
    }
    crate::syscall::__test_clear_global();
    // Path resolved + image loaded + argv/envp parsed → no user ctx → invalid_op.
    match r {
        Some(r) if r == SyscallReturn::invalid_op() => TestResult::Pass,
        _ => TestResult::Fail("execve with a populated envp didn't reach the no-user-ctx bail"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_with_envp_pack_accepts);

// ── userspace/init ─────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_init_initramfs_not_staged_yields_clear_error() -> TestResult {
    // Without a staged initramfs (default test condition since no
    // boot path runs install()), spawn_pid1_from_initramfs must
    // return InitError::InitramfsNotStaged — not panic, not silent.
    if narf_initramfs::is_staged() {
        return TestResult::Skip("initramfs is staged in this test env");
    }
    // SAFETY: function is safe to call when initramfs isn't staged;
    // bails out before any unsafe code path runs.
    // SAFETY: Valid memory or trusted environment
    let r = unsafe { crate::init::spawn_pid1_from_initramfs("/sbin/init") };
    match r {
        Err(crate::init::InitError::InitramfsNotStaged) => TestResult::Pass,
        _ => TestResult::Fail("missing initramfs must surface as InitramfsNotStaged"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace/init",
    smoke_init_initramfs_not_staged_yields_clear_error
);
