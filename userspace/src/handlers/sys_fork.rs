#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fork(ctx: &mut dyn TrapContext) {
    let parent_as = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    // Fork-bomb guard: refuse before the COW copy when we're at the live
    // user-task cap. POSIX: fork(2) returns EAGAIN when RLIMIT_NPROC would be
    // exceeded. Without this an uncapped fork loop floods the per-CPU ready
    // queues + kernel heap (and, under SMP, every core + the shootdown path).
    if !narf_scheduler::user_nproc_available() {
        ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        return;
    }

    // SAFETY: clone_for_fork's contract — paging is live; the
    // frame allocator was initialised at boot.
    // SAFETY: Valid memory or trusted environment
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
    // SMP note: this only invlpg's the local CPU, but every user-task
    // resume reloads CR3 via `activate()` (flushing the non-global
    // user TLB), so a migrated parent re-derives RO PTEs and faults
    // into COW correctly on its next write.
    // SAFETY: identity map live; root valid; may be called while
    // the parent AS is the active CR3 — invlpg per page keeps the
    // TLB coherent.
    // SAFETY: Valid memory or trusted environment
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
        // SAFETY: Valid memory or trusted environment
        let ok = unsafe { ctx.save_user_state(s.as_mut_ptr() as *mut u8) };
        if ok {
            // SAFETY: save_user_state returned true → it wrote a
            // valid UserState into `s`.
            // SAFETY: Valid memory or trusted environment
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
    // Parent-of bookkeeping MUST be published BEFORE the child is spawned:
    // `spawn_user_process*` makes the child immediately runnable, and under SMP
    // it can begin executing on ANOTHER CPU before this handler finishes. A
    // child that runs `ptrace(PTRACE_TRACEME)` in that window reads this same
    // PARENT_OF map (`parent_of_get` in the TRACEME handler) — if the row is not
    // yet present it returns EINVAL and registers no tracer, so the child's
    // `raise(SIGSTOP)` degrades to a plain job-control stop that a PLAIN (non-
    // WUNTRACED) waitpid never reaps → the tracer's wait hangs (the SMP
    // strace_smoke flake). Publishing it here, before the spawn, closes the
    // race (was previously set only after all the inheritance work below, well
    // past the point the spawned child could already be running). Keyed by the
    // child's ProcessId so `on_child_exit(child_pid)` can resolve the parent —
    // `notify_task_exited` passes `this.process.pid.raw()` (ProcessId), so the
    // key here must be ProcessId, not TaskId.
    parent_of_set(child_pid.raw(), parent_pid);
    crate::mapped_file::fork_process(
        task_to_pid_raw(parent_pid).unwrap_or(parent_pid),
        child_pid.raw(),
    );
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
            // SAFETY: `rdmsr` reads MSR `ecx`=IA32_FS_BASE into edx:eax; the MSR is
            // architectural and readable at CPL0. Operands name the ABI registers and
            // the instruction has no memory side effects.
            #[cfg(target_arch = "x86_64")]
            // SAFETY: Valid memory or trusted environment
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

    let child_tid = match child_state {
        Some(state) => crate::user_task::spawn_user_process_resume(
            proc,
            state,
            narf_scheduler::TaskSpec::user_task(),
        ),
        // Fallback if save_user_state didn't fire (test contexts
        // with synthetic TrapContexts whose stub returns false).
        None => crate::user_task::spawn_user_process(proc, narf_scheduler::TaskSpec::user_task()),
    };
    // Record the explicit ProcessId ↔ TaskId binding.  Must happen
    // before any code that crosses the ID-space boundary.
    register_pid_task_mapping(child_pid.raw(), child_tid.raw());
    // POSIX inheritance — fd / cwd / brk / sigaction handlers are
    // copied; pending signals reset (handled by sigaction_fork
    // not touching the pending bitmap).
    crate::fd::fork(parent_pid, child_tid.raw());
    cwd_fork(parent_pid, child_tid.raw());
    // chroot inheritance (see do_clone3) — child inherits the parent's root.
    #[cfg(feature = "linux-compat")]
    root_dir_fork(parent_pid, child_tid.raw());
    uidgid_fork(parent_pid, child_tid.raw());
    brk_fork(parent_pid, child_tid.raw());
    sigaction_fork(parent_pid, child_tid.raw());
    signal_mask_fork(parent_pid, child_tid.raw());
    // POSIX: inherit the parent's process group, session, and controlling
    // terminal. pgid inheritance keeps a forked foreground job in the
    // terminal's foreground pgrp (no spurious SIGTTIN on its first read).
    pgid_fork(parent_pid, child_tid.raw());
    sid_fork(parent_pid, child_tid.raw());
    #[cfg(feature = "linux-compat")]
    ctty_fork(parent_pid, child_tid.raw());
    // Wave-67 — propagate the parent's PID + mount namespaces into
    // the child. Tasks in the root namespace skip the rebind (no
    // translation needed) but inherit_into_child returns None
    // silently in that case.
    // fork(2)'s return value to the parent must be the child's pid in the
    // PARENT's namespace, and it must agree with what the child's own getpid()
    // reports (now that `inherit_into_child` keys the child's ns by TaskId, the
    // child self-reports its INNER pid). Root-namespace parents keep the outer
    // ProcessId (inherit_into_child returns None). These two facts are coupled:
    // changing only one re-opens the mismatch (see project_pidns_flow_model).
    #[cfg(feature = "container")]
    let mut child_ns_pid = child_pid.raw();
    #[cfg(feature = "container")]
    {
        if let Some(inner) =
            crate::pid_ns::inherit_into_child(parent_pid, child_tid.raw(), child_pid.raw())
        {
            child_ns_pid = inner;
        }
        mount_ns_inherit(parent_pid, child_tid.raw());
        // UTS / NET / IPC / User namespaces share the parent's Arc.
        crate::namespaces::inherit_into_child(parent_pid, child_tid.raw());
    }
    // A forked child joins its parent's cgroup. cgroup membership is keyed by
    // ProcessId (per-process in v2), so the parent must be looked up by its
    // ProcessId — passing the raw TaskId missed every parent's cgroup and
    // dumped forked children into the ROOT cgroup, so systemd never saw a
    // service's subprocesses in its unit cgroup (project_pidns_flow_model).
    #[cfg(feature = "cgroup")]
    narf_filesystem::cgroupfs::fork_inherit(
        task_to_pid_raw(parent_pid).unwrap_or(parent_pid),
        child_pid.raw(),
    );
    // Inherit the parent's cgroup-namespace root (if any).
    #[cfg(all(feature = "cgroup", feature = "container"))]
    narf_filesystem::cgroupfs::fork_inherit_ns(parent_pid, child_pid.raw());
    // Parent-of bookkeeping was published above, BEFORE the spawn, to close
    // the SMP TRACEME race (see the comment at the `parent_of_set` call site).
    // Return the child's pid in the parent's namespace (POSIX fork(2)
    // contract). The parent's waitpid() passes this same value back as
    // `want_pid`, which sys_wait4 translates back to the outer ProcessId before
    // matching PENDING_EXITS. Root-namespace parents see the outer pid.
    #[cfg(feature = "container")]
    ctx.set_return(SyscallReturn::ok(child_ns_pid));
    #[cfg(not(feature = "container"))]
    ctx.set_return(SyscallReturn::ok(child_pid.raw()));
}
