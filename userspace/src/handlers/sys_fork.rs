#[allow(unused_imports)]
use super::*;

// Start on the first AP in the common contiguous topology. The BSP remains in
// the rotation, but a single fork does not immediately collide with its kernel
// housekeeping / RX-forwarder work.
static NEXT_FORK_CPU: AtomicU64 = AtomicU64::new(1);

fn round_robin_cpu(mut candidates: u64, sequence: u64) -> Option<narf_scheduler::CpuId> {
    let count = u64::from(candidates.count_ones());
    if count == 0 {
        return None;
    }
    let mut ordinal = sequence % count;
    loop {
        let cpu = candidates.trailing_zeros();
        if ordinal == 0 {
            return Some(narf_scheduler::CpuId(cpu));
        }
        candidates &= candidates - 1;
        ordinal -= 1;
    }
}

fn parent_rotated_cpu(
    candidates: u64,
    parent_cpu: narf_scheduler::CpuId,
    sequence: u64,
) -> Option<narf_scheduler::CpuId> {
    if parent_cpu.0 >= 64 || candidates & (1u64 << parent_cpu.0) == 0 {
        return round_robin_cpu(candidates, sequence);
    }
    let before_parent = if parent_cpu.0 == 0 {
        0
    } else {
        candidates & ((1u64 << parent_cpu.0) - 1)
    };
    round_robin_cpu(
        candidates,
        u64::from(before_parent.count_ones())
            .wrapping_add(1)
            .wrapping_add(sequence),
    )
}

/// Place a parent's first process child on the next online allowed CPU, then
/// rotate that parent's later process children over the remaining CPUs. This
/// avoids initially queueing a runnable child behind its still-running parent,
/// while a per-parent cursor prevents helper forks made by one child from
/// consuming another parent's placement sequence. This is shared by `fork(2)`
/// and process-creating `clone(2)`/`clone3(2)`; pthread siblings remain local.
pub(super) fn fork_cpu(allowed: narf_scheduler::CpuSet) -> Option<narf_scheduler::CpuId> {
    let candidates = allowed.intersection(narf_scheduler::online_cpu_set()).bits();
    let current_cpu = narf_lib::percpu::current_cpu() as u32;
    let rotated = match crate::task::current_next_fork_sequence(current_cpu) {
        Some((base_cpu, sequence)) => {
            parent_rotated_cpu(candidates, narf_scheduler::CpuId(base_cpu), sequence)
        }
        None => round_robin_cpu(candidates, NEXT_FORK_CPU.fetch_add(1, Ordering::Relaxed)),
    };
    let preferred = rotated.unwrap_or(narf_scheduler::CpuId(current_cpu));
    narf_scheduler::select_fork_cpu(allowed, preferred).or(rotated)
}

pub(crate) fn sys_fork(ctx: &mut dyn TrapContext) {
    // Per-uid RLIMIT_NPROC. The global live-task cap below bounds the whole
    // MACHINE; this bounds ONE user, so a single unprivileged account cannot
    // consume every slot that cap allows.
    //
    // Ahead of the address-space work on purpose: `copy_process` runs
    // `copy_creds` — and this check — long before `copy_mm`, so a process
    // over its limit gets -EAGAIN rather than the -ENOMEM an AS failure
    // would report. The two errnos mean very different things to a caller
    // deciding whether to retry.
    if nproc_fork_would_exceed(current_task_id()) {
        ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        return;
    }

    let parent_as = match current_address_space() {
        Some(a) => a,
        None => {
            // No live address space (internal) → ENOMEM.
            ctx.set_return(SyscallReturn::ok((-12i64) as u64));
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
            // COW dup allocation failed → ENOMEM.
            ctx.set_return(SyscallReturn::ok((-12i64) as u64));
            return;
        }
    };
    // LAZY child materialize (Linux-style demand fork): do NOT eagerly install a
    // leaf PTE for every inherited base page. Each base page the child actually
    // touches demand-faults through `claim_demand_page`'s already-backed path,
    // which installs a READ-ONLY COW leaf from the resident `region.phys[i]`
    // (`user_page_writable` returns false while the frame is COW-shared) — the
    // same PTE eager materialize would have written, but only for pages the child
    // uses. A fork→exit child (the common case) installs a handful of pages
    // instead of the whole address space, eliminating the ~8.7ms materialize
    // pass measured in the fork profile.
    //
    // Correctness:
    // - Huge regions have no demand-fault path, but `clone_for_fork` already maps
    //   them eagerly (`map_huge_region`), so they are unaffected.
    // - An un-faulted child still holds a COW reference (`inc_ref` in
    //   `clone_for_fork`), so its `region.phys[i]` frame cannot be freed by
    //   compaction/migration (free happens only at refcount 0); it stays valid to
    //   fault in later even if the parent's copy is relocated.
    // `clone_for_fork` has already write-protected the present parent leaves
    // whose backing became newly shared. Repeated forks therefore do not
    // re-walk pages that were already COW read-only.
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
    // SPSR); `UserTaskFuture::resume_with` restores it through the
    // aarch64 EL0 polling path. Test contexts whose synthetic
    // TrapContext can't save user state (the trait default returns
    // false) fall back to `UserTaskFuture::new` against the parent's
    // load-time (entry, stack_top).
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
    #[cfg(feature = "container")]
    let pid_plan = match crate::pid_ns::prepare_clone(parent_pid, &[], false, None) {
        Ok(plan) => plan,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
            return;
        }
    };
    #[cfg(feature = "container")]
    let child_pid = crate::ProcessId(pid_plan.outer());
    #[cfg(feature = "container")]
    let child_ns_pid = pid_plan.parent_visible();

    #[cfg(not(feature = "container"))]
    let child_pid = {
        let pid = crate::alloc_pid();
        if pid.raw() == 0 {
            ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
            return;
        }
        pid
    };
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
    crate::mapped_file::fork_address_space(parent_as.identity(), child_as.identity());
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
            {
                // Linux's `current_save_fsgs()` uses RDFSBASE when the CPU
                // enabled CR4.FSGSBASE and falls back to RDMSR otherwise.
                // Reuse NARF's identically-gated helper: besides avoiding a
                // serialising MSR read on every fork, it snapshots direct
                // userspace WRFSBASE updates from the live register.
                // SAFETY: the syscall handler executes at CPL0 on the current
                // CPU; the helper owns the per-CPU feature gate and fences.
                let value = unsafe { narf_arch::x86_64::user_mode::user_fs_base() };
                if value == 0 {
                    None
                } else {
                    Some(value)
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                let value: u64;
                // Linux arm64 copy_thread reads the live TPIDR_EL0 because it
                // may differ from any saved creation-time value. Zero remains
                // an explicit inherited TLS value.
                // SAFETY: TPIDR_EL0 is readable at EL1 without side effects.
                unsafe {
                    core::arch::asm!(
                        "mrs {value}, tpidr_el0",
                        value = out(reg) value,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                Some(value)
            }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            None
        },
        entry_arg: None,
        loaded_mappings: alloc::vec::Vec::new(),
    };

    // Register the child under its TaskId but defer scheduler publication
    // until all fork inheritance below is complete.  The child may otherwise
    // run on another CPU before `fd::fork` installs its table.
    let mut child_spec = narf_scheduler::TaskSpec::user_task();
    if let Some(cpu) = fork_cpu(child_spec.affinity.allowed) {
        child_spec.affinity.preferred = Some(cpu);
    }
    let pending_child = match child_state {
        Some(state) => crate::user_task::prepare_user_process_resume(
            proc,
            state,
            child_spec,
        ),
        // Fallback if save_user_state didn't fire (test contexts
        // with synthetic TrapContexts whose stub returns false).
        None => crate::user_task::prepare_user_process_initial(proc, child_spec),
    };
    let child_tid = pending_child.task_id();
    #[cfg(feature = "container")]
    pid_plan.install(child_tid.raw());
    // Record the explicit ProcessId ↔ TaskId binding.  Must happen
    // before any code that crosses the ID-space boundary.
    register_pid_task_mapping(child_pid.raw(), child_tid.raw());
    rlimit_fork(parent_pid, child_tid.raw());
    cap_fork(parent_pid, child_tid.raw());
    // fork(2) copies (never shares) a pre-existing io_context.
    ioprio_fork(parent_pid, child_tid.raw(), false);
    // POSIX inheritance — fd / cwd / brk / sigaction handlers are
    // copied; pending signals reset (handled by sigaction_fork
    // not touching the pending bitmap).
    crate::fd::fork(parent_pid, child_tid.raw());
    crate::mqueue::fork_fd_paths(parent_pid, child_tid.raw());
    cwd_fork(parent_pid, child_tid.raw());
    // chroot inheritance (see do_clone3) — child inherits the parent's root.
    root_dir_fork(parent_pid, child_tid.raw());
    uidgid_fork(parent_pid, child_tid.raw());
    // brk is inherited by `clone_for_fork` (it's address-space state), not copied
    // per-task.
    sigaction_fork(parent_pid, child_tid.raw());
    signal_mask_fork(parent_pid, child_tid.raw());
    // POSIX: inherit the parent's process group, session, and controlling
    // terminal. pgid inheritance keeps a forked foreground job in the
    // terminal's foreground pgrp (no spurious SIGTTIN on its first read).
    pgid_fork(parent_pid, child_tid.raw());
    sid_fork(parent_pid, child_tid.raw());
    ctty_fork(parent_pid, child_tid.raw());
    // Mount namespaces are implemented by the Linux-compat layer itself, not
    // by the optional container feature. A child always shares its parent's
    // current mount namespace until it explicitly unshares a new one.
    crate::handlers::mount_ns_inherit(parent_pid, child_tid.raw());

    #[cfg(feature = "container")]
    {
        let parent_task = current_task_id();
        // UTS / NET / IPC / User namespaces share the parent's Arc.
        crate::namespaces::inherit_into_child(parent_task, child_tid.raw());
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
    crate::perf_event::on_fork(
        task_to_pid_raw(parent_pid).unwrap_or(parent_pid),
        child_pid.raw(),
        parent_pid,
        child_tid.raw(),
    );
    // Parent-of bookkeeping was published above, BEFORE the spawn, to close
    // the SMP TRACEME race (see the comment at the `parent_of_set` call site).
    // Return the child's pid in the PARENT's namespace (POSIX fork(2) contract).
    // The parent's waitpid() passes this same value back as `want_pid`, which
    // sys_wait4 translates back to the outer ProcessId before matching
    // PENDING_EXITS. `fork_return_to_parent` yields the outer pid for a root-ns
    // parent (including one that just did `unshare(CLONE_NEWPID)`) and the
    // child's in-namespace pid for an ordinary container fork.
    // All child-visible state is now installed, so it is safe for the child
    // to execute on another CPU.
    pending_child.spawn();
    #[cfg(feature = "container")]
    ctx.set_return(SyscallReturn::ok(crate::pid_ns::fork_return_to_parent(
        parent_pid,
        child_pid.raw(),
        child_ns_pid,
    )));
    #[cfg(not(feature = "container"))]
    ctx.set_return(SyscallReturn::ok(child_pid.raw()));
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_fork_cpu_rotation_is_parent_local_and_sparse_safe() -> TestResult {
        let candidates = (1u64 << 1) | (1u64 << 3) | (1u64 << 7);
        let observed = [0, 1, 2, 3].map(|sequence| {
            parent_rotated_cpu(candidates, narf_scheduler::CpuId(3), sequence)
                .map(|cpu| cpu.0)
                .unwrap_or(u32::MAX)
        });
        if observed != [7, 1, 3, 7] {
            return TestResult::Fail("per-parent fork rotation lost locality or sparse coverage");
        }
        if parent_rotated_cpu(0, narf_scheduler::CpuId(3), 0).is_some() {
            return TestResult::Fail("empty fork CPU candidate set selected a CPU");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace/process",
        smoke_fork_cpu_rotation_is_parent_local_and_sparse_safe
    );
}
