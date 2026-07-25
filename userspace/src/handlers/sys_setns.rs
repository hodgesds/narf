#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setns(ctx: &mut dyn TrapContext) {
    #[cfg(feature = "container")]
    {
        let args = *ctx.args();
        let target = args.arg0;
        let nstype = args.arg1;
        const CLONE_NEWNS: u64 = 0x00020000;
        const CLONE_NEWPID: u64 = 0x20000000;
        let caller = current_task_id();
        let mut any = false;

        // ── fd-based setns (Linux primary path) ──────────────────
        //
        // arg0 is normally an fd opened from /proc/<pid>/ns/<flavour>.
        // If it resolves to an `NsFd` in the caller's fd table, install
        // the held namespace and return. The held `Arc` keeps the ns
        // alive even after its originator exited.
        if let Some(held) = crate::fd::with_table(caller, |t| {
            t.get(target as u32).and_then(|e| {
                e.ops
                    .as_any()
                    .and_then(|a| a.downcast_ref::<crate::namespaces::NsFd>())
                    .map(|nsfd| nsfd.held().clone())
            })
        })
        .flatten()
        {
            let outer = task_to_pid_raw(caller).unwrap_or(caller);
            // Mount-ns is held but installed through the handlers' mount
            // table, not the namespaces module.
            if let crate::namespaces::HeldNs::Mnt(mnt) = &held {
                if nstype == 0 || nstype & CLONE_NEWNS != 0 {
                    install_mount_namespace(caller, mnt.clone());
                    ctx.set_return(SyscallReturn::ok(0));
                    return;
                }
                ctx.set_return(SyscallReturn::ok(!0u64));
                return;
            }
            if crate::namespaces::install_held_ns(caller, outer, &held, nstype) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                ctx.set_return(SyscallReturn::ok(!0u64));
            }
            return;
        }

        // ── Legacy NARF TaskId path (kept for existing tests) ─────
        //
        // Resolve target: prefer outer-pid lookup, fall back to
        // treating `target` as an outer TaskId directly.
        let target_task = pid_to_task_raw(target).unwrap_or(target);

        if nstype & CLONE_NEWPID != 0 {
            match crate::pid_ns::ns_of(target_task) {
                Some(ns) => {
                    let outer = task_to_pid_raw(caller).unwrap_or(caller);
                    let _ = crate::pid_ns::attach_to_ns(caller, outer, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }

        if nstype & CLONE_NEWNS != 0 {
            match mount_namespace_of(target_task) {
                Some(ns) => {
                    install_mount_namespace(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }

        // Wave-72 — UTS / NET / IPC. Target must have an explicit
        // per-task NS of the requested flavour; otherwise EINVAL.
        if nstype & crate::namespaces::CLONE_NEWUTS != 0 {
            match crate::namespaces::uts_ns_of(target_task) {
                Some(ns) => {
                    crate::namespaces::setns_uts(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }
        if nstype & crate::namespaces::CLONE_NEWNET != 0 {
            match crate::namespaces::net_ns_of(target_task) {
                Some(ns) => {
                    crate::namespaces::setns_net(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }
        if nstype & crate::namespaces::CLONE_NEWIPC != 0 {
            match crate::namespaces::ipc_ns_of(target_task) {
                Some(ns) => {
                    crate::namespaces::setns_ipc(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }
        if nstype & crate::namespaces::CLONE_NEWUSER != 0 {
            match crate::namespaces::user_ns_of(target_task) {
                Some(ns) => {
                    crate::namespaces::setns_user(caller, ns);
                    any = true;
                }
                None => {
                    ctx.set_return(SyscallReturn::ok(!0u64));
                    return;
                }
            }
        }

        if !any {
            // No supported nstype bits — Linux returns EINVAL.
            ctx.set_return(SyscallReturn::ok(!0u64));
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
    }
    #[cfg(not(feature = "container"))]
    {
        ctx.set_return(SyscallReturn::ok(!0u64));
    }
}
