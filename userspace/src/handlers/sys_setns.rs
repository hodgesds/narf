#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setns(ctx: &mut dyn TrapContext) {
    #[cfg(feature = "container")]
    {
        let args = *ctx.args();
        let target = args.arg0;
        let nstype = args.arg1;
        const CLONE_NEWNS: u64 = 0x00020000;
        let caller = current_task_id();

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
            if let crate::namespaces::HeldNs::MntGlobal(_) = &held {
                if nstype == 0 || nstype & CLONE_NEWNS != 0 {
                    install_initial_mount_namespace(caller);
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

        // arg0 did not resolve to a namespace fd. Linux setns(2) requires an fd
        // that refers to a namespace (opened from /proc/<pid>/ns/<flavour> or a
        // pidfd); a bad or wrong-type fd is EBADF/EINVAL — never a pid. The old
        // "legacy TaskId path" reinterpreted the fd NUMBER as an outer pid and
        // joined that process's namespaces with NO pid-namespace translation — a
        // containment hazard reachable by any caller passing a stray integer,
        // and non-Linux. No caller or test depended on it (#34), so reject.
        // NARF returns the bare -1 sentinel here; the LINUX-GAP is only the
        // specific EBADF-vs-EINVAL split.
        let _ = (target, nstype, caller);
        ctx.set_return(SyscallReturn::ok(!0u64));
    }
    #[cfg(not(feature = "container"))]
    {
        ctx.set_return(SyscallReturn::ok(!0u64));
    }
}
