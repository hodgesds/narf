#[allow(unused_imports)]
use super::*;

const EBADF: i64 = 9;
const EINVAL: i64 = 22;

#[inline]
fn fail(errno: i64) -> SyscallReturn {
    SyscallReturn::ok((-errno) as u64)
}

/// `kernel/nsproxy.c::SYSCALL_DEFINE2(setns, int fd, int flags)`:
///
/// ```text
///   if (fd_empty(f))                      return -EBADF;
///   if (proc_ns_file(fd_file(f))) {
///           ns = get_proc_ns(...);
///           if (flags && (ns->ns_type != flags)) err = -EINVAL;
///   } else if (!IS_ERR(pidfd_pid(fd_file(f)))) {
///           err = check_setns_flags(flags);        /* -EINVAL */
///   } else {
///           err = -EINVAL;
///   }
/// ```
///
/// All four failures were the bare `-1` sentinel, i.e. EPERM. That is the
/// one answer setns(2) never gives for these, and it is actively misleading:
/// a container runtime that gets EPERM from setns concludes it is running
/// unprivileged and abandons the join, when the real fault is a descriptor
/// it closed too early (EBADF) or an `nstype` that does not match the
/// namespace the fd names (EINVAL) — both of which it can fix and retry.
///
/// The EBADF/EINVAL split is exactly Linux's: "not an open descriptor" is
/// EBADF, "an open descriptor that is not a namespace file" is EINVAL. The
/// split is decided from the fd table alone, so it holds in builds without
/// the `container` namespace bundle too — there, no descriptor can ever be a
/// namespace file, so every open fd is EINVAL.
///
/// LINUX-GAP: `prepare_nsset`/`validate_nsset` reject a caller lacking
/// CAP_SYS_ADMIN in the target user namespace with -EPERM after these
/// checks; NARF models no per-task capability set here.
pub(crate) fn sys_setns(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Both arguments are `int`: the upper 32 bits of the syscall registers
    // are not part of the call. A negative fd can never name an open file,
    // so it takes the same -EBADF as an unoccupied slot.
    let fd = args.arg0 as i32;
    #[allow(unused_variables)]
    let nstype = args.arg1 as u32 as u64;
    let caller = current_task_id();

    // `fd_empty(f)` → -EBADF.
    if fd < 0 || !crate::fd::with_table(caller, |t| t.get(fd as u32).is_some()).unwrap_or(false) {
        ctx.set_return(fail(EBADF));
        return;
    }

    #[cfg(feature = "container")]
    {
        const CLONE_NEWNS: u64 = 0x00020000;

        // ── fd-based setns (Linux primary path) ──────────────────
        //
        // The fd is normally one opened from /proc/<pid>/ns/<flavour>.
        // If it resolves to an `NsFd` in the caller's fd table, install
        // the held namespace and return. The held `Arc` keeps the ns
        // alive even after its originator exited.
        if let Some(held) = crate::fd::with_table(caller, |t| {
            t.get(fd as u32).and_then(|e| {
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
                // `flags && ns->ns_type != flags` → -EINVAL.
                ctx.set_return(fail(EINVAL));
                return;
            }
            if let crate::namespaces::HeldNs::MntGlobal(_) = &held {
                if nstype == 0 || nstype & CLONE_NEWNS != 0 {
                    install_initial_mount_namespace(caller);
                    ctx.set_return(SyscallReturn::ok(0));
                    return;
                }
                ctx.set_return(fail(EINVAL));
                return;
            }
            if crate::namespaces::install_held_ns(caller, outer, &held, nstype) {
                ctx.set_return(SyscallReturn::ok(0));
            } else {
                // The fd names a namespace, but not one of the type the
                // caller asked for — Linux's `ns->ns_type != flags`.
                ctx.set_return(fail(EINVAL));
            }
            return;
        }
    }

    // An open descriptor that is not a namespace file. Linux setns(2) takes
    // ONLY an fd; the old "legacy TaskId path" reinterpreted the fd NUMBER as
    // an outer pid and joined that process's namespaces with NO pid-namespace
    // translation — a containment hazard reachable by any caller passing a
    // stray integer, and non-Linux. No caller or test depended on it (#34),
    // so the number is rejected here as Linux's final `else` does.
    ctx.set_return(fail(EINVAL));
}
