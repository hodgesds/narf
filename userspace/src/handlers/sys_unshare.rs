#[allow(unused_imports)]
use super::*;

const ENOMEM: i64 = 12;
const EINVAL: i64 = 22;

#[inline]
fn fail(errno: i64) -> SyscallReturn {
    SyscallReturn::ok((-errno) as u64)
}

// The exact set `kernel/fork.c::check_unshare_flags` accepts. `unshare(2)`
// takes an `unsigned long`, so every other bit — including the whole upper
// half of the word — is rejected.
const CLONE_NEWTIME: u64 = 0x0000_0080;
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;
const UNSHARE_VALID_FLAGS: u64 = CLONE_THREAD
    | CLONE_FS
    | CLONE_NEWNS
    | CLONE_SIGHAND
    | CLONE_VM
    | CLONE_FILES
    | CLONE_SYSVSEM
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWCGROUP
    | CLONE_NEWTIME;

/// `kernel/fork.c::ksys_unshare` → `check_unshare_flags`:
///
/// ```text
///   if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND|
///                         CLONE_VM|CLONE_FILES|CLONE_SYSVSEM|
///                         CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|
///                         CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWCGROUP|
///                         CLONE_NEWTIME))
///           return -EINVAL;
/// ```
///
/// checked BEFORE any namespace is actually unshared, so a call carrying one
/// unsupported bit changes nothing at all. NARF used to ignore unknown bits
/// entirely and return 0, which is worse than a wrong errno: a runtime that
/// probes for a namespace feature by calling `unshare(CLONE_NEW<x>)` and
/// checking for EINVAL concluded the feature was present, then ran the
/// workload unisolated. Feature probing is exactly what runc, bubblewrap and
/// systemd's `RestrictNamespaces=` do at startup.
///
/// The one remaining failure inside the handler is the mount-namespace table
/// refusing to initialise, which is an allocation failure — `copy_mnt_ns`'s
/// -ENOMEM, not the `-1`/EPERM it used to report. A caller retries ENOMEM;
/// EPERM tells it to give up and drop privileges it never lacked.
///
/// LINUX-GAP, both about checks NARF cannot make yet:
///   * `unshare(CLONE_NEWNS)` without CAP_SYS_ADMIN in the owning user
///     namespace is -EPERM (`fs/namespace.c::copy_mnt_ns`); NARF models no
///     per-task capability set here.
///   * `ksys_unshare` folds CLONE_NEWUSER into CLONE_THREAD|CLONE_FS first,
///     and `check_unshare_flags` then rejects CLONE_THREAD/SIGHAND/VM with
///     -EINVAL unless the caller is single-threaded — so `unshare(CLONE_NEWUSER)`
///     from a multi-threaded process fails on Linux and succeeds here.
pub(crate) fn sys_unshare(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0;

    // `check_unshare_flags` runs before anything is unshared: an unsupported
    // bit leaves the caller's namespaces untouched.
    if flags & !UNSHARE_VALID_FLAGS != 0 {
        ctx.set_return(fail(EINVAL));
        return;
    }

    let mut any = false;

    if flags & CLONE_NEWNS != 0 {
        task_mount_ns_init();
        let task = current_task_id();
        let snap = snapshot_current_mount_namespace();
        let mut g = TASK_MOUNT_NS.lock();
        if let Some(m) = g.as_mut() {
            m.insert(task, snap);
            any = true;
        } else {
            // The per-task namespace table could not be created — the
            // allocation failure `copy_mnt_ns` reports as -ENOMEM.
            ctx.set_return(fail(ENOMEM));
            return;
        }
    }

    #[cfg(feature = "container")]
    if flags & CLONE_NEWPID != 0 {
        let task = current_task_id();
        let _ns = crate::pid_ns::unshare_pid_ns_for_children(task);
        any = true;
    }

    // Wave-72 — UTS / NET / IPC namespaces.
    #[cfg(feature = "container")]
    {
        let task = current_task_id();
        // CLONE_NEWUSER must be applied FIRST: Linux makes the caller
        // uid 0 inside the new user-ns and (in a real cap model) grants
        // a full cap set, which is what authorises the other unshares.
        // We record the creator's HOST uid as the ns owner, then set
        // the caller's in-ns uid/gid to 0 so it is root *inside*.
        if flags & crate::namespaces::CLONE_NEWUSER != 0 {
            let host_uid = read_uidgid(task).euid;
            let _ns = crate::namespaces::unshare_user(task, host_uid);
            // The caller becomes uid 0 inside the new namespace.
            let _ = write_uidgid(task, |e| {
                e.uid = 0;
                e.gid = 0;
                e.euid = 0;
                e.egid = 0;
                e.fsuid = 0;
                e.fsgid = 0;
            });
            any = true;
        }
        if flags & crate::namespaces::CLONE_NEWUTS != 0 {
            crate::namespaces::unshare_uts(task);
            any = true;
        }
        if flags & crate::namespaces::CLONE_NEWNET != 0 {
            crate::namespaces::unshare_net(task);
            any = true;
        }
        if flags & crate::namespaces::CLONE_NEWIPC != 0 {
            crate::namespaces::unshare_ipc(task);
            any = true;
        }
    }

    // CLONE_NEWCGROUP — pin the calling process's current cgroup as its
    // cgroup-namespace root so /proc/self/cgroup renders relative to it.
    #[cfg(all(feature = "cgroup", feature = "container"))]
    if flags & CLONE_NEWCGROUP != 0 {
        let task = current_task_id();
        let pid = task_to_pid_raw(task).unwrap_or(task);
        narf_filesystem::cgroupfs::unshare_cgroup_ns(pid);
        any = true;
    }

    // Honour the no-op path (no NS bits set) as success — Linux unshare
    // returns 0 with flags=0.
    let _ = any;
    ctx.set_return(SyscallReturn::ok(0));
}
