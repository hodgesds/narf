#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_unshare(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0;
    const CLONE_NEWNS: u64 = 0x00020000;
    #[cfg(feature = "container")]
    const CLONE_NEWPID: u64 = 0x20000000;

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
            ctx.set_return(SyscallReturn::ok(!0u64));
            return;
        }
    }

    #[cfg(feature = "container")]
    if flags & CLONE_NEWPID != 0 {
        let task = current_task_id();
        // The task's outer pid is what the root-namespace fork
        // recorded. If no mapping is present, fall back to the task
        // id itself — it's a kernel-spawned task with implicit
        // outer == inner already.
        let outer = task_to_pid_raw(task).unwrap_or(task);
        let _ns = crate::pid_ns::unshare_pid_ns(task, outer);
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
    {
        const CLONE_NEWCGROUP: u64 = 0x0200_0000;
        if flags & CLONE_NEWCGROUP != 0 {
            let task = current_task_id();
            let pid = task_to_pid_raw(task).unwrap_or(task);
            narf_filesystem::cgroupfs::unshare_cgroup_ns(pid);
            any = true;
        }
    }

    // Honour the no-op path (no NS bits set) as success — Linux unshare
    // returns 0 with flags=0.
    let _ = any;
    ctx.set_return(SyscallReturn::ok(0));
}
