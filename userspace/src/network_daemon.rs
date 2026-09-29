//! Explicit network-service launch authority. A typed stack-attach reply is
//! installed before the task can run; ordinary socket() then derives its
//! interface/namespace authority from that grant. UIDs convey no grant.

use crate::{socket::SocketFile, task::Task};

/// Prepare a network service without publishing it to the scheduler. The
/// caller chooses/loads the executable and supplies a successful stack attach.
/// This grants only that interface, including to fork/clone descendants;
/// exec retains the grant, like an inherited administrative socket.
/// Callers can install stdio/root/cwd using the pending task ID before spawn.
pub fn prepare(
    process: crate::UserProcess,
    reply: &narf_net::StackAttachReply,
    spec: narf_scheduler::TaskSpec,
) -> Result<crate::user_task::PendingUserProcess, narf_net::stack::AdminError> {
    // A freshly launched task starts in the initial network namespace.
    // Verify before registering a task, so denial creates no orphan task.
    reply
        .admin
        .authorize_interface(reply.admin.iface_name(), 0)?;
    let pending = crate::user_task::prepare_user_process_initial(process, spec);
    let task = crate::task::task_get(pending.task_id().raw()).expect("prepared user task");
    *task.network_admin.lock() = Some(reply.admin.clone());
    Ok(pending)
}

/// Launch a loaded network service with its explicit interface grant already
/// installed. No post-spawn race and no special userspace netlink-fd API.
pub fn spawn(
    process: crate::UserProcess,
    reply: &narf_net::StackAttachReply,
    spec: narf_scheduler::TaskSpec,
) -> Result<narf_scheduler::TaskId, narf_net::stack::AdminError> {
    Ok(prepare(process, reply, spec)?.spawn())
}

pub(crate) fn inherit(parent: u64, child: u64) {
    let grant = crate::task::task_get(parent).and_then(|task| task.network_admin.lock().clone());
    if let Some(task) = crate::task::task_get(child) {
        *task.network_admin.lock() = grant;
    }
}

pub(crate) fn delegate_socket(task: &Task, socket: &SocketFile) {
    use crate::socket::{AF_NETLINK, NETLINK_GENERIC, NETLINK_ROUTE};
    if socket.domain != AF_NETLINK || !matches!(socket.protocol, NETLINK_GENERIC | NETLINK_ROUTE) {
        return;
    }
    let grant = task.network_admin.lock().clone();
    if let Some(admin) = grant {
        // Namespace moves/revocation remove effective authority. They do
        // not prevent creating a socket for unprivileged queries/events.
        if admin
            .authorize_interface(admin.iface_name(), socket.net_ns_id())
            .is_ok()
        {
            let _ = socket.delegate_netlink_admin(admin);
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::socket::{AF_INET, AF_NETLINK, NETLINK_GENERIC, NETLINK_ROUTE, SOCK_RAW};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_network_daemon_grant_scope_and_inheritance() -> TestResult {
        let parent = narf_scheduler::alloc_task_id().raw();
        let child = narf_scheduler::alloc_task_id().raw();
        let parent_task = Task::new_registered(parent, parent);
        let child_task = Task::new_registered(child, child);
        let result = (|| {
            let ordinary = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
            delegate_socket(&parent_task, &ordinary);
            if ordinary.__test_has_netlink_admin() {
                return TestResult::Fail("ordinary task acquired network authority");
            }
            *parent_task.network_admin.lock() = Some(narf_net::initial_loopback_admin());
            inherit(parent, child);
            for protocol in [NETLINK_GENERIC, NETLINK_ROUTE] {
                let socket = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, protocol);
                delegate_socket(&child_task, &socket);
                if !socket.__test_has_netlink_admin() {
                    return TestResult::Fail("launched daemon/child lost explicit grant");
                }
                let other_ns = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, protocol);
                other_ns.set_net_ns_id(0x1199);
                delegate_socket(&child_task, &other_ns);
                if other_ns.__test_has_netlink_admin() {
                    return TestResult::Fail("grant escaped its network namespace");
                }
            }
            let inet = SocketFile::with_protocol(AF_INET, SOCK_RAW, 1);
            delegate_socket(&child_task, &inet);
            if inet.__test_has_netlink_admin() || ordinary.__test_has_netlink_admin() {
                return TestResult::Fail("grant retroactively changed unrelated sockets");
            }
            TestResult::Pass
        })();
        crate::task::release_task(child);
        crate::task::release_task(parent);
        result
    }
    kernel_test_in!(
        "userspace/network_daemon",
        smoke_network_daemon_grant_scope_and_inheritance
    );
}
