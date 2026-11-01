//! Real typed parent/child capabilities retained by an exact netlink file.
use super::*;
use narf_capabilities::{Cap, Invoke, Write};
use narf_ipc::{Consumer, Producer};
use narf_net::netlink_generic::DeferredReplySink;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};

struct Device {
    name: String,
    namespace: Option<u64>,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl Interface for Device {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0x76, 0x17]
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        self.namespace
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
fn device(name: String, namespace: Option<u64>) -> Device {
    Device {
        name,
        namespace,
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    }
}
fn reject(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}
struct Fixture {
    name: String,
    child_name: String,
    parent: Cap<narf_net::NetIface, Write>,
    child: Cap<narf_net::NetIface, Write>,
    daemon: Cap<narf_net::stack::StackDaemon, Invoke>,
    parent_admin: narf_net::AdminHandle,
    child_admin: narf_net::AdminHandle,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        narf_net::registry().unregister_for_handle(&self.child);
        narf_net::registry().unregister_for_handle(&self.parent);
        narf_net::iface::unregister(&self.name);
    }
}
fn fixture() -> Result<Fixture, &'static str> {
    let name = narf_net::iface::register("socket-child-src%d", [2, 0, 0, 0, 0x76, 0x17], reject);
    let grant = narf_net::bootstrap_authority();
    let parent = narf_net::registry()
        .register(&grant, device(name.clone(), None))
        .map_err(|_| "actual socket parent registration")?;
    let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
    let parent_admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
        iface: parent,
        daemon,
    })
    .map_err(|_| "actual socket parent daemon grant")?
    .admin;
    let child_name = alloc::format!("{}-control", name);
    let child = narf_net::registry()
        .register_control_child(&grant, &parent, device(child_name.clone(), Some(0)))
        .map_err(|_| "actual socket control-child registration")?;
    let child_admin = parent_admin
        .control_registered_child(&child)
        .map_err(|_| "actual parent-to-child delegation")?
        .ok_or("delegated child grant absent")?;
    Ok(Fixture {
        name,
        child_name,
        parent,
        child,
        daemon,
        parent_admin,
        child_admin,
    })
}
fn socket(portid: u32) -> Result<(Arc<SocketFile>, GenericReplyEndpoint), &'static str> {
    let socket = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if !matches!(
        socket.dispatch_op(SocketOp::Bind {
            addr: SocketFile::netlink_sockaddr(portid, 0)
        }),
        SocketOpResult::Ok(_)
    ) {
        return Err("actual control source socket bind");
    }
    let endpoint =
        GenericReplyEndpoint::capture(&socket, socket.netlink_portid.load(Ordering::Acquire));
    Ok((socket, endpoint))
}
fn retains() -> Result<(), &'static str> {
    let f = fixture()?;
    let (socket, endpoint) = socket(0)?;
    socket
        .delegate_netlink_admin(f.parent_admin.clone())
        .map_err(|_| "actual source parent grant")?;
    endpoint
        .retain_control_admin(f.child_admin.clone())
        .map_err(|_| "exact source retains fresh child grant")?;
    if endpoint.control_admin(&f.child_name, 0).is_none()
        || endpoint.control_admin(&f.child_name, 27).is_some()
        || endpoint.control_admin(&f.name, 0).is_some()
        || endpoint
            .retain_control_admin(f.parent_admin.clone())
            .is_ok()
        || socket.netlink_controls.lock().len() != 1
    {
        return Err("exact source invented a child/parent/namespace grant");
    }
    // Replacing an explicit base delegation never inherits its old controls.
    socket
        .delegate_netlink_admin(f.parent_admin.clone())
        .map_err(|_| "explicit source grant replacement")?;
    if endpoint.control_admin(&f.child_name, 0).is_some()
        || !socket.netlink_controls.lock().is_empty()
    {
        return Err("base delegation replacement retained stale child controls");
    }
    Ok(())
}
fn netlink_control_child_admin_is_explicit_namespace_bound_and_pruned() -> TestResult {
    retains().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "userspace/socket",
    netlink_control_child_admin_is_explicit_namespace_bound_and_pruned
);

fn lost_grants() -> Result<(), &'static str> {
    for cause in 0..3 {
        let f = fixture()?;
        let (socket, endpoint) = socket(0)?;
        endpoint
            .retain_control_admin(f.child_admin.clone())
            .map_err(|_| "native source child retention")?;
        match cause {
            0 => f.parent.revoke(),
            1 => f.daemon.revoke(),
            _ => f.child.revoke(),
        }
        if endpoint.control_admin(&f.child_name, 0).is_some()
            || !socket.netlink_controls.lock().is_empty()
        {
            return Err(
                "source retained child administration after actual parent/daemon/child revocation",
            );
        }
    }
    Ok(())
}
fn netlink_control_child_admin_rechecks_parent_daemon_and_child_grants() -> TestResult {
    lost_grants().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "userspace/socket",
    netlink_control_child_admin_rechecks_parent_daemon_and_child_grants
);

fn closed() -> Result<(), &'static str> {
    let f = fixture()?;
    let (old, endpoint) = socket(0)?;
    endpoint
        .retain_control_admin(f.child_admin.clone())
        .map_err(|_| "old exact source control retention")?;
    let portid = endpoint.portid;
    drop(old);
    let (replacement, current) = socket(portid)?;
    if endpoint.current()
        || endpoint.control_admin(&f.child_name, 0).is_some()
        || endpoint.retain_control_admin(f.child_admin.clone()).is_ok()
        || current.control_admin(&f.child_name, 0).is_some()
        || !replacement.netlink_controls.lock().is_empty()
    {
        return Err("closed source/port reuse transferred an old control child grant");
    }
    current
        .retain_control_admin(f.child_admin.clone())
        .map_err(|_| "fresh explicit child delegation to new exact source")?;
    if current.control_admin(&f.child_name, 0).is_none() {
        return Err("fresh source's actual explicit child grant refused");
    }
    narf_net::registry().unregister_for_handle(&f.child);
    let next = narf_net::registry()
        .register_control_child(
            &narf_net::bootstrap_authority(),
            &f.parent,
            device(f.child_name.clone(), Some(0)),
        )
        .map_err(|_| "actual same-name control successor")?;
    let stale = current.control_admin(&f.child_name, 0).is_some();
    narf_net::registry().unregister_for_handle(&next);
    if stale || !replacement.netlink_controls.lock().is_empty() {
        return Err("same-name successor revived old source child authority");
    }
    Ok(())
}
fn netlink_control_child_admin_never_moves_across_close_rebind_or_replacement() -> TestResult {
    closed().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "userspace/socket",
    netlink_control_child_admin_never_moves_across_close_rebind_or_replacement
);
