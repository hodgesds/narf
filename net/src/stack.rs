//! Userspace stack-daemon attach protocol — Stage-4 structural
//! shape.
//!
//! Spec: `net/specification/spec.md` (Stage-4: userspace stack-
//! daemon attach protocol, admin cap flow). In the NARF model the
//! TCP/IP stack itself lives in a user-mode daemon; the kernel
//! only moves frames through cap-gated rings and publishes
//! per-interface admin handles.
//!
//! Protocol shapes pinned here:
//! - `StackAttach` — the slow-path bootstrap request the user
//!   daemon submits to claim an interface. Carries
//!   `Cap<NetIface, Write>` + the daemon's own identity.
//! - `StackAttachReply` — kernel response with an `AdminCap` +
//!   the pair of rings (RX consumer + TX producer) already
//!   installed.
//! - `AdminCap` marker type — `Cap<AdminCap, Invoke>` is the
//!   authority to set link state / MTU / MAC on the attached
//!   interface.
//!
//! The public attach path resolves the presented interface cap against the
//! driver registry before binding the daemon. A future userspace ABI opcode
//! still needs per-task cap-table resolution before it can expose this path.

use alloc::string::String;
use alloc::sync::Arc;

use narf_capabilities::{Cap, CapKind, CapType, Invoke, Write};

use crate::bypass::xdp::XdpSocket;
use crate::{Interface, NetIface};
#[path = "stack_child.rs"]
mod child;
#[cfg(feature = "kernel-test")]
#[path = "stack_identity_tests.rs"]
mod identity_tests;
#[path = "stack_metadata.rs"]
pub(crate) mod metadata;

/// Cap-type marker for per-interface admin authority.
/// `Cap<AdminCap, Invoke>` gates `set_link_up` / `set_mtu` /
/// `set_mac` on the attached interface. Distinct from
/// `Cap<NetIface, Write>` (which is the frame-ring handle) so an
/// audit can tell "may drive this NIC" apart from "may reconfigure
/// this NIC".
#[derive(Copy, Clone, Debug)]
pub struct AdminCap;

impl CapType for AdminCap {
    const KIND: CapKind = CapKind::NetIface;
}

/// Attach request from a userspace stack daemon. The daemon presents
/// prior `Cap<NetIface, Write>` plus the daemon's own
/// `Cap<StackDaemon, Invoke>` identity (the latter is minted at
/// daemon spawn time against `StackInstall`).
#[derive(Copy, Clone, Debug)]
pub struct StackAttach {
    pub iface: Cap<NetIface, Write>,
    pub daemon: Cap<StackDaemon, Invoke>,
}

/// Marker for the stack-daemon identity cap.
#[derive(Copy, Clone, Debug)]
pub struct StackDaemon;

impl CapType for StackDaemon {
    const KIND: CapKind = CapKind::StackInstall;
}

/// Reply the kernel sends back to a successful `StackAttach`.
/// Carries the admin authority the daemon holds for the rest of
/// the interface's lifetime.
#[derive(Clone, Debug)]
pub struct StackAttachReply {
    pub admin: AdminHandle,
}

/// Per-interface administrative authority. The interface name is inseparable
/// from the revocable cap, preventing a valid cap for one NIC from being
/// replayed against another NIC's control plane.
#[derive(Clone, Debug)]
pub struct AdminHandle {
    cap: Cap<AdminCap, Invoke>,
    iface_name: String,
    source: Option<AdminSource>,
}
#[derive(Clone, Debug)]
struct AdminSource {
    attach: StackAttach,
    registration: Option<u64>,
    parent: Option<child::ControlParent>,
}

/// Mint the kernel-held administrative handle for the initial namespace's
/// synthetic loopback device.
///
/// This is intentionally narrower than a stack-daemon attachment: callers
/// can operate only on `lo`, which has ifindex 1 and is always up. The Linux
/// syscall ABI never accepts a serialized admin handle.
pub fn initial_loopback_admin() -> AdminHandle {
    AdminHandle::new(Cap::<AdminCap, Invoke>::bootstrap(), String::from("lo"))
}

/// Kernel-held administrative handles, one per interface name, minted on
/// first use and cached (minting allocates a capability slot, so it must not
/// happen per request). These carry the authority a Linux caller holding
/// CAP_NET_ADMIN over the interface's network namespace exercises through
/// rtnetlink; the netlink layer decides who may use them.
static KERNEL_ADMIN: narf_lib::sync::IrqSafeSpinLock<
    alloc::collections::BTreeMap<String, AdminHandle>,
> = narf_lib::sync::IrqSafeSpinLock::new(alloc::collections::BTreeMap::new());

/// The kernel-held handle for `iface`, or `None` if no such interface exists.
pub fn kernel_admin(iface: &str) -> Option<AdminHandle> {
    if iface != "lo"
        && crate::iface::lookup(iface).is_none()
        && !crate::registry()
            .with_interface(iface, |iface| iface.control_namespace().is_some())
            .unwrap_or(false)
    {
        return None;
    }
    if let Some(handle) = KERNEL_ADMIN.lock().get(iface) {
        return Some(handle.clone());
    }
    let minted = if iface == "lo" {
        initial_loopback_admin()
    } else {
        AdminHandle::new(Cap::<AdminCap, Invoke>::bootstrap(), String::from(iface))
    };
    Some(
        KERNEL_ADMIN
            .lock()
            .entry(String::from(iface))
            .or_insert(minted)
            .clone(),
    )
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AdminIpv4Route {
    pub dst: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
    pub preferred_src: Option<[u8; 4]>,
    pub metric: u32,
    pub scope: crate::route::Scope,
    pub table: u8,
    /// `rtm_protocol` of the request.
    pub protocol: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AdminIpv6Route {
    pub dst: [u8; 16],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 16]>,
    pub metric: u32,
}

impl AdminHandle {
    pub(crate) fn new(cap: Cap<AdminCap, Invoke>, iface_name: String) -> Self {
        Self {
            cap,
            iface_name,
            source: None,
        }
    }

    pub fn iface_name(&self) -> &str {
        &self.iface_name
    }

    pub fn is_live(&self) -> bool {
        self.check_live().is_ok()
    }

    pub fn net_ns_id(&self) -> Result<u64, AdminError> {
        self.check_live()?;
        self.observed_namespace().ok_or(AdminError::NoIface)
    }
    fn observed_namespace(&self) -> Option<u64> {
        if self.iface_name == "lo" {
            return Some(0);
        }
        if let Some(iface) = crate::iface::lookup(&self.iface_name) {
            return Some(iface.net_ns_id);
        }
        crate::registry().with_interface(&self.iface_name, |iface| {
            iface.control_namespace().unwrap_or(0)
        })
    }

    pub fn check_live(&self) -> Result<(), AdminError> {
        self.cap
            .invoke(AdminLiveness(self))
            .map_err(|_| AdminError::AuthorityRevoked)?
            .then_some(())
            .ok_or(AdminError::NoIface)
    }

    /// Invoke the interface/namespace authorization operation at the
    /// control-plane boundary. A stored handle alone is not authority
    /// after revocation or transfer to another network namespace.
    pub fn authorize_interface(&self, name: &str, net_ns_id: u64) -> Result<(), AdminError> {
        let permitted = self
            .cap
            .invoke(AdminContext {
                handle: self,
                name,
                net_ns_id,
                ownership_epoch: None,
            })
            .map_err(|_| AdminError::AuthorityRevoked)?;
        if permitted {
            Ok(())
        } else {
            Err(AdminError::NoIface)
        }
    }

    pub fn set_link(&self, up: bool) -> Result<(), AdminError> {
        self.check_live()?;
        // Loopback is synthetic rather than a legacy L3 interface. It is
        // permanently up, so systemd's idempotent RTM_SETLINK(IFF_UP) is a
        // successful no-op.
        if self.iface_name == "lo" && up {
            return Ok(());
        }
        crate::iface::admin::apply(self, crate::iface::admin::Change::Link(up))
    }

    /// Transfer this interface to a network namespace. The interface-bound
    /// capability is checked immediately before changing ownership.
    pub fn move_to_net_ns(&self, net_ns_id: u64) -> Result<(), AdminError> {
        self.check_live()?;
        crate::iface::set_net_ns(&self.iface_name, net_ns_id)
            .then_some(())
            .ok_or(AdminError::NoIface)
    }

    pub fn set_mtu(&self, mtu: u32) -> Result<(), AdminError> {
        self.check_live()?;
        if !(68..=65_535).contains(&mtu) {
            return Err(AdminError::InvalidMtu);
        }
        crate::iface::admin::apply(self, crate::iface::admin::Change::Mtu(mtu))
    }

    pub fn set_mac(&self, mac: [u8; 6]) -> Result<(), AdminError> {
        self.check_live()?;
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(AdminError::InvalidMac);
        }
        crate::iface::admin::apply(self, crate::iface::admin::Change::Mac(mac))
    }

    pub fn add_ipv4(&self, addr: [u8; 4], prefix_len: u8) -> Result<(), AdminError> {
        self.check_live()?;
        if prefix_len > 32 {
            return Err(AdminError::InvalidPrefix);
        }
        crate::iface::add_addr(&self.iface_name, addr, prefix_len);
        Ok(())
    }

    pub fn del_ipv4(&self, addr: [u8; 4], prefix_len: u8) -> Result<(), AdminError> {
        self.check_live()?;
        if prefix_len > 32 {
            return Err(AdminError::InvalidPrefix);
        }
        crate::iface::del_addr(&self.iface_name, addr, prefix_len);
        Ok(())
    }

    pub fn add_ipv6(&self, addr: [u8; 16], prefix_len: u8) -> Result<(), AdminError> {
        self.check_live()?;
        if prefix_len > 128 {
            return Err(AdminError::InvalidPrefix);
        }
        if crate::iface::lookup(&self.iface_name).is_none() {
            return Err(AdminError::NoIface);
        }
        crate::ipv6::addrs::add(crate::ipv6::addrs::Ipv6IfAddr {
            iface: self.iface_name.clone(),
            addr,
            prefix_len,
            state: crate::ipv6::addrs::AddrState::Preferred,
            scope: crate::ipv6::addrs::scope_of(&addr),
            preferred_deadline_ns: u64::MAX,
            valid_deadline_ns: u64::MAX,
            temporary: false,
        });
        Ok(())
    }

    pub fn del_ipv6(&self, addr: [u8; 16], prefix_len: u8) -> Result<(), AdminError> {
        self.check_live()?;
        if prefix_len > 128 {
            return Err(AdminError::InvalidPrefix);
        }
        crate::ipv6::addrs::remove(&self.iface_name, &addr);
        Ok(())
    }

    pub fn add_ipv4_route(&self, route: AdminIpv4Route) -> Result<(), AdminError> {
        self.check_live()?;
        if route.prefix_len > 32 {
            return Err(AdminError::InvalidPrefix);
        }
        let iface = crate::iface::lookup(&self.iface_name).ok_or(AdminError::NoIface)?;
        crate::route::route_add(crate::route::Route {
            net_ns_id: iface.net_ns_id,
            dst: crate::route::Ipv4Net {
                addr: crate::ipv4::Ipv4Addr(route.dst),
                prefix_len: route.prefix_len,
            },
            gateway: route.gateway.map(crate::ipv4::Ipv4Addr),
            iface: self.iface_name.clone(),
            src_hint: route.preferred_src.map(crate::ipv4::Ipv4Addr),
            metric: route.metric,
            scope: route.scope,
            table: route.table,
            protocol: route.protocol,
        });
        Ok(())
    }

    pub fn del_ipv4_route(
        &self,
        dst: [u8; 4],
        prefix_len: u8,
        table: u8,
    ) -> Result<(), AdminError> {
        self.del_ipv4_route_matching(dst, prefix_len, table, None, None, 0)
            .map(|_| ())
    }

    /// `fib_table_delete` on this interface: remove the first route at
    /// `dst/prefix_len` in `table` whose metric, gateway and protocol match
    /// those given (`None`/0 match anything). `Ok(false)` when none did.
    pub fn del_ipv4_route_matching(
        &self,
        dst: [u8; 4],
        prefix_len: u8,
        table: u8,
        metric: Option<u32>,
        gateway: Option<[u8; 4]>,
        protocol: u8,
    ) -> Result<bool, AdminError> {
        self.check_live()?;
        if prefix_len > 32 {
            return Err(AdminError::InvalidPrefix);
        }
        let iface = crate::iface::lookup(&self.iface_name).ok_or(AdminError::NoIface)?;
        Ok(crate::route::route_delete_matching_in(
            iface.net_ns_id,
            crate::route::Ipv4Net {
                addr: crate::ipv4::Ipv4Addr(dst),
                prefix_len,
            },
            table,
            crate::route::RouteMatch {
                iface: Some(&self.iface_name),
                metric,
                gateway: gateway.map(crate::ipv4::Ipv4Addr),
                protocol,
            },
        ))
    }

    pub fn add_ipv6_route(&self, route: AdminIpv6Route) -> Result<(), AdminError> {
        self.check_live()?;
        if route.prefix_len > 128 {
            return Err(AdminError::InvalidPrefix);
        }
        if crate::iface::lookup(&self.iface_name).is_none() {
            return Err(AdminError::NoIface);
        }
        crate::ipv6::route::add(crate::ipv6::route::Route {
            prefix: route.dst,
            prefix_len: route.prefix_len,
            gateway: route.gateway,
            iface: self.iface_name.clone(),
            metric: route.metric,
            valid_deadline_ns: 0,
        });
        Ok(())
    }

    pub fn del_ipv6_route(&self, dst: [u8; 16], prefix_len: u8) -> Result<(), AdminError> {
        self.check_live()?;
        if prefix_len > 128 {
            return Err(AdminError::InvalidPrefix);
        }
        crate::ipv6::route::remove(&dst, prefix_len, &self.iface_name);
        Ok(())
    }

    pub fn set_ipv4_neighbor(&self, ip: [u8; 4], mac: [u8; 6]) -> Result<(), AdminError> {
        self.check_live()?;
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(AdminError::InvalidMac);
        }
        crate::arp::insert(&self.iface_name, ip, mac);
        Ok(())
    }

    pub fn del_ipv4_neighbor(&self, ip: [u8; 4]) -> Result<(), AdminError> {
        self.check_live()?;
        crate::arp::remove(&self.iface_name, ip);
        Ok(())
    }

    pub fn set_ipv6_neighbor(
        &self,
        ip: [u8; 16],
        mac: Option<[u8; 6]>,
        state: crate::ipv6::ndp::NeighState,
        is_router: bool,
    ) -> Result<(), AdminError> {
        self.check_live()?;
        if mac.is_some_and(|mac| mac == [0; 6] || mac[0] & 1 != 0) {
            return Err(AdminError::InvalidMac);
        }
        crate::ipv6::ndp::neigh_upsert(crate::ipv6::ndp::Neigh {
            iface: self.iface_name.clone(),
            ip,
            mac,
            state,
            is_router,
            deadline_ns: 0,
        });
        Ok(())
    }

    pub fn del_ipv6_neighbor(&self, ip: [u8; 16]) -> Result<(), AdminError> {
        self.check_live()?;
        crate::ipv6::ndp::neigh_remove(&self.iface_name, &ip);
        Ok(())
    }
}

struct AdminContext<'a> {
    handle: &'a AdminHandle,
    name: &'a str,
    net_ns_id: u64,
    ownership_epoch: Option<u64>,
}
impl narf_capabilities::CapOp<AdminCap, Invoke> for AdminContext<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<AdminCap, Invoke>) -> Result<bool, narf_capabilities::CapError> {
        if self.handle.iface_name() != self.name {
            return Ok(false);
        }
        if let Some(source) = self.handle.source.as_ref() {
            source.attach.daemon.invoke(DelegatedAdminIdentity {
                source,
                name: self.name,
                namespace: Some(self.net_ns_id),
                ownership_epoch: self.ownership_epoch,
            })
        } else {
            // Kernel namespace/name handles retain their existing scope.
            Ok(self.handle.observed_namespace() == Some(self.net_ns_id))
        }
    }
}
struct AdminLiveness<'a>(&'a AdminHandle);
impl narf_capabilities::CapOp<AdminCap, Invoke> for AdminLiveness<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<AdminCap, Invoke>) -> Result<bool, narf_capabilities::CapError> {
        match self.0.source.as_ref() {
            Some(source) => source.attach.daemon.invoke(DelegatedAdminIdentity {
                source,
                name: self.0.iface_name(),
                namespace: None,
                ownership_epoch: None,
            }),
            None => Ok(true),
        }
    }
}
#[derive(Clone, Copy)]
struct DelegatedAdminIdentity<'a> {
    source: &'a AdminSource,
    name: &'a str,
    namespace: Option<u64>,
    ownership_epoch: Option<u64>,
}
impl narf_capabilities::CapOp<StackDaemon, Invoke> for DelegatedAdminIdentity<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<StackDaemon, Invoke>) -> Result<bool, narf_capabilities::CapError> {
        if self
            .source
            .parent
            .as_ref()
            .is_some_and(|parent| !parent.current())
        {
            return Ok(false);
        }
        self.source.attach.iface.invoke(self)
    }
}
impl narf_capabilities::CapOp<NetIface, Write> for DelegatedAdminIdentity<'_> {
    type Output = bool;
    fn execute(self, cap: &Cap<NetIface, Write>) -> Result<bool, narf_capabilities::CapError> {
        Ok(crate::registry()
            .with_interface_for_handle(cap, |iface| {
                if iface.name() != self.name {
                    return false;
                }
                if let Some(namespace) = iface.control_namespace() {
                    self.source.registration.is_none()
                        && crate::iface::registration_matches(self.name, None, None)
                        && self.namespace.is_none_or(|expected| expected == namespace)
                } else {
                    crate::iface::registration_owner_matches(
                        self.name,
                        self.source.registration,
                        self.namespace,
                        self.ownership_epoch,
                    )
                }
            })
            .unwrap_or(false))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AdminError {
    /// Positive Linux errno from the device's hardware control callback.
    DeviceError(i32),
    AuthorityRevoked,
    NoIface,
    InvalidMtu,
    InvalidMac,
    InvalidPrefix,
}

/// Errors that can surface during attach.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttachError {
    DaemonCapRevoked,
    IfaceCapRevoked,
    /// The interface cap is live but was not minted for a registered entry.
    IfaceMismatch,
    InterfaceBusy,
}

/// Attach a stack daemon to `iface`. Verifies both caps, registers
/// the daemon's pre-created XDP socket as the whole-NIC owner of
/// the iface in the bypass classifier, and returns a fresh
/// AdminCap.
///
/// `socket` is the XdpSocket the daemon built earlier via
/// `XdpSocket::create(umem)` (so the daemon already holds the
/// user-side halves of the four rings). After this call returns,
/// every inbound frame from `iface_object` is routed to the daemon's
/// RX ring via the classifier and the kernel TCP/IP stack sees
/// nothing from that iface.
pub fn attach(
    req: &StackAttach,
    iface_object: &dyn Interface,
    socket: Arc<XdpSocket>,
) -> Result<StackAttachReply, AttachError> {
    crate::bypass::daemon_attach::attach(req, iface_object, socket)
}

/// Attach using the canonical driver registry. The presented interface cap
/// must be the exact handle retained beside the selected interface object.
pub fn attach_registered(
    req: &StackAttach,
    socket: Arc<XdpSocket>,
) -> Result<StackAttachReply, AttachError> {
    req.iface
        .check_live()
        .map_err(|_| AttachError::IfaceCapRevoked)?;
    crate::registry()
        .with_interface_for_handle(&req.iface, |iface| attach(req, iface, socket))
        .ok_or(AttachError::IfaceMismatch)?
}

/// Delegate control of a registered interface without attaching its frame
/// path to an XDP stack. Wireless supplicants need administration while the
/// existing IP stack continues to receive traffic. Both presented grants
/// must remain live for the resulting handle's lifetime.
pub fn control_registered(req: &StackAttach) -> Result<StackAttachReply, AttachError> {
    req.daemon
        .invoke(ControlGrant(*req))
        .map_err(|_| AttachError::DaemonCapRevoked)?
}
struct ControlGrant(StackAttach);
impl narf_capabilities::CapOp<StackDaemon, Invoke> for ControlGrant {
    type Output = Result<StackAttachReply, AttachError>;
    fn execute(
        self,
        _: &Cap<StackDaemon, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        Ok(match self.0.iface.invoke(InterfaceControl(self.0)) {
            Ok(Some(reply)) => Ok(reply),
            Ok(None) => Err(AttachError::IfaceMismatch),
            Err(_) => Err(AttachError::IfaceCapRevoked),
        })
    }
}
struct InterfaceControl(StackAttach);
impl narf_capabilities::CapOp<NetIface, Write> for InterfaceControl {
    type Output = Option<StackAttachReply>;
    fn execute(
        self,
        cap: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        Ok(crate::registry()
            .with_interface_for_handle(cap, |iface| {
                let registration = crate::iface::registration_identity(iface.name());
                if registration == Some(0) {
                    return None;
                }
                Some(StackAttachReply {
                    admin: AdminHandle {
                        cap: Cap::<AdminCap, Invoke>::bootstrap(),
                        iface_name: String::from(iface.name()),
                        source: Some(AdminSource {
                            attach: self.0,
                            registration,
                            parent: None,
                        }),
                    },
                })
            })
            .flatten())
    }
}
