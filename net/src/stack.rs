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
//! Real attach handling happens in a future `abi/` opcode +
//! dispatch wiring; this module lets every consumer agree on the
//! wire shape.

use alloc::string::String;
use alloc::sync::Arc;

use narf_capabilities::{Cap, CapKind, CapType, Invoke, Write};

use crate::bypass::xdp::XdpSocket;
use crate::{Interface, NetIface};

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
}

impl AdminHandle {
    pub(crate) fn new(cap: Cap<AdminCap, Invoke>, iface_name: String) -> Self {
        Self { cap, iface_name }
    }

    pub fn iface_name(&self) -> &str {
        &self.iface_name
    }

    pub fn is_live(&self) -> bool {
        self.cap.is_live()
    }

    pub fn check_live(&self) -> Result<(), AdminError> {
        self.cap
            .check_live()
            .map_err(|_| AdminError::AuthorityRevoked)
    }

    pub fn set_link(&self, up: bool) -> Result<(), AdminError> {
        self.check_live()?;
        crate::iface::set_link_state(&self.iface_name, up)
            .then_some(())
            .ok_or(AdminError::NoIface)
    }

    pub fn set_mtu(&self, mtu: u32) -> Result<(), AdminError> {
        self.check_live()?;
        if !(68..=65_535).contains(&mtu) {
            return Err(AdminError::InvalidMtu);
        }
        crate::iface::set_mtu(&self.iface_name, mtu)
            .then_some(())
            .ok_or(AdminError::NoIface)
    }

    pub fn set_mac(&self, mac: [u8; 6]) -> Result<(), AdminError> {
        self.check_live()?;
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(AdminError::InvalidMac);
        }
        crate::iface::set_mac(&self.iface_name, mac)
            .then_some(())
            .ok_or(AdminError::NoIface)
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

    pub fn add_ipv4_route(&self, route: AdminIpv4Route) -> Result<(), AdminError> {
        self.check_live()?;
        if route.prefix_len > 32 {
            return Err(AdminError::InvalidPrefix);
        }
        if crate::iface::lookup(&self.iface_name).is_none() {
            return Err(AdminError::NoIface);
        }
        crate::route::route_add(crate::route::Route {
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
        });
        Ok(())
    }

    pub fn del_ipv4_route(
        &self,
        dst: [u8; 4],
        prefix_len: u8,
        table: u8,
    ) -> Result<(), AdminError> {
        self.check_live()?;
        if prefix_len > 32 {
            return Err(AdminError::InvalidPrefix);
        }
        crate::route::route_delete(
            crate::route::Ipv4Net {
                addr: crate::ipv4::Ipv4Addr(dst),
                prefix_len,
            },
            &self.iface_name,
            table,
        );
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AdminError {
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
