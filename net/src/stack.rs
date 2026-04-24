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

use narf_capabilities::{Cap, CapKind, CapType, Invoke, Write};

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
    pub iface:  Cap<NetIface, Write>,
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
#[derive(Copy, Clone, Debug)]
pub struct StackAttachReply {
    pub admin: Cap<AdminCap, Invoke>,
}

/// Errors that can surface during attach.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttachError {
    DaemonCapRevoked,
    IfaceCapRevoked,
    InterfaceBusy,
    NotImplemented,
}

/// Attach a stack daemon to `iface`. Stage-4 structural — returns
/// `NotImplemented` until `abi/` grows a `StackAttach` opcode and
/// the kernel-side bootstrap is written.
pub fn attach(
    req: &StackAttach,
    _iface_object: &dyn Interface,
) -> Result<StackAttachReply, AttachError> {
    req.iface.check_live().map_err(|_| AttachError::IfaceCapRevoked)?;
    req.daemon.check_live().map_err(|_| AttachError::DaemonCapRevoked)?;
    Err(AttachError::NotImplemented)
}
