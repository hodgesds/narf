//! Stage-4 daemon-attach protocol — real implementation behind
//! `stack::attach`.
//!
//! Workflow:
//! 1. Userspace daemon mints `Cap<StackDaemon, Invoke>` at spawn
//!    against `StackInstall`. (Per spec; handled in `init/`.)
//! 2. Daemon obtains a `Cap<NetIface, Write>` for the target iface
//!    via `Registry::register` (cap is the handle returned at
//!    register time).
//! 3. Daemon calls the [`crate::stack::attach`] entry, which lands
//!    here.
//! 4. We mint a fresh [`crate::AdminCap`], record (iface_name,
//!    socket=daemon's XDP socket) in the classifier's whole-NIC
//!    table, and return the admin cap to the daemon.
//!
//! Once attached, every inbound frame from the iface is routed to
//! the daemon's RX ring via [`super::classifier`] — the kernel
//! TCP/IP stack sees nothing from this iface.
//!
//! Detach is `[`detach`]`: classifier slot freed + admin cap left to
//! the caller (revocation is the caller's call). Re-attach is
//! permitted after detach.
//!
//! Linux ref: there isn't a clean Linux analog — AF_XDP's
//! `XDP_ATTACH` mode pins a single program per iface but doesn't
//! hand the whole NIC to one userspace process. NARF's daemon
//! attach is closer to DPDK's `rte_eth_dev_owner_set`.

use alloc::string::String;
use alloc::sync::Arc;

use narf_capabilities::{Cap, Invoke};

use crate::stack::{AttachError, StackAttach, StackAttachReply};
use crate::{AdminCap, Interface};

use super::classifier;
use super::xdp::XdpSocket;

/// Per-attached-iface record. Held while the daemon owns the iface.
/// `socket` and `admin` are kept for revocation / detach paths that
/// reach into the record to take the cap or the Arc — the dead-code
/// lint can't see those uses because they go through `__reset_for_test`
/// plus the classifier's `daemon_socket` helper rather than direct field
/// reads here.
#[allow(dead_code)]
#[derive(Clone)]
struct AttachRecord {
    iface_name: String,
    socket: Arc<XdpSocket>,
    admin: Cap<AdminCap, Invoke>,
}

impl core::fmt::Debug for AttachRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachRecord")
            .field("iface_name", &self.iface_name)
            .finish_non_exhaustive()
    }
}

static RECORDS: narf_lib::sync::IrqSafeSpinLock<alloc::vec::Vec<AttachRecord>> =
    narf_lib::sync::IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Real implementation of `stack::attach`. Validates both caps,
/// registers the daemon's bypass socket as the whole-NIC owner of
/// the iface, and returns a fresh AdminCap.
///
/// `socket` is the daemon's pre-created XDP socket — built via
/// `XdpSocket::create(umem)` so the four rings are paired and the
/// daemon already holds the user halves.
pub fn attach(
    req: &StackAttach,
    iface_obj: &dyn Interface,
    socket: Arc<XdpSocket>,
) -> Result<StackAttachReply, AttachError> {
    req.iface
        .check_live()
        .map_err(|_| AttachError::IfaceCapRevoked)?;
    req.daemon
        .check_live()
        .map_err(|_| AttachError::DaemonCapRevoked)?;

    let iface_name = alloc::string::String::from(iface_obj.name());

    let mut g = RECORDS.lock();
    if g.iter().any(|r| r.iface_name == iface_name) {
        return Err(AttachError::InterfaceBusy);
    }

    classifier::attach_daemon(iface_name.clone(), socket.clone())
        .map_err(|_| AttachError::InterfaceBusy)?;
    let admin = Cap::<AdminCap, Invoke>::bootstrap();
    g.push(AttachRecord {
        iface_name,
        socket,
        admin,
    });
    Ok(StackAttachReply { admin })
}

/// Detach the daemon currently bound to `iface_name`. Returns `true`
/// if a record was removed. The caller is responsible for revoking
/// the previously-issued admin cap.
pub fn detach(iface_name: &str) -> bool {
    let mut g = RECORDS.lock();
    let before = g.len();
    g.retain(|r| r.iface_name != iface_name);
    let removed = g.len() != before;
    drop(g);
    if removed {
        let _ = classifier::detach_daemon(iface_name);
    }
    removed
}

/// `true` iff `iface_name` is currently daemon-attached.
pub fn is_attached(iface_name: &str) -> bool {
    RECORDS.lock().iter().any(|r| r.iface_name == iface_name)
}

/// Snapshot of attached iface names. For diagnostics + tests.
pub fn attached_ifaces() -> alloc::vec::Vec<String> {
    RECORDS
        .lock()
        .iter()
        .map(|r| r.iface_name.clone())
        .collect()
}

/// Test-only reset hook. Drops every recorded attach.
#[doc(hidden)]
pub fn __reset_for_test() {
    RECORDS.lock().clear();
}
