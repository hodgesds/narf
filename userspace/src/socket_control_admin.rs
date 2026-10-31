//! Explicit fresh control-child grants stay with the exact creating file.
//! No port-id/name lookup or serialized wire capability installs authority.
use super::*;

impl GenericReplyEndpoint {
    pub(super) fn retain_child_admin(&self, admin: narf_net::AdminHandle) -> Result<(), i32> {
        use narf_net::netlink_generic::DeferredReplySink;
        if !self.current() {
            return Err(125);
        }
        if !admin.is_control_child() || admin.net_ns_id().ok() != Some(self.namespace) {
            return Err(1);
        }
        let socket = self.socket.upgrade().ok_or(125)?;
        {
            let mut controls = socket.netlink_controls.lock();
            controls.retain(|old| old.is_live() && old.net_ns_id().ok() == Some(self.namespace));
            controls.retain(|old| old.iface_name() != admin.iface_name());
            controls.push(admin);
        }
        if !self.current() {
            return Err(125);
        }
        Ok(())
    }
    pub(super) fn child_admin(&self, name: &str, namespace: u64) -> Option<narf_net::AdminHandle> {
        use narf_net::netlink_generic::DeferredReplySink;
        if namespace != self.namespace || !self.current() {
            return None;
        }
        let socket = self.socket.upgrade()?;
        let mut controls = socket.netlink_controls.lock();
        controls.retain(|admin| admin.is_live() && admin.net_ns_id().ok() == Some(namespace));
        controls
            .iter()
            .find(|admin| admin.authorize_interface(name, namespace).is_ok())
            .cloned()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "socket_control_admin_tests.rs"]
mod tests;
