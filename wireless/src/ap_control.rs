//! Current authority and interface/mode identity for native async AP work.
//! A netlink reply sink supplies liveness, never administrative authority.

use alloc::sync::{Arc, Weak};
use core::{fmt, num::NonZeroU64};
use narf_net::{netlink_generic::DeferredReplySink, AdminHandle};

use crate::{WirelessError, WirelessNetIface};

#[cfg(feature = "kernel-test")]
#[path = "ap_control_tests.rs"]
mod tests;

/// An actual request's existing administrative grant plus exact interface
/// and mode generation. Drivers check it at command/poll/publication
/// boundaries; retaining this object alone never proves current authority.
#[derive(Clone)]
pub struct ApControlAuthority {
    iface: Weak<dyn WirelessNetIface>,
    admin: AdminHandle,
    namespace: u64,
    ifindex: u32,
    mode: u32,
    generation: NonZeroU64,
    reply: Arc<dyn DeferredReplySink>,
}

impl fmt::Debug for ApControlAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApControlAuthority")
            .field("namespace", &self.namespace)
            .field("ifindex", &self.ifindex)
            .field("mode", &self.mode)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl narf_net::netlink_generic::DeferredAuthority for ApControlAuthority {
    fn current(&self) -> bool {
        ApControlAuthority::current(self).is_ok()
    }
}

impl ApControlAuthority {
    /// Bind an existing grant to this actual registered AP/GO and exact
    /// source socket. Namespace and ifindex are the original request's
    /// kernel-resolved identity, never a fresh lookup after a transfer.
    /// Trusted registration pairs net/wireless entries for the same device.
    /// No administrative capability is minted or exported.
    pub fn bind(
        admin: AdminHandle,
        iface: &Arc<dyn WirelessNetIface>,
        namespace: u64,
        ifindex: u32,
        reply: Arc<dyn DeferredReplySink>,
    ) -> Result<Self, WirelessError> {
        let generation = iface
            .ap_control_generation()
            .ok_or(WirelessError::NotSupported)?;
        let authority = Self {
            iface: Arc::downgrade(iface),
            admin,
            namespace,
            ifindex,
            mode: iface.current_iftype(),
            generation,
            reply,
        };
        if !matches!(authority.mode, 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        authority.current()?;
        Ok(authority)
    }

    pub fn current(&self) -> Result<(), WirelessError> {
        self.check(None)
    }

    /// Also prove that a concrete receiver is the exact interface named by
    /// the request; a valid grant for another AP cannot be replayed here.
    pub fn check_for<I: WirelessNetIface + ?Sized>(&self, iface: &I) -> Result<(), WirelessError> {
        self.check(Some(core::ptr::from_ref(iface).cast::<()>()))
    }

    fn check(&self, receiver: Option<*const ()>) -> Result<(), WirelessError> {
        if !self.reply.current() {
            return Err(WirelessError::Denied);
        }
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        if receiver.is_some_and(|pointer| pointer != Arc::as_ptr(&iface).cast::<()>())
            || iface.current_iftype() != self.mode
            || iface.ap_control_generation() != Some(self.generation)
            || narf_net::iface::lookup_in(self.namespace, iface.name())
                .is_none_or(|link| link.ifindex != self.ifindex)
            || !crate::registry::list()
                .iter()
                .any(|registered| Arc::ptr_eq(registered, &iface))
        {
            return Err(WirelessError::Denied);
        }
        self.admin
            .authorize_interface(iface.name(), self.namespace)
            .map_err(|_| WirelessError::Denied)
    }
}
