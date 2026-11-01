//! Fixed capability operations for native AP emission. Capture may call the
//! ordinary control plane; current() never calls a virtual interface/provider.
use super::*;
use crate::native_emission::Lifetime;
use core::task::Waker;

/// Original actual grants and weak exact provider registrations. Retaining
/// this guard alone is not authority: current() invokes every retained cap.
/// It grants no hardware, RF, key, controlled-port or cleanup permission.
#[derive(Clone, Debug)]
pub struct AdminEmissionAuthority {
    admin: Cap<AdminCap, Invoke>,
    daemon: Option<Cap<StackDaemon, Invoke>>,
    iface: Cap<NetIface, Write>,
    registration: Lifetime,
    identity: Lifetime,
}
impl AdminHandle {
    /// Capture only a real Ethernet netdev, under this original current
    /// administrative grant. Unsupported control-child ancestry refuses;
    /// no name lookup can recreate a lost original delegated registration.
    pub fn native_emission(
        &self,
        name: &str,
        namespace: u64,
        ifindex: u32,
        ownership_epoch: u64,
        mac: [u8; 6],
    ) -> Result<AdminEmissionAuthority, AdminError> {
        self.authorize_interface(name, namespace)?;
        if self
            .source
            .as_ref()
            .is_some_and(|source| source.parent.is_some())
        {
            return Err(AdminError::NoIface);
        }
        let (identity, registration_epoch) =
            crate::iface::native_identity(name, namespace, ifindex, ownership_epoch, mac)
                .ok_or(AdminError::NoIface)?;
        let (iface, registration) = {
            let entries = crate::registry().inner.lock();
            let entry = entries
                .iter()
                .find(|entry| {
                    entry.name == name
                        && entry.control_namespace.is_none()
                        && entry.control_parent.is_none()
                        && self.source.as_ref().is_none_or(|source| {
                            source.registration == Some(registration_epoch)
                                && source.attach.iface.slot() == entry.handle.slot()
                        })
                })
                .ok_or(AdminError::NoIface)?;
            (entry.handle, entry.native_lifetime.observe())
        };
        let guard = AdminEmissionAuthority {
            admin: self.cap,
            daemon: self.source.as_ref().map(|source| source.attach.daemon),
            iface,
            registration,
            identity,
        };
        if !guard.current() {
            return Err(AdminError::AuthorityRevoked);
        }
        Ok(guard)
    }
}
impl AdminEmissionAuthority {
    /// Actual Cap::invoke operations plus fixed weak/atomic observations.
    /// No registry/IFACES/socket/native-state lock or arbitrary callback.
    pub fn current(&self) -> bool {
        self.admin.invoke(Check(self)) == Ok(true)
    }
    /// Arm outside native State/provider locks, then recheck current. Cap
    /// epoch revocation is also checked on the native owner's bounded timer:
    /// the generic capability table supplies no provider wake callback.
    pub fn watch(&self, waker: &Waker) -> bool {
        self.registration.watch(waker.clone())
            && self.identity.watch(waker.clone())
            && self.current()
    }
}
#[derive(Clone, Copy)]
struct Check<'a>(&'a AdminEmissionAuthority);
impl narf_capabilities::CapOp<AdminCap, Invoke> for Check<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<AdminCap, Invoke>) -> Result<bool, narf_capabilities::CapError> {
        if let Some(daemon) = self.0.daemon {
            daemon.invoke(self)
        } else {
            self.0.iface.invoke(self)
        }
    }
}
impl narf_capabilities::CapOp<StackDaemon, Invoke> for Check<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<StackDaemon, Invoke>) -> Result<bool, narf_capabilities::CapError> {
        self.0.iface.invoke(self)
    }
}
impl narf_capabilities::CapOp<NetIface, Write> for Check<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<NetIface, Write>) -> Result<bool, narf_capabilities::CapError> {
        Ok(self.0.registration.current() && self.0.identity.current())
    }
}
