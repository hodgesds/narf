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
    parent: Option<Arc<ParentEmission>>,
}
#[derive(Debug)]
struct ParentEmission {
    admin: Option<Cap<AdminCap, Invoke>>,
    daemon: Option<Cap<StackDaemon, Invoke>>,
    iface: Cap<NetIface, Write>,
    registration: Lifetime,
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
            parent: None,
        };
        if !guard.current() {
            return Err(AdminError::AuthorityRevoked);
        }
        Ok(guard)
    }
    /// Capture this actual registered control child under its existing
    /// administrative grant and explicit original Write capability. The
    /// child's native START/RF and source socket remain separate proofs.
    /// No netdev, IFINDEX or administrative-UP condition is fabricated.
    pub fn native_control_emission(
        &self,
        child: &Cap<NetIface, Write>,
        namespace: u64,
    ) -> Result<AdminEmissionAuthority, AdminError> {
        self.authorize_interface(self.iface_name(), namespace)?;
        let guard = crate::iface::native_control_capture(|| {
            self.cap
                .invoke(CaptureControl {
                    admin: self,
                    child: *child,
                    namespace,
                })
                .map_err(|_| AdminError::AuthorityRevoked)?
        })?;
        // Full control callbacks stay outside native State and publication
        // locks. The last fixed check catches retirement during callbacks.
        self.authorize_interface(self.iface_name(), namespace)?;
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
            && self
                .parent
                .as_ref()
                .is_none_or(|parent| parent.registration.watch(waker.clone()))
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
        Ok(self.0.registration.current()
            && self.0.identity.current()
            && self.0.parent.as_ref().is_none_or(|parent| parent.current()))
    }
}

impl ParentEmission {
    fn current(&self) -> bool {
        let check = CheckParent(self);
        (match self.admin {
            Some(admin) => admin.invoke(check),
            None => self.iface.invoke(check),
        }) == Ok(true)
    }
}
#[derive(Clone, Copy)]
struct CheckParent<'a>(&'a ParentEmission);
impl narf_capabilities::CapOp<AdminCap, Invoke> for CheckParent<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<AdminCap, Invoke>) -> Result<bool, narf_capabilities::CapError> {
        match self.0.daemon {
            Some(daemon) => daemon.invoke(self),
            None => self.0.iface.invoke(self),
        }
    }
}
impl narf_capabilities::CapOp<StackDaemon, Invoke> for CheckParent<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<StackDaemon, Invoke>) -> Result<bool, narf_capabilities::CapError> {
        self.0.iface.invoke(self)
    }
}
impl narf_capabilities::CapOp<NetIface, Write> for CheckParent<'_> {
    type Output = bool;
    fn execute(self, _: &Cap<NetIface, Write>) -> Result<bool, narf_capabilities::CapError> {
        Ok(self.0.registration.current())
    }
}

#[derive(Clone, Copy)]
struct CaptureControl<'a> {
    admin: &'a AdminHandle,
    child: Cap<NetIface, Write>,
    namespace: u64,
}
type Captured = Result<AdminEmissionAuthority, AdminError>;
impl narf_capabilities::CapOp<AdminCap, Invoke> for CaptureControl<'_> {
    type Output = Captured;
    fn execute(self, _: &Cap<AdminCap, Invoke>) -> Result<Captured, narf_capabilities::CapError> {
        if let Some(source) = &self.admin.source {
            if source.parent.is_none()
                || source.registration.is_some()
                || source.attach.iface.slot() != self.child.slot()
            {
                return Ok(Err(AdminError::NoIface));
            }
            source.attach.daemon.invoke(self)
        } else {
            self.child.invoke(self)
        }
    }
}
impl narf_capabilities::CapOp<StackDaemon, Invoke> for CaptureControl<'_> {
    type Output = Captured;
    fn execute(
        self,
        _: &Cap<StackDaemon, Invoke>,
    ) -> Result<Captured, narf_capabilities::CapError> {
        self.child.invoke(self)
    }
}
impl narf_capabilities::CapOp<NetIface, Write> for CaptureControl<'_> {
    type Output = Captured;
    fn execute(self, cap: &Cap<NetIface, Write>) -> Result<Captured, narf_capabilities::CapError> {
        let entries = crate::registry().inner.lock();
        let Some(child) = entries.iter().find(|entry| {
            entry.handle.slot() == cap.slot()
                && entry.name == self.admin.iface_name()
                && entry.control_namespace == Some(self.namespace)
        }) else {
            return Ok(Err(AdminError::NoIface));
        };
        let Some(parent) = child.control_parent else {
            return Ok(Err(AdminError::NoIface));
        };
        parent.invoke(CaptureParent {
            capture: self,
            entries: &entries,
            child,
        })
    }
}
struct CaptureParent<'a> {
    capture: CaptureControl<'a>,
    entries: &'a [crate::Entry],
    child: &'a crate::Entry,
}
impl narf_capabilities::CapOp<NetIface, Write> for CaptureParent<'_> {
    type Output = Captured;
    fn execute(self, cap: &Cap<NetIface, Write>) -> Result<Captured, narf_capabilities::CapError> {
        let Some(parent) = self.entries.iter().find(|entry| {
            entry.handle.slot() == cap.slot()
                && entry.control_namespace.is_none()
                && entry.control_parent.is_none()
        }) else {
            return Ok(Err(AdminError::NoIface));
        };
        let source = self.capture.admin.source.as_ref();
        let mut registration = None;
        let mut ownership = None;
        let mut parent_admin = None;
        let mut parent_daemon = None;
        if let Some(child_source) = source {
            let Some(lineage) = &child_source.parent else {
                return Ok(Err(AdminError::NoIface));
            };
            let (original, namespace, epoch) = lineage.native_binding();
            let Some(original_source) = &original.source else {
                return Ok(Err(AdminError::NoIface));
            };
            if namespace != self.capture.namespace
                || epoch == 0
                || original.iface_name() != parent.name
                || original_source.parent.is_some()
                || original_source.registration.is_none()
                || original_source.attach.iface.slot() != cap.slot()
                || original_source.attach.daemon.slot() != child_source.attach.daemon.slot()
            {
                return Ok(Err(AdminError::NoIface));
            }
            registration = original_source.registration;
            ownership = Some(epoch);
            parent_admin = Some(original.cap);
            parent_daemon = Some(original_source.attach.daemon);
        }
        let Some(identity) = crate::iface::native_control_parent_identity(
            &self.child.name,
            &parent.name,
            self.capture.namespace,
            registration,
            ownership,
        ) else {
            return Ok(Err(AdminError::NoIface));
        };
        Ok(Ok(AdminEmissionAuthority {
            admin: self.capture.admin.cap,
            daemon: source.map(|source| source.attach.daemon),
            iface: self.capture.child,
            registration: self.child.native_lifetime.observe(),
            identity,
            parent: Some(Arc::new(ParentEmission {
                admin: parent_admin,
                daemon: parent_daemon,
                iface: *cap,
                registration: parent.native_lifetime.observe(),
            })),
        }))
    }
}
