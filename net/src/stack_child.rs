//! Fresh control-child delegation from actual typed parent/child receipts.
//! Neither a child name nor a WDEV observation creates authority.
use super::*;

#[derive(Clone, Debug)]
pub(super) struct ControlParent {
    admin: Arc<AdminHandle>,
    namespace: u64,
    ownership_epoch: u64,
}
impl ControlParent {
    pub(super) fn current(&self) -> bool {
        self.admin.cap.invoke(AdminContext {
            handle: &self.admin,
            name: self.admin.iface_name(),
            net_ns_id: self.namespace,
            ownership_epoch: Some(self.ownership_epoch),
        }) == Ok(true)
    }
}
impl AdminHandle {
    /// Current explicitly delegated control-child scope. Ordinary interface
    /// and kernel namespace handles are never promoted by this observation.
    pub fn is_control_child(&self) -> bool {
        self.source
            .as_ref()
            .is_some_and(|source| source.parent.is_some())
            && self.is_live()
    }
    /// Bind a freshly registered control child's actual Write cap to this
    /// creating daemon. Registration must have recorded the exact current
    /// physical parent via `Registry::register_control_child`. Namespace and
    /// parent ownership are checked inside the invoked parent/daemon/child
    /// operations. The returned child retains both parent and child grants;
    /// parent transfer/rebind/revocation or child retirement invalidates it.
    /// A kernel namespace handle needs no extra delegation and returns None.
    pub fn control_registered_child(
        &self,
        child: &Cap<NetIface, Write>,
    ) -> Result<Option<AdminHandle>, AdminError> {
        self.cap
            .invoke(Parent {
                admin: self,
                child: *child,
            })
            .map_err(|_| AdminError::AuthorityRevoked)?
    }
}
#[derive(Clone, Copy)]
struct Parent<'a> {
    admin: &'a AdminHandle,
    child: Cap<NetIface, Write>,
}
impl narf_capabilities::CapOp<AdminCap, Invoke> for Parent<'_> {
    type Output = Result<Option<AdminHandle>, AdminError>;
    fn execute(
        self,
        _: &Cap<AdminCap, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let Some(source) = self.admin.source.as_ref() else {
            return self.child.invoke(KernelChild { parent: self.admin });
        };
        source.attach.daemon.invoke(self)
    }
}
struct KernelChild<'a> {
    parent: &'a AdminHandle,
}
impl narf_capabilities::CapOp<NetIface, Write> for KernelChild<'_> {
    type Output = Result<Option<AdminHandle>, AdminError>;
    fn execute(
        self,
        cap: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let entries = crate::registry().inner.lock();
        let Some(child) = entries
            .iter()
            .find(|entry| entry.handle.slot() == cap.slot())
        else {
            return Ok(Err(AdminError::NoIface));
        };
        let Some(parent_cap) = child.control_parent else {
            return Ok(Err(AdminError::NoIface));
        };
        parent_cap.invoke(KernelParent {
            entries: &entries,
            parent: self.parent,
            child,
        })
    }
}
struct KernelParent<'a> {
    entries: &'a [crate::Entry],
    parent: &'a AdminHandle,
    child: &'a crate::Entry,
}
impl narf_capabilities::CapOp<NetIface, Write> for KernelParent<'_> {
    type Output = Result<Option<AdminHandle>, AdminError>;
    fn execute(
        self,
        cap: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let valid = self
            .entries
            .iter()
            .find(|entry| entry.handle.slot() == cap.slot())
            .is_some_and(|parent| {
                parent.iface.name() == self.parent.iface_name()
                    && parent.iface.control_namespace().is_none()
                    && crate::iface::lookup(parent.iface.name()).is_some_and(|metadata| {
                        metadata.ownership_epoch != 0
                            && self.child.iface.control_namespace() == Some(metadata.net_ns_id)
                            && crate::iface::lookup(self.child.iface.name()).is_none()
                    })
            });
        Ok(if valid {
            Ok(None)
        } else {
            Err(AdminError::NoIface)
        })
    }
}
impl narf_capabilities::CapOp<StackDaemon, Invoke> for Parent<'_> {
    type Output = Result<Option<AdminHandle>, AdminError>;
    fn execute(
        self,
        _: &Cap<StackDaemon, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        self.admin
            .source
            .as_ref()
            .ok_or(narf_capabilities::CapError::Revoked)?
            .attach
            .iface
            .invoke(self)
    }
}
impl narf_capabilities::CapOp<NetIface, Write> for Parent<'_> {
    type Output = Result<Option<AdminHandle>, AdminError>;
    fn execute(
        self,
        parent: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let source = self
            .admin
            .source
            .as_ref()
            .ok_or(narf_capabilities::CapError::Revoked)?;
        if source.parent.is_some()
            || !(DelegatedAdminIdentity {
                source,
                name: self.admin.iface_name(),
                namespace: None,
                ownership_epoch: None,
            })
            .execute(parent)?
        {
            return Ok(Err(AdminError::NoIface));
        }
        self.child.invoke(Child {
            parent: self.admin,
            parent_cap: *parent,
            child_cap: self.child,
        })
    }
}
struct Child<'a> {
    parent: &'a AdminHandle,
    parent_cap: Cap<NetIface, Write>,
    child_cap: Cap<NetIface, Write>,
}
impl narf_capabilities::CapOp<NetIface, Write> for Child<'_> {
    type Output = Result<Option<AdminHandle>, AdminError>;
    fn execute(
        self,
        _: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let source = self
            .parent
            .source
            .as_ref()
            .ok_or(narf_capabilities::CapError::Revoked)?;
        let entries = crate::registry().inner.lock();
        let Some(parent) = entries
            .iter()
            .find(|entry| entry.handle.slot() == self.parent_cap.slot())
        else {
            return Ok(Err(AdminError::NoIface));
        };
        let Some(child) = entries
            .iter()
            .find(|entry| entry.handle.slot() == self.child_cap.slot())
        else {
            return Ok(Err(AdminError::NoIface));
        };
        let Some(metadata) = crate::iface::lookup(parent.iface.name()) else {
            return Ok(Err(AdminError::NoIface));
        };
        if parent.iface.name() != self.parent.iface_name()
            || parent.iface.control_namespace().is_some()
            || child
                .control_parent
                .is_none_or(|cap| cap.slot() != self.parent_cap.slot())
            || child.iface.control_namespace() != Some(metadata.net_ns_id)
            || crate::iface::lookup(child.iface.name()).is_some()
            || metadata.ownership_epoch == 0
            || !crate::iface::registration_owner_matches(
                parent.iface.name(),
                source.registration,
                Some(metadata.net_ns_id),
                Some(metadata.ownership_epoch),
            )
        {
            return Ok(Err(AdminError::NoIface));
        }
        Ok(Ok(Some(AdminHandle {
            cap: Cap::<AdminCap, Invoke>::bootstrap(),
            iface_name: String::from(child.iface.name()),
            source: Some(AdminSource {
                attach: StackAttach {
                    iface: self.child_cap,
                    daemon: source.attach.daemon,
                },
                registration: None,
                parent: Some(ControlParent {
                    admin: Arc::new(self.parent.clone()),
                    namespace: metadata.net_ns_id,
                    ownership_epoch: metadata.ownership_epoch,
                }),
            }),
        })))
    }
}
