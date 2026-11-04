//! Exact control-child withdrawal and an observation-only final-ACK receipt.
//! This module is staged with the concrete asynchronous control lifecycle.
use super::*;

#[derive(Clone, Debug)]
struct Identity {
    child_name: String,
    parent: Cap<NetIface, Write>,
    parent_name: String,
    registration: Option<u64>,
    namespace: u64,
    ownership_epoch: u64,
}
/// The actual control entry has been withdrawn inside its current invoked
/// admin/daemon/parent/child grants. This object can only check that original
/// retirement for terminal publication; it exports no administrative action,
/// capability, successor lookup or hardware/packet authority.
#[derive(Clone)]
pub struct ControlRetirement {
    admin: AdminHandle,
    child: Cap<NetIface, Write>,
    identity: Identity,
}
impl core::fmt::Debug for ControlRetirement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControlRetirement")
            .field("namespace", &self.identity.namespace)
            .finish_non_exhaustive()
    }
}
impl ControlRetirement {
    pub fn current(&self) -> bool {
        let operation = Operation {
            admin: &self.admin,
            child: self.child,
            namespace: self.identity.namespace,
            action: Action::Check(&self.identity),
        };
        matches!(self.admin.cap.invoke(operation), Ok(Ok(None)))
    }
}
impl AdminHandle {
    /// Withdraw exactly this actual control child's registration after the
    /// driver has proved native stop/retirement. A scoped child handle must
    /// retain the actual parent/daemon grants. Namespace kernel handles keep
    /// their intended scope and still invoke the stored real parent/child.
    /// Driver callbacks, hardware waits and final socket publication occur
    /// outside this operation and every registry spinlock.
    pub fn retire_control_child(
        &self,
        child: &Cap<NetIface, Write>,
        namespace: u64,
    ) -> Result<ControlRetirement, AdminError> {
        let identity = self
            .cap
            .invoke(Operation {
                admin: self,
                child: *child,
                namespace,
                action: Action::Remove,
            })
            .map_err(|_| AdminError::AuthorityRevoked)??
            .ok_or(AdminError::NoIface)?;
        Ok(ControlRetirement {
            admin: self.clone(),
            child: *child,
            identity,
        })
    }
}
#[derive(Clone, Copy)]
enum Action<'a> {
    Remove,
    Check(&'a Identity),
}
#[derive(Clone, Copy)]
struct Operation<'a> {
    admin: &'a AdminHandle,
    child: Cap<NetIface, Write>,
    namespace: u64,
    action: Action<'a>,
}
type Outcome = Result<Option<Identity>, AdminError>;
impl narf_capabilities::CapOp<AdminCap, Invoke> for Operation<'_> {
    type Output = Outcome;
    fn execute(
        self,
        _: &Cap<AdminCap, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        match &self.admin.source {
            Some(source) => source.attach.daemon.invoke(self),
            None => {
                let identity = match self.action {
                    Action::Remove => match self.child.invoke(FindParent { operation: self })? {
                        Ok(identity) => identity,
                        Err(error) => return Ok(Err(error)),
                    },
                    Action::Check(identity) => identity.clone(),
                };
                identity.parent.invoke(KernelParent {
                    operation: self,
                    identity: &identity,
                })
            }
        }
    }
}
impl narf_capabilities::CapOp<StackDaemon, Invoke> for Operation<'_> {
    type Output = Outcome;
    fn execute(
        self,
        _: &Cap<StackDaemon, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let source = self
            .admin
            .source
            .as_ref()
            .ok_or(narf_capabilities::CapError::Revoked)?;
        let Some(parent) = source.parent.as_ref() else {
            return Ok(Err(AdminError::NoIface));
        };
        if source.registration.is_some()
            || source.attach.iface.slot() != self.child.slot()
            || parent.namespace != self.namespace
        {
            return Ok(Err(AdminError::NoIface));
        }
        parent.admin.cap.invoke(Parent {
            operation: self,
            parent,
        })
    }
}
#[derive(Clone, Copy)]
struct Parent<'a> {
    operation: Operation<'a>,
    parent: &'a ControlParent,
}
impl narf_capabilities::CapOp<AdminCap, Invoke> for Parent<'_> {
    type Output = Outcome;
    fn execute(
        self,
        _: &Cap<AdminCap, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let source = self
            .parent
            .admin
            .source
            .as_ref()
            .ok_or(narf_capabilities::CapError::Revoked)?;
        if source.parent.is_some() {
            return Ok(Err(AdminError::NoIface));
        }
        source.attach.daemon.invoke(self)
    }
}
impl narf_capabilities::CapOp<StackDaemon, Invoke> for Parent<'_> {
    type Output = Outcome;
    fn execute(
        self,
        _: &Cap<StackDaemon, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        self.parent
            .admin
            .source
            .as_ref()
            .ok_or(narf_capabilities::CapError::Revoked)?
            .attach
            .iface
            .invoke(self)
    }
}
impl narf_capabilities::CapOp<NetIface, Write> for Parent<'_> {
    type Output = Outcome;
    fn execute(
        self,
        cap: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let source = self
            .parent
            .admin
            .source
            .as_ref()
            .ok_or(narf_capabilities::CapError::Revoked)?;
        self.operation.child.invoke(Final {
            operation: self.operation,
            binding: Binding {
                parent: *cap,
                name: self.parent.admin.iface_name(),
                registration: source.registration,
                namespace: self.parent.namespace,
                ownership_epoch: self.parent.ownership_epoch,
            },
        })
    }
}
struct FindParent<'a> {
    operation: Operation<'a>,
}
impl narf_capabilities::CapOp<NetIface, Write> for FindParent<'_> {
    type Output = Result<Identity, AdminError>;
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
        let Some(parent) = entries
            .iter()
            .find(|entry| entry.handle.slot() == parent_cap.slot())
        else {
            return Ok(Err(AdminError::NoIface));
        };
        let Some(metadata) = crate::iface::lookup(&parent.name) else {
            return Ok(Err(AdminError::NoIface));
        };
        if child.name != self.operation.admin.iface_name()
            || child.control_namespace != Some(self.operation.namespace)
            || parent.control_namespace.is_some()
            || metadata.net_ns_id != self.operation.namespace
            || metadata.ownership_epoch == 0
        {
            return Ok(Err(AdminError::NoIface));
        }
        Ok(Ok(Identity {
            child_name: child.name.clone(),
            parent: parent_cap,
            parent_name: parent.name.clone(),
            registration: crate::iface::registration_identity(&parent.name),
            namespace: metadata.net_ns_id,
            ownership_epoch: metadata.ownership_epoch,
        }))
    }
}
struct KernelParent<'a> {
    operation: Operation<'a>,
    identity: &'a Identity,
}
impl narf_capabilities::CapOp<NetIface, Write> for KernelParent<'_> {
    type Output = Outcome;
    fn execute(
        self,
        cap: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        self.operation.child.invoke(Final {
            operation: self.operation,
            binding: Binding {
                parent: *cap,
                name: &self.identity.parent_name,
                registration: self.identity.registration,
                namespace: self.identity.namespace,
                ownership_epoch: self.identity.ownership_epoch,
            },
        })
    }
}
#[derive(Clone, Copy)]
struct Binding<'a> {
    parent: Cap<NetIface, Write>,
    name: &'a str,
    registration: Option<u64>,
    namespace: u64,
    ownership_epoch: u64,
}
struct Final<'a> {
    operation: Operation<'a>,
    binding: Binding<'a>,
}
impl narf_capabilities::CapOp<NetIface, Write> for Final<'_> {
    type Output = Outcome;
    fn execute(
        self,
        cap: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        let operation = self.operation;
        let parent = self.binding;
        // Only immutable cached registration fields and pure legacy metadata
        // are inspected while locked. No driver/sink callback or destructor.
        let removed = {
            let mut entries = crate::registry().inner.lock();
            let valid_parent = entries.iter().any(|entry| {
                entry.handle.slot() == parent.parent.slot()
                    && entry.name == parent.name
                    && entry.control_namespace.is_none()
            }) && parent.namespace == operation.namespace
                && parent.ownership_epoch != 0
                && crate::iface::registration_owner_matches(
                    parent.name,
                    parent.registration,
                    Some(parent.namespace),
                    Some(parent.ownership_epoch),
                );
            if !valid_parent {
                return Ok(Err(AdminError::NoIface));
            }
            match operation.action {
                Action::Check(identity) => {
                    let valid = identity.child_name == operation.admin.iface_name()
                        && identity.parent.slot() == parent.parent.slot()
                        && identity.parent_name == parent.name
                        && identity.registration == parent.registration
                        && identity.namespace == parent.namespace
                        && identity.ownership_epoch == parent.ownership_epoch
                        && !entries
                            .iter()
                            .any(|entry| entry.handle.slot() == cap.slot());
                    return Ok(if valid {
                        Ok(None)
                    } else {
                        Err(AdminError::NoIface)
                    });
                }
                Action::Remove => {
                    let Some(index) = entries.iter().position(|entry| {
                        entry.handle.slot() == cap.slot()
                            && entry.name == operation.admin.iface_name()
                            && entry.control_namespace == Some(operation.namespace)
                            && entry
                                .control_parent
                                .is_some_and(|cap| cap.slot() == parent.parent.slot())
                    }) else {
                        return Ok(Err(AdminError::NoIface));
                    };
                    if crate::iface::lookup(operation.admin.iface_name()).is_some() {
                        return Ok(Err(AdminError::NoIface));
                    }
                    entries.remove(index)
                }
            }
        };
        // Dropping an Interface implementation can release owned objects;
        // keep even that destruction outside the registry spinlock.
        let identity = Identity {
            child_name: removed.name.clone(),
            parent: parent.parent,
            parent_name: String::from(parent.name),
            registration: parent.registration,
            namespace: parent.namespace,
            ownership_epoch: parent.ownership_epoch,
        };
        drop(removed);
        Ok(Ok(Some(identity)))
    }
}
