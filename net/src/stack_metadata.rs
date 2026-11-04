//! Actual grants contain the metadata mutation, not only a prior name check.
use super::*;
use crate::iface::admin::{self, Binding, Change, Effects};

impl AdminHandle {
    pub(crate) fn invoke_metadata(&self, change: Change) -> Result<Effects, AdminError> {
        self.cap
            .invoke(Operation {
                handle: self,
                change,
            })
            .map_err(|_| AdminError::AuthorityRevoked)?
            .ok_or(AdminError::NoIface)
    }
}
struct Operation<'a> {
    handle: &'a AdminHandle,
    change: Change,
}
impl narf_capabilities::CapOp<AdminCap, Invoke> for Operation<'_> {
    type Output = Option<Effects>;
    fn execute(
        self,
        _: &Cap<AdminCap, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        match &self.handle.source {
            Some(source) => source.attach.daemon.invoke(Delegated {
                source,
                name: self.handle.iface_name(),
                change: self.change,
            }),
            None => Ok(admin::mutate(
                self.handle.iface_name(),
                Binding::Name,
                self.change,
            )),
        }
    }
}
#[derive(Clone, Copy)]
struct Delegated<'a> {
    source: &'a AdminSource,
    name: &'a str,
    change: Change,
}
impl narf_capabilities::CapOp<StackDaemon, Invoke> for Delegated<'_> {
    type Output = Option<Effects>;
    fn execute(
        self,
        _: &Cap<StackDaemon, Invoke>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        if self
            .source
            .parent
            .as_ref()
            .is_some_and(|parent| !parent.current())
        {
            return Ok(None);
        }
        self.source.attach.iface.invoke(self)
    }
}
impl narf_capabilities::CapOp<NetIface, Write> for Delegated<'_> {
    type Output = Option<Effects>;
    fn execute(
        self,
        cap: &Cap<NetIface, Write>,
    ) -> Result<Self::Output, narf_capabilities::CapError> {
        Ok(crate::registry()
            .with_interface_for_handle(cap, |iface| {
                if iface.name() != self.name {
                    return None;
                }
                admin::mutate(
                    self.name,
                    Binding::Registration(self.source.registration),
                    self.change,
                )
            })
            .flatten())
    }
}

#[cfg(feature = "kernel-test")]
type MetadataHook = (String, fn(&str));
#[cfg(feature = "kernel-test")]
pub(super) static BEFORE_APPLY: narf_lib::sync::IrqSafeSpinLock<Option<MetadataHook>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
#[cfg(feature = "kernel-test")]
pub(crate) fn before_apply(name: &str) {
    let action = {
        let mut hook = BEFORE_APPLY.lock();
        if hook.as_ref().is_some_and(|(expected, _)| expected == name) {
            hook.take().map(|(_, action)| action)
        } else {
            None
        }
    };
    if let Some(action) = action {
        action(name);
    }
}
