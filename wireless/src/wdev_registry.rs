//! Registered wireless objects. A control-only P2P wdev has an actual
//! typed interface/control grant, but no fabricated netdev or ifindex.
use crate::*;
use alloc::{sync::Arc, vec::Vec};
use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};
use narf_lib::sync::IrqSafeSpinLock;

struct Entry {
    iface: Arc<dyn WirelessNetIface>,
    control: Option<ControlWdev>,
}
static REGISTRY: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_CONTROL: AtomicU64 = AtomicU64::new(1);
const CONTROL_ID: u64 = 1 << 63;

/// Registration/namespace observation only: no admin, device or RF grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlWdev {
    id: NonZeroU64,
    namespace: u64,
}
impl ControlWdev {
    pub fn id(self) -> u64 {
        self.id.get()
    }
    pub fn namespace(self) -> u64 {
        self.namespace
    }
    pub fn current_for<I: WirelessNetIface + ?Sized>(self, iface: &I) -> bool {
        control_for(iface) == Some(self)
            && iface.control_namespace() == Some(self.namespace)
            && iface.current_iftype() == 10
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRegistrationError {
    Invalid,
    Duplicate,
    ParentGone,
    Exhausted,
}

/// Ordinary netdev registration keeps its existing discovery behavior.
/// A control-only owner must use `register_control` instead.
pub fn register(iface: Arc<dyn WirelessNetIface>) {
    if iface.control_namespace().is_none() {
        REGISTRY.lock().push(Entry {
            iface,
            control: None,
        });
    }
}
/// Trusted driver binding pairs this actual child with its still-registered
/// physical parent. Caller separately invokes its actual registration/device
/// grants and current request authority; this function mints no capability.
/// The control namespace is immutable for this registration's lifetime.
pub fn register_control(
    parent: &Arc<dyn WirelessNetIface>,
    iface: Arc<dyn WirelessNetIface>,
) -> Result<ControlWdev, ControlRegistrationError> {
    let namespace = iface
        .control_namespace()
        .ok_or(ControlRegistrationError::Invalid)?;
    if iface.name() == "lo"
        || iface.name().is_empty()
        || narf_net::iface::lookup(iface.name()).is_some()
        || iface.current_iftype() != 10
        || iface.wiphy_id() != parent.wiphy_id()
        || parent.control_namespace().is_some()
    {
        return Err(ControlRegistrationError::Invalid);
    }
    let mut registry = REGISTRY.lock();
    if !registry
        .iter()
        .any(|entry| entry.control.is_none() && Arc::ptr_eq(&entry.iface, parent))
    {
        return Err(ControlRegistrationError::ParentGone);
    }
    if registry
        .iter()
        .any(|entry| entry.iface.name() == iface.name())
    {
        return Err(ControlRegistrationError::Duplicate);
    }
    let next = NEXT_CONTROL
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            if next < CONTROL_ID {
                next.checked_add(1)
            } else {
                None
            }
        })
        .map_err(|_| ControlRegistrationError::Exhausted)?;
    let control = ControlWdev {
        id: NonZeroU64::new(CONTROL_ID | next).ok_or(ControlRegistrationError::Exhausted)?,
        namespace,
    };
    registry.push(Entry {
        iface,
        control: Some(control),
    });
    Ok(control)
}
pub fn control_for<I: WirelessNetIface + ?Sized>(iface: &I) -> Option<ControlWdev> {
    let expected = core::ptr::from_ref(iface).cast::<()>();
    REGISTRY
        .lock()
        .iter()
        .find(|entry| Arc::as_ptr(&entry.iface).cast::<()>() == expected)
        .and_then(|entry| entry.control)
}
pub fn control_by_id(id: u64, namespace: u64) -> Option<Arc<dyn WirelessNetIface>> {
    let iface = REGISTRY
        .lock()
        .iter()
        .find(|entry| {
            entry
                .control
                .is_some_and(|control| control.id() == id && control.namespace == namespace)
        })
        .map(|entry| entry.iface.clone());
    iface.filter(|iface| {
        iface.control_namespace() == Some(namespace) && iface.current_iftype() == 10
    })
}
/// Retire only this exact control registration/receiver. A stale handle
/// cannot remove a same-name replacement, even with the same MAC/mode.
pub fn unregister_control<I: WirelessNetIface + ?Sized>(expected: ControlWdev, iface: &I) -> bool {
    let receiver = core::ptr::from_ref(iface).cast::<()>();
    let mut registry = REGISTRY.lock();
    let before = registry.len();
    registry.retain(|entry| {
        entry.control != Some(expected) || Arc::as_ptr(&entry.iface).cast::<()>() != receiver
    });
    before != registry.len()
}
pub fn list() -> Vec<Arc<dyn WirelessNetIface>> {
    REGISTRY
        .lock()
        .iter()
        .map(|entry| entry.iface.clone())
        .collect()
}
/// One representative per physical radio, preserving legacy order/indices.
pub fn wiphys() -> Vec<Arc<dyn WirelessNetIface>> {
    let mut ids = Vec::new();
    let mut out = Vec::new();
    for entry in REGISTRY.lock().iter() {
        let id = entry.iface.wiphy_id();
        if !ids.contains(&id) {
            ids.push(id);
            out.push(entry.iface.clone());
        }
    }
    out
}
/// Legacy netdev WDEV encoding uses a nonnegative signed wiphy index,
/// matching Linux wiphy_new_nm. Its high bit cannot overlap control IDs.
pub fn wiphy_index(id: u64) -> Option<u32> {
    wiphys()
        .iter()
        .position(|iface| iface.wiphy_id() == id)
        .and_then(|index| u32::try_from(index).ok())
        .filter(|index| *index <= i32::MAX as u32)
}
pub fn unregister(name: &str) {
    REGISTRY.lock().retain(|entry| entry.iface.name() != name);
}
