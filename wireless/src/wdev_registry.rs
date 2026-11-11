//! Registered wireless objects. A control-only P2P wdev has an actual
//! typed interface/control grant, but no fabricated netdev or ifindex.
use crate::*;
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};
use narf_lib::sync::IrqSafeSpinLock;

struct Entry {
    iface: Arc<dyn WirelessNetIface>,
    name: alloc::string::String,
    wiphy: u64,
    control: Option<ControlWdev>,
    parent: Option<Weak<dyn WirelessNetIface>>,
    retired: bool,
    native_lifetime: narf_net::native_emission::ProviderLifetime,
}
static REGISTRY: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_CONTROL: AtomicU64 = AtomicU64::new(1);
const CONTROL_ID: u64 = 1 << 63;
fn parent_current(registry: &[Entry], entry: &Entry) -> bool {
    entry.control.is_none()
        || entry.parent.as_ref().is_some_and(|parent| {
            registry.iter().any(|actual| {
                actual.control.is_none() && Weak::ptr_eq(parent, &Arc::downgrade(&actual.iface))
            })
        })
}

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
        let name = iface.name().into();
        let wiphy = iface.wiphy_id();
        REGISTRY.lock().push(Entry {
            iface,
            name,
            wiphy,
            control: None,
            parent: None,
            retired: false,
            native_lifetime: narf_net::native_emission::ProviderLifetime::new(),
        });
        crate::rfkill::wiphy_added(wiphy);
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
    let name = alloc::string::String::from(iface.name());
    let wiphy = iface.wiphy_id();
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
    if registry.iter().any(|entry| entry.name == name) {
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
        name,
        wiphy,
        control: Some(control),
        parent: Some(Arc::downgrade(parent)),
        retired: false,
        native_lifetime: narf_net::native_emission::ProviderLifetime::new(),
    });
    Ok(control)
}
/// The actual registered parent-child objects, not matching names/MACs or
/// merely a shared wiphy number. This observation creates no grant.
pub(crate) fn control_parent_matches(
    parent: &Arc<dyn WirelessNetIface>,
    child: &Arc<dyn WirelessNetIface>,
) -> bool {
    let registry = REGISTRY.lock();
    registry
        .iter()
        .any(|entry| entry.control.is_none() && Arc::ptr_eq(&entry.iface, parent))
        && registry.iter().any(|entry| {
            Arc::ptr_eq(&entry.iface, child)
                && !entry.retired
                && entry.control.is_some()
                && entry
                    .parent
                    .as_ref()
                    .is_some_and(|actual| Weak::ptr_eq(actual, &Arc::downgrade(parent)))
        })
}
pub fn control_for<I: WirelessNetIface + ?Sized>(iface: &I) -> Option<ControlWdev> {
    let expected = core::ptr::from_ref(iface).cast::<()>();
    let registry = REGISTRY.lock();
    registry
        .iter()
        .find(|entry| {
            Arc::as_ptr(&entry.iface).cast::<()>() == expected && parent_current(&registry, entry)
        })
        .and_then(|entry| entry.control)
}
pub fn control_by_id(id: u64, namespace: u64) -> Option<Arc<dyn WirelessNetIface>> {
    let registry = REGISTRY.lock();
    let iface = registry
        .iter()
        .find(|entry| {
            parent_current(&registry, entry)
                && !entry.retired
                && entry
                    .control
                    .is_some_and(|control| control.id() == id && control.namespace == namespace)
        })
        .map(|entry| entry.iface.clone());
    drop(registry);
    iface.filter(|iface| {
        iface.control_namespace() == Some(namespace) && iface.current_iftype() == 10
    })
}
/// Retire only this exact control registration/receiver. A stale handle
/// cannot remove a same-name replacement, even with the same MAC/mode.
pub fn unregister_control<I: WirelessNetIface + ?Sized>(expected: ControlWdev, iface: &I) -> bool {
    let receiver = core::ptr::from_ref(iface).cast::<()>();
    let removed = {
        let mut registry = REGISTRY.lock();
        registry
            .iter()
            .position(|entry| {
                entry.control == Some(expected)
                    && Arc::as_ptr(&entry.iface).cast::<()>() == receiver
            })
            .map(|index| {
                let native = registry[index].native_lifetime.retire();
                (registry.remove(index), native)
            })
    };
    if let Some((entry, native)) = removed {
        native.notify();
        drop(entry);
        true
    } else {
        false
    }
}
/// Hide the exact natively retired object from every public selector while
/// retaining its observation identity for its original terminal ACK only.
pub(crate) fn retire_control(expected: ControlWdev, iface: &Arc<dyn WirelessNetIface>) -> bool {
    let mut registry = REGISTRY.lock();
    let Some(index) = registry.iter().position(|entry| {
        entry.control == Some(expected)
            && Arc::ptr_eq(&entry.iface, iface)
            && !entry.retired
            && parent_current(&registry, entry)
    }) else {
        return false;
    };
    let native = registry[index].native_lifetime.retire();
    registry[index].retired = true;
    drop(registry);
    native.notify();
    true
}
pub(crate) fn retired_control_current(
    expected: ControlWdev,
    iface: &Arc<dyn WirelessNetIface>,
) -> bool {
    let registry = REGISTRY.lock();
    registry.iter().any(|entry| {
        entry.control == Some(expected)
            && Arc::ptr_eq(&entry.iface, iface)
            && entry.retired
            && parent_current(&registry, entry)
    })
}
pub fn list() -> Vec<Arc<dyn WirelessNetIface>> {
    let registry = REGISTRY.lock();
    registry
        .iter()
        .filter(|entry| !entry.retired && parent_current(&registry, entry))
        .map(|entry| entry.iface.clone())
        .collect()
}
/// One representative per physical radio, preserving legacy order/indices.
pub fn wiphys() -> Vec<Arc<dyn WirelessNetIface>> {
    let mut ids = Vec::new();
    let mut out = Vec::new();
    for entry in REGISTRY.lock().iter() {
        if entry.control.is_some() {
            continue;
        }
        let id = entry.wiphy;
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
    let removed = {
        let mut registry = REGISTRY.lock();
        let mut removed = Vec::new();
        let mut index = 0;
        while index < registry.len() {
            if registry[index].name == name {
                let native = registry[index].native_lifetime.retire();
                removed.push((registry.remove(index), native));
            } else {
                index += 1;
            }
        }
        removed
    };
    for (entry, native) in removed {
        native.notify();
        let wiphy = entry.wiphy;
        drop(entry);
        if !REGISTRY.lock().iter().any(|entry| entry.wiphy == wiphy) {
            crate::rfkill::wiphy_removed(wiphy);
        }
    }
}

/// Exact registration observation captured outside the native owner lock.
/// No name, MAC or newly registered successor can revive this weak receipt.
pub(crate) fn native_registration<I: WirelessNetIface + ?Sized>(
    iface: &I,
) -> Option<narf_net::native_emission::Lifetime> {
    let receiver = core::ptr::from_ref(iface).cast::<()>();
    REGISTRY
        .lock()
        .iter()
        .find(|entry| {
            !entry.retired
                && entry.control.is_none()
                && Arc::as_ptr(&entry.iface).cast::<()>() == receiver
        })
        .map(|entry| entry.native_lifetime.observe())
}

/// Exact weak child/parent observations for a control-only WDEV. Capability
/// invocation and the immutable namespace/role/source checks are independent.
/// Cached registry facts avoid virtual receiver callbacks while locked.
pub(crate) fn native_control_registration<I: WirelessNetIface + ?Sized>(
    iface: &I,
    expected: ControlWdev,
) -> Option<(
    narf_net::native_emission::Lifetime,
    narf_net::native_emission::Lifetime,
)> {
    let receiver = core::ptr::from_ref(iface).cast::<()>();
    let registry = REGISTRY.lock();
    let child = registry.iter().find(|entry| {
        !entry.retired
            && entry.control == Some(expected)
            && Arc::as_ptr(&entry.iface).cast::<()>() == receiver
    })?;
    let actual_parent = child.parent.as_ref()?;
    let parent = registry.iter().find(|entry| {
        !entry.retired
            && entry.control.is_none()
            && Weak::ptr_eq(actual_parent, &Arc::downgrade(&entry.iface))
    })?;
    Some((
        child.native_lifetime.observe(),
        parent.native_lifetime.observe(),
    ))
}
