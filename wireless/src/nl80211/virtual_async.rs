//! Exact source-bound control-only NEW/DEL with terminal publication leases.
use super::*;
use crate::ap_control::{RadioControlAuthority, RadioControlRetirement};
use alloc::boxed::Box;
use core::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
};
use narf_net::netlink_generic::{DeferredAuthority, DeferredRequest};

struct Creation {
    authority: RadioControlAuthority,
    child: IrqSafeSpinLock<Option<(Arc<dyn crate::WirelessNetIface>, core::num::NonZeroU64)>>,
    published: AtomicBool,
}
impl core::fmt::Debug for Creation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Creation")
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}
impl DeferredAuthority for Creation {
    fn current(&self) -> bool {
        if self.authority.current().is_err() {
            return false;
        }
        let child = { self.child.lock().clone() };
        child.is_none_or(|(child, generation)| {
            child.radio_control_generation() == Some(generation)
                && crate::registry::control_for(child.as_ref())
                    .is_some_and(|wdev| wdev.current_for(child.as_ref()))
                && crate::registry::list()
                    .iter()
                    .any(|actual| Arc::ptr_eq(actual, &child))
        })
    }
    fn delivered(&self) {
        if self.current() {
            self.published.store(true, Ordering::Release);
        }
    }
}
impl Drop for Creation {
    fn drop(&mut self) {
        if !self.published.load(Ordering::Acquire) {
            let child = { self.child.lock().take() };
            if let Some((child, _)) = child {
                child.release_control_metadata();
            }
        }
    }
}
#[derive(Debug)]
struct Deletion {
    authority: RadioControlAuthority,
    retired: IrqSafeSpinLock<Option<RadioControlRetirement>>,
}
impl DeferredAuthority for Deletion {
    fn current(&self) -> bool {
        let retired = { self.retired.lock().clone() };
        match retired {
            Some(retired) => retired.current(),
            None => self.authority.retirement_wait_current(),
        }
    }
}
fn bind(
    iface: &Arc<dyn crate::WirelessNetIface>,
    admin: narf_net::AdminHandle,
    namespace: u64,
    slot: &DeferredRequest,
) -> Result<RadioControlAuthority, i32> {
    let authority = match iface.control_namespace() {
        Some(_) => {
            let wdev = crate::registry::control_for(iface.as_ref()).ok_or(ENODEV)?;
            RadioControlAuthority::bind_wdev(admin, iface, namespace, wdev.id(), slot.reply_sink())
        }
        None => {
            let index = narf_net::netlink_route::ifindex_for_name(iface.name()).ok_or(ENODEV)?;
            RadioControlAuthority::bind(admin, iface, namespace, index, slot.reply_sink())
        }
    };
    authority
        .and_then(RadioControlAuthority::reserve)
        .map_err(virtual_interface_errno)
}
pub(super) fn create(
    iface: Arc<dyn crate::WirelessNetIface>,
    admin: narf_net::AdminHandle,
    namespace: u64,
    name: String,
    iftype: u32,
    mac: Option<[u8; 6]>,
    slot: Option<&DeferredRequest>,
) -> Result<Vec<GenlReply>, i32> {
    let slot = slot.ok_or(EOPNOTSUPP)?;
    // This opt-in currently creates a control-only DEVICE. Other legacy
    // roles continue through their existing callbacks without aliases.
    if iftype != 10 {
        return Err(EOPNOTSUPP);
    }
    let guard = Arc::new(Creation {
        authority: bind(&iface, admin, namespace, slot)?,
        child: IrqSafeSpinLock::new(None),
        published: AtomicBool::new(false),
    });
    let retained = guard.clone();
    slot.defer_replies_checked(
        Box::pin(async move {
            let mut native = Box::pin(iface.new_control_interface_async(
                &retained.authority,
                &name,
                iftype,
                mac,
            ));
            let result = core::future::poll_fn(|cx| {
                if !retained.current() {
                    return core::task::Poll::Ready(Err(crate::WirelessError::Denied));
                }
                native.as_mut().poll(cx)
            })
            .await;
            drop(native);
            let child = result.map_err(virtual_interface_errno)?;
            // Retain cleanup even when a misbehaving driver returns a stale or
            // invalid object. The original serialization lease is still held.
            let generation = child.radio_control_generation();
            let Some(generation) = generation else {
                child.release_control_metadata();
                return Err(EPERM);
            };
            *retained.child.lock() = Some((child.clone(), generation));
            if child.name() != name
                || child.current_iftype() != iftype
                || child.control_namespace() != Some(namespace)
                || !retained.current()
            {
                return Err(EPERM);
            }
            let wiphy = crate::registry::wiphy_index(child.wiphy_id()).ok_or(ENODEV)?;
            Ok(alloc::vec![GenlReply {
                command: NEW_INTERFACE,
                attrs: super::super::interface_attrs(wiphy, child.as_ref(), iftype)
            }])
        }),
        guard,
    )?;
    Ok(Vec::new())
}
pub(super) fn delete(
    iface: Arc<dyn crate::WirelessNetIface>,
    admin: narf_net::AdminHandle,
    namespace: u64,
    slot: Option<&DeferredRequest>,
) -> Result<Vec<GenlReply>, i32> {
    let slot = slot.ok_or(EOPNOTSUPP)?;
    let guard = Arc::new(Deletion {
        authority: bind(&iface, admin, namespace, slot)?,
        retired: IrqSafeSpinLock::new(None),
    });
    let retained = guard.clone();
    slot.defer_replies_checked(
        Box::pin(async move {
            let mut native = Box::pin(iface.delete_control_interface_async(&retained.authority));
            let result = core::future::poll_fn(|cx| {
                if !retained.current() {
                    return core::task::Poll::Ready(Err(crate::WirelessError::Denied));
                }
                native.as_mut().poll(cx)
            })
            .await;
            drop(native);
            let retired = result.map_err(virtual_interface_errno)?;
            *retained.retired.lock() = Some(retired);
            if !retained.current() {
                return Err(EPERM);
            }
            Ok(Vec::new())
        }),
        guard,
    )?;
    Ok(Vec::new())
}
