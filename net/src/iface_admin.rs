//! Pure interface metadata changes and detached, registration-owned effects.
//! PUBLISH is acquired before the exact Registry/IFACES mutation, and all
//! registry/IRQ locks are released before any ndo callback runs.
use super::*;

/// A trusted driver captures its original receiver in this target. It must
/// use that receiver's actual device grant, never a fresh name lookup.
pub trait OpenStopTarget: core::fmt::Debug + Send + Sync {
    fn transition(&self, event: OpenStopEvent);
}

/// The original metadata transition. This observation supplies no grant.
/// A stale UP cannot start a replacement; DOWN may clean up the captured
/// old device under its own still-current device capability.
#[derive(Clone, Debug)]
pub struct OpenStopEvent {
    snapshot: NetIfaceSnapshot,
}
impl OpenStopEvent {
    pub fn name(&self) -> &str {
        &self.snapshot.name
    }
    pub fn up(&self) -> bool {
        self.snapshot.link_up
    }
    pub fn current(&self) -> bool {
        let guard = IFACES.lock();
        guard.as_ref().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry.registration_epoch != 0
                    && entry.registration_epoch == self.snapshot.registration_epoch
                    && entry.net_ns_id == self.snapshot.net_ns_id
                    && entry.ownership_epoch == self.snapshot.ownership_epoch
                    && entry.link_up == self.snapshot.link_up
            })
        })
    }
}

/// Install an original-receiver target only for this actual registration.
/// The snapshot is an identity fence; trusted driver binding and current
/// device authority remain independent preconditions.
pub fn set_open_stop_target(expected: &NetIfaceSnapshot, target: Arc<dyn OpenStopTarget>) -> bool {
    let mut guard = IFACES.lock();
    let Some(entry) = guard.as_mut().and_then(|entries| {
        entries.iter_mut().find(|entry| {
            expected.registration_epoch != 0
                && entry.registration_epoch == expected.registration_epoch
        })
    }) else {
        return false;
    };
    entry.open_stop = None;
    entry.open_stop_target = Some(target);
    true
}

#[derive(Clone, Copy)]
pub(crate) enum Change {
    Link(bool),
    Mtu(u32),
    Mac([u8; 6]),
}
#[derive(Clone, Copy)]
pub(crate) enum Binding {
    Name,
    Registration(Option<u64>),
}
pub(crate) struct Effects {
    link: Option<LinkEffect>,
    retired_capture: Option<NetIfaceSnapshot>,
    /// MTU/MAC change on an interface with a `DeviceControl` hook. It is
    /// authorized inside the grant but committed afterwards through
    /// `try_set_mtu`/`try_set_mac`, so the driver callback runs with no
    /// IFACES, Registry or PUBLISH lock held.
    device: Option<Change>,
    native: Vec<crate::native_emission::Retirement>,
}
struct LinkEffect {
    event: OpenStopEvent,
    legacy: Option<OpenStopFn>,
    target: Option<Arc<dyn OpenStopTarget>>,
}
impl Effects {
    fn invalidate(&self) {
        if let Some(old) = &self.retired_capture {
            monitor::invalidate(old);
        }
    }
    fn notify(self) {
        for native in self.native {
            native.notify();
        }
        let Some(LinkEffect {
            event,
            legacy,
            target,
        }) = self.link
        else {
            return;
        };
        // Neither IFACES, Registry nor PUBLISH is held over driver code.
        if let Some(target) = target {
            target.transition(event.clone());
        } else if let Some(legacy) = legacy {
            // Legacy hooks keep their existing original-device binding
            // precondition. This check alone is not an SMP receiver lease.
            if event.current() {
                legacy(event.name(), event.up());
            }
        }
        // A reentrant callback may retire/rebind or reverse the transition.
        // Serialize this final original-event check with registration/mode
        // publication, then notify only that current metadata generation.
        let _publish = monitor::PUBLISH.lock();
        if event.current() {
            crate::raw_sock::netdev_event(
                event.snapshot.net_ns_id,
                event.snapshot.ifindex,
                if event.up() {
                    crate::raw_sock::NetdevEvent::Up
                } else {
                    crate::raw_sock::NetdevEvent::Down
                },
            );
        }
    }
}

/// Called inside the actual grant and exact typed-registry invocation.
/// No callback, notifier or capability operation runs under IFACES.
pub(crate) fn mutate(name: &str, binding: Binding, change: Change) -> Option<Effects> {
    let mut guard = IFACES.lock();
    let entry = guard
        .as_mut()?
        .iter_mut()
        .find(|entry| entry.name == name)?;
    if let Binding::Registration(expected) = binding {
        if entry.registration_epoch == 0 || expected != Some(entry.registration_epoch) {
            return None;
        }
    }
    let mut effects = Effects {
        link: None,
        retired_capture: None,
        device: None,
        native: Vec::new(),
    };
    if entry.control.is_some() && matches!(change, Change::Mtu(_) | Change::Mac(_)) {
        effects.device = Some(change);
        return Some(effects);
    }
    match change {
        Change::Mtu(mtu) => entry.mtu = mtu,
        Change::Mac(mac) => {
            if entry.mac != mac {
                effects.native.push(entry.retire_native());
                entry.ownership_epoch = next_ownership_epoch();
            }
            entry.mac = mac;
            entry.addr_assign_type = 3;
        }
        Change::Link(up) => {
            if entry.link_up != up {
                if !up {
                    effects.native.push(entry.retire_native());
                }
                entry.link_up = up;
                if !up {
                    entry.ownership_epoch = next_ownership_epoch();
                    entry.monitor_epoch = 0;
                    if entry.link_layer == LinkLayer::Ieee80211Radiotap {
                        entry.packet_generation = monitor::next_epoch().unwrap_or(u64::MAX);
                        monitor::carrier(entry, false);
                    }
                    effects.retired_capture = Some(snapshot(entry));
                }
                effects.link = Some(LinkEffect {
                    event: OpenStopEvent {
                        snapshot: snapshot(entry),
                    },
                    legacy: entry.open_stop,
                    target: entry.open_stop_target.clone(),
                });
            }
        }
    }
    Some(effects)
}

pub(crate) fn apply(
    admin: &crate::stack::AdminHandle,
    change: Change,
) -> Result<(), crate::stack::AdminError> {
    #[cfg(feature = "kernel-test")]
    crate::stack::metadata::before_apply(admin.iface_name());
    let publish = monitor::PUBLISH.lock();
    let effects = admin.invoke_metadata(change)?;
    effects.invalidate();
    drop(publish);
    let device = effects.device;
    effects.notify();
    // Hardware-aware commit for DeviceControl interfaces, preserving the
    // driver's Linux errno.
    let result = match device {
        Some(Change::Mtu(mtu)) => {
            super::try_set_mtu(admin.iface_name(), mtu).map_err(|code| match code {
                19 => crate::stack::AdminError::NoIface,
                22 => crate::stack::AdminError::InvalidMtu,
                other => crate::stack::AdminError::DeviceError(other),
            })
        }
        Some(Change::Mac(mac)) => {
            super::try_set_mac(admin.iface_name(), mac).map_err(|code| match code {
                19 => crate::stack::AdminError::NoIface,
                22 => crate::stack::AdminError::InvalidMac,
                other => crate::stack::AdminError::DeviceError(other),
            })
        }
        _ => Ok(()),
    };
    result
}
pub(super) fn apply_name(name: &str, change: Change) -> bool {
    let publish = monitor::PUBLISH.lock();
    let Some(effects) = mutate(name, Binding::Name, change) else {
        return false;
    };
    effects.invalidate();
    drop(publish);
    effects.notify();
    true
}
