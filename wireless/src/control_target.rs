//! Identity observations for a netdev or an actual control-only wdev.
//! Neither representation supplies administrative/native packet authority.
use super::*;
use core::num::NonZeroU32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Target {
    Netdev {
        ifindex: NonZeroU32,
        epoch: NonZeroU64,
    },
    Control(crate::registry::ControlWdev),
}
impl Target {
    pub fn netdev(name: &str, namespace: u64, ifindex: u32) -> Result<Self, WirelessError> {
        let snapshot = narf_net::iface::lookup_in(namespace, name).ok_or(WirelessError::Denied)?;
        Ok(Self::Netdev {
            ifindex: NonZeroU32::new(ifindex)
                .filter(|id| id.get() == snapshot.ifindex)
                .ok_or(WirelessError::Denied)?,
            epoch: NonZeroU64::new(snapshot.ownership_epoch).ok_or(WirelessError::Denied)?,
        })
    }
    pub fn control<I: WirelessNetIface + ?Sized>(
        iface: &I,
        namespace: u64,
        id: u64,
    ) -> Result<Self, WirelessError> {
        let control = crate::registry::control_for(iface).ok_or(WirelessError::Denied)?;
        if control.id() != id || control.namespace() != namespace || !control.current_for(iface) {
            return Err(WirelessError::Denied);
        }
        Ok(Self::Control(control))
    }
    pub fn current<I: WirelessNetIface + ?Sized>(
        self,
        iface: &I,
        namespace: u64,
        require_up: bool,
    ) -> bool {
        match self {
            Self::Netdev { ifindex, epoch } => narf_net::iface::lookup_in(namespace, iface.name())
                .is_some_and(|link| {
                    link.ifindex == ifindex.get()
                        && link.ownership_epoch == epoch.get()
                        && (!require_up || link.link_up)
                }),
            Self::Control(control) => {
                !require_up
                    && iface.current_iftype() == 10
                    && control.namespace() == namespace
                    && control.current_for(iface)
            }
        }
    }
    pub fn netdev_ifindex(self) -> Result<u32, WirelessError> {
        match self {
            Self::Netdev { ifindex, .. } => Ok(ifindex.get()),
            Self::Control(_) => Err(WirelessError::Denied),
        }
    }
    pub fn wdev(self, wiphy: u32) -> u64 {
        match self {
            Self::Netdev { ifindex, .. } => (u64::from(wiphy) << 32) | u64::from(ifindex.get()),
            Self::Control(control) => control.id(),
        }
    }
}
