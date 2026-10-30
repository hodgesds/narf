//! Current authority and interface/mode identity for native async AP work.
//! A netlink reply sink supplies liveness, never administrative authority.

use alloc::sync::{Arc, Weak};
use core::{
    fmt,
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};
use narf_net::{netlink_generic::DeferredReplySink, AdminHandle};

use crate::{WirelessError, WirelessNetIface};

#[path = "ap_event.rs"]
mod event;
pub use event::ApEventAuthority;

#[cfg(feature = "kernel-test")]
#[path = "ap_control_tests.rs"]
mod tests;

/// An actual request's existing administrative grant plus exact interface
/// and mode generation. Drivers check it at command/poll/publication
/// boundaries; retaining this object alone never proves current authority.
#[derive(Clone)]
pub struct ApControlAuthority {
    iface: Weak<dyn WirelessNetIface>,
    admin: AdminHandle,
    namespace: u64,
    ifindex: u32,
    ownership_epoch: NonZeroU64,
    mode: u32,
    generation: NonZeroU64,
    reply: Arc<dyn DeferredReplySink>,
    reservation: Option<Arc<dyn ApControlReservation>>,
    reserved: bool,
}

impl fmt::Debug for ApControlAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApControlAuthority")
            .field("namespace", &self.namespace)
            .field("ifindex", &self.ifindex)
            .field("mode", &self.mode)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl narf_net::netlink_generic::DeferredAuthority for ApControlAuthority {
    fn current(&self) -> bool {
        ApControlAuthority::current(self).is_ok()
    }
}

impl ApControlAuthority {
    /// Bind an existing grant to this actual registered AP/GO and exact
    /// source socket. Namespace and ifindex are the original request's
    /// kernel-resolved identity, never a fresh lookup after a transfer.
    /// Trusted registration pairs net/wireless entries for the same device.
    /// No administrative capability is minted or exported.
    pub fn bind(
        admin: AdminHandle,
        iface: &Arc<dyn WirelessNetIface>,
        namespace: u64,
        ifindex: u32,
        reply: Arc<dyn DeferredReplySink>,
    ) -> Result<Self, WirelessError> {
        let generation = iface
            .ap_control_generation()
            .ok_or(WirelessError::NotSupported)?;
        let snapshot =
            narf_net::iface::lookup_in(namespace, iface.name()).ok_or(WirelessError::Denied)?;
        let ownership_epoch =
            NonZeroU64::new(snapshot.ownership_epoch).ok_or(WirelessError::Denied)?;
        let authority = Self {
            iface: Arc::downgrade(iface),
            admin,
            namespace,
            ifindex,
            ownership_epoch,
            mode: iface.current_iftype(),
            generation,
            reply,
            reservation: None,
            reserved: false,
        };
        if !matches!(authority.mode, 3 | 9) {
            return Err(WirelessError::NotSupported);
        }
        authority.current()?;
        Ok(authority)
    }

    pub fn current(&self) -> Result<(), WirelessError> {
        self.check(None)
    }
    /// Whether a native driver actually supplied its synchronous admission
    /// lease. This is serialization metadata, never current authority.
    pub fn has_reservation(&self) -> bool {
        self.reserved && self.reservation.is_some()
    }

    /// Reserve driver control order before the deferred callback's first
    /// poll. A retained native owner clones this guard until its terminal
    /// cleanup; dropping only the borrowed API waiter cannot release it.
    pub fn reserve(mut self) -> Result<Self, WirelessError> {
        self.current()?;
        if self.reserved {
            return Err(WirelessError::Busy);
        }
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        self.reservation = iface.reserve_ap_control()?;
        self.reserved = true;
        self.current()?;
        Ok(self)
    }

    /// Also prove that a concrete receiver is the exact interface named by
    /// the request; a valid grant for another AP cannot be replayed here.
    pub fn check_for<I: WirelessNetIface + ?Sized>(&self, iface: &I) -> Result<(), WirelessError> {
        self.check(Some(core::ptr::from_ref(iface).cast::<()>()))
    }

    fn check(&self, receiver: Option<*const ()>) -> Result<(), WirelessError> {
        if !self.reply.current()
            || self
                .reservation
                .as_ref()
                .is_some_and(|lease| !lease.current())
        {
            return Err(WirelessError::Denied);
        }
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        if receiver.is_some_and(|pointer| pointer != Arc::as_ptr(&iface).cast::<()>())
            || iface.current_iftype() != self.mode
            || iface.ap_control_generation() != Some(self.generation)
            || narf_net::iface::lookup_in(self.namespace, iface.name()).is_none_or(|link| {
                link.ifindex != self.ifindex || link.ownership_epoch != self.ownership_epoch.get()
            })
            || !crate::registry::list()
                .iter()
                .any(|registered| Arc::ptr_eq(registered, &iface))
        {
            return Err(WirelessError::Denied);
        }
        self.admin
            .authorize_interface(iface.name(), self.namespace)
            .map_err(|_| WirelessError::Denied)
    }
}

/// Completed AP interface identity, independent of a request socket's lifetime.
/// This is an observation fence, not a capability or frame-admission grant.
/// Native device/RF/key/controlled-port owners must still authorize every packet.
#[derive(Clone)]
pub struct ApInterfaceIdentity {
    iface: Weak<dyn WirelessNetIface>,
    namespace: u64,
    ifindex: u32,
    mode: u32,
    generation: NonZeroU64,
    ownership_epoch: NonZeroU64,
    mac: [u8; 6],
}
impl fmt::Debug for ApInterfaceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApInterfaceIdentity")
            .field("namespace", &self.namespace)
            .field("ifindex", &self.ifindex)
            .field("generation", &self.generation)
            .field("ownership_epoch", &self.ownership_epoch)
            .finish_non_exhaustive()
    }
}
impl ApControlAuthority {
    /// The START/update packet owner additionally needs the original current
    /// administrative-UP generation. STOP cleanup need not require UP.
    pub fn require_up(&self) -> Result<(), WirelessError> {
        self.current()?;
        self.identity()?.current()
    }
    /// Capture identity only while the actual request is current. Calling
    /// this does not prove native command completion or open a port/carrier.
    pub fn identity(&self) -> Result<ApInterfaceIdentity, WirelessError> {
        self.current()?;
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        let identity = ApInterfaceIdentity {
            iface: self.iface.clone(),
            namespace: self.namespace,
            ifindex: self.ifindex,
            mode: self.mode,
            generation: self.generation,
            ownership_epoch: self.ownership_epoch,
            mac: iface.mac(),
        };
        identity.current()?;
        Ok(identity)
    }
}
impl ApInterfaceIdentity {
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    /// Observe the same current UP identity for an identity-fenced net
    /// metadata update. The snapshot carries no administrative/native grant.
    pub fn metadata_snapshot(&self) -> Result<narf_net::iface::NetIfaceSnapshot, WirelessError> {
        self.current()?;
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        let snapshot = narf_net::iface::lookup_in(self.namespace, iface.name())
            .ok_or(WirelessError::Denied)?;
        if !snapshot.link_up
            || snapshot.ifindex != self.ifindex
            || snapshot.ownership_epoch != self.ownership_epoch.get()
            || snapshot.mac != self.mac
        {
            return Err(WirelessError::Denied);
        }
        Ok(snapshot)
    }
    pub fn current(&self) -> Result<(), WirelessError> {
        self.check(None)
    }
    pub fn check_for<I: WirelessNetIface + ?Sized>(&self, iface: &I) -> Result<(), WirelessError> {
        self.check(Some(core::ptr::from_ref(iface).cast::<()>()))
    }
    fn check(&self, receiver: Option<*const ()>) -> Result<(), WirelessError> {
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        if receiver.is_some_and(|pointer| pointer != Arc::as_ptr(&iface).cast::<()>())
            || iface.current_iftype() != self.mode
            || iface.ap_control_generation() != Some(self.generation)
            || iface.mac() != self.mac
            || narf_net::iface::lookup_in(self.namespace, iface.name()).is_none_or(|link| {
                !link.link_up
                    || link.ifindex != self.ifindex
                    || link.ownership_epoch != self.ownership_epoch.get()
            })
            || !crate::registry::list()
                .iter()
                .any(|registered| Arc::ptr_eq(registered, &iface))
        {
            return Err(WirelessError::Denied);
        }
        Ok(())
    }
}

/// Native control serialization only. This object grants no administrative,
/// device or packet authority; ApControlAuthority still checks actual grants.
pub trait ApControlReservation: fmt::Debug + Send + Sync {
    fn current(&self) -> bool;
}
/// Optional single-operation admission for a native driver. This is acquired
/// synchronously at netlink dispatch, before executor scheduling can reorder
/// two mutations. Existing drivers can keep their own ordered admission.
#[derive(Debug)]
pub struct ExclusiveControl {
    next: AtomicU64,
    owner: AtomicU64,
}
impl Default for ExclusiveControl {
    fn default() -> Self {
        Self::new()
    }
}
impl ExclusiveControl {
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            owner: AtomicU64::new(0),
        }
    }
    pub fn try_reserve(self: &Arc<Self>) -> Result<Arc<dyn ApControlReservation>, WirelessError> {
        if self.owner.load(Ordering::Acquire) != 0 {
            return Err(WirelessError::Busy);
        }
        let nonce = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1)
            })
            .map_err(|_| WirelessError::Denied)?;
        self.owner
            .compare_exchange(0, nonce, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| WirelessError::Busy)?;
        Ok(Arc::new(ExclusiveReservation {
            control: self.clone(),
            nonce,
        }))
    }
}
#[derive(Debug)]
struct ExclusiveReservation {
    control: Arc<ExclusiveControl>,
    nonce: u64,
}
impl ApControlReservation for ExclusiveReservation {
    fn current(&self) -> bool {
        self.control.owner.load(Ordering::Acquire) == self.nonce
    }
}
impl Drop for ExclusiveReservation {
    fn drop(&mut self) {
        // Even a delayed old Drop cannot clear a successor's reservation.
        let _ =
            self.control
                .owner
                .compare_exchange(self.nonce, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}
