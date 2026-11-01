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
#[path = "control_target.rs"]
mod target;
use target::Target;

#[path = "ap_event.rs"]
mod event;
pub use event::{ApEventAuthority, PreparedApEvent};
#[path = "radio_control.rs"]
mod radio;
pub use radio::{
    PreparedRadioManagementEvent, RadioControlAuthority, RadioEmissionAuthority,
    RadioEventAuthority, RadioInterfaceIdentity, RadioReceiveFence,
};
#[path = "ap_emission.rs"]
mod emission;
pub use emission::ApEmissionAuthority;
#[path = "control_lifecycle.rs"]
mod lifecycle;
pub use lifecycle::RadioControlRetirement;

#[derive(Clone, Copy, Debug)]
enum ControlKind {
    Ap,
    Radio,
}
impl ControlKind {
    fn generation(self, iface: &dyn WirelessNetIface) -> Option<NonZeroU64> {
        match self {
            Self::Ap => iface.ap_control_generation(),
            Self::Radio => iface.radio_control_generation(),
        }
    }
    fn permits(self, mode: u32) -> bool {
        match self {
            Self::Ap => matches!(mode, 3 | 9),
            Self::Radio => matches!(mode, 2 | 3 | 8 | 9 | 10),
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "ap_control_tests.rs"]
mod tests;

/// An actual request's existing administrative grant plus exact interface
/// and mode generation. Drivers check it at command/poll/publication
/// boundaries; retaining this object alone never proves current authority.
#[derive(Clone)]
pub struct ApControlAuthority {
    kind: ControlKind,
    iface: Weak<dyn WirelessNetIface>,
    admin: AdminHandle,
    namespace: u64,
    target: Target,
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
            .field("target", &self.target)
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
        Self::bind_kind(admin, iface, namespace, ifindex, reply, ControlKind::Ap)
    }
    fn bind_radio(
        admin: AdminHandle,
        iface: &Arc<dyn WirelessNetIface>,
        namespace: u64,
        ifindex: u32,
        reply: Arc<dyn DeferredReplySink>,
    ) -> Result<Self, WirelessError> {
        Self::bind_kind(admin, iface, namespace, ifindex, reply, ControlKind::Radio)
    }
    fn bind_kind(
        admin: AdminHandle,
        iface: &Arc<dyn WirelessNetIface>,
        namespace: u64,
        ifindex: u32,
        reply: Arc<dyn DeferredReplySink>,
        kind: ControlKind,
    ) -> Result<Self, WirelessError> {
        let generation = kind
            .generation(iface.as_ref())
            .ok_or(WirelessError::NotSupported)?;
        let target = Target::netdev(iface.name(), namespace, ifindex)?;
        let authority = Self {
            kind,
            iface: Arc::downgrade(iface),
            admin,
            namespace,
            target,
            mode: iface.current_iftype(),
            generation,
            reply,
            reservation: None,
            reserved: false,
        };
        if !kind.permits(authority.mode) {
            return Err(WirelessError::NotSupported);
        }
        authority.current()?;
        Ok(authority)
    }

    pub fn current(&self) -> Result<(), WirelessError> {
        self.check(None)
    }
    fn bind_control_wdev(
        admin: AdminHandle,
        iface: &Arc<dyn WirelessNetIface>,
        namespace: u64,
        id: u64,
        reply: Arc<dyn DeferredReplySink>,
    ) -> Result<Self, WirelessError> {
        if iface.current_iftype() != 10 {
            return Err(WirelessError::NotSupported);
        }
        let authority = Self {
            kind: ControlKind::Radio,
            iface: Arc::downgrade(iface),
            admin,
            namespace,
            target: Target::control(iface.as_ref(), namespace, id)?,
            mode: 10,
            generation: ControlKind::Radio
                .generation(iface.as_ref())
                .ok_or(WirelessError::NotSupported)?,
            reply,
            reservation: None,
            reserved: false,
        };
        authority.current()?;
        Ok(authority)
    }
    fn netdev_ifindex(&self) -> Result<u32, WirelessError> {
        self.target.netdev_ifindex()
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
        self.reservation = match self.kind {
            ControlKind::Ap => iface.reserve_ap_control()?,
            ControlKind::Radio => iface.reserve_radio_control()?,
        };
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
            || self.kind.generation(iface.as_ref()) != Some(self.generation)
            || !self.target.current(iface.as_ref(), self.namespace, false)
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
    kind: ControlKind,
    iface: Weak<dyn WirelessNetIface>,
    namespace: u64,
    target: Target,
    mode: u32,
    generation: NonZeroU64,
    mac: [u8; 6],
}
impl fmt::Debug for ApInterfaceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApInterfaceIdentity")
            .field("namespace", &self.namespace)
            .field("target", &self.target)
            .field("generation", &self.generation)
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
        self.capture_identity(true)
    }
    fn capture_identity(&self, require_up: bool) -> Result<ApInterfaceIdentity, WirelessError> {
        self.current()?;
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        let identity = ApInterfaceIdentity {
            kind: self.kind,
            iface: self.iface.clone(),
            namespace: self.namespace,
            target: self.target,
            mode: self.mode,
            generation: self.generation,
            mac: iface.mac(),
        };
        identity.check_with_up(None, require_up)?;
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
            || snapshot.ifindex != self.target.netdev_ifindex()?
            || !self.target.current(iface.as_ref(), self.namespace, true)
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
        self.check_with_up(receiver, true)
    }
    fn check_with_up(
        &self,
        receiver: Option<*const ()>,
        require_up: bool,
    ) -> Result<(), WirelessError> {
        let iface = self.iface.upgrade().ok_or(WirelessError::Denied)?;
        if receiver.is_some_and(|pointer| pointer != Arc::as_ptr(&iface).cast::<()>())
            || iface.current_iftype() != self.mode
            || self.kind.generation(iface.as_ref()) != Some(self.generation)
            || iface.mac() != self.mac
            || !self
                .target
                .current(iface.as_ref(), self.namespace, require_up)
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
