//! Original P2P control-WDEV request/source retention. This grants no
//! PHY/AUX/session/ROC or RF publication receipt by itself.
//! Full provider/interface callbacks run only in capture(), outside State;
//! the native pump uses the captured typed providers and concrete role epoch.
use alloc::sync::{Arc, Weak};
use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::Waker,
};
use narf_capabilities::{Cap, CapError, CapOp, Grant, Write};
use narf_wireless::{
    ap_control::{RadioControlAuthority, RadioEmissionAuthority, RadioEventAuthority},
    WirelessNetIface,
};

/// Original successful physical publication receipts. Re-invocation adds
/// current registrar/parent authority to the independent original child
/// Admin/daemon/provider/source chain; no discovery lookup substitutes one.
#[derive(Clone, Copy)]
pub(super) struct Registration {
    pub grant: Cap<narf_net::NetIface, Grant>,
    pub parent: Cap<narf_net::NetIface, Write>,
}
struct CurrentWrite;
impl CapOp<narf_net::NetIface, Write> for CurrentWrite {
    type Output = bool;
    fn execute(self, _: &Cap<narf_net::NetIface, Write>) -> Result<bool, CapError> {
        Ok(true)
    }
}
impl CapOp<narf_net::NetIface, Grant> for Registration {
    type Output = bool;
    fn execute(self, _: &Cap<narf_net::NetIface, Grant>) -> Result<bool, CapError> {
        self.parent.invoke(CurrentWrite)
    }
}
impl Registration {
    pub fn current(self) -> bool {
        self.grant.invoke(self) == Ok(true)
    }
}

/// One original START/ROC/FRAME request. The physical device START owner
/// and each operation retain separate instances; cancelling an operation
/// must not substitute its source for the original START authority.
pub(super) struct Request {
    receiver: Weak<dyn WirelessNetIface>,
    generation: Arc<AtomicU64>,
    captured_generation: NonZeroU64,
    role: narf_net::native_emission::Lifetime,
    emission: RadioEmissionAuthority,
    event: RadioEventAuthority,
    cancel: AtomicBool,
    pump: Waker,
    own: [u8; 6],
    registration: Registration,
}
impl Request {
    /// `generation` is the actual control child's mode-generation atomic,
    /// and `pump` belongs to the retained physical device worker. Capture
    /// cannot grant a WDEV from an observed IFINDEX or a fresh parent source.
    pub fn capture(
        authority: &RadioControlAuthority,
        receiver: &Arc<dyn WirelessNetIface>,
        child: &Cap<narf_net::NetIface, Write>,
        registration: Registration,
        generation: Arc<AtomicU64>,
        role: narf_net::native_emission::Lifetime,
        pump: Waker,
    ) -> Result<Arc<Self>, &'static str> {
        authority
            .require_mode(10)
            .map_err(|_| "Intel P2P request is not its control WDEV")?;
        authority
            .check_for(receiver.as_ref())
            .map_err(|_| "Intel P2P original source/registration retired")?;
        let identity = authority
            .identity()
            .map_err(|_| "Intel P2P current control identity absent")?;
        let own = identity.mac();
        if own == [0; 6] || own[0] & 1 != 0 {
            return Err("Intel P2P original control address invalid");
        }
        let event = authority
            .event_authority()
            .map_err(|_| "Intel P2P original event source unavailable")?;
        let emission = authority
            .native_control_emission_for(receiver.as_ref(), child)
            .map_err(|_| "Intel P2P actual child/source providers unsupported")?;
        authority
            .check_for(receiver.as_ref())
            .map_err(|_| "Intel P2P original request changed during capture")?;
        let captured_generation = NonZeroU64::new(generation.load(Ordering::Acquire))
            .filter(|current| emission.matches_mode(receiver.as_ref(), 10, *current))
            .ok_or("Intel P2P actual child mode epoch changed during capture")?;
        let request = Arc::new(Self {
            receiver: Arc::downgrade(receiver),
            generation,
            captured_generation,
            role,
            emission,
            event,
            cancel: AtomicBool::new(false),
            pump,
            own,
            registration,
        });
        request.check()?;
        Ok(request)
    }
    /// Fixed Cap invocations/weak typed provider observations only. Never
    /// call arbitrary Socket/DeferredReplySink/virtual iface callbacks here.
    /// This is one mandatory input to native admission, not a firmware grant.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.cancel.load(Ordering::Acquire)
            || !self.role.current()
            || !self.registration.current()
        {
            return Err("Intel P2P original operation/role retired");
        }
        // Never upgrade/drop the virtual interface here: a last Arc could
        // otherwise run its destructor while the caller holds native State.
        // Capture already bound this immutable receiver and exact epoch.
        if self.receiver.strong_count() == 0
            || self.generation.load(Ordering::Acquire) != self.captured_generation.get()
            || !self.emission.current()
        {
            return Err("Intel P2P current original control authority retired");
        }
        Ok(())
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
        self.pump.wake_by_ref();
    }
    /// The physical pump also uses its bounded timer to notice actual cap
    /// revocations, which need not notify a provider lifetime. Watch refusal
    /// is admission failure; it never falls back to a cached validity bit.
    pub fn watch(&self) -> bool {
        self.role.watch(self.pump.clone())
            && self.emission.watch(&self.pump)
            && self.check().is_ok()
    }
    pub fn own(&self) -> [u8; 6] {
        self.own
    }
    pub fn same_receiver(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.receiver, &other.receiver)
            && Arc::ptr_eq(&self.generation, &other.generation)
            && self.captured_generation == other.captured_generation
    }
    pub fn emission(&self) -> &RadioEmissionAuthority {
        &self.emission
    }
    /// Event preparation/delivery may invoke providers and must run outside
    /// native State. The caller separately proves actual START/terminal/RX
    /// receipt, current grant epoch and RF policy at its final publication.
    pub fn event(&self) -> RadioEventAuthority {
        self.event.clone()
    }
}

/// Dropping a public waiter requests cancellation. Hardware resources stay
/// with the physical owner's queued operation until native cleanup/reset.
pub(super) struct Waiter {
    request: Arc<Request>,
    complete: bool,
}
impl Waiter {
    pub fn new(request: Arc<Request>) -> Self {
        Self {
            request,
            complete: false,
        }
    }
    pub fn complete(&mut self) {
        self.complete = true;
    }
}
impl Drop for Waiter {
    fn drop(&mut self) {
        if !self.complete {
            self.request.cancel();
        }
    }
}
