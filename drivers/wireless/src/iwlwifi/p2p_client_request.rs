//! Source-current CLIENT Radio requests. Full socket/interface callbacks
//! execute only during capture and after native State is released.
use alloc::sync::Arc;
use core::future::Future;
use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicBool, Ordering},
    task::Waker,
};
use narf_wireless::{
    ap_control::{RadioControlAuthority, RadioEmissionAuthority},
    WirelessNetIface,
};
pub(super) struct Origin {
    pub sources: super::runtime::source::Fence,
    pub mvm: Option<super::mvm_publication::Source>,
    pub generation: (Arc<core::sync::atomic::AtomicU64>, u64),
    pub receive: Option<super::runtime::rx_epoch::Publication>,
}
impl Origin {
    fn check(&self) -> Result<(), &'static str> {
        let check = || {
            if self.generation.0.load(Ordering::Acquire) != self.generation.1
                || self.receive.as_ref().is_some_and(|epoch| !epoch.current())
            {
                return Err("P2P FRAME original controlled-port/copy owner retired");
            }
            Ok(())
        };
        self.sources.invoke(|| match &self.mvm {
            Some(source) => source.invoke(check),
            None => check(),
        })
    }
}
pub(super) struct Request {
    pub cancel: Arc<AtomicBool>,
    pub native: Arc<super::p2p_client::Native>,
    emission: RadioEmissionAuthority,
    role: narf_net::native_emission::Lifetime,
    pump: Waker,
    origin: Origin,
    initiation: narf_lib::sync::IrqSafeSpinLock<Option<super::mld_policy::Fence>>,
}
impl Request {
    #[allow(clippy::too_many_arguments)]
    pub fn capture<I: WirelessNetIface + ?Sized>(
        authority: &RadioControlAuthority,
        receiver: &I,
        generation: NonZeroU64,
        role: narf_net::native_emission::Lifetime,
        pump: Waker,
        native: Arc<super::p2p_client::Native>,
        origin: Origin,
    ) -> Result<Arc<Self>, &'static str> {
        authority
            .require_mode(8)
            .map_err(|_| "P2P client request belongs to another role")?;
        authority
            .check_for(receiver)
            .map_err(|_| "P2P client original request/source retired")?;
        authority
            .require_link()
            .map_err(|_| "P2P client actual netdev not UP")?;
        if !authority.has_reservation() {
            return Err("P2P client request lacks original native reservation");
        }
        let emission = authority
            .native_emission_for(receiver)
            .map_err(|_| "P2P client concrete original source providers unsupported")?;
        if !emission.matches_mode(receiver, 8, generation) || !role.current() {
            return Err("P2P client original mode changed during capture");
        }
        let request = Arc::new(Self {
            cancel: Arc::new(AtomicBool::new(false)),
            native,
            origin,
            emission,
            role,
            pump,
            initiation: narf_lib::sync::IrqSafeSpinLock::new(None),
        });
        request.check()?;
        Ok(request)
    }
    pub fn check(&self) -> Result<(), &'static str> {
        self.native.current()?;
        self.origin.check()?;
        if self.cancel.load(Ordering::Acquire) || !self.role.current() || !self.emission.current() {
            Err("P2P client original request/role/source retired")
        } else {
            Ok(())
        }
    }
    pub fn qualify(&self, fence: super::mld_policy::Fence) -> Result<(), &'static str> {
        self.check()?;
        fence.check()?;
        let mut slot = self.initiation.lock();
        if slot.is_some() {
            return Err("P2P FRAME initiating proof already recorded");
        }
        *slot = Some(fence);
        Ok(())
    }
    pub fn transmission(&self) -> Result<(), &'static str> {
        self.check()?;
        self.native.transmission()?;
        let fence = { self.initiation.lock().clone() }
            .ok_or("P2P FRAME has no actual initiating RF/power receipt")?;
        fence.check()?;
        self.check()
    }
    pub fn watch(&self) -> bool {
        self.role.watch(self.pump.clone())
            && self.emission.watch(&self.pump)
            && self.check().is_ok()
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
        self.pump.wake_by_ref();
    }
}
pub(super) struct Waiter {
    pub inner: super::ap_host::Waiter,
    pub request: Arc<Request>,
}
impl Future for Waiter {
    type Output = Result<bool, i32>;
    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        core::pin::Pin::new(&mut self.inner).poll(cx)
    }
}
impl Drop for Waiter {
    fn drop(&mut self) {
        if !self.inner.consumed {
            self.request.cancel();
        }
    }
}

/// Only fixed retained checks run at the shared final publication fence.
/// Native source capabilities and physical association are the exact owners
/// captured before work; no State, virtual interface or socket callback.
pub(super) struct Completion {
    pub request: Arc<Request>,
}
impl narf_wireless::ap_control::RadioFrameCompletion for Completion {
    fn current(&self) -> bool {
        self.request.transmission().is_ok()
    }
}
