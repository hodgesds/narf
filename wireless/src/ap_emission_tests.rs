//! Actual delegated AP authority; callbacks remain outside a native fence.
use super::*;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};

#[derive(Debug)]
struct NativeSource {
    owner: narf_net::native_emission::ProviderLifetime,
    callbacks: AtomicU32,
}
impl NativeSource {
    fn new() -> Self {
        Self {
            owner: narf_net::native_emission::ProviderLifetime::new(),
            callbacks: AtomicU32::new(0),
        }
    }
}
impl DeferredReplySink for NativeSource {
    fn current(&self) -> bool {
        self.callbacks.fetch_add(1, Ordering::AcqRel);
        self.owner.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.owner.observe())
    }
    fn deliver(&self, _: Vec<u8>) -> Result<(), i32> {
        Err(95)
    }
}
fn bound(
    f: &Fixture,
    source: Arc<dyn DeferredReplySink>,
) -> Result<ApControlAuthority, &'static str> {
    ApControlAuthority::bind(f.admin.clone(), &f.iface, 0, f.ifindex, source)
        .map_err(|_| "actual delegated AP binding")
}
fn native_fences() -> Result<(), &'static str> {
    let f = fixture()?;
    if bound(&f, f.source.clone())?
        .native_emission_for(f.radio.as_ref())
        .is_ok()
    {
        return Err("unknown source provider armed autonomous AP emission");
    }
    for boundary in 0..6 {
        let f = fixture()?;
        let source = Arc::new(NativeSource::new());
        let guard = bound(&f, source.clone())?
            .native_emission_for(f.radio.as_ref())
            .map_err(|_| "actual native source/registration/cap capture")?;
        let callbacks = source.callbacks.load(Ordering::Acquire);
        let generation = NonZeroU64::new(1).unwrap();
        if !guard.matches_role(f.radio.as_ref(), 3, generation)
            || guard.matches_role(&Radio::new(String::from("other-native-ap")), 3, generation)
            || guard.matches_role(f.radio.as_ref(), 3, NonZeroU64::new(3).unwrap())
        {
            return Err("native fence lost its exact concrete receiver/mode generation");
        }
        let ready = AtomicBool::new(false);
        let publications = AtomicU32::new(0);
        let mut pending = Box::pin(core::future::poll_fn(|_| {
            if !ready.load(Ordering::Acquire) {
                return Poll::Pending;
            }
            if !guard.current() {
                return Poll::Ready(Err(()));
            }
            publications.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(Ok(()))
        }));
        let mut cx = Context::from_waker(Waker::noop());
        if pending.as_mut().poll(&mut cx).is_ready() {
            return Err("held native-publication fixture did not wait");
        }
        match boundary {
            0 => source.owner.retire().notify(),
            1 => f.daemon.revoke(),
            2 => f.cap.revoke(),
            3 => {
                narf_net::iface::set_link_state(f.radio.name(), false);
                narf_net::iface::set_link_state(f.radio.name(), true);
            }
            4 => {
                crate::registry::unregister(f.radio.name());
                crate::registry::register(f.iface.clone());
            }
            _ => {
                narf_net::registry().unregister_for_handle(&f.cap);
                narf_net::registry()
                    .register(
                        &narf_net::bootstrap_authority(),
                        Registered(f.radio.clone()),
                    )
                    .map_err(|_| "replacement typed AP provider")?;
            }
        }
        ready.store(true, Ordering::Release);
        if pending.as_mut().poll(&mut cx) != Poll::Ready(Err(()))
            || publications.load(Ordering::Acquire) != 0
            || source.callbacks.load(Ordering::Acquire) != callbacks
        {
            return Err(
                "held AP publication survived actual retirement or called arbitrary source code",
            );
        }
    }
    Ok(())
}
fn ap_native_fence_denies_unknown_source_and_rechecks_actual_authority_after_waits_without_callbacks(
) -> TestResult {
    native_fences().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!("wireless/ap_emission", ap_native_fence_denies_unknown_source_and_rechecks_actual_authority_after_waits_without_callbacks);
