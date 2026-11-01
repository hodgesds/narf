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
    delivered: AtomicU32,
    delivery_attempts: AtomicU32,
}
impl NativeSource {
    fn new() -> Self {
        Self {
            owner: narf_net::native_emission::ProviderLifetime::new(),
            callbacks: AtomicU32::new(0),
            delivered: AtomicU32::new(0),
            delivery_attempts: AtomicU32::new(0),
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
        self.delivery_attempts.fetch_add(1, Ordering::AcqRel);
        if !self.owner.observe().current() {
            return Err(125);
        }
        self.delivered.fetch_add(1, Ordering::AcqRel);
        Ok(())
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

fn station_native_fence_preserves_radio_kind_source_and_exact_receiver() -> TestResult {
    let check = || -> Result<(), &'static str> {
        for boundary in 0..6 {
            let f = fixture()?;
            f.radio.mode.store(2, Ordering::Release);
            let source = Arc::new(NativeSource::new());
            let authority = RadioControlAuthority::bind(
                f.admin.clone(),
                &f.iface,
                0,
                f.ifindex,
                source.clone(),
            )
            .map_err(|_| "actual station Radio binding")?;
            let guard = authority
                .native_emission_for(f.radio.as_ref())
                .map_err(|_| "actual station fixed native capture")?;
            let callbacks = source.callbacks.load(Ordering::Acquire);
            if !guard.matches_role(f.radio.as_ref(), NonZeroU64::new(1).unwrap())
                || guard.matches_role(
                    &Radio::new(String::from("other-native-station")),
                    NonZeroU64::new(1).unwrap(),
                )
                || authority
                    .guard
                    .native_emission_for(f.radio.as_ref())
                    .is_ok()
            {
                return Err("Radio fence lost receiver or became an AP emission guard");
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
                        .map_err(|_| "station provider replacement")?;
                }
            }
            if guard.current() || source.callbacks.load(Ordering::Acquire) != callbacks {
                return Err(
                    "station native fence survived actual retirement or called a source callback",
                );
            }
        }
        let f = fixture()?;
        let ap = bound(&f, f.source.clone())?;
        if RadioControlAuthority::bind(f.admin.clone(), &f.iface, 0, f.ifindex, f.source.clone())
            .map_err(|_| "AP-mode Radio binding")?
            .native_emission_for(f.radio.as_ref())
            .is_ok()
            || ap.native_emission_for(f.radio.as_ref()).is_ok()
        {
            return Err("unsupported provider or AP mode captured station-only Radio guard");
        }
        Ok(())
    };
    check().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_emission",
    station_native_fence_preserves_radio_kind_source_and_exact_receiver
);

fn prepared_radio_rx_checks_fixed_original_guards_and_epoch_after_source_callbacks() -> TestResult {
    let check = || -> Result<(), &'static str> {
        for boundary in 0..7 {
            let f = fixture()?;
            f.radio.mode.store(2, Ordering::Release);
            let source = Arc::new(NativeSource::new());
            let authority = RadioControlAuthority::bind(
                f.admin.clone(),
                &f.iface,
                0,
                f.ifindex,
                source.clone(),
            )
            .map_err(|_| "prepared Radio actual source")?;
            let guard = authority
                .native_emission_for(f.radio.as_ref())
                .map_err(|_| "prepared Radio native fixed source")?;
            let event = authority
                .event_authority()
                .map_err(|_| "prepared Radio actual event authority")?;
            let mut frame = alloc::vec![0;26];
            frame[0] = 0xd0;
            frame[4..10].copy_from_slice(&f.radio.mac());
            frame[10..16].copy_from_slice(&[2, 0, 0, 0, 0x79, 9]);
            frame[16..22].fill(255);
            frame[24] = 4;
            let prepared = event
                .prepare_management_received(5180, None, &frame)
                .map_err(|_| "prepared Radio metadata")?;
            let callbacks = source.callbacks.load(Ordering::Acquire);
            let epoch = AtomicU64::new(7);
            match boundary {
                1 => {
                    epoch.store(8, Ordering::Release);
                }
                2 => source.owner.retire().notify(),
                3 => f.cap.revoke(),
                4 => f.daemon.revoke(),
                5 => {
                    narf_net::iface::set_link_state(f.radio.name(), false);
                    narf_net::iface::set_link_state(f.radio.name(), true);
                }
                6 => {
                    crate::registry::unregister(f.radio.name());
                    crate::registry::register(f.iface.clone());
                }
                _ => {}
            }
            let result = prepared.deliver(RadioReceiveFence {
                epoch: &epoch,
                generation: 7,
                receiver: &guard,
                origin: &guard,
            });
            if result.is_ok() != (boundary == 0)
                || source.delivered.load(Ordering::Acquire) != u32::from(boundary == 0)
                || source.callbacks.load(Ordering::Acquire) != callbacks
            {
                return Err("prepared receive called a dynamic source, recaptured retirement or crossed native copy epoch");
            }
        }
        // Another valid current receiver must not retarget serialized metadata.
        let f = fixture()?;
        let other = fixture()?;
        f.radio.mode.store(2, Ordering::Release);
        other.radio.mode.store(2, Ordering::Release);
        let source = Arc::new(NativeSource::new());
        let a =
            RadioControlAuthority::bind(f.admin.clone(), &f.iface, 0, f.ifindex, source.clone())
                .map_err(|_| "first exact receiver")?;
        let b = RadioControlAuthority::bind(
            other.admin.clone(),
            &other.iface,
            0,
            other.ifindex,
            source.clone(),
        )
        .map_err(|_| "foreign exact receiver")?;
        let foreign = b
            .native_emission_for(other.radio.as_ref())
            .map_err(|_| "foreign fixed receiver")?;
        let event = a.event_authority().map_err(|_| "first event")?;
        let mut frame = alloc::vec![0;26];
        frame[0] = 0xd0;
        frame[24] = 4;
        let prepared = event
            .prepare_management_received(5180, None, &frame)
            .map_err(|_| "first serialized event")?;
        let epoch = AtomicU64::new(1);
        if prepared
            .deliver(RadioReceiveFence {
                epoch: &epoch,
                generation: 1,
                receiver: &foreign,
                origin: &foreign,
            })
            .is_ok()
            || source.delivered.load(Ordering::Acquire) != 0
        {
            return Err("another actual receiver retargeted prepared management event");
        }
        // A current guard from another socket on the same native receiver
        // cannot replace the serialized event's original source lifetime.
        let f = fixture()?;
        f.radio.mode.store(2, Ordering::Release);
        let source = Arc::new(NativeSource::new());
        let other = Arc::new(NativeSource::new());
        let a =
            RadioControlAuthority::bind(f.admin.clone(), &f.iface, 0, f.ifindex, source.clone())
                .map_err(|_| "original same-receiver source")?;
        let b = RadioControlAuthority::bind(f.admin.clone(), &f.iface, 0, f.ifindex, other)
            .map_err(|_| "other same-receiver source")?;
        let replacement = b
            .native_emission_for(f.radio.as_ref())
            .map_err(|_| "current replacement socket fence")?;
        let prepared = a
            .event_authority()
            .map_err(|_| "original event")?
            .prepare_management_received(5180, None, &frame)
            .map_err(|_| "original serialized event")?;
        source.owner.retire().notify();
        if prepared
            .deliver(RadioReceiveFence {
                epoch: &epoch,
                generation: 1,
                receiver: &replacement,
                origin: &replacement,
            })
            .is_ok()
            || source.delivery_attempts.load(Ordering::Acquire) != 0
        {
            return Err("same-receiver successor source bypassed original fixed lifetime");
        }
        Ok(())
    };
    check().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/ap_emission",
    prepared_radio_rx_checks_fixed_original_guards_and_epoch_after_source_callbacks
);
