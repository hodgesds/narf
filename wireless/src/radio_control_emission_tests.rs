//! Exact control-WDEV/native-source fences; no hardware/RF receipt is claimed.
use super::*;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_capabilities::Write;
struct WakeCount(AtomicU32);
impl alloc::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct NativeSource {
    owner: narf_net::native_emission::ProviderLifetime,
    callbacks: AtomicU32,
    attempts: AtomicU32,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
    epoch: AtomicU64,
    advance: AtomicBool,
}
impl NativeSource {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            owner: narf_net::native_emission::ProviderLifetime::new(),
            callbacks: AtomicU32::new(0),
            attempts: AtomicU32::new(0),
            messages: IrqSafeSpinLock::new(Vec::new()),
            epoch: AtomicU64::new(1),
            advance: AtomicBool::new(false),
        })
    }
}
impl DeferredReplySink for NativeSource {
    fn current(&self) -> bool {
        self.callbacks.fetch_add(1, Ordering::AcqRel);
        if self.advance.swap(false, Ordering::AcqRel) {
            self.epoch.fetch_add(1, Ordering::AcqRel);
        }
        self.owner.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.owner.observe())
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if !self.owner.observe().current() {
            return Err(125);
        }
        self.messages.lock().push(message);
        Ok(())
    }
}
struct Control {
    inner: Radio,
    physical: u64,
}
impl Interface for Control {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        Some(0)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.inner.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.inner.tx
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for Control {
    fn wiphy_id(&self) -> u64 {
        self.physical
    }
    fn current_iftype(&self) -> u32 {
        self.inner.mode.load(Ordering::Acquire)
    }
    fn radio_control_generation(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.inner.generation.load(Ordering::Acquire))
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        self.inner.get_wireless_info()
    }
    async fn scan(&self, _: crate::ScanRequest) -> Result<Vec<crate::BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}
struct RegisteredControl(Arc<Control>);
impl Interface for RegisteredControl {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        0
    }
    fn link_up(&self) -> bool {
        false
    }
    fn control_namespace(&self) -> Option<u64> {
        Some(0)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
struct Child {
    radio: Arc<Control>,
    iface: Arc<dyn WirelessNetIface>,
    cap: Cap<narf_net::NetIface, Write>,
    registration: crate::registry::ControlWdev,
    admin: AdminHandle,
}
impl Child {
    fn new(parent: &Fixture) -> Result<Self, &'static str> {
        static NEXT: AtomicU32 = AtomicU32::new(1);
        let inner = Radio::new(alloc::format!(
            "native-wdev-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        inner.mode.store(10, Ordering::Release);
        let radio = Arc::new(Control {
            inner,
            physical: parent.iface.wiphy_id(),
        });
        let iface: Arc<dyn WirelessNetIface> = radio.clone();
        let cap = narf_net::registry()
            .register_control_child(
                &narf_net::bootstrap_authority(),
                &parent.cap,
                RegisteredControl(radio.clone()),
            )
            .map_err(|_| "native WDEV actual typed parent-child pair")?;
        let registration = match crate::registry::register_control(&parent.iface, iface.clone()) {
            Ok(registration) => registration,
            Err(_) => {
                narf_net::registry().unregister_for_handle(&cap);
                return Err("native WDEV actual wireless parent-child pair");
            }
        };
        let admin = parent
            .admin
            .control_registered_child(&cap)
            .map_err(|_| "native WDEV original child delegation")?
            .ok_or("native WDEV missing delegated source")?;
        Ok(Self {
            radio,
            iface,
            cap,
            registration,
            admin,
        })
    }
    fn bind(
        &self,
        source: Arc<dyn DeferredReplySink>,
    ) -> Result<RadioControlAuthority, &'static str> {
        RadioControlAuthority::bind_wdev(
            self.admin.clone(),
            &self.iface,
            0,
            self.registration.id(),
            source,
        )
        .map_err(|_| "native WDEV original source binding")
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        crate::registry::unregister_control(self.registration, self.radio.as_ref());
        narf_net::registry().unregister_for_handle(&self.cap);
    }
}
fn control_fences() -> Result<(), &'static str> {
    for boundary in 0..10 {
        let parent = fixture()?;
        parent
            .admin
            .set_link(false)
            .map_err(|_| "actual parent DOWN")?;
        let mut child = Child::new(&parent)?;
        if child
            .bind(parent.source.clone())?
            .native_control_emission_for(child.radio.as_ref(), &child.cap)
            .is_ok()
        {
            return Err("unknown source provider armed a control-WDEV native fence");
        }
        let source = NativeSource::new();
        let authority = child.bind(source.clone())?;
        let guard = authority
            .native_control_emission_for(child.radio.as_ref(), &child.cap)
            .map_err(|_| "actual control-WDEV fixed native capture")?;
        let generation = NonZeroU64::new(1).unwrap();
        if !guard.matches_mode(child.radio.as_ref(), 10, generation)
            || guard.matches_role(child.radio.as_ref(), generation)
            || guard.matches_mode(child.radio.as_ref(), 8, generation)
            || authority.native_emission_for(child.radio.as_ref()).is_ok()
            || authority
                .native_control_emission_for(child.radio.as_ref(), &parent.cap)
                .is_ok()
            || narf_net::iface::lookup(child.radio.name()).is_some()
        {
            return Err("control proof lost exact role/cap or fabricated a netdev");
        }
        let wakes = Arc::new(WakeCount(AtomicU32::new(0)));
        if !guard.watch(&Waker::from(wakes.clone())) {
            return Err("actual WDEV proof could not watch its retained cleanup owner");
        }
        let callbacks = source.callbacks.load(Ordering::Acquire);
        let ready = AtomicBool::new(false);
        let publications = AtomicU32::new(0);
        let mut held = Box::pin(core::future::poll_fn(|_| {
            if !ready.load(Ordering::Acquire) {
                return Poll::Pending;
            }
            let current =
                NonZeroU64::new(child.radio.inner.generation.load(Ordering::Acquire)).ok_or(())?;
            if !guard.matches_mode(child.radio.as_ref(), 10, current) {
                return Poll::Ready(Err(()));
            }
            publications.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(Ok(()))
        }));
        let mut cx = Context::from_waker(Waker::noop());
        if held.as_mut().poll(&mut cx).is_ready() {
            return Err("control-WDEV publication fixture did not hold its wait");
        }
        match boundary {
            0 => source.owner.retire().notify(),
            1 => parent.daemon.revoke(),
            2 => parent.cap.revoke(),
            3 => child.cap.revoke(),
            4 => crate::registry::unregister(parent.iface.name()),
            5 => {
                crate::registry::unregister_control(child.registration, child.radio.as_ref());
                child.registration =
                    crate::registry::register_control(&parent.iface, child.iface.clone())
                        .map_err(|_| "same receiver wireless WDEV replacement")?;
            }
            6 => {
                parent
                    .admin
                    .move_to_net_ns(27)
                    .map_err(|_| "native parent move")?;
                parent
                    .admin
                    .move_to_net_ns(0)
                    .map_err(|_| "native parent return")?;
            }
            7 => {
                narf_net::iface::register(child.radio.name(), child.radio.mac(), reject);
                narf_net::iface::unregister(child.radio.name());
            }
            8 => {
                child.radio.inner.generation.fetch_add(1, Ordering::AcqRel);
            }
            _ => {
                narf_net::registry().unregister_for_handle(&child.cap);
            }
        }
        ready.store(true, Ordering::Release);
        if held.as_mut().poll(&mut cx) != Poll::Ready(Err(()))
            || publications.load(Ordering::Acquire) != 0
            || source.callbacks.load(Ordering::Acquire) != callbacks
        {
            return Err(
                "held control emission survived retirement or called full source under State",
            );
        }
        if boundary == 0 && wakes.0.load(Ordering::Acquire) != 1 {
            return Err("source closure did not wake the original WDEV cleanup owner");
        }
    }
    Ok(())
}
fn control_wdev_native_fence_keeps_original_source_caps_registration_and_role_after_waits(
) -> TestResult {
    control_fences().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    control_wdev_native_fence_keeps_original_source_caps_registration_and_role_after_waits
);

fn prepared_events() -> Result<(), &'static str> {
    let parent = fixture()?;
    parent
        .admin
        .set_link(false)
        .map_err(|_| "prepared parent DOWN")?;
    let child = Child::new(&parent)?;
    let source = NativeSource::new();
    let authority = child.bind(source.clone())?;
    let guard = authority
        .native_control_emission_for(child.radio.as_ref(), &child.cap)
        .map_err(|_| "prepared actual WDEV proof")?;
    let event = authority
        .event_authority()
        .map_err(|_| "original WDEV event")?;
    let frame = [0xd0; 24];
    source.advance.store(true, Ordering::Release);
    let prepared = event
        .prepare_control_management_received(&child.cap, 2412, Some(-40), &frame)
        .map_err(|_| "prepare WDEV bytes outside State")?;
    let callbacks = source.callbacks.load(Ordering::Acquire);
    if prepared.deliver(RadioReceiveFence {
        epoch: &source.epoch,
        generation: 1,
        receiver: &guard,
        origin: &guard,
    }) != Err(WirelessError::Denied)
        || source.attempts.load(Ordering::Acquire) != 0
        || source.callbacks.load(Ordering::Acquire) != callbacks
    {
        return Err("reentrant source callback relabelled an old control RX copy");
    }
    let other = Child::new(&parent)?;
    let foreign = other
        .bind(source.clone())?
        .native_control_emission_for(other.radio.as_ref(), &other.cap)
        .map_err(|_| "other actual WDEV native proof")?;
    let epoch = source.epoch.load(Ordering::Acquire);
    let wrong_receiver = event
        .prepare_control_management_received(&child.cap, 2412, Some(-40), &frame)
        .map_err(|_| "prepare original WDEV for foreign-receiver negative")?;
    if wrong_receiver.deliver(RadioReceiveFence {
        epoch: &source.epoch,
        generation: epoch,
        receiver: &foreign,
        origin: &guard,
    }) != Err(WirelessError::Denied)
        || source.attempts.load(Ordering::Acquire) != 0
    {
        return Err("another live same-MAC WDEV replaced the original native receiver");
    }
    let received = event
        .prepare_control_management_received(&child.cap, 2412, Some(-40), &frame)
        .map_err(|_| "prepare current WDEV management bytes")?;
    let callbacks = source.callbacks.load(Ordering::Acquire);
    received
        .deliver(RadioReceiveFence {
            epoch: &source.epoch,
            generation: epoch,
            receiver: &guard,
            origin: &guard,
        })
        .map_err(|_| "current fixed WDEV management delivery")?;
    if source.callbacks.load(Ordering::Acquire) != callbacks {
        return Err("management final delivery called the arbitrary current source");
    }
    let ready = event
        .prepare_roc_ready(&guard, 7, 2412, 100)
        .map_err(|_| "prepare actual READY bytes")?;
    let callbacks = source.callbacks.load(Ordering::Acquire);
    ready
        .deliver(RadioReceiveFence {
            epoch: &source.epoch,
            generation: epoch,
            receiver: &guard,
            origin: &guard,
        })
        .map_err(|_| "current fixed READY delivery")?;
    if source.callbacks.load(Ordering::Acquire) != callbacks {
        return Err("READY final fixed delivery called the arbitrary source");
    }
    let old = source.epoch.load(Ordering::Acquire);
    source.advance.store(true, Ordering::Release);
    let expired = event
        .prepare_roc_expired(&guard, 7, 2412, 100)
        .map_err(|_| "prepare reentrant EXPIRED bytes")?;
    if expired.deliver(RadioReceiveFence {
        epoch: &source.epoch,
        generation: old,
        receiver: &guard,
        origin: &guard,
    }) != Err(WirelessError::Denied)
    {
        return Err("reentrant callback published a retired ROC epoch");
    }
    let epoch = source.epoch.load(Ordering::Acquire);
    event
        .prepare_roc_expired(&guard, 7, 2412, 100)
        .map_err(|_| "prepare current EXPIRED bytes")?
        .deliver(RadioReceiveFence {
            epoch: &source.epoch,
            generation: epoch,
            receiver: &guard,
            origin: &guard,
        })
        .map_err(|_| "current fixed EXPIRED delivery")?;
    let messages = source.messages.lock();
    if messages
        .iter()
        .map(|message| message[16])
        .collect::<Vec<_>>()
        != [59, 55, 56]
    {
        return Err("control event fixtures lost management/READY/EXPIRED order");
    }
    for bytes in messages.iter() {
        let mut at = 20;
        let mut wdev = false;
        while at < bytes.len() {
            let len = usize::from(u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap()));
            let kind = u16::from_ne_bytes(bytes[at + 2..at + 4].try_into().unwrap());
            if kind == 3 {
                return Err("control-WDEV event invented an IFINDEX attribute");
            }
            if kind == 153 {
                wdev = bytes[at + 4..at + len] == child.registration.id().to_ne_bytes();
            }
            at += (len + 3) & !3;
        }
        if !wdev {
            return Err("control-WDEV event lost its actual registered WDEV id");
        }
    }
    Ok(())
}
fn control_wdev_prepared_management_and_roc_events_keep_original_epoch_without_callbacks(
) -> TestResult {
    prepared_events().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    control_wdev_prepared_management_and_roc_events_keep_original_epoch_without_callbacks
);

fn netdev_modes() -> Result<(), &'static str> {
    for mode in [8, 9] {
        let parent = fixture()?;
        parent.radio.mode.store(mode, Ordering::Release);
        let source = NativeSource::new();
        let authority = RadioControlAuthority::bind(
            parent.admin.clone(),
            &parent.iface,
            0,
            parent.ifindex,
            source.clone(),
        )
        .map_err(|_| "P2P netdev Radio authority")?;
        let guard = authority
            .native_emission_for(parent.radio.as_ref())
            .map_err(|_| "P2P netdev actual UP proof")?;
        let generation = NonZeroU64::new(1).unwrap();
        if !guard.matches_mode(parent.radio.as_ref(), mode, generation)
            || guard.matches_role(parent.radio.as_ref(), generation)
            || guard.matches_mode(parent.radio.as_ref(), 10, generation)
        {
            return Err("P2P real netdev proof lost its exact original mode");
        }
        parent
            .admin
            .set_link(false)
            .map_err(|_| "P2P netdev actual DOWN")?;
        if guard.current() || authority.native_emission_for(parent.radio.as_ref()).is_ok() {
            return Err("P2P client/GO netdev inherited control-only no-UP semantics");
        }
    }
    Ok(())
}
fn p2p_netdev_native_fences_keep_exact_modes_and_real_up_requirement() -> TestResult {
    netdev_modes().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    p2p_netdev_native_fences_keep_exact_modes_and_real_up_requirement
);
