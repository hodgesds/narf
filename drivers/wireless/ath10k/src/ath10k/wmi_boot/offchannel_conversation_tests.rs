//! Native ROC plus real netdev delegation and source-lifetime captures. Cases
//! author their own foreign/home events and management terminal indications.
use super::super::super::offchannel_native as native;
use super::*;
use core::{
    future::Future,
    sync::atomic::Ordering,
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, Invoke, Write};
use narf_net::netlink_generic::DeferredReplySink;
#[path = "offchannel_receive_conversation_tests.rs"]
mod receive;
use narf_wireless::{ap_control::RadioControlAuthority, MgmtTxRequest, WirelessNetIface};
#[derive(Debug)]
struct Source {
    live: narf_net::native_emission::ProviderLifetime,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
    callback: IrqSafeSpinLock<Option<Callback>>,
}
struct Callback(alloc::boxed::Box<dyn FnOnce() + Send>);
impl core::fmt::Debug for Callback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Callback").finish_non_exhaustive()
    }
}
impl Source {
    fn new() -> Self {
        Self {
            live: narf_net::native_emission::ProviderLifetime::new(),
            messages: IrqSafeSpinLock::new(Vec::new()),
            callback: IrqSafeSpinLock::new(None),
        }
    }
}
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        let callback = self.callback.lock().take();
        if let Some(callback) = callback {
            callback.0();
        }
        self.live.observe().current()
    }
    fn native_source(&self) -> Option<narf_net::native_emission::Lifetime> {
        Some(self.live.observe())
    }
    fn deliver(&self, b: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(125);
        }
        self.messages.lock().push(b);
        Ok(())
    }
}
struct Registered(Arc<ModelDevice>);
#[async_trait::async_trait]
impl WirelessNetIface for Registered {
    fn radio_control_generation(&self) -> Option<core::num::NonZeroU64> {
        self.0.radio_generation_for_test()
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn narf_wireless::ap_control::ApControlReservation>>, WirelessError>
    {
        self.0.reserve_control()
    }
    fn get_wireless_info(&self) -> narf_wireless::WirelessIfaceInfo {
        narf_wireless::WirelessIfaceInfo {
            base_name: self.0.name().into(),
            base_mac: self.0.mac(),
            bands: Vec::new(),
            modes: narf_wireless::iface::WirelessModes::STATION,
            hw_caps: narf_wireless::iface::HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }
    async fn scan(&self, _: ScanRequest) -> Result<Vec<narf_wireless::BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn set_config(&self, _: narf_wireless::WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
}

impl Interface for Registered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.0.link_up()
    }
    fn rx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<narf_ipc::Consumer<narf_net::Frame, { narf_net::RX_RING_N }>>>
    {
        self.0.rx_ring()
    }
    fn tx_ring(
        &self,
    ) -> &IrqSafeSpinLock<Option<narf_ipc::Producer<narf_net::Frame, { narf_net::TX_RING_N }>>>
    {
        self.0.tx_ring()
    }
}
struct Bound {
    iface: Arc<dyn WirelessNetIface>,
    cap: Cap<narf_net::NetIface, Write>,
    daemon: Cap<narf_net::stack::StackDaemon, Invoke>,
    admin: narf_net::AdminHandle,
    source: Arc<Source>,
    index: u32,
    name: String,
    subscriptions: Arc<radio::offchannel::Subscriptions>,
}
impl Bound {
    fn new(h: &Harness) -> Result<Self, &'static str> {
        let iface: Arc<dyn WirelessNetIface> = Arc::new(Registered(h.device.clone()));
        let cap = narf_net::registry()
            .register(
                &narf_net::bootstrap_authority(),
                Registered(h.device.clone()),
            )
            .map_err(|_| "ROC actual typed netdev registration")?;
        let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon,
        })
        .map_err(|_| "ROC actual delegated netdev admin")?
        .admin;
        narf_wireless::registry::register(iface.clone());
        let index = narf_net::iface::lookup(&h.name)
            .ok_or("ROC actual IFINDEX")?
            .ifindex;
        Ok(Self {
            iface,
            cap,
            daemon,
            admin,
            source: Arc::new(Source::new()),
            index,
            name: h.name.clone(),
            subscriptions: h.device.management_subscriptions_for_test(),
        })
    }
    fn authority(&self) -> Result<RadioControlAuthority, &'static str> {
        RadioControlAuthority::bind(
            self.admin.clone(),
            &self.iface,
            0,
            self.index,
            self.source.clone(),
        )
        .and_then(RadioControlAuthority::reserve)
        .map_err(|_| "ROC exact source/reservation binding")
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        narf_wireless::registry::unregister(&self.name);
        narf_net::registry().unregister_for_handle(&self.cap);
    }
}
fn harness(version: u32, dialect: Dialect, secured: bool, htt: bool) -> Harness {
    harness_version(version, dialect, secured, htt, (3, 1))
}
fn harness_version(
    version: u32,
    dialect: Dialect,
    secured: bool,
    htt: bool,
    firmware_version: (u8, u8),
) -> Harness {
    let hardware = if dialect == Dialect::Tlv {
        HwRev::Qca6174
    } else if dialect == Dialect::TenFour {
        HwRev::Qca9984
    } else {
        HwRev::Qca988x
    };
    let h = Harness::new_on_firmware(
        version,
        dialect,
        secured,
        false,
        2412,
        0x8348,
        NativeFirmware {
            ht: None,
            radio: RadioSource {
                hardware,
                rf_chains: 2,
                vht: None,
            },
            all_inventory: false,
            features: (1 << 10)
                | if htt {
                    0
                } else {
                    (1 << 2) | if dialect == Dialect::Tlv { 1 << 18 } else { 0 }
                },
            htt: firmware_version,
            hardware_keys: false,
            nlo: false,
        },
    );
    *h.policy.lock() = Some(five_ghz_policy());
    h
}
fn arm(h: &Harness, dialect: Dialect, associated: bool, transmit: bool) -> Arc<native::Signals> {
    let channels = h
        .device
        .radio
        .try_lock()
        .unwrap()
        .configured_channels()
        .to_vec();
    h.model(|m| {
        let fixture = native::Fixture::new(
            dialect,
            &channels,
            associated.then_some(2412),
            if associated { 2 } else { 1 },
            5180,
            500,
            transmit,
        );
        let signals = fixture.signals.clone();
        m.offchannel = Some(fixture);
        signals
    })
}
fn action() -> MgmtTxRequest {
    MgmtTxRequest {
        frequency_mhz: 5180,
        frame: native::frame(),
        offchannel_ok: true,
        duration: 0,
        no_cck: true,
    }
}
fn messages(b: &Bound, command: u8) -> usize {
    b.source
        .messages
        .lock()
        .iter()
        .filter(|m| m.get(16) == Some(&command))
        .count()
}
fn owner(
    b: &Bound,
    authority: &RadioControlAuthority,
) -> Result<radio::offchannel::Owner, &'static str> {
    Ok(radio::offchannel::Owner {
        emission: authority
            .native_emission_for(b.iface.as_ref())
            .map_err(|_| "actual fixed Radio source")?,
        event: authority
            .event_authority()
            .map_err(|_| "actual ROC event source")?,
        identity: authority
            .identity()
            .map_err(|_| "actual registered ROC identity")?,
    })
}
async fn acquire(
    h: &Harness,
    b: &Bound,
    authority: &RadioControlAuthority,
    cookie: u64,
    frequency: u16,
    duration: u32,
) -> Result<(), radio::Error> {
    let owner = owner(b, authority).map_err(|_| radio::Error::Failed)?;
    let receipt = radio::offchannel::Receipt {
        cookie,
        frequency,
        duration,
    };
    let mut r = h.device.radio.lock().await;
    r.bind_roc_subscriptions(b.subscriptions.clone())?;
    r.validate_roc_request(
        receipt,
        h.policy.lock().as_ref().ok_or(radio::Error::Unsupported)?,
    )?;
    r.begin_roc(owner.clone(), receipt, true, || {
        h.policy.lock().clone().ok_or(radio::Error::Unsupported)
    })
    .await?;
    if !r.roc_current(h.policy.lock().as_ref().ok_or(radio::Error::Unsupported)?)? {
        return Err(radio::Error::Failed);
    }
    drop(r);
    owner
        .event
        .roc_ready(cookie, u32::from(frequency), duration)
        .map_err(|_| radio::Error::Failed)
}
async fn service(h: &Harness, b: Option<&Bound>) -> Result<(), radio::Error> {
    let mut r = h.device.radio.lock().await;
    let notice = r
        .service_roc(
            false,
            || h.policy.lock().clone().ok_or(radio::Error::Unsupported),
            || Ok(()),
        )
        .await?;
    let copies = r.take_roc_captures();
    drop(r);
    if let Some(b) = b {
        for copy in copies {
            let Ok(event) = copy.prepare(b.iface.as_ref()) else {
                continue;
            };
            let domain = h.policy.lock().clone();
            if let Some(domain) = domain {
                let _ = copy.deliver(event, &domain);
            }
        }
    }
    if let Some((owner, receipt)) = notice {
        owner
            .event
            .roc_expired(
                receipt.cookie,
                u32::from(receipt.frequency),
                receipt.duration,
            )
            .map_err(|_| radio::Error::Failed)?;
    }
    Ok(())
}
async fn cancel_native(h: &Harness, b: &Bound, cookie: u64) -> Result<(), radio::Error> {
    h.device.radio.lock().await.roc_cancel(cookie)?;
    service(h, Some(b)).await
}
async fn action_native(
    h: &Harness,
    b: &Bound,
    a: &RadioControlAuthority,
    cookie: u64,
    request: MgmtTxRequest,
) -> Result<bool, radio::Error> {
    let emission = a
        .native_emission_for(b.iface.as_ref())
        .map_err(|_| radio::Error::Failed)?;
    let mut r = h.device.radio.lock().await;
    r.validate_roc_action(
        cookie,
        &request,
        &emission,
        h.policy.lock().as_ref().ok_or(radio::Error::Unsupported)?,
    )?;
    r.begin_roc_action(cookie, &request, emission.clone(), || {
        h.policy.lock().clone().ok_or(radio::Error::Unsupported)
    })
    .await?;
    drop(r);
    for _ in 0..65536 {
        if !emission.current() {
            return Err(radio::Error::Failed);
        }
        service(h, Some(b)).await?;
        if let Some(status) = h.device.radio.lock().await.take_roc_action_status(cookie)? {
            return Ok(status);
        }
        narf_scheduler::yield_now().await;
    }
    Err(radio::Error::Timeout)
}
fn start(h: &Harness, b: &Bound) -> Result<(), &'static str> {
    let authority = b.authority()?;
    if !matches!(
        drive(acquire(h, b, &authority, 71, 5180, 500)),
        Poll::Ready(Ok(()))
    ) {
        return Err("ROC native FOREIGN_CHANNEL acquisition");
    };
    if messages(b, 55) != 1 || messages(b, 56) != 0 {
        return Err("ROC READY before matching foreign or premature expiry");
    };
    Ok(())
}
fn cancel(h: &Harness, b: &Bound) -> Result<(), &'static str> {
    let a = b.authority()?;
    let owner = h
        .device
        .radio
        .try_lock()
        .unwrap()
        .roc_owner()
        .ok_or("retained ROC owner")?;
    a.check_identity(&owner.identity)
        .map_err(|_| "actual cancel source and retained identity")?;
    if !matches!(drive(cancel_native(h, b, 71)), Poll::Ready(Ok(()))) {
        return Err("ROC exact STOP/COMPLETE/home restoration");
    };
    if messages(b, 56) != 1 || h.device.radio.try_lock().unwrap().scan_in_progress() {
        return Err("ROC expiry before exact terminal/restore or interval leaked");
    };
    Ok(())
}
fn acquisition() -> Result<(), &'static str> {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        let h = harness(version, dialect, false, false);
        let b = Bound::new(&h)?;
        let signals = arm(&h, dialect, false, true);
        signals.foreign.store(false, Ordering::Release);
        let authority = b.authority()?;
        let mut pending = alloc::boxed::Box::pin(acquire(&h, &b, &authority, 71, 5180, 500));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..128 {
            if pending.as_mut().poll(&mut cx).is_ready() {
                return Err("ROC STARTED/wrong-frequency event invented READY");
            };
            if signals.started.load(Ordering::Acquire) {
                break;
            }
        }
        if !signals.started.load(Ordering::Acquire) || messages(&b, 55) != 0 {
            return Err("ROC held native start or source observation missing");
        }
        signals.foreign.store(true, Ordering::Release);
        if !matches!(drive(pending.as_mut()), Poll::Ready(Ok(()))) {
            return Err("matching foreign event did not complete ROC");
        };
        drop(pending);
        drop(authority);
        cancel(&h, &b)?;
        if !h.model(|m| m.offchannel.as_ref().unwrap().done) || h.device.link_up() {
            return Err("unassociated ROC invented a BSS or skipped passive restore");
        }
    }
    Ok(())
}
fn smoke_ath10k_roc_requires_exact_foreign_channel_all_six_dialects() -> TestResult {
    acquisition().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_roc_requires_exact_foreign_channel_all_six_dialects
);
fn associated() -> Result<(), &'static str> {
    for (version, dialect) in [(1, Dialect::Main), (4, Dialect::Tlv), (6, Dialect::TenFour)] {
        for secured in [false, true] {
            let h = harness(version, dialect, secured, false);
            h.join()?;
            let b = Bound::new(&h)?;
            arm(&h, dialect, true, true);
            start(&h, &b)?;
            let (packet, down) = packets();
            let before = h.model(|m| m.inner.storage.as_ref().unwrap().tx.pending());
            h.device
                .enqueue(&packet, narf_net::TxMeta::plain())
                .map_err(|_| "ROC retained host queue")?;
            h.device.drain();
            if h.model(|m| m.inner.storage.as_ref().unwrap().tx.pending()) != before {
                return Err("host DATA escaped during foreign dwell");
            }
            cancel(&h, &b)?;
            h.pump();
            if !h.device.link_up() {
                return Err("healthy ROC changed actual BSS/key owner");
            }
            let lease =
                narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "post-ROC native DHCP")?;
            if !network().matches_lease(&lease)
                || !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&packet))
            {
                return Err("post-ROC DHCP or retained native DATA changed");
            }
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                let frame = f.downlink(&down);
                f.queue.push_back(frame);
            });
            h.pump();
            if !h.received(&down) {
                return Err("post-ROC exact pairwise PN/key DATA not delivered");
            }
        }
    }
    Ok(())
}
fn smoke_ath10k_roc_associated_open_wpa2_keeps_data_until_terminal_home() -> TestResult {
    associated().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_roc_associated_open_wpa2_keeps_data_until_terminal_home
);
fn action_terminal() -> Result<(), &'static str> {
    for (version, dialect, htt, firmware_version, temporary) in [
        (1, Dialect::Main, true, (3, 1), true),
        (4, Dialect::Tlv, true, (3, 1), true),
        (4, Dialect::Tlv, true, (2, 1), true),
        (4, Dialect::Tlv, true, (3, 4), false),
        (4, Dialect::Tlv, false, (3, 1), true),
        (6, Dialect::TenFour, true, (3, 1), true),
    ] {
        for multicast in [false, true] {
            let h = harness_version(version, dialect, false, htt, firmware_version);
            let b = Bound::new(&h)?;
            let signals = arm(&h, dialect, false, true);
            signals.multicast.store(multicast, Ordering::Release);
            signals.terminal.store(false, Ordering::Release);
            start(&h, &b)?;
            let authority = b.authority()?;
            let mut request = action();
            if multicast {
                request.frame[4..10].fill(255);
            }
            let mut pending =
                alloc::boxed::Box::pin(action_native(&h, &b, &authority, 91, request));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..512 {
                if pending.as_mut().poll(&mut cx).is_ready() {
                    return Err("CE/TX publication invented native action ACK");
                };
                if signals.descriptors.load(Ordering::Acquire) != 0 {
                    break;
                }
            }
            if signals.descriptors.load(Ordering::Acquire) != 1
                || signals.deletes.load(Ordering::Acquire) != 0
            {
                return Err("action descriptor/native temporary peer ownership missing");
            }
            signals.terminal.store(true, Ordering::Release);
            if !matches!(drive(pending.as_mut()), Poll::Ready(Ok(status)) if status != multicast) {
                return Err("exact native action completion did not publish ACK");
            };
            drop(pending);
            drop(authority);
            if signals.deletes.load(Ordering::Acquire) != u32::from(temporary) {
                return Err("action DA peer not deleted after actual native terminal");
            }
            cancel(&h, &b)?;
        }
    }
    Ok(())
}
fn smoke_ath10k_roc_action_htt_reference_ack_requires_terminal_before_peer_delete() -> TestResult {
    action_terminal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_roc_action_htt_reference_ack_requires_terminal_before_peer_delete
);
fn cancellation() -> Result<(), &'static str> {
    let h = harness(1, Dialect::Main, false, true);
    let b = Bound::new(&h)?;
    let signals = arm(&h, Dialect::Main, false, true);
    start(&h, &b)?;
    signals.stop_receipt.store(false, Ordering::Release);
    let authority = b.authority()?;
    let mut pending = alloc::boxed::Box::pin(cancel_native(&h, &b, 71));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..128 {
        if pending.as_mut().poll(&mut cx).is_ready() {
            return Err("STOP command/CE progress invented ROC terminal");
        }
    }
    if messages(&b, 56) != 0 {
        return Err("ROC expiry preceded matching scan/home terminal");
    }
    signals.stop_receipt.store(true, Ordering::Release);
    if !matches!(drive(pending.as_mut()), Poll::Ready(Ok(()))) {
        return Err("retained cancel did not observe its exact terminal");
    };
    drop(pending);
    drop(authority);
    // An elapsed host interval also requests STOP; it still waits for the
    // actual native terminal before sending EXPIRED and restoring inventory.
    let h = harness(1, Dialect::Main, false, true);
    let b = Bound::new(&h)?;
    let signals = arm(&h, Dialect::Main, false, true);
    start(&h, &b)?;
    signals.stop_receipt.store(false, Ordering::Release);
    h.device
        .radio
        .try_lock()
        .unwrap()
        .expire_roc_for_test()
        .map_err(|_| "actual granted ROC deadline")?;
    let mut pending = alloc::boxed::Box::pin(service(&h, Some(&b)));
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..128 {
        if pending.as_mut().poll(&mut cx).is_ready() {
            return Err("host ROC timer invented firmware terminal");
        }
    }
    if messages(&b, 56) != 0 {
        return Err("host ROC timer published early EXPIRED");
    }
    signals.stop_receipt.store(true, Ordering::Release);
    if !matches!(drive(pending.as_mut()), Poll::Ready(Ok(()))) || messages(&b, 56) != 1 {
        return Err("expired ROC did not finish exact native stop and restore");
    }
    Ok(())
}
fn smoke_ath10k_roc_cancel_waits_for_matching_terminal_and_restore() -> TestResult {
    cancellation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_roc_cancel_waits_for_matching_terminal_and_restore
);
fn revocation() -> Result<(), &'static str> {
    for boundary in 0..4 {
        let h = harness(1, Dialect::Main, false, true);
        let b = Bound::new(&h)?;
        arm(&h, Dialect::Main, false, true);
        start(&h, &b)?;
        match boundary {
            0 => b.source.live.retire().notify(),
            1 => b.cap.revoke(),
            2 => b.daemon.revoke(),
            _ => {
                h.policy.lock().as_mut().unwrap().rules[1].flags =
                    narf_wireless::reg::RegFlags::NO_IR;
            }
        }
        if !matches!(drive(service(&h, Some(&b))), Poll::Ready(Ok(())))
            || h.device.radio.try_lock().unwrap().scan_in_progress()
            || messages(&b, 56) != 0
            || messages(&b, 55) != 1
        {
            return Err(
                "lost ROC source/policy did not retain STOP/terminal or published stale expiry",
            );
        }
        let before = h.model(|m| m.sent.len());
        if b.authority().is_ok_and(|a| {
            matches!(
                drive(action_native(&h, &b, &a, 91, action())),
                Poll::Ready(Ok(_))
            )
        }) || h.model(|m| m.sent.len()) != before
        {
            return Err("revoked/restored ROC source reached a later action descriptor");
        }
    }
    Ok(())
}
fn smoke_ath10k_roc_source_cap_daemon_and_policy_loss_stop_without_late_status() -> TestResult {
    revocation().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_roc_source_cap_daemon_and_policy_loss_stop_without_late_status
);
fn refusals() -> Result<(), &'static str> {
    let h = harness(1, Dialect::Main, false, false);
    let b = Bound::new(&h)?;
    let before = h.model(|m| m.sent.len());
    for (cookie, frequency, duration) in
        [(0, 5180, 100), (1, 5180, 0), (1, 5180, 501), (1, 5500, 100)]
    {
        let a = b.authority()?;
        if matches!(
            drive(acquire(&h, &b, &a, cookie, frequency, duration)),
            Poll::Ready(Ok(()))
        ) {
            return Err("invalid/DFS ROC reached native acquisition");
        }
    }
    if h.model(|m| m.sent.len()) != before || h.device.radio.try_lock().unwrap().scan_in_progress()
    {
        return Err("pure invalid ROC mutated native scan ownership");
    }
    arm(&h, Dialect::Main, false, true);
    start(&h, &b)?;
    let a = b.authority()?;
    let before = h.model(|m| m.sent.len());
    if matches!(
        drive(action_native(&h, &b, &a, 91, action())),
        Poll::Ready(Ok(_))
    ) || h.model(|m| m.sent.len()) != before
    {
        return Err("inline WMI transport invented action air terminal/ACK");
    }
    drop(a);
    cancel(&h, &b)?;
    let h = harness(1, Dialect::Main, false, true);
    let b = Bound::new(&h)?;
    h.policy.lock().as_mut().unwrap().rules[1].flags = narf_wireless::reg::RegFlags::NO_IR;
    arm(&h, Dialect::Main, false, false);
    start(&h, &b)?;
    let a = b.authority()?;
    let before = h.model(|m| m.sent.len());
    if matches!(
        drive(action_native(&h, &b, &a, 91, action())),
        Poll::Ready(Ok(_))
    ) || h.model(|m| m.sent.len()) != before
    {
        return Err("receive-only ROC upgraded itself to TX power/peer authority");
    }
    drop(a);
    cancel(&h, &b)?;
    Ok(())
}
fn smoke_ath10k_roc_pure_bounds_inline_tx_and_passive_channel_never_invent_authority() -> TestResult
{
    refusals().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_roc_pure_bounds_inline_tx_and_passive_channel_never_invent_authority
);
