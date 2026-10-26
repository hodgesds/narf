//! Actual retained Device → native CE/HTT/Supplicant → kernel DHCP/IP.
//! Only the firmware/AP and physical DMA register interface are models.
use super::*;
use crate::ath10k::interface::Device;
use alloc::{string::String, sync::Arc};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_net::Interface;
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessError};
type ModelDevice = Device<RadioModel>;
static ACTIVE_TEST: IrqSafeSpinLock<Option<Arc<ModelDevice>>> = IrqSafeSpinLock::new(None);
fn send(generation: u64, bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_TEST.lock().clone().ok_or(())?;
    device.enqueue_generation(generation, bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE_TEST.lock().clone();
    device.is_some_and(|device| device.drain())
}
struct Harness {
    device: Arc<ModelDevice>,
    policy: Arc<IrqSafeSpinLock<Option<narf_wireless::reg::RegulatoryDomain>>>,
    name: String,
    secured: bool,
    active_scan: bool,
}
impl Harness {
    fn new(version: u32, dialect: Dialect, secured: bool) -> Self {
        Self::new_scan(version, dialect, secured, false)
    }
    fn new_scan(version: u32, dialect: Dialect, secured: bool, active_scan: bool) -> Self {
        let mut radio = radio_boot_features(
            version,
            dialect,
            (1 << 10) | (1 << 2) | if dialect == Dialect::Tlv { 1 << 18 } else { 0 },
        );
        if active_scan {
            let mut fixture = super::super::active_scan_tests::Fixture::directed(1);
            fixture.extra_ies = super::super::active_scan_tests::PROBE_IES.to_vec();
            radio.htt.wmi.htc.transport.active = Some(fixture);
        }
        assert!(matches!(
            drive(radio.start(if active_scan {
                &[2412, 2437, 5180]
            } else {
                &[2412, 5180]
            })),
            Poll::Ready(Ok(_))
        ));
        let m = &mut radio.htt.wmi.htc.transport;
        let mut fixture = Fixture::new(secured);
        fixture.automatic = true;
        m.data = Some(fixture);
        let hardware = if dialect == Dialect::Tlv {
            HwRev::Qca6174
        } else if dialect == Dialect::TenFour {
            HwRev::Qca9984
        } else {
            HwRev::Qca988x
        };
        m.ce = Some(crate::ath10k::boot::CeFixture::new(hardware));
        let name = String::from(narf_net::iface::reserve_name("wlan%d"));
        let policy = Arc::new(IrqSafeSpinLock::new(Some(station_tests::policy())));
        let current = policy.clone();
        let device = Arc::new(Device::for_test(
            &name,
            OWN,
            Arc::new(Mutex::new(radio)),
            move || current.lock().clone(),
        ));
        narf_net::iface::register_with_context(&name, OWN, device.generation_for_test(), send);
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::set_link_state(&name, true); // operator IFF_UP
        narf_net::iface::set_link_metadata(&name, false, None, None);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Self {
            device,
            policy,
            name,
            secured,
            active_scan,
        }
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: b"narf".to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            security: if self.secured {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }
    fn scan(&self) -> Result<(), &'static str> {
        let Poll::Ready(Ok(bss)) = drive(self.device.scan(ScanRequest {
            ssids: vec![b"narf".to_vec()],
            frequencies_mhz: if self.active_scan {
                vec![2412, 2437]
            } else {
                vec![2412]
            },
            channels: if self.active_scan {
                vec![1, 6]
            } else {
                vec![1]
            },
            active: self.active_scan,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: if self.active_scan {
                super::super::active_scan_tests::PROBE_IES.to_vec()
            } else {
                Vec::new()
            },
        })) else {
            return Err("retained Device native scan failed");
        };
        if bss.len() != 1 || bss[0].bssid != AP || bss[0].frequency_mhz != 2412 {
            return Err("retained Device scan identity");
        }
        Ok(())
    }
    fn join(&self) -> Result<(), &'static str> {
        self.scan()?;
        if !matches!(
            drive(self.device.associate_for_test(self.request(), [0x73; 32])),
            Poll::Ready(Ok(()))
        ) {
            return Err("native Device management/early-M1/RSNA failed");
        }
        if !self.device.link_up()
            || narf_net::iface::lookup(&self.name).is_none_or(|i| {
                !i.link_up || !i.carrier || i.carrier_up_count != 1 || i.carrier_down_count != 0
            })
        {
            return Err("real Device carrier did not follow exact authorization");
        }
        narf_net::iface::set_link_state(&self.name, false);
        self.device.drain();
        if narf_net::iface::lookup(&self.name).is_none_or(|i| i.link_up || !i.carrier) {
            return Err("native Device physical carrier overwrote operator DOWN");
        }
        narf_net::iface::set_link_state(&self.name, true);
        Ok(())
    }
    fn pump(&self) {
        for _ in 0..12 {
            self.device.drain();
        }
    }
    fn model<R>(&self, operation: impl FnOnce(&mut RadioModel) -> R) -> R {
        let mut r = self.device.radio.try_lock().unwrap();
        operation(&mut r.htt.wmi.htc.transport)
    }
    fn closed(&self) -> bool {
        !self.device.link_up()
            && narf_net::iface::lookup(&self.name).is_some_and(|i| {
                !i.carrier && i.link_up && i.carrier_up_count == 1 && i.carrier_down_count == 1
            })
    }
    fn received(&self, expected: &[u8]) -> bool {
        let mut rx = self.device.rx_ring().lock();
        let Some(rx) = rx.as_mut() else {
            return false;
        };
        for _ in 0..narf_net::RX_RING_N {
            let Ok(Some(frame)) = rx.try_recv() else {
                break;
            };
            if frame.payload() == expected {
                return true;
            }
        }
        false
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_TEST.lock() = None;
        narf_net::iface::set_link_state(&self.name, false);
        narf_net::iface::set_link_metadata(&self.name, false, None, None);
        narf_net::iface::unregister(&self.name);
    }
}
fn composition(version: u32, dialect: Dialect, secured: bool) -> Result<(), &'static str> {
    composition_scan(version, dialect, secured, false)
}

fn smoke_ath10k_recovery_generation_rejects_stale_net_snapshot_and_old_device() -> TestResult {
    for (version, dialect) in [(1, Dialect::Main), (4, Dialect::Tlv)] {
        for secured in [false, true] {
            let old = Harness::new(version, dialect, secured);
            if let Err(error) = old.join() {
                return TestResult::Fail(error);
            }
            let snapshot = narf_net::iface::lookup(&old.name).unwrap();
            old.device.retire_host();
            let new = Harness::new(version, dialect, secured);
            if let Err(error) = new.join() {
                return TestResult::Fail(error);
            }
            let (uplink, _) = packets();
            let before = new.model(|model| model.sent.len());
            if old.name == new.name
                || old.device.generation_for_test() == new.device.generation_for_test()
                || snapshot.xmit(&uplink).is_ok()
                || old
                    .device
                    .enqueue(&uplink, narf_net::TxMeta::plain())
                    .is_ok()
                || new.model(|model| model.sent.len()) != before
            {
                return TestResult::Fail("old interface generation admitted TX into replacement");
            }
            // Repeated late old-owner closure must not flap the new carrier.
            old.device.close_before_lock_for_test();
            if !new.device.link_up()
                || !narf_net::iface::lookup(&new.name).unwrap().carrier
                || narf_net::iface::lookup(&new.name)
                    .unwrap()
                    .xmit(&uplink)
                    .is_err()
            {
                return TestResult::Fail("retired owner closed replacement or rejected fresh TX");
            }
            new.device.drain();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_generation_rejects_stale_net_snapshot_and_old_device
);

fn retire_model(radio: &Arc<Mutex<radio::Radio<RadioModel>>>) {
    let mut active = ACTIVE_TEST.lock();
    let Some(device) = active
        .as_ref()
        .filter(|device| Arc::ptr_eq(&device.radio, radio))
        .cloned()
    else {
        return;
    };
    *active = None;
    drop(active);
    device.retire_host();
}
fn smoke_ath10k_recovery_cancelled_mutex_wait_keeps_host_generation_closed() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    if let Err(error) = h.join() {
        return TestResult::Fail(error);
    }
    let radio = h.device.radio.clone();
    let held = radio.try_lock().unwrap();
    let before = held.htt.wmi.htc.transport.sent.len();
    let quarantine = core::sync::atomic::AtomicBool::new(false);
    if !drive(crate::ath10k::pci::retire_radio(
        &radio,
        &quarantine,
        || retire_model(&radio),
    ))
    .is_pending()
        || !quarantine.load(core::sync::atomic::Ordering::Acquire)
        || h.device.link_up()
        || narf_net::iface::lookup(&h.name).is_some()
        || held.htt.wmi.htc.transport.sent.len() != before
        || held
            .htt
            .wmi
            .htc
            .transport
            .inner
            .storage
            .as_ref()
            .unwrap()
            .filled
            != 1023
        || held.htt.wmi.htc.transport.inner.inner.retained.is_none()
    {
        return TestResult::Fail("cancelled reset wait reopened host or touched/released live DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_cancelled_mutex_wait_keeps_host_generation_closed
);

fn smoke_ath10k_recovery_fences_publication_between_first_close_and_radio_lock() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, false);
    if let Err(error) = h.join() {
        return TestResult::Fail(error);
    }
    let radio = h.device.radio.clone();
    let held = radio.try_lock().unwrap();
    *ACTIVE_TEST.lock() = None; // Old publication is still behind the Radio lock.
    let quarantine = core::sync::atomic::AtomicBool::new(false);
    {
        let mut future = core::pin::pin!(crate::ath10k::pci::retire_radio(
            &radio,
            &quarantine,
            || retire_model(&radio)
        ));
        let mut cx = Context::from_waker(Waker::noop());
        if !future.as_mut().poll(&mut cx).is_pending() {
            return TestResult::Fail("reset did not wait for old publication owner");
        }
        *ACTIVE_TEST.lock() = Some(h.device.clone()); // Real old Device becomes visible.
        drop(held);
        if !matches!(drive(future.as_mut()), Poll::Ready(_)) {
            return TestResult::Fail("reset did not acquire released old publication owner");
        }
    }
    let (uplink, _) = packets();
    if !quarantine.load(core::sync::atomic::Ordering::Acquire)
        || ACTIVE_TEST.lock().is_some()
        || h.device.link_up()
        || narf_net::iface::lookup(&h.name).is_some()
        || h.device.enqueue(&uplink, narf_net::TxMeta::plain()).is_ok()
        || radio.try_lock().unwrap().station_link().is_some()
    {
        return TestResult::Fail("late old publication escaped second under-lock retirement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_fences_publication_between_first_close_and_radio_lock
);
fn smoke_ath10k_recovery_cancelled_missing_publication_cannot_publish_late() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, false);
    let radio = h.device.radio.clone();
    let held = radio.try_lock().unwrap();
    if held.station_publishable().is_err() {
        return TestResult::Fail("late-publication fixture was not otherwise publishable");
    }
    *ACTIVE_TEST.lock() = None;
    narf_net::iface::unregister(&h.name);
    let quarantine = core::sync::atomic::AtomicBool::new(false);
    if !drive(crate::ath10k::pci::retire_radio(
        &radio,
        &quarantine,
        || retire_model(&radio),
    ))
    .is_pending()
    {
        return TestResult::Fail("late-publication cancellation fixture did not suspend");
    }
    // The actual production publication gate runs under ACTIVE, before any
    // registration writes. The owner remains publishable while its mutex is
    // held, so only the persistent retirement token may block this transaction.
    let mut active = ACTIVE_TEST.lock();
    let result = crate::ath10k::interface::admit_generation(&quarantine, || {
        narf_net::iface::register_with_context(&h.name, OWN, h.device.generation_for_test(), send);
        *active = Some(h.device.clone());
        Ok(())
    });
    if result != Err(radio::Error::Failed)
        || active.is_some()
        || narf_net::iface::lookup(&h.name).is_some()
        || held.station_publishable().is_err()
        || held.htt.wmi.htc.transport.inner.inner.retained.is_none()
    {
        return TestResult::Fail(
            "cancelled reset missed initial ACTIVE and allowed old publication",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_cancelled_missing_publication_cannot_publish_late
);

fn smoke_ath10k_power_save_native_six_dialects_open_wpa2_dhcp_ip() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        for secured in [false, true] {
            if let Err(error) = composition_options(version, dialect, secured, false, true) {
                return TestResult::Fail(error);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/power-save",
    smoke_ath10k_power_save_native_six_dialects_open_wpa2_dhcp_ip
);

fn smoke_ath10k_power_save_each_cancelled_publication_closes_and_retains_dma() -> TestResult {
    for step in 0..6 {
        let h = Harness::new(4, Dialect::Tlv, true);
        if let Err(error) = h.join() {
            return TestResult::Fail(error);
        }
        let hold = Arc::new(core::sync::atomic::AtomicBool::new(true));
        h.model(|model| {
            let mut ps = super::super::power_save_tests::Fixture::new(Dialect::Tlv, true);
            ps.hold = Some((step, hold.clone()));
            model.ps = Some(ps);
        });
        h.device.request_power_save(true).unwrap();
        if !drive(h.device.apply_power_save()).is_pending()
            || !h.closed()
            || h.device.request_power_save(false) != Err(-19)
            || !h.model(|model| {
                model.inner.storage.as_ref().unwrap().filled == 1023
                    && model.inner.inner.retained.is_some()
            })
        {
            return TestResult::Fail(
                "cancelled PS control reopened host or released uncertain DMA",
            );
        }
        let before = h.model(|model| model.sent.len());
        hold.store(false, core::sync::atomic::Ordering::Release);
        h.pump();
        if !h.closed() || h.model(|model| model.sent.len()) != before {
            return TestResult::Fail("late PS send reopened cancelled owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/power-save",
    smoke_ath10k_power_save_each_cancelled_publication_closes_and_retains_dma
);

fn smoke_ath10k_power_save_policy_clear_and_native_failure_are_terminal() -> TestResult {
    for failure in [false, true] {
        for step in 0..6 {
            let h = Harness::new(4, Dialect::Tlv, false);
            if let Err(error) = h.join() {
                return TestResult::Fail(error);
            }
            h.model(|model| {
                let mut ps = super::super::power_save_tests::Fixture::new(Dialect::Tlv, true);
                if failure {
                    ps.fail = Some(step);
                } else {
                    ps.change = Some((step, h.policy.clone()));
                }
                model.ps = Some(ps);
            });
            h.device.request_power_save(true).unwrap();
            if !matches!(drive(h.device.apply_power_save()), Poll::Ready(Err(_))) || !h.closed() {
                return TestResult::Fail("PS ignored policy loss or failed native publication");
            }
            *h.policy.lock() = Some(station_tests::policy());
            if h.device.request_power_save(false) != Err(-19)
                || !h.model(|model| {
                    model.inner.inner.retained.is_some()
                        && model.inner.storage.as_ref().unwrap().filled == 1023
                })
            {
                return TestResult::Fail("restored policy reopened failed PS grant or freed DMA");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/power-save",
    smoke_ath10k_power_save_policy_clear_and_native_failure_are_terminal
);

fn smoke_ath10k_power_save_latest_preference_survives_inflight_completion() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, false);
    if let Err(error) = h.join() {
        return TestResult::Fail(error);
    }
    let hold = Arc::new(core::sync::atomic::AtomicBool::new(true));
    h.model(|model| {
        let mut ps = super::super::power_save_tests::Fixture::new(Dialect::Tlv, true);
        ps.queue(Dialect::Tlv, false);
        ps.hold = Some((5, hold.clone()));
        model.ps = Some(ps);
    });
    h.device.request_power_save(true).unwrap();
    {
        let mut applying = core::pin::pin!(h.device.apply_power_save());
        if !drive(applying.as_mut()).is_pending() {
            return TestResult::Fail("PS coalescing fixture did not wait");
        }
        h.device.request_power_save(false).unwrap();
        hold.store(false, core::sync::atomic::Ordering::Release);
        if !matches!(drive(applying.as_mut()), Poll::Ready(Ok(()))) {
            return TestResult::Fail("PS enable did not finish native receipt");
        }
    }
    if !matches!(drive(h.device.apply_power_save()), Poll::Ready(Ok(())))
        || !h.model(|model| {
            model
                .ps
                .as_ref()
                .is_some_and(|ps| ps.mode == Some(false) && ps.expected.is_empty() && ps.seen == 7)
        })
        || !h.device.link_up()
    {
        return TestResult::Fail("old PS completion overwrote newer disable preference");
    }
    let before = h.model(|model| model.sent.len());
    if !matches!(drive(h.device.apply_power_save()), Poll::Ready(Ok(())))
        || h.model(|model| model.sent.len()) != before
    {
        return TestResult::Fail("coalesced PS preference replayed a command");
    }
    *h.policy.lock() = None;
    if !matches!(drive(h.device.apply_power_save()), Poll::Ready(Err(_))) || !h.closed() {
        return TestResult::Fail("coalesced PS no-op bypassed current policy closure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/power-save",
    smoke_ath10k_power_save_latest_preference_survives_inflight_completion
);

fn smoke_ath10k_power_save_no_ps_firmware_rejects_before_publication() -> TestResult {
    let mut radio = radio_boot_features(4, Dialect::Tlv, (1 << 10) | (1 << 17));
    if !matches!(drive(radio.start(&[2412, 5180])), Poll::Ready(Ok(_)))
        || radio.power_save_supported()
    {
        return TestResult::Fail("NO_PS firmware capability was misclassified");
    }
    let before = radio.htt.wmi.htc.transport.sent.len();
    let owner = Arc::new(Mutex::new(radio));
    let device = Device::for_test("narf-test-no-ps", OWN, owner.clone(), || {
        Some(station_tests::policy())
    });
    if device.request_power_save(true) != Err(-95)
        || device.request_power_save(false) != Err(-95)
        || owner.try_lock().unwrap().htt.wmi.htc.transport.sent.len() != before
    {
        return TestResult::Fail(
            "NO_PS setter changed native state or advertised unsupported control",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/power-save",
    smoke_ath10k_power_save_no_ps_firmware_rejects_before_publication
);

fn smoke_ath10k_power_save_host_close_during_send_cannot_reopen() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, false);
    if let Err(error) = h.join() {
        return TestResult::Fail(error);
    }
    let hold = Arc::new(core::sync::atomic::AtomicBool::new(true));
    h.model(|model| {
        let mut ps = super::super::power_save_tests::Fixture::new(Dialect::Tlv, true);
        ps.hold = Some((5, hold.clone()));
        model.ps = Some(ps);
    });
    h.device.request_power_save(true).unwrap();
    {
        let mut applying = core::pin::pin!(h.device.apply_power_save());
        if !drive(applying.as_mut()).is_pending() {
            return TestResult::Fail("close/PS fixture never held native send");
        }
        h.device.close_before_lock_for_test();
        hold.store(false, core::sync::atomic::Ordering::Release);
        if !matches!(drive(applying.as_mut()), Poll::Ready(Err(_))) {
            return TestResult::Fail("PS ignored concurrent host close");
        }
    }
    if !h.closed()
        || !h.model(|model| {
            model.inner.storage.as_ref().unwrap().filled == 1023
                && model.inner.inner.retained.is_some()
        })
    {
        return TestResult::Fail("late PS completion reopened carrier or released firmware DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/power-save",
    smoke_ath10k_power_save_host_close_during_send_cannot_reopen
);

fn composition_scan(
    version: u32,
    dialect: Dialect,
    secured: bool,
    active_scan: bool,
) -> Result<(), &'static str> {
    composition_options(version, dialect, secured, active_scan, false)
}
fn composition_options(
    version: u32,
    dialect: Dialect,
    secured: bool,
    active_scan: bool,
    power_save: bool,
) -> Result<(), &'static str> {
    let h = Harness::new_scan(version, dialect, secured, active_scan);
    if power_save {
        h.model(|model| {
            model.ps = Some(super::super::power_save_tests::Fixture::new(dialect, true))
        });
        h.device
            .request_power_save(true)
            .map_err(|_| "PS preference rejected")?;
        if !matches!(drive(h.device.apply_power_save()), Poll::Ready(Ok(())))
            || h.model(|model| model.ps.as_ref().unwrap().seen) != 0
        {
            return Err("PS preference emitted before association");
        }
    }
    let (uplink, downlink) = packets();
    if narf_net::dhcp::acquire(&h.name, 0).is_ok()
        || h.device.enqueue(&uplink, narf_net::TxMeta::plain()).is_ok()
    {
        return Err("DHCP/data escaped preauthorization carrier");
    }
    h.join()?;
    if !power_save && !h.model(|model| model.ps_default_off) {
        return Err("awake default was not submitted before carrier");
    }
    if power_save
        && !h.model(|model| {
            model
                .ps
                .as_ref()
                .is_some_and(|ps| ps.seen == 6 && ps.expected.is_empty() && ps.mode == Some(true))
        })
    {
        return Err("power-save initialization did not precede carrier");
    }
    if active_scan {
        let sent = h.model(|m| m.sent.len());
        let request = ScanRequest {
            ssids: vec![b"narf".to_vec()],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        };
        if !matches!(
            drive(h.device.scan(request)),
            Poll::Ready(Err(WirelessError::Busy))
        ) || !h.device.link_up()
            || h.model(|m| m.sent.len()) != sent
        {
            return Err("associated active scan failed to preserve exclusive peer and carrier");
        }
    }
    let lease = narf_net::dhcp::dhcp_acquire(&h.name, 0)
        .map_err(|_| "actual kernel DHCP through CE/HTT failed")?;
    if !network().matches_lease(&lease)
        || !h.model(|m| {
            let f = m.data.as_ref().unwrap();
            let seen = f.server.observations();
            seen.discovers == 1 && seen.requests == 1 && f.ap.phase() == ApPhase::Authorized
        })
    {
        return Err("native AP DHCP conversation or exact lease terms");
    }
    narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "native netdev uplink enqueue")?;
    h.pump();
    if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&uplink)) {
        return Err("native HTT/AP IP uplink changed");
    }
    let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&downlink);
        f.queue.push_back(frame);
    });
    h.pump();
    if !h.received(&downlink)
        || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets <= before
    {
        return Err("native IP downlink did not reach both Narf-Ring and kernel stack intact");
    }
    h.model(|m| teardown_tests::arm_data_disconnect(m, false));
    if !matches!(drive(h.device.disassociate()), Poll::Ready(Ok(()))) {
        return Err("native Device terminal peer/vdev disconnect failed");
    }
    h.pump();
    if !h.closed()
        || narf_net::iface::send_on(&h.name, &uplink).is_ok()
        || !h.model(|m| {
            m.ce.as_ref().unwrap().retained() && m.inner.storage.as_ref().unwrap().tx.pending() == 0
        })
    {
        return Err("native disconnect reused DMA or left carrier/data open");
    }
    let name = h.name.clone();
    drop(h);
    if narf_net::ipv4::lookup_binding(&name).is_some() {
        return Err("removed ath10k netdev retained DHCP binding");
    }
    Ok(())
}
fn smoke_ath10k_native_device_open_wpa2_dhcp_and_bidirectional_ip() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        for secured in [false, true] {
            if let Err(e) = composition(version, dialect, secured) {
                return TestResult::Fail(e);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_native_device_open_wpa2_dhcp_and_bidirectional_ip
);
fn smoke_ath10k_active_probe_cache_native_open_wpa2_dhcp_ip_and_teardown() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        for secured in [false, true] {
            if let Err(error) = composition_scan(version, dialect, secured, true) {
                return TestResult::Fail(error);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/active-scan",
    smoke_ath10k_active_probe_cache_native_open_wpa2_dhcp_ip_and_teardown
);
fn occupancy(htt_first: bool) -> Result<(), &'static str> {
    let h = Harness::new(4, Dialect::Tlv, true);
    h.join()?;
    let (uplink, downlink) = packets();
    h.model(|m| {
        m.ce.as_mut().unwrap().hold_source(true);
        m.data.as_mut().unwrap().hold_data = true;
    });
    narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "held native submit")?;
    h.pump();
    let (bounce, sent) = h.model(|m| {
        (
            m.ce.as_ref().unwrap().source_bytes(4),
            m.ce.as_ref().unwrap().sent,
        )
    });
    if !h.model(|m| {
        m.inner.storage.as_ref().unwrap().tx.pending() == 1
            && !m.ce.as_mut().unwrap().source_ready(4).unwrap()
    }) {
        return Err("fixture did not retain real CE/HTT owners");
    }
    narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "queued second native submit")?;
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&downlink);
        f.queue.push_back(frame);
    });
    h.pump();
    if !h.received(&downlink)
        || !h.device.link_up()
        || !h.model(|m| {
            m.ce.as_ref().unwrap().sent == sent
                && m.ce.as_ref().unwrap().source_bytes(4) == bounce
                && m.inner.storage.as_ref().unwrap().tx.pending() == 1
        })
    {
        return Err("pending CE bounce overwritten, forged HTT completion or RX stalled");
    }
    if htt_first {
        h.model(|m| {
            let id = m.data.as_mut().unwrap().held.pop_front().unwrap();
            complete(m, id, 0);
        });
        h.pump();
        if !h.model(|m| {
            m.ce.as_ref().unwrap().sent == sent
                && m.ce.as_ref().unwrap().source_bytes(4) == bounce
                && !m.ce.as_mut().unwrap().source_ready(4).unwrap()
                && m.inner.storage.as_ref().unwrap().tx.pending() == 0
        }) {
            return Err("HTT receipt reused CE bounce before its terminal source index");
        }
    }
    h.model(|m| m.ce.as_mut().unwrap().hold_source(false));
    if !h.model(|m| m.ce.as_mut().unwrap().source_ready(4).unwrap()) {
        return Err("fixture release did not publish actual terminal CE source index");
    }
    if !htt_first {
        h.pump();
        if !h.model(|m| {
            m.ce.as_ref().unwrap().sent == sent
                && m.inner.storage.as_ref().unwrap().tx.pending() == 1
        }) {
            return Err("CE receipt substituted for actual HTT completion");
        }
        h.model(|m| {
            let id = m.data.as_mut().unwrap().held.pop_front().unwrap();
            complete(m, id, 0);
        });
    }
    h.pump();
    if !h.model(|m| {
        m.ce.as_ref().unwrap().sent == sent + 1
            && m.inner.storage.as_ref().unwrap().tx.pending() == 1
            && m.data.as_ref().unwrap().held.len() == 1
            && m.data.as_ref().unwrap().uplink == [uplink.clone(), uplink]
    }) {
        return Err("terminal HTT ID did not unlock exactly queued frame");
    }
    Ok(())
}
fn smoke_ath10k_ce_bounce_busy_preserves_rx_and_exact_htt_ownership() -> TestResult {
    for htt_first in [false, true] {
        if let Err(e) = occupancy(htt_first) {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_ce_bounce_busy_preserves_rx_and_exact_htt_ownership
);
fn smoke_ath10k_device_held_m4_cancellation_cannot_raise_carrier() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    if let Err(e) = h.scan() {
        return TestResult::Fail(e);
    }
    h.model(|m| m.data.as_mut().unwrap().hold_m4 = true);
    {
        let mut future = core::pin::pin!(h.device.associate_for_test(h.request(), [0x73; 32]));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..48 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("native held M4 raised carrier");
            }
        }
    }
    h.pump();
    if h.device.link_up()
        || narf_net::dhcp::acquire(&h.name, 0).is_ok()
        || !h.model(|m| {
            m.data.as_ref().unwrap().ap.phase() == ApPhase::Authorized
                && m.data.as_ref().unwrap().held.len() == 1
                && m.inner.storage.as_ref().unwrap().tx.pending() == 1
                && m.ce.as_ref().unwrap().retained()
        })
    {
        return TestResult::Fail("cancelled actual M4 lost DMA or opened DHCP/carrier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_device_held_m4_cancellation_cannot_raise_carrier
);
fn smoke_ath10k_device_connection_loss_and_failed_disconnect_stay_terminal() -> TestResult {
    for fail in [false, true] {
        let h = Harness::new(4, Dialect::Tlv, true);
        if let Err(e) = h.join() {
            return TestResult::Fail(e);
        }
        let (uplink, _) = packets();
        h.model(|m| m.data.as_mut().unwrap().hold_data = true);
        if narf_net::iface::send_on(&h.name, &uplink).is_err() {
            return TestResult::Fail("negative data enqueue");
        }
        h.pump();
        if fail {
            h.model(|m| teardown_tests::arm_data_disconnect(m, true));
            if !matches!(drive(h.device.disassociate()), Poll::Ready(Err(_))) {
                return TestResult::Fail("failed native disconnect accepted");
            }
        } else {
            h.device.radio.try_lock().unwrap().expire_data_for_test();
            h.pump();
        }
        if !h.closed()
            || narf_net::iface::send_on(&h.name, &uplink).is_ok()
            || !h.model(|m| {
                m.inner.storage.as_ref().unwrap().tx.pending() == 1
                    && m.ce.as_ref().unwrap().retained()
            })
            || !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            )
        {
            return TestResult::Fail(
                "lost/failed native station reopened or reclaimed uncertain DMA",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_device_connection_loss_and_failed_disconnect_stay_terminal
);

fn smoke_ath10k_host_close_worker_interleave_preserves_native_teardown() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, false);
    if let Err(e) = h.join() {
        return TestResult::Fail(e);
    }
    h.device.close_before_lock_for_test();
    h.pump();
    if h.device.radio.try_lock().unwrap().prepared_peer().is_none() {
        return TestResult::Fail(
            "host-close worker poisoned radio before teardown could acquire it",
        );
    }
    h.model(|m| teardown_tests::arm_data_disconnect(m, false));
    if !matches!(drive(h.device.disassociate()), Poll::Ready(Ok(())))
        || !h.closed()
        || !h.model(|m| teardown_tests::data_disconnect_completed(m))
    {
        return TestResult::Fail("worker interleave prevented real DOWN/DELETE/STOP correlation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_host_close_worker_interleave_preserves_native_teardown
);

fn rekey_and_offloads() -> Result<(), &'static str> {
    let h = Harness::new(4, Dialect::Tlv, true);
    h.join()?;
    let (uplink, _) = packets();
    let before = h.model(|m| m.data.as_ref().unwrap().uplink.len());
    for meta in [
        narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Udp),
        narf_net::TxMeta::with_tso(1200),
        narf_net::TxMeta {
            vlan_tag: Some(7),
            ..narf_net::TxMeta::plain()
        },
    ] {
        if h.device.enqueue(&uplink, meta).is_ok() {
            return Err("unsupported netdev offload admitted");
        }
        let memory = narf_io::alloc_coherent(uplink.len(), narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| "offload test memory")?;
        let mut frame = narf_net::Frame::new(memory, uplink.len() as u32);
        frame.payload_mut().copy_from_slice(&uplink);
        frame.set_tx_meta(meta);
        h.device
            .tx_ring()
            .lock()
            .as_mut()
            .unwrap()
            .try_send(frame)
            .map_err(|_| "direct offload ring submit")?;
        h.pump();
    }
    if h.model(|m| m.data.as_ref().unwrap().uplink.len()) != before {
        return Err("direct frame-ring client bypassed offload admission");
    }
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.hold_data = true;
        let group = f.group_rekey();
        f.queue.push_back(group);
    });
    h.pump();
    if !h.device.link_up()
        || !h.model(|m| {
            m.data.as_ref().unwrap().held.len() == 1 && m.data.as_ref().unwrap().group_replies == 1
        })
    {
        return Err("native GTK reply wait lost carrier or exact terminal owner");
    }
    narf_net::iface::send_on(&h.name, &uplink).map_err(|_| "rekey queued uplink")?;
    h.pump();
    if h.model(|m| m.data.as_ref().unwrap().uplink.len()) != before
        || narf_net::iface::lookup(&h.name)
            .is_none_or(|i| !i.carrier || i.carrier_up_count != 1 || i.carrier_down_count != 0)
    {
        return Err("GTK reply wait opened data port or flapped physical carrier");
    }
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.hold_data = false;
        let id = f.held.pop_front().unwrap();
        complete(m, id, 0);
    });
    h.pump();
    if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&uplink)) || !h.device.link_up() {
        return Err("real GTK reply receipt did not reopen queued native data");
    }
    Ok(())
}
fn smoke_ath10k_native_rekey_keeps_carrier_and_ring_offloads_stay_closed() -> TestResult {
    match rekey_and_offloads() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_native_rekey_keeps_carrier_and_ring_offloads_stay_closed
);

fn smoke_ath10k_close_mid_progress_fences_native_tx_rx_and_stale_carrier() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, true);
    if let Err(e) = h.join() {
        return TestResult::Fail(e);
    }
    let (uplink, downlink) = packets();
    if narf_net::iface::send_on(&h.name, &uplink).is_err() {
        return TestResult::Fail("mid-progress native TX enqueue");
    }
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        let frame = f.downlink(&downlink);
        f.queue.push_back(frame);
        super::poll(m).unwrap();
    });
    let sent = h.model(|m| m.ce.as_ref().unwrap().sent);
    let rx = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
    h.device.close_mid_progress_for_test();
    h.device.drain();
    h.device.stale_link_after_close_for_test(AP);
    if !h.closed()
        || h.received(&downlink)
        || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != rx
        || h.model(|m| m.ce.as_ref().unwrap().sent) != sent
        || narf_net::iface::send_on(&h.name, &uplink).is_ok()
    {
        return TestResult::Fail(
            "host close raced native publication, RX dispatch or stale carrier intent",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_close_mid_progress_fences_native_tx_rx_and_stale_carrier
);

fn smoke_ath10k_current_policy_restriction_fences_native_station_publication() -> TestResult {
    for (version, dialect) in [(1, Dialect::Main), (4, Dialect::Tlv)] {
        for restriction in 0..3 {
            let h = Harness::new(version, dialect, true);
            if let Err(e) = h.join() {
                return TestResult::Fail(e);
            }
            let (uplink, downlink) = packets();
            if narf_net::iface::send_on(&h.name, &uplink).is_err() {
                return TestResult::Fail("policy restriction host TX setup");
            }
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                let frame = f.downlink(&downlink);
                f.queue.push_back(frame);
            });
            let sent = h.model(|m| m.ce.as_ref().unwrap().sent);
            let rx = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
            let mut restricted = station_tests::policy();
            match restriction {
                // This still permits channel1, but no longer permits the
                // power actually programmed by START. It cannot be silently
                // accepted without a distinct native retune/power owner.
                0 => restricted.rules[0].max_power_dbm = 16,
                1 => restricted.rules[0].freq_start_mhz = 2427,
                _ => {}
            }
            *h.policy.lock() = (restriction != 2).then_some(restricted);
            h.pump();
            if !h.closed()
                || h.received(&downlink)
                || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != rx
                || !h.model(|m| {
                    m.ce.as_ref().unwrap().sent == sent
                        && m.inner.storage.as_ref().unwrap().tx.pending() == 0
                        && m.data.as_ref().unwrap().uplink.is_empty()
                })
                || narf_net::iface::send_on(&h.name, &uplink).is_ok()
            {
                return TestResult::Fail(
                    "restricted current policy published native TX/RX or retained carrier",
                );
            }
            *h.policy.lock() = Some(station_tests::policy());
            h.pump();
            if !h.closed() || h.model(|m| m.ce.as_ref().unwrap().sent) != sent {
                return TestResult::Fail("policy restoration reopened terminal station");
            }
        }
        let h = Harness::new(version, dialect, false);
        if let Err(e) = h.scan() {
            return TestResult::Fail(e);
        }
        let sent = h.model(|m| m.sent.len());
        let mut restricted = station_tests::policy();
        restricted.rules[0].freq_start_mhz = 2427;
        *h.policy.lock() = Some(restricted);
        if !matches!(
            drive(h.device.associate_for_test(h.request(), [0x73; 32])),
            Poll::Ready(Err(_))
        ) || h.model(|m| m.sent.len()) != sent
            || h.device.radio.try_lock().unwrap().prepared_peer().is_some()
            || h.device.link_up()
        {
            return TestResult::Fail(
                "association used policy captured before the current restriction",
            );
        }
        let h = Harness::new(version, dialect, false);
        let sent = h.model(|m| m.sent.len());
        *h.policy.lock() = None;
        if h.scan().is_ok() || h.model(|m| m.sent.len()) != sent {
            return TestResult::Fail("passive scan published without current receive policy");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_current_policy_restriction_fences_native_station_publication
);

fn smoke_ath10k_station_publish_admission_stages_missing_regulatory_only_for_raw_radio(
) -> TestResult {
    use crate::ath10k::interface::{classify_domain_admission, Admission};
    use narf_firmware::FirmwareError;
    use narf_wireless::reg::policy::Error as RegPolicyError;

    if classify_domain_admission(Err(RegPolicyError::Firmware(FirmwareError::NotFound)), true)
        != Ok(Admission::PendingAssets)
        || classify_domain_admission(Err(RegPolicyError::Authority), false)
            != Ok(Admission::PendingAssets)
        || classify_domain_admission(Err(RegPolicyError::Authority), true)
            != Err(crate::ath10k::wmi_runtime::Error::Unsupported)
        || classify_domain_admission(Err(RegPolicyError::Unsigned), true)
            != Err(crate::ath10k::wmi_runtime::Error::Unsupported)
        || classify_domain_admission(Err(RegPolicyError::Format("bad")), true)
            != Err(crate::ath10k::wmi_runtime::Error::Unsupported)
        || classify_domain_admission(Ok(station_tests::policy()), true) != Ok(Admission::Ready)
    {
        return TestResult::Fail(
            "ath10k regulatory staging classification mishandled error states",
        );
    }

    let mut non_raw = radio_boot_features(4, Dialect::Tlv, 1 << 2);
    assert!(matches!(
        drive(non_raw.start(&[2412, 5180])),
        Poll::Ready(Ok(_))
    ));
    if non_raw.station_publishable() != Err(crate::ath10k::wmi_runtime::Error::Unsupported) {
        return TestResult::Fail("non-RAW ath10k radio was admitted as station-publishable");
    }

    let mut raw = radio_boot_features(4, Dialect::Tlv, (1 << 10) | (1 << 2) | (1 << 18));
    if raw.station_publishable() != Err(crate::ath10k::wmi_runtime::Error::Failed) {
        return TestResult::Fail("unstarted ath10k radio was admitted as station-publishable");
    }
    assert!(matches!(
        drive(raw.start(&[2412, 5180])),
        Poll::Ready(Ok(_))
    ));
    if raw.station_publishable() != Ok(OWN) {
        return TestResult::Fail("started RAW ath10k radio was not station-publishable");
    }
    raw.fail_station_data();
    if raw.station_publishable() != Err(crate::ath10k::wmi_runtime::Error::Failed) {
        return TestResult::Fail("failed ath10k radio remained station-publishable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/station",
    smoke_ath10k_station_publish_admission_stages_missing_regulatory_only_for_raw_radio
);
