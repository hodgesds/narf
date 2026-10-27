//! Production Device/Radio/Packet, actual Narf-Rings and kernel DHCP. The
//! shared AR9285 fixture reacts only after reading actual doorbell DMA.
use super::*;
use crate::ath9k::{
    packet::tests::Model,
    station::tests::{self, Env, Peer, TestRadio, AP, PMK, SSID},
};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{udp_ipv4, NetworkPlan};
type TestDevice = Device<Arc<Model>, Arc<Env>>;
static ACTIVE_TEST: IrqSafeSpinLock<Option<Arc<TestDevice>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_TEST.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE_TEST.lock().clone();
    device.is_some_and(|device| device.drain())
}
struct Harness {
    device: Arc<TestDevice>,
    model: Arc<Model>,
    peer: Arc<IrqSafeSpinLock<Peer>>,
    env: Arc<Env>,
    plan: NetworkPlan,
}
impl Harness {
    fn new(protected: bool) -> Self {
        Self::new_rates(protected, None)
    }
    fn new_rates(protected: bool, rates: Option<&[u8]>) -> Self {
        Self::new_inner(protected, rates, None)
    }
    fn new_ht(protected: bool, mcs: u8) -> Self {
        Self::new_inner(protected, None, Some(mcs))
    }
    fn new_inner(protected: bool, rates: Option<&[u8]>, ht: Option<u8>) -> Self {
        assert!(ACTIVE_TEST.lock().is_none());
        let tests::Fixture {
            radio,
            model,
            peer,
            env,
            plan,
        } = if let Some(mask) = ht {
            tests::fixture_ht(protected, mask)
        } else {
            tests::fixture_rates(protected, rates)
        }
        .unwrap();
        let radio: Arc<Mutex<TestRadio>> = Arc::new(Mutex::new(radio));
        let name = narf_net::iface::reserve_name("ar9-native%d");
        let device = Arc::new(Device::new(name, radio).unwrap());
        device.admit_for_test();
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::register(name, plan.station, send);
        narf_net::iface::set_link_state(name, true); // operator IFF_UP
        device.link(None);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Self {
            device,
            model,
            peer,
            env,
            plan,
        }
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            security: if self.peer.lock().ap.protected() {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }
    fn scan(&self) {
        self.scan_mode(false);
    }
    fn scan_mode(&self, active: bool) {
        let result = tests::complete(self.device.scan(ScanRequest {
            ssids: vec![SSID.to_vec()],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(1),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }))
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].bssid, AP);
        assert_eq!(result[0].ssid, SSID);
    }
    fn join(&self) {
        self.join_mode(false);
    }
    fn join_mode(&self, active: bool) {
        self.scan_mode(active);
        tests::complete(self.device.associate(self.request())).unwrap();
        assert!(self.device.link_up());
        assert_eq!(self.device.connected_bssid(), Some(AP));
        // Operator DOWN must survive another real radio carrier sample.
        narf_net::iface::set_link_state(self.device.name(), false);
        self.device.drain();
        assert!(narf_net::iface::lookup(self.device.name())
            .is_some_and(|iface| !iface.link_up && iface.carrier));
        narf_net::iface::set_link_state(self.device.name(), true);
    }
    fn pump(&self) {
        for _ in 0..16 {
            self.device.drain();
        }
    }
    fn closed(&self) -> bool {
        !self.device.link_up()
            && self.device.connected_bssid().is_none()
            && narf_net::iface::lookup(self.device.name())
                .is_some_and(|iface| !iface.carrier && iface.link_up)
    }
    fn received(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        let mut slot = self.device.rx_ring().lock();
        let ring = slot.as_mut().unwrap();
        while let Ok(Some(frame)) = ring.try_recv() {
            result.push(frame.payload().to_vec());
        }
        result
    }
    fn rx_count(&self) -> u64 {
        narf_net::iface::snapshot_counters()
            .iter()
            .find(|iface| iface.name == self.device.name())
            .map_or(0, |iface| iface.rx_packets)
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_TEST.lock() = None;
        narf_net::iface::unregister(self.device.name());
    }
}
fn composition(protected: bool) -> TestResult {
    composition_mode(protected, false)
}
fn smoke_ar9285_legacy_rate_profiles_native_open_wpa2_kernel_dhcp_ip() -> TestResult {
    for profile in [
        &[0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108][..],
        &[0x8c, 24, 48, 108][..],
        &[0x82, 4, 11, 22][..],
    ] {
        for protected in [false, true] {
            if let failure @ TestResult::Fail(_) =
                composition_rates(protected, false, Some(profile))
            {
                return failure;
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rates",
    smoke_ar9285_legacy_rate_profiles_native_open_wpa2_kernel_dhcp_ip
);
fn composition_mode(protected: bool, active: bool) -> TestResult {
    composition_rates(protected, active, None)
}
fn composition_rates(protected: bool, active: bool, rates: Option<&[u8]>) -> TestResult {
    composition_inner(protected, active, rates, None)
}
fn composition_inner(
    protected: bool,
    active: bool,
    rates: Option<&[u8]>,
    ht: Option<u8>,
) -> TestResult {
    composition_profile(protected, active, rates, ht, None, None)
}
fn composition_profile(
    protected: bool,
    active: bool,
    rates: Option<&[u8]>,
    ht: Option<u8>,
    ba: Option<u8>,
    protection: Option<(u8, bool)>,
) -> TestResult {
    let h = if let Some(mask) = ht {
        Harness::new_ht(protected, mask)
    } else {
        Harness::new_rates(protected, rates)
    };
    if let Some(window) = ba {
        crate::ath9k::rx_ba::tests::qualify(&h.model, window);
    }
    if let Some((mode, erp)) = protection {
        h.peer.lock().ht = Some(crate::ath9k::ht::tests::protection_elements(mode, erp));
        let beacon = h.peer.lock().beacon();
        h.model.inject(&beacon, 0).unwrap();
        h.device.radio.try_lock().unwrap().poll().unwrap();
    }
    if !h.closed() || narf_net::dhcp::acquire(h.device.name(), 100).is_ok() {
        return TestResult::Fail("AR9285 DHCP passed before real native association");
    }
    h.join_mode(active);
    if let Some(window) = ba {
        h.model
            .inject(
                &crate::ath9k::rx_ba::tests::addba(0, 0, u16::from(window), 0, false),
                0,
            )
            .unwrap();
        h.pump();
        if h.peer.lock().ba_accepts.len() != 1
            || h.model.registers.borrow().get(&0x803c) != Some(&0x417)
        {
            return TestResult::Fail("DHCP BA setup lacked actual response/filter receipt");
        }
        h.model.rx_aggr.set((1 << 17) | (1 << 29));
    }
    if active {
        let sent = h.model.transmitted.borrow().len();
        let request = ScanRequest {
            ssids: vec![SSID.to_vec()],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: Some(20),
            duration_mandatory: false,
            extra_ies: Vec::new(),
        };
        if !matches!(
            tests::complete(h.device.scan(request)),
            Err(WirelessError::Busy)
        ) || h.model.transmitted.borrow().len() != sent
            || !h.device.link_up()
        {
            return TestResult::Fail(
                "associated AR9285 active scan changed carrier or native owner",
            );
        }
    }
    let lease = match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
        Ok(lease) => lease,
        Err(_) => return TestResult::Fail("AR9285 actual kernel DHCP failed"),
    };
    if !h.plan.matches_lease(&lease) {
        return TestResult::Fail("AR9285 DHCP terms differ from reactive AP lease");
    }
    {
        let peer = h.peer.lock();
        let seen = peer.server.observations();
        if seen.discovers != 1 || seen.requests != 1 || peer.uplink.len() != 2 {
            return TestResult::Fail("AR9285 real native DORA receipts differ");
        }
    }
    let uplink = udp_ipv4(
        AP,
        h.plan.station,
        h.plan.lease_ip,
        h.plan.server_ip,
        49152,
        7,
        b"ar9285-device-native-uplink",
    );
    if narf_net::iface::send_on(h.device.name(), &uplink).is_err() {
        return TestResult::Fail("AR9285 Device rejected IP uplink");
    }
    h.pump();
    if h.peer.lock().uplink.last() != Some(&uplink) {
        return TestResult::Fail("AR9285 actual DMA Ethernet/IP uplink differs");
    }
    let downlink = udp_ipv4(
        h.plan.station,
        AP,
        h.plan.server_ip,
        h.plan.lease_ip,
        7,
        49152,
        b"ar9285-device-native-downlink",
    );
    let before = h.rx_count();
    let wire = { h.peer.lock().downlink(&downlink).unwrap() };
    h.model.inject(&wire, 0).unwrap();
    h.pump();
    if !h.received().contains(&downlink) || h.rx_count() <= before {
        return TestResult::Fail("AR9285 exact IP downlink missed real Narf-Ring or stack");
    }
    if protection.is_some() {
        let d = h.model.registers.borrow()[&0x800];
        if h.model.word(d + 8).unwrap() & ((1 << 22) | (1 << 31)) != 1 << 22
            || h.model.word(d + 24).unwrap() & 0x8000 == 0
            || h.model.word(d + 36).unwrap() >> 20 & 255 != 0x1b
        {
            return TestResult::Fail("real DHCP/IP lost native RTS/CTS protection/control rate");
        }
    }
    if tests::complete(h.device.disassociate()).is_err() || !h.closed() || h.model.master.get() {
        return TestResult::Fail("AR9285 Device disconnect retained carrier or active DMA");
    }
    if tests::complete(h.device.associate(h.request())).is_ok()
        || narf_net::iface::send_on(h.device.name(), &uplink).is_ok()
    {
        return TestResult::Fail("AR9285 terminal station reopened");
    }
    TestResult::Pass
}
fn smoke_ar9285_native_device_open_kernel_dhcp_exact_bidirectional_ip() -> TestResult {
    composition(false)
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ar9285_native_device_open_kernel_dhcp_exact_bidirectional_ip
);
fn smoke_ar9285_native_device_wpa2_kernel_dhcp_exact_bidirectional_ip() -> TestResult {
    composition(true)
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ar9285_native_device_wpa2_kernel_dhcp_exact_bidirectional_ip
);

fn smoke_ar9285_native_device_held_m4_cancel_and_modified_dma_never_authorize() -> TestResult {
    for cancel in [true, false] {
        let h = Harness::new(true);
        h.scan();
        h.peer.lock().hold_m4 = true;
        let mut future = Box::pin(h.device.associate(h.request()));
        let mut held = false;
        for _ in 0..200 {
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("AR9285 held M4 completed Device association");
            }
            held = h.peer.lock().ap.phase() == narf_wifi_fixtures::ApPhase::Authorized
                && h.model.tx.get().is_some();
            if held {
                break;
            }
        }
        if !held || !h.closed() || narf_net::dhcp::acquire(h.device.name(), 100).is_ok() {
            return TestResult::Fail(
                "AR9285 held M4 lacked native DMA hold or controlled port stayed open",
            );
        }
        if cancel {
            drop(future);
            h.model.complete(true).unwrap();
            h.pump();
        } else {
            let descriptor = h.model.tx.get().unwrap();
            let body = h.model.word(descriptor + 4).unwrap();
            let word = h.model.word(body).unwrap();
            h.model.put(body, word ^ 0x1000_0000).unwrap();
            h.model.complete(true).unwrap();
            if tests::complete(future).is_ok() {
                return TestResult::Fail("AR9285 modified actual M4 DMA receipt authorized keys");
            }
            h.pump();
        }
        if !h.closed() || h.model.master.get() || !h.peer.lock().uplink.is_empty() {
            return TestResult::Fail("AR9285 failed M4 reopened carrier or data");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ar9285_native_device_held_m4_cancel_and_modified_dma_never_authorize
);

fn direct(device: &TestDevice, bytes: &[u8], meta: narf_net::TxMeta) {
    let buffer = narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0).unwrap();
    let mut frame = Frame::new(buffer, bytes.len() as u32);
    frame.payload_mut().copy_from_slice(bytes);
    frame.set_tx_meta(meta);
    device
        .tx_ring()
        .lock()
        .as_mut()
        .unwrap()
        .try_send(frame)
        .unwrap();
}
fn smoke_ar9285_native_device_direct_ring_metadata_policy_and_capability_fail_closed() -> TestResult
{
    for capability in [false, true] {
        let h = Harness::new(true);
        h.join();
        let data = udp_ipv4(
            AP,
            h.plan.station,
            h.plan.lease_ip,
            h.plan.server_ip,
            49152,
            7,
            b"ar9285-direct-native-ip",
        );
        for meta in [
            narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Udp),
            narf_net::TxMeta {
                tso_mss: Some(512),
                ..Default::default()
            },
            narf_net::TxMeta {
                vlan_tag: Some(3),
                ..Default::default()
            },
        ] {
            if h.device.enqueue(&data, meta).is_ok() {
                return TestResult::Fail("AR9285 callback accepted unsupported metadata");
            }
            direct(&h.device, &data, meta);
        }
        let mut source = data.clone();
        source[6] ^= 2;
        direct(&h.device, &source, Default::default());
        let mut eapol = data.clone();
        eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
        direct(&h.device, &eapol, Default::default());
        h.pump();
        if !h.peer.lock().uplink.is_empty() || !h.device.link_up() {
            return TestResult::Fail("AR9285 raw IPC bypassed metadata/source/EAPOL admission");
        }
        direct(&h.device, &data, Default::default());
        h.pump();
        if h.peer.lock().uplink != vec![data.clone()] {
            return TestResult::Fail("AR9285 valid direct-ring data missed native DMA");
        }
        if capability {
            h.model.authority.set(false);
        } else {
            h.model.allowed.set(false);
        }
        h.pump();
        if !h.closed()
            || h.device.enqueue(&data, Default::default()).is_ok()
            || !capability && h.model.master.get()
        {
            return TestResult::Fail("AR9285 stale policy/capability retained native admission");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ar9285_native_device_direct_ring_metadata_policy_and_capability_fail_closed
);

fn smoke_ar9285_native_device_disconnect_cancellation_and_stale_publication_stay_closed(
) -> TestResult {
    let h = Harness::new(true);
    h.join();
    h.peer.lock().hold_data = true;
    let bytes = udp_ipv4(
        AP,
        h.plan.station,
        h.plan.lease_ip,
        h.plan.server_ip,
        49152,
        7,
        b"ar9285-held-before-disconnect",
    );
    h.device.enqueue(&bytes, Default::default()).unwrap();
    h.pump();
    if h.model.tx.get().is_none() {
        return TestResult::Fail("AR9285 disconnect fixture lacks actual pending DMA");
    }
    let owner = h.device.radio.try_lock().unwrap();
    let previous = owner.peer();
    let mut disconnect = Box::pin(h.device.disassociate());
    if disconnect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
        || !h.closed()
    {
        return TestResult::Fail("AR9285 disconnect did not close before waiting for native owner");
    }
    h.device.link(previous);
    if !h.closed() {
        return TestResult::Fail("AR9285 stale native publisher reopened closed station");
    }
    drop(disconnect);
    drop(owner);
    h.pump();
    if !h.closed() || h.model.master.get() || h.model.tx.get().is_none() {
        return TestResult::Fail("AR9285 cancelled disconnect failed safe retained-DMA stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ar9285_native_device_disconnect_cancellation_and_stale_publication_stay_closed
);

fn smoke_ar9285_native_device_entropy_and_peer_deadline_fail_closed() -> TestResult {
    {
        let h = Harness::new(true);
        h.scan();
        h.env.entropy.store(false, Ordering::Release);
        let before = h.model.transmitted.borrow().len();
        if tests::complete(h.device.associate(h.request())).is_ok()
            || !h.closed()
            || h.model.transmitted.borrow().len() != before
        {
            return TestResult::Fail("AR9285 unavailable entropy published MLME or carrier");
        }
    }
    let h = Harness::new(false);
    h.join();
    h.env.now.fetch_add(6000, Ordering::AcqRel);
    h.pump();
    if !h.closed() || h.model.master.get() {
        return TestResult::Fail("AR9285 peer deadline retained carrier or packet DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ar9285_native_device_entropy_and_peer_deadline_fail_closed
);

fn smoke_ar9285_native_rekey_missing_m3_expires_despite_fresh_beacons() -> TestResult {
    use narf_wireless::eapol::{KeyFrame, KI_KEY_MIC};
    let h = Harness::new(true);
    h.join();
    let mappings = h
        .model
        .regions
        .borrow()
        .iter()
        .map(|r| (r.bus, r.cpu, r.len))
        .collect::<Vec<_>>();
    let before = h.model.transmitted.borrow().len();
    let wire = h.peer.lock().pairwise_rekey();
    h.model.inject(&wire, 0).unwrap();
    h.pump();
    let m2 = h.peer.lock().uplink.last().cloned().unwrap_or_default();
    let reply = m2.get(18..).and_then(|bytes| KeyFrame::decode(bytes, 16));
    if reply.is_none_or(|key| key.replay_counter != 3 || key.key_information & KI_KEY_MIC == 0)
        || m2.get(12..14) != Some(&[0x88, 0x8e])
        || h.model.transmitted.borrow().len() != before + 1
        || h.model.tx.get().is_some()
        || h.peer.lock().pairwise_replies != 1
        || !h.device.radio.try_lock().unwrap().ready()
        || !h.device.link_up()
    {
        return TestResult::Fail(
            "AR9285 rekey lacks real terminal old-key M2 and reopened old-key port",
        );
    }
    let probe = udp_ipv4(
        AP,
        h.plan.station,
        h.plan.lease_ip,
        h.plan.server_ip,
        49152,
        7,
        b"ar9285-missing-rekey-m3",
    );
    // Peer::react opens this actual DMA packet with the retained OLD TK. Its
    // candidate PTK was used only to check M2's MIC and was never installed.
    if h.device.enqueue(&probe, Default::default()).is_err() {
        return TestResult::Fail("AR9285 old-key DATA remained closed after terminal M2");
    }
    h.pump();
    if h.peer.lock().uplink.last() != Some(&probe)
        || h.model.tx.get().is_some()
        || !h.device.radio.try_lock().unwrap().ready()
    {
        return TestResult::Fail("AR9285 actual old-key DATA failed while awaiting replacement M3");
    }
    let start = h.env.now.load(Ordering::Acquire);
    for delta in [1000, 2000, 3000, 4000, 4999] {
        h.env.now.store(start + delta, Ordering::Release);
        let beacon = h.peer.lock().ap.beacon();
        h.model.inject(&beacon, 0).unwrap();
        h.pump();
        if !h.device.link_up() || !h.device.radio.try_lock().unwrap().ready() {
            return TestResult::Fail(
                "AR9285 valid beacons failed to retain the pre-deadline old-key station",
            );
        }
    }
    h.env.now.store(start + 5001, Ordering::Release);
    let beacon = h.peer.lock().ap.beacon();
    h.model.inject(&beacon, 0).unwrap();
    h.pump();
    let retained = h
        .model
        .regions
        .borrow()
        .iter()
        .map(|r| (r.bus, r.cpu, r.len))
        .collect::<Vec<_>>();
    if !h.closed()
        || h.model.master.get()
        || h.device.enqueue(&probe, Default::default()).is_ok()
        || h.device.radio.try_lock().unwrap().ready()
        || retained != mappings
        || h.model.tx.get().is_some()
    {
        return TestResult::Fail(
            "AR9285 fresh beacons hid M3 timeout or terminal failure lost retained DMA",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ar9285_native_rekey_missing_m3_expires_despite_fresh_beacons
);

fn smoke_ar9285_active_probe_native_open_wpa2_dhcp_and_bidirectional_ip() -> TestResult {
    for protected in [false, true] {
        if let TestResult::Fail(error) = composition_mode(protected, true) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/active-scan",
    smoke_ar9285_active_probe_native_open_wpa2_dhcp_and_bidirectional_ip
);

fn smoke_ar9285_drive_scheduled_retries_policy_and_stops_on_terminal_error() -> TestResult {
    use crate::ath9k::{BringUpError, RadioCalibration};
    let sample = RadioCalibration {
        country: [b'U', b'S'],
        frequency_mhz: 2412,
        max_power_half_dbm: 40,
        pa_offset: Some(0),
        iq_i: 0,
        iq_q: 0,
        measured_noise_dbm: -95,
        noise_dbm: -95,
    };

    // Case 1: retries on BringUpError::Policy and succeeds
    let attempts = core::cell::Cell::new(0);
    let waits = core::cell::Cell::new(0);
    let result = narf_scheduler::block_on(crate::ath9k::drive_scheduled(
        5,
        || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move {
                if n < 2 {
                    Err(BringUpError::Policy)
                } else {
                    Ok(sample)
                }
            }
        },
        || {
            waits.set(waits.get() + 1);
            async {}
        },
    ));
    if result != Ok(sample) || attempts.get() != 3 || waits.get() != 2 {
        return TestResult::Fail("ath9k drive_scheduled failed to retry on Policy");
    }

    // Case 2: terminates immediately on non-Policy error (e.g. BadState)
    attempts.set(0);
    waits.set(0);
    let result = narf_scheduler::block_on(crate::ath9k::drive_scheduled(
        10,
        || {
            let n = attempts.get();
            attempts.set(n + 1);
            async move { Err(BringUpError::BadState) }
        },
        || {
            waits.set(waits.get() + 1);
            async {}
        },
    ));
    if result != Err(BringUpError::BadState) || attempts.get() != 1 || waits.get() != 0 {
        return TestResult::Fail(
            "ath9k drive_scheduled did not terminate immediately on non-Policy error",
        );
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/device",
    smoke_ar9285_drive_scheduled_retries_policy_and_stops_on_terminal_error
);
fn smoke_ar9285_ht20_native_open_wpa2_all_mcs_kernel_dhcp_and_bidirectional_ip() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for protected in [false, true] {
        for mcs in 0..8 {
            if let failure @ TestResult::Fail(_) =
                composition_inner(protected, false, None, Some(1 << mcs))
            {
                return failure;
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_open_wpa2_all_mcs_kernel_dhcp_and_bidirectional_ip
);
fn aggregate_for(h: &Harness, pn: u64) -> (Vec<u8>, Vec<Vec<u8>>) {
    let (body, expected) = crate::ath9k::ht::tests::aggregate_body(h.plan.station);
    let mut header = vec![0x88, 0x42, 0, 0];
    header.extend_from_slice(&h.plan.station);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&[0x10, 0, 0x8f, 0]);
    let key: [u8; 16] = h
        .peer
        .lock()
        .ptk
        .as_ref()
        .unwrap()
        .tk
        .as_slice()
        .try_into()
        .unwrap();
    let mut body = body;
    let cipher =
        narf_wireless::ccmp::protect(&tests::Ccm, &header, &key, pn, 0, 15, false, &mut body)
            .unwrap();
    header.extend_from_slice(&cipher);
    (header, expected)
}
fn smoke_ar9285_ht20_native_final_allocation_and_callback_source_fences() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for point in [
        ReceivePoint::AfterFrameAllocation,
        ReceivePoint::BeforeCallbackAdmission,
    ] {
        let h = Harness::new_ht(true, 255);
        h.join();
        let (wire, _) = aggregate_for(&h, 9);
        let model = h.model.clone();
        let called = Arc::new(AtomicBool::new(false));
        let seen = called.clone();
        *h.device.receive_hook.lock() = Some(Arc::new(move |at| {
            if at == point && !seen.swap(true, Ordering::AcqRel) {
                model.allowed.set(false);
            }
        }));
        let before = h.rx_count();
        h.model.inject(&wire, 0).unwrap();
        h.device.drain();
        if !called.load(Ordering::Acquire)
            || !h.closed()
            || h.rx_count() != before
            || !h.received().is_empty()
        {
            return TestResult::Fail(
                "HT source lost at actual IPC/callback boundary still published",
            );
        }
        h.model.allowed.set(true);
        h.model.inject(&wire, 0).ok();
        h.pump();
        if !h.closed()
            || h.device
                .enqueue(
                    &udp_ipv4(
                        AP,
                        h.plan.station,
                        h.plan.lease_ip,
                        h.plan.server_ip,
                        1,
                        2,
                        b"closed",
                    ),
                    narf_net::TxMeta::plain(),
                )
                .is_ok()
        {
            return TestResult::Fail("restored current policy reopened terminal HT interface");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_final_allocation_and_callback_source_fences
);
fn smoke_ar9285_ht20_native_same_drain_group_reply_retires_aggregate_and_keeps_carrier(
) -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let h = Harness::new_ht(true, 255);
    h.join();
    let (wire, _) = aggregate_for(&h, 9);
    let group = {
        let mut p = h.peer.lock();
        p.hold_group = true;
        p.group_rekey()
    };
    h.model.inject(&wire, 0).unwrap();
    h.model.inject(&group, 0).unwrap();
    h.device.drain();
    if !h.device.link_up()
        || !h.received().is_empty()
        || h.peer.lock().group_replies != 1
        || h.model.tx.get().is_none()
        || h.device.radio.try_lock().unwrap().receive_open()
    {
        return TestResult::Fail(
            "same-drain group epoch leaked aggregate prefix/carrier or forged receipt",
        );
    }
    let (closed_wire, _) = aggregate_for(&h, 10);
    h.model.inject(&closed_wire, 0).unwrap();
    h.device.drain();
    h.model.complete(true).unwrap();
    h.pump();
    if !h.received().is_empty() || !h.device.radio.try_lock().unwrap().receive_open() {
        return TestResult::Fail("late group receipt published preauthorized ciphertext");
    }
    h.model.inject(&closed_wire, 0).unwrap();
    h.pump();
    if h.received().len() != 3 || !h.device.link_up() {
        return TestResult::Fail("closed-port capture advanced PN or fresh epoch failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_same_drain_group_reply_retires_aggregate_and_keeps_carrier
);
type HtCallback = Arc<dyn Fn(&mut [u8]) + Send + Sync>;
static HT_CALLBACK: IrqSafeSpinLock<Option<HtCallback>> = IrqSafeSpinLock::new(None);
fn ht_callback(_name: &str, bytes: &mut [u8]) {
    let callback = HT_CALLBACK.lock().clone();
    if let Some(f) = callback {
        f(bytes);
    }
}
struct RestoreHtCallback;
impl Drop for RestoreHtCallback {
    fn drop(&mut self) {
        *HT_CALLBACK.lock() = None;
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
    }
}
fn smoke_ar9285_ht20_native_reentrant_aggregate_rekey_epoch_and_ordinary_tx_credit() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for mode in 0..3 {
        let h = Arc::new(Harness::new_ht(true, 255));
        h.join();
        let (wire, expected) = aggregate_for(&h, 9);
        let group = h.peer.lock().group_rekey();
        let seen = Arc::new(IrqSafeSpinLock::new(Vec::<Vec<u8>>::new()));
        let count = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let okay = Arc::new(AtomicBool::new(true));
        let target = h.clone();
        let got = seen.clone();
        let calls = count.clone();
        let valid = okay.clone();
        *HT_CALLBACK.lock() = Some(Arc::new(move |bytes| {
            got.lock().push(bytes.to_vec());
            if calls.fetch_add(1, Ordering::AcqRel) != 0 {
                return;
            }
            // Actual stack callback must own none of the driver/radio/ring/
            // publication locks and can synchronously queue host TX+drain.
            if target.device.radio.try_lock().is_none()
                || target.device.state.try_lock().is_none()
                || target.device.publication.try_lock().is_none()
                || target.device.rx.try_lock().is_none()
                || target.device.tx.try_lock().is_none()
            {
                valid.store(false, Ordering::Release);
                return;
            }
            if mode == 0 {
                target.peer.lock().hold_data = true;
                let packet = udp_ipv4(
                    AP,
                    target.plan.station,
                    target.plan.lease_ip,
                    target.plan.server_ip,
                    100,
                    101,
                    b"held TX",
                );
                if target
                    .device
                    .enqueue(&packet, narf_net::TxMeta::plain())
                    .is_err()
                {
                    valid.store(false, Ordering::Release);
                }
                target.device.drain();
            } else {
                target.peer.lock().hold_group = mode == 1;
                target.model.inject(&group, 0).unwrap();
                target.device.drain();
                if mode == 2 {
                    target.device.drain();
                }
            }
        }));
        let _restore = RestoreHtCallback;
        narf_net::iface::install_rx_handler(ht_callback);
        h.model.inject(&wire, 0).unwrap();
        h.device.drain();
        if !okay.load(Ordering::Acquire)
            || !h.device.link_up()
            || *seen.lock()
                != if mode == 0 {
                    expected
                } else {
                    vec![expected[0].clone()]
                }
        {
            return TestResult::Fail("reentrant stack callback escaped key epoch or confused ordinary TX with receive port");
        }
        h.peer.lock().hold_data = false;
        if h.model.tx.get().is_some() {
            h.model.complete(true).unwrap();
        }
        h.pump();
        let (fresh, _) = aggregate_for(&h, 10);
        h.model.inject(&fresh, 0).unwrap();
        h.pump();
        if seen.lock().len() != if mode == 0 { 6 } else { 4 } {
            return TestResult::Fail(
                "fresh current receive epoch could not publish original aggregate",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_reentrant_aggregate_rekey_epoch_and_ordinary_tx_credit
);
fn smoke_ar9285_ht20_native_held_m4_pre_authorization_aggregate_has_no_late_pn_commit() -> TestResult
{
    let _policy = crate::ath9k::ht::tests::Policy::install();
    let h = Harness::new_ht(true, 255);
    h.scan();
    h.peer.lock().hold_m4 = true;
    let mut future = Box::pin(h.device.associate(h.request()));
    let mut reached = false;
    for _ in 0..256 {
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("held native HT M4 completed early");
        }
        if h.peer.lock().ap.phase() == narf_wifi_fixtures::ApPhase::Authorized
            && h.model.tx.get().is_some()
        {
            reached = true;
            break;
        }
    }
    if !reached || !h.closed() {
        return TestResult::Fail("initial held M4 published carrier");
    }
    let (wire, _) = aggregate_for(&h, 13);
    h.model.inject(&wire, 0).unwrap();
    for _ in 0..3 {
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("preauthorization RX supplied M4 receipt");
        }
    }
    h.model.complete(true).unwrap();
    if tests::complete(future).is_err() || !h.device.link_up() {
        return TestResult::Fail("exact positive native M4 could not authorize current link");
    }
    h.pump();
    if !h.received().is_empty() {
        return TestResult::Fail("late M4 retrospectively published old captured aggregate");
    }
    h.model.inject(&wire, 0).unwrap();
    h.pump();
    if h.received().len() != 3 {
        return TestResult::Fail("discarded pre-M4 native ciphertext advanced controlled-port PN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_held_m4_pre_authorization_aggregate_has_no_late_pn_commit
);
fn smoke_ar9285_rx_ba_native_open_wpa2_kernel_dhcp_and_bidirectional_ip() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for protected in [false, true] {
        if let failure @ TestResult::Fail(_) =
            composition_profile(protected, false, None, Some(255), Some(64), None)
        {
            return failure;
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_rx_ba_native_open_wpa2_kernel_dhcp_and_bidirectional_ip
);
fn smoke_ar9285_ht20_native_mixed_bss_protection_kernel_dhcp_and_bidirectional_ip() -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for protected in [false, true] {
        for ba in [None, Some(64)] {
            if let failure @ TestResult::Fail(_) =
                composition_profile(protected, false, None, Some(255), ba, Some((3, true)))
            {
                return failure;
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ht",
    smoke_ar9285_ht20_native_mixed_bss_protection_kernel_dhcp_and_bidirectional_ip
);
fn smoke_ar9285_native_ht_rx_ba_receive_runs_during_held_data_then_waits_for_rekey_receipt(
) -> TestResult {
    let _policy = crate::ath9k::ht::tests::Policy::install();
    for ba in [false, true] {
        let h = Harness::new_ht(true, 255);
        if ba {
            crate::ath9k::rx_ba::tests::qualify(&h.model, 64);
        }
        h.join();
        if ba {
            h.model
                .inject(&crate::ath9k::rx_ba::tests::addba(0, 0, 64, 0, true), 0)
                .unwrap();
            h.pump();
            h.model.rx_aggr.set((1 << 17) | (1 << 29));
        }
        h.peer.lock().hold_data = true;
        let up = udp_ipv4(
            AP,
            h.plan.station,
            h.plan.lease_ip,
            h.plan.server_ip,
            4501,
            4502,
            b"held actual data TX",
        );
        h.device.enqueue(&up, narf_net::TxMeta::plain()).unwrap();
        h.device.drain();
        let pending = h.model.tx.get().unwrap();
        let down = udp_ipv4(
            h.plan.station,
            AP,
            h.plan.server_ip,
            h.plan.lease_ip,
            4502,
            4501,
            b"fresh RX during held TX",
        );
        let wire = h.peer.lock().downlink(&down).unwrap();
        h.model.inject(&wire, 0).unwrap();
        h.device.drain();
        if h.model.tx.get() != Some(pending) || !h.received().contains(&down) || !h.device.link_up()
        {
            return TestResult::Fail(
                "ordinary native DATA credit stalled independent RX authorization",
            );
        }
        let group = {
            let mut peer = h.peer.lock();
            peer.hold_group = true;
            peer.group_rekey()
        };
        h.model.inject(&group, 0).unwrap();
        h.device.drain();
        if !h.device.link_up()
            || h.device.radio.try_lock().unwrap().receive_open()
            || h.peer.lock().group_replies != 0
            || h.device.enqueue(&up, narf_net::TxMeta::plain()).is_ok()
        {
            return TestResult::Fail(
                "actual rekey did not close RX while ordinary TX held, or forged free TX credit",
            );
        }
        h.model.complete(true).unwrap();
        h.device.drain();
        if h.peer.lock().group_replies != 1 || h.model.tx.get().is_none() {
            return TestResult::Fail(
                "terminal ordinary TX did not continue real pending group reply",
            );
        }
        let closed = h.peer.lock().downlink(&down).unwrap();
        h.model.inject(&closed, 0).unwrap();
        h.device.drain();
        assert!(h.received().is_empty());
        h.model.complete(true).unwrap();
        h.pump();
        h.model.inject(&closed, 0).unwrap();
        h.pump();
        if !h.received().contains(&down) || !h.device.link_up() {
            return TestResult::Fail(
                "closed rekey capture consumed BA sequence/PN or late native receipt failed",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/rx-ba",
    smoke_ar9285_native_ht_rx_ba_receive_runs_during_held_data_then_waits_for_rekey_receipt
);
