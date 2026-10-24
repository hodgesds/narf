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
        assert!(ACTIVE_TEST.lock().is_none());
        let tests::Fixture {
            radio,
            model,
            peer,
            env,
            plan,
        } = tests::fixture(protected).unwrap();
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
        let result = tests::complete(self.device.scan(ScanRequest {
            ssids: vec![SSID.to_vec()],
            frequencies_mhz: vec![2412],
            channels: vec![1],
            active: false,
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
        self.scan();
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
    let h = Harness::new(protected);
    if !h.closed() || narf_net::dhcp::acquire(h.device.name(), 100).is_ok() {
        return TestResult::Fail("AR9285 DHCP passed before real native association");
    }
    h.join();
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
    use narf_wireless::eapol::{
        KeyFrame, KI_KEY_ACK, KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE, KI_VERSION_HMAC_SHA1_AES,
    };
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
    let mut m1 = KeyFrame::empty(16);
    m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_VERSION_HMAC_SHA1_AES;
    m1.key_length = 16;
    m1.replay_counter = 3;
    m1.key_nonce = [0xbb; 32];
    let mut ethernet = h.plan.station.to_vec();
    ethernet.extend_from_slice(&AP);
    ethernet.extend_from_slice(&[0x88, 0x8e]);
    ethernet.extend_from_slice(&m1.into_eapol());
    let wire = h.peer.lock().downlink(&ethernet).unwrap();
    h.model.inject(&wire, 0).unwrap();
    h.pump();
    let m2 = h.peer.lock().uplink.last().cloned().unwrap_or_default();
    let reply = m2.get(18..).and_then(|bytes| KeyFrame::decode(bytes, 16));
    if reply.is_none_or(|key| key.replay_counter != 3 || key.key_information & KI_KEY_MIC == 0)
        || m2.get(12..14) != Some(&[0x88, 0x8e])
        || h.model.transmitted.borrow().len() != before + 1
        || h.model.tx.get().is_some()
        || !h.device.radio.try_lock().unwrap().ready()
        || !h.device.link_up()
    {
        return TestResult::Fail(
            "AR9285 rekey lacks real terminal old-key M2 and reopened old-key port",
        );
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
    let probe = udp_ipv4(
        AP,
        h.plan.station,
        h.plan.lease_ip,
        h.plan.server_ip,
        49152,
        7,
        b"ar9285-missing-rekey-m3",
    );
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
