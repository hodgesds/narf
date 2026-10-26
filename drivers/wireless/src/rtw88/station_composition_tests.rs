//! Actual retained firmware/calibration/packet/Device through kernel DHCP.
//! Synthetic radio assets stay inside the private model and grant no device authority.
use super::radio_tests::RadioIo;
use crate::rtw88::{firmware_lifecycle::Lifecycle, interface::Device, station::Environment};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Interface, TxMeta};
use narf_wifi_fixtures::{udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan};
use narf_wireless::eapol::{KeyFrame, KeyMgmt, Ptk};
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessNetIface};
#[path = "wmm_station_tests.rs"]
mod wmm_tests;
const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
const SSID: &[u8] = b"narf-8822ce";
const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
struct Env {
    clock: Arc<AtomicU64>,
    entropy: AtomicBool,
}
#[async_trait::async_trait]
impl Environment for Env {
    fn now_ms(&self) -> u64 {
        self.clock.load(Ordering::Acquire)
    }
    fn nonce(&self) -> Option<[u8; 32]> {
        self.entropy.load(Ordering::Acquire).then_some([0x33; 32])
    }
    async fn pause(&self) {
        let mut pending = true;
        core::future::poll_fn(|cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                self.clock.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        })
        .await;
    }
}
struct Ccm;
impl narf_wireless::ccmp::AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body)
            .map_err(|_| narf_wireless::ccmp::CcmpError::TooLong)
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
}
pub(in crate::rtw88) struct Peer {
    pub(in crate::rtw88) wmm: Option<Vec<u8>>,
    pub(in crate::rtw88) qos: bool,
    pub(in crate::rtw88) association: Option<Vec<u8>>,
    pub(in crate::rtw88) response_rates: Option<Vec<u8>>,
    pub(in crate::rtw88) response_wmm: Option<Option<Vec<u8>>>,
    pub(in crate::rtw88) ht: Option<Vec<u8>>,
    pub(in crate::rtw88) declines: Vec<Vec<u8>>,
    pub(in crate::rtw88) hold_decline: bool,
    pub(in crate::rtw88) ap: FakeAp,
    pub(in crate::rtw88) plan: NetworkPlan,
    pub(super) server: DhcpServer,
    pub(in crate::rtw88) ptk: Option<Ptk>,
    pub(super) replay: narf_wireless::ccmp::ReplayWindow,
    pub(in crate::rtw88) pn: u64,
    pub(in crate::rtw88) uplink: Vec<Vec<u8>>,
    pub(in crate::rtw88) hold_m4: bool,
    pub(in crate::rtw88) hold_data: bool,
}
impl Peer {
    pub(in crate::rtw88) fn new(protected: bool) -> Self {
        let plan = NetworkPlan {
            station: OWN,
            bssid: AP,
            server_ip: [10, 88, 1, 1],
            lease_ip: [10, 88, 1, 42],
            netmask: [255, 255, 255, 0],
            lease_seconds: 3600,
        };
        let ap = if protected {
            FakeAp::wpa2(plan, SSID, 1, 42, PMK, ANONCE)
        } else {
            FakeAp::open(plan, SSID, 1, 42)
        }
        .unwrap()
        .with_basic_1mbps()
        .unwrap();
        Self {
            wmm: None,
            qos: false,
            association: None,
            response_rates: None,
            response_wmm: None,
            ht: None,
            declines: Vec::new(),
            hold_decline: false,
            ap,
            plan,
            server: DhcpServer::new(plan),
            ptk: None,
            replay: narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 },
            pn: 1,
            uplink: Vec::new(),
            hold_m4: false,
            hold_data: false,
        }
    }
    pub(in crate::rtw88) fn downlink(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut frame = vec![
            if self.qos { 0x88 } else { 8 },
            if self.ap.protected() { 0x42 } else { 2 },
            0,
            0,
        ];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&AP);
        frame.extend_from_slice(&ethernet[6..12]);
        frame.extend_from_slice(&[0, 0]);
        if self.qos {
            frame.extend_from_slice(&[0, 0]);
        }
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
        body.extend_from_slice(&ethernet[12..]);
        if self.ap.protected() {
            let key: &[u8; 16] = self
                .ptk
                .as_ref()
                .ok_or("AP missing TK")?
                .tk
                .as_slice()
                .try_into()
                .map_err(|_| "AP TK extent")?;
            body = narf_wireless::ccmp::protect(&Ccm, &frame, key, self.pn, 0, 0, false, &mut body)
                .map_err(|_| "AP downlink CCMP")?;
            self.pn += 1;
        }
        frame.extend_from_slice(&body);
        Ok(frame)
    }
    pub(in crate::rtw88) fn react(
        &mut self,
        frame: &[u8],
    ) -> Result<(Vec<Vec<u8>>, bool), &'static str> {
        if frame.len() < 24 || frame[4..10] != AP || frame[10..16] != self.plan.station {
            return Err("native AP peer identity");
        }
        if frame[0] == 0xd0 {
            if frame.len() != 33 || frame[24..26] != [3, 1] || frame[27..29] != [37, 0] {
                return Err("native ADDBA decline differs");
            }
            self.declines.push(frame.to_vec());
            return Ok((Vec::new(), self.hold_decline));
        }
        if self.ap.phase() != ApPhase::Authorized || matches!(frame[0], 0 | 0xb0) {
            let before = self.ap.phase();
            if frame[0] == 0 {
                let count = frame
                    .get(28..)
                    .ok_or("native association IE extent")?
                    .windows(9)
                    .filter(|w| *w == narf_wireless::wmm::INFORMATION)
                    .count();
                if count > 1 || count == 1 && self.wmm.is_none() {
                    return Err("unexpected native station WMM Information IE");
                }
                self.qos = count == 1;
                self.association = Some(frame.to_vec());
            }
            let mut replies = self
                .ap
                .receive(frame)
                .map_err(|_| "shared AP rejected real native MLME/EAPOL")?;
            for response in &mut replies {
                if response.first() == Some(&0x10) {
                    if let Some(rates) = &self.response_rates {
                        let mut native = response[..30].to_vec();
                        let mut ies = &response[30..];
                        while !ies.is_empty() {
                            let end = 2 + usize::from(*ies.get(1).ok_or("AP response extent")?);
                            let ie = ies.get(..end).ok_or("AP response IE extent")?;
                            if !matches!(ie[0], 1 | 50) {
                                native.extend_from_slice(ie);
                            }
                            ies = &ies[end..];
                        }
                        let split = rates.len().min(8);
                        native.extend_from_slice(&[1, split as u8]);
                        native.extend_from_slice(&rates[..split]);
                        if rates.len() > split {
                            native.extend_from_slice(&[50, (rates.len() - split) as u8]);
                            native.extend_from_slice(&rates[split..]);
                        }
                        *response = native;
                    }
                    if let Some(wmm) = self
                        .response_wmm
                        .as_ref()
                        .map_or(self.wmm.as_ref(), |p| p.as_ref())
                    {
                        response.extend_from_slice(wmm);
                    }
                    if let Some(ht) = &self.ht {
                        response.extend_from_slice(ht);
                    }
                }
            }
            if before == ApPhase::Message2 {
                let key =
                    KeyFrame::decode(frame.get(36..).ok_or("M2 extent")?, 16).ok_or("M2 key")?;
                self.ptk = Some(narf_wireless::eapol::wpa_pmk_to_ptk(
                    KeyMgmt::Psk,
                    &PMK,
                    &AP,
                    &self.plan.station,
                    &ANONCE,
                    &key.key_nonce,
                    16,
                ));
            }
            return Ok((replies, before == ApPhase::Message4 && self.hold_m4));
        }
        let header = if self.qos && frame[0] == 0x88 { 26 } else { 24 };
        if frame.len() < header
            || !matches!(frame[0], 8 | 0x88)
            || frame[0] == 0x88 && !self.qos
            || header == 26 && frame[24..26] != [0, 0]
            || frame[1] & 3 != 1
            || (frame[1] & 0x40 != 0) != self.ap.protected()
        {
            return Err("native AP data protection/direction");
        }
        let mut body = frame[header..].to_vec();
        if self.ap.protected() {
            let key: &[u8; 16] = self
                .ptk
                .as_ref()
                .ok_or("AP missing uplink TK")?
                .tk
                .as_slice()
                .try_into()
                .map_err(|_| "AP uplink TK extent")?;
            body = narf_wireless::ccmp::unprotect(
                &Ccm,
                &frame[..header],
                key,
                0,
                false,
                &mut self.replay,
                &mut body,
            )
            .map_err(|_| "AP uplink CCMP/MIC/replay")?;
        }
        if body.get(..6) != Some(&[0xaa, 0xaa, 3, 0, 0, 0]) {
            return Err("native AP RFC1042 extent");
        }
        let mut ethernet = frame[16..22].to_vec();
        ethernet.extend_from_slice(&frame[10..16]);
        ethernet.extend_from_slice(&body[6..]);
        if self.qos && header == 24 && ethernet.get(12..14) != Some(&[0x88, 0x8e]) {
            return Err("native WMM non-QoS data is not private EAPOL");
        }
        self.uplink.push(ethernet.clone());
        let replies = match self.server.receive(&ethernet) {
            Some(reply) => vec![self.downlink(&reply)?],
            None => Vec::new(),
        };
        Ok((replies, self.hold_data))
    }
}

type TestDevice = Device<RadioIo>;
static ACTIVE_TEST: IrqSafeSpinLock<Option<Arc<TestDevice>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: TxMeta) -> Result<(), ()> {
    let device = ACTIVE_TEST.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE_TEST.lock().clone();
    device.is_some_and(|device| device.drain())
}
fn complete<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    for _ in 0..100_000 {
        if let Poll::Ready(value) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            return value;
        }
    }
    panic!("RTL8822CE retained station fixture stalled");
}
struct Harness {
    device: Arc<TestDevice>,
    lifecycle: Arc<Lifecycle<RadioIo>>,
    peer: Arc<IrqSafeSpinLock<Peer>>,
    env: Arc<Env>,
    plan: NetworkPlan,
    calibration: narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
}
impl Harness {
    fn new(protected: bool) -> Self {
        assert!(ACTIVE_TEST.lock().is_none());
        let mut io = RadioIo::new();
        let env = Arc::new(Env {
            clock: io.clock.clone(),
            entropy: AtomicBool::new(true),
        });
        let peer = Arc::new(IrqSafeSpinLock::new(Peer::new(protected)));
        let plan = peer.lock().plan;
        let actor = peer.clone();
        io.packets.reaction = Some(Arc::new(move |bytes| {
            actor
                .lock()
                .react(bytes)
                .map_err(|_| crate::rtw88::packet_core::Error::Packet)
        }));
        let lifecycle = Arc::new(Lifecycle::new(0xc822));
        let name = narf_net::iface::reserve_name("r88-native%d");
        let device = Arc::new(Device::new(name, OWN, lifecycle.clone(), env.clone()));
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::register(name, OWN, send);
        narf_net::iface::set_link_state(name, true); // operator IFF_UP, not PHY state
        narf_net::iface::set_link_metadata(name, false, None, None);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        device.admit_for_test();
        // This exact lifecycle retains the one firmware/radio owner before
        // its first simulated firmware publication and all real packet DMA.
        complete(lifecycle.initialize_bytes(move || Ok(io), super::mac_tests::firmware())).unwrap();
        complete(lifecycle.prepare_mac()).unwrap();
        let factory = super::power_policy_tests::make_factory(0, 60);
        complete(lifecycle.prepare_phy_tables(&factory)).unwrap();
        let board = {
            let retained = lifecycle.retained.try_lock().unwrap();
            let owner = retained.as_ref().unwrap();
            crate::rtw88::power_policy::Board::new(
                &factory,
                owner.phy_info().unwrap(),
                owner.hardware_info().unwrap(),
                owner.image_digest().unwrap(),
            )
            .unwrap()
        };
        let calibration = narf_capabilities::Cap::bootstrap();
        let domain = super::power_policy_tests::domain();
        let source = super::power_policy_tests::source(
            super::power_policy_tests::image(board, &factory),
            calibration,
        );
        let permission =
            complete(lifecycle.qualify_board_with_source(&factory, &domain, source)).unwrap();
        {
            let mut retained = lifecycle.retained.try_lock().unwrap();
            let owner = retained.as_mut().unwrap();
            owner.io.arm_calibration();
            *owner.io.policy.lock() = domain.clone();
        }
        complete(lifecycle.prepare_radio_with_policy(&factory, permission, || Ok(domain.clone())))
            .unwrap();
        complete(device.activate()).unwrap();
        {
            let beacon = peer.lock().ap.beacon();
            let mut retained = lifecycle.retained.try_lock().unwrap();
            retained
                .as_mut()
                .unwrap()
                .io
                .packets
                .receive(&beacon, false, false);
        }
        Self {
            device,
            lifecycle,
            peer,
            env,
            plan,
            calibration,
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
        let seen = complete(self.device.scan(ScanRequest {
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
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].bssid, AP);
        assert_eq!(seen[0].ssid, SSID);
    }
    fn join(&self) {
        self.scan();
        complete(self.device.associate(self.request())).unwrap();
        assert!(self.device.link_up());
        assert_eq!(self.device.connected_bssid(), Some(AP));
    }
    fn model<T>(&self, operation: impl FnOnce(&mut RadioIo) -> T) -> T {
        let mut retained = self.lifecycle.retained.try_lock().unwrap();
        operation(&mut retained.as_mut().unwrap().io)
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
                .is_some_and(|iface| iface.link_up && !iface.carrier)
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
        return TestResult::Fail("RTL8822CE DHCP passed before native association");
    }
    h.join();
    let lease = match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
        Ok(lease) => lease,
        Err(_) => return TestResult::Fail("RTL8822CE actual kernel DHCP failed"),
    };
    if !h.plan.matches_lease(&lease) {
        return TestResult::Fail("RTL8822CE native DORA lease differs");
    }
    {
        let peer = h.peer.lock();
        let seen = peer.server.observations();
        if seen.discovers != 1 || seen.requests != 1 || peer.uplink.len() != 2 {
            return TestResult::Fail("RTL8822CE native DHCP receipts differ");
        }
    }
    let uplink = udp_ipv4(
        AP,
        OWN,
        h.plan.lease_ip,
        h.plan.server_ip,
        49152,
        7,
        b"rtw8822ce-native-uplink",
    );
    if narf_net::iface::send_on(h.device.name(), &uplink).is_err() {
        return TestResult::Fail("RTL8822CE native IP TX refused");
    }
    h.pump();
    if h.peer.lock().uplink.last() != Some(&uplink) {
        return TestResult::Fail("RTL8822CE actual DMA IP TX differs");
    }
    let downlink = udp_ipv4(
        OWN,
        AP,
        h.plan.server_ip,
        h.plan.lease_ip,
        7,
        49152,
        b"rtw8822ce-native-downlink",
    );
    let wire = h.peer.lock().downlink(&downlink).unwrap();
    h.model(|io| io.packets.receive(&wire, false, false));
    h.pump();
    if !h.received().contains(&downlink) {
        return TestResult::Fail("RTL8822CE native IP RX differs");
    }
    if complete(h.device.disassociate()).is_err() || !h.closed() || h.model(|io| io.packets.active)
    {
        return TestResult::Fail("RTL8822CE terminal disconnect not parked");
    }
    if h.device.enqueue(&uplink, TxMeta::default()).is_ok() {
        return TestResult::Fail("RTL8822CE disconnected packet publication reopened");
    }
    TestResult::Pass
}
fn smoke_rtw8822ce_earned_native_device_open_kernel_dhcp_ip() -> TestResult {
    composition(false)
}
fn smoke_rtw8822ce_earned_native_device_wpa2_kernel_dhcp_ip() -> TestResult {
    composition(true)
}
kernel_test_in!(
    "drivers/wireless/rtw88/station",
    smoke_rtw8822ce_earned_native_device_open_kernel_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw88/station",
    smoke_rtw8822ce_earned_native_device_wpa2_kernel_dhcp_ip
);

fn smoke_rtw8822ce_native_m4_requires_exact_terminal_receipt_and_idle_peer() -> TestResult {
    // Each case traverses the real firmware, factory, calibration, mailbox,
    // DMA, host EAPOL and public Device path before the actual M4 is held.
    for case in 0..4 {
        let h = Harness::new(true);
        h.scan();
        h.peer.lock().hold_m4 = true;
        let controls = h.model(|io| io.packets.controls.clone());
        let mut future = Box::pin(h.device.associate(h.request()));
        for _ in 0..500 {
            if controls.held.load(Ordering::Acquire) {
                break;
            }
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("RTL8822CE held M4 completed association");
            }
        }
        if !controls.held.load(Ordering::Acquire)
            || !h.closed()
            || h.peer.lock().ap.phase() != ApPhase::Authorized
            || narf_net::dhcp::acquire(h.device.name(), 100).is_ok()
        {
            return TestResult::Fail("RTL8822CE M4 did not retain an actual closed DMA wait");
        }
        match case {
            0 => {
                drop(future);
                controls.release.store(true, Ordering::Release);
                h.pump();
                if !h.device.closed() || !h.closed() || h.model(|io| io.packets.active) {
                    return TestResult::Fail(
                        "RTL8822CE cancelled M4 later reopened or kept DMA active",
                    );
                }
                continue;
            }
            1 => controls.corrupt_receipt.store(true, Ordering::Release),
            2 => {
                let mut deauth = vec![0xc0, 0, 0, 0];
                deauth.extend_from_slice(&OWN);
                deauth.extend_from_slice(&AP);
                deauth.extend_from_slice(&AP);
                deauth.extend_from_slice(&[0, 0, 1, 0]);
                controls.incoming.lock().push_back(deauth);
            }
            _ => {}
        }
        controls.release.store(true, Ordering::Release);
        let result = complete(future);
        if case == 3 {
            if result.is_err() || !h.device.link_up() {
                return TestResult::Fail("RTL8822CE exact terminal M4 failed to authorize");
            }
            complete(h.device.disassociate()).unwrap();
        } else if result.is_ok() || !h.closed() || h.model(|io| io.packets.active) {
            return TestResult::Fail("RTL8822CE altered M4 or queued peer loss authorized");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/station",
    smoke_rtw8822ce_native_m4_requires_exact_terminal_receipt_and_idle_peer
);

fn smoke_rtw8822ce_native_entropy_peer_deadline_and_current_power_close() -> TestResult {
    let h = Harness::new(true);
    h.scan();
    h.env.entropy.store(false, Ordering::Release);
    let before = h.model(|io| io.packets.tx_publications);
    if complete(h.device.associate(h.request())).is_ok()
        || !h.closed()
        || h.model(|io| io.packets.tx_publications) != before
    {
        return TestResult::Fail("RTL8822CE entropy failure published authentication");
    }
    drop(h);
    for case in 0..3 {
        let h = Harness::new(false);
        h.join();
        match case {
            0 => {
                h.env.clock.fetch_add(6000, Ordering::AcqRel);
            }
            1 => h.calibration.revoke(),
            _ => h.model(|io| io.policy.lock().rules.clear()),
        }
        h.pump();
        if !h.closed() || h.model(|io| io.packets.active) {
            return TestResult::Fail(
                "RTL8822CE expired peer or lost current power retained traffic",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/station",
    smoke_rtw8822ce_native_entropy_peer_deadline_and_current_power_close
);

fn smoke_rtw8822ce_native_rekey_missing_m3_expires_despite_fresh_beacons() -> TestResult {
    use narf_wireless::eapol::{
        KI_KEY_ACK, KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE, KI_VERSION_HMAC_SHA1_AES,
    };
    let h = Harness::new(true);
    h.join();
    let before = h.model(|io| io.packets.tx_publications);
    let mut m1 = KeyFrame::empty(16);
    m1.key_information = KI_KEY_TYPE_PAIRWISE | KI_KEY_ACK | KI_VERSION_HMAC_SHA1_AES;
    m1.key_length = 16;
    m1.replay_counter = 3;
    m1.key_nonce = [0xbb; 32];
    let mut ethernet = OWN.to_vec();
    ethernet.extend_from_slice(&AP);
    ethernet.extend_from_slice(&[0x88, 0x8e]);
    ethernet.extend_from_slice(&m1.into_eapol());
    let wire = h.peer.lock().downlink(&ethernet).unwrap();
    h.model(|io| io.packets.receive(&wire, false, false));
    h.pump();
    let m2 = h.peer.lock().uplink.last().cloned().unwrap_or_default();
    let reply = m2.get(18..).and_then(|bytes| KeyFrame::decode(bytes, 16));
    if reply.is_none_or(|key| key.replay_counter != 3 || key.key_information & KI_KEY_MIC == 0)
        || m2.get(12..14) != Some(&[0x88, 0x8e])
        || h.model(|io| io.packets.tx_publications) != before + 1
        || !h
            .lifecycle
            .retained
            .try_lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .station_ready()
        || !h.device.link_up()
    {
        return TestResult::Fail("RTL8822CE rekey lacks terminal old-key M2 and reopened old port");
    }
    let start = h.env.clock.load(Ordering::Acquire);
    for delta in [1000, 2000, 3000, 4000, 4999, 5001] {
        h.env.clock.store(start + delta, Ordering::Release);
        let beacon = h.peer.lock().ap.beacon();
        h.model(|io| io.packets.receive(&beacon, false, false));
        h.pump();
        if delta < 5000 && !h.device.link_up() {
            return TestResult::Fail("RTL8822CE rekey prematurely lost established carrier");
        }
    }
    if !h.closed() || h.model(|io| io.packets.active) {
        return TestResult::Fail("RTL8822CE fresh beacons hid whole-rekey M3 timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/station",
    smoke_rtw8822ce_native_rekey_missing_m3_expires_despite_fresh_beacons
);

fn smoke_rtw8822ce_native_publication_rechecks_actual_calibration_epoch() -> TestResult {
    let h = Harness::new(false);
    h.join();
    let uplink = udp_ipv4(
        AP,
        OWN,
        h.plan.lease_ip,
        h.plan.server_ip,
        49152,
        7,
        b"epoch-edge",
    );
    let mut wrong = uplink.clone();
    wrong[6] ^= 1;
    if h.device.enqueue(&wrong, TxMeta::default()).is_ok()
        || h.device
            .enqueue(
                &uplink,
                TxMeta {
                    tso_mss: Some(100),
                    ..TxMeta::default()
                },
            )
            .is_ok()
    {
        return TestResult::Fail("RTL8822CE queue accepted foreign source or unsupported offload");
    }
    h.device.enqueue(&uplink, TxMeta::default()).unwrap();
    let cap = h.calibration;
    let before = h.model(|io| {
        io.packets.after_descriptor = Some(Arc::new(move || {
            cap.revoke();
        }));
        io.packets.tx_publications
    });
    h.pump();
    if !h.closed()
        || h.model(|io| io.packets.active || io.packets.tx_publications != before)
        || !h.peer.lock().uplink.is_empty()
    {
        return TestResult::Fail("RTL8822CE revoked calibration after BD copy still rang doorbell");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/station",
    smoke_rtw8822ce_native_publication_rechecks_actual_calibration_epoch
);

fn smoke_rtw8822ce_native_disconnect_reservation_and_cancel_preserve_cleanup() -> TestResult {
    for cancel in [false, true] {
        let h = Harness::new(false);
        h.join();
        let retained = h.lifecycle.retained.try_lock().unwrap();
        let mut future = Box::pin(h.device.disassociate());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
            || !h.closed()
            || !h.device.admission().teardown_pending()
            || !retained.as_ref().unwrap().io.packets.active
        {
            return TestResult::Fail("RTL8822CE disconnect failed to reserve before owner wait");
        }
        drop(retained);
        h.pump();
        if !h.model(|io| io.packets.active) {
            return TestResult::Fail(
                "RTL8822CE worker terminalized native owner before media-down",
            );
        }
        if cancel {
            drop(future);
            h.pump();
        } else if complete(future).is_err() {
            return TestResult::Fail("RTL8822CE reserved disconnect could not finish cleanup");
        }
        if !h.closed() || h.model(|io| io.packets.active) || h.device.admission().teardown_pending()
        {
            return TestResult::Fail("RTL8822CE finished or cancelled disconnect retained traffic");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/station",
    smoke_rtw8822ce_native_disconnect_reservation_and_cancel_preserve_cleanup
);
