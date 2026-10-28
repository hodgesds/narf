//! Real native RTL8188EU Device/Service/Station/USB composition. Only the EP0
//! and bulk endpoints are inert models. Firmware/IQK, signed-metadata parsing,
//! MAC admission, management/RSNA, software CCMP, Narf-Rings, stack dispatch and
//! the DHCP client run through their production implementations.
//! Synthetic power qualification stays inside the existing private test seam;
//! these bytes never enter a firmware registry or qualify any physical board.
use super::super::super::{
    firmware_transport_tests::{initialized_firmware, Fake},
    interface::Device,
    packet_codec::{MAX_TRANSFER, TX_DESC},
    packet_transport::Io,
    receive_runtime::{Permission as ReceivePermission, Receiver},
    service_runtime::{Environment, Error as ServiceError, Service},
};
use super::native_permission;
use alloc::{boxed::Box, collections::VecDeque, string::String, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_drivers_usb::device::UsbError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::Interface;
use narf_wifi_fixtures::{dhcp_message_type, udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan};
use narf_wireless::eapol::{KeyFrame, KeyMgmt, Ptk};
use narf_wireless::{AssociateRequest, ScanRequest, SecurityConfig, WirelessNetIface};

const AP: [u8; 6] = [2, 0x18, 0x88, 0, 0, 2];
const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
const SSID: &[u8] = b"narf-basic1";

macro_rules! ensure {
    ($condition:expr, $reason:literal) => {
        if !$condition {
            return Err($reason);
        }
    };
}
fn plan(station: [u8; 6]) -> NetworkPlan {
    NetworkPlan {
        station,
        bssid: AP,
        server_ip: [10, 88, 0, 1],
        lease_ip: [10, 88, 0, 42],
        netmask: [255, 255, 255, 0],
        lease_seconds: 3600,
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
struct Tx {
    id: u64,
    bytes: usize,
    m4: bool,
    data: bool,
    control: bool,
}
struct Peer {
    ht: bool,
    response_ht: Option<Vec<u8>>,
    response_wmm: bool,
    declines: usize,
    actions: Vec<Vec<u8>>,
    native_tx: Vec<Vec<u8>>,
    raw_queue: VecDeque<Vec<u8>>,
    rekey: Option<u8>,
    rekey_ptk: Option<Ptk>,
    hold_control: bool,
    ap: FakeAp,
    network: NetworkPlan,
    server: DhcpServer,
    ptk: Option<Ptk>,
    replay: narf_wireless::ccmp::ReplayWindow,
    next_pn: u64,
    next_receipt: u64,
    rx: Option<u64>,
    tx: Option<Tx>,
    queue: VecDeque<Vec<u8>>,
    uplink: Vec<(Vec<u8>, bool)>,
    downlink: Vec<Vec<u8>>,
    sent: usize,
    posts: usize,
    stops: usize,
    hold_m4: bool,
    hold_data: bool,
    fail_stop: bool,
    error: Option<&'static str>,
}
impl Peer {
    fn new(network: NetworkPlan, protected: bool) -> Self {
        let ap = if protected {
            FakeAp::wpa2(network, SSID, 1, 42, PMK, ANONCE)
        } else {
            FakeAp::open(network, SSID, 1, 42)
        }
        .unwrap()
        .with_basic_1mbps()
        .unwrap();
        Self {
            ht: false,
            response_ht: None,
            response_wmm: true,
            declines: 0,
            actions: Vec::new(),
            native_tx: Vec::new(),
            raw_queue: VecDeque::new(),
            rekey: None,
            rekey_ptk: None,
            hold_control: false,
            ap,
            network,
            server: DhcpServer::new(network),
            ptk: None,
            replay: narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 },
            next_pn: 1,
            next_receipt: 0,
            rx: None,
            tx: None,
            queue: VecDeque::new(),
            uplink: Vec::new(),
            downlink: Vec::new(),
            sent: 0,
            posts: 0,
            stops: 0,
            hold_m4: false,
            hold_data: false,
            fail_stop: false,
            error: None,
        }
    }
    fn downlink(&mut self, ethernet: &[u8]) -> Result<(), &'static str> {
        ensure!(
            ethernet.len() >= 14 && ethernet[..6] == self.network.station,
            "AP downlink identity"
        );
        let mut frame = vec![
            if self.ht { 0x88 } else { 8 },
            if self.ap.protected() { 0x42 } else { 2 },
            0,
            0,
        ];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&AP);
        frame.extend_from_slice(&ethernet[6..12]);
        frame.extend_from_slice(&[0, 0]);
        if self.ht {
            frame.extend_from_slice(&[0, 0]);
        }
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
        body.extend_from_slice(&ethernet[12..]);
        if self.ap.protected() {
            let tk: &[u8; 16] = self
                .ptk
                .as_ref()
                .ok_or("AP missing authorized TK")?
                .tk
                .as_slice()
                .try_into()
                .map_err(|_| "AP TK extent")?;
            body = narf_wireless::ccmp::protect(
                &Ccm,
                &frame,
                tk,
                self.next_pn,
                0,
                0,
                false,
                &mut body,
            )
            .map_err(|_| "AP downlink CCMP")?;
            self.next_pn += 1;
        }
        frame.extend_from_slice(&body);
        self.downlink.push(ethernet.to_vec());
        self.queue.push_back(frame);
        Ok(())
    }
    fn react(&mut self, frame: &[u8]) -> Result<(bool, bool), &'static str> {
        ensure!(
            frame.len() >= 24 && frame[4..10] == AP && frame[10..16] == self.network.station,
            "USB frame peer/direction"
        );
        if frame[0] == 0xd0 {
            // Driver-owned BA actions: ADDBA Response (33) or DELBA (30).
            ensure!(
                self.ht
                    && (frame.len() == 33 && matches!(frame[24..26], [3, 0] | [3, 1])
                        || frame.len() == 30 && frame[24..26] == [3, 2]),
                "EU wrong native BA action"
            );
            self.declines += 1;
            self.actions.push(frame.to_vec());
            return Ok((false, false));
        }
        if let Some(stage) = self.rekey {
            // Retained shared Security encrypts rekey replies with the OLD
            // installed packet key. The proposed EAPOL PTK is separate until
            // the actual M4 reaches this native peer; never read ciphertext
            // as plaintext SNAP or install proposed material after M2.
            let body = if frame[0] == 8 {
                ensure!(
                    frame[1] & 0xc7 == 0x41,
                    "EU rekey reply skipped old-key CCMP"
                );
                let mut wire = frame[24..].to_vec();
                narf_wireless::ccmp::unprotect(
                    &Ccm,
                    &frame[..24],
                    self.ptk
                        .as_ref()
                        .ok_or("EU missing old rekey TK")?
                        .tk
                        .as_slice()
                        .try_into()
                        .map_err(|_| "EU old rekey TK extent")?,
                    0,
                    false,
                    &mut self.replay,
                    &mut wire,
                )
                .map_err(|_| "EU rekey reply old-key CCMP/PN")?
            } else {
                Vec::new()
            };
            if body.get(..8) == Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]) {
                let key = KeyFrame::decode(body.get(12..).ok_or("EU rekey key extent")?, 16)
                    .ok_or("EU rekey key")?;
                ensure!(
                    key.replay_counter == if stage == 1 { 3 } else { 4 },
                    "EU rekey replay mismatch"
                );
                if stage == 1 {
                    // Established-PTK M2 carries SECURE as well as descriptor
                    // version2, PAIRWISE and MIC (the initial M2 is0x010a).
                    ensure!(key.key_information == 0x30a, "EU rekey M2 flags");
                    self.rekey_ptk = Some(narf_wireless::eapol::wpa_pmk_to_ptk(
                        KeyMgmt::Psk,
                        &PMK,
                        &AP,
                        &self.network.station,
                        &[0xab; 32],
                        &key.key_nonce,
                        16,
                    ));
                } else {
                    ensure!(key.key_information == 0x30a, "EU rekey M4 flags");
                }
                let mut authenticated = body[8..].to_vec();
                let mic = authenticated[81..97].to_vec();
                authenticated[81..97].fill(0);
                let ptk = self.rekey_ptk.as_ref().ok_or("EU proposed rekey PTK")?;
                ensure!(
                    narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.kck, &authenticated)[..16] == mic,
                    "EU rekey reply MIC"
                );
                if stage == 1 {
                    let reply = rekey_message(self.network.station, 0x13ca, 4, Some(ptk))?;
                    self.queue.push_back(reply);
                    self.rekey = Some(2);
                } else {
                    ensure!(
                        self.ptk.as_ref().is_some_and(|old| old.tk != ptk.tk),
                        "EU rekey fixture did not produce genuinely new packet material"
                    );
                    self.ptk = self.rekey_ptk.take();
                    self.rekey = None;
                    self.next_pn = 1;
                    self.replay.last_seen_pn = 0; // A genuinely new installed peer TK.
                }
                return Ok((true, false));
            }
        }
        if self.ap.phase() != ApPhase::Authorized || matches!(frame[0], 0 | 0xb0) {
            let before = self.ap.phase();
            if self.ht && frame[0] == 0 {
                ensure!(
                    frame.windows(4).any(|x| x == [45, 26, 12, 0])
                        && frame
                            .windows(9)
                            .any(|x| x == narf_wireless::wmm::INFORMATION),
                    "EU missing driver-owned HT/WMM request"
                );
            }
            let mut replies = self
                .ap
                .receive(frame)
                .map_err(|_| "shared AP rejected real management/EAPOL")?;
            if self.ht {
                for reply in &mut replies {
                    if reply.first() == Some(&0x10) {
                        if self.response_wmm {
                            reply.extend_from_slice(&super::ht_tests::WMM);
                        }
                        if let Some(ht) = &self.response_ht {
                            reply.extend_from_slice(ht);
                        }
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
                    &self.network.station,
                    &ANONCE,
                    &key.key_nonce,
                    16,
                ));
            }
            self.queue.extend(replies);
            return Ok((before == ApPhase::Message4, false));
        }
        ensure!(
            frame[0] == if self.ht { 0x88 } else { 8 } && frame[1] & 3 == 1,
            "USB data is not native ToDS"
        );
        let protected = frame[1] & 0x40 != 0;
        ensure!(
            protected == self.ap.protected(),
            "data crossed controlled port with wrong protection"
        );
        let header = if frame[0] == 0x88 {
            ensure!(
                frame.get(24..26) == Some(&[0, 0]),
                "EU native QoS TID0 changed"
            );
            26
        } else {
            24
        };
        let mut body = frame[header..].to_vec();
        if protected {
            let tk: &[u8; 16] = self
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
                tk,
                0,
                false,
                &mut self.replay,
                &mut body,
            )
            .map_err(|_| "AP uplink CCMP/MIC/replay")?;
        }
        ensure!(
            body.get(..6) == Some(&[0xaa, 0xaa, 3, 0, 0, 0]),
            "uplink RFC1042 extent"
        );
        let mut ethernet = frame[16..22].to_vec();
        ethernet.extend_from_slice(&frame[10..16]);
        ethernet.extend_from_slice(&body[6..]);
        self.uplink.push((ethernet.clone(), protected));
        if let Some(reply) = self.server.receive(&ethernet) {
            self.downlink(&reply)?;
        }
        Ok((false, true))
    }
}
#[derive(Clone)]
struct Link(Arc<IrqSafeSpinLock<Peer>>);
#[async_trait::async_trait]
impl Io for Link {
    type Receipt = u64;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<u64, UsbError> {
        let mut p = self.0.lock();
        if p.rx.is_some() || dci != 3 || length != MAX_TRANSFER {
            return Err(UsbError::Stall);
        }
        p.next_receipt += 1;
        let id = p.next_receipt;
        p.rx = Some(id);
        p.posts += 1;
        Ok(id)
    }
    fn poll_receive(&self, receipt: &u64, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        let mut p = self.0.lock();
        if p.rx != Some(*receipt) {
            return Err(UsbError::Stall);
        }
        if let Some(raw) = p.raw_queue.pop_front() {
            if raw.len() > out.len() {
                return Err(UsbError::Stall);
            }
            out[..raw.len()].copy_from_slice(&raw);
            p.rx = None;
            return Ok(Some(raw.len()));
        }
        let Some(frame) = p.queue.pop_front() else {
            return Ok(None);
        };
        let ht = p.ht && frame.first() == Some(&0x88);
        let length = 24 + if ht { 32 } else { 0 } + frame.len();
        if length > out.len() {
            return Err(UsbError::Stall);
        }
        out[..length].fill(0);
        let d0 = frame.len() as u32
            | (1 << 27)
            | (1 << 28)
            | (1 << 29)
            | if frame.first() == Some(&0x88) {
                1 << 23
            } else {
                0
            }
            | if ht { (4 << 16) | (1 << 26) } else { 0 };
        out[..4].copy_from_slice(&d0.to_le_bytes());
        out[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
        if frame.first() == Some(&0x88) {
            let d1 =
                u32::from(frame[24] & 15) << 5 | if frame[24] & 0x80 != 0 { 1 << 13 } else { 0 };
            out[4..8].copy_from_slice(&d1.to_le_bytes());
        }
        if ht {
            out[12..16].copy_from_slice(&(19u32 | (1 << 6)).to_le_bytes());
        }
        out[if ht { 56 } else { 24 }..length].copy_from_slice(&frame);
        p.rx = None;
        Ok(Some(length))
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<u64, UsbError> {
        let mut p = self.0.lock();
        if p.tx.is_some()
            || !matches!(dci, 4 | 8)
            || bytes.len() < TX_DESC + 24
            || usize::from(u16::from_le_bytes([bytes[0], bytes[1]])) != bytes.len() - TX_DESC
            || bytes[2] != TX_DESC as u8
            || bytes[..TX_DESC]
                .chunks_exact(2)
                .fold(0u16, |sum, b| sum ^ u16::from_le_bytes([b[0], b[1]]))
                != 0
        {
            return Err(UsbError::Stall);
        }
        p.native_tx.push(bytes.to_vec());
        let (m4, data) = match p.react(&bytes[TX_DESC..]) {
            Ok(result) => result,
            Err(error) => {
                p.error = Some(error);
                return Err(UsbError::Stall);
            }
        };
        p.next_receipt += 1;
        let id = p.next_receipt;
        p.tx = Some(Tx {
            id,
            bytes: bytes.len(),
            m4,
            data,
            control: bytes.get(TX_DESC) == Some(&0xd0),
        });
        p.sent += 1;
        Ok(id)
    }
    fn poll_send(&self, receipt: &u64) -> Result<Option<usize>, UsbError> {
        let mut p = self.0.lock();
        let tx = p.tx.as_ref().ok_or(UsbError::Stall)?;
        if tx.id != *receipt {
            return Err(UsbError::Stall);
        }
        if tx.m4 && p.hold_m4 || tx.data && p.hold_data || tx.control && p.hold_control {
            return Ok(None);
        }
        let bytes = tx.bytes;
        p.tx = None;
        Ok(Some(bytes))
    }
    async fn stop(&self, receipt: &u64) -> Result<(), UsbError> {
        let mut p = self.0.lock();
        p.stops += 1;
        if p.fail_stop {
            return Err(UsbError::Timeout);
        }
        if p.rx == Some(*receipt) {
            p.rx = None;
            return Ok(());
        }
        if p.tx.as_ref().is_some_and(|tx| tx.id == *receipt) {
            p.tx = None;
            return Ok(());
        }
        Err(UsbError::Stall)
    }
}
#[derive(Clone, Default)]
struct Env(Arc<AtomicU64>);
impl Environment for Env {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
    fn fresh_nonce(&self) -> Result<[u8; 32], ServiceError> {
        Ok([0x73; 32])
    }
    async fn pause(&self) {
        let mut yielded = false;
        core::future::poll_fn(|cx| {
            if !yielded {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                self.0.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(())
            }
        })
        .await
    }
}
type ModelDevice = Device<Fake, Link, Env>;
static ACTIVE_TEST: IrqSafeSpinLock<Option<Arc<ModelDevice>>> = IrqSafeSpinLock::new(None);
fn send(bytes: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let device = ACTIVE_TEST.lock().clone().ok_or(())?;
    device.enqueue(bytes, meta)
}
fn drain() -> bool {
    let device = ACTIVE_TEST.lock().clone();
    device.is_some_and(|device| device.drain())
}
fn complete<T>(future: impl Future<Output = T>) -> Result<T, &'static str> {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..512 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return Ok(value);
        }
    }
    Err("native EU fixture conversation did not complete")
}
struct Harness {
    device: Arc<ModelDevice>,
    link: Link,
    env: Env,
    name: String,
    control: Fake,
    qualification: Option<super::ht_tests::Qualification>,
}
impl Harness {
    fn new(protected: bool) -> Result<Self, &'static str> {
        Self::new_profile(protected, false)
    }
    fn new_profile(protected: bool, ht: bool) -> Result<Self, &'static str> {
        let (control, firmware) = if ht {
            super::super::super::firmware_transport_tests::initialized_registered_firmware()
        } else {
            initialized_firmware()
        };
        let factory = firmware.factory().ok_or("EU fixture factory identity")?;
        let network = plan(factory.mac);
        let link = Link(Arc::new(IrqSafeSpinLock::new(Peer::new(
            network, protected,
        ))));
        if ht {
            let mut p = link.0.lock();
            p.ht = true;
            p.response_ht = Some(super::ht_tests::elements(255));
        }
        let domain = narf_wireless::reg::RegulatoryDomain {
            country_code: *b"US",
            rules: vec![narf_wireless::reg::RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2422,
                max_bandwidth_mhz: 20,
                max_power_dbm: 17,
                flags: narf_wireless::reg::RegFlags::empty(),
            }],
        };
        let mut receive = Receiver::new(
            firmware.clone(),
            link.clone(),
            ReceivePermission::from_domain(&domain).map_err(|_| "EU fixture RX policy")?,
        )
        .map_err(|_| "EU fixture retained RX owner")?;
        let qualification = if ht {
            let q = super::ht_tests::qualify(&firmware)?;
            receive.install_wmm_model(q.proof.clone());
            complete(receive.install_ht(q.grant.clone()))?
                .map_err(|_| "EU same-owner parked HT program")?;
            Some(q)
        } else {
            None
        };
        let env = Env::default();
        let service = complete(Service::start(
            receive,
            native_permission(factory),
            env.clone(),
        ))?
        .map_err(|_| "EU fixture native service initialization")?;
        let name = narf_net::iface::register("wlan%d", factory.mac, send);
        narf_net::iface::set_link_state(&name, true); // operator IFF_UP
        let device = Arc::new(Device::new(&name, service));
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        Ok(Self {
            device,
            link,
            env,
            name,
            control,
            qualification,
        })
    }
    fn request(&self) -> AssociateRequest {
        AssociateRequest {
            bssid: AP,
            ssid: SSID.to_vec(),
            frequency_mhz: 2412,
            channel: 1,
            security: if self.link.0.lock().ap.protected() {
                SecurityConfig::Wpa2 { psk: PMK }
            } else {
                SecurityConfig::Open
            },
            ie: Vec::new(),
        }
    }
    fn scan(&self) -> Result<(), &'static str> {
        let mut beacon = self.link.0.lock().ap.beacon();
        if self.link.0.lock().ht {
            beacon.extend_from_slice(&super::ht_tests::WMM);
            beacon.extend_from_slice(&super::ht_tests::elements(255));
        }
        self.link.0.lock().queue.push_back(beacon);
        let result = narf_scheduler::block_on(self.device.scan(ScanRequest {
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
        .map_err(|_| "EU native Device passive scan")?;
        ensure!(
            result.len() == 1 && result[0].bssid == AP && result[0].ssid == SSID,
            "EU native beacon was not decoded into scan cache"
        );
        Ok(())
    }
    fn join(&self) -> Result<(), &'static str> {
        complete(self.device.associate(self.request()))?.map_err(|_| {
            self.link
                .0
                .lock()
                .error
                .unwrap_or("EU native association/RSNA")
        })?;
        ensure!(
            self.link.0.lock().ap.phase() == ApPhase::Authorized,
            "shared AP did not verify authorization"
        );
        ensure!(
            self.device.link_up() && self.device.connected_bssid() == Some(AP),
            "EU Device carrier identity"
        );
        ensure!(
            narf_net::iface::lookup(&self.name).is_some_and(|i| i.link_up
                && i.carrier
                && i.carrier_up_count == 1
                && i.carrier_down_count == 0),
            "EU netdev carrier metadata missing"
        );
        narf_net::iface::set_link_state(&self.name, false);
        self.device.drain();
        ensure!(
            narf_net::iface::lookup(&self.name).is_some_and(|i| !i.link_up && i.carrier),
            "EU physical carrier overwrote operator DOWN"
        );
        narf_net::iface::set_link_state(&self.name, true);
        Ok(())
    }
    fn pump(&self) {
        for _ in 0..16 {
            self.device.drain();
        }
    }
    fn closed(&self) -> bool {
        !self.device.link_up()
            && self.device.connected_bssid().is_none()
            && narf_net::iface::lookup(&self.name).is_some_and(|i| {
                i.link_up && !i.carrier && i.carrier_up_count == 1 && i.carrier_down_count == 1
            })
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

fn composition(protected: bool) -> Result<(), &'static str> {
    composition_profile(protected, false)
}
fn composition_profile(protected: bool, ht: bool) -> Result<(), &'static str> {
    let h = Harness::new_profile(protected, ht)?;
    let network = h.link.0.lock().network;
    ensure!(
        !h.device.link_up() && narf_net::dhcp::acquire(&h.name, 400).is_err(),
        "EU DHCP transmitted before association"
    );
    ensure!(
        h.link.0.lock().uplink.is_empty(),
        "EU preassociation data reached AP"
    );
    h.scan()?;
    h.join()?;
    let lease =
        narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "EU actual kernel DHCP failed")?;
    ensure!(
        network.matches_lease(&lease),
        "EU DHCP lease differs from server terms"
    );
    {
        let p = h.link.0.lock();
        let seen = p.server.observations();
        ensure!(
            seen.discovers == 1 && seen.requests == 1,
            "EU AP missing DISCOVER/REQUEST evidence"
        );
        ensure!(
            p.uplink
                .iter()
                .filter(|(f, _)| dhcp_message_type(f).is_some())
                .count()
                == 2
                && p.uplink
                    .iter()
                    .all(|(_, encrypted)| *encrypted == protected),
            "EU DHCP native protection mismatch"
        );
        ensure!(p.error.is_none(), "shared AP rejected native EU traffic");
    }
    let uplink = udp_ipv4(
        AP,
        network.station,
        network.lease_ip,
        network.server_ip,
        49152,
        7,
        b"narf-eu-uplink",
    );
    narf_net::iface::send_on(&h.name, &uplink)
        .map_err(|_| "EU registered netdev refused uplink")?;
    h.pump();
    ensure!(
        h.link
            .0
            .lock()
            .uplink
            .iter()
            .any(|(f, encrypted)| *f == uplink && *encrypted == protected),
        "EU AP uplink payload changed"
    );
    let downlink = udp_ipv4(
        network.station,
        AP,
        network.server_ip,
        network.lease_ip,
        7,
        49152,
        b"narf-eu-downlink",
    );
    let counters = || {
        narf_net::iface::snapshot_counters()
            .iter()
            .find(|i| i.name == h.name)
            .map_or(0, |i| i.rx_packets)
    };
    let before = counters();
    h.link.0.lock().downlink(&downlink)?;
    let mut ring = h
        .device
        .rx_ring()
        .lock()
        .take()
        .ok_or("EU RX Narf-Ring unavailable")?;
    h.pump();
    let mut exact = false;
    for _ in 0..32 {
        match ring.try_recv() {
            Ok(Some(frame)) => exact |= frame.payload() == downlink,
            _ => break,
        }
    }
    ensure!(
        exact && counters() > before,
        "EU downlink did not reach both actual RX ring and stack intact"
    );
    let (receipt, posts) = {
        let p = h.link.0.lock();
        (p.rx, p.posts)
    };
    h.pump();
    {
        let p = h.link.0.lock();
        ensure!(
            p.rx == receipt && p.posts == posts,
            "EU quiet polling cancelled/reposted persistent RX receipt"
        );
    }
    complete(h.device.disassociate())?.map_err(|_| "EU native disconnect/USB retirement")?;
    h.pump();
    ensure!(h.closed(), "EU disconnect retained physical carrier");
    {
        let p = h.link.0.lock();
        ensure!(
            p.rx.is_none() && p.tx.is_none() && p.stops != 0,
            "EU disconnect failed to stop exact receipts"
        );
    }
    ensure!(
        narf_net::iface::send_on(&h.name, &uplink).is_err()
            && complete(h.device.associate(h.request()))?.is_err(),
        "EU stopped one-shot service reopened"
    );
    let name = h.name.clone();
    drop(h);
    ensure!(
        narf_net::ipv4::lookup_binding(&name).is_none(),
        "EU removed netdev retained DHCP binding"
    );
    Ok(())
}
fn smoke_rtl8188eu_open_native_scan_dhcp_and_bidirectional_ip() -> TestResult {
    match composition(false) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/dhcp",
    smoke_rtl8188eu_open_native_scan_dhcp_and_bidirectional_ip
);
fn smoke_rtl8188eu_wpa2_native_scan_dhcp_and_bidirectional_ip() -> TestResult {
    match composition(true) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/dhcp",
    smoke_rtl8188eu_wpa2_native_scan_dhcp_and_bidirectional_ip
);

fn held_m4_and_failure() -> Result<(), &'static str> {
    let h = Harness::new(true)?;
    h.scan()?;
    h.link.0.lock().hold_m4 = true;
    let mut joining = Box::pin(h.device.associate(h.request()));
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..128 {
        ensure!(
            joining.as_mut().poll(&mut context).is_pending(),
            "EU held M4 prematurely completed"
        );
        if h.link.0.lock().tx.as_ref().is_some_and(|tx| tx.m4) {
            break;
        }
    }
    {
        let p = h.link.0.lock();
        ensure!(
            p.ap.phase() == ApPhase::Authorized && p.tx.as_ref().is_some_and(|tx| tx.m4),
            "EU fixture did not hold exact M4 USB receipt"
        );
    }
    ensure!(
        !h.device.link_up()
            && narf_net::dhcp::acquire(&h.name, 400).is_err()
            && h.link.0.lock().uplink.is_empty(),
        "EU data port opened before M4 receipt"
    );
    h.link.0.lock().hold_m4 = false;
    complete(joining.as_mut())?.map_err(|_| "EU M4 receipt did not authorize service")?;
    drop(joining);
    let network = h.link.0.lock().network;
    let probe = udp_ipv4(
        AP,
        network.station,
        network.lease_ip,
        network.server_ip,
        12345,
        7,
        b"held-eu-data",
    );
    h.link.0.lock().hold_data = true;
    narf_net::iface::send_on(&h.name, &probe).map_err(|_| "EU pending-data submit")?;
    h.pump();
    ensure!(
        h.link.0.lock().tx.as_ref().is_some_and(|tx| tx.data),
        "EU data receipt not retained"
    );
    let (rx, tx, sent, stops) = {
        let p = h.link.0.lock();
        (p.rx, p.tx.as_ref().map(|tx| tx.id), p.sent, p.stops)
    };
    h.env.0.fetch_add(2000, Ordering::AcqRel);
    h.pump();
    ensure!(
        h.closed() && narf_net::iface::send_on(&h.name, &probe).is_err(),
        "EU timed-out data left carrier/admission open"
    );
    let p = h.link.0.lock();
    ensure!(
        p.rx == rx && p.tx.as_ref().map(|tx| tx.id) == tx && p.sent == sent && p.stops == stops,
        "EU timeout reclaimed/reposted uncertain USB receipts"
    );
    Ok(())
}
fn smoke_rtl8188eu_held_m4_closes_dhcp_and_timed_out_data_retains_receipts() -> TestResult {
    match held_m4_and_failure() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/dhcp",
    smoke_rtl8188eu_held_m4_closes_dhcp_and_timed_out_data_retains_receipts
);

fn failed_stop_retains_owned_receipts() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.scan()?;
    h.join()?;
    let network = h.link.0.lock().network;
    let probe = udp_ipv4(
        AP,
        network.station,
        network.lease_ip,
        network.server_ip,
        12346,
        7,
        b"eu-failed-stop",
    );
    h.link.0.lock().hold_data = true;
    narf_net::iface::send_on(&h.name, &probe).map_err(|_| "EU failed-stop data submit")?;
    h.pump();
    let (rx, tx, posts, sent) = {
        let mut p = h.link.0.lock();
        p.fail_stop = true;
        (p.rx, p.tx.as_ref().map(|t| t.id), p.posts, p.sent)
    };
    ensure!(
        rx.is_some() && tx.is_some(),
        "EU failed-stop fixture lacks live RX/TX receipts"
    );
    ensure!(
        complete(h.device.disassociate())?.is_err() && h.closed(),
        "EU failed USB stop left carrier/open admission"
    );
    h.pump();
    ensure!(
        narf_net::iface::send_on(&h.name, &probe).is_err()
            && complete(h.device.associate(h.request()))?.is_err(),
        "EU failed-stop lifecycle reopened"
    );
    let p = h.link.0.lock();
    ensure!(
        p.rx == rx
            && p.tx.as_ref().map(|t| t.id) == tx
            && p.posts == posts
            && p.sent == sent
            && p.stops == 1,
        "EU failed-stop reclaimed or replayed uncertain receipts"
    );
    Ok(())
}
fn smoke_rtl8188eu_failed_disconnect_retains_both_usb_receipts() -> TestResult {
    match failed_stop_retains_owned_receipts() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/dhcp",
    smoke_rtl8188eu_failed_disconnect_retains_both_usb_receipts
);

fn disconnect_overrides_waiting_old_publisher() -> Result<(), &'static str> {
    let h = Harness::new(false)?;
    h.scan()?;
    h.join()?;
    let network = h.link.0.lock().network;
    let probe = udp_ipv4(
        AP,
        network.station,
        network.lease_ip,
        network.server_ip,
        12347,
        7,
        b"eu-disconnect-publication",
    );
    narf_net::iface::send_on(&h.name, &probe).map_err(|_| "EU queue before racing disconnect")?;
    complete(
        crate::rtl8xxxu::interface::publication_test::disconnect_after_old_publication(
            &h.device, AP,
        ),
    )??;
    // Inspect before any later progress() can repair stale cached metadata.
    ensure!(
        !h.device.link_up()
            && h.device.connected_bssid().is_none()
            && narf_net::iface::lookup(&h.name).is_some_and(|i| {
                i.link_up && !i.carrier && i.carrier_up_count == 1 && i.carrier_down_count == 1
            })
            && narf_net::iface::send_on(&h.name, &probe).is_err(),
        "EU old publisher reopened carrier/BSSID after completed disconnect"
    );
    let p = h.link.0.lock();
    ensure!(
        p.rx.is_none() && p.tx.is_none() && p.stops != 0 && p.uplink.is_empty(),
        "EU racing disconnect did not retire USB ownership or discard queued data"
    );
    Ok(())
}
fn smoke_rtl8188eu_disconnect_overrides_waiting_old_link_publication() -> TestResult {
    match disconnect_overrides_waiting_old_publisher() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/dhcp",
    smoke_rtl8188eu_disconnect_overrides_waiting_old_link_publication
);

fn rekey_message(
    own: [u8; 6],
    information: u16,
    replay: u64,
    ptk: Option<&Ptk>,
) -> Result<Vec<u8>, &'static str> {
    let mut key = KeyFrame::empty(16);
    key.key_information = information;
    key.key_length = 16;
    key.replay_counter = replay;
    key.key_nonce = [0xab; 32];
    if information & 0x1000 != 0 {
        // Literal WPA2-PSK/CCMP AP RSNE and fresh GTK, bound by real AES-KW/MIC.
        let mut kde = vec![
            48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0,
        ];
        kde.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, 2, 0]);
        kde.extend_from_slice(&[0x7d; 16]);
        kde.push(0xdd);
        while kde.len() % 8 != 0 {
            kde.push(0);
        }
        key.key_data = narf_crypto::aes_kw::aes_wrap(
            ptk.ok_or("EU rekey missing KEK")?
                .kek
                .as_slice()
                .try_into()
                .map_err(|_| "EU KEK")?,
            &kde,
        )
        .ok_or("EU rekey AES-KW")?;
    }
    let mut pdu = key.into_eapol();
    pdu[0] = 2;
    if information & 0x100 != 0 {
        let mic =
            narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.ok_or("EU rekey missing KCK")?.kck, &pdu);
        pdu[81..97].copy_from_slice(&mic[..16]);
    }
    let mut native = vec![8, 2, 0, 0];
    native.extend_from_slice(&own);
    native.extend_from_slice(&AP);
    native.extend_from_slice(&AP);
    native.extend_from_slice(&[0, 0, 0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    native.extend_from_slice(&pdu);
    Ok(native)
}
fn aggregate(
    h: &Harness,
    sizes: &[usize],
    pn: u64,
    tid: u8,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), &'static str> {
    let p = h.link.0.lock();
    let own = p.network.station;
    let mut header = vec![0x88, if p.ap.protected() { 0x42 } else { 2 }, 0, 0];
    header.extend_from_slice(&own);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&[0, 0, 0x80 | tid, 0]);
    let mut body = Vec::new();
    let mut expected = Vec::new();
    for (i, size) in sizes.iter().copied().enumerate() {
        if i != 0 {
            while body.len() % 4 != 0 {
                body.push(0xcc);
            }
        }
        body.extend_from_slice(&own);
        body.extend_from_slice(&AP);
        body.extend_from_slice(&((size + 8) as u16).to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
        body.resize(body.len() + size, 0x30 + i as u8);
        let mut ethernet = own.to_vec();
        ethernet.extend_from_slice(&AP);
        ethernet.extend_from_slice(&[8, 0]);
        ethernet.resize(ethernet.len() + size, 0x30 + i as u8);
        expected.push(ethernet);
    }
    if p.ap.protected() {
        body = narf_wireless::ccmp::protect(
            &Ccm,
            &header,
            p.ptk
                .as_ref()
                .ok_or("EU aggregate TK")?
                .tk
                .as_slice()
                .try_into()
                .map_err(|_| "EU aggregate TK extent")?,
            pn,
            0,
            tid,
            false,
            &mut body,
        )
        .map_err(|_| "EU aggregate CCMP")?;
    }
    header.extend_from_slice(&body);
    Ok((header, expected))
}
fn ht_record(frame: &[u8], phy_bytes: usize) -> Vec<u8> {
    let mut wire = vec![0; 24 + phy_bytes + frame.len()];
    let d0 = frame.len() as u32
        | (1 << 27)
        | (1 << 28)
        | (1 << 29)
        | (1 << 23)
        | if phy_bytes != 0 {
            (phy_bytes as u32 / 8) << 16 | 1 << 26
        } else {
            0
        };
    let d1 = u32::from(frame[24] & 15) << 5 | if frame[24] & 0x80 != 0 { 1 << 13 } else { 0 };
    wire[..4].copy_from_slice(&d0.to_le_bytes());
    wire[4..8].copy_from_slice(&d1.to_le_bytes());
    wire[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
    wire[12..16].copy_from_slice(&(19u32 | 1 << 6).to_le_bytes());
    wire[24 + phy_bytes..].copy_from_slice(frame);
    wire
}
fn ht_result(result: Result<(), &'static str>) -> TestResult {
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn smoke_rtl8188eu_ht20_open_native_usb_kernel_dhcp_ip() -> TestResult {
    ht_result(composition_profile(false, true))
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_open_native_usb_kernel_dhcp_ip
);
fn smoke_rtl8188eu_ht20_wpa2_native_usb_kernel_dhcp_ip() -> TestResult {
    ht_result(composition_profile(true, true))
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_wpa2_native_usb_kernel_dhcp_ip
);
fn ht_aggregate() -> Result<(), &'static str> {
    for protected in [false, true] {
        let h = Harness::new_profile(protected, true)?;
        h.scan()?;
        h.join()?;
        let (frame, expected) = aggregate(&h, &[1500, 1500, 769], 1, 15)?;
        ensure!(
            frame.len() == 26 + 3839 + if protected { 16 } else { 0 },
            "EU test did not reach default3839"
        );
        h.link.0.lock().raw_queue.push_back(ht_record(&frame, 32));
        ensure!(
            h.device.progress() == expected,
            "EU full3839 A-MSDU did not publish atomically"
        );
        let mut ring = h
            .device
            .rx_ring()
            .lock()
            .take()
            .ok_or("EU HT ring absent")?;
        for exact in expected {
            ensure!(
                ring.try_recv()
                    .ok()
                    .flatten()
                    .is_some_and(|f| f.payload() == exact),
                "EU aggregate native RX ring changed subframe"
            );
        }
        if protected {
            h.link.0.lock().raw_queue.push_back(ht_record(&frame, 32));
            ensure!(
                h.device.progress().is_empty(),
                "EU aggregate replay reopened PN"
            );
        }
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_whole3839_amsdu_open_and_real_ccmp() -> TestResult {
    ht_result(ht_aggregate())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_whole3839_amsdu_open_and_real_ccmp
);
fn ht_phy() -> Result<(), &'static str> {
    let h = Harness::new_profile(true, true)?;
    h.scan()?;
    h.join()?;
    for case in 0..13 {
        let (frame, expected) = aggregate(&h, &[7, 9], 1 + case, 0)?;
        let mut raw = ht_record(
            &frame,
            if case == 10 {
                24
            } else if case == 11 {
                64
            } else {
                32
            },
        );
        let field = |raw: &mut Vec<u8>, at: usize, mask: u32| {
            let value = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) ^ mask;
            raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        match case {
            0 => field(&mut raw, 12, 1 << 9),
            1 => field(&mut raw, 12, 1 << 7),
            2 => field(&mut raw, 12, 1 << 8),
            3 => field(&mut raw, 12, 1 << 10),
            4 => field(&mut raw, 4, 1 << 14),
            5 => field(&mut raw, 4, 1 << 13),
            6 => field(&mut raw, 4, 1 << 5),
            7 => field(&mut raw, 8, 1 << 12),
            8 => raw[24 + 27] |= 2,
            9 => raw[24 + 27] |= 12,
            10 | 11 => (),
            12 => {
                raw = ht_record(&frame, 0);
                field(&mut raw, 0, 1 << 26);
            }
            _ => unreachable!(),
        }
        h.link.0.lock().raw_queue.push_back(raw);
        ensure!(
            h.device.progress().is_empty() && h.device.link_up(),
            "EU foreign PHY/aggregate metadata reached PN or closed valid owner"
        );
        h.link
            .0
            .lock()
            .raw_queue
            .push_back(ht_record(&frame, if case == 12 { 0 } else { 32 }));
        ensure!(
            h.device.progress() == expected,
            "EU bad PHY consumed aggregate PN or changed retry"
        );
    }
    // Legacy CCK/OFDM MPDUs inside the same HT station retain native QoS/TID
    // admission before the legacy-rate return, including protected A-MSDUs.
    let mut pn = 100;
    for aggregate_frame in [false, true] {
        for rate in [0u32, 3, 4, 11] {
            for mismatch_tid in [false, true] {
                let (frame, expected) = if aggregate_frame {
                    aggregate(&h, &[7, 9], pn, 0)?
                } else {
                    let ethernet = udp_ipv4(
                        h.device.mac(),
                        AP,
                        [10, 88, 0, 1],
                        [10, 88, 0, 42],
                        7,
                        8,
                        b"EU legacy PHY current original",
                    );
                    let frame = {
                        let mut p = h.link.0.lock();
                        p.next_pn = pn;
                        p.downlink(&ethernet)?;
                        p.queue.pop_back().ok_or("EU legacy PHY frame")?
                    };
                    (frame, vec![ethernet])
                };
                pn += 1;
                let mut valid = ht_record(&frame, 0);
                valid[12..16].copy_from_slice(&rate.to_le_bytes());
                let mut wrong = valid.clone();
                let at = if mismatch_tid { 4 } else { 0 };
                let value = u32::from_le_bytes(wrong[at..at + 4].try_into().unwrap())
                    ^ if mismatch_tid { 1 << 5 } else { 1 << 23 };
                wrong[at..at + 4].copy_from_slice(&value.to_le_bytes());
                h.link.0.lock().raw_queue.push_back(wrong);
                ensure!(
                    h.device.progress().is_empty() && h.device.link_up(),
                    "EU legacy native QoS/TID mismatch reached crypto"
                );
                h.link.0.lock().raw_queue.push_back(valid);
                ensure!(
                    h.device.progress() == expected,
                    "EU legacy metadata mismatch consumed ordinary/aggregate PN"
                );
            }
        }
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_native_phy_rejects_before_same_pn_retry() -> TestResult {
    ht_result(ht_phy())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_native_phy_rejects_before_same_pn_retry
);
fn ht_response() -> Result<(), &'static str> {
    for case in 0..5 {
        let h = Harness::new_profile(true, true)?;
        h.scan()?;
        {
            let mut p = h.link.0.lock();
            match case {
                0 => p.response_ht = None,
                1 => p.response_wmm = false,
                2 => p.response_ht.as_mut().unwrap()[30] = 6,
                3 => p.response_ht.as_mut().unwrap()[32] = 1,
                4 => p
                    .response_ht
                    .as_mut()
                    .unwrap()
                    .extend_from_slice(&super::ht_tests::elements(255)),
                _ => unreachable!(),
            }
        }
        ensure!(
            complete(h.device.associate(h.request()))?.is_err(),
            "EU malformed/downgraded/foreign HT response opened"
        );
        ensure!(
            !h.device.link_up()
                && h.link.0.lock().rx.is_some()
                && h.link.0.lock().uplink.is_empty(),
            "EU denied HT response released RX or data"
        );
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_bound_response_denial_retains_usb() -> TestResult {
    ht_result(ht_response())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_bound_response_denial_retains_usb
);
fn ht_sources() -> Result<(), &'static str> {
    for case in 0..4 {
        let h = Harness::new_profile(true, true)?;
        h.scan()?;
        h.join()?;
        let q = h.qualification.as_ref().ok_or("EU missing qualifier")?;
        let before = h.link.0.lock().sent;
        match case {
            0 => q.cap.revoke(),
            1 => q.legacy.revoke(),
            2 => q.source.revoke(),
            3 => q.domain.lock().rules.clear(),
            _ => unreachable!(),
        }
        let frame = udp_ipv4(
            AP,
            h.device.mac(),
            [10, 88, 0, 42],
            [10, 88, 0, 1],
            7,
            8,
            b"EU denied",
        );
        ensure!(
            h.device.enqueue(&frame, Default::default()).is_err(),
            "EU revoked source enqueued DATA"
        );
        h.device.progress();
        ensure!(
            !h.device.link_up() && h.link.0.lock().sent == before && h.link.0.lock().rx.is_some(),
            "EU revoked HT owner reopened/reclaimed USB"
        );
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_all_signed_sources_and_current_policy_terminal() -> TestResult {
    ht_result(ht_sources())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_all_signed_sources_and_current_policy_terminal
);
fn addba_request(h: &Harness, token: u8, params: u16, timeout: u16, ssn: u16) -> Vec<u8> {
    let mut request = vec![0xd0, 0, 0, 0];
    request.extend_from_slice(&h.device.mac());
    request.extend_from_slice(&AP);
    request.extend_from_slice(&AP);
    request.extend_from_slice(&[0, 0, 3, 0, token]);
    request.extend_from_slice(&params.to_le_bytes());
    request.extend_from_slice(&timeout.to_le_bytes());
    request.extend_from_slice(&(ssn << 4).to_le_bytes());
    request
}
fn delba(h: &Harness, tid: u16, initiator: bool) -> Vec<u8> {
    let mut frame = vec![0xd0, 0, 0, 0];
    frame.extend_from_slice(&h.device.mac());
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0, 3, 2]);
    frame.extend_from_slice(&(tid << 12 | u16::from(initiator) << 11).to_le_bytes());
    frame.extend_from_slice(&1u16.to_le_bytes());
    frame
}
/// One non-A-MSDU QoS DATA MPDU on `tid` with sequence `seq` and CCMP PN `pn`.
fn qos_mpdu(
    h: &Harness,
    seq: u16,
    tid: u8,
    pn: u64,
    fill: u8,
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let p = h.link.0.lock();
    let own = p.network.station;
    let mut header = vec![0x88, if p.ap.protected() { 0x42 } else { 2 }, 0, 0];
    header.extend_from_slice(&own);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&AP);
    header.extend_from_slice(&(seq << 4).to_le_bytes());
    header.extend_from_slice(&[tid, 0]);
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 8, 0];
    body.resize(body.len() + 64, fill);
    let mut ethernet = own.to_vec();
    ethernet.extend_from_slice(&AP);
    ethernet.extend_from_slice(&[8, 0]);
    ethernet.resize(ethernet.len() + 64, fill);
    if p.ap.protected() {
        body = narf_wireless::ccmp::protect(
            &Ccm,
            &header,
            p.ptk
                .as_ref()
                .ok_or("EU BA TK")?
                .tk
                .as_slice()
                .try_into()
                .map_err(|_| "EU BA TK extent")?,
            pn,
            0,
            tid,
            false,
            &mut body,
        )
        .map_err(|_| "EU BA CCMP")?;
    }
    header.extend_from_slice(&body);
    Ok((header, ethernet))
}
/// Native rxdesc16 for an MPDU inside an A-MPDU: PAGGR, plus FAGGR on the first.
fn ba_record(frame: &[u8], first: bool) -> Vec<u8> {
    let mut raw = ht_record(frame, 32);
    let d1 = u32::from_le_bytes(raw[4..8].try_into().unwrap())
        | 1 << 14
        | if first { 1 << 15 } else { 0 };
    raw[4..8].copy_from_slice(&d1.to_le_bytes());
    raw
}
fn ht_rx_ba() -> Result<(), &'static str> {
    for protected in [false, true] {
        let h = Harness::new_profile(protected, true)?;
        h.scan()?;
        h.join()?;
        // ADDBA Request TID5, immediate, window32, no timeout, SSN100. The
        // response is accepted, held as an actual native control receipt.
        let params = 2u16 | 5 << 2 | 32 << 6;
        {
            let mut p = h.link.0.lock();
            p.hold_control = true;
            p.queue.push_back(addba_request(&h, 7, params, 0, 100));
        }
        h.pump();
        {
            let p = h.link.0.lock();
            ensure!(
                p.declines == 1 && p.tx.as_ref().is_some_and(|t| t.control) && p.rx.is_some(),
                "EU ADDBA response lacked actual held native receipt"
            );
        }
        h.link.0.lock().hold_control = false;
        h.pump();
        {
            let p = h.link.0.lock();
            let response = p.actions.last().ok_or("EU missing ADDBA response")?;
            let native = p
                .native_tx
                .iter()
                .rev()
                .find(|x| x.get(32) == Some(&0xd0))
                .ok_or("EU missing native ADDBA bytes")?;
            ensure!(
                response[26] == 7
                    && response[27..29] == [0, 0]
                    && response[29..31] == params.to_le_bytes()
                    && response[31..33] == [0, 0]
                    && native[20] & 63 == 0
                    && p.tx.is_none()
                    && h.device.link_up(),
                "EU ADDBA acceptance status/params/A-MSDU/policy/rate"
            );
        }
        // Out-of-order A-MPDU MPDUs are released in sequence before PN.
        let (f100, e100) = qos_mpdu(&h, 100, 5, 100, 0x41)?;
        let (f101, e101) = qos_mpdu(&h, 101, 5, 101, 0x42)?;
        let (f102, e102) = qos_mpdu(&h, 102, 5, 102, 0x43)?;
        h.link.0.lock().raw_queue.push_back(ba_record(&f100, true));
        ensure!(
            h.device.progress() == vec![e100],
            "EU BA head MPDU not delivered"
        );
        h.link.0.lock().raw_queue.push_back(ba_record(&f102, false));
        ensure!(
            h.device.progress().is_empty(),
            "EU BA delivered past a sequence hole"
        );
        h.link.0.lock().raw_queue.push_back(ba_record(&f101, false));
        ensure!(
            h.device.progress() == vec![e101, e102],
            "EU BA hole fill did not release in sequence order"
        );
        h.link.0.lock().raw_queue.push_back(ba_record(&f101, false));
        ensure!(
            h.device.progress().is_empty(),
            "EU BA duplicate/old sequence delivered"
        );
        // A hole releases buffered MPDUs after the 100ms reorder timeout.
        let (f104, e104) = qos_mpdu(&h, 104, 5, 104, 0x44)?;
        h.link.0.lock().raw_queue.push_back(ba_record(&f104, false));
        ensure!(
            h.device.progress().is_empty(),
            "EU BA delivered before reorder timeout"
        );
        h.env.0.fetch_add(101, Ordering::AcqRel);
        ensure!(
            h.device.progress() == vec![e104],
            "EU BA reorder timeout did not release the held MPDU"
        );
        // A-MSDU inside an A-MPDU is never granted (response A-MSDU bit 0).
        let (mut amsdu, _) = aggregate(&h, &[7, 9], 105, 5)?;
        amsdu[22..24].copy_from_slice(&(105u16 << 4).to_le_bytes());
        h.link
            .0
            .lock()
            .raw_queue
            .push_back(ba_record(&amsdu, false));
        ensure!(
            h.device.progress().is_empty() && h.device.link_up(),
            "EU A-MSDU in A-MPDU reached PN/delivery"
        );
        // The refused record is discarded at native admission and never
        // occupies its sequence slot, so the next MPDU may reuse SN105.
        let (mut amsdu, expected) = aggregate(&h, &[7, 9], 106, 5)?;
        amsdu[22..24].copy_from_slice(&(105u16 << 4).to_le_bytes());
        h.link.0.lock().raw_queue.push_back(ht_record(&amsdu, 32));
        ensure!(
            h.device.progress() == expected,
            "EU standalone A-MSDU on a BA TID was not ordered/delivered"
        );
        // Originator DELBA ends the session: PAGGR is native-rejected again
        // and ordinary QoS MPDUs on the TID bypass reordering.
        h.link.0.lock().queue.push_back(delba(&h, 5, true));
        h.pump();
        let (f107, _) = qos_mpdu(&h, 107, 5, 107, 0x45)?;
        h.link.0.lock().raw_queue.push_back(ba_record(&f107, false));
        ensure!(
            h.device.progress().is_empty() && h.device.link_up(),
            "EU A-MPDU accepted after originator DELBA"
        );
        let (f109, e109) = qos_mpdu(&h, 109, 5, 109, 0x46)?;
        h.link.0.lock().raw_queue.push_back(ht_record(&f109, 32));
        ensure!(
            h.device.progress() == vec![e109],
            "EU post-DELBA ordinary QoS MPDU"
        );
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_rx_ba_reorders_ampdu_before_pn() -> TestResult {
    ht_result(ht_rx_ba())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_rx_ba_reorders_ampdu_before_pn
);
fn ht_rx_ba_policy() -> Result<(), &'static str> {
    let h = Harness::new_profile(false, true)?;
    h.scan()?;
    h.join()?;
    let status = |h: &Harness, request: Vec<u8>| -> Result<[u8; 4], &'static str> {
        let before = h.link.0.lock().actions.len();
        h.link.0.lock().queue.push_back(request);
        h.pump();
        let p = h.link.0.lock();
        ensure!(p.actions.len() == before + 1, "EU ADDBA response missing");
        let r = p.actions.last().unwrap();
        Ok([r[27], r[28], r[29], r[30]])
    };
    // TSPEC TID: declined; delayed policy / window65: invalid QoS param.
    let tid9 = status(&h, addba_request(&h, 1, 2 | 9 << 2 | 8 << 6, 0, 0))?;
    let delayed = status(&h, addba_request(&h, 2, 3 << 2 | 8 << 6, 0, 0))?;
    let wide = status(&h, addba_request(&h, 3, 2 | 3 << 2 | 65 << 6, 0, 0))?;
    // Window0 selects the HT maximum64.
    let zero = status(&h, addba_request(&h, 4, 2 | 3 << 2, 100, 0))?;
    ensure!(
        tid9[..2] == [37, 0]
            && delayed[..2] == [38, 0]
            && wide[..2] == [38, 0]
            && zero == [0, 0, 0x0e, 0x10],
        "EU ADDBA status/window selection differs from mac80211"
    );
    // Same token: unchanged timeout succeeds, a changed timeout is declined
    // and keeps the existing session.
    let same = status(&h, addba_request(&h, 4, 2 | 3 << 2, 100, 0))?;
    let changed = status(&h, addba_request(&h, 4, 2 | 3 << 2, 200, 0))?;
    ensure!(
        same[..2] == [0, 0] && changed[..2] == [37, 0],
        "EU ADDBA same-token update policy"
    );
    // Session inactivity of100TU (102ms) sends recipient DELBA QSTA_TIMEOUT.
    let before = h.link.0.lock().actions.len();
    h.env.0.fetch_add(103, Ordering::AcqRel);
    h.pump();
    {
        let p = h.link.0.lock();
        let d = p.actions.last().ok_or("EU missing DELBA")?;
        ensure!(
            p.actions.len() == before + 1
                && d.len() == 30
                && d[24..26] == [3, 2]
                && d[26..28] == (3u16 << 12).to_le_bytes()
                && d[28..30] == [39, 0]
                && h.device.link_up(),
            "EU BA inactivity timeout DELBA"
        );
    }
    let (f, _) = qos_mpdu(&h, 0, 3, 1, 0x50)?;
    h.link.0.lock().raw_queue.push_back(ba_record(&f, true));
    ensure!(
        h.device.progress().is_empty() && h.device.link_up(),
        "EU timed-out BA session still admitted A-MPDU"
    );
    Ok(())
}
fn smoke_rtl8188eu_ht20_rx_ba_policy_and_inactivity_delba() -> TestResult {
    ht_result(ht_rx_ba_policy())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_rx_ba_policy_and_inactivity_delba
);
fn ba_action(h: &Harness, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0xd0, 0, 0, 0];
    frame.extend_from_slice(&h.device.mac());
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(body);
    frame
}
fn ht_tx_ba() -> Result<(), &'static str> {
    use super::super::super::firmware_transport_tests::Op;
    for protected in [false, true] {
        let h = Harness::new_profile(protected, true)?;
        h.scan()?;
        h.join()?;
        let tx = udp_ipv4(
            AP,
            h.device.mac(),
            [10, 88, 0, 42],
            [10, 88, 0, 1],
            7,
            8,
            b"EU originator BA",
        );
        let send = |h: &Harness| -> Result<[u32; 2], &'static str> {
            ensure!(
                h.device.enqueue(&tx, Default::default()).is_ok(),
                "EU TX BA enqueue"
            );
            h.pump();
            let p = h.link.0.lock();
            let d = p
                .native_tx
                .iter()
                .rev()
                .find(|x| x.get(TX_DESC) == Some(&0x88))
                .ok_or("EU TX BA QoS data")?;
            let w = |at: usize| u32::from_le_bytes(d[at..at + 4].try_into().unwrap());
            Ok([w(8), w(16)])
        };
        let ampdu_writes = |h: &Harness, from: usize| {
            let ops = &h.control.0.lock().ops;
            [0x458u16, 0x459, 0x45a, 0x45b, 0x45c].iter().all(|r| {
                ops[from..]
                    .iter()
                    .any(|o| matches!(o, Op::Write(a, _) if a == r))
            })
        };
        let maintain = |h: &Harness| complete(h.device.maintain());
        // First QoS DATA to the HT peer: density/RTS24M, AGG_BREAK, and a
        // session start that only the async path may program.
        let [dw2, dw4] = send(&h)?;
        ensure!(
            dw2 & (1 << 16) != 0
                && dw2 & (1 << 12) == 0
                && dw4 & 31 == 8
                && dw4 & (3 << 12) == 3 << 12,
            "EU HT QoS DATA lacked ampdu_enable RTS/density/AGG_BREAK"
        );
        let ops = h.control.0.lock().ops.len();
        maintain(&h)?;
        ensure!(
            ampdu_writes(&h, ops),
            "EU TX_START AGGLEN/MIN_SPACE EP0 writes"
        );
        h.pump();
        let token = {
            let p = h.link.0.lock();
            let r = p.actions.last().ok_or("EU ADDBA Request missing")?;
            ensure!(
                r.len() == 33
                    && r[24..26] == [3, 0]
                    && r[27..29] == (2u16 | 64 << 6).to_le_bytes()
                    && r[29..31] == [0, 0]
                    && r[31] & 15 == 0,
                "EU ADDBA Request policy/A-MSDU/window/timeout/SSN"
            );
            r[26]
        };
        // Accepted: the TID becomes operational and DATA aggregates.
        h.link
            .0
            .lock()
            .queue
            .push_back(ba_action(&h, &[3, 1, token, 0, 0, 0x02, 0x08, 0, 0]));
        h.pump();
        let [dw2, _] = send(&h)?;
        ensure!(
            dw2 & (1 << 12) != 0 && dw2 & (1 << 16) == 0,
            "EU operational TID lacked AGG_ENABLE"
        );
        // Recipient DELBA: TX_STOP EP0 writes, no DELBA of our own.
        let actions = h.link.0.lock().actions.len();
        h.link
            .0
            .lock()
            .queue
            .push_back(ba_action(&h, &[3, 2, 0, 0, 1, 0]));
        h.pump();
        let ops = h.control.0.lock().ops.len();
        maintain(&h)?;
        ensure!(
            ampdu_writes(&h, ops) && h.link.0.lock().actions.len() == actions,
            "EU peer DELBA TX_STOP"
        );
        // The next DATA restarts; no response within 1s sends initiator DELBA.
        let [dw2, _] = send(&h)?;
        ensure!(dw2 & (1 << 16) != 0, "EU stopped TID still aggregated");
        maintain(&h)?;
        h.pump();
        let second = h.link.0.lock().actions.last().map(|r| r[26]);
        ensure!(
            second == Some(token.wrapping_add(1)),
            "EU restarted ADDBA token"
        );
        h.env.0.fetch_add(1001, Ordering::AcqRel);
        h.pump();
        maintain(&h)?;
        h.pump();
        {
            let p = h.link.0.lock();
            let d = p.actions.last().ok_or("EU initiator DELBA")?;
            ensure!(
                d.len() == 30
                    && d[24..26] == [3, 2]
                    && d[26..28] == (1u16 << 11).to_le_bytes()
                    && d[28..30] == [37, 0],
                "EU ADDBA response timeout initiator DELBA"
            );
        }
        // A declined request stops without DELBA.
        send(&h)?;
        maintain(&h)?;
        h.pump();
        let third = h.link.0.lock().actions.last().map(|r| r[26]).unwrap_or(0);
        h.link
            .0
            .lock()
            .queue
            .push_back(ba_action(&h, &[3, 1, third, 37, 0, 0x02, 0x08, 0, 0]));
        h.pump();
        let actions = h.link.0.lock().actions.len();
        maintain(&h)?;
        h.pump();
        let [dw2, _] = send(&h)?;
        ensure!(
            dw2 & (1 << 16) != 0 && h.link.0.lock().actions.len() == actions && h.device.link_up(),
            "EU declined ADDBA aggregated or sent DELBA"
        );
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_originator_ba_and_tx_ampdu() -> TestResult {
    ht_result(ht_tx_ba())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_originator_ba_and_tx_ampdu
);
fn ht_m4() -> Result<(), &'static str> {
    for cancelled in [false, true] {
        let h = Harness::new_profile(true, true)?;
        h.scan()?;
        h.link.0.lock().hold_m4 = true;
        let mut join = alloc::boxed::Box::pin(h.device.associate(h.request()));
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..200 {
            ensure!(
                join.as_mut().poll(&mut context).is_pending(),
                "EU held M4 completed"
            );
            if h.link.0.lock().tx.as_ref().is_some_and(|tx| tx.m4) {
                break;
            }
        }
        ensure!(
            h.link.0.lock().tx.as_ref().is_some_and(|tx| tx.m4),
            "EU native M4 not reached"
        );
        let (frame, expected) = aggregate(&h, &[11, 13], 1, 0)?;
        h.link.0.lock().raw_queue.push_back(ht_record(&frame, 32));
        for _ in 0..4 {
            ensure!(
                join.as_mut().poll(&mut context).is_pending(),
                "EU held M4 opened port"
            );
        }
        if cancelled {
            drop(join);
            h.device.progress();
            ensure!(
                !h.device.link_up() && h.link.0.lock().rx.is_some() && h.link.0.lock().tx.is_some(),
                "EU cancelled M4 released receipt/reopened"
            );
        } else {
            h.link.0.lock().hold_m4 = false;
            complete(join)?.map_err(|_| "EU native M4 release")?;
            ensure!(
                h.device.progress().is_empty(),
                "EU pre-M4 capture retrospectively admitted"
            );
            h.link.0.lock().raw_queue.push_back(ht_record(&frame, 32));
            ensure!(
                h.device.progress() == expected,
                "EU closed capture consumed PN"
            );
        }
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_held_m4_capture_and_cancel_keep_usb() -> TestResult {
    ht_result(ht_m4())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_held_m4_capture_and_cancel_keep_usb
);
fn ht_reentrant() -> Result<(), &'static str> {
    for case in 0..3 {
        let h = Harness::new_profile(true, true)?;
        h.scan()?;
        h.join()?;
        let (frame, expected) = aggregate(&h, &[11, 13], 1, 0)?;
        h.link.0.lock().raw_queue.push_back(ht_record(&frame, 32));
        let mut delivered = Vec::new();
        let mut callback_error = None;
        h.device.dispatch_with(|frame| {
            delivered.push(frame.to_vec());
            if delivered.len() != 1 {
                return;
            }
            if case == 2 {
                let tx = udp_ipv4(
                    AP,
                    h.device.mac(),
                    [10, 88, 0, 42],
                    [10, 88, 0, 1],
                    7,
                    8,
                    b"EU reentrant ordinary",
                );
                h.link.0.lock().hold_data = true;
                if h.device.enqueue(&tx, Default::default()).is_err() {
                    callback_error = Some("EU ordinary callback TX");
                }
                h.device.drain();
            } else {
                let message = match rekey_message(h.device.mac(), 0x8a, 3, None) {
                    Ok(b) => b,
                    Err(e) => {
                        callback_error = Some(e);
                        return;
                    }
                };
                {
                    let mut p = h.link.0.lock();
                    p.rekey = Some(1);
                    p.hold_m4 = case == 0;
                    p.queue.push_back(message);
                }
                for _ in 0..12 {
                    h.device.drain();
                }
            }
        });
        if let Some(error) = callback_error {
            return Err(error);
        }
        if !h.device.link_up() {
            return Err(h.link.0.lock().error.unwrap_or(match case {
                0 => "EU reentrant held-key reply caused false disconnect",
                1 => "EU reentrant completed-key reply caused false disconnect",
                _ => "EU reentrant ordinary TX credit caused false disconnect",
            }));
        }
        if case == 1 {
            ensure!(
                h.link.0.lock().rekey.is_none(),
                "EU reentrant replacement key never completed"
            );
        }
        if case == 2 {
            ensure!(
                delivered == expected,
                "EU ordinary TX credit retired receive epoch"
            );
        } else {
            ensure!(
                delivered == expected[..1],
                "EU old aggregate crossed a held/reopened key epoch"
            );
            ensure!(
                h.device
                    .rx_ring()
                    .lock()
                    .as_mut()
                    .is_none_or(|ring| !matches!(ring.try_recv(), Ok(Some(_)))),
                "EU old IPC aggregate survived key retirement"
            );
        }
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_reentrant_key_epochs_and_ordinary_credit() -> TestResult {
    ht_result(ht_reentrant())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_reentrant_key_epochs_and_ordinary_credit
);
fn ht_rates() -> Result<(), &'static str> {
    for mcs in 0..8 {
        let h = Harness::new_profile(true, true)?;
        h.scan()?;
        h.link.0.lock().response_ht = Some(super::ht_tests::elements(1 << mcs));
        h.join()?;
        let frame = udp_ipv4(
            AP,
            h.device.mac(),
            [10, 88, 0, 42],
            [10, 88, 0, 1],
            7,
            8,
            b"EU exact MCS",
        );
        h.device
            .enqueue(&frame, Default::default())
            .map_err(|_| "EU MCS enqueue")?;
        h.pump();
        let p = h.link.0.lock();
        let tx = p
            .native_tx
            .iter()
            .rev()
            .find(|x| x.get(32) == Some(&0x88))
            .ok_or("EU MCS native TX")?;
        let word = |at| u32::from_le_bytes(tx[at..at + 4].try_into().unwrap());
        ensure!(
            word(20) & 0x7f == 12 + mcs
                && word(16) & 0x7c0 == 0x540
                && word(8) & (1 << 12) == 0
                && tx[56..58] == [0, 0],
            "EU native TXDESC32 rate/LGI/DISFB/AGG/TID changed"
        );
        ensure!(
            p.uplink
                .iter()
                .any(|(f, encrypted)| *f == frame && *encrypted),
            "EU source-native MCS did not carry real CCMP"
        );
        let c = h.control.0.lock();
        let read = |at| u32::from_le_bytes(c.regs[at..at + 4].try_into().unwrap());
        ensure!(
            read(0xe10) == 0x1e1e1e1e
                && read(0xe14) == 0x1e1e1e1e
                && c.regs[0x429] == 16
                && read(0x508) & 255 == 76,
            "EU source gains/SIFS/HT EDCA readback changed"
        );
    }
    Ok(())
}
fn smoke_rtl8188eu_ht20_all_mcs_response_bound_native_descriptor_ccmp() -> TestResult {
    ht_result(ht_rates())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_all_mcs_response_bound_native_descriptor_ccmp
);
fn ht_aggregate_atomic_failure() -> Result<(), &'static str> {
    let h = Harness::new_profile(true, true)?;
    h.scan()?;
    h.join()?;
    let (good, expected) = aggregate(&h, &[11, 13], 1, 0)?;
    let mut mic = good.clone();
    *mic.last_mut().ok_or("EU aggregate MIC")? ^= 1;
    h.link.0.lock().raw_queue.push_back(ht_record(&mic, 32));
    ensure!(
        h.device.progress().is_empty(),
        "EU forged aggregate published prefix"
    );
    let mut wire = good[26..].to_vec();
    let mut window = narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 };
    let key: [u8; 16] = h
        .link
        .0
        .lock()
        .ptk
        .as_ref()
        .ok_or("EU aggregate PTK")?
        .tk
        .as_slice()
        .try_into()
        .map_err(|_| "EU aggregate TK")?;
    let mut body =
        narf_wireless::ccmp::unprotect(&Ccm, &good[..26], &key, 0, false, &mut window, &mut wire)
            .map_err(|_| "EU fixture aggregate decrypt")?;
    body[42..48].copy_from_slice(&h.device.mac()); // Second SA is local: reject whole authenticated aggregate.
    let encrypted =
        narf_wireless::ccmp::protect(&Ccm, &good[..26], &key, 1, 0, 0, false, &mut body)
            .map_err(|_| "EU malformed aggregate CCMP")?;
    let mut malformed = good[..26].to_vec();
    malformed.extend_from_slice(&encrypted);
    h.link
        .0
        .lock()
        .raw_queue
        .push_back(ht_record(&malformed, 32));
    ensure!(
        h.device.progress().is_empty(),
        "EU bad final subframe published authenticated prefix"
    );
    h.link.0.lock().raw_queue.push_back(ht_record(&good, 32));
    ensure!(
        h.device.progress() == expected,
        "EU bad MIC/subframe consumed PN"
    );
    Ok(())
}
fn smoke_rtl8188eu_ht20_amsdu_bad_mic_and_tail_preserve_whole_pn() -> TestResult {
    ht_result(ht_aggregate_atomic_failure())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_amsdu_bad_mic_and_tail_preserve_whole_pn
);
fn ht_truncated() -> Result<(), &'static str> {
    let h = Harness::new_profile(true, true)?;
    h.scan()?;
    h.join()?;
    let (frame, _) = aggregate(&h, &[11, 13], 1, 0)?;
    let mut raw = ht_record(&frame, 32);
    raw.pop();
    h.link.0.lock().raw_queue.push_back(raw);
    ensure!(
        h.device.progress().is_empty() && !h.device.link_up(),
        "EU truncated native HT bulk record was accepted"
    );
    ensure!(
        h.link.0.lock().stops == 0,
        "EU malformed transfer fabricated USB stop proof"
    );
    Ok(())
}
fn smoke_rtl8188eu_ht20_truncated_usb_record_is_terminal() -> TestResult {
    ht_result(ht_truncated())
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_truncated_usb_record_is_terminal
);
