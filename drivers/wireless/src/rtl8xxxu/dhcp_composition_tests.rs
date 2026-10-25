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
}
struct Peer {
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
        let mut frame = vec![8, if self.ap.protected() { 0x42 } else { 2 }, 0, 0];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&AP);
        frame.extend_from_slice(&ethernet[6..12]);
        frame.extend_from_slice(&[0, 0]);
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
        if self.ap.phase() != ApPhase::Authorized || matches!(frame[0], 0 | 0xb0) {
            let before = self.ap.phase();
            let replies = self
                .ap
                .receive(frame)
                .map_err(|_| "shared AP rejected real management/EAPOL")?;
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
            frame[0] == 8 && frame[1] & 3 == 1,
            "USB data is not native ToDS"
        );
        let protected = frame[1] & 0x40 != 0;
        ensure!(
            protected == self.ap.protected(),
            "data crossed controlled port with wrong protection"
        );
        let mut body = frame[24..].to_vec();
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
                &frame[..24],
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
        let Some(frame) = p.queue.pop_front() else {
            return Ok(None);
        };
        let length = 24 + frame.len();
        if length > out.len() {
            return Err(UsbError::Stall);
        }
        out[..length].fill(0);
        let d0 = frame.len() as u32 | (1 << 27) | (1 << 28) | (1 << 29);
        out[..4].copy_from_slice(&d0.to_le_bytes());
        out[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
        out[24..length].copy_from_slice(&frame);
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
        if tx.m4 && p.hold_m4 || tx.data && p.hold_data {
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
}
impl Harness {
    fn new(protected: bool) -> Result<Self, &'static str> {
        let (_, firmware) = initialized_firmware();
        let factory = firmware.factory().ok_or("EU fixture factory identity")?;
        let network = plan(factory.mac);
        let link = Link(Arc::new(IrqSafeSpinLock::new(Peer::new(
            network, protected,
        ))));
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
        let receive = Receiver::new(
            firmware,
            link.clone(),
            ReceivePermission::from_domain(&domain).map_err(|_| "EU fixture RX policy")?,
        )
        .map_err(|_| "EU fixture retained RX owner")?;
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
        let beacon = self.link.0.lock().ap.beacon();
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
    let h = Harness::new(protected)?;
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
                i.link_up && !i.carrier && i.carrier_up_count == 2 && i.carrier_down_count == 2
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
