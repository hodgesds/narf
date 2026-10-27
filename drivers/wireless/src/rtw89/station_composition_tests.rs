//! Actual source controller and native packet model through public Device/DHCP.
//! This fixture grants no production full-RF receipt or physical readiness.
use crate::rtw89::{interface::Device, station::Environment, station_lifecycle::Lifecycle};
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
const OWN: [u8; 6] = [2, 4, 6, 8, 10, 12];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
const SSID: &[u8] = b"narf-8852b";
const WMM: [u8; 26] = [
    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x81, 0, 0x62, 0x32, 47, 0, 3, 0xa4, 0, 0, 0x42, 0x43, 94, 0,
    0x27, 0xa4, 0, 0,
];
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
pub(super) struct Peer {
    pub(super) ap: FakeAp,
    pub(super) plan: NetworkPlan,
    pub(super) server: DhcpServer,
    pub(super) ptk: Option<Ptk>,
    pub(super) replay: narf_wireless::ccmp::ReplayWindow,
    pub(super) pn: u64,
    pub(super) uplink: Vec<Vec<u8>>,
    pub(super) hold_m4: bool,
    pub(super) hold_data: bool,
    wmm: Option<Vec<u8>>,
    qos: bool,
}
impl Peer {
    pub(super) fn new(protected: bool) -> Self {
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
            ap,
            plan,
            server: DhcpServer::new(plan),
            ptk: None,
            replay: narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 },
            pn: 1,
            uplink: Vec::new(),
            hold_m4: false,
            hold_data: false,
            wmm: None,
            qos: false,
        }
    }
    pub(super) fn downlink(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, &'static str> {
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
    pub(super) fn react(&mut self, frame: &[u8]) -> Result<(Vec<Vec<u8>>, bool), &'static str> {
        if frame.len() < 24 || frame[4..10] != AP || frame[10..16] != self.plan.station {
            return Err("native AP peer identity");
        }
        if self.ap.phase() != ApPhase::Authorized || matches!(frame[0], 0 | 0xb0) {
            if frame[0] == 0 {
                self.qos = self.wmm.is_some() && frame.ends_with(&narf_wireless::wmm::INFORMATION);
            }
            let before = self.ap.phase();
            let mut replies = self
                .ap
                .receive(frame)
                .map_err(|_| "shared AP rejected real native MLME/EAPOL")?;
            for reply in &mut replies {
                if reply.first() == Some(&0x10) {
                    if let Some(p) = &self.wmm {
                        reply.extend_from_slice(p);
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
        if frame[0] != if self.qos { 0x88 } else { 8 }
            || frame[1] & 3 != 1
            || (frame[1] & 0x40 != 0) != self.ap.protected()
        {
            return Err("native AP data protection/direction");
        }
        let header = if self.qos {
            if frame.get(24..26) != Some(&[0, 0]) {
                return Err("AP BE/TID0 QoS control");
            }
            26
        } else {
            24
        };
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
        self.uplink.push(ethernet.clone());
        let replies = match self.server.receive(&ethernet) {
            Some(reply) => vec![self.downlink(&reply)?],
            None => Vec::new(),
        };
        Ok((replies, self.hold_data))
    }
}

struct DriverModel {
    controller: crate::rtw89::station_control::Controller,
    control: crate::rtw89::station_control::tests::Model,
    packets: crate::rtw89::packet_core::tests::Model,
    core: Option<crate::rtw89::packet_core::Core>,
    clock: Arc<AtomicU64>,
    stopped: bool,
    packet_error: Option<crate::rtw89::packet_core::Error>,
    wmm: bool,
    irq: Option<IrqModel>,
}
/// AX v0 interrupt registers with write-1-clear status, behind the same
/// `irq::Mask` programs the native binding runs.
#[derive(Default)]
struct IrqModel {
    regs: alloc::collections::BTreeMap<u32, u32>,
    mask: crate::rtw89::irq::Mask,
    services: u32,
    rearms: u32,
}
impl IrqModel {
    fn get(&self, address: u32) -> u32 {
        *self.regs.get(&address).unwrap_or(&0)
    }
}
impl crate::rtw89::irq::Regs for IrqModel {
    fn read32(&mut self, address: u32) -> Result<u32, crate::rtw89::power::Error> {
        Ok(self.get(address))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), crate::rtw89::power::Error> {
        use crate::rtw89::irq::{R_AX_HISR0, R_AX_PCIE_HISR00, R_AX_PCIE_HISR10};
        let entry = self.regs.entry(address).or_insert(0);
        if matches!(address, R_AX_HISR0 | R_AX_PCIE_HISR00 | R_AX_PCIE_HISR10) {
            *entry &= !value;
        } else {
            *entry = value;
        }
        Ok(())
    }
}
impl DriverModel {
    fn new() -> Self {
        let factory = crate::rtw89::station_control::tests::factory(false);
        Self {
            controller: crate::rtw89::station_control::Controller::new(&factory).unwrap(),
            control: crate::rtw89::station_control::tests::Model::new(),
            packets: crate::rtw89::packet_core::tests::Model::new(),
            core: None,
            clock: Arc::new(AtomicU64::new(0)),
            stopped: false,
            packet_error: None,
            wmm: false,
            irq: None,
        }
    }
    fn packet<T>(
        &mut self,
        op: impl FnOnce(
            &mut crate::rtw89::packet_core::Core,
            &mut crate::rtw89::packet_core::tests::Model,
        ) -> Result<T, crate::rtw89::packet_core::Error>,
    ) -> Result<T, crate::rtw89::packet_core::Error> {
        self.packets.now = self.clock.load(Ordering::Acquire) * 1000;
        let result = op(
            self.core
                .as_mut()
                .ok_or(crate::rtw89::packet_core::Error::State)?,
            &mut self.packets,
        );
        if let Err(error) = result {
            self.packet_error = Some(error);
        }
        result
    }
}
#[async_trait::async_trait]
// SAFETY: private inert source-controller/actual-DMA model only; the production
// Native OrdinaryGrant remains unconstructible by this fixture. Both adapters
// invoke their actual typed fixture capability around published operations.
unsafe impl crate::rtw89::station::Io for DriverModel {
    fn station_allowed(&mut self) -> Result<(), crate::rtw89::power::Error> {
        if self.stopped {
            return Err(crate::rtw89::power::Error::Terminal);
        }
        self.packets
            .authority
            .check_live()
            .map_err(|_| crate::rtw89::power::Error::Access)
    }
    fn station_own(&mut self) -> Result<[u8; 6], crate::rtw89::power::Error> {
        self.station_allowed()?;
        Ok(self.controller.own())
    }
    fn station_wmm_allowed(&mut self) -> Result<bool, crate::rtw89::power::Error> {
        self.station_allowed()?;
        Ok(self.wmm)
    }
    async fn station_configure_wmm(
        &mut self,
        p: narf_wireless::wmm::Parameters,
        short: bool,
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        self.station_allowed()?;
        if !self.wmm {
            return Err(crate::rtw89::power::Error::Unsupported);
        }
        self.controller
            .configure_wmm(&mut self.control, p, short, admission)
            .await
    }
    async fn station_prepare_initial(
        &mut self,
        own: [u8; 6],
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        if own != self.controller.own() {
            return Err(crate::rtw89::power::Error::Unsupported);
        }
        self.controller
            .initialize(&mut self.control, admission)
            .await
    }
    async fn station_prepare_peer(
        &mut self,
        peer: [u8; 6],
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        self.packets.peer = Some(
            self.controller
                .prepare_peer(&mut self.control, peer, admission)
                .await?,
        );
        Ok(())
    }
    async fn station_commit_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        short: bool,
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        self.controller
            .commit_peer(&mut self.control, peer, aid, short, admission)
            .await
    }
    async fn station_disconnect(
        &mut self,
        _peer: [u8; 6],
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        self.controller
            .disconnect(&mut self.control, admission)
            .await
    }
    fn packet_prepare(
        &mut self,
        own: [u8; 6],
        macid: u8,
    ) -> Result<(), crate::rtw89::packet_core::Error> {
        self.core = Some(crate::rtw89::packet_core::Core::prepare(
            &mut self.packets,
            own,
            macid,
        )?);
        Ok(())
    }
    fn packet_start(&mut self) -> Result<(), crate::rtw89::packet_core::Error> {
        self.packet(|c, p| c.start(p))
    }
    fn packet_ready(&self) -> bool {
        self.core
            .as_ref()
            .is_some_and(crate::rtw89::packet_core::Core::ready)
    }
    fn packet_submit(
        &mut self,
        bytes: &[u8],
        report: bool,
    ) -> Result<u64, crate::rtw89::packet_core::Error> {
        self.packet(|c, p| c.submit(p, bytes, report))
    }
    fn packet_submit_rate(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
    ) -> Result<u64, crate::rtw89::packet_core::Error> {
        if rate != 0 && !self.wmm {
            return Err(crate::rtw89::packet_core::Error::Access);
        }
        self.packet(|c, p| c.submit_rate(p, bytes, report, rate))
    }
    fn packet_poll(
        &mut self,
    ) -> Result<crate::rtw89::packet_core::Step, crate::rtw89::packet_core::Error> {
        self.packet(|c, p| c.poll(p))
    }
    fn irq_start(
        &mut self,
        _line: &Arc<crate::rtw89::irq::Line>,
    ) -> Result<u8, crate::rtw89::power::Error> {
        if self.stopped || self.irq.is_some() || !self.packet_ready() {
            return Err(crate::rtw89::power::Error::Terminal);
        }
        let mut model = IrqModel {
            mask: crate::rtw89::irq::Mask::config(crate::rtw89::mac::ChipId::Rtl8852B, false)
                .ok_or(crate::rtw89::power::Error::Unsupported)?,
            ..IrqModel::default()
        };
        let mask = model.mask;
        mask.enable(&mut model)?;
        self.irq = Some(model);
        Ok(0x40)
    }
    fn irq_service(&mut self) -> Result<crate::rtw89::irq::Events, crate::rtw89::power::Error> {
        let Some(model) = self.irq.as_mut() else {
            return Ok(crate::rtw89::irq::Events::default());
        };
        model.services += 1;
        let mask = model.mask;
        crate::rtw89::irq::Mask::disable(model)?;
        Ok(mask.recognize(model)?.events())
    }
    fn irq_rearm(&mut self) -> Result<(), crate::rtw89::power::Error> {
        let Some(model) = self.irq.as_mut() else {
            return Ok(());
        };
        model.rearms += 1;
        let mask = model.mask;
        mask.enable(model)
    }
    fn packet_stop(&mut self) -> Result<(), crate::rtw89::packet_core::Error> {
        if let Some(model) = self.irq.as_mut() {
            let _ = crate::rtw89::irq::Mask::disable(model);
        }
        self.controller.invalidate();
        self.stopped = true;
        if self.core.is_some() {
            self.packet(|c, p| c.stop(p))
        } else {
            Ok(())
        }
    }
}

type TestDevice = Device<DriverModel>;
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
    panic!("RTL8852B retained station fixture stalled");
}
struct Harness {
    device: Arc<TestDevice>,
    lifecycle: Arc<Lifecycle<DriverModel>>,
    peer: Arc<IrqSafeSpinLock<Peer>>,
    env: Arc<Env>,
    plan: NetworkPlan,
}
impl Harness {
    fn new(protected: bool) -> Self {
        Self::profile(protected, false)
    }
    fn profile(protected: bool, wmm: bool) -> Self {
        Self::rates_profile(protected, wmm, None)
    }
    fn rates_profile(protected: bool, wmm: bool, rates: Option<&[u8]>) -> Self {
        assert!(ACTIVE_TEST.lock().is_none());
        let mut io = DriverModel::new();
        io.wmm = wmm;
        // The AP sees current DMA at publication; these independent device
        // actions then advance the real modeled RP and emit parsed RPQ.
        io.packets.consume = true;
        io.packets.release = true;
        let env = Arc::new(Env {
            clock: io.clock.clone(),
            entropy: AtomicBool::new(true),
        });
        let mut peer = Peer::new(protected);
        if let Some(rates) = rates {
            peer.ap = peer.ap.with_legacy_rates(rates).unwrap();
        }
        let peer = Arc::new(IrqSafeSpinLock::new(peer));
        if wmm {
            peer.lock().wmm = Some(WMM.to_vec());
        }
        let plan = peer.lock().plan;
        let actor = peer.clone();
        io.packets.reaction = Some(Arc::new(move |bytes| {
            actor
                .lock()
                .react(bytes)
                .map_err(|_| crate::rtw89::packet_core::Error::Packet)
        }));
        let lifecycle = Arc::new(Lifecycle::new(io));
        let name = narf_net::iface::reserve_name("r89-source%d");
        let device = Arc::new(Device::new(name, OWN, lifecycle.clone(), env.clone()));
        *ACTIVE_TEST.lock() = Some(device.clone());
        narf_net::iface::register(name, OWN, send);
        narf_net::iface::set_link_state(name, true); // operator IFF_UP, not PHY state
        narf_net::iface::set_link_metadata(name, false, None, None);
        narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
        narf_net::iface::install_rx_drain(drain);
        device.admit_for_test();
        complete(device.activate()).unwrap();
        {
            let mut beacon = peer.lock().ap.beacon();
            if wmm {
                beacon.extend_from_slice(&WMM);
            }
            let mut retained = lifecycle.retained.try_lock().unwrap();
            retained
                .as_mut()
                .unwrap()
                .io
                .packets
                .inject(&beacon)
                .unwrap();
        }
        Self {
            device,
            lifecycle,
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
    fn join(&self) -> Result<(), narf_wireless::WirelessError> {
        self.scan();
        complete(self.device.associate(self.request()))?;
        assert!(self.device.link_up());
        assert_eq!(self.device.connected_bssid(), Some(AP));
        Ok(())
    }
    fn model<T>(&self, operation: impl FnOnce(&mut DriverModel) -> T) -> T {
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
fn smoke_rtw8852b_negotiated_legacy_rate_actual_txwd_ccmp_and_source_gate() -> TestResult {
    const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    for protected in [false, true] {
        let cases = RATES
            .iter()
            .enumerate()
            .map(|(index, &code)| {
                (
                    if index == 0 {
                        vec![code]
                    } else {
                        vec![0x82, code]
                    },
                    index as u16,
                )
            })
            .chain(core::iter::once((RATES.to_vec(), 11)));
        for (response, expected) in cases {
            let h = Harness::rates_profile(protected, true, Some(&RATES));
            {
                let mut p = h.peer.lock();
                let ap = core::mem::replace(&mut p.ap, Peer::new(protected).ap);
                p.ap = ap.with_legacy_rates(&response).unwrap();
            }
            if h.join().is_err() {
                return TestResult::Fail("B richer rate source-controller association");
            }
            let ethernet = udp_ipv4(
                AP,
                OWN,
                h.plan.lease_ip,
                h.plan.server_ip,
                44002,
                44003,
                b"B12 legacy native TXWD",
            );
            if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
                return TestResult::Fail("B richer-rate publication");
            }
            h.pump();
            if h.peer.lock().uplink.last() != Some(&ethernet)
                || h.model(|io| io.packets.last.map(|s| s.legacy_rate)) != Some(expected)
            {
                return TestResult::Fail("B native TXWD rate or response-bound data/CCMP differs");
            }
            h.model(|io| io.packets.authority.revoke());
            h.pump();
            if !h.closed() {
                return TestResult::Fail("B richer-rate owner survived PCI epoch loss");
            }
        }
    }
    // An unchanged legacy qualification continues to choose CCK1 even if the
    // AP offers all rates; formatting/native DMA alone cannot opt it in.
    let h = Harness::rates_profile(false, false, Some(&RATES));
    if h.join().is_err() {
        return TestResult::Fail("B legacy qualification rate regression");
    }
    let ethernet = udp_ipv4(
        AP,
        OWN,
        h.plan.lease_ip,
        h.plan.server_ip,
        44002,
        44003,
        b"B legacy scope",
    );
    if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
        return TestResult::Fail("B legacy fixed rate send");
    }
    h.pump();
    if h.model(|io| io.packets.last.map(|s| s.legacy_rate)) != Some(0) {
        return TestResult::Fail("B legacy qualification promoted richer rates");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/rates",
    smoke_rtw8852b_negotiated_legacy_rate_actual_txwd_ccmp_and_source_gate
);
impl Drop for Harness {
    fn drop(&mut self) {
        *ACTIVE_TEST.lock() = None;
        narf_net::iface::unregister(self.device.name());
    }
}
fn smoke_rtw8852b_wmm_source_peer_commands_native_qos_ccmp_and_ip() -> TestResult {
    for protected in [false, true] {
        let h = Harness::profile(protected, true);
        if h.join().is_err() {
            return TestResult::Fail("B WMM actual controller/packet association failed");
        }
        let commands = h.model(|io| io.control.packets().to_vec());
        let tail: Vec<_> = commands
            .iter()
            .filter(|p| {
                p.len() == 20 && p[8..12] == [0, 0, 0, 0] && p[12..16] == [0x46, 0xa5, 0, 0]
            })
            .collect();
        if tail.len() != 1 || !h.peer.lock().qos {
            return TestResult::Fail("B WMM firmware EDCA literal or bound AP negotiation missing");
        }
        let ethernet = udp_ipv4(
            AP,
            OWN,
            h.plan.lease_ip,
            h.plan.server_ip,
            45000,
            45001,
            b"B WMM exact uplink",
        );
        if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
            return TestResult::Fail("B QoS publish refused");
        }
        h.pump();
        if h.peer.lock().uplink.last() != Some(&ethernet) {
            return TestResult::Fail("B QoS raw26/TID0 TXWD or CCMP failed");
        }
        let reply = udp_ipv4(
            OWN,
            AP,
            h.plan.server_ip,
            h.plan.lease_ip,
            45001,
            45000,
            b"B WMM exact reply",
        );
        let frame = match h.peer.lock().downlink(&reply) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("B WMM AP fixture"),
        };
        h.model(|io| io.packets.inject(&frame)).unwrap();
        h.pump();
        if h.received() != vec![reply] {
            return TestResult::Fail("B WMM native RX/per-TID CCMP data changed");
        }
        h.model(|io| io.packets.authority.revoke());
        h.pump();
        if !h.closed() {
            return TestResult::Fail("B WMM retained carrier after actual PCI epoch loss");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/wmm",
    smoke_rtw8852b_wmm_source_peer_commands_native_qos_ccmp_and_ip
);
fn smoke_rtw8852b_wmm_response_rejection_and_pending_m4_cancellation_close_owner() -> TestResult {
    for cancel in [false, true] {
        let h = Harness::profile(true, true);
        h.scan();
        if cancel {
            h.peer.lock().hold_m4 = true;
        } else {
            h.peer.lock().wmm.as_mut().unwrap()[14] |= 16;
        }
        let controls = h.model(|io| io.packets.controls.clone());
        let mut operation = Box::pin(h.device.associate(h.request()));
        let mut cx = Context::from_waker(Waker::noop());
        if cancel {
            let mut held = false;
            for _ in 0..10000 {
                if operation.as_mut().poll(&mut cx).is_ready() {
                    return TestResult::Fail("B WMM held M4 completed");
                }
                if controls.held.load(Ordering::Acquire) {
                    held = true;
                    break;
                }
            }
            if !held {
                return TestResult::Fail("B WMM fixture never retained M4 DMA");
            }
            drop(operation);
        } else {
            let result = complete(operation);
            if result.is_ok() {
                return TestResult::Fail("B invalid response BE admission promoted QoS");
            }
        }
        h.pump();
        if !h.closed() {
            return TestResult::Fail("B cancelled/invalid WMM retained established metadata");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/wmm",
    smoke_rtw8852b_wmm_response_rejection_and_pending_m4_cancellation_close_owner
);
fn composition(protected: bool) -> TestResult {
    let h = Harness::new(protected);
    if !h.closed() || narf_net::dhcp::acquire(h.device.name(), 100).is_ok() {
        return TestResult::Fail("RTL8852B DHCP passed before native association");
    }
    if let Err(error) = h.join() {
        h.model(|io| narf_console::klog!("rtw8852b fixture associate {:?}, packet {:?}, controller {:?}, TX {} commands {}\n", error, io.packet_error, io.controller.phase(), io.packets.transmitted.len(), io.control.packets().len()));
        return TestResult::Fail("RTL8852B source controller/packet association failed");
    }
    let lease = match narf_net::dhcp::dhcp_acquire(h.device.name(), 0) {
        Ok(lease) => lease,
        Err(_) => return TestResult::Fail("RTL8852B actual kernel DHCP failed"),
    };
    if !h.plan.matches_lease(&lease) {
        return TestResult::Fail("RTL8852B native DORA lease differs");
    }
    {
        let peer = h.peer.lock();
        let seen = peer.server.observations();
        if seen.discovers != 1 || seen.requests != 1 || peer.uplink.len() != 2 {
            return TestResult::Fail("RTL8852B native DHCP receipts differ");
        }
    }
    let uplink = udp_ipv4(
        AP,
        OWN,
        h.plan.lease_ip,
        h.plan.server_ip,
        49152,
        7,
        b"rtw8852b-native-uplink",
    );
    if narf_net::iface::send_on(h.device.name(), &uplink).is_err() {
        return TestResult::Fail("RTL8852B native IP TX refused");
    }
    h.pump();
    if h.peer.lock().uplink.last() != Some(&uplink) {
        return TestResult::Fail("RTL8852B actual DMA IP TX differs");
    }
    let downlink = udp_ipv4(
        OWN,
        AP,
        h.plan.server_ip,
        h.plan.lease_ip,
        7,
        49152,
        b"rtw8852b-native-downlink",
    );
    let wire = h.peer.lock().downlink(&downlink).unwrap();
    h.model(|io| io.packets.inject(&wire).unwrap());
    h.pump();
    if !h.received().contains(&downlink) {
        return TestResult::Fail("RTL8852B native IP RX differs");
    }
    if complete(h.device.disassociate()).is_err() || !h.closed() || !h.model(|io| io.stopped) {
        return TestResult::Fail("RTL8852B terminal disconnect not parked");
    }
    if h.device.enqueue(&uplink, TxMeta::default()).is_ok() {
        return TestResult::Fail("RTL8852B disconnected packet publication reopened");
    }
    TestResult::Pass
}
fn smoke_rtw8852b_source_controller_packet_device_open_kernel_dhcp_ip() -> TestResult {
    composition(false)
}
fn smoke_rtw8852b_source_controller_packet_device_wpa2_kernel_dhcp_ip() -> TestResult {
    composition(true)
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_source_controller_packet_device_open_kernel_dhcp_ip
);
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_source_controller_packet_device_wpa2_kernel_dhcp_ip
);

fn smoke_rtw8852b_native_m4_requires_exact_terminal_receipt_and_idle_peer() -> TestResult {
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
                return TestResult::Fail("RTL8852B held M4 completed association");
            }
        }
        if !controls.held.load(Ordering::Acquire)
            || !h.closed()
            || h.peer.lock().ap.phase() != ApPhase::Authorized
            || narf_net::dhcp::acquire(h.device.name(), 100).is_ok()
        {
            return TestResult::Fail("RTL8852B M4 did not retain an actual closed DMA wait");
        }
        match case {
            0 => {
                drop(future);
                controls.release.store(true, Ordering::Release);
                h.pump();
                if !h.device.closed() || !h.closed() || !h.model(|io| io.stopped) {
                    return TestResult::Fail(
                        "RTL8852B cancelled M4 later reopened or kept DMA active",
                    );
                }
                continue;
            }
            1 => controls.corrupt.store(true, Ordering::Release),
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
                return TestResult::Fail("RTL8852B exact terminal M4 failed to authorize");
            }
            complete(h.device.disassociate()).unwrap();
        } else if result.is_ok() || !h.closed() || !h.model(|io| io.stopped) {
            return TestResult::Fail("RTL8852B altered M4 or queued peer loss authorized");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_native_m4_requires_exact_terminal_receipt_and_idle_peer
);

fn smoke_rtw8852b_native_rekey_missing_m3_expires_despite_fresh_beacons() -> TestResult {
    use narf_wireless::eapol::{
        KI_KEY_ACK, KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE, KI_VERSION_HMAC_SHA1_AES,
    };
    let h = Harness::new(true);
    h.join().unwrap();
    let before = h.model(|io| io.packets.publications);
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
    h.model(|io| io.packets.inject(&wire).unwrap());
    h.pump();
    let m2 = h.peer.lock().uplink.last().cloned().unwrap_or_default();
    let reply = m2.get(18..).and_then(|bytes| KeyFrame::decode(bytes, 16));
    if reply.is_none_or(|key| key.replay_counter != 3 || key.key_information & KI_KEY_MIC == 0)
        || m2.get(12..14) != Some(&[0x88, 0x8e])
        || h.model(|io| io.packets.publications) != before + 1
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
        return TestResult::Fail("RTL8852B rekey lacks terminal old-key M2 and reopened old port");
    }
    let start = h.env.clock.load(Ordering::Acquire);
    for delta in [1000, 2000, 3000, 4000, 4999, 5001] {
        h.env.clock.store(start + delta, Ordering::Release);
        let beacon = h.peer.lock().ap.beacon();
        h.model(|io| io.packets.inject(&beacon).unwrap());
        h.pump();
        if delta < 5000 && !h.device.link_up() {
            return TestResult::Fail("RTL8852B rekey prematurely lost established carrier");
        }
    }
    if !h.closed() || !h.model(|io| io.stopped) {
        return TestResult::Fail("RTL8852B fresh beacons hid whole-rekey M3 timeout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_native_rekey_missing_m3_expires_despite_fresh_beacons
);

fn smoke_rtw8852b_native_disconnect_reservation_and_cancel_preserve_cleanup() -> TestResult {
    for cancel in [false, true] {
        let h = Harness::new(false);
        h.join().unwrap();
        let retained = h.lifecycle.retained.try_lock().unwrap();
        let mut future = Box::pin(h.device.disassociate());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
            || !h.closed()
            || !h.device.admission().teardown_pending()
            || retained.as_ref().unwrap().io.stopped
        {
            return TestResult::Fail("RTL8852B disconnect failed to reserve before owner wait");
        }
        drop(retained);
        h.pump();
        if h.model(|io| io.stopped) {
            return TestResult::Fail("RTL8852B worker terminalized native owner before media-down");
        }
        if cancel {
            drop(future);
            h.pump();
        } else if complete(future).is_err() {
            return TestResult::Fail("RTL8852B reserved disconnect could not finish cleanup");
        }
        if !h.closed() || !h.model(|io| io.stopped) || h.device.admission().teardown_pending() {
            return TestResult::Fail("RTL8852B finished or cancelled disconnect retained traffic");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_native_disconnect_reservation_and_cancel_preserve_cleanup
);

fn smoke_rtw8852b_irq_driven_worker_services_rearms_and_halts() -> TestResult {
    use crate::rtw89::irq::*;
    let h = Harness::new(false);
    if h.join().is_err() {
        return TestResult::Fail("RTL8852B IRQ fixture association failed");
    }
    if complete(h.device.arm_interrupts()) != Ok(0x40) || !h.device.interrupts() {
        return TestResult::Fail("RTL8852B MSI binding not armed after station start");
    }
    if complete(h.device.arm_interrupts()).is_ok() {
        return TestResult::Fail("RTL8852B MSI bound twice");
    }
    if h.model(|io| io.irq.as_ref().map(|m| m.get(R_AX_PCIE_HIMR00))) != Some(0x011e_0007) {
        return TestResult::Fail("RTL8852B start did not enable the Linux mask");
    }
    // Downlink frame arrives with RXDMA status and an MSI.
    let downlink = udp_ipv4(
        OWN,
        AP,
        h.plan.server_ip,
        [10, 0, 0, 9],
        7,
        9,
        b"rtw8852b-irq",
    );
    let Ok(wire) = h.peer.lock().downlink(&downlink) else {
        return TestResult::Fail("fixture downlink failed");
    };
    let injected = h.model(|io| {
        if let Some(m) = io.irq.as_mut() {
            m.regs
                .insert(R_AX_PCIE_HISR00, B_AX_RXDMA_INT_EN | (1 << 9));
        }
        io.packets.inject(&wire).is_ok()
    });
    if !injected {
        return TestResult::Fail("fixture injection failed");
    }
    let before = h.device.line().raised();
    h.device.line().raise();
    if h.device.line().raised() == before {
        return TestResult::Fail("line did not record the MSI");
    }
    h.device.drain();
    let (services, rearms, hisr, himr) = h.model(|io| {
        io.irq.as_ref().map_or((0, 0, 0, 0), |m| {
            (
                m.services,
                m.rearms,
                m.get(R_AX_PCIE_HISR00),
                m.get(R_AX_PCIE_HIMR00),
            )
        })
    });
    if services != 1 || rearms != 1 {
        return TestResult::Fail("worker pass did not service then rearm exactly once");
    }
    if hisr != 1 << 9 || himr != 0x011e_0007 {
        return TestResult::Fail("worker acknowledged foreign status or left the mask off");
    }
    // A TX enqueue kicks the worker line instead of waiting for a poll tick.
    let uplink = udp_ipv4(AP, OWN, [10, 0, 0, 9], h.plan.server_ip, 9, 7, b"kick");
    let kicked = h.device.line().raised();
    if h.device.enqueue(&uplink, TxMeta::default()).is_err() || h.device.line().raised() == kicked {
        return TestResult::Fail("TX enqueue did not kick the IRQ worker");
    }
    h.pump();
    // Firmware halt (SER) is fatal: the owner closes and stops packets.
    h.model(|io| {
        if let Some(m) = io.irq.as_mut() {
            m.regs.insert(R_AX_HISR0, B_AX_HALT_C2H_INT_EN);
        }
    });
    h.device.line().raise();
    h.device.drain();
    if !h.closed() || !h.model(|io| io.stopped) || h.device.interrupts() {
        return TestResult::Fail("RTL8852B halt interrupt did not terminate the station");
    }
    if h.model(|io| io.irq.as_ref().map(|m| m.get(R_AX_PCIE_HIMR00))) != Some(0) {
        return TestResult::Fail("RTL8852B stop left the interrupt mask enabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_irq_driven_worker_services_rearms_and_halts
);
