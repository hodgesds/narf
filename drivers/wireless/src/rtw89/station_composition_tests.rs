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
/// AP HT Capabilities (LDPC|SGI20, 64K/no density, RX MCS0..15) and HT
/// Operation (primary channel 1, 20MHz).
const HT_IES: [u8; 52] = [
    45, 26, 33, 0, 3, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61,
    22, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// AP HE Capabilities (2.4GHz 20MHz, HTC_HE, LDPC, STBC RX, DCM RX 16QAM,
/// RX/TX 2SS HE-MCS0..11) and HE Operation (BSS color 1, basic NSS1
/// HE-MCS0..7, ER SU allowed).
const HE_IES: [u8; 33] = [
    255, 22, 35, 0x01, 0, 0, 0, 0, 0, 0x00, 0x20, 0x08, 0x18, 0, 0, 0, 0, 0, 0, 0, 0xfa, 0xff,
    0xfa, 0xff, 255, 7, 36, 0, 0, 0, 1, 0xfc, 0xff,
];
/// `HE_IES` with HE Operation ER SU Disable set and no DCM RX.
const HE_IES_NO_ER: [u8; 33] = [
    255, 22, 35, 0x01, 0, 0, 0, 0, 0, 0x00, 0x20, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0xfa, 0xff,
    0xfa, 0xff, 255, 7, 36, 0, 0, 1, 1, 0xfc, 0xff,
];
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
    /// Accept TID1..7 (all-AC program); otherwise only BE/TID0.
    qos_all: bool,
    /// QoS TID of each accepted uplink data frame.
    pub(super) tids: Vec<u8>,
    /// AP HT Capabilities + HT Operation appended to the association response.
    ht: Option<Vec<u8>>,
    /// Station association request carried an HT Capabilities element.
    pub(super) station_ht: bool,
    /// AP HE Capabilities + HE Operation appended to the association response.
    he: Option<Vec<u8>>,
    /// Station association request carried an HE Capabilities element.
    pub(super) station_he: bool,
    /// Action frames sent by the station after authorization.
    pub(super) actions: Vec<Vec<u8>>,
    /// Probe requests sent by the station.
    pub(super) probes: Vec<Vec<u8>>,
    /// Answer an ADDBA Request with (status, buffer size); `None` ignores it.
    pub(super) addba: Option<(u16, u16)>,
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
            qos_all: false,
            tids: Vec::new(),
            ht: None,
            station_ht: false,
            he: None,
            station_he: false,
            actions: Vec::new(),
            probes: Vec::new(),
            addba: None,
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
        if frame[0] == 0x40 {
            // Answer like an AP: the beacon body as a directed probe response.
            self.probes.push(frame.to_vec());
            let mut response = self.ap.beacon();
            response[0] = 0x50;
            // Directed to the probe's source (own or random scan address).
            response[4..10].copy_from_slice(&frame[10..16]);
            if let Some(p) = &self.wmm {
                response.extend_from_slice(p);
            }
            return Ok((vec![response], false));
        }
        if frame.len() < 24 || frame[4..10] != AP || frame[10..16] != self.plan.station {
            return Err("native AP peer identity");
        }
        if self.ap.phase() == ApPhase::Authorized && frame[0] == 0xd0 {
            self.actions.push(frame.to_vec());
            // ADDBA Request -> ADDBA Response (token, status, policy|TID|buf).
            if let (Some((status, buf)), Some(&[3, 0, token, c0, c1])) =
                (self.addba, frame.get(24..29))
            {
                let tid = (u16::from_le_bytes([c0, c1]) >> 2) & 0xf;
                let capab = 1u16 << 1 | tid << 2 | buf << 6;
                let mut response = vec![0xd0, 0, 0, 0];
                response.extend_from_slice(&OWN);
                response.extend_from_slice(&AP);
                response.extend_from_slice(&AP);
                response.extend_from_slice(&[0x20, 0, 3, 1, token]);
                response.extend_from_slice(&status.to_le_bytes());
                response.extend_from_slice(&capab.to_le_bytes());
                response.extend_from_slice(&[0, 0]);
                return Ok((vec![response], false));
            }
            return Ok((Vec::new(), false));
        }
        if self.ap.phase() != ApPhase::Authorized || matches!(frame[0], 0 | 0xb0) {
            if frame[0] == 0 {
                self.qos = self.wmm.is_some() && frame.ends_with(&narf_wireless::wmm::INFORMATION);
                // Fixed fields end at 28; walk the IEs for HT Capabilities.
                let mut ies = frame.get(28..).unwrap_or(&[]);
                self.station_ht = false;
                self.station_he = false;
                while ies.len() >= 2 {
                    let end = 2 + usize::from(ies[1]);
                    if ies[0] == 45 && ies[1] == 26 {
                        self.station_ht = true;
                    }
                    if ies[0] == 255 && ies.get(2) == Some(&35) {
                        self.station_he = true;
                    }
                    ies = ies.get(end..).unwrap_or(&[]);
                }
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
                    if let Some(ht) = &self.ht {
                        reply.extend_from_slice(ht);
                    }
                    if let Some(he) = &self.he {
                        reply.extend_from_slice(he);
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
        let mut priority = 0;
        let header = if self.qos {
            let tid = frame.get(24).copied().ok_or("AP QoS control")?;
            priority = tid;
            if frame.get(25) != Some(&0) || tid > 7 || (!self.qos_all && tid != 0) {
                return Err("AP BE/TID0 QoS control");
            }
            self.tids.push(tid);
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
                priority,
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
    qos_all: bool,
    firmware_ra: bool,
    ht: bool,
    he: bool,
    /// Signed originator BA / TX A-MPDU program (`Program::Ampdu`).
    ampdu: bool,
    irq: Option<IrqModel>,
    /// HCI DMA stop/busy block behind `dma_stop::stop`.
    dma: crate::rtw89::dma_stop::tests::Model,
    reclaimed: Option<usize>,
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
            qos_all: false,
            firmware_ra: false,
            ht: false,
            he: false,
            ampdu: false,
            irq: None,
            dma: crate::rtw89::dma_stop::tests::Model::new(),
            reclaimed: None,
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
    fn station_firmware_ra_allowed(&mut self) -> Result<bool, crate::rtw89::power::Error> {
        self.station_allowed()?;
        Ok(self.wmm && self.firmware_ra)
    }
    async fn station_configure_ba(
        &mut self,
        valid: bool,
        tid: u8,
        buf: u16,
        ssn: u16,
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        if valid && !self.ht {
            return Err(crate::rtw89::power::Error::Unsupported);
        }
        self.controller
            .configure_ba(&mut self.control, valid, tid, buf, ssn, admission)
            .await
    }
    fn station_ht_allowed(&mut self) -> Result<bool, crate::rtw89::power::Error> {
        self.station_allowed()?;
        Ok(self.wmm && self.firmware_ra && self.ht)
    }
    fn station_he_allowed(&mut self) -> Result<bool, crate::rtw89::power::Error> {
        self.station_allowed()?;
        Ok(self.wmm && self.firmware_ra && self.ht && self.he)
    }
    fn station_ampdu_allowed(&mut self) -> Result<bool, crate::rtw89::power::Error> {
        self.station_allowed()?;
        Ok(self.wmm && self.firmware_ra && self.ht && self.ampdu)
    }
    async fn station_configure_agg_limit(
        &mut self,
        agg_num: Option<u16>,
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        if agg_num.is_some() && !self.station_ampdu_allowed()? {
            return Err(crate::rtw89::power::Error::Unsupported);
        }
        self.controller
            .configure_agg_limit(&mut self.control, agg_num, admission)
    }
    fn packet_ready_aggregate(&self) -> bool {
        self.core
            .as_ref()
            .is_some_and(crate::rtw89::packet_core::Core::ready_aggregate)
    }
    fn packet_submit_agg(
        &mut self,
        bytes: &[u8],
        report: bool,
        rate: u8,
        agg: crate::rtw89::packet_format::Agg,
    ) -> Result<u64, crate::rtw89::packet_core::Error> {
        if !(self.wmm && self.firmware_ra && self.ht && self.ampdu) {
            return Err(crate::rtw89::packet_core::Error::Access);
        }
        self.packet(|c, p| c.submit_agg(p, bytes, report, rate, Some(agg)))
    }
    async fn station_scan_address(
        &mut self,
        address: Option<[u8; 6]>,
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        self.controller
            .scan_address(&mut self.control, address, admission)
            .await
    }
    fn packet_scan_address(
        &mut self,
        scan: Option<[u8; 6]>,
    ) -> Result<(), crate::rtw89::packet_core::Error> {
        self.packet(|c, _| c.set_scan_address(scan))
    }
    async fn station_configure_ra(
        &mut self,
        rates: u16,
        ht: Option<crate::rtw89::station_control::HtRa>,
        he: Option<crate::rtw89::station_control::HeRa>,
        admission: &crate::rtw89::station_control::Admission,
    ) -> Result<(), crate::rtw89::power::Error> {
        if !self.station_firmware_ra_allowed()?
            || ht.is_some() && !self.ht
            || he.is_some() && !self.station_he_allowed()?
        {
            return Err(crate::rtw89::power::Error::Unsupported);
        }
        self.controller
            .configure_ra(&mut self.control, rates, ht, he, admission)
            .await
    }
    fn station_qos_all_allowed(&mut self) -> Result<bool, crate::rtw89::power::Error> {
        self.station_allowed()?;
        Ok(self.wmm && self.qos_all)
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
            .await?;
        if self.qos_all {
            self.controller.admit_all_tids(admission)?;
        }
        Ok(())
    }
    async fn station_update_wmm(
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
            .update_wmm(&mut self.control, p, short, admission)
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
        let mut core = crate::rtw89::packet_core::Core::prepare_with(
            &mut self.packets,
            own,
            macid,
            self.wmm && self.qos_all,
            crate::rtw89::packet_core::RxPhy::from_programs(
                self.wmm && self.firmware_ra && self.ht,
                self.wmm && self.firmware_ra && self.ht && self.he,
            ),
        )?;
        if self.wmm && self.firmware_ra && self.ht && self.ampdu {
            core.enable_aggregation()?;
        }
        self.core = Some(core);
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
        if rate != 0 && !self.wmm
            || rate & crate::rtw89::packet_format::FIRMWARE_RA != 0 && !self.firmware_ra
        {
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
    fn retire_dma(&mut self) -> bool {
        if crate::rtw89::dma_stop::stop(&mut self.dma).is_err() {
            return false;
        }
        // SAFETY: the modeled engines were proven idle with BME off; the
        // packet model has no device or DMA producer.
        let storage = self
            .core
            .as_mut()
            .map_or(0, |core| unsafe { core.reclaim_fenced() }.len());
        self.reclaimed = Some(storage);
        true
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
        Self::build(protected, wmm, false, rates, false)
    }
    fn build(protected: bool, wmm: bool, qos_all: bool, rates: Option<&[u8]>, ht: bool) -> Self {
        Self::build_phy(protected, wmm, qos_all, rates, ht, None)
    }
    /// `he`: `Some(program granted)` makes the AP advertise `HE_IES`
    /// (with ER SU disabled when `HE_IES_NO_ER` is chosen by the caller).
    fn build_phy(
        protected: bool,
        wmm: bool,
        qos_all: bool,
        rates: Option<&[u8]>,
        ht: bool,
        he: Option<(bool, &[u8])>,
    ) -> Self {
        Self::build_full(protected, wmm, qos_all, rates, ht, he, false)
    }
    /// `ampdu`: the signed aggregate program is granted.
    fn build_full(
        protected: bool,
        wmm: bool,
        qos_all: bool,
        rates: Option<&[u8]>,
        ht: bool,
        he: Option<(bool, &[u8])>,
        ampdu: bool,
    ) -> Self {
        assert!(ACTIVE_TEST.lock().is_none());
        let mut io = DriverModel::new();
        io.ampdu = ampdu;

        io.wmm = wmm;
        io.qos_all = qos_all;
        io.ht = ht;
        io.he = he.is_some_and(|(granted, _)| granted);
        io.firmware_ra |= ht;
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
            peer.lock().qos_all = qos_all;
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
            if ht {
                beacon.extend_from_slice(&HT_IES);
                peer.lock().ht = Some(HT_IES.to_vec());
            }
            if let Some((_, ies)) = he {
                beacon.extend_from_slice(ies);
                peer.lock().he = Some(ies.to_vec());
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

fn edca_beacon(h: &Harness, qos_info: u8, be_aci_aifsn: u8) -> Vec<u8> {
    let mut wmm = WMM;
    wmm[8] = qos_info;
    wmm[14] = be_aci_aifsn;
    let mut beacon = h.peer.lock().ap.beacon();
    beacon.extend_from_slice(&wmm);
    beacon
}
fn edca_rows(h: &Harness) -> Vec<Vec<u8>> {
    h.model(|io| io.control.packets().to_vec())
}
fn smoke_rtw8852b_live_ap_edca_change_reprograms_without_reassociation() -> TestResult {
    let h = Harness::profile(false, true);
    if h.join().is_err() {
        return TestResult::Fail("B WMM association failed");
    }
    let before = edca_rows(&h).len();
    // Same parameter-set count with different content: mac80211 ignores it.
    let ignored = edca_beacon(&h, 0x81, 0x05);
    if h.model(|io| io.packets.inject(&ignored)).is_err() {
        return TestResult::Fail("fixture injection failed");
    }
    h.pump();
    complete(h.device.apply_edca());
    if h.closed() || edca_rows(&h).len() != before {
        return TestResult::Fail("unchanged parameter-set count reprogrammed or closed");
    }
    // New count, BE AIFSN 3 -> 4: four source H2C rows, link stays up.
    let changed = edca_beacon(&h, 0x82, 0x04);
    if h.model(|io| io.packets.inject(&changed)).is_err() {
        return TestResult::Fail("fixture injection failed");
    }
    h.pump();
    complete(h.device.apply_edca());
    let rows = edca_rows(&h);
    let added = rows.get(before..).unwrap_or(&[]);
    if h.closed() || added.len() != 4 || added.iter().any(|row| row.len() != 20) {
        return TestResult::Fail("live EDCA change did not program exactly four rows");
    }
    if !added
        .iter()
        .any(|row| row[8..12] == [0, 0, 0, 0] && row[12..16] != [0x46, 0xa5, 0, 0])
    {
        return TestResult::Fail("live EDCA BE row unchanged");
    }
    // QoS data still flows on the updated peer.
    let ethernet = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 1, 2, b"edca");
    if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
        return TestResult::Fail("QoS publish refused after EDCA update");
    }
    h.pump();
    if h.peer.lock().uplink.last() != Some(&ethernet) {
        return TestResult::Fail("QoS data lost after EDCA update");
    }
    // A repeated beacon with the applied count is idempotent.
    h.model(|io| io.packets.inject(&changed)).ok();
    h.pump();
    complete(h.device.apply_edca());
    if edca_rows(&h).len() != before + 4 {
        return TestResult::Fail("applied EDCA set reprogrammed again");
    }
    // An inadmissible set (ACM on BE) still closes the station.
    let bad = edca_beacon(&h, 0x83, 0x13);
    h.model(|io| io.packets.inject(&bad)).ok();
    h.pump();
    if !h.closed() {
        return TestResult::Fail("inadmissible live EDCA set kept the link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/wmm",
    smoke_rtw8852b_live_ap_edca_change_reprograms_without_reassociation
);

/// Mark an Ethernet/IPv4 frame with `dscp` and refresh the header checksum.
fn with_dscp(mut frame: Vec<u8>, dscp: u8) -> Vec<u8> {
    frame[15] = dscp << 2;
    frame[24] = 0;
    frame[25] = 0;
    let mut sum = 0u32;
    for chunk in frame[14..34].chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    frame[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    frame
}
fn smoke_rtw8852b_all_ac_qos_routes_tids_to_ach_rings_with_strict_priority() -> TestResult {
    for protected in [false, true] {
        let h = Harness::build(protected, true, true, None, false);
        if h.join().is_err() {
            return TestResult::Fail("all-AC QoS association failed");
        }
        let ip = |port: u16, dscp: u8| {
            with_dscp(
                udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, port, 9, b"qos"),
                dscp,
            )
        };
        // EF (DSCP46) -> UP6 -> VO/ACH3 with QSEL3.
        let voice = ip(1000, 46);
        if narf_net::iface::send_on(h.device.name(), &voice).is_err() {
            return TestResult::Fail("VO publish refused");
        }
        h.pump();
        let last = h.model(|io| io.packets.last.map(|s| s.channel));
        if h.peer.lock().uplink.last() != Some(&voice)
            || h.peer.lock().tids.last() != Some(&6)
            || last != Some(3)
        {
            let tids = h.peer.lock().tids.clone();
            let matched = h.peer.lock().uplink.last() == Some(&voice);
            h.model(|io| {
                narf_console::klog!(
                    "rtw8852b qos fixture: matched={} tids={:?} channel={:?} packet={:?} closed={}\n",
                    matched,
                    tids,
                    last,
                    io.packet_error,
                    io.stopped
                )
            });
            return TestResult::Fail("EF frame not sent as TID6 on ACH3");
        }
        // Queue BK (CS1), BE (DF) and VI (AF41) before the worker runs: the
        // host scheduler serves VI, BE, BK in strict AC priority.
        let background = ip(1001, 8);
        let best = ip(1002, 0);
        let video = ip(1003, 34);
        for frame in [&background, &best, &video] {
            if narf_net::iface::send_on(h.device.name(), frame).is_err() {
                return TestResult::Fail("queued publish refused");
            }
        }
        h.pump();
        let (uplink, tids) = {
            let peer = h.peer.lock();
            (peer.uplink.clone(), peer.tids.clone())
        };
        let tail = uplink.get(uplink.len().saturating_sub(3)..).unwrap_or(&[]);
        if tail != [video.clone(), best.clone(), background.clone()]
            || tids.get(tids.len().saturating_sub(3)..) != Some(&[4, 0, 1][..])
        {
            return TestResult::Fail("strict AC priority or TID mapping differs");
        }
        if !protected {
            // RX on a non-zero TID is delivered (per-TID QoS header).
            let reply = udp_ipv4(OWN, AP, h.plan.server_ip, h.plan.lease_ip, 9, 1003, b"vi");
            let Ok(mut wire) = h.peer.lock().downlink(&reply) else {
                return TestResult::Fail("fixture downlink failed");
            };
            wire[24] = 5;
            if h.model(|io| io.packets.inject(&wire)).is_err() {
                return TestResult::Fail("fixture injection failed");
            }
            h.pump();
            if h.received() != vec![reply] {
                return TestResult::Fail("TID5 downlink not delivered");
            }
        }
    }
    // Without the signed all-AC program, EF stays on BE/TID0 (flags7 recipe).
    let h = Harness::profile(false, true);
    if h.join().is_err() {
        return TestResult::Fail("WMM-only association failed");
    }
    let voice = with_dscp(
        udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 1, 9, b"qos"),
        46,
    );
    if narf_net::iface::send_on(h.device.name(), &voice).is_err() {
        return TestResult::Fail("WMM-only publish refused");
    }
    h.pump();
    if h.peer.lock().tids.last() != Some(&0)
        || h.model(|io| io.packets.last.map(|s| s.channel)) != Some(0)
    {
        return TestResult::Fail("WMM-only recipe left BE/TID0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/wmm",
    smoke_rtw8852b_all_ac_qos_routes_tids_to_ach_rings_with_strict_priority
);

fn smoke_rtw8852b_firmware_ra_h2c_and_adaptive_data_txwd() -> TestResult {
    const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    // AP response: 1(basic),2,5.5,11,6,24,54 -> hardware bits 0..4, 8, 11.
    const RESPONSE: [u8; 7] = [0x82, 4, 11, 22, 12, 48, 108];
    for protected in [false, true] {
        let h = Harness::rates_profile(protected, true, Some(&RATES));
        {
            let mut p = h.peer.lock();
            let ap = core::mem::replace(&mut p.ap, Peer::new(protected).ap);
            let Ok(ap) = ap.with_legacy_rates(&RESPONSE) else {
                return TestResult::Fail("fixture AP rates");
            };
            p.ap = ap;
        }
        h.model(|io| io.firmware_ra = true);
        if h.join().is_err() {
            return TestResult::Fail("firmware RA association failed");
        }
        // Independent rtw89_phy_ra_sta_update arithmetic: mask 0x91f &
        // (OFDM|SUBCCK) = 0x915, mode CCK|OFDM, UPD_ALL, 20MHz, MACID0.
        let mut expected = [0u8; 16];
        expected[..4].copy_from_slice(&0x0010_0006u32.to_le_bytes());
        expected[4..8].copy_from_slice(&0x0915u32.to_le_bytes());
        let commands = h.model(|io| io.control.packets().to_vec());
        if commands
            .iter()
            .filter(|p| p.len() == 24 && p[8..] == expected)
            .count()
            != 1
        {
            return TestResult::Fail("RA_MACIDCFG H2C missing or differs");
        }
        let ethernet = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 7, 8, b"ra");
        if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
            return TestResult::Fail("firmware RA data refused");
        }
        h.pump();
        let last = h.model(|io| io.packets.last.map(|s| (s.fixed_rate, s.retry_lowest)));
        if h.peer.lock().uplink.last() != Some(&ethernet) || last != Some((false, 0)) {
            return TestResult::Fail("data TXWD did not hand the rate to firmware RA");
        }
    }
    // Without the signed program the revision2 fixed fastest rate remains.
    let h = Harness::rates_profile(false, true, Some(&RATES));
    if h.join().is_err() {
        return TestResult::Fail("fixed-rate association failed");
    }
    let ethernet = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 7, 8, b"fixed");
    if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
        return TestResult::Fail("fixed-rate data refused");
    }
    h.pump();
    let last = h.model(|io| io.packets.last.map(|s| (s.fixed_rate, s.legacy_rate)));
    if last != Some((true, 11)) {
        return TestResult::Fail("fixed-rate recipe changed without firmware RA");
    }
    if h.model(|io| io.control.packets().to_vec())
        .iter()
        .any(|p| p.len() == 24 && p[8..12] == 0x0010_0006u32.to_le_bytes())
    {
        return TestResult::Fail("RA H2C sent without the signed program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/rates",
    smoke_rtw8852b_firmware_ra_h2c_and_adaptive_data_txwd
);

fn smoke_rtw8852b_ht20_capability_ra_mcs_and_rx() -> TestResult {
    const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    for protected in [false, true] {
        let h = Harness::build(protected, true, false, Some(&RATES), true);
        if h.join().is_err() {
            return TestResult::Fail("HT20 association failed");
        }
        if !h.peer.lock().station_ht {
            return TestResult::Fail("association request lacked HT Capabilities");
        }
        // CCK|OFDM|HT, SGI20 and LDPC negotiated; legacy 0xfff plus peer
        // MCS0..15 masked to HT1SS|SUBOFDM|SUBCCK = 0xff015.
        let mut expected = [0u8; 16];
        expected[..4].copy_from_slice(&0x0070_000eu32.to_le_bytes());
        expected[4..8].copy_from_slice(&0x000f_f015u32.to_le_bytes());
        let commands = h.model(|io| io.control.packets().to_vec());
        if commands
            .iter()
            .filter(|p| p.len() == 24 && p[8..] == expected)
            .count()
            != 1
        {
            return TestResult::Fail("HT RA_MACIDCFG H2C missing or differs");
        }
        let ethernet = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 5, 6, b"ht");
        if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
            return TestResult::Fail("HT data refused");
        }
        h.pump();
        if h.peer.lock().uplink.last() != Some(&ethernet)
            || h.model(|io| io.packets.last.map(|s| s.fixed_rate)) != Some(false)
        {
            return TestResult::Fail("HT data not handed to firmware RA");
        }
        // Downlink at HT MCS7 (RTW89_HW_RATE_MCS0 + 7) is delivered.
        let reply = udp_ipv4(OWN, AP, h.plan.server_ip, h.plan.lease_ip, 6, 5, b"mcs7");
        let Ok(wire) = h.peer.lock().downlink(&reply) else {
            return TestResult::Fail("fixture downlink failed");
        };
        if h.model(|io| io.packets.inject_rate(&wire, 0x87)).is_err() {
            return TestResult::Fail("fixture injection failed");
        }
        h.pump();
        if h.received() != vec![reply] {
            return TestResult::Fail("HT MCS7 downlink not delivered");
        }
    }
    // Without the program: no HT element, and an HT PPDU is dropped
    // without closing the station.
    let h = Harness::rates_profile(false, true, Some(&RATES));
    if h.join().is_err() || h.peer.lock().station_ht {
        return TestResult::Fail("HT offered without the signed program");
    }
    let reply = udp_ipv4(OWN, AP, h.plan.server_ip, h.plan.lease_ip, 6, 5, b"mcs7");
    let Ok(wire) = h.peer.lock().downlink(&reply) else {
        return TestResult::Fail("fixture downlink failed");
    };
    if h.model(|io| io.packets.inject_rate(&wire, 0x87)).is_err() {
        return TestResult::Fail("fixture injection failed");
    }
    h.pump();
    if !h.received().is_empty() {
        return TestResult::Fail("non-HT station accepted an HT PPDU");
    }
    if h.closed() {
        h.model(|io| {
            narf_console::klog!(
                "rtw8852b ht drop: packet {:?} stopped {}\n",
                io.packet_error,
                io.stopped
            )
        });
        return TestResult::Fail("non-HT station died on an HT PPDU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/rates",
    smoke_rtw8852b_ht20_capability_ra_mcs_and_rx
);

fn he_ra(w0: u32, w1: u32) -> [u8; 16] {
    let mut expected = [0u8; 16];
    expected[..4].copy_from_slice(&w0.to_le_bytes());
    expected[4..8].copy_from_slice(&w1.to_le_bytes());
    expected
}
fn smoke_rtw8852b_he20_capability_ra_er_and_gi_ltf_rx() -> TestResult {
    const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    for protected in [false, true] {
        let h = Harness::build_phy(
            protected,
            true,
            false,
            Some(&RATES),
            true,
            Some((true, &HE_IES)),
        );
        if h.join().is_err() {
            return TestResult::Fail("HE20 association failed");
        }
        if !h.peer.lock().station_ht || !h.peer.lock().station_he {
            return TestResult::Fail("association request lacked HT/HE Capabilities");
        }
        // MODE HE|CCK|OFDM (0x13 << 1), DCM (peer DCM RX), UPD_ALL, SGI20
        // (HT), LDPC (peer HE); mask legacy 0xfff + HE NSS1 MCS0..11 masked
        // to HE1SS|SUBOFDM|SUBCCK = 0xfff015; no fixed GI/LTF.
        let commands = h.model(|io| io.control.packets().to_vec());
        let expected = he_ra(0x0071_0026, 0x00ff_f015);
        if commands
            .iter()
            .filter(|p| p.len() == 24 && p[8..] == expected)
            .count()
            != 1
        {
            return TestResult::Fail("HE RA_MACIDCFG H2C missing or differs");
        }
        let ethernet = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 5, 6, b"he");
        if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
            return TestResult::Fail("HE data refused");
        }
        h.pump();
        if h.peer.lock().uplink.last() != Some(&ethernet)
            || h.model(|io| io.packets.last.map(|s| (s.fixed_rate, s.er))) != Some((false, true))
        {
            return TestResult::Fail("HE data not on firmware RA with DATA_ER");
        }
        // Downlink at HE NSS1 MCS11 1xLTF+0.8us and NSS2 MCS0 4xLTF+3.2us.
        for (rate, gi_ltf, tag) in [(0x18bu16, 5u8, &b"mcs11"[..]), (0x190, 0, &b"nss2"[..])] {
            let reply = udp_ipv4(OWN, AP, h.plan.server_ip, h.plan.lease_ip, 6, 5, tag);
            let Ok(wire) = h.peer.lock().downlink(&reply) else {
                return TestResult::Fail("fixture downlink failed");
            };
            if h.model(|io| io.packets.inject_phy(&wire, rate, gi_ltf))
                .is_err()
            {
                return TestResult::Fail("fixture injection failed");
            }
            h.pump();
            if h.received() != vec![reply] {
                return TestResult::Fail("HE downlink not delivered");
            }
        }
        // Undefined GI/LTF (6) and HE NSS3 are dropped, not fatal.
        for (rate, gi_ltf) in [(0x18bu16, 6u8), (0x1a0, 0)] {
            let reply = udp_ipv4(OWN, AP, h.plan.server_ip, h.plan.lease_ip, 6, 5, b"bad");
            let Ok(wire) = h.peer.lock().downlink(&reply) else {
                return TestResult::Fail("fixture downlink failed");
            };
            if h.model(|io| io.packets.inject_phy(&wire, rate, gi_ltf))
                .is_err()
            {
                return TestResult::Fail("fixture injection failed");
            }
            h.pump();
            if !h.received().is_empty() || h.closed() {
                return TestResult::Fail("invalid HE PPDU delivered or fatal");
            }
        }
        // Teardown clears the negotiated HE state with the station.
        if complete(h.device.disassociate()).is_err() || !h.closed() || !h.model(|io| io.stopped) {
            return TestResult::Fail("HE disconnect not parked");
        }
    }
    // ER SU disabled by the AP: no DATA_ER; no AP DCM RX: no DCM bit.
    let h = Harness::build_phy(
        false,
        true,
        false,
        Some(&RATES),
        true,
        Some((true, &HE_IES_NO_ER)),
    );
    if h.join().is_err() {
        return TestResult::Fail("HE20 no-ER association failed");
    }
    let expected = he_ra(0x0070_0026, 0x00ff_f015);
    if !h
        .model(|io| io.control.packets().to_vec())
        .iter()
        .any(|p| p.len() == 24 && p[8..] == expected)
    {
        return TestResult::Fail("HE RA without DCM differs");
    }
    let ethernet = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, 5, 6, b"noer");
    if narf_net::iface::send_on(h.device.name(), &ethernet).is_err() {
        return TestResult::Fail("HE no-ER data refused");
    }
    h.pump();
    if h.model(|io| io.packets.last.map(|s| s.er)) != Some(false) {
        return TestResult::Fail("DATA_ER set although the AP disabled ER SU");
    }
    drop(h);
    // Program not granted: HT only, no HE element, HE PPDU dropped
    // without closing the station.
    let h = Harness::build_phy(
        false,
        true,
        false,
        Some(&RATES),
        true,
        Some((false, &HE_IES)),
    );
    if h.join().is_err() || !h.peer.lock().station_ht || h.peer.lock().station_he {
        return TestResult::Fail("HE offered without the signed program");
    }
    let ht = he_ra(0x0070_000e, 0x000f_f015);
    if !h
        .model(|io| io.control.packets().to_vec())
        .iter()
        .any(|p| p.len() == 24 && p[8..] == ht)
    {
        return TestResult::Fail("non-HE station did not keep the HT RA");
    }
    let reply = udp_ipv4(OWN, AP, h.plan.server_ip, h.plan.lease_ip, 6, 5, b"he");
    let Ok(wire) = h.peer.lock().downlink(&reply) else {
        return TestResult::Fail("fixture downlink failed");
    };
    if h.model(|io| io.packets.inject_phy(&wire, 0x185, 3))
        .is_err()
    {
        return TestResult::Fail("fixture injection failed");
    }
    h.pump();
    if !h.received().is_empty() || h.closed() {
        return TestResult::Fail("non-HE station accepted or died on an HE PPDU");
    }
    drop(h);
    // Failure: an AP without HE keeps the HT association under the program.
    let h = Harness::build_phy(false, true, false, Some(&RATES), true, None);
    if h.join().is_err() || h.peer.lock().station_he {
        return TestResult::Fail("HT-only AP association changed");
    }
    if !h
        .model(|io| io.control.packets().to_vec())
        .iter()
        .any(|p| p.len() == 24 && p[8..] == ht)
    {
        return TestResult::Fail("HT-only AP did not get the HT RA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/rates",
    smoke_rtw8852b_he20_capability_ra_er_and_gi_ltf_rx
);

fn ba_action(body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0xd0, 0, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0x10, 0]);
    frame.extend_from_slice(body);
    frame
}
fn addba_request(tid: u8, buf: u16, ssn: u16) -> Vec<u8> {
    let capab = 1u16 << 1 | u16::from(tid) << 2 | buf << 6;
    let mut body = vec![3, 0, 5];
    body.extend_from_slice(&capab.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(ssn << 4).to_le_bytes());
    ba_action(&body)
}
fn downlink_seq(h: &Harness, sequence: u16, tag: u8) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let reply = udp_ipv4(OWN, AP, h.plan.server_ip, h.plan.lease_ip, 9, 9, &[tag; 8]);
    let mut wire = h.peer.lock().downlink(&reply)?;
    wire[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    Ok((wire, reply))
}
fn smoke_rtw8852b_recipient_block_ack_reorders_and_tears_down() -> TestResult {
    const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    let h = Harness::build(false, true, false, Some(&RATES), true);
    if h.join().is_err() {
        return TestResult::Fail("HT association failed");
    }
    let before = h.model(|io| io.control.packets().len());
    if h.model(|io| io.packets.inject(&addba_request(0, 64, 100)))
        .is_err()
    {
        return TestResult::Fail("fixture injection failed");
    }
    h.pump();
    complete(h.device.apply_edca());
    h.pump();
    // rtw89_fw_h2c_ba_cam: VALID|INIT_REQ, entry0, TID0, MACID0, bmap 64, SSN100.
    let cam = h.model(|io| io.control.packets()[before..].to_vec());
    if !cam
        .iter()
        .any(|p| p.len() == 16 && p[8..12] == 0x0640_0003u32.to_le_bytes())
    {
        return TestResult::Fail("BA CAM H2C missing or differs");
    }
    let response = h.peer.lock().actions.last().cloned().unwrap_or_default();
    // category3 action1 token5 status0, capab policy1|TID0|buf64, timeout0.
    if response.get(24..) != Some(&[3, 1, 5, 0, 0, 0x02, 0x10, 0, 0][..]) {
        return TestResult::Fail("ADDBA response differs");
    }
    // 101 is held until the hole at 100 fills, then both release in order.
    let (Ok((w101, e101)), Ok((w100, e100))) = (downlink_seq(&h, 101, 1), downlink_seq(&h, 100, 0))
    else {
        return TestResult::Fail("fixture downlink failed");
    };
    if h.model(|io| io.packets.inject_rate(&w101, 0x87)).is_err() {
        return TestResult::Fail("fixture injection failed");
    }
    h.pump();
    if !h.received().is_empty() {
        return TestResult::Fail("out-of-order MPDU delivered before the hole");
    }
    if h.model(|io| io.packets.inject_rate(&w100, 0x87)).is_err() {
        return TestResult::Fail("fixture injection failed");
    }
    h.pump();
    if h.received() != vec![e100, e101] {
        return TestResult::Fail("reorder release order differs");
    }
    // 103 waits for 102; a BAR with SSN104 flushes it.
    let Ok((w103, e103)) = downlink_seq(&h, 103, 3) else {
        return TestResult::Fail("fixture downlink failed");
    };
    let _ = h.model(|io| io.packets.inject_rate(&w103, 0x87));
    h.pump();
    if !h.received().is_empty() {
        return TestResult::Fail("MPDU after a hole delivered early");
    }
    let mut bar = vec![0x84, 0, 0, 0];
    bar.extend_from_slice(&OWN);
    bar.extend_from_slice(&AP);
    bar.extend_from_slice(&(0b100u16).to_le_bytes());
    bar.extend_from_slice(&(104u16 << 4).to_le_bytes());
    let _ = h.model(|io| io.packets.inject(&bar));
    h.pump();
    if h.received() != vec![e103] {
        return TestResult::Fail("BAR did not release the held MPDU");
    }
    // DELBA from the originator tears the session down (BA CAM invalidate).
    let delba = ba_action(&[3, 2, 0x00, 0x08, 1, 0]); // TID0, initiator
    let before = h.model(|io| io.control.packets().len());
    let _ = h.model(|io| io.packets.inject(&delba));
    h.pump();
    complete(h.device.apply_edca());
    let cam = h.model(|io| io.control.packets()[before..].to_vec());
    if !cam
        .iter()
        .any(|p| p.len() == 16 && p[8..12] == [0, 0, 0, 0])
        || h.closed()
    {
        return TestResult::Fail("DELBA did not invalidate the BA CAM entry");
    }
    // Without a session data is delivered directly again.
    let Ok((w200, e200)) = downlink_seq(&h, 200, 4) else {
        return TestResult::Fail("fixture downlink failed");
    };
    let _ = h.model(|io| io.packets.inject_rate(&w200, 0x87));
    h.pump();
    if h.received() != vec![e200] {
        return TestResult::Fail("post-DELBA data not delivered");
    }
    drop(h);
    // A non-HT link declines (status 37) without touching the BA CAM.
    let h = Harness::rates_profile(false, true, Some(&RATES));
    if h.join().is_err() {
        return TestResult::Fail("legacy association failed");
    }
    let before = h.model(|io| io.control.packets().len());
    let _ = h.model(|io| io.packets.inject(&addba_request(0, 64, 7)));
    h.pump();
    complete(h.device.apply_edca());
    h.pump();
    let response = h.peer.lock().actions.last().cloned().unwrap_or_default();
    if response.get(27..29) != Some(&[37, 0][..])
        || h.model(|io| io.control.packets().len()) != before
    {
        return TestResult::Fail("non-HT ADDBA not declined");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/block_ack",
    smoke_rtw8852b_recipient_block_ack_reorders_and_tears_down
);

fn cam_with(packets: &[Vec<u8>], address: [u8; 6]) -> Vec<usize> {
    packets
        .iter()
        .enumerate()
        .filter(|(_, p)| p.len() == 68 && p.windows(6).any(|w| w == address))
        .map(|(i, _)| i)
        .collect()
}
fn smoke_rtw8852b_random_scan_address_cam_probe_and_restore() -> TestResult {
    let h = Harness::new(false);
    let request = |random_mac| ScanRequest {
        ssids: vec![SSID.to_vec()],
        frequencies_mhz: vec![2412],
        channels: vec![1],
        active: true,
        random_mac,
        colocated_6ghz: false,
        duration_tu: Some(20),
        duration_mandatory: false,
        extra_ies: Vec::new(),
    };
    let base = narf_wireless::ScanRandomMac {
        addr: [0x02, 0x11, 0x22, 0, 0, 0],
        mask: [0xff, 0xff, 0xff, 0, 0, 0],
    };
    // Failure: a mask that randomizes the group bit (cfg80211 rejects it)
    // is refused before any controller or RF activity.
    let before = h.model(|io| io.control.packets().len());
    let bad = narf_wireless::ScanRandomMac {
        addr: base.addr,
        mask: [0xfe, 0xff, 0xff, 0, 0, 0],
    };
    if complete(h.device.scan(request(Some(bad)))).is_ok()
        || h.model(|io| io.control.packets().len()) != before
        || !h.peer.lock().probes.is_empty()
    {
        return TestResult::Fail("random scan with a group-bit mask accepted");
    }
    // Success: probe from the masked random address, response directed to
    // it is cached, and the address CAM moves to it and back.
    let Ok(seen) = complete(h.device.scan(request(Some(base)))) else {
        return TestResult::Fail("random-address scan failed");
    };
    let probes = h.peer.lock().probes.clone();
    let Some(probe) = probes.last() else {
        return TestResult::Fail("no random-address probe request");
    };
    let mut random = [0u8; 6];
    random.copy_from_slice(&probe[10..16]);
    if random[..3] != base.addr[..3] || random == OWN || random[0] & 1 != 0 {
        return TestResult::Fail("probe source is not the masked random address");
    }
    if seen.len() != 1 || seen[0].bssid != AP {
        return TestResult::Fail("response to the random address not observed");
    }
    let packets = h.model(|io| io.control.packets().to_vec());
    let to_random = cam_with(&packets, random);
    let to_own: Vec<usize> = cam_with(&packets, OWN)
        .into_iter()
        .filter(|i| to_random.first().is_some_and(|r| i > r))
        .collect();
    if to_random.len() != 1 || to_own.len() != 1 {
        return TestResult::Fail("address CAM not moved to the scan address and restored");
    }
    // Teardown/restore: an ordinary scan and association use the own address.
    if complete(h.device.scan(request(None))).is_err()
        || h.peer.lock().probes.last().map(|p| p[10..16].to_vec()) != Some(OWN.to_vec())
    {
        return TestResult::Fail("own-address scan after random scan differs");
    }
    if complete(h.device.associate(h.request())).is_err() || !h.device.link_up() {
        return TestResult::Fail("association after random scan failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/scan",
    smoke_rtw8852b_random_scan_address_cam_probe_and_restore
);
fn smoke_rtw8852b_random_sn_probe_requests() -> TestResult {
    use narf_wireless::scan::ScanFlags;
    let h = Harness::new(false);
    if !h.device.supports_scan_random_sn() {
        return TestResult::Fail("NL80211_EXT_FEATURE_SCAN_RANDOM_SN not advertised");
    }
    let request = |ssids: Vec<Vec<u8>>| ScanRequest {
        ssids,
        frequencies_mhz: vec![2412],
        channels: vec![1],
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: Some(20),
        duration_mandatory: false,
        extra_ies: Vec::new(),
    };
    let random = ScanFlags { random_sn: true };
    let seq = |p: &Vec<u8>| u16::from_le_bytes([p[22], p[23]]);
    // Ordinary flags: the station counter numbers the probe.
    if complete(
        h.device
            .scan_with_flags(request(vec![SSID.to_vec()]), ScanFlags::default()),
    )
    .is_err()
    {
        return TestResult::Fail("flagless scan failed");
    }
    let Some(counted) = h.peer.lock().probes.last().map(seq) else {
        return TestResult::Fail("no counted probe request");
    };
    // Success: each probe carries its own get_random_u16() SN (the fixture
    // entropy is 0x33.., so SN 0x333) and the counter is not advanced.
    let Ok(seen) = complete(
        h.device
            .scan_with_flags(request(vec![SSID.to_vec(), b"other".to_vec()]), random),
    ) else {
        return TestResult::Fail("random-SN scan failed");
    };
    let probes = h.peer.lock().probes.clone();
    if probes.len() != 3
        || probes[1..].iter().any(|p| seq(p) != 0x333 << 4)
        || seen.len() != 1
        || seen[0].bssid != AP
    {
        return TestResult::Fail("random-SN probe requests differ");
    }
    if complete(h.device.scan(request(vec![SSID.to_vec()]))).is_err()
        || h.peer.lock().probes.last().map(seq) != Some(counted.wrapping_add(1 << 4))
    {
        return TestResult::Fail("random-SN scan advanced the station sequence counter");
    }
    // Passive scan: the flag is accepted and nothing is transmitted.
    let mut passive = request(Vec::new());
    passive.active = false;
    let before = h.peer.lock().probes.len();
    if complete(h.device.scan_with_flags(passive, random)).is_err()
        || h.peer.lock().probes.len() != before
    {
        return TestResult::Fail("passive random-SN scan transmitted");
    }
    // Failure: no entropy refuses the scan before any probe or CAM write
    // (the station closes like any failed scan).
    h.env.entropy.store(false, Ordering::Release);
    let packets = h.model(|io| io.control.packets().len());
    if complete(
        h.device
            .scan_with_flags(request(vec![SSID.to_vec()]), random),
    )
    .is_ok()
        || h.peer.lock().probes.len() != before
        || h.model(|io| io.control.packets().len()) != packets
    {
        return TestResult::Fail("random-SN scan without entropy transmitted");
    }
    // Teardown: the failed scan stopped the station; nothing scans again.
    if complete(h.device.scan(request(vec![SSID.to_vec()]))).is_ok()
        || h.peer.lock().probes.len() != before
        || h.device.connected_bssid().is_some()
    {
        return TestResult::Fail("failed random-SN scan left the station open");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/scan",
    smoke_rtw8852b_random_sn_probe_requests
);
fn smoke_rtw8852b_active_scan_probe_requests_and_extra_ies() -> TestResult {
    let h = Harness::new(false);
    let active = |ssids: Vec<Vec<u8>>, extra_ies: Vec<u8>| ScanRequest {
        ssids,
        frequencies_mhz: vec![2412],
        channels: vec![1],
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: Some(20),
        duration_mandatory: false,
        extra_ies,
    };
    let vendor = vec![221, 4, 0x00, 0x11, 0x22, 0x33];
    let Ok(seen) = complete(h.device.scan(active(vec![SSID.to_vec()], vendor.clone()))) else {
        return TestResult::Fail("active scan failed");
    };
    let probes = h.peer.lock().probes.clone();
    let Some(probe) = probes.first() else {
        return TestResult::Fail("no probe request transmitted");
    };
    let mut body = vec![0, SSID.len() as u8];
    body.extend_from_slice(SSID);
    body.extend_from_slice(&[1, 8, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24]);
    body.extend_from_slice(&[50, 4, 0x30, 0x48, 0x60, 0x6c, 3, 1, 1]);
    body.extend_from_slice(&vendor);
    if probes.len() != 1
        || probe[..2] != [0x40, 0]
        || probe[4..10] != [0xff; 6]
        || probe[10..16] != OWN
        || probe[16..22] != [0xff; 6]
        || probe[24..] != body[..]
        || seen.len() != 1
        || seen[0].bssid != AP
    {
        return TestResult::Fail("directed probe request or response handling differs");
    }
    // Wildcard (no SSIDs) and one probe per requested SSID.
    if complete(h.device.scan(active(Vec::new(), Vec::new()))).is_err()
        || h.peer.lock().probes.last().map(|p| p[24..26].to_vec()) != Some(vec![0, 0])
    {
        return TestResult::Fail("wildcard probe request differs");
    }
    let before = h.peer.lock().probes.len();
    if complete(
        h.device
            .scan(active(vec![SSID.to_vec(), b"other".to_vec()], Vec::new())),
    )
    .is_err()
        || h.peer.lock().probes.len() != before + 2
    {
        return TestResult::Fail("per-SSID probe requests differ");
    }
    // Malformed or driver-owned IEs, oversize IEs, too many SSIDs and a
    // random-MAC mask that randomizes the group bit are refused without
    // transmitting (valid random MACs: random_scan_address smoke).
    let before = h.peer.lock().probes.len();
    for request in [
        active(vec![SSID.to_vec()], vec![0, 1, 0x41]),
        active(vec![SSID.to_vec()], vec![221, 9, 0]),
        active(vec![SSID.to_vec()], vec![221; 513]),
        active(vec![SSID.to_vec(); 9], Vec::new()),
    ] {
        if complete(h.device.scan(request)).is_ok() {
            return TestResult::Fail("invalid active scan request accepted");
        }
    }
    let mut random = active(Vec::new(), Vec::new());
    random.random_mac = Some(narf_wireless::scan::ScanRandomMac {
        addr: [2, 0, 0, 0, 0, 9],
        mask: [0xfe, 0xff, 0xff, 0, 0, 0],
    });
    if complete(h.device.scan(random)).is_ok() || h.peer.lock().probes.len() != before {
        return TestResult::Fail("group-bit random-MAC scan accepted or probe sent");
    }
    if h.closed() && h.device.connected_bssid().is_some() {
        return TestResult::Fail("station state disturbed by scans");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_active_scan_probe_requests_and_extra_ies
);

fn smoke_rtw8852b_scan_dwell_follows_requested_duration() -> TestResult {
    let h = Harness::new(false);
    let request = |duration_tu: Option<u16>, duration_mandatory: bool| ScanRequest {
        ssids: vec![SSID.to_vec()],
        frequencies_mhz: vec![2412],
        channels: vec![1],
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu,
        duration_mandatory,
        extra_ies: Vec::new(),
    };
    // NL80211_ATTR_MEASUREMENT_DURATION in TUs -> dwell ceil(TU*1024/1000) ms.
    for (tu, ms) in [(50u16, 52u64), (200, 205), (1000, 1024)] {
        let start = h.env.clock.load(Ordering::Acquire);
        let Ok(seen) = complete(h.device.scan(request(Some(tu), true))) else {
            return TestResult::Fail("dwell-controlled scan failed");
        };
        let elapsed = h.env.clock.load(Ordering::Acquire) - start;
        if seen.len() != 1 || !(ms..=ms + 1).contains(&elapsed) {
            return TestResult::Fail("scan dwell differs from the requested duration");
        }
    }
    // Default dwell without a request is 200ms.
    let start = h.env.clock.load(Ordering::Acquire);
    if complete(h.device.scan(request(None, false))).is_err()
        || !(200..=201).contains(&(h.env.clock.load(Ordering::Acquire) - start))
    {
        return TestResult::Fail("default scan dwell differs");
    }
    // Out-of-range or missing mandatory durations are refused before scanning.
    for (tu, mandatory) in [(Some(0), false), (Some(1001), true), (None, true)] {
        let start = h.env.clock.load(Ordering::Acquire);
        if !matches!(
            complete(h.device.scan(request(tu, mandatory))),
            Err(narf_wireless::WirelessError::InvalidArgs)
        ) || h.env.clock.load(Ordering::Acquire) != start
        {
            return TestResult::Fail("invalid scan duration accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_scan_dwell_follows_requested_duration
);

fn smoke_rtw8852b_removal_retires_station_and_reclaims_behind_stop_proof() -> TestResult {
    for busy in [false, true] {
        let h = Harness::new(false);
        if h.join().is_err() {
            return TestResult::Fail("RTL8852B removal fixture association failed");
        }
        if busy {
            // TX engine never drains within the Linux 100us budget.
            h.model(|io| io.dma.tx_busy_reads = 64);
        }
        let mut retained = h.lifecycle.retained.try_lock().unwrap();
        let owner = retained.as_mut().unwrap();
        let reclaimed = owner.retire();
        let stopped = owner.station_check().is_err()
            && owner.station_phase() == Some(crate::rtw89::station::Phase::Stopped);
        let io = &owner.io;
        let core_reclaimed = io
            .core
            .as_ref()
            .is_some_and(crate::rtw89::packet_core::Core::reclaimed);
        if !stopped || !io.stopped || io.dma.bme {
            return TestResult::Fail("removal left the station, packets or BME open");
        }
        if busy {
            if reclaimed || io.reclaimed.is_some() || core_reclaimed {
                return TestResult::Fail("busy DMA engine still released published storage");
            }
        } else if !reclaimed || io.reclaimed.is_none_or(|count| count < 2) || !core_reclaimed {
            return TestResult::Fail("proven DMA stop did not release published storage");
        }
        drop(retained);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/station",
    smoke_rtw8852b_removal_retires_station_and_reclaims_behind_stop_proof
);

fn ampdu_harness(granted: bool, addba: Option<(u16, u16)>) -> Harness {
    const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    let h = Harness::build_full(false, true, false, Some(&RATES), true, None, granted);
    h.peer.lock().addba = addba;
    h
}
fn uplink(h: &Harness, port: u16) -> Result<Vec<u8>, &'static str> {
    let frame = udp_ipv4(AP, OWN, h.plan.lease_ip, h.plan.server_ip, port, 9, b"agg");
    narf_net::iface::send_on(h.device.name(), &frame).map_err(|_| "uplink refused")?;
    h.pump();
    Ok(frame)
}
fn addba_requests(h: &Harness) -> Vec<Vec<u8>> {
    h.peer
        .lock()
        .actions
        .iter()
        .filter(|a| a.get(24..26) == Some(&[3, 0][..]))
        .cloned()
        .collect()
}
fn smoke_rtw8852b_originator_block_ack_tx_ampdu() -> TestResult {
    // Success: the first TID0 frame goes out unaggregated and starts
    // ieee80211_start_tx_ba_session; the ADDBA response makes the session
    // operational after the RA aggregation limit write.
    let h = ampdu_harness(true, Some((0, 64)));
    if h.join().is_err() {
        return TestResult::Fail("HT association failed");
    }
    if uplink(&h, 1000).is_err() || h.model(|io| io.packets.last.and_then(|s| s.agg)).is_some() {
        return TestResult::Fail("session-starting frame differs");
    }
    h.pump();
    let requests = addba_requests(&h);
    let Some(request) = requests.first() else {
        return TestResult::Fail("no ADDBA request sent");
    };
    // category3 action0 token1, capab A-MSDU|policy|TID0|buf64, timeout0,
    // SSN = next QoS SN (the triggering frame took the previous one).
    // Open QoS data shares the station counter: data X, ADDBA X+1, SSN X+2.
    let ssn = u16::from_le_bytes([request[31], request[32]]) >> 4;
    let data = h.model(|io| {
        io.packets
            .transmitted
            .iter()
            .rev()
            .find(|b| b[0] == 0x88)
            .map(|b| u16::from_le_bytes([b[22], b[23]]) >> 4)
    });
    if request.get(24..31) != Some(&[3, 0, 1, 0x03, 0x10, 0, 0][..])
        || request.len() != 33
        || data.map(|x| (x + 2) & 4095) != Some(ssn)
    {
        return TestResult::Fail("ADDBA request differs");
    }
    complete(h.device.apply_edca());
    h.pump();
    // rtw89_phy_ra_recalc_agg_limit: 0xc610[23:16] = 64 - 1.
    if h.model(|io| io.control.word(0xc610) >> 16 & 0xff) != 63 {
        return TestResult::Fail("RA aggregation limit not programmed");
    }
    if uplink(&h, 1001).is_err()
        || h.model(|io| io.packets.last.and_then(|s| s.agg)) != Some((63, 0))
        || h.peer.lock().tids.last() != Some(&0)
    {
        return TestResult::Fail("operational session frame lacks TXWD AGG_EN");
    }
    // Several aggregated frames in flight on separate slots.
    h.peer.lock().hold_data = true;
    let before = h.model(|io| io.packets.history.len());
    if uplink(&h, 1002).is_err() || uplink(&h, 1003).is_err() {
        return TestResult::Fail("aggregated frame refused while another was in flight");
    }
    let held: Vec<_> = h.model(|io| io.packets.history[before..].to_vec());
    if held.len() != 2 || held.iter().any(|s| s.agg.is_none()) {
        return TestResult::Fail("two aggregated frames not in flight together");
    }
    h.peer.lock().hold_data = false;
    let released = h.model(|io| {
        io.packets.consumed(held[1]);
        held.iter().try_for_each(|s| io.packets.report(*s, 0))
    });
    if released.is_err() {
        return TestResult::Fail("fixture release");
    }
    h.pump();
    if h.closed() || uplink(&h, 1004).is_err() {
        return TestResult::Fail("multi-frame retirement failed");
    }
    // Teardown: DELBA from the recipient (AGG_STOP_PEER_REQUEST) stops the
    // session without a DELBA back and restores the 0x3f limit.
    let delba = ba_action(&[3, 2, 0x00, 0x00, 1, 0]); // TID0, recipient
    let actions = h.peer.lock().actions.len();
    let _ = h.model(|io| io.packets.inject(&delba));
    h.pump();
    complete(h.device.apply_edca());
    h.pump();
    if h.model(|io| io.control.word(0xc610) >> 16 & 0xff) != 0x3f
        || h.peer.lock().actions.len() != actions
    {
        return TestResult::Fail("recipient DELBA did not stop the TX session");
    }
    if uplink(&h, 1005).is_err() || h.model(|io| io.packets.last.and_then(|s| s.agg)).is_some() {
        return TestResult::Fail("aggregation continued after DELBA");
    }
    drop(h);
    // Failure: a declined response leaves the TID unaggregated.
    let h = ampdu_harness(true, Some((37, 0)));
    if h.join().is_err() || uplink(&h, 1100).is_err() {
        return TestResult::Fail("declined fixture join");
    }
    h.pump();
    complete(h.device.apply_edca());
    h.pump();
    if addba_requests(&h).len() != 1
        || uplink(&h, 1101).is_err()
        || h.model(|io| io.packets.last.and_then(|s| s.agg)).is_some()
        || h.closed()
    {
        return TestResult::Fail("declined ADDBA response aggregated");
    }
    drop(h);
    // Failure: no response within ADDBA_RESP_INTERVAL stops the session
    // with DELBA(initiator, QSTA_NOT_USE).
    let h = ampdu_harness(true, None);
    if h.join().is_err() || uplink(&h, 1200).is_err() {
        return TestResult::Fail("timeout fixture join");
    }
    h.pump();
    if addba_requests(&h).len() != 1 {
        return TestResult::Fail("timeout fixture sent no ADDBA request");
    }
    h.env.clock.fetch_add(1000, Ordering::AcqRel);
    h.pump();
    h.pump();
    let last = h.peer.lock().actions.last().cloned().unwrap_or_default();
    if last.get(24..30) != Some(&[3, 2, 0x00, 0x08, 37, 0][..]) || h.closed() {
        return TestResult::Fail("ADDBA response timeout did not send DELBA");
    }
    drop(h);
    // Program not granted: HT data never starts a TX session.
    let h = ampdu_harness(false, Some((0, 64)));
    if h.join().is_err() || uplink(&h, 1300).is_err() || uplink(&h, 1301).is_err() {
        return TestResult::Fail("ungranted fixture join");
    }
    h.pump();
    if !addba_requests(&h).is_empty() || h.model(|io| io.packets.last.and_then(|s| s.agg)).is_some()
    {
        return TestResult::Fail("ADDBA or AGG_EN without the signed program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/block_ack",
    smoke_rtw8852b_originator_block_ack_tx_ampdu
);
