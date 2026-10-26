//! A reactive AP receives only bytes read from published native descriptors.
use super::super::super::station::{Environment, Error as StationError, Phase as Logical};
use super::*;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicU64};
use narf_wifi_fixtures::{udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan};
use narf_wireless::association::SecurityMode;
use narf_wireless::eapol::{KeyFrame, KeyMgmt, Ptk};
use zeroize::Zeroizing;
const SSID: &[u8] = b"narf-ee1";
const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
pub(super) struct Env {
    now: AtomicU64,
    power: AtomicI8,
    entropy: AtomicBool,
    policy: Option<Arc<narf_wireless::reg::db::Database>>,
    qualification:
        Option<narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>>,
}
impl Env {
    fn new() -> Self {
        Self {
            now: AtomicU64::new(0),
            power: AtomicI8::new(17),
            entropy: AtomicBool::new(true),
            policy: None,
            qualification: None,
        }
    }
}
impl Environment for Env {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }
    fn fresh_nonce(&self) -> Option<[u8; 32]> {
        self.entropy.load(Ordering::Acquire).then_some([0x33; 32])
    }
    fn domain(&self) -> Result<narf_wireless::reg::RegulatoryDomain, StationError> {
        if let Some(policy) = &self.policy {
            return super::super::super::super::interface::installed_domain(policy.snapshot());
        }
        Ok(power::domain(self.power.load(Ordering::Acquire)))
    }
    async fn pause(&self) {
        let mut yielded = false;
        core::future::poll_fn(|cx| {
            if !yielded {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                self.now.fetch_add(1, Ordering::AcqRel);
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
    ap: FakeAp,
    plan: NetworkPlan,
    server: DhcpServer,
    ptk: Option<Ptk>,
    replay: narf_wireless::ccmp::ReplayWindow,
    pn: u64,
    uplink: Vec<Vec<u8>>,
    hold_m4: bool,
    hold_data: bool,
    wmm: Option<Vec<u8>>,
}
impl Peer {
    fn new(protected: bool) -> Self {
        let plan = NetworkPlan {
            station: power::factory().mac,
            bssid: PEER,
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
        }
    }
    fn downlink(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut frame = vec![
            if self.wmm.is_some() { 0x88 } else { 8 },
            if self.ap.protected() { 0x42 } else { 2 },
            0,
            0,
        ];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&PEER);
        frame.extend_from_slice(&ethernet[6..12]);
        frame.extend_from_slice(&[0, 0]);
        if self.wmm.is_some() {
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
        if frame.len() < 24 || frame[4..10] != PEER || frame[10..16] != self.plan.station {
            return Err("native AP peer identity");
        }
        if self.ap.phase() != ApPhase::Authorized || matches!(frame[0], 0 | 0xb0) {
            let before = self.ap.phase();
            let mut replies = self
                .ap
                .receive(frame)
                .map_err(|_| "shared AP rejected real native MLME/EAPOL")?;
            for reply in &mut replies {
                if reply.first() == Some(&0x10) {
                    if let Some(parameters) = &self.wmm {
                        reply.extend_from_slice(parameters);
                    }
                }
            }
            if before == ApPhase::Message2 {
                let key =
                    KeyFrame::decode(frame.get(36..).ok_or("M2 extent")?, 16).ok_or("M2 key")?;
                self.ptk = Some(narf_wireless::eapol::wpa_pmk_to_ptk(
                    KeyMgmt::Psk,
                    &PMK,
                    &PEER,
                    &self.plan.station,
                    &ANONCE,
                    &key.key_nonce,
                    16,
                ));
            }
            return Ok((replies, before == ApPhase::Message4 && self.hold_m4));
        }
        if frame[0] != if self.wmm.is_some() { 0x88 } else { 8 }
            || frame[1] & 3 != 1
            || (frame[1] & 0x40 != 0) != self.ap.protected()
        {
            return Err("native AP data protection/direction");
        }
        let header = if self.wmm.is_some() {
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
fn complete<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..20000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("EE station future stalled")
}
fn started(
    protected: bool,
) -> (
    Prepared<PacketPort, Block>,
    PacketPort,
    Arc<IrqSafeSpinLock<Peer>>,
    Env,
) {
    started_profile(protected, None)
}
fn started_profile(
    protected: bool,
    parameters: Option<Vec<u8>>,
) -> (
    Prepared<PacketPort, Block>,
    PacketPort,
    Arc<IrqSafeSpinLock<Peer>>,
    Env,
) {
    started_rates(protected, parameters, None)
}
fn started_rates(
    protected: bool,
    parameters: Option<Vec<u8>>,
    rates: Option<&[u8]>,
) -> (
    Prepared<PacketPort, Block>,
    PacketPort,
    Arc<IrqSafeSpinLock<Peer>>,
    Env,
) {
    let (mut owner, port) = control_owner();
    let mut env = Env::new();
    let calibration = if rates.is_some() {
        let cap = narf_capabilities::Cap::bootstrap();
        env.qualification = Some(cap);
        power::calibration_with_cap(&power::factory(), cap)
    } else {
        power::calibration(&power::factory())
    };
    owner
        .stage_station_calibration(calibration, &power::domain(17))
        .unwrap();
    complete(owner.start_station_service(&env)).unwrap();
    let mut peer = Peer::new(protected);
    if let Some(rates) = rates {
        peer.ap = peer.ap.with_legacy_rates(rates).unwrap();
    }
    let peer = Arc::new(IrqSafeSpinLock::new(peer));
    peer.lock().wmm = parameters.clone();
    port.model.lock().peer = Some(peer.clone());
    let mut beacon = { peer.lock().ap.beacon() };
    if let Some(parameters) = parameters {
        beacon.extend_from_slice(&parameters);
    }
    port.emit(&beacon).unwrap();
    owner.progress_station(&env).unwrap();
    assert_eq!(owner.station_candidates(env.now_ms()).len(), 1);
    (owner, port, peer, env)
}
const WMM: [u8; 26] = [
    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x81, 0, 0x62, 0x32, 47, 0, 3, 0xa4, 0, 0, 0x42, 0x43, 94, 0,
    0x27, 0xa4, 0, 0,
];
const LEGACY_RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
fn smoke_rtl8188ee_negotiated_legacy_data_rate_uses_native_descriptor_and_ccmp() -> TestResult {
    for protected in [false, true] {
        let cases = LEGACY_RATES
            .iter()
            .enumerate()
            .map(|(index, &code)| {
                (
                    if index == 0 {
                        vec![code]
                    } else {
                        vec![0x82, code]
                    },
                    index as u32,
                )
            })
            .chain(core::iter::once((LEGACY_RATES.to_vec(), 11)));
        for (response, expected) in cases {
            let (mut owner, port, peer, env) =
                started_rates(protected, Some(WMM.to_vec()), Some(&LEGACY_RATES));
            // The immutable scan offered all12; the actual response may narrow it.
            {
                let mut p = peer.lock();
                let ap = core::mem::replace(&mut p.ap, Peer::new(protected).ap);
                p.ap = ap.with_legacy_rates(&response).unwrap();
            }
            if complete(owner.connect_station(
                PEER,
                SSID,
                if protected {
                    SecurityMode::Wpa2Psk
                } else {
                    SecurityMode::Open
                },
                protected.then(|| Zeroizing::new(PMK)),
                &[],
                &env,
            ))
            .is_err()
            {
                return TestResult::Fail("EE negotiated legacy native association");
            }
            let plan = peer.lock().plan;
            let ethernet = udp_ipv4(
                PEER,
                plan.station,
                plan.lease_ip,
                plan.server_ip,
                44000,
                44001,
                b"EE all12 legacy DATA",
            );
            let slot = port.model.lock().slots[4];
            if owner.send_station_ethernet(&ethernet, &env).is_err()
                || owner.progress_station(&env).is_err()
                || peer.lock().uplink.last() != Some(&ethernet)
            {
                return TestResult::Fail("EE actual richer-rate native data/CCMP");
            }
            let descriptor = port.descriptor(4, slot);
            if word(&descriptor, 20) & 63 != expected
                || word(&descriptor, 16) & ((1 << 8) | (1 << 10)) != ((1 << 8) | (1 << 10))
            {
                return TestResult::Fail("EE response intersection or native forced rate differs");
            }
            let retained = port.live_regions();
            if protected {
                env.qualification.unwrap().revoke();
            } else {
                port.model.lock().live = false;
            }
            if owner.send_station_ethernet(&ethernet, &env).is_ok()
                || owner.station_peer().is_some()
            {
                return TestResult::Fail("EE richer rates survived signed/PCI authority loss");
            }
            drop(owner);
            if retained.iter().any(|r| !r.live.load(Ordering::Acquire)) {
                return TestResult::Fail("EE richer-rate terminal owner freed native mappings");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rates",
    smoke_rtl8188ee_negotiated_legacy_data_rate_uses_native_descriptor_and_ccmp
);
fn smoke_rtl8188ee_wmm_real_dma_edca_and_open_wpa2_qos_data() -> TestResult {
    for protected in [false, true] {
        let (mut owner, port, peer, mut env) = started_profile(protected, Some(WMM.to_vec()));
        let policy = Arc::new(narf_wireless::reg::db::Database::new());
        policy.install(power::domain(17));
        env.policy = Some(policy.clone());
        if complete(owner.connect_station(
            PEER,
            SSID,
            if protected {
                SecurityMode::Wpa2Psk
            } else {
                SecurityMode::Open
            },
            protected.then(|| Zeroizing::new(PMK)),
            &[],
            &env,
        ))
        .is_err()
        {
            return TestResult::Fail("EE WMM response/native association failed");
        }
        if [0x508, 0x50c, 0x504, 0x500].map(|r| port.radio.word(r))
            != [0xa546, 0xa496, 0x005e4332, 0x002f3232]
            || !port
                .model
                .lock()
                .observed
                .iter()
                .any(|f| f.first() == Some(&0) && f.ends_with(&narf_wireless::wmm::INFORMATION))
        {
            return TestResult::Fail(
                "EE actual EDCA fields or driver-owned WMM IE differ from literals",
            );
        }
        let plan = peer.lock().plan;
        let ethernet = udp_ipv4(
            PEER,
            plan.station,
            plan.lease_ip,
            plan.server_ip,
            45000,
            45001,
            b"EE WMM exact QoS",
        );
        // WPA2 M2/M4 also use BE and have already advanced this native ring.
        // Inspect the slot consumed by the next actual DATA publication.
        let slot = port.model.lock().slots[4];
        if owner.send_station_ethernet(&ethernet, &env).is_err() {
            return TestResult::Fail("EE native QoS publication failed");
        }
        if owner.progress_station(&env).is_err() {
            return TestResult::Fail("EE native QoS DMA receipt failed");
        }
        if peer.lock().uplink.last() != Some(&ethernet) {
            return TestResult::Fail("EE actual QoS/TID0 AP bytes or CCMP data changed");
        }
        if u32::from_le_bytes(port.descriptor(4, slot)[16..20].try_into().unwrap()) & 64 == 0 {
            return TestResult::Fail("EE published DATA descriptor omitted QOS bit");
        }
        let reply = udp_ipv4(
            plan.station,
            PEER,
            plan.server_ip,
            plan.lease_ip,
            45001,
            45000,
            b"EE WMM exact reply",
        );
        let frame = match peer.lock().downlink(&reply) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("EE QoS AP fixture"),
        };
        if port.emit(&frame).is_err() || owner.progress_station(&env) != Ok(vec![reply]) {
            return TestResult::Fail("EE QoS RX/CCMP normalization failed");
        }
        // Completed MLME/data payloads have already retired legitimately.
        // Track the exact remaining ring/RX/reserved mappings across failure.
        let retained = port.live_regions();
        if protected {
            policy.clear();
        } else {
            port.model.lock().live = false;
        }
        if owner.send_station_ethernet(&ethernet, &env).is_ok() || owner.station_peer().is_some() {
            return TestResult::Fail("EE QoS survived current policy/PCI authority loss");
        }
        policy.install(power::domain(17));
        if owner.send_station_ethernet(&ethernet, &env).is_ok() || owner.station_peer().is_some() {
            return TestResult::Fail("EE explicit policy reinstall revived a terminal WMM station");
        }
        drop(owner);
        if retained
            .iter()
            .any(|region| !region.live.load(Ordering::Acquire))
        {
            return TestResult::Fail("EE WMM authority failure freed published DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/wmm",
    smoke_rtl8188ee_wmm_real_dma_edca_and_open_wpa2_qos_data
);
fn smoke_rtl8188ee_wmm_malformed_response_and_native_readback_are_terminal() -> TestResult {
    for case in 0..4 {
        let (mut owner, port, peer, env) = started_profile(false, Some(WMM.to_vec()));
        let retained = port.live_regions();
        match case {
            0 => peer.lock().wmm = None,
            1 => peer.lock().wmm.as_mut().unwrap()[7] = 2,
            2 => peer.lock().wmm.as_mut().unwrap()[14] |= 16,
            _ => port.radio.ignore(0x508),
        }
        if complete(owner.connect_station(PEER, SSID, SecurityMode::Open, None, &[], &env)).is_ok()
            || owner.station_peer().is_some()
            || owner.station_phase() != Logical::Failed
            || complete(owner.connect_station(PEER, SSID, SecurityMode::Open, None, &[], &env))
                .is_ok()
        {
            return TestResult::Fail("EE invalid WMM/readback admitted or replayed native station");
        }
        drop(owner);
        if retained
            .iter()
            .any(|region| !region.live.load(Ordering::Acquire))
        {
            return TestResult::Fail("EE partial WMM released published DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/wmm",
    smoke_rtl8188ee_wmm_malformed_response_and_native_readback_are_terminal
);
fn smoke_rtl8188ee_wmm_m4_cancellation_keeps_port_closed_and_exact_owner() -> TestResult {
    let (mut owner, port, peer, env) = started_rates(true, Some(WMM.to_vec()), Some(&LEGACY_RATES));
    peer.lock().hold_m4 = true;
    let mut operation = Box::pin(owner.connect_station(
        PEER,
        SSID,
        SecurityMode::Wpa2Psk,
        Some(Zeroizing::new(PMK)),
        &[],
        &env,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    let mut held = false;
    for _ in 0..1000 {
        if operation.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("EE WMM M4 did not retain pending delivery");
        }
        if port.model.lock().held.is_some() {
            held = true;
            break;
        }
    }
    // Include the actual held M4 payload as well as the posted native rings,
    // RX buffers and reserved beacon, excluding earlier terminal payloads.
    let retained = port.live_regions();
    drop(operation);
    if !held
        || owner.station_peer().is_some()
        || owner.station_transmit_ready()
        || owner.progress_station(&env).is_ok()
    {
        return TestResult::Fail("EE cancelled WMM M4 reopened controlled port");
    }
    drop(owner);
    if retained
        .iter()
        .any(|region| !region.live.load(Ordering::Acquire))
    {
        return TestResult::Fail("EE cancelled WMM discarded real native mappings");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/wmm",
    smoke_rtl8188ee_wmm_m4_cancellation_keeps_port_closed_and_exact_owner
);
fn connected(
    protected: bool,
) -> (
    Prepared<PacketPort, Block>,
    PacketPort,
    Arc<IrqSafeSpinLock<Peer>>,
    Env,
) {
    let (mut owner, port, peer, env) = started(protected);
    let mode = if protected {
        SecurityMode::Wpa2Psk
    } else {
        SecurityMode::Open
    };
    if let Err(error) = complete(owner.connect_station(
        PEER,
        SSID,
        mode,
        protected.then(|| Zeroizing::new(PMK)),
        &[],
        &env,
    )) {
        panic!(
            "native EE association failed: {:?}, device error={:?}",
            error,
            port.model.lock().error
        );
    }
    assert_eq!(owner.station_peer(), Some(PEER));
    (owner, port, peer, env)
}
pub(crate) fn smoke_rtl8188ee_real_station_open_wpa2_native_exact_ip() -> TestResult {
    for protected in [false, true] {
        let (mut owner, port, peer, env) = connected(protected);
        let plan = peer.lock().plan;
        let uplink = udp_ipv4(
            PEER,
            plan.station,
            plan.lease_ip,
            plan.server_ip,
            12345,
            9999,
            b"native EE exact uplink",
        );
        owner.send_station_ethernet(&uplink, &env).unwrap();
        owner.progress_station(&env).unwrap();
        if peer.lock().uplink.last() != Some(&uplink) {
            return TestResult::Fail("native station uplink bytes/MIC/replay differ");
        }
        let downlink = udp_ipv4(
            plan.station,
            PEER,
            plan.server_ip,
            plan.lease_ip,
            9999,
            12345,
            b"native EE exact downlink",
        );
        let wire = { peer.lock().downlink(&downlink).unwrap() };
        port.emit(&wire).unwrap();
        if owner.progress_station(&env).unwrap() != vec![downlink] {
            return TestResult::Fail("native station downlink exact Ethernet/IP mismatch");
        }
        complete(owner.disconnect_station()).unwrap();
        if owner.station_peer().is_some() || port.model.lock().master {
            return TestResult::Fail("native station disconnect retained carrier/BME");
        }
        if owner.station_transmit_ready() {
            return TestResult::Fail("native stopped station reopened transmit");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/station",
    smoke_rtl8188ee_real_station_open_wpa2_native_exact_ip
);

pub(crate) fn smoke_rtl8188ee_real_station_m4_cancel_current_policy_and_entropy_fail_closed(
) -> TestResult {
    let (mut owner, port, peer, env) = started(true);
    peer.lock().hold_m4 = true;
    let mut future = Box::pin(owner.connect_station(
        PEER,
        SSID,
        SecurityMode::Wpa2Psk,
        Some(Zeroizing::new(PMK)),
        &[],
        &env,
    ));
    for _ in 0..200 {
        if port.model.lock().held.is_some() {
            break;
        }
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("held native M4 reported association ready");
        }
    }
    if port.model.lock().held.is_none() {
        return TestResult::Fail("M4 fixture did not observe an actual native DMA publication");
    }
    drop(future);
    if owner.station_phase() != Logical::Failed || owner.station_peer().is_some() {
        return TestResult::Fail("cancelled M4 opened logical/carrier state");
    }
    let drops = port.drops.load(Ordering::SeqCst);
    port.release_held();
    if owner.progress_station(&env).is_ok() {
        return TestResult::Fail("cancelled native owner resumed on a late M4 receipt");
    }
    drop(owner);
    if port.drops.load(Ordering::SeqCst) != drops {
        return TestResult::Fail("cancelled M4 or reserved beacon released retained DMA");
    }
    for entropy in [true, false] {
        let (mut owner, port, _, env) = started(true);
        if entropy {
            env.entropy.store(false, Ordering::Release);
        } else {
            env.power.store(10, Ordering::Release);
        }
        if complete(owner.connect_station(
            PEER,
            SSID,
            SecurityMode::Wpa2Psk,
            Some(Zeroizing::new(PMK)),
            &[],
            &env,
        ))
        .is_ok()
            || owner.station_peer().is_some()
        {
            return TestResult::Fail("stale policy/missing entropy authorized station");
        }
        // A policy denial before any join publication leaves Passive intact;
        // entropy refusal after live MLME is terminal and parks the owner.
        if entropy && port.model.lock().master {
            return TestResult::Fail("entropy failure kept active packet gates");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/station",
    smoke_rtl8188ee_real_station_m4_cancel_current_policy_and_entropy_fail_closed
);

#[path = "device_composition_tests.rs"]
mod device_tests;
