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
}
impl Env {
    fn new() -> Self {
        Self {
            now: AtomicU64::new(0),
            power: AtomicI8::new(17),
            entropy: AtomicBool::new(true),
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
        }
    }
    fn downlink(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut frame = vec![8, if self.ap.protected() { 0x42 } else { 2 }, 0, 0];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&PEER);
        frame.extend_from_slice(&ethernet[6..12]);
        frame.extend_from_slice(&[0, 0]);
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
            let replies = self
                .ap
                .receive(frame)
                .map_err(|_| "shared AP rejected real native MLME/EAPOL")?;
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
        if frame[0] != 8 || frame[1] & 3 != 1 || (frame[1] & 0x40 != 0) != self.ap.protected() {
            return Err("native AP data protection/direction");
        }
        let mut body = frame[24..].to_vec();
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
                &frame[..24],
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
    let (mut owner, port) = control_owner();
    let env = Env::new();
    owner
        .stage_station_calibration(power::calibration(&power::factory()), &power::domain(17))
        .unwrap();
    complete(owner.start_station_service(&env)).unwrap();
    let peer = Arc::new(IrqSafeSpinLock::new(Peer::new(protected)));
    port.model.lock().peer = Some(peer.clone());
    let beacon = { peer.lock().ap.beacon() };
    port.emit(&beacon).unwrap();
    owner.progress_station(&env).unwrap();
    assert_eq!(owner.station_candidates(env.now_ms()).len(), 1);
    (owner, port, peer, env)
}
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
