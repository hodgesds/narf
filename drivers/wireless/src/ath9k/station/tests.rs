// A reactive AP consumes only bytes read from the actual published AR9285 DMA.
use super::*;
use crate::ath9k::packet::tests::Model;
use alloc::sync::Arc;
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU64},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wifi_fixtures::{udp_ipv4, ApPhase, DhcpServer, FakeAp, NetworkPlan};
use narf_wireless::eapol::{KeyFrame, KeyMgmt, Ptk};
const OWN: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(in crate::ath9k) const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub(in crate::ath9k) const SSID: &[u8] = b"narf-ar9";
pub(in crate::ath9k) const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
pub(in crate::ath9k) struct Env {
    pub now: AtomicU64,
    pub entropy: AtomicBool,
}
impl Environment for Arc<Env> {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::Acquire)
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
pub(in crate::ath9k) struct Peer {
    pub(in crate::ath9k) ap: FakeAp,
    pub(in crate::ath9k) plan: NetworkPlan,
    pub(in crate::ath9k) server: DhcpServer,
    pub(in crate::ath9k) ptk: Option<Ptk>,
    pub(in crate::ath9k) replay: narf_wireless::ccmp::ReplayWindow,
    pub(in crate::ath9k) pn: u64,
    pub(in crate::ath9k) uplink: Vec<Vec<u8>>,
    pub(in crate::ath9k) hold_m4: bool,
    pub(in crate::ath9k) hold_data: bool,
}
impl Peer {
    pub(in crate::ath9k) fn new(protected: bool) -> Self {
        let plan = NetworkPlan {
            station: OWN,
            bssid: AP,
            server_ip: [10, 9, 1, 1],
            lease_ip: [10, 9, 1, 42],
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
    pub(in crate::ath9k) fn downlink(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut frame = vec![8, if self.ap.protected() { 0x42 } else { 2 }, 0, 0];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&AP);
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
    pub(in crate::ath9k) fn react(
        &mut self,
        frame: &[u8],
    ) -> Result<(Vec<Vec<u8>>, bool), &'static str> {
        if frame.len() < 24 || frame[4..10] != AP || frame[10..16] != self.plan.station {
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
                    &AP,
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

pub(in crate::ath9k) type TestRadio = Radio<Arc<Model>, Arc<Env>>;
pub(in crate::ath9k) struct Fixture {
    pub radio: TestRadio,
    pub model: Arc<Model>,
    pub peer: Arc<IrqSafeSpinLock<Peer>>,
    pub env: Arc<Env>,
    pub plan: NetworkPlan,
}
pub(in crate::ath9k) fn fixture(protected: bool) -> Result<Fixture, &'static str> {
    let model = Model::new();
    let peer = Arc::new(IrqSafeSpinLock::new(Peer::new(protected)));
    let plan = peer.lock().plan;
    let reacting = peer.clone();
    *model.reaction.borrow_mut() = Some(Arc::new(move |bytes| {
        reacting
            .lock()
            .react(bytes)
            .map_err(|_| packet::Error::Packet)
    }));
    let env = Arc::new(Env {
        now: AtomicU64::new(0),
        entropy: AtomicBool::new(true),
    });
    // SAFETY: isolated parked device model. No physical controller or calibration authority is substituted.
    let packet = unsafe { Packet::prepare(model.clone(), OWN) }.map_err(|_| "packet prepare")?;
    let mut radio = Radio::new(packet, OWN, -118, env.clone());
    radio.start().map_err(|_| "radio start")?;
    let beacon = { peer.lock().ap.beacon() };
    model.inject(&beacon, 0).map_err(|_| "beacon")?;
    radio.poll().map_err(|_| "scan poll")?;
    Ok(Fixture {
        radio,
        model,
        peer,
        env,
        plan,
    })
}
pub(in crate::ath9k) fn complete<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..20000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("AR9285 station fixture stalled");
}
fn conversation() -> Result<(), &'static str> {
    for protected in [false, true] {
        let mut f = fixture(protected)?;
        complete(
            f.radio
                .associate(AP, SSID, protected.then(|| Zeroizing::new(PMK)), &[]),
        )
        .map_err(|_| "native association")?;
        if f.radio.peer() != Some(AP)
            || !f.radio.ready()
            || f.peer.lock().ap.phase() != ApPhase::Authorized
        {
            return Err("native station not authorized");
        }
        let outbound = udp_ipv4(
            f.plan.bssid,
            f.plan.station,
            f.plan.lease_ip,
            f.plan.server_ip,
            4001,
            4002,
            b"AR9285 uplink",
        );
        f.radio.send(&outbound).map_err(|_| "native send")?;
        f.radio.poll().map_err(|_| "native delivery")?;
        if f.peer.lock().uplink.last() != Some(&outbound) {
            return Err("exact native uplink bytes");
        }
        let inbound = udp_ipv4(
            f.plan.station,
            f.plan.bssid,
            f.plan.server_ip,
            f.plan.lease_ip,
            4002,
            4001,
            b"AR9285 downlink",
        );
        let wire = f.peer.lock().downlink(&inbound)?;
        f.model.inject(&wire, 0).map_err(|_| "native RX")?;
        if f.radio.poll().map_err(|_| "RX progress")? != vec![inbound] {
            return Err("exact native downlink bytes");
        }
        f.radio.stop().map_err(|_| "terminal stop")?;
        if f.radio.peer().is_some() || f.radio.send(&outbound) != Err(Error::Busy) {
            return Err("closed radio reopened");
        }
    }
    Ok(())
}
fn held_m4() -> Result<(), &'static str> {
    let mut f = fixture(true)?;
    f.peer.lock().hold_m4 = true;
    let closed = f.radio.closed();
    {
        let mut future =
            core::pin::pin!(f.radio.associate(AP, SSID, Some(Zeroizing::new(PMK)), &[]));
        let mut cx = Context::from_waker(Waker::noop());
        let mut saw = false;
        for _ in 0..1000 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("held M4 completed association");
            }
            if f.peer.lock().ap.phase() == ApPhase::Authorized && f.model.tx.get().is_some() {
                saw = true;
                break;
            }
        }
        if !saw {
            return Err("native M4 was never published");
        }
    }
    if !closed.load(Ordering::Acquire) || f.radio.peer().is_some() || f.radio.ready() {
        return Err("cancelled M4 opened controlled port");
    }
    f.model.complete(true).map_err(|_| "late M4 receipt")?;
    if f.radio.poll().is_ok() || f.radio.peer().is_some() || f.model.master.get() {
        return Err("late M4 reauthorized or DMA remained active");
    }
    Ok(())
}
fn smoke_ar9285_native_station_open_wpa2_and_exact_bidirectional_ip() -> TestResult {
    match conversation() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
fn smoke_ar9285_held_native_m4_drop_and_late_receipt_stay_terminal() -> TestResult {
    match held_m4() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/station",
    smoke_ar9285_native_station_open_wpa2_and_exact_bidirectional_ip
);
kernel_test_in!(
    "drivers/wireless/ath9k/station",
    smoke_ar9285_held_native_m4_drop_and_late_receipt_stay_terminal
);
