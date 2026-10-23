use super::super::super::{
    firmware_transport_tests::{initialized_firmware, Fake, Op},
    management_runtime::{Candidate, SecurityMode},
    packet_codec::{Mpdu, MAX_TRANSFER},
    packet_transport::Io,
    receive_runtime::{Permission as RxPermission, Receiver},
    station_runtime::{Error, Phase, Station},
};
use super::native_permission;
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_drivers_usb::device::UsbError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_wireless::eapol::{KeyFrame, KeyMgmt, Ptk};
use zeroize::Zeroizing;
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
const PMK: [u8; 32] = [0x55; 32];
const AN: [u8; 32] = [0x11; 32];
const SN: [u8; 32] = [0x22; 32];
fn rsne() -> Vec<u8> {
    narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body()
}
fn mgmt(subtype: u8, own: [u8; 6]) -> Vec<u8> {
    let mut b = vec![subtype, 0, 0, 0];
    b.extend_from_slice(&own);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&AP);
    b.extend_from_slice(&[0, 0]);
    b
}
fn mpdu(bytes: Vec<u8>) -> Mpdu {
    Mpdu {
        bytes,
        phy: Vec::new(),
        rate: 0,
        ht: false,
        bandwidth40: false,
        tid: 0,
        decrypted: false,
        timestamp: 0,
    }
}
fn beacon(protected: bool) -> Mpdu {
    let mut b = mgmt(0x80, [255; 6]);
    b.extend_from_slice(&[0; 8]);
    b.extend_from_slice(&100u16.to_le_bytes());
    b.extend_from_slice(&(if protected { 0x11u16 } else { 1 }).to_le_bytes());
    b.extend_from_slice(&[0, 4, b'n', b'a', b'r', b'f', 1, 1, 0x82, 3, 1, 1]);
    if protected {
        let r = rsne();
        b.extend_from_slice(&[48, r.len() as u8]);
        b.extend_from_slice(&r);
    }
    mpdu(b)
}
fn native(own: [u8; 6], pdu: &[u8]) -> Vec<u8> {
    let mut b = mgmt(8, own);
    b[1] = 2;
    b.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    b.extend_from_slice(pdu);
    b
}
fn ap_key(ki: u16, rc: u64, ptk: Option<&Ptk>) -> Vec<u8> {
    let mut k = KeyFrame::empty(16);
    k.key_information = ki;
    k.key_length = 16;
    k.replay_counter = rc;
    k.key_nonce = AN;
    if ki & 0x1000 != 0 {
        let r = rsne();
        let mut kd = vec![48, r.len() as u8];
        kd.extend_from_slice(&r);
        kd.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, 2, 0]);
        kd.extend_from_slice(&[0x7c; 16]);
        kd.push(0xdd);
        while kd.len() % 8 != 0 {
            kd.push(0);
        }
        k.key_data =
            narf_crypto::aes_kw::aes_wrap(ptk.unwrap().kek.as_slice().try_into().unwrap(), &kd)
                .unwrap();
    }
    let mut b = k.into_eapol();
    b[0] = 2;
    if ki & 0x100 != 0 {
        let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(&ptk.unwrap().kck, &b);
        b[81..97].copy_from_slice(&mic[..16]);
    }
    b
}
#[derive(Default)]
struct LinkState {
    next: u64,
    rx: Option<u64>,
    tx: Option<(u64, usize, bool)>,
    queue: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    posts: usize,
    hold_m4: bool,
    quiet: bool,
    ptk: Option<Ptk>,
}
#[derive(Clone)]
struct Link {
    own: [u8; 6],
    protected: bool,
    state: Arc<IrqSafeSpinLock<LinkState>>,
}
struct Ccm;
impl narf_wireless::ccmp::AesCcm for Ccm {
    fn encrypt(&self, k: &[u8; 16], n: &[u8; 13], a: &[u8], b: &mut [u8]) -> [u8; 8] {
        narf_crypto::aes_ccm::seal(k, n, a, b).unwrap()
    }
    fn decrypt(
        &self,
        k: &[u8; 16],
        n: &[u8; 13],
        a: &[u8],
        b: &mut [u8],
        t: &[u8; 8],
    ) -> Result<(), narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::open(k, n, a, b, t)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
}
#[async_trait::async_trait]
impl Io for Link {
    type Receipt = u64;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<u64, UsbError> {
        let mut m = self.state.lock();
        if m.rx.is_some() || dci != 3 || length != MAX_TRANSFER {
            return Err(UsbError::Stall);
        }
        m.next += 1;
        let id = m.next;
        m.rx = Some(id);
        m.posts += 1;
        Ok(id)
    }
    fn poll_receive(&self, r: &u64, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        let mut m = self.state.lock();
        if m.rx != Some(*r) {
            return Err(UsbError::Stall);
        }
        let Some(frame) = m.queue.pop_front() else {
            return Ok(None);
        };
        let len = 24 + frame.len();
        if len > out.len() {
            return Err(UsbError::Stall);
        }
        out[..len].fill(0);
        let d0 = frame.len() as u32 | (1 << 27) | (1 << 28) | (1 << 29);
        out[..4].copy_from_slice(&d0.to_le_bytes());
        out[8..12].copy_from_slice(&(1u32 << 16).to_le_bytes());
        out[24..len].copy_from_slice(&frame);
        m.rx = None;
        Ok(Some(len))
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<u64, UsbError> {
        let mut m = self.state.lock();
        if m.tx.is_some() || dci != 4 && dci != 8 || bytes.len() < 56 {
            return Err(UsbError::Stall);
        }
        let f = &bytes[32..];
        let mut m4 = false;
        if !m.quiet {
            match f[0] {
                0xb0 => {
                    let mut b = mgmt(0xb0, self.own);
                    b.extend_from_slice(&[0, 0, 2, 0, 0, 0]);
                    m.queue.push_back(b);
                }
                0 => {
                    let mut b = mgmt(0x10, self.own);
                    b.extend_from_slice(&(if self.protected { 0x11u16 } else { 1 }).to_le_bytes());
                    b.extend_from_slice(&[0, 0, 42, 0xc0]);
                    m.queue.push_back(b);
                    if self.protected {
                        m.queue.push_back(native(self.own, &ap_key(0x8a, 1, None)));
                    }
                }
                8 => {
                    let body = if f[1] & 0x40 != 0 {
                        let mut w = narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 };
                        let mut b = f[24..].to_vec();
                        narf_wireless::ccmp::unprotect(
                            &Ccm,
                            &f[..24],
                            m.ptk.as_ref().unwrap().tk.as_slice().try_into().unwrap(),
                            0,
                            false,
                            &mut w,
                            &mut b,
                        )
                        .unwrap()
                    } else {
                        f[24..].to_vec()
                    };
                    if body.get(..8) == Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]) {
                        let k = KeyFrame::decode(&body[12..], 16).unwrap();
                        if k.key_information & 0x200 == 0 {
                            let p = narf_wireless::eapol::wpa_pmk_to_ptk(
                                KeyMgmt::Psk,
                                &PMK,
                                &AP,
                                &self.own,
                                &AN,
                                &k.key_nonce,
                                16,
                            );
                            let reply = ap_key(0x13ca, k.replay_counter + 1, Some(&p));
                            m.ptk = Some(p);
                            m.queue.push_back(native(self.own, &reply));
                        } else {
                            m4 = true;
                        }
                    } else {
                        let mut reply = mgmt(8, self.own);
                        reply[1] = if self.protected { 0x42 } else { 2 };
                        if self.protected {
                            let mut plain = body;
                            let wire = narf_wireless::ccmp::protect(
                                &Ccm,
                                &reply,
                                m.ptk.as_ref().unwrap().tk.as_slice().try_into().unwrap(),
                                1,
                                0,
                                0,
                                false,
                                &mut plain,
                            );
                            reply.extend_from_slice(&wire);
                        } else {
                            reply.extend_from_slice(&body);
                        }
                        m.queue.push_back(reply);
                    }
                }
                _ => (),
            }
        }
        m.next += 1;
        let id = m.next;
        m.tx = Some((id, bytes.len(), m4));
        m.sent.push(bytes.to_vec());
        Ok(id)
    }
    fn poll_send(&self, r: &u64) -> Result<Option<usize>, UsbError> {
        let mut m = self.state.lock();
        let (id, n, m4) = m.tx.ok_or(UsbError::Stall)?;
        if id != *r {
            return Err(UsbError::Stall);
        }
        if m4 && m.hold_m4 {
            return Ok(None);
        }
        m.tx = None;
        Ok(Some(n))
    }
    async fn stop(&self, r: &u64) -> Result<(), UsbError> {
        let mut m = self.state.lock();
        if m.rx == Some(*r) {
            m.rx = None;
            return Ok(());
        }
        if m.tx.is_some_and(|t| t.0 == *r) {
            m.tx = None;
            return Ok(());
        }
        Err(UsbError::Stall)
    }
}
fn raw(
    protected: bool,
) -> (
    Fake,
    Link,
    Receiver<Fake, Link>,
    super::super::super::power_policy::Permission,
) {
    let (control, firmware) = initialized_firmware();
    let own = firmware.factory().unwrap().mac;
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
    let link = Link {
        own,
        protected,
        state: Arc::new(IrqSafeSpinLock::new(LinkState::default())),
    };
    let permission = native_permission(firmware.factory().unwrap());
    let rx = Receiver::new(
        firmware,
        link.clone(),
        RxPermission::from_domain(&domain).unwrap(),
    )
    .unwrap();
    (control, link, rx, permission)
}
fn prepared(protected: bool) -> (Fake, Link, Station<Fake, Link>) {
    let (control, link, rx, permission) = raw(protected);
    let candidate = Candidate::from_receive(&beacon(protected), 1, link.own).unwrap();
    let station = Station::new(
        rx,
        candidate,
        b"narf",
        if protected {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        },
        protected.then(|| Zeroizing::new(PMK)),
        permission,
    )
    .unwrap();
    (control, link, station)
}
fn smoke_rtl8188eu_real_station_auth_assoc_fw_rsna_and_packet_roundtrip() -> TestResult {
    for protected in [false, true] {
        let (control, link, mut s) = prepared(protected);
        narf_scheduler::block_on(s.begin(0)).unwrap();
        for now in 1..20 {
            narf_scheduler::block_on(s.step(now, SN)).unwrap();
            if s.controlled_port_open() {
                break;
            }
        }
        if !s.controlled_port_open() {
            return TestResult::Fail("native station failed to reach controlled port");
        }
        let m = control.0.lock();
        if m.regs[0x102] & 3 != 2
            || m.regs[0x618..0x61e] != AP
            || m.regs[0x550] & 0x19 != 9
            || m.regs[0x6a0..0x6a2] != [255, 255]
            || m.regs[0x6a4..0x6a6] != [255, 255]
            || m.regs[0xc50] & 0x7f != 0x1e
            || m.regs[0x6a8..0x6aa] != [42, 0xc0]
            || !m
                .ops
                .iter()
                .any(|op| matches!(op,Op::Write(0x1d0,b) if b.as_slice()==[1,0x21,0,0]))
        {
            return TestResult::Fail("real firmware station media/AID contract was skipped");
        }
        drop(m);
        let mut ethernet = AP.to_vec();
        ethernet.extend_from_slice(&link.own);
        ethernet.extend_from_slice(&[8, 0, 0x45, 0, 0, 20]);
        s.send_ethernet(&ethernet, 20).unwrap();
        for now in 21..25 {
            s.poll_network(now, SN).unwrap();
        }
        let mut expected = link.own.to_vec();
        expected.extend_from_slice(&AP);
        expected.extend_from_slice(&ethernet[12..]);
        if s.pop_received() != Some(expected) {
            return TestResult::Fail(
                "native Ethernet/CCMP roundtrip did not use actual owned transport",
            );
        }
        if link.state.lock().sent.len() != if protected { 5 } else { 3 } {
            return TestResult::Fail("station transmitted an unexpected pipeline");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_real_station_auth_assoc_fw_rsna_and_packet_roundtrip
);
fn smoke_rtl8188eu_station_m4_receipt_is_required_and_timeout_retains_it() -> TestResult {
    let (_, link, mut s) = prepared(true);
    link.state.lock().hold_m4 = true;
    narf_scheduler::block_on(s.begin(0)).unwrap();
    for now in 1..10 {
        narf_scheduler::block_on(s.step(now, SN)).unwrap();
    }
    if s.controlled_port_open() || s.phase() != Phase::FourWay || link.state.lock().tx.is_none() {
        return TestResult::Fail("M4 submission was treated as terminal delivery");
    }
    let count = link.state.lock().sent.len();
    if narf_scheduler::block_on(s.step(2000, SN)) != Err(Error::Timeout)
        || s.phase() != Phase::Failed
        || link.state.lock().tx.is_none()
        || link.state.lock().sent.len() != count
    {
        return TestResult::Fail("M4 timeout reopened/reused uncertain TX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_station_m4_receipt_is_required_and_timeout_retains_it
);
fn smoke_rtl8188eu_station_active_media_command_cancellation_is_terminal() -> TestResult {
    let (control, link, mut s) = prepared(false);
    narf_scheduler::block_on(s.begin(0)).unwrap();
    narf_scheduler::block_on(s.step(1, SN)).unwrap();
    control.0.lock().pending_write = Some(0x1d0);
    let mut step = Box::pin(s.step(2, SN));
    let mut cx = Context::from_waker(Waker::noop());
    if step.as_mut().poll(&mut cx) != Poll::Pending || !control.0.lock().active_td {
        return TestResult::Fail("fixture did not submit the actual firmware media command");
    }
    drop(step);
    let n = control.0.lock().ops.len();
    let sent = link.state.lock().sent.len();
    if s.phase() != Phase::Failed
        || s.carrier_up()
        || narf_scheduler::block_on(s.step(3, SN)) != Err(Error::State)
        || control.0.lock().ops.len() != n
        || link.state.lock().sent.len() != sent
        || control.0.lock().unsafe_reuses != 0
    {
        return TestResult::Fail("cancelled media command reused EP0 or authorized station");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_station_active_media_command_cancellation_is_terminal
);

fn smoke_rtl8188eu_station_disconnect_closes_port_media_and_owned_receipts() -> TestResult {
    let (control, link, mut s) = prepared(true);
    narf_scheduler::block_on(s.begin(0)).unwrap();
    for now in 1..20 {
        narf_scheduler::block_on(s.step(now, SN)).unwrap();
        if s.controlled_port_open() {
            break;
        }
    }
    let mut ethernet = AP.to_vec();
    ethernet.extend_from_slice(&link.own);
    ethernet.extend_from_slice(&[8, 0, 0x45]);
    s.send_ethernet(&ethernet, 20).unwrap();
    narf_scheduler::block_on(s.disconnect()).unwrap();
    if s.phase() != Phase::Stopped
        || s.carrier_up()
        || s.pop_received().is_some()
        || s.send_ethernet(&ethernet, 21) != Err(Error::State)
        || narf_scheduler::block_on(s.begin(21)) != Err(Error::State)
        || link.state.lock().rx.is_some()
        || link.state.lock().tx.is_some()
    {
        return TestResult::Fail(
            "successful disconnect retained admission or reused key lifecycle",
        );
    }
    let m = control.0.lock();
    let disabled = m
        .ops
        .iter()
        .position(|op| matches!(op,Op::Write(0x550,b) if b[0]&0x10!=0));
    let disconnected = m
        .ops
        .iter()
        .rposition(|op| matches!(op,Op::Write(0x1d4,b) if b.as_slice()==[1,0x20,0,0]));
    if m.regs[0x100] & 0xc0 != 0
        || m.regs[0x550] & 0x10 == 0
        || disabled.is_none()
        || disconnected.is_none()
        || disabled >= disconnected
    {
        return TestResult::Fail("disconnect omitted ordered TSF/media/MAC closure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_station_disconnect_closes_port_media_and_owned_receipts
);
fn smoke_rtl8188eu_station_disconnect_cancel_retains_claim_and_forbids_reuse() -> TestResult {
    let (control, link, mut s) = prepared(false);
    narf_scheduler::block_on(s.begin(0)).unwrap();
    narf_scheduler::block_on(s.step(1, SN)).unwrap();
    narf_scheduler::block_on(s.step(2, SN)).unwrap();
    control.0.lock().pending_write = Some(0x1d4);
    let mut disconnect = Box::pin(s.disconnect());
    let mut cx = Context::from_waker(Waker::noop());
    if disconnect.as_mut().poll(&mut cx) != Poll::Pending || !control.0.lock().active_td {
        return TestResult::Fail("disconnect fixture did not submit its media transfer");
    }
    drop(disconnect);
    let n = control.0.lock().ops.len();
    let posts = link.state.lock().posts;
    if s.phase() != Phase::Failed
        || s.carrier_up()
        || narf_scheduler::block_on(s.disconnect()) != Err(Error::State)
        || control.0.lock().ops.len() != n
        || control.0.lock().unsafe_reuses != 0
        || link.state.lock().rx.is_none()
        || link.state.lock().posts != posts
    {
        return TestResult::Fail("cancelled disconnect reused EP0 or abandoned RX ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_station_disconnect_cancel_retains_claim_and_forbids_reuse
);

#[derive(Clone, Default)]
struct Env {
    now: Arc<core::sync::atomic::AtomicU64>,
    no_entropy: Arc<core::sync::atomic::AtomicBool>,
    nonce_calls: Arc<core::sync::atomic::AtomicUsize>,
    pause_pending: Arc<core::sync::atomic::AtomicBool>,
}
impl super::super::super::service_runtime::Environment for Env {
    fn now_ms(&self) -> u64 {
        self.now.load(core::sync::atomic::Ordering::Acquire)
    }
    fn fresh_nonce(&self) -> Result<[u8; 32], super::super::super::service_runtime::Error> {
        self.nonce_calls
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        if self.no_entropy.load(core::sync::atomic::Ordering::Acquire) {
            Err(super::super::super::service_runtime::Error::Entropy)
        } else {
            Ok(SN)
        }
    }
    async fn pause(&self) {
        core::future::poll_fn(|_| {
            if self
                .pause_pending
                .load(core::sync::atomic::Ordering::Acquire)
            {
                Poll::Pending
            } else {
                self.now.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
                Poll::Ready(())
            }
        })
        .await
    }
}
fn smoke_rtl8188eu_service_composes_passive_scan_optional_ies_rsna_and_sync_network() -> TestResult
{
    use super::super::super::service_runtime::{Phase as ServicePhase, Service};
    let (control, link, radio, power) = raw(true);
    let env = Env::default();
    let mut service = narf_scheduler::block_on(Service::start(radio, power, env)).unwrap();
    link.state.lock().queue.push_back(beacon(true).bytes);
    service.poll().unwrap();
    if service.candidates().len() != 1 || service.phase() != ServicePhase::Passive {
        return TestResult::Fail("passive native cache unavailable");
    }
    let n = control.0.lock().ops.len();
    if narf_scheduler::block_on(service.connect(
        AP,
        b"narf",
        SecurityMode::Wpa2Psk,
        Some(Zeroizing::new(PMK)),
        &[221, 3, 0],
    ))
    .is_ok()
        || control.0.lock().ops.len() != n
        || service.phase() != ServicePhase::Passive
        || !link.state.lock().sent.is_empty()
    {
        return TestResult::Fail("invalid SME input changed the retained receive/radio owner");
    }
    let vendor = [221, 4, 0x12, 0x34, 0x56, 0x78];
    narf_scheduler::block_on(service.connect(
        AP,
        b"narf",
        SecurityMode::Wpa2Psk,
        Some(Zeroizing::new(PMK)),
        &vendor,
    ))
    .unwrap();
    if service.connected_peer() != Some(AP)
        || !service.transmit_ready()
        || !link.state.lock().sent[1]
            .windows(vendor.len())
            .any(|b| b == vendor)
    {
        return TestResult::Fail("retained service skipped RSNA or optional IE forwarding");
    }
    let mut ethernet = AP.to_vec();
    ethernet.extend_from_slice(&link.own);
    ethernet.extend_from_slice(&[8, 0, 0x45, 0, 0, 20]);
    service.transmit(&ethernet).unwrap();
    let received = service.poll().unwrap();
    let mut expected = link.own.to_vec();
    expected.extend_from_slice(&AP);
    expected.extend_from_slice(&ethernet[12..]);
    if received != vec![expected] || !service.transmit_ready() {
        return TestResult::Fail("sync service did not retire real TX and deliver CCMP RX");
    }
    narf_scheduler::block_on(service.disconnect()).unwrap();
    if service.phase() != ServicePhase::Stopped
        || service.connected_peer().is_some()
        || service.transmit_ready()
        || !service.poll().unwrap().is_empty()
        || narf_scheduler::block_on(service.connect(
            AP,
            b"narf",
            SecurityMode::Wpa2Psk,
            Some(Zeroizing::new(PMK)),
            &[],
        ))
        .is_ok()
    {
        return TestResult::Fail("stopped service reconstructed station/key history");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_service_composes_passive_scan_optional_ies_rsna_and_sync_network
);
fn smoke_rtl8188eu_service_entropy_failure_precedes_radio_tx_and_cancel_is_terminal() -> TestResult
{
    use super::super::super::service_runtime::{
        Error as ServiceError, Phase as ServicePhase, Service,
    };
    let (control, link, radio, power) = raw(true);
    let env = Env::default();
    let mut service = narf_scheduler::block_on(Service::start(radio, power, env.clone())).unwrap();
    link.state.lock().queue.push_back(beacon(true).bytes);
    service.poll().unwrap();
    env.no_entropy
        .store(true, core::sync::atomic::Ordering::Release);
    let n = control.0.lock().ops.len();
    if narf_scheduler::block_on(service.connect(
        AP,
        b"narf",
        SecurityMode::Wpa2Psk,
        Some(Zeroizing::new(PMK)),
        &[],
    )) != Err(ServiceError::Entropy)
        || control.0.lock().ops.len() != n
        || control.0.lock().regs[0x100] & 0x40 != 0
        || !link.state.lock().sent.is_empty()
    {
        return TestResult::Fail("service used missing entropy or opened TX before admission");
    }
    env.no_entropy
        .store(false, core::sync::atomic::Ordering::Release);
    env.pause_pending
        .store(true, core::sync::atomic::Ordering::Release);
    let mut connect = Box::pin(service.connect(
        AP,
        b"narf",
        SecurityMode::Wpa2Psk,
        Some(Zeroizing::new(PMK)),
        &[],
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if connect.as_mut().poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("fixture did not reach actual retained join pause");
    }
    drop(connect);
    let n = control.0.lock().ops.len();
    let sent = link.state.lock().sent.len();
    if service.phase() != ServicePhase::Failed
        || service.connected_peer().is_some()
        || service.poll().is_ok()
        || control.0.lock().ops.len() != n
        || link.state.lock().sent.len() != sent
        || link.state.lock().rx.is_none()
    {
        return TestResult::Fail("cancelled join future resumed or abandoned persistent RX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_service_entropy_failure_precedes_radio_tx_and_cancel_is_terminal
);

fn smoke_rtl8188eu_service_rekey_closes_controlled_port_without_false_disconnect() -> TestResult {
    use super::super::super::service_runtime::Service;
    let (_, link, radio, power) = raw(true);
    let mut service =
        narf_scheduler::block_on(Service::start(radio, power, Env::default())).unwrap();
    link.state.lock().queue.push_back(beacon(true).bytes);
    service.poll().unwrap();
    narf_scheduler::block_on(service.connect(
        AP,
        b"narf",
        SecurityMode::Wpa2Psk,
        Some(Zeroizing::new(PMK)),
        &[],
    ))
    .unwrap();
    link.state.lock().hold_m4 = true;
    link.state
        .lock()
        .queue
        .push_back(native(link.own, &ap_key(0x8a, 3, None)));
    service.poll().unwrap();
    service.poll().unwrap();
    if service.connected_peer() != Some(AP)
        || service.transmit_ready()
        || link.state.lock().tx.is_none()
    {
        return TestResult::Fail(
            "pending retained rekey was exposed as disconnect or open data port",
        );
    }
    link.state.lock().hold_m4 = false;
    service.poll().unwrap();
    if service.connected_peer() != Some(AP) || !service.transmit_ready() {
        return TestResult::Fail("exact rekey M4 delivery failed to preserve station/carrier");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_service_rekey_closes_controlled_port_without_false_disconnect
);
fn smoke_rtl8188eu_interface_uses_controlled_port_rings_and_synchronous_usb_progress() -> TestResult
{
    use super::super::super::{interface::Device, service_runtime::Service};
    use narf_net::{Frame, Interface};
    use narf_wireless::{AssociateRequest, SecurityConfig, WirelessNetIface};
    let (_, link, radio, power) = raw(true);
    let mut service =
        narf_scheduler::block_on(Service::start(radio, power, Env::default())).unwrap();
    link.state.lock().queue.push_back(beacon(true).bytes);
    service.poll().unwrap();
    let device = Device::new("rtl8188eu-test", service);
    let mut producer = device.tx_ring().lock().take().unwrap();
    let mut consumer = device.rx_ring().lock().take().unwrap();
    if device.link_up() || device.connected_bssid().is_some() {
        return TestResult::Fail("unassociated native interface published carrier");
    }
    narf_scheduler::block_on(device.associate(AssociateRequest {
        bssid: AP,
        ssid: b"narf".to_vec(),
        frequency_mhz: 2412,
        channel: 1,
        security: SecurityConfig::Wpa2 { psk: PMK },
        ie: Vec::new(),
    }))
    .unwrap();
    if !device.link_up() || device.connected_bssid() != Some(AP) {
        return TestResult::Fail("actual M4 delivery did not publish interface carrier");
    }
    let mut ethernet = AP.to_vec();
    ethernet.extend_from_slice(&link.own);
    ethernet.extend_from_slice(&[8, 0, 0x45, 0, 0, 20]);
    let allocate = |bytes: &[u8]| {
        let buffer =
            narf_io::alloc_coherent(bytes.len(), narf_lib::id::DomainId::DRIVER_0).unwrap();
        let mut frame = Frame::new(buffer, bytes.len() as u32);
        frame.payload_mut().copy_from_slice(bytes);
        frame
    };
    let mut eapol = ethernet.clone();
    eapol[12..14].copy_from_slice(&[0x88, 0x8e]);
    if producer.try_send(allocate(&eapol)).is_err() {
        return TestResult::Fail("test ring unexpectedly full");
    }
    let mut offload = allocate(&ethernet);
    let mut meta = offload.tx_meta();
    meta.tso_mss = Some(1200);
    offload.set_tx_meta(meta);
    if producer.try_send(offload).is_err() || producer.try_send(allocate(&ethernet)).is_err() {
        return TestResult::Fail("test ring unexpectedly full");
    }
    device.progress();
    let received = device.progress();
    let mut expected = link.own.to_vec();
    expected.extend_from_slice(&AP);
    expected.extend_from_slice(&ethernet[12..]);
    if received != vec![expected.clone()] || link.state.lock().sent.len() != 5 {
        return TestResult::Fail(
            "ring clients bypassed native EAPOL/offload admission or sync USB progress",
        );
    }
    let Ok(Some(frame)) = consumer.try_recv() else {
        return TestResult::Fail("native plaintext did not reach RX Narf-Ring");
    };
    if frame.payload() != expected || !matches!(consumer.try_recv(), Ok(None)) {
        return TestResult::Fail("RX ring delivered altered or extra plaintext");
    }
    narf_scheduler::block_on(device.disassociate()).unwrap();
    if device.link_up()
        || device.connected_bssid().is_some()
        || !device.progress().is_empty()
        || link.state.lock().rx.is_some()
    {
        return TestResult::Fail(
            "interface disconnect failed to close carrier and stop real receipts",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_interface_uses_controlled_port_rings_and_synchronous_usb_progress
);
fn smoke_rtl8188eu_ap_broadcast_teardown_closes_retained_station() -> TestResult {
    let (_, link, mut station) = prepared(false);
    narf_scheduler::block_on(station.begin(0)).unwrap();
    narf_scheduler::block_on(station.step(1, SN)).unwrap();
    narf_scheduler::block_on(station.step(2, SN)).unwrap();
    let mut deauth = mgmt(0xc0, [255; 6]);
    deauth.extend_from_slice(&3u16.to_le_bytes());
    link.state.lock().queue.push_back(deauth);
    if station.poll_network(3, SN)
        != Err(Error::Management(
            super::super::super::management_runtime::Error::PeerLeft(3),
        ))
        || station.phase() != Phase::Failed
        || station.carrier_up()
        || link.state.lock().rx.is_none()
    {
        return TestResult::Fail("matching AP broadcast teardown was ignored or freed active RX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_ap_broadcast_teardown_closes_retained_station
);

fn smoke_rtl8188eu_service_only_draws_entropy_at_new_handshake_consumption() -> TestResult {
    use super::super::super::service_runtime::Service;
    let (_, link, radio, power) = raw(true);
    let env = Env::default();
    let mut service = narf_scheduler::block_on(Service::start(radio, power, env.clone())).unwrap();
    link.state.lock().queue.push_back(beacon(true).bytes);
    service.poll().unwrap();
    narf_scheduler::block_on(service.connect(
        AP,
        b"narf",
        SecurityMode::Wpa2Psk,
        Some(Zeroizing::new(PMK)),
        &[],
    ))
    .unwrap();
    if env.nonce_calls.load(core::sync::atomic::Ordering::Acquire) != 1 {
        return TestResult::Fail("first handshake did not retain pre-TX entropy for M1");
    }
    env.no_entropy
        .store(true, core::sync::atomic::Ordering::Release);
    for _ in 0..10 {
        service.poll().unwrap();
    }
    let mut ethernet = AP.to_vec();
    ethernet.extend_from_slice(&link.own);
    ethernet.extend_from_slice(&[8, 0, 0x45]);
    service.transmit(&ethernet).unwrap();
    service.poll().unwrap();
    if env.nonce_calls.load(core::sync::atomic::Ordering::Acquire) != 1
        || service.connected_peer() != Some(AP)
    {
        return TestResult::Fail(
            "idle/data service consumed entropy or lost carrier on source starvation",
        );
    }
    env.no_entropy
        .store(false, core::sync::atomic::Ordering::Release);
    link.state.lock().hold_m4 = true;
    link.state
        .lock()
        .queue
        .push_back(native(link.own, &ap_key(0x8a, 3, None)));
    service.poll().unwrap();
    service.poll().unwrap();
    if env.nonce_calls.load(core::sync::atomic::Ordering::Acquire) != 2 {
        return TestResult::Fail("new rekey M1 failed to consume exactly one new nonce");
    }
    env.no_entropy
        .store(true, core::sync::atomic::Ordering::Release);
    for _ in 0..10 {
        service.poll().unwrap();
    }
    link.state.lock().hold_m4 = false;
    service.poll().unwrap();
    if env.nonce_calls.load(core::sync::atomic::Ordering::Acquire) != 2 || !service.transmit_ready()
    {
        return TestResult::Fail("pending/rekey M4 wait requested extra entropy");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_service_only_draws_entropy_at_new_handshake_consumption
);
