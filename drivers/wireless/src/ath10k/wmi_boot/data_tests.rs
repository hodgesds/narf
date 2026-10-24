//! Firmware-side RAW packet conversation over actual HTT TX/RX DMA storage.
use super::*;
use narf_wifi_fixtures::{udp_ipv4, ApPhase, FakeAp, NetworkPlan};
use narf_wireless::eapol::{KeyFrame, KeyMgmt, Ptk};
const OWN: [u8; 6] = [2, 3, 4, 5, 6, 7];
const AP: [u8; 6] = [2, 8, 9, 10, 11, 12];
const PMK: [u8; 32] = [0x55; 32];
const ANONCE: [u8; 32] = [0xaa; 32];
fn network() -> NetworkPlan {
    NetworkPlan {
        station: OWN,
        bssid: AP,
        server_ip: [10, 77, 0, 1],
        lease_ip: [10, 77, 0, 42],
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
pub(super) struct Fixture {
    ap: FakeAp,
    ptk: Option<Ptk>,
    queue: VecDeque<Vec<u8>>,
    uplink: Vec<Vec<u8>>,
    held: VecDeque<u16>,
    pn: u64,
    replay: narf_wireless::ccmp::ReplayWindow,
    hold_m4: bool,
    hold_data: bool,
    stall_ce: bool,
    status: u8,
    next_decap: u32,
    next_attention: u32,
    next_peer: Option<u16>,
    next_tid: Option<u8>,
}
impl core::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeDataFirmware")
            .field("phase", &self.ap.phase())
            .finish_non_exhaustive()
    }
}
impl Fixture {
    fn new(secured: bool) -> Self {
        let ap = if secured {
            FakeAp::wpa2(network(), b"narf", 1, 7, PMK, ANONCE)
        } else {
            FakeAp::open(network(), b"narf", 1, 7)
        }
        .unwrap();
        Self {
            ap,
            ptk: None,
            queue: VecDeque::new(),
            uplink: Vec::new(),
            held: VecDeque::new(),
            pn: 1,
            replay: narf_wireless::ccmp::ReplayWindow { last_seen_pn: 0 },
            hold_m4: false,
            hold_data: false,
            stall_ce: false,
            status: 0,
            next_decap: 0,
            next_attention: 0,
            next_peer: None,
            next_tid: None,
        }
    }
    fn react(&mut self, frame: &[u8]) -> Result<bool, BmiError> {
        if self.ap.phase() != ApPhase::Authorized {
            let phase = self.ap.phase();
            let replies = self.ap.receive(frame).map_err(|_| BmiError::BadResponse)?;
            if phase == ApPhase::Message2 {
                let m2 = KeyFrame::decode(frame.get(36..).ok_or(BmiError::BadResponse)?, 16)
                    .ok_or(BmiError::BadResponse)?;
                self.ptk = Some(narf_wireless::eapol::wpa_pmk_to_ptk(
                    KeyMgmt::Psk,
                    &PMK,
                    &AP,
                    &OWN,
                    &ANONCE,
                    &m2.key_nonce,
                    16,
                ));
            }
            self.queue.extend(replies.into_iter().filter(|f| f[0] == 8));
            return Ok(phase == ApPhase::Message4);
        }
        if frame.len() < 32
            || frame[..2] != [8, if self.ap.protected() { 0x41 } else { 1 }]
            || frame[4..10] != AP
            || frame[10..16] != OWN
        {
            return Err(BmiError::BadResponse);
        }
        let mut body = frame[24..].to_vec();
        if self.ap.protected() {
            let tk: &[u8; 16] = self
                .ptk
                .as_ref()
                .ok_or(BmiError::BadResponse)?
                .tk
                .as_slice()
                .try_into()
                .unwrap();
            body = narf_wireless::ccmp::unprotect(
                &Ccm,
                &frame[..24],
                tk,
                0,
                false,
                &mut self.replay,
                &mut body,
            )
            .map_err(|_| BmiError::BadResponse)?;
        }
        if body.get(..6) != Some(&[0xaa, 0xaa, 3, 0, 0, 0]) {
            return Err(BmiError::BadResponse);
        }
        let mut ethernet = frame[16..22].to_vec();
        ethernet.extend_from_slice(&frame[10..16]);
        ethernet.extend_from_slice(&body[6..]);
        self.uplink.push(ethernet);
        Ok(false)
    }
    fn downlink(&mut self, ethernet: &[u8]) -> Vec<u8> {
        let mut frame = vec![8, if self.ap.protected() { 0x42 } else { 2 }, 0, 0];
        frame.extend_from_slice(&ethernet[..6]);
        frame.extend_from_slice(&AP);
        frame.extend_from_slice(&ethernet[6..12]);
        frame.extend_from_slice(&[0, 0]);
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
        body.extend_from_slice(&ethernet[12..]);
        if self.ap.protected() {
            let tk: &[u8; 16] = self.ptk.as_ref().unwrap().tk.as_slice().try_into().unwrap();
            body = narf_wireless::ccmp::protect(&Ccm, &frame, tk, self.pn, 0, 0, false, &mut body)
                .unwrap();
            self.pn += 1;
        }
        frame.extend_from_slice(&body);
        frame
    }
}
fn complete(m: &mut RadioModel, id: u16, status: u8) {
    let mut b = vec![7, status, 1, 0];
    b.extend_from_slice(&id.to_le_bytes());
    b.extend_from_slice(&[0, 0]);
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &b)));
}
pub(super) async fn send(m: &mut RadioModel, bytes: &[u8]) -> Result<(), BmiError> {
    let body = bytes.get(8..).ok_or(BmiError::BadResponse)?;
    if bytes[0] != 1
        || bytes[1] != 0
        || bytes[5] != m.inner.sequence
        || bytes[2..4] != (bytes.len() as u16 - 8).to_le_bytes()
        || body.len() < 16
        || body[..4] != [1, 5, 0, 0x0c]
        || body[12..16] != [0xff, 0xff, 0, 0]
    {
        return Err(BmiError::BadResponse);
    }
    m.inner.sequence = m.inner.sequence.wrapping_add(1);
    let length = usize::from(u16::from_le_bytes(body[4..6].try_into().unwrap()));
    let id = u16::from_le_bytes(body[6..8].try_into().unwrap());
    let storage = m.inner.storage.as_ref().ok_or(BmiError::BadResponse)?;
    let (address, payload) = storage.tx.snapshot(id).ok_or(BmiError::BadResponse)?;
    let frame = payload.get(..length).ok_or(BmiError::BadResponse)?;
    let prefetch = length.min(50).div_ceil(4) * 4;
    if body.len() != 16 + prefetch || body[16..] != payload[..prefetch] {
        return Err(BmiError::BadResponse);
    }
    if let Some(fragments) = &storage.fragments {
        let at = usize::from(id) * 64;
        let pointer = u32::from_le_bytes(body[8..12].try_into().unwrap());
        if u64::from(pointer) != fragments.address + at as u64
            || fragments.bytes[at + 16..at + 20] != (address as u32).to_le_bytes()
            || fragments.bytes[at + 22..at + 24] != (length as u16).to_le_bytes()
        {
            return Err(BmiError::BadResponse);
        }
    }
    let fixture = m.data.as_mut().unwrap();
    let m4 = fixture.react(frame)?;
    if m4 && fixture.hold_m4
        || fixture.ap.phase() == ApPhase::Authorized && !m4 && fixture.hold_data
    {
        fixture.held.push_back(id);
    } else {
        let status = fixture.status;
        complete(m, id, status);
    }
    if m.data.as_ref().unwrap().stall_ce {
        core::future::pending::<()>().await;
    }
    Ok(())
}
pub(super) fn poll(m: &mut RadioModel) -> Result<(), BmiError> {
    let Some(fixture) = m.data.as_mut() else {
        return Ok(());
    };
    if !m.inner.inner.rx.is_empty() {
        return Ok(());
    }
    let Some(mut frame) = fixture.queue.pop_front() else {
        return Ok(());
    };
    let peer = fixture.next_peer.take().unwrap_or(1800);
    let tid = fixture.next_tid.take().unwrap_or(16);
    let protected = frame[1] & 0x40 != 0;
    let sequence = u16::from_le_bytes([frame[22], frame[23]]) >> 4;
    frame.extend_from_slice(&[0; 4]);
    let mut descriptor = [0u8; 300];
    u32at(
        &mut descriptor,
        4,
        (1 << 31)
            | 3
            | if protected { 1 << 29 } else { 0 }
            | core::mem::take(&mut fixture.next_attention),
    );
    u32at(
        &mut descriptor,
        12,
        u32::from(peer)
            | (1 << 11)
            | (u32::from(sequence) << 16)
            | if protected { 6 << 28 } else { 7 << 28 },
    );
    u32at(
        &mut descriptor,
        20,
        u32::from(if tid == 16 { 0 } else { tid }) << 28,
    );
    u32at(&mut descriptor, 24, frame.len() as u32);
    u32at(
        &mut descriptor,
        28,
        core::mem::take(&mut fixture.next_decap) << 8,
    );
    u32at(&mut descriptor, 56, 0xc000);
    u32at(&mut descriptor, 104, 0x0400000b); // legacy OFDM6
    let storage = m.inner.storage.as_mut().ok_or(BmiError::BadResponse)?;
    let index = *storage.order.front().ok_or(BmiError::BadResponse)?;
    let buffer = storage.buffers[index]
        .as_mut()
        .ok_or(BmiError::BadResponse)?;
    if frame.len() + 300 > buffer.bytes.len() {
        return Err(BmiError::BadResponse);
    }
    buffer.bytes[..300].copy_from_slice(&descriptor);
    buffer.bytes[300..300 + frame.len()].copy_from_slice(&frame);
    let body = if m.inner.config.dialect == 3 {
        let mut b = vec![0x12, tid];
        b.extend_from_slice(&peer.to_le_bytes());
        b.extend_from_slice(&[0, 0, 1, 0]);
        b.extend_from_slice(&(buffer.address as u32).to_le_bytes());
        b.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b
    } else {
        let mut b = vec![0; 52];
        b[0] = 1;
        b[1] = tid;
        b[2..4].copy_from_slice(&peer.to_le_bytes());
        b[7] = 1;
        b[48] = 1;
        b[49] = 1;
        b
    };
    m.inner
        .inner
        .rx
        .push_back((m.inner.receive_pipe, header(1, &body)));
    Ok(())
}
fn joined(version: u32, dialect: Dialect, secured: bool, raw: bool) -> radio::Radio<RadioModel> {
    let mut r = mlme_tests::prepared_profile(version, dialect, secured, raw);
    let mode = if secured {
        narf_wireless::association::SecurityMode::Wpa2Psk
    } else {
        narf_wireless::association::SecurityMode::Open
    };
    assert!(matches!(
        drive(r.associate_station(&station_tests::policy(), b"narf", mode, &[])),
        Poll::Ready(Ok(_))
    ));
    let m = &mut r.htt.wmi.htc.transport;
    let mut fixture = Fixture::new(secured);
    // Seed the independent AP using the exact native frames transmitted by
    // real JoinPlan/WMI; its RSNA starts only after it verifies those requests.
    for frame in &m.native_management {
        let replies = fixture
            .ap
            .receive(frame)
            .expect("independent AP rejected actual native management");
        fixture
            .queue
            .extend(replies.into_iter().filter(|f| f[0] == 8));
    }
    m.data = Some(fixture);
    r
}
fn packets() -> (Vec<u8>, Vec<u8>) {
    let n = network();
    (
        udp_ipv4(
            AP,
            OWN,
            n.lease_ip,
            n.server_ip,
            49152,
            7,
            b"ath10k-native-uplink",
        ),
        udp_ipv4(
            OWN,
            AP,
            n.server_ip,
            n.lease_ip,
            7,
            49152,
            b"ath10k-native-downlink",
        ),
    )
}
fn start(
    r: &mut radio::Radio<RadioModel>,
    secured: bool,
) -> Poll<Result<radio::StationLink, radio::Error>> {
    drive(r.start_data_with_nonce(
        &station_tests::policy(),
        if secured { Some(&PMK) } else { None },
        || Some([0x73; 32]),
    ))
}
fn composition(version: u32, dialect: Dialect, secured: bool) -> Result<(), &'static str> {
    let mut r = joined(version, dialect, secured, true);
    let (uplink, downlink) = packets();
    if r.station_link().is_some()
        || !matches!(
            drive(r.transmit_ethernet(&station_tests::policy(), &uplink)),
            Poll::Ready(Err(_))
        )
    {
        return Err("native association authorized data before packet owner/RSNA");
    }
    if !matches!(start(&mut r, secured), Poll::Ready(Ok(_))) || r.station_link().is_none() {
        return Err("native RAW/EAPOL/Supplicant path did not authorize");
    }
    if !matches!(
        drive(r.transmit_ethernet(&station_tests::policy(), &uplink)),
        Poll::Ready(Ok(_))
    ) || r
        .htt
        .wmi
        .htc
        .transport
        .inner
        .storage
        .as_ref()
        .unwrap()
        .tx
        .pending()
        != 1
    {
        return Err("native CE receipt retired payload before HTT status");
    }
    if !matches!(
        drive(r.poll_ethernet(&station_tests::policy())),
        Poll::Ready(Ok(_))
    ) || r
        .htt
        .wmi
        .htc
        .transport
        .inner
        .storage
        .as_ref()
        .unwrap()
        .tx
        .pending()
        != 0
        || !r
            .htt
            .wmi
            .htc
            .transport
            .data
            .as_ref()
            .unwrap()
            .uplink
            .contains(&uplink)
    {
        return Err("native HTT/CCMP changed Ethernet uplink or terminal owner");
    }
    let m = &mut r.htt.wmi.htc.transport;
    let fixture = m.data.as_mut().unwrap();
    let frame = fixture.downlink(&downlink);
    fixture.queue.push_back(frame.clone());
    let Poll::Ready(Ok(received)) = drive(r.poll_ethernet(&station_tests::policy())) else {
        return Err("native RX packet polling failed");
    };
    if received != [downlink] {
        return Err("native RAW descriptor/CCMP/RFC1042 did not preserve exact downlink");
    }
    if secured {
        r.htt
            .wmi
            .htc
            .transport
            .data
            .as_mut()
            .unwrap()
            .queue
            .push_back(frame);
        if !matches!(drive(r.poll_ethernet(&station_tests::policy())),Poll::Ready(Ok(f)) if f.is_empty())
        {
            return Err("native replay escaped software per-key replay policy");
        }
    }
    Ok(())
}
fn smoke_ath10k_raw_native_open_wpa2_and_exact_bidirectional_ip() -> TestResult {
    for (version, dialect) in [
        (1, Dialect::Main),
        (2, Dialect::TenOne),
        (3, Dialect::TenTwo),
        (4, Dialect::Tlv),
        (5, Dialect::TenTwoFour),
        (6, Dialect::TenFour),
    ] {
        for secured in [false, true] {
            if let Err(e) = composition(version, dialect, secured) {
                return TestResult::Fail(e);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_raw_native_open_wpa2_and_exact_bidirectional_ip
);
fn smoke_ath10k_data_requires_raw_init_and_exact_descriptor_peer_profile() -> TestResult {
    let mut r = joined(4, Dialect::Tlv, false, false);
    if start(&mut r, false) != Poll::Ready(Err(radio::Error::Unsupported)) {
        return TestResult::Fail("software crypto accepted native-WiFi WMI INIT");
    }
    let mut r = joined(4, Dialect::Tlv, false, true);
    assert!(matches!(start(&mut r, false), Poll::Ready(Ok(_))));
    let (_, downlink) = packets();
    for negative in 0..5 {
        let m = &mut r.htt.wmi.htc.transport;
        let f = m.data.as_mut().unwrap();
        let mut frame = f.downlink(&downlink);
        match negative {
            0 => f.next_peer = Some(1801),
            1 => f.next_tid = Some(3),
            2 => f.next_decap = 1,
            3 => f.next_attention = 1 << 30,
            _ => frame[10] ^= 2,
        };
        f.queue.push_back(frame);
        if !matches!(drive(r.poll_ethernet(&station_tests::policy())),Poll::Ready(Ok(frames)) if frames.is_empty())
        {
            return TestResult::Fail("foreign peer/TID/decap/CRC/TA reached native data owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_data_requires_raw_init_and_exact_descriptor_peer_profile
);
fn smoke_ath10k_m4_receipt_and_cancel_close_data_with_native_dma_retained() -> TestResult {
    let mut r = joined(4, Dialect::Tlv, true, true);
    r.htt.wmi.htc.transport.data.as_mut().unwrap().hold_m4 = true;
    {
        let policy = station_tests::policy();
        let mut future =
            core::pin::pin!(r.start_data_with_nonce(&policy, Some(&PMK), || Some([0x73; 32])));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..32 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return TestResult::Fail("held M4 terminal HTT status authorized port");
            }
        }
    }
    let m = &r.htt.wmi.htc.transport;
    if r.station_link().is_some()
        || m.data.as_ref().unwrap().held.len() != 1
        || m.inner.storage.as_ref().unwrap().tx.pending() != 1
    {
        return TestResult::Fail("cancelled RSNA lost exact held M4 payload/closed admission");
    }
    if !matches!(
        drive(r.poll_ethernet(&station_tests::policy())),
        Poll::Ready(Err(radio::Error::Failed))
    ) {
        return TestResult::Fail("cancelled M4 owner resumed packet service");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/data",
    smoke_ath10k_m4_receipt_and_cancel_close_data_with_native_dma_retained
);
