use super::management_runtime::{Action, Candidate, Error, Join, Phase, SecurityMode};
use super::packet_codec::{self, Kind, Mpdu};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn frame(subtype: u8, receiver: [u8; 6]) -> Vec<u8> {
    let mut bytes = vec![0; 24];
    bytes[0] = subtype;
    bytes[4..10].copy_from_slice(&receiver);
    bytes[10..16].copy_from_slice(&AP);
    bytes[16..22].copy_from_slice(&AP);
    bytes
}
fn mpdu(bytes: Vec<u8>) -> Mpdu {
    Mpdu {
        native: None,
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
    let mut bytes = frame(0x80, [255; 6]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&100u16.to_le_bytes());
    bytes.extend_from_slice(&(if protected { 0x0431u16 } else { 0x0421 }).to_le_bytes());
    bytes.extend_from_slice(&[
        0, 4, b'n', b'a', b'r', b'f', 1, 4, 0x82, 0x84, 0x8b, 0x96, 3, 1, 1,
    ]);
    if protected {
        let body = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
        bytes.extend_from_slice(&[48, body.len() as u8]);
        bytes.extend_from_slice(&body);
    }
    mpdu(bytes)
}
fn auth(status: u16) -> Mpdu {
    let mut bytes = frame(0xb0, LOCAL);
    bytes.extend_from_slice(&[0, 0, 2, 0]);
    bytes.extend_from_slice(&status.to_le_bytes());
    mpdu(bytes)
}
fn assoc(protected: bool) -> Mpdu {
    let mut bytes = frame(0x10, LOCAL);
    bytes.extend_from_slice(&(if protected { 0x11u16 } else { 1 }).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0xc123u16.to_le_bytes());
    bytes.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
    mpdu(bytes)
}
fn join(protected: bool) -> Join {
    Join::prepare(
        Candidate::from_receive(&beacon(protected), 1, LOCAL).unwrap(),
        LOCAL,
        b"narf",
        if protected {
            SecurityMode::Wpa2Psk
        } else {
            SecurityMode::Open
        },
    )
    .unwrap()
}

fn smoke_rtl8188eu_management_candidate_native_identity_and_profile() -> TestResult {
    let frame = beacon(false);
    let candidate = Candidate::from_receive(&frame, 1, LOCAL).unwrap();
    if candidate.bssid() != AP || candidate.ssid() != b"narf" || candidate.channel() != 1 {
        return TestResult::Fail("candidate identity was not retained");
    }
    let mut variants = Vec::new();
    let mut f = frame.clone();
    f.bytes[16] ^= 2;
    variants.push(f);
    let mut f = frame.clone();
    f.bytes[4..10].copy_from_slice(&LOCAL);
    variants.push(f);
    let mut f = frame.clone();
    f.bytes[1] = 4;
    variants.push(f);
    let mut f = frame.clone();
    f.bytes[22] = 1;
    variants.push(f);
    let mut f = frame.clone();
    f.bytes[44] = 2;
    variants.push(f); // 1Mbps lacks the basic flag.
    let mut f = frame.clone();
    f.decrypted = true;
    variants.push(f);
    let mut f = frame.clone();
    f.ht = true;
    variants.push(f);
    let mut f = frame.clone();
    f.bandwidth40 = true;
    variants.push(f);
    let mut f = frame.clone();
    f.bytes.extend_from_slice(&[3, 1, 1]);
    variants.push(f);
    let mut f = frame.clone();
    f.bytes.extend_from_slice(&[0, 0]);
    variants.push(f);
    let mut f = frame.clone();
    f.bytes.extend_from_slice(&[221, 4, 0]);
    variants.push(f);
    if Candidate::from_receive(&frame, 6, LOCAL).is_ok()
        || variants
            .iter()
            .any(|v| Candidate::from_receive(v, 1, LOCAL).is_ok())
    {
        return TestResult::Fail("invalid native profile/IE was admitted");
    }
    let mut probe = frame;
    probe.bytes[0] = 0x50;
    probe.bytes[4..10].copy_from_slice(&LOCAL);
    if Candidate::from_receive(&probe, 1, LOCAL).is_err() {
        return TestResult::Fail("local probe response was rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_management_candidate_native_identity_and_profile
);

fn smoke_rtl8188eu_management_actual_plan_native_frames_and_association() -> TestResult {
    for protected in [false, true] {
        let mut join = join(protected);
        let Action::Transmit(auth_frame) = join.begin().unwrap() else {
            return TestResult::Fail("missing authentication");
        };
        let packet = packet_codec::transmit(&auth_frame, Kind::Management).unwrap();
        if packet[3] != 0x8c
            || packet[5] != 0x12
            || packet[20] != 0
            || packet[22..24] != [0x1a, 0]
            || packet[32] != 0xb0
            || packet[36..42] != AP
            || packet[42..48] != LOCAL
            || packet[48..54] != AP
            || packet[56..] != [0, 0, 1, 0, 0, 0]
        {
            return TestResult::Fail("native authentication or Realtek rate/queue differs");
        }
        if join.phase() != Phase::AwaitAuthentication || join.begin().is_ok() {
            return TestResult::Fail("authentication was not one-shot");
        }
        let Some(Action::Transmit(association)) = join.receive(&auth(0)).unwrap() else {
            return TestResult::Fail("missing association request");
        };
        if association[0] != 0
            || association[22..24] != [16, 0]
            || association[28..34] != [0, 4, b'n', b'a', b'r', b'f']
            || association[34..40] != [1, 4, 0x82, 0x84, 0x8b, 0x96]
        {
            return TestResult::Fail("association identity/rates/software sequence differs");
        }
        if join.receive(&assoc(protected)).unwrap() != Some(Action::Associated { aid: 0x123 })
            || join.phase() != (Phase::Associated { aid: 0x123 })
        {
            return TestResult::Fail("matching association response did not advance");
        }
        // No result in this module represents a controlled-port transition.
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_management_actual_plan_native_frames_and_association
);

fn smoke_rtl8188eu_management_rejections_and_original_rsna_binding() -> TestResult {
    let mut b = beacon(true);
    let mut original = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp();
    original.rsn_capabilities = 0x80; // AP is PMF-capable, not PMF-required.
    let body = original.encode_body();
    b.bytes.truncate(51);
    b.bytes.extend_from_slice(&[48, body.len() as u8]);
    b.bytes.extend_from_slice(&body);
    b.bytes.extend_from_slice(&[244, 1, 0x20]);
    let candidate = Candidate::from_receive(&b, 1, LOCAL).unwrap();
    if candidate.ap_rsne() != Some(body.as_slice()) || candidate.ap_rsnxe() != Some(&[0x20][..]) {
        return TestResult::Fail("original AP RSNA was replaced");
    }
    if Join::prepare(candidate.clone(), LOCAL, b"narf", SecurityMode::Open).is_ok() {
        return TestResult::Fail("protected AP downgraded to Open");
    }
    let mut p = Join::prepare(candidate, LOCAL, b"narf", SecurityMode::Wpa2Psk).unwrap();
    if p.rsn_body().as_deref() == Some(body.as_slice()) {
        return TestResult::Fail("AP capabilities confused with selected station RSNE");
    }
    p.begin().unwrap();
    let mut other = auth(0);
    other.bytes[10] ^= 2;
    if p.receive(&other).unwrap().is_some() || p.phase() != Phase::AwaitAuthentication {
        return TestResult::Fail("other peer changed authentication");
    }
    if p.receive(&auth(13))
        != Err(Error::Protocol(
            narf_wireless::association::Error::Rejected(13),
        ))
        || p.phase() != Phase::Failed
    {
        return TestResult::Fail("matching rejection was not terminal");
    }
    let mut p = join(false);
    p.begin().unwrap();
    p.receive(&auth(0)).unwrap();
    let mut a = assoc(false);
    a.bytes[22] = 1;
    if p.receive(&a) != Err(Error::Frame) || p.phase() != Phase::Failed {
        return TestResult::Fail("fragment association admitted");
    }
    let mut p = join(false);
    p.begin().unwrap();
    p.receive(&auth(0)).unwrap();
    p.receive(&assoc(false)).unwrap();
    let mut deauth = frame(0xc0, LOCAL);
    deauth.extend_from_slice(&3u16.to_le_bytes());
    if p.receive(&mpdu(deauth)) != Err(Error::PeerLeft(3)) || p.phase() != Phase::Failed {
        return TestResult::Fail("AP teardown did not revoke association");
    }
    // The common response parser accepts the AID first. A subsequent native
    // WMM rejection must retire that intermediate association for direct
    // callers too, independently of Station's outer failure guard.
    const WMM: [u8; 26] = [
        221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94, 0,
        0x62, 0x32, 47, 0,
    ];
    for fault in 0..3 {
        let mut advertised = beacon(false);
        advertised.bytes.extend_from_slice(&WMM);
        let candidate = Candidate::from_receive(&advertised, 1, LOCAL).unwrap();
        let mut p = Join::prepare(candidate, LOCAL, b"narf", SecurityMode::Open).unwrap();
        p.begin().unwrap();
        p.receive(&auth(0)).unwrap();
        let mut response = assoc(false);
        if fault != 0 {
            let mut parameters = WMM;
            if fault == 1 {
                parameters[7] = 2; // Unsupported version.
            } else {
                parameters[10] |= 16; // BE requires admission control.
            }
            response.bytes.extend_from_slice(&parameters);
        }
        if p.receive(&response) != Err(Error::Profile)
            || p.phase() != Phase::Failed
            || p.wmm().is_some()
            || p.receive(&assoc(false)) != Ok(None)
        {
            return TestResult::Fail("WMM rejection retained an intermediate Join association");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_management_rejections_and_original_rsna_binding
);

#[derive(Default)]
struct Model {
    receives: usize,
    sent: Vec<(u8, Vec<u8>)>,
}
#[derive(Clone)]
struct Io(Arc<IrqSafeSpinLock<Model>>);
#[async_trait::async_trait]
impl super::packet_transport::Io for Io {
    type Receipt = usize;
    fn begin_receive(&self, _: u8, _: usize) -> Result<usize, narf_drivers_usb::device::UsbError> {
        self.0.lock().receives += 1;
        Ok(usize::MAX)
    }
    fn poll_receive(
        &self,
        _: &usize,
        _: &mut [u8],
    ) -> Result<Option<usize>, narf_drivers_usb::device::UsbError> {
        Ok(None)
    }
    fn begin_send(
        &self,
        dci: u8,
        bytes: &[u8],
    ) -> Result<usize, narf_drivers_usb::device::UsbError> {
        let mut m = self.0.lock();
        m.sent.push((dci, bytes.to_vec()));
        Ok(m.sent.len() - 1)
    }
    fn poll_send(
        &self,
        receipt: &usize,
    ) -> Result<Option<usize>, narf_drivers_usb::device::UsbError> {
        Ok(Some(self.0.lock().sent[*receipt].1.len()))
    }
    async fn stop(&self, _: &usize) -> Result<(), narf_drivers_usb::device::UsbError> {
        Ok(())
    }
}
fn smoke_rtl8188eu_management_plan_uses_actual_retained_packet_owner() -> TestResult {
    let io = Io(Arc::new(IrqSafeSpinLock::new(Model::default())));
    let mut packet = super::packet_transport::Owner::new(
        io.clone(),
        super::device_init::Endpoints {
            input: 0x81,
            input_packet: 512,
            output_packets: [512; 3],
            output: [2, 3, 4],
            output_count: 3,
        },
        1,
    )
    .unwrap();
    packet.start().unwrap();
    let mut plan = join(true);
    let Action::Transmit(first) = plan.begin().unwrap() else {
        return TestResult::Fail("missing auth");
    };
    packet.submit(Kind::Management, &first).unwrap();
    let Some(Action::Transmit(second)) = plan.receive(&auth(0)).unwrap() else {
        return TestResult::Fail("missing assoc");
    };
    if packet.submit(Kind::Management, &second) != Err(super::packet_transport::Error::Busy) {
        return TestResult::Fail("two frames shared one endpoint receipt");
    }
    packet.poll_transmit().unwrap().unwrap();
    packet.submit(Kind::Management, &second).unwrap();
    packet.poll_transmit().unwrap().unwrap();
    let m = io.0.lock();
    if m.receives != 1
        || m.sent.len() != 2
        || m.sent.iter().any(|(dci, _)| *dci != 4)
        || m.sent[0].1[32..] != first
        || m.sent[1].1[32..] != second
    {
        return TestResult::Fail("native management did not use the retained Realtek endpoint");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_management_plan_uses_actual_retained_packet_owner
);
