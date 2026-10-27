// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/tests.rs — WWAN Stage-0/1 smoke tests

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    iosm::{
        INTEL_CP_DEVICE_7360_ID, INTEL_CP_DEVICE_7560_ID, IOSM_PCI_DEVICES, IPC_DOORBELL_CH_OFFSET,
        PCI_VENDOR_INTEL,
    },
    mbim::{
        self, MbimHeader, MbimMessageType, MBIM_COMMAND_MSG, MBIM_HEADER_SIZE, MBIM_OPEN,
        MBIM_OPEN_MSG_LEN,
    },
    qmi::{QmiHeader, QMI_SVC_CTL, QMUX_FLAGS_SENDER_HOST, QMUX_HEADER_SIZE, QMUX_IF_TYPE},
    WwanPortKind,
};

// ─── Smoke 1: MBIM message header encode (type + length + tx-id) ─────────────
//
// MBIM 1.0 §10.3.1: MessageType, MessageLength, TransactionId are all
// little-endian u32.  An MBIM_OPEN header with length=16, tx_id=1 must
// produce exact bytes:
//   [01 00 00 00]  MessageType = 0x0000_0001
//   [10 00 00 00]  MessageLength = 16
//   [01 00 00 00]  TransactionId = 1

fn smoke_mbim_header_encode() -> TestResult {
    let hdr = MbimHeader {
        message_type: MbimMessageType::Open,
        message_length: 16,
        transaction_id: 1,
    };
    let wire = hdr.encode();

    // Check MessageType bytes
    if wire[0..4] != [0x01, 0x00, 0x00, 0x00] {
        return TestResult::Fail("MessageType bytes mismatch");
    }
    // Check MessageLength bytes
    if wire[4..8] != [0x10, 0x00, 0x00, 0x00] {
        return TestResult::Fail("MessageLength bytes mismatch (expected 16 LE)");
    }
    // Check TransactionId bytes
    if wire[8..12] != [0x01, 0x00, 0x00, 0x00] {
        return TestResult::Fail("TransactionId bytes mismatch");
    }
    if wire.len() != MBIM_HEADER_SIZE {
        return TestResult::Fail("encoded length is not 12");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_header_encode);

// ─── Smoke 2: MBIM_OPEN command shape ────────────────────────────────────────
//
// build_open() must return a 16-byte packet whose first 4 bytes are
// MBIM_OPEN (0x0000_0001, LE), bytes 4..8 are 0x10000000 (16 LE), and
// bytes 12..16 carry the MaxControlTransfer value (4096 = 0x1000 LE).

fn smoke_mbim_open_shape() -> TestResult {
    let pkt = mbim::build_open(/*tx_id=*/ 1, /*max_ctrl_xfer=*/ 4096);

    if pkt.len() != MBIM_OPEN_MSG_LEN as usize {
        return TestResult::Fail("MBIM_OPEN packet is not 16 bytes");
    }

    // MessageType = MBIM_OPEN = 0x0000_0001 LE
    let msg_type = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
    if msg_type != MBIM_OPEN {
        return TestResult::Fail("MessageType is not MBIM_OPEN");
    }

    // MessageLength = 16
    let msg_len = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if msg_len != 16 {
        return TestResult::Fail("MessageLength should be 16");
    }

    // MaxControlTransfer = 4096 = 0x00001000 LE
    let max_xfer = u32::from_le_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    if max_xfer != 4096 {
        return TestResult::Fail("MaxControlTransfer mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_open_shape);

// ─── Smoke 3: QMI control message header encode (svc + flags + tx-id + msg-id + tlv-count) ─

fn smoke_qmi_ctl_header_encode() -> TestResult {
    let hdr = QmiHeader {
        if_type: QMUX_IF_TYPE,
        length: (QMUX_HEADER_SIZE - 1) as u16, // 11
        flags: QMUX_FLAGS_SENDER_HOST,
        service_id: QMI_SVC_CTL,
        client_id: 0x00,
        tx_id: 0x0042,
        msg_id: 0x0021, // QMI_CTL_GET_VERSION_INFO
        tlv_length: 0x0000,
    };
    let wire = hdr.encode();

    if wire.len() != QMUX_HEADER_SIZE {
        return TestResult::Fail("encoded length is not 12");
    }
    if wire[0] != QMUX_IF_TYPE {
        return TestResult::Fail("if_type byte mismatch");
    }
    if wire[3] != QMUX_FLAGS_SENDER_HOST {
        return TestResult::Fail("flags byte mismatch");
    }
    if wire[4] != QMI_SVC_CTL {
        return TestResult::Fail("service_id mismatch");
    }
    if wire[5] != 0x00 {
        return TestResult::Fail("client_id mismatch");
    }

    let tx_id = u16::from_le_bytes([wire[6], wire[7]]);
    if tx_id != 0x0042 {
        return TestResult::Fail("tx_id mismatch");
    }

    let msg_id = u16::from_le_bytes([wire[8], wire[9]]);
    if msg_id != 0x0021 {
        return TestResult::Fail("msg_id mismatch");
    }

    let tlv_len = u16::from_le_bytes([wire[10], wire[11]]);
    if tlv_len != 0 {
        return TestResult::Fail("tlv_length should be 0");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_qmi_ctl_header_encode);

// ─── Smoke 4: WwanPortKind enum exhaustive match ──────────────────────────────
//
// Verifies that every variant of WwanPortKind is matchable and maps to an
// expected string tag.  If a new variant is added without updating this test
// the compiler will produce an unreachable-pattern or non-exhaustive error.

fn smoke_port_kind_exhaustive() -> TestResult {
    let kinds = [
        WwanPortKind::AtCmd,
        WwanPortKind::Mbim,
        WwanPortKind::Qmi,
        WwanPortKind::Data,
    ];
    let expected_names = ["AtCmd", "Mbim", "Qmi", "Data"];

    for (kind, expected) in kinds.iter().zip(expected_names.iter()) {
        // Exhaustive match — compiler errors if a variant is missing.
        let name = match kind {
            WwanPortKind::AtCmd => "AtCmd",
            WwanPortKind::Mbim => "Mbim",
            WwanPortKind::Qmi => "Qmi",
            WwanPortKind::Data => "Data",
        };
        if name != *expected {
            return TestResult::Fail("WwanPortKind name mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_port_kind_exhaustive);

// ─── Smoke 5: IOSM PCI device-ID table (Intel 7560 / 7360) ───────────────────
//
// Asserts the static table contains the two known Intel XMM device IDs and
// that the vendor field is PCI_VENDOR_INTEL (0x8086).

fn smoke_iosm_pci_device_ids() -> TestResult {
    if IOSM_PCI_DEVICES.len() < 2 {
        return TestResult::Fail("IOSM_PCI_DEVICES must have at least 2 entries");
    }

    let has_7560 = IOSM_PCI_DEVICES
        .iter()
        .any(|d| d.vendor == PCI_VENDOR_INTEL && d.device == INTEL_CP_DEVICE_7560_ID);
    if !has_7560 {
        return TestResult::Fail("XMM 7560 (0x7560) missing from IOSM_PCI_DEVICES");
    }

    let has_7360 = IOSM_PCI_DEVICES
        .iter()
        .any(|d| d.vendor == PCI_VENDOR_INTEL && d.device == INTEL_CP_DEVICE_7360_ID);
    if !has_7360 {
        return TestResult::Fail("XMM 7360 (0x7360) missing from IOSM_PCI_DEVICES");
    }

    // Sanity: doorbell offset must be 32 (BIT(5)).
    if IPC_DOORBELL_CH_OFFSET != 32 {
        return TestResult::Fail("IPC_DOORBELL_CH_OFFSET should be 32");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_iosm_pci_device_ids);

// ─── Bonus: MBIM header decode round-trip ────────────────────────────────────

fn smoke_mbim_header_roundtrip() -> TestResult {
    let original = MbimHeader {
        message_type: MbimMessageType::CommandDone,
        message_length: 100,
        transaction_id: 0xDEAD_BEEF,
    };
    let wire = original.encode();
    let decoded = match MbimHeader::decode(&wire) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("decode failed"),
    };
    if decoded != original {
        return TestResult::Fail("header round-trip mismatch");
    }
    // Also verify MbimMessageType::from_raw round-trips through MBIM_COMMAND_MSG.
    if MbimMessageType::from_raw(MBIM_COMMAND_MSG).to_raw() != MBIM_COMMAND_MSG {
        return TestResult::Fail("MbimMessageType::CommandMsg raw round-trip failed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_header_roundtrip);

// ─── Bonus: QMI header decode round-trip ─────────────────────────────────────

fn smoke_qmi_header_roundtrip() -> TestResult {
    let original = QmiHeader {
        if_type: QMUX_IF_TYPE,
        length: 11,
        flags: QMUX_FLAGS_SENDER_HOST,
        service_id: 0x01, // WDS
        client_id: 0x05,
        tx_id: 0x1234,
        msg_id: 0x0020,
        tlv_length: 0,
    };
    let wire = original.encode();
    let decoded = match QmiHeader::decode(&wire) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("QMI header decode failed"),
    };
    if decoded != original {
        return TestResult::Fail("QMI header round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_qmi_header_roundtrip);

// ─── MBIM completion fixtures (issue #1032) ──────────────────────────────────
//
// The fake modem below answers the MBIM conversation with its OWN
// byte writers (fw32/fw16/fstr16 pushes), never the production
// builders, so a framing error shared by a builder and its parser
// cannot pass silently. Two fixtures additionally pin fully literal
// byte arrays (CONNECT set, DEVICE_CAPS response) written out field
// by field from MBIM 1.0.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    bearer::{self, BearerTxSink},
    mbim::{
        build_command, build_connect_set, parse_command_head, ConnectSetParams, DeviceCapsInfo,
        IpConfigurationInfo, COMMAND_TYPE_SET, MBIM_STATUS_FAILURE, MBIM_UUID_BASIC_CONNECT,
    },
    session::{MbimModem, MbimTransport},
    usb_mbim::find_mbim_function,
    WwanError, WwanPort,
};

fn fw32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn fw16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn fw64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn frd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn fstr16(v: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        fw16(v, u);
    }
}

/// The fake's scripted IPv4 configuration for one session.
#[derive(Clone, Copy)]
struct FakeIp {
    addr: [u8; 4],
    prefix: u32,
    gateway: [u8; 4], // [0;4] = none
    dns: [[u8; 4]; 2],
    dns_count: usize,
    mtu: u32, // 0 = none
}

struct FakeState {
    sent_control: Vec<Vec<u8>>,
    recv_control: VecDeque<Vec<u8>>,
    sent_data: Vec<Vec<u8>>,
    recv_data: VecDeque<Vec<u8>>,
    radio_sw: u32,
    pkt_state: u32,
    active: [bool; 8],
    session_ip: [Option<FakeIp>; 8],
    refuse_connect_status: Option<u32>,
    refuse_connect_state: Option<u32>,
    fragment_caps: bool,
    indicate_before_caps: bool,
}

/// A scripted MBIM function: answers OPEN/CLOSE, the Basic Connect
/// CIDs this crate issues, and records everything the host sends on
/// both channels so fixtures can prove control/data separation.
#[derive(Clone)]
struct FakeModem {
    st: Arc<IrqSafeSpinLock<FakeState>>,
}

fn fake_done(ty: u32, txn: u32, status: u32) -> Vec<u8> {
    // OPEN_DONE / CLOSE_DONE: header + status (MBIM 1.0 §10.3.1).
    let mut v = Vec::new();
    fw32(&mut v, ty);
    fw32(&mut v, 16);
    fw32(&mut v, txn);
    fw32(&mut v, status);
    v
}

fn fake_command_done(txn: u32, cid: u32, status: u32, info: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    fw32(&mut v, 0x8000_0003); // COMMAND_DONE
    fw32(&mut v, (48 + info.len()) as u32);
    fw32(&mut v, txn);
    fw32(&mut v, 1);
    fw32(&mut v, 0); // fragment header: single fragment
    v.extend_from_slice(&[
        0x33, 0xCC, 0x89, 0xA2, 0xBC, 0xBB, 0x45, 0x18, 0xBB, 0xDB, 0x34, 0xEC, 0x7E, 0xDF, 0xB8,
        0x73,
    ]); // UUID_BASIC_CONNECT, wire order
    fw32(&mut v, cid);
    fw32(&mut v, status);
    fw32(&mut v, info.len() as u32);
    v.extend_from_slice(info);
    v
}

fn fake_connect_info(session: u32, state: u32, ip_type: u32, nw_error: u32) -> Vec<u8> {
    // MBIM_CONNECT_INFO (36 bytes), MBIM 1.0 §10.5.10.
    let mut v = Vec::new();
    fw32(&mut v, session);
    fw32(&mut v, state);
    fw32(&mut v, 0); // voice call state: none
    fw32(&mut v, ip_type);
    v.extend_from_slice(&[0u8; 16]); // context type: default
    fw32(&mut v, nw_error);
    v
}

fn fake_indicate_connect(session: u32, state: u32) -> Vec<u8> {
    // INDICATE_STATUS_MSG for CID_CONNECT: header + fragment header +
    // UUID + CID + length + info — note: NO status field (§10.3.1).
    let info = fake_connect_info(session, state, 1, 0);
    let mut v = Vec::new();
    fw32(&mut v, 0x8000_0007);
    fw32(&mut v, (44 + info.len()) as u32);
    fw32(&mut v, 0); // function-initiated: transaction 0
    fw32(&mut v, 1);
    fw32(&mut v, 0);
    v.extend_from_slice(&[
        0x33, 0xCC, 0x89, 0xA2, 0xBC, 0xBB, 0x45, 0x18, 0xBB, 0xDB, 0x34, 0xEC, 0x7E, 0xDF, 0xB8,
        0x73,
    ]);
    fw32(&mut v, mbim::CID_CONNECT);
    fw32(&mut v, info.len() as u32);
    v.extend_from_slice(&info);
    v
}

fn fake_caps_info() -> Vec<u8> {
    // MBIM_DEVICE_CAPS_INFO (§10.5.1): 64-byte fixed part, then the
    // string data the OL pairs point at (offsets 64 / 94 / 134).
    let mut v = Vec::new();
    fw32(&mut v, 2); // DeviceType: removable
    fw32(&mut v, 1); // CellularClass: GSM
    fw32(&mut v, 1); // VoiceClass: no voice
    fw32(&mut v, 2); // SimClass: removable
    fw32(&mut v, 0x24); // DataClass: UMTS | LTE bits
    fw32(&mut v, 3); // SmsCaps
    fw32(&mut v, 1); // ControlCaps
    fw32(&mut v, 8); // MaxSessions
    fw32(&mut v, 0);
    fw32(&mut v, 0); // CustomDataClass OL: empty
    fw32(&mut v, 64);
    fw32(&mut v, 30); // DeviceId OL
    fw32(&mut v, 94);
    fw32(&mut v, 40); // FirmwareInfo OL
    fw32(&mut v, 134);
    fw32(&mut v, 12); // HardwareInfo OL
    fstr16(&mut v, "359072060009999");
    fstr16(&mut v, "SWI9X30C_02.08.02.00");
    fstr16(&mut v, "MC7455");
    v
}

fn fake_ready_info() -> Vec<u8> {
    // MBIM_SUBSCRIBER_READY_INFO: 28-byte fixed header + ICCID.
    let mut v = Vec::new();
    fw32(&mut v, 1); // ReadyState: initialized
    fw32(&mut v, 0); // SubscriberId OL: empty
    fw32(&mut v, 0);
    fw32(&mut v, 28); // SimIccid OL
    fw32(&mut v, 38);
    fw32(&mut v, 0); // ReadyInfo
    fw32(&mut v, 0); // TelephoneNumbersCount
    fstr16(&mut v, "8901260421234567890");
    v
}

fn fake_ip_info(session: u32, cfg: &FakeIp) -> Vec<u8> {
    // MBIM_IP_CONFIGURATION_INFO (§10.5.12): 68-byte fixed part, then
    // address element (68), gateway (76), DNS array (80 with gateway,
    // 76 without).
    let has_gw = cfg.gateway != [0, 0, 0, 0];
    let mut avail = mbim::IP_AVAIL_ADDRESS;
    if has_gw {
        avail |= mbim::IP_AVAIL_GATEWAY;
    }
    if cfg.dns_count > 0 {
        avail |= mbim::IP_AVAIL_DNS;
    }
    if cfg.mtu > 0 {
        avail |= mbim::IP_AVAIL_MTU;
    }
    let dns_off = if has_gw { 80 } else { 76 };
    let mut v = Vec::new();
    fw32(&mut v, session);
    fw32(&mut v, avail);
    fw32(&mut v, 0); // IPv6 availability: none
    fw32(&mut v, 1);
    fw32(&mut v, 68); // IPv4 address count / offset
    fw32(&mut v, 0);
    fw32(&mut v, 0); // IPv6 address count / offset
    fw32(&mut v, if has_gw { 76 } else { 0 }); // IPv4 gateway offset
    fw32(&mut v, 0); // IPv6 gateway offset
    fw32(&mut v, cfg.dns_count as u32);
    fw32(&mut v, if cfg.dns_count > 0 { dns_off } else { 0 });
    fw32(&mut v, 0);
    fw32(&mut v, 0); // IPv6 DNS count / offset
    fw32(&mut v, cfg.mtu); // IPv4 MTU
    fw32(&mut v, 0); // IPv6 MTU
    fw32(&mut v, 0); // IPv4 metric
    fw32(&mut v, 0); // IPv6 metric
    fw32(&mut v, cfg.prefix);
    v.extend_from_slice(&cfg.addr);
    if has_gw {
        v.extend_from_slice(&cfg.gateway);
    }
    for i in 0..cfg.dns_count {
        v.extend_from_slice(&cfg.dns[i]);
    }
    v
}

impl FakeModem {
    fn new() -> Self {
        let mut session_ip = [None; 8];
        session_ip[0] = Some(FakeIp {
            addr: [10, 0, 0, 2],
            prefix: 24,
            gateway: [10, 0, 0, 1],
            dns: [[8, 8, 8, 8], [0, 0, 0, 0]],
            dns_count: 1,
            mtu: 1500,
        });
        session_ip[1] = Some(FakeIp {
            addr: [10, 1, 0, 2],
            prefix: 24,
            gateway: [10, 1, 0, 1],
            dns: [[0, 0, 0, 0]; 2],
            dns_count: 0,
            mtu: 1400,
        });
        Self {
            st: Arc::new(IrqSafeSpinLock::new(FakeState {
                sent_control: Vec::new(),
                recv_control: VecDeque::new(),
                sent_data: Vec::new(),
                recv_data: VecDeque::new(),
                radio_sw: 0,
                pkt_state: 0,
                active: [false; 8],
                session_ip,
                refuse_connect_status: None,
                refuse_connect_state: None,
                fragment_caps: false,
                indicate_before_caps: false,
            })),
        }
    }

    fn tx_sink(&self) -> Arc<dyn BearerTxSink> {
        struct Sink {
            st: Arc<IrqSafeSpinLock<FakeState>>,
        }
        impl BearerTxSink for Sink {
            fn send_ntb(&self, ntb: &[u8]) -> Result<(), WwanError> {
                self.st.lock().sent_data.push(ntb.to_vec());
                Ok(())
            }
        }
        Arc::new(Sink {
            st: self.st.clone(),
        })
    }

    fn sent_control(&self) -> Vec<Vec<u8>> {
        self.st.lock().sent_control.clone()
    }
    fn sent_data(&self) -> Vec<Vec<u8>> {
        self.st.lock().sent_data.clone()
    }
    fn set_refuse_connect_status(&self, status: u32) {
        self.st.lock().refuse_connect_status = Some(status);
    }
    fn set_refuse_connect_state(&self, nw_error: u32) {
        self.st.lock().refuse_connect_state = Some(nw_error);
    }
    fn set_fragment_caps(&self) {
        self.st.lock().fragment_caps = true;
    }
    fn set_indicate_before_caps(&self) {
        self.st.lock().indicate_before_caps = true;
    }

    fn handle_control(&self, msg: &[u8]) {
        let mut st = self.st.lock();
        st.sent_control.push(msg.to_vec());
        if msg.len() < 12 {
            return;
        }
        let ty = frd32(msg, 0);
        let txn = frd32(msg, 8);
        match ty {
            1 => {
                let r = fake_done(0x8000_0001, txn, 0);
                st.recv_control.push_back(r);
            }
            2 => {
                let r = fake_done(0x8000_0002, txn, 0);
                st.recv_control.push_back(r);
            }
            3 => {
                if msg.len() < 48 {
                    return;
                }
                let cid = frd32(msg, 36);
                let cmd_type = frd32(msg, 40);
                let info_len = frd32(msg, 44) as usize;
                let end = core::cmp::min(msg.len(), 48 + info_len);
                let info = &msg[48..end];
                match cid {
                    mbim::CID_DEVICE_CAPS => {
                        if st.indicate_before_caps {
                            let ind = fake_indicate_connect(7, 2);
                            st.recv_control.push_back(ind);
                        }
                        let caps = fake_caps_info();
                        if st.fragment_caps {
                            // Two fragments: the COMMAND_DONE head +
                            // caps[..80], then header + fragment header
                            // + caps[80..] (§10.3.1 continuation shape).
                            let mut f0 = Vec::new();
                            fw32(&mut f0, 0x8000_0003);
                            fw32(&mut f0, (48 + 80) as u32);
                            fw32(&mut f0, txn);
                            fw32(&mut f0, 2);
                            fw32(&mut f0, 0);
                            f0.extend_from_slice(&[
                                0x33, 0xCC, 0x89, 0xA2, 0xBC, 0xBB, 0x45, 0x18, 0xBB, 0xDB, 0x34,
                                0xEC, 0x7E, 0xDF, 0xB8, 0x73,
                            ]);
                            fw32(&mut f0, cid);
                            fw32(&mut f0, 0);
                            fw32(&mut f0, caps.len() as u32);
                            f0.extend_from_slice(&caps[..80]);
                            let mut f1 = Vec::new();
                            fw32(&mut f1, 0x8000_0003);
                            fw32(&mut f1, (20 + (caps.len() - 80)) as u32);
                            fw32(&mut f1, txn);
                            fw32(&mut f1, 2);
                            fw32(&mut f1, 1);
                            f1.extend_from_slice(&caps[80..]);
                            st.recv_control.push_back(f0);
                            st.recv_control.push_back(f1);
                        } else {
                            let r = fake_command_done(txn, cid, 0, &caps);
                            st.recv_control.push_back(r);
                        }
                    }
                    mbim::CID_SUBSCRIBER_READY_STATUS => {
                        let r = fake_command_done(txn, cid, 0, &fake_ready_info());
                        st.recv_control.push_back(r);
                    }
                    mbim::CID_RADIO_STATE => {
                        if cmd_type == 1 && info.len() >= 4 {
                            st.radio_sw = frd32(info, 0);
                        }
                        let mut ri = Vec::new();
                        fw32(&mut ri, 1); // hardware radio: on
                        fw32(&mut ri, st.radio_sw);
                        let r = fake_command_done(txn, cid, 0, &ri);
                        st.recv_control.push_back(r);
                    }
                    mbim::CID_PACKET_SERVICE => {
                        if cmd_type == 1 && info.len() >= 4 {
                            st.pkt_state = if frd32(info, 0) == mbim::PACKET_SERVICE_ATTACH {
                                mbim::PACKET_SERVICE_ATTACHED
                            } else {
                                mbim::PACKET_SERVICE_DETACHED
                            };
                        }
                        let mut pi = Vec::new();
                        fw32(&mut pi, 0); // nw error
                        fw32(&mut pi, st.pkt_state);
                        fw32(&mut pi, 0x20); // highest data class: LTE
                        fw64(&mut pi, 50_000_000);
                        fw64(&mut pi, 100_000_000);
                        let r = fake_command_done(txn, cid, 0, &pi);
                        st.recv_control.push_back(r);
                    }
                    mbim::CID_CONNECT => {
                        if info.len() < 8 {
                            let r = fake_command_done(txn, cid, MBIM_STATUS_FAILURE, &[]);
                            st.recv_control.push_back(r);
                            return;
                        }
                        let session = frd32(info, 0);
                        let activation = frd32(info, 4);
                        if cmd_type == 1 {
                            if activation == 1 {
                                if let Some(status) = st.refuse_connect_status {
                                    let ci = fake_connect_info(session, 0, 1, 0);
                                    let r = fake_command_done(txn, cid, status, &ci);
                                    st.recv_control.push_back(r);
                                } else if let Some(nw) = st.refuse_connect_state {
                                    let ci = fake_connect_info(session, 0, 1, nw);
                                    let r = fake_command_done(txn, cid, 0, &ci);
                                    st.recv_control.push_back(r);
                                } else {
                                    if (session as usize) < st.active.len() {
                                        st.active[session as usize] = true;
                                    }
                                    let ip_type =
                                        if info.len() >= 44 { frd32(info, 40) } else { 1 };
                                    let ci = fake_connect_info(session, 2, ip_type, 0);
                                    let r = fake_command_done(txn, cid, 0, &ci);
                                    st.recv_control.push_back(r);
                                }
                            } else {
                                if (session as usize) < st.active.len() {
                                    st.active[session as usize] = false;
                                }
                                let ci = fake_connect_info(session, 0, 1, 0);
                                let r = fake_command_done(txn, cid, 0, &ci);
                                st.recv_control.push_back(r);
                            }
                        } else {
                            let state = if st.active.get(session as usize).copied().unwrap_or(false)
                            {
                                2
                            } else {
                                0
                            };
                            let ci = fake_connect_info(session, state, 1, 0);
                            let r = fake_command_done(txn, cid, 0, &ci);
                            st.recv_control.push_back(r);
                        }
                    }
                    mbim::CID_IP_CONFIGURATION_INFO => {
                        let session = if info.len() >= 4 { frd32(info, 0) } else { 0 };
                        let resp = match st.session_ip.get(session as usize).and_then(|o| *o) {
                            Some(cfg) => fake_ip_info(session, &cfg),
                            None => {
                                let mut v = alloc::vec![0u8; 68];
                                v[0..4].copy_from_slice(&session.to_le_bytes());
                                v
                            }
                        };
                        let r = fake_command_done(txn, cid, 0, &resp);
                        st.recv_control.push_back(r);
                    }
                    _ => {
                        let r = fake_command_done(txn, cid, MBIM_STATUS_FAILURE, &[]);
                        st.recv_control.push_back(r);
                    }
                }
            }
            _ => {}
        }
    }
}

impl MbimTransport for FakeModem {
    async fn control_send(&self, msg: &[u8]) -> Result<(), WwanError> {
        self.handle_control(msg);
        Ok(())
    }
    async fn control_recv(&self, buf: &mut [u8]) -> Result<usize, WwanError> {
        let mut st = self.st.lock();
        match st.recv_control.pop_front() {
            Some(m) => {
                let n = m.len().min(buf.len());
                buf[..n].copy_from_slice(&m[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }
    async fn data_send(&self, ntb: &[u8]) -> Result<(), WwanError> {
        self.st.lock().sent_data.push(ntb.to_vec());
        Ok(())
    }
    async fn data_recv(&self, buf: &mut [u8]) -> Result<usize, WwanError> {
        let mut st = self.st.lock();
        match st.recv_data.pop_front() {
            Some(m) => {
                let n = m.len().min(buf.len());
                buf[..n].copy_from_slice(&m[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }
}

/// Build an NTB with the fixture's own writers (NTH16 + one NDP16
/// whose signature byte 3 is `session`), independent of the
/// production builder it exercises on the receive path.
fn fake_ntb(session: u8, payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut v = Vec::new();
    v.extend_from_slice(&[0x4E, 0x43, 0x4D, 0x48]); // "NCMH"
    fw16(&mut v, 12); // header length
    fw16(&mut v, 1); // sequence
    fw16(&mut v, total as u16); // block length
    fw16(&mut v, 12); // NDP index
    v.extend_from_slice(&[0x4E, 0x43, 0x4D, session]); // "NCM" + session
    fw16(&mut v, 16); // NDP length
    fw16(&mut v, 0); // next NDP: none
    fw16(&mut v, 28); // datagram offset
    fw16(&mut v, payload.len() as u16);
    fw16(&mut v, 0);
    fw16(&mut v, 0); // null terminator entry
    v.extend_from_slice(payload);
    v
}

// ─── Fixture: CONNECT set pinned byte-for-byte ───────────────────────────────
//
// The full COMMAND_MSG for a session-0 activation with APN "web",
// written out field by field from MBIM 1.0 §10.3.1 (framing) and
// §10.5.10 (MBIM_SET_CONNECT). Production builders must reproduce it
// exactly.

fn smoke_mbim_connect_set_pinned() -> TestResult {
    let params = ConnectSetParams::activate(0, Some(String::from("web")));
    let msg = build_command(
        7,
        &MBIM_UUID_BASIC_CONNECT,
        mbim::CID_CONNECT,
        COMMAND_TYPE_SET,
        &build_connect_set(&params),
    );
    let expected: &[u8] = &[
        0x03, 0x00, 0x00, 0x00, // MessageType = COMMAND_MSG (3)
        0x72, 0x00, 0x00, 0x00, // MessageLength = 114
        0x07, 0x00, 0x00, 0x00, // TransactionId = 7
        0x01, 0x00, 0x00, 0x00, // Fragment: total = 1
        0x00, 0x00, 0x00, 0x00, // Fragment: current = 0
        0x33, 0xCC, 0x89, 0xA2, 0xBC, 0xBB, 0x45, 0x18, // UUID_BASIC_CONNECT (wire order)
        0xBB, 0xDB, 0x34, 0xEC, 0x7E, 0xDF, 0xB8, 0x73, //
        0x0C, 0x00, 0x00, 0x00, // CID = MBIM_CID_CONNECT (12)
        0x01, 0x00, 0x00, 0x00, // CommandType = SET
        0x42, 0x00, 0x00, 0x00, // InformationBufferLength = 66
        // MBIM_SET_CONNECT fixed part (60 bytes):
        0x00, 0x00, 0x00, 0x00, // SessionId = 0
        0x01, 0x00, 0x00, 0x00, // ActivationCommand = ACTIVATE
        0x3C, 0x00, 0x00, 0x00, // AccessString offset = 60
        0x06, 0x00, 0x00, 0x00, // AccessString size = 6
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // UserName OL: absent
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Password OL: absent
        0x00, 0x00, 0x00, 0x00, // CompressionType = NONE
        0x00, 0x00, 0x00, 0x00, // AuthProtocolType = NONE
        0x01, 0x00, 0x00, 0x00, // IpType = IPv4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ContextType: default (zero GUID)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x77, 0x00, 0x65, 0x00, 0x62, 0x00, // "web" UTF-16LE
    ];
    if msg.len() != 114 {
        return TestResult::Fail("CONNECT set is not the spec-shaped 114 bytes");
    }
    if msg.as_slice() != expected {
        return TestResult::Fail("CONNECT set bytes differ from the spec-shaped frame");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_connect_set_pinned);

// ─── Fixture: DEVICE_CAPS response pinned byte-for-byte ──────────────────────
//
// A complete COMMAND_DONE for MBIM_CID_DEVICE_CAPS written out byte
// by byte from MBIM 1.0 §10.5.1 — NOT produced by any builder in
// this crate or in the fixture fake — parsed by production code.

fn smoke_mbim_caps_response_pinned() -> TestResult {
    let msg: &[u8] = &[
        0x03, 0x00, 0x00, 0x80, // MessageType = COMMAND_DONE
        0xC2, 0x00, 0x00, 0x00, // MessageLength = 194
        0x02, 0x00, 0x00, 0x00, // TransactionId = 2
        0x01, 0x00, 0x00, 0x00, // Fragment: total = 1
        0x00, 0x00, 0x00, 0x00, // Fragment: current = 0
        0x33, 0xCC, 0x89, 0xA2, 0xBC, 0xBB, 0x45, 0x18, // UUID_BASIC_CONNECT
        0xBB, 0xDB, 0x34, 0xEC, 0x7E, 0xDF, 0xB8, 0x73, //
        0x01, 0x00, 0x00, 0x00, // CID = MBIM_CID_DEVICE_CAPS (1)
        0x00, 0x00, 0x00, 0x00, // Status = SUCCESS
        0x92, 0x00, 0x00, 0x00, // InformationBufferLength = 146
        // MBIM_DEVICE_CAPS_INFO fixed part (64 bytes):
        0x02, 0x00, 0x00, 0x00, // DeviceType = removable
        0x01, 0x00, 0x00, 0x00, // CellularClass = GSM
        0x01, 0x00, 0x00, 0x00, // VoiceClass = no voice
        0x02, 0x00, 0x00, 0x00, // SimClass = removable
        0x24, 0x00, 0x00, 0x00, // DataClass = UMTS | LTE
        0x03, 0x00, 0x00, 0x00, // SmsCaps
        0x01, 0x00, 0x00, 0x00, // ControlCaps
        0x08, 0x00, 0x00, 0x00, // MaxSessions = 8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // CustomDataClass OL: empty
        0x40, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, // DeviceId OL: offset 64, size 30
        0x5E, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, // FirmwareInfo OL: offset 94, size 40
        0x86, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00,
        0x00, // HardwareInfo OL: offset 134, size 12
        // "359072060009999" UTF-16LE (30 bytes)
        0x33, 0x00, 0x35, 0x00, 0x39, 0x00, 0x30, 0x00, 0x37, 0x00, 0x32, 0x00, 0x30, 0x00, 0x36,
        0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x39, 0x00, 0x39, 0x00, 0x39, 0x00, 0x39, 0x00,
        // "SWI9X30C_02.08.02.00" UTF-16LE (40 bytes)
        0x53, 0x00, 0x57, 0x00, 0x49, 0x00, 0x39, 0x00, 0x58, 0x00, 0x33, 0x00, 0x30, 0x00, 0x43,
        0x00, 0x5F, 0x00, 0x30, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x38, 0x00, 0x2E, 0x00,
        0x30, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x30, 0x00,
        // "MC7455" UTF-16LE (12 bytes)
        0x4D, 0x00, 0x43, 0x00, 0x37, 0x00, 0x34, 0x00, 0x35, 0x00, 0x35, 0x00,
    ];
    let (hdr, frag, head) = match parse_command_head(msg) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("literal CAPS response head did not parse"),
    };
    if hdr.message_length != 194 || frag.total_fragments != 1 {
        return TestResult::Fail("literal CAPS response framing wrong");
    }
    if head.cid != mbim::CID_DEVICE_CAPS || head.status != Some(0) {
        return TestResult::Fail("literal CAPS response head fields wrong");
    }
    let caps = match DeviceCapsInfo::parse(&msg[head.info_offset..]) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("literal CAPS info did not parse"),
    };
    if caps.device_type != 2 || caps.cellular_class != 1 || caps.data_class != 0x24 {
        return TestResult::Fail("literal CAPS scalar fields wrong");
    }
    if caps.max_sessions != 8 {
        return TestResult::Fail("literal CAPS max_sessions is not 8");
    }
    if caps.device_id != "359072060009999"
        || caps.firmware_info != "SWI9X30C_02.08.02.00"
        || caps.hardware_info != "MC7455"
    {
        return TestResult::Fail("literal CAPS strings wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_caps_response_pinned);

// ─── Fixture: IP_CONFIGURATION_INFO literal parse ────────────────────────────

fn smoke_mbim_ip_config_pinned() -> TestResult {
    // MBIM_IP_CONFIGURATION_INFO (§10.5.12) for session 0:
    // 10.0.0.2/24, gateway 10.0.0.1, DNS 8.8.8.8 + 1.1.1.1, MTU 1500.
    let mut info = Vec::new();
    fw32(&mut info, 0); // SessionId
    fw32(&mut info, 0x0F); // IPv4ConfigurationAvailable: addr|gw|dns|mtu
    fw32(&mut info, 0); // IPv6ConfigurationAvailable
    fw32(&mut info, 1);
    fw32(&mut info, 68); // IPv4 address count / offset
    fw32(&mut info, 0);
    fw32(&mut info, 0); // IPv6 address count / offset
    fw32(&mut info, 76); // IPv4 gateway offset
    fw32(&mut info, 0); // IPv6 gateway offset
    fw32(&mut info, 2);
    fw32(&mut info, 80); // IPv4 DNS count / offset
    fw32(&mut info, 0);
    fw32(&mut info, 0); // IPv6 DNS count / offset
    fw32(&mut info, 1500); // IPv4 MTU
    fw32(&mut info, 0); // IPv6 MTU
    fw32(&mut info, 0); // IPv4 metric
    fw32(&mut info, 0); // IPv6 metric
    fw32(&mut info, 24); // address element: prefix length
    info.extend_from_slice(&[10, 0, 0, 2]);
    info.extend_from_slice(&[10, 0, 0, 1]); // gateway at 76
    info.extend_from_slice(&[8, 8, 8, 8]); // DNS at 80
    info.extend_from_slice(&[1, 1, 1, 1]);
    let parsed = match IpConfigurationInfo::parse(&info) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("literal IP config did not parse"),
    };
    if parsed.session_id != 0 {
        return TestResult::Fail("literal IP config session wrong");
    }
    let v4 = match &parsed.ipv4 {
        Some(v) => v,
        None => return TestResult::Fail("literal IP config lost its IPv4 block"),
    };
    if v4.address != [10, 0, 0, 2] || v4.prefix_length != 24 {
        return TestResult::Fail("literal IP config address/prefix wrong");
    }
    if v4.gateway != Some([10, 0, 0, 1]) {
        return TestResult::Fail("literal IP config gateway wrong");
    }
    if v4.dns_servers != alloc::vec![[8, 8, 8, 8], [1, 1, 1, 1]] {
        return TestResult::Fail("literal IP config DNS wrong");
    }
    if v4.mtu != Some(1500) {
        return TestResult::Fail("literal IP config MTU wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_ip_config_pinned);

// ─── Fixture: NTB session signing pinned ─────────────────────────────────────

fn smoke_mbim_ntb_session_signing() -> TestResult {
    let payload: &[u8] = &[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2, 8, 8,
        8, 8,
    ];
    let ntb = bearer::build_mbim_ntb(3, 1, payload);
    // NTH16 + NDP16 per NCM 1.0 §3.2 with the MBIM session-signed
    // NDP signature (Linux cdc_mbim): "NCM" + SessionId in byte 3.
    let expected: &[u8] = &[
        0x4E, 0x43, 0x4D, 0x48, // NTH signature "NCMH"
        0x0C, 0x00, // header length 12
        0x03, 0x00, // sequence 3
        0x30, 0x00, // block length 48
        0x0C, 0x00, // NDP index 12
        0x4E, 0x43, 0x4D, 0x01, // NDP signature: session 1
        0x10, 0x00, // NDP length 16
        0x00, 0x00, // next NDP: none
        0x1C, 0x00, // datagram offset 28
        0x14, 0x00, // datagram length 20
        0x00, 0x00, 0x00, 0x00, // null terminator entry
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2, 8, 8,
        8, 8,
    ];
    if ntb.as_slice() != expected {
        return TestResult::Fail("built NTB differs from the pinned layout");
    }
    let dgrams = match bearer::parse_mbim_ntb(&ntb) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("pinned NTB did not parse"),
    };
    if dgrams.len() != 1 || dgrams[0].session != 1 || dgrams[0].data != payload {
        return TestResult::Fail("pinned NTB datagram wrong");
    }
    // Signature decode follows the Linux cdc_mbim demux exactly:
    // "NCM0" (an NCM function's NDP) is IPS session 0x30, and a value
    // with garbage in the low three bytes is not an MBIM NDP at all.
    if bearer::ndp_signature_session(0x304D_434E) != Some(0x30) {
        return TestResult::Fail("NCM0 signature did not decode as session 0x30");
    }
    if bearer::ndp_signature_session(bearer::ndp_signature_ips(5)) != Some(5) {
        return TestResult::Fail("IPS signature round trip failed");
    }
    if bearer::ndp_signature_session(0xDEAD_BEEF).is_some() {
        return TestResult::Fail("garbage signature decoded as a session");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_ntb_session_signing);

// ─── Fixture: end-to-end two-session conversation ────────────────────────────

fn eth_frame(dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn smoke_mbim_end_to_end_two_sessions() -> TestResult {
    let fake = FakeModem::new();
    let bearer_idx = bearer::register_bearer(fake.tx_sink(), [0x02, 0x4D, 0x42, 0x49, 0x4D, 0x01]);
    let mut modem = MbimModem::new(fake.clone());
    let fake2 = fake.clone();
    let scenario = async move {
        modem.open().await.map_err(|_| "open failed")?;
        let caps = modem.device_caps().await.map_err(|_| "caps failed")?;
        if caps.max_sessions != 8 || caps.device_id != "359072060009999" {
            return Err("caps fields wrong");
        }
        let ready = modem
            .subscriber_ready()
            .await
            .map_err(|_| "subscriber ready failed")?;
        if ready.ready_state != 1
            || !ready.subscriber_id.is_empty()
            || ready.sim_iccid != "8901260421234567890"
            || ready.ready_info != 0
        {
            return Err("subscriber fields wrong");
        }
        let radio = modem
            .radio_state()
            .await
            .map_err(|_| "radio query failed")?;
        if radio.software_state != 0 {
            return Err("radio should start off");
        }
        let radio = modem
            .set_radio_state(true)
            .await
            .map_err(|_| "radio set failed")?;
        if radio.software_state != 1 {
            return Err("radio set did not take");
        }
        let ps = modem
            .set_packet_service(true)
            .await
            .map_err(|_| "packet service set failed")?;
        if ps.packet_service_state != 2 {
            return Err("packet service not attached");
        }

        // Session 0: activation publishes wwan<N> with the modem's
        // reported address/gateway/MTU and raises carrier.
        let ip0 = bearer::activate_session(
            &mut modem,
            bearer_idx,
            &ConnectSetParams::activate(0, Some(String::from("web"))),
        )
        .await
        .map_err(|_| "activate session 0 failed")?;
        let v4 = ip0
            .ipv4
            .as_ref()
            .ok_or("session 0 reported no IPv4 config")?;
        if v4.address != [10, 0, 0, 2] || v4.gateway != Some([10, 0, 0, 1]) || v4.mtu != Some(1500)
        {
            return Err("session 0 IP config wrong");
        }
        let name0 =
            bearer::session_iface_name(bearer_idx, 0).ok_or("session 0 netdev unpublished")?;
        if name0 != alloc::format!("wwan{}", bearer_idx) {
            return Err("session 0 netdev name wrong");
        }
        let snap0 = narf_net::iface::lookup(&name0).ok_or("session 0 netdev not in registry")?;
        if !snap0.carrier || snap0.ipv4 != [10, 0, 0, 2] || snap0.gateway != [10, 0, 0, 1] {
            return Err("session 0 netdev parameters wrong");
        }
        if snap0.mtu != 1500 {
            return Err("session 0 netdev MTU wrong");
        }

        // Session 1: independent netdev with its own parameters.
        let ip1 =
            bearer::activate_session(&mut modem, bearer_idx, &ConnectSetParams::activate(1, None))
                .await
                .map_err(|_| "activate session 1 failed")?;
        if ip1.ipv4.as_ref().map(|v| v.address) != Some([10, 1, 0, 2]) {
            return Err("session 1 IP config wrong");
        }
        let name1 =
            bearer::session_iface_name(bearer_idx, 1).ok_or("session 1 netdev unpublished")?;
        let snap1 = narf_net::iface::lookup(&name1).ok_or("session 1 netdev not in registry")?;
        if !snap1.carrier || snap1.ipv4 != [10, 1, 0, 2] || snap1.mtu != 1400 {
            return Err("session 1 netdev parameters wrong");
        }

        // TX: each iface's frame leaves signed with ITS session id —
        // the masking-defeating property of the bearer.
        let p0: &[u8] = &[
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 0x40, 0x06, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8,
        ];
        let p1: &[u8] = &[
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 0x40, 0x06, 0, 0, 10, 1, 0, 2, 1, 1, 1, 1,
        ];
        if snap0.xmit(&eth_frame(snap0.mac, 0x0800, p0)).is_err() {
            return Err("session 0 xmit failed");
        }
        if snap1.xmit(&eth_frame(snap1.mac, 0x0800, p1)).is_err() {
            return Err("session 1 xmit failed");
        }
        let sent = fake2.sent_data();
        if sent.len() != 2 {
            return Err("expected exactly two NTBs on the data channel");
        }
        let d0 = bearer::parse_mbim_ntb(&sent[0]).map_err(|_| "TX NTB 0 unparseable")?;
        if d0.len() != 1 || d0[0].session != 0 || d0[0].data != p0 {
            return Err("session 0 frame cross-wired or mangled");
        }
        let d1 = bearer::parse_mbim_ntb(&sent[1]).map_err(|_| "TX NTB 1 unparseable")?;
        if d1.len() != 1 || d1[0].session != 1 || d1[0].data != p1 {
            return Err("session 1 frame cross-wired or mangled");
        }

        // Non-IP egress (ARP) is dropped + counted, never sent.
        if snap0
            .xmit(&eth_frame(snap0.mac, 0x0806, &[0u8; 28]))
            .is_err()
        {
            return Err("ARP xmit should be a counted drop, not an error");
        }
        if fake2.sent_data().len() != 2 {
            return Err("ARP frame leaked onto the bearer");
        }
        let drops = bearer::bearer_drop_counters(bearer_idx).ok_or("bearer vanished")?;
        if drops.0 != 1 {
            return Err("non-IP TX drop not counted");
        }

        // RX: a session-1 NTB lands ONLY on session 1's iface.
        let rx0_before = narf_net::iface::lookup(&name0)
            .ok_or("netdev 0 vanished")?
            .stats
            .rx_packets;
        let rx1_before = narf_net::iface::lookup(&name1)
            .ok_or("netdev 1 vanished")?
            .stats
            .rx_packets;
        let rx1: &[u8] = &[
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 8, 8, 8, 8, 10,
            1, 0, 2, 0x00, 0x35, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, b'm', b'b', b'i', b'm',
        ];
        bearer::deliver_ntb(bearer_idx, &fake_ntb(1, rx1))
            .map_err(|_| "deliver session 1 NTB failed")?;
        let rx0_after = narf_net::iface::lookup(&name0)
            .ok_or("netdev 0 vanished")?
            .stats
            .rx_packets;
        let rx1_after = narf_net::iface::lookup(&name1)
            .ok_or("netdev 1 vanished")?
            .stats
            .rx_packets;
        if rx1_after != rx1_before + 1 {
            return Err("session 1 RX not delivered to its iface");
        }
        if rx0_after != rx0_before {
            return Err("session 1 RX cross-delivered to session 0");
        }

        // RX for an unactivated session, and an NCM-signed NTB
        // (decodes as session 0x30), are dropped + counted.
        bearer::deliver_ntb(bearer_idx, &fake_ntb(5, rx1))
            .map_err(|_| "deliver unknown-session NTB failed")?;
        let mut ncm = fake_ntb(0, rx1);
        ncm[15] = 0x30; // NDP signature byte 3: '0' → session 0x30
        bearer::deliver_ntb(bearer_idx, &ncm).map_err(|_| "deliver NCM-signed NTB failed")?;
        let drops = bearer::bearer_drop_counters(bearer_idx).ok_or("bearer vanished")?;
        if drops.1 != 2 {
            return Err("unknown-session RX drops not counted");
        }

        // Channel separation: control carried only MBIM messages,
        // data carried only NTBs.
        for m in fake2.sent_control() {
            if mbim::MbimHeader::decode(&m).is_err() {
                return Err("non-MBIM bytes on the control channel");
            }
        }
        for n in fake2.sent_data() {
            if n.len() < 4 || n[0..4] != [0x4E, 0x43, 0x4D, 0x48] {
                return Err("non-NTB bytes on the data channel");
            }
        }

        // Disconnect session 1: the netdev stays, carrier drops.
        bearer::deactivate_session(&mut modem, bearer_idx, 1)
            .await
            .map_err(|_| "deactivate session 1 failed")?;
        let snap1 =
            narf_net::iface::lookup(&name1).ok_or("session 1 netdev vanished on disconnect")?;
        if snap1.carrier {
            return Err("session 1 carrier still up after disconnect");
        }
        modem.close().await.map_err(|_| "close failed")?;
        Ok::<(), &'static str>(())
    };
    match narf_scheduler::block_on(scenario) {
        Ok(()) => TestResult::Pass,
        Err(tag) => TestResult::Fail(tag),
    }
}
kernel_test_in!("drivers/wwan", smoke_mbim_end_to_end_two_sessions);

// ─── Fixture: connect refused → typed error, no netdev ───────────────────────

fn smoke_mbim_connect_refused() -> TestResult {
    // Case A: the modem answers CONNECT with MBIM_STATUS_FAILURE.
    let fake = FakeModem::new();
    fake.set_refuse_connect_status(MBIM_STATUS_FAILURE);
    let b = bearer::register_bearer(fake.tx_sink(), [0x02, 0x4D, 0x42, 0x49, 0x4D, 0x02]);
    let mut modem = MbimModem::new(fake.clone());
    let r = narf_scheduler::block_on(async {
        modem.open().await?;
        bearer::activate_session(
            &mut modem,
            b,
            &ConnectSetParams::activate(0, Some(String::from("web"))),
        )
        .await
    });
    match r {
        Err(WwanError::ModemStatus(s)) if s == MBIM_STATUS_FAILURE => {}
        Err(_) => return TestResult::Fail("status refusal surfaced as the wrong error"),
        Ok(_) => return TestResult::Fail("refused connect reported success"),
    }
    if bearer::session_iface_name(b, 0).is_some() {
        return TestResult::Fail("netdev published for a refused connect");
    }
    if narf_net::iface::lookup(&alloc::format!("wwan{}", b)).is_some() {
        return TestResult::Fail("refused session's iface exists in the registry");
    }

    // Case B: status SUCCESS but the session stays DEACTIVATED with
    // a network error — the refusal is the nw_error, typed the same.
    let fake = FakeModem::new();
    fake.set_refuse_connect_state(mbim::MBIM_STATUS_NO_PACKET_SERVICE);
    let b = bearer::register_bearer(fake.tx_sink(), [0x02, 0x4D, 0x42, 0x49, 0x4D, 0x03]);
    let mut modem = MbimModem::new(fake.clone());
    let r = narf_scheduler::block_on(async {
        modem.open().await?;
        bearer::activate_session(&mut modem, b, &ConnectSetParams::activate(0, None)).await
    });
    match r {
        Err(WwanError::ModemStatus(s)) if s == mbim::MBIM_STATUS_NO_PACKET_SERVICE => {}
        Err(_) => return TestResult::Fail("state refusal surfaced as the wrong error"),
        Ok(_) => return TestResult::Fail("deactivated connect reported success"),
    }
    if bearer::session_iface_name(b, 0).is_some() {
        return TestResult::Fail("netdev published for a deactivated connect");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_connect_refused);

// ─── Fixture: fragmented response + interleaved indication ────────────────────

fn smoke_mbim_fragmented_caps_and_indicate() -> TestResult {
    let fake = FakeModem::new();
    fake.set_fragment_caps();
    fake.set_indicate_before_caps();
    let mut modem = MbimModem::new(fake);
    let r = narf_scheduler::block_on(async {
        modem.open().await?;
        let caps = modem.device_caps().await?;
        if caps.max_sessions != 8 || caps.hardware_info != "MC7455" {
            return Err(WwanError::MalformedFrame);
        }
        // The unsolicited CID_CONNECT event for session 7, interleaved
        // ahead of the fragmented CAPS response, was captured — not
        // mistaken for the response, not lost.
        match modem.take_connect_event() {
            Some(ev) if ev.session_id == 7 && ev.activation_state == 2 => {}
            _ => return Err(WwanError::MalformedFrame),
        }
        Ok::<(), WwanError>(())
    });
    match r {
        Ok(()) => TestResult::Pass,
        Err(_) => TestResult::Fail("fragmented CAPS / interleaved INDICATE mishandled"),
    }
}
kernel_test_in!("drivers/wwan", smoke_mbim_fragmented_caps_and_indicate);

// ─── Fixture: descriptor absence behaviour ────────────────────────────────────

fn desc_iface(v: &mut Vec<u8>, number: u8, alt: u8, num_eps: u8, class: u8, subclass: u8) {
    v.extend_from_slice(&[9, 0x04, number, alt, num_eps, class, subclass, 0, 0]);
}
fn desc_ep(v: &mut Vec<u8>, addr: u8, attrs: u8, max_pkt: u16) {
    v.extend_from_slice(&[7, 0x05, addr, attrs]);
    v.extend_from_slice(&max_pkt.to_le_bytes());
    v.push(10);
}
fn mbim_blob(subclass: u8, with_mbim_desc: bool, with_union: bool, data_alts: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[9, 0x02, 0, 0, 2, 1, 0, 0x80, 0x32]); // config header
    desc_iface(&mut v, 0, 0, 1, 0x02, subclass); // comm interface
    v.extend_from_slice(&[5, 0x24, 0x00, 0x10, 0x01]); // header functional desc
    if with_union {
        v.extend_from_slice(&[5, 0x24, 0x06, 0, 1]); // union: control 0, subordinate 1
    }
    if with_mbim_desc {
        // MBIM functional descriptor (§6.5): bcd 1.00, max control
        // 4096, 16 filters, max filter 128, max segment 4096.
        v.extend_from_slice(&[
            12, 0x24, 0x1B, 0x00, 0x01, 0x00, 0x10, 16, 128, 0x00, 0x10, 0x20,
        ]);
    }
    desc_ep(&mut v, 0x83, 0x03, 16); // notification endpoint (interrupt IN)
    desc_iface(&mut v, 1, 0, 0, 0x0A, 0x00); // data interface, alt 0 (no endpoints)
    if data_alts > 1 {
        desc_iface(&mut v, 1, 1, 2, 0x0A, 0x00); // data interface, alt 1
        desc_ep(&mut v, 0x82, 0x02, 512); // bulk IN
        desc_ep(&mut v, 0x01, 0x02, 512); // bulk OUT
    }
    v
}

fn smoke_mbim_find_function_absence() -> TestResult {
    let good = mbim_blob(0x0E, true, true, 2);
    let f = match find_mbim_function(&good) {
        Some(f) => f,
        None => return TestResult::Fail("valid MBIM blob did not bind"),
    };
    if f.comm_iface != 0 || f.data_iface != 1 || f.data_alt != 1 {
        return TestResult::Fail("MBIM function interfaces wrong");
    }
    if f.descriptor.max_control_message != 4096 || f.descriptor.max_segment_size != 4096 {
        return TestResult::Fail("MBIM descriptor fields wrong");
    }
    // An NCM function (subclass 0x0D) is not MBIM, MBIM descriptor
    // or not — the neighbouring claimant keeps it.
    if find_mbim_function(&mbim_blob(0x0D, true, true, 2)).is_some() {
        return TestResult::Fail("NCM function bound as MBIM");
    }
    // MBIM subclass without the MBIM functional descriptor: no binding.
    if find_mbim_function(&mbim_blob(0x0E, false, true, 2)).is_some() {
        return TestResult::Fail("descriptor-less MBIM subclass bound");
    }
    // No data interface at all (blob ends after the comm group).
    let mut truncated = mbim_blob(0x0E, true, false, 2);
    truncated.truncate(9 + 9 + 5 + 12 + 7);
    if find_mbim_function(&truncated).is_some() {
        return TestResult::Fail("data-less function bound");
    }
    // Data interface whose only alt setting carries no endpoints.
    if find_mbim_function(&mbim_blob(0x0E, true, true, 1)).is_some() {
        return TestResult::Fail("endpoint-less data interface bound");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_find_function_absence);

// ─── Fixture: control-port registry ───────────────────────────────────────────

fn smoke_mbim_port_registry() -> TestResult {
    struct FakePort;
    impl WwanPort for FakePort {
        fn name(&self) -> &str {
            "wwan-fake0"
        }
        fn kind(&self) -> WwanPortKind {
            WwanPortKind::Mbim
        }
        fn send(&self, _payload: &[u8]) -> Result<(), WwanError> {
            Ok(())
        }
        fn recv(&self, _buf: &mut [u8]) -> Result<usize, WwanError> {
            Ok(0)
        }
    }
    let before = crate::port_count();
    crate::register_port(Arc::new(FakePort));
    if crate::port_count() != before + 1 {
        return TestResult::Fail("port registration did not stick");
    }
    match crate::port_by_name("wwan-fake0") {
        Some(p) if p.kind() == WwanPortKind::Mbim => {}
        _ => return TestResult::Fail("registered port not findable by name"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wwan", smoke_mbim_port_registry);
