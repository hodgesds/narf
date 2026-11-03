//! MEI client layer and GSC proxy smokes, run against the register-
//! level CSME model in `crate::mei_model`. The pre-existing MEI smokes
//! (match table, register layout, header and HBM encoding) stay in
//! `tests.rs`.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_drivers::gsc_proxy::{self as registry, DisplayComponent};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::mei::{
    self, errno, HbmPropsResponse, MeiClientProperties, MeiDevState, MeiDevice, MeiError,
    MeiMsgHdr, MeiTimeouts, MeiUuid, CLIENT_CONNECT_REQ_CMD, CLIENT_DISCONNECT_REQ_CMD,
    CLIENT_DISCONNECT_RES_CMD, HOST_CLIENT_PROPERTIES_REQ_CMD, HOST_CLIENT_PROPERTIES_RES_CMD,
    HOST_ENUM_RES_CMD, H_IE, H_RST, MEI_FLOW_CONTROL_CMD, MEI_HBMS_ALREADY_EXISTS,
    MEI_HBMS_CLIENT_NOT_FOUND, MEI_HBMS_INVALID_PARAMETER, MEI_HBMS_NOT_ALLOWED, MEI_HBMS_REJECTED,
};
use crate::mei_gsc_proxy::{self as proxy, ProxyProbeError, MEI_UUID_GSC_PROXY};
use crate::mei_model::{HeciModel, ModelClient, ModelRegs, Reply};

/// Short budgets: every success path completes on its first check
/// against the synchronous model, so these only bound the timeout
/// paths.
const FAST: MeiTimeouts = MeiTimeouts {
    hw_ready_ms: 10,
    hbm_ms: 10,
    hbuf_drain_ms: 10,
    connect_ms: 10,
    cl_io_ms: 10,
};
const GSC: u8 = 7;
const MTU: u32 = 4096;
const OTHER_UUID: MeiUuid = mei::uuid_le(0x1111_2222, 0x3333, 0x4444, [1, 2, 3, 4, 5, 6, 7, 8]);
const THIRD_UUID: MeiUuid = mei::uuid_le(0x5555_6666, 0x7777, 0x8888, [8, 7, 6, 5, 4, 3, 2, 1]);

type Dev = Arc<MeiDevice<ModelRegs>>;

fn up_as(model: &Arc<HeciModel>, did: u16) -> Option<Dev> {
    MeiDevice::<ModelRegs>::bring_up_with(model.regs(), did, 0, 0, FAST)
        .ok()
        .map(Arc::new)
}

fn up(model: &Arc<HeciModel>) -> Option<Dev> {
    up_as(model, mei::MEI_DEV_MTL_M)
}

fn gsc() -> ModelClient {
    ModelClient::new(GSC, MEI_UUID_GSC_PROXY, MTU)
}

/// Bus messages of one command the host wrote.
fn hbm_sent(model: &HeciModel, cmd: u8) -> Vec<Vec<u8>> {
    model
        .packets()
        .into_iter()
        .filter(|p| p.hdr.is_hbm() && p.data.first() == Some(&cmd))
        .map(|p| p.data)
        .collect()
}

fn igpu() -> DisplayComponent {
    DisplayComponent {
        segment: 0,
        bus: 0,
        device: 2,
        function: 0,
        vendor: 0x8086,
        class: 0x03_00_00,
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

// ── Properties and UUID ─────────────────────────────────────────────

fn smoke_mei_props_layout_and_gsc_uuid() -> TestResult {
    // UUID_LE(0xf73db04, 0x97ab, 0x4125, 0xb8, 0x93, 0xe9, 0x4, 0xad,
    // 0xd, 0x54, 0x64): the first three fields little-endian.
    const WIRE: MeiUuid = [
        0x04, 0xdb, 0x73, 0x0f, 0xab, 0x97, 0x25, 0x41, 0xb8, 0x93, 0xe9, 0x04, 0xad, 0x0d, 0x54,
        0x64,
    ];
    if MEI_UUID_GSC_PROXY != WIRE {
        return TestResult::Fail("GSC proxy UUID is not UUID_LE(0xf73db04, ...) on the wire");
    }
    let mut raw = [0u8; mei::MEI_CLIENT_PROPERTIES_LEN];
    raw[..16].copy_from_slice(&WIRE);
    raw[16] = 3; // protocol_version
    raw[17] = 1; // max_number_of_connections
    raw[18] = 0; // fixed_address
    raw[19] = 0b10; // vt_supported, not single_recv_buf
    raw[20..24].copy_from_slice(&0x0000_8000u32.to_le_bytes());
    let Some(p) = MeiClientProperties::parse(&raw) else {
        return TestResult::Fail("24-byte properties rejected");
    };
    if p.protocol_name != WIRE
        || p.protocol_version != 3
        || p.max_number_of_connections != 1
        || p.fixed_address != 0
        || p.single_recv_buf
        || !p.vt_supported
        || p.max_msg_length != 0x8000
    {
        return TestResult::Fail("properties decoded from the wrong offsets");
    }
    if p.to_bytes() != raw {
        return TestResult::Fail("properties did not round-trip");
    }
    if MeiClientProperties::parse(&raw[..23]).is_some() {
        return TestResult::Fail("short properties accepted");
    }
    // A NOT_FOUND answer may stop after the four header bytes.
    let short = [
        HOST_CLIENT_PROPERTIES_RES_CMD,
        9,
        MEI_HBMS_CLIENT_NOT_FOUND,
        0,
    ];
    match HbmPropsResponse::parse(&short) {
        Some(r) if r.me_addr == 9 && r.status == 1 && r.props.is_none() => {}
        _ => return TestResult::Fail("short properties response decoded wrong"),
    }
    if HbmPropsResponse::parse(&[HOST_ENUM_RES_CMD, 9, 0, 0]).is_some() {
        return TestResult::Fail("properties response with the wrong opcode accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_props_layout_and_gsc_uuid);

fn smoke_mei_props_walk_records_clients() -> TestResult {
    let model = HeciModel::new(
        32,
        32,
        vec![
            ModelClient::new(2, OTHER_UUID, 512),
            gsc(),
            ModelClient::new(9, THIRD_UUID, 64),
        ],
    );
    // In the bitmap, but firmware answers CLIENT_NOT_FOUND.
    model.add_enum_only(5);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up against the model failed");
    };
    if dev.props_error.is_some() || dev.state() != MeiDevState::Enabled {
        return TestResult::Fail("properties walk did not finish");
    }
    let addrs: Vec<u8> = dev.me_clients().iter().map(|c| c.addr).collect();
    if addrs != [2, GSC, 9] {
        return TestResult::Fail("walk recorded the wrong clients (NOT_FOUND must be skipped)");
    }
    // mei_hbm_prop_req: one request per set bit, lowest address first.
    let asked: Vec<u8> = hbm_sent(&model, HOST_CLIENT_PROPERTIES_REQ_CMD)
        .iter()
        .map(|d| d[1])
        .collect();
    if asked != [2, 5, GSC, 9] {
        return TestResult::Fail("properties requests not in address order");
    }
    match proxy::find_client(&dev) {
        Some(c) if c.addr == GSC && c.props.max_msg_length == MTU => {}
        _ => return TestResult::Fail("GSC proxy UUID not matched to its address"),
    }
    match dev.me_client_by_uuid(&THIRD_UUID) {
        Some(c) if c.addr == 9 && c.props.max_msg_length == 64 => TestResult::Pass,
        _ => TestResult::Fail("UUID lookup returned the wrong client"),
    }
}
kernel_test_in!("drivers/platform/mei", smoke_mei_props_walk_records_clients);

fn smoke_mei_props_walk_refuses_bad_status() -> TestResult {
    let mut c = gsc();
    c.props_status = MEI_HBMS_INVALID_PARAMETER;
    let model = HeciModel::new(32, 32, vec![c]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("a failed walk must not fail link bring-up");
    };
    if dev.props_error != Some(MeiError::HbmStatus(MEI_HBMS_INVALID_PARAMETER)) {
        return TestResult::Fail("bad properties status not reported");
    }
    if !dev.me_clients().is_empty() {
        return TestResult::Fail("clients recorded from a failed walk");
    }
    if dev.cl_connect(GSC) != Err(errno::ENOTTY) {
        return TestResult::Fail("connect after a failed walk must refuse with -ENOTTY");
    }
    if !hbm_sent(&model, CLIENT_CONNECT_REQ_CMD).is_empty() {
        return TestResult::Fail("connect request sent for an unknown client");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/mei",
    smoke_mei_props_walk_refuses_bad_status
);

fn smoke_mei_props_walk_refuses_address_mismatch() -> TestResult {
    let model = HeciModel::new(32, 32, vec![gsc()]);
    model.set_props_addr_skew(1);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("a failed walk must not fail link bring-up");
    };
    if dev.props_error
        != Some(MeiError::HbmAddressMismatch {
            asked: GSC,
            got: GSC + 1,
        })
    {
        return TestResult::Fail("properties for another address accepted");
    }
    if proxy::find_client(&dev).is_some() {
        return TestResult::Fail("client recorded under a mismatched address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/mei",
    smoke_mei_props_walk_refuses_address_mismatch
);

// ── Connect, flow control, disconnect ───────────────────────────────

fn smoke_mei_cl_connect_and_flow_control() -> TestResult {
    let mut c = gsc();
    c.grant_after_message = false;
    c.reply = Reply::Silent;
    let model = HeciModel::new(32, 32, vec![c]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    let h = match dev.cl_connect(GSC) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("connect failed"),
    };
    // mei_cl_link: host address 0 is reserved, so the first is 1.
    if h.host_addr != 1 || h.me_addr != GSC || !dev.cl_connected(h) {
        return TestResult::Fail("connect handle wrong");
    }
    if hbm_sent(&model, CLIENT_CONNECT_REQ_CMD) != [vec![CLIENT_CONNECT_REQ_CMD, GSC, 1, 0]] {
        return TestResult::Fail("connect request not hbm_client_connect_request");
    }
    if dev.cl_mtu(h) != MTU as usize {
        return TestResult::Fail("mtu is not the client's max_msg_length");
    }
    // The credit firmware granted on connect covers one message.
    if dev.cl_send(h, b"one") != Ok(3) {
        return TestResult::Fail("send with a credit failed");
    }
    // No second credit: the write waits, then times out.
    if dev.cl_send(h, b"two") != Err(errno::ETIME) {
        return TestResult::Fail("send without a credit did not wait for one");
    }
    if model.delivered().len() != 1 {
        return TestResult::Fail("a message went out without a credit");
    }
    model.grant(GSC, 1);
    if dev.cl_send(h, b"two") != Ok(3) {
        return TestResult::Fail("send after a fresh credit failed");
    }
    let got: Vec<Vec<u8>> = model.delivered().into_iter().map(|d| d.2).collect();
    if got != [b"one".to_vec(), b"two".to_vec()] {
        return TestResult::Fail("firmware received the wrong messages");
    }
    if dev.cl_disconnect(h).is_err() || model.conn_count() != 0 {
        return TestResult::Fail("disconnect handshake failed");
    }
    if hbm_sent(&model, CLIENT_DISCONNECT_REQ_CMD) != [vec![CLIENT_DISCONNECT_REQ_CMD, GSC, 1, 0]] {
        return TestResult::Fail("disconnect request malformed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/mei",
    smoke_mei_cl_connect_and_flow_control
);

fn smoke_mei_cl_connect_status_errnos() -> TestResult {
    // hbm.c::mei_cl_conn_status_to_errno.
    let table = [
        (MEI_HBMS_CLIENT_NOT_FOUND, errno::ENOTTY),
        (MEI_HBMS_ALREADY_EXISTS, errno::EBUSY),
        (MEI_HBMS_REJECTED, errno::EBUSY),
        (MEI_HBMS_INVALID_PARAMETER, errno::EINVAL),
        (MEI_HBMS_NOT_ALLOWED, errno::EBUSY),
        (9, errno::EINVAL),
    ];
    for (status, want) in table {
        if mei::cl_conn_status_to_errno(status) != want {
            return TestResult::Fail("connect status errno mapping differs from Linux");
        }
        let mut c = gsc();
        c.connect_status = status;
        let model = HeciModel::new(32, 32, vec![c]);
        let Some(dev) = up(&model) else {
            return TestResult::Fail("bring-up failed");
        };
        if dev.cl_connect(GSC) != Err(want) {
            return TestResult::Fail("refused connect returned the wrong errno");
        }
        let gone = dev.me_client_by_uuid(&MEI_UUID_GSC_PROXY).is_none();
        // mei_hbm_cl_connect_res: only NOT_FOUND deletes the client.
        if gone != (status == MEI_HBMS_CLIENT_NOT_FOUND) {
            return TestResult::Fail("firmware client table wrong after a refused connect");
        }
    }
    if mei::cl_conn_status_to_errno(0) != 0 {
        return TestResult::Fail("success status is not 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_cl_connect_status_errnos);

fn smoke_mei_cl_connect_timeout_disconnects() -> TestResult {
    let model = HeciModel::new(32, 32, vec![gsc()]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    model.set_ignore_connect(true);
    // mei_connect_timeout with hbm_f_dot_supported → DISCONNECT_REQUIRED
    // → __mei_cl_disconnect, and mei_cl_connect returns -EFAULT.
    if dev.cl_connect(GSC) != Err(errno::EFAULT) {
        return TestResult::Fail("unanswered connect did not fail with -EFAULT");
    }
    if hbm_sent(&model, CLIENT_DISCONNECT_REQ_CMD).len() != 1 {
        return TestResult::Fail("timed-out connect was not followed by a disconnect");
    }
    if dev.state() != MeiDevState::Enabled {
        return TestResult::Fail("an answered disconnect must keep the link up");
    }
    model.set_ignore_connect(false);
    match dev.cl_connect(GSC) {
        Ok(h) if h.host_addr == 1 => TestResult::Pass,
        Ok(_) => TestResult::Fail("timed-out connect leaked its host address"),
        Err(_) => TestResult::Fail("reconnect after a timeout failed"),
    }
}
kernel_test_in!(
    "drivers/platform/mei",
    smoke_mei_cl_connect_timeout_disconnects
);

fn smoke_mei_cl_fixed_address_refused() -> TestResult {
    let mut c = gsc();
    c.props.fixed_address = GSC;
    let model = HeciModel::new(32, 32, vec![c]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    if dev.cl_connect(GSC) != Err(errno::EOPNOTSUPP) {
        return TestResult::Fail("fixed-address client not refused");
    }
    if !hbm_sent(&model, CLIENT_CONNECT_REQ_CMD).is_empty() {
        return TestResult::Fail("connect request sent to a fixed-address client");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_cl_fixed_address_refused);

fn smoke_mei_cl_single_recv_buf_credits() -> TestResult {
    for single in [true, false] {
        let mut c = gsc();
        c.props.single_recv_buf = single;
        c.grant_on_connect = false;
        c.grant_after_message = false;
        c.reply = Reply::Silent;
        let model = HeciModel::new(32, 32, vec![c]);
        let Some(dev) = up(&model) else {
            return TestResult::Fail("bring-up failed");
        };
        let Ok(h) = dev.cl_connect(GSC) else {
            return TestResult::Fail("connect failed");
        };
        if dev.cl_send(h, b"x") != Err(errno::ETIME) {
            return TestResult::Fail("send without any credit did not time out");
        }
        // host_addr 0: a credit for the firmware client's shared buffer.
        model.grant(GSC, 0);
        let want = if single { Ok(1) } else { Err(errno::ETIME) };
        if dev.cl_send(h, b"x") != want {
            return TestResult::Fail(if single {
                "single_recv_buf credit not usable"
            } else {
                "shared-buffer credit accepted for a per-connection client"
            });
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_cl_single_recv_buf_credits);

// ── Send / receive framing and limits ───────────────────────────────

fn smoke_mei_cl_send_recv_fragments() -> TestResult {
    // 16-slot buffers: 60 payload bytes per packet each way.
    let model = HeciModel::new(16, 16, vec![gsc()]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    let Ok(h) = dev.cl_connect(GSC) else {
        return TestResult::Fail("connect failed");
    };
    model.clear_packets();
    let msg = pattern(200);
    if dev.cl_send(h, &msg) != Ok(200) {
        return TestResult::Fail("fragmented send failed");
    }
    let frags: Vec<(MeiMsgHdr, Vec<u8>)> = model
        .packets()
        .into_iter()
        .filter(|p| !p.hdr.is_hbm())
        .map(|p| (p.hdr, p.data))
        .collect();
    let lens: Vec<u16> = frags.iter().map(|f| f.0.length).collect();
    if lens != [60, 60, 60, 20] {
        return TestResult::Fail("send not split to the host buffer");
    }
    if frags
        .iter()
        .enumerate()
        .any(|(k, f)| f.0.msg_complete != (k == 3) || f.0.me_addr != GSC || f.0.host_addr != 1)
    {
        return TestResult::Fail("msg_complete / addressing wrong on fragments");
    }
    if model.delivered() != [(GSC, 1, msg.clone())] {
        return TestResult::Fail("firmware reassembled something else");
    }
    let mut buf = vec![0u8; 512];
    if dev.cl_recv(h, &mut buf) != Ok(200) || buf[..200] != msg[..] {
        return TestResult::Fail("fragmented reply not reassembled");
    }
    // The read's credit went out before the reply could.
    let fc = hbm_sent(&model, MEI_FLOW_CONTROL_CMD);
    if fc != [vec![MEI_FLOW_CONTROL_CMD, GSC, 1, 0, 0, 0, 0, 0]] {
        return TestResult::Fail("read did not grant exactly one hbm_flow_control credit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_cl_send_recv_fragments);

fn smoke_mei_cl_size_limits() -> TestResult {
    let model = HeciModel::new(32, 16, vec![ModelClient::new(GSC, MEI_UUID_GSC_PROXY, 100)]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    let Ok(h) = dev.cl_connect(GSC) else {
        return TestResult::Fail("connect failed");
    };
    // __mei_cl_send: longer than the MTU is -EFBIG, before any I/O.
    if dev.cl_send(h, &pattern(101)) != Err(errno::EFBIG) {
        return TestResult::Fail("over-MTU send not refused with -EFBIG");
    }
    if !model.delivered().is_empty() {
        return TestResult::Fail("over-MTU send reached firmware");
    }
    let msg = pattern(100);
    if dev.cl_send(h, &msg) != Ok(100) {
        return TestResult::Fail("MTU-sized send failed");
    }
    // The read buffer is max(16, MTU): the 100-byte echo fits and is
    // truncated to the caller's 16 bytes.
    let mut small = [0u8; 16];
    if dev.cl_recv(h, &mut small) != Ok(16) || small[..] != msg[..16] {
        return TestResult::Fail("reply not truncated to the caller's buffer");
    }
    // A reply beyond max(len, MTU) overflows the read: -EMSGSIZE.
    model.set_reply(GSC, Reply::Bytes(pattern(150)));
    if dev.cl_send(h, b"q") != Ok(1) {
        return TestResult::Fail("send before the oversized reply failed");
    }
    if dev.cl_recv(h, &mut small) != Err(errno::EMSGSIZE) {
        return TestResult::Fail("oversized reply not -EMSGSIZE");
    }
    // The connection survives.
    model.set_reply(GSC, Reply::Echo);
    if dev.cl_send(h, b"ok") != Ok(2) {
        return TestResult::Fail("send after -EMSGSIZE failed");
    }
    let mut buf = [0u8; 8];
    if dev.cl_recv(h, &mut buf) != Ok(2) || buf[..2] != b"ok"[..] {
        return TestResult::Fail("receive after -EMSGSIZE got the overflow's tail");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_cl_size_limits);

fn smoke_mei_cl_recv_timeout_keeps_credit() -> TestResult {
    let mut c = gsc();
    c.reply = Reply::Silent;
    let model = HeciModel::new(32, 32, vec![c]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    let Ok(h) = dev.cl_connect(GSC) else {
        return TestResult::Fail("connect failed");
    };
    let mut buf = [0u8; 16];
    if dev.cl_recv(h, &mut buf) != Err(errno::ETIME) {
        return TestResult::Fail("silent firmware did not time the receive out");
    }
    // The credit stays outstanding; a late reply is the next read's.
    model.queue_reply(GSC, 1, b"late");
    if dev.cl_recv(h, &mut buf) != Ok(4) || buf[..4] != b"late"[..] {
        return TestResult::Fail("late reply lost");
    }
    if hbm_sent(&model, MEI_FLOW_CONTROL_CMD).len() != 1 {
        return TestResult::Fail("a second read credit was granted while one was outstanding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/mei",
    smoke_mei_cl_recv_timeout_keeps_credit
);

// ── Teardown ────────────────────────────────────────────────────────

fn smoke_mei_cl_device_loss_tears_down() -> TestResult {
    let model = HeciModel::new(32, 32, vec![gsc()]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    let Ok(h) = dev.cl_connect(GSC) else {
        return TestResult::Fail("connect failed");
    };
    model.set_gone(true);
    let mut buf = [0u8; 8];
    if dev.cl_recv(h, &mut buf) != Err(errno::ENODEV) {
        return TestResult::Fail("receive on a lost device not -ENODEV");
    }
    if dev.state() != MeiDevState::Lost || dev.cl_connected(h) {
        return TestResult::Fail("device loss did not disconnect the client");
    }
    // NARF does not re-run bring-up on its own.
    model.set_gone(false);
    if dev.cl_send(h, b"x") != Err(errno::ENODEV) {
        return TestResult::Fail("send after loss not -ENODEV");
    }
    if dev.cl_connect(GSC) != Err(errno::ENOTTY) {
        return TestResult::Fail("loss must forget the firmware clients");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_cl_device_loss_tears_down);

fn smoke_mei_cl_fw_not_ready_tears_down() -> TestResult {
    let model = HeciModel::new(32, 32, vec![gsc()]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    let Ok(h) = dev.cl_connect(GSC) else {
        return TestResult::Fail("connect failed");
    };
    model.set_me_ready(false);
    if dev.cl_send(h, b"x") != Err(errno::ENODEV) || dev.state() != MeiDevState::Lost {
        return TestResult::Fail("firmware dropping ME_RDY did not take the link down");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_cl_fw_not_ready_tears_down);

fn smoke_mei_cl_fw_disconnect_request() -> TestResult {
    let mut c = gsc();
    c.reply = Reply::Silent;
    let model = HeciModel::new(32, 32, vec![c]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    let Ok(h) = dev.cl_connect(GSC) else {
        return TestResult::Fail("connect failed");
    };
    model.inject_hbm(&[CLIENT_DISCONNECT_REQ_CMD, GSC, 1, 0]);
    let mut buf = [0u8; 8];
    if dev.cl_recv(h, &mut buf) != Err(errno::ENODEV) {
        return TestResult::Fail("receive across a firmware disconnect not -ENODEV");
    }
    // mei_hbm_fw_disconnect_req → mei_hbm_cl_disconnect_rsp.
    if hbm_sent(&model, CLIENT_DISCONNECT_RES_CMD) != [vec![CLIENT_DISCONNECT_RES_CMD, GSC, 1, 0]] {
        return TestResult::Fail("firmware disconnect not acknowledged");
    }
    if dev.cl_connected(h) || dev.state() != MeiDevState::Enabled {
        return TestResult::Fail("firmware disconnect must drop the client, not the link");
    }
    if dev.cl_disconnect(h).is_err() || dev.cl_disconnect(h) != Err(errno::ENODEV) {
        return TestResult::Fail("disable after a firmware disconnect must just unlink");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_cl_fw_disconnect_request);

fn smoke_mei_cl_protocol_errors_reset_link() -> TestResult {
    let reserved = MeiMsgHdr::bus_message(0).to_u32() | (1 << 25);
    let extended = MeiMsgHdr {
        extended: true,
        ..MeiMsgHdr::bus_message(4)
    }
    .to_u32();
    let dma = MeiMsgHdr {
        dma_ring: true,
        ..MeiMsgHdr::bus_message(4)
    }
    .to_u32();
    let unknown_client = MeiMsgHdr {
        me_addr: GSC,
        host_addr: 9,
        ..MeiMsgHdr::bus_message(0)
    }
    .to_u32();
    let bad: [&[u32]; 7] = [
        &[0],
        &[reserved],
        &[extended, 0],
        &[dma, 0],
        &[unknown_client],
        // A flow-control message shorter than hbm_flow_control.
        &[
            MeiMsgHdr::bus_message(4).to_u32(),
            u32::from_le_bytes([MEI_FLOW_CONTROL_CMD, GSC, 1, 0]),
        ],
        // An enumeration response nobody asked for.
        &[
            MeiMsgHdr::bus_message(4).to_u32(),
            u32::from(HOST_ENUM_RES_CMD),
        ],
    ];
    for words in bad {
        let model = HeciModel::new(32, 32, vec![gsc()]);
        let Some(dev) = up(&model) else {
            return TestResult::Fail("bring-up failed");
        };
        let Ok(h) = dev.cl_connect(GSC) else {
            return TestResult::Fail("connect failed");
        };
        model.inject_raw(words);
        if dev.cl_send(h, b"x") != Err(errno::ENODEV) || dev.state() != MeiDevState::Lost {
            return TestResult::Fail("protocol violation did not take the link down");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/mei",
    smoke_mei_cl_protocol_errors_reset_link
);

fn smoke_mei_power_down_and_restart() -> TestResult {
    let model = HeciModel::new(32, 32, vec![gsc()]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    let Ok(h) = dev.cl_connect(GSC) else {
        return TestResult::Fail("connect failed");
    };
    let resets = model.resets();
    model.clear_packets();
    dev.power_down();
    if dev.state() != MeiDevState::PowerDown || dev.cl_connected(h) {
        return TestResult::Fail("power-down left the client connected");
    }
    // mei_me_hw_reset(dev, false): asserted, released, IRQs off.
    if model.resets() != resets + 1 || model.host_bits() & (H_RST | H_IE) != 0 {
        return TestResult::Fail("power-down did not reset and release the link");
    }
    let mut buf = [0u8; 4];
    if dev.cl_send(h, b"x") != Err(errno::ENODEV) || dev.cl_recv(h, &mut buf) != Err(errno::ENODEV)
    {
        return TestResult::Fail("I/O after power-down not -ENODEV");
    }
    // MEI_DEV_POWERING_DOWN: disable unlinks without a handshake.
    if dev.cl_disconnect(h).is_err() || !model.packets().is_empty() {
        return TestResult::Fail("disable after power-down talked to firmware");
    }
    let Ok(again) = dev.restart() else {
        return TestResult::Fail("restart after power-down failed");
    };
    if again.state() != MeiDevState::Enabled || proxy::find_client(&again).is_none() {
        return TestResult::Fail("restart did not re-enumerate");
    }
    match again.cl_connect(GSC) {
        Ok(h2) if again.cl_connected(h2) => TestResult::Pass,
        _ => TestResult::Fail("connect after restart failed"),
    }
}
kernel_test_in!("drivers/platform/mei", smoke_mei_power_down_and_restart);

// ── GSC proxy client ────────────────────────────────────────────────

fn smoke_mei_gsc_proxy_component_match() -> TestResult {
    if !proxy::component_match(&igpu()) {
        return TestResult::Fail("built-in Intel VGA on bus 0 not matched");
    }
    let mut d = igpu();
    d.bus = 3;
    if proxy::component_match(&d) {
        return TestResult::Fail("discrete (bus != 0) display matched");
    }
    let mut d = igpu();
    d.class = 0x03_80_00;
    if proxy::component_match(&d) {
        return TestResult::Fail("non-VGA display class matched");
    }
    let mut d = igpu();
    d.class = 0x03_00_01;
    if proxy::component_match(&d) {
        return TestResult::Fail("class compare ignored the prog-if byte");
    }
    let mut d = igpu();
    d.vendor = 0x1002;
    if proxy::component_match(&d) {
        return TestResult::Fail("non-Intel display matched");
    }
    if proxy::GSC_PROXY_HECI_IDS != [0x7E70, 0x7F68, 0x7770] {
        return TestResult::Fail("GSC proxy HECI ids differ from MTL-M / ARL-S / ARL-H");
    }
    if !proxy::GSC_PROXY_HECI_IDS
        .iter()
        .all(|&d| mei::is_supported_device(d))
        || proxy::heci_carries_gsc_proxy(mei::MEI_DEV_PTL_H)
    {
        return TestResult::Fail("GSC proxy HECI gate wrong");
    }
    // number_of_connections + vt_support.
    let mut info = mei::MeClientInfo {
        addr: GSC,
        props: gsc().props,
    };
    if !proxy::client_eligible(&info) {
        return TestResult::Fail("single-connection GSC proxy client not eligible");
    }
    info.props.max_number_of_connections = 2;
    if proxy::client_eligible(&info) {
        return TestResult::Fail("multi-connection client without vtags eligible");
    }
    info.props.vt_supported = true;
    if !proxy::client_eligible(&info) {
        return TestResult::Fail("vt_support fixup not applied");
    }
    info.props.protocol_name = OTHER_UUID;
    if proxy::client_eligible(&info) {
        return TestResult::Fail("other UUID matched");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_gsc_proxy_component_match);

fn gsc_proxy_binds_display() -> TestResult {
    let model = HeciModel::new(32, 32, vec![ModelClient::new(2, OTHER_UUID, 512), gsc()]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    if registry::lookup(&igpu()).is_some() {
        return TestResult::Fail("component bound before the client probed");
    }
    let bound = match proxy::probe(&dev) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("GSC proxy probe failed"),
    };
    let Some(b) = registry::lookup(&igpu()) else {
        return TestResult::Fail("built-in display did not bind");
    };
    if b.generation != bound.generation || b.name != proxy::DRIVER_NAME {
        return TestResult::Fail("binding is not the registered master");
    }
    let mut d = igpu();
    d.bus = 3;
    if registry::lookup(&d).is_some() {
        return TestResult::Fail("discrete display bound");
    }
    if b.send(b"proxy") != Ok(5) {
        return TestResult::Fail("ops->send failed");
    }
    let mut buf = [0u8; 32];
    if b.recv(&mut buf) != Ok(5) || buf[..5] != b"proxy"[..] {
        return TestResult::Fail("ops->recv failed");
    }
    if model.delivered() != [(GSC, bound.proxy.handle().host_addr, b"proxy".to_vec())] {
        return TestResult::Fail("proxy message went to the wrong client");
    }
    // A stale generation cannot withdraw the master.
    if registry::unregister_master(bound.generation.wrapping_add(1000)) {
        return TestResult::Fail("stale generation withdrew the master");
    }
    if proxy::remove(&bound).is_err() {
        return TestResult::Fail("remove failed");
    }
    if registry::lookup(&igpu()).is_some() || model.conn_count() != 0 {
        return TestResult::Fail("remove did not unbind and disconnect");
    }
    if b.send(b"x") != Err(errno::ENODEV) || b.connected() {
        return TestResult::Fail("op on an unbound binding not -ENODEV");
    }
    // Re-probe: a new generation.
    let again = match proxy::probe(&dev) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("re-probe failed"),
    };
    let ok = again.generation > bound.generation
        && registry::lookup(&igpu()).is_some_and(|b2| b2.generation == again.generation);
    let _ = proxy::remove(&again);
    if !ok {
        return TestResult::Fail("re-probe did not publish a new generation");
    }
    TestResult::Pass
}

fn smoke_mei_gsc_proxy_binds_display() -> TestResult {
    registry::__reset_for_test();
    let r = gsc_proxy_binds_display();
    registry::__reset_for_test();
    r
}
kernel_test_in!("drivers/platform/mei", smoke_mei_gsc_proxy_binds_display);

fn gsc_proxy_unbinds_on_loss() -> TestResult {
    let model = HeciModel::new(32, 32, vec![gsc()]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    if proxy::probe(&dev).is_err() {
        return TestResult::Fail("GSC proxy probe failed");
    }
    let Some(b) = registry::lookup(&igpu()) else {
        return TestResult::Fail("display did not bind");
    };
    model.set_gone(true);
    if b.send(b"x") != Err(errno::ENODEV) {
        return TestResult::Fail("send on a lost device not -ENODEV");
    }
    if registry::lookup(&igpu()).is_some() {
        return TestResult::Fail("component still bound after device loss");
    }
    TestResult::Pass
}

fn smoke_mei_gsc_proxy_unbinds_on_loss() -> TestResult {
    registry::__reset_for_test();
    let r = gsc_proxy_unbinds_on_loss();
    registry::__reset_for_test();
    r
}
kernel_test_in!("drivers/platform/mei", smoke_mei_gsc_proxy_unbinds_on_loss);

fn gsc_proxy_refusals() -> TestResult {
    // A HECI function outside MTL-M / ARL-S / ARL-H: refused before
    // any I/O, even with the client present.
    let model = HeciModel::new(32, 32, vec![gsc()]);
    let Some(dev) = up_as(&model, mei::MEI_DEV_PTL_H) else {
        return TestResult::Fail("bring-up failed");
    };
    if proxy::probe(&dev).err() != Some(ProxyProbeError::NotGscProxyHeci(mei::MEI_DEV_PTL_H)) {
        return TestResult::Fail("GSC proxy bound on a non-MTL/ARL HECI");
    }
    if !hbm_sent(&model, CLIENT_CONNECT_REQ_CMD).is_empty() {
        return TestResult::Fail("refused probe still connected");
    }
    // No GSC proxy client in firmware.
    let model = HeciModel::new(32, 32, vec![ModelClient::new(2, OTHER_UUID, 512)]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    if proxy::probe(&dev).err() != Some(ProxyProbeError::NoClient) {
        return TestResult::Fail("probe without the client not refused");
    }
    if registry::lookup(&igpu()).is_some() {
        return TestResult::Fail("component bound with no client");
    }
    // Refused connect: the errno comes back, nothing is published.
    let mut c = gsc();
    c.connect_status = MEI_HBMS_NOT_ALLOWED;
    let model = HeciModel::new(32, 32, vec![c]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    if proxy::probe(&dev).err() != Some(ProxyProbeError::Enable(errno::EBUSY)) {
        return TestResult::Fail("refused connect not reported as Enable(-EBUSY)");
    }
    if registry::lookup(&igpu()).is_some() {
        return TestResult::Fail("component bound after a refused connect");
    }
    // Unknown firmware address and stale handles.
    let model = HeciModel::new(32, 32, vec![ModelClient::new(2, OTHER_UUID, 512)]);
    let Some(dev) = up(&model) else {
        return TestResult::Fail("bring-up failed");
    };
    if dev.cl_connect(99) != Err(errno::ENOTTY) {
        return TestResult::Fail("connect to an unknown address not -ENOTTY");
    }
    let Ok(h) = dev.cl_connect(2) else {
        return TestResult::Fail("connect failed");
    };
    if dev.cl_disconnect(h).is_err() {
        return TestResult::Fail("disconnect failed");
    }
    let mut buf = [0u8; 4];
    if dev.cl_send(h, b"x") != Err(errno::ENODEV)
        || dev.cl_recv(h, &mut buf) != Err(errno::ENODEV)
        || dev.cl_disconnect(h) != Err(errno::ENODEV)
    {
        return TestResult::Fail("stale handle not refused with -ENODEV");
    }
    // A reconnect reuses host address 1 under a new generation; the
    // stale handle must not reach it.
    let Ok(h2) = dev.cl_connect(2) else {
        return TestResult::Fail("reconnect failed");
    };
    if h2.host_addr != h.host_addr || h2 == h || dev.cl_send(h, b"x") != Err(errno::ENODEV) {
        return TestResult::Fail("stale handle reached a reused host address");
    }
    TestResult::Pass
}

fn smoke_mei_gsc_proxy_refusals() -> TestResult {
    registry::__reset_for_test();
    let r = gsc_proxy_refusals();
    registry::__reset_for_test();
    r
}
kernel_test_in!("drivers/platform/mei", smoke_mei_gsc_proxy_refusals);
