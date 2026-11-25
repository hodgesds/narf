//! MEI HDCP client smokes, run against the register-level CSME model in
//! `crate::mei_model`. The command bytes are laid out from
//! `include/drm/intel/i915_hdcp_interface.h` by hand here, never by the
//! display driver's encoder, so the transport is pinned independently.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_drivers::hdcp_component::{self as registry, DisplayComponent};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::mei::{self, errno, MeiDevice, MeiTimeouts, MeiUuid, MEI_HBMS_NOT_ALLOWED};
use crate::mei_hdcp::{self as hdcp, HdcpProbeError, MEI_UUID_HDCP};
use crate::mei_model::{HeciModel, ModelClient, ModelRegs, Reply};

const FAST: MeiTimeouts = MeiTimeouts {
    hw_ready_ms: 10,
    hbm_ms: 10,
    hbuf_drain_ms: 10,
    connect_ms: 10,
    cl_io_ms: 10,
};
const HDCP: u8 = 9;
const OTHER_UUID: MeiUuid = mei::uuid_le(0x1111_2222, 0x3333, 0x4444, [1, 2, 3, 4, 5, 6, 7, 8]);

type Dev = Arc<MeiDevice<ModelRegs>>;

fn up_as(model: &Arc<HeciModel>, did: u16) -> Option<Dev> {
    MeiDevice::<ModelRegs>::bring_up_with(model.regs(), did, 0, 0, FAST)
        .ok()
        .map(Arc::new)
}

fn client() -> ModelClient {
    ModelClient::new(HDCP, MEI_UUID_HDCP, 4096)
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

/// `struct hdcp_cmd_header` (api_version, command_id, status,
/// buffer_len, all little endian) followed by `struct hdcp_port_id`.
fn header(command: u32, buffer_len: u32, port: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // HDCP_API_VERSION
    v.extend_from_slice(&command.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // FW_HDCP_STATUS_SUCCESS
    v.extend_from_slice(&buffer_len.to_le_bytes());
    v.extend_from_slice(&port);
    v
}

fn smoke_mei_hdcp_component_match() -> TestResult {
    if MEI_UUID_HDCP
        != [
            0x7E, 0xAB, 0x38, 0xB6, 0xE2, 0x94, 0xA2, 0x4E, 0xA5, 0x52, 0xD1, 0xC5, 0x4B, 0x62,
            0x7F, 0x04,
        ]
    {
        return TestResult::Fail("MEI_UUID_HDCP wire bytes differ from UUID_LE(0xB638AB7E, ...)");
    }
    if !hdcp::component_match(&igpu()) {
        return TestResult::Fail("built-in Intel VGA on bus 0 not matched");
    }
    let mut d = igpu();
    d.bus = 3;
    if hdcp::component_match(&d) {
        return TestResult::Fail("discrete display matched");
    }
    let mut d = igpu();
    d.vendor = 0x1002;
    if hdcp::component_match(&d) {
        return TestResult::Fail("non-Intel display matched");
    }
    let mut d = igpu();
    d.class = 0x03_80_00;
    if hdcp::component_match(&d) {
        return TestResult::Fail("non-VGA display matched");
    }
    // Display 12/13 PCHs only: Meteor Lake and later use the GSC.
    if hdcp::HDCP_HECI_IDS != [0xA0E0, 0x43E0, 0x7AE8, 0x7A60, 0x51E0, 0x54E0, 0x7A68] {
        return TestResult::Fail("HDCP HECI ids differ from TGP / ADP / RPL");
    }
    if hdcp::heci_carries_hdcp(mei::MEI_DEV_MTL_M) || hdcp::heci_carries_hdcp(mei::MEI_DEV_PTL_H) {
        return TestResult::Fail("HDCP client bound on a GSC-era HECI");
    }
    let mut info = mei::MeClientInfo {
        addr: HDCP,
        props: client().props,
    };
    if !hdcp::client_eligible(&info) {
        return TestResult::Fail("single-connection HDCP client not eligible");
    }
    info.props.max_number_of_connections = 2;
    if hdcp::client_eligible(&info) {
        return TestResult::Fail("multi-connection client without vtags eligible");
    }
    info.props.protocol_name = OTHER_UUID;
    info.props.max_number_of_connections = 1;
    if hdcp::client_eligible(&info) {
        return TestResult::Fail("other UUID matched");
    }
    // The strict option.
    let opt = hdcp::BOOT_OPTION;
    if !hdcp::boot_opt_in("quiet narf.intel.hdcp=1", opt)
        || hdcp::boot_opt_in("narf.intel.hdcp", opt)
        || hdcp::boot_opt_in("narf.intel.hdcp=0", opt)
        || hdcp::boot_opt_in("narf.intel.hdcp=1 narf.intel.hdcp=1", opt)
        || hdcp::boot_opt_in("-- narf.intel.hdcp=1", opt)
        || hdcp::boot_opt_in("", opt)
    {
        return TestResult::Fail("narf.intel.hdcp is not a strict =1 option");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_hdcp_component_match);

fn hdcp_binds_display() -> TestResult {
    let model = HeciModel::new(32, 32, vec![ModelClient::new(2, OTHER_UUID, 512), client()]);
    let Some(dev) = up_as(&model, mei::MEI_DEV_ADP_P) else {
        return TestResult::Fail("bring-up failed");
    };
    if registry::lookup(&igpu()).is_some() {
        return TestResult::Fail("component bound before the client probed");
    }
    let bound = match hdcp::probe(&dev) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("HDCP probe failed"),
    };
    let Some(b) = registry::lookup(&igpu()) else {
        return TestResult::Fail("built-in display did not bind");
    };
    if b.generation != bound.generation || b.name != hdcp::DRIVER_NAME {
        return TestResult::Fail("binding is not the registered master");
    }
    // wired_cmd_initiate_hdcp2_session_in: header (buffer_len
    // WIRED_CMD_BUF_LEN_INITIATE_HDCP2_SESSION_IN = 5), port
    // {INTEGRATED, physical 0, transcoder A = 0x10}, protocol DP.
    let mut command = header(0x0003_1000, 5, [1, 0, 0x10, 0]);
    command.push(2);
    // ..._out: header (buffer_len 15), port, r_tx[8], tx_caps {2, 0, 0}.
    let mut reply = header(0x0003_1000, 15, [1, 0, 0x10, 0]);
    reply.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 2, 0, 0]);
    model.set_reply(HDCP, Reply::Bytes(reply.clone()));
    let mut out = [0u8; 31];
    if command.len() != 21 || b.exchange(&command, &mut out) != Ok(31) || out[..] != reply[..] {
        return TestResult::Fail("initiate-session command did not round-trip");
    }
    if model.delivered() != [(HDCP, bound.client.handle().host_addr, command)] {
        return TestResult::Fail("command went to the wrong client or changed");
    }
    if hdcp::remove(&bound).is_err() {
        return TestResult::Fail("remove failed");
    }
    if registry::lookup(&igpu()).is_some() || model.conn_count() != 0 {
        return TestResult::Fail("remove did not unbind and disconnect");
    }
    let mut buf = [0u8; 4];
    if b.exchange(b"x", &mut buf) != Err(errno::ENODEV) || b.connected() {
        return TestResult::Fail("exchange on an unbound binding not -ENODEV");
    }
    TestResult::Pass
}

fn smoke_mei_hdcp_binds_display() -> TestResult {
    registry::__reset_for_test();
    let r = hdcp_binds_display();
    registry::__reset_for_test();
    r
}
kernel_test_in!("drivers/platform/mei", smoke_mei_hdcp_binds_display);

fn hdcp_refusals() -> TestResult {
    // Meteor Lake HECI: the GSC carries HDCP there; refused before I/O.
    let model = HeciModel::new(32, 32, vec![client()]);
    let Some(dev) = up_as(&model, mei::MEI_DEV_MTL_M) else {
        return TestResult::Fail("bring-up failed");
    };
    if hdcp::probe(&dev).err() != Some(HdcpProbeError::NotHdcpHeci(mei::MEI_DEV_MTL_M)) {
        return TestResult::Fail("HDCP client bound on Meteor Lake's HECI");
    }
    if model.conn_count() != 0 {
        return TestResult::Fail("refused probe still connected");
    }
    // No HDCP client in firmware.
    let model = HeciModel::new(32, 32, vec![ModelClient::new(2, OTHER_UUID, 512)]);
    let Some(dev) = up_as(&model, mei::MEI_DEV_TGP_LP) else {
        return TestResult::Fail("bring-up failed");
    };
    if hdcp::probe(&dev).err() != Some(HdcpProbeError::NoClient) {
        return TestResult::Fail("probe without the client not refused");
    }
    // Refused connect.
    let mut c = client();
    c.connect_status = MEI_HBMS_NOT_ALLOWED;
    let model = HeciModel::new(32, 32, vec![c]);
    let Some(dev) = up_as(&model, mei::MEI_DEV_ADP_S) else {
        return TestResult::Fail("bring-up failed");
    };
    if hdcp::probe(&dev).err() != Some(HdcpProbeError::Enable(errno::EBUSY)) {
        return TestResult::Fail("refused connect not reported as Enable(-EBUSY)");
    }
    if registry::lookup(&igpu()).is_some() {
        return TestResult::Fail("component bound after a refused connect");
    }
    // Device loss unbinds.
    let model = HeciModel::new(32, 32, vec![client()]);
    let Some(dev) = up_as(&model, mei::MEI_DEV_ADP_P) else {
        return TestResult::Fail("bring-up failed");
    };
    if hdcp::probe(&dev).is_err() {
        return TestResult::Fail("probe failed");
    }
    let Some(b) = registry::lookup(&igpu()) else {
        return TestResult::Fail("display did not bind");
    };
    model.set_gone(true);
    let mut buf = [0u8; 4];
    if b.exchange(b"x", &mut buf) != Err(errno::ENODEV) || registry::lookup(&igpu()).is_some() {
        return TestResult::Fail("device loss did not unbind");
    }
    TestResult::Pass
}

fn smoke_mei_hdcp_refusals() -> TestResult {
    registry::__reset_for_test();
    let r = hdcp_refusals();
    registry::__reset_for_test();
    r
}
kernel_test_in!("drivers/platform/mei", smoke_mei_hdcp_refusals);
