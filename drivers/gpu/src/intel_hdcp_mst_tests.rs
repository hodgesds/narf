//! HDCP over DP MST fixtures (`intel_dp_mst_hdcp_shim`'s stream side and
//! the multi-stream paths of `intel_hdcp.c`), on the register, sink and
//! firmware models of `intel_hdcp_tests.rs`.

use super::*;
use crate::intel_hdcp::mst::{
    hdcp_status_stream_enc, trans_hdcp2_stream_status, MstHdcp, STREAM_ENCRYPTION_STATUS,
    TRANS_DDI_HDCP_SELECT,
};

/// An MST branch device as an HDCP 2.2 repeater over DP: the receiver ID
/// list (RxInfo DEV_COUNT 1, no HDCP 1.x or 2.0 device, seq_num_v 0, V',
/// KSV0) announced by RxStatus READY, and M' for stream management.
fn mst_branch(d: &Hdcp2Data) -> DpSink {
    let mut s = DpSink::hdcp22(d);
    s.rx_status |= 1;
    s.put(shim::DP_HDCP_2_2_REG_RXINFO_OFFSET, &[0x00, 0x10]);
    let mut list = vec![0, 0, 0];
    list.extend(&d.vprime);
    list.extend(KSV0);
    s.put(shim::DP_HDCP_2_2_REG_RXINFO_OFFSET + 2, &list);
    s.put(shim::DP_HDCP_2_2_REG_MPRIME_OFFSET, &d.mprime);
    s
}

/// The write index of the last write of `value & mask == want` to `reg`.
fn last_write(regs: &Regs, reg: u64, mask: u32, want: u32) -> Option<usize> {
    regs.0
        .lock()
        .writes
        .iter()
        .rposition(|&(r, v)| r == reg && v & mask == want)
}

/// Two MST streams on transcoders B (the master) and C, payload IDs 2 and
/// 3, over an HDCP 2.2 branch with the MEI firmware model:
/// - one port authentication (`auth_status`), RepeaterAuth_Stream_Manage
///   with k = 2, both streams type 1 because the topology is type-1
///   capable (`intel_hdcp_required_content_stream`), enable_auth with
///   stream 0's type;
/// - link encryption on the master's TRANS_HDCP2_CTL only, each stream
///   by TRANS_DDI_HDCP_SELECT in its own TRANS_DDI_FUNC_CTL, confirmed in
///   its TRANS_HDCP2_STREAM_STATUS (`intel_dp_mst_hdcp2_stream_encryption`);
/// - the link check reads RxStatus for the authenticating stream only
///   (`intel_dp_mst_hdcp2_check_link`);
/// - the disable drops stream C's select with the link still encrypted
///   (`num_streams`), then stream B's with the link, then closes the
///   session.
fn hdcp22_mst_two_streams() -> TestResult {
    let regs = Regs::new(1);
    let d = Hdcp2Data::new(true);
    let mut s = DpShim::new(mst_branch(&d));
    let mut fw = FwModel::new(&regs, 1, msg::HDCP_PROTOCOL_DP, Hdcp2Data::new(true));
    fw.mst_streams = Some(vec![(2, 1), (3, 1)]);
    let mut env = Env::default();
    let mut hdcp = MstHdcp::new(1, &[(1, 2), (2, 3)], LineRekey::None, true);
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: Some(&mut fw),
            env: &mut env,
        };
        drive(hdcp.enable(&mut cx, 0))
    };
    if let Some(bad) = fw.bad {
        return TestResult::Fail(bad);
    }
    if r != Some(Ok(()))
        || hdcp.value() != CpValue::Enabled
        || !hdcp.streams.iter().all(|st| st.hdcp2_encrypted())
        || hdcp.link.num_streams != 2
        || !hdcp.link.auth_status
    {
        return TestResult::Fail("two-stream HDCP 2.2 enable failed");
    }
    // AKE, LC, SKE, the receiver ID list, stream management, port auth:
    // once for the port.
    let want = [
        0x0003_1000,
        0x0003_1001,
        0x0003_1002,
        0x0003_1003,
        0x0003_1004,
        0x0003_1005,
        0x0003_1006,
        0x0003_1008,
        0x0003_1009,
        0x0003_1007,
    ];
    if fw.log != want {
        return TestResult::Fail("port authentication not once with both streams managed");
    }
    // RepeaterAuth_Stream_Manage on the DPCD (no message ID): seq_num_m 0,
    // k = 2, {2, type 1}, {3, type 1}.
    if s.dpcd.got(shim::DP_HDCP_2_2_REG_SEQ_NUM_M_OFFSET, 9) != [0, 0, 0, 0, 2, 2, 1, 3, 1] {
        return TestResult::Fail("RepeaterAuth_Stream_Manage contents");
    }
    if regs.get(trans_hdcp2_ctl(1)) & CTL_LINK_ENCRYPTION_REQ == 0
        || !regs.wrote(trans_hdcp2_ctl(2)).is_empty()
    {
        return TestResult::Fail("link encryption not on the master transcoder alone");
    }
    for t in [1, 2] {
        if regs.get(trans_ddi_func_ctl(t)) & TRANS_DDI_HDCP_SELECT == 0
            || regs.read32(trans_hdcp2_stream_status(t)) & STREAM_ENCRYPTION_STATUS == 0
        {
            return TestResult::Fail("stream HDCP select / stream encryption");
        }
    }
    // The branch's list was read; the link check reads RxStatus once (the
    // authenticating stream), and the link stays protected.
    s.dpcd.rx_status &= !1;
    let before = s
        .dpcd
        .reads
        .iter()
        .filter(|&&a| a == shim::DP_HDCP_2_2_REG_RXSTATUS_OFFSET)
        .count();
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: Some(&mut fw),
            env: &mut env,
        };
        drive(hdcp.check_link(&mut cx))
    };
    let after = s
        .dpcd
        .reads
        .iter()
        .filter(|&&a| a == shim::DP_HDCP_2_2_REG_RXSTATUS_OFFSET)
        .count();
    if r != Some(Ok(())) || after != before + 1 || hdcp.value() != CpValue::Enabled {
        return TestResult::Fail("MST link check");
    }
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: Some(&mut fw),
            env: &mut env,
        };
        drive(hdcp.disable(&mut cx))
    };
    let c_off = last_write(&regs, trans_ddi_func_ctl(2), TRANS_DDI_HDCP_SELECT, 0);
    let b_off = last_write(&regs, trans_ddi_func_ctl(1), TRANS_DDI_HDCP_SELECT, 0);
    let link_off = last_write(&regs, trans_hdcp2_ctl(1), CTL_LINK_ENCRYPTION_REQ, 0);
    if r != Some(Ok(()))
        || hdcp.value() != CpValue::Undesired
        || hdcp.link.num_streams != 0
        || hdcp.link.auth_status
        || !(c_off < b_off && b_off < link_off && c_off.is_some())
        || fw.log.last() != Some(&0x0003_100a)
        || fw.log.iter().filter(|&&c| c == 0x0003_100a).count() != 1
    {
        return TestResult::Fail("MST disable order or session close");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp22_mst_two_streams() -> TestResult {
    hdcp22_mst_two_streams()
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp22_mst_two_streams);

/// A stream whose encryption never confirms (`-ETIMEDOUT` from
/// `intel_dp_mst_hdcp2_stream_encryption`) fails the enable and takes the
/// stream already enabled back down: no stream select, no link encryption
/// and no firmware session are left, and the connector is not ENABLED.
fn hdcp22_mst_stream_failure() -> TestResult {
    let regs = Regs::new(1);
    regs.0.lock().stuck_stream = Some(2);
    let d = Hdcp2Data::new(true);
    let mut s = DpShim::new(mst_branch(&d));
    let mut fw = FwModel::new(&regs, 1, msg::HDCP_PROTOCOL_DP, Hdcp2Data::new(true));
    fw.mst_streams = Some(vec![(2, 1), (3, 1)]);
    let mut env = Env::default();
    let mut hdcp = MstHdcp::new(1, &[(1, 2), (2, 3)], LineRekey::None, true);
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: Some(&mut fw),
            env: &mut env,
        };
        drive(hdcp.enable(&mut cx, 0))
    };
    if r != Some(Err(HdcpError::Timeout))
        || hdcp.value() == CpValue::Enabled
        || hdcp.streams.iter().any(|st| st.value() == CpValue::Enabled)
        || hdcp.link.num_streams != 0
        || regs.get(trans_ddi_func_ctl(1)) & TRANS_DDI_HDCP_SELECT != 0
        || regs.get(trans_ddi_func_ctl(2)) & TRANS_DDI_HDCP_SELECT != 0
        || regs.get(trans_hdcp2_ctl(1)) & CTL_LINK_ENCRYPTION_REQ != 0
        || fw.log.last() != Some(&0x0003_100a)
    {
        return TestResult::Fail("a failed stream left the route partly protected");
    }
    // The second stream never tried HDCP 1.4 under the HDCP 2.2 link.
    if !regs.wrote(trans_hdcp_conf(1)).is_empty() {
        return TestResult::Fail("HDCP 1.4 attempted under an HDCP 2.2 port");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp22_mst_stream_failure() -> TestResult {
    hdcp22_mst_stream_failure()
}
kernel_test_in!(
    "drivers/gpu/intel_hdcp",
    smoke_intel_hdcp22_mst_stream_failure
);

/// HDCP 1.4 over MST (`intel_dp_mst_hdcp_stream_encryption`): part 1 on
/// the master transcoder for each stream's connector, then that stream's
/// select, confirmed by its HDCP_STATUS_STREAM_x_ENC bit in its own
/// transcoder's HDCP_STATUS; the disable keeps the link while a stream
/// stays ENABLED.
fn hdcp14_mst_two_streams() -> TestResult {
    let regs = Regs::new(1);
    let mut s = DpShim::new(DpSink::hdcp14(false));
    let mut env = Env::default();
    let mut hdcp = MstHdcp::new(1, &[(1, 2), (2, 3)], LineRekey::None, true);
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: None::<&mut FwModel>,
            env: &mut env,
        };
        drive(hdcp.enable(&mut cx, 0))
    };
    if r != Some(Ok(()))
        || hdcp.value() != CpValue::Enabled
        || !hdcp.streams.iter().all(|st| st.hdcp_encrypted())
    {
        return TestResult::Fail("two-stream HDCP 1.4 enable failed");
    }
    if !regs.wrote(trans_hdcp_conf(2)).is_empty()
        || regs.read32(trans_hdcp_status(1)) & hdcp_status_stream_enc(1) == 0
        || regs.read32(trans_hdcp_status(2)) & hdcp_status_stream_enc(2) == 0
    {
        return TestResult::Fail("HDCP 1.4 stream encryption status");
    }
    if hdcp_status_stream_enc(0) != 1 << 31 || hdcp_status_stream_enc(3) != 1 << 28 {
        return TestResult::Fail("HDCP_STATUS_STREAM_x_ENC bits");
    }
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: None::<&mut FwModel>,
            env: &mut env,
        };
        drive(hdcp.disable(&mut cx))
    };
    let c_off = last_write(&regs, trans_ddi_func_ctl(2), TRANS_DDI_HDCP_SELECT, 0);
    let conf_off = last_write(&regs, trans_hdcp_conf(1), !0, 0);
    if r != Some(Ok(()))
        || hdcp.value() != CpValue::Undesired
        || !(c_off.is_some() && c_off < conf_off)
        || regs.get(trans_hdcp_conf(1)) != 0
    {
        return TestResult::Fail("HDCP 1.4 MST disable");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp14_mst_two_streams() -> TestResult {
    hdcp14_mst_two_streams()
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp14_mst_two_streams);

/// The registers of the MST stream side (`intel_hdcp_regs.h`,
/// `intel_display_regs.h`) and the live route's stream list.
fn smoke_intel_hdcp_mst_layouts() -> TestResult {
    if TRANS_DDI_HDCP_SELECT != 1 << 5
        || trans_hdcp2_stream_status(0) != 0x664c0
        || trans_hdcp2_stream_status(1) != 0x665c0
        || mst::trans_hdcp2_auth_stream(0) != 0x66f00
        || mst::trans_hdcp2_auth_stream(1) != 0x66f04
        || STREAM_ENCRYPTION_STATUS != 1 << 31
        || mst::STREAM_TYPE_STATUS != 1 << 30
        || mst::AUTH_STREAM_TYPE != 1 << 31
        || hdcp_status_stream_enc(4) != 0
    {
        return TestResult::Fail("MST HDCP register layout");
    }
    // A port manages at most four streams, on transcoders A–D.
    let five = [(0, 1), (1, 2), (2, 3), (3, 4), (0, 5)];
    if live::MstStreams::new(&five).is_some()
        || live::MstStreams::new(&[(4, 1)]).is_some()
        || live::MstStreams::new(&[(1, 2), (2, 3)]).map(|m| m.as_slice().to_vec())
            != Some(vec![(1, 2), (2, 3)])
    {
        return TestResult::Fail("MST stream list bounds");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp_mst_layouts);
