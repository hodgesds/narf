//! Native fixtures for the MTL HDMI TMDS PLL layer and route.
extern crate alloc;

use super::*;
use crate::intel_gpu_modeset::PixelFormat;
use crate::intel_gpu_xelpg::tests::FakePhy;
use crate::intel_gpu_xelpg::{
    c10_vdr_cmn, c10_vdr_tx, cx0_vdrovrd_ctl, lane_powerdown_new_state, lane_powerdown_update,
    BOTH_LANES, C20_CONTEXT_TOGGLE, C20_HDMI_RATE_MASK, C20_SERDES_IS_DP, C20_SERDES_RATE_MASK,
    C20_VDR_CUSTOM_SERDES_RATE, C20_VDR_HDMI_RATE, C20_WR_ADDRESS_H, C20_WR_ADDRESS_L,
    DDI_CLOCK_SELECT_MASK, DDI_CLOCK_SELECT_MAXPCLK, P2_STATE_READY, POWERDOWN_NEW_STATE_MASK_BOTH,
    SSC_ENABLE_PLLB,
};
use crate::intel_gpu_xelpg_external::tests::{edid_for, ExtFake, Sink};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn update_writes(fake: &FakePhy, port: XeLpgPort) -> Vec<u32> {
    let update = lane_powerdown_update(0) | lane_powerdown_update(1);
    fake.writes_to(port.buf_ctl2())
        .into_iter()
        .filter(|w| w & update == update)
        .collect()
}

fn smoke_mtl_hdmi_pll_tables_and_typed_refusals() -> TestResult {
    if C10_HDMI_TABLES.len() != 45 || C20_HDMI_TMDS_TABLES.len() != 5 {
        return TestResult::Fail("source HDMI table inventory changed");
    }
    // mtl_c10_hdmi_25_2 verbatim, then intel_c10pll_update_pll zeroes
    // bytes 4..8 (the 0x20 at pll[8] included) for non-SSC HDMI.
    let (clock, raw) = C10_HDMI_TABLES[0];
    if clock != 25_200
        || raw.pll[..3] != [0x04, 0x00, 0xB2]
        || raw.pll[8] != 0x20
        || raw.pll[15..] != [0x0D, 0x06, 0x8F, 0x84, 0x23]
    {
        return TestResult::Fail("mtl_c10_hdmi_25_2 differs from the source");
    }
    match hdmi_pll_request(XeLpgPort::B, 25_200, false) {
        Ok(PllRequest {
            state: Cx0PllState::C10(state),
            lane_count: 4,
            ssc: false,
            hdmi: true,
            protocol_switch: false,
            port_clock_khz: 25_200,
            ..
        }) if state.pll[4..9] == [0; 5] && state.pll[15] == 0x0D => {}
        _ => return TestResult::Fail("C10 HDMI request must be the non-SSC table state"),
    }
    // C20 74.25 MHz: table words plus TMDS VDR; legacy adds the switch.
    for legacy in [false, true] {
        match hdmi_pll_request(XeLpgPort::Tc1, 74_250, legacy) {
            Ok(PllRequest {
                state: Cx0PllState::C20(state, vdr),
                protocol_switch,
                ..
            }) if state.mpllb[0] == 0x609A
                && state.tx[1] == 0x9800
                && vdr == C20Vdr::hdmi_tmds()
                && protocol_switch == legacy => {}
            _ => return TestResult::Fail("C20 HDMI request must carry the table and TMDS VDR"),
        }
    }
    let refusals = [
        (XeLpgPort::B, 300_000, HdmiError::FrlClock(300_000)),
        (
            XeLpgPort::B,
            594_000,
            HdmiError::ScramblingRequired(594_000),
        ),
        (XeLpgPort::B, 123_456, HdmiError::UnsupportedClock(123_456)),
        (XeLpgPort::B, 20_000, HdmiError::UnsupportedClock(20_000)),
        (XeLpgPort::Tc1, 25_200, HdmiError::UnsupportedClock(25_200)),
        (
            XeLpgPort::Tc2,
            594_000,
            HdmiError::ScramblingRequired(594_000),
        ),
    ];
    for (port, clock, error) in refusals {
        if hdmi_pll_request(port, clock, false) != Err(error) {
            return TestResult::Fail("unsupported HDMI clocks must refuse with typed errors");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_pll_tables_and_typed_refusals
);

fn smoke_mtl_hdmi_c10_enable_no_ssc_and_wa_toggle() -> TestResult {
    let fake = FakePhy::new(XeLpgPort::B);
    let request = match hdmi_pll_request(XeLpgPort::B, 148_500, false) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("148.5 MHz must resolve on C10"),
    };
    if enable_port_pll_state(&fake, XeLpgPort::B, &request).is_err() {
        return TestResult::Fail("C10 HDMI PLL enable failed against a healthy PHY");
    }
    let clock = fake.read32(XeLpgPort::B.port_clock_ctl());
    if clock & SSC_ENABLE_PLLB != 0 || clock & DDI_CLOCK_SELECT_MASK != DDI_CLOCK_SELECT_MAXPCLK {
        return TestResult::Fail("HDMI TMDS must select maxPCLK without SSC");
    }
    if fake.writes_to(0x6_4130) != [148_500] {
        return TestResult::Fail("DDI_CLK_VALFREQ(B) must carry the TMDS clock");
    }
    // Lane reset + P2 ready, then the Wa_13013502646 P0 -> P2 toggle.
    let updates = update_writes(&fake, XeLpgPort::B);
    let p2 =
        lane_powerdown_new_state(0, P2_STATE_READY) | lane_powerdown_new_state(1, P2_STATE_READY);
    if updates.len() != 4
        || updates[2] & POWERDOWN_NEW_STATE_MASK_BOTH != 0
        || updates[3] & POWERDOWN_NEW_STATE_MASK_BOTH != p2
    {
        return TestResult::Fail("C10 HDMI must toggle powerdown P0 then P2 after lock");
    }
    // The DP request on the same PHY keeps SSC and has no toggle.
    let dp = FakePhy::new(XeLpgPort::B);
    let request = dp_pll_request_for_test(XeLpgPort::B);
    if enable_port_pll_state(&dp, XeLpgPort::B, &request).is_err()
        || update_writes(&dp, XeLpgPort::B).len() != 2
        || dp.read32(XeLpgPort::B.port_clock_ctl()) & SSC_ENABLE_PLLB == 0
    {
        return TestResult::Fail("DP request must keep SSC and skip the HDMI toggle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_c10_enable_no_ssc_and_wa_toggle
);

fn dp_pll_request_for_test(port: XeLpgPort) -> PllRequest {
    crate::intel_gpu_xelpg::dp_pll_request(
        port,
        crate::intel_gpu_pll::LinkRate::DpHbr2,
        4,
        false,
        false,
    )
    .unwrap()
}

fn smoke_mtl_hdmi_c20_tmds_vdr_and_legacy_protocol_switch() -> TestResult {
    let fake = FakePhy::new(XeLpgPort::Tc1);
    let phy = Cx0Phy::new(&fake, XeLpgPort::Tc1);
    // Inherited DP context: serdes IS_DP | rate 2, a stale HDMI rate.
    if phy
        .write(
            BOTH_LANES,
            C20_VDR_CUSTOM_SERDES_RATE,
            C20_SERDES_IS_DP | (2 << 1),
            true,
        )
        .is_err()
        || phy.write(BOTH_LANES, C20_VDR_HDMI_RATE, 3, true).is_err()
    {
        return TestResult::Fail("seeding the C20 VDR failed");
    }
    let before = fake.msgbus_txns(0).len();
    let request = hdmi_pll_request(XeLpgPort::Tc1, 74_250, true).unwrap();
    if enable_port_pll_state(&fake, XeLpgPort::Tc1, &request).is_err() {
        return TestResult::Fail("C20 HDMI PLL enable failed against a healthy PHY");
    }
    for lane in 0..2u8 {
        let serdes = fake.vdr_get(lane, C20_VDR_CUSTOM_SERDES_RATE);
        if serdes & C20_SERDES_RATE_MASK != 0
            || serdes & C20_CONTEXT_TOGGLE == 0
            || fake.vdr_get(lane, C20_VDR_HDMI_RATE) & C20_HDMI_RATE_MASK != 0
        {
            return TestResult::Fail(
                "TMDS VDR must clear DP bits, set HDMI rate 0, toggle context",
            );
        }
    }
    // Context B received the table's TX cfg1 word.
    let (_, table) = C20_HDMI_TMDS_TABLES[2];
    if fake.sram_get(0xCF2A - 1) != table.tx[1] {
        return TestResult::Fail("C20 HDMI TX context words not written");
    }
    // Legacy protocol switch: MPLLB CAL_DONE banks 0x303D..0x3040 cleared
    // on lane 0 before the context write.
    let txns = fake.msgbus_txns(0);
    for low in 0x3Du8..=0x40 {
        if !txns[before..].contains(&(1, C20_WR_ADDRESS_L, low))
            || !txns[before..].contains(&(1, C20_WR_ADDRESS_H, 0x30))
        {
            return TestResult::Fail("legacy C20 must clear the MPLLB CAL_DONE banks");
        }
    }
    // No HDMI toggle on C20; no switch for a non-legacy DP request.
    if update_writes(&fake, XeLpgPort::Tc1).len() != 2 {
        return TestResult::Fail("C20 HDMI must not run the C10 powerdown toggle");
    }
    let dp = FakePhy::new(XeLpgPort::Tc1);
    if enable_port_pll_state(
        &dp,
        XeLpgPort::Tc1,
        &dp_pll_request_for_test(XeLpgPort::Tc1),
    )
    .is_err()
        || dp.msgbus_txns(0).contains(&(1, C20_WR_ADDRESS_L, 0x3D))
    {
        return TestResult::Fail("non-legacy DP must not clear CAL_DONE banks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_c20_tmds_vdr_and_legacy_protocol_switch
);

fn smoke_mtl_hdmi_tx_levels_c10_c20() -> TestResult {
    let c10 = FakePhy::new(XeLpgPort::B);
    if set_signal_levels_hdmi(&Cx0Phy::new(&c10, XeLpgPort::B)).is_err() {
        return TestResult::Fail("C10 HDMI levels failed");
    }
    for (lane, tx) in [(0u8, 0u16), (0, 1), (1, 0), (1, 1)] {
        if c10.vdr_get(lane, cx0_vdrovrd_ctl(lane as u16, tx, 1)) != 62
            || c10.vdr_get(lane, cx0_vdrovrd_ctl(lane as u16, tx, 0)) != 0
        {
            return TestResult::Fail("C10 HDMI must drive the last DP14 preset on all lanes");
        }
    }
    if c10.vdr_get(0, c10_vdr_cmn(3)) != 5 << 5 || c10.vdr_get(0, c10_vdr_tx(1)) != 6 << 5 {
        return TestResult::Fail("C10 HDMI vboost 5 / termctl 6 not staged");
    }
    let c20 = FakePhy::new(XeLpgPort::Tc2);
    if set_signal_levels_hdmi(&Cx0Phy::new(&c20, XeLpgPort::Tc2)).is_err() {
        return TestResult::Fail("C20 HDMI levels failed");
    }
    if c20.vdr_get(1, cx0_vdrovrd_ctl(1, 1, 1)) != 48 || c20.vdr_get(0, c10_vdr_cmn(3)) != 0 {
        return TestResult::Fail("C20 HDMI must use mtl_c20_trans_hdmi preset 0 only");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_tx_levels_c10_c20
);

fn hdmi_probe_b() -> MtlHdmiProbe {
    let mode = Mode::VESA_1024X768_60;
    MtlHdmiProbe {
        port: XeLpgPort::B,
        tc: None,
        mode,
        pll: hdmi_pll_request(XeLpgPort::B, mode.pixel_clock_khz, false).unwrap(),
        edid: [0; crate::intel_gpu_hdmi::EDID_CAPACITY],
        edid_len: 0,
    }
}

fn hdmi_fb() -> Framebuffer {
    Framebuffer {
        phys_addr: 0x100_0000,
        stride_bytes: 4096,
        format: PixelFormat::Xrgb8888,
    }
}

fn smoke_mtl_hdmi_ddi_b_route_activate_and_stop() -> TestResult {
    let io = ExtFake::new(
        XeLpgPort::B,
        Sink::new(0x14, edid_for(65_000, 1024, 320, 24, 136, 768, 38, 3, 6)),
    );
    let mut route = match activate_hdmi(&io, hdmi_probe_b(), hdmi_fb()) {
        Ok(route) if route.state() == HdmiRouteState::Live => route,
        _ => return TestResult::Fail("DDI B HDMI must light pipe A"),
    };
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, false, false);
    if io.read32(TRANS_DDI_FUNC_CTL_A) != func
        || io.read32(XeLpgPort::B.ddi_buf_ctl()) != DDI_BUF_CTL_ENABLE | (3 << 1)
        || io.read32(XeLpgPort::B.buf_ctl1()) & PORT_WIDTH_MASK != 3 << 1
        || io.read32(TRANS_CLK_SEL_A) != 0x2000_0000
    {
        return TestResult::Fail("HDMI function, DDI width or transcoder clock wrong");
    }
    let dip = Transcoder::A.base() + crate::intel_gpu_hdmi::VIDEO_DIP_CTL_OFFSET;
    if io.read32(dip) & crate::intel_gpu_hdmi::VIDEO_DIP_ENABLE_AVI == 0 {
        return TestResult::Fail("AVI infoframe must be enabled");
    }
    if !io.writes_to(0x6_0540).is_empty() || io.phy.writes_to(0x6_4130) != [65_000] {
        return TestResult::Fail("HDMI must not touch DP_TP_CTL; VALFREQ carries TMDS clock");
    }
    // intel_ddi_enable: transcoder before DDI_CTL_DE.
    let writes = io.writes.borrow();
    let pipe_on = writes
        .iter()
        .position(|&(o, v)| o == PIPECONF_A && v & ENABLE != 0);
    let ddi_on = writes
        .iter()
        .position(|&(o, v)| o == XeLpgPort::B.ddi_buf_ctl() && v & DDI_BUF_CTL_ENABLE != 0);
    match (pipe_on, ddi_on) {
        (Some(a), Some(b)) if a < b => {}
        _ => return TestResult::Fail("HDMI DDI buffer must enable after the transcoder"),
    }
    drop(writes);
    if route.stop(&io).is_err() || route.state() != HdmiRouteState::Stopped {
        return TestResult::Fail("HDMI local stop must be proven");
    }
    if io.read32(dip) & crate::intel_gpu_hdmi::VIDEO_DIP_ENABLE_AVI != 0
        || io.read32(XeLpgPort::B.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
        || io.read32(TRANS_CLK_SEL_A) != 0
        || io.phy.writes_to(0x6_4130).last() != Some(&0)
        || io.read32(PIPECONF_A) & (ENABLE | STATE) != 0
    {
        return TestResult::Fail("HDMI stop must clear infoframes, DDI, clock and PLL");
    }
    if route.release(&io).is_err() {
        return TestResult::Fail("stopped DDI B route must release");
    }
    // A busy pipe refuses before any write and returns the probe.
    let busy = ExtFake::new(XeLpgPort::B, Sink::new(0x14, alloc::vec::Vec::new()));
    busy.phy.write32(PLANE_CTL_1_A, ENABLE);
    match activate_hdmi(&busy, hdmi_probe_b(), hdmi_fb()) {
        Err((Err(_), HdmiError::Route(ExternalError::PipeBusy)))
            if busy.writes.borrow().is_empty() => {}
        _ => return TestResult::Fail("busy pipe must refuse before programming"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_ddi_b_route_activate_and_stop
);

fn smoke_mtl_hdmi_probe_refusals_before_mmio() -> TestResult {
    struct NoAccess;
    impl MmioWindow for NoAccess {
        fn read32(&self, _: u64) -> u32 {
            panic!("refused HDMI probe read");
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("refused HDMI probe write");
        }
    }
    let cases = [
        (
            Generation::TigerLake,
            XeLpgPort::B,
            false,
            HdmiError::Route(ExternalError::UnsupportedGeneration),
        ),
        (
            Generation::MeteorLake,
            XeLpgPort::A,
            false,
            HdmiError::Route(ExternalError::UnsupportedPort),
        ),
        (
            Generation::MeteorLake,
            XeLpgPort::Tc1,
            false,
            HdmiError::NotLegacy,
        ),
        (
            Generation::MeteorLake,
            XeLpgPort::Tc3,
            true,
            HdmiError::DdcUnavailable,
        ),
    ];
    for (generation, port, legacy, error) in cases {
        match probe_hdmi(&NoAccess, generation, port, legacy) {
            Err(e) if e == error => {}
            _ => return TestResult::Fail("HDMI probe refusals must precede MMIO"),
        }
    }
    if ddc_pin(XeLpgPort::B) != Some(PinPair::DdiA) || ddc_pin(XeLpgPort::Tc1).is_some() {
        return TestResult::Fail("MTP DDC pin 2 (dpb) must be the only mapped pin");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_probe_refusals_before_mmio
);
