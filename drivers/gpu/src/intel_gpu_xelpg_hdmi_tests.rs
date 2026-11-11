//! Native fixtures for the MTL HDMI TMDS PLL layer and route.
extern crate alloc;

use super::*;
use crate::intel_gpu_gmbus::tests::FakeGmbus;
use crate::intel_gpu_modeset::PixelFormat;
use crate::intel_gpu_pipes::{Transcoder, PIPECONF_ENABLE as ENABLE, PIPECONF_STATE as STATE};
use crate::intel_gpu_xelpg::tests::FakePhy;
use crate::intel_gpu_xelpg::{
    c10_vdr_cmn, c10_vdr_tx, cx0_vdrovrd_ctl, lane_powerdown_new_state, lane_powerdown_update,
    BOTH_LANES, C20_CONTEXT_TOGGLE, C20_HDMI_RATE_MASK, C20_SERDES_IS_DP, C20_SERDES_RATE_MASK,
    C20_VDR_CUSTOM_SERDES_RATE, C20_VDR_HDMI_RATE, C20_WR_ADDRESS_H, C20_WR_ADDRESS_L,
    DDI_CLOCK_SELECT_MASK, DDI_CLOCK_SELECT_MAXPCLK, P2_STATE_READY, POWERDOWN_NEW_STATE_MASK_BOTH,
    SSC_ENABLE_PLLB,
};
use crate::intel_gpu_xelpg_external::tests::{
    edid_for, ExtFake, Sink, PIPECONF_B, PLANE_CTL_1_A, TRANS_CLK_SEL_B, TRANS_DDI_FUNC_CTL_B,
};
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
    // Above 340 MHz the PLL resolves from the source tables (C10
    // mtl_c10_hdmi_594, C20 TMDS 594 MHz); whether the sink can take it is
    // the scrambling decision (tmds_link), tested separately.
    for port in [XeLpgPort::B, XeLpgPort::Tc2] {
        match hdmi_pll_request(port, 594_000, false) {
            Ok(PllRequest {
                port_clock_khz: 594_000,
                hdmi: true,
                ..
            }) => {}
            _ => return TestResult::Fail("594 MHz TMDS must resolve on C10 and C20"),
        }
    }
    let refusals = [
        (XeLpgPort::B, 300_000, HdmiError::FrlClock(300_000)),
        (XeLpgPort::B, 600_000, HdmiError::FrlClock(600_000)),
        (XeLpgPort::B, 650_000, HdmiError::UnsupportedClock(650_000)),
        (XeLpgPort::B, 123_456, HdmiError::UnsupportedClock(123_456)),
        (XeLpgPort::B, 20_000, HdmiError::UnsupportedClock(20_000)),
        (XeLpgPort::Tc1, 25_200, HdmiError::UnsupportedClock(25_200)),
        (
            XeLpgPort::Tc2,
            497_750,
            HdmiError::UnsupportedClock(497_750),
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
        true,
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
        sink: SinkScdc::default(),
        link: TmdsLink::default(),
        ddc: PinPair::Pin2Bxt,
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
    let mut route = match activate_hdmi(&io, hdmi_probe_b(), hdmi_fb(), &MtlDisplay::NONE) {
        Ok(route) if route.state() == HdmiRouteState::Live => route,
        _ => return TestResult::Fail("DDI B HDMI must light Pipe B"),
    };
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, false, false);
    if io.read32(TRANS_DDI_FUNC_CTL_B) != func
        || io.read32(XeLpgPort::B.ddi_buf_ctl()) != DDI_BUF_CTL_ENABLE | (3 << 1)
        || io.read32(XeLpgPort::B.buf_ctl1()) & PORT_WIDTH_MASK != 3 << 1
        || io.read32(TRANS_CLK_SEL_B) != 0x2000_0000
    {
        return TestResult::Fail("HDMI function, DDI width or transcoder clock wrong");
    }
    let dip = Transcoder::B.base() + crate::intel_gpu_hdmi::VIDEO_DIP_CTL_OFFSET;
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
        .position(|&(o, v)| o == PIPECONF_B && v & ENABLE != 0);
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
        || io.read32(TRANS_CLK_SEL_B) != 0
        || io.phy.writes_to(0x6_4130).last() != Some(&0)
        || io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
    {
        return TestResult::Fail("HDMI stop must clear infoframes, DDI, clock and PLL");
    }
    if route.release(&io).is_err() {
        return TestResult::Fail("stopped DDI B route must release");
    }
    // A foreign fetcher on a dark Pipe A refuses before any write and
    // returns the probe. It is now the Pipe B–D owner's admission (every
    // pipe the all-off commit reprograms must be idle) that refuses, with
    // its typed Busy, rather than the old "pipe A busy" preflight: the
    // route no longer takes Pipe A, but its resource transaction would
    // repartition it.
    let busy = ExtFake::new(XeLpgPort::B, Sink::new(0x14, alloc::vec::Vec::new()));
    busy.phy.write32(PLANE_CTL_1_A, ENABLE);
    match activate_hdmi(&busy, hdmi_probe_b(), hdmi_fb(), &MtlDisplay::NONE) {
        Err((Err(_), HdmiError::Route(ExternalError::Pipe(PipeRefusal::Busy))))
            if busy.writes.borrow().is_empty() => {}
        _ => return TestResult::Fail("busy pipe must refuse before programming"),
    }
    // A lit Pipe A that is not the owned panel profile refuses PipeBusy.
    let lit = ExtFake::new(XeLpgPort::B, Sink::new(0x14, alloc::vec::Vec::new()));
    lit.set_conf(0, ENABLE);
    match activate_hdmi(&lit, hdmi_probe_b(), hdmi_fb(), &MtlDisplay::NONE) {
        Err((Err(_), HdmiError::Route(ExternalError::PipeBusy)))
            if lit.writes.borrow().is_empty() => {}
        _ => return TestResult::Fail("an unowned lit Pipe A must refuse before programming"),
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
    ];
    for (generation, port, legacy, error) in cases {
        match probe_hdmi(&NoAccess, generation, port, legacy, ddc_pin(port)) {
            Err(e) if e == error => {}
            _ => return TestResult::Fail("HDMI probe refusals must precede MMIO"),
        }
    }
    // Corrected GMBUS numbering (Linux b90c984d): DDI B = GMBUS_PIN_2_BXT
    // ("dpb"), TCn = GMBUS_PIN_9_TC1_ICP + n - 1, all in gmbus_pins_mtp.
    // The Type-C DDC refusal is lifted now the pins are expressible.
    let pins = [
        (XeLpgPort::B, 2u32, "dpb"),
        (XeLpgPort::Tc1, 9, "tc1"),
        (XeLpgPort::Tc2, 10, "tc2"),
        (XeLpgPort::Tc3, 11, "tc3"),
        (XeLpgPort::Tc4, 12, "tc4"),
    ];
    for (port, pin, name) in pins {
        match ddc_pin(port) {
            Some(p)
                if p.encode() == pin
                    && crate::intel_gpu_gmbus::GmbusPinTable::Mtp.name(p) == Some(name) => {}
            _ => return TestResult::Fail("MTL DDC pin differs from gmbus_pins_mtp"),
        }
    }
    if ddc_pin(XeLpgPort::A).is_some() {
        return TestResult::Fail("internal DDI A has no external DDC pin");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_probe_refusals_before_mmio
);

// ── HDMI 2.0 scrambling + SCDC ─────────────────────────────────────

/// `base` (one block) plus a CTA-861 revision 3 extension whose data
/// block collection is `blocks`, both with valid checksums.
fn edid_with_cta(mut base: Vec<u8>, blocks: &[u8]) -> Vec<u8> {
    fn checksum(block: &mut [u8]) {
        let sum: u32 = block[..127].iter().map(|&b| b as u32).sum();
        block[127] = ((256 - sum % 256) % 256) as u8;
    }
    base[126] = 1;
    checksum(&mut base[..128]);
    let mut ext = alloc::vec![0u8; 128];
    ext[0] = 0x02;
    ext[1] = 0x03;
    ext[2] = (4 + blocks.len()) as u8;
    ext[4..4 + blocks.len()].copy_from_slice(blocks);
    checksum(&mut ext);
    base.extend_from_slice(&ext);
    base
}

/// HF-VSDB (`cea_db_is_hdmi_forum_vsdb`): vendor tag 3, payload 7, the
/// HDMI Forum OUI LSB first, version 1, rate (×5 MHz), flags.
fn hf_vsdb(rate: u8, flags: u8) -> [u8; 8] {
    [(3 << 5) | 7, 0xD8, 0x5D, 0xC4, 1, rate, flags, 0]
}

/// HF-SCDB (`cea_db_is_hdmi_forum_scdb`): extended tag 7 / 0x79.
fn hf_scdb(rate: u8, flags: u8) -> [u8; 8] {
    [(7 << 5) | 7, 0x79, 0, 0, 1, rate, flags, 0]
}

fn edid_4k60() -> Vec<u8> {
    edid_for(594_000, 3840, 560, 176, 88, 2160, 90, 8, 10)
}

fn edid_1080p() -> Vec<u8> {
    edid_for(148_500, 1920, 280, 88, 44, 1080, 45, 4, 5)
}

fn smoke_mtl_hdmi_sink_scdc_parse_and_tmds_link() -> TestResult {
    let full = SinkScdc {
        scdc: true,
        scrambling: true,
        low_rates: false,
        max_tmds_clock_khz: 600_000,
    };
    // drm_parse_hdmi_forum_scds over HF-VSDB and HF-SCDB alike.
    for block in [hf_vsdb(120, 0x80), hf_scdb(120, 0x80)] {
        if parse_sink_scdc(&edid_with_cta(edid_4k60(), &block)) != full {
            return TestResult::Fail("HF-VSDB/HF-SCDB must declare SCDC scrambling to 600 MHz");
        }
    }
    let low = parse_sink_scdc(&edid_with_cta(edid_4k60(), &hf_vsdb(120, 0x88)));
    let no_rate = parse_sink_scdc(&edid_with_cta(edid_4k60(), &hf_vsdb(0, 0x80)));
    let rate_300 = parse_sink_scdc(&edid_with_cta(edid_4k60(), &hf_vsdb(60, 0x80)));
    let no_scdc = parse_sink_scdc(&edid_with_cta(edid_4k60(), &hf_vsdb(120, 0x08)));
    if !low.low_rates
        || no_rate
            != (SinkScdc {
                scdc: true,
                ..SinkScdc::default()
            })
        || !rate_300.scrambling
        || rate_300.max_tmds_clock_khz != 0
        || no_scdc
            != (SinkScdc {
                max_tmds_clock_khz: 600_000,
                ..SinkScdc::default()
            })
    {
        return TestResult::Fail("HF block fields must decode as drm_edid does");
    }
    // Not HDMI Forum data: short payload, bad checksum, CTA rev 2, d = 0,
    // another vendor's OUI, no extension at all.
    let mut short = hf_vsdb(120, 0x80);
    short[0] = (3 << 5) | 6;
    let mut bad_sum = edid_with_cta(edid_4k60(), &hf_vsdb(120, 0x80));
    bad_sum[200] ^= 1;
    let mut rev2 = edid_with_cta(edid_4k60(), &hf_vsdb(120, 0x80));
    rev2[129] = 2;
    rev2[255] = rev2[255].wrapping_add(1);
    let mut d0 = edid_with_cta(edid_4k60(), &hf_vsdb(120, 0x80));
    d0[130] = 0;
    d0[255] = d0[255].wrapping_add(12);
    let mut other_oui = hf_vsdb(120, 0x80);
    other_oui[1] = 0x03;
    for edid in [
        edid_with_cta(edid_4k60(), &short[..7]),
        bad_sum,
        rev2,
        d0,
        edid_with_cta(edid_4k60(), &other_oui),
        edid_4k60(),
    ] {
        if parse_sink_scdc(&edid) != SinkScdc::default() {
            return TestResult::Fail("non-HDMI-Forum data must declare nothing");
        }
    }
    // intel_hdmi_compute_config.
    let both = TmdsLink {
        scrambling: true,
        high_tmds_clock_ratio: true,
    };
    let scramble_only = TmdsLink {
        scrambling: true,
        high_tmds_clock_ratio: false,
    };
    let narrow = SinkScdc {
        max_tmds_clock_khz: 550_000,
        ..full
    };
    if tmds_link(594_000, &full) != Ok(both)
        || tmds_link(148_500, &full) != Ok(TmdsLink::default())
        || tmds_link(148_500, &low) != Ok(scramble_only)
        || tmds_link(148_500, &SinkScdc::default()) != Ok(TmdsLink::default())
        || tmds_link(594_000, &SinkScdc::default()) != Err(HdmiError::ScramblingRequired(594_000))
        || tmds_link(594_000, &no_scdc) != Err(HdmiError::ScramblingRequired(594_000))
        || tmds_link(594_000, &rate_300)
            != Err(HdmiError::SinkClockLimit {
                clock_khz: 594_000,
                max_khz: 0,
            })
        || tmds_link(594_000, &narrow)
            != Err(HdmiError::SinkClockLimit {
                clock_khz: 594_000,
                max_khz: 550_000,
            })
    {
        return TestResult::Fail("scrambling decision differs from intel_hdmi_compute_config");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_sink_scdc_parse_and_tmds_link
);

/// DDI B with `edid` on DDC pin 2 and an SCDC slave.
fn ddi_b_hdmi_sink(edid: &[u8]) -> ExtFake {
    let mut io = ExtFake::new(XeLpgPort::B, Sink::new(0x14, alloc::vec::Vec::new()));
    io.ddc = FakeGmbus::with_edid(edid);
    io.ddc.set_pin(2);
    io.ddc.set_scdc_present(true);
    io
}

/// GMBUS3 preloads of SCDC writes: `offset | value << 8`.
fn scdc_writes(io: &ExtFake) -> Vec<u32> {
    let writes = io.writes.borrow();
    let mut out = Vec::new();
    for (i, &(off, v)) in writes.iter().enumerate() {
        let next_is_scdc_write = writes[i + 1..].first().is_some_and(|&(o, p)| {
            o == crate::intel_gpu_gmbus::GMBUS1 && (p >> 1) & 0x7F == 0x54 && p & 1 == 0
        });
        if off == crate::intel_gpu_gmbus::GMBUS3 && next_is_scdc_write {
            out.push(v & 0xFFFF);
        }
    }
    out
}

fn position(io: &ExtFake, f: impl Fn(u64, u32) -> bool) -> Option<usize> {
    io.writes.borrow().iter().position(|&(o, v)| f(o, v))
}

fn smoke_mtl_routes_leave_stack_for_resource_planning() -> TestResult {
    // These values also live in activation results and error paths. Keep
    // repeated route temporaries small enough to leave planner scratch room
    // on ARM's 64 KiB bootstrap stack. The 4K60 lifecycle below exercises the
    // complete call chain; inline resource snapshots copied through owners
    // and results made it overflow that stack.
    if core::mem::size_of::<MtlHdmiRoute>() > 2048
        || core::mem::size_of::<crate::intel_gpu_xelpg_external::MtlExternalRoute>() > 2048
        || core::mem::size_of::<crate::intel_gpu_xelpg_pipes::Pipes>() > 512
    {
        return TestResult::Fail("route values must leave room for resource planner scratch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_routes_leave_stack_for_resource_planning
);

fn smoke_mtl_hdmi_594_scrambled_route_scdc_order_and_reset() -> TestResult {
    let io = ddi_b_hdmi_sink(&edid_with_cta(edid_4k60(), &hf_vsdb(120, 0x80)));
    let probe = match probe_hdmi(
        &io,
        Generation::MeteorLake,
        XeLpgPort::B,
        false,
        ddc_pin(XeLpgPort::B),
    ) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("4K60 HF-VSDB sink must probe"),
    };
    if probe.mode.pixel_clock_khz != 594_000
        || probe.link
            != (TmdsLink {
                scrambling: true,
                high_tmds_clock_ratio: true,
            })
        || !probe.sink.scrambling
    {
        return TestResult::Fail("594 MHz mode must plan scrambling and the 1/40 ratio");
    }
    let fb = Framebuffer {
        phys_addr: 0x100_0000,
        stride_bytes: 3840 * 4,
        format: PixelFormat::Xrgb8888,
    };
    let mut route = match activate_hdmi(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == HdmiRouteState::Live => route,
        _ => return TestResult::Fail("scrambled 594 MHz HDMI must light Pipe B"),
    };
    let func = crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, true, true);
    if io.read32(TRANS_DDI_FUNC_CTL_B) != func
        || func & (1 << 4 | 1) != (1 << 4 | 1)
        || io.phy.writes_to(0x6_4130) != [594_000]
        || io.ddc.scdc_at(SCDC_TMDS_CONFIG)
            != SCDC_TMDS_BIT_CLOCK_RATIO_BY_40 | SCDC_SCRAMBLING_ENABLE
    {
        return TestResult::Fail("TRANS_DDI_FUNC_CTL and the sink must both scramble at 1/40");
    }
    // drm_scdc_set_high_tmds_clock_ratio, then drm_scdc_set_scrambling,
    // after the transcoder is on and before the DDI buffer
    // (intel_ddi_enable -> intel_ddi_enable_hdmi).
    if scdc_writes(&io) != [0x0220, 0x0320] {
        return TestResult::Fail("SCDC must set the ratio first, then scrambling");
    }
    let pipe_on = position(&io, |o, v| o == PIPECONF_B && v & ENABLE != 0);
    let scdc = position(&io, |o, v| {
        o == crate::intel_gpu_gmbus::GMBUS1 && (v >> 1) & 0x7F == 0x54
    });
    let ddi_on = position(&io, |o, v| {
        o == XeLpgPort::B.ddi_buf_ctl() && v & DDI_BUF_CTL_ENABLE != 0
    });
    match (pipe_on, scdc, ddi_on) {
        (Some(a), Some(b), Some(c)) if a < b && b < c => {}
        _ => return TestResult::Fail("SCDC must run between transcoder and DDI enable"),
    }
    // intel_ddi_disable_hdmi: reset ratio and scrambling before the
    // transcoder goes down; the stop is still proven.
    let before = io.writes.borrow().len();
    if route.stop(&io).is_err() || route.state() != HdmiRouteState::Stopped {
        return TestResult::Fail("scrambled route must stop");
    }
    let reset = position(&io, |o, v| {
        o == crate::intel_gpu_gmbus::GMBUS1 && (v >> 1) & 0x7F == 0x54
    });
    let resets = scdc_writes(&io);
    let pipe_off = io
        .writes
        .borrow()
        .iter()
        .enumerate()
        .skip(before)
        .position(|(_, &(o, v))| o == PIPECONF_B && v & ENABLE == 0)
        .map(|p| p + before);
    let last_scdc = io
        .writes
        .borrow()
        .iter()
        .rposition(|&(o, v)| o == crate::intel_gpu_gmbus::GMBUS1 && (v >> 1) & 0x7F == 0x54);
    if reset.is_none()
        || resets != [0x0220, 0x0320, 0x0120, 0x0020]
        || io.ddc.scdc_at(SCDC_TMDS_CONFIG) != 0
        || !matches!((last_scdc, pipe_off), (Some(s), Some(p)) if s < p)
    {
        return TestResult::Fail("stop must reset ratio then scrambling before the pipe");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_594_scrambled_route_scdc_order_and_reset
);

fn smoke_mtl_hdmi_scdc_low_rates_reset_and_failures() -> TestResult {
    // <=340 MHz on a scrambling-capable sink: Linux still writes SCDC,
    // clearing a stale ratio/scrambling; the source does not scramble.
    let io = ddi_b_hdmi_sink(&edid_with_cta(edid_1080p(), &hf_vsdb(120, 0x80)));
    io.ddc.set_scdc(SCDC_TMDS_CONFIG, 0x03);
    let probe = match probe_hdmi(
        &io,
        Generation::MeteorLake,
        XeLpgPort::B,
        false,
        ddc_pin(XeLpgPort::B),
    ) {
        Ok(p) if p.link == TmdsLink::default() => p,
        _ => return TestResult::Fail("1080p on an HDMI 2.0 sink must not scramble"),
    };
    let fb = Framebuffer {
        phys_addr: 0x100_0000,
        stride_bytes: 1920 * 4,
        format: PixelFormat::Xrgb8888,
    };
    match activate_hdmi(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == HdmiRouteState::Live => {}
        _ => return TestResult::Fail("1080p HDMI route must light"),
    }
    if io.ddc.scdc_at(SCDC_TMDS_CONFIG) != 0
        || io.read32(TRANS_DDI_FUNC_CTL_B)
            != crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, false, false)
    {
        return TestResult::Fail("stale sink scrambling must be cleared at 1/10");
    }
    // LTE_340Mcsc_Scramble: scramble at 148.5 MHz without the 1/40 ratio.
    let io = ddi_b_hdmi_sink(&edid_with_cta(edid_1080p(), &hf_vsdb(120, 0x88)));
    let probe = match probe_hdmi(
        &io,
        Generation::MeteorLake,
        XeLpgPort::B,
        false,
        ddc_pin(XeLpgPort::B),
    ) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("low-rate scrambling sink must probe"),
    };
    match activate_hdmi(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) if route.state() == HdmiRouteState::Live => {}
        _ => return TestResult::Fail("low-rate scrambled route must light"),
    }
    if io.ddc.scdc_at(SCDC_TMDS_CONFIG) != SCDC_SCRAMBLING_ENABLE
        || io.read32(TRANS_DDI_FUNC_CTL_B)
            != crate::intel_gpu_pipes::build_trans_ddi_func_ctl_hdmi(1, true, false)
    {
        return TestResult::Fail("low-rate scrambling must set bit 0 only, both sides");
    }
    // A 594 MHz mode the sink cannot scramble is refused at the probe.
    let io = ddi_b_hdmi_sink(&edid_4k60());
    if probe_hdmi(
        &io,
        Generation::MeteorLake,
        XeLpgPort::B,
        false,
        ddc_pin(XeLpgPort::B),
    )
    .err()
        != Some(HdmiError::ScramblingRequired(594_000))
    {
        return TestResult::Fail("594 MHz without HF-VSDB must refuse");
    }
    // The SCDC slave vanishes after the probe: the scrambled stream cannot
    // work, activation fails, the local stop is still proven.
    let io = ddi_b_hdmi_sink(&edid_with_cta(edid_4k60(), &hf_vsdb(120, 0x80)));
    let probe = match probe_hdmi(
        &io,
        Generation::MeteorLake,
        XeLpgPort::B,
        false,
        ddc_pin(XeLpgPort::B),
    ) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("4K probe must succeed"),
    };
    io.ddc.set_scdc_present(false);
    let fb = Framebuffer {
        phys_addr: 0x100_0000,
        stride_bytes: 3840 * 4,
        format: PixelFormat::Xrgb8888,
    };
    match activate_hdmi(&io, probe, fb, &MtlDisplay::NONE) {
        Err((Ok(route), HdmiError::Scdc(_))) if route.state() == HdmiRouteState::Stopped => {
            if route.release(&io).is_err()
                || io.read32(XeLpgPort::B.ddi_buf_ctl()) & DDI_BUF_CTL_ENABLE != 0
                || io.read32(PIPECONF_B) & (ENABLE | STATE) != 0
            {
                return TestResult::Fail("failed SCDC activation must leave DDI B stopped");
            }
        }
        _ => return TestResult::Fail("lost SCDC must fail a scrambled activation"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hdmi",
    smoke_mtl_hdmi_scdc_low_rates_reset_and_failures
);
