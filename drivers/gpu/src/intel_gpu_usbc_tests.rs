//! USB-C ownership tests using the production PHY and external-route models.
use super::tests::FakePhy;
use super::*;
use crate::intel_gpu::Generation;
use crate::intel_gpu_modeset::Framebuffer;
use crate::intel_gpu_modeset::PixelFormat;
use crate::intel_gpu_xelpg_external::tests::{edid_for, ExtFake, Sink};
use crate::intel_gpu_xelpg_external::{activate, probe_sink, MtlDisplay};
use crate::intel_gpu_xelpg_tc::PIN_ASSIGNMENT_D;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_usbc_pin_d_pll_signal_and_stop_preserve_usb_lane() -> TestResult {
    let port = XeLpgPort::Tc2;
    let io = FakePhy::new(port);
    let usb_clock = lane_pclk_pll_request(1) | lane_pclk_refclk_request(1);
    io.write32(port.port_clock_ctl(), usb_clock);
    io.write32(port.buf_ctl2(), lane_powerdown_new_state(1, 7));
    let native = Cx0Phy::new(&io, port);
    if native
        .write(LANE1, C20_VDR_CUSTOM_WIDTH, 0xA5, true)
        .is_err()
    {
        return TestResult::Fail("USB lane sentinel setup");
    }
    io.writes.borrow_mut().clear();
    let lanes = PhyLaneConfig::for_route(true, 2, false).unwrap();
    let mut request = dp_pll_request(port, LinkRate::DpHbr2, 2, true, false, false).unwrap();
    request.lanes = lanes;
    let phy = Cx0Phy::with_lanes(&io, port, lanes);
    if enable_port_pll_state(&io, port, &request).is_err()
        || set_signal_levels(&phy, LinkRate::DpHbr2, 2, &[(0, 0); 4]).is_err()
        || disable_port_pll_lanes(&io, port, lanes).is_err()
    {
        return TestResult::Fail("pin D PLL/signal/stop must complete");
    }
    if io.read32(port.port_clock_ctl()) & usb_clock != usb_clock
        || io.read32(port.buf_ctl2()) & lane_powerdown_new_state(1, 0xF)
            != lane_powerdown_new_state(1, 7)
        || io.vdr_get(1, C20_VDR_CUSTOM_WIDTH) != 0xA5
        || io
            .writes
            .borrow()
            .iter()
            .any(|(off, _)| *off == port.msgbus_ctl_ln0() + 4 || *off == port.msgbus_ctl_ln0() + 12)
    {
        return TestResult::Fail("pin D must preserve USB clocks, power and message bus");
    }
    let writes = io.writes.borrow().len();
    request.lane_count = 4;
    if enable_port_pll_state(&io, port, &request).is_ok()
        || phy.write(BOTH_LANES, C20_VDR_CUSTOM_WIDTH, 0, true).is_ok()
        || io.writes.borrow().len() != writes
    {
        return TestResult::Fail("invalid lane ownership must refuse before writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg",
    smoke_usbc_pin_d_pll_signal_and_stop_preserve_usb_lane
);

fn smoke_usbc_board_reversal_selects_lane1_clock_and_high_txs() -> TestResult {
    let port = XeLpgPort::B;
    let io = FakePhy::new(port);
    let mut request = dp_pll_request(port, LinkRate::DpHbr2, 2, false, false, false).unwrap();
    request.lanes = PhyLaneConfig::for_route(false, 4, true).unwrap();
    if enable_port_pll_state(&io, port, &request).is_err() {
        return TestResult::Fail("reversed PLL must enable");
    }
    if io.read32(port.buf_ctl1()) & PORT_BUF_REVERSAL == 0
        || io.read32(port.port_clock_ctl()) & (LANE1_PHY_CLOCK_SELECT | lane_pclk_pll_request(1))
            != LANE1_PHY_CLOCK_SELECT | lane_pclk_pll_request(1)
        || io.read32(port.port_clock_ctl()) & lane_pclk_pll_request(0) != 0
    {
        return TestResult::Fail("board reversal must select maxPCLK on lane 1");
    }
    for (lane, disabled) in [(0, true), (1, false)] {
        for tx in 1..=2 {
            if (io.vdr_get(lane, cx0_tx_control(tx, 2)) & TX_CONTROL2_DISABLE_SINGLE_TX != 0)
                != disabled
            {
                return TestResult::Fail("reversed two-lane route must enable high TX pair");
            }
        }
    }
    if disable_port_pll_lanes(&io, port, request.lanes).is_err()
        || PhyLaneConfig::for_route(true, 2, true).is_ok()
    {
        return TestResult::Fail("reversal stop or DP-alt cable-flip distinction");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg",
    smoke_usbc_board_reversal_selects_lane1_clock_and_high_txs
);

fn smoke_usbc_tbt_clock_rates_preserve_phy_and_timeout() -> TestResult {
    let port = XeLpgPort::Tc3;
    for (rate, select) in [
        (LinkRate::DpRbr, 0xC),
        (LinkRate::DpHbr, 0xD),
        (LinkRate::DpHbr2, 0xE),
        (LinkRate::DpHbr3, 0xF),
    ] {
        let io = FakePhy::new(port);
        if enable_tbt_clock(&io, port, rate).is_err()
            || io.read32(port.port_clock_ctl()) & DDI_CLOCK_SELECT_MASK != select << 12
            || disable_tbt_clock(&io, port).is_err()
            || io
                .writes
                .borrow()
                .iter()
                .any(|(off, _)| *off != port.port_clock_ctl())
        {
            return TestResult::Fail("TBT clock must use fabric rate without touching C20");
        }
    }
    let stuck = FakePhy::new(port);
    stuck.no_clock_ack.set(true);
    if enable_tbt_clock(&stuck, port, LinkRate::DpHbr2) != Err(Cx0Error::Timeout) {
        return TestResult::Fail("TBT clock needs a hardware ACK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg",
    smoke_usbc_tbt_clock_rates_preserve_phy_and_timeout
);

fn smoke_usbc_pin_d_external_route_keeps_usb_clock_running() -> TestResult {
    let port = XeLpgPort::Tc1;
    let edid = edid_for(148_500, 1920, 280, 88, 44, 1080, 45, 4, 5);
    let io = ExtFake::new(port, Sink::new(0x14, edid));
    io.pin.set(PIN_ASSIGNMENT_D);
    let usb = lane_pclk_pll_request(1) | lane_pclk_refclk_request(1);
    io.phy.write32(port.port_clock_ctl(), usb);
    let probe = match probe_sink(&io, Generation::MeteorLake, port, false) {
        Ok(probe) if probe.negotiated.lanes <= 2 => probe,
        _ => return TestResult::Fail("pin D probe must bound negotiation to two lanes"),
    };
    let fb = Framebuffer {
        phys_addr: 0x0100_0000,
        stride_bytes: 7680,
        format: PixelFormat::Xrgb8888,
    };
    let mut route = match activate(&io, probe, fb, &MtlDisplay::NONE) {
        Ok(route) => route,
        Err(_) => return TestResult::Fail("pin D must modeset beside the active USB clock"),
    };
    if route.stop(&io).is_err()
        || route.release(&io).is_err()
        || io.phy.read32(port.port_clock_ctl()) & usb != usb
    {
        return TestResult::Fail("pin D teardown must preserve USB and release display");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg",
    smoke_usbc_pin_d_external_route_keeps_usb_clock_running
);
