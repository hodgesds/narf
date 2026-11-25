//! Display-35 owned modeset fixtures: the display-14 modeset model
//! (`intel_gpu_modeset_xelpg::tests::MtlFake`) presenting Nova Lake-S, with
//! the LT PHY's message bus, P2P status, lane status and MacCLK registers of
//! DDI A answered by the LT PHY model (`intel_gpu_lt_phy::tests::FakeLtMmio`)
//! at their PICA offsets.

use super::*;
use crate::intel_gpu_lt_phy::tests::FakeLtMmio;
use crate::intel_gpu_lt_phy::{
    txy_ctl, LT_PHY_VDR_0_CONFIG, LT_PHY_VDR_1_CONFIG, LT_PHY_VDR_2_CONFIG,
};
use crate::intel_gpu_modeset::PixelFormat;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

/// DDI A's LT-only registers: `PORT_BUF_CTL2`, `PORT_BUF_CTL5`, the lane-0/1
/// M2P control and P2M status, `PORT_CLOCK_CTL` and the P2P status.
fn lt_reg(r: u64) -> bool {
    matches!(
        r,
        0x16fa04
            | 0x16fa34
            | 0x16fa40
            | 0x16fa44
            | 0x16fa48
            | 0x16fa4c
            | 0x16fa60
            | 0x16faa0
            | 0x16faa4
    )
}

/// DDI A's relocated buffer and AUX registers, mapped back to the display-14
/// offsets the modeset model answers at.
fn from_pica(r: u64) -> Option<u64> {
    match r {
        0x16fa00 | 0x16fa08 => Some(r - 0x16fa00 + 0x64004),
        0x16fa10..=0x16fa24 => Some(r - 0x16fa00 + 0x64000),
        _ => None,
    }
}

/// DDI A's display-14 PHY/AUX offsets, which display 35 must never touch.
fn display14_phy(r: u64) -> bool {
    matches!(r, 0x64004..=0x64024 | 0x64040..=0x6404c | 0x640d8 | 0x640dc | 0x640e0)
}

/// The display-20/30/35 resource registers the model keeps in `values`.
fn resource(r: u64) -> bool {
    matches!(
        r,
        0x510a0
            | 0x41100
            | 0x46460
            | 0x45230
            | 0x45234
            | 0x46440
            | 0x46438
            | 0x4438c
            | 0x7003c
            | 0x44464
            | 0x44468
            | 0x4446c
            | 0x45780
            | 0x45784
            | 0x45788
            | 0x45008
            | 0x44fe8
            | 0x44300
            | 0x44304
            | 0x45004
            | 0x71008
            | 0x72008
            | 0x73008
            | 0x43288
            | 0x432c8
            | 0x6fa88
            | 0x60404
    ) || ((0x70000..0x75000).contains(&r)
        && r & 0xfff >= 0x140
        && r & 0xfff <= 0x87c
        && r & 0xff < 0x80)
}

struct Nova {
    mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake,
    lt: FakeLtMmio,
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    strays: RefCell<Vec<u64>>,
    /// `XELPDP_DP_AUX_CH_CTL_POWER_STATUS` follows its request on LT.
    aux_power: Cell<bool>,
}

impl Nova {
    fn new() -> Self {
        Self {
            mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake::new(
                crate::intel_gpu_xelpg::XeLpgPort::A,
            ),
            lt: FakeLtMmio::default(),
            values: RefCell::new(
                [
                    (0x510a0, 35 << 22),
                    (0x45780, 6 | (8 << 16)),
                    (0x45784, 10 | (12 << 16)),
                    (0x45788, 14 | (16 << 16)),
                ]
                .into_iter()
                .collect(),
            ),
            writes: RefCell::new(Vec::new()),
            strays: RefCell::new(Vec::new()),
            aux_power: Cell::new(false),
        }
    }
    fn get(&self, r: u64) -> u32 {
        self.read32(r)
    }
    fn written(&self, r: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == r)
            .map(|(_, v)| *v)
            .collect()
    }
    fn vdr(&self, lane: u8, address: u16) -> Option<u8> {
        self.lt.vdr.borrow().get(&(lane, address)).copied()
    }
    fn fb() -> Framebuffer {
        Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 4096,
            format: PixelFormat::Xrgb8888,
        }
    }
    fn run(&self) -> Result<Mode, ModesetError> {
        modeset(&View(self), &Self::fb(), Some(&Mode::VESA_1024X768_60))
    }
}

impl MmioWindow for Nova {
    fn read32(&self, r: u64) -> u32 {
        if display14_phy(r) {
            self.strays.borrow_mut().push(r);
            return u32::MAX;
        }
        if lt_reg(r) {
            return self.lt.read32(r);
        }
        if let Some(m) = from_pica(r) {
            let v = self.mode.read32(m);
            return if r == 0x16fa10 && self.aux_power.get() {
                v | crate::intel_gpu_aux::XELPDP_AUX_CH_CTL_POWER_STATUS
            } else {
                v
            };
        }
        if resource(r) {
            *self.values.borrow().get(&r).unwrap_or(&0)
        } else if r == 0x46070 {
            let v = self.mode.read32(r);
            v | ((v >> 1) & (1 << 22))
        } else if r == 0x64000 {
            // XE2LPD_DDI_BUF_D2D_LINK_STATE follows its enable; a
            // read-modify-write carrying it back must not latch it.
            let v = self.mode.read32(r);
            (v & !(1 << 28)) | ((v >> 1) & (1 << 28))
        } else {
            self.mode.read32(r)
        }
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        if display14_phy(r) {
            self.strays.borrow_mut().push(r);
            return;
        }
        if lt_reg(r) {
            return self.lt.write32(r, v);
        }
        if let Some(m) = from_pica(r) {
            if r == 0x16fa10 {
                self.aux_power
                    .set(v & crate::intel_gpu_aux::XELPDP_AUX_CH_CTL_POWER_REQUEST != 0);
            }
            return self.mode.write32(m, v);
        }
        if resource(r) {
            let mut value = v;
            if r == 0x45234 && v & (1 << 31) != 0 {
                value &= !(1 << 31)
            }
            if [0x45008, 0x44fe8, 0x44300, 0x44304].contains(&r) && v & (1 << 31) != 0 {
                value |= 1 << 30
            }
            self.values.borrow_mut().insert(r, value);
        } else {
            self.mode.write32(r, v)
        }
    }
}

/// The owned Pipe-A eDP modeset on display 35: the LT PHY's eDP PLL image
/// (HBR2 with the eDP `config[2]` mark) and eDP signal levels, the
/// display-35 CDCLK rung, and no Cx0 or display-14 PHY access.
fn smoke_nvl_owned_modeset_lights_pipe_a_through_the_lt_phy() -> TestResult {
    let io = Nova::new();
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    assert!(io.strays.borrow().is_empty(), "{:x?}", io.strays.borrow());
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::owned_panel_mode(),
        Some(Mode::VESA_1024X768_60)
    );
    // xe3plpd_lt_dp_hbr2 through the eDP table: config[2] = 1.
    assert_eq!(io.vdr(0, LT_PHY_VDR_0_CONFIG), Some(0x93));
    assert_eq!(io.vdr(0, LT_PHY_VDR_1_CONFIG), Some(0x2d));
    assert_eq!(io.vdr(0, LT_PHY_VDR_2_CONFIG), Some(1));
    // The warm panel's PLL is retired (VALFREQ 0), then the link symbol
    // clock of the HBR2 start rate.
    assert_eq!(io.written(0x64030), [0, 540_000]);
    // MacCLK requested and acknowledged on lane 0, forward clock ungated,
    // the MacCLK select and no SSC.
    let clock = io.get(0x16fa60);
    assert_eq!(clock & (3 << 30), 3 << 30, "{clock:#x}");
    assert_eq!(clock & (1 << 10), 1 << 10);
    assert_eq!(clock & (0x1f << 12), 0x8 << 12);
    assert_eq!(clock & 3, 0);
    // Training converged at levels 0/0: every link lane carries the eDP
    // table's entry 0 (swing level 0, main cursor 12).
    for lane in 0..2u8 {
        for tx in 0..2u8 {
            let main = io.vdr(lane, txy_ctl(tx, 3).unwrap());
            assert_eq!(main.map(|v| v & 0x3f), Some(12), "lane {lane} tx {tx}");
        }
    }
    // The D2D link is DDI_BUF_CTL's on display >= 20.
    assert!(io.written(0x64000).iter().any(|v| v & (1 << 29) != 0));
    // CDCLK from an off PLL on the display-35 table: Wa_13012396614's MDCLK
    // select first, the 151.2 MHz rung (ratio 21, waveform 0xa4a4).
    assert_eq!(io.written(0x46000), [0, 0x0200_0000]);
    assert_eq!(io.written(0x46070), [0, 0x15, 0x8000_0015]);
    assert_eq!(io.written(0x46008), [0x8f00_a4a4]);
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&io),
        151_200
    );
    // The MDCLK ratio after the raise in the Xe3P throttle field (16:13):
    // ceil(806.4 / 151.2) = 6, joined.
    assert_eq!(io.get(0x4438c) & (0xf << 13), 5 << 13);
    // The VRR timing generator at fixed refresh, as on display 30.
    assert_eq!(io.written(0x6000c), [767]);
    assert!(!io.written(0x60420).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_owned_modeset_lights_pipe_a_through_the_lt_phy
);

/// The entry refuses read-only: a Cx0 view, another display IP, and an
/// armed or secondary CMTG.
fn smoke_nvl_owned_modeset_admission_is_read_only() -> TestResult {
    struct Cx0<'a>(&'a Nova);
    impl MmioWindow for Cx0<'_> {
        fn read32(&self, r: u64) -> u32 {
            self.0.read32(r)
        }
        fn write32(&self, r: u64, v: u32) {
            self.0.write32(r, v)
        }
    }
    let fb = Nova::fb();
    let mode = Mode::VESA_1024X768_60;
    let io = Nova::new();
    assert_eq!(
        modeset(&Cx0(&io), &fb, Some(&mode)),
        Err(ModesetError::UnsupportedGeneration)
    );
    io.values.borrow_mut().insert(0x510a0, 30 << 22);
    assert_eq!(
        modeset(&View(&io), &fb, Some(&mode)),
        Err(ModesetError::UnsupportedGeneration)
    );
    io.values.borrow_mut().insert(0x510a0, 35 << 22);
    io.values.borrow_mut().insert(0x6fa88, 1 << 31);
    assert_eq!(
        modeset(&View(&io), &fb, Some(&mode)),
        Err(ModesetError::DisplayResourceUnavailable)
    );
    io.values.borrow_mut().insert(0x6fa88, 0);
    io.values.borrow_mut().insert(0x60404, 1 << 3);
    assert_eq!(
        modeset(&View(&io), &fb, Some(&mode)),
        Err(ModesetError::DisplayResourceUnavailable)
    );
    assert!(io.writes.borrow().is_empty(), "{:x?}", io.writes.borrow());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_owned_modeset_admission_is_read_only
);

/// The in-place takeover reads the panel's EDID before anything else: a
/// sink without one, or an XBGR firmware primary, refuses with only AUX
/// traffic written.
fn smoke_nvl_takeover_refuses_before_destructive_writes() -> TestResult {
    let primary = FirmwarePrimary {
        format: crate::drm::card::PixelFormat::Xrgb8888,
        geometry: crate::intel_gpu_scanout::Geometry {
            width: 1024,
            height: 768,
            pitch: 4096,
        },
        gtt_offset: 0x100_0000,
    };
    let io = Nova::new();
    assert_eq!(
        takeover(&View(&io), &primary),
        Err(ModesetError::EdidUnavailable)
    );
    let aux = |r: u64| (0x16fa10..=0x16fa24).contains(&r);
    assert!(io.writes.borrow().iter().all(|(r, _)| aux(*r)));
    let bgr = FirmwarePrimary {
        format: crate::drm::card::PixelFormat::Xbgr8888,
        ..primary
    };
    let io = Nova::new();
    assert_eq!(
        takeover(&View(&io), &bgr),
        Err(ModesetError::InvalidFramebuffer)
    );
    assert!(io.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_takeover_refuses_before_destructive_writes
);

/// System suspend and resume on display 35 (`drm_atomic_helper_suspend`,
/// then `xe_display_pm_resume`). The owned panel's crtc goes off through the
/// LT PHY (`intel_lt_phy_pll_disable`) and leaves the panel-off record.
/// After the power loss the relight reprograms the sequencer delays the
/// probe kept (`pps_init_registers`: the BIOS power-up, power-down and cycle
/// fields, T8/T9 forced to 1 as `pps_init_delays` does) before
/// `intel_pps_on`, then lights the panel through the LT PHY with the D2D
/// link enable carried in `DDI_BUF_CTL` (`mtl_ddi_prepare_link_retrain` 6.i)
/// and the plane on the new console surface.
fn smoke_nvl_suspend_relight_round_trip_through_the_lt_phy() -> TestResult {
    use crate::intel_gpu_edp::{PP_CONTROL, PP_OFF_DELAYS, PP_ON_DELAYS};
    use crate::intel_gpu_modeset_xelpg::{forget_panel_off, owned_panel_mode, panel_off_record};
    forget_panel_off();
    let io = Nova::new();
    io.mode.model_panel_power();
    // The firmware sequencer: T1-T3 210 ms, T8 and T9 50 ms, T10 500 ms, a
    // 700 ms power cycle; the panel powered with its backlight gate open.
    io.mode.write32(PP_ON_DELAYS, (2100 << 16) | 500);
    io.mode.write32(PP_OFF_DELAYS, (5000 << 16) | 500);
    io.mode.write32(PP_CONTROL, (7 << 4) | 4 | 1);
    let mode = Mode::VESA_1024X768_60;
    assert_eq!(io.run(), Ok(mode));
    let delays = record_panel_delays(&io);
    assert_eq!(panel_delays(), Some(delays));

    // Suspend: the planes, then the rest of hsw_crtc_disable.
    let view = View(&io);
    let mut ms = panel_orchestrator(&view);
    assert_eq!(ms.disable_planes(), Ok(()));
    let off = ms.panel_off().unwrap();
    assert_eq!(off.port, crate::intel_gpu_xelpg::XeLpgPort::A);
    assert_eq!(off.mode, Some(mode));
    assert_eq!(panel_off_record(), Some(off));
    assert_eq!(owned_panel_mode(), None);
    // DDI_CTL_DE and the D2D link off, panel power off, MacCLK released.
    assert_eq!(io.get(0x64000) & ((1 << 31) | (3 << 28)), 0);
    assert_eq!(io.get(PP_CONTROL) & 1, 0);
    assert_eq!(io.get(0x16fa60) & (3 << 30), 0);
    assert!(io.strays.borrow().is_empty(), "{:x?}", io.strays.borrow());

    // System suspend loses the sequencer's registers.
    for reg in [PP_ON_DELAYS, PP_OFF_DELAYS, PP_CONTROL] {
        io.mode.write32(reg, 0);
    }
    io.writes.borrow_mut().clear();

    let console = Framebuffer {
        phys_addr: 0x200_0000,
        stride_bytes: 4096,
        format: PixelFormat::Xrgb8888,
    };
    assert_eq!(relight(&View(&io), &console, &mode, delays), Ok(mode));
    let writes = io.writes.borrow().clone();
    let first = |f: &dyn Fn(u64, u32) -> bool| writes.iter().position(|&(r, v)| f(r, v));
    let pp_on = first(&|r, v| r == PP_ON_DELAYS && v == (2100 << 16) | 1);
    let pp_off = first(&|r, v| r == PP_OFF_DELAYS && v == (5000 << 16) | 1);
    let cycle = first(&|r, v| r == PP_CONTROL && (v >> 4) & 0x1f == 7);
    let power = first(&|r, v| r == PP_CONTROL && v & 1 != 0);
    let pll = first(&|r, _| lt_reg(r));
    let (Some(pp_on), Some(pp_off), Some(cycle), Some(power), Some(pll)) =
        (pp_on, pp_off, cycle, power, pll)
    else {
        return TestResult::Fail("the relight must reprogram the sequencer and the LT PLL");
    };
    assert!(pp_on < power && pp_off < power && cycle < power);
    assert!(power < pll, "intel_pps_on precedes the port PLL");
    // DDI_CTL_DE with DDI_PORT_WIDTH(4) and the display-20+ D2D enable.
    assert!(writes
        .iter()
        .any(|&(r, v)| r == 0x64000 && v == (1 << 31) | (1 << 29) | (3 << 1)));
    // The plane scans out the new console surface; the record is gone.
    assert_eq!(
        io.written(0x7019c).last(),
        Some(&(console.phys_addr as u32))
    );
    assert_eq!(panel_off_record(), None);
    assert_eq!(owned_panel_mode(), Some(mode));
    assert!(io.strays.borrow().is_empty(), "{:x?}", io.strays.borrow());
    forget_panel_off();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_suspend_relight_round_trip_through_the_lt_phy
);

/// The relight refuses before any write: without the panel-off record (the
/// panel was not turned off before suspend, so only the warm modeset of a
/// DDI system suspend powered down would remain), or on another display IP.
fn smoke_nvl_relight_refusals_write_nothing() -> TestResult {
    crate::intel_gpu_modeset_xelpg::forget_panel_off();
    let delays = crate::intel_gpu_edp::PanelDelays::SPEC_DEFAULTS;
    let mode = Mode::VESA_1024X768_60;
    let io = Nova::new();
    assert_eq!(
        relight(&View(&io), &Nova::fb(), &mode, delays),
        Err(RelightRefusal::PanelNotOff)
    );
    io.values.borrow_mut().insert(0x510a0, 30 << 22);
    assert_eq!(
        relight(&View(&io), &Nova::fb(), &mode, delays),
        Err(RelightRefusal::Modeset(ModesetError::UnsupportedGeneration))
    );
    assert!(io.writes.borrow().is_empty(), "{:x?}", io.writes.borrow());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_relight_refusals_write_nothing
);

/// `xe3plpd_pwdoms_dc_off` puts every AUX channel in the `DC_off` well and
/// `intel_dp_aux_xfer` holds the channel's AUX domain across a transfer: with
/// DC6 entered on the Nova fake, a DPCD read through the display-35 view
/// writes `DC_STATE_DISABLE` before its first AUX register write, keeps DC0
/// to the end and defers re-entry 17 ms; DC6 then returns. A refused exit
/// touches no AUX register. A window without the LT PHY never consults the
/// display-35 hook.
fn smoke_nvl_dc6_disarmed_around_an_aux_transfer() -> TestResult {
    use crate::dp_aux::{AuxChannel as _, AuxError};
    use crate::intel_gpu_aux::IntelAux;
    use crate::intel_gpu_dc_states::xe3plpd_dc_tests::{armed_local, RefuseDcOff};
    use crate::intel_gpu_dc_states::{ArmGates, DC_REENABLE_DELAY_NS};
    use crate::intel_gpu_dmc::DC_STATE_EN;
    use core::sync::atomic::Ordering;
    const MS: u64 = 1_000_000;
    let io = Nova::new();
    let local = match armed_local(&io) {
        Ok(local) => local,
        Err(why) => return TestResult::Fail(why),
    };
    assert_eq!(io.get(DC_STATE_EN) & 3, 2, "the fixture starts in DC6");
    local.now.store(7 * MS, Ordering::Relaxed);
    io.writes.borrow_mut().clear();
    let view = View(&io);
    let base = crate::intel_gpu_xelpg::XeLpgPort::A.aux_base();
    let mut buf = [0u8; 1];
    let mut aux = IntelAux::with_base(&view, base).with_dc_off(&local);
    assert!(aux.dpcd_read(0x000, &mut buf).is_ok());
    assert_eq!(buf[0], 0x12, "the sink's DPCD revision");
    let writes = io.writes.borrow().clone();
    // DDI A's AUX control at its PICA offset (`__xe2lpd_aux_ch_idx`).
    let exit = writes.iter().position(|w| *w == (DC_STATE_EN, 0));
    let first_aux = writes.iter().position(|(r, _)| *r == 0x16fa10);
    match (exit, first_aux) {
        (Some(0), Some(at)) if at > 0 => {}
        _ => return TestResult::Fail("DC exit must precede the transfer's first AUX write"),
    }
    assert_eq!(io.written(DC_STATE_EN), [0], "DC0 for the whole transfer");
    assert_eq!(local.core.lock().total(), 0);
    let due = local.deadline.load(Ordering::Relaxed);
    assert_eq!(due, 7 * MS + DC_REENABLE_DELAY_NS);
    assert_eq!(
        local.core.lock().arm_if_due(&io, due, ArmGates::default()),
        Ok(2)
    );
    assert_eq!(io.get(DC_STATE_EN) & 3, 2, "DC6 again after the deferral");

    io.writes.borrow_mut().clear();
    let mut aux = IntelAux::with_base(&view, base).with_dc_off(&RefuseDcOff);
    assert!(matches!(
        aux.dpcd_read(0x000, &mut buf),
        Err(AuxError::Deferred)
    ));
    assert!(io.writes.borrow().is_empty(), "{:x?}", io.writes.borrow());
    // The same registers behind a window without the LT PHY: the display-35
    // hook is not consulted.
    struct NoLt<'a>(&'a View<'a, Nova>);
    impl MmioWindow for NoLt<'_> {
        fn read32(&self, r: u64) -> u32 {
            self.0.read32(r)
        }
        fn write32(&self, r: u64, v: u32) {
            self.0.write32(r, v)
        }
    }
    let plain = NoLt(&view);
    let mut aux = IntelAux::with_base(&plain, base).with_dc_off(&RefuseDcOff);
    assert!(aux.dpcd_read(0x000, &mut buf).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_dc6_disarmed_around_an_aux_transfer
);

/// `intel_lt_phy_transaction_begin` holds `POWER_DOMAIN_DC_OFF` around
/// every LT PHY message-bus conversation: with DC6 entered, a signal-level
/// update on port A exits DC6 before its first message-bus write, keeps DC0
/// to the end and defers re-entry 17 ms. A refused exit writes nothing.
fn smoke_nvl_dc6_disarmed_around_an_lt_phy_transaction() -> TestResult {
    use crate::intel_gpu_dc_states::xe3plpd_dc_tests::{armed_local, RefuseDcOff};
    use crate::intel_gpu_dc_states::{ArmGates, DC_REENABLE_DELAY_NS};
    use crate::intel_gpu_dmc::DC_STATE_EN;
    use crate::intel_gpu_lt_phy::{LtPhy, LtPort, LtSignalProtocol};
    use core::sync::atomic::Ordering;
    const MS: u64 = 1_000_000;
    let io = Nova::new();
    let local = match armed_local(&io) {
        Ok(local) => local,
        Err(why) => return TestResult::Fail(why),
    };
    local.now.store(9 * MS, Ordering::Relaxed);
    io.writes.borrow_mut().clear();
    let view = View(&io);
    let phy = LtPhy::new(&view, LtPort::A, false, 4, false)
        .unwrap()
        .with_dc_off(&local);
    assert_eq!(
        phy.program_signal_levels(LtSignalProtocol::Edp, &[0, 0, 0, 0]),
        Ok(())
    );
    let writes = io.writes.borrow().clone();
    let exit = writes.iter().position(|w| *w == (DC_STATE_EN, 0));
    let first_bus = writes.iter().position(|(r, _)| lt_reg(*r));
    match (exit, first_bus) {
        (Some(0), Some(at)) if at > 0 => {}
        _ => return TestResult::Fail("DC exit must precede the first message-bus write"),
    }
    assert_eq!(
        io.written(DC_STATE_EN),
        [0],
        "DC0 for the whole transaction"
    );
    let due = local.deadline.load(Ordering::Relaxed);
    assert_eq!(due, 9 * MS + DC_REENABLE_DELAY_NS);
    assert_eq!(
        local.core.lock().arm_if_due(&io, due, ArmGates::default()),
        Ok(2)
    );

    io.writes.borrow_mut().clear();
    let phy = LtPhy::new(&view, LtPort::A, false, 4, false)
        .unwrap()
        .with_dc_off(&RefuseDcOff);
    assert_eq!(
        phy.program_signal_levels(LtSignalProtocol::Edp, &[0, 0, 0, 0]),
        Err(crate::intel_gpu_xelpg::Cx0Error::PhyError)
    );
    assert!(phy.disable().is_err());
    assert!(io.writes.borrow().is_empty(), "{:x?}", io.writes.borrow());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_modeset",
    smoke_nvl_dc6_disarmed_around_an_lt_phy_transaction
);
