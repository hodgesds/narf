//! Gen9 display suspend owner fixtures. The machine is the modeset's
//! scripted sink (its PLLs, DBUF, pcode, AUX engine and DP sink) with the
//! panel hardware the sink does not model added: `PP_STATUS` follows
//! `PP_CONTROL`'s power target on both sequencer instances (the south
//! display's at 0xC7200, Gen9 LP's at 0x61200) and the PG0/PG1 fuses read
//! distributed. Power loss replaces the sink with a fresh one. The `DC_off`
//! service is a fixture core (`LocalDc`) booted with the Gen9 DMC fixture
//! container. Expected values come from the Linux sources the module header
//! cites (`hsw_crtc_disable`, `intel_ddi_post_disable_dp`,
//! `intel_edp_backlight_off/on`, `lpt_/bxt_*_backlight`,
//! `intel_irq_suspend`, `skl/bxt_display_core_uninit/init`,
//! `bxt_enable_dc9`), never recorded from the owner.

use super::*;
use crate::intel_gpu::{ChipInfo, Generation};
use crate::intel_gpu_dmc::{DC_STATE_EN, SKL_DMC_MAX_FW_SIZE};
use crate::intel_gpu_gen9_dc_states::service_tests::{load, resident, LocalDc};
use crate::intel_gpu_gen9_dc_states::{Gen9ArmGates, Gen9DcCore, Gen9DcUser, NoDcSuspend};
use crate::intel_gpu_modeset::tests::ScriptedSinkMmio;
use crate::intel_gpu_modeset::{modeset_display_for_chip, Framebuffer, Mode, PixelFormat};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::Ordering;
use narf_kernel_test::{kernel_test_in, TestResult};

const MS: u64 = 1_000_000;
/// The firmware's PWM: a 0x1000-cycle period at half duty, active low, on
/// the alternate increment.
const PERIOD: u32 = 0x1000;
const DUTY: u32 = 0x0800;
/// `PP_CONTROL` bits: `PANEL_POWER_ON` 0, `EDP_FORCE_VDD` 3,
/// `EDP_BLC_ENABLE` 2.
const POWER_ON: u32 = 1 << 0;
const FORCE_VDD: u32 = 1 << 3;
const BLC: u32 = 1 << 2;
/// `GEN8_MASTER_IRQ` and its `GEN8_MASTER_IRQ_CONTROL`.
const MASTER: u64 = 0x44200;
const MASTER_ON: u32 = 1 << 31;
/// `DC_STATE_EN_DC9`.
const DC9: u32 = 1 << 3;

/// The scripted display plus the panel's power hardware.
struct Machine {
    sink: RefCell<Box<ScriptedSinkMmio>>,
    /// Writes to `GEN8_MASTER_IRQ` do not stick.
    master_stuck: Cell<bool>,
}

impl Machine {
    fn new() -> Self {
        Self {
            sink: RefCell::new(Box::new(ScriptedSinkMmio::new(1 << 29))),
            master_stuck: Cell::new(false),
        }
    }
    /// S3: every register back at reset, program RAM included.
    fn power_loss(&self) {
        *self.sink.borrow_mut() = Box::new(ScriptedSinkMmio::new(1 << 29));
    }
    fn writes_to(&self, off: u64) -> Vec<u32> {
        self.sink.borrow().writes_to(off)
    }
    fn log(&self) -> Vec<(u64, u32)> {
        self.sink.borrow().writes.borrow().clone()
    }
    fn clear_log(&self) {
        self.sink.borrow().writes.borrow_mut().clear();
    }
    fn at(&self, pred: impl Fn(u64, u32) -> bool) -> Option<usize> {
        self.log().iter().position(|(o, v)| pred(*o, *v))
    }
}

impl MmioWindow for Machine {
    fn read32(&self, off: u64) -> u32 {
        let sink = self.sink.borrow();
        match off {
            // PP_STATUS: on-idle (PP_ON | PP_SEQUENCE_STATE_ON_IDLE) with the
            // power target set, off-idle with no cycle delay otherwise.
            0xC7200 | 0x61200 => {
                if sink.read32(off + 4) & POWER_ON != 0 {
                    0x8000_0008
                } else {
                    0
                }
            }
            // SKL_FUSE_STATUS: PG0 and PG1 distributed.
            0x42000 => sink.read32(off) | (1 << 27) | (1 << 26),
            _ => sink.read32(off),
        }
    }
    fn write32(&self, off: u64, val: u32) {
        if off == MASTER && self.master_stuck.get() {
            return;
        }
        self.sink.borrow().write32(off, val);
    }
}

fn skl() -> ChipInfo {
    ChipInfo {
        vid: 0x8086,
        did: 0x1912,
        generation: Generation::Skylake,
        asic: "skylake",
    }
}

fn bxt() -> ChipInfo {
    ChipInfo {
        vid: 0x8086,
        did: 0x5a85,
        generation: Generation::Broxton,
        asic: "broxton",
    }
}

fn fb() -> Framebuffer {
    Framebuffer {
        phys_addr: 0x100_0000,
        stride_bytes: 1920 * 4,
        format: PixelFormat::Xrgb8888,
    }
}

/// Short sequencer delays (100 us each, no power-cycle wait) so the fixture
/// spins little; the register encodings are the probe's.
fn panel(platform: Gen9Platform) -> Panel {
    Panel {
        platform,
        delays: PanelDelays {
            t1_t3: 1,
            t8: 1,
            t9: 1,
            t10: 1,
            t11_t12: 0,
        },
        pwm: if platform.is_lp() {
            PwmLayout::Bxt(0)
        } else {
            PwmLayout::Spt
        },
        dmc: Some((resident(), SKL_DMC_MAX_FW_SIZE)),
    }
}

/// Probe's first light: the DMC loaded, the DPIO PHYs on Gen9 LP, the
/// sequencer initialised and powered, the panel modeset from EDID, the PPS
/// gate open, and the PWM as firmware left it. Then a `DC_off` core booted
/// and re-entered (DC6 on display 9, DC5 on Gen9 LP).
fn first_light(
    m: &Machine,
    panel: &Panel,
    chip: ChipInfo,
) -> Result<(Mode, LocalDc), &'static str> {
    let blob = resident();
    load(m, blob);
    if panel.lp() {
        use crate::intel_gpu_bxt_phy::Port;
        for port in [Port::A, Port::B, Port::C] {
            crate::intel_gpu_bxt_display::power_port(m, panel.glk(), port)
                .map_err(|_| "the DPIO PHYs must power")?;
        }
    }
    let pps_window = crate::intel_gpu_bxt_display::PpsWindow::new(m, panel.lp());
    let mut pps = PanelPowerSequencer::with_delays(&pps_window, panel.delays);
    pps.init_registers();
    pps.power_on().map_err(|_| "the panel must power on")?;
    let mode = modeset_display_for_chip(m, chip, &fb(), None).map_err(|_| "first light failed")?;
    pps.backlight_on().map_err(|_| "the PPS gate must open")?;
    match panel.pwm {
        PwmLayout::Spt => {
            m.write32(SOUTH_CHICKEN1, SPT_PWM_GRANULARITY);
            m.write32(BLC_PWM_PCH_CTL2, (PERIOD << 16) | DUTY);
            m.write32(BLC_PWM_PCH_CTL1, BLM_PCH_PWM_ENABLE | BLM_PCH_POLARITY);
        }
        PwmLayout::Bxt(c) => {
            m.write32(bxt_blc_pwm_freq(c), PERIOD);
            m.write32(bxt_blc_pwm_duty(c), DUTY);
            m.write32(bxt_blc_pwm_ctl(c), BXT_BLC_PWM_ENABLE | BXT_BLC_PWM_POLARITY);
        }
        PwmLayout::None => {}
    }
    // Firmware left the master interrupt enabled.
    m.write32(MASTER, MASTER_ON);
    let mut core = Gen9DcCore::new(panel.platform);
    let _ = core.boot(m);
    core.provide_program(blob, SKL_DMC_MAX_FW_SIZE);
    let due = core.release_init(0).ok_or("Init must be released")?;
    core.arm_if_due(m, due, Gen9ArmGates::default())
        .map_err(|_| "DC states must be re-entered")?;
    Ok((mode, LocalDc::new(core)))
}

/// Both `TRANSCONF`s Pipe A uses read off, and the EDP transcoder's DDI
/// function too.
fn dark(m: &Machine) -> bool {
    m.read32(0x7f008) & (1 << 31) == 0
        && m.read32(0x70008) & (1 << 31) == 0
        && m.read32(0x6f400) & (1 << 31) == 0
}

/// Display 9 proper, S3 and back: the eDP crtc off in `hsw_crtc_disable`'s
/// order (planes; the PPS gate then `lpt_disable_backlight`; the transcoder,
/// its DDI function; DDI A's buffer; `intel_pps_off`; `skl_ddi_disable_clock`'s
/// `DPLL_CTRL2_DDI_CLK_OFF(PORT_A)` bit 15), the master interrupt off, DC
/// states held off; `skl_display_core_uninit` (DBUF, DPLL0, PW_1); after power
/// loss `skl_display_core_init` (the PCH handshake bit 4, PW_1 and MISC IO,
/// 337.5 MHz on VCO 8100: `CDCLK_CTL` 0x080002A1, DBUF) and the DMC reload;
/// then the relight in `intel_edp_backlight_on`'s order (the PWM restored —
/// `SPT_PWM_GRANULARITY`, the period, `BLM_PCH_POLARITY`, the enable, the
/// duty — before the PPS gate) and DC6 back 17 ms after it.
fn big_core_round_trip() -> Result<(), &'static str> {
    let m = Machine::new();
    let p = panel(Gen9Platform::Skylake);
    let (mode, local) = first_light(&m, &p, skl())?;
    m.clear_log();
    let saved = prepare(&m, &p, &local, 10 * MS).map_err(|_| "the preparation must succeed")?;
    let want = Saved {
        pwm: Pwm::Spt {
            period: PERIOD,
            duty: DUTY,
            active_low: true,
            alternate_increment: true,
        },
        vco: 8_100_000,
    };
    if saved != want {
        return Err("the PWM and DPLL0's VCO must be recorded as found");
    }
    if !dark(&m) || m.read32(0x70180) != 0 || m.read32(0x64000) & (1 << 31) != 0 {
        return Err("planes, transcoder, DDI function and buffer must be off");
    }
    if m.read32(0xC7204) & (POWER_ON | FORCE_VDD | BLC) != 0 {
        return Err("the panel must be unpowered with its gate closed");
    }
    if m.read32(0x6c05c) & (1 << 15) == 0 {
        return Err("DDI A's clock must be gated (DPLL_CTRL2_DDI_CLK_OFF)");
    }
    if m.read32(BLC_PWM_PCH_CTL1) & BLM_PCH_PWM_ENABLE != 0
        || m.read32(BLC_PWM_PCH_CTL2) != PERIOD << 16
    {
        return Err("the PWM must be disabled at duty 0 with its period kept");
    }
    if m.read32(MASTER) & MASTER_ON != 0 || m.read32(DC_STATE_EN) != 0 {
        return Err("the master interrupt and DC states must be off");
    }
    if local.core.lock().refs(Gen9DcUser::Suspend) != 1 {
        return Err("the Suspend reference must be held through the resume");
    }
    let order = [
        m.at(|o, v| o == 0x70180 && v == 0),
        m.at(|o, v| o == 0xC7204 && v & BLC == 0 && v & POWER_ON != 0),
        m.at(|o, v| o == BLC_PWM_PCH_CTL1 && v & BLM_PCH_PWM_ENABLE == 0),
        m.at(|o, v| o == 0x7f008 && v & (1 << 31) == 0),
        m.at(|o, v| o == 0x6f400 && v & (1 << 31) == 0),
        m.at(|o, v| o == 0x64000 && v & (1 << 31) == 0),
        m.at(|o, v| o == 0xC7204 && v & POWER_ON == 0),
        m.at(|o, v| o == 0x6c05c && v & (1 << 15) != 0),
    ];
    if order.iter().any(Option::is_none) || order.windows(2).any(|w| w[0] >= w[1]) {
        return Err("the crtc disable must follow hsw_crtc_disable's order");
    }
    // Late suspend, S3: the display core uninitialized, DC0.
    if suspend_late(&m, &p, SystemSleepState::S3, true, &local) != LateOutcome::Uninit {
        return Err("display 9 must uninitialize its core for S3");
    }
    if m.read32(0x46010) & (1 << 31) != 0
        || m.read32(0x45008) & (1 << 31) != 0
        || m.read32(0x45404) & (1 << 29) != 0
    {
        return Err("DPLL0, DBUF and PW_1 must be released");
    }
    m.power_loss();
    if resume_early(&m, &p, &saved, Some(LateOutcome::Uninit), &local).is_err() {
        return Err("the early resume must reinitialize the core and reload the DMC");
    }
    if m.writes_to(0x46408) != [1 << 4] || m.read32(0x46000) != 0x0800_02A1 {
        return Err("the PCH handshake and 337.5 MHz CDCLK on resume");
    }
    let order = [
        m.at(|o, _| o == 0x46408),
        m.at(|o, v| o == 0x45404 && v & (1 << 29) != 0),
        m.at(|o, _| o == 0x46000),
        m.at(|o, v| o == 0x45008 && v & (1 << 31) != 0),
        m.at(|o, _| (0x80000..0x8F000).contains(&o)),
    ];
    if order.iter().any(Option::is_none) || order.windows(2).any(|w| w[0] >= w[1]) {
        return Err("handshake, PW_1, CDCLK, DBUF, then the program reload");
    }
    m.clear_log();
    let relit = resume_late(&m, &p, &saved, Ok(()), &local, 100 * MS, || {
        modeset_display_for_chip(&m, skl(), &fb(), Some(&mode)).is_ok()
    });
    if relit.is_err() {
        return Err("the relight must succeed");
    }
    if m.read32(0xC7208) != p.delays.pp_on_value()
        || m.read32(0xC7204) & (POWER_ON | BLC) != POWER_ON | BLC
        || m.read32(0x7f008) & (1 << 31) == 0
    {
        return Err("the sequencer reprogrammed, the panel powered and lit");
    }
    if m.read32(SOUTH_CHICKEN1) & SPT_PWM_GRANULARITY == 0
        || m.read32(BLC_PWM_PCH_CTL2) != (PERIOD << 16) | DUTY
        || m.read32(BLC_PWM_PCH_CTL1) != BLM_PCH_PWM_ENABLE | BLM_PCH_POLARITY
    {
        return Err("the PWM must be restored as found");
    }
    let order = [
        m.at(|o, v| o == 0xC7204 && v & POWER_ON != 0),
        m.at(|o, _| o == 0x64000),
        m.at(|o, v| o == BLC_PWM_PCH_CTL1 && v & BLM_PCH_PWM_ENABLE != 0),
        m.at(|o, v| o == 0xC7204 && v & BLC != 0),
    ];
    if order.iter().any(Option::is_none) || order.windows(2).any(|w| w[0] >= w[1]) {
        return Err("power, modeset, PWM, then the PPS gate");
    }
    let core = local.core.lock();
    if core.refs(Gen9DcUser::Suspend) != 0
        || local.deadline.load(Ordering::Relaxed) != 117 * MS
    {
        return Err("the Suspend reference must drop with re-entry 17 ms later");
    }
    Ok(())
}

fn smoke_gen9_suspend_big_core_round_trip() -> TestResult {
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(true);
    let result = big_core_round_trip();
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_suspend",
    smoke_gen9_suspend_big_core_round_trip
);

/// Broxton, S3 with DC9 entered and left: the crtc off (the port A PLL,
/// `BXT_PORT_PLL_ENABLE` 0x46074 bit 31, instead of a DPLL_CTRL2 gate;
/// `bxt_disable_backlight` on controller 0), the DPIO PHYs off,
/// `bxt_display_core_uninit` (CDCLK at the 19.2 MHz bypass, decimal 36) and
/// `bxt_enable_dc9` (`DC_STATE_EN` 0x8); after power loss `bxt_disable_dc9`
/// first, the core init and reload, then the relight: the PHYs, the
/// display-engine sequencer at 0x61200, the panel, and the PWM restored
/// (`BXT_BLC_PWM_FREQ1`, `DUTY1`, `CTL1` with `BXT_BLC_PWM_POLARITY`).
fn lp_dc9_round_trip() -> Result<(), &'static str> {
    let m = Machine::new();
    let p = panel(Gen9Platform::Broxton);
    let (mode, local) = first_light(&m, &p, bxt())?;
    m.clear_log();
    let saved = prepare(&m, &p, &local, 10 * MS).map_err(|_| "the preparation must succeed")?;
    if saved.pwm
        != (Pwm::Bxt {
            controller: 0,
            period: PERIOD,
            duty: DUTY,
            active_low: true,
            util_active_low: false,
        })
    {
        return Err("the BXT PWM must be recorded as found");
    }
    if !dark(&m) || m.read32(0x46074) & (1 << 31) != 0 || !m.writes_to(0x6c05c).is_empty() {
        return Err("the crtc off with the port A PLL down and no DPLL_CTRL2 write");
    }
    if m.read32(0x61204) & (POWER_ON | BLC) != 0
        || m.read32(bxt_blc_pwm_ctl(0)) & BXT_BLC_PWM_ENABLE != 0
        || m.read32(bxt_blc_pwm_duty(0)) != 0
    {
        return Err("the display-engine sequencer and the BXT PWM must be off");
    }
    if suspend_late(&m, &p, SystemSleepState::S3, true, &local) != LateOutcome::Dc9 {
        return Err("Gen9 LP must enter DC9");
    }
    if m.read32(DC_STATE_EN) != DC9
        || m.read32(crate::intel_gpu_bxt_phy::DISP_PWRON) != 0
        || m.read32(0x46070) & (1 << 31) != 0
        || m.read32(0x46000) & 0x7ff != 36
    {
        return Err("DC9 with the PHYs, the DE PLL and CDCLK down");
    }
    m.power_loss();
    m.write32(DC_STATE_EN, DC9);
    m.clear_log();
    if resume_early(&m, &p, &saved, Some(LateOutcome::Dc9), &local).is_err() {
        return Err("the early resume must leave DC9 and reload the DMC");
    }
    if m.log().first() != Some(&(DC_STATE_EN, 0)) || m.read32(0x46000) != 0x00F0_011E {
        return Err("bxt_disable_dc9 first, then 144 MHz CDCLK");
    }
    m.clear_log();
    let relit = resume_late(&m, &p, &saved, Ok(()), &local, 50 * MS, || {
        modeset_display_for_chip(&m, bxt(), &fb(), Some(&mode)).is_ok()
    });
    if relit.is_err() {
        return Err("the relight must succeed");
    }
    if m.read32(crate::intel_gpu_bxt_phy::DISP_PWRON) == 0
        || m.read32(0x61208) != p.delays.pp_on_value()
        || m.read32(0x61204) & (POWER_ON | BLC) != POWER_ON | BLC
        || m.read32(0x7f008) & (1 << 31) == 0
    {
        return Err("the PHYs, sequencer, power and pipe back");
    }
    if m.read32(bxt_blc_pwm_freq(0)) != PERIOD
        || m.read32(bxt_blc_pwm_duty(0)) != DUTY
        || m.read32(bxt_blc_pwm_ctl(0)) != BXT_BLC_PWM_ENABLE | BXT_BLC_PWM_POLARITY
    {
        return Err("the BXT PWM must be restored as found");
    }
    let core = local.core.lock();
    if core.dc9() || core.refs(Gen9DcUser::Suspend) != 0 {
        return Err("DC9 left and the Suspend reference released");
    }
    Ok(())
}

fn smoke_gen9_suspend_lp_dc9_round_trip() -> TestResult {
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(true);
    let result = lp_dc9_round_trip();
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_suspend",
    smoke_gen9_suspend_lp_dc9_round_trip
);

/// Refusals:
/// - the option is strict and default off, and admission needs a Gen9
///   display and an owned panel mode; without an owner the device-PM hooks
///   are inert;
/// - a DSI transcoder lit on Gen9 LP (`BXT_MIPI_PORT_CTRL(PORT_A)` 0x6b0c0
///   `DPI_ENABLE` behind a locked DSI PLL with valid dividers) refuses the
///   preparation (the panel-off does not reach it) and, after one, the late
///   step: DC0, no uninit write, with or without a `DC_off` service;
/// - a master interrupt that stays enabled refuses the preparation, and one
///   re-enabled after it refuses DC9.
fn smoke_gen9_suspend_refusals() -> TestResult {
    use narf_boot::args::KernelCmdline;
    if !requested(KernelCmdline::new("quiet narf.intel.gen9_suspend=1")) {
        return TestResult::Fail("narf.intel.gen9_suspend=1 must opt in");
    }
    for line in [
        "",
        "narf.intel.gen9_suspend",
        "narf.intel.gen9_suspend=0",
        "narf.intel.gen9_suspend=1 narf.intel.gen9_suspend=1",
        "-- narf.intel.gen9_suspend=1",
        "narf.intel.gen9_dc=1",
    ] {
        if requested(KernelCmdline::new(line)) {
            return TestResult::Fail("only one exact narf.intel.gen9_suspend=1 before -- opts in");
        }
    }
    let mode = Mode::VESA_1024X768_60;
    let tgl = ChipInfo {
        vid: 0x8086,
        did: 0x9a49,
        generation: Generation::TigerLake,
        asic: "tigerlake",
    };
    if admit(false, skl(), Some(mode)).is_some()
        || admit(true, skl(), None).is_some()
        || admit(true, tgl, Some(mode)).is_some()
        || admit(true, bxt(), Some(mode)).map(|(p, _)| p) != Some(Gen9Platform::Broxton)
    {
        return TestResult::Fail("admission needs the option, a Gen9 display and a panel");
    }
    if owner().is_none() {
        use narf_power::device_pm::DevicePmOps as _;
        if SystemPm.suspend().is_err() || SystemPm.resume().is_err() {
            return TestResult::Fail("without an owner the device-PM hooks are inert");
        }
    }
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(true);
    let result = refusals_on_hardware();
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}

fn refusals_on_hardware() -> Result<(), &'static str> {
    let dsi = |m: &Machine| {
        m.write32(dc::BXT_DSI_PLL_ENABLE, (1 << 31) | (1 << 30));
        m.write32(dc::BXT_DSI_PLL_CTL, (1 << 8) | (1 << 10));
        m.write32(0x6b0c0, 1 << 31);
    };
    let still_lit = Gen9SuspendError::StillLit {
        reg: 0x6b0c0,
        value: 1 << 31,
    };
    // The preparation refuses a lit DSI port and drops Suspend again.
    let m = Machine::new();
    let p = panel(Gen9Platform::Broxton);
    let (_, local) = first_light(&m, &p, bxt())?;
    dsi(&m);
    match prepare(&m, &p, &local, 0) {
        Err(Refusal {
            error,
            touched: true,
            ..
        }) if error == still_lit => {}
        _ => return Err("a lit DSI port must refuse the preparation"),
    }
    if local.core.lock().refs(Gen9DcUser::Suspend) != 0 {
        return Err("a refused preparation must drop the Suspend reference");
    }
    // Lit after a completed preparation: the late step refuses, DC0.
    for with_service in [true, false] {
        let m = Machine::new();
        let (_, local) = first_light(&m, &p, bxt())?;
        let dc_off: &dyn Gen9DcSuspend = if with_service { &local } else { &NoDcSuspend };
        if prepare(&m, &p, dc_off, 0).is_err() {
            return Err("a dark display must prepare");
        }
        dsi(&m);
        m.clear_log();
        let want = LateOutcome::Refused(Dc9Block::DsiActive {
            reg: 0x6b0c0,
            value: 1 << 31,
        });
        if suspend_late(&m, &p, SystemSleepState::S3, true, dc_off) != want {
            return Err("a lit DSI transcoder must refuse the late step");
        }
        if m.log().iter().any(|(o, _)| *o == DC_STATE_EN || *o == 0x46070 || *o == 0x45008)
        {
            return Err("a refused late step must write nothing to DC, CDCLK or DBUF");
        }
    }
    // A master interrupt that will not turn off refuses the preparation.
    let m = Machine::new();
    let (_, local) = first_light(&m, &p, bxt())?;
    m.master_stuck.set(true);
    match prepare(&m, &p, &local, 0) {
        Err(Refusal {
            error: Gen9SuspendError::InterruptsLive(MASTER_ON),
            touched: true,
            ..
        }) => {}
        _ => return Err("live interrupts must refuse the preparation"),
    }
    // Re-enabled after the preparation: DC9 refuses, nothing written.
    let m = Machine::new();
    let (_, local) = first_light(&m, &p, bxt())?;
    if prepare(&m, &p, &local, 0).is_err() {
        return Err("the preparation must succeed");
    }
    m.write32(MASTER, MASTER_ON);
    m.clear_log();
    if suspend_late(&m, &p, SystemSleepState::S3, true, &local)
        != LateOutcome::Refused(Dc9Block::InterruptsLive(MASTER_ON))
        || m.log().iter().any(|(o, _)| *o == DC_STATE_EN)
    {
        return Err("live interrupts must refuse DC9 before any write");
    }
    if local.core.lock().get(&m, Gen9DcUser::Kms) != Ok(true) {
        return Err("a refused DC9 must lift its fence");
    }
    Ok(())
}
kernel_test_in!("drivers/gpu/intel_gpu_gen9_suspend", smoke_gen9_suspend_refusals);

/// Display 9 proper into suspend-to-idle with a DMC payload keeps its core
/// (`intel_power_domains_suspend`'s early return): the late step writes
/// nothing, and the early resume only exits DC states, with no CDCLK, power
/// well or program writes.
fn s2idle_keeps_the_core() -> Result<(), &'static str> {
    let m = Machine::new();
    let p = panel(Gen9Platform::KabyLake);
    let (_, local) = first_light(&m, &p, ChipInfo { did: 0x5916, asic: "kabylake", ..skl() })?;
    let saved = prepare(&m, &p, &local, 0).map_err(|_| "the preparation must succeed")?;
    m.clear_log();
    let late = suspend_late(&m, &p, SystemSleepState::S0Idle, true, &local);
    if late != LateOutcome::Kept || !m.log().is_empty() {
        return Err("s2idle with the DMC must keep the core untouched");
    }
    if resume_early(&m, &p, &saved, Some(late), &local).is_err()
        || m
            .log()
            .iter()
            .any(|(o, _)| *o == 0x46000 || *o == 0x45404 || (0x80000..0x8F000).contains(o))
    {
        return Err("the early resume must not reinitialize a kept core");
    }
    Ok(())
}

fn smoke_gen9_suspend_s2idle_keeps_the_core() -> TestResult {
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(true);
    let result = s2idle_keeps_the_core();
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(false);
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_suspend",
    smoke_gen9_suspend_s2idle_keeps_the_core
);
