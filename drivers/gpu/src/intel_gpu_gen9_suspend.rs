//! Gen9 display system suspend: the owned internal panel turned off before
//! system sleep and relit after it, on Skylake, Kaby Lake, Coffee Lake and
//! Comet Lake (display 9) and on Broxton and Gemini Lake (Gen9 LP). Opted in
//! with `narf.intel.gen9_suspend=1` (default off: without it nothing here is
//! installed, every hook is absent and nothing is written).
//!
//! ## Why
//!
//! Without an owner nothing turns a Gen9 panel off before system sleep or
//! relights it after, so the Gen9 LP DC9 entry (`bxt_enable_dc9`, which the
//! `DC_off` service refuses while a transcoder is lit) never runs, and a
//! display-9 S3 loses the panel.
//!
//! ## Linux grounding (7.4-rc4, `drivers/gpu/drm/i915`)
//!
//! `i915_driver.c::i915_drm_suspend` runs `intel_display_driver_suspend`
//! (`drm_atomic_helper_suspend`: every crtc off) and then `intel_irq_suspend`;
//! `i915_drm_suspend_late` runs `intel_display_power_suspend_late`; resume
//! mirrors it (`intel_display_power_resume_early`, then the display resume
//! that commits the saved state again). Here:
//!
//! - preparation (asynchronous, device interrupts still usable): the KMS
//!   owner restores its console and closes admission and every external route
//!   retires (`intel_gpu_kms::quiesce_for_legacy`); the `DC_off` service takes
//!   its Suspend reference (DC states off through the resume); the eDP crtc
//!   goes off in `hsw_crtc_disable`'s order for the eDP port
//!   ([`panel_off`]); the device's master interrupt is disabled
//!   (`intel_irq_suspend` → `gen8_irq_reset`'s `gen8_master_intr_disable`);
//!   PCI configuration is saved;
//! - late suspend (the device-PM fan-out, interrupts gated): `intel_power_domains_suspend`'s
//!   display-core uninit ([`suspend_late`]) and, on Gen9 LP, `bxt_enable_dc9`;
//! - early resume (the device-PM fan-out): PCI configuration restored,
//!   `bxt_disable_dc9` or the display-core init's `DC_STATE_DISABLE`, the
//!   display-core init and the DMC reload ([`resume_early`]);
//! - resume (asynchronous): the relight ([`relight`]: the DPIO PHYs on Gen9
//!   LP, the panel power sequencer re-initialised and powered, the panel
//!   modeset at the probe mode, the backlight PWM and the PPS gate), then
//!   the `DC_off` Suspend reference released.
//!
//! Stricter than Linux, and why: a failed step of the panel-off refuses the
//! suspend and relights the panel (Linux continues); a panel that still reads
//! lit after it, or a master interrupt that stays enabled, refuses too; a
//! DMC program that does not reload after resume leaves the panel dark (the
//! Gen9 modeset requires a loaded DMC); the relight is the probe's full
//! panel modeset at the probe mode, not a restore of the last atomic state.
//! Not done, unlike Linux: the master interrupt is not re-enabled after
//! resume (no Gen9 interrupt handler is installed in this driver);
//! `PP_DIVISOR` on pre-CNP south displays is not programmed (the probe's
//! sequencer init does not either).

use alloc::boxed::Box;
use alloc::sync::Arc;

use narf_lib::sync::IrqSafeSpinLock;
use narf_power::system_pm::SystemSleepState;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_dc_states::{UTIL_PIN_CTL, UTIL_PIN_ENABLE, UTIL_PIN_MODE_PWM};
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_edp::{PanelDelays, PanelPowerSequencer, PpsError};
use crate::intel_gpu_gen9_dc_states::{self as dc, CoreInitError, Dc9Block, Gen9DcSuspend};
use crate::intel_gpu_gt::Gen9Platform;
use crate::intel_gpu_pipes::Pipe;

/// The boot option opting the Gen9 display into the suspend owner.
pub const OPT_IN: &str = "narf.intel.gen9_suspend";

/// `narf.intel.gen9_suspend=1`, with the strict grammar every Intel opt-in
/// uses ([`crate::intel_gpu_gt::boot_opt_in`]).
pub fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, OPT_IN)
}

// ── Backlight PWM (`display/intel_backlight.c`) ─────────────────

/// `BLC_PWM_CPU_CTL2` and `BLM_PWM_ENABLE`.
pub const BLC_PWM_CPU_CTL2: u64 = 0x48250;
/// `BLM_PWM_ENABLE`.
pub const BLM_PWM_ENABLE: u32 = 1 << 31;
/// `BLC_PWM_PCH_CTL1`: `BLM_PCH_PWM_ENABLE` and `BLM_PCH_POLARITY`.
pub const BLC_PWM_PCH_CTL1: u64 = 0xC8250;
/// `BLM_PCH_PWM_ENABLE`.
pub const BLM_PCH_PWM_ENABLE: u32 = 1 << 31;
/// `BLM_PCH_POLARITY`.
pub const BLM_PCH_POLARITY: u32 = 1 << 29;
/// `BLC_PWM_PCH_CTL2`: the period in [31:16], the duty in [15:0].
pub const BLC_PWM_PCH_CTL2: u64 = 0xC8254;
/// `SOUTH_CHICKEN1` and `SPT_PWM_GRANULARITY`.
pub const SOUTH_CHICKEN1: u64 = 0xC2000;
/// `SPT_PWM_GRANULARITY`.
pub const SPT_PWM_GRANULARITY: u32 = 1 << 0;
/// `BXT_BLC_PWM_ENABLE`.
pub const BXT_BLC_PWM_ENABLE: u32 = 1 << 31;
/// `BXT_BLC_PWM_POLARITY`.
pub const BXT_BLC_PWM_POLARITY: u32 = 1 << 29;
/// `UTIL_PIN_POLARITY`.
pub const UTIL_PIN_POLARITY: u32 = 1 << 22;

/// `BXT_BLC_PWM_CTL(controller)`: controller 1's block is 0x100 above.
pub const fn bxt_blc_pwm_ctl(controller: u8) -> u64 {
    0xC8250 + 0x100 * (controller as u64 & 1)
}
/// `BXT_BLC_PWM_FREQ(controller)`.
pub const fn bxt_blc_pwm_freq(controller: u8) -> u64 {
    bxt_blc_pwm_ctl(controller) + 4
}
/// `BXT_BLC_PWM_DUTY(controller)`.
pub const fn bxt_blc_pwm_duty(controller: u8) -> u64 {
    bxt_blc_pwm_ctl(controller) + 8
}

/// Which PWM block drives the panel's backlight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PwmLayout {
    /// None installed: the PWM is left alone.
    None,
    /// The south display's PWM (`spt_pwm_funcs` / `lpt_*_backlight`).
    Spt,
    /// Gen9 LP's PWM on a VBT controller (`bxt_pwm_funcs`).
    Bxt(u8),
}

/// The PWM as the suspend found it: what `*_enable_backlight` restores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pwm {
    /// Nothing to restore (no PWM, or it was not running).
    None,
    /// `lpt_enable_backlight`'s inputs.
    Spt {
        period: u32,
        duty: u32,
        active_low: bool,
        alternate_increment: bool,
    },
    /// `bxt_enable_backlight`'s inputs.
    Bxt {
        controller: u8,
        period: u32,
        duty: u32,
        active_low: bool,
        util_active_low: bool,
    },
}

fn read(regs: &dyn MmioWindow, reg: u64) -> Result<u32, Gen9SuspendError> {
    let value = regs.read32(reg);
    if value == u32::MAX || !regs.display_access_ok() {
        Err(Gen9SuspendError::Unavailable)
    } else {
        Ok(value)
    }
}

/// Record the running PWM (`lpt_setup_backlight` / `bxt_setup_backlight`'s
/// readout): its period, duty and polarity. A PWM that is not enabled, or
/// has no period, records [`Pwm::None`].
pub fn pwm_save(regs: &dyn MmioWindow, layout: PwmLayout) -> Result<Pwm, Gen9SuspendError> {
    match layout {
        PwmLayout::None => Ok(Pwm::None),
        PwmLayout::Spt => {
            let ctl1 = read(regs, BLC_PWM_PCH_CTL1)?;
            let ctl2 = read(regs, BLC_PWM_PCH_CTL2)?;
            let chicken = read(regs, SOUTH_CHICKEN1)?;
            if ctl1 & BLM_PCH_PWM_ENABLE == 0 || ctl2 >> 16 == 0 {
                return Ok(Pwm::None);
            }
            Ok(Pwm::Spt {
                period: ctl2 >> 16,
                duty: ctl2 & 0xffff,
                active_low: ctl1 & BLM_PCH_POLARITY != 0,
                alternate_increment: chicken & SPT_PWM_GRANULARITY != 0,
            })
        }
        PwmLayout::Bxt(controller) => {
            let controller = controller & 1;
            let ctl = read(regs, bxt_blc_pwm_ctl(controller))?;
            let period = read(regs, bxt_blc_pwm_freq(controller))?;
            let duty = read(regs, bxt_blc_pwm_duty(controller))?;
            let util = if controller == 1 {
                read(regs, UTIL_PIN_CTL)?
            } else {
                0
            };
            if ctl & BXT_BLC_PWM_ENABLE == 0 || period == 0 {
                return Ok(Pwm::None);
            }
            Ok(Pwm::Bxt {
                controller,
                period,
                duty,
                active_low: ctl & BXT_BLC_PWM_POLARITY != 0,
                util_active_low: util & UTIL_PIN_POLARITY != 0,
            })
        }
    }
}

/// `intel_backlight_disable` at level 0: `lpt_disable_backlight` (the duty
/// to 0, a CPU PWM left by firmware disabled, the PCH PWM disabled) or
/// `bxt_disable_backlight` (the duty to 0, the PWM disabled, and controller
/// 1's utility pin).
pub fn pwm_disable(regs: &dyn MmioWindow, pwm: &Pwm) {
    match *pwm {
        Pwm::None => {}
        Pwm::Spt { .. } => {
            let ctl2 = regs.read32(BLC_PWM_PCH_CTL2);
            regs.write32(BLC_PWM_PCH_CTL2, ctl2 & !0xffff);
            let cpu = regs.read32(BLC_PWM_CPU_CTL2);
            if cpu & BLM_PWM_ENABLE != 0 {
                regs.write32(BLC_PWM_CPU_CTL2, cpu & !BLM_PWM_ENABLE);
            }
            let ctl1 = regs.read32(BLC_PWM_PCH_CTL1);
            regs.write32(BLC_PWM_PCH_CTL1, ctl1 & !BLM_PCH_PWM_ENABLE);
        }
        Pwm::Bxt { controller, .. } => {
            regs.write32(bxt_blc_pwm_duty(controller), 0);
            let ctl = regs.read32(bxt_blc_pwm_ctl(controller));
            regs.write32(bxt_blc_pwm_ctl(controller), ctl & !BXT_BLC_PWM_ENABLE);
            if controller == 1 {
                let util = regs.read32(UTIL_PIN_CTL);
                regs.write32(UTIL_PIN_CTL, util & !UTIL_PIN_ENABLE);
            }
        }
    }
}

/// `intel_backlight_enable` with the recorded inputs:
/// `lpt_enable_backlight` (a running PWM disabled first, the granularity,
/// the period, the polarity, the enable after a posting read, then the duty)
/// or `bxt_enable_backlight` (controller 1's utility pin on Pipe A in PWM
/// mode, a running PWM disabled first, the period, the duty, the polarity,
/// then the enable after a posting read).
pub fn pwm_enable(regs: &dyn MmioWindow, pwm: &Pwm) {
    match *pwm {
        Pwm::None => {}
        Pwm::Spt {
            period,
            duty,
            active_low,
            alternate_increment,
        } => {
            let ctl1 = regs.read32(BLC_PWM_PCH_CTL1);
            if ctl1 & BLM_PCH_PWM_ENABLE != 0 {
                regs.write32(BLC_PWM_PCH_CTL1, ctl1 & !BLM_PCH_PWM_ENABLE);
            }
            let chicken = regs.read32(SOUTH_CHICKEN1);
            let want = if alternate_increment {
                chicken | SPT_PWM_GRANULARITY
            } else {
                chicken & !SPT_PWM_GRANULARITY
            };
            if want != chicken {
                regs.write32(SOUTH_CHICKEN1, want);
            }
            regs.write32(BLC_PWM_PCH_CTL2, period << 16);
            let ctl1 = if active_low { BLM_PCH_POLARITY } else { 0 };
            regs.write32(BLC_PWM_PCH_CTL1, ctl1);
            let _ = regs.read32(BLC_PWM_PCH_CTL1);
            regs.write32(BLC_PWM_PCH_CTL1, ctl1 | BLM_PCH_PWM_ENABLE);
            // lpt_set_backlight: "This won't stick until the above enable."
            let ctl2 = regs.read32(BLC_PWM_PCH_CTL2);
            regs.write32(BLC_PWM_PCH_CTL2, (ctl2 & !0xffff) | (duty & 0xffff));
        }
        Pwm::Bxt {
            controller,
            period,
            duty,
            active_low,
            util_active_low,
        } => {
            if controller == 1 {
                let util = regs.read32(UTIL_PIN_CTL);
                if util & UTIL_PIN_ENABLE != 0 {
                    regs.write32(UTIL_PIN_CTL, util & !UTIL_PIN_ENABLE);
                }
                let polarity = if util_active_low { UTIL_PIN_POLARITY } else { 0 };
                // UTIL_PIN_PIPE(PIPE_A) is 0.
                regs.write32(
                    UTIL_PIN_CTL,
                    polarity | UTIL_PIN_MODE_PWM | UTIL_PIN_ENABLE,
                );
            }
            let ctl = regs.read32(bxt_blc_pwm_ctl(controller));
            if ctl & BXT_BLC_PWM_ENABLE != 0 {
                regs.write32(bxt_blc_pwm_ctl(controller), ctl & !BXT_BLC_PWM_ENABLE);
            }
            regs.write32(bxt_blc_pwm_freq(controller), period);
            regs.write32(bxt_blc_pwm_duty(controller), duty);
            let ctl = if active_low { BXT_BLC_PWM_POLARITY } else { 0 };
            regs.write32(bxt_blc_pwm_ctl(controller), ctl);
            let _ = regs.read32(bxt_blc_pwm_ctl(controller));
            regs.write32(bxt_blc_pwm_ctl(controller), ctl | BXT_BLC_PWM_ENABLE);
        }
    }
}

// ── The panel's crtc off (`hsw_crtc_disable` for eDP on DDI A) ───

/// One step of the panel's crtc disable that did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelOffStep {
    /// A transcoder's state did not clear (`intel_disable_transcoder`'s
    /// 100 ms wait).
    Transcoder,
    /// DDI A's buffer did not go idle (`intel_wait_ddi_buf_idle`).
    DdiBuffer,
    /// Gen9 LP's port A PLL did not power down (`bxt_ddi_pll_disable`).
    PortPll,
}

/// Why the Gen9 suspend owner refused or stopped. Every refusal of the
/// preparation leaves the panel relit and the suspend aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gen9SuspendError {
    /// A register read all-ones: the function is not in D0, or access was
    /// revoked.
    Unavailable,
    /// The `DC_off` service could not exit DC states.
    DcOff,
    /// The KMS owner did not restore its console or close admission.
    Kms,
    /// An external route is still live.
    ExternalRoute,
    /// A step of the panel-off did not complete.
    PanelOff(PanelOffStep),
    /// The panel power sequencer did not complete its sequence.
    Pps(PpsError),
    /// A pipe still reads lit after the panel-off: `reg` and its value
    /// (`TRANSCONF`, or Gen9 LP's `BXT_MIPI_PORT_CTRL`).
    StillLit { reg: u64, value: u32 },
    /// The device's master interrupt stayed enabled
    /// (`GEN8_MASTER_IRQ_CONTROL`).
    InterruptsLive(u32),
    /// PCI configuration could not be saved.
    Pci,
    /// The resume's display-core init stopped.
    CoreInit(CoreInitError),
    /// The DMC program did not reload after the resume: the Gen9 modeset
    /// requires it, so the panel stays dark.
    DmcReload,
    /// The relight modeset failed.
    Relight,
}

/// The panel facts the owner works from, fixed at probe.
#[derive(Clone, Copy, Debug)]
pub struct Panel {
    pub platform: Gen9Platform,
    /// The sequencer delays decoded at probe (`pps_init_delays`).
    pub delays: PanelDelays,
    pub pwm: PwmLayout,
    /// The probe-time DMC container and its payload ceiling, for the
    /// resume's `intel_dmc_load_program`.
    pub dmc: Option<(&'static [u8], usize)>,
}

impl Panel {
    fn lp(&self) -> bool {
        self.platform.is_lp()
    }
    fn glk(&self) -> bool {
        self.platform == Gen9Platform::GeminiLake
    }
    fn broxton(&self) -> bool {
        self.platform == Gen9Platform::Broxton
    }
}

/// What the preparation recorded for the resume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Saved {
    /// The PWM as found.
    pub pwm: Pwm,
    /// Display 9 proper: DPLL0's VCO (`skl_preferred_vco_freq`); 0 when off
    /// or on Gen9 LP.
    pub vco: u32,
}

/// A refused preparation and the PWM it had recorded, which the relight
/// that undoes it restores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub error: Gen9SuspendError,
    pub pwm: Pwm,
    /// Whether the panel-off had started (the panel needs the relight);
    /// otherwise the panel is as it was.
    pub touched: bool,
}

/// `PLANE_CTL_1_A`, `_2_A`, `_3_A` (`skl_universal_plane_regs.h`); each
/// plane's `PLANE_SURF` is at +0x1C.
const PLANE_CTL_A: [u64; 3] = [0x70180, 0x70280, 0x70380];
/// `CURCNTR(PIPE_A)` / `CURBASE(PIPE_A)` and `MCURSOR_MODE_MASK`.
const CURCNTR_A: u64 = 0x70080;
const CURBASE_A: u64 = 0x70084;
const MCURSOR_MODE_MASK: u32 = 0x27;
/// `TRANSCONF(TRANSCODER_EDP)` and the Pipe A `TRANSCONF` beside it.
const TRANSCONF_EDP: u64 = 0x7f008;
const TRANSCONF_A: u64 = 0x70008;
/// `TRANSCONF_STATE_ENABLE`.
const TRANSCONF_STATE: u32 = 1 << 30;
/// `TRANS_DDI_FUNC_CTL(TRANSCODER_EDP)`.
const TRANS_DDI_FUNC_CTL_EDP: u64 = 0x6f400;
/// `intel_ddi_disable_transcoder_func` on display 9/10: `TRANS_DDI_FUNC_ENABLE`,
/// `TRANS_DDI_PORT_MASK` (7 << 28), `TRANS_DDI_MODE_SELECT_MASK` (7 << 24),
/// `TRANS_DDI_PORT_SYNC_MASTER_SELECT_MASK` (19:18) and
/// `TRANS_DDI_PORT_SYNC_ENABLE` (bit 15).
const TRANS_DDI_FUNC_CLEAR: u32 = (1 << 31) | (7 << 28) | (7 << 24) | (3 << 18) | (1 << 15);
/// `DDI_BUF_CTL(PORT_A)` and `DP_TP_CTL(PORT_A)` with their enables.
const DDI_BUF_CTL_A: u64 = 0x64000;
const DP_TP_CTL_A: u64 = 0x64040;
const DDI_BUF_IS_IDLE: u32 = 1 << 7;
/// `DP_SET_POWER` = `DP_SET_POWER_D3` (`intel_dp_set_power`).
const DP_SET_POWER: u32 = 0x600;
const DP_SET_POWER_D3: u8 = 0x2;

fn wait_clear(regs: &dyn MmioWindow, reg: u64, bit: u32, us: u64) -> Result<bool, Gen9SuspendError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let value = regs.read32(reg);
            lost = value == u32::MAX || !regs.display_access_ok();
            lost || value & bit == 0
        },
        narf_time::Deadline::after_us(us),
    );
    if lost {
        Err(Gen9SuspendError::Unavailable)
    } else {
        Ok(done)
    }
}

/// `intel_crtc_disable_planes` on Pipe A: every enabled universal plane off
/// (`skl_plane_disable_arm`: `PLANE_CTL` then `PLANE_SURF` zero) and the
/// cursor (`i9xx_cursor_disable_arm`: its mode cleared, `CURBASE` rewritten
/// to arm it).
fn disable_planes(regs: &dyn MmioWindow) -> Result<(), Gen9SuspendError> {
    for ctl in PLANE_CTL_A {
        if read(regs, ctl)? & crate::intel_gpu_pipes::PLANE_CTL_ENABLE != 0 {
            regs.write32(ctl, 0);
            regs.write32(ctl + crate::intel_gpu_pipes::PLANE_SURF_OFFSET, 0);
        }
    }
    let cursor = read(regs, CURCNTR_A)?;
    if cursor & MCURSOR_MODE_MASK != 0 {
        regs.write32(CURCNTR_A, cursor & !MCURSOR_MODE_MASK);
        let base = read(regs, CURBASE_A)?;
        regs.write32(CURBASE_A, base);
    }
    Ok(())
}

/// `intel_disable_transcoder` for the eDP transcoder, then the Pipe A
/// `TRANSCONF` the modeset enabled beside it: the enable cleared, the state
/// waited out for 100 ms each.
fn disable_transcoders(regs: &dyn MmioWindow) -> Result<(), Gen9SuspendError> {
    for reg in [TRANSCONF_EDP, TRANSCONF_A] {
        let conf = read(regs, reg)?;
        if conf & dc::TRANSCONF_ENABLE == 0 && conf & TRANSCONF_STATE == 0 {
            continue;
        }
        regs.write32(reg, conf & !dc::TRANSCONF_ENABLE);
        if !wait_clear(regs, reg, TRANSCONF_STATE, 100_000)? {
            return Err(Gen9SuspendError::PanelOff(PanelOffStep::Transcoder));
        }
    }
    Ok(())
}

/// `intel_ddi_buf_disable` on DDI A: the buffer and `DP_TP_CTL` disabled,
/// then `intel_wait_ddi_buf_idle` (a fixed 16 us on Broxton, otherwise
/// `DDI_BUF_IS_IDLE` within 10 ms).
fn disable_ddi_buffer(regs: &dyn MmioWindow, panel: &Panel) -> Result<(), Gen9SuspendError> {
    let buf = read(regs, DDI_BUF_CTL_A)?;
    regs.write32(DDI_BUF_CTL_A, buf & !crate::intel_gpu_ddi::DDI_BUF_CTL_ENABLE);
    let tp = read(regs, DP_TP_CTL_A)?;
    regs.write32(DP_TP_CTL_A, tp & !(1 << 31));
    if panel.broxton() {
        let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(16));
        return Ok(());
    }
    let mut lost = false;
    let idle = narf_scheduler::responsive_spin_until(
        || {
            let value = regs.read32(DDI_BUF_CTL_A);
            lost = value == u32::MAX;
            lost || value & DDI_BUF_IS_IDLE != 0
        },
        narf_time::Deadline::after_us(10_000),
    );
    match (lost, idle) {
        (true, _) => Err(Gen9SuspendError::Unavailable),
        (false, true) => Ok(()),
        (false, false) => Err(Gen9SuspendError::PanelOff(PanelOffStep::DdiBuffer)),
    }
}

/// The eDP panel's crtc off with the PWM already recorded, in
/// `hsw_crtc_disable`'s order for an eDP encoder on DDI A:
/// `intel_crtc_disable_planes`; `intel_edp_backlight_off` (the PPS gate
/// closed with its T9 wait, then `intel_backlight_disable`);
/// `intel_disable_transcoder`, `intel_ddi_disable_transcoder_func` and
/// `skl_scaler_disable`; `intel_ddi_post_disable_dp` (the sink to D3 over
/// AUX, best effort as in Linux; `intel_ddi_buf_disable`;
/// `intel_pps_vdd_on` then `intel_pps_off`; `skl_ddi_disable_clock`); then
/// Gen9 LP's port PLL (`bxt_ddi_pll_disable`; display 9's eDP DPLL0 disable
/// is empty).
pub fn panel_off(regs: &dyn MmioWindow, panel: &Panel, pwm: &Pwm) -> Result<(), Gen9SuspendError> {
    disable_planes(regs)?;
    let pps_window = crate::intel_gpu_bxt_display::PpsWindow::new(regs, panel.lp());
    let mut pps = PanelPowerSequencer::with_delays(&pps_window, panel.delays);
    pps.backlight_off();
    pwm_disable(regs, pwm);
    disable_transcoders(regs)?;
    let func = read(regs, TRANS_DDI_FUNC_CTL_EDP)?;
    regs.write32(TRANS_DDI_FUNC_CTL_EDP, func & !TRANS_DDI_FUNC_CLEAR);
    for id in 0..crate::intel_gpu_xelpg_scaler::display9_scalers(Pipe::A) {
        let ctrl = crate::intel_gpu_xelpg_scaler::ps_ctrl(Pipe::A, id);
        if read(regs, ctrl)? & crate::intel_gpu_xelpg_scaler::PS_SCALER_EN != 0 {
            regs.write32(ctrl, 0);
            regs.write32(crate::intel_gpu_xelpg_scaler::ps_win_pos(Pipe::A, id), 0);
            regs.write32(crate::intel_gpu_xelpg_scaler::ps_win_sz(Pipe::A, id), 0);
        }
    }
    {
        use crate::dp_aux::AuxChannel as _;
        let mut aux = crate::intel_gpu_aux::IntelAux::new(regs, Ddi::A);
        let _ = aux.dpcd_write(DP_SET_POWER, &[DP_SET_POWER_D3]);
    }
    disable_ddi_buffer(regs, panel)?;
    pps.vdd_on_then_off().map_err(Gen9SuspendError::Pps)?;
    if panel.lp() {
        crate::intel_gpu_bxt_dpll::disable(regs, panel.glk(), crate::intel_gpu_bxt_phy::Port::A)
            .map_err(|_| Gen9SuspendError::PanelOff(PanelOffStep::PortPll))?;
    } else {
        crate::intel_gpu_gen9_dpll::disable_clock(regs, Ddi::A);
    }
    Ok(())
}

/// `intel_irq_suspend`'s `gen8_master_intr_disable`: the device can raise
/// no interrupt once `GEN8_MASTER_IRQ_CONTROL` reads clear.
pub fn quiesce_interrupts(regs: &dyn MmioWindow) -> Result<(), Gen9SuspendError> {
    use crate::intel_gpu_gen9_irq::{GEN8_MASTER_IRQ, GEN8_MASTER_IRQ_CONTROL};
    read(regs, GEN8_MASTER_IRQ)?;
    regs.write32(GEN8_MASTER_IRQ, 0);
    let after = read(regs, GEN8_MASTER_IRQ)?;
    if after & GEN8_MASTER_IRQ_CONTROL != 0 {
        return Err(Gen9SuspendError::InterruptsLive(after));
    }
    Ok(())
}

fn lit(block: Dc9Block) -> Gen9SuspendError {
    match block {
        Dc9Block::DisplayActive { reg, value } | Dc9Block::DsiActive { reg, value } => {
            Gen9SuspendError::StillLit { reg, value }
        }
        Dc9Block::DsiPllUnverified(value) => Gen9SuspendError::StillLit {
            reg: dc::BXT_DSI_PLL_CTL,
            value,
        },
        _ => Gen9SuspendError::Unavailable,
    }
}

/// The preparation's register half, after the KMS owner closed admission
/// and every external route stopped: the `DC_off` Suspend reference (DC
/// states off through the resume), DPLL0's VCO recorded, the PWM recorded,
/// [`panel_off`], the dark check (every transcoder and, on Gen9 LP, the DSI
/// ports) and [`quiesce_interrupts`]. A refusal drops the Suspend reference
/// again; when it is `touched`, the caller relights the panel with the
/// returned PWM.
pub fn prepare(
    regs: &dyn MmioWindow,
    panel: &Panel,
    dc_off: &dyn Gen9DcSuspend,
    now: u64,
) -> Result<Saved, Refusal> {
    if dc_off.suspend_begin(regs).is_err() {
        return Err(Refusal {
            error: Gen9SuspendError::DcOff,
            pwm: Pwm::None,
            touched: false,
        });
    }
    let refuse = |error, pwm, touched| {
        dc_off.suspend_abort(now);
        Refusal {
            error,
            pwm,
            touched,
        }
    };
    let vco = if panel.lp() {
        0
    } else {
        crate::intel_gpu_gen9_cdclk::Current::read(regs).map_or(0, |hw| hw.vco)
    };
    let pwm = pwm_save(regs, panel.pwm).map_err(|error| refuse(error, Pwm::None, false))?;
    panel_off(regs, panel, &pwm).map_err(|error| refuse(error, pwm, true))?;
    dc::display_dark(regs, panel.lp(), panel.broxton())
        .map_err(|block| refuse(lit(block), pwm, true))?;
    quiesce_interrupts(regs).map_err(|error| refuse(error, pwm, true))?;
    Ok(Saved { pwm, vco })
}

/// What the late suspend did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LateOutcome {
    /// Gen9 LP: the display core uninitialized and DC9 entered.
    Dc9,
    /// The display core uninitialized; DC states off (DC0). Gen9 LP without
    /// a `DC_off` service ends here (DC9 is the service's).
    Uninit,
    /// Display 9 proper into suspend-to-idle with a DMC payload: the core is
    /// kept and the DMC stays active (`intel_power_domains_suspend`).
    Kept,
    /// The admission refused before any write; the core is as it was (DC0).
    Refused(Dc9Block),
    /// The uninit stopped part way; the resume's display-core init restores
    /// the core.
    UninitFailed(CoreInitError),
    /// Gen9 LP: the uninit completed but the DC9 write refused (DC0).
    Dc9Refused(Dc9Block),
}

/// The late suspend (`intel_display_power_suspend_late`), in the device-PM
/// fan-out with interrupts gated, after [`prepare`]: on Gen9 LP the DC9
/// admission (`assert_can_enable_dc9` as refusals, the dark display, no other
/// holder), the DPIO PHYs powered down (the `dpio-common` wells, released
/// with the last domain at `intel_power_domains_suspend`),
/// `bxt_display_core_uninit` and `bxt_enable_dc9`; on display 9 proper, unless
/// suspend-to-idle keeps a DMC-driven core, `skl_display_core_uninit`.
/// Nothing here aborts the suspend.
pub fn suspend_late(
    regs: &dyn MmioWindow,
    panel: &Panel,
    target: SystemSleepState,
    dmc: bool,
    dc_off: &dyn Gen9DcSuspend,
) -> LateOutcome {
    let service = dc_off.present();
    if panel.lp() {
        let admitted = if service {
            dc_off.dc9_admit(regs)
        } else {
            dc::display_dark(regs, true, panel.broxton())
        };
        if let Err(block) = admitted {
            dc_off.dc9_abort();
            return LateOutcome::Refused(block);
        }
        for (phy, _) in crate::intel_gpu_bxt_phy::phys(panel.glk()) {
            if crate::intel_gpu_bxt_phy::is_enabled(regs, panel.glk(), *phy) {
                crate::intel_gpu_bxt_phy::uninit(regs, panel.glk(), *phy);
            }
        }
        if let Err(error) = dc::display_core_uninit_lp(regs, panel.glk()) {
            dc_off.dc9_abort();
            return LateOutcome::UninitFailed(error);
        }
        if !service {
            return LateOutcome::Uninit;
        }
        return match dc_off.enter_dc9(regs) {
            Ok(()) => LateOutcome::Dc9,
            Err(block) => {
                dc_off.dc9_abort();
                LateOutcome::Dc9Refused(block)
            }
        };
    }
    if target == SystemSleepState::S0Idle && dmc {
        return LateOutcome::Kept;
    }
    let admitted = if service {
        dc_off.uninit_admit(regs)
    } else {
        dc::display_dark(regs, false, false)
    };
    if let Err(block) = admitted {
        return LateOutcome::Refused(block);
    }
    match dc::display_core_uninit_skl(regs, panel.platform) {
        Ok(_) => LateOutcome::Uninit,
        Err(error) => LateOutcome::UninitFailed(error),
    }
}

/// The early resume (`intel_display_power_resume_early`), in the device-PM
/// fan-out: `gen9_sanitize_dc_state` and `bxt_disable_dc9` or the
/// display-core init's `DC_STATE_DISABLE`, then (unless the late suspend
/// kept the core, or never ran) the rest of `skl_display_core_init` /
/// `bxt_display_core_init` at the recorded VCO and `intel_dmc_load_program`
/// from the probe's container. `Ok` means a verified program: the relight
/// may run.
pub fn resume_early(
    regs: &dyn MmioWindow,
    panel: &Panel,
    saved: &Saved,
    late: Option<LateOutcome>,
    dc_off: &dyn Gen9DcSuspend,
) -> Result<(), Gen9SuspendError> {
    if dc_off.present() {
        dc_off
            .resume_begin(regs)
            .map_err(|_| Gen9SuspendError::DcOff)?;
    } else {
        let mut state = if panel.lp() {
            dc::Gen9Dc::new_lp()
        } else {
            dc::Gen9Dc::new()
        };
        state
            .sanitize(regs)
            .and_then(|()| state.disable(regs))
            .map_err(|_| Gen9SuspendError::DcOff)?;
    }
    if matches!(late, None | Some(LateOutcome::Kept)) {
        return Ok(());
    }
    dc::display_core_init(regs, panel.platform, saved.vco).map_err(Gen9SuspendError::CoreInit)?;
    let loaded = panel
        .dmc
        .is_some_and(|(blob, max)| dc::reload_program(regs, blob, max));
    if !loaded {
        return Err(Gen9SuspendError::DmcReload);
    }
    Ok(())
}

/// The relight (`intel_display_driver_resume` committing the panel again,
/// in the probe's order): on Gen9 LP the DPIO PHYs of every port powered
/// (`power_port`, as probe does), the sequencer's registers reprogrammed
/// from the probe delays (`pps_init_registers`) and the panel powered
/// (`intel_pps_on`), `light` (the panel modeset at the probe mode), then
/// `intel_edp_backlight_on`: the PWM restored (`intel_backlight_enable`),
/// then the PPS gate after T8.
pub fn relight(
    regs: &dyn MmioWindow,
    panel: &Panel,
    saved: &Saved,
    light: impl FnOnce() -> bool,
) -> Result<(), Gen9SuspendError> {
    if panel.lp() {
        use crate::intel_gpu_bxt_phy::Port;
        for port in [Port::A, Port::B, Port::C] {
            let _ = crate::intel_gpu_bxt_display::power_port(regs, panel.glk(), port);
        }
    }
    let pps_window = crate::intel_gpu_bxt_display::PpsWindow::new(regs, panel.lp());
    let mut pps = PanelPowerSequencer::with_delays(&pps_window, panel.delays);
    pps.init_registers();
    pps.power_on().map_err(Gen9SuspendError::Pps)?;
    if !light() {
        return Err(Gen9SuspendError::Relight);
    }
    pwm_enable(regs, &saved.pwm);
    pps.backlight_on().map_err(Gen9SuspendError::Pps)
}

/// The resume's last half: [`relight`] when the early resume verified the
/// program (`early`), then the `DC_off` Suspend reference released with
/// that outcome (DC states return 17 ms later only with a verified
/// program).
pub fn resume_late(
    regs: &dyn MmioWindow,
    panel: &Panel,
    saved: &Saved,
    early: Result<(), Gen9SuspendError>,
    dc_off: &dyn Gen9DcSuspend,
    now: u64,
    light: impl FnOnce() -> bool,
) -> Result<(), Gen9SuspendError> {
    let loaded = early.is_ok();
    let relit = early.and_then(|()| relight(regs, panel, saved, light));
    dc_off.resume_finish(loaded, now);
    relit
}

// ── Production owner ────────────────────────────────────────────

const PM_NAME: &str = "intel-gen9-suspend";

/// The owned panel of one Gen9 function.
struct Installed {
    bar: narf_bus::MmioRegion,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    window: crate::intel_gpu_gt_hw::AuthorizedWindow,
    panel: Panel,
    mode: crate::intel_gpu_modeset::Mode,
    state: IrqSafeSpinLock<Transition>,
}

/// One system-sleep transition's progress.
#[derive(Default)]
struct Transition {
    target: Option<SystemSleepState>,
    /// The preparation completed: the panel is off.
    saved: Option<Saved>,
    pci: Option<narf_bus::pci::SavedPciConfig>,
    late: Option<LateOutcome>,
    early: Option<Result<(), Gen9SuspendError>>,
}

static OWNER: IrqSafeSpinLock<Option<Arc<Installed>>> = IrqSafeSpinLock::new(None);

fn owner() -> Option<Arc<Installed>> {
    OWNER.lock().clone()
}

fn log(text: &str) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "intel-gpu: {text}");
}

/// The panel's PWM block: the south display's on display 9 proper, the
/// VBT's controller on Gen9 LP, as probe installs the backlight.
fn pwm_layout(platform: Gen9Platform) -> PwmLayout {
    if platform.is_lp() {
        PwmLayout::Bxt(crate::intel_gpu_vbt::gen9_lp().backlight_controller)
    } else {
        PwmLayout::Spt
    }
}

/// Whether an owner may be installed: the option set, a Gen9 display
/// (`gen9_family_for_chip`) and an owned panel mode. Writes nothing.
pub fn admit(
    opted_in: bool,
    chip: crate::intel_gpu::ChipInfo,
    mode: Option<crate::intel_gpu_modeset::Mode>,
) -> Option<(Gen9Platform, crate::intel_gpu_modeset::Mode)> {
    if !opted_in {
        return None;
    }
    Some((crate::intel_gpu_modeset::gen9_family_for_chip(chip)?, mode?))
}

/// End of probe, with the internal panel owned at `mode`: with
/// `narf.intel.gen9_suspend=1`, install the owner for this Gen9 display,
/// hand it the `DC_off` service's system-suspend steps and register its
/// system-PM and device-PM participants. Without the option (or on any
/// other display) nothing is installed and nothing is written. Returns
/// whether an owner was installed.
pub(crate) fn install(
    opted_in: bool,
    chip: crate::intel_gpu::ChipInfo,
    bar: narf_bus::MmioRegion,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    mode: Option<crate::intel_gpu_modeset::Mode>,
) -> bool {
    let Some((platform, mode)) = admit(opted_in, chip, mode) else {
        return false;
    };
    let mut slot = OWNER.lock();
    if slot.is_some() {
        return false;
    }
    let panel = Panel {
        platform,
        delays: crate::intel_gpu_edp::panel_delays(),
        pwm: pwm_layout(platform),
        dmc: crate::intel_gpu_gen9_dmc::resident_program()
            .filter(|_| crate::intel_gpu_gen9_dmc::gen9_dmc_loaded()),
    };
    *slot = Some(Arc::new(Installed {
        bar,
        device,
        cap,
        window: crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap),
        panel,
        mode,
        state: IrqSafeSpinLock::new(Transition::default()),
    }));
    drop(slot);
    dc::hand_suspend_to_owner(&bar);
    narf_power::system_pm::register_async_system_pm(PM_NAME, Arc::new(SystemPm));
    narf_power::device_pm::register_device_pm_ops(PM_NAME, Arc::new(SystemPm));
    log("Gen9 display suspend owner installed: the panel turns off for system sleep");
    true
}

/// Reopen KMS over the unchanged console after a preparation that stopped
/// before touching the panel.
fn reopen_kms(bar: &narf_bus::MmioRegion) {
    let (Some(display), Some(console)) = (
        crate::intel_gpu_kms::display_for_bar(bar),
        crate::intel_gpu::with_controller(|gpu| gpu.current_mode()).flatten(),
    ) else {
        return;
    };
    let guard = display.legacy();
    if let Ok(mut guard) = guard {
        guard.console_replaced(&console);
    }
}

/// The production relight: [`relight`] with the controller's panel modeset
/// (`relight_display`: a fresh scanout, the modeset at the probe mode, KMS
/// reopened on the new console).
fn relight_installed(owner: &Installed, saved: &Saved) -> Result<(), Gen9SuspendError> {
    let mode = owner.mode;
    let result = relight(&owner.window, &owner.panel, saved, || {
        crate::intel_gpu::relight_display(&mode).is_some()
    });
    // The sequencer was reprogrammed here: a DC9 excursion's PPS reset is
    // consumed.
    let _ = dc::take_pps_reset_for_bar(&owner.bar);
    result
}

fn error_text(error: Gen9SuspendError) -> &'static str {
    match error {
        Gen9SuspendError::Unavailable => "the display registers are unavailable",
        Gen9SuspendError::DcOff => "DC states could not be exited",
        Gen9SuspendError::Kms => "KMS did not close admission",
        Gen9SuspendError::ExternalRoute => "an external route is still live",
        Gen9SuspendError::PanelOff(_) => "a step of the panel-off did not complete",
        Gen9SuspendError::Pps(_) => "the panel power sequence did not complete",
        Gen9SuspendError::StillLit { .. } => "a pipe still reads lit",
        Gen9SuspendError::InterruptsLive(_) => "the device interrupts stayed enabled",
        Gen9SuspendError::Pci => "PCI configuration could not be saved",
        Gen9SuspendError::CoreInit(_) => "the display-core init did not complete",
        Gen9SuspendError::DmcReload => "the DMC program did not reload",
        Gen9SuspendError::Relight => "the panel modeset failed",
    }
}

async fn prepare_installed(target: SystemSleepState) -> Result<(), Gen9SuspendError> {
    let Some(owner) = owner() else {
        return Ok(());
    };
    // drm_atomic_helper_suspend's admission: the KMS owner restores its
    // console and closes; every external route retires.
    crate::intel_gpu_kms::quiesce_for_legacy(&owner.bar)
        .await
        .map_err(|_| Gen9SuspendError::Kms)?;
    if !crate::intel_gpu::external_routes_stopped(&owner.bar) {
        reopen_kms(&owner.bar);
        return Err(Gen9SuspendError::ExternalRoute);
    }
    let dc_off = dc::ServiceDcSuspend { bar: owner.bar };
    let saved = match prepare(&owner.window, &owner.panel, &dc_off, narf_time::monotonic_ns()) {
        Ok(saved) => saved,
        Err(refusal) => {
            if !refusal.touched {
                reopen_kms(&owner.bar);
                return Err(refusal.error);
            }
            let undo = Saved {
                pwm: refusal.pwm,
                vco: 0,
            };
            if relight_installed(&owner, &undo).is_err() {
                log("Gen9 display suspend: the panel did not relight after a refused suspend");
            }
            return Err(refusal.error);
        }
    };
    let pci = match narf_bus::pci::save_config(&owner.cap, &owner.device) {
        Ok(pci) => pci,
        Err(_) => {
            dc_off.suspend_abort(narf_time::monotonic_ns());
            let _ = relight_installed(&owner, &saved);
            return Err(Gen9SuspendError::Pci);
        }
    };
    *owner.state.lock() = Transition {
        target: Some(target),
        saved: Some(saved),
        pci: Some(pci),
        late: None,
        early: None,
    };
    log("Gen9 display suspend: the panel is off");
    Ok(())
}

async fn resume_installed() -> Result<(), Gen9SuspendError> {
    let Some(owner) = owner() else {
        return Ok(());
    };
    let (saved, early) = {
        let mut state = owner.state.lock();
        let taken = core::mem::take(&mut *state);
        (taken.saved, taken.early)
    };
    let Some(saved) = saved else {
        return Ok(());
    };
    // Without the device-PM fan-out (a later preparation refused) nothing
    // was lost: the relight runs on the program still loaded.
    let early = early.unwrap_or(Ok(()));
    let dc_off = dc::ServiceDcSuspend { bar: owner.bar };
    let result = resume_late(
        &owner.window,
        &owner.panel,
        &saved,
        early,
        &dc_off,
        narf_time::monotonic_ns(),
        || {
            let mode = owner.mode;
            crate::intel_gpu::relight_display(&mode).is_some()
        },
    );
    let _ = dc::take_pps_reset_for_bar(&owner.bar);
    match result {
        Ok(()) => log("Gen9 display resume: the panel is relit"),
        Err(error) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu: Gen9 display resume: panel left dark: {}",
                error_text(error)
            );
        }
    }
    result
}

/// The owner's system-sleep participant.
#[derive(Debug)]
struct SystemPm;

impl narf_power::system_pm::AsyncSystemPm for SystemPm {
    fn prepare_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        self.prepare_suspend_target(SystemSleepState::S3)
    }
    fn prepare_suspend_target(
        &self,
        target: SystemSleepState,
    ) -> narf_power::system_pm::SystemPmFuture<'_> {
        Box::pin(async move {
            prepare_installed(target).await.map_err(|error| {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "intel-gpu: Gen9 display suspend refused: {}",
                    error_text(error)
                );
                narf_power::device_pm::DeviceSuspendError::Busy
            })
        })
    }
    fn resume_from_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        Box::pin(async {
            resume_installed()
                .await
                .map_err(|_| narf_power::device_pm::DeviceSuspendError::DriverError)
        })
    }
}

impl narf_power::device_pm::DevicePmOps for SystemPm {
    /// `intel_display_power_suspend_late`, interrupts gated. Refuses only a
    /// suspend whose asynchronous preparation did not turn the panel off.
    fn suspend(&self) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
        let Some(owner) = owner() else {
            return Ok(());
        };
        let (saved, target) = {
            let state = owner.state.lock();
            (state.saved, state.target)
        };
        if saved.is_none() {
            return Err(narf_power::device_pm::DeviceSuspendError::Busy);
        }
        let dc_off = dc::ServiceDcSuspend { bar: owner.bar };
        let outcome = suspend_late(
            &owner.window,
            &owner.panel,
            target.unwrap_or(SystemSleepState::S3),
            owner.panel.dmc.is_some(),
            &dc_off,
        );
        owner.state.lock().late = Some(outcome);
        log(match outcome {
            LateOutcome::Dc9 => "Gen9 LP display in DC9 for system suspend",
            LateOutcome::Uninit => "Gen9 display core uninitialized for system suspend",
            LateOutcome::Kept => "Gen9 display core kept for suspend-to-idle (DMC active)",
            LateOutcome::Refused(_) | LateOutcome::Dc9Refused(_) => {
                "Gen9 display core left as it is for system suspend; DC states held off"
            }
            LateOutcome::UninitFailed(_) => {
                "Gen9 display-core uninit did not complete; the resume restores it"
            }
        });
        Ok(())
    }
    /// `intel_display_power_resume_early`: PCI configuration restored, the
    /// DC exit, the display-core init and the DMC reload.
    fn resume(&self) -> Result<(), narf_power::device_pm::DeviceSuspendError> {
        let Some(owner) = owner() else {
            return Ok(());
        };
        let (saved, pci, late) = {
            let state = owner.state.lock();
            (state.saved, state.pci, state.late)
        };
        let Some(saved) = saved else {
            return Ok(());
        };
        if let Some(pci) = pci.as_ref() {
            let _ = narf_bus::pci::restore_config(&owner.cap, &owner.device, pci);
        }
        let dc_off = dc::ServiceDcSuspend { bar: owner.bar };
        let early = resume_early(&owner.window, &owner.panel, &saved, late, &dc_off);
        owner.state.lock().early = Some(early);
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_gen9_suspend_tests.rs"]
mod tests;
