//! Intel eDP panel power sequencing (PPS) + Panel Self Refresh
//! (PSR) — issue #1020, Intel GPU queue Q7.
//!
//! Two cooperating halves for the internal panel on DDI A:
//!
//! * **PPS** — the `PP_*` register conversation that raises panel
//!   VDD in the order the eDP spec mandates (T1–T12), programs the
//!   panel's power-cycle delays, gates the backlight on/off around
//!   the sequence, and enforces the T11+T12 power-cycle delay
//!   before a panel may be powered again. A panel that fails its
//!   sequence is left powered-down with a typed error — never
//!   half-sequenced, never backlit.
//! * **PSR** — PSR1/PSR2 per the eDP spec: capability decode from
//!   DPCD, sink setup over AUX (`DP_PSR_EN_CFG`, ALPM, set-power),
//!   source activation (`EDP_PSR_CTL` / `EDP_PSR2_CTL` on
//!   transcoder A), and the selective-update discipline for PSR2 —
//!   the SU region programmed into `PSR2_MAN_TRK_CTL` is the
//!   granularity-aligned dirtied region, not the full frame. A
//!   panel without PSR runs plain eDP with zero PSR traffic.
//!
//! ## Composition
//!
//! * Probe (`intel_gpu::probe`) runs the PPS power-on **before**
//!   `intel_gpu_modeset::takeover_display` (AUX/EDID traffic needs
//!   VDD) and gates `narf_drivers_backlight::intel_bl::install` on
//!   its success; the PPS backlight gate opens only after the
//!   takeover produced a mode. This is the seam PR #1037's
//!   backlight composition builds on: brightness-0 via
//!   `narf_drivers_backlight::panel_owner()` runs before the PPS
//!   backlight gate closes in [`panel_power_off`].
//! * PSR entry/exit is notification-driven, never polled:
//!   `intel_gpu::publish_scanout` calls [`on_scanout_published`]
//!   (a scanout publish is what exits PSR), and region-granular
//!   callers use [`notify_scanout_dirty`]. Q4's (#1114) session
//!   machinery drives flips through [`set_flip_pending`]; a dirty
//!   notification that arrives while a flip is pending is refused
//!   before any register is touched.
//!
//! ## References
//!
//! * VESA eDP 1.4b: DPCD PSR field (0x070–0x074, 0x116, 0x170,
//!   0x600, 0x2006–0x2009) and the T1–T12 power-sequence timings
//!   (upper limits from eDP 1.3 §"panel power sequencing", the
//!   same table i915's `pps_init_delays_spec` encodes).
//! * Intel Tiger Lake PRM Vol. 12 (display engine): PPS register
//!   block and PSR register blocks. Cross-checked against Linux
//!   `drivers/gpu/drm/i915/display/intel_pps_regs.h`,
//!   `intel_psr_regs.h`, `intel_pps.c`, `intel_psr.c` and
//!   `include/drm/display/drm_dp.h`.
//!
//! ## Platform notes (Gen12, PCH-split)
//!
//! * The PPS instance lives in the south-display block at
//!   `0xC7200` (i915 `PCH_PPS_BASE`; this driver's backlight PWM
//!   and `SOUTH_CHICKEN1` already live in the same block). One
//!   panel on DDI A → PPS index 0; TGL+ exposes a second instance
//!   at `+0x100` for a second eDP panel, out of scope here.
//! * On CNP-and-later PCH the power-cycle delay moved from
//!   `PP_DIVISOR` into `PP_CONTROL[8:4]` — there is no divisor
//!   register to write (i915 `intel_pps_get_registers`).
//! * The `PANEL_UNLOCK_REGS` key is a pre-DDI (≤CPT/PPT) concern;
//!   DDI platforms never lock the PPS registers (i915
//!   `intel_pps_unlock_regs_wa` returns early under `HAS_DDI`), so
//!   no unlock write is issued.
//! * Gen12 has no separate EDP transcoder: PSR registers are the
//!   transcoder-A instances (`EDP_PSR_CTL` = 0x60800, not the
//!   Haswell fixed block at 0x64800).

use narf_lib::sync::IrqSafeSpinLock;

use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxStatus};
use crate::intel_gpu::Generation;
use crate::intel_gpu_aux::{IntelAux, MmioWindow};
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_modeset::Mode;

// ── PPS register block (PCH instance 0) ─────────────────────────
//
// Layout per `intel_pps_regs.h`: STATUS +0x00, CONTROL +0x04,
// ON_DELAYS +0x08, OFF_DELAYS +0x0C, stride 0x100 per instance.

/// `PP_STATUS` — sequence state readback.
pub const PP_STATUS: u64 = 0xC_7200;
/// `PP_CONTROL` — power target, VDD force, backlight gate,
/// power-cycle delay field.
pub const PP_CONTROL: u64 = 0xC_7204;
/// `PP_ON_DELAYS` — T1+T3 (power-up) and T8 (light-on) delays.
pub const PP_ON_DELAYS: u64 = 0xC_7208;
/// `PP_OFF_DELAYS` — T10 (power-down) and T9 (light-off) delays.
pub const PP_OFF_DELAYS: u64 = 0xC_720C;

// PP_STATUS bits.
const PP_ON: u32 = 1 << 31;
const PP_SEQUENCE_MASK: u32 = 0x3 << 28;
const PP_SEQUENCE_NONE: u32 = 0 << 28;
const PP_CYCLE_DELAY_ACTIVE: u32 = 1 << 27;
const PP_SEQUENCE_STATE_MASK: u32 = 0xF;
const PP_SEQUENCE_STATE_OFF_IDLE: u32 = 0x0;
const PP_SEQUENCE_STATE_ON_IDLE: u32 = 0x8;

// PP_CONTROL bits / fields.
const PP_POWER_CYCLE_DELAY_MASK: u32 = 0x1F << 4;
const PP_POWER_CYCLE_DELAY_SHIFT: u32 = 4;
const EDP_FORCE_VDD: u32 = 1 << 3;
const EDP_BLC_ENABLE: u32 = 1 << 2;
const PANEL_POWER_ON: u32 = 1 << 0;

// Delay fields (all in 100 µs units, per the PRM).
const PANEL_POWER_UP_DELAY_MASK: u32 = 0x1FFF << 16;
const PANEL_LIGHT_ON_DELAY_MASK: u32 = 0x1FFF;
const PANEL_POWER_DOWN_DELAY_MASK: u32 = 0x1FFF << 16;
const PANEL_LIGHT_OFF_DELAY_MASK: u32 = 0x1FFF;

// wait_panel_status masks/values (i915 `intel_pps.c` IDLE_*).
const IDLE_ON_MASK: u32 = PP_ON | PP_SEQUENCE_MASK | PP_SEQUENCE_STATE_MASK;
const IDLE_ON_VALUE: u32 = PP_ON | PP_SEQUENCE_NONE | PP_SEQUENCE_STATE_ON_IDLE;
const IDLE_OFF_MASK: u32 = PP_ON | PP_SEQUENCE_MASK;
const IDLE_OFF_VALUE: u32 = PP_SEQUENCE_NONE;
const IDLE_CYCLE_MASK: u32 =
    PP_ON | PP_SEQUENCE_MASK | PP_CYCLE_DELAY_ACTIVE | PP_SEQUENCE_STATE_MASK;
const IDLE_CYCLE_VALUE: u32 = PP_SEQUENCE_NONE | PP_SEQUENCE_STATE_OFF_IDLE;

/// Poll budget for PP_STATUS waits. i915 budgets 5000 ms; at
/// roughly one MMIO read per microsecond on real hardware this
/// count covers it, and — per the #879 lesson — the budget is a
/// poll count, not a wall-clock deadline, so TCG slowness cannot
/// turn a slow-but-healthy sequence into a spurious timeout.
pub const STATUS_POLL_BUDGET: u32 = 5_000_000;

/// Panel power-sequence delays, in the hardware's 100 µs units.
/// Field names follow the eDP spec's T-numbers as i915 names them
/// (`struct edp_power_seq`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PanelDelays {
    /// T1+T3: VDD on → link training may start.
    pub t1_t3: u16,
    /// T8: power on → backlight on.
    pub t8: u16,
    /// T9: backlight off → power down may start.
    pub t9: u16,
    /// T10: power down → VDD off.
    pub t10: u16,
    /// T11+T12: minimum power-off → power-on cycle time. The
    /// hardware field has 100 ms granularity and is zero-based in
    /// effect, hence the spec default's `+100`.
    pub t11_t12: u16,
}

impl PanelDelays {
    /// Upper limits from the eDP spec (i915
    /// `pps_init_delays_spec`): used for any field neither the
    /// firmware-programmed registers nor a VBT supply. This
    /// driver has no VBT parser, so the merge rule is: a nonzero
    /// firmware-programmed field wins, a zero field takes the
    /// spec value.
    pub const SPEC_DEFAULTS: PanelDelays = PanelDelays {
        t1_t3: 210 * 10,
        t8: 50 * 10,
        t9: 50 * 10,
        t10: 500 * 10,
        t11_t12: (510 + 100) * 10,
    };

    /// Decode the delays from the current register values,
    /// applying the merge rule above. `pp_ctl` supplies the
    /// power-cycle field (CNP+ layout): field × 1000 in 100 µs
    /// units (100 ms granularity).
    pub fn from_hw(pp_on: u32, pp_off: u32, pp_ctl: u32) -> PanelDelays {
        let spec = Self::SPEC_DEFAULTS;
        let pick = |v: u16, spec_v: u16| if v == 0 { spec_v } else { v };
        let t1_t3 = ((pp_on & PANEL_POWER_UP_DELAY_MASK) >> 16) as u16;
        let t8 = (pp_on & PANEL_LIGHT_ON_DELAY_MASK) as u16;
        let t9 = (pp_off & PANEL_LIGHT_OFF_DELAY_MASK) as u16;
        let t10 = ((pp_off & PANEL_POWER_DOWN_DELAY_MASK) >> 16) as u16;
        let cycle_field = (pp_ctl & PP_POWER_CYCLE_DELAY_MASK) >> PP_POWER_CYCLE_DELAY_SHIFT;
        PanelDelays {
            t1_t3: pick(t1_t3, spec.t1_t3),
            // The register copy of T8/T9 is forced to 1 when we
            // program it (the waits are done in software), so a
            // readback of 1 means "unset" as surely as 0 does.
            t8: if t8 <= 1 { spec.t8 } else { t8 },
            t9: if t9 <= 1 { spec.t9 } else { t9 },
            t10: pick(t10, spec.t10),
            t11_t12: if cycle_field == 0 {
                spec.t11_t12
            } else {
                (cycle_field * 1000) as u16
            },
        }
    }

    /// `PP_ON_DELAYS` value to program. The hardware T8 field is
    /// forced to 1 (100 µs): this driver performs the T8 wait in
    /// software, as i915 does ("We override the HW backlight
    /// delays to 1 because we do manual waits on them. For T8,
    /// even BSpec recommends doing it.").
    pub fn pp_on_value(&self) -> u32 {
        ((self.t1_t3 as u32) << 16) | 1
    }

    /// `PP_OFF_DELAYS` value to program; T9 forced to 1 for the
    /// same reason as T8 (otherwise the off wait would be paid
    /// twice — once in software, once in the PP_STATUS wait).
    pub fn pp_off_value(&self) -> u32 {
        ((self.t10 as u32) << 16) | 1
    }

    /// Power-cycle delay in the `PP_CONTROL[8:4]` encoding:
    /// 100 ms units, rounded up (i915 `DIV_ROUND_UP(t11_t12,
    /// 1000)` on the 100 µs-unit value).
    pub fn cycle_field(&self) -> u32 {
        ((self.t11_t12 as u32).div_ceil(1000)).min(0x1F)
    }
}

/// Typed PPS failures. Every variant leaves the panel in a
/// defined state; see [`PanelPowerSequencer::power_on`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PpsError {
    /// The panel never reached the on-idle state within the poll
    /// budget. Carries the last `PP_STATUS` read. The power
    /// target has already been cleared again — the panel is off.
    PowerOnTimeout { status: u32 },
    /// The panel never reached the off state within the poll
    /// budget. Carries the last `PP_STATUS` read.
    PowerOffTimeout { status: u32 },
    /// The power-cycle delay never elapsed (status side) within
    /// the poll budget. Carries the last `PP_STATUS` read.
    PowerCycleTimeout { status: u32 },
    /// Backlight was requested while the panel is not powered.
    NotPoweredOn,
}

/// Spin for `cycles` TSC cycles (bounded busy-wait for the
/// sub-millisecond-to-hundreds-of-milliseconds spec delays; the
/// same primitive `intel_gpu_aux` uses for its AUX budget).
fn spin_cycles(cycles: u64) {
    let start = narf_time::now_cycles();
    while narf_time::now_cycles().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

/// The panel power sequencer for the single internal panel.
/// Generic over the MMIO window so fixtures drive the exact
/// production code against a scripted panel.
pub struct PanelPowerSequencer<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    delays: PanelDelays,
    powered_on: bool,
    backlight_on: bool,
    last_power_on_cycles: Option<u64>,
    last_power_off_cycles: Option<u64>,
    /// Poll budget for status waits; a field so fixtures can run
    /// the timeout path without burning the production budget.
    status_poll_budget: u32,
}

impl<M: MmioWindow + ?Sized> core::fmt::Debug for PanelPowerSequencer<'_, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PanelPowerSequencer")
            .field("delays", &self.delays)
            .field("powered_on", &self.powered_on)
            .field("backlight_on", &self.backlight_on)
            .field("last_power_on_cycles", &self.last_power_on_cycles)
            .field("last_power_off_cycles", &self.last_power_off_cycles)
            .field("status_poll_budget", &self.status_poll_budget)
            .finish_non_exhaustive()
    }
}

impl<'a, M: MmioWindow + ?Sized> PanelPowerSequencer<'a, M> {
    /// Adopt the sequencer: decode delays from the firmware's
    /// register programming (merged with spec defaults) and note
    /// whether the panel is already powered (the usual GOP case).
    pub fn new(mmio: &'a M) -> Self {
        let pp_on = mmio.read32(PP_ON_DELAYS);
        let pp_off = mmio.read32(PP_OFF_DELAYS);
        let pp_ctl = mmio.read32(PP_CONTROL);
        let mut seq = Self {
            mmio,
            delays: PanelDelays::from_hw(pp_on, pp_off, pp_ctl),
            powered_on: false,
            backlight_on: false,
            last_power_on_cycles: None,
            last_power_off_cycles: None,
            status_poll_budget: STATUS_POLL_BUDGET,
        };
        seq.powered_on = seq.have_panel_power();
        seq
    }

    /// Rebuild a sequencer from previously-captured delays (the
    /// runtime power-off path, where re-decoding is unnecessary).
    pub fn with_delays(mmio: &'a M, delays: PanelDelays) -> Self {
        let mut seq = Self {
            mmio,
            delays,
            powered_on: false,
            backlight_on: false,
            last_power_on_cycles: None,
            last_power_off_cycles: None,
            status_poll_budget: STATUS_POLL_BUDGET,
        };
        seq.powered_on = seq.have_panel_power();
        seq
    }

    /// The delays in force for this panel.
    pub fn delays(&self) -> PanelDelays {
        self.delays
    }

    /// Whether this sequencer believes the panel is powered.
    pub fn is_powered_on(&self) -> bool {
        self.powered_on
    }

    /// `PP_STATUS.PP_ON` — the hardware's own word on whether
    /// panel power is up (i915 `edp_have_panel_power`).
    pub fn have_panel_power(&self) -> bool {
        self.mmio.read32(PP_STATUS) & PP_ON != 0
    }

    /// Program the delay registers from [`PanelDelays`]: the
    /// on/off delay registers outright, and the power-cycle field
    /// in `PP_CONTROL` by read-modify-write (CNP+ has no divisor
    /// register). Port-select bits are zero: Haswell-and-later
    /// sequencers have no port selection.
    pub fn init_registers(&mut self) {
        self.mmio.write32(PP_ON_DELAYS, self.delays.pp_on_value());
        self.mmio.write32(PP_OFF_DELAYS, self.delays.pp_off_value());
        self.pp_control_rmw(
            PP_POWER_CYCLE_DELAY_MASK,
            self.delays.cycle_field() << PP_POWER_CYCLE_DELAY_SHIFT,
        );
    }

    /// Force VDD on so the AUX channel is reachable while the
    /// panel is otherwise off (i915 `intel_pps_vdd_on_unlocked`).
    /// Respects the power-cycle delay first when the panel is
    /// fully off.
    pub fn vdd_on(&mut self) -> Result<(), PpsError> {
        if !self.have_panel_power() {
            self.wait_power_cycle()?;
        }
        self.pp_control_rmw(0, EDP_FORCE_VDD);
        Ok(())
    }

    /// Drop the VDD force. When this is the transition that
    /// leaves the panel unpowered, the power-cycle clock starts
    /// here (i915: "When we disable the VDD override bit last we
    /// have to do the manual wait").
    pub fn vdd_off(&mut self) {
        self.pp_control_rmw(EDP_FORCE_VDD, 0);
        if !self.have_panel_power() {
            self.last_power_off_cycles = Some(narf_time::now_cycles());
        }
    }

    /// Run the power-on sequence: enforce T11+T12, set the power
    /// target, wait for the on-idle state.
    ///
    /// Failure discipline: on timeout the power target and the
    /// VDD force are cleared again before the error returns, so
    /// a failed panel is left powered-down — never half-sequenced
    /// — and neither backlight nor modeset may follow (the probe
    /// wiring enforces that ordering).
    pub fn power_on(&mut self) -> Result<(), PpsError> {
        if self.have_panel_power() {
            self.powered_on = true;
            return Ok(());
        }
        self.wait_power_cycle()?;
        self.pp_control_rmw(0, PANEL_POWER_ON);
        match self.poll_status(IDLE_ON_MASK, IDLE_ON_VALUE) {
            Ok(_) => {
                self.powered_on = true;
                self.last_power_on_cycles = Some(narf_time::now_cycles());
                Ok(())
            }
            Err(status) => {
                self.pp_control_rmw(PANEL_POWER_ON | EDP_FORCE_VDD, 0);
                self.powered_on = false;
                Err(PpsError::PowerOnTimeout { status })
            }
        }
    }

    /// Open the PPS backlight gate (`EDP_BLC_ENABLE`) after the
    /// T8 wait from the power-on stamp. The PWM itself is the
    /// backlight crate's; this gate is the sequencer's half of
    /// the composition — light before T8 or without power is a
    /// spec violation, so both are refused.
    pub fn backlight_on(&mut self) -> Result<(), PpsError> {
        if !self.powered_on {
            return Err(PpsError::NotPoweredOn);
        }
        self.wait_since(self.last_power_on_cycles, self.delays.t8);
        self.pp_control_rmw(0, EDP_BLC_ENABLE);
        self.backlight_on = true;
        Ok(())
    }

    /// Close the PPS backlight gate, then observe T9 in software
    /// (the register field is forced to 1, so the sequencer will
    /// not wait it out for us before dropping power). Closing an
    /// already-closed gate is a harmless no-op write, so this is
    /// unconditional — the runtime power-off path rebuilds its
    /// sequencer fresh and cannot know the gate's state.
    pub fn backlight_off(&mut self) {
        self.pp_control_rmw(EDP_BLC_ENABLE, 0);
        self.backlight_on = false;
        self.spin_units(self.delays.t9);
    }

    /// Run the power-off sequence: backlight gate first (with its
    /// T9 wait), then drop the power target and the VDD force and
    /// wait for the off state. Stamps the power-off time that the
    /// next [`PanelPowerSequencer::power_on`] measures T11+T12
    /// against.
    pub fn power_off(&mut self) -> Result<(), PpsError> {
        if self.backlight_on {
            self.backlight_off();
        }
        self.pp_control_rmw(PANEL_POWER_ON | EDP_FORCE_VDD, 0);
        match self.poll_status(IDLE_OFF_MASK, IDLE_OFF_VALUE) {
            Ok(_) => {
                self.powered_on = false;
                self.last_power_off_cycles = Some(narf_time::now_cycles());
                Ok(())
            }
            Err(status) => Err(PpsError::PowerOffTimeout { status }),
        }
    }

    /// Wait out the power-cycle delay: the software remainder of
    /// T11+T12 since the recorded power-off, then the hardware
    /// side — `PP_STATUS` must show the cycle delay inactive and
    /// the sequence off-idle (i915 `wait_panel_power_cycle`).
    fn wait_power_cycle(&mut self) -> Result<(), PpsError> {
        if let Some(off) = self.last_power_off_cycles {
            let target = narf_time::wall::ns_to_cycles(self.delays.t11_t12 as u64 * 100_000);
            let elapsed = narf_time::now_cycles().wrapping_sub(off);
            if elapsed < target {
                spin_cycles(target - elapsed);
            }
        }
        self.poll_status(IDLE_CYCLE_MASK, IDLE_CYCLE_VALUE)
            .map(|_| ())
            .map_err(|status| PpsError::PowerCycleTimeout { status })
    }

    /// Poll `PP_STATUS` until `(value & mask) == expected`,
    /// bounded by the poll budget. Returns the failing status on
    /// exhaustion.
    fn poll_status(&self, mask: u32, expected: u32) -> Result<u32, u32> {
        let mut last = 0;
        for _ in 0..self.status_poll_budget {
            last = self.mmio.read32(PP_STATUS);
            if (last & mask) == expected {
                return Ok(last);
            }
            core::hint::spin_loop();
        }
        Err(last)
    }

    /// Wait until `units` (100 µs) have elapsed since `stamp`;
    /// a no-op without a stamp (nothing to measure against).
    fn wait_since(&self, stamp: Option<u64>, units: u16) {
        if let Some(stamp) = stamp {
            let target = narf_time::wall::ns_to_cycles(units as u64 * 100_000);
            let elapsed = narf_time::now_cycles().wrapping_sub(stamp);
            if elapsed < target {
                spin_cycles(target - elapsed);
            }
        }
    }

    /// Spin for `units` (100 µs) outright.
    fn spin_units(&self, units: u16) {
        spin_cycles(narf_time::wall::ns_to_cycles(units as u64 * 100_000));
    }

    /// Read-modify-write `PP_CONTROL`, with a compiler fence
    /// after the write so subsequent polls cannot be reordered
    /// ahead of the command (the posting discipline the AUX
    /// transport uses for its control register).
    fn pp_control_rmw(&self, clear: u32, set: u32) {
        let cur = self.mmio.read32(PP_CONTROL);
        self.mmio.write32(PP_CONTROL, (cur & !clear) | set);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// ── PSR: DPCD field (VESA eDP 1.4b; drm_dp.h) ───────────────────

/// `DP_PSR_SUPPORT` — enumerated: 0 = none, 1 = PSR1,
/// 2 = PSR2, 3 = PSR2 + Y-coordinate, 4 = PSR2 + Y-coord ET.
pub const DPCD_PSR_SUPPORT: u32 = 0x070;
/// `DP_PSR_CAPS` — setup-time field, granularity requirements.
pub const DPCD_PSR_CAPS: u32 = 0x071;
/// `DP_PSR2_SU_X_GRANULARITY` — 2 bytes, little-endian.
pub const DPCD_PSR2_SU_X_GRANULARITY: u32 = 0x072;
/// `DP_PSR2_SU_Y_GRANULARITY` — 1 byte.
pub const DPCD_PSR2_SU_Y_GRANULARITY: u32 = 0x074;
/// `DP_RECEIVER_ALPM_CONFIG` — ALPM enable for PSR2.
pub const DPCD_RECEIVER_ALPM_CONFIG: u32 = 0x116;
/// `DP_PSR_EN_CFG` — the sink PSR configuration byte.
pub const DPCD_PSR_EN_CFG: u32 = 0x170;
/// `DP_SET_POWER` — sink power state; D0 must follow PSR setup.
pub const DPCD_SET_POWER: u32 = 0x600;
/// `DP_PSR_ERROR_STATUS` — link CRC / RFB storage / VSC errors.
pub const DPCD_PSR_ERROR_STATUS: u32 = 0x2006;
/// `DP_PSR_STATUS` — sink PSR state (mask 0x7).
pub const DPCD_PSR_STATUS: u32 = 0x2008;
/// `DP_SYNCHRONIZATION_LATENCY_IN_SINK` — last-actual sync
/// latency in bits [7:4], in frames.
pub const DPCD_SYNC_LATENCY: u32 = 0x2009;

// DP_PSR_EN_CFG bits.
const PSR_EN_CFG_ENABLE: u8 = 1 << 0;
const PSR_EN_CFG_MAIN_LINK_ACTIVE: u8 = 1 << 1;
const PSR_EN_CFG_CRC_VERIFICATION: u8 = 1 << 2;
const PSR_EN_CFG_IRQ_HPD_WITH_CRC_ERRORS: u8 = 1 << 5;
const PSR_EN_CFG_ENABLE_PSR2: u8 = 1 << 6;
const PSR_EN_CFG_ENABLE_SU_REGION_ET: u8 = 1 << 7;

// DP_RECEIVER_ALPM_CONFIG bits. Bit 1 is eDP 1.5; i915 sets it
// unconditionally on the PSR2 path, and 1.4 sinks treat it as
// reserved-zero-tolerant — we follow i915.
const ALPM_ENABLE: u8 = 1 << 0;
const ALPM_LOCK_ERROR_IRQ_HPD_ENABLE: u8 = 1 << 1;

const SET_POWER_D0: u8 = 0x1;

/// `DP_MAX_LANE_COUNT` — TPS3 support lives in bit 6; the probe
/// wiring reads it to pick the PSR1 training-pattern select.
pub const DPCD_MAX_LANE_COUNT: u32 = 0x002;
const TPS3_SUPPORTED: u8 = 1 << 6;

/// PSR setup times by `DP_PSR_CAPS[3:1]` code (µs). Code 7 is
/// reserved by the spec — a panel that reports it is lying about
/// a field it must implement, and PSR is refused.
const PSR_SETUP_TIME_US: [u16; 7] = [330, 275, 220, 165, 110, 55, 0];

/// Typed PSR failures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PsrError {
    /// AUX transport failure during sink setup or caps decode.
    Aux(AuxError),
    /// The panel's PSR DPCD field is malformed (see the variant's
    /// static description). PSR is refused; plain eDP continues.
    InvalidCaps(&'static str),
    /// The sink's PSR setup time does not fit the mode's
    /// blanking interval (i915 `intel_psr_entry_setup_frames`
    /// rejects the same configuration).
    SetupTimeExceedsBlanking,
    /// A dirty notification arrived with no PSR session active.
    NotEnabled,
    /// A dirty notification arrived while a flip is pending.
    /// Refused before any register write: programming an SU
    /// region against a scanout that is about to change would
    /// update the wrong frame.
    FlipPending,
    /// A source register was inaccessible or refused the disable request.
    Unavailable,
    /// The source did not leave self-refresh within the bounded idle wait.
    Timeout,
}

impl From<AuxError> for PsrError {
    fn from(e: AuxError) -> Self {
        PsrError::Aux(e)
    }
}

/// One native-AUX read built on `transact` directly. (The
/// `AuxChannel::dpcd_read` default passes an empty length
/// placeholder, which the Intel transport decodes as a zero-byte
/// read; reads here carry the requested length as the
/// placeholder, the convention the AUX transport implements.)
fn sink_read<A: AuxChannel>(aux: &mut A, addr: u32, buf: &mut [u8]) -> Result<(), AuxError> {
    let zeros = [0u8; 16];
    let req = AuxRequest {
        cmd: AuxCommand::NativeRead,
        address: addr,
        data: &zeros[..buf.len()],
    };
    let mut reply = [0u8; 17];
    let resp = aux.transact(&req, &mut reply)?;
    if resp.status != AuxStatus::Ack {
        return Err(AuxError::Nacked);
    }
    if resp.data.len() != buf.len() {
        return Err(AuxError::ShortReply);
    }
    buf.copy_from_slice(resp.data);
    Ok(())
}

/// One native-AUX write; payload is the real data.
fn sink_write<A: AuxChannel>(aux: &mut A, addr: u32, data: &[u8]) -> Result<(), AuxError> {
    let req = AuxRequest {
        cmd: AuxCommand::NativeWrite,
        address: addr,
        data,
    };
    let mut reply = [0u8; 1];
    let resp = aux.transact(&req, &mut reply)?;
    if resp.status != AuxStatus::Ack {
        return Err(AuxError::Nacked);
    }
    Ok(())
}

/// Decoded PSR capabilities of the attached panel.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PsrCaps {
    /// Panel supports PSR2 (support byte ≥ 2).
    pub psr2: bool,
    /// PSR2 with Y-coordinate support (support byte ≥ 3).
    pub y_coordinate: bool,
    /// PSR2 SU-region early-transport support (support byte = 4).
    pub su_region_et: bool,
    /// Sink PSR setup time in µs (`DP_PSR_CAPS` field, decoded).
    pub setup_time_us: u16,
    /// Sink needs no link training on PSR exit.
    pub no_train_on_exit: bool,
    /// Selective-update X granularity (pixels). 4 when the sink
    /// does not require its programmed granularity.
    pub su_x_granularity: u16,
    /// Selective-update Y granularity (lines). 4 when the sink
    /// does not require its programmed granularity.
    pub su_y_granularity: u16,
    /// Sink synchronization latency in frames (DPCD 0x2009
    /// last-actual field). 0 when the read is unavailable —
    /// pre-1.4 sinks may not implement the register.
    pub sink_sync_latency: u8,
}

impl PsrCaps {
    /// Probe the panel's PSR field. `Ok(None)` means the panel
    /// has no PSR (support byte 0) or reports a reserved support
    /// value (> 4): either way it runs plain eDP and the caller
    /// must generate no PSR traffic. A PSR-claiming panel with a
    /// reserved setup-time code is `Err(InvalidCaps)`.
    pub fn probe<A: AuxChannel>(aux: &mut A) -> Result<Option<PsrCaps>, PsrError> {
        // One burst over the contiguous field 0x070..=0x074.
        let mut head = [0u8; 5];
        sink_read(aux, DPCD_PSR_SUPPORT, &mut head)?;
        let support = head[0];
        if support == 0 || support > 4 {
            return Ok(None);
        }
        let caps_byte = head[1];
        let setup_code = (caps_byte >> 1) & 0x7;
        let setup_time_us = match PSR_SETUP_TIME_US.get(setup_code as usize) {
            Some(&t) => t,
            None => return Err(PsrError::InvalidCaps("reserved PSR setup-time code")),
        };
        let psr2 = support >= 2;
        // Granularity bytes are only meaningful when the sink
        // sets SU_GRANULARITY_REQUIRED; otherwise the spec
        // default (4×4) applies and the bytes are not consulted.
        let mut su_x: u16 = 4;
        let mut su_y: u16 = 4;
        if psr2 && (caps_byte & (1 << 5)) != 0 {
            su_x = u16::from_le_bytes([head[2], head[3]]);
            if su_x == 0 {
                su_x = 4;
            }
            su_y = head[4] as u16;
            if su_y == 0 {
                su_y = 4;
            }
        }
        // Sync latency is best-effort: a NACK leaves 0, which
        // only makes the idle-frame floors more conservative in
        // relative terms (they are floored at 6 / 2 regardless).
        let mut lat = [0u8; 1];
        let sink_sync_latency = match sink_read(aux, DPCD_SYNC_LATENCY, &mut lat) {
            Ok(()) => (lat[0] >> 4) & 0xF,
            Err(_) => 0,
        };
        Ok(Some(PsrCaps {
            psr2,
            y_coordinate: support >= 3,
            su_region_et: support == 4,
            setup_time_us,
            no_train_on_exit: (caps_byte & 1) != 0,
            su_x_granularity: su_x,
            su_y_granularity: su_y,
            sink_sync_latency,
        }))
    }

    /// Idle frames before PSR entry (i915
    /// `psr_compute_idle_frames`, minus the VBT term this driver
    /// does not have): at least 6 — "to cover all known cases
    /// including the off-by-one issue that HW has in some
    /// cases" — at least sink-sync-latency + 1, at most the
    /// 4-bit field maximum.
    pub fn idle_frames(&self) -> u32 {
        let latency = self.sink_sync_latency as u32 + 1;
        6.max(latency).min(0xF)
    }

    /// Frames the source must send before the first selective
    /// update (i915 `frames_before_su_entry` with Gen12's
    /// entry-setup-frames of 0): at least latency + 1, at
    /// least 2.
    pub fn frames_before_su(&self) -> u32 {
        (self.sink_sync_latency as u32 + 1).max(2)
    }

    /// The `DP_PSR_EN_CFG` byte for PSR1: enable, main link kept
    /// active (link standby — the mode i915 enables by default),
    /// CRC verification on (Gen8+ sources).
    pub fn sink_cfg_psr1(&self) -> u8 {
        PSR_EN_CFG_ENABLE | PSR_EN_CFG_MAIN_LINK_ACTIVE | PSR_EN_CFG_CRC_VERIFICATION
    }

    /// The `DP_PSR_EN_CFG` byte for PSR2: enable + PSR2 + CRC
    /// error IRQ HPD, plus SU-region early transport when the
    /// panel advertises it.
    pub fn sink_cfg_psr2(&self) -> u8 {
        let mut v = PSR_EN_CFG_ENABLE | PSR_EN_CFG_ENABLE_PSR2 | PSR_EN_CFG_IRQ_HPD_WITH_CRC_ERRORS;
        if self.su_region_et {
            v |= PSR_EN_CFG_ENABLE_SU_REGION_ET;
        }
        v
    }
}

/// PSR sink state from `DP_PSR_STATUS` (diagnostics; the state
/// values are the eDP enumeration: 0 inactive, 1 active/source
/// synced, 2 active/RFB, 3 active/sink synced, 4 resync,
/// 7 internal error).
pub fn psr_sink_state<A: AuxChannel>(aux: &mut A) -> Result<u8, PsrError> {
    let mut b = [0u8; 1];
    sink_read(aux, DPCD_PSR_STATUS, &mut b)?;
    Ok(b[0] & 0x7)
}

/// PSR error byte from `DP_PSR_ERROR_STATUS` (diagnostics).
pub fn psr_error_status<A: AuxChannel>(aux: &mut A) -> Result<u8, PsrError> {
    let mut b = [0u8; 1];
    sink_read(aux, DPCD_PSR_ERROR_STATUS, &mut b)?;
    Ok(b[0])
}

// ── PSR: source registers (transcoder A; intel_psr_regs.h) ──────

/// `EDP_PSR_CTL` (transcoder A) — PSR1 source control.
pub const PSR_CTL: u64 = 0x6_0800;
/// `EDP_PSR_STATUS` (transcoder A) — state field in [31:29]:
/// 0 idle, 1 SRD-on-ACK, 2 SRD-enter, 3 BUF-off, 4 BUF-on,
/// 5 AUX-ACK, 6 SRD-off-ACK.
pub const PSR_STATUS: u64 = 0x6_0840;
/// `EDP_PSR2_CTL` (transcoder A) — PSR2 source control.
pub const PSR2_CTL: u64 = 0x6_0900;
/// `PSR2_MAN_TRK_CTL` (transcoder A) — manual tracking / SU
/// region programming.
pub const PSR2_MAN_TRK_CTL: u64 = 0x6_0910;
/// `EDP_PSR2_STATUS` (transcoder A) — state field in [31:28];
/// 0x8 is deep sleep.
pub const PSR2_STATUS: u64 = 0x6_0940;

// EDP_PSR_CTL fields.
const PSR_CTL_ENABLE: u32 = 1 << 31;
const PSR_CTL_RESTORE_ACTIVE_CTX: u32 = 1 << 29; // SW can't modify; preserved by RMW.
const PSR_CTL_LINK_STANDBY: u32 = 1 << 27;
const PSR_CTL_MAX_SLEEP_TIME_MASK: u32 = 0x1F << 20;
const PSR_CTL_TP_TP1_TP3: u32 = 1 << 11;
const PSR_CTL_CRC_ENABLE: u32 = 1 << 10;
const PSR_CTL_TP2_TP3_TIME_MASK: u32 = 0x3 << 8;
const PSR_CTL_TP4_TIME_MASK: u32 = 0x3 << 6;
const PSR_CTL_TP1_TIME_MASK: u32 = 0x3 << 4;
const PSR_CTL_IDLE_FRAMES_MASK: u32 = 0xF;
// Training-pattern wake-time field encodings (both TP fields
// share the bucket order 500/100/2500/0 µs = 0/1/2/3; TP4's 0 µs
// encoding is 3).
const TP_TIME_2500US: u32 = 2;
const TP4_TIME_0US: u32 = 3;

// EDP_PSR2_CTL fields.
const PSR2_CTL_ENABLE: u32 = 1 << 31;
const PSR2_CTL_SU_TRACK_ENABLE: u32 = 1 << 30; // up to ADL-P steppings i915 gates per-platform; see psr2_ctl_value.
const PSR2_CTL_BLOCK_COUNT_NUM_3: u32 = 1 << 28;
const PSR2_CTL_Y_COORDINATE_ENABLE: u32 = 1 << 25; // display 10..12
const PSR2_CTL_IO_BUFFER_WAKE_MASK: u32 = 0x7 << 13; // TGL encoding: lines − 5
const PSR2_CTL_FAST_WAKE_MASK: u32 = 0x7 << 10; // TGL encoding: lines − 5
const PSR2_CTL_TP2_TIME_MASK: u32 = 0x3 << 8;
const PSR2_CTL_FRAME_BEFORE_SU_MASK: u32 = 0xF << 4;
const PSR2_CTL_IDLE_FRAMES_MASK: u32 = 0xF;
const PSR2_WAKE_TIME_MIN_LINES: u32 = 5;

/// Which Gen12 platform's PSR register layout applies. The two
/// differ in `PSR2_MAN_TRK_CTL` field placement and in which
/// PSR2_CTL feature bits exist.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PsrLayout {
    TigerLake,
    AlderLakeP,
}

impl PsrLayout {
    /// Map the driver's chip generation onto a PSR layout.
    /// Only called for display-supported generations.
    pub fn from_generation(generation: Generation) -> PsrLayout {
        match generation {
            Generation::AlderLake => PsrLayout::AlderLakeP,
            _ => PsrLayout::TigerLake,
        }
    }
}

/// Whole microseconds → whole scanlines of `mode`, rounded up
/// (i915 `intel_usecs_to_scanlines`). Line time is
/// `h_total / pixel_clock_khz` µs × 1000.
pub fn usecs_to_scanlines(mode: &Mode, us: u32) -> u32 {
    let den = mode.h_total as u64 * 1000;
    if den == 0 {
        return u32::MAX;
    }
    let num = us as u64 * mode.pixel_clock_khz as u64;
    num.div_ceil(den) as u32
}

/// PSR2 wake-line computation (i915 `_compute_psr2_wake_times`
/// for display ≥ 12): the IO-buffer wake is 42 µs, the fast wake
/// 45 µs (BSpec says 42; i915 testing found it short), each
/// floored at 7 lines, and PSR2 is not usable when either needs
/// more than 12 lines.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Psr2WakeLines {
    pub io: u32,
    pub fast: u32,
}

/// Compute the PSR2 wake lines for `mode`; `None` when PSR2
/// cannot be configured for this mode (caller falls back to
/// PSR1).
pub fn psr2_wake_lines(mode: &Mode) -> Option<Psr2WakeLines> {
    let io = usecs_to_scanlines(mode, 42).max(7);
    let fast = usecs_to_scanlines(mode, 45).max(7);
    if io > 12 || fast > 12 {
        None
    } else {
        Some(Psr2WakeLines { io, fast })
    }
}

/// Whether the PSR2 block count is 3 (else 2): i915
/// `psr2_block_count` — the block spans 8 lines when both wake
/// counts are under 9, else 12; the count field is lines / 4.
fn psr2_block_count_is_3(wake: &Psr2WakeLines) -> bool {
    !(wake.io < 9 && wake.fast < 9)
}

/// The `EDP_PSR_CTL` value for PSR1 activation (i915
/// `hsw_activate_psr1`, Gen12 terms).
///
/// Training-pattern wake times are the conservative 2500 µs
/// bucket for both TP1 and TP2/TP3: i915 takes these from the
/// VBT PSR block, this driver has no VBT, and a longer wake
/// time is always spec-legal — it only costs exit latency.
/// TP select follows the sink's TPS3 support; TP4 is 0 µs
/// (ICL+ row). Max sleep time is the field maximum, 0x1F.
pub fn psr1_ctl_value(caps: &PsrCaps, tps3_supported: bool) -> u32 {
    let mut v = PSR_CTL_ENABLE;
    v |= caps.idle_frames() & PSR_CTL_IDLE_FRAMES_MASK;
    v |= PSR_CTL_MAX_SLEEP_TIME_MASK; // 0x1F at field position.
    v |= PSR_CTL_LINK_STANDBY;
    v |= (TP_TIME_2500US << 4) & PSR_CTL_TP1_TIME_MASK;
    v |= (TP_TIME_2500US << 8) & PSR_CTL_TP2_TP3_TIME_MASK;
    v |= (TP4_TIME_0US << 6) & PSR_CTL_TP4_TIME_MASK;
    v |= PSR_CTL_CRC_ENABLE;
    if tps3_supported {
        v |= PSR_CTL_TP_TP1_TP3;
    }
    v
}

/// The `EDP_PSR2_CTL` value for PSR2 activation (i915
/// `hsw_activate_psr2`, Gen12 terms).
///
/// Platform deltas, from the same function: SU tracking is set
/// on Tiger Lake but not on Alder Lake P; the Y-coordinate
/// enable exists on display 10..12 (Tiger Lake yes, ADL-P's
/// display 13 no). The ADL-P A0–E0 wake-field scramble
/// (Wa_22012278275) is not applied — this driver reads no
/// stepping — and is named here so the omission is a decision,
/// not an oversight.
pub fn psr2_ctl_value(caps: &PsrCaps, layout: PsrLayout, wake: &Psr2WakeLines) -> u32 {
    let mut v = PSR2_CTL_ENABLE;
    v |= caps.idle_frames() & PSR2_CTL_IDLE_FRAMES_MASK;
    v |= (caps.frames_before_su() << 4) & PSR2_CTL_FRAME_BEFORE_SU_MASK;
    v |= (TP_TIME_2500US << 8) & PSR2_CTL_TP2_TIME_MASK;
    match layout {
        PsrLayout::TigerLake => {
            v |= PSR2_CTL_SU_TRACK_ENABLE;
            v |= PSR2_CTL_Y_COORDINATE_ENABLE;
        }
        PsrLayout::AlderLakeP => {}
    }
    // (ADL-P note: its PSR2_CTL has no Y-coordinate-enable bit —
    // display 13 dropped it — so a Y-coordinate panel on ADL-P
    // gets the coordinate in the VSC SDP only. Nothing to set.)
    if psr2_block_count_is_3(wake) {
        v |= PSR2_CTL_BLOCK_COUNT_NUM_3;
    }
    v |= ((wake.io - PSR2_WAKE_TIME_MIN_LINES) << 13) & PSR2_CTL_IO_BUFFER_WAKE_MASK;
    v |= ((wake.fast - PSR2_WAKE_TIME_MIN_LINES) << 10) & PSR2_CTL_FAST_WAKE_MASK;
    v
}

/// Enable PSR for a panel whose caps were probed: validate the
/// configuration, set the sink up over AUX, then activate the
/// source. Returns the mode actually enabled — PSR2 when the
/// panel and the mode's wake lines allow it, PSR1 otherwise.
///
/// Validation happens **before** any sink or source write: a
/// configuration i915 would reject (setup time longer than the
/// blanking interval) leaves zero PSR traffic, exactly like the
/// unsupported-panel case.
pub fn psr_enable<M: MmioWindow + ?Sized, A: AuxChannel>(
    mmio: &M,
    aux: &mut A,
    caps: &PsrCaps,
    layout: PsrLayout,
    mode: &Mode,
    tps3_supported: bool,
) -> Result<PsrMode, PsrError> {
    // Setup-fit: the sink's setup time, in scanlines, must fit
    // the blanking interval (i915: setup lines > vblank − 1 is
    // a hard failure pre-LNL).
    let vblank = mode.v_total.saturating_sub(mode.v_active);
    let setup_lines = usecs_to_scanlines(mode, caps.setup_time_us as u32);
    if vblank == 0 || setup_lines > vblank as u32 - 1 {
        return Err(PsrError::SetupTimeExceedsBlanking);
    }
    let wake = if caps.psr2 {
        psr2_wake_lines(mode)
    } else {
        None
    };
    match wake {
        Some(wake) => {
            // Sink: ALPM first, then the PSR2 config byte, then
            // D0 (i915 `intel_psr_enable_sink` order).
            sink_write(
                aux,
                DPCD_RECEIVER_ALPM_CONFIG,
                &[ALPM_ENABLE | ALPM_LOCK_ERROR_IRQ_HPD_ENABLE],
            )?;
            sink_write(aux, DPCD_PSR_EN_CFG, &[caps.sink_cfg_psr2()])?;
            sink_write(aux, DPCD_SET_POWER, &[SET_POWER_D0])?;
            // Source: PSR1 CTL must stay disabled while PSR2 is
            // active (the PSR2 hardware misuses its TP1/TP3
            // select); write it first, then PSR2_CTL, then the
            // manual-tracking register in continuous-full-frame
            // state until the first dirty notification.
            mmio.write32(PSR_CTL, 0);
            mmio.write32(PSR2_CTL, psr2_ctl_value(caps, layout, &wake));
            mmio.write32(PSR2_MAN_TRK_CTL, man_trk_value(layout, None));
            Ok(PsrMode::Psr2)
        }
        None => {
            // Sink: config byte, then D0.
            sink_write(aux, DPCD_PSR_EN_CFG, &[caps.sink_cfg_psr1()])?;
            sink_write(aux, DPCD_SET_POWER, &[SET_POWER_D0])?;
            // Source: RMW preserving the one bit software must
            // not modify (the HW context-restore flag).
            let cur = mmio.read32(PSR_CTL);
            mmio.write32(
                PSR_CTL,
                (cur & PSR_CTL_RESTORE_ACTIVE_CTX) | psr1_ctl_value(caps, tps3_supported),
            );
            Ok(PsrMode::Psr1)
        }
    }
}

/// Disable PSR: source first (stop sending PSR frames), then the
/// sink config byte. The panel stays powered at D0.
pub fn psr_disable<M: MmioWindow + ?Sized, A: AuxChannel>(
    mmio: &M,
    aux: &mut A,
    active: PsrMode,
) -> Result<(), PsrError> {
    match active {
        PsrMode::Psr2 => {
            mmio.write32(PSR2_CTL, 0);
            mmio.write32(PSR2_MAN_TRK_CTL, 0);
        }
        PsrMode::Psr1 => {
            let cur = mmio.read32(PSR_CTL);
            mmio.write32(PSR_CTL, cur & PSR_CTL_RESTORE_ACTIVE_CTX);
        }
    }
    sink_write(aux, DPCD_PSR_EN_CFG, &[0])?;
    Ok(())
}

/// Which PSR generation a session is running.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PsrMode {
    Psr1,
    Psr2,
}

/// A dirtied rectangle of the scanout, in pixels/lines with
/// exclusive end coordinates (the `drm_rect` convention the
/// selective-fetch computation uses).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SuRegion {
    pub x1: u16,
    pub y1: u16,
    pub x2: u16,
    pub y2: u16,
}

impl SuRegion {
    /// The region covering a whole `width`×`height` frame.
    pub fn full(width: u16, height: u16) -> SuRegion {
        SuRegion {
            x1: 0,
            y1: 0,
            x2: width,
            y2: height,
        }
    }
}

/// Align a dirtied region outward to the sink's SU granularity
/// and clip it to the frame (i915
/// `intel_psr2_sel_fetch_pipe_alignment`, plus the X dimension):
/// the region the sink is told about must cover every dirtied
/// pixel, so starts round down and ends round up.
pub fn align_su_region(
    region: SuRegion,
    caps: &PsrCaps,
    layout: PsrLayout,
    width: u16,
    height: u16,
) -> SuRegion {
    let gx = caps.su_x_granularity.max(1) as u32;
    let mut gy = caps.su_y_granularity.max(1) as u32;
    if layout == PsrLayout::TigerLake {
        // TGL's MAN_TRK region fields are in 4-line units; the
        // clip must be 4-aligned before the encoding divides.
        gy = gy.div_ceil(4) * 4;
    }
    let align_down = |v: u16, g: u32| (v as u32 - (v as u32 % g)) as u16;
    let align_up = |v: u16, g: u32| ((v as u32).div_ceil(g) * g).min(u16::MAX as u32) as u16;
    SuRegion {
        x1: align_down(region.x1, gx),
        y1: align_down(region.y1, gy),
        x2: align_up(region.x2, gx).min(width),
        y2: align_up(region.y2, gy).min(height),
    }
}

/// The `PSR2_MAN_TRK_CTL` value for a selective update.
/// `None` (or a region that alignment expanded to the whole
/// frame — callers pass `None` for that case) is the
/// continuous-full-frame value: partial-frame updates stay
/// enabled, and the single + continuous full-frame bits are set
/// (i915 `psr2_man_trk_ctl_calc` — "SF partial frame enable has
/// to be set even on full update").
///
/// TGL fields hold the region in 4-line units, biased by +1;
/// ADL-P fields hold raw scanlines, end-exclusive-minus-one.
/// The region must already be granularity-aligned
/// ([`align_su_region`]).
pub fn man_trk_value(layout: PsrLayout, region: Option<SuRegion>) -> u32 {
    match layout {
        PsrLayout::TigerLake => {
            const ENABLE: u32 = 1 << 31;
            const SF_PARTIAL: u32 = 1 << 1;
            const SF_SINGLE: u32 = 1 << 3;
            const SF_CONTINUOUS: u32 = 1 << 2;
            match region {
                None => ENABLE | SF_PARTIAL | SF_SINGLE | SF_CONTINUOUS,
                Some(r) => {
                    let start = (r.y1 as u32 / 4 + 1) & 0x3FF;
                    let end = (r.y2 as u32 / 4 + 1) & 0x3FF;
                    ENABLE | SF_PARTIAL | (start << 21) | (end << 11)
                }
            }
        }
        PsrLayout::AlderLakeP => {
            const SF_PARTIAL: u32 = 1 << 31;
            const SF_SINGLE: u32 = 1 << 14;
            const SF_CONTINUOUS: u32 = 1 << 13;
            match region {
                None => SF_PARTIAL | SF_SINGLE | SF_CONTINUOUS,
                Some(r) => {
                    let start = (r.y1 as u32) & 0x1FFF;
                    let end = (r.y2 as u32).saturating_sub(1) & 0x1FFF;
                    SF_PARTIAL | (start << 16) | end
                }
            }
        }
    }
}

// ── Runtime state + composition glue ────────────────────────────
//
// The transports (MMIO window, AUX channel) are borrowed, so
// they cannot live in a static; what persists across probe is
// the *state*: delays, caps, layout, the active PSR mode, the
// flip-pending flag, and the last SU region. Every entry point
// below takes the window from its caller and operates on this
// state. Lock order is CONTROLLER (intel_gpu) → EDP_RUNTIME;
// no path takes them in the other order.

/// Outcome of a dirty notification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DirtyOutcome {
    /// No PSR session is active; the publish proceeds as a
    /// plain scanout update.
    NoPsr,
    /// PSR1 exited (or PSR2 fell back to a full-frame update);
    /// the whole frame is retransmitted.
    FullFrameExit,
    /// PSR2 selective update armed for exactly this
    /// (granularity-aligned) region.
    SelectiveUpdate(SuRegion),
}

#[derive(Copy, Clone, Debug)]
struct EdpRuntime {
    delays: Option<PanelDelays>,
    layout: Option<PsrLayout>,
    caps: Option<PsrCaps>,
    active: Option<PsrMode>,
    flip_pending: bool,
    frame: (u16, u16),
    last_region: Option<SuRegion>,
    kms_inhibited: bool,
}

impl EdpRuntime {
    const fn new() -> Self {
        Self {
            delays: None,
            layout: None,
            caps: None,
            active: None,
            flip_pending: false,
            frame: (0, 0),
            last_region: None,
            kms_inhibited: false,
        }
    }

    /// The notification core, separated from the static so
    /// fixtures can drive it directly.
    fn notify_dirty<M: MmioWindow + ?Sized>(
        &mut self,
        mmio: &M,
        region: Option<SuRegion>,
    ) -> Result<DirtyOutcome, PsrError> {
        if self.kms_inhibited {
            return Err(PsrError::FlipPending);
        }
        let Some(active) = self.active else {
            return Ok(DirtyOutcome::NoPsr);
        };
        // Refused before any register write — see PsrError.
        if self.flip_pending {
            return Err(PsrError::FlipPending);
        }
        match active {
            PsrMode::Psr1 => {
                // PSR1 has no SU registers: exit is a pipeline
                // event (the publish itself, via frontbuffer
                // tracking). The driver's act is to record that
                // the frame went out whole.
                self.last_region = None;
                Ok(DirtyOutcome::FullFrameExit)
            }
            PsrMode::Psr2 => {
                let (Some(caps), Some(layout)) = (self.caps, self.layout) else {
                    return Err(PsrError::NotEnabled);
                };
                let aligned =
                    region.map(|r| align_su_region(r, &caps, layout, self.frame.0, self.frame.1));
                // A region that alignment expanded to the whole
                // frame (or an empty clip) takes the full-frame
                // encoding, not a degenerate region encoding.
                let effective = match aligned {
                    Some(r) if r.y1 < r.y2 && r != SuRegion::full(self.frame.0, self.frame.1) => {
                        Some(r)
                    }
                    _ => None,
                };
                mmio.write32(PSR2_MAN_TRK_CTL, man_trk_value(layout, effective));
                self.last_region = effective;
                Ok(match effective {
                    Some(r) => DirtyOutcome::SelectiveUpdate(r),
                    None => DirtyOutcome::FullFrameExit,
                })
            }
        }
    }

    /// Surface updates require a real scanout fetch, rather than a panel
    /// still showing self-refresh. MIT Linux b90c984d intel_psr.c disables
    /// the source and waits for idle before handing the sink back.
    fn inhibit_for_kms<M: MmioWindow + ?Sized, A: AuxChannel>(
        &mut self,
        mmio: &M,
        aux: &mut A,
    ) -> Result<(), PsrError> {
        self.kms_inhibited = true;
        self.flip_pending = true;
        let psr1 = mmio.read32(PSR_CTL);
        let psr2 = mmio.read32(PSR2_CTL);
        if psr1 == u32::MAX || psr2 == u32::MAX {
            return Err(PsrError::Unavailable);
        }
        let enabled = self.active.is_some() || (psr1 | psr2) & (1 << 31) != 0;
        mmio.write32(PSR_CTL, psr1 & PSR_CTL_RESTORE_ACTIVE_CTX);
        mmio.write32(PSR2_CTL, 0);
        mmio.write32(PSR2_MAN_TRK_CTL, 0);
        let mut unavailable = false;
        let idle = narf_scheduler::responsive_spin_until(
            || {
                let ctl1 = mmio.read32(PSR_CTL);
                let ctl2 = mmio.read32(PSR2_CTL);
                let status1 = mmio.read32(PSR_STATUS);
                let status2 = mmio.read32(PSR2_STATUS);
                unavailable = [ctl1, ctl2, status1, status2].contains(&u32::MAX)
                    || (ctl1 | ctl2) & (1 << 31) != 0;
                unavailable || (status1 & (7 << 29) == 0 && status2 & (15 << 28) == 0)
            },
            narf_time::Deadline::after_ms(2000),
        );
        if unavailable {
            return Err(PsrError::Unavailable);
        }
        if !idle {
            return Err(PsrError::Timeout);
        }
        if enabled {
            sink_write(aux, DPCD_PSR_EN_CFG, &[0])?;
        }
        self.active = None;
        self.last_region = None;
        Ok(())
    }
}

static EDP_RUNTIME: IrqSafeSpinLock<EdpRuntime> = IrqSafeSpinLock::new(EdpRuntime::new());

/// Record the panel's delays + PSR layout at probe time (the
/// power-off path rebuilds its sequencer from these).
pub fn runtime_install_panel(delays: PanelDelays, layout: PsrLayout) {
    let mut rt = EDP_RUNTIME.lock();
    rt.delays = Some(delays);
    rt.layout = Some(layout);
}

/// Record a live PSR session at probe time.
pub fn runtime_install_psr(caps: PsrCaps, active: PsrMode, width: u16, height: u16) {
    let mut rt = EDP_RUNTIME.lock();
    if rt.kms_inhibited {
        return;
    }
    rt.caps = Some(caps);
    rt.active = Some(active);
    rt.frame = (width, height);
}

/// Mark a flip as pending (or complete). While a flip is
/// pending, dirty notifications are refused — the seam Q4's
/// session machinery drives around its page flips.
pub fn set_flip_pending(pending: bool) {
    EDP_RUNTIME.lock().flip_pending = pending;
}

/// The caller retains its KMS session, PCI authority and display power. An
/// error leaves PSR inhibited so another task cannot re-enter during recovery.
pub(crate) fn kms_inhibit_psr(mmio: &impl MmioWindow) -> Result<(), PsrError> {
    let mut aux = IntelAux::new(mmio, Ddi::A);
    EDP_RUNTIME.lock().inhibit_for_kms(mmio, &mut aux)
}

/// Called only after console restoration or verified fetch stop. PSR stays
/// disabled until a later explicit enable; releasing this guard is not proof
/// that a panel supports re-entry with a changed configuration.
pub(crate) fn kms_release_psr() {
    let mut runtime = EDP_RUNTIME.lock();
    runtime.kms_inhibited = false;
    runtime.flip_pending = false;
}

/// Notify the PSR session that scanout content changed.
/// `None` means the whole frame is dirty (the publish path);
/// `Some(region)` is a region-granular update. This is the
/// only entry into PSR exit/SU programming — nothing polls.
pub fn notify_scanout_dirty<M: MmioWindow + ?Sized>(
    mmio: &M,
    region: Option<SuRegion>,
) -> Result<DirtyOutcome, PsrError> {
    EDP_RUNTIME.lock().notify_dirty(mmio, region)
}

/// Scanout-publish hook, called from `intel_gpu::publish_scanout`
/// whenever a new scanout appears: a publish is a full-frame
/// update, which is what exits PSR.
pub fn on_scanout_published() {
    let _ = crate::intel_gpu::with_controller(|gpu| {
        let window = BarWindow(&gpu.gtt_mmadr);
        let _ = notify_scanout_dirty(&window, None);
    });
}

/// `MmioWindow` over the GPU's BAR0 mapping — the same adapter
/// shape `takeover_display` builds locally, shared here so the
/// PPS/PSR paths and the publish hook use one implementation.
pub struct BarWindow<'a>(pub &'a narf_bus::bar::MmioRegion);

impl core::fmt::Debug for BarWindow<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BarWindow").finish_non_exhaustive()
    }
}

impl MmioWindow for BarWindow<'_> {
    fn read32(&self, off: u64) -> u32 {
        // SAFETY: `self.0` is the GPU's MMADR BAR window mapped
        // by probe; `off` is a display register offset within
        // that BAR, and a 32-bit register read has no unwanted
        // side-effect.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.0.read32(off) }
    }
    fn write32(&self, off: u64, val: u32) {
        // SAFETY: `self.0` is the probe-mapped MMADR BAR owned
        // exclusively by this driver; `off` is an in-range
        // display register offset.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.0.write32(off, val) }
    }
}

/// Probe-time PSR bring-up for a panel that powered on and
/// modeset successfully. Any failure — no PSR, malformed caps,
/// a configuration the mode cannot host — leaves plain eDP
/// running; PSR is an optimization, never a boot blocker.
pub fn enable_psr_for_panel(gpu: &crate::intel_gpu::IntelGpu, mode: &Mode) {
    use core::fmt::Write as _;
    let mut runtime = EDP_RUNTIME.lock();
    if runtime.kms_inhibited {
        return;
    }
    let window = BarWindow(&gpu.gtt_mmadr);
    let mut aux = IntelAux::new(&window, Ddi::A);
    let caps = match PsrCaps::probe(&mut aux) {
        Ok(Some(caps)) => caps,
        Ok(None) => return,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu/edp: PSR caps probe failed: {:?} — plain eDP",
                e
            );
            return;
        }
    };
    let mut lane_count = [0u8; 1];
    let tps3 = sink_read(&mut aux, DPCD_MAX_LANE_COUNT, &mut lane_count).is_ok()
        && (lane_count[0] & TPS3_SUPPORTED) != 0;
    let layout = PsrLayout::from_generation(gpu.chip.generation);
    match psr_enable(&window, &mut aux, &caps, layout, mode, tps3) {
        Ok(active) => {
            runtime.caps = Some(caps);
            runtime.active = Some(active);
            runtime.frame = (mode.h_active, mode.v_active);
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu/edp: PSR enabled: {:?} (idle {} frames)",
                active,
                caps.idle_frames()
            );
        }
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "intel-gpu/edp: PSR not enabled: {:?} — plain eDP",
                e
            );
        }
    }
}

/// Runtime panel power-off, composed in spec order: PSR
/// disabled while the sink is still reachable, brightness to
/// zero through the backlight owner registry (the #1037
/// composition), then the PPS backlight gate and power target.
/// For suspend/remove paths; probe never calls it.
pub fn panel_power_off(gpu: &crate::intel_gpu::IntelGpu) -> Result<(), PpsError> {
    // AUX disable parks the desired level instead of replacing it with zero;
    // the post-S3 live-panel path replays the latest retained request. A failed
    // AUX disable still closes the independent PPS gate before dropping power.
    let aux_owned = crate::intel_dpcd_bl::suspend_for_bar(&gpu.gtt_mmadr).unwrap_or(true);
    if !aux_owned {
        if let Some(owner) = narf_drivers_backlight::panel_owner() {
            owner.set_brightness(0);
        }
    }
    let window = BarWindow(&gpu.gtt_mmadr);
    let (delays, active) = {
        let rt = EDP_RUNTIME.lock();
        (rt.delays, rt.active)
    };
    if let Some(active) = active {
        let mut aux = IntelAux::new(&window, Ddi::A);
        // A sink that won't answer its disable is not a reason
        // to leave the panel powered; the source side is already
        // off by the time this can fail.
        let _ = psr_disable(&window, &mut aux, active);
        EDP_RUNTIME.lock().active = None;
    }
    let delays = delays.unwrap_or(PanelDelays::SPEC_DEFAULTS);
    let mut pps = PanelPowerSequencer::with_delays(&window, delays);
    // The runtime sequencer starts with backlight_on = false;
    // the gate may nevertheless be open from probe time, so
    // close it explicitly (with its T9 wait) before power drops.
    pps.backlight_off();
    pps.power_off()
}

/// A PPS operation must not derive writes from inaccessible register values.
/// This guard latches any lost read, suppresses all later writes, and makes a
/// partial sequence return failure rather than publishing a recovered panel.
struct CheckedPps<'a, M: MmioWindow> {
    io: &'a M,
    lost: core::cell::Cell<bool>,
}
impl<'a, M: MmioWindow> CheckedPps<'a, M> {
    fn new(io: &'a M) -> Self {
        Self {
            io,
            lost: core::cell::Cell::new(false),
        }
    }
    fn valid(&self) -> bool {
        !self.lost.get()
    }
}
impl<M: MmioWindow> MmioWindow for CheckedPps<'_, M> {
    fn read32(&self, reg: u64) -> u32 {
        if self.lost.get() {
            return u32::MAX;
        }
        let value = self.io.read32(reg);
        if value == u32::MAX {
            self.lost.set(true);
        }
        value
    }
    fn write32(&self, reg: u64, value: u32) {
        if !self.lost.get() {
            self.io.write32(reg, value);
        }
    }
}
fn aux_panel_delays() -> PanelDelays {
    EDP_RUNTIME
        .lock()
        .delays
        .unwrap_or(PanelDelays::SPEC_DEFAULTS)
}
/// Close/post the source gate before system power may disappear. The caller
/// stamps this returned T9 duration after readback and waits asynchronously.
/// Linux b90c984d intel_pps.c::intel_pps_backlight_off closes/posts first,
/// then stamps last_backlight_off and waits edp_wait_backlight_off.
pub(crate) fn park_aux_backlight(mmio: &impl MmioWindow) -> Result<u64, PpsError> {
    let checked = CheckedPps::new(mmio);
    let control = checked.read32(PP_CONTROL);
    if !checked.valid() {
        return Err(PpsError::NotPoweredOn);
    }
    checked.write32(PP_CONTROL, control & !EDP_BLC_ENABLE);
    if checked.read32(PP_CONTROL) & EDP_BLC_ENABLE != 0 || !checked.valid() {
        return Err(PpsError::NotPoweredOn);
    }
    Ok(u64::from(aux_panel_delays().t9) * 100_000)
}
/// The qualified AUX owner supplies a current-capability/D0 checked window.
/// Keep the independent PPS gate closed across fresh video and DPCD restore.
pub(crate) fn prepare_aux_backlight_relight(mmio: &impl MmioWindow) -> Result<u64, PpsError> {
    let checked = CheckedPps::new(mmio);
    let mmio = &checked;
    if mmio.read32(PP_STATUS) == u32::MAX || mmio.read32(PP_CONTROL) == u32::MAX {
        return Err(PpsError::NotPoweredOn);
    }
    let delays = aux_panel_delays();
    let mut pps = PanelPowerSequencer::with_delays(mmio, delays);
    pps.init_registers();
    if mmio.read32(PP_ON_DELAYS) != delays.pp_on_value()
        || mmio.read32(PP_OFF_DELAYS) != delays.pp_off_value()
        || mmio.read32(PP_CONTROL) & PP_POWER_CYCLE_DELAY_MASK
            != delays.cycle_field() << PP_POWER_CYCLE_DELAY_SHIFT
        || !checked.valid()
    {
        return Err(PpsError::NotPoweredOn);
    }
    // No power-down follows this gate close, so T9 is not owed here.
    pps.pp_control_rmw(EDP_BLC_ENABLE, 0);
    pps.power_on()?;
    if mmio.read32(PP_STATUS) & IDLE_ON_MASK != IDLE_ON_VALUE
        || mmio.read32(PP_CONTROL) & EDP_BLC_ENABLE != 0
        || !checked.valid()
    {
        return Err(PpsError::NotPoweredOn);
    }
    // The owner stamps its monotonic deadline only after power-on completes,
    // then waits asynchronously across the real modeset/DPCD restoration.
    Ok(u64::from(delays.t8) * 100_000)
}
pub(crate) fn finish_aux_backlight_relight(
    mmio: &impl MmioWindow,
    deadline: u64,
    now: u64,
) -> Result<(), PpsError> {
    if now < deadline {
        return Err(PpsError::NotPoweredOn);
    }
    let checked = CheckedPps::new(mmio);
    let mmio = &checked;
    if mmio.read32(PP_STATUS) & IDLE_ON_MASK != IDLE_ON_VALUE || !checked.valid() {
        return Err(PpsError::NotPoweredOn);
    }
    let mut pps = PanelPowerSequencer::with_delays(mmio, aux_panel_delays());
    // T8 has already elapsed through the owner's async timer. No block_on or
    // synchronous delay is permitted in the system-PM executor poll.
    pps.backlight_on()?;
    let control = mmio.read32(PP_CONTROL);
    if !checked.valid() || control & EDP_BLC_ENABLE == 0 {
        return Err(PpsError::NotPoweredOn);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the PPS + PSR lane (#1020). Both halves are
    //! driven through scripted counterparts built from the
    //! specifications, not from the production decode: the MMIO
    //! panel replays `PP_STATUS` transitions the PRM describes,
    //! and the AUX sink's DPCD image is laid out per the eDP
    //! spec's field map (drm_dp.h), so a production constant
    //! that disagreed with the spec would fail here instead of
    //! agreeing with itself.

    extern crate alloc;

    use super::*;
    use crate::dp_aux::{AuxCommand, AuxRequest, AuxResponse, AuxStatus};
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Scripted MMIO panel ─────────────────────────────────

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum Event {
        Read(u64, u32),
        Write(u64, u32),
    }

    /// MMIO window whose reads replay a per-register script
    /// (then stick at the last value, like a status register
    /// holding state) and whose writes are recorded and read
    /// back — except the status registers, which only the
    /// script moves.
    #[derive(Default)]
    struct ScriptMmio {
        writes: RefCell<Vec<(u64, u32)>>,
        events: RefCell<Vec<Event>>,
        script: RefCell<BTreeMap<u64, Vec<u32>>>,
        current: RefCell<BTreeMap<u64, u32>>,
    }

    impl ScriptMmio {
        fn script_reads(&self, off: u64, vals: &[u32]) {
            self.script.borrow_mut().insert(off, vals.to_vec());
        }
        fn set_current(&self, off: u64, val: u32) {
            self.current.borrow_mut().insert(off, val);
        }
        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
        fn all_writes(&self) -> Vec<(u64, u32)> {
            self.writes.borrow().clone()
        }
    }

    impl MmioWindow for ScriptMmio {
        fn read32(&self, off: u64) -> u32 {
            let scripted = self.script.borrow_mut().get_mut(&off).and_then(|q| {
                if q.is_empty() {
                    None
                } else {
                    Some(q.remove(0))
                }
            });
            let v = match scripted {
                Some(v) => v,
                None => *self.current.borrow().get(&off).unwrap_or(&0),
            };
            self.current.borrow_mut().insert(off, v);
            self.events.borrow_mut().push(Event::Read(off, v));
            v
        }
        fn write32(&self, off: u64, val: u32) {
            self.events.borrow_mut().push(Event::Write(off, val));
            self.writes.borrow_mut().push((off, val));
            if off != PP_STATUS && off != PSR_STATUS && off != PSR2_STATUS {
                self.current.borrow_mut().insert(off, val);
            }
        }
    }

    // ── Scripted AUX sink ───────────────────────────────────

    /// An `AuxChannel` backed by a sparse DPCD image laid out
    /// per the spec; writes are logged verbatim for the
    /// byte-exact sink-setup assertions.
    #[derive(Default)]
    struct ScriptAux {
        dpcd: RefCell<BTreeMap<u32, u8>>,
        writes: RefCell<Vec<(u32, Vec<u8>)>>,
    }

    impl ScriptAux {
        fn set(&self, addr: u32, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                self.dpcd.borrow_mut().insert(addr + i as u32, *b);
            }
        }
        fn writes(&self) -> Vec<(u32, Vec<u8>)> {
            self.writes.borrow().clone()
        }
    }

    impl AuxChannel for ScriptAux {
        fn transact<'a>(
            &mut self,
            req: &AuxRequest<'_>,
            reply_buf: &'a mut [u8],
        ) -> Result<AuxResponse<'a>, AuxError> {
            match req.cmd {
                AuxCommand::NativeWrite => {
                    self.writes
                        .borrow_mut()
                        .push((req.address, req.data.to_vec()));
                    for (i, b) in req.data.iter().enumerate() {
                        self.dpcd.borrow_mut().insert(req.address + i as u32, *b);
                    }
                    reply_buf[0] = 0;
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[..0],
                    })
                }
                AuxCommand::NativeRead => {
                    let n = req.data.len();
                    reply_buf[0] = 0;
                    for i in 0..n {
                        reply_buf[1 + i] = *self
                            .dpcd
                            .borrow()
                            .get(&(req.address + i as u32))
                            .unwrap_or(&0);
                    }
                    Ok(AuxResponse {
                        status: AuxStatus::Ack,
                        data: &reply_buf[1..1 + n],
                    })
                }
                _ => Err(AuxError::UnknownStatus),
            }
        }
    }

    /// 1920×1080 panel mode (148.5 MHz, standard CEA timing).
    fn mode_1080p() -> Mode {
        Mode {
            pixel_clock_khz: 148_500,
            h_active: 1920,
            h_total: 2200,
            h_sync_start: 2008,
            h_sync_end: 2052,
            v_active: 1080,
            v_total: 1125,
            v_sync_start: 1084,
            v_sync_end: 1089,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }

    /// PSR2 caps as the spec-shaped DPCD image decodes them:
    /// support 3, setup code 2 (220 µs), sync latency 2.
    fn caps_psr2() -> PsrCaps {
        PsrCaps {
            psr2: true,
            y_coordinate: true,
            su_region_et: false,
            setup_time_us: 220,
            no_train_on_exit: false,
            su_x_granularity: 8,
            su_y_granularity: 8,
            sink_sync_latency: 2,
        }
    }

    fn runtime_psr2(layout: PsrLayout) -> EdpRuntime {
        let mut rt = EdpRuntime::new();
        rt.layout = Some(layout);
        rt.caps = Some(caps_psr2());
        rt.active = Some(PsrMode::Psr2);
        rt.frame = (1920, 1080);
        rt
    }

    fn smoke_kms_psr_handoff_requires_idle_and_inhibits_dirty() -> TestResult {
        for active in [PsrMode::Psr1, PsrMode::Psr2] {
            let mmio = ScriptMmio::default();
            mmio.set_current(PSR_CTL, PSR_CTL_RESTORE_ACTIVE_CTX | (1 << 31));
            mmio.set_current(PSR2_CTL, if active == PsrMode::Psr2 { 1 << 31 } else { 0 });
            mmio.script_reads(PSR_STATUS, &[3 << 29, 1 << 29, 0]);
            mmio.script_reads(PSR2_STATUS, &[8 << 28, 1 << 28, 0]);
            let mut aux = ScriptAux::default();
            let mut rt = runtime_psr2(PsrLayout::TigerLake);
            rt.active = Some(active);
            assert_eq!(rt.inhibit_for_kms(&mmio, &mut aux), Ok(()));
            assert!(rt.kms_inhibited && rt.flip_pending && rt.active.is_none());
            assert_eq!(
                mmio.writes_to(PSR_CTL),
                alloc::vec![PSR_CTL_RESTORE_ACTIVE_CTX]
            );
            assert_eq!(mmio.writes_to(PSR2_CTL), alloc::vec![0]);
            assert_eq!(mmio.writes_to(PSR2_MAN_TRK_CTL), alloc::vec![0]);
            assert_eq!(aux.writes(), alloc::vec![(DPCD_PSR_EN_CFG, alloc::vec![0])]);
            let writes = mmio.all_writes();
            assert_eq!(rt.notify_dirty(&mmio, None), Err(PsrError::FlipPending));
            assert_eq!(mmio.all_writes(), writes);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_kms",
        smoke_kms_psr_handoff_requires_idle_and_inhibits_dirty
    );

    fn smoke_kms_psr_failed_read_or_disable_preserves_inhibition() -> TestResult {
        struct Refused<'a>(&'a ScriptMmio);
        impl MmioWindow for Refused<'_> {
            fn read32(&self, off: u64) -> u32 {
                self.0.read32(off)
            }
            fn write32(&self, off: u64, value: u32) {
                if off != PSR_CTL {
                    self.0.write32(off, value);
                }
            }
        }
        for unavailable in [true, false] {
            let mmio = ScriptMmio::default();
            mmio.set_current(PSR_CTL, if unavailable { u32::MAX } else { 1 << 31 });
            let mut aux = ScriptAux::default();
            let mut rt = runtime_psr2(PsrLayout::TigerLake);
            assert_eq!(
                rt.inhibit_for_kms(&Refused(&mmio), &mut aux),
                Err(PsrError::Unavailable)
            );
            assert!(rt.kms_inhibited && rt.flip_pending && rt.active.is_some());
            assert!(aux.writes().is_empty());
            assert_eq!(rt.notify_dirty(&mmio, None), Err(PsrError::FlipPending));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_kms",
        smoke_kms_psr_failed_read_or_disable_preserves_inhibition
    );

    // ── PPS fixtures ────────────────────────────────────────

    /// The full power cycle, pinned step-for-step: delay
    /// programming from the spec defaults, cycle field in
    /// PP_CONTROL, then on → backlight → off with the exact
    /// PP_CONTROL value at every step.
    fn smoke_pps_power_cycle_sequence_is_pinned() -> TestResult {
        let mmio = ScriptMmio::default();
        // PP_STATUS reads in order: ctor (off), power_on's
        // have-power (off), cycle poll (off-idle), on poll
        // (sequencing, then on-idle), off poll (powering down,
        // then off).
        mmio.script_reads(
            PP_STATUS,
            &[0, 0, 0, 0x1000_0000, 0x8000_0008, 0x2000_0000, 0],
        );
        let delays = PanelDelays {
            t1_t3: 2100,
            t8: 2,
            t9: 2,
            t10: 5000,
            t11_t12: 6100,
        };
        let mut pps = PanelPowerSequencer::with_delays(&mmio, delays);
        pps.init_registers();
        if pps.power_on().is_err() || !pps.is_powered_on() {
            return TestResult::Fail("scripted panel must power on");
        }
        if pps.backlight_on().is_err() {
            return TestResult::Fail("backlight must follow power-on");
        }
        if pps.power_off().is_err() || pps.is_powered_on() {
            return TestResult::Fail("scripted panel must power off");
        }
        let expected = alloc::vec![
            (PP_ON_DELAYS, 0x0834_0001),  // t1_t3 2100 << 16 | hw t8 = 1
            (PP_OFF_DELAYS, 0x1388_0001), // t10 5000 << 16 | hw t9 = 1
            (PP_CONTROL, 0x70),           // cycle field 7 (610 ms, 100 ms units)
            (PP_CONTROL, 0x71),           // + PANEL_POWER_ON
            (PP_CONTROL, 0x75),           // + EDP_BLC_ENABLE
            (PP_CONTROL, 0x71),           // backlight gate closed first
            (PP_CONTROL, 0x70),           // power target dropped
        ];
        if mmio.all_writes() != expected {
            return TestResult::Fail("PP write sequence diverged from the pinned sequence");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_pps_power_cycle_sequence_is_pinned
    );

    /// A panel that never asserts the on-idle state: typed
    /// timeout, power target cleared again, backlight never
    /// touched — the panel is left powered-down.
    fn smoke_pps_panel_that_never_powers_on_is_left_off() -> TestResult {
        let mmio = ScriptMmio::default();
        let mut pps = PanelPowerSequencer::with_delays(&mmio, PanelDelays::SPEC_DEFAULTS);
        pps.status_poll_budget = 16;
        match pps.power_on() {
            Err(PpsError::PowerOnTimeout { status: 0 }) => {}
            _ => return TestResult::Fail("silent panel must produce PowerOnTimeout"),
        }
        if pps.is_powered_on() {
            return TestResult::Fail("failed panel must not read as powered");
        }
        // Writes: set PANEL_POWER_ON, then clear it again.
        if mmio.writes_to(PP_CONTROL) != alloc::vec![1, 0] {
            return TestResult::Fail("power target must be set once and cleared on failure");
        }
        if mmio
            .writes_to(PP_CONTROL)
            .iter()
            .any(|v| v & EDP_BLC_ENABLE != 0)
        {
            return TestResult::Fail("backlight gate must never open for a failed panel");
        }
        match pps.backlight_on() {
            Err(PpsError::NotPoweredOn) => {}
            _ => return TestResult::Fail("backlight without power must be refused"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_pps_panel_that_never_powers_on_is_left_off
    );

    /// Firmware-programmed delays win over the spec defaults;
    /// only zero (or forced-manual T8/T9) fields fall back.
    fn smoke_pps_programmed_delays_win_over_spec_defaults() -> TestResult {
        let mmio = ScriptMmio::default();
        mmio.set_current(PP_ON_DELAYS, (300 << 16) | 77);
        mmio.set_current(PP_OFF_DELAYS, 0);
        mmio.set_current(PP_CONTROL, 0);
        let mut pps = PanelPowerSequencer::new(&mmio);
        let d = pps.delays();
        if d.t1_t3 != 300 || d.t8 != 77 {
            return TestResult::Fail("programmed on-delays must be adopted verbatim");
        }
        if d.t9 != 500 || d.t10 != 5000 || d.t11_t12 != 6100 {
            return TestResult::Fail("zero fields must fall back to the spec defaults");
        }
        pps.init_registers();
        if mmio.writes_to(PP_ON_DELAYS) != alloc::vec![(300 << 16) | 1] {
            return TestResult::Fail("adopted t1_t3 must be reprogrammed (hw t8 forced to 1)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_pps_programmed_delays_win_over_spec_defaults
    );

    /// After a power-off, the cycle-delay status must clear
    /// before the power target is set again (T11+T12 enforced
    /// on the status side, not just by the timestamp).
    fn smoke_pps_cycle_delay_enforced_before_repower() -> TestResult {
        let mmio = ScriptMmio::default();
        mmio.script_reads(PP_STATUS, &[0, 0, 0x0800_0000, 0, 0x8000_0008]);
        let mut pps = PanelPowerSequencer::with_delays(&mmio, PanelDelays::SPEC_DEFAULTS);
        // Backdate the power-off stamp far beyond t11_t12 so the
        // software remainder is zero and only the status side
        // gates the sequence.
        pps.last_power_off_cycles = Some(
            narf_time::now_cycles().wrapping_sub(narf_time::wall::ns_to_cycles(10_000_000_000)),
        );
        if pps.power_on().is_err() {
            return TestResult::Fail("panel must power on once the cycle delay clears");
        }
        let events = mmio.events.borrow();
        let cycle_seen = events
            .iter()
            .position(|e| *e == Event::Read(PP_STATUS, 0x0800_0000));
        let target_set = events
            .iter()
            .position(|e| matches!(e, Event::Write(PP_CONTROL, v) if v & PANEL_POWER_ON != 0));
        match (cycle_seen, target_set) {
            (Some(c), Some(t)) if c < t => {}
            _ => {
                return TestResult::Fail(
                    "PANEL_POWER_ON must not be written before the cycle delay clears",
                )
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_pps_cycle_delay_enforced_before_repower
    );

    // ── PSR fixtures ────────────────────────────────────────

    /// The sink-setup conversation, byte-for-byte against the
    /// eDP spec field: PSR2 gets ALPM enable (0x03), the
    /// EN_CFG byte 0x61 (ENABLE | ENABLE_PSR2 | IRQ_HPD_CRC),
    /// then SET_POWER D0; PSR1 gets EN_CFG 0x07 (ENABLE |
    /// MAIN_LINK_ACTIVE | CRC) then D0. Source values are
    /// asserted as literals computed from the PRM field map.
    fn smoke_psr_sink_setup_bytes_are_spec_exact() -> TestResult {
        // PSR2 panel: support 3, caps = setup code 2, latency 2.
        let aux = ScriptAux::default();
        aux.set(DPCD_PSR_SUPPORT, &[3, 0x04, 0, 0, 0]);
        aux.set(DPCD_SYNC_LATENCY, &[0x20]);
        let mut aux = aux;
        let caps = match PsrCaps::probe(&mut aux) {
            Ok(Some(c)) => c,
            _ => return TestResult::Fail("support-3 panel must decode as PSR2 caps"),
        };
        let mmio = ScriptMmio::default();
        match psr_enable(
            &mmio,
            &mut aux,
            &caps,
            PsrLayout::AlderLakeP,
            &mode_1080p(),
            false,
        ) {
            Ok(PsrMode::Psr2) => {}
            _ => return TestResult::Fail("PSR2 panel + 1080p mode must enable PSR2"),
        }
        let expected_writes = alloc::vec![
            (DPCD_RECEIVER_ALPM_CONFIG, alloc::vec![0x03]),
            (DPCD_PSR_EN_CFG, alloc::vec![0x61]),
            (DPCD_SET_POWER, alloc::vec![0x01]),
        ];
        if aux.writes() != expected_writes {
            return TestResult::Fail("PSR2 sink setup diverged from the spec bytes");
        }
        if mmio.writes_to(PSR_CTL) != alloc::vec![0] {
            return TestResult::Fail("PSR1 CTL must be written disabled under PSR2");
        }
        // ENABLE | idle 6 | frame-before-SU 3 | TP2 2500us |
        // IO wake (7-5) | fast wake (7-5); ADL-P: no SU-track,
        // no Y-coordinate bit, block count 2.
        if mmio.writes_to(PSR2_CTL) != alloc::vec![0x8000_4A36] {
            return TestResult::Fail("PSR2_CTL composition diverged from the PRM fields");
        }
        if mmio.writes_to(PSR2_MAN_TRK_CTL) != alloc::vec![0x8000_6000] {
            return TestResult::Fail("MAN_TRK must start in continuous full frame");
        }

        // PSR1 panel: support 1, same caps/timing bytes.
        let aux = ScriptAux::default();
        aux.set(DPCD_PSR_SUPPORT, &[1, 0x04, 0, 0, 0]);
        aux.set(DPCD_SYNC_LATENCY, &[0x20]);
        let mut aux = aux;
        let caps = match PsrCaps::probe(&mut aux) {
            Ok(Some(c)) => c,
            _ => return TestResult::Fail("support-1 panel must decode as PSR1 caps"),
        };
        let mmio = ScriptMmio::default();
        match psr_enable(
            &mmio,
            &mut aux,
            &caps,
            PsrLayout::TigerLake,
            &mode_1080p(),
            false,
        ) {
            Ok(PsrMode::Psr1) => {}
            _ => return TestResult::Fail("PSR1 panel must enable PSR1"),
        }
        let expected_writes = alloc::vec![
            (DPCD_PSR_EN_CFG, alloc::vec![0x07]),
            (DPCD_SET_POWER, alloc::vec![0x01]),
        ];
        if aux.writes() != expected_writes {
            return TestResult::Fail("PSR1 sink setup diverged from the spec bytes");
        }
        // ENABLE | link standby | max sleep 0x1F | CRC |
        // TP1 2500 | TP2/TP3 2500 | TP4 0 | idle 6.
        if mmio.writes_to(PSR_CTL) != alloc::vec![0x89F0_06E6] {
            return TestResult::Fail("PSR1 CTL composition diverged from the PRM fields");
        }
        if !mmio.writes_to(PSR2_CTL).is_empty() || !mmio.writes_to(PSR2_MAN_TRK_CTL).is_empty() {
            return TestResult::Fail("PSR1 enable must not touch PSR2 registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_psr_sink_setup_bytes_are_spec_exact
    );

    /// The masking-defeating case: a PSR2 panel dirtied over
    /// lines 100..199 of 1080 must get an SU region equal to
    /// the granularity-aligned dirtied region (96..200 at
    /// granularity 8) — in each platform's MAN_TRK encoding —
    /// never the full frame.
    fn smoke_psr2_selective_update_region_matches_dirtied_region() -> TestResult {
        let dirty = SuRegion {
            x1: 8,
            y1: 100,
            x2: 1912,
            y2: 199,
        };
        let aligned = SuRegion {
            x1: 8,
            y1: 96,
            x2: 1912,
            y2: 200,
        };
        // ADL-P encoding: partial bit 31 | start 96 << 16 |
        // end (200 - 1).
        let mmio = ScriptMmio::default();
        let mut rt = runtime_psr2(PsrLayout::AlderLakeP);
        match rt.notify_dirty(&mmio, Some(dirty)) {
            Ok(DirtyOutcome::SelectiveUpdate(r)) if r == aligned => {}
            _ => return TestResult::Fail("ADL-P notify must return the aligned region"),
        }
        if mmio.writes_to(PSR2_MAN_TRK_CTL) != alloc::vec![0x8060_00C7] {
            return TestResult::Fail("ADL-P MAN_TRK value must encode lines 96..199");
        }
        if man_trk_value(PsrLayout::AlderLakeP, None) == 0x8060_00C7 {
            return TestResult::Fail("full-frame value must differ from the partial encoding");
        }
        // TGL encoding: enable | partial | start (96/4+1) << 21
        // | end (200/4+1) << 11.
        let mmio = ScriptMmio::default();
        let mut rt = runtime_psr2(PsrLayout::TigerLake);
        match rt.notify_dirty(&mmio, Some(dirty)) {
            Ok(DirtyOutcome::SelectiveUpdate(r)) if r == aligned => {}
            _ => return TestResult::Fail("TGL notify must return the aligned region"),
        }
        if mmio.writes_to(PSR2_MAN_TRK_CTL) != alloc::vec![0x8321_9802] {
            return TestResult::Fail("TGL MAN_TRK value must encode lines 96..200 in 4-line units");
        }
        // A whole-frame notify takes the full-frame encoding.
        match rt.notify_dirty(&mmio, None) {
            Ok(DirtyOutcome::FullFrameExit) => {}
            _ => return TestResult::Fail("full-frame notify must report FullFrameExit"),
        }
        if mmio.writes_to(PSR2_MAN_TRK_CTL)
            != alloc::vec![0x8321_9802, man_trk_value(PsrLayout::TigerLake, None)]
        {
            return TestResult::Fail("full-frame notify must program the full-frame value");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_psr2_selective_update_region_matches_dirtied_region
    );

    /// No-PSR and reserved-support panels: caps probe declines
    /// and the sink sees zero PSR writes.
    fn smoke_psr_unsupported_panels_get_zero_psr_traffic() -> TestResult {
        for support in [0u8, 5u8] {
            let aux = ScriptAux::default();
            aux.set(DPCD_PSR_SUPPORT, &[support, 0, 0, 0, 0]);
            let mut aux = aux;
            match PsrCaps::probe(&mut aux) {
                Ok(None) => {}
                _ => return TestResult::Fail("unsupported panel must not decode as PSR caps"),
            }
            if !aux.writes().is_empty() {
                return TestResult::Fail("unsupported panel must see zero PSR writes");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_psr_unsupported_panels_get_zero_psr_traffic
    );

    /// Malformed caps on a PSR-claiming panel are refused, and
    /// granularity bytes are ignored unless the sink requires
    /// its programmed granularity.
    fn smoke_psr_malformed_caps_are_refused() -> TestResult {
        // Setup-time code 7 is reserved by the spec.
        let aux = ScriptAux::default();
        aux.set(DPCD_PSR_SUPPORT, &[2, 0x0E, 0, 0, 0]);
        let mut aux = aux;
        match PsrCaps::probe(&mut aux) {
            Err(PsrError::InvalidCaps(_)) => {}
            _ => return TestResult::Fail("reserved setup-time code must be refused"),
        }
        if !aux.writes().is_empty() {
            return TestResult::Fail("refused caps must produce zero PSR writes");
        }
        // Granularity-required clear: garbage granularity bytes
        // must not leak into the decode (defaults are 4x4).
        let aux = ScriptAux::default();
        aux.set(DPCD_PSR_SUPPORT, &[3, 0x04, 0xFF, 0xFF, 0xFF]);
        aux.set(DPCD_SYNC_LATENCY, &[0x20]);
        let mut aux = aux;
        match PsrCaps::probe(&mut aux) {
            Ok(Some(c)) if c.su_x_granularity == 4 && c.su_y_granularity == 4 => {}
            _ => return TestResult::Fail("unrequired granularity bytes must be ignored"),
        }
        // Granularity-required set with zero fields: fall back
        // to the same defaults rather than dividing by zero
        // downstream.
        let aux = ScriptAux::default();
        aux.set(DPCD_PSR_SUPPORT, &[3, 0x24, 0, 0, 0]);
        aux.set(DPCD_SYNC_LATENCY, &[0x20]);
        let mut aux = aux;
        match PsrCaps::probe(&mut aux) {
            Ok(Some(c)) if c.su_x_granularity == 4 && c.su_y_granularity == 4 => {}
            _ => return TestResult::Fail("zero granularity fields must fall back to 4x4"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_psr_malformed_caps_are_refused
    );

    /// A dirty notification while a flip is pending is refused
    /// before any register write; clearing the flag admits the
    /// same notification.
    fn smoke_psr_entry_refused_while_flip_pending() -> TestResult {
        let mmio = ScriptMmio::default();
        let mut rt = runtime_psr2(PsrLayout::AlderLakeP);
        rt.flip_pending = true;
        match rt.notify_dirty(
            &mmio,
            Some(SuRegion {
                x1: 0,
                y1: 10,
                x2: 100,
                y2: 40,
            }),
        ) {
            Err(PsrError::FlipPending) => {}
            _ => return TestResult::Fail("flip-pending notify must be refused"),
        }
        if !mmio.all_writes().is_empty() {
            return TestResult::Fail("refused notify must not write any register");
        }
        rt.flip_pending = false;
        match rt.notify_dirty(
            &mmio,
            Some(SuRegion {
                x1: 0,
                y1: 10,
                x2: 100,
                y2: 40,
            }),
        ) {
            Ok(DirtyOutcome::SelectiveUpdate(_)) => {}
            _ => return TestResult::Fail("cleared flip flag must admit the notify"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_psr_entry_refused_while_flip_pending
    );

    /// A mode whose scanlines are too short for the PSR2 wake
    /// times (synthetic 800 MHz pixel clock) falls back to
    /// PSR1: PSR2 sink setup and registers stay untouched.
    fn smoke_psr2_falls_back_to_psr1_when_wake_lines_exceed() -> TestResult {
        let aux = ScriptAux::default();
        aux.set(DPCD_PSR_SUPPORT, &[3, 0x04, 0, 0, 0]);
        aux.set(DPCD_SYNC_LATENCY, &[0x20]);
        let mut aux = aux;
        let caps = match PsrCaps::probe(&mut aux) {
            Ok(Some(c)) => c,
            _ => return TestResult::Fail("PSR2 caps must decode"),
        };
        let fast_mode = Mode {
            pixel_clock_khz: 800_000,
            v_total: 1500,
            ..mode_1080p()
        };
        let mmio = ScriptMmio::default();
        match psr_enable(
            &mmio,
            &mut aux,
            &caps,
            PsrLayout::TigerLake,
            &fast_mode,
            false,
        ) {
            Ok(PsrMode::Psr1) => {}
            _ => return TestResult::Fail("over-long wake lines must fall back to PSR1"),
        }
        let expected_writes = alloc::vec![
            (DPCD_PSR_EN_CFG, alloc::vec![0x07]),
            (DPCD_SET_POWER, alloc::vec![0x01]),
        ];
        if aux.writes() != expected_writes {
            return TestResult::Fail("fallback must run the PSR1 sink setup (no ALPM write)");
        }
        if !mmio.writes_to(PSR2_CTL).is_empty() {
            return TestResult::Fail("fallback must not program PSR2_CTL");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_edp",
        smoke_psr2_falls_back_to_psr1_when_wake_lines_exceed
    );
}
