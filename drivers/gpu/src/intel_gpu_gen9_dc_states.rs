//! Display-9 (Skylake / Kaby Lake / Coffee Lake / Whiskey
//! Lake / Comet Lake) DC states: the DC-state mask, the
//! allowed mask and the target, plus the small state machine
//! that programs them.
//!
//! This is deliberately not the display-14 module
//! (`intel_gpu_dc_states`): that module's mask
//! (DC5 | DC6 | DC9 | DC3CO) is the display >= 12 mask, and
//! its service — the `DC_off` well, the DMC program lifecycle,
//! the pipe DMC, the deferred re-entry task — is display-14
//! machinery. Display 9 has its own mask, derived below
//! from the same Linux sources: [`Gen9Dc`] is the mask +
//! target + sticky-write core, in the shape of the display-11
//! module (`intel_gpu_gen11_dc_states`), and the Gen9
//! `DC_off` service built on it ([`Gen9DcCore`], below) is
//! opted in with `narf.intel.gen9_dc=1`. The DMC program it
//! depends on is the probe-time Gen9 load
//! (`intel_gpu_gen9_dmc`).
//!
//! ## Derivation (Linux 7.4-rc2, commit 7475ea8b)
//!
//! - `display/intel_display_power_well.c::gen9_dc_mask`:
//!   the base is `DC_STATE_EN_UPTO_DC5`; the final `else`
//!   arm — the one display 9 (non-GLK/BXT) takes — adds
//!   `DC_STATE_EN_UPTO_DC6`. So the display-9 mask is
//!   UPTO_DC5 | UPTO_DC6 = 0x3. (The grounding's "UPTO_DC5
//!   alone" recollection is wrong: it missed the `else`
//!   arm. The display-11 arm adds UPTO_DC6 | DC9, the
//!   GLK/BXT arm adds DC9, and DC3CO joins only at
//!   `DISPLAY_VER >= 12`.)
//! - `display/intel_display_power.c::get_allowed_dc_mask`:
//!   display 9 takes `max_dc = 2` (the `DISPLAY_VER >= 9`
//!   arm); the mask starts at 0 — DC9 joins only for
//!   GLK/BXT or `DISPLAY_VER >= 11`, so a Skylake-family
//!   part gets none of it — and `requested_dc = max_dc = 2`
//!   adds `DC_STATE_EN_UPTO_DC6`. So the allowed mask is
//!   UPTO_DC6 = 0x2, and the sanitized target
//!   (`sanitize_target_dc_state(display, UPTO_DC6)`) is DC6.
//!   This closes the grounding §17 display-9 `max_dc` /
//!   allowed-DC-mask item: `max_dc` is 2, the allowed mask
//!   is 0x2, and DC9 is NOT allowed on display 9 (it is a
//!   GLK/BXT-or-11+ bit).
//! - `display/intel_display_power_well.c::gen9_set_dc_state`:
//!   the target is masked by the allowed mask, written with
//!   `gen9_write_dc_state`'s re-read/rewrite discipline, and
//!   the tracked field is `DC_STATE_EN & gen9_dc_mask`.
//!   `gen9_sanitize_dc_state` adopts the hardware field the
//!   same way.
//!
//! ## Preconditions (not checked here)
//!
//! Entering DC6 requires a loaded main DMC program
//! (`assert_can_enable_dc6`): on Gen9 that is the SKL DMC
//! (`skl_dmc_ver1_27`) or the KBL DMC (`kbl_dmc_ver1_04`,
//! 0x3000 per-program ceiling), loaded by the modeset's DMC
//! step. This module programs the target; the caller arms it
//! only with a loaded program. DC9 is never this module's
//! target — it is not even in the allowed mask on display 9.
//!
//! ## Gen9 LP (Broxton / Gemini Lake)
//!
//! [`Gen9Dc::new_lp`] is the GLK/BXT arm of the same sources:
//! `gen9_dc_mask` is UPTO_DC5 | DC9 (no DC6), `get_allowed_dc_mask` takes
//! DC9 plus `max_dc = 1`'s UPTO_DC5, and the sanitized target falls from
//! DC6 to DC5. DC9 stays out of the runtime target here as well: it is the
//! system-suspend state (`bxt_enable_dc9`), entered by the service's
//! suspend preparation below.
//!
//! ## The `DC_off` service (`narf.intel.gen9_dc=1`)
//!
//! [`Gen9DcCore`] is the display-9 / Gen9 LP `DC_off` power well: per-user
//! references ([`Gen9DcUser`]), the deferred re-entry deadline and the arm
//! gates, around a [`Gen9Dc`]. It is a sibling of the display-14 `DcCore`
//! (`intel_gpu_dc_states`), not a generalisation of it: that core carries
//! the display >= 12 mask, the display >= 14 DC6-residency counter, the pipe
//! DMC gate and a registry-acquired DMC container, none of which exist on
//! Gen9, and leaving it untouched keeps display 14 byte-identical. The only
//! join is that the display-14 `DcRef` (KMS sessions, legacy guards) carries
//! this service's reference when no display-14 service is installed.
//!
//! Sources (Linux 7.4-rc4):
//!
//! - `intel_display_power_map.c`: `skl_pwdoms_dc_off` is PW_2's domains
//!   (pipes B/C, transcoders A-C, DDI lanes B-E, AUX B-D, audio, VGA) plus
//!   AUX_A, GT_IRQ, DC_OFF and INIT; `bxt_pwdoms_dc_off` and
//!   `glk_pwdoms_dc_off` add GMBUS. Pipe A, the eDP transcoder and DDI A are
//!   in none of them (PW_1, "handled by the DMC firmware"), which is why an
//!   idle lit eDP panel on Pipe A may sit in DC5/DC6.
//! - `intel_display_power_well.c`: enabling `DC_off`
//!   (`gen9_dc_off_power_well_enable` → `gen9_disable_dc_states`) writes
//!   `DC_STATE_DISABLE`; disabling it enables the target, and only with a
//!   DMC payload (`gen9_dc_off_power_well_disable`): `skl_enable_dc6` or
//!   `gen9_enable_dc5`, each applying Wa Display #1183
//!   (`SKL_SELECT_ALTERNATE_DC_EXIT` in `GEN8_CHICKEN_DCPR_1`) on
//!   `DISPLAY_VER == 9 && !broxton` (Gemini Lake is display 10). The
//!   asserts become refusals: `assert_can_enable_dc5` (power well 2 off,
//!   main DMC loaded) and `assert_can_enable_dc6` (utility pin not in PWM
//!   mode, main DMC loaded).
//! - `intel_display_power.c`: `get_allowed_dc_mask` / `sanitize_target_dc_state`
//!   (DC6 on display 9, DC5 on GLK/BXT, as [`Gen9Dc`] derives),
//!   `skl_display_core_init` / `bxt_display_core_init` (DC_STATE_DISABLE
//!   first), `__intel_display_power_init_hw` (the `POWER_DOMAIN_INIT`
//!   reference held until hardware readout), and `skl_display_core_uninit`
//!   / `bxt_display_core_uninit` (DC states disabled before suspend).
//! - `intel_display.c::intel_atomic_commit_tail` releases its `DC_OFF`
//!   reference 17 ms late (`intel_display_power_put_async_delay`).
//!
//! Production wiring, all behind `narf.intel.gen9_dc=1` (default off: with
//! the option clear no service exists, every hook is inert and nothing new
//! is written): probe installs the service before the Gen9 DMC load and
//! holds the Init reference (DC states disabled); the end of probe releases
//! it only with a loaded DMC and an owned internal panel on Pipe A (the
//! probe-time takeover, PPS power-on, DPIO PHY power and hotplug pass all
//! run under Init). After that, these take a reference for their hardware
//! conversation: the Gen9 modeset and pipeline teardown
//! (`intel_gpu_modeset::Modeset`), every AUX transfer (`IntelAux`), GMBUS
//! on Gen9 LP, the hotplug poll and enable (`intel_gpu_dp`), the
//! external-output pass (`intel_gpu::poll_dp_hpd_events`), the runtime
//! panel power-off (`intel_gpu_edp::panel_power_off`), and KMS sessions and
//! legacy guards (through the display-14 `DcRef`). The execlists GT owner
//! holds a `GtIrq` reference while it is unparked (`__gt_unpark`'s
//! `POWER_DOMAIN_GT_IRQ`, a latency workaround) and drops it at park, after
//! which re-entry waits Linux's 100 ms async put. Panel brightness (the
//! backlight crate's PWM writes) takes none, as in Linux.
//!
//! System suspend (`intel_display_power_suspend_late`) takes the Suspend
//! reference first. On Gen9 LP, with every transcoder off, power well 2
//! not requested and no other holder in its conversation, it then runs the
//! rest of `bxt_display_core_uninit` (DBUF off, CDCLK to the bypass with
//! the DE PLL off, the PW_1 request dropped) and `bxt_enable_dc9`
//! (`bxt_pps_reset_all`, then DC9); no reference is granted until the
//! resume. Otherwise DC states stay disabled and the suspend proceeds.
//! Resume (`intel_display_power_resume_early`) re-adopts the field, runs
//! `bxt_disable_dc9` (or the display-core init's `DC_STATE_DISABLE`), the
//! rest of `skl_display_core_init` / `bxt_display_core_init` (the PCH reset
//! handshake, PW_1 with its fuses, MISC IO on display 9 proper,
//! `intel_cdclk_init_hw`, the DBUF slice) and `intel_dmc_load_program` from
//! the resident copy, and releases the Suspend reference only once the
//! reloaded program verifies. The next eDP sequencer user after DC9
//! reprograms its registers first (`bxt_power_sequencer_idx`).
//!
//! Stricter than Linux, and why: every last release defers re-entry by 17
//! ms, or 100 ms after GT_IRQ as in Linux (Linux releases GMBUS and INIT
//! synchronously and AUX after 100 ms);
//! DC6 also requires power well 2 off (Linux checks it only on the DC5
//! path) and any requester's PW_2 bit refuses, not only the driver's; the
//! hotplug poll and the panel power-off, which Linux runs without
//! `DC_off`, take a reference; a live external route refuses re-entry even
//! with power well 2 off; a program lost at runtime is never re-entered
//! (only the resume reloads it); DC5/DC6 are disarmed for every system
//! sleep target (Linux leaves display 9 in DC6 across s2idle); DC9 is
//! refused unless the display is dark (Linux only warns) and fences every
//! holder; a CDCLK init that fails (Linux only logs) fails the display-core
//! init, so the program is not reloaded and DC states stay off; Skylake's
//! CDCLK init never takes VCO 8640 (Wa Display #1183, Linux warns);
//! a DC exit refused at unpark leaves the GT running without `GT_IRQ`.
//! Not checked, unlike Linux: `assert_can_enable_dc9`'s "interrupts
//! disabled" (the async preparation runs with device interrupts live; the
//! fence keeps every display holder out instead).

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_dc_states::{
    sanitize_target, write_dc_state_sticky, DcError, DcUser, DC_REENABLE_DELAY_NS,
    DC_STATE_DISABLE, DC_STATE_EN_UPTO_DC5, DC_STATE_EN_UPTO_DC5_DC6_MASK, DC_STATE_EN_UPTO_DC6,
    UTIL_PIN_CTL, UTIL_PIN_ENABLE, UTIL_PIN_MODE_MASK, UTIL_PIN_MODE_PWM,
};
use crate::intel_gpu_dmc::{parse_dmc_firmware_gen9_max, verify_program, DmcId, DC_STATE_EN};
use crate::intel_gpu_gt::Gen9Platform;

/// `gen9_dc_mask` for display 9: UPTO_DC5 | UPTO_DC6.
pub const GEN9_DC_MASK: u32 = DC_STATE_EN_UPTO_DC5 | DC_STATE_EN_UPTO_DC6;
/// `get_allowed_dc_mask` for display 9 (`max_dc = 2`):
/// UPTO_DC6.
pub const GEN9_ALLOWED_DC_MASK: u32 = DC_STATE_EN_UPTO_DC6;
/// The sanitized target on display 9: DC6.
pub const GEN9_DC_TARGET: u32 = DC_STATE_EN_UPTO_DC6;
/// `gen9_dc_mask` for Gemini Lake and Broxton: UPTO_DC5 | DC9.
pub const GEN9_LP_DC_MASK: u32 = DC_STATE_EN_UPTO_DC5 | crate::intel_gpu_dc_states::DC_STATE_EN_DC9;
/// `get_allowed_dc_mask` for Gemini Lake and Broxton (DC9, `max_dc = 1`):
/// DC9 | UPTO_DC5.
pub const GEN9_LP_ALLOWED_DC_MASK: u32 =
    crate::intel_gpu_dc_states::DC_STATE_EN_DC9 | DC_STATE_EN_UPTO_DC5;

/// The display-9 DC-state core: the tracked
/// `DC_STATE_EN & GEN9_DC_MASK` field, the sanitized target,
/// and the latched write failure, if any.
#[derive(Clone, Copy, Debug)]
pub struct Gen9Dc {
    /// `gen9_dc_mask` and `get_allowed_dc_mask` for the part.
    mask: u32,
    allowed: u32,
    tracked: u32,
    target: u32,
    fault: Option<DcError>,
    mismatches: u32,
}

impl Gen9Dc {
    /// A display-9 core with nothing tracked and the target
    /// sanitized against the derived allowed mask (DC6).
    pub fn new() -> Self {
        Self::with_masks(GEN9_DC_MASK, GEN9_ALLOWED_DC_MASK)
    }

    /// The Gemini Lake / Broxton core: the GLK/BXT masks, and DC6
    /// sanitized down to DC5.
    pub fn new_lp() -> Self {
        Self::with_masks(GEN9_LP_DC_MASK, GEN9_LP_ALLOWED_DC_MASK)
    }

    fn with_masks(mask: u32, allowed: u32) -> Self {
        Self {
            mask,
            allowed,
            tracked: 0,
            target: sanitize_target(allowed, GEN9_DC_TARGET),
            fault: None,
            mismatches: 0,
        }
    }

    /// The derived allowed mask of display 9 (big core).
    pub fn allowed() -> u32 {
        GEN9_ALLOWED_DC_MASK
    }

    /// This core's allowed mask.
    pub fn allowed_mask(&self) -> u32 {
        self.allowed
    }

    /// This core's `gen9_dc_mask`.
    pub fn mask(&self) -> u32 {
        self.mask
    }

    /// The tracked `DC_STATE_EN & GEN9_DC_MASK`.
    pub fn tracked(&self) -> u32 {
        self.tracked
    }

    /// The sanitized target this core programs.
    pub fn target(&self) -> u32 {
        self.target
    }

    /// The latched write failure, if any.
    pub fn fault(&self) -> Option<DcError> {
        self.fault
    }

    /// Whether a DC5/DC6 target is currently programmed.
    pub fn armed(&self) -> bool {
        self.tracked & DC_STATE_EN_UPTO_DC5_DC6_MASK != 0
    }

    /// Times `DC_STATE_EN` disagreed with the tracked value.
    pub fn mismatches(&self) -> u32 {
        self.mismatches
    }

    /// `gen9_sanitize_dc_state`: adopt the hardware field,
    /// masked by the display-9 mask. Bits outside the mask
    /// (notably DC9 and DC3CO) are dropped from tracking.
    pub fn sanitize<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), DcError> {
        let value = regs.read32(DC_STATE_EN);
        if value == u32::MAX {
            return Err(DcError::Unavailable);
        }
        self.tracked = value & self.mask;
        Ok(())
    }

    /// `gen9_set_dc_state` for display 9: the state is
    /// masked by the allowed mask and written with the
    /// sticky-write discipline. A write that does not stick
    /// latches the fault and the found value.
    pub fn set_dc_state<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        state: u32,
    ) -> Result<(), DcError> {
        let state = state & self.allowed;
        let value = regs.read32(DC_STATE_EN);
        if value == u32::MAX {
            return Err(DcError::Unavailable);
        }
        if value & self.mask != self.tracked {
            self.mismatches = self.mismatches.saturating_add(1);
        }
        let wanted = (value & !self.mask) | state;
        if let Err(found) = write_dc_state_sticky(regs, wanted) {
            let error = DcError::DidNotStick { wanted, found };
            self.fault = Some(error);
            self.tracked = found & self.mask;
            return Err(error);
        }
        self.tracked = wanted & self.mask;
        Ok(())
    }

    /// Program the sanitized target (DC6).
    pub fn set_target<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), DcError> {
        let target = self.target;
        self.set_dc_state(regs, target)
    }

    /// Exit every DC state.
    pub fn disable<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), DcError> {
        self.set_dc_state(regs, DC_STATE_DISABLE)
    }
}

impl Default for Gen9Dc {
    fn default() -> Self {
        Self::new()
    }
}

// ── The Gen9 `DC_off` well ──────────────────────────────────────

/// `HSW_PWR_WELL_CTL1`: the BIOS request register.
pub const HSW_PWR_WELL_CTL1: u64 = 0x45400;
/// `HSW_PWR_WELL_CTL2`: the driver request register.
pub const HSW_PWR_WELL_CTL2: u64 = 0x45404;
/// `HSW_PWR_WELL_CTL3`: the KVMR request register.
pub const HSW_PWR_WELL_CTL3: u64 = 0x45408;
/// `HSW_PWR_WELL_CTL4`: the debug request register.
pub const HSW_PWR_WELL_CTL4: u64 = 0x4540C;
/// `SKL_PW_CTL_IDX_PW_2`.
pub const SKL_PW_CTL_IDX_PW_2: u32 = 15;
/// `HSW_PWR_WELL_CTL_REQ(SKL_PW_CTL_IDX_PW_2) |
/// HSW_PWR_WELL_CTL_STATE(SKL_PW_CTL_IDX_PW_2)`: `0x2 << 30 | 0x1 << 30`.
pub const PW_2_REQ_STATE: u32 =
    (0x2 << (SKL_PW_CTL_IDX_PW_2 * 2)) | (0x1 << (SKL_PW_CTL_IDX_PW_2 * 2));
/// `GEN8_CHICKEN_DCPR_1`.
pub const GEN8_CHICKEN_DCPR_1: u64 = 0x46430;
/// `SKL_SELECT_ALTERNATE_DC_EXIT` (Wa Display #1183).
pub const SKL_SELECT_ALTERNATE_DC_EXIT: u32 = 1 << 30;

/// A holder of the Gen9 `DC_off` well. Each user is counted separately,
/// so a release can never cancel somebody else's reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gen9DcUser {
    /// Probe through the end of hardware readout (`POWER_DOMAIN_INIT`).
    Init = 0,
    /// A Gen9 modeset, relight or pipeline teardown: the commit's
    /// `POWER_DOMAIN_DC_OFF` (`intel_atomic_commit_tail`).
    Modeset = 1,
    /// A KMS transaction (flip, cursor, colour, console), through the
    /// display-14 `DcRef` that carries this service's reference.
    Kms = 2,
    /// One AUX transfer: `intel_dp_aux_xfer` holds the port's AUX domain,
    /// and AUX_A (and AUX_B-D, through PW_2's domains) is in every Gen9
    /// `dc_off` list.
    Aux = 3,
    /// One GMBUS transfer (`POWER_DOMAIN_GMBUS`): a `dc_off` domain on
    /// Broxton and Gemini Lake only (`bxt_pwdoms_dc_off`,
    /// `glk_pwdoms_dc_off`); `skl_pwdoms_dc_off` has none, so on display 9
    /// this reference holds nothing.
    Gmbus = 4,
    /// One hotplug poll or enable (stricter than Linux, which reads the
    /// hotplug registers without `DC_off`).
    Hpd = 5,
    /// One external-output pass: hotplug handling, probe, connect,
    /// disconnect.
    External = 6,
    /// One panel power-sequencer conversation (stricter than Linux, whose
    /// PPS takes `POWER_DOMAIN_DISPLAY_CORE`, outside `DC_off`).
    Pps = 7,
    /// System suspend preparation through the resume that reloads the DMC
    /// program.
    Suspend = 8,
    /// The GT while it is unparked (`__gt_unpark`'s `POWER_DOMAIN_GT_IRQ`,
    /// a `dc_off` domain on every Gen9 part): DMC DC-state transitions during
    /// command submission cost interrupt latency. Released at park with
    /// Linux's 100 ms async put ([`GT_IRQ_PUT_DELAY_NS`]).
    GtIrq = 9,
}

/// Number of [`Gen9DcUser`]s.
pub const GEN9_DC_USER_COUNT: usize = 10;

/// `__gt_park`'s `intel_display_power_put_async(.., POWER_DOMAIN_GT_IRQ, ..)`
/// with the default delay (`__intel_display_power_put_async`: 100 ms).
pub const GT_IRQ_PUT_DELAY_NS: u64 = 100_000_000;

impl From<DcUser> for Gen9DcUser {
    /// The display-14 vocabulary the shared KMS / legacy-guard paths use,
    /// onto this service's users.
    fn from(user: DcUser) -> Self {
        match user {
            DcUser::Init | DcUser::Load => Self::Init,
            DcUser::Modeset | DcUser::PipeDmc | DcUser::Phy => Self::Modeset,
            DcUser::Kms | DcUser::Psr => Self::Kms,
            DcUser::Suspend => Self::Suspend,
            DcUser::Aux => Self::Aux,
            DcUser::ExternalRoute | DcUser::External => Self::External,
        }
    }
}

/// Inputs to the re-entry decision that live outside this module.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gen9ArmGates {
    /// An external DP/HDMI/MST route is live or its stop is unproven
    /// (`intel_gpu::external_routes_stopped`).
    pub external_route_active: bool,
}

/// Why Gen9 DC re-entry did not happen. Except `NotDue`, every block
/// consumes the pending release: the next release re-evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gen9ArmBlock {
    /// A `DC_off` reference is held.
    Busy,
    /// No release is pending.
    NotScheduled,
    /// The 17 ms deferral has not elapsed; retry at the deadline.
    NotDue(u64),
    /// A `DC_STATE_EN` write failed earlier (latched).
    Faulted,
    /// No verified DMC program was handed to the service.
    NoProgram,
    /// The resident main program no longer verifies.
    ProgramLost,
    /// The allowed mask admits no target.
    NoTarget,
    /// See [`Gen9ArmGates::external_route_active`].
    ExternalRoute,
    /// Power well 2 is requested or on (`assert_can_enable_dc5`): `reg`
    /// is the `HSW_PWR_WELL_CTL*` register that showed it.
    PowerWell2 { reg: u64, value: u32 },
    /// The utility pin drives PWM (`assert_can_enable_dc6`).
    UtilPinPwm,
    /// A gate register read all-ones.
    Unavailable,
    /// The target write failed (and is latched).
    Write(DcError),
}

/// `TRANSCONF` of transcoders A, B, C and EDP (`HSW_PIPE_OFFSETS` on Gen9
/// LP: 0x70008, 0x71008, 0x72008, 0x7f008) and `TRANSCONF_ENABLE`.
pub const TRANSCONF_REGS: [u64; 4] = [0x70008, 0x71008, 0x72008, 0x7f008];
/// `TRANSCONF_ENABLE`.
pub const TRANSCONF_ENABLE: u32 = 1 << 31;
/// `SKL_PW_CTL_IDX_PW_1`.
pub const SKL_PW_CTL_IDX_PW_1: u32 = 14;
/// `SKL_PW_CTL_IDX_MISC_IO`.
pub const SKL_PW_CTL_IDX_MISC_IO: u32 = 0;
/// `SKL_FUSE_STATUS` and `SKL_FUSE_PG_DIST_STATUS(pg)` (bit `27 - pg`).
pub const SKL_FUSE_STATUS: u64 = 0x42000;
/// `DBUF_CTL_S(0)`, `DBUF_POWER_REQUEST` and `DBUF_POWER_STATE`.
pub const DBUF_CTL_S1: u64 = 0x45008;
/// `DBUF_POWER_REQUEST`.
pub const DBUF_POWER_REQUEST: u32 = 1 << 31;
/// `DBUF_POWER_STATE`.
pub const DBUF_POWER_STATE: u32 = 1 << 30;
/// `HSW_NDE_RSTWRN_OPT` (`intel_display_regs.h`).
pub const HSW_NDE_RSTWRN_OPT: u64 = 0x46408;
/// `RESET_PCH_HANDSHAKE_ENABLE` (bit 4 of `HSW_NDE_RSTWRN_OPT`).
pub const RESET_PCH_HANDSHAKE_ENABLE: u32 = 1 << 4;

/// `HSW_PWR_WELL_CTL_REQ(idx)`.
pub const fn pw_req(idx: u32) -> u32 {
    0x2 << (idx * 2)
}
/// `HSW_PWR_WELL_CTL_STATE(idx)`.
pub const fn pw_state(idx: u32) -> u32 {
    0x1 << (idx * 2)
}
/// `SKL_FUSE_PG_DIST_STATUS(pg)`.
pub const fn fuse_pg_dist_status(pg: u32) -> u32 {
    1 << (27 - pg)
}

/// Why Gen9 LP did not enter DC9 for a system suspend. Every refusal but
/// [`Dc9Block::Uninit`] precedes any write; DC states then stay disabled
/// (DC0) through the suspend, which proceeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dc9Block {
    /// Not Broxton / Gemini Lake: DC9 is not in display 9's allowed mask.
    NotLp,
    /// No Suspend reference is held (preparation did not run).
    NotSuspending,
    /// A holder other than Init and Suspend is in its hardware conversation.
    Busy,
    /// A `DC_STATE_EN` write failed earlier (latched).
    Faulted,
    /// `DC_STATE_EN` already has DC9 (`assert_can_enable_dc9`).
    AlreadyProgrammed,
    /// `DC_STATE_EN` still has DC5 (`assert_can_enable_dc9`).
    Dc5Programmed,
    /// The driver requests power well 2 (`assert_can_enable_dc9`).
    PowerWell2(u32),
    /// A transcoder is still enabled (Linux's "mode set disable sequence was
    /// followed" TODO, as a refusal): `reg` is its `TRANSCONF`.
    DisplayActive { reg: u64, value: u32 },
    /// A gate register read all-ones.
    Unavailable,
    /// `bxt_display_core_uninit`'s DBUF, CDCLK or PW_1 step did not
    /// complete; the display core may be partly uninitialized (the resume's
    /// display-core init restores it).
    Uninit,
    /// The DC9 write failed (and is latched).
    Write(DcError),
}

/// The probe-time DMC container the service re-verifies before every
/// re-entry, with its per-program payload ceiling.
#[derive(Clone, Copy)]
struct Resident {
    blob: &'static [u8],
    max: usize,
}

impl core::fmt::Debug for Resident {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Resident")
            .field("bytes", &self.blob.len())
            .field("max", &self.max)
            .finish()
    }
}

/// The Gen9 `DC_off` well: references, the deferred re-entry, the
/// resident DMC program and the [`Gen9Dc`] it programs.
#[derive(Clone, Debug)]
pub struct Gen9DcCore {
    dc: Gen9Dc,
    /// The sub-platform (the resume's CDCLK init needs Skylake's VCO rule).
    platform: Gen9Platform,
    /// Broxton / Gemini Lake: GMBUS is a `DC_off` domain and Wa Display
    /// #1183 does not apply.
    lp: bool,
    /// Gemini Lake (its CDCLK table).
    glk: bool,
    /// Display 9 proper: DPLL0's VCO when the suspend began
    /// (`skl_preferred_vco_freq`), restored by the resume's CDCLK init; 0
    /// when unknown.
    vco: u32,
    refs: [u32; GEN9_DC_USER_COUNT],
    arm_at: Option<u64>,
    /// The GT_IRQ reference's 100 ms async put: no re-entry before it.
    gt_irq_until: Option<u64>,
    /// No new reference is granted: DC9 is being entered or is entered.
    fenced: bool,
    /// DC9 entered by [`Self::enter_dc9`]; cleared by the resume's exit.
    dc9: bool,
    /// `bxt_pps_reset_all`: the eDP power sequencer lost its registers in
    /// DC9 and is reprogrammed at its next use ([`Self::take_pps_reset`]).
    pps_reset: bool,
    /// The probe-time DMC container.
    program: Option<Resident>,
    /// The main program stopped verifying: never re-entered again.
    lost: bool,
    /// [`Self::boot`] read the field and wrote `DC_STATE_DISABLE`.
    booted: bool,
    arms: u64,
    last_block: Option<Gen9ArmBlock>,
}

impl Gen9DcCore {
    /// A core for `platform`: [`Gen9Dc::new_lp`] on Broxton / Gemini
    /// Lake, [`Gen9Dc::new`] otherwise. Nothing held, nothing written.
    pub fn new(platform: Gen9Platform) -> Self {
        let lp = platform.is_lp();
        Self {
            dc: if lp { Gen9Dc::new_lp() } else { Gen9Dc::new() },
            platform,
            lp,
            glk: platform == Gen9Platform::GeminiLake,
            vco: 0,
            refs: [0; GEN9_DC_USER_COUNT],
            arm_at: None,
            gt_irq_until: None,
            fenced: false,
            dc9: false,
            pps_reset: false,
            program: None,
            lost: false,
            booted: false,
            arms: 0,
            last_block: None,
        }
    }

    /// Whether this is the Gen9 LP core.
    pub fn lp(&self) -> bool {
        self.lp
    }
    /// The DC-state core.
    pub fn dc(&self) -> &Gen9Dc {
        &self.dc
    }
    /// The sanitized target (DC6 on display 9, DC5 on Gen9 LP).
    pub fn target(&self) -> u32 {
        self.dc.target()
    }
    /// Whether a DC5/DC6 target is currently programmed.
    pub fn armed(&self) -> bool {
        self.dc.armed()
    }
    /// Total `DC_off` references.
    pub fn total(&self) -> u32 {
        self.refs.iter().fold(0u32, |sum, r| sum.saturating_add(*r))
    }
    /// References held by `user`.
    pub fn refs(&self, user: Gen9DcUser) -> u32 {
        self.refs[user as usize]
    }
    /// Pending re-entry deadline.
    pub fn arm_deadline(&self) -> Option<u64> {
        self.arm_at
    }
    /// Successful re-entries.
    pub fn arms(&self) -> u64 {
        self.arms
    }
    /// The last re-entry refusal.
    pub fn last_block(&self) -> Option<Gen9ArmBlock> {
        self.last_block
    }
    /// Whether the resident program stopped verifying.
    pub fn program_lost(&self) -> bool {
        self.lost
    }
    /// Whether DC9 is entered.
    pub fn dc9(&self) -> bool {
        self.dc9
    }
    /// Whether this is the Gemini Lake core.
    pub fn glk(&self) -> bool {
        self.glk
    }
    /// The sub-platform.
    pub fn platform(&self) -> Gen9Platform {
        self.platform
    }
    /// DPLL0's VCO recorded when the suspend began (display 9 proper), the
    /// resume's preferred VCO; 0 when unknown.
    pub fn preferred_vco(&self) -> u32 {
        self.vco
    }
    /// The probe-time DMC container and its payload ceiling, if handed over.
    pub fn resident(&self) -> Option<(&'static [u8], usize)> {
        self.program.map(|r| (r.blob, r.max))
    }
    /// `bxt_power_sequencer_idx`'s `bxt_pps_reset` test-and-clear: whether
    /// the eDP sequencer must be reprogrammed (`pps_init_registers`) before
    /// its next use, because DC9 lost its registers.
    pub fn take_pps_reset(&mut self) -> bool {
        core::mem::take(&mut self.pps_reset)
    }

    /// Whether `user`'s hardware is in this platform's `DC_off` domains
    /// (every user but GMBUS on display 9).
    pub fn needs_dc_off(&self, user: Gen9DcUser) -> bool {
        user != Gen9DcUser::Gmbus || self.lp
    }

    /// Display-core init (`skl_display_core_init` /
    /// `bxt_display_core_init`): adopt the hardware field
    /// (`gen9_sanitize_dc_state`), write `DC_STATE_DISABLE`
    /// (`gen9_set_dc_state`, unconditional as in Linux), and hold the Init
    /// reference whatever the outcome: after a failure (an all-ones read,
    /// or a write that did not stick) [`Self::release_init`] keeps it, so
    /// DC states are never re-entered.
    pub fn boot<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), DcError> {
        let result = self.dc.sanitize(regs).and_then(|()| self.dc.disable(regs));
        self.booted = result.is_ok();
        self.arm_at = None;
        let slot = &mut self.refs[Gen9DcUser::Init as usize];
        *slot = slot.saturating_add(1);
        result
    }

    /// Take a `DC_off` reference. The first one cancels any pending
    /// re-entry and, if the hardware field or the tracked state shows a DC
    /// state enabled, exits it (`gen9_disable_dc_states`) before
    /// returning: the caller may touch display registers only after `Ok`.
    /// `Ok(false)`: `user` needs no `DC_off` here and nothing was counted.
    /// A failed exit counts nothing.
    pub fn get<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        user: Gen9DcUser,
    ) -> Result<bool, DcError> {
        if !self.needs_dc_off(user) {
            return Ok(false);
        }
        // DC9 (or its entry) fences the display: nothing is granted until
        // the resume exits it.
        if self.fenced {
            return Err(DcError::Unavailable);
        }
        let next = self.refs[user as usize]
            .checked_add(1)
            .ok_or(DcError::Overflow)?;
        if user == Gen9DcUser::GtIrq {
            // A new GT_IRQ reference takes over the pending async put.
            self.gt_irq_until = None;
        }
        if self.total() == 0 {
            self.arm_at = None;
            let value = regs.read32(DC_STATE_EN);
            if value == u32::MAX {
                return Err(DcError::Unavailable);
            }
            if value & self.dc.mask() != 0 || self.dc.tracked() != 0 {
                self.dc.disable(regs)?;
            }
        }
        self.refs[user as usize] = next;
        Ok(true)
    }

    /// Release a reference. The last release schedules re-entry at
    /// `now + 17 ms`, or later while a GT_IRQ async put is pending (100 ms
    /// after the GT parked), and returns that deadline; nothing is written
    /// here. An unbalanced release is ignored.
    pub fn put(&mut self, user: Gen9DcUser, now: u64) -> Option<u64> {
        let slot = &mut self.refs[user as usize];
        if *slot == 0 {
            return None;
        }
        *slot -= 1;
        if user == Gen9DcUser::GtIrq && *slot == 0 {
            self.gt_irq_until = Some(now.saturating_add(GT_IRQ_PUT_DELAY_NS));
        }
        if self.total() == 0 {
            let at = now
                .saturating_add(DC_REENABLE_DELAY_NS)
                .max(self.gt_irq_until.unwrap_or(0));
            self.arm_at = Some(at);
            Some(at)
        } else {
            None
        }
    }

    /// Hand the service the probe-time DMC container (verified by the
    /// Gen9 load) and its per-program payload ceiling.
    pub fn provide_program(&mut self, blob: &'static [u8], max: usize) {
        self.program = Some(Resident { blob, max });
        self.lost = false;
    }

    /// End of probe: release the Init reference, but only after a
    /// successful [`Self::boot`], with a program and no latched fault
    /// (Linux keeps `POWER_DOMAIN_INIT` without a DMC: "runtime suspend
    /// *requires* a working DMC"). Returns the re-entry deadline.
    pub fn release_init(&mut self, now: u64) -> Option<u64> {
        if !self.booted || self.program.is_none() || self.lost || self.dc.fault().is_some() {
            return None;
        }
        let mut deadline = None;
        while self.refs(Gen9DcUser::Init) > 0 {
            if let Some(at) = self.put(Gen9DcUser::Init, now) {
                deadline = Some(at);
            }
        }
        deadline
    }

    /// `assert_main_dmc_loaded`, as a check: the resident container
    /// parses and its main program's RAM start dword and MMIO table read
    /// back.
    fn program_verifies<M: MmioWindow + ?Sized>(&self, regs: &M) -> bool {
        let Some(Resident { blob, max }) = self.program else {
            return false;
        };
        let Ok(firmware) = parse_dmc_firmware_gen9_max(blob, b'*', b'*', max) else {
            return false;
        };
        firmware.has_main() && verify_program(regs, &firmware, DmcId::Main).is_ok()
    }

    /// Re-enter the target if the pending release is due and every gate
    /// passes: the disable half of the `DC_off` well
    /// (`gen9_dc_off_power_well_disable`).
    pub fn arm_if_due<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        now: u64,
        gates: Gen9ArmGates,
    ) -> Result<u32, Gen9ArmBlock> {
        let result = self.arm_inner(regs, now, gates);
        self.last_block = result.err();
        result
    }

    fn arm_inner<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        now: u64,
        gates: Gen9ArmGates,
    ) -> Result<u32, Gen9ArmBlock> {
        if self.total() != 0 {
            return Err(Gen9ArmBlock::Busy);
        }
        let at = self.arm_at.ok_or(Gen9ArmBlock::NotScheduled)?;
        if now < at {
            return Err(Gen9ArmBlock::NotDue(at));
        }
        // The release is consumed from here on.
        self.arm_at = None;
        if self.dc.fault().is_some() {
            return Err(Gen9ArmBlock::Faulted);
        }
        if self.program.is_none() {
            return Err(Gen9ArmBlock::NoProgram);
        }
        if self.lost {
            return Err(Gen9ArmBlock::ProgramLost);
        }
        let target = self.dc.target();
        if target == DC_STATE_DISABLE {
            return Err(Gen9ArmBlock::NoTarget);
        }
        if gates.external_route_active {
            return Err(Gen9ArmBlock::ExternalRoute);
        }
        // assert_can_enable_dc5: "Power wells at this level and above must
        // be disabled for DC5 entry" (high_pg = SKL_DISP_PW_2). Every
        // requester (BIOS, driver, KVMR, debug) and the state bit refuse.
        for reg in [
            HSW_PWR_WELL_CTL1,
            HSW_PWR_WELL_CTL2,
            HSW_PWR_WELL_CTL3,
            HSW_PWR_WELL_CTL4,
        ] {
            let value = regs.read32(reg);
            if value == u32::MAX {
                return Err(Gen9ArmBlock::Unavailable);
            }
            if value & PW_2_REQ_STATE != 0 {
                return Err(Gen9ArmBlock::PowerWell2 { reg, value });
            }
        }
        // assert_can_enable_dc6: the utility pin must not drive PWM.
        if target & DC_STATE_EN_UPTO_DC6 != 0 {
            let util = regs.read32(UTIL_PIN_CTL);
            if util == u32::MAX {
                return Err(Gen9ArmBlock::Unavailable);
            }
            if util & (UTIL_PIN_ENABLE | UTIL_PIN_MODE_MASK) == UTIL_PIN_ENABLE | UTIL_PIN_MODE_PWM
            {
                return Err(Gen9ArmBlock::UtilPinPwm);
            }
        }
        // assert_main_dmc_loaded, as a refusal.
        if !self.program_verifies(regs) {
            self.lost = true;
            return Err(Gen9ArmBlock::ProgramLost);
        }
        // Wa Display #1183: skl,kbl,cfl (DISPLAY_VER == 9 && !broxton;
        // Gemini Lake is display 10): intel_de_rmw(GEN8_CHICKEN_DCPR_1, 0,
        // SKL_SELECT_ALTERNATE_DC_EXIT), an unconditional write.
        if !self.lp {
            let chicken = regs.read32(GEN8_CHICKEN_DCPR_1);
            if chicken == u32::MAX {
                return Err(Gen9ArmBlock::Unavailable);
            }
            regs.write32(GEN8_CHICKEN_DCPR_1, chicken | SKL_SELECT_ALTERNATE_DC_EXIT);
        }
        self.dc.set_target(regs).map_err(Gen9ArmBlock::Write)?;
        self.arms = self.arms.saturating_add(1);
        Ok(target)
    }

    /// System suspend preparation (`skl_display_core_uninit` /
    /// `bxt_display_core_uninit` → `gen9_disable_dc_states`): exit DC
    /// states and hold them off through the resume. Idempotent. On display
    /// 9 proper it also records DPLL0's running VCO, the resume CDCLK
    /// init's preferred VCO (`skl_preferred_vco_freq`).
    pub fn suspend_begin<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), DcError> {
        if self.refs(Gen9DcUser::Suspend) != 0 {
            return Ok(());
        }
        self.get(regs, Gen9DcUser::Suspend)?;
        if !self.lp {
            if let Ok(hw) = crate::intel_gpu_gen9_cdclk::Current::read(regs) {
                if hw.vco != 0 {
                    self.vco = hw.vco;
                }
            }
        }
        Ok(())
    }

    /// Gen9 LP system suspend, after [`Self::suspend_begin`]: whether DC9
    /// may be entered (`assert_can_enable_dc9`, as refusals), read-only.
    /// Admission also needs the display dark, every transcoder off (the
    /// mode-set disable sequence Linux's assert leaves as a TODO), and no
    /// holder but Init and Suspend. On `Ok` the core is fenced: no new
    /// reference is granted until the resume, so the display-core uninit
    /// and the DC9 write run alone. [`Self::dc9_abort`] lifts the fence.
    pub fn dc9_admit<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Dc9Block> {
        if !self.lp {
            return Err(Dc9Block::NotLp);
        }
        if self.refs(Gen9DcUser::Suspend) == 0 {
            return Err(Dc9Block::NotSuspending);
        }
        if self.total() != self.refs(Gen9DcUser::Suspend) + self.refs(Gen9DcUser::Init) {
            return Err(Dc9Block::Busy);
        }
        if self.dc.fault().is_some() {
            return Err(Dc9Block::Faulted);
        }
        self.dc9_gates(regs)?;
        for reg in TRANSCONF_REGS {
            let value = regs.read32(reg);
            if value == u32::MAX {
                return Err(Dc9Block::Unavailable);
            }
            if value & TRANSCONF_ENABLE != 0 {
                return Err(Dc9Block::DisplayActive { reg, value });
            }
        }
        self.fenced = true;
        Ok(())
    }

    /// `assert_can_enable_dc9`'s register checks.
    fn dc9_gates<M: MmioWindow + ?Sized>(&self, regs: &M) -> Result<(), Dc9Block> {
        let state = regs.read32(DC_STATE_EN);
        let wells = regs.read32(HSW_PWR_WELL_CTL2);
        if state == u32::MAX || wells == u32::MAX {
            return Err(Dc9Block::Unavailable);
        }
        if state & crate::intel_gpu_dc_states::DC_STATE_EN_DC9 != 0 {
            return Err(Dc9Block::AlreadyProgrammed);
        }
        if state & DC_STATE_EN_UPTO_DC5 != 0 {
            return Err(Dc9Block::Dc5Programmed);
        }
        if wells & pw_req(SKL_PW_CTL_IDX_PW_2) != 0 {
            return Err(Dc9Block::PowerWell2(wells));
        }
        Ok(())
    }

    /// `bxt_enable_dc9`, after [`Self::dc9_admit`] and the display-core
    /// uninit ([`display_core_uninit_lp`]): the gates again, then
    /// `bxt_pps_reset_all` (the eDP sequencer is reprogrammed at its next
    /// use) and `gen9_set_dc_state(DC_STATE_EN_DC9)`. The fence stays up.
    pub fn enter_dc9<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), Dc9Block> {
        if !self.fenced {
            return Err(Dc9Block::NotSuspending);
        }
        self.dc9_gates(regs)?;
        self.pps_reset = true;
        self.dc
            .set_dc_state(regs, crate::intel_gpu_dc_states::DC_STATE_EN_DC9)
            .map_err(Dc9Block::Write)?;
        self.dc9 = true;
        Ok(())
    }

    /// A DC9 attempt that stopped before the DC9 write: lift the fence.
    /// Every reference stays as it was (Suspend held, DC0).
    pub fn dc9_abort(&mut self) {
        if !self.dc9 {
            self.fenced = false;
        }
    }

    /// First half of the resume (`intel_display_power_resume_early`):
    /// `gen9_sanitize_dc_state`, then `bxt_disable_dc9` or the display-core
    /// init's `DC_STATE_DISABLE` whenever a DC state reads enabled, and the
    /// fence lifted. `Ok(true)` when a Suspend reference waits for the
    /// display-core init and program reload ([`Self::resume_finish`]). A
    /// failed exit keeps the fence and the Suspend reference.
    pub fn resume_begin<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<bool, DcError> {
        if self.refs(Gen9DcUser::Suspend) == 0 {
            return Ok(false);
        }
        self.dc.sanitize(regs)?;
        if self.dc9 || self.dc.tracked() != 0 {
            self.dc.disable(regs)?;
        }
        self.dc9 = false;
        self.fenced = false;
        Ok(true)
    }

    /// Last half of the resume: with the program reloaded and verified
    /// (`loaded`, `intel_dmc_load_program` from the display-core init),
    /// release the Suspend reference and return the re-entry deadline;
    /// otherwise the program is lost and DC states stay disabled.
    pub fn resume_finish(&mut self, loaded: bool, now: u64) -> Option<u64> {
        if self.refs(Gen9DcUser::Suspend) == 0 {
            return None;
        }
        if !loaded {
            self.lost = true;
            return None;
        }
        self.lost = false;
        self.put(Gen9DcUser::Suspend, now)
    }

    /// The whole resume on one window: [`Self::resume_begin`], the
    /// display-core init ([`display_core_init`]), the program reload
    /// ([`reload_program`]) and [`Self::resume_finish`]. Production runs the
    /// middle two outside the service lock.
    pub fn resume<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        now: u64,
    ) -> Result<Option<u64>, DcError> {
        if !self.resume_begin(regs)? {
            return Ok(None);
        }
        let loaded = display_core_init(regs, self.platform, self.vco).is_ok()
            && self
                .resident()
                .is_some_and(|(blob, max)| reload_program(regs, blob, max));
        Ok(self.resume_finish(loaded, now))
    }
}

/// Why the display-core init or uninit around a system suspend stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreInitError {
    /// A register read all-ones.
    Unavailable,
    /// A power well's state did not follow its request: its index.
    Well(u32),
    /// A fuse distribution status did not set: its power gate.
    Fuse(u32),
    /// The DBUF slice did not follow its request.
    Dbuf,
    /// CDCLK could not be moved to the bypass (uninit) or initialized
    /// (`intel_cdclk_init_hw` on resume).
    Cdclk,
}

fn wait_bits<M: MmioWindow + ?Sized>(regs: &M, reg: u64, mask: u32, want: u32, us: u64) -> bool {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let value = regs.read32(reg);
            lost = value == u32::MAX;
            lost || value & mask == want
        },
        narf_time::Deadline::after_us(us),
    );
    done && !lost
}

/// `gen9_dbuf_slice_set`: request (or drop) slice S1, post, wait 10 us and
/// check the state.
fn dbuf_set<M: MmioWindow + ?Sized>(regs: &M, enable: bool) -> Result<(), CoreInitError> {
    let value = regs.read32(DBUF_CTL_S1);
    if value == u32::MAX {
        return Err(CoreInitError::Unavailable);
    }
    let request = if enable { DBUF_POWER_REQUEST } else { 0 };
    regs.write32(DBUF_CTL_S1, (value & !DBUF_POWER_REQUEST) | request);
    let _ = regs.read32(DBUF_CTL_S1);
    let want = if enable { DBUF_POWER_STATE } else { 0 };
    if wait_bits(regs, DBUF_CTL_S1, DBUF_POWER_STATE, want, 10) {
        Ok(())
    } else {
        Err(CoreInitError::Dbuf)
    }
}

/// `hsw_power_well_enable` for PW_1 (with its fuses: PG0 before, PG1 after)
/// or MISC IO (no fuses): request, then 1 ms for the state.
fn well_enable<M: MmioWindow + ?Sized>(regs: &M, idx: u32) -> Result<(), CoreInitError> {
    let fuses = idx == SKL_PW_CTL_IDX_PW_1;
    if fuses
        && !wait_bits(
            regs,
            SKL_FUSE_STATUS,
            fuse_pg_dist_status(0),
            fuse_pg_dist_status(0),
            1_000,
        )
    {
        return Err(CoreInitError::Fuse(0));
    }
    let value = regs.read32(HSW_PWR_WELL_CTL2);
    if value == u32::MAX {
        return Err(CoreInitError::Unavailable);
    }
    regs.write32(HSW_PWR_WELL_CTL2, value | pw_req(idx));
    if !wait_bits(regs, HSW_PWR_WELL_CTL2, pw_state(idx), pw_state(idx), 1_000) {
        return Err(CoreInitError::Well(idx));
    }
    if fuses
        && !wait_bits(
            regs,
            SKL_FUSE_STATUS,
            fuse_pg_dist_status(1),
            fuse_pg_dist_status(1),
            1_000,
        )
    {
        return Err(CoreInitError::Fuse(1));
    }
    Ok(())
}

/// The rest of `bxt_display_core_uninit` before `bxt_enable_dc9`, with DC
/// states already disabled and the display dark ([`Gen9DcCore::dc9_admit`]):
/// `gen9_dbuf_disable`, `intel_cdclk_uninit_hw` (CDCLK to the 19.2 MHz
/// bypass with the DE PLL off, `bxt_set_cdclk` with `INVALID_PIPE`) and the
/// driver's PW_1 request dropped (`hsw_power_well_disable`: the state is
/// waited for only when no other requester holds the well; the DMC may keep
/// it), then the 10 us BSpec delay.
pub fn display_core_uninit_lp<M: MmioWindow + ?Sized>(
    regs: &M,
    glk: bool,
) -> Result<(), CoreInitError> {
    dbuf_set(regs, false)?;
    let current =
        crate::intel_gpu_bxt_cdclk::Current::read(regs).map_err(|_| CoreInitError::Cdclk)?;
    crate::intel_gpu_bxt_cdclk::program(regs, glk, current, crate::intel_gpu_bxt_cdclk::REF_KHZ)
        .map_err(|_| CoreInitError::Cdclk)?;
    pw1_release(regs)
}

/// The driver's PW_1 request dropped (`hsw_power_well_disable`: the state
/// is waited for only when no other requester holds the well; the DMC may
/// keep it), then the 10 us BSpec delay. MISC IO is left requested ("BSpec
/// says to keep the MISC IO power well enabled here").
fn pw1_release<M: MmioWindow + ?Sized>(regs: &M) -> Result<(), CoreInitError> {
    let value = regs.read32(HSW_PWR_WELL_CTL2);
    if value == u32::MAX {
        return Err(CoreInitError::Unavailable);
    }
    regs.write32(HSW_PWR_WELL_CTL2, value & !pw_req(SKL_PW_CTL_IDX_PW_1));
    let mut others = 0;
    for reg in [HSW_PWR_WELL_CTL1, HSW_PWR_WELL_CTL3, HSW_PWR_WELL_CTL4] {
        others |= regs.read32(reg) & pw_req(SKL_PW_CTL_IDX_PW_1);
    }
    if others == 0 {
        // Bspec does not require the wait; Linux waits 1 ms and only logs.
        let _ = wait_bits(
            regs,
            HSW_PWR_WELL_CTL2,
            pw_state(SKL_PW_CTL_IDX_PW_1),
            0,
            1_000,
        );
    }
    let _ = narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(10));
    Ok(())
}

/// `skl_display_core_uninit` after `gen9_disable_dc_states` (DC states
/// already off) with the display dark: `gen9_dbuf_disable`,
/// `intel_cdclk_uninit_hw` (`skl_cdclk_uninit_hw`: CDCLK to the 24 MHz
/// bypass with DPLL0 off) and the driver's PW_1 request dropped, MISC IO
/// kept. Returns the VCO DPLL0 ran at, the resume CDCLK init's preferred
/// VCO.
pub fn display_core_uninit_skl<M: MmioWindow + ?Sized>(
    regs: &M,
    platform: Gen9Platform,
) -> Result<u32, CoreInitError> {
    dbuf_set(regs, false)?;
    let vco = crate::intel_gpu_gen9_cdclk::uninit_hw(regs, platform)
        .map_err(|_| CoreInitError::Cdclk)?;
    pw1_release(regs)?;
    Ok(vco)
}

/// `intel_pch_reset_handshake`: `RESET_PCH_HANDSHAKE_ENABLE` in
/// `HSW_NDE_RSTWRN_OPT` set or cleared by read-modify-write, written only
/// when it changes (`intel_de_rmw`). Display 9 proper enables it (it has a
/// south display: `!HAS_PCH_NOP` holds whenever the display is present);
/// Broxton and Gemini Lake clear it ("must always be 0b on BXT or else the
/// reset will hang because there is no PCH to respond").
pub fn pch_reset_handshake<M: MmioWindow + ?Sized>(
    regs: &M,
    enable: bool,
) -> Result<(), CoreInitError> {
    let old = regs.read32(HSW_NDE_RSTWRN_OPT);
    if old == u32::MAX {
        return Err(CoreInitError::Unavailable);
    }
    let new = if enable {
        old | RESET_PCH_HANDSHAKE_ENABLE
    } else {
        old & !RESET_PCH_HANDSHAKE_ENABLE
    };
    if new != old {
        regs.write32(HSW_NDE_RSTWRN_OPT, new);
    }
    Ok(())
}

/// The rest of `skl_display_core_init` / `bxt_display_core_init` for a
/// resume, after the DC exit (`gen9_set_dc_state(DC_STATE_DISABLE)` or
/// `bxt_disable_dc9`) and before the program reload, in Linux's order: the
/// PCH reset handshake (`intel_pch_reset_handshake`: enabled on display 9
/// proper, cleared on Gen9 LP), PW_1 with its fuses (and MISC IO on display
/// 9 proper), `intel_cdclk_init_hw` (`skl_cdclk_init_hw` at
/// `preferred_vco`, or `bxt_cdclk_init_hw`), then the DBUF slice
/// (`gen9_dbuf_enable`).
pub fn display_core_init<M: MmioWindow + ?Sized>(
    regs: &M,
    platform: Gen9Platform,
    preferred_vco: u32,
) -> Result<(), CoreInitError> {
    let lp = platform.is_lp();
    pch_reset_handshake(regs, !lp)?;
    well_enable(regs, SKL_PW_CTL_IDX_PW_1)?;
    if !lp {
        well_enable(regs, SKL_PW_CTL_IDX_MISC_IO)?;
    }
    if lp {
        crate::intel_gpu_bxt_cdclk::init_hw(regs, platform == Gen9Platform::GeminiLake)
            .map_err(|_| CoreInitError::Cdclk)?;
    } else {
        crate::intel_gpu_gen9_cdclk::init_hw(regs, platform, preferred_vco)
            .map_err(|_| CoreInitError::Cdclk)?;
    }
    dbuf_set(regs, true)
}

/// `intel_dmc_load_program` from the display-core init on resume: stream
/// the resident container's programs and verify them (`assert_dmc_loaded`,
/// as a refusal). `false` when the container no longer parses or the
/// program does not read back.
pub fn reload_program<M: MmioWindow + ?Sized>(regs: &M, blob: &[u8], max: usize) -> bool {
    let Ok(firmware) = parse_dmc_firmware_gen9_max(blob, b'*', b'*', max) else {
        return false;
    };
    if !firmware.has_main() {
        return false;
    }
    crate::intel_gpu_dmc::load_program(regs, &firmware);
    crate::intel_gpu_dmc::verify_loaded(regs, &firmware).is_ok()
}

/// A `DC_off` holder's view of the Gen9 service: the production service
/// (`ServiceDcOff`, inert where none is installed) or a fixture's own
/// core. `regs` is the caller's register window; the production service
/// uses its own authorized window instead.
pub trait Gen9DcOff: Sync {
    /// Take a reference (see [`Gen9DcCore::get`]). `Ok(true)` when one
    /// was counted and must be released.
    fn get(&self, regs: &dyn MmioWindow, user: Gen9DcUser) -> Result<bool, DcError>;
    /// Release a reference `get` counted.
    fn put(&self, user: Gen9DcUser);
}

/// The caller's window as a `dyn MmioWindow` (register access only).
struct RegsRef<'b, M: ?Sized>(&'b M);

impl<M: MmioWindow + ?Sized> MmioWindow for RegsRef<'_, M> {
    fn read32(&self, off: u64) -> u32 {
        self.0.read32(off)
    }
    fn write32(&self, off: u64, val: u32) {
        self.0.write32(off, val)
    }
    fn display_access_ok(&self) -> bool {
        self.0.display_access_ok()
    }
}

/// A held reference on a [`Gen9DcOff`]; dropping it releases it.
#[must_use = "dropping the guard releases DC_off immediately"]
pub struct Gen9DcGuard<'a> {
    hook: &'a dyn Gen9DcOff,
    user: Gen9DcUser,
    held: bool,
}

impl core::fmt::Debug for Gen9DcGuard<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gen9DcGuard")
            .field("user", &self.user)
            .field("held", &self.held)
            .finish()
    }
}

impl Drop for Gen9DcGuard<'_> {
    fn drop(&mut self) {
        if self.held {
            self.hook.put(self.user);
        }
    }
}

/// Take `user`'s reference on `hook` before touching `regs`' display
/// registers. `Err` means DC states could not be exited: the caller runs
/// nothing.
pub fn hold<'a, M: MmioWindow + ?Sized>(
    hook: &'a dyn Gen9DcOff,
    regs: &M,
    user: Gen9DcUser,
) -> Result<Gen9DcGuard<'a>, DcError> {
    let held = hook.get(&RegsRef(regs), user)?;
    Ok(Gen9DcGuard { hook, user, held })
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the display-9 DC mask and target. The
    //! fake is a plain register file (plus a deaf variant
    //! whose writes never stick). Expected values are
    //! hand-derived from `gen9_dc_mask` /
    //! `get_allowed_dc_mask` — never recorded from the
    //! implementation under test.

    use super::*;
    use crate::intel_gpu_dc_states::{DC_STATE_EN_DC3CO, DC_STATE_EN_DC9};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A plain register file over `DC_STATE_EN` (and any
    /// other offset); `stick == false` drops writes.
    #[derive(Debug)]
    struct FakeDc {
        regs: RefCell<Vec<(u64, u32)>>,
        stick: bool,
    }

    impl FakeDc {
        fn new() -> Self {
            Self {
                regs: RefCell::new(Vec::new()),
                stick: true,
            }
        }

        fn deaf() -> Self {
            Self {
                regs: RefCell::new(Vec::new()),
                stick: false,
            }
        }

        fn set(&self, off: u64, val: u32) {
            self.regs.borrow_mut().push((off, val));
        }
    }

    impl MmioWindow for FakeDc {
        fn read32(&self, off: u64) -> u32 {
            let mut v = 0;
            for (o, val) in self.regs.borrow().iter() {
                if *o == off {
                    v = *val;
                }
            }
            v
        }

        fn write32(&self, off: u64, val: u32) {
            if self.stick {
                self.regs.borrow_mut().push((off, val));
            }
        }
    }

    fn smoke_gen9_dc_mask_derivation() -> TestResult {
        // gen9_dc_mask, display 9: the base UPTO_DC5 plus
        // the `else` arm's UPTO_DC6 — and NOT DC9 (that bit
        // joins only for GLK/BXT or DISPLAY_VER >= 11) and
        // NOT DC3CO (DISPLAY_VER >= 12 only). The
        // grounding's "UPTO_DC5 alone" is wrong: it missed
        // the `else` arm.
        if GEN9_DC_MASK != DC_STATE_EN_UPTO_DC5 | DC_STATE_EN_UPTO_DC6 {
            return TestResult::Fail("Gen9 DC mask must be UPTO_DC5 | UPTO_DC6");
        }
        if GEN9_DC_MASK != 0x3 {
            return TestResult::Fail("Gen9 DC mask must be 0x3");
        }
        if GEN9_DC_MASK & (DC_STATE_EN_DC9 | DC_STATE_EN_DC3CO) != 0 {
            return TestResult::Fail("DC9 and DC3CO must not be in the display-9 mask");
        }
        // get_allowed_dc_mask, display 9 (max_dc 2): UPTO_DC6
        // only. DC9 is not allowed on display 9 — the
        // display-11 allowed mask (DC9 | UPTO_DC6 = 0xA) does
        // not carry over.
        if GEN9_ALLOWED_DC_MASK != DC_STATE_EN_UPTO_DC6 {
            return TestResult::Fail("Gen9 allowed mask must be UPTO_DC6");
        }
        if GEN9_ALLOWED_DC_MASK != 0x2 {
            return TestResult::Fail("Gen9 allowed mask must be 0x2");
        }
        // The sanitized target is DC6.
        if GEN9_DC_TARGET != DC_STATE_EN_UPTO_DC6 || Gen9Dc::new().target() != 0x2 {
            return TestResult::Fail("Gen9 DC target must be UPTO_DC6");
        }
        // The display-9 mask differs from the display-11
        // mask (0xB) exactly by the DC9 bit.
        if crate::intel_gpu_gen11_dc_states::GEN11_DC_MASK != 0xB
            || GEN9_DC_MASK | DC_STATE_EN_DC9 != crate::intel_gpu_gen11_dc_states::GEN11_DC_MASK
        {
            return TestResult::Fail("display-11 mask pin moved");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dc_states",
        smoke_gen9_dc_mask_derivation
    );

    fn smoke_sanitize_adopts_masked_field() -> TestResult {
        let fake = FakeDc::new();
        let mut dc = Gen9Dc::new();
        // All-ones: the function is not in D0.
        fake.set(DC_STATE_EN, u32::MAX);
        if dc.sanitize(&fake) != Err(DcError::Unavailable) {
            return TestResult::Fail("sanitize must refuse an all-ones DC_STATE_EN");
        }
        // A DC9 bit in the hardware field is outside the
        // display-9 mask and must not enter tracking.
        fake.set(DC_STATE_EN, DC_STATE_EN_DC9 | DC_STATE_EN_UPTO_DC6);
        if dc.sanitize(&fake).is_err() || dc.tracked() != DC_STATE_EN_UPTO_DC6 {
            return TestResult::Fail("sanitize must adopt the field masked by GEN9_DC_MASK");
        }
        // A DC3CO bit is outside the mask too.
        fake.set(DC_STATE_EN, DC_STATE_EN_DC3CO | DC_STATE_EN_UPTO_DC5);
        if dc.sanitize(&fake).is_err() || dc.tracked() != DC_STATE_EN_UPTO_DC5 {
            return TestResult::Fail("sanitize must drop DC3CO from tracking");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dc_states",
        smoke_sanitize_adopts_masked_field
    );

    fn smoke_set_target_and_disable() -> TestResult {
        let fake = FakeDc::new();
        let mut dc = Gen9Dc::new();
        if dc.set_target(&fake).is_err() {
            return TestResult::Fail("set_target failed against the fake");
        }
        if fake.read32(DC_STATE_EN) != DC_STATE_EN_UPTO_DC6 {
            return TestResult::Fail("set_target must program DC_STATE_EN = UPTO_DC6");
        }
        if !dc.armed() || dc.tracked() != DC_STATE_EN_UPTO_DC6 {
            return TestResult::Fail("set_target must leave DC6 tracked and armed");
        }
        if dc.disable(&fake).is_err() {
            return TestResult::Fail("disable failed against the fake");
        }
        if fake.read32(DC_STATE_EN) != 0 || dc.armed() {
            return TestResult::Fail("disable must program DC_STATE_EN = 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dc_states",
        smoke_set_target_and_disable
    );

    fn smoke_set_dc_state_masks_by_allowed() -> TestResult {
        let fake = FakeDc::new();
        let mut dc = Gen9Dc::new();
        // DC5 is in the mask but NOT in the allowed mask:
        // Linux targets it only via the sanitize fallback,
        // and a direct request is stripped to disabled.
        if dc.set_dc_state(&fake, DC_STATE_EN_UPTO_DC5).is_err() || fake.read32(DC_STATE_EN) != 0 {
            return TestResult::Fail("DC5 must be stripped by the allowed mask");
        }
        // DC9 is outside the allowed mask on display 9: the
        // write is stripped to disabled, not programmed.
        // (On display 11 the same request programs — the
        // masking-defeating case for a copied Gen11 mask.)
        if dc.set_dc_state(&fake, DC_STATE_EN_DC9).is_err() || fake.read32(DC_STATE_EN) != 0 {
            return TestResult::Fail("DC9 must be stripped by the allowed mask on display 9");
        }
        // DC6 programs.
        if dc.set_dc_state(&fake, DC_STATE_EN_UPTO_DC6).is_err()
            || fake.read32(DC_STATE_EN) != DC_STATE_EN_UPTO_DC6
        {
            return TestResult::Fail("DC6 is allowed and must program");
        }
        // A stale tracked value is counted, not trusted.
        fake.set(DC_STATE_EN, DC_STATE_EN_UPTO_DC5);
        if dc.set_dc_state(&fake, DC_STATE_EN_UPTO_DC6).is_err() || dc.mismatches() != 1 {
            return TestResult::Fail("a hardware/tracked disagreement must be counted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dc_states",
        smoke_set_dc_state_masks_by_allowed
    );

    fn smoke_write_failure_latches_fault() -> TestResult {
        let fake = FakeDc::deaf();
        let mut dc = Gen9Dc::new();
        match dc.set_target(&fake) {
            Err(DcError::DidNotStick { wanted, found }) => {
                if wanted != DC_STATE_EN_UPTO_DC6 || found != 0 {
                    return TestResult::Fail("DidNotStick must carry the wanted/found values");
                }
            }
            _ => return TestResult::Fail("a write that never sticks must fail"),
        }
        if dc.fault().is_none() || dc.tracked() != 0 {
            return TestResult::Fail("a failed write must latch the fault");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dc_states",
        smoke_write_failure_latches_fault
    );

    /// Gemini Lake / Broxton: `gen9_dc_mask` UPTO_DC5 | DC9, allowed
    /// DC9 | UPTO_DC5, target DC5. DC6 is stripped, DC5 and DC9 program,
    /// and sanitize keeps DC9 (in this mask) but drops DC6.
    fn smoke_gen9_lp_dc_mask_and_target() -> TestResult {
        if GEN9_LP_DC_MASK != 0x9 || GEN9_LP_ALLOWED_DC_MASK != 0x9 {
            return TestResult::Fail("GLK/BXT masks are UPTO_DC5 | DC9");
        }
        let fake = FakeDc::new();
        let mut dc = Gen9Dc::new_lp();
        if dc.target() != DC_STATE_EN_UPTO_DC5 || dc.allowed_mask() != 0x9 {
            return TestResult::Fail("the LP target sanitizes DC6 down to DC5");
        }
        if dc.set_dc_state(&fake, DC_STATE_EN_UPTO_DC6).is_err() || fake.read32(DC_STATE_EN) != 0 {
            return TestResult::Fail("DC6 is not allowed on Gen9 LP");
        }
        if dc.set_target(&fake).is_err() || fake.read32(DC_STATE_EN) != DC_STATE_EN_UPTO_DC5 {
            return TestResult::Fail("the LP target programs DC5");
        }
        if dc.set_dc_state(&fake, DC_STATE_EN_DC9).is_err()
            || fake.read32(DC_STATE_EN) != DC_STATE_EN_DC9
        {
            return TestResult::Fail("DC9 is allowed on Gen9 LP");
        }
        fake.set(
            DC_STATE_EN,
            DC_STATE_EN_DC9 | DC_STATE_EN_UPTO_DC6 | (1 << 8),
        );
        if dc.sanitize(&fake).is_err() || dc.tracked() != DC_STATE_EN_DC9 {
            return TestResult::Fail("sanitize adopts the field under the LP mask");
        }
        if dc.disable(&fake).is_err() || fake.read32(DC_STATE_EN) != DC_STATE_EN_UPTO_DC6 | (1 << 8)
        {
            return TestResult::Fail("disable clears only the LP mask's bits");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_dc_states",
        smoke_gen9_lp_dc_mask_and_target
    );
}

// ── Production service ──────────────────────────────────────────

/// The boot option opting the Gen9 display into DC states.
pub const OPT_IN: &str = "narf.intel.gen9_dc";

/// `narf.intel.gen9_dc=1`, with the strict grammar every Intel opt-in uses
/// ([`crate::intel_gpu_gt::boot_opt_in`]): exactly one `=1` before `--`.
pub fn requested(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    crate::intel_gpu_gt::boot_opt_in(args, OPT_IN)
}

/// Install-time core: `None` (and nothing written) without the option;
/// otherwise a core for `platform`, booted on `regs` (`DC_STATE_DISABLE`,
/// the Init reference held).
pub fn boot_if_requested<M: MmioWindow + ?Sized>(
    opted_in: bool,
    platform: Gen9Platform,
    regs: &M,
) -> Option<Gen9DcCore> {
    if !opted_in {
        return None;
    }
    let mut core = Gen9DcCore::new(platform);
    // A failed write is latched inside the core: Init stays held and DC
    // states are never re-entered.
    let _ = core.boot(regs);
    Some(core)
}

/// The per-function service: one integrated Gen9 display exists, so one
/// service does too.
#[derive(Debug)]
struct Gen9Service {
    window: crate::intel_gpu_gt_hw::AuthorizedWindow,
    bar: narf_bus::MmioRegion,
    core: IrqSafeSpinLock<Gen9DcCore>,
    arming: AtomicBool,
}

static SERVICE: IrqSafeSpinLock<Option<Arc<Gen9Service>>> = IrqSafeSpinLock::new(None);

fn service() -> Option<Arc<Gen9Service>> {
    SERVICE.lock().clone()
}

fn service_for(bar: &narf_bus::MmioRegion) -> Option<Arc<Gen9Service>> {
    service().filter(|service| service.bar.phys == bar.phys)
}

fn log(text: &str) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "intel-gpu: {text}");
}

/// A held production reference. Dropping it releases the reference and,
/// for the last one, schedules deferred re-entry; nothing is written to
/// hardware on drop. Inert where no Gen9 service exists (the option is
/// clear, or this is not a Gen9 display).
#[must_use = "dropping the reference releases DC_off immediately"]
pub(crate) struct Gen9DcRef {
    service: Option<Arc<Gen9Service>>,
    user: Gen9DcUser,
}

impl core::fmt::Debug for Gen9DcRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gen9DcRef")
            .field("user", &self.user)
            .field("held", &self.service.is_some())
            .finish()
    }
}

impl Drop for Gen9DcRef {
    fn drop(&mut self) {
        if let Some(service) = self.service.take() {
            release(&service, self.user);
        }
    }
}

fn release(service: &Arc<Gen9Service>, user: Gen9DcUser) {
    let due = service.core.lock().put(user, narf_time::monotonic_ns());
    if due.is_some() {
        schedule_arm(service);
    }
}

fn take(service: Option<Arc<Gen9Service>>, user: Gen9DcUser) -> Result<Gen9DcRef, DcError> {
    let Some(service) = service else {
        return Ok(Gen9DcRef {
            service: None,
            user,
        });
    };
    let held = service.core.lock().get(&service.window, user)?;
    Ok(Gen9DcRef {
        service: held.then_some(service),
        user,
    })
}

/// Take `user`'s reference on the Gen9 service, if one is installed. On
/// `Ok` DC states are off until the reference drops; `Err` means they could
/// not be exited, and the caller runs nothing.
pub(crate) fn acquire(user: Gen9DcUser) -> Result<Gen9DcRef, DcError> {
    take(service(), user)
}

/// [`acquire`] for the service of exactly this BAR.
pub(crate) fn acquire_for_bar(
    bar: &narf_bus::MmioRegion,
    user: Gen9DcUser,
) -> Result<Gen9DcRef, DcError> {
    take(service_for(bar), user)
}

/// The production [`Gen9DcOff`]: the installed Gen9 service through its
/// own authorized window (the holder's window addresses the same BAR), and
/// inert without one.
#[derive(Clone, Copy, Debug, Default)]
pub struct ServiceDcOff;

impl Gen9DcOff for ServiceDcOff {
    fn get(&self, _regs: &dyn MmioWindow, user: Gen9DcUser) -> Result<bool, DcError> {
        let Some(service) = service() else {
            return Ok(false);
        };
        let mut core = service.core.lock();
        core.get(&service.window, user)
    }
    fn put(&self, user: Gen9DcUser) {
        if let Some(service) = service() {
            release(&service, user);
        }
    }
}

fn gates(service: &Gen9Service) -> Gen9ArmGates {
    Gen9ArmGates {
        external_route_active: !crate::intel_gpu::external_routes_stopped(&service.bar),
    }
}

fn schedule_arm(service: &Arc<Gen9Service>) {
    if service.arming.swap(true, Ordering::AcqRel) {
        return;
    }
    let service = service.clone();
    let _ = narf_scheduler::spawn(arm_task(service));
}

async fn arm_task(service: Arc<Gen9Service>) {
    loop {
        loop {
            let Some(at) = service.core.lock().arm_deadline() else {
                break;
            };
            let now = narf_time::monotonic_ns();
            if now < at {
                narf_time::SleepUntil::new(narf_time::Deadline::after_ns(at - now).as_instant())
                    .await;
                continue;
            }
            // The gates read other modules' state: evaluate them with no
            // lock of ours held.
            let gates = gates(&service);
            let result =
                service
                    .core
                    .lock()
                    .arm_if_due(&service.window, narf_time::monotonic_ns(), gates);
            match result {
                Err(Gen9ArmBlock::NotDue(_)) => continue,
                _ => break,
            }
        }
        service.arming.store(false, Ordering::Release);
        // A release that raced with this exit saw `arming` set and did not
        // spawn; pick its deadline up here.
        if service.core.lock().arm_deadline().is_none()
            || service.arming.swap(true, Ordering::AcqRel)
        {
            return;
        }
    }
}

/// Probe, before the Gen9 DMC load: with `narf.intel.gen9_dc=1`, create
/// the service for this display, disable DC states and hold the Init
/// reference until [`probe_complete`], and register the system-suspend
/// hook. Without the option nothing is created and nothing is written.
pub(crate) fn install(
    platform: Gen9Platform,
    bar: narf_bus::MmioRegion,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) {
    let opted_in = requested(narf_boot::args());
    if !opted_in {
        return;
    }
    let mut slot = SERVICE.lock();
    if slot.is_some() {
        return;
    }
    let window = crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap);
    let Some(core) = boot_if_requested(opted_in, platform, &window) else {
        return;
    };
    *slot = Some(Arc::new(Gen9Service {
        window,
        bar,
        core: IrqSafeSpinLock::new(core),
        arming: AtomicBool::new(false),
    }));
    drop(slot);
    narf_power::system_pm::register_async_system_pm(PM_NAME, Arc::new(SystemPm));
}

/// End of probe (`intel_display_power_enable` dropping the init
/// wakeref): hand the service the probe-time DMC program and release the
/// Init reference, but only when that program loaded and the internal
/// panel on Pipe A is owned. Otherwise DC states stay disabled.
pub(crate) fn probe_complete(bar: &narf_bus::MmioRegion, panel_owned: bool) {
    let Some(service) = service_for(bar) else {
        return;
    };
    let resident = crate::intel_gpu_gen9_dmc::resident_program()
        .filter(|_| crate::intel_gpu_gen9_dmc::gen9_dmc_loaded());
    let (due, target) = {
        let mut core = service.core.lock();
        if let Some((blob, max)) = resident {
            core.provide_program(blob, max);
        }
        let due = if panel_owned {
            core.release_init(narf_time::monotonic_ns())
        } else {
            None
        };
        (due, core.target())
    };
    log(match (due.is_some(), resident.is_some(), panel_owned) {
        (true, _, _) if target == DC_STATE_EN_UPTO_DC6 => "Gen9 DC states enabled (DC6 when idle)",
        (true, _, _) => "Gen9 DC states enabled (DC5 when idle)",
        (false, false, _) => "Gen9 DC states held off: no verified DMC program",
        (false, true, false) => "Gen9 DC states held off: no owned internal panel",
        (false, true, true) => "Gen9 DC states held off: DC_STATE_EN did not take DC0",
    });
    if due.is_some() {
        schedule_arm(&service);
    }
}

const PM_NAME: &str = "intel-gen9-dc";

/// The system-suspend participant: DC states off before the platform
/// transition, and back only with a program that survived it.
#[derive(Debug)]
struct SystemPm;

impl narf_power::system_pm::AsyncSystemPm for SystemPm {
    fn prepare_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        Box::pin(async {
            suspend_begin().map_err(|_| narf_power::device_pm::DeviceSuspendError::DriverError)
        })
    }
    fn resume_from_suspend(&self) -> narf_power::system_pm::SystemPmFuture<'_> {
        Box::pin(async {
            resume_after_suspend();
            Ok(())
        })
    }
}

fn suspend_begin() -> Result<(), DcError> {
    let Some(service) = service() else {
        return Ok(());
    };
    service.core.lock().suspend_begin(&service.window)?;
    // Gen9 LP: bxt_display_core_uninit, then bxt_enable_dc9
    // (intel_display_power_suspend_late). A refusal leaves DC0 and the
    // suspend proceeds.
    let admitted = {
        let mut core = service.core.lock();
        if !core.lp() {
            return Ok(());
        }
        core.dc9_admit(&service.window).map(|()| core.glk())
    };
    let outcome = match admitted {
        Ok(glk) => match display_core_uninit_lp(&service.window, glk) {
            Ok(()) => service.core.lock().enter_dc9(&service.window),
            Err(_) => Err(Dc9Block::Uninit),
        },
        Err(block) => Err(block),
    };
    if outcome.is_err() {
        service.core.lock().dc9_abort();
    }
    log(match outcome {
        Ok(()) => "Gen9 LP display in DC9 for system suspend",
        Err(Dc9Block::DisplayActive { .. }) => {
            "Gen9 LP DC9 refused: a transcoder is still enabled; DC states held off"
        }
        Err(Dc9Block::Uninit) => {
            "Gen9 LP DC9 refused: display-core uninit did not complete; DC states held off"
        }
        Err(_) => "Gen9 LP DC9 refused; DC states held off",
    });
    Ok(())
}

fn resume_after_suspend() {
    let Some(service) = service() else {
        return;
    };
    // bxt_disable_dc9 / the display-core init's DC_STATE_DISABLE.
    let (pending, platform, vco, resident) = {
        let mut core = service.core.lock();
        let pending = core.resume_begin(&service.window);
        (pending, core.platform(), core.preferred_vco(), core.resident())
    };
    match pending {
        Ok(true) => {}
        Ok(false) => return,
        Err(_) => {
            log("Gen9 DC states held off after resume: DC_STATE_EN unavailable");
            return;
        }
    }
    // The rest of the display-core init (PCH handshake, power wells, CDCLK,
    // DBUF), then intel_dmc_load_program, outside the service lock.
    let core_up = display_core_init(&service.window, platform, vco);
    let loaded = core_up.is_ok()
        && resident.is_some_and(|(blob, max)| reload_program(&service.window, blob, max));
    let due = service
        .core
        .lock()
        .resume_finish(loaded, narf_time::monotonic_ns());
    match (due, core_up) {
        (Some(_), _) => schedule_arm(&service),
        (None, Err(_)) => log("Gen9 DC states held off after resume: display-core init failed"),
        (None, Ok(())) if resident.is_none() => {}
        (None, Ok(())) => {
            log("Gen9 DC states held off after resume: the DMC program did not reload")
        }
    }
}

/// `bxt_power_sequencer_idx`'s reset check for this BAR's display: whether
/// a DC9 excursion lost the eDP sequencer's registers, so its next user
/// reprograms them (`pps_init_registers`) first. Clears the flag; `false`
/// without a Gen9 service.
pub(crate) fn take_pps_reset_for_bar(bar: &narf_bus::MmioRegion) -> bool {
    service_for(bar).is_some_and(|service| service.core.lock().take_pps_reset())
}

/// `__gt_unpark`'s `POWER_DOMAIN_GT_IRQ` for this BAR's display: a
/// [`Gen9DcUser::GtIrq`] reference held while the GT is unparked, released
/// at park (re-entry then waits [`GT_IRQ_PUT_DELAY_NS`]). Best effort: the
/// hold is a latency workaround, so a refused DC exit returns `None` and the
/// GT runs without it. Inert without a Gen9 service.
pub(crate) fn gt_unparked(bar: &narf_bus::MmioRegion) -> Option<Gen9DcRef> {
    acquire_for_bar(bar, Gen9DcUser::GtIrq).ok()
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_gen9_dc_states_tests.rs"]
pub(crate) mod service_tests;
