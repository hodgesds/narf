//! Display power services for display 14 (Meteor Lake / Arrow Lake):
//! the "DC off" power well and its reference counting, DC5/DC6 entry
//! with a lit panel, and ownership of the MTL DMC program those states
//! depend on.
//!
//! ## Model
//!
//! Pinned source: Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad.
//!
//! - `intel_display_power_map.c::xelpdp_power_wells` — PW_1 is
//!   "handled by the DMC firmware" (always-on to the driver); PW_A
//!   carries pipe A; the `DC_off` well (`xelpd_pwdoms_dc_off`) is
//!   required by AUX_A, AUX_B, the C/D pipes, the Type-C lanes,
//!   `POWER_DOMAIN_DC_OFF` and `POWER_DOMAIN_INIT`. Pipe A, transcoder
//!   A and DDI A are *not* in it, which is why a lit eDP panel on pipe
//!   A can sit in DC5/DC6 once every DC_off user has gone.
//! - `intel_display_power_well.c` — enabling `DC_off`
//!   (`gen9_dc_off_power_well_enable` → `gen9_disable_dc_states`)
//!   programs `DC_STATE_DISABLE`; disabling it enables the sanitized
//!   target (`skl_enable_dc6`), and only with a DMC payload.
//!   `gen9_set_dc_state` read-modify-writes `DC_STATE_EN` under
//!   `gen9_dc_mask` (display >= 12: DC5 | DC6 | DC9 | DC3CO), counts
//!   DC6-allowed residency on display >= 14
//!   (`intel_dmc_update_dc6_allowed_count`, from
//!   `DG1_DMC_DEBUG_DC5_COUNT` deltas) and writes through
//!   `gen9_write_dc_state`'s re-read/rewrite discipline.
//!   `assert_can_enable_dc6` requires the main DMC loaded and the
//!   utility pin out of PWM mode.
//! - `intel_display_power.c` — display 14 allows DC9 | DC3CO | DC6
//!   (`get_allowed_dc_mask`, max_dc 4) and targets DC6
//!   (`sanitize_target_dc_state`). `intel_dmc_init` holds
//!   `POWER_DOMAIN_INIT` until the program is loaded, and on failure
//!   keeps it ("runtime suspend *requires* a working DMC").
//!   `icl_display_core_uninit` disables DC states and the DMC program
//!   before suspend; resume reloads the program before DC re-entry.
//! - `intel_display.c::intel_atomic_commit_tail` holds
//!   `POWER_DOMAIN_DC_OFF` across every plane update and releases it
//!   17 ms later (`intel_display_power_put_async_delay`);
//!   `intel_cx0_phy.c` holds it across PHY message-bus transactions.
//!
//! ## What this driver does with it
//!
//! [`DcCore`] is the state machine: per-user `DC_off` references
//! ([`DcUser`]), the tracked `DC_STATE_EN` field, the retained DMC
//! container, the deferred re-enable deadline and the arm gates. The
//! first reference exits DC states before its holder touches hardware;
//! the last release only *schedules* re-entry 17 ms later. Re-entry
//! runs from a spawned service task with no caller lock held, after
//! re-checking every gate and re-verifying the loaded main program.
//!
//! Production wiring (all Meteor Lake / Arrow Lake only; Gen12 has no
//! service and every hook is inert there):
//!
//! - KMS install creates the service and takes the Init reference:
//!   DC states are exited and stay off.
//! - After each GT publication the card worker runs
//!   [`service_after_publication`]: acquire `i915/mtl_dmc.bin` from the
//!   firmware registry (bounded, parse-validated copy), load and verify
//!   the program under a Load reference, then drop the Init and any
//!   suspend reference. A firmware, parse or verification failure is
//!   latched and the Init reference is kept: DC0, wells up.
//! - KMS sessions (flips, cursor, color, DSB, console restore,
//!   recovery, format refresh), legacy PM guards, the MTL modeset, PSR
//!   scanout notifications and every full-AUX panel-backlight
//!   conversation (AUX transaction, PPS gate, relight step) take a
//!   reference for their whole hardware conversation.
//! - System suspend preparation takes a Suspend reference first, and
//!   after the display has quiesced disables the DMC program; the
//!   first publication after resume reloads it before releasing.
//!
//! Pipe DMC (`intel_dmc_enable_pipe` / `intel_dmc_disable_pipe`): every
//! accepted pipe program is loaded with the main program, events
//! disabled. A pipe owner reports its pipe lit ([`pipe_lit_for_bar`])
//! and dark ([`pipe_dark_for_bar`]) at Linux's crtc call sites through
//! [`PipeDmc`]: lit as the first step of the pipe's enable (before its
//! port PLL), dark as the last step of its disable (after the port PLL);
//! the service enables `PIPEDMC_ENABLE_MTL(pipe)` for every lit pipe
//! whose program is loaded, re-enables them after every (re)load, and
//! clears its enables before the suspend-time program disable. KMS
//! install reports the owned internal Pipe A lit when it adopts it; the
//! MTL modeset reports Pipe A around its own disable/enable and the
//! Pipe B–D owner reports each external pipe.
//!
//! Stricter than the pinned tree, and why: re-entry is refused (not
//! merely warned about) with the utility pin in PWM mode, with a pipe
//! DMC enabled that this driver did not enable, while an external route
//! is live, after any `DC_STATE_EN` write failed to stick, and whenever
//! the main program no longer verifies. A pipe program that does not
//! verify is not enabled. DC3CO and DC9 are never targeted. Program
//! loss found at re-entry is repaired by a reload before the next
//! attempt.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_lib::sync::IrqSafeSpinLock;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_dmc::{
    disable_pipe, disable_program, enable_pipe, load_program, parse_dmc_firmware_xelpdp,
    pipedmc_enable_mtl, verify_loaded, verify_program, DmcError, DmcFirmware, DmcId,
    DmcVerifyError, DC_STATE_EN, DG1_DMC_DEBUG_DC5_COUNT, MTL_DMC_FIRMWARE, MTL_PIPEDMC_CONTROL,
};

// ── Register facts (intel_display_regs.h, intel_backlight_regs.h) ─

/// `DC_STATE_DISABLE`.
pub const DC_STATE_DISABLE: u32 = 0;
/// `DC_STATE_EN_UPTO_DC5`.
pub const DC_STATE_EN_UPTO_DC5: u32 = 1;
/// `DC_STATE_EN_UPTO_DC6`.
pub const DC_STATE_EN_UPTO_DC6: u32 = 2;
/// `DC_STATE_EN_DC9`.
pub const DC_STATE_EN_DC9: u32 = 1 << 3;
/// `DC_STATE_EN_DC3CO`.
pub const DC_STATE_EN_DC3CO: u32 = 1 << 30;
/// `DC_STATE_EN_UPTO_DC5_DC6_MASK`.
pub const DC_STATE_EN_UPTO_DC5_DC6_MASK: u32 = 0x3;
/// `gen9_dc_mask` for display >= 12.
pub const GEN12_DC_MASK: u32 =
    DC_STATE_EN_UPTO_DC5 | DC_STATE_EN_DC3CO | DC_STATE_EN_UPTO_DC6 | DC_STATE_EN_DC9;
/// `UTIL_PIN_CTL`.
pub const UTIL_PIN_CTL: u64 = 0x48400;
/// `UTIL_PIN_ENABLE`.
pub const UTIL_PIN_ENABLE: u32 = 1 << 31;
/// `UTIL_PIN_MODE_MASK`.
pub const UTIL_PIN_MODE_MASK: u32 = 0xf << 24;
/// `UTIL_PIN_MODE_PWM`.
pub const UTIL_PIN_MODE_PWM: u32 = 1 << 24;
/// `gen9_write_dc_state`'s rewrite ceiling.
pub const DC_WRITE_MAX_REWRITES: u32 = 100;
/// The commit path's deferred DC re-enable
/// (`intel_display_power_put_async_delay(.., 17)`), in ns.
pub const DC_REENABLE_DELAY_NS: u64 = 17_000_000;
/// The DC targets this driver may program on display 14: the DC6
/// component of `get_allowed_dc_mask`. DC3CO (a PSR2 exit-line
/// feature this driver does not configure) and DC9 (the display-core
/// uninit path this driver does not run) are never targeted.
pub const XELPDP_ALLOWED_DC_MASK: u32 = DC_STATE_EN_UPTO_DC6;
/// Upper bound on the retained container copy: 32 FW-info entries of
/// a 256-byte v3 header plus a 0x7000-byte payload, plus the CSS and
/// package headers, fit well below this.
pub const MAX_DMC_CONTAINER_BYTES: usize = 1 << 20;
/// Every `PIPEDMC_ENABLE_MTL(pipe)` bit, pipes A..D.
pub const PIPEDMC_ENABLE_MTL_ALL: u32 =
    pipedmc_enable_mtl(0) | pipedmc_enable_mtl(1) | pipedmc_enable_mtl(2) | pipedmc_enable_mtl(3);

/// `gen9_write_dc_state`: write, then re-read until the value reads
/// back unchanged seven times in a row; a read that disagrees rewrites
/// and restarts the count, at most [`DC_WRITE_MAX_REWRITES`] times.
/// On failure returns the last value read (i915 logs it).
pub fn write_dc_state_sticky<M: MmioWindow + ?Sized>(regs: &M, state: u32) -> Result<(), u32> {
    regs.write32(DC_STATE_EN, state);
    let mut rewrites = 0u32;
    let mut rereads = 0u32;
    let mut value;
    loop {
        value = regs.read32(DC_STATE_EN);
        if value != state {
            regs.write32(DC_STATE_EN, state);
            rewrites += 1;
            rereads = 0;
        } else {
            let stable = rereads > 5;
            rereads += 1;
            if stable {
                break;
            }
        }
        if rewrites >= DC_WRITE_MAX_REWRITES {
            break;
        }
    }
    if value == state {
        Ok(())
    } else {
        Err(value)
    }
}

/// `sanitize_target_dc_state` over the DC5/DC6 subset: fall from DC6
/// to DC5 to disabled until the allowed mask admits the target.
pub fn sanitize_target(allowed: u32, target: u32) -> u32 {
    let mut target = target;
    if target == DC_STATE_EN_UPTO_DC6 && allowed & DC_STATE_EN_UPTO_DC6 == 0 {
        target = DC_STATE_EN_UPTO_DC5;
    }
    if target == DC_STATE_EN_UPTO_DC5 && allowed & DC_STATE_EN_UPTO_DC5 == 0 {
        target = DC_STATE_DISABLE;
    }
    target
}

// ── Vocabulary ──────────────────────────────────────────────────

/// A holder of the `DC_off` well. Each user is counted separately so
/// a release can never cancel somebody else's reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcUser {
    /// Probe through first successful DMC load (`POWER_DOMAIN_INIT`).
    Init = 0,
    /// A DMC program (re)load.
    Load = 1,
    /// A modeset or relight.
    Modeset = 2,
    /// A KMS transaction (plane, cursor, color, DSB, console).
    Kms = 3,
    /// A PSR scanout notification.
    Psr = 4,
    /// System suspend preparation through the post-resume reload.
    Suspend = 5,
    /// One full-AUX panel-backlight conversation (AUX transaction, PPS
    /// gate, relight step): AUX_A is a DC_off domain on display 14.
    Aux = 6,
    /// One pipe-DMC enable or disable conversation
    /// (`MTL_PIPEDMC_CONTROL`, pipe C/D MMIO re-apply).
    PipeDmc = 9,
    /// An external display route, held from activation until its stop is
    /// verified. The Type-C/DDI lanes, AUX_B and pipes B-D are DC_off
    /// domains (`xelpd_pwdoms_dc_off`), and `intel_cx0_phy.c` holds
    /// `POWER_DOMAIN_DC_OFF` around every PHY message-bus transaction:
    /// while this reference lives, DC5/DC6 are never re-entered.
    ExternalRoute = 7,
    /// One external-output hardware pass: HPD poll/handle, probe, Type-C
    /// connect/disconnect, activate, stop, release, service pass or
    /// teardown. A route that stays live between passes is reported by the
    /// registered liveness predicate ([`register_external_live`]).
    External = 8,
}
const USER_COUNT: usize = 10;

/// Why a DC transition could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcError {
    /// `DC_STATE_EN` read all-ones: the function is not in D0, or the
    /// BAR authority is gone. Nothing was written.
    Unavailable,
    /// A `DC_STATE_EN` write did not stick (`gen9_write_dc_state`'s
    /// failure). Latched: DC states are never re-entered afterwards.
    DidNotStick { wanted: u32, found: u32 },
    /// A per-user reference count would overflow.
    Overflow,
}

/// Why the DMC program is not (or no longer) usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcRefusal {
    /// No firmware-registry authority could be derived.
    Authority,
    /// The registry refused the open or the view.
    Registry(narf_firmware::FirmwareError),
    /// The container exceeds [`MAX_DMC_CONTAINER_BYTES`].
    TooLarge(usize),
    /// The retained copy could not be allocated.
    Allocation,
    /// The container failed display-14 validation.
    Parse(DmcError),
    /// The program did not read back as loaded.
    Verify(DmcVerifyError),
}

/// The DMC program's lifecycle as this service sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramState {
    /// No container acquired yet.
    Absent,
    /// Acquisition, validation or verification failed; latched until a
    /// later acquisition succeeds.
    Refused(DcRefusal),
    /// A validated container is retained but not loaded yet.
    Pending,
    /// Loaded and verified; the CSS version is carried.
    Loaded { version: u32 },
    /// Event handlers swept for system suspend; reload before use.
    Disabled,
    /// Program RAM no longer verified at re-entry; reload before use.
    Lost,
}

/// Inputs to the re-entry decision that live outside this module.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArmGates {
    /// An external route is live or quarantined: the predicate registered
    /// with [`register_external_live`] reports it, or a pre-existing
    /// (Gen12-model) DP/HDMI/MST session is not stopped.
    pub external_route_active: bool,
}

/// Why DC re-entry did not happen. Except `NotDue`, every block
/// consumes the pending release: the next release re-evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmBlock {
    /// A DC_off reference is held.
    Busy,
    /// No release is pending.
    NotScheduled,
    /// The 17 ms deferral has not elapsed; retry at the deadline.
    NotDue(u64),
    /// A DC_STATE_EN write failed earlier.
    Faulted,
    /// No loaded and verified program.
    NoProgram,
    /// The loaded program no longer verifies; a reload is required.
    ProgramLost,
    /// The allowed mask admits no target.
    NoTarget,
    /// See [`ArmGates::external_route_active`].
    ExternalRoute,
    /// A pipe DMC is enabled that this driver did not enable.
    UnownedPipeDmc(u32),
    /// The utility pin drives PWM (`assert_can_enable_dc6`).
    UtilPinPwm,
    /// A gate register read all-ones.
    Unavailable,
    /// The target write failed (and is latched).
    Write(DcError),
}

// ── The state machine ───────────────────────────────────────────

/// Display-14 `DC_off` well, DC target and DMC program state.
#[derive(Clone, Debug)]
pub struct DcCore {
    refs: [u32; USER_COUNT],
    /// i915's `power_domains->dc_state`: DC_STATE_EN & GEN12_DC_MASK
    /// as last written or sanitized.
    tracked: u32,
    allowed: u32,
    target: u32,
    blob: Option<Arc<Vec<u8>>>,
    program: ProgramState,
    fault: Option<DcError>,
    arm_at: Option<u64>,
    dc6_start: u32,
    dc6_allowed: u32,
    mismatches: u32,
    arms: u64,
    last_block: Option<ArmBlock>,
    /// Pipes (bit per pipe index) whose owner reported them lit.
    pipes_lit: u32,
    /// Pipes whose `PIPEDMC_ENABLE_MTL` bit this driver set.
    pipes_enabled: u32,
}

/// `MTL_PIPEDMC_CONTROL` bits for a pipe mask.
fn pipedmc_bits(pipes: u32) -> u32 {
    (0..4)
        .filter(|p| pipes & (1 << p) != 0)
        .fold(0, |bits, p| bits | pipedmc_enable_mtl(p))
}

impl DcCore {
    /// A core with no references, nothing loaded and the target
    /// sanitized against `allowed` (from DC6 down).
    pub fn new(allowed: u32) -> Self {
        Self {
            refs: [0; USER_COUNT],
            tracked: 0,
            allowed,
            target: sanitize_target(allowed, DC_STATE_EN_UPTO_DC6),
            blob: None,
            program: ProgramState::Absent,
            fault: None,
            arm_at: None,
            dc6_start: 0,
            dc6_allowed: 0,
            mismatches: 0,
            arms: 0,
            last_block: None,
            pipes_lit: 0,
            pipes_enabled: 0,
        }
    }

    /// Total DC_off references.
    pub fn total(&self) -> u32 {
        self.refs.iter().fold(0u32, |sum, r| sum.saturating_add(*r))
    }
    /// References held by `user`.
    pub fn refs(&self, user: DcUser) -> u32 {
        self.refs[user as usize]
    }
    /// The program lifecycle state.
    pub fn program(&self) -> ProgramState {
        self.program
    }
    /// The latched write failure, if any.
    pub fn fault(&self) -> Option<DcError> {
        self.fault
    }
    /// The tracked `DC_STATE_EN & GEN12_DC_MASK`.
    pub fn tracked(&self) -> u32 {
        self.tracked
    }
    /// The sanitized target this core re-enters.
    pub fn target(&self) -> u32 {
        self.target
    }
    /// Whether a DC5/DC6 target is currently programmed.
    pub fn armed(&self) -> bool {
        self.tracked & DC_STATE_EN_UPTO_DC5_DC6_MASK != 0
    }
    /// Pending re-entry deadline.
    pub fn arm_deadline(&self) -> Option<u64> {
        self.arm_at
    }
    /// DC5 entries counted while DC6 was allowed (display >= 14).
    pub fn dc6_allowed_count(&self) -> u32 {
        self.dc6_allowed
    }
    /// Times `DC_STATE_EN` disagreed with the tracked value.
    pub fn mismatches(&self) -> u32 {
        self.mismatches
    }
    /// Successful re-entries.
    pub fn arms(&self) -> u64 {
        self.arms
    }
    /// The last re-entry refusal.
    pub fn last_block(&self) -> Option<ArmBlock> {
        self.last_block
    }
    /// Pipes reported lit.
    pub fn pipes_lit(&self) -> u32 {
        self.pipes_lit
    }
    /// Pipes whose pipe DMC this driver enabled.
    pub fn pipes_enabled(&self) -> u32 {
        self.pipes_enabled
    }

    /// A pipe owner lit `pipe` (or adopted it lit): record it and, with a
    /// loaded program, `intel_dmc_enable_pipe`. The caller holds a DC_off
    /// reference. Returns whether the pipe DMC is now enabled.
    pub fn pipe_lit<M: MmioWindow + ?Sized>(&mut self, regs: &M, pipe: u32) -> bool {
        if pipe >= 4 {
            return false;
        }
        self.pipes_lit |= 1 << pipe;
        if !matches!(self.program, ProgramState::Loaded { .. }) {
            return false;
        }
        let Some(blob) = self.blob.clone() else {
            return false;
        };
        let Ok(firmware) = parse_dmc_firmware_xelpdp(&blob, b'*', b'*') else {
            return false;
        };
        self.enable_one(regs, &firmware, pipe)
    }

    /// A pipe owner is about to disable `pipe`: `intel_dmc_disable_pipe`
    /// for an enable this driver made, then forget the pipe. The caller
    /// holds a DC_off reference.
    pub fn pipe_dark<M: MmioWindow + ?Sized>(&mut self, regs: &M, pipe: u32) {
        if pipe >= 4 {
            return;
        }
        self.pipes_lit &= !(1 << pipe);
        if self.pipes_enabled & (1 << pipe) == 0 {
            return;
        }
        if let Some(blob) = self.blob.clone() {
            if let Ok(firmware) = parse_dmc_firmware_xelpdp(&blob, b'*', b'*') {
                if disable_pipe(regs, &firmware, pipe).is_ok() {
                    self.pipes_enabled &= !(1 << pipe);
                }
            }
        }
    }

    fn enable_one<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        firmware: &DmcFirmware<'_>,
        pipe: u32,
    ) -> bool {
        match enable_pipe(regs, firmware, pipe) {
            Ok(true) => {
                self.pipes_enabled |= 1 << pipe;
                true
            }
            _ => {
                self.pipes_enabled &= !(1 << pipe);
                false
            }
        }
    }

    /// After a (re)load: `intel_dmc_enable_pipe` for every lit pipe, as
    /// the crtc enable / sanitize paths do once the program is back.
    pub fn enable_lit_pipes<M: MmioWindow + ?Sized>(&mut self, regs: &M, blob: &[u8]) {
        let Ok(firmware) = parse_dmc_firmware_xelpdp(blob, b'*', b'*') else {
            return;
        };
        for pipe in 0..4 {
            if self.pipes_lit & (1 << pipe) != 0 {
                self.enable_one(regs, &firmware, pipe);
            }
        }
    }

    /// `gen9_sanitize_dc_state`: adopt the hardware field.
    pub fn sanitize<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), DcError> {
        let value = regs.read32(DC_STATE_EN);
        if value == u32::MAX {
            return Err(DcError::Unavailable);
        }
        self.tracked = value & GEN12_DC_MASK;
        Ok(())
    }

    /// Record an Init reference without touching hardware: probe could
    /// not verify its DC exit, but re-entry must still wait for a load.
    pub fn pin_init(&mut self) {
        let slot = &mut self.refs[DcUser::Init as usize];
        *slot = slot.saturating_add(1);
        self.arm_at = None;
    }

    /// Take a `DC_off` reference. The first reference cancels any
    /// pending re-entry and, if the hardware field shows any DC state
    /// enabled, exits it (`gen9_disable_dc_states`) before returning:
    /// the caller may touch display registers only after `Ok`. A
    /// failed exit counts nothing.
    pub fn get<M: MmioWindow + ?Sized>(&mut self, regs: &M, user: DcUser) -> Result<(), DcError> {
        let next = self.refs[user as usize]
            .checked_add(1)
            .ok_or(DcError::Overflow)?;
        if self.total() == 0 {
            self.arm_at = None;
            let value = regs.read32(DC_STATE_EN);
            if value == u32::MAX {
                return Err(DcError::Unavailable);
            }
            if value & GEN12_DC_MASK != 0 || self.tracked != 0 {
                self.set_dc_state(regs, DC_STATE_DISABLE)?;
            }
        }
        self.refs[user as usize] = next;
        Ok(())
    }

    /// Release a reference. The last release schedules re-entry at
    /// `now + 17 ms` and returns that deadline; nothing is written
    /// here. An unbalanced release is ignored.
    pub fn put(&mut self, user: DcUser, now: u64) -> Option<u64> {
        let slot = &mut self.refs[user as usize];
        if *slot == 0 {
            return None;
        }
        *slot -= 1;
        if self.total() == 0 {
            let at = now.saturating_add(DC_REENABLE_DELAY_NS);
            self.arm_at = Some(at);
            Some(at)
        } else {
            None
        }
    }

    /// `gen9_set_dc_state` for display 14.
    fn set_dc_state<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        state: u32,
    ) -> Result<(), DcError> {
        // Never program anything outside the allowed mask.
        let state = state & self.allowed;
        let value = regs.read32(DC_STATE_EN);
        if value == u32::MAX {
            return Err(DcError::Unavailable);
        }
        if value & GEN12_DC_MASK != self.tracked {
            self.mismatches = self.mismatches.saturating_add(1);
        }
        let enable_dc6 = state & DC_STATE_EN_UPTO_DC6 != 0;
        let dc6_was_enabled = value & DC_STATE_EN_UPTO_DC6 != 0;
        if !dc6_was_enabled && enable_dc6 {
            self.dc6_start = regs.read32(DG1_DMC_DEBUG_DC5_COUNT);
        }
        let wanted = (value & !GEN12_DC_MASK) | state;
        if let Err(found) = write_dc_state_sticky(regs, wanted) {
            let error = DcError::DidNotStick { wanted, found };
            self.fault = Some(error);
            self.tracked = found & GEN12_DC_MASK;
            return Err(error);
        }
        if !enable_dc6 && dc6_was_enabled {
            let current = regs.read32(DG1_DMC_DEBUG_DC5_COUNT);
            self.dc6_allowed = self
                .dc6_allowed
                .wrapping_add(current.wrapping_sub(self.dc6_start));
            self.dc6_start = current;
        }
        self.tracked = wanted & GEN12_DC_MASK;
        Ok(())
    }

    /// Re-enter the target DC state if the pending release is due and
    /// every gate passes (the disable half of the `DC_off` well).
    pub fn arm_if_due<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        now: u64,
        gates: ArmGates,
    ) -> Result<u32, ArmBlock> {
        let result = self.arm_inner(regs, now, gates);
        self.last_block = result.err();
        result
    }

    fn arm_inner<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        now: u64,
        gates: ArmGates,
    ) -> Result<u32, ArmBlock> {
        if self.total() != 0 {
            return Err(ArmBlock::Busy);
        }
        let at = self.arm_at.ok_or(ArmBlock::NotScheduled)?;
        if now < at {
            return Err(ArmBlock::NotDue(at));
        }
        // The release is consumed from here on.
        self.arm_at = None;
        if self.fault.is_some() {
            return Err(ArmBlock::Faulted);
        }
        if !matches!(self.program, ProgramState::Loaded { .. }) {
            return Err(ArmBlock::NoProgram);
        }
        if self.target == DC_STATE_DISABLE {
            return Err(ArmBlock::NoTarget);
        }
        if gates.external_route_active {
            return Err(ArmBlock::ExternalRoute);
        }
        let pipedmc = regs.read32(MTL_PIPEDMC_CONTROL);
        if pipedmc == u32::MAX {
            return Err(ArmBlock::Unavailable);
        }
        if pipedmc & PIPEDMC_ENABLE_MTL_ALL & !pipedmc_bits(self.pipes_enabled) != 0 {
            return Err(ArmBlock::UnownedPipeDmc(pipedmc));
        }
        if self.target & DC_STATE_EN_UPTO_DC6 != 0 {
            let util = regs.read32(UTIL_PIN_CTL);
            if util == u32::MAX {
                return Err(ArmBlock::Unavailable);
            }
            if util & (UTIL_PIN_ENABLE | UTIL_PIN_MODE_MASK) == UTIL_PIN_ENABLE | UTIL_PIN_MODE_PWM
            {
                return Err(ArmBlock::UtilPinPwm);
            }
        }
        // assert_main_dmc_loaded, as a refusal. Only the main program:
        // pipe C/D DMC state is not kept across DC6 by design
        // (need_pipedmc_load_mmio re-applies it at pipe enable).
        let blob = self.blob.clone().ok_or(ArmBlock::NoProgram)?;
        let firmware =
            parse_dmc_firmware_xelpdp(&blob, b'*', b'*').map_err(|_| ArmBlock::NoProgram)?;
        if verify_program(regs, &firmware, DmcId::Main).is_err() {
            self.program = ProgramState::Lost;
            return Err(ArmBlock::ProgramLost);
        }
        let target = self.target;
        self.set_dc_state(regs, target).map_err(ArmBlock::Write)?;
        self.arms = self.arms.saturating_add(1);
        Ok(target)
    }

    /// Whether a firmware acquisition should be attempted.
    pub fn needs_firmware(&self) -> bool {
        self.blob.is_none()
    }

    /// Record an acquisition outcome. A validated container becomes
    /// `Pending`; a refusal is latched until a later success.
    pub fn provide_firmware(&mut self, result: Result<Arc<Vec<u8>>, DcRefusal>) {
        match result {
            Ok(blob) => {
                self.blob = Some(blob);
                self.program = ProgramState::Pending;
            }
            Err(refusal) => self.program = ProgramState::Refused(refusal),
        }
    }

    /// Begin a (re)load: with a retained container, no latched fault
    /// and a program that is pending, disabled or lost, take the Load
    /// reference (exiting DC states) and hand back the container to
    /// stream outside any lock. `Ok(None)` when nothing needs loading.
    pub fn begin_load<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
    ) -> Result<Option<Arc<Vec<u8>>>, DcError> {
        if self.fault.is_some()
            || !matches!(
                self.program,
                ProgramState::Pending | ProgramState::Disabled | ProgramState::Lost
            )
        {
            return Ok(None);
        }
        let Some(blob) = self.blob.clone() else {
            return Ok(None);
        };
        self.get(regs, DcUser::Load)?;
        Ok(Some(blob))
    }

    /// Finish a load begun by [`Self::begin_load`]: record the outcome
    /// and release the Load reference.
    pub fn finish_load(&mut self, result: Result<u32, DcRefusal>, now: u64) -> Option<u64> {
        self.program = match result {
            Ok(version) => ProgramState::Loaded { version },
            Err(refusal) => ProgramState::Refused(refusal),
        };
        self.put(DcUser::Load, now)
    }

    /// Release the Init and Suspend references once a loaded program
    /// exists (the i915 order: load, then drop the init wakeref).
    /// Without one both stay held: DC0 with the wells up.
    pub fn release_held(&mut self, now: u64) -> Option<u64> {
        if self.fault.is_some() || !matches!(self.program, ProgramState::Loaded { .. }) {
            return None;
        }
        let mut deadline = None;
        for user in [DcUser::Init, DcUser::Suspend] {
            while self.refs(user) > 0 {
                if let Some(at) = self.put(user, now) {
                    deadline = Some(at);
                }
            }
        }
        deadline
    }

    /// First half of suspend preparation: hold DC_off (exiting DC
    /// states) for the rest of the transition. Idempotent.
    pub fn suspend_begin<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), DcError> {
        if self.refs(DcUser::Suspend) != 0 {
            return Ok(());
        }
        self.get(regs, DcUser::Suspend)
    }

    /// Second half, after the display has quiesced: disable the DMC
    /// program (`intel_dmc_disable_program`). The Suspend reference
    /// stays held until the post-resume reload.
    pub fn suspend_commit<M: MmioWindow + ?Sized>(&mut self, regs: &M) {
        if self.refs(DcUser::Suspend) == 0 {
            return;
        }
        if let (ProgramState::Loaded { .. }, Some(blob)) = (self.program, self.blob.clone()) {
            if let Ok(firmware) = parse_dmc_firmware_xelpdp(&blob, b'*', b'*') {
                // The pipes go dark before display-core uninit
                // (intel_dmc_disable_pipe at crtc disable); they stay
                // recorded lit and are re-enabled after the reload.
                for pipe in 0..4 {
                    if self.pipes_enabled & (1 << pipe) != 0
                        && disable_pipe(regs, &firmware, pipe).is_ok()
                    {
                        self.pipes_enabled &= !(1 << pipe);
                    }
                }
                disable_program(regs, &firmware);
            }
            self.program = ProgramState::Disabled;
        }
    }

    /// A failed preparation: drop the Suspend reference again.
    pub fn suspend_abort(&mut self, now: u64) -> Option<u64> {
        self.put(DcUser::Suspend, now)
    }
}

/// Stream and verify a display-14 container (`intel_dmc_load_program`
/// followed by `assert_dmc_loaded`, as a refusal). The caller holds a
/// DC_off reference; no core lock is needed.
pub fn load_and_verify<M: MmioWindow + ?Sized>(regs: &M, blob: &[u8]) -> Result<u32, DcRefusal> {
    let firmware = parse_dmc_firmware_xelpdp(blob, b'*', b'*').map_err(DcRefusal::Parse)?;
    load_program(regs, &firmware);
    verify_loaded(regs, &firmware).map_err(DcRefusal::Verify)?;
    Ok(firmware.version)
}

/// One publication-time pass: acquire firmware if none is retained,
/// (re)load the program outside the core lock, then release the Init
/// and Suspend references. Returns a re-entry deadline to schedule.
pub fn publication_step<M: MmioWindow + ?Sized>(
    core: &IrqSafeSpinLock<DcCore>,
    regs: &M,
    now: u64,
    acquire: impl FnOnce() -> Result<Arc<Vec<u8>>, DcRefusal>,
) -> Option<u64> {
    if core.lock().needs_firmware() {
        let result = acquire();
        core.lock().provide_firmware(result);
    }
    let mut deadline = None;
    let blob = core.lock().begin_load(regs).ok().flatten();
    if let Some(blob) = blob {
        let result = load_and_verify(regs, &blob);
        let mut core = core.lock();
        // Under the Load reference, before it is released.
        if result.is_ok() {
            core.enable_lit_pipes(regs, &blob);
        }
        deadline = core.finish_load(result, now);
    }
    core.lock().release_held(now).or(deadline)
}

/// One re-entry attempt. A lost program is reloaded outside the core
/// lock; the reload's own release then reschedules (`NotDue`).
pub fn arm_step<M: MmioWindow + ?Sized>(
    core: &IrqSafeSpinLock<DcCore>,
    regs: &M,
    now: u64,
    gates: ArmGates,
) -> Result<u32, ArmBlock> {
    let result = core.lock().arm_if_due(regs, now, gates);
    if result != Err(ArmBlock::ProgramLost) {
        return result;
    }
    let blob = core.lock().begin_load(regs).ok().flatten();
    if let Some(blob) = blob {
        let loaded = load_and_verify(regs, &blob);
        let mut core = core.lock();
        if loaded.is_ok() {
            core.enable_lit_pipes(regs, &blob);
        }
        core.finish_load(loaded, now);
    }
    core.lock().arm_if_due(regs, now, gates)
}

// ── Firmware acquisition ────────────────────────────────────────

struct OpenContainer;
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenContainer {
    type Output = Result<Arc<Vec<u8>>, DcRefusal>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(MTL_DMC_FIRMWARE, cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(DcRefusal::Registry(error))),
        };
        blob.invoke(CopyContainer)
    }
}

struct CopyContainer;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyContainer {
    type Output = Result<Arc<Vec<u8>>, DcRefusal>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(DcRefusal::Registry)?;
            if view.bytes.len() > MAX_DMC_CONTAINER_BYTES {
                return Err(DcRefusal::TooLarge(view.bytes.len()));
            }
            // Validate before retaining: a refused container is never
            // copied, and nothing is written to hardware here.
            parse_dmc_firmware_xelpdp(view.bytes, b'*', b'*').map_err(DcRefusal::Parse)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| DcRefusal::Allocation)?;
            bytes.extend_from_slice(view.bytes);
            Ok(Arc::new(bytes))
        })())
    }
}

/// Open `i915/mtl_dmc.bin` through `authority` and return a bounded,
/// parse-validated copy. Stepping selection is wildcard: this driver
/// has no display-stepping readout, so the container's generic entry
/// is selected, exactly as the Gen12 PM seam does.
pub fn open_firmware(
    authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
) -> Result<Arc<Vec<u8>>, DcRefusal> {
    authority
        .invoke(OpenContainer)
        .map_err(|_| DcRefusal::Authority)?
}

fn acquire_firmware() -> Result<Arc<Vec<u8>>, DcRefusal> {
    let authority: Cap<narf_firmware::FirmwareRegistry, Read> =
        narf_firmware::trusted_loader_authority()
            .ok_or(DcRefusal::Authority)?
            .derive()
            .map_err(|_| DcRefusal::Authority)?;
    open_firmware(&authority)
}

// ── Production service ──────────────────────────────────────────

/// The per-function service: one integrated MTL/ARL display exists
/// (the controller is a singleton), so one service does too.
#[derive(Debug)]
pub(crate) struct DcService {
    window: crate::intel_gpu_gt_hw::AuthorizedWindow,
    bar: narf_bus::MmioRegion,
    core: IrqSafeSpinLock<DcCore>,
    arming: AtomicBool,
}

static SERVICE: IrqSafeSpinLock<Option<Arc<DcService>>> = IrqSafeSpinLock::new(None);

impl DcService {
    fn gates(&self) -> ArmGates {
        ArmGates {
            external_route_active: !crate::intel_gpu::external_routes_stopped(&self.bar)
                || external_live(),
        }
    }
}

/// The registered external-output liveness predicate (display 14).
static EXTERNAL_LIVE: IrqSafeSpinLock<Option<fn() -> bool>> = IrqSafeSpinLock::new(None);

/// Register (or, with `None`, clear) the predicate that reports an
/// external route as live or quarantined; returns the previous one. It is
/// evaluated only from the re-entry task, with no lock of this module
/// held, and must not touch registers or block. The integrator registers
/// the outputs lane's route state, e.g.
/// `register_external_live(Some(|| route_live() || !routes_stopped()))`.
pub fn register_external_live(predicate: Option<fn() -> bool>) -> Option<fn() -> bool> {
    core::mem::replace(&mut *EXTERNAL_LIVE.lock(), predicate)
}

/// Whether the registered predicate reports a live external route.
/// The predicate runs after the registry lock is released.
pub fn external_live() -> bool {
    let predicate = *EXTERNAL_LIVE.lock();
    predicate.is_some_and(|live| live())
}

/// A held `DC_off` reference. Dropping it releases the reference and,
/// for the last one, schedules deferred re-entry; nothing is written
/// to hardware on drop. Inert (holds nothing) where no display-14
/// service exists — every Gen12 path and every fixture platform.
#[must_use = "dropping the reference releases DC_off immediately"]
pub(crate) struct DcRef {
    service: Option<Arc<DcService>>,
    user: DcUser,
}

impl DcRef {
    /// A reference that holds nothing.
    pub(crate) fn none(user: DcUser) -> Self {
        Self {
            service: None,
            user,
        }
    }
}

impl core::fmt::Debug for DcRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DcRef")
            .field("user", &self.user)
            .field("held", &self.service.is_some())
            .finish()
    }
}

impl Drop for DcRef {
    fn drop(&mut self) {
        let Some(service) = self.service.take() else {
            return;
        };
        let due = service
            .core
            .lock()
            .put(self.user, narf_time::monotonic_ns());
        if due.is_some() {
            schedule_arm(&service);
        }
    }
}

fn service() -> Option<Arc<DcService>> {
    SERVICE.lock().clone()
}

fn service_for(bar: &narf_bus::MmioRegion) -> Option<Arc<DcService>> {
    service().filter(|service| service.bar.phys == bar.phys)
}

fn take(service: Option<Arc<DcService>>, user: DcUser) -> Result<DcRef, DcError> {
    let Some(service) = service else {
        return Ok(DcRef::none(user));
    };
    service.core.lock().get(&service.window, user)?;
    Ok(DcRef {
        service: Some(service),
        user,
    })
}

/// Take a `DC_off` reference on the display-14 service, if one is
/// installed. On `Ok` DC states are off until the reference drops.
pub(crate) fn acquire(user: DcUser) -> Result<DcRef, DcError> {
    take(service(), user)
}

/// [`acquire`] for the service of exactly this BAR.
///
/// External outputs and hotplug (display 14) join through two hooks:
///
/// - Every external hardware pass takes one [`DcUser::External`]
///   reference before its first register access (PHY message bus, DDI,
///   transcoder, AUX, HPD) and drops it when the pass ends:
///   `let _dc = acquire(DcUser::External).map_err(..)?; f()`.
///   `Err` means DC states could not be exited: run nothing and report the
///   port unavailable.
/// - Liveness between passes is a predicate registered once with
///   [`register_external_live`]; while it reports true, DC5/DC6 re-entry
///   is refused (`ArmBlock::ExternalRoute`). The pass that stops a route
///   releases its reference afterwards, which re-evaluates re-entry.
///
/// An owner that prefers a held reference instead may keep a
/// [`DcUser::ExternalRoute`] reference for the route's lifetime.
pub(crate) fn acquire_for_bar(bar: &narf_bus::MmioRegion, user: DcUser) -> Result<DcRef, DcError> {
    take(service_for(bar), user)
}

/// A pipe owner lit `pipe` on this BAR's display (after enabling it, or
/// when adopting a pipe firmware left lit): the pipe DMC is enabled
/// under a [`DcUser::PipeDmc`] reference once the program is loaded,
/// and again after every reload. Inert without a display-14 service.
/// `Err` means DC states could not be exited; the pipe is still
/// recorded and is enabled after the next load.
pub fn pipe_lit_for_bar(bar: &narf_bus::MmioRegion, pipe: u32) -> Result<(), DcError> {
    let Some(service) = service_for(bar) else {
        return Ok(());
    };
    let power = match take(Some(service.clone()), DcUser::PipeDmc) {
        Ok(power) => power,
        Err(error) => {
            let mut core = service.core.lock();
            if pipe < 4 {
                core.pipes_lit |= 1 << pipe;
            }
            return Err(error);
        }
    };
    service.core.lock().pipe_lit(&service.window, pipe);
    drop(power);
    Ok(())
}

/// A pipe owner is about to disable `pipe`: the pipe DMC this driver
/// enabled is disabled first (`intel_dmc_disable_pipe`). Inert without a
/// display-14 service. `Err` means DC states could not be exited; the
/// pipe is forgotten but its enable bit, if any, remains and blocks DC
/// re-entry as foreign until the hardware clears it.
pub fn pipe_dark_for_bar(bar: &narf_bus::MmioRegion, pipe: u32) -> Result<(), DcError> {
    let Some(service) = service_for(bar) else {
        return Ok(());
    };
    let power = match take(Some(service.clone()), DcUser::PipeDmc) {
        Ok(power) => power,
        Err(error) => {
            let mut core = service.core.lock();
            if pipe < 4 {
                core.pipes_lit &= !(1 << pipe);
                core.pipes_enabled &= !(1 << pipe);
            }
            return Err(error);
        }
    };
    service.core.lock().pipe_dark(&service.window, pipe);
    drop(power);
    Ok(())
}

/// A pipe owner's per-pipe DMC lifetime, at Linux's call sites:
/// [`PipeDmc::enable_pipe`] is the first step of a crtc enable
/// (`hsw_crtc_enable` → `intel_dmc_enable_pipe`, before the port PLL) and
/// [`PipeDmc::disable_pipe`] the last step of a crtc disable
/// (`hsw_crtc_disable` → `intel_dmc_disable_pipe`, after the port PLL).
/// Both are best effort: a refused DC exit never fails the pipe change.
pub trait PipeDmc {
    /// `intel_dmc_enable_pipe(pipe)`.
    fn enable_pipe(&self, pipe: u32);
    /// `intel_dmc_disable_pipe(pipe)`.
    fn disable_pipe(&self, pipe: u32);
}

/// The production sink: the display-14 DC service of the probed display
/// (one integrated display, so one service), through
/// [`pipe_lit_for_bar`] / [`pipe_dark_for_bar`] with that service's BAR.
/// Inert without a service, like [`acquire`].
#[derive(Clone, Copy, Debug, Default)]
pub struct ServicePipeDmc;

impl PipeDmc for ServicePipeDmc {
    fn enable_pipe(&self, pipe: u32) {
        if let Some(service) = service() {
            // Err: DC states could not be exited; the pipe is recorded
            // and its DMC is enabled after the next program load.
            let _ = pipe_lit_for_bar(&service.bar, pipe);
        }
    }
    fn disable_pipe(&self, pipe: u32) {
        if let Some(service) = service() {
            // Err: the pipe is forgotten; a stale enable bit blocks DC
            // re-entry as foreign until the hardware clears it.
            let _ = pipe_dark_for_bar(&service.bar, pipe);
        }
    }
}

/// A sink that reports nowhere (no display-14 DC service is involved).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPipeDmc;

impl PipeDmc for NoPipeDmc {
    fn enable_pipe(&self, _pipe: u32) {}
    fn disable_pipe(&self, _pipe: u32) {}
}

fn schedule_arm(service: &Arc<DcService>) {
    if service.arming.swap(true, Ordering::AcqRel) {
        return;
    }
    let service = service.clone();
    narf_scheduler::spawn(async move { arm_task(service).await });
}

async fn arm_task(service: Arc<DcService>) {
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
            // Gates read other modules' state: evaluate them with no
            // lock of ours held.
            let gates = service.gates();
            match arm_step(
                &service.core,
                &service.window,
                narf_time::monotonic_ns(),
                gates,
            ) {
                Err(ArmBlock::NotDue(_)) => continue,
                _ => break,
            }
        }
        service.arming.store(false, Ordering::Release);
        // A release that raced with this exit saw `arming` set and did
        // not spawn; pick its deadline up here.
        if service.core.lock().arm_deadline().is_none()
            || service.arming.swap(true, Ordering::AcqRel)
        {
            return;
        }
    }
}

/// KMS install for a display-14 function: create the service and hold
/// the Init reference (DC states exited) until the program is loaded.
pub(crate) fn install(
    generation: crate::intel_gpu::Generation,
    bar: narf_bus::MmioRegion,
    cap: Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) {
    if generation != crate::intel_gpu::Generation::MeteorLake {
        return;
    }
    let mut slot = SERVICE.lock();
    if slot.is_some() {
        return;
    }
    let service = DcService {
        window: crate::intel_gpu_gt_hw::AuthorizedWindow::new(bar, cap),
        bar,
        core: IrqSafeSpinLock::new(DcCore::new(XELPDP_ALLOWED_DC_MASK)),
        arming: AtomicBool::new(false),
    };
    {
        let mut core = service.core.lock();
        let _ = core.sanitize(&service.window);
        if core.get(&service.window, DcUser::Init).is_err() {
            core.pin_init();
        }
    }
    *slot = Some(Arc::new(service));
}

/// Card-worker hook, run after each successful GT publication with no
/// lock held: acquire, load and verify the DMC program as needed, then
/// release the Init/Suspend references.
pub(crate) fn service_after_publication(bar: &narf_bus::MmioRegion) {
    let Some(service) = service_for(bar) else {
        return;
    };
    if publication_step(
        &service.core,
        &service.window,
        narf_time::monotonic_ns(),
        acquire_firmware,
    )
    .is_some()
    {
        schedule_arm(&service);
    }
}

/// System suspend preparation, first step: exit and hold DC states off.
pub(crate) fn suspend_begin_for_bar(bar: &narf_bus::MmioRegion) -> Result<(), DcError> {
    let Some(service) = service_for(bar) else {
        return Ok(());
    };
    let mut core = service.core.lock();
    core.suspend_begin(&service.window)
}

/// System suspend preparation, last step: disable the DMC program when
/// the display quiesced (`prepared`), otherwise drop the Suspend
/// reference again.
pub(crate) fn suspend_finish_for_bar(bar: &narf_bus::MmioRegion, prepared: bool) {
    let Some(service) = service_for(bar) else {
        return;
    };
    let due = {
        let mut core = service.core.lock();
        if prepared {
            core.suspend_commit(&service.window);
            None
        } else {
            core.suspend_abort(narf_time::monotonic_ns())
        }
    };
    if due.is_some() {
        schedule_arm(&service);
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_dc_states_tests.rs"]
pub(crate) mod tests;
