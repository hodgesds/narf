//! Intel Gen9/Gen11/Gen12 RC6 — render power conservation and the
//! coarse power-gating configuration that feeds it.
//!
//! ## What RC6 is (and is not)
//!
//! RC6 is the GT's deep idle state: when every engine has been
//! idle past the programmed thresholds, the hardware may drop
//! the GT power wells and (in RC6's deeper forms) power-gate
//! the render/media blocks entirely, restoring context state
//! on the next wake. On a laptop this is the difference
//! between an idle machine that sips power and one that drains
//! its battery driving an idle GPU. This module owns the
//! *host* side of RC6 on Gen9/Gen11/Gen12 parts:
//!
//! - the enable sequence (wake-rate limits, evaluation
//!   interval, idle hysteresis, per-engine max-idle, the RC6
//!   threshold, and the coarse power-gating enables),
//! - the park / unpark discipline that arms and disarms the
//!   RC6 control register as GT activity comes and goes,
//! - the residency accounting that proves the hardware
//!   actually idles (a 32-bit hardware counter in 1.28 µs
//!   units, accumulated wrap-safely into nanoseconds).
//!
//! It is not the display DC states (DC5/DC6) — those are the
//! display microcontroller's business and live in
//! `intel_gpu_dmc`. It is also not forcewake: forcewake
//! (`intel_gpu_forcewake`) keeps a power well *up* against
//! the gating RC6 performs, and the two compose — see
//! "Composition" below.
//!
//! ## Register facts — sources
//!
//! Derived from i915, the authoritative restatement of the
//! PRM this crate uses everywhere (see `intel_gpu_regions`'
//! header). Files consulted at torvalds/linux master,
//! 2026-10-27; the Gen11 values were re-verified against
//! Linux 7.4-rc2 (commit 7475ea8b) by the Gen11 power lane,
//! which found two Gen11/Gen12 divergences and fixed them
//! (see `GUC_MAX_IDLE_COUNT` and `pg_enable_value_gen11`
//! below):
//!
//! - `drivers/gpu/drm/i915/gt/intel_rc6.c`:
//!   `gen11_rc6_enable` (used for GRAPHICS_VER ≥ 11, so it is
//!   the Gen12 sequence) programs, in order:
//!   `GEN6_RC6_WAKE_RATE_LIMIT` = `54 << 16 | 85`,
//!   `GEN10_MEDIA_WAKE_RATE_LIMIT` = 150,
//!   `GEN6_RC_EVALUATION_INTERVAL` = 125000,
//!   `GEN6_RC_IDLE_HYSTERSIS` = 25,
//!   `RING_MAX_IDLE(engine)` = 10 for each present engine,
//!   `GEN6_RC_SLEEP` = 0, `GEN6_RC6_THRESHOLD` = 50000; then
//!   the coarse power-gating hysteresis
//!   `GEN9_MEDIA_PG_IDLE_HYSTERESIS` = 60 and
//!   `GEN9_RENDER_PG_IDLE_HYSTERESIS` = 60 (the Gen11 values;
//!   Gen9 used 250), and finally `GEN9_PG_ENABLE` =
//!   render + media + media-sampler power-gate enables, plus —
//!   on Gen12 only (`GRAPHICS_VER >= 12 && !IS_DG1`) — per
//!   present video engine the VDN HCP/MFX power-gate enables.
//!   Gen11 programs render + media + media-sampler only
//!   (`pg_enable_value_gen11`). `intel_rc6_enable` runs the
//!   whole sequence with FORCEWAKE_ALL held. The sanitize/disable path
//!   (`__intel_rc6_disable`, also run at init) zeroes
//!   `GEN9_PG_ENABLE`, `GEN6_RC_CONTROL` and `GEN6_RC_STATE`.
//!   Park (`intel_rc6_park`) writes `GEN6_RC_CONTROL` =
//!   `GEN6_RC_CTL_RC6_ENABLE` alone — hardware timers off,
//!   proceed directly to RC6 — and `GEN6_RC_STATE` with the
//!   software target state 4 (normal RC6) in bits [18:16];
//!   unpark restores the full enable value into
//!   `GEN6_RC_CONTROL`. Residency
//!   (`intel_rc6_residency_ns`): the hardware counters are
//!   32-bit, in 1.28 µs units on Gen11/12, and i915
//!   accumulates wrap-safe deltas into a 64-bit total.
//! - `drivers/gpu/drm/i915/gt/intel_rc6.c`:
//!   `gen9_rc6_enable` (used for GRAPHICS_VER 9) is NOT the
//!   Gen11 sequence with a different hysteresis — the Gen9
//!   lane re-verified it in full and found five divergences
//!   from `gen11_rc6_enable` (see `enable_gen9`):
//!   (1) the wake-rate limit is platform-split — Skylake
//!   writes `108 << 16` (`WaRsDoubleRc6WrlWithCoarsePowerGating:skl`,
//!   doubling WRL only when coarse power gating is enabled),
//!   every other Gen9 part writes `54 << 16` — and the
//!   `GEN10_MEDIA_WAKE_RATE_LIMIT` write (150) does not
//!   exist on this path at all; (2) the coarse power-gating
//!   hysteresis is 250, not 60; (3) `GEN6_RC6_THRESHOLD` is
//!   37500 (37.5/125 ms per EI), not 50000 — and it is
//!   written *after* the hysteresis writes, not before
//!   them; (4) `GEN9_PG_ENABLE` is render + media only
//!   (0x3): no media-sampler bit (that enable is Gen11+,
//!   `GEN11_MEDIA_SAMPLER_PG_ENABLE`) and no VDN bits —
//!   and on Skylake GT3/GT4 parts the write is skipped
//!   entirely (`WaRsDisableCoarsePowerGating:skl,cnl`,
//!   `i915_drv.h`: `IS_SKYLAKE && (gt == 3 || gt == 4)`);
//!   (5) after the sequence `intel_rc6_enable` zeroes
//!   `rc6->ctl_enable` for GRAPHICS_VER == 9
//!   (`NEEDS_RC6_CTX_CORRUPTION_WA`), so Gen9 unpark writes
//!   0 to `GEN6_RC_CONTROL`, not the host-owned 0x88040000 —
//!   while park still works, because `rc6->manual` is latched
//!   from the pre-zeroed value and park writes
//!   `GEN6_RC_CTL_RC6_ENABLE` + target 4 itself. The park
//!   target stays 4 on Gen9: `has_rc6p` is 0 (Gen9 inherits
//!   `G75_FEATURES` via `GEN8_FEATURES`, "RC6p removed-by
//!   HSW") and `HAS_RC6pp` is always false.
//!
//! ## The Gen9 remainder in this file
//!
//! The `pctx_corrupted` check (`GEN8_RC6_CTX_INFO` 0x8504,
//! `gt/intel_gt_regs.h:544`): Linux reads it at the tail of
//! `intel_rc6_enable` and at the head of `intel_rc6_park` —
//! a zeroed context-info register means the RC6 context was
//! corrupted, and Linux then disables runtime power
//! management (`intel_rc6_disable` from park; enable returns
//! without setting `rc6->enabled`). That check needs the
//! runtime-PM disable path to land on, so it is NOT modelled
//! here: `enable_gen9` programs the thresholds and marks the
//! state enabled exactly like the Gen11 path. The register
//! offset is recorded here so the runtime-PM lane wires it
//! without re-deriving it.
//! - `drivers/gpu/drm/i915/gt/intel_gt_regs.h`: the register
//!   offsets and `GEN6_RC_CTL_*` bit definitions used below.
//! - `drivers/gpu/drm/i915/gt/intel_engine_regs.h`:
//!   `RING_MAX_IDLE(base)` = `base + 0x54`.
//!
//! ## The control value, and the GuC question
//!
//! i915 computes the `GEN6_RC_CONTROL` enable value two
//! ways. Where the GuC owns RC (TGL laptops under Linux),
//! the GuC firmware programs the thresholds itself and the
//! host only sets the RC6-enable bit. Where the host owns
//! RC, the value is `GEN6_RC_CTL_HW_ENABLE |
//! GEN6_RC_CTL_RC6_ENABLE | GEN6_RC_CTL_EI_MODE(1)`.
//! NARF has no GuC (unscoped — see the queue record), so the
//! host owns RC6 fully and this module always uses the
//! host-owned value, 0x8804_0000. (Polarity check against
//! Linux 7.4-rc2, `gt/intel_rc6.c::gen11_rc6_enable` +
//! `gt/uc/intel_guc_rc.c::intel_guc_rc_enable`: that function
//! *enables* GuC RC and returns 0 on success, so
//! `!intel_guc_rc_enable(...)` is true exactly when GuC RC
//! is active and the host sets the RC6 bit alone; a failure
//! — including no GuC at all, this driver's case — takes the
//! full host value. The in-tree value is the host-owned one.)
//! `GUC_MAX_IDLE_COUNT` (0xC3E4, `gt/uc/intel_guc_reg.h:62`)
//! is written with 0xA after the `RING_MAX_IDLE` writes, in
//! the host-owned branch of `gen11_rc6_enable` — it programs
//! the GuC's engine-idle policy, so with no GuC it has no
//! consumer here, but the sequence mirrors Linux's write
//! rather than omitting a step the reference performs.
//!
//! ## Discipline (this implementation)
//!
//! - **Enable/disable run under FORCEWAKE_ALL.** The RC6
//!   registers sit inside the gated wells; programming them
//!   without holding every aggregate domain risks dropped
//!   writes — the same reason i915 wraps the sequence.
//!   Holds are acquired render → blitter → media and
//!   released in reverse; a failed acquire rolls the earlier
//!   holds back and leaves `enabled` untouched.
//! - **Park is refused while any domain is held.** A
//!   forcewake hold means someone is mid-conversation with
//!   the hardware (an RCS submission runs inside a render
//!   hold). Parking then would arm RC6 under that work.
//!   [`Rc6::park`] checks every domain's hold count first
//!   and returns [`Rc6Error::DomainsHeld`] without touching
//!   a register. The check is on the live counts, not a
//!   latch: once the holders release, park succeeds.
//! - **Park/unpark require a prior enable.** Programming
//!   the control register before the thresholds exist is
//!   meaningless; both return [`Rc6Error::NotEnabled`].
//! - **Residency deltas are wrap-safe by construction.**
//!   The accumulator stores the previous raw sample and
//!   adds `wrapping_sub` deltas × 1280 ns; the first sample
//!   only primes. No clock is consulted, so fixtures stay
//!   deterministic under TCG.
//!
//! ## Composition
//!
//! Like [`Forcewake`] itself, `Rc6` owns no register
//! window: every operation takes the caller's `&M:
//! MmioWindow` plus the caller's `&mut Forcewake`, so the
//! enable sequence's holds nest correctly with holds other
//! subsystems already hold (acquire is refcounted — an
//! enable issued while a submission holds render simply
//! bumps the count). Production wiring follows the library
//! pattern of the other Gen12 power modules: the controller
//! composes this state next to its `Forcewake` when the
//! runtime-PM lane wires park/unpark to GT activity.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_forcewake::{Forcewake, FwDomain, FwError, FW_DOMAINS};
use crate::intel_gpu_gt::Gen9Platform;

// ── Register map (intel_gt_regs.h) ──────────────────────────

/// GEN6_RC_CONTROL — the RC6 master control register.
pub const GEN6_RC_CONTROL: u64 = 0xA090;
/// GEN6_RC_STATE — RC state / software target state.
pub const GEN6_RC_STATE: u64 = 0xA094;
/// GEN6_RC6_WAKE_RATE_LIMIT.
pub const GEN6_RC6_WAKE_RATE_LIMIT: u64 = 0xA09C;
/// GEN10_MEDIA_WAKE_RATE_LIMIT.
pub const GEN10_MEDIA_WAKE_RATE_LIMIT: u64 = 0xA0A0;
/// GEN6_RC_EVALUATION_INTERVAL.
pub const GEN6_RC_EVALUATION_INTERVAL: u64 = 0xA0A8;
/// GEN6_RC_IDLE_HYSTERSIS.
pub const GEN6_RC_IDLE_HYSTERSIS: u64 = 0xA0AC;
/// GEN6_RC_SLEEP.
pub const GEN6_RC_SLEEP: u64 = 0xA0B0;
/// GEN6_RC6_THRESHOLD.
pub const GEN6_RC6_THRESHOLD: u64 = 0xA0B8;
/// GEN9_MEDIA_PG_IDLE_HYSTERESIS.
pub const GEN9_MEDIA_PG_IDLE_HYSTERESIS: u64 = 0xA0C4;
/// GEN9_RENDER_PG_IDLE_HYSTERESIS.
pub const GEN9_RENDER_PG_IDLE_HYSTERESIS: u64 = 0xA0C8;
/// GEN9_PG_ENABLE — coarse power-gating enables.
pub const GEN9_PG_ENABLE: u64 = 0xA210;
/// GUC_MAX_IDLE_COUNT — the GuC's engine-idle-count policy
/// register (`gt/uc/intel_guc_reg.h:62`).
pub const GUC_MAX_IDLE_COUNT: u64 = 0xC3E4;
/// GEN6_GT_GFX_RC6_LOCKED — RC6 residency, locked sample.
pub const GEN6_GT_GFX_RC6_LOCKED: u64 = 0x138104;
/// GEN6_GT_GFX_RC6 — RC6 residency counter (1.28 µs units
/// on Gen11/12).
pub const GEN6_GT_GFX_RC6: u64 = 0x138108;

// ── GEN6_RC_CONTROL bits (intel_gt_regs.h) ──────────────────

/// RC6pp (deepest) enable — Gen12 has no RC6p/RC6pp; the
/// bits exist in the register definition only.
pub const RC_CTL_RC6PP_ENABLE: u32 = 1 << 16;
/// RC6p enable — not used on Gen12 (see above).
pub const RC_CTL_RC6P_ENABLE: u32 = 1 << 17;
/// RC6 enable.
pub const RC_CTL_RC6_ENABLE: u32 = 1 << 18;
/// RC1e enable.
pub const RC_CTL_RC1E_ENABLE: u32 = 1 << 20;
/// RC7 enable.
pub const RC_CTL_RC7_ENABLE: u32 = 1 << 22;
/// EI mode field, bits [28:27].
pub const fn rc_ctl_ei_mode(mode: u32) -> u32 {
    mode << 27
}
/// Hardware RC enable.
pub const RC_CTL_HW_ENABLE: u32 = 1 << 31;

/// The host-owned RC6 control value: HW enable + RC6
/// enable + EI mode 1. See the module header for why the
/// GuC-owned variant is never used here.
pub const RC6_CTL_HOST: u32 = RC_CTL_HW_ENABLE | RC_CTL_RC6_ENABLE | rc_ctl_ei_mode(1);

// ── GEN6_RC_STATE fields ────────────────────────────────────

/// Software target-state field shift in GEN6_RC_STATE.
pub const RC_SW_TARGET_STATE_SHIFT: u32 = 16;
/// Software target-state mask (3 bits at [18:16]).
pub const RC_SW_TARGET_STATE_MASK: u32 = 0x7 << RC_SW_TARGET_STATE_SHIFT;
/// Target state 4: normal RC6 (5/6 are RC6p/RC6pp, which
/// Gen12 does not implement).
pub const RC_TARGET_RC6: u32 = 4 << RC_SW_TARGET_STATE_SHIFT;

// ── GEN9_PG_ENABLE bits ─────────────────────────────────────

/// Render coarse power-gating enable.
pub const PG_RENDER_ENABLE: u32 = 1 << 0;
/// Media coarse power-gating enable.
pub const PG_MEDIA_ENABLE: u32 = 1 << 1;
/// Media sampler power-gating enable (Gen11+).
pub const PG_MEDIA_SAMPLER_ENABLE: u32 = 1 << 2;
/// VDN HCP power-gate enable for video engine `n`.
pub const fn pg_vdn_hcp_enable(n: u8) -> u32 {
    1 << (3 + 2 * n)
}
/// VDN MFX power-gate enable for video engine `n`.
pub const fn pg_vdn_mfx_enable(n: u8) -> u32 {
    1 << (4 + 2 * n)
}

// ── Programmed values (intel_rc6.c, gen11_rc6_enable) ───────

/// GEN6_RC6_WAKE_RATE_LIMIT value: render limit 54 in the
/// high half, media limit 85 in the low half.
pub const RC6_WAKE_RATE_LIMIT_VALUE: u32 = (54 << 16) | 85;
/// GEN10_MEDIA_WAKE_RATE_LIMIT value.
pub const MEDIA_WAKE_RATE_LIMIT_VALUE: u32 = 150;
/// GEN6_RC_EVALUATION_INTERVAL value (12500 × 1280 ns
/// evaluation windows, counted in the register's units).
pub const RC_EVALUATION_INTERVAL_VALUE: u32 = 125_000;
/// GEN6_RC_IDLE_HYSTERSIS value.
pub const RC_IDLE_HYSTERSIS_VALUE: u32 = 25;
/// RING_MAX_IDLE value programmed per present engine.
pub const RING_MAX_IDLE_VALUE: u32 = 10;
/// RING_MAX_IDLE offset from an engine's register base
/// (intel_engine_regs.h).
pub const RING_MAX_IDLE_OFFSET: u64 = 0x54;
/// GEN6_RC6_THRESHOLD value (in 1.28 µs units, ≈ 64 ms of
/// accumulated idle before RC6 entry).
pub const RC6_THRESHOLD_VALUE: u32 = 50_000;
/// Gen11 coarse power-gating idle hysteresis (media and
/// render).
pub const PG_IDLE_HYSTERESIS_VALUE: u32 = 60;
/// Gen9 coarse power-gating idle hysteresis (media and
/// render): 250, not the Gen11 60 (`gen9_rc6_enable`).
pub const PG_IDLE_HYSTERESIS_VALUE_GEN9: u32 = 250;
/// Gen9 RC6 threshold: 37500 (37.5/125 ms per EI), not the
/// Gen11/Gen12 50000 (`gen9_rc6_enable`).
pub const RC6_THRESHOLD_VALUE_GEN9: u32 = 37_500;
/// Gen9 wake-rate limit on Skylake: `108 << 16`
/// (`WaRsDoubleRc6WrlWithCoarsePowerGating:skl` — doubling
/// WRL only when coarse power gating is enabled).
pub const RC6_WAKE_RATE_LIMIT_VALUE_GEN9_SKL: u32 = 108 << 16;
/// Gen9 wake-rate limit off Skylake (Kaby Lake / Coffee
/// Lake / Comet Lake): `54 << 16`.
pub const RC6_WAKE_RATE_LIMIT_VALUE_GEN9: u32 = 54 << 16;
/// The `GEN6_RC_CONTROL` value unpark restores on Gen9: 0.
/// Linux zeroes `rc6->ctl_enable` for GRAPHICS_VER == 9
/// (`NEEDS_RC6_CTX_CORRUPTION_WA`) after the enable
/// sequence, so Gen9 unpark writes 0 — not the host-owned
/// 0x88040000. See the module header.
pub const RC6_CTL_GEN9: u32 = 0;
/// GUC_MAX_IDLE_COUNT value (`gen11_rc6_enable` writes 0xA).
pub const GUC_MAX_IDLE_COUNT_VALUE: u32 = 0xA;

/// The Gen12 GT's only video engine base a fixture needs:
/// VCS0, `GEN6_BSD_RING_BASE` in i915_reg.h (the VCS0 ring
/// whose sync registers `intel_engine_regs.h` names). The
/// production presence list is RCS-only today; this exists
/// so fixtures can exercise the per-engine writes and the
/// VDN power-gate bits against a second engine.
pub const VCS0_BASE: u64 = 0x12000;

/// Nanoseconds per residency-counter unit on Gen11/12
/// (1.28 µs).
pub const RESIDENCY_UNIT_NS: u64 = 1280;

/// Failure modes of the RC6 state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rc6Error {
    /// A forcewake acquire/release underneath the operation
    /// failed; the RC6 state is unchanged.
    Fw(FwError),
    /// Park/unpark was attempted before a successful
    /// enable (or after disable).
    NotEnabled,
    /// Park was refused: this forcewake domain is held, so
    /// arming RC6 could gate hardware out from under an
    /// active user (e.g. an RCS submission inside its
    /// render hold).
    DomainsHeld(FwDomain),
}

impl From<FwError> for Rc6Error {
    fn from(e: FwError) -> Self {
        Rc6Error::Fw(e)
    }
}

/// The per-generation values of the RC6 enable sequence
/// (`gen11_rc6_enable` vs `gen9_rc6_enable`): the wake-rate
/// limit, whether the media wake-rate register is written
/// at all (`None` on Gen9 — the write does not exist on
/// that path), the RC6 threshold, the coarse power-gating
/// hysteresis, the `GEN9_PG_ENABLE` value (`None` skips the
/// write — the `WaRsDisableCoarsePowerGating` case), the
/// control value unpark restores, and whether the threshold
/// precedes the hysteresis writes (Gen11/Gen12) or follows
/// them (Gen9).
struct EnableSeq {
    wake_rate_limit: u32,
    media_wake_rate_limit: Option<u32>,
    threshold: u32,
    pg_hysteresis: u32,
    pg_enable: Option<u32>,
    ctl_enable: u32,
    threshold_before_hysteresis: bool,
}

/// RC6 state: whether the enable sequence has run, and the
/// `GEN6_RC_CONTROL` value unpark restores (Linux's
/// `rc6->ctl_enable`). The register conversation itself is
/// stateless beyond this — thresholds live in the hardware
/// once programmed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rc6 {
    enabled: bool,
    ctl_enable: u32,
}

impl Rc6 {
    /// A fresh state: RC6 not enabled. The hardware side is
    /// reconciled by [`Rc6::sanitize`] at attach time.
    /// `ctl_enable` is 0 until an enable runs; it is only
    /// meaningful while `enabled` (unpark refuses otherwise).
    pub const fn new() -> Self {
        Self {
            enabled: false,
            ctl_enable: 0,
        }
    }

    /// The `GEN6_RC_CONTROL` value the last enable programmed
    /// unpark to restore (the host-owned value on Gen11/Gen12,
    /// 0 on Gen9 — see [`RC6_CTL_GEN9`]).
    pub fn ctl_enable(&self) -> u32 {
        self.ctl_enable
    }

    /// Whether the enable sequence has run (and disable has
    /// not).
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The GEN9_PG_ENABLE value for a GT with `vcs_count`
    /// video engines: render + media + media-sampler coarse
    /// gating, plus the per-VCS VDN HCP/MFX enables
    /// (gen11_rc6_enable). Gen12 only: Linux gates the VDN
    /// bits on `GRAPHICS_VER >= 12 && !IS_DG1` — Gen11 callers
    /// must use [`Self::pg_enable_value_gen11`] instead.
    pub fn pg_enable_value(vcs_count: u8) -> u32 {
        let mut v = PG_RENDER_ENABLE | PG_MEDIA_ENABLE | PG_MEDIA_SAMPLER_ENABLE;
        for n in 0..vcs_count {
            v |= pg_vdn_hcp_enable(n) | pg_vdn_mfx_enable(n);
        }
        v
    }

    /// The GEN9_PG_ENABLE value on Gen11: render + media +
    /// media-sampler coarse gating only, however many video
    /// engines are present. Linux's `gen11_rc6_enable` sets
    /// the per-VCS VDN HCP/MFX bits only at
    /// `GRAPHICS_VER >= 12` (and not on DG1), so a Gen11
    /// enable never carries them.
    pub const fn pg_enable_value_gen11() -> u32 {
        PG_RENDER_ENABLE | PG_MEDIA_ENABLE | PG_MEDIA_SAMPLER_ENABLE
    }

    /// The GEN9_PG_ENABLE value on Gen9: render + media
    /// coarse gating only (0x3). No media-sampler bit — that
    /// enable is Gen11+ (`GEN11_MEDIA_SAMPLER_PG_ENABLE`);
    /// no VDN bits — those are Gen12-only. Skylake GT3/GT4
    /// parts take the `WaRsDisableCoarsePowerGating` path
    /// instead and never write `GEN9_PG_ENABLE` at all (see
    /// [`Self::enable_gen9`]).
    pub const fn pg_enable_value_gen9() -> u32 {
        PG_RENDER_ENABLE | PG_MEDIA_ENABLE
    }

    /// Acquire every aggregate forcewake domain
    /// (FORCEWAKE_ALL), rolling back on failure.
    fn acquire_all<M: MmioWindow>(fw: &mut Forcewake, regs: &M) -> Result<(), Rc6Error> {
        let mut taken = 0;
        for domain in FW_DOMAINS {
            match fw.acquire(regs, domain) {
                Ok(()) => taken += 1,
                Err(e) => {
                    for d in FW_DOMAINS.iter().take(taken).rev() {
                        let _ = fw.release(regs, *d);
                    }
                    return Err(Rc6Error::Fw(e));
                }
            }
        }
        Ok(())
    }

    /// Release every aggregate domain, in reverse
    /// acquisition order. The first release error is
    /// reported; all releases are attempted regardless.
    fn release_all<M: MmioWindow>(fw: &mut Forcewake, regs: &M) -> Result<(), Rc6Error> {
        let mut first_err = None;
        for domain in FW_DOMAINS.iter().rev() {
            if let Err(e) = fw.release(regs, *domain) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(Rc6Error::Fw(e)),
            None => Ok(()),
        }
    }

    /// The disable write set, shared by sanitize and
    /// disable: PG enables off, RC control off, RC state
    /// cleared — `__intel_rc6_disable`'s conversation.
    fn write_disable_set<M: MmioWindow>(regs: &M) {
        regs.write32(GEN9_PG_ENABLE, 0);
        regs.write32(GEN6_RC_CONTROL, 0);
        regs.write32(GEN6_RC_STATE, 0);
    }

    /// Probe-time sanitize, mirroring i915 running
    /// `__intel_rc6_disable` at init: under FORCEWAKE_ALL,
    /// zero the power-gating enables, the RC control
    /// register and the RC state register, whatever a
    /// previous owner (firmware, a crashed kernel) left
    /// behind. Afterwards RC6 is not enabled.
    pub fn sanitize<M: MmioWindow>(
        &mut self,
        fw: &mut Forcewake,
        regs: &M,
    ) -> Result<(), Rc6Error> {
        Self::acquire_all(fw, regs)?;
        Self::write_disable_set(regs);
        self.enabled = false;
        Self::release_all(fw, regs)
    }

    /// The Gen11/Gen12 enable sequence (see the module
    /// header for the sourced order and values), run under
    /// FORCEWAKE_ALL. `engines` lists the register base of
    /// each present engine that takes a `RING_MAX_IDLE`
    /// write, in probe order (production: `&[RCS_BASE]`);
    /// `vcs_count` is the number of present video engines,
    /// feeding the VDN power-gate bits. Gen12 only: Gen11
    /// callers must use [`Self::enable_gen11`], whose
    /// `GEN9_PG_ENABLE` value carries no VDN bits. If
    /// acquiring the holds fails, nothing is programmed and
    /// `enabled` is unchanged.
    pub fn enable<M: MmioWindow>(
        &mut self,
        fw: &mut Forcewake,
        regs: &M,
        engines: &[u64],
        vcs_count: u8,
    ) -> Result<(), Rc6Error> {
        self.enable_inner(
            fw,
            regs,
            engines,
            EnableSeq {
                wake_rate_limit: RC6_WAKE_RATE_LIMIT_VALUE,
                media_wake_rate_limit: Some(MEDIA_WAKE_RATE_LIMIT_VALUE),
                threshold: RC6_THRESHOLD_VALUE,
                pg_hysteresis: PG_IDLE_HYSTERESIS_VALUE,
                pg_enable: Some(Self::pg_enable_value(vcs_count)),
                ctl_enable: RC6_CTL_HOST,
                threshold_before_hysteresis: true,
            },
        )
    }

    /// The Gen11 enable sequence: the same thresholds and
    /// hysteresis as [`Self::enable`], but `GEN9_PG_ENABLE`
    /// is the Gen11 value (render + media + media-sampler
    /// only — no VDN bits, whatever video engines are
    /// present). `engines` lists the register base of each
    /// present engine that takes a `RING_MAX_IDLE` write, in
    /// probe order (Gen11 production: RCS plus each present
    /// VCS engine's base). No production caller wires it yet — the
    /// Gen12 PM seam owns the only live enable — so this is
    /// the sequence the Gen11 PM wiring will call.
    pub fn enable_gen11<M: MmioWindow>(
        &mut self,
        fw: &mut Forcewake,
        regs: &M,
        engines: &[u64],
    ) -> Result<(), Rc6Error> {
        self.enable_inner(
            fw,
            regs,
            engines,
            EnableSeq {
                wake_rate_limit: RC6_WAKE_RATE_LIMIT_VALUE,
                media_wake_rate_limit: Some(MEDIA_WAKE_RATE_LIMIT_VALUE),
                threshold: RC6_THRESHOLD_VALUE,
                pg_hysteresis: PG_IDLE_HYSTERESIS_VALUE,
                pg_enable: Some(Self::pg_enable_value_gen11()),
                ctl_enable: RC6_CTL_HOST,
                threshold_before_hysteresis: true,
            },
        )
    }

    /// The Gen9 enable sequence (`gt/intel_rc6.c::
    /// gen9_rc6_enable`), run under FORCEWAKE_ALL. `engines`
    /// lists the register base of each present engine that
    /// takes a `RING_MAX_IDLE` write, in probe order (Gen9
    /// production: RCS plus each present VCS/BCS/VECS base,
    /// once Lane 3's `GEN9_MEDIA_ENGINES` table lands).
    /// `platform` selects the wake-rate limit: Skylake writes
    /// `108 << 16` (`WaRsDoubleRc6WrlWithCoarsePowerGating`),
    /// every other Gen9 platform writes `54 << 16`.
    /// `wa_disable_coarse_pg` is the
    /// `WaRsDisableCoarsePowerGating:skl,cnl` input — true on
    /// Skylake GT3/GT4 parts (`IS_SKYLAKE && (gt == 3 || gt
    /// == 4)`), false everywhere else (Kaby Lake / Coffee
    /// Lake / Comet Lake never take it): when true the
    /// `GEN9_PG_ENABLE` write is skipped entirely. The
    /// driver does not model the GT tier yet, so the caller
    /// passes the WA input explicitly — it is a SKU fact,
    /// not something this module can derive from the
    /// sub-platform. No production caller wires this yet —
    /// the Gen12 PM seam owns the only live enable — so this
    /// is the sequence the Gen9 PM wiring will call.
    /// If acquiring the holds fails, nothing is programmed
    /// and `enabled` is unchanged.
    pub fn enable_gen9<M: MmioWindow>(
        &mut self,
        fw: &mut Forcewake,
        regs: &M,
        engines: &[u64],
        platform: Gen9Platform,
        wa_disable_coarse_pg: bool,
    ) -> Result<(), Rc6Error> {
        let wake_rate_limit = match platform {
            Gen9Platform::Skylake => RC6_WAKE_RATE_LIMIT_VALUE_GEN9_SKL,
            Gen9Platform::KabyLake | Gen9Platform::CometLake => RC6_WAKE_RATE_LIMIT_VALUE_GEN9,
        };
        let pg_enable = if wa_disable_coarse_pg {
            None
        } else {
            Some(Self::pg_enable_value_gen9())
        };
        self.enable_inner(
            fw,
            regs,
            engines,
            EnableSeq {
                wake_rate_limit,
                media_wake_rate_limit: None,
                threshold: RC6_THRESHOLD_VALUE_GEN9,
                pg_hysteresis: PG_IDLE_HYSTERESIS_VALUE_GEN9,
                pg_enable,
                ctl_enable: RC6_CTL_GEN9,
                threshold_before_hysteresis: false,
            },
        )
    }

    fn enable_inner<M: MmioWindow>(
        &mut self,
        fw: &mut Forcewake,
        regs: &M,
        engines: &[u64],
        seq: EnableSeq,
    ) -> Result<(), Rc6Error> {
        Self::acquire_all(fw, regs)?;
        regs.write32(GEN6_RC6_WAKE_RATE_LIMIT, seq.wake_rate_limit);
        if let Some(media_wake_rate) = seq.media_wake_rate_limit {
            regs.write32(GEN10_MEDIA_WAKE_RATE_LIMIT, media_wake_rate);
        }
        regs.write32(GEN6_RC_EVALUATION_INTERVAL, RC_EVALUATION_INTERVAL_VALUE);
        regs.write32(GEN6_RC_IDLE_HYSTERSIS, RC_IDLE_HYSTERSIS_VALUE);
        for base in engines {
            regs.write32(base + RING_MAX_IDLE_OFFSET, RING_MAX_IDLE_VALUE);
        }
        regs.write32(GUC_MAX_IDLE_COUNT, GUC_MAX_IDLE_COUNT_VALUE);
        regs.write32(GEN6_RC_SLEEP, 0);
        if seq.threshold_before_hysteresis {
            regs.write32(GEN6_RC6_THRESHOLD, seq.threshold);
        }
        regs.write32(GEN9_MEDIA_PG_IDLE_HYSTERESIS, seq.pg_hysteresis);
        regs.write32(GEN9_RENDER_PG_IDLE_HYSTERESIS, seq.pg_hysteresis);
        if !seq.threshold_before_hysteresis {
            regs.write32(GEN6_RC6_THRESHOLD, seq.threshold);
        }
        if let Some(pg_enable) = seq.pg_enable {
            regs.write32(GEN9_PG_ENABLE, pg_enable);
        }
        self.ctl_enable = seq.ctl_enable;
        self.enabled = true;
        Self::release_all(fw, regs)
    }

    /// Disable RC6: the same zeroing conversation as
    /// sanitize, under FORCEWAKE_ALL. Afterwards park and
    /// unpark refuse with [`Rc6Error::NotEnabled`].
    pub fn disable<M: MmioWindow>(&mut self, fw: &mut Forcewake, regs: &M) -> Result<(), Rc6Error> {
        Self::acquire_all(fw, regs)?;
        Self::write_disable_set(regs);
        self.enabled = false;
        Self::release_all(fw, regs)
    }

    /// Unpark: GT activity is starting, so restore the
    /// enable-time control value into GEN6_RC_CONTROL
    /// (hardware evaluation timers back on). That value is
    /// the host-owned value on Gen11/Gen12 and 0 on Gen9
    /// (the `NEEDS_RC6_CTX_CORRUPTION_WA` zeroing — see
    /// [`RC6_CTL_GEN9`]). The write runs inside a render
    /// forcewake hold — RC_CONTROL lives in the render well,
    /// and the hold is what guarantees the write lands while
    /// the well is up.
    pub fn unpark<M: MmioWindow>(&self, fw: &mut Forcewake, regs: &M) -> Result<(), Rc6Error> {
        if !self.enabled {
            return Err(Rc6Error::NotEnabled);
        }
        fw.with_domain(regs, FwDomain::Render, || {
            regs.write32(GEN6_RC_CONTROL, self.ctl_enable);
        })?;
        Ok(())
    }

    /// Park: GT activity has drained, so arm RC6 — control
    /// register to the RC6-enable bit alone (hardware
    /// timers off, proceed directly to RC6) and the
    /// software target state to normal RC6.
    ///
    /// Refused, with no register touched, while any
    /// forcewake domain is held: a hold means a user is
    /// mid-conversation with gated hardware, and RC6 must
    /// not be armed under them. The two writes run inside a
    /// render hold taken *after* that check (the hold this
    /// call takes for its own writes is not a conflict —
    /// it is dropped before returning, and only then can
    /// the hardware actually gate).
    pub fn park<M: MmioWindow>(&self, fw: &mut Forcewake, regs: &M) -> Result<(), Rc6Error> {
        if !self.enabled {
            return Err(Rc6Error::NotEnabled);
        }
        for domain in FW_DOMAINS {
            if fw.is_held(domain) {
                return Err(Rc6Error::DomainsHeld(domain));
            }
        }
        fw.with_domain(regs, FwDomain::Render, || {
            regs.write32(GEN6_RC_CONTROL, RC_CTL_RC6_ENABLE);
            regs.write32(GEN6_RC_STATE, RC_TARGET_RC6);
        })?;
        Ok(())
    }

    /// The software target state currently programmed in
    /// GEN6_RC_STATE (bits [18:16]).
    pub fn sw_target_state<M: MmioWindow>(regs: &M) -> u32 {
        (regs.read32(GEN6_RC_STATE) & RC_SW_TARGET_STATE_MASK) >> RC_SW_TARGET_STATE_SHIFT
    }
}

/// Wrap-safe RC6 residency accumulator.
///
/// The hardware counter (`GEN6_GT_GFX_RC6`) is 32 bits of
/// 1.28 µs units: it wraps every ~92 minutes, so a raw read
/// is meaningless on its own. This accumulator turns a
/// sample stream into a monotonic nanosecond total exactly
/// as i915's `intel_rc6_residency_ns` does — each new
/// sample contributes its `wrapping_sub` delta from the
/// previous sample. The first sample after construction
/// only primes the accumulator (a delta needs two points).
#[derive(Clone, Copy, Debug, Default)]
pub struct Rc6Residency {
    prev_raw: Option<u32>,
    total_ns: u64,
}

impl Rc6Residency {
    /// A fresh accumulator: no samples, zero total.
    pub const fn new() -> Self {
        Self {
            prev_raw: None,
            total_ns: 0,
        }
    }

    /// Feed one raw counter sample; returns the accumulated
    /// residency in nanoseconds.
    pub fn update(&mut self, raw: u32) -> u64 {
        if let Some(prev) = self.prev_raw {
            let delta = raw.wrapping_sub(prev) as u64;
            self.total_ns = self.total_ns.saturating_add(delta * RESIDENCY_UNIT_NS);
        }
        self.prev_raw = Some(raw);
        self.total_ns
    }

    /// The accumulated residency in nanoseconds so far.
    pub fn total_ns(&self) -> u64 {
        self.total_ns
    }

    /// Sample the hardware counter and fold it in. The
    /// register lives in the render well, so the read runs
    /// inside a render forcewake hold — i915 likewise reads
    /// residency under the domain that owns the register.
    pub fn sample<M: MmioWindow>(&mut self, fw: &mut Forcewake, regs: &M) -> Result<u64, Rc6Error> {
        let total = fw.with_domain(regs, FwDomain::Render, || {
            self.update(regs.read32(GEN6_GT_GFX_RC6))
        })?;
        Ok(total)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the RC6 conversation. The fake is a
    //! model of the *hardware side* of the PRM conversation:
    //! forcewake request registers apply the masked-write
    //! rule and their ack bits converge after a programmable
    //! number of ack polls (the same hardware model the
    //! forcewake module's own fixtures use), and every other
    //! register is a plain storage cell. Expected write
    //! sequences are hand-derived from intel_rc6.c's
    //! `gen11_rc6_enable` / `gen9_rc6_enable` / park / unpark
    //! — never recorded from the implementation under test.

    use super::*;
    use crate::intel_gpu_rcs::RCS_BASE;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Fake hardware ───────────────────────────────────────

    /// Hardware model state for one forcewake domain
    /// (mirrors the forcewake fixtures' model).
    #[derive(Clone)]
    struct FakeDomain {
        set_val: u32,
        ack: bool,
        ack_target: bool,
        ack_pending: u32,
        ack_delay: u32,
        stuck_set: bool,
    }

    impl FakeDomain {
        fn new() -> Self {
            Self {
                set_val: 0,
                ack: false,
                ack_target: false,
                ack_pending: 0,
                ack_delay: 0,
                stuck_set: false,
            }
        }
    }

    /// A fake GT window: forcewake domains with converging
    /// acks over a plain register file, plus full write/read
    /// logs.
    #[derive(Clone)]
    struct FakeGt {
        domains: Rc<RefCell<[FakeDomain; 3]>>,
        regs: Rc<RefCell<BTreeMap<u64, u32>>>,
        writes: Rc<RefCell<Vec<(u64, u32)>>>,
        reads: Rc<RefCell<Vec<u64>>>,
    }

    impl FakeGt {
        fn new() -> Self {
            Self {
                domains: Rc::new(RefCell::new([
                    FakeDomain::new(),
                    FakeDomain::new(),
                    FakeDomain::new(),
                ])),
                regs: Rc::new(RefCell::new(BTreeMap::new())),
                writes: Rc::new(RefCell::new(Vec::new())),
                reads: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn writes(&self) -> Vec<(u64, u32)> {
            self.writes.borrow().clone()
        }

        fn reads(&self) -> Vec<u64> {
            self.reads.borrow().clone()
        }

        fn clear_logs(&self) {
            self.writes.borrow_mut().clear();
            self.reads.borrow_mut().clear();
        }

        fn set_stuck_set(&self, domain: FwDomain) {
            self.domains.borrow_mut()[dom_idx(domain)].stuck_set = true;
        }

        fn reg(&self, off: u64) -> u32 {
            *self.regs.borrow().get(&off).unwrap_or(&0)
        }
    }

    impl MmioWindow for FakeGt {
        fn read32(&self, off: u64) -> u32 {
            self.reads.borrow_mut().push(off);
            for domain in FW_DOMAINS {
                if off == domain.ack_reg() {
                    let mut domains = self.domains.borrow_mut();
                    let d = &mut domains[dom_idx(domain)];
                    if d.ack_pending > 0 {
                        d.ack_pending -= 1;
                    } else {
                        d.ack = d.ack_target;
                    }
                    return if d.ack {
                        crate::intel_gpu_forcewake::FORCEWAKE_KERNEL
                    } else {
                        0
                    };
                }
            }
            for domain in FW_DOMAINS {
                if off == domain.set_reg() {
                    return self.domains.borrow()[dom_idx(domain)].set_val;
                }
            }
            self.reg(off)
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            for domain in FW_DOMAINS {
                if off == domain.set_reg() {
                    let mut domains = self.domains.borrow_mut();
                    let d = &mut domains[dom_idx(domain)];
                    // PRM masked-write rule: high half is
                    // the per-bit write mask.
                    let mask = val >> 16;
                    d.set_val = (d.set_val & !mask) | (val & mask);
                    let want = d.set_val & crate::intel_gpu_forcewake::FORCEWAKE_KERNEL != 0;
                    if want != d.ack_target {
                        let frozen = want && d.stuck_set;
                        if !frozen {
                            d.ack_target = want;
                            d.ack_pending = d.ack_delay;
                        }
                    }
                    return;
                }
            }
            self.regs.borrow_mut().insert(off, val);
        }
    }

    /// Local domain -> fake-slot map (the forcewake
    /// module's own index helper is private to it). The
    /// fake's slots are consistent by construction: every
    /// access goes through this map.
    fn dom_idx(domain: FwDomain) -> usize {
        match domain {
            FwDomain::Render => 0,
            FwDomain::Blitter => 1,
            FwDomain::Media => 2,
        }
    }

    /// The masked-enable / masked-disable values the
    /// forcewake manager programs (hand-derived from
    /// `_MASKED_BIT_ENABLE/DISABLE(FORCEWAKE_KERNEL)`).
    const FW_ON: u32 = 0x0001_0001;
    const FW_OFF: u32 = 0x0001_0000;

    fn fw_acquire_writes() -> Vec<(u64, u32)> {
        FW_DOMAINS.iter().map(|d| (d.set_reg(), FW_ON)).collect()
    }

    fn fw_release_writes() -> Vec<(u64, u32)> {
        FW_DOMAINS
            .iter()
            .rev()
            .map(|d| (d.set_reg(), FW_OFF))
            .collect()
    }

    // ── Fixtures ────────────────────────────────────────────

    fn smoke_register_map_pinned() -> TestResult {
        // Hand-pinned from intel_gt_regs.h — see the module
        // header.
        if GEN6_RC_CONTROL != 0xA090
            || GEN6_RC_STATE != 0xA094
            || GEN6_RC6_WAKE_RATE_LIMIT != 0xA09C
            || GEN10_MEDIA_WAKE_RATE_LIMIT != 0xA0A0
            || GEN6_RC_EVALUATION_INTERVAL != 0xA0A8
            || GEN6_RC_IDLE_HYSTERSIS != 0xA0AC
            || GEN6_RC_SLEEP != 0xA0B0
            || GEN6_RC6_THRESHOLD != 0xA0B8
            || GEN9_MEDIA_PG_IDLE_HYSTERESIS != 0xA0C4
            || GEN9_RENDER_PG_IDLE_HYSTERESIS != 0xA0C8
            || GEN9_PG_ENABLE != 0xA210
        {
            return TestResult::Fail("RC6 register offsets diverge from intel_gt_regs.h");
        }
        if GEN6_GT_GFX_RC6 != 0x138108 || GEN6_GT_GFX_RC6_LOCKED != 0x138104 {
            return TestResult::Fail("residency counter offsets diverge from intel_gt_regs.h");
        }
        // GUC_MAX_IDLE_COUNT (intel_guc_reg.h:62) and the
        // Gen11 PG_ENABLE value (no VDN bits on Gen11).
        if GUC_MAX_IDLE_COUNT != 0xC3E4 || GUC_MAX_IDLE_COUNT_VALUE != 0xA {
            return TestResult::Fail("GUC_MAX_IDLE_COUNT diverges from intel_guc_reg.h");
        }
        if Rc6::pg_enable_value_gen11() != 0x7 {
            return TestResult::Fail("Gen11 PG_ENABLE must be render|media|sampler only");
        }
        // The host-owned control value: HW_ENABLE (bit31) |
        // EI_MODE(1) (bit27) | RC6_ENABLE (bit18).
        if RC6_CTL_HOST != 0x8804_0000 {
            return TestResult::Fail("RC6_CTL_HOST must be 0x8804_0000");
        }
        if RC_TARGET_RC6 != 0x0004_0000 {
            return TestResult::Fail("RC6 target state must be 4 << 16");
        }
        // PG_ENABLE bit layout: render/media/sampler at
        // 0/1/2, VDN pairs from bit 3.
        if Rc6::pg_enable_value(0) != 0x7
            || Rc6::pg_enable_value(1) != 0x1F
            || Rc6::pg_enable_value(2) != 0x7F
        {
            return TestResult::Fail("PG_ENABLE composition diverges from gen11_rc6_enable");
        }
        // Gen9 pins (gen9_rc6_enable): hysteresis 250 (not
        // 60), threshold 37500 (not 50000), the platform-split
        // wake-rate limit (SKL 108<<16, everything else
        // 54<<16), PG_ENABLE render|media only (0x3, no
        // sampler bit), and the Gen9 unpark value 0 (the
        // RC6_CTX_CORRUPTION_WA zeroing).
        if PG_IDLE_HYSTERESIS_VALUE_GEN9 != 250
            || RC6_THRESHOLD_VALUE_GEN9 != 37_500
            || RC6_WAKE_RATE_LIMIT_VALUE_GEN9_SKL != (108 << 16)
            || RC6_WAKE_RATE_LIMIT_VALUE_GEN9 != (54 << 16)
            || Rc6::pg_enable_value_gen9() != 0x3
            || RC6_CTL_GEN9 != 0
        {
            return TestResult::Fail("Gen9 RC6 values diverge from gen9_rc6_enable");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_register_map_pinned);

    fn smoke_sanitize_conversation() -> TestResult {
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.sanitize(&mut fw, &fake) != Ok(()) {
            return TestResult::Fail("sanitize failed against the fake GT");
        }
        let mut expected = fw_acquire_writes();
        expected.push((GEN9_PG_ENABLE, 0));
        expected.push((GEN6_RC_CONTROL, 0));
        expected.push((GEN6_RC_STATE, 0));
        expected.extend(fw_release_writes());
        if fake.writes() != expected {
            return TestResult::Fail(
                "sanitize conversation diverges from __intel_rc6_disable under FORCEWAKE_ALL",
            );
        }
        if rc6.is_enabled() {
            return TestResult::Fail("sanitize must leave RC6 disabled");
        }
        for d in FW_DOMAINS {
            if fw.is_held(d) {
                return TestResult::Fail("sanitize leaked a forcewake hold");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_sanitize_conversation);

    fn smoke_enable_conversation_rcs_only() -> TestResult {
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable(&mut fw, &fake, &[RCS_BASE], 0) != Ok(()) {
            return TestResult::Fail("enable failed against the fake GT");
        }
        // Hand-derived from gen11_rc6_enable, in order,
        // bracketed by the FORCEWAKE_ALL holds.
        let mut expected = fw_acquire_writes();
        expected.push((GEN6_RC6_WAKE_RATE_LIMIT, 0x0036_0055));
        expected.push((GEN10_MEDIA_WAKE_RATE_LIMIT, 150));
        expected.push((GEN6_RC_EVALUATION_INTERVAL, 125_000));
        expected.push((GEN6_RC_IDLE_HYSTERSIS, 25));
        expected.push((RCS_BASE + RING_MAX_IDLE_OFFSET, 10));
        expected.push((GUC_MAX_IDLE_COUNT, 0xA));
        expected.push((GEN6_RC_SLEEP, 0));
        expected.push((GEN6_RC6_THRESHOLD, 50_000));
        expected.push((GEN9_MEDIA_PG_IDLE_HYSTERESIS, 60));
        expected.push((GEN9_RENDER_PG_IDLE_HYSTERESIS, 60));
        expected.push((GEN9_PG_ENABLE, 0x7));
        expected.extend(fw_release_writes());
        if fake.writes() != expected {
            return TestResult::Fail("enable conversation diverges from gen11_rc6_enable");
        }
        if !rc6.is_enabled() {
            return TestResult::Fail("enable must mark RC6 enabled");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rc6",
        smoke_enable_conversation_rcs_only
    );

    fn smoke_enable_gen11_conversation() -> TestResult {
        // The Gen11 enable sequence, pinned end to end:
        // the same thresholds as the Gen12 sequence, but
        // PG_ENABLE is 0x7 even with a video engine present
        // — Linux gates the VDN HCP/MFX bits on
        // GRAPHICS_VER >= 12, so they never appear here.
        // This is the masking-defeating case for a
        // version-blind pg_enable_value(vcs_count) call.
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable_gen11(&mut fw, &fake, &[RCS_BASE, VCS0_BASE]) != Ok(()) {
            return TestResult::Fail("Gen11 enable failed against the fake GT");
        }
        let mut expected = fw_acquire_writes();
        expected.push((GEN6_RC6_WAKE_RATE_LIMIT, 0x0036_0055));
        expected.push((GEN10_MEDIA_WAKE_RATE_LIMIT, 150));
        expected.push((GEN6_RC_EVALUATION_INTERVAL, 125_000));
        expected.push((GEN6_RC_IDLE_HYSTERSIS, 25));
        expected.push((RCS_BASE + RING_MAX_IDLE_OFFSET, 10));
        expected.push((VCS0_BASE + RING_MAX_IDLE_OFFSET, 10));
        expected.push((GUC_MAX_IDLE_COUNT, 0xA));
        expected.push((GEN6_RC_SLEEP, 0));
        expected.push((GEN6_RC6_THRESHOLD, 50_000));
        expected.push((GEN9_MEDIA_PG_IDLE_HYSTERESIS, 60));
        expected.push((GEN9_RENDER_PG_IDLE_HYSTERESIS, 60));
        expected.push((GEN9_PG_ENABLE, 0x7));
        expected.extend(fw_release_writes());
        if fake.writes() != expected {
            return TestResult::Fail("Gen11 enable conversation diverges from gen11_rc6_enable");
        }
        if !rc6.is_enabled() {
            return TestResult::Fail("Gen11 enable must mark RC6 enabled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_enable_gen11_conversation);

    fn smoke_enable_gen9_conversation() -> TestResult {
        // The Gen9 enable sequence, pinned end to end
        // (`gen9_rc6_enable`, Kaby Lake — the non-Skylake
        // wake-rate arm): the wake-rate limit is 54<<16 with
        // NO media wake-rate write, the threshold is 37500
        // written AFTER the 250 hysteresis writes, and
        // PG_ENABLE is render|media only (0x3).
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable_gen9(
            &mut fw,
            &fake,
            &[RCS_BASE, VCS0_BASE],
            Gen9Platform::KabyLake,
            false,
        ) != Ok(())
        {
            return TestResult::Fail("Gen9 enable failed against the fake GT");
        }
        let mut expected = fw_acquire_writes();
        expected.push((GEN6_RC6_WAKE_RATE_LIMIT, 0x0036_0000));
        expected.push((GEN6_RC_EVALUATION_INTERVAL, 125_000));
        expected.push((GEN6_RC_IDLE_HYSTERSIS, 25));
        expected.push((RCS_BASE + RING_MAX_IDLE_OFFSET, 10));
        expected.push((VCS0_BASE + RING_MAX_IDLE_OFFSET, 10));
        expected.push((GUC_MAX_IDLE_COUNT, 0xA));
        expected.push((GEN6_RC_SLEEP, 0));
        expected.push((GEN9_MEDIA_PG_IDLE_HYSTERESIS, 250));
        expected.push((GEN9_RENDER_PG_IDLE_HYSTERESIS, 250));
        expected.push((GEN6_RC6_THRESHOLD, 37_500));
        expected.push((GEN9_PG_ENABLE, 0x3));
        expected.extend(fw_release_writes());
        if fake.writes() != expected {
            return TestResult::Fail("Gen9 enable conversation diverges from gen9_rc6_enable");
        }
        if !rc6.is_enabled() || rc6.ctl_enable() != 0 {
            return TestResult::Fail("Gen9 enable must mark RC6 enabled with ctl_enable 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_enable_gen9_conversation);

    fn smoke_enable_gen9_skl_wake_rate() -> TestResult {
        // Skylake doubles the wake-rate limit
        // (WaRsDoubleRc6WrlWithCoarsePowerGating:skl): 108<<16,
        // while the rest of the sequence is the Gen9 one.
        // This is the masking-defeating case for a
        // platform-blind `54 << 16` wake-rate value.
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable_gen9(&mut fw, &fake, &[RCS_BASE], Gen9Platform::Skylake, false) != Ok(()) {
            return TestResult::Fail("Skylake Gen9 enable failed against the fake GT");
        }
        let writes = fake.writes();
        if !writes.contains(&(GEN6_RC6_WAKE_RATE_LIMIT, 0x006C_0000)) {
            return TestResult::Fail("Skylake wake-rate limit must be 108 << 16");
        }
        if writes
            .iter()
            .any(|(off, _)| *off == GEN10_MEDIA_WAKE_RATE_LIMIT)
        {
            return TestResult::Fail("Gen9 enable must not write the media wake-rate register");
        }
        if !writes.contains(&(GEN9_PG_ENABLE, 0x3)) {
            return TestResult::Fail("Skylake PG_ENABLE must be render|media only");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_enable_gen9_skl_wake_rate);

    fn smoke_enable_gen9_skl_gt3_skips_pg_enable() -> TestResult {
        // WaRsDisableCoarsePowerGating (Skylake GT3/GT4):
        // the PG_ENABLE write is skipped entirely — render
        // and media coarse gating stay off with RC6. This is
        // the masking-defeating case for an unconditional
        // PG_ENABLE write.
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable_gen9(&mut fw, &fake, &[RCS_BASE], Gen9Platform::Skylake, true) != Ok(()) {
            return TestResult::Fail("Skylake GT3 Gen9 enable failed against the fake GT");
        }
        if fake.writes().iter().any(|(off, _)| *off == GEN9_PG_ENABLE) {
            return TestResult::Fail("WaRsDisableCoarsePowerGating must skip the PG_ENABLE write");
        }
        if !rc6.is_enabled() {
            return TestResult::Fail("skipping PG_ENABLE must still mark RC6 enabled");
        }
        // The thresholds are still programmed: the WA only
        // drops the coarse-gating enable.
        if !fake
            .writes()
            .contains(&(GEN9_RENDER_PG_IDLE_HYSTERESIS, 250))
            || !fake.writes().contains(&(GEN6_RC6_THRESHOLD, 37_500))
        {
            return TestResult::Fail("the WA must not drop the threshold/hysteresis writes");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rc6",
        smoke_enable_gen9_skl_gt3_skips_pg_enable
    );

    fn smoke_gen9_park_unpark_conversation() -> TestResult {
        // Gen9 park/unpark after a Gen9 enable: unpark
        // writes 0 to GEN6_RC_CONTROL (the
        // RC6_CTX_CORRUPTION_WA zeroing), while park still
        // arms RC6 with the RC6-enable bit alone + target
        // state 4 — `manual` is latched from the pre-zeroed
        // control value.
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable_gen9(&mut fw, &fake, &[RCS_BASE], Gen9Platform::CometLake, false) != Ok(()) {
            return TestResult::Fail("Gen9 enable failed against the fake GT");
        }
        fake.clear_logs();
        if rc6.unpark(&mut fw, &fake) != Ok(()) {
            return TestResult::Fail("Gen9 unpark failed");
        }
        let expected = alloc::vec![
            (FwDomain::Render.set_reg(), FW_ON),
            (GEN6_RC_CONTROL, 0),
            (FwDomain::Render.set_reg(), FW_OFF),
        ];
        if fake.writes() != expected {
            return TestResult::Fail("Gen9 unpark must write GEN6_RC_CONTROL = 0");
        }
        fake.clear_logs();
        if rc6.park(&mut fw, &fake) != Ok(()) {
            return TestResult::Fail("Gen9 park failed");
        }
        let expected = alloc::vec![
            (FwDomain::Render.set_reg(), FW_ON),
            (GEN6_RC_CONTROL, RC_CTL_RC6_ENABLE),
            (GEN6_RC_STATE, RC_TARGET_RC6),
            (FwDomain::Render.set_reg(), FW_OFF),
        ];
        if fake.writes() != expected {
            return TestResult::Fail("Gen9 park conversation diverges from intel_rc6_park");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rc6",
        smoke_gen9_park_unpark_conversation
    );

    fn smoke_enable_conversation_with_vcs() -> TestResult {
        // A second engine present: its RING_MAX_IDLE write
        // joins the sequence and the VDN HCP/MFX bits join
        // PG_ENABLE. This is the masking-defeating case for
        // a hardcoded RCS-only sequence.
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable(&mut fw, &fake, &[RCS_BASE, VCS0_BASE], 1) != Ok(()) {
            return TestResult::Fail("enable with VCS failed against the fake GT");
        }
        let writes = fake.writes();
        let rcs_idle = (RCS_BASE + RING_MAX_IDLE_OFFSET, 10);
        let vcs_idle = (VCS0_BASE + RING_MAX_IDLE_OFFSET, 10);
        let pos = |needle: &(u64, u32)| writes.iter().position(|w| w == needle);
        match (pos(&rcs_idle), pos(&vcs_idle)) {
            (Some(a), Some(b)) if a < b => {}
            _ => {
                return TestResult::Fail("per-engine RING_MAX_IDLE writes missing or out of order");
            }
        }
        if !writes.contains(&(GEN9_PG_ENABLE, 0x1F)) {
            return TestResult::Fail("PG_ENABLE must carry VDN HCP/MFX bits for one VCS");
        }
        // The Gen12 sequence also carries the GuC idle-count
        // write (this fixture is the Gen12 path — the Gen11
        // path pins its own sequence separately).
        if !writes.contains(&(GUC_MAX_IDLE_COUNT, 0xA)) {
            return TestResult::Fail("enable must write GUC_MAX_IDLE_COUNT = 0xA");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rc6",
        smoke_enable_conversation_with_vcs
    );

    fn smoke_park_unpark_conversation() -> TestResult {
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable(&mut fw, &fake, &[RCS_BASE], 0) != Ok(()) {
            return TestResult::Fail("enable failed against the fake GT");
        }
        fake.clear_logs();
        if rc6.unpark(&mut fw, &fake) != Ok(()) {
            return TestResult::Fail("unpark failed");
        }
        let mut expected = alloc::vec![
            (FwDomain::Render.set_reg(), FW_ON),
            (GEN6_RC_CONTROL, RC6_CTL_HOST),
            (FwDomain::Render.set_reg(), FW_OFF),
        ];
        if fake.writes() != expected {
            return TestResult::Fail(
                "unpark must restore the full control value inside a render hold",
            );
        }
        fake.clear_logs();
        if rc6.park(&mut fw, &fake) != Ok(()) {
            return TestResult::Fail("park failed");
        }
        expected = alloc::vec![
            (FwDomain::Render.set_reg(), FW_ON),
            (GEN6_RC_CONTROL, RC_CTL_RC6_ENABLE),
            (GEN6_RC_STATE, RC_TARGET_RC6),
            (FwDomain::Render.set_reg(), FW_OFF),
        ];
        if fake.writes() != expected {
            return TestResult::Fail("park conversation diverges from intel_rc6_park");
        }
        if Rc6::sw_target_state(&fake) != 4 {
            return TestResult::Fail("park must leave target state 4 (normal RC6) in RC_STATE");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_park_unpark_conversation);

    fn smoke_park_refused_while_held() -> TestResult {
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable(&mut fw, &fake, &[RCS_BASE], 0) != Ok(()) {
            return TestResult::Fail("enable failed against the fake GT");
        }
        // An active user: a render hold, as an RCS
        // submission holds while it runs.
        if fw.acquire(&fake, FwDomain::Render) != Ok(()) {
            return TestResult::Fail("fixture could not take the render hold");
        }
        fake.clear_logs();
        if rc6.park(&mut fw, &fake) != Err(Rc6Error::DomainsHeld(FwDomain::Render)) {
            return TestResult::Fail("park must refuse while the render domain is held");
        }
        if !fake.writes().is_empty() {
            return TestResult::Fail("a refused park must not touch any register");
        }
        // A media hold alone also blocks park (any domain
        // held = work in flight somewhere in the GT).
        if fw.acquire(&fake, FwDomain::Media) != Ok(()) {
            return TestResult::Fail("fixture could not take the media hold");
        }
        if fw.release(&fake, FwDomain::Render) != Ok(()) {
            return TestResult::Fail("fixture could not drop the render hold");
        }
        fake.clear_logs();
        if rc6.park(&mut fw, &fake) != Err(Rc6Error::DomainsHeld(FwDomain::Media)) {
            return TestResult::Fail("park must refuse while the media domain is held");
        }
        if !fake.writes().is_empty() {
            return TestResult::Fail("a refused park must not touch any register");
        }
        // Once every holder releases, park succeeds — the
        // refusal tracks live holds, it is not a latch.
        if fw.release(&fake, FwDomain::Media) != Ok(()) {
            return TestResult::Fail("fixture could not drop the media hold");
        }
        fake.clear_logs();
        if rc6.park(&mut fw, &fake) != Ok(()) {
            return TestResult::Fail("park must succeed once all holds are dropped");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_park_refused_while_held);

    fn smoke_park_unpark_require_enable() -> TestResult {
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let rc6 = Rc6::new();
        if rc6.unpark(&mut fw, &fake) != Err(Rc6Error::NotEnabled) {
            return TestResult::Fail("unpark before enable must refuse");
        }
        if rc6.park(&mut fw, &fake) != Err(Rc6Error::NotEnabled) {
            return TestResult::Fail("park before enable must refuse");
        }
        if !fake.writes().is_empty() {
            return TestResult::Fail("refused park/unpark must not touch any register");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rc6",
        smoke_park_unpark_require_enable
    );

    fn smoke_disable_conversation() -> TestResult {
        let fake = FakeGt::new();
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        if rc6.enable(&mut fw, &fake, &[RCS_BASE], 0) != Ok(()) {
            return TestResult::Fail("enable failed against the fake GT");
        }
        fake.clear_logs();
        if rc6.disable(&mut fw, &fake) != Ok(()) {
            return TestResult::Fail("disable failed against the fake GT");
        }
        let mut expected = fw_acquire_writes();
        expected.push((GEN9_PG_ENABLE, 0));
        expected.push((GEN6_RC_CONTROL, 0));
        expected.push((GEN6_RC_STATE, 0));
        expected.extend(fw_release_writes());
        if fake.writes() != expected {
            return TestResult::Fail("disable conversation diverges from __intel_rc6_disable");
        }
        if rc6.is_enabled() || rc6.park(&mut fw, &fake) != Err(Rc6Error::NotEnabled) {
            return TestResult::Fail("disable must return the state machine to not-enabled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_disable_conversation);

    fn smoke_enable_acquire_failure_rolls_back() -> TestResult {
        // The media domain's ack never sets: enable must
        // fail, program nothing, mark nothing, and roll the
        // render/blitter holds back off (no leaked holds).
        let fake = FakeGt::new();
        fake.set_stuck_set(FwDomain::Media);
        let mut fw = Forcewake::new();
        let mut rc6 = Rc6::new();
        match rc6.enable(&mut fw, &fake, &[RCS_BASE], 0) {
            Err(Rc6Error::Fw(_)) => {}
            _ => return TestResult::Fail("enable must surface the forcewake failure"),
        }
        if rc6.is_enabled() {
            return TestResult::Fail("a failed enable must not mark RC6 enabled");
        }
        for d in FW_DOMAINS {
            if fw.is_held(d) {
                return TestResult::Fail("a failed enable leaked a forcewake hold");
            }
        }
        for (off, _) in fake.writes() {
            if off == GEN9_PG_ENABLE || off == GEN6_RC6_THRESHOLD {
                return TestResult::Fail("a failed enable must not program RC6 registers");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rc6",
        smoke_enable_acquire_failure_rolls_back
    );

    fn smoke_residency_accumulation() -> TestResult {
        let mut acc = Rc6Residency::new();
        // First sample primes only.
        if acc.update(1_000) != 0 {
            return TestResult::Fail("first residency sample must contribute nothing");
        }
        // +500 counts × 1280 ns.
        if acc.update(1_500) != 640_000 {
            return TestResult::Fail("residency delta must be counts × 1280 ns");
        }
        // Wrap: prev near the top, next just past it.
        let mut acc2 = Rc6Residency::new();
        acc2.update(0xFFFF_FF00);
        let expect = 0x200u64 * RESIDENCY_UNIT_NS;
        if acc2.update(0x0000_0100) != expect {
            return TestResult::Fail("residency accumulation must be wrap-safe");
        }
        // A stalled counter contributes nothing.
        if acc2.update(0x0000_0100) != expect {
            return TestResult::Fail("a repeated sample must not double-count");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_rc6", smoke_residency_accumulation);

    fn smoke_residency_sample_holds_render() -> TestResult {
        let fake = FakeGt::new();
        fake.regs.borrow_mut().insert(GEN6_GT_GFX_RC6, 42);
        let mut fw = Forcewake::new();
        let mut acc = Rc6Residency::new();
        if acc.sample(&mut fw, &fake) != Ok(0) {
            return TestResult::Fail("first hardware sample must prime to zero");
        }
        // The counter read happened, bracketed by the
        // render hold's set/clear writes.
        let writes = fake.writes();
        if writes.first() != Some(&(FwDomain::Render.set_reg(), FW_ON))
            || writes.last() != Some(&(FwDomain::Render.set_reg(), FW_OFF))
        {
            return TestResult::Fail("residency read must run inside a render forcewake hold");
        }
        if !fake.reads().contains(&GEN6_GT_GFX_RC6) {
            return TestResult::Fail("residency sample must read GEN6_GT_GFX_RC6");
        }
        fake.regs.borrow_mut().insert(GEN6_GT_GFX_RC6, 42 + 8);
        if acc.sample(&mut fw, &fake) != Ok(8 * RESIDENCY_UNIT_NS) {
            return TestResult::Fail("second hardware sample must fold its delta in");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_rc6",
        smoke_residency_sample_holds_render
    );
}
