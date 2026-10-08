//! AMD GPU reset paths: TDR (Timeout Detection and Recovery), soft
//! reset (per-engine), and full reset (BACO — Bus Active Compute Off).
//!
//! ## TDR — Timeout Detection and Recovery
//!
//! Every ring-submission carries a fence the GPU is expected to
//! publish within a per-engine TDR window (typical: GFX 10 s,
//! Compute 60 s, SDMA 8 s). If a fence misses its TDR, the host
//! escalates:
//!
//!   1. **Soft reset** — halt the offending engine, drain pending
//!      packets, re-init the ring, retire all fences as "lost".
//!      Per-engine; other engines keep running.
//!   2. **Full reset** — soft reset didn't recover. Hand the GPU
//!      a BACO transition: power down to PCIe link-only state,
//!      then back up. Loses all in-flight state on every engine.
//!
//! ## BACO sequence
//!
//! BACO entry is driven via the SMU mailbox (`PPSMC_MSG_EnterBaco`)
//! after the driver tears down all rings + flushes the IOMMU. BACO
//! exit is `PPSMC_MSG_ExitBaco` followed by full reinit (PSP
//! firmware re-load, ring re-init, VMID re-bind).
//!
//! ## References (post 2026-05-20 GPL relicense)
//!
//! - drivers/gpu/drm/amd/amdgpu/amdgpu_device.c::
//!   amdgpu_device_pre_asic_reset / amdgpu_device_gpu_recover.
//! - drivers/gpu/drm/amd/pm/swsmu/smu13/smu_v13_0.c (BACO SMU
//!   message routing for Phoenix).

extern crate alloc;

#[cfg(target_arch = "x86_64")]
use alloc::vec::Vec;

// ── Engine + TDR config ────────────────────────────────────────────

/// Engines we can reset independently. GPU has one each except
/// SDMA (two on dGPU).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResetEngine {
    Gfx,
    Compute,
    Sdma0,
    Sdma1,
    Vcn,
}

impl ResetEngine {
    pub fn name(self) -> &'static str {
        match self {
            ResetEngine::Gfx => "gfx",
            ResetEngine::Compute => "compute",
            ResetEngine::Sdma0 => "sdma0",
            ResetEngine::Sdma1 => "sdma1",
            ResetEngine::Vcn => "vcn",
        }
    }
}

/// Default TDR windows. Per Linux's `amdgpu/amdgpu_device.c`:
///   - GFX:     ~10 s
///   - Compute: ~60 s (compute kernels can legitimately run long)
///   - SDMA:    ~8 s
///   - VCN:     ~10 s
pub fn default_tdr_ms(engine: ResetEngine) -> u32 {
    match engine {
        ResetEngine::Gfx => 10_000,
        ResetEngine::Compute => 60_000,
        ResetEngine::Sdma0 | ResetEngine::Sdma1 => 8_000,
        ResetEngine::Vcn => 10_000,
    }
}

// ── Reset decisions ────────────────────────────────────────────────

/// What the TDR escalation policy decided to do. Returned by
/// [`evaluate_hang`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResetAction {
    /// No hang — fence is still progressing.
    NoAction,
    /// Per-engine soft reset.
    Soft(ResetEngine),
    /// Full BACO reset — soft didn't help.
    Baco,
}

/// Per-engine TDR state. The driver bumps `last_fence_observed`
/// whenever the GPU publishes a fence; the watchdog evaluates the
/// "time since last progress" against the engine's TDR window.
#[derive(Copy, Clone, Debug)]
pub struct EngineTdrState {
    pub engine: ResetEngine,
    pub last_fence_observed: u64,
    pub last_fence_progress_at_ms: u64,
    /// How many soft resets we've already issued for this hang.
    /// After `max_soft_resets`, the next escalation goes to BACO.
    pub soft_resets_done: u32,
    pub max_soft_resets: u32,
    pub tdr_window_ms: u32,
}

impl EngineTdrState {
    pub fn new(engine: ResetEngine) -> Self {
        Self {
            engine,
            last_fence_observed: 0,
            last_fence_progress_at_ms: 0,
            soft_resets_done: 0,
            max_soft_resets: 2,
            tdr_window_ms: default_tdr_ms(engine),
        }
    }

    /// Caller bumps this whenever the GPU's fence dword advances.
    /// Resets the TDR-elapsed timer.
    pub fn note_fence_progress(&mut self, current_seq: u64, now_ms: u64) {
        if current_seq > self.last_fence_observed {
            self.last_fence_observed = current_seq;
            self.last_fence_progress_at_ms = now_ms;
            // Fresh progress — reset the soft-reset counter so
            // future hangs start fresh.
            self.soft_resets_done = 0;
        }
    }
}

/// Watchdog tick. Evaluates whether `engine` has hung past its
/// TDR window + (if so) which reset to apply.
pub fn evaluate_hang(state: &EngineTdrState, now_ms: u64) -> ResetAction {
    let elapsed = now_ms.saturating_sub(state.last_fence_progress_at_ms);
    if elapsed < state.tdr_window_ms as u64 {
        return ResetAction::NoAction;
    }
    if state.soft_resets_done < state.max_soft_resets {
        ResetAction::Soft(state.engine)
    } else {
        ResetAction::Baco
    }
}

// ── Soft reset (per-engine) ────────────────────────────────────────

/// `regGRBM_SOFT_RESET` is dword 0x0da8 at BASE_IDX **0**, so the byte offset
/// within the GC window is `0x0da8 << 2`.
pub const GRBM_SOFT_RESET_OFFSET: u32 = 0x0DA8 << 2;

/// Per-engine `GRBM_SOFT_RESET` bit positions, from `gc_11_0_0_sh_mask.h`.
/// The bits are not densely packed and not ordered by engine: CP is at 0, RLC
/// at 2, then a gap to UTCL2 at 15, GFX at 16, the three CP sub-blocks at
/// 17..19, CAC at 20, EA at 22 and the two SDMAs at 23 and 24.
pub const SOFT_RESET_BIT_CP: u32 = 1 << 0;
pub const SOFT_RESET_BIT_RLC: u32 = 1 << 2;
pub const SOFT_RESET_BIT_UTCL2: u32 = 1 << 15;
/// `SOFT_RESET_GFX` is bit **16**. Bit 14 — what this used to carry — is not
/// a defined field in this register at all.
pub const SOFT_RESET_BIT_GFX: u32 = 1 << 16;
pub const SOFT_RESET_BIT_CPF: u32 = 1 << 17;
pub const SOFT_RESET_BIT_CPC: u32 = 1 << 18;
pub const SOFT_RESET_BIT_CPG: u32 = 1 << 19;
pub const SOFT_RESET_BIT_CAC: u32 = 1 << 20;
pub const SOFT_RESET_BIT_EA: u32 = 1 << 22;
/// The two SDMA engines have **separate** bits, 23 and 24 — not one shared
/// bit, and not bit 1, which is undefined here.
pub const SOFT_RESET_BIT_SDMA0: u32 = 1 << 23;
pub const SOFT_RESET_BIT_SDMA1: u32 = 1 << 24;

// LINUX-GAP: there is no VCN bit in `GRBM_SOFT_RESET`. GRBM covers the
// graphics and SDMA blocks only; VCN resets through its own
// `UVD_SOFT_RESET`/`UVD_POWER_STATUS` path in `vcn_v4_0.c`, or through the
// SMU's `PowerDownVcn`/`PowerUpVcn` pair on an APU. What stood here was
// `1 << 17`, which is `SOFT_RESET_CPF` — a VCN reset request would have reset
// the command processor's fetcher instead.

/// The `GRBM_SOFT_RESET` bits for `engine`, or `None` for an engine this
/// register does not cover.
pub fn soft_reset_bit(engine: ResetEngine) -> Option<u32> {
    match engine {
        // `gfx_v11_0_soft_reset` pulses the graphics block together with the
        // CP sub-blocks that feed it.
        ResetEngine::Gfx => Some(
            SOFT_RESET_BIT_GFX
                | SOFT_RESET_BIT_CP
                | SOFT_RESET_BIT_CPF
                | SOFT_RESET_BIT_CPG
                | SOFT_RESET_BIT_CPC,
        ),
        // Compute runs on the MEC, which is the CPC sub-block.
        ResetEngine::Compute => Some(SOFT_RESET_BIT_CP | SOFT_RESET_BIT_CPC),
        ResetEngine::Sdma0 => Some(SOFT_RESET_BIT_SDMA0),
        ResetEngine::Sdma1 => Some(SOFT_RESET_BIT_SDMA1),
        // Not a GRBM block — see the gap note above.
        ResetEngine::Vcn => None,
    }
}

/// MMIO trait for the reset path.
pub trait ResetMmio {
    fn read(&mut self, byte_off: u32) -> u32;
    fn write(&mut self, byte_off: u32, value: u32);
}

/// Apply a per-engine soft reset by pulsing the `GRBM_SOFT_RESET` bits.
/// Sequence per Linux `gfx_v11_0.c::gfx_v11_0_soft_reset`:
///
///   1. Read GRBM_SOFT_RESET, OR in the engine's bits, write back.
///   2. Wait ~50 µs for the engine to halt.
///   3. Clear the bits (write back without them) — engine restarts.
///
/// Returns `false` for an engine `GRBM_SOFT_RESET` does not cover, without
/// touching the register.
pub fn apply_soft_reset<M: ResetMmio>(mmio: &mut M, engine: ResetEngine) -> bool {
    let Some(bit) = soft_reset_bit(engine) else {
        return false;
    };
    let cur = mmio.read(GRBM_SOFT_RESET_OFFSET);
    mmio.write(GRBM_SOFT_RESET_OFFSET, cur | bit);
    // Caller's responsibility to wait for the halt. In production
    // this is a udelay(50). We don't have a delay primitive in the
    // pure-logic layer; production glue wraps the call.
    mmio.write(GRBM_SOFT_RESET_OFFSET, cur & !bit);
    true
}

// ── BACO (full reset) ──────────────────────────────────────────────

/// State machine for a BACO entry/exit cycle. Sequence per
/// `smu_v13_0.c::smu_v13_0_baco_set_state`:
///   Active → DrainQueues → SaveState → SendEnterBaco → Off
///   Off → SendExitBaco → ReloadFirmware → ReinitRings → Active
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BacoState {
    Active,
    DrainQueues,
    SaveState,
    EnteringBaco,
    Off,
    ExitingBaco,
    ReloadingFirmware,
    ReinitRings,
}

/// BACO controller — tracks the state machine + counts attempts.
#[derive(Copy, Clone, Debug)]
pub struct BacoController {
    pub state: BacoState,
    pub attempts: u32,
    pub successes: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BacoError {
    /// Transition isn't legal from the current state.
    IllegalTransition,
    /// SMU rejected the BACO entry/exit message.
    SmuReject,
}

impl BacoController {
    pub fn new() -> Self {
        Self {
            state: BacoState::Active,
            attempts: 0,
            successes: 0,
        }
    }

    /// Kick off a BACO entry. Caller's responsibility to call
    /// `advance` periodically to push the state machine forward.
    pub fn begin_entry(&mut self) -> Result<(), BacoError> {
        if !matches!(self.state, BacoState::Active) {
            return Err(BacoError::IllegalTransition);
        }
        self.attempts += 1;
        self.state = BacoState::DrainQueues;
        Ok(())
    }

    /// Advance the state machine one step. Each call corresponds
    /// to one driver work-item that's completed.
    pub fn advance(&mut self) -> Result<(), BacoError> {
        self.state = match self.state {
            BacoState::Active => return Err(BacoError::IllegalTransition),
            BacoState::DrainQueues => BacoState::SaveState,
            BacoState::SaveState => BacoState::EnteringBaco,
            BacoState::EnteringBaco => BacoState::Off,
            BacoState::Off => BacoState::ExitingBaco,
            BacoState::ExitingBaco => BacoState::ReloadingFirmware,
            BacoState::ReloadingFirmware => BacoState::ReinitRings,
            BacoState::ReinitRings => {
                self.successes += 1;
                BacoState::Active
            }
        };
        Ok(())
    }

    /// `true` if a BACO cycle has completed and the GPU is live again.
    pub fn is_live(&self) -> bool {
        matches!(self.state, BacoState::Active)
    }
}

impl Default for BacoController {
    fn default() -> Self {
        Self::new()
    }
}

// ── Smoke tests ───────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_default_tdr_per_engine() -> TestResult {
        if default_tdr_ms(ResetEngine::Gfx) != 10_000 {
            return TestResult::Fail("gfx TDR");
        }
        if default_tdr_ms(ResetEngine::Compute) != 60_000 {
            return TestResult::Fail("compute TDR");
        }
        if default_tdr_ms(ResetEngine::Sdma0) != 8_000 {
            return TestResult::Fail("sdma TDR");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_default_tdr_per_engine);

    fn smoke_engine_tdr_progress_resets_timer() -> TestResult {
        let mut s = EngineTdrState::new(ResetEngine::Gfx);
        s.note_fence_progress(1, 1000);
        if s.last_fence_progress_at_ms != 1000 {
            return TestResult::Fail("timer not updated");
        }
        // No progress on a smaller seq.
        s.note_fence_progress(0, 2000);
        if s.last_fence_progress_at_ms != 1000 {
            return TestResult::Fail("regression in seq updated timer");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_engine_tdr_progress_resets_timer);

    fn smoke_evaluate_hang_no_action_within_window() -> TestResult {
        let s = EngineTdrState::new(ResetEngine::Gfx);
        if evaluate_hang(&s, 1000) != ResetAction::NoAction {
            return TestResult::Fail("false-positive hang");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_evaluate_hang_no_action_within_window);

    fn smoke_evaluate_hang_soft_reset_after_tdr() -> TestResult {
        let s = EngineTdrState::new(ResetEngine::Gfx);
        // 15 s elapsed — well past 10 s TDR.
        match evaluate_hang(&s, 15_000) {
            ResetAction::Soft(ResetEngine::Gfx) => {}
            _ => return TestResult::Fail("should escalate to soft"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_evaluate_hang_soft_reset_after_tdr);

    fn smoke_evaluate_hang_escalate_to_baco() -> TestResult {
        let mut s = EngineTdrState::new(ResetEngine::Gfx);
        s.soft_resets_done = 2; // max reached
        match evaluate_hang(&s, 15_000) {
            ResetAction::Baco => {}
            _ => return TestResult::Fail("should escalate to BACO"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_evaluate_hang_escalate_to_baco);

    /// Mock reset MMIO.
    struct MockResetMmio {
        writes: Vec<(u32, u32)>,
    }
    impl ResetMmio for MockResetMmio {
        fn read(&mut self, _off: u32) -> u32 {
            0
        }
        fn write(&mut self, off: u32, val: u32) {
            self.writes.push((off, val));
        }
    }

    /// Bit positions spelled out from `gc_11_0_0_sh_mask.h`, not built from
    /// the module's constants.
    fn smoke_grbm_soft_reset_bit_positions() -> TestResult {
        if GRBM_SOFT_RESET_OFFSET != 0x0DA8 << 2 {
            return TestResult::Fail("regGRBM_SOFT_RESET is dword 0x0da8 at BASE_IDX 0");
        }
        if SOFT_RESET_BIT_CP != 1 || SOFT_RESET_BIT_RLC != 1 << 2 {
            return TestResult::Fail("CP is bit 0 and RLC bit 2");
        }
        // GFX is 16, not 14, and the three CP sub-blocks follow it.
        if SOFT_RESET_BIT_GFX != 1 << 16 {
            return TestResult::Fail("SOFT_RESET_GFX is bit 16");
        }
        if SOFT_RESET_BIT_CPF != 1 << 17
            || SOFT_RESET_BIT_CPC != 1 << 18
            || SOFT_RESET_BIT_CPG != 1 << 19
        {
            return TestResult::Fail("CPF/CPC/CPG are bits 17, 18, 19");
        }
        if SOFT_RESET_BIT_UTCL2 != 1 << 15
            || SOFT_RESET_BIT_CAC != 1 << 20
            || SOFT_RESET_BIT_EA != 1 << 22
        {
            return TestResult::Fail("UTCL2 15, CAC 20, EA 22");
        }
        // Two SDMA engines, two bits, 23 and 24 — bit 1 is undefined here.
        if SOFT_RESET_BIT_SDMA0 != 1 << 23 || SOFT_RESET_BIT_SDMA1 != 1 << 24 {
            return TestResult::Fail("the SDMA engines have separate bits at 23 and 24");
        }
        if soft_reset_bit(ResetEngine::Sdma0) == soft_reset_bit(ResetEngine::Sdma1) {
            return TestResult::Fail("the two SDMAs must not share a reset bit");
        }
        // VCN is not in this register at all.
        if soft_reset_bit(ResetEngine::Vcn).is_some() {
            return TestResult::Fail("GRBM_SOFT_RESET has no VCN bit");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_grbm_soft_reset_bit_positions);

    fn smoke_apply_soft_reset_pulses_bit() -> TestResult {
        let mut m = MockResetMmio { writes: Vec::new() };
        if !apply_soft_reset(&mut m, ResetEngine::Gfx) {
            return TestResult::Fail("GFX reset refused");
        }
        // 2 writes: set-bit, clear-bit.
        if m.writes.len() != 2 {
            return TestResult::Fail("expected 2 writes");
        }
        let bit = soft_reset_bit(ResetEngine::Gfx).expect("gfx has a bit");
        // First write OR'd the bits; second cleared them.
        if m.writes[0].1 & bit != bit {
            return TestResult::Fail("set didn't include every bit");
        }
        if m.writes[1].1 & bit != 0 {
            return TestResult::Fail("clear left bits set");
        }
        // A VCN request touches nothing rather than resetting the CP fetcher.
        let mut m = MockResetMmio { writes: Vec::new() };
        if apply_soft_reset(&mut m, ResetEngine::Vcn) {
            return TestResult::Fail("VCN soft reset must be refused");
        }
        if !m.writes.is_empty() {
            return TestResult::Fail("a refused reset must not write GRBM_SOFT_RESET");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_apply_soft_reset_pulses_bit);

    fn smoke_baco_full_cycle_returns_to_active() -> TestResult {
        let mut b = BacoController::new();
        b.begin_entry().expect("begin");
        // 7 advances to walk through DrainQueues → ... → Active.
        for _ in 0..7 {
            b.advance().expect("advance");
        }
        if b.state != BacoState::Active {
            return TestResult::Fail("not back to Active");
        }
        if b.successes != 1 {
            return TestResult::Fail("success count not bumped");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_baco_full_cycle_returns_to_active);

    fn smoke_baco_rejects_begin_when_not_active() -> TestResult {
        let mut b = BacoController::new();
        b.begin_entry().expect("begin once");
        // Begin again while in DrainQueues — illegal.
        match b.begin_entry() {
            Err(BacoError::IllegalTransition) => {}
            _ => return TestResult::Fail("double-begin not rejected"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_baco_rejects_begin_when_not_active);
}
