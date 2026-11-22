//! Display-11 (Ice Lake / Elkhart Lake / Jasper Lake) DC
//! states: the DC-state mask, the allowed mask and the
//! target, plus the small state machine that programs them.
//!
//! This is deliberately not the display-14 module
//! (`intel_gpu_dc_states`): that module's mask
//! (DC5 | DC6 | DC9 | DC3CO) is the display >= 12 mask, and
//! its service — the `DC_off` well, the DMC program lifecycle,
//! the pipe DMC, the deferred re-entry task — is display-14
//! machinery. Display 11 has its own mask, derived below
//! from the same Linux sources, and this module is only the
//! mask + target + sticky-write core. Production wiring (who
//! takes `DC_off` references, when the target is armed) belongs
//! to the modeset that owns the display; the DMC program load
//! it depends on is Lane 5's DMC work.
//!
//! ## Derivation (Linux 7.4-rc2, commit 7475ea8b)
//!
//! - `display/intel_display_power_well.c::gen9_dc_mask`:
//!   the base is `DC_STATE_EN_UPTO_DC5`; `DISPLAY_VER == 11`
//!   adds `DC_STATE_EN_UPTO_DC6 | DC_STATE_EN_DC9`. So the
//!   display-11 mask is UPTO_DC5 | UPTO_DC6 | DC9 = 0xB.
//!   (The grounding's recollection — "DC5|DC6 only" — is
//!   wrong: DC9 is in the mask. DC3CO is not: that bit joins
//!   only at `DISPLAY_VER >= 12`.)
//! - `display/intel_display_power.c::get_allowed_dc_mask`:
//!   display 11 takes `max_dc = 2` (the `DISPLAY_VER >= 9`
//!   arm); the mask starts with `DC_STATE_EN_DC9`
//!   (`DISPLAY_VER >= 11`), and `requested_dc = max_dc = 2`
//!   adds `DC_STATE_EN_UPTO_DC6`. So the allowed mask is
//!   DC9 | UPTO_DC6 = 0xA, and the sanitized target
//!   (`sanitize_target_dc_state(display, UPTO_DC6)`) is DC6.
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
//! (`assert_can_enable_dc6`): on Gen11 that is the ICL DMC
//! (`icl_dmc_ver1_09`), loaded by the modeset's DMC step.
//! This module programs the target; the caller arms it only
//! with a loaded program. DC9 is in the mask for tracking
//! (Linux targets it from the suspend path) but is never
//! this module's target — the target is always DC6 (or the
//! `sanitize_target` fallback when the allowed mask does not
//! admit it).

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_dc_states::{
    sanitize_target, write_dc_state_sticky, DcError, DC_STATE_DISABLE, DC_STATE_EN_DC9,
    DC_STATE_EN_UPTO_DC5, DC_STATE_EN_UPTO_DC5_DC6_MASK, DC_STATE_EN_UPTO_DC6,
};
use crate::intel_gpu_dmc::DC_STATE_EN;

/// `gen9_dc_mask` for `DISPLAY_VER == 11`:
/// UPTO_DC5 | UPTO_DC6 | DC9.
pub const GEN11_DC_MASK: u32 = DC_STATE_EN_UPTO_DC5 | DC_STATE_EN_UPTO_DC6 | DC_STATE_EN_DC9;
/// `get_allowed_dc_mask` for display 11 (`max_dc = 2`):
/// DC9 | UPTO_DC6.
pub const GEN11_ALLOWED_DC_MASK: u32 = DC_STATE_EN_DC9 | DC_STATE_EN_UPTO_DC6;
/// The sanitized target on display 11: DC6.
pub const GEN11_DC_TARGET: u32 = DC_STATE_EN_UPTO_DC6;

/// The display-11 DC-state core: the tracked
/// `DC_STATE_EN & GEN11_DC_MASK` field, the sanitized target,
/// and the latched write failure, if any.
#[derive(Clone, Copy, Debug)]
pub struct Gen11Dc {
    tracked: u32,
    target: u32,
    fault: Option<DcError>,
    mismatches: u32,
}

impl Gen11Dc {
    /// A display-11 core with nothing tracked and the target
    /// sanitized against the derived allowed mask (DC6).
    pub fn new() -> Self {
        Self {
            tracked: 0,
            target: sanitize_target(GEN11_ALLOWED_DC_MASK, GEN11_DC_TARGET),
            fault: None,
            mismatches: 0,
        }
    }

    /// The derived allowed mask.
    pub fn allowed() -> u32 {
        GEN11_ALLOWED_DC_MASK
    }

    /// The tracked `DC_STATE_EN & GEN11_DC_MASK`.
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
    /// masked by the display-11 mask. Bits outside the mask
    /// (notably DC3CO) are dropped from tracking.
    pub fn sanitize<M: MmioWindow + ?Sized>(&mut self, regs: &M) -> Result<(), DcError> {
        let value = regs.read32(DC_STATE_EN);
        if value == u32::MAX {
            return Err(DcError::Unavailable);
        }
        self.tracked = value & GEN11_DC_MASK;
        Ok(())
    }

    /// `gen9_set_dc_state` for display 11: the state is
    /// masked by the allowed mask and written with the
    /// sticky-write discipline. A write that does not stick
    /// latches the fault and the found value.
    pub fn set_dc_state<M: MmioWindow + ?Sized>(
        &mut self,
        regs: &M,
        state: u32,
    ) -> Result<(), DcError> {
        let state = state & GEN11_ALLOWED_DC_MASK;
        let value = regs.read32(DC_STATE_EN);
        if value == u32::MAX {
            return Err(DcError::Unavailable);
        }
        if value & GEN11_DC_MASK != self.tracked {
            self.mismatches = self.mismatches.saturating_add(1);
        }
        let wanted = (value & !GEN11_DC_MASK) | state;
        if let Err(found) = write_dc_state_sticky(regs, wanted) {
            let error = DcError::DidNotStick { wanted, found };
            self.fault = Some(error);
            self.tracked = found & GEN11_DC_MASK;
            return Err(error);
        }
        self.tracked = wanted & GEN11_DC_MASK;
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

impl Default for Gen11Dc {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Fixtures for the display-11 DC mask and target. The
    //! fake is a plain register file (plus a deaf variant
    //! whose writes never stick). Expected values are
    //! hand-derived from `gen9_dc_mask` /
    //! `get_allowed_dc_mask` — never recorded from the
    //! implementation under test.

    use super::*;
    use crate::intel_gpu_dc_states::DC_STATE_EN_DC3CO;
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

    fn smoke_gen11_dc_mask_derivation() -> TestResult {
        // gen9_dc_mask, DISPLAY_VER == 11: the base UPTO_DC5
        // plus UPTO_DC6 | DC9 — and NOT DC3CO, which joins
        // only at DISPLAY_VER >= 12.
        if GEN11_DC_MASK != DC_STATE_EN_UPTO_DC5 | DC_STATE_EN_UPTO_DC6 | DC_STATE_EN_DC9 {
            return TestResult::Fail("Gen11 DC mask must be UPTO_DC5 | UPTO_DC6 | DC9");
        }
        if GEN11_DC_MASK != 0xB {
            return TestResult::Fail("Gen11 DC mask must be 0xB");
        }
        if GEN11_DC_MASK & DC_STATE_EN_DC3CO != 0 {
            return TestResult::Fail("DC3CO must not be in the display-11 mask");
        }
        // get_allowed_dc_mask, display 11 (max_dc 2): DC9 |
        // UPTO_DC6. The grounding's "DC5|DC6 only"
        // recollection is wrong — DC9 is allowed.
        if GEN11_ALLOWED_DC_MASK != DC_STATE_EN_DC9 | DC_STATE_EN_UPTO_DC6 {
            return TestResult::Fail("Gen11 allowed mask must be DC9 | UPTO_DC6");
        }
        if GEN11_ALLOWED_DC_MASK != 0xA {
            return TestResult::Fail("Gen11 allowed mask must be 0xA");
        }
        // The sanitized target is DC6, and it differs from
        // the display-14 allowed mask (DC6 only there).
        if GEN11_DC_TARGET != DC_STATE_EN_UPTO_DC6 || Gen11Dc::new().target() != 0x2 {
            return TestResult::Fail("Gen11 DC target must be UPTO_DC6");
        }
        if crate::intel_gpu_dc_states::XELPDP_ALLOWED_DC_MASK != DC_STATE_EN_UPTO_DC6 {
            return TestResult::Fail("display-14 allowed-mask pin moved");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dc_states",
        smoke_gen11_dc_mask_derivation
    );

    fn smoke_sanitize_adopts_masked_field() -> TestResult {
        let fake = FakeDc::new();
        let mut dc = Gen11Dc::new();
        // All-ones: the function is not in D0.
        fake.set(DC_STATE_EN, u32::MAX);
        if dc.sanitize(&fake) != Err(DcError::Unavailable) {
            return TestResult::Fail("sanitize must refuse an all-ones DC_STATE_EN");
        }
        // A DC3CO bit in the hardware field is outside the
        // display-11 mask and must not enter tracking.
        fake.set(DC_STATE_EN, DC_STATE_EN_DC3CO | DC_STATE_EN_UPTO_DC6);
        if dc.sanitize(&fake).is_err() || dc.tracked() != DC_STATE_EN_UPTO_DC6 {
            return TestResult::Fail("sanitize must adopt the field masked by GEN11_DC_MASK");
        }
        // A DC9 bit is inside the mask and is tracked.
        fake.set(DC_STATE_EN, DC_STATE_EN_DC9 | DC_STATE_EN_UPTO_DC5);
        if dc.sanitize(&fake).is_err() || dc.tracked() != DC_STATE_EN_DC9 | DC_STATE_EN_UPTO_DC5 {
            return TestResult::Fail("sanitize must track DC9 inside the mask");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dc_states",
        smoke_sanitize_adopts_masked_field
    );

    fn smoke_set_target_and_disable() -> TestResult {
        let fake = FakeDc::new();
        let mut dc = Gen11Dc::new();
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
        "drivers/gpu/intel_gpu_gen11_dc_states",
        smoke_set_target_and_disable
    );

    fn smoke_set_dc_state_masks_by_allowed() -> TestResult {
        let fake = FakeDc::new();
        let mut dc = Gen11Dc::new();
        // DC9 is an allowed state: Linux targets it from the
        // suspend path, so programming it sticks.
        if dc.set_dc_state(&fake, DC_STATE_EN_DC9).is_err()
            || fake.read32(DC_STATE_EN) != DC_STATE_EN_DC9
        {
            return TestResult::Fail("DC9 is allowed and must program");
        }
        // DC3CO is outside the allowed mask: the write is
        // stripped to disabled, not programmed.
        if dc.set_dc_state(&fake, DC_STATE_EN_DC3CO).is_err() || fake.read32(DC_STATE_EN) != 0 {
            return TestResult::Fail("DC3CO must be stripped by the allowed mask");
        }
        // A stale tracked value is counted, not trusted.
        fake.set(DC_STATE_EN, DC_STATE_EN_UPTO_DC5);
        if dc.set_dc_state(&fake, DC_STATE_EN_UPTO_DC6).is_err() || dc.mismatches() != 1 {
            return TestResult::Fail("a hardware/tracked disagreement must be counted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dc_states",
        smoke_set_dc_state_masks_by_allowed
    );

    fn smoke_write_failure_latches_fault() -> TestResult {
        let fake = FakeDc::deaf();
        let mut dc = Gen11Dc::new();
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
        "drivers/gpu/intel_gpu_gen11_dc_states",
        smoke_write_failure_latches_fault
    );
}
