//! RCS0 nonprivileged MMIO policy for the physical GuC profiles.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! xe_reg_whitelist.c (sorted oag_mmio_trg_rcs), regs/xe_engine_regs.h,
//! regs/xe_oa_regs.h, and i915 intel_engine_apply_whitelist's unused-slot
//! RING_NOPID fill. This initializes engine policy, not userspace submission
//! or an OA stream; neither is admitted by installing these registers.

use crate::{
    intel_gpu_aux::MmioWindow, intel_gpu_gt::GtPlatform, intel_gpu_gt_registers::RegisterError,
};

const FIRST: u64 = 0x24d0;
const SLOTS: usize = 12;
const NOPID: u32 = 0x2094;
// Address-sorted, as xe_reg_whitelist's xarray traversal: status RD,
// head/tail/buffer/control RD (four registers), MMIO trigger RW.
const ALLOWED: [u32; 3] = [0x1000_dafc, 0x1000_db01, 0x0000_db1c];

#[derive(Copy, Clone, Debug)]
pub(crate) struct RcsPolicy;

impl RcsPolicy {
    /// The enclosing GT has already validated live GMD IP/stepping and PCI
    /// identity. Gen12 execlists, media and future IPs need separate policies.
    pub(crate) fn new(platform: GtPlatform) -> Result<Self, RegisterError> {
        match platform {
            GtPlatform::Alchemist
            | GtPlatform::Battlemage
            | GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake) => Ok(Self),
            _ => Err(RegisterError::Identity),
        }
    }

    /// Engine must be idle and exclusively owned with both forcewake holds.
    /// No new grant is written until every inherited slot is cleared and its
    /// posted readback verified. Any failure blocks engine publication.
    pub(crate) fn install(self, mmio: &impl MmioWindow) -> Result<(), RegisterError> {
        for slot in 0..SLOTS {
            if mmio.read32(register(slot)) == u32::MAX {
                return Err(RegisterError::Unavailable);
            }
        }
        for slot in 0..SLOTS {
            mmio.write32(register(slot), NOPID);
        }
        verify_words(mmio, |_| NOPID)?;
        for (slot, word) in ALLOWED.into_iter().enumerate() {
            mmio.write32(register(slot), word);
        }
        self.verify(mmio)
    }

    /// Validate without repairing a potentially live engine's access policy.
    pub(crate) fn verify(self, mmio: &impl MmioWindow) -> Result<(), RegisterError> {
        verify_words(mmio, |slot| ALLOWED.get(slot).copied().unwrap_or(NOPID))
    }
}

fn register(slot: usize) -> u64 {
    FIRST + slot as u64 * 4
}

fn verify_words(
    mmio: &impl MmioWindow,
    expected: impl Fn(usize) -> u32,
) -> Result<(), RegisterError> {
    for slot in 0..SLOTS {
        let reg = register(slot);
        let value = mmio.read32(reg);
        if value == u32::MAX {
            return Err(RegisterError::Unavailable);
        }
        if value != expected(slot) {
            return Err(RegisterError::Verify(reg));
        }
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Window {
        slots: RefCell<[u32; 12]>,
        writes: RefCell<Vec<(u64, u32)>>,
        unavailable: Cell<Option<usize>>,
        reject: Cell<Option<(usize, bool)>>,
        corrupt_neighbor: Cell<bool>,
    }
    impl Window {
        fn new() -> Self {
            Self {
                slots: RefCell::new([0x2030; 12]),
                writes: RefCell::new(Vec::new()),
                unavailable: Cell::new(None),
                reject: Cell::new(None),
                corrupt_neighbor: Cell::new(false),
            }
        }
        fn slot(reg: u64) -> usize {
            assert!((0x24d0..=0x24fc).contains(&reg) && reg % 4 == 0);
            (reg as usize - 0x24d0) / 4
        }
    }
    impl MmioWindow for Window {
        fn read32(&self, reg: u64) -> u32 {
            let slot = Self::slot(reg);
            if self.unavailable.get() == Some(slot) {
                u32::MAX
            } else {
                self.slots.borrow()[slot]
            }
        }
        fn write32(&self, reg: u64, word: u32) {
            let slot = Self::slot(reg);
            self.writes.borrow_mut().push((reg, word));
            if self.reject.get() == Some((slot, word != 0x2094)) {
                return;
            }
            self.slots.borrow_mut()[slot] = word;
            if self.corrupt_neighbor.get() && word == 0xdb1c {
                self.slots.borrow_mut()[11] = 0x20002030;
            }
        }
    }

    fn smoke_nonpriv_literal_policy_and_inherited_slot_clear() -> TestResult {
        for platform in [
            GtPlatform::Alchemist,
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            GtPlatform::Battlemage,
        ] {
            let w = Window::new();
            let policy = RcsPolicy::new(platform).unwrap();
            policy.install(&w).unwrap();
            assert_eq!(
                *w.slots.borrow(),
                [
                    0x1000dafc, 0x1000db01, 0xdb1c, 0x2094, 0x2094, 0x2094, 0x2094, 0x2094, 0x2094,
                    0x2094, 0x2094, 0x2094
                ]
            );
            let writes = w.writes.borrow();
            assert_eq!(writes.len(), 15);
            for slot in 0..12 {
                assert_eq!(writes[slot], (0x24d0 + slot as u64 * 4, 0x2094));
            }
            assert_eq!(
                &writes[12..],
                &[(0x24d0, 0x1000dafc), (0x24d4, 0x1000db01), (0x24d8, 0xdb1c)]
            );
            policy.verify(&w).unwrap();
        }
        for generation in [
            crate::intel_gpu::Generation::TigerLake,
            crate::intel_gpu::Generation::AlderLake,
            crate::intel_gpu::Generation::PantherLake,
        ] {
            assert!(matches!(
                RcsPolicy::new(GtPlatform::Integrated(generation)),
                Err(RegisterError::Identity)
            ));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_nonpriv",
        smoke_nonpriv_literal_policy_and_inherited_slot_clear
    );

    fn smoke_nonpriv_unavailable_dropped_and_cross_slot_writes() -> TestResult {
        for failure in 0..4 {
            let w = Window::new();
            let expected = match failure {
                0 => {
                    w.unavailable.set(Some(7));
                    RegisterError::Unavailable
                }
                1 => {
                    w.reject.set(Some((11, false)));
                    RegisterError::Verify(0x24fc)
                }
                2 => {
                    w.reject.set(Some((1, true)));
                    RegisterError::Verify(0x24d4)
                }
                _ => {
                    w.corrupt_neighbor.set(true);
                    RegisterError::Verify(0x24fc)
                }
            };
            assert_eq!(
                RcsPolicy::new(GtPlatform::Battlemage).unwrap().install(&w),
                Err(expected)
            );
            if failure == 0 {
                assert!(w.writes.borrow().is_empty());
            }
            if failure <= 1 {
                assert!(
                    w.writes.borrow().iter().all(|(_, word)| *word == 0x2094),
                    "granted access before all inherited slots were cleared"
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_nonpriv",
        smoke_nonpriv_unavailable_dropped_and_cross_slot_writes
    );

    fn smoke_nonpriv_verification_never_repairs_live_policy() -> TestResult {
        let w = Window::new();
        let policy = RcsPolicy::new(GtPlatform::Alchemist).unwrap();
        policy.install(&w).unwrap();
        let expected = *w.slots.borrow();
        let writes = w.writes.borrow().len();
        for (slot, word) in expected.into_iter().enumerate() {
            // Address, range, RD/WR, DENY and reserved bits must all match.
            for bit in [1, 4, 1 << 28, 1 << 29, 1 << 30, 1 << 27] {
                w.slots.borrow_mut()[slot] = word ^ bit;
                assert_eq!(
                    policy.verify(&w),
                    Err(RegisterError::Verify(0x24d0 + slot as u64 * 4))
                );
                assert_eq!(w.writes.borrow().len(), writes);
                w.slots.borrow_mut()[slot] = word;
            }
        }
        w.unavailable.set(Some(11));
        assert_eq!(policy.verify(&w), Err(RegisterError::Unavailable));
        assert_eq!(w.writes.borrow().len(), writes);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_nonpriv",
        smoke_nonpriv_verification_never_repairs_live_policy
    );
}
