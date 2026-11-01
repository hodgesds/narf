//! RCS0/BCS0 nonprivileged MMIO policy for the physical GuC profiles.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! xe_reg_whitelist.c (sorted oag_mmio_trg_rcs), regs/xe_engine_regs.h,
//! regs/xe_oa_regs.h, and i915 intel_engine_apply_whitelist's unused-slot
//! RING_NOPID fill. This initializes engine policy, not userspace submission
//! or an OA stream; neither is admitted by installing these registers.
//! BCS0 has no whitelist entry on these profiles (only PVC/MERT copy
//! engines do), so every inherited BCS0 slot is cleared to its own NOPID.

use crate::{
    intel_gpu_aux::MmioWindow, intel_gpu_gt::GtPlatform, intel_gpu_gt_registers::RegisterError,
};

const SLOTS: usize = 12;
// Address-sorted, as xe_reg_whitelist's xarray traversal: status RD,
// head/tail/buffer/control RD (four registers), MMIO trigger RW.
const ALLOWED: [u32; 3] = [0x1000_dafc, 0x1000_db01, 0x0000_db1c];

/// RING_FORCE_TO_NONPRIV(base, n) = base + 0x4d0 + 4n; RING_NOPID = base + 0x94.
#[derive(Copy, Clone, Debug)]
struct Slots {
    base: u32,
    allowed: &'static [u32],
}

impl Slots {
    fn register(self, slot: usize) -> u64 {
        u64::from(self.base) + 0x4d0 + slot as u64 * 4
    }
    fn nopid(self) -> u32 {
        self.base + 0x94
    }
    fn expected(self, slot: usize) -> u32 {
        self.allowed.get(slot).copied().unwrap_or(self.nopid())
    }
}

const RCS: Slots = Slots {
    base: 0x2000,
    allowed: &ALLOWED,
};
const BCS: Slots = Slots {
    base: 0x22000,
    allowed: &[],
};
/// xe_reg_whitelist.c oag_mmio_trg_ccs: the same OAG grants as RCS0.
const CCS: Slots = Slots {
    base: 0x1a000,
    allowed: &ALLOWED,
};

#[derive(Copy, Clone, Debug)]
pub(crate) struct EnginePolicy {
    compute: bool,
}

impl EnginePolicy {
    /// The enclosing GT has already validated live GMD IP/stepping and PCI
    /// identity. Gen12 execlists, media and future IPs need separate policies.
    pub(crate) fn new(
        platform: GtPlatform,
        engines: crate::intel_gpu_engine::EngineSet,
    ) -> Result<Self, RegisterError> {
        match platform {
            GtPlatform::Alchemist
            | GtPlatform::Battlemage
            | GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake) => Ok(Self {
                compute: engines.contains(crate::intel_gpu_engine::Engine::Ccs0),
            }),
            _ => Err(RegisterError::Identity),
        }
    }

    fn banks(self) -> impl Iterator<Item = Slots> {
        [Some(RCS), Some(BCS), self.compute.then_some(CCS)]
            .into_iter()
            .flatten()
    }

    /// Engine must be idle and exclusively owned with both forcewake holds.
    /// No new grant is written until every inherited slot is cleared and its
    /// posted readback verified. Any failure blocks engine publication.
    pub(crate) fn install(self, mmio: &impl MmioWindow) -> Result<(), RegisterError> {
        for slots in self.banks() {
            for slot in 0..SLOTS {
                if mmio.read32(slots.register(slot)) == u32::MAX {
                    return Err(RegisterError::Unavailable);
                }
            }
        }
        for slots in self.banks() {
            for slot in 0..SLOTS {
                mmio.write32(slots.register(slot), slots.nopid());
            }
        }
        for slots in self.banks() {
            verify_words(mmio, slots, |_| slots.nopid())?;
        }
        for slots in self.banks() {
            for (slot, word) in slots.allowed.iter().enumerate() {
                mmio.write32(slots.register(slot), *word);
            }
        }
        self.verify(mmio)
    }

    /// Validate without repairing a potentially live engine's access policy.
    pub(crate) fn verify(self, mmio: &impl MmioWindow) -> Result<(), RegisterError> {
        for slots in self.banks() {
            verify_words(mmio, slots, |slot| slots.expected(slot))?;
        }
        Ok(())
    }
}

fn verify_words(
    mmio: &impl MmioWindow,
    slots: Slots,
    expected: impl Fn(usize) -> u32,
) -> Result<(), RegisterError> {
    for slot in 0..SLOTS {
        let reg = slots.register(slot);
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

    fn rcs_bcs() -> crate::intel_gpu_engine::EngineSet {
        use crate::intel_gpu_engine::{Engine, EngineSet};
        EngineSet::of(&[Engine::Rcs0, Engine::Bcs0])
    }

    struct Window {
        slots: RefCell<[u32; 36]>,
        writes: RefCell<Vec<(u64, u32)>>,
        unavailable: Cell<Option<usize>>,
        reject: Cell<Option<(usize, bool)>>,
        corrupt_neighbor: Cell<bool>,
    }
    impl Window {
        fn new() -> Self {
            Self {
                slots: RefCell::new([0x2030; 36]),
                writes: RefCell::new(Vec::new()),
                unavailable: Cell::new(None),
                reject: Cell::new(None),
                corrupt_neighbor: Cell::new(false),
            }
        }
        fn slot(reg: u64) -> usize {
            assert_eq!(reg % 4, 0);
            match reg {
                0x24d0..=0x24fc => (reg as usize - 0x24d0) / 4,
                0x224d0..=0x224fc => 12 + (reg as usize - 0x224d0) / 4,
                0x1a4d0..=0x1a4fc => 24 + (reg as usize - 0x1a4d0) / 4,
                _ => panic!("unexpected NONPRIV register {reg:x}"),
            }
        }
        fn nopid(slot: usize) -> u32 {
            match slot {
                0..12 => 0x2094,
                12..24 => 0x22094,
                _ => 0x1a094,
            }
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
            if self.reject.get() == Some((slot, word != Self::nopid(slot))) {
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
            let policy = EnginePolicy::new(platform, rcs_bcs()).unwrap();
            policy.install(&w).unwrap();
            assert_eq!(
                w.slots.borrow()[..12],
                [
                    0x1000dafc, 0x1000db01, 0xdb1c, 0x2094, 0x2094, 0x2094, 0x2094, 0x2094, 0x2094,
                    0x2094, 0x2094, 0x2094
                ]
            );
            assert!(w.slots.borrow()[12..24].iter().all(|word| *word == 0x22094));
            assert!(w.slots.borrow()[24..].iter().all(|word| *word == 0x2030));
            let writes = w.writes.borrow();
            assert_eq!(writes.len(), 27);
            for slot in 0..12 {
                assert_eq!(writes[slot], (0x24d0 + slot as u64 * 4, 0x2094));
                assert_eq!(writes[12 + slot], (0x224d0 + slot as u64 * 4, 0x22094));
            }
            assert_eq!(
                &writes[24..],
                &[(0x24d0, 0x1000dafc), (0x24d4, 0x1000db01), (0x24d8, 0xdb1c)]
            );
            policy.verify(&w).unwrap();
        }
        // With CCS0 present, its bank receives the RCS OAG grants as well.
        let w = Window::new();
        let policy = EnginePolicy::new(
            GtPlatform::Battlemage,
            crate::intel_gpu_engine::EngineSet::of(&[
                crate::intel_gpu_engine::Engine::Rcs0,
                crate::intel_gpu_engine::Engine::Bcs0,
                crate::intel_gpu_engine::Engine::Ccs0,
            ]),
        )
        .unwrap();
        policy.install(&w).unwrap();
        assert_eq!(w.slots.borrow()[24..27], [0x1000dafc, 0x1000db01, 0xdb1c]);
        assert!(w.slots.borrow()[27..].iter().all(|word| *word == 0x1a094));
        policy.verify(&w).unwrap();
        for generation in [
            crate::intel_gpu::Generation::TigerLake,
            crate::intel_gpu::Generation::AlderLake,
            crate::intel_gpu::Generation::PantherLake,
        ] {
            assert!(matches!(
                EnginePolicy::new(GtPlatform::Integrated(generation), rcs_bcs()),
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
        for failure in 0..6 {
            let w = Window::new();
            let expected = match failure {
                4 => {
                    w.unavailable.set(Some(15));
                    RegisterError::Unavailable
                }
                5 => {
                    w.reject.set(Some((17, false)));
                    RegisterError::Verify(0x224e4)
                }
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
                EnginePolicy::new(GtPlatform::Battlemage, rcs_bcs())
                    .unwrap()
                    .install(&w),
                Err(expected)
            );
            if failure == 0 || failure == 4 {
                assert!(w.writes.borrow().is_empty());
            }
            if failure <= 1 || failure >= 4 {
                assert!(
                    w.writes
                        .borrow()
                        .iter()
                        .all(|(reg, word)| *word == Window::nopid(Window::slot(*reg))),
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
        let policy = EnginePolicy::new(GtPlatform::Alchemist, rcs_bcs()).unwrap();
        policy.install(&w).unwrap();
        let expected = *w.slots.borrow();
        let writes = w.writes.borrow().len();
        for (slot, word) in expected.into_iter().enumerate() {
            // Address, range, RD/WR, DENY and reserved bits must all match.
            for bit in [1, 4, 1 << 28, 1 << 29, 1 << 30, 1 << 27] {
                w.slots.borrow_mut()[slot] = word ^ bit;
                if slot >= 24 {
                    continue; // no CCS bank in this policy
                }
                let reg = if slot < 12 {
                    0x24d0 + slot as u64 * 4
                } else {
                    0x224d0 + (slot as u64 - 12) * 4
                };
                assert_eq!(policy.verify(&w), Err(RegisterError::Verify(reg)));
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
