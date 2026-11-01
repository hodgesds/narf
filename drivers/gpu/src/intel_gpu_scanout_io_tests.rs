// Independent native conversations using the production PollIo adapter.
// MIT Linux b90c984d: intel_display_regs.h source offsets/bits and
// gen8_de_irq_postinstall IER latching vs IMR delivery separation.
use super::*;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

const FOREIGN_IIR: u32 = (1 << 0) | (1 << 6);
const LAST_PTE: u64 = GGTT_ARRAY_BASE + (GEM_SCANOUT_GTT_END / 4096 - 1) * 8;

#[derive(Default)]
struct Hardware {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    authorized: bool,
    powered: bool,
    dropped_write: Option<u64>,
    queued_flip: bool,
    deliveries: u32,
}
#[derive(Clone)]
struct Access(Rc<RefCell<Hardware>>);
impl Access {
    fn new() -> Self {
        let mut state = Hardware {
            authorized: true,
            powered: true,
            ..Hardware::default()
        };
        state.regs.insert(Pipe::A.base() + 0x40, 100);
        state.regs.insert(0x44404, u32::MAX);
        state.regs.insert(0x44408, FOREIGN_IIR);
        state.regs.insert(0x4440c, 1); // Foreign vblank source.
        Self(Rc::new(RefCell::new(state)))
    }
    fn emit(&self, bit: u32) {
        let mut state = self.0.borrow_mut();
        let ier = state.regs[&0x4440c];
        let imr = state.regs[&0x44404];
        // IER controls latching; IMR controls delivery, independently.
        if ier & bit != 0 {
            *state.regs.entry(0x44408).or_default() |= bit;
            if imr & bit == 0 {
                state.deliveries += 1;
            }
        }
    }
}
impl MmioWindow for Access {
    fn read32(&self, offset: u64) -> u32 {
        let state = self.0.borrow();
        if !state.authorized || !state.powered {
            return u32::MAX;
        }
        *state.regs.get(&offset).unwrap_or(&0)
    }
    fn write32(&self, offset: u64, value: u32) {
        let mut state = self.0.borrow_mut();
        if !state.authorized || !state.powered {
            return;
        }
        state.writes.push((offset, value));
        if state.dropped_write == Some(offset) {
            return;
        }
        if offset == 0x44408 {
            *state.regs.entry(offset).or_default() &= !value;
            if state.queued_flip {
                *state.regs.entry(offset).or_default() |= 1 << 3;
                state.queued_flip = false;
            }
        } else {
            state.regs.insert(offset, value);
        }
    }
}
// SAFETY: native model revokes all access on either authority or power loss;
// each test owns its complete emulated register bank and has no DMA clients.
unsafe impl DisplayAccess for Access {
    fn access_ok(&self) -> bool {
        let state = self.0.borrow();
        state.authorized && state.powered
    }
}
fn adapter(access: Access, generation: Generation) -> PollIo<Access> {
    // SAFETY: isolated native bank; no GT users, UC posting semantics and no
    // other display client. The source profile's pipe A is powered/running.
    unsafe { PollIo::new(access, generation, Pipe::A, 0x1000000) }.unwrap()
}

fn smoke_scanout_io_profile_latching_and_masked_delivery() -> TestResult {
    for generation in [
        Generation::TigerLake,
        Generation::AlderLake,
        Generation::MeteorLake,
    ] {
        let access = Access::new();
        access.emit(1 << 3);
        assert_eq!(
            access.read32(0x44408),
            FOREIGN_IIR,
            "IER=0 cannot latch flipdone"
        );
        // Two preexisting flip indications require the source's two W1Cs.
        {
            let mut hw = access.0.borrow_mut();
            hw.regs.insert(0x44408, FOREIGN_IIR | (1 << 3));
            hw.queued_flip = true;
        }
        let io = adapter(access.clone(), generation);
        let expected = if generation == Generation::MeteorLake {
            (1 << 3) | (1 << 7) | (1 << 18) | (1 << 24) | (1 << 25) | (1 << 31)
        } else {
            (1 << 3) | (1 << 7) | (1 << 25) | (1 << 31)
        };
        assert_eq!(access.read32(0x4440c), 1 | expected);
        assert_eq!(access.read32(0x44404), u32::MAX);
        assert_eq!(io.read32(0x44408), FOREIGN_IIR);
        access.emit(1 << 3);
        assert_eq!(io.read32(0x44408), FOREIGN_IIR | (1 << 3));
        assert_eq!(
            access.0.borrow().deliveries,
            0,
            "poll-only status delivered IRQ"
        );
        io.write32(0x44408, 1 << 3);
        assert_eq!(io.read32(0x44408), FOREIGN_IIR);
        access.emit(1 << 7);
        assert_eq!(
            io.read32(0x44408) & (1 << 7),
            1 << 7,
            "fault source lacked IER"
        );
        // SAFETY: the native model never installed a mapping or armed a fetch.
        assert!(unsafe { io.restore_stopped() });
        assert_eq!(access.read32(0x4440c), 1);
        assert_eq!(access.read32(0x44404), u32::MAX);
        assert_eq!(access.read32(0x44408) & FOREIGN_IIR, FOREIGN_IIR);
        assert_eq!(
            io.format(),
            if generation == Generation::MeteorLake {
                PteFormat::XeLpg
            } else {
                PteFormat::Gen12
            }
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout_io",
    smoke_scanout_io_profile_latching_and_masked_delivery
);

fn smoke_scanout_io_refuses_unsupported_conflicting_and_faulted_owners() -> TestResult {
    for case in 0..6 {
        let access = Access::new();
        let (generation, pipe, len) = match case {
            0 => (Generation::PantherLake, Pipe::A, 0x1000000),
            1 => (Generation::TigerLake, Pipe::B, 0x1000000),
            2 => (Generation::TigerLake, Pipe::A, 0x800000),
            3 => {
                let mut hw = access.0.borrow_mut();
                hw.regs.insert(0x4440c, 1 << 3);
                hw.regs.insert(0x44404, !(1 << 3));
                (Generation::TigerLake, Pipe::A, 0x1000000)
            }
            4 => {
                access.0.borrow_mut().regs.insert(0x44408, 1 << 7);
                (Generation::TigerLake, Pipe::A, 0x1000000)
            }
            _ => {
                access.0.borrow_mut().powered = false;
                (Generation::MeteorLake, Pipe::A, 0x1000000)
            }
        };
        // SAFETY: only qualification/ownership is intentionally varied; the
        // fixture owns this isolated bank and no existing DMA addresses.
        let result = unsafe { PollIo::new(access.clone(), generation, pipe, len) };
        assert!(result.is_err());
        assert!(
            access.0.borrow().writes.is_empty(),
            "refused owner changed hardware"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout_io",
    smoke_scanout_io_refuses_unsupported_conflicting_and_faulted_owners
);

fn smoke_scanout_io_posts_clear_and_install_without_gt_register_writes() -> TestResult {
    let access = Access::new();
    let io = adapter(access.clone(), Generation::MeteorLake);
    let before = access.0.borrow().writes.len();
    for (offset, value) in [
        (LAST_PTE, 0x12345001),
        (LAST_PTE + 4, 0x10),
        (LAST_PTE, 0),
        (LAST_PTE + 4, 0),
    ] {
        io.write32(offset, value);
        assert!(io.invalidate_ggtt());
        assert_eq!(access.read32(offset), value);
    }
    // This display-only UC mapping has no GuC/engine translation-cache user.
    // Source gen8_ggtt_invalidate skips GFX_FLSH_CNTL on these generations.
    assert!(access.0.borrow().writes[before..]
        .iter()
        .all(|(reg, _)| *reg >= 0x800000));
    access.0.borrow_mut().dropped_write = Some(LAST_PTE);
    io.write32(LAST_PTE, 0x43210001);
    assert!(
        !io.invalidate_ggtt(),
        "unposted PTE accepted as invalidated"
    );
    assert_eq!(io.read32(0x44408), u32::MAX);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout_io",
    smoke_scanout_io_posts_clear_and_install_without_gt_register_writes
);

fn smoke_scanout_io_revocation_power_loss_and_stolen_delivery_fail_closed() -> TestResult {
    for case in 0..5 {
        let access = Access::new();
        let io = adapter(access.clone(), Generation::TigerLake);
        let writes = access.0.borrow().writes.len();
        match case {
            0 => access.0.borrow_mut().authorized = false,
            1 => access.0.borrow_mut().powered = false,
            2 => {
                access.0.borrow_mut().regs.insert(0x44404, !(1 << 3));
            }
            3 => io.write32(0x44404, 0), // Clients cannot unmask delivery.
            _ => io.write32(0x800000, 1), // Nor touch another GGTT arena.
        }
        assert_eq!(io.read32(0x44408), u32::MAX);
        assert!(!io.invalidate_ggtt());
        io.write32(LAST_PTE, 1);
        // SAFETY: no native mapping/fetch ever existed; restoration must still
        // refuse revoked/stolen authority rather than touch a newer owner.
        assert!(!unsafe { io.restore_stopped() });
        drop(io);
        assert_eq!(access.0.borrow().writes.len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout_io",
    smoke_scanout_io_revocation_power_loss_and_stolen_delivery_fail_closed
);

fn smoke_scanout_io_restores_owned_bits_and_preserves_new_foreign_changes() -> TestResult {
    let access = Access::new();
    // Source initially disabled, delivery unmasked: construction masks before
    // enabling IER, restoration must disable IER before unmasking delivery.
    access.0.borrow_mut().regs.insert(0x44404, !(1 << 3));
    let io = adapter(access.clone(), Generation::TigerLake);
    {
        let mut hw = access.0.borrow_mut();
        *hw.regs.get_mut(&0x4440c).unwrap() |= 1 << 10;
        *hw.regs.get_mut(&0x44404).unwrap() &= !(1 << 5);
    }
    let before = access.0.borrow().writes.len();
    // SAFETY: no owned mapping or fetch was created in this native model.
    assert!(unsafe { io.restore_stopped() });
    assert_eq!(access.read32(0x4440c), 1 | (1 << 10));
    assert_eq!(access.read32(0x44404), !(1 << 3) & !(1 << 5));
    assert_eq!(access.read32(0x44408), FOREIGN_IIR);
    assert_eq!(
        access.0.borrow().writes[before..],
        [
            (0x4440c, 1 | (1 << 10)),
            (0x44408, 1 << 3),
            (0x44408, 1 << 3),
            (0x44404, !(1 << 3) & !(1 << 5)),
        ]
    );
    // A restored adapter cannot be reused to create a new mapping or flip.
    let writes = access.0.borrow().writes.len();
    io.write32(LAST_PTE, 1);
    assert_eq!(access.0.borrow().writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_scanout_io",
    smoke_scanout_io_restores_owned_bits_and_preserves_new_foreign_changes
);
