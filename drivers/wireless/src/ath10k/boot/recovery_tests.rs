use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

type Trace = Rc<RefCell<Vec<(u64, u32)>>>;
#[derive(Default)]
struct Io {
    values: BTreeMap<u64, u32>,
    writes: Trace,
}
impl Ath10kMmio for Io {
    fn read32(&mut self, offset: u64) -> u32 {
        self.values.get(&offset).copied().unwrap_or(0)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.values.insert(offset, value);
        self.writes.borrow_mut().push((offset, value));
    }
}
fn ready(base: u64, count: u8) -> Io {
    let mut io = Io::default();
    for pipe in 0..count {
        io.values.insert(base + u64::from(pipe) * 0x400 + 0x18, 8);
    }
    io
}
const MASTER_DISABLED: u64 = u64::MAX;

fn smoke_ath10k_recovery_masks_all_engines_before_master_disable() -> TestResult {
    // Authored PCI-family register maps, Linux ath10k/hw.c and ce.c.
    for (hardware, core, base, count) in [
        (HwRev::Qca988x, 0x9000, 0x57400, 8),
        (HwRev::Qca6174, 0x3a000, 0x34400, 8),
        (HwRev::Qca9377, 0x3a000, 0x34400, 8),
        (HwRev::Qca99x0, 0x82000, 0x4a000, 12),
        (HwRev::Qca9888, 0x82000, 0x4a000, 12),
        (HwRev::Qca9984, 0x82000, 0x4a000, 12),
    ] {
        let mut io = ready(base, count);
        let trace = io.writes.clone();
        if park(&mut io, hardware, || {
            trace.borrow_mut().push((MASTER_DISABLED, 0));
            Ok(())
        })
        .is_err()
        {
            return TestResult::Fail("recovery rejected halted native CE family");
        }
        let mut expected = vec![(core + 8, 0)];
        for pipe in 0..count {
            let at = base + u64::from(pipe) * 0x400;
            expected.extend_from_slice(&[(at + 0x2c, 0), (at + 0x34, 0), (at + 0x18, 9)]);
        }
        expected.push((MASTER_DISABLED, 0));
        if *trace.borrow() != expected {
            return TestResult::Fail(
                "CE retirement missed an engine, reordered master disable or reset CPU",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_masks_all_engines_before_master_disable
);

fn smoke_ath10k_recovery_halt_failure_still_disables_master_and_closes_other_engines() -> TestResult
{
    let mut io = ready(0x4a000, 12);
    io.values.insert(0x4a018, u32::MAX);
    let trace = io.writes.clone();
    let result = park(&mut io, HwRev::Qca9984, || {
        trace.borrow_mut().push((MASTER_DISABLED, 0));
        Ok(())
    });
    if result != Err(BmiError::Timeout)
        || trace.borrow().last() != Some(&(MASTER_DISABLED, 0))
        || !trace.borrow().contains(&(0x4cc18, 9))
    {
        return TestResult::Fail(
            "failed first CE bypassed remaining retirement or allowed restart",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_halt_failure_still_disables_master_and_closes_other_engines
);

fn smoke_ath10k_recovery_master_error_and_unsupported_hardware_cannot_restart() -> TestResult {
    let mut io = ready(0x34400, 8);
    if park(&mut io, HwRev::Qca6174, || Err(BmiError::Pci)) != Err(BmiError::Pci) {
        return TestResult::Fail("unconfirmed bus-master disable authorized restart");
    }
    io.writes.borrow_mut().clear();
    if park(&mut io, HwRev::Ar9462Legacy, || {
        panic!("legacy master access")
    }) != Err(BmiError::Unsupported)
        || !io.writes.borrow().is_empty()
    {
        return TestResult::Fail("unsupported legacy hardware received recovery writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_master_error_and_unsupported_hardware_cannot_restart
);

fn smoke_ath10k_recovery_real_cap_revocation_before_and_after_master_disable() -> TestResult {
    for during in [false, true] {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        let revoke = cap.derive::<Write>().unwrap();
        let mut mmio = Mmio {
            cap,
            io: ready(0x34400, 8),
            sources: None,
        };
        let mut revoke = Some(revoke);
        if !during {
            revoke.take().unwrap().revoke();
        }
        let trace = mmio.io.writes.clone();
        if park(&mut mmio, HwRev::Qca6174, || {
            trace.borrow_mut().push((MASTER_DISABLED, 0));
            revoke.take().unwrap().revoke();
            Ok(())
        }) != Err(BmiError::Pci)
            || (!during && !trace.borrow().is_empty())
            || (during && trace.borrow().last() != Some(&(MASTER_DISABLED, 0)))
        {
            return TestResult::Fail("revoked real PCI authority escaped recovery boundary");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_real_cap_revocation_before_and_after_master_disable
);

fn smoke_ath10k_recovery_retired_physical_drop_preserves_successor_and_pins_dma() -> TestResult {
    let hardware = HwRev::Qca6174;
    let registers = hardware.registers().unwrap();
    let mut words = vec![0u32; 0x100000 / 4];
    for pipe in 0..8 {
        words[(0x34418 + pipe * 0x400) / 4] = 8;
    }
    // This is a deliberately non-PCI config fixture: the native retirement
    // must fail master disable yet keep its terminal state/Drop contract.
    let base = narf_memory::PhysAddr::new(0);
    let device = BusDevice {
        addr: narf_bus::BusAddr::Mmio(base),
        id: narf_bus::DeviceId {
            vendor: 0x168c,
            device: 0x003e,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: narf_bus::BusKind::VirtioMmio {
            base,
            len: 0x1000,
            device_id: 1,
        },
    };
    let resources = Resources::allocate(hardware).unwrap();
    let old_addresses = [
        resources.request.dma_address(),
        resources.response.dma_address(),
        resources.diag.dma_address(),
    ];
    let mut owner = PciBoot {
        mmio: Mmio {
            cap: Cap::bootstrap(),
            sources: None,
            io: RawMmio(MmioRegion {
                phys: base,
                virt: words.as_mut_ptr() as u64,
                len: 0x100000,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            }),
        },
        hardware,
        registers,
        device,
        resources: ManuallyDrop::new(resources),
        hif: ManuallyDrop::new(None),
        hif_live: false,
        mission_pending: true,
        power_ready: true,
        armed: true,
        poisoned: false,
        saved_aspm: None,
        retired: false,
        reclaimable: false,
        interrupts: None,
        msi: None,
        signal: crate::ath10k::irq::Signal::new(),
        serviced: 0,
        firmware_crashed: false,
    };
    if !matches!(owner.retire_for_restart(), Err(BmiError::Pci))
        || !owner.retired
        || owner.reclaimable
        || owner.hif_source_ready(3).is_ok()
    {
        return TestResult::Fail("failed physical park did not retire old transport");
    }
    let after = words.clone();
    if !matches!(owner.retire_for_restart(), Err(BmiError::BadResponse)) || words != after {
        return TestResult::Fail("retired transport was allowed a second physical attempt");
    }
    words.fill(0x1234); // A successor's hypothetical live register state.
    drop(owner);
    if words.iter().any(|value| *value != 0x1234) {
        return TestResult::Fail("late retired physical Drop modified successor hardware");
    }
    let fresh = Resources::allocate(hardware).unwrap();
    if [
        fresh.request.dma_address(),
        fresh.response.dma_address(),
        fresh.diag.dma_address(),
    ]
    .iter()
    .any(|address| old_addresses.contains(address))
    {
        return TestResult::Fail("old uncertain DMA was recycled into a fresh owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_retired_physical_drop_preserves_successor_and_pins_dma
);

/// A retirement that proved quiescence frees on Drop without any hardware
/// access; a function without a PCIe ordering proof is never reclaimable.
fn smoke_ath10k_recovery_reclaimable_retired_drop_frees_without_hardware_access() -> TestResult {
    let hardware = HwRev::Qca6174;
    let registers = hardware.registers().unwrap();
    let mut words = vec![0u32; 0x100000 / 4];
    let base = narf_memory::PhysAddr::new(0);
    let device = BusDevice {
        addr: narf_bus::BusAddr::Mmio(base),
        id: narf_bus::DeviceId {
            vendor: 0x168c,
            device: 0x003e,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: narf_bus::BusKind::VirtioMmio {
            base,
            len: 0x1000,
            device_id: 1,
        },
    };
    let make = |words: &mut Vec<u32>, reclaimable: bool| PciBoot {
        mmio: Mmio {
            cap: Cap::bootstrap(),
            sources: None,
            io: RawMmio(MmioRegion {
                phys: base,
                virt: words.as_mut_ptr() as u64,
                len: 0x100000,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            }),
        },
        hardware,
        registers,
        device,
        resources: ManuallyDrop::new(Resources::allocate(hardware).unwrap()),
        hif: ManuallyDrop::new(None),
        hif_live: false,
        mission_pending: true,
        power_ready: false,
        armed: true,
        poisoned: true,
        saved_aspm: None,
        retired: true,
        reclaimable,
        interrupts: None,
        msi: None,
        signal: crate::ath10k::irq::Signal::new(),
        serviced: 0,
        firmware_crashed: false,
    };
    let mut owner = make(&mut words, false);
    // Not a PCIe function: no Device Control ordering proof exists.
    if owner.flushed() {
        return TestResult::Fail("non-PCIe function produced an ordered flush proof");
    }
    drop(owner);
    let owner = make(&mut words, true);
    words.fill(0x5678); // A successor's live register state.
    drop(owner);
    if words.iter().any(|value| *value != 0x5678) {
        return TestResult::Fail("reclaiming retired Drop touched successor hardware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_reclaimable_retired_drop_frees_without_hardware_access
);
