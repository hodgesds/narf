use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// A live-looking runtime owner over a word-array BAR on a non-PCI fixture
/// function: MSI discovery must fail and leave polled service.
fn owner(words: &mut Vec<u32>, hardware: HwRev) -> PciBoot {
    let registers = hardware.registers().unwrap();
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
    PciBoot {
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
        hif: ManuallyDrop::new(Some(hif::Runtime::allocate(hardware, allocate).unwrap())),
        hif_live: true,
        mission_pending: true,
        power_ready: true,
        armed: true,
        poisoned: false,
        saved_aspm: None,
        retired: false,
        reclaimable: false,
        interrupts: None,
        msi: None,
        signal: Signal::new(),
        serviced: 0,
        firmware_crashed: false,
    }
}
/// Retire without hardware access so the fixture Drop never halts engines
/// on the word array; uncertain DMA stays pinned as in recovery tests.
fn park(mut owner: PciBoot) {
    owner.retired = true;
    owner.reclaimable = false;
    drop(owner);
}

fn smoke_ath10k_interrupts_without_msi_fall_back_to_polled_service() -> TestResult {
    let hardware = HwRev::Qca6174;
    let p = Program::for_hw(hardware).unwrap();
    let mut words = vec![0u32; 0x100000 / 4];
    words[(p.soc_core as usize + 8) / 4] = 0xffff_ffff;
    let mut owner = owner(&mut words, hardware);
    owner.start_interrupts();
    let (_, delivered) = owner.interrupt();
    if delivered || owner.interrupts.is_some() || owner.msi.is_some() {
        park(owner);
        return TestResult::Fail("a function without MSI must keep polled service");
    }
    if words[(p.soc_core as usize + 8) / 4] != 0 {
        park(owner);
        return TestResult::Fail("polled owner must leave the PCIe line masked");
    }
    if !matches!(owner.hif_poll_now(), Ok(None)) {
        park(owner);
        return TestResult::Fail("idle polled service must succeed without events");
    }
    park(owner);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/interrupts",
    smoke_ath10k_interrupts_without_msi_fall_back_to_polled_service
);

fn smoke_ath10k_interrupts_firmware_crash_poisons_generation() -> TestResult {
    let hardware = HwRev::Qca988x;
    let p = Program::for_hw(hardware).unwrap();
    let mut words = vec![0u32; 0x100000 / 4];
    let mut owner = owner(&mut words, hardware);
    words[p.fw_indicator as usize / 4] = FW_IND_EVENT_PENDING_BIT | 2;
    if owner.hif_poll_now() != Err(BmiError::FirmwareCrashed) || !owner.has_crashed() {
        park(owner);
        return TestResult::Fail("FW_IND_EVENT_PENDING must end the generation");
    }
    if words[p.fw_indicator as usize / 4] != 2 {
        park(owner);
        return TestResult::Fail("crash acknowledgement must clear only EVENT_PENDING");
    }
    // Terminal: no replay of a crashed firmware's rings.
    if owner.hif_poll_now() != Err(BmiError::BadResponse)
        || owner.hif_source_ready(3).is_ok()
        || owner.hif_begin_send(3, &[1]).is_ok()
    {
        park(owner);
        return TestResult::Fail("crashed generation accepted further service");
    }
    park(owner);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/interrupts",
    smoke_ath10k_interrupts_firmware_crash_poisons_generation
);

fn smoke_ath10k_interrupts_delivered_service_brackets_ring_poll() -> TestResult {
    let hardware = HwRev::Qca9984;
    let p = Program::for_hw(hardware).unwrap();
    let mut words = vec![0u32; 0x100000 / 4];
    let mut owner = owner(&mut words, hardware);
    // Model a delivered vector: program enabled, then one MSI raised.
    let present = [2u8, 3, 4, 5, 8];
    p.enable(&mut owner.mmio, &irq::serviced_pipes(&present));
    owner.interrupts = Some(p);
    if words[(p.soc_core as usize + 8) / 4] != p.fw_mask | p.ce_mask_all {
        park(owner);
        return TestResult::Fail("enabled owner must unmask firmware + CE causes");
    }
    words[p.ce_wrapper as usize / 4] = (1 << 8) << p.summary_lsb;
    words[(p.ce0 as usize + 8 * 0x400 + 0x30) / 4] = 0;
    owner.signal.raise();
    let before = owner.signal.count();
    if !matches!(owner.hif_poll_now(), Ok(None)) {
        park(owner);
        return TestResult::Fail("delivered service failed on an idle ring");
    }
    if words[(p.ce0 as usize + 8 * 0x400 + 0x30) / 4] != 0x1f {
        park(owner);
        return TestResult::Fail("summarized CE8 status was not cleared before service");
    }
    // The word-array summary does not self-clear: the epilogue must keep the
    // line masked and reschedule (napi_schedule) instead of unmasking.
    if owner.signal.count() == before || words[(p.soc_core as usize + 8) / 4] != 0 {
        park(owner);
        return TestResult::Fail("re-asserted summary must reschedule masked");
    }
    words[p.ce_wrapper as usize / 4] = 0;
    if !matches!(owner.hif_poll_now(), Ok(None))
        || words[(p.soc_core as usize + 8) / 4] != p.fw_mask | p.ce_mask_all
    {
        park(owner);
        return TestResult::Fail("empty summary must re-enable the line");
    }
    // Teardown (ath10k_pci_irq_disable) is idempotent.
    owner.stop_interrupts();
    owner.stop_interrupts();
    if owner.interrupts.is_some()
        || words[(p.soc_core as usize + 8) / 4] != 0
        || (0..p.ce_count).any(|pipe| {
            words[(p.ce0 as usize + pipe as usize * 0x400 + 0x2c) / 4] & HOST_IS_COPY_COMPLETE != 0
        })
    {
        park(owner);
        return TestResult::Fail("teardown left a CE or line source enabled");
    }
    park(owner);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/interrupts",
    smoke_ath10k_interrupts_delivered_service_brackets_ring_poll
);

const FW_IND_EVENT_PENDING_BIT: u32 = crate::ath10k::hw::FW_IND_EVENT_PENDING;
use crate::ath10k::irq::HOST_IS_COPY_COMPLETE;
