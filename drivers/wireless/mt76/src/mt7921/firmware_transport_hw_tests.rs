//! Exercise the production descriptor/doorbell backend on owned memory.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn rig() -> Result<(Vec<u32>, Hardware), Error> {
    let mut words = vec![0u32; 0x100000 / 4];
    let addr = narf_bus::PcieAddr::new(0, 0, 0, 0);
    let device = BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        id: narf_bus::DeviceId {
            vendor: 0x14c3,
            device: 0x0616,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: narf_bus::BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let mmio = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x100000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let storage = Storage {
        wm: Ring::allocate(TX_WM, false)?,
        fwdl: Ring::allocate(TX_FWDL, false)?,
        rx: [
            Ring::allocate(RX_PRE, true)?,
            Ring::allocate(RX_POST, true)?,
        ],
    };
    Ok((
        words,
        Hardware {
            mmio,
            device,
            authority: Cap::bootstrap(),
            owner: super::super::Retained {
                storage: Some(storage),
                published: false,
            },
        },
    ))
}

fn mcu_dma_production_tx_descriptor_completion_and_wrap() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("transport DMA model allocation failed"),
    };
    for turn in 0..DEPTH + 2 {
        let slot = turn % DEPTH;
        let next = (slot + 1) % DEPTH;
        if hw.submit(true, &[0x55; 64]).is_err() || words[(0xd4400 + 8) / 4] != next as u32 {
            return TestResult::Fail("FWDL did not ring hardware queue 16");
        }
        let ring = &hw.owner.storage.as_ref().unwrap().fwdl;
        if ring.word(slot, 1) != ((64 << 16) | LAST)
            || ring.word(slot, 2) != 0
            || ring.word(slot, 3) != (ring.buffers[slot].dma_addr().raw() >> 32) as u32
        {
            return TestResult::Fail("descriptor lengths/segments/address-high layout");
        }
        if hw.tx_complete(true) != Ok(false) {
            return TestResult::Fail("TX completed before DMA");
        }
        hw.owner
            .storage
            .as_ref()
            .unwrap()
            .fwdl
            .set_word(slot, 1, (64 << 16) | LAST | DONE);
        words[(0xd4400 + 12) / 4] = next as u32;
        if hw.tx_complete(true) != Ok(true) {
            return TestResult::Fail("TX completion/wrap failed");
        }
    }
    words[(0xd4400 + 12) / 4] = 99;
    if hw.tx_complete(true) != Err(Error::Ring) {
        return TestResult::Fail("corrupt DMA index accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_dma_production_tx_descriptor_completion_and_wrap
);

fn mcu_dma_production_rx_copies_before_rearm_and_checks_lengths() -> TestResult {
    let (mut words, mut hw) = match rig() {
        Ok(rig) => rig,
        Err(_) => return TestResult::Fail("transport DMA model allocation failed"),
    };
    let mut event = vec![0u8; 36];
    event[..4].copy_from_slice(&((7u32 << 27) | 36).to_le_bytes());
    event[24..26].copy_from_slice(&12u16.to_le_bytes());
    event[28] = 4;
    event[29] = 1;
    event[32] = 2;
    {
        let ring = &hw.owner.storage.as_ref().unwrap().rx[0];
        // SAFETY: model acts as the device, writing its owned coherent buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                event.as_ptr(),
                ring.buffers[0].cpu_mut_ptr::<u8>(),
                event.len(),
            )
        };
        ring.set_word(0, 1, (36 << 16) | LAST | DONE);
    }
    words[(RX_PRE + 12) as usize / 4] = 1;
    if hw.receive() != Ok(Some(event)) || words[(RX_PRE + 8) as usize / 4] != 0 {
        return TestResult::Fail("RX response or release doorbell");
    }
    let ring = &hw.owner.storage.as_ref().unwrap().rx[0];
    if ring.index != 1 || ring.word(0, 1) != (MAX_FRAME as u32) << 16 {
        return TestResult::Fail("RX did not rearm consumed descriptor");
    }
    ring.set_word(1, 1, (((MAX_FRAME + 1) as u32) << 16) | LAST | DONE);
    words[(RX_PRE + 12) as usize / 4] = 2;
    if hw.receive() != Err(Error::MalformedEvent) {
        return TestResult::Fail("oversized RX accepted");
    }
    hw.authority.revoke();
    let old = words[(TX_WM + 8) as usize / 4];
    if hw.submit(false, &[1; 64]) != Err(Error::Authority) || words[(TX_WM + 8) as usize / 4] != old
    {
        return TestResult::Fail("revoked authority published a DMA descriptor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/transport",
    mcu_dma_production_rx_copies_before_rearm_and_checks_lengths
);
