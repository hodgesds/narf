use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug)]
struct Buffer {
    bytes: Vec<u8>,
    dma: u64,
}
impl Buffer {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![0; size],
            dma: 0x100000,
        }
    }
}
impl Memory for Buffer {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn dma_address(&self) -> u64 {
        self.dma
    }
    fn read(&self, offset: usize) -> u8 {
        self.bytes[offset]
    }
    fn write(&mut self, offset: usize, value: u8) {
        self.bytes[offset] = value;
    }
}
#[derive(Debug, Default)]
struct Registers {
    values: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
}
impl Ath10kMmio for Registers {
    fn read32(&mut self, offset: u64) -> u32 {
        self.values.get(&offset).copied().unwrap_or(0)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.writes.push((offset, value));
        self.values.insert(offset, value);
    }
}

fn smoke_ath10k_dma_ring_reuses_only_terminal_descriptors() -> TestResult {
    let mut mmio = Registers::default();
    let mut ring = match Ring::new(Buffer::new(16), HwRev::Qca6174, 0, 2, Direction::Source) {
        Ok(ring) => ring,
        Err(_) => return TestResult::Fail("valid CE ring rejected"),
    };
    if ring.initialize(&mut mmio, HwRev::Qca6174, 0, 256).is_err() {
        return TestResult::Fail("CE init failed");
    }
    for transfer in 0..6u32 {
        let slot = (transfer & 1) as usize * 8;
        if ring.post(&mut mmio, 0x12345678, 44).is_err()
            || ring.memory.bytes[slot..slot + 8] != [0x78, 0x56, 0x34, 0x12, 44, 0, 0, 0]
            || ring.post(&mut mmio, 0x12345678, 44) != Err(DmaError::Busy)
            || ring.completion(&mut mmio) != Ok(None)
        {
            return TestResult::Fail("CE source descriptor reused before completion");
        }
        mmio.values
            .insert(0x34400 + ce_off::CURRENT_SRRI, (transfer + 1) & 1);
        if ring.completion(&mut mmio) != Ok(Some(44)) || ring.completion(&mut mmio) != Ok(None) {
            return TestResult::Fail("CE source completion/wrap accounting wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/dma",
    smoke_ath10k_dma_ring_reuses_only_terminal_descriptors
);

fn smoke_ath10k_dma_rx_count_and_buffer_bounds() -> TestResult {
    let mut mmio = Registers::default();
    let mut ring = match Ring::new(
        Buffer::new(16),
        HwRev::Qca99x0,
        7,
        2,
        Direction::Destination,
    ) {
        Ok(ring) => ring,
        Err(_) => return TestResult::Fail("valid diag destination ring rejected"),
    };
    if ring.initialize(&mut mmio, HwRev::Qca99x0, 7, 2048).is_err()
        || ring.post(&mut mmio, 0x100000, 12).is_err()
        || ring.completion(&mut mmio) != Ok(None)
    {
        return TestResult::Fail("CE RX descriptor was not posted empty");
    }
    ring.memory.bytes[4] = 13;
    if ring.completion(&mut mmio) != Err(DmaError::BadCompletion)
        || ring.post(&mut mmio, 0x100000, 12) != Err(DmaError::Busy)
    {
        return TestResult::Fail("oversized RX released its DMA ownership");
    }
    ring.memory.bytes[4] = 12;
    if ring.completion(&mut mmio) != Ok(Some(12)) || ring.memory.bytes[4..6] != [0, 0] {
        return TestResult::Fail("terminal RX descriptor not retired");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/dma",
    smoke_ath10k_dma_rx_count_and_buffer_bounds
);

fn smoke_ath10k_dma_rejects_geometry_and_inherited_queues() -> TestResult {
    for (hardware, pipe, size, entries, address) in [
        (HwRev::Qca988x, 8, 16, 2, 0x100000),
        (HwRev::Qca99x0, 12, 16, 2, 0x100000),
        (HwRev::Qca988x, 0, 8, 2, 0x100000),
        (HwRev::Qca988x, 0, 16, 2, 0x100001),
        (HwRev::Qca988x, 0, 16, 2, 0xfffffff8),
        (HwRev::Qca988x, 0, 16, 1, 0x100000),
    ] {
        let mut buffer = Buffer::new(size);
        buffer.dma = address;
        if !matches!(
            Ring::new(buffer, hardware, pipe, entries, Direction::Source),
            Err(DmaError::BadConfig)
        ) {
            return TestResult::Fail("invalid CE geometry/DMA mask accepted");
        }
    }
    let mut ring = match Ring::new(Buffer::new(16), HwRev::Qca988x, 0, 2, Direction::Source) {
        Ok(ring) => ring,
        Err(_) => return TestResult::Fail("valid ring rejected"),
    };
    let mut mmio = Registers::default();
    mmio.values.insert(0x57400 + ce_off::SR_WR_INDEX, 1);
    if ring.initialize(&mut mmio, HwRev::Qca988x, 0, 256) != Err(DmaError::Busy)
        || !mmio.writes.is_empty()
    {
        return TestResult::Fail("CE inherited queue was repointed to new DMA memory");
    }
    mmio.values.insert(0x57400 + ce_off::CURRENT_SRRI, 1);
    if ring.initialize(&mut mmio, HwRev::Qca988x, 0, 256).is_err()
        || mmio
            .writes
            .iter()
            .any(|&(address, value)| address == 0x57400 + ce_off::SR_WR_INDEX && value == 0)
    {
        return TestResult::Fail("CE warm init destroyed the existing empty index");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/dma",
    smoke_ath10k_dma_rejects_geometry_and_inherited_queues
);
