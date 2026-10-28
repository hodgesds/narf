use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Model the observed Navi22/Raphael address latch, including discarded
/// low address bits. An ordinary RAM-backed MMIO fixture misses this bug.
struct Device {
    index: u32,
    writes: Vec<(u64, u32)>,
    words: Vec<(u32, u32)>,
    absent: bool,
    stuck: bool,
}

impl Device {
    fn new() -> Self {
        Self {
            index: 0xfed0_4714,
            writes: Vec::new(),
            words: Vec::new(),
            absent: false,
            stuck: false,
        }
    }
}

impl RegisterIo for Device {
    fn read32(&mut self, offset: u64) -> u32 {
        match offset {
            INDEX if self.absent => u32::MAX,
            INDEX => self.index,
            DATA => self
                .words
                .iter()
                .find(|(address, _)| *address == self.index)
                .map(|(_, value)| *value)
                .unwrap_or(u32::MAX),
            _ => panic!("unexpected register port"),
        }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        self.writes.push((offset, value));
        match offset {
            INDEX if !self.stuck => self.index = value & !3,
            INDEX => {}
            DATA => self.words.push((self.index, value)),
            _ => panic!("unexpected register port"),
        }
    }
}

fn smoke_amdgpu_index_aligned_probe_restores_latch() -> TestResult {
    let mut device = Device::new();
    // Reproduce the exact failed hardware transaction before exercising
    // the production probe against that same register behavior.
    device.write32(INDEX, 0xcafe_f00d);
    if device.read32(INDEX) != 0xcafe_f00c {
        return TestResult::Fail("fixture must reproduce hardware address rounding");
    }
    let previous = 0xfed0_4714;
    device.index = previous;
    device.writes.clear();
    if probe_with(&mut device).is_err() || device.index != previous {
        return TestResult::Fail("live aligned latch rejected or original selection lost");
    }
    if device.writes.as_slice() != [(INDEX, 0x378c), (INDEX, previous)] {
        return TestResult::Fail(
            "probe must select a valid address, restore, and never access DATA",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/index",
    smoke_amdgpu_index_aligned_probe_restores_latch
);

fn smoke_amdgpu_index_probe_rejects_absent_and_stuck() -> TestResult {
    let mut absent = Device::new();
    absent.absent = true;
    if probe_with(&mut absent) != Err(ProbeError::Unresponsive) || !absent.writes.is_empty() {
        return TestResult::Fail("absent hardware must fail without any writes");
    }
    let mut stuck = Device::new();
    stuck.stuck = true;
    let previous = stuck.index;
    if probe_with(&mut stuck)
        != Err(ProbeError::Mismatch {
            previous,
            echo: previous,
        })
        || stuck.writes.last() != Some(&(INDEX, previous))
    {
        return TestResult::Fail("stuck latch must fail and attempt restoration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/index",
    smoke_amdgpu_index_probe_rejects_absent_and_stuck
);

fn smoke_amdgpu_index_register_ids_reach_byte_addresses() -> TestResult {
    let mut device = Device::new();
    device.words.push((0x378c, 12288));
    if read_with(&mut device, 0x0de3) != 12288 {
        return TestResult::Fail("DWORD register ID did not select its byte address");
    }
    device.writes.clear();
    // A register ID with nonzero low bits also catches accidental rounding
    // of the DWORD ID itself rather than scaling at the hardware boundary.
    write_with(&mut device, 0x2201, 0x1234_5678);
    if device.writes.as_slice() != [(INDEX, 0x8804), (DATA, 0x1234_5678)]
        || read_with(&mut device, 0x2201) != 0x1234_5678
    {
        return TestResult::Fail("register write/read went to the wrong hardware address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/index",
    smoke_amdgpu_index_register_ids_reach_byte_addresses
);

fn smoke_amdgpu_index_register_access_cannot_select_vram() -> TestResult {
    let mut device = Device::new();
    for invalid in [0x2000_0000, 0x4000_0000, u32::MAX] {
        if read_with(&mut device, invalid) != u32::MAX {
            return TestResult::Fail("unrepresentable register address accepted");
        }
        write_with(&mut device, invalid, 1);
    }
    if !device.writes.is_empty() {
        return TestResult::Fail("invalid register address performed device I/O");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/index",
    smoke_amdgpu_index_register_access_cannot_select_vram
);
