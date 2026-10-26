//! PCI configuration model: live decode must never see a probe address.
use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Word(u64, u16),
    Dword(u64, u32),
}

#[derive(Debug)]
struct Model {
    command: u16,
    original_command: u16,
    status: u16,
    bars: [u32; 6],
    originals: [u32; 6],
    masks: [u32; 6],
    writes: Vec<Event>,
    violations: usize,
    decode_stuck: bool,
    refuse_bar_restore: bool,
    refuse_enable: bool,
}

impl Model {
    fn new(bars: [u32; 6], masks: [u32; 6]) -> Self {
        Self {
            command: 0x0407,
            original_command: 0x0407,
            status: 0xf900,
            originals: bars,
            bars,
            masks,
            writes: Vec::new(),
            violations: 0,
            decode_stuck: false,
            refuse_bar_restore: false,
            refuse_enable: false,
        }
    }
    fn doorbells() -> Self {
        // GPU BAR2 reproducer: 256 MiB, 64-bit and prefetchable. With
        // decode live, probing its high half creates ffffffff00000000.
        Self::new([0, 0, 0xc, 0xe1, 0, 0], [0, 0, 0xf000_000c, u32::MAX, 0, 0])
    }
    fn slot(offset: u64) -> Option<usize> {
        if (0x10..0x28).contains(&offset) && offset % 4 == 0 {
            Some(((offset - 0x10) / 4) as usize)
        } else {
            None
        }
    }
    fn restored(&self) -> bool {
        self.command == self.original_command
            && self.status == 0xf900
            && self.bars == self.originals
            && self.violations == 0
    }
}

impl Config for Model {
    fn read16(&mut self, offset: u64) -> u16 {
        match offset {
            4 => self.command,
            6 => self.status,
            _ => u16::MAX,
        }
    }
    fn write16(&mut self, offset: u64, value: u16) {
        self.writes.push(Event::Word(offset, value));
        if offset == 4 {
            if value & 3 != 0 && self.bars != self.originals {
                self.violations += 1;
            }
            if (self.decode_stuck && value & 3 == 0) || (self.refuse_enable && value & 3 != 0) {
                return;
            }
            self.command = value;
        } else if offset == 6 {
            self.status &= !value; // PCI Status has RW1C bits.
        } else {
            self.violations += 1;
        }
    }
    fn read32(&mut self, offset: u64) -> u32 {
        if offset == 4 {
            return u32::from(self.command) | (u32::from(self.status) << 16);
        }
        match Self::slot(offset) {
            Some(slot) if self.bars[slot] == u32::MAX => self.masks[slot],
            Some(slot) => self.bars[slot],
            None => 0,
        }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.writes.push(Event::Dword(offset, value));
        if offset == 4 {
            self.command = value as u16;
            self.status &= !((value >> 16) as u16);
            self.violations += 1;
            return;
        }
        let Some(slot) = Self::slot(offset) else {
            self.violations += 1;
            return;
        };
        if self.command & 3 != 0 {
            self.violations += 1;
        }
        if self.refuse_bar_restore && self.bars[slot] == u32::MAX && value == self.originals[slot] {
            return;
        }
        self.bars[slot] = value;
    }
}

fn bar_64bit_probe_is_hidden_until_both_halves_are_restored() -> TestResult {
    let mut model = Model::doorbells();
    let result = read_bar_with(&mut model, 2);
    let expected = [
        Event::Word(4, 0x0404),
        Event::Dword(0x18, u32::MAX),
        Event::Dword(0x18, 0xc),
        Event::Dword(0x1c, u32::MAX),
        Event::Dword(0x1c, 0xe1),
        Event::Word(4, 0x0407),
    ];
    let Ok(bar) = result else {
        return TestResult::Fail("64-bit BAR probe failed");
    };
    if !model.restored()
        || model.writes != expected
        || bar.size != 0x1000_0000
        || bar.phys.raw() != 0x0000_00e1_0000_0000
        || bar.kind != (BarKind::Mmio64 { prefetchable: true })
    {
        return TestResult::Fail("probe address was live, state lost, or BAR2 decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/bar/model",
    bar_64bit_probe_is_hidden_until_both_halves_are_restored
);

fn bar_io_and_32bit_probes_restore_command_and_status() -> TestResult {
    for (index, original, mask, expected) in [
        (4, 0xc001, 0xffff_ff01, Some((BarKind::Io, 0xc000, 0x100))),
        (
            5,
            0xfeb0_0000,
            0xfff0_0000,
            Some((
                BarKind::Mmio32 {
                    prefetchable: false,
                },
                0xfeb0_0000,
                0x10_0000,
            )),
        ),
        (0, 0, 0, None),
    ] {
        let mut bars = [0; 6];
        let mut masks = [0; 6];
        bars[index] = original;
        masks[index] = mask;
        let mut model = Model::new(bars, masks);
        let result = read_bar_with(&mut model, index as u8);
        let valid = match (result, expected) {
            (Ok(bar), Some((kind, phys, size))) => {
                bar.kind == kind && bar.phys.raw() == phys && bar.size == size
            }
            (Err(BarError::Unimplemented), None) => true,
            _ => false,
        };
        if !valid || !model.restored() {
            return TestResult::Fail("I/O, MMIO32 or absent BAR lost Command/Status state");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/bar/model",
    bar_io_and_32bit_probes_restore_command_and_status
);

fn bar_invalid_slots_never_write_configuration() -> TestResult {
    for index in [3, 6] {
        let mut model = Model::doorbells();
        if !matches!(read_bar_with(&mut model, index), Err(BarError::OutOfRange))
            || !model.writes.is_empty()
            || !model.restored()
        {
            return TestResult::Fail("high half or out-of-range BAR mutated configuration");
        }
    }
    let mut bars = [0; 6];
    bars[5] = 4;
    let mut model = Model::new(bars, [0; 6]);
    if !matches!(read_bar_with(&mut model, 5), Err(BarError::OutOfRange))
        || !model.writes.is_empty()
    {
        return TestResult::Fail("truncated 64-bit BAR pair was probed");
    }
    TestResult::Pass
}
kernel_test_in!("bus/bar/model", bar_invalid_slots_never_write_configuration);

fn bar_decode_disable_requires_readback_before_probe() -> TestResult {
    let mut model = Model::doorbells();
    model.decode_stuck = true;
    if !matches!(read_bar_with(&mut model, 2), Err(BarError::ConfigFailed))
        || !model.restored()
        || model
            .writes
            .iter()
            .any(|event| matches!(event, Event::Dword(..)))
    {
        return TestResult::Fail("BAR writes occurred while decode could not be disabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/bar/model",
    bar_decode_disable_requires_readback_before_probe
);

fn bar_large_window_preserves_already_disabled_decoding() -> TestResult {
    let mut model = Model::new([0xc, 0xe0, 0, 0, 0, 0], [0xc, 0xffff_fffc, 0, 0, 0, 0]);
    model.command = 0x0404;
    model.original_command = 0x0404;
    let result = read_bar_with(&mut model, 0);
    if !matches!(result, Ok(bar) if bar.size == 0x4_0000_0000 && bar.phys.raw() == 0x0000_00e0_0000_0000)
        || !model.restored()
        || model
            .writes
            .iter()
            .any(|event| matches!(event, Event::Word(..)))
    {
        return TestResult::Fail("large BAR sizing enabled decoding or truncated size");
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/bar/model",
    bar_large_window_preserves_already_disabled_decoding
);

fn bar_failed_restoration_cannot_expose_probe_address() -> TestResult {
    for fail_bar in [true, false] {
        let mut model = Model::doorbells();
        model.refuse_bar_restore = fail_bar;
        model.refuse_enable = !fail_bar;
        if !matches!(read_bar_with(&mut model, 2), Err(BarError::ConfigFailed))
            || model.command != 0x0404
            || model.status != 0xf900
            || model.violations != 0
        {
            return TestResult::Fail("failed BAR/Command restore reopened a probe window");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "bus/bar/model",
    bar_failed_restoration_cannot_expose_probe_address
);
