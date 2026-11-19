// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone)]
struct Model {
    words: BTreeMap<u32, u32>,
    writes: Vec<(u32, u32)>,
    binding: cold::Binding,
    accesses: usize,
    fail_at: Option<usize>,
    failed: bool,
    drop_address: Option<u32>,
}
impl Model {
    fn new() -> Self {
        let cap =
            narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x40000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        Self {
            words: [
                (0x24, 0x1f00_0000),
                (0x84, 0x0201_0002),
                (0x88, 0x802),
                (0x8400, 0x7fff_4f80),
                (0x10000, 0xc000_01ff),
                (0xb010, 0),
                (0xb000, 0x30),
            ]
            .into_iter()
            .collect(),
            writes: Vec::new(),
            binding: cold::Binding::observe(&region, &cap),
            accesses: 0,
            fail_at: None,
            failed: false,
            drop_address: None,
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        if self.failed {
            return Err(power::Error::Access);
        }
        self.accesses += 1;
        if self.fail_at == Some(self.accesses) {
            self.failed = true;
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn word(&self, a: u32) -> u32 {
        self.words.get(&a).copied().unwrap_or(0)
    }
}
impl cold::Regs for Model {
    fn binding(&self) -> cold::Binding {
        self.binding
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.access()
    }
    fn read8(&mut self, _a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Err(power::Error::Access)
    }
    fn read16(&mut self, _a: u32) -> Result<u16, power::Error> {
        self.access()?;
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        Ok(self.word(a))
    }
    fn write8(&mut self, _a: u32, _v: u8) -> Result<(), power::Error> {
        self.access()?;
        Err(power::Error::Access)
    }
    fn write16(&mut self, _a: u32, _v: u16) -> Result<(), power::Error> {
        self.access()?;
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        self.writes.push((a, v));
        if self.drop_address == Some(a) {
            return Ok(());
        }
        self.words.insert(a, v);
        if a == 0x8400 {
            let ready = if v & 0x0480_0000 == 0x0480_0000 { 3 } else { 0 };
            self.words.insert(0x8d00, ready);
            self.words.insert(0x9100, ready);
        }
        Ok(())
    }
    fn poll32(&mut self, a: u32, mask: u32, want: u32, us: u64) -> Result<(), power::Error> {
        self.access()?;
        if us != 2000 {
            return Err(power::Error::Access);
        }
        if self.word(a) & mask == want {
            Ok(())
        } else {
            Err(power::Error::Timeout)
        }
    }
    fn delay_us(&mut self, _us: u64) -> Result<(), power::Error> {
        self.access()?;
        Err(power::Error::Access)
    }
}
fn whole(io: &mut Model, p: &mut Preinit) -> Result<(), Error> {
    p.dle_hfc(io)?;
    p.recovery(io)?;
    p.settings(io)?;
    p.ready(io)
}
fn smoke_rtw8922a_checked_dlfw_preinit_literal_program_and_pci_receipts() -> TestResult {
    let mut io = Model::new();
    let mut p = Preinit::new(1);
    kt_assert_eq!(whole(&mut io, &mut p), Ok(()));
    kt_assert_eq!(
        &io.writes[..10],
        &[
            (0xb010, 0x8000_7fff),
            (0xb000, 0x80),
            (0x7880, 3),
            (0xb000, 0x80),
            (0x8420, 0x1000),
            (0x8400, 0x7b7f_4f80),
            (0x8404, 0x0480_0000),
            (0x8c08, 0),
            (0x9008, 0x0b70_1a01),
            (0x8c40, 0)
        ]
    );
    kt_assert_eq!(io.word(0x8c44), 0x0006_0006);
    kt_assert_eq!(io.word(0x9048), 0x0020_0020);
    kt_assert_eq!(io.word(0x904c), 0x0100_0100);
    kt_assert_eq!(io.word(0xb700) & 9, 8);
    kt_assert_eq!(io.word(0xb704), 0);
    kt_assert_eq!(io.word(0xb010), 0x8000_7fff);
    kt_assert_eq!(io.word(0xb000) & 0xb0, 0x80);
    let recovery = io
        .writes
        .iter()
        .position(|p| *p == (0x306c, 0x800))
        .unwrap();
    kt_assert_eq!(
        &io.writes[recovery..recovery + 11],
        &[
            (0x306c, 0x800),
            (0x3090, 0x800),
            (0x309c, 0x800),
            (0x3144, 0x800),
            (0x3150, 0x800),
            (0x315c, 0x800),
            (0x3164, 0x800),
            (0x316c, 0x800),
            (0x3054, 0x27100),
            (0x3060, 0x27100),
            (0x3084, 0x1e848)
        ]
    );
    kt_assert_eq!(io.word(0x34a8) & 0x800e_0000, 0x0004_0000);
    kt_assert_eq!(io.word(0x10000) & 0x3000_0000, 0);
    let count = io.writes.len();
    kt_assert_eq!(p.dle_hfc(&mut io), Err(Error::State));
    kt_assert_eq!(io.writes.len(), count);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_dlfw_preinit_literal_program_and_pci_receipts
);
fn smoke_rtw8922a_checked_preinit_each_access_and_dropped_quota_are_terminal() -> TestResult {
    let template = Model::new();
    let mut reference = template.clone();
    kt_assert_eq!(whole(&mut reference, &mut Preinit::new(1)), Ok(()));
    for at in 1..=reference.accesses {
        let mut io = template.clone();
        io.fail_at = Some(at);
        let mut p = Preinit::new(1);
        kt_assert!(whole(&mut io, &mut p).is_err());
        kt_assert_eq!(p.stage, Stage::Failed);
        let count = io.writes.len();
        kt_assert_eq!(p.dle_hfc(&mut io), Err(Error::State));
        kt_assert_eq!(io.writes.len(), count);
    }
    let mut dropped = template.clone();
    dropped.drop_address = Some(0x8c44);
    let mut p = Preinit::new(1);
    kt_assert_eq!(p.dle_hfc(&mut dropped), Err(Error::Readback(0x8c44)));
    kt_assert_eq!(p.stage, Stage::Failed);
    for (a, v) in [
        (0x24, 0),
        (0x84, 0x0203_0002),
        (0x10000, 0xf000_01ff),
        (0x88, 2),
    ] {
        let mut io = template.clone();
        io.words.insert(a, v);
        kt_assert!(Preinit::new(1).dle_hfc(&mut io).is_err());
        kt_assert!(io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_preinit_each_access_and_dropped_quota_are_terminal
);
