// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Byte(u32, u8),
    Short(u32, u16),
    Word(u32, u32),
    Delay(u64),
}
struct Model {
    words: BTreeMap<u32, u32>,
    physical: Vec<u8>,
    request: Option<u32>,
    ops: Vec<Op>,
    accesses: usize,
    fault_at: Option<usize>,
    failed: bool,
    fail_data: Option<u32>,
    binding: crate::rtw89::cold_8922a::Binding,
}
impl Model {
    fn new() -> Self {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x40000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        Self {
            words: [
                (0x3f0, 0x0220_0000),
                (0x3104, 0x1102),
                (0x3106, 0x3322),
                (0x3108, 0x5544),
            ]
            .into_iter()
            .collect(),
            physical: vec![0xff; 0x2000],
            request: None,
            ops: Vec::new(),
            accesses: 0,
            fault_at: None,
            failed: false,
            fail_data: None,
            binding: crate::rtw89::cold_8922a::Binding::observe(&region, &cap),
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        if self.failed {
            return Err(power::Error::Access);
        }
        self.accesses += 1;
        if self.fault_at == Some(self.accesses) {
            self.failed = true;
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn word(&self, a: u32) -> u32 {
        self.words.get(&a).copied().unwrap_or(0)
    }
}
impl Regs for Model {
    fn binding(&self) -> crate::rtw89::cold_8922a::Binding {
        self.binding
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.access()
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(self.word(a) as u8)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.access()?;
        Ok(self.word(a) as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        if a == 0x34 {
            let address = self.request.ok_or(power::Error::Access)?;
            if self.fail_data == Some(address) {
                self.failed = true;
                return Err(power::Error::Access);
            }
            let start = address as usize;
            let data = self
                .physical
                .get(start..start + 4)
                .ok_or(power::Error::Access)?;
            return Ok(u32::from_le_bytes(data.try_into().unwrap()));
        }
        Ok(self.word(a))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access()?;
        self.ops.push(Op::Byte(a, v));
        self.words.insert(a, u32::from(v));
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.access()?;
        self.ops.push(Op::Short(a, v));
        self.words.insert(a, u32::from(v));
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        self.ops.push(Op::Word(a, v));
        self.words.insert(a, v);
        if a == 0x30 {
            self.request = Some(v & 0xffff)
        }
        Ok(())
    }
    fn poll32(&mut self, a: u32, mask: u32, want: u32, us: u64) -> Result<(), power::Error> {
        self.access()?;
        if (a, mask, want, us) != (0x30, 0x2000_0000, 0x2000_0000, 1_000_000)
            || self.request.is_none()
        {
            return Err(power::Error::Access);
        }
        self.words.insert(a, self.word(a) | 0x2000_0000);
        Ok(())
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        self.access()?;
        self.ops.push(Op::Delay(us));
        Ok(())
    }
}
fn smoke_rtw8922a_checked_efuse_literal_width_order_and_first_error() -> TestResult {
    let mut io = Model::new();
    io.physical[0x1700..0x1704].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    let mut out = [0; 4];
    kt_assert_eq!(dump(&mut io, false, 0x1700, &mut out), Ok(()));
    kt_assert_eq!(out, [0x11, 0x22, 0x33, 0x44]);
    kt_assert_eq!(
        io.ops,
        vec![
            Op::Word(0x68, 0),
            Op::Byte(0xcc, 4),
            Op::Short(0, 0x4000),
            Op::Delay(1000),
            Op::Short(0, 0xc000),
            Op::Short(0, 0xc000),
            Op::Word(0xa4, 0x80000),
            Op::Word(0x30, 0x1700),
            Op::Short(0, 0xc100),
            Op::Short(0, 0x4100),
            Op::Delay(1000),
            Op::Short(0, 0x100),
            Op::Byte(0xcc, 0),
            Op::Word(0xa4, 0),
            Op::Word(0x68, 0x10000)
        ]
    );
    for at in 1..=io.accesses {
        let mut bad = Model::new();
        bad.fault_at = Some(at);
        kt_assert_eq!(
            dump(&mut bad, false, 0x1700, &mut [0; 4]),
            Err(Error::Io(power::Error::Access))
        );
        let effects = bad.ops.len();
        kt_assert_eq!(bad.current(), Err(power::Error::Access));
        kt_assert_eq!(bad.ops.len(), effects);
    }
    let mut cav = Model::new();
    kt_assert_eq!(dump(&mut cav, true, 0x1700, &mut [0; 4]), Ok(()));
    kt_assert!(cav
        .ops
        .iter()
        .all(|op| !matches!(op, Op::Short(..) | Op::Delay(..))));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_efuse_literal_width_order_and_first_error
);
fn smoke_rtw8922a_checked_factory_erased_data_and_failed_cv_are_distinct() -> TestResult {
    let mut io = Model::new();
    let factory = match read(&mut io, 1) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("checked erased factory read"),
    };
    kt_assert_eq!(factory.mac, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
    kt_assert_eq!(factory.cv, None);
    kt_assert_eq!(factory.thermal_k, None);
    kt_assert!(!factory.secure.secure_boot);
    let mut cv = Model::new();
    cv.fail_data = Some(0x17c8);
    kt_assert!(matches!(
        read(&mut cv, 1),
        Err(Error::Io(power::Error::Access))
    ));
    let mut mac = Model::new();
    mac.words.insert(0x3104, 0);
    mac.words.insert(0x3106, 0);
    mac.words.insert(0x3108, 0);
    kt_assert!(matches!(read(&mut mac, 1), Err(Error::Mac)));
    TestResult::Pass
}
fn smoke_rtw8922a_checked_ecv_precedes_maps_and_corrects_power_cut() -> TestResult {
    for (raw_cut, ecv) in [(1, 0), (0, 1)] {
        let mut io = Model::new();
        io.physical[0x17ca] = ecv << 4;
        let snapshot = match read_all(&mut io, raw_cut) {
            Ok(snapshot) => snapshot,
            Err(_) => return TestResult::Fail("actual checked ECV/map read"),
        };
        kt_assert_eq!(snapshot.factory.cv, Some(ecv));
        let requests: Vec<_> = io
            .ops
            .iter()
            .filter_map(|op| {
                if let Op::Word(0x30, address) = op {
                    Some(*address)
                } else {
                    None
                }
            })
            .collect();
        kt_assert_eq!(&requests[..2], &[0x17c8, 0]);
        // Partition at the second dump request. The source corrected-cut
        // branch controls all subsequent EFUSE power transitions, including
        // the setup immediately preceding the physical-map address zero.
        let first_end = io
            .ops
            .iter()
            .position(|op| *op == Op::Word(0x68, 0x10000))
            .unwrap()
            + 1;
        let first_has_short = io.ops[..first_end]
            .iter()
            .any(|op| matches!(op, Op::Short(0, _)));
        let later_has_short = io.ops[first_end..]
            .iter()
            .any(|op| matches!(op, Op::Short(0, _)));
        kt_assert_eq!(first_has_short, raw_cut != 0);
        kt_assert_eq!(later_has_short, ecv != 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_ecv_precedes_maps_and_corrects_power_cut
);
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_factory_erased_data_and_failed_cv_are_distinct
);
fn smoke_rtw8922a_checked_efuse_native_erasure_current_and_closure() -> TestResult {
    let mut words = vec![0u32; 0x40000 / 4];
    words[0x24 / 4] = 0x1f00_0000;
    words[0x84 / 4] = 0x0201_0000;
    words[0x88 / 4] = 0x802;
    words[0x10000 / 4] = 0xc000_01ff;
    words[0x34 / 4] = u32::MAX;
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x40000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    // SAFETY: exclusive aligned RAM model with the exact closed power tuple.
    let mut io = unsafe { Native::new(&region, &cap) };
    kt_assert_eq!(io.read32(0x34), Ok(u32::MAX));
    kt_assert_eq!(io.write32(0x30, 0x1700), Ok(()));
    cap.revoke();
    kt_assert_eq!(io.write32(0x30, 0x1704), Err(power::Error::Access));
    kt_assert_eq!(words[0x30 / 4], 0x1700);
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    words[0x10000 / 4] |= 0x1000_0000;
    // SAFETY: private RAM model deliberately presents an open packet gate.
    let mut denied = unsafe { Native::new(&region, &cap) };
    kt_assert_eq!(denied.write32(0x30, 0x1708), Err(power::Error::Access));
    kt_assert_eq!(words[0x30 / 4], 0x1700);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_efuse_native_erasure_current_and_closure
);
