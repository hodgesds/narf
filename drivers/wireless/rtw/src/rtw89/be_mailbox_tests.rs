// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use crate::rtw89::cold_8922a::Binding;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Byte(u32, u8),
    Word(u32, u32),
}
struct Model {
    words: BTreeMap<u32, u32>,
    ops: Vec<Op>,
    count: usize,
    fail_at: Option<usize>,
    failed: bool,
    wrong_part: bool,
    drop_part1: bool,
    binding: Binding,
}
impl Model {
    fn new() -> Self {
        let region = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x40000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let cap =
            narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
        Self {
            words: [(0x3f0, 0x02200000)].into_iter().collect(),
            ops: Vec::new(),
            count: 0,
            fail_at: None,
            failed: false,
            wrong_part: false,
            drop_part1: false,
            binding: Binding::observe(&region, &cap),
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        if self.failed {
            return Err(power::Error::Access);
        }
        self.count += 1;
        if self.fail_at == Some(self.count) {
            self.failed = true;
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn word(&self, a: u32) -> u32 {
        *self.words.get(&a).unwrap_or(&0)
    }
}
impl Regs for Model {
    fn binding(&self) -> Binding {
        self.binding
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.access()
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(self.word(a) as u8)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        Ok(self.word(a))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access()?;
        self.ops.push(Op::Byte(a, v));
        self.words.insert(a, u32::from(v));
        // The actual source trigger consumes H2CREG and publishes a new reply.
        // Merely writing DATA, converting EFUSE state or reading a register
        // cannot create either hardware receipt in this model.
        if a == 0x7160 && v == 1 {
            let part = (self.word(0x7140) >> 16) & 255;
            let words = if part == 0 {
                [
                    if self.wrong_part { 0x2040c } else { 0x20403 },
                    0x402,
                    0,
                    0x20200,
                ]
            } else {
                [0x40c, 0, 3, 0]
            };
            for (i, v) in words.into_iter().enumerate() {
                self.words.insert(0x7150 + i as u32 * 4, v);
            }
            self.words.insert(0x7160, 0);
            self.words.insert(0x7164, 1);
        }
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        self.ops.push(Op::Word(a, v));
        if !(self.drop_part1 && a == 0x7140 && v == 0x10103) {
            self.words.insert(a, v);
        }
        Ok(())
    }
    fn poll32(&mut self, _: u32, _: u32, _: u32, _: u64) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn delay_us(&mut self, _: u64) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
}
impl Interface for Model {
    fn active(&mut self) -> Result<(), power::Error> {
        self.access()
    }
}
fn smoke_rtw8922a_mailbox_get_feature_literal_parts_and_terminal_errors() -> TestResult {
    let features = Features::fixture([0, 35, 54, 0]);
    let mut io = Model::new();
    let mut mailbox = Mailbox::default();
    let receipt = mailbox.query(&mut io, features, 0x8922).unwrap();
    kt_assert_eq!(receipt.topology(), (2, 2, 3, 3, false));
    kt_assert!(!receipt.no_eht());
    kt_assert!(!receipt.no_mcs_12_13());
    kt_assert_eq!(mailbox.state(), State::Complete);
    kt_assert_eq!(
        io.ops,
        vec![
            Op::Word(0x68, 0),
            Op::Word(0x7140, 0x103),
            Op::Word(0x7144, 0),
            Op::Word(0x7148, 0),
            Op::Word(0x714c, 0),
            Op::Byte(0x1f5, 1),
            Op::Byte(0x7160, 1),
            Op::Byte(0x7164, 0),
            Op::Byte(0x1f5, 0x11),
            Op::Word(0x68, 0x10000),
            Op::Word(0x68, 0),
            Op::Word(0x7140, 0x10103),
            Op::Word(0x7144, 0),
            Op::Word(0x7148, 0),
            Op::Word(0x714c, 0),
            Op::Byte(0x1f5, 0x12),
            Op::Byte(0x7160, 1),
            Op::Byte(0x7164, 0),
            Op::Byte(0x1f5, 0x22),
            Op::Word(0x68, 0x10000),
        ]
    );
    for at in 1..=io.count {
        let mut bad = Model::new();
        bad.fail_at = Some(at);
        let mut retained = Mailbox::default();
        kt_assert!(retained.query(&mut bad, features, 0x8922).is_err());
        kt_assert_eq!(retained.state(), State::Pending);
        let effects = bad.ops.len();
        kt_assert!(matches!(
            retained.query(&mut bad, features, 0x8922),
            Err(power::Error::Terminal)
        ));
        kt_assert_eq!(bad.ops.len(), effects);
    }
    let mut stale = Model::new();
    stale.words.insert(0x7164, 1);
    kt_assert!(Mailbox::default()
        .query(&mut stale, features, 0x8922)
        .is_err());
    kt_assert_eq!(stale.ops, vec![Op::Word(0x68, 0)]);
    let mut wrong = Model::new();
    wrong.wrong_part = true;
    kt_assert!(Mailbox::default()
        .query(&mut wrong, features, 0x8922)
        .is_err());
    kt_assert_eq!(wrong.ops.last(), Some(&Op::Byte(0x1f5, 0x11)));
    let mut dropped = Model::new();
    dropped.drop_part1 = true;
    kt_assert!(Mailbox::default()
        .query(&mut dropped, features, 0x8922)
        .is_err());
    kt_assert_eq!(dropped.ops.last(), Some(&Op::Word(0x7140, 0x10103)));
    kt_assert_eq!(
        dropped
            .ops
            .iter()
            .filter(|op| **op == Op::Byte(0x7160, 1))
            .count(),
        1
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_mailbox_get_feature_literal_parts_and_terminal_errors
);
fn smoke_rtw8922a_mailbox_source_variants_feature_boundary_and_capability_binding() -> TestResult {
    let old = Features::fixture([0, 35, 50, 255]);
    let current = Features::fixture([0, 35, 54, 0]);
    kt_assert!(!old.phycap_part1());
    kt_assert!(Features::fixture([0, 35, 51, 0]).phycap_part1());
    kt_assert!(!Features::fixture([0, 35, 53, 255]).supports_device(0x892b));
    kt_assert!(current.supports_device(0x892b));
    let mut model = Model::new();
    let receipt = Mailbox::default().query(&mut model, old, 0x8922).unwrap();
    kt_assert_eq!(receipt.words().1, None);
    kt_assert_eq!(
        model
            .ops
            .iter()
            .filter(|op| **op == Op::Byte(0x7160, 1))
            .count(),
        1
    );
    let mut unsupported = Model::new();
    kt_assert!(matches!(
        Mailbox::default().query(&mut unsupported, old, 0x892b),
        Err(power::Error::Unsupported)
    ));
    kt_assert!(unsupported.ops.is_empty());
    let p0 = [0x20403, 0x402, 0, 0x20200];
    for (device, qam, limited) in [
        (0x8922, 0, false),
        (0x8922, 1, true),
        (0x8922, 2, true),
        (0x8922, 3, false),
        (0x892b, 3, true),
    ] {
        let receipt = Receipt::decode(p0, Some([0x40c, 0, qam, 0]), current, device).unwrap();
        kt_assert_eq!(receipt.no_mcs_12_13(), limited);
    }
    let bind = |receipt: &Receipt| {
        let mut hash = narf_crypto::sha256::Sha256::new();
        receipt.bind(&mut hash);
        hash.finalize()
    };
    let base = Receipt::decode(p0, Some([0x40c, 0, 3, 0]), current, 0x8922).unwrap();
    let transaction = Receipt::decode(
        [p0[0] | 0xf080, p0[1], p0[2], p0[3]],
        Some([0x40c | 0x7080, 0, 3, 0]),
        current,
        0x8922,
    )
    .unwrap();
    kt_assert_eq!(bind(&base), bind(&transaction));
    let variant = Receipt::decode(p0, Some([0x40c, 0, 3, 0]), current, 0x892b).unwrap();
    kt_assert!(bind(&base) != bind(&variant));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_mailbox_source_variants_feature_boundary_and_capability_binding
);
