// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Native closure programs and first-failure ownership tests.
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Byte(u32, u8),
    Short(u32, u16),
    Word(u32, u32),
}
struct Model {
    words: BTreeMap<u32, u32>,
    writes: Vec<Op>,
    polls: Vec<(u32, u32, u32, u64)>,
    accesses: usize,
    failed: bool,
    fail_at: Option<usize>,
    drop_at: Option<usize>,
    unsafe_activation: bool,
    isolation_drops: bool,
    binding: Binding,
    xtal: BTreeMap<u8, u8>,
}
impl Model {
    fn warm() -> Self {
        Self {
            words: [
                (0x84, 0x0003_0303),
                (0x24, 0x1f00_001f),
                (0x88, 2),
                (0x10000, 0xf050_01ff),
                (0x14000, 0xf060_01ff),
                (0x4, 1 << 17),
                (0x3f0, 0),
            ]
            .into_iter()
            .collect(),
            writes: Vec::new(),
            polls: Vec::new(),
            accesses: 0,
            failed: false,
            fail_at: None,
            drop_at: None,
            unsafe_activation: false,
            isolation_drops: false,
            binding: Binding {
                slot: CapSlot::EMPTY,
                phys: 0,
                virt: 0,
                len: 0x40000,
            },
            xtal: BTreeMap::new(),
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
    fn bank(&mut self, a: u32) -> Result<(), power::Error> {
        if (0x14000..0x18000).contains(&a) {
            self.unsafe_activation = true;
            return Err(power::Error::Access);
        }
        if (0x10000..0x14000).contains(&a)
            && (self.word(0x24) & 0x1f00_0000 != 0x1f00_0000
                || self.word(0x84) & 0x0101_0000 != 0x0001_0000)
        {
            self.unsafe_activation = true;
            return Err(power::Error::Access);
        }
        Ok(())
    }
    fn effect(&mut self, a: u32, v: u32) {
        let old = self.word(a);
        // Any new BB release requires a powered, packet-closed MAC0 and
        // complete MAC1 power isolation, not an off-domain zero read.
        if a == 0x84 && v & !old & 0x303 != 0 {
            self.unsafe_activation |= self.word(0x24) & 0x1f00_001f != 0x1f00_0000
                || v & 0x0303_0000 != 0x0201_0000
                || self.word(0x10000) & 0x3000_0000 != 0;
        }
        if a == 0x88 && v & 2 != 0 && old & 2 == 0 && v & 0x800 == 0 {
            self.unsafe_activation = true;
        }
        if self.drop_at == Some(self.writes.len()) {
            return;
        }
        let mut v = v;
        if a == 0x84 && self.isolation_drops {
            v &= !0x0300_0000;
        }
        // HAXI/WLAN IO enable has distinct observed status bits.
        if a == 0x74 {
            v = (v & !0x8800_0000) | ((v & 0x0100_0000) << 3) | ((v & 0x1000_0000) << 3);
        }
        self.words.insert(a, v);
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
        self.bank(a)?;
        Ok((self.word(a & !3) >> ((a & 3) * 8)) as u8)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.access()?;
        self.bank(a)?;
        Ok((self.word(a & !3) >> ((a & 3) * 8)) as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        self.bank(a)?;
        Ok(self.word(a))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access()?;
        self.bank(a)?;
        self.writes.push(Op::Byte(a, v));
        let shift = (a & 3) * 8;
        self.effect(
            a & !3,
            (self.word(a & !3) & !(255 << shift)) | (u32::from(v) << shift),
        );
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.access()?;
        self.bank(a)?;
        self.writes.push(Op::Short(a, v));
        let shift = (a & 3) * 8;
        self.effect(
            a & !3,
            (self.word(a & !3) & !(65535 << shift)) | (u32::from(v) << shift),
        );
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        self.bank(a)?;
        self.writes.push(Op::Word(a, v));
        self.effect(a, v);
        Ok(())
    }
    fn poll32(&mut self, a: u32, m: u32, v: u32, us: u64) -> Result<(), power::Error> {
        self.access()?;
        self.polls.push((a, m, v, us));
        // Only documented self-clearing requests get hardware progress.
        match a {
            0xa0 if self.word(a) & 0x0400_0000 != 0 => {
                self.words.insert(a, self.word(a) & !0x1ff);
            }
            0x4 if m == 0x100 && self.word(a) & m != 0 => {
                self.words.insert(a, self.word(a) & !m);
            }
            0x270 if m == 0x8000_0000 && self.word(a) & m != 0 => {
                let cmd = self.word(a);
                let response = if cmd & 0x0300_0000 == 0x0100_0000 {
                    (cmd & !0x0000_ff00)
                        | (u32::from(*self.xtal.get(&(cmd as u8)).unwrap_or(&0)) << 8)
                } else {
                    cmd
                };
                self.words.insert(a, response & !m);
            }
            _ => {}
        }
        if self.word(a) & m == v {
            Ok(())
        } else {
            Err(power::Error::Timeout)
        }
    }
    fn delay_us(&mut self, _us: u64) -> Result<(), power::Error> {
        self.access()
    }
}
fn entry_program() -> Vec<Op> {
    vec![
        Op::Byte(0x84, 0),
        Op::Word(0x84, 0x0003_0000),
        Op::Word(0x88, 0),
        Op::Word(0x88, 0x800),
        Op::Word(0x88, 0x802),
        Op::Word(0x84, 0x0002_0000),
        Op::Word(0x84, 0x0102_0000),
        Op::Word(0x24, 0x1f),
        Op::Word(0x84, 0x0100_0000),
        Op::Word(0x84, 0x0300_0000),
        Op::Word(0x24, 0),
    ]
}
fn smoke_rtw8922a_cold_entry_literal_closure_and_first_failure() -> TestResult {
    let mut good = Model::warm();
    kt_assert_eq!(entry_close(&mut good), Ok(()));
    kt_assert_eq!(good.writes, entry_program());
    kt_assert_eq!(good.word(0x84), 0x0300_0000);
    kt_assert_eq!(good.word(0x10000) & 0x3000_0000, 0x3000_0000);
    kt_assert!(!good.unsafe_activation);
    for at in 1..=good.accesses {
        let mut bad = Model::warm();
        bad.fail_at = Some(at);
        kt_assert!(entry_close(&mut bad).is_err());
        let writes = bad.writes.clone();
        kt_assert_eq!(bad.current(), Err(power::Error::Access));
        kt_assert_eq!(bad.writes, writes);
        kt_assert!(!bad.unsafe_activation);
    }
    for at in 1..=11 {
        let mut dropped = Model::warm();
        dropped.drop_at = Some(at);
        kt_assert!(entry_close(&mut dropped).is_err());
        kt_assert!(!dropped.unsafe_activation);
    }
    let mut off_zero = Model::warm();
    off_zero.isolation_drops = true;
    kt_assert!(entry_close(&mut off_zero).is_err());
    kt_assert!(off_zero
        .writes
        .iter()
        .all(|op| !matches!(op, Op::Word(0x10000 | 0x10004, _))));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_cold_entry_literal_closure_and_first_failure
);
fn smoke_rtw8922a_checked_identity_observes_xtal_not_defaults() -> TestResult {
    let mut io = Model::warm();
    let mut cold = Cold::default();
    // SAFETY: inert exclusive register model; no hardware or DMA exists.
    let powered = unsafe { cold.power_on(&mut io, 1) };
    kt_assert_eq!(powered, Ok(()));
    io.xtal.extend([(0x41, 0xb3), (0xfd, 0x34), (0xfe, 0x12)]);
    io.words.insert(0xfc, 0x56);
    let before = io.writes.len();
    let start_access = io.accesses;
    kt_assert_eq!(
        cold.chip_version(&mut io),
        Ok(p::HalChipVer {
            cv: 1,
            acv: 3,
            cid: p::Cid::Unknown(0x56),
            aid: 0x1234,
        })
    );
    kt_assert_eq!(
        &io.writes[before..],
        &[
            Op::Word(0x270, 0x8100_0041),
            Op::Word(0x270, 0x8100_00fd),
            Op::Word(0x270, 0x8100_00fe),
        ]
    );
    kt_assert_eq!(cold.state(), State::ClosedPower);
    kt_assert_eq!(io.word(0x10000) & 0x3000_0000, 0);
    let identity_accesses = io.accesses - start_access;
    for at in 1..=identity_accesses {
        let mut bad = Model::warm();
        let mut owner = Cold::default();
        // SAFETY: independent inert register model with no hardware or DMA.
        let powered = unsafe { owner.power_on(&mut bad, 1) };
        kt_assert_eq!(powered, Ok(()));
        bad.fail_at = Some(bad.accesses + at);
        kt_assert!(owner.chip_version(&mut bad).is_err());
        let effects = bad.writes.len();
        kt_assert_eq!(owner.chip_version(&mut bad), Err(Error::Terminal));
        kt_assert_eq!(bad.writes.len(), effects);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_checked_identity_observes_xtal_not_defaults
);
fn smoke_rtw8922a_cold_power_and_bb_prefix_keep_packet_closure() -> TestResult {
    let mut model = Model::warm();
    let mut cold = Cold::default();
    kt_assert_eq!(
        // SAFETY: inert exclusive register model, no live DMA or function.
        unsafe { cold.power_on(&mut model, 0) },
        Ok(())
    );
    kt_assert_eq!(cold.state(), State::ClosedPower);
    kt_assert_eq!(&model.writes[..11], &entry_program());
    kt_assert_eq!(model.writes[11], Op::Word(0xa0, 0x0400_0000));
    kt_assert_eq!(model.word(0x10000), 0xc050_01ff);
    kt_assert_eq!(model.word(0x10004) & 0x4000_01ff, 0x4000_01ff);
    kt_assert_eq!(model.word(0x84) & 0x303, 0);
    kt_assert_eq!(model.word(0x24) & 0x1f00_001f, 0x1f00_0000);
    kt_assert_eq!(cold.prepare_bbmcu0(&mut model), Ok(()));
    kt_assert_eq!(cold.state(), State::BbMcu0Prepared);
    kt_assert_eq!(model.word(0x84) & 0x303, 2);
    kt_assert_eq!(model.word(0x10000) & 0x3000_0000, 0);
    kt_assert!(!model.unsafe_activation);
    let attempts = model.accesses;
    let writes = model.writes.clone();
    kt_assert_eq!(cold.prepare_bbmcu0(&mut model), Err(Error::Terminal));
    kt_assert_eq!(model.accesses, attempts);
    kt_assert_eq!(model.writes, writes);
    let writes = model.writes.len();
    kt_assert_eq!(
        cold.native_download_boundary(&mut model),
        Err(Error::MissingDmaBridge)
    );
    kt_assert_eq!(cold.state(), State::Failed(Error::MissingDmaBridge));
    kt_assert_eq!(model.writes.len(), writes);
    kt_assert_eq!(model.word(0x10000) & 0x3000_0000, 0);
    for at in 1..=attempts {
        let mut bad = Model::warm();
        bad.fail_at = Some(at);
        let mut owner = Cold::default();
        // SAFETY: inert exclusive model injects a single access failure.
        let result =
            unsafe { owner.power_on(&mut bad, 0) }.and_then(|()| owner.prepare_bbmcu0(&mut bad));
        kt_assert!(result.is_err());
        kt_assert!(matches!(owner.state(), State::Failed(_)));
        kt_assert!(!bad.unsafe_activation);
        let count = bad.writes.len();
        kt_assert_eq!(owner.prepare_bbmcu0(&mut bad), Err(Error::Terminal));
        kt_assert_eq!(bad.writes.len(), count);
    }
    let mut other = Model::warm();
    let mut original = Cold::default();
    kt_assert_eq!(
        // SAFETY: separate inert exclusive model, no published DMA.
        unsafe { original.power_on(&mut other, 0) },
        Ok(())
    );
    let writes = other.writes.len();
    other.binding.virt = 4; // Represents a different mapped BAR, not a new receipt.
    kt_assert_eq!(original.prepare_bbmcu0(&mut other), Err(Error::Identity));
    kt_assert_eq!(original.state(), State::Failed(Error::Identity));
    kt_assert_eq!(other.writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_cold_power_and_bb_prefix_keep_packet_closure
);
fn smoke_rtw8922a_cold_native_access_is_latched_and_current() -> TestResult {
    let mut words = vec![0u32; 0x40000 / 4];
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x40000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    for (a, w) in [(0x14000, 4), (0xb010, 4), (0x10001, 4), (0x85, 1)] {
        // SAFETY: one private aligned RAM mapping, tested port is exclusive.
        let mut io = unsafe { NativeRegs::new(&region, &cap) };
        let result = if w == 1 {
            io.write8(a, 1)
        } else {
            io.write32(a, 1)
        };
        kt_assert_eq!(result, Err(power::Error::Access));
        kt_assert_eq!(io.write32(0x84, 3), Err(power::Error::Access));
        kt_assert_eq!(words[0x84 / 4], 0);
    }
    // SAFETY: private aligned RAM, no hardware or concurrent mapping user.
    let mut packet = unsafe { NativeRegs::new(&region, &cap) };
    kt_assert_eq!(
        packet.write32(0x10000, 0x3000_0000),
        Err(power::Error::Access)
    );
    kt_assert_eq!(words[0x10000 / 4], 0);
    let mut short = region;
    short.len = 0x84;
    // SAFETY: private RAM mapping, deliberately shortened checked extent.
    let mut bounded = unsafe { NativeRegs::new(&short, &cap) };
    kt_assert_eq!(bounded.read32(0x84), Err(power::Error::Access));
    words[0x84 / 4] = u32::MAX;
    // SAFETY: private aligned RAM mapping, now models a gone common bank.
    let mut gone = unsafe { NativeRegs::new(&region, &cap) };
    kt_assert_eq!(gone.read32(0x84), Err(power::Error::Gone));
    kt_assert_eq!(gone.write32(0x84, 0), Err(power::Error::Gone));
    words[0x84 / 4] = 0;
    // SAFETY: private aligned RAM mapping remains exclusive to this port.
    let mut io = unsafe { NativeRegs::new(&region, &cap) };
    kt_assert_eq!(io.write32(0x84, 0x0300_0000), Ok(()));
    kt_assert_eq!(words[0x84 / 4], 0x0300_0000);
    cap.revoke();
    kt_assert_eq!(io.write32(0x84, 0), Err(power::Error::Access));
    kt_assert_eq!(words[0x84 / 4], 0x0300_0000);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_cold_native_access_is_latched_and_current
);

fn smoke_rtw8922a_fresh_boot_status_clear_requires_observed_cpu_hold() -> TestResult {
    let model = || {
        let mut io = Model::warm();
        io.words.insert(0x88, 2);
        io.words.insert(0x1e0, 0xcc00_0a03);
        io
    };
    let mut io = model();
    kt_assert_eq!(disable_cpu(&mut io), Ok(()));
    kt_assert_eq!(
        &io.writes[..4],
        &[
            Op::Word(0x88, 0),
            Op::Word(0x88, 0x800),
            Op::Word(0x88, 0x802),
            Op::Word(0x1e0, 0xc000_0000)
        ]
    );
    kt_assert_eq!(io.word(0x1e0), 0xc000_0000);
    kt_assert_eq!(io.word(0x88) & 0x802, 0x802);
    for at in 1..=4 {
        let mut refused = model();
        refused.drop_at = Some(at);
        let address = if at == 4 { 0x1e0 } else { 0x88 };
        kt_assert_eq!(disable_cpu(&mut refused), Err(Error::Readback(address)));
        kt_assert_eq!(refused.writes.len(), at);
    }
    // A previous loader becoming ready after that clear cannot authorize
    // this attempt: fresh path/status must still be zero before CPU release.
    io.words.insert(0x1e0, 0xcc00_0003);
    let before = io.writes.len();
    kt_assert!(matches!(enable_wcpu(&mut io), Err(Error::Readback(0x1e0))));
    kt_assert_eq!(io.writes.len(), before + 1);
    kt_assert_eq!(io.word(0x88) & 0x802, 0x802);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_fresh_boot_status_clear_requires_observed_cpu_hold
);
