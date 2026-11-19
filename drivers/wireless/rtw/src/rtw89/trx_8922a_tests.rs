// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Source protocol model: readiness changes only on its actual request edge.
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effect {
    Byte(u32, u8),
    Short(u32, u16),
    Word(u32, u32),
}
#[derive(Clone)]
struct Model {
    words: BTreeMap<u32, u32>,
    effects: Vec<Effect>,
    accesses: usize,
    fail_at: Option<usize>,
    failed: bool,
    drop_address: Option<u32>,
    stuck_cam: bool,
    pending_cam: bool,
    pending_ba: bool,
    mlo_requested: bool,
    unsafe_effect: bool,
    bad_accounting: bool,
    binding: cold::Binding,
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
                (0x24, 0x1f00_0000),
                (0x84, 0x0201_0003),
                (0x88, 2),
                (0x8400, 0x7fff_4f80),
                (0x10000, 0xc000_01ff),
                (0xb010, 0x8000_7fff),
                (0xb000, 0x80),
            ]
            .into_iter()
            .collect(),
            effects: Vec::new(),
            accesses: 0,
            fail_at: None,
            failed: false,
            drop_address: None,
            stuck_cam: false,
            pending_cam: false,
            pending_ba: false,
            mlo_requested: false,
            unsafe_effect: false,
            bad_accounting: false,
            binding: cold::Binding::observe(&region, &cap),
        }
    }
    fn word(&self, a: u32) -> u32 {
        self.words.get(&(a & !3)).copied().unwrap_or(0)
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
    fn effect(&mut self, a: u32, v: u32) {
        self.unsafe_effect |= self.word(0x10000) & 0x3000_0000 != 0
            || self.word(0xb010) & 0x8000_7fff != 0x8000_7fff
            || self.word(0xb000) & 0xb0 != 0x80
            || self.word(0x24) & 0x1f00_001f != 0x1f00_0000
            || self.word(0x84) & 0x0303_0303 != 0x0201_0003;
        if self.drop_address == Some(a) {
            return;
        }
        self.words.insert(a, v);
        match a {
            0x8400 => {
                let ready = if v & 0x0480_0000 == 0x0480_0000 { 3 } else { 0 };
                self.words.insert(0x8d00, ready);
                self.words.insert(0x9100, ready);
            }
            0xa310 if v & 1 != 0 => {
                self.words.insert(a, v | 0x8000_0000);
            }
            0xa114 if v & 0x0080_0000 != 0 => self.mlo_requested = true,
            0xa114 if self.mlo_requested => {
                self.words.insert(a, v | 0x8000_0000);
            }
            0x11434 if v & 0x100 != 0 => self.pending_cam = true,
            0x1143c if v & 3 == 2 => self.pending_ba = true,
            0xb700 if v & 9 == 9 => {
                self.words
                    .insert(0xb7a0, if self.bad_accounting { 3301 } else { 3302 });
            }
            _ => {}
        }
    }
}
impl Regs for Model {
    fn binding(&self) -> cold::Binding {
        self.binding
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.access()
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok((self.word(a) >> ((a & 3) * 8)) as u8)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.access()?;
        if a == 0x11434 && self.pending_cam && !self.stuck_cam {
            self.words.insert(a, self.word(a) & !0x100);
            self.pending_cam = false;
        }
        Ok((self.word(a) >> ((a & 3) * 8)) as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        Ok(self.word(a))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access()?;
        self.effects.push(Effect::Byte(a, v));
        let shift = (a & 3) * 8;
        self.effect(
            a & !3,
            (self.word(a) & !(0xff << shift)) | (u32::from(v) << shift),
        );
        Ok(())
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.access()?;
        self.effects.push(Effect::Short(a, v));
        let shift = (a & 3) * 8;
        self.effect(
            a & !3,
            (self.word(a) & !(0xffff << shift)) | (u32::from(v) << shift),
        );
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        self.effects.push(Effect::Word(a, v));
        self.effect(a, v);
        Ok(())
    }
    fn poll32(&mut self, a: u32, mask: u32, want: u32, us: u64) -> Result<(), power::Error> {
        self.access()?;
        if !(1..=2000).contains(&us) {
            return Err(power::Error::Access);
        }
        if a == 0x1143c && self.pending_ba {
            self.words.insert(a, self.word(a) & !3);
            self.pending_ba = false;
        }
        if self.word(a) & mask == want {
            Ok(())
        } else {
            Err(power::Error::Timeout)
        }
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        self.access()?;
        if us == 10 {
            Ok(())
        } else {
            Err(power::Error::Access)
        }
    }
}
fn configure(io: &mut Model, trx: &mut Trx, cv: u8) -> Result<(), Error> {
    // SAFETY: exclusively owned inert source protocol model, no real device,
    // DMA, reset, IRQ or producer. This mints no native readiness receipt.
    unsafe { trx.configure(io, cv) }
}
fn smoke_rtw8922a_trx_literal_scc_quota_hfc_and_closed_protocol() -> TestResult {
    let mut io = Model::new();
    let mut trx = Trx::default();
    kt_assert_eq!(configure(&mut io, &mut trx, 0), Ok(()));
    kt_assert_eq!(trx.state(), State::ConfiguredClosed);
    kt_assert!(!io.unsafe_effect);
    // mac.c wde_size0_v1, ple_size0_v1, wde_qt0_v1, ple_qt0/1;
    // rtw8922a.c PCIe SCC selects this exact carve (589824 bytes).
    kt_assert_eq!(
        &io.effects[..23],
        &[
            Effect::Word(0x8400, 0x7b7f_4f80),
            Effect::Word(0x8404, 0x0480_0000),
            Effect::Word(0x8c08, 0x0d00_0000),
            Effect::Word(0x9008, 0x0a80_1a01),
            Effect::Word(0x8c40, 0x0ce6_0ce6),
            Effect::Word(0x8c44, 0x0006_0006),
            Effect::Word(0x8c48, 0),
            Effect::Word(0x8c4c, 0),
            Effect::Word(0x8c50, 0x0014_0014),
            Effect::Word(0x9040, 0x0140_0140),
            Effect::Word(0x9044, 0x0140_0140),
            Effect::Word(0x9048, 0x0020_0020),
            Effect::Word(0x904c, 0x0010_0010),
            Effect::Word(0x9050, 0x0524_000d),
            Effect::Word(0x9054, 0x0524_000d),
            Effect::Word(0x9058, 0x063b_0124),
            Effect::Word(0x905c, 0x063b_0124),
            Effect::Word(0x9060, 0x0557_0040),
            Effect::Word(0x9064, 0x0529_0012),
            Effect::Word(0x9068, 0x0001_0001),
            Effect::Word(0x906c, 0x051b_0004),
            Effect::Word(0x9070, 0),
            Effect::Word(0x8400, 0x7fff_4f80)
        ]
    );
    // HFC c0 fields: precost2/32; all four full-condition fields zero.
    kt_assert!(io.effects.contains(&Effect::Word(0xb790, 0x0673_0673)));
    kt_assert!(io.effects.contains(&Effect::Word(0xb704, 0x0020_0002)));
    kt_assert_eq!(io.word(0xb700) & 0xfff, 9);
    kt_assert_eq!(io.word(0xb718), 0x0669_0002);
    kt_assert_eq!(io.word(0xb728), 0x8669_0002);
    // Source default filter, SCC MPDU/CSI reservation and report geometry.
    kt_assert_eq!(io.word(0x11420), 0x0f17_40be);
    kt_assert_eq!(io.word(0x9f10), 0x8a80_0012);
    kt_assert_eq!(io.word(0x11810), 0x006c_0a82);
    kt_assert_eq!(io.word(0x9444), 0x0fff_001e);
    kt_assert_eq!(io.word(0x10160), u32::MAX);
    kt_assert_eq!(io.word(0x10000) & 0x3000_0000, 0);
    kt_assert_eq!(io.word(0xb010), 0x8000_7fff);
    let effects = io.effects.len();
    kt_assert_eq!(configure(&mut io, &mut trx, 0), Err(Error::State));
    kt_assert_eq!(io.effects.len(), effects);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_trx_literal_scc_quota_hfc_and_closed_protocol
);
fn smoke_rtw8922a_trx_refusal_at_each_access_keeps_packet_and_dma_closure() -> TestResult {
    let template = Model::new();
    let mut reference = template.clone();
    kt_assert_eq!(configure(&mut reference, &mut Trx::default(), 1), Ok(()));
    for at in 1..=reference.accesses {
        let mut io = template.clone();
        io.fail_at = Some(at);
        let mut trx = Trx::default();
        kt_assert_eq!(
            configure(&mut io, &mut trx, 1),
            Err(Error::Io(power::Error::Access))
        );
        kt_assert_eq!(io.accesses, at);
        kt_assert!(!io.unsafe_effect);
        let effects = io.effects.len();
        kt_assert_eq!(configure(&mut io, &mut trx, 1), Err(Error::State));
        kt_assert_eq!(io.effects.len(), effects);
    }
    for (a, v) in [
        (0x24, 0x1e00_0000),
        (0x84, 0x0203_0003),
        (0x88, 0x802),
        (0x10000, 0xf000_01ff),
        (0xb010, 0x8000_6fff),
        (0xb000, 0x30),
        (0xb01c, 1),
    ] {
        let mut io = template.clone();
        io.words.insert(a, v);
        kt_assert!(configure(&mut io, &mut Trx::default(), 1).is_err());
        kt_assert!(io.effects.is_empty());
    }
    let mut dropped = template.clone();
    dropped.drop_address = Some(0xb718);
    kt_assert_eq!(
        configure(&mut dropped, &mut Trx::default(), 1),
        Err(Error::Readback(0xb718))
    );
    let mut bad = template.clone();
    bad.bad_accounting = true;
    kt_assert_eq!(
        configure(&mut bad, &mut Trx::default(), 1),
        Err(Error::Accounting)
    );
    kt_assert!(!bad
        .effects
        .iter()
        .any(|op| matches!(op, Effect::Byte(0xa310, _))));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_trx_refusal_at_each_access_keeps_packet_and_dma_closure
);
fn smoke_rtw8922a_trx_native_current_exact_source_surface_and_cancel() -> TestResult {
    let mut words = vec![0u32; 0x40000 / 4];
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x40000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let cancel = core::sync::atomic::AtomicBool::new(false);
    for (a, v) in [
        (0x14000, 0),
        (0x1c000, 0),
        (0xb010, 0),
        (0x10000, 0xf000_01ff),
    ] {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        // SAFETY: exclusive inert aligned RAM register model; no real device.
        let mut io = unsafe { Native::new(&region, &cap, &cancel) };
        kt_assert_eq!(io.write32(a, v), Err(power::Error::Access));
        kt_assert_eq!(io.write32(0x8c40, 1), Err(power::Error::Access));
    }
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    // SAFETY: exclusive inert aligned RAM model of the bounded source port.
    let mut io = unsafe { Native::new(&region, &cap, &cancel) };
    kt_assert_eq!(io.write32(0x8c40, 0x0ce6_0ce6), Ok(()));
    cap.revoke();
    kt_assert_eq!(io.write32(0x8c40, 0), Err(power::Error::Access));
    kt_assert_eq!(words[0x8c40 / 4], 0x0ce6_0ce6);
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    cancel.store(true, core::sync::atomic::Ordering::Release);
    // SAFETY: same inert RAM model; cancellation must deny before the effect.
    let mut denied = unsafe { Native::new(&region, &cap, &cancel) };
    kt_assert_eq!(denied.write32(0x8c40, 0), Err(power::Error::Access));
    kt_assert_eq!(words[0x8c40 / 4], 0x0ce6_0ce6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/8922a",
    smoke_rtw8922a_trx_native_current_exact_source_surface_and_cancel
);
