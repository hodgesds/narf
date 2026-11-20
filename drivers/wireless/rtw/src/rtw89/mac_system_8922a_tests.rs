// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteOp {
    Byte(u32, u8),
    Word(u32, u32),
}
struct Model {
    words: BTreeMap<u32, u32>,
    writes: Vec<WriteOp>,
    accesses: usize,
    fail_at: Option<usize>,
    corrupt: Option<u32>,
    drop_byte: bool,
    gone_after_byte: bool,
    byte_written: bool,
    unsafe_activation: bool,
}
impl Model {
    fn new(warm: bool) -> Self {
        let mut words = BTreeMap::new();
        words.insert(0xb010, 0x8000_6fff); // CH12-only TX authority.
        words.insert(0xb000, 0x0e00_603c); // Global DMA state is preserved.
        words.insert(0x0024, 0x1f20_0040);
        words.insert(0x0084, if warm { 0x2201_0053 } else { 0x2201_0052 });
        words.insert(0x10000, if warm { 0xf050_01ff } else { 0x0050_0000 });
        words.insert(0x10004, 0x0000_c000);
        // Neither the 8922A no-op hooks nor MAC1, DLE, HFC or IMRs belong
        // to this stage. Sentinel values make accidental writes observable.
        words.insert(0x8400, 0x1234_5678);
        words.insert(0xe000, 0x2345_6789);
        words.insert(0x14000, 0x3456_789a);
        words.insert(0x14004, 0x4567_89ab);
        Self {
            words,
            writes: Vec::new(),
            accesses: 0,
            fail_at: None,
            corrupt: None,
            drop_byte: false,
            gone_after_byte: false,
            byte_written: false,
            unsafe_activation: false,
        }
    }
    fn observe_activation(&mut self, address: u32) {
        // The initial packet-closure write is the only effect allowed
        // while inherited packet gates are set. All later activation
        // writes require MAC0 gates clear and MAC1 power off.
        if address != 0x10000 {
            let gates = self.words.get(&0x10000).copied().unwrap_or(0);
            let fen = self.words.get(&0x0084).copied().unwrap_or(0);
            let afe = self.words.get(&0x0024).copied().unwrap_or(0);
            self.unsafe_activation |= gates & 0x3000_0000 != 0
                || fen & 0x0303_0000 != 0x0201_0000
                || afe & 0x1f00_001f != 0x1f00_0000;
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        self.accesses += 1;
        if self.fail_at == Some(self.accesses) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
}
impl Regs for Model {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(if self.gone_after_byte && self.byte_written {
            u8::MAX
        } else {
            self.words.get(&address).copied().unwrap_or(0) as u8
        })
    }
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        self.access()?;
        self.writes.push(WriteOp::Byte(address, value));
        self.observe_activation(address);
        self.byte_written = true;
        let old = self.words.get(&address).copied().unwrap_or(0);
        if !self.drop_byte {
            self.words.insert(address, (old & !0xff) | u32::from(value));
        }
        Ok(())
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.access()?;
        Ok(self.words.get(&address).copied().unwrap_or(0))
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.access()?;
        self.writes.push(WriteOp::Word(address, value));
        self.observe_activation(address);
        if self.corrupt != Some(address) {
            self.words.insert(address, value);
        }
        Ok(())
    }
}

fn configure_model(system: &mut System, regs: &mut impl Regs) -> Result<(), Error> {
    // SAFETY: every caller owns a private inert register model exclusively;
    // no physical device, concurrent reset or ordinary producer can run.
    unsafe { system.configure(regs) }
}

fn smoke_rtw8922a_system_source_order_closed_cold_and_warm() -> TestResult {
    for warm in [false, true] {
        let mut model = Model::new(warm);
        let mut system = System::default();
        // SAFETY: private inert register model; no DMA, reset or producer.
        kt_assert_eq!(configure_model(&mut system, &mut model), Ok(()));
        kt_assert_eq!(system.state(), State::SystemConfigured);
        // MAC0 power is already released and MAC1 is off in both cases.
        // Native packet closure is the first effect, before the source BB
        // hook, idempotent MAC0 power writes, clocks and structural functions.
        kt_assert_eq!(
            model.writes.as_slice(),
            &[
                WriteOp::Word(0x10000, if warm { 0xc050_01ff } else { 0x0050_0000 }),
                WriteOp::Byte(0x0084, 0x53),
                WriteOp::Word(0x842c, 0x7ff9_7ff9),
                WriteOp::Word(0x0024, 0x1f20_0040),
                WriteOp::Word(0x0084, 0x2201_0053),
                WriteOp::Word(0x0084, 0x2201_0053),
                WriteOp::Word(0x10004, 0x4000_c1ff),
                WriteOp::Word(0x10000, 0xc050_01ff),
            ]
        );
        kt_assert!(!model.unsafe_activation);
        kt_assert!(model.accesses > model.writes.len());
        kt_assert_eq!(model.words.get(&0xb010), Some(&0x8000_6fff));
        kt_assert_eq!(model.words.get(&0xb000), Some(&0x0e00_603c));
        kt_assert_eq!(model.words.get(&0x8400), Some(&0x1234_5678));
        kt_assert_eq!(model.words.get(&0xe000), Some(&0x2345_6789));
        kt_assert_eq!(model.words.get(&0x14000), Some(&0x3456_789a));
        kt_assert_eq!(model.words.get(&0x14004), Some(&0x4567_89ab));
        let accesses = model.accesses;
        // SAFETY: same inert exclusive model; repeated calls must refuse.
        kt_assert_eq!(
            configure_model(&mut system, &mut model),
            Err(Error::Terminal)
        );
        kt_assert_eq!(model.accesses, accesses);
    }
    TestResult::Pass
}

fn smoke_rtw8922a_system_failed_access_and_readback_are_terminal() -> TestResult {
    // Every access boundary, including readback and the final DMA observation.
    let mut reference = Model::new(true);
    kt_assert_eq!(
        configure_model(&mut System::default(), &mut reference),
        Ok(())
    );
    for fail_at in 1..=reference.accesses {
        let mut model = Model::new(true);
        model.fail_at = Some(fail_at);
        let mut system = System::default();
        // SAFETY: private inert model with an injected register-access failure.
        kt_assert_eq!(
            configure_model(&mut system, &mut model),
            Err(Error::Io(power::Error::Access))
        );
        kt_assert_eq!(
            system.state(),
            State::Failed(Error::Io(power::Error::Access))
        );
        kt_assert_eq!(model.accesses, fail_at);
        kt_assert!(!model.unsafe_activation);
        if !model.writes.is_empty() {
            kt_assert_eq!(
                model.words.get(&0x10000).copied().unwrap_or(0) & 0x3000_0000,
                0
            );
        }
        model.fail_at = None;
        // SAFETY: same exclusive model; a partial program cannot replay.
        kt_assert_eq!(
            configure_model(&mut system, &mut model),
            Err(Error::Terminal)
        );
        kt_assert_eq!(model.accesses, fail_at);
    }
    for address in [0x842c, 0x10000, 0x10004] {
        let mut model = Model::new(true);
        model.corrupt = Some(address);
        let mut system = System::default();
        // SAFETY: private inert model; the selected write is not acknowledged.
        kt_assert_eq!(
            configure_model(&mut system, &mut model),
            Err(Error::Readback(address))
        );
        kt_assert_eq!(system.state(), State::Failed(Error::Readback(address)));
        kt_assert!(!model.unsafe_activation);
        if address == 0x10000 {
            kt_assert_eq!(model.writes.len(), 1);
        }
    }
    for dma in [0x0000_6fff, 0x8000_7fff, 0x8000_6ffe] {
        let mut model = Model::new(false);
        model.words.insert(0xb010, dma);
        let mut system = System::default();
        // SAFETY: private model deliberately violates the DMA prerequisite.
        kt_assert_eq!(
            configure_model(&mut system, &mut model),
            Err(Error::DmaState)
        );
        kt_assert!(model.writes.is_empty());
    }
    let mut model = Model::new(false);
    model.words.insert(0xb010, u32::MAX);
    let mut system = System::default();
    // SAFETY: private inert model represents a removed device.
    kt_assert_eq!(
        configure_model(&mut system, &mut model),
        Err(Error::Io(power::Error::Gone))
    );
    kt_assert!(model.writes.is_empty());
    TestResult::Pass
}

fn smoke_rtw8922a_system_requires_released_mac0_and_closed_mac1() -> TestResult {
    for (fen, error) in [
        (0x2203_0052, Error::UnsupportedMac1),
        (0x2200_0052, Error::MacPowerRequired),
        (0x2301_0052, Error::MacPowerRequired),
        (0x2001_0052, Error::UnsupportedMac1), // MAC1 isolation not asserted.
    ] {
        let mut model = Model::new(true);
        model.words.insert(0x0084, fen);
        let mut system = System::default();
        kt_assert_eq!(configure_model(&mut system, &mut model), Err(error));
        kt_assert_eq!(system.state(), State::Failed(error));
        kt_assert!(model.writes.is_empty());
        kt_assert!(!model.unsafe_activation);
    }
    // Every individual AFE enable is load-bearing: MAC0 must have
    // all five set, and MAC1 must have all five clear, independently
    // of the apparently valid FEN/isolation receipt.
    for bit in 0..5 {
        for (afe, error) in [
            (0x1f20_0040 & !(1 << (24 + bit)), Error::MacPowerRequired),
            (0x1f20_0040 | (1 << bit), Error::UnsupportedMac1),
        ] {
            let mut model = Model::new(true);
            model.words.insert(0x0024, afe);
            let mut system = System::default();
            kt_assert_eq!(configure_model(&mut system, &mut model), Err(error));
            kt_assert_eq!(system.state(), State::Failed(error));
            kt_assert!(model.writes.is_empty());
            kt_assert!(!model.unsafe_activation);
        }
    }
    for (afe, error) in [
        (0x0020_0040, Error::MacPowerRequired),
        (0x1f20_005f, Error::UnsupportedMac1),
        (u32::MAX, Error::Io(power::Error::Gone)),
    ] {
        let mut model = Model::new(true);
        model.words.insert(0x0024, afe);
        let mut system = System::default();
        kt_assert_eq!(configure_model(&mut system, &mut model), Err(error));
        kt_assert!(model.writes.is_empty());
    }
    for gone in [false, true] {
        let mut model = Model::new(false);
        model.drop_byte = !gone;
        model.gone_after_byte = gone;
        let mut system = System::default();
        let error = if gone {
            Error::Io(power::Error::Gone)
        } else {
            Error::Readback(0x0084)
        };
        kt_assert_eq!(configure_model(&mut system, &mut model), Err(error));
        kt_assert_eq!(system.state(), State::Failed(error));
        kt_assert_eq!(
            model.writes,
            vec![
                WriteOp::Word(0x10000, 0x0050_0000),
                WriteOp::Byte(0x0084, 0x53),
            ]
        );
        kt_assert!(!model.unsafe_activation);
        kt_assert!(!model.words.contains_key(&0x842c));
        let accesses = model.accesses;
        kt_assert_eq!(
            configure_model(&mut system, &mut model),
            Err(Error::Terminal)
        );
        kt_assert_eq!(model.accesses, accesses);
    }
    TestResult::Pass
}

struct RevokeOnReadback<'a> {
    native: NativeRegs<'a>,
    cap: Cap<BusDeviceCap, Write>,
}
impl Regs for RevokeOnReadback<'_> {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        self.native.read8(address)
    }
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        self.native.write8(address, value)?;
        self.cap.revoke();
        Ok(())
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.native.read32(address)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.native.write32(address, value)
    }
}
fn smoke_rtw8922a_native_system_current_authority_and_bounds() -> TestResult {
    let mut words = vec![0u32; 0x10008 / 4];
    words[0xb010 / 4] = 0x8000_6fff;
    words[0x0024 / 4] = 0x1f20_0040;
    words[0x0084 / 4] = 0x2201_0052;
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x10008,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    // SAFETY: private aligned BAR RAM remains exclusively owned for the port.
    let mut native = unsafe { NativeRegs::new(&region, &cap) };
    kt_assert_eq!(native.read32(0x10001), Err(power::Error::Access));
    kt_assert_eq!(native.write32(0xb010, 0), Err(power::Error::Access));
    kt_assert_eq!(native.read32(0xe000), Err(power::Error::Access));
    kt_assert_eq!(native.write8(0x0085, 0), Err(power::Error::Access));
    let mut short = region;
    short.len = 0x10004;
    // SAFETY: same exclusive BAR RAM, intentionally shortened checked extent.
    let mut short_port = unsafe { NativeRegs::new(&short, &cap) };
    kt_assert_eq!(short_port.read32(0x10004), Err(power::Error::Access));
    // Each refused probe above latched that port's fault for good, so the
    // revocation case needs a fresh port over the same BAR.
    drop(native);
    // SAFETY: same exclusive BAR RAM; the faulted port is gone.
    let native = unsafe { NativeRegs::new(&region, &cap) };
    let mut system = System::default();
    let mut revoking = RevokeOnReadback { native, cap };
    // SAFETY: exclusive inert BAR model; capability expires after the first write.
    kt_assert_eq!(
        configure_model(&mut system, &mut revoking),
        Err(Error::Io(power::Error::Access))
    );
    kt_assert_eq!(
        system.state(),
        State::Failed(Error::Io(power::Error::Access))
    );
    kt_assert_eq!(words[0x0084 / 4], 0x2201_0053);
    kt_assert_eq!(words[0x10000 / 4] & 0x3000_0000, 0);
    kt_assert_eq!(words[0x842c / 4], 0);
    let snapshot = words.clone();
    // SAFETY: same model; terminal state must refuse without register access.
    kt_assert_eq!(
        configure_model(&mut system, &mut revoking),
        Err(Error::Terminal)
    );
    kt_assert_eq!(words, snapshot);
    kt_assert_eq!(revoking.native.read32(0xb010), Err(power::Error::Access));
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_system_source_order_closed_cold_and_warm
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_system_failed_access_and_readback_are_terminal
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_native_system_current_authority_and_bounds
);

kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8922a_system_requires_released_mac0_and_closed_mac1
);
