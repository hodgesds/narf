//! Device-side 88EE BB/RF model and original Linux trace comparison.
use super::*;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
include!("radio/golden.rs");

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Stable,
    BadTx,
    BadRx,
    Unstable,
}
pub(crate) struct Model {
    registers: Vec<u8>,
    rf: [u32; 256],
    trace: Vec<(u8, u16, u32)>,
    accesses: usize,
    fail: Option<usize>,
    mode: Mode,
    shots: usize,
    pass: u16,
    delays: usize,
    pause: Option<usize>,
    ignore: Option<u16>,
}
#[derive(Clone)]
pub(crate) struct Port(Arc<IrqSafeSpinLock<Model>>);
impl Port {
    pub(crate) fn stable() -> Self {
        Self::new(Mode::Stable)
    }
    fn new(mode: Mode) -> Self {
        let mut registers = vec![0; 0x1000];
        registers[0x100] = 0xff;
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            registers,
            rf: [0; 256],
            trace: Vec::new(),
            accesses: 0,
            fail: None,
            mode,
            shots: 0,
            pass: 0,
            delays: 0,
            pause: None,
            ignore: None,
        })))
    }
}
fn value(model: &Model, reg: u16) -> u32 {
    u32::from_le_bytes(
        model.registers[usize::from(reg)..usize::from(reg) + 4]
            .try_into()
            .unwrap(),
    )
}
fn store(model: &mut Model, reg: u16, data: u32) {
    model.registers[usize::from(reg)..usize::from(reg) + 4].copy_from_slice(&data.to_le_bytes());
}
fn access(model: &mut Model) -> Result<(), AccessError> {
    let current = model.accesses;
    model.accesses += 1;
    if model.fail == Some(current) {
        Err(AccessError::Access)
    } else {
        Ok(())
    }
}
#[async_trait::async_trait]
impl Io for Port {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        let mut model = self.0.lock();
        access(&mut model)?;
        Ok(model.registers[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        let mut model = self.0.lock();
        access(&mut model)?;
        if reg == 0x1e0 {
            let word = value(&model, reg);
            store(&mut model, reg, word & 0x3fffffff);
        }
        Ok(value(&model, reg))
    }
    fn write8(&self, reg: u16, data: u8) -> Result<(), AccessError> {
        let mut model = self.0.lock();
        access(&mut model)?;
        model.trace.push((8, reg, u32::from(data)));
        if model.ignore == Some(reg) {
            return Ok(());
        }
        model.registers[usize::from(reg)] = data;
        Ok(())
    }
    fn write32(&self, reg: u16, data: u32) -> Result<(), AccessError> {
        let mut model = self.0.lock();
        access(&mut model)?;
        model.trace.push((32, reg, data));
        if model.ignore == Some(reg) {
            return Ok(());
        }
        store(&mut model, reg, data);
        if reg == 0x840 {
            model.rf[((data >> 20) & 255) as usize] = data & 0xfffff;
        }
        if reg == 0x824 && data & (1 << 31) != 0 {
            let result = model.rf[((data >> 23) & 255) as usize];
            store(&mut model, 0x8a0, result);
            store(&mut model, 0x8b8, result);
        }
        if reg == 0xe48 && data == 0xf8000000 {
            model.shots += 1;
            let stage = value(&model, 0xe38);
            if stage == 0x8214032a {
                model.pass += 1;
            }
            let drift = if model.mode == Mode::Unstable {
                model.pass * 12
            } else {
                0
            };
            store(&mut model, 0xe94, u32::from(0x105 + drift) << 16);
            store(&mut model, 0xe9c, 0x3fa0000);
            let rx = stage == 0x82160c05;
            let bad = if model.mode == Mode::BadTx {
                1 << 28
            } else if model.mode == Mode::BadRx && rx {
                1 << 27
            } else {
                0
            };
            store(&mut model, 0xea4, if rx { 0x1010000 } else { 0 });
            store(&mut model, 0xeac, if rx { 0x3f90000 | bad } else { bad });
        }
        Ok(())
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), AccessError> {
        for (i, byte) in bytes.iter().enumerate() {
            self.write8(reg + i as u16, *byte)?;
        }
        Ok(())
    }
    async fn delay_us(&self, micros: u64) {
        let pause = {
            let mut model = self.0.lock();
            model.trace.push((0, 0, micros as u32));
            model.delays += 1;
            if micros >= 50_000 {
                model.rf[0x18] &= !(1 << 15);
            }
            model.pause == Some(model.delays)
        };
        if pause {
            core::future::pending::<()>().await;
        }
    }
}
pub(crate) struct Block {
    address: u64,
    bytes: Vec<u8>,
    drops: Arc<AtomicUsize>,
}
impl Drop for Block {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: exclusive synthetic DMA extents backed by inert model byte arrays.
// No address is exposed to a physical device; Prepared owns published lifetime.
unsafe impl super::super::prepare::Memory for Block {
    fn address(&self) -> u64 {
        self.address
    }
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), super::super::prepare::Error> {
        self.bytes
            .get_mut(offset..offset + 4)
            .ok_or(super::super::prepare::Error::Memory)?
            .copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn sync(&self) {}
}
fn prepared(port: Port, drops: Arc<AtomicUsize>) -> super::super::prepare::Prepared<Port, Block> {
    let mut address = 0x10000;
    let mut owner = super::super::prepare::Prepared::allocate(port.clone(), 4, |bytes| {
        address = (address + 255) & !255;
        let block = Block {
            address,
            bytes: vec![0; bytes],
            drops: drops.clone(),
        };
        address += bytes as u64;
        Ok(block)
    })
    .unwrap();
    assert!(run(owner.prepare()).is_ok());
    {
        let mut model = port.0.lock();
        model.trace.clear();
        model.accesses = 0;
    }
    owner
}
fn profile() -> Profile {
    let mut factory = super::super::efuse::Factory {
        mac: [2, 1, 2, 3, 4, 5],
        logical: [255; 512],
    };
    factory.logical[..2].copy_from_slice(&0x8129u16.to_le_bytes());
    factory.logical[0xd6..0xd8].copy_from_slice(&0x10ecu16.to_le_bytes());
    factory.logical[0xd8..0xda].copy_from_slice(&0x8179u16.to_le_bytes());
    Profile::from_factory(&factory).unwrap()
}
pub(crate) fn channel_owner(
    factory: &super::super::efuse::Factory,
) -> (super::super::prepare::Prepared<Port, Block>, Port) {
    let port = Port::new(Mode::Stable);
    let mut owner = prepared(port.clone(), Arc::new(AtomicUsize::new(0)));
    assert!(run(owner.configure_radio(Profile::from_factory(factory).unwrap())).is_ok());
    {
        let mut model = port.0.lock();
        model.trace.clear();
        model.accesses = 0;
    }
    (owner, port)
}
impl Port {
    pub(crate) fn trace(&self) -> Vec<(u8, u16, u32)> {
        self.0.lock().trace.clone()
    }
    pub(crate) fn accesses(&self) -> usize {
        self.0.lock().accesses
    }
    pub(crate) fn fail_at(&self, at: usize) {
        self.0.lock().fail = Some(at);
    }
    pub(crate) fn ignore(&self, reg: u16) {
        self.0.lock().ignore = Some(reg);
    }
    pub(crate) fn pause_after(&self, delays: usize) {
        let mut model = self.0.lock();
        model.pause = Some(model.delays + delays);
    }
    pub(crate) fn word(&self, reg: u16) -> u32 {
        value(&self.0.lock(), reg)
    }
    pub(crate) fn rf(&self, reg: u8) -> u32 {
        self.0.lock().rf[usize::from(reg)]
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("unpaused radio model unexpectedly waited"),
    }
}

pub(super) fn smoke_rtl8188ee_radio_matches_original_linux_trace_and_iq_matrix() -> TestResult {
    let port = Port::new(Mode::Stable);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = prepared(port.clone(), drops.clone());
    if run(owner.configure_radio(profile())).is_err() {
        return TestResult::Fail("native retained radio configuration failed");
    }
    let model = port.0.lock();
    if model.trace != LINUX_RADIO {
        use core::fmt::Write;
        let at = model
            .trace
            .iter()
            .zip(LINUX_RADIO)
            .position(|(a, b)| a != b)
            .unwrap_or(model.trace.len().min(LINUX_RADIO.len()));
        let _ = writeln!(
            narf_console::Writer,
            "8188EE Linux radio trace mismatch at {at}: actual={:?} expected={:?} lengths={}/{}",
            model.trace.get(at),
            LINUX_RADIO.get(at),
            model.trace.len(),
            LINUX_RADIO.len()
        );
        return TestResult::Fail("retained radio register/delay trace differs from Linux");
    }
    if owner.phase() != super::super::prepare::Phase::RadioConfigured
        || owner.radio_report().is_none_or(|report| {
            report.iqk != [0x105, 0x3fa, 0x101, 0x3f9] || report.channel_rf != 0x407
        })
        || value(&model, 0xc80) != 0x393a00e8
        || value(&model, 0xc14) != 0x4000e501
        || value(&model, 0xca0) != 0xf0000000
        || model.registers[0x301] != 255
        || model.registers[0x100] & 0xcf != 0
        || value(&model, 0xb0) != 0
        || value(&model, 0xb8) != 0
    {
        use core::fmt::Write;
        let _ = writeln!(
            narf_console::Writer,
            "8188EE report={:?} matrix={:x}/{:x}/{:x} gates={:x}/{:x}/{:x}/{:x}",
            owner.radio_report(),
            value(&model, 0xc80),
            value(&model, 0xc14),
            value(&model, 0xca0),
            model.registers[0x301],
            model.registers[0x100],
            value(&model, 0xb0),
            value(&model, 0xb8)
        );
        return TestResult::Fail("radio report/matrix or parked packet gates differ");
    }
    drop(model);
    let accesses = port.0.lock().accesses;
    if run(owner.configure_radio(profile())) != Err(super::super::prepare::Error::State)
        || port.0.lock().accesses != accesses
    {
        return TestResult::Fail("radio owner repeated initialization");
    }
    drop(owner);
    if drops.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("radio owner dropped published DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/radio",
    smoke_rtl8188ee_radio_matches_original_linux_trace_and_iq_matrix
);

pub(super) fn smoke_rtl8188ee_radio_bad_measurements_and_access_failure_are_terminal() -> TestResult
{
    for mode in [Mode::BadTx, Mode::BadRx, Mode::Unstable] {
        let port = Port::new(mode);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut owner = prepared(port.clone(), drops.clone());
        if run(owner.configure_radio(profile()))
            != Err(super::super::prepare::Error::Radio(Error::Calibration))
            || owner.radio_report().is_some()
            || owner.phase() != super::super::prepare::Phase::Failed
        {
            return TestResult::Fail("failed IQK fabricated radio readiness");
        }
        drop(owner);
        if drops.load(Ordering::Relaxed) != 0 {
            return TestResult::Fail("failed IQK released published descriptor owner");
        }
    }
    // Sample transactions across the successful original-Linux path,
    // including RF readback/measurement and final restoration accesses.
    let baseline = Port::new(Mode::Stable);
    let mut owner = prepared(baseline.clone(), Arc::new(AtomicUsize::new(0)));
    assert!(run(owner.configure_radio(profile())).is_ok());
    let total = baseline.0.lock().accesses;
    drop(owner);
    for fault in (0..total).step_by(19).chain(core::iter::once(total - 1)) {
        let port = Port::new(Mode::Stable);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut owner = prepared(port.clone(), drops.clone());
        port.0.lock().fail = Some(fault);
        if run(owner.configure_radio(profile())).is_ok()
            || owner.phase() != super::super::prepare::Phase::Failed
            || owner.radio_report().is_some()
        {
            return TestResult::Fail("radio access fault committed readiness");
        }
        let at = port.0.lock().accesses;
        if run(owner.configure_radio(profile())) != Err(super::super::prepare::Error::State)
            || port.0.lock().accesses != at
        {
            return TestResult::Fail("failed radio attempted retry I/O");
        }
        drop(owner);
        if drops.load(Ordering::Relaxed) != 0 {
            return TestResult::Fail("radio fault released published DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/radio",
    smoke_rtl8188ee_radio_bad_measurements_and_access_failure_are_terminal
);

pub(super) fn smoke_rtl8188ee_radio_cancellation_retains_native_owner_and_gates() -> TestResult {
    let mut count = 0;
    let delays: Vec<_> = LINUX_RADIO
        .iter()
        .filter_map(|(kind, _, micros)| {
            if *kind != 0 {
                return None;
            }
            count += 1;
            (count == 1 || count == 200 || *micros >= 10_000).then_some(count)
        })
        .collect();
    for delay in delays {
        let port = Port::new(Mode::Stable);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut owner = prepared(port.clone(), drops.clone());
        port.0.lock().pause = Some(delay);
        let mut future = Box::pin(owner.configure_radio(profile()));
        let mut cx = Context::from_waker(Waker::noop());
        let outcome = future.as_mut().poll(&mut cx);
        drop(future);
        if outcome.is_ready()
            || owner.phase() != super::super::prepare::Phase::Failed
            || owner.radio_report().is_some()
        {
            return TestResult::Fail("cancelled calibration reopened native owner");
        }
        let model = port.0.lock();
        if model.registers[0x301] != 255
            || model.registers[0x100] & 0xcf != 0
            || value(&model, 0xb0) != 0
            || value(&model, 0xb8) != 0
        {
            return TestResult::Fail("calibration cancellation admitted DMA/IRQ");
        }
        drop(model);
        let at = port.0.lock().accesses;
        if run(owner.configure_radio(profile())) != Err(super::super::prepare::Error::State)
            || port.0.lock().accesses != at
        {
            return TestResult::Fail("cancelled radio retried native accesses");
        }
        drop(owner);
        if drops.load(Ordering::Relaxed) != 0 {
            return TestResult::Fail("cancelled calibration released published mappings");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/radio",
    smoke_rtl8188ee_radio_cancellation_retains_native_owner_and_gates
);

pub(super) fn smoke_rtl8188ee_factory_profile_and_hp_rf_variant_are_exact() -> TestResult {
    let mut factory = super::super::efuse::Factory {
        mac: [2, 1, 2, 3, 4, 5],
        logical: [255; 512],
    };
    for (at, value) in [
        (0, 0x8129u16),
        (0xd6, 0x10ec),
        (0xd8, 0x8179),
        (0xda, 0x103c),
        (0xdc, 0x197d),
    ] {
        factory.logical[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    let Ok(hp) = Profile::from_factory(&factory) else {
        return TestResult::Fail("valid HP factory profile rejected");
    };
    if hp == profile() || power_groups().len() != 88 {
        return TestResult::Fail("8188EE factory/OEM or complete PG table identity");
    }
    for (at, value) in [(0, 0x8128u16), (0xd6, 0x10ed), (0xd8, 0x818b)] {
        let mut invalid = factory.clone();
        invalid.logical[at..at + 2].copy_from_slice(&value.to_le_bytes());
        if Profile::from_factory(&invalid) != Err(Error::Profile) {
            return TestResult::Fail("foreign factory profile admitted RF programming");
        }
    }
    let port = Port::new(Mode::Stable);
    let mut owner = prepared(port.clone(), Arc::new(AtomicUsize::new(0)));
    if run(owner.configure_radio(Profile::from_factory(&factory).unwrap())).is_err()
        || port.0.lock().rf[0x52] != 0x7e4bd
    {
        return TestResult::Fail("HP197d RF override absent from retained native path");
    }
    factory.logical[0xc5] = 2;
    if !Profile::from_factory(&factory).is_ok_and(|profile| !profile.is_hp()) {
        return TestResult::Fail("non-default OEM selected HP RF override");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/radio",
    smoke_rtl8188ee_factory_profile_and_hp_rf_variant_are_exact
);
