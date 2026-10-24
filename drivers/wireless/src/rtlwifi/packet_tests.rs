//! Device model observes retained DMA after actual descriptor publication.
use super::super::super::{
    channel_power::tests as power, firmware_transport::Error as AccessError, radio,
};
use super::*;
use alloc::{boxed::Box, sync::Arc, vec};
use core::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
include!("radio/packet_golden.rs");

#[derive(Clone)]
struct Region {
    address: u64,
    bytes: Arc<IrqSafeSpinLock<Vec<u8>>>,
}
struct Block {
    region: Region,
    drops: Arc<AtomicUsize>,
}
impl Drop for Block {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: distinct inert synthetic extents, shared solely with this device
// model; no synthetic address is a CPU pointer or exposed to a physical bus.
unsafe impl Memory for Block {
    fn address(&self) -> u64 {
        self.region.address
    }
    fn len(&self) -> usize {
        self.region.bytes.lock().len()
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.write_bytes(offset, &value.to_le_bytes())
    }
    fn read32(&self, offset: usize) -> Result<u32, Error> {
        let mut bytes = [0; 4];
        self.read_bytes(offset, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.region
            .bytes
            .lock()
            .get_mut(offset..offset + bytes.len())
            .ok_or(Error::Memory)?
            .copy_from_slice(bytes);
        Ok(())
    }
    fn read_bytes(&self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.copy_from_slice(
            self.region
                .bytes
                .lock()
                .get(offset..offset + bytes.len())
                .ok_or(Error::Memory)?,
        );
        Ok(())
    }
    fn sync(&self) {}
}
struct Model {
    regions: Vec<Region>,
    next: u64,
    live: bool,
    master: bool,
    started: bool,
    complete: bool,
    wait: bool,
    kicks: Vec<u16>,
    observed: Vec<Vec<u8>>,
    slots: [usize; 7],
}
#[derive(Clone)]
struct PacketPort {
    radio: radio::tests::Port,
    model: Arc<IrqSafeSpinLock<Model>>,
    drops: Arc<AtomicUsize>,
}
impl PacketPort {
    fn new() -> Self {
        Self {
            radio: radio::tests::Port::stable(),
            model: Arc::new(IrqSafeSpinLock::new(Model {
                regions: Vec::new(),
                next: 0x10000,
                live: true,
                master: false,
                started: false,
                complete: true,
                wait: false,
                kicks: Vec::new(),
                observed: Vec::new(),
                slots: [0; 7],
            })),
            drops: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn check(&self) -> Result<(), AccessError> {
        if self.model.lock().live {
            Ok(())
        } else {
            Err(AccessError::Access)
        }
    }
    fn allocate(&self, bytes: usize) -> Block {
        let mut model = self.model.lock();
        let address = (model.next + 255) & !255;
        model.next = address + bytes as u64;
        let region = Region {
            address,
            bytes: Arc::new(IrqSafeSpinLock::new(vec![0; bytes])),
        };
        model.regions.push(region.clone());
        Block {
            region,
            drops: self.drops.clone(),
        }
    }
    fn region(&self, address: u64) -> Region {
        self.model
            .lock()
            .regions
            .iter()
            .find(|r| r.address == address)
            .unwrap()
            .clone()
    }
    fn descriptor(&self, queue: usize, slot: usize) -> Vec<u8> {
        let base = self.radio.word(LINUX_TX_BASES[queue]);
        let region = self.region(u64::from(base));
        let bytes = region.bytes.lock()[slot * 64..(slot + 1) * 64].to_vec();
        bytes
    }
    fn tx_word(&self, queue: usize, slot: usize, word: usize, value: u32) {
        let region = self.region(u64::from(self.radio.word(LINUX_TX_BASES[queue])));
        region.bytes.lock()[slot * 64 + word * 4..slot * 64 + word * 4 + 4]
            .copy_from_slice(&value.to_le_bytes());
    }
    fn inject(
        &self,
        slot: usize,
        bytes: &[u8],
        status_extra: u32,
        report: u32,
        extra: u32,
    ) -> Region {
        let ring = self.region(u64::from(self.radio.word(LINUX_RX_BASE)));
        let address = word(&ring.bytes.lock(), slot * 32 + 24);
        let buffer = self.region(u64::from(address));
        // Driver-info=16 and shift=2 exercise actual payload offset handling.
        buffer.bytes.lock()[18..18 + bytes.len()].copy_from_slice(bytes);
        let mut descriptor = ring.bytes.lock();
        let eor = if slot == 3 { 1 << 30 } else { 0 };
        put(
            &mut descriptor,
            slot * 32,
            bytes.len() as u32 | eor | (3 << 28) | (2 << 16) | (2 << 24) | status_extra,
        );
        put(&mut descriptor, slot * 32 + 4, extra);
        put(&mut descriptor, slot * 32 + 8, 0);
        put(&mut descriptor, slot * 32 + 12, report);
        buffer
    }
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
#[async_trait::async_trait]
impl Io for PacketPort {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        self.check()?;
        self.radio.read8(reg)
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        self.check()?;
        self.radio.read32(reg)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        self.check()?;
        self.radio.write8(reg, value)
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        self.check()?;
        self.radio.write32(reg, value)
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), AccessError> {
        self.check()?;
        self.radio.write_bytes(reg, bytes)
    }
    async fn delay_us(&self, micros: u64) {
        let wait = { self.model.lock().wait };
        if wait {
            core::future::pending::<()>().await;
        }
        self.radio.delay_us(micros).await;
    }
}
impl Port for PacketPort {
    type Buffer = Block;
    fn authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.check()?;
        if self.model.lock().master != active {
            return Err(Error::State);
        }
        operation()
    }
    fn allocate_packet(&self, bytes: usize) -> Result<Block, Error> {
        self.check()?;
        Ok(self.allocate(bytes))
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.check()?;
        let mut model = self.model.lock();
        if enabled && model.started {
            return Err(Error::State);
        }
        model.master = enabled;
        model.started |= enabled;
        Ok(())
    }
    fn kick(&self, bit: u16) -> Result<(), Error> {
        self.check()?;
        // Independent Linux queue dispatch, not the driver's vector index.
        let (base, queue) = match bit {
            64 => (LINUX_TX_BASES[1], 1),
            2 => (LINUX_TX_BASES[4], 4),
            _ => return Err(Error::Descriptor),
        };
        let (slot, complete) = {
            let mut model = self.model.lock();
            if !model.master {
                return Err(Error::State);
            }
            model.kicks.push(bit);
            (model.slots[queue], model.complete)
        };
        let ring = self.region(u64::from(self.radio.word(base)));
        let descriptor = ring.bytes.lock()[slot * 64..slot * 64 + 64].to_vec();
        let control = word(&descriptor, 0);
        let length = (control & 0xffff) as usize;
        if control & 0x8c000000 != 0x8c000000
            || (control >> 16) & 255 != 32
            || word(&descriptor, 28) & 0xffff != length as u32
            || (word(&descriptor, 4) >> 8) & 31 != if bit == 64 { 0x12 } else { 0 }
            || word(&descriptor, 36) != 0
            || word(&descriptor, 40) != ring.address as u32 + (((slot + 1) % 4) * 64) as u32
        {
            return Err(Error::Descriptor);
        }
        let payload = self.region(u64::from(word(&descriptor, 32)));
        let bytes = payload
            .bytes
            .lock()
            .get(..length)
            .ok_or(Error::Descriptor)?
            .to_vec();
        self.model.lock().observed.push(bytes);
        if complete {
            let mut bytes = ring.bytes.lock();
            put(&mut bytes, slot * 64, control & !OWN);
            self.model.lock().slots[queue] = (slot + 1) % 4;
        }
        Ok(())
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("unexpected packet model wait"),
    }
}
fn owner() -> (Prepared<PacketPort, Block>, PacketPort) {
    let port = PacketPort::new();
    let factory = power::factory();
    let mut owner = Prepared::allocate(port.clone(), 4, |bytes| Ok(port.allocate(bytes))).unwrap();
    run(owner.prepare()).unwrap();
    run(owner.configure_radio(radio::Profile::from_factory(&factory).unwrap())).unwrap();
    let permission = power::calibration(&factory)
        .permission(&power::domain(17), 1)
        .unwrap();
    run(owner.configure_channel(permission)).unwrap();
    owner.configure_mac(&factory).unwrap();
    (owner, port)
}
fn frame(data: bool) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..2].copy_from_slice(&(if data { 0x0108u16 } else { 0x00b0 }).to_le_bytes());
    bytes[4..10].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    bytes[10..16].copy_from_slice(&power::factory().mac);
    bytes[16..22].copy_from_slice(&[2, 9, 8, 7, 6, 5]);
    bytes[22..24].copy_from_slice(&0x1230u16.to_le_bytes());
    bytes
}

pub(crate) fn smoke_rtl8188ee_native_packets_use_actual_linux_descriptors_and_dma() -> TestResult {
    let (mut owner, port) = owner();
    if owner.start_packets().is_err() {
        return TestResult::Fail("native packet admission failed");
    }
    for data in [
        false, true, false, true, false, true, false, true, false, true,
    ] {
        let bytes = frame(data);
        let queue = if data { 4 } else { 1 };
        let slot = owner.packet.next[queue];
        let id = owner.submit(&bytes, 0).unwrap();
        let descriptor = port.descriptor(queue, slot);
        let mut expected = if data { LINUX_DATA } else { LINUX_MANAGEMENT };
        expected[0] &= !OWN;
        expected[8] = word(&descriptor, 32);
        expected[10] = word(&descriptor, 40);
        if (0..12).any(|n| word(&descriptor, n * 4) != expected[n]) {
            return TestResult::Fail("actual DMA descriptor differs from original Linux setters");
        }
        let receipt = owner.poll_delivery().unwrap().unwrap();
        if receipt.id != id || receipt.bytes != bytes {
            return TestResult::Fail("terminal DMA receipt lost exact native payload");
        }
    }
    let correct = {
        let model = port.model.lock();
        model.kicks == LINUX_POLLS && model.observed.len() == 10
    };
    if !correct || port.drops.load(Ordering::SeqCst) != 10 {
        return TestResult::Fail("Linux native queue polling/retirement differs");
    }
    if port.radio.word(0xb0) != 0
        || port.radio.word(0xb8) != 0
        || port.radio.read8(0x680).unwrap() != 0
    {
        return TestResult::Fail("polling profile enabled IRQ/HW crypto");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/packet",
    smoke_rtl8188ee_native_packets_use_actual_linux_descriptors_and_dma
);

pub(crate) fn smoke_rtl8188ee_native_receive_offset_fcs_profiles_and_repost() -> TestResult {
    let (mut owner, port) = owner();
    owner.start_packets().unwrap();
    let original = frame(false);
    let mut wire = original.clone();
    wire.extend_from_slice(&[1, 2, 3, 4]);
    port.inject(0, &wire, 0, 0, 0);
    let packet = owner.poll_receive().unwrap().unwrap();
    if packet.bytes() != original || packet.channel() != 1 {
        return TestResult::Fail("native RX offset/FCS boundary differs");
    }
    let ring = port.region(u64::from(port.radio.word(LINUX_RX_BASE)));
    if word(&ring.bytes.lock(), 0) != OWN | 4096 {
        return TestResult::Fail("consumed native RX buffer not reposted");
    }
    // Distinct raw descriptor failures, including non-MPDU reports and an
    // encrypted frame whose native descriptor claims hardware decryption.
    for (index, (status, report, extra, protected)) in [
        (1 << 14, 0, 0, false),
        (1 << 15, 0, 0, false),
        (0, 1 << 14, 0, false),
        (0, 1 << 6, 0, false),
        (0, 1 << 9, 0, false),
        (0, 0, 1 << 14, false),
        (0, 0, 1 << 27, false),
        (0, 0, 0, true),
    ]
    .into_iter()
    .enumerate()
    {
        let slot = (index + 1) % 4;
        let mut rejected = wire.clone();
        if protected {
            rejected[1] |= 0x40;
        }
        port.inject(slot, &rejected, status, report, extra);
        if owner.poll_receive().unwrap().is_some() {
            return TestResult::Fail("native receive admitted a rejected descriptor/profile");
        }
    }
    let mut protected = wire;
    protected[1] |= 0x40;
    port.inject(1, &protected, 1 << 27, 0, 0);
    if owner.poll_receive().unwrap().is_none() {
        return TestResult::Fail("unaltered software-CCMP MPDU was lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/packet",
    smoke_rtl8188ee_native_receive_offset_fcs_profiles_and_repost
);

pub(crate) fn smoke_rtl8188ee_native_cancel_timeout_and_stop_retain_owners() -> TestResult {
    for cancel in [false, true] {
        let (mut owner, port) = owner();
        owner.start_packets().unwrap();
        port.model.lock().complete = false;
        owner.submit(&frame(false), 0).unwrap();
        if cancel {
            port.model.lock().wait = true;
            let mut future = Box::pin(owner.wait_delivery(2));
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("cancel fixture did not wait for actual OWN");
            }
            drop(future);
        } else if run(owner.wait_delivery(2)) != Err(Error::PacketTimeout) {
            return TestResult::Fail("absent native completion did not time out");
        }
        if owner.phase() != Phase::Failed || owner.submit(&frame(false), 0) != Err(Error::State) {
            return TestResult::Fail("cancelled/failed native TX reopened admission");
        }
        owner.stop_packets().unwrap();
        if port.model.lock().master
            || port.radio.read8(0x100).unwrap() & 0xcf != 0
            || port.radio.read8(0x301).unwrap() != 255
        {
            return TestResult::Fail("terminal stop retained an independent packet gate");
        }
        if owner.start_packets() != Err(Error::State) {
            return TestResult::Fail("terminal stop reconstructed active DMA");
        }
        drop(owner);
        if port.drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("stop/cancel released possibly prefetched DMA mappings");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/packet",
    smoke_rtl8188ee_native_cancel_timeout_and_stop_retain_owners
);

pub(crate) fn smoke_rtl8188ee_native_rebinding_authority_and_terminal_failure() -> TestResult {
    // Recreate the formerly shared 8192EE register publication. A valid
    // allocation is insufficient if the actual EE queue map is rebound.
    let (mut wrong_map, port) = owner();
    for (&reg, memory) in [0x308, 0x310, 0x318, 0x320, 0x328, 0x330, 0x340]
        .iter()
        .zip(&wrong_map.tx)
    {
        port.radio.write32(reg, memory.address() as u32).unwrap();
    }
    port.radio
        .write32(0x338, wrong_map.receive.as_ref().unwrap().address() as u32)
        .unwrap();
    if wrong_map.start_packets() != Err(Error::Readback) || port.model.lock().master {
        return TestResult::Fail("8192EE base aliases admitted RTL8188EE packet DMA");
    }
    for corrupt in [false, true] {
        let (mut owner, port) = owner();
        owner.start_packets().unwrap();
        owner.submit(&frame(false), 0).unwrap();
        if corrupt {
            port.tx_word(1, 0, 8, 0xdead0000);
        } else {
            port.model.lock().live = false;
        }
        if owner.poll_delivery().is_ok() || owner.phase() != Phase::Failed {
            return TestResult::Fail("rebound descriptor/stale authority completed a native owner");
        }
        if !corrupt && owner.stop_packets().is_ok() {
            return TestResult::Fail("revoked PCI authority performed stop I/O");
        }
        drop(owner);
        if port.drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("ambiguous DMA ownership was released");
        }
    }
    let (mut owner, port) = owner();
    port.radio.ignore(0x301);
    if owner.start_packets().is_ok() || owner.phase() != Phase::Failed {
        return TestResult::Fail("ignored native DMA opening was reported ready");
    }
    owner.stop_packets().unwrap();
    if port.model.lock().master {
        return TestResult::Fail("readback failure did not park BME on terminal stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/packet",
    smoke_rtl8188ee_native_rebinding_authority_and_terminal_failure
);
