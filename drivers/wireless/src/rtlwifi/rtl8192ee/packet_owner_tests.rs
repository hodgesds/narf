// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE BD-ring owner model tests (written, unexecuted).
use super::super::super::super::rtl8192ee::trx;
use super::super::super::{Chip, Error, Phase, Prepared};
use super::super::{Port, ReceiveStep};
use super::{blocks, DEPTH};
use crate::rtlwifi::firmware_transport::{Error as AccessError, Io};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Default)]
struct Model {
    regs: Vec<u8>,
    trace: Vec<(u8, u16, u32)>,
    master: bool,
    next: u64,
}
#[derive(Clone)]
struct Bus(Arc<IrqSafeSpinLock<Model>>);
impl Bus {
    fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs: vec![0; 0x1000],
            next: 0x0100_0000,
            ..Model::default()
        })))
    }
    fn traced(&self, row: (u8, u16, u32)) -> bool {
        self.0.lock().trace.contains(&row)
    }
    fn set32(&self, reg: u16, value: u32) {
        let at = usize::from(reg);
        self.0.lock().regs[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}
#[async_trait::async_trait]
impl Io for Bus {
    fn read8(&self, reg: u16) -> Result<u8, AccessError> {
        Ok(self.0.lock().regs[usize::from(reg)])
    }
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        let at = usize::from(reg);
        Ok(u32::from_le_bytes(
            self.0.lock().regs[at..at + 4].try_into().unwrap(),
        ))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        m.trace.push((8, reg, u32::from(value)));
        m.regs[usize::from(reg)] = value;
        Ok(())
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        m.trace.push((16, reg, u32::from(value)));
        let at = usize::from(reg);
        m.regs[at..at + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        let mut m = self.0.lock();
        m.trace.push((32, reg, value));
        let at = usize::from(reg);
        m.regs[at..at + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write_bytes(&self, _: u16, _: &[u8]) -> Result<(), AccessError> {
        Err(AccessError::Access)
    }
    async fn delay_us(&self, _: u64) {}
}
struct Block {
    address: u64,
    bytes: Vec<u8>,
    drops: Option<Arc<AtomicUsize>>,
}
// SAFETY: inert byte storage with unique synthetic DMA extents; the model
// never exposes an address to a physical device.
unsafe impl super::super::super::Memory for Block {
    fn address(&self) -> u64 {
        self.address
    }
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.write_bytes(offset, &value.to_le_bytes())
    }
    fn read32(&self, offset: usize) -> Result<u32, Error> {
        let mut b = [0; 4];
        self.read_bytes(offset, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.bytes
            .get_mut(offset..offset + bytes.len())
            .ok_or(Error::Memory)?
            .copy_from_slice(bytes);
        Ok(())
    }
    fn read_bytes(&self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.copy_from_slice(
            self.bytes
                .get(offset..offset + bytes.len())
                .ok_or(Error::Memory)?,
        );
        Ok(())
    }
    fn sync(&self) {}
}
impl Drop for Block {
    fn drop(&mut self) {
        if let Some(drops) = &self.drops {
            drops.fetch_add(1, Ordering::AcqRel);
        }
    }
}
impl Bus {
    fn block(&self, bytes: usize, drops: Option<Arc<AtomicUsize>>) -> Block {
        let mut m = self.0.lock();
        let address = (m.next + 255) & !255;
        m.next = address + bytes as u64;
        Block {
            address,
            bytes: vec![0xa5; bytes],
            drops,
        }
    }
}
impl Port for Bus {
    type Buffer = Block;
    fn authority<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.0.lock().master != active {
            return Err(Error::State);
        }
        operation()
    }
    fn allocate_packet(&self, bytes: usize) -> Result<Block, Error> {
        Ok(self.block(bytes, None))
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.0.lock().master = enabled;
        Ok(())
    }
    fn kick(&self, _: u16) -> Result<(), Error> {
        Err(Error::State)
    }
}

fn allocated(bus: &Bus, drops: &Arc<AtomicUsize>) -> Result<Prepared<Bus, Block>, Error> {
    let mut shape = blocks();
    let source = bus.clone();
    Prepared::allocate_rtl8192ee(bus.clone(), |bytes| {
        if shape.next() != Some(bytes) {
            return Err(Error::Geometry);
        }
        Ok(source.block(bytes, Some(drops.clone())))
    })
}
fn word(block: &Block, offset: usize) -> u32 {
    u32::from_le_bytes(block.bytes[offset..offset + 4].try_into().unwrap())
}

pub(crate) fn smoke_rtl8192ee_bd_rings_allocation_publish_and_retention() -> TestResult {
    let bus = Bus::new();
    let drops = Arc::new(AtomicUsize::new(0));
    let Ok(mut owner) = allocated(&bus, &drops) else {
        return TestResult::Fail("8192EE BD-ring allocation shape");
    };
    if Chip::from_device(0x818b) != Some(Chip::Rtl8192ee)
        || Prepared::allocate_for(Chip::Rtl8192ee, bus.clone(), 4, |n| Ok(bus.block(n, None)))
            .is_ok()
        || owner.tx.len() != 14
        || owner.tx[0].bytes.len() != 2 * trx::TX_BD_SIZE
        || owner.tx[4].bytes.len() != DEPTH * trx::TX_BD_SIZE
        || owner
            .tx
            .iter()
            .any(|ring| ring.bytes.iter().any(|b| *b != 0))
    {
        return TestResult::Fail("8192EE profile/linked-ring refusal/zeroed TX rings");
    }
    let rx = owner.receive.as_ref().unwrap();
    for (slot, buffer) in owner.buffers.iter().enumerate() {
        if word(rx, slot * 16) != 8192 + 24
            || word(rx, slot * 16 + 4) != buffer.address as u32
            || word(rx, slot * 16 + 8) != 0
        {
            return TestResult::Fail("HW_DESC_RX_PREPARE buffer descriptors");
        }
    }
    if narf_scheduler::block_on(owner.prepare()).is_err() || owner.phase() != Phase::Prepared {
        return TestResult::Fail("8192EE preparation");
    }
    let tx: Vec<u32> = owner.tx.iter().map(|r| r.address as u32).collect();
    let rx_base = owner.receive.as_ref().unwrap().address as u32;
    for (at, base) in [0x308u16, 0x310, 0x318, 0x320, 0x328, 0x330, 0x340]
        .into_iter()
        .zip(&tx[..7])
    {
        if !bus.traced((32, at, *base)) {
            return TestResult::Fail("BD ring base not published");
        }
    }
    if !bus.traced((8, 0x3f3, 4))
        || !bus.traced((32, 0x338, rx_base))
        || !bus.traced((16, 0x388, 0x1200))
        || !bus.traced((16, 0x382, 0xa200))
        || bus.traced((16, 0x100, 0x2ff))
        || bus.traced((16, 0x300, 0x8000))
    {
        return TestResult::Fail("dma-hang probe / BD counts / deferred releases");
    }
    {
        let m = bus.0.lock();
        if m.regs[0x301] != 0xff || m.regs[0x100] & 0xcf != 0 || m.master {
            return TestResult::Fail("preparation opened DMA gates");
        }
    }
    let gate = narf_scheduler::block_on(
        owner.configure_radio(super::super::super::super::radio::Profile::gate_fixture()),
    );
    if gate != Err(Error::State) || owner.phase() != Phase::Prepared {
        return TestResult::Fail("EE radio tables qualified an 8192EE owner");
    }
    drop(owner);
    if drops.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("published BD rings freed without quiescence");
    }
    // A hung PCIe DMA engine (0x3f3 BIT(0)/BIT(1)) is refused before any base.
    let hung = Bus::new();
    hung.0.lock().regs[0x3f3] = 1 << 2 | 1;
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = allocated(&hung, &drops).unwrap();
    if narf_scheduler::block_on(owner.prepare()) != Err(Error::Readback)
        || hung.traced((32, 0x328, owner.tx[4].address as u32))
        || hung.traced((8, 0x3f3, 5))
    {
        return TestResult::Fail("hung DMA engine admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_bd_rings_allocation_publish_and_retention
);

pub(crate) fn smoke_rtl8192ee_txbd_doorbell_completion_and_rx_ack() -> TestResult {
    let bus = Bus::new();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = allocated(&bus, &drops).unwrap();
    narf_scheduler::block_on(owner.prepare()).unwrap();
    let local = [2, 0, 0, 0, 0, 1];
    if owner.start_packets() != Err(Error::State) {
        return TestResult::Fail("start before MacConfigured");
    }
    owner.phase = Phase::MacConfigured;
    owner.packet.local = Some(local);
    owner.packet.ee92.channel = Some(1);
    let started = owner.start_packets();
    let master = bus.0.lock().master;
    if started.is_err()
        || owner.phase() != Phase::Running
        || !bus.traced((16, 0x100, 0x2ff))
        || !bus.traced((16, 0x300, 0x8000))
        || !master
        || owner.enable_interrupts() != Err(Error::State)
    {
        return TestResult::Fail("REG_CR / REG_PCIE_CTRL_REG release");
    }
    // Non-QoS to-DS DATA on BE.
    let mut frame = vec![0u8; 40];
    frame[0] = 0x08;
    frame[1] = 0x01;
    frame[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    frame[10..16].copy_from_slice(&local);
    frame[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    frame[22] = 0x50;
    let Ok(id) = owner.submit(&frame, trx::DESC_RATE54M) else {
        return TestResult::Fail("8192EE submit");
    };
    let pending_addr = owner.packet.pending.as_ref().unwrap().buffer.address as u32;
    let desc_addr = owner.tx[11].address as u32;
    let bd = &owner.tx[4];
    if !bus.traced((16, 0x3a8, 1))
        || word(bd, 4) != desc_addr
        || word(bd, 20) != pending_addr
        || word(bd, 16) != 40
        || word(bd, 0) != 40 | 1 << 16
        || word(&owner.tx[11], 40) != pending_addr
        || word(&owner.tx[11], 0) & 0xffff != 40
        || owner.submit(&frame, 0) != Err(Error::State)
        || owner.submit(&frame, trx::DESC_RATEMCS0).is_ok()
    {
        return TestResult::Fail("BD/descriptor/doorbell or second outstanding frame");
    }
    if owner.poll_delivery() != Ok(None) {
        return TestResult::Fail("delivered before the device read point moved");
    }
    bus.set32(0x3a8, 1 << 16 | 1);
    match owner.poll_delivery() {
        Ok(Some(d)) if d.id == id && d.bytes == frame => {}
        _ => return TestResult::Fail("is_tx_desc_closed receipt"),
    }
    // RX: one 34-byte beacon (with FCS) in slot 0; device read point 2.
    let mut status = [0u8; 24];
    status[0..4].copy_from_slice(&(34u32 | 1 << 27).to_le_bytes());
    let mut beacon = [0u8; 30];
    beacon[0] = 0x80;
    {
        let buffer = &mut owner.buffers[0];
        buffer.bytes[..24].copy_from_slice(&status);
        buffer.bytes[24..54].copy_from_slice(&beacon);
        let rx = owner.receive.as_mut().unwrap();
        let dw0 = word(rx, 0) | 1 << 15 | 1 << 16;
        rx.bytes[0..4].copy_from_slice(&dw0.to_le_bytes());
    }
    bus.set32(0x3b4, 2 << 16);
    match owner.poll_receive_step() {
        Ok(ReceiveStep {
            consumed: true,
            packet: Some(p),
        }) if p.bytes() == &beacon[..] && p.channel() == 1 => {}
        _ => return TestResult::Fail("RXQ_TXBD_IDX remained count / payload"),
    }
    let rx = owner.receive.as_ref().unwrap();
    if !bus.traced((16, 0x3b4, 1))
        || word(rx, 0) != 8192 + 24
        || word(rx, 4) != owner.buffers[0].address as u32
    {
        return TestResult::Fail("0x3b4 acknowledgement / re-prepared BD");
    }
    // calc_fifo_space(2, 1) == 0: idle, nothing consumed.
    match owner.poll_receive_step() {
        Ok(ReceiveStep {
            consumed: false,
            packet: None,
        }) => {}
        _ => return TestResult::Fail("idle RX after the batch"),
    }
    if owner.stop_packets().is_err()
        || narf_scheduler::block_on(owner.quiesce()) != Err(Error::State)
    {
        return TestResult::Fail("stop / 88EE quiescence proof applied to 8192EE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_txbd_doorbell_completion_and_rx_ack
);

fn running(bus: &Bus, local: [u8; 6]) -> Prepared<Bus, Block> {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = allocated(bus, &drops).unwrap();
    narf_scheduler::block_on(owner.prepare()).unwrap();
    owner.phase = Phase::MacConfigured;
    owner.packet.local = Some(local);
    owner.packet.ee92.channel = Some(1);
    owner.start_packets().unwrap();
    owner
}

pub(crate) fn smoke_rtl8192ee_rsvd_page_download_through_beacon_bd() -> TestResult {
    use super::super::super::super::rtl8192ee::rsvd_page as rp;
    let bus = Bus::new();
    let local = [2, 0, 0, 0, 0, 1];
    let bssid = [2, 0, 0, 0, 0, 9];
    let mut owner = running(&bus, local);
    bus.0.lock().regs[0x422] = 0x40;
    bus.0.lock().regs[0x6a9] = 0xc0;
    let policy = |_: &Prepared<Bus, Block>| Ok(());
    if narf_scheduler::block_on(owner.ee92_join_report(bssid, 0, None, &policy))
        != Err(Error::Packet)
    {
        return TestResult::Fail("AID 0 accepted");
    }
    if narf_scheduler::block_on(owner.ee92_join_report(bssid, 5, None, &policy)).is_err()
        || owner.phase() != Phase::Running
    {
        return TestResult::Fail("8192EE join report / rsvd page download");
    }
    let Some(body) = owner.packet.reserved.as_ref() else {
        return TestResult::Fail("reserved body not retained");
    };
    let address = body.address as u32;
    if body.bytes[..] != rp::pages(local, bssid, 5).unwrap()[..] {
        return TestResult::Fail("reserved body bytes");
    }
    let desc = &owner.tx[7];
    let bd = &owner.tx[0];
    if word(bd, 0) != 40 | 5 << 16 | 1 << 31
        || word(bd, 4) != desc.address as u32
        || word(bd, 16) != 1024
        || word(bd, 20) != address
        || word(desc, 40) != address
        || word(desc, 0) != 1024 | 40 << 16 | 1 << 26 | 1 << 27 | 1 << 31
        || word(desc, 12) != 1 << 8
    {
        return TestResult::Fail("beacon BD 0 / tx_fill_cmddesc descriptor 0");
    }
    let order: Vec<(u8, u16, u32)> = bus
        .0
        .lock()
        .trace
        .iter()
        .copied()
        .filter(|(_, reg, _)| {
            matches!(
                *reg,
                0x101 | 0x20a | 0x383 | 0x422 | 0x550 | 0x6a8 | 0x1d0 | 0x1d4
            )
        })
        .collect();
    let expected: [(u8, u16, u32); 14] = [
        (16, 0x6a8, 0xc005),
        (8, 0x101, 0x03),
        (8, 0x550, 0x15),
        (8, 0x550, 0x15),
        (8, 0x422, 0x00),
        (8, 0x20a, 0x01),
        (8, 0x1d0, 0x00),
        (8, 0x383, 0x10),
        (8, 0x20a, 0x01),
        (8, 0x550, 0x1d),
        (8, 0x550, 0x0d),
        (8, 0x422, 0x40),
        (8, 0x101, 0x02),
        (8, 0x1d4, 0x01),
    ];
    if order != expected {
        return TestResult::Fail("download order / BCN_VALID acknowledgement / MSRRPT");
    }
    if narf_scheduler::block_on(owner.ee92_join_report(bssid, 5, None, &policy))
        != Err(Error::State)
    {
        return TestResult::Fail("second body while one is retained");
    }
    // A stale beacon BD OWN without an earlier proven upload is refused.
    let stale = Bus::new();
    let mut owner = running(&stale, local);
    owner.tx[0].bytes[3] = 0x80;
    if narf_scheduler::block_on(owner.ee92_join_report(bssid, 5, None, &policy))
        != Err(Error::Descriptor)
    {
        return TestResult::Fail("stale beacon BD OWN overwritten");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_rsvd_page_download_through_beacon_bd
);
