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
    /// Test-only hardware model: when true, pausing RX DMA lets a
    /// draining engine clear its backdoor hang report — the transient
    /// hang a recovery is meant to admit. False (default) models a
    /// truly wedged engine whose report persists.
    hang_clears_on_pause: bool,
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
        // Transient-hang model (see `Model::hang_clears_on_pause`): the
        // RX DMA pause lets a draining engine drop its hang report.
        if reg == super::REG_RXDMA_CONTROL
            && value & super::RXDMA_PAUSE != 0
            && m.hang_clears_on_pause
        {
            m.regs[usize::from(super::REG_BACKDOOR_DBI_DATA + 3)] &= !0x03;
        }
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
    owner.rtl8192ee_power = Some(permission20());
    let started = owner.start_packets();
    let master = bus.0.lock().master;
    if started.is_err()
        || owner.phase() != Phase::Running
        || !bus.traced((16, 0x100, 0x2ff))
        || !bus.traced((16, 0x300, 0x8000))
        || !master
    {
        return TestResult::Fail("REG_CR / REG_PCIE_CTRL_REG release");
    }
    // rtl92ee_enable_interrupt (c2c8ae88b): HIMR / HIMRE masks, once.
    {
        use super::super::super::super::rtl8192ee::h2c;
        if owner.enable_interrupts().is_err()
            || !bus.traced((32, h2c::REG_HIMR, h2c::IRQ_MASK0))
            || !bus.traced((32, h2c::REG_HIMRE, h2c::IRQ_MASK1))
            || owner.enable_interrupts() != Err(Error::State)
        {
            return TestResult::Fail("8192EE interrupt masks after start");
        }
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
    // ee92_quiesce: every TX queue's read point at the host write point
    // (BE 1/1), the 0x5f8 buffers empty, then the RX DMA pause.
    if owner.stop_packets().is_err()
        || narf_scheduler::block_on(owner.quiesce()).is_err()
        || !bus.traced((8, 0x286, 4))
        || owner.published
        || narf_scheduler::block_on(owner.quiesce()) != Err(Error::State)
    {
        return TestResult::Fail("stop / 8192EE card-disable retirement proof");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_txbd_doorbell_completion_and_rx_ack
);

/// A signed-format `N92E` envelope with every curve measured (rows: 20 MHz
/// and 40 MHz above on channel 1) under a 20 dBm 2402-2472 MHz rule.
fn envelope() -> (
    super::super::super::super::rtl8192ee::envelope::Calibration,
    narf_wireless::reg::RegulatoryDomain,
) {
    use super::super::super::super::rtl8192ee::{
        envelope::Calibration,
        phy_tests::{envelope_factory, n92e},
    };
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let factory = envelope_factory();
    let file = n92e(&factory, &[(1, 20, 0), (1, 40, 1)], 4, &[]);
    let cal = Calibration::from_verified(&file, Some([1; 32]), &factory).unwrap();
    let domain = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 40,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    };
    (cal, domain)
}

/// The channel-1 20 MHz permission of [`envelope`] (every rate admitted),
/// which `ee92_submit` checks every on-air rate against.
fn permission20() -> super::super::super::super::rtl8192ee::envelope::Permission {
    let (cal, domain) = envelope();
    cal.permission(&domain, 1).unwrap()
}

fn running(bus: &Bus, local: [u8; 6]) -> Prepared<Bus, Block> {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = allocated(bus, &drops).unwrap();
    narf_scheduler::block_on(owner.prepare()).unwrap();
    owner.phase = Phase::MacConfigured;
    owner.packet.local = Some(local);
    owner.packet.ee92.channel = Some(1);
    owner.rtl8192ee_power = Some(permission20());
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
    // Only the join's own writes are ordered below (start_packets wrote
    // 0x422/0x550 already).
    bus.0.lock().trace.clear();
    // `_rtl92ee_download_rsvd_page` (rtl8192ee/hw.c:366-374) writes
    // `REG_MGQ_TXBD_NUM + 3 = txbc | BIT(4)` from what it read; init_mac
    // left the RX_RXBD_NUM high byte there.
    let txbc = bus.0.lock().regs[0x383];
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
        (8, 0x383, u32::from(txbc | 0x10)),
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

pub(crate) fn smoke_rtl8192ee_tx_report_rate_mask_watchdog_and_quiesce() -> TestResult {
    use super::super::super::super::rtl8192ee::h2c;
    let bus = Bus::new();
    let local = [2, 0, 0, 0, 0, 1];
    let ap = [2, 0, 0, 0, 0, 9];
    let mut owner = running(&bus, local);
    // EAPOL (to-DS, non-QoS): rtl_is_tx_report_skb ⇒ SPE_RPT + SW_DEFINE
    // `(1 & 0x3f) << 2`.
    let mut eapol = vec![0u8; 40];
    eapol[0] = 0x08;
    eapol[1] = 0x01;
    eapol[4..10].copy_from_slice(&ap);
    eapol[10..16].copy_from_slice(&local);
    eapol[16..22].copy_from_slice(&ap);
    eapol[24..32].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    if owner.submit(&eapol, trx::DESC_RATE1M).is_err() {
        return TestResult::Fail("EAPOL submit");
    }
    if word(&owner.tx[11], 8) & 1 << 19 == 0 || word(&owner.tx[11], 24) & 0xfff != 4 {
        return TestResult::Fail("EAPOL frame without SPE_RPT/SW_DEFINE");
    }
    bus.set32(0x3a8, 1 << 16 | 1);
    if !matches!(owner.poll_delivery(), Ok(Some(_))) {
        return TestResult::Fail("EAPOL delivery");
    }
    // 2T2R HT peer at 20 MHz, INIT level: full mask; refused unless every
    // mask rate is admitted.
    let peer = h2c::Peer {
        legacy: 0xfff,
        ht: Some([0xff, 0xff]),
        sgi20: false,
        sgi40: false,
    };
    let full = h2c::mask_rates(&h2c::rate_mask(&peer, false, 0, true)).unwrap();
    if narf_scheduler::block_on(owner.ee92_install_rate_mask(peer, false, 0, full >> 1))
        != Err(Error::Power(
            super::super::super::super::channel_power::Error::Policy,
        ))
        || owner.phase() != Phase::Running
        || owner.packet.ee92.link.is_some()
    {
        return TestResult::Fail("RA mask outside the admitted rates installed");
    }
    if narf_scheduler::block_on(owner.ee92_install_rate_mask(peer, false, 0, full)).is_err()
        || owner.packet.ee92.link.map(|l| l.2) != Some(h2c::ARFR_NB)
        || !bus.traced((8, 0x1d0, u32::from(h2c::H2C_RA_MASK)))
        || !bus.traced((8, 0x550, 0x1d))
    {
        return TestResult::Fail("H2C_92E_RA_MASK / BCN_CTRL BIT(3)");
    }
    // Watchdog: PWDB 60 from INIT is HIGH (> 50): refresh at level 1.
    match narf_scheduler::block_on(owner.ee92_dm_watchdog(60, full)) {
        Ok(true) if owner.packet.ee92.ratr_state == 1 => {}
        _ => return TestResult::Fail("watchdog RA state refresh"),
    }
    if !bus.traced((8, 0x1d4, u32::from(h2c::H2C_RA_MASK))) {
        return TestResult::Fail("refreshed mask not sent in the next box");
    }
    // Same level: no refresh; a pending RA report is applied.
    owner.packet.ee92.ra_report = Some((0x14, false));
    match narf_scheduler::block_on(owner.ee92_dm_watchdog(60, full)) {
        Ok(false) if owner.packet.ee92.ra_report.is_none() => {}
        _ => return TestResult::Fail("watchdog without a level change / RA report"),
    }
    let (low, high) = super::super::super::super::rtl8192ee::c2h::dynamic_arfb(0x14, false);
    if !bus.traced((32, 0x430, low)) || !bus.traced((32, 0x434, high)) {
        return TestResult::Fail("dynamic ARFB pair");
    }
    // Leisure: the watchdog does not run.
    owner.packet.leisure = true;
    if narf_scheduler::block_on(owner.ee92_dm_watchdog(0, full)) != Ok(false)
        || owner.packet.ee92.ratr_state != 1
    {
        return TestResult::Fail("watchdog ran in LPS");
    }
    owner.packet.leisure = false;
    // A TX queue whose device read point lags keeps every mapping.
    bus.set32(0x3a8, 1);
    if owner.stop_packets().is_err()
        || narf_scheduler::block_on(owner.quiesce()) != Err(Error::PacketTimeout)
        || !owner.published
        || bus.traced((8, 0x286, 4))
    {
        return TestResult::Fail("lagging read point retired");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_tx_report_rate_mask_watchdog_and_quiesce
);

/// HT TX on the 8192EE owner: adaptive DATA needs the installed RA mask;
/// with it the descriptor leaves USE_RATE/DISFB clear, starts at
/// `_rtl_get_highest_n_rate` (MCS15 for a 2T2R peer), names RATE_ID NGB
/// (`_rtl_txrate_selectmode`, no NEW_RATEID) and carries AGG_EN, the peer
/// density and `max_agg_num 0x14`; multicast adaptive frames and legacy
/// links' aggregation are refused.
pub(crate) fn smoke_rtl8192ee_ht_ra_adaptive_aggregate_tx() -> TestResult {
    use super::super::super::super::rtl8192ee::h2c;
    let bus = Bus::new();
    let local = [2, 0, 0, 0, 0, 1];
    let ap = [2, 0, 0, 0, 0, 9];
    let mut owner = running(&bus, local);
    owner.packet.qos = true;
    let mut frame = vec![0u8; 40];
    frame[0] = 0x88;
    frame[1] = 0x01;
    frame[4..10].copy_from_slice(&ap);
    frame[10..16].copy_from_slice(&local);
    frame[16..22].copy_from_slice(&ap);
    if owner.submit_aggregate(
        &frame,
        trx::DESC_RATEMCS0 + 7,
        Some((5, true)),
        false,
        false,
    ) != Err(Error::Packet)
    {
        return TestResult::Fail("aggregation on a legacy link");
    }
    owner.packet.ht = true;
    if owner.submit_aggregate(&frame, trx::DESC_RATEMCS0 + 7, None, true, false)
        != Err(Error::State)
    {
        return TestResult::Fail("adaptive DATA without an RA mask");
    }
    let peer = h2c::Peer {
        legacy: 0xfff,
        ht: Some([0xff, 0xff]),
        sgi20: true,
        sgi40: false,
    };
    let admitted = permission20().admitted_rates() as u32;
    if narf_scheduler::block_on(owner.ee92_install_rate_mask(peer, false, 0, admitted)).is_err() {
        return TestResult::Fail("RA mask install");
    }
    let mut group = frame.clone();
    group[4] = 0xff;
    if owner.submit_aggregate(&group, trx::DESC_RATEMCS0 + 7, None, true, false)
        != Err(Error::Packet)
    {
        return TestResult::Fail("adaptive multicast DATA");
    }
    if owner
        .submit_aggregate(&frame, trx::DESC_RATEMCS0 + 7, Some((5, true)), true, true)
        .is_err()
    {
        return TestResult::Fail("adaptive HT DATA submit");
    }
    let desc = &owner.tx[11];
    let (dw1, dw2, dw3, dw4) = (word(desc, 4), word(desc, 8), word(desc, 12), word(desc, 16));
    if dw4 & 0x7f != u32::from(trx::DESC_RATEMCS15)
        || dw3 & (1 << 8 | 1 << 10) != 0
        || (dw1 >> 16) & 0x1f != 0
        || dw2 & 1 << 12 == 0
        || (dw2 >> 20) & 7 != 5
        || (dw3 >> 17) & 0x1f != 0x14
        || (dw4 >> 5) & 3 != 0
    {
        return TestResult::Fail("RA-adapted HT descriptor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_ht_ra_adaptive_aggregate_tx
);

/// Station branch of the 8192EE owner: `rtl_op_add_interface` network type
/// at start, `prepare_station_peer` (`HW_VAR_BSSID`/`BASIC_RATE`/slot/SIFS/
/// `set_qos`/`ACK_PREAMBLE`), `complete_station_peer_admitted` (CAM reset,
/// keep-alive, linked network type, join report), LPS enter/leave through
/// the 8192EE mailbox, and `leave_station_peer` (NOLINK, MSRRPT
/// disconnect, zero BSSID) — none of it on the 88EE paths.
pub(crate) fn smoke_rtl8192ee_station_peer_join_lps_and_leave() -> TestResult {
    use super::super::super::super::rtl8192ee::{h2c, mac, station as hw};
    let bus = Bus::new();
    let local = [2, 0, 0, 0, 0, 1];
    let ap = [2, 0, 0, 0, 0, 9];
    bus.0.lock().regs[usize::from(hw::MSR)] = 0x04;
    let mut owner = running(&bus, local);
    if bus.0.lock().regs[usize::from(hw::MSR)] != 0x04
        || bus.read32(mac::REG_RCR).unwrap()
            != mac::RECEIVE_CONFIG & !(hw::RCR_CBSSID_DATA | hw::RCR_CBSSID_BCN)
        || !bus.traced((8, 0x541, 0x64))
        || !bus.traced((8, 0x511, 0x66))
    {
        return TestResult::Fail("start: rtl92ee_set_network_type(STATION) NOLINK");
    }
    // Basic {1, 2, 5.5, 11}, supported adds OFDM: RRSR from supp_rates.
    let rates = 0x0fff;
    let basic = 0x000f;
    if narf_scheduler::block_on(owner.prepare_station_peer(ap, rates, basic, 0x0421)).is_err() {
        return TestResult::Fail("8192EE prepare_station_peer");
    }
    let rrsr = hw::basic_rate(rates);
    if rrsr != 0x015d
        || !bus.traced((8, 0x440, 0x5d))
        || !bus.traced((8, 0x441, 0x01))
        || !bus.traced((8, 0x51b, 9))
        || !bus.traced((8, 0x515, 0x0a))
        || !bus.traced((8, 0x517, 0x0a))
        || !bus.traced((8, 0x429, 0x0a))
        || !bus.traced((8, 0x63b, 0x0a))
        || !bus.traced((16, 0x63e, 0x0e0e))
        || !bus.traced((32, 0x50c, 0xa44f))
        || !bus.traced((32, 0x504, 0x5e_4322))
        || !bus.traced((32, 0x500, 0x2f_3222))
        || !bus.traced((8, 0x442, 0x80))
        || (0..6).any(|i| bus.0.lock().regs[0x618 + i] != ap[i])
    {
        return TestResult::Fail("BSSID / RRSR / slot / SIFS / set_qos / ACK preamble");
    }
    if narf_scheduler::block_on(owner.prepare_station_peer([1, 0, 0, 0, 0, 0], rates, basic, 0))
        != Err(Error::Packet)
    {
        return TestResult::Fail("multicast BSSID accepted");
    }
    let before = owner.packet.ee92.mailbox.next_box();
    let policy = |_: &Prepared<Bus, Block>| Ok(());
    if narf_scheduler::block_on(owner.complete_station_peer_admitted(ap, 5, None, policy)).is_err()
        || owner.phase() != Phase::Running
        || owner.packet.reserved.is_none()
    {
        return TestResult::Fail("8192EE complete_station_peer_admitted");
    }
    let keep_alive = 0x1d0 + u16::from(before) * 4;
    if !bus.traced((32, hw::REG_CAMCMD, hw::CAM_RESET))
        || !bus.traced((8, keep_alive, u32::from(h2c::H2C_KEEP_ALIVE_CTRL)))
        || !bus.traced((8, keep_alive + 1, 0xff))
        || !bus.traced((8, keep_alive + 2, 10))
        || bus.0.lock().regs[usize::from(hw::MSR)] != 0x04 | hw::MSR_INFRA
        || bus.read32(mac::REG_RCR).unwrap()
            != mac::RECEIVE_CONFIG | hw::RCR_CBSSID_DATA | hw::RCR_CBSSID_BCN
        || bus.0.lock().regs[0x6a8] != 5
    {
        return TestResult::Fail("CAM reset / keep-alive / linked network type / AID");
    }
    let entered = narf_scheduler::block_on(owner.enter_leisure()).is_ok()
        && owner.leisure()
        && !owner.packet.ee92.mailbox.ps_active;
    let left = narf_scheduler::block_on(owner.leave_leisure()).is_ok()
        && !owner.leisure()
        && owner.packet.ee92.mailbox.ps_active;
    if !entered || !left || !bus.traced((8, 0x3dc, 0x80)) || !bus.traced((8, 0x3dc, 0x00)) {
        return TestResult::Fail("8192EE fwlps enter/leave");
    }
    if narf_scheduler::block_on(owner.leave_station_peer()).is_err()
        || owner.phase() != Phase::Running
        || owner.packet.reserved.is_some()
        || owner.packet.retired.is_empty()
        || owner.packet.ee92.link.is_some()
        || bus.0.lock().regs[usize::from(hw::MSR)] != 0x04
        || bus.read32(mac::REG_RCR).unwrap()
            != mac::RECEIVE_CONFIG & !(hw::RCR_CBSSID_DATA | hw::RCR_CBSSID_BCN)
        || (0..6).any(|i| bus.0.lock().regs[0x618 + i] != 0)
    {
        return TestResult::Fail("leave_station_peer NOLINK / MSRRPT / BSSID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_station_peer_join_lps_and_leave
);

/// `_rtl_query_protection_mode` on 8192EE: RTS/CTS (RTS_EN) and
/// CTS-to-self (CTS2SELF) at `DESC_RATE24M`, long preamble, kept with the
/// firmware RA (USE_RATE/DISFB clear); `rtl_is_special_data` EAPOL forced
/// to `DESC_RATE11M` with USE_RATE + DISFB; a Null DATA frame with an
/// installed RA mask clears USE_RATE (DISFB, `RATR_INX_WIRELESS_MC`); and
/// the mac80211 ERP preamble/slot derivation with its
/// `BSS_CHANGED_ERP_*` register writes.
pub(crate) fn smoke_rtl8192ee_erp_protection_special_and_null_tx() -> TestResult {
    use super::super::super::super::protection::Mode;
    use super::super::super::super::rtl8192ee::{h2c, station as hw};
    let local = [2, 0, 0, 0, 0, 1];
    let ap = [2, 0, 0, 0, 0, 9];
    let peer = h2c::Peer {
        legacy: 0xfff,
        ht: None,
        sgi20: false,
        sgi40: false,
    };
    let admitted = permission20().admitted_rates() as u32;
    // Descriptor words 1/3/4 of the single pending frame.
    let words = |owner: &Prepared<Bus, Block>| {
        let pending = owner.packet.pending.as_ref().unwrap();
        let desc = &owner.tx[7 + pending.queue];
        let base = pending.slot * trx::TX_DESC_SIZE;
        (
            word(desc, base + 4),
            word(desc, base + 12),
            word(desc, base + 16),
        )
    };
    let mut data = vec![0u8; 40];
    data[0] = 0x08;
    data[1] = 0x01;
    data[4..10].copy_from_slice(&ap);
    data[10..16].copy_from_slice(&local);
    data[16..22].copy_from_slice(&ap);
    for (mode, rts, cts) in [(Mode::RtsCts, 1u32, 0u32), (Mode::CtsToSelf, 0, 1)] {
        let bus = Bus::new();
        let mut owner = running(&bus, local);
        if narf_scheduler::block_on(owner.ee92_install_rate_mask(peer, false, 0, admitted)).is_err()
        {
            return TestResult::Fail("RA mask install");
        }
        owner.packet.protection = mode;
        if owner
            .submit_aggregate(&data, trx::DESC_RATE54M, None, true, false)
            .is_err()
        {
            return TestResult::Fail("protected adaptive DATA refused");
        }
        let (_, dw3, dw4) = words(&owner);
        if (dw3 >> 12) & 1 != rts
            || (dw3 >> 11) & 1 != cts
            || dw3 & (1 << 13) != 0
            || (dw4 >> 24) & 0x1f != u32::from(trx::DESC_RATE24M)
            || dw3 & (1 << 8 | 1 << 10) != 0
        {
            return TestResult::Fail("RTS/CTS-to-self descriptor with firmware RA");
        }
    }
    // EAPOL (unprotected, LLC/SNAP 0x888e): special data at 11M.
    let mut eapol = data.clone();
    eapol[24..30].copy_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0]);
    eapol[30..32].copy_from_slice(&[0x88, 0x8e]);
    let mut dhcp = vec![0u8; 24 + 8 + 28];
    dhcp[..24].copy_from_slice(&data[..24]);
    dhcp[30..32].copy_from_slice(&[0x08, 0x00]);
    dhcp[32] = 0x45;
    dhcp[41] = 17;
    dhcp[53] = 68;
    dhcp[55] = 67;
    let mut protected = eapol.clone();
    protected[1] |= 0x40;
    if !super::special_data(&eapol)
        || !super::special_data(&dhcp)
        || super::special_data(&protected)
        || super::special_data(&data)
    {
        return TestResult::Fail("rtl_is_special_data classification");
    }
    {
        let bus = Bus::new();
        let mut owner = running(&bus, local);
        if narf_scheduler::block_on(owner.ee92_install_rate_mask(peer, false, 0, admitted)).is_err()
            || owner
                .submit_aggregate(&eapol, trx::DESC_RATE1M, None, true, false)
                .is_err()
        {
            return TestResult::Fail("EAPOL submit");
        }
        let (dw1, dw3, dw4) = words(&owner);
        if dw4 & 0x7f != u32::from(trx::DESC_RATE11M)
            || dw3 & (1 << 8) == 0
            || dw3 & (1 << 10) == 0
            || (dw1 >> 16) & 0x1f != 7
        {
            return TestResult::Fail("special data forced DESC_RATE11M");
        }
    }
    // Null DATA: driver rate before the RA mask, firmware RA after it.
    let mut null = data[..24].to_vec();
    null[0] = 0x48;
    for installed in [false, true] {
        let bus = Bus::new();
        let mut owner = running(&bus, local);
        if installed
            && narf_scheduler::block_on(owner.ee92_install_rate_mask(peer, false, 0, admitted))
                .is_err()
        {
            return TestResult::Fail("RA mask install");
        }
        if owner
            .submit_aggregate(&null, trx::DESC_RATE1M, None, false, false)
            .is_err()
        {
            return TestResult::Fail("Null submit");
        }
        let (dw1, dw3, _) = words(&owner);
        if (dw3 & (1 << 8) != 0) == installed || dw3 & (1 << 10) == 0 || (dw1 >> 16) & 0x1f != 7 {
            return TestResult::Fail("Null DATA USE_RATE / DISFB / RATE_ID");
        }
    }
    // ieee80211_handle_bss_capability: ERP Barker bit wins over the
    // capability; no ERP element falls back to it.
    if hw::erp_timing(0x0420, Some(0x04)) != (false, true)
        || hw::erp_timing(0x0020, Some(0x03)) != (true, false)
        || hw::erp_timing(0x0020, None) != (true, false)
        || hw::erp_timing(0x0400, None) != (false, true)
        || hw::erp_octet(&[42, 1, 0x07]) != Ok(Some(0x07))
        || hw::erp_octet(&[42, 2, 0, 0]).is_ok()
        || hw::erp_octet(&[42, 1, 0, 42, 1, 0]).is_ok()
    {
        return TestResult::Fail("ERP preamble / slot derivation");
    }
    let bus = Bus::new();
    if hw::erp_changed(&bus, (true, true), (false, false), 1).is_err()
        || !bus.traced((8, 0x442, 0x20))
        || !bus.traced((8, 0x51b, 20))
    {
        return TestResult::Fail("BSS_CHANGED_ERP_PREAMBLE / _SLOT writes");
    }
    let unchanged = Bus::new();
    if hw::erp_changed(&unchanged, (true, false), (true, false), 0).is_err()
        || unchanged.0.lock().trace.iter().any(|row| row.0 == 8)
    {
        return TestResult::Fail("unchanged ERP flags rewritten");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_erp_protection_special_and_null_tx
);

pub(crate) fn smoke_rtl8192ee_pcie_dma_hang_recovery_and_release() -> TestResult {
    // Transient hang: the backdoor probe bit is set and the TX hang bit
    // is reported, but the engine is only draining from a previous
    // owner — pausing RX DMA clears the report, so recovery admits the
    // board and releases the pause.
    let bus = Bus::new();
    bus.0.lock().hang_clears_on_pause = true;
    bus.0.lock().regs[usize::from(super::REG_BACKDOOR_DBI_DATA + 3)] = 1 << 2 | 1;
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = allocated(&bus, &drops).unwrap();
    if narf_scheduler::block_on(owner.prepare()).is_err() || owner.phase() != Phase::Prepared {
        return TestResult::Fail("transient DMA hang not recovered");
    }
    if !bus.traced((8, super::REG_RXDMA_CONTROL, u32::from(super::RXDMA_PAUSE)))
        || !bus.traced((8, super::REG_RXDMA_CONTROL, 0))
    {
        return TestResult::Fail("recovery RX DMA pause/release not traced");
    }
    {
        let m = bus.0.lock();
        if m.regs[usize::from(super::REG_RXDMA_CONTROL)] & super::RXDMA_PAUSE != 0
            || m.regs[0x301] != 0xff
            || m.regs[0x100] & 0xcf != 0
        {
            return TestResult::Fail("recovered board left DMA paused or gates open");
        }
    }
    if !bus.traced((32, 0x328, owner.tx[4].address as u32)) {
        return TestResult::Fail("recovered board published no BD bases");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8192ee_pcie_dma_hang_recovery_and_release
);
