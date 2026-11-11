use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

const LOCAL: [u8; 6] = [2, 1, 2, 3, 4, 5];

/// A parked AR9300 MAC with coherent DMA regions, both receive FIFOs and
/// the queue-0 FIFO observed at their push registers.
struct Model {
    registers: RefCell<BTreeMap<u64, u32>>,
    regions: RefCell<Vec<(u64, usize, usize)>>,
    master: Cell<bool>,
    now: Cell<u64>,
    hp: RefCell<Vec<u32>>,
    lp: RefCell<Vec<u32>>,
    pushed: RefCell<Vec<u32>>,
    status_tail: Cell<usize>,
    released: RefCell<Vec<DmaBuffer>>,
    signal: RefCell<Option<Arc<crate::ath9k::irq::Signal>>>,
    delivered: RefCell<Vec<bool>>,
    writes: RefCell<Vec<(u64, u32)>>,
}

impl Model {
    fn new() -> Self {
        Self {
            registers: RefCell::new(BTreeMap::from([
                (CR, 0),
                (QTXE, 0),
                (QSTS, 0),
                (DIAG, RX_PARK),
                (irq::IER, 0),
            ])),
            regions: RefCell::new(Vec::new()),
            master: Cell::new(false),
            now: Cell::new(0),
            hp: RefCell::new(Vec::new()),
            lp: RefCell::new(Vec::new()),
            pushed: RefCell::new(Vec::new()),
            status_tail: Cell::new(0),
            released: RefCell::new(Vec::new()),
            signal: RefCell::new(None),
            delivered: RefCell::new(Vec::new()),
            writes: RefCell::new(Vec::new()),
        }
    }
    fn reg(&self, register: u64) -> u32 {
        self.registers.borrow().get(&register).copied().unwrap_or(0)
    }
    fn set(&self, register: u64, value: u32) {
        self.registers.borrow_mut().insert(register, value);
    }
    fn pointer(&self, address: u32, length: usize) -> *mut u8 {
        let address = u64::from(address);
        let regions = self.regions.borrow();
        let &(bus, cpu, _) = regions
            .iter()
            .find(|&&(bus, _, len)| address >= bus && address + length as u64 <= bus + len as u64)
            .expect("device access inside an owned region");
        (cpu + (address - bus) as usize) as *mut u8
    }
    fn put(&self, address: u32, value: u32) {
        // SAFETY: device-side write inside a live model region.
        unsafe { (self.pointer(address, 4) as *mut u32).write_volatile(value.to_le()) }
    }
    fn get(&self, address: u32) -> u32 {
        // SAFETY: device-side read inside a live model region.
        u32::from_le(unsafe { (self.pointer(address, 4) as *const u32).read_volatile() })
    }
    /// The device completes the queue-0 frame into the status ring.
    fn complete(&self, ok: bool) {
        let tail = self.status_tail.get();
        let entry = self.reg(Q_STATUS_RING_START) + (tail * TXS_BYTES) as u32;
        let words = [
            (0x168c << 16) | (1 << 15) | 9,
            0x0005_0000,
            0,
            if ok { 1 } else { 0x2 | (10 << 8) },
            1234,
            0,
            0,
            0x2a00_0000,
            1 | (7 << 1),
        ];
        for (index, word) in words.iter().enumerate() {
            self.put(entry + index as u32 * 4, *word);
        }
        self.status_tail.set((tail + 1) % TS_ENTRIES);
    }
    /// The device fills the head buffer of a receive FIFO.
    fn receive(&self, high: bool, frame: &[u8], more: bool) {
        let address = if high {
            self.hp.borrow_mut().remove(0)
        } else {
            self.lp.borrow_mut().remove(0)
        };
        let length = frame.len() + 4;
        let payload = self.pointer(address + RXS_BYTES as u32, length);
        for (index, byte) in frame.iter().chain(&[0xde, 0xad, 0xbe, 0xef]).enumerate() {
            // SAFETY: payload extent inside the posted buffer.
            unsafe { payload.add(index).write_volatile(*byte) }
        }
        self.put(address, 0x168c << 16);
        self.put(address + 4, 0x1b << 24);
        self.put(address + 8, length as u32 | if more { 0x1000 } else { 0 });
        self.put(address + 20, 0x3000_0000);
        self.put(address + 44, 3);
    }
}

impl Port for &Model {
    fn tx_chainmask(&self) -> u8 {
        7
    }
    fn transmit_allowed(&self) -> Result<(), Error> {
        Ok(())
    }
    fn access<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if self.master.get() != active {
            return Err(Error::Access);
        }
        operation()
    }
    fn read(&self, register: u64) -> Result<u32, Error> {
        Ok(self.reg(register))
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.writes.borrow_mut().push((register, value));
        match register {
            0x0074 => self.hp.borrow_mut().push(value),
            0x0078 => self.lp.borrow_mut().push(value),
            QTXDP => self.pushed.borrow_mut().push(value),
            // AR_CR_RXD stops both receive queues.
            CR if value & CR_RXD != 0 => self.set(CR, 0),
            CR => self.set(CR, if value == 0 { CR_RXE } else { value }),
            _ => self.set(register, value),
        }
        Ok(())
    }
    fn allocate(&self, bytes: usize) -> Result<DmaBuffer, Error> {
        let memory = narf_io::alloc_coherent_masked(
            bytes,
            narf_lib::id::DomainId::DRIVER_0,
            u64::from(u32::MAX),
        )
        .map_err(|_| Error::Memory)?;
        self.regions.borrow_mut().push((
            memory.dma_addr().raw(),
            memory.cpu_mut_ptr::<u8>() as usize,
            memory.len(),
        ));
        Ok(memory)
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.master.set(enabled);
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now.get()
    }
    fn delay_us(&self, us: u64) {
        self.now.set(self.now.get() + us);
    }
    fn release(&self, buffers: Vec<DmaBuffer>) {
        self.released.borrow_mut().extend(buffers);
    }
    fn interrupt(&self) -> Option<Arc<crate::ath9k::irq::Signal>> {
        self.signal.borrow().clone()
    }
    fn deliver(&self, enabled: bool) -> Result<(), Error> {
        self.delivered.borrow_mut().push(enabled);
        Ok(())
    }
}

fn outbound() -> Vec<u8> {
    let mut frame = vec![0x59; 64];
    frame[..2].copy_from_slice(&[8, 1]);
    frame[4..10].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[10..16].copy_from_slice(&LOCAL);
    frame[22..24].copy_from_slice(&[0x30, 0]);
    frame
}

fn received() -> Vec<u8> {
    let mut frame = outbound();
    frame[1] = 2;
    frame
}

fn check_packet_path(model: &Model) -> Result<(), &'static str> {
    // SAFETY: isolated model begins parked; no physical controller is touched.
    let mut packet = unsafe { Packet::prepare(model, LOCAL) }.map_err(|_| "prepare fault")?;
    let start = model.reg(Q_STATUS_RING_START);
    if start == 0
        || model.reg(Q_STATUS_RING_END) != start + 16 * 36
        || model.reg(DATABUF_SIZE) != 4048
        || model.master.get()
    {
        return Err("status ring / RX buffer size programming differs");
    }
    packet.start().map_err(|_| "start fault")?;
    if model.hp.borrow().len() != 4
        || model.lp.borrow().len() != 8
        || !model.master.get()
        || model.reg(DIAG) & RX_PARK != 0
        || !model.writes.borrow().contains(&(CR, 0))
    {
        return Err("ath_edma_start_recv sequence differs");
    }
    let id = packet.submit(&outbound(), 0).map_err(|_| "submit fault")?;
    let pushed = *model.pushed.borrow().last().ok_or("no QTXDP push")?;
    let txc: [u32; 32] = core::array::from_fn(|i| model.get(pushed + 4 * i as u32));
    if txc[0] != (0x168c << 16) | 0xc000 | 0x17
        || txc[2] == 0
        || txc[3] != 64 << 16
        || txc[11] != 68 | (63 << 16) | 0x100_0000
        || (txc[18] >> 2) & 7 != 7
        || txc[19] != 0x2000_0000
        || model.writes.borrow().iter().any(|&(r, _)| r == QTXE)
    {
        return Err("ar9003_txc of the legacy frame differs");
    }
    if !matches!(packet.delivery(), Ok(None)) {
        return Err("delivery reported before AR_TxDone");
    }
    model.complete(true);
    match packet.delivery() {
        Ok(Some(d)) if d.id == id && d.delivered && d.bytes == outbound() => {}
        _ => return Err("status-ring completion not delivered"),
    }
    if model.get(start + 8 * 4) != 0 {
        return Err("consumed status entry not cleared");
    }
    packet
        .submit(&outbound(), 0)
        .map_err(|_| "second submit fault")?;
    model.complete(false);
    match packet.delivery() {
        Ok(Some(d)) if !d.delivered => {}
        _ => return Err("excessive retries delivered"),
    }
    // HP is serviced before LP; the consumed buffer is fed back.
    model.receive(false, &received(), false);
    let mut high = received();
    high[30] = 0x11;
    model.receive(true, &high, false);
    match packet.receive() {
        Ok(step) if step.consumed && step.frame.as_ref().is_some_and(|f| f.bytes() == high) => {}
        _ => return Err("HP FIFO frame not received first"),
    }
    match packet.receive() {
        Ok(step) if step.frame.as_ref().is_some_and(|f| f.bytes() == received()) => {}
        _ => return Err("LP FIFO frame not received"),
    }
    if model.hp.borrow().len() != 4 || model.lp.borrow().len() != 8 {
        return Err("consumed buffers not re-posted");
    }
    // A multi-buffer chain and its continuation are dropped.
    model.receive(false, &received(), true);
    model.receive(false, &received()[..40], false);
    model.receive(false, &received(), false);
    for expected in [false, false, true] {
        match packet.receive() {
            Ok(step) if step.consumed && step.frame.is_some() == expected => {}
            _ => return Err("rs_more chain handling differs"),
        }
    }
    if !matches!(packet.receive(), Ok(step) if !step.consumed) {
        return Err("idle FIFO reported a buffer");
    }
    // A two-series rate-control frame: 11 Mbps x2 then 1 Mbps x4.
    let series = crate::ath9k::rates::Series {
        rates: [3, 0, 0, 0],
        tries: [2, 4, 0, 0],
        basic: 0,
    };
    packet
        .submit_rates(&outbound(), series)
        .map_err(|_| "rate submit fault")?;
    let pushed = *model.pushed.borrow().last().ok_or("no QTXDP push")?;
    let txc: [u32; 32] = core::array::from_fn(|i| model.get(pushed + 4 * i as u32));
    if txc[13] & 0xff_0000 != (2 << 16) | (4 << 20)
        || txc[14] & 0xffff != 0x18 | (0x1b << 8)
        || (txc[18] >> 7) & 7 != 7
        || packet.idle_admissible()
    {
        return Err("rate series not carried into ctl13/14/18");
    }
    model.complete(true);
    if !matches!(packet.delivery(), Ok(Some(d)) if d.delivered) || !packet.idle_admissible() {
        return Err("rate-control frame not delivered");
    }
    // MSI service: causes read, IER killed, RXEOL masked until the end.
    *model.signal.borrow_mut() = Some(crate::ath9k::irq::Signal::new());
    if !matches!(packet.enable_interrupts(), Ok(true)) || packet.interrupt().is_none() {
        return Err("interrupts not enabled with an installed vector");
    }
    model.set(0x4038, 2);
    model.set(0x7044, 2);
    model.set(0x80, 0x12);
    model.set(0xc0, 0x12);
    match packet.service_begin() {
        Ok(Some(e)) if e.rx_lp && e.rx_eol && model.reg(irq::IER) == 0 => {}
        _ => return Err("service_begin decode/kill differs"),
    }
    if model.reg(irq::IMR) != irq::STATION_IMR & !irq::RX_EOL_ORN {
        return Err("RXEOL|RXORN not masked during service");
    }
    packet.service_end().map_err(|_| "service_end fault")?;
    if model.reg(irq::IMR) != irq::STATION_IMR || model.reg(irq::IER) != 1 {
        return Err("service_end did not restore the mask");
    }
    model.set(0x4038, 0);
    model.set(0x80, 0);
    model.set(0xc0, 0);
    packet.stop().map_err(|_| "stop fault")?;
    if !packet.reclaimed()
        || packet.phase() != Phase::Stopped
        || model.master.get()
        || model.released.borrow().len() != 16
        || model.delivered.borrow().as_slice() != [true, false]
    {
        return Err("terminal stop did not reclaim every allocation");
    }
    Ok(())
}

fn smoke_ath9k_ar9300_edma_packet_owner_tx_rx_and_stop() -> TestResult {
    let model = Model::new();
    match check_packet_path(&model) {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}

fn check_interrupts() -> Result<(), &'static str> {
    let model = Model::new();
    let port = &model;
    model.set(0x40a4, 0x5064_0000);
    let mask = irq::enable(&port, true).map_err(|_| "enable fault")?;
    if model.reg(irq::IMR) != 0x8180_0175
        || model.reg(0xac) != 0x00c1_0000
        || model.reg(0xa4) != 1
        || model.reg(0xa8) != 1
        || model.reg(0x2c) != (2000 << 16) | 500
        || model.reg(0x40a4) & 1 == 0
        || model.reg(0x40d4) != 7
        || model.reg(irq::IER) != 1
        || mask.imr != irq::STATION_IMR
    {
        return Err("EDMA station interrupt programming differs");
    }
    model.set(0x4038, 2);
    model.set(0x7044, 2);
    model.set(0x80, 0x41);
    model.set(0xc0, 0x41);
    let events = irq::cause(&port, mask.imr, false)
        .map_err(|_| "cause fault")?
        .ok_or("pending cause lost")?;
    if !events.rx_hp || events.rx_lp || !events.tx || events.reset() {
        return Err("ar9003_hw_get_isr RX/TX decode differs");
    }
    model.set(0x80, 0x0080_0000);
    model.set(0xc0, 0x0080_0000);
    model.set(0x8c, 0x0001_0000);
    model.set(0xa7c0, 0x1f);
    let events = irq::cause(&port, mask.imr, false)
        .map_err(|_| "cause fault")?
        .ok_or("watchdog cause lost")?;
    if events.bb_watchdog != Some(0x1f) || !events.reset() || model.reg(0xa7c0) != 0x17 {
        return Err("BB watchdog not read and reported for chip reset");
    }
    model.set(0x4038, 0);
    model.set(0x80, 0);
    model.set(0x4028, 0x1000);
    let events = irq::cause(&port, mask.imr, false)
        .map_err(|_| "cause fault")?
        .ok_or("sync cause lost")?;
    if !events.fatal
        || !model
            .writes
            .borrow()
            .ends_with(&[(0x4000, 0x100), (0x4000, 0), (0x4028, 0x1000)])
    {
        return Err("completion timeout not pulsed and reported fatal");
    }
    model.set(0x4028, 0);
    if !matches!(irq::cause(&port, mask.imr, false), Ok(None)) {
        return Err("idle cause reported");
    }
    // MCI routing: the async MCI bit reports only when MCI is enabled.
    if irq::INT_MCI != 0x200 {
        return Err("INT_MCI is not 0x200");
    }
    model.set(0x4038, 0x80);
    let events = irq::cause(&port, mask.imr, true)
        .map_err(|_| "cause fault (mci)")?
        .ok_or("mci cause lost")?;
    if !events.mci {
        return Err("async MCI bit not reported with MCI enabled");
    }
    let events = irq::cause(&port, mask.imr, false)
        .map_err(|_| "cause fault (mci off)")?
        .ok_or("mci cause lost (off)")?;
    if events.mci {
        return Err("async MCI bit reported with MCI disabled");
    }
    Ok(())
}

fn smoke_ath9k_ar9300_edma_interrupt_mask_and_cause() -> TestResult {
    match check_interrupts() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}

/// In-place `ath_reset`: a FATAL cause queues a reset instead of closing
/// the owner; `ath_prepare_reset` stops RX/TX with every allocation kept,
/// the chip reset wipes the MAC, and `ath_complete_reset` re-feeds the same
/// buffers, re-writes BSSID/AID and re-enables interrupts, after which RX
/// and TX run again on the retained rings.
fn check_in_place_reset() -> Result<(), &'static str> {
    const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
    let model = Model::new();
    // SAFETY: isolated model begins parked; no physical controller is touched.
    let mut packet = unsafe { Packet::prepare(&model, LOCAL) }.map_err(|_| "prepare fault")?;
    let start = model.reg(Q_STATUS_RING_START);
    packet.start().map_err(|_| "start fault")?;
    packet
        .set_peer(Some((AP, 5)), 9)
        .map_err(|_| "peer fault")?;
    *model.signal.borrow_mut() = Some(crate::ath9k::irq::Signal::new());
    if !matches!(packet.enable_interrupts(), Ok(true)) {
        return Err("interrupts not enabled");
    }
    let mut posted: Vec<u32> = model
        .hp
        .borrow()
        .iter()
        .chain(model.lp.borrow().iter())
        .copied()
        .collect();
    posted.sort_unstable();
    let id = packet.submit(&outbound(), 0).map_err(|_| "submit fault")?;
    // ATH9K_INT_FATAL (PCIe completion timeout sync cause).
    model.set(0x7044, 2);
    model.set(0x4038, 0);
    model.set(0x80, 0);
    model.set(0xc0, 0);
    model.set(0x4028, 0x1000);
    if packet.service_begin().is_ok() || packet.reset_request() != Some(ResetType::FatalInt) {
        return Err("FATAL did not queue RESET_TYPE_FATAL_INT");
    }
    model.set(0x4028, 0);
    if packet.pause_for_reset() != Ok(Some(id))
        || model.master.get()
        || model.reg(irq::IER) & 1 != 0
        || model.reg(CR) & CR_RXE != 0
        || !model.released.borrow().is_empty()
        || packet.reclaimed()
        || packet.paused_port().is_none()
    {
        return Err("ath_prepare_reset did not stop DMA while keeping storage");
    }
    // ath9k_hw_chip_reset: the MAC loses its ring, FIFO, BSSID and IRQ state.
    for register in [
        Q_STATUS_RING_START,
        Q_STATUS_RING_END,
        DATABUF_SIZE,
        0x8008,
        0x800c,
        irq::IMR,
    ] {
        model.set(register, 0);
    }
    model.hp.borrow_mut().clear();
    model.lp.borrow_mut().clear();
    model.status_tail.set(0);
    packet
        .resume_after_reset()
        .map_err(|_| "ath_complete_reset fault")?;
    let mut reposted: Vec<u32> = model
        .hp
        .borrow()
        .iter()
        .chain(model.lp.borrow().iter())
        .copied()
        .collect();
    reposted.sort_unstable();
    if model.reg(Q_STATUS_RING_START) != start
        || model.reg(DATABUF_SIZE) != 4048
        || reposted != posted
        || !model.master.get()
        || model.reg(DIAG) & RX_PARK != 0
        || model.reg(0x8008) != u32::from_le_bytes([AP[0], AP[1], AP[2], AP[3]])
        || model.reg(irq::IER) != 1
        || model.reg(irq::IMR) != irq::STATION_IMR
        || packet.reset_request().is_some()
        || packet.phase() != Phase::Running
    {
        return Err("ath_complete_reset did not restart the retained engines");
    }
    model.receive(true, &received(), false);
    match packet.receive() {
        Ok(step) if step.frame.as_ref().is_some_and(|f| f.bytes() == received()) => {}
        _ => return Err("RX did not restart"),
    }
    let next = packet
        .submit(&outbound(), 0)
        .map_err(|_| "post-reset submit")?;
    model.complete(true);
    if !matches!(packet.delivery(), Ok(Some(d)) if d.id == next && d.delivered) {
        return Err("TX did not restart on the reset status ring");
    }
    model.set(0x80, 0);
    model.set(0xc0, 0);
    packet.stop().map_err(|_| "stop fault")?;
    if !packet.reclaimed() || model.released.borrow().len() != 16 {
        return Err("terminal stop after reset did not reclaim");
    }
    Ok(())
}

fn smoke_ath9k_ar9300_in_place_reset_keeps_rings_and_restarts_rx_tx() -> TestResult {
    match check_in_place_reset() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_edma_packet_owner_tx_rx_and_stop
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_in_place_reset_keeps_rings_and_restarts_rx_tx
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_edma_interrupt_mask_and_cause
);
