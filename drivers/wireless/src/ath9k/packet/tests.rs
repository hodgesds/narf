use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::{IrqSafeSpinLock, IrqSafeSpinLockGuard};
// Synchronous model operations never retain these guards across an await.
// Arc-backed fixtures can therefore exercise the actual Send+Sync Device.
pub(in crate::ath9k) struct Cell<T> {
    value: IrqSafeSpinLock<T>,
}
impl<T> Cell<T> {
    pub fn new(value: T) -> Self {
        Self {
            value: IrqSafeSpinLock::new(value),
        }
    }
    pub fn set(&self, value: T) {
        *self.value.lock() = value;
    }
}
impl<T: Copy> Cell<T> {
    pub fn get(&self) -> T {
        *self.value.lock()
    }
}
pub(in crate::ath9k) struct RefCell<T> {
    value: IrqSafeSpinLock<T>,
}
impl<T> RefCell<T> {
    pub fn new(value: T) -> Self {
        Self {
            value: IrqSafeSpinLock::new(value),
        }
    }
    pub fn borrow(&self) -> IrqSafeSpinLockGuard<'_, T> {
        self.value.lock()
    }
    pub fn borrow_mut(&self) -> IrqSafeSpinLockGuard<'_, T> {
        self.value.lock()
    }
}
const LOCAL: [u8; 6] = [2, 1, 2, 3, 4, 5];
#[derive(Clone, Copy)]
pub(in crate::ath9k) struct Region {
    pub bus: u64,
    pub cpu: usize,
    pub len: usize,
}
pub(in crate::ath9k) struct Model {
    pub(in crate::ath9k) registers: RefCell<BTreeMap<u64, u32>>,
    pub(in crate::ath9k) regions: RefCell<Vec<Region>>,
    pub(in crate::ath9k) master: Cell<bool>,
    pub(in crate::ath9k) allowed: Cell<bool>,
    pub(in crate::ath9k) authority: Cell<bool>,
    pub(in crate::ath9k) now: Cell<u64>,
    pub(in crate::ath9k) count: Cell<usize>,
    pub(in crate::ath9k) fault: Cell<Option<usize>>,
    pub(in crate::ath9k) ignore: Cell<Option<u64>>,
    pub(in crate::ath9k) transmitted: RefCell<Vec<Vec<u8>>>,
    pub(in crate::ath9k) tx: Cell<Option<u32>>,
    pub(in crate::ath9k) pair_tail: Cell<Option<u32>>,
    pair_seq: Cell<u16>,
    pub(in crate::ath9k) last_pair: Cell<Option<(u32, u32)>>,
    pub(in crate::ath9k) pair_received: Cell<u8>,
    pub(in crate::ath9k) ba_bitmap: Cell<Option<u64>>,
    pub(in crate::ath9k) ba_flag: Cell<bool>,
    pub(in crate::ath9k) ba_tid: Cell<u8>,
    pub(in crate::ath9k) ba_ssn: Cell<Option<u16>>,
    pub(in crate::ath9k) hold_pair: Cell<bool>,
    pub(in crate::ath9k) data_ack: Cell<bool>,
    pub(in crate::ath9k) retry_receive: Cell<bool>,
    bar_reply: RefCell<Option<Vec<u8>>>,
    pub(in crate::ath9k) cursor: Cell<u32>,
    pub(in crate::ath9k) last_rx: Cell<Option<u32>>,
    pub(in crate::ath9k) reaction: RefCell<Option<Arc<Reaction>>>,
    pub(in crate::ath9k) ht: RefCell<Option<Arc<crate::ath9k::ht::Grant>>>,
    pub(in crate::ath9k) ba: RefCell<Option<Arc<crate::ath9k::rx_ba::Grant>>>,
    pub(in crate::ath9k) tx_ba: RefCell<Option<Arc<crate::ath9k::tx_ba::Grant>>>,
    pub(in crate::ath9k) ht_rate: Cell<u8>,
    pub(in crate::ath9k) rx_aggr: Cell<u32>,
    pub(in crate::ath9k) dma_transmitted: RefCell<Vec<Vec<u8>>>,
    /// Keep AR_Q_TXE/QSTS pending despite AR_Q_TXD (wedged DCU).
    pub(in crate::ath9k) stuck_tx: Cell<bool>,
    /// Keep AR_CR_RXE set despite AR_CR_RXD (wedged RX DMA).
    pub(in crate::ath9k) stuck_rx: Cell<bool>,
    /// Allocations the owner released after its quiescence proof. The
    /// model keeps them alive; any later device access is an error.
    pub(in crate::ath9k) released: RefCell<Vec<DmaBuffer>>,
    /// Installed MSI wake source and the delivery transitions requested.
    pub(in crate::ath9k) signal: RefCell<Option<Arc<crate::ath9k::irq::Signal>>>,
    pub(in crate::ath9k) delivered: RefCell<Vec<bool>>,
}
pub(in crate::ath9k) type Reaction =
    dyn Fn(&[u8]) -> Result<(Vec<Vec<u8>>, bool), Error> + Send + Sync;
impl Model {
    pub(in crate::ath9k) fn new() -> Arc<Self> {
        Arc::new(Self {
            registers: RefCell::new(BTreeMap::from([
                (CR, 0),
                (QTXE, 0),
                (QSTS, 0),
                (DIAG, RX_PARK),
                (0x24, 0),
                (0x803c, 0x17),
            ])),
            regions: RefCell::new(Vec::new()),
            master: Cell::new(false),
            allowed: Cell::new(true),
            authority: Cell::new(true),
            now: Cell::new(0),
            count: Cell::new(0),
            fault: Cell::new(None),
            ignore: Cell::new(None),
            transmitted: RefCell::new(Vec::new()),
            tx: Cell::new(None),
            pair_tail: Cell::new(None),
            pair_seq: Cell::new(0),
            last_pair: Cell::new(None),
            pair_received: Cell::new(3),
            ba_bitmap: Cell::new(None),
            ba_flag: Cell::new(true),
            ba_tid: Cell::new(0),
            ba_ssn: Cell::new(None),
            hold_pair: Cell::new(false),
            data_ack: Cell::new(true),
            retry_receive: Cell::new(true),
            bar_reply: RefCell::new(None),
            cursor: Cell::new(0),
            last_rx: Cell::new(None),
            reaction: RefCell::new(None),
            ht: RefCell::new(None),
            ba: RefCell::new(None),
            tx_ba: RefCell::new(None),
            ht_rate: Cell::new(0x80),
            rx_aggr: Cell::new(0),
            dma_transmitted: RefCell::new(Vec::new()),
            stuck_tx: Cell::new(false),
            stuck_rx: Cell::new(false),
            released: RefCell::new(Vec::new()),
            signal: RefCell::new(None),
            delivered: RefCell::new(Vec::new()),
        })
    }
    fn access(&self) -> Result<(), Error> {
        let count = self.count.get();
        self.count.set(count + 1);
        if !self.authority.get() || self.fault.get() == Some(count) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn pointer(&self, address: u32, length: usize) -> Result<*mut u8, Error> {
        let address = u64::from(address);
        if self
            .released
            .borrow()
            .iter()
            .any(|b| address >= b.dma_addr().raw() && address < b.dma_addr().raw() + b.len() as u64)
        {
            return Err(Error::Access);
        }
        let regions = self.regions.borrow();
        let region = regions
            .iter()
            .find(|r| {
                address >= r.bus
                    && address
                        .checked_add(length as u64)
                        .is_some_and(|end| end <= r.bus + r.len as u64)
            })
            .ok_or(Error::Address)?;
        // CPU provenance was captured from the actual returned DmaBuffer;
        // the device bus address is only used for a bounded region lookup.
        Ok((region.cpu + (address - region.bus) as usize) as *mut u8)
    }
    pub(in crate::ath9k) fn word(&self, address: u32) -> Result<u32, Error> {
        let pointer = self.pointer(address, 4)?;
        if pointer as usize & 3 != 0 {
            return Err(Error::Address);
        }
        // SAFETY: pointer came from an actual still-retained CPU map with
        // complete checked dword extent/alignment, not a DMA address cast.
        Ok(u32::from_le(unsafe {
            pointer.cast::<u32>().read_volatile()
        }))
    }
    pub(in crate::ath9k) fn put(&self, address: u32, value: u32) -> Result<(), Error> {
        let pointer = self.pointer(address, 4)?;
        if pointer as usize & 3 != 0 {
            return Err(Error::Address);
        }
        // SAFETY: complete checked retained CPU map; model is sole device writer.
        unsafe {
            pointer.cast::<u32>().write_volatile(value.to_le());
        }
        Ok(())
    }
    pub(in crate::ath9k) fn bytes(&self, address: u32, length: usize) -> Result<Vec<u8>, Error> {
        let pointer = self.pointer(address, length)?;
        let mut bytes = Vec::new();
        for index in 0..length {
            // SAFETY: whole byte extent validated against actual allocation above.
            bytes.push(unsafe { pointer.add(index).read_volatile() });
        }
        Ok(bytes)
    }
    pub(in crate::ath9k) fn complete(&self, success: bool) -> Result<(), Error> {
        let descriptor = self.tx.get().ok_or(Error::State)?;
        let tail = self.pair_tail.get().unwrap_or(descriptor);
        let mut done = 1;
        let ba = if self.pair_tail.get().is_some() {
            Some((
                self.pair_seq.get(),
                0,
                self.ba_bitmap
                    .get()
                    .unwrap_or(u64::from(self.pair_received.get())),
            ))
        } else {
            self.bar_reply.borrow().as_ref().map(|b| {
                (
                    u16::from_le_bytes([b[18], b[19]]) >> 4,
                    (u16::from_le_bytes([b[16], b[17]]) >> 12) as u8,
                    u64::from_le_bytes(b[20..32 - 4].try_into().unwrap()),
                )
            })
        };
        if let Some((ssn, tid, bitmap)) = ba {
            self.put(tail + 56, u32::from(self.ba_flag.get()) << 30)?;
            self.put(tail + 68, bitmap as u32)?;
            self.put(tail + 72, (bitmap >> 32) as u32)?;
            let tid = if self.ba_tid.get() != 0 {
                self.ba_tid.get()
            } else {
                tid
            };
            done |= u32::from(self.ba_ssn.get().unwrap_or(ssn)) << 1 | u32::from(tid) << 28;
        }
        self.put(tail + 60, u32::from(success))?;
        self.put(tail + 92, done)?;
        self.registers.borrow_mut().insert(QTXE, 0);
        self.registers.borrow_mut().insert(QSTS, 0);
        self.tx.set(None);
        self.pair_tail.set(None);
        self.bar_reply.borrow_mut().take();
        Ok(())
    }
    fn wire(&self, descriptor: u32) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let length = (self.word(descriptor + 8)? & 0xfff) as usize;
        let dma = self.bytes(
            self.word(descriptor + 4)?,
            (self.word(descriptor + 12)? & 0xfff) as usize,
        )?;
        if length < 4 {
            return Err(Error::Descriptor);
        }
        let original = if dma.first() == Some(&0x88) {
            if dma.len() != length - 2 || dma.len() < 28 || dma[26..28] != [0, 0] {
                return Err(Error::Descriptor);
            }
            let mut f = dma[..26].to_vec();
            f.extend_from_slice(&dma[28..]);
            f
        } else {
            if dma.len() != length - 4 {
                return Err(Error::Descriptor);
            }
            dma.clone()
        };
        Ok((dma, original))
    }
    pub(in crate::ath9k) fn inject(&self, bytes: &[u8], error: u32) -> Result<(), Error> {
        let mut padded = Vec::new();
        if bytes.first() == Some(&0x88) {
            if bytes.len() < 26 {
                return Err(Error::Packet);
            }
            padded.extend_from_slice(&bytes[..26]);
            padded.extend_from_slice(&[0, 0]);
            padded.extend_from_slice(&bytes[26..]);
        }
        let bytes = if padded.is_empty() { bytes } else { &padded };
        let descriptor = self.cursor.get();
        if descriptor == 0 || !self.master.get() {
            return Err(Error::State);
        }
        if self.word(descriptor + 48)? & 1 != 0 {
            return Err(Error::Descriptor);
        }
        let length = bytes.len() + 4;
        let payload = self.word(descriptor + 4)?;
        let pointer = self.pointer(payload, length)?;
        for (index, value) in bytes
            .iter()
            .copied()
            .chain([0xde, 0xad, 0xbe, 0xef])
            .enumerate()
        {
            // SAFETY: full actual payload mapping checked above; device-only write.
            unsafe {
                pointer.add(index).write_volatile(value);
            }
        }
        self.put(
            descriptor + 16,
            u32::from(if bytes.first() == Some(&0x88) {
                self.ht_rate.get()
            } else {
                0x1b
            }) << 24,
        )?;
        self.put(descriptor + 20, length as u32)?;
        self.put(
            descriptor + 48,
            3 | error
                | if bytes.first() == Some(&0x88) {
                    self.rx_aggr.get()
                } else {
                    0
                },
        )?;
        self.last_rx.set(Some(descriptor));
        self.cursor.set(self.word(descriptor)?);
        Ok(())
    }
}
impl Port for Arc<Model> {
    fn tx_ba_grant(&self) -> Option<Arc<crate::ath9k::tx_ba::Grant>> {
        self.tx_ba.borrow().clone()
    }
    fn rx_ba_grant(&self) -> Option<Arc<crate::ath9k::rx_ba::Grant>> {
        self.ba.borrow().clone()
    }
    fn ht_grant(&self) -> Option<Arc<crate::ath9k::ht::Grant>> {
        self.ht.borrow().clone()
    }
    fn transmit_allowed(&self) -> Result<(), Error> {
        if self.allowed.get() {
            if let Some(g) = self.rx_ba_grant() {
                g.check()?;
            }
            if let Some(g) = self.ht_grant() {
                g.readback(self)?;
            }
            Ok(())
        } else {
            Err(Error::Access)
        }
    }
    fn access<T>(
        &self,
        active: bool,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.as_ref().access()?;
        if self.master.get() != active {
            return Err(Error::Access);
        }
        let operation = || {
            if let Some(g) = self.rx_ba_grant() {
                g.invoke(operation)
            } else if let Some(g) = self.ht_grant() {
                g.invoke(operation)
            } else {
                operation()
            }
        };
        if let Some(g) = self.tx_ba_grant() {
            g.invoke(operation)
        } else {
            operation()
        }
    }
    fn read(&self, reg: u64) -> Result<u32, Error> {
        self.as_ref().access()?;
        if let Some(g) = self.tx_ba_grant() {
            g.check()?;
        }
        if let Some(g) = self.rx_ba_grant() {
            g.check()?;
        }
        if let Some(g) = self.ht_grant() {
            g.check()?;
        }
        Ok(*self.registers.borrow().get(&reg).unwrap_or(&0))
    }
    fn write(&self, reg: u64, value: u32) -> Result<(), Error> {
        self.as_ref().access()?;
        if let Some(g) = self.tx_ba_grant() {
            g.check()?;
        }
        if let Some(g) = self.rx_ba_grant() {
            g.check()?;
        }
        if let Some(g) = self.ht_grant() {
            g.check()?;
        }
        if self.ignore.get() == Some(reg) {
            return Ok(());
        }
        self.registers.borrow_mut().insert(reg, value);
        if reg == RXDP {
            self.cursor.set(value);
        }
        if reg == CR && value == 4 && self.cursor.get() == 0 {
            if let Some(last) = self.last_rx.get() {
                self.cursor.set(self.word(last)?);
            }
        }
        if reg == QTXE && value == 1 {
            if !self.master.get() || !self.allowed.get() {
                return Err(Error::Access);
            }
            let descriptor = self.read(QTXDP)?;
            let tail = self.word(descriptor)?;
            if tail != 0
                && (self.word(tail)? != 0
                    || self.word(descriptor + 12)? & 0x6000_0000 != 0x6000_0000
                    || self.word(tail + 12)? & 0x6000_0000 != 0x4000_0000
                    || self.word(tail + 16)? != 0
                    || self.word(tail + 20)? != 0)
            {
                return Err(Error::Descriptor);
            }
            if tail != 0 {
                self.pair_tail.set(Some(tail));
                self.last_pair.set(Some((descriptor, tail)));
            }
            self.tx.set(Some(descriptor));
            self.registers.borrow_mut().insert(QSTS, 1);
            let reaction = { self.reaction.borrow().clone() };
            let mut held = reaction.is_none() || tail != 0 && self.hold_pair.get();
            let mut ack = true;
            for (i, d) in [descriptor, tail].into_iter().enumerate() {
                if d == 0 {
                    continue;
                }
                let (dma, observed) = self.wire(d)?;
                if tail != 0 && i == 0 {
                    self.pair_seq
                        .set(u16::from_le_bytes([observed[22], observed[23]]) >> 4);
                }
                self.dma_transmitted.borrow_mut().push(dma);
                self.transmitted.borrow_mut().push(observed.clone());
                let data = observed.first() == Some(&0x88);
                if data && tail == 0 {
                    ack = self.data_ack.get();
                }
                let received = if tail != 0 {
                    self.pair_received.get() & (1 << i) != 0
                } else {
                    !data || observed[1] & 8 == 0 || self.retry_receive.get()
                };
                if received {
                    if let Some(reaction) = &reaction {
                        let (responses, hold) = reaction(&observed)?;
                        held |= hold;
                        for response in responses {
                            // A solicited compressed BA is consumed by the native
                            // MAC into BAR TX status, never invented as RAW RX.
                            if observed.first() == Some(&0x84)
                                && response.len() == 28
                                && response[..2] == [0x94, 0]
                                && response[4..10] == observed[10..16]
                                && response[10..16] == observed[4..10]
                            {
                                *self.bar_reply.borrow_mut() = Some(response);
                            } else {
                                self.inject(&response, 0)?;
                            }
                        }
                    }
                }
            }
            if !held {
                self.complete(ack)?;
            }
        }
        if reg == CR && value == 0x20 && !self.stuck_rx.get() {
            self.registers.borrow_mut().insert(CR, 0);
        }
        if reg == CR && value == 4 && self.stuck_rx.get() {
            self.registers.borrow_mut().insert(CR, 4);
        }
        if reg == QTXD && value & 1 != 0 && !self.stuck_tx.get() {
            // Disabled DCU: the in-flight descriptor is abandoned unsent.
            self.registers.borrow_mut().insert(QTXE, 0);
            self.registers.borrow_mut().insert(QSTS, 0);
            self.tx.set(None);
            self.pair_tail.set(None);
        }
        Ok(())
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
        self.as_ref().access()?;
        self.delivered.borrow_mut().push(enabled);
        Ok(())
    }
    fn allocate(&self, bytes: usize) -> Result<DmaBuffer, Error> {
        self.as_ref().access()?;
        let memory = narf_io::alloc_coherent_masked(
            bytes,
            narf_lib::id::DomainId::DRIVER_0,
            u64::from(u32::MAX),
        )
        .map_err(|_| Error::Memory)?;
        self.regions.borrow_mut().push(Region {
            bus: memory.dma_addr().raw(),
            cpu: memory.cpu_mut_ptr::<u8>() as usize,
            len: memory.len(),
        });
        Ok(memory)
    }
    fn master(&self, enabled: bool) -> Result<(), Error> {
        self.as_ref().access()?;
        self.master.set(enabled);
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now.get()
    }
}
fn owner(model: Arc<Model>) -> Result<Packet<Arc<Model>>, Error> {
    // SAFETY: isolated model begins parked; no physical controller is touched.
    unsafe { Packet::prepare(model, LOCAL) }
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
fn check_ownership() -> Result<(), &'static str> {
    let model = Model::new();
    let mut packet = owner(model.clone()).map_err(|_| "prepare")?;
    if model.master.get() || !model.transmitted.borrow().is_empty() {
        return Err("preparation activated DMA");
    }
    packet.start().map_err(|_| "start")?;
    let bytes = outbound();
    let mut previous = 0;
    for _ in 0..7 {
        let id = packet.submit(&bytes, 0).map_err(|_| "submit")?;
        if id <= previous || model.transmitted.borrow().last() != Some(&bytes) {
            return Err("native doorbell/payload mismatch");
        }
        if packet.submit(&bytes, 0) != Err(Error::Busy)
            || packet.delivery().map_err(|_| "pending")?.is_some()
        {
            return Err("pending ownership overwritten");
        }
        let native = model.tx.get().ok_or("no native queue")?;
        let payload = model.word(native + 4).map_err(|_| "native payload")?;
        // Status alone cannot hide a queue that still names this descriptor.
        model.put(native + 60, 1).map_err(|_| "ACK")?;
        model.put(native + 92, 1).map_err(|_| "Done")?;
        if packet.delivery().map_err(|_| "busy queue")?.is_some() {
            return Err("queue-active descriptor retired");
        }
        model.complete(true).map_err(|_| "completion")?;
        let receipt = packet
            .delivery()
            .map_err(|_| "delivery")?
            .ok_or("terminal receipt missing")?;
        if receipt.id != id
            || !receipt.delivered
            || receipt.bytes != bytes
            || model
                .bytes(payload, bytes.len())
                .map_err(|_| "retained body")?
                != bytes
        {
            return Err("exact native receipt mismatch");
        }
        previous = id;
    }
    let receive = received();
    for _ in 0..32 {
        model.inject(&receive, 0).map_err(|_| "inject")?;
        let step = packet.receive().map_err(|_| "RX")?;
        if !step.consumed || step.frame.ok_or("native RX lost")?.bytes() != receive {
            return Err("RX payload/fence mismatch");
        }
        if packet.receive().map_err(|_| "idle RX")?.consumed {
            return Err("old RX replayed");
        }
    }
    // Invalid input was consumed, and is not a receive-quiescence fence.
    model.inject(&receive, 4).map_err(|_| "CRC inject")?;
    let step = packet.receive().map_err(|_| "CRC step")?;
    if !step.consumed || step.frame.is_some() {
        return Err("rejected RX became idle or delivery");
    }
    let address = model.regions.borrow()[0].bus as u32;
    packet.stop().map_err(|_| "stop")?;
    if model.master.get()
        || packet.phase() != Phase::Stopped
        || packet.submit(&bytes, 0) != Err(Error::State)
    {
        return Err("terminal park reopened");
    }
    check_reclaimed(&model, &packet)?;
    drop(packet);
    if model.word(address) != Err(Error::Access) {
        return Err("released mapping still reachable by the model device");
    }
    Ok(())
}
pub(in crate::ath9k) fn check_reclaimed(
    model: &Model,
    packet: &Packet<Arc<Model>>,
) -> Result<(), &'static str> {
    let registers = model.registers.borrow();
    let reg = |r| *registers.get(&r).unwrap_or(&0);
    if !packet.reclaimed()
        || model.released.borrow().len() != 2 + TX_DEPTH + RX_DEPTH
        || model.released.borrow().len() != model.regions.borrow().len()
        || reg(QTXD) != 0x3ff
        || reg(RX_FILTER) != 0
        || reg(DIAG) & RX_PARK != RX_PARK
        || reg(DIAG) & DIAG_IDLE_HIGH != 0
        || reg(PCU_MISC) & PCU_QUIET != 0
        || reg(IFS_MISC) & IGNORE_BACKOFF != 0
        || reg(0x24) != 0
    {
        return Err("DMA stop/abort did not reclaim the exact packet storage");
    }
    Ok(())
}
/// Linux `ath_drain_all_txq`/`ath_stoprecv` abort a held descriptor with
/// bus mastering still enabled; only a proved stop releases the storage.
fn check_reclamation() -> Result<(), &'static str> {
    // Held TX in flight is aborted, then the storage is released.
    let model = Model::new();
    let mut packet = owner(model.clone()).map_err(|_| "prepare")?;
    packet.start().map_err(|_| "start")?;
    packet.submit(&outbound(), 0).map_err(|_| "submit")?;
    if model.tx.get().is_none() || model.registers.borrow().get(&QTXE) != Some(&1) {
        return Err("model did not hold the TX descriptor");
    }
    packet.stop().map_err(|_| "abort stop")?;
    check_reclaimed(&model, &packet)?;
    if packet.delivery() != Err(Error::State) || packet.stop() != Err(Error::State) {
        return Err("reclaimed owner reopened delivery or replayed stop");
    }
    // Never-started owner: engines already parked, storage still reclaimed.
    let model = Model::new();
    let mut packet = owner(model.clone()).map_err(|_| "prepare idle")?;
    packet.stop().map_err(|_| "idle stop")?;
    check_reclaimed(&model, &packet)?;
    // A wedged DCU or RX DMA keeps every allocation pinned and readable.
    for wedged_tx in [true, false] {
        let model = Model::new();
        let mut packet = owner(model.clone()).map_err(|_| "prepare wedged")?;
        packet.start().map_err(|_| "start wedged")?;
        packet.submit(&outbound(), 0).map_err(|_| "submit wedged")?;
        if wedged_tx {
            model.stuck_tx.set(true);
        } else {
            model.complete(true).map_err(|_| "complete wedged")?;
            model.stuck_rx.set(true);
            model.registers.borrow_mut().insert(CR, 4);
        }
        let before = model.now.get();
        if packet.stop() != Err(Error::Timeout) {
            return Err("wedged DMA stop claimed success");
        }
        let waited = model.now.get() - before;
        let budget = if wedged_tx {
            u64::from(TX_ABORT_POLLS - 1) * 5
        } else {
            u64::from(RX_STOP_POLLS) * 10
        };
        if waited != budget {
            return Err("DMA stop poll budget differs from Linux");
        }
        if packet.reclaimed() || !model.released.borrow().is_empty() || model.master.get() {
            return Err("unproved DMA stop released storage or kept BME");
        }
        let address = model.regions.borrow()[0].bus as u32;
        drop(packet);
        if model.word(address).is_err() {
            return Err("unproved storage was freed on drop");
        }
    }
    // Pre-AR9300 DMADBG_7 hang signature ends the RX stop after two samples.
    let model = Model::new();
    let mut packet = owner(model.clone()).map_err(|_| "prepare hang")?;
    packet.start().map_err(|_| "start hang")?;
    model.stuck_rx.set(true);
    model.registers.borrow_mut().insert(CR, 4);
    model.registers.borrow_mut().insert(DMADBG_7, 0x1c0);
    let before = model.now.get();
    if packet.stop() != Err(Error::Timeout)
        || model.now.get() - before != 10
        || model.registers.borrow().get(&MACMISC) != Some(&((8 << 5) | (1 << 15)))
        || packet.reclaimed()
    {
        return Err("RX DMA hang signature not honoured");
    }
    // A BAR fault during stop never claims reclamation.
    let model = Model::new();
    let mut packet = owner(model.clone()).map_err(|_| "prepare fault")?;
    packet.start().map_err(|_| "start fault")?;
    model.authority.set(false);
    if packet.stop().is_ok() || packet.reclaimed() || !model.released.borrow().is_empty() {
        return Err("revoked stop reclaimed storage");
    }
    Ok(())
}
fn smoke_ar9285_packet_dma_stop_proof_reclaims_storage() -> TestResult {
    match check_reclamation() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/packet",
    smoke_ar9285_packet_dma_stop_proof_reclaims_storage
);
fn check_deadlines_and_authority() -> Result<(), &'static str> {
    for done in [false, true] {
        let model = Model::new();
        let mut packet = owner(model.clone()).map_err(|_| "prepare")?;
        packet.start().map_err(|_| "start")?;
        packet.submit(&outbound(), 0).map_err(|_| "submit")?;
        if done {
            let address = model.tx.get().ok_or("missing TX")?;
            model.put(address + 60, 1).map_err(|_| "ACK")?;
            model.put(address + 92, 1).map_err(|_| "Done")?;
        }
        model.now.set(1_000_000);
        if packet.delivery() != Err(Error::Timeout)
            || packet.phase() != Phase::Failed
            || packet.submit(&outbound(), 0) != Err(Error::State)
        {
            return Err("pending/queue-active deadline reopened owner");
        }
    }
    let model = Model::new();
    let mut packet = owner(model.clone()).map_err(|_| "prepare")?;
    packet.start().map_err(|_| "start")?;
    model.allowed.set(false);
    let before = model.transmitted.borrow().len();
    if packet.submit(&outbound(), 0) != Err(Error::Access)
        || model.transmitted.borrow().len() != before
    {
        return Err("changed policy published a frame");
    }
    model.authority.set(false);
    if packet.receive().is_ok() || packet.stop().is_ok() || packet.phase() != Phase::Stopped {
        return Err("revoked packet owner reached DMA or claimed park");
    }
    Ok(())
}
fn check_failures() -> Result<(), &'static str> {
    let model = Model::new();
    let mut packet = owner(model.clone()).map_err(|_| "prepare")?;
    let begin = model.count.get();
    packet.start().map_err(|_| "start")?;
    packet.submit(&outbound(), 0).map_err(|_| "submit")?;
    model.complete(true).map_err(|_| "complete")?;
    packet.delivery().map_err(|_| "delivery")?;
    model.inject(&received(), 0).map_err(|_| "inject")?;
    packet.receive().map_err(|_| "RX")?;
    let end = model.count.get();
    for fault in begin..end {
        let model = Model::new();
        let mut packet = owner(model.clone()).map_err(|_| "fault prepare")?;
        model.fault.set(Some(fault));
        let result = (|| {
            packet.start()?;
            packet.submit(&outbound(), 0)?;
            model.complete(true)?;
            packet.delivery()?;
            model.inject(&received(), 0)?;
            packet.receive()?;
            Ok::<(), Error>(())
        })();
        if result.is_ok() {
            return Err("injected native transaction failure hidden");
        }
        // A pre-admission failure has no native side effects; ambiguous
        // publication or DMA read failure makes the existing owner terminal.
        if packet.phase() == Phase::Failed && packet.start() != Err(Error::State) {
            return Err("failed owner replayed");
        }
        model.fault.set(None);
        let _ = packet.stop();
    }
    for ignored in [RXDP, QTXDP] {
        let model = Model::new();
        let mut packet = owner(model.clone()).map_err(|_| "ignore prepare")?;
        if ignored == QTXDP {
            packet.start().map_err(|_| "ignore start")?;
        }
        model.ignore.set(Some(ignored));
        let result = if ignored == RXDP {
            packet.start()
        } else {
            packet.submit(&outbound(), 0).map(|_| ())
        };
        if result != Err(Error::Descriptor) || !model.transmitted.borrow().is_empty() {
            return Err("ignored address write activated native packet");
        }
    }
    Ok(())
}
fn smoke_ar9285_native_packet_ownership_rx_recycle_and_terminal_park() -> TestResult {
    match check_ownership() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
fn smoke_ar9285_packet_deadlines_and_current_admission() -> TestResult {
    match check_deadlines_and_authority() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
fn smoke_ar9285_packet_every_native_access_and_address_readback_failure() -> TestResult {
    match check_failures() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/packet",
    smoke_ar9285_native_packet_ownership_rx_recycle_and_terminal_park
);
kernel_test_in!(
    "drivers/wireless/ath9k/packet",
    smoke_ar9285_packet_deadlines_and_current_admission
);
kernel_test_in!(
    "drivers/wireless/ath9k/packet",
    smoke_ar9285_packet_every_native_access_and_address_readback_failure
);

fn check_interrupt_service() -> Result<(), &'static str> {
    use core::future::Future as _;
    use crate::ath9k::irq;
    // No vector: the owner stays polled and service is a no-op.
    let model = Model::new();
    let mut packet = owner(model.clone()).map_err(|_| "prepare polled")?;
    if packet.enable_interrupts() != Err(Error::State) {
        return Err("interrupts enabled before rings ran");
    }
    packet.start().map_err(|_| "start polled")?;
    if packet.enable_interrupts() != Ok(false)
        || packet.interrupt().is_some()
        || packet.service_begin() != Ok(None)
        || model
            .registers
            .borrow()
            .get(&irq::IER)
            .copied()
            .unwrap_or(0)
            != 0
    {
        return Err("polled owner programmed interrupts");
    }
    let model = Model::new();
    let signal = irq::Signal::new();
    *model.signal.borrow_mut() = Some(signal.clone());
    let mut packet = owner(model.clone()).map_err(|_| "prepare irq")?;
    packet.start().map_err(|_| "start irq")?;
    if packet.enable_interrupts() != Ok(true) || packet.interrupt().is_none() {
        return Err("MSI owner did not enable interrupts");
    }
    let reg = |r: u64| model.registers.borrow().get(&r).copied().unwrap_or(0);
    if reg(irq::IER) != 1
        || reg(irq::IMR) != irq::imr(false)
        || irq::imr(false) != 0x9100_04b0
        || reg(0xa4) != 1 << 16
        || reg(0xa8) != 1 << 16
        || reg(0x2c) != (700 << 16) | 250
        || reg(0x5c) != 6
        || reg(0x403c) != 2
        || reg(0x4034) != irq::SYNC_DEFAULT
        || reg(0x40d4) != 7
        || reg(0x4094) & 1 == 0
        || *model.delivered.borrow() != [true]
    {
        return Err("interrupt programming differs from Linux station mask");
    }
    // Spurious vector: nothing pending, IER is still killed then resumed.
    if packet.service_begin() != Ok(None) || reg(irq::IER) != 0 {
        return Err("spurious vector");
    }
    packet.service_end().map_err(|_| "resume")?;
    if reg(irq::IER) != 1 {
        return Err("IER not resumed");
    }
    // RX mitigation + TX descriptor completion on QCU0, plus RXEOL.
    {
        let mut r = model.registers.borrow_mut();
        r.insert(0x4038, 2);
        r.insert(0x7044, 2);
        r.insert(0x80, 0x8000_0000);
        r.insert(0xc0, 0x8000_0000 | 0x80 | 0x10);
        r.insert(0xc4, 1 << 16);
    }
    let events = packet
        .service_begin()
        .map_err(|_| "service")?
        .ok_or("pending causes lost")?;
    if !events.rx || !events.tx || events.txqs != 1 || !events.rx_eol || events.fatal {
        return Err("cause decode differs from ar9002_hw_get_isr");
    }
    if reg(irq::IER) != 0 || reg(irq::IMR) & irq::RX_EOL_ORN != 0 {
        return Err("RXEOL did not drop RXEOL|RXORN with IER killed");
    }
    packet.service_end().map_err(|_| "resume eol")?;
    if reg(irq::IER) != 1 || reg(irq::IMR) != irq::imr(false) {
        return Err("RXEOL|RXORN not restored after service");
    }
    // Completion timeout pulses AR_RC_HOSTIF and is fatal for the owner.
    {
        let mut r = model.registers.borrow_mut();
        r.insert(0x4038, 0);
        r.insert(0x4028, 0x1000);
    }
    if packet.service_begin() != Err(Error::Access)
        || packet.phase() != Phase::Failed
        || reg(0x4000) != 0
        || reg(0x4028) != 0x1000
    {
        return Err("fatal sync cause did not close the owner");
    }
    packet.stop().map_err(|_| "stop irq")?;
    if *model.delivered.borrow() != [true, false]
        || packet.interrupt().is_some()
        || reg(0x403c) != 0
        || reg(0x402c) != 0
        || reg(0x40d4) != 0
    {
        return Err("stop left interrupt delivery open");
    }
    check_reclaimed(&model, &packet)?;
    // Wake future: a raise between snapshot and wait completes it at once;
    // otherwise the housekeeping fallback ends it without an interrupt.
    let waker = core::task::Waker::noop();
    let mut cx = core::task::Context::from_waker(waker);
    let seen = signal.count();
    signal.raise();
    let mut wait = signal.wait(seen, core::future::pending::<()>());
    if core::pin::Pin::new(&mut wait).poll(&mut cx) != core::task::Poll::Ready(true) {
        return Err("raised signal not observed");
    }
    let seen = signal.count();
    let mut wait = signal.wait(seen, core::future::pending::<()>());
    if core::pin::Pin::new(&mut wait).poll(&mut cx).is_ready() {
        return Err("idle signal completed");
    }
    let mut wait = signal.wait(seen, core::future::ready(()));
    if core::pin::Pin::new(&mut wait).poll(&mut cx) != core::task::Poll::Ready(false) {
        return Err("fallback did not end wait");
    }
    Ok(())
}
fn smoke_ar9285_packet_msi_cause_kill_resume_and_fatal() -> TestResult {
    match check_interrupt_service() {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/ath9k/packet",
    smoke_ar9285_packet_msi_cause_kill_resume_and_fatal
);
