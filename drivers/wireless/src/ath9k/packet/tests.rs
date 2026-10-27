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
    pub(in crate::ath9k) cursor: Cell<u32>,
    pub(in crate::ath9k) last_rx: Cell<Option<u32>>,
    pub(in crate::ath9k) reaction: RefCell<Option<Arc<Reaction>>>,
    pub(in crate::ath9k) ht: RefCell<Option<Arc<crate::ath9k::ht::Grant>>>,
    pub(in crate::ath9k) ba: RefCell<Option<Arc<crate::ath9k::rx_ba::Grant>>>,
    pub(in crate::ath9k) ht_rate: Cell<u8>,
    pub(in crate::ath9k) rx_aggr: Cell<u32>,
    pub(in crate::ath9k) dma_transmitted: RefCell<Vec<Vec<u8>>>,
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
            cursor: Cell::new(0),
            last_rx: Cell::new(None),
            reaction: RefCell::new(None),
            ht: RefCell::new(None),
            ba: RefCell::new(None),
            ht_rate: Cell::new(0x80),
            rx_aggr: Cell::new(0),
            dma_transmitted: RefCell::new(Vec::new()),
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
        self.put(descriptor + 60, u32::from(success))?;
        self.put(descriptor + 92, 1)?;
        self.registers.borrow_mut().insert(QTXE, 0);
        self.registers.borrow_mut().insert(QSTS, 0);
        self.tx.set(None);
        Ok(())
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
        if let Some(g) = self.rx_ba_grant() {
            g.invoke(operation)
        } else if let Some(g) = self.ht_grant() {
            g.invoke(operation)
        } else {
            operation()
        }
    }
    fn read(&self, reg: u64) -> Result<u32, Error> {
        self.as_ref().access()?;
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
            let length = (self.word(descriptor + 8)? & 0xfff) as usize;
            let body = self.word(descriptor + 4)?;
            if self.word(descriptor)? != 0 || length < 4 {
                return Err(Error::Descriptor);
            }
            let dma_length = (self.word(descriptor + 12)? & 0xfff) as usize;
            let dma = self.bytes(body, dma_length)?;
            self.dma_transmitted.borrow_mut().push(dma.clone());
            let observed = if dma.first() == Some(&0x88) {
                if dma.len() != length - 2 || dma.len() < 28 || dma[26..28] != [0, 0] {
                    return Err(Error::Descriptor);
                }
                let mut original = dma[..26].to_vec();
                original.extend_from_slice(&dma[28..]);
                original
            } else {
                if dma_length != length - 4 {
                    return Err(Error::Descriptor);
                }
                dma
            };
            self.transmitted.borrow_mut().push(observed.clone());
            self.tx.set(Some(descriptor));
            self.registers.borrow_mut().insert(QSTS, 1);
            let reaction = { self.reaction.borrow().clone() };
            if let Some(reaction) = reaction {
                let (responses, hold) = reaction(&observed)?;
                if !hold {
                    self.complete(true)?;
                }
                for response in responses {
                    self.inject(&response, 0)?;
                }
            }
        }
        if reg == CR && value == 0x20 {
            self.registers.borrow_mut().insert(CR, 0);
        }
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
    let before = model.word(address).map_err(|_| "published mapping")?;
    packet.stop().map_err(|_| "stop")?;
    if model.master.get()
        || packet.phase() != Phase::Stopped
        || packet.submit(&bytes, 0) != Err(Error::State)
    {
        return Err("terminal park reopened");
    }
    drop(packet);
    if model.word(address).map_err(|_| "retained mapping")? != before {
        return Err("published mapping freed/changed after stop");
    }
    Ok(())
}
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
