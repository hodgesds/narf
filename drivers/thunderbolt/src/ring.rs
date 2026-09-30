//! USB4 NHI ring zero. Register/descriptor layout: Linux nhi_regs.h and
//! nhi.c. Control packets are raw 256-byte frames, including CRC32C.
use alloc::sync::Arc;
use core::{
    mem::ManuallyDrop,
    sync::atomic::{fence, AtomicBool, Ordering},
};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion, MsixTable};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_interrupts::{dispatch, vector};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

const COUNT: usize = 16;
const FRAME: usize = 256;
const TX: u64 = 0;
const RX: u64 = 0x8000;
const TX_OPT: u64 = 0x19800;
const RX_OPT: u64 = 0x29800;
const POSTED: u32 = 4 << 20;
const COMPLETED: u32 = 2 << 20;
const INTERRUPT: u32 = 8 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Allocation,
    Invalid,
    Full,
    Failed,
    Timeout,
    Remote(u8),
}

#[derive(Debug)]
pub(crate) struct IoOp<F>(pub F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for IoOp<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

#[derive(Debug)]
struct Irq {
    bar: MmioRegion,
    hops: u16,
    intel: bool,
    pending: AtomicBool,
}
fn interrupt(cookie: u64) -> dispatch::IrqStatus {
    // SAFETY: Arc is retained by Ring until the handler has been removed and
    // synchronize_irq completed. All register bounds were checked at probe.
    let irq = unsafe { &*(cookie as *const Irq) };
    if !irq.intel {
        // MSI-X identifies our private vector. Match Linux ring_clear_msix:
        // clear TX ring zero and RX ring zero in their respective banks.
        for bit in [0, irq.hops as u64] {
            // SAFETY: bounded register bank, explicit W1C on AMD USB4.
            unsafe { irq.bar.write32(0x37808 + (bit / 32) * 4, 1 << (bit % 32)) };
        }
    }
    irq.pending.store(true, Ordering::Release);
    dispatch::IrqStatus::Handled
}

#[derive(Debug)]
struct IrqRoute {
    vector: u8,
    table: MsixTable,
    state: Arc<Irq>,
}
impl Drop for IrqRoute {
    fn drop(&mut self) {
        // SAFETY: Ring masks device sources before releasing the IRQ route.
        unsafe { self.table.disable() };
        dispatch::remove_handler(self.vector, "usb4-ring0", Arc::as_ptr(&self.state) as u64);
        dispatch::synchronize_irq(self.vector);
        let _ = vector::free(self.vector);
    }
}

#[derive(Debug)]
pub(crate) struct Ring {
    bar: MmioRegion,
    hops: u16,
    intel: bool,
    descriptors: ManuallyDrop<DmaBuffer>,
    buffers: ManuallyDrop<DmaBuffer>,
    tx_head: usize,
    tx_tail: usize,
    rx_head: usize,
    rx_tail: usize,
    running: bool,
    irq: Option<IrqRoute>,
    authority: Option<Cap<BusDeviceCap, Write>>,
}
impl Ring {
    /// # Safety
    /// Caller exclusively owns the NHI and has negotiated native USB4 control.
    pub unsafe fn new(bar: MmioRegion, hops: u16, intel: bool) -> Result<Self, Error> {
        // USB4 implementations use a small hop count; bound all bitmap and
        // vector banks by the documented MMIO aperture, including bad devices.
        if hops == 0 || hops > 256 || bar.len < 0x39948 {
            return Err(Error::Invalid);
        }
        let descriptors =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| Error::Allocation)?;
        let buffers =
            alloc_coherent(2 * COUNT * FRAME, DomainId::DRIVER_0).map_err(|_| Error::Allocation)?;
        Ok(Self {
            bar,
            hops,
            intel,
            descriptors: ManuallyDrop::new(descriptors),
            buffers: ManuallyDrop::new(buffers),
            tx_head: 0,
            tx_tail: 0,
            rx_head: COUNT - 1,
            rx_tail: 0,
            running: false,
            irq: None,
            authority: None,
        })
    }
    pub fn bind_authority(&mut self, cap: Cap<BusDeviceCap, Write>) {
        self.authority = Some(cap);
    }
    fn write(&self, offset: u64, value: u32) {
        // SAFETY: fixed ring-zero/register offsets inside the validated BAR.
        unsafe { self.bar.write32(offset, value) };
    }
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: fixed ring-zero/register offsets inside the validated BAR.
        unsafe { self.bar.read32(offset) }
    }
    fn desc(&self, rx: bool, index: usize) -> *mut u32 {
        self.descriptors
            .cpu_mut_ptr_at::<u32>(((if rx { COUNT } else { 0 }) + index) as u64 * 16)
    }
    fn flags(&self, rx: bool, index: usize) -> u32 {
        // SAFETY: indices are modulo COUNT; dword 2 is device-updated status.
        let flags = unsafe { self.desc(rx, index).add(2).read_volatile() };
        if flags & COMPLETED != 0 {
            fence(Ordering::Acquire);
        }
        flags
    }
    fn post(&self, rx: bool, index: usize, length: usize, kind: u8) {
        let buffer = ((if rx { COUNT } else { 0 }) + index) * FRAME;
        let address = self.buffers.dma_addr_at(buffer as u64).raw();
        let flags = POSTED
            | if self.irq.is_some() { INTERRUPT } else { 0 }
            | if rx {
                0
            } else {
                length as u32 | ((kind as u32) << 12) | ((kind as u32) << 16)
            };
        // SAFETY: software owns this slot until the head doorbell is advanced.
        unsafe {
            let p = self.desc(rx, index);
            p.write_volatile(address as u32);
            p.add(1).write_volatile((address >> 32) as u32);
            p.add(3).write_volatile(0);
            p.add(2).write_volatile(flags);
        }
        fence(Ordering::Release);
    }
    pub fn install_irq(
        &mut self,
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<(), Error> {
        let mut table = narf_bus::enable_msix(cap, device).map_err(|_| Error::Failed)?;
        // SAFETY: caller owns PCI function and no ring has been started yet.
        unsafe { table.disable() };
        let vector = vector::alloc().map_err(|_| Error::Allocation)?;
        let state = Arc::new(Irq {
            bar: self.bar,
            hops: self.hops,
            intel: self.intel,
            pending: AtomicBool::new(false),
        });
        dispatch::install_handler_named(
            vector,
            "usb4-ring0",
            Arc::as_ptr(&state) as u64,
            interrupt,
        );
        let mut route = IrqRoute {
            vector,
            table,
            state,
        };
        #[cfg(target_arch = "x86_64")]
        // SAFETY: APIC initialization precedes device initcalls.
        let target = unsafe { narf_interrupts::current_cpu_target_id() };
        #[cfg(not(target_arch = "x86_64"))]
        let target = 0;
        if target > 255 || route.table.alloc_vector().is_none() {
            return Err(Error::Failed);
        }
        // SAFETY: one owned vector, installed handler, validated CPU target.
        unsafe {
            route
                .table
                .program_vector(0, target, vector)
                .map_err(|_| Error::Failed)?;
            route.table.enable().map_err(|_| Error::Failed)?;
        }
        self.write(
            0x39864,
            self.read(0x39864) | if self.intel { 1 << 2 } else { 1 << 17 },
        );
        for index in [0, self.hops as u64] {
            let reg = 0x38c40 + (index / 8) * 4;
            self.write(reg, self.read(reg) & !(15 << ((index % 8) * 4)));
        }
        self.write(0x38c00, 500); // 128 us moderation, both rings use MSI-X entry 0.
        self.irq = Some(route);
        Ok(())
    }
    fn mask(&self) {
        for word in 0..(2 * self.hops as u64).div_ceil(32) {
            self.write(
                if self.intel { 0x38200 } else { 0x38208 } + word * 4,
                if self.intel { 0 } else { u32::MAX },
            );
        }
    }
    pub fn start(&mut self) {
        self.mask();
        self.tx_head = 0;
        self.tx_tail = 0;
        self.rx_head = COUNT - 1;
        self.rx_tail = 0;
        self.write(TX_OPT, 0);
        self.write(RX_OPT, 0);
        for (base, offset) in [(TX, 0), (RX, COUNT * 16)] {
            let address = self.descriptors.dma_addr_at(offset as u64).raw();
            self.write(base, address as u32);
            self.write(base + 4, (address >> 32) as u32);
            self.write(base + 8, 0);
            self.write(
                base + 12,
                COUNT as u32 | if base == RX { (FRAME as u32) << 16 } else { 0 },
            );
        }
        self.write(TX_OPT + 4, 0);
        self.write(RX_OPT + 4, 0xffff);
        // Leave one empty entry to distinguish full and empty rings.
        for index in 0..COUNT - 1 {
            self.post(true, index, 0, 0);
        }
        self.write(TX_OPT, 3 << 30);
        self.write(RX_OPT, 3 << 30);
        self.write(RX + 8, self.rx_head as u32);
        if self.irq.is_some() {
            for bit in [0, self.hops as u64] {
                let reg = 0x38200 + (bit / 32) * 4;
                self.write(reg, self.read(reg) | (1 << (bit % 32)));
            }
        }
        self.running = true;
    }
    pub fn send(&mut self, kind: u8, words: &[u32]) -> Result<(), Error> {
        if let Some(cap) = self.authority {
            return cap
                .invoke(IoOp(|| self.send_owned(kind, words)))
                .map_err(|_| Error::Failed)?;
        }
        self.send_owned(kind, words)
    }
    fn send_owned(&mut self, kind: u8, words: &[u32]) -> Result<(), Error> {
        if kind > 15 {
            return Err(Error::Invalid);
        }
        if !self.running {
            return Err(Error::Failed);
        }
        while self.tx_tail != self.tx_head && self.flags(false, self.tx_tail) & COMPLETED != 0 {
            self.tx_tail = (self.tx_tail + 1) % COUNT;
        }
        let next = (self.tx_head + 1) % COUNT;
        if next == self.tx_tail {
            return Err(Error::Full);
        }
        let mut bytes = [0u8; FRAME];
        let len = encode(words, &mut bytes)?;
        let out = self
            .buffers
            .cpu_mut_ptr_at::<u8>((self.tx_head * FRAME) as u64);
        // SAFETY: slot is not posted yet, and encode bounded its length.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, len) };
        self.post(false, self.tx_head, len, kind);
        self.tx_head = next;
        self.write(TX + 8, (next as u32) << 16);
        Ok(())
    }
    pub fn receive(&mut self) -> Result<Option<Packet>, Error> {
        if let Some(cap) = self.authority {
            return cap
                .invoke(IoOp(|| self.receive_owned()))
                .map_err(|_| Error::Failed)?;
        }
        self.receive_owned()
    }
    fn receive_owned(&mut self) -> Result<Option<Packet>, Error> {
        if !self.running {
            return Err(Error::Failed);
        }
        let flags = self.flags(true, self.rx_tail);
        if flags & COMPLETED == 0 {
            return Ok(None);
        }
        let len = (flags & 0xfff) as usize;
        let mut bytes = [0u8; FRAME];
        let valid =
            (4..=FRAME).contains(&len) && flags & ((1 | 4) << 20) == 0 && flags & (15 << 16) == 0;
        if valid {
            // SAFETY: completed descriptor transfers this bounded buffer to CPU.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.buffers
                        .cpu_ptr_at::<u8>(((COUNT + self.rx_tail) * FRAME) as u64),
                    bytes.as_mut_ptr(),
                    len,
                )
            };
        }
        // Replenish the previously empty slot, then release the consumed one.
        self.post(true, self.rx_head, 0, 0);
        self.rx_head = (self.rx_head + 1) % COUNT;
        self.rx_tail = (self.rx_tail + 1) % COUNT;
        self.write(RX + 8, self.rx_head as u32);
        if !valid {
            return Err(Error::Invalid);
        }
        decode(((flags >> 12) & 15) as u8, &bytes[..len]).map(Some)
    }
    pub async fn wait(&self, millis: u64) {
        let deadline = narf_time::Deadline::after_ms(millis);
        if let Some(irq) = &self.irq {
            // Snapshot the IRQ watermark before consuming the pending flag.
            let wait = narf_interrupts::wait_for_irq_until(irq.vector, deadline);
            if !irq.state.pending.swap(false, Ordering::AcqRel) {
                let _ = wait.await;
            }
        } else {
            narf_time::SleepUntil::new(deadline.as_instant()).await;
        }
    }
    pub fn stop(&mut self) -> bool {
        self.mask();
        self.write(TX_OPT, 0);
        self.write(RX_OPT, 0);
        let stopped = self.read(TX_OPT) & (1 << 31) == 0 && self.read(RX_OPT) & (1 << 31) == 0;
        if stopped {
            for base in [TX, RX] {
                for offset in [0, 4, 8, 12] {
                    self.write(base + offset, 0);
                }
            }
            let _ = self.read(RX + 12);
        }
        self.running = false;
        self.irq.take();
        stopped
    }
}
impl Drop for Ring {
    fn drop(&mut self) {
        // Failed MMIO reads leave ENABLE set: quarantine DMA rather than let
        // a disappeared or wedged device write into reallocated memory.
        if self.stop() {
            // SAFETY: hardware has acknowledged both ring enables cleared.
            unsafe {
                ManuallyDrop::drop(&mut self.buffers);
                ManuallyDrop::drop(&mut self.descriptors);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Packet {
    pub kind: u8,
    pub words: alloc::vec::Vec<u32>,
}
fn crc(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in bytes {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn encode(words: &[u32], bytes: &mut [u8; FRAME]) -> Result<usize, Error> {
    if words.is_empty() || words.len() > 63 {
        return Err(Error::Invalid);
    }
    let len = words.len() * 4;
    for (out, word) in bytes[..len].chunks_exact_mut(4).zip(words) {
        out.copy_from_slice(&word.to_be_bytes());
    }
    let crc = crc(&bytes[..len]);
    bytes[len..len + 4].copy_from_slice(&crc.to_be_bytes());
    Ok(len + 4)
}
fn decode(kind: u8, bytes: &[u8]) -> Result<Packet, Error> {
    if bytes.len() < 8 || bytes.len() > FRAME || bytes.len() % 4 != 0 {
        return Err(Error::Invalid);
    }
    let body = &bytes[..bytes.len() - 4];
    if crc(body) != u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap()) {
        return Err(Error::Invalid);
    }
    Ok(Packet {
        kind,
        words: body
            .chunks_exact(4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
            .collect(),
    })
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn usb4_ring_ownership_wrap_and_bad_completion() -> TestResult {
        let mut mmio = alloc::vec![0u32; 0x3a000 / 4];
        let bar = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: mmio.as_mut_ptr() as u64,
            len: 0x3a000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: the model owns the backing array; all DMA descriptors are
        // real coherent allocations but are only accessed by this test.
        let mut ring = match unsafe { Ring::new(bar, 16, true) } {
            Ok(ring) => ring,
            Err(_) => return TestResult::Fail("model DMA allocation"),
        };
        let authority = Cap::<BusDeviceCap, Write>::bootstrap();
        ring.bind_authority(authority);
        ring.start();
        for _ in 0..COUNT - 1 {
            if ring.send(1, &[0x1234]).is_err() {
                return TestResult::Fail("TX capacity");
            }
        }
        if ring.send(1, &[0x1234]) != Err(Error::Full) {
            return TestResult::Fail("TX overwrote device-owned descriptor");
        }
        for _ in 0..COUNT * 3 {
            // Complete one TX, then post one: exercise producer wrap/full.
            // SAFETY: model owns these coherent descriptors and no device runs.
            unsafe {
                ring.desc(false, ring.tx_tail)
                    .add(2)
                    .write_volatile(COMPLETED);
            }
            if ring.send(1, &[0x1234]).is_err() {
                return TestResult::Fail("TX completion did not free slot");
            }
            let mut bytes = [0; FRAME];
            let len = encode(&[0x8000_0000, 7, 42], &mut bytes).unwrap();
            // SAFETY: bounded model RX slot; encode produced at most FRAME bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    ring.buffers
                        .cpu_mut_ptr_at::<u8>(((COUNT + ring.rx_tail) * FRAME) as u64),
                    len,
                );
                ring.desc(true, ring.rx_tail)
                    .add(2)
                    .write_volatile(COMPLETED | (1 << 12) | len as u32);
            }
            if !matches!(ring.receive(), Ok(Some(Packet { kind: 1, words })) if words == [0x8000_0000, 7, 42])
            {
                return TestResult::Fail("RX completion/repost/wrap");
            }
        }
        // SAFETY: model owns the current RX descriptor; only its length is bad.
        unsafe {
            ring.desc(true, ring.rx_tail)
                .add(2)
                .write_volatile(COMPLETED | 4095);
        }
        if !matches!(ring.receive(), Err(Error::Invalid)) || !matches!(ring.receive(), Ok(None)) {
            return TestResult::Fail(
                "bad RX length must consume and replenish exactly one descriptor",
            );
        }
        authority.revoke();
        let producer = ring.tx_head;
        if ring.send(1, &[0x1234]) != Err(Error::Failed)
            || !matches!(ring.receive(), Err(Error::Failed))
            || ring.tx_head != producer
        {
            return TestResult::Fail("revoked bus capability accessed/reposted DMA");
        }
        if !ring.stop() || ring.read(TX) != 0 || ring.read(RX) != 0 {
            return TestResult::Fail("stopped ring retained DMA base");
        }
        drop(ring);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/ring",
        usb4_ring_ownership_wrap_and_bad_completion
    );
    fn usb4_wire_crc_and_order() -> TestResult {
        if crc(b"123456789") != 0xe306_9283 {
            return TestResult::Fail("CRC32C known vector");
        }
        let words = [0x8000_0000, 0x0102_0304, 0x0400_2000];
        let mut bytes = [0; FRAME];
        let len = encode(&words, &mut bytes).unwrap();
        if bytes[4..8] != [1, 2, 3, 4] || decode(1, &bytes[..len]).unwrap().words != words {
            return TestResult::Fail("control packet endian conversion");
        }
        bytes[9] ^= 1;
        if decode(1, &bytes[..len]).is_ok() || encode(&[0; 64], &mut bytes).is_ok() {
            return TestResult::Fail("corrupt/oversize packet accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/thunderbolt/ring", usb4_wire_crc_and_order);
}
