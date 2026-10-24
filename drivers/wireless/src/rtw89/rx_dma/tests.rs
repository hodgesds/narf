use super::super::phy_access::Generation;
use super::*;
use alloc::vec;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("../rx_packet/golden.rs");
include!("ltr_golden.rs");
struct Model {
    bytes: Vec<u8>,
    operations: usize,
    fail: Option<usize>,
    pending: Option<usize>,
    ignore: Option<u32>,
    writes: Vec<(u32, u32)>,
}
impl Model {
    fn new() -> Self {
        let mut bytes = vec![0; 0x10100];
        bytes[0x1010..0x1014].copy_from_slice(&0xb0f03u32.to_le_bytes());
        bytes[0x9a00] = 2;
        bytes[0x10034] = 0x40;
        bytes[0x10040] = 0x10;
        bytes[0x10042] = 2;
        bytes[0x10069] = 4; // actual PCIe DEVCTL2 LTR enable bit10
        Self {
            bytes,
            operations: 0,
            fail: None,
            pending: None,
            ignore: None,
            writes: Vec::new(),
        }
    }
    fn read(&mut self, a: u32, width: usize) -> Result<u32, power::Error> {
        self.access()?;
        let mut value = [0; 4];
        value[..width].copy_from_slice(&self.bytes[a as usize..a as usize + width]);
        Ok(u32::from_le_bytes(value))
    }
    fn write(&mut self, a: u32, width: usize, value: u32) -> Result<(), power::Error> {
        self.access()?;
        self.writes.push((a, value));
        if self.ignore != Some(a) {
            self.bytes[a as usize..a as usize + width]
                .copy_from_slice(&value.to_le_bytes()[..width]);
        }
        Ok(())
    }
    fn access(&mut self) -> Result<(), power::Error> {
        let op = self.operations;
        self.operations += 1;
        if self.fail == Some(op) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn raw(&self, a: u64) -> u32 {
        u32::from_le_bytes(self.bytes[a as usize..a as usize + 4].try_into().unwrap())
    }
    // Device model follows actual programmed bases and retained descriptor
    // bytes. A source packet is written only after proving the descriptor's
    // complete address/length belongs to that held allocation; never cast DMA.
    fn inject(&mut self, owner: &Rx, channel: usize, slot: usize, packet: &[u8]) -> bool {
        if owner.state() != State::Polling
            || self.raw(0x1000) & (1 << 13) == 0
            || self.raw(0x8380) & 2 == 0
            || self.raw(0x1010) & (1 << channel) != 0
        {
            return false;
        }
        let ring = &owner.rings.as_ref().unwrap()[channel];
        let descriptors = ring.descriptors.as_ref().unwrap();
        let base = self.raw(ring.regs.desa_l) as u64 | ((self.raw(ring.regs.desa_h) as u64) << 32);
        let count = u16::from_le_bytes(
            self.bytes[ring.regs.num as usize..ring.regs.num as usize + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        if base != descriptors.dma_addr().raw()
            || base > DEVICE_DMA_MASK
            || count != ring.buffers.len()
            || slot >= count
        {
            return false;
        }
        descriptors.sync(slot * 8, 8);
        let bd = &descriptors.as_slice()[slot * 8..slot * 8 + 8];
        let length = u16::from_le_bytes(bd[..2].try_into().unwrap()) as usize;
        let opt = u16::from_le_bytes(bd[2..4].try_into().unwrap());
        let address =
            u32::from_le_bytes(bd[4..8].try_into().unwrap()) as u64 | (((opt >> 6) as u64) << 32);
        let buffer = &ring.buffers[slot];
        if length != BUFFER_SIZE
            || address.saturating_add(length as u64 - 1) > DEVICE_DMA_MASK
            || opt & !0x3fc0 != 0
            || address != buffer.dma_addr().raw()
            || packet.len() > length
        {
            return false;
        }
        // SAFETY: exact model descriptor was validated against this retained
        // buffer's address/extent above; inert RAM has no concurrent producer.
        unsafe {
            core::ptr::copy_nonoverlapping(packet.as_ptr(), buffer.as_mut_ptr(), packet.len());
        }
        buffer.sync(0, length);
        let next = ((slot + 1) % count) as u32;
        let idx = ring.regs.idx as usize;
        self.bytes[idx + 2..idx + 4].copy_from_slice(&(next as u16).to_le_bytes());
        true
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        Ok(self.read(a, 1)? as u8)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        Ok(self.read(a, 2)? as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.read(a, 4)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.write(a, 1, v as u32)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.write(a, 2, v as u32)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.write(a, 4, v)
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Ok(None)
    }
}
impl Interface for Model {
    async fn config_read8(&mut self, a: u16) -> Result<u8, power::Error> {
        if self.pending == Some(self.operations) {
            core::future::pending::<()>().await;
        }
        Ok(self.read(0x10000 + a as u32, 1)? as u8)
    }
    async fn config_write8(&mut self, a: u16, v: u8) -> Result<(), power::Error> {
        self.write(0x10000 + a as u32, 1, v as u32)
    }
    async fn phy_read(&mut self, _: Generation, _: u8) -> Result<u16, power::Error> {
        Err(power::Error::Unsupported)
    }
    async fn phy_write(&mut self, _: Generation, _: u8, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
}
struct Fixture {
    rx: Rx,
    model: Model,
}
impl Fixture {
    fn new() -> Self {
        Self {
            rx: Rx::default(),
            model: Model::new(),
        }
    }
    fn prepare(&mut self) -> Option<Result<(), Error>> {
        // SAFETY: private RAM model with no DMA/reset/IRQ producer; the outer
        // fixture retains every allocation and fences it before destruction.
        ready(unsafe { self.rx.prepare(&mut self.model, 4) })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: this fixture is inert owned RAM, with no device, prefetch,
        // IRQ or other writer; all model accesses finish before destruction.
        unsafe {
            self.rx.reclaim_fenced();
        }
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
fn packet(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 20 + payload.len()];
    let size = bytes.len() as u32 | 0xc000;
    bytes[..4].copy_from_slice(&size.to_le_bytes());
    bytes[4..8].copy_from_slice(&((kind as u32) << 24 | payload.len() as u32).to_le_bytes());
    bytes[20..].copy_from_slice(payload);
    bytes
}
fn smoke_rtw89_rx_rings_original_linux_geometry_and_real_dma() -> TestResult {
    for &(address, expected) in BD {
        if descriptor(address, BUFFER_SIZE) != Ok(expected) {
            return TestResult::Fail("RXBD address geometry differs from Linux original C");
        }
    }
    for &(depth, wp, index, expected) in INDEX {
        if available(depth, wp, index) != Ok(expected) {
            return TestResult::Fail("RX ring count differs from Linux original C");
        }
    }
    let mut f = Fixture::new();
    if f.prepare() != Some(Ok(()))
        || f.rx.state() != State::Polling
        || f.model.raw(0x1010) & 0xb0f03 != 0xb0f00
    {
        return TestResult::Fail("RXQ/RPQ publication enabled unowned packet DMA");
    }
    let payload: Vec<u8> = (0..40).collect();
    if !f.model.inject(&f.rx, 0, 0, &packet(0, &payload))
        || !f
            .model
            .inject(&f.rx, 1, 0, &packet(7, &0x0000_1201u32.to_le_bytes()))
    {
        return TestResult::Fail("device model did not follow actual RXBD allocations");
    }
    let events = f.rx.poll(&mut f.model, 1).unwrap();
    if !matches!(events.as_slice(), [Event::Releases(records), Event::Wifi(_, bytes)]
        if records.len() == 1 && records[0].channel == 8 && bytes == &payload[..36])
        || f.model.raw(0x1050) != 0x10001
        || f.model.raw(0x1054) != 0x10001
    {
        return TestResult::Fail("RX/RPQ actual DMA or host-only WP publication");
    }
    // Real DMA mutation after device publication must affect delivered bytes.
    for slot in 1..5 {
        let slot = slot % 4;
        if !f.model.inject(&f.rx, 0, slot, &packet(0, &payload)) {
            return TestResult::Fail("wrapped RX descriptor allocation missing");
        }
        let buffer = &f.rx.rings.as_ref().unwrap()[0].buffers[slot];
        // SAFETY: complete private fixture buffer, device model finished its
        // write; this mutation is the exact DMA body the production poll reads.
        unsafe {
            buffer.as_mut_ptr().add(20).write_volatile(0xa6);
        }
        buffer.sync(0, BUFFER_SIZE);
        if !matches!(f.rx.poll(&mut f.model, 1).unwrap().as_slice(), [Event::Wifi(_, frame)] if frame[0] == 0xa6)
        {
            return TestResult::Fail("RX observer used pre-publication source bytes");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_rings_original_linux_geometry_and_real_dma
);

fn smoke_rtw89_rx_publication_failure_cancel_and_stale_indices_are_terminal() -> TestResult {
    let mut baseline = Fixture::new();
    if baseline.prepare() != Some(Ok(())) {
        return TestResult::Fail("RX baseline");
    }
    let operations = baseline.model.operations;
    for op in 0..operations {
        let mut f = Fixture::new();
        f.model.fail = Some(op);
        if !matches!(f.prepare(), Some(Err(_))) || f.rx.state() != State::Terminal {
            return TestResult::Fail("RX publication ignored register/configuration failure");
        }
        let before = f.model.operations;
        if f.prepare() != Some(Err(Error::Terminal)) || f.model.operations != before {
            return TestResult::Fail("failed RX publication replayed allocation/registers");
        }
    }
    for a in [
        0x8410, 0x8414, 0x8418, 0x841c, 0x1020, 0x1100, 0x1022, 0x1108, 0x8810, 0x9a00, 0x1010,
        0x1000, 0x8380,
    ] {
        let mut f = Fixture::new();
        f.model.ignore = Some(a);
        if !matches!(f.prepare(), Some(Err(_))) || f.rx.state() != State::Terminal {
            return TestResult::Fail("ignored RX/LTR/ring activation write accepted");
        }
    }
    let mut cancelled = 0;
    for pending in 3..11 {
        let mut f = Fixture::new();
        f.model.pending = Some(pending);
        if f.prepare().is_none() {
            cancelled += 1;
            let before = f.model.operations;
            if f.rx.state() != State::Publishing
                || f.prepare() != Some(Err(Error::Terminal))
                || f.model.operations != before
            {
                return TestResult::Fail("cancelled RX prepare reopened owner");
            }
        }
    }
    if cancelled < 3 {
        return TestResult::Fail("RX configuration cancellation did not reach real awaits");
    }
    for index in [0xffff_ffffu32, 0x40000, 0x10001] {
        let mut f = Fixture::new();
        if f.prepare() != Some(Ok(())) {
            return TestResult::Fail("RX index baseline");
        }
        f.model.bytes[0x1050..0x1054].copy_from_slice(&index.to_le_bytes());
        let addresses: Vec<_> = f.rx.rings.as_ref().unwrap()[0]
            .buffers
            .iter()
            .map(|b| b.dma_addr().raw())
            .collect();
        if f.rx.poll(&mut f.model, 1).is_ok()
            || f.rx.state() != State::Terminal
            || f.rx.rings.as_ref().unwrap()[0]
                .buffers
                .iter()
                .map(|b| b.dma_addr().raw())
                .collect::<Vec<_>>()
                != addresses
        {
            return TestResult::Fail("bad hardware index published RX or released uncertain DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_publication_failure_cancel_and_stale_indices_are_terminal
);

fn smoke_rtw89_rx_device_model_rejects_unowned_dma_and_ignored_repost() -> TestResult {
    let mut f = Fixture::new();
    if f.prepare() != Some(Ok(())) {
        return TestResult::Fail("RX negative baseline");
    }
    let bytes = packet(0, &[0x5a; 40]);
    let ring = &f.rx.rings.as_ref().unwrap()[0];
    let bd = ring.descriptors.as_ref().unwrap();
    let original = bd.as_slice()[..8].to_vec();
    // SAFETY: first actual eight-byte descriptor is owned by this inert model.
    unsafe {
        core::ptr::write_bytes(bd.as_mut_ptr(), 0, 8);
    }
    bd.sync(0, 8);
    if f.model.inject(&f.rx, 0, 0, &bytes) {
        return TestResult::Fail("unwritten RXBD produced fixture success");
    }
    // SAFETY: same complete owned descriptor; restore then change actual DMA
    // address without fabricating a CPU pointer from that corrupted address.
    unsafe {
        core::ptr::copy_nonoverlapping(original.as_ptr(), bd.as_mut_ptr(), 8);
        bd.as_mut_ptr().add(4).write_volatile(original[4] ^ 0x80);
    }
    bd.sync(0, 8);
    if f.model.inject(&f.rx, 0, 0, &bytes) {
        return TestResult::Fail("out-of-owner RXBD produced fixture success");
    }
    // SAFETY: restore that same private descriptor before actual device write.
    unsafe {
        core::ptr::copy_nonoverlapping(original.as_ptr(), bd.as_mut_ptr(), 8);
    }
    bd.sync(0, 8);
    if !f.model.inject(&f.rx, 0, 0, &bytes) {
        return TestResult::Fail("restored native RXBD not observed");
    }
    f.model.ignore = Some(0x1050);
    if f.rx.poll(&mut f.model, 1) != Err(Error::Index) || f.rx.state() != State::Terminal {
        return TestResult::Fail("ignored host RX repost returned frame success");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_device_model_rejects_unowned_dma_and_ignored_repost
);

fn smoke_rtw89_rx_ltr_follows_actual_host_policy_and_original_linux_c() -> TestResult {
    for &(host, seed, expected) in LTR {
        let mut f = Fixture::new();
        f.model.bytes[0x8410..0x8420].fill(seed);
        f.model.bytes[0x10069] = if host { 4 } else { 0 };
        if f.prepare() != Some(Ok(())) {
            return TestResult::Fail("actual PCIe LTR control profile rejected");
        }
        let trace: Vec<_> = f
            .model
            .writes
            .iter()
            .copied()
            .filter(|(a, _)| (0x8410..=0x841c).contains(a))
            .collect();
        if trace != expected {
            return TestResult::Fail("native LTR writes differ from original Linux callback");
        }
    }
    for address in [0x8410, 0x8414, 0x8418, 0x841c] {
        for invalid in [u32::MAX, 0xeaea_eaea] {
            let mut f = Fixture::new();
            f.model.bytes[address..address + 4].copy_from_slice(&invalid.to_le_bytes());
            if !matches!(f.prepare(), Some(Err(_)))
                || f.rx.armed
                || f.model.raw(0x1100) != 0
                || f.model.raw(0x1108) != 0
            {
                return TestResult::Fail("invalid LTR register allowed RX base publication");
            }
        }
    }
    for corrupt in [0x40u8, 0x41, 0xff] {
        let mut f = Fixture::new();
        f.model.bytes[0x10040] = 5;
        f.model.bytes[0x10041] = corrupt;
        if !matches!(f.prepare(), Some(Err(_))) || f.rx.armed {
            return TestResult::Fail("cyclic/misaligned PCIe capability permitted RX DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_ltr_follows_actual_host_policy_and_original_linux_c
);

fn smoke_rtw89_rx_current_native_authority_precedes_allocation_and_dma_reads() -> TestResult {
    use narf_bus::{BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, MmioRegion, PcieAddr};
    use narf_capabilities::{object_table, Cap, CapKind, CapSlot, Rights, Write};
    let (index, generation) = object_table::register(CapKind::BusDevice);
    // SAFETY: fresh private object with exact BusDevice/Write generation and
    // rights; the model owns all mapped register RAM for this capability.
    let authority = unsafe {
        Cap::<BusDeviceCap, Write>::mint(CapSlot::new(
            generation,
            index,
            Write::BITS,
            CapKind::BusDevice as u32,
        ))
    };
    let mut words = vec![0u32; 0x10000 / 4];
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x10000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: complete aligned exclusively owned inert RAM; no real device,
    // hardware producer or independent PHY/reset/IRQ owner exists.
    let mut io = unsafe {
        super::super::power_native::NativeIo::new(region, authority, ChipId::Rtl8852B, 0)
    }
    .unwrap();
    let address = PcieAddr::new(0, 0, 7, 0);
    let device = BusDevice {
        addr: BusAddr::Pcie(address),
        id: DeviceId {
            vendor: 0x10ec,
            device: 0xb852,
            class: 0x028000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr: address,
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let mut prepared = Fixture::new();
    if prepared.prepare() != Some(Ok(())) {
        return TestResult::Fail("native authority RX baseline");
    }
    let before: Vec<_> = prepared
        .rx
        .rings
        .as_ref()
        .unwrap()
        .iter()
        .flat_map(|r| r.buffers.iter().map(|b| b.dma_addr().raw()))
        .collect();
    authority.revoke();
    let mut cold = Rx::default();
    let mut access = super::super::pcie_native::Native {
        io: &mut io,
        device: &device,
        authority: &authority,
    };
    // SAFETY: revoked exact NativeIo authority must reject at the first
    // register read, before allocation or deliberately unmapped PCI config.
    let result = ready(unsafe { cold.prepare(&mut access, 4) });
    if result != Some(Err(Error::Register(power::Error::Access)))
        || cold.rings.is_some()
        || cold.armed
        || words.iter().any(|v| *v != 0)
    {
        return TestResult::Fail("revoked RX publication accessed PCI/BAR or allocated DMA");
    }
    if prepared.rx.poll(&mut io, 1) != Err(Error::Register(power::Error::Access))
        || prepared.rx.state() != State::Terminal
        || prepared
            .rx
            .rings
            .as_ref()
            .unwrap()
            .iter()
            .flat_map(|r| r.buffers.iter().map(|b| b.dma_addr().raw()))
            .collect::<Vec<_>>()
            != before
    {
        return TestResult::Fail("revoked RX poll read a DMA packet or released retained storage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_current_native_authority_precedes_allocation_and_dma_reads
);
