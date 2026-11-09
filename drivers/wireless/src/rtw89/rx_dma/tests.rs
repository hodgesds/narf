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
    c: bool,
}
impl Model {
    /// RTL8852C after its CH12-only download: HAXI stops 0xbff00 (no RX stop
    /// bits), TX HCI bit 7 only, `R_AX_HCI_FUNC_EN_V1` TX-only.
    fn new_c() -> Self {
        let mut m = Self::new();
        m.c = true;
        m.bytes[0x1010..0x1014].copy_from_slice(&0xbff00u32.to_le_bytes());
        m.bytes[0x1000..0x1004].copy_from_slice(&(1u32 << 7).to_le_bytes());
        m.bytes[0x7880..0x7884].copy_from_slice(&1u32.to_le_bytes());
        m
    }
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
            c: false,
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
        let (rx, hci) = if self.c {
            (1 << 15, 0x7880)
        } else {
            (1 << 13, 0x8380)
        };
        if owner.state() != State::Polling
            || self.raw(0x1000) & rx == 0
            || self.raw(hci) & 2 == 0
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
fn smoke_rtw89_rx_rings_reference_geometry_and_real_dma() -> TestResult {
    for &(address, expected) in BD {
        if descriptor(address, BUFFER_SIZE) != Ok(expected) {
            return TestResult::Fail("RXBD address geometry differs from the frozen reference");
        }
    }
    for &(depth, wp, index, expected) in INDEX {
        if available(depth, wp, index) != Ok(expected) {
            return TestResult::Fail("RX ring count differs from the frozen reference");
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
    smoke_rtw89_rx_rings_reference_geometry_and_real_dma
);

fn smoke_rtw89_rx_partial_descriptor_is_progress_not_idle() -> TestResult {
    let mut f = Fixture::new();
    if f.prepare() != Some(Ok(())) {
        return TestResult::Fail("RX preparation");
    }
    let mut bytes = packet(0, &[0x56; 40]);
    // FIRST without LAST: assembler owns an incomplete actual DMA record.
    bytes.truncate(40); // RXD promises40 bytes, this first fragment carries20.
    let first = bytes.len() as u32 | 1 << 15;
    bytes[..4].copy_from_slice(&first.to_le_bytes());
    if !f.model.inject(&f.rx, 0, 0, &bytes) {
        return TestResult::Fail("RX injection");
    }
    let Ok(batch) = f.rx.poll_step(&mut f.model, 1) else {
        return TestResult::Fail("valid partial native RX record was rejected");
    };
    if !batch.consumed || !batch.events.is_empty() {
        return TestResult::Fail("partial FS/LS record became an event or idle fence");
    }
    let idle = f.rx.poll_step(&mut f.model, 1).unwrap();
    if idle.consumed || !idle.events.is_empty() {
        return TestResult::Fail("fresh RXQ/RPQ idle indices invented progress");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_partial_descriptor_is_progress_not_idle
);

fn smoke_rtw89_rx_publication_failure_cancel_and_stale_indices_are_terminal() -> TestResult {
    let mut unqualified = Fixture::new();
    unqualified.model.bytes[0xc000..0xc004].copy_from_slice(&(1u32 << 29).to_le_bytes());
    if unqualified.prepare() != Some(Err(Error::Register(power::Error::Access)))
        || unqualified.rx.armed
        || unqualified.rx.rings.is_some()
    {
        return TestResult::Fail(
            "RX publication accepted an unqualified autonomous response TX gate",
        );
    }
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
    let mut f = Fixture::new();
    if f.prepare() != Some(Ok(())) || !f.model.inject(&f.rx, 0, 0, &bytes) {
        return TestResult::Fail("RX response-policy negative baseline");
    }
    f.model.bytes[0xc000..0xc004].copy_from_slice(&(1u32 << 29).to_le_bytes());
    if f.rx.poll(&mut f.model, 1) != Err(Error::Register(power::Error::Access))
        || f.model.raw(0x1050) != 0x10000
        || f.rx.state() != State::Terminal
    {
        return TestResult::Fail(
            "RX poll returned frame evidence after autonomous TX gate changed",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_device_model_rejects_unowned_dma_and_ignored_repost
);

fn smoke_rtw89_rx_ltr_follows_actual_host_policy_and_frozen_references() -> TestResult {
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
    smoke_rtw89_rx_ltr_follows_actual_host_policy_and_frozen_references
);

fn smoke_rtw89_rx_current_native_authority_precedes_allocation_and_dma_reads() -> TestResult {
    use narf_bus::{BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, MmioRegion, PcieAddr};
    use narf_capabilities::{Cap, Write};
    // Fresh live BusDevice/Write fixture authority, minted via the
    // safe `Cap::bootstrap` path (SEC-B5, #1293: `Cap::mint` is
    // crate-private to `capabilities/`).
    let authority = Cap::<BusDeviceCap, Write>::bootstrap();
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

fn smoke_rtw89_rx_reclaim_releases_both_rings_once_and_stays_terminal() -> TestResult {
    let mut f = Fixture::new();
    if f.prepare() != Some(Ok(())) || f.rx.state() != State::Polling {
        return TestResult::Fail("RX reclaim baseline");
    }
    // SAFETY: inert RAM model; no device, prefetch or IRQ producer exists.
    let storage = unsafe { f.rx.reclaim_fenced() };
    // Two rings: one descriptor array plus depth (4) buffers each.
    if storage.len() != 2 * (1 + 4)
        || f.rx.armed
        || f.rx.rings.is_some()
        || f.rx.state() != State::Terminal
        || f.rx.poll(&mut f.model, 1).is_ok()
    {
        return TestResult::Fail("RX reclamation kept, duplicated or reopened ring storage");
    }
    // SAFETY: same inert model; a second reclaim has nothing to release.
    if !unsafe { f.rx.reclaim_fenced() }.is_empty() {
        return TestResult::Fail("RX reclamation released storage twice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_rx_reclaim_releases_both_rings_once_and_stays_terminal
);

/// Actual prepare/allocation/descriptor owner using the same inert source IO
/// model; caller retains/fences every allocation before fixture destruction.
pub(in crate::rtw89) fn native_fixture() -> Rx {
    let mut rx = Rx::default();
    let mut model = Model::new();
    // SAFETY: exclusive private RAM/config/DMA model, no hardware/prefetch;
    // the returned owner is reclaimed only by the caller's inert fence.
    let prepared = unsafe { rx.prepare(&mut model, 4) };
    assert!(matches!(ready(prepared), Some(Ok(()))));
    rx
}

/// Inert device producer writes the ORIGINAL retained next RX buffer. Caller
/// separately publishes its actual HCI producer index, then actual Native/Rx
/// consumes/rearms this mapping; no fabricated receive/current-source receipt.
pub(in crate::rtw89) fn native_publish_one(rx: &mut Rx, mpdu: &[u8]) {
    let ring = &mut rx.rings.as_mut().unwrap()[0];
    let buffer = &ring.buffers[usize::from(ring.wp)];
    let mut wire = alloc::vec![0;20];
    wire[..4].copy_from_slice(&((20 + mpdu.len() + 4) as u32 | 1 << 15 | 1 << 14).to_le_bytes());
    wire[4..8].copy_from_slice(&((mpdu.len() + 4) as u32).to_le_bytes());
    wire.extend_from_slice(mpdu);
    wire.extend_from_slice(&[0; 4]);
    assert!(wire.len() <= buffer.len());
    // SAFETY: exclusive inert retained DMA buffer, exact checked extent; no
    // real hardware, concurrent Native access, prefetch or Rust memory alias.
    unsafe {
        core::ptr::copy_nonoverlapping(wire.as_ptr(), buffer.as_mut_ptr(), wire.len());
    }
    buffer.sync(0, wire.len());
}

fn smoke_rtw8852c_rx_rings_follow_haxi_v1_geometry() -> TestResult {
    let mut f = Fixture {
        rx: Rx::default(),
        model: Model::new_c(),
    };
    // SAFETY: private RAM model with no DMA/reset/IRQ producer; the fixture
    // retains every allocation and fences it before destruction.
    if ready(unsafe { f.rx.prepare_for(&mut f.model, ChipId::Rtl8852C, 4) }) != Some(Ok(()))
        || f.rx.state() != State::Polling
    {
        return TestResult::Fail("C RXQ/RPQ preparation did not reach Polling");
    }
    let m = &f.model;
    let wrote = |a: u32| m.writes.iter().any(|&(w, _)| w == a);
    // rtw89_pci_ch_dma_addr_set_v1 bases, RX index clear V1, LTR v1, RX HCI
    // V1 layers released; no B HCI/stop/address-info register touched.
    let rings = f.rx.rings.as_ref().unwrap();
    if rings[0].regs.desa_l != 0x1220
        || rings[1].regs.desa_l != 0x1228
        || m.raw(0x1220) as u64
            != rings[0].descriptors.as_ref().unwrap().dma_addr().raw() & 0xffff_ffff
        || m.raw(0x1200) & 3 != 3
        || m.raw(0x1600) & 7 != 6
        || m.raw(0x8410) & 0x703 != 0x703
        || m.raw(0x8414) != 0x0028_0028
        || m.raw(0x1610) != 0x9003_9003
        || m.raw(0x1604) != 0x880b_880b
        || m.raw(0x1000) & (1 << 15) == 0
        || m.raw(0x7880) & 3 != 3
        || m.raw(0x1010) != 0xbff00
        || wrote(0x8380)
        || wrote(0x8810)
        || wrote(0x9a00)
        || wrote(0x1018)
        || wrote(0x8418)
    {
        return TestResult::Fail("C RX geometry differs from rtw8852c_pci_info");
    }
    let payload: Vec<u8> = (0..40).collect();
    if !f.model.inject(&f.rx, 0, 0, &packet(0, &payload)) {
        return TestResult::Fail("C device model did not follow actual V1 RXBD allocations");
    }
    let events = f.rx.poll(&mut f.model, 1).unwrap();
    if !matches!(events.as_slice(), [Event::Wifi(_, bytes)] if bytes == &payload[..36]) {
        return TestResult::Fail("C RXQ did not deliver the actual DMA frame");
    }
    // AX_RXD_BW_v1_MASK: dword1 bit 29 is C bandwidth, B INTER_PPDU.
    let mut wide = packet(0, &payload);
    wide[8..12].copy_from_slice(&(1u32 << 29).to_le_bytes());
    if rx_packet::Descriptor::parse_v1(&wide).map(|d| d.bandwidth) != Ok(1)
        || rx_packet::Descriptor::parse(&wide).map(|d| d.bandwidth) != Ok(0)
    {
        return TestResult::Fail("C RX descriptor bandwidth layout differs from AX_RXD_BW_v1_MASK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_rx_rings_follow_haxi_v1_geometry
);
fn smoke_rtw8852c_rx_refuses_open_rx_before_publication() -> TestResult {
    for (address, value) in [
        (0x1000u32, (1u32 << 7) | (1 << 15)),
        (0x7880, 3),
        (0x1010, 0xb0f00),
    ] {
        let mut f = Fixture {
            rx: Rx::default(),
            model: Model::new_c(),
        };
        f.model.bytes[address as usize..address as usize + 4].copy_from_slice(&value.to_le_bytes());
        // SAFETY: as above; invalid prerequisite geometry must be refused.
        if ready(unsafe { f.rx.prepare_for(&mut f.model, ChipId::Rtl8852C, 4) })
            != Some(Err(Error::Register(power::Error::Access)))
            || !f.model.writes.is_empty()
        {
            return TestResult::Fail("C RX published rings over open or B RX geometry");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_rx_refuses_open_rx_before_publication
);

fn smoke_rtw8852a_rx_prepare_takes_ax_geometry_and_ltr_trigger() -> TestResult {
    let mut f = Fixture::new();
    // Seed the full A DMA-stop state: A stops ACH4/6, CH8, CH12
    // (`B_AX_TX_STOP1_MASK`) plus CH10/11 (`B_AX_TX_STOP2_ALL`), a
    // superset of B's V1 mask; the shared stopped readback must hold.
    f.model.bytes[0x1010..0x1014].copy_from_slice(&0xf5f03u32.to_le_bytes());
    f.model.bytes[0x1310..0x1314].copy_from_slice(&3u32.to_le_bytes());
    // SAFETY: private RAM model with no DMA/reset/IRQ producer; the fixture
    // retains every allocation and fences it before destruction.
    if ready(unsafe { f.rx.prepare_for(&mut f.model, ChipId::Rtl8852A, 4) }) != Some(Ok(()))
        || f.rx.state() != State::Polling
    {
        return TestResult::Fail("A RXQ/RPQ preparation did not reach Polling");
    }
    let m = &f.model;
    // AX baseline ring addresses (rtw8852ae.c `rtw89_pci_ch_dma_addr_set`),
    // RXQ 0x1100 / RPQ 0x1108, with the 0x1010 stop bits minus RXQ/RPQ.
    let rings = f.rx.rings.as_ref().unwrap();
    if rings[0].regs.desa_l != 0x1100
        || rings[1].regs.desa_l != 0x1108
        || m.raw(0x1010) != 0xf5f00
        || m.raw(0x1000) & (1 << 13) == 0
        || m.raw(0x8380) & 2 == 0
    {
        return TestResult::Fail("A RX geometry differs from rtw8852a_pci_info");
    }
    // A-only LTR software trigger (pci.c `mac_post_init_ax`): 0x8410 bit 5.
    // 8-byte address-info mode (A/B only): 0x8810 bit 0 set, 0x9a00 bit 1
    // clear. The V1 release registers stay untouched.
    if m.raw(0x8410) & (1 << 5) == 0
        || m.raw(0x8810) & 1 == 0
        || m.raw(0x9a00) & 2 != 0
        || m.raw(0x7880) != 0
        || m.raw(0x1200) != 0
    {
        return TestResult::Fail("A LTR trigger or address-info mode missing");
    }
    let payload: Vec<u8> = (0..40).collect();
    if !f.model.inject(&f.rx, 0, 0, &packet(0, &payload)) {
        return TestResult::Fail("A device model did not follow actual AX RXBD allocations");
    }
    let events = f.rx.poll(&mut f.model, 1).unwrap();
    if !matches!(events.as_slice(), [Event::Wifi(_, bytes)] if bytes == &payload[..36]) {
        return TestResult::Fail("A RXQ did not deliver the actual DMA frame");
    }
    // B keeps its own path: no A-only LTR trigger bit.
    let mut b = Fixture::new();
    if b.prepare() != Some(Ok(())) || b.model.raw(0x8410) & (1 << 5) != 0 {
        return TestResult::Fail("B RX prepare set the A-only LTR trigger");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_rx_prepare_takes_ax_geometry_and_ltr_trigger
);
