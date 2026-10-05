//! Phoenix ACP 6.3 PDM capture, native (no DSP firmware).
//! References: Linux sound/soc/amd/ps/{pci-ps,ps-common,ps-pdm-dma}.c
//! and include/sound/acp63_chip_offset_byte.h. SoundWire-only configurations
//! are left unbound; HDA remains an independent PCI function.
use crate::{
    native_irq::{Kind, Route, State},
    native_pcm::Ring,
};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::Ordering;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_drivers_sound::{
    format::{ChannelCount, HwParams, SampleFormat, SampleRate},
    hardware::{PcmDevice, PcmHardware},
    SoundError,
};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

pub const VENDOR: u16 = 0x1022;
pub const DEVICE: u16 = 0x15e2;
pub const REVISION: u8 = 0x63;
const RESET: u64 = 0x1000;
const CONTROL: u64 = 0x1004;
const ZSC: u64 = 0x1014;
const POWER_CONTROL: u64 = 0x1024;
const POWER_STATUS: u64 = 0x1028;
const PIN_CONFIG: u64 = 0x1440;
const INTR_ENABLE: u64 = 0x1a00;
const INTR_CONTROL: u64 = 0x1a04;
const INTR_STATUS: u64 = 0x1a0c;
const PDM_ENABLE: u64 = 0x2c04;
const DMA_ENABLE: u64 = 0x2c08;
const RING_ADDR: u64 = 0x2c0c;
const RING_SIZE: u64 = 0x2c10;
const COUNT_HIGH: u64 = 0x2c18;
const COUNT_LOW: u64 = 0x2c1c;
const WATERMARK: u64 = 0x2c20;
const FIFO_FLUSH: u64 = 0x2c24;
const CHANNELS: u64 = 0x2c28;
const DECIMATION: u64 = 0x2c2c;
const CLOCK: u64 = 0x2c60;
const MISC: u64 = 0x2c5c;
const ATU_PAGE_SIZE: u64 = 0xc00;
const ATU_BASE: u64 = 0xc04;
const ATU_CONTROL: u64 = 0xc40;
const SCRATCH: u64 = 0x10000;
const DMA_WINDOW: u32 = 0x4000000;
const PTE_BASE: u32 = 0x03800000;
const PDM_IRQ: u32 = 1 << 16;

#[derive(Debug, Default)]
struct Capture {
    ring: Option<Ring>,
    claimed: bool,
    baseline: u64,
}
#[derive(Debug)]
struct Controller {
    mmio: MmioRegion,
    irq: Arc<State>,
    route: Option<Route>,
    capture: IrqSafeSpinLock<Capture>,
}
fn wait(predicate: impl FnMut() -> bool) -> bool {
    narf_scheduler::responsive_spin_until(predicate, Deadline::after_ms(100))
}
/// Linux acp63_get_config: PDM can coexist with SoundWire; revision alone
/// does not describe the board wiring.
pub fn pin_config_has_pdm(config: u32) -> bool {
    matches!(config, 4 | 5 | 6 | 7 | 8 | 10 | 11 | 12 | 13 | 14)
}
impl Controller {
    fn reset(mmio: MmioRegion) -> bool {
        // SAFETY: exclusively owned, validated ACP 6.3 register window.
        unsafe {
            mmio.write32(RESET, 1);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { mmio.read32(RESET) } & 0x10001 != 0) {
            return false;
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            mmio.write32(RESET, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        wait(|| unsafe { mmio.read32(RESET) } == 0)
    }
    fn init(mmio: MmioRegion) -> Result<Self, SoundError> {
        if mmio.len < SCRATCH + 64 {
            return Err(SoundError::NoSuchDevice);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let state = unsafe { mmio.read32(POWER_STATUS) };
        if state == u32::MAX {
            return Err(SoundError::NoSuchDevice);
        }
        if state != 0 {
            if state & 3 != 1 {
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe {
                    mmio.write32(POWER_CONTROL, 1);
                }
            }
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            if !wait(|| unsafe { mmio.read32(POWER_STATUS) } == 0) {
                return Err(SoundError::BadState);
            }
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            mmio.write32(CONTROL, 1);
        }
        if !Self::reset(mmio) {
            return Err(SoundError::BadState);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            mmio.write32(INTR_CONTROL, 0);
            mmio.write32(INTR_ENABLE, 0);
            mmio.write32(INTR_STATUS, u32::MAX);
            mmio.write32(ZSC, 0);
        }
        Ok(Self {
            mmio,
            irq: State::new(mmio, Kind::Acp),
            route: None,
            capture: IrqSafeSpinLock::new(Capture::default()),
        })
    }
    fn count(&self) -> Result<u64, SoundError> {
        // Counter can roll over between reads; bounded high/low/high snapshot.
        for _ in 0..4 {
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            let (hi, lo, again) = unsafe {
                (
                    self.mmio.read32(COUNT_HIGH),
                    self.mmio.read32(COUNT_LOW),
                    self.mmio.read32(COUNT_HIGH),
                )
            };
            if hi == again {
                return Ok(((hi as u64) << 32) | lo as u64);
            }
        }
        Err(SoundError::BadState)
    }
    fn stop(&self, state: &mut Capture) -> Result<(), SoundError> {
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        unsafe {
            self.mmio
                .write32(INTR_CONTROL, self.mmio.read32(INTR_CONTROL) & !PDM_IRQ);
            if self.mmio.read32(DMA_ENABLE) & 3 != 0 {
                self.mmio.write32(DMA_ENABLE, 2);
            }
        }
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        if !wait(|| unsafe { self.mmio.read32(DMA_ENABLE) } & 2 == 0) {
            self.irq.failed.store(true, Ordering::Release);
            return Err(SoundError::BadState);
        }
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        unsafe {
            self.mmio.write32(PDM_ENABLE, 0);
            self.mmio.write32(FIFO_FLUSH, 1);
        }
        if let Some(ring) = state.ring.as_mut() {
            ring.running = false;
            ring.prepared = false;
        }
        Ok(())
    }
    fn update(&self, state: &mut Capture) {
        let Some(ring) = state.ring.as_mut() else {
            return;
        };
        if !ring.running {
            return;
        }
        let count = self.count();
        if self.irq.failed.load(Ordering::Acquire) || count.is_err() {
            ring.xrun = true;
            let _ = self.stop(state);
            return;
        }
        ring.hardware = count.unwrap().wrapping_sub(state.baseline) & !7;
        if ring.hardware.saturating_sub(ring.application) > ring.bytes as u64 {
            ring.xrun = true;
            let _ = self.stop(state);
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            self.mmio.write32(INTR_CONTROL, 0);
            self.mmio.write32(INTR_ENABLE, 0);
        }
        self.route.take();
        let stopped = Self::reset(self.mmio);
        if let Some(ring) = self.capture.lock().ring.take() {
            if !stopped {
                core::mem::forget(ring);
            }
        }
        if stopped {
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            unsafe {
                self.mmio.write32(CONTROL, 0);
                self.mmio.write32(ZSC, 1);
            }
        }
    }
}
#[derive(Debug)]
struct Card(Arc<Controller>);
impl PcmDevice for Card {
    fn capabilities(&self, capture: bool) -> narf_drivers_sound::hardware::PcmCapabilities {
        let mut caps =
            narf_drivers_sound::hardware::PcmCapabilities::fixed(self.default_params(capture));
        caps.period_frames = (512, 1024);
        caps.buffer_bytes = (16384, 32768);
        caps.period_byte_alignment = 128;
        caps
    }
    fn default_params(&self, _: bool) -> HwParams {
        HwParams {
            format: SampleFormat::S32LE,
            rate: SampleRate::R48000,
            channels: ChannelCount::Stereo,
            period_size: 1024,
            periods: 4,
        }
    }
    fn open(&self, capture: bool, device: u32) -> Result<Box<dyn PcmHardware>, SoundError> {
        if !capture || device != 0 {
            return Err(SoundError::NoSuchDevice);
        }
        let mut state = self.0.capture.lock();
        if state.claimed {
            return Err(SoundError::DeviceBusy);
        }
        if self.0.irq.failed.load(Ordering::Acquire) {
            return Err(SoundError::BadState);
        }
        state.claimed = true;
        Ok(Box::new(Pcm(self.0.clone())))
    }
}
#[derive(Debug)]
struct Pcm(Arc<Controller>);
impl PcmHardware for Pcm {
    fn configure(&mut self, params: HwParams) -> Result<(), SoundError> {
        if params.format != SampleFormat::S32LE
            || params.rate != SampleRate::R48000
            || params.channels != ChannelCount::Stereo
            || params.periods != 4
            || !(512..=1024).contains(&params.period_size)
        {
            return Err(SoundError::InvalidParams);
        }
        let ring = Ring::new(params)?;
        let mut state = self.0.capture.lock();
        self.0.stop(&mut state)?;
        state.ring = Some(ring);
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SoundError> {
        let mut state = self.0.capture.lock();
        self.0.stop(&mut state)?;
        if self.0.irq.failed.load(Ordering::Acquire) {
            return Err(SoundError::BadState);
        }
        let ring = state.ring.as_mut().ok_or(SoundError::BadState)?;
        ring.reset();
        let mmio = self.0.mmio;
        // ACP's internal ATU translates its fixed DMA window to system DMA
        // pages; a CPU virtual address must never be programmed here.
        // SAFETY: DMA is stopped; validated ring geometry bounds PTE writes within the mapped scratch window.
        unsafe {
            mmio.write32(ATU_BASE, PTE_BASE | (1 << 31));
            mmio.write32(ATU_PAGE_SIZE, 2);
            for page in 0..ring.bytes.div_ceil(4096) {
                let address = ring.data.dma_addr_at((page * 4096) as u64).raw();
                mmio.write32(SCRATCH + page as u64 * 8, address as u32);
                mmio.write32(
                    SCRATCH + page as u64 * 8 + 4,
                    (address >> 32) as u32 | (1 << 31),
                );
            }
            mmio.write32(RING_ADDR, DMA_WINDOW);
            mmio.write32(RING_SIZE, ring.bytes as u32);
            mmio.write32(WATERMARK, ring.params.period_bytes() as u32);
            mmio.write32(ATU_CONTROL, 1);
            mmio.write32(INTR_STATUS, PDM_IRQ);
        }
        Ok(())
    }
    fn start(&mut self) -> Result<(), SoundError> {
        let mut state = self.0.capture.lock();
        if !state
            .ring
            .as_ref()
            .is_some_and(|r| r.prepared && !r.xrun && !r.running)
            || self.0.irq.failed.load(Ordering::Acquire)
        {
            return Err(SoundError::BadState);
        }
        // Preserve the logical position across PAUSE/RESUME; PREPARE resets
        // hardware to zero, while a paused stream retains its completed bytes.
        state.baseline = self
            .0
            .count()?
            .wrapping_sub(state.ring.as_ref().unwrap().hardware);
        let mmio = self.0.mmio;
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        unsafe {
            mmio.write32(CHANNELS, 0);
            mmio.write32(DECIMATION, 2);
            mmio.write32(CLOCK, 7);
            mmio.write32(MISC, (mmio.read32(MISC) & !(3 << 3)) | (3 << 3));
            mmio.write32(INTR_CONTROL, (1 << 29) | PDM_IRQ);
            mmio.write32(INTR_ENABLE, u32::from(self.0.route.is_some()));
            mmio.write32(PDM_ENABLE, 1);
            mmio.write32(DMA_ENABLE, 1);
        }
        // Set before polling: even a timed-out start may have begun DMA.
        state.ring.as_mut().unwrap().running = true;
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        if !wait(|| unsafe { mmio.read32(DMA_ENABLE) } & 2 != 0) {
            let _ = self.0.stop(&mut state);
            return Err(SoundError::BadState);
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), SoundError> {
        self.0.stop(&mut self.0.capture.lock())
    }
    fn reset(&mut self) -> Result<(), SoundError> {
        let mut state = self.0.capture.lock();
        self.0.update(&mut state);
        let ring = state.ring.as_mut().ok_or(SoundError::BadState)?;
        ring.application = ring.hardware;
        Ok(())
    }
    fn pause(&mut self, paused: bool) -> Result<(), SoundError> {
        if !paused {
            return self.start();
        }
        let mut state = self.0.capture.lock();
        self.0.update(&mut state);
        self.0.stop(&mut state)?;
        state.ring.as_mut().ok_or(SoundError::BadState)?.prepared = true;
        Ok(())
    }
    fn pointer(&self) -> u64 {
        let mut state = self.0.capture.lock();
        self.0.update(&mut state);
        state.ring.as_ref().map_or(0, |r| r.hardware / 8)
    }
    fn write(&mut self, _: &[u8]) -> Result<usize, SoundError> {
        Err(SoundError::BadState)
    }
    fn read(&mut self, out: &mut [u8]) -> Result<usize, SoundError> {
        let mut state = self.0.capture.lock();
        self.0.update(&mut state);
        let ring = state.ring.as_mut().ok_or(SoundError::BadState)?;
        let original = ring.application;
        let count = ring.read(out)?;
        // Detect a DMA wrap racing the CPU copy; don't report overwritten data.
        self.0.update(&mut state);
        let ring = state.ring.as_mut().ok_or(SoundError::BadState)?;
        if ring.xrun || ring.hardware.saturating_sub(original) > ring.bytes as u64 {
            ring.xrun = true;
            let _ = self.0.stop(&mut state);
            return Err(SoundError::BadState);
        }
        Ok(count)
    }
    fn drain(&mut self) -> Result<(), SoundError> {
        self.stop()
    }
}
impl Drop for Pcm {
    fn drop(&mut self) {
        let mut state = self.0.capture.lock();
        if self.0.stop(&mut state).is_ok() {
            state.ring.take();
        }
        state.claimed = false;
    }
}
static CONTROLLER: IrqSafeSpinLock<Option<(Arc<Controller>, u32)>> = IrqSafeSpinLock::new(None);
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}
pub fn capture_card() -> Option<u32> {
    CONTROLLER.lock().as_ref().map(|(_, card)| *card)
}
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    use narf_bus::ProbeError;
    let revision =
        narf_bus::pci::read_config32(&cap, &device, 8).map_err(|_| ProbeError::BadDevice)? as u8;
    if device.id.vendor != VENDOR
        || device.id.device != DEVICE
        || device.id.class != 0x048000
        || revision != REVISION
    {
        return Err(ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Err(ProbeError::NotForThisDriver);
    }
    if !crate::native_firmware::acp_dmic_present(&device) {
        return Err(ProbeError::NotForThisDriver);
    }
    crate::native_pci::power_on(&device, &cap)?;
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| ProbeError::BadDevice)?;
    // SAFETY: Bus probing has exclusively claimed this function and its BAR.
    let mmio = unsafe { narf_bus::bar::map_bar(&device, 0) }.map_err(|_| ProbeError::BadDevice)?;
    let mut dev = Controller::init(mmio).map_err(|_| ProbeError::BadDevice)?;
    // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
    if !pin_config_has_pdm(unsafe { mmio.read32(PIN_CONFIG) }) {
        return Err(ProbeError::NotForThisDriver);
    }
    dev.route = Route::new(&device, &cap, dev.irq.clone());
    let dev = Arc::new(dev);
    let info = narf_drivers_sound::CardInfo {
        index: 0,
        driver: "acp63-pdm",
        id: "ACP63",
        name: "AMD ACP 6.3 Digital Microphone",
        playback_count: 0,
        capture_count: 1,
    };
    let card = narf_drivers_sound::register_hardware_card_at(
        info,
        Arc::new(Card(dev.clone())),
        Some(device.addr),
    );
    *CONTROLLER.lock() = Some((dev.clone(), card));
    let weak = Arc::downgrade(&dev);
    narf_scheduler::spawn(async move {
        loop {
            narf_time::SleepUntil::new(Deadline::after_ms(2).as_instant()).await;
            let Some(dev) = weak.upgrade() else {
                break;
            };
            dev.irq.service();
            dev.update(&mut dev.capture.lock());
        }
    });
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: "acp63-pdm".into(),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(VENDOR),
        pci_did: Some(DEVICE),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
}
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "acp63-pdm",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VENDOR,
            device: DEVICE,
        },
        probe,
    });
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;
    use narf_io::{alloc_coherent, DmaBuffer};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::id::DomainId;
    static MODEL: IrqSafeSpinLock<usize> = IrqSafeSpinLock::new(0);
    static REGISTERED: AtomicBool = AtomicBool::new(false);
    struct Model {
        mmio: MmioRegion,
        cpu: usize,
        stall_stop: bool,
    }
    fn pump() {
        let pointer = MODEL.lock();
        if *pointer == 0 {
            return;
        }
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        let model = unsafe { &mut *(*pointer as *mut Model) };
        if model.cpu != narf_lib::percpu::current_cpu() {
            return;
        }
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        unsafe {
            match model.mmio.read32(DMA_ENABLE) {
                1 => model.mmio.write32(DMA_ENABLE, 3),
                2 if !model.stall_stop => model.mmio.write32(DMA_ENABLE, 0),
                _ => {}
            }
        }
    }
    struct Fixture {
        dev: Option<Arc<Controller>>,
        model: Box<Model>,
        _memory: DmaBuffer,
    }
    impl Fixture {
        fn new() -> Result<Self, SoundError> {
            let memory =
                alloc_coherent(0x11000, DomainId::DRIVER_0).map_err(|_| SoundError::NoMemory)?;
            let mmio = MmioRegion {
                phys: memory.phys_addr(),
                virt: memory.cpu_mut_ptr::<u8>() as u64,
                len: memory.len() as u64,
                kind: narf_bus::bar::BarKind::Mmio32 {
                    prefetchable: false,
                },
            };
            let mut fixture = Self {
                dev: None,
                model: Box::new(Model {
                    mmio,
                    cpu: narf_lib::percpu::current_cpu(),
                    stall_stop: false,
                }),
                _memory: memory,
            };
            *MODEL.lock() = &mut *fixture.model as *mut Model as usize;
            if !REGISTERED.swap(true, Ordering::AcqRel) {
                narf_scheduler::sleep_pumps::register_nested_only(pump);
            }
            fixture.dev = Some(Arc::new(Controller::init(mmio)?));
            Ok(fixture)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.dev.take();
            *MODEL.lock() = 0;
        }
    }
    fn native_acp63_pdm_dma_and_failed_stop() -> TestResult {
        let mut fixture = match Fixture::new() {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        let card = Card(dev.clone());
        let mut pcm = match card.open(true, 0) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("ACP open"),
        };
        if card.open(true, 0).is_ok() || card.open(false, 0).is_ok() {
            return TestResult::Fail("ACP direction/exclusivity");
        }
        let params = card.default_params(true);
        if pcm.configure(params).is_err() || pcm.prepare().is_err() {
            return TestResult::Fail("ACP PCM setup");
        }
        let dma = dev
            .capture
            .lock()
            .ring
            .as_ref()
            .unwrap()
            .data
            .dma_addr()
            .raw();
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        unsafe {
            if dev.mmio.read32(ATU_BASE) != (PTE_BASE | (1 << 31))
                || dev.mmio.read32(ATU_PAGE_SIZE) != 2
                || dev.mmio.read32(SCRATCH) != dma as u32
                || dev.mmio.read32(SCRATCH + 4) != ((dma >> 32) as u32 | (1 << 31))
                || dev.mmio.read32(RING_ADDR) != DMA_WINDOW
                || dev.mmio.read32(RING_SIZE) != 32768
            {
                return TestResult::Fail("ACP ATU/DMA layout");
            }
            dev.mmio.write32(COUNT_HIGH, 1);
            dev.mmio.write32(COUNT_LOW, 0xfffffff0);
        }
        if pcm.start().is_err() {
            return TestResult::Fail("ACP start");
        }
        {
            let state = dev.capture.lock();
            // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
            unsafe {
                core::ptr::write_bytes(
                    state.ring.as_ref().unwrap().data.cpu_mut_ptr::<u8>(),
                    0x27,
                    4096,
                );
                dev.mmio.write32(COUNT_HIGH, 2);
                dev.mmio.write32(COUNT_LOW, 0xff0);
            }
        }
        if pcm.pointer() != 512 {
            return TestResult::Fail("ACP 64-bit counter rollover");
        }
        let mut output = [0; 4096];
        if pcm.read(&mut output) != Ok(4096)
            || output != [0x27; 4096]
            || pcm.read(&mut output) != Ok(0)
        {
            return TestResult::Fail("ACP completed capture data");
        }
        if pcm.pause(true).is_err() || pcm.pointer() != 512 {
            return TestResult::Fail("ACP pause preserves position");
        }
        // SAFETY: this fixture owns the fake counter register window. Model a
        // changed physical count across the stopped interval, then fresh DMA.
        unsafe {
            dev.mmio.write32(COUNT_LOW, 0x1ff0);
        }
        if pcm.pointer() != 512 || pcm.pause(false).is_err() || pcm.pointer() != 512 {
            return TestResult::Fail("ACP resume preserves logical baseline");
        }
        // SAFETY: same live fake counter registers as above.
        unsafe {
            dev.mmio.write32(COUNT_LOW, 0x2ff0);
        }
        if pcm.pointer() != 1024 || pcm.reset().is_err() || pcm.read(&mut output) != Ok(0) {
            return TestResult::Fail("ACP resumed progress and application reset");
        }
        fixture.model.stall_stop = true;
        if pcm.stop().is_ok() {
            return TestResult::Fail("stalled DMA stop must fail");
        }
        if dev
            .capture
            .lock()
            .ring
            .as_ref()
            .unwrap()
            .data
            .dma_addr()
            .raw()
            != dma
            || !dev.irq.failed.load(Ordering::Acquire)
        {
            return TestResult::Fail("failed stop retained DMA");
        }
        fixture.model.stall_stop = false;
        drop(pcm);
        if dev.capture.lock().ring.is_some() {
            return TestResult::Fail("confirmed stop releases DMA");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63", native_acp63_pdm_dma_and_failed_stop);

    fn native_acp63_overrun_and_pin_config() -> TestResult {
        for config in 0..20 {
            if pin_config_has_pdm(config) != [4, 5, 6, 7, 8, 10, 11, 12, 13, 14].contains(&config) {
                return TestResult::Fail("ACP pin configuration");
            }
        }
        let fixture = match Fixture::new() {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        let card = Card(dev.clone());
        let mut pcm = card.open(true, 0).unwrap();
        if pcm.configure(card.default_params(true)).is_err()
            || pcm.prepare().is_err()
            || pcm.start().is_err()
        {
            return TestResult::Fail("ACP capture start");
        }
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        unsafe {
            dev.mmio.write32(COUNT_LOW, 32776);
        }
        if pcm.read(&mut [0; 8]) != Err(SoundError::BadState) {
            return TestResult::Fail("capture overrun must be reported");
        }
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        if unsafe { dev.mmio.read32(DMA_ENABLE) } & 2 != 0 {
            return TestResult::Fail("overrun must stop DMA");
        }
        if pcm.prepare().is_err() || pcm.start().is_err() {
            return TestResult::Fail("prepare clears overrun");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63", native_acp63_overrun_and_pin_config);
}
