//! Renoir / Lucienne / Cezanne ACP 3.x PDM capture, native (no DSP
//! firmware). The ACP on these APUs is the 3.x generation of the same
//! block the Phoenix ACP 6.3 engine (`acp63`) drives: the WOV/PDM, ATU
//! and scratch windows sit at identical offsets, and the PCM contract
//! matches exactly (S32LE, 48 kHz, stereo, four periods of 512–1024
//! frames). The generation deltas are the probe revision (0x01, not
//! 0x63), the power/reset sequencing (PGFSM handshake + CLKMUX select
//! instead of the 6.x power registers), the external-interrupt block
//! address, and the ATU SRAM PTE base.
//! References: Linux sound/soc/amd/renoir/{rn-pci-acp3x.c,
//! acp3x-pdm-dma.c, rn_acp3x.h, rn_chip_offset_byte.h}.
//!
//! Linux splits power management on a module parameter
//! (`acp_power_gating`, default off): deinit resets the block and
//! clears CLKMUX/CONTROL but does not power the ACP off. This driver
//! follows the default. Linux also carries a DMI quirk table for
//! boards whose ACPI advertises a DMIC that is not populated; the
//! shared `native_firmware::acp_dmic_present` gate (the same one the
//! 6.3 path uses) is the only presence check here.
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
/// PCI revision of the ACP 3.x generation (`rn-pci-acp3x.c` rejects
/// any other revision on this device id).
pub const REVISION: u8 = 0x01;
const RESET: u64 = 0x1000;
const CONTROL: u64 = 0x1004;
const PGFSM_CONTROL: u64 = 0x141c;
const PGFSM_STATUS: u64 = 0x1420;
const CLKMUX_SEL: u64 = 0x1424;
const INTR_ENABLE: u64 = 0x1800;
const INTR_CONTROL: u64 = 0x1804;
const INTR_STATUS: u64 = 0x1808;
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
/// Linux `ACP_SRAM_PTE_OFFSET` for the 3.x ATU group-1 window.
const PTE_BASE: u32 = 0x02050000;
const PDM_IRQ: u32 = 1 << 16;
const ERROR_IRQ: u32 = 1 << 29;

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
impl Controller {
    fn reset(mmio: MmioRegion) -> bool {
        // SAFETY: exclusively owned, validated ACP 3.x register window.
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
        // Linux rn_acp_power_on: PGFSM status 0 means already on; any
        // other state needs a power-on request unless one is in flight.
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let state = unsafe { mmio.read32(PGFSM_STATUS) };
        if state == u32::MAX {
            return Err(SoundError::NoSuchDevice);
        }
        if state != 0 {
            if state & 3 != 1 {
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe {
                    mmio.write32(PGFSM_CONTROL, 1);
                }
            }
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            if !wait(|| unsafe { mmio.read32(PGFSM_STATUS) } == 0) {
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
            mmio.write32(CLKMUX_SEL, 3);
            mmio.write32(INTR_CONTROL, 0);
            mmio.write32(INTR_ENABLE, 0);
            mmio.write32(INTR_STATUS, u32::MAX);
        }
        Ok(Self {
            mmio,
            irq: State::new(mmio, Kind::Acp3x),
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
                self.mmio.write32(CLKMUX_SEL, 0);
                self.mmio.write32(CONTROL, 0);
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
            mmio.write32(INTR_CONTROL, ERROR_IRQ | PDM_IRQ);
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
/// Probe entry for the ACP 3.x generation. Called from `acp63::probe`'s
/// revision dispatch (the bus match is shared — one PCI id serves both
/// generations); the revision is re-checked here so the entry stays safe
/// to call on its own.
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
    dev.route = Route::new(&device, &cap, dev.irq.clone());
    let dev = Arc::new(dev);
    let info = narf_drivers_sound::CardInfo {
        index: 0,
        driver: "acp3x-pdm",
        id: "ACP3X",
        name: "AMD ACP 3.x Digital Microphone",
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
        name: "acp3x-pdm".into(),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(VENDOR),
        pci_did: Some(DEVICE),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
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
            // PGFSM: a power-on request completes immediately.
            if model.mmio.read32(PGFSM_CONTROL) == 1 && model.mmio.read32(PGFSM_STATUS) != 0 {
                model.mmio.write32(PGFSM_STATUS, 0);
            }
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
        fn new(pgfsm_status: u32) -> Result<Self, SoundError> {
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
            // SAFETY: Fixture owns the fake MMIO window; pre-seed the power state before init runs.
            unsafe {
                mmio.write32(PGFSM_STATUS, pgfsm_status);
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
    fn native_acp3x_pdm_dma_and_failed_stop() -> TestResult {
        let mut fixture = match Fixture::new(0) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP3x init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        // Init conversation on an already-powered block: no PGFSM
        // request, CONTROL set, CLKMUX routed to the PDM clock.
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        unsafe {
            if dev.mmio.read32(PGFSM_CONTROL) != 0
                || dev.mmio.read32(CONTROL) != 1
                || dev.mmio.read32(CLKMUX_SEL) != 3
            {
                return TestResult::Fail("ACP3x init conversation");
            }
        }
        let card = Card(dev.clone());
        let mut pcm = match card.open(true, 0) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("ACP3x open"),
        };
        if card.open(true, 0).is_ok() || card.open(false, 0).is_ok() {
            return TestResult::Fail("ACP3x direction/exclusivity");
        }
        let params = card.default_params(true);
        if pcm.configure(params).is_err() || pcm.prepare().is_err() {
            return TestResult::Fail("ACP3x PCM setup");
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
                || dev.mmio.read32(WATERMARK) != 8192
            {
                return TestResult::Fail("ACP3x ATU/DMA layout");
            }
            dev.mmio.write32(COUNT_HIGH, 1);
            dev.mmio.write32(COUNT_LOW, 0xfffffff0);
        }
        if pcm.start().is_err() {
            return TestResult::Fail("ACP3x start");
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
            return TestResult::Fail("ACP3x 64-bit counter rollover");
        }
        let mut output = [0; 4096];
        if pcm.read(&mut output) != Ok(4096)
            || output != [0x27; 4096]
            || pcm.read(&mut output) != Ok(0)
        {
            return TestResult::Fail("ACP3x completed capture data");
        }
        if pcm.pause(true).is_err() || pcm.pointer() != 512 {
            return TestResult::Fail("ACP3x pause preserves position");
        }
        // SAFETY: this fixture owns the fake counter register window. Model a
        // changed physical count across the stopped interval, then fresh DMA.
        unsafe {
            dev.mmio.write32(COUNT_LOW, 0x1ff0);
        }
        if pcm.pointer() != 512 || pcm.pause(false).is_err() || pcm.pointer() != 512 {
            return TestResult::Fail("ACP3x resume preserves logical baseline");
        }
        // SAFETY: same live fake counter registers as above.
        unsafe {
            dev.mmio.write32(COUNT_LOW, 0x2ff0);
        }
        if pcm.pointer() != 1024 || pcm.reset().is_err() || pcm.read(&mut output) != Ok(0) {
            return TestResult::Fail("ACP3x resumed progress and application reset");
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
    kernel_test_in!("audio/acp3x", native_acp3x_pdm_dma_and_failed_stop);

    fn native_acp3x_power_on_and_overrun() -> TestResult {
        // PGFSM reports powered-off (2): init must issue the power-on
        // request and wait for the status to reach 0.
        let fixture = match Fixture::new(2) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP3x power-on init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        // SAFETY: Fixture owns the fake MMIO/DMA allocations until all test leases are dropped.
        unsafe {
            if dev.mmio.read32(PGFSM_CONTROL) != 1
                || dev.mmio.read32(PGFSM_STATUS) != 0
                || dev.mmio.read32(CLKMUX_SEL) != 3
            {
                return TestResult::Fail("ACP3x PGFSM power-on conversation");
            }
        }
        let card = Card(dev.clone());
        let mut pcm = card.open(true, 0).unwrap();
        if pcm.configure(card.default_params(true)).is_err()
            || pcm.prepare().is_err()
            || pcm.start().is_err()
        {
            return TestResult::Fail("ACP3x capture start");
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
    kernel_test_in!("audio/acp3x", native_acp3x_power_on_and_overrun);
}
