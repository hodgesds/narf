//! Phoenix ACP 6.3 PDM capture, native (no DSP firmware).
//! References: Linux sound/soc/amd/ps/{pci-ps,ps-common,ps-pdm-dma}.c
//! and include/sound/acp63_chip_offset_byte.h. SoundWire-only configurations
//! are left unbound; HDA remains an independent PCI function.
use crate::{
    native_irq::{Kind, Route, State},
    native_pcm::Ring,
};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};
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
/// ACP DMA channel block, shared with the SDW DMA engine in
/// `crate::acp63_sdw_dma` (the SDW binding owns the function
/// exclusively when it binds, so the channel is free for its stream).
/// Offsets as in Linux `include/sound/acp63_chip_offset_byte.h`, the
/// same header the PDM path's constants come from.
pub(crate) const DMA_ENABLE: u64 = 0x2c08;
pub(crate) const RING_ADDR: u64 = 0x2c0c;
pub(crate) const RING_SIZE: u64 = 0x2c10;
pub(crate) const COUNT_HIGH: u64 = 0x2c18;
pub(crate) const COUNT_LOW: u64 = 0x2c1c;
pub(crate) const WATERMARK: u64 = 0x2c20;
const FIFO_FLUSH: u64 = 0x2c24;
const CHANNELS: u64 = 0x2c28;
const DECIMATION: u64 = 0x2c2c;
const CLOCK: u64 = 0x2c60;
const MISC: u64 = 0x2c5c;
pub(crate) const ATU_PAGE_SIZE: u64 = 0xc00;
pub(crate) const ATU_BASE: u64 = 0xc04;
pub(crate) const ATU_CONTROL: u64 = 0xc40;
pub(crate) const SCRATCH: u64 = 0x10000;
pub(crate) const DMA_WINDOW: u32 = 0x4000000;
pub(crate) const PTE_BASE: u32 = 0x03800000;
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
    /// Power-management park flag (#779): set by quiesce once the
    /// capture engine is stopped and IRQs are off, cleared by
    /// reinit. The PCM bring-up paths reinit when they see it set;
    /// the service loop skips work while it is set.
    suspended: AtomicBool,
    /// Software capture gain, left/right in 0..87 ALSA-style units
    /// (87 = unity). The PDM blocks expose no hardware gain stage
    /// in-tree, so the card scales samples in `Pcm::read` instead of
    /// programming an ungrounded register.
    capture_volume: IrqSafeSpinLock<(u8, u8)>,
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
    /// Block power-up + reset sequence shared by `init` and
    /// `reinit` (#779): power the block up if its status says
    /// otherwise, enable the block, reset it, and leave IRQs off.
    /// The power-down direction is deliberately NOT written here:
    /// the ACP power register semantics are not pinned by an
    /// in-tree source, and guessing a power-down value could wedge
    /// the block. Real power saving comes from the PCI D3hot move
    /// in the runtime-PM wrapper (follow-up) and platform S3.
    fn power_up_and_reset(mmio: MmioRegion) -> Result<(), SoundError> {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let state = unsafe { mmio.read32(POWER_STATUS) };
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
        Ok(())
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
        Self::power_up_and_reset(mmio)?;
        Ok(Self {
            mmio,
            irq: State::new(mmio, Kind::Acp),
            route: None,
            capture: IrqSafeSpinLock::new(Capture::default()),
            suspended: AtomicBool::new(false),
            capture_volume: IrqSafeSpinLock::new((87, 87)),
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

    // ── Power management (#779) ──────────────────────────────────
    // Same two layers as HDA (see `hda::runtime`): system PM via
    // `AcpSystemPm` registered at probe, runtime PM via
    // `AcpRuntimePm` over this core, fixture-proven directly with
    // `block_on_spin` (the generic `PciRuntimePm` wrapper around
    // the same trait is proven by the HDA test). Production probe
    // registration of the PCI node is the same follow-up as HDA
    // (PCM start is sync and cannot await a framework resume).
    // The live idle path is the PCM stop hook below: engine
    // stopped, IRQs off, PCI stays D0.
    // There is no codec verb here: PDM capture has no codec, and
    // the SDW manager on this function is a separate binding with
    // its own quiesce still to land — PDM and SDW probes are
    // mutually exclusive, so the SDW case never shares this
    // controller, and leaving it unregistered preserves today's
    // behavior for it rather than suspending under a live manager.

    /// True when no capture can move samples: no ring, or a ring
    /// that is neither running nor prepared. A prepared-but-idle
    /// ring still blocks quiesce, for the same BDL-staleness reason
    /// as HDA: its ATU programming would go stale across a reset.
    fn capture_idle(&self) -> bool {
        let state = self.capture.lock();
        state
            .ring
            .as_ref()
            .is_none_or(|r| !r.running && !r.prepared)
    }

    /// Power-management quiesce: stop the capture engine, IRQs
    /// off, park flag set. Idempotent. Refuses with BadState when
    /// capture is running or prepared; the owner must stop it
    /// first — suspend never discards capture state. No ACP power
    /// register is written: the power-down direction is not pinned
    /// by an in-tree source (see `power_up_and_reset`).
    fn quiesce(&self) -> Result<(), SoundError> {
        if self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut state = self.capture.lock();
        if state.ring.as_ref().is_some_and(|r| r.running || r.prepared) {
            return Err(SoundError::BadState);
        }
        self.stop(&mut state)?;
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        unsafe {
            self.mmio.write32(INTR_ENABLE, 0);
        }
        self.suspended.store(true, Ordering::Release);
        Ok(())
    }

    /// Reverse of quiesce: restore the block to its post-`init`
    /// baseline (power-up, enable, reset, IRQs off) and clear the
    /// sticky IRQ failure: the reset re-establishes the block, so
    /// a pre-suspend engine failure must not poison post-resume
    /// starts. Stream state is NOT restored: suspend refused
    /// running or prepared capture, so capture needs a fresh
    /// prepare after resume. Idempotent.
    fn reinit(&self) -> Result<(), SoundError> {
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        Self::power_up_and_reset(self.mmio)?;
        self.irq.failed.store(false, Ordering::Release);
        self.suspended.store(false, Ordering::Release);
        Ok(())
    }

    /// PCM bring-up entry: reinit a parked block before any path
    /// that programs the capture engine.
    fn ensure_active(&self) -> Result<(), SoundError> {
        self.reinit()
    }

    /// Best-effort idle transition for the PCM stop path: quiesce
    /// when capture is stopped, ignore failures (the next stop
    /// retries; the block simply stays powered).
    fn maybe_idle_quiesce(&self) {
        if self.suspended.load(Ordering::Acquire) || !self.capture_idle() {
            return;
        }
        let _ = self.quiesce();
    }
}

/// System-PM ops for the ACP 6.3 PDM controller (#779). The
/// device_pm registry holds one entry per name; the single
/// CONTROLLER static is fanned out here. Suspend refuses (Busy)
/// while capture is running or prepared; resume restores the
/// post-`init` baseline.
struct AcpSystemPm;
impl narf_power::device_pm::DevicePmOps for AcpSystemPm {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        use narf_power::device_pm::DeviceSuspendError as E;
        let dev = CONTROLLER.lock().as_ref().map(|(dev, _)| dev.clone());
        if let Some(dev) = dev {
            // Precise reason: a running or prepared capture is
            // Busy; a quiesce failure (engine will not stop) is a
            // driver error. Either way S3 aborts.
            if !dev.capture_idle() {
                return Err(E::Busy);
            }
            dev.quiesce().map_err(|_| E::DriverError)?;
        }
        Ok(())
    }

    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        use narf_power::device_pm::DeviceSuspendError as E;
        let dev = CONTROLLER.lock().as_ref().map(|(dev, _)| dev.clone());
        if let Some(dev) = dev {
            dev.reinit().map_err(|_| E::DriverError)?;
        }
        Ok(())
    }
}

/// Runtime-PM ops for one ACP 6.3 PDM controller (#779). The core
/// is synchronous (see above), so the async callbacks simply run
/// it; the PCI D3hot move belongs to the `PciRuntimePm` wrapper.
/// Constructed by kernel tests today; production probe
/// registration is the same follow-up as HDA (it needs an
/// async-aware PCM start path), so the non-test build does not
/// construct it yet.
#[allow(dead_code)]
struct AcpRuntimePm {
    dev: Arc<Controller>,
}
impl narf_power::runtime_pm::RuntimePmOps for AcpRuntimePm {
    fn runtime_suspend(&self) -> narf_power::runtime_pm::RpmFuture<'_> {
        let dev = self.dev.clone();
        Box::pin(async move {
            dev.quiesce()
                .map_err(|_| narf_power::runtime_pm::RpmError::Failed)
        })
    }

    fn runtime_resume(&self) -> narf_power::runtime_pm::RpmFuture<'_> {
        let dev = self.dev.clone();
        Box::pin(async move {
            dev.reinit()
                .map_err(|_| narf_power::runtime_pm::RpmError::Failed)
        })
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
/// Scale `count` bytes of S32LE stereo samples in place by the
/// per-channel 0..87 gains (87 = unity, exact passthrough; 0 =
/// silence). The product is computed in i64 and clamped to i32;
/// with gains ≤ 87 the result never exceeds the input magnitude,
/// so the clamp is defense only. Shared by the ACP 3.x and 6.3
/// cards, whose PDM paths are both S32LE.
pub(crate) fn scale_capture_samples(buf: &mut [u8], count: usize, left: u8, right: u8) {
    if left == 87 && right == 87 {
        return;
    }
    let count = count.min(buf.len()) / 4 * 4;
    for (index, sample) in buf[..count].chunks_exact_mut(4).enumerate() {
        let value = i32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
        let gain = if index % 2 == 0 { left } else { right };
        let scaled =
            (value as i64 * gain as i64 / 87).clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        sample.copy_from_slice(&scaled.to_le_bytes());
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
    fn controls(&self) -> alloc::vec::Vec<narf_drivers_sound::mixer::ControlId> {
        alloc::vec![narf_drivers_sound::mixer::ControlId {
            index: 0,
            kind: narf_drivers_sound::mixer::ControlKind::CaptureVolume,
        }]
    }
    fn get_control(
        &self,
        id: narf_drivers_sound::mixer::ControlId,
    ) -> Result<narf_drivers_sound::mixer::ControlValue, SoundError> {
        if !self.controls().contains(&id) {
            return Err(SoundError::NoSuchControl);
        }
        let (left, right) = *self.0.capture_volume.lock();
        Ok(narf_drivers_sound::mixer::ControlValue::integer(
            left as i32,
            right as i32,
        ))
    }
    fn set_control(
        &self,
        id: narf_drivers_sound::mixer::ControlId,
        value: narf_drivers_sound::mixer::ControlValue,
    ) -> Result<(), SoundError> {
        use narf_drivers_sound::mixer::{ControlKind, ControlValue};
        if !self.controls().contains(&id) {
            return Err(SoundError::NoSuchControl);
        }
        match (id.kind, value) {
            (ControlKind::CaptureVolume, ControlValue::Integer { left, right })
                if (0..=87).contains(&left) && (0..=87).contains(&right) =>
            {
                *self.0.capture_volume.lock() = (left as u8, right as u8);
                Ok(())
            }
            _ => Err(SoundError::OutOfRange),
        }
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
        // A parked block cannot program the capture engine.
        self.0.ensure_active()?;
        let ring = Ring::new(params)?;
        let mut state = self.0.capture.lock();
        self.0.stop(&mut state)?;
        state.ring = Some(ring);
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SoundError> {
        // A parked block cannot program the capture engine.
        self.0.ensure_active()?;
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
        // A parked block cannot program the capture engine.
        self.0.ensure_active()?;
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
        self.0.stop(&mut self.0.capture.lock())?;
        // Last stop parks the block (best-effort idle, #779).
        self.0.maybe_idle_quiesce();
        Ok(())
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
        // Software capture gain: the PDM block has no hardware gain
        // stage, so the card's CaptureVolume scales the copied
        // samples. Unity (87, 87) is an exact passthrough.
        let (left, right) = *self.0.capture_volume.lock();
        scale_capture_samples(out, count, left, right);
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
/// ACP generation behind the shared 1022:15e2 PCI id. The bus match
/// is registered once (this module's `register_pci_driver`); the PCI
/// revision selects the register map, exactly as Linux splits
/// snd_pci_ps (6.x) from rn-pci-acp3x (3.x) on the same device id.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Generation {
    Acp3x,
    Acp63,
}
pub(crate) fn generation(revision: u8) -> Option<Generation> {
    match revision {
        REVISION => Some(Generation::Acp63),
        crate::acp3x::REVISION => Some(Generation::Acp3x),
        _ => None,
    }
}
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    use narf_bus::ProbeError;
    let revision =
        narf_bus::pci::read_config32(&cap, &device, 8).map_err(|_| ProbeError::BadDevice)? as u8;
    if device.id.vendor != VENDOR || device.id.device != DEVICE || device.id.class != 0x048000 {
        return Err(ProbeError::NotForThisDriver);
    }
    match generation(revision) {
        Some(Generation::Acp63) => probe_63(device, cap),
        Some(Generation::Acp3x) => crate::acp3x::probe(device, cap),
        None => Err(ProbeError::NotForThisDriver),
    }
}
fn probe_63(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
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
    // Compose SoundWire alongside PDM when the function is wired for
    // both (#871): the manager init + enumeration runs on the block
    // this probe already powered, and any codecs found are published
    // as SDW cards next to the PDM capture card. Failure here is not
    // a PDM error — it just means PDM-only, exactly as before — so
    // the result is deliberately swallowed.
    let _ = crate::acp63_sdw::bind_composed(dev.mmio, device.addr);
    let weak = Arc::downgrade(&dev);
    narf_scheduler::spawn(async move {
        loop {
            narf_time::SleepUntil::new(Deadline::after_ms(2).as_instant()).await;
            let Some(dev) = weak.upgrade() else {
                break;
            };
            if !dev.suspended.load(Ordering::Acquire) {
                dev.irq.service();
                dev.update(&mut dev.capture.lock());
            }
        }
    });
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: "acp63-pdm".into(),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(VENDOR),
        pci_did: Some(DEVICE),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    // System power management (#779): one registry entry for the
    // single PDM controller. Registration is idempotent on the
    // name, so re-probe is safe.
    narf_power::device_pm::register_device_pm_ops("acp63-pdm", Arc::new(AcpSystemPm));
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

    fn native_acp_generation_dispatch() -> TestResult {
        // The shared PCI id dispatches on revision only: 0x63 is the
        // Phoenix ACP 6.3 map, 0x01 the Renoir ACP 3.x map, and every
        // other revision (including the 6.0/6.2 silicon this driver
        // does not implement) stays unbound.
        if generation(0x63) != Some(Generation::Acp63)
            || generation(0x01) != Some(Generation::Acp3x)
            || generation(0x00).is_some()
            || generation(0x60).is_some()
            || generation(0x62).is_some()
            || generation(0x64).is_some()
        {
            return TestResult::Fail("ACP generation dispatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63", native_acp_generation_dispatch);

    // ── Power management (#779) ──────────────────────────────

    fn native_acp63_pm_quiesce_reinit_parks_and_restores() -> TestResult {
        let fixture = match Fixture::new() {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        if dev.quiesce().is_err() {
            return TestResult::Fail("quiesce idle block");
        }
        // SAFETY: Fixture owns the fake MMIO until all test leases drop.
        let intr_enable = unsafe { dev.mmio.read32(INTR_ENABLE) };
        if !dev.suspended.load(Ordering::Acquire) || intr_enable != 0 {
            return TestResult::Fail("quiesce parks and gates IRQs");
        }
        // Idempotent: a second quiesce is Ok and changes nothing.
        if dev.quiesce().is_err() || !dev.suspended.load(Ordering::Acquire) {
            return TestResult::Fail("quiesce idempotent");
        }
        if dev.reinit().is_err() {
            return TestResult::Fail("reinit parked block");
        }
        // SAFETY: Fixture owns the fake MMIO until all test leases drop.
        let (control, intr_control, intr_enable, intr_status) = unsafe {
            (
                dev.mmio.read32(CONTROL),
                dev.mmio.read32(INTR_CONTROL),
                dev.mmio.read32(INTR_ENABLE),
                dev.mmio.read32(INTR_STATUS),
            )
        };
        if dev.suspended.load(Ordering::Acquire)
            || control != 1
            || intr_control != 0
            || intr_enable != 0
            || intr_status != u32::MAX
        {
            return TestResult::Fail("reinit restores the post-init baseline");
        }
        if dev.reinit().is_err() || dev.suspended.load(Ordering::Acquire) {
            return TestResult::Fail("reinit idempotent");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "audio/acp63",
        native_acp63_pm_quiesce_reinit_parks_and_restores
    );

    fn native_acp63_pm_busy_while_capture_runs_or_prepared() -> TestResult {
        let fixture = match Fixture::new() {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        let card = Card(dev.clone());
        let mut pcm = match card.open(true, 0) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("ACP open"),
        };
        if pcm.configure(card.default_params(true)).is_err() || pcm.prepare().is_err() {
            return TestResult::Fail("ACP PCM setup");
        }
        // Prepared-but-idle still blocks quiesce: the ATU window is
        // programmed and would go stale across a reset.
        if dev.quiesce().is_ok() {
            return TestResult::Fail("quiesce must refuse prepared capture");
        }
        if pcm.start().is_err() {
            return TestResult::Fail("ACP capture start");
        }
        if dev.quiesce().is_ok() {
            return TestResult::Fail("quiesce must refuse running capture");
        }
        // Layer 1: the PCM stop path parks the block itself.
        if pcm.stop().is_err() || !dev.suspended.load(Ordering::Acquire) {
            return TestResult::Fail("stop parks the block");
        }
        // And the next start transparently re-inits it.
        if pcm.configure(card.default_params(true)).is_err()
            || pcm.prepare().is_err()
            || pcm.start().is_err()
            || dev.suspended.load(Ordering::Acquire)
        {
            return TestResult::Fail("start re-inits a parked block");
        }
        if pcm.stop().is_err() || !dev.suspended.load(Ordering::Acquire) {
            return TestResult::Fail("second stop re-parks the block");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "audio/acp63",
        native_acp63_pm_busy_while_capture_runs_or_prepared
    );

    fn native_acp63_pm_system_fanout_suspends_and_resumes() -> TestResult {
        let _pm = narf_power::device_pm::__test_isolate_registry();
        let fixture = match Fixture::new() {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        // Restore the controller static on every exit, including
        // early failure returns: other smokes share this global.
        struct ControllerGuard {
            old: Option<(Arc<Controller>, u32)>,
        }
        impl Drop for ControllerGuard {
            fn drop(&mut self) {
                *CONTROLLER.lock() = self.old.take();
            }
        }
        let _cguard = ControllerGuard {
            old: CONTROLLER.lock().clone(),
        };
        *CONTROLLER.lock() = Some((dev.clone(), 0));
        narf_power::device_pm::register_device_pm_ops("acp63-pdm", Arc::new(AcpSystemPm));
        if !narf_power::device_pm::suspend_all_devices().ok()
            || !dev.suspended.load(Ordering::Acquire)
        {
            return TestResult::Fail("fanout suspend parks the block");
        }
        if !narf_power::device_pm::resume_all_devices().ok()
            || dev.suspended.load(Ordering::Acquire)
        {
            return TestResult::Fail("fanout resume re-inits the block");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "audio/acp63",
        native_acp63_pm_system_fanout_suspends_and_resumes
    );

    fn native_acp63_pm_runtime_ops() -> TestResult {
        use narf_power::runtime_pm::RuntimePmOps;
        let fixture = match Fixture::new() {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        let ops = AcpRuntimePm { dev: dev.clone() };
        if narf_scheduler::block_on_spin(ops.runtime_suspend()).is_err()
            || !dev.suspended.load(Ordering::Acquire)
        {
            return TestResult::Fail("runtime suspend parks the block");
        }
        if narf_scheduler::block_on_spin(ops.runtime_resume()).is_err()
            || dev.suspended.load(Ordering::Acquire)
        {
            return TestResult::Fail("runtime resume re-inits the block");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63", native_acp63_pm_runtime_ops);

    fn native_acp63_software_capture_gain() -> TestResult {
        // Unity (87, 87) is an exact passthrough, including extremes.
        let mut buf = [
            0x00, 0x00, 0x00, 0x40, // 0x40000000
            0x00, 0x00, 0x00, 0xC0, // -0x40000000
            0xFF, 0xFF, 0xFF, 0x7F, // i32::MAX
        ];
        scale_capture_samples(&mut buf, 12, 87, 87);
        if buf
            != [
                0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xC0, 0xFF, 0xFF, 0xFF, 0x7F,
            ]
        {
            return TestResult::Fail("unity gain must pass samples through exactly");
        }
        // Channels scale independently: left silenced, right at 43.
        scale_capture_samples(&mut buf, 12, 0, 43);
        let right = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let expected = (-0x40000000i64 * 43 / 87) as i32;
        if buf[0..4] != [0, 0, 0, 0] || right != expected || buf[8..12] != [0, 0, 0, 0] {
            return TestResult::Fail("per-channel software gain");
        }
        // A trailing partial sample is never touched.
        let mut tail = [0x00, 0x00, 0x00, 0x40, 0xAA, 0xBB];
        scale_capture_samples(&mut tail, 6, 0, 0);
        if tail != [0, 0, 0, 0, 0xAA, 0xBB] {
            return TestResult::Fail("partial trailing sample untouched");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63", native_acp63_software_capture_gain);

    fn native_acp63_capture_volume_control() -> TestResult {
        use narf_drivers_sound::mixer::{ControlId, ControlKind, ControlValue};
        let fixture = match Fixture::new() {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("ACP init"),
        };
        let dev = fixture.dev.as_ref().unwrap().clone();
        let card = Card(dev);
        let id = ControlId {
            index: 0,
            kind: ControlKind::CaptureVolume,
        };
        if !card.controls().contains(&id)
            || card.get_control(id) != Ok(ControlValue::integer(87, 87))
            || card.set_control(id, ControlValue::integer(10, 20)).is_err()
            || card.get_control(id) != Ok(ControlValue::integer(10, 20))
            || card.set_control(id, ControlValue::integer(88, 0)).is_ok()
            || card
                .set_control(
                    ControlId {
                        index: 1,
                        kind: ControlKind::MasterVolume,
                    },
                    ControlValue::integer(10, 10),
                )
                .is_ok()
        {
            return TestResult::Fail("ACP capture volume control round-trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp63", native_acp63_capture_volume_control);
}
