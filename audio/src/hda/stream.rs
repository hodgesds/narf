//! PCM leases with real DMA ownership, backpressure and bounded STOP/drain.
use super::*;
use crate::native_pcm::Ring;
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::Ordering;
use narf_drivers_sound::{
    format::{pack_sdfmt, ChannelCount, HwParams, SampleFormat, SampleRate},
    hardware::{PcmDevice, PcmHardware},
    SoundError,
};

pub(super) fn default_params() -> HwParams {
    HwParams {
        format: SampleFormat::S16LE,
        rate: SampleRate::R48000,
        channels: ChannelCount::Stereo,
        period_size: 1024,
        periods: 4,
    }
}
#[derive(Debug)]
pub(super) struct Stream {
    pub ring: Option<Ring>,
    index: u8,
    capture: bool,
    claimed: bool,
    last_position: u32,
    last_sample: u64,
}
impl Stream {
    pub fn new(index: u8, capture: bool) -> Self {
        Self {
            ring: None,
            index,
            capture,
            claimed: false,
            last_position: 0,
            last_sample: 0,
        }
    }
    fn stop(&mut self, dev: &IntelHda) -> Result<(), SoundError> {
        let sd = sd_base(self.index);
        // SAFETY: stream descriptor is within the validated GCAP register range.
        unsafe {
            dev.bar0.write8(sd, dev.bar0.read8(sd) & !0x1e);
        }
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        if !super::runtime::wait(|| unsafe { dev.bar0.read8(sd) } & 2 == 0, 100) {
            dev.irq.failed.store(true, Ordering::Release);
            return Err(SoundError::BadState);
        }
        if let Some(ring) = self.ring.as_mut() {
            ring.running = false;
            ring.prepared = false;
        }
        Ok(())
    }
    fn configure(&mut self, dev: &IntelHda, params: HwParams) -> Result<(), SoundError> {
        if !matches!(params.format, SampleFormat::S16LE | SampleFormat::S32LE)
            || params.rate != SampleRate::R48000
            || params.channels != ChannelCount::Stereo
        {
            return Err(SoundError::InvalidParams);
        }
        self.stop(dev)?;
        let ring = Ring::new(params)?;
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if unsafe { dev.bar0.read16(REG_GCAP) } & 1 == 0
            && (ring.data.dma_addr().raw() >> 32 != 0 || ring.bdl.dma_addr().raw() >> 32 != 0)
        {
            return Err(SoundError::NoMemory);
        }
        self.ring = Some(ring);
        Ok(())
    }
    fn prepare(&mut self, dev: &IntelHda) -> Result<(), SoundError> {
        self.stop(dev)?;
        if dev.irq.failed.load(Ordering::Acquire) {
            return Err(SoundError::BadState);
        }
        let ring = self.ring.as_mut().ok_or(SoundError::BadState)?;
        let sd = sd_base(self.index);
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        unsafe {
            dev.bar0.write8(sd, 1);
        }
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        if !super::runtime::wait(|| unsafe { dev.bar0.read8(sd) } & 1 != 0, 100) {
            return Err(SoundError::BadState);
        }
        super::runtime::delay_us(3);
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        unsafe {
            dev.bar0.write8(sd, 0);
        }
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        if !super::runtime::wait(|| unsafe { dev.bar0.read8(sd) } & 1 == 0, 100) {
            return Err(SoundError::BadState);
        }
        ring.reset();
        self.last_position = 0;
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        unsafe {
            dev.bar0.write8(sd + SD_STS, 0x1c);
            dev.bar0.write32(sd + SD_CBL, ring.bytes as u32);
            dev.bar0
                .write16(sd + SD_LVI, (ring.params.periods - 1) as u16);
            dev.bar0.write16(
                sd + SD_FMT,
                pack_sdfmt(ring.params.format, ring.params.rate, ring.params.channels),
            );
            dev.bar0
                .write32(sd + SD_BDPL, ring.bdl.dma_addr().raw() as u32);
            dev.bar0
                .write32(sd + SD_BDPU, (ring.bdl.dma_addr().raw() >> 32) as u32);
            // Write the tag byte without touching the adjacent W1C status byte.
            dev.bar0
                .write8(sd + 2, if self.capture { 2 << 4 } else { 1 << 4 });
        }
        Ok(())
    }
    fn start(&mut self, dev: &IntelHda) -> Result<(), SoundError> {
        let ring = self.ring.as_mut().ok_or(SoundError::BadState)?;
        if !ring.prepared
            || ring.running
            || ring.xrun
            || dev.irq.failed.load(Ordering::Acquire)
            || (!self.capture && ring.application == 0)
        {
            return Err(SoundError::BadState);
        }
        let sd = sd_base(self.index);
        self.last_sample = narf_time::now_cycles();
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        unsafe {
            if dev.irq_vector.is_some() {
                // Playback and capture have separate stream locks; serialize
                // their updates to this shared controller enable register.
                let _control = dev.irq_control.lock();
                dev.bar0
                    .write32(REG_INTCTL, dev.bar0.read32(REG_INTCTL) | (1 << self.index));
            }
            dev.bar0.write8(sd, SDCTL_RUN as u8 | 0x1c);
        }
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        if !super::runtime::wait(|| unsafe { dev.bar0.read8(sd) } & 2 != 0, 100) {
            return Err(SoundError::BadState);
        }
        ring.running = true;
        Ok(())
    }
    pub fn update(&mut self, dev: &IntelHda) {
        let Some(ring) = self.ring.as_mut() else {
            return;
        };
        if !ring.running {
            return;
        }
        // SAFETY: Stream lock serializes access; fixed registers lie within the controller's validated mapping.
        let position = unsafe { dev.bar0.read32(sd_base(self.index) + SD_LPIB) };
        let now = narf_time::now_cycles();
        let wrap_ns = ring.bytes as u64 * 1_000_000_000 / (48_000 * ring.frame_bytes as u64);
        if position >= ring.bytes as u32
            || (!ring.free_running
                && now.wrapping_sub(self.last_sample) >= narf_time::wall::ns_to_cycles(wrap_ns))
            || dev.irq.failed.load(Ordering::Acquire)
        {
            ring.xrun = true;
            let _ = self.stop(dev);
            return;
        }
        let mut delta =
            ((position + ring.bytes as u32 - self.last_position) % ring.bytes as u32) as u64;
        if ring.free_running {
            let elapsed = now.wrapping_sub(self.last_sample);
            let wrap_cycles = narf_time::wall::ns_to_cycles(wrap_ns).max(1);
            let expected = (elapsed as u128 * ring.bytes as u128 / wrap_cycles as u128) as u64;
            delta += (expected.saturating_sub(delta) + ring.bytes as u64 / 2) / ring.bytes as u64
                * ring.bytes as u64;
        }
        self.last_position = position;
        self.last_sample = now;
        ring.hardware += delta;
        // Clear retired playback samples before the controller can wrap over them.
        if !self.capture && !ring.free_running {
            for byte in ring.hardware.saturating_sub(delta)..ring.hardware {
                // SAFETY: Only retired playback bytes are cleared; modulo bounds every DMA-buffer offset.
                unsafe {
                    ring.data
                        .cpu_mut_ptr::<u8>()
                        .add((byte % ring.bytes as u64) as usize)
                        .write_volatile(0);
                }
            }
        }
        if (self.capture && ring.hardware.saturating_sub(ring.application) > ring.bytes as u64)
            || (!self.capture && !ring.free_running && ring.hardware >= ring.application)
        {
            // Playback at the queued end is stopped; drain can report completion.
            // A subsequent write requires prepare, avoiding stale cyclic replay.
            ring.xrun = true;
            let _ = self.stop(dev);
        }
    }
}

#[derive(Debug)]
pub(super) struct Card(pub Arc<IntelHda>);
impl PcmDevice for Card {
    fn capabilities(&self, _: bool) -> narf_drivers_sound::hardware::PcmCapabilities {
        use narf_drivers_sound::hardware::PcmCapabilities;
        PcmCapabilities {
            formats: alloc::vec![SampleFormat::S16LE, SampleFormat::S32LE],
            rates: alloc::vec![SampleRate::R48000],
            channels: alloc::vec![ChannelCount::Stereo],
            period_frames: (16, 32768),
            periods: (2, 256),
            buffer_bytes: (4096, 256 * 1024),
            period_byte_alignment: 128,
        }
    }
    fn controls(&self) -> alloc::vec::Vec<narf_drivers_sound::mixer::ControlId> {
        self.0.mixer_controls()
    }
    fn get_control(
        &self,
        id: narf_drivers_sound::mixer::ControlId,
    ) -> Result<narf_drivers_sound::mixer::ControlValue, SoundError> {
        self.0.get_mixer(id)
    }
    fn set_control(
        &self,
        id: narf_drivers_sound::mixer::ControlId,
        value: narf_drivers_sound::mixer::ControlValue,
    ) -> Result<(), SoundError> {
        self.0.set_mixer(id, value)
    }
    fn open(&self, capture: bool, device: u32) -> Result<Box<dyn PcmHardware>, SoundError> {
        if device != 0
            || (capture && self.0.input.is_none())
            || (!capture && self.0.outputs.is_empty())
        {
            return Err(SoundError::NoSuchDevice);
        }
        let mut state = self.0.streams[usize::from(capture)].lock();
        if state.claimed {
            return Err(SoundError::DeviceBusy);
        }
        state.stop(&self.0)?;
        state.ring.take();
        state.claimed = true;
        Ok(Box::new(Pcm {
            dev: self.0.clone(),
            capture,
        }))
    }
}
#[derive(Debug)]
struct Pcm {
    dev: Arc<IntelHda>,
    capture: bool,
}
impl PcmHardware for Pcm {
    fn configure(&mut self, params: HwParams) -> Result<(), SoundError> {
        self.dev.streams[usize::from(self.capture)]
            .lock()
            .configure(&self.dev, params)?;
        if self.dev.configure_paths(self.capture, params).is_err() {
            // configure() stopped the engine; the new BDL has not been
            // published. A failed codec setup must not leave a startable ring.
            self.dev.streams[usize::from(self.capture)]
                .lock()
                .ring
                .take();
            return Err(SoundError::InvalidParams);
        }
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SoundError> {
        self.dev.streams[usize::from(self.capture)]
            .lock()
            .prepare(&self.dev)?;
        if !self.capture {
            self.dev.refresh_jacks().map_err(|_| SoundError::BadState)?;
        }
        Ok(())
    }
    fn start(&mut self) -> Result<(), SoundError> {
        self.dev.streams[usize::from(self.capture)]
            .lock()
            .start(&self.dev)
    }
    fn stop(&mut self) -> Result<(), SoundError> {
        self.dev.streams[usize::from(self.capture)]
            .lock()
            .stop(&self.dev)
    }
    fn pause(&mut self, paused: bool) -> Result<(), SoundError> {
        let mut state = self.dev.streams[usize::from(self.capture)].lock();
        if !paused {
            return state.start(&self.dev);
        }
        state.update(&self.dev);
        let index = state.index;
        // SAFETY: the stream lock owns this validated descriptor. Only RUN
        // is cleared; BDL, position and all buffered samples remain intact.
        unsafe {
            self.dev
                .bar0
                .write8(sd_base(index), self.dev.bar0.read8(sd_base(index)) & !2);
        }
        // SAFETY: same descriptor range and serialization as above.
        if !super::runtime::wait(
            // SAFETY: the validated controller mapping and stream lock remain live.
            || unsafe { self.dev.bar0.read8(sd_base(index)) } & 2 == 0,
            100,
        ) {
            return Err(SoundError::BadState);
        }
        state.ring.as_mut().ok_or(SoundError::BadState)?.running = false;
        Ok(())
    }
    fn reset(&mut self) -> Result<(), SoundError> {
        let mut state = self.dev.streams[usize::from(self.capture)].lock();
        state.update(&self.dev);
        let ring = state.ring.as_mut().ok_or(SoundError::BadState)?;
        ring.application = ring.hardware;
        Ok(())
    }
    fn free_running(&mut self, enabled: bool) -> Result<(), SoundError> {
        self.dev.streams[usize::from(self.capture)]
            .lock()
            .ring
            .as_mut()
            .ok_or(SoundError::BadState)?
            .free_running = enabled;
        Ok(())
    }
    fn overwrite(&mut self, frame: u64, data: &[u8]) -> Result<(), SoundError> {
        if self.capture {
            return Err(SoundError::BadState);
        }
        self.dev.streams[0]
            .lock()
            .ring
            .as_mut()
            .ok_or(SoundError::BadState)?
            .overwrite(frame, data)
    }
    fn pointer(&self) -> u64 {
        let mut state = self.dev.streams[usize::from(self.capture)].lock();
        state.update(&self.dev);
        state
            .ring
            .as_ref()
            .map_or(0, |r| r.hardware / r.frame_bytes as u64)
    }
    fn write(&mut self, data: &[u8]) -> Result<usize, SoundError> {
        if self.capture {
            return Err(SoundError::BadState);
        }
        let mut state = self.dev.streams[0].lock();
        state.update(&self.dev);
        state.ring.as_mut().ok_or(SoundError::BadState)?.write(data)
    }
    fn read(&mut self, data: &mut [u8]) -> Result<usize, SoundError> {
        if !self.capture {
            return Err(SoundError::BadState);
        }
        let mut state = self.dev.streams[1].lock();
        state.update(&self.dev);
        let ring = state.ring.as_mut().ok_or(SoundError::BadState)?;
        let original = ring.application;
        let count = ring.read(data)?;
        state.update(&self.dev);
        let ring = state.ring.as_mut().ok_or(SoundError::BadState)?;
        if ring.xrun || ring.hardware.saturating_sub(original) > ring.bytes as u64 {
            ring.xrun = true;
            let _ = state.stop(&self.dev);
            return Err(SoundError::BadState);
        }
        Ok(count)
    }
    fn drain(&mut self) -> Result<(), SoundError> {
        if self.capture {
            return self.stop();
        }
        let mut error = false;
        let done = super::runtime::wait(
            || {
                let mut state = self.dev.streams[0].lock();
                state.update(&self.dev);
                let Some(ring) = state.ring.as_ref() else {
                    error = true;
                    return true;
                };
                if ring.hardware >= ring.application {
                    return true;
                }
                if ring.xrun || !ring.running {
                    error = true;
                    return true;
                }
                false
            },
            2000,
        );
        self.stop()?;
        if done && !error {
            Ok(())
        } else {
            Err(SoundError::BadState)
        }
    }
}
impl Drop for Pcm {
    fn drop(&mut self) {
        let mut state = self.dev.streams[usize::from(self.capture)].lock();
        if state.stop(&self.dev).is_ok() {
            state.ring.take();
        }
        state.claimed = false;
    }
}

/// Play a complete buffer, observing DMA progress and stopping at its end.
pub fn play_buffer(data: &[u8]) -> Result<usize, SoundError> {
    if data.is_empty() {
        return Ok(0);
    }
    let dev = super::runtime::controller().ok_or(SoundError::NoSuchCard)?;
    let mut stream = Card(dev).open(false, 0)?;
    stream.configure(default_params())?;
    stream.prepare()?;
    let mut written = stream.write(data)?;
    stream.start()?;
    while written < data.len() {
        let mut result = Ok(0);
        let advanced = super::runtime::wait(
            || {
                result = stream.write(&data[written..]);
                !matches!(result, Ok(0))
            },
            1000,
        );
        if !advanced {
            return Err(SoundError::BadState);
        }
        written += result?;
    }
    stream.drain()?;
    Ok(written)
}
impl IntelHda {
    pub fn load_period(&self, samples: &[i16]) -> usize {
        if self.stream_counts().1 == 0 {
            return 0;
        }
        let mut state = self.streams[0].lock();
        if state.claimed || state.stop(self).is_err() {
            return 0;
        }
        if state.configure(self, default_params()).is_err() || state.prepare(self).is_err() {
            return 0;
        }
        drop(state);
        if self.configure_paths(false, default_params()).is_err() {
            return 0;
        }
        let n = samples.len().min(2048) & !1;
        let bytes: alloc::vec::Vec<u8> =
            samples[..n].iter().flat_map(|s| s.to_le_bytes()).collect();
        self.streams[0]
            .lock()
            .ring
            .as_mut()
            .and_then(|r| r.write(&bytes).ok())
            .unwrap_or(0)
            / 2
    }
    /// # Safety
    /// Caller owns the controller; legacy playback must not overlap a PCM lease.
    pub unsafe fn start_output(&self) -> bool {
        if self.stream_counts().1 == 0 {
            return false;
        }
        let mut state = self.streams[0].lock();
        !state.claimed && state.start(self).is_ok()
    }
    /// # Safety
    /// Same ownership requirement as start_output.
    pub unsafe fn stop_output(&self) -> bool {
        if self.stream_counts().1 == 0 {
            return false;
        }
        let mut state = self.streams[0].lock();
        !state.claimed && state.stop(self).is_ok()
    }
    /// # Safety
    /// The controller mapping must be live.
    pub unsafe fn output_position(&self) -> u32 {
        if self.stream_counts().1 == 0 {
            return 0;
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            self.bar0
                .read32(sd_base(self.output_stream_idx()) + SD_LPIB)
        }
    }
    /// # Safety
    /// The controller mapping must be live.
    pub unsafe fn output_running(&self) -> bool {
        self.streams[0]
            .lock()
            .ring
            .as_ref()
            .is_some_and(|r| r.running)
    }
    pub fn load_sine_test_tone(&self, freq: u32) -> usize {
        const SIN: [i16; 16] = [
            0, 6269, 11585, 15136, 16383, 15136, 11585, 6269, 0, -6269, -11585, -15136, -16383,
            -15136, -11585, -6269,
        ];
        let samples: alloc::vec::Vec<i16> = (0..1024)
            .flat_map(|i| {
                let s = SIN[((i as u64 * freq as u64 * 16 / 48000) & 15) as usize];
                [s, s]
            })
            .collect();
        self.load_period(&samples)
    }
    /// # Safety
    /// Caller owns the output controller and intends audible playback.
    pub unsafe fn play_test_tone(&self, freq: u32) -> Result<(), HdaError> {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if self.load_sine_test_tone(freq) == 0 || !unsafe { self.start_output() } {
            return Err(HdaError::NoOutputStream);
        }
        Ok(())
    }
}
