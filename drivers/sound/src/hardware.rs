//! Hardware backends for the PCM card registry. The stream owns its DMA until
//! the device has acknowledged STOP; a failed stop must retain that storage.

use crate::{format::HwParams, SoundError};
use alloc::boxed::Box;

/// One independently claimable PCM endpoint on a physical card.
pub trait PcmDevice: Send + Sync + core::fmt::Debug {
    fn control_info(
        &self,
        id: crate::mixer::ControlId,
    ) -> Result<crate::mixer::ControlInfo, SoundError> {
        if !self.controls().contains(&id) {
            return Err(SoundError::NoSuchControl);
        }
        Ok(crate::mixer::ControlInfo {
            id,
            name: id.kind.name(),
            value_min: 0,
            value_max: if id.kind.is_boolean() { 1 } else { 87 },
            step: 1,
            channels: if id.kind.is_boolean() { 1 } else { 2 },
            is_boolean: id.kind.is_boolean(),
            is_read_only: id.kind.is_read_only(),
        })
    }
    /// Side-effect-free constraints for ALSA parameter negotiation. Backends
    /// override this to describe every supported hardware configuration.
    fn capabilities(&self, capture: bool) -> PcmCapabilities {
        PcmCapabilities::fixed(self.default_params(capture))
    }
    fn controls(&self) -> alloc::vec::Vec<crate::mixer::ControlId> {
        alloc::vec::Vec::new()
    }
    fn get_control(
        &self,
        _: crate::mixer::ControlId,
    ) -> Result<crate::mixer::ControlValue, SoundError> {
        Err(SoundError::NoSuchControl)
    }
    fn set_control(
        &self,
        _: crate::mixer::ControlId,
        _: crate::mixer::ControlValue,
    ) -> Result<(), SoundError> {
        Err(SoundError::NoSuchControl)
    }
    fn default_params(&self, _capture: bool) -> HwParams {
        use crate::format::{ChannelCount, SampleFormat, SampleRate};
        HwParams {
            format: SampleFormat::S16LE,
            rate: SampleRate::R48000,
            channels: ChannelCount::Stereo,
            period_size: 1024,
            periods: 4,
        }
    }
    fn open(&self, capture: bool, device: u32) -> Result<Box<dyn PcmHardware>, SoundError>;
}

/// Finite format/rate/channel sets plus integer DMA geometry constraints.
#[derive(Clone, Debug)]
pub struct PcmCapabilities {
    pub formats: alloc::vec::Vec<crate::format::SampleFormat>,
    pub rates: alloc::vec::Vec<crate::format::SampleRate>,
    pub channels: alloc::vec::Vec<crate::format::ChannelCount>,
    pub period_frames: (u32, u32),
    pub periods: (u32, u32),
    pub buffer_bytes: (u32, u32),
    pub period_byte_alignment: u32,
}

impl PcmCapabilities {
    pub fn fixed(params: HwParams) -> Self {
        Self {
            formats: alloc::vec![params.format],
            rates: alloc::vec![params.rate],
            channels: alloc::vec![params.channels],
            period_frames: (params.period_size, params.period_size),
            periods: (params.periods, params.periods),
            buffer_bytes: (params.buffer_bytes() as u32, params.buffer_bytes() as u32),
            period_byte_alignment: 1,
        }
    }
}

/// Exclusive stream lease. Implementations quiesce DMA in Drop.
pub trait PcmHardware: Send + core::fmt::Debug {
    fn configure(&mut self, params: HwParams) -> Result<(), SoundError>;
    fn prepare(&mut self) -> Result<(), SoundError>;
    fn start(&mut self) -> Result<(), SoundError>;
    fn stop(&mut self) -> Result<(), SoundError>;
    fn pointer(&self) -> u64;
    fn write(&mut self, samples: &[u8]) -> Result<usize, SoundError>;
    fn read(&mut self, out: &mut [u8]) -> Result<usize, SoundError>;
    fn drain(&mut self) -> Result<(), SoundError>;
    /// Freeze/restart DMA without discarding queued samples or frame position.
    /// Backends whose STOP preserves their queue can use this default.
    fn pause(&mut self, paused: bool) -> Result<(), SoundError> {
        if paused {
            self.stop()
        } else {
            self.start()
        }
    }
    /// Discard queued application frames without stopping DMA or changing position.
    fn reset(&mut self) -> Result<(), SoundError> {
        Ok(())
    }
    /// Allow the ALSA layer to own underrun policy for cyclic playback.
    fn free_running(&mut self, _enabled: bool) -> Result<(), SoundError> {
        Ok(())
    }
    /// Refresh already-submitted playback slots. The offset is an absolute
    /// frame position; implementations wrap it by their buffer capacity.
    fn overwrite(&mut self, _frame: u64, _samples: &[u8]) -> Result<(), SoundError> {
        Err(SoundError::InvalidParams)
    }
}
