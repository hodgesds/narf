//! Hardware backends for the PCM card registry. The stream owns its DMA until
//! the device has acknowledged STOP; a failed stop must retain that storage.

use crate::{format::HwParams, SoundError};
use alloc::boxed::Box;

/// One independently claimable PCM endpoint on a physical card.
pub trait PcmDevice: Send + Sync + core::fmt::Debug {
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
}
