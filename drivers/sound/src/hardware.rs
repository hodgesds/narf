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
        // A byte or integer-array control's element count is its current
        // length (Linux hdmi_eld_ctl_info reports the live ELD size; the
        // channel map has one element per slot).
        let channels = if id.kind.is_bytes() || id.kind == crate::mixer::ControlKind::ChannelMap {
            match self.get_control(id)? {
                crate::mixer::ControlValue::Bytes { len, .. }
                | crate::mixer::ControlValue::Integers { len, .. } => len,
                _ => 0,
            }
        } else if id.kind.is_boolean() || id.kind.is_iec958() {
            1
        } else {
            2
        };
        let (value_max, step) = match id.kind {
            k if k.is_bytes() || k.is_iec958() => (0, 0),
            // SNDRV_CHMAP_LAST; Linux hdmi_chmap_ctl_info leaves the step 0.
            crate::mixer::ControlKind::ChannelMap => (36, 0),
            k if k.is_boolean() => (1, 1),
            _ => (87, 1),
        };
        Ok(crate::mixer::ControlInfo {
            id,
            name: id.kind.name(),
            value_min: 0,
            value_max,
            step,
            channels,
            is_boolean: id.kind.is_boolean(),
            is_read_only: id.kind.is_read_only(),
        })
    }
    /// The TLV words of a control whose kind `has_tlv`, container header
    /// included, computed at read time like a Linux TLV callback.
    fn control_tlv(&self, _: crate::mixer::ControlId) -> Result<alloc::vec::Vec<u32>, SoundError> {
        Err(SoundError::NoSuchControl)
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
    /// The hardware pointer moves in whole transfer blocks (e.g. VirtIO
    /// message completions) rather than per frame. ALSA reports
    /// `SNDRV_PCM_INFO_BATCH | SNDRV_PCM_INFO_BLOCK_TRANSFER` so PipeWire
    /// and PulseAudio keep an extra period of headroom.
    pub batch: bool,
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
            batch: false,
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
