//! The shared sound-card interface for the implemented VirtIO playback stream.
use super::{PcmParams, ReqGate, VirtioSoundPci};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::Ordering;
use narf_drivers_sound::{
    format::{ChannelCount, HwParams, SampleFormat, SampleRate},
    hardware::{PcmDevice, PcmHardware},
    SoundError,
};

#[derive(Debug)]
pub(super) struct Card(pub Arc<VirtioSoundPci>);

impl PcmDevice for Card {
    fn default_params(&self, _capture: bool) -> HwParams {
        let info = self
            .0
            .playback_info
            .expect("registered playback card has PCM_INFO");
        HwParams {
            format: SampleFormat::S16LE,
            rate: if info.rates & (1 << super::VIRTIO_SND_PCM_RATE_48000) != 0 {
                SampleRate::R48000
            } else {
                SampleRate::R44100
            },
            channels: if info.channels_max >= 2 {
                ChannelCount::Stereo
            } else {
                ChannelCount::Mono
            },
            period_size: 1024,
            periods: 4,
        }
    }

    fn open(&self, capture: bool, device: u32) -> Result<Box<dyn PcmHardware>, SoundError> {
        if capture || device != 0 || self.0.cfg.streams == 0 {
            return Err(SoundError::NoSuchDevice);
        }
        let _gate = ReqGate::acquire(&self.0.req_gate);
        if self.0.failed.load(Ordering::Acquire) {
            return Err(SoundError::BadState);
        }
        if self.0.claimed.swap(true, Ordering::AcqRel) {
            return Err(SoundError::DeviceBusy);
        }
        if self.0.stop_pcm_locked().is_err() {
            self.0.claimed.store(false, Ordering::Release);
            return Err(SoundError::BadState);
        }
        Ok(Box::new(Playback {
            device: self.0.clone(),
            params: None,
            pending: Vec::new(),
            prepared: false,
            running: false,
            frames: 0,
        }))
    }
}

#[derive(Debug)]
struct Playback {
    device: Arc<VirtioSoundPci>,
    params: Option<PcmParams>,
    pending: Vec<u8>,
    prepared: bool,
    running: bool,
    frames: u64,
}

fn params(params: HwParams) -> Result<PcmParams, SoundError> {
    if params.format != SampleFormat::S16LE
        || !matches!(params.channels, ChannelCount::Mono | ChannelCount::Stereo)
        || params.period_size == 0
        || !(2..=256).contains(&params.periods)
        || params.buffer_bytes() > 256 * 1024
    {
        return Err(SoundError::InvalidParams);
    }
    let rate = match params.rate {
        SampleRate::R44100 => super::VIRTIO_SND_PCM_RATE_44100,
        SampleRate::R48000 => super::VIRTIO_SND_PCM_RATE_48000,
        _ => return Err(SoundError::InvalidParams),
    };
    Ok(PcmParams {
        buffer_bytes: params.buffer_bytes() as u32,
        period_bytes: params.period_bytes() as u32,
        channels: params.channels.count(),
        format: super::VIRTIO_SND_PCM_FMT_S16,
        rate,
    })
}

impl Playback {
    fn submit_pending(&mut self) -> Result<(), SoundError> {
        let params = self.params.ok_or(SoundError::BadState)?;
        let frame_bytes = usize::from(params.channels) * 2;
        let _gate = ReqGate::acquire(&self.device.req_gate);
        // Keep both scratch and stream configuration exclusive for the entire
        // submission. All samples are copied to controller-owned coherent DMA.
        for chunk in self.pending.chunks(4024 / frame_bytes * frame_bytes) {
            self.device
                .play_buffer_locked(params, chunk)
                .map_err(|_| SoundError::BadState)?;
            self.frames += (chunk.len() / frame_bytes) as u64;
        }
        self.pending.clear();
        Ok(())
    }
}

impl PcmHardware for Playback {
    fn configure(&mut self, requested: HwParams) -> Result<(), SoundError> {
        if self.running {
            return Err(SoundError::BadState);
        }
        let params = params(requested)?;
        if !self
            .device
            .playback_info
            .is_some_and(|info| info.supports(params))
        {
            return Err(SoundError::InvalidParams);
        }
        self.params = Some(params);
        self.pending.clear();
        self.prepared = false;
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SoundError> {
        if self.params.is_none() || self.running || self.device.failed.load(Ordering::Acquire) {
            return Err(SoundError::BadState);
        }
        self.pending.clear();
        self.frames = 0;
        self.prepared = true;
        Ok(())
    }
    fn start(&mut self) -> Result<(), SoundError> {
        if !self.prepared || self.running {
            return Err(SoundError::BadState);
        }
        self.submit_pending()?;
        self.running = true;
        Ok(())
    }
    fn stop(&mut self) -> Result<(), SoundError> {
        let _gate = ReqGate::acquire(&self.device.req_gate);
        self.device
            .stop_pcm_locked()
            .map_err(|_| SoundError::BadState)?;
        self.running = false;
        self.pending.clear();
        Ok(())
    }
    fn pointer(&self) -> u64 {
        self.frames
    }
    fn write(&mut self, samples: &[u8]) -> Result<usize, SoundError> {
        if !self.prepared {
            return Err(SoundError::BadState);
        }
        let params = self.params.ok_or(SoundError::BadState)?;
        let frame_bytes = usize::from(params.channels) * 2;
        if samples.len() % frame_bytes != 0 {
            return Err(SoundError::InvalidParams);
        }
        let count = samples
            .len()
            .min(params.buffer_bytes as usize - self.pending.len());
        self.pending.extend_from_slice(&samples[..count]);
        if self.running {
            self.submit_pending()?;
        }
        Ok(count)
    }
    fn read(&mut self, _: &mut [u8]) -> Result<usize, SoundError> {
        Err(SoundError::BadState)
    }
    fn drain(&mut self) -> Result<(), SoundError> {
        if !self.prepared {
            return Err(SoundError::BadState);
        }
        self.submit_pending()?;
        self.stop()
    }
}

impl Drop for Playback {
    fn drop(&mut self) {
        let _gate = ReqGate::acquire(&self.device.req_gate);
        let _ = self.device.stop_pcm_locked();
        self.device.claimed.store(false, Ordering::Release);
    }
}
