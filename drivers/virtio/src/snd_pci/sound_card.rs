//! The shared sound-card interface for the implemented VirtIO playback stream.
use super::{PcmParams, ReqGate, VirtioSoundPci, VIRTIO_SND_S_OK};
use crate::queue::{VirtqDesc, VIRTQ_DESC_F_WRITE};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use core::sync::atomic::{compiler_fence, Ordering};
use narf_drivers_sound::{
    format::{ChannelCount, HwParams, SampleFormat, SampleRate},
    hardware::{PcmDevice, PcmHardware},
    SoundError,
};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::{id::DomainId, sync::IrqSafeSpinLock};

#[derive(Debug)]
pub(super) struct Card(pub Arc<VirtioSoundPci>);

impl PcmDevice for Card {
    fn capabilities(&self, capture: bool) -> narf_drivers_sound::hardware::PcmCapabilities {
        let mut caps =
            narf_drivers_sound::hardware::PcmCapabilities::fixed(self.default_params(capture));
        let Some(info) = self.0.playback_info else {
            return caps;
        };
        caps.rates = [SampleRate::R44100, SampleRate::R48000]
            .into_iter()
            .filter(|rate| {
                info.rates
                    & (1 << if *rate == SampleRate::R48000 {
                        super::VIRTIO_SND_PCM_RATE_48000
                    } else {
                        super::VIRTIO_SND_PCM_RATE_44100
                    })
                    != 0
            })
            .collect();
        caps.channels = [ChannelCount::Mono, ChannelCount::Stereo]
            .into_iter()
            .filter(|channels| (info.channels_min..=info.channels_max).contains(&channels.count()))
            .collect();
        caps.period_frames = (32, 32768);
        caps.periods = (2, 256);
        caps.buffer_bytes = (128, 256 * 1024);
        caps
    }
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
            prepared: false,
            running: false,
            tx: IrqSafeSpinLock::new(Tx::default()),
        }))
    }
}

/// Upper bound on one `virtio_snd_pcm_xfer` payload. Linux sends one message
/// per period; capping keeps very large periods from collapsing the ring to a
/// couple of coarse position updates.
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Header (`virtio_snd_pcm_xfer`, 8 B) + status (`virtio_snd_pcm_status`,
/// 8 B) per message slot.
const META_BYTES: usize = 16;
/// Descriptors per message: header, payload, status.
const DESCS_PER_MESSAGE: usize = 3;

#[derive(Debug)]
struct Message {
    head: u16,
    slot: usize,
    frames: u64,
    done: bool,
}

/// Asynchronous TX ring, after Linux `sound/virtio/virtio_pcm_msg.c`: the
/// device owns up to `slots` messages at once and the hardware position
/// advances only as it returns them.
///
/// The device acks a buffer once it has consumed it, at playback rate. Waiting
/// for each ack inside `write`/`start` therefore reported every written frame
/// as already played when the call returned: ALSA saw an empty ring after
/// each refill, raised XRUN, and PipeWire's DROP/PREPARE/START recovery hit the
/// same wall forever (no audio clock, so browser video froze too).
#[derive(Debug, Default)]
struct Tx {
    payload: Option<DmaBuffer>,
    meta: Option<DmaBuffer>,
    message_bytes: usize,
    frame_bytes: usize,
    slots: usize,
    next_slot: usize,
    in_flight: VecDeque<Message>,
    in_flight_frames: u64,
    /// Accepted bytes not yet handed to the device; always whole frames.
    pending: VecDeque<u8>,
    /// Frames the device has returned since PREPARE: the hardware pointer.
    completed: u64,
    failed: bool,
}

impl Tx {
    /// Retire returned messages in submission order. Non-blocking.
    fn reap(&mut self, device: &VirtioSoundPci) {
        if self.in_flight.is_empty() {
            return;
        }
        let mut g = device.tx_q.lock();
        let Some(q) = g.as_mut() else {
            self.failed = true;
            return;
        };
        while let Some((id, _)) = q.poll_used() {
            if let Some(m) = self
                .in_flight
                .iter_mut()
                .find(|m| !m.done && u32::from(m.head) == id)
            {
                m.done = true;
            }
        }
        let Some(meta) = self.meta.as_ref() else {
            return;
        };
        while self.in_flight.front().is_some_and(|m| m.done) {
            let m = self.in_flight.pop_front().unwrap();
            // SAFETY: the device returned this message, so its status slot is
            // driver-owned again and lies within the coherent meta buffer.
            let status = unsafe {
                core::ptr::read_volatile(meta.cpu_ptr_at::<u32>((m.slot * META_BYTES + 8) as u64))
            };
            if status != VIRTIO_SND_S_OK {
                self.failed = true;
            }
            q.free_chain(m.head);
            self.completed += m.frames;
            self.in_flight_frames -= m.frames;
        }
    }

    /// Hand pending frames to the device while message slots are free.
    fn submit(&mut self, device: &VirtioSoundPci) {
        let (Some(payload), Some(meta)) = (self.payload.as_ref(), self.meta.as_ref()) else {
            return;
        };
        let mut queued = false;
        {
            let mut g = device.tx_q.lock();
            let Some(q) = g.as_mut() else {
                self.failed = true;
                return;
            };
            while !self.pending.is_empty() && self.in_flight.len() < self.slots {
                let bytes = self.pending.len().min(self.message_bytes);
                let slot = self.next_slot;
                let data = (slot * self.message_bytes) as u64;
                let hdr = (slot * META_BYTES) as u64;
                let (a, b) = self.pending.as_slices();
                let first = a.len().min(bytes);
                // SAFETY: slots are reused in FIFO order and fewer than
                // `slots` messages are in flight, so this slot is
                // driver-owned; both copies stay inside the coherent buffers
                // sized `slots * message_bytes` and `slots * META_BYTES`.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        a.as_ptr(),
                        payload.cpu_mut_ptr_at::<u8>(data),
                        first,
                    );
                    core::ptr::copy_nonoverlapping(
                        b.as_ptr(),
                        payload.cpu_mut_ptr_at::<u8>(data + first as u64),
                        bytes - first,
                    );
                    // virtio_snd_pcm_xfer { stream_id = 0, padding }
                    core::ptr::write_volatile(meta.cpu_mut_ptr_at::<u64>(hdr), 0);
                    // virtio_snd_pcm_status { status, latency_bytes }:
                    // pre-poison so a missing write-back is an error.
                    core::ptr::write_volatile(meta.cpu_mut_ptr_at::<u32>(hdr + 8), u32::MAX);
                    core::ptr::write_volatile(meta.cpu_mut_ptr_at::<u32>(hdr + 12), 0);
                }
                let descs = [
                    VirtqDesc {
                        addr: meta.dma_addr_at(hdr).raw(),
                        len: 8,
                        flags: 0,
                        next: 0,
                    },
                    VirtqDesc {
                        addr: payload.dma_addr_at(data).raw(),
                        len: bytes as u32,
                        flags: 0,
                        next: 0,
                    },
                    VirtqDesc {
                        addr: meta.dma_addr_at(hdr + 8).raw(),
                        len: 8,
                        flags: VIRTQ_DESC_F_WRITE,
                        next: 0,
                    },
                ];
                let Some(head) = q.add_buffer(&descs) else {
                    break;
                };
                self.pending.drain(..bytes);
                let frames = (bytes / self.frame_bytes) as u64;
                self.in_flight.push_back(Message {
                    head,
                    slot,
                    frames,
                    done: false,
                });
                self.in_flight_frames += frames;
                self.next_slot = (slot + 1) % self.slots;
                queued = true;
            }
        }
        if queued {
            compiler_fence(Ordering::SeqCst);
            device.kick_tx();
        }
    }
}

#[derive(Debug)]
struct Playback {
    device: Arc<VirtioSoundPci>,
    params: Option<PcmParams>,
    prepared: bool,
    running: bool,
    /// Interior lock: `pointer(&self)` reaps completions and refills.
    tx: IrqSafeSpinLock<Tx>,
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
    fn service(&self) -> Result<(), SoundError> {
        let mut tx = self.tx.lock();
        tx.reap(&self.device);
        if self.running && !tx.failed {
            tx.submit(&self.device);
        }
        if tx.failed {
            return Err(SoundError::BadState);
        }
        Ok(())
    }

    /// Wait for the device to return every in-flight message. Caller has
    /// issued RELEASE, which makes the device flush its queue; until then the
    /// DMA slots still belong to the device.
    fn reclaim(&self) -> Result<(), SoundError> {
        if self.device.failed.load(Ordering::Acquire) {
            // The failing path already reset the device; nothing is in DMA.
            let mut tx = self.tx.lock();
            tx.in_flight.clear();
            tx.in_flight_frames = 0;
            return Err(SoundError::BadState);
        }
        let done = narf_scheduler::responsive_spin_until(
            || {
                let mut tx = self.tx.lock();
                tx.reap(&self.device);
                tx.in_flight.is_empty()
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            self.device.failed.store(true, Ordering::Release);
            assert!(
                self.device.reset_device(),
                "virtio-snd playback reset failed"
            );
            let mut tx = self.tx.lock();
            tx.in_flight.clear();
            tx.in_flight_frames = 0;
            return Err(SoundError::BadState);
        }
        Ok(())
    }

    /// STOP + RELEASE, then take back every queued message. Flushed messages
    /// count as consumed: the device returns them without saying how much it
    /// played, and Linux likewise discards them on release.
    fn halt(&mut self) -> Result<(), SoundError> {
        let stopped = {
            let _gate = ReqGate::acquire(&self.device.req_gate);
            self.device.stop_pcm_locked()
        };
        self.running = false;
        self.reclaim()?;
        stopped.map_err(|_| SoundError::BadState)
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
        let frame_bytes = usize::from(params.channels) * 2;
        let message_bytes =
            (params.period_bytes as usize).min(MAX_MESSAGE_BYTES) / frame_bytes * frame_bytes;
        let depth = self
            .device
            .tx_q
            .lock()
            .as_ref()
            .map_or(0, |q| usize::from(q.capacity()));
        let slots = (depth / DESCS_PER_MESSAGE)
            .min((params.buffer_bytes as usize).div_ceil(message_bytes))
            .min(4096 / META_BYTES);
        if slots == 0 {
            return Err(SoundError::BadState);
        }
        let payload = alloc_coherent(slots * message_bytes, DomainId::DRIVER_0)
            .map_err(|_| SoundError::NoMemory)?;
        let meta = alloc_coherent(slots * META_BYTES, DomainId::DRIVER_0)
            .map_err(|_| SoundError::NoMemory)?;
        let mut tx = self.tx.lock();
        if !tx.in_flight.is_empty() {
            return Err(SoundError::BadState);
        }
        *tx = Tx {
            payload: Some(payload),
            meta: Some(meta),
            message_bytes,
            frame_bytes,
            slots,
            ..Tx::default()
        };
        drop(tx);
        self.params = Some(params);
        self.prepared = false;
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), SoundError> {
        if self.params.is_none() || self.running || self.device.failed.load(Ordering::Acquire) {
            return Err(SoundError::BadState);
        }
        let mut tx = self.tx.lock();
        if !tx.in_flight.is_empty() {
            return Err(SoundError::BadState);
        }
        tx.pending.clear();
        tx.completed = 0;
        tx.failed = false;
        drop(tx);
        self.prepared = true;
        Ok(())
    }
    fn start(&mut self) -> Result<(), SoundError> {
        if !self.prepared || self.running {
            return Err(SoundError::BadState);
        }
        let params = self.params.ok_or(SoundError::BadState)?;
        {
            let _gate = ReqGate::acquire(&self.device.req_gate);
            self.device
                .ensure_started(params)
                .map_err(|_| SoundError::BadState)?;
        }
        self.running = true;
        self.service()
    }
    fn stop(&mut self) -> Result<(), SoundError> {
        let result = self.halt();
        self.tx.lock().pending.clear();
        result
    }
    fn reset(&mut self) -> Result<(), SoundError> {
        self.tx.lock().pending.clear();
        Ok(())
    }
    fn pause(&mut self, paused: bool) -> Result<(), SoundError> {
        if !paused {
            return self.start();
        }
        self.halt()
    }
    fn pointer(&self) -> u64 {
        let _ = self.service();
        self.tx.lock().completed
    }
    fn overwrite(&mut self, frame: u64, samples: &[u8]) -> Result<(), SoundError> {
        let width = usize::from(self.params.ok_or(SoundError::BadState)?.channels) * 2;
        if samples.len() % width != 0 {
            return Err(SoundError::InvalidParams);
        }
        // Device-owned messages are immutable; only the unsubmitted suffix
        // can change. Later messages are read from the shared ring.
        let mut tx = self.tx.lock();
        let queued = tx.completed + tx.in_flight_frames;
        for (i, chunk) in samples.chunks_exact(width).enumerate() {
            let at = frame + i as u64;
            if at < queued {
                continue;
            }
            let off = (at - queued) as usize * width;
            if off + width > tx.pending.len() {
                break;
            }
            for (j, byte) in chunk.iter().enumerate() {
                tx.pending[off + j] = *byte;
            }
        }
        Ok(())
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
        let count = {
            let mut tx = self.tx.lock();
            if tx.failed {
                return Err(SoundError::BadState);
            }
            let held = tx.pending.len() + tx.in_flight_frames as usize * frame_bytes;
            let count = samples
                .len()
                .min((params.buffer_bytes as usize).saturating_sub(held));
            tx.pending.extend(&samples[..count]);
            count
        };
        if self.running {
            self.service()?;
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
        if !self.running {
            self.start()?;
        }
        let params = self.params.ok_or(SoundError::BadState)?;
        let rate = if params.rate == super::VIRTIO_SND_PCM_RATE_48000 {
            48_000
        } else {
            44_100
        };
        let frames = u64::from(params.buffer_bytes) / (u64::from(params.channels) * 2);
        let mut failed = false;
        let drained = narf_scheduler::responsive_spin_until(
            || {
                if self.service().is_err() {
                    failed = true;
                    return true;
                }
                let tx = self.tx.lock();
                tx.pending.is_empty() && tx.in_flight.is_empty()
            },
            narf_time::Deadline::after_ms(1_000 + frames * 1_000 / rate),
        );
        let stopped = self.stop();
        if failed || !drained {
            return Err(SoundError::BadState);
        }
        stopped
    }
}

impl Drop for Playback {
    fn drop(&mut self) {
        // The DMA slots must not be freed while the device still owns them.
        let _ = self.halt();
        self.device.claimed.store(false, Ordering::Release);
    }
}
