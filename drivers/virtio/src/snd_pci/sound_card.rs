//! The shared sound-card interface for the implemented VirtIO playback
//! and capture streams, plus the event-queue jack state and
//! control-element mixer surface.
use super::{ctl_info_kind, PcmParams, ReqGate, VirtioSoundPci, VIRTIO_SND_S_OK};
use crate::queue::{VirtqDesc, VIRTQ_DESC_F_WRITE};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{compiler_fence, Ordering};
use narf_drivers_sound::{
    format::{ChannelCount, HwParams, SampleFormat, SampleRate},
    hardware::{PcmDevice, PcmHardware},
    mixer::{ControlId, ControlInfo, ControlKind, ControlValue},
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
        // The pointer advances only as whole TX/RX messages complete.
        caps.batch = true;
        let info = if capture {
            self.0.capture_info
        } else {
            self.0.playback_info
        };
        let Some(info) = info else {
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

    fn default_params(&self, capture: bool) -> HwParams {
        // Playback keeps the old panic: a registered playback card
        // always has PCM_INFO. Capture has no such invariant (the
        // card registers with capture_count 0 when no input stream
        // exists), so a missing capture info yields fixed defaults
        // instead of panicking on a merely-queried direction.
        let info = if capture {
            self.0.capture_info
        } else {
            self.0.playback_info
        };
        let Some(info) = info else {
            if capture {
                return HwParams {
                    format: SampleFormat::S16LE,
                    rate: SampleRate::R48000,
                    channels: ChannelCount::Stereo,
                    period_size: 1024,
                    periods: 4,
                };
            }
            panic!("registered playback card has PCM_INFO");
        };
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
        if device != 0 || self.0.cfg.streams == 0 {
            return Err(SoundError::NoSuchDevice);
        }
        if capture {
            let Some(stream_id) = self.0.capture_stream_id else {
                return Err(SoundError::NoSuchDevice);
            };
            let _gate = ReqGate::acquire(&self.0.req_gate);
            if self.0.failed.load(Ordering::Acquire) {
                return Err(SoundError::BadState);
            }
            if self.0.capture_claimed.swap(true, Ordering::AcqRel) {
                return Err(SoundError::DeviceBusy);
            }
            if self.0.stream_stop(&self.0.capture, stream_id).is_err() {
                self.0.capture_claimed.store(false, Ordering::Release);
                return Err(SoundError::BadState);
            }
            return Ok(Box::new(Capture {
                device: self.0.clone(),
                stream_id,
                params: None,
                prepared: false,
                running: false,
                rx: IrqSafeSpinLock::new(Rx::default()),
            }));
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

    /// JackSense controls, one per jack id, followed by the mapped
    /// control elements in device order. Elements without a mixer
    /// kind are not listed here at all.
    fn controls(&self) -> Vec<ControlId> {
        let mut out = Vec::new();
        for jack in 0..self.0.cfg.jacks {
            out.push(ControlId {
                index: jack,
                kind: ControlKind::JackSense,
            });
        }
        for info in &self.0.ctl_infos {
            if let Some(kind) = ctl_info_kind(info) {
                out.push(ControlId {
                    index: info.id,
                    kind,
                });
            }
        }
        out
    }

    fn control_info(&self, id: ControlId) -> Result<ControlInfo, SoundError> {
        if let Some(elem) = self.0.ctl_element_for(id) {
            // Device range, clamped into i32: element bounds are
            // wire u32/u64 values, and the registry info is i32.
            // A variable step (0) is reported as 1.
            let clamp = |v: i64| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
            return Ok(ControlInfo {
                id,
                name: id.kind.name(),
                value_min: clamp(elem.min),
                value_max: clamp(elem.max),
                step: if elem.step == 0 { 1 } else { clamp(elem.step) },
                channels: elem.count as u8,
                is_boolean: elem.ctype == super::VIRTIO_SND_CTL_TYPE_BOOLEAN,
                is_read_only: !elem.writable(),
            });
        }
        // Only JackSense ids reach here: every other kind in
        // controls() is a CTL element caught above, and anything not
        // in controls() is not a control at all.
        if id.kind != ControlKind::JackSense || !self.controls().contains(&id) {
            return Err(SoundError::NoSuchControl);
        }
        Ok(ControlInfo {
            id,
            name: id.kind.name(),
            value_min: 0,
            value_max: 1,
            step: 1,
            channels: 1,
            is_boolean: true,
            is_read_only: true,
        })
    }

    fn get_control(&self, id: ControlId) -> Result<ControlValue, SoundError> {
        // Jack state is only as fresh as the last event service, so
        // service before reading it. Control reads round-trip live
        // regardless, so no cache invalidation is needed for them.
        self.0.service_events();
        if id.kind == ControlKind::JackSense {
            let state = self.0.jack_connected.lock();
            let plugged = state.get(id.index as usize).copied().unwrap_or(false);
            return Ok(ControlValue::Boolean(plugged));
        }
        let Some(elem) = self.0.ctl_element_for(id) else {
            return Err(SoundError::NoSuchControl);
        };
        if !elem.readable() {
            return Err(SoundError::NoSuchControl);
        }
        let value = {
            let _gate = ReqGate::acquire(&self.0.req_gate);
            self.0
                .ctl_read_value(elem.id)
                .map_err(|_| SoundError::BadState)?
        };
        let v0 = u32::from_le_bytes(value[0..4].try_into().unwrap());
        let v1 = u32::from_le_bytes(value[4..8].try_into().unwrap());
        match elem.ctype {
            super::VIRTIO_SND_CTL_TYPE_BOOLEAN => Ok(ControlValue::Boolean(v0 != 0)),
            super::VIRTIO_SND_CTL_TYPE_INTEGER => {
                // Clamp into the advertised range: the wire values
                // are u32, the registry values i32, and a device
                // reporting outside its own bounds must not wrap.
                let clamp = |v: u32| {
                    (v as i64)
                        .clamp(elem.min, elem.max)
                        .clamp(i32::MIN as i64, i32::MAX as i64) as i32
                };
                if elem.count == 1 {
                    let v = clamp(v0);
                    Ok(ControlValue::Integer { left: v, right: v })
                } else {
                    Ok(ControlValue::Integer {
                        left: clamp(v0),
                        right: clamp(v1),
                    })
                }
            }
            _ => Err(SoundError::NoSuchControl),
        }
    }

    fn set_control(&self, id: ControlId, value: ControlValue) -> Result<(), SoundError> {
        let Some(elem) = self.0.ctl_element_for(id) else {
            // JackSense and everything unmapped: the default
            // PcmDevice behavior is NoSuchControl for unwritable ids.
            return Err(SoundError::NoSuchControl);
        };
        if !elem.writable() {
            return Err(SoundError::NoSuchControl);
        }
        let mut raw = [0u8; 512];
        match (elem.ctype, value) {
            (super::VIRTIO_SND_CTL_TYPE_BOOLEAN, ControlValue::Boolean(b)) => {
                raw[0..4].copy_from_slice(&(b as u32).to_le_bytes());
            }
            (super::VIRTIO_SND_CTL_TYPE_INTEGER, ControlValue::Integer { left, right }) => {
                // Range-check against the device's own bounds before
                // sending: a write the device would reject with
                // S_BAD_MSG surfaces as OutOfRange here instead.
                if i64::from(left) < elem.min
                    || i64::from(left) > elem.max
                    || i64::from(right) < elem.min
                    || i64::from(right) > elem.max
                {
                    return Err(SoundError::OutOfRange);
                }
                raw[0..4].copy_from_slice(&left.to_le_bytes());
                if elem.count >= 2 {
                    raw[4..8].copy_from_slice(&right.to_le_bytes());
                }
            }
            _ => return Err(SoundError::InvalidParams),
        }
        let _gate = ReqGate::acquire(&self.0.req_gate);
        self.0
            .ctl_write_value(elem.id, &raw)
            .map_err(|_| SoundError::BadState)
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
                    // virtio_snd_pcm_xfer { stream_id, padding }
                    core::ptr::write_volatile(
                        meta.cpu_mut_ptr_at::<u64>(hdr),
                        u64::from(device.playback_stream_id),
                    );
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
        // Keep the event queue drained on the same lazy schedule as
        // the control reads: no pump task, no MSI-X on this driver.
        self.device.service_events();
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

#[derive(Debug)]
struct RxMessage {
    head: u16,
    slot: usize,
    done: bool,
    /// Used-ring length for this completion: status (8 B) +
    /// recorded frames, per 1.2 §5.14.6.8.2. The header descriptor
    /// is device-readable, so it is not counted.
    used_len: u32,
}

/// Asynchronous RX ring, the capture mirror of [`Tx`]: the driver
/// pre-posts empty period buffers and the device fills them at the
/// capture rate. Completions land in submission order; the used
/// length says how many frames each one actually recorded.
#[derive(Debug, Default)]
struct Rx {
    payload: Option<DmaBuffer>,
    meta: Option<DmaBuffer>,
    message_bytes: usize,
    frame_bytes: usize,
    slots: usize,
    next_slot: usize,
    in_flight: VecDeque<RxMessage>,
    /// Frames delivered by the device since PREPARE, in order.
    /// Not yet drained by `read`.
    read: VecDeque<u8>,
    /// Frames the device has returned since PREPARE: the hardware
    /// pointer. Cumulative; `read` does not move it back.
    completed: u64,
    buffer_bytes: usize,
    failed: bool,
}

impl Rx {
    /// Retire returned messages in submission order, appending their
    /// recorded frames to the read queue. Non-blocking.
    fn reap(&mut self, device: &VirtioSoundPci) {
        if self.in_flight.is_empty() {
            return;
        }
        let mut g = device.rx_q.lock();
        let Some(q) = g.as_mut() else {
            self.failed = true;
            return;
        };
        while let Some((id, len)) = q.poll_used() {
            if let Some(m) = self
                .in_flight
                .iter_mut()
                .find(|m| !m.done && u32::from(m.head) == id)
            {
                m.done = true;
                m.used_len = len;
            }
        }
        let (Some(payload), Some(meta)) = (self.payload.as_ref(), self.meta.as_ref()) else {
            return;
        };
        while self.in_flight.front().is_some_and(|m| m.done) {
            let m = self.in_flight.pop_front().unwrap();
            // SAFETY: the device returned this message, so its status slot is
            // driver-owned again and lies within the coherent meta buffer.
            let status = unsafe {
                core::ptr::read_volatile(meta.cpu_ptr_at::<u32>((m.slot * META_BYTES + 8) as u64))
            };
            let recorded = m.used_len.checked_sub(8);
            let valid = status == VIRTIO_SND_S_OK
                && matches!(recorded, Some(bytes) if bytes as usize <= self.message_bytes
                    && bytes as usize % self.frame_bytes == 0);
            if !valid {
                self.failed = true;
                q.free_chain(m.head);
                continue;
            }
            // Validated <= message_bytes above, so the widening cast is lossless.
            let recorded = recorded.unwrap() as usize;
            // Overrun: the application has not drained a full ring.
            // ALSA reports overrun as an error, so the stream fails
            // rather than silently dropping or overwriting samples.
            if self.read.len() + recorded > self.buffer_bytes {
                self.failed = true;
                q.free_chain(m.head);
                continue;
            }
            // SAFETY: the slot is driver-owned again, `recorded` was
            // validated against `message_bytes`, and the slot lies
            // inside the coherent payload buffer sized
            // `slots * message_bytes`.
            unsafe {
                let src = payload.cpu_ptr_at::<u8>((m.slot * self.message_bytes) as u64);
                let bytes = core::slice::from_raw_parts(src, recorded);
                self.read.extend(bytes.iter().copied());
            }
            q.free_chain(m.head);
            self.completed += (recorded / self.frame_bytes) as u64;
        }
    }

    /// Post empty period buffers while slots are free. The device
    /// fills them at the capture rate; a slot stays posted until its
    /// completion is reaped.
    fn repost(&mut self, device: &VirtioSoundPci, stream_id: u32) {
        let (Some(payload), Some(meta)) = (self.payload.as_ref(), self.meta.as_ref()) else {
            return;
        };
        let mut queued = false;
        {
            let mut g = device.rx_q.lock();
            let Some(q) = g.as_mut() else {
                self.failed = true;
                return;
            };
            while self.in_flight.len() < self.slots {
                let slot = self.next_slot;
                let data = (slot * self.message_bytes) as u64;
                let hdr = (slot * META_BYTES) as u64;
                // SAFETY: slots are reused in FIFO order and fewer than
                // `slots` messages are in flight, so this slot is
                // driver-owned; both writes stay inside the coherent
                // buffers sized `slots * message_bytes` and
                // `slots * META_BYTES`.
                unsafe {
                    // virtio_snd_pcm_xfer { stream_id, padding }
                    core::ptr::write_volatile(
                        meta.cpu_mut_ptr_at::<u64>(hdr),
                        u64::from(stream_id),
                    );
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
                        len: self.message_bytes as u32,
                        flags: VIRTQ_DESC_F_WRITE,
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
                self.in_flight.push_back(RxMessage {
                    head,
                    slot,
                    done: false,
                    used_len: 0,
                });
                self.next_slot = (slot + 1) % self.slots;
                queued = true;
            }
        }
        if queued {
            compiler_fence(Ordering::SeqCst);
            device.kick_rx();
        }
    }
}

#[derive(Debug)]
struct Capture {
    device: Arc<VirtioSoundPci>,
    stream_id: u32,
    params: Option<PcmParams>,
    prepared: bool,
    running: bool,
    /// Interior lock: `pointer(&self)` reaps completions and reposts.
    rx: IrqSafeSpinLock<Rx>,
}

impl Capture {
    fn service(&self) -> Result<(), SoundError> {
        let mut rx = self.rx.lock();
        rx.reap(&self.device);
        if self.running && !rx.failed {
            rx.repost(&self.device, self.stream_id);
        }
        if rx.failed {
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
            let mut rx = self.rx.lock();
            rx.in_flight.clear();
            return Err(SoundError::BadState);
        }
        let done = narf_scheduler::responsive_spin_until(
            || {
                let mut rx = self.rx.lock();
                rx.reap(&self.device);
                rx.in_flight.is_empty()
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if !done {
            self.device.failed.store(true, Ordering::Release);
            assert!(
                self.device.reset_device(),
                "virtio-snd capture reset failed"
            );
            let mut rx = self.rx.lock();
            rx.in_flight.clear();
            return Err(SoundError::BadState);
        }
        Ok(())
    }

    /// STOP + RELEASE (or RELEASE alone when merely prepared), then
    /// take back every queued message.
    fn halt(&mut self) -> Result<(), SoundError> {
        let stopped = {
            let _gate = ReqGate::acquire(&self.device.req_gate);
            self.device
                .stream_stop(&self.device.capture, self.stream_id)
        };
        self.running = false;
        self.reclaim()?;
        stopped.map_err(|_| SoundError::BadState)
    }
}

impl PcmHardware for Capture {
    fn configure(&mut self, requested: HwParams) -> Result<(), SoundError> {
        if self.running {
            return Err(SoundError::BadState);
        }
        let params = params(requested)?;
        if !self
            .device
            .capture_info
            .is_some_and(|info| info.supports(params))
        {
            return Err(SoundError::InvalidParams);
        }
        let frame_bytes = usize::from(params.channels) * 2;
        let message_bytes =
            (params.period_bytes as usize).min(MAX_MESSAGE_BYTES) / frame_bytes * frame_bytes;
        let depth = self
            .device
            .rx_q
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
        let mut rx = self.rx.lock();
        if !rx.in_flight.is_empty() {
            return Err(SoundError::BadState);
        }
        *rx = Rx {
            payload: Some(payload),
            meta: Some(meta),
            message_bytes,
            frame_bytes,
            slots,
            buffer_bytes: params.buffer_bytes as usize,
            ..Rx::default()
        };
        drop(rx);
        self.params = Some(params);
        self.prepared = false;
        Ok(())
    }

    fn prepare(&mut self) -> Result<(), SoundError> {
        if self.params.is_none() || self.running || self.device.failed.load(Ordering::Acquire) {
            return Err(SoundError::BadState);
        }
        let mut rx = self.rx.lock();
        if !rx.in_flight.is_empty() {
            return Err(SoundError::BadState);
        }
        rx.read.clear();
        rx.completed = 0;
        rx.failed = false;
        drop(rx);
        self.prepared = true;
        Ok(())
    }

    fn start(&mut self) -> Result<(), SoundError> {
        if !self.prepared || self.running {
            return Err(SoundError::BadState);
        }
        let params = self.params.ok_or(SoundError::BadState)?;
        let info = self.device.capture_info.ok_or(SoundError::BadState)?;
        {
            let _gate = ReqGate::acquire(&self.device.req_gate);
            self.device
                .stream_prepare(&self.device.capture, self.stream_id, info, params)
                .map_err(|_| SoundError::BadState)?;
        }
        // Buffers before START, per the spec's input-stream SHOULD:
        // the device must have somewhere to record into from the
        // first moment it runs.
        self.running = true;
        self.service()?;
        {
            let _gate = ReqGate::acquire(&self.device.req_gate);
            if self
                .device
                .stream_start(&self.device.capture, self.stream_id)
                .is_err()
            {
                // Posted buffers stay posted until halt/reclaim
                // takes them back; the stream simply never started.
                self.running = false;
                return Err(SoundError::BadState);
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), SoundError> {
        let result = self.halt();
        self.rx.lock().read.clear();
        result
    }

    fn reset(&mut self) -> Result<(), SoundError> {
        self.rx.lock().read.clear();
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
        self.device.service_events();
        self.rx.lock().completed
    }

    fn write(&mut self, _: &[u8]) -> Result<usize, SoundError> {
        // Capture streams take no application writes; the mirror of
        // Playback::read.
        Err(SoundError::BadState)
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize, SoundError> {
        if !self.prepared {
            return Err(SoundError::BadState);
        }
        self.service()?;
        let params = self.params.ok_or(SoundError::BadState)?;
        let frame_bytes = usize::from(params.channels) * 2;
        let want = out.len() / frame_bytes * frame_bytes;
        let mut rx = self.rx.lock();
        if rx.failed {
            return Err(SoundError::BadState);
        }
        let count = rx.read.len().min(want);
        let (a, b) = rx.read.as_slices();
        let first = a.len().min(count);
        out[..first].copy_from_slice(&a[..first]);
        out[first..count].copy_from_slice(&b[..count - first]);
        rx.read.drain(..count);
        Ok(count)
    }

    fn drain(&mut self) -> Result<(), SoundError> {
        // A capture stream never drains itself dry (the device
        // produces indefinitely), so drain is stop + discard.
        if !self.prepared {
            return Err(SoundError::BadState);
        }
        self.stop()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // The DMA slots must not be freed while the device still owns them.
        let _ = self.halt();
        self.device.capture_claimed.store(false, Ordering::Release);
    }
}
