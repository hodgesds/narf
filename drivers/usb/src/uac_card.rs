//! Sound-card publication for bound USB Audio devices.
//!
//! Turns a bound `UacTopology` (see `crate::uac`) into a
//! `narf-drivers-sound` hardware card: `UacCardState::from_bind`
//! snapshots the negotiated topology, `register_card` publishes
//! it through `register_hardware_card` (parentless — USB slots
//! have no `narf_bus::BusAddr`), and the `PcmDevice` /
//! `PcmHardware` implementations drive the device from the sound
//! layer: alt-setting selection at `prepare`, sampling-frequency
//! SET_CUR, FeatureUnit mixer controls, and a per-stream isoch
//! pump task started/stopped with the stream.
//!
//! Sync↔async bridging follows the precedent set by
//! `uac::playback_one_packet` in this crate: control transfers
//! and the fixture-facing one-packet path use
//! `narf_scheduler::block_on` from non-executor contexts, while
//! the spawned pump task awaits the xHCI directly (never
//! `block_on` from inside an executor poll).

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use narf_drivers_sound as sound;
use narf_lib::sync::IrqSafeSpinLock;
use sound::format::{ChannelCount, HwParams, SampleFormat, SampleRate};
use sound::hardware::{PcmCapabilities, PcmDevice, PcmHardware};
use sound::mixer::{ControlId, ControlInfo, ControlKind, ControlValue};
use sound::{CardInfo, SoundError};

use crate::uac::{
    alt_sound_rates, BindOutcome, PcmFormat, PcmRing, StreamChoice, UacAlt, UacTopology,
    UacVersion, CHANNEL_MASTER, FEATURE_MUTE, FEATURE_VOLUME, FU_CS_MUTE, FU_CS_VOLUME,
};

// ── Format mapping (descriptor shape → sound enums) ────────────────

pub fn sound_format(subframe_size: u8, bit_resolution: u8) -> Option<SampleFormat> {
    match (subframe_size, bit_resolution) {
        (2, 1..=16) => Some(SampleFormat::S16LE),
        (3, 20) => Some(SampleFormat::S20LE),
        (3, 24) => Some(SampleFormat::S24LE),
        // 24-in-32 rides the 32-bit container, as on Linux.
        (4, 1..=32) => Some(SampleFormat::S32LE),
        _ => None,
    }
}

pub fn rate_enum(hz: u32) -> Option<SampleRate> {
    Some(match hz {
        44_100 => SampleRate::R44100,
        48_000 => SampleRate::R48000,
        88_200 => SampleRate::R88200,
        96_000 => SampleRate::R96000,
        176_400 => SampleRate::R176400,
        192_000 => SampleRate::R192000,
        _ => return None,
    })
}

pub fn channels_enum(n: u8) -> Option<ChannelCount> {
    Some(match n {
        1 => ChannelCount::Mono,
        2 => ChannelCount::Stereo,
        4 => ChannelCount::Quad,
        6 => ChannelCount::Surround51,
        8 => ChannelCount::Surround71,
        _ => return None,
    })
}

/// Find the alt of `stream` serving exactly (format, channels,
/// rate) — the configure-time selection. `alts` are the stream's
/// recorded alt settings.
pub fn find_alt_for(alts: &[UacAlt], version: UacVersion, params: &HwParams) -> Option<(u8, u8)> {
    // Returns (alt_setting, ep_addr).
    for alt in alts {
        if alt.ep_addr == 0 {
            continue;
        }
        let Some(fmt) = &alt.format else {
            continue;
        };
        if channels_enum(fmt.channels) != Some(params.channels) {
            continue;
        }
        if sound_format(fmt.subframe_size, fmt.bit_resolution) != Some(params.format) {
            continue;
        }
        if !alt_sound_rates(alt, version).contains(&params.rate.hz()) {
            continue;
        }
        let frame_bytes = params.channels.count() as u32 * fmt.subframe_size as u32;
        let need = (params.rate.hz() * frame_bytes).div_ceil(1000);
        if (alt.ep_max_packet as u32) < need {
            continue;
        }
        return Some((alt.alt_setting, alt.ep_addr));
    }
    None
}

// ── Per-direction state ────────────────────────────────────────────

/// Feature Unit state for one direction.
#[derive(Debug)]
pub struct FuState {
    pub unit_id: u8,
    pub master_controls: u16,
    /// (min, max, res) in dB×256, from the bind-time GET_MIN /
    /// GET_MAX / GET_RES (spec defaults when the reads failed).
    pub volume_range: (i32, i32, i32),
    /// Last programmed master volume (dB×256).
    pub volume_db256: IrqSafeSpinLock<i32>,
    pub muted: AtomicBool,
}

impl FuState {
    pub fn has_volume(&self) -> bool {
        self.master_controls & FEATURE_VOLUME != 0
    }
    pub fn has_mute(&self) -> bool {
        self.master_controls & FEATURE_MUTE != 0
    }
}

/// One direction (playback or capture) of the card.
#[derive(Debug)]
pub struct StreamState {
    pub iface: u8,
    pub terminal_link: u8,
    pub capture: bool,
    /// All recorded alt settings of the stream interface.
    pub alts: Vec<UacAlt>,
    /// Bind-time choice (the defaults the card opens with).
    pub choice: StreamChoice,
    pub fu: Option<FuState>,
    /// UAC2 clock entity driving this stream, if any.
    pub clock_id: Option<u8>,
    pub clock_programmable: bool,
    /// Rate currently programmed on the device (Hz).
    pub current_rate_hz: IrqSafeSpinLock<u32>,
    /// Alt setting currently selected on the device (0 = idle).
    pub active_alt: AtomicU8,
    /// Exclusive-open claim.
    pub claimed: AtomicBool,
    /// The live stream's pump state, while a lease is open.
    pub live: IrqSafeSpinLock<Option<Arc<PumpShared>>>,
}

/// Whole-device card state, shared between the UAC registry, the
/// sound layer's `PcmDevice`, and every open lease.
#[derive(Debug)]
pub struct UacCardState {
    pub slot_id: u8,
    pub ac_iface: u8,
    pub version: UacVersion,
    pub playback: Option<Arc<StreamState>>,
    pub capture: Option<Arc<StreamState>>,
    /// Sound registry index once published.
    pub card_index: IrqSafeSpinLock<Option<u32>>,
    pub detached: AtomicBool,
}

impl UacCardState {
    /// Snapshot the negotiated topology after a successful bind
    /// conversation. `outcome` carries the FU volume ranges and
    /// any UAC2 clock rates the conversation learned.
    pub fn from_bind(
        slot_id: u8,
        topo: &UacTopology,
        choices: &[StreamChoice],
        outcome: &BindOutcome,
    ) -> Arc<Self> {
        let build = |choice: &StreamChoice| -> Arc<StreamState> {
            let dir = BindOutcome::dir_idx(choice.capture);
            let stream = topo.streams.iter().find(|s| s.iface == choice.iface);
            let fu = topo
                .feature_unit_for(choice.terminal_link)
                .map(|f| FuState {
                    unit_id: f.id,
                    master_controls: f.master_controls,
                    volume_range: outcome.volume_range[dir].unwrap_or((i16::MIN as i32, 0, 256)),
                    volume_db256: IrqSafeSpinLock::new(0),
                    muted: AtomicBool::new(false),
                });
            let clock = topo.clock_for_terminal(choice.terminal_link);
            let rate_hz = match topo.version {
                UacVersion::V2 => outcome.clock_rate_hz[dir].unwrap_or(choice.rate_hz),
                UacVersion::V1 => choice.rate_hz,
            };
            Arc::new(StreamState {
                iface: choice.iface,
                terminal_link: choice.terminal_link,
                capture: choice.capture,
                alts: stream.map(|s| s.alts.clone()).unwrap_or_default(),
                choice: *choice,
                fu,
                clock_id: clock.map(|c| c.id),
                clock_programmable: clock.map(|c| c.freq_programmable).unwrap_or(false),
                current_rate_hz: IrqSafeSpinLock::new(rate_hz),
                active_alt: AtomicU8::new(choice.alt_setting),
                claimed: AtomicBool::new(false),
                live: IrqSafeSpinLock::new(None),
            })
        };
        Arc::new(Self {
            slot_id,
            ac_iface: topo.ac_iface,
            version: topo.version,
            playback: choices.iter().find(|c| !c.capture).map(build),
            capture: choices.iter().find(|c| c.capture).map(build),
            card_index: IrqSafeSpinLock::new(None),
            detached: AtomicBool::new(false),
        })
    }

    pub fn stream(&self, capture: bool) -> Option<&Arc<StreamState>> {
        if capture {
            self.capture.as_ref()
        } else {
            self.playback.as_ref()
        }
    }

    /// Detach: stop live pumps and unregister the card. Open
    /// leases keep their `Arc`s (and the hardware contract) alive
    /// until they stop, per the sound layer's unregister
    /// semantics.
    pub fn detach(&self) {
        self.detached.store(true, Ordering::SeqCst);
        for s in [self.playback.as_ref(), self.capture.as_ref()]
            .into_iter()
            .flatten()
        {
            if let Some(shared) = s.live.lock().as_ref() {
                shared.stop.store(true, Ordering::SeqCst);
            }
        }
        if let Some(idx) = self.card_index.lock().take() {
            sound::unregister_hardware_card(idx);
        }
    }

    // ── Control-transfer helpers (sync, block_on-bridged) ──────

    fn control_out(
        &self,
        rt: u8,
        req: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<(), SoundError> {
        let ctrl = crate::xhci::controller().ok_or(SoundError::NoSuchCard)?;
        let slot = self.slot_id;
        narf_scheduler::block_on(async move {
            ctrl.control_out(slot, rt, req, value, index, data).await
        })
        .map_err(|_| SoundError::BadState)
        .map(|_| ())
    }

    fn control_in(
        &self,
        rt: u8,
        req: u8,
        value: u16,
        index: u16,
        out: &mut [u8],
    ) -> Result<usize, SoundError> {
        let ctrl = crate::xhci::controller().ok_or(SoundError::NoSuchCard)?;
        let slot = self.slot_id;
        narf_scheduler::block_on(
            async move { ctrl.control_in(slot, rt, req, value, index, out).await },
        )
        .map_err(|_| SoundError::BadState)
    }

    /// SET_INTERFACE to `alt` on `iface` (alt 0 idles the stream).
    pub fn set_interface(&self, iface: u8, alt: u8) -> Result<(), SoundError> {
        self.control_out(
            0x01,
            crate::control::REQ_SET_INTERFACE,
            alt as u16,
            iface as u16,
            &[],
        )
    }

    /// Program the sampling frequency for one direction: UAC1
    /// endpoint control, or the UAC2 clock entity when the clock
    /// is programmable (a fixed clock rejects with BadState and
    /// the caller keeps the bind-time rate).
    pub fn set_rate(&self, dir: &StreamState, hz: u32) -> Result<(), SoundError> {
        match self.version {
            UacVersion::V1 => self.control_out(
                0x22,
                crate::uac::REQ_SET_CUR,
                (crate::uac::SAMPLING_FREQUENCY_CONTROL as u16) << 8,
                dir.choice.ep_addr as u16,
                &crate::uac::encode_sampling_freq(hz),
            ),
            UacVersion::V2 => {
                let clock = dir.clock_id.ok_or(SoundError::BadState)?;
                if !dir.clock_programmable {
                    return Err(SoundError::BadState);
                }
                self.control_out(
                    0x21,
                    crate::uac::REQ_CUR,
                    (crate::uac::CLOCK_CS_SAMPLING_FREQUENCY as u16) << 8,
                    ((clock as u16) << 8) | self.ac_iface as u16,
                    &hz.to_le_bytes(),
                )
            }
        }
    }

    fn fu_set_cur(&self, fu: &FuState, cs: u8, data: &[u8]) -> Result<(), SoundError> {
        self.control_out(
            0x21,
            crate::uac::REQ_SET_CUR,
            crate::uac::fu_wvalue(cs, CHANNEL_MASTER),
            crate::uac::fu_windex(fu.unit_id, self.ac_iface),
            data,
        )
    }

    fn fu_get_cur(&self, fu: &FuState, cs: u8, out: &mut [u8]) -> Result<usize, SoundError> {
        self.control_in(
            0xA1,
            crate::uac::REQ_GET_CUR,
            crate::uac::fu_wvalue(cs, CHANNEL_MASTER),
            crate::uac::fu_windex(fu.unit_id, self.ac_iface),
            out,
        )
    }
}

/// Publish a bound device's card in the sound registry. Returns
/// the assigned card index.
pub fn register_card(state: &Arc<UacCardState>) -> Result<u32, SoundError> {
    let info = CardInfo {
        index: 0,
        driver: "snd-usb-audio",
        id: "USB",
        name: "USB Audio Device",
        playback_count: if state.playback.is_some() { 1 } else { 0 },
        capture_count: if state.capture.is_some() { 1 } else { 0 },
    };
    let device: Arc<dyn PcmDevice> = Arc::new(UsbAudioCard(state.clone()));
    let idx = sound::register_hardware_card(info, device);
    *state.card_index.lock() = Some(idx);
    Ok(idx)
}

// ── Pump plumbing ──────────────────────────────────────────────────

/// State shared between a stream lease and its pump.
#[derive(Debug)]
pub struct PumpShared {
    pub stop: AtomicBool,
    pub frames_clocked: AtomicU64,
    pub ring: IrqSafeSpinLock<PcmRing>,
    /// Fractional frame accumulator for rates like 44.1 kHz
    /// (44/45-frame packet alternation).
    pub phase: IrqSafeSpinLock<u32>,
}

impl PumpShared {
    pub fn new(format: PcmFormat, capacity_bytes: usize) -> Self {
        Self {
            stop: AtomicBool::new(false),
            frames_clocked: AtomicU64::new(0),
            ring: IrqSafeSpinLock::new(PcmRing::new(format, capacity_bytes)),
            phase: IrqSafeSpinLock::new(0),
        }
    }

    /// Frames in the next 1 ms packet at `rate_hz`, with the
    /// fractional remainder carried in `phase`.
    pub fn next_packet_frames(&self, rate_hz: u32) -> usize {
        let mut phase = self.phase.lock();
        let acc = *phase + rate_hz;
        *phase = acc % 1000;
        (acc / 1000) as usize
    }

    /// Take the next playback packet: queued frames first,
    /// silence for the underrun remainder. The packet is always
    /// full-length — a running USB stream clocks silence, it
    /// does not stall.
    pub fn take_playback_packet(&self, rate_hz: u32, frame_bytes: usize) -> Vec<u8> {
        let frames = self.next_packet_frames(rate_hz);
        let mut buf = alloc::vec![0u8; frames * frame_bytes];
        {
            let mut ring = self.ring.lock();
            let _ = ring.pop(&mut buf);
        }
        self.frames_clocked
            .fetch_add(frames as u64, Ordering::SeqCst);
        buf
    }

    /// Ingest one capture packet's bytes; whole frames only,
    /// overflow dropped (a full ring means the reader stalled).
    pub fn ingest_capture(&self, data: &[u8], frame_bytes: usize) {
        if frame_bytes == 0 {
            return;
        }
        let whole = data.len() - (data.len() % frame_bytes);
        if whole == 0 {
            return;
        }
        {
            let mut ring = self.ring.lock();
            let _ = ring.push(&data[..whole]);
        }
        self.frames_clocked
            .fetch_add((whole / frame_bytes) as u64, Ordering::SeqCst);
    }
}

/// One isochronous transfer endpoint pair, abstracted so the
/// pump step is fixture-testable without an xHCI.
pub trait IsoTransfer: Send + Sync + core::fmt::Debug {
    fn isoch_out(&self, data: &[u8]) -> Result<usize, SoundError>;
    fn isoch_in(&self, out: &mut [u8]) -> Result<usize, SoundError>;
}

/// Production transport: bridges to the xHCI via `block_on`,
/// the `playback_one_packet` precedent. Used by the fixture /
/// one-packet path; the spawned pump task awaits the controller
/// directly instead (see `spawn_pump`).
#[derive(Debug)]
pub struct XhciIso {
    pub slot_id: u8,
    pub dci: u8,
}

impl IsoTransfer for XhciIso {
    fn isoch_out(&self, data: &[u8]) -> Result<usize, SoundError> {
        let ctrl = crate::xhci::controller().ok_or(SoundError::NoSuchCard)?;
        let (slot, dci) = (self.slot_id, self.dci);
        narf_scheduler::block_on(async move { ctrl.isoch_out(slot, dci, data).await })
            .map_err(|_| SoundError::BadState)
    }
    fn isoch_in(&self, out: &mut [u8]) -> Result<usize, SoundError> {
        let ctrl = crate::xhci::controller().ok_or(SoundError::NoSuchCard)?;
        let (slot, dci) = (self.slot_id, self.dci);
        narf_scheduler::block_on(async move { ctrl.isoch_in(slot, dci, out).await })
            .map_err(|_| SoundError::BadState)
    }
}

/// Run one pump cycle against an explicit transport: playback
/// ships the next packet out, capture pulls one packet in. This
/// is the exact step the fixture drives; the production pump
/// task performs the same ring movement around direct awaits.
pub fn pump_step(
    shared: &PumpShared,
    iso: &dyn IsoTransfer,
    capture: bool,
    rate_hz: u32,
    frame_bytes: usize,
    ep_max_packet: usize,
) -> Result<(), SoundError> {
    if capture {
        let frames = shared.next_packet_frames(rate_hz);
        let want = (frames * frame_bytes).min(ep_max_packet.max(frame_bytes));
        let mut buf = alloc::vec![0u8; want];
        let n = iso.isoch_in(&mut buf)?;
        shared.ingest_capture(&buf[..n.min(want)], frame_bytes);
        Ok(())
    } else {
        let packet = shared.take_playback_packet(rate_hz, frame_bytes);
        iso.isoch_out(&packet)?;
        Ok(())
    }
}

// ── PcmDevice ──────────────────────────────────────────────────────

/// The sound-layer face of a bound USB audio device.
#[derive(Debug)]
pub struct UsbAudioCard(pub Arc<UacCardState>);

impl UsbAudioCard {
    fn dir(&self, capture: bool) -> Result<&Arc<StreamState>, SoundError> {
        self.0.stream(capture).ok_or(SoundError::NoSuchDevice)
    }

    fn fu_for(&self, kind: ControlKind) -> Option<(&Arc<StreamState>, &FuState)> {
        let capture = matches!(kind, ControlKind::CaptureVolume);
        let dir = self.0.stream(capture)?;
        let fu = dir.fu.as_ref()?;
        Some((dir, fu))
    }
}

impl PcmDevice for UsbAudioCard {
    fn default_params(&self, capture: bool) -> HwParams {
        match self.dir(capture) {
            Ok(dir) => {
                let c = &dir.choice;
                HwParams {
                    format: sound_format(c.subframe_size, c.bit_resolution)
                        .unwrap_or(SampleFormat::S16LE),
                    rate: rate_enum(*dir.current_rate_hz.lock()).unwrap_or(SampleRate::R48000),
                    channels: channels_enum(c.channels).unwrap_or(ChannelCount::Stereo),
                    period_size: 1024,
                    periods: 4,
                }
            }
            Err(_) => HwParams {
                format: SampleFormat::S16LE,
                rate: SampleRate::R48000,
                channels: ChannelCount::Stereo,
                period_size: 1024,
                periods: 4,
            },
        }
    }

    fn capabilities(&self, capture: bool) -> PcmCapabilities {
        let Ok(dir) = self.dir(capture) else {
            return PcmCapabilities::fixed(self.default_params(capture));
        };
        let mut formats: Vec<SampleFormat> = Vec::new();
        let mut rates: Vec<SampleRate> = Vec::new();
        let mut channels: Vec<ChannelCount> = Vec::new();
        let mut max_frame_bytes = 0usize;
        for alt in &dir.alts {
            let Some(fmt) = &alt.format else {
                continue;
            };
            if let Some(f) = sound_format(fmt.subframe_size, fmt.bit_resolution) {
                if !formats.contains(&f) {
                    formats.push(f);
                }
            }
            if let Some(ch) = channels_enum(fmt.channels) {
                if !channels.contains(&ch) {
                    channels.push(ch);
                }
            }
            for hz in alt_sound_rates(alt, self.0.version) {
                if let Some(r) = rate_enum(hz) {
                    if !rates.contains(&r) {
                        rates.push(r);
                    }
                }
            }
            max_frame_bytes =
                max_frame_bytes.max(fmt.channels as usize * fmt.subframe_size as usize);
        }
        if formats.is_empty() {
            return PcmCapabilities::fixed(self.default_params(capture));
        }
        let frame = max_frame_bytes.max(1) as u32;
        PcmCapabilities {
            formats,
            rates,
            channels,
            period_frames: (128, 4096),
            periods: (2, 8),
            buffer_bytes: (frame * 128 * 2, frame * 4096 * 8),
            period_byte_alignment: frame,
            batch: true,
        }
    }

    fn controls(&self) -> Vec<ControlId> {
        let mut out = Vec::new();
        if let Some(dir) = self.0.playback.as_ref() {
            if let Some(fu) = &dir.fu {
                if fu.has_volume() {
                    out.push(ControlId {
                        index: 0,
                        kind: ControlKind::MasterVolume,
                    });
                }
                if fu.has_mute() {
                    out.push(ControlId {
                        index: 0,
                        kind: ControlKind::MasterMute,
                    });
                }
            }
        }
        if let Some(dir) = self.0.capture.as_ref() {
            if let Some(fu) = &dir.fu {
                if fu.has_volume() {
                    out.push(ControlId {
                        index: 0,
                        kind: ControlKind::CaptureVolume,
                    });
                }
            }
        }
        out
    }

    fn control_info(&self, id: ControlId) -> Result<ControlInfo, SoundError> {
        if matches!(
            id.kind,
            ControlKind::MasterVolume | ControlKind::CaptureVolume
        ) {
            let (_, fu) = self.fu_for(id.kind).ok_or(SoundError::NoSuchControl)?;
            let (min, max, res) = fu.volume_range;
            return Ok(ControlInfo {
                id,
                name: id.kind.name(),
                value_min: min,
                value_max: max,
                step: res,
                channels: 2,
                is_boolean: false,
                is_read_only: false,
            });
        }
        // Default trait behaviour for the boolean mute.
        if !self.controls().contains(&id) {
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
            is_read_only: false,
        })
    }

    fn get_control(&self, id: ControlId) -> Result<ControlValue, SoundError> {
        match id.kind {
            ControlKind::MasterVolume | ControlKind::CaptureVolume => {
                let (_, fu) = self.fu_for(id.kind).ok_or(SoundError::NoSuchControl)?;
                if !fu.has_volume() {
                    return Err(SoundError::NoSuchControl);
                }
                // Live read, falling back to the last programmed
                // value when the device won't answer.
                let mut buf = [0u8; 2];
                let value = match self.0.fu_get_cur(fu, FU_CS_VOLUME, &mut buf) {
                    Ok(_) => crate::uac::decode_volume(&buf)
                        .map(|v| v as i32)
                        .unwrap_or(*fu.volume_db256.lock()),
                    Err(_) => *fu.volume_db256.lock(),
                };
                Ok(ControlValue::Integer {
                    left: value,
                    right: value,
                })
            }
            ControlKind::MasterMute => {
                let dir = self.dir(false)?;
                let fu = dir.fu.as_ref().ok_or(SoundError::NoSuchControl)?;
                if !fu.has_mute() {
                    return Err(SoundError::NoSuchControl);
                }
                Ok(ControlValue::Boolean(fu.muted.load(Ordering::SeqCst)))
            }
            _ => Err(SoundError::NoSuchControl),
        }
    }

    fn set_control(&self, id: ControlId, value: ControlValue) -> Result<(), SoundError> {
        match (id.kind, value) {
            (
                ControlKind::MasterVolume | ControlKind::CaptureVolume,
                ControlValue::Integer { left, .. },
            ) => {
                let (_, fu) = self.fu_for(id.kind).ok_or(SoundError::NoSuchControl)?;
                if !fu.has_volume() {
                    return Err(SoundError::NoSuchControl);
                }
                let (min, max, _) = fu.volume_range;
                let clamped = left.clamp(min, max);
                self.0
                    .fu_set_cur(fu, FU_CS_VOLUME, &crate::uac::encode_volume(clamped as i16))?;
                *fu.volume_db256.lock() = clamped;
                Ok(())
            }
            (ControlKind::MasterMute, ControlValue::Boolean(muted)) => {
                let dir = self.dir(false)?;
                let fu = dir.fu.as_ref().ok_or(SoundError::NoSuchControl)?;
                if !fu.has_mute() {
                    return Err(SoundError::NoSuchControl);
                }
                self.0
                    .fu_set_cur(fu, FU_CS_MUTE, &crate::uac::encode_mute(muted))?;
                fu.muted.store(muted, Ordering::SeqCst);
                Ok(())
            }
            _ => Err(SoundError::NoSuchControl),
        }
    }

    fn open(&self, capture: bool, device: u32) -> Result<Box<dyn PcmHardware>, SoundError> {
        if device != 0 {
            return Err(SoundError::NoSuchDevice);
        }
        if self.0.detached.load(Ordering::SeqCst) {
            return Err(SoundError::NoSuchCard);
        }
        let dir = self.dir(capture)?.clone();
        if dir
            .claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SoundError::DeviceBusy);
        }
        let choice = dir.choice;
        let format = PcmFormat {
            channels: choice.channels,
            bytes_per_sample: choice.subframe_size,
            bit_depth: choice.bit_resolution,
        };
        let shared = Arc::new(PumpShared::new(format, 64 * 1024));
        *dir.live.lock() = Some(shared.clone());
        Ok(Box::new(UacStream {
            card: self.0.clone(),
            dir,
            shared,
            iso: Box::new(XhciIso {
                slot_id: self.0.slot_id,
                dci: choice.dci,
            }),
            spawn_pump: true,
            params: None,
            chosen_alt: None,
            prepared: false,
            running: false,
        }))
    }
}

// ── PcmHardware lease ──────────────────────────────────────────────

/// One open stream. Endpoint lifecycle: `configure` selects the
/// alt, `prepare` programs the device (SET_INTERFACE and the rate
/// SET_CUR), `start` runs the pump, `stop` idles the interface
/// back to alt 0.
pub struct UacStream {
    card: Arc<UacCardState>,
    dir: Arc<StreamState>,
    shared: Arc<PumpShared>,
    iso: Box<dyn IsoTransfer>,
    /// Production leases spawn the pump task; fixture leases are
    /// stepped explicitly via `pump_once`.
    spawn_pump: bool,
    params: Option<HwParams>,
    chosen_alt: Option<u8>,
    prepared: bool,
    running: bool,
}

impl core::fmt::Debug for UacStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UacStream")
            .field("capture", &self.dir.capture)
            .field("prepared", &self.prepared)
            .field("running", &self.running)
            .finish()
    }
}

impl UacStream {
    /// Fixture constructor: a lease over an explicit transport,
    /// stepped by `pump_once` instead of a spawned task.
    #[doc(hidden)]
    pub fn with_iso(
        card: Arc<UacCardState>,
        capture: bool,
        iso: Box<dyn IsoTransfer>,
    ) -> Result<Self, SoundError> {
        let dir = card
            .stream(capture)
            .ok_or(SoundError::NoSuchDevice)?
            .clone();
        let c = &dir.choice;
        let format = PcmFormat {
            channels: c.channels,
            bytes_per_sample: c.subframe_size,
            bit_depth: c.bit_resolution,
        };
        let shared = Arc::new(PumpShared::new(format, 64 * 1024));
        *dir.live.lock() = Some(shared.clone());
        Ok(Self {
            card,
            dir,
            shared,
            iso,
            spawn_pump: false,
            params: None,
            chosen_alt: None,
            prepared: false,
            running: false,
        })
    }

    /// One pump cycle (fixture path; production uses the task).
    pub fn pump_once(&mut self) -> Result<(), SoundError> {
        if !self.running {
            return Err(SoundError::BadState);
        }
        let params = self.params.ok_or(SoundError::BadState)?;
        pump_step(
            &self.shared,
            &*self.iso,
            self.dir.capture,
            params.rate.hz(),
            params.format.bytes_per_sample() * params.channels.count() as usize,
            1024,
        )
    }

    fn program_device(&mut self, alt: u8, rate_hz: u32) -> Result<(), SoundError> {
        if self.dir.active_alt.load(Ordering::SeqCst) != alt {
            self.card.set_interface(self.dir.iface, alt)?;
            self.dir.active_alt.store(alt, Ordering::SeqCst);
        }
        if *self.dir.current_rate_hz.lock() != rate_hz {
            match self.card.set_rate(&self.dir, rate_hz) {
                Ok(()) => *self.dir.current_rate_hz.lock() = rate_hz,
                // A fixed UAC2 clock cannot move; refuse params
                // the bind did not negotiate.
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl PcmHardware for UacStream {
    fn configure(&mut self, params: HwParams) -> Result<(), SoundError> {
        let (alt, _ep) = find_alt_for(&self.dir.alts, self.card.version, &params)
            .ok_or(SoundError::InvalidParams)?;
        self.params = Some(params);
        self.chosen_alt = Some(alt);
        self.prepared = false;
        // Rebuild the ring at the negotiated shape.
        let format = PcmFormat {
            channels: params.channels.count(),
            bytes_per_sample: params.format.bytes_per_sample() as u8,
            bit_depth: match params.format {
                SampleFormat::S16LE => 16,
                SampleFormat::S20LE => 20,
                SampleFormat::S24LE => 24,
                SampleFormat::S32LE => 32,
            },
        };
        *self.shared.ring.lock() = PcmRing::new(format, params.buffer_bytes());
        Ok(())
    }

    fn prepare(&mut self) -> Result<(), SoundError> {
        let params = self.params.ok_or(SoundError::BadState)?;
        let alt = self.chosen_alt.ok_or(SoundError::BadState)?;
        if self.spawn_pump {
            self.program_device(alt, params.rate.hz())?;
        } else {
            // Fixture lease: no hardware to program; mirror the
            // bookkeeping so lifecycle assertions hold.
            self.dir.active_alt.store(alt, Ordering::SeqCst);
            *self.dir.current_rate_hz.lock() = params.rate.hz();
        }
        self.prepared = true;
        Ok(())
    }

    fn start(&mut self) -> Result<(), SoundError> {
        if !self.prepared {
            return Err(SoundError::BadState);
        }
        if self.running {
            return Ok(());
        }
        self.shared.stop.store(false, Ordering::SeqCst);
        self.running = true;
        if self.spawn_pump {
            spawn_pump(
                self.card.clone(),
                self.dir.clone(),
                self.shared.clone(),
                self.params.unwrap(),
            );
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), SoundError> {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.running = false;
        if self.spawn_pump && self.dir.active_alt.load(Ordering::SeqCst) != 0 {
            // Release the streaming interface: alt 0 is the
            // zero-bandwidth setting.
            self.card.set_interface(self.dir.iface, 0)?;
            self.dir.active_alt.store(0, Ordering::SeqCst);
        } else {
            self.dir.active_alt.store(0, Ordering::SeqCst);
        }
        self.prepared = false;
        Ok(())
    }

    fn pointer(&self) -> u64 {
        self.shared.frames_clocked.load(Ordering::SeqCst)
    }

    fn write(&mut self, samples: &[u8]) -> Result<usize, SoundError> {
        if self.dir.capture {
            return Err(SoundError::InvalidParams);
        }
        let frame = self.shared.ring.lock().format.audio_frame_bytes();
        if frame == 0 {
            return Err(SoundError::BadState);
        }
        let aligned = samples.len() - (samples.len() % frame);
        let mut ring = self.shared.ring.lock();
        let want = aligned.min(ring.free() - (ring.free() % frame));
        if want == 0 {
            return Ok(0);
        }
        ring.push(&samples[..want])
            .map_err(|_| SoundError::BadState)?;
        Ok(want)
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize, SoundError> {
        if !self.dir.capture {
            return Err(SoundError::InvalidParams);
        }
        let mut ring = self.shared.ring.lock();
        match ring.pop(out) {
            Ok(n) => Ok(n),
            Err(crate::uac::PcmError::Empty) => Ok(0),
            Err(_) => Err(SoundError::BadState),
        }
    }

    fn drain(&mut self) -> Result<(), SoundError> {
        if self.dir.capture {
            return Ok(());
        }
        // Bounded wait for the pump to empty the ring.
        for _ in 0..10_000 {
            if self.shared.ring.lock().filled() == 0 {
                return Ok(());
            }
            narf_scheduler::sleep_pumps::run();
        }
        Ok(())
    }
}

impl Drop for UacStream {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let mut live = self.dir.live.lock();
        if let Some(cur) = live.as_ref() {
            if Arc::ptr_eq(cur, &self.shared) {
                *live = None;
            }
        }
        self.dir.claimed.store(false, Ordering::SeqCst);
    }
}

/// Spawn the production pump task for a running stream. The task
/// awaits the xHCI directly (executor context — no `block_on`),
/// moving one packet per millisecond tick with the same ring
/// helpers the fixture path uses.
fn spawn_pump(
    card: Arc<UacCardState>,
    dir: Arc<StreamState>,
    shared: Arc<PumpShared>,
    params: HwParams,
) {
    let frame_bytes = params.format.bytes_per_sample() * params.channels.count() as usize;
    let rate_hz = params.rate.hz();
    let capture = dir.capture;
    let slot = card.slot_id;
    let dci = dir.choice.dci;
    narf_scheduler::spawn(async move {
        let ctrl = crate::xhci::controller();
        loop {
            if shared.stop.load(Ordering::SeqCst) {
                break;
            }
            if let Some(c) = &ctrl {
                if capture {
                    let frames = shared.next_packet_frames(rate_hz);
                    let mut buf = alloc::vec![0u8; frames * frame_bytes];
                    if let Ok(n) = c.isoch_in(slot, dci, &mut buf).await {
                        let n = n.min(buf.len());
                        shared.ingest_capture(&buf[..n], frame_bytes);
                    }
                } else {
                    let packet = shared.take_playback_packet(rate_hz, frame_bytes);
                    let _ = c.isoch_out(slot, dci, &packet).await;
                }
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    });
}
