//! virtio-sound over modern virtio-PCI transport (VirtIO 1.2 §5.14).
//!   <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
//!
//! Modern virtio-sound's PCI device id is `0x1040 + 25 = 0x1059`.
//! Four virtqueues:
//!   - 0 = controlq (PCM info / set-params / start / stop verbs).
//!   - 1 = eventq   (jack / PCM / control notifications).
//!   - 2 = txq      (driver → device PCM data; playback).
//!   - 3 = rxq      (device → driver PCM data; capture).
//!
//! Registers the first output stream as playback device 0 and, when the
//! device reports one, the first input stream as capture device 0 in the
//! shared sound registry. The event queue is serviced lazily (on every
//! PCM pointer read and every control read): jack connect/disconnect
//! events update per-jack state exposed as JackSense controls, control
//! notifications are consumed (control reads always round-trip live, so
//! there is no cache to invalidate), and PCM period/xrun events are
//! consumed. Control elements are queried when VIRTIO_SND_F_CTLS is
//! negotiated and mapped role-first onto the registry's mixer kinds;
//! anything without a mixer kind is left unadvertised, never guessed.
//! PCM submissions use owned coherent DMA with exclusive leases and
//! bounded device waits.

use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pci::{
    discover, map_cap, VirtioCaps, VirtioPciError, VirtioRegion, CC_DEVICE_FEATURE,
    CC_DEVICE_FEATURE_SELECT, CC_DEVICE_STATUS, CC_DRIVER_FEATURE, CC_DRIVER_FEATURE_SELECT,
    CC_QUEUE_DESC, CC_QUEUE_DEVICE, CC_QUEUE_DRIVER, CC_QUEUE_ENABLE, CC_QUEUE_NOTIFY_OFF,
    CC_QUEUE_SELECT, CC_QUEUE_SIZE,
};
use crate::queue::{VirtqDesc, Virtqueue, VirtqueueLayout, VIRTQ_DESC_F_WRITE};
use crate::req_gate::ReqGate;

mod sound_card;
use crate::{
    VIRTIO_F_VERSION_1, VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK,
};

// ── Spec constants (VirtIO 1.2 §5.14.6) ─────────────────────────────

// Jack request codes (1.2 §5.14.6).
const VIRTIO_SND_R_JACK_INFO: u32 = 1;

const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;

const VIRTIO_SND_S_OK: u32 = 0x8000;

// virtio_snd_pcm_fmt (VirtIO 1.2 §5.14.6.6.3.1.1).
// IMA_ADPCM=0, MU_LAW=1, A_LAW=2, S8=3, U8=4, S16=5, U16=6, ...
pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;

// virtio_snd_pcm_rate (VirtIO 1.2 §5.14.6.6.3.1.2).
// 5512=0, 8000=1, 11025=2, 16000=3, 22050=4, 32000=5, 44100=6, 48000=7, ...
pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
pub const VIRTIO_SND_PCM_RATE_48000: u8 = 7;

// ── Control-element extension (NOT in VirtIO 1.2) ────────────────────
// VirtIO 1.2 §5.14 has no control elements: no feature bit, no `controls`
// config field, no 0x03xx request codes, no 0x1200 event. The whole
// control-element section below comes from the later extension, verified
// against VirtIO 1.4 csprd01 §5.14.6.10 (the 1.2 PCM/jack/event constants
// above were re-checked against that same text and are unchanged there).
// A device that does not offer VIRTIO_SND_F_CTLS is a pure-1.2 device:
// this driver then never issues a CTL request and never reads the
// `controls` config field, so the extension is inert on such devices.

// Feature bit 0: device supports control elements (1.4 §5.14.3).
const VIRTIO_SND_F_CTLS: u64 = 0;

// Control-element request codes (1.4 §5.14.6.10).
const VIRTIO_SND_R_CTL_INFO: u32 = 0x0300;
const VIRTIO_SND_R_CTL_READ: u32 = 0x0302;
const VIRTIO_SND_R_CTL_WRITE: u32 = 0x0303;

// Event codes (1.2 §5.14.6 jack/PCM; 1.4 §5.14.6.10.4 control notify).
const VIRTIO_SND_EVT_JACK_CONNECTED: u32 = 0x1000;
const VIRTIO_SND_EVT_JACK_DISCONNECTED: u32 = 0x1001;
const VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED: u32 = 0x1100;
const VIRTIO_SND_EVT_PCM_XRUN: u32 = 0x1101;
const VIRTIO_SND_EVT_CTL_NOTIFY: u32 = 0x1200;

// virtio_snd_ctl_role base values (1.4 §5.14.6.10.1). The wire `role`
// field is `(base << 1) | direction`, except UNDEFINED = 0 which carries
// no direction.
const VIRTIO_SND_CTL_ROLE_VOLUME: u32 = 1;
const VIRTIO_SND_CTL_ROLE_MUTE: u32 = 2;
const VIRTIO_SND_CTL_ROLE_GAIN: u32 = 3;

// virtio_snd_ctl_type values (1.4 §5.14.6.10.1).
const VIRTIO_SND_CTL_TYPE_BOOLEAN: u32 = 0;
const VIRTIO_SND_CTL_TYPE_INTEGER: u32 = 1;
const VIRTIO_SND_CTL_TYPE_INTEGER64: u32 = 2;
const VIRTIO_SND_CTL_TYPE_ENUMERATED: u32 = 3;
const VIRTIO_SND_CTL_TYPE_BYTES: u32 = 4;
const VIRTIO_SND_CTL_TYPE_IEC958: u32 = 5;

// virtio_snd_ctl_access bits, as `1 << bit` (1.4 §5.14.6.10.1).
const VIRTIO_SND_CTL_ACCESS_READ: u32 = 0;
const VIRTIO_SND_CTL_ACCESS_WRITE: u32 = 1;

// Wire sizes (1.4 §5.14.6.10.1/§5.14.6.10.2).
const VIRTIO_SND_CTL_INFO_SIZE: usize = 92;
const VIRTIO_SND_CTL_VALUE_SIZE: usize = 512;

pub const VIRTIO_SND_PCI_VENDOR: u16 = 0x1AF4;
pub const VIRTIO_SND_PCI_DEVICE: u16 = 0x1059;

/// Virtio-sound device-cfg layout (VirtIO 1.2 §5.14.4, plus the
/// control-element extension's `controls` field at +12, present only
/// when VIRTIO_SND_F_CTLS is negotiated — 1.4 §5.14.4). All fields
/// little-endian; `repr(C)` mirrors the wire format so we can read
/// the cfg BAR directly.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct VirtioSndConfig {
    pub jacks: u32,
    pub streams: u32,
    pub chmaps: u32,
    pub controls: u32,
}

/// Per-direction PCM lifecycle state. Playback and capture are
/// independent streams with independent verbs, so sharing one
/// `started`/`params` pair between directions (as the old playback-only
/// code did) would let a capture start clobber playback state and
/// vice versa. Each direction owns one of these; all three verbs
/// (prepare/start/stop) take the direction's state explicitly.
#[derive(Debug)]
struct StreamState {
    /// SET_PARAMS + PREPARE done (params slot holds the prepared set).
    prepared: AtomicBool,
    /// START done.
    started: AtomicBool,
    params: IrqSafeSpinLock<Option<PcmParams>>,
}

impl StreamState {
    const fn new() -> Self {
        Self {
            prepared: AtomicBool::new(false),
            started: AtomicBool::new(false),
            params: IrqSafeSpinLock::new(None),
        }
    }
}

/// One parsed control element (1.4 §5.14.6.10.1 `virtio_snd_ctl_info`,
/// 92 bytes). `min`/`max`/`step` are widened to i64 so the INTEGER64
/// form fits; INTEGER values widen from i32. The wire `index` member
/// (offset 20) and the ENUMERATED union member are not retained:
/// element identity is the CTL_INFO query position (`id`, filled by
/// the caller), and ENUMERATED elements are unmapped, so neither
/// value feeds a decision. The 44-byte name is intentionally not
/// stored: mapping is role-first, never name-driven, and names are
/// free-form device strings.
#[derive(Copy, Clone, Debug)]
pub(crate) struct CtlInfo {
    pub(crate) id: u32,
    pub(crate) role: u32,
    pub(crate) ctype: u32,
    pub(crate) access: u32,
    pub(crate) count: u32,
    pub(crate) min: i64,
    pub(crate) max: i64,
    pub(crate) step: i64,
}

impl CtlInfo {
    fn readable(&self) -> bool {
        self.access & (1 << VIRTIO_SND_CTL_ACCESS_READ) != 0
    }
    fn writable(&self) -> bool {
        self.access & (1 << VIRTIO_SND_CTL_ACCESS_WRITE) != 0
    }
}

/// A decoded event-queue notification (`virtio_snd_event`, 8 bytes:
/// code u32 + data u32 — except CTL_NOTIFY, whose data word splits
/// into control_id u16 + mask u16, 1.4 §5.14.6.10.4).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum SndEvent {
    JackConnected(u32),
    JackDisconnected(u32),
    PcmPeriodElapsed(u32),
    PcmXrun(u32),
    CtlNotify { control_id: u16, mask: u16 },
}

/// Decode one 8-byte event slot. Pure: fixtures pin it byte-for-byte
/// without a device. Unknown codes and short buffers decode to `None`
/// (consumed and ignored by the service path, never applied).
pub(crate) fn decode_event(bytes: &[u8]) -> Option<SndEvent> {
    if bytes.len() < 8 {
        return None;
    }
    let code = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let data = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    match code {
        VIRTIO_SND_EVT_JACK_CONNECTED => Some(SndEvent::JackConnected(data)),
        VIRTIO_SND_EVT_JACK_DISCONNECTED => Some(SndEvent::JackDisconnected(data)),
        VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED => Some(SndEvent::PcmPeriodElapsed(data)),
        VIRTIO_SND_EVT_PCM_XRUN => Some(SndEvent::PcmXrun(data)),
        VIRTIO_SND_EVT_CTL_NOTIFY => Some(SndEvent::CtlNotify {
            control_id: (data & 0xFFFF) as u16,
            mask: (data >> 16) as u16,
        }),
        _ => None,
    }
}

/// Apply a decoded jack event to a jack-state slice. Pure: fixtures
/// drive it with a fake slice. Out-of-range jack ids and non-jack
/// events are ignored — a malformed event must never flip state.
pub(crate) fn apply_jack_event(state: &mut [bool], event: SndEvent) {
    let (id, plugged) = match event {
        SndEvent::JackConnected(id) => (id, true),
        SndEvent::JackDisconnected(id) => (id, false),
        _ => return,
    };
    if let Some(slot) = state.get_mut(id as usize) {
        *slot = plugged;
    }
}

/// Split a wire `role` field into (role base, direction). Returns
/// `None` for UNDEFINED and for values outside the (base << 1) |
/// direction encoding, so unmapped roles can never reach the mixer.
/// Note role 1 is also rejected: it would decode to base UNDEFINED
/// with the direction bit set, which the spec's rule — the shifted
/// base must be one of VOLUME/MUTE/GAIN — does not allow.
pub(crate) fn split_ctl_role(role: u32) -> Option<(u32, u32)> {
    if role <= 1 || role > 7 {
        return None;
    }
    Some((role >> 1, role & 1))
}

/// Map a (role base, direction) pair onto a registry mixer kind.
/// Only pairs with an exact kind are mapped: input mutes and output
/// gains have no mixer kind, so those elements stay unadvertised
/// rather than being mislabeled as a different control.
pub(crate) fn ctl_kind_for(
    role_base: u32,
    direction: u32,
) -> Option<narf_drivers_sound::mixer::ControlKind> {
    use narf_drivers_sound::mixer::ControlKind;
    match (role_base, direction) {
        (VIRTIO_SND_CTL_ROLE_VOLUME, 0) => Some(ControlKind::MasterVolume),
        (VIRTIO_SND_CTL_ROLE_VOLUME, 1) => Some(ControlKind::CaptureVolume),
        (VIRTIO_SND_CTL_ROLE_MUTE, 0) => Some(ControlKind::MasterMute),
        (VIRTIO_SND_CTL_ROLE_GAIN, 1) => Some(ControlKind::MicBoost),
        _ => None,
    }
}

/// The registry kind for a control element, or `None` when the element
/// must stay unadvertised (unmapped role/direction, unmapped type, or
/// a value shape the registry cannot carry: INTEGER with more than 2
/// members, BOOLEAN with more than 1).
pub(crate) fn ctl_info_kind(info: &CtlInfo) -> Option<narf_drivers_sound::mixer::ControlKind> {
    let (base, direction) = split_ctl_role(info.role)?;
    let kind = ctl_kind_for(base, direction)?;
    match info.ctype {
        VIRTIO_SND_CTL_TYPE_BOOLEAN if info.count == 1 => Some(kind),
        VIRTIO_SND_CTL_TYPE_INTEGER if (1..=2).contains(&info.count) => Some(kind),
        _ => None,
    }
}

/// Parse one 32-byte `virtio_snd_pcm_info` record (1.2 §5.14.6.6.2).
/// Returns the raw fields; viability filtering is separate
/// ([`PlaybackInfo::is_viable_candidate`]).
pub(crate) fn parse_pcm_info_record(record: &[u8]) -> Option<PlaybackInfo> {
    if record.len() != 32 {
        return None;
    }
    Some(PlaybackInfo {
        formats: u64::from_le_bytes(record[8..16].try_into().unwrap()),
        rates: u64::from_le_bytes(record[16..24].try_into().unwrap()),
        direction: record[24],
        channels_min: record[25],
        channels_max: record[26],
    })
}

/// Parse one 24-byte `virtio_snd_jack_info` record (1.2 §5.14.6.4.1).
/// The `connected` byte sits at offset 16 (4 hda_fn_nid + 4 features +
/// 4 defconf + 4 caps). Values other than 0/1 are undefined by the
/// spec and parse to `None` rather than being guessed.
pub(crate) fn parse_jack_info_record(record: &[u8]) -> Option<bool> {
    if record.len() != 24 {
        return None;
    }
    match record[16] {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// Parse one 92-byte `virtio_snd_ctl_info` record (1.4 §5.14.6.10.1).
/// Returns `None` for structurally invalid records (undefined role,
/// type, or access bits; zero count; count above the type's spec
/// maximum): one bad element must not poison the whole query.
pub(crate) fn parse_ctl_info_record(record: &[u8]) -> Option<CtlInfo> {
    if record.len() != VIRTIO_SND_CTL_INFO_SIZE {
        return None;
    }
    let role = u32::from_le_bytes(record[4..8].try_into().unwrap());
    let ctype = u32::from_le_bytes(record[8..12].try_into().unwrap());
    let access = u32::from_le_bytes(record[12..16].try_into().unwrap());
    let count = u32::from_le_bytes(record[16..20].try_into().unwrap());
    if role > 7 || ctype > VIRTIO_SND_CTL_TYPE_IEC958 || access & !0x7F != 0 || count == 0 {
        return None;
    }
    let max_count = match ctype {
        VIRTIO_SND_CTL_TYPE_BOOLEAN
        | VIRTIO_SND_CTL_TYPE_INTEGER
        | VIRTIO_SND_CTL_TYPE_ENUMERATED => 128,
        VIRTIO_SND_CTL_TYPE_INTEGER64 => 64,
        VIRTIO_SND_CTL_TYPE_BYTES => 512,
        VIRTIO_SND_CTL_TYPE_IEC958 => 1,
        _ => return None,
    };
    if count > max_count {
        return None;
    }
    let (min, max, step) = match ctype {
        VIRTIO_SND_CTL_TYPE_INTEGER64 => (
            i64::from_le_bytes(record[68..76].try_into().unwrap()),
            i64::from_le_bytes(record[76..84].try_into().unwrap()),
            i64::from_le_bytes(record[84..92].try_into().unwrap()),
        ),
        VIRTIO_SND_CTL_TYPE_ENUMERATED => (0, 0, 0),
        _ => (
            i32::from_le_bytes(record[68..72].try_into().unwrap()) as i64,
            i32::from_le_bytes(record[72..76].try_into().unwrap()) as i64,
            i32::from_le_bytes(record[76..80].try_into().unwrap()) as i64,
        ),
    };
    Some(CtlInfo {
        id: 0, // Filled in by the caller: the id is the query position.
        role,
        ctype,
        access,
        count,
        min,
        max,
        step,
    })
}

#[derive(Debug)]
pub struct VirtioSoundPci {
    /// Common configuration window retained so teardown can reset the
    /// transport before any queue-backed DMA memory is released.
    common: VirtioRegion,
    control_q: IrqSafeSpinLock<Option<Virtqueue>>,
    event_q: IrqSafeSpinLock<Option<Virtqueue>>,
    tx_q: IrqSafeSpinLock<Option<Virtqueue>>,
    rx_q: IrqSafeSpinLock<Option<Virtqueue>>,
    _q_buf_control: DmaBuffer,
    _q_buf_event: DmaBuffer,
    _q_buf_tx: DmaBuffer,
    _q_buf_rx: DmaBuffer,
    /// Notify region + per-queue notify offsets, captured at probe.
    /// Writing a 2-byte 0 to `notify.virt + notify_off_mul *
    /// queue_notify_off[i]` kicks queue `i`.
    notify: VirtioRegion,
    notify_off_multiplier: u32,
    queue_notify_off: [u16; 4],
    /// Scratch DMA region for synchronous control-vq round-trips.
    /// Big enough for `virtio_snd_pcm_set_params` (24 B) + the
    /// response (4 B); we lay them out at +0 and +64 so the
    /// device-write-back doesn't stomp the request mid-flight.
    ctrl_buf: DmaBuffer,
    /// Scratch DMA region for tx-vq submissions: header (8 B at
    /// +0) + payload (up to 4024 B at +64) + status (8 B at
    /// +4088). One outstanding submission at a time today; a
    /// pool lands when the user-facing surface needs concurrency.
    tx_buf: DmaBuffer,
    /// Event-queue slot memory: 4 posted 8-byte device-writable
    /// buffers, one per event-queue entry. `event_slot_head[i]` is
    /// the descriptor head currently posted for slot `i` (None when
    /// the slot is not posted); the service path matches used
    /// completions back to slots through these heads.
    _event_buf: DmaBuffer,
    event_slot_head: IrqSafeSpinLock<[Option<u16>; 4]>,
    /// Scratch DMA region for CTL_WRITE round-trips, which the shared
    /// ctrl scratch cannot serve: a write request is 8-byte header +
    /// 512-byte value = 520 bytes, past the ctrl scratch's 60-byte
    /// request cap and overlapping its +64 response slot. Layout
    /// here is request at +0 (520 B) and the 4-byte status at +1024.
    ctl_write_buf: DmaBuffer,
    /// Per-direction lifecycle state. Playback and capture are
    /// independent streams with independent verbs, so sharing one
    /// `started`/`params` pair between directions (as the old
    /// playback-only code did) would let a capture start clobber
    /// playback state and vice versa. Written only under `req_gate`,
    /// so plain atomics suffice — crucially no IRQ-masking lock is
    /// held across the control round-trips the sequences issue.
    playback: StreamState,
    capture: StreamState,
    claimed: AtomicBool,
    capture_claimed: AtomicBool,
    failed: AtomicBool,
    playback_info: Option<PlaybackInfo>,
    playback_stream_id: u32,
    capture_info: Option<PlaybackInfo>,
    capture_stream_id: Option<u32>,
    /// Whether VIRTIO_SND_F_CTLS was negotiated. False on pure-1.2
    /// devices, where no CTL request is ever issued and the
    /// `controls` config field is never read.
    ctls: bool,
    /// Parsed control elements (empty when CTLS was not negotiated
    /// or the device reports none). Order is device order.
    ctl_infos: Vec<CtlInfo>,
    /// Current jack connection state, one entry per jack id. Seeded
    /// from JACK_INFO at probe, corrected by event-queue jack events
    /// thereafter. Exposed through JackSense controls.
    jack_connected: IrqSafeSpinLock<Vec<bool>>,
    /// Serialises the shared ctrl/tx scratch and the SET_PARAMS →
    /// PREPARE → START sequence WITHOUT masking interrupts while
    /// waiting — see [`crate::req_gate`]. The device may legitimately
    /// hold a PCM buffer for multiple milliseconds before acking, so
    /// waiting here with interrupts masked (as the old global
    /// CONTROLLER hold did) starved timers/RCU on every submit.
    req_gate: AtomicBool,
    pub cfg: VirtioSndConfig,
    pub ready: bool,
}

impl VirtioSoundPci {
    /// Reset the device and wait until it can no longer access the old
    /// virtqueues.
    ///
    /// VirtIO 1.2 section 2.4.2 requires the driver to observe
    /// `device_status == 0` before reinitializing a device. Linux's modern
    /// virtio-pci reset path follows the same ordering before freeing queues.
    fn reset_device(&self) -> bool {
        // SAFETY: `common` remains mapped for the controller's lifetime and
        // this controller exclusively owns the device.
        unsafe {
            self.common.write8(CC_DEVICE_STATUS, 0);
        }
        narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: same live common-cfg mapping as the reset write.
                unsafe { self.common.read8(CC_DEVICE_STATUS) == 0 }
            },
            narf_time::Deadline::after_ms(1_000),
        )
    }

    /// # Safety
    /// Caller owns the device exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VirtioPciError> {
        // SAFETY: bounded walk.
        let caps: VirtioCaps = unsafe { discover(device) }?;
        // SAFETY: caller-owned.
        let common = unsafe { map_cap(device, &caps.common) }?;

        // Reset + ACK + DRIVER. The specification requires observing zero
        // before reinitializing; in particular, that observation guarantees
        // that the device has stopped using queue memory from a prior driver.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            common.write8(CC_DEVICE_STATUS, 0);
        }
        let reset = narf_scheduler::responsive_spin_until(
            || {
                // SAFETY: caller-owned, live common-cfg mapping.
                unsafe { common.read8(CC_DEVICE_STATUS) == 0 }
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if !reset {
            return Err(VirtioPciError::CompletionTimeout);
        }
        // SAFETY: reset completion was observed above; status negotiation may
        // now begin on the same caller-owned common-cfg mapping.
        unsafe {
            common.write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u8);
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u8,
            );
        }

        // Feature negotiation: VERSION_1, plus VIRTIO_SND_F_CTLS when
        // the device offers it. The low word is otherwise written as
        // zero: no other low-word feature is used, and a feature must
        // never be negotiated that the device did not offer.
        // SAFETY: same.
        let feats_lo = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 0);
            common.read32(CC_DEVICE_FEATURE)
        };
        // SAFETY: same.
        let feats_hi = unsafe {
            common.write32(CC_DEVICE_FEATURE_SELECT, 1);
            common.read32(CC_DEVICE_FEATURE)
        };
        let feats = (feats_hi as u64) << 32 | feats_lo as u64;
        if feats & (1u64 << VIRTIO_F_VERSION_1) == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let ctls = feats & (1u64 << VIRTIO_SND_F_CTLS) != 0;
        // SAFETY: same.
        unsafe {
            common.write32(CC_DRIVER_FEATURE_SELECT, 0);
            common.write32(CC_DRIVER_FEATURE, u32::from(ctls));
            common.write32(CC_DRIVER_FEATURE_SELECT, 1);
            common.write32(CC_DRIVER_FEATURE, 1u32 << (VIRTIO_F_VERSION_1 - 32));
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK)
                    as u8,
            );
        }
        // SAFETY: same.
        let post = unsafe { common.read8(CC_DEVICE_STATUS) };
        if post & VIRTIO_STATUS_FEATURES_OK as u8 == 0 {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // Read device-cfg topology. The device cap's BAR is the
        // start of the device-cfg window; layout is
        // `virtio_snd_config { u32 jacks, streams, chmaps }` in 1.2,
        // plus `u32 controls` at +12 under the control-element
        // extension. The controls field MUST NOT be read unless
        // VIRTIO_SND_F_CTLS was negotiated (1.4 §5.14.5.1): on a
        // pure-1.2 device offset +12 is outside the defined config.
        // device_cfg is optional in the spec, but every QEMU
        // virtio-sound advertises it.
        let dev_cap = caps
            .device_cfg
            .as_ref()
            .ok_or(VirtioPciError::DeviceRejectedFeatures)?;
        // SAFETY: caller-owned device, identity-mapped MMIO.
        let dev_cfg = unsafe { map_cap(device, dev_cap) }?;
        // SAFETY: same.
        let cfg = unsafe {
            VirtioSndConfig {
                jacks: dev_cfg.read32(0),
                streams: dev_cfg.read32(4),
                chmaps: dev_cfg.read32(8),
                controls: if ctls { dev_cfg.read32(12) } else { 0 },
            }
        };

        // Map the notify cap and capture its multiplier — needed
        // to kick queues after submission.
        // SAFETY: caller-owned device.
        let notify = unsafe { map_cap(device, &caps.notify) }?;
        let notify_off_multiplier = caps.notify.notify_off_multiplier;
        let mut queue_notify_off = [0u16; 4];

        // Set up four virtqueues: 0=control, 1=event, 2=tx, 3=rx.
        // Each gets a 4 KiB coherent buffer for descriptor + ring
        // storage. The ALSA playback path keeps the whole ring in flight
        // as 3-descriptor messages, so tx gets the deepest queue that
        // still fits one page (128 entries = 42 messages). Capture
        // pre-posts empty period buffers the same way, so rx gets 32
        // entries (10 messages) instead of 4: with a single in-flight
        // message any scheduling delay between reap and repost is an
        // overrun. Control and event stay at 4 (one control round-trip
        // and a handful of rare notifications at a time).
        let mut setup_q = |idx: u16| -> Result<(VirtqueueLayout, DmaBuffer), VirtioPciError> {
            // SAFETY: identity-mapped MMIO.
            let qmax = unsafe {
                common.write16(CC_QUEUE_SELECT, idx);
                common.read16(CC_QUEUE_SIZE)
            };
            if qmax == 0 {
                return Err(VirtioPciError::QueueTooSmall);
            }
            let qsize = match idx {
                2 => 128u16,
                3 => 32u16,
                _ => 4,
            }
            .min(qmax);
            let buf = alloc_coherent(4096, DomainId::DRIVER_0)
                .map_err(|_| VirtioPciError::BarMapFailed)?;
            let layout = VirtqueueLayout::new(qsize, buf.dma_addr().raw())
                .ok_or(VirtioPciError::QueueTooSmall)?;
            // SAFETY: same.
            unsafe {
                common.write16(CC_QUEUE_SIZE, qsize);
                common.write64_split(CC_QUEUE_DESC, layout.desc_table);
                common.write64_split(CC_QUEUE_DRIVER, layout.avail_ring);
                common.write64_split(CC_QUEUE_DEVICE, layout.used_ring);
                common.write16(crate::pci::CC_QUEUE_MSIX_VECTOR, 0xFFFF);
                common.write16(CC_QUEUE_ENABLE, 1);
            }
            // SAFETY: same.
            let off = unsafe { common.read16(CC_QUEUE_NOTIFY_OFF) };
            queue_notify_off[idx as usize] = off;
            Ok((layout, buf))
        };
        let (ctrl_layout, ctrl_buf) = setup_q(0)?;
        let (event_layout, event_buf) = setup_q(1)?;
        let (tx_layout, tx_buf) = setup_q(2)?;
        let (rx_layout, rx_buf) = setup_q(3)?;

        // Scratch DMA buffers for ctrl + tx round-trips. Allocated
        // once at probe so submissions don't allocate on the hot
        // path.
        let ctrl_scratch =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let tx_scratch =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        // Event-queue slot memory (4 × 8-byte device-writable slots)
        // and the CTL_WRITE scratch (520-byte request + 4-byte status
        // at +1024). Both allocated once at probe.
        let event_slot_buf =
            alloc_coherent(128, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;
        let ctl_write_buf =
            alloc_coherent(2048, DomainId::DRIVER_0).map_err(|_| VirtioPciError::BarMapFailed)?;

        // DRIVER_OK.
        // SAFETY: same.
        unsafe {
            common.write8(
                CC_DEVICE_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE
                    | VIRTIO_STATUS_DRIVER
                    | VIRTIO_STATUS_FEATURES_OK
                    | VIRTIO_STATUS_DRIVER_OK) as u8,
            );
        }

        // SAFETY: Virtqueue::new wipes the layout regions; the
        // backing pages may be recycled (alloc_frame doesn't zero).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let control_q = unsafe { Virtqueue::new(ctrl_layout) };
        // SAFETY: same.
        let mut event_q = unsafe { Virtqueue::new(event_layout) };
        // SAFETY: same.
        let tx_q = unsafe { Virtqueue::new(tx_layout) };
        // SAFETY: same.
        let rx_q = unsafe { Virtqueue::new(rx_layout) };
        // Populate the event queue (spec initialization step 6):
        // one 8-byte device-writable buffer per entry, then a kick so
        // the device knows buffers are available. A slot that fails
        // to post stays unposted; the service path reposts only slots
        // it knows about, so this degrades to fewer live slots, never
        // to a buffer the device does not own.
        let event_phys = event_slot_buf.dma_addr().raw();
        let mut event_slot_head: [Option<u16>; 4] = [None; 4];
        for (slot, head_slot) in event_slot_head.iter_mut().enumerate() {
            let desc = VirtqDesc {
                addr: event_phys + slot as u64 * 8,
                len: 8,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };
            if let Some(head) = event_q.add_buffer(&[desc]) {
                *head_slot = Some(head);
            }
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            notify.write16(notify_off_multiplier as u64 * queue_notify_off[1] as u64, 1);
        }
        Ok(Self {
            common,
            control_q: IrqSafeSpinLock::new(Some(control_q)),
            event_q: IrqSafeSpinLock::new(Some(event_q)),
            tx_q: IrqSafeSpinLock::new(Some(tx_q)),
            rx_q: IrqSafeSpinLock::new(Some(rx_q)),
            _q_buf_control: ctrl_buf,
            _q_buf_event: event_buf,
            _q_buf_tx: tx_buf,
            _q_buf_rx: rx_buf,
            notify,
            notify_off_multiplier,
            queue_notify_off,
            ctrl_buf: ctrl_scratch,
            tx_buf: tx_scratch,
            _event_buf: event_slot_buf,
            event_slot_head: IrqSafeSpinLock::new(event_slot_head),
            ctl_write_buf,
            playback: StreamState::new(),
            capture: StreamState::new(),
            claimed: AtomicBool::new(false),
            capture_claimed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            playback_info: None,
            playback_stream_id: 0,
            capture_info: None,
            capture_stream_id: None,
            ctls,
            ctl_infos: Vec::new(),
            jack_connected: IrqSafeSpinLock::new(Vec::new()),
            req_gate: AtomicBool::new(false),
            cfg,
            ready: true,
        })
    }

    /// Submit a request to the control vq + poll for the response.
    /// `req` is copied into the ctrl scratch buffer at offset 0;
    /// the device writes its `virtio_snd_hdr { u32 status }` at
    /// offset 64. Returns the response status code.
    ///
    /// Caller must hold the request gate (the ctrl scratch is shared).
    fn ctrl_request(&self, req: &[u8]) -> Result<u32, VirtioPciError> {
        self.ctrl_request_data(req, &mut [])
    }

    fn ctrl_request_data(&self, req: &[u8], response: &mut [u8]) -> Result<u32, VirtioPciError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        if req.len() > 60 || response.len() > 4028 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let req_phys = self.ctrl_buf.dma_addr().raw();
        let resp_phys = req_phys + 64;
        // SAFETY: identity-mapped DMA. Bulk copy — coherent DMA memory,
        // not MMIO; ordering vs. the device comes from the SeqCst fence
        // before the notify write below.
        unsafe {
            core::ptr::copy_nonoverlapping(
                req.as_ptr(),
                self.ctrl_buf.cpu_mut_ptr::<u8>(),
                req.len(),
            );
            // Pre-clear the response slot so we can detect a
            // device that didn't write anything.
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(resp_phys).kernel_mut_ptr::<u32>(),
                0xFFFF_FFFF,
            );
        }
        let descs = [
            VirtqDesc {
                addr: req_phys,
                len: req.len() as u32,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: resp_phys,
                len: 4 + response.len() as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = {
            let mut g = self.control_q.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(
                self.notify_off_multiplier as u64 * self.queue_notify_off[0] as u64,
                0,
            );
        }
        // Poll used ring for the matching head, bounded.
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay alive.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.control_q.lock();
                    match g.as_mut() {
                        Some(q) => q.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                matches!(elem, Some((id, _)) if id == head as u32)
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        if !done {
            self.failed.store(true, Ordering::Release);
            // A timed-out request still belongs to the device. Reset before
            // returning; never recycle its descriptor or shared scratch.
            assert!(self.reset_device(), "virtio-snd control reset failed");
            return Err(VirtioPciError::QueueTooSmall);
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(resp_phys).kernel_ptr::<u32>())
        };
        if status == VIRTIO_SND_S_OK {
            // SAFETY: completion transferred ownership back to the driver;
            // the response length fits the coherent scratch allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    narf_memory::PhysAddr::new(resp_phys + 4).kernel_ptr::<u8>(),
                    response.as_mut_ptr(),
                    response.len(),
                );
            }
        }
        let mut g = self.control_q.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        Ok(status)
    }

    /// Notify the device that the tx queue has new buffers.
    fn kick_tx(&self) {
        self.kick_queue(2);
    }

    /// Notify the device that the rx queue has new buffers.
    fn kick_rx(&self) {
        self.kick_queue(3);
    }

    /// Notify the device that the event queue has new buffers.
    fn kick_event(&self) {
        self.kick_queue(1);
    }

    fn kick_queue(&self, idx: usize) {
        // SAFETY: identity-mapped notify region captured at probe.
        unsafe {
            self.notify.write16(
                self.notify_off_multiplier as u64 * self.queue_notify_off[idx] as u64,
                idx as u16,
            );
        }
    }

    /// Run SET_PARAMS + PREPARE + START on the playback stream if not
    /// already started. Idempotent. Thin wrapper over the generalized
    /// per-direction sequence; kept so the playback path is untouched.
    ///
    /// Caller must hold the request gate, which is what makes the
    /// check-then-sequence race-free.
    fn ensure_started(&self, params: PcmParams) -> Result<(), VirtioPciError> {
        let info = self.playback_info.ok_or(VirtioPciError::NoQueues)?;
        self.stream_prepare(&self.playback, self.playback_stream_id, info, params)?;
        self.stream_start(&self.playback, self.playback_stream_id)
    }

    /// Caller holds the request gate; no IRQ-masking guard spans device waits.
    /// Playback wrapper over the generalized stop.
    fn stop_pcm_locked(&self) -> Result<(), VirtioPciError> {
        self.stream_stop(&self.playback, self.playback_stream_id)
    }

    /// SET_PARAMS + PREPARE for one direction's stream, idempotent.
    /// A started stream with the same params is already prepared;
    /// a started stream with different params is stopped first
    /// (STOP + RELEASE); a merely-prepared stream takes SET_PARAMS
    /// directly, which the lifecycle allows from PREPARE.
    /// Caller must hold the request gate.
    fn stream_prepare(
        &self,
        state: &StreamState,
        stream_id: u32,
        info: PlaybackInfo,
        params: PcmParams,
    ) -> Result<(), VirtioPciError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        if !info.supports(params) {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        if state.started.load(Ordering::Acquire) {
            if *state.params.lock() == Some(params) {
                return Ok(());
            }
            self.stream_stop(state, stream_id)?;
        } else if state.prepared.load(Ordering::Acquire) && *state.params.lock() == Some(params) {
            return Ok(());
        }

        // SET_PARAMS request: virtio_snd_pcm_set_params layout.
        //   +0  hdr.code (u32)        = VIRTIO_SND_R_PCM_SET_PARAMS
        //   +4  hdr.stream_id (u32)
        //   +8  buffer_bytes (u32)
        //   +12 period_bytes (u32)
        //   +16 features (u32)        = 0
        //   +20 channels (u8)
        //   +21 format (u8)
        //   +22 rate (u8)
        //   +23 padding (u8)
        let mut req = [0u8; 24];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_SET_PARAMS.to_le_bytes());
        req[4..8].copy_from_slice(&stream_id.to_le_bytes());
        req[8..12].copy_from_slice(&params.buffer_bytes.to_le_bytes());
        req[12..16].copy_from_slice(&params.period_bytes.to_le_bytes());
        req[16..20].copy_from_slice(&0u32.to_le_bytes());
        req[20] = params.channels;
        req[21] = params.format;
        req[22] = params.rate;
        let s = self.ctrl_request(&req)?;
        if s != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        // PREPARE: virtio_snd_pcm_hdr { code, stream_id }.
        let mut req = [0u8; 8];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_PREPARE.to_le_bytes());
        req[4..8].copy_from_slice(&stream_id.to_le_bytes());
        let s = self.ctrl_request(&req)?;
        if s != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }

        state.prepared.store(true, Ordering::Release);
        *state.params.lock() = Some(params);
        Ok(())
    }

    /// START for one direction's stream. The stream must already be
    /// prepared; starting an unprepared stream is a lifecycle error
    /// and is refused here rather than sent to the device.
    /// Caller must hold the request gate.
    fn stream_start(&self, state: &StreamState, stream_id: u32) -> Result<(), VirtioPciError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        if state.started.load(Ordering::Acquire) {
            return Ok(());
        }
        if !state.prepared.load(Ordering::Acquire) {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        let mut req = [0u8; 8];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_START.to_le_bytes());
        req[4..8].copy_from_slice(&stream_id.to_le_bytes());
        let s = self.ctrl_request(&req)?;
        if s != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        state.started.store(true, Ordering::Release);
        Ok(())
    }

    /// STOP + RELEASE for a started stream, RELEASE alone for a
    /// merely-prepared one, nothing for an untouched one. A failed
    /// verb poisons the controller and resets the device, mirroring
    /// the old playback-only stop: DMA storage must never be freed
    /// while the device may still own it.
    /// Caller must hold the request gate.
    fn stream_stop(&self, state: &StreamState, stream_id: u32) -> Result<(), VirtioPciError> {
        let started = state.started.load(Ordering::Acquire);
        let prepared = state.prepared.load(Ordering::Acquire);
        if !started && !prepared {
            return Ok(());
        }
        // A started stream takes STOP then RELEASE; a merely-prepared
        // one takes RELEASE alone (STOP is not a valid transition
        // from PREPARE).
        let mut commands: [u32; 2] = [VIRTIO_SND_R_PCM_RELEASE, VIRTIO_SND_R_PCM_RELEASE];
        let mut count = 1;
        if started {
            commands = [VIRTIO_SND_R_PCM_STOP, VIRTIO_SND_R_PCM_RELEASE];
            count = 2;
        }
        for command in &commands[..count] {
            let mut request = [0; 8];
            request[..4].copy_from_slice(&command.to_le_bytes());
            request[4..8].copy_from_slice(&stream_id.to_le_bytes());
            if self.ctrl_request(&request)? != VIRTIO_SND_S_OK {
                self.failed.store(true, Ordering::Release);
                assert!(self.reset_device(), "virtio-snd stop reset failed");
                return Err(VirtioPciError::DeviceRejectedFeatures);
            }
        }
        state.started.store(false, Ordering::Release);
        state.prepared.store(false, Ordering::Release);
        *state.params.lock() = None;
        Ok(())
    }

    /// CTL_READ round-trip for one control element (1.4 §5.14.6.10.2):
    /// 8-byte `virtio_snd_ctl_hdr` request, 4-byte status + 512-byte
    /// value response. Caller must hold the request gate (the shared
    /// ctrl scratch and control queue are not per-caller).
    fn ctl_read_value(&self, control_id: u32) -> Result<[u8; 512], VirtioPciError> {
        let mut req = [0u8; 8];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_CTL_READ.to_le_bytes());
        req[4..8].copy_from_slice(&control_id.to_le_bytes());
        let mut value = [0u8; VIRTIO_SND_CTL_VALUE_SIZE];
        let status = self.ctrl_request_data(&req, &mut value)?;
        if status != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(value)
    }

    /// CTL_WRITE round-trip (1.4 §5.14.6.10.2): 8-byte header +
    /// 512-byte value request, 4-byte status response. Uses the
    /// dedicated CTL_WRITE scratch, not the shared ctrl scratch
    /// (whose 60-byte request cap a 520-byte write exceeds).
    /// Caller must hold the request gate.
    fn ctl_write_value(&self, control_id: u32, value: &[u8; 512]) -> Result<(), VirtioPciError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        let req_phys = self.ctl_write_buf.dma_addr().raw();
        let resp_phys = req_phys + 1024;
        // SAFETY: identity-mapped DMA. Bulk copy — coherent DMA memory,
        // not MMIO; ordering vs. the device comes from the SeqCst fence
        // before the notify write below.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(req_phys).kernel_mut_ptr::<u32>(),
                VIRTIO_SND_R_CTL_WRITE,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(req_phys + 4).kernel_mut_ptr::<u32>(),
                control_id,
            );
            core::ptr::copy_nonoverlapping(
                value.as_ptr(),
                narf_memory::PhysAddr::new(req_phys + 8).kernel_mut_ptr::<u8>(),
                VIRTIO_SND_CTL_VALUE_SIZE,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(resp_phys).kernel_mut_ptr::<u32>(),
                0xFFFF_FFFF,
            );
        }
        let descs = [
            VirtqDesc {
                addr: req_phys,
                len: 8 + VIRTIO_SND_CTL_VALUE_SIZE as u32,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: resp_phys,
                len: 4,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = {
            let mut g = self.control_q.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(
                self.notify_off_multiplier as u64 * self.queue_notify_off[0] as u64,
                0,
            );
        }
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.control_q.lock();
                    match g.as_mut() {
                        Some(q) => q.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                matches!(elem, Some((id, _)) if id == head as u32)
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        if !done {
            self.failed.store(true, Ordering::Release);
            assert!(self.reset_device(), "virtio-snd control reset failed");
            return Err(VirtioPciError::QueueTooSmall);
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(resp_phys).kernel_ptr::<u32>())
        };
        let mut g = self.control_q.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        if status != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Service the event queue: reap every completed event buffer,
    /// apply jack events to jack state, consume everything else, and
    /// repost each consumed slot. Never blocks and never takes the
    /// request gate (event buffers are independent of control
    /// scratch), so PCM pointer reads and control reads can call it
    /// freely. There is no pump task and no MSI-X on this driver
    /// (vector 0xFFFF), so lazy polling here is the service model.
    pub(crate) fn service_events(&self) {
        // Phase 1: reap completed buffer heads.
        let mut done: [u32; 4] = [0; 4];
        let mut count = 0;
        {
            let mut g = self.event_q.lock();
            let Some(q) = g.as_mut() else {
                return;
            };
            while count < 4 {
                match q.poll_used() {
                    Some((id, _)) => {
                        done[count] = id;
                        count += 1;
                    }
                    None => break,
                }
            }
        }
        if count == 0 {
            return;
        }
        // Phase 2: decode, apply, repost per slot.
        let event_phys = self._event_buf.dma_addr().raw();
        let mut reposted = false;
        for &id in &done[..count] {
            let slot = {
                let mut heads = self.event_slot_head.lock();
                let found = heads.iter().position(|h| *h == Some(id as u16));
                if let Some(slot) = found {
                    heads[slot] = None;
                }
                found
            };
            let Some(slot) = slot else {
                // Stale completion for a slot we no longer track:
                // drop it rather than reposting unknown memory.
                continue;
            };
            let mut bytes = [0u8; 8];
            // SAFETY: the device returned this slot, so its 8 bytes
            // are driver-owned again and lie within the event buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    narf_memory::PhysAddr::new(event_phys + slot as u64 * 8).kernel_ptr::<u8>(),
                    bytes.as_mut_ptr(),
                    8,
                );
            }
            if let Some(event) = decode_event(&bytes) {
                let mut state = self.jack_connected.lock();
                apply_jack_event(&mut state, event);
            }
            // Free the consumed chain, then repost the same slot.
            let mut g = self.event_q.lock();
            let Some(q) = g.as_mut() else {
                continue;
            };
            q.free_chain(id as u16);
            let desc = VirtqDesc {
                addr: event_phys + slot as u64 * 8,
                len: 8,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };
            if let Some(head) = q.add_buffer(&[desc]) {
                *self
                    .event_slot_head
                    .lock()
                    .get_mut(slot)
                    .expect("event slot index is bounded by the queue depth") = Some(head);
                reposted = true;
            }
        }
        if reposted {
            compiler_fence(Ordering::SeqCst);
            self.kick_event();
        }
    }

    /// Find the control element a registry `ControlId` names, or
    /// `None` when the id is not an advertised control. Membership is
    /// exact: the element must forward-map to exactly this kind at
    /// exactly this element id, so a forged id naming an unmapped
    /// element (wrong type, wrong count, unmapped role) never
    /// resolves.
    pub(crate) fn ctl_element_for(
        &self,
        id: narf_drivers_sound::mixer::ControlId,
    ) -> Option<CtlInfo> {
        self.ctl_infos
            .iter()
            .find(|info| info.id == id.index && ctl_info_kind(info) == Some(id.kind))
            .copied()
    }

    /// Generic PCM submit: header + status come from the
    /// per-controller scratch (small, fixed); the payload
    /// descriptor points at caller-supplied phys. The payload
    /// must be physically contiguous for `payload_len` bytes
    /// (single-page from a `narf-shmem` region, or any kernel
    /// `DmaBuffer`).
    ///
    /// Blocks until the device acks via the tx vq used ring — which
    /// routinely takes multiple milliseconds, since the device may not
    /// ack a PCM buffer until it has consumed it. The wait happens
    /// under the device's request gate with interrupts ENABLED; no
    /// global or IRQ-masking lock is held.
    pub fn play_buffer_phys(
        &self,
        params: PcmParams,
        payload_phys: u64,
        payload_len: u32,
    ) -> Result<(), VirtioPciError> {
        let _gate = ReqGate::acquire(&self.req_gate);
        if self.claimed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        self.play_buffer_phys_locked(params, payload_phys, payload_len)
    }

    /// Gate-free body of [`play_buffer_phys`]; caller must hold the
    /// request gate (it protects the shared ctrl/tx scratch and the
    /// single-outstanding-submission contract).
    fn play_buffer_phys_locked(
        &self,
        params: PcmParams,
        payload_phys: u64,
        payload_len: u32,
    ) -> Result<(), VirtioPciError> {
        if payload_len == 0 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        // virtio-spec requires the payload not cross into
        // unmapped pages; that's the caller's contract on
        // `payload_phys + payload_len`.
        self.ensure_started(params)?;

        // Header (+0) and status (+4088) live in the controller's
        // 4 KiB scratch. Per-controller, single-outstanding-submit
        // today; concurrency lands when AudioWriter grows a
        // submission ring.
        let base = self.tx_buf.dma_addr().raw();
        let hdr_phys = base;
        let status_phys = base + 4088;

        // SAFETY: identity-mapped scratch DMA.
        unsafe {
            // virtio_snd_pcm_xfer { u32 stream_id, u32 padding }
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(hdr_phys).kernel_mut_ptr::<u32>(),
                self.playback_stream_id,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(hdr_phys + 4).kernel_mut_ptr::<u32>(),
                0u32,
            );
            // Pre-clear status to detect non-write-back.
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys).kernel_mut_ptr::<u32>(),
                0xFFFF_FFFF,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(status_phys + 4).kernel_mut_ptr::<u32>(),
                0u32,
            );
        }
        let descs = [
            VirtqDesc {
                addr: hdr_phys,
                len: 8,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: payload_phys,
                len: payload_len,
                flags: 0,
                next: 0,
            },
            VirtqDesc {
                addr: status_phys,
                len: 8,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let head = {
            let mut g = self.tx_q.lock();
            let q = g.as_mut().ok_or(VirtioPciError::NoQueues)?;
            q.add_buffer(&descs).ok_or(VirtioPciError::QueueTooSmall)?
        };
        compiler_fence(Ordering::SeqCst);
        // SAFETY: identity-mapped notify region.
        unsafe {
            self.notify.write16(
                self.notify_off_multiplier as u64 * self.queue_notify_off[2] as u64,
                2,
            );
        }
        // responsive_spin_until ticks sleep_pumps so cursor/FB / audio
        // pump itself stay alive while waiting for tx-q completion.
        let mut q_err = false;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let elem = {
                    let mut g = self.tx_q.lock();
                    match g.as_mut() {
                        Some(q) => q.poll_used(),
                        None => {
                            q_err = true;
                            return true;
                        }
                    }
                };
                matches!(elem, Some((id, _)) if id == head as u32)
            },
            narf_time::Deadline::after_ms(1_000),
        );
        if q_err {
            return Err(VirtioPciError::NoQueues);
        }
        if !done {
            self.failed.store(true, Ordering::Release);
            // Caller-owned PCM storage cannot be released until DMA stops.
            assert!(self.reset_device(), "virtio-snd playback reset failed");
            return Err(VirtioPciError::QueueTooSmall);
        }
        // SAFETY: identity-mapped DMA.
        let status = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(status_phys).kernel_ptr::<u32>())
        };
        let mut g = self.tx_q.lock();
        if let Some(q) = g.as_mut() {
            q.free_chain(head);
        }
        if status != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        Ok(())
    }

    /// Slice-friendly wrapper. Copies `pcm` into the controller's
    /// payload-scratch region within the existing tx_buf, then
    /// submits whole-frame chunks of at most 4024 bytes. The completion
    /// status occupies the remaining eight bytes of the scratch page.
    pub fn play_buffer(&self, params: PcmParams, pcm: &[u8]) -> Result<(), VirtioPciError> {
        // The gate must cover the payload copy too, or two concurrent
        // players could interleave their copies into the shared scratch
        // and then serialise only the submits.
        let _gate = ReqGate::acquire(&self.req_gate);
        if self.claimed.load(Ordering::Acquire) {
            return Err(VirtioPciError::NoQueues);
        }
        let frame_bytes = usize::from(params.channels) * 2;
        if frame_bytes == 0 || frame_bytes > 4024 || pcm.len() % frame_bytes != 0 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        for chunk in pcm.chunks(4024 / frame_bytes * frame_bytes) {
            self.play_buffer_locked(params, chunk)?;
        }
        Ok(())
    }

    fn play_buffer_locked(&self, params: PcmParams, pcm: &[u8]) -> Result<(), VirtioPciError> {
        // Status starts at 4088 and payload at 64: 4024 usable bytes.
        if pcm.is_empty() || pcm.len() > 4024 {
            return Err(VirtioPciError::QueueTooSmall);
        }
        let base = self.tx_buf.dma_addr().raw();
        let payload_phys = base + 64;
        // SAFETY: identity-mapped scratch DMA; the gate makes the slot
        // ours. Bulk copy — this is the per-PCM-buffer hot path, and a
        // per-byte volatile loop paid 4024 single-byte stores per
        // period. Ordering vs. the device comes from the SeqCst fence
        // before the notify write in `play_buffer_phys_locked`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                pcm.as_ptr(),
                narf_memory::PhysAddr::new(payload_phys).kernel_mut_ptr::<u8>(),
                pcm.len(),
            );
        }
        self.play_buffer_phys_locked(params, payload_phys, pcm.len() as u32)
    }
}

/// PCM stream parameters.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PcmParams {
    pub buffer_bytes: u32,
    pub period_bytes: u32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
}

impl PcmParams {
    /// Stage-4 default: 8 KiB ring, 2 KiB period, S16LE @ 48 kHz
    /// stereo. Matches `narf_audio::AudioFormat::default_playback`.
    pub const fn default_playback() -> Self {
        Self {
            buffer_bytes: 8192,
            period_bytes: 2048,
            channels: 2,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_48000,
        }
    }
}

/// The probed controller, behind an `Arc` so callers can snapshot the
/// handle under a brief lock hold and release `CONTROLLER` BEFORE the
/// device round-trip (the same clone-and-release pattern as the mount
/// registry and virtio-net). An `&'static` handout (as virtio-blk uses)
/// would be unsound here: `__reset_for_test` legitimately drops the
/// controller, so the install-once invariant that justifies `&'static`
/// does not hold for this driver. The `Arc` keeps a snapshotted device
/// alive across that window instead.
static CONTROLLER: IrqSafeSpinLock<Option<Arc<VirtioSoundPci>>> = IrqSafeSpinLock::new(None);
static CARD_INDEX: IrqSafeSpinLock<Option<u32>> = IrqSafeSpinLock::new(None);

#[derive(Clone, Copy, Debug)]
pub(crate) struct PlaybackInfo {
    pub(crate) formats: u64,
    pub(crate) rates: u64,
    pub(crate) direction: u8,
    pub(crate) channels_min: u8,
    pub(crate) channels_max: u8,
}

impl PlaybackInfo {
    /// Whether this stream is a viable candidate for the S16
    /// 44.1/48 kHz mono/stereo surface: the advertised-set checks
    /// the probe filter applies before any specific parameter set
    /// is negotiated. Direction is NOT part of viability — the
    /// caller splits output from input records first.
    pub(crate) fn is_viable_candidate(self) -> bool {
        self.channels_min <= 2
            && self.channels_max != 0
            && self.channels_min <= self.channels_max
            && self.formats & (1 << VIRTIO_SND_PCM_FMT_S16) != 0
            && self.rates & ((1 << VIRTIO_SND_PCM_RATE_44100) | (1 << VIRTIO_SND_PCM_RATE_48000))
                != 0
    }

    fn supports(self, params: PcmParams) -> bool {
        let frame_bytes = u32::from(params.channels) * 2;
        params.format == VIRTIO_SND_PCM_FMT_S16
            && matches!(
                params.rate,
                VIRTIO_SND_PCM_RATE_44100 | VIRTIO_SND_PCM_RATE_48000
            )
            && (1..=2).contains(&params.channels)
            && (self.channels_min..=self.channels_max).contains(&params.channels)
            && self.formats & (1u64 << params.format) != 0
            && self.rates & (1u64 << params.rate) != 0
            && params.period_bytes != 0
            && params.period_bytes % frame_bytes == 0
            && params.buffer_bytes >= params.period_bytes.saturating_mul(2)
            && params.buffer_bytes <= 256 * 1024
            && params.buffer_bytes % params.period_bytes == 0
    }
}

/// Split viable stream records into the first output id and the
/// first input id, in device order. The single selection rule probe
/// and fixtures both exercise: later streams of the same direction
/// are not exposed (device 0 only per direction).
pub(crate) fn split_stream_records(records: &[(u32, PlaybackInfo)]) -> (Option<u32>, Option<u32>) {
    let mut output = None;
    let mut input = None;
    for (id, info) in records {
        if !info.is_viable_candidate() {
            continue;
        }
        match info.direction {
            0 if output.is_none() => output = Some(*id),
            1 if input.is_none() => input = Some(*id),
            _ => {}
        }
    }
    (output, input)
}

/// Query every PCM stream's 32-byte `virtio_snd_pcm_info` record
/// (1.2 §5.14.6.6.2) in batches of 32 — the control scratch caps a
/// response payload at 4028 bytes and 32 × 32 + 4 fits comfortably.
/// Returns `(stream id, info)` for viable candidates only, in device
/// order: a record with an undefined direction or without S16 +
/// 44.1/48 kHz + sane channels is skipped, not fatal. A failed batch
/// is fatal here (playback enumeration is load-bearing for probe);
/// jack and CTL queries below are fail-soft instead.
/// Caller must hold the request gate.
fn stream_records(device: &VirtioSoundPci) -> Result<Vec<(u32, PlaybackInfo)>, VirtioPciError> {
    if device.cfg.streams == 0 {
        return Err(VirtioPciError::NoQueues);
    }
    let mut out = Vec::new();
    let mut start = 0u32;
    while start < device.cfg.streams {
        let count = (device.cfg.streams - start).min(32);
        let mut request = [0; 16];
        request[..4].copy_from_slice(&VIRTIO_SND_R_PCM_INFO.to_le_bytes());
        request[4..8].copy_from_slice(&start.to_le_bytes());
        request[8..12].copy_from_slice(&count.to_le_bytes());
        request[12..].copy_from_slice(&32u32.to_le_bytes());
        let mut response = alloc::vec![0u8; count as usize * 32];
        if device.ctrl_request_data(&request, &mut response)? != VIRTIO_SND_S_OK {
            return Err(VirtioPciError::DeviceRejectedFeatures);
        }
        for i in 0..count as usize {
            let record = &response[i * 32..(i + 1) * 32];
            if let Some(info) = parse_pcm_info_record(record) {
                if matches!(info.direction, 0 | 1) && info.is_viable_candidate() {
                    out.push((start + i as u32, info));
                }
            }
        }
        start += count;
    }
    Ok(out)
}

/// Query every jack's 24-byte `virtio_snd_jack_info` record
/// (1.2 §5.14.6.4.1) and seed connection state from the `connected`
/// byte. Fail-soft: any failed batch leaves those jacks disconnected
/// — live jack events correct the state afterwards, and jack state
/// is advisory (it only feeds JackSense controls).
/// Caller must hold the request gate.
fn jack_states(device: &VirtioSoundPci) -> Vec<bool> {
    let mut out = alloc::vec![false; device.cfg.jacks as usize];
    if device.cfg.jacks == 0 {
        return out;
    }
    let mut start = 0u32;
    while start < device.cfg.jacks {
        let count = (device.cfg.jacks - start).min(64);
        let mut request = [0; 16];
        request[..4].copy_from_slice(&VIRTIO_SND_R_JACK_INFO.to_le_bytes());
        request[4..8].copy_from_slice(&start.to_le_bytes());
        request[8..12].copy_from_slice(&count.to_le_bytes());
        request[12..].copy_from_slice(&24u32.to_le_bytes());
        let mut response = alloc::vec![0u8; count as usize * 24];
        match device.ctrl_request_data(&request, &mut response) {
            Ok(status) if status == VIRTIO_SND_S_OK => {
                for i in 0..count as usize {
                    if let Some(connected) = parse_jack_info_record(&response[i * 24..(i + 1) * 24])
                    {
                        out[(start as usize) + i] = connected;
                    }
                }
            }
            _ => break,
        }
        start += count;
    }
    out
}

/// Query every control element's 92-byte `virtio_snd_ctl_info` record
/// (1.4 §5.14.6.10.1) in batches of 32. Returns parsed elements in
/// device order; structurally invalid records are skipped by the
/// parser. Fail-soft throughout: not negotiated, zero controls, or
/// any failed batch yields whatever was collected (possibly none) —
/// playback and capture must keep working without CTL.
/// Caller must hold the request gate.
fn query_ctl_infos(device: &VirtioSoundPci) -> Vec<CtlInfo> {
    let mut out = Vec::new();
    if !device.ctls || device.cfg.controls == 0 {
        return out;
    }
    let mut start = 0u32;
    while start < device.cfg.controls {
        let count = (device.cfg.controls - start).min(32);
        let mut request = [0; 16];
        request[..4].copy_from_slice(&VIRTIO_SND_R_CTL_INFO.to_le_bytes());
        request[4..8].copy_from_slice(&start.to_le_bytes());
        request[8..12].copy_from_slice(&count.to_le_bytes());
        request[12..].copy_from_slice(&(VIRTIO_SND_CTL_INFO_SIZE as u32).to_le_bytes());
        let mut response = alloc::vec![0u8; count as usize * VIRTIO_SND_CTL_INFO_SIZE];
        match device.ctrl_request_data(&request, &mut response) {
            Ok(status) if status == VIRTIO_SND_S_OK => {
                for i in 0..count as usize {
                    let record =
                        &response[i * VIRTIO_SND_CTL_INFO_SIZE..(i + 1) * VIRTIO_SND_CTL_INFO_SIZE];
                    if let Some(mut info) = parse_ctl_info_record(record) {
                        info.id = start + i as u32;
                        out.push(info);
                    }
                }
            }
            _ => break,
        }
        start += count;
    }
    out
}

/// Snapshot the installed controller. Takes `CONTROLLER` only long
/// enough to clone the `Arc`.
fn probed() -> Option<Arc<VirtioSoundPci>> {
    CONTROLLER.lock().clone()
}

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let mut dev = match unsafe { VirtioSoundPci::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    // Stream enumeration is load-bearing: without a viable output
    // stream there is no card. The gate is held only for the query
    // itself (shared ctrl scratch), never across the reset below.
    let records = {
        let _gate = ReqGate::acquire(&dev.req_gate);
        stream_records(&dev)
    };
    let records = match records {
        Ok(records) => records,
        Err(_) => {
            assert!(
                dev.reset_device(),
                "unsupported virtio-snd device did not reset"
            );
            return Err(narf_bus::ProbeError::NotForThisDriver);
        }
    };
    // First viable output stream is playback; first viable input
    // stream is capture. Without an output stream there is no card.
    let (playback_id, capture_id) = split_stream_records(&records);
    let Some(playback_id) = playback_id else {
        assert!(
            dev.reset_device(),
            "virtio-snd device without an output stream did not reset"
        );
        return Err(narf_bus::ProbeError::NotForThisDriver);
    };
    let playback_info = records
        .iter()
        .find(|(id, _)| *id == playback_id)
        .map(|(_, info)| *info)
        .expect("split returned an id from the same record list");
    dev.playback_stream_id = playback_id;
    dev.playback_info = Some(playback_info);
    dev.capture_stream_id = capture_id;
    dev.capture_info = capture_id.and_then(|id| {
        records
            .iter()
            .find(|(rid, _)| *rid == id)
            .map(|(_, info)| *info)
    });
    // Fail-soft queries: jack state and control elements are
    // advisory. A failure here must not fail the probe.
    {
        let _gate = ReqGate::acquire(&dev.req_gate);
        dev.jack_connected = IrqSafeSpinLock::new(jack_states(&dev));
        dev.ctl_infos = query_ctl_infos(&dev);
    }
    let dev = Arc::new(dev);
    *CONTROLLER.lock() = Some(dev.clone());
    let card = narf_drivers_sound::register_hardware_card_at(
        narf_drivers_sound::CardInfo {
            index: 0,
            driver: "virtio-sound",
            id: "VirtIO",
            name: "VirtIO Sound",
            playback_count: 1,
            capture_count: u32::from(dev.capture_info.is_some()),
        },
        Arc::new(sound_card::Card(dev)),
        Some(device.addr),
    );
    *CARD_INDEX.lock() = Some(card);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("vsnd0"),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(VIRTIO_SND_PCI_VENDOR),
        pci_did: Some(VIRTIO_SND_PCI_DEVICE),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "virtio-snd-pci",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: VIRTIO_SND_PCI_VENDOR,
            device: VIRTIO_SND_PCI_DEVICE,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Whether stream 0 advertised the requested format through PCM_INFO.
pub fn supports_playback(params: PcmParams) -> bool {
    probed().is_some_and(|device| {
        !device.failed.load(Ordering::Acquire)
            && device
                .playback_info
                .is_some_and(|info| info.supports(params))
    })
}

/// Topology snapshot — `(jacks, streams, chmaps)`. Returns `None`
/// if the device hasn't probed.
pub fn topology() -> Option<(u32, u32, u32)> {
    CONTROLLER
        .lock()
        .as_ref()
        .map(|c| (c.cfg.jacks, c.cfg.streams, c.cfg.chmaps))
}

/// Submit one PCM buffer through the probed virtio-sound device's
/// stream 0. Blocks until the device acks. Slice-friendly; copies
/// into the per-controller scratch.
///
/// The `CONTROLLER` lock is released before the submit: the device
/// may hold a PCM buffer for milliseconds before acking, and waiting
/// that out under an IRQ-masking global lock starved timers/RCU on
/// this CPU and spun every other audio submitter interrupts-masked.
/// Mutual exclusion is provided by the device's own request gate.
pub fn play_buffer(params: PcmParams, pcm: &[u8]) -> Result<(), VirtioPciError> {
    let c = probed().ok_or(VirtioPciError::NoQueues)?;
    c.play_buffer(params, pcm)
}

/// Zero-copy submit: the payload descriptor points directly at
/// `(payload_phys, payload_len)`. The header + status still come
/// from the per-controller scratch. Use this when the PCM source
/// is already in DMA-coherent memory — typically a `narf-shmem`
/// region's `phys_at(handle, offset)`. Locking as [`play_buffer`].
pub fn play_buffer_phys(
    params: PcmParams,
    payload_phys: u64,
    payload_len: u32,
) -> Result<(), VirtioPciError> {
    let c = probed().ok_or(VirtioPciError::NoQueues)?;
    c.play_buffer_phys(params, payload_phys, payload_len)
}

/// Sound-registry card index of the probed controller.
#[doc(hidden)]
pub fn __card_index_for_test() -> Option<u32> {
    *CARD_INDEX.lock()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    let card = CARD_INDEX.lock().take();
    if let Some(card) = card {
        narf_drivers_sound::unregister_hardware_card(card);
    }
    // Snapshot + release, then take the device's request gate so a
    // submit that already snapshotted the controller finishes before
    // the device is reset underneath it (the old whole-function
    // CONTROLLER hold provided that exclusion implicitly).
    let Some(current) = probed() else {
        return;
    };
    let _gate = ReqGate::acquire(&current.req_gate);
    current.failed.store(true, Ordering::Release);
    // Do not release queue-backed DMA while the device may still access it.
    // Failing loudly is preferable to either hiding a stale controller or
    // manufacturing a use-after-free in the host device model. The `Arc`
    // keeps the allocation alive until the last in-flight snapshot drops.
    assert!(
        current.reset_device(),
        "virtio-snd device did not acknowledge reset"
    );
    *CONTROLLER.lock() = None;
}
