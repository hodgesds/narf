//! ALSA-style mixer control surface — volume, mute, jack-sense.
//!
//! Linux ALSA defines a small set of `snd_kcontrol`s per card; the
//! HDA codec patches register controls named "Master Playback Volume",
//! "Headphone Playback Volume", "Speaker Playback Switch", etc. Each
//! control has:
//!
//! - an info packet (min, max, step, count, channel layout),
//! - a get fn returning the current value,
//! - a put fn writing a new value, and
//! - optionally a TLV callback returning a dB conversion table.
//!
//! Realtek output amps use a 7-bit attenuator (0..127). The standard
//! Realtek "Master Playback Volume" exposes 0..87 (about 65 dB of
//! useful range — values above 87 wrap to mute on most laptop OEM
//! tunings, so we cap the userspace-visible max at 87 to match
//! `amixer set Master 65%` semantics on Linux).
//!
//! Linux references:
//! - `sound/core/control.c::snd_ctl_register_ioctl`
//! - `sound/hda/codecs/realtek/realtek.c::alc_build_controls`

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// One control's identity.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ControlId {
    /// Stable index within the card's control list.
    pub index: u32,
    /// What kind of control this is.
    pub kind: ControlKind,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ControlKind {
    /// Master Playback Volume — 0..87 attenuator value, ALSA-style.
    MasterVolume,
    /// Master Playback Switch — 1 = unmute, 0 = mute.
    MasterMute,
    /// Headphone Playback Volume.
    HeadphoneVolume,
    /// Speaker Playback Volume.
    SpeakerVolume,
    /// Mic Boost (Capture path).
    MicBoost,
    /// Capture Volume.
    CaptureVolume,
    /// Jack-Sense — read-only, 1 = plugged.
    JackSense,
}

impl ControlKind {
    pub const fn name(self) -> &'static str {
        match self {
            ControlKind::MasterVolume => "Master Playback Volume",
            ControlKind::MasterMute => "Master Playback Switch",
            ControlKind::HeadphoneVolume => "Headphone Playback Volume",
            ControlKind::SpeakerVolume => "Speaker Playback Volume",
            ControlKind::MicBoost => "Mic Boost",
            ControlKind::CaptureVolume => "Capture Volume",
            ControlKind::JackSense => "Headphone Jack",
        }
    }

    /// True if the control is a boolean (mute or sense).
    pub const fn is_boolean(self) -> bool {
        matches!(self, ControlKind::MasterMute | ControlKind::JackSense)
    }

    /// True if the control is read-only.
    pub const fn is_read_only(self) -> bool {
        matches!(self, ControlKind::JackSense)
    }
}

/// A current control value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ControlValue {
    /// Integer value (volume / boost).
    Integer { left: i32, right: i32 },
    /// Boolean (mute / jack-sense).
    Boolean(bool),
}

impl ControlValue {
    pub const fn integer(left: i32, right: i32) -> Self {
        ControlValue::Integer { left, right }
    }
    pub const fn boolean(b: bool) -> Self {
        ControlValue::Boolean(b)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MixerError {
    NoSuchControl,
    OutOfRange,
    ReadOnly,
}

/// Control info — bounds + name.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ControlInfo {
    pub id: ControlId,
    pub name: &'static str,
    pub value_min: i32,
    pub value_max: i32,
    pub step: i32,
    pub channels: u8,
    pub is_boolean: bool,
    pub is_read_only: bool,
}

impl ControlInfo {
    /// Realtek output-volume max (the user-visible range
    /// `amixer` would show).
    pub const REALTEK_VOLUME_MAX: i32 = 87;
}

/// Per-card mixer state — a `Vec<Control>` indexed by `ControlId`.
#[derive(Debug)]
struct CardMixer {
    controller_index: usize,
    controls: Vec<Control>,
}

#[derive(Debug)]
struct Control {
    info: ControlInfo,
    /// Current value, atomically updated so jack-sense can be written
    /// from the unsolicited-response IRQ path while userspace reads.
    /// Encoded as two i16s packed into the low 32 bits.
    value_packed: AtomicI32,
}

impl Control {
    fn read(&self) -> ControlValue {
        let v = self.value_packed.load(Ordering::Acquire);
        if self.info.is_boolean {
            ControlValue::Boolean((v & 1) != 0)
        } else {
            let left = (v >> 16) as i16 as i32;
            let right = (v & 0xFFFF) as i16 as i32;
            ControlValue::Integer { left, right }
        }
    }

    fn write(&self, value: ControlValue) -> Result<(), MixerError> {
        if self.info.is_read_only {
            return Err(MixerError::ReadOnly);
        }
        match value {
            ControlValue::Integer { left, right } => {
                if left < self.info.value_min
                    || left > self.info.value_max
                    || right < self.info.value_min
                    || right > self.info.value_max
                {
                    return Err(MixerError::OutOfRange);
                }
                let packed = ((left as u16 as u32) << 16) | (right as u16 as u32);
                self.value_packed.store(packed as i32, Ordering::Release);
                Ok(())
            }
            ControlValue::Boolean(b) => {
                self.value_packed.store(b as i32, Ordering::Release);
                Ok(())
            }
        }
    }
}

// ── Registry ────────────────────────────────────────────────────────

static MIXER_REGISTRY: IrqSafeSpinLock<Vec<CardMixer>> = IrqSafeSpinLock::new(Vec::new());

/// Reset the mixer registry (test-only).
pub fn __reset_for_test() {
    MIXER_REGISTRY.lock().clear();
}

/// Register a standard Realtek-laptop control set against the
/// controller-index. Called once per card at probe-time after the
/// codec graph walk identifies which paths exist.
pub fn register_standard_realtek(
    controller_index: usize,
    has_speaker: bool,
    has_headphone: bool,
    has_mic: bool,
) {
    let mut mx = MIXER_REGISTRY.lock();
    let mut controls = Vec::new();
    let mut next_idx = 0u32;

    let mut add = |info: ControlInfo, initial: ControlValue| {
        let packed = match initial {
            ControlValue::Integer { left, right } => {
                ((left as u16 as u32) << 16) | (right as u16 as u32)
            }
            ControlValue::Boolean(b) => b as u32,
        };
        controls.push(Control {
            info,
            value_packed: AtomicI32::new(packed as i32),
        });
    };

    let master = ControlId {
        index: next_idx,
        kind: ControlKind::MasterVolume,
    };
    next_idx += 1;
    add(
        ControlInfo {
            id: master,
            name: ControlKind::MasterVolume.name(),
            value_min: 0,
            value_max: ControlInfo::REALTEK_VOLUME_MAX,
            step: 1,
            channels: 2,
            is_boolean: false,
            is_read_only: false,
        },
        ControlValue::integer(67, 67), // ~75% default
    );

    let master_mute = ControlId {
        index: next_idx,
        kind: ControlKind::MasterMute,
    };
    next_idx += 1;
    add(
        ControlInfo {
            id: master_mute,
            name: ControlKind::MasterMute.name(),
            value_min: 0,
            value_max: 1,
            step: 1,
            channels: 1,
            is_boolean: true,
            is_read_only: false,
        },
        ControlValue::boolean(true), // start unmuted
    );

    if has_speaker {
        let id = ControlId {
            index: next_idx,
            kind: ControlKind::SpeakerVolume,
        };
        next_idx += 1;
        add(
            ControlInfo {
                id,
                name: ControlKind::SpeakerVolume.name(),
                value_min: 0,
                value_max: ControlInfo::REALTEK_VOLUME_MAX,
                step: 1,
                channels: 2,
                is_boolean: false,
                is_read_only: false,
            },
            ControlValue::integer(67, 67),
        );
    }

    if has_headphone {
        let id = ControlId {
            index: next_idx,
            kind: ControlKind::HeadphoneVolume,
        };
        next_idx += 1;
        add(
            ControlInfo {
                id,
                name: ControlKind::HeadphoneVolume.name(),
                value_min: 0,
                value_max: ControlInfo::REALTEK_VOLUME_MAX,
                step: 1,
                channels: 2,
                is_boolean: false,
                is_read_only: false,
            },
            ControlValue::integer(67, 67),
        );
        let jack = ControlId {
            index: next_idx,
            kind: ControlKind::JackSense,
        };
        next_idx += 1;
        add(
            ControlInfo {
                id: jack,
                name: ControlKind::JackSense.name(),
                value_min: 0,
                value_max: 1,
                step: 1,
                channels: 1,
                is_boolean: true,
                is_read_only: true,
            },
            ControlValue::boolean(false), // not plugged
        );
    }

    if has_mic {
        let id = ControlId {
            index: next_idx,
            kind: ControlKind::CaptureVolume,
        };
        next_idx += 1;
        add(
            ControlInfo {
                id,
                name: ControlKind::CaptureVolume.name(),
                value_min: 0,
                value_max: ControlInfo::REALTEK_VOLUME_MAX,
                step: 1,
                channels: 2,
                is_boolean: false,
                is_read_only: false,
            },
            ControlValue::integer(60, 60),
        );
        let id = ControlId {
            index: next_idx,
            kind: ControlKind::MicBoost,
        };
        let _ = next_idx; // last add — keep symmetry, suppress lint
        add(
            ControlInfo {
                id,
                name: ControlKind::MicBoost.name(),
                value_min: 0,
                value_max: 3,
                step: 1,
                channels: 2,
                is_boolean: false,
                is_read_only: false,
            },
            ControlValue::integer(1, 1),
        );
    }

    mx.push(CardMixer {
        controller_index,
        controls,
    });
}

/// List the control identities for a controller.
pub fn list_for_controller(controller_index: usize) -> Vec<ControlId> {
    let mx = MIXER_REGISTRY.lock();
    if let Some(card) = mx.iter().find(|c| c.controller_index == controller_index) {
        card.controls.iter().map(|c| c.info.id).collect()
    } else {
        Vec::new()
    }
}

/// Look up a control's info.
pub fn info(controller_index: usize, id: ControlId) -> Result<ControlInfo, MixerError> {
    let mx = MIXER_REGISTRY.lock();
    let card = mx
        .iter()
        .find(|c| c.controller_index == controller_index)
        .ok_or(MixerError::NoSuchControl)?;
    let ctrl = card
        .controls
        .iter()
        .find(|c| c.info.id == id)
        .ok_or(MixerError::NoSuchControl)?;
    Ok(ctrl.info)
}

/// Get a control's current value.
pub fn get(controller_index: usize, id: ControlId) -> Result<ControlValue, MixerError> {
    let mx = MIXER_REGISTRY.lock();
    let card = mx
        .iter()
        .find(|c| c.controller_index == controller_index)
        .ok_or(MixerError::NoSuchControl)?;
    let ctrl = card
        .controls
        .iter()
        .find(|c| c.info.id == id)
        .ok_or(MixerError::NoSuchControl)?;
    Ok(ctrl.read())
}

/// Set a control's value. Range-checks against the control's info.
pub fn set(controller_index: usize, id: ControlId, value: ControlValue) -> Result<(), MixerError> {
    let mx = MIXER_REGISTRY.lock();
    let card = mx
        .iter()
        .find(|c| c.controller_index == controller_index)
        .ok_or(MixerError::NoSuchControl)?;
    let ctrl = card
        .controls
        .iter()
        .find(|c| c.info.id == id)
        .ok_or(MixerError::NoSuchControl)?;
    ctrl.write(value)
}

/// Drive a jack-sense event — called from the unsolicited-response
/// handler on the controller side.
pub fn jack_event(controller_index: usize, plugged: bool) {
    let mx = MIXER_REGISTRY.lock();
    if let Some(card) = mx.iter().find(|c| c.controller_index == controller_index) {
        for ctrl in card.controls.iter() {
            if matches!(ctrl.info.id.kind, ControlKind::JackSense) {
                let _ = ctrl.value_packed.store(plugged as i32, Ordering::Release);
            }
        }
    }
}
