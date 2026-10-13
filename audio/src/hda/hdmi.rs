//! AMD/ATI GPU HDMI/DP ports: emulated ELD, CEA channel allocation and
//! jack-driven routing. Linux references: sound/hda/codecs/hdmi/atihdmi.c
//! (get_eld_ati, atihdmi_pin_set_slot_channel), hdmi.c
//! (hdmi_present_sense_via_verbs, update_eld,
//! snd_hda_hdmi_setup_audio_infoframe), eld.c
//! (snd_hdmi_eld_update_pcm_info), sound/core/pcm_drm_eld.c (snd_parse_eld)
//! and sound/hda/core/hdmi_chmap.c (channel_allocations,
//! hdmi_std_setup_channel_mapping).
use super::*;
use crate::hda_codec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use narf_drivers_sound::{
    format::ChannelCount,
    mixer::{ControlId, ControlKind},
};

const GET_PIN_SENSE: u32 = 0xf09;
const PINSENSE_PRESENCE: u32 = 1 << 31;
const PINSENSE_ELDV: u32 = 1 << 30;
const SET_AUDIO_DESCRIPTOR: u32 = 0x776;
const SET_SINK_INFO_INDEX: u32 = 0x780;
const GET_SPEAKER_ALLOCATION: u32 = 0xf70;
const GET_AUDIO_DESCRIPTOR: u32 = 0xf76;
const GET_AUDIO_VIDEO_DELAY: u32 = 0xf7b;
const GET_SINK_INFO_DATA: u32 = 0xf81;
const SPKALLOC_TYPE_DISPLAYPORT: u32 = 0x200;

const ELD_VER_CEA_861D: u8 = 2;
const ELD_VER_PARTIAL: u8 = 31;
const ELD_FIXED_BYTES: usize = 20;
const ELD_MAX_MNL: usize = 16;
const ELD_MAX_SAD: usize = 16;
const AUDIO_CODING_TYPE_LPCM: u8 = 1;

/// A sink's ELD and what playback needs from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sink {
    pub eld: Vec<u8>,
    /// ELD speaker allocation, 0xffff when the sink sent none (snd_parse_eld
    /// then assumes every speaker so multichannel is not refused).
    pub spk_alloc: u16,
    /// Most channels any SAD advertises, at least 2.
    pub channels_max: u8,
    /// An LPCM SAD carries 20- or 24-bit samples (S32_LE allowed).
    pub s32: bool,
}

/// `snd_parse_eld` plus update_eld's validity rule (at least one SAD) and
/// the limits `snd_hdmi_eld_update_pcm_info` derives.
pub(crate) fn parse_eld(buf: &[u8]) -> Option<Sink> {
    if buf.len() < ELD_FIXED_BYTES {
        return None;
    }
    let version = buf[0] >> 3;
    if version != ELD_VER_CEA_861D && version != ELD_VER_PARTIAL {
        return None;
    }
    let mnl = usize::from(buf[4] & 0x1f);
    if mnl > ELD_MAX_MNL || ELD_FIXED_BYTES + mnl > buf.len() {
        return None;
    }
    let sad_count = usize::from(buf[5] >> 4);
    if sad_count == 0 {
        return None;
    }
    let mut channels_max = 2;
    let mut s32 = false;
    for i in 0..sad_count {
        let at = ELD_FIXED_BYTES + mnl + 3 * i;
        let sad = buf.get(at..at + 3)?;
        channels_max = channels_max.max((sad[0] & 7) + 1);
        if (sad[0] >> 3) & 0xf == AUDIO_CODING_TYPE_LPCM && sad[2] & 6 != 0 {
            s32 = true;
        }
    }
    let spk_alloc = match u16::from(buf[7] & 0x7f) {
        0 => 0xffff,
        spk => spk,
    };
    Some(Sink {
        eld: buf.to_vec(),
        spk_alloc,
        channels_max,
        s32,
    })
}

// CEA speaker placements (hdmi_chmap.c enum cea_speaker_placement).
const FL: u32 = 1 << 0;
const FC: u32 = 1 << 1;
const FR: u32 = 1 << 2;
const FLC: u32 = 1 << 3;
const FRC: u32 = 1 << 4;
const RL: u32 = 1 << 5;
const RC: u32 = 1 << 6;
const RR: u32 = 1 << 7;
const RLC: u32 = 1 << 8;
const RRC: u32 = 1 << 9;
const LFE: u32 = 1 << 10;
const FLW: u32 = 1 << 11;
const FRW: u32 = 1 << 12;
const FLH: u32 = 1 << 13;
const FCH: u32 = 1 << 14;
const FRH: u32 = 1 << 15;
const TC: u32 = 1 << 16;

/// ELD speaker-allocation bit -> speaker mask (eld_speaker_allocation_bits).
const ELD_SPEAKERS: [u32; 11] = [
    FL | FR,
    LFE,
    FC,
    RL | RR,
    RC,
    FLC | FRC,
    RLC | RRC,
    FLW | FRW,
    FLH | FRH,
    TC,
    FCH,
];

/// `channel_allocations[]` in Linux's preference order: CA index and the
/// speaker in each slot, slot 7 first.
const ALLOCATIONS: [(u8, [u32; 8]); 50] = [
    (0x00, [0, 0, 0, 0, 0, 0, FR, FL]),
    (0x01, [0, 0, 0, 0, 0, LFE, FR, FL]),
    (0x02, [0, 0, 0, 0, FC, 0, FR, FL]),
    (0x08, [0, 0, RR, RL, 0, 0, FR, FL]),
    (0x09, [0, 0, RR, RL, 0, LFE, FR, FL]),
    (0x0a, [0, 0, RR, RL, FC, 0, FR, FL]),
    (0x0b, [0, 0, RR, RL, FC, LFE, FR, FL]),
    (0x0f, [0, RC, RR, RL, FC, LFE, FR, FL]),
    (0x13, [RRC, RLC, RR, RL, FC, LFE, FR, FL]),
    (0x03, [0, 0, 0, 0, FC, LFE, FR, FL]),
    (0x04, [0, 0, 0, RC, 0, 0, FR, FL]),
    (0x05, [0, 0, 0, RC, 0, LFE, FR, FL]),
    (0x06, [0, 0, 0, RC, FC, 0, FR, FL]),
    (0x07, [0, 0, 0, RC, FC, LFE, FR, FL]),
    (0x0c, [0, RC, RR, RL, 0, 0, FR, FL]),
    (0x0d, [0, RC, RR, RL, 0, LFE, FR, FL]),
    (0x0e, [0, RC, RR, RL, FC, 0, FR, FL]),
    (0x10, [RRC, RLC, RR, RL, 0, 0, FR, FL]),
    (0x11, [RRC, RLC, RR, RL, 0, LFE, FR, FL]),
    (0x12, [RRC, RLC, RR, RL, FC, 0, FR, FL]),
    (0x14, [FRC, FLC, 0, 0, 0, 0, FR, FL]),
    (0x15, [FRC, FLC, 0, 0, 0, LFE, FR, FL]),
    (0x16, [FRC, FLC, 0, 0, FC, 0, FR, FL]),
    (0x17, [FRC, FLC, 0, 0, FC, LFE, FR, FL]),
    (0x18, [FRC, FLC, 0, RC, 0, 0, FR, FL]),
    (0x19, [FRC, FLC, 0, RC, 0, LFE, FR, FL]),
    (0x1a, [FRC, FLC, 0, RC, FC, 0, FR, FL]),
    (0x1b, [FRC, FLC, 0, RC, FC, LFE, FR, FL]),
    (0x1c, [FRC, FLC, RR, RL, 0, 0, FR, FL]),
    (0x1d, [FRC, FLC, RR, RL, 0, LFE, FR, FL]),
    (0x1e, [FRC, FLC, RR, RL, FC, 0, FR, FL]),
    (0x1f, [FRC, FLC, RR, RL, FC, LFE, FR, FL]),
    (0x20, [0, FCH, RR, RL, FC, 0, FR, FL]),
    (0x21, [0, FCH, RR, RL, FC, LFE, FR, FL]),
    (0x22, [TC, 0, RR, RL, FC, 0, FR, FL]),
    (0x23, [TC, 0, RR, RL, FC, LFE, FR, FL]),
    (0x24, [FRH, FLH, RR, RL, 0, 0, FR, FL]),
    (0x25, [FRH, FLH, RR, RL, 0, LFE, FR, FL]),
    (0x26, [FRW, FLW, RR, RL, 0, 0, FR, FL]),
    (0x27, [FRW, FLW, RR, RL, 0, LFE, FR, FL]),
    (0x28, [TC, RC, RR, RL, FC, 0, FR, FL]),
    (0x29, [TC, RC, RR, RL, FC, LFE, FR, FL]),
    (0x2a, [FCH, RC, RR, RL, FC, 0, FR, FL]),
    (0x2b, [FCH, RC, RR, RL, FC, LFE, FR, FL]),
    (0x2c, [TC, FCH, RR, RL, FC, 0, FR, FL]),
    (0x2d, [TC, FCH, RR, RL, FC, LFE, FR, FL]),
    (0x2e, [FRH, FLH, RR, RL, FC, 0, FR, FL]),
    (0x2f, [FRH, FLH, RR, RL, FC, LFE, FR, FL]),
    (0x30, [FRW, FLW, RR, RL, FC, 0, FR, FL]),
    (0x31, [FRW, FLW, RR, RL, FC, LFE, FR, FL]),
];

fn allocation(ca: u8) -> &'static [u32; 8] {
    ALLOCATIONS
        .iter()
        .find(|(index, _)| *index == ca)
        .map_or(&ALLOCATIONS[0].1, |(_, speakers)| speakers)
}
fn allocation_channels(speakers: &[u32; 8]) -> u8 {
    speakers.iter().filter(|s| **s != 0).count() as u8
}

/// `hdmi_channel_allocation_spk_alloc_blk`: the first CA (in preference
/// order) with exactly `channels` speakers the sink has, else the first
/// with that many channels at all. Stereo and below is always CA 0.
pub(crate) fn channel_allocation(spk_alloc: u16, channels: u8) -> u8 {
    if channels <= 2 {
        return 0;
    }
    let mask = ELD_SPEAKERS
        .iter()
        .enumerate()
        .filter(|(bit, _)| spk_alloc & (1 << bit) != 0)
        .fold(0, |mask, (_, speakers)| mask | speakers);
    let fits = |speakers: &[u32; 8]| allocation_channels(speakers) == channels;
    let mask_of = |speakers: &[u32; 8]| speakers.iter().fold(0, |m, s| m | s);
    ALLOCATIONS
        .iter()
        .find(|(_, s)| fits(s) && mask & mask_of(s) == mask_of(s))
        .or_else(|| ALLOCATIONS.iter().find(|(_, s)| fits(s)))
        .map_or(0, |(ca, _)| *ca)
}

/// `snd_hdac_get_active_channels`: the speakers CA `ca` carries.
pub(crate) fn active_channels(ca: u8) -> u8 {
    allocation_channels(allocation(ca))
}

/// `hdmi_std_setup_channel_mapping` for LPCM: eight `(channel << 4) | slot`
/// entries in the order Linux writes them; channel 0xf leaves a slot empty.
pub(crate) fn channel_mapping(ca: u8) -> [u8; 8] {
    // Linux's fixed table for the ALSA surround layouts.
    let fixed: Option<[u8; 8]> = match ca {
        0x00 => Some([0x00, 0x11, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]),
        0x01 => Some([0x00, 0x11, 0x22, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]),
        0x02 => Some([0x00, 0x11, 0x23, 0xf2, 0xf4, 0xf5, 0xf6, 0xf7]),
        0x08 => Some([0x00, 0x11, 0x24, 0x35, 0xf3, 0xf2, 0xf6, 0xf7]),
        0x03 => Some([0x00, 0x11, 0x23, 0x32, 0x44, 0xf5, 0xf6, 0xf7]),
        0x09 => Some([0x00, 0x11, 0x24, 0x35, 0x42, 0xf3, 0xf6, 0xf7]),
        0x0a => Some([0x00, 0x11, 0x24, 0x35, 0x43, 0xf2, 0xf6, 0xf7]),
        0x0b => Some([0x00, 0x11, 0x24, 0x35, 0x43, 0x52, 0xf6, 0xf7]),
        0x13 => Some([0x00, 0x11, 0x26, 0x37, 0x43, 0x52, 0x64, 0x75]),
        _ => None,
    };
    if let Some(map) = fixed {
        return map;
    }
    // Stream channels fill the occupied slots in order, then the empty
    // slots take channel 0xf.
    let speakers = allocation(ca);
    let mut map = [0u8; 8];
    let mut i = 0;
    let mut slot = 0;
    'fill: while i < usize::from(allocation_channels(speakers)) && slot < 8 {
        while speakers[7 - slot] == 0 {
            slot += 1;
            if slot >= 8 {
                break 'fill;
            }
        }
        map[i] = ((i as u8) << 4) | slot as u8;
        i += 1;
        slot += 1;
    }
    for slot in 0..8 {
        if speakers[7 - slot] == 0 {
            map[i] = 0xf0 | slot as u8;
            i += 1;
        }
    }
    map
}

/// `atihdmi_pin_set_slot_channel`: the verb and payload one map entry
/// becomes. Pre-rev3 codecs map slot pairs with FC/LFE swapped and skip an
/// empty odd slot (its even partner decides the pair).
pub(crate) fn ati_slot_verb(entry: u8, rev3: bool) -> Option<(u32, u32)> {
    const SET_MULTICHANNEL_01: u32 = 0x777;
    let (mut slot, mut channel) = (u32::from(entry & 0xf), u32::from(entry >> 4));
    if !rev3 {
        slot = match slot {
            2 => 3,
            3 => 2,
            slot => slot,
        };
        if slot % 2 != 0 && channel == 0xf {
            return None;
        }
        slot -= slot % 2;
        if channel != 0xf {
            channel -= channel % 2;
        }
    }
    let verb = SET_MULTICHANNEL_01 + slot / 2 + (slot % 2) * 0xe;
    let setup = if channel == 0xf {
        0
    } else {
        (channel << 4) | 1
    };
    Some((verb, setup))
}

/// One HDMI/DP port pin and what its sense last reported.
#[derive(Clone, Debug)]
pub(crate) struct Port {
    /// Index into `IntelHda::outputs`.
    pub output: usize,
    pub present: bool,
    /// Pin sense ELD-valid bit, kept so the poll re-reads the ELD only when
    /// the sense changes (or the last read gave no usable ELD).
    pub eldv: bool,
    pub sink: Option<Sink>,
}

impl IntelHda {
    /// Every ATI codec output path, unsensed.
    pub(super) fn hdmi_ports(&self) -> Vec<Port> {
        self.outputs
            .iter()
            .enumerate()
            .filter(|(_, path)| hda_codec::is_ati_hdmi(&self.graphs[path.codec]))
            .map(|(output, _)| Port {
                output,
                present: false,
                eldv: false,
                sink: None,
            })
            .collect()
    }

    /// `get_eld_ati`: build an ELD from the codec's copy of what the display
    /// driver wrote into the Azalia endpoint. `None` without a speaker
    /// allocation or without any audio descriptor.
    fn ati_eld(&self, cad: u8, pin: u8, rev3: bool) -> Result<Option<Vec<u8>>, HdaError> {
        let verb = |verb: u32| self.verb(cad, pin, verb);
        let spkalloc = verb(GET_SPEAKER_ALLOCATION << 8)?;
        if spkalloc as i32 <= 0 {
            return Ok(None);
        }
        let mut buf = [0u8; ELD_FIXED_BYTES + ELD_MAX_MNL + ELD_MAX_SAD * 3];
        buf[0] = ELD_VER_CEA_861D << 3;
        buf[7] = (spkalloc & 0x7f) as u8;
        if spkalloc & SPKALLOC_TYPE_DISPLAYPORT != 0 {
            buf[5] |= 0x04;
        }
        let mut pos = ELD_FIXED_BYTES;
        let mut mnl = 0;
        if rev3 {
            let info = |index: u32| -> Result<u32, HdaError> {
                verb((SET_SINK_INFO_INDEX << 8) | index)?;
                verb(GET_SINK_INFO_DATA << 8)
            };
            buf[8..12].copy_from_slice(&info(3)?.to_le_bytes());
            buf[12..16].copy_from_slice(&info(4)?.to_le_bytes());
            buf[16..18].copy_from_slice(&(info(0)? as u16).to_le_bytes());
            buf[18..20].copy_from_slice(&(info(1)? as u16).to_le_bytes());
            mnl = (info(2)? as usize).min(ELD_MAX_MNL);
            buf[4] |= mnl as u8;
            for i in 0..mnl {
                buf[pos] = info(5 + i as u32)? as u8;
                pos += 1;
            }
        }
        // LPCM..WMAPRO, skipping SACD and DST which the codec cannot report.
        for coding in (1..=15u32).filter(|c| *c != 9 && *c != 11) {
            verb((SET_AUDIO_DESCRIPTOR << 8) | (coding << 3))?;
            let sad = verb(GET_AUDIO_DESCRIPTOR << 8)?;
            if sad as i32 <= 0 {
                continue;
            }
            if sad & 0xff00 != 0 {
                buf[pos..pos + 3].copy_from_slice(&sad.to_le_bytes()[..3]);
                pos += 3;
            }
            // LPCM carries a separate stereo rate mask in its top byte.
            let stereo = sad & 0xff00_0000;
            if coding == 1 && stereo != 0 && stereo >> 16 != sad & 0xff00 {
                buf[pos] = (sad as u8 & !7) | 1;
                buf[pos + 1] = (sad >> 24) as u8;
                buf[pos + 2] = (sad >> 16) as u8;
                pos += 3;
            }
        }
        if pos == ELD_FIXED_BYTES + mnl {
            return Ok(None);
        }
        // HDMI VSDB latencies (x - 1) * 2 ms -> HDA video-after-audio x * 2.
        let sync = verb(GET_AUDIO_VIDEO_DELAY << 8)?;
        let (video, audio) = (sync & 0xff, (sync >> 8) & 0xff);
        if video != 0 && audio != 0 && video <= 0xfb && audio <= 0xfb && video > audio {
            buf[6] = (video - audio) as u8;
        }
        buf[5] |= (((pos - ELD_FIXED_BYTES - mnl) / 3) << 4) as u8;
        let pos = pos.next_multiple_of(4);
        buf[2] = ((pos - 4) / 4) as u8;
        Ok(Some(buf[..pos].to_vec()))
    }

    /// `hdmi_present_sense_via_verbs` + `update_eld` for every port: pin
    /// sense, then the ELD while it reads valid. Returns the ports whose
    /// presence or ELD changed.
    fn sense_hdmi(&self) -> Result<Vec<usize>, HdaError> {
        let mut changed = Vec::new();
        let count = self.hdmi.lock().len();
        for index in 0..count {
            let output = self.hdmi.lock()[index].output;
            let path = &self.outputs[output];
            let graph = &self.graphs[path.codec];
            let pin = path.nodes.pin_nid;
            let sense = self.verb(graph.addr, pin, GET_PIN_SENSE << 8)?;
            let present = sense & PINSENSE_PRESENCE != 0;
            let eldv = present && sense & PINSENSE_ELDV != 0;
            {
                let ports = self.hdmi.lock();
                let port = &ports[index];
                if port.present == present && port.eldv == eldv && (!eldv || port.sink.is_some()) {
                    continue;
                }
            }
            let sink = if eldv {
                self.ati_eld(graph.addr, pin, hda_codec::ati_hdmi_rev3(graph))?
                    .and_then(|eld| parse_eld(&eld))
            } else {
                None
            };
            let mut ports = self.hdmi.lock();
            let port = &mut ports[index];
            port.eldv = eldv;
            if port.present != present || port.sink != sink {
                port.present = present;
                port.sink = sink;
                changed.push(index);
            }
        }
        Ok(changed)
    }

    /// Output paths a PCM routes to: every port with a monitor whose ELD
    /// reads valid. With none, every path, as Linux's static PCM mapping
    /// keeps a pin attached before the display side publishes an ELD.
    pub(super) fn routed_outputs(&self) -> Vec<usize> {
        let ports = self.hdmi.lock();
        let live: Vec<usize> = ports
            .iter()
            .filter(|p| p.present && p.sink.is_some())
            .map(|p| p.output)
            .collect();
        if live.is_empty() {
            (0..self.outputs.len()).collect()
        } else {
            // Analog paths on another codec of the same controller stay.
            (0..self.outputs.len())
                .filter(|o| live.contains(o) || !ports.iter().any(|p| p.output == *o))
                .collect()
        }
    }

    /// The sink of a routed output, for CA selection.
    pub(super) fn hdmi_sink(&self, output: usize) -> Option<Sink> {
        self.hdmi
            .lock()
            .iter()
            .find(|p| p.output == output)
            .and_then(|p| p.sink.clone())
    }

    /// Playback limits across the sinks playback currently reaches
    /// (`snd_hdmi_eld_update_pcm_info` per pin, intersected because one
    /// native PCM mirrors to every routed port): channel ceiling and whether
    /// S32_LE is allowed. Without any ELD: the ATI converter's own 8 / S32.
    pub(super) fn hdmi_limits(&self) -> Option<(u8, bool)> {
        let ports = self.hdmi.lock();
        if ports.is_empty() {
            return None;
        }
        Some(
            ports
                .iter()
                .filter_map(|p| p.sink.as_ref().filter(|_| p.present))
                .fold((8, true), |(channels, s32), sink| {
                    (channels.min(sink.channels_max), s32 && sink.s32)
                }),
        )
    }

    /// Channel counts playback offers: stereo, plus the even surround
    /// layouts up to the HDMI ceiling on a GPU codec (ATI converters take
    /// eight channels whatever they advertise; Linux atihdmi_probe).
    pub(super) fn playback_channels(&self) -> Vec<ChannelCount> {
        let max = self.hdmi_limits().map_or(2, |(channels, _)| channels);
        [
            ChannelCount::Stereo,
            ChannelCount::Quad,
            ChannelCount::Surround51,
            ChannelCount::Surround71,
        ]
        .into_iter()
        .filter(|c| c.count() <= max)
        .collect()
    }

    /// Jack and ELD control values (Linux reports the jack as AVOUT only
    /// with presence and a valid ELD). The ELD is the first live port's.
    pub(super) fn hdmi_jack(&self) -> (bool, Vec<u8>) {
        let ports = self.hdmi.lock();
        ports
            .iter()
            .find_map(|p| p.sink.as_ref().filter(|_| p.present))
            .map_or((false, Vec::new()), |sink| (true, sink.eld.clone()))
    }

    /// Re-sense the ports; on a change, notify the jack and ELD controls
    /// and, with `reconfigure` while a playback stream is configured,
    /// re-set-up each port that just gained a valid ELD (Linux update_eld's
    /// `eld_valid && !old_eld_valid && per_pin->setup`).
    pub(super) fn refresh_hdmi(&self, reconfigure: bool) -> Result<(), HdaError> {
        if self.hdmi.lock().is_empty() {
            return Ok(());
        }
        let before: Vec<bool> = self.hdmi.lock().iter().map(|p| p.sink.is_some()).collect();
        let changed = self.sense_hdmi()?;
        if changed.is_empty() {
            return Ok(());
        }
        let card = self.card.load(Ordering::Acquire);
        if card != u32::MAX {
            for kind in [ControlKind::HdmiJack, ControlKind::Eld] {
                if let Some(id) = self
                    .mixer_controls()
                    .into_iter()
                    .find(|id: &ControlId| id.kind == kind)
                {
                    narf_drivers_sound::control_changed(card, id);
                }
            }
        }
        if !reconfigure {
            return Ok(());
        }
        let params = self.streams[0].lock().ring.as_ref().map(|ring| ring.params);
        if let Some(params) = params {
            for index in changed {
                let (output, gained) = {
                    let ports = self.hdmi.lock();
                    let port = &ports[index];
                    (port.output, port.sink.is_some() && !before[index])
                };
                if gained {
                    self.configure_path(&self.outputs[output], output, false, params)?;
                }
            }
        }
        Ok(())
    }
}
