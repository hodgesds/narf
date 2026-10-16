//! AMD/ATI GPU HDMI/DP ports: emulated ELD, CEA channel allocation and
//! jack-driven routing. Linux references: sound/hda/codecs/hdmi/atihdmi.c
//! (get_eld_ati, atihdmi_pin_set_slot_channel), hdmi.c
//! (hdmi_present_sense_via_verbs, update_eld,
//! snd_hda_hdmi_setup_audio_infoframe), eld.c
//! (snd_hdmi_eld_update_pcm_info), sound/core/pcm_drm_eld.c (snd_parse_eld)
//! and sound/hda/core/hdmi_chmap.c (channel_allocations,
//! hdmi_std_setup_channel_mapping, the channel-map control). Compressed
//! passthrough follows sound/hda/common/codec.c's IEC958 controls and
//! hdmi.c/atihdmi.c's non-PCM, ramp-rate and HBR handling.
use super::*;
use crate::hda_codec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use narf_drivers_sound::{
    format::{ChannelCount, SampleRate},
    mixer::{ControlId, ControlKind},
    SoundError,
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
const SET_DIGI_CONVERT_1: u32 = 0x70d;
const SET_DIGI_CONVERT_2: u32 = 0x70e;

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
    /// Union of every SAD's sample rates (CEA bits: 32, 44.1, 48, 88.2,
    /// 96, 176.4, 192 kHz), as snd_hdmi_eld_update_pcm_info collects them.
    pub rates: u8,
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
    let mut rates = 0;
    for i in 0..sad_count {
        let at = ELD_FIXED_BYTES + mnl + 3 * i;
        let sad = buf.get(at..at + 3)?;
        channels_max = channels_max.max((sad[0] & 7) + 1);
        rates |= sad[1] & 0x7f;
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
        rates,
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

fn speaker_mask(speakers: &[u32; 8]) -> u32 {
    speakers.iter().fold(0, |m, s| m | s)
}

// ALSA channel positions (SNDRV_CHMAP_*) and map_tables' speaker for each.
const CHMAP_NA: u8 = 1;
pub(crate) const CHMAP_LAST: u8 = 36;
const CHMAP_SPEAKERS: [(u8, u32); 17] = [
    (3, FL),
    (4, FR),
    (5, RL),
    (6, RR),
    (8, LFE),
    (7, FC),
    (14, RLC),
    (15, RRC),
    (11, RC),
    (12, FLC),
    (13, FRC),
    (22, FLH), // TFL
    (23, FRH), // TFR
    (16, FLW),
    (17, FRW),
    (21, TC),
    (24, FCH), // TFC
];
/// `snd_hdac_chmap_to_spk_mask`.
fn chmap_to_speaker(position: u8) -> u32 {
    CHMAP_SPEAKERS
        .iter()
        .find(|(p, _)| *p == position)
        .map_or(0, |(_, s)| *s)
}
/// `snd_hdac_spk_to_chmap`.
fn speaker_to_chmap(speaker: u32) -> u8 {
    CHMAP_SPEAKERS
        .iter()
        .find(|(_, s)| *s == speaker)
        .map_or(0, |(p, _)| *p)
}

/// `hdmi_manual_channel_allocation`: the first CA (in Linux's order) whose
/// channel count is `channels` or the number of placed speakers, and whose
/// speakers the map all names.
pub(crate) fn manual_allocation(channels: usize, map: &[u8; 8]) -> Option<u8> {
    let (placed, mask) = map[..channels.min(8)]
        .iter()
        .map(|p| chmap_to_speaker(*p))
        .filter(|m| *m != 0)
        .fold((0, 0), |(n, mask), m| (n + 1, mask | m));
    ALLOCATIONS
        .iter()
        .find(|(_, s)| {
            let n = usize::from(allocation_channels(s));
            (channels == n || placed == n) && mask & speaker_mask(s) == speaker_mask(s)
        })
        .map(|(ca, _)| *ca)
}

/// `snd_hdac_channel_allocation`: a user map (PCM only) chooses the CA,
/// else the sink's speakers do. An unmatched user map falls back to CA 0.
pub(crate) fn stream_allocation(spk_alloc: u16, channels: u8, pcm: &Playback) -> u8 {
    if !pcm.non_pcm && pcm.chmap_set {
        manual_allocation(usize::from(channels), &pcm.chmap).unwrap_or(0)
    } else {
        channel_allocation(spk_alloc, channels)
    }
}

/// `snd_hdac_setup_channel_mapping`'s slot entries, `(channel << 4) | slot`
/// with channel 0xf for an empty slot: a user map
/// (`hdmi_manual_setup_channel_mapping`), stream order for non-PCM, else
/// Linux's standard layout.
pub(crate) fn slot_entries(ca: u8, channels: u8, pcm: &Playback) -> [u8; 8] {
    if !pcm.non_pcm && pcm.chmap_set {
        let speakers = allocation(ca);
        let mut assignments = [0xf_u8; 8];
        for (position, chmap) in pcm.chmap[..usize::from(channels.min(8))].iter().enumerate() {
            let mask = chmap_to_speaker(*chmap);
            if mask == 0 {
                continue;
            }
            if let Some(slot) = (0..8).find(|slot| speakers[7 - slot] == mask) {
                assignments[slot] = position as u8;
            }
        }
        return core::array::from_fn(|slot| (assignments[slot] << 4) | slot as u8);
    }
    if pcm.non_pcm {
        let active = active_channels(ca);
        return core::array::from_fn(|i| {
            let i = i as u8;
            if i < active {
                (i << 4) | i
            } else {
                0xf0 | i
            }
        });
    }
    channel_mapping(ca)
}

/// `hdmi_setup_fake_chmap`: the ALSA map the standard layout for `ca`
/// produces, which the control reports until userspace sets one.
pub(crate) fn default_chmap(ca: u8) -> [u8; 8] {
    let speakers = allocation(ca);
    let mapping = channel_mapping(ca);
    let active = usize::from(allocation_channels(speakers));
    core::array::from_fn(|i| {
        if i < active {
            speaker_to_chmap(speakers[7 - usize::from(mapping[i] & 0xf)])
        } else {
            0
        }
    })
}

/// atihdmi_paired_swap_fc_lfe: pairwise mode swaps FC and LFE itself.
fn paired_swap(position: usize) -> usize {
    match position {
        2 => 3,
        3 => 2,
        position => position,
    }
}

/// `atihdmi_paired_chmap_validate`: pre-rev3 ATI codecs remap only whole
/// slot pairs, so each mapped pair must land on one CA pair in order.
pub(crate) fn paired_chmap_valid(ca: u8, map: &[u8; 8]) -> bool {
    let cap = allocation(ca);
    let mut i = 0;
    while i < 8 {
        let mask = chmap_to_speaker(map[i]);
        if mask == 0 {
            i += 1;
            continue;
        }
        let mut companion = false;
        let Some(j) = (i % 2..8)
            .step_by(2)
            .find(|j| cap[7 - paired_swap(*j)] == mask)
        else {
            return false;
        };
        if i % 2 == 0 && i + 1 < 8 {
            if chmap_to_speaker(map[i + 1]) != cap[7 - paired_swap(j + 1)] {
                return false;
            }
            companion = true;
        }
        i += if companion { 2 } else { 1 };
    }
    true
}

/// `hdmi_chmap_ctl_tlv`: a TLV container with one entry per CA the sink's
/// speakers cover, two channels upward. Rev3+ maps are freely swappable
/// (CHMAP_VAR); pre-rev3 ones pair-wise (CHMAP_PAIRED, with N/A beside a
/// lone speaker of a pair). `None` where Linux returns -ENODEV: a pre-rev3
/// layout that cannot be expressed in pairs.
pub(crate) fn chmap_tlv(spk_alloc: u16, paired: bool) -> Option<Vec<u32>> {
    const TLVT_CONTAINER: u32 = 0;
    const TLVT_CHMAP_VAR: u32 = 0x102;
    const TLVT_CHMAP_PAIRED: u32 = 0x103;
    let spk_mask = ELD_SPEAKERS
        .iter()
        .enumerate()
        .filter(|(bit, _)| spk_alloc & (1 << bit) != 0)
        .fold(ELD_SPEAKERS[0], |mask, (_, speakers)| mask | speakers);
    let mut words = alloc::vec![TLVT_CONTAINER, 0];
    for channels in 2..=spk_mask.count_ones() {
        for (_, cap) in &ALLOCATIONS {
            if u32::from(allocation_channels(cap)) != channels
                || speaker_mask(cap) & spk_mask != speaker_mask(cap)
            {
                continue;
            }
            let mut positions = Vec::new();
            let kind = if paired {
                let pairs = (0..8)
                    .step_by(2)
                    .filter(|c| cap[*c] != 0 || cap[c + 1] != 0);
                if channels % 2 != 0 || pairs.count() as u32 * 2 != channels {
                    return None;
                }
                for c in (0..8).rev() {
                    let chan = 7 - paired_swap(7 - c);
                    match cap[chan] {
                        0 if cap[chan ^ 1] != 0 => positions.push(u32::from(CHMAP_NA)),
                        0 => {}
                        speaker => positions.push(u32::from(speaker_to_chmap(speaker))),
                    }
                }
                TLVT_CHMAP_PAIRED
            } else {
                for speaker in cap.iter().rev().filter(|s| **s != 0) {
                    positions.push(u32::from(speaker_to_chmap(*speaker)));
                }
                TLVT_CHMAP_VAR
            };
            words.extend([kind, channels * 4]);
            words.extend(positions);
        }
    }
    words[1] = (words.len() as u32 - 2) * 4;
    Some(words)
}

// IEC958 channel-status bits (asoundef.h) and the digital converter's DIG1
// byte (hda_verbs.h).
const AES0_PROFESSIONAL: u32 = 1 << 0;
const AES0_NONAUDIO: u32 = 1 << 1;
const AES0_PRO_EMPHASIS: u32 = 7 << 2;
const AES0_PRO_EMPHASIS_5015: u32 = 3 << 2;
const AES0_CON_NOT_COPYRIGHT: u32 = 1 << 2;
const AES0_CON_EMPHASIS: u32 = 7 << 3;
const AES0_CON_EMPHASIS_5015: u32 = 1 << 3;
const AES1_CON_CATEGORY: u32 = 0x7f;
const AES1_CON_ORIGINAL: u32 = 1 << 7;
pub(crate) const DIG1_ENABLE: u16 = 1 << 0;
const DIG1_EMPHASIS: u16 = 1 << 3;
const DIG1_COPYRIGHT: u16 = 1 << 4;
const DIG1_NONAUDIO: u16 = 1 << 5;
const DIG1_PROFESSIONAL: u16 = 1 << 6;
const DIG1_LEVEL: u16 = 1 << 7;
/// `snd_hda_spdif_cmask_get` / `snd_hda_spdif_pmask_get`.
pub(crate) const CON_MASK: [u8; 2] = [
    (AES0_PROFESSIONAL | AES0_NONAUDIO | AES0_CON_EMPHASIS_5015 | AES0_CON_NOT_COPYRIGHT) as u8,
    (AES1_CON_CATEGORY | AES1_CON_ORIGINAL) as u8,
];
pub(crate) const PRO_MASK: [u8; 1] =
    [(AES0_PROFESSIONAL | AES0_NONAUDIO | AES0_PRO_EMPHASIS_5015) as u8];

/// `convert_from_spdif_status`: DIG1 (low byte) and DIG2 for channel
/// status `sbits`, DIGEN clear.
pub(crate) fn spdif_ctls(sbits: u32) -> u16 {
    let mut val = 0;
    if sbits & AES0_PROFESSIONAL != 0 {
        val |= DIG1_PROFESSIONAL;
    }
    if sbits & AES0_NONAUDIO != 0 {
        val |= DIG1_NONAUDIO;
    }
    if sbits & AES0_PROFESSIONAL != 0 {
        if sbits & AES0_PRO_EMPHASIS == AES0_PRO_EMPHASIS_5015 {
            val |= DIG1_EMPHASIS;
        }
    } else {
        if sbits & AES0_CON_EMPHASIS == AES0_CON_EMPHASIS_5015 {
            val |= DIG1_EMPHASIS;
        }
        if sbits & AES0_CON_NOT_COPYRIGHT == 0 {
            val |= DIG1_COPYRIGHT;
        }
        if sbits & (AES1_CON_ORIGINAL << 8) != 0 {
            val |= DIG1_LEVEL;
        }
        val |= (sbits & (AES1_CON_CATEGORY << 8)) as u16;
    }
    val
}

/// `convert_to_spdif_status`.
pub(crate) fn spdif_status(val: u16) -> u32 {
    let mut sbits = 0;
    if val & DIG1_NONAUDIO != 0 {
        sbits |= AES0_NONAUDIO;
    }
    if val & DIG1_PROFESSIONAL != 0 {
        sbits |= AES0_PROFESSIONAL;
    }
    if sbits & AES0_PROFESSIONAL != 0 {
        if val & DIG1_EMPHASIS != 0 {
            sbits |= AES0_PRO_EMPHASIS_5015;
        }
    } else {
        if val & DIG1_EMPHASIS != 0 {
            sbits |= AES0_CON_EMPHASIS_5015;
        }
        if val & DIG1_COPYRIGHT == 0 {
            sbits |= AES0_CON_NOT_COPYRIGHT;
        }
        if val & DIG1_LEVEL != 0 {
            sbits |= AES1_CON_ORIGINAL << 8;
        }
        sbits |= u32::from(val) & (0x7f << 8);
    }
    sbits
}

/// The HDMI playback PCM's digital-output and channel-map state (Linux
/// keeps it in hda_spdif_out and hdmi_spec_per_pin). One native PCM
/// mirrors to every routed port, so this is shared by all of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Playback {
    /// IEC958 channel status, AES0..AES3 ("IEC958 Playback Default").
    pub status: u32,
    /// DIG1 (low byte, with DIGEN) and DIG2 every port's converter carries.
    pub ctls: u16,
    /// The non-audio bit as of the last hw_params/prepare (per_pin->non_pcm):
    /// IEC 61937 data in place of LPCM.
    pub non_pcm: bool,
    /// The channel map and whether userspace set it (per_pin->chmap{,_set});
    /// otherwise the standard layout's map after a prepare.
    pub chmap: [u8; 8],
    pub chmap_set: bool,
}
impl Playback {
    /// From the converter's DIG1/DIG2 (snd_hda_create_dig_out_ctls), with
    /// the digital output enabled: the PCM has no other owner of DIGEN and
    /// playback to a monitor must not depend on a userspace hook.
    pub fn from_converter(dig: u16) -> Self {
        let ctls = dig | DIG1_ENABLE;
        Self {
            status: spdif_status(ctls),
            ctls,
            non_pcm: false,
            chmap: [0; 8],
            chmap_set: false,
        }
    }
    /// The non-audio bit of the current channel status.
    pub fn nonaudio(&self) -> bool {
        self.status & AES0_NONAUDIO != 0
    }
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

    /// The PCM's digital state from the first port's converter
    /// (snd_hda_create_dig_out_ctls reads GET_DIGI_CONVERT_1).
    pub(super) fn initial_hdmi_playback(&self) -> Result<Playback, HdaError> {
        let Some(port) = self.hdmi.lock().first().map(|p| p.output) else {
            return Ok(Playback::from_converter(0));
        };
        let path = &self.outputs[port];
        let dig = self.verb(
            self.graphs[path.codec].addr,
            path.nodes.converter_nid,
            0xf0d << 8,
        )?;
        Ok(Playback::from_converter(dig as u16))
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
    /// native PCM mirrors to every routed port): channel ceiling, whether
    /// S32_LE is allowed and the CEA rate bits. Without any ELD: the ATI
    /// converter's own 8 / S32 / every rate (atihdmi_probe's
    /// SUPPORTED_RATES).
    pub(super) fn hdmi_limits(&self) -> Option<(u8, bool, u8)> {
        let ports = self.hdmi.lock();
        if ports.is_empty() {
            return None;
        }
        Some(
            ports
                .iter()
                .filter_map(|p| p.sink.as_ref().filter(|_| p.present))
                .fold((8, true, 0x7f), |(channels, s32, rates), sink| {
                    (
                        channels.min(sink.channels_max),
                        s32 && sink.s32,
                        rates & sink.rates,
                    )
                }),
        )
    }

    /// Playback rates on a GPU codec: the sinks' common SAD rates the
    /// sound core can name (no 32 kHz), 48 kHz when they share none.
    pub(super) fn playback_rates(&self) -> Vec<SampleRate> {
        let Some((_, _, rates)) = self.hdmi_limits() else {
            return alloc::vec![SampleRate::R48000];
        };
        let rates: Vec<SampleRate> = [
            (1, SampleRate::R44100),
            (2, SampleRate::R48000),
            (3, SampleRate::R88200),
            (4, SampleRate::R96000),
            (5, SampleRate::R176400),
            (6, SampleRate::R192000),
        ]
        .into_iter()
        .filter(|(bit, _)| rates & (1 << bit) != 0)
        .map(|(_, rate)| rate)
        .collect();
        if rates.is_empty() {
            alloc::vec![SampleRate::R48000]
        } else {
            rates
        }
    }

    /// The port the ELD, jack and channel-map controls describe: the first
    /// with a monitor and valid ELD, else the first port.
    pub(super) fn hdmi_primary(&self) -> Option<usize> {
        let ports = self.hdmi.lock();
        ports
            .iter()
            .find(|p| p.present && p.sink.is_some())
            .or(ports.first())
            .map(|p| p.output)
    }

    /// Pre-rev3 ATI codecs remap channels in pairs (has_amd_full_remap_support).
    fn hdmi_paired(&self) -> bool {
        self.hdmi
            .lock()
            .iter()
            .any(|p| !hda_codec::ati_hdmi_rev3(&self.graphs[self.outputs[p.output].codec]))
    }

    /// `set_dig_out_convert` on every HDMI converter: DIG1 and, with
    /// `dig2`, DIG2.
    fn write_spdif_ctls(&self, ctls: u16, dig2: bool) -> Result<(), HdaError> {
        let outputs: Vec<usize> = self.hdmi.lock().iter().map(|p| p.output).collect();
        for output in outputs {
            let path = &self.outputs[output];
            let (cad, cvt) = (self.graphs[path.codec].addr, path.nodes.converter_nid);
            self.verb(cad, cvt, (SET_DIGI_CONVERT_1 << 8) | u32::from(ctls & 0xff))?;
            if dig2 {
                self.verb(cad, cvt, (SET_DIGI_CONVERT_2 << 8) | u32::from(ctls >> 8))?;
            }
        }
        Ok(())
    }

    /// `snd_hda_spdif_default_put`: new channel status; the converters
    /// take its DIG1/DIG2 when they change. The non-audio bit applies to
    /// the stream at its next hw_params or prepare.
    pub(super) fn set_spdif_status(&self, status: [u8; 24]) -> Result<(), HdaError> {
        let sbits = u32::from_le_bytes([status[0], status[1], status[2], status[3]]);
        let old = self.hdmi_playback.lock().ctls;
        let ctls = spdif_ctls(sbits) | (old & DIG1_ENABLE);
        // No codec command runs under the IRQ-safe state lock.
        if ctls != old {
            self.write_spdif_ctls(ctls, true)?;
        }
        let mut pcm = self.hdmi_playback.lock();
        pcm.status = sbits;
        pcm.ctls = ctls;
        Ok(())
    }

    /// `snd_hda_spdif_out_switch_put`: DIGEN on every HDMI converter.
    pub(super) fn set_spdif_enable(&self, enable: bool) -> Result<(), HdaError> {
        let old = self.hdmi_playback.lock().ctls;
        let ctls = (old & !DIG1_ENABLE) | if enable { DIG1_ENABLE } else { 0 };
        if ctls != old {
            self.write_spdif_ctls(ctls, false)?;
        }
        self.hdmi_playback.lock().ctls = ctls;
        Ok(())
    }

    /// `hdmi_chmap_ctl_tlv` for the primary port's speakers.
    pub(super) fn chmap_tlv(&self) -> Option<Vec<u32>> {
        let spk_alloc = self
            .hdmi_primary()
            .and_then(|o| self.hdmi_sink(o))
            .map_or(0, |s| s.spk_alloc);
        chmap_tlv(spk_alloc, self.hdmi_paired())
    }

    /// `hdmi_chmap_ctl_put`. Ignored without an open stream (so a saved
    /// state restores harmlessly), refused once the stream runs. A map no
    /// CA carries, or (pre-rev3) one that splits a slot pair, is invalid.
    /// With the stream prepared, every routed port takes it immediately.
    pub(super) fn set_chmap(&self, values: &[i32]) -> Result<(), SoundError> {
        if values.len() != 8
            || values
                .iter()
                .any(|v| !(0..=i32::from(CHMAP_LAST)).contains(v))
        {
            return Err(SoundError::OutOfRange);
        }
        let map: [u8; 8] = core::array::from_fn(|i| values[i] as u8);
        let (prepared, channels) = {
            let stream = self.streams[0].lock();
            let Some(prepared) = stream.chmap_state()? else {
                return Ok(());
            };
            let channels = stream.ring.as_ref().map(|r| r.params.channels.count());
            (prepared, channels)
        };
        if self.hdmi_playback.lock().chmap == map {
            return Ok(());
        }
        let ca = manual_allocation(8, &map).ok_or(SoundError::OutOfRange)?;
        if self.hdmi_paired() && !paired_chmap_valid(ca, &map) {
            return Err(SoundError::OutOfRange);
        }
        let pcm = {
            let mut pcm = self.hdmi_playback.lock();
            pcm.chmap = map;
            pcm.chmap_set = true;
            *pcm
        };
        if let (true, Some(channels)) = (prepared, channels) {
            for output in self.routed_outputs() {
                let path = &self.outputs[output];
                let graph = &self.graphs[path.codec];
                if !hda_codec::is_ati_hdmi(graph) {
                    continue;
                }
                let spk_alloc = self.hdmi_sink(output).map_or(0, |s| s.spk_alloc);
                self.ati_hdmi_infoframe(graph, &path.nodes, channels, spk_alloc, &pcm)
                    .map_err(|_| SoundError::BadState)?;
            }
        }
        Ok(())
    }

    /// hdmi_pcm_close: the user map lasts as long as the stream is open.
    pub(super) fn reset_chmap(&self) {
        let mut pcm = self.hdmi_playback.lock();
        pcm.chmap = [0; 8];
        pcm.chmap_set = false;
    }

    /// Latch the non-audio bit for the stream being set up.
    pub(super) fn latch_non_pcm(&self) {
        let mut pcm = self.hdmi_playback.lock();
        pcm.non_pcm = pcm.nonaudio();
    }

    /// Channel counts playback offers: stereo, plus the even surround
    /// layouts up to the HDMI ceiling on a GPU codec (ATI converters take
    /// eight channels whatever they advertise; Linux atihdmi_probe).
    pub(super) fn playback_channels(&self) -> Vec<ChannelCount> {
        let max = self.hdmi_limits().map_or(2, |(channels, _, _)| channels);
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
