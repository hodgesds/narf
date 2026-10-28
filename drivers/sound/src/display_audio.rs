//! Display-audio sink — the shared ELD publication surface.
//!
//! SEAM — SHARED DISPLAY-AUDIO SINK (named for its consumers).
//!
//! Display pipelines (DP/HDMI) produce an ELD (EDID-Like Data)
//! describing the *sink's* audio capabilities; the HDA/ALSA side
//! consumes it to expose the HDMI/DP jack + ELD controls and to
//! gate stream formats. This module is the one meeting point:
//!
//!   - **Publishers** (display lanes) build an ELD from the
//!     sink's EDID with [`build_eld`] and publish it with
//!     [`publish_display_audio`], clearing it with
//!     [`clear_display_audio`] on disconnect. First publisher:
//!     the Intel DP-full lane (#1092). **HDMI-full (#1019)
//!     consumes this exact seam as the second publisher** — it
//!     must not grow a second sink. The AMD display-audio gap
//!     (#778) closes by publishing here too when that lane runs.
//!   - **Consumers** (HDA codec / ALSA bridge) read the current
//!     publication with [`current_display_audio`] /
//!     [`display_audio_snapshot`].
//!
//! ## ELD byte layout
//!
//! The baseline ELD follows CEA-861-D §7.5 / the HD-Audio ELD
//! definition, field-for-field as the HDA codec's own parser
//! (`snd_hdmi_parse_eld`) decodes it:
//!
//! ```text
//! byte 0      bits[7:3] ELD version = 2 (CEA-861-D)
//! byte 2      baseline ELD length, in 4-byte units, covering
//!             the whole baseline block (fixed part + name + SADs)
//! byte 4      bits[4:0] monitor-name length (MNL, ≤ 16)
//!             bits[7:5] CEA-EDID version (from the CTA extension)
//! byte 5      bit 0 HDCP support, bit 1 AI support,
//!             bits[3:2] connection type (0 = HDMI, 1 = DP),
//!             bits[7:4] SAD count (≤ 15)
//! byte 6      A/V sync delay, in 2 ms units (0 = not reported)
//! byte 7      bits[6:0] speaker allocation (CTA speaker block)
//! bytes 8–15  port ID (little-endian, publisher-assigned)
//! bytes 16–17 manufacturer ID (EDID bytes 8–9, verbatim)
//! bytes 18–19 product code (EDID bytes 10–11, verbatim — the
//!             EDID stores this field little-endian already)
//! bytes 20..  monitor name (MNL bytes), then the SADs verbatim
//!             (3 bytes each) from the CTA audio data block
//! ```

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// Fixed part of the baseline ELD, before the monitor name.
pub const ELD_FIXED_BYTES: usize = 20;
/// Maximum monitor-name length the ELD carries.
pub const ELD_MAX_MNL: usize = 16;
/// Maximum number of Short Audio Descriptors in one ELD.
pub const ELD_MAX_SAD: usize = 15;
/// Largest ELD this sink stores: fixed part + name + all SADs.
pub const ELD_MAX_BYTES: usize = ELD_FIXED_BYTES + ELD_MAX_MNL + ELD_MAX_SAD * 3;

/// CEA-861-D ELD version written at byte 0 bits[7:3].
const ELD_VER_CEA_861D: u8 = 2;

/// Connection type for the ELD byte-5 bits[3:2] field.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DisplayConnector {
    /// HDMI (connection-type field 0).
    Hdmi,
    /// DisplayPort (connection-type field 1).
    DisplayPort,
}

impl DisplayConnector {
    fn eld_conn_type(self) -> u8 {
        match self {
            DisplayConnector::Hdmi => 0,
            DisplayConnector::DisplayPort => 1,
        }
    }
}

/// Identity of one display-audio sink slot. Publishers assign
/// these from their own connector numbering (the Intel lane
/// uses `DDI index + 1`, reserving 0); the sink treats the id
/// as opaque and ids never alias across publishers as long as
/// each publisher owns a distinct range — the Intel DP lane
/// owns `1..=8` (DDI A–H), and #1019's HDMI publisher on the
/// same DDI space reuses the same id for the same physical
/// connector, since a connector is either DP or HDMI at a time.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisplaySinkId(pub u32);

/// A built ELD plus the LPCM capability summary the consumer
/// side needs without re-parsing SADs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayAudioPublication {
    /// The ELD bytes, `eld_len` of `eld` valid.
    pub eld: [u8; ELD_MAX_BYTES],
    /// Number of valid bytes in `eld`.
    pub eld_len: u8,
    /// Channels of the best LPCM SAD (0 when the sink reported
    /// no LPCM descriptor).
    pub lpcm_max_channels: u8,
    /// Sample-rate mask of the best LPCM SAD (CTA SAD byte 1:
    /// bit 0 = 32 kHz, 1 = 44.1, 2 = 48, 3 = 88.2, 4 = 96,
    /// 5 = 176.4, 6 = 192).
    pub lpcm_sample_rates: u8,
    /// Bit-depth mask of the best LPCM SAD (CTA SAD byte 2
    /// bits[2:0]: bit 0 = 16-bit, 1 = 20-bit, 2 = 24-bit).
    pub lpcm_bit_depths: u8,
    /// Total SAD count carried in the ELD (all formats).
    pub sad_count: u8,
}

impl DisplayAudioPublication {
    /// The valid ELD bytes.
    pub fn eld_bytes(&self) -> &[u8] {
        &self.eld[..self.eld_len as usize]
    }
}

/// Build an ELD publication from a complete EDID (base block +
/// extension blocks, as produced by
/// `narf_drivers_gpu::dp_edid::read_full_edid` on the DP side).
///
/// Returns `None` when the sink has no audio story to tell: the
/// EDID is truncated, carries no CTA-861 extension, or the CTA
/// extension carries no audio data block / no SADs. A `None`
/// here is a *fact about the sink*, not an error — the display
/// lane simply does not enable display audio.
///
/// Fields the EDID cannot express stay at their "not reported"
/// encodings: HDCP/AI support bits are 0 and the A/V sync delay
/// is 0 (the graphics driver learns both later than EDID time
/// on real stacks too; Linux's `drm_edid_to_eld` leaves them
/// likewise until the connector properties land).
pub fn build_eld(
    edid: &[u8],
    connector: DisplayConnector,
    port_id: u64,
) -> Option<DisplayAudioPublication> {
    if edid.len() < 128 {
        return None;
    }
    // Locate the CTA-861 extension (tag 0x02) among the blocks
    // the base block advertises.
    let extensions = edid[126] as usize;
    let mut cta: Option<&[u8]> = None;
    for i in 0..extensions {
        let off = (i + 1) * 128;
        if off + 128 > edid.len() {
            break;
        }
        if edid[off] == 0x02 {
            cta = Some(&edid[off..off + 128]);
            break;
        }
    }
    let cta = cta?;
    let cea_version = cta[1];

    // Walk the CTA data-block collection: blocks start at
    // offset 4 and end at the detailed-timing offset (byte 2),
    // or at the first zero header.
    let dtd_start = (cta[2] as usize).min(127);
    let mut sads: [[u8; 3]; ELD_MAX_SAD] = [[0u8; 3]; ELD_MAX_SAD];
    let mut sad_count = 0usize;
    let mut speaker_alloc: u8 = 0;
    let mut pos = 4usize;
    while pos < dtd_start && pos < 127 {
        let header = cta[pos];
        if header == 0 {
            break;
        }
        let tag = header >> 5;
        let len = (header & 0x1F) as usize;
        let body = pos + 1;
        if body + len > 128 {
            break;
        }
        match tag {
            // Audio data block: a run of 3-byte SADs.
            1 => {
                let mut j = 0usize;
                while j + 3 <= len && sad_count < ELD_MAX_SAD {
                    sads[sad_count] = [cta[body + j], cta[body + j + 1], cta[body + j + 2]];
                    sad_count += 1;
                    j += 3;
                }
            }
            // Speaker-allocation data block: byte 0 is the
            // allocation bitmask the ELD carries at byte 7.
            4 => {
                if len >= 1 {
                    speaker_alloc = cta[body] & 0x7F;
                }
            }
            _ => {}
        }
        pos = body + len;
    }
    if sad_count == 0 {
        return None;
    }

    // Monitor name: the base block's 0xFC descriptor, if any.
    // Descriptors live at offsets 54/72/90/108; the name string
    // is 13 bytes, 0x0A-terminated, space-padded.
    let mut name: [u8; ELD_MAX_MNL] = [0u8; ELD_MAX_MNL];
    let mut mnl = 0usize;
    for desc_off in [54usize, 72, 90, 108] {
        if edid[desc_off] == 0 && edid[desc_off + 1] == 0 && edid[desc_off + 3] == 0xFC {
            for k in 0..13 {
                let c = edid[desc_off + 5 + k];
                if c == 0x0A || mnl >= ELD_MAX_MNL {
                    break;
                }
                name[mnl] = c;
                mnl += 1;
            }
            break;
        }
    }

    // LPCM summary: the LPCM SAD (format tag 1 in bits[6:3] of
    // SAD byte 0) with the most channels.
    let mut lpcm_max_channels = 0u8;
    let mut lpcm_sample_rates = 0u8;
    let mut lpcm_bit_depths = 0u8;
    for sad in sads.iter().take(sad_count) {
        if (sad[0] >> 3) & 0xF == 1 {
            let channels = (sad[0] & 0x07) + 1;
            if channels > lpcm_max_channels {
                lpcm_max_channels = channels;
                lpcm_sample_rates = sad[1];
                lpcm_bit_depths = sad[2] & 0x07;
            }
        }
    }

    let total = ELD_FIXED_BYTES + mnl + sad_count * 3;
    let mut eld = [0u8; ELD_MAX_BYTES];
    eld[0] = ELD_VER_CEA_861D << 3;
    // Baseline length in 4-byte units, rounded up.
    eld[2] = total.div_ceil(4) as u8;
    eld[4] = ((cea_version & 0x07) << 5) | (mnl as u8 & 0x1F);
    eld[5] = ((sad_count as u8 & 0x0F) << 4) | (connector.eld_conn_type() << 2);
    eld[6] = 0; // A/V sync delay not reported.
    eld[7] = speaker_alloc;
    eld[8..16].copy_from_slice(&port_id.to_le_bytes());
    eld[16] = edid[8];
    eld[17] = edid[9];
    eld[18] = edid[10];
    eld[19] = edid[11];
    eld[ELD_FIXED_BYTES..ELD_FIXED_BYTES + mnl].copy_from_slice(&name[..mnl]);
    for (i, sad) in sads.iter().take(sad_count).enumerate() {
        let at = ELD_FIXED_BYTES + mnl + i * 3;
        eld[at..at + 3].copy_from_slice(sad);
    }

    Some(DisplayAudioPublication {
        eld,
        eld_len: total as u8,
        lpcm_max_channels,
        lpcm_sample_rates,
        lpcm_bit_depths,
        sad_count: sad_count as u8,
    })
}

// ── Registry ────────────────────────────────────────────────────────

/// Maximum simultaneous display-audio publications. One per
/// physical connector on any realistic board.
const MAX_DISPLAY_SINKS: usize = 8;

static DISPLAY_AUDIO: IrqSafeSpinLock<
    [Option<(DisplaySinkId, DisplayAudioPublication)>; MAX_DISPLAY_SINKS],
> = IrqSafeSpinLock::new([const { None }; MAX_DISPLAY_SINKS]);

/// Publish (or replace) the display-audio state for `id`.
/// Called by a display lane when a sink with audio comes up.
/// If the table is full and `id` is new, the publication is
/// dropped — the table is sized past any real connector count,
/// and a silent drop beats aliasing two sinks.
pub fn publish_display_audio(id: DisplaySinkId, publication: DisplayAudioPublication) {
    let mut table = DISPLAY_AUDIO.lock();
    let mut empty: Option<usize> = None;
    for (i, slot) in table.iter_mut().enumerate() {
        match slot {
            Some((existing, _)) if *existing == id => {
                *slot = Some((id, publication));
                return;
            }
            None => {
                if empty.is_none() {
                    empty = Some(i);
                }
            }
            _ => {}
        }
    }
    if let Some(i) = empty {
        table[i] = Some((id, publication));
    }
}

/// Clear the publication for `id` (sink disconnected / audio
/// torn down). Clearing an unknown id is a no-op.
pub fn clear_display_audio(id: DisplaySinkId) {
    let mut table = DISPLAY_AUDIO.lock();
    for slot in table.iter_mut() {
        if let Some((existing, _)) = slot {
            if *existing == id {
                *slot = None;
            }
        }
    }
}

/// The current publication for `id`, if any.
pub fn current_display_audio(id: DisplaySinkId) -> Option<DisplayAudioPublication> {
    let table = DISPLAY_AUDIO.lock();
    table.iter().find_map(|slot| match slot {
        Some((existing, publication)) if *existing == id => Some(publication.clone()),
        _ => None,
    })
}

/// All current publications (consumer-side enumeration for the
/// ALSA bridge's per-connector control creation).
pub fn display_audio_snapshot() -> Vec<(DisplaySinkId, DisplayAudioPublication)> {
    let table = DISPLAY_AUDIO.lock();
    table.iter().filter_map(|slot| slot.clone()).collect()
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Hand-built EDID fixture: base block (manufacturer
    /// "NAR", product 0x1234, monitor-name descriptor
    /// "TEST DP MON") + one CTA-861 v3 extension carrying an
    /// LPCM SAD (2 ch, 32–192 kHz, 16/20/24-bit), an AC-3 SAD
    /// (6 ch, 32–48 kHz), and a speaker-allocation block
    /// (FL/FR = 0x01). Checksums computed per E-EDID.
    fn fixture_edid() -> [u8; 256] {
        let mut e = [0u8; 256];
        // Base block header + identity.
        e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        // Manufacturer "NAR": (N=14)<<10 | (A=1)<<5 | (R=18).
        let mfr: u16 = (14 << 10) | (1 << 5) | 18;
        e[8] = (mfr >> 8) as u8;
        e[9] = mfr as u8;
        e[10] = 0x34; // product 0x1234, little-endian
        e[11] = 0x12;
        e[18] = 1; // EDID 1.4
        e[19] = 4;
        e[126] = 1; // one extension
                    // Monitor-name descriptor at offset 54 (tag 0xFC).
        e[54 + 3] = 0xFC;
        let name = b"TEST DP MON";
        e[54 + 5..54 + 5 + name.len()].copy_from_slice(name);
        e[54 + 5 + name.len()] = 0x0A;
        for b in &mut e[54 + 5 + name.len() + 1..54 + 18] {
            *b = 0x20;
        }
        // CTA extension at 128: tag 0x02, rev 3, DTD offset,
        // basic-audio flag (byte 3 bit 6).
        let cta = 128usize;
        e[cta] = 0x02;
        e[cta + 1] = 3;
        e[cta + 3] = 0x40;
        let mut p = cta + 4;
        // Audio data block (tag 1, len 6): two SADs.
        e[p] = (1 << 5) | 6;
        p += 1;
        // LPCM: format 1, 2 channels (field = ch-1 = 1).
        e[p] = (1 << 3) | 1;
        e[p + 1] = 0x7F; // all rates 32..192 kHz
        e[p + 2] = 0x07; // 16/20/24-bit
        p += 3;
        // AC-3: format 2, 6 channels.
        e[p] = (2 << 3) | 5;
        e[p + 1] = 0x07; // 32/44.1/48 kHz
        e[p + 2] = 0x00; // max bitrate field (×8 kbps = 0, unused)
        p += 3;
        // Speaker-allocation block (tag 4, len 3): FL/FR.
        e[p] = (4 << 5) | 3;
        e[p + 1] = 0x01;
        p += 1 + 3;
        e[cta + 2] = (p - cta) as u8; // DTD offset = end of blocks
                                      // Checksums (each 128-byte block sums to 0 mod 256).
        let sum: u32 = e[..127].iter().map(|&b| b as u32).sum();
        e[127] = ((256 - (sum % 256)) % 256) as u8;
        let sum2: u32 = e[128..255].iter().map(|&b| b as u32).sum();
        e[255] = ((256 - (sum2 % 256)) % 256) as u8;
        e
    }

    fn smoke_build_eld_matches_consumer_layout() -> TestResult {
        let edid = fixture_edid();
        let pub_ = match build_eld(&edid, DisplayConnector::DisplayPort, 0x1122_3344_5566_7788) {
            Some(p) => p,
            None => return TestResult::Fail("CTA EDID with SADs must produce an ELD"),
        };
        let b = pub_.eld_bytes();
        // Layout per the HDA consumer parser's field offsets.
        if b[0] != 2 << 3 {
            return TestResult::Fail("ELD version field must be 2 at byte 0 bits[7:3]");
        }
        let total = 20 + 11 + 2 * 3;
        if pub_.eld_len as usize != total {
            return TestResult::Fail("ELD length must be fixed + name + SADs");
        }
        if b[2] as usize != total.div_ceil(4) {
            return TestResult::Fail("baseline length must be total/4 rounded up");
        }
        if b[4] & 0x1F != 11 || b[4] >> 5 != 3 {
            return TestResult::Fail("byte 4 must carry MNL=11 and CEA version 3");
        }
        if b[5] != (2 << 4) | (1 << 2) {
            return TestResult::Fail("byte 5 must carry SAD count 2 and DP conn type");
        }
        if b[7] != 0x01 {
            return TestResult::Fail("byte 7 must carry the speaker allocation");
        }
        if b[8..16] != 0x1122_3344_5566_7788u64.to_le_bytes() {
            return TestResult::Fail("port ID must be stored little-endian at bytes 8..16");
        }
        if b[16..20] != edid[8..12] {
            return TestResult::Fail("manufacturer + product must be copied from the EDID");
        }
        if &b[20..31] != b"TEST DP MON" {
            return TestResult::Fail("monitor name must follow the fixed part");
        }
        if b[31..34] != [0x09, 0x7F, 0x07] || b[34..37] != [0x15, 0x07, 0x00] {
            return TestResult::Fail("SADs must be copied verbatim after the name");
        }
        if pub_.lpcm_max_channels != 2
            || pub_.lpcm_sample_rates != 0x7F
            || pub_.lpcm_bit_depths != 0x07
        {
            return TestResult::Fail("LPCM summary must come from the LPCM SAD");
        }
        if pub_.sad_count != 2 {
            return TestResult::Fail("SAD count must be 2");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sound/display_audio",
        smoke_build_eld_matches_consumer_layout
    );

    fn smoke_build_eld_none_without_audio() -> TestResult {
        // Base block only, no extensions.
        let mut e = [0u8; 128];
        e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        if build_eld(&e, DisplayConnector::Hdmi, 0).is_some() {
            return TestResult::Fail("no CTA extension must mean no ELD");
        }
        // Truncated input.
        if build_eld(&e[..64], DisplayConnector::Hdmi, 0).is_some() {
            return TestResult::Fail("truncated EDID must mean no ELD");
        }
        // CTA extension present but zero SADs: strip the audio
        // block by moving the DTD offset to the first block.
        let mut e2 = fixture_edid();
        e2[128 + 2] = 4;
        if build_eld(&e2, DisplayConnector::DisplayPort, 0).is_some() {
            return TestResult::Fail("CTA without SADs must mean no ELD");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sound/display_audio",
        smoke_build_eld_none_without_audio
    );

    fn smoke_publish_clear_roundtrip() -> TestResult {
        let edid = fixture_edid();
        let pub_ = match build_eld(&edid, DisplayConnector::DisplayPort, 7) {
            Some(p) => p,
            None => return TestResult::Fail("fixture must build"),
        };
        let id = DisplaySinkId(0xD1092);
        clear_display_audio(id);
        if current_display_audio(id).is_some() {
            return TestResult::Fail("sink must start empty");
        }
        publish_display_audio(id, pub_.clone());
        match current_display_audio(id) {
            Some(got) if got == pub_ => {}
            _ => return TestResult::Fail("published ELD must read back verbatim"),
        }
        // A second id is independent.
        if current_display_audio(DisplaySinkId(0xD1093)).is_some() {
            return TestResult::Fail("unrelated sink id must stay empty");
        }
        if display_audio_snapshot()
            .iter()
            .filter(|(i, _)| *i == id)
            .count()
            != 1
        {
            return TestResult::Fail("snapshot must contain exactly one entry for the id");
        }
        clear_display_audio(id);
        if current_display_audio(id).is_some() {
            return TestResult::Fail("cleared sink must read back empty");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sound/display_audio", smoke_publish_clear_roundtrip);
}
