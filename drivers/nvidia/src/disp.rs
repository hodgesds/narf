//! Display engine — KMS scaffolding.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/dispnv50/disp.c`**
//!   — the Maxwell+ display top entry. Maxwell, Pascal, Volta,
//!   Turing, Ampere, Ada all share the NV50/NVD0/NV9x family of
//!   dispclasses.
//! - **`drivers/gpu/drm/nouveau/dispnv50/head.c`** + `head507d.c` /
//!   `head827d.c` / `head907d.c` / `head917d.c` / `headc37d.c` —
//!   per-ASIC head (CRTC) class.
//! - **`drivers/gpu/drm/nouveau/dispnv50/core.c`** + the matching
//!   `corec37d.c` / `corec57d.c` / `corec67d.c` — display "core"
//!   channel (mode-set submission).
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/bios/dcb.c`** — DCB
//!   table parse (display configuration block / connector
//!   enumeration).
//!
//! The dispclass numbers form the per-ASIC dispatch key in
//! `dispnv50/disp.c::nv50_disp_new_`. They're listed in
//! `include/nvif/class.h` (e.g. `NV50_DISP = 0x00005070`,
//! `GA102_DISP = 0x0000c670`).

#![allow(dead_code)]

use crate::chip::ChipFamily;

pub mod nv50;

// ── Dispclass numbers per family ─────────────────────────────────
//
// Cited `/home/daniel/git/linux/drivers/gpu/drm/nouveau/include/nvif/class.h`
// (`NV50_DISP` etc.) and `dispnv50/disp.c::nv50_disp_new_`.

/// NV50 — Maxwell (G84/GM107 era → GTX 9xx).
pub const NV50_DISP: u32 = 0x0000_5070;
/// NV82 — earlier Tesla (kept for completeness).
pub const NV82_DISP: u32 = 0x0000_8270;
/// NV84 — Tesla.
pub const NV84_DISP: u32 = 0x0000_8470;
/// NVA0 — Fermi.
pub const NVA0_DISP: u32 = 0x0000_a070;
/// NV90 — Fermi.
pub const NV90_DISP: u32 = 0x0000_9070;
/// NVA3 — Tesla GT215.
pub const NVA3_DISP: u32 = 0x0000_a370;
/// NV94 — Tesla.
pub const NV94_DISP: u32 = 0x0000_9470;
/// NV98 — Tesla.
pub const NV98_DISP: u32 = 0x0000_9870;
/// GF110 — Fermi.
pub const GF110_DISP: u32 = 0x0000_9170;
/// GK104 — Kepler.
pub const GK104_DISP: u32 = 0x0000_9270;
/// GK110 — Kepler.
pub const GK110_DISP: u32 = 0x0000_9270;
/// GM107 — Maxwell.
pub const GM107_DISP: u32 = 0x0000_9470;
/// GM200 — Maxwell.
pub const GM200_DISP: u32 = 0x0000_9570;
/// GP100 — Pascal.
pub const GP100_DISP: u32 = 0x0000_9770;
/// GP102 — Pascal.
pub const GP102_DISP: u32 = 0x0000_9870;
/// GV100 — Volta.
pub const GV100_DISP: u32 = 0x0000_c370;
/// TU102 — Turing.
pub const TU102_DISP: u32 = 0x0000_c570;
/// GA102 — Ampere.
pub const GA102_DISP: u32 = 0x0000_c670;
/// AD102 — Ada.
pub const AD102_DISP: u32 = 0x0000_c770;

/// Pick the dispclass for a chip family. Cite
/// `dispnv50/disp.c::nv50_disp_new_` for the same table.
pub const fn dispclass_for(family: ChipFamily) -> Option<u32> {
    match family {
        ChipFamily::Maxwell => Some(GM200_DISP),
        ChipFamily::Pascal => Some(GP102_DISP),
        ChipFamily::Volta => Some(GV100_DISP),
        ChipFamily::Turing => Some(TU102_DISP),
        ChipFamily::Ampere => Some(GA102_DISP),
        ChipFamily::Ada => Some(AD102_DISP),
        _ => None,
    }
}

// ── DCB (Display Configuration Block) ────────────────────────────
//
// Cite `nvkm/subdev/bios/dcb.c::dcb_outp_parse`. DCB lives in the
// VBIOS image; each entry describes one display output.

/// DCB entry — one display output. Cited
/// `nvkm/subdev/bios/dcb.c::dcb_outp_parse`.
///
/// The first 32-bit word holds the per-output identifier, packed as:
/// ```text
///   bits  3:0   type        (DCB_OUTPUT_*, our `encoder_type`)
///   bits  7:4   i2c_index
///   bits 11:8   heads bitmask
///   bits 15:12  connector index (into the connector table)
///   bits 19:16  bus
///   bits 21:20  location
///   bits 27:24  or (output resource)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DcbEntry {
    /// Encoder type (`DCB_OUTPUT_*` in the BIOS).
    pub encoder_type: EncoderType,
    /// Index into the BIOS connector table — the entry there
    /// names the physical connector. Stage 1 only carries the
    /// index; full table parse is a follow-up.
    pub connector_index: u8,
    /// Output resource — Maxwell+ SOR/PIOR/DAC index in
    /// bits[27:24] of the head word. Low byte = SOR/DAC index.
    pub or: u8,
    /// I²C bus index (DDC).
    pub i2c_index: u8,
    /// Heads this output can drive. Bit `n` = head `n`.
    pub heads: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncoderType {
    /// CRT (DAC).
    Crt,
    /// TMDS over DVI.
    Tmds,
    /// LVDS panel.
    Lvds,
    /// DisplayPort over SOR.
    DisplayPort,
    /// Embedded DisplayPort (eDP).
    Edp,
    /// HDMI over SOR.
    Hdmi,
    /// External / unspecified.
    External,
    Unknown(u8),
}

impl EncoderType {
    /// Map DCB type byte. Cite `dcb_outp_parse` field `i.type`.
    pub const fn from_dcb(t: u8) -> Self {
        match t {
            0x00 => EncoderType::Crt,
            0x01 => EncoderType::Tmds,
            0x02 => EncoderType::Lvds,
            0x03 => EncoderType::DisplayPort,
            0x06 => EncoderType::Hdmi,
            0x07 => EncoderType::Edp,
            0x08 => EncoderType::External,
            n => EncoderType::Unknown(n),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectorType {
    Vga,
    DviI,
    DviD,
    Hdmi,
    DisplayPort,
    Edp,
    Lvds,
    Unknown(u8),
}

impl ConnectorType {
    /// Map DCB connector-type byte. Cite `nvkm/subdev/bios/conn.c`.
    pub const fn from_dcb(t: u8) -> Self {
        match t {
            0x00 => ConnectorType::Vga,
            0x30 => ConnectorType::DviI,
            0x31 => ConnectorType::DviD,
            0x60 => ConnectorType::Hdmi,
            0x46 => ConnectorType::DisplayPort,
            0x47 => ConnectorType::Edp,
            0x40 => ConnectorType::Lvds,
            n => ConnectorType::Unknown(n),
        }
    }
}

/// Decode the common 32-bit identification word shared by all DCB
/// versions >= 2.0. Cite `nvkm/subdev/bios/dcb.c::dcb_outp_parse`
/// (`*ver >= 0x20` branch):
///
/// ```text
///   bits  3:0   type        (encoder)
///   bits  7:4   i2c_index
///   bits 11:8   heads bitmask
///   bits 15:12  connector index
///   bits 19:16  bus
///   bits 21:20  location
///   bits 27:24  or (output resource)
/// ```
///
/// Returns `None` on the "no-output" sentinels `0x0000_0000` and
/// `0xffff_ffff` (cite `dcb_outp_foreach`).
fn decode_dcb_head_word(w: u32) -> Option<DcbEntry> {
    if w == 0xFFFF_FFFF || w == 0x0000_0000 {
        return None;
    }
    let encoder_type = EncoderType::from_dcb((w & 0x0F) as u8);
    let i2c_index = ((w >> 4) & 0x0F) as u8;
    let heads = ((w >> 8) & 0x0F) as u8;
    let connector_index = ((w >> 12) & 0x0F) as u8;
    let or = ((w >> 24) & 0x0F) as u8;
    Some(DcbEntry {
        encoder_type,
        connector_index,
        or,
        i2c_index,
        heads,
    })
}

/// Decode an 8-byte DCB v4.0 entry. The second 32-bit word
/// (`conf`, at bytes[4..8]) carries per-type link configuration
/// (DP link rate/lane count, SOR dual-link select, etc.) but we
/// don't decode it here — the first word is sufficient for KMS
/// connector enumeration. Cite
/// `nvkm/subdev/bios/dcb.c::dcb_outp_parse`.
///
/// Returns `None` if the entry is the "no-output" sentinel.
pub fn decode_dcb_entry(raw: &[u8; 8]) -> Option<DcbEntry> {
    let head_word = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    decode_dcb_head_word(head_word)
}

/// Decode an 8-byte DCB v3.0 entry. DCB v3.0 (version 0x30..0x3f)
/// uses the same 32-bit identification word layout as v4.x but its
/// entries are only 8 bytes total — there is no second `conf` word
/// with per-type link configuration. Cite
/// `nvkm/subdev/bios/dcb.c::dcb_outp_parse` (`*ver >= 0x20`
/// branch, which covers v3.0).
///
/// Kepler / early Pascal / some Fermi VBIOSes use v3.0.
///
/// Returns `None` if the entry is the "no-output" sentinel.
pub fn decode_dcb_entry_v30(raw: &[u8; 8]) -> Option<DcbEntry> {
    let head_word = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    decode_dcb_head_word(head_word)
}

/// Version-routing DCB entry decoder. Dispatches to the v3.0 or
/// v4.x decoder based on the `version` byte from the DCB header.
///
/// - `0x30..0x3f` → [`decode_dcb_entry_v30`] (Kepler / early Pascal)
/// - `0x40..0x41` → [`decode_dcb_entry`] (Maxwell+)
///
/// Returns `None` for an unsupported version or a sentinel entry.
/// Cite `nvkm/subdev/bios/dcb.c::dcb_outp_parse`.
pub fn decode_dcb_entry_versioned(raw: &[u8; 8], version: u8) -> Option<DcbEntry> {
    match version {
        0x30..=0x3F => decode_dcb_entry_v30(raw),
        0x40..=0x41 => decode_dcb_entry(raw),
        _ => None,
    }
}

// ── KMS scaffolding ──────────────────────────────────────────────

/// Connector / encoder / CRTC triple — the KMS unit. Stage 2
/// scaffold; live mode-set wiring happens in nv50 module per
/// family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DisplayPath {
    pub connector_id: u8,
    pub encoder_id: u8,
    pub crtc_id: u8,
    pub encoder_type: EncoderType,
    pub connector_type: ConnectorType,
}

/// Mode descriptor — the timing parameters the CRTC's HEAD block
/// is programmed with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mode {
    pub clock_khz: u32,
    pub h_display: u16,
    pub h_sync_start: u16,
    pub h_sync_end: u16,
    pub h_total: u16,
    pub v_display: u16,
    pub v_sync_start: u16,
    pub v_sync_end: u16,
    pub v_total: u16,
    pub flags: ModeFlags,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct ModeFlags {
    pub hsync_positive: bool,
    pub vsync_positive: bool,
    pub interlaced: bool,
    pub double_scan: bool,
}

impl Mode {
    pub const fn refresh_hz(&self) -> u32 {
        if self.h_total == 0 || self.v_total == 0 {
            return 0;
        }
        let line_total = self.h_total as u32 * self.v_total as u32;
        if line_total == 0 {
            return 0;
        }
        (self.clock_khz * 1000) / line_total
    }
}
