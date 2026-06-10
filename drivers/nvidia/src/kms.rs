//! KMS — connector / encoder / CRTC enumeration + binding.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/dispnv50/disp.c`**
//!   `nv50_disp_atomic_*` — Maxwell+ atomic mode-set commit.
//! - **`drivers/gpu/drm/nouveau/dispnv50/head.c`** /
//!   **`headc37d.c`** — per-family CRTC class binding.
//! - **`drivers/gpu/drm/nouveau/nouveau_connector.c`** —
//!   connector enumerate + EDID re-probe.
//! - **`drivers/gpu/drm/nouveau/nouveau_encoder.c`** — encoder
//!   class binding (SOR for TMDS/DP/LVDS, DAC for VGA).
//!
//! ## What this module does
//!
//! Walks the DCB table (see `vbios::dcb_header` + `disp::
//! decode_dcb_entry`), groups DCB entries into KMS triples
//! (connector, encoder, CRTC), and produces a state vector the
//! upper KMS layer can drive. Stage 2: the data model; live
//! programming arrives with the mode-set sequence in `disp::nv50`.

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::disp::{decode_dcb_entry_versioned, ConnectorType, DcbEntry, DisplayPath, EncoderType};

/// One enumerated display path — connector + encoder + the
/// candidate CRTC indices it can drive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumeratedPath {
    pub dcb_index: u8,
    pub entry: DcbEntry,
    /// Bitmask of which CRTCs (heads) can drive this output.
    pub valid_crtcs: u8,
}

/// Maximum DCB entry count we'll honour. Cite DCB v4 spec:
/// `dcb_header.entry_count` is a u8; 16 is comfortably above the
/// observed max on Maxwell+ (typically 4-6 outputs).
pub const MAX_DCB_ENTRIES: u8 = 16;

/// Walk a slice of 8-byte DCB entries using the v4.x decoder.
/// Bytes outside `entries..` are ignored. Returns the live entries
/// in order; skips sentinels.
///
/// For Kepler / early Pascal chips with DCB v3.0 VBIOSes use
/// [`enumerate_dcb_versioned`] instead.
pub fn enumerate_dcb(raw: &[u8]) -> Vec<EnumeratedPath> {
    enumerate_dcb_versioned(raw, 0x40)
}

/// Walk a slice of 8-byte DCB entries with explicit version routing.
/// The `version` byte comes from [`vbios::dcb_header`]'s
/// `DcbHeader::version` field.
///
/// Supported versions:
/// - `0x30..=0x3F` — DCB v3.0 (Kepler / early Pascal / some Fermi)
/// - `0x40..=0x41` — DCB v4.x (Maxwell+)
///
/// Entries that fail `decode_dcb_entry_versioned` (sentinels or
/// unsupported version) are skipped. Cite
/// `nvkm/subdev/bios/dcb.c::dcb_outp_foreach`.
pub fn enumerate_dcb_versioned(raw: &[u8], version: u8) -> Vec<EnumeratedPath> {
    let mut out = Vec::new();
    let n = raw.len() / 8;
    for i in 0..n.min(MAX_DCB_ENTRIES as usize) {
        let off = i * 8;
        let arr: [u8; 8] = [
            raw[off],
            raw[off + 1],
            raw[off + 2],
            raw[off + 3],
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ];
        if let Some(entry) = decode_dcb_entry_versioned(&arr, version) {
            out.push(EnumeratedPath {
                dcb_index: i as u8,
                valid_crtcs: entry.heads,
                entry,
            });
        }
    }
    out
}

/// Filter to outputs we can actually drive — drop external /
/// unknown encoders and LVDS for now (LVDS is a panel-side type
/// that needs its own bring-up sequence).
pub fn driveable(paths: &[EnumeratedPath]) -> Vec<EnumeratedPath> {
    paths
        .iter()
        .filter(|p| {
            !matches!(
                p.entry.encoder_type,
                EncoderType::Unknown(_) | EncoderType::External
            )
        })
        .cloned()
        .collect()
}

/// Pick a CRTC for an enumerated path. `available_crtcs` is a
/// bitmask of CRTCs currently unbound; returns the lowest-set
/// CRTC index intersecting `valid_crtcs` ∩ `available_crtcs`, or
/// `None` if there's no overlap.
pub fn pick_crtc(p: &EnumeratedPath, available_crtcs: u8) -> Option<u8> {
    let overlap = p.valid_crtcs & available_crtcs;
    if overlap == 0 {
        return None;
    }
    Some(overlap.trailing_zeros() as u8)
}

/// Build a DisplayPath triple from an EnumeratedPath + an
/// allocated CRTC index. The connector_id is the DCB index;
/// encoder_id is the OR field (SOR/DAC index).
pub fn build_path(p: &EnumeratedPath, crtc_id: u8) -> DisplayPath {
    DisplayPath {
        connector_id: p.dcb_index,
        encoder_id: p.entry.or,
        crtc_id,
        encoder_type: p.entry.encoder_type,
        connector_type: lookup_connector_type(p.entry.connector_index),
    }
}

/// Resolve the connector-type byte from the BIOS connector table.
/// Synthetic fallback retained for callers that don't have a BIOS
/// image (or are running before the BIOS parser walked the table).
/// Real driver path is `lookup_connector_type_from_bios`.
/// Cite `nvkm/subdev/bios/conn.c::nvbios_connEp`.
pub fn lookup_connector_type(idx: u8) -> ConnectorType {
    // Naive mapping used when the BIOS table isn't yet available;
    // values match common DCB indices seen in captures of Maxwell+
    // VBIOSes.
    match idx {
        0 => ConnectorType::Vga,
        1 | 2 => ConnectorType::DviI,
        3 => ConnectorType::Hdmi,
        4 | 5 => ConnectorType::DisplayPort,
        6 => ConnectorType::Edp,
        7 => ConnectorType::Lvds,
        n => ConnectorType::Unknown(n),
    }
}

/// Resolve the connector type from the actual BIOS connector table.
/// Walks the DCB connector table via `vbios::connector_entry` and
/// maps the type byte through `ConnectorType::from_dcb`.
///
/// `image` is the NVIDIA image inside the option ROM; `dcb_off` is
/// the offset of the DCB table within that image (returned by
/// `vbios::dcb_table_offset`).
pub fn lookup_connector_type_from_bios(image: &[u8], dcb_off: u16, idx: u8) -> ConnectorType {
    let conn_off = match crate::vbios::connector_table_offset(image, dcb_off) {
        Some(o) => o,
        None => return lookup_connector_type(idx),
    };
    match crate::vbios::connector_entry(image, conn_off, idx) {
        Some(e) => ConnectorType::from_dcb(e.conn_type),
        None => lookup_connector_type(idx),
    }
}
