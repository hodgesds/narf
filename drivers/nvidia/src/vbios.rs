//! VBIOS — PCI Option ROM walk + table extraction.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/bios/image.c`**
//!   `nvbios_image` / `nvbios_imagen` — walk a multi-image Option
//!   ROM looking for the NVIDIA image (`PCIR.type == 0x70`).
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/bios/pcir.c`** — PCI
//!   Data Structure ("PCIR") header decode.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/bios/bit.c`** — BIT
//!   table walk; the modern NVIDIA-image layout pivots off this.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/bios/dcb.c`** — DCB
//!   table locator (`dcb_table`).
//!
//! ## ROM signatures
//!
//! - `0xaa55` — PC BIOS Option ROM
//! - `0xbb77` — NVIDIA's EFI image
//! - `0x4e56` — "NV" — NVIDIA's modern unified image header
//!
//! ## Image layout
//!
//! An Option ROM is a sequence of images; each starts with a
//! signature, has a PCIR descriptor at offset+0x18 holding image
//! size and image type, and is followed by the next image until
//! `PCIR.last == 1` is set.

#![allow(dead_code)]

// ── Constants ────────────────────────────────────────────────────

/// PC BIOS / x86 Option ROM signature.
pub const ROM_SIG_PCI: u16 = 0xAA55;
/// NVIDIA EFI image.
pub const ROM_SIG_NV_EFI: u16 = 0xBB77;
/// NVIDIA modern unified image.
pub const ROM_SIG_NV: u16 = 0x4E56;

/// PCIR table type code for an NVIDIA image (host-OS-friendly).
pub const PCIR_TYPE_NV: u8 = 0x70;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VbiosError {
    /// Buffer too small to hold the documented header.
    Truncated,
    /// Signature didn't match any of the known forms.
    UnknownSignature(u16),
    /// PCIR descriptor at the expected offset didn't match `"PCIR"`.
    MissingPcir,
}

/// One image entry inside an Option ROM. Cited
/// `include/subdev/bios/image.h::nvbios_image`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VbiosImage {
    /// Byte offset of this image inside the ROM.
    pub base: u32,
    /// Image size in bytes (from PCIR).
    pub size: u32,
    /// PCIR image type (0x70 = NVIDIA host image).
    pub image_type: u8,
    /// `last` flag from PCIR — final image in the ROM.
    pub last: bool,
}

/// Walk an Option ROM, returning the NVIDIA image (PCIR type 0x70)
/// or `None` if no NV image found. Each image starts with a
/// 2-byte signature; immediately followed by a 1-byte `+0x02`
/// size-in-512B sectors; the PCIR offset is `*(uint16*)(base+0x18)`
/// from the image start.
///
/// Cite `nvkm/subdev/bios/image.c::nvbios_imagen`.
pub fn find_nv_image(rom: &[u8]) -> Option<VbiosImage> {
    let mut base: u32 = 0;
    loop {
        let img = parse_image_at(rom, base).ok()?;
        if img.image_type == PCIR_TYPE_NV {
            return Some(img);
        }
        if img.last {
            return None;
        }
        base = base.checked_add(img.size)?;
        if (base as usize) >= rom.len() {
            return None;
        }
    }
}

/// Parse the image header at `rom[base..]`. Returns the PCIR
/// descriptor.
pub fn parse_image_at(rom: &[u8], base: u32) -> Result<VbiosImage, VbiosError> {
    let bi = base as usize;
    if bi + 0x1A >= rom.len() {
        return Err(VbiosError::Truncated);
    }
    let sig = u16::from_le_bytes([rom[bi], rom[bi + 1]]);
    match sig {
        ROM_SIG_PCI | ROM_SIG_NV_EFI | ROM_SIG_NV => {}
        n => return Err(VbiosError::UnknownSignature(n)),
    }
    // PCIR offset is at base + 0x18 (little-endian u16).
    let pcir_off = u16::from_le_bytes([rom[bi + 0x18], rom[bi + 0x19]]) as usize;
    let pi = bi + pcir_off;
    if pi + 0x18 > rom.len() {
        return Err(VbiosError::Truncated);
    }
    if &rom[pi..pi + 4] != b"PCIR" {
        return Err(VbiosError::MissingPcir);
    }
    // PCIR layout (cite include/subdev/bios/pcir.h):
    //   +0x00  "PCIR"
    //   +0x04  vendor (le16)
    //   +0x06  device (le16)
    //   +0x10  image length in 512B units (le16)
    //   +0x14  image type (u8)
    //   +0x15  flags (u8) — bit 7 = "last image" flag.
    let len_blocks = u16::from_le_bytes([rom[pi + 0x10], rom[pi + 0x11]]) as u32;
    let size = len_blocks.saturating_mul(512);
    let image_type = rom[pi + 0x14];
    let last = rom[pi + 0x15] & 0x80 != 0;
    Ok(VbiosImage {
        base,
        size,
        image_type,
        last,
    })
}

// ── Header offsets inside an NVIDIA host image ───────────────────
//
// Cite `nvkm/subdev/bios/base.c::nvkm_bios_oneinit` which reads:
//   image[0x36..0x38] = LE16 offset of the DCB table
//
// We expose a single `dcb_table_offset` helper; the actual entry
// parse goes through `disp::decode_dcb_entry`.

/// Offset (inside the NVIDIA image) of the LE16 DCB table pointer.
pub const NV_HEADER_DCB_PTR: usize = 0x36;

/// Read the DCB table offset out of the NVIDIA image. Cite
/// `nvkm/subdev/bios/dcb.c::dcb_table`.
pub fn dcb_table_offset(image: &[u8]) -> Option<u16> {
    if image.len() < NV_HEADER_DCB_PTR + 2 {
        return None;
    }
    let off = u16::from_le_bytes([image[NV_HEADER_DCB_PTR], image[NV_HEADER_DCB_PTR + 1]]);
    if off == 0 {
        return None;
    }
    Some(off)
}

/// Magic signature in DCB v3.0 header at `dcb+6` (LE32).
/// Cite `nvkm/subdev/bios/dcb.c::dcb_table`:
///   `nvbios_rd32(bios, dcb + 6) == 0x4edcbdcb`.
pub const DCB_V30_MAGIC: u32 = 0x4edcbdcb;

/// Parse the DCB header at `image[off..]`. Returns
/// `(version, header_len, entry_count, entry_size)` per
/// `dcb_table`.
///
/// Supports DCB v3.0 (version 0x30..0x3f) and v4.x (version
/// 0x40..0x41). For v3.0 the header MUST carry the magic
/// `0x4edcbdcb` at `dcb+6`; for v4.x there is no magic check
/// here (the BIT table already validated the image). Cite
/// `nvkm/subdev/bios/dcb.c::dcb_table`.
pub fn dcb_header(image: &[u8], off: u16) -> Option<DcbHeader> {
    let p = off as usize;
    if p + 4 > image.len() {
        return None;
    }
    let version = image[p];
    if version >= 0x42 {
        return None;
    }
    let header_len = image[p + 1];
    let entry_count = image[p + 2];
    let entry_size = image[p + 3];

    if version >= 0x30 && version < 0x40 {
        // DCB v3.0: magic at dcb+6 (10 bytes minimum).
        if p + 10 > image.len() {
            return None;
        }
        let magic = u32::from_le_bytes([
            image[p + 6],
            image[p + 7],
            image[p + 8],
            image[p + 9],
        ]);
        if magic != DCB_V30_MAGIC {
            return None;
        }
    } else if version < 0x30 {
        // DCB v2.x and older: not supported.
        return None;
    }
    Some(DcbHeader {
        version,
        header_len,
        entry_count,
        entry_size,
    })
}

/// Decoded DCB table header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DcbHeader {
    pub version: u8,
    pub header_len: u8,
    pub entry_count: u8,
    pub entry_size: u8,
}

// ── Connector-table parse (item 13) ──────────────────────────────
//
// Cite `nvkm/subdev/bios/conn.c`:
//   `nvbios_connTe` (table find): the connector-table pointer
//   lives at DCB+0x14 (DCB v3.0+).
//   `nvbios_connEp` (entry parse): per-entry layout = type, location,
//   hpd, dp, di, sr, lcdid.

/// Offset (inside DCB) of the LE16 connector-table pointer. Cite
/// `nvbios_connTe` — `nvbios_rd16(bios, dcb + 0x14)`.
pub const DCB_CONN_TABLE_PTR_OFFSET: usize = 0x14;

/// Read the connector-table pointer from a DCB header. Returns the
/// byte offset (within the BIOS image) of the connector table, or
/// `None` when the DCB version doesn't support it.
pub fn connector_table_offset(image: &[u8], dcb_off: u16) -> Option<u16> {
    let p = dcb_off as usize + DCB_CONN_TABLE_PTR_OFFSET;
    if p + 2 > image.len() {
        return None;
    }
    let v = u16::from_le_bytes([image[p], image[p + 1]]);
    if v == 0 {
        None
    } else {
        Some(v)
    }
}

/// Connector-table header (per `nvbios_connTe`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnTableHeader {
    pub version: u8,
    pub header_len: u8,
    pub entry_count: u8,
    pub entry_size: u8,
}

/// Decoded connector-entry. Cite `nvbios_connEp`'s `nvbios_connE`
/// struct.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnectorEntry {
    /// Connector-type byte (matches `disp::ConnectorType::from_dcb`).
    pub conn_type: u8,
    /// Physical location code (0..15).
    pub location: u8,
    /// HPD GPIO line.
    pub hpd_gpio: u8,
    /// DP port-mux selector.
    pub dp_mux: u8,
    /// Digital interface (DI) — eDP / DP / HDMI mux.
    pub di: u8,
    /// Display port "side-band reserved" bit.
    pub sr: bool,
    /// LCD id (panel index for LVDS / eDP).
    pub lcd_id: u8,
}

/// Parse the connector-table header.
pub fn connector_table_header(image: &[u8], off: u16) -> Option<ConnTableHeader> {
    let p = off as usize;
    if p + 4 > image.len() {
        return None;
    }
    let version = image[p];
    if version != 0x30 && version != 0x40 {
        return None;
    }
    Some(ConnTableHeader {
        version,
        header_len: image[p + 1],
        entry_count: image[p + 2],
        entry_size: image[p + 3],
    })
}

/// Decode the connector entry at `index` from a connector table at
/// byte offset `off`. Returns `None` when index is out of range,
/// the table version is unsupported, or the entry data falls outside
/// the image.
///
/// Cite `nvbios_connEp` — the bit-layout we mirror.
pub fn connector_entry(
    image: &[u8],
    off: u16,
    index: u8,
) -> Option<ConnectorEntry> {
    let hdr = connector_table_header(image, off)?;
    if index >= hdr.entry_count {
        return None;
    }
    let entry_start = off as usize
        + hdr.header_len as usize
        + (index as usize) * (hdr.entry_size as usize);
    if entry_start + hdr.entry_size as usize > image.len() {
        return None;
    }
    let b0 = image[entry_start];
    let b1 = image[entry_start + 1];
    let mut entry = ConnectorEntry {
        conn_type: b0,
        location: b1 & 0x0F,
        hpd_gpio: (b1 & 0x30) >> 4,
        dp_mux: (b1 & 0xC0) >> 6,
        di: 0,
        sr: false,
        lcd_id: 0,
    };
    if hdr.entry_size >= 4 {
        let b2 = image[entry_start + 2];
        let b3 = image[entry_start + 3];
        entry.hpd_gpio |= (b2 & 0x03) << 2;
        entry.dp_mux |= b2 & 0x0C;
        entry.di = (b2 & 0xF0) >> 4;
        entry.hpd_gpio |= (b3 & 0x07) << 4;
        entry.sr = b3 & 0x08 != 0;
        entry.lcd_id = (b3 & 0x70) >> 4;
    }
    Some(entry)
}
