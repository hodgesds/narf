//! RTW89 firmware downloader — Stage-7.
//!
//! Parses the rtw89 firmware-blob "Format v0" header (8 dwords + N
//! section descriptors) and the Format v1 header (12 dwords) — the
//! split that `rtw89_fw_hdr_parser_v0` / `rtw89_fw_hdr_parser_v1`
//! handle in Linux (`fw.c:140`, `fw.c:440`). Walks the section table
//! and segments each section into FW-DL packets of ≤2020 bytes (`fw.h:287`
//! `FWDL_SECTION_PER_PKT_LEN`), with an 8-byte checksum trailer when
//! the section header sets `CHECKSUM` (`fw.h:579`).
//!
//! ## What lands in this stage
//!
//! - **Header parsing** for both v0 and v1 layouts.
//! - **Section iteration** with type / length / DL-addr / CHKSUM /
//!   REDL flags surfaced.
//! - **Packet segmentation** (≤ 2020 bytes per H2C FWDL packet).
//!
//! What it does **not** do: the actual H2C DMA push (that's the
//! pci.rs / dma.rs handshake that the next stage glues together
//! through `make_fwhdr_dl_h2c` + the CH12 (FW-cmd) TX ring).
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `rtw89/fw.h:583..611` — `struct rtw89_fw_hdr` (v0).
//! - Linux `rtw89/fw.h:632..665` — `struct rtw89_fw_hdr_v1` (v1).
//! - Linux `rtw89/fw.h:285..301` — `FWDL_SECTION_*` constants +
//!   `rtw89_fw_hdr_section_info`.
//! - Linux `rtw89/fw.c:140..280` — `rtw89_fw_hdr_parser_v0`.
//! - Linux `rtw89/fw.c:440..540` — `rtw89_fw_hdr_parser_v1`.
//! - Linux `rtw89/core.h:4723..4730` — `enum rtw89_fw_type`.

#![allow(dead_code)]

use core::convert::TryInto;

use super::fw::FwError;

// ── FW type enum ────────────────────────────────────────────────────

/// `RTW89_FW_NORMAL` (1) — main MAC firmware. `core.h:4724`.
pub const FW_TYPE_NORMAL: u8 = 1;
/// `RTW89_FW_WOWLAN` (3) — wake-on-WLAN firmware. `core.h:4725`.
pub const FW_TYPE_WOWLAN: u8 = 3;
/// `RTW89_FW_NORMAL_CE` (5) — CE-region MAC firmware. `core.h:4726`.
pub const FW_TYPE_NORMAL_CE: u8 = 5;
/// `RTW89_FW_BBMCU0` (64) — BB MCU firmware, instance 0. `core.h:4727`.
pub const FW_TYPE_BBMCU0: u8 = 64;
/// `RTW89_FW_BBMCU1` (65) — BB MCU firmware, instance 1. `core.h:4728`.
pub const FW_TYPE_BBMCU1: u8 = 65;
/// `RTW89_FW_LOGFMT` (255) — log-format descriptor. `core.h:4729`.
pub const FW_TYPE_LOGFMT: u8 = 255;

// ── FW download constants ───────────────────────────────────────────

/// `FWDL_SECTION_PER_PKT_LEN` — max bytes per FW-DL packet on AX chips.
/// `fw.h:287`.
pub const FWDL_SECTION_PER_PKT_LEN: usize = 2020;
/// `FWDL_SECTION_CHKSUM_LEN` — trailing checksum bytes appended to a
/// section when the CHECKSUM flag is set. `fw.h:286`.
pub const FWDL_SECTION_CHKSUM_LEN: usize = 8;
/// `FWDL_SECTION_MAX_NUM` — upper bound on section count Linux
/// pre-allocates section_info for. `fw.h:285`.
pub const FWDL_SECTION_MAX_NUM: usize = 10;

/// Size of the v0 base header in bytes (8 × u32).
pub const FW_HDR_V0_BASE_SIZE: usize = 8 * 4;
/// Size of one v0 section descriptor in bytes (3 × u32). The Linux
/// struct (`fw.h:573`) is `w0/w1/w2`.
pub const FW_HDR_V0_SECTION_SIZE: usize = 3 * 4;

/// Size of the v1 base header in bytes (12 × u32).
pub const FW_HDR_V1_BASE_SIZE: usize = 12 * 4;
/// Size of one v1 section descriptor in bytes (4 × u32). `fw.h:614`.
pub const FW_HDR_V1_SECTION_SIZE: usize = 4 * 4;

// ── Header bit fields (v0) ──────────────────────────────────────────

/// `FW_HDR_W6_SEC_NUM` — `GENMASK(15, 8)`. `fw.h:608`.
pub const FW_HDR_W6_SEC_NUM_SHIFT: u32 = 8;
pub const FW_HDR_W6_SEC_NUM_MASK: u32 = 0xFF << FW_HDR_W6_SEC_NUM_SHIFT;
/// `FW_HDR_W7_DYN_HDR` — `BIT(16)`. `fw.h:610`.
pub const FW_HDR_W7_DYN_HDR: u32 = 1 << 16;
/// `FW_HDR_W1_MAJOR_VERSION` — bits[7:0]. `fw.h:596`.
pub const FW_HDR_W1_MAJOR_MASK: u32 = 0xFF;
/// `FW_HDR_W1_MINOR_VERSION` — bits[15:8]. `fw.h:597`.
pub const FW_HDR_W1_MINOR_SHIFT: u32 = 8;
pub const FW_HDR_W1_MINOR_MASK: u32 = 0xFF << FW_HDR_W1_MINOR_SHIFT;
/// `FW_HDR_W3_LEN` — `GENMASK(23, 16)`. `fw.h:601`. Hdr-only length
/// (for dynamic-hdr-mode).
pub const FW_HDR_W3_LEN_SHIFT: u32 = 16;
pub const FW_HDR_W3_LEN_MASK: u32 = 0xFF << FW_HDR_W3_LEN_SHIFT;

// ── Header bit fields (v1) ──────────────────────────────────────────

/// `FW_HDR_V1_W6_SEC_NUM` — `GENMASK(15, 8)`. `fw.h:661`.
pub const FW_HDR_V1_W6_SEC_NUM_SHIFT: u32 = 8;
pub const FW_HDR_V1_W6_SEC_NUM_MASK: u32 = 0xFF << FW_HDR_V1_W6_SEC_NUM_SHIFT;
/// `FW_HDR_V1_W7_PART_SIZE` — `GENMASK(15, 0)`. `fw.h:663`.
pub const FW_HDR_V1_W7_PART_SIZE_MASK: u32 = 0xFFFF;
/// `FW_HDR_V1_W7_DYN_HDR` — `BIT(16)`. `fw.h:664`.
pub const FW_HDR_V1_W7_DYN_HDR: u32 = 1 << 16;
/// `FW_HDR_V1_W5_HDR_SIZE` — `GENMASK(31, 16)`. `fw.h:660`.
pub const FW_HDR_V1_W5_HDR_SIZE_SHIFT: u32 = 16;
pub const FW_HDR_V1_W5_HDR_SIZE_MASK: u32 = 0xFFFF << FW_HDR_V1_W5_HDR_SIZE_SHIFT;

// ── Section-descriptor bit fields ───────────────────────────────────

/// `FWSECTION_HDR_W0_DL_ADDR` — full 32 bits. `fw.h:573`. Note the
/// caller must `& 0x1FFFFFFF` per fw.c:196.
pub const FWSECTION_W0_DL_ADDR_MASK: u32 = 0x1FFF_FFFF;
/// `FWSECTION_HDR_W1_SECTIONTYPE` — bits[27:24]. `fw.h:577`.
pub const FWSECTION_W1_TYPE_SHIFT: u32 = 24;
pub const FWSECTION_W1_TYPE_MASK: u32 = 0xF << FWSECTION_W1_TYPE_SHIFT;
/// `FWSECTION_HDR_W1_SEC_SIZE` — bits[23:0]. `fw.h:578`.
pub const FWSECTION_W1_SEC_SIZE_MASK: u32 = 0x00FF_FFFF;
/// `FWSECTION_HDR_W1_CHECKSUM` — `BIT(28)`. `fw.h:579`.
pub const FWSECTION_W1_CHECKSUM: u32 = 1 << 28;
/// `FWSECTION_HDR_W1_REDL` — `BIT(29)`. `fw.h:580`. Re-download flag.
pub const FWSECTION_W1_REDL: u32 = 1 << 29;

// ── Parsed types ────────────────────────────────────────────────────

/// Decoded section descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FwSection {
    /// Section type (`enum rtw89_fw_type` value). For BB-MCU FW the
    /// value is `RTW89_FW_BBMCU0` (64).
    pub kind: u8,
    /// Download-target address inside the WCPU IMEM/DMEM.
    pub dladdr: u32,
    /// Section data length in bytes, **including** the 8-byte
    /// checksum trailer if `chksum` is set. Matches Linux's adjusted
    /// `section_info->len` after the `+= FWDL_SECTION_CHKSUM_LEN`
    /// addition at `fw.c:193`.
    pub len: u32,
    /// True if the 8-byte checksum trailer is appended.
    pub chksum: bool,
    /// True if the section is a re-download (FWDL_SECTION_REDL).
    pub redl: bool,
    /// Byte offset (relative to the start of the blob) where the
    /// section's payload begins.
    pub payload_off: usize,
}

/// Parsed firmware header. Holds the per-blob metadata and a slice of
/// parsed sections.
#[derive(Debug)]
pub struct FwHeader {
    /// Header layout version (0 or 1).
    pub version: u8,
    /// Firmware major/minor version pulled from W1.
    pub fw_major: u8,
    pub fw_minor: u8,
    /// Number of sections.
    pub section_num: u8,
    /// Total header length in bytes (base + dynamic).
    pub hdr_len: usize,
    /// Per-packet split length used during DMA push.
    pub part_size: usize,
    /// True if a dynamic header follows the base.
    pub dynamic_hdr: bool,
}

// ── v0 parser ───────────────────────────────────────────────────────

fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(off..off + 4)?.try_into().ok()?))
}

/// Parse a v0 firmware blob header. Sections are written into
/// `sections` (caller-allocated, must hold at least `section_num`
/// entries). Returns the parsed header.
///
/// Mirrors `rtw89_fw_hdr_parser_v0` (`fw.c:140`).
pub fn parse_v0(blob: &[u8], sections: &mut [FwSection]) -> Result<FwHeader, FwError> {
    if blob.len() < FW_HDR_V0_BASE_SIZE {
        return Err(FwError::BadFormat);
    }
    let w1 = read_u32(blob, 4).ok_or(FwError::BadFormat)?;
    let w3 = read_u32(blob, 12).ok_or(FwError::BadFormat)?;
    let w6 = read_u32(blob, 24).ok_or(FwError::BadFormat)?;
    let w7 = read_u32(blob, 28).ok_or(FwError::BadFormat)?;
    let major = (w1 & FW_HDR_W1_MAJOR_MASK) as u8;
    let minor = ((w1 & FW_HDR_W1_MINOR_MASK) >> FW_HDR_W1_MINOR_SHIFT) as u8;
    let section_num = ((w6 & FW_HDR_W6_SEC_NUM_MASK) >> FW_HDR_W6_SEC_NUM_SHIFT) as u8;
    let dynamic = w7 & FW_HDR_W7_DYN_HDR != 0;

    if section_num as usize > FWDL_SECTION_MAX_NUM {
        return Err(FwError::BadFormat);
    }
    if (section_num as usize) > sections.len() {
        return Err(FwError::BadFormat);
    }

    let base_hdr_len = FW_HDR_V0_BASE_SIZE + section_num as usize * FW_HDR_V0_SECTION_SIZE;
    let hdr_len = if dynamic {
        ((w3 & FW_HDR_W3_LEN_MASK) >> FW_HDR_W3_LEN_SHIFT) as usize
    } else {
        base_hdr_len
    };

    if blob.len() < hdr_len {
        return Err(FwError::BadFormat);
    }

    // Walk per-section descriptors.
    let mut payload_off = hdr_len;
    for i in 0..section_num as usize {
        let sec_off = FW_HDR_V0_BASE_SIZE + i * FW_HDR_V0_SECTION_SIZE;
        let sw0 = read_u32(blob, sec_off).ok_or(FwError::BadFormat)?;
        let sw1 = read_u32(blob, sec_off + 4).ok_or(FwError::BadFormat)?;
        let kind = ((sw1 & FWSECTION_W1_TYPE_MASK) >> FWSECTION_W1_TYPE_SHIFT) as u8;
        let chksum = sw1 & FWSECTION_W1_CHECKSUM != 0;
        let redl = sw1 & FWSECTION_W1_REDL != 0;
        let raw_len = sw1 & FWSECTION_W1_SEC_SIZE_MASK;
        let final_len = if chksum {
            raw_len + FWDL_SECTION_CHKSUM_LEN as u32
        } else {
            raw_len
        };
        let dladdr = sw0 & FWSECTION_W0_DL_ADDR_MASK;

        sections[i] = FwSection {
            kind,
            dladdr,
            len: final_len,
            chksum,
            redl,
            payload_off,
        };
        payload_off = payload_off.saturating_add(final_len as usize);
    }

    Ok(FwHeader {
        version: 0,
        fw_major: major,
        fw_minor: minor,
        section_num,
        hdr_len,
        part_size: FWDL_SECTION_PER_PKT_LEN,
        dynamic_hdr: dynamic,
    })
}

// ── v1 parser ───────────────────────────────────────────────────────

/// Parse a v1 firmware blob header (8852C / BE-family blobs).
/// Mirrors `rtw89_fw_hdr_parser_v1` (`fw.c:440`).
pub fn parse_v1(blob: &[u8], sections: &mut [FwSection]) -> Result<FwHeader, FwError> {
    if blob.len() < FW_HDR_V1_BASE_SIZE {
        return Err(FwError::BadFormat);
    }
    let w1 = read_u32(blob, 4).ok_or(FwError::BadFormat)?;
    let w5 = read_u32(blob, 20).ok_or(FwError::BadFormat)?;
    let w6 = read_u32(blob, 24).ok_or(FwError::BadFormat)?;
    let w7 = read_u32(blob, 28).ok_or(FwError::BadFormat)?;
    let major = (w1 & FW_HDR_W1_MAJOR_MASK) as u8;
    let minor = ((w1 & FW_HDR_W1_MINOR_MASK) >> FW_HDR_W1_MINOR_SHIFT) as u8;
    let section_num = ((w6 & FW_HDR_V1_W6_SEC_NUM_MASK) >> FW_HDR_V1_W6_SEC_NUM_SHIFT) as u8;
    let dynamic = w7 & FW_HDR_V1_W7_DYN_HDR != 0;
    let part_size = (w7 & FW_HDR_V1_W7_PART_SIZE_MASK) as usize;
    let hdr_size_field = ((w5 & FW_HDR_V1_W5_HDR_SIZE_MASK) >> FW_HDR_V1_W5_HDR_SIZE_SHIFT) as usize;

    if section_num as usize > FWDL_SECTION_MAX_NUM {
        return Err(FwError::BadFormat);
    }
    if (section_num as usize) > sections.len() {
        return Err(FwError::BadFormat);
    }

    let base_hdr_len = FW_HDR_V1_BASE_SIZE + section_num as usize * FW_HDR_V1_SECTION_SIZE;
    let hdr_len = if hdr_size_field != 0 { hdr_size_field } else { base_hdr_len };

    if blob.len() < hdr_len {
        return Err(FwError::BadFormat);
    }

    let mut payload_off = hdr_len;
    for i in 0..section_num as usize {
        let sec_off = FW_HDR_V1_BASE_SIZE + i * FW_HDR_V1_SECTION_SIZE;
        let sw0 = read_u32(blob, sec_off).ok_or(FwError::BadFormat)?;
        let sw1 = read_u32(blob, sec_off + 4).ok_or(FwError::BadFormat)?;
        // v1 type is at bits [27:24] same as v0 per fw.h:623.
        let kind = ((sw1 & FWSECTION_W1_TYPE_MASK) >> FWSECTION_W1_TYPE_SHIFT) as u8;
        let chksum = sw1 & FWSECTION_W1_CHECKSUM != 0;
        let redl = sw1 & FWSECTION_W1_REDL != 0;
        let raw_len = sw1 & FWSECTION_W1_SEC_SIZE_MASK;
        let final_len = if chksum {
            raw_len + FWDL_SECTION_CHKSUM_LEN as u32
        } else {
            raw_len
        };
        // v1 DL_ADDR is full 32 bits (no 0x1FFFFFFF mask in fw.c:496-ish).
        sections[i] = FwSection {
            kind,
            dladdr: sw0,
            len: final_len,
            chksum,
            redl,
            payload_off,
        };
        payload_off = payload_off.saturating_add(final_len as usize);
    }

    Ok(FwHeader {
        version: 1,
        fw_major: major,
        fw_minor: minor,
        section_num,
        hdr_len,
        part_size: if part_size != 0 { part_size } else { FWDL_SECTION_PER_PKT_LEN },
        dynamic_hdr: dynamic,
    })
}

// ── Auto-detect parser ──────────────────────────────────────────────

/// Header-version detection. v1 blobs set `W3[31:24] = 1`
/// (`FW_HDR_W3_HDR_VER`) — Linux's `__rtw89_fw_recognize` (~`fw.c:730`)
/// branches on this.
pub fn detect_version(blob: &[u8]) -> Result<u8, FwError> {
    if blob.len() < FW_HDR_V0_BASE_SIZE {
        return Err(FwError::BadFormat);
    }
    let w3 = read_u32(blob, 12).ok_or(FwError::BadFormat)?;
    let version = ((w3 >> 24) & 0xFF) as u8;
    Ok(version)
}

/// Generic parser — chooses v0 or v1 based on header byte.
pub fn parse_auto(blob: &[u8], sections: &mut [FwSection]) -> Result<FwHeader, FwError> {
    let ver = detect_version(blob)?;
    if ver >= 1 {
        parse_v1(blob, sections)
    } else {
        parse_v0(blob, sections)
    }
}

// ── Packet segmentation ─────────────────────────────────────────────

/// One slice of a section ready to be wrapped in a FWHDR_DL H2C and
/// pushed via CH12. Linux's `__rtw89_fw_download_section` (`fw.c:284`)
/// segments by `info->part_size` (2020 on AX, header-specified on v1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FwdlPacket {
    /// Offset inside the section's payload.
    pub section_off: usize,
    /// Bytes carried by this packet.
    pub len: usize,
    /// `true` for the final packet of the section. Linux sets the
    /// `FWDL_LAST_PKT` flag in the H2C payload header here.
    pub is_last: bool,
}

/// Iterator over the FWDL packets for one section.
#[derive(Debug)]
pub struct FwdlPacketIter {
    section_len: usize,
    part_size: usize,
    cursor: usize,
}

impl FwdlPacketIter {
    /// Build an iterator that walks `section` in `part_size` chunks.
    pub fn new(section_len: usize, part_size: usize) -> Self {
        let part_size = if part_size == 0 { FWDL_SECTION_PER_PKT_LEN } else { part_size };
        Self {
            section_len,
            part_size,
            cursor: 0,
        }
    }
}

impl Iterator for FwdlPacketIter {
    type Item = FwdlPacket;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.section_len {
            return None;
        }
        let remaining = self.section_len - self.cursor;
        let chunk = if remaining > self.part_size {
            self.part_size
        } else {
            remaining
        };
        let pkt = FwdlPacket {
            section_off: self.cursor,
            len: chunk,
            is_last: chunk == remaining,
        };
        self.cursor += chunk;
        Some(pkt)
    }
}

/// Convenience: total packet count for a section of `len` bytes split
/// into `part_size`-byte packets.
pub const fn packet_count(len: usize, part_size: usize) -> usize {
    let ps = if part_size == 0 { FWDL_SECTION_PER_PKT_LEN } else { part_size };
    (len + ps - 1) / ps
}
