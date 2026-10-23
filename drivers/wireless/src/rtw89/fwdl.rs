//! Checked AX firmware containers and raw section segmentation.
//!
//! Linux rtw89/fw.h defines v0 header32/section16 and v1 header48/section16.
//! Both use four-bit inner section types; outer MFW image types select a
//! normal, CE or BB-MCU image independently. AX chunks are always2020 bytes.
//! Dynamic headers, checksums and indexed/formatted hardware signature pools
//! are bounded before caller section metadata is committed. Selecting secure
//! hardware signatures and activating the retained CH12 owner are separate
//! boot steps.
//!
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
/// Size of one v0 section descriptor in bytes (4 × u32): w0..w3.
pub const FW_HDR_V0_SECTION_SIZE: usize = 4 * 4;

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
/// v1 section types remain four bits; BBMCU is an outer MFW image type.
pub const FWSECTION_V1_W1_TYPE_SHIFT: u32 = 24;
pub const FWSECTION_V1_W1_TYPE_MASK: u32 = 0xF << FWSECTION_V1_W1_TYPE_SHIFT;
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
    /// Inner four-bit section type. BBMCU0(64) is an outer MFW image
    /// type and cannot appear in this field.
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
    /// Bounded hardware-signature pools, excluded from section DMA payloads.
    pub signature_pools: [Option<SignaturePool>; FWDL_SECTION_MAX_NUM],
}

/// Firmware-provided signature storage; selecting a signature still requires
/// the real secure-boot fuse policy. Parsing a pool grants no device authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignaturePool {
    pub offset: usize,
    pub len: usize,
    pub signatures_offset: usize,
    pub signature_len: usize,
    pub signature_count: usize,
    pub bitmap: bool,
}

// ── Checked AX firmware layouts ─────────────────────────────────────

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FwError> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or(FwError::BadFormat)?)
        .ok_or(FwError::BadFormat)?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| FwError::BadFormat)?,
    ))
}

/// Header-version detection; unknown layouts are never interpreted as v1.
pub fn detect_version(blob: &[u8]) -> Result<u8, FwError> {
    if blob.len() < FW_HDR_V0_BASE_SIZE {
        return Err(FwError::BadFormat);
    }
    Ok((read_u32(blob, 12)? >> 24) as u8)
}

/// Parse AX layout v0. The caller output remains untouched on any failure.
pub fn parse_v0(blob: &[u8], sections: &mut [FwSection]) -> Result<FwHeader, FwError> {
    parse_layout(blob, sections, 0)
}
/// Parse AX layout v1; AX always uses 2020-byte download chunks, including
/// RTL8852C. Header-version is independent of chip generation/firmware suit.
pub fn parse_v1(blob: &[u8], sections: &mut [FwSection]) -> Result<FwHeader, FwError> {
    parse_layout(blob, sections, 1)
}

fn parse_layout(blob: &[u8], sections: &mut [FwSection], version: u8) -> Result<FwHeader, FwError> {
    if detect_version(blob)? != version {
        return Err(FwError::UnsupportedFormat);
    }
    let base_size = if version == 0 { 32usize } else { 48 };
    if blob.len() < base_size {
        return Err(FwError::BadFormat);
    }
    let w1 = read_u32(blob, 4)?;
    let w6 = read_u32(blob, 24)?;
    let w7 = read_u32(blob, 28)?;
    let count = ((w6 >> 8) & 255) as usize;
    if count == 0 || count > FWDL_SECTION_MAX_NUM || count > sections.len() {
        return Err(FwError::BadFormat);
    }
    let fixed = base_size + 16 * count;
    let dynamic = w7 & (1 << 16) != 0;
    let length = if !dynamic {
        fixed
    } else if version == 0 {
        ((read_u32(blob, 12)? >> 16) & 255) as usize
    } else {
        (read_u32(blob, 20)? >> 16) as usize
    };
    if length < fixed || length > blob.len() {
        return Err(FwError::BadFormat);
    }
    if dynamic {
        let extra = length - fixed;
        if extra < 8 || read_u32(blob, fixed)? as usize != extra {
            return Err(FwError::BadFormat);
        }
    }
    let empty = FwSection {
        kind: 0,
        dladdr: 0,
        len: 0,
        chksum: false,
        redl: false,
        payload_off: 0,
    };
    let mut checked = [empty; FWDL_SECTION_MAX_NUM];
    let mut position = length;
    let mut signature_pools = [None; FWDL_SECTION_MAX_NUM];
    for (index, section) in checked.iter_mut().take(count).enumerate() {
        let offset = base_size + 16 * index;
        let address = read_u32(blob, offset)?;
        let flags = read_u32(blob, offset + 4)?;
        let kind = ((flags >> 24) & 15) as u8;
        let checksum = flags & (1 << 28) != 0;
        let raw_len = flags & 0x00ff_ffff;
        let len = raw_len
            .checked_add(if checksum { 8 } else { 0 })
            .ok_or(FwError::BadFormat)?;
        let end = position
            .checked_add(len as usize)
            .ok_or(FwError::BadFormat)?;
        if end > blob.len() {
            return Err(FwError::BadFormat);
        }
        let dladdr = if version == 0 {
            address & 0x1fff_ffff
        } else {
            address
        };
        dladdr
            .checked_add(len.saturating_sub(1))
            .ok_or(FwError::BadFormat)?;
        *section = FwSection {
            kind,
            dladdr,
            len,
            chksum: checksum,
            redl: flags & (1 << 29) != 0,
            payload_off: position,
        };
        let pool = if kind == 9 {
            signature_pool(
                blob,
                version,
                read_u32(blob, offset + 8)?,
                position,
                len as usize,
                version == 1 && w6 & (1 << 24) != 0,
            )?
        } else {
            None
        };
        position = end
            .checked_add(pool.map_or(0, |pool| pool.len))
            .ok_or(FwError::BadFormat)?;
        if position > blob.len() {
            return Err(FwError::BadFormat);
        }
        signature_pools[index] = pool;
    }
    if position != blob.len() {
        return Err(FwError::BadFormat);
    }
    sections[..count].copy_from_slice(&checked[..count]);
    Ok(FwHeader {
        version,
        fw_major: w1 as u8,
        fw_minor: (w1 >> 8) as u8,
        section_num: count as u8,
        hdr_len: length,
        part_size: FWDL_SECTION_PER_PKT_LEN,
        dynamic_hdr: dynamic,
        signature_pools,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<usize, FwError> {
    let value = bytes
        .get(offset..offset.checked_add(2).ok_or(FwError::BadFormat)?)
        .ok_or(FwError::BadFormat)?;
    Ok(usize::from(u16::from_le_bytes(
        value.try_into().map_err(|_| FwError::BadFormat)?,
    )))
}
fn signature_pool(
    blob: &[u8],
    version: u8,
    mssc: u32,
    content: usize,
    content_len: usize,
    dsp_checksum: bool,
) -> Result<Option<SignaturePool>, FwError> {
    let count = if version == 0 {
        mssc as usize
    } else {
        (mssc & 255) as usize
    };
    if count == 0 {
        return Ok(None);
    }
    let offset = content.checked_add(content_len).ok_or(FwError::BadFormat)?;
    let suffix = blob.get(offset..).ok_or(FwError::BadFormat)?;
    let (signatures, count, signature_len, bitmap) = if count & 255 == 255 {
        let header = suffix.get(..32).ok_or(FwError::BadFormat)?;
        if &header[..8] != b"MSSKPOOL" || header[20] != 0 {
            return Err(FwError::UnsupportedFormat);
        }
        let entries = usize::from(header[21])
            .checked_mul(read_u16(header, 24)?)
            .and_then(|n| n.checked_mul(read_u16(header, 26).ok()?))
            .ok_or(FwError::BadFormat)?;
        // Linux's bitmask table has a whole number of bytes.
        if entries & 7 != 0 {
            return Err(FwError::BadFormat);
        }
        let bitmap_len = (entries / 8)
            .checked_add(if header[16] != 0 { 8 } else { 0 })
            .ok_or(FwError::BadFormat)?;
        let signatures = 32usize.checked_add(bitmap_len).ok_or(FwError::BadFormat)?;
        if read_u32(header, 8)? != 32 || read_u32(header, 12)? as usize != signatures {
            return Err(FwError::BadFormat);
        }
        let body = blob
            .get(content..content.checked_add(content_len).ok_or(FwError::BadFormat)?)
            .ok_or(FwError::BadFormat)?;
        let length = match read_u16(body, 60)? >> 2 {
            0 => 512,
            other => other,
        };
        (signatures, read_u16(header, 22)?, length, true)
    } else {
        (0, count, 512, false)
    };
    let signature_len = signature_len
        .checked_add(if dsp_checksum { 8 } else { 0 })
        .ok_or(FwError::BadFormat)?;
    let len = signature_len
        .checked_mul(count)
        .and_then(|n| n.checked_add(signatures))
        .ok_or(FwError::BadFormat)?;
    if len > suffix.len() {
        return Err(FwError::BadFormat);
    }
    Ok(Some(SignaturePool {
        offset,
        len,
        signatures_offset: offset + signatures,
        signature_len,
        signature_count: count,
        bitmap,
    }))
}

/// Parse either supported AX header layout, rejecting future versions.
pub fn parse_auto(blob: &[u8], sections: &mut [FwSection]) -> Result<FwHeader, FwError> {
    match detect_version(blob)? {
        0 => parse_v0(blob, sections),
        1 => parse_v1(blob, sections),
        _ => Err(FwError::UnsupportedFormat),
    }
}

/// Select a normal/CE/WoW/BB-MCU image from a Realtek multi-firmware file.
/// Selection follows Linux's nearest non-manufacturing CV <= physical cut.
/// Every entry is bounded before selecting one; payloads cannot overlap TOC.
pub fn select_image(blob: &[u8], cut: u8, image_type: u8) -> Result<&[u8], FwError> {
    if blob.first() != Some(&255) {
        return if image_type == FW_TYPE_NORMAL {
            Ok(blob)
        } else {
            Err(FwError::ImageMissing)
        };
    }
    let count = usize::from(*blob.get(1).ok_or(FwError::BadFormat)?);
    let table_end = 16 + count * 16;
    if count == 0 || table_end > blob.len() {
        return Err(FwError::BadFormat);
    }
    let mut selected: Option<(u8, usize, usize)> = None;
    for index in 0..count {
        let offset = 16 + index * 16;
        let entry = &blob[offset..offset + 16];
        let start = read_u32(entry, 4)? as usize;
        let size = read_u32(entry, 8)? as usize;
        let end = start.checked_add(size).ok_or(FwError::BadFormat)?;
        if start < table_end || size == 0 || end > blob.len() {
            return Err(FwError::BadFormat);
        }
        if entry[1] != image_type || entry[2] != 0 || entry[0] > cut {
            continue;
        }
        match selected {
            Some((cv, _, _)) if cv == entry[0] => return Err(FwError::BadFormat),
            Some((cv, _, _)) if cv > entry[0] => {}
            _ => selected = Some((entry[0], start, end)),
        }
    }
    let (_, start, end) = selected.ok_or(FwError::ImageMissing)?;
    Ok(&blob[start..end])
}

// ── Packet segmentation ─────────────────────────────────────────────

/// One raw section slice for CH12. Only the firmware header is an FWHDR_DL
/// H2C command; section chunks carry no additional H2C header or last-packet
/// flag. Linux segments all AX chips by2020, independent of header version.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FwdlPacket {
    /// Offset inside the section's payload.
    pub section_off: usize,
    /// Bytes carried by this packet.
    pub len: usize,
    /// `true` for the final slice; host bookkeeping only, never a wire flag.
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
        let part_size = if part_size == 0 {
            FWDL_SECTION_PER_PKT_LEN
        } else {
            part_size
        };
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
    let ps = if part_size == 0 {
        FWDL_SECTION_PER_PKT_LEN
    } else {
        part_size
    };
    len.div_ceil(ps)
}
