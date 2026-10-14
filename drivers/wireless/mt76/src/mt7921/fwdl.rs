//! MT7921 firmware downloader — Stage-5/6/7.
//!
//! Three firmware blobs land in this order:
//!
//!   1. **ROM patch** (`mt76_connac2_patch_hdr` prefix) — primes the
//!      MCU boot ROM. Loaded via raw PCIe writes through `MT_MCU_CMD`,
//!      semaphore-gated via `MCU_CMD_PATCH_SEM_CONTROL`.
//!   2. **WM (Wi-Fi Master) RAM code** (`mt76_connac2_fw_trailer` at
//!      tail) — the runtime firmware. Loaded via the FWDL TX ring
//!      (queue 16) and the `MCU_CMD_TARGET_ADDRESS_LEN_REQ` /
//!      `MCU_CMD_FW_SCATTER` / `MCU_CMD_FW_START_REQ` triplet.
//!   3. **WA (Wi-Fi Accelerator) RAM code** — optional offload
//!      firmware. Same protocol as WM but flagged as `is_wa = true`.
//!
//! ## What this module owns
//!
//! - `Connac2PatchHdr` / `Connac2PatchSection` parsers (big-endian
//!   wire layout).
//! - `Connac2FwTrailer` / `Connac2FwRegion` parsers (little-endian
//!   wire layout).
//! - `parse_patch_header`, `iter_patch_sections`, `parse_fw_trailer`,
//!   `iter_fw_regions` — pure-data decoders that exercise via
//!   round-trip tests.
//! - `PatchSemControl::encode` / `FwScatterChunk::encode` — MCU
//!   command body encoders.
//! - `download_patch` / `download_wm` / `download_wa` orchestrators
//!   that drive the FWDL queue via the Stage-4 ring scaffold.
//!
//! ## References (all GPL-2.0)
//!
//! - `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.h:139..L194`
//!   — `struct mt76_connac2_patch_hdr`, `struct mt76_connac2_patch_sec`,
//!   `struct mt76_connac2_fw_trailer`, `struct mt76_connac2_fw_region`.
//! - `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.c:3099..L3182`
//!   — `mt76_connac2_load_patch` orchestrator.
//! - `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.c:3004..L3068`
//!   — `mt76_connac2_load_ram` orchestrator (WM + WA legs).
//! - `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.c:2900..L3000`
//!   — `mt76_connac_mcu_send_ram_firmware` + helpers.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryInto;

// ── Wire-layout constants ────────────────────────────────────────

/// Size of `struct mt76_connac2_patch_hdr` (16 + 4 + 4 + 4 + 2 + 2 +
/// 4 + 4 + 4 + 4 + 4 + 4*11 = 92 bytes).
pub const PATCH_HDR_SIZE: usize = 92;
/// Size of `struct mt76_connac2_patch_sec` (4 + 4 + 4 + 4*13 = 64).
pub const PATCH_SEC_SIZE: usize = 64;
/// Size of `struct mt76_connac2_fw_trailer` (1+1+1+1+1+2+10+15+4 = 36).
pub const FW_TRAILER_SIZE: usize = 36;
/// Size of `struct mt76_connac2_fw_region` (4+4+4+4+4+4+1+1+14 = 40).
pub const FW_REGION_SIZE: usize = 40;

/// `PATCH_SEC_TYPE_MASK` — Linux `mt76_connac_mcu.h:1389`-ish, low byte
/// of `mt76_connac2_patch_sec.type`.
pub const PATCH_SEC_TYPE_MASK: u32 = 0x0000_00FF;
/// `PATCH_SEC_TYPE_INFO` — the only section type Linux currently
/// accepts in `mt76_connac2_load_patch`.
pub const PATCH_SEC_TYPE_INFO: u32 = 0x02;

/// Patch download size for PCIe transport (Linux's `max_len` is 4096
/// for non-SDIO).
pub const PCIE_FWDL_CHUNK_SIZE: usize = 4096;

// ── Patch header parser ──────────────────────────────────────────

/// Parsed `mt76_connac2_patch_hdr`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Connac2PatchHdr {
    /// `build_date[16]` — opaque ASCII.
    pub build_date: [u8; 16],
    /// `platform[4]` — chip platform tag.
    pub platform: [u8; 4],
    /// `hw_sw_ver` — big-endian.
    pub hw_sw_ver: u32,
    /// `patch_ver` — big-endian.
    pub patch_ver: u32,
    /// `checksum` — big-endian u16.
    pub checksum: u16,
    /// `desc.n_region` — big-endian, number of patch sections.
    pub n_region: u32,
}

/// Errors from the firmware-blob parsers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwParseError {
    /// Blob is shorter than the header it should contain.
    TooShort,
    /// Section type bits don't match `PATCH_SEC_TYPE_INFO`.
    BadSectionType,
    /// `n_region * sizeof(patch_sec)` overshoots the blob bounds.
    SectionTableOverrun,
    /// CRC stored in the trailer doesn't match an XOR over the blob.
    /// We deliberately don't verify against the firmware's true CRC
    /// here — we surface the field but don't gate-keep on it.
    CrcMismatch,
}

/// Parse the patch header out of `blob[..PATCH_HDR_SIZE]`.
pub fn parse_patch_header(blob: &[u8]) -> Result<Connac2PatchHdr, FwParseError> {
    if blob.len() < PATCH_HDR_SIZE {
        return Err(FwParseError::TooShort);
    }
    let mut build_date = [0u8; 16];
    build_date.copy_from_slice(&blob[0..16]);
    let mut platform = [0u8; 4];
    platform.copy_from_slice(&blob[16..20]);
    let hw_sw_ver = u32::from_be_bytes(blob[20..24].try_into().unwrap());
    let patch_ver = u32::from_be_bytes(blob[24..28].try_into().unwrap());
    let checksum = u16::from_be_bytes(blob[28..30].try_into().unwrap());
    // bytes 30..32: rsv (u16). desc starts at 32.
    // desc.patch_ver @ 32; desc.subsys @ 36; desc.feature @ 40;
    // desc.n_region @ 44; desc.crc @ 48; 11 rsv dwords (44 bytes).
    let n_region = u32::from_be_bytes(blob[44..48].try_into().unwrap());
    Ok(Connac2PatchHdr {
        build_date,
        platform,
        hw_sw_ver,
        patch_ver,
        checksum,
        n_region,
    })
}

/// Parsed `mt76_connac2_patch_sec` (only the `.info` union arm —
/// Linux's loader rejects everything else).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Connac2PatchSection {
    /// `type` — big-endian; the low byte must be `PATCH_SEC_TYPE_INFO`.
    pub sec_type: u32,
    /// `offs` — big-endian, byte offset into the blob where this
    /// section's data starts.
    pub offset: u32,
    /// `size` — big-endian, byte length of this section's data.
    pub size: u32,
    /// `info.addr` — big-endian, destination MCU address.
    pub addr: u32,
    /// `info.len` — big-endian, length of the data at `addr`.
    pub len: u32,
    /// `info.sec_key_idx` — big-endian, encryption-mode tag.
    pub sec_key_idx: u32,
}

/// Iterate the patch sections following the header.
///
/// `blob` is the full firmware blob; the parser walks `n_region`
/// 64-byte sections starting immediately after the header.
pub fn iter_patch_sections<'a>(
    blob: &'a [u8],
    hdr: &Connac2PatchHdr,
) -> Result<impl Iterator<Item = Result<Connac2PatchSection, FwParseError>> + 'a, FwParseError> {
    let n = hdr.n_region as usize;
    let needed = PATCH_HDR_SIZE + n * PATCH_SEC_SIZE;
    if blob.len() < needed {
        return Err(FwParseError::SectionTableOverrun);
    }
    Ok((0..n).map(move |i| {
        let start = PATCH_HDR_SIZE + i * PATCH_SEC_SIZE;
        let s = &blob[start..start + PATCH_SEC_SIZE];
        parse_patch_section(s)
    }))
}

fn parse_patch_section(s: &[u8]) -> Result<Connac2PatchSection, FwParseError> {
    if s.len() < PATCH_SEC_SIZE {
        return Err(FwParseError::TooShort);
    }
    let sec_type = u32::from_be_bytes(s[0..4].try_into().unwrap());
    let offset = u32::from_be_bytes(s[4..8].try_into().unwrap());
    let size = u32::from_be_bytes(s[8..12].try_into().unwrap());
    // .info starts at offset 12.
    let addr = u32::from_be_bytes(s[12..16].try_into().unwrap());
    let len = u32::from_be_bytes(s[16..20].try_into().unwrap());
    let sec_key_idx = u32::from_be_bytes(s[20..24].try_into().unwrap());
    if (sec_type & PATCH_SEC_TYPE_MASK) != PATCH_SEC_TYPE_INFO {
        return Err(FwParseError::BadSectionType);
    }
    Ok(Connac2PatchSection {
        sec_type,
        offset,
        size,
        addr,
        len,
        sec_key_idx,
    })
}

// ── FW trailer parser (WM + WA) ──────────────────────────────────

/// Parsed `mt76_connac2_fw_trailer` (the 36-byte trailer at the end
/// of the WM / WA firmware blob).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Connac2FwTrailer {
    pub chip_id: u8,
    pub eco_code: u8,
    pub n_region: u8,
    pub format_ver: u8,
    pub format_flag: u8,
    pub fw_ver: [u8; 10],
    pub build_date: [u8; 15],
    pub crc: u32,
}

/// Parse the FW trailer from the last `FW_TRAILER_SIZE` bytes of the
/// firmware blob.
pub fn parse_fw_trailer(blob: &[u8]) -> Result<Connac2FwTrailer, FwParseError> {
    if blob.len() < FW_TRAILER_SIZE {
        return Err(FwParseError::TooShort);
    }
    let tail = &blob[blob.len() - FW_TRAILER_SIZE..];
    let chip_id = tail[0];
    let eco_code = tail[1];
    let n_region = tail[2];
    let format_ver = tail[3];
    let format_flag = tail[4];
    // bytes 5..7: rsv[2].
    let mut fw_ver = [0u8; 10];
    fw_ver.copy_from_slice(&tail[7..17]);
    let mut build_date = [0u8; 15];
    build_date.copy_from_slice(&tail[17..32]);
    let crc = u32::from_le_bytes(tail[32..36].try_into().unwrap());
    Ok(Connac2FwTrailer {
        chip_id,
        eco_code,
        n_region,
        format_ver,
        format_flag,
        fw_ver,
        build_date,
        crc,
    })
}

/// Parsed `mt76_connac2_fw_region`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Connac2FwRegion {
    pub decomp_crc: u32,
    pub decomp_len: u32,
    pub decomp_blk_sz: u32,
    pub addr: u32,
    pub len: u32,
    pub feature_set: u8,
    pub region_type: u8,
}

/// Iterate the WM / WA firmware regions. The region table sits
/// immediately before the trailer — `n_region` 40-byte entries.
pub fn iter_fw_regions<'a>(
    blob: &'a [u8],
    trailer: &Connac2FwTrailer,
) -> Result<impl Iterator<Item = Result<Connac2FwRegion, FwParseError>> + 'a, FwParseError> {
    let n = trailer.n_region as usize;
    let needed = FW_TRAILER_SIZE + n * FW_REGION_SIZE;
    if blob.len() < needed {
        return Err(FwParseError::SectionTableOverrun);
    }
    let regions_start = blob.len() - needed;
    Ok((0..n).map(move |i| {
        let s = &blob[regions_start + i * FW_REGION_SIZE..][..FW_REGION_SIZE];
        parse_fw_region(s)
    }))
}

fn parse_fw_region(s: &[u8]) -> Result<Connac2FwRegion, FwParseError> {
    if s.len() < FW_REGION_SIZE {
        return Err(FwParseError::TooShort);
    }
    let decomp_crc = u32::from_le_bytes(s[0..4].try_into().unwrap());
    let decomp_len = u32::from_le_bytes(s[4..8].try_into().unwrap());
    let decomp_blk_sz = u32::from_le_bytes(s[8..12].try_into().unwrap());
    // bytes 12..16: rsv.
    let addr = u32::from_le_bytes(s[16..20].try_into().unwrap());
    let len = u32::from_le_bytes(s[20..24].try_into().unwrap());
    let feature_set = s[24];
    let region_type = s[25];
    Ok(Connac2FwRegion {
        decomp_crc,
        decomp_len,
        decomp_blk_sz,
        addr,
        len,
        feature_set,
        region_type,
    })
}

// ── MCU command body encoders ────────────────────────────────────

/// `PATCH_SEM_RELEASE = 0` / `PATCH_SEM_GET = 1` per
/// `mt76_connac_mcu.h:1358`. Used as the body of
/// `MCU_CMD_PATCH_SEM_CONTROL`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PatchSemOp {
    Release = 0,
    Get = 1,
}

/// `op = release|get` — Linux `mt76_connac_mcu_patch_sem_ctrl` body.
pub fn encode_patch_sem_control(op: PatchSemOp, out: &mut [u8]) -> Option<()> {
    if out.len() < 4 {
        return None;
    }
    let op_u32 = op as u32;
    out[0..4].copy_from_slice(&op_u32.to_le_bytes());
    Some(())
}

/// `MCU_CMD_PATCH_FINISH_REQ` body: `{ check_crc: u8 }`. Linux uses
/// `check_crc = 0` for the PCIe path.
pub fn encode_patch_finish_req(check_crc: u8, out: &mut [u8]) -> Option<()> {
    if out.is_empty() {
        return None;
    }
    out[0] = check_crc;
    for b in &mut out[1..] {
        *b = 0;
    }
    Some(())
}

/// `MCU_CMD_TARGET_ADDRESS_LEN_REQ` body —
/// `{ addr: u32 LE, len: u32 LE, data_mode: u32 LE }`.
///
/// Per Linux `mt76_connac_mcu_init_download` (mt76_connac_mcu.c:2960).
pub fn encode_target_address_len_req(
    addr: u32,
    len: u32,
    data_mode: u32,
    out: &mut [u8],
) -> Option<()> {
    if out.len() < 12 {
        return None;
    }
    out[0..4].copy_from_slice(&addr.to_le_bytes());
    out[4..8].copy_from_slice(&len.to_le_bytes());
    out[8..12].copy_from_slice(&data_mode.to_le_bytes());
    Some(())
}

/// `MCU_CMD_FW_START_REQ` body — `{ override_addr: u32, addr: u32 }`.
/// Linux uses `override = 0, addr = 0` for the standard kick.
pub fn encode_fw_start_req(override_addr: u32, addr: u32, out: &mut [u8]) -> Option<()> {
    if out.len() < 8 {
        return None;
    }
    out[0..4].copy_from_slice(&override_addr.to_le_bytes());
    out[4..8].copy_from_slice(&addr.to_le_bytes());
    Some(())
}

/// One chunk of an `MCU_CMD_FW_SCATTER` payload — Linux splits the
/// firmware blob into `PCIE_FWDL_CHUNK_SIZE` slices and writes each
/// through the FWDL TX queue with the opcode + sequence + payload.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FwScatterChunk<'a> {
    /// Byte offset of this chunk into the firmware blob.
    pub offset: usize,
    /// Length of this chunk.
    pub len: usize,
    /// Borrowed payload bytes.
    pub payload: &'a [u8],
}

/// Split `blob` into FW_SCATTER chunks of at most `chunk_size` bytes.
///
/// Returns an iterator over `(offset, payload)` pairs. The caller
/// wraps each in the MCU TXD + FW_SCATTER header before pushing onto
/// the FWDL ring.
pub fn iter_fw_scatter_chunks(
    blob: &[u8],
    chunk_size: usize,
) -> impl Iterator<Item = FwScatterChunk<'_>> + '_ {
    let chunk_size = chunk_size.max(1);
    (0..blob.len()).step_by(chunk_size).map(move |off| {
        let end = (off + chunk_size).min(blob.len());
        FwScatterChunk {
            offset: off,
            len: end - off,
            payload: &blob[off..end],
        }
    })
}

// ── Top-level orchestrator stubs (require live MCU rings) ────────

/// Errors from the firmware downloader orchestrator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DownloadError {
    /// Underlying blob parser failed.
    Parse(FwParseError),
    /// MCU mailbox poll didn't complete within budget.
    Timeout,
    /// Firmware not registered in `narf_firmware`.
    Missing,
    /// The download path needs a Stage-13 alive MCU + FWDL ring; this
    /// is the typed error you get when called before that exists.
    NotImplemented,
}

impl From<FwParseError> for DownloadError {
    fn from(e: FwParseError) -> Self {
        DownloadError::Parse(e)
    }
}

/// Top-level patch download — Linux's `mt76_connac2_load_patch`.
///
/// Stage-5 owns the wire-layout parsing + opcode encoding. The
/// actual ring-side dispatch (sem-ctrl + per-section
/// `init_download` + `FW_SCATTER` + patch-finish) is staged here
/// behind `NotImplemented` until the MCU mailbox lifts in Stage-13.
pub fn download_patch(blob: &[u8]) -> Result<Connac2PatchHdr, DownloadError> {
    let hdr = parse_patch_header(blob)?;
    // Walk the sections so a malformed blob fails up-front rather
    // than mid-download.
    let n = hdr.n_region as usize;
    let needed = PATCH_HDR_SIZE + n * PATCH_SEC_SIZE;
    if blob.len() < needed {
        return Err(DownloadError::Parse(FwParseError::SectionTableOverrun));
    }
    for i in 0..n {
        let start = PATCH_HDR_SIZE + i * PATCH_SEC_SIZE;
        parse_patch_section(&blob[start..start + PATCH_SEC_SIZE])?;
    }
    // Real ring dispatch lifts when MCU mailbox lands.
    Err(DownloadError::NotImplemented)
}

/// Top-level WM RAM-code download — Linux's `mt76_connac2_load_ram`
/// (WM leg).
pub fn download_wm(blob: &[u8]) -> Result<Connac2FwTrailer, DownloadError> {
    let trailer = parse_fw_trailer(blob)?;
    let regions: Result<Vec<Connac2FwRegion>, FwParseError> =
        iter_fw_regions(blob, &trailer)?.collect();
    let regions = regions?;
    // We don't dispatch the regions yet — Stage-13 MCU mailbox owns
    // that. Surface the parsed trailer + the region count consistency
    // check.
    if regions.len() != trailer.n_region as usize {
        return Err(DownloadError::Parse(FwParseError::SectionTableOverrun));
    }
    Err(DownloadError::NotImplemented)
}

/// Top-level WA RAM-code download — same protocol as WM but with the
/// `is_wa = true` flag set on the per-region MCU command.
pub fn download_wa(blob: &[u8]) -> Result<Connac2FwTrailer, DownloadError> {
    // Identical parsing to WM; the differences live in the MCU side.
    download_wm(blob)
}
