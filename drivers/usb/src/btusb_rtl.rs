//! Realtek USB Bluetooth firmware setup (RTL8761 / RTL8852 / RTL8822).
//!
//! Realtek controllers boot a ROM patcher: the host reads the ROM
//! version, selects the matching patch from the vendor firmware file,
//! and downloads it with HCI vendor opcode 0xFC20. Only after the
//! download does the controller answer normal HCI.
//!
//! Reference: Linux `drivers/bluetooth/btrtl.c` and
//! `drivers/bluetooth/btrtl.h` (GPL-2.0-or-later), consulted under
//! NARF's GPL-2.0-or-later licensing, plus the in-tree quirk table
//! (`bluetooth/src/btusb_quirks.rs`, whose Realtek names come from
//! the same file).
//!
//! Wire sequence (the `rtl8723b` path, which Linux selects for every
//! lmp subversion this loader serves):
//! 1. Read ROM version, HCI vendor opcode 0xFC6D, no parameters.
//!    The Command Complete return parameters are `[status, version]`.
//! 2. Read the security key id, HCI vendor opcode 0xFC61 with the
//!    `RTL_SEC_PROJ` register command `{0x10, 0xA4, 0xAD, 0x00,
//!    0xB0}`. The return parameters are `[status, key_id_lo,
//!    key_id_hi]`; the key id is the low byte.
//! 3. Parse the firmware file (v1 or v2, by signature) and select
//!    the patch for this ROM (see below), verifying the file's
//!    project id against the chip family the USB product id
//!    implies. When the key id is zero and a config file is
//!    provisioned, its bytes are appended verbatim to the patch.
//! 4. Download the buffer with opcode 0xFC20 in `RTL_FRAG_LEN`
//!    (252) byte fragments; see [`fragment_index`] for the index
//!    scheme. After the download, pending vendor events are drained
//!    so the generic bring-up sees a clean event stream.
//!
//! Firmware file format v1, signature `"Realtech"` (`btrtl.h`
//! `rtl_epatch_header`): header `[signature[8], fw_version LE32,
//! num_patches LE16]`, then a metadata section of `num_patches`
//! chip ids (LE16 each), patch lengths (LE16 each) and patch
//! offsets (LE32 each). The patch whose chip id equals
//! `rom_version + 1` is selected; the download buffer is the patch
//! bytes minus their last 4 bytes, followed by the header's
//! `fw_version` (4 bytes LE).
//!
//! Firmware file format v2, signature `"RTBTCore"` (`btrtl.h`
//! `rtl_epatch_header_v2`): header `[signature[8], fw_version[8],
//! num_sections LE32]`, then sections `[opcode LE32, len LE32,
//! data]`; each section's data starts with `[num_subsecs LE16,
//! reserved LE16]` followed by subsections `[eco, prio, cb[2],
//! len LE32, data]`. Subsections whose `eco` equals
//! `rom_version + 1` are kept, ordered by ascending `prio`
//! (inserted before the first kept subsection with `prio` greater
//! than or equal to the new one, exactly as Linux's
//! `btrtl_insert_ordered_subsec`), and concatenated in that order.
//! Security-header sections (opcode 0x03) are ignored entirely
//! when the chip key id is zero, and otherwise keep only
//! subsections whose key-id byte (offset 2, where the common
//! subsection layout has `cb[2]`) equals the chip key id. Unknown
//! section opcodes are skipped. Sections are parsed within
//! `fw_len - 7` bytes ("cut the tail").
//!
//! Both formats carry a vendor extension trailer: the last 4 bytes
//! must be `{0x51, 0x04, 0xFD, 0x77}`, and walking backward from
//! there over `[payload..., data, length, opcode]` instructions
//! must find a project-id instruction (`opcode == 0`,
//! `length == 1`); opcode 0xFF ends the walk without a project id
//! and a zero length is corrupt. The project id maps to an lmp
//! subversion through [`project_lmp_subver`] (the
//! `project_id_to_lmp_subver` table); it must equal the chip
//! family's expected value or the file is rejected.
//!
//! Deliberate strictness deltas vs Linux, all fail-closed:
//! - The fragment response's echoed index is verified (low 7
//!   bits); Linux checks only the response length.
//! - A truncated v2 section or subsection fails the parse; Linux
//!   keeps the partial patch set and downloads it.
//! - A trailing partial record in a section is impossible by
//!   construction: subsections are consumed exactly
//!   `num_subsecs` times, and leftover section bytes are ignored,
//!   as in Linux.
//!
//! The pure helpers (`parse_realtek_firmware`, `fragment_index`,
//! `fragment_plan`, `project_lmp_subver`) carry the conversation
//! fixtures; the async glue is a thin loop over them.

use alloc::format;
use alloc::vec::Vec;

use narf_bluetooth::btusb_quirks::{self, Quirk};

use crate::btusb::{self, BtUsbError};
use crate::xhci::Xhci;

/// HCI vendor opcode: read ROM version, no parameters.
const OP_READ_ROM_VERSION: u16 = 0xFC6D;
/// HCI vendor opcode: download firmware fragment.
const OP_DOWNLOAD: u16 = 0xFC20;
/// HCI vendor opcode: read a vendor register.
const OP_READ_REG: u16 = 0xFC61;
/// Register command selecting the security-project register.
const SEC_PROJ_CMD: [u8; 5] = [0x10, 0xA4, 0xAD, 0x00, 0xB0];
/// Max data bytes per 0xFC20 fragment (`RTL_FRAG_LEN`).
const FRAG_LEN: usize = 252;
/// Highest fragment index value. The counter runs 0..=0x7F,
/// then wraps to 1: the 0x80 bit of the index byte is the
/// data-end flag, so the counter field is 7 bits wide and 0x7F
/// is a real, sent index, not a skipped one.
const FRAG_INDEX_MAX: u8 = 0x7F;
/// Bit marking the last fragment in its index byte.
const FRAG_INDEX_LAST: u8 = 0x80;

/// v1 firmware signature (`RTL_EPATCH_SIGNATURE`).
const SIG_V1: &[u8; 8] = b"Realtech";
/// v2 firmware signature (`RTL_EPATCH_SIGNATURE_V2`).
const SIG_V2: &[u8; 8] = b"RTBTCore";
/// Vendor extension signature at the last 4 bytes of the file.
const EXT_SIG: [u8; 4] = [0x51, 0x04, 0xFD, 0x77];
/// v1 header size: signature[8] + fw_version[4] + num_patches[2].
const V1_HEADER_SIZE: usize = 14;
/// v2 header size: signature[8] + fw_version[8] + num_sections[4].
const V2_HEADER_SIZE: usize = 20;
/// Backward extension walk never runs into the header region:
/// the walk guard is the v1 header size plus one instruction's
/// three header bytes, exactly as in Linux.
const EXT_WALK_GUARD: usize = V1_HEADER_SIZE + 3;
/// Bytes cut from the tail when bounding v2 section parsing.
const V2_TAIL_CUT: usize = 7;
/// v2 section data header: num_subsecs LE16 + reserved LE16.
const V2_SECTION_HDR_SIZE: usize = 4;
/// v2 subsection fixed part: eco + prio + cb[2] + len LE32.
const V2_SUBSEC_HDR_SIZE: usize = 8;
/// v2 section opcode: patch snippets.
const SEC_OP_SNIPPETS: u32 = 0x01;
/// v2 section opcode: dummy header.
const SEC_OP_DUMMY_HEADER: u32 = 0x02;
/// v2 section opcode: security header.
const SEC_OP_SECURITY_HEADER: u32 = 0x03;
/// Extension instruction opcode: end of the instruction list.
const EXT_OP_EOF: u8 = 0xFF;
/// Extension instruction opcode: project id.
const EXT_OP_PROJECT_ID: u8 = 0x00;

/// Registry prefix for Realtek firmware names.
const RTL_PREFIX: &str = "rtl_bt";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RtlError {
    /// A vendor command failed at the HCI layer.
    Transport(BtUsbError),
    /// USB product ID is not a Realtek part this loader knows.
    UnsupportedDevice,
    /// No provisioned firmware file for this controller.
    FirmwareUnavailable,
    /// The firmware file failed structural validation.
    FirmwareInvalid,
    /// The firmware file is for a different chip family than the
    /// USB product id implies.
    ProjectMismatch,
    /// No patch in the file matches this controller's ROM version.
    NoPatchForRomVersion,
    /// The download buffer is empty after selection.
    EmptyDownload,
    /// A fragment response did not echo the sent fragment index.
    FragmentMismatch,
}

impl From<BtUsbError> for RtlError {
    fn from(e: BtUsbError) -> Self {
        RtlError::Transport(e)
    }
}

/// Chip family a USB product id implies: the firmware basename
/// from the quirk table and the lmp subversion Linux's `ic_info`
/// table records for that chip family. The basename is resolved
/// through [`btusb_quirks::firmware_paths`] so the quirk table
/// stays the single authority for names; the lmp value is what
/// the file's project id must map to.
fn realtek_chip(vendor_id: u16, product_id: u16) -> Option<(&'static str, u16)> {
    match (vendor_id, product_id) {
        // RTL8761BU: Linux 8761BU USB entry, lmp 0x8761.
        (0x0bda, 0x8771) | (0x0bda, 0xc123) => Some(("rtl8761bu_fw.bin", 0x8761)),
        // RTL8852A: Linux 8852A USB entry, lmp 0x8852.
        (0x0bda, 0xb852) => Some(("rtl8852au_fw.bin", 0x8852)),
        // RTL8852C: Linux 8852C USB entry, lmp 0x8852.
        (0x0bda, 0xc852) => Some(("rtl8852cu_fw.bin", 0x8852)),
        // RTL8822CE module: Linux 8822C USB entry, lmp 0x8822.
        (0x13d3, 0x3548) => Some(("rtl8822cu_fw.bin", 0x8822)),
        _ => None,
    }
}

/// Map a firmware project id to its lmp subversion
/// (`project_id_to_lmp_subver`).
fn project_lmp_subver(project_id: u8) -> Option<u16> {
    Some(match project_id {
        0 => 0x8723,
        1 => 0x8723,
        2 => 0x8821,
        3 => 0x8761,
        7 => 0x8703,
        8 => 0x8822,
        9 => 0x8723,
        10 => 0x8821,
        13 => 0x8822,
        14 => 0x8761,
        18 => 0x8852,
        20 => 0x8852,
        25 => 0x8852,
        36 => 0x8851,
        44 => 0x8922,
        47 => 0x8852,
        51 => 0x8761,
        _ => return None,
    })
}

/// Fragment index for the `pos`-th fragment (0-based), mirroring
/// Linux's counter (`btrtl.c` `rtl_download_firmware`: `index =
/// j++`, then `if (index == 0x7f) j = 1`). The counter runs
/// 0..=0x7F — 0x7F IS sent — then wraps to 1, repeating with
/// period 127 (values 1..=0x7F) after the first 128 fragments.
fn fragment_index(pos: usize) -> u8 {
    if pos <= FRAG_INDEX_MAX as usize {
        pos as u8
    } else {
        ((pos - FRAG_INDEX_MAX as usize - 1) % FRAG_INDEX_MAX as usize + 1) as u8
    }
}

/// Plan the fragment download of `len` bytes: one `(index,
/// offset, chunk_len)` triple per fragment. There is always a
/// final fragment; when `len` is a multiple of [`FRAG_LEN`] the
/// final fragment carries zero data bytes, exactly as Linux's
/// `fw_len / RTL_FRAG_LEN + 1` count.
fn fragment_plan(len: usize) -> Vec<(u8, usize, usize)> {
    let count = len / FRAG_LEN + 1;
    let mut plan = Vec::with_capacity(count);
    for pos in 0..count {
        let offset = pos * FRAG_LEN;
        let chunk_len = len.saturating_sub(offset).min(FRAG_LEN);
        let mut index = fragment_index(pos);
        if pos + 1 == count {
            index |= FRAG_INDEX_LAST;
        }
        plan.push((index, offset, chunk_len));
    }
    plan
}

/// Find the project id in a firmware file's extension trailer by
/// walking backward from the last 4 bytes (the extension
/// signature, already verified by the caller). Returns `None`
/// when the walk hits the end marker or the header guard without
/// finding a project-id instruction.
fn find_project_id(fw: &[u8]) -> Option<u8> {
    let mut p = fw.len().checked_sub(EXT_SIG.len())?;
    while p >= EXT_WALK_GUARD {
        let opcode = *fw.get(p - 1)?;
        let length = *fw.get(p - 2)?;
        let data = *fw.get(p - 3)?;
        p -= 3;
        if opcode == EXT_OP_EOF {
            return None;
        }
        if length == 0 {
            return None;
        }
        if opcode == EXT_OP_PROJECT_ID && length == 1 {
            return Some(data);
        }
        p = p.checked_sub(length as usize)?;
    }
    None
}

/// Parse a v1 (`"Realtech"`) firmware file and select the patch
/// for `rom_version`. The download buffer is the patch bytes
/// minus their last 4 bytes, followed by the header's fw_version.
fn parse_v1(fw: &[u8], rom_version: u8) -> Result<Vec<u8>, RtlError> {
    let num_patches = u16::from_le_bytes([fw[12], fw[13]]) as usize;
    let meta_end = V1_HEADER_SIZE
        .checked_add(
            num_patches
                .checked_mul(8)
                .ok_or(RtlError::FirmwareInvalid)?,
        )
        .ok_or(RtlError::FirmwareInvalid)?;
    if fw.len() < meta_end {
        return Err(RtlError::FirmwareInvalid);
    }
    let target = rom_version as u16 + 1;
    let mut selected: Option<(usize, usize)> = None;
    for i in 0..num_patches {
        let chip_base = V1_HEADER_SIZE + i * 2;
        let len_base = V1_HEADER_SIZE + num_patches * 2 + i * 2;
        let off_base = V1_HEADER_SIZE + num_patches * 4 + i * 4;
        let chip_id = u16::from_le_bytes([fw[chip_base], fw[chip_base + 1]]);
        if chip_id != target {
            continue;
        }
        let patch_len = u16::from_le_bytes([fw[len_base], fw[len_base + 1]]) as usize;
        let patch_off = u32::from_le_bytes([
            fw[off_base],
            fw[off_base + 1],
            fw[off_base + 2],
            fw[off_base + 3],
        ]) as usize;
        selected = Some((patch_off, patch_len));
        break;
    }
    let (patch_off, patch_len) = selected.ok_or(RtlError::NoPatchForRomVersion)?;
    if patch_len < 4 {
        return Err(RtlError::FirmwareInvalid);
    }
    let patch_end = patch_off
        .checked_add(patch_len)
        .ok_or(RtlError::FirmwareInvalid)?;
    if patch_end > fw.len() {
        return Err(RtlError::FirmwareInvalid);
    }
    let mut buf = Vec::with_capacity(patch_len);
    buf.extend_from_slice(&fw[patch_off..patch_end - 4]);
    buf.extend_from_slice(&fw[8..12]);
    Ok(buf)
}

/// Parse one v2 section's subsections, keeping those whose `eco`
/// equals `rom_version + 1` (and, for security-header sections,
/// whose key-id byte equals `key_id`). Kept subsections are
/// inserted into `kept` ordered by ascending `prio`, before the
/// first kept subsection with `prio` greater than or equal to
/// the new one.
fn parse_v2_section(
    opcode: u32,
    data: &[u8],
    rom_version: u8,
    key_id: u8,
    kept: &mut Vec<(u8, Vec<u8>)>,
) -> Result<(), RtlError> {
    if data.len() < V2_SECTION_HDR_SIZE {
        return Err(RtlError::FirmwareInvalid);
    }
    let num_subsecs = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut pos = V2_SECTION_HDR_SIZE;
    let target = rom_version as u16 + 1;
    for _ in 0..num_subsecs {
        let hdr = data
            .get(pos..pos + V2_SUBSEC_HDR_SIZE)
            .ok_or(RtlError::FirmwareInvalid)?;
        let eco = hdr[0];
        let prio = hdr[1];
        let sub_key_id = hdr[2];
        let sub_len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        pos += V2_SUBSEC_HDR_SIZE;
        let body = data
            .get(pos..pos + sub_len)
            .ok_or(RtlError::FirmwareInvalid)?;
        pos += sub_len;
        if eco as u16 != target {
            continue;
        }
        if opcode == SEC_OP_SECURITY_HEADER && sub_key_id != key_id {
            continue;
        }
        let insert_at = kept
            .iter()
            .position(|(p, _)| *p >= prio)
            .unwrap_or(kept.len());
        kept.insert(insert_at, (prio, body.to_vec()));
    }
    Ok(())
}

/// Parse a v2 (`"RTBTCore"`) firmware file and concatenate the
/// kept subsections in prio order.
fn parse_v2(fw: &[u8], rom_version: u8, key_id: u8) -> Result<Vec<u8>, RtlError> {
    let bound = fw
        .len()
        .checked_sub(V2_TAIL_CUT)
        .ok_or(RtlError::FirmwareInvalid)?;
    if bound < V2_HEADER_SIZE {
        return Err(RtlError::FirmwareInvalid);
    }
    let num_sections = u32::from_le_bytes([fw[16], fw[17], fw[18], fw[19]]) as usize;
    let mut pos = V2_HEADER_SIZE;
    let mut kept: Vec<(u8, Vec<u8>)> = Vec::new();
    for _ in 0..num_sections {
        let hdr = fw.get(pos..pos + 8).ok_or(RtlError::FirmwareInvalid)?;
        let opcode = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let sec_len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        pos += 8;
        if pos > bound || sec_len > bound - pos {
            return Err(RtlError::FirmwareInvalid);
        }
        let data = &fw[pos..pos + sec_len];
        pos += sec_len;
        match opcode {
            SEC_OP_SNIPPETS | SEC_OP_DUMMY_HEADER => {
                parse_v2_section(opcode, data, rom_version, key_id, &mut kept)?;
            }
            SEC_OP_SECURITY_HEADER => {
                // A zero chip key id ignores all security headers.
                if key_id != 0 {
                    parse_v2_section(opcode, data, rom_version, key_id, &mut kept)?;
                }
            }
            _ => {}
        }
    }
    if kept.is_empty() {
        return Err(RtlError::NoPatchForRomVersion);
    }
    let total: usize = kept.iter().map(|(_, b)| b.len()).sum();
    if total == 0 {
        return Err(RtlError::EmptyDownload);
    }
    let mut buf = Vec::with_capacity(total);
    for (_, body) in kept {
        buf.extend_from_slice(&body);
    }
    Ok(buf)
}

/// Parse a Realtek firmware file (v1 or v2, by signature) and
/// return the download buffer for `rom_version`, verifying the
/// file's project id against `expected_lmp`.
fn parse_realtek_firmware(
    fw: &[u8],
    rom_version: u8,
    key_id: u8,
    expected_lmp: u16,
) -> Result<Vec<u8>, RtlError> {
    if fw.len() <= 8 {
        return Err(RtlError::FirmwareInvalid);
    }
    let is_v1 = fw.starts_with(SIG_V1);
    let is_v2 = fw.starts_with(SIG_V2);
    if !is_v1 && !is_v2 {
        return Err(RtlError::FirmwareInvalid);
    }
    let min_size = if is_v1 {
        V1_HEADER_SIZE + EXT_SIG.len() + 3
    } else {
        V2_HEADER_SIZE + EXT_SIG.len() + 3
    };
    if fw.len() < min_size {
        return Err(RtlError::FirmwareInvalid);
    }
    if fw[fw.len() - EXT_SIG.len()..] != EXT_SIG {
        return Err(RtlError::FirmwareInvalid);
    }
    let project_id = find_project_id(fw).ok_or(RtlError::FirmwareInvalid)?;
    let lmp = project_lmp_subver(project_id).ok_or(RtlError::FirmwareInvalid)?;
    if lmp != expected_lmp {
        return Err(RtlError::ProjectMismatch);
    }
    if is_v1 {
        parse_v1(fw, rom_version)
    } else {
        parse_v2(fw, rom_version, key_id)
    }
}

/// Read the controller's ROM version (0xFC6D). The return
/// parameters are `[status, version]`; the helper already
/// enforces a zero status.
async fn read_rom_version(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
) -> Result<u8, RtlError> {
    let ret = btusb::send_command_and_await_complete(
        xhci,
        slot_id,
        interface,
        event_dci,
        OP_READ_ROM_VERSION,
        &[],
    )
    .await?;
    if ret.len() != 2 {
        return Err(RtlError::Transport(BtUsbError::ShortReturnParams));
    }
    Ok(ret[1])
}

/// Read the chip security key id (0xFC61 + `RTL_SEC_PROJ`). The
/// return parameters are `[status, key_id_lo, key_id_hi]`.
async fn read_key_id(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
) -> Result<u8, RtlError> {
    let ret = btusb::send_command_and_await_complete(
        xhci,
        slot_id,
        interface,
        event_dci,
        OP_READ_REG,
        &SEC_PROJ_CMD,
    )
    .await?;
    if ret.len() != 3 {
        return Err(RtlError::Transport(BtUsbError::ShortReturnParams));
    }
    Ok(ret[1])
}

/// Download `buffer` with 0xFC20 fragments, verifying each
/// fragment response echoes the sent index's low 7 bits.
async fn download_firmware(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    buffer: &[u8],
) -> Result<(), RtlError> {
    for (index, offset, chunk_len) in fragment_plan(buffer.len()) {
        let mut params = Vec::with_capacity(1 + chunk_len);
        params.push(index);
        params.extend_from_slice(&buffer[offset..offset + chunk_len]);
        let ret = btusb::send_command_and_await_complete(
            xhci,
            slot_id,
            interface,
            event_dci,
            OP_DOWNLOAD,
            &params,
        )
        .await?;
        if ret.len() != 2 || ret[1] & 0x7F != index & 0x7F {
            return Err(RtlError::FragmentMismatch);
        }
    }
    Ok(())
}

/// Run the Realtek firmware setup for a just-configured USB
/// Bluetooth controller. On success the controller is running
/// patched firmware and the generic bring-up may proceed.
pub(crate) async fn setup_realtek(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    vendor_id: u16,
    product_id: u16,
) -> Result<(), RtlError> {
    let (fw_name, expected_lmp) =
        realtek_chip(vendor_id, product_id).ok_or(RtlError::UnsupportedDevice)?;
    let (fw_name, cfg_name) = btusb_quirks::firmware_paths(Quirk::Realtek)
        .into_iter()
        .find(|(name, _)| *name == fw_name)
        .ok_or(RtlError::FirmwareUnavailable)?;
    let fw_cap = btusb::firmware_cap(&format!("{RTL_PREFIX}/{fw_name}"))
        .ok_or(RtlError::FirmwareUnavailable)?;
    let fw_view = narf_firmware::view_of(&fw_cap).map_err(|_| RtlError::FirmwareUnavailable)?;
    let rom_version = read_rom_version(xhci, slot_id, interface, event_dci).await?;
    let key_id = read_key_id(xhci, slot_id, interface, event_dci).await?;
    let mut buffer = parse_realtek_firmware(fw_view.bytes, rom_version, key_id, expected_lmp)?;
    // Config bytes are appended verbatim, but only when the chip
    // key id is zero: a nonzero key id means security headers
    // carry the configuration instead. All five USB parts this
    // loader serves have `config_needed = false` in Linux's
    // `ic_info` table, so a missing config file is tolerated.
    if key_id == 0 {
        if let Some(cfg_name) = cfg_name {
            if let Some(cfg_cap) = btusb::firmware_cap(&format!("{RTL_PREFIX}/{cfg_name}")) {
                if let Ok(cfg_view) = narf_firmware::view_of(&cfg_cap) {
                    buffer.extend_from_slice(cfg_view.bytes);
                }
            }
        }
    }
    if buffer.is_empty() {
        return Err(RtlError::EmptyDownload);
    }
    download_firmware(xhci, slot_id, interface, event_dci, &buffer).await?;
    btusb::drain_pending_events(xhci, slot_id, event_dci, 500).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// Build a synthetic v1 file: two patches, chip ids 0x0005
    /// and 0x0007, then an extension trailer carrying project id
    /// 14 (8761B, lmp 0x8761) and the extension signature.
    fn synthetic_v1() -> Vec<u8> {
        let mut fw = Vec::new();
        fw.extend_from_slice(SIG_V1);
        fw.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        fw.extend_from_slice(&2u16.to_le_bytes());
        // Chip ids.
        fw.extend_from_slice(&0x0005u16.to_le_bytes());
        fw.extend_from_slice(&0x0007u16.to_le_bytes());
        // Patch lengths.
        fw.extend_from_slice(&8u16.to_le_bytes());
        fw.extend_from_slice(&10u16.to_le_bytes());
        // Patch offsets (after the 14 + 16 metadata bytes).
        fw.extend_from_slice(&30u32.to_le_bytes());
        fw.extend_from_slice(&38u32.to_le_bytes());
        // Patch 0: 8 bytes; patch 1: 10 bytes.
        fw.extend_from_slice(b"PATCH000");
        fw.extend_from_slice(b"PATCH10001");
        // Extension trailer: one project-id instruction, forward
        // layout [payload, data, length, opcode] = [0x00, 14, 1,
        // 0x00], then the extension signature.
        fw.extend_from_slice(&[0x00, 14, 1, 0x00]);
        fw.extend_from_slice(&EXT_SIG);
        fw
    }

    #[test]
    fn v1_selects_patch_by_rom_version_plus_one() {
        let fw = synthetic_v1();
        // ROM version 0x0006 selects chip id 0x0007 (patch 1).
        let buf = parse_realtek_firmware(&fw, 0x06, 0, 0x8761).unwrap();
        // Patch bytes minus their last 4, then fw_version LE.
        let mut expected = b"PATCH1".to_vec();
        expected.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        assert_eq!(buf, expected);
    }

    #[test]
    fn v1_rejects_unmatched_rom_version() {
        let fw = synthetic_v1();
        assert_eq!(
            parse_realtek_firmware(&fw, 0x09, 0, 0x8761),
            Err(RtlError::NoPatchForRomVersion)
        );
    }

    #[test]
    fn v1_rejects_project_mismatch() {
        let fw = synthetic_v1();
        // Project 14 maps to lmp 0x8761, not 0x8852.
        assert_eq!(
            parse_realtek_firmware(&fw, 0x06, 0, 0x8852),
            Err(RtlError::ProjectMismatch)
        );
    }

    #[test]
    fn v1_rejects_bad_extension_signature() {
        let mut fw = synthetic_v1();
        let n = fw.len();
        fw[n - 1] = 0x00;
        assert_eq!(
            parse_realtek_firmware(&fw, 0x06, 0, 0x8761),
            Err(RtlError::FirmwareInvalid)
        );
    }

    #[test]
    fn fragment_plan_counts_and_wraps() {
        // 504 bytes = 2 full fragments + the mandatory empty
        // final fragment. The last fragment ORs 0x80 onto the
        // running index (2), per `btrtl.c` (`dl_cmd->index |=
        // 0x80`), so it carries 0x82, not a flat 0x80.
        let plan = fragment_plan(504);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0], (0x00, 0, 252));
        assert_eq!(plan[1], (0x01, 252, 252));
        assert_eq!(plan[2], (0x82, 504, 0));
        // Index cycle: 0..=0x7F, then 1..=0x7F repeating with
        // period 127. 0x7F IS sent (fragment 127), then the
        // counter wraps to 1.
        assert_eq!(fragment_index(126), 0x7E);
        assert_eq!(fragment_index(127), 0x7F);
        assert_eq!(fragment_index(128), 0x01);
        assert_eq!(fragment_index(254), 0x7F);
        assert_eq!(fragment_index(255), 0x01);
        // A single-byte buffer is one last fragment.
        let plan = fragment_plan(1);
        assert_eq!(plan, vec![(0x80, 0, 1)]);
    }

    /// Build a synthetic v2 file: one snippets section with two
    /// subsections (eco 0x06 prio 1, eco 0x07 prio 2) and one
    /// security section with one subsection (eco 0x07, key id
    /// 0x42, prio 0). ROM version 0x06 keeps eco 0x07 only.
    fn synthetic_v2() -> Vec<u8> {
        let mut fw = Vec::new();
        fw.extend_from_slice(SIG_V2);
        fw.extend_from_slice(&[0u8; 8]);
        fw.extend_from_slice(&2u32.to_le_bytes());
        // Section 1: snippets.
        let mut sec1 = Vec::new();
        sec1.extend_from_slice(&2u16.to_le_bytes());
        sec1.extend_from_slice(&0u16.to_le_bytes());
        sec1.push(0x06);
        sec1.push(1);
        sec1.extend_from_slice(&[0, 0]);
        sec1.extend_from_slice(&2u32.to_le_bytes());
        sec1.extend_from_slice(b"AA");
        sec1.push(0x07);
        sec1.push(2);
        sec1.extend_from_slice(&[0, 0]);
        sec1.extend_from_slice(&2u32.to_le_bytes());
        sec1.extend_from_slice(b"BB");
        fw.extend_from_slice(&SEC_OP_SNIPPETS.to_le_bytes());
        fw.extend_from_slice(&(sec1.len() as u32).to_le_bytes());
        fw.extend_from_slice(&sec1);
        // Section 2: security header, key id 0x42.
        let mut sec2 = Vec::new();
        sec2.extend_from_slice(&1u16.to_le_bytes());
        sec2.extend_from_slice(&0u16.to_le_bytes());
        sec2.push(0x07);
        sec2.push(0);
        sec2.push(0x42);
        sec2.push(0);
        sec2.extend_from_slice(&2u32.to_le_bytes());
        sec2.extend_from_slice(b"CC");
        fw.extend_from_slice(&SEC_OP_SECURITY_HEADER.to_le_bytes());
        fw.extend_from_slice(&(sec2.len() as u32).to_le_bytes());
        fw.extend_from_slice(&sec2);
        // Extension trailer, in forward order: the project-id
        // instruction [project_id, length, opcode] = [14, 1,
        // 0x00], then a dummy instruction the backward walk
        // must skip ([payload 0xAA 0xBB, data 0x99, length 2,
        // opcode 0x55]), then the extension signature at the
        // very end of the file, as Linux's extension check
        // requires (`fw_data + fw_len - 4`). The v2 section
        // parser cuts the last 7 bytes as a guard (the minimal
        // trailer: 3-byte last instruction + 4-byte signature);
        // the section loop stops after `num_sections`
        // regardless, so the longer trailer here is never read
        // as section data — exactly as in real files, whose
        // trailers are variable-length.
        fw.extend_from_slice(&[14, 1, 0x00]);
        fw.extend_from_slice(&[0xAA, 0xBB, 0x99, 2, 0x55]);
        fw.extend_from_slice(&EXT_SIG);
        fw
    }

    #[test]
    fn v2_keeps_matching_subsecs_in_prio_order() {
        let fw = synthetic_v2();
        // Key id 0x42 matches the security subsection: prio 0
        // ("CC") sorts before prio 2 ("BB"); eco 0x06 ("AA") is
        // dropped.
        let buf = parse_realtek_firmware(&fw, 0x06, 0x42, 0x8761).unwrap();
        assert_eq!(buf, b"CCBB");
    }

    #[test]
    fn v2_ignores_security_sections_with_zero_key_id() {
        let fw = synthetic_v2();
        let buf = parse_realtek_firmware(&fw, 0x06, 0, 0x8761).unwrap();
        assert_eq!(buf, b"BB");
    }

    #[test]
    fn v2_rejects_unmatched_key_id_subsection() {
        let fw = synthetic_v2();
        // Key id 0x43 matches nothing in the security section,
        // so only the snippets subsection survives.
        let buf = parse_realtek_firmware(&fw, 0x06, 0x43, 0x8761).unwrap();
        assert_eq!(buf, b"BB");
    }

    #[test]
    fn v2_rejects_no_matching_patch() {
        let fw = synthetic_v2();
        assert_eq!(
            parse_realtek_firmware(&fw, 0x09, 0x42, 0x8761),
            Err(RtlError::NoPatchForRomVersion)
        );
    }

    #[test]
    fn chip_map_covers_quirk_table_pids() {
        // Every Realtek PID the quirk table identifies must map
        // to a pair the quirk table actually records.
        for (vendor_id, product_id) in [
            (0x0bda, 0x8771),
            (0x0bda, 0xb852),
            (0x0bda, 0xc852),
            (0x0bda, 0xc123),
            (0x13d3, 0x3548),
        ] {
            let (fw_name, _) = realtek_chip(vendor_id, product_id).unwrap();
            assert!(
                btusb_quirks::firmware_paths(Quirk::Realtek)
                    .iter()
                    .any(|(name, _)| *name == fw_name),
                "no quirk pair for {vendor_id:04x}:{product_id:04x} ({fw_name})",
            );
        }
        assert_eq!(realtek_chip(0x0bda, 0x9999), None);
    }
}
