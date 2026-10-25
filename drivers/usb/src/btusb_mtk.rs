//! MediaTek USB Bluetooth firmware setup (MT7921 / MT7922).
//!
//! MT792x controllers boot a ROM patcher: the host downloads the
//! `BT_RAM_CODE_MT*_hdr.bin` image section by section with WMT
//! (Wireless Management Task) commands riding HCI vendor opcode
//! 0xFC6F, and the ROM applies each section to RAM. Only after the
//! download does the controller answer normal HCI.
//!
//! Reference: Linux `drivers/bluetooth/btmtk.c`
//! (`btmtk_setup_firmware_79xx`) and `drivers/bluetooth/btmtk.h`,
//! ISC-licensed, plus `btmtk_usb_hci_wmt_sync` in
//! `drivers/bluetooth/btusb.c` (GPL-2.0), consulted under NARF's
//! GPL-2.0-or-later licensing.
//!
//! Image layout (all LE):
//! - bytes 0..32 — patch header region: `datetime[16]`,
//!   `platform[4]`, `hwver u16`, `swver u16`, `magicnum u32`.
//! - bytes 32..96 — global descriptor: `patch_ver`, `sub_sys`,
//!   `feature_opt`, `section_num` (u32 each; `section_num` at +12).
//! - bytes 96.. — one 64-byte section map per section:
//!   `sectype u32`, `secoffset u32`, `secsize u32`, then the
//!   `bin_info_spec` union whose `dlAddr` / `dlsize` sit at +12 /
//!   +16 within the map.
//!
//! Download per section with `dlsize > 0` (Linux's exact state
//! machine):
//! 1. Send the section-map tail as one WMT PATCH_DWNLD command
//!    (flag 0): payload = `[0x00] ++ section_map[12..64]` (the 0
//!    selects legacy download mode). The WMT event's flag byte
//!    answers the patch state: 1 UNDONE → proceed, 2 PROGRESS →
//!    wait 100 ms and ask again (≤ 20 retries), 3 DONE → the
//!    section is already applied, skip it; anything else fails.
//! 2. Send the section body from `image[secoffset..+dlsize]` in
//!    ≤ 250-byte WMT PATCH_DWNLD chunks: flag 1 on the first chunk,
//!    2 on middle chunks, 3 on the last.
//!
//! WMT framing: HCI command parameters are
//! `[dir=0x01, op, dlen u16 LE (= 5 + data len), flag, data...]`;
//! the answer is HCI event 0xE4 whose parameters carry the same
//! 5-byte WMT header with `dir = 0x02` and the status in its flag
//! byte (`btmtk_hci_wmt_evt`).
//!
//! Deliberate simplification vs Linux: `btusb`'s pre-download
//! subsystem reset for MT7922 (register pokes via WMT REGISTER) is
//! not reproduced. On a cold boot the ROM patch state is UNDONE and
//! the download proceeds; the state machine above still converges
//! if a previous attempt left a section PROGRESS or DONE, so the
//! reset is a recovery accelerator, not a correctness requirement.
//!
//! The pure helpers (`parse_ram_code`, `section_chunks`,
//! `wmt_params`, `parse_wmt_event`, `patch_action`) carry the
//! conversation fixtures; the async glue is a thin loop over them.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use narf_bluetooth::btusb_quirks::{self, Quirk};

use crate::btusb::{self, BtUsbError};
use crate::xhci::Xhci;

/// HCI opcode carrying WMT commands.
const OP_WMT: u16 = 0xFC6F;
/// HCI event code carrying WMT events.
const EVT_WMT: u8 = 0xE4;
/// WMT op: patch download.
const WMT_PATCH_DWNLD: u8 = 0x01;
/// WMT direction byte for host → device commands.
const WMT_DIR_COMMAND: u8 = 0x01;
/// WMT direction byte for device → host events.
const WMT_DIR_EVENT: u8 = 0x02;

/// Patch header region size.
const PATCH_HEADER_SIZE: usize = 32;
/// Global descriptor size.
const GLOBAL_DESC_SIZE: usize = 64;
/// Section map size.
const SECTION_MAP_SIZE: usize = 64;
/// Offset of `bin_info_spec` inside a section map.
const SEC_MAP_SPEC_OFFSET: usize = 12;
/// Max data bytes per WMT PATCH_DWNLD chunk.
const CHUNK_MAX: usize = 250;
/// Section-map probe retries while the ROM reports PROGRESS.
const PROBE_RETRIES: usize = 20;

/// Patch states reported in the WMT event flag byte
/// (`btmtk.h` BTMTK_WMT_PATCH_*).
const PATCH_UNDONE: u8 = 1;
const PATCH_PROGRESS: u8 = 2;
const PATCH_DONE: u8 = 3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum MtkError {
    /// A vendor command failed at the HCI layer.
    Transport(BtUsbError),
    /// USB product ID is not a MediaTek part this loader knows.
    UnsupportedDevice,
    /// No provisioned RAM-code image for this controller.
    FirmwareUnavailable,
    /// The RAM-code image failed structural validation.
    FirmwareInvalid,
    /// The WMT event did not match the command sent.
    WmtEvent,
    /// The ROM reported an unexpected patch state.
    PatchStatus(u8),
}

impl From<BtUsbError> for MtkError {
    fn from(e: BtUsbError) -> Self {
        MtkError::Transport(e)
    }
}

/// What to do with a section after its probe answer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PatchAction {
    /// State UNDONE: download the section body.
    Download,
    /// State PROGRESS: wait and probe again.
    Retry,
    /// State DONE: already applied, skip the body.
    Skip,
    /// Any other state: fail the setup.
    Fail,
}

pub(crate) fn patch_action(status: u8) -> PatchAction {
    match status {
        PATCH_UNDONE => PatchAction::Download,
        PATCH_PROGRESS => PatchAction::Retry,
        PATCH_DONE => PatchAction::Skip,
        _ => PatchAction::Fail,
    }
}

/// One downloadable section of a RAM-code image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MtkSection {
    /// Offset of the section body in the image.
    pub offset: u32,
    /// Download size (bytes) — the section is skipped when 0.
    pub dl_size: u32,
    /// Probe payload: `[0x00] ++ section_map[12..64]`.
    pub probe: [u8; 53],
}

/// A parsed RAM-code image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MtkImage {
    pub hw_ver: u16,
    pub sw_ver: u16,
    pub sections: Vec<MtkSection>,
}

/// Parse and structurally validate a `BT_RAM_CODE_MT*_hdr.bin` image.
pub(crate) fn parse_ram_code(image: &[u8]) -> Result<MtkImage, MtkError> {
    if image.len() < PATCH_HEADER_SIZE + GLOBAL_DESC_SIZE {
        return Err(MtkError::FirmwareInvalid);
    }
    let le16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let le32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let hw_ver = le16(&image[20..22]);
    let sw_ver = le16(&image[22..24]);
    let section_num = le32(&image[PATCH_HEADER_SIZE + 12..PATCH_HEADER_SIZE + 16]) as usize;
    if section_num > 64 {
        return Err(MtkError::FirmwareInvalid);
    }
    let maps_end = PATCH_HEADER_SIZE + GLOBAL_DESC_SIZE + SECTION_MAP_SIZE * section_num;
    if image.len() < maps_end {
        return Err(MtkError::FirmwareInvalid);
    }
    let mut sections = Vec::with_capacity(section_num);
    for i in 0..section_num {
        let base = PATCH_HEADER_SIZE + GLOBAL_DESC_SIZE + SECTION_MAP_SIZE * i;
        let offset = le32(&image[base + 4..base + 8]);
        let dl_size = le32(&image[base + SEC_MAP_SPEC_OFFSET + 4..base + SEC_MAP_SPEC_OFFSET + 8]);
        if dl_size > 0 && offset as usize + dl_size as usize > image.len() {
            return Err(MtkError::FirmwareInvalid);
        }
        let mut probe = [0u8; 53];
        probe[1..53].copy_from_slice(&image[base + SEC_MAP_SPEC_OFFSET..base + SECTION_MAP_SIZE]);
        sections.push(MtkSection {
            offset,
            dl_size,
            probe,
        });
    }
    Ok(MtkImage {
        hw_ver,
        sw_ver,
        sections,
    })
}

/// Split a section body into WMT chunks with their flags: 1 = first,
/// 2 = middle, 3 = last. A single-chunk section is flag 1 (the first
/// flag wins, exactly as in Linux's loop).
pub(crate) fn section_chunks<'a>(image: &'a [u8], section: &MtkSection) -> Vec<(u8, &'a [u8])> {
    let start = section.offset as usize;
    let end = start + section.dl_size as usize;
    let body = &image[start..end];
    let mut out = Vec::new();
    let mut pos = 0;
    let mut first = true;
    while pos < body.len() {
        let n = core::cmp::min(CHUNK_MAX, body.len() - pos);
        let flag = if first {
            1
        } else if pos + n >= body.len() {
            3
        } else {
            2
        };
        out.push((flag, &body[pos..pos + n]));
        first = false;
        pos += n;
    }
    out
}

/// Build the HCI command parameters for one WMT command.
pub(crate) fn wmt_params(op: u8, flag: u8, data: &[u8]) -> Vec<u8> {
    let dlen = (5 + data.len()) as u16;
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(WMT_DIR_COMMAND);
    out.push(op);
    out.extend_from_slice(&dlen.to_le_bytes());
    out.push(flag);
    out.extend_from_slice(data);
    out
}

/// Parse a WMT event's parameters into `(op, flag)`.
pub(crate) fn parse_wmt_event(params: &[u8]) -> Option<(u8, u8)> {
    if params.len() < 5 || params[0] != WMT_DIR_EVENT {
        return None;
    }
    Some((params[1], params[4]))
}

/// Send one WMT command and return the answering event's flag byte.
async fn wmt_sync(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    op: u8,
    flag: u8,
    data: &[u8],
) -> Result<u8, MtkError> {
    let event = btusb::send_command_and_await_event(
        xhci,
        slot_id,
        interface,
        event_dci,
        OP_WMT,
        &wmt_params(op, flag, data),
        EVT_WMT,
    )
    .await?;
    let (ev_op, ev_flag) = parse_wmt_event(&event.params).ok_or(MtkError::WmtEvent)?;
    if ev_op != op {
        return Err(MtkError::WmtEvent);
    }
    Ok(ev_flag)
}

async fn cooperative_delay_ms(ms: u64) {
    let deadline = narf_time::Deadline::after_ms(ms);
    while !deadline.expired() {
        narf_scheduler::yield_now().await;
    }
}

/// Map a USB product ID to the chip's device ID used for firmware
/// naming (the Lite-On 13d3:3563 module carries an MT7922).
fn device_id(product_id: u16) -> Option<u16> {
    match product_id {
        0x7961 => Some(0x7961),
        0x7922 | 0x3563 => Some(0x7922),
        _ => None,
    }
}

/// The provisioned RAM-code name for a device ID, from the quirk
/// table's MediaTek entries under the `mediatek/` prefix.
fn firmware_name(dev_id: u16) -> Option<String> {
    let needle = if dev_id == 0x7961 { "MT7961" } else { "MT7922" };
    btusb_quirks::firmware_paths(Quirk::MediaTek)
        .into_iter()
        .map(|(name, _)| name)
        .find(|name| name.contains(needle))
        .map(|name| format!("mediatek/{name}"))
}

/// Run the MediaTek firmware setup for a just-configured USB
/// Bluetooth controller. On success the RAM code is applied and the
/// generic bring-up may proceed.
pub(crate) async fn setup_mediatek(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    product_id: u16,
) -> Result<(), MtkError> {
    let dev_id = device_id(product_id).ok_or(MtkError::UnsupportedDevice)?;
    let name = firmware_name(dev_id).ok_or(MtkError::FirmwareUnavailable)?;
    let cap = btusb::firmware_cap(&name).ok_or(MtkError::FirmwareUnavailable)?;
    let view = narf_firmware::view_of(&cap).map_err(|_| MtkError::FirmwareUnavailable)?;
    let image = view.bytes;
    let parsed = parse_ram_code(image)?;

    for section in &parsed.sections {
        if section.dl_size == 0 {
            continue;
        }
        // Probe: ask the ROM for this section's patch state.
        let mut retries = 0;
        let download = loop {
            let status = wmt_sync(
                xhci,
                slot_id,
                interface,
                event_dci,
                WMT_PATCH_DWNLD,
                0,
                &section.probe,
            )
            .await?;
            match patch_action(status) {
                PatchAction::Download => break true,
                PatchAction::Skip => break false,
                PatchAction::Retry => {
                    retries += 1;
                    if retries > PROBE_RETRIES {
                        return Err(MtkError::PatchStatus(status));
                    }
                    cooperative_delay_ms(100).await;
                }
                PatchAction::Fail => return Err(MtkError::PatchStatus(status)),
            }
        };
        if !download {
            continue;
        }
        for (flag, chunk) in section_chunks(image, section) {
            wmt_sync(
                xhci,
                slot_id,
                interface,
                event_dci,
                WMT_PATCH_DWNLD,
                flag,
                chunk,
            )
            .await?;
        }
    }

    // Firmware activation takes a few moments (Linux sleeps
    // 100-120 ms); then drain any asynchronous WMT chatter so the
    // generic bring-up's first Command Complete is the next event.
    cooperative_delay_ms(100).await;
    btusb::drain_pending_events(xhci, slot_id, event_dci, 50).await;
    Ok(())
}

#[cfg(test)]
mod unit {
    use super::*;

    fn synthetic_image() -> alloc::vec::Vec<u8> {
        // One section: body at offset 200, dl_size 600.
        let mut image = alloc::vec![0u8; 800];
        image[20..22].copy_from_slice(&0x7961u16.to_le_bytes());
        image[22..24].copy_from_slice(&0x0102u16.to_le_bytes());
        // Global descriptor: section_num at +12.
        image[44..48].copy_from_slice(&1u32.to_le_bytes());
        // Section map at 96: pattern first (the probe copies it
        // verbatim), then the fields parse_ram_code reads.
        for (i, b) in image[108..160].iter_mut().enumerate() {
            *b = (i as u8) ^ 0xA5;
        }
        // secoffset at +4, dlsize at +16.
        image[100..104].copy_from_slice(&200u32.to_le_bytes());
        image[112..116].copy_from_slice(&600u32.to_le_bytes());
        image
    }

    #[test]
    fn parse_ram_code_reads_header_and_section() {
        let image = synthetic_image();
        let parsed = parse_ram_code(&image).unwrap();
        assert_eq!(parsed.hw_ver, 0x7961);
        assert_eq!(parsed.sw_ver, 0x0102);
        assert_eq!(parsed.sections.len(), 1);
        let section = &parsed.sections[0];
        assert_eq!(section.offset, 200);
        assert_eq!(section.dl_size, 600);
        assert_eq!(section.probe[0], 0);
        assert_eq!(&section.probe[1..53], &image[108..160]);
    }

    #[test]
    fn parse_ram_code_rejects_truncated_section() {
        let mut image = synthetic_image();
        image[112..116].copy_from_slice(&10_000u32.to_le_bytes());
        assert_eq!(parse_ram_code(&image), Err(MtkError::FirmwareInvalid));
    }

    #[test]
    fn section_chunks_flag_progression() {
        let image = synthetic_image();
        let parsed = parse_ram_code(&image).unwrap();
        let chunks = section_chunks(&image, &parsed.sections[0]);
        let flags: alloc::vec::Vec<u8> = chunks.iter().map(|(f, _)| *f).collect();
        let sizes: alloc::vec::Vec<usize> = chunks.iter().map(|(_, c)| c.len()).collect();
        assert_eq!(flags, [1, 2, 3]);
        assert_eq!(sizes, [250, 250, 100]);
    }

    #[test]
    fn wmt_framing_and_event_parse() {
        let params = wmt_params(WMT_PATCH_DWNLD, 3, &[0xAA; 10]);
        assert_eq!(params[0], 0x01);
        assert_eq!(params[1], WMT_PATCH_DWNLD);
        assert_eq!(u16::from_le_bytes([params[2], params[3]]), 15);
        assert_eq!(params[4], 3);
        let event_params = [0x02, WMT_PATCH_DWNLD, 0x05, 0x00, PATCH_PROGRESS];
        assert_eq!(
            parse_wmt_event(&event_params),
            Some((WMT_PATCH_DWNLD, PATCH_PROGRESS))
        );
        assert_eq!(patch_action(PATCH_UNDONE), PatchAction::Download);
        assert_eq!(patch_action(PATCH_PROGRESS), PatchAction::Retry);
        assert_eq!(patch_action(PATCH_DONE), PatchAction::Skip);
        assert_eq!(patch_action(0x7F), PatchAction::Fail);
    }
}
