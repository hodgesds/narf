//! Intel USB Bluetooth firmware setup (AX200 / AX210 class).
//!
//! Intel combo controllers enumerate in a bootloader mode that only
//! understands vendor commands; the operational firmware (`.sfi`)
//! must be downloaded over "secure send" before normal HCI works,
//! then booted with the Intel Reset, then configured with the
//! device-specific DDC parameters (`.ddc`).
//!
//! Reference: Linux `drivers/bluetooth/btintel.c` +
//! `drivers/bluetooth/btusb.c` (`btusb_setup_intel_newgen`,
//! `btusb_intel_download_firmware_newgen`, `btintel_download_fw_tlv`,
//! `btintel_secure_send`, `btintel_load_ddc_config`), GPL-2.0,
//! consulted under NARF's GPL-2.0-or-later licensing.
//!
//! Sequence implemented here (newgen / TLV devices — USB PIDs
//! 0x0032 AX210, 0x0033 AX211, 0x0036 BE200 — and the legacy
//! `intel_version` devices 0x0026 / 0x0029, which share the same
//! secure-send machinery with an RSA-only header):
//!
//! 1. Read Version — opcode 0xFC05. Newgen devices take one 0xFF
//!    parameter and answer with a TLV stream; `img_type` 0x01 =
//!    bootloader, 0x03 = operational firmware already running (skip
//!    to DDC). Legacy devices answer the fixed 10-byte
//!    `intel_version` struct; `fw_variant` 0x06 = bootloader,
//!    0x23 = operational.
//! 2. Read Boot Params — opcode 0xFC0D (26-byte `intel_boot_params`).
//! 3. Firmware selection: the candidate (`.sfi`, `.ddc`) pairs named
//!    by `narf_bluetooth::btusb_quirks::firmware_paths` under the
//!    `intel/` prefix; the first pair whose `.sfi` the firmware
//!    registry can open wins. (Linux computes the name from the
//!    version fields instead; the NARF firmware provisioning stages
//!    blobs under the quirk table's names, so selection is by
//!    provisioned name.)
//! 4. If the image's embedded build (in its Write Boot Params
//!    command, opcode 0xFC0E) matches the running build, the
//!    download is skipped and only the boot runs.
//! 5. Download: CSS header validation, then secure-send fragments
//!    (opcode 0xFC09; first byte = fragment type, ≤ 252 payload
//!    bytes per command, each acked by Command Complete):
//!    RSA header (type 0x00 Init 128 B, 0x03 PKey 256 B, 0x02 Sign
//!    256 B from offset 388) or, for hw variants ≥ 0x17 with an
//!    ECDSA secure-boot engine, the ECDSA header at offset 644
//!    (128 / 96 / 96 B); then the payload as type 0x01 Data
//!    fragments grouped on 4-byte-aligned HCI-command boundaries.
//! 6. Boot: Intel Reset — opcode 0xFC01, params
//!    {reset_type 0x00, patch_enable 0x01, ddc_reload 0x00,
//!    boot_option 0x01, boot_param}.
//! 7. DDC: each record of the `.ddc` file as one Intel Write DDC
//!    command (opcode 0xFC8B), best-effort — the device works
//!    without DDC parameters.
//!
//! The pure helpers (`IntelVersionTlv::parse`, `header_fragments`,
//! `payload_fragments`, `scan_boot_param`, `validate_css`) carry the
//! conversation fixtures; the async glue is a thin loop over them
//! through `btusb::send_command_and_await_complete`.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use narf_bluetooth::btusb_quirks::{self, Quirk};

use crate::btusb::{self, BtUsbError};
use crate::xhci::Xhci;

/// Intel Read Version (vendor opcode 0xFC05).
const OP_READ_VERSION: u16 = 0xFC05;
/// Intel Read Boot Params (vendor opcode 0xFC0D).
const OP_READ_BOOT_PARAMS: u16 = 0xFC0D;
/// Write Boot Params command embedded in `.sfi` images (0xFC0E).
const OP_WRITE_BOOT_PARAMS: u16 = 0xFC0E;
/// Intel Secure Send (vendor opcode 0xFC09).
const OP_SECURE_SEND: u16 = 0xFC09;
/// Intel Reset (vendor opcode 0xFC01).
const OP_INTEL_RESET: u16 = 0xFC01;
/// Intel Write DDC (vendor opcode 0xFC8B).
const OP_WRITE_DDC: u16 = 0xFC8B;

/// RSA secure-boot header length at the start of every `.sfi`.
const RSA_HEADER_LEN: usize = 644;
/// ECDSA header length, present after the RSA header on hw ≥ 0x17.
const ECDSA_HEADER_LEN: usize = 320;
/// Offset of the ECDSA header inside the image.
const ECDSA_OFFSET: usize = RSA_HEADER_LEN;
/// CSS header version field offset (bytes 8..12 of a CSS header).
const CSS_HEADER_OFFSET: usize = 8;
/// CSS header version for RSA images.
const CSS_VER_RSA: u32 = 0x0001_0000;
/// CSS header version for ECDSA images.
const CSS_VER_ECDSA: u32 = 0x0002_0000;
/// Max payload bytes per secure-send command (253-byte HCI parameter
/// limit minus the fragment-type byte).
const FRAGMENT_PAYLOAD_MAX: usize = 252;

// Version TLV type tags (`btintel.h` INTEL_TLV_*).
const TLV_CNVI_TOP: u8 = 0x10;
const TLV_CNVR_TOP: u8 = 0x11;
const TLV_CNVI_BT: u8 = 0x12;
const TLV_CNVR_BT: u8 = 0x13;
const TLV_DEV_REV_ID: u8 = 0x14;
const TLV_IMAGE_TYPE: u8 = 0x15;
const TLV_TIME_STAMP: u8 = 0x16;
const TLV_BUILD_TYPE: u8 = 0x17;
const TLV_BUILD_NUM: u8 = 0x18;
const TLV_SECURE_BOOT: u8 = 0x19;
const TLV_OTP_LOCK: u8 = 0x1A;
const TLV_API_LOCK: u8 = 0x1B;
const TLV_DEBUG_LOCK: u8 = 0x1C;
const TLV_MIN_FW: u8 = 0x1D;
const TLV_LIMITED_CCE: u8 = 0x1E;
const TLV_SBE_TYPE: u8 = 0x1F;

/// `img_type` value for bootloader mode.
const IMG_TYPE_BOOTLOADER: u8 = 0x01;
/// `img_type` value for operational firmware.
const IMG_TYPE_OPERATIONAL: u8 = 0x03;
/// Legacy `fw_variant` value for bootloader mode.
const FW_VARIANT_BOOTLOADER: u8 = 0x06;
/// Legacy `fw_variant` value for operational firmware.
const FW_VARIANT_OPERATIONAL: u8 = 0x23;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum IntelError {
    /// A vendor command failed at the HCI layer.
    Transport(BtUsbError),
    /// Version response did not parse.
    Version,
    /// Hardware platform is not 0x37.
    UnsupportedPlatform,
    /// Hardware variant is not one this loader supports.
    UnsupportedVariant,
    /// Image type / firmware variant is neither bootloader nor
    /// operational.
    UnsupportedImage,
    /// Bootloader requires limited Command Complete mode; the
    /// download here needs one ack per fragment.
    LimitedCce,
    /// Secure-boot engine type is neither RSA (0) nor ECDSA (1).
    SecureBootEngine,
    /// Boot-params response did not parse or reported an error.
    BootParams,
    /// No provisioned `.sfi` image for this controller.
    FirmwareUnavailable,
    /// The `.sfi` image failed CSS / structure validation.
    FirmwareInvalid,
}

impl From<BtUsbError> for IntelError {
    fn from(e: BtUsbError) -> Self {
        IntelError::Transport(e)
    }
}

/// Parsed Intel version TLV stream (newgen devices).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IntelVersionTlv {
    pub cnvi_top: u32,
    pub cnvr_top: u32,
    pub cnvi_bt: u32,
    pub cnvr_bt: u32,
    pub dev_rev_id: u16,
    pub img_type: u8,
    pub limited_cce: u8,
    pub sbe_type: u8,
    pub min_fw_build_nn: u8,
    pub min_fw_build_cw: u8,
    pub min_fw_build_yy: u8,
}

impl IntelVersionTlv {
    /// Parse a Read Version return-params block: status byte first,
    /// then `{type, len, value}` TLVs (`btintel_parse_version_tlv`).
    pub(crate) fn parse(ret: &[u8]) -> Option<Self> {
        if ret.is_empty() || ret[0] != 0 {
            return None;
        }
        let mut ver = Self::default();
        let mut i = 1;
        while i < ret.len() {
            if i + 2 > ret.len() {
                return None;
            }
            let ty = ret[i];
            let len = ret[i + 1] as usize;
            if i + 2 + len > ret.len() {
                return None;
            }
            let val = &ret[i + 2..i + 2 + len];
            let le32 = |v: &[u8]| -> u32 {
                if v.len() >= 4 {
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
                } else {
                    0
                }
            };
            match ty {
                TLV_CNVI_TOP => ver.cnvi_top = le32(val),
                TLV_CNVR_TOP => ver.cnvr_top = le32(val),
                TLV_CNVI_BT => ver.cnvi_bt = le32(val),
                TLV_CNVR_BT => ver.cnvr_bt = le32(val),
                TLV_DEV_REV_ID => {
                    if val.len() >= 2 {
                        ver.dev_rev_id = u16::from_le_bytes([val[0], val[1]]);
                    }
                }
                TLV_IMAGE_TYPE => ver.img_type = *val.first()?,
                TLV_TIME_STAMP => {
                    if val.len() >= 2 {
                        ver.min_fw_build_cw = val[0];
                        ver.min_fw_build_yy = val[1];
                    }
                }
                TLV_BUILD_NUM => ver.min_fw_build_nn = *val.first()?,
                TLV_LIMITED_CCE => ver.limited_cce = *val.first()?,
                TLV_SBE_TYPE => ver.sbe_type = *val.first()?,
                // TIME_STAMP handled above; BUILD_TYPE / SECURE_BOOT /
                // OTP_LOCK / API_LOCK / DEBUG_LOCK / MIN_FW and unknown
                // tags are informational for this loader.
                TLV_BUILD_TYPE | TLV_SECURE_BOOT | TLV_OTP_LOCK | TLV_API_LOCK | TLV_DEBUG_LOCK
                | TLV_MIN_FW => {}
                _ => {}
            }
            i += 2 + len;
        }
        Some(ver)
    }

    /// Hardware platform packed in `cnvi_bt` (must be 0x37).
    pub(crate) fn hw_platform(&self) -> u8 {
        ((self.cnvi_bt >> 24) & 0xFF) as u8
    }

    /// Hardware variant packed in `cnvi_bt` (0x17 TyP = AX210, …).
    pub(crate) fn hw_variant(&self) -> u8 {
        ((self.cnvi_bt >> 16) & 0x3F) as u8
    }
}

/// Parsed legacy `intel_version` struct (10 bytes incl. status).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IntelVersion {
    pub hw_platform: u8,
    pub hw_variant: u8,
    pub fw_variant: u8,
    pub fw_build_num: u8,
    pub fw_build_ww: u8,
    pub fw_build_yy: u8,
}

impl IntelVersion {
    pub(crate) fn parse(ret: &[u8]) -> Option<Self> {
        if ret.len() < 10 || ret[0] != 0 {
            return None;
        }
        Some(Self {
            hw_platform: ret[1],
            hw_variant: ret[2],
            fw_variant: ret[4],
            fw_build_num: ret[6],
            fw_build_ww: ret[7],
            fw_build_yy: ret[8],
        })
    }
}

/// Parsed `intel_boot_params` (fields this loader uses).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IntelBootParams {
    pub dev_revid: u16,
    pub min_fw_build_nn: u8,
    pub min_fw_build_cw: u8,
    pub min_fw_build_yy: u8,
}

impl IntelBootParams {
    /// Layout (status byte first): status, otp_format, otp_content,
    /// otp_patch, dev_revid(2 LE), secure_boot, key_from_hdr,
    /// key_type, otp_lock, api_lock, debug_lock, otp_bdaddr(6),
    /// min_fw_build_nn, min_fw_build_cw, min_fw_build_yy,
    /// limited_cce, unlocked_state — 23 bytes.
    pub(crate) fn parse(ret: &[u8]) -> Option<Self> {
        if ret.len() < 23 || ret[0] != 0 {
            return None;
        }
        Some(Self {
            dev_revid: u16::from_le_bytes([ret[4], ret[5]]),
            min_fw_build_nn: ret[18],
            min_fw_build_cw: ret[19],
            min_fw_build_yy: ret[20],
        })
    }
}

/// One secure-send fragment of a header: `(fragment_type, offset,
/// len)` into the image.
pub(crate) type HeaderFragment = (u8, usize, usize);

/// Header fragment plan (`btintel_sfi_rsa_header_secure_send` /
/// `btintel_sfi_ecdsa_header_secure_send`).
pub(crate) fn header_fragments(image: &[u8], ecdsa: bool) -> Option<Vec<HeaderFragment>> {
    if ecdsa {
        if image.len() < ECDSA_OFFSET + ECDSA_HEADER_LEN {
            return None;
        }
        Some(alloc::vec![
            (0x00, ECDSA_OFFSET, 128),
            (0x03, ECDSA_OFFSET + 128, 96),
            (0x02, ECDSA_OFFSET + 224, 96),
        ])
    } else {
        if image.len() < RSA_HEADER_LEN {
            return None;
        }
        Some(alloc::vec![
            (0x00, 0, 128),
            (0x03, 128, 256),
            (0x02, 388, 256),
        ])
    }
}

/// Payload fragment plan (`btintel_download_firmware_payload`): walk
/// the image's embedded HCI commands from `offset`, accumulating
/// commands until the accumulated length is 4-byte aligned; each
/// aligned run is one type 0x01 Data fragment. `None` for a
/// malformed image (truncated command, or a trailing unaligned run —
/// Linux rejects those too).
pub(crate) fn payload_fragments(image: &[u8], offset: usize) -> Option<Vec<(usize, usize)>> {
    let mut out = Vec::new();
    let mut run_start = offset;
    let mut run_len = 0usize;
    let mut pos = offset;
    while pos < image.len() {
        if pos + 3 > image.len() {
            return None;
        }
        let plen = image[pos + 2] as usize;
        let cmd_len = 3 + plen;
        if pos + cmd_len > image.len() {
            return None;
        }
        run_len += cmd_len;
        pos += cmd_len;
        if run_len % 4 == 0 {
            out.push((run_start, run_len));
            run_start = pos;
            run_len = 0;
        }
    }
    if run_len != 0 {
        return None;
    }
    Some(out)
}

/// Find the Write Boot Params command embedded in the image payload
/// and extract `(boot_addr, build_num, build_ww, build_yy)`
/// (`btintel_firmware_version`).
pub(crate) fn scan_boot_param(image: &[u8], offset: usize) -> Option<(u32, u8, u8, u8)> {
    let mut pos = offset;
    while pos + 3 <= image.len() {
        let opcode = u16::from_le_bytes([image[pos], image[pos + 1]]);
        let plen = image[pos + 2] as usize;
        if opcode == OP_WRITE_BOOT_PARAMS && plen >= 7 && pos + 3 + 7 <= image.len() {
            let p = &image[pos + 3..];
            return Some((
                u32::from_le_bytes([p[0], p[1], p[2], p[3]]),
                p[4],
                p[5],
                p[6],
            ));
        }
        pos += 3 + plen;
    }
    None
}

/// Validate the CSS headers and decide whether the ECDSA header is
/// the one to send (`btintel_download_fw_tlv`'s checks).
/// Returns `use_ecdsa_header`.
pub(crate) fn validate_css(image: &[u8], hw_variant: u8, sbe_type: u8) -> Result<bool, IntelError> {
    if image.len() < RSA_HEADER_LEN {
        return Err(IntelError::FirmwareInvalid);
    }
    let css_ver = u32::from_le_bytes([
        image[CSS_HEADER_OFFSET],
        image[CSS_HEADER_OFFSET + 1],
        image[CSS_HEADER_OFFSET + 2],
        image[CSS_HEADER_OFFSET + 3],
    ]);
    if css_ver != CSS_VER_RSA {
        return Err(IntelError::FirmwareInvalid);
    }
    if hw_variant <= 0x14 {
        if sbe_type != 0x00 {
            return Err(IntelError::SecureBootEngine);
        }
        return Ok(false);
    }
    if hw_variant >= 0x17 {
        if image.len() < ECDSA_OFFSET + ECDSA_HEADER_LEN || image[ECDSA_OFFSET] != 0x06 {
            return Err(IntelError::FirmwareInvalid);
        }
        let css2 = u32::from_le_bytes([
            image[ECDSA_OFFSET + CSS_HEADER_OFFSET],
            image[ECDSA_OFFSET + CSS_HEADER_OFFSET + 1],
            image[ECDSA_OFFSET + CSS_HEADER_OFFSET + 2],
            image[ECDSA_OFFSET + CSS_HEADER_OFFSET + 3],
        ]);
        if css2 != CSS_VER_ECDSA {
            return Err(IntelError::FirmwareInvalid);
        }
        return Ok(sbe_type == 0x01);
    }
    Err(IntelError::UnsupportedVariant)
}

/// Build one secure-send command's parameters: fragment-type byte +
/// up to [`FRAGMENT_PAYLOAD_MAX`] payload bytes.
pub(crate) fn secure_send_params(fragment_type: u8, chunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + chunk.len());
    out.push(fragment_type);
    out.extend_from_slice(chunk);
    out
}

async fn secure_send(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    fragment_type: u8,
    data: &[u8],
) -> Result<(), IntelError> {
    for chunk in data.chunks(FRAGMENT_PAYLOAD_MAX) {
        btusb::send_command_and_await_complete(
            xhci,
            slot_id,
            interface,
            event_dci,
            OP_SECURE_SEND,
            &secure_send_params(fragment_type, chunk),
        )
        .await?;
    }
    Ok(())
}

/// Select the provisioned firmware pair for this controller: the
/// first `btusb_quirks` Intel pair whose `.sfi` opens. Returns the
/// blob cap and the `.ddc` name (if the pair has one).
fn select_firmware() -> Option<(
    narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    Option<String>,
)> {
    for (sfi, ddc) in btusb_quirks::firmware_paths(Quirk::Intel) {
        let name = format!("intel/{sfi}");
        if let Some(cap) = btusb::firmware_cap(&name) {
            return Some((cap, ddc.map(|d| format!("intel/{d}"))));
        }
    }
    None
}

/// Apply the `.ddc` configuration file, best-effort: each record is
/// `[len][DDC id(2)][value(len-2)]` and goes out as one Write DDC
/// command whose parameter block is the whole record (`len + 1`
/// bytes). Errors are ignored — the device works without DDC.
async fn load_ddc(xhci: &Xhci, slot_id: u8, interface: u8, event_dci: u8, ddc_name: &str) {
    let Some(cap) = btusb::firmware_cap(ddc_name) else {
        return;
    };
    let Ok(view) = narf_firmware::view_of(&cap) else {
        return;
    };
    let bytes = view.bytes;
    let mut pos = 0;
    while pos < bytes.len() {
        let rec_len = bytes[pos] as usize + 1;
        if rec_len < 3 || pos + rec_len > bytes.len() {
            break;
        }
        if btusb::send_command_and_await_complete(
            xhci,
            slot_id,
            interface,
            event_dci,
            OP_WRITE_DDC,
            &bytes[pos..pos + rec_len],
        )
        .await
        .is_err()
        {
            break;
        }
        pos += rec_len;
    }
}

/// Run the Intel firmware setup for a just-configured USB Bluetooth
/// controller. On success the controller is running operational
/// firmware (or already was) and the generic bring-up may proceed.
pub(crate) async fn setup_intel(
    xhci: &Xhci,
    slot_id: u8,
    interface: u8,
    event_dci: u8,
    product_id: u16,
) -> Result<(), IntelError> {
    // Newgen (TLV) parts vs legacy `intel_version` parts, by USB PID
    // — the same split Linux's btusb device table makes.
    let newgen = matches!(product_id, 0x0032 | 0x0033 | 0x0036);

    let (hw_variant, sbe_type, running_build, operational) = if newgen {
        let ret = btusb::send_command_and_await_complete(
            xhci,
            slot_id,
            interface,
            event_dci,
            OP_READ_VERSION,
            &[0xFF],
        )
        .await?;
        let ver = IntelVersionTlv::parse(&ret).ok_or(IntelError::Version)?;
        if ver.hw_platform() != 0x37 {
            return Err(IntelError::UnsupportedPlatform);
        }
        if !matches!(ver.hw_variant(), 0x17 | 0x18 | 0x19 | 0x1B | 0x1C) {
            return Err(IntelError::UnsupportedVariant);
        }
        match ver.img_type {
            IMG_TYPE_OPERATIONAL => (ver.hw_variant(), ver.sbe_type, (0, 0, 0), true),
            IMG_TYPE_BOOTLOADER => {
                if ver.limited_cce != 0x00 {
                    return Err(IntelError::LimitedCce);
                }
                if ver.sbe_type > 0x01 {
                    return Err(IntelError::SecureBootEngine);
                }
                (
                    ver.hw_variant(),
                    ver.sbe_type,
                    (
                        ver.min_fw_build_nn,
                        ver.min_fw_build_cw,
                        ver.min_fw_build_yy,
                    ),
                    false,
                )
            }
            _ => return Err(IntelError::UnsupportedImage),
        }
    } else {
        let ret = btusb::send_command_and_await_complete(
            xhci,
            slot_id,
            interface,
            event_dci,
            OP_READ_VERSION,
            &[],
        )
        .await?;
        let ver = IntelVersion::parse(&ret).ok_or(IntelError::Version)?;
        if ver.hw_platform != 0x37 {
            return Err(IntelError::UnsupportedPlatform);
        }
        if !matches!(ver.hw_variant, 0x0B | 0x0C | 0x11 | 0x12 | 0x13 | 0x14) {
            return Err(IntelError::UnsupportedVariant);
        }
        match ver.fw_variant {
            FW_VARIANT_OPERATIONAL => (ver.hw_variant, 0, (0, 0, 0), true),
            FW_VARIANT_BOOTLOADER => (
                ver.hw_variant,
                0,
                (ver.fw_build_num, ver.fw_build_ww, ver.fw_build_yy),
                false,
            ),
            _ => return Err(IntelError::UnsupportedImage),
        }
    };

    if operational {
        // Already running operational firmware: apply DDC if a pair
        // is provisioned, and finish. Nothing here may fail the bind.
        if let Some((_cap, Some(ddc_name))) = select_firmware() {
            load_ddc(xhci, slot_id, interface, event_dci, &ddc_name).await;
        }
        return Ok(());
    }

    // Boot params (validates the bootloader is responsive and gives
    // the device revision for the transcript).
    let ret = btusb::send_command_and_await_complete(
        xhci,
        slot_id,
        interface,
        event_dci,
        OP_READ_BOOT_PARAMS,
        &[],
    )
    .await?;
    let _boot_params = IntelBootParams::parse(&ret).ok_or(IntelError::BootParams)?;

    let (cap, ddc_name) = select_firmware().ok_or(IntelError::FirmwareUnavailable)?;
    let view = narf_firmware::view_of(&cap).map_err(|_| IntelError::FirmwareUnavailable)?;
    let image = view.bytes;

    let use_ecdsa = validate_css(image, hw_variant, sbe_type)?;
    let payload_offset = if hw_variant >= 0x17 {
        RSA_HEADER_LEN + ECDSA_HEADER_LEN
    } else {
        RSA_HEADER_LEN
    };

    // Skip the download when the image's build is already running;
    // the embedded boot address is still needed for the boot reset.
    let embedded = scan_boot_param(image, payload_offset);
    let already_loaded = matches!(
        embedded,
        Some((_, num, ww, yy)) if (num, ww, yy) == running_build && running_build != (0, 0, 0)
    );
    let boot_param = embedded.map(|(addr, _, _, _)| addr).unwrap_or(0);

    if !already_loaded {
        let fragments = header_fragments(image, use_ecdsa).ok_or(IntelError::FirmwareInvalid)?;
        for (fragment_type, offset, len) in fragments {
            secure_send(
                xhci,
                slot_id,
                interface,
                event_dci,
                fragment_type,
                &image[offset..offset + len],
            )
            .await?;
        }
        let payload =
            payload_fragments(image, payload_offset).ok_or(IntelError::FirmwareInvalid)?;
        for (offset, len) in payload {
            secure_send(
                xhci,
                slot_id,
                interface,
                event_dci,
                0x01,
                &image[offset..offset + len],
            )
            .await?;
        }
    }

    // Boot the downloaded image (Intel Reset with a boot address).
    let mut params = [0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
    params[4..8].copy_from_slice(&boot_param.to_le_bytes());
    btusb::send_command_and_await_complete(
        xhci,
        slot_id,
        interface,
        event_dci,
        OP_INTEL_RESET,
        &params,
    )
    .await?;

    if let Some(ddc_name) = &ddc_name {
        load_ddc(xhci, slot_id, interface, event_dci, ddc_name).await;
    }

    // The boot emits an asynchronous vendor bootup event (0xFF/0x02);
    // drain it (and anything else queued) so the generic bring-up's
    // first Command Complete is the next event read.
    btusb::drain_pending_events(xhci, slot_id, event_dci, 200).await;
    Ok(())
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn version_tlv_parses_newgen_fields() {
        // status + CNVI_BT(0x3717_0000) + IMAGE_TYPE(1) +
        // LIMITED_CCE(0) + SBE_TYPE(1) + BUILD_NUM(nn=0x35) +
        // TIME_STAMP(cw=0x28, yy=0x18).
        let mut ret = alloc::vec![0u8];
        ret.extend_from_slice(&[TLV_CNVI_BT, 4]);
        ret.extend_from_slice(&0x3717_0000u32.to_le_bytes());
        ret.extend_from_slice(&[TLV_IMAGE_TYPE, 1, 0x01]);
        ret.extend_from_slice(&[TLV_LIMITED_CCE, 1, 0x00]);
        ret.extend_from_slice(&[TLV_SBE_TYPE, 1, 0x01]);
        ret.extend_from_slice(&[TLV_BUILD_NUM, 4]);
        ret.extend_from_slice(&0x35u32.to_le_bytes());
        ret.extend_from_slice(&[TLV_TIME_STAMP, 2, 0x28, 0x18]);
        let ver = IntelVersionTlv::parse(&ret).unwrap();
        assert_eq!(ver.hw_platform(), 0x37);
        assert_eq!(ver.hw_variant(), 0x17);
        assert_eq!(ver.img_type, 0x01);
        assert_eq!(ver.sbe_type, 0x01);
        assert_eq!(ver.min_fw_build_nn, 0x35);
        assert_eq!(ver.min_fw_build_cw, 0x28);
        assert_eq!(ver.min_fw_build_yy, 0x18);
    }

    #[test]
    fn header_fragment_plans_match_linux_offsets() {
        let image = alloc::vec![0u8; 2048];
        let rsa = header_fragments(&image, false).unwrap();
        assert_eq!(rsa, [(0x00, 0, 128), (0x03, 128, 256), (0x02, 388, 256)]);
        let ecdsa = header_fragments(&image, true).unwrap();
        assert_eq!(ecdsa, [(0x00, 644, 128), (0x03, 772, 96), (0x02, 868, 96)]);
    }

    #[test]
    fn payload_fragments_group_on_aligned_boundaries() {
        // Two commands: 11 bytes (opcode + plen 8) then 5 bytes
        // (plen 2) -> one aligned 16-byte Data fragment. A trailing
        // 3-byte command leaves an unaligned run -> malformed.
        let mut image = alloc::vec![0u8; 964];
        image[964 - 16] = 0x0E;
        image[964 - 15] = 0xFC;
        image[964 - 14] = 8;
        image[964 - 5] = 0x00;
        image[964 - 4] = 0x00;
        image[964 - 3] = 2;
        let frags = payload_fragments(&image, 948).unwrap();
        assert_eq!(frags, [(948, 16)]);
        let mut bad = image.clone();
        bad.extend_from_slice(&[0x00, 0x00, 0x00]);
        assert_eq!(payload_fragments(&bad, 948), None);
    }

    #[test]
    fn scan_boot_param_finds_embedded_command() {
        let mut image = alloc::vec![0u8; 1024];
        // Write Boot Params at offset 964: boot_addr 0x00021000,
        // build 53 / week 40 / year 24.
        image[964] = 0x0E;
        image[965] = 0xFC;
        image[966] = 7;
        image[967..971].copy_from_slice(&0x0002_1000u32.to_le_bytes());
        image[971] = 53;
        image[972] = 40;
        image[973] = 24;
        assert_eq!(
            scan_boot_param(&image, 964),
            Some((0x0002_1000, 53, 40, 24))
        );
        let blank = alloc::vec![0u8; 1024];
        assert_eq!(scan_boot_param(&blank, 964), None);
    }

    #[test]
    fn secure_send_params_prefix_fragment_type() {
        let params = secure_send_params(0x01, &[0xAA; 4]);
        assert_eq!(params.len(), 5);
        assert_eq!(params[0], 0x01);
        assert!(params[1..].iter().all(|b| *b == 0xAA));
    }
}
