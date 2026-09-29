//! Intel Bluetooth firmware download over the PCIe DMA transport.
//!
//! The controller comes out of reset running a ROM bootloader that
//! speaks HCI but implements almost nothing: it answers Intel Read
//! Version (`0xFC05`), accepts signed firmware fragments via Intel
//! Secure Send (`0xFC09`), and reboots into the downloaded image on
//! Intel Reset (`0xFC01`). Everything a Bluetooth stack actually
//! wants — Read Local Version, the LE commands, an event mask worth
//! setting — only exists once operational firmware is running.
//!
//! Panther Lake (CNVi Scorpius Peak, `hw_variant` 0x1f) boots in two
//! stages. The ROM loads an *intermediate loader* (`-iml.sfi`), which
//! reboots and reports `img_type == IML`; the IML then loads the
//! operational image (`-<fw_id>.sfi`) and reboots again into
//! `img_type == OP`. Each stage is the same download-then-reset
//! dance, which is why [`download_image`] and [`boot`] are separate
//! and [`setup`] runs them twice.
//!
//! ## Image layout
//!
//! An `.sfi` is a signed container: a 644-byte RSA CSS header, then
//! (on `hw_variant >= 0x17`) a 320-byte ECDSA CSS header, then the
//! payload — a flat stream of HCI commands the bootloader replays.
//! Which header gets sent is decided by `sbe_type` from the version
//! TLV, not by the file: both are present, and the secure-boot engine
//! the part was fused for picks one. The payload is always sent from
//! `RSA_HEADER_LEN + ECDSA_HEADER_LEN`.
//!
//! ## Sources
//!
//! Linux `drivers/bluetooth/btintel.c` (GPL-2.0, consulted per the
//! NARF 2026-05-20 relicense to GPL-2.0-or-later):
//! `btintel_read_version_tlv`, `btintel_parse_version_tlv`,
//! `btintel_get_fw_name_tlv`, `btintel_download_fw_tlv`,
//! `btintel_sfi_{rsa,ecdsa}_header_secure_send`,
//! `btintel_download_firmware_payload`, `btintel_secure_send`,
//! `btintel_boot`, `btintel_bootloader_setup_tlv`,
//! `btintel_load_ddc_config`; and `btintel_pcie.c`
//! `btintel_pcie_setup_internal`, `btintel_pcie_recv_event`.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareRegistry;

use super::rings::{HCI_CMD_PKT, HCI_EVT_PKT};
use super::{cnvx_top_step, cnvx_top_type, BtIntelPcie, BtPcieError};

// ── HCI opcodes ─────────────────────────────────────────────────────

/// `BTINTEL_HCI_OP_RESET` — Intel Reset. Reboots the controller into
/// either the current image or a specified boot address.
pub const OP_INTEL_RESET: u16 = 0xFC01;
/// Intel Read Version. With a single `0xFF` parameter the reply is a
/// TLV stream rather than the legacy fixed struct.
pub const OP_INTEL_READ_VERSION: u16 = 0xFC05;
/// Intel Secure Send — one signed firmware fragment per command.
pub const OP_INTEL_SECURE_SEND: u16 = 0xFC09;
/// Intel Set DSBR — sets the drive strength of the BRI response.
pub const OP_INTEL_SET_DSBR: u16 = 0xFC0A;
/// Intel Set Event Mask — enables the vendor events worth having.
pub const OP_INTEL_SET_EVENT_MASK: u16 = 0xFC52;
/// Intel Write DDC — one device-configuration record per command.
pub const OP_INTEL_WRITE_DDC: u16 = 0xFC8B;
/// `CMD_WRITE_BOOT_PARAMS` — not sent by the host. This opcode
/// appears *inside* the firmware payload and carries the per-SKU boot
/// address the subsequent Intel Reset must use.
pub const OP_WRITE_BOOT_PARAMS: u16 = 0xFC0E;

// ── HCI event framing ───────────────────────────────────────────────

/// Event packets are `[code, plen, params…]`.
pub const EVT_HDR_LEN: usize = 2;
/// Command Complete (Core spec v5.3 Vol 4 Part E §7.7.14): params are
/// `[ncmd, opcode_lo, opcode_hi, return_params…]`.
pub const EVT_CMD_COMPLETE: u8 = 0x0E;
/// Command Status (§7.7.15): params are `[status, ncmd, op_lo, op_hi]`.
pub const EVT_CMD_STATUS: u8 = 0x0F;
/// Vendor-specific event: params are `[subcode, …]`.
pub const EVT_VENDOR: u8 = 0xFF;
/// Vendor subcode 0x02 — the bootup notification the freshly booted
/// image sends unprompted.
pub const VENDOR_BOOTUP: u8 = 0x02;
/// Vendor subcode 0x06 — the secure-send result, sent once after the
/// last firmware fragment has been verified.
pub const VENDOR_SECURE_SEND_RESULT: u8 = 0x06;

/// `struct intel_bootup` is six bytes.
pub const BOOTUP_EVT_LEN: usize = 6;
/// `struct intel_secure_send_result` is four bytes.
pub const SECURE_SEND_RESULT_LEN: usize = 4;

/// The largest payload one Secure Send carries. The command's own
/// parameter byte budget is 255; one byte goes to the fragment type
/// and Linux caps the rest at 252.
pub const SECURE_SEND_MAX_FRAGMENT: usize = 252;

/// Fragment type 0x00 — Init, the CSS header.
pub const FRAG_INIT: u8 = 0x00;
/// Fragment type 0x01 — firmware data.
pub const FRAG_DATA: u8 = 0x01;
/// Fragment type 0x02 — signature.
pub const FRAG_SIGN: u8 = 0x02;
/// Fragment type 0x03 — public key.
pub const FRAG_PKEY: u8 = 0x03;

// ── Image container geometry ────────────────────────────────────────

/// Length of the RSA CSS header that opens every `.sfi`.
pub const RSA_HEADER_LEN: usize = 644;
/// Length of the ECDSA CSS header that follows it on `hw_variant >= 0x17`.
pub const ECDSA_HEADER_LEN: usize = 320;
/// Byte offset of the CSS header version word within a CSS header.
pub const CSS_HEADER_OFFSET: usize = 8;
/// Offset of the ECDSA CSS header — immediately after the RSA one.
pub const ECDSA_OFFSET: usize = RSA_HEADER_LEN;
/// Where the replayable HCI command stream starts in a dual-header
/// image.
pub const PAYLOAD_OFFSET: usize = RSA_HEADER_LEN + ECDSA_HEADER_LEN;

/// CSS header version marking an RSA-signed header.
pub const RSA_HEADER_VER: u32 = 0x0001_0000;
/// CSS header version marking an ECDSA-signed header.
pub const ECDSA_HEADER_VER: u32 = 0x0002_0000;

/// The marker byte Linux requires at [`ECDSA_OFFSET`] before it will
/// believe an ECDSA header follows the RSA one.
pub const ECDSA_PRESENT_MARKER: u8 = 0x06;

// ── Image / platform identity ───────────────────────────────────────

/// `BTINTEL_IMG_BOOTLOADER` — the ROM bootloader is running.
pub const IMG_BOOTLOADER: u8 = 0x01;
/// `BTINTEL_IMG_IML` — the intermediate loader is running.
pub const IMG_IML: u8 = 0x02;
/// `BTINTEL_IMG_OP` — operational firmware is running.
pub const IMG_OP: u8 = 0x03;

/// The only hardware platform value btintel accepts.
pub const HW_PLATFORM_INTEL: u8 = 0x37;

/// Hardware variants that take the TLV firmware-loading path:
/// BlazarI, ScP, ScP2, ScP2F, BlazarIW. The MS-03's Panther Lake
/// controller is `0x1f` (ScP).
pub const SUPPORTED_HW_VARIANTS: &[u8] = &[0x1e, 0x1f, 0x20, 0x21, 0x22];

/// The first hardware variant that ships an intermediate loader, and
/// so uses the `-iml` firmware name while in the ROM bootloader.
pub const FIRST_IML_HW_VARIANT: u8 = 0x1e;

/// `INTEL_HW_PLATFORM` — bits 15:8 of `cnvi_bt`.
pub const fn hw_platform(cnvi_bt: u32) -> u8 {
    ((cnvi_bt & 0x0000_FF00) >> 8) as u8
}

/// `INTEL_HW_VARIANT` — bits 21:16 of `cnvi_bt`.
pub const fn hw_variant(cnvi_bt: u32) -> u8 {
    ((cnvi_bt & 0x003F_0000) >> 16) as u8
}

/// `INTEL_CNVX_TOP_PACK_SWAB` — pack a top type and stepping into the
/// byte-swapped 16-bit form that appears in firmware filenames.
///
/// The swap is why the MS-03's CNVi type `0xA00` stepping `0` prints
/// as `00a0` rather than `a000`.
pub const fn cnvx_pack_swab(top_type: u16, step: u8) -> u16 {
    let packed = (top_type << 4) | (step as u16 & 0xF);
    packed.rotate_left(8)
}

// ── DSBR ────────────────────────────────────────────────────────────
//
// The BRI (Bluetooth Radio Interface) response drive strength is a
// board-level electrical parameter: the platform measures it and
// publishes it in a UEFI variable, and the host has to hand it to the
// controller. Linux treats a failure here as fatal, and the MS-03's
// firmware does need it — Scorpius Peak in its intermediate loader is
// one of the cases `btintel_set_dsbr` covers.

/// `BTINTEL_HWID_GAP` — Gale Peak2, Meteor Lake.
pub const HWID_GAP: u8 = 0x1C;
/// `BTINTEL_HWID_BZRU` — BlazarU, Meteor Lake.
pub const HWID_BZRU: u8 = 0x1D;
/// `BTINTEL_HWID_BZRI` — BlazarI, Lunar Lake.
pub const HWID_BZRI: u8 = 0x1E;
/// `BTINTEL_HWID_SCP` — Scorpius Peak, Panther Lake. The MS-03.
pub const HWID_SCP: u8 = 0x1F;
/// `BTINTEL_HWID_SCP2` — Scorpius Peak2, Nova Lake.
pub const HWID_SCP2: u8 = 0x20;
/// `BTINTEL_HWID_SCP2F` — Scorpius Peak2-F, Nova Lake.
pub const HWID_SCP2F: u8 = 0x21;
/// `BTINTEL_HWID_BZRIW` — BlazarIW, Wildcat Lake.
pub const HWID_BZRIW: u8 = 0x22;

/// `BTINTEL_EFI_DSBR` — the UEFI variable carrying the DSBR setting.
pub const DSBR_EFI_VAR: &str = "UefiCnvCommonDSBR";

/// Vendor GUID for [`DSBR_EFI_VAR`].
pub const DSBR_EFI_GUID: narf_efi::runtime::EfiGuid = narf_efi::runtime::EfiGuid::new(
    0xe65d_8884,
    0xd4af,
    0x4b20,
    [0x8d, 0x03, 0x77, 0x2e, 0xcc, 0x3d, 0xa5, 0x31],
);

/// `struct btintel_dsbr { u8 header; u32 dsbr; } __packed` — five
/// bytes, and a variable of any other size is not this structure.
pub const DSBR_EFI_VAR_LEN: usize = 5;

/// Decode the DSBR word out of the UEFI variable's payload.
///
/// This is the variable body only: on Linux the four attribute bytes
/// that `efivarfs` prepends to the file are not part of it.
pub fn parse_dsbr_variable(data: &[u8]) -> Option<u32> {
    if data.len() != DSBR_EFI_VAR_LEN {
        return None;
    }
    Some(le32(&data[1..]))
}

/// Split the DSBR word into the two command parameters: bit 0 is the
/// enable flag and bits 7:4 are the value.
pub const fn dsbr_command_params(dsbr: u32) -> [u8; 2] {
    [(dsbr & 1) as u8, ((dsbr >> 4) & 0xF) as u8]
}

/// Whether this controller needs the DSBR command, given the image it
/// is currently running.
///
/// Mirrors the switch in `btintel_set_dsbr`, specialised to the PCIe
/// transport: the Gale Peak2 / BlazarU case is USB-only and so never
/// fires here.
pub const fn dsbr_required(variant: u8, img_type: u8, cnvi_step: u8) -> bool {
    match variant {
        HWID_BZRI | HWID_BZRIW => img_type == IMG_IML && cnvi_step == 0x01,
        // Gale Peak2 and BlazarU want it in the operational image over
        // USB only; over PCIe there is nothing to send.
        HWID_GAP | HWID_BZRU => false,
        HWID_SCP => img_type == IMG_IML,
        // Scorpius Peak2 onwards, PCIe, intermediate loader.
        v => v >= HWID_SCP2 && img_type == IMG_IML,
    }
}

// ── Version TLV ─────────────────────────────────────────────────────

/// TLV record types carried by Intel Read Version. Numbering runs
/// consecutively from `INTEL_TLV_CNVI_TOP` except for `FW_ID`.
pub const TLV_CNVI_TOP: u8 = 0x10;
/// CNVr top identity word.
pub const TLV_CNVR_TOP: u8 = 0x11;
/// CNVi Bluetooth identity word — carries platform and hw variant.
pub const TLV_CNVI_BT: u8 = 0x12;
/// CNVr Bluetooth identity word.
pub const TLV_CNVR_BT: u8 = 0x13;
/// Device revision id.
pub const TLV_DEV_REV_ID: u8 = 0x16;
/// Which image is currently running — one of the `IMG_*` values.
pub const TLV_IMAGE_TYPE: u8 = 0x1C;
/// Build timestamp (calendar week and year).
pub const TLV_TIME_STAMP: u8 = 0x1D;
/// Build type.
pub const TLV_BUILD_TYPE: u8 = 0x1E;
/// Build number.
pub const TLV_BUILD_NUM: u8 = 0x1F;
/// Secure-boot enable.
pub const TLV_SECURE_BOOT: u8 = 0x28;
/// OTP lock state.
pub const TLV_OTP_LOCK: u8 = 0x2A;
/// API lock state.
pub const TLV_API_LOCK: u8 = 0x2B;
/// Debug lock state.
pub const TLV_DEBUG_LOCK: u8 = 0x2C;
/// Minimum acceptable firmware build (`nn`, `cw`, `yy`).
pub const TLV_MIN_FW: u8 = 0x2D;
/// Limited-CCE state.
pub const TLV_LIMITED_CCE: u8 = 0x2E;
/// Secure-boot engine type — selects the RSA or ECDSA header.
pub const TLV_SBE_TYPE: u8 = 0x2F;
/// Bluetooth device address fused into OTP.
pub const TLV_OTP_BDADDR: u8 = 0x30;
/// Firmware git revision.
pub const TLV_GIT_SHA1: u8 = 0x32;
/// Firmware id string — the operational image's filename stem.
pub const TLV_FW_ID: u8 = 0x50;

/// Secure-boot engine using the RSA CSS header.
pub const SBE_RSA: u8 = 0x00;
/// Secure-boot engine using the ECDSA CSS header.
pub const SBE_ECDSA: u8 = 0x01;

/// `BTINTEL_FWID_MAXLEN` — the firmware id is at most 64 bytes.
pub const FWID_MAXLEN: usize = 64;

/// The minimum length a TLV of this type must carry to be usable.
///
/// Mirrors `btintel_version_tlv_min_len`. This is an input-validation
/// guard on device-supplied data: without it a truncated record would
/// silently decode as a short read of the next record's bytes.
pub const fn tlv_min_len(ty: u8) -> usize {
    match ty {
        TLV_CNVI_TOP | TLV_CNVR_TOP | TLV_CNVI_BT | TLV_CNVR_BT | TLV_BUILD_NUM | TLV_GIT_SHA1 => 4,
        TLV_DEV_REV_ID | TLV_TIME_STAMP => 2,
        TLV_IMAGE_TYPE | TLV_BUILD_TYPE | TLV_SECURE_BOOT | TLV_OTP_LOCK | TLV_API_LOCK
        | TLV_DEBUG_LOCK | TLV_LIMITED_CCE | TLV_SBE_TYPE => 1,
        TLV_MIN_FW => 3,
        TLV_OTP_BDADDR => 6,
        _ => 0,
    }
}

/// The fields of an Intel Read Version TLV reply this driver uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntelVersionTlv {
    /// CNVi top identity — type and stepping for the firmware name.
    pub cnvi_top: u32,
    /// CNVr top identity — type and stepping for the firmware name.
    pub cnvr_top: u32,
    /// CNVi Bluetooth identity — hardware platform and variant.
    pub cnvi_bt: u32,
    /// CNVr Bluetooth identity.
    pub cnvr_bt: u32,
    /// Device revision id.
    pub dev_rev_id: u16,
    /// Which image is running: [`IMG_BOOTLOADER`], [`IMG_IML`] or
    /// [`IMG_OP`].
    pub img_type: u8,
    /// Build timestamp, calendar week in the low byte.
    pub timestamp: u16,
    /// Build type.
    pub build_type: u8,
    /// Build number.
    pub build_num: u32,
    /// Secure boot enabled.
    pub secure_boot: u8,
    /// OTP lock state.
    pub otp_lock: u8,
    /// API lock state.
    pub api_lock: u8,
    /// Debug lock state.
    pub debug_lock: u8,
    /// Minimum firmware build number.
    pub min_fw_build_nn: u8,
    /// Minimum firmware build calendar week.
    pub min_fw_build_cw: u8,
    /// Minimum firmware build year.
    pub min_fw_build_yy: u8,
    /// Limited-CCE state.
    pub limited_cce: u8,
    /// Secure-boot engine type: [`SBE_RSA`] or [`SBE_ECDSA`].
    pub sbe_type: u8,
    /// Bluetooth address fused into OTP; all-zero means unconfigured.
    pub otp_bd_addr: [u8; 6],
    /// Firmware git revision.
    pub git_sha1: u32,
    /// Firmware id string, empty when the TLV was absent.
    pub fw_id: String,
}

impl IntelVersionTlv {
    /// Hardware platform from `cnvi_bt`.
    pub const fn hw_platform(&self) -> u8 {
        hw_platform(self.cnvi_bt)
    }

    /// Hardware variant from `cnvi_bt`.
    pub const fn hw_variant(&self) -> u8 {
        hw_variant(self.cnvi_bt)
    }

    /// `true` when the OTP carries no Bluetooth address, which Linux
    /// reports as an unconfigured controller.
    pub fn bdaddr_unconfigured(&self) -> bool {
        self.otp_bd_addr == [0u8; 6]
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Why a firmware download did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// The underlying DMA transport failed.
    Transport(BtPcieError),
    /// No event arrived before the deadline.
    Timeout,
    /// A command completed with a non-zero HCI status.
    CommandFailed {
        /// The opcode that failed.
        opcode: u16,
        /// The HCI status byte it came back with.
        status: u8,
    },
    /// An event was shorter than its own header claims.
    MalformedEvent,
    /// The Read Version TLV stream did not decode.
    MalformedVersion,
    /// The firmware registry has no blob under this name.
    FirmwareMissing(String),
    /// The image is too short to contain its headers.
    ImageTooShort(usize),
    /// The CSS header version word is not one this driver handles.
    BadCssVersion(u32),
    /// `hw_variant >= 0x17` but the ECDSA marker byte was absent.
    MissingEcdsaHeader,
    /// The version TLV reported a secure-boot engine this driver does
    /// not know how to feed.
    UnsupportedSbeType(u8),
    /// The payload's embedded HCI command stream does not divide into
    /// 4-byte-aligned fragments that end exactly at the last byte.
    MalformedPayload,
    /// The controller reported a firmware-verification failure.
    SecureSendFailed(u8),
    /// The image carried no `Intel_Write_Boot_Params`, so there is no
    /// address to reboot into.
    NoBootAddress,
    /// The controller is not one this path supports.
    UnsupportedController {
        /// `INTEL_HW_PLATFORM(cnvi_bt)`.
        platform: u8,
        /// `INTEL_HW_VARIANT(cnvi_bt)`.
        variant: u8,
    },
}

impl From<BtPcieError> for FwError {
    fn from(e: BtPcieError) -> Self {
        FwError::Transport(e)
    }
}

// ── Pure decode helpers ─────────────────────────────────────────────

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Decode an Intel Read Version TLV stream.
///
/// `tlvs` is the Command Complete return parameters *after* the
/// status byte, matching the `skb_pull(skb, 1)` in
/// `btintel_parse_version_tlv`.
pub fn parse_version_tlv(tlvs: &[u8]) -> Result<IntelVersionTlv, FwError> {
    let mut v = IntelVersionTlv::default();
    let mut rest = tlvs;
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err(FwError::MalformedVersion);
        }
        let ty = rest[0];
        let len = rest[1] as usize;
        if rest.len() < 2 + len {
            return Err(FwError::MalformedVersion);
        }
        let val = &rest[2..2 + len];
        if len < tlv_min_len(ty) {
            return Err(FwError::MalformedVersion);
        }
        match ty {
            TLV_CNVI_TOP => v.cnvi_top = le32(val),
            TLV_CNVR_TOP => v.cnvr_top = le32(val),
            TLV_CNVI_BT => v.cnvi_bt = le32(val),
            TLV_CNVR_BT => v.cnvr_bt = le32(val),
            TLV_DEV_REV_ID => v.dev_rev_id = le16(val),
            TLV_IMAGE_TYPE => v.img_type = val[0],
            TLV_TIME_STAMP => {
                // Linux keeps both readings: the 16-bit timestamp and
                // the same two bytes as calendar week / year, which
                // are only meaningful for an operational image.
                v.min_fw_build_cw = val[0];
                v.min_fw_build_yy = val[1];
                v.timestamp = le16(val);
            }
            TLV_BUILD_TYPE => v.build_type = val[0],
            TLV_BUILD_NUM => {
                v.min_fw_build_nn = val[0];
                v.build_num = le32(val);
            }
            TLV_SECURE_BOOT => v.secure_boot = val[0],
            TLV_OTP_LOCK => v.otp_lock = val[0],
            TLV_API_LOCK => v.api_lock = val[0],
            TLV_DEBUG_LOCK => v.debug_lock = val[0],
            TLV_MIN_FW => {
                v.min_fw_build_nn = val[0];
                v.min_fw_build_cw = val[1];
                v.min_fw_build_yy = val[2];
            }
            TLV_LIMITED_CCE => v.limited_cce = val[0],
            TLV_SBE_TYPE => v.sbe_type = val[0],
            TLV_OTP_BDADDR => v.otp_bd_addr.copy_from_slice(&val[..6]),
            TLV_GIT_SHA1 => v.git_sha1 = le32(val),
            TLV_FW_ID => {
                let take = core::cmp::min(len, FWID_MAXLEN);
                if let Ok(s) = core::str::from_utf8(&val[..take]) {
                    v.fw_id = String::from(s.trim_end_matches('\0'));
                }
            }
            // Everything else is informational; skip it the way
            // `btintel_parse_version_tlv`'s default arm does.
            _ => {}
        }
        rest = &rest[2 + len..];
    }
    Ok(v)
}

/// Derive the firmware filename for `ver`.
///
/// Mirrors `btintel_get_fw_name_tlv`. On the MS-03 the ROM bootloader
/// reports CNVi top `0xA00` step 0 and CNVr top `0xA10` step 1, which
/// yields `intel/ibt-00a0-01a1-iml.sfi`.
pub fn fw_name(ver: &IntelVersionTlv, suffix: &str) -> String {
    let cnvi = cnvx_pack_swab(cnvx_top_type(ver.cnvi_top), cnvx_top_step(ver.cnvi_top));
    let cnvr = cnvx_pack_swab(cnvx_top_type(ver.cnvr_top), cnvx_top_step(ver.cnvr_top));

    if ver.hw_variant() >= FIRST_IML_HW_VARIANT {
        // Only parts with an intermediate loader use the `-iml` name,
        // and only while the ROM bootloader is the thing asking.
        if ver.img_type == IMG_BOOTLOADER {
            return format!("intel/ibt-{cnvi:04x}-{cnvr:04x}-iml.{suffix}");
        }
        if !ver.fw_id.is_empty() {
            return format!("intel/ibt-{cnvi:04x}-{cnvr:04x}-{}.{suffix}", ver.fw_id);
        }
    }
    format!("intel/ibt-{cnvi:04x}-{cnvr:04x}.{suffix}")
}

/// Derive the intermediate-loader filename regardless of `img_type`.
///
/// Mirrors `btintel_get_iml_tlv`, used when an already-operational
/// controller needs its IML version compared against what is on disk.
pub fn iml_name(ver: &IntelVersionTlv, suffix: &str) -> String {
    let cnvi = cnvx_pack_swab(cnvx_top_type(ver.cnvi_top), cnvx_top_step(ver.cnvi_top));
    let cnvr = cnvx_pack_swab(cnvx_top_type(ver.cnvr_top), cnvx_top_step(ver.cnvr_top));
    format!("intel/ibt-{cnvi:04x}-{cnvr:04x}-iml.{suffix}")
}

/// The boot parameters embedded in a firmware image.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BootParams {
    /// Address the subsequent Intel Reset must boot from.
    pub boot_addr: u32,
    /// Build number of the image carrying this record.
    pub fw_build_num: u8,
    /// Build calendar week.
    pub fw_build_ww: u8,
    /// Build year.
    pub fw_build_yy: u8,
}

/// Find the `Intel_Write_Boot_Params` record inside a firmware image.
///
/// Each SKU boots from a different address, and that address is not
/// in any header — it is a command in the payload. Linux walks the
/// whole file from byte zero as if it were an HCI command stream
/// (`btintel_firmware_version`), which strides through the CSS header
/// as garbage before landing on the real record; this reproduces that
/// walk exactly, because a different walk finds a different record.
pub fn scan_boot_params(image: &[u8]) -> Option<BootParams> {
    let mut i = 0usize;
    while i + 3 <= image.len() {
        let opcode = le16(&image[i..]);
        let plen = image[i + 2] as usize;
        if opcode == OP_WRITE_BOOT_PARAMS {
            if i + 3 + 7 > image.len() {
                return None;
            }
            let p = &image[i + 3..];
            return Some(BootParams {
                boot_addr: le32(p),
                fw_build_num: p[4],
                fw_build_ww: p[5],
                fw_build_yy: p[6],
            });
        }
        i += 3 + plen;
    }
    None
}

/// One Secure Send fragment: a type byte and a slice of the image.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// One of the `FRAG_*` constants.
    pub kind: u8,
    /// Byte offset into the image.
    pub offset: usize,
    /// Fragment length in bytes.
    pub len: usize,
}

/// Build the header fragments for `image` given the controller's
/// secure-boot engine type.
///
/// Both CSS headers are present in the file; `sbe_type` decides which
/// one the part will accept. Getting this backwards does not fail
/// loudly on the wire — the bootloader rejects the signature much
/// later — so the choice is validated here.
pub fn plan_header_fragments(
    image: &[u8],
    hw_variant_id: u8,
    sbe_type: u8,
) -> Result<Vec<Fragment>, FwError> {
    if image.len() < RSA_HEADER_LEN {
        return Err(FwError::ImageTooShort(image.len()));
    }

    let css_ver = le32(&image[CSS_HEADER_OFFSET..]);
    if css_ver != RSA_HEADER_VER {
        return Err(FwError::BadCssVersion(css_ver));
    }

    if hw_variant_id <= 0x14 {
        if sbe_type != SBE_RSA {
            return Err(FwError::UnsupportedSbeType(sbe_type));
        }
        return Ok(rsa_header_fragments());
    }

    // hw_variant >= 0x17: an ECDSA header must follow the RSA one.
    if image.len() < PAYLOAD_OFFSET {
        return Err(FwError::ImageTooShort(image.len()));
    }
    if image[ECDSA_OFFSET] != ECDSA_PRESENT_MARKER {
        return Err(FwError::MissingEcdsaHeader);
    }
    let ecdsa_ver = le32(&image[ECDSA_OFFSET + CSS_HEADER_OFFSET..]);
    if ecdsa_ver != ECDSA_HEADER_VER {
        return Err(FwError::BadCssVersion(ecdsa_ver));
    }

    match sbe_type {
        SBE_RSA => Ok(rsa_header_fragments()),
        SBE_ECDSA => Ok(ecdsa_header_fragments()),
        other => Err(FwError::UnsupportedSbeType(other)),
    }
}

/// `btintel_sfi_rsa_header_secure_send`: 128-byte CSS header, then a
/// 256-byte public key, then a 256-byte signature.
fn rsa_header_fragments() -> Vec<Fragment> {
    alloc::vec![
        Fragment {
            kind: FRAG_INIT,
            offset: 0,
            len: 128
        },
        Fragment {
            kind: FRAG_PKEY,
            offset: 128,
            len: 256
        },
        Fragment {
            kind: FRAG_SIGN,
            offset: 388,
            len: 256
        },
    ]
}

/// `btintel_sfi_ecdsa_header_secure_send`: the same three fragments
/// taken from the ECDSA header, with 96-byte key and signature.
fn ecdsa_header_fragments() -> Vec<Fragment> {
    alloc::vec![
        Fragment {
            kind: FRAG_INIT,
            offset: ECDSA_OFFSET,
            len: 128
        },
        Fragment {
            kind: FRAG_PKEY,
            offset: ECDSA_OFFSET + 128,
            len: 96
        },
        Fragment {
            kind: FRAG_SIGN,
            offset: ECDSA_OFFSET + 224,
            len: 96
        },
    ]
}

/// Split the payload into Secure Send data fragments.
///
/// The payload is a stream of HCI commands. A fragment may only end
/// on a 4-byte boundary, so commands are accumulated until the run
/// length is a multiple of four — the image is built with `Intel_NOP`
/// padding so this always converges. A run that never aligns, or one
/// that overruns the image, means the payload is not what it claims.
pub fn plan_payload_fragments(image: &[u8], start: usize) -> Result<Vec<Fragment>, FwError> {
    if start > image.len() {
        return Err(FwError::ImageTooShort(image.len()));
    }
    let mut out = Vec::new();
    let mut base = start;
    let mut run = 0usize;
    while base + run < image.len() {
        let cmd = base + run;
        if cmd + 3 > image.len() {
            return Err(FwError::MalformedPayload);
        }
        let plen = image[cmd + 2] as usize;
        run += 3 + plen;
        if base + run > image.len() {
            return Err(FwError::MalformedPayload);
        }
        if run % 4 == 0 {
            out.push(Fragment {
                kind: FRAG_DATA,
                offset: base,
                len: run,
            });
            base += run;
            run = 0;
        }
    }
    if run != 0 {
        return Err(FwError::MalformedPayload);
    }
    Ok(out)
}

/// Split a DDC file into Intel Write DDC command parameters.
///
/// Each record is `[len, id_lo, id_hi, value…]` where `len` counts
/// everything after itself; the command parameter is the whole
/// record including the length byte.
pub fn plan_ddc_records(image: &[u8]) -> Result<Vec<Fragment>, FwError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < image.len() {
        let plen = image[i] as usize + 1;
        if i + plen > image.len() {
            return Err(FwError::MalformedPayload);
        }
        out.push(Fragment {
            kind: FRAG_DATA,
            offset: i,
            len: plen,
        });
        i += plen;
    }
    Ok(out)
}

// ── Transport-side HCI exchange ─────────────────────────────────────

/// How long to wait for a Command Complete.
pub const CMD_TIMEOUT_MS: u64 = 2_000;
/// How long to wait for the secure-send result after the last
/// fragment. Linux allows 5 s; the MS-03's ROM takes ~38 ms.
pub const DOWNLOAD_TIMEOUT_MS: u64 = 5_000;
/// How long to wait for the bootup notification after Intel Reset.
pub const BOOT_TIMEOUT_MS: u64 = 5_000;
/// How long to wait for the device to acknowledge the D0 transition.
pub const D0_TIMEOUT_MS: u64 = 2_000;

/// A firmware-download session over one controller.
///
/// Holds the vendor events that arrive unprompted while a command is
/// in flight. The bootup notification in particular is sent by the
/// newly booted image with no command outstanding, so it has to be
/// latched rather than waited for synchronously.
#[derive(Debug)]
pub struct Session<'a> {
    dev: &'a BtIntelPcie,
    /// Set when a vendor bootup notification has been seen.
    pub bootup_seen: bool,
    /// Result byte from the vendor secure-send-result event.
    pub secure_send_result: Option<u8>,
}

impl<'a> Session<'a> {
    /// Start a session against `dev`, whose rings must already be up.
    pub fn new(dev: &'a BtIntelPcie) -> Self {
        Self {
            dev,
            bootup_seen: false,
            secure_send_result: None,
        }
    }

    /// Latch a vendor event. Returns `true` if it was consumed.
    fn absorb_vendor(&mut self, params: &[u8]) -> bool {
        if params.is_empty() {
            return false;
        }
        let rest = &params[1..];
        match params[0] {
            VENDOR_BOOTUP if rest.len() == BOOTUP_EVT_LEN => {
                self.bootup_seen = true;
                true
            }
            VENDOR_SECURE_SEND_RESULT if rest.len() == SECURE_SEND_RESULT_LEN => {
                self.secure_send_result = Some(rest[0]);
                true
            }
            _ => false,
        }
    }

    /// Pull one event packet from the RX ring, latching vendor events
    /// as they pass. Returns the event code and its parameters.
    fn next_event(&mut self) -> Option<(u8, Vec<u8>)> {
        loop {
            let (ty, pkt) = self.dev.recv_packet()?;
            if ty != HCI_EVT_PKT || pkt.len() < EVT_HDR_LEN {
                continue;
            }
            let code = pkt[0];
            let plen = pkt[1] as usize;
            if pkt.len() < EVT_HDR_LEN + plen {
                continue;
            }
            let params = pkt[EVT_HDR_LEN..EVT_HDR_LEN + plen].to_vec();
            if code == EVT_VENDOR {
                self.absorb_vendor(&params);
            }
            return Some((code, params));
        }
    }

    /// Send an HCI command and wait for its Command Complete.
    ///
    /// Returns the return parameters, status byte first. Events for
    /// other opcodes and unsolicited vendor events are absorbed while
    /// waiting rather than treated as the answer.
    pub fn cmd_sync(
        &mut self,
        opcode: u16,
        params: &[u8],
        timeout_ms: u64,
    ) -> Result<Vec<u8>, FwError> {
        let mut pkt = Vec::with_capacity(3 + params.len());
        pkt.extend_from_slice(&opcode.to_le_bytes());
        pkt.push(params.len() as u8);
        pkt.extend_from_slice(params);
        self.dev.send_packet(HCI_CMD_PKT, &pkt)?;

        let mut outcome: Option<Result<Vec<u8>, FwError>> = None;
        let done = narf_scheduler::responsive_spin_until(
            || {
                while let Some((code, ev)) = self.next_event() {
                    match code {
                        EVT_CMD_COMPLETE => {
                            if ev.len() < 4 {
                                outcome = Some(Err(FwError::MalformedEvent));
                                return true;
                            }
                            if le16(&ev[1..]) != opcode {
                                continue;
                            }
                            let ret = &ev[3..];
                            outcome = Some(if ret[0] == 0 {
                                Ok(ret.to_vec())
                            } else {
                                Err(FwError::CommandFailed {
                                    opcode,
                                    status: ret[0],
                                })
                            });
                            return true;
                        }
                        EVT_CMD_STATUS => {
                            if ev.len() < 4 {
                                outcome = Some(Err(FwError::MalformedEvent));
                                return true;
                            }
                            if le16(&ev[2..]) != opcode {
                                continue;
                            }
                            if ev[0] != 0 {
                                outcome = Some(Err(FwError::CommandFailed {
                                    opcode,
                                    status: ev[0],
                                }));
                                return true;
                            }
                            // Success here only promises the real
                            // answer is still to come; keep waiting.
                        }
                        _ => {}
                    }
                }
                false
            },
            narf_time::Deadline::after_ms(timeout_ms),
        );

        match outcome {
            Some(r) => r,
            None => {
                debug_assert!(!done, "spin reported completion with no outcome recorded");
                Err(FwError::Timeout)
            }
        }
    }

    /// Drain pending events until `pred` holds or the deadline passes.
    fn wait_until(&mut self, timeout_ms: u64, pred: fn(&Self) -> bool) -> Result<(), FwError> {
        let ok = narf_scheduler::responsive_spin_until(
            || {
                while self.next_event().is_some() {
                    if pred(self) {
                        return true;
                    }
                }
                pred(self)
            },
            narf_time::Deadline::after_ms(timeout_ms),
        );
        if ok {
            Ok(())
        } else {
            Err(FwError::Timeout)
        }
    }

    /// Read the controller's version as a TLV stream.
    pub fn read_version(&mut self) -> Result<IntelVersionTlv, FwError> {
        let ret = self.cmd_sync(OP_INTEL_READ_VERSION, &[0xFF], CMD_TIMEOUT_MS)?;
        // `cmd_sync` already rejected a non-zero status; the TLVs are
        // everything after it.
        parse_version_tlv(&ret[1..])
    }

    /// Send one fragment, split across as many Secure Send commands
    /// as its length requires.
    pub fn secure_send(&mut self, kind: u8, data: &[u8]) -> Result<(), FwError> {
        let mut buf = [0u8; SECURE_SEND_MAX_FRAGMENT + 1];
        for chunk in data.chunks(SECURE_SEND_MAX_FRAGMENT) {
            buf[0] = kind;
            buf[1..1 + chunk.len()].copy_from_slice(chunk);
            self.cmd_sync(
                OP_INTEL_SECURE_SEND,
                &buf[..1 + chunk.len()],
                CMD_TIMEOUT_MS,
            )?;
        }
        Ok(())
    }

    /// Reboot the controller into `boot_addr` and wait for the image
    /// to announce itself.
    ///
    /// The bootloader gives no completion for Intel Reset — the newly
    /// booted image sends an unsolicited vendor bootup notification
    /// instead, which is why this waits on the latch rather than on a
    /// Command Complete.
    pub fn boot(&mut self, boot_addr: u32) -> Result<(), FwError> {
        self.bootup_seen = false;

        // `struct intel_reset`: soft reset, patches enabled, no DDC
        // reload, boot from the specified address.
        let mut params = [0u8; 8];
        params[0] = 0x00; // reset_type: soft
        params[1] = 0x01; // patch_enable
        params[2] = 0x00; // ddc_reload
        params[3] = 0x01; // boot_option: specified address
        params[4..8].copy_from_slice(&boot_addr.to_le_bytes());

        // Intel Reset is answered by the reboot itself, not by a
        // Command Complete: the controller tears down the link before
        // it could send one. A timeout here is the expected path.
        match self.cmd_sync(OP_INTEL_RESET, &params, CMD_TIMEOUT_MS) {
            Ok(_) | Err(FwError::Timeout) => {}
            Err(e) => return Err(e),
        }

        self.wait_until(BOOT_TIMEOUT_MS, |s| s.bootup_seen)?;

        // An operational image needs the host to acknowledge the
        // power transition before it will serve HCI; the intermediate
        // loader has no D-state concept and needs nothing.
        let stage = self.dev.current_boot_stage();
        if stage & super::BOOT_STAGE_OPFW != 0 {
            self.dev.set_power_state(super::POWER_STATE_D0);
        }
        Ok(())
    }
}

// ── Orchestration ───────────────────────────────────────────────────

/// Open a firmware blob and run one download stage against it.
///
/// Returns the boot address the image wants to be started from.
pub fn download_image(
    session: &mut Session<'_>,
    auth: &Cap<FirmwareRegistry, Read>,
    ver: &IntelVersionTlv,
) -> Result<u32, FwError> {
    let name = fw_name(ver, "sfi");
    let cap =
        narf_firmware::open(&name, auth).map_err(|_| FwError::FirmwareMissing(name.clone()))?;
    let view = narf_firmware::view_of(&cap).map_err(|_| FwError::FirmwareMissing(name.clone()))?;
    let image = view.bytes;

    if image.len() < RSA_HEADER_LEN {
        return Err(FwError::ImageTooShort(image.len()));
    }

    let boot = scan_boot_params(image).ok_or(FwError::NoBootAddress)?;

    let headers = plan_header_fragments(image, ver.hw_variant(), ver.sbe_type)?;
    let payload = plan_payload_fragments(image, PAYLOAD_OFFSET)?;

    narf_console::klog!(
        "  btintel-pcie: {name} ({} bytes), boot 0x{:08x}, fw {}-{}.{}",
        image.len(),
        boot.boot_addr,
        boot.fw_build_num,
        boot.fw_build_ww,
        boot.fw_build_yy
    );

    session.secure_send_result = None;
    for f in headers.iter().chain(payload.iter()) {
        session.secure_send(f.kind, &image[f.offset..f.offset + f.len])?;
    }

    // The bootloader verifies the whole image only once the last
    // fragment lands, and reports the verdict as a vendor event.
    session.wait_until(DOWNLOAD_TIMEOUT_MS, |s| s.secure_send_result.is_some())?;
    match session.secure_send_result {
        Some(0) => Ok(boot.boot_addr),
        Some(r) => Err(FwError::SecureSendFailed(r)),
        None => Err(FwError::Timeout),
    }
}

/// Apply a device-configuration (DDC) file, if one is present.
///
/// The controller works without it, so a missing or rejected file is
/// reported and otherwise ignored — same as `btintel_load_ddc_config`
/// being called for effect only.
pub fn load_ddc(
    session: &mut Session<'_>,
    auth: &Cap<FirmwareRegistry, Read>,
    ver: &IntelVersionTlv,
) -> Result<usize, FwError> {
    let name = fw_name(ver, "ddc");
    let cap =
        narf_firmware::open(&name, auth).map_err(|_| FwError::FirmwareMissing(name.clone()))?;
    let view = narf_firmware::view_of(&cap).map_err(|_| FwError::FirmwareMissing(name.clone()))?;
    let records = plan_ddc_records(view.bytes)?;
    for r in &records {
        session.cmd_sync(
            OP_INTEL_WRITE_DDC,
            &view.bytes[r.offset..r.offset + r.len],
            CMD_TIMEOUT_MS,
        )?;
    }
    Ok(records.len())
}

/// Hand the controller its board's BRI drive strength.
///
/// Returns the parameters sent, or `None` when this controller and
/// image combination does not take the command. A platform with no
/// DSBR variable still gets the command, with the disabled default —
/// that is what Linux sends when the UEFI read fails.
pub fn set_dsbr(
    session: &mut Session<'_>,
    ver: &IntelVersionTlv,
) -> Result<Option<[u8; 2]>, FwError> {
    if !dsbr_required(ver.hw_variant(), ver.img_type, cnvx_top_step(ver.cnvi_top)) {
        return Ok(None);
    }

    // SAFETY: EFI runtime services are installed for the life of the
    // kernel and this runs in a driver bring-up context, not from an
    // interrupt handler, which is the contract `get_variable` states.
    let raw = unsafe { narf_efi::runtime::get_variable(DSBR_EFI_VAR, &DSBR_EFI_GUID) };
    let dsbr = raw
        .ok()
        .as_deref()
        .and_then(parse_dsbr_variable)
        .unwrap_or(0);

    let params = dsbr_command_params(dsbr);
    narf_console::klog!(
        "  btintel-pcie: dsbr enable {:#04x} value {:#04x}",
        params[0],
        params[1]
    );
    session.cmd_sync(OP_INTEL_SET_DSBR, &params, CMD_TIMEOUT_MS)?;
    Ok(Some(params))
}

/// Enable the Intel vendor events worth having in normal operation.
pub fn set_event_mask(session: &mut Session<'_>) -> Result<(), FwError> {
    let mask = [0x87u8, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    session.cmd_sync(OP_INTEL_SET_EVENT_MASK, &mask, CMD_TIMEOUT_MS)?;
    Ok(())
}

/// Bring a controller from its ROM bootloader to operational firmware.
///
/// Mirrors `btintel_bootloader_setup_tlv`: download, boot, re-read the
/// version, and if the part landed in its intermediate loader, do it
/// once more to reach the operational image.
pub fn setup(
    dev: &BtIntelPcie,
    auth: &Cap<FirmwareRegistry, Read>,
) -> Result<IntelVersionTlv, FwError> {
    let mut session = Session::new(dev);
    let mut ver = session.read_version()?;

    if ver.hw_platform() != HW_PLATFORM_INTEL || !SUPPORTED_HW_VARIANTS.contains(&ver.hw_variant())
    {
        return Err(FwError::UnsupportedController {
            platform: ver.hw_platform(),
            variant: ver.hw_variant(),
        });
    }

    if ver.bdaddr_unconfigured() {
        narf_console::klog!("  btintel-pcie: no device address configured");
    }

    // Already operational — nothing to download.
    if ver.img_type != IMG_OP {
        let boot_addr = download_image(&mut session, auth, &ver)?;
        session.boot(boot_addr)?;
        ver = session.read_version()?;

        // The board's BRI drive strength has to reach the controller
        // before the operational image loads; Linux fails setup if
        // this command does.
        set_dsbr(&mut session, &ver)?;

        // Parts with an intermediate loader land in the IML first;
        // the operational image is a second download through it.
        if ver.img_type == IMG_IML {
            let boot_addr = download_image(&mut session, auth, &ver)?;
            session.boot(boot_addr)?;
            ver = session.read_version()?;
        }
    }

    match load_ddc(&mut session, auth, &ver) {
        Ok(n) => narf_console::klog!("  btintel-pcie: applied {n} DDC record(s)"),
        Err(FwError::FirmwareMissing(name)) => {
            narf_console::klog!("  btintel-pcie: no DDC file {name}, continuing")
        }
        Err(e) => narf_console::klog!("  btintel-pcie: DDC load failed: {e:?}"),
    }

    // Informational only; the controller is usable without it.
    if let Err(e) = set_event_mask(&mut session) {
        narf_console::klog!("  btintel-pcie: set event mask failed: {e:?}");
    }

    Ok(ver)
}
