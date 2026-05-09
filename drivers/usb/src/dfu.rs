//! USB DFU 1.1 (Device Firmware Upgrade) — clean-room.
//!
//! Reference: **USB Device Class Specification for Device
//! Firmware Upgrade, Version 1.1** (USB-IF, 5 August 2004).
//! Public, usb.org. §3 (descriptor layout), §4 (state machine),
//! §5 (class-specific requests), §6.1 (status block).
//!   <https://www.usb.org/document-library/device-firmware-upgrade-11-new>
//!
//! No GPL Linux source consulted.
//!
//! ## Why DFU
//!
//! USB DFU is the standard firmware-update path on every modern
//! USB peripheral that supports field updates: USB-C dock
//! firmware, xHCI hub firmware, USB-PD controller firmware
//! (TPS65987 / FUSB302), and most ARM dev boards (STM32, NXP
//! K-series). The host driver:
//!
//! 1. Walks the descriptor tree, finds an interface with
//!    class `0xFE` / subclass `0x01` (DFU), parses its DFU
//!    Functional Descriptor to learn `wTransferSize`,
//!    capabilities, and DFU version.
//! 2. Issues `DFU_DETACH` to put the device into DFU mode
//!    (devices typically re-enumerate at this point with a
//!    different VID/PID).
//! 3. Sends `DFU_DNLOAD` setup packets carrying chunks of the
//!    new firmware blob; polls `DFU_GETSTATUS` until each chunk
//!    completes (the device returns a `bwPollTimeout` it expects
//!    the host to honour).
//! 4. Sends a zero-length `DFU_DNLOAD` to mark end-of-firmware,
//!    polls `DFU_GETSTATUS` through the manifestation phase, and
//!    waits for the device to re-enumerate to runtime mode.
//!
//! ## Scope
//!
//! Codec layer — DFU functional-descriptor parser, all 7
//! class-specific SETUP-packet builders, the 6-byte status
//! block decoder + the 10-state state-machine enum. The actual
//! xHCI transfer-ring scheduling lives in the per-controller
//! driver.

use core::convert::TryFrom;

use super::cdc::CdcError;

// ── Class triple (DFU 1.1 §3.1) ──────────────────────────────────

/// `bInterfaceClass = 0xFE` — application-specific class.
pub const USB_CLASS_APP_SPECIFIC: u8 = 0xFE;
/// `bInterfaceSubClass = 0x01` — Device Firmware Upgrade.
pub const USB_SUBCLASS_DFU: u8 = 0x01;
/// `bInterfaceProtocol = 0x01` — runtime mode (device speaks its
/// normal class while reporting DFU capability).
pub const USB_PROTOCOL_DFU_RUNTIME: u8 = 0x01;
/// `bInterfaceProtocol = 0x02` — DFU mode (device is updating;
/// only DFU requests work).
pub const USB_PROTOCOL_DFU_MODE: u8 = 0x02;

// ── DFU functional descriptor (§4.1.3) ───────────────────────────

/// `bDescriptorType = 0x21` — DFU Functional Descriptor (note:
/// distinct from CDC's `0x24` `CS_INTERFACE`; DFU uses its own
/// type byte).
pub const DFU_FUNCTIONAL_DESCRIPTOR: u8 = 0x21;

/// `bmAttributes` bit positions in the DFU functional descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct DfuAttributes {
    /// `bitCanDnload` — device can download (host → device).
    pub can_download: bool,
    /// `bitCanUpload` — device can upload (device → host) the
    /// running image.
    pub can_upload: bool,
    /// `bitManifestationTolerant` — device tolerates further
    /// requests during the manifestation phase. When clear, the
    /// host must wait for the device to re-enumerate.
    pub manifestation_tolerant: bool,
    /// `bitWillDetach` — device will perform USB detach when it
    /// receives DFU_DETACH (rather than the host having to issue
    /// USB_RESET).
    pub will_detach: bool,
}

impl DfuAttributes {
    pub fn decode(byte: u8) -> Self {
        Self {
            can_download: byte & 0x01 != 0,
            can_upload: byte & 0x02 != 0,
            manifestation_tolerant: byte & 0x04 != 0,
            will_detach: byte & 0x08 != 0,
        }
    }
}

/// Parsed DFU Functional Descriptor.
///
/// ```text
///   u8  bLength             (9 for DFU 1.1; 7 for DFU 1.0)
///   u8  bDescriptorType     (0x21)
///   u8  bmAttributes
///   u16 wDetachTimeOut      (ms — max time host should wait for
///                            DFU_DETACH to complete)
///   u16 wTransferSize       (max bytes per DNLOAD/UPLOAD chunk)
///   u16 bcdDFUVersion       (DFU 1.1 = 0x0110)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DfuDescriptor {
    pub attributes: DfuAttributes,
    pub detach_timeout_ms: u16,
    pub transfer_size: u16,
    pub bcd_dfu_version: u16,
}

impl DfuDescriptor {
    pub fn parse(buf: &[u8]) -> Result<Self, CdcError> {
        if buf.len() < 7 {
            return Err(CdcError::Short);
        }
        let length = buf[0] as usize;
        if length < 7 || length > buf.len() {
            return Err(CdcError::Truncated);
        }
        if buf[1] != DFU_FUNCTIONAL_DESCRIPTOR {
            return Err(CdcError::NotClassSpecific);
        }
        let attributes = DfuAttributes::decode(buf[2]);
        let detach_timeout_ms = u16::from_le_bytes([buf[3], buf[4]]);
        let transfer_size = u16::from_le_bytes([buf[5], buf[6]]);
        // DFU 1.1 carries bcdDFUVersion at +7..+9; DFU 1.0
        // descriptors stop at +7. Default to 0x0100 if absent.
        let bcd_dfu_version = if length >= 9 {
            u16::from_le_bytes([buf[7], buf[8]])
        } else {
            0x0100
        };
        Ok(Self {
            attributes,
            detach_timeout_ms,
            transfer_size,
            bcd_dfu_version,
        })
    }
}

// ── Class-specific request codes (§5) ────────────────────────────

pub const REQ_DETACH: u8 = 0x00;
pub const REQ_DNLOAD: u8 = 0x01;
pub const REQ_UPLOAD: u8 = 0x02;
pub const REQ_GETSTATUS: u8 = 0x03;
pub const REQ_CLRSTATUS: u8 = 0x04;
pub const REQ_GETSTATE: u8 = 0x05;
pub const REQ_ABORT: u8 = 0x06;

/// USB setup packet — 8 bytes per USB 2.0 §9.3. Mirrors the one
/// in `super::cdc_acm` for the DFU-specific request side.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SetupPacket {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

impl SetupPacket {
    pub fn encode(&self) -> [u8; 8] {
        [
            self.bm_request_type,
            self.b_request,
            self.w_value as u8,
            (self.w_value >> 8) as u8,
            self.w_index as u8,
            (self.w_index >> 8) as u8,
            self.w_length as u8,
            (self.w_length >> 8) as u8,
        ]
    }
}

const RT_CLASS_INTERFACE_OUT: u8 = 0x21;
const RT_CLASS_INTERFACE_IN: u8 = 0xA1;

/// Build the SETUP packet for `DFU_DETACH`. `timeout_ms` is the
/// host's requested detach window; the device promises to honour
/// it if it advertised `bitWillDetach`.
pub fn build_detach(iface: u8, timeout_ms: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_OUT,
        b_request: REQ_DETACH,
        w_value: timeout_ms,
        w_index: iface as u16,
        w_length: 0,
    }
}

/// Build the SETUP packet for `DFU_DNLOAD`. `block_num` is the
/// per-transfer counter (host-monotonic, starts at 0). `length`
/// is the number of bytes the host will send in the data stage
/// (0 marks end-of-firmware).
pub fn build_dnload(iface: u8, block_num: u16, length: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_OUT,
        b_request: REQ_DNLOAD,
        w_value: block_num,
        w_index: iface as u16,
        w_length: length,
    }
}

/// Build the SETUP packet for `DFU_UPLOAD`. Mirror of DNLOAD in
/// the IN direction.
pub fn build_upload(iface: u8, block_num: u16, length: u16) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_IN,
        b_request: REQ_UPLOAD,
        w_value: block_num,
        w_index: iface as u16,
        w_length: length,
    }
}

/// Build the SETUP packet for `DFU_GETSTATUS`. The 6-byte status
/// block comes back in the data stage.
pub fn build_get_status(iface: u8) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_IN,
        b_request: REQ_GETSTATUS,
        w_value: 0,
        w_index: iface as u16,
        w_length: 6,
    }
}

/// Build the SETUP packet for `DFU_CLRSTATUS`. Clears any latched
/// dfuERROR state.
pub fn build_clr_status(iface: u8) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_OUT,
        b_request: REQ_CLRSTATUS,
        w_value: 0,
        w_index: iface as u16,
        w_length: 0,
    }
}

/// Build the SETUP packet for `DFU_GETSTATE`. 1-byte response is
/// just the state field; for full status use `DFU_GETSTATUS`.
pub fn build_get_state(iface: u8) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_IN,
        b_request: REQ_GETSTATE,
        w_value: 0,
        w_index: iface as u16,
        w_length: 1,
    }
}

/// Build the SETUP packet for `DFU_ABORT`. Aborts an in-progress
/// DNLOAD or UPLOAD and returns to dfuIDLE.
pub fn build_abort(iface: u8) -> SetupPacket {
    SetupPacket {
        bm_request_type: RT_CLASS_INTERFACE_OUT,
        b_request: REQ_ABORT,
        w_value: 0,
        w_index: iface as u16,
        w_length: 0,
    }
}

// ── DFU state machine (§4.1.4 / §6.1.2) ──────────────────────────

/// `bState` field of the DFU status block (and the entire payload
/// of `DFU_GETSTATE`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DfuState {
    /// `appIDLE` — runtime mode, no DFU activity.
    AppIdle = 0,
    /// `appDETACH` — host has issued DFU_DETACH; awaiting USB
    /// reset.
    AppDetach = 1,
    /// `dfuIDLE` — DFU mode, ready to start.
    DfuIdle = 2,
    /// `dfuDNLOAD-SYNC` — block received, waiting on
    /// DFU_GETSTATUS.
    DfuDnloadSync = 3,
    /// `dfuDNBUSY` — device flushing block to flash.
    DfuDnBusy = 4,
    /// `dfuDNLOAD-IDLE` — between blocks.
    DfuDnloadIdle = 5,
    /// `dfuMANIFEST-SYNC` — final block delivered; waiting on
    /// host's DFU_GETSTATUS.
    DfuManifestSync = 6,
    /// `dfuMANIFEST` — device finalising the new firmware
    /// (typically a CRC verify).
    DfuManifest = 7,
    /// `dfuMANIFEST-WAIT-RESET` — finalisation done; device
    /// awaiting USB reset.
    DfuManifestWaitReset = 8,
    /// `dfuUPLOAD-IDLE` — UPLOAD in progress.
    DfuUploadIdle = 9,
    /// `dfuERROR` — error latched; needs DFU_CLRSTATUS.
    DfuError = 10,
}

impl DfuState {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => DfuState::AppIdle,
            1 => DfuState::AppDetach,
            2 => DfuState::DfuIdle,
            3 => DfuState::DfuDnloadSync,
            4 => DfuState::DfuDnBusy,
            5 => DfuState::DfuDnloadIdle,
            6 => DfuState::DfuManifestSync,
            7 => DfuState::DfuManifest,
            8 => DfuState::DfuManifestWaitReset,
            9 => DfuState::DfuUploadIdle,
            10 => DfuState::DfuError,
            _ => return None,
        })
    }
}

/// `bStatus` field of the DFU status block (§6.1.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DfuStatusCode {
    Ok = 0x00,
    /// File written but firmware refused it (CRC / signature).
    ErrTarget = 0x01,
    /// File for unintended target.
    ErrFile = 0x02,
    /// Write failed.
    ErrWrite = 0x03,
    /// Erase failed.
    ErrErase = 0x04,
    /// Erase check failed.
    ErrCheckErased = 0x05,
    /// Programming faulted.
    ErrProg = 0x06,
    /// Verify after programming failed.
    ErrVerify = 0x07,
    /// Address out of range.
    ErrAddress = 0x08,
    /// Reserved-zero byte at end of file expected.
    ErrNotDone = 0x09,
    /// Firmware corrupted.
    ErrFirmware = 0x0A,
    /// iString reference invalid.
    ErrVendor = 0x0B,
    /// Device detected unexpected USB reset signaling.
    ErrUsbR = 0x0C,
    /// Device detected unexpected power on reset.
    ErrPor = 0x0D,
    /// Unknown.
    ErrUnknown = 0x0E,
    /// Cannot stall.
    ErrStalledPkt = 0x0F,
}

impl DfuStatusCode {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => DfuStatusCode::Ok,
            0x01 => DfuStatusCode::ErrTarget,
            0x02 => DfuStatusCode::ErrFile,
            0x03 => DfuStatusCode::ErrWrite,
            0x04 => DfuStatusCode::ErrErase,
            0x05 => DfuStatusCode::ErrCheckErased,
            0x06 => DfuStatusCode::ErrProg,
            0x07 => DfuStatusCode::ErrVerify,
            0x08 => DfuStatusCode::ErrAddress,
            0x09 => DfuStatusCode::ErrNotDone,
            0x0A => DfuStatusCode::ErrFirmware,
            0x0B => DfuStatusCode::ErrVendor,
            0x0C => DfuStatusCode::ErrUsbR,
            0x0D => DfuStatusCode::ErrPor,
            0x0E => DfuStatusCode::ErrUnknown,
            0x0F => DfuStatusCode::ErrStalledPkt,
            _ => return None,
        })
    }
}

/// 6-byte DFU status block — payload of `DFU_GETSTATUS`.
///
/// ```text
///   u8 bStatus               (DfuStatusCode)
///   u24 bwPollTimeout (LE)   (ms host should wait before next GETSTATUS)
///   u8 bState                (DfuState)
///   u8 iString               (string-descriptor index for diag text)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DfuStatus {
    pub status: DfuStatusCode,
    pub poll_timeout_ms: u32,
    pub state: DfuState,
    pub i_string: u8,
}

impl DfuStatus {
    pub fn decode(bytes: &[u8]) -> Result<Self, CdcError> {
        if bytes.len() < 6 {
            return Err(CdcError::Truncated);
        }
        let status = DfuStatusCode::from_u8(bytes[0]).ok_or(CdcError::MalformedField)?;
        let poll_timeout_ms =
            (bytes[1] as u32) | ((bytes[2] as u32) << 8) | ((bytes[3] as u32) << 16);
        let state = DfuState::from_u8(bytes[4]).ok_or(CdcError::MalformedField)?;
        let i_string = bytes[5];
        Ok(Self {
            status,
            poll_timeout_ms,
            state,
            i_string,
        })
    }
}

impl TryFrom<u8> for DfuState {
    type Error = CdcError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        DfuState::from_u8(b).ok_or(CdcError::MalformedField)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_dfu_descriptor_v11() -> TestResult {
        // bLength=9, type=0x21, attrs=0x0D (Dnload+Manifest+Detach),
        // wDetachTimeOut=1000ms, wTransferSize=2048, bcdDFU=0x0110.
        let raw = [
            9u8,
            DFU_FUNCTIONAL_DESCRIPTOR,
            0x0D,
            0xE8,
            0x03,
            0x00,
            0x08,
            0x10,
            0x01,
        ];
        let d = match DfuDescriptor::parse(&raw) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("clean DFU desc rejected"),
        };
        if !d.attributes.can_download
            || !d.attributes.manifestation_tolerant
            || !d.attributes.will_detach
        {
            return TestResult::Fail("attribute bits lost");
        }
        if d.attributes.can_upload {
            return TestResult::Fail("upload bit must be clear");
        }
        if d.detach_timeout_ms != 1000 {
            return TestResult::Fail("detach timeout lost");
        }
        if d.transfer_size != 2048 {
            return TestResult::Fail("transfer size lost");
        }
        if d.bcd_dfu_version != 0x0110 {
            return TestResult::Fail("bcdDFUVersion wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/dfu", smoke_dfu_descriptor_v11);

    fn smoke_dnload_setup_layout() -> TestResult {
        let s = build_dnload(2, 7, 1024);
        let bytes = s.encode();
        if bytes[0] != 0x21 {
            return TestResult::Fail("bmRequestType wrong");
        }
        if bytes[1] != REQ_DNLOAD {
            return TestResult::Fail("bRequest wrong");
        }
        if u16::from_le_bytes([bytes[2], bytes[3]]) != 7 {
            return TestResult::Fail("block_num lost");
        }
        if u16::from_le_bytes([bytes[6], bytes[7]]) != 1024 {
            return TestResult::Fail("wLength lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/dfu", smoke_dnload_setup_layout);

    fn smoke_get_status_setup_in_direction() -> TestResult {
        let s = build_get_status(0);
        let bytes = s.encode();
        if bytes[0] != 0xA1 {
            return TestResult::Fail("GET_STATUS must be IN");
        }
        if bytes[6] != 6 {
            return TestResult::Fail("wLength must be 6");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/dfu", smoke_get_status_setup_in_direction);

    fn smoke_status_block_decode() -> TestResult {
        // Status=Ok, poll=750ms (0x0002EE), state=dfuDnloadIdle (5),
        // iString=0.
        let raw = [0x00, 0xEE, 0x02, 0x00, 0x05, 0x00];
        let s = match DfuStatus::decode(&raw) {
            Ok(s) => s,
            Err(_) => return TestResult::Fail("clean status rejected"),
        };
        if s.status != DfuStatusCode::Ok {
            return TestResult::Fail("status code lost");
        }
        if s.poll_timeout_ms != 750 {
            return TestResult::Fail("poll timeout lost");
        }
        if s.state != DfuState::DfuDnloadIdle {
            return TestResult::Fail("state lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/dfu", smoke_status_block_decode);

    fn smoke_status_block_rejects_bad_state() -> TestResult {
        let raw = [0x00, 0, 0, 0, 0xFF, 0]; // state byte invalid
        match DfuStatus::decode(&raw) {
            Err(CdcError::MalformedField) => TestResult::Pass,
            _ => TestResult::Fail("invalid state must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/usb/dfu",
        smoke_status_block_rejects_bad_state
    );

    fn smoke_v10_descriptor_default_version() -> TestResult {
        // 7-byte (DFU 1.0) descriptor — no bcdDFUVersion field.
        let raw = [7u8, DFU_FUNCTIONAL_DESCRIPTOR, 0x01, 0xE8, 0x03, 0x00, 0x08];
        let d = match DfuDescriptor::parse(&raw) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("DFU 1.0 desc rejected"),
        };
        if d.bcd_dfu_version != 0x0100 {
            return TestResult::Fail("expected DFU 1.0 default version");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/dfu", smoke_v10_descriptor_default_version);
}
