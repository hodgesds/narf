//! USB-side wrapper for the Windows Biometric Device Interface
//! (WBDI) recogniser.
//!
//! ## Sources (public only)
//!
//! - **Microsoft, "Microsoft OS 2.0 Descriptors Specification"**,
//!   Version 1.0, July 13, 2018.
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-os-2-0-descriptors-specification>
//! - **Microsoft, "Biometric devices design guide"** — public
//!   reference for the WBDI sensor adapter that every Windows-
//!   certified fingerprint reader implements.
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/biometric/>
//! - **USB 3.1 §9.6.2** — BOS descriptor; **§9.6.2.2** — Device
//!   Capability descriptor (Platform Capability sub-type).
//!     <https://www.usb.org/document-library/usb-32-revision-11-june-2022>
//!
//! No GPL / Linux source consulted. Vendor command codecs (Goodix,
//! Synaptics/Validity, ELAN) are intentionally NOT covered here —
//! those wire protocols are libfprint-derived and not part of any
//! public Microsoft / vendor spec.
//!
//! ## Recogniser shape
//!
//! 1. Pre-filter on `bInterfaceClass == 0xFF` (vendor class). Skips
//!    devices that obviously can't be a WBDI sensor without the
//!    extra MS OS 2.0 round-trip.
//! 2. Issue GET_DESCRIPTOR(BOS) and look for a Platform Capability
//!    descriptor whose UUID is the MS OS 2.0 Platform Capability
//!    GUID (`{D8DD60DF-4589-4CC7-9CD2-659D9E648A9F}`). That cap's
//!    payload carries the `bMS_VendorCode` byte and the total
//!    length of the MS OS 2.0 descriptor set.
//! 3. Vendor control IN (bmRequestType=0xC0, bRequest=vendor_code,
//!    wValue=0, wIndex=MS_OS_20_DESCRIPTOR_INDEX=0x07) returns the
//!    descriptor set. Walk it for a `FEATURE_COMPATIBLE_ID` (type
//!    0x03, length 20) whose compatible_id is `b"WINUSB\0\0"` AND
//!    sub_compatible_id is `b"WBDI\0\0\0\0"`.
//! 4. On match: log + push a registry entry. Slot stays alive.

extern crate alloc;

use crate::xhci::Xhci;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// MS OS 2.0 Platform Capability UUID, encoded as a 16-byte
/// little-endian GUID per the MS OS 2.0 spec §3.4 Table 4.
/// `{D8DD60DF-4589-4CC7-9CD2-659D9E648A9F}`.
const MS_OS_20_PLATFORM_CAPABILITY_UUID: [u8; 16] = [
    0xDF, 0x60, 0xDD, 0xD8, 0x89, 0x45, 0xC7, 0x4C, 0x9C, 0xD2, 0x65, 0x9D, 0x9E, 0x64, 0x8A, 0x9F,
];

/// wIndex value for the MS OS 2.0 vendor request that returns the
/// descriptor set (MS OS 2.0 §4.1 Table 11).
const MS_OS_20_DESCRIPTOR_INDEX: u16 = 0x07;

/// USB 2.0 §9.6 bDescriptorType for BOS, plus the
/// Device-Capability / Platform-Capability sub-types.
const DESC_TYPE_BOS: u16 = 0x0F;
const DESC_TYPE_DEVICE_CAPABILITY: u8 = 0x10;
const DEV_CAP_TYPE_PLATFORM: u8 = 0x05;

/// MS OS 2.0 descriptor wDescriptorType for Compatible-ID feature.
const FEATURE_COMPATIBLE_ID: u16 = 0x03;

/// Cap on BOS descriptor length we'll accept. Real BOS descriptors
/// are < 64 bytes (a single Platform Capability is 28 bytes).
const BOS_MAX_LEN: usize = 256;

/// Cap on MS OS 2.0 descriptor-set length. The platform-capability
/// descriptor carries the real total in `dwMsOsDescSetTotalLength`,
/// but cap conservatively so a hostile / broken device can't coax
/// a giant allocation.
const MS_OS_20_MAX_LEN: usize = 4096;

/// Compatible-ID strings the WBDI sensor adapter advertises.
const COMPATIBLE_ID_WINUSB: [u8; 8] = *b"WINUSB\0\0";
const SUB_COMPATIBLE_ID_WBDI: [u8; 8] = *b"WBDI\0\0\0\0";

/// Registry entry for a recognised WBDI sensor.
#[derive(Debug)]
pub struct WbdiDevice {
    pub slot_id: u8,
    /// USB interface number that carries the vendor (0xFF) class.
    pub vendor_iface: u8,
}

/// Global registry of bound WBDI sensors. Append-only — a userland
/// fingerprint driver attaches by slot_id when it loads.
pub static WBDI_DEVICES: IrqSafeSpinLock<Vec<WbdiDevice>> = IrqSafeSpinLock::new(Vec::new());

#[derive(Copy, Clone, Debug)]
pub enum WbdiBindError {
    /// No vendor-class (0xFF) interface in the configuration — not
    /// a fingerprint-reader shape.
    NoVendorInterface,
    /// BOS descriptor request failed or returned no MS OS 2.0
    /// platform-capability entry. Most devices that aren't
    /// MS-OS-aware land here.
    NoMsOs20PlatformCap,
    /// Issued the vendor control request but the device returned a
    /// blob that doesn't parse as an MS OS 2.0 descriptor set.
    InvalidDescriptorSet,
    /// Parsed an MS OS 2.0 descriptor set but no Compatible-ID
    /// declared WBDI.
    NotWbdi,
}

/// Walk the device's configuration descriptor for the first vendor-
/// class (0xFF) interface. Returns its bInterfaceNumber.
fn find_vendor_interface(cfg: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        // bDescriptorType=4 (Interface), bInterfaceClass at +5.
        if cfg[i + 1] == 4 && len >= 9 && cfg[i + 5] == 0xFF {
            return Some(cfg[i + 2]);
        }
        i += len;
    }
    None
}

/// Issue GET_DESCRIPTOR(BOS) and search the returned blob for an
/// MS OS 2.0 Platform Capability descriptor. Returns
/// `(vendor_code, ms_os_desc_total_length)` on match.
async fn fetch_ms_os_20_platform_cap(xhci_dev: &Xhci, slot_id: u8) -> Option<(u8, u16)> {
    // Stage 1: 5-byte BOS header to learn wTotalLength
    // (USB 3.1 §9.6.2.1).
    let mut head = [0u8; 5];
    xhci_dev
        .control_in(
            slot_id,
            0x80, // device-to-host | standard | device
            crate::xhci::USB_REQ_GET_DESCRIPTOR,
            DESC_TYPE_BOS << 8,
            0,
            &mut head,
        )
        .await
        .ok()?;
    if head[0] != 5 || head[1] as u16 != DESC_TYPE_BOS {
        return None;
    }
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(5..=BOS_MAX_LEN).contains(&total) {
        return None;
    }
    let mut blob = alloc::vec![0u8; total];
    xhci_dev
        .control_in(
            slot_id,
            0x80,
            crate::xhci::USB_REQ_GET_DESCRIPTOR,
            DESC_TYPE_BOS << 8,
            0,
            &mut blob,
        )
        .await
        .ok()?;
    // Walk Device Capability descriptors after the 5-byte BOS header.
    // Platform Capability (sub-type 0x05) carries a 16-byte UUID at
    // +4..20. For MS OS 2.0 the descriptor data following the UUID is:
    //   +20..24: dwWindowsVersion
    //   +24..26: wMSOSDescriptorSetTotalLength
    //   +26:     bMS_VendorCode
    //   +27:     bAltEnumCode
    let mut i = 5usize;
    while i + 2 <= blob.len() {
        let len = blob[i] as usize;
        if len < 2 || i + len > blob.len() {
            break;
        }
        if blob[i + 1] == DESC_TYPE_DEVICE_CAPABILITY
            && len >= 28
            && blob[i + 2] == DEV_CAP_TYPE_PLATFORM
            && blob[i + 4..i + 20] == MS_OS_20_PLATFORM_CAPABILITY_UUID
        {
            let total_set = u16::from_le_bytes([blob[i + 24], blob[i + 25]]);
            let vendor_code = blob[i + 26];
            return Some((vendor_code, total_set));
        }
        i += len;
    }
    None
}

/// Walk an MS OS 2.0 descriptor-set blob for any Compatible-ID
/// feature whose (compatible_id, sub_compatible_id) names WBDI.
fn is_wbdi_descriptor_set(blob: &[u8]) -> bool {
    if blob.len() < 10 {
        return false;
    }
    // Set Header (MS OS 2.0 §3 Table 5): 10 bytes,
    //   +0..2 wLength=10, +2..4 wDescriptorType=0, +4..8 dwWindowsVersion,
    //   +8..10 wTotalLength.
    let header_len = u16::from_le_bytes([blob[0], blob[1]]) as usize;
    if header_len != 10 || blob[2] != 0 || blob[3] != 0 {
        return false;
    }
    let total = u16::from_le_bytes([blob[8], blob[9]]) as usize;
    if total < 10 || total > blob.len() {
        return false;
    }
    let mut off = 10usize;
    while off + 4 <= total {
        let length = u16::from_le_bytes([blob[off], blob[off + 1]]) as usize;
        let dt = u16::from_le_bytes([blob[off + 2], blob[off + 3]]);
        if length < 4 || off + length > total {
            return false;
        }
        if dt == FEATURE_COMPATIBLE_ID && length == 20 {
            let cid: [u8; 8] = blob[off + 4..off + 12].try_into().unwrap_or([0u8; 8]);
            let sub: [u8; 8] = blob[off + 12..off + 20].try_into().unwrap_or([0u8; 8]);
            if cid == COMPATIBLE_ID_WINUSB && sub == SUB_COMPATIBLE_ID_WBDI {
                return true;
            }
        }
        off += length;
    }
    false
}

/// Run the WBDI recogniser on an already-addressed device. Cheap
/// no-op for devices that aren't MS-OS-aware. Returns
/// `Err(NotWbdi)` for devices that are MS-OS-aware but advertise
/// something other than a fingerprint sensor (plain WinUSB, MTP,
/// etc.) — the dispatcher continues to the UnknownClass log path.
///
/// **Slot lifecycle**: does NOT call `disable_slot` on failure. The
/// dispatcher owns the slot.
pub async fn try_bind_wbdi_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, WbdiBindError> {
    let vendor_iface = find_vendor_interface(cfg).ok_or(WbdiBindError::NoVendorInterface)?;
    let (vendor_code, total_set) = fetch_ms_os_20_platform_cap(xhci_dev, slot_id)
        .await
        .ok_or(WbdiBindError::NoMsOs20PlatformCap)?;
    let total_set = total_set as usize;
    if total_set < 10 || total_set > MS_OS_20_MAX_LEN {
        return Err(WbdiBindError::InvalidDescriptorSet);
    }
    // Vendor request: bmRequestType=0xC0 (device-to-host | vendor |
    // device), bRequest=vendor_code, wValue=0,
    // wIndex=MS_OS_20_DESCRIPTOR_INDEX (=0x07).
    let mut blob = alloc::vec![0u8; total_set];
    xhci_dev
        .control_in(
            slot_id,
            0xC0,
            vendor_code,
            0,
            MS_OS_20_DESCRIPTOR_INDEX,
            &mut blob,
        )
        .await
        .map_err(|_| WbdiBindError::InvalidDescriptorSet)?;
    if !is_wbdi_descriptor_set(&blob) {
        return Err(WbdiBindError::NotWbdi);
    }
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  usb-wbdi: fingerprint reader recognised on slot={} iface={}",
        slot_id, vendor_iface
    );
    let mut g = WBDI_DEVICES.lock();
    let idx = g.len();
    g.push(WbdiDevice {
        slot_id,
        vendor_iface,
    });
    Ok(idx)
}

/// Number of WBDI sensors currently registered.
pub fn attached_wbdi_count() -> usize {
    WBDI_DEVICES.lock().len()
}

#[doc(hidden)]
pub fn __reset_wbdi_for_test() {
    WBDI_DEVICES.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_wbdi_set_recognises_winusb_wbdi() {
        // Minimal MS OS 2.0 set: 10-byte header + 20-byte
        // Compatible-ID with WINUSB / WBDI.
        let mut blob = alloc::vec![0u8; 30];
        // Set header: wLength=10, wDescriptorType=0, dwWindowsVersion=NTDDI_WIN8_1,
        // wTotalLength=30.
        blob[0..2].copy_from_slice(&10u16.to_le_bytes());
        blob[2..4].copy_from_slice(&0u16.to_le_bytes());
        blob[4..8].copy_from_slice(&0x06030000u32.to_le_bytes());
        blob[8..10].copy_from_slice(&30u16.to_le_bytes());
        // Compatible-ID feature: wLength=20, wDescriptorType=3, +
        // 8-byte compatible_id, 8-byte sub_compatible_id.
        blob[10..12].copy_from_slice(&20u16.to_le_bytes());
        blob[12..14].copy_from_slice(&FEATURE_COMPATIBLE_ID.to_le_bytes());
        blob[14..22].copy_from_slice(b"WINUSB\0\0");
        blob[22..30].copy_from_slice(b"WBDI\0\0\0\0");
        assert!(is_wbdi_descriptor_set(&blob));
    }

    #[test]
    fn is_wbdi_set_rejects_plain_winusb() {
        let mut blob = alloc::vec![0u8; 30];
        blob[0..2].copy_from_slice(&10u16.to_le_bytes());
        blob[8..10].copy_from_slice(&30u16.to_le_bytes());
        blob[10..12].copy_from_slice(&20u16.to_le_bytes());
        blob[12..14].copy_from_slice(&FEATURE_COMPATIBLE_ID.to_le_bytes());
        blob[14..22].copy_from_slice(b"WINUSB\0\0");
        // sub_compatible_id is empty — plain WinUSB device.
        assert!(!is_wbdi_descriptor_set(&blob));
    }

    #[test]
    fn find_vendor_iface_returns_first_ff() {
        // Two interface descriptors: HID (0x03) first, vendor (0xFF) second.
        let cfg = [
            // cfg header (9 bytes)
            0x09, 0x02, 0x20, 0x00, 0x02, 0x01, 0x00, 0x80, 0x32,
            // iface 0 (HID, class 0x03)
            0x09, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            // iface 1 (vendor, class 0xFF)
            0x09, 0x04, 0x07, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00,
        ];
        assert_eq!(find_vendor_interface(&cfg), Some(0x07));
    }
}
