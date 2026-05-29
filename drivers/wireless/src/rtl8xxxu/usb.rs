//! RTL8XXXU USB transport layer.
//!
//! Encodes the three USB transfer types used by Realtek USB WiFi dongles:
//!
//! 1. **Control transfers** — register read (`usb_read8/16/32`) and
//!    write (`usb_write8/16/32`) via `bmRequestType=REALTEK_USB_READ/WRITE`,
//!    `bRequest=REALTEK_USB_CMD_REQ`, `wValue=register_address`.
//!
//! 2. **Bulk-OUT** — TX data frames and H2C (host-to-chip) commands.
//!    The host prefixes a `TxDesc32` or `TxDesc40` to each frame before
//!    submission on the appropriate bulk-OUT endpoint.
//!
//! 3. **Bulk-IN** — RX data frames on the bulk-IN endpoint. Frames are
//!    prefixed with an `RxDesc16` (16-byte rx descriptor).
//!
//! 4. **Interrupt-IN** — asynchronous 56-byte status notifications from
//!    the chip on the interrupt endpoint.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c`
//!   - `rtl8xxxu_read8/16/32`, `rtl8xxxu_write8/16/32` (~L611..L740):
//!     control-transfer encode.
//!   - `rtl8xxxu_probe` (~L7692): USB endpoint enumeration.
//!   - `rtl8xxxu_usb_disconnect` (~L7860): teardown.
//! - `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.h`:
//!   `REALTEK_USB_READ/WRITE/CMD_REQ`, `USB_INTR_CONTENT_LENGTH`.

#![allow(dead_code)]

use super::regs::*;

// ── USB control-transfer descriptor ────────────────────────────────

/// A fully-encoded USB control-transfer setup packet for a Realtek
/// register read or write.
///
/// The 8-byte USB setup packet layout (§9.3 of the USB 2.0 spec):
///
/// ```text
/// [0]   bmRequestType
/// [1]   bRequest
/// [2-3] wValue  (register address, little-endian)
/// [4-5] wIndex  (always 0)
/// [6-7] wLength (transfer length: 1 / 2 / 4 bytes)
/// ```
///
/// Source: `core.c::rtl8xxxu_read8/16/32` — all use
/// `REALTEK_USB_CMD_REQ`, the address in `wValue`, `0` in `wIndex`,
/// and the width in `wLength`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UsbControlSetup {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16, // register address (LE)
    pub w_index: u16, // always 0
    pub w_length: u16, // 1 / 2 / 4
}

impl UsbControlSetup {
    /// Encode a register **read** setup packet.
    ///
    /// `bmRequestType = REALTEK_USB_READ (0xC0)` — device-to-host,
    /// vendor, device. `bRequest = REALTEK_USB_CMD_REQ (0x05)`.
    /// `wValue = addr`, `wIndex = 0`, `wLength = width`.
    ///
    /// Source: `core.c::rtl8xxxu_read8` ~L621.
    pub const fn read(addr: u16, width: u16) -> Self {
        Self {
            bm_request_type: REALTEK_USB_READ,
            b_request: REALTEK_USB_CMD_REQ,
            w_value: addr,
            w_index: REALTEK_USB_CMD_IDX,
            w_length: width,
        }
    }

    /// Encode a register **write** setup packet.
    ///
    /// `bmRequestType = REALTEK_USB_WRITE (0x40)` — host-to-device,
    /// vendor, device. `bRequest = REALTEK_USB_CMD_REQ (0x05)`.
    /// `wValue = addr`, `wIndex = 0`, `wLength = width`.
    ///
    /// Source: `core.c::rtl8xxxu_write8` ~L690.
    pub const fn write(addr: u16, width: u16) -> Self {
        Self {
            bm_request_type: REALTEK_USB_WRITE,
            b_request: REALTEK_USB_CMD_REQ,
            w_value: addr,
            w_index: REALTEK_USB_CMD_IDX,
            w_length: width,
        }
    }

    /// Return `[bmRequestType, bRequest, wValue_lo, wValue_hi,
    ///          wIndex_lo, wIndex_hi, wLength_lo, wLength_hi]`.
    pub fn to_bytes(self) -> [u8; 8] {
        [
            self.bm_request_type,
            self.b_request,
            (self.w_value & 0xFF) as u8,
            (self.w_value >> 8) as u8,
            (self.w_index & 0xFF) as u8,
            (self.w_index >> 8) as u8,
            (self.w_length & 0xFF) as u8,
            (self.w_length >> 8) as u8,
        ]
    }
}

// ── TX descriptor (32-byte variant) ────────────────────────────────
//
// Used by 8188EU / 8192EU / 8723BU.
// Source: `rtl8xxxu.h::rtl8xxxu_txdesc32` (the 32-byte packed struct).
//
// The host prepends this to every bulk-OUT frame submitted for TX or
// H2C commands. The firmware reads the descriptor to determine frame
// type, rate, aggregation, etc.

/// 32-byte TX descriptor prepended to bulk-OUT frames on 8188EU /
/// 8192EU / 8723BU parts.
///
/// Source: `rtl8xxxu.h::rtl8xxxu_txdesc32`.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TxDesc32 {
    /// Word 0: packet length [12:0] + flags.
    pub dw0: u32,
    /// Word 1: queue select [12:8], rate [22:16], etc.
    pub dw1: u32,
    /// Word 2: queue tail / extra desc.
    pub dw2: u32,
    /// Word 3: NAV protection fields.
    pub dw3: u32,
    /// Word 4: TX count / retry limit.
    pub dw4: u32,
    /// Word 5: TX rate fallback.
    pub dw5: u32,
    /// Word 6: TX AGG descriptor.
    pub dw6: u32,
    /// Word 7: voodoo — must be zeroed at submission.
    pub dw7: u32,
}

impl TxDesc32 {
    pub const SIZE: usize = TXDESC_SIZE_32;

    /// Build a minimal management-frame TX descriptor.
    ///
    /// - `pkt_len`: MPDU body length in bytes (not including this header).
    /// - `qsel`: queue selector bits [12:8] of DW1 (0 = BE queue).
    ///
    /// DW0 bits: `pkt_len[12:0]`, `OWN (bit 31)`.
    /// DW1 bits: `QSEL[12:8]`, default rate / no retry override.
    pub fn management(pkt_len: u16, qsel: u8) -> Self {
        let dw0 = (pkt_len as u32 & 0x1FFF) | (1u32 << 31); // PKT_LEN + OWN
        let dw1 = ((qsel as u32) << 8) & 0x1F00;
        Self {
            dw0,
            dw1,
            ..Default::default()
        }
    }

    /// Serialize to bytes for DMA submission.
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.dw0.to_le_bytes());
        buf[4..8].copy_from_slice(&self.dw1.to_le_bytes());
        buf[8..12].copy_from_slice(&self.dw2.to_le_bytes());
        buf[12..16].copy_from_slice(&self.dw3.to_le_bytes());
        buf[16..20].copy_from_slice(&self.dw4.to_le_bytes());
        buf[20..24].copy_from_slice(&self.dw5.to_le_bytes());
        buf[24..28].copy_from_slice(&self.dw6.to_le_bytes());
        buf[28..32].copy_from_slice(&self.dw7.to_le_bytes());
        buf
    }

    /// Deserialize from a 32-byte buffer.
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Self {
        Self {
            dw0: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            dw1: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            dw2: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            dw3: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            dw4: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            dw5: u32::from_le_bytes(b[20..24].try_into().unwrap()),
            dw6: u32::from_le_bytes(b[24..28].try_into().unwrap()),
            dw7: u32::from_le_bytes(b[28..32].try_into().unwrap()),
        }
    }

    /// Extract the packet length from DW0 bits[12:0].
    pub fn pkt_len(&self) -> u16 {
        (self.dw0 & 0x1FFF) as u16
    }
}

// ── Bulk-OUT TX frame builder ───────────────────────────────────────

/// Build a complete bulk-OUT frame: `TxDesc32 || payload`.
///
/// The descriptor's `pkt_len` is set from `payload.len()`. Queue
/// selector defaults to 0 (best-effort).
///
/// Source: `core.c::rtl8xxxu_submit_int_urb` / the fill_txdesc callback
/// chain showing how the Linux driver constructs bulk-OUT frames.
pub fn build_bulk_out_frame(payload: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let desc = TxDesc32::management(payload.len() as u16, 0);
    let desc_bytes = desc.to_bytes();
    let mut out = Vec::with_capacity(TxDesc32::SIZE + payload.len());
    out.extend_from_slice(&desc_bytes);
    out.extend_from_slice(payload);
    out
}

// ── Interrupt-IN frame ──────────────────────────────────────────────

/// A 56-byte interrupt-IN notification from the chip.
/// Source: `rtl8xxxu.h` / `USB_INTR_CONTENT_LENGTH = 56`.
///
/// The first 4 bytes contain status flags; the rest are chip-specific
/// fields (rate/AGC reports, etc.). For the baseline we expose raw bytes.
#[derive(Copy, Clone, Debug)]
pub struct IntrIn {
    pub data: [u8; USB_INTR_CONTENT_LEN],
}

impl IntrIn {
    pub const fn new() -> Self {
        Self { data: [0u8; USB_INTR_CONTENT_LEN] }
    }

    /// Low 4 bytes as a status word.
    pub fn status_word(&self) -> u32 {
        u32::from_le_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ])
    }
}

extern crate alloc;

// ── narf-usb bridge ────────────────────────────────────────────────
//
// Forwards rtl8xxxu's USB transfer primitives to the narf-usb crate.
// The crate exposes the `USBDevice` handle a class driver gets after
// the host-controller enumerator finishes Address Device + Configure
// Endpoint; the bridge functions below adapt the rtl8xxxu request
// shape (`UsbControlSetup`, raw bulk-OUT byte buffer, 56-byte
// interrupt-IN frame) onto that handle.
//
// rtl8xxxu's chip-specific code never references the underlying xHCI
// types — every transfer goes through this bridge so the driver stays
// portable to the eventual EHCI / OHCI / UHCI controllers without
// touching its USB transport.

/// Mirror of the rtl8xxxu interrupt-IN content length, re-exported
/// for the narf-usb-side intr::arm() callers.
pub use crate::rtl8xxxu::regs::USB_INTR_CONTENT_LEN as RTL_INTR_LEN;

/// Forward a Realtek vendor register READ (1 / 2 / 4 byte payload) to
/// the USB control pipe of `dev`. The encoding is byte-identical to
/// the `UsbControlSetup::read` SETUP packet — `narf-usb`'s control
/// builder packs the same `bmRT / bReq / wValue / wIndex / wLength`
/// bytes onto the wire (USB 2.0 §9.3).
///
/// `out.len()` must equal the width (1 / 2 / 4); the function reads
/// exactly that many bytes from the device into `out`.
///
/// Returns the number of bytes the controller reports as transferred.
pub async fn read_register(
    dev: &narf_drivers_usb::device::USBDevice,
    addr: u16,
    out: &mut [u8],
) -> Result<usize, narf_drivers_usb::device::UsbError> {
    let setup = UsbControlSetup::read(addr, out.len() as u16);
    dev.control_in(
        setup.bm_request_type,
        setup.b_request,
        setup.w_value,
        setup.w_index,
        out,
    )
    .await
}

/// Forward a Realtek vendor register WRITE (1 / 2 / 4 byte payload).
/// Symmetric to [`read_register`].
pub async fn write_register(
    dev: &narf_drivers_usb::device::USBDevice,
    addr: u16,
    data: &[u8],
) -> Result<usize, narf_drivers_usb::device::UsbError> {
    let setup = UsbControlSetup::write(addr, data.len() as u16);
    dev.control_out(
        setup.bm_request_type,
        setup.b_request,
        setup.w_value,
        setup.w_index,
        data,
    )
    .await
}

/// Submit a `build_bulk_out_frame` payload (TxDesc32 || mpdu) on a
/// bulk-OUT endpoint. `ep_addr` is the USB-side endpoint address
/// (low nibble = endpoint number, bit 7 clear for OUT).
pub async fn bulk_out_frame(
    dev: &narf_drivers_usb::device::USBDevice,
    ep_addr: u8,
    frame: &[u8],
) -> Result<usize, narf_drivers_usb::device::UsbError> {
    narf_drivers_usb::bulk::bulk_out(dev, ep_addr, frame).await
}

/// Receive a single bulk-IN frame (one RxDesc16 + MPDU). `out` is
/// sized to the maximum URB length the chip will deliver
/// (RxDesc16 + jumbo). Returns the bytes copied.
pub async fn bulk_in_frame(
    dev: &narf_drivers_usb::device::USBDevice,
    ep_addr: u8,
    out: &mut [u8],
) -> Result<usize, narf_drivers_usb::device::UsbError> {
    narf_drivers_usb::bulk::bulk_in(dev, ep_addr, out).await
}

/// Pre-post + poll the 56-byte interrupt-IN status notification. Used
/// by the rtl8xxxu watcher to surface TX_OK / RX_AVL / C2H events.
///
/// `ep_addr` is the USB-side endpoint address (bit 7 set: IN).
pub fn arm_intr_in(
    dev: &narf_drivers_usb::device::USBDevice,
    ep_addr: u8,
) -> Result<u64, narf_drivers_usb::device::UsbError> {
    narf_drivers_usb::intr::arm(dev, ep_addr, USB_INTR_CONTENT_LEN as u32)
}

/// Non-blocking drain of the most recent 56-byte interrupt-IN frame
/// into an [`IntrIn`]. `Ok(Some(_))` when a fresh frame arrived;
/// `Ok(None)` when no event has been demuxed for this endpoint yet.
pub fn poll_intr_in(
    dev: &narf_drivers_usb::device::USBDevice,
    ep_addr: u8,
) -> Result<Option<IntrIn>, narf_drivers_usb::device::UsbError> {
    let mut buf = [0u8; USB_INTR_CONTENT_LEN];
    match narf_drivers_usb::intr::poll(dev, ep_addr, &mut buf)? {
        Some(n) if n == USB_INTR_CONTENT_LEN => Ok(Some(IntrIn { data: buf })),
        Some(_) => Ok(None),
        None => Ok(None),
    }
}

/// Upload a firmware blob via bulk-OUT. The Realtek 8051 MCU expects
/// the blob in MaxPacket-sized chunks; the wrapper handles that.
pub async fn upload_firmware(
    dev: &narf_drivers_usb::device::USBDevice,
    ep_addr: u8,
    blob: &[u8],
    max_packet: u16,
) -> Result<usize, narf_drivers_usb::firmware::FirmwareError> {
    narf_drivers_usb::firmware::upload_default(dev, ep_addr, blob, max_packet).await
}
