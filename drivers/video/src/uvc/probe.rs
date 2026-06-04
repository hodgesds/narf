//! USB class 0x0E match + interface enumeration.
//!
//! Walks a USB configuration descriptor blob to locate the Video Control
//! (VC) and Video Streaming (VS) interface pair and returns a [`UvcProbeResult`]
//! carrying the interface numbers and the raw class-specific descriptor blobs
//! for each.
//!
//! Linux reference: `drivers/media/usb/uvc/uvc_driver.c`
//! `uvc_probe()` (around line 1800) — checks `intf->altsetting[0].desc`
//! against `bInterfaceClass == USB_CLASS_VIDEO` and then delegates to
//! `uvc_parse_control()` / `uvc_parse_streaming()`.

use super::descriptor::{
    USB_CLASS_VIDEO, USB_VIDEO_SUBCLASS_VIDEOCONTROL, USB_VIDEO_SUBCLASS_VIDEOSTREAMING,
};
use alloc::vec::Vec;

/// Error type for the probe walk.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Configuration descriptor is too short or malformed.
    MalformedConfig,
    /// No USB Video Class VideoControl interface found — not a UVC device.
    NotUvc,
    /// VideoControl interface found but no VideoStreaming interface present.
    NoStreamingInterface,
}

/// Endpoint descriptor found during probe.
#[derive(Copy, Clone, Debug)]
pub struct EndpointInfo {
    /// USB endpoint address (including direction bit).
    pub address: u8,
    /// bmAttributes — bits 1:0 encode transfer type:
    /// 0=Control, 1=Iso, 2=Bulk, 3=Interrupt.
    pub attributes: u8,
    /// wMaxPacketSize in bytes.
    pub max_packet_size: u16,
    /// DCI = (ep_number * 2) + direction_bit.  Stored for xHCI use.
    pub dci: u8,
}

impl EndpointInfo {
    /// True iff this is an isochronous IN endpoint.
    pub fn is_iso_in(&self) -> bool {
        self.attributes & 0x03 == 1 && self.address & 0x80 != 0
    }

    /// True iff this is a bulk IN endpoint.
    pub fn is_bulk_in(&self) -> bool {
        self.attributes & 0x03 == 2 && self.address & 0x80 != 0
    }
}

/// Result of a successful UVC probe.
#[derive(Clone, Debug)]
pub struct UvcProbeResult {
    /// `bInterfaceNumber` of the VideoControl interface.
    pub vc_interface: u8,
    /// Class-specific descriptor blob for the VC interface.
    pub vc_cs_blob: Vec<u8>,

    /// `bInterfaceNumber` of the primary VideoStreaming interface.
    pub vs_interface: u8,
    /// Class-specific descriptor blob for the VS interface.
    pub vs_cs_blob: Vec<u8>,

    /// Isochronous IN endpoint in the VS interface, if present.
    pub iso_in: Option<EndpointInfo>,
    /// Bulk IN endpoint in the VS interface, if present (fallback path).
    pub bulk_in: Option<EndpointInfo>,
}

/// Walk a raw USB configuration descriptor blob.
///
/// `cfg` must be the full configuration descriptor starting from the
/// wTotalLength-bounded bDescriptorType=0x02 header. Returns the first
/// UVC VideoControl/VideoStreaming pair found.
///
/// This mirrors the interface-enumeration walk in Linux
/// `uvc_probe()` → `usb_ifnum_to_if()` + `uvc_parse_control()` in
/// `uvc_driver.c` around lines 1800-1840.
pub fn probe_uvc(cfg: &[u8]) -> Result<UvcProbeResult, ProbeError> {
    if cfg.len() < 9 {
        return Err(ProbeError::MalformedConfig);
    }

    let mut vc_iface_num: Option<u8> = None;
    let mut vc_cs_blob: Vec<u8> = Vec::new();
    let mut vs_iface_num: Option<u8> = None;
    let mut vs_cs_blob: Vec<u8> = Vec::new();
    let mut iso_in: Option<EndpointInfo> = None;
    let mut bulk_in: Option<EndpointInfo> = None;

    // Current interface context.
    let mut cur_class: u8 = 0;
    let mut cur_subclass: u8 = 0;
    #[allow(unused_assignments)]
    let mut cur_iface: u8 = 0;

    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let blen = cfg[i] as usize;
        if blen < 2 || i + blen > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];

        match desc_type {
            // ── Interface descriptor (bDescriptorType = 0x04) ────────
            0x04 if blen >= 9 => {
                cur_iface = cfg[i + 2];
                cur_class = cfg[i + 5];
                cur_subclass = cfg[i + 6];

                if cur_class == USB_CLASS_VIDEO
                    && cur_subclass == USB_VIDEO_SUBCLASS_VIDEOCONTROL
                    && vc_iface_num.is_none()
                {
                    vc_iface_num = Some(cur_iface);
                }
                if cur_class == USB_CLASS_VIDEO
                    && cur_subclass == USB_VIDEO_SUBCLASS_VIDEOSTREAMING
                    && vs_iface_num.is_none()
                {
                    vs_iface_num = Some(cur_iface);
                }
            }

            // ── Class-specific interface descriptor (0x24) ──────────
            0x24 if blen >= 3 => {
                if cur_class == USB_CLASS_VIDEO {
                    if cur_subclass == USB_VIDEO_SUBCLASS_VIDEOCONTROL {
                        vc_cs_blob.extend_from_slice(&cfg[i..i + blen]);
                    } else if cur_subclass == USB_VIDEO_SUBCLASS_VIDEOSTREAMING {
                        vs_cs_blob.extend_from_slice(&cfg[i..i + blen]);
                    }
                }
            }

            // ── Endpoint descriptor (0x05) ───────────────────────────
            0x05 if blen >= 7 => {
                if cur_class == USB_CLASS_VIDEO && cur_subclass == USB_VIDEO_SUBCLASS_VIDEOSTREAMING
                {
                    let ep_addr = cfg[i + 2];
                    let attrs = cfg[i + 3];
                    let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                    let ep_num = ep_addr & 0x0F;
                    let dir_bit = if ep_addr & 0x80 != 0 { 1u8 } else { 0u8 };
                    let dci = ep_num * 2 + dir_bit;
                    let ep = EndpointInfo {
                        address: ep_addr,
                        attributes: attrs,
                        max_packet_size: mps,
                        dci,
                    };

                    if ep.is_iso_in() && iso_in.is_none() {
                        iso_in = Some(ep);
                    } else if ep.is_bulk_in() && bulk_in.is_none() {
                        bulk_in = Some(ep);
                    }
                }
            }

            _ => {}
        }

        i += blen;
    }

    let vc_interface = vc_iface_num.ok_or(ProbeError::NotUvc)?;
    let vs_interface = vs_iface_num.ok_or(ProbeError::NoStreamingInterface)?;

    Ok(UvcProbeResult {
        vc_interface,
        vc_cs_blob,
        vs_interface,
        vs_cs_blob,
        iso_in,
        bulk_in,
    })
}

/// Check whether a raw interface descriptor matches USB Video Class.
///
/// Useful as a quick guard before running the full `probe_uvc()` walk.
pub fn is_video_interface(interface_class: u8, interface_sub_class: u8) -> bool {
    interface_class == USB_CLASS_VIDEO
        && (interface_sub_class == USB_VIDEO_SUBCLASS_VIDEOCONTROL
            || interface_sub_class == USB_VIDEO_SUBCLASS_VIDEOSTREAMING)
}
