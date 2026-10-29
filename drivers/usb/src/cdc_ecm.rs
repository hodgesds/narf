//! USB CDC Ethernet Control Model (ECM) 1.2 — clean-room.
//!
//! References (public-only):
//! - **USB Ethernet Control Model (ECM) Specification, Revision
//!   1.2** (USB-IF, February 2007). Public, usb.org. §5.4
//!   (Ethernet Networking Functional Descriptor), §6.2
//!   (class-specific requests).
//!   <https://www.usb.org/document-library/class-definitions-communication-devices-12>
//! - **USB Class Definitions for Communications Devices, Revision
//!   1.2, Errata 1** (USB-IF, November 2010 / errata July 2012).
//!   Public. §3 (architecture), §5.2.3 (functional descriptors),
//!   §6.2 (common class-specific requests), §6.3 (notifications).
//! - **USB Specification 2.0** §9 (standard descriptors). Public.
//!
//! No GPL Linux source consulted.
//!
//! ## Why ECM, and how it differs from NCM
//!
//! ECM is the older USB-Ethernet model: the one ECM-only dongles,
//! docks, and tethered phones speak. Where NCM batches Ethernet
//! datagrams into NTB framing (`cdc_ncm`), ECM carries **one raw
//! Ethernet frame per bulk transfer, with no framing at all** —
//! no NTH/NDP headers, no sequence numbers, no CRC mode, no
//! `GET_NTB_PARAMETERS` negotiation, and no `GET_NET_ADDRESS`
//! (that request is NCM-only). A driver that wrapped ECM frames
//! in NTBs — or stripped CRCs that were never appended — would
//! corrupt every frame. The two models share only the CDC-common
//! layer, and this module reuses exactly that:
//!
//! **Shared with NCM (not duplicated):**
//! - `EthernetNetworkingDescriptor::parse` — ECM 1.2 §5.4 is
//!   ECM's *own* descriptor; NCM reuses it for the MAC slot.
//! - `parse_mac_string_descriptor` / `is_valid_station_address` —
//!   the iMACAddress string is ECM's *only* station-address
//!   source (ECM has no `GET_NET_ADDRESS`).
//! - `REQ_SET_PACKET_FILTER` + `PacketFilter::NORMAL` — CDC 1.2
//!   §6.2.4, a CDC-common request, not an NCM one.
//! - The config-walking idiom, the netdev publication pattern
//!   (`register_with_context` / `on_rx_frame_from` /
//!   `unregister`), the attach-cascade bind shape, and the RX
//!   pump shape from `cdc_ncm`.
//!
//! **ECM-only (new here, never taken from NCM):**
//! - The Comm-interface finder (subclass `0x06`, not `0x0D`),
//!   the Union-aware bulk-endpoint selection, the notification
//!   endpoint finder, and the notification decoder below.
//! - The datapath itself: TX sends the frame verbatim (bounded
//!   only by `wMaxSegmentSize`); RX treats each bulk-IN transfer
//!   as exactly one frame. There is no FCS handling: USB ECM
//!   frames carry no FCS.
//!
//! ## Notification model
//!
//! The Comm interface's interrupt-IN endpoint delivers CDC §6.3
//! notifications: an 8-byte header (`bmRequestType`, code,
//! `wValue`, `wIndex`, `wLength`, all little-endian) followed by
//! `wLength` payload bytes. ECM uses three codes:
//!
//! - `NETWORK_CONNECTION` (`0x00`): `wValue` bit 0 set ↔ link
//!   up (same rule as the ACM module's decoder).
//! - `RESPONSE_AVAILABLE` (`0x01`): an encapsulated response is
//!   waiting. ECM uses no encapsulated commands, so this is
//!   decoded and ignored.
//! - `CONNECTION_SPEED_CHANGE` (`0x0A`): 8-byte payload,
//!   downlink bitrate `u32` LE followed by uplink bitrate `u32`
//!   LE. Stored on the device record for diagnostics; it does
//!   not gate the datapath.

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use super::cdc::{CdcError, FunctionalSubtype, UnionDescriptor, CDC_SUBCLASS_ENCM};
use super::cdc_ncm::{
    is_valid_station_address, parse_mac_string_descriptor, EthernetNetworkingDescriptor,
    PacketFilter, REQ_SET_PACKET_FILTER,
};
use super::xhci::{EndpointConfig, EndpointKind};

// ── ECM class-specific request codes (ECM 1.2 §6.2, CDC 1.2 §6.2) ──

/// `SET_ETHERNET_PACKET_FILTER` — CDC 1.2 §6.2.4, shared with NCM
/// (re-exported from `cdc_ncm` so there is exactly one source).
pub use super::cdc_ncm::REQ_SET_PACKET_FILTER as REQ_SET_ETHERNET_PACKET_FILTER;

// ── ECM notification codes (CDC 1.2 §6.3) ───────────────────────────

/// `NETWORK_CONNECTION` notification code.
pub const NOTIFICATION_NETWORK_CONNECTION: u8 = 0x00;
/// `RESPONSE_AVAILABLE` notification code.
pub const NOTIFICATION_RESPONSE_AVAILABLE: u8 = 0x01;
/// `CONNECTION_SPEED_CHANGE` notification code.
pub const NOTIFICATION_CONNECTION_SPEED_CHANGE: u8 = 0x0A;

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EcmError {
    /// Buffer too short for the structure being decoded.
    Truncated,
    /// The device's descriptors didn't include a CDC-Comm /
    /// ECM (subclass 0x06) interface — not an ECM device.
    NotEcm,
    /// SET_CONFIGURATION control transfer failed during bind.
    SetConfigFailed,
    /// The iMACAddress string descriptor yielded no valid station
    /// address during bind. The bind fails rather than inventing
    /// an address.
    NoMacAddress,
    /// No CDC-Data interface with a bulk IN/OUT pair was found.
    NoBulkEndpoints,
    /// A TX frame exceeds the device's `wMaxSegmentSize`.
    FrameTooLarge,
    /// No xHCI controller is available for a transfer.
    NoController,
    /// The device record is detached (or missing) — no transfer.
    NotBound,
}

// ── Notification decoder ─────────────────────────────────────────────

/// Decoded notification packet from the CDC-Comm notification IN
/// endpoint. Wire format is the 8-byte header followed by
/// `wLength` data bytes (see the module docs).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EcmNotification {
    /// `NETWORK_CONNECTION` — `wValue` bit 0 set ↔ link up.
    NetworkConnection { up: bool },
    /// `RESPONSE_AVAILABLE` — no encapsulated commands in ECM;
    /// decoded and ignored by the pump.
    ResponseAvailable,
    /// `CONNECTION_SPEED_CHANGE` — 8-byte payload: downlink
    /// bitrate `u32` LE, then uplink bitrate `u32` LE.
    ConnectionSpeedChange { downlink_bps: u32, uplink_bps: u32 },
    /// Notification code the parser doesn't decode further.
    Unknown { code: u8, value: u16, index: u16 },
}

impl EcmNotification {
    pub fn decode(packet: &[u8]) -> Result<Self, CdcError> {
        if packet.len() < 8 {
            return Err(CdcError::Short);
        }
        let code = packet[1];
        let value = u16::from_le_bytes([packet[2], packet[3]]);
        let index = u16::from_le_bytes([packet[4], packet[5]]);
        let length = u16::from_le_bytes([packet[6], packet[7]]) as usize;
        if packet.len() < 8 + length {
            return Err(CdcError::Truncated);
        }
        Ok(match code {
            NOTIFICATION_NETWORK_CONNECTION => {
                EcmNotification::NetworkConnection { up: value & 1 != 0 }
            }
            NOTIFICATION_RESPONSE_AVAILABLE => EcmNotification::ResponseAvailable,
            NOTIFICATION_CONNECTION_SPEED_CHANGE => {
                if length < 8 {
                    return Err(CdcError::Truncated);
                }
                EcmNotification::ConnectionSpeedChange {
                    downlink_bps: u32::from_le_bytes([
                        packet[8], packet[9], packet[10], packet[11],
                    ]),
                    uplink_bps: u32::from_le_bytes([
                        packet[12], packet[13], packet[14], packet[15],
                    ]),
                }
            }
            other => EcmNotification::Unknown {
                code: other,
                value,
                index,
            },
        })
    }
}

// ── Config-blob walkers ──────────────────────────────────────────────
//
// All walkers take a raw configuration descriptor blob and never
// touch hardware, so they are directly unit-testable against
// modelled descriptors. Descriptor walking idiom mirrors
// `cdc_ncm`: `len` guards every step; a malformed block ends
// the walk instead of panicking.

/// Find the first CDC-Comm interface with subclass ECM (0x06) in
/// `cfg`. Returns its `bInterfaceNumber`. An NCM (0x0D) or ACM
/// (0x02) Comm interface does not match — this is what keeps
/// the attach cascade's ECM attempt from claiming NCM devices
/// (and vice versa: NCM's finder requires 0x0D).
pub fn find_ecm_comm_interface(cfg: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 0x04 && len >= 9 {
            let cls = cfg[i + 5];
            let sub = cfg[i + 6];
            if cls == super::cdc::USB_CLASS_CDC_COMM && sub == CDC_SUBCLASS_ENCM {
                return Some(cfg[i + 2]);
            }
        }
        i += len;
    }
    None
}

/// Locate the Union + Ethernet Networking functional descriptors
/// in the descriptor set that follows the Comm interface
/// `comm_iface` within `cfg`. Either may be absent on malformed
/// firmware; the caller decides what is fatal (Union is not —
/// see the bulk-endpoint fallback; the Ethernet Networking
/// descriptor is, because it carries the MAC string index).
pub fn find_ecm_functional_descriptors(
    cfg: &[u8],
    comm_iface: u8,
) -> (
    Option<UnionDescriptor>,
    Option<EthernetNetworkingDescriptor>,
) {
    let mut in_comm = false;
    let mut union = None;
    let mut eth = None;
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            // INTERFACE descriptor — byte 2 is bInterfaceNumber.
            in_comm = cfg[i + 2] == comm_iface;
        } else if desc_type == 0x24 && in_comm {
            let chunk = &cfg[i..i + len];
            match FunctionalSubtype::decode(chunk[2]) {
                FunctionalSubtype::Union => {
                    if union.is_none() {
                        union = UnionDescriptor::parse(chunk).ok();
                    }
                }
                FunctionalSubtype::EthernetNetworking => {
                    if eth.is_none() {
                        eth = EthernetNetworkingDescriptor::parse(chunk).ok();
                    }
                }
                _ => {}
            }
        }
        i += len;
    }
    (union, eth)
}

/// One CDC-Data interface's bulk pair as seen while walking.
struct DataPair {
    num: u8,
    bulk_in: Option<EndpointConfig>,
    bulk_out: Option<EndpointConfig>,
}

/// Walk the config blob for the CDC-Data interface that belongs
/// to the ECM function on Comm interface `comm_iface`, and
/// return its (interface_number, bulk_in_ep, bulk_out_ep).
///
/// Selection rule: the Union descriptor is authoritative (CDC
/// 1.2 §5.2.3.2 groups one control interface with its
/// subordinate data interfaces). If the Union names a
/// subordinate Data interface that carries a complete bulk pair,
/// that interface wins — even when another Data interface
/// appears earlier or later in the blob (composite trap). With
/// no usable Union, the first Data interface *after* the Comm
/// interface with a complete pair wins. Data interfaces before
/// the Comm interface belong to another function and never win.
///
/// Alt-setting rule, mirroring the NCM walker: within one
/// interface number, the *last* alt setting seen wins its pair
/// (the standard ECM layout is alt 0 with no endpoints, then
/// alt 1 with the bulk pair).
pub fn find_ecm_bulk_endpoints(
    cfg: &[u8],
    comm_iface: u8,
) -> Option<(u8, EndpointConfig, EndpointConfig)> {
    let (union, _) = find_ecm_functional_descriptors(cfg, comm_iface);
    let union_subs: Vec<u8> = union.map(|u| u.subordinate_interfaces).unwrap_or_default();

    let mut seen_comm = false;
    let mut current_data: Option<usize> = None;
    let mut datas: Vec<DataPair> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            let num = cfg[i + 2];
            let cls = cfg[i + 5];
            if num == comm_iface {
                seen_comm = true;
                current_data = None;
            } else if seen_comm && cls == super::cdc::USB_CLASS_CDC_DATA {
                // New (or new alt of a) Data interface: last alt
                // wins its pair, so reset on a repeat number.
                match datas.iter_mut().find(|d| d.num == num) {
                    Some(d) => {
                        d.bulk_in = None;
                        d.bulk_out = None;
                        current_data = datas.iter().position(|d| d.num == num);
                    }
                    None => {
                        datas.push(DataPair {
                            num,
                            bulk_in: None,
                            bulk_out: None,
                        });
                        current_data = Some(datas.len() - 1);
                    }
                }
            } else {
                current_data = None;
            }
        } else if desc_type == 0x05 && len >= 7 {
            if let Some(di) = current_data {
                let ep_addr = cfg[i + 2];
                let attrs = cfg[i + 3];
                let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF;
                let is_in = ep_addr & 0x80 != 0;
                // Bulk = transfer type 2 in attrs[1:0].
                if attrs & 0x03 == 2 {
                    let kind = if is_in {
                        EndpointKind::BulkIn
                    } else {
                        EndpointKind::BulkOut
                    };
                    let cfg_ep = EndpointConfig {
                        ep_addr,
                        max_packet,
                        kind,
                        interval: 0,
                    };
                    if is_in {
                        datas[di].bulk_in = Some(cfg_ep);
                    } else {
                        datas[di].bulk_out = Some(cfg_ep);
                    }
                }
            }
        }
        i += len;
    }
    // Union-authoritative selection first, then first complete
    // pair in descriptor order.
    let complete = |d: &DataPair| d.bulk_in.is_some() && d.bulk_out.is_some();
    let picked = union_subs
        .iter()
        .filter_map(|sub| datas.iter().find(|d| d.num == *sub && complete(d)))
        .next()
        .or_else(|| datas.iter().find(|d| complete(d)));
    picked.map(|d| {
        (
            d.num,
            d.bulk_in.expect("complete pair"),
            d.bulk_out.expect("complete pair"),
        )
    })
}

/// Find the endpoint-bearing alt setting of a CDC-Data interface:
/// the first Data interface (class 0x0A) under which a bulk
/// endpoint appears. Returns (interface_number, alt_setting).
/// Mirrors `find_ncm_data_alt_setting`.
pub fn find_ecm_data_alt_setting(cfg: &[u8]) -> Option<(u8, u8)> {
    let mut current: Option<(u8, u8, bool)> = None; // (num, alt, is_data)
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            current = Some((
                cfg[i + 2],
                cfg[i + 3],
                cfg[i + 5] == super::cdc::USB_CLASS_CDC_DATA,
            ));
        } else if desc_type == 0x05 && len >= 7 {
            if let Some((num, alt, true)) = current {
                // Bulk endpoint under the current Data interface.
                if cfg[i + 3] & 0x03 == 2 {
                    return Some((num, alt));
                }
            }
        }
        i += len;
    }
    None
}

/// Find the Comm interface's notification (interrupt-IN)
/// endpoint, if the function exposes one. Returns its
/// `EndpointConfig` (kind `InterruptIn`, interval from the
/// descriptor). A missing notification endpoint is not fatal:
/// the datapath works without link-state updates.
pub fn find_ecm_notification_endpoint(cfg: &[u8], comm_iface: u8) -> Option<EndpointConfig> {
    let mut in_comm = false;
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            in_comm = cfg[i + 2] == comm_iface;
        } else if desc_type == 0x05 && len >= 7 && in_comm {
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let is_in = ep_addr & 0x80 != 0;
            // Interrupt = transfer type 3 in attrs[1:0].
            if is_in && attrs & 0x03 == 3 {
                return Some(EndpointConfig {
                    ep_addr,
                    max_packet: u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF,
                    kind: EndpointKind::InterruptIn,
                    interval: cfg[i + 6],
                });
            }
        }
        i += len;
    }
    None
}

// ── Pure datapath helpers ────────────────────────────────────────────
//
// These carry the ECM framing rules with no hardware attached, so
// the kernel-test smokes pin them exactly. The live pump/TX paths
// call these, they do not re-implement the rules.

/// Validate a TX frame against the device's `wMaxSegmentSize`
/// and return it verbatim. ECM has no framing: the frame goes on
/// the wire byte-for-byte, with no NTB header, no sequence, and
/// no CRC appended. A zero `max_segment_size` means the device
/// reported no cap — no limit is applied. An over-cap frame is
/// rejected, never truncated.
pub fn ecm_tx_frame(frame: &[u8], max_segment_size: u16) -> Result<&[u8], EcmError> {
    if max_segment_size > 0 && frame.len() > max_segment_size as usize {
        return Err(EcmError::FrameTooLarge);
    }
    Ok(frame)
}

/// Interpret one bulk-IN transfer as an ECM frame: exactly one
/// frame per transfer, no reassembly, no splitting. An empty
/// transfer yields `None` (the pump yields and retries); a
/// length beyond the buffer is impossible from the controller
/// and yields `None` rather than a torn frame.
pub fn ecm_rx_transfer(buf: &[u8], n: usize) -> Option<&[u8]> {
    if n == 0 || n > buf.len() {
        None
    } else {
        Some(&buf[..n])
    }
}

/// RX buffer size for a device reporting `max_segment_size`:
/// the cap itself, clamped to a sane window (a 1518-byte floor
/// covers a full-size Ethernet frame even when firmware reports
/// a degenerate cap; 64 KiB ceiling bounds the allocation). A
/// zero cap means "no info" — fall back to 16 KiB.
///
/// Takes `u32` (not the descriptor's `u16`) so the ceiling arm
/// is reachable and testable — a `u16` input could never exceed
/// it.
pub fn ecm_rx_buf_len(max_segment_size: u32) -> usize {
    if max_segment_size == 0 {
        16384
    } else {
        (max_segment_size as usize).clamp(1518, 65535)
    }
}

// ── Device record + registry ─────────────────────────────────────────

/// One bound CDC-ECM device.
#[derive(Debug)]
pub struct CdcEcmDevice {
    pub slot_id: u8,
    /// `bInterfaceNumber` of the CDC-Comm/ECM interface.
    pub comm_iface: u8,
    /// `bInterfaceNumber` of the CDC-Data interface (where the
    /// bulk endpoints live). 0xFF means "not yet enumerated".
    pub data_iface: u8,
    /// DCI of the bulk-IN endpoint. 0 = not enumerated.
    pub bulk_in_dci: u8,
    /// DCI of the bulk-OUT endpoint.
    pub bulk_out_dci: u8,
    /// DCI of the notification interrupt-IN endpoint.
    /// 0 = the function exposes none; no notification pump runs.
    pub notif_dci: u8,
    /// Station address read from the device at bind (the
    /// iMACAddress string descriptor — ECM's only source).
    pub mac: [u8; 6],
    /// `wMaxSegmentSize` from the Ethernet Networking descriptor
    /// (0 = device reported no cap).
    pub max_segment_size: u16,
    /// Assigned `narf_net::iface` name (`usb-ecm{N}`).
    pub iface_name: String,
    /// RX pump liveness flag (pump clears it on exit).
    pub pump_running: bool,
    /// Notification pump liveness flag (pump clears it on exit).
    pub notif_running: bool,
    /// Last reported link state (NETWORK_CONNECTION). Starts
    /// down; the datapath does not wait for link-up.
    pub link_up: bool,
    /// Last reported link speeds (CONNECTION_SPEED_CHANGE).
    pub downlink_bps: u32,
    /// Last reported link speeds (CONNECTION_SPEED_CHANGE).
    pub uplink_bps: u32,
    /// Detach tombstone: set by `detach_ecm_slot`. Pumps exit
    /// when they see it; TX/RX resolve to `NotBound`. Records
    /// are never removed, because net-registry TX cookies are
    /// record indices — removing a record would retarget every
    /// later device's cookie at the wrong device.
    pub detached: bool,
}

/// System-wide registry of bound CDC-ECM devices.
pub static CDC_ECM_DEVICES: IrqSafeSpinLock<Vec<CdcEcmDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Number of live (non-detached) ECM devices.
pub fn attached_ecm_count() -> usize {
    CDC_ECM_DEVICES
        .lock()
        .iter()
        .filter(|d| !d.detached)
        .count()
}

#[doc(hidden)]
pub fn __reset_ecm_for_test() {
    CDC_ECM_DEVICES.lock().clear();
}

// ── Live bind ────────────────────────────────────────────────────────

/// Fetch the iMACAddress string descriptor (`index`) from the
/// device and decode it. Mirrors the NCM helper: the LANGID is
/// read from the string-0 table first, falling back to en-US
/// (0x0409). Index 0 means "no string" and yields `None`.
async fn fetch_mac_string(xhci_dev: &crate::xhci::Xhci, slot_id: u8, index: u8) -> Option<[u8; 6]> {
    if index == 0 {
        return None;
    }
    let mut lang = [0u8; 4];
    let langid = match xhci_dev
        .control_in(slot_id, 0x80, 6, 0x0300, 0, &mut lang)
        .await
    {
        Ok(n) if n >= 4 => u16::from_le_bytes([lang[2], lang[3]]),
        _ => 0x0409,
    };
    let mut buf = [0u8; 64];
    let n = xhci_dev
        .control_in(slot_id, 0x80, 6, 0x0300 | index as u16, langid, &mut buf)
        .await
        .ok()?;
    parse_mac_string_descriptor(&buf[..n])
}

/// Bind an already-addressed ECM device: SET_CONFIGURATION,
/// Data alt-setting activation, bulk-pair (+ notification
/// endpoint, when present) configuration, station-address
/// acquisition, packet-filter programming, netdev publication,
/// and pump spawn.
///
/// Station address comes ONLY from the iMACAddress string
/// descriptor. ECM defines no `GET_NET_ADDRESS` request — the
/// NCM-only request must never be issued here; a device that
/// yields no valid address fails the bind rather than getting
/// an invented address.
///
/// `SET_ETHERNET_PACKET_FILTER` failure is tolerated (the
/// device keeps its default filter); the datapath does not
/// depend on it. A missing notification endpoint is tolerated
/// the same way: the datapath runs, link state just stays at
/// its initial values.
pub async fn try_bind_ecm_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, EcmError> {
    let comm_iface = find_ecm_comm_interface(cfg).ok_or(EcmError::NotEcm)?;
    let cfg_value = if cfg.len() >= 9 { cfg[5] } else { 1 };
    if xhci_dev
        .control_out(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .is_err()
    {
        return Err(EcmError::SetConfigFailed);
    }
    // Find the CDC-Data interface + its bulk endpoint pair. The
    // Union-aware selection handles composites; the fallback
    // covers functions that omit the Union descriptor.
    let (data_iface, bulk_in_ep, bulk_out_ep) = match find_ecm_bulk_endpoints(cfg, comm_iface) {
        Some(t) => t,
        None => return Err(EcmError::NoBulkEndpoints),
    };
    // Activate the data interface's endpoint-bearing alt setting
    // (commonly alt 1; alt 0 carries no endpoints and leaves the
    // data pipe inert on real firmware).
    if let Some((alt_iface, alt)) = find_ecm_data_alt_setting(cfg) {
        if alt > 0 {
            let _ = xhci_dev
                .control_out(slot_id, 0x01, 0x0B, alt as u16, alt_iface as u16, &[])
                .await;
        }
    }
    let notif_ep = find_ecm_notification_endpoint(cfg, comm_iface);
    // Configure the bulk pair (+ notification endpoint when the
    // function exposes one) so the controller wires up its
    // Transfer Rings. Mirrors the NCM/MSC bind path.
    let mut eps = alloc::vec![bulk_in_ep, bulk_out_ep];
    if let Some(ep) = notif_ep {
        eps.push(ep);
    }
    if xhci_dev.configure_endpoints(slot_id, &eps).await.is_err() {
        return Err(EcmError::SetConfigFailed);
    }
    let bulk_in_dci = ((bulk_in_ep.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = (bulk_out_ep.ep_addr & 0x0F) * 2;
    let notif_dci = notif_ep
        .map(|ep| ((ep.ep_addr & 0x0F) * 2) + 1)
        .unwrap_or(0);

    // Functional descriptors drive MAC acquisition. The Ethernet
    // Networking descriptor is required: without it there is no
    // iMACAddress index and therefore no station address.
    let (_, eth_desc) = find_ecm_functional_descriptors(cfg, comm_iface);
    let eth = eth_desc.ok_or(EcmError::NoMacAddress)?;
    let mac = fetch_mac_string(xhci_dev, slot_id, eth.mac_string_index)
        .await
        .ok_or(EcmError::NoMacAddress)?;
    if !is_valid_station_address(&mac) {
        return Err(EcmError::NoMacAddress);
    }

    // Normal receive filtering (directed + broadcast + multicast).
    // Best-effort: a device that refuses the request keeps its
    // default filter and the datapath still works.
    let _ = xhci_dev
        .control_out(
            slot_id,
            0x21,
            REQ_SET_PACKET_FILTER,
            PacketFilter::NORMAL.encode(),
            comm_iface as u16,
            &[],
        )
        .await;

    let idx = {
        let mut g = CDC_ECM_DEVICES.lock();
        let idx = g.len();
        g.push(CdcEcmDevice {
            slot_id,
            comm_iface,
            data_iface,
            bulk_in_dci,
            bulk_out_dci,
            notif_dci,
            mac,
            max_segment_size: eth.max_segment_size,
            iface_name: alloc::format!("usb-ecm{}", idx),
            pump_running: false,
            notif_running: false,
            link_up: false,
            downlink_bps: 0,
            uplink_bps: 0,
            detached: false,
        });
        idx
    };
    // Publish with per-device TX routing: the registration cookie
    // is this record's index, and the send hook resolves it back
    // to this device — and only this device.
    let assigned = register_ecm_iface(idx, mac);
    {
        let mut g = CDC_ECM_DEVICES.lock();
        g[idx].iface_name = assigned;
        g[idx].pump_running = true;
        g[idx].notif_running = notif_dci != 0;
    }
    // Pre-arm the notification endpoint so the controller starts
    // polling the device for link events. Failure only disables
    // link-state updates; the datapath is unaffected.
    if notif_dci != 0 {
        let max_packet = notif_ep.map(|ep| ep.max_packet).unwrap_or(16);
        if xhci_dev
            .arm_interrupt_in(slot_id, notif_dci, max_packet.min(64) as u32)
            .is_err()
        {
            let mut g = CDC_ECM_DEVICES.lock();
            if let Some(dev) = g.get_mut(idx) {
                dev.notif_running = false;
            }
        }
    }
    narf_scheduler::spawn(async move {
        ecm_rx_pump(idx).await;
    });
    if notif_dci != 0 {
        narf_scheduler::spawn(async move {
            ecm_notif_pump(idx).await;
        });
    }
    Ok(idx)
}

/// Supervised RX pump for one bound ECM device: post bulk-IN
/// reads sized by the device's segment cap, and hand each
/// transfer to the stack as exactly one Ethernet frame — ECM
/// has no NTB to walk and no FCS to strip. Stops after a
/// bounded run of consecutive transfer errors (a removed device
/// surfaces as persistent errors) or when the record vanishes
/// or is detached.
async fn ecm_rx_pump(idx: usize) {
    let (slot_id, bulk_in_dci, name, buf_len) = {
        let g = CDC_ECM_DEVICES.lock();
        let Some(dev) = g.get(idx).filter(|d| !d.detached) else {
            return;
        };
        (
            dev.slot_id,
            dev.bulk_in_dci,
            dev.iface_name.clone(),
            ecm_rx_buf_len(dev.max_segment_size as u32),
        )
    };
    let Some(c) = crate::xhci::controller() else {
        let mut g = CDC_ECM_DEVICES.lock();
        if let Some(dev) = g.get_mut(idx) {
            dev.pump_running = false;
        }
        return;
    };
    let mut buf = alloc::vec![0u8; buf_len];
    let mut errors = 0u32;
    loop {
        // Detach check each iteration: the pump must not deliver
        // frames for a device whose iface was unregistered.
        {
            let g = CDC_ECM_DEVICES.lock();
            if g.get(idx).map(|d| d.detached).unwrap_or(true) {
                break;
            }
        }
        match c.bulk_in(slot_id, bulk_in_dci, &mut buf).await {
            Ok(n) => {
                errors = 0;
                if let Some(frame) = ecm_rx_transfer(&buf, n) {
                    let mut owned = frame.to_vec();
                    narf_net::iface::on_rx_frame_from(&name, &mut owned);
                } else {
                    narf_scheduler::yield_now().await;
                }
            }
            Err(_) => {
                errors += 1;
                if errors >= 16 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
        }
    }
    let mut g = CDC_ECM_DEVICES.lock();
    if let Some(dev) = g.get_mut(idx) {
        dev.pump_running = false;
    }
}

/// Notification pump for one bound ECM device: poll the
/// interrupt-IN endpoint and apply NETWORK_CONNECTION /
/// CONNECTION_SPEED_CHANGE to the record. RESPONSE_AVAILABLE and
/// unknown codes are decoded and ignored. Exits when the record
/// vanishes, is detached, or after a bounded run of errors.
async fn ecm_notif_pump(idx: usize) {
    let (slot_id, notif_dci) = {
        let g = CDC_ECM_DEVICES.lock();
        let Some(dev) = g.get(idx).filter(|d| !d.detached) else {
            return;
        };
        (dev.slot_id, dev.notif_dci)
    };
    if notif_dci == 0 {
        return;
    }
    let Some(c) = crate::xhci::controller() else {
        let mut g = CDC_ECM_DEVICES.lock();
        if let Some(dev) = g.get_mut(idx) {
            dev.notif_running = false;
        }
        return;
    };
    let mut buf = [0u8; 64];
    let mut errors = 0u32;
    loop {
        {
            let g = CDC_ECM_DEVICES.lock();
            if g.get(idx).map(|d| d.detached).unwrap_or(true) {
                break;
            }
        }
        match c.poll_interrupt_in(slot_id, notif_dci, &mut buf) {
            Ok(Some(n)) => {
                errors = 0;
                if let Ok(notif) = EcmNotification::decode(&buf[..n.min(buf.len())]) {
                    let mut g = CDC_ECM_DEVICES.lock();
                    if let Some(dev) = g.get_mut(idx) {
                        match notif {
                            EcmNotification::NetworkConnection { up } => {
                                dev.link_up = up;
                            }
                            EcmNotification::ConnectionSpeedChange {
                                downlink_bps,
                                uplink_bps,
                            } => {
                                dev.downlink_bps = downlink_bps;
                                dev.uplink_bps = uplink_bps;
                            }
                            EcmNotification::ResponseAvailable
                            | EcmNotification::Unknown { .. } => {}
                        }
                    }
                }
            }
            Ok(None) => narf_scheduler::yield_now().await,
            Err(_) => {
                errors += 1;
                if errors >= 16 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
        }
    }
    let mut g = CDC_ECM_DEVICES.lock();
    if let Some(dev) = g.get_mut(idx) {
        dev.notif_running = false;
    }
}

// ── TX / RX trampolines + detach ─────────────────────────────────────

/// Resolve a device-record index to its TX target
/// `(slot_id, bulk_out_dci)`. Detached or missing records
/// resolve to `None` — the net stack must never send to a
/// detached device, and a tombstoned index must never retarget
/// another device.
pub fn tx_target(idx: usize) -> Option<(u8, u8)> {
    let g = CDC_ECM_DEVICES.lock();
    let dev = g.get(idx).filter(|d| !d.detached)?;
    Some((dev.slot_id, dev.bulk_out_dci))
}

/// Send `eth_frame` via the bound ECM device. The frame goes on
/// bulk-OUT verbatim — no NTB wrap, no sequence, no CRC — after
/// the `wMaxSegmentSize` cap check in [`ecm_tx_frame`].
pub fn send_frame(idx: usize, eth_frame: &[u8]) -> Result<usize, EcmError> {
    let (slot_id, bulk_out_dci, max_segment_size) = {
        let g = CDC_ECM_DEVICES.lock();
        let dev = g
            .get(idx)
            .filter(|d| !d.detached)
            .ok_or(EcmError::NotBound)?;
        (dev.slot_id, dev.bulk_out_dci, dev.max_segment_size)
    };
    let frame = ecm_tx_frame(eth_frame, max_segment_size)?;
    // The net stack's `SendFn` is sync — bridge to the now-async
    // bulk_out via block_on. Safe here because the trampoline is
    // called from netstack TX paths that are not themselves inside
    // an executor poll.
    let c = crate::xhci::controller().ok_or(EcmError::NoController)?;
    let outcome =
        narf_scheduler::block_on(async move { c.bulk_out(slot_id, bulk_out_dci, frame).await });
    match outcome {
        Ok(n) => Ok(n),
        Err(_) => Err(EcmError::Truncated),
    }
}

/// Pull one Ethernet frame off the bound ECM device's bulk-IN
/// endpoint. One transfer is one frame; an empty transfer yields
/// `None`. Caller polls this periodically; on real silicon the
/// RX pump (not this call) is what streams frames in.
pub fn recv_frame(idx: usize, scratch: &mut [u8]) -> Result<Option<&[u8]>, EcmError> {
    let (slot_id, bulk_in_dci) = {
        let g = CDC_ECM_DEVICES.lock();
        let dev = g
            .get(idx)
            .filter(|d| !d.detached)
            .ok_or(EcmError::NotBound)?;
        (dev.slot_id, dev.bulk_in_dci)
    };
    // Sync entry-point on the net RX path; bridge to async bulk_in
    // via block_on. Called from non-executor contexts. Plain
    // `async` (not `async move`) so `scratch` is reborrowed into
    // the future and stays usable for the return slice below —
    // the NCM `recv_frame` shape; `async move` would move the
    // `&mut` in and E0382 on the borrow after.
    let c = crate::xhci::controller().ok_or(EcmError::NoController)?;
    let outcome =
        narf_scheduler::block_on(async { c.bulk_in(slot_id, bulk_in_dci, scratch).await });
    match outcome {
        Ok(n) => Ok(ecm_rx_transfer(scratch, n)),
        Err(_) => Err(EcmError::Truncated),
    }
}

/// Detach hook for a slot: tombstone every ECM record bound to
/// it and unregister its net iface. Pumps exit on the tombstone;
/// TX cookies for the index keep resolving to `NotBound` instead
/// of retargeting a later device (records are never removed).
/// Unknown slots no-op.
pub fn detach_ecm_slot(slot_id: u8) {
    let mut g = CDC_ECM_DEVICES.lock();
    for dev in g.iter_mut().filter(|d| d.slot_id == slot_id && !d.detached) {
        dev.detached = true;
        let _ = narf_net::iface::unregister(&dev.iface_name);
    }
}

fn ecm_send_ctx(cookie: u64, frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    match send_frame(cookie as usize, frame) {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

/// Register the ECM device at `idx` as a network interface under
/// `usb-ecm{idx}`, publishing the device-supplied station
/// address `mac`. Returns the assigned interface name.
fn register_ecm_iface(idx: usize, mac: [u8; 6]) -> String {
    let name = alloc::format!("usb-ecm{}", idx);
    narf_net::iface::register_with_context(&name, mac, idx as u64, ecm_send_ctx)
}

// ── CdcEcmIface — logical per-device interface handle ───────────────

/// Logical handle to a bound CDC-ECM device exposed to the rest of
/// the kernel as a narf-net `NetIfaceEntry`-compatible face.
///
/// After [`try_bind_ecm_already_addressed`] succeeds, callers
/// can borrow a `CdcEcmIface` via [`CdcEcmIface::from_idx`] to send
/// or receive Ethernet frames without going through the static
/// trampoline used during bring-up.
#[derive(Copy, Clone, Debug)]
pub struct CdcEcmIface {
    /// Index into [`CDC_ECM_DEVICES`].
    pub idx: usize,
    /// Station address read from the device at bind.
    pub mac: [u8; 6],
}

impl CdcEcmIface {
    /// Construct from a bound-device index. Returns `None` if `idx`
    /// is out of range or the record is detached.
    pub fn from_idx(idx: usize) -> Option<Self> {
        let g = CDC_ECM_DEVICES.lock();
        let dev = g.get(idx).filter(|d| !d.detached)?;
        Some(Self { idx, mac: dev.mac })
    }

    /// Send `eth_frame` via the bound ECM device. The frame goes
    /// on bulk-OUT verbatim (see [`send_frame`]).
    pub fn send(&self, eth_frame: &[u8]) -> Result<usize, EcmError> {
        send_frame(self.idx, eth_frame)
    }

    /// Receive the next Ethernet frame off the bulk-IN endpoint.
    /// `scratch` must be at least as large as the device's RX
    /// buffer (see [`ecm_rx_buf_len`]). Returns the frame slice
    /// (borrowed from `scratch`) or `None` if the transfer was
    /// empty.
    pub fn recv<'a>(&self, scratch: &'a mut [u8]) -> Result<Option<&'a [u8]>, EcmError> {
        recv_frame(self.idx, scratch)
    }
}

// ── Class-registry wiring ────────────────────────────────────────────

pub static CDC_ECM_MATCH: [crate::class_registry::UsbClassMatch; 1] = [
    // Class 2 (Comm), Subclass 6 (ECM)
    crate::class_registry::UsbClassMatch {
        vendor_id: 0,
        product_id: 0,
        class: Some(2),
        subclass: Some(6),
        protocol: None,
    },
];

pub fn probe(
    _device: alloc::sync::Arc<crate::device::USBDevice>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    use core::fmt::Write;
    let _ = writeln!(narf_console::Writer, "  usb: CDC-ECM device bound!");
    Ok(())
}

pub fn register_initcalls() {
    let _ = crate::class_registry::register_class_driver_with_unbind(
        "cdc-ecm",
        &CDC_ECM_MATCH,
        probe,
        detach_ecm_slot,
    );
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn modelled_ecm_cfg() -> Vec<u8> {
        #[rustfmt::skip]
        let cfg: &[u8] = &[
            9, 2, 0, 0, 2, 1, 0, 0x80, 0x32, // config (len patched below)
            // Comm interface 0, subclass ECM, 1 endpoint
            9, 4, 0, 0, 1, 0x02, 0x06, 0, 0,
            // Header functional descriptor, CDC 1.2
            5, 0x24, 0x00, 0x20, 0x01,
            // Union { ctrl=0, sub=1 }
            5, 0x24, 0x06, 0, 1,
            // Ethernet Networking descriptor, iMACAddress = 5,
            // stats = 0, max_segment = 1514, mc = 0, power = 0
            13, 0x24, 0x0F, 5, 0, 0, 0, 0, 0xEA, 0x05, 0, 0, 0,
            // interrupt endpoint of the Comm interface
            7, 5, 0x83, 3, 16, 0, 8,
            // Data interface 1, alt 0, no endpoints
            9, 4, 1, 0, 0, 0x0A, 0, 0, 0,
            // Data interface 1, alt 1, bulk pair
            9, 4, 1, 1, 2, 0x0A, 0, 0, 0,
            7, 5, 0x81, 2, 64, 0, 0,
            7, 5, 0x02, 2, 64, 0, 0,
        ];
        let mut v = cfg.to_vec();
        let total = v.len() as u16;
        v[2..4].copy_from_slice(&total.to_le_bytes());
        v
    }

    /// Composite trap: Union names Data 1, but Data 2 appears
    /// first in the blob. Union-authoritative selection must
    /// pick Data 1's pair; a "last Data wins" walker picks 2.
    fn modelled_ecm_composite_cfg() -> Vec<u8> {
        #[rustfmt::skip]
        let cfg: &[u8] = &[
            9, 2, 0, 0, 3, 1, 0, 0x80, 0x32,
            9, 4, 0, 0, 0, 0x02, 0x06, 0, 0,
            5, 0x24, 0x06, 0, 1, // Union { ctrl=0, sub=1 }
            13, 0x24, 0x0F, 5, 0, 0, 0, 0, 0xEA, 0x05, 0, 0, 0,
            // Data interface 2 first — must NOT win.
            9, 4, 2, 1, 2, 0x0A, 0, 0, 0,
            7, 5, 0x82, 2, 64, 0, 0,
            7, 5, 0x03, 2, 64, 0, 0,
            // Data interface 1 second — Union-named, must win.
            9, 4, 1, 1, 2, 0x0A, 0, 0, 0,
            7, 5, 0x81, 2, 64, 0, 0,
            7, 5, 0x02, 2, 64, 0, 0,
        ];
        let mut v = cfg.to_vec();
        let total = v.len() as u16;
        v[2..4].copy_from_slice(&total.to_le_bytes());
        v
    }

    fn smoke_ecm_comm_interface_finder() -> TestResult {
        let cfg = modelled_ecm_cfg();
        if find_ecm_comm_interface(&cfg) != Some(0) {
            return TestResult::Fail("ECM comm interface not found");
        }
        // NCM comm (subclass 0x0D) must NOT match the ECM finder.
        let mut ncm_cfg = cfg.clone();
        // Comm interface descriptor starts at offset 9; subclass
        // byte is at +6 within it.
        ncm_cfg[9 + 6] = 0x0D;
        if find_ecm_comm_interface(&ncm_cfg).is_some() {
            return TestResult::Fail("NCM comm must not match ECM finder");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_comm_interface_finder);

    fn smoke_ecm_functional_descriptor_finder() -> TestResult {
        let cfg = modelled_ecm_cfg();
        let (union, eth) = find_ecm_functional_descriptors(&cfg, 0);
        let u = match union {
            Some(u) => u,
            None => return TestResult::Fail("union descriptor not found"),
        };
        if u.control_interface != 0 || u.subordinate_interfaces != alloc::vec![1] {
            return TestResult::Fail("union content wrong");
        }
        let e = match eth {
            Some(e) => e,
            None => return TestResult::Fail("ethernet descriptor not found"),
        };
        if e.mac_string_index != 5 || e.max_segment_size != 1514 {
            return TestResult::Fail("ethernet descriptor content wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ecm",
        smoke_ecm_functional_descriptor_finder
    );

    fn smoke_ecm_ethernet_descriptor_parse() -> TestResult {
        // ECM 1.2 §5.4, byte-for-byte: len 13, CS_INTERFACE,
        // subtype 0x0F, iMAC=5, stats=1, maxseg=1514, mc=3, power=2.
        let raw = [13u8, 0x24, 0x0F, 5, 1, 0, 0, 0, 0xEA, 0x05, 3, 0, 2];
        let e = match EthernetNetworkingDescriptor::parse(&raw) {
            Ok(e) => e,
            Err(_) => return TestResult::Fail("clean ethernet descriptor rejected"),
        };
        if e.mac_string_index != 5
            || e.statistics_bitmap != 1
            || e.max_segment_size != 1514
            || e.number_mc_filters != 3
            || e.number_power_filters != 2
        {
            return TestResult::Fail("ethernet descriptor fields mis-decoded");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_ethernet_descriptor_parse);

    fn smoke_ecm_bulk_endpoints_union_select() -> TestResult {
        let cfg = modelled_ecm_composite_cfg();
        let (iface, bulk_in, bulk_out) = match find_ecm_bulk_endpoints(&cfg, 0) {
            Some(t) => t,
            None => return TestResult::Fail("bulk endpoints not found"),
        };
        // Union names Data 1: its pair is 0x81 in / 0x02 out.
        // Data 2's pair (0x82/0x03) must NOT win.
        if iface != 1 || bulk_in.ep_addr != 0x81 || bulk_out.ep_addr != 0x02 {
            return TestResult::Fail("union selection lost to descriptor order");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_bulk_endpoints_union_select);

    fn smoke_ecm_bulk_endpoints_fallback() -> TestResult {
        // Same composite blob with the Union descriptor removed:
        // fallback is the first Data interface after Comm (2).
        let mut cfg = modelled_ecm_composite_cfg();
        // Union block is 5 bytes starting at offset 18
        // (config 9 + comm iface 9). Remove it.
        cfg.drain(18..23);
        let total = cfg.len() as u16;
        cfg[2..4].copy_from_slice(&total.to_le_bytes());
        let (iface, bulk_in, bulk_out) = match find_ecm_bulk_endpoints(&cfg, 0) {
            Some(t) => t,
            None => return TestResult::Fail("bulk endpoints not found"),
        };
        if iface != 2 || bulk_in.ep_addr != 0x82 || bulk_out.ep_addr != 0x03 {
            return TestResult::Fail("fallback must pick first Data after Comm");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_bulk_endpoints_fallback);

    fn smoke_ecm_data_alt_setting_finder() -> TestResult {
        let cfg = modelled_ecm_cfg();
        if find_ecm_data_alt_setting(&cfg) != Some((1, 1)) {
            return TestResult::Fail("data alt setting must be (1, 1)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_data_alt_setting_finder);

    fn smoke_ecm_notification_endpoint_finder() -> TestResult {
        let cfg = modelled_ecm_cfg();
        let ep = match find_ecm_notification_endpoint(&cfg, 0) {
            Some(ep) => ep,
            None => return TestResult::Fail("notification endpoint not found"),
        };
        if ep.ep_addr != 0x83 || ep.interval != 8 {
            return TestResult::Fail("notification endpoint fields wrong");
        }
        if ep.kind != EndpointKind::InterruptIn {
            return TestResult::Fail("notification endpoint must be InterruptIn");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/cdc_ecm",
        smoke_ecm_notification_endpoint_finder
    );

    fn smoke_ecm_notification_decode() -> TestResult {
        // NETWORK_CONNECTION up (wValue bit 0) and down.
        let up = [0xA1u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        if EcmNotification::decode(&up) != Ok(EcmNotification::NetworkConnection { up: true }) {
            return TestResult::Fail("link-up notification mis-decoded");
        }
        let down = [0xA1u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        if EcmNotification::decode(&down) != Ok(EcmNotification::NetworkConnection { up: false }) {
            return TestResult::Fail("link-down notification mis-decoded");
        }
        // CONNECTION_SPEED_CHANGE, byte-for-byte: DL 100 Mbps,
        // UL 10 Mbps, distinct values so a swapped decode fails.
        let speed = [
            0xA1u8, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0xE1, 0xF5, 0x05, 0x80, 0x96,
            0x98, 0x00,
        ];
        if EcmNotification::decode(&speed)
            != Ok(EcmNotification::ConnectionSpeedChange {
                downlink_bps: 100_000_000,
                uplink_bps: 10_000_000,
            })
        {
            return TestResult::Fail("speed-change notification mis-decoded");
        }
        // RESPONSE_AVAILABLE.
        let resp = [0xA1u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        if EcmNotification::decode(&resp) != Ok(EcmNotification::ResponseAvailable) {
            return TestResult::Fail("response-available mis-decoded");
        }
        // Unknown code passes through with its fields.
        let unk = [0xA1u8, 0x42, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00];
        if EcmNotification::decode(&unk)
            != Ok(EcmNotification::Unknown {
                code: 0x42,
                value: 7,
                index: 3,
            })
        {
            return TestResult::Fail("unknown notification must pass through");
        }
        // Truncation: short header, and wLength over-promising.
        if EcmNotification::decode(&[0xA1u8, 0x00, 0x01]).is_ok() {
            return TestResult::Fail("short header must be rejected");
        }
        let overlong = [0xA1u8, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00];
        if EcmNotification::decode(&overlong).is_ok() {
            return TestResult::Fail("wLength beyond packet must be rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_notification_decode);

    fn smoke_ecm_tx_frame_verbatim() -> TestResult {
        // A real Ethernet frame (dest + src + ethertype + payload)
        // must pass through byte-for-byte: ECM adds no header.
        // The first four bytes are the destination MAC, NOT an
        // NTB signature — an NTB-wrapping implementation fails here.
        let frame = [
            0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00,
            0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let out = match ecm_tx_frame(&frame, 1518) {
            Ok(out) => out,
            Err(_) => return TestResult::Fail("clean frame rejected"),
        };
        if out != frame {
            return TestResult::Fail("TX frame must be verbatim");
        }
        if out[0..4] == [0x4Eu8, 0x43, 0x4D, 0x48] {
            return TestResult::Fail("TX frame must not carry an NTB header");
        }
        // Over-cap frames are rejected, never truncated.
        let big = [0u8; 2000];
        if ecm_tx_frame(&big, 1518) != Err(EcmError::FrameTooLarge) {
            return TestResult::Fail("over-cap frame must be rejected");
        }
        // Zero cap means no limit.
        if ecm_tx_frame(&big, 0).is_err() {
            return TestResult::Fail("zero cap must not limit TX");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_tx_frame_verbatim);

    fn smoke_ecm_rx_transfer_is_one_frame() -> TestResult {
        let buf = [1u8, 2, 3, 4, 5];
        if ecm_rx_transfer(&buf, 5) != Some(&buf[..]) {
            return TestResult::Fail("one transfer must yield one frame");
        }
        if ecm_rx_transfer(&buf, 0).is_some() {
            return TestResult::Fail("empty transfer must yield no frame");
        }
        if ecm_rx_transfer(&buf, 6).is_some() {
            return TestResult::Fail("over-long transfer must yield no frame");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_rx_transfer_is_one_frame);

    fn smoke_ecm_rx_buf_len() -> TestResult {
        if ecm_rx_buf_len(0) != 16384 {
            return TestResult::Fail("zero cap must fall back to 16 KiB");
        }
        if ecm_rx_buf_len(100) != 1518 {
            return TestResult::Fail("degenerate cap must clamp to floor");
        }
        if ecm_rx_buf_len(1518) != 1518 || ecm_rx_buf_len(9000) != 9000 {
            return TestResult::Fail("sane caps must pass through");
        }
        if ecm_rx_buf_len(100000) != 65535 {
            return TestResult::Fail("huge cap must clamp to ceiling");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_rx_buf_len);

    fn smoke_mac_string_parse() -> TestResult {
        // UTF-16LE "001A2B3C4D5E" → 00:1A:2B:3C:4D:5E.
        let mut desc = alloc::vec![26u8, 0x03];
        for ch in "001A2B3C4D5E".bytes() {
            desc.push(ch);
            desc.push(0);
        }
        if parse_mac_string_descriptor(&desc) != Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]) {
            return TestResult::Fail("MAC string mis-decoded");
        }
        // Multicast first byte and all-zero are invalid.
        let mut mc = alloc::vec![26u8, 0x03];
        for ch in "011A2B3C4D5E".bytes() {
            mc.push(ch);
            mc.push(0);
        }
        if parse_mac_string_descriptor(&mc).is_some() {
            return TestResult::Fail("multicast MAC must be rejected");
        }
        let mut zero = alloc::vec![26u8, 0x03];
        for ch in "000000000000".bytes() {
            zero.push(ch);
            zero.push(0);
        }
        if parse_mac_string_descriptor(&zero).is_some() {
            return TestResult::Fail("all-zero MAC must be rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_mac_string_parse);

    fn smoke_ecm_tx_routing_two_devices() -> TestResult {
        __reset_ecm_for_test();
        let mk = |slot: u8, dci: u8| CdcEcmDevice {
            slot_id: slot,
            comm_iface: 0,
            data_iface: 1,
            bulk_in_dci: dci + 1,
            bulk_out_dci: dci,
            notif_dci: 0,
            mac: [0x02, 0, 0, 0, 0, slot],
            max_segment_size: 1518,
            iface_name: alloc::format!("usb-ecm{}", slot),
            pump_running: false,
            notif_running: false,
            link_up: false,
            downlink_bps: 0,
            uplink_bps: 0,
            detached: false,
        };
        {
            let mut g = CDC_ECM_DEVICES.lock();
            g.push(mk(3, 4));
            g.push(mk(5, 6));
        }
        if tx_target(0) != Some((3, 4)) || tx_target(1) != Some((5, 6)) {
            __reset_ecm_for_test();
            return TestResult::Fail("TX routing must resolve per-device");
        }
        // Detach must tombstone index 0 without retargeting 1,
        // and must not shift 1's cookie.
        detach_ecm_slot(3);
        let ok = tx_target(0).is_none() && tx_target(1) == Some((5, 6));
        __reset_ecm_for_test();
        if !ok {
            return TestResult::Fail("detach must tombstone, not shift cookies");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/cdc_ecm", smoke_ecm_tx_routing_two_devices);
}
