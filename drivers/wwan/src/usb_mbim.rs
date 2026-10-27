// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/usb_mbim.rs — USB CDC-MBIM binding
//
// Claims USB CDC Communications-class interfaces with subclass 0x0E
// (MBIM) from the USB class-driver registry, runs the descriptor /
// class-request bring-up conversation, and composes the pieces from
// crate::mbim (codec), crate::session (control plane) and
// crate::bearer (datapath + netdev handoff) into a working modem:
//
//   probe (sync, registry) → spawn bring-up task:
//     GET_DESCRIPTOR (config) → find the MBIM function →
//     SET_CONFIGURATION → SET_INTERFACE (data alt) →
//     Configure Endpoints → GET_NTB_PARAMETERS → MBIM_OPEN →
//     DEVICE_CAPS / SUBSCRIBER_READY / RADIO_STATE queries →
//     register the MBIM control port + the bearer → spawn the RX
//     pump and the RESPONSE_AVAILABLE notification drain.
//
//   connect (API, async) → crate::bearer::activate_session — the
//   netdev appears with the session's MBIM-reported parameters.
//
// Claimant analysis (done before choosing the match): the registry
// match is class 0x02 / subclass 0x0E only. In-tree neighbours claim
// disjoint triples — CDC-ACM requires subclass 0x02, the built-in
// CDC-NCM binder and its registry stub require subclass 0x0D, the
// USB-serial families and every other registry driver match on
// VID/PID tables — and the registry runs after the built-in cascade,
// so nothing else can take an MBIM function first, and this driver
// cannot take theirs. One honest boundary: modems that *disguise*
// themselves as NCM (subclass 0x0D on the wire, MBIM inside — the
// population Linux's cdc_mbim handles via `prefer_mbim` probing)
// still bind to cdc_ncm here; arbitrating that population requires
// probing MBIM_OPEN on an NCM-claimed device, which belongs to the
// NCM binder, not this lane.
//
// Control-channel requests (USB CDC 1.2 §6.2, as used by Linux's
// cdc-wdm driver, which owns this channel on Linux):
//   SEND_ENCAPSULATED_COMMAND  bRequest 0x00, bmRequestType 0x21
//   GET_ENCAPSULATED_RESPONSE  bRequest 0x01, bmRequestType 0xA1
//   RESPONSE_AVAILABLE         notification code 0x01 on the
//                              comm interface's interrupt endpoint.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use narf_drivers_usb::cdc::{CDC_SUBCLASS_MBIM, USB_CLASS_CDC_COMM, USB_CLASS_CDC_DATA};
use narf_drivers_usb::cdc_ncm::{NtbParameters, REQ_GET_NTB_PARAMETERS};
use narf_drivers_usb::class_registry::{
    register_class_driver_with_unbind, UsbClassMatch, UsbProbeError,
};
use narf_drivers_usb::device::USBDevice;
use narf_drivers_usb::xhci::EndpointConfig;
use narf_lib::sync::IrqSafeSpinLock;

use crate::bearer::{self, BearerTxSink};
use crate::mbim::{DeviceCapsInfo, IpConfigurationInfo};
use crate::session::{MbimModem, MbimTransport};
use crate::{WwanError, WwanPort, WwanPortKind};

// ─── USB request codes ───────────────────────────────────────────────────────

/// CDC SEND_ENCAPSULATED_COMMAND (CDC 1.2 §6.2.1).
pub const REQ_SEND_ENCAPSULATED_COMMAND: u8 = 0x00;
/// CDC GET_ENCAPSULATED_RESPONSE (CDC 1.2 §6.2.2).
pub const REQ_GET_ENCAPSULATED_RESPONSE: u8 = 0x01;
/// CDC notification code RESPONSE_AVAILABLE (CDC 1.2 Table 40).
pub const NOTIFY_RESPONSE_AVAILABLE: u8 = 0x01;
/// USB standard request SET_CONFIGURATION (USB 2.0 §9.4.7).
const STD_REQ_SET_CONFIGURATION: u8 = 9;
/// USB standard request SET_INTERFACE (USB 2.0 §9.4.10).
const STD_REQ_SET_INTERFACE: u8 = 0x0B;

/// The class match this driver registers: any CDC-Comm interface
/// whose subclass is MBIM, regardless of VID/PID or protocol byte.
pub static MBIM_USB_MATCH: [UsbClassMatch; 1] = [UsbClassMatch {
    vendor_id: 0,
    product_id: 0,
    class: Some(USB_CLASS_CDC_COMM),
    subclass: Some(CDC_SUBCLASS_MBIM),
    protocol: None,
}];

// ─── Descriptor model ────────────────────────────────────────────────────────

/// The MBIM functional descriptor (MBIM 1.0 §6.5): 12 bytes,
/// CS_INTERFACE subtype 0x1B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbimFunctionalDescriptor {
    /// bcdMBIMVersion (0x0100 = MBIM 1.0).
    pub bcd_mbim_version: u16,
    /// wMaxControlMessage — largest control message the function accepts.
    pub max_control_message: u16,
    /// bNumberFilters.
    pub number_filters: u8,
    /// bMaxFilterSize.
    pub max_filter_size: u8,
    /// wMaxSegmentSize — largest NTB segment the function handles.
    pub max_segment_size: u16,
    /// bmNetworkCapabilities (raw byte; bit meanings in MBIM 1.0 §6.5).
    pub network_capabilities: u8,
}

impl MbimFunctionalDescriptor {
    /// Parse from a functional-descriptor slice (subtype already
    /// checked by the caller's walk).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 || buf[0] < 12 {
            return None;
        }
        Some(Self {
            bcd_mbim_version: u16::from_le_bytes([buf[3], buf[4]]),
            max_control_message: u16::from_le_bytes([buf[5], buf[6]]),
            number_filters: buf[7],
            max_filter_size: buf[8],
            max_segment_size: u16::from_le_bytes([buf[9], buf[10]]),
            network_capabilities: buf[11],
        })
    }
}

/// Everything the binding needs from a configuration blob.
#[derive(Debug, Clone)]
pub struct MbimFunction {
    /// Interface number of the CDC-Comm (control) interface.
    pub comm_iface: u8,
    /// The parsed MBIM functional descriptor.
    pub descriptor: MbimFunctionalDescriptor,
    /// Interface number of the CDC-Data interface (from the Union
    /// descriptor, or the first CDC-Data interface as a fallback).
    pub data_iface: u8,
    /// The data interface's endpoint-bearing alternate setting.
    pub data_alt: u8,
    /// Interrupt-IN endpoint of the comm interface (notifications).
    pub notify_ep: EndpointConfig,
    /// Bulk-IN endpoint of the data interface's active alt setting.
    pub bulk_in_ep: EndpointConfig,
    /// Bulk-OUT endpoint of the data interface's active alt setting.
    pub bulk_out_ep: EndpointConfig,
}

impl PartialEq for MbimFunction {
    fn eq(&self, other: &Self) -> bool {
        fn same_endpoint(a: &EndpointConfig, b: &EndpointConfig) -> bool {
            a.ep_addr == b.ep_addr
                && a.max_packet == b.max_packet
                && a.kind == b.kind
                && a.interval == b.interval
        }

        self.comm_iface == other.comm_iface
            && self.descriptor == other.descriptor
            && self.data_iface == other.data_iface
            && self.data_alt == other.data_alt
            && same_endpoint(&self.notify_ep, &other.notify_ep)
            && same_endpoint(&self.bulk_in_ep, &other.bulk_in_ep)
            && same_endpoint(&self.bulk_out_ep, &other.bulk_out_ep)
    }
}

impl Eq for MbimFunction {}

/// Raw endpoint facts collected during the descriptor walk.
#[derive(Clone, Copy)]
struct RawEp {
    addr: u8,
    attrs: u8,
    max_packet: u16,
}

/// Find the MBIM function in a full configuration-descriptor blob.
///
/// Returns `None` — binding declines — unless ALL of these exist: a
/// CDC-Comm interface with subclass MBIM, an MBIM functional
/// descriptor under it, a Union (or a CDC-Data interface) naming the
/// data interface, an interrupt-IN endpoint on the comm interface,
/// and an alternate setting of the data interface carrying a bulk
/// pair. A blob that merely *mentions* MBIM (e.g. an NCM function
/// with an MBIM-extended descriptor) does not bind.
pub fn find_mbim_function(cfg: &[u8]) -> Option<MbimFunction> {
    // Pass 1: locate the comm interface and scan its descriptor group
    // (functional descriptors + endpoints up to the next interface).
    let mut comm_iface: Option<u8> = None;
    let mut descriptor: Option<MbimFunctionalDescriptor> = None;
    let mut union_data_iface: Option<u8> = None;
    let mut notify_ep: Option<RawEp> = None;

    let mut i = 0usize;
    let mut in_comm_group = false;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        if dtype == 0x04 && len >= 9 {
            // INTERFACE descriptor.
            let number = cfg[i + 2];
            let alt = cfg[i + 3];
            let class = cfg[i + 5];
            let subclass = cfg[i + 6];
            in_comm_group = false;
            if class == USB_CLASS_CDC_COMM && subclass == CDC_SUBCLASS_MBIM && alt == 0 {
                comm_iface = Some(number);
                in_comm_group = true;
            }
        } else if in_comm_group && dtype == 0x24 && len >= 3 {
            // CS_INTERFACE functional descriptor under the comm iface.
            match cfg[i + 2] {
                0x1B => {
                    descriptor = MbimFunctionalDescriptor::parse(&cfg[i..i + len]);
                }
                0x06 => {
                    // Union: control interface at [3], first
                    // subordinate at [4].
                    if len >= 5 {
                        union_data_iface = Some(cfg[i + 4]);
                    }
                }
                _ => {}
            }
        } else if in_comm_group && dtype == 0x05 && len >= 7 {
            // ENDPOINT under the comm interface: the notification
            // endpoint is its interrupt-IN endpoint.
            let ep = RawEp {
                addr: cfg[i + 2],
                attrs: cfg[i + 3],
                max_packet: u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF,
            };
            if ep.addr & 0x80 != 0 && ep.attrs & 0x03 == 3 {
                notify_ep = Some(ep);
            }
        }
        i += len;
    }

    let comm_iface = comm_iface?;
    let descriptor = descriptor?;
    let notify_ep = notify_ep?;

    // Pass 2: the data interface — the Union's subordinate when the
    // union named one (validated to actually be a CDC-Data
    // interface), else the first CDC-Data interface. Among its alt
    // settings pick the one carrying a bulk pair.
    let mut data_iface: Option<u8> = None;
    let mut data_alt: Option<u8> = None;
    let mut bulk_in: Option<RawEp> = None;
    let mut bulk_out: Option<RawEp> = None;

    let mut i = 0usize;
    let mut current: Option<(u8, u8)> = None; // (interface, alt)
    let mut alt_in: Option<RawEp> = None;
    let mut alt_out: Option<RawEp> = None;
    let flush_alt = |data_iface: &mut Option<u8>,
                     data_alt: &mut Option<u8>,
                     bulk_in: &mut Option<RawEp>,
                     bulk_out: &mut Option<RawEp>,
                     current: &Option<(u8, u8)>,
                     alt_in: &Option<RawEp>,
                     alt_out: &Option<RawEp>| {
        if let (Some(&(number, alt)), Some(&bi), Some(&bo)) =
            (current.as_ref(), alt_in.as_ref(), alt_out.as_ref())
        {
            let wanted = union_data_iface.map(|u| u == number).unwrap_or(true);
            if wanted && data_alt.is_none() {
                *data_iface = Some(number);
                *data_alt = Some(alt);
                *bulk_in = Some(bi);
                *bulk_out = Some(bo);
            }
        }
    };
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        if dtype == 0x04 && len >= 9 {
            flush_alt(
                &mut data_iface,
                &mut data_alt,
                &mut bulk_in,
                &mut bulk_out,
                &current,
                &alt_in,
                &alt_out,
            );
            alt_in = None;
            alt_out = None;
            let class = cfg[i + 5];
            if class == USB_CLASS_CDC_DATA {
                current = Some((cfg[i + 2], cfg[i + 3]));
            } else {
                current = None;
            }
        } else if dtype == 0x05 && current.is_some() && len >= 7 {
            let ep = RawEp {
                addr: cfg[i + 2],
                attrs: cfg[i + 3],
                max_packet: u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]) & 0x07FF,
            };
            if ep.attrs & 0x03 == 2 {
                if ep.addr & 0x80 != 0 {
                    alt_in = Some(ep);
                } else {
                    alt_out = Some(ep);
                }
            }
        }
        i += len;
    }
    flush_alt(
        &mut data_iface,
        &mut data_alt,
        &mut bulk_in,
        &mut bulk_out,
        &current,
        &alt_in,
        &alt_out,
    );

    Some(MbimFunction {
        comm_iface,
        descriptor,
        data_iface: data_iface?,
        data_alt: data_alt?,
        notify_ep: narf_drivers_usb::device::interrupt_in_ep(
            notify_ep.addr & 0x0F,
            notify_ep.max_packet,
        ),
        bulk_in_ep: narf_drivers_usb::device::bulk_in_ep(bulk_in?.addr & 0x0F, bulk_in?.max_packet),
        bulk_out_ep: narf_drivers_usb::device::bulk_out_ep(
            bulk_out?.addr & 0x0F,
            bulk_out?.max_packet,
        ),
    })
}

// ─── USB transport ───────────────────────────────────────────────────────────

/// The production [`MbimTransport`]: encapsulated commands over the
/// comm interface's control pipe, NTBs over the data bulk pair.
#[derive(Clone)]
pub struct UsbMbimTransport {
    device: Arc<USBDevice>,
    comm_iface: u8,
    bulk_in_dci: u8,
    bulk_out_dci: u8,
}

impl core::fmt::Debug for UsbMbimTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UsbMbimTransport")
            .field("comm_iface", &self.comm_iface)
            .field("bulk_in_dci", &self.bulk_in_dci)
            .field("bulk_out_dci", &self.bulk_out_dci)
            .finish_non_exhaustive()
    }
}

impl UsbMbimTransport {
    /// The USB device handle (the control port shares it).
    pub fn device(&self) -> &Arc<USBDevice> {
        &self.device
    }

    /// The comm interface number (encapsulated-command target).
    pub fn comm_iface(&self) -> u8 {
        self.comm_iface
    }
}

impl MbimTransport for UsbMbimTransport {
    async fn control_send(&self, msg: &[u8]) -> Result<(), WwanError> {
        self.device
            .control_out(
                0x21,
                REQ_SEND_ENCAPSULATED_COMMAND,
                0,
                self.comm_iface as u16,
                msg,
            )
            .await
            .map(|_| ())
            .map_err(|_| WwanError::Io)
    }

    async fn control_recv(&self, buf: &mut [u8]) -> Result<usize, WwanError> {
        self.device
            .control_in(
                0xA1,
                REQ_GET_ENCAPSULATED_RESPONSE,
                0,
                self.comm_iface as u16,
                buf,
            )
            .await
            .map_err(|_| WwanError::Io)
    }

    async fn data_send(&self, ntb: &[u8]) -> Result<(), WwanError> {
        self.device
            .bulk_out(self.bulk_out_dci, ntb)
            .await
            .map(|_| ())
            .map_err(|_| WwanError::Io)
    }

    async fn data_recv(&self, buf: &mut [u8]) -> Result<usize, WwanError> {
        self.device
            .bulk_in(self.bulk_in_dci, buf)
            .await
            .map_err(|_| WwanError::Io)
    }
}

/// The bearer's TX sink over USB: bridges the sync netdev trampoline
/// to the async bulk-OUT transfer with `block_on` — the same bridge
/// cdc_ncm's `send_frame` uses from its trampoline.
struct UsbTxSink {
    device: Arc<USBDevice>,
    bulk_out_dci: u8,
}

impl BearerTxSink for UsbTxSink {
    fn send_ntb(&self, ntb: &[u8]) -> Result<(), WwanError> {
        let device = self.device.clone();
        let dci = self.bulk_out_dci;
        narf_scheduler::block_on(async move { device.bulk_out(dci, ntb).await })
            .map(|_| ())
            .map_err(|_| WwanError::Io)
    }
}

// ─── Control port (WwanPort) ─────────────────────────────────────────────────

/// The MBIM control channel exposed as a [`WwanPort`]: raw MBIM
/// message passthrough with /dev/cdc-wdm semantics — `send` queues a
/// whole MBIM message via SEND_ENCAPSULATED_COMMAND, `recv` reads one
/// pending message via GET_ENCAPSULATED_RESPONSE. The in-kernel
/// session driver is the normal consumer; the port exists so the
/// registry the crate was scaffolded around has its real member.
struct UsbMbimControlPort {
    name: String,
    device: Arc<USBDevice>,
    comm_iface: u8,
    max_control_message: u16,
}

impl WwanPort for UsbMbimControlPort {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> WwanPortKind {
        WwanPortKind::Mbim
    }

    fn send(&self, payload: &[u8]) -> Result<(), WwanError> {
        if payload.len() > self.max_control_message as usize {
            return Err(WwanError::MessageTooLarge);
        }
        let device = self.device.clone();
        let iface = self.comm_iface;
        narf_scheduler::block_on(async move {
            device
                .control_out(
                    0x21,
                    REQ_SEND_ENCAPSULATED_COMMAND,
                    0,
                    iface as u16,
                    payload,
                )
                .await
        })
        .map(|_| ())
        .map_err(|_| WwanError::Io)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, WwanError> {
        let device = self.device.clone();
        let iface = self.comm_iface;
        narf_scheduler::block_on(async move {
            device
                .control_in(0xA1, REQ_GET_ENCAPSULATED_RESPONSE, 0, iface as u16, buf)
                .await
        })
        .map_err(|_| WwanError::Io)
    }
}

// ─── Device records, probe, bring-up ─────────────────────────────────────────

/// One bound USB MBIM modem.
struct UsbMbimDevice {
    slot_id: u8,
    transport: UsbMbimTransport,
    /// The session owner, in a take/put cell: exactly one driver of
    /// the control conversation at a time.
    modem: IrqSafeSpinLock<Option<MbimModem<UsbMbimTransport>>>,
    bearer: usize,
    caps: Option<DeviceCapsInfo>,
}

static USB_MBIM_DEVICES: IrqSafeSpinLock<Vec<Arc<UsbMbimDevice>>> =
    IrqSafeSpinLock::new(Vec::new());

/// Slots with a bring-up in flight or completed (probe dedupe).
static MBIM_CLAIMED_SLOTS: IrqSafeSpinLock<Vec<u8>> = IrqSafeSpinLock::new(Vec::new());

/// Number of bound USB MBIM modems.
pub fn attached_mbim_count() -> usize {
    USB_MBIM_DEVICES.lock().len()
}

/// Class-registry probe: claim the slot and spawn the async
/// bring-up. Returns `Ok` on claim, mirroring the rtl8xxxu pattern.
pub fn probe(device: Arc<USBDevice>) -> Result<(), UsbProbeError> {
    {
        let mut claimed = MBIM_CLAIMED_SLOTS.lock();
        if claimed.contains(&device.slot_id()) {
            return Ok(());
        }
        claimed.push(device.slot_id());
    }
    let _ = writeln!(
        narf_console::Writer,
        "  wwan: MBIM function claimed (slot={}, {:04x}:{:04x})",
        device.slot_id(),
        device.vendor_id(),
        device.product_id()
    );
    narf_scheduler::spawn(async move {
        if let Err(e) = bring_up(device.clone()).await {
            let _ = writeln!(
                narf_console::Writer,
                "  wwan: MBIM bring-up failed (slot={}): {:?}",
                device.slot_id(),
                e
            );
            let mut claimed = MBIM_CLAIMED_SLOTS.lock();
            claimed.retain(|s| *s != device.slot_id());
        }
    });
    Ok(())
}

/// Class-registry unbind hook: drop the binding for `slot_id`.
pub fn unbind(slot_id: u8) {
    let rec = {
        let mut g = USB_MBIM_DEVICES.lock();
        let pos = g.iter().position(|d| d.slot_id == slot_id);
        pos.map(|p| g.remove(p))
    };
    if let Some(rec) = rec {
        bearer::detach_bearer(rec.bearer);
    }
    let mut claimed = MBIM_CLAIMED_SLOTS.lock();
    claimed.retain(|s| *s != slot_id);
}

/// Derive the locally administered MAC for a modem's netdevs. MBIM
/// exposes no station address (Linux's cdc_mbim generates a random
/// one at bind); NARF derives a stable one from the USB slot so a
/// modem keeps its address across reboots of the same slot:
/// 02:57:57:41:4E:<slot> ("WWAN" in the middle, LAA bit set).
fn derive_mac(device: &USBDevice) -> [u8; 6] {
    [0x02, 0x57, 0x57, 0x41, 0x4E, device.slot_id()]
}

/// The async bring-up conversation for one claimed device.
async fn bring_up(device: Arc<USBDevice>) -> Result<(), WwanError> {
    // Read the configuration blob (9-byte head, then the full block).
    let mut head = [0u8; 9];
    let n = device
        .get_config_descriptor(0, &mut head)
        .await
        .map_err(|_| WwanError::Io)?;
    if n < 9 {
        return Err(WwanError::MalformedFrame);
    }
    let total_len = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=4096).contains(&total_len) {
        return Err(WwanError::MalformedFrame);
    }
    let mut cfg = alloc::vec![0u8; total_len];
    let n = device
        .get_config_descriptor(0, &mut cfg)
        .await
        .map_err(|_| WwanError::Io)?;
    cfg.truncate(n);
    let function = find_mbim_function(&cfg).ok_or(WwanError::NotReady)?;

    // SET_CONFIGURATION, then select the data alt setting.
    let cfg_value = if cfg.len() >= 6 { cfg[5] } else { 1 };
    device
        .control_out(0x00, STD_REQ_SET_CONFIGURATION, cfg_value as u16, 0, &[])
        .await
        .map_err(|_| WwanError::Io)?;
    if function.data_alt > 0 {
        let _ = device
            .control_out(
                0x01,
                STD_REQ_SET_INTERFACE,
                function.data_alt as u16,
                function.data_iface as u16,
                &[],
            )
            .await;
    }
    device
        .configure_endpoints(&[
            function.notify_ep,
            function.bulk_in_ep,
            function.bulk_out_ep,
        ])
        .await
        .map_err(|_| WwanError::Io)?;

    // NTB parameters: learn the function's NTB sizes (the same
    // class request cdc_ncm issues; MBIM functions answer it too —
    // the datapath framing is NCM's).
    let mut raw = [0u8; NtbParameters::WIRE_LEN];
    let mut ntb_out_max: usize = 16 * 1024;
    if device
        .control_in(
            0xA1,
            REQ_GET_NTB_PARAMETERS,
            0,
            function.comm_iface as u16,
            &mut raw,
        )
        .await
        .is_ok()
    {
        if let Ok(params) = NtbParameters::decode(&raw) {
            if params.ntb_out_max_size > 0 {
                ntb_out_max = (params.ntb_out_max_size as usize).clamp(4096, 64 * 1024);
            }
        }
    }

    let bulk_in_dci = ((function.bulk_in_ep.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = (function.bulk_out_ep.ep_addr & 0x0F) * 2;
    let notify_dci = ((function.notify_ep.ep_addr & 0x0F) * 2) + 1;
    let transport = UsbMbimTransport {
        device: device.clone(),
        comm_iface: function.comm_iface,
        bulk_in_dci,
        bulk_out_dci,
    };

    // MBIM_OPEN + capability queries.
    let mut modem = MbimModem::new(transport.clone());
    modem.open().await?;
    let caps = modem.device_caps().await.ok();
    if let Some(caps) = &caps {
        let _ = writeln!(
            narf_console::Writer,
            "  wwan: modem caps: type={} data_class={:#x} max_sessions={} id={} fw={} hw={}",
            caps.device_type,
            caps.data_class,
            caps.max_sessions,
            caps.device_id,
            caps.firmware_info,
            caps.hardware_info
        );
    }
    if let Ok(ready) = modem.subscriber_ready().await {
        let _ = writeln!(
            narf_console::Writer,
            "  wwan: subscriber ready_state={} iccid={}",
            ready.ready_state,
            ready.sim_iccid
        );
    }
    if let Ok(radio) = modem.radio_state().await {
        let _ = writeln!(
            narf_console::Writer,
            "  wwan: radio hw={} sw={}",
            radio.hardware_state,
            radio.software_state
        );
    }

    // Compose: bearer + control port + record + pumps.
    let bearer = bearer::register_bearer(
        Arc::new(UsbTxSink {
            device: device.clone(),
            bulk_out_dci,
        }),
        derive_mac(&device),
    );
    crate::register_port(Arc::new(UsbMbimControlPort {
        name: alloc::format!("wwan{}mbim", bearer),
        device: device.clone(),
        comm_iface: function.comm_iface,
        max_control_message: function.descriptor.max_control_message,
    }));
    let record = Arc::new(UsbMbimDevice {
        slot_id: device.slot_id(),
        transport: transport.clone(),
        modem: IrqSafeSpinLock::new(Some(modem)),
        bearer,
        caps,
    });
    USB_MBIM_DEVICES.lock().push(record.clone());

    let _ = writeln!(
        narf_console::Writer,
        "  wwan: MBIM modem bound as bearer {} (slot={})",
        bearer,
        device.slot_id()
    );

    // RX pump: NTBs off the bulk-IN pair, demultiplexed by bearer.rs.
    {
        let transport = transport.clone();
        narf_scheduler::spawn(async move {
            let mut buf = alloc::vec![0u8; ntb_out_max];
            let mut errors = 0u32;
            loop {
                if bearer::bearer_detached(bearer) {
                    break;
                }
                match transport.data_recv(&mut buf).await {
                    Ok(n) if n > 0 => {
                        errors = 0;
                        let _ = bearer::deliver_ntb(bearer, &buf[..n]);
                    }
                    Ok(_) => narf_scheduler::yield_now().await,
                    Err(_) => {
                        errors += 1;
                        if errors >= 16 {
                            break;
                        }
                        narf_scheduler::yield_now().await;
                    }
                }
            }
        });
    }

    // Notification drain: RESPONSE_AVAILABLE on the interrupt
    // endpoint means control messages are waiting. The drain only
    // runs while no command exchange owns the modem (take/put); an
    // in-flight command's own read loop consumes whatever arrives
    // meanwhile, indications included.
    {
        let device = device.clone();
        let record = record.clone();
        narf_scheduler::spawn(async move {
            let mut note = [0u8; 8];
            loop {
                if bearer::bearer_detached(bearer) {
                    break;
                }
                if device.arm_interrupt_in(notify_dci, 8).is_err() {
                    break;
                }
                match device.poll_interrupt_in(notify_dci, &mut note) {
                    Ok(Some(_)) if note[0] == 0xA1 && note[1] == NOTIFY_RESPONSE_AVAILABLE => {
                        drain_notifications(&record).await;
                    }
                    Ok(_) => narf_scheduler::yield_now().await,
                    Err(_) => break,
                }
            }
        });
    }

    Ok(())
}

/// Drain pending control messages while the modem is idle, feeding
/// unsolicited events into the session state and the netdev carrier.
async fn drain_notifications(record: &Arc<UsbMbimDevice>) {
    let mut modem = {
        let mut g = record.modem.lock();
        match g.take() {
            Some(m) => m,
            None => return, // a command exchange owns the modem
        }
    };
    let mut scratch = alloc::vec![0u8; 4096];
    for _ in 0..8 {
        match record.transport.control_recv(&mut scratch).await {
            Ok(n) if n > 0 => {
                let msg = &scratch[..n];
                if let Some(event) = crate::mbim::parse_indicate_connect_event(msg) {
                    bearer::note_external_connect_state(
                        record.bearer,
                        event.session_id as u8,
                        event.activation_state == crate::mbim::ACTIVATION_STATE_ACTIVATED,
                    );
                }
                modem.note_external_message(msg);
            }
            _ => break,
        }
    }
    let mut g = record.modem.lock();
    *g = Some(modem);
}

// ─── Connect API ─────────────────────────────────────────────────────────────

/// Find the bound device record for a bearer index.
fn record_for_bearer(bearer: usize) -> Option<Arc<UsbMbimDevice>> {
    let g = USB_MBIM_DEVICES.lock();
    g.iter().find(|d| d.bearer == bearer).cloned()
}

/// Activate a session on the modem behind bearer `bearer` and
/// publish its netdev with the MBIM-reported parameters (see
/// crate::bearer::activate_session). `access_string` is the APN.
pub async fn connect(
    bearer: usize,
    session: u8,
    access_string: Option<String>,
) -> Result<IpConfigurationInfo, WwanError> {
    let record = record_for_bearer(bearer).ok_or(WwanError::NotReady)?;
    if let Some(caps) = &record.caps {
        if (session as u32) >= caps.max_sessions {
            return Err(WwanError::NotReady);
        }
    }
    let mut modem = {
        let mut g = record.modem.lock();
        g.take().ok_or(WwanError::NotReady)?
    };
    let params = crate::mbim::ConnectSetParams::activate(session as u32, access_string);
    let result = bearer::activate_session(&mut modem, bearer, &params).await;
    let mut g = record.modem.lock();
    *g = Some(modem);
    result
}

/// Deactivate a session on the modem behind bearer `bearer`.
pub async fn disconnect(bearer: usize, session: u8) -> Result<(), WwanError> {
    let record = record_for_bearer(bearer).ok_or(WwanError::NotReady)?;
    let mut modem = {
        let mut g = record.modem.lock();
        g.take().ok_or(WwanError::NotReady)?
    };
    let result = bearer::deactivate_session(&mut modem, bearer, session).await;
    let mut g = record.modem.lock();
    *g = Some(modem);
    result
}

/// Register the MBIM class driver with the USB class registry.
/// Called from the crate's Stage::Subsys initcall.
pub fn register() {
    let _ = register_class_driver_with_unbind("cdc-mbim", &MBIM_USB_MATCH, probe, unbind);
}
