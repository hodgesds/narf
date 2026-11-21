//! USB Hub class driver — clean-room.
//!
//! Reference: **"Universal Serial Bus Specification Revision 2.0"
//! Chapter 11** ("Hub Specification"), USB-IF (free PDF, usb.org).
//! Section numbers below (`§11.x`) refer to that chapter.
//!   <https://www.usb.org/document-library/usb-20-specification>
//!   <https://www.usb.org/document-library/usb-32-revision-11-june-2022>
//!
//! ## Protocol shape
//!
//! Hubs identify by Class 0x09. The interesting verbs are
//! class-specific control requests on the default control
//! endpoint:
//!
//! | bRequest        | wValue          | wIndex   | direction |
//! |-----------------|-----------------|----------|-----------|
//! | GET_DESCRIPTOR  | (Hub<<8)        | 0        | IN        |
//! | SET_FEATURE     | PORT_RESET      | port     | OUT       |
//! | SET_FEATURE     | PORT_POWER      | port     | OUT       |
//! | CLEAR_FEATURE   | C_PORT_RESET    | port     | OUT       |
//! | GET_STATUS      | 0               | port     | IN (4 B)  |
//!
//! `bmRequestType` is `Class | Other | Host-to-Device` (0x23) for
//! port SET/CLEAR FEATURE, and `Class | Other | Device-to-Host`
//! (0xA3) for GET_STATUS. For hub-wide GET_DESCRIPTOR it's
//! `Class | Device | Device-to-Host` (0xA0).
//!
//! ## Stage cut
//!
//! - GET_DESCRIPTOR(Hub) → 9-byte (USB 2.0) hub descriptor.
//! - SET_FEATURE(PORT_POWER) for every downstream port.
//! - GET_STATUS / SET_FEATURE(PORT_RESET) drive the per-port
//!   reset that the xHCI hot-plug walker normally does at the
//!   root-hub level. The same flow applies to children behind a
//!   USB hub.
//!
//! Cascading enumeration (xHCI Address Device for downstream
//! devices) lands when the xHCI driver gains route-string-aware
//! `address_device` (currently it hard-codes the root-hub port).

extern crate alloc;

use alloc::vec::Vec;

use crate::xhci::{self, EndpointConfig, EndpointKind, PortSpeed, Topology, Xhci};

// ── Class triple ───────────────────────────────────────────────────

pub const HUB_INTERFACE_CLASS: u8 = 0x09;

/// High-speed hub device protocol: one shared Transaction Translator.
pub const HUB_PROTOCOL_SINGLE_TT: u8 = 0x01;
/// High-speed hub device protocol: one Transaction Translator per port.
pub const HUB_PROTOCOL_MULTI_TT: u8 = 0x02;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HubRequest {
    kind: u8,
    code: u8,
    value: u16,
    index: u16,
}

// The same attach sequence runs against xHCI and the firmware model. Keep
// requests at the wire boundary so tests observe the selected hub mode.
trait HubTransport: Sync {
    fn read<'a>(
        &'a self,
        slot: u8,
        request: HubRequest,
        data: &'a mut [u8],
    ) -> impl core::future::Future<Output = Result<usize, xhci::XhciError>> + Send + 'a;

    fn write(
        &self,
        slot: u8,
        request: HubRequest,
    ) -> impl core::future::Future<Output = Result<usize, xhci::XhciError>> + Send;

    /// Add the hub's status-change interrupt-IN endpoint to the slot.
    fn configure_status(
        &self,
        slot: u8,
        endpoint: EndpointConfig,
    ) -> impl core::future::Future<Output = Result<(), xhci::XhciError>> + Send;

    /// Submit (or resubmit) the status-change transfer of `len` bytes.
    fn arm_status(&self, slot: u8, dci: u8, len: u32) -> Result<(), xhci::XhciError>;
}

impl HubTransport for Xhci {
    async fn read<'a>(
        &'a self,
        slot: u8,
        request: HubRequest,
        data: &'a mut [u8],
    ) -> Result<usize, xhci::XhciError> {
        self.control_in(
            slot,
            request.kind,
            request.code,
            request.value,
            request.index,
            data,
        )
        .await
    }

    async fn write(&self, slot: u8, request: HubRequest) -> Result<usize, xhci::XhciError> {
        self.control_out(
            slot,
            request.kind,
            request.code,
            request.value,
            request.index,
            &[],
        )
        .await
    }

    async fn configure_status(
        &self,
        slot: u8,
        endpoint: EndpointConfig,
    ) -> Result<(), xhci::XhciError> {
        self.configure_endpoints(slot, &[endpoint]).await
    }

    fn arm_status(&self, slot: u8, dci: u8, len: u32) -> Result<(), xhci::XhciError> {
        self.arm_interrupt_in(slot, dci, len).map(|_| ())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "hub_tests.rs"]
mod tests;

// ── Class-specific request encodings ───────────────────────────────

/// Standard `GET_DESCRIPTOR` (§11.24.2.5) targeting the hub
/// descriptor type.
pub const HUB_DESC_TYPE: u8 = 0x29;

// `bmRequestType` discriminators.
pub const RT_HOST_TO_DEV_CLASS_OTHER: u8 = 0x23;
pub const RT_DEV_TO_HOST_CLASS_OTHER: u8 = 0xA3;
pub const RT_DEV_TO_HOST_CLASS_DEVICE: u8 = 0xA0;

// `bRequest` values (§11.24.2).
pub const REQ_GET_STATUS: u8 = 0x00;
pub const REQ_CLEAR_FEATURE: u8 = 0x01;
pub const REQ_SET_FEATURE: u8 = 0x03;
pub const REQ_GET_DESCRIPTOR: u8 = 0x06;

// Port features (§11.24.2.7.2 Table 11-17).
pub const PORT_CONNECTION: u16 = 0;
pub const PORT_ENABLE: u16 = 1;
pub const PORT_SUSPEND: u16 = 2;
pub const PORT_OVER_CURRENT: u16 = 3;
pub const PORT_RESET: u16 = 4;
pub const PORT_POWER: u16 = 8;
pub const PORT_LOW_SPEED: u16 = 9;
pub const C_PORT_CONNECTION: u16 = 16;
pub const C_PORT_ENABLE: u16 = 17;
pub const C_PORT_SUSPEND: u16 = 18;
pub const C_PORT_OVER_CURRENT: u16 = 19;
pub const C_PORT_RESET: u16 = 20;

/// Port change bits (status word bits 16..) the walk acknowledges, with
/// the feature that clears each (Linux `port_event` /
/// `hub_port_connect_change`). Bits 21..23 are the USB 3.x hub's
/// C_BH_PORT_RESET / C_PORT_LINK_STATE / C_PORT_CONFIG_ERROR (USB 3.2
/// §10.16.2.6), reserved zero on a USB 2.0 hub. C_PORT_SUSPEND stays set
/// for the remote-wakeup watch (`suspend_change_set`), which owns it.
const WALK_ACKED_CHANGES: [(u32, u16); 7] = [
    (1 << 16, C_PORT_CONNECTION),
    (1 << 17, C_PORT_ENABLE),
    (1 << 19, C_PORT_OVER_CURRENT),
    (1 << 20, C_PORT_RESET),
    (1 << 21, 29), // C_BH_PORT_RESET
    (1 << 22, 25), // C_PORT_LINK_STATE
    (1 << 23, 26), // C_PORT_CONFIG_ERROR
];
/// Hub features C_HUB_LOCAL_POWER / C_HUB_OVER_CURRENT (§11.24.2,
/// Table 11-17) and the hub-recipient request type.
const C_HUB_LOCAL_POWER: u16 = 0;
const C_HUB_OVER_CURRENT: u16 = 1;
const RT_HOST_TO_DEV_CLASS_DEVICE: u8 = 0x20;
/// Linux `hub->buffer` is 8 bytes: the status-change transfer is
/// `min(wMaxPacketSize, 8)` (`hub_configure`).
const STATUS_BUFFER_BYTES: u16 = 8;

// Port status word bits (§11.24.2.7.1 Table 11-15).
pub const PSTAT_CONNECTION: u16 = 1 << 0;
pub const PSTAT_ENABLE: u16 = 1 << 1;
pub const PSTAT_SUSPEND: u16 = 1 << 2;
pub const PSTAT_OVER_CURRENT: u16 = 1 << 3;
pub const PSTAT_RESET: u16 = 1 << 4;
/// Low Speed Device Attached (§11.24.2.7.1 bit 9). Mutually
/// exclusive with `PSTAT_HIGH_SPEED`; both clear means full-speed.
pub const PSTAT_LOW_SPEED: u16 = 1 << 9;
/// High Speed Device Attached (§11.24.2.7.1 bit 10).
pub const PSTAT_HIGH_SPEED: u16 = 1 << 10;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HubError {
    NotHub,
    Xhci(xhci::XhciError),
    BadDescriptor,
    PortResetTimeout,
}

impl From<xhci::XhciError> for HubError {
    fn from(e: xhci::XhciError) -> Self {
        HubError::Xhci(e)
    }
}

/// Decoded hub descriptor (USB 2.0, 9 bytes — USB 3.x has an
/// extension we don't decode here).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HubDescriptor {
    /// Number of downstream ports.
    pub num_ports: u8,
    /// Hub characteristics bitmap (§11.23.2.1).
    pub characteristics: u16,
    /// Power-on time in 2 ms units.
    pub poweron_time_2ms: u8,
    /// Hub controller current draw (mA).
    pub controller_current: u8,
}

impl HubDescriptor {
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 9 || buf[1] != HUB_DESC_TYPE {
            return None;
        }
        Some(Self {
            num_ports: buf[2],
            characteristics: u16::from_le_bytes([buf[3], buf[4]]),
            poweron_time_2ms: buf[5],
            controller_current: buf[6],
        })
    }

    /// Hub Descriptor `wHubCharacteristics[6:5]`, encoded exactly as
    /// xHCI Slot Context `TT Think Time[1:0]`: 0/1/2/3 means
    /// 8/16/24/32 full-speed bit times.
    pub const fn tt_think_time(self) -> u8 {
        ((self.characteristics >> 5) & 0x3) as u8
    }
}

/// One bound hub.
#[derive(Copy, Clone, Debug)]
pub struct UsbHub {
    pub slot_id: u8,
    pub iface_num: u8,
    pub descriptor: HubDescriptor,
    /// Speed negotiated between this hub and its upstream port.
    pub speed: PortSpeed,
    /// Device Descriptor capability; protocol 2 still starts in single-TT
    /// mode until its multiple-TT alternate interface has been selected.
    pub device_protocol: u8,
    pub interface_alt: u8,
    pub interface_protocol: u8,
    /// The status-change interrupt-IN endpoint (USB 2.0 §11.12.1) and
    /// the length of its transfer, from the configuration descriptor;
    /// `None` when the hub offers none or `activate` could not submit it
    /// (then only the supervisor's periodic walk sees port changes).
    pub status: Option<HubStatusEndpoint>,
}

/// A hub's status-change endpoint as submitted (`UsbHub::activate`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HubStatusEndpoint {
    pub endpoint: EndpointConfig,
    pub dci: u8,
    pub len: u16,
}

/// The status-change endpoint of hub interface `iface` alternate `alt`:
/// its first endpoint, which must be interrupt-IN (Linux `hub_probe`:
/// "bogus hub" otherwise).
pub fn status_endpoint(config: &[u8], iface: u8, alt: u8) -> Option<EndpointConfig> {
    let mut offset = 0;
    let mut in_interface = false;
    while offset + 2 <= config.len() {
        let len = config[offset] as usize;
        if len < 2 || offset + len > config.len() {
            return None;
        }
        let d = &config[offset..offset + len];
        match d[1] {
            4 if len >= 9 => {
                in_interface = d[2] == iface && d[3] == alt && d[5] == HUB_INTERFACE_CLASS;
            }
            5 if in_interface && len >= 7 => {
                let ep_addr = d[2];
                if ep_addr & 0x80 == 0 || d[3] & 0x3 != 3 {
                    return None;
                }
                return Some(EndpointConfig {
                    ep_addr,
                    max_packet: u16::from_le_bytes([d[4], d[5]]),
                    kind: EndpointKind::InterruptIn,
                    interval: d[6],
                });
            }
            _ => {}
        }
        offset += len;
    }
    None
}

/// Resolve the active hub interface before any class request. USB 2.0
/// configuration selects alternate zero. A high-speed multiple-TT hub must
/// explicitly select its advertised protocol-2 alternate (USB 2.0 §11.23).
fn hub_interface_mode(
    config: &[u8],
    iface: u8,
    device_protocol: u8,
    speed: PortSpeed,
) -> Result<(u8, u8), HubError> {
    let multiple = matches!(speed, PortSpeed::High) && device_protocol == HUB_PROTOCOL_MULTI_TT;
    let mut default = None;
    let mut selected = None;
    let mut offset = 0;
    while offset + 2 <= config.len() {
        let len = config[offset] as usize;
        if len < 2 || offset + len > config.len() {
            return Err(HubError::BadDescriptor);
        }
        let descriptor = &config[offset..offset + len];
        if descriptor[1] == 4
            && len >= 9
            && descriptor[2] == iface
            && descriptor[5] == HUB_INTERFACE_CLASS
        {
            let alternate = descriptor[3];
            let protocol = descriptor[7];
            if alternate == 0 {
                default = Some((alternate, protocol));
            } else if protocol == HUB_PROTOCOL_MULTI_TT {
                selected.get_or_insert((alternate, protocol));
            }
        }
        offset += len;
    }
    let default = default.ok_or(HubError::BadDescriptor)?;
    if multiple {
        selected.ok_or(HubError::BadDescriptor)
    } else {
        Ok(default)
    }
}

/// Walk a Configuration Descriptor tree looking for the first
/// interface whose `bInterfaceClass` is 0x09 (Hub). Returns the
/// interface number.
pub fn find_hub_interface(cfg: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        if dtype == 4 && len >= 9 && cfg[i + 5] == HUB_INTERFACE_CLASS {
            return Some(cfg[i + 2]);
        }
        i += len;
    }
    None
}

impl UsbHub {
    /// Bind to an already-addressed USB hub slot. Issues
    /// GET_DESCRIPTOR(Hub) so `descriptor` is populated, then
    /// powers on every downstream port.
    pub async fn attach(
        xhci_dev: &Xhci,
        slot_id: u8,
        iface_num: u8,
        device_protocol: u8,
        speed: PortSpeed,
        config: &[u8],
    ) -> Result<Self, HubError> {
        Self::attach_transport(xhci_dev, slot_id, iface_num, device_protocol, speed, config).await
    }

    async fn attach_transport(
        transport: &impl HubTransport,
        slot_id: u8,
        iface_num: u8,
        device_protocol: u8,
        speed: PortSpeed,
        config: &[u8],
    ) -> Result<Self, HubError> {
        let (mut interface_alt, mut interface_protocol) =
            hub_interface_mode(config, iface_num, device_protocol, speed)?;
        if interface_alt != 0
            && transport
                .write(
                    slot_id,
                    HubRequest {
                        kind: 0x01, // Host-to-device | Standard | Interface.
                        code: 11,   // SET_INTERFACE (USB 2.0 §9.4.10).
                        value: interface_alt as u16,
                        index: iface_num as u16,
                    },
                )
                .await
                .is_err()
        {
            // hub_configure: "Using single TT (err ...)" — a hub that
            // refuses its multi-TT alternate keeps working in alt 0.
            interface_alt = 0;
            interface_protocol = HUB_PROTOCOL_SINGLE_TT;
        }
        // GET_DESCRIPTOR(Hub) — bmRequestType 0xA0, value
        // (HUB_DESC_TYPE << 8), index 0.
        let mut desc_buf = [0u8; 16];
        let n = transport
            .read(
                slot_id,
                HubRequest {
                    kind: RT_DEV_TO_HOST_CLASS_DEVICE,
                    code: REQ_GET_DESCRIPTOR,
                    value: (HUB_DESC_TYPE as u16) << 8,
                    index: 0,
                },
                &mut desc_buf,
            )
            .await?;
        if n < 9 {
            return Err(HubError::BadDescriptor);
        }
        let descriptor = HubDescriptor::decode(&desc_buf[..n]).ok_or(HubError::BadDescriptor)?;

        // Power on every downstream port via SET_FEATURE(PORT_POWER).
        for p in 1..=descriptor.num_ports {
            let _ = transport
                .write(
                    slot_id,
                    HubRequest {
                        kind: RT_HOST_TO_DEV_CLASS_OTHER,
                        code: REQ_SET_FEATURE,
                        value: PORT_POWER,
                        index: p as u16,
                    },
                )
                .await;
        }
        // hub_power_on: wait bPwrOn2PwrGood (2 ms units) for power to be
        // good on every port, and at least the 100 ms connect debounce
        // (hub_port_debounce) before the first port status is trusted.
        let settle_ms = (u64::from(descriptor.poweron_time_2ms) * 2).max(100);
        narf_time::sleep_ms(settle_ms).await;

        Ok(UsbHub {
            slot_id,
            iface_num,
            descriptor,
            speed,
            device_protocol,
            interface_alt,
            interface_protocol,
            status: status_endpoint(config, iface_num, interface_alt).map(|endpoint| {
                HubStatusEndpoint {
                    endpoint,
                    dci: endpoint.dci(),
                    len: (endpoint.max_packet & 0x7ff).clamp(1, STATUS_BUFFER_BYTES),
                }
            }),
        })
    }

    /// Submit the hub's status-change transfer once the slot is marked
    /// as a hub (Linux `hub_activate`: `usb_submit_urb(hub->urb)`), so a
    /// port change reaches the supervisor as a Transfer Event (`hub_irq`
    /// → `kick_hub_wq`) instead of waiting for its periodic walk. On
    /// failure the hub keeps working through the walk alone and
    /// `status` is cleared.
    pub async fn activate(&mut self, xhci_dev: &Xhci) -> Result<(), HubError> {
        self.activate_transport(xhci_dev).await
    }

    async fn activate_transport(&mut self, transport: &impl HubTransport) -> Result<(), HubError> {
        let Some(status) = self.status else {
            return Ok(());
        };
        let result = match transport
            .configure_status(self.slot_id, status.endpoint)
            .await
        {
            Ok(()) => transport.arm_status(self.slot_id, status.dci, u32::from(status.len)),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            self.status = None;
            return Err(HubError::Xhci(error));
        }
        Ok(())
    }

    /// Consume a completed status-change transfer: the bitmap of what
    /// changed (bit 0 the hub itself, bit N port N), or `None` when the
    /// hub reported nothing. The transfer is resubmitted, as `hub_irq`
    /// does.
    pub fn take_status_change(&self, xhci_dev: &Xhci) -> Option<u64> {
        let status = self.status?;
        let mut buf = [0u8; STATUS_BUFFER_BYTES as usize];
        let n = match xhci_dev.poll_interrupt_in(
            self.slot_id,
            status.dci,
            &mut buf[..usize::from(status.len)],
        ) {
            Ok(Some(n)) => n.min(usize::from(status.len)),
            _ => return None,
        };
        Some(
            buf[..n]
                .iter()
                .enumerate()
                .fold(0u64, |bits, (i, b)| bits | u64::from(*b) << (8 * i)),
        )
    }

    /// Acknowledge a hub-level change (status-change bit 0): clear
    /// C_HUB_LOCAL_POWER and C_HUB_OVER_CURRENT so the hub stops
    /// reporting it (Linux `hub_event` → `hub_hub_status`).
    pub async fn clear_hub_change(&self, xhci_dev: &Xhci) {
        for feature in [C_HUB_LOCAL_POWER, C_HUB_OVER_CURRENT] {
            let _ = HubTransport::write(
                xhci_dev,
                self.slot_id,
                HubRequest {
                    kind: RT_HOST_TO_DEV_CLASS_DEVICE,
                    code: REQ_CLEAR_FEATURE,
                    value: feature,
                    index: 0,
                },
            )
            .await;
        }
    }

    /// Whether this is a high-speed multiple-TT hub.
    pub const fn is_multi_tt(&self) -> bool {
        matches!(self.speed, PortSpeed::High) && self.interface_protocol == HUB_PROTOCOL_MULTI_TT
    }

    /// Build the xHCI route metadata for a child on this hub. Low- and
    /// full-speed children need the parent slot/port and the hub's MTT;
    /// high-speed and faster children use only the route string.
    pub(crate) fn child_topology(
        &self,
        parent_route: u32,
        parent_tier: u32,
        hub_port: u8,
        child_speed: PortSpeed,
    ) -> Topology {
        let mut topology = Topology::for_downstream(parent_route, parent_tier, hub_port);
        if matches!(self.speed, PortSpeed::High)
            && matches!(child_speed, PortSpeed::Low | PortSpeed::Full)
        {
            topology.parent_hub_slot_id = self.slot_id;
            topology.parent_hub_port = hub_port;
            topology.mtt = self.is_multi_tt();
        }
        topology
    }

    /// Read the 4-byte port status word for `port` (1-indexed).
    pub async fn port_status(&self, xhci_dev: &Xhci, port: u8) -> Result<u32, HubError> {
        self.port_status_transport(xhci_dev, port).await
    }

    async fn port_status_transport(
        &self,
        transport: &impl HubTransport,
        port: u8,
    ) -> Result<u32, HubError> {
        let mut buf = [0u8; 4];
        transport
            .read(
                self.slot_id,
                HubRequest {
                    kind: RT_DEV_TO_HOST_CLASS_OTHER,
                    code: REQ_GET_STATUS,
                    value: 0,
                    index: port as u16,
                },
                &mut buf,
            )
            .await?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Drive a per-port reset on a downstream port. Sets
    /// PORT_RESET, polls PORT_STATUS until RESET clears + ENABLE
    /// asserts, then clears the C_PORT_RESET change bit.
    pub async fn port_reset(&self, xhci_dev: &Xhci, port: u8) -> Result<(), HubError> {
        let _ = xhci_dev
            .control_out(
                self.slot_id,
                RT_HOST_TO_DEV_CLASS_OTHER,
                REQ_SET_FEATURE,
                PORT_RESET,
                port as u16,
                &[],
            )
            .await?;
        // hub_port_wait_reset: sleep before the first status read so it
        // cannot observe the pre-reset (still enabled) port, then poll
        // within HUB_RESET_TIMEOUT (800 ms).
        narf_time::sleep_ms(10).await;
        let deadline = narf_time::Deadline::after_ms(800);
        let mut got_reset = false;
        loop {
            match self.port_status(xhci_dev, port).await {
                Ok(s) => {
                    let lo = s as u16;
                    if lo & PSTAT_RESET == 0 && lo & PSTAT_ENABLE != 0 {
                        got_reset = true;
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
            if deadline.expired() {
                break;
            }
            // HUB_SHORT_RESET_TIME between polls.
            narf_time::sleep_ms(10).await;
        }
        if got_reset {
            // Clear the change bit so the next reset returns a
            // fresh edge.
            let _ = xhci_dev
                .control_out(
                    self.slot_id,
                    RT_HOST_TO_DEV_CLASS_OTHER,
                    REQ_CLEAR_FEATURE,
                    C_PORT_RESET,
                    port as u16,
                    &[],
                )
                .await;
            // hub_port_reset: TRSTRCY (10 ms) plus Linux's extra 40 ms
            // before the device is addressed; full-speed devices often
            // ignore SET_ADDRESS inside the recovery window.
            narf_time::sleep_ms(50).await;
            return Ok(());
        }
        Err(HubError::PortResetTimeout)
    }

    /// Suspend a downstream port — host issues
    /// `SET_FEATURE(PORT_SUSPEND)`, the hub gates D+/D- so the
    /// attached device enters Suspend (USB 2.0 §11.5). No polling
    /// is needed since the bit-set is fire-and-forget; the device
    /// goes into Suspend within 3 ms of seeing the J/K bus state.
    /// Re-issue [`port_resume`] to wake it.
    pub async fn port_suspend(&self, xhci_dev: &Xhci, port: u8) -> Result<(), HubError> {
        let _ = xhci_dev
            .control_out(
                self.slot_id,
                RT_HOST_TO_DEV_CLASS_OTHER,
                REQ_SET_FEATURE,
                PORT_SUSPEND,
                port as u16,
                &[],
            )
            .await?;
        Ok(())
    }

    /// Resume a previously suspended downstream port. Clears
    /// `PORT_SUSPEND` so the hub un-gates D+/D-; the device sees
    /// the resume signaling and exits Suspend after T_RSMRCY
    /// (~10 ms). Then acks the change bit via
    /// `CLEAR_FEATURE(C_PORT_SUSPEND)` so the next suspend cycle
    /// observes a fresh edge.
    pub async fn port_resume(&self, xhci_dev: &Xhci, port: u8) -> Result<(), HubError> {
        let _ = xhci_dev
            .control_out(
                self.slot_id,
                RT_HOST_TO_DEV_CLASS_OTHER,
                REQ_CLEAR_FEATURE,
                PORT_SUSPEND,
                port as u16,
                &[],
            )
            .await?;
        let _ = xhci_dev
            .control_out(
                self.slot_id,
                RT_HOST_TO_DEV_CLASS_OTHER,
                REQ_CLEAR_FEATURE,
                C_PORT_SUSPEND,
                port as u16,
                &[],
            )
            .await;
        Ok(())
    }

    /// True iff the downstream port is currently in Suspend state.
    /// Reads PORT_STATUS and inspects `PSTAT_SUSPEND`.
    pub async fn port_is_suspended(&self, xhci_dev: &Xhci, port: u8) -> Result<bool, HubError> {
        let s = self.port_status(xhci_dev, port).await? as u16;
        Ok(s & PSTAT_SUSPEND != 0)
    }

    /// Slot-id accessor — needed by the supervisor for diagnostics
    /// and the hub-port-suspend bookkeeping (which doesn't hold a
    /// reference to the `UsbHub` itself across IRQ wakes).
    pub fn slot_id(&self) -> u8 {
        self.slot_id
    }

    /// Returns the list of downstream ports that report a connected
    /// device (PORT_STATUS.CONNECTION = 1), acknowledging each port's
    /// connect / enable / over-current / reset change bits on the way
    /// (Linux `port_event`): the hub reports a port on its status-change
    /// endpoint for as long as a change bit stays set. `suspended` holds
    /// the ports the host has suspended (bit N = port N), whose
    /// C_PORT_SUSPEND belongs to the remote-wakeup watches.
    pub async fn connected_downstream_ports(&self, xhci_dev: &Xhci, suspended: u64) -> Vec<u8> {
        self.connected_downstream_ports_transport(xhci_dev, suspended)
            .await
    }

    async fn connected_downstream_ports_transport(
        &self,
        transport: &impl HubTransport,
        suspended: u64,
    ) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        for p in 1..=self.descriptor.num_ports {
            let Ok(s) = self.port_status_transport(transport, p).await else {
                continue;
            };
            // On a port the host considers awake, C_PORT_SUSPEND only says
            // a host resume completed (Linux `port_event` clears it); on a
            // suspended one it is a remote wakeup, left to the watches.
            let awake_resume = s & (1 << 18) != 0 && suspended & (1u64 << (p & 63)) == 0;
            let acked = WALK_ACKED_CHANGES
                .into_iter()
                .chain(awake_resume.then_some((1 << 18, C_PORT_SUSPEND)));
            for (bit, feature) in acked {
                if s & bit != 0 {
                    let _ = transport
                        .write(
                            self.slot_id,
                            HubRequest {
                                kind: RT_HOST_TO_DEV_CLASS_OTHER,
                                code: REQ_CLEAR_FEATURE,
                                value: feature,
                                index: p as u16,
                            },
                        )
                        .await;
                }
            }
            if (s as u16) & PSTAT_CONNECTION != 0 {
                v.push(p);
            }
        }
        v
    }

    /// Decode the negotiated USB speed for a downstream port from
    /// the hub-class GET_STATUS word. USB 2.0 §11.24.2.7.1: the LS
    /// bit (9) and HS bit (10) of the status word are mutually
    /// exclusive; both clear means full-speed. USB 3.x hubs report
    /// SuperSpeed via the PORT_LINK_STATE field — the device-class
    /// hub spec for SS hubs ("USB 3.0 Hub Specification" §11.5)
    /// rides on top of this same encoding for the SS LinkState
    /// nibble. For Stage 1 we only resolve LS / FS / HS; SS hubs
    /// are reported as HS until link-state decoding lands.
    pub async fn port_speed(
        &self,
        xhci_dev: &Xhci,
        port: u8,
    ) -> Result<crate::xhci::PortSpeed, HubError> {
        use crate::xhci::PortSpeed;
        let s = self.port_status(xhci_dev, port).await? as u16;
        if s & PSTAT_LOW_SPEED != 0 {
            Ok(PortSpeed::Low)
        } else if s & PSTAT_HIGH_SPEED != 0 {
            Ok(PortSpeed::High)
        } else {
            Ok(PortSpeed::Full)
        }
    }
}
