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

use crate::xhci::{self, Xhci};

// ── Class triple ───────────────────────────────────────────────────

pub const HUB_INTERFACE_CLASS: u8 = 0x09;

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
}

/// One bound hub.
#[derive(Copy, Clone, Debug)]
pub struct UsbHub {
    pub slot_id: u8,
    pub iface_num: u8,
    pub descriptor: HubDescriptor,
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
    pub async fn attach(xhci_dev: &Xhci, slot_id: u8, iface_num: u8) -> Result<Self, HubError> {
        // GET_DESCRIPTOR(Hub) — bmRequestType 0xA0, value
        // (HUB_DESC_TYPE << 8), index 0.
        let mut desc_buf = [0u8; 16];
        let n = xhci_dev.control_in(
            slot_id,
            RT_DEV_TO_HOST_CLASS_DEVICE,
            REQ_GET_DESCRIPTOR,
            (HUB_DESC_TYPE as u16) << 8,
            0,
            &mut desc_buf,
        ).await?;
        if n < 9 {
            return Err(HubError::BadDescriptor);
        }
        let descriptor = HubDescriptor::decode(&desc_buf[..n]).ok_or(HubError::BadDescriptor)?;

        // Power on every downstream port via SET_FEATURE(PORT_POWER).
        let mut nothing = [0u8; 0];
        for p in 1..=descriptor.num_ports {
            let _ = xhci_dev.control_in(
                slot_id,
                RT_HOST_TO_DEV_CLASS_OTHER,
                REQ_SET_FEATURE,
                PORT_POWER,
                p as u16,
                &mut nothing,
            ).await;
        }

        Ok(UsbHub {
            slot_id,
            iface_num,
            descriptor,
        })
    }

    /// Read the 4-byte port status word for `port` (1-indexed).
    pub async fn port_status(&self, xhci_dev: &Xhci, port: u8) -> Result<u32, HubError> {
        let mut buf = [0u8; 4];
        xhci_dev.control_in(
            self.slot_id,
            RT_DEV_TO_HOST_CLASS_OTHER,
            REQ_GET_STATUS,
            0,
            port as u16,
            &mut buf,
        ).await?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Drive a per-port reset on a downstream port. Sets
    /// PORT_RESET, polls PORT_STATUS until RESET clears + ENABLE
    /// asserts, then clears the C_PORT_RESET change bit.
    pub async fn port_reset(&self, xhci_dev: &Xhci, port: u8) -> Result<(), HubError> {
        let mut nothing = [0u8; 0];
        let _ = xhci_dev.control_in(
            self.slot_id,
            RT_HOST_TO_DEV_CLASS_OTHER,
            REQ_SET_FEATURE,
            PORT_RESET,
            port as u16,
            &mut nothing,
        ).await?;
        // 100 ms wall-clock budget (USB 2.0 §11.5.1.5 TDRST max
        // 50 ms + ~10 ms TDRSTR + headroom). Between status polls
        // we sleep briefly so the executor isn't pinned to one task.
        let deadline = narf_time::Deadline::after_ms(100);
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
            // Park 1 ms between polls instead of burning CPU. Hub
            // port reset is observed over a 50ms TDRST window; 1ms
            // granularity gives ~50 polls inside the budget.
            narf_time::sleep_cycles(1_000_000).await;
        }
        if got_reset {
            // Clear the change bit so the next reset returns a
            // fresh edge.
            let _ = xhci_dev.control_in(
                self.slot_id,
                RT_HOST_TO_DEV_CLASS_OTHER,
                REQ_CLEAR_FEATURE,
                C_PORT_RESET,
                port as u16,
                &mut nothing,
            ).await;
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
        let mut nothing = [0u8; 0];
        let _ = xhci_dev.control_in(
            self.slot_id,
            RT_HOST_TO_DEV_CLASS_OTHER,
            REQ_SET_FEATURE,
            PORT_SUSPEND,
            port as u16,
            &mut nothing,
        ).await?;
        Ok(())
    }

    /// Resume a previously suspended downstream port. Clears
    /// `PORT_SUSPEND` so the hub un-gates D+/D-; the device sees
    /// the resume signaling and exits Suspend after T_RSMRCY
    /// (~10 ms). Then acks the change bit via
    /// `CLEAR_FEATURE(C_PORT_SUSPEND)` so the next suspend cycle
    /// observes a fresh edge.
    pub async fn port_resume(&self, xhci_dev: &Xhci, port: u8) -> Result<(), HubError> {
        let mut nothing = [0u8; 0];
        let _ = xhci_dev.control_in(
            self.slot_id,
            RT_HOST_TO_DEV_CLASS_OTHER,
            REQ_CLEAR_FEATURE,
            PORT_SUSPEND,
            port as u16,
            &mut nothing,
        ).await?;
        let _ = xhci_dev.control_in(
            self.slot_id,
            RT_HOST_TO_DEV_CLASS_OTHER,
            REQ_CLEAR_FEATURE,
            C_PORT_SUSPEND,
            port as u16,
            &mut nothing,
        ).await;
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
    /// device (PORT_STATUS.CONNECTION = 1).
    pub async fn connected_downstream_ports(&self, xhci_dev: &Xhci) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        for p in 1..=self.descriptor.num_ports {
            if let Ok(s) = self.port_status(xhci_dev, p).await {
                if (s as u16) & PSTAT_CONNECTION != 0 {
                    v.push(p);
                }
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
    pub async fn port_speed(&self, xhci_dev: &Xhci, port: u8) -> Result<crate::xhci::PortSpeed, HubError> {
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
