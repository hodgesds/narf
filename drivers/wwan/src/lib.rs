// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/lib.rs — WWAN port API + subsystem core
//
// WWAN (Wireless Wide Area Network) covers M.2 cellular modems attached via
// USB, PCIe/MHI, or shared-memory (IOSM).  This crate defines the abstract
// WwanPort trait, the MBIM and QMI protocol codec layers, and the IOSM PCI
// device-ID table for Intel XMM 7560/7360 modems.
//
// Scope:
//   - WwanPort trait + WwanPortKind enum + the port registry
//   - MBIM full control-message codec (MBIM 1.0): headers, fragments,
//     Basic Connect CIDs, information-buffer structures
//   - MBIM session driver (open / caps / radio / packet-service /
//     connect / IP-configuration) over a transport seam
//   - USB CDC-MBIM binding: class-registry claim, descriptor +
//     class-request bring-up, control port, RX/notification pumps
//   - Raw-IP bearer → netdev handoff over the NCM NTB-16 framing
//     with MBIM session-signed NDPs (Linux cdc_mbim's adaptation)
//   - QMI control-message header encode (Qualcomm QMI framing)
//   - IOSM PCI device-ID table (XMM 7560 / 7360)
//
// Deferred (separate concerns):
//   - SIM management / USSD / STK / SMS upper layers
//   - Radio Interface Layer (RIL) integration
//   - Actual modem firmware loading
//   - MHI ring bring-up for IOSM (PCIe) — follow-on when a target
//     with an XMM modem is confirmed; the IOSM table stays codec-only
//   - A userspace/supervisor trigger for usb_mbim::connect — the
//     control plane and API are in-kernel (as with the tree's other
//     composition surfaces); nothing auto-connects without an APN
//     policy, exactly as Linux never auto-connects an MBIM bearer
//
// Linux cross-references (GPL-2.0-or-later, post-2026-05-20 relicense):
//   - include/linux/wwan.h          — port types enum
//   - drivers/net/wwan/wwan_core.c  — port registration model
//   - drivers/net/usb/cdc_mbim.c    — MBIM datapath adaptation
//   - drivers/usb/class/cdc-wdm.c   — encapsulated-command channel
//   - drivers/net/wwan/iosm/iosm_ipc_pcie.h — INTEL_CP_DEVICE_*_ID
//   - drivers/net/wwan/mhi_wwan_ctrl.c      — MHI-over-WWAN pattern

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod bearer;
pub mod iosm;
pub mod mbim;
pub mod qmi;
pub mod session;
pub mod usb_mbim;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

// ─── WwanPortKind ────────────────────────────────────────────────────────────

/// Classifies what protocol a WWAN port speaks.
///
/// Mirrors `enum wwan_port_type` from `include/linux/wwan.h` but trimmed to
/// the subset NARF needs for Stage-0/1.  Variants are kept exhaustive so that
/// `match` arms can never silently miss a new kind.
///
/// Linux ref: `include/linux/wwan.h` — `WWAN_PORT_AT`, `WWAN_PORT_MBIM`,
/// `WWAN_PORT_QMI`, `WWAN_PORT_FIREHOSE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WwanPortKind {
    /// AT command channel (Hayes / 3GPP TS 27.007).
    AtCmd,
    /// Mobile Broadband Interface Model (Microsoft MBIM 1.0).
    Mbim,
    /// Qualcomm Modem Interface (QMI).
    Qmi,
    /// Raw IP data bearer (no control protocol framing on this port).
    Data,
}

// ─── WwanError ───────────────────────────────────────────────────────────────

/// Error type returned by WwanPort operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WwanError {
    /// The underlying transport could not send or receive.
    Io,
    /// The payload was too large for the port's MTU.
    MessageTooLarge,
    /// A malformed frame was received.
    MalformedFrame,
    /// The port is not in a state that allows this operation.
    NotReady,
    /// The modem answered with a non-success MBIM_STATUS code
    /// (mbim::MBIM_STATUS_*), e.g. it refused a connect.
    ModemStatus(u32),
    /// The modem did not answer within the polling budget.
    Timeout,
}

// ─── WwanPort trait ──────────────────────────────────────────────────────────

/// Abstraction over a single logical WWAN port.
///
/// A physical modem typically exposes several ports simultaneously
/// (AT + MBIM + data), each implementing this trait separately.
///
/// Trait is intentionally synchronous at Stage-0/1; the async wrapper lands
/// when the scheduler's waker integration is complete.
pub trait WwanPort {
    /// Human-readable port name, e.g. `"wwan0mbim"` or `"wwan0at"`.
    fn name(&self) -> &str;

    /// Protocol kind this port carries.
    fn kind(&self) -> WwanPortKind;

    /// Transmit `payload` to the modem over this port.
    ///
    /// Returns `Err(WwanError::MessageTooLarge)` if the payload exceeds the
    /// port's maximum transfer unit.
    fn send(&self, payload: &[u8]) -> Result<(), WwanError>;

    /// Receive up to `buf.len()` bytes from the modem into `buf`.
    ///
    /// Returns the number of bytes actually written into `buf`, or an error.
    fn recv(&self, buf: &mut [u8]) -> Result<usize, WwanError>;
}

// ─── Port registry ───────────────────────────────────────────────────────────
//
// The registry the crate was scaffolded around: every bound modem
// registers its control port here at bring-up (the USB MBIM binding
// registers one Mbim port per modem). Data bearers are NOT ports —
// they are netdevs (see bearer.rs), mirroring Linux's wwan core,
// where bearers surface as network devices and only control channels
// are wwan ports.

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

static WWAN_PORTS: IrqSafeSpinLock<Vec<Arc<dyn WwanPort>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a bound modem's port. Called by transport bindings at
/// bring-up; ports are never removed (a detached modem's port fails
/// its operations at the transport, like a stale /dev/cdc-wdm node).
pub fn register_port(port: Arc<dyn WwanPort>) {
    WWAN_PORTS.lock().push(port);
}

/// Snapshot of all registered ports.
pub fn ports() -> Vec<Arc<dyn WwanPort>> {
    WWAN_PORTS.lock().clone()
}

/// Number of registered ports.
pub fn port_count() -> usize {
    WWAN_PORTS.lock().len()
}

/// Look up a port by its name (e.g. "wwan0mbim").
pub fn port_by_name(name: &str) -> Option<Arc<dyn WwanPort>> {
    WWAN_PORTS.lock().iter().find(|p| p.name() == name).cloned()
}

// ─── initcall registration ───────────────────────────────────────────────────
//
// The crate's first initcall: one Stage::Subsys registration,
// "wwan-usb-mbim", which registers the CDC-MBIM class driver with
// the USB class registry. The IOSM initcall the Stage-0/1 scaffold
// once sketched ("wwan-iosm") is NOT registered: there is still no
// IOSM transport to probe with, and an initcall that cannot bind
// anything would be census noise. It lands with the PCIe follow-on.

/// Register the crate's initcalls. Called by frame at boot.
pub fn register_initcalls() {
    narf_init::register(narf_init::Stage::Subsys, "wwan-usb-mbim", || {
        usb_mbim::register();
        narf_init::InitResult::Ok
    });
}

// ─── Re-exports for convenience ──────────────────────────────────────────────

pub use iosm::IOSM_PCI_DEVICES;
pub use mbim::{MbimError, MbimHeader, MbimMessageType};
pub use qmi::{QmiError, QmiHeader};
pub use session::{MbimModem, MbimTransport};
