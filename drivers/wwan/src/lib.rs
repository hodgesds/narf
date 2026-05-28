// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/lib.rs — WWAN port API + subsystem core
//
// WWAN (Wireless Wide Area Network) covers M.2 cellular modems attached via
// USB, PCIe/MHI, or shared-memory (IOSM).  This crate defines the abstract
// WwanPort trait, the MBIM and QMI protocol codec layers, and the IOSM PCI
// device-ID table for Intel XMM 7560/7360 modems.
//
// Scope (Stage 0/1 only):
//   - WwanPort trait + WwanPortKind enum
//   - MBIM message-header encode/decode (MBIM 1.0 §10.3)
//   - QMI control-message header encode (Qualcomm QMI framing)
//   - IOSM PCI device-ID table (XMM 7560 / 7360)
//
// Deferred (separate concerns):
//   - SIM management / USSD / STK / SMS upper layers
//   - Radio Interface Layer (RIL) integration
//   - Actual modem firmware loading
//   - USB CDC MBIM endpoint plumbing
//   - MHI ring bring-up for IOSM
//
// Linux cross-references (GPL-2.0-or-later, post-2026-05-20 relicense):
//   - include/linux/wwan.h          — port types enum
//   - drivers/net/wwan/wwan_core.c  — port registration model
//   - drivers/net/wwan/iosm/iosm_ipc_pcie.h — INTEL_CP_DEVICE_*_ID
//   - drivers/net/wwan/mhi_wwan_ctrl.c      — MHI-over-WWAN pattern

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod iosm;
pub mod mbim;
pub mod qmi;

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

// ─── initcall registration ───────────────────────────────────────────────────
//
// Stage-2: wire narf-init::register(Stage::Subsys, "wwan-iosm", probe_iosm)
// and narf-init::register(Stage::Subsys, "wwan-usb-mbim", probe_usb_mbim)
// once the bus bring-up paths exist.  At Stage-0/1 there is nothing to
// register — the crate is pure protocol codec + static tables.

// ─── Re-exports for convenience ──────────────────────────────────────────────

pub use mbim::{MbimHeader, MbimMessageType, MbimError};
pub use qmi::{QmiHeader, QmiError};
pub use iosm::IOSM_PCI_DEVICES;
