// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/nfc/src/nxp_pn553.rs — NXP PN553 I2C vendor driver scaffold
//
// The PN553 is an NCI 1.0 compliant NFC controller accessed over I2C at
// 7-bit address 0x29 (typical board default).  The Linux driver it is derived
// from lives at drivers/nfc/nxp-nci/i2c.c; that driver uses a 32-byte max
// payload per I2C transaction (NXP_NCI_I2C_MAX_PAYLOAD = 32).
//
// Stage-0 only:
//   - I2C address constant
//   - Pn553Driver<T> wrapper struct
//   - NCI dispatcher helpers (send_cmd / recv_rsp)
//   - CORE_RESET / CORE_INIT / RF_DISCOVER_MAP / RF_DISCOVER convenience wrappers
//
// Deferred: firmware download, HCI bridge, secure element access.

use alloc::vec::Vec;

use crate::{
    core_init, core_reset, rf_discover, rf_discover_map, CoreInitResponse, NciMessage,
    NfcError, NfcTransport, RfDiscoverEntry, RfDiscoverMapEntry, NCI_RESET_RESET_CONFIG,
};

/// Default I2C 7-bit address of the NXP PN553.
///
/// Boards may override via firmware/ACPI, but 0x29 is the NXP silicon default.
/// Linux reference: drivers/nfc/nxp-nci/i2c.c — no explicit constant, derived
/// from board files / ACPI _HID NXP0001 / NXP0002.
pub const NXP_PN553_I2C_ADDR: u8 = 0x29;

/// Maximum NCI payload bytes per I2C transaction (NXP constraint).
///
/// Linux: `#define NXP_NCI_I2C_MAX_PAYLOAD 32`  (drivers/nfc/nxp-nci/i2c.c)
pub const NXP_PN553_MAX_PAYLOAD: usize = 32;

/// NXP PN553 NCI controller driver.
///
/// `T` is the concrete `NfcTransport` implementation (I2C bus wrapper).
/// In production this would hold a handle into the NARF I2C bus abstraction;
/// for Stage-0 we keep it generic so tests can inject a loopback transport.
#[derive(Debug)]
pub struct Pn553Driver<T: NfcTransport> {
    transport: T,
    /// I2C address in use (almost always NXP_PN553_I2C_ADDR).
    pub i2c_addr: u8,
}

impl<T: NfcTransport> Pn553Driver<T> {
    /// Construct a new PN553 driver bound to the given transport.
    pub fn new(transport: T) -> Self {
        Self { transport, i2c_addr: NXP_PN553_I2C_ADDR }
    }

    /// Construct with a non-default I2C address.
    pub fn with_addr(transport: T, addr: u8) -> Self {
        Self { transport, i2c_addr: addr }
    }

    // ─── Low-level dispatch ──────────────────────────────────────────────

    /// Serialize and transmit an `NciMessage` to the controller.
    ///
    /// The PN553 I2C transport has a 32-byte payload ceiling per transaction;
    /// multi-fragment transfers are not implemented at Stage-0.
    pub fn send_cmd(&self, msg: &NciMessage) -> Result<(), NfcError> {
        if msg.payload.len() > NXP_PN553_MAX_PAYLOAD {
            return Err(NfcError::LengthMismatch);
        }
        let wire = msg.encode();
        self.transport.write(&wire)
    }

    /// Read one NCI response/notification from the controller.
    ///
    /// Strategy (mirroring Linux nxp_nci_i2c_read):
    ///   1. Read the 3-byte NCI header.
    ///   2. Extract payload length from byte 2.
    ///   3. Read that many additional bytes.
    ///   4. Reassemble into an `NciMessage`.
    pub fn recv_rsp(&self) -> Result<NciMessage, NfcError> {
        let mut hdr = [0u8; 3];
        let n = self.transport.read(&mut hdr)?;
        if n < 3 {
            return Err(NfcError::ShortResponse);
        }
        let payload_len = hdr[2] as usize;
        let mut payload = Vec::with_capacity(payload_len);
        if payload_len > 0 {
            // Safety: we're about to write payload_len bytes via read()
            payload.resize(payload_len, 0u8);
            let got = self.transport.read(&mut payload)?;
            if got < payload_len {
                return Err(NfcError::ShortResponse);
            }
        }
        // Reconstruct a flat buffer for NciMessage::decode.
        let mut flat = Vec::with_capacity(3 + payload_len);
        flat.extend_from_slice(&hdr);
        flat.extend_from_slice(&payload);
        NciMessage::decode(&flat)
    }

    // ─── NCI command helpers ──────────────────────────────────────────────

    /// Send CORE_RESET_CMD and return the decoded response.
    ///
    /// `reset_config`: pass `NCI_RESET_RESET_CONFIG` to clear all NVM settings.
    pub fn do_core_reset(&self, reset_type: u8) -> Result<NciMessage, NfcError> {
        self.send_cmd(&core_reset(reset_type))?;
        self.recv_rsp()
    }

    /// Send CORE_RESET_CMD with RESET_CONFIG and return the decoded response.
    pub fn reset(&self) -> Result<NciMessage, NfcError> {
        self.do_core_reset(NCI_RESET_RESET_CONFIG)
    }

    /// Send CORE_INIT_CMD and decode the CORE_INIT_RSP.
    pub fn init(&self) -> Result<CoreInitResponse, NfcError> {
        self.send_cmd(&core_init())?;
        let rsp = self.recv_rsp()?;
        CoreInitResponse::from_message(&rsp)
    }

    /// Send RF_DISCOVER_MAP_CMD.
    pub fn discover_map(&self, entries: &[RfDiscoverMapEntry]) -> Result<NciMessage, NfcError> {
        self.send_cmd(&rf_discover_map(entries))?;
        self.recv_rsp()
    }

    /// Send RF_DISCOVER_CMD.
    pub fn discover(&self, entries: &[RfDiscoverEntry]) -> Result<NciMessage, NfcError> {
        self.send_cmd(&rf_discover(entries))?;
        self.recv_rsp()
    }
}
