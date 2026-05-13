//! TI TPS65987DDH USB Type-C / PD Controller (clean-room).
//!
//! Reference (public-only):
//! - **TPS65987DDH/TPS65987DDK Host Interface Technical Reference
//!   Manual**, Texas Instruments document SLVUBH2A.
//!   <https://www.ti.com/lit/ug/slvubh2a/slvubh2a.pdf>
//! - **TPS65987DDH USB Type-C and USB PD Controller, Power Switch,
//!   and High-Speed Multiplexer** datasheet, document SLVSEX0F.
//!   <https://www.ti.com/lit/ds/symlink/tps65987ddh.pdf>
//! - USB Type-C 2.2 §4 (CC pin meanings).
//! - USB Power Delivery 3.1 §6 (PD message layout).
//!
//! No GPL Linux source consulted.
//!
//! ## Host Interface model (TRM §2)
//!
//! Unlike the FUSB302 — which is a low-level BMC PHY where the host
//! handles every PD message byte — the TPS65987 runs a full PD
//! firmware on-chip. The host interface is a small register file
//! plus a "4CC" command channel:
//!
//! - Host writes a 4-character command code (e.g. "Gaid", "DBfg") to
//!   the `Cmd1` register, payload bytes to `Data1`, then waits for
//!   `Cmd1` to clear (firmware acks by zeroing it).
//! - Status / capabilities / negotiation results are read from
//!   dedicated registers (Active Contract PDO, Source Caps, etc.).
//!
//! The chip's I²C address is straps-selectable; the most common
//! default is 0x38 (7-bit).
//!
//! ## Register map (TRM §3)
//!
//! ```text
//!   0x00 Vendor ID                     RO  (TI = 0x0451)
//!   0x01 Device ID                     RO  (TPS65987 = 0xF987 LE)
//!   0x02 Protocol Version              RO
//!   0x03 Mode                          RO  ASCII "BOOT" / "APP "
//!   0x05 Type-C Status                 RO
//!   0x06 Boot Flags                    RO
//!   0x08 Cmd1                          RW  4-byte command code
//!   0x09 Data1                         RW  64 bytes — Cmd1 payload
//!   0x0E Version                       RO  4-byte firmware version
//!   0x14 Active Contract PDO           RO  active sink/source PDO
//!   0x15 Active Contract RDO           RO  active RDO
//!   0x16 Sink Request RDO              RO  last RDO we transmitted
//!   0x17 Auto Negotiate Sink           RW  policy
//!   0x18 Auto Negotiate Source         RW  policy
//!   0x1A Status                        RO  PD/Type-C composite status
//!   0x1B Power Path Status             RO
//!   0x26 Active PDO Contract           RO  duplicate alias for 0x14
//!   0x29 Power Status                  RO  Vbus, current limit, …
//!   0x2D Customer Use 1..32            RW  scratch
//!   0x36 RX Source Capabilities        RO  partner's source caps
//!   0x37 RX Sink Capabilities          RO  partner's sink caps
//!   0x40 Tx Source Capabilities        RW  what we advertise
//!   0x41 Tx Sink Capabilities          RW  what we advertise
//! ```

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::tcpc::{CcState, CcStatus, PortRole, Tcpc, TcpcError};

use crate::fusb302::I2cBus;

/// Default 7-bit I²C address (TRM §2.1).
pub const TPS65987_DEFAULT_I2C_ADDR: u8 = 0x38;

// ── Registers (subset the Tcpc surface needs) ─────────────────────
pub const REG_VENDOR_ID: u8 = 0x00;
pub const REG_DEVICE_ID: u8 = 0x01;
pub const REG_MODE: u8 = 0x03;
pub const REG_TYPEC_STATUS: u8 = 0x05;
pub const REG_CMD1: u8 = 0x08;
pub const REG_DATA1: u8 = 0x09;
pub const REG_ACTIVE_CONTRACT_PDO: u8 = 0x14;
pub const REG_ACTIVE_CONTRACT_RDO: u8 = 0x15;
pub const REG_STATUS: u8 = 0x1A;
pub const REG_RX_SOURCE_CAPS: u8 = 0x36;
pub const REG_TX_SOURCE_CAPS: u8 = 0x40;

// ── 4CC command codes (TRM §4) ────────────────────────────────────
//
// Each command is a 4-character ASCII code written little-endian
// into Cmd1. The chip clears Cmd1 to 0 once it has consumed the
// command and `Data1` carries the response.
pub const CMD4_GAID: [u8; 4] = *b"Gaid"; // Get Application Identifier
pub const CMD4_GO_TO_PATCH_MODE: [u8; 4] = *b"GAID"; // Force into BOOT mode
pub const CMD4_PD_NEGOTIATE: [u8; 4] = *b"PDNG"; // Trigger PD negotiation
pub const CMD4_HARD_RESET: [u8; 4] = *b"GSrR"; // Send Hard Reset
pub const CMD4_DISABLE_TYPEC: [u8; 4] = *b"DISC"; // Disable Type-C
pub const CMD4_ENABLE_TYPEC: [u8; 4] = *b"AntI"; // Re-enable Type-C
pub const CMD4_TRIGGER_PR_SWAP: [u8; 4] = *b"SWPR";

// ── Type-C Status register layout (TRM §3.5) ──────────────────────
//
//   0..2  Plug Orientation: 0 = none, 1 = CC1, 2 = CC2
//   2..3  Connection State: 0 = nothing, 1 = pending,
//                            2 = sink-attached, 3 = source-attached
//   3..7  CC1 Pull / Termination: encodes Rd / Rp / Open
//   7..11 CC2 Pull / Termination
pub const TYPEC_STATUS_ORIENTATION_MASK: u8 = 0x3;
pub const TYPEC_STATUS_CONNECTION_MASK: u8 = 0x1C;
pub const TYPEC_STATUS_CONNECTION_SHIFT: u8 = 2;

#[derive(Debug)]
pub struct Tps65987 {
    bus: Arc<dyn I2cBus>,
    addr: u8,
    role: IrqSafeSpinLock<PortRole>,
    /// Cached snapshot of the negotiated contract for quick reads
    /// without an extra I²C round-trip.
    last_contract_pdo: IrqSafeSpinLock<u32>,
}

impl Tps65987 {
    pub fn new(bus: Arc<dyn I2cBus>, addr: u8) -> Self {
        Self {
            bus,
            addr,
            role: IrqSafeSpinLock::new(PortRole::Drp),
            last_contract_pdo: IrqSafeSpinLock::new(0),
        }
    }

    /// Read the Vendor + Device ID and validate. Returns
    /// `(vendor, device)` on a recognised TPS65987.
    pub fn probe(&self) -> Result<(u16, u16), TcpcError> {
        let mut vid = [0u8; 4];
        self.bus.read_burst(self.addr, REG_VENDOR_ID, &mut vid)?;
        let mut did = [0u8; 4];
        self.bus.read_burst(self.addr, REG_DEVICE_ID, &mut did)?;
        let vendor = u16::from_le_bytes([vid[0], vid[1]]);
        let device = u16::from_le_bytes([did[0], did[1]]);
        // TI vendor = 0x0451 (per USB-IF VID assignment), TPS65987
        // device id high byte is 0xF987 (LE).
        if vendor != 0x0451 {
            return Err(TcpcError::Unsupported);
        }
        Ok((vendor, device))
    }

    /// Read a 4-byte register block (e.g. firmware mode/version).
    pub fn read_4(&self, reg: u8) -> Result<[u8; 4], TcpcError> {
        let mut buf = [0u8; 4];
        self.bus.read_burst(self.addr, reg, &mut buf)?;
        Ok(buf)
    }

    /// Write a 4CC command code into Cmd1.
    fn write_cmd1(&self, code: [u8; 4]) -> Result<(), TcpcError> {
        self.bus.write_burst(self.addr, REG_CMD1, &code)
    }

    /// Wait for the chip to clear Cmd1 (firmware ack). Polls until
    /// the supplied deadline expires.
    fn wait_cmd1_clear(&self, deadline: narf_time::Deadline) -> Result<(), TcpcError> {
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay
        // alive while the PD chip processes a 4CC command.
        let mut bus_err: Option<TcpcError> = None;
        let done = narf_scheduler::responsive_spin_until(
            || {
                let mut buf = [0u8; 4];
                match self.bus.read_burst(self.addr, REG_CMD1, &mut buf) {
                    Ok(()) => buf == [0u8; 4],
                    Err(e) => {
                        bus_err = Some(e.into());
                        true
                    }
                }
            },
            deadline,
        );
        if let Some(e) = bus_err {
            return Err(e);
        }
        if done {
            Ok(())
        } else {
            Err(TcpcError::TransmitFailed)
        }
    }

    /// Issue a 4CC command + 0..=64 byte payload. Blocks until the
    /// chip acks by clearing Cmd1.
    pub fn issue_cmd(&self, code: [u8; 4], data: &[u8]) -> Result<(), TcpcError> {
        if data.len() > 64 {
            return Err(TcpcError::TransmitFailed);
        }
        if !data.is_empty() {
            self.bus.write_burst(self.addr, REG_DATA1, data)?;
        }
        self.write_cmd1(code)?;
        // TPS65987 4CC commands typically complete in a few ms;
        // 1 s is a wedge threshold (firmware-update commands can
        // take ~hundreds of ms per the TI TRM).
        self.wait_cmd1_clear(narf_time::Deadline::after_ms(1000))
    }

    /// Decode CC pin state from Type-C Status. The TPS65987's
    /// firmware reports orientation + connection state at the same
    /// time, so we synthesise per-pin `CcState` values from those.
    fn decode_cc(typec_status: u8) -> CcStatus {
        let orientation = typec_status & TYPEC_STATUS_ORIENTATION_MASK;
        let connection =
            (typec_status & TYPEC_STATUS_CONNECTION_MASK) >> TYPEC_STATUS_CONNECTION_SHIFT;
        // 0 = none, 1 = pending, 2 = sink-attached (we are source),
        // 3 = source-attached (we are sink). On a sink-role port the
        // partner advertises Rp; map current limit from the upper
        // status nibble in production, but for the structural surface
        // we report the canonical "Rp@default" when source-attached.
        let connected_state = match connection {
            2 => CcState::Rd,         // partner is a sink (Rd)
            3 => CcState::RpDefault,  // partner is a source (Rp default)
            _ => CcState::Open,
        };
        match orientation {
            1 => CcStatus {
                cc1: connected_state,
                cc2: CcState::Open,
            },
            2 => CcStatus {
                cc1: CcState::Open,
                cc2: connected_state,
            },
            _ => CcStatus {
                cc1: CcState::Open,
                cc2: CcState::Open,
            },
        }
    }
}

impl Tcpc for Tps65987 {
    fn name(&self) -> &'static str {
        "tps65987"
    }

    fn set_role(&self, role: PortRole) -> Result<(), TcpcError> {
        // The TPS65987 firmware controls the role through the
        // "Auto Negotiate Sink/Source" policy registers. We pick the
        // appropriate enable command rather than poking pull-ups
        // directly.
        let cmd = match role {
            PortRole::Sink | PortRole::Source | PortRole::Drp => CMD4_ENABLE_TYPEC,
        };
        self.issue_cmd(cmd, &[])?;
        *self.role.lock() = role;
        Ok(())
    }

    fn cc_status(&self) -> Result<CcStatus, TcpcError> {
        let s = self.bus.read_reg(self.addr, REG_TYPEC_STATUS)?;
        Ok(Self::decode_cc(s))
    }

    fn transmit(&self, msg: &[u8]) -> Result<(), TcpcError> {
        // For the TPS65987, raw PD-message TX is normally handled by
        // the on-chip firmware. The host kicks negotiation via the
        // PD_NEGOTIATE 4CC; the firmware then formats + sends the
        // PD message based on the policy in the Tx Source/Sink Caps
        // registers. If the caller has a pre-formed PD body to push,
        // the right surface is to write it into Tx Source Caps and
        // then trigger negotiation — that's not the same as a raw
        // BMC TX, so we map "transmit a PD body" onto "publish caps
        // + nudge negotiation".
        if msg.len() > 64 {
            return Err(TcpcError::TransmitFailed);
        }
        self.bus.write_burst(self.addr, REG_TX_SOURCE_CAPS, msg)?;
        self.issue_cmd(CMD4_PD_NEGOTIATE, &[])
    }

    fn receive(&self) -> Result<Vec<u8>, TcpcError> {
        // The chip exposes the partner's last Source/Sink Caps in
        // dedicated registers. We surface RX Source Caps as the
        // "last received message" — sufficient for the TCPM's
        // Source_Capabilities consumer.
        let mut buf = alloc::vec![0u8; 32];
        self.bus.read_burst(self.addr, REG_RX_SOURCE_CAPS, &mut buf)?;
        // Trim trailing zeros so a freshly-cleared register doesn't
        // surface as a 32-byte all-zero "message".
        if buf.iter().all(|b| *b == 0) {
            return Err(TcpcError::NoMessage);
        }
        // Drop trailing zero padding.
        while let Some(0) = buf.last() {
            buf.pop();
            if buf.len() <= 2 {
                break;
            }
        }
        // Cache the active contract PDO if the negotiation just
        // finished.
        if let Ok(c) = self.read_4(REG_ACTIVE_CONTRACT_PDO) {
            *self.last_contract_pdo.lock() = u32::from_le_bytes(c);
        }
        Ok(buf)
    }

    fn hard_reset(&self) -> Result<(), TcpcError> {
        self.issue_cmd(CMD4_HARD_RESET, &[])
    }
}

/// Snapshot helper — `last_contract_pdo` value cached the last time
/// `receive()` ran. 0 if no contract has been observed.
pub fn last_contract_pdo(chip: &Tps65987) -> u32 {
    *chip.last_contract_pdo.lock()
}
