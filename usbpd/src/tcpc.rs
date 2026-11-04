//! Type-C Port Controller interface (TCPCI 2.0).
//!
//! A TCPC is the chip that sits next to the Type-C connector and
//! handles physical-layer USB-PD framing, BMC encoding, and CC pin
//! sensing. The TCPM (in `tcpm.rs`) drives a TCPC over a register
//! interface defined by USB-IF TCPCI 2.0 — every vendor TCPC
//! (Fairchild FUSB302, TI TPS6598x, ON FUSB30x) exposes the same
//! register map (with vendor extensions).
//!
//! We model only the subset the sink-role state machine needs:
//! - Read CC1/CC2 status.
//! - Set port role (sink / source / drp).
//! - Transmit a PD message.
//! - Receive the next pending PD message.

use alloc::vec::Vec;
use core::fmt::Debug;

/// Error from a TCPC operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpcError {
    /// I2C / SPI bus error talking to the chip.
    BusError,
    /// Chip reported a transmit failure (BMC collision, no GoodCRC).
    TransmitFailed,
    /// Receive FIFO is empty.
    NoMessage,
    /// Operation isn't supported by this TCPC.
    Unsupported,
}

/// CC pin state (TCPCI §4.4.2.1, "ROLE_CONTROL.CC*"). The TCPM reads
/// this to decide attach/detach + cable orientation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CcState {
    /// CC pin is open — no termination.
    Open,
    /// CC pin sees Rd from the partner: a sink is attached.
    Rd,
    /// CC pin sees Ra from the partner: a powered cable is attached.
    Ra,
    /// CC pin sees Rp@1.5A — partner is advertising 5V/1.5A.
    Rp1A5,
    /// CC pin sees Rp@3A — partner is advertising 5V/3A.
    Rp3A0,
    /// CC pin sees Rp@default — partner is advertising USB default current.
    RpDefault,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CcStatus {
    pub cc1: CcState,
    pub cc2: CcState,
}

impl CcStatus {
    /// `true` when at least one CC line shows a connected sink/cable.
    pub fn attached(&self) -> bool {
        !matches!(
            (self.cc1, self.cc2),
            (CcState::Open, CcState::Open)
                | (CcState::Open, CcState::Ra)
                | (CcState::Ra, CcState::Open)
        )
    }
}

/// Port role programmed into the TCPC.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PortRole {
    /// Sink: pull-down (Rd) on both CC pins.
    Sink,
    /// Source: pull-up (Rp) on both CC pins.
    Source,
    /// Dual-Role Power: toggle Rp/Rd looking for a partner.
    Drp,
}

/// SOP* message target (USB-PD §6.2.1.1.6 values; mirrors the
/// `sop_prime` target constants).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SopTarget {
    /// Port partner (DFP/UFP).
    Sop = 0,
    /// Cable plug nearer the VConn source.
    SopPrime = 1,
    /// Cable plug at the far end of the cable.
    SopDoublePrime = 2,
}

impl SopTarget {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Sop),
            1 => Some(Self::SopPrime),
            2 => Some(Self::SopDoublePrime),
            _ => None,
        }
    }
}

/// TCPC trait. Vendor drivers (FUSB302, TPS6598x, …) implement.
pub trait Tcpc: Send + Sync + Debug {
    /// Stable name for diagnostics.
    fn name(&self) -> &'static str;

    /// Set the port's CC-line role.
    fn set_role(&self, role: PortRole) -> Result<(), TcpcError>;

    /// Snapshot the CC pin status.
    fn cc_status(&self) -> Result<CcStatus, TcpcError>;

    /// Transmit a PD message (header + data objects, already
    /// little-endian-packed by `message::encode_message`).
    fn transmit(&self, sop_msg: &[u8]) -> Result<(), TcpcError>;

    /// Transmit a PD message to a SOP* target. Default: `Sop`
    /// delegates to [`transmit`]; any other target reports
    /// `Unsupported` (the TCPC has no SOP* transmit path, e.g.
    /// firmware-mediated chips). FUSB302 overrides this with its
    /// SOP'/SOP'' ordered-set framing.
    fn transmit_sop(&self, target: SopTarget, msg: &[u8]) -> Result<(), TcpcError> {
        match target {
            SopTarget::Sop => self.transmit(msg),
            _ => Err(TcpcError::Unsupported),
        }
    }

    /// Pull the next pending PD message from the receive FIFO.
    /// Returns `Err(TcpcError::NoMessage)` when nothing is queued.
    fn receive(&self) -> Result<Vec<u8>, TcpcError>;

    /// Pull the next pending PD message plus the SOP* target it
    /// arrived on. Default: [`receive`] with target `Sop` (chips
    /// whose RX path does not report the target). FUSB302 overrides
    /// this from the RX FIFO token byte (datasheet Table 42: top
    /// three bits 111 = SOP, 110 = SOP', 101 = SOP'').
    /// SOP'/SOP'' reception additionally requires the chip-side
    /// enable (FUSB302 CONTROL1 ENSOP1/ENSOP2); without it the
    /// chip never queues cable-plug packets.
    fn receive_sop(&self) -> Result<(SopTarget, Vec<u8>), TcpcError> {
        Ok((SopTarget::Sop, self.receive()?))
    }

    /// Issue a Hard Reset on the wire. Used by the TCPM when
    /// negotiation goes wrong (§8.3.3.6).
    fn hard_reset(&self) -> Result<(), TcpcError> {
        Err(TcpcError::Unsupported)
    }
}
