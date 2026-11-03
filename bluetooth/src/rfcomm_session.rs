//! RFCOMM responder session — one L2CAP channel's multiplexer.
//!
//! Spec sources (public-only):
//! - Bluetooth Core Specification 5.3, Vol 3 Part B (RFCOMM). §5.2
//!   frame format, §5.3 frame types, §5.4 DLCI assignment.
//! - ETSI TS 07.10 — the underlying multiplexed-serial protocol.
//!   Only the byte layout is referenced here (via `rfcomm::Frame`).
//!
//! No GPL Linux source consulted.
//!
//! ## Behaviour contract
//!
//! - The session mirrors the peer's DLCIs: it never computes a
//!   server-channel → DLCI mapping itself (the direction-bit
//!   convention is deliberately not interpreted here), so SABM on
//!   any DLCI is answered on that same DLCI.
//! - Responses flip the incoming frame's C/R bit (command/response
//!   distinction, TS 07.10 §5.1.1); the session never initiates.
//! - Multiplexer-control UIH commands (MSC, PN, RPN, RLS, NSC) are
//!   NOT answered: the peer proceeds with defaults. This is a
//!   documented limitation, not silent success — data DLCs work
//!   without them.
//! - UIH data on a closed DLC gets DM (not silent drop); SABM on a
//!   closed multiplexer gets DM; SABM re-opens a DLC with a cleared
//!   receive queue.

use alloc::vec::Vec;

use crate::rfcomm::{Frame, FRAME_DISC, FRAME_DM, FRAME_SABM, FRAME_UA, FRAME_UIH};

/// Maximum DLCs per session (DLCI 1..=61 are user channels).
const MAX_DLCS: usize = 61;

/// One data link connection inside the session.
#[derive(Debug)]
struct SessionDlc {
    dlci: u8,
    open: bool,
    rx: Vec<Vec<u8>>,
}

/// Responder-side RFCOMM session for one L2CAP channel.
#[derive(Debug)]
pub struct RfcommSession {
    mux_open: bool,
    dlcs: Vec<SessionDlc>,
}

impl Default for RfcommSession {
    fn default() -> Self {
        Self::new()
    }
}

impl RfcommSession {
    pub fn new() -> Self {
        Self {
            mux_open: false,
            dlcs: Vec::new(),
        }
    }

    pub fn is_mux_open(&self) -> bool {
        self.mux_open
    }

    /// Drain all staged UIH payloads for `dlci` (clears the queue).
    /// Returns an empty vec for an unknown or closed DLC.
    pub fn drain_rx(&mut self, dlci: u8) -> Vec<Vec<u8>> {
        match self.dlcs.iter_mut().find(|d| d.dlci == dlci) {
            Some(dlc) => core::mem::take(&mut dlc.rx),
            None => Vec::new(),
        }
    }

    /// Feed one decoded RFCOMM frame; returns the response frames
    /// (usually zero or one). Corrupt frames never reach here —
    /// `Frame::decode` rejects them first.
    pub fn feed(&mut self, frame: &Frame) -> Vec<Frame> {
        if frame.dlci == 0 {
            return self.feed_mux(frame);
        }
        self.feed_dlc(frame)
    }

    fn feed_mux(&mut self, frame: &Frame) -> Vec<Frame> {
        match frame.frame_type {
            FRAME_SABM => {
                self.mux_open = true;
                alloc::vec![Frame::ua(0, !frame.cr)]
            }
            FRAME_DISC => {
                self.mux_open = false;
                for dlc in self.dlcs.iter_mut() {
                    dlc.open = false;
                    dlc.rx.clear();
                }
                alloc::vec![Frame::ua(0, !frame.cr)]
            }
            FRAME_UA | FRAME_DM => Vec::new(),
            // UIH on the mux channel is a multiplexer-control command
            // (MSC/PN/RPN/RLS/NSC): unimplemented, no response.
            _ => Vec::new(),
        }
    }

    fn feed_dlc(&mut self, frame: &Frame) -> Vec<Frame> {
        let idx = self.dlcs.iter().position(|d| d.dlci == frame.dlci);
        match frame.frame_type {
            FRAME_SABM => {
                if !self.mux_open {
                    return alloc::vec![Frame::dm(frame.dlci, !frame.cr)];
                }
                match idx {
                    Some(i) => {
                        self.dlcs[i].open = true;
                        self.dlcs[i].rx.clear();
                    }
                    None => {
                        if self.dlcs.len() >= MAX_DLCS {
                            return alloc::vec![Frame::dm(frame.dlci, !frame.cr)];
                        }
                        self.dlcs.push(SessionDlc {
                            dlci: frame.dlci,
                            open: true,
                            rx: Vec::new(),
                        });
                    }
                }
                alloc::vec![Frame::ua(frame.dlci, !frame.cr)]
            }
            FRAME_DISC => match idx {
                Some(i) if self.dlcs[i].open => {
                    self.dlcs[i].open = false;
                    self.dlcs[i].rx.clear();
                    alloc::vec![Frame::ua(frame.dlci, !frame.cr)]
                }
                _ => alloc::vec![Frame::dm(frame.dlci, !frame.cr)],
            },
            FRAME_UIH => match idx {
                Some(i) if self.dlcs[i].open => {
                    self.dlcs[i].rx.push(frame.info.clone());
                    Vec::new()
                }
                _ => alloc::vec![Frame::dm(frame.dlci, !frame.cr)],
            },
            FRAME_DM => {
                if let Some(i) = idx {
                    self.dlcs[i].open = false;
                    self.dlcs[i].rx.clear();
                }
                Vec::new()
            }
            // UA and anything else: we never initiate, so there is
            // nothing to acknowledge.
            _ => Vec::new(),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn rfcomm_mux_then_dlc_round_trip() -> TestResult {
        let mut session = RfcommSession::new();
        // SABM on a DLC before the mux is open -> DM.
        let rsp = session.feed(&Frame::sabm(2, true));
        if rsp.len() != 1 || rsp[0].frame_type != FRAME_DM {
            return TestResult::Fail("SABM before mux open should get DM");
        }
        // Open the mux, then the DLC.
        let rsp = session.feed(&Frame::sabm(0, true));
        if rsp.len() != 1 || rsp[0].frame_type != FRAME_UA || !session.is_mux_open() {
            return TestResult::Fail("mux SABM should get UA and open");
        }
        let rsp = session.feed(&Frame::sabm(2, true));
        if rsp.len() != 1 || rsp[0].frame_type != FRAME_UA || rsp[0].dlci != 2 {
            return TestResult::Fail("DLC SABM should get UA on the same DLCI");
        }
        // Data stages; DISC closes; UIH after close gets DM.
        let rsp = session.feed(&Frame::uih(2, true, alloc::vec![b'h', b'i']));
        if !rsp.is_empty() {
            return TestResult::Fail("UIH data must not be answered");
        }
        if session.drain_rx(2) != alloc::vec![alloc::vec![b'h', b'i']] {
            return TestResult::Fail("staged UIH payload mismatch");
        }
        let rsp = session.feed(&Frame::disc(2, true));
        if rsp.len() != 1 || rsp[0].frame_type != FRAME_UA {
            return TestResult::Fail("DLC DISC should get UA");
        }
        let rsp = session.feed(&Frame::uih(2, true, alloc::vec![b'x']));
        if rsp.len() != 1 || rsp[0].frame_type != FRAME_DM {
            return TestResult::Fail("UIH on closed DLC should get DM");
        }
        // Mux DISC closes everything.
        let rsp = session.feed(&Frame::disc(0, true));
        if rsp.len() != 1 || rsp[0].frame_type != FRAME_UA || session.is_mux_open() {
            return TestResult::Fail("mux DISC should get UA and close");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/rfcomm-session", rfcomm_mux_then_dlc_round_trip);
}
