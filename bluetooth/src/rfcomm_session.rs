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
    /// True when WE initiated this DLC (SABM sent by us): our UIH
    /// and DISC frames then carry C/R=1 (TS 07.10 §5.1.1 — the
    /// initiator sets C/R=1, the responder 0). Responder-side DLCs
    /// (peer SABM) keep C/R=0.
    initiator: bool,
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

    /// Whether `dlci` is currently open (SABM answered, no DISC
    /// since). A socket send must refuse a closed DLC instead of
    /// emitting a UIH the peer answers with DM.
    pub fn is_dlc_open(&self, dlci: u8) -> bool {
        self.dlcs.iter().any(|d| d.dlci == dlci && d.open)
    }

    /// DLCIs currently open, in open order. A socket `accept` claims
    /// the DLC whose server channel matches its listener.
    pub fn open_dlcs(&self) -> Vec<u8> {
        self.dlcs
            .iter()
            .filter(|d| d.open)
            .map(|d| d.dlci)
            .collect()
    }

    /// Whether `dlci` was opened by us (initiator) — our UIH/DISC
    /// frames on it carry C/R=1. False for responder-side DLCs and
    /// unknown DLCIs.
    pub fn is_dlc_initiator(&self, dlci: u8) -> bool {
        self.dlcs
            .iter()
            .any(|d| d.dlci == dlci && d.open && d.initiator)
    }

    /// Initiator side (#1532): record that the peer answered our
    /// SABM on DLCI 0 with UA — the multiplexer is open. The
    /// responder's `feed` ignores UA, so the initiator records it
    /// explicitly instead.
    pub fn mux_opened(&mut self) {
        self.mux_open = true;
    }

    /// Initiator side (#1532): record that the peer answered our
    /// SABM on `dlci` with UA — the DLC is open, initiated by us
    /// (C/R=1 on our frames), with a cleared receive queue.
    pub fn dlc_opened(&mut self, dlci: u8) {
        match self.dlcs.iter_mut().find(|d| d.dlci == dlci) {
            Some(dlc) => {
                dlc.open = true;
                dlc.initiator = true;
                dlc.rx.clear();
            }
            None => {
                if self.dlcs.len() < MAX_DLCS {
                    self.dlcs.push(SessionDlc {
                        dlci,
                        open: true,
                        initiator: true,
                        rx: Vec::new(),
                    });
                }
            }
        }
    }

    /// Close `dlci` from our side (the socket layer sends the DISC
    /// frame itself): the DLC stops staging and a later UIH on it
    /// gets DM, exactly as if the peer's DISC had arrived.
    pub fn close_dlc(&mut self, dlci: u8) {
        if let Some(dlc) = self.dlcs.iter_mut().find(|d| d.dlci == dlci) {
            dlc.open = false;
            dlc.rx.clear();
        }
    }

    /// Drain all staged UIH payloads for `dlci` (clears the queue).
    /// Returns an empty vec for an unknown or closed DLC.
    pub fn drain_rx(&mut self, dlci: u8) -> Vec<Vec<u8>> {
        match self.dlcs.iter_mut().find(|d| d.dlci == dlci) {
            Some(dlc) => core::mem::take(&mut dlc.rx),
            None => Vec::new(),
        }
    }

    /// Whether staged inbound data awaits on `dlci` — non-consuming
    /// peek for poll readability.
    pub fn rx_pending(&self, dlci: u8) -> bool {
        self.dlcs
            .iter()
            .any(|d| d.dlci == dlci && d.open && !d.rx.is_empty())
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
                        self.dlcs[i].initiator = false;
                        self.dlcs[i].rx.clear();
                    }
                    None => {
                        if self.dlcs.len() >= MAX_DLCS {
                            return alloc::vec![Frame::dm(frame.dlci, !frame.cr)];
                        }
                        self.dlcs.push(SessionDlc {
                            dlci: frame.dlci,
                            open: true,
                            initiator: false,
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

    /// #814: the socket-side DLC queries — open tracking, our-side
    /// close, and the open-DLC enumeration accept uses.
    fn rfcomm_session_dlc_queries() -> TestResult {
        let mut session = RfcommSession::new();
        if session.is_dlc_open(2) || !session.open_dlcs().is_empty() {
            return TestResult::Fail("fresh session should have no open DLC");
        }
        let _ = session.feed(&Frame::sabm(0, true));
        let _ = session.feed(&Frame::sabm(2, true));
        let _ = session.feed(&Frame::sabm(4, true));
        if !session.is_dlc_open(2) || !session.is_dlc_open(4) {
            return TestResult::Fail("SABM'd DLCs should read open");
        }
        if session.open_dlcs() != alloc::vec![2, 4] {
            return TestResult::Fail("open DLC enumeration mismatch");
        }
        // Our-side close: stops staging, later UIH gets DM.
        session.close_dlc(2);
        if session.is_dlc_open(2) || session.open_dlcs() != alloc::vec![4] {
            return TestResult::Fail("close_dlc should forget the DLC");
        }
        let rsp = session.feed(&Frame::uih(2, true, alloc::vec![b'x']));
        if rsp.len() != 1 || rsp[0].frame_type != FRAME_DM {
            return TestResult::Fail("UIH on our-closed DLC should get DM");
        }
        // Peek: staged data reads pending until drained.
        let _ = session.feed(&Frame::uih(4, true, alloc::vec![b'y']));
        if !session.rx_pending(4) || session.rx_pending(2) {
            return TestResult::Fail("rx_pending should track staged data");
        }
        let _ = session.drain_rx(4);
        if session.rx_pending(4) {
            return TestResult::Fail("drained DLC should not read pending");
        }
        // Closing an unknown DLC is a no-op, not a panic.
        session.close_dlc(60);
        if session.open_dlcs() != alloc::vec![4] {
            return TestResult::Fail("closing an unknown DLC must be a no-op");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/rfcomm-session", rfcomm_session_dlc_queries);

    /// #1532: the initiator side — UA receipts open the mux/DLC
    /// with C/R=1, and a responder-opened DLC stays C/R=0.
    fn rfcomm_session_initiator_open() -> TestResult {
        let mut session = RfcommSession::new();
        if session.is_dlc_initiator(2) {
            return TestResult::Fail("unknown DLC must not read initiator");
        }
        // Our SABM on DLCI 0 answered with UA: mux opens.
        session.mux_opened();
        if !session.is_mux_open() {
            return TestResult::Fail("mux_opened should open the mux");
        }
        // Our SABM on DLCI 3 answered with UA: DLC opens, initiator.
        session.dlc_opened(3);
        if !session.is_dlc_open(3) || !session.is_dlc_initiator(3) {
            return TestResult::Fail("dlc_opened should open an initiator DLC");
        }
        // Data stages on the initiator DLC.
        let rsp = session.feed(&Frame::uih(3, false, alloc::vec![b'k']));
        if !rsp.is_empty() || session.drain_rx(3) != alloc::vec![alloc::vec![b'k']] {
            return TestResult::Fail("initiator DLC should stage UIH data");
        }
        // A peer SABM on DLCI 4 opens a responder DLC (C/R=0).
        let rsp = session.feed(&Frame::sabm(4, true));
        if rsp.len() != 1 || rsp[0].frame_type != FRAME_UA {
            return TestResult::Fail("peer SABM should get UA");
        }
        if !session.is_dlc_open(4) || session.is_dlc_initiator(4) {
            return TestResult::Fail("peer-opened DLC must read responder-side");
        }
        // Re-opening an initiator DLC via dlc_opened keeps it
        // initiator and clears staged data.
        let _ = session.feed(&Frame::uih(3, false, alloc::vec![b'z']));
        session.dlc_opened(3);
        if !session.is_dlc_initiator(3) || !session.drain_rx(3).is_empty() {
            return TestResult::Fail("dlc_opened should clear rx and keep initiator");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/rfcomm-session", rfcomm_session_initiator_open);
}
