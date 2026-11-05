//! L2CAP channel servers — the PSM registry and per-connection
//! channel state the pump routes dynamic CIDs to.
//!
//! Spec sources (public-only):
//! - Bluetooth Core Specification 5.3, Vol 3 Part A (L2CAP). §4
//!   (signalling), §4.22–§4.24 (LE credit-based connection, LE
//!   connection response, flow control credit), §3 (LE COC
//!   segmentation: the first K-frame of an SDU carries its 2-byte
//!   LE length prefix; later K-frames carry raw segments).
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! No GPL Linux source consulted.
//!
//! ## Credit convention (grounded, not guessed)
//!
//! The CID in a Flow Control Credit command is the *sender's local*
//! channel ID: the granter names the channel it receives on, and the
//! credit count is the number of further K-frames the peer may send
//! to that channel. So on receipt we match `peer_cid` (the peer's
//! local CID — the CID we send data on is the peer's, and the CID
//! the peer receives on is its own), and our own grants carry our
//! `local_cid`. A credit for an unknown CID is ignored, never
//! misapplied to another channel.
//!
//! ## Implementation choices (not spec values)
//!
//! - `LE_COC_MTU` (1024): largest SDU this side stages. `LE_COC_MPS`
//!   (256): largest single K-frame accepted. `LE_COC_INITIAL_CREDITS`
//!   (16): credits granted at open; when the remaining grant falls
//!   to `LE_COC_TOP_UP_THRESHOLD` (4) the pump tops it back up to
//!   16, so a well-behaved peer never stalls.
//! - An SDU whose declared length exceeds MTU, a K-frame larger than
//!   MPS, or a segment run that overruns the declared length is a
//!   peer protocol violation: the channel is dropped (the pump
//!   sends a Disconnection Request). The violation is never staged
//!   as data.
//! - BR/EDR data is routed regardless of the `configured` flag: the
//!   flag records that the peer completed configuration, but staged
//!   data is harmless and strict gating would drop data from peers
//!   that send early.

use alloc::vec::Vec;

use crate::rfcomm_session::RfcommSession;

/// What a registered PSM serves.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ServerKind {
    /// SDP server (BR/EDR PSM 0x0001).
    Sdp,
    /// RFCOMM responder session (BR/EDR PSM 0x0003).
    Rfcomm,
    /// No service handler: payloads are staged for a consumer.
    Generic,
}

/// PSM → server registry. BR/EDR and LE PSMs live in separate
/// namespaces (LE PSMs are the SPSM values of §4.22).
#[derive(Debug)]
pub struct ServerRegistry {
    bredr: Vec<(u16, ServerKind)>,
    le: Vec<(u16, ServerKind)>,
}

impl Default for ServerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerRegistry {
    /// Default registry: SDP + RFCOMM on BR/EDR, nothing on LE
    /// (LE services register explicitly via [`register_le`]).
    pub fn new() -> Self {
        Self {
            bredr: alloc::vec![
                (crate::l2cap::PSM_SDP, ServerKind::Sdp),
                (crate::l2cap::PSM_RFCOMM, ServerKind::Rfcomm),
            ],
            le: Vec::new(),
        }
    }

    pub fn register_bredr(&mut self, psm: u16, kind: ServerKind) {
        if let Some(slot) = self.bredr.iter_mut().find(|(p, _)| *p == psm) {
            slot.1 = kind;
        } else {
            self.bredr.push((psm, kind));
        }
    }

    pub fn register_le(&mut self, psm: u16, kind: ServerKind) {
        if let Some(slot) = self.le.iter_mut().find(|(p, _)| *p == psm) {
            slot.1 = kind;
        } else {
            self.le.push((psm, kind));
        }
    }

    pub fn lookup_bredr(&self, psm: u16) -> Option<ServerKind> {
        self.bredr
            .iter()
            .find(|(p, _)| *p == psm)
            .map(|(_, kind)| *kind)
    }

    pub fn lookup_le(&self, psm: u16) -> Option<ServerKind> {
        self.le
            .iter()
            .find(|(p, _)| *p == psm)
            .map(|(_, kind)| *kind)
    }

    /// Release a `Generic` (socket-listener) registration. Service
    /// entries (SDP/RFCOMM) are never removed: a socket that
    /// listened on a service PSM was refused at registration, so
    /// there is no Generic entry to remove for them.
    pub fn unregister_bredr(&mut self, psm: u16) {
        self.bredr
            .retain(|(p, kind)| !(*p == psm && *kind == ServerKind::Generic));
    }

    /// Release a `Generic` (socket-listener) LE registration.
    pub fn unregister_le(&mut self, psm: u16) {
        self.le
            .retain(|(p, kind)| !(*p == psm && *kind == ServerKind::Generic));
    }
}

/// Largest SDU staged on an LE COC channel (implementation choice).
pub const LE_COC_MTU: u16 = 1024;
/// Largest single K-frame accepted on an LE COC channel.
pub const LE_COC_MPS: u16 = 256;
/// Credits granted to the peer at open, and topped back up to.
pub const LE_COC_INITIAL_CREDITS: u16 = 16;
/// Remaining-credit level that triggers a top-up grant.
pub const LE_COC_TOP_UP_THRESHOLD: u16 = 4;

/// Outcome of feeding one K-frame to an LE COC channel.
#[derive(Debug, PartialEq, Eq)]
pub enum LeReceiveOutcome {
    /// K-frame consumed; no SDU completed yet, no grant due.
    Consumed,
    /// K-frame consumed and an SDU completed; staged for drain.
    /// A top-up may also be due; the pump checks `take_top_up`
    /// after every consumed outcome.
    ConsumedSdu,
    /// No credit left: K-frame dropped, channel untouched.
    DroppedNoCredit,
    /// Peer protocol violation (oversize SDU, over-MPS K-frame,
    /// overrun): the pump must drop the channel.
    Violation,
}

/// One LE credit-based channel endpoint.
#[derive(Debug)]
pub struct LeCocChannel {
    pub local_cid: u16,
    pub peer_cid: u16,
    pub le_psm: u16,
    /// Largest SDU the peer accepts from us (informational: the
    /// pump never initiates sends on this channel yet).
    pub peer_mtu: u16,
    /// Largest K-frame the peer accepts from us (informational).
    pub peer_mps: u16,
    /// Credits the peer granted us (our send budget).
    pub peer_credits: u16,
    /// Credits we granted the peer (their send budget).
    pub local_credits: u16,
    /// Completed SDUs awaiting drain.
    pub rx: Vec<Vec<u8>>,
    /// In-progress SDU reassembly buffer (segments so far, without
    /// the 2-byte length prefix).
    reassembly: Vec<u8>,
    /// Declared SDU length once the first K-frame arrived; None
    /// when no SDU is in progress.
    reassembly_expected: Option<usize>,
    /// Pending top-up grant owed to the peer (set when the grant
    /// falls to the threshold; taken by the pump).
    top_up_due: u16,
}

impl LeCocChannel {
    pub fn new(
        local_cid: u16,
        peer_cid: u16,
        le_psm: u16,
        peer_mtu: u16,
        peer_mps: u16,
        peer_credits: u16,
    ) -> Self {
        Self {
            local_cid,
            peer_cid,
            le_psm,
            peer_mtu,
            peer_mps,
            peer_credits,
            local_credits: LE_COC_INITIAL_CREDITS,
            rx: Vec::new(),
            reassembly: Vec::new(),
            reassembly_expected: None,
            top_up_due: 0,
        }
    }

    /// Grant from the peer (Flow Control Credit receipt): adds to
    /// our send budget, saturating.
    pub fn grant_credits(&mut self, n: u16) {
        self.peer_credits = self.peer_credits.saturating_add(n);
    }

    /// Take a pending top-up grant owed to the peer (0 = none).
    pub fn take_top_up(&mut self) -> u16 {
        core::mem::take(&mut self.top_up_due)
    }

    /// Segment one SDU into K-frame payloads for transmission (§4.22:
    /// the first K-frame carries the 2-byte LE length prefix, later
    /// K-frames carry raw segments; each K-frame is at most
    /// `peer_mps`). All-or-nothing: `None` when the SDU exceeds the
    /// peer's MTU or the peer-credit budget cannot cover every
    /// K-frame — no credit is spent and no partial SDU is ever sent,
    /// so a `WouldBlock` send leaves the peer's reassembly untouched.
    /// On `Some`, the spent credits are deducted here.
    pub fn take_send_frames(&mut self, sdu: &[u8]) -> Option<Vec<Vec<u8>>> {
        if sdu.len() > self.peer_mtu as usize {
            return None;
        }
        let mps = self.peer_mps as usize;
        if mps < 2 {
            // An MPS below the length prefix cannot carry even the
            // first K-frame; the peer's open parameters were
            // unacceptable, so refuse rather than emit a malformed
            // frame. (Open refuses MPS 0; MPS 1 is refused here.)
            return None;
        }
        // K-frames: first carries the 2-byte prefix + up to mps-2
        // payload bytes; the rest carry up to mps bytes each.
        let first_capacity = mps - 2;
        let remaining = sdu.len().saturating_sub(first_capacity);
        let extra = remaining.div_ceil(mps);
        let needed = 1usize + extra;
        if (self.peer_credits as usize) < needed {
            return None;
        }
        self.peer_credits -= needed as u16;
        let mut frames = Vec::with_capacity(needed);
        let first_len = core::cmp::min(sdu.len(), first_capacity);
        let mut first = Vec::with_capacity(2 + first_len);
        first.extend_from_slice(&(sdu.len() as u16).to_le_bytes());
        first.extend_from_slice(&sdu[..first_len]);
        frames.push(first);
        let mut idx = first_len;
        while idx < sdu.len() {
            let end = core::cmp::min(idx + mps, sdu.len());
            frames.push(sdu[idx..end].to_vec());
            idx = end;
        }
        Some(frames)
    }

    /// Drain completed SDUs (clears the queue).
    pub fn take_rx(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.rx)
    }

    /// Feed one K-frame payload. Credit is consumed per K-frame,
    /// before any content check: a violating peer still spends its
    /// grant.
    pub fn receive(&mut self, kframe: &[u8]) -> LeReceiveOutcome {
        if self.local_credits == 0 {
            return LeReceiveOutcome::DroppedNoCredit;
        }
        self.local_credits -= 1;
        if self.local_credits <= LE_COC_TOP_UP_THRESHOLD {
            self.top_up_due = LE_COC_INITIAL_CREDITS - self.local_credits;
            self.local_credits = LE_COC_INITIAL_CREDITS;
        }
        if kframe.len() > LE_COC_MPS as usize {
            return LeReceiveOutcome::Violation;
        }
        if self.reassembly_expected.is_none() {
            if kframe.len() < 2 {
                // A first K-frame shorter than the length prefix
                // cannot start an SDU; drop the SDU, keep the
                // channel (defensive: the peer may retry).
                return LeReceiveOutcome::Consumed;
            }
            let expected = u16::from_le_bytes([kframe[0], kframe[1]]) as usize;
            if expected == 0 || expected > LE_COC_MTU as usize {
                return LeReceiveOutcome::Violation;
            }
            self.reassembly_expected = Some(expected);
            self.reassembly.extend_from_slice(&kframe[2..]);
        } else {
            self.reassembly.extend_from_slice(kframe);
        }
        let expected = self.reassembly_expected.unwrap();
        if self.reassembly.len() > expected {
            return LeReceiveOutcome::Violation;
        }
        if self.reassembly.len() == expected {
            let sdu = core::mem::take(&mut self.reassembly);
            self.reassembly_expected = None;
            self.rx.push(sdu);
            return LeReceiveOutcome::ConsumedSdu;
        }
        LeReceiveOutcome::Consumed
    }
}

/// Service state behind one BR/EDR channel.
#[derive(Debug)]
pub enum ChannelService {
    /// SDP request/response handler (stateless; the pump owns the
    /// record database).
    Sdp,
    /// RFCOMM responder session.
    Rfcomm(RfcommSession),
    /// Staged payloads for a consumer.
    Generic { rx: Vec<Vec<u8>> },
}

/// One BR/EDR dynamic channel endpoint.
#[derive(Debug)]
pub struct BrEdrChannel {
    pub local_cid: u16,
    pub peer_cid: u16,
    pub psm: u16,
    pub service: ChannelService,
    /// True once the peer's Configure Request was accepted.
    pub configured: bool,
}

impl BrEdrChannel {
    pub fn new(local_cid: u16, peer_cid: u16, psm: u16, kind: ServerKind) -> Self {
        let service = match kind {
            ServerKind::Sdp => ChannelService::Sdp,
            ServerKind::Rfcomm => ChannelService::Rfcomm(RfcommSession::new()),
            ServerKind::Generic => ChannelService::Generic { rx: Vec::new() },
        };
        Self {
            local_cid,
            peer_cid,
            psm,
            service,
            configured: false,
        }
    }
}

/// One open dynamic channel on a connection.
#[derive(Debug)]
pub enum Channel {
    Le(LeCocChannel),
    BrEdr(BrEdrChannel),
}

impl Channel {
    pub fn local_cid(&self) -> u16 {
        match self {
            Channel::Le(ch) => ch.local_cid,
            Channel::BrEdr(ch) => ch.local_cid,
        }
    }

    pub fn peer_cid(&self) -> u16 {
        match self {
            Channel::Le(ch) => ch.peer_cid,
            Channel::BrEdr(ch) => ch.peer_cid,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn le_coc_credit_and_reassembly() -> TestResult {
        let mut ch = LeCocChannel::new(0x0040, 0x0041, 0x0080, 1024, 256, 8);
        // Single-K-frame SDU "hi": length prefix + payload.
        match ch.receive(&[0x02, 0x00, b'h', b'i']) {
            LeReceiveOutcome::ConsumedSdu => {}
            _ => return TestResult::Fail("single-K-frame SDU should complete"),
        }
        if ch.take_rx() != alloc::vec![alloc::vec![b'h', b'i']] {
            return TestResult::Fail("completed SDU mismatch");
        }
        // Two-K-frame SDU "hello": 3 bytes then 2.
        match ch.receive(&[0x05, 0x00, b'h', b'e', b'l']) {
            LeReceiveOutcome::Consumed => {}
            _ => return TestResult::Fail("first segment should not complete"),
        }
        match ch.receive(b"lo") {
            LeReceiveOutcome::ConsumedSdu => {}
            _ => return TestResult::Fail("second segment should complete"),
        }
        if ch.take_rx() != alloc::vec![alloc::vec![b'h', b'e', b'l', b'l', b'o']] {
            return TestResult::Fail("segmented SDU mismatch");
        }
        // Credit accounting: 16 granted, 3 spent so far... this
        // channel started at 16: spent 3 (hi + 2 segments) = 13 left.
        // Spend 9 more single-K-frame SDUs -> 4 left -> top-up due.
        for _ in 0..9 {
            match ch.receive(&[0x01, 0x00, b'x']) {
                LeReceiveOutcome::ConsumedSdu => {}
                _ => return TestResult::Fail("top-up run SDU should complete"),
            }
        }
        if ch.local_credits != 16 {
            return TestResult::Fail("grant should top back up to 16");
        }
        if ch.take_top_up() != 12 {
            return TestResult::Fail("top-up grant should be 12");
        }
        // Zero-credit drop: force credits to 0 without a top-up by
        // spending... top-up always restores, so drain the grant
        // directly and check the defensive path.
        ch.local_credits = 0;
        ch.top_up_due = 0;
        match ch.receive(&[0x01, 0x00, b'y']) {
            LeReceiveOutcome::DroppedNoCredit => {}
            _ => return TestResult::Fail("zero-credit K-frame should drop"),
        }
        // Oversize SDU -> violation.
        ch.local_credits = 16;
        match ch.receive(&[0xFF, 0x07, b'z']) {
            LeReceiveOutcome::Violation => {}
            _ => return TestResult::Fail("oversize SDU should violate"),
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/l2cap-server", le_coc_credit_and_reassembly);

    /// #814: LE CoC send segmentation — K-frame layout, credit
    /// deduction, all-or-nothing refusal when the budget or the
    /// peer MTU cannot cover the SDU.
    fn le_coc_send_segmentation_and_credits() -> TestResult {
        // Peer MTU 1024, MPS 256, 8 credits.
        let mut ch = LeCocChannel::new(0x0040, 0x0041, 0x0080, 1024, 256, 8);
        // 5-byte SDU: one K-frame (2-byte prefix + 5 payload).
        let frames = match ch.take_send_frames(b"hello") {
            Some(f) => f,
            None => return TestResult::Fail("small SDU should segment"),
        };
        if frames.len() != 1 || frames[0] != alloc::vec![0x05, 0x00, b'h', b'e', b'l', b'l', b'o'] {
            return TestResult::Fail("single-K-frame layout mismatch");
        }
        if ch.peer_credits != 7 {
            return TestResult::Fail("one credit should be spent");
        }
        // 300-byte SDU: first K-frame carries 254 payload bytes
        // (256 - 2 prefix), second carries the remaining 46.
        let sdu = alloc::vec![0xAB; 300];
        let frames = match ch.take_send_frames(&sdu) {
            Some(f) => f,
            None => return TestResult::Fail("300-byte SDU should segment"),
        };
        if frames.len() != 2 || frames[0].len() != 256 || frames[1].len() != 46 {
            return TestResult::Fail("two-K-frame split mismatch");
        }
        if frames[0][0] != 0x2C || frames[0][1] != 0x01 {
            return TestResult::Fail("length prefix should be 300 LE");
        }
        if ch.peer_credits != 5 {
            return TestResult::Fail("two more credits should be spent");
        }
        // Oversize vs peer MTU: refused, no credit spent.
        let big = alloc::vec![0x00; 1025];
        if ch.take_send_frames(&big).is_some() {
            return TestResult::Fail("SDU over peer MTU should refuse");
        }
        if ch.peer_credits != 5 {
            return TestResult::Fail("refused SDU must not spend credit");
        }
        // Credit exhaustion: a 5-K-frame SDU needs 5 credits, 5 are
        // left — succeeds and drains the budget; the next send (any
        // size) refuses with the budget at zero.
        let sdu = alloc::vec![0xCD; 1024];
        let frames = match ch.take_send_frames(&sdu) {
            Some(f) => f,
            None => return TestResult::Fail("1024-byte SDU should take 5 credits"),
        };
        if frames.len() != 5 || ch.peer_credits != 0 {
            return TestResult::Fail("budget should drain to zero");
        }
        if ch.take_send_frames(b"x").is_some() {
            return TestResult::Fail("zero-credit send should refuse");
        }
        // Granting credits re-opens the budget.
        ch.grant_credits(2);
        if ch.take_send_frames(b"hi").is_none() || ch.peer_credits != 1 {
            return TestResult::Fail("granted credits should fund a send");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/l2cap-server",
        le_coc_send_segmentation_and_credits
    );

    /// #814: the registry releases only Generic (socket-listener)
    /// entries; service entries survive unregister.
    fn server_registry_unregister_keeps_services() -> TestResult {
        let mut reg = ServerRegistry::new();
        if reg.lookup_bredr(crate::l2cap::PSM_SDP) != Some(ServerKind::Sdp) {
            return TestResult::Fail("SDP should be pre-registered");
        }
        reg.register_bredr(0x0101, ServerKind::Generic);
        reg.register_le(0x0080, ServerKind::Generic);
        reg.unregister_bredr(crate::l2cap::PSM_SDP);
        reg.unregister_bredr(crate::l2cap::PSM_RFCOMM);
        reg.unregister_bredr(0x0101);
        reg.unregister_le(0x0080);
        if reg.lookup_bredr(crate::l2cap::PSM_SDP) != Some(ServerKind::Sdp) {
            return TestResult::Fail("unregister must not remove SDP");
        }
        if reg.lookup_bredr(crate::l2cap::PSM_RFCOMM) != Some(ServerKind::Rfcomm) {
            return TestResult::Fail("unregister must not remove RFCOMM");
        }
        if reg.lookup_bredr(0x0101).is_some() || reg.lookup_le(0x0080).is_some() {
            return TestResult::Fail("Generic entries should be released");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/l2cap-server",
        server_registry_unregister_keeps_services
    );
}
