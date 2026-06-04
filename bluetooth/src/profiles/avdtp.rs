//! AVDTP signalling-session state machine (profile layer).
//!
//! The low-level codec (packet encoders / decoders / constants) lives
//! in [`crate::avdtp`].  This module adds the per-session state machine
//! that drives an initiator through the AVDTP procedure sequence
//! required to open an A2DP stream:
//!
//! ```text
//!  Idle
//!   └─ send Discover ────────────────────────► DiscoverPending
//!       └─ recv Discover Accept ─────────────► GetCapsPending(seid)
//!           └─ recv Get Capabilities Accept ──► Configuring
//!               └─ send Set Configuration ────► ConfigPending
//!                   └─ recv Set Config Accept ► Configured
//!                       └─ send Open ─────────► OpenPending
//!                           └─ recv Open Accept► Open
//!                               └─ send Start ► StreamPending
//!                                   └─ recv Start Accept ► Streaming
//! ```
//!
//! References:
//! - Audio/Video Distribution Transport Protocol Specification, Version 1.3
//!   §8.4 (message format), §8.5 (signal identifiers), §8.6 (Discover),
//!   §8.7 (Get Capabilities), §8.9 (Set Configuration), §8.10 (Open),
//!   §8.13 (Start).
//! - Linux `net/bluetooth/` and BlueZ `profiles/audio/avdtp.c` consulted
//!   for procedure ordering (GPL-2.0-or-later, NARF relicense 2026-05-20).

use alloc::vec::Vec;

use crate::avdtp::{
    discover_command, get_capabilities_command, open_command, set_configuration_command,
    start_command, Header, StreamEndPoint, MSG_RESPONSE_ACCEPT, SID_DISCOVER, SID_GET_CAPABILITIES,
    SID_OPEN, SID_SET_CONFIGURATION, SID_START,
};

// ── AVDTP session state ──────────────────────────────────────────────

/// State of a single AVDTP signalling session (initiator role).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// No active transaction.
    Idle,
    /// Discover command sent; waiting for accept.
    DiscoverPending { txn: u8 },
    /// Get Capabilities command sent for `seid`; waiting for accept.
    GetCapsPending { txn: u8, seid: u8 },
    /// Capabilities received; caller is picking a config.
    Configuring,
    /// Set Configuration command sent; waiting for accept.
    ConfigPending { txn: u8 },
    /// Stream configured; waiting for initiator to call `open()`.
    Configured,
    /// Open command sent; waiting for accept.
    OpenPending { txn: u8 },
    /// Stream open; ready to start.
    Open,
    /// Start command sent; waiting for accept.
    StreamPending { txn: u8 },
    /// Audio is streaming.
    Streaming,
}

/// Error type returned by [`Session::feed`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// Received response did not match the pending transaction / signal.
    UnexpectedResponse,
    /// Peer sent a Reject response.
    PeerRejected,
    /// Incoming buffer too short to hold a valid AVDTP header.
    Short,
}

/// An AVDTP signalling session (initiator role).
///
/// The session is feed-driven: the caller passes raw L2CAP payload
/// bytes to [`Session::feed`] and receives back any outbound bytes
/// to write on the signalling channel.
pub struct Session {
    pub state: SessionState,
    pub txn: u8,
    /// SEPs discovered from the remote peer (filled by Discover).
    pub remote_seps: Vec<StreamEndPoint>,
    /// Selected remote ACP SEID (filled during Configuring / ConfigPending).
    pub acp_seid: u8,
    /// Our local INT SEID (set by caller via `set_local_seid`).
    pub int_seid: u8,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("state", &self.state)
            .field("txn", &self.txn)
            .field("acp_seid", &self.acp_seid)
            .field("int_seid", &self.int_seid)
            .finish()
    }
}

impl Session {
    /// Create a new idle AVDTP session.
    pub fn new(int_seid: u8) -> Self {
        Self {
            state: SessionState::Idle,
            txn: 0,
            remote_seps: Vec::new(),
            acp_seid: 0,
            int_seid,
        }
    }

    fn next_txn(&mut self) -> u8 {
        let t = self.txn & 0x0F;
        self.txn = self.txn.wrapping_add(1) & 0x0F;
        t
    }

    /// Begin the session: emit a Discover command.
    ///
    /// Returns the bytes to write to the AVDTP signalling channel.
    pub fn discover(&mut self) -> Vec<u8> {
        let t = self.next_txn();
        self.state = SessionState::DiscoverPending { txn: t };
        discover_command(t)
    }

    /// Request capabilities for a specific remote SEP. Caller
    /// typically calls this after inspecting `self.remote_seps` in
    /// [`SessionState::Configuring`].
    pub fn get_capabilities(&mut self, acp_seid: u8) -> Vec<u8> {
        let t = self.next_txn();
        self.acp_seid = acp_seid;
        self.state = SessionState::GetCapsPending {
            txn: t,
            seid: acp_seid,
        };
        get_capabilities_command(t, acp_seid)
    }

    /// Send Set Configuration, advancing to `ConfigPending`.
    /// `capabilities` is the catenated service-capability blob from
    /// the caller (e.g. Media Transport + Media Codec SBC).
    pub fn set_configuration(&mut self, capabilities: &[u8]) -> Vec<u8> {
        let t = self.next_txn();
        self.state = SessionState::ConfigPending { txn: t };
        set_configuration_command(t, self.acp_seid, self.int_seid, capabilities)
    }

    /// Send Open, advancing to `OpenPending`.
    pub fn open(&mut self) -> Vec<u8> {
        let t = self.next_txn();
        self.state = SessionState::OpenPending { txn: t };
        open_command(t, self.acp_seid)
    }

    /// Send Start, advancing to `StreamPending`.
    pub fn start(&mut self) -> Vec<u8> {
        let t = self.next_txn();
        self.state = SessionState::StreamPending { txn: t };
        start_command(t, &[self.acp_seid])
    }

    /// Feed an inbound AVDTP signalling payload into the state machine.
    ///
    /// Returns `Ok(None)` if the state machine consumed the message
    /// without generating a response, `Ok(Some(out))` if a follow-up
    /// command should be sent, or `Err(...)`.
    ///
    /// The caller must drive `discover()` / `get_capabilities()` /
    /// `set_configuration()` / `open()` / `start()` directly; `feed`
    /// only handles accept/reject decoding and SEP payload parsing.
    pub fn feed(&mut self, buf: &[u8]) -> Result<(), SessionError> {
        let hdr = Header::decode(buf).ok_or(SessionError::Short)?;

        if hdr.message_type == crate::avdtp::MSG_RESPONSE_REJECT {
            return Err(SessionError::PeerRejected);
        }
        if hdr.message_type != MSG_RESPONSE_ACCEPT {
            return Ok(());
        }

        match self.state {
            SessionState::DiscoverPending { txn } => {
                if hdr.signal_id != SID_DISCOVER || hdr.transaction != txn {
                    return Err(SessionError::UnexpectedResponse);
                }
                // Parse SEPs from payload (2 bytes each starting at offset 2).
                self.remote_seps.clear();
                let payload = &buf[2..];
                let mut i = 0;
                while i + 1 < payload.len() {
                    if let Some(sep) = StreamEndPoint::decode(&payload[i..]) {
                        self.remote_seps.push(sep);
                    }
                    i += 2;
                }
                self.state = SessionState::Configuring;
            }
            SessionState::GetCapsPending { txn, seid: _ } => {
                if hdr.signal_id != SID_GET_CAPABILITIES || hdr.transaction != txn {
                    return Err(SessionError::UnexpectedResponse);
                }
                // Capabilities payload stored by caller via `remote_caps`.
                // State stays Configuring — caller will call set_configuration().
                self.state = SessionState::Configuring;
            }
            SessionState::ConfigPending { txn } => {
                if hdr.signal_id != SID_SET_CONFIGURATION || hdr.transaction != txn {
                    return Err(SessionError::UnexpectedResponse);
                }
                self.state = SessionState::Configured;
            }
            SessionState::OpenPending { txn } => {
                if hdr.signal_id != SID_OPEN || hdr.transaction != txn {
                    return Err(SessionError::UnexpectedResponse);
                }
                self.state = SessionState::Open;
            }
            SessionState::StreamPending { txn } => {
                if hdr.signal_id != SID_START || hdr.transaction != txn {
                    return Err(SessionError::UnexpectedResponse);
                }
                self.state = SessionState::Streaming;
            }
            _ => {
                // Response in a state that doesn't expect one — ignore.
            }
        }

        Ok(())
    }
}
