//! TCP connection state machine — RFC 9293 §3.3.2.
//!
//! ## State catalogue
//!
//! The eleven canonical states. Order is the "lifecycle order" for
//! a connection that takes the active-open path: SYN-SENT →
//! ESTABLISHED → FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT → CLOSED. The
//! enum derives `Copy` so the FSM can be passed by value through
//! the lock-protected TCB and asserted against in test fixtures
//! without cloning vec deques.
//!
//! ## Transition policy
//!
//! All transitions are encoded as direct assignments in `process()`
//! at call sites that own the lock on the connection; this module
//! deliberately exposes the enum + a thin `expects_*` predicate
//! surface and otherwise leaves the policy to the caller. That
//! keeps the segment-arrival fast-path in `tcp_stack` short while
//! still letting test harnesses ask "does this state still owe a
//! FIN?" without pulling in the whole arrival routine.
//!
//! Linux ref: `net/ipv4/tcp_input.c::tcp_rcv_state_process` and
//! `include/net/tcp_states.h`'s `TCP_FIN_WAIT1` etc. enum.

#![allow(dead_code)]

/// Canonical TCP connection state per RFC 9293 §3.3.2.
///
/// `Closed` is also used as the synthetic "no connection" sentinel
/// — a TCB whose state is `Closed` is queued for removal from the
/// table; it never appears on a live socket.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TcpState {
    /// No connection — pre-open or post-close.
    Closed,
    /// Passive open: accept queue installed, awaiting SYN.
    Listen,
    /// Active open: SYN sent, awaiting SYN+ACK.
    SynSent,
    /// Passive open: SYN received, SYN+ACK sent, awaiting ACK.
    SynReceived,
    /// Three-way handshake complete; data flow.
    Established,
    /// Active close: FIN sent, awaiting ACK + their FIN.
    FinWait1,
    /// Active close: our FIN ACKed; awaiting their FIN.
    FinWait2,
    /// Passive close: their FIN received; app may still write.
    CloseWait,
    /// Simultaneous close: both FINs in flight, awaiting ACK of ours.
    Closing,
    /// Passive close: their FIN ACKed; awaiting ACK of our FIN.
    LastAck,
    /// Quiet period after active close to soak up stragglers (2*MSL).
    TimeWait,
}

impl TcpState {
    /// Returns `true` iff the state can accept user-data segments.
    /// Per RFC 9293 §3.10.7.4 — ESTABLISHED + the FIN-WAIT states
    /// still queue data into the receive buffer (the user can keep
    /// reading after sending FIN); CLOSE-WAIT permits send only.
    #[inline]
    pub fn can_recv_data(self) -> bool {
        matches!(self, Self::Established | Self::FinWait1 | Self::FinWait2)
    }

    /// Returns `true` iff the user is permitted to send more data.
    /// CLOSE-WAIT is the after-passive-close-but-before-FIN window
    /// where the app can drain remaining writes before closing.
    #[inline]
    pub fn can_send_data(self) -> bool {
        matches!(self, Self::Established | Self::CloseWait)
    }

    /// Returns `true` iff segments arriving in this state are
    /// expected to carry a valid ACK field. Per RFC 9293, the only
    /// state where ACK is optional is the initial SYN (LISTEN /
    /// SYN-SENT inbound paths).
    #[inline]
    pub fn requires_ack(self) -> bool {
        !matches!(self, Self::Listen | Self::SynSent | Self::Closed)
    }

    /// `true` iff the state is "synchronised" per RFC 9293 §3.5.2 —
    /// rules for RST validity differ between the synchronised and
    /// unsynchronised state groups.
    #[inline]
    pub fn is_synchronised(self) -> bool {
        matches!(
            self,
            Self::Established
                | Self::FinWait1
                | Self::FinWait2
                | Self::CloseWait
                | Self::Closing
                | Self::LastAck
                | Self::TimeWait
        )
    }

    /// `true` iff a TCB in this state is eligible for the TIME-WAIT
    /// reaper. Stage cleanup paths (`fin_processed_in`) consult
    /// this to decide between TIME-WAIT (active-close) and CLOSED
    /// (passive-close).
    #[inline]
    pub fn closes_via_timewait(self) -> bool {
        matches!(self, Self::FinWait1 | Self::FinWait2 | Self::Closing)
    }
}

/// `tcp_shutdown(how)` value space — modelled on POSIX.
///
/// `Read` quiesces inbound delivery into the user buffer (the wire
/// keeps ACKing so the peer can finish draining), `Write` sends a
/// FIN and stops accepting further `tcp_send`s, `Both` does both.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Shutdown {
    Read,
    Write,
    Both,
}

/// Cause of a connection drop, surfaced through `tcp_recv` /
/// `tcp_send` errors. Tracked on the TCB so the user-visible
/// `getsockopt(SO_ERROR)` can report a meaningful code.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DropCause {
    /// Normal close — peer sent FIN, we ACKed.
    Graceful,
    /// Peer sent RST.
    PeerReset,
    /// USER-TIMEOUT exhausted while waiting for an ACK.
    UserTimeout,
    /// Retransmit counter exceeded RFC 6298 §5 R2.
    RetransmitGiveUp,
    /// Keepalive ran out of probes (RFC 9293 §3.8.4).
    KeepaliveDead,
}

/// Direction-of-events log entry. Stored in the TCB ring buffer
/// when the `trace` feature is on; otherwise compiled out. We
/// keep the API public-shaped so test harnesses can match on the
/// last-N transitions a connection took.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    pub from: TcpState,
    pub to: TcpState,
    /// Wall cycles at the moment of the transition.
    pub at_cycles: u64,
}
