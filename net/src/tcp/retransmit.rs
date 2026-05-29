//! RFC 6298 retransmit timer + RTT estimator.
//!
//! ## RTT estimator (RFC 6298 §2)
//!
//! On the *first* RTT measurement R:
//! ```text
//!   SRTT     ← R
//!   RTTVAR   ← R / 2
//!   RTO      ← SRTT + max(G, K * RTTVAR)        K = 4
//! ```
//!
//! On each subsequent measurement R':
//! ```text
//!   RTTVAR   ← (1 - beta) * RTTVAR + beta * |SRTT - R'|     beta = 1/4
//!   SRTT     ← (1 - alpha) * SRTT + alpha * R'              alpha = 1/8
//!   RTO      ← SRTT + max(G, K * RTTVAR)
//! ```
//!
//! `G` is the clock granularity. We use 1 ms because both the
//! kernel timer wheel and `narf_time::Deadline::after_ms` round
//! to ms granularity at this layer.
//!
//! ## RTO bounds (RFC 6298 §2.4, §2.5)
//!
//! - Minimum: 200 ms (RFC 6298 says ≥1 s, Linux uses 200 ms via
//!   `TCP_RTO_MIN` and so do we to keep low-RTT links snappy).
//! - Maximum: 60 s.
//! - On retransmit, RTO doubles ("Karn back-off"); capped at the
//!   60 s ceiling.
//!
//! ## Karn's algorithm (§3)
//!
//! Don't take RTT samples on retransmitted segments — an ambiguous
//! ACK could be for either copy. `RttEstimator::sample` is only
//! called from the "ACK arrived for a non-retransmitted segment"
//! path in `tcp_stack`.
//!
//! ## Retransmit give-up (§5 R2)
//!
//! After 7 unsuccessful retransmits (`MAX_RETRANSMITS`), the
//! connection is dropped with `DropCause::RetransmitGiveUp`. Linux
//! defaults to 15 (`net.ipv4.tcp_retries2`); 7 keeps fast-fail
//! semantics suitable for embedded workloads on a flaky link.
//!
//! Linux ref: `net/ipv4/tcp_input.c::tcp_rtt_estimator`,
//! `net/ipv4/tcp_timer.c::tcp_retransmit_timer`,
//! `include/net/tcp.h::TCP_RTO_MIN`/`TCP_RTO_MAX`.

#![allow(dead_code)]

/// Minimum RTO. RFC 6298 says 1 s; we follow Linux's 200 ms.
pub const RTO_MIN_NS: u64 = 200_000_000;
/// Maximum RTO. RFC 6298 §2.5 caps at "at least 60 seconds".
pub const RTO_MAX_NS: u64 = 60_000_000_000;
/// Initial RTO before the first measurement (RFC 6298 §2.1).
pub const RTO_INITIAL_NS: u64 = 1_000_000_000;
/// Clock granularity for the `G` term in RTO computation.
pub const RTO_GRANULARITY_NS: u64 = 1_000_000;
/// `K` multiplier on RTTVAR (RFC 6298 §2).
pub const K: u64 = 4;
/// `alpha = 1/8` — applied as bit-shift on the integer state.
pub const ALPHA_SHIFT: u32 = 3;
/// `beta = 1/4` — applied as bit-shift on the integer state.
pub const BETA_SHIFT: u32 = 2;
/// Stop retransmitting after this many failed attempts.
pub const MAX_RETRANSMITS: u32 = 7;

/// RFC 6298 RTT smoothing state.
///
/// We hold the smoothed RTT and the variation in *nanoseconds* —
/// big enough headroom for an RTO clamped to 60 s and small enough
/// to avoid 128-bit arithmetic for the EWMA update.
///
/// `valid` is false before the first sample lands; `current_rto()`
/// returns the initial 1 s in that case (RFC 6298 §2.1).
#[derive(Copy, Clone, Debug)]
pub struct RttEstimator {
    pub srtt_ns: u64,
    pub rttvar_ns: u64,
    /// Current RTO from the last update (cached so the timer-arm
    /// path doesn't re-derive it). Includes the `*K * RTTVAR + G`
    /// term and is already clamped to [`RTO_MIN_NS`, `RTO_MAX_NS`].
    pub rto_ns: u64,
    /// True iff `sample` has been called at least once.
    pub valid: bool,
    /// Number of back-to-back retransmits without a fresh ACK.
    /// Doubled into RTO each time `back_off()` is called.
    pub backoff_count: u32,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    /// Fresh estimator. RTO seeded to 1 s, no samples taken yet.
    pub const fn new() -> Self {
        Self {
            srtt_ns: 0,
            rttvar_ns: 0,
            rto_ns: RTO_INITIAL_NS,
            valid: false,
            backoff_count: 0,
        }
    }

    /// Returns the RTO in nanoseconds, clamped to [`RTO_MIN_NS`,
    /// `RTO_MAX_NS`]. Use this when arming the retransmit timer.
    #[inline]
    pub fn current_rto(&self) -> u64 {
        self.rto_ns.clamp(RTO_MIN_NS, RTO_MAX_NS)
    }

    /// Feed a new RTT measurement (`rtt_ns`). Updates SRTT, RTTVAR
    /// and `rto_ns` per RFC 6298 §2. Resets the back-off counter
    /// because a successful ACK arrived.
    pub fn sample(&mut self, rtt_ns: u64) {
        if !self.valid {
            // RFC 6298 §2.2: first measurement.
            self.srtt_ns = rtt_ns;
            self.rttvar_ns = rtt_ns / 2;
            self.valid = true;
        } else {
            // RFC 6298 §2.3: subsequent measurements.
            // RTTVAR ← (1-β)·RTTVAR + β·|SRTT - R'|
            let diff = self.srtt_ns.abs_diff(rtt_ns);
            self.rttvar_ns = self.rttvar_ns - (self.rttvar_ns >> BETA_SHIFT)
                + (diff >> BETA_SHIFT);
            // SRTT ← (1-α)·SRTT + α·R'
            self.srtt_ns = self.srtt_ns - (self.srtt_ns >> ALPHA_SHIFT)
                + (rtt_ns >> ALPHA_SHIFT);
        }
        // RTO ← SRTT + max(G, K·RTTVAR)
        let var_term = core::cmp::max(RTO_GRANULARITY_NS, K * self.rttvar_ns);
        self.rto_ns = (self.srtt_ns.saturating_add(var_term))
            .clamp(RTO_MIN_NS, RTO_MAX_NS);
        self.backoff_count = 0;
    }

    /// RFC 6298 §5.5: on retransmit, double the RTO (with the
    /// 60 s cap). Returns true if the caller may retry; false if
    /// the back-off counter exceeded `MAX_RETRANSMITS`.
    pub fn back_off(&mut self) -> bool {
        self.backoff_count = self.backoff_count.saturating_add(1);
        if self.backoff_count > MAX_RETRANSMITS {
            return false;
        }
        let doubled = self.rto_ns.saturating_mul(2);
        self.rto_ns = doubled.clamp(RTO_MIN_NS, RTO_MAX_NS);
        true
    }

    /// Reset to "as new" — for connection close / reopen.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// One outstanding unacked segment held in the retransmit queue.
///
/// `seq` is the segment's sequence number, `len` is the payload
/// length consumed in sequence space (FIN/SYN add their phantom
/// byte), `sent_at_cycles` is the cycles count at original send
/// for RTT measurement, and `retransmitted` flags whether Karn's
/// algorithm forbids using this segment for an RTT sample.
#[derive(Copy, Clone, Debug)]
pub struct OutSeg {
    pub seq: u32,
    pub len: u32,
    pub sent_at_cycles: u64,
    pub retransmitted: bool,
    /// Flag bits at original send (used to rebuild the segment on
    /// retransmit — FIN/SYN need their bit reasserted).
    pub flags: u8,
}

impl OutSeg {
    /// End of the sequence-space range this segment covers
    /// (exclusive). The retransmit queue uses this to find
    /// segments that are now fully acked.
    #[inline]
    pub fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_seeds_srtt_and_rttvar() {
        let mut e = RttEstimator::new();
        e.sample(100_000_000); // 100 ms
        assert!(e.valid);
        assert_eq!(e.srtt_ns, 100_000_000);
        assert_eq!(e.rttvar_ns, 50_000_000);
        // RTO = SRTT + 4*RTTVAR = 100ms + 200ms = 300ms.
        assert_eq!(e.current_rto(), 300_000_000);
    }

    #[test]
    fn second_sample_smooths_srtt() {
        let mut e = RttEstimator::new();
        e.sample(100_000_000);
        e.sample(200_000_000);
        // SRTT should move 1/8 of the way toward 200ms.
        assert!(e.srtt_ns > 100_000_000 && e.srtt_ns < 200_000_000);
    }

    #[test]
    fn rto_clamp_min_and_max() {
        let mut e = RttEstimator::new();
        e.sample(1); // tiny RTT
        assert!(e.current_rto() >= RTO_MIN_NS);
        // Many back-offs: should saturate at RTO_MAX_NS.
        for _ in 0..20 {
            let _ = e.back_off();
        }
        assert_eq!(e.current_rto(), RTO_MAX_NS);
    }

    #[test]
    fn back_off_gives_up_after_max_retransmits() {
        let mut e = RttEstimator::new();
        for i in 0..MAX_RETRANSMITS {
            assert!(e.back_off(), "back_off {} should succeed", i);
        }
        // One more should return false.
        assert!(!e.back_off());
    }
}
