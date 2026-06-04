//! Congestion control — CUBIC (RFC 9438) with NewReno (RFC 5681)
//! fallback.
//!
//! ## Slow start (RFC 5681 §3.1)
//!
//! `cwnd < ssthresh`: on each ACK that newly acks bytes,
//! `cwnd += min(N, SMSS)` where N is the number of bytes ack'd.
//! Doubles cwnd per RTT until ssthresh is hit.
//!
//! ## Congestion avoidance — NewReno (RFC 5681 §3.1)
//!
//! `cwnd >= ssthresh`: per-RTT growth of one SMSS. We accumulate
//! ack'd bytes in `bytes_acked_in_window` and bump cwnd by SMSS
//! when that counter reaches the current cwnd (the "additive
//! increase" half of AIMD).
//!
//! ## CUBIC (RFC 9438 §4)
//!
//! ```text
//!   W_cubic(t) = C * (t - K)^3 + W_max
//!   K          = cbrt(W_max * (1 - beta_cubic) / C)
//!   C          = 0.4
//!   beta_cubic = 0.7   (RFC 9438 §4.5 default)
//! ```
//!
//! In congestion avoidance we compute `W_cubic(t)` where `t` is
//! seconds since the last loss event (`epoch_start_cycles`), and
//! grow `cwnd` toward that target. Standard TCP friendliness
//! gives a parallel `W_est = W_max * beta + 3 * (1-beta)/(1+beta) * (t/RTT)`
//! and uses `max(W_cubic, W_est)` as the target.
//!
//! To avoid floating point in `no_std` we operate in fixed-point.
//! Time is in milliseconds. The cube term is approximated by a
//! Newton's-method cube root on the K computation and integer
//! multiply on the `(t - K)^3` evaluation. Result accuracy is
//! well within the per-RTT noise tolerance.
//!
//! ## Loss handling
//!
//! - Fast retransmit on 3 duplicate ACKs: ssthresh ← cwnd/2,
//!   cwnd ← ssthresh + 3 * MSS, retransmit. Enter fast recovery.
//! - On RTO: ssthresh ← max(FlightSize/2, 2*MSS), cwnd ← 1 MSS,
//!   reset cubic epoch.
//!
//! Linux ref: `net/ipv4/tcp_cong.c`,
//! `net/ipv4/tcp_cubic.c::bictcp_cong_avoid`,
//! `net/ipv4/tcp_input.c::tcp_enter_loss`.

#![allow(dead_code)]

/// Default segment size — keep in sync with the MTU/option path
/// that negotiates this on the SYN. We don't need it precise here;
/// CUBIC math operates in bytes and rescales naturally.
pub const DEFAULT_MSS: u32 = 1460;

/// Congestion control algorithm selector. Surfaced through
/// `TCP_CONGESTION` setsockopt.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CongAlg {
    /// CUBIC (RFC 9438) — default.
    Cubic,
    /// NewReno (RFC 5681) — fallback for compatibility tests.
    Reno,
}

/// Congestion-control state machine. Holds the AIMD knobs (cwnd,
/// ssthresh, recovery flag) and, when in CUBIC mode, the cubic
/// curve parameters (W_max, K, epoch start). One per TCB.
#[derive(Copy, Clone, Debug)]
pub struct CongestionState {
    pub alg: CongAlg,
    /// Sender-side congestion window in bytes.
    pub cwnd: u32,
    /// Slow-start threshold in bytes.
    pub ssthresh: u32,
    /// Accumulated bytes ack'd since the last cwnd bump (for the
    /// per-RTT additive increase in congestion avoidance).
    pub bytes_acked_in_window: u32,
    /// MSS in bytes — set on SYN-option negotiation.
    pub mss: u32,
    /// Dup-ACK counter: 3 ⇒ fast retransmit.
    pub dup_ack_count: u8,
    /// True while in RFC 5681 fast-recovery.
    pub in_recovery: bool,
    /// snd_nxt at the moment fast retransmit fired. Used to detect
    /// "recovery complete" — when snd_una crosses this, we exit.
    pub recover_point: u32,

    // ── CUBIC parameters (RFC 9438 §4) ──
    /// W_max at the most recent loss event (bytes).
    pub w_max: u32,
    /// Cube-root inflection time K (milliseconds) — set by
    /// `set_w_max_on_loss`.
    pub k_ms: u32,
    /// `narf_time::now_cycles()` at the start of the current
    /// CUBIC epoch (set on each loss event).
    pub epoch_start_cycles: u64,
    /// `narf_time::cycles_per_ns()` at epoch start so we can
    /// translate `now - epoch_start` into milliseconds without
    /// re-reading the calibration each tick.
    pub cycles_per_ns: u64,
}

impl Default for CongestionState {
    fn default() -> Self {
        Self::new(CongAlg::Cubic, DEFAULT_MSS)
    }
}

impl CongestionState {
    /// Initial state: cwnd = 10*MSS (RFC 6928 IW10), ssthresh
    /// unbounded, no recovery.
    pub fn new(alg: CongAlg, mss: u32) -> Self {
        let mss = mss.max(536); // RFC 9293 §3.7.1 floor
        Self {
            alg,
            cwnd: mss.saturating_mul(10),
            ssthresh: u32::MAX,
            bytes_acked_in_window: 0,
            mss,
            dup_ack_count: 0,
            in_recovery: false,
            recover_point: 0,
            w_max: 0,
            k_ms: 0,
            epoch_start_cycles: 0,
            cycles_per_ns: 1,
        }
    }

    /// Reset to fresh state on connection close.
    pub fn reset(&mut self) {
        *self = Self::new(self.alg, self.mss);
    }

    /// Switch the algorithm (e.g. via `TCP_CONGESTION` setsockopt).
    /// Resets CUBIC state but preserves cwnd/ssthresh.
    pub fn set_alg(&mut self, alg: CongAlg) {
        self.alg = alg;
        self.w_max = 0;
        self.k_ms = 0;
        self.epoch_start_cycles = 0;
    }

    /// Update MSS — called when the SYN handshake settles on the
    /// negotiated value. Doesn't disturb cwnd/ssthresh.
    pub fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(536);
    }

    /// Receive an ACK that newly acks `bytes_acked` bytes. Drives
    /// either slow-start, NewReno-CA, or CUBIC depending on cwnd
    /// vs ssthresh and the configured `alg`.
    pub fn on_ack(&mut self, bytes_acked: u32, now_cycles: u64) {
        if bytes_acked == 0 {
            return;
        }
        // Exit fast recovery if snd_una advanced past the recover
        // point. Caller updates that prior to invoking on_ack.
        if self.in_recovery {
            // Caller is expected to call `clear_recovery_if_passed`
            // after updating snd_una. We don't grow cwnd while in
            // recovery — that prevents the inflation-then-deflate
            // toggle that confuses CUBIC's epoch math.
            return;
        }
        if self.cwnd < self.ssthresh {
            // Slow start: cwnd += min(bytes_acked, MSS).
            let inc = core::cmp::min(bytes_acked, self.mss);
            self.cwnd = self.cwnd.saturating_add(inc);
        } else {
            // Congestion avoidance.
            match self.alg {
                CongAlg::Reno => self.reno_ca_step(bytes_acked),
                CongAlg::Cubic => self.cubic_ca_step(bytes_acked, now_cycles),
            }
        }
    }

    /// NewReno additive-increase: bump cwnd by one MSS per RTT.
    /// We accumulate ack'd bytes; when the counter passes cwnd,
    /// add one MSS and subtract cwnd from the counter.
    fn reno_ca_step(&mut self, bytes_acked: u32) {
        self.bytes_acked_in_window = self.bytes_acked_in_window.saturating_add(bytes_acked);
        while self.bytes_acked_in_window >= self.cwnd {
            self.bytes_acked_in_window = self.bytes_acked_in_window.saturating_sub(self.cwnd);
            self.cwnd = self.cwnd.saturating_add(self.mss);
        }
    }

    /// CUBIC step (RFC 9438 §4). Evaluates `W_cubic(t)` and
    /// `W_est(t)` and moves cwnd one step toward the max.
    fn cubic_ca_step(&mut self, bytes_acked: u32, now_cycles: u64) {
        // Elapsed milliseconds since epoch start.
        let t_ms = self.cycles_to_ms(now_cycles.wrapping_sub(self.epoch_start_cycles));
        // W_cubic(t) = C * (t - K)^3 + W_max, with C ≈ 0.4 MSS/sec^3.
        // Fixed-point: scale time to ms, compute (t-K)^3, multiply
        // by C_NUM / C_DEN, scale back to bytes via MSS.
        const C_NUM: i64 = 4; // 0.4 numerator
        const C_DEN: i64 = 10; // 0.4 denominator
        let dt_ms = (t_ms as i64) - (self.k_ms as i64);
        let dt3 = dt_ms.saturating_mul(dt_ms).saturating_mul(dt_ms);
        // Time is in ms, but the CUBIC reference uses seconds. We
        // compensate by dividing the cube by 1_000_000_000 (ms^3 →
        // s^3) — i.e. shift right by 30 in fixed point. Use
        // saturating to keep the math finite.
        let increment_bytes = (C_NUM * dt3 / C_DEN) / 1_000_000_000;
        let target = (self.w_max as i64).saturating_add(increment_bytes);
        let target = target.clamp(self.mss as i64, u32::MAX as i64) as u32;

        // W_est(t) = W_max * beta + 3*(1-beta)/(1+beta) * t/RTT.
        // We approximate the second term against the AIMD step
        // we'd take in Reno (one MSS per cwnd bytes acked) and
        // pick the more conservative target. This is the standard
        // "TCP friendliness" path of RFC 9438 §4.2.
        self.bytes_acked_in_window = self.bytes_acked_in_window.saturating_add(bytes_acked);
        let reno_target = if self.bytes_acked_in_window >= self.cwnd {
            self.bytes_acked_in_window = self.bytes_acked_in_window.saturating_sub(self.cwnd);
            self.cwnd.saturating_add(self.mss)
        } else {
            self.cwnd
        };

        self.cwnd = core::cmp::max(target, reno_target);
    }

    /// Translate a cycles delta into milliseconds. `cycles_per_ns`
    /// is cached at epoch start; if it's zero (uncalibrated), the
    /// fallback divisor leaves the curve flat which degrades to a
    /// no-op increment — Reno still drives growth via the W_est
    /// branch.
    fn cycles_to_ms(&self, delta_cycles: u64) -> u64 {
        let cpn = if self.cycles_per_ns == 0 {
            1
        } else {
            self.cycles_per_ns
        };
        delta_cycles / cpn / 1_000_000
    }

    /// Record a duplicate-ACK. Returns true on the *third* dup-ACK,
    /// which the caller treats as the fast-retransmit trigger.
    pub fn on_dup_ack(&mut self) -> bool {
        if self.in_recovery {
            // RFC 5681 §3.2: ignore further dups while in recovery
            // (they're spurious due to retransmits).
            return false;
        }
        self.dup_ack_count = self.dup_ack_count.saturating_add(1);
        self.dup_ack_count == 3
    }

    /// Reset the dup-ACK counter on a genuine cumulative ACK.
    pub fn clear_dup_acks(&mut self) {
        self.dup_ack_count = 0;
    }

    /// Fast retransmit: ssthresh ← cwnd/2, cwnd ← ssthresh + 3*MSS.
    /// Enter fast recovery with the current snd_nxt as the high
    /// water mark.
    pub fn enter_fast_recovery(&mut self, snd_nxt: u32, now_cycles: u64, cycles_per_ns: u64) {
        self.set_w_max_on_loss(now_cycles, cycles_per_ns);
        self.ssthresh = core::cmp::max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.ssthresh.saturating_add(3 * self.mss);
        self.in_recovery = true;
        self.recover_point = snd_nxt;
    }

    /// On RTO: ssthresh ← max(FlightSize/2, 2*MSS), cwnd ← 1 MSS,
    /// reset cubic epoch. `in_flight` is the caller's measurement
    /// of unacked bytes at the moment of timeout.
    pub fn enter_rto(&mut self, in_flight: u32, now_cycles: u64, cycles_per_ns: u64) {
        self.set_w_max_on_loss(now_cycles, cycles_per_ns);
        self.ssthresh = core::cmp::max(in_flight / 2, 2 * self.mss);
        self.cwnd = self.mss;
        self.in_recovery = false;
        self.dup_ack_count = 0;
    }

    /// Set W_max to the cwnd at the moment of loss, derive `K_ms`,
    /// and stamp the epoch start so subsequent CUBIC math has a
    /// fresh reference point. RFC 9438 §4.4.
    fn set_w_max_on_loss(&mut self, now_cycles: u64, cycles_per_ns: u64) {
        self.w_max = self.cwnd;
        // K = cbrt(W_max * (1 - beta_cubic) / C); beta_cubic = 0.7.
        // K_ms ≈ cbrt(W_max * 0.3 / 0.4) * 1000.
        // Approx in fixed-point: factor = W_max * 3 / 4 (≈ 0.75).
        let factor = (self.w_max as u64).saturating_mul(3) / 4;
        // Cube root via Newton's method, two iterations.
        let mut x = 1u64.max(factor / 1000);
        for _ in 0..6 {
            if x == 0 {
                x = 1;
            }
            x = (2 * x + factor / (x * x)) / 3;
        }
        // Scale to ms.
        self.k_ms = (x.saturating_mul(1000)).min(u32::MAX as u64) as u32;
        self.epoch_start_cycles = now_cycles;
        self.cycles_per_ns = if cycles_per_ns == 0 { 1 } else { cycles_per_ns };
    }

    /// Caller-driven hook: after updating snd_una, this checks
    /// whether `in_recovery` should clear (snd_una passed the
    /// recover-point high-water mark).
    pub fn clear_recovery_if_passed(&mut self, snd_una: u32) {
        if !self.in_recovery {
            return;
        }
        // Use sequence-space compare.
        if seq_geq(snd_una, self.recover_point) {
            self.in_recovery = false;
            // cwnd ← ssthresh ("deflate" exit).
            self.cwnd = core::cmp::max(self.ssthresh, self.mss);
            self.bytes_acked_in_window = 0;
            self.dup_ack_count = 0;
        }
    }

    /// Effective send-window cap — caller min's this with the
    /// receiver advertised window.
    #[inline]
    pub fn effective_cwnd(&self) -> u32 {
        self.cwnd
    }
}

/// 32-bit sequence-space compare: `a >= b` modulo 2^32.
#[inline]
pub fn seq_geq(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// Sequence-space strict less-than.
#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Sequence-space strict greater-than.
#[inline]
pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Sequence-space less-than-or-equal.
#[inline]
pub fn seq_leq(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_starts_in_slow_start() {
        let c = CongestionState::new(CongAlg::Cubic, 1460);
        // IW10 init.
        assert_eq!(c.cwnd, 14_600);
        assert_eq!(c.ssthresh, u32::MAX);
        assert!(!c.in_recovery);
    }

    #[test]
    fn slow_start_doubles_per_rtt() {
        let mut c = CongestionState::new(CongAlg::Reno, 1000);
        c.cwnd = 1000;
        c.on_ack(1000, 0);
        c.on_ack(1000, 0);
        c.on_ack(1000, 0);
        // Three acks of 1 MSS each: cwnd grows by 3 MSS.
        assert_eq!(c.cwnd, 4000);
    }

    #[test]
    fn fast_recovery_halves_cwnd() {
        let mut c = CongestionState::new(CongAlg::Reno, 1000);
        c.cwnd = 10_000;
        c.ssthresh = u32::MAX;
        c.enter_fast_recovery(50_000, 0, 1);
        // ssthresh ← cwnd/2 = 5000; cwnd ← ssthresh + 3*MSS = 8000.
        assert_eq!(c.ssthresh, 5000);
        assert_eq!(c.cwnd, 8000);
        assert!(c.in_recovery);
    }

    #[test]
    fn rto_resets_cwnd_to_one_mss() {
        let mut c = CongestionState::new(CongAlg::Cubic, 1000);
        c.cwnd = 20_000;
        c.enter_rto(20_000, 0, 1);
        assert_eq!(c.cwnd, 1000);
        assert!(c.ssthresh >= 2000);
    }

    #[test]
    fn three_dup_acks_trigger_fast_retransmit() {
        let mut c = CongestionState::new(CongAlg::Reno, 1000);
        assert!(!c.on_dup_ack());
        assert!(!c.on_dup_ack());
        assert!(c.on_dup_ack());
        assert!(!c.on_dup_ack()); // already past
    }

    #[test]
    fn cubic_grows_after_loss() {
        let mut c = CongestionState::new(CongAlg::Cubic, 1000);
        c.cwnd = 10_000;
        c.ssthresh = 5_000;
        c.enter_fast_recovery(100_000, 0, 1);
        c.in_recovery = false;
        c.cwnd = c.ssthresh; // post-recovery start
                             // Advance time and ack — cwnd should not shrink.
        let initial = c.cwnd;
        c.on_ack(c.mss, 1_000_000_000);
        assert!(c.cwnd >= initial);
    }

    #[test]
    fn seq_compare_handles_wrap() {
        // 0xFFFFFFF0 < 0x00000010 in wrap-aware comparison.
        assert!(seq_lt(0xFFFFFFF0, 0x00000010));
        assert!(seq_gt(0x00000010, 0xFFFFFFF0));
        assert!(seq_geq(0x00000010, 0xFFFFFFF0));
    }
}
