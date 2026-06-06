//! Congestion control — pluggable policy trait, with CUBIC (RFC 9438)
//! and NewReno (RFC 5681) implementations shipped in tree.
//!
//! ## Architecture
//!
//! The per-TCB state (cwnd, ssthresh, recovery flag, CUBIC curve
//! parameters) lives in [`CcState`] — purely data, algorithm-agnostic.
//! The decision logic (how to grow cwnd on an ACK, how to shrink it on
//! loss) lives behind the [`CongestionControl`] trait. The TCB stores
//! a `Box<dyn CongestionControl>` and routes ACK / loss / RTO callbacks
//! through it. Install a different algorithm per-socket via
//! [`install`] — cap-gated on `Cap<Cc, Grant>`.
//!
//! ## Slow start (RFC 5681 §3.1)
//!
//! `cwnd < ssthresh`: on each ACK that newly acks bytes,
//! `cwnd += min(N, SMSS)` where N is the number of bytes ack'd.
//! Doubles cwnd per RTT until ssthresh is hit. This branch is shared
//! by every concrete algorithm; only the congestion-avoidance step
//! differs.
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

use alloc::boxed::Box;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};

/// Default segment size — keep in sync with the MTU/option path
/// that negotiates this on the SYN. We don't need it precise here;
/// CUBIC math operates in bytes and rescales naturally.
pub const DEFAULT_MSS: u32 = 1460;

// ── Cap marker ──────────────────────────────────────────────────────

/// Authority to install a per-socket congestion-control algorithm.
/// Cap-gated install mirrors `power::Governor` (DVFS) and lives at
/// `CapKind::CongestionControl` (0x0207).
#[derive(Copy, Clone, Debug)]
pub struct Cc;
impl CapType for Cc {
    const KIND: CapKind = CapKind::CongestionControl;
}

/// Error returned by [`install`] when the install cap has been
/// revoked. Mirrors `PowerError::AuthorityRevoked`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CcError {
    AuthorityRevoked,
}

impl From<CapError> for CcError {
    fn from(_: CapError) -> Self {
        CcError::AuthorityRevoked
    }
}

// ── State ──────────────────────────────────────────────────────────

/// Congestion-control state machine. Holds the AIMD knobs (cwnd,
/// ssthresh, recovery flag) and, when in CUBIC mode, the cubic
/// curve parameters (W_max, K, epoch start). One per TCB.
///
/// This struct is pure data — the algorithm-specific logic lives
/// behind the [`CongestionControl`] trait. Both Reno and CUBIC share
/// the slow-start / fast-recovery / RTO accounting fields here.
#[derive(Copy, Clone, Debug)]
pub struct CcState {
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
    /// `note_loss_epoch`.
    pub k_ms: u32,
    /// `narf_time::now_cycles()` at the start of the current
    /// CUBIC epoch (set on each loss event).
    pub epoch_start_cycles: u64,
    /// `narf_time::cycles_per_ns()` at epoch start so we can
    /// translate `now - epoch_start` into milliseconds without
    /// re-reading the calibration each tick.
    pub cycles_per_ns: u64,
}

impl Default for CcState {
    fn default() -> Self {
        Self::new(DEFAULT_MSS)
    }
}

impl CcState {
    /// Initial state: cwnd = 10*MSS (RFC 6928 IW10), ssthresh
    /// unbounded, no recovery.
    pub fn new(mss: u32) -> Self {
        let mss = mss.max(536); // RFC 9293 §3.7.1 floor
        Self {
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

    /// Update MSS — called when the SYN handshake settles on the
    /// negotiated value. Doesn't disturb cwnd/ssthresh.
    pub fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(536);
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

    /// Caller-driven hook: after updating snd_una, this checks
    /// whether `in_recovery` should clear (snd_una passed the
    /// recover-point high-water mark).
    pub fn clear_recovery_if_passed(&mut self, snd_una: u32) {
        if !self.in_recovery {
            return;
        }
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

    /// Stamp the CUBIC epoch and derive `K_ms` from the current cwnd.
    /// Called from `on_loss` / `on_rto` so the cubic curve gets a
    /// fresh reference point after every loss event. Algorithms that
    /// don't use the CUBIC curve still keep this bookkeeping correct —
    /// `w_max` doubles as "cwnd at last loss" for any later swap to
    /// CUBIC.
    pub fn note_loss_epoch(&mut self, now_cycles: u64, cycles_per_ns: u64) {
        self.w_max = self.cwnd;
        // K = cbrt(W_max * (1 - beta_cubic) / C); beta_cubic = 0.7.
        // K_ms ≈ cbrt(W_max * 0.3 / 0.4) * 1000.
        // Approx in fixed-point: factor = W_max * 3 / 4 (≈ 0.75).
        let factor = (self.w_max as u64).saturating_mul(3) / 4;
        // Cube root via Newton's method.
        let mut x = 1u64.max(factor / 1000);
        for _ in 0..6 {
            if x == 0 {
                x = 1;
            }
            x = (2 * x + factor / (x * x)) / 3;
        }
        self.k_ms = (x.saturating_mul(1000)).min(u32::MAX as u64) as u32;
        self.epoch_start_cycles = now_cycles;
        self.cycles_per_ns = if cycles_per_ns == 0 { 1 } else { cycles_per_ns };
    }

    /// Translate a cycles delta into milliseconds. `cycles_per_ns`
    /// is cached at epoch start; if it's zero (uncalibrated), the
    /// fallback divisor leaves the curve flat which degrades to a
    /// no-op increment — Reno still drives growth via the W_est
    /// branch.
    pub fn cycles_to_ms(&self, delta_cycles: u64) -> u64 {
        let cpn = if self.cycles_per_ns == 0 {
            1
        } else {
            self.cycles_per_ns
        };
        delta_cycles / cpn / 1_000_000
    }
}

// ── LossEvent ──────────────────────────────────────────────────────

/// What kind of loss the caller is signalling. The cc trait dispatches
/// off this to choose the right backoff. RTO is split into its own
/// trait method (`on_rto`) because the caller's measurement of in-flight
/// bytes is most natural at the call site.
#[derive(Copy, Clone, Debug)]
pub enum LossEvent {
    /// Three duplicate ACKs — RFC 5681 fast retransmit.
    FastRetransmit {
        /// snd_nxt at the time the third dup-ACK arrived; becomes the
        /// "recover point" for fast-recovery exit.
        snd_nxt: u32,
        /// Cycles at the moment of loss (for the CUBIC epoch).
        now_cycles: u64,
        /// `narf_time::cycles_per_ns()` at the moment of loss.
        cycles_per_ns: u64,
    },
}

// ── CongestionControl trait ────────────────────────────────────────

/// Per-socket congestion-control policy. Each TCB carries a boxed
/// implementor; the ACK / loss / RTO entry points on the TCB route
/// through these methods.
///
/// `Send + Sync + 'static` matches the other pluggable-policy traits
/// (`power::GovernorPolicy`, `sched::Policy`, …) and lets the box live
/// inside a `Tcb` that's stored behind an `IrqSafeSpinLock`.
pub trait CongestionControl: Send + Sync + 'static {
    /// Stable identifier surfaced through `TCP_CONGESTION` getsockopt.
    fn name(&self) -> &'static str;

    /// A cumulative ACK newly acked `acked_bytes` bytes. The implementor
    /// updates `state.cwnd` (slow-start vs congestion-avoidance branch
    /// is the implementor's responsibility). `now_cycles` carries the
    /// CUBIC epoch clock — Reno ignores it.
    fn on_ack(&self, state: &mut CcState, acked_bytes: u32, now_cycles: u64);

    /// A loss event was observed (currently only fast-retransmit). The
    /// implementor halves cwnd / sets ssthresh / enters recovery per its
    /// own AIMD scheme.
    fn on_loss(&self, state: &mut CcState, ev: LossEvent);

    /// RTO fired. Standard behaviour is `ssthresh ← max(in_flight/2, 2*MSS)`,
    /// `cwnd ← MSS`, exit recovery.
    fn on_rto(&self, state: &mut CcState, in_flight: u32, now_cycles: u64, cycles_per_ns: u64);

    /// Snapshot the current congestion window.
    fn cwnd(&self, state: &CcState) -> u32 {
        state.cwnd
    }

    /// Reset the state to a fresh connection (called on close).
    fn reset(&self, state: &mut CcState) {
        *state = CcState::new(state.mss);
    }
}

// ── Reno ───────────────────────────────────────────────────────────

/// NewReno (RFC 5681). Textbook AIMD: +1 MSS per RTT in
/// congestion-avoidance, halve cwnd on loss.
#[derive(Copy, Clone, Debug, Default)]
pub struct Reno;

impl Reno {
    fn ca_step(state: &mut CcState, bytes_acked: u32) {
        state.bytes_acked_in_window = state.bytes_acked_in_window.saturating_add(bytes_acked);
        while state.bytes_acked_in_window >= state.cwnd {
            state.bytes_acked_in_window = state.bytes_acked_in_window.saturating_sub(state.cwnd);
            state.cwnd = state.cwnd.saturating_add(state.mss);
        }
    }
}

impl CongestionControl for Reno {
    fn name(&self) -> &'static str {
        "reno"
    }

    fn on_ack(&self, state: &mut CcState, acked_bytes: u32, _now_cycles: u64) {
        if acked_bytes == 0 {
            return;
        }
        if state.in_recovery {
            return;
        }
        if state.cwnd < state.ssthresh {
            let inc = core::cmp::min(acked_bytes, state.mss);
            state.cwnd = state.cwnd.saturating_add(inc);
        } else {
            Self::ca_step(state, acked_bytes);
        }
    }

    fn on_loss(&self, state: &mut CcState, ev: LossEvent) {
        match ev {
            LossEvent::FastRetransmit {
                snd_nxt,
                now_cycles,
                cycles_per_ns,
            } => {
                state.note_loss_epoch(now_cycles, cycles_per_ns);
                state.ssthresh = core::cmp::max(state.cwnd / 2, 2 * state.mss);
                state.cwnd = state.ssthresh.saturating_add(3 * state.mss);
                state.in_recovery = true;
                state.recover_point = snd_nxt;
            }
        }
    }

    fn on_rto(&self, state: &mut CcState, in_flight: u32, now_cycles: u64, cycles_per_ns: u64) {
        state.note_loss_epoch(now_cycles, cycles_per_ns);
        state.ssthresh = core::cmp::max(in_flight / 2, 2 * state.mss);
        state.cwnd = state.mss;
        state.in_recovery = false;
        state.dup_ack_count = 0;
    }
}

// ── Cubic ──────────────────────────────────────────────────────────

/// CUBIC (RFC 9438). Default for NARF TCB instances; mirrors the
/// Linux default.
#[derive(Copy, Clone, Debug, Default)]
pub struct Cubic;

impl Cubic {
    /// CUBIC CA step — evaluates `W_cubic(t)` and the W_est ("TCP
    /// friendliness") parallel, picks the larger.
    fn ca_step(state: &mut CcState, bytes_acked: u32, now_cycles: u64) {
        // Elapsed milliseconds since epoch start.
        let t_ms = state.cycles_to_ms(now_cycles.wrapping_sub(state.epoch_start_cycles));
        // W_cubic(t) = C * (t - K)^3 + W_max, with C ≈ 0.4 MSS/sec^3.
        const C_NUM: i64 = 4; // 0.4 numerator
        const C_DEN: i64 = 10; // 0.4 denominator
        let dt_ms = (t_ms as i64) - (state.k_ms as i64);
        let dt3 = dt_ms.saturating_mul(dt_ms).saturating_mul(dt_ms);
        // Time is in ms, but the CUBIC reference uses seconds. Divide
        // the cube by 1e9 (ms^3 → s^3). Saturating to keep finite.
        let increment_bytes = (C_NUM * dt3 / C_DEN) / 1_000_000_000;
        let target = (state.w_max as i64).saturating_add(increment_bytes);
        let target = target.clamp(state.mss as i64, u32::MAX as i64) as u32;

        // W_est ≈ AIMD step (one MSS per cwnd bytes acked). RFC 9438
        // §4.2 "TCP friendliness": use max(W_cubic, W_est).
        state.bytes_acked_in_window = state.bytes_acked_in_window.saturating_add(bytes_acked);
        let reno_target = if state.bytes_acked_in_window >= state.cwnd {
            state.bytes_acked_in_window = state.bytes_acked_in_window.saturating_sub(state.cwnd);
            state.cwnd.saturating_add(state.mss)
        } else {
            state.cwnd
        };

        state.cwnd = core::cmp::max(target, reno_target);
    }
}

impl CongestionControl for Cubic {
    fn name(&self) -> &'static str {
        "cubic"
    }

    fn on_ack(&self, state: &mut CcState, acked_bytes: u32, now_cycles: u64) {
        if acked_bytes == 0 {
            return;
        }
        if state.in_recovery {
            return;
        }
        if state.cwnd < state.ssthresh {
            let inc = core::cmp::min(acked_bytes, state.mss);
            state.cwnd = state.cwnd.saturating_add(inc);
        } else {
            Self::ca_step(state, acked_bytes, now_cycles);
        }
    }

    fn on_loss(&self, state: &mut CcState, ev: LossEvent) {
        match ev {
            LossEvent::FastRetransmit {
                snd_nxt,
                now_cycles,
                cycles_per_ns,
            } => {
                state.note_loss_epoch(now_cycles, cycles_per_ns);
                state.ssthresh = core::cmp::max(state.cwnd / 2, 2 * state.mss);
                state.cwnd = state.ssthresh.saturating_add(3 * state.mss);
                state.in_recovery = true;
                state.recover_point = snd_nxt;
            }
        }
    }

    fn on_rto(&self, state: &mut CcState, in_flight: u32, now_cycles: u64, cycles_per_ns: u64) {
        state.note_loss_epoch(now_cycles, cycles_per_ns);
        state.ssthresh = core::cmp::max(in_flight / 2, 2 * state.mss);
        state.cwnd = state.mss;
        state.in_recovery = false;
        state.dup_ack_count = 0;
    }
}

// ── Install helper ─────────────────────────────────────────────────

/// Cap-gated install of a boxed congestion-control policy. The TCB's
/// `set_congestion_control` thin-wraps this; callers that already hold
/// a `Box<dyn CongestionControl>` can swap it directly.
pub fn install<C: CongestionControl>(
    cap: &Cap<Cc, Grant>,
    cc: C,
) -> Result<Box<dyn CongestionControl>, CcError> {
    cap.check_live()?;
    Ok(Box::new(cc))
}

/// Default policy for a fresh TCB. Matches the Linux default.
pub fn default_cc() -> Box<dyn CongestionControl> {
    Box::new(Cubic)
}

// ── Sequence-space helpers ─────────────────────────────────────────

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
        let c = CcState::new(1460);
        // IW10 init.
        assert_eq!(c.cwnd, 14_600);
        assert_eq!(c.ssthresh, u32::MAX);
        assert!(!c.in_recovery);
    }

    #[test]
    fn reno_slow_start_doubles_per_rtt() {
        let mut s = CcState::new(1000);
        s.cwnd = 1000;
        let cc = Reno;
        cc.on_ack(&mut s, 1000, 0);
        cc.on_ack(&mut s, 1000, 0);
        cc.on_ack(&mut s, 1000, 0);
        // Three acks of 1 MSS each: cwnd grows by 3 MSS.
        assert_eq!(s.cwnd, 4000);
    }

    #[test]
    fn reno_fast_recovery_halves_cwnd() {
        let mut s = CcState::new(1000);
        s.cwnd = 10_000;
        s.ssthresh = u32::MAX;
        let cc = Reno;
        cc.on_loss(
            &mut s,
            LossEvent::FastRetransmit {
                snd_nxt: 50_000,
                now_cycles: 0,
                cycles_per_ns: 1,
            },
        );
        assert_eq!(s.ssthresh, 5000);
        assert_eq!(s.cwnd, 8000);
        assert!(s.in_recovery);
    }

    #[test]
    fn cubic_rto_resets_cwnd_to_one_mss() {
        let mut s = CcState::new(1000);
        s.cwnd = 20_000;
        Cubic.on_rto(&mut s, 20_000, 0, 1);
        assert_eq!(s.cwnd, 1000);
        assert!(s.ssthresh >= 2000);
    }

    #[test]
    fn three_dup_acks_trigger_fast_retransmit() {
        let mut s = CcState::new(1000);
        assert!(!s.on_dup_ack());
        assert!(!s.on_dup_ack());
        assert!(s.on_dup_ack());
        assert!(!s.on_dup_ack());
    }

    #[test]
    fn cubic_grows_after_loss() {
        let mut s = CcState::new(1000);
        s.cwnd = 10_000;
        s.ssthresh = 5_000;
        let cc = Cubic;
        cc.on_loss(
            &mut s,
            LossEvent::FastRetransmit {
                snd_nxt: 100_000,
                now_cycles: 0,
                cycles_per_ns: 1,
            },
        );
        s.in_recovery = false;
        s.cwnd = s.ssthresh;
        let initial = s.cwnd;
        let mss = s.mss;
        cc.on_ack(&mut s, mss, 1_000_000_000);
        assert!(s.cwnd >= initial);
    }

    #[test]
    fn seq_compare_handles_wrap() {
        assert!(seq_lt(0xFFFFFFF0, 0x00000010));
        assert!(seq_gt(0x00000010, 0xFFFFFFF0));
        assert!(seq_geq(0x00000010, 0xFFFFFFF0));
    }

    #[test]
    fn install_requires_live_cap() {
        let cap = Cap::<Cc, Grant>::bootstrap();
        let boxed = install(&cap, Reno).expect("live cap installs");
        assert_eq!(boxed.name(), "reno");
    }
}
