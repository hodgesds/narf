//! Socket-buffer autotuning: Linux's Dynamic Right-Sizing of the receive
//! buffer and its congestion-window-driven send buffer.
//!
//! A fixed buffer caps a connection at `buffer / RTT` whatever the link can
//! carry: 256 KiB over a 10 ms path is 210 Mbit/s. Linux starts small and
//! grows each buffer to what the connection demonstrably uses, up to
//! `tcp_rmem[2]` / `tcp_wmem[2]`.
//!
//! Receive side — `tcp_rcv_space_adjust` / `tcp_rcvbuf_grow`
//! (`net/ipv4/tcp_input.c`): once per receiver round trip, compare the bytes
//! the application consumed with the previous round's figure. If it consumed
//! more, the sender is still ramping up and the application is keeping pace,
//! so the window is opened to twice that amount plus slow-start headroom.
//! The receiver's round-trip estimate comes from `tcp_rcv_rtt_measure_ts`
//! (timestamp echo) and `tcp_rcv_rtt_measure` (time to receive one window).
//!
//! Send side — `tcp_sndbuf_expand`, gated by `tcp_should_expand_sndbuf`:
//! when the writer ran out of buffer, allow twice the congestion window.
//!
//! NARF's `RecvBuf::limit` is the *window* a receive buffer yields — Linux's
//! `tcp_win_from_space(sk_rcvbuf)`, half of `sk_rcvbuf` at the default
//! scaling ratio — so the receive cap here is `tcp_rmem[2] / 2`. `SendBuf`
//! charges payload bytes only, so Linux's per-segment truesize (`per_mss`)
//! is the MSS itself.

use core::sync::atomic::Ordering;

/// `TCP_INIT_CWND`.
const TCP_INIT_CWND: u32 = 10;
/// `net.ipv4.tcp_rcvbuf_low_rtt` default (`USEC_PER_MSEC`).
const RCVBUF_LOW_RTT_US: u32 = 1000;

fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Receive-side autotuning state: `tp->rcv_rtt_est`, `tp->rcvq_space`,
/// `tp->copied_seq` and `SOCK_RCVBUF_LOCK`.
#[derive(Clone, Copy, Debug, Default)]
pub struct RcvSpace {
    /// `rcv_rtt_est.rtt_us`: receiver RTT estimate, microseconds << 3. Zero
    /// until the first sample; no tuning happens before then.
    pub rtt_us8: u32,
    /// `rcv_rtt_est.seq`: sequence that ends the current window-based sample.
    pub rtt_seq: u32,
    /// `rcv_rtt_est.time`: start of that sample (µs); 0 = not started.
    pub rtt_time_us: u64,
    /// `rcv_rtt_last_tsecr`: each echoed timestamp is sampled once.
    pub last_tsecr: u32,
    /// `rcvq_space.space`: bytes the application consumed in the last round
    /// that grew. Zero until initialised from the advertised MSS.
    pub space: u32,
    /// `copied_seq`, as a running byte count handed to the application.
    pub copied: u32,
    /// `rcvq_space.seq`: `copied` when the current round started.
    pub seq: u32,
    /// `rcvq_space.time`: when the current round started (µs).
    pub time_us: u64,
    /// `SOCK_RCVBUF_LOCK`: the application set `SO_RCVBUF`; never resize.
    pub locked: bool,
}

impl RcvSpace {
    /// `tcp_rcv_rtt_update`. Without `win_dep` the estimate is smoothed
    /// (7/8), but only from samples taken with an empty receive queue; a
    /// window-dependent sample only ever lowers it.
    pub fn rtt_update(&mut self, sample_us: u32, win_dep: bool, queue_empty: bool) {
        let old = self.rtt_us8;
        let m = sample_us.saturating_mul(8);
        let new = if old == 0 || m < old {
            m
        } else {
            if win_dep || !queue_empty {
                return;
            }
            (old - (old >> 3)).saturating_add(sample_us)
        };
        self.rtt_us8 = new;
    }

    /// `tcp_rcv_rtt_measure`: the time to receive one full advertised window
    /// is at least one round trip. Called for every in-order data segment.
    pub fn measure_window(&mut self, rcv_nxt: u32, rcv_wnd: u32, now_us: u64) {
        if self.rtt_time_us != 0 {
            if seq_before(rcv_nxt, self.rtt_seq) {
                return;
            }
            let delta = now_us
                .saturating_sub(self.rtt_time_us)
                .clamp(1, u32::MAX as u64);
            self.rtt_update(delta as u32, true, true);
        }
        self.rtt_seq = rcv_nxt.wrapping_add(rcv_wnd);
        // 0 means "not started"; a boot-time stamp of exactly 0 is nudged.
        self.rtt_time_us = now_us.max(1);
    }

    /// `tcp_rcv_rtt_measure_ts`: a full-sized segment echoing a timestamp we
    /// have not sampled yet gives `now - TSecr`. Timestamps tick in
    /// milliseconds (`TCP_TS_HZ`), and a zero delta is not a sample
    /// (`tcp_rtt_tsopt_us(tp, 0)`).
    pub fn measure_ts(
        &mut self,
        tsecr: u32,
        now_ts_ms: u32,
        segment_len: u32,
        rcv_mss: u32,
        queue_empty: bool,
    ) {
        if tsecr == self.last_tsecr {
            return;
        }
        self.last_tsecr = tsecr;
        if segment_len < rcv_mss {
            return;
        }
        let delta_ms = now_ts_ms.wrapping_sub(tsecr);
        if delta_ms == 0 || delta_ms >= (i32::MAX as u32) / 1000 {
            return;
        }
        self.rtt_update(delta_ms * 1000, false, queue_empty);
    }

    /// `tcp_rcv_space_adjust` + `tcp_rcvbuf_grow`, run whenever data is
    /// copied to the application. `inq` is what is still queued in order,
    /// `ooo_span` how far past `rcv_nxt` the out-of-order queue reaches,
    /// `advmss` our advertised MSS and `limit` the current window limit.
    /// Returns the larger window limit to install, if the round grew.
    pub fn adjust(
        &mut self,
        now_us: u64,
        inq: u32,
        ooo_span: u32,
        advmss: u32,
        limit: u32,
    ) -> Option<u32> {
        if self.rtt_us8 == 0 {
            return None;
        }
        if self.space == 0 {
            // `tcp_init_buffer_space`: min3(rcv_ssthresh, rcv_wnd,
            // TCP_INIT_CWND * advmss).
            self.space = limit.min(TCP_INIT_CWND.saturating_mul(advmss)).max(1);
        }
        let rtt_us = self.rtt_us8 >> 3;
        if now_us.saturating_sub(self.time_us) < u64::from(rtt_us) {
            return None;
        }
        // Bytes copied to the application in the last RTT, less what it has
        // not taken yet.
        let copied = self.copied.wrapping_sub(self.seq) as i32 as i64 - i64::from(inq);
        let mut grown = None;
        if copied > i64::from(self.space) {
            let newval = copied.min(i64::from(u32::MAX)) as u32;
            let oldval = self.space;
            self.space = newval;
            if !self.locked
                && narf_lib::sysctl::ipv4::TCP_MODERATE_RCVBUF.load(Ordering::Relaxed) != 0
            {
                // DRS is always one RTT late.
                let rcvwin = u64::from(newval) << 1;
                let grow = if rtt_us < RCVBUF_LOW_RTT_US {
                    // Small RTT: grow gently, avoiding buffer inflation.
                    rcvwin * u64::from(rtt_us) / u64::from(RCVBUF_LOW_RTT_US)
                } else {
                    // Slow start: allow the sender to double its rate.
                    (rcvwin << 1) * u64::from(newval - oldval) / u64::from(oldval)
                };
                let rcvwin = rcvwin
                    .saturating_add(grow)
                    .saturating_add(u64::from(ooo_span));
                let cap =
                    u64::from(narf_lib::sysctl::ipv4::TCP_RMEM_MAX.load(Ordering::Relaxed)) / 2;
                let window = rcvwin.min(cap) as u32;
                if window > limit {
                    grown = Some(window);
                }
            }
        }
        self.seq = self.copied;
        self.time_us = now_us;
        grown
    }
}

/// `tcp_sndbuf_expand`: the send-buffer limit a congestion window of `cwnd`
/// bytes calls for, if larger than `limit`. Twice the window (CUBIC needs
/// 1.7 for fast recovery, rounded up for a writer slow to react to
/// `EPOLLOUT`), never less than the initial window, at most `tcp_wmem[2]`.
pub fn sndbuf_for(cwnd: u32, mss: u32, limit: usize) -> Option<usize> {
    let window = cwnd.max(TCP_INIT_CWND.saturating_mul(mss));
    let cap = narf_lib::sysctl::ipv4::TCP_WMEM_MAX.load(Ordering::Relaxed) as usize;
    let sndmem = (window as usize).saturating_mul(2).min(cap);
    (sndmem > limit).then_some(sndmem)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

    const MSS: u32 = 1448;
    const LIMIT: u32 = 256 * 1024;

    /// One 10 ms round in which the application read `bytes`.
    fn round(s: &mut RcvSpace, now_us: &mut u64, bytes: u32, limit: u32) -> Option<u32> {
        s.copied = s.copied.wrapping_add(bytes);
        *now_us += 10_000;
        s.adjust(*now_us, 0, 0, MSS, limit)
    }

    fn rcv_space_does_nothing_without_an_rtt_sample() -> TestResult {
        let mut s = RcvSpace::default();
        let mut now = 1_000_000;
        kt_assert_eq!(round(&mut s, &mut now, 4 << 20, LIMIT), None);
        kt_assert_eq!(s.space, 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "net/tcp/autotune",
        rcv_space_does_nothing_without_an_rtt_sample
    );

    /// A reader keeping pace with a ramping sender must see its window grow
    /// past the fixed 256 KiB default and stop at `tcp_rmem[2] / 2`.
    fn rcv_space_grows_with_consumption_up_to_tcp_rmem() -> TestResult {
        let mut s = RcvSpace::default();
        s.rtt_update(10_000, false, true);
        kt_assert_eq!(s.rtt_us8, 80_000);
        let mut now = 1_000_000u64;
        let mut limit = LIMIT;
        // Round 1 only initialises: 10 * MSS consumed is not growth.
        kt_assert_eq!(round(&mut s, &mut now, 10 * MSS, limit), None);
        kt_assert_eq!(s.space, 10 * MSS);
        // Doubling consumption: rcvwin = 2*new + 4*new*(new-old)/old.
        let grown = round(&mut s, &mut now, 60_000, limit);
        let old = u64::from(10 * MSS);
        let expect = (120_000u64 + 240_000 * (60_000 - old) / old) as u32;
        kt_assert_eq!(grown, Some(expect));
        kt_assert!(
            expect > LIMIT && expect < 6_291_456 / 2,
            "window did not grow past the old fixed limit"
        );
        limit = expect;
        // The same consumption again is not growth; the limit never shrinks.
        kt_assert_eq!(round(&mut s, &mut now, 60_000, limit), None);
        // Sustained growth saturates at half of tcp_rmem[2].
        for _ in 0..8 {
            let bytes = s.space.saturating_mul(2);
            if let Some(next) = round(&mut s, &mut now, bytes, limit) {
                kt_assert!(next > limit, "autotuning shrank the window");
                limit = next;
            }
        }
        kt_assert_eq!(limit, 6_291_456 / 2);
        TestResult::Pass
    }
    kernel_test_in!(
        "net/tcp/autotune",
        rcv_space_grows_with_consumption_up_to_tcp_rmem
    );

    fn rcv_space_respects_round_boundary_backlog_and_lock() -> TestResult {
        let mut s = RcvSpace::default();
        s.rtt_update(10_000, false, true);
        let mut now = 1_000_000u64;
        let _ = round(&mut s, &mut now, 10 * MSS, LIMIT);
        // Less than one RTT since the round began: no decision yet.
        s.copied = s.copied.wrapping_add(500_000);
        kt_assert_eq!(s.adjust(now + 9_999, 0, 0, MSS, LIMIT), None);
        kt_assert_eq!(s.space, 10 * MSS);
        // Bytes still queued were not consumed: 500000 - 490000 <= space.
        kt_assert_eq!(s.adjust(now + 10_000, 490_000, 0, MSS, LIMIT), None);
        kt_assert_eq!(s.space, 10 * MSS);
        // SO_RCVBUF pins the buffer, but the measurement still advances.
        s.locked = true;
        now += 10_000;
        kt_assert_eq!(round(&mut s, &mut now, 500_000, LIMIT), None);
        kt_assert_eq!(s.space, 500_000);
        // tcp_moderate_rcvbuf=0 does the same for every socket.
        s.locked = false;
        narf_lib::sysctl::ipv4::TCP_MODERATE_RCVBUF.store(0, Ordering::Relaxed);
        let off = round(&mut s, &mut now, 1_500_000, LIMIT);
        narf_lib::sysctl::ipv4::TCP_MODERATE_RCVBUF.store(1, Ordering::Relaxed);
        kt_assert_eq!(off, None);
        // A hole in the sequence space widens the window by its span.
        s.copied = s.copied.wrapping_add(2_000_000);
        now += 10_000;
        let with_hole = s.adjust(now, 0, 30_000, MSS, LIMIT);
        let expect = 4_000_000u64 + 8_000_000 * 500_000 / 1_500_000 + 30_000;
        kt_assert_eq!(with_hole, Some(expect.min(6_291_456 / 2) as u32));
        TestResult::Pass
    }
    kernel_test_in!(
        "net/tcp/autotune",
        rcv_space_respects_round_boundary_backlog_and_lock
    );

    fn rcv_rtt_samples_follow_linux_rules() -> TestResult {
        let mut s = RcvSpace::default();
        // Window-based: armed by the first segment, sampled once a full
        // window has arrived, and only ever lowers the estimate.
        s.measure_window(1000, 65_535, 5_000_000);
        kt_assert_eq!(s.rtt_us8, 0);
        s.measure_window(1000 + 30_000, 65_535, 5_004_000);
        kt_assert_eq!(s.rtt_us8, 0);
        s.measure_window(1000 + 65_535, 65_535, 5_020_000);
        kt_assert_eq!(s.rtt_us8, 20_000 * 8);
        s.measure_window(1000 + 131_070, 65_535, 5_070_000);
        kt_assert_eq!(s.rtt_us8, 20_000 * 8, "a window sample raised the estimate");
        // Timestamp echo: a full-sized segment, each TSecr once, smoothed.
        s.measure_ts(100, 108, MSS, MSS, true);
        kt_assert_eq!(s.rtt_us8, 8_000 * 8);
        s.measure_ts(100, 150, MSS, MSS, true);
        kt_assert_eq!(s.rtt_us8, 8_000 * 8, "one TSecr was sampled twice");
        s.measure_ts(101, 125, MSS - 1, MSS, true);
        kt_assert_eq!(s.rtt_us8, 8_000 * 8, "a short segment was sampled");
        s.measure_ts(102, 126, MSS, MSS, false);
        kt_assert_eq!(s.rtt_us8, 8_000 * 8, "sampled with data still queued");
        s.measure_ts(103, 127, MSS, MSS, true);
        kt_assert_eq!(s.rtt_us8, 64_000 - 8_000 + 24_000);
        s.measure_ts(104, 104, MSS, MSS, true);
        kt_assert_eq!(s.rtt_us8, 80_000, "a zero delta was taken as a sample");
        TestResult::Pass
    }
    kernel_test_in!("net/tcp/autotune", rcv_rtt_samples_follow_linux_rules);

    fn sndbuf_tracks_twice_the_congestion_window() -> TestResult {
        // Below the default limit nothing changes.
        kt_assert_eq!(sndbuf_for(10 * MSS, MSS, 256 * 1024), None);
        kt_assert_eq!(sndbuf_for(128 * 1024, MSS, 256 * 1024), None);
        // A window the fixed 256 KiB buffer could not fill.
        kt_assert_eq!(sndbuf_for(1 << 20, MSS, 256 * 1024), Some(2 << 20));
        // Capped at tcp_wmem[2]; never shrinks.
        kt_assert_eq!(sndbuf_for(8 << 20, MSS, 256 * 1024), Some(4_194_304));
        kt_assert_eq!(sndbuf_for(1 << 20, MSS, 4_194_304), None);
        // Initial-window floor on a tiny user-unlocked buffer.
        kt_assert_eq!(sndbuf_for(MSS, MSS, 4096), Some(20 * MSS as usize));
        TestResult::Pass
    }
    kernel_test_in!(
        "net/tcp/autotune",
        sndbuf_tracks_twice_the_congestion_window
    );
}
