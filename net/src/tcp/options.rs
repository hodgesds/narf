//! TCP option negotiation — MSS, Window Scale, Timestamps,
//! SACK-Permitted.
//!
//! ## What gets sent on SYN (active or passive)
//!
//! - MSS (RFC 9293 §3.2): announce the largest payload we can
//!   accept in a single segment. Default: MTU - 40 (IP + TCP
//!   headers without options).
//! - Window Scale (RFC 7323 §2): announce the shift count for the
//!   receive window. Default: 7 (multiplies the 16-bit window by
//!   128). Effective only if the peer also sends a WS option.
//! - Timestamps (RFC 7323 §3): TSval = our monotonic clock, TSecr
//!   = 0 on initial SYN. Once both ends ack TS, every subsequent
//!   segment carries the option for PAWS + better RTT samples.
//! - SACK-Permitted (RFC 2018 §2): one-bit advertisement.
//!
//! ## Parse result
//!
//! `ParsedOptions` is what `tcp_stack` extracts from an incoming
//! SYN to decide whether to negotiate scaling / TS / SACK and
//! what MSS to use.
//!
//! ## PAWS (RFC 7323 §5.3)
//!
//! Protect Against Wrapped Sequences. With TSopt enabled, a
//! segment whose TSval is older than the last-received TSval is
//! a stale duplicate and gets dropped. We maintain `ts_recent`
//! per TCB and let the arrival path consult `paws_reject` before
//! processing the data.
//!
//! Linux ref: `net/ipv4/tcp_output.c::tcp_options_write`,
//! `net/ipv4/tcp_input.c::tcp_parse_options`,
//! `net/ipv4/tcp_input.c::tcp_paws_check`.

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::pkt_tcp::{
    iter_options, TcpOption, OPT_MSS, OPT_NOP, OPT_SACK, OPT_SACK_PERMITTED, OPT_TIMESTAMPS,
    OPT_WINDOW_SCALE,
};

use super::sack::SackBlock;

/// Window-scale shift count we advertise on SYN. RFC 7323 §2.2
/// caps at 14. 7 (×128) gives us a 8.4 MB effective receive
/// window which matches the default 256 KiB socket buffer × the
/// 16-bit field.
pub const DEFAULT_WSCALE: u8 = 7;

/// MTU we assume in absence of an iface override; sender's MSS
/// is `ASSUMED_MTU - 40` to leave room for IPv4 + TCP headers
/// without options.
pub const ASSUMED_MTU: u16 = 1500;

/// Default MSS announced if nothing else is known.
pub const DEFAULT_MSS: u16 = ASSUMED_MTU - 40;

/// Floor on the MSS we'll accept (RFC 9293 §3.7.1).
pub const MIN_MSS: u16 = 536;

/// Options parsed out of an incoming segment. `None` means the
/// option was not present.
#[derive(Copy, Clone, Debug, Default)]
pub struct ParsedOptions {
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: Option<(u32, u32)>, // (TSval, TSecr)
    /// Up to MAX_SACK_BLOCKS SACK blocks, in option order. We
    /// borrow them from a stack-allocated slot in the parser to
    /// avoid an alloc on the fast path.
    pub sack_blocks: [Option<SackBlock>; 4],
}

impl ParsedOptions {
    pub fn parse(raw: &[u8]) -> Self {
        let mut out = Self::default();
        let mut sack_idx = 0;
        for opt in iter_options(raw) {
            match opt {
                TcpOption::Mss(m) => {
                    out.mss = Some(m.max(MIN_MSS));
                }
                TcpOption::WindowScale(s) => {
                    out.wscale = Some(s.min(14));
                }
                TcpOption::SackPermitted => {
                    out.sack_permitted = true;
                }
                TcpOption::Timestamps { tsval, tsecr } => {
                    out.timestamps = Some((tsval, tsecr));
                }
                TcpOption::Other { kind, data } if kind == OPT_SACK => {
                    let mut i = 0;
                    while i + 8 <= data.len() && sack_idx < 4 {
                        let left = u32::from_be_bytes([
                            data[i],
                            data[i + 1],
                            data[i + 2],
                            data[i + 3],
                        ]);
                        let right = u32::from_be_bytes([
                            data[i + 4],
                            data[i + 5],
                            data[i + 6],
                            data[i + 7],
                        ]);
                        out.sack_blocks[sack_idx] = Some(SackBlock { left, right });
                        sack_idx += 1;
                        i += 8;
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Iterator helper — yields the present SACK blocks in
    /// declaration order.
    pub fn sack_iter(&self) -> impl Iterator<Item = SackBlock> + '_ {
        self.sack_blocks.iter().filter_map(|o| *o)
    }
}

/// Builder used at outbound segment time. Holds the per-TCB
/// negotiation state so each call can decide which options to
/// emit on the wire.
#[derive(Copy, Clone, Debug)]
pub struct OptionsState {
    /// MSS the *peer* announced (and that we honour for the send
    /// path). 0 ⇒ use DEFAULT_MSS.
    pub peer_mss: u16,
    /// MSS *we* announced on the SYN (peer applies it on the send
    /// path that flows toward us).
    pub our_mss: u16,
    /// Window-scale shift we advertised — applied to every
    /// receive-window value we send.
    pub our_wscale: u8,
    /// Window-scale shift the peer advertised — applied to every
    /// receive-window value we receive.
    pub peer_wscale: u8,
    /// `true` iff both sides agreed on Window Scale during SYN.
    pub wscale_active: bool,
    /// `true` iff both sides agreed on Timestamps during SYN.
    pub timestamps_active: bool,
    /// `true` iff both sides agreed on SACK during SYN.
    pub sack_active: bool,
    /// Most-recently-seen valid TSval from the peer (RFC 7323 §3).
    /// Echoed back as TSecr.
    pub ts_recent: u32,
    /// Cycles snapshot at the moment `ts_recent` was updated —
    /// PAWS skews by this delta when scoring "old segment".
    pub ts_recent_at_cycles: u64,
}

impl Default for OptionsState {
    fn default() -> Self {
        Self::new()
    }
}

impl OptionsState {
    pub const fn new() -> Self {
        Self {
            peer_mss: DEFAULT_MSS,
            our_mss: DEFAULT_MSS,
            our_wscale: DEFAULT_WSCALE,
            peer_wscale: 0,
            wscale_active: false,
            timestamps_active: false,
            sack_active: false,
            ts_recent: 0,
            ts_recent_at_cycles: 0,
        }
    }

    /// Apply the peer's SYN options to our state — called once
    /// when transitioning out of SYN-SENT or SYN-RECEIVED.
    pub fn negotiate(&mut self, peer: &ParsedOptions, our_offered_wscale: u8) {
        if let Some(m) = peer.mss {
            // RFC 9293 §3.7.1: use the *lower* of the two MSS so a
            // small-MSS link in the path doesn't fragment.
            self.peer_mss = m.min(self.our_mss).max(MIN_MSS);
        }
        if let Some(ws) = peer.wscale {
            self.peer_wscale = ws;
            self.wscale_active = true;
            self.our_wscale = our_offered_wscale;
        } else {
            // RFC 7323 §2.2: if peer didn't offer WS, neither side
            // scales.
            self.wscale_active = false;
            self.our_wscale = 0;
            self.peer_wscale = 0;
        }
        if peer.timestamps.is_some() {
            self.timestamps_active = true;
        }
        if peer.sack_permitted {
            self.sack_active = true;
        }
    }

    /// Decode a 16-bit raw window field using the peer's announced
    /// scale shift. If WS wasn't negotiated the shift is 0 (no-op).
    #[inline]
    pub fn decode_peer_window(&self, raw: u16) -> u32 {
        (raw as u32) << self.peer_wscale
    }

    /// Encode a 32-bit effective window into the 16-bit on-wire
    /// field using our advertised scale shift.
    #[inline]
    pub fn encode_our_window(&self, effective: u32) -> u16 {
        if self.our_wscale == 0 {
            effective.min(u16::MAX as u32) as u16
        } else {
            let scaled = effective >> self.our_wscale;
            scaled.min(u16::MAX as u32) as u16
        }
    }

    /// RFC 7323 §5.3 PAWS check: returns true iff the segment
    /// should be *rejected* as a stale duplicate.
    pub fn paws_reject(&self, peer_tsval: u32) -> bool {
        if !self.timestamps_active {
            return false;
        }
        // Tolerate wrap with the signed-distance trick; reject
        // strictly older TSvals.
        ((peer_tsval.wrapping_sub(self.ts_recent)) as i32) < 0
    }

    /// Record a fresh TSval from the peer.
    pub fn update_ts_recent(&mut self, peer_tsval: u32, now_cycles: u64) {
        // Only move forward (sequence-space compare).
        if ((peer_tsval.wrapping_sub(self.ts_recent)) as i32) >= 0 {
            self.ts_recent = peer_tsval;
            self.ts_recent_at_cycles = now_cycles;
        }
    }
}

/// Encode the options payload for a SYN we send. Includes MSS,
/// Window Scale, SACK-Permitted, and Timestamps. Caller embeds
/// the result into a `TcpHeader.options` slot.
pub fn encode_syn_options(mss: u16, wscale: u8, our_tsval: u32, peer_tsecr: u32) -> Vec<u8> {
    let mut opts = Vec::with_capacity(20);
    // MSS
    opts.push(OPT_MSS);
    opts.push(4);
    opts.extend_from_slice(&mss.to_be_bytes());
    // NOP pad so WS lines up.
    opts.push(OPT_NOP);
    // Window Scale
    opts.push(OPT_WINDOW_SCALE);
    opts.push(3);
    opts.push(wscale);
    // SACK-Permitted
    opts.push(OPT_SACK_PERMITTED);
    opts.push(2);
    // NOP pad before TS.
    opts.push(OPT_NOP);
    opts.push(OPT_NOP);
    // Timestamps
    opts.push(OPT_TIMESTAMPS);
    opts.push(10);
    opts.extend_from_slice(&our_tsval.to_be_bytes());
    opts.extend_from_slice(&peer_tsecr.to_be_bytes());
    // Pad to 4-byte multiple.
    while opts.len() % 4 != 0 {
        opts.push(0);
    }
    opts
}

/// Encode options for a non-SYN segment. Honours the negotiation
/// state — only emits Timestamps if TS was negotiated, only emits
/// SACK if SACK was negotiated.
pub fn encode_data_options(
    state: &OptionsState,
    our_tsval: u32,
    sack_blocks: &[SackBlock],
) -> Vec<u8> {
    let mut opts = Vec::with_capacity(20);
    if state.timestamps_active {
        opts.push(OPT_NOP);
        opts.push(OPT_NOP);
        opts.push(OPT_TIMESTAMPS);
        opts.push(10);
        opts.extend_from_slice(&our_tsval.to_be_bytes());
        opts.extend_from_slice(&state.ts_recent.to_be_bytes());
    }
    if state.sack_active && !sack_blocks.is_empty() {
        let n = sack_blocks.len().min(super::sack::MAX_SACK_BLOCKS);
        opts.push(OPT_NOP);
        opts.push(OPT_NOP);
        opts.push(OPT_SACK);
        opts.push((2 + 8 * n) as u8);
        for b in &sack_blocks[..n] {
            opts.extend_from_slice(&b.left.to_be_bytes());
            opts.extend_from_slice(&b.right.to_be_bytes());
        }
    }
    while opts.len() % 4 != 0 {
        opts.push(0);
    }
    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_finds_all_negotiated_options() {
        let opts = encode_syn_options(1460, 7, 0xDEADBEEF, 0);
        let parsed = ParsedOptions::parse(&opts);
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.wscale, Some(7));
        assert!(parsed.sack_permitted);
        assert_eq!(parsed.timestamps, Some((0xDEADBEEF, 0)));
    }

    #[test]
    fn negotiate_picks_lower_mss() {
        let mut state = OptionsState::new();
        state.our_mss = 1460;
        let peer = ParsedOptions {
            mss: Some(536),
            ..Default::default()
        };
        state.negotiate(&peer, 7);
        assert_eq!(state.peer_mss, 536);
    }

    #[test]
    fn paws_rejects_old_tsval() {
        let mut state = OptionsState::new();
        state.timestamps_active = true;
        state.ts_recent = 100;
        assert!(state.paws_reject(50));
        assert!(!state.paws_reject(100));
        assert!(!state.paws_reject(150));
    }

    #[test]
    fn window_scale_encode_round_trip() {
        let mut state = OptionsState::new();
        state.our_wscale = 7;
        state.peer_wscale = 7;
        state.wscale_active = true;
        // 256 KiB effective → 2048 on the wire after shift.
        assert_eq!(state.encode_our_window(256 * 1024), 2048);
        // 2048 on the wire from peer → 256 KiB.
        assert_eq!(state.decode_peer_window(2048), 256 * 1024);
    }

    #[test]
    fn wscale_disabled_if_peer_didnt_offer() {
        let mut state = OptionsState::new();
        let peer = ParsedOptions::default();
        state.negotiate(&peer, 7);
        assert!(!state.wscale_active);
        assert_eq!(state.our_wscale, 0);
    }
}
