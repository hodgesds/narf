// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A FWCMD framing for H2C bodies (chip-row remainder).
//!
//! The station owner builds CCTL / BA-CAM / RA bodies and the
//! transport (`tx_8922a::H2cTx`) moves caller-framed buffers
//! across CH12 — but nothing framed them or recorded which
//! firmware command each retained buffer was. This module is
//! that layer: it wraps a body in the 8-byte FWCMD header
//! (`struct fwcmd_hdr`, `fw.h:4710`), allocates the sequence from
//! the shared `H2cSeqAllocator`, and matches the C2H MAC INFO
//! acknowledgements (`rx_packet::C2h::ack`) back to the retained
//! buffer by the (category, class, function, sequence) the ack
//! echoes.
//!
//! BE framing rules, all from Linux `fw.c`
//! `rtw89_h2c_pkt_set_hdr` (`fw.c:1817..1840`):
//! - hdr0 = `DEL_TYPE | CAT | CLASS | FUNC | H2C_SEQ` (the
//!   per-device sequence counter, incremented per command);
//! - hdr1 = `TOTAL_LEN (payload + 8) | REC_ACK | DONE_ACK`.
//! - The AX-only quirk (`fw.c:1826`: force `rec_ack` when
//!   `h2c_seq % 4 == 0` on AX chips) does NOT apply to BE — the
//!   caller's ack bits pass through unchanged. Forcing it here
//!   would invent acknowledgements the firmware was never asked
//!   for.
//!
//! Ack matching (`mac.c:5465` `rtw89_mac_c2h_rec_ack` and
//! `mac.c:5501` `rtw89_mac_c2h_done_ack`): the ack's third dword
//! echoes the acknowledged command's category, class, function
//! and H2C sequence (plus a return code on DONE_ACK). A retained
//! buffer is released only on an exact (cat, class, func, seq)
//! match — freeing on any ack would be fabrication
//! (`completion_8922a.rs` docs). A DONE_ACK with a nonzero return
//! still releases the buffer (the firmware consumed it) and the
//! return code is reported to the caller. An ack that matches
//! nothing releases nothing.

use super::h2c::H2cSeqAllocator;
use super::rx_packet::Ack;
use super::txrx::{encode_h2c_header, H2C_HEADER_LEN};

/// Maximum H2C payload bytes: the header's `TOTAL_LEN` field is
/// 14 bits (`H2C_HDR_TOTAL_LEN`, `fw.h:4755`), so payload + 8
/// must fit in 0x3FFF.
pub(super) const MAX_PAYLOAD_LEN: usize = 0x3FFF - H2C_HEADER_LEN;

/// Identity of one H2C command (category, class, function):
/// the address the firmware routes it by. The sequence is
/// allocated per command by `frame_h2c` and is not part of
/// the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct H2cCmd {
    /// Command category (`H2C_CAT_*`).
    pub(super) cat: u8,
    /// Command class within the category.
    pub(super) class: u8,
    /// Command function within the class.
    pub(super) func: u8,
}

/// Identity of one framed H2C command: the address the firmware
/// routes it by plus the sequence the C2H ack echoes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FramedH2c {
    /// H2C sequence allocated for this command.
    pub(super) seq: u8,
    /// Command category (`H2C_CAT_*`).
    pub(super) cat: u8,
    /// Command class within the category.
    pub(super) class: u8,
    /// Command function within the class.
    pub(super) func: u8,
}

/// A retained H2C buffer released by its C2H acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Released {
    /// The command that was acknowledged.
    pub(super) framed: FramedH2c,
    /// `None` for a REC_ACK (receipt only, never execution
    /// completion); `Some(code)` for a DONE_ACK's return code
    /// (0 = firmware executed the command).
    pub(super) result: Option<u8>,
}

/// Frame one H2C body: the 8-byte FWCMD header followed by
/// `payload`, into `out`. Returns the command identity and the
/// total wire length on success. Refused when `out` is too small
/// or the payload cannot fit the 14-bit total-length field —
/// never truncated.
pub(super) fn frame_h2c(
    alloc: &H2cSeqAllocator,
    cmd: H2cCmd,
    payload: &[u8],
    rec_ack: bool,
    done_ack: bool,
    out: &mut [u8],
) -> Option<(FramedH2c, usize)> {
    if payload.len() > MAX_PAYLOAD_LEN || out.len() < H2C_HEADER_LEN + payload.len() {
        return None;
    }
    let seq = alloc.next();
    encode_h2c_header(
        cmd.cat,
        cmd.class,
        cmd.func,
        seq,
        payload.len() as u16,
        rec_ack,
        done_ack,
        &mut out[..H2C_HEADER_LEN],
    )?;
    out[H2C_HEADER_LEN..H2C_HEADER_LEN + payload.len()].copy_from_slice(payload);
    Some((
        FramedH2c {
            seq,
            cat: cmd.cat,
            class: cmd.class,
            func: cmd.func,
        },
        H2C_HEADER_LEN + payload.len(),
    ))
}

/// True when `ack` acknowledges `framed`: the ack echoes the
/// original command's (category, class, function, sequence)
/// (`mac.c` rec_ack / done_ack handlers). The ack's `result`
/// (DONE_ACK return code) does not affect the match.
pub(super) const fn matches_ack(ack: &Ack, framed: &FramedH2c) -> bool {
    ack.category == framed.cat
        && ack.class == framed.class
        && ack.function == framed.func
        && ack.sequence == framed.seq
}
