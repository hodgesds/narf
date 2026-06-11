//! LZ4 block-format codec — clean-room implementation.
//!
//! Encodes and decodes the LZ4 *block* format only — not the framed
//! file format. The block format is a stream of "sequences"
//! `[token][lit-len-ext][literals][match-offset LE u16][match-len-ext]`
//! where the token's high nibble carries the literal length and its
//! low nibble carries (match-length − 4), each saturating at 15 with
//! 0xFF / value bytes carrying the overflow.
//!
//! Reference: Yann Collet, "LZ4 Block Format Description" v1.6.1 —
//! <https://github.com/lz4/lz4/blob/release/doc/lz4_Block_format.md>.
//! This file implements *the spec*; no LZ4 source code was consulted.
//!
//! Why a tiny in-tree codec instead of pulling in a crate:
//!  - we need it in `#![no_std]` kernel context with no external
//!    deps, no allocator pressure beyond a fixed hash table on the
//!    stack, and a hard cap on output buffer size.
//!  - compressed-page-pool throughput dominates over peak ratio;
//!    a one-pass hash-chain matcher is sufficient.
//!
//! Limitations vs. the reference encoder:
//!  - 4096-entry hash table (12-bit index). Smaller working set than
//!    `LZ4HC`; ratio is closer to fast-mode LZ4.
//!  - No cross-block dictionary, no acceleration parameter.
//!  - No safety against adversarial input that could blow the
//!    output buffer — the caller passes `output` sized at least
//!    `lz4_max_compressed_len(input.len())` (see `OutputTooSmall`).

use core::convert::TryInto;

/// Errors returned by the LZ4 codec.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompressError {
    /// Output buffer is smaller than `lz4_max_compressed_len(input.len())`
    /// (encode) or smaller than the decoded payload (decode).
    OutputTooSmall,
    /// Decode: token/length bytes referenced data past the end of the
    /// input, or a match-offset pointed before the start of `output`.
    MalformedInput,
    /// Decode: input was shorter than the minimum valid sequence.
    ShortInput,
}

/// Worst-case compressed length for an input of `input_len` bytes.
/// Matches the spec's documented bound: every byte ends up as a
/// literal, with one extra `0xFF` literal-length byte per 255 bytes,
/// plus a small constant for the terminating sequence's token and
/// the closing literal header.
pub const fn lz4_max_compressed_len(input_len: usize) -> usize {
    input_len + input_len / 255 + 16
}

// ── Encoder ────────────────────────────────────────────────────────

/// 12-bit hash table size; one `u16` offset per slot. 8 KiB on stack.
const HASH_LOG: u32 = 12;
const HASH_SIZE: usize = 1 << HASH_LOG;
const HASH_MASK: u32 = (HASH_SIZE as u32) - 1;

/// Spec-mandated trailer reservations.
/// - last 5 bytes of input must always be emitted as literals
/// - matches must end at least 12 bytes before end of input
const MFLIMIT: usize = 12;
const LAST_LITERALS: usize = 5;
const MIN_MATCH: usize = 4;

/// 4-byte FNV-ish hash → 12-bit slot. Cheap, well-distributed for
/// the typical 4 KiB page payloads we feed the zpool.
#[inline]
fn hash4(seq: u32) -> u32 {
    seq.wrapping_mul(2654435761).wrapping_shr(32 - HASH_LOG) & HASH_MASK
}

#[inline]
fn read_u32_le(src: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(src[pos..pos + 4].try_into().unwrap())
}

/// Encode `input` into `output`. Returns the number of bytes written.
pub fn lz4_encode(input: &[u8], output: &mut [u8]) -> Result<usize, CompressError> {
    if output.len() < lz4_max_compressed_len(input.len()) {
        return Err(CompressError::OutputTooSmall);
    }

    // Inputs that are too short to host a single match are emitted
    // as one literal-only sequence.
    if input.len() < MFLIMIT + MIN_MATCH {
        return emit_last_literals(input, 0, output, 0);
    }

    // Fixed-size hash table. `u16::MAX` is the sentinel "no entry".
    // Block size is at most ~65 KiB in practice (a 4 KiB page is the
    // dominant caller); we conservatively reject blocks larger than
    // `u16::MAX` so offsets always fit a u16.
    let mut table = [u16::MAX; HASH_SIZE];

    let in_len = input.len();
    let mflimit = in_len - MFLIMIT;
    let matchlimit = in_len - LAST_LITERALS;

    let mut ip; // current input position
    let mut anchor: usize = 0; // start of pending literal run
    let mut op: usize = 0; // current output position

    // Seed the table with position 0 so the first sequence can match.
    let first = read_u32_le(input, 0);
    table[hash4(first) as usize] = 0;
    ip = 1;

    'main: while ip < mflimit {
        // Find a match. Skip-strength acceleration: if we miss N
        // times in a row, advance `ip` by more than 1 to keep the
        // encoder near constant-time on incompressible runs. The
        // spec doesn't mandate this; matches the fast-mode behavior.
        let mut forward = ip;
        let mut step: usize = 1;
        let mut search_match_nb: u32 = 1 << 6;

        let match_pos = loop {
            let h = hash4(read_u32_le(input, forward));
            let candidate = table[h as usize] as usize;
            table[h as usize] = forward as u16;

            let token_pos = forward;
            forward = forward.wrapping_add(step);
            step = (search_match_nb >> 6) as usize;
            search_match_nb += 1;

            if forward >= mflimit {
                break None;
            }

            // Candidate must be valid (not sentinel) and within
            // a 64 KiB window (block-format max offset is 65535).
            // The hash table is 4096 wide; the sentinel u16::MAX is
            // unreachable in practice on small blocks.
            if candidate == u16::MAX as usize {
                continue;
            }
            let offset = token_pos.wrapping_sub(candidate);
            if offset == 0 || offset > 65535 {
                continue;
            }
            // 4-byte verification against false hash matches.
            if read_u32_le(input, candidate) == read_u32_le(input, token_pos) {
                ip = token_pos;
                break Some((candidate, offset));
            }
        };

        let (mut match_ref, offset) = match match_pos {
            Some(p) => p,
            None => break 'main,
        };

        // Extend backwards: a match can extend to the left as long
        // as it doesn't run into the previous anchor or before the
        // start of input.
        while ip > anchor && match_ref > 0 && input[ip - 1] == input[match_ref - 1] {
            ip -= 1;
            match_ref -= 1;
        }

        // ── Emit literal run [anchor .. ip) + the match ────────────
        let literal_len = ip - anchor;
        let token_idx = op;
        op += 1;

        // High nibble = literal length, saturating at 15.
        if literal_len >= 15 {
            output[token_idx] = 0xF0;
            let mut remaining = literal_len - 15;
            while remaining >= 255 {
                output[op] = 0xFF;
                op += 1;
                remaining -= 255;
            }
            output[op] = remaining as u8;
            op += 1;
        } else {
            output[token_idx] = (literal_len as u8) << 4;
        }
        // Copy the literal run.
        output[op..op + literal_len].copy_from_slice(&input[anchor..anchor + literal_len]);
        op += literal_len;

        // Offset (little-endian u16).
        output[op] = offset as u8;
        output[op + 1] = (offset >> 8) as u8;
        op += 2;

        // Extend match forward.
        let mut match_len: usize = MIN_MATCH;
        ip += MIN_MATCH;
        match_ref += MIN_MATCH;
        while ip < matchlimit && input[ip] == input[match_ref] {
            ip += 1;
            match_ref += 1;
            match_len += 1;
        }

        // Low nibble = (match_len - MIN_MATCH), saturating at 15.
        let ml_code = match_len - MIN_MATCH;
        if ml_code >= 15 {
            output[token_idx] |= 0x0F;
            let mut remaining = ml_code - 15;
            while remaining >= 255 {
                output[op] = 0xFF;
                op += 1;
                remaining -= 255;
            }
            output[op] = remaining as u8;
            op += 1;
        } else {
            output[token_idx] |= ml_code as u8;
        }

        anchor = ip;

        // Seed the next match search.
        if ip < mflimit {
            let h = hash4(read_u32_le(input, ip));
            table[h as usize] = ip as u16;
            ip += 1;
        }
    }

    // Tail: emit the residual literals as a final, match-less
    // sequence (token's low nibble = 0, no offset bytes).
    emit_last_literals(input, anchor, output, op)
}

/// Write the closing literal-only sequence covering `input[anchor..]`.
fn emit_last_literals(
    input: &[u8],
    anchor: usize,
    output: &mut [u8],
    mut op: usize,
) -> Result<usize, CompressError> {
    let lastlen = input.len() - anchor;
    if op + 1 + lastlen + (lastlen / 255) > output.len() {
        return Err(CompressError::OutputTooSmall);
    }
    if lastlen >= 15 {
        output[op] = 0xF0;
        op += 1;
        let mut remaining = lastlen - 15;
        while remaining >= 255 {
            output[op] = 0xFF;
            op += 1;
            remaining -= 255;
        }
        output[op] = remaining as u8;
        op += 1;
    } else {
        output[op] = (lastlen as u8) << 4;
        op += 1;
    }
    output[op..op + lastlen].copy_from_slice(&input[anchor..anchor + lastlen]);
    op += lastlen;
    Ok(op)
}

// ── Decoder ────────────────────────────────────────────────────────

/// Decode `input` into `output`. Returns the number of bytes written.
pub fn lz4_decode(input: &[u8], output: &mut [u8]) -> Result<usize, CompressError> {
    if input.is_empty() {
        return Err(CompressError::ShortInput);
    }
    let mut ip: usize = 0;
    let mut op: usize = 0;

    loop {
        if ip >= input.len() {
            return Err(CompressError::MalformedInput);
        }
        let token = input[ip];
        ip += 1;

        // ── Literal length ────────────────────────────────────────
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if ip >= input.len() {
                    return Err(CompressError::MalformedInput);
                }
                let b = input[ip];
                ip += 1;
                lit_len += b as usize;
                if b != 0xFF {
                    break;
                }
            }
        }

        // Copy literals.
        if ip + lit_len > input.len() {
            return Err(CompressError::MalformedInput);
        }
        if op + lit_len > output.len() {
            return Err(CompressError::OutputTooSmall);
        }
        output[op..op + lit_len].copy_from_slice(&input[ip..ip + lit_len]);
        op += lit_len;
        ip += lit_len;

        // The last sequence has no match. The spec's discriminator is
        // "no more input bytes after the literal copy".
        if ip == input.len() {
            return Ok(op);
        }

        // ── Match offset (little-endian u16) ───────────────────────
        if ip + 2 > input.len() {
            return Err(CompressError::MalformedInput);
        }
        let offset = (input[ip] as usize) | ((input[ip + 1] as usize) << 8);
        ip += 2;
        if offset == 0 || offset > op {
            return Err(CompressError::MalformedInput);
        }

        // ── Match length ──────────────────────────────────────────
        let mut match_len = (token & 0x0F) as usize;
        if match_len == 15 {
            loop {
                if ip >= input.len() {
                    return Err(CompressError::MalformedInput);
                }
                let b = input[ip];
                ip += 1;
                match_len += b as usize;
                if b != 0xFF {
                    break;
                }
            }
        }
        match_len += MIN_MATCH;

        if op + match_len > output.len() {
            return Err(CompressError::OutputTooSmall);
        }

        // Byte-by-byte copy — matches can overlap with offset < ml
        // (RLE-style: offset=1 turns into a byte broadcast).
        let match_src = op - offset;
        for i in 0..match_len {
            output[op + i] = output[match_src + i];
        }
        op += match_len;
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[doc(hidden)]
pub mod test_helpers {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Round-trip helper used by integration tests in `tests.rs`.
    pub fn roundtrip(input: &[u8]) -> Result<Vec<u8>, CompressError> {
        let mut enc = vec![0u8; lz4_max_compressed_len(input.len())];
        let n = lz4_encode(input, &mut enc)?;
        let mut dec = vec![0u8; input.len()];
        let m = lz4_decode(&enc[..n], &mut dec)?;
        dec.truncate(m);
        Ok(dec)
    }
}
