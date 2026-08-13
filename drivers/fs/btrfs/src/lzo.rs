//! LZO decompression for btrfs extents.
//!
//! Two layers:
//!
//! * [`lzo1x_decompress`] — a faithful safe-Rust port of the kernel's
//!   `lib/lzo/lzo1x_decompress_safe.c` (index-based, no unaligned fast paths).
//!   btrfs stores raw LZO1X segments, so byte-for-byte agreement with that
//!   routine is what makes reads correct.
//!
//! * [`decompress_extent`] — btrfs's on-disk LZO framing (`fs/btrfs/lzo.c`): a
//!   4-byte little-endian total length, then segments each prefixed by a 4-byte
//!   little-endian length; a segment decompresses to at most one sector, and a
//!   segment header never crosses a sector boundary (padding is skipped).

use alloc::vec::Vec;

use narf_filesystem::FsError;

// LZO error is folded into `FsError::InvalidData`; only success/failure matters.
const M2_MAX_OFFSET: usize = 0x0800;
const MAX_255_COUNT: usize = (usize::MAX / 255) - 2;
const MIN_ZERO_RUN_LENGTH: usize = 4;

/// On-disk length prefix size (`LZO_LEN`).
const LZO_LEN: usize = 4;

fn rd(src: &[u8], ip: usize) -> Result<u8, FsError> {
    src.get(ip).copied().ok_or(FsError::InvalidData)
}

fn le16(src: &[u8], ip: usize) -> Result<usize, FsError> {
    Ok(usize::from(rd(src, ip)?) | (usize::from(rd(src, ip + 1)?) << 8))
}

/// Decompress a single raw LZO1X stream in `src`, appending to `out`.
///
/// Port of `lzo1x_decompress_safe`. Match copies reference already-emitted
/// output (LZ77); overlapping copies are done one byte at a time.
pub fn lzo1x_decompress(src: &[u8], out: &mut Vec<u8>) -> Result<(), FsError> {
    if src.len() < 3 {
        return Err(FsError::InvalidData);
    }
    let mut ip = 0usize;
    let mut state = 0usize;
    let mut t: usize;
    let mut next: usize;
    // Absolute index into `out` for the current match position.
    let mut m: usize;

    // Optional bitstream-version prefix (17, version). btrfs uses version 0.
    let bitstream_version: u8 = if src.len() >= 5 && src[0] == 17 {
        let v = src[1];
        ip += 2;
        v
    } else {
        0
    };

    // Copy `n` bytes of a back-reference starting at output index `m` to the end
    // of `out`, byte by byte (safe for overlap).
    macro_rules! copy_match {
        ($m:expr, $n:expr) => {{
            let mut mm = $m;
            for _ in 0..$n {
                let b = *out.get(mm).ok_or(FsError::InvalidData)?;
                out.push(b);
                mm += 1;
            }
        }};
    }
    // Copy `n` literal bytes from the input at `ip` to `out`.
    macro_rules! copy_literals {
        ($n:expr) => {{
            for _ in 0..$n {
                let b = rd(src, ip)?;
                out.push(b);
                ip += 1;
            }
        }};
    }

    // Emulate the C control flow: the `'main` loop body, with `match_next`
    // reached via a flag so both the initial special case and the in-loop paths
    // share it.
    let first = rd(src, ip)?;
    let mut goto_match_next: Option<usize> = None;
    if first > 17 {
        t = usize::from(first) - 17;
        ip += 1;
        if t < 4 {
            next = t;
            goto_match_next = Some(next);
        } else {
            copy_literals!(t);
            state = 4;
        }
    }

    'main: loop {
        // Handle a pending `match_next` (state/next carry the literal count).
        if let Some(n) = goto_match_next.take() {
            state = n;
            copy_literals!(n);
            continue 'main;
        }

        t = usize::from(rd(src, ip)?);
        ip += 1;
        if t < 16 {
            if state == 0 {
                if t == 0 {
                    let ip_last = ip;
                    while rd(src, ip)? == 0 {
                        ip += 1;
                    }
                    let offset = ip - ip_last;
                    if offset > MAX_255_COUNT {
                        return Err(FsError::InvalidData);
                    }
                    t += (offset << 8) - offset;
                    t += 15 + usize::from(rd(src, ip)?);
                    ip += 1;
                }
                t += 3;
                copy_literals!(t);
                state = 4;
                continue 'main;
            } else if state != 4 {
                next = t & 3;
                // m_pos = op - 1 - (t >> 2) - (*ip << 2)
                m = out.len();
                let dist = 1 + (t >> 2) + (usize::from(rd(src, ip)?) << 2);
                ip += 1;
                if dist > m {
                    return Err(FsError::InvalidData);
                }
                m -= dist;
                copy_match!(m, 2);
                goto_match_next = Some(next);
                continue 'main;
            } else {
                next = t & 3;
                m = out.len();
                let dist = 1 + M2_MAX_OFFSET + (t >> 2) + (usize::from(rd(src, ip)?) << 2);
                ip += 1;
                if dist > m {
                    return Err(FsError::InvalidData);
                }
                m -= dist;
                t = 3;
            }
        } else if t >= 64 {
            next = t & 3;
            m = out.len();
            let dist = 1 + ((t >> 2) & 7) + (usize::from(rd(src, ip)?) << 3);
            ip += 1;
            if dist > m {
                return Err(FsError::InvalidData);
            }
            m -= dist;
            t = (t >> 5) - 1 + (3 - 1);
        } else if t >= 32 {
            t = (t & 31) + (3 - 1);
            if t == 2 {
                let ip_last = ip;
                while rd(src, ip)? == 0 {
                    ip += 1;
                }
                let offset = ip - ip_last;
                if offset > MAX_255_COUNT {
                    return Err(FsError::InvalidData);
                }
                t += (offset << 8) - offset;
                t += 31 + usize::from(rd(src, ip)?);
                ip += 1;
            }
            // M3: m_pos = op - 1 - (next >> 2)
            m = out.len();
            next = le16(src, ip)?;
            ip += 2;
            let dist = 1 + (next >> 2);
            next &= 3;
            if dist > m {
                return Err(FsError::InvalidData);
            }
            m -= dist;
        } else {
            // M4: t in 16..=31
            next = le16(src, ip)?;
            if (next & 0xfffc) == 0xfffc && (t & 0xf8) == 0x18 && bitstream_version != 0 {
                // Zero-run (only in versioned bitstreams; not produced by btrfs).
                t &= 7;
                t |= usize::from(rd(src, ip + 2)?) << 3;
                t += MIN_ZERO_RUN_LENGTH;
                for _ in 0..t {
                    out.push(0);
                }
                next &= 3;
                ip += 3;
                goto_match_next = Some(next);
                continue 'main;
            }
            // m_pos = op - ((t & 8) << 11) - (next >> 2); the eof marker is
            // exactly the case where both subtrahends are zero.
            let hi = (t & 8) << 11; // 0 or 0x4000
            t = (t & 7) + (3 - 1);
            if t == 2 {
                let ip_last = ip;
                while rd(src, ip)? == 0 {
                    ip += 1;
                }
                let offset = ip - ip_last;
                if offset > MAX_255_COUNT {
                    return Err(FsError::InvalidData);
                }
                t += (offset << 8) - offset;
                t += 7 + usize::from(rd(src, ip)?);
                ip += 1;
                next = le16(src, ip)?;
            }
            ip += 2;
            let low = next >> 2;
            next &= 3;
            if hi == 0 && low == 0 {
                break 'main; // end-of-stream marker
            }
            let dist = hi + low + 0x4000;
            if dist > out.len() {
                return Err(FsError::InvalidData);
            }
            m = out.len() - dist;
        }

        // Copy the match. `t` already includes the minimum match length (each
        // branch added `(3 - 1)`), so this copies exactly `t` bytes.
        if m >= out.len() {
            return Err(FsError::InvalidData);
        }
        copy_match!(m, t);

        // Trailing literals (0..=3) are encoded in `next`; handled by the shared
        // match_next step on the following iteration.
        goto_match_next = Some(next);
    }

    // The stream terminates on the M4 end-of-stream marker (`m == op`), which
    // breaks the loop above.
    Ok(())
}

/// Decompress a whole btrfs LZO extent (`compressed`) into a fresh buffer,
/// honoring the segment framing and sector padding for `sectorsize`.
pub fn decompress_extent(compressed: &[u8], sectorsize: usize) -> Result<Vec<u8>, FsError> {
    if compressed.len() < LZO_LEN || sectorsize == 0 {
        return Err(FsError::InvalidData);
    }
    let total = le32(compressed, 0)? as usize;
    if total > compressed.len() {
        return Err(FsError::InvalidData);
    }
    let mut out = Vec::new();
    let mut cur = LZO_LEN;
    while cur < total {
        let seg_len = le32(compressed, cur)? as usize;
        cur += LZO_LEN;
        let end = cur.checked_add(seg_len).ok_or(FsError::InvalidData)?;
        let seg = compressed.get(cur..end).ok_or(FsError::InvalidData)?;
        lzo1x_decompress(seg, &mut out)?;
        cur = end;
        // A segment header never crosses a sector boundary; skip padding zeros.
        let sector_bytes_left = sectorsize - (cur % sectorsize);
        if sector_bytes_left < LZO_LEN {
            cur += sector_bytes_left;
        }
    }
    Ok(out)
}

fn le32(src: &[u8], off: usize) -> Result<u32, FsError> {
    let b = src.get(off..off + 4).ok_or(FsError::InvalidData)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
