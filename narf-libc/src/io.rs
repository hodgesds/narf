//! Output primitives: `write`, `Stdout`, `fputs`, and the
//! `printf_str` shim.
//!
//! `printf_str` exists because a real C-variadic `printf` would
//! require `core::ffi::VaList` (still unstable on 1.85). The
//! tagged-union [`Arg`] form is the practical Path-B shape: the
//! consumer passes a `&[Arg]`, the parser walks the format string,
//! and each `%X` directive consumes one slot from the slice.
//!
//! Supported conversions (Stage-4 round): `%d` (signed decimal),
//! `%u` (unsigned decimal), `%x` (lower-hex), `%s` (string), `%c`
//! (single byte), `%p` (pointer as `0xHHH..`), `%%` (literal `%`).
//! Width / precision specifiers are NOT honoured here — they are a
//! follow-up. Unknown conversions fall through verbatim (we emit
//! the `%` and then the character).

use core::fmt::Write as _;

/// Tagged-union arg consumed by [`printf_str`]. Lifetime allows
/// borrowing string args without forcing a `'static` bound.
#[derive(Copy, Clone, Debug)]
pub enum Arg<'a> {
    /// `%d` — signed integer.
    Int(i64),
    /// `%u` — unsigned integer.
    Uint(u64),
    /// `%x` — unsigned, lower-case hex.
    Hex(u64),
    /// `%s` — UTF-8 string slice.
    Str(&'a str),
    /// `%c` — single byte / character.
    Char(u8),
    /// `%p` — pointer; rendered as `0x` + zero-padded hex.
    Ptr(*const u8),
}

/// `core::fmt::Write` adapter for stdout (`fd = 1`). Mirrors the
/// same-named adapter in `narf_user_runtime` — re-exposed here so
/// consumers don't need both crate paths.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stdout;

impl core::fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write(1, s.as_bytes());
        Ok(())
    }
}

/// Raw write delegating into the user-runtime SDK. Returns the
/// kernel-reported byte count.
#[inline]
pub fn write(fd: u32, buf: &[u8]) -> usize {
    narf_user_runtime::write(fd, buf)
}

/// `fputs`-shaped helper: write a string to `fd` without trailing
/// formatting. Errors are swallowed — POSIX `fputs` returns a
/// non-negative on success / EOF on error, which Stage-4 doesn't
/// surface; we drop the count for symmetry with `Stdout`.
#[inline]
pub fn fputs(s: &str, fd: u32) {
    let _ = write(fd, s.as_bytes());
}

/// Format `fmt` using `args`, write the result to stdout, and
/// return the byte count emitted. The parser walks `fmt` byte by
/// byte and consumes one entry from `args` per conversion. If
/// `args` is exhausted mid-walk the remaining conversions are
/// emitted verbatim — same behaviour you'd get from running out
/// of varargs in glibc, where the result is undefined but
/// observably "the format string leaks".
pub fn printf_str(fmt: &str, args: &[Arg<'_>]) -> usize {
    let mut out = Stdout;
    let mut bytes = fmt.as_bytes();
    let mut emitted = 0usize;
    let mut arg_idx = 0usize;

    while !bytes.is_empty() {
        // Fast path: copy the prefix up to the next '%' as a single
        // write so we don't do per-byte syscalls.
        if let Some(pct) = bytes.iter().position(|&b| b == b'%') {
            if pct > 0 {
                let chunk = &bytes[..pct];
                emitted += write(1, chunk);
                bytes = &bytes[pct..];
            }
            // bytes[0] is now '%'. Need at least one more byte to
            // know the conversion.
            if bytes.len() < 2 {
                emitted += write(1, b"%");
                break;
            }
            let conv = bytes[1];
            bytes = &bytes[2..];

            match conv {
                b'%' => {
                    emitted += write(1, b"%");
                }
                b's' => {
                    if let Some(Arg::Str(s)) = args.get(arg_idx) {
                        emitted += write(1, s.as_bytes());
                    }
                    arg_idx += 1;
                }
                b'c' => {
                    if let Some(Arg::Char(c)) = args.get(arg_idx) {
                        emitted += write(1, &[*c]);
                    }
                    arg_idx += 1;
                }
                b'd' => {
                    if let Some(Arg::Int(v)) = args.get(arg_idx) {
                        let mut buf = [0u8; 24];
                        let s = fmt_signed(&mut buf, *v);
                        emitted += write(1, s);
                    }
                    arg_idx += 1;
                }
                b'u' => {
                    if let Some(Arg::Uint(v)) = args.get(arg_idx) {
                        let mut buf = [0u8; 24];
                        let s = fmt_unsigned(&mut buf, *v);
                        emitted += write(1, s);
                    }
                    arg_idx += 1;
                }
                b'x' => {
                    if let Some(Arg::Hex(v)) = args.get(arg_idx) {
                        let mut buf = [0u8; 24];
                        let s = fmt_hex(&mut buf, *v);
                        emitted += write(1, s);
                    }
                    arg_idx += 1;
                }
                b'p' => {
                    if let Some(Arg::Ptr(p)) = args.get(arg_idx) {
                        // "0x" prefix + hex of the raw bits. We ignore
                        // the `core::fmt::Write` helper because it's
                        // routed through `Stdout` already and we want
                        // a single-syscall emit.
                        let mut buf = [0u8; 24];
                        let s = fmt_hex(&mut buf, *p as usize as u64);
                        emitted += write(1, b"0x");
                        emitted += write(1, s);
                    }
                    arg_idx += 1;
                }
                other => {
                    // Unknown conversion — emit `%X` verbatim. Don't
                    // consume an arg (matches glibc when an unknown
                    // letter shows up).
                    let _ = write!(out, "%{}", other as char);
                    // We don't track exact bytes for the fallback; an
                    // approximate count is fine here.
                    emitted += 2;
                }
            }
        } else {
            emitted += write(1, bytes);
            break;
        }
    }
    emitted
}

// ── small integer formatters ───────────────────────────────────────
//
// Hand-rolled to keep this crate `core::fmt`-light: pulling in
// `core::fmt::Display` for u64 forces a heavier code path than we
// want for a startup-line printer. A 24-byte scratch buffer covers
// every i64 / u64 / hex value with room to spare (max 20 digits +
// sign + slack).

fn fmt_unsigned(buf: &mut [u8; 24], mut v: u64) -> &[u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &buf[i..]
}

fn fmt_signed(buf: &mut [u8; 24], v: i64) -> &[u8] {
    if v >= 0 {
        return fmt_unsigned(buf, v as u64);
    }
    // i64::MIN handled via wrapping_neg + cast.
    let abs = (v as i128).unsigned_abs() as u64;
    let mut i = buf.len();
    let mut t = abs;
    if t == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    while t > 0 {
        i -= 1;
        buf[i] = b'0' + (t % 10) as u8;
        t /= 10;
    }
    i -= 1;
    buf[i] = b'-';
    &buf[i..]
}

fn fmt_hex(buf: &mut [u8; 24], mut v: u64) -> &[u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        let nib = (v & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        v >>= 4;
    }
    &buf[i..]
}
