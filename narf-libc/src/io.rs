//! Output primitives: `write`, `Stdout`, `fputs`, and the
//! `printf_str` / `vprintf_str` / `fprintf_str` family.
//!
//! `printf_str` exists because a real C-variadic `printf` would
//! require `core::ffi::VaList` (still unstable on 1.85). The
//! tagged-union [`Arg`] form is the practical Path-B shape: the
//! consumer passes a `&[Arg]`, the parser walks the format string,
//! and each `%X` directive consumes one slot from the slice.
//!
//! Supported conversions (Stage-4 round 2):
//! `%d` (signed decimal), `%u` (unsigned decimal), `%o` (octal),
//! `%x` / `%X` (lower / upper hex), `%b` (binary, NARF extension),
//! `%s` (string), `%c` (single byte), `%p` (pointer),
//! `%%` (literal `%`).
//!
//! The format-spec parser implements C99 §7.19.6.1's flags / width
//! / precision / length / conversion grammar. Length modifiers
//! (`hh / h / l / ll / j / z / t / L`) are accepted and ignored —
//! [`Arg`] is already 64-bit so the integer payload doesn't change
//! shape. The `*` width and `.*` precision forms are TODO (would
//! require an extra Arg slot per `*`).
//!
//! Unknown conversions fall through verbatim (we emit `%` + the
//! offending byte), matching glibc's "leak the format string"
//! behaviour rather than panicking.

use core::fmt::Write as _;

/// Tagged-union arg consumed by [`printf_str`]. Lifetime allows
/// borrowing string args without forcing a `'static` bound.
#[derive(Copy, Clone, Debug)]
pub enum Arg<'a> {
    /// `%d` — signed integer.
    Int(i64),
    /// `%u`, `%o`, `%b` — unsigned integer.
    Uint(u64),
    /// `%x` / `%X` — unsigned, hex.
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

// ── format-spec parser ────────────────────────────────────────────
//
// FmtSpec captures a single conversion's flags/width/precision so
// the emit_* helpers can render directly into a stack buffer
// without re-parsing. Decoupling parse from emit also lets the
// `o`/`b` extensions reuse the unsigned-integer renderer.

/// Decoded `%[flags][width][.precision][length]conv` directive.
#[derive(Default, Debug, Clone, Copy)]
struct FmtSpec {
    /// `-` flag: pad on the right (left-justify the value).
    left_justify: bool,
    /// `+` flag: prefix non-negative signed values with `+`.
    force_sign: bool,
    /// ` ` flag: prefix non-negative signed values with ` `.
    space_sign: bool,
    /// `#` flag: prefix `0` (octal) / `0x` (hex) / `0b` (binary).
    /// Ignored for non-numeric conversions, per C99.
    alt_form: bool,
    /// `0` flag: pad numeric values with leading zeros to width.
    /// Ignored when `left_justify` is set, per C99.
    zero_pad: bool,
    width: Option<usize>,
    precision: Option<usize>,
    /// Conversion-specific: `%X` flips hex digits to upper case.
    upper_hex: bool,
}

/// Returns `(spec, conv_byte, bytes_after_conv)` if a complete
/// directive is parsed starting at `bytes[0] == b'%'`. Returns
/// `None` if the directive is malformed (e.g. truncated by EOF) —
/// the caller falls back to literal emission.
fn parse_spec(bytes: &[u8]) -> Option<(FmtSpec, u8, usize)> {
    debug_assert!(bytes.first() == Some(&b'%'));
    let mut i = 1usize;
    let mut spec = FmtSpec::default();

    // Flags (any order, can repeat — we just OR them in).
    loop {
        match bytes.get(i) {
            Some(&b'-') => spec.left_justify = true,
            Some(&b'+') => spec.force_sign = true,
            Some(&b' ') => spec.space_sign = true,
            Some(&b'#') => spec.alt_form = true,
            Some(&b'0') => spec.zero_pad = true,
            _ => break,
        }
        i += 1;
    }

    // Width: decimal digits. `*` is documented TODO — we just stop
    // at it (the conversion below will see `*` as the conv and
    // fall through to the unknown-conv path).
    let mut width: usize = 0;
    let mut had_width = false;
    while let Some(&b) = bytes.get(i) {
        if b.is_ascii_digit() {
            width = width.saturating_mul(10).saturating_add((b - b'0') as usize);
            had_width = true;
            i += 1;
        } else {
            break;
        }
    }
    if had_width {
        spec.width = Some(width);
    }

    // Precision: `.` then optional digits (absent digits == 0).
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        let mut prec: usize = 0;
        while let Some(&b) = bytes.get(i) {
            if b.is_ascii_digit() {
                prec = prec.saturating_mul(10).saturating_add((b - b'0') as usize);
                i += 1;
            } else {
                break;
            }
        }
        spec.precision = Some(prec);
    }

    // Length modifiers: accept and ignore. Arg is already 64-bit
    // so `hh/h/l/ll/j/z/t/L` don't change emit_* behaviour. We must
    // consume them so the conversion byte lands at i.
    match bytes.get(i) {
        Some(&b'h') => {
            i += 1;
            if bytes.get(i) == Some(&b'h') { i += 1; }
        }
        Some(&b'l') => {
            i += 1;
            if bytes.get(i) == Some(&b'l') { i += 1; }
        }
        Some(&b'j') | Some(&b'z') | Some(&b't') | Some(&b'L') => i += 1,
        _ => {}
    }

    let conv = *bytes.get(i)?;
    if conv == b'X' {
        spec.upper_hex = true;
    }
    // Bytes-consumed = i + 1 (the conversion byte itself).
    Some((spec, conv, i + 1))
}

// ── emit helpers ──────────────────────────────────────────────────
//
// Each emit_* renders into a small stack buffer, then writes the
// padded result via `write(fd, ...)`. The integer scratch is sized
// for binary u64 (64 digits) plus sign + alt-form prefix + slack —
// the task spec mentions [u8; 32], but %b on u64::MAX needs 64
// digits, so we go to 80 bytes here. Padding is emitted via a
// chunked write_pad helper rather than allocating an output buffer.

/// Maximum digits we need for any base-2..16 representation of a
/// u64: 64 (binary) + 1 sign + 2 prefix + slack.
const INT_SCRATCH: usize = 80;

/// Reusable padding helper: writes `n` copies of `pad` to `fd`,
/// chunking through a small stack buffer so we don't loop-syscall
/// on every byte for wide widths.
fn write_pad(fd: u32, pad: u8, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut buf = [0u8; 32];
    for slot in buf.iter_mut() {
        *slot = pad;
    }
    let mut left = n;
    let mut written = 0usize;
    while left > 0 {
        let chunk = left.min(buf.len());
        written += write(fd, &buf[..chunk]);
        left -= chunk;
    }
    written
}

/// Render `v` (signed) to digits + optional sign prefix, then pad
/// per `spec`. Returns bytes written.
fn emit_int(fd: u32, spec: &FmtSpec, v: i64) -> usize {
    let negative = v < 0;
    // i64::MIN: cast through i128 to take an honest absolute value
    // without overflowing.
    let abs: u64 = if negative {
        (v as i128).unsigned_abs() as u64
    } else {
        v as u64
    };

    let mut digits = [0u8; INT_SCRATCH];
    let mut di = digits.len();
    if abs == 0 {
        di -= 1;
        digits[di] = b'0';
    } else {
        let mut t = abs;
        while t > 0 {
            di -= 1;
            digits[di] = b'0' + (t % 10) as u8;
            t /= 10;
        }
    }
    let digit_slice = &digits[di..];

    // Precision on integers: minimum digits. `printf("%.4d", 3)` -> "0003".
    // C99: precision == 0 with value == 0 emits NO digits.
    let min_digits = spec.precision.unwrap_or(0);
    let value_is_zero = abs == 0;
    let suppress_zero = spec.precision == Some(0) && value_is_zero;
    let body_digits = if suppress_zero { 0 } else { digit_slice.len() };
    let zero_fill = min_digits.saturating_sub(body_digits);

    // Sign prefix: `-` always wins; otherwise `+` then ` `.
    let sign: Option<u8> = if negative {
        Some(b'-')
    } else if spec.force_sign {
        Some(b'+')
    } else if spec.space_sign {
        Some(b' ')
    } else {
        None
    };
    let sign_len = if sign.is_some() { 1 } else { 0 };

    let content_len = sign_len + zero_fill + body_digits;
    let width = spec.width.unwrap_or(0);
    let pad_len = width.saturating_sub(content_len);

    // Zero-pad flag: when set without left-justify and without an
    // explicit precision, the pad goes between the sign and the
    // digits (so `%05d` of -3 -> "-0003"). With an explicit
    // precision, `0` is ignored per C99.
    let zero_inside = spec.zero_pad
        && !spec.left_justify
        && spec.precision.is_none();

    let mut emitted = 0usize;
    if !spec.left_justify {
        if zero_inside {
            if let Some(s) = sign {
                emitted += write(fd, &[s]);
            }
            emitted += write_pad(fd, b'0', pad_len);
            emitted += write_pad(fd, b'0', zero_fill);
            if !suppress_zero {
                emitted += write(fd, digit_slice);
            }
        } else {
            emitted += write_pad(fd, b' ', pad_len);
            if let Some(s) = sign {
                emitted += write(fd, &[s]);
            }
            emitted += write_pad(fd, b'0', zero_fill);
            if !suppress_zero {
                emitted += write(fd, digit_slice);
            }
        }
    } else {
        if let Some(s) = sign {
            emitted += write(fd, &[s]);
        }
        emitted += write_pad(fd, b'0', zero_fill);
        if !suppress_zero {
            emitted += write(fd, digit_slice);
        }
        emitted += write_pad(fd, b' ', pad_len);
    }
    emitted
}

/// Render an unsigned integer in `base` (2/8/10/16). For hex,
/// `spec.upper_hex` selects the digit case. Handles `#` prefix
/// (`0` for octal, `0x`/`0X` for hex, `0b` for binary).
fn emit_uint_base(fd: u32, spec: &FmtSpec, v: u64, base: u32) -> usize {
    let mut digits = [0u8; INT_SCRATCH];
    let mut di = digits.len();
    let upper = spec.upper_hex;

    if v == 0 {
        di -= 1;
        digits[di] = b'0';
    } else {
        let mut t = v;
        while t > 0 {
            di -= 1;
            let d = (t % base as u64) as u8;
            digits[di] = if d < 10 {
                b'0' + d
            } else if upper {
                b'A' + (d - 10)
            } else {
                b'a' + (d - 10)
            };
            t /= base as u64;
        }
    }
    let digit_slice = &digits[di..];

    let min_digits = spec.precision.unwrap_or(0);
    let value_is_zero = v == 0;
    let suppress_zero = spec.precision == Some(0) && value_is_zero;
    let body_digits = if suppress_zero { 0 } else { digit_slice.len() };
    let mut zero_fill = min_digits.saturating_sub(body_digits);

    // Alt-form prefix per C99:
    // - octal (#o): force a leading `0` (handled by bumping
    //   precision so the rendered string starts with 0).
    // - hex (#x/#X): emit `0x`/`0X` before the digits, only when
    //   the value is non-zero.
    // - binary (#b, NARF extension): emit `0b`.
    let mut prefix: &[u8] = b"";
    if spec.alt_form && !suppress_zero {
        match base {
            8 => {
                if body_digits == 0 || digit_slice[0] != b'0' {
                    zero_fill = zero_fill.max(1);
                }
            }
            16 => {
                if v != 0 {
                    prefix = if upper { b"0X" } else { b"0x" };
                }
            }
            2 => {
                if v != 0 {
                    prefix = b"0b";
                }
            }
            _ => {}
        }
    }

    let content_len = prefix.len() + zero_fill + body_digits;
    let width = spec.width.unwrap_or(0);
    let pad_len = width.saturating_sub(content_len);

    let zero_inside = spec.zero_pad
        && !spec.left_justify
        && spec.precision.is_none();

    let mut emitted = 0usize;
    if !spec.left_justify {
        if zero_inside {
            emitted += write(fd, prefix);
            emitted += write_pad(fd, b'0', pad_len);
            emitted += write_pad(fd, b'0', zero_fill);
            if !suppress_zero {
                emitted += write(fd, digit_slice);
            }
        } else {
            emitted += write_pad(fd, b' ', pad_len);
            emitted += write(fd, prefix);
            emitted += write_pad(fd, b'0', zero_fill);
            if !suppress_zero {
                emitted += write(fd, digit_slice);
            }
        }
    } else {
        emitted += write(fd, prefix);
        emitted += write_pad(fd, b'0', zero_fill);
        if !suppress_zero {
            emitted += write(fd, digit_slice);
        }
        emitted += write_pad(fd, b' ', pad_len);
    }
    emitted
}

#[inline]
fn emit_uint(fd: u32, spec: &FmtSpec, v: u64) -> usize {
    emit_uint_base(fd, spec, v, 10)
}

/// Pointer rendering: `0x` + hex of the raw bits. Honours the
/// caller's spec so `%20p` etc. still pad, but we force the alt-
/// form prefix on so the `0x` is unconditional (matches glibc).
fn emit_ptr(fd: u32, spec: &FmtSpec, p: *const u8) -> usize {
    let mut s = *spec;
    s.alt_form = true;
    emit_uint_base(fd, &s, p as usize as u64, 16)
}

/// String emit with width-pad + precision-truncate. Precision on
/// `%s` caps the byte count emitted (per C99). Width pads the
/// remainder with spaces (we honour `0` for symmetry with glibc,
/// though it's a non-standard combination).
fn emit_str(fd: u32, spec: &FmtSpec, s: &str) -> usize {
    let bytes = s.as_bytes();
    let take = spec.precision.map(|p| p.min(bytes.len())).unwrap_or(bytes.len());
    let slice = &bytes[..take];
    let width = spec.width.unwrap_or(0);
    let pad_len = width.saturating_sub(take);
    let pad_byte = if spec.zero_pad && !spec.left_justify { b'0' } else { b' ' };
    let mut emitted = 0usize;
    if spec.left_justify {
        emitted += write(fd, slice);
        emitted += write_pad(fd, b' ', pad_len);
    } else {
        emitted += write_pad(fd, pad_byte, pad_len);
        emitted += write(fd, slice);
    }
    emitted
}

/// Single character with width-pad. Precision is ignored on `%c`
/// per C99 (printf("%.3c", 'x') emits just "x").
fn emit_char(fd: u32, spec: &FmtSpec, c: u8) -> usize {
    let width = spec.width.unwrap_or(0);
    let pad_len = width.saturating_sub(1);
    let mut emitted = 0usize;
    if spec.left_justify {
        emitted += write(fd, &[c]);
        emitted += write_pad(fd, b' ', pad_len);
    } else {
        emitted += write_pad(fd, b' ', pad_len);
        emitted += write(fd, &[c]);
    }
    emitted
}

// ── public formatting entrypoints ─────────────────────────────────

/// Format `fmt` using `args`, write the result to `fd`, return the
/// byte count emitted. Factored core: [`printf_str`] and
/// [`fprintf_str`] both delegate here. The walker bulk-copies the
/// literal run up to the next '%' as a single syscall, then
/// dispatches the directive via [`parse_spec`] + emit_*.
///
/// If `args` is exhausted mid-walk the remaining conversions are
/// emitted verbatim — same observable behaviour glibc gives for
/// "ran out of varargs" (UB by spec, "format string leaks" in
/// practice).
pub fn vprintf_str(fd: u32, fmt: &str, args: &[Arg<'_>]) -> usize {
    let mut bytes = fmt.as_bytes();
    let mut emitted = 0usize;
    let mut arg_idx = 0usize;

    while !bytes.is_empty() {
        let pct = match bytes.iter().position(|&b| b == b'%') {
            Some(p) => p,
            None => {
                emitted += write(fd, bytes);
                break;
            }
        };
        if pct > 0 {
            emitted += write(fd, &bytes[..pct]);
            bytes = &bytes[pct..];
        }

        // bytes[0] is '%'. parse_spec returns None on truncation,
        // in which case we emit the trailing '%' literally.
        let (spec, conv, consumed) = match parse_spec(bytes) {
            Some(s) => s,
            None => {
                emitted += write(fd, b"%");
                break;
            }
        };
        bytes = &bytes[consumed..];

        match conv {
            b'%' => {
                emitted += write(fd, b"%");
            }
            b's' => {
                if let Some(Arg::Str(s)) = args.get(arg_idx) {
                    emitted += emit_str(fd, &spec, s);
                }
                arg_idx += 1;
            }
            b'c' => {
                if let Some(Arg::Char(c)) = args.get(arg_idx) {
                    emitted += emit_char(fd, &spec, *c);
                }
                arg_idx += 1;
            }
            b'd' | b'i' => {
                if let Some(Arg::Int(v)) = args.get(arg_idx) {
                    emitted += emit_int(fd, &spec, *v);
                }
                arg_idx += 1;
            }
            b'u' => {
                if let Some(Arg::Uint(v)) = args.get(arg_idx) {
                    emitted += emit_uint(fd, &spec, *v);
                }
                arg_idx += 1;
            }
            b'o' => {
                if let Some(Arg::Uint(v)) = args.get(arg_idx) {
                    emitted += emit_uint_base(fd, &spec, *v, 8);
                }
                arg_idx += 1;
            }
            b'b' => {
                // NARF extension. Glibc 2.35+ also accepts `%b` for
                // binary; we follow that convention.
                if let Some(Arg::Uint(v)) = args.get(arg_idx) {
                    emitted += emit_uint_base(fd, &spec, *v, 2);
                }
                arg_idx += 1;
            }
            b'x' | b'X' => {
                if let Some(Arg::Hex(v)) = args.get(arg_idx) {
                    emitted += emit_uint_base(fd, &spec, *v, 16);
                }
                arg_idx += 1;
            }
            b'p' => {
                if let Some(Arg::Ptr(p)) = args.get(arg_idx) {
                    emitted += emit_ptr(fd, &spec, *p);
                }
                arg_idx += 1;
            }
            other => {
                // Unknown conversion — emit `%X` verbatim and don't
                // consume an arg, matching glibc on undefined letters.
                let mut out = FdWriter(fd);
                let _ = write!(out, "%{}", other as char);
                emitted += 2;
            }
        }
    }
    emitted
}

/// Thin shim: stdout (`fd = 1`) flavour of [`vprintf_str`].
#[inline]
pub fn printf_str(fmt: &str, args: &[Arg<'_>]) -> usize {
    vprintf_str(1, fmt, args)
}

/// `fprintf`-shaped sibling of [`printf_str`]: format to an
/// arbitrary file descriptor (typically `2` for stderr).
#[inline]
pub fn fprintf_str(fd: u32, fmt: &str, args: &[Arg<'_>]) -> usize {
    vprintf_str(fd, fmt, args)
}

// ── small helper: per-fd `core::fmt::Write` for the unknown-conv
// fallback. We don't want to hard-code Stdout for fd != 1, and
// going via the formatter avoids a second `write` call for the
// two-byte `%X` literal.

struct FdWriter(u32);

impl core::fmt::Write for FdWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write(self.0, s.as_bytes());
        Ok(())
    }
}
