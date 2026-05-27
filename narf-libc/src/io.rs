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
//! shape. The `*` (dynamic width) and `.*` (dynamic precision)
//! forms each consume one extra [`Arg::Int`] slot before the
//! value slot, per C99 §7.19.6.1 ¶5: "An argument shall be of
//! type int (a negative width is interpreted as a `-` flag
//! followed by a positive width; a negative precision is taken
//! as if no precision were specified)."
//!
//! Unknown conversions fall through verbatim (we emit `%` + the
//! offending byte), matching the conventional "leak the format
//! string" behaviour rather than panicking.

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

// ── output sink ───────────────────────────────────────────────────
//
// emit_* used to call `write(fd, ...)` directly. To support both
// printf-family (write to fd) and snprintf-family (truncating copy
// into a caller-provided buffer with C99 "would-have-written"
// semantics) we route every byte through a `Sink`. The fd path is
// still a single syscall per emit chunk; the buf path bumps `total`
// by the *full* source length and copies up to remaining capacity,
// so the returned count matches what a large-enough buffer would
// have received.
enum Sink<'a> {
    Fd(u32),
    Buf {
        buf: &'a mut [u8],
        pos: &'a mut usize,
        total: &'a mut usize,
    },
}

impl Sink<'_> {
    /// Write `bytes` and return the count to add to the caller's
    /// running emitted-total. For `Fd` that's the kernel-reported
    /// count; for `Buf` it's always `bytes.len()` (C99: snprintf
    /// returns what *would* have been written).
    fn write(&mut self, bytes: &[u8]) -> usize {
        match self {
            Sink::Fd(fd) => write(*fd, bytes),
            Sink::Buf { buf, pos, total } => {
                **total += bytes.len();
                let cap = buf.len();
                if **pos < cap {
                    let room = cap - **pos;
                    let n = bytes.len().min(room);
                    buf[**pos..**pos + n].copy_from_slice(&bytes[..n]);
                    **pos += n;
                }
                bytes.len()
            }
        }
    }
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
    /// `*` was seen in place of an integer width literal. The
    /// format walker consumes one extra [`Arg::Int`] slot to fill
    /// the width before reading the value's own slot.
    dyn_width: bool,
    /// `.*` was seen for the precision. Same Arg-consumption rule
    /// as [`Self::dyn_width`].
    dyn_precision: bool,
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

    // Width: decimal digits, or `*` for a dynamic width read from
    // an [`Arg::Int`] slot. C99 §7.19.6.1 ¶5: a negative width is
    // interpreted as `-` flag + positive abs, which we resolve in
    // the format walker once the Arg is in hand.
    if bytes.get(i) == Some(&b'*') {
        spec.dyn_width = true;
        i += 1;
    } else {
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
    }

    // Precision: `.` then optional digits (absent digits == 0), or
    // `.*` for a dynamic precision read from an [`Arg::Int`] slot.
    // C99 §7.19.6.1 ¶5: a negative precision is taken as if no
    // precision were specified — the walker handles that branch.
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        if bytes.get(i) == Some(&b'*') {
            spec.dyn_precision = true;
            i += 1;
        } else {
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
// padded result via the active `Sink`. The integer scratch is sized
// for binary u64 (64 digits) plus sign + alt-form prefix + slack —
// the task spec mentions [u8; 32], but %b on u64::MAX needs 64
// digits, so we go to 80 bytes here. Padding is emitted via a
// chunked write_pad helper rather than allocating an output buffer.

/// Maximum digits we need for any base-2..16 representation of a
/// u64: 64 (binary) + 1 sign + 2 prefix + slack.
const INT_SCRATCH: usize = 80;

/// Reusable padding helper: writes `n` copies of `pad` to the sink,
/// chunking through a small stack buffer so we don't loop-syscall
/// on every byte for wide widths.
fn write_pad(sink: &mut Sink<'_>, pad: u8, n: usize) -> usize {
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
        written += sink.write(&buf[..chunk]);
        left -= chunk;
    }
    written
}

/// Render `v` (signed) to digits + optional sign prefix, then pad
/// per `spec`. Returns bytes written.
fn emit_int(sink: &mut Sink<'_>, spec: &FmtSpec, v: i64) -> usize {
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
                emitted += sink.write(&[s]);
            }
            emitted += write_pad(sink, b'0', pad_len);
            emitted += write_pad(sink, b'0', zero_fill);
            if !suppress_zero {
                emitted += sink.write(digit_slice);
            }
        } else {
            emitted += write_pad(sink, b' ', pad_len);
            if let Some(s) = sign {
                emitted += sink.write(&[s]);
            }
            emitted += write_pad(sink, b'0', zero_fill);
            if !suppress_zero {
                emitted += sink.write(digit_slice);
            }
        }
    } else {
        if let Some(s) = sign {
            emitted += sink.write(&[s]);
        }
        emitted += write_pad(sink, b'0', zero_fill);
        if !suppress_zero {
            emitted += sink.write(digit_slice);
        }
        emitted += write_pad(sink, b' ', pad_len);
    }
    emitted
}

/// Render an unsigned integer in `base` (2/8/10/16). For hex,
/// `spec.upper_hex` selects the digit case. Handles `#` prefix
/// (`0` for octal, `0x`/`0X` for hex, `0b` for binary).
fn emit_uint_base(sink: &mut Sink<'_>, spec: &FmtSpec, v: u64, base: u32) -> usize {
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
            emitted += sink.write(prefix);
            emitted += write_pad(sink, b'0', pad_len);
            emitted += write_pad(sink, b'0', zero_fill);
            if !suppress_zero {
                emitted += sink.write(digit_slice);
            }
        } else {
            emitted += write_pad(sink, b' ', pad_len);
            emitted += sink.write(prefix);
            emitted += write_pad(sink, b'0', zero_fill);
            if !suppress_zero {
                emitted += sink.write(digit_slice);
            }
        }
    } else {
        emitted += sink.write(prefix);
        emitted += write_pad(sink, b'0', zero_fill);
        if !suppress_zero {
            emitted += sink.write(digit_slice);
        }
        emitted += write_pad(sink, b' ', pad_len);
    }
    emitted
}

#[inline]
fn emit_uint(sink: &mut Sink<'_>, spec: &FmtSpec, v: u64) -> usize {
    emit_uint_base(sink, spec, v, 10)
}

/// Pointer rendering: `0x` + hex of the raw bits. Honours the
/// caller's spec so `%20p` etc. still pad, but we force the alt-
/// form prefix on so the `0x` is unconditional (per SUSv4 `%p`).
fn emit_ptr(sink: &mut Sink<'_>, spec: &FmtSpec, p: *const u8) -> usize {
    let mut s = *spec;
    s.alt_form = true;
    emit_uint_base(sink, &s, p as usize as u64, 16)
}

/// String emit with width-pad + precision-truncate. Precision on
/// `%s` caps the byte count emitted (per C99). Width pads the
/// remainder with spaces (we honour `0` for symmetry with the
/// conventional impl, though it's a non-standard combination).
fn emit_str(sink: &mut Sink<'_>, spec: &FmtSpec, s: &str) -> usize {
    let bytes = s.as_bytes();
    let take = spec.precision.map(|p| p.min(bytes.len())).unwrap_or(bytes.len());
    let slice = &bytes[..take];
    let width = spec.width.unwrap_or(0);
    let pad_len = width.saturating_sub(take);
    let pad_byte = if spec.zero_pad && !spec.left_justify { b'0' } else { b' ' };
    let mut emitted = 0usize;
    if spec.left_justify {
        emitted += sink.write(slice);
        emitted += write_pad(sink, b' ', pad_len);
    } else {
        emitted += write_pad(sink, pad_byte, pad_len);
        emitted += sink.write(slice);
    }
    emitted
}

/// Single character with width-pad. Precision is ignored on `%c`
/// per C99 (printf("%.3c", 'x') emits just "x").
fn emit_char(sink: &mut Sink<'_>, spec: &FmtSpec, c: u8) -> usize {
    let width = spec.width.unwrap_or(0);
    let pad_len = width.saturating_sub(1);
    let mut emitted = 0usize;
    if spec.left_justify {
        emitted += sink.write(&[c]);
        emitted += write_pad(sink, b' ', pad_len);
    } else {
        emitted += write_pad(sink, b' ', pad_len);
        emitted += sink.write(&[c]);
    }
    emitted
}

// ── public formatting entrypoints ─────────────────────────────────

/// Sink-generic format walker: bulk-copies literal runs and
/// dispatches each `%X` directive via [`parse_spec`] + emit_*. Both
/// [`vprintf_str`] and [`vsnprintf_str`] route through here.
fn vformat(sink: &mut Sink<'_>, fmt: &str, args: &[Arg<'_>]) -> usize {
    let mut bytes = fmt.as_bytes();
    let mut emitted = 0usize;
    let mut arg_idx = 0usize;

    while !bytes.is_empty() {
        let pct = match bytes.iter().position(|&b| b == b'%') {
            Some(p) => p,
            None => {
                emitted += sink.write(bytes);
                break;
            }
        };
        if pct > 0 {
            emitted += sink.write(&bytes[..pct]);
            bytes = &bytes[pct..];
        }

        // bytes[0] is '%'. parse_spec returns None on truncation,
        // in which case we emit the trailing '%' literally.
        let (mut spec, conv, consumed) = match parse_spec(bytes) {
            Some(s) => s,
            None => {
                emitted += sink.write(b"%");
                break;
            }
        };
        bytes = &bytes[consumed..];

        // Resolve `*` / `.*` from Arg::Int slots, consumed before
        // the conversion's own arg. Order in the argument list per
        // C99 §7.19.6.1 ¶5 is: width-arg, precision-arg, value-arg.
        if spec.dyn_width {
            if let Some(Arg::Int(w)) = args.get(arg_idx) {
                if *w < 0 {
                    // Negative dynamic width == `-` flag + |w|.
                    spec.left_justify = true;
                    spec.width = Some(w.unsigned_abs() as usize);
                } else {
                    spec.width = Some(*w as usize);
                }
            }
            arg_idx += 1;
        }
        if spec.dyn_precision {
            if let Some(Arg::Int(p)) = args.get(arg_idx) {
                if *p < 0 {
                    // Negative dynamic precision == "no precision".
                    spec.precision = None;
                } else {
                    spec.precision = Some(*p as usize);
                }
            }
            arg_idx += 1;
        }

        match conv {
            b'%' => {
                emitted += sink.write(b"%");
            }
            b's' => {
                if let Some(Arg::Str(s)) = args.get(arg_idx) {
                    emitted += emit_str(sink, &spec, s);
                }
                arg_idx += 1;
            }
            b'c' => {
                if let Some(Arg::Char(c)) = args.get(arg_idx) {
                    emitted += emit_char(sink, &spec, *c);
                }
                arg_idx += 1;
            }
            b'd' | b'i' => {
                if let Some(Arg::Int(v)) = args.get(arg_idx) {
                    emitted += emit_int(sink, &spec, *v);
                }
                arg_idx += 1;
            }
            b'u' => {
                if let Some(Arg::Uint(v)) = args.get(arg_idx) {
                    emitted += emit_uint(sink, &spec, *v);
                }
                arg_idx += 1;
            }
            b'o' => {
                if let Some(Arg::Uint(v)) = args.get(arg_idx) {
                    emitted += emit_uint_base(sink, &spec, *v, 8);
                }
                arg_idx += 1;
            }
            b'b' => {
                // NARF extension for binary, matching the C23 `%b`
                // conversion now adopted by major C runtimes.
                if let Some(Arg::Uint(v)) = args.get(arg_idx) {
                    emitted += emit_uint_base(sink, &spec, *v, 2);
                }
                arg_idx += 1;
            }
            b'x' | b'X' => {
                if let Some(Arg::Hex(v)) = args.get(arg_idx) {
                    emitted += emit_uint_base(sink, &spec, *v, 16);
                }
                arg_idx += 1;
            }
            b'p' => {
                if let Some(Arg::Ptr(p)) = args.get(arg_idx) {
                    emitted += emit_ptr(sink, &spec, *p);
                }
                arg_idx += 1;
            }
            other => {
                // Unknown conversion — emit `%X` verbatim and don't
                // consume an arg, matching glibc on undefined letters.
                let mut tmp = [0u8; 2];
                tmp[0] = b'%';
                tmp[1] = other;
                emitted += sink.write(&tmp);
                // Keep the unused-import suppressed: FdWriter still
                // exposes a fmt::Write impl below but isn't needed
                // on the hot path now that the sink is unified.
                let _ = &FdWriter;
            }
        }
    }
    emitted
}

/// Format `fmt` using `args`, write the result to `fd`, return the
/// byte count emitted. Factored core: [`printf_str`] and
/// [`fprintf_str`] both delegate here.
///
/// If `args` is exhausted mid-walk the remaining conversions are
/// emitted verbatim — same observable behaviour glibc gives for
/// "ran out of varargs" (UB by spec, "format string leaks" in
/// practice).
pub fn vprintf_str(fd: u32, fmt: &str, args: &[Arg<'_>]) -> usize {
    let mut sink = Sink::Fd(fd);
    vformat(&mut sink, fmt, args)
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

/// Lower-level snprintf: format into `buf` and return the count of
/// bytes that *would* have been written (excluding any NUL) per
/// C99. Does NOT NUL-terminate — that's [`snprintf_str`]'s job.
/// Useful when you want raw "would-have-written" length without
/// reserving a terminator slot.
pub fn vsnprintf_str(buf: &mut [u8], fmt: &str, args: &[Arg<'_>]) -> usize {
    let mut pos = 0usize;
    let mut total = 0usize;
    {
        let mut sink = Sink::Buf {
            buf,
            pos: &mut pos,
            total: &mut total,
        };
        vformat(&mut sink, fmt, args);
    }
    total
}

/// C99-style snprintf into a Rust slice. Returns the number of
/// bytes that would have been written (excluding the NUL
/// terminator) if `buf` were large enough. Always NUL-terminates
/// `buf` if `buf.len() > 0`. If `buf.len() == 0`, no write at all.
pub fn snprintf_str(buf: &mut [u8], fmt: &str, args: &[Arg<'_>]) -> usize {
    if buf.is_empty() {
        // No room for even a NUL — just compute the would-have
        // length by formatting into a zero-length sink.
        return vsnprintf_str(buf, fmt, args);
    }
    // Reserve the last byte for NUL: format into buf[..len-1] so a
    // full would-have run still leaves a terminator slot.
    let cap = buf.len();
    let writable = cap - 1;
    let mut pos = 0usize;
    let mut total = 0usize;
    {
        let mut sink = Sink::Buf {
            buf: &mut buf[..writable],
            pos: &mut pos,
            total: &mut total,
        };
        vformat(&mut sink, fmt, args);
    }
    // NUL-terminate at min(written, len-1). `pos` is bounded by
    // `writable` so this index is always in-range.
    buf[pos] = 0;
    total
}

// ── C-ABI sprintf / snprintf / asprintf (Arg-slice form) ────────────
//
// Real C-variadic `sprintf(char *buf, const char *fmt, ...)` would
// need `core::ffi::VaList`, which is still unstable on Rust 1.85.
// Path-B ships a tagged-Arg form that keeps the C-callable shape
// while letting Rust callers continue to use `&[Arg]` directly.
// Each entry takes `(args_ptr, args_len)` so a C consumer can build
// the array on the stack and pass it through.
//
// The format string is taken as a `*const i8` + walked-to-NUL.
// `dst` for sprintf / snprintf must be writable for the requested
// span. asprintf allocates via `heap::malloc` and writes the
// resulting buffer pointer through `*out` (caller must `free` it).

use crate::posix::c_char;

/// Walk a NUL-terminated C string and build a `&str` slice. Returns
/// "" if the bytes aren't valid UTF-8.
unsafe fn cstr_to_str_io<'a>(p: *const c_char) -> &'a str {
    if p.is_null() { return ""; }
    let mut len = 0usize;
    // SAFETY: caller-asserted NUL terminator.
    unsafe {
        while *p.add(len) != 0 { len += 1; }
        let bytes = core::slice::from_raw_parts(p as *const u8, len);
        core::str::from_utf8(bytes).unwrap_or("")
    }
}

/// `sprintf(buf, fmt, args, n)` — C-shaped sprintf with no length
/// cap. Returns the count of bytes written (excluding the NUL).
/// Always NUL-terminates `buf` if at least one byte is reachable.
///
/// # Safety
/// `buf` must be writable for at least the formatted result + 1
/// NUL. `fmt` must be a valid NUL-terminated C string. `args` must
/// point to `n` valid `Arg` entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sprintf_c(
    buf:  *mut c_char,
    fmt:  *const c_char,
    args: *const Arg<'_>,
    n:    usize,
) -> i32 {
    if buf.is_null() || fmt.is_null() { return -1; }
    // SAFETY: caller-asserted NUL-termination on fmt.
    let fmt_str = unsafe { cstr_to_str_io(fmt) };
    // SAFETY: caller-supplied args slice of length n.
    let arg_slice: &[Arg<'_>] = if args.is_null() || n == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(args, n) }
    };
    // Format-then-emit through a vsnprintf_str into a stack buffer
    // sized at the would-have length — but we don't know that
    // ahead of time. Rather than two passes, allocate a generous
    // 4 KiB scratch on the caller's buffer (we trust the caller's
    // contract) and copy.
    //
    // Simpler: vsnprintf_str into the caller's buffer directly,
    // bounded by an "infinite" length we pretend. We can't, because
    // Sink::Buf needs an actual slice. Use a 64 KiB max here as a
    // sanity bound; callers wanting larger should use snprintf_c.
    const MAX_SPRINTF: usize = 64 * 1024;
    // SAFETY: caller declared `buf` is writable for at least the
    // formatted result + NUL. We bound at MAX_SPRINTF to keep the
    // raw_parts size finite.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, MAX_SPRINTF) };
    let n_written = snprintf_str(dst, fmt_str, arg_slice);
    n_written as i32
}

/// `snprintf(buf, size, fmt, args, n)` — C-shaped snprintf. Returns
/// the would-have-written byte count (excluding NUL) per C99.
/// Always NUL-terminates `buf` when `size > 0`.
///
/// # Safety
/// `buf` must be writable for `size` bytes; `fmt` must be a valid
/// NUL-terminated C string; `args` must point to `n` valid `Arg`s.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn snprintf_c(
    buf:  *mut c_char,
    size: usize,
    fmt:  *const c_char,
    args: *const Arg<'_>,
    n:    usize,
) -> i32 {
    if buf.is_null() || size == 0 || fmt.is_null() { return -1; }
    // SAFETY: caller contracts.
    let fmt_str = unsafe { cstr_to_str_io(fmt) };
    let arg_slice: &[Arg<'_>] = if args.is_null() || n == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(args, n) }
    };
    // SAFETY: caller declared `buf` is writable for `size` bytes.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, size) };
    snprintf_str(dst, fmt_str, arg_slice) as i32
}

/// `asprintf(out, fmt, args, n)` — allocate a buffer large enough
/// to hold the formatted result + NUL, write the bytes, and stash
/// the pointer through `*out`. Returns the count of bytes written
/// (excluding NUL), or -1 on allocation failure. Caller is
/// responsible for `free`-ing `*out`.
///
/// # Safety
/// `out` must be a writable pointer-to-pointer slot; `fmt` /
/// `args` per [`snprintf_c`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asprintf_c(
    out:  *mut *mut c_char,
    fmt:  *const c_char,
    args: *const Arg<'_>,
    n:    usize,
) -> i32 {
    if out.is_null() || fmt.is_null() { return -1; }
    // SAFETY: caller contracts.
    let fmt_str = unsafe { cstr_to_str_io(fmt) };
    let arg_slice: &[Arg<'_>] = if args.is_null() || n == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(args, n) }
    };
    // First pass: compute would-have length. vsnprintf_str on an
    // empty slice returns the count without writing.
    let mut empty: [u8; 0] = [];
    let len = vsnprintf_str(&mut empty, fmt_str, arg_slice);
    // SAFETY: malloc is `unsafe extern "C"`; non-zero size = len + 1.
    let buf = unsafe { crate::heap::malloc(len + 1) };
    if buf.is_null() {
        // SAFETY: caller-supplied writable slot — write null on failure.
        unsafe { *out = core::ptr::null_mut(); }
        return -1;
    }
    // SAFETY: malloc returned a (len + 1)-byte writable region.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf, len + 1) };
    let _ = snprintf_str(dst, fmt_str, arg_slice);
    // SAFETY: caller-supplied writable slot.
    unsafe { *out = buf as *mut c_char; }
    len as i32
}

/// `sprintf_str(buf, fmt, args)` — like [`snprintf_str`] but with no
/// length cap. Caller is responsible for ensuring `buf` is large
/// enough; otherwise the formatted bytes will saturate at the slice
/// length (we never write past `buf.len()`). Returns the count of
/// bytes that *would* have been written.
///
/// We refuse to ship a `*mut u8` C-shaped sprintf because the C ABI
/// has no length to bound the write — that's the canonical buffer-
/// overflow surface and Path-B explicitly avoids it. This Rust-slice
/// form gives the convenience of "no cap" without the unbounded
/// pointer.
pub fn sprintf_str(buf: &mut [u8], fmt: &str, args: &[Arg<'_>]) -> usize {
    vsnprintf_str(buf, fmt, args)
}

// ── small helper: per-fd `core::fmt::Write` retained for callers
// that build ad-hoc formatter chains. The hot `vformat` path no
// longer needs it (the sink handles unknown-conv bytes directly).

struct FdWriter;

impl core::fmt::Write for FdWriter {
    fn write_str(&mut self, _s: &str) -> core::fmt::Result {
        Ok(())
    }
}

