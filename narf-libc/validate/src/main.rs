//! narf-libc-validate — smoke binary for narf-libc.
//!
//! Links against the relibc-shaped libc shim. The C-style `main`
//! signature is what `narf_libc::__libc_start_main` calls into;
//! `narf_libc::_start` (re-exported from the lib crate) is the
//! ELF entry point per `validate.ld`'s `ENTRY(_start)`.
//!
//! Behaviour: prints a `hello from narf-libc; pid=<n>` line via the
//! printf-shim, then exercises the new FILE* layer over fd 1 by
//! emitting `stdio: fputs ok` (via `fputs`) and `stdio: fwrite ok`
//! (via `fwrite`), then `fflush`-ing the stdout stream. Returns 0.
//! The harness's pass signal is the validate runner's "validate
//! round-trip succeeded" line — the stdio output is observable in
//! the kernel console for visual confirmation that the buffered
//! layer round-tripped through `narf_user_runtime::write`.

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

// The lib crate's `_start` is the ELF entry point. We don't re-
// export it here — the linker pulls it out of the rlib because
// `validate.ld` names `_start` as `ENTRY`.
extern crate narf_libc;

// The 16-byte TLS template is BYTE()'d directly into `.tdata` by
// `validate.ld` rather than declared here. See the script for the
// rationale (Rust's `#[link_section = ".tdata"]` marks statics as
// TLS GLOBAL with vaddr 0, which makes codegen emit literal-zero
// loads for the address). The kernel's PT_TLS staging copies those
// 16 bytes into a per-task block; narf-libc's errno helpers read
// `fs_base - 8`, which lands inside that image.

/// Atexit callback for the validation probe. Must be `extern "C"`
/// to match the registration ABI.
extern "C" fn cleanup() {
    narf_libc::printf_str("atexit: ok\n", &[]);
}

#[no_mangle]
pub extern "C" fn main(
    _argc: i32,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    use narf_libc::Arg;

    let pid = narf_libc::getpid();
    narf_libc::printf_str(
        "hello from narf-libc; pid=%d\n",
        &[Arg::Int(pid as i64)],
    );

    // ── printf-shim format-spec probes ────────────────────────────
    // Each probe drives a distinct branch of the format-spec parser.
    // The round-trip succeeding proves no fault on width / precision
    // / flag combinations.
    narf_libc::printf_str("padded: '%5d'\n",   &[Arg::Int(42)]);
    narf_libc::printf_str("zero: '%05d'\n",    &[Arg::Int(42)]);
    narf_libc::printf_str("left: '%-5d|'\n",   &[Arg::Int(42)]);
    narf_libc::printf_str("prec: '%.4x'\n",    &[Arg::Hex(0x2a)]);
    narf_libc::printf_str("octal: '%o'\n",     &[Arg::Uint(42)]);
    narf_libc::printf_str("binary: '%b'\n",    &[Arg::Uint(42)]);
    narf_libc::printf_str("long: '%lld'\n",    &[Arg::Int(-1)]);
    narf_libc::printf_str(
        "strpad: '%-10s|%.3s'\n",
        &[Arg::Str("hi"), Arg::Str("abcdef")],
    );
    narf_libc::printf_str(
        "altsign: '%+d %#x'\n",
        &[Arg::Int(7), Arg::Hex(0xdead)],
    );
    narf_libc::fprintf_str(1, "fprintf: '%u'\n", &[Arg::Uint(123)]);

    // ── FILE* layer probes over static stdout ─────────────────────
    // No fopen — the validate runner has no mount table. fd 1 via
    // the static stdout() FILE is enough to prove the buffered
    // write path round-trips.
    //
    // SAFETY: stdout() is a stable pointer to a static File; byte
    // pointers are 'static literals; lengths match the literals.
    unsafe {
        let stream = narf_libc::stdout();
        let msg1 = b"stdio: fputs ok\n";
        narf_libc::fputs(msg1.as_ptr(), msg1.len(), stream);
        let msg2 = b"stdio: fwrite ok\n";
        narf_libc::fwrite(msg2.as_ptr(), 1, msg2.len(), stream);
        narf_libc::fflush(stream);
    }

    // ── string battery + env + atexit probes ─────────────────────
    // strchr probe — confirm the byte search lands on the first 'l'
    // of "hello".
    let hello: *const u8 = b"hello\0".as_ptr();
    // SAFETY: `hello` points to a NUL-terminated static literal; the
    // returned pointer (if non-null) is inside that literal.
    let p = unsafe { narf_libc::strchr(hello, b'l' as i32) };
    // SAFETY: `p` is either NULL or points into the literal "hello\0"
    // which is alive for the program's lifetime.
    unsafe {
        if !p.is_null() && *p == b'l' {
            narf_libc::printf_str("strchr: ok\n", &[]);
        } else {
            narf_libc::printf_str("strchr: bad\n", &[]);
        }
    }

    // memmove with overlap — the destination overlaps the source
    // (dst = src + 2). Direction-aware copy must take
    // "abcdefgh" -> "ababcdgh" (bytes 0..4 land at positions 2..6).
    let mut buf: [u8; 8] = *b"abcdefgh";
    // SAFETY: `buf` is 8 bytes; src=buf, dst=buf+2, n=4 stays inside.
    unsafe {
        narf_libc::memmove(buf.as_mut_ptr().add(2), buf.as_ptr(), 4);
    }
    let ok = &buf == b"ababcdgh";
    narf_libc::printf_str(
        if ok { "memmove: ok\n" } else { "memmove: bad\n" },
        &[],
    );

    // getenv probe — the validate harness boots with no envp, so any
    // lookup must miss cleanly (NULL return). Confirms both the
    // ENVIRON-init wiring AND the empty-table walk path.
    let n: *const u8 = b"PATH\0".as_ptr();
    // SAFETY: `n` is NUL-terminated and `name_len = 4` fits.
    let v = unsafe { narf_libc::getenv(n, 4) };
    narf_libc::printf_str(
        if v.is_null() { "getenv: ok\n" } else { "getenv: bad\n" },
        &[],
    );

    // atexit registration — `cleanup` runs after `main` returns,
    // BEFORE the kernel-side exit_task. The ordering proves the
    // dispatch loop in `narf_libc::exit` walks the table.
    // SAFETY: `cleanup` is a `'static` extern "C" fn; single-threaded
    // user mode keeps the table-write race-free.
    unsafe {
        let _ = narf_libc::atexit(cleanup);
    }

    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
