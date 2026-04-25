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

#[no_mangle]
pub extern "C" fn main(
    _argc: i32,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    let pid = narf_libc::getpid();
    narf_libc::printf_str(
        "hello from narf-libc; pid=%d\n",
        &[narf_libc::Arg::Int(pid as i64)],
    );

    // Exercise the FILE* layer over the static stdout. We don't go
    // through `fopen` here because the validate kernel runner does
    // not stand up a mount table — fd 1 is sufficient to prove the
    // buffered write path round-trips. `fflush` forces the line
    // out even if the line-buffer heuristic ever changes underfoot.
    //
    // SAFETY: `stdout()` returns a stable pointer to a static
    // `narf_libc::File`; the byte pointers are `'static` literals;
    // lengths match the literals exactly.
    unsafe {
        let s = narf_libc::stdout();
        let msg1 = b"stdio: fputs ok\n";
        narf_libc::fputs(msg1.as_ptr(), msg1.len(), s);
        let msg2 = b"stdio: fwrite ok\n";
        narf_libc::fwrite(msg2.as_ptr(), 1, msg2.len(), s);
        narf_libc::fflush(s);
    }
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
