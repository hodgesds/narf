//! narf-libc-validate — smoke binary for narf-libc.
//!
//! Links against the relibc-shaped libc shim. The C-style `main`
//! signature is what `narf_libc::__libc_start_main` calls into;
//! `narf_libc::_start` (re-exported from the lib crate) is the
//! ELF entry point per `validate.ld`'s `ENTRY(_start)`.
//!
//! Behaviour: prints a single line containing `hello from narf-libc;
//! pid=<n>` to stdout, returns 0. The harness greps for the literal
//! prefix to confirm the printf-shim parsed correctly.

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
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}
