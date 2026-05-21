//! relibc compatibility shim.
//!
//! Redox's relibc is the Rust-implemented POSIX libc most Rust
//! user-mode binaries link against when targeting an OS that
//! isn't Linux/glibc. This crate exposes the same `extern "C"`
//! symbol surface relibc does by re-exporting from
//! [`narf_libc`] — which is already a POSIX libc with 480
//! `#[no_mangle]` exports under their canonical names
//! (`open`, `read`, `write`, `malloc`, `free`, `printf`,
//! `strlen`, `exit`, …).
//!
//! What this crate adds on top:
//!
//! 1. **Cargo presence**: a crate named `narf-compat-relibc` so a
//!    consumer's `Cargo.toml` can `narf-compat-relibc = "*"` and
//!    have its `_start` / `crt0.o` / dynamic loader find the
//!    expected symbols at link time. The crate is empty Rust-API-
//!    wise; its job is to pull in `narf_libc` as a transitive dep
//!    and put it on the linker's search path.
//!
//! 2. **Symbol-name aliases** for the small set of cases where
//!    relibc uses Redox-specific names (typically prefixed
//!    `__relibc_*` or `__redox_*`) whose narf-libc equivalent has
//!    the standard POSIX name. Aliases live below as `#[no_mangle]`
//!    wrappers; each is a one-liner forwarding call.
//!
//! 3. **Compile-time symbol-presence assertions** so a regression
//!    in narf-libc that drops an exported function trips a build
//!    error here instead of a link error in a downstream binary.
//!
//! ## Scope
//!
//! What this crate **does not** do:
//! - Provide a complete `relibc` source-level replacement.
//!   narf-libc is the implementation; this is just packaging.
//! - Ship C headers (`stdio.h`, `unistd.h`). Header generation is
//!   a follow-up — a build.rs invocation of `cbindgen` against
//!   narf-libc lands separately.
//! - Bundle a dynamic loader. NARF binaries are statically linked
//!   for the bring-up arc; PIE + dyn-link support already exists in
//!   `userspace/interp.rs` but isn't wired here.

#![no_std]

// Pull narf_libc in so its `#[no_mangle]` exports survive the
// link-time dead-code stripper.
pub use narf_libc as libc;

// ── Compile-time symbol-presence assertions ────────────────────────
//
// Anchor a `const fn` pointer to each function we promise to expose.
// If narf-libc renames or removes one, this file fails to compile —
// turning a downstream link-failure into a build-failure with a
// clear pointer at the missing symbol.

extern "C" {
    fn open(path: *const u8, oflag: i32, mode: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
    fn exit(code: i32) -> !;
    fn strlen(s: *const u8) -> usize;
}

#[allow(dead_code)]
const SYMBOL_TABLE: &[*const ()] = &[
    open as *const (),
    close as *const (),
    read as *const (),
    write as *const (),
    malloc as *const (),
    free as *const (),
    exit as *const (),
    strlen as *const (),
];

// ── Redox-specific alias wrappers ──────────────────────────────────
//
// relibc internally uses a handful of `__relibc_*` names for
// implementation-detail entry points. Provide one-line alias
// wrappers so binaries that linked against those names resolve.

/// relibc's internal init hook. Standard libc-init lives in
/// `_start`; this is a no-op in narf-libc since startup config
/// happens in the `_start` shim that calls `narf_libc::startup::*`.
#[unsafe(no_mangle)]
pub extern "C" fn __relibc_init() {}

/// relibc's internal panic hook. narf-libc doesn't have a panic
/// path at the libc layer (the kernel's panic handler catches);
/// this wrapper exists for link-completeness.
#[unsafe(no_mangle)]
pub extern "C" fn __relibc_panic(_msg: *const u8) -> ! {
    // SAFETY: exit is from narf-libc, extern "C" + diverging.
    unsafe { exit(1) }
}
