//! `__libc_start_main` — the Rust-side of the relibc startup
//! contract. Parses argc/argv/envp/auxv off the SysV-AMD64 entry
//! stack, calls user `main`, then `exit`s with the returned status.
//!
//! Why this shape: relibc / glibc share the same observable
//! contract — `_start` (asm, captures rsp) -> `__libc_start_main`
//! (C, parses startup vectors + initialises libc internals) ->
//! user `main` -> `exit`. NARF doesn't yet need the full glibc
//! pipeline (no ctors/dtors, no env-table linking, no
//! `__libc_init_first`) so we ship just the parsing + dispatch
//! frame and keep the rest as TODO follow-ups.

use crate::env::init_environ;
use crate::process::exit;

/// Saved entry-stack pointer, captured by the SysV `_start` shim.
/// Stored statically so child code (e.g. `getauxval`-shaped helpers
/// in a follow-up round) can re-walk the aux vector without needing
/// us to thread it through every call.
///
/// On aarch64 (where the Stage-4 pipeline doesn't hand argv on the
/// stack yet) this stays 0 and the parse path is skipped.
static mut RSP_AT_ENTRY: u64 = 0;

/// Rust entry from `_start`. `rsp_at_entry` is the original `rsp`
/// at user-mode entry — `[rsp]` is argc, `[rsp+8..]` is argv. We
/// must not assume any prologue-mutated rsp here; the caller did
/// `mov rdi, rsp` before any prologue ran.
///
/// # Safety
/// `rsp_at_entry` must be either 0 (aarch64 / pre-stack pipelines)
/// or the genuine kernel-laid-down argv stack. Trusting a forged
/// value would let the parse path read arbitrary memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_start_main(rsp_at_entry: u64) -> ! {
    // SAFETY: single-threaded startup — no other code can race the
    // initial write into RSP_AT_ENTRY.
    unsafe {
        RSP_AT_ENTRY = rsp_at_entry;
    }

    let (argc, argv, envp) = if rsp_at_entry == 0 {
        (0i32, core::ptr::null::<*const u8>(), core::ptr::null::<*const u8>())
    } else {
        // SAFETY: trusting `rsp_at_entry` per the function-level
        // contract. The kernel's stack initialiser writes a
        // canonical SysV-AMD64 argv frame: argc | argv[..argc] |
        // NULL | envp[..] | NULL | auxv[..] | AT_NULL.
        unsafe { parse_startup_stack(rsp_at_entry) }
    };

    // Publish the kernel-supplied envp into the global `ENVIRON`
    // BEFORE user `main` runs, so a `getenv` from inside `main`
    // observes a populated table. Single-threaded startup means no
    // race vs. concurrent readers.
    //
    // SAFETY: write-once during single-threaded startup.
    unsafe { init_environ(envp) };

    // SAFETY: `main` is the consumer-supplied `extern "C" fn`
    // declared in `lib.rs`. It is the bin's responsibility to
    // honour the C ABI (we declared it `extern "C"`).
    let rc = unsafe { super::main(argc, argv, envp) };
    exit(rc)
}

/// SAFETY: see [`__libc_start_main`]'s contract.
unsafe fn parse_startup_stack(rsp: u64) -> (i32, *const *const u8, *const *const u8) {
    // SAFETY: the kernel laid out a real argv frame at `rsp`.
    let argc = unsafe { core::ptr::read_volatile(rsp as *const i64) } as i32;
    // argv starts immediately after argc.
    let argv = (rsp + 8) as *const *const u8;
    // envp starts after argv's argc entries + the NULL terminator.
    let envp_off = 8 + ((argc as u64).saturating_add(1)).saturating_mul(8);
    let envp = (rsp + envp_off) as *const *const u8;
    (argc, argv, envp)
}

/// Read-only accessor for the saved entry-rsp. Returns 0 if the
/// startup walk didn't run (e.g. aarch64).
pub fn entry_rsp() -> u64 {
    // SAFETY: write-once during single-threaded startup; subsequent
    // reads observe the published value.
    unsafe { RSP_AT_ENTRY }
}
