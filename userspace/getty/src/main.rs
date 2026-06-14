//! NARF getty / login.
//!
//! The first userspace login agent on the boot console. It establishes a
//! real login *session* and then hands off to the shell:
//!
//!   1. `setsid()`                  — become session + process-group leader
//!                                    (drops any inherited controlling tty).
//!   2. `ioctl(0, TIOCSCTTY)`       — claim the console (fd 0/1/2, inherited
//!                                    at spawn) as this session's controlling
//!                                    terminal.
//!   3. `ioctl(0, TIOCSPGRP, &pgid)`— make our group the terminal's
//!                                    foreground process group (tcsetpgrp),
//!                                    so the shell runs in the foreground and
//!                                    a background job it spawns trips
//!                                    SIGTTIN / SIGTTOU on console access.
//!   4. print a login banner.
//!   5. `execve("/bin/shell")`      — replace ourselves with the shell,
//!                                    which inherits the session, controlling
//!                                    terminal, and foreground pgrp.
//!
//! There is no password database yet, so this is an auto-login as root —
//! the structure (session leader → ctty → fg pgrp → exec login shell) is
//! the real getty/login flow; only the credential check is stubbed.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

/// x86_64 Linux `ioctl(2)` syscall number. narf-libc's `ioctl` wrapper is
/// a stub (returns ENOTTY), so the terminal ioctls go through the raw
/// syscall path like other narf-libc tty callers.
const SYS_IOCTL: u64 = 16;
const TIOCSCTTY: u64 = 0x540E;
const TIOCSPGRP: u64 = 0x5410;

/// Write `bytes` to fd 1 (the console), looping on short writes.
unsafe fn write_console(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: `bytes` is a valid slice; posix_write is a syscall shim.
        let n = unsafe {
            libc::posix_write(
                1,
                bytes.as_ptr().add(written) as *const _,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            break;
        }
        written += n as usize;
    }
}

#[no_mangle]
// Fixed entry signature; argv/envp are unused (we synthesize the shell's).
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // SAFETY: every call below is a syscall shim / raw syscall with
    // arguments that are either scalars or pointers into this function's
    // own stack/rodata, valid for the duration of the call.
    unsafe {
        // 1. New session: getty becomes session + group leader and detaches
        //    any inherited controlling terminal.
        libc::setsid();

        // 2. Claim the boot console as this session's controlling tty.
        narf_user_runtime::syscall3_raw(SYS_IOCTL, 0, TIOCSCTTY, 0);

        // 3. Foreground our process group (tcsetpgrp). As session leader,
        //    pgid == pid.
        let pgid: i32 = libc::getpid();
        narf_user_runtime::syscall3_raw(SYS_IOCTL, 0, TIOCSPGRP, &pgid as *const i32 as u64);

        // 4. Login banner.
        write_console(b"\nNARF login: root (auto-login)\n\n");

        // 5. Hand off to the shell, which inherits session + ctty + fg pgrp.
        //    A leading '-' in argv[0] marks it as a login shell.
        let path = b"/bin/shell\0";
        let arg0 = b"-shell\0";
        let argv = [arg0.as_ptr() as *const i8, core::ptr::null()];
        let envp = [core::ptr::null::<i8>()];
        libc::execve(path.as_ptr() as *const i8, argv.as_ptr(), envp.as_ptr());

        // execve only returns on failure.
        write_console(b"getty: exec /bin/shell failed\n");
        libc::_exit(1)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
