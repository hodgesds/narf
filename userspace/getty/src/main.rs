//! NARF getty / login.
//!
//! The first userspace login agent on the boot console. It sets up a login
//! *session*, authenticates a user, and then hands off to the shell:
//!
//!   1. `setsid()`                  — become session + process-group leader.
//!   2. `ioctl(0, TIOCSCTTY)`       — claim the console as the session's
//!                                    controlling terminal.
//!   3. `ioctl(0, TIOCSPGRP, &pgid)`— tcsetpgrp: foreground our group so we
//!                                    can read the tty without SIGTTIN.
//!   4. login loop: prompt `login:`, read a username (echoed); prompt
//!      `Password:`, read a password with ECHO disabled; verify against
//!      `/etc/passwd`. Retry (with a delay) on failure.
//!   5. `execve("/bin/shell")`      — the shell inherits session + ctty +
//!                                    foreground pgrp.
//!
//! Credentials live in `/etc/passwd` (classic 7-field, password in field 2
//! — pre-`/etc/shadow`, plaintext). This is an educational kernel with no
//! crypto/`crypt(3)` and a capability-based authority model (POSIX uids are
//! cosmetic), so the password is a real *gate on the login flow*, not a
//! security boundary. An empty password field means "no password" (the
//! login succeeds immediately for that user), mirroring historical Unix.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

/// x86_64 Linux `ioctl(2)` syscall number. narf-libc's `ioctl` wrapper is
/// a stub (returns ENOTTY), so terminal ioctls go through the raw syscall
/// path, like other narf-libc tty callers.
const SYS_IOCTL: u64 = 16;
const TIOCSCTTY: u64 = 0x540E;
const TIOCSPGRP: u64 = 0x5410;
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
/// `c_lflag` ECHO bit (asm-generic termbits); c_lflag is at wire offset 12.
const L_ECHO: u32 = 0x0000_0008;

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

/// Read one cooked input line from fd 0 into `buf` (the trailing newline is
/// consumed but not stored). Returns the line length. Echo is governed by
/// the terminal's ECHO flag (toggled by the caller via `set_echo`), so this
/// is used for both the visible username and the hidden password.
unsafe fn read_line(buf: &mut [u8]) -> usize {
    let mut len = 0usize;
    loop {
        let mut b = [0u8; 1];
        // SAFETY: 1-byte read into a stack buffer; the console blocks until
        // a byte (or a completed line in cooked mode) is available.
        let n = unsafe { libc::posix_read(0, b.as_mut_ptr() as *mut _, 1) };
        if n <= 0 {
            break; // EOF / error — return what we have
        }
        match b[0] {
            b'\n' | b'\r' => break,
            c if len < buf.len() => {
                buf[len] = c;
                len += 1;
            }
            _ => {} // line full — drop the overflow
        }
    }
    len
}

/// Enable or disable terminal echo (TCGETS → toggle ECHO in c_lflag →
/// TCSETS) so the password is not displayed as it is typed.
unsafe fn set_echo(on: bool) {
    let mut t = [0u8; 60];
    // SAFETY: raw TCGETS writes the 60-byte termios into our stack buffer.
    let g = unsafe { narf_user_runtime::syscall3_raw(SYS_IOCTL, 0, TCGETS, t.as_mut_ptr() as u64) };
    if g as i64 != 0 {
        return; // no tty — nothing to toggle
    }
    let mut lflag = u32::from_le_bytes([t[12], t[13], t[14], t[15]]);
    if on {
        lflag |= L_ECHO;
    } else {
        lflag &= !L_ECHO;
    }
    t[12..16].copy_from_slice(&lflag.to_le_bytes());
    // SAFETY: raw TCSETS reads the 60-byte termios from our stack buffer.
    unsafe {
        narf_user_runtime::syscall3_raw(SYS_IOCTL, 0, TCSETS, t.as_ptr() as u64);
    }
}

/// Split a `/etc/passwd` line into (username, password) — field 1 and the
/// classic plaintext password in field 2. `None` if there is no `:`.
fn split_user_pass(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let c1 = line.iter().position(|&b| b == b':')?;
    let rest = &line[c1 + 1..];
    let c2 = rest.iter().position(|&b| b == b':').unwrap_or(rest.len());
    Some((&line[..c1], &rest[..c2]))
}

/// Length-checked, difference-accumulating byte compare (avoids an early
/// `return` on the first mismatched byte).
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verify `(user, pass)` against `/etc/passwd`. Reads the file, scans for a
/// line whose field 1 == `user`, and compares field 2 to `pass`. An empty
/// stored password matches an empty entered password (no-password account).
unsafe fn check_credentials(user: &[u8], pass: &[u8]) -> bool {
    // SAFETY: NUL-terminated literal path; O_RDONLY = 0.
    let fd = unsafe { libc::posix_open(b"/etc/passwd\0".as_ptr() as *const i8, 0, 0) };
    if fd < 0 {
        return false;
    }
    let mut buf = [0u8; 1024];
    let mut total = 0usize;
    while total < buf.len() {
        // SAFETY: read into the unused tail of our stack buffer.
        let n = unsafe {
            libc::posix_read(fd, buf.as_mut_ptr().add(total) as *mut _, buf.len() - total)
        };
        if n <= 0 {
            break;
        }
        total += n as usize;
    }
    // SAFETY: fd was opened above.
    unsafe { libc::posix_close(fd) };

    let data = &buf[..total];
    let mut line_start = 0usize;
    let mut i = 0usize;
    while i <= data.len() {
        if i == data.len() || data[i] == b'\n' {
            let line = &data[line_start..i];
            line_start = i + 1;
            if let Some((u, p)) = split_user_pass(line) {
                if bytes_eq(u, user) && bytes_eq(p, pass) {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

#[no_mangle]
// Fixed entry signature; argv/envp are unused (we synthesize the shell's).
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // SAFETY: every call below is a syscall shim / raw syscall with
    // arguments that are scalars or pointers into this function's own
    // stack / rodata, valid for the duration of the call.
    unsafe {
        // 1. New session: getty becomes session + group leader, detaching
        //    any inherited controlling terminal.
        libc::setsid();
        // 2. Claim the boot console as this session's controlling tty.
        narf_user_runtime::syscall3_raw(SYS_IOCTL, 0, TIOCSCTTY, 0);
        // 3. Foreground our process group (tcsetpgrp). As session leader,
        //    pgid == pid — so we can read the login prompt without SIGTTIN.
        let pgid: i32 = libc::getpid();
        narf_user_runtime::syscall3_raw(SYS_IOCTL, 0, TIOCSPGRP, &pgid as *const i32 as u64);

        // 4. Authenticate.
        let mut user = [0u8; 64];
        loop {
            write_console(b"\nNARF login: ");
            let ulen = read_line(&mut user);
            if ulen == 0 {
                continue; // empty username — re-prompt
            }

            write_console(b"Password: ");
            set_echo(false);
            let mut pass = [0u8; 64];
            let plen = read_line(&mut pass);
            set_echo(true);
            write_console(b"\n"); // the (un-echoed) newline

            if check_credentials(&user[..ulen], &pass[..plen]) {
                break;
            }
            // Wrong credentials: a brief delay (anti-brute-force, like real
            // login) then re-prompt.
            write_console(b"Login incorrect\n");
            libc::usleep(1_000_000);
        }

        write_console(b"\nWelcome to NARF.\n\n");

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
