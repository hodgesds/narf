//! NARF interactive shell.
//!
//! Reads keystrokes from `/dev/console` one byte at a time, builds
//! a line buffer, and dispatches a tiny set of built-ins on Enter.
//! Single-process, no fork — every command runs synchronously inside
//! the shell's own trap context.
//!
//! Built-in commands:
//!   help               — list commands.
//!   echo <text>        — write text + newline back to the console.
//!   uname              — print "NARF" + the kernel version banner.
//!   pid                — call `getpid()` and print the result.
//!   exit               — terminate the shell process.
//!
//! Anything else is reported as "unknown command". The dispatch table
//! lives in `dispatch_line` so adding a new built-in is one match arm
//! plus its handler.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

const PROMPT: &[u8] = b"narf> ";
const NEWLINE: &[u8] = b"\n";

/// Maximum line length. Bounded to keep the buffer on the stack
/// (we have no heap in this binary) and bounded small to keep the
/// shell from consuming the keystroke ring on a stuck user.
const LINE_BUF: usize = 256;

/// Resolve the console fd. Tries `/dev/console`, then `/dev/tty`
/// as a fallback. Returns `-1` if neither exists.
unsafe fn open_console() -> i32 {
    for path in [b"/dev/console\0".as_ptr(), b"/dev/tty\0".as_ptr()] {
        let fd = unsafe { libc::posix_open(path as *const i8, libc::O_RDWR, 0) };
        if fd >= 0 {
            return fd;
        }
    }
    -1
}

/// Block-style write of `bytes` to `fd`, looping until everything is out.
/// Short writes are normal — the console fd's underlying `write` returns
/// the number of bytes the FileOps consumed.
unsafe fn write_all(fd: i32, bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        let n = unsafe {
            libc::posix_write(
                fd,
                bytes.as_ptr().add(written) as *const _,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            return;
        }
        written += n as usize;
    }
}

/// Cooperative blocking read: poll the console fd, sleeping briefly
/// when empty so we don't hot-spin against the input ring. Returns
/// the byte read, or `None` on EOF / error.
unsafe fn read_byte(fd: i32) -> Option<u8> {
    let mut buf = [0u8; 1];
    loop {
        let n = unsafe { libc::posix_read(fd, buf.as_mut_ptr() as *mut _, 1) };
        if n == 1 {
            return Some(buf[0]);
        }
        if n < 0 {
            return None;
        }
        // n == 0 → no input queued. Yield via a short sleep so
        // other tasks (the keyboard pump, the scheduler tick) get
        // CPU. 1 second matches `libc::sleep`'s coarse resolution
        // today; refining to ~10 ms is a follow-up.
        unsafe {
            libc::sleep(0);
        }
    }
}

/// Inspect a single byte for line-editing semantics. Returns the
/// action the read loop should take.
enum LineAction {
    Append(u8),
    Backspace,
    Submit,
    Ignore,
}

fn classify(b: u8) -> LineAction {
    match b {
        b'\n' | b'\r' => LineAction::Submit,
        // Backspace = 0x7F (DEL) per the /dev/console translation.
        // ^H = 0x08 from terminals that send it instead.
        0x7F | 0x08 => LineAction::Backspace,
        // Printable ASCII range. Tab is intentionally not allowed —
        // shell built-ins don't take whitespace-quoted args.
        0x20..=0x7E => LineAction::Append(b),
        _ => LineAction::Ignore,
    }
}

/// Strip leading whitespace + return the (command, rest) split.
fn split_first<'a>(line: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    let start = line.iter().position(|&b| b != b' ').unwrap_or(line.len());
    let line = &line[start..];
    match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], skip_ws(&line[i..])),
        None => (line, &[]),
    }
}

fn skip_ws(s: &[u8]) -> &[u8] {
    let i = s.iter().position(|&b| b != b' ').unwrap_or(s.len());
    &s[i..]
}

unsafe fn dispatch_line(fd: i32, line: &[u8]) -> bool {
    let (cmd, rest) = split_first(line);
    if cmd.is_empty() {
        return true;
    }
    if cmd == b"help" {
        unsafe {
            write_all(fd, b"commands: help echo uname pid exit\n");
        }
    } else if cmd == b"echo" {
        unsafe {
            write_all(fd, rest);
            write_all(fd, NEWLINE);
        }
    } else if cmd == b"uname" {
        unsafe {
            write_all(fd, b"NARF (microkernel)\n");
        }
    } else if cmd == b"pid" {
        let pid = unsafe { libc::getpid() };
        let mut buf = [0u8; 12];
        let s = u32_to_decimal(pid as u32, &mut buf);
        unsafe {
            write_all(fd, b"pid: ");
            write_all(fd, s);
            write_all(fd, NEWLINE);
        }
    } else if cmd == b"exit" {
        return false;
    } else {
        unsafe {
            write_all(fd, b"unknown command: ");
            write_all(fd, cmd);
            write_all(fd, NEWLINE);
            write_all(fd, b"type 'help' for the built-in list\n");
        }
    }
    true
}

fn u32_to_decimal(mut v: u32, buf: &mut [u8]) -> &[u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut tmp = [0u8; 12];
    let mut i = 0;
    while v != 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    for (j, &c) in tmp[..i].iter().rev().enumerate() {
        buf[j] = c;
    }
    &buf[..i]
}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    unsafe {
        libc::puts(b"NARF shell -- type 'help' for commands.\n\0".as_ptr());

        let fd = open_console();
        if fd < 0 {
            libc::puts(b"shell: failed to open /dev/console\n\0".as_ptr());
            return 1;
        }

        let mut line = [0u8; LINE_BUF];

        loop {
            // Prompt.
            write_all(fd, PROMPT);

            // Line editor.
            let mut len = 0usize;
            loop {
                let b = match read_byte(fd) {
                    Some(b) => b,
                    None => return 0,
                };
                match classify(b) {
                    LineAction::Append(c) if len < LINE_BUF => {
                        line[len] = c;
                        len += 1;
                        // Local echo so the user sees what they typed
                        // — `/dev/console` doesn't echo by itself.
                        write_all(fd, &[c]);
                    }
                    LineAction::Append(_) => {
                        // Line full; ring the bell and drop the byte.
                        write_all(fd, b"\x07");
                    }
                    LineAction::Backspace if len > 0 => {
                        len -= 1;
                        // Visual erase: BS, space, BS.
                        write_all(fd, b"\x08 \x08");
                    }
                    LineAction::Backspace => {}
                    LineAction::Submit => {
                        write_all(fd, NEWLINE);
                        break;
                    }
                    LineAction::Ignore => {}
                }
            }

            if !dispatch_line(fd, &line[..len]) {
                write_all(fd, b"shell: bye\n");
                return 0;
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
