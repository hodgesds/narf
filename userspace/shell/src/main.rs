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
use core::sync::atomic::AtomicU32;
use narf_libc as libc;

/// Counts signal-handler hits for the `raise` smoke command.
static RAISED: AtomicU32 = AtomicU32::new(0);

/// Path used by the `socktest` smoke command. Static so both the
/// listener thread and the connecter agree.
const SOCKTEST_PATH: &[u8] = b"/sock/test\0";

/// Build a sockaddr_un on the stack with the given path bytes.
/// Returns (struct, total length).
fn make_sockaddr_un(buf: &mut [u8; 110], path: &[u8]) -> u32 {
    // sa_family = 1 (AF_UNIX), little-endian u16
    buf[0] = 1;
    buf[1] = 0;
    let n = core::cmp::min(path.len(), 108);
    for i in 0..n {
        buf[2 + i] = path[i];
    }
    (2 + n) as u32
}

extern "C" fn socktest_listener(_arg: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    use core::sync::atomic::Ordering;
    let lfd = unsafe { libc::socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0) };
    if lfd < 0 {
        SOCKTEST_RESULT.store(0xE1, Ordering::SeqCst);
        return core::ptr::null_mut();
    }
    let mut addr_buf = [0u8; 110];
    let alen = make_sockaddr_un(&mut addr_buf, SOCKTEST_PATH);
    let r = unsafe {
        libc::bind(lfd, addr_buf.as_ptr() as *const libc::sockaddr, alen)
    };
    if r < 0 {
        SOCKTEST_RESULT.store(0xE2, Ordering::SeqCst);
        return core::ptr::null_mut();
    }
    let r = unsafe { libc::listen(lfd, 4) };
    if r < 0 {
        SOCKTEST_RESULT.store(0xE3, Ordering::SeqCst);
        return core::ptr::null_mut();
    }
    SOCKTEST_LISTENING.store(1, Ordering::SeqCst);
    let cfd = unsafe {
        libc::accept(lfd, core::ptr::null_mut(), core::ptr::null_mut())
    };
    if cfd < 0 {
        SOCKTEST_RESULT.store(0xE4, Ordering::SeqCst);
        return core::ptr::null_mut();
    }
    // Read "ping" (4 bytes).
    let mut rbuf = [0u8; 16];
    let n = unsafe {
        libc::recv(cfd, rbuf.as_mut_ptr() as *mut core::ffi::c_void, rbuf.len(), 0)
    };
    if n != 4 || &rbuf[..4] != b"ping" {
        SOCKTEST_RESULT.store(0xE5, Ordering::SeqCst);
        return core::ptr::null_mut();
    }
    // Write "pong".
    let n = unsafe {
        libc::send(cfd, b"pong".as_ptr() as *const core::ffi::c_void, 4, 0)
    };
    if n != 4 {
        SOCKTEST_RESULT.store(0xE6, Ordering::SeqCst);
        return core::ptr::null_mut();
    }
    SOCKTEST_RESULT.store(1, Ordering::SeqCst);
    // Release the listener path so subsequent runs can re-bind.
    let _ = unsafe { libc::posix::close(lfd) };
    let _ = unsafe { libc::posix::close(cfd) };
    core::ptr::null_mut()
}

static SOCKTEST_LISTENING: AtomicU32 = AtomicU32::new(0);
static SOCKTEST_RESULT: AtomicU32 = AtomicU32::new(0);

fn socktest_run(fd: i32) {
    use core::sync::atomic::Ordering;
    SOCKTEST_LISTENING.store(0, Ordering::SeqCst);
    SOCKTEST_RESULT.store(0, Ordering::SeqCst);
    // Spawn the listener thread.
    let mut tid: u64 = 0;
    let attr = core::ptr::null::<libc::pthread_attr_t>();
    let rc = unsafe {
        libc::pthread_create(
            &mut tid as *mut u64,
            attr,
            socktest_listener,
            core::ptr::null_mut(),
        )
    };
    if rc != 0 {
        unsafe { write_all(fd, b"socktest: pthread_create failed\n"); }
        return;
    }
    // Spin until the listener says it's bound + listening. The
    // 1-CPU executor gives the listener a slice every time we
    // yield (sleep with non-zero ns triggers the scheduler's
    // park-and-repoll path; sleep(0) is a fast no-op kernel-side
    // and would never yield).
    while SOCKTEST_LISTENING.load(Ordering::SeqCst) == 0 {
        unsafe { libc::usleep(1000); } // 1 ms
    }
    // Parent: connect, write ping, read pong.
    let cfd = unsafe { libc::socket(1, 1, 0) };
    if cfd < 0 {
        unsafe { write_all(fd, b"socktest: parent socket() failed\n"); }
        return;
    }
    let mut addr_buf = [0u8; 110];
    let alen = make_sockaddr_un(&mut addr_buf, SOCKTEST_PATH);
    let r = unsafe {
        libc::connect(cfd, addr_buf.as_ptr() as *const libc::sockaddr, alen)
    };
    if r < 0 {
        unsafe { write_all(fd, b"socktest: parent connect() failed\n"); }
        return;
    }
    let n = unsafe {
        libc::send(cfd, b"ping".as_ptr() as *const core::ffi::c_void, 4, 0)
    };
    if n != 4 {
        unsafe { write_all(fd, b"socktest: parent send(ping) short\n"); }
        return;
    }
    let mut rbuf = [0u8; 16];
    let n = unsafe {
        libc::recv(cfd, rbuf.as_mut_ptr() as *mut core::ffi::c_void, rbuf.len(), 0)
    };
    if n != 4 || &rbuf[..4] != b"pong" {
        unsafe { write_all(fd, b"socktest: parent recv != pong\n"); }
        return;
    }
    // Join the listener.
    let _ = unsafe { libc::pthread_join(tid, core::ptr::null_mut()) };
    let _ = unsafe { libc::posix::close(cfd) };
    let result = SOCKTEST_RESULT.load(Ordering::SeqCst);
    if result == 1 {
        unsafe { write_all(fd, b"socktest: ok (ping<->pong over AF_UNIX)\n"); }
    } else {
        let mut buf = [0u8; 12];
        let s = u32_to_decimal(result, &mut buf);
        unsafe {
            write_all(fd, b"socktest: failed listener-stage=0x");
            write_all(fd, s);
            write_all(fd, NEWLINE);
        }
    }
}

/// Shared counter the `threads` smoke command increments from
/// every worker thread.
static COUNTER: AtomicU32 = AtomicU32::new(0);

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
        // CPU. `libc::sleep(0)` is a no-op (sys_sleep early-returns
        // on ns==0), which would hot-spin posix_read and burn the
        // kernel heap inside whatever per-read allocation devfs
        // does. usleep(10_000) = 10 ms gives a reasonable typing
        // latency while letting the executor round-robin other
        // tasks, including init's deadline-park sleep.
        unsafe {
            libc::usleep(10_000);
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
            write_all(fd, b"commands: help echo uname pid exec exit\n");
        }
    } else if cmd == b"exec" {
        // exec <path> — POSIX-style replace-current-task with the
        // ELF at <path>. Argv passed: ["<path>"] (basename
        // convention is left to the caller's path). Envp empty.
        // On success this call NEVER returns — we never get to
        // print "unknown command" or anything else.
        let path = skip_ws(rest);
        // Also trim trailing whitespace + control chars.
        let path: &[u8] = {
            let mut end = path.len();
            while end > 0 && (path[end - 1] == b' ' || path[end - 1] < 0x20) {
                end -= 1;
            }
            &path[..end]
        };
        if path.is_empty() {
            unsafe { write_all(fd, b"exec: missing path\n"); }
        } else {
            // Build a NUL-terminated path on the stack (cap at
            // 256 bytes — anything longer is rejected as bad
            // input).
            let mut pbuf = [0u8; 256];
            if path.len() >= pbuf.len() {
                unsafe { write_all(fd, b"exec: path too long\n"); }
            } else {
                pbuf[..path.len()].copy_from_slice(path);
                let argv0 = pbuf.as_ptr() as *const i8;
                let argv: [*const i8; 2] = [argv0, core::ptr::null()];
                let envp: [*const i8; 1] = [core::ptr::null()];
                let rc = unsafe {
                    libc::execve(argv0, argv.as_ptr(), envp.as_ptr())
                };
                // execve returns only on failure.
                let mut buf = [0u8; 32];
                let s = u32_to_decimal(rc as u32, &mut buf);
                unsafe {
                    write_all(fd, b"exec: failed (rc=");
                    write_all(fd, s);
                    write_all(fd, b")\n");
                }
            }
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
    } else if cmd == b"socktest" {
        // socktest — spawn a worker that binds an AF_UNIX listener
        // at /sock/test, accepts one connection, reads "ping" and
        // writes "pong". Parent connects, writes "ping", reads
        // "pong", joins. Validates socket / bind / listen /
        // accept / connect / send / recv end-to-end.
        socktest_run(fd);
    } else if cmd == b"threads" {
        // threads <N> — spawn N threads, each increments a shared
        // atomic counter K times, joins all, prints total. Exercises
        // the full clone -> trampoline -> exit -> futex_wake -> join
        // loop end-to-end.
        let s = skip_ws(rest);
        let mut n: i32 = 0;
        for &b in s.iter() {
            if (b as char).is_ascii_digit() {
                n = n * 10 + ((b - b'0') as i32);
            } else {
                break;
            }
        }
        if n <= 0 || n > 16 {
            unsafe { write_all(fd, b"threads: pass 1..16\n"); }
        } else {
            const K: u32 = 1000;
            COUNTER.store(0, core::sync::atomic::Ordering::SeqCst);
            extern "C" fn worker(_arg: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
                use core::sync::atomic::Ordering;
                for _ in 0..K {
                    COUNTER.fetch_add(1, Ordering::SeqCst);
                }
                core::ptr::null_mut()
            }
            let mut tids = [0u64; 16];
            for i in 0..n as usize {
                let attr = core::ptr::null::<libc::pthread_attr_t>();
                let _rc = unsafe {
                    libc::pthread_create(
                        &mut tids[i] as *mut u64,
                        attr,
                        worker,
                        core::ptr::null_mut(),
                    )
                };
            }
            for i in 0..n as usize {
                let _ = unsafe {
                    libc::pthread_join(tids[i], core::ptr::null_mut())
                };
            }
            let total = COUNTER.load(core::sync::atomic::Ordering::SeqCst);
            let mut buf = [0u8; 16];
            let s = u32_to_decimal(total, &mut buf);
            unsafe {
                write_all(fd, b"threads: total=");
                write_all(fd, s);
                write_all(fd, b" expected=");
                let mut e_buf = [0u8; 16];
                let e_s = u32_to_decimal((n as u32) * K, &mut e_buf);
                write_all(fd, e_s);
                write_all(fd, NEWLINE);
            }
        }
    } else if cmd == b"raise" {
        // raise <signum> — install a tiny handler for the named
        // signal, raise(signum) to deliver it to ourselves, then
        // confirm the handler ran. Exercises the full kill ->
        // delivery -> sigreturn loop.
        let s = skip_ws(rest);
        let mut signum: i32 = 0;
        for &b in s.iter() {
            if (b as char).is_ascii_digit() {
                signum = signum * 10 + ((b - b'0') as i32);
            } else {
                break;
            }
        }
        if signum == 0 {
            unsafe { write_all(fd, b"raise: missing signum\n"); }
        } else {
            // Install the smoke handler. RAISED counts hits.
            extern "C" fn smoke_handler(_n: i32) {
                use core::sync::atomic::Ordering;
                RAISED.fetch_add(1, Ordering::SeqCst);
            }
            let prior = unsafe {
                libc::signal(signum, smoke_handler as usize)
            };
            let _ = prior;
            // Self-deliver via raise(2).
            let r = unsafe { libc::raise(signum) };
            // Read back the count and report.
            let count = RAISED.load(core::sync::atomic::Ordering::SeqCst);
            let mut buf = [0u8; 12];
            let s = u32_to_decimal(count, &mut buf);
            unsafe {
                write_all(fd, b"raise: rc=");
                let mut rc_buf = [0u8; 12];
                let rc_s = u32_to_decimal(r as u32, &mut rc_buf);
                write_all(fd, rc_s);
                write_all(fd, b" handler-hits=");
                write_all(fd, s);
                write_all(fd, NEWLINE);
            }
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
