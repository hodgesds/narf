//! The same raw Linux syscall assertions run on host Linux and in NARF user mode.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::fmt::{self, Write};

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const CLOSE: usize = 3;
    pub const LSEEK: usize = 8;
    pub const IOCTL: usize = 16;
    pub const PREAD: usize = 17;
    pub const PWRITE: usize = 18;
    pub const READV: usize = 19;
    pub const WRITEV: usize = 20;
    pub const PIPE: usize = 22;
    pub const DUP: usize = 32;
    pub const DUP3: usize = 292;
    pub const SENDFILE: usize = 40;
    pub const FCNTL: usize = 72;
    pub const EXIT: usize = 60;
    pub const PIPE2: usize = 293;
    pub const SPLICE: usize = 275;
    pub const TEE: usize = 276;
    pub const VMSPLICE: usize = 278;
    pub const PPOLL: usize = 271;
    pub const MEMFD: usize = 319;
    pub const SIGMASK: usize = 14;
    pub const SIGPENDING: usize = 127;
    pub const OPENAT: usize = 257;
    pub const MKNODAT: usize = 259;
    pub const UNLINKAT: usize = 263;
    pub const GETPID: usize = 39;
    pub const CLONE: usize = 56;
    pub const WAIT4: usize = 61;
    pub const COPY_FILE_RANGE: usize = 326;
    pub const MMAP: usize = 9;
    pub const MUNMAP: usize = 11;
}
#[cfg(target_arch = "aarch64")]
mod nr {
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const CLOSE: usize = 57;
    pub const LSEEK: usize = 62;
    pub const IOCTL: usize = 29;
    pub const PREAD: usize = 67;
    pub const PWRITE: usize = 68;
    pub const READV: usize = 65;
    pub const WRITEV: usize = 66;
    pub const DUP: usize = 23;
    pub const DUP3: usize = 24;
    pub const SENDFILE: usize = 71;
    pub const FCNTL: usize = 25;
    pub const EXIT: usize = 93;
    pub const PIPE2: usize = 59;
    pub const SPLICE: usize = 76;
    pub const TEE: usize = 77;
    pub const VMSPLICE: usize = 75;
    pub const PPOLL: usize = 73;
    pub const MEMFD: usize = 279;
    pub const SIGMASK: usize = 135;
    pub const SIGPENDING: usize = 136;
    pub const OPENAT: usize = 56;
    pub const MKNODAT: usize = 33;
    pub const UNLINKAT: usize = 35;
    pub const GETPID: usize = 172;
    pub const CLONE: usize = 220;
    pub const WAIT4: usize = 260;
    pub const COPY_FILE_RANGE: usize = 285;
    pub const MMAP: usize = 222;
    pub const MUNMAP: usize = 215;
}

// All pointers passed to the syscall ABI are checked by the kernel. Several
// assertions intentionally pass invalid addresses to verify EFAULT precedence.
fn call(n: usize, a: [usize; 6]) -> isize {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Linux syscall register ABI; memory effects are not marked nomem.
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") n => ret,
        in("rdi") a[0], in("rsi") a[1], in("rdx") a[2], in("r10") a[3],
        in("r8") a[4], in("r9") a[5], lateout("rcx") _, lateout("r11") _);
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Linux AArch64 syscall register ABI.
    unsafe {
        core::arch::asm!("svc #0", in("x8") n, inlateout("x0") a[0] => ret,
        inlateout("x1") a[1] => _, inlateout("x2") a[2] => _,
        inlateout("x3") a[3] => _, inlateout("x4") a[4] => _, inlateout("x5") a[5] => _);
    }
    ret
}
struct Output;
impl Write for Output {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let r = call(nr::WRITE, [1, s.as_ptr() as usize, s.len(), 0, 0, 0]);
        if r == s.len() as isize {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}
fn eq(name: &str, got: isize, want: isize) {
    if got != want {
        let _ = writeln!(Output, "pipe-abi FAIL {name}: got {got}, expected {want}");
        exit(1);
    }
}
fn yes(name: &str, value: bool) {
    eq(name, value as isize, 1);
}
fn exit(code: usize) -> ! {
    call(nr::EXIT, [code, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}
const NB: usize = 0x800;
const DIRECT: usize = 0x4000;
const CLOEXEC: usize = 0x80000;
const BAD: usize = usize::MAX;
const FAULT: usize = usize::MAX - 4095;
const AT_FDCWD: usize = (-100isize) as usize;
#[repr(C)]
struct Iov {
    base: usize,
    len: usize,
}
#[repr(C)]
struct Poll {
    fd: i32,
    events: i16,
    revents: i16,
}
fn pipe(flags: usize) -> [usize; 2] {
    let mut pair = [-1i32; 2];
    eq(
        "pipe2",
        call(nr::PIPE2, [pair.as_mut_ptr() as usize, flags, 0, 0, 0, 0]),
        0,
    );
    [pair[0] as usize, pair[1] as usize]
}
fn close(fd: usize) {
    eq("close", call(nr::CLOSE, [fd, 0, 0, 0, 0, 0]), 0);
}
fn close_pair(p: [usize; 2]) {
    close(p[0]);
    close(p[1]);
}
fn write(fd: usize, b: &[u8]) -> isize {
    call(nr::WRITE, [fd, b.as_ptr() as usize, b.len(), 0, 0, 0])
}
fn read(fd: usize, b: &mut [u8]) -> isize {
    call(nr::READ, [fd, b.as_mut_ptr() as usize, b.len(), 0, 0, 0])
}
fn fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    call(nr::FCNTL, [fd, cmd, arg, 0, 0, 0])
}
fn available(fd: usize) -> isize {
    let mut n = -1i32;
    eq(
        "FIONREAD",
        call(nr::IOCTL, [fd, 0x541b, &mut n as *mut _ as usize, 0, 0, 0]),
        0,
    );
    n as isize
}
fn splice(src: usize, dst: usize, n: usize, flags: usize) -> isize {
    call(nr::SPLICE, [src, 0, dst, 0, n, flags])
}
fn tee(src: usize, dst: usize, n: usize, flags: usize) -> isize {
    call(nr::TEE, [src, dst, n, flags, 0, 0])
}
fn vmsplice(fd: usize, iov: &[Iov], flags: usize) -> isize {
    call(
        nr::VMSPLICE,
        [fd, iov.as_ptr() as usize, iov.len(), flags, 0, 0],
    )
}
fn memfd() -> usize {
    let r = call(nr::MEMFD, [c"pipe-abi".as_ptr() as usize, 0, 0, 0, 0, 0]);
    yes("memfd_create", r >= 0);
    r as usize
}
fn poll(fd: usize, events: i16) -> i16 {
    let mut p = Poll {
        fd: fd as i32,
        events,
        revents: 0,
    };
    let timeout = [0u64; 2];
    let r = call(
        nr::PPOLL,
        [
            &mut p as *mut _ as usize,
            1,
            timeout.as_ptr() as usize,
            0,
            8,
            0,
        ],
    );
    yes("ppoll count", r == 0 || r == 1);
    p.revents
}
fn creation() {
    eq(
        "pipe2 unknown flags before EFAULT",
        call(nr::PIPE2, [FAULT, 1, 0, 0, 0, 0]),
        -22,
    );
    eq("pipe2 EFAULT", call(nr::PIPE2, [FAULT, 0, 0, 0, 0, 0]), -14);
    let p = pipe(NB | CLOEXEC | DIRECT);
    eq("read end status", fcntl(p[0], 3, 0), NB as isize);
    eq(
        "write end status",
        fcntl(p[1], 3, 0),
        (NB | DIRECT | 1) as isize,
    );
    eq("reader CLOEXEC", fcntl(p[0], 1, 0), 1);
    eq("writer CLOEXEC", fcntl(p[1], 1, 0), 1);
    close_pair(p);
    let p = pipe(1usize << 32);
    eq("pipe2 int truncation", fcntl(p[1], 3, 0), 1);
    close_pair(p);
    #[cfg(target_arch = "x86_64")]
    {
        let mut p = [-1i32; 2];
        eq(
            "legacy pipe",
            call(nr::PIPE, [p.as_mut_ptr() as usize, 0, 0, 0, 0, 0]),
            0,
        );
        close_pair([p[0] as usize, p[1] as usize]);
        eq(
            "legacy pipe EFAULT",
            call(nr::PIPE, [FAULT, 0, 0, 0, 0, 0]),
            -14,
        );
    }
}
fn scalar_and_vector() {
    let p = pipe(NB);
    let mut b = [0u8; 8];
    eq("empty live read", read(p[0], &mut b), -11);
    eq("read write-end", read(p[1], &mut b), -9);
    eq("write read-end", write(p[0], b"a"), -9);
    eq(
        "read bad fd zero",
        call(nr::READ, [BAD, FAULT, 0, 0, 0, 0]),
        -9,
    );
    eq(
        "read mode before EFAULT",
        call(nr::READ, [p[1], FAULT, 1, 0, 0, 0]),
        -9,
    );
    eq("write zero", write(p[1], b""), 0);
    eq("read zero", read(p[0], &mut []), 0);
    eq(
        "readv fd before vector",
        call(nr::READV, [BAD, FAULT, 1025, 0, 0, 0]),
        -9,
    );
    eq(
        "readv too many",
        call(nr::READV, [p[0], 0, 1025, 0, 0, 0]),
        -22,
    );
    eq(
        "writev invalid vector",
        call(nr::WRITEV, [p[1], FAULT, 1, 0, 0, 0]),
        -14,
    );
    eq(
        "writev zero vectors",
        call(nr::WRITEV, [p[1], FAULT, 0, 0, 0, 0]),
        0,
    );
    let v = [
        Iov {
            base: b"ab".as_ptr() as usize,
            len: 2,
        },
        Iov {
            base: b"cde".as_ptr() as usize,
            len: 3,
        },
    ];
    eq(
        "writev",
        call(nr::WRITEV, [p[1], v.as_ptr() as usize, 2, 0, 0, 0]),
        5,
    );
    eq("FIONREAD writer", available(p[1]), 5);
    eq(
        "read EFAULT",
        call(nr::READ, [p[0], FAULT, 2, 0, 0, 0]),
        -14,
    );
    eq("EFAULT preserves data", available(p[0]), 5);
    let v = [
        Iov {
            base: b.as_mut_ptr() as usize,
            len: 2,
        },
        Iov {
            base: b[2..].as_mut_ptr() as usize,
            len: 3,
        },
    ];
    eq(
        "readv",
        call(nr::READV, [p[0], v.as_ptr() as usize, 2, 0, 0, 0]),
        5,
    );
    yes("vector bytes", &b[..5] == b"abcde");
    for n in [nr::LSEEK, nr::PREAD, nr::PWRITE] {
        let fd = if n == nr::PWRITE { p[1] } else { p[0] };
        eq(
            "pipe positional ESPIPE",
            call(n, [fd, b.as_mut_ptr() as usize, 1, 0, 0, 0]),
            -29,
        );
    }
    eq(
        "pipe ioctl unknown",
        call(nr::IOCTL, [p[0], 0x12345678, 0, 0, 0, 0]),
        -25,
    );
    eq(
        "FIONREAD EFAULT",
        call(nr::IOCTL, [p[0], 0x541b, FAULT, 0, 0, 0]),
        -14,
    );
    close(p[1]);
    eq("EOF", read(p[0], &mut b), 0);
    close(p[0]);
}
fn capacity_and_lifetime() {
    let p = pipe(NB);
    let cap = fcntl(p[0], 1032, 0);
    yes("capacity positive", cap >= 4096);
    eq("shrink to page", fcntl(p[1], 1031, 1), 4096);
    eq("shared capacity", fcntl(p[0], 1032, 0), 4096);
    eq("size invalid", fcntl(p[1], 1031, BAD), -22);
    let page = [7u8; 4096];
    eq("fill pipe", write(p[1], &page), 4096);
    eq("full EAGAIN", write(p[1], b"x"), -11);
    eq(
        "full writev atomic",
        call(nr::WRITEV, [p[1], 0, 0, 0, 0, 0]),
        0,
    );
    eq("full writer poll", poll(p[1], 4) as isize, 0);
    let dup = call(nr::DUP, [p[1], 0, 0, 0, 0, 0]);
    yes("dup", dup >= 0);
    let dup = dup as usize;
    eq("setfl alias", fcntl(dup, 4, 0), 0);
    eq("getfl shared", fcntl(p[1], 3, 0), 1);
    eq("restore nonblock", fcntl(dup, 4, NB), 0);
    eq("setfd local", fcntl(dup, 2, 1), 0);
    eq("cloexec not shared", fcntl(p[1], 1, 0), 0);
    close(p[1]);
    let mut b = [0u8; 4096];
    eq("read full", read(p[0], &mut b), 4096);
    eq("dup keeps writer alive", read(p[0], &mut b), -11);
    close(dup);
    yes("EOF poll HUP", poll(p[0], 1) & 16 != 0);
    eq("last alias EOF", read(p[0], &mut b), 0);
    close(p[0]);
    let p = pipe(NB);
    eq("dup3 samefd", call(nr::DUP3, [p[0], p[0], 0, 0, 0, 0]), -22);
    close_pair(p);
    let f = memfd();
    eq("nonpipe capacity", fcntl(f, 1032, 0), -9);
    eq("nonpipe resize", fcntl(f, 1031, 4096), -9);
    close(f);
}
fn packets() {
    let p = pipe(NB | DIRECT);
    eq("packet write1", write(p[1], b"abc"), 3);
    eq("packet write2", write(p[1], b"de"), 2);
    let mut b = [0u8; 8192];
    eq("packet truncate", read(p[0], &mut b[..1]), 1);
    eq("packet tail discarded", available(p[0]), 2);
    eq("next packet", read(p[0], &mut b), 2);
    yes("packet bytes", &b[..2] == b"de");
    eq("large packet", write(p[1], &[9u8; 4097]), 4097);
    eq("split at PIPE_BUF", read(p[0], &mut b), 4096);
    eq("packet remainder", read(p[0], &mut b), 1);
    eq("disable packet", fcntl(p[1], 4, NB), 0);
    eq("stream write1", write(p[1], b"ab"), 2);
    eq("stream write2", write(p[1], b"cd"), 2);
    eq("stream coalesces", read(p[0], &mut b), 4);
    close_pair(p);
}
fn transfer_errors() {
    let p = pipe(NB);
    let q = pipe(NB);
    let f = memfd();
    let mut off = 0i64;
    eq(
        "splice zero precedes flags",
        call(nr::SPLICE, [BAD, FAULT, BAD, FAULT, 0, BAD]),
        0,
    );
    eq("splice flags precede fd", splice(BAD, BAD, 1, 0x10), -22);
    eq("tee flags before zero", tee(BAD, BAD, 0, 0x10), -22);
    eq("tee zero ignores fd", tee(BAD, BAD, 0, 0), 0);
    eq("splice bad fd", splice(BAD, q[1], 1, 2), -9);
    eq("tee bad fd", tee(BAD, q[1], 1, 2), -9);
    eq(
        "splice input offset",
        call(nr::SPLICE, [p[0], FAULT, q[1], 0, 1, 2]),
        -29,
    );
    eq(
        "splice output offset",
        call(nr::SPLICE, [p[0], 0, q[1], FAULT, 1, 2]),
        -29,
    );
    eq(
        "splice file offset fault",
        call(nr::SPLICE, [p[0], 0, f, FAULT, 1, 2]),
        -14,
    );
    eq("splice wrong input mode", splice(p[1], q[1], 1, 2), -9);
    eq("tee wrong output mode", tee(p[0], q[0], 1, 2), -9);
    eq("splice same pipe", splice(p[0], p[1], 1, 2), -22);
    eq("tee same pipe", tee(p[0], p[1], 1, 2), -22);
    eq("splice no pipe", splice(f, f, 1, 2), -22);
    eq("tee no pipe", tee(f, q[1], 1, 2), -22);
    eq("empty splice", splice(p[0], q[1], 1, 2), -11);
    eq("empty tee", tee(p[0], q[1], 1, 2), -11);
    eq(
        "splice unsigned flags truncation",
        splice(p[0], q[1], 1, (1usize << 32) | 2),
        -11,
    );
    eq(
        "tee unsigned flags truncation",
        tee(p[0], q[1], 1, (1usize << 32) | 2),
        -11,
    );
    eq(
        "sendfile pipe offset",
        call(
            nr::SENDFILE,
            [q[1], p[0], &mut off as *mut _ as usize, 1, 0, 0],
        ),
        -29,
    );
    eq(
        "copy_file_range pipe",
        call(nr::COPY_FILE_RANGE, [p[0], 0, f, 0, 1, 0]),
        -22,
    );
    close_pair(p);
    close_pair(q);
    close(f);
}
fn transfers() {
    let p = pipe(NB);
    let q = pipe(NB);
    let f = memfd();
    let mut b = [0u8; 16];
    eq("source data", write(p[1], b"abcdef"), 6);
    eq("tee prefix", tee(p[0], q[1], 3, 2), 3);
    eq("tee preserves source", available(p[0]), 6);
    eq("tee output", read(q[0], &mut b), 3);
    yes("tee bytes", &b[..3] == b"abc");
    eq("splice prefix", splice(p[0], q[1], 2, 2), 2);
    eq("splice consumes prefix", available(p[0]), 4);
    eq("splice output", read(q[0], &mut b), 2);
    yes("splice bytes", &b[..2] == b"ab");
    eq("pipe to file", splice(p[0], f, 4, 2), 4);
    eq("file position", call(nr::LSEEK, [f, 0, 1, 0, 0, 0]), 4);
    let mut off = 1i64;
    eq(
        "file explicit to pipe",
        call(nr::SPLICE, [f, &mut off as *mut _ as usize, q[1], 0, 2, 2]),
        2,
    );
    eq("explicit offset advanced", off as isize, 3);
    eq(
        "explicit preserves file pos",
        call(nr::LSEEK, [f, 0, 1, 0, 0, 0]),
        4,
    );
    eq("file splice output", read(q[0], &mut b), 2);
    yes("file splice bytes", &b[..2] == b"de");
    off = 0;
    eq(
        "sendfile to pipe",
        call(
            nr::SENDFILE,
            [q[1], f, &mut off as *mut _ as usize, 4, 0, 0],
        ),
        4,
    );
    eq("sendfile offset", off as isize, 4);
    eq("sendfile output", read(q[0], &mut b), 4);
    yes("sendfile bytes", &b[..4] == b"cdef");
    close(p[1]);
    eq("splice EOF", splice(p[0], q[1], 1, 2), 0);
    eq("tee EOF", tee(p[0], q[1], 1, 2), 0);
    close(p[0]);
    close_pair(q);
    close(f);
    let p = pipe(NB | DIRECT);
    let q = pipe(NB);
    eq("packet source", write(p[1], b"abcdef"), 6);
    eq("short packet tee", tee(p[0], q[1], 2, 2), 2);
    eq("teed packet truncate", read(q[0], &mut b[..1]), 1);
    eq("teed packet flag", available(q[0]), 0);
    eq("short packet splice", splice(p[0], q[1], 2, 2), 2);
    eq("split packet source", available(p[0]), 4);
    eq("spliced packet truncate", read(q[0], &mut b[..1]), 1);
    eq("spliced packet flag", available(q[0]), 0);
    eq("remaining packet", read(p[0], &mut b), 4);
    yes("remaining packet bytes", &b[..4] == b"cdef");
    close_pair(p);
    close_pair(q);
}
fn vmsplice_cases() {
    let p = pipe(NB);
    let f = memfd();
    let mut b = [0u8; 8];
    let v = [Iov {
        base: b"abcd".as_ptr() as usize,
        len: 4,
    }];
    eq(
        "vmsplice flags before fd",
        call(nr::VMSPLICE, [BAD, FAULT, 1, 0x10, 0, 0]),
        -22,
    );
    eq(
        "vmsplice fd before iov",
        call(nr::VMSPLICE, [BAD, FAULT, 1, 0, 0, 0]),
        -9,
    );
    eq(
        "vmsplice too many",
        call(nr::VMSPLICE, [p[1], 0, 1025, 0, 0, 0]),
        -22,
    );
    eq(
        "vmsplice iov fault",
        call(nr::VMSPLICE, [p[1], FAULT, 1, 0, 0, 0]),
        -14,
    );
    eq(
        "vmsplice zero nonpipe",
        call(nr::VMSPLICE, [f, FAULT, 0, 0, 0, 0]),
        0,
    );
    eq("vmsplice nonpipe", vmsplice(f, &v, 2), -9);
    eq(
        "vmsplice negative length",
        vmsplice(
            p[1],
            &[Iov {
                base: FAULT,
                len: BAD,
            }],
            2,
        ),
        -22,
    );
    eq(
        "vmsplice invalid payload",
        vmsplice(
            p[1],
            &[Iov {
                base: FAULT,
                len: 1,
            }],
            2,
        ),
        -14,
    );
    eq("vmsplice in", vmsplice(p[1], &v, 2), 4);
    let dst = [
        Iov {
            base: b.as_mut_ptr() as usize,
            len: 2,
        },
        Iov {
            base: b[2..].as_mut_ptr() as usize,
            len: 2,
        },
    ];
    eq("vmsplice out", vmsplice(p[0], &dst, 2), 4);
    yes("vmsplice bytes", &b[..4] == b"abcd");
    eq("vmsplice empty", vmsplice(p[0], &dst, 2), -11);
    close(p[1]);
    eq("vmsplice EOF", vmsplice(p[0], &dst, 2), 0);
    close(p[0]);
    close(f);
}
fn broken_pipe() {
    let mask = 1u64 << 12;
    eq(
        "block SIGPIPE",
        call(nr::SIGMASK, [0, &mask as *const _ as usize, 0, 8, 0, 0]),
        0,
    );
    let p = pipe(NB);
    let q = pipe(NB);
    close(q[0]);
    let mut pending = 0u64;
    eq(
        "source EAGAIN before broken destination splice",
        splice(p[0], q[1], 1, 2),
        -11,
    );
    eq(
        "source EAGAIN before broken destination tee",
        tee(p[0], q[1], 1, 2),
        -11,
    );
    eq("broken write zero", write(q[1], b""), 0);
    eq("broken write", write(q[1], b"x"), -32);
    eq(
        "SIGPIPE pending query",
        call(
            nr::SIGPENDING,
            [&mut pending as *mut _ as usize, 8, 0, 0, 0, 0],
        ),
        0,
    );
    yes("SIGPIPE delivered", pending & mask != 0);
    eq("broken writer POLLERR", (poll(q[1], 4) & 8) as isize, 8);
    eq("populate source", write(p[1], b"x"), 1);
    eq("splice EPIPE", splice(p[0], q[1], 1, 2), -32);
    eq("tee EPIPE", tee(p[0], q[1], 1, 2), -32);
    eq("broken transfer preserves source", available(p[0]), 1);
    let v = [Iov {
        base: b"x".as_ptr() as usize,
        len: 1,
    }];
    eq("vmsplice EPIPE", vmsplice(q[1], &v, 2), -32);
    close(q[1]);
    close_pair(p);
}
fn fifo() {
    let mut name = [0u8; 80];
    let pid = call(nr::GETPID, [0; 6]);
    struct Buf<'a>(&'a mut [u8], usize);
    impl Write for Buf<'_> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.1 + s.len();
            self.0[self.1..end].copy_from_slice(s.as_bytes());
            self.1 = end;
            Ok(())
        }
    }
    let mut path = Buf(&mut name, 0);
    let _ = write!(path, "/tmp/narf-pipe-abi-{pid}");
    let ptr = name.as_ptr() as usize;
    eq(
        "mknodat FIFO",
        call(nr::MKNODAT, [AT_FDCWD, ptr, 0o10600, 0, 0, 0]),
        0,
    );
    eq(
        "FIFO no reader ENXIO",
        call(nr::OPENAT, [AT_FDCWD, ptr, 1 | NB, 0, 0, 0]),
        -6,
    );
    let r = call(nr::OPENAT, [AT_FDCWD, ptr, NB, 0, 0, 0]);
    yes("FIFO read open", r >= 0);
    let r = r as usize;
    let mut b = [0u8; 4];
    eq("FIFO no writer EOF", read(r, &mut b), 0);
    let w = call(nr::OPENAT, [AT_FDCWD, ptr, 1 | NB, 0, 0, 0]);
    yes("FIFO write open", w >= 0);
    let w = w as usize;
    eq("FIFO empty live EAGAIN", read(r, &mut b), -11);
    eq("FIFO write", write(w, b"fifo"), 4);
    eq("FIFO FIONREAD", available(r), 4);
    eq("FIFO writer FIONREAD", available(w), 4);
    eq(
        "FIFO FIONREAD EFAULT",
        call(nr::IOCTL, [w, 0x541b, FAULT, 0, 0, 0]),
        -14,
    );
    eq("FIFO read", read(r, &mut b), 4);
    yes("FIFO bytes", &b == b"fifo");
    eq("FIFO resize", fcntl(w, 1031, 4096), 4096);
    eq("FIFO shared capacity", fcntl(r, 1032, 0), 4096);
    let p = pipe(NB | DIRECT);
    eq("packet source", write(p[1], b"abcd"), 4);
    eq("tee anonymous to FIFO", tee(p[0], w, 4, 2), 4);
    eq("FIFO tee cannot merge", write(w, b"x"), -11);
    eq("FIFO packet truncation", read(r, &mut b[..2]), 2);
    eq("FIFO packet tail discarded", available(r), 0);
    eq("splice anonymous to FIFO", splice(p[0], w, 4, 2), 4);
    eq("tee FIFO to anonymous", tee(r, p[1], 4, 2), 4);
    eq("anonymous teed packet", read(p[0], &mut b[..2]), 2);
    eq("anonymous packet tail discarded", available(p[0]), 0);
    eq("splice FIFO to anonymous", splice(r, p[1], 4, 2), 4);
    eq("FIFO splice consumed", available(r), 0);
    eq("read transferred packet", read(p[0], &mut b), 4);
    yes("transferred content", &b == b"abcd");
    close_pair(p);
    eq("FIFO enable packet mode", fcntl(w, 4, NB | DIRECT), 0);
    eq("FIFO packet write", write(w, b"fifo"), 4);
    eq("FIFO own packet truncates", read(r, &mut b[..1]), 1);
    eq("FIFO own packet discarded", available(r), 0);
    close(w);
    eq("FIFO final EOF", read(r, &mut b), 0);
    close(r);
    let reopened = call(nr::OPENAT, [AT_FDCWD, ptr, NB | 2, 0, 0, 0]);
    yes("reopen FIFO", reopened >= 0);
    eq(
        "reopened FIFO default capacity",
        fcntl(reopened as usize, 1032, 0),
        65536,
    );
    eq("FIFO abandoned bytes", write(reopened as usize, b"left"), 4);
    close(reopened as usize);
    let reopened = call(nr::OPENAT, [AT_FDCWD, ptr, NB | 2, 0, 0, 0]);
    yes("reopen abandoned FIFO", reopened >= 0);
    eq(
        "last close discards FIFO data",
        available(reopened as usize),
        0,
    );
    close(reopened as usize);
    eq(
        "unlink FIFO",
        call(nr::UNLINKAT, [AT_FDCWD, ptr, 0, 0, 0, 0]),
        0,
    );
}
fn pinned_pages() {
    let mapping = call(nr::MMAP, [0, 8192, 3, 0x22, usize::MAX, 0]);
    yes("vmsplice mmap", mapping > 0);
    let address = mapping as usize;
    // SAFETY: successful anonymous read/write mapping owned by this test.
    unsafe {
        (address as *mut u8).write_volatile(b'a');
        ((address + 4095) as *mut u8).write_volatile(b'b');
        ((address + 4096) as *mut u8).write_volatile(b'c');
    }
    let p = pipe(NB | DIRECT);
    let q = pipe(NB);
    eq("pinned destination size", fcntl(p[1], 1031, 4096), 4096);
    eq(
        "pin one byte",
        vmsplice(
            p[1],
            &[Iov {
                base: address,
                len: 1,
            }],
            2,
        ),
        1,
    );
    eq("pinned page cannot merge", write(p[1], b"x"), -11);
    eq("tee retained user page", tee(p[0], q[1], 1, 2), 1);
    // Without SPLICE_F_GIFT Linux retains the actual user page. A later user
    // store is observable; this distinguishes page references from a copy.
    unsafe {
        (address as *mut u8).write_volatile(b'z');
    }
    let mut b = [0u8; 8];
    eq("read pinned live page", read(p[0], &mut b), 1);
    eq("pinned data reflects source", b[0] as isize, b'z' as isize);
    eq(
        "unaligned pin limited by slots",
        vmsplice(
            p[1],
            &[Iov {
                base: address + 4095,
                len: 2,
            }],
            2,
        ),
        1,
    );
    eq("pin unaligned tail", tee(p[0], q[1], 1, 2), 1);
    close_pair(p);
    eq(
        "unmap retained source",
        call(nr::MUNMAP, [address, 8192, 0, 0, 0, 0]),
        0,
    );
    eq("read after source unmap and close", read(q[0], &mut b), 2);
    yes("retained contents survive", &b[..2] == b"zb");
    close_pair(q);
}

fn page_buffers() {
    let p = pipe(NB);
    let q = pipe(NB);
    eq("one source slot", fcntl(p[1], 1031, 4096), 4096);
    eq("one destination slot", fcntl(q[1], 1031, 4096), 4096);
    eq("seed mergeable page", write(p[1], b"abc"), 3);
    eq("share prefix", tee(p[0], q[1], 2, 2), 2);
    eq("tee clears destination merge flag", write(q[1], b"z"), -11);
    eq("source still mergeable", write(p[1], b"d"), 1);
    let mut b = [0u8; 4096];
    eq("shared prefix size", read(q[0], &mut b), 2);
    yes("shared prefix immutable", &b[..2] == b"ab");
    eq("split buffer", splice(p[0], q[1], 2, 2), 2);
    eq("split source still mergeable", write(p[1], b"e"), 1);
    eq("split destination not mergeable", write(q[1], b"z"), -11);
    eq("split destination bytes", read(q[0], &mut b), 2);
    yes("split content", &b[..2] == b"ab");
    eq("source retained suffix", read(p[0], &mut b), 3);
    yes("suffix content", &b[..3] == b"cde");
    eq("fill page", write(p[1], &b), 4096);
    eq("consume prefix", read(p[0], &mut b[..1]), 1);
    eq(
        "occupied page cannot reuse headroom",
        write(p[1], b"x"),
        -11,
    );
    eq("drain remainder", read(p[0], &mut b), 4095);
    eq("slot recycled", write(p[1], b"x"), 1);
    eq("move complete mergeable page", splice(p[0], q[1], 1, 2), 1);
    eq("whole move retains merge flag", write(q[1], b"y"), 1);
    eq("whole move content length", read(q[0], &mut b), 2);
    yes("whole move content", &b[..2] == b"xy");
    for fd in [p[0], p[1], q[0], q[1]] {
        close(fd);
    }
}

fn file_pages_and_faults() {
    let mut name = [0u8; 80];
    let prefix = b"/tmp/narf-pipe-file-";
    name[..prefix.len()].copy_from_slice(prefix);
    let mut pid = call(nr::GETPID, [0; 6]) as usize;
    let mut end = prefix.len();
    while pid != 0 {
        name[end] = b'0' + (pid % 10) as u8;
        end += 1;
        pid /= 10;
    }
    for named in [false, true] {
        let file = if named {
            let f = call(
                nr::OPENAT,
                [
                    AT_FDCWD,
                    name.as_ptr() as usize,
                    2 | 0x40 | 0x80,
                    0o600,
                    0,
                    0,
                ],
            );
            yes("create splice file", f >= 0);
            f as usize
        } else {
            memfd()
        };
        eq("file page contents", write(file, b"abcd"), 4);
        eq(
            "rewind splice file",
            call(nr::LSEEK, [file, 0, 0, 0, 0, 0]),
            0,
        );
        let p = pipe(NB);
        let q = pipe(NB);
        eq("file page capacity", fcntl(p[1], 1031, 4096), 4096);
        eq("splice retained file page", splice(file, p[1], 4, 2), 4);
        eq("file page is nonmergeable", write(p[1], b"x"), -11);
        eq("tee retained file page", tee(p[0], q[1], 4, 2), 4);
        eq(
            "modify retained file page",
            call(nr::PWRITE, [file, b"Z".as_ptr() as usize, 1, 1, 0, 0]),
            1,
        );
        close(file);
        if named {
            eq(
                "unlink retained file",
                call(nr::UNLINKAT, [AT_FDCWD, name.as_ptr() as usize, 0, 0, 0, 0]),
                0,
            );
        }
        for fd in [p[0], q[0]] {
            let mut bytes = [0; 4];
            eq("read retained file page", read(fd, &mut bytes), 4);
            yes("file page sharing survives close", &bytes == b"aZcd");
        }
        close_pair(p);
        close_pair(q);
    }
    let address = call(nr::MMAP, [0, 8192, 3, 0x22, BAD, 0]);
    yes("fault-prefix mmap", address > 0);
    let address = address as usize;
    eq(
        "create low canonical hole",
        call(nr::MUNMAP, [address + 4096, 4096, 0, 0, 0, 0]),
        0,
    );
    let p = pipe(NB);
    let vector = [
        Iov {
            base: address,
            len: 4096,
        },
        Iov {
            base: address + 4096,
            len: 4096,
        },
    ];
    eq(
        "writev commits page before EFAULT",
        call(nr::WRITEV, [p[1], vector.as_ptr() as usize, 2, 0, 0, 0]),
        4096,
    );
    eq("writev fault occupancy", available(p[0]), 4096);
    let mut page = [0u8; 4096];
    eq("drain writev prefix", read(p[0], &mut page), 4096);
    eq("fill readv fault pages", write(p[1], &[b'v'; 8192]), 8192);
    eq(
        "readv commits page before EFAULT",
        call(nr::READV, [p[0], vector.as_ptr() as usize, 2, 0, 0, 0]),
        4096,
    );
    eq("readv fault keeps second page", available(p[0]), 4096);
    let short = [
        Iov {
            base: address,
            len: 1024,
        },
        Iov {
            base: address + 4096,
            len: 1024,
        },
    ];
    eq(
        "same-page vector fault is transactional",
        call(nr::READV, [p[0], short.as_ptr() as usize, 2, 0, 0, 0]),
        -14,
    );
    eq("same-page fault keeps buffer", available(p[0]), 4096);
    close_pair(p);
    eq(
        "unmap fault prefix",
        call(nr::MUNMAP, [address, 4096, 0, 0, 0, 0]),
        0,
    );
}

fn pin_fork_and_shared() {
    let address = call(nr::MMAP, [0, 4096, 3, 0x22, BAD, 0]);
    yes("fork pin mmap", address > 0);
    let address = address as usize;
    // SAFETY: private writable mapping owned by this process.
    unsafe {
        (address as *mut u8).write_volatile(b'a');
    }
    let p = pipe(NB);
    eq(
        "pin before fork",
        vmsplice(
            p[1],
            &[Iov {
                base: address,
                len: 1,
            }],
            2,
        ),
        1,
    );
    let child = call(nr::CLONE, [17, 0, 0, 0, 0, 0]);
    yes("fork pinned page", child >= 0);
    if child == 0 {
        // SAFETY: fork inherited a private writable mapping.
        unsafe {
            (address as *mut u8).write_volatile(b'b');
        }
        exit(0);
    }
    let mut status = -1i32;
    eq(
        "wait pinned child",
        call(
            nr::WAIT4,
            [child as usize, &mut status as *mut _ as usize, 0, 0, 0, 0],
        ),
        child,
    );
    eq("pinned child status", status as isize, 0);
    // SAFETY: the parent still owns this private mapping.
    unsafe {
        eq(
            "child write isolated from parent",
            (address as *const u8).read_volatile() as isize,
            b'a' as isize,
        );
        (address as *mut u8).write_volatile(b'c');
    }
    let mut byte = [0];
    eq("read pin after fork", read(p[0], &mut byte), 1);
    eq("pin retains pre-COW page", byte[0] as isize, b'a' as isize);
    eq(
        "unmap fork pin",
        call(nr::MUNMAP, [address, 4096, 0, 0, 0, 0]),
        0,
    );
    close_pair(p);

    let file = memfd();
    eq("size shared pin file", write(file, &[b's'; 4096]), 4096);
    let address = call(nr::MMAP, [0, 4096, 3, 1, file, 0]);
    yes("shared pin mmap", address > 0);
    let p = pipe(NB);
    eq(
        "pin shared file",
        vmsplice(
            p[1],
            &[Iov {
                base: address as usize,
                len: 1,
            }],
            2,
        ),
        1,
    );
    close(file);
    eq(
        "unmap shared pin",
        call(nr::MUNMAP, [address as usize, 4096, 0, 0, 0, 0]),
        0,
    );
    eq("read retained shared file", read(p[0], &mut byte), 1);
    eq("shared pin content", byte[0] as isize, b's' as isize);
    close_pair(p);
}

fn blocking() {
    let p = pipe(0);
    let child = call(nr::CLONE, [17, 0, 0, 0, 0, 0]);
    if child < 0 {
        eq("fork via clone errno", child, 0);
    }
    if child == 0 {
        close(p[0]);
        eq("child write", write(p[1], b"child"), 5);
        exit(0);
    }
    close(p[1]);
    let mut b = [0u8; 8];
    eq("blocking read", read(p[0], &mut b), 5);
    yes("blocking bytes", &b[..5] == b"child");
    eq("exit closes writer EOF", read(p[0], &mut b), 0);
    close(p[0]);
    let mut status = -1i32;
    eq(
        "wait child",
        call(
            nr::WAIT4,
            [child as usize, &mut status as *mut _ as usize, 0, 0, 0, 0],
        ),
        child,
    );
    eq("child status", status as isize, 0);
}

fn blocking_writers() {
    for vectored in [false, true] {
        let p = pipe(0);
        eq("blocking writer capacity", fcntl(p[1], 1031, 4096), 4096);
        let child = call(nr::CLONE, [17, 0, 0, 0, 0, 0]);
        yes("fork blocking writer", child >= 0);
        if child == 0 {
            close(p[0]);
            let bytes = [b'w'; 8192];
            let result = if vectored {
                let v = [
                    Iov {
                        base: bytes.as_ptr() as usize,
                        len: 3000,
                    },
                    Iov {
                        base: bytes[3000..].as_ptr() as usize,
                        len: 5192,
                    },
                ];
                call(nr::WRITEV, [p[1], v.as_ptr() as usize, 2, 0, 0, 0])
            } else {
                write(p[1], &bytes)
            };
            eq("blocking large write completes", result, 8192);
            exit(0);
        }
        close(p[1]);
        let mut bytes = [0; 4096];
        let mut total = 0;
        loop {
            let n = read(p[0], &mut bytes);
            yes("blocking writer read", n >= 0);
            if n == 0 {
                break;
            }
            yes(
                "blocking writer content",
                bytes[..n as usize].iter().all(|b| *b == b'w'),
            );
            total += n;
        }
        eq("blocking writer total", total, 8192);
        close(p[0]);
        let mut status = -1i32;
        eq(
            "wait blocking writer",
            call(
                nr::WAIT4,
                [child as usize, &mut status as *mut _ as usize, 0, 0, 0, 0],
            ),
            child,
        );
        eq("blocking writer exit", status as isize, 0);
    }
}

fn reader_wake_chain() {
    let data = pipe(0);
    let ready = pipe(0);
    let done = pipe(0);
    let mut children = [0isize; 3];
    for child in &mut children {
        *child = call(nr::CLONE, [17, 0, 0, 0, 0, 0]);
        yes("fork waiting readers", *child >= 0);
        if *child == 0 {
            close(data[1]);
            close(ready[0]);
            close(done[0]);
            eq("reader ready", write(ready[1], b"r"), 1);
            let mut byte = [0];
            eq("reader wakes for byte", read(data[0], &mut byte), 1);
            eq("reader wake content", byte[0] as isize, b'x' as isize);
            eq("reader done", write(done[1], b"d"), 1);
            exit(0);
        }
    }
    close(ready[1]);
    close(done[1]);
    let mut bytes = [0; 3];
    let mut total = 0;
    while total < 3 {
        let n = read(ready[0], &mut bytes[total..]);
        yes("collect ready readers", n > 0);
        total += n as usize;
    }
    eq("wake one reader then relay", write(data[1], b"xxx"), 3);
    total = 0;
    while total < 3 {
        let n = read(done[0], &mut bytes[total..]);
        yes("all readers finish without writer close", n > 0);
        total += n as usize;
    }
    close_pair(data);
    close(ready[0]);
    close(done[0]);
    for child in children {
        let mut status = -1i32;
        eq(
            "wait reader",
            call(
                nr::WAIT4,
                [child as usize, &mut status as *mut _ as usize, 0, 0, 0, 0],
            ),
            child,
        );
        eq("reader exit", status as isize, 0);
    }
}

fn writer_wake_chain() {
    let data = pipe(0);
    eq("writer relay capacity", fcntl(data[1], 1031, 16384), 16384);
    eq("fill writer relay pipe", write(data[1], &[0; 16384]), 16384);
    let ready = pipe(0);
    let done = pipe(0);
    let mut children = [0isize; 3];
    for child in &mut children {
        *child = call(nr::CLONE, [17, 0, 0, 0, 0, 0]);
        yes("fork waiting writers", *child >= 0);
        if *child == 0 {
            close(data[0]);
            close(ready[0]);
            close(done[0]);
            eq("writer ready", write(ready[1], b"r"), 1);
            eq("writer wakes for slot", write(data[1], b"x"), 1);
            eq("writer done", write(done[1], b"d"), 1);
            exit(0);
        }
    }
    close(ready[1]);
    close(done[1]);
    let mut bytes = [0; 3];
    let mut total = 0;
    while total < 3 {
        let n = read(ready[0], &mut bytes[total..]);
        yes("collect ready writers", n > 0);
        total += n as usize;
    }
    eq(
        "wake one writer then relay",
        read(data[0], &mut [0; 16384]),
        16384,
    );
    total = 0;
    while total < 3 {
        let n = read(done[0], &mut bytes[total..]);
        yes("all writers finish without reader close", n > 0);
        total += n as usize;
    }
    eq("all relayed writer bytes", read(data[0], &mut bytes), 3);
    yes("writer relay content", bytes == *b"xxx");
    close_pair(data);
    close(ready[0]);
    close(done[0]);
    for child in children {
        let mut status = -1i32;
        eq(
            "wait writer",
            call(
                nr::WAIT4,
                [child as usize, &mut status as *mut _ as usize, 0, 0, 0, 0],
            ),
            child,
        );
        eq("writer exit", status as isize, 0);
    }
}

static SIGNAL_SEEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static SIGNAL_ACK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
unsafe extern "C" {
    static narf_pipe_signal_svc: u8;
}
extern "C" fn catch_signal(_: i32, _: *const u8, context: *const u8) {
    #[cfg(target_arch = "x86_64")]
    let (pc_offset, instruction_len) = (168, 2);
    #[cfg(target_arch = "aarch64")]
    let (pc_offset, instruction_len) = (440, 4);
    // SAFETY: SA_SIGINFO supplies the architecture's Linux ucontext. The
    // symbol is the SVC/syscall instruction in signal_io below.
    let (pc, svc) = unsafe {
        (
            context.add(pc_offset).cast::<usize>().read_unaligned(),
            core::ptr::addr_of!(narf_pipe_signal_svc) as usize,
        )
    };
    if pc == svc || pc == svc + instruction_len {
        SIGNAL_SEEN.store(true, core::sync::atomic::Ordering::SeqCst);
        let _ = write(SIGNAL_ACK.load(core::sync::atomic::Ordering::SeqCst), b"s");
    }
    // Deliberately clobber a caller-saved vector register. sigreturn must
    // restore the interrupted read's value, on EINTR and restart alike.
    #[cfg(target_arch = "x86_64")]
    // SAFETY: modifies only the declared caller-saved vector register.
    unsafe {
        core::arch::asm!("pxor xmm0, xmm0", out("xmm0") _, options(nostack));
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: modifies only the declared caller-saved vector register.
    unsafe {
        core::arch::asm!("movi v0.16b, #0", out("v0") _, options(nostack));
    }
}
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn signal_return() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn signal_return() {
    core::arch::naked_asm!("mov x8, #139", "svc #0");
}
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn signal_io(_: usize, _: *mut u8, _: usize, _: *mut u8, _: usize) -> isize {
    core::arch::naked_asm!(
        "mov rax, r8",
        "mov r8, rcx",
        "pcmpeqb xmm0, xmm0",
        ".global narf_pipe_signal_svc",
        "narf_pipe_signal_svc:",
        "syscall",
        "movdqu [r8], xmm0",
        "ret"
    );
}
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn signal_io(_: usize, _: *mut u8, _: usize, _: *mut u8, _: usize) -> isize {
    core::arch::naked_asm!(
        "movi v0.16b, #255",
        "mov x8, x4",
        ".global narf_pipe_signal_svc",
        "narf_pipe_signal_svc:",
        "svc #0",
        "str q0, [x3]",
        "ret"
    );
}

fn signals_and_restart() {
    #[cfg(target_arch = "x86_64")]
    const SIGNAL_CALLS: (usize, usize, usize, usize) = (13, 62, 24, 228);
    #[cfg(target_arch = "aarch64")]
    const SIGNAL_CALLS: (usize, usize, usize, usize) = (134, 129, 124, 113);
    let (sigaction, kill, sched_yield, clock_gettime) = SIGNAL_CALLS;
    let now = || {
        let mut ts = [0u64; 2];
        eq(
            "signal test monotonic clock",
            call(clock_gettime, [1, ts.as_mut_ptr() as usize, 0, 0, 0, 0]),
            0,
        );
        ts[0] * 1_000_000_000 + ts[1]
    };
    let parent = call(nr::GETPID, [0; 6]);
    for (writing, restart, prefilled) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
        (true, true, true),
    ] {
        let _ = writeln!(
            Output,
            "pipe-abi signal case writing={writing} restart={restart} prefilled={prefilled}"
        );
        SIGNAL_SEEN.store(false, core::sync::atomic::Ordering::SeqCst);
        let action = [
            catch_signal as *const () as usize,
            0x04000004 | if restart { 0x10000000 } else { 0 },
            signal_return as *const () as usize,
            0,
        ];
        eq(
            "install pipe signal action",
            call(sigaction, [10, action.as_ptr() as usize, 0, 8, 0, 0]),
            0,
        );
        let p = pipe(0);
        if writing {
            eq("partial write capacity", fcntl(p[1], 1031, 4096), 4096);
        }
        if prefilled {
            eq(
                "fill before interrupted write",
                write(p[1], &[b'f'; 4096]),
                4096,
            );
        }
        let ack = pipe(NB);
        let start = pipe(0);
        SIGNAL_ACK.store(ack[1], core::sync::atomic::Ordering::SeqCst);
        let child = call(nr::CLONE, [17, 0, 0, 0, 0, 0]);
        yes("fork pipe signaller", child >= 0);
        if child == 0 {
            close(p[usize::from(writing)]);
            close(ack[1]);
            close(start[1]);
            let mut go = [0];
            eq("wait for signal target setup", read(start[0], &mut go), 1);
            close(start[0]);
            let mut observed = false;
            // A retry count depends on CPU placement and can expire before
            // the other process is scheduled. Bound elapsed time instead.
            let deadline = now().saturating_add(5_000_000_000);
            while now() < deadline {
                let mut byte = [0];
                let n = read(ack[0], &mut byte);
                if n == 1 {
                    observed = true;
                    break;
                }
                eq("signal acknowledgment pending", n, -11);
                eq("signal yield", call(sched_yield, [0; 6]), 0);
                eq(
                    "interrupt pipe I/O",
                    call(kill, [parent as usize, 10, 0, 0, 0, 0]),
                    0,
                );
            }
            yes("handler acknowledged interrupted pipe I/O", observed);
            if prefilled {
                let mut fill = [0; 4096];
                eq("release interrupted writer", read(p[0], &mut fill), 4096);
                yes("prefill content", fill == [b'f'; 4096]);
            }
            if restart && !writing {
                eq("restart payload", write(p[1], b"r"), 1);
            }
            exit(0);
        }
        if !writing {
            close(p[1]);
        }
        close(ack[0]);
        close(start[0]);
        let mut byte = [b'w'; 8192];
        let mut fp = [0u8; 16];
        eq("signal target ready", write(start[1], b"g"), 1);
        // SAFETY: the wrapper follows the C ABI and receives live buffers.
        let result = unsafe {
            signal_io(
                p[usize::from(writing)],
                byte.as_mut_ptr(),
                if writing && !prefilled { 8192 } else { 1 },
                fp.as_mut_ptr(),
                if writing { nr::WRITE } else { nr::READ },
            )
        };
        close(start[1]);
        eq(
            "pipe EINTR or SA_RESTART",
            result,
            if writing && !prefilled {
                4096
            } else if restart {
                1
            } else {
                -4
            },
        );
        yes(
            "pipe signal delivered during I/O",
            SIGNAL_SEEN.load(core::sync::atomic::Ordering::SeqCst),
        );
        yes("signal restores vector registers", fp == [255; 16]);
        if writing && !prefilled {
            eq(
                "interrupted write prefix queued once",
                available(p[0]),
                4096,
            );
            let mut prefix = [0; 4096];
            eq(
                "interrupted write prefix readable",
                read(p[0], &mut prefix),
                4096,
            );
            yes("interrupted write prefix content", prefix == [b'w'; 4096]);
            close(p[1]);
        } else if !writing && restart {
            eq("restarted read data", byte[0] as isize, b'r' as isize);
        }
        let mut status = -1i32;
        loop {
            let waited = call(
                nr::WAIT4,
                [child as usize, &mut status as *mut _ as usize, 0, 0, 0, 0],
            );
            if waited == -4 {
                continue;
            }
            eq("wait pipe signaller", waited, child);
            break;
        }
        eq("pipe signaller exit", status as isize, 0);
        if prefilled {
            eq(
                "zero-progress write queued once",
                available(p[0]),
                if restart { 1 } else { 0 },
            );
            if restart {
                let mut written = [0];
                eq("restarted write readable", read(p[0], &mut written), 1);
                yes("restarted write content", written == [b'w']);
            }
            close(p[1]);
        }
        close(p[0]);
        close(ack[1]);
    }
    let action = [0usize; 4];
    eq(
        "reset pipe signal action",
        call(sigaction, [10, action.as_ptr() as usize, 0, 8, 0, 0]),
        0,
    );
}
fn full_and_atomic() {
    let p = pipe(NB);
    let q = pipe(NB);
    let mut b = [0u8; 4096];
    eq("small destination", fcntl(q[1], 1031, 4096), 4096);
    eq("fill destination", write(q[1], &b), 4096);
    eq("source byte", write(p[1], b"x"), 1);
    eq("full splice", splice(p[0], q[1], 1, 2), -11);
    eq("full tee", tee(p[0], q[1], 1, 2), -11);
    eq("blocked move preserves source", available(p[0]), 1);
    let v = [Iov {
        base: b.as_ptr() as usize,
        len: 1,
    }];
    eq("full vmsplice", vmsplice(q[1], &v, 2), -11);
    eq(
        "vmsplice EFAULT before fullness",
        vmsplice(
            q[1],
            &[Iov {
                base: FAULT,
                len: 1,
            }],
            2,
        ),
        -14,
    );
    eq("full zero write", write(q[1], b""), 0);
    eq("drain destination", read(q[0], &mut b), 4096);
    eq("almost full", write(q[1], &b[..4095]), 4095);
    eq("small write atomic", write(q[1], b"xy"), -11);
    let v = [
        Iov {
            base: b"x".as_ptr() as usize,
            len: 1,
        },
        Iov {
            base: b"y".as_ptr() as usize,
            len: 1,
        },
    ];
    eq(
        "small writev atomic",
        call(nr::WRITEV, [q[1], v.as_ptr() as usize, 2, 0, 0, 0]),
        -11,
    );
    eq("atomic failure kept occupancy", available(q[0]), 4095);
    eq("drain almost full", read(q[0], &mut b), 4095);
    eq("large write partial", write(q[1], &[0u8; 4097]), 4096);
    close_pair(p);
    close_pair(q);
    let p = pipe(NB | DIRECT);
    eq("one packet slot", fcntl(p[1], 1031, 4096), 4096);
    eq("one-byte packet", write(p[1], b"a"), 1);
    eq("packet slots full", write(p[1], b"b"), -11);
    eq("packet full readiness", (poll(p[1], 4) & 4) as isize, 0);
    close_pair(p);
}
fn descriptor_exhaustion() {
    #[cfg(target_arch = "x86_64")]
    const PRLIMIT: usize = 302;
    #[cfg(target_arch = "aarch64")]
    const PRLIMIT: usize = 261;
    let mut old = [0u64; 2];
    eq(
        "get nofile",
        call(PRLIMIT, [0, 7, 0, old.as_mut_ptr() as usize, 0, 0]),
        0,
    );
    let limited = [16u64, old[1]];
    eq(
        "limit nofile",
        call(PRLIMIT, [0, 7, limited.as_ptr() as usize, 0, 0, 0]),
        0,
    );
    let mut held = [-1i32; 16];
    let mut used = 0;
    loop {
        let mut pair = [-77i32; 2];
        let r = call(nr::PIPE2, [pair.as_mut_ptr() as usize, NB, 0, 0, 0, 0]);
        if r < 0 {
            eq("pipe EMFILE", r, -24);
            yes("EMFILE leaves output unchanged", pair == [-77; 2]);
            break;
        }
        yes("fd limit enforced", used + 2 <= held.len());
        held[used..used + 2].copy_from_slice(&pair);
        used += 2;
    }
    // One free descriptor is insufficient for pipe: neither half may leak.
    eq(
        "EMFILE before output EFAULT",
        call(nr::PIPE2, [FAULT, 0, 0, 0, 0, 0]),
        -24,
    );
    for fd in &held[..used] {
        close(*fd as usize);
    }
    eq(
        "restore nofile",
        call(PRLIMIT, [0, 7, old.as_ptr() as usize, 0, 0, 0]),
        0,
    );
    let p = pipe(0);
    close_pair(p);
}
fn readiness() {
    #[cfg(target_arch = "x86_64")]
    const EPOLL_CREATE: usize = 291;
    #[cfg(target_arch = "aarch64")]
    const EPOLL_CREATE: usize = 20;
    #[cfg(target_arch = "x86_64")]
    const EPOLL_CTL: usize = 233;
    #[cfg(target_arch = "aarch64")]
    const EPOLL_CTL: usize = 21;
    #[cfg(target_arch = "x86_64")]
    const EPOLL_WAIT: usize = 281;
    #[cfg(target_arch = "aarch64")]
    const EPOLL_WAIT: usize = 22;
    #[cfg_attr(target_arch = "x86_64", repr(C, packed))]
    #[cfg_attr(target_arch = "aarch64", repr(C))]
    struct Event {
        events: u32,
        data: u64,
    }
    let p = pipe(NB);
    let ep = call(EPOLL_CREATE, [CLOEXEC, 0, 0, 0, 0, 0]);
    yes("epoll_create1", ep >= 0);
    let ep = ep as usize;
    let event = Event {
        events: 1,
        data: 123,
    };
    eq(
        "epoll add reader",
        call(EPOLL_CTL, [ep, 1, p[0], &event as *const _ as usize, 0, 0]),
        0,
    );
    let mut out = Event { events: 0, data: 0 };
    let ptr = &mut out as *mut _ as usize;
    eq(
        "epoll initially empty",
        call(EPOLL_WAIT, [ep, ptr, 1, 0, 0, 8]),
        0,
    );
    eq("epoll wake data", write(p[1], b"x"), 1);
    eq("epoll readable", call(EPOLL_WAIT, [ep, ptr, 1, 0, 0, 8]), 1);
    yes("epoll data token", out.data == 123 && out.events & 1 != 0);
    close(p[1]);
    eq(
        "epoll readable hangup",
        call(EPOLL_WAIT, [ep, ptr, 1, 0, 0, 8]),
        1,
    );
    yes("epoll IN plus HUP", out.events & 17 == 17);
    let mut b = [0u8; 1];
    eq("epoll drain", read(p[0], &mut b), 1);
    eq(
        "epoll EOF remains",
        call(EPOLL_WAIT, [ep, ptr, 1, 0, 0, 8]),
        1,
    );
    yes("epoll only HUP", out.events & 17 == 16);
    eq("epoll remove", call(EPOLL_CTL, [ep, 2, p[0], 0, 0, 0]), 0);
    close(p[0]);
    close(ep);
}
fn run() {
    for (name, test) in [
        ("creation", creation as fn()),
        ("scalar/vector", scalar_and_vector),
        ("capacity/lifetime", capacity_and_lifetime),
        ("packet", packets),
        ("full/atomic", full_and_atomic),
        ("page buffers", page_buffers),
        ("file pages/faults", file_pages_and_faults),
        ("pinned pages", pinned_pages),
        ("readiness", readiness),
        ("transfer errors", transfer_errors),
        ("transfers", transfers),
        ("vmsplice", vmsplice_cases),
        ("SIGPIPE", broken_pipe),
        ("FIFO", fifo),
        ("blocking/exit", blocking),
        ("blocking writers", blocking_writers),
        ("reader wake chain", reader_wake_chain),
        ("writer wake chain", writer_wake_chain),
        ("signals/restart", signals_and_restart),
        ("pin fork/shared", pin_fork_and_shared),
        ("descriptor exhaustion", descriptor_exhaustion),
    ] {
        let _ = writeln!(Output, "pipe-abi RUN {name}");
        test();
        let _ = writeln!(Output, "pipe-abi OK {name}");
    }
    let _ = writeln!(Output, "pipe-abi: all passed");
    #[cfg(target_os = "none")]
    // SAFETY: the kernel harness supplies a writable result page at this VA.
    unsafe {
        (0x0000_5001_0000_0000usize as *mut u64).write_volatile(0x5049_5045_5041_5353);
    }
}
#[cfg(target_os = "linux")]
fn main() {
    run();
}
/// # Safety
/// Entered by the ELF loader with a mapped writable userspace stack.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("and rsp, -16","call {entry}",entry=sym start);
}
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    start()
}
#[cfg(target_os = "none")]
fn start() -> ! {
    run();
    exit(0)
}
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    let _ = writeln!(Output, "pipe-abi: panic");
    exit(2)
}
#[cfg(target_os = "none")]
#[no_mangle]
unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(src.add(i).read_volatile());
        }
    }
    dst
}
#[cfg(target_os = "none")]
#[no_mangle]
unsafe extern "C" fn memset(dst: *mut u8, value: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(value as u8);
        }
    }
    dst
}
