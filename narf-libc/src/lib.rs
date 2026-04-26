//! narf-libc — relibc-shaped libc shim for NARF user binaries.
//!
//! Path B of the relibc rollout: an in-tree, `no_std`, no-alloc-by-
//! default crate that supplies a user binary the relibc startup
//! contract (`_start` -> `__libc_start_main` -> user `main`) plus a
//! minimum libc surface (write/printf-shim, exit, getpid, malloc-on-
//! brk, errno-via-TLS, mem/str helpers) needed to validate the
//! Stage-4 user-mode toolchain end-to-end.
//!
//! Every libc-style entry delegates into [`narf_user_runtime`] for
//! the actual syscall — this crate adds the C-ABI startup glue and
//! a printf-shim parser, nothing more. A real C-variadic `printf`
//! requires `core::ffi::VaList` (still unstable as of 1.85), so we
//! ship a tagged-union [`Arg`] + [`printf_str`] pair instead. That
//! is the practical Path-B shape; full POSIX printf is a follow-up.
//!
//! Layout assumptions:
//! - x86_64 SysV: `_start` reads `[rsp]`, builds argc/argv/envp/
//!   auxv off the entry-rsp, then tail-calls user `main`.
//! - TLS: initial-exec model. The kernel programs `IA32_FS_BASE` to
//!   the per-thread TCB self-pointer; `*(fs:0) == fs_base`. The TLS
//!   template lives at `fs_base - mem_size`. errno occupies the
//!   last 8 bytes of the template.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern "C" {
    /// User-supplied entry point. Linked against the consumer
    /// binary; signature mirrors C `int main(int, char**, char**)`.
    fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32;
}

pub mod arch;
pub mod assert;
pub mod ctype;
pub mod env;
pub mod errno;
pub mod fd;
pub mod fs;
pub mod getopt;
pub mod heap;
pub mod io;
pub mod math;
pub mod posix;
pub mod process;
pub mod setjmp;
pub mod signal;
pub mod startup;
pub mod stdio;
pub mod stdlib;
pub mod string;
pub mod time;

pub use arch::_start;
pub use assert::__assert_fail;
pub use ctype::{
    isalnum, isalpha, isascii, iscntrl, isdigit, isgraph, islower, isprint,
    ispunct, isspace, isupper, isxdigit, tolower, toupper,
};
pub use env::{getenv, getenv_cstr, putenv, setenv, unsetenv, ENVIRON};
pub use errno::{errno, set_errno, strerror, __errno_location};
pub use fd::{
    dup, dup2, fcntl, fstat, isatty, pipe, stat, FD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD,
    F_SETFL, StatBuf,
};
pub use fs::{chdir, getcwd};
pub use getopt::{getopt, optarg, opterr, optind, optopt};
pub use heap::{calloc, free, malloc, realloc};
// `io::fputs(&str, fd)` deliberately omitted — the `stdio::fputs`
// FILE*-shaped one (re-exported below) is the canonical public
// surface. The internal helper is still reachable as
// `crate::io::fputs` for non-public call sites that haven't migrated.
pub use io::{
    fprintf_str, printf_str, snprintf_str, sprintf_str, vprintf_str, vsnprintf_str,
    write, Arg, Stdout,
};
pub use math::{
    ceil, ceilf, copysign, copysignf, fabs, fabsf, floor, floorf,
    fmax, fmaxf, fmin, fminf, fmod, fmodf, isfinite, isinf, isnan,
    round, roundf, signbit, sqrt, sqrtf, trunc, truncf,
};
pub use posix::{
    close as posix_close, lseek as posix_lseek, mkdir as posix_mkdir,
    open as posix_open, read as posix_read, rename as posix_rename,
    rmdir as posix_rmdir, unlink as posix_unlink, write as posix_write,
    O_APPEND, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
    SEEK_CUR, SEEK_END, SEEK_SET,
};
pub use process::{abort, atexit, exit, _exit, getpid, getppid, getuid, sleep, usleep};
pub use setjmp::{jmp_buf, longjmp, setjmp, JMP_BUF_LEN};
pub use signal::{
    kill, raise, signal, sighandler_t,
    SIG_DFL_RAW, SIG_IGN_RAW, SIGABRT, SIGALRM, SIGCHLD, SIGFPE, SIGHUP, SIGILL,
    SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSEGV, SIGTERM,
};
pub use stdlib::{
    abs, atoi, atol, bsearch, div, div_t, labs, ldiv, ldiv_t, qsort, rand, srand,
    sscanf_ints, strtol, strtoul, RAND_MAX,
};
pub use time::{
    asctime, clock_gettime, ctime, difftime, gettimeofday, gmtime, gmtime_r,
    localtime, localtime_r, mktime, strftime, time, timespec, timeval, tm,
};
pub use startup::__libc_start_main;
// Note: `stdio::fputs` shadows the older `io::fputs(&str, fd)` helper
// — the FILE*-shaped one is the POSIX-correct surface and is the one
// downstream callers should use. The old `io::fputs` remains
// accessible as `crate::io::fputs` for any internal call-sites that
// haven't migrated yet.
pub use stdio::{
    clearerr, fclose, feof, ferror, fflush, fgetc, fgets, fopen, fputc, fputs, fread,
    fseek, ftell, fwrite, getc, getchar, perror, putc, putchar, puts, rewind, stderr,
    stdin, stdout, File,
};
pub use string::{
    memchr, memcmp, memcpy, memmove, memset, strcat, strchr, strcmp, strcpy, strcspn,
    strdup, strlen, strncmp, strncpy, strpbrk, strrchr, strspn, strstr, strtok_r,
};
