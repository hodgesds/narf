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

pub mod account;
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
pub mod locale;
pub mod math;
pub mod net;
pub mod numeric;
pub mod path;
pub mod poll;
pub mod posix;
pub mod pthread;
pub mod random;
pub mod regex;
pub mod search;
pub mod sys;
pub mod sysvipc;
pub mod term;
pub mod process;
pub mod setjmp;
pub mod signal;
pub mod socket_extra;
pub mod startup;
pub mod stdio;
pub mod stdlib;
pub mod string;
pub mod time;

pub use account::{
    endgrent, endpwent, getgrent, getgrgid, getgrnam, getgrouplist, getpwent, getpwnam,
    getpwuid, gid_t, group, passwd, setgrent, setpwent, uid_t,
};
pub use arch::_start;
pub use assert::__assert_fail;
pub use ctype::{
    isalnum, isalpha, isascii, isblank, iscntrl, isdigit, isgraph, islower, isprint,
    ispunct, isspace, isupper, isxdigit, tolower, toupper,
};
pub use env::{getenv, getenv_cstr, putenv, setenv, unsetenv, ENVIRON};
pub use errno::{errno, set_errno, strerror, __errno_location};
pub use fd::{
    dup, dup2, fcntl, fstat, isatty, pipe, pipe2, stat, FD_CLOEXEC, F_GETFD, F_GETFL,
    F_SETFD, F_SETFL, StatBuf,
};
pub use fs::{
    chdir, chmod, getcwd, umask, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK,
    S_IFMT, S_IFREG, S_IFSOCK, S_ISCHR, S_ISDIR, S_ISFIFO, S_ISLNK, S_ISREG,
};
pub use getopt::{
    getopt, getopt_long, optarg, opterr, optind, optopt, option,
    NO_ARGUMENT, OPTIONAL_ARGUMENT, REQUIRED_ARGUMENT,
};
pub use heap::{aligned_alloc, calloc, free, malloc, posix_memalign, realloc};
// `io::fputs(&str, fd)` deliberately omitted — the `stdio::fputs`
// FILE*-shaped one (re-exported below) is the canonical public
// surface. The internal helper is still reachable as
// `crate::io::fputs` for non-public call sites that haven't migrated.
pub use io::{
    asprintf_c, fprintf_str, printf_str, snprintf_c, snprintf_str, sprintf_c,
    sprintf_str, vprintf_str, vsnprintf_str, write, Arg, Stdout,
};
pub use math::{
    atan, atan2, atan2f, atanf, ceil, ceilf, copysign, copysignf, cos, cosf, exp, expf,
    fabs, fabsf, floor, floorf, fmax, fmaxf, fmin, fminf, fmod, fmodf, frexp, frexpf,
    isfinite, isinf, isnan, ldexp, ldexpf, log, log10, log10f, log2, log2f, logf,
    modf, modff, pow, powf, round, roundf, signbit, sin, sinf, sqrt, sqrtf, tan,
    tanf, trunc, truncf,
};
pub use numeric::{
    cabs, cadd, cdiv, cimag, cmul, complex_double, complex_float, conj, creal, csub,
    feclearexcept, fegetenv, fegetround, feraiseexcept, fesetenv, fesetround,
    fetestexcept, fenv_t, fexcept_t, FE_ALL_EXCEPT, FE_DIVBYZERO, FE_DOWNWARD,
    FE_INEXACT, FE_INVALID, FE_OVERFLOW, FE_TONEAREST, FE_TOWARDZERO, FE_UNDERFLOW,
    FE_UPWARD,
};
pub use net::{
    accept, addrinfo, bind, connect, freeaddrinfo, gai_strerror, getaddrinfo,
    getsockopt, htonl, htons, in_addr, inet_addr, inet_aton, inet_ntop, inet_pton,
    listen, ntohl, ntohs, recv, recvfrom, send, sendto, setsockopt, shutdown, sockaddr,
    sockaddr_in, sockaddr_in6, socket, AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC,
    EAI_FAIL, EAI_NONAME, INADDR_NONE, INET_ADDRSTRLEN, IPPROTO_IP, IPPROTO_TCP,
    IPPROTO_UDP, SHUT_RD, SHUT_RDWR, SHUT_WR, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM,
    SOL_SOCKET, SO_KEEPALIVE, SO_LINGER, SO_RCVBUF, SO_REUSEADDR, SO_SNDBUF,
};
pub use locale::{
    iconv, iconv_close, iconv_open, mbtowc, nl_langinfo, setlocale, wchar_t, wcscmp,
    wcslen, wctomb, AM_STR, CODESET, CRNCYSTR, D_FMT, D_T_FMT, EILSEQ, LC_ALL,
    LC_COLLATE, LC_CTYPE, LC_MESSAGES, LC_MONETARY, LC_NUMERIC, LC_TIME, PM_STR,
    RADIXCHAR, T_FMT, T_FMT_AMPM, THOUSEP,
};
pub use poll::{
    epoll_create, epoll_create1, epoll_ctl, epoll_event, epoll_wait, eventfd, fd_set,
    itimerspec, pollfd, poll, select, signalfd, timerfd_create, timerfd_gettime,
    timerfd_settime, timeval_select, EPOLLERR, EPOLLHUP, EPOLLIN, EPOLLOUT,
    EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD, FD_CLR, FD_ISSET, FD_SET, FD_SETSIZE,
    FD_ZERO, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI, POLLRDHUP,
};
pub use path::{
    basename, closedir, dirent, dirname, fnmatch, opendir, readdir, rewinddir,
    DIR, DT_CHR, DT_DIR, DT_FIFO, DT_LNK, DT_REG, DT_UNKNOWN, FNM_NOESCAPE,
    FNM_NOMATCH, FNM_PATHNAME, FNM_PERIOD,
};
pub use posix::{
    access, close as posix_close, fallocate, fdatasync, fsync, ftruncate,
    gethostname, getpagesize, link, lseek as posix_lseek,
    mkdir as posix_mkdir, open as posix_open, posix_fallocate, pread, pwrite,
    read as posix_read, readlink, rename as posix_rename,
    rmdir as posix_rmdir, sethostname, symlink, sync, sysconf, truncate,
    unlink as posix_unlink, write as posix_write,
    FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE,
    FALLOC_FL_ZERO_RANGE, O_APPEND, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC,
    O_WRONLY, SEEK_CUR, SEEK_END, SEEK_SET, _SC_OPEN_MAX, _SC_PAGESIZE,
    _SC_PAGE_SIZE,
};
pub use sys::{
    cpu_set_t, dlclose, dlerror, dlopen, dlsym, getcpu, getrlimit, getrusage,
    madvise, mlock, mlockall, mmap, mprotect, munlock, munlockall, munmap, rlimit,
    rusage, sched_getaffinity, sched_getcpu, sched_setaffinity, setrlimit,
    sysinfo, sysinfo_t, uname, utsname, CPU_ISSET, CPU_SET, CPU_ZERO,
    MAP_ANONYMOUS, MAP_FAILED, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, PROT_EXEC,
    PROT_NONE, PROT_READ, PROT_WRITE, RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU,
    RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_NOFILE, RLIMIT_STACK, RLIM_INFINITY,
    RTLD_GLOBAL, RTLD_LAZY, RTLD_LOCAL, RTLD_NOW, RUSAGE_CHILDREN, RUSAGE_SELF,
};
pub use sysvipc::{
    ftok, ipc_perm, msgctl, msgget, msgrcv, msgsnd, msqid_ds, sembuf, semctl, semget,
    semid_ds, semop, shmat, shmctl, shmdt, shmget, shmid_ds, IPC_CREAT, IPC_EXCL,
    IPC_INFO, IPC_NOWAIT, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, MSG_EXCEPT,
    MSG_NOERROR, SEM_UNDO, SHM_EXEC, SHM_RDONLY, SHM_REMAP, SHM_RND,
};
pub use term::{
    flock, futimens, ioctl, tcdrain, tcflush, tcgetattr, tcsetattr, termios,
    timeval64, utime, utimbuf, utimes, LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN, NCCS,
    TCSADRAIN, TCSAFLUSH, TCSANOW,
};
pub use pthread::{
    pthread_attr_destroy, pthread_attr_init, pthread_attr_t, pthread_cond_t,
    pthread_condattr_t, pthread_create, pthread_detach, pthread_equal,
    pthread_getspecific, pthread_join, pthread_key_create, pthread_key_delete,
    pthread_key_t, pthread_mutex_destroy, pthread_mutex_init, pthread_mutex_lock,
    pthread_mutex_t, pthread_mutex_trylock, pthread_mutex_unlock,
    pthread_mutexattr_t, pthread_once, pthread_once_t, pthread_rwlock_t,
    pthread_self, pthread_setspecific, pthread_t, MAIN_THREAD, PTHREAD_ONCE_INIT,
};
pub use process::{
    abort, atexit, execv, execve, execvp, exit, fork, getegid, geteuid, getgid,
    getpgid, getpgrp, getpid, getppid, getpriority, getsid, gettid, getuid,
    nice, prctl, setgid, setpgid, setpriority, setsid, setuid, sleep, usleep,
    vfork, wait, waitpid, _exit, PRIO_PGRP, PRIO_PROCESS, PRIO_USER,
    PR_GET_DUMPABLE, PR_GET_NAME, PR_GET_NO_NEW_PRIVS, PR_SET_DUMPABLE,
    PR_SET_NAME, PR_SET_NO_NEW_PRIVS,
};
pub use setjmp::{
    jmp_buf, longjmp, setjmp, sigjmp_buf, siglongjmp, sigsetjmp, JMP_BUF_LEN,
};
pub use random::{
    getentropy, getrandom, iovec, readv, writev, GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM,
};
pub use regex::{
    regcomp, regerror, regexec, regfree, regex_t, regmatch_t,
    REG_BADBR, REG_BADPAT, REG_BADRPT, REG_EBRACE, REG_EBRACK, REG_ECOLLATE,
    REG_ECTYPE, REG_EESCAPE, REG_EPAREN, REG_ERANGE, REG_ESPACE, REG_ESUBREG,
    REG_EXTENDED, REG_ICASE, REG_NEWLINE, REG_NOERROR, REG_NOMATCH, REG_NOSUB,
    REG_NOTBOL, REG_NOTEOL,
};
pub use signal::{
    kill, raise, signal, sighandler_t,
    SIG_DFL_RAW, SIG_IGN_RAW, SIGABRT, SIGALRM, SIGCHLD, SIGFPE, SIGHUP, SIGILL,
    SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSEGV, SIGTERM,
};
pub use search::{
    crypt, crypt_data, crypt_r, endutent, getutent, pututline, setutent, tdelete, tfind,
    tsearch, twalk, utmp, utmpname, ENDORDER, LEAF, POSTORDER, PREORDER,
};
pub use socket_extra::{
    cmsghdr, getpeername, getsockname, msghdr, recvmsg, sendmsg, sockaddr_un, sockatmark,
    socketpair, MSG_CMSG_CLOEXEC, MSG_CTRUNC, MSG_DONTROUTE, MSG_DONTWAIT, MSG_EOR,
    MSG_NOSIGNAL, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL, SCM_CREDENTIALS, SCM_RIGHTS,
};
pub use stdlib::{
    abs, atoi, atol, bsearch, div, div_t, labs, ldiv, ldiv_t, qsort, rand, srand,
    sscanf_ints, strtol, strtoul, RAND_MAX,
};
pub use time::{
    asctime, clock, clock_gettime, ctime, difftime, gettimeofday, gmtime,
    gmtime_r, localtime, localtime_r, mktime, strftime, time, times, timespec,
    timeval, tm, tms,
};
pub use startup::__libc_start_main;
// Note: `stdio::fputs` shadows the older `io::fputs(&str, fd)` helper
// — the FILE*-shaped one is the POSIX-correct surface and is the one
// downstream callers should use. The old `io::fputs` remains
// accessible as `crate::io::fputs` for any internal call-sites that
// haven't migrated yet.
pub use stdio::{
    clearerr, fclose, feof, ferror, fflush, fgetc, fgets, fopen, fputc, fputs, fread,
    fseek, ftell, fwrite, getc, getchar, perror, putc, putchar, puts, rewind, setbuf,
    setvbuf, stderr, stdin, stdout, ungetc, File, _IOFBF, _IOLBF, _IONBF,
};
pub use string::{
    memchr, memcmp, memcpy, memmem, memmove, memset, strcasecmp, strcat, strchr,
    strcmp, strcoll, strcpy, strcspn, strdup, strlen, strncasecmp, strncmp, strncpy,
    strndup, strnlen, strpbrk, strrchr, strspn, strstr, strtok_r, strxfrm,
    __memcpy_chk, __memmove_chk, __memset_chk, __strcpy_chk,
};
