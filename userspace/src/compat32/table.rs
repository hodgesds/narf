//! The i386 system-call table (`arch/x86/entry/syscalls/syscall_32.tbl`).
//!
//! [`super::dispatch`] reaches this after seccomp and the TLS calls; it
//! owns nothing but the number → handler mapping. An i386 call whose
//! arguments match a native handler's is served with [`forward`]; one that
//! needs converting (64-bit argument pairs, compat structs) gets its own
//! handler. Unlisted numbers answer -ENOSYS (`sys_ni_syscall`).
//!
//! Each arm names the Linux entry point it mirrors. Handlers shared with
//! the native table pick the i386 layout themselves from
//! `TrapContext::in_ia32_syscall()` (Linux `in_compat_syscall()`: iovecs,
//! `struct stat64`, `struct compat_sigaction`, the robust-list head) or,
//! where one handler serves several i386 entry points, from the
//! [`Ia32Abi`] this table attaches ([`forward_abi`]). Arguments that are a
//! signed C type are sign-extended first ([`forward_sx`]), as the
//! `__ia32_sys_*` wrappers' `__SC_COMPAT_CAST` does; everything else —
//! pointers above all (`compat_ptr`) — stays zero-extended.

use narf_memory::AddressSpace;

use super::conv;
use super::ctx::Ia32ArgsCtx;
use crate::errno::{to_ret, EBADF, EINVAL, ENOMEM, ENOTTY};
use crate::syscall::Ia32Flock;
use crate::syscall::{Ia32Abi, Syscall, SyscallArgs, SyscallReturn, TrapContext};

/// i386 system-call numbers (`syscall_32.tbl`).
pub mod nr {
    pub const RESTART_SYSCALL: u32 = 0;
    pub const EXIT: u32 = 1;
    pub const FORK: u32 = 2;
    pub const READ: u32 = 3;
    pub const WRITE: u32 = 4;
    pub const OPEN: u32 = 5;
    pub const CLOSE: u32 = 6;
    pub const WAITPID: u32 = 7;
    pub const CREAT: u32 = 8;
    pub const LINK: u32 = 9;
    pub const UNLINK: u32 = 10;
    pub const EXECVE: u32 = 11;
    pub const CHDIR: u32 = 12;
    pub const TIME: u32 = 13;
    pub const MKNOD: u32 = 14;
    pub const CHMOD: u32 = 15;
    pub const LCHOWN: u32 = 16;
    pub const LSEEK: u32 = 19;
    pub const GETPID: u32 = 20;
    pub const MOUNT: u32 = 21;
    pub const SETUID: u32 = 23;
    pub const GETUID: u32 = 24;
    pub const ALARM: u32 = 27;
    pub const PAUSE: u32 = 29;
    pub const UTIME: u32 = 30;
    pub const ACCESS: u32 = 33;
    pub const SYNC: u32 = 36;
    pub const KILL: u32 = 37;
    pub const RENAME: u32 = 38;
    pub const MKDIR: u32 = 39;
    pub const RMDIR: u32 = 40;
    pub const DUP: u32 = 41;
    pub const PIPE: u32 = 42;
    pub const TIMES: u32 = 43;
    pub const BRK: u32 = 45;
    pub const SETGID: u32 = 46;
    pub const GETGID: u32 = 47;
    pub const GETEUID: u32 = 49;
    pub const GETEGID: u32 = 50;
    pub const UMOUNT2: u32 = 52;
    pub const IOCTL: u32 = 54;
    pub const FCNTL: u32 = 55;
    pub const SETPGID: u32 = 57;
    pub const UMASK: u32 = 60;
    pub const CHROOT: u32 = 61;
    pub const DUP2: u32 = 63;
    pub const GETPPID: u32 = 64;
    pub const GETPGRP: u32 = 65;
    pub const SETSID: u32 = 66;
    pub const SETREUID: u32 = 70;
    pub const SETREGID: u32 = 71;
    pub const SETHOSTNAME: u32 = 74;
    pub const SETRLIMIT: u32 = 75;
    pub const GETRLIMIT: u32 = 76;
    pub const GETRUSAGE: u32 = 77;
    pub const GETTIMEOFDAY: u32 = 78;
    pub const SETTIMEOFDAY: u32 = 79;
    pub const GETGROUPS: u32 = 80;
    pub const SETGROUPS: u32 = 81;
    pub const SELECT: u32 = 82;
    pub const SYMLINK: u32 = 83;
    pub const READLINK: u32 = 85;
    pub const REBOOT: u32 = 88;
    pub const MMAP: u32 = 90;
    pub const MUNMAP: u32 = 91;
    pub const TRUNCATE: u32 = 92;
    pub const FTRUNCATE: u32 = 93;
    pub const FCHMOD: u32 = 94;
    pub const FCHOWN: u32 = 95;
    pub const GETPRIORITY: u32 = 96;
    pub const SETPRIORITY: u32 = 97;
    pub const STATFS: u32 = 99;
    pub const FSTATFS: u32 = 100;
    pub const SOCKETCALL: u32 = 102;
    pub const SYSLOG: u32 = 103;
    pub const VHANGUP: u32 = 111;
    pub const WAIT4: u32 = 114;
    pub const SYSINFO: u32 = 116;
    pub const IPC: u32 = 117;
    pub const FSYNC: u32 = 118;
    pub const CLONE: u32 = 120;
    pub const SETDOMAINNAME: u32 = 121;
    pub const UNAME: u32 = 122;
    pub const MPROTECT: u32 = 125;
    pub const INIT_MODULE: u32 = 128;
    pub const DELETE_MODULE: u32 = 129;
    pub const GETPGID: u32 = 132;
    pub const FCHDIR: u32 = 133;
    pub const PERSONALITY: u32 = 136;
    pub const SETFSUID: u32 = 138;
    pub const SETFSGID: u32 = 139;
    pub const LLSEEK: u32 = 140;
    pub const NEWSELECT: u32 = 142;
    pub const FLOCK: u32 = 143;
    pub const MSYNC: u32 = 144;
    pub const READV: u32 = 145;
    pub const WRITEV: u32 = 146;
    pub const GETSID: u32 = 147;
    pub const FDATASYNC: u32 = 148;
    pub const MLOCK: u32 = 150;
    pub const MUNLOCK: u32 = 151;
    pub const MLOCKALL: u32 = 152;
    pub const MUNLOCKALL: u32 = 153;
    pub const SCHED_SETPARAM: u32 = 154;
    pub const SCHED_GETPARAM: u32 = 155;
    pub const SCHED_SETSCHEDULER: u32 = 156;
    pub const SCHED_GETSCHEDULER: u32 = 157;
    pub const SCHED_YIELD: u32 = 158;
    pub const SCHED_GET_PRIORITY_MAX: u32 = 159;
    pub const SCHED_GET_PRIORITY_MIN: u32 = 160;
    pub const SCHED_RR_GET_INTERVAL: u32 = 161;
    pub const NANOSLEEP: u32 = 162;
    pub const MREMAP: u32 = 163;
    pub const SETRESUID: u32 = 164;
    pub const GETRESUID: u32 = 165;
    pub const POLL: u32 = 168;
    pub const SETRESGID: u32 = 170;
    pub const GETRESGID: u32 = 171;
    pub const PRCTL: u32 = 172;
    pub const RT_SIGACTION: u32 = 174;
    pub const RT_SIGPROCMASK: u32 = 175;
    pub const RT_SIGPENDING: u32 = 176;
    pub const RT_SIGSUSPEND: u32 = 179;
    pub const PREAD64: u32 = 180;
    pub const PWRITE64: u32 = 181;
    pub const CHOWN: u32 = 182;
    pub const GETCWD: u32 = 183;
    pub const CAPGET: u32 = 184;
    pub const CAPSET: u32 = 185;
    pub const SIGALTSTACK: u32 = 186;
    pub const SENDFILE: u32 = 187;
    pub const VFORK: u32 = 190;
    pub const UGETRLIMIT: u32 = 191;
    pub const MMAP2: u32 = 192;
    pub const TRUNCATE64: u32 = 193;
    pub const FTRUNCATE64: u32 = 194;
    pub const STAT64: u32 = 195;
    pub const LSTAT64: u32 = 196;
    pub const FSTAT64: u32 = 197;
    pub const LCHOWN32: u32 = 198;
    pub const GETUID32: u32 = 199;
    pub const GETGID32: u32 = 200;
    pub const GETEUID32: u32 = 201;
    pub const GETEGID32: u32 = 202;
    pub const SETREUID32: u32 = 203;
    pub const SETREGID32: u32 = 204;
    pub const GETGROUPS32: u32 = 205;
    pub const SETGROUPS32: u32 = 206;
    pub const FCHOWN32: u32 = 207;
    pub const SETRESUID32: u32 = 208;
    pub const GETRESUID32: u32 = 209;
    pub const SETRESGID32: u32 = 210;
    pub const GETRESGID32: u32 = 211;
    pub const CHOWN32: u32 = 212;
    pub const SETUID32: u32 = 213;
    pub const SETGID32: u32 = 214;
    pub const SETFSUID32: u32 = 215;
    pub const SETFSGID32: u32 = 216;
    pub const PIVOT_ROOT: u32 = 217;
    pub const MINCORE: u32 = 218;
    pub const MADVISE: u32 = 219;
    pub const GETDENTS64: u32 = 220;
    pub const FCNTL64: u32 = 221;
    pub const GETTID: u32 = 224;
    pub const READAHEAD: u32 = 225;
    pub const SETXATTR: u32 = 226;
    pub const LSETXATTR: u32 = 227;
    pub const FSETXATTR: u32 = 228;
    pub const GETXATTR: u32 = 229;
    pub const LGETXATTR: u32 = 230;
    pub const FGETXATTR: u32 = 231;
    pub const LISTXATTR: u32 = 232;
    pub const LLISTXATTR: u32 = 233;
    pub const FLISTXATTR: u32 = 234;
    pub const REMOVEXATTR: u32 = 235;
    pub const LREMOVEXATTR: u32 = 236;
    pub const FREMOVEXATTR: u32 = 237;
    pub const TKILL: u32 = 238;
    pub const SENDFILE64: u32 = 239;
    pub const FUTEX: u32 = 240;
    pub const SCHED_SETAFFINITY: u32 = 241;
    pub const SCHED_GETAFFINITY: u32 = 242;
    pub const IO_DESTROY: u32 = 246;
    pub const IO_GETEVENTS: u32 = 247;
    pub const IO_CANCEL: u32 = 249;
    pub const FADVISE64: u32 = 250;
    pub const EXIT_GROUP: u32 = 252;
    pub const EPOLL_CREATE: u32 = 254;
    pub const EPOLL_CTL: u32 = 255;
    pub const EPOLL_WAIT: u32 = 256;
    pub const SET_TID_ADDRESS: u32 = 258;
    pub const TIMER_SETTIME: u32 = 260;
    pub const TIMER_GETTIME: u32 = 261;
    pub const TIMER_GETOVERRUN: u32 = 262;
    pub const TIMER_DELETE: u32 = 263;
    pub const CLOCK_SETTIME: u32 = 264;
    pub const CLOCK_GETTIME: u32 = 265;
    pub const CLOCK_GETRES: u32 = 266;
    pub const CLOCK_NANOSLEEP: u32 = 267;
    pub const STATFS64: u32 = 268;
    pub const FSTATFS64: u32 = 269;
    pub const TGKILL: u32 = 270;
    pub const UTIMES: u32 = 271;
    pub const FADVISE64_64: u32 = 272;
    pub const MQ_UNLINK: u32 = 278;
    pub const MQ_TIMEDSEND: u32 = 279;
    pub const MQ_TIMEDRECEIVE: u32 = 280;
    pub const WAITID: u32 = 284;
    pub const ADD_KEY: u32 = 286;
    pub const REQUEST_KEY: u32 = 287;
    pub const IOPRIO_SET: u32 = 289;
    pub const IOPRIO_GET: u32 = 290;
    pub const INOTIFY_INIT: u32 = 291;
    pub const INOTIFY_ADD_WATCH: u32 = 292;
    pub const INOTIFY_RM_WATCH: u32 = 293;
    pub const OPENAT: u32 = 295;
    pub const MKDIRAT: u32 = 296;
    pub const MKNODAT: u32 = 297;
    pub const FCHOWNAT: u32 = 298;
    pub const FUTIMESAT: u32 = 299;
    pub const FSTATAT64: u32 = 300;
    pub const UNLINKAT: u32 = 301;
    pub const RENAMEAT: u32 = 302;
    pub const LINKAT: u32 = 303;
    pub const SYMLINKAT: u32 = 304;
    pub const READLINKAT: u32 = 305;
    pub const FCHMODAT: u32 = 306;
    pub const FACCESSAT: u32 = 307;
    pub const PSELECT6: u32 = 308;
    pub const PPOLL: u32 = 309;
    pub const UNSHARE: u32 = 310;
    pub const SET_ROBUST_LIST: u32 = 311;
    pub const SPLICE: u32 = 313;
    pub const SYNC_FILE_RANGE: u32 = 314;
    pub const TEE: u32 = 315;
    pub const GETCPU: u32 = 318;
    pub const EPOLL_PWAIT: u32 = 319;
    pub const UTIMENSAT: u32 = 320;
    pub const SIGNALFD: u32 = 321;
    pub const TIMERFD_CREATE: u32 = 322;
    pub const EVENTFD: u32 = 323;
    pub const FALLOCATE: u32 = 324;
    pub const TIMERFD_SETTIME: u32 = 325;
    pub const TIMERFD_GETTIME: u32 = 326;
    pub const SIGNALFD4: u32 = 327;
    pub const EVENTFD2: u32 = 328;
    pub const EPOLL_CREATE1: u32 = 329;
    pub const DUP3: u32 = 330;
    pub const PIPE2: u32 = 331;
    pub const INOTIFY_INIT1: u32 = 332;
    pub const PREADV: u32 = 333;
    pub const PWRITEV: u32 = 334;
    pub const PERF_EVENT_OPEN: u32 = 336;
    pub const RECVMMSG: u32 = 337;
    pub const FANOTIFY_INIT: u32 = 338;
    pub const PRLIMIT64: u32 = 340;
    pub const NAME_TO_HANDLE_AT: u32 = 341;
    pub const SYNCFS: u32 = 344;
    pub const SENDMMSG: u32 = 345;
    pub const SETNS: u32 = 346;
    pub const KCMP: u32 = 349;
    pub const FINIT_MODULE: u32 = 350;
    pub const SCHED_SETATTR: u32 = 351;
    pub const SCHED_GETATTR: u32 = 352;
    pub const RENAMEAT2: u32 = 353;
    pub const GETRANDOM: u32 = 355;
    pub const MEMFD_CREATE: u32 = 356;
    pub const BPF: u32 = 357;
    pub const EXECVEAT: u32 = 358;
    pub const SOCKET: u32 = 359;
    pub const SOCKETPAIR: u32 = 360;
    pub const BIND: u32 = 361;
    pub const CONNECT: u32 = 362;
    pub const LISTEN: u32 = 363;
    pub const ACCEPT4: u32 = 364;
    pub const GETSOCKOPT: u32 = 365;
    pub const SETSOCKOPT: u32 = 366;
    pub const GETSOCKNAME: u32 = 367;
    pub const GETPEERNAME: u32 = 368;
    pub const SENDTO: u32 = 369;
    pub const SENDMSG: u32 = 370;
    pub const RECVFROM: u32 = 371;
    pub const RECVMSG: u32 = 372;
    pub const SHUTDOWN: u32 = 373;
    pub const MEMBARRIER: u32 = 375;
    pub const MLOCK2: u32 = 376;
    pub const COPY_FILE_RANGE: u32 = 377;
    pub const PREADV2: u32 = 378;
    pub const PWRITEV2: u32 = 379;
    pub const PKEY_MPROTECT: u32 = 380;
    pub const PKEY_ALLOC: u32 = 381;
    pub const PKEY_FREE: u32 = 382;
    pub const STATX: u32 = 383;
    pub const ARCH_PRCTL: u32 = 384;
    pub const RSEQ: u32 = 386;
    pub const SEMGET: u32 = 393;
    pub const SEMCTL: u32 = 394;
    pub const SHMGET: u32 = 395;
    pub const SHMCTL: u32 = 396;
    pub const SHMAT: u32 = 397;
    pub const SHMDT: u32 = 398;
    pub const MSGGET: u32 = 399;
    pub const MSGSND: u32 = 400;
    pub const MSGRCV: u32 = 401;
    pub const MSGCTL: u32 = 402;
    pub const CLOCK_GETTIME64: u32 = 403;
    pub const CLOCK_SETTIME64: u32 = 404;
    pub const CLOCK_ADJTIME64: u32 = 405;
    pub const CLOCK_GETRES_TIME64: u32 = 406;
    pub const CLOCK_NANOSLEEP_TIME64: u32 = 407;
    pub const TIMER_GETTIME64: u32 = 408;
    pub const TIMER_SETTIME64: u32 = 409;
    pub const TIMERFD_GETTIME64: u32 = 410;
    pub const TIMERFD_SETTIME64: u32 = 411;
    pub const UTIMENSAT_TIME64: u32 = 412;
    pub const PSELECT6_TIME64: u32 = 413;
    pub const PPOLL_TIME64: u32 = 414;
    pub const RECVMMSG_TIME64: u32 = 417;
    pub const MQ_TIMEDSEND_TIME64: u32 = 418;
    pub const MQ_TIMEDRECEIVE_TIME64: u32 = 419;
    pub const SEMTIMEDOP_TIME64: u32 = 420;
    pub const FUTEX_TIME64: u32 = 422;
    pub const SCHED_RR_GET_INTERVAL_TIME64: u32 = 423;
    pub const PIDFD_SEND_SIGNAL: u32 = 424;
    pub const OPEN_TREE: u32 = 428;
    pub const MOVE_MOUNT: u32 = 429;
    pub const FSOPEN: u32 = 430;
    pub const FSCONFIG: u32 = 431;
    pub const FSMOUNT: u32 = 432;
    pub const FSPICK: u32 = 433;
    pub const PIDFD_OPEN: u32 = 434;
    pub const CLONE3: u32 = 435;
    pub const CLOSE_RANGE: u32 = 436;
    pub const OPENAT2: u32 = 437;
    pub const PIDFD_GETFD: u32 = 438;
    pub const FACCESSAT2: u32 = 439;
    pub const EPOLL_PWAIT2: u32 = 441;
    pub const MOUNT_SETATTR: u32 = 442;
    pub const LANDLOCK_CREATE_RULESET: u32 = 444;
    pub const LANDLOCK_ADD_RULE: u32 = 445;
    pub const LANDLOCK_RESTRICT_SELF: u32 = 446;
    pub const MEMFD_SECRET: u32 = 447;
    pub const PROCESS_MRELEASE: u32 = 448;
    pub const FUTEX_WAITV: u32 = 449;
    pub const SET_MEMPOLICY_HOME_NODE: u32 = 450;
    pub const CACHESTAT: u32 = 451;
    pub const FCHMODAT2: u32 = 452;
    pub const FUTEX_WAKE: u32 = 454;
    pub const FUTEX_WAIT: u32 = 455;
    pub const FUTEX_REQUEUE: u32 = 456;
    pub const STATMOUNT: u32 = 457;
    pub const LISTMOUNT: u32 = 458;
    pub const LSM_GET_SELF_ATTR: u32 = 459;
    pub const LSM_SET_SELF_ATTR: u32 = 460;
    pub const LSM_LIST_MODULES: u32 = 461;
    pub const MSEAL: u32 = 462;
    pub const SETXATTRAT: u32 = 463;
    pub const GETXATTRAT: u32 = 464;
    pub const LISTXATTRAT: u32 = 465;
    pub const REMOVEXATTRAT: u32 = 466;
    pub const OPEN_TREE_ATTR: u32 = 467;
    pub const FILE_GETATTR: u32 = 468;
    pub const FILE_SETATTR: u32 = 469;
    pub const LISTNS: u32 = 470;
}

/// i386 `exit`.
pub const NR_EXIT: u32 = nr::EXIT;
/// i386 `getpid`.
pub const NR_GETPID: u32 = nr::GETPID;
/// i386 `uname` (`sys_newuname`; `struct new_utsname` is ABI-identical).
pub const NR_UNAME: u32 = nr::UNAME;
/// i386 `sched_yield`.
pub const NR_SCHED_YIELD: u32 = nr::SCHED_YIELD;
/// i386 `gettid`.
pub const NR_GETTID: u32 = nr::GETTID;
/// i386 `exit_group`.
pub const NR_EXIT_GROUP: u32 = nr::EXIT_GROUP;

/// Serve i386 system call `nr` on `ctx`. Returns the native syscall that
/// served it, if any: [`super::dispatch`] classifies restartability by it
/// when the call parks to be re-executed.
pub fn dispatch(nr: u32, ctx: &mut dyn TrapContext) -> Option<Syscall> {
    use nr::*;
    // Bit i of a mask: argument i is a signed C type (`int`, `pid_t`,
    // `clockid_t`, ...) and is sign-extended.
    match nr {
        // kernel/exit.c
        EXIT => forward(ctx, Syscall::ExitTask),
        // fs/exec.c: `compat_sys_execve` / `compat_sys_execveat` read argv and
        // envp as 32-bit pointers (the native handler checks
        // `in_ia32_syscall`); the image may be either class.
        EXECVE => forward(ctx, Syscall::Execve),
        EXECVEAT => forward_sx(ctx, Syscall::Execveat, 0b10001),
        // kernel/fork.c. The child returns to user mode in the caller's mode
        // with its segment state (`copy_thread`), and an i386 CLONE_SETTLS
        // names a `struct user_desc` (`set_new_tls`): the native handlers
        // read both from the context.
        FORK => forward(ctx, Syscall::Fork),
        VFORK => forward(ctx, Syscall::Vfork),
        CLONE => compat_sys_ia32_clone(ctx),
        CLONE3 => forward(ctx, Syscall::Clone3),
        // kernel/exit.c: `sys_waitpid` is `kernel_wait4(pid, stat_addr,
        // options, NULL)`.
        WAITPID => sys_waitpid(ctx),
        EXIT_GROUP => forward(ctx, Syscall::ExitGroup),
        // fs/read_write.c, fs/open.c, fs/pipe.c, fs/file.c
        READ => forward(ctx, Syscall::Read),
        WRITE => forward(ctx, Syscall::Write),
        // `sys_readv`/`sys_writev`: `import_iovec` reads compat_iovecs under
        // `in_compat_syscall()`.
        READV => forward(ctx, Syscall::Readv),
        WRITEV => forward(ctx, Syscall::Writev),
        // `compat_sys_open`/`compat_sys_openat`: `do_sys_open` without the
        // 64-bit O_LARGEFILE force.
        OPEN => forward(ctx, Syscall::OpenFile),
        OPENAT => forward_sx(ctx, Syscall::Openat, 0b101),
        CLOSE => forward(ctx, Syscall::Close),
        PIPE => forward(ctx, Syscall::Pipe),
        PIPE2 => forward(ctx, Syscall::Pipe2),
        DUP => forward(ctx, Syscall::Dup),
        DUP2 => forward(ctx, Syscall::Dup2),
        DUP3 => forward(ctx, Syscall::Dup3),
        IOCTL => compat_sys_ioctl(ctx),
        CHDIR => forward(ctx, Syscall::Chdir),
        GETCWD => forward(ctx, Syscall::Getcwd),
        UMASK => forward(ctx, Syscall::Umask),
        // `compat_sys_lseek` takes a `compat_off_t`; `sys_llseek` and the
        // `sys_ia32_p{read,write}64` wrappers carry a 64-bit offset in two
        // registers.
        LSEEK => forward_sx(ctx, Syscall::Lseek, 0b10),
        LLSEEK => sys_llseek(ctx),
        PREAD64 => sys_ia32_pread_pwrite(ctx, Syscall::Pread64),
        PWRITE64 => sys_ia32_pread_pwrite(ctx, Syscall::Pwrite64),
        GETDENTS64 => forward(ctx, Syscall::Getdents64),
        // `compat_sys_fcntl64` / `compat_sys_fcntl` (`do_compat_fcntl64`).
        FCNTL64 => compat_sys_fcntl64(ctx, true),
        FCNTL => compat_sys_fcntl64(ctx, false),
        // fs/stat.c via `cp_stat64` (`put_linux_stat` under
        // `in_ia32_syscall()`): `compat_sys_ia32_{stat,lstat,fstat,fstatat}64`.
        STAT64 => forward(ctx, Syscall::Stat),
        LSTAT64 => forward(ctx, Syscall::Lstat),
        FSTAT64 => forward(ctx, Syscall::Fstat),
        FSTATAT64 => forward_sx(ctx, Syscall::Newfstatat, 0b1),
        STATX => forward_sx(ctx, Syscall::Statx, 0b1),
        ACCESS => forward(ctx, Syscall::Access),
        FACCESSAT => forward_sx(ctx, Syscall::Faccessat, 0b1),
        FACCESSAT2 => forward_sx(ctx, Syscall::Faccessat2, 0b1),
        READLINK => forward(ctx, Syscall::Readlink),
        READLINKAT => forward_sx(ctx, Syscall::Readlinkat, 0b1001),
        UNLINK => forward(ctx, Syscall::Unlink),
        UNLINKAT => forward_sx(ctx, Syscall::Unlinkat, 0b101),
        MKDIR => forward(ctx, Syscall::Mkdir),
        MKDIRAT => forward_sx(ctx, Syscall::Mkdirat, 0b1),
        RMDIR => forward(ctx, Syscall::Rmdir),
        RENAME => forward(ctx, Syscall::Rename),
        // mm/
        BRK => forward(ctx, Syscall::Brk),
        MMAP2 => sys_mmap_pgoff(ctx),
        MMAP => compat_sys_ia32_mmap(ctx),
        MUNMAP => forward(ctx, Syscall::Munmap),
        MPROTECT => forward(ctx, Syscall::MProtect),
        MADVISE => forward(ctx, Syscall::Madvise),
        MREMAP => forward(ctx, Syscall::Mremap),
        // kernel/sys.c, kernel/exec_domain.c
        UNAME => forward(ctx, Syscall::Uname),
        PERSONALITY => forward(ctx, Syscall::Personality),
        GETPID => forward(ctx, Syscall::GetPid),
        GETPPID => forward(ctx, Syscall::GetPpid),
        GETTID => forward(ctx, Syscall::Gettid),
        GETUID32 => forward(ctx, Syscall::GetUid),
        GETGID32 => forward(ctx, Syscall::GetGid),
        GETEUID32 => forward(ctx, Syscall::Geteuid),
        GETEGID32 => forward(ctx, Syscall::Getegid),
        GETRESUID32 => forward(ctx, Syscall::Getresuid),
        GETRESGID32 => forward(ctx, Syscall::Getresgid),
        // The 16-bit uid calls (`sys_getuid16`, ...): `high2lowuid`.
        GETUID => uid16(ctx, Syscall::GetUid),
        GETGID => uid16(ctx, Syscall::GetGid),
        GETEUID => uid16(ctx, Syscall::Geteuid),
        GETEGID => uid16(ctx, Syscall::Getegid),
        // kernel/sys.c, kernel/resource: `struct rlimit64` is two u64s in
        // both ABIs.
        PRLIMIT64 => forward_sx(ctx, Syscall::Prlimit64, 0b1),
        GETRANDOM => forward(ctx, Syscall::GetRandom),
        // `compat_sys_sched_getaffinity`: the length unit is
        // `compat_ulong_t` (the native handler checks `in_ia32_syscall`).
        SCHED_GETAFFINITY => forward_sx(ctx, Syscall::SchedGetaffinity, 0b1),
        ARCH_PRCTL => sys_arch_prctl(ctx),
        // NARF has no IA-32 rseq ABI (a `struct rseq` registered from compat
        // mode needs the 32-bit `rseq_cs` handling); -ENOSYS is what a kernel
        // without CONFIG_RSEQ answers, and glibc then runs without rseq.
        RSEQ => {
            ctx.set_return(SyscallReturn::not_implemented());
            None
        }
        // kernel/fork.c, kernel/sched/syscalls.c, kernel/signal.c
        SET_TID_ADDRESS => forward(ctx, Syscall::SetTidAddress),
        SCHED_YIELD => forward(ctx, Syscall::Yield),
        KILL => forward_sx(ctx, Syscall::Kill, 0b11),
        TKILL => forward_sx(ctx, Syscall::Tkill, 0b11),
        TGKILL => forward_sx(ctx, Syscall::Tgkill, 0b111),
        // kernel/signal.c: `compat_sys_rt_sigaction` reads a
        // `struct compat_sigaction` (the native handler checks
        // `in_ia32_syscall`); a `compat_sigset_t` is the same 8 bytes as
        // `sigset_t` on little-endian x86, so `rt_sigprocmask` is unchanged.
        RT_SIGACTION => forward(ctx, Syscall::RtSigaction),
        RT_SIGPROCMASK => forward_sx(ctx, Syscall::Sigprocmask, 0b1),
        // kernel/futex/syscalls.c: `sys_futex_time32` reads an
        // `old_timespec32` timeout, `sys_futex` (futex_time64) a
        // `__kernel_timespec`; `compat_sys_set_robust_list` takes the 12-byte
        // compat head (the native handler checks `in_ia32_syscall`).
        FUTEX => forward_abi(ctx, Syscall::Futex, 0, TIME32),
        FUTEX_TIME64 => forward(ctx, Syscall::Futex),
        SET_ROBUST_LIST => forward(ctx, Syscall::SetRobustList),
        // kernel/time/posix-timers.c: `clock_gettime32` writes an
        // `old_timespec32`, `clock_gettime` (the time64 entry) a
        // `__kernel_timespec`.
        CLOCK_GETTIME => forward_abi(ctx, Syscall::ClockGetTime, 0b1, TIME32),
        CLOCK_GETTIME64 => forward_sx(ctx, Syscall::ClockGetTime, 0b1),
        // fs/eventpoll.c, fs/eventfd.c: native entries (`struct epoll_event`
        // is packed on x86, so both ABIs share its 12-byte layout; the
        // epoll_pwait sigmask is a `sigset_t` either way; epoll_pwait2's
        // `compat_sys_epoll_pwait2` takes the 64-bit `__kernel_timespec`).
        EPOLL_CREATE => forward_sx(ctx, Syscall::EpollCreateLegacy, 0b1),
        EPOLL_CREATE1 => forward_sx(ctx, Syscall::EpollCreate, 0b1),
        EPOLL_CTL => forward_sx(ctx, Syscall::EpollCtl, 0b111),
        EPOLL_WAIT => forward_sx(ctx, Syscall::EpollWait, 0b1101),
        EPOLL_PWAIT => forward_sx(ctx, Syscall::EpollPwait, 0b1101),
        EPOLL_PWAIT2 => forward_sx(ctx, Syscall::EpollPwait2, 0b101),
        EVENTFD => forward(ctx, Syscall::EventfdLegacy),
        EVENTFD2 => forward_sx(ctx, Syscall::Eventfd, 0b10),
        // fs/namei.c
        MKNOD => forward(ctx, Syscall::Mknod),
        MKNODAT => forward_sx(ctx, Syscall::Mknodat, 0b1),
        // ipc/: the direct System V calls (i386 has had them since 5.1) and
        // the `ipc` multiplexer before them. `struct sembuf` is the same on
        // both ABIs; message buffers and the control structures are not, and
        // the native handlers convert them under `in_ia32_syscall()`.
        IPC => compat_sys_ipc(ctx),
        SEMGET => forward_sx(ctx, Syscall::Semget, 0b111),
        SEMCTL => {
            let a = *ctx.args();
            compat_semctl(ctx, a.arg0, a.arg1, a.arg2, a.arg3)
        }
        SEMTIMEDOP_TIME64 => forward_sx(ctx, Syscall::Semtimedop, 0b1),
        MSGGET => forward_sx(ctx, Syscall::Msgget, 0b11),
        MSGSND => forward_sx(ctx, Syscall::Msgsnd, 0b1101),
        MSGRCV => forward_sx(ctx, Syscall::Msgrcv, 0b11101),
        MSGCTL => {
            let a = *ctx.args();
            compat_msgctl(ctx, a.arg0, a.arg1, a.arg2)
        }
        SHMGET => forward_sx(ctx, Syscall::Shmget, 0b101),
        SHMAT => forward_sx(ctx, Syscall::Shmat, 0b101),
        SHMDT => forward(ctx, Syscall::Shmdt),
        SHMCTL => {
            let a = *ctx.args();
            compat_shmctl(ctx, a.arg0, a.arg1, a.arg2)
        }
        // net/socket.c, net/compat.c: the direct socket calls (i386 has had
        // them since 4.3) and the `socketcall` multiplexer before them.
        // `struct sockaddr` is the same on both ABIs; msghdr/mmsghdr, their
        // iovecs and control messages, and the old SO_*TIMEO timevals are
        // converted in `compat32::socket`.
        SOCKETCALL => super::socket::compat_socketcall(ctx),
        SOCKET => forward_sx(ctx, Syscall::SocketOpen, 0b111),
        SOCKETPAIR => forward_sx(ctx, Syscall::SocketPair, 0b111),
        BIND => forward_sx(ctx, Syscall::SocketBind, 0b101),
        CONNECT => forward_sx(ctx, Syscall::SocketConnect, 0b101),
        LISTEN => forward_sx(ctx, Syscall::SocketListen, 0b11),
        ACCEPT4 => forward_sx(ctx, Syscall::SocketAccept4, 0b1001),
        GETSOCKNAME => forward_sx(ctx, Syscall::SocketGetSockName, 0b1),
        GETPEERNAME => forward_sx(ctx, Syscall::SocketGetPeerName, 0b1),
        SENDTO => forward_sx(ctx, Syscall::SocketSend, 0b100001),
        RECVFROM => forward_sx(ctx, Syscall::SocketRecv, 0b1),
        SHUTDOWN => forward_sx(ctx, Syscall::SocketShutdown, 0b11),
        GETSOCKOPT => super::socket::compat_sockopt(ctx, false),
        SETSOCKOPT => super::socket::compat_sockopt(ctx, true),
        SENDMSG => {
            let a = *ctx.args();
            super::socket::compat_sendmsg(ctx, a.arg0, a.arg1, a.arg2)
        }
        RECVMSG => {
            let a = *ctx.args();
            super::socket::compat_recvmsg(ctx, a.arg0, a.arg1, a.arg2)
        }
        SENDMMSG => {
            let a = *ctx.args();
            super::socket::compat_sendmmsg(ctx, a.arg0, a.arg1, a.arg2, a.arg3)
        }
        RECVMMSG => {
            let a = *ctx.args();
            super::socket::compat_recvmmsg(ctx, a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, true)
        }
        RECVMMSG_TIME64 => {
            let a = *ctx.args();
            super::socket::compat_recvmmsg(ctx, a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, false)
        }
        // Native entries in syscall_32.tbl: the i386 call is the x86_64 one
        // with its signed C arguments sign-extended (`__SC_COMPAT_CAST`).
        // Generated from `include/linux/syscalls.h`.
        RESTART_SYSCALL => forward(ctx, Syscall::RestartSyscall),
        CREAT => forward(ctx, Syscall::Creat),
        LINK => forward(ctx, Syscall::Link),
        CHMOD => forward(ctx, Syscall::Chmod),
        MOUNT => forward(ctx, Syscall::Mount),
        ALARM => forward(ctx, Syscall::Alarm),
        PAUSE => forward(ctx, Syscall::Pause),
        SYNC => forward(ctx, Syscall::Sync),
        UMOUNT2 => forward_sx(ctx, Syscall::Umount2, 0b10),
        SETPGID => forward_sx(ctx, Syscall::Setpgid, 0b11),
        CHROOT => forward(ctx, Syscall::Chroot),
        GETPGRP => forward(ctx, Syscall::Getpgrp),
        SETSID => forward(ctx, Syscall::Setsid),
        SETHOSTNAME => forward_sx(ctx, Syscall::SetHostname, 0b10),
        SYMLINK => forward(ctx, Syscall::Symlink),
        REBOOT => forward_sx(ctx, Syscall::Reboot, 0b11),
        FCHMOD => forward(ctx, Syscall::Fchmod),
        GETPRIORITY => forward_sx(ctx, Syscall::Getpriority, 0b11),
        SETPRIORITY => forward_sx(ctx, Syscall::Setpriority, 0b111),
        SYSLOG => forward_sx(ctx, Syscall::Syslog, 0b101),
        VHANGUP => forward(ctx, Syscall::Vhangup),
        FSYNC => forward(ctx, Syscall::Fsync),
        SETDOMAINNAME => forward_sx(ctx, Syscall::Setdomainname, 0b10),
        INIT_MODULE => forward(ctx, Syscall::InitModule),
        DELETE_MODULE => forward(ctx, Syscall::DeleteModule),
        GETPGID => forward_sx(ctx, Syscall::Getpgid, 0b1),
        FCHDIR => forward(ctx, Syscall::Fchdir),
        FLOCK => forward(ctx, Syscall::Flock),
        MSYNC => forward_sx(ctx, Syscall::Msync, 0b100),
        GETSID => forward_sx(ctx, Syscall::Getsid, 0b1),
        FDATASYNC => forward(ctx, Syscall::Fdatasync),
        MLOCK => forward(ctx, Syscall::MLock),
        MUNLOCK => forward(ctx, Syscall::MUnlock),
        MLOCKALL => forward_sx(ctx, Syscall::Mlockall, 0b1),
        MUNLOCKALL => forward(ctx, Syscall::Munlockall),
        SCHED_SETPARAM => forward_sx(ctx, Syscall::SchedSetparam, 0b1),
        SCHED_GETPARAM => forward_sx(ctx, Syscall::SchedGetparam, 0b1),
        SCHED_SETSCHEDULER => forward_sx(ctx, Syscall::SchedSetScheduler, 0b11),
        SCHED_GETSCHEDULER => forward_sx(ctx, Syscall::SchedGetScheduler, 0b1),
        SCHED_GET_PRIORITY_MAX => forward_sx(ctx, Syscall::SchedGetPriorityMax, 0b1),
        SCHED_GET_PRIORITY_MIN => forward_sx(ctx, Syscall::SchedGetPriorityMin, 0b1),
        POLL => forward_sx(ctx, Syscall::Poll, 0b100),
        PRCTL => forward_sx(ctx, Syscall::Prctl, 0b1),
        CAPGET => forward(ctx, Syscall::Capget),
        CAPSET => forward(ctx, Syscall::Capset),
        LCHOWN32 => forward(ctx, Syscall::Lchown),
        SETREUID32 => forward(ctx, Syscall::Setreuid),
        SETREGID32 => forward(ctx, Syscall::Setregid),
        GETGROUPS32 => forward_sx(ctx, Syscall::Getgroups, 0b1),
        SETGROUPS32 => forward_sx(ctx, Syscall::Setgroups, 0b1),
        FCHOWN32 => forward(ctx, Syscall::Fchown),
        SETRESUID32 => forward(ctx, Syscall::Setresuid),
        SETRESGID32 => forward(ctx, Syscall::Setresgid),
        CHOWN32 => forward(ctx, Syscall::Chown),
        SETUID32 => forward(ctx, Syscall::SetUid),
        SETGID32 => forward(ctx, Syscall::SetGid),
        SETFSUID32 => forward(ctx, Syscall::Setfsuid),
        SETFSGID32 => forward(ctx, Syscall::Setfsgid),
        PIVOT_ROOT => forward(ctx, Syscall::PivotRoot),
        MINCORE => forward(ctx, Syscall::Mincore),
        SETXATTR => forward_sx(ctx, Syscall::Setxattr, 0b10000),
        LSETXATTR => forward_sx(ctx, Syscall::Lsetxattr, 0b10000),
        FSETXATTR => forward_sx(ctx, Syscall::Fsetxattr, 0b10001),
        GETXATTR => forward(ctx, Syscall::Getxattr),
        LGETXATTR => forward(ctx, Syscall::Lgetxattr),
        FGETXATTR => forward_sx(ctx, Syscall::Fgetxattr, 0b1),
        LISTXATTR => forward(ctx, Syscall::Listxattr),
        LLISTXATTR => forward(ctx, Syscall::Llistxattr),
        FLISTXATTR => forward_sx(ctx, Syscall::Flistxattr, 0b1),
        REMOVEXATTR => forward(ctx, Syscall::Removexattr),
        LREMOVEXATTR => forward(ctx, Syscall::Lremovexattr),
        FREMOVEXATTR => forward_sx(ctx, Syscall::Fremovexattr, 0b1),
        SENDFILE64 => forward_sx(ctx, Syscall::Sendfile, 0b11),
        IO_DESTROY => forward(ctx, Syscall::IoDestroy),
        IO_CANCEL => forward(ctx, Syscall::IoCancel),
        TIMER_GETOVERRUN => forward_sx(ctx, Syscall::TimerGetoverrun, 0b1),
        TIMER_DELETE => forward_sx(ctx, Syscall::TimerDelete, 0b1),
        MQ_UNLINK => forward(ctx, Syscall::MqUnlink),
        ADD_KEY => forward_sx(ctx, Syscall::AddKey, 0b10000),
        REQUEST_KEY => forward_sx(ctx, Syscall::RequestKey, 0b1000),
        IOPRIO_SET => forward_sx(ctx, Syscall::IoprioSet, 0b111),
        IOPRIO_GET => forward_sx(ctx, Syscall::IoprioGet, 0b11),
        INOTIFY_INIT => forward(ctx, Syscall::InotifyInit),
        INOTIFY_ADD_WATCH => forward_sx(ctx, Syscall::InotifyAddWatch, 0b1),
        INOTIFY_RM_WATCH => forward_sx(ctx, Syscall::InotifyRmWatch, 0b11),
        FCHOWNAT => forward_sx(ctx, Syscall::Fchownat, 0b10001),
        RENAMEAT => forward_sx(ctx, Syscall::Renameat, 0b101),
        LINKAT => forward_sx(ctx, Syscall::Linkat, 0b10101),
        SYMLINKAT => forward_sx(ctx, Syscall::Symlinkat, 0b10),
        FCHMODAT => forward_sx(ctx, Syscall::Fchmodat, 0b1),
        UNSHARE => forward(ctx, Syscall::Unshare),
        SPLICE => forward_sx(ctx, Syscall::Splice, 0b101),
        TEE => forward_sx(ctx, Syscall::Tee, 0b11),
        GETCPU => forward(ctx, Syscall::Getcpu),
        TIMERFD_CREATE => forward_sx(ctx, Syscall::TimerfdCreate, 0b11),
        INOTIFY_INIT1 => forward_sx(ctx, Syscall::InotifyInit1, 0b1),
        PERF_EVENT_OPEN => forward_sx(ctx, Syscall::PerfEventOpen, 0b1110),
        FANOTIFY_INIT => forward(ctx, Syscall::FanotifyInit),
        NAME_TO_HANDLE_AT => forward_sx(ctx, Syscall::NameToHandleAt, 0b10001),
        SYNCFS => forward_sx(ctx, Syscall::Syncfs, 0b1),
        SETNS => forward_sx(ctx, Syscall::Setns, 0b11),
        KCMP => forward_sx(ctx, Syscall::Kcmp, 0b111),
        FINIT_MODULE => forward_sx(ctx, Syscall::FinitModule, 0b101),
        SCHED_SETATTR => forward_sx(ctx, Syscall::SchedSetattr, 0b1),
        SCHED_GETATTR => forward_sx(ctx, Syscall::SchedGetattr, 0b1),
        RENAMEAT2 => forward_sx(ctx, Syscall::Renameat2, 0b101),
        MEMFD_CREATE => forward(ctx, Syscall::MemfdCreate),
        BPF => forward_sx(ctx, Syscall::Bpf, 0b1),
        MEMBARRIER => forward_sx(ctx, Syscall::Membarrier, 0b101),
        MLOCK2 => forward_sx(ctx, Syscall::Mlock2, 0b100),
        COPY_FILE_RANGE => forward_sx(ctx, Syscall::CopyFileRange, 0b101),
        PKEY_MPROTECT => forward_sx(ctx, Syscall::PkeyMprotect, 0b1000),
        PKEY_ALLOC => forward(ctx, Syscall::PkeyAlloc),
        PKEY_FREE => forward_sx(ctx, Syscall::PkeyFree, 0b1),
        CLOCK_SETTIME64 => forward_sx(ctx, Syscall::ClockSetTime, 0b1),
        CLOCK_ADJTIME64 => forward_sx(ctx, Syscall::ClockAdjtime, 0b1),
        CLOCK_GETRES_TIME64 => forward_sx(ctx, Syscall::ClockGetres, 0b1),
        CLOCK_NANOSLEEP_TIME64 => forward_sx(ctx, Syscall::ClockNanosleep, 0b11),
        TIMER_GETTIME64 => forward_sx(ctx, Syscall::TimerGettime, 0b1),
        TIMER_SETTIME64 => forward_sx(ctx, Syscall::TimerSettime, 0b11),
        TIMERFD_GETTIME64 => forward_sx(ctx, Syscall::TimerfdGettime, 0b1),
        TIMERFD_SETTIME64 => forward_sx(ctx, Syscall::TimerfdSettime, 0b11),
        UTIMENSAT_TIME64 => forward_sx(ctx, Syscall::Utimensat, 0b1001),
        MQ_TIMEDSEND_TIME64 => forward_sx(ctx, Syscall::MqTimedsend, 0b1),
        MQ_TIMEDRECEIVE_TIME64 => forward_sx(ctx, Syscall::MqTimedreceive, 0b1),
        SCHED_RR_GET_INTERVAL_TIME64 => forward_sx(ctx, Syscall::SchedRrGetInterval, 0b1),
        PIDFD_SEND_SIGNAL => forward_sx(ctx, Syscall::PidfdSendSignal, 0b11),
        OPEN_TREE => forward_sx(ctx, Syscall::OpenTree, 0b1),
        MOVE_MOUNT => forward_sx(ctx, Syscall::MoveMount, 0b101),
        FSOPEN => forward(ctx, Syscall::Fsopen),
        FSCONFIG => forward_sx(ctx, Syscall::Fsconfig, 0b10001),
        FSMOUNT => forward_sx(ctx, Syscall::Fsmount, 0b1),
        FSPICK => forward_sx(ctx, Syscall::Fspick, 0b1),
        PIDFD_OPEN => forward_sx(ctx, Syscall::PidfdOpen, 0b1),
        CLOSE_RANGE => forward(ctx, Syscall::CloseRange),
        OPENAT2 => forward_sx(ctx, Syscall::Openat2, 0b1),
        PIDFD_GETFD => forward_sx(ctx, Syscall::PidfdGetfd, 0b11),
        MOUNT_SETATTR => forward_sx(ctx, Syscall::MountSetattr, 0b1),
        LANDLOCK_CREATE_RULESET => forward(ctx, Syscall::LandlockCreateRuleset),
        LANDLOCK_ADD_RULE => forward_sx(ctx, Syscall::LandlockAddRule, 0b1),
        LANDLOCK_RESTRICT_SELF => forward_sx(ctx, Syscall::LandlockRestrictSelf, 0b1),
        MEMFD_SECRET => forward(ctx, Syscall::MemfdSecret),
        PROCESS_MRELEASE => forward_sx(ctx, Syscall::ProcessMrelease, 0b1),
        FUTEX_WAITV => forward_sx(ctx, Syscall::FutexWaitv, 0b10000),
        SET_MEMPOLICY_HOME_NODE => forward(ctx, Syscall::SetMempolicyHomeNode),
        CACHESTAT => forward(ctx, Syscall::Cachestat),
        FCHMODAT2 => forward_sx(ctx, Syscall::Fchmodat2, 0b1),
        FUTEX_WAKE => forward_sx(ctx, Syscall::FutexWake, 0b100),
        FUTEX_WAIT => forward_sx(ctx, Syscall::FutexWait, 0b100000),
        FUTEX_REQUEUE => forward_sx(ctx, Syscall::FutexRequeue, 0b1100),
        STATMOUNT => forward(ctx, Syscall::Statmount),
        LISTMOUNT => forward(ctx, Syscall::Listmount),
        LSM_GET_SELF_ATTR => forward(ctx, Syscall::LsmGetSelfAttr),
        LSM_SET_SELF_ATTR => forward(ctx, Syscall::LsmSetSelfAttr),
        LSM_LIST_MODULES => forward(ctx, Syscall::LsmListModules),
        MSEAL => forward(ctx, Syscall::Mseal),
        SETXATTRAT => forward_sx(ctx, Syscall::Setxattrat, 0b1),
        GETXATTRAT => forward_sx(ctx, Syscall::Getxattrat, 0b1),
        LISTXATTRAT => forward_sx(ctx, Syscall::Listxattrat, 0b1),
        REMOVEXATTRAT => forward_sx(ctx, Syscall::Removexattrat, 0b1),
        OPEN_TREE_ATTR => forward_sx(ctx, Syscall::OpenTreeAttr, 0b1),
        FILE_GETATTR => forward_sx(ctx, Syscall::FileGetattr, 0b1),
        FILE_SETATTR => forward_sx(ctx, Syscall::FileSetattr, 0b1),
        LISTNS => forward(ctx, Syscall::Listns),
        // Compat structures, 32-bit times and split 64-bit arguments
        // (`compat_sys_*`, `sys_ia32_*`), converted in `compat32::misc`.
        TIME => super::misc::time32(ctx),
        GETTIMEOFDAY => super::misc::timeofday(ctx, false),
        SETTIMEOFDAY => super::misc::timeofday(ctx, true),
        TIMES => super::misc::times(ctx),
        GETRLIMIT => super::misc::getrlimit(ctx, true),
        UGETRLIMIT => super::misc::getrlimit(ctx, false),
        SETRLIMIT => super::misc::setrlimit(ctx),
        GETRUSAGE => super::misc::getrusage(ctx),
        WAIT4 => super::misc::wait4(ctx),
        WAITID => super::misc::waitid(ctx),
        STATFS => super::misc::statfs(ctx, false, false),
        FSTATFS => super::misc::statfs(ctx, true, false),
        STATFS64 => super::misc::statfs(ctx, false, true),
        FSTATFS64 => super::misc::statfs(ctx, true, true),
        SYSINFO => super::misc::sysinfo(ctx),
        TRUNCATE | FTRUNCATE | TRUNCATE64 | FTRUNCATE64 | FALLOCATE | FADVISE64 | FADVISE64_64
        | READAHEAD | SYNC_FILE_RANGE => super::misc::split_offsets(ctx, nr),
        PREADV => super::misc::preadv(ctx, Syscall::Preadv, false),
        PWRITEV => super::misc::preadv(ctx, Syscall::Pwritev, false),
        PREADV2 => super::misc::preadv(ctx, Syscall::Preadv2, true),
        PWRITEV2 => super::misc::preadv(ctx, Syscall::Pwritev2, true),
        SENDFILE => super::misc::sendfile32(ctx),
        SIGALTSTACK => super::misc::sigaltstack(ctx),
        SELECT | NEWSELECT | PSELECT6 | PSELECT6_TIME64 => super::misc::select(ctx, nr),
        PPOLL => super::misc::ppoll_time32(ctx),
        // `struct pollfd` and the sigset are shared; the timeout is 64-bit.
        PPOLL_TIME64 => forward(ctx, Syscall::Ppoll),
        // A `compat_sigset_t` has the bytes of the native 64-signal set.
        RT_SIGPENDING => forward(ctx, Syscall::RtSigpending),
        RT_SIGSUSPEND => forward(ctx, Syscall::RtSigsuspend),
        SIGNALFD => {
            let a = *ctx.args();
            let args = SyscallArgs {
                arg0: conv::sext(a.arg0),
                arg1: a.arg1,
                arg2: a.arg2,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            };
            forward_args(ctx, Syscall::Signalfd, args, Ia32Abi::default())
        }
        SIGNALFD4 => forward_sx(ctx, Syscall::Signalfd, 0b1001),
        // `compat_get_user_cpu_mask` reads `len` bytes of 32-bit words: the
        // same bytes the native handler copies.
        SCHED_SETAFFINITY => forward_sx(ctx, Syscall::SchedSetaffinity, 0b1),
        // The `*_time32` entries (`old_timespec32`, `old_timeval32`,
        // `old_utimbuf32`), in `compat32::legacy`.
        NANOSLEEP
        | CLOCK_NANOSLEEP
        | CLOCK_SETTIME
        | CLOCK_GETRES
        | TIMER_SETTIME
        | TIMER_GETTIME
        | TIMERFD_SETTIME
        | TIMERFD_GETTIME
        | UTIMENSAT
        | FUTIMESAT
        | UTIMES
        | UTIME
        | SCHED_RR_GET_INTERVAL
        | IO_GETEVENTS
        | MQ_TIMEDSEND
        | MQ_TIMEDRECEIVE => super::legacy::time32_nr(ctx, nr),
        // kernel/uid16.c: `low2highuid` in, `high2lowuid` out.
        CHOWN => super::legacy::set_ids16(ctx, Syscall::Chown, 0b110),
        LCHOWN => super::legacy::set_ids16(ctx, Syscall::Lchown, 0b110),
        FCHOWN => super::legacy::set_ids16(ctx, Syscall::Fchown, 0b110),
        SETUID => super::legacy::set_ids16(ctx, Syscall::SetUid, 0b1),
        SETGID => super::legacy::set_ids16(ctx, Syscall::SetGid, 0b1),
        SETREUID => super::legacy::set_ids16(ctx, Syscall::Setreuid, 0b11),
        SETREGID => super::legacy::set_ids16(ctx, Syscall::Setregid, 0b11),
        SETRESUID => super::legacy::set_ids16(ctx, Syscall::Setresuid, 0b111),
        SETRESGID => super::legacy::set_ids16(ctx, Syscall::Setresgid, 0b111),
        SETFSUID => super::legacy::set_ids16(ctx, Syscall::Setfsuid, 0b1),
        SETFSGID => super::legacy::set_ids16(ctx, Syscall::Setfsgid, 0b1),
        GETRESUID => super::legacy::getres_ids16(ctx, Syscall::Getresuid),
        GETRESGID => super::legacy::getres_ids16(ctx, Syscall::Getresgid),
        GETGROUPS => super::legacy::getgroups16(ctx),
        SETGROUPS => super::legacy::setgroups16(ctx),
        _ => {
            ctx.set_return(SyscallReturn::not_implemented());
            None
        }
    }
}

/// The y2038-limited entry points' layout choice.
const TIME32: Ia32Abi = Ia32Abi {
    time32: true,
    flock: crate::syscall::Ia32Flock::Native,
};

/// Serve an i386 call with the native handler for `variant`: the context's
/// six arguments are already ebx, ecx, edx, esi, edi, ebp zero-extended.
pub fn forward(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    crate::syscall::dispatch_native(variant, ctx);
    Some(variant)
}

/// [`forward`] with the arguments `signed` names sign-extended.
fn forward_sx(ctx: &mut dyn TrapContext, variant: Syscall, signed: u8) -> Option<Syscall> {
    forward_abi(ctx, variant, signed, Ia32Abi::default())
}

/// [`forward_sx`] that also tells the native handler which i386 layout to
/// use where `in_ia32_syscall()` alone does not decide it.
fn forward_abi(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    signed: u8,
    abi: Ia32Abi,
) -> Option<Syscall> {
    let args = signed_args(ctx.args(), signed);
    forward_args(ctx, variant, args, abi)
}

/// Serve an i386 call with `variant`'s native handler on `args`.
pub(super) fn forward_args(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    args: SyscallArgs,
    abi: Ia32Abi,
) -> Option<Syscall> {
    let mut native = Ia32ArgsCtx::forwarding(ctx, args, abi);
    crate::syscall::dispatch_native(variant, &mut native);
    Some(variant)
}

/// Run `variant`'s native handler on `args` and hand back its return
/// without writing it to `ctx` (`None`: it set none and parked to
/// re-execute the call).
pub(super) fn call_native(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    args: SyscallArgs,
    abi: Ia32Abi,
) -> Option<SyscallReturn> {
    let mut native = Ia32ArgsCtx::capturing(ctx, args, abi);
    crate::syscall::dispatch_native(variant, &mut native);
    native.take_return()
}

// ── processes ────────────────────────────────────────────────────────

/// `clone(flags, newsp, parent_tidptr, tls, child_tidptr)` (i386 120,
/// `compat_sys_ia32_clone`): the 32-bit ABI is CONFIG_CLONE_BACKWARDS, TLS
/// before the child tid where x86_64's `clone` takes the child tid first,
/// so the two swap on the way to the native handler. `tls` is then a
/// `struct user_desc` pointer, which the handler sees through
/// `in_ia32_syscall()`. The flags are `unsigned long`: zero-extended.
fn compat_sys_ia32_clone(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let a = *ctx.args();
    let args = SyscallArgs {
        arg3: a.arg4,
        arg4: a.arg3,
        ..a
    };
    forward_args(ctx, Syscall::Clone, args, Ia32Abi::default())
}

/// `waitpid(pid, stat_addr, options)` (i386 7): `kernel_wait4` with no
/// rusage. `pid` and `options` are `int`.
fn sys_waitpid(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let a = *ctx.args();
    let args = SyscallArgs {
        arg0: conv::sext(a.arg0),
        arg1: a.arg1,
        arg2: conv::sext(a.arg2),
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    forward_args(ctx, Syscall::Wait4, args, Ia32Abi::default())
}

/// `args` with the arguments `signed` names sign-extended from 32 bits.
fn signed_args(args: &SyscallArgs, signed: u8) -> SyscallArgs {
    let pick = |i: u8, v: u64| {
        if signed & (1 << i) != 0 {
            conv::sext(v)
        } else {
            v
        }
    };
    SyscallArgs {
        arg0: pick(0, args.arg0),
        arg1: pick(1, args.arg1),
        arg2: pick(2, args.arg2),
        arg3: pick(3, args.arg3),
        arg4: pick(4, args.arg4),
        arg5: pick(5, args.arg5),
    }
}

/// Is `ret` a success (not an errno)?
#[inline]
pub(super) fn succeeded(ret: &SyscallReturn) -> bool {
    ret.status == SyscallReturn::OK && (ret.value as i64) >= 0
}

// ── System V IPC ─────────────────────────────────────────────────────

/// `IPC_64`, the flag an i386 libc ORs into a control command to ask for the
/// `*id64_ds` layouts.
const IPC_64: u32 = 0x100;

/// `compat_ipc_parse_version`: the command without `IPC_64`. Without the
/// flag a structured command means the pre-2.4 layouts (`struct
/// compat_semid_ds` and friends, with 16-bit ids), which NARF does not
/// convert: `None`, and the call answers EINVAL. `structured` lists the
/// commands whose structure depends on the version.
fn ipc_compat_cmd(cmd: u64, structured: &[u32]) -> Option<u64> {
    let raw = cmd as u32;
    let base = raw & !IPC_64;
    if raw & IPC_64 == 0 && structured.contains(&base) {
        None
    } else {
        Some(u64::from(base))
    }
}

/// `semctl(semid, semnum, cmd, arg)` (i386 394, `compat_sys_semctl`). `arg`
/// is the `union semun` word: SETVAL's value or a pointer. IPC_STAT,
/// SEM_STAT(_ANY) and IPC_SET move a `compat_semid64_ds`.
fn compat_semctl(
    ctx: &mut dyn TrapContext,
    semid: u64,
    semnum: u64,
    cmd: u64,
    arg: u64,
) -> Option<Syscall> {
    const STRUCTURED: [u32; 4] = [1, 2, 18, 20]; // IPC_SET, IPC_STAT, SEM_STAT, SEM_STAT_ANY
    let Some(cmd) = ipc_compat_cmd(cmd, &STRUCTURED) else {
        ctx.set_return(to_ret(EINVAL));
        return Some(Syscall::Semctl);
    };
    let args = SyscallArgs {
        arg0: conv::sext(semid),
        arg1: conv::sext(semnum),
        arg2: cmd,
        arg3: arg,
        arg4: 0,
        arg5: 0,
    };
    forward_args(ctx, Syscall::Semctl, args, Ia32Abi::default())
}

/// `msgctl(msqid, cmd, buf)` (i386 402, `compat_sys_msgctl`): IPC_STAT,
/// MSG_STAT(_ANY) and IPC_SET move a `compat_msqid64_ds`; `struct msginfo`
/// is all ints, the same on both ABIs.
fn compat_msgctl(ctx: &mut dyn TrapContext, msqid: u64, cmd: u64, buf: u64) -> Option<Syscall> {
    const STRUCTURED: [u32; 4] = [1, 2, 11, 13]; // IPC_SET, IPC_STAT, MSG_STAT, MSG_STAT_ANY
    let Some(cmd) = ipc_compat_cmd(cmd, &STRUCTURED) else {
        ctx.set_return(to_ret(EINVAL));
        return Some(Syscall::Msgctl);
    };
    let args = SyscallArgs {
        arg0: conv::sext(msqid),
        arg1: cmd,
        arg2: buf,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    forward_args(ctx, Syscall::Msgctl, args, Ia32Abi::default())
}

/// `shmctl(shmid, cmd, buf)` (i386 396, `compat_sys_shmctl`): IPC_STAT,
/// SHM_STAT(_ANY) and IPC_SET move a `compat_shmid64_ds`, IPC_INFO a
/// `compat_shminfo64`, SHM_INFO a `compat_shm_info`.
fn compat_shmctl(ctx: &mut dyn TrapContext, shmid: u64, cmd: u64, buf: u64) -> Option<Syscall> {
    // IPC_SET, IPC_STAT, IPC_INFO, SHM_STAT, SHM_STAT_ANY
    const STRUCTURED: [u32; 5] = [1, 2, 3, 13, 15];
    let Some(cmd) = ipc_compat_cmd(cmd, &STRUCTURED) else {
        ctx.set_return(to_ret(EINVAL));
        return Some(Syscall::Shmctl);
    };
    let args = SyscallArgs {
        arg0: conv::sext(shmid),
        arg1: cmd,
        arg2: buf,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    forward_args(ctx, Syscall::Shmctl, args, Ia32Abi::default())
}

/// `ipc(call, first, second, third, ptr, fifth)` (i386 117,
/// `compat_sys_ipc`): the System V IPC multiplexer an i386 libc built for
/// kernels before 5.1 calls for every operation. `call`'s upper half is the
/// interface version: version 0 `msgrcv` passes its buffer and type through
/// a `struct compat_ipc_kludge` at `ptr`, version 1 `shmat` is refused.
fn compat_sys_ipc(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    const SEMOP: u64 = 1;
    const SEMGET: u64 = 2;
    const SEMCTL: u64 = 3;
    const SEMTIMEDOP: u64 = 4;
    const MSGSND: u64 = 11;
    const MSGRCV: u64 = 12;
    const MSGGET: u64 = 13;
    const MSGCTL: u64 = 14;
    const SHMAT: u64 = 21;
    const SHMDT: u64 = 22;
    const SHMGET: u64 = 23;
    const SHMCTL: u64 = 24;
    let a = *ctx.args();
    let version = (a.arg0 >> 16) & 0xFFFF;
    let call = a.arg0 & 0xFFFF;
    let (first, second, third, ptr, fifth) = (a.arg1, a.arg2, a.arg3, a.arg4, a.arg5);
    let args = |arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64| SyscallArgs {
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5: 0,
    };
    let none = Ia32Abi::default();
    let sx = conv::sext;
    match call {
        SEMOP => forward_args(
            ctx,
            Syscall::Semop,
            args(sx(first), ptr, second, 0, 0),
            none,
        ),
        SEMTIMEDOP => {
            let args = args(sx(first), ptr, second, fifth, 0);
            forward_args(ctx, Syscall::Semtimedop, args, TIME32)
        }
        SEMGET => {
            let args = args(sx(first), sx(second), sx(third), 0, 0);
            forward_args(ctx, Syscall::Semget, args, none)
        }
        SEMCTL => {
            // The `union semun` comes by reference: `get_user(pad, ptr)`.
            if ptr == 0 {
                ctx.set_return(to_ret(EINVAL));
                return Some(Syscall::Semctl);
            }
            let mut pad = [0u8; 4];
            if let Err(e) = conv::read_user(ptr, &mut pad) {
                ctx.set_return(to_ret(e));
                return Some(Syscall::Semctl);
            }
            compat_semctl(
                ctx,
                first,
                second,
                third,
                u64::from(u32::from_le_bytes(pad)),
            )
        }
        MSGSND => {
            let args = args(sx(first), ptr, sx(second), sx(third), 0);
            forward_args(ctx, Syscall::Msgsnd, args, none)
        }
        MSGRCV => {
            if (first as u32 as i32) < 0 || (second as u32 as i32) < 0 {
                ctx.set_return(to_ret(EINVAL));
                return Some(Syscall::Msgrcv);
            }
            let (msgp, msgtyp) = if version == 0 {
                // struct compat_ipc_kludge { compat_uptr_t msgp; compat_long_t msgtyp; }
                if ptr == 0 {
                    ctx.set_return(to_ret(EINVAL));
                    return Some(Syscall::Msgrcv);
                }
                let mut kludge = [0u8; 8];
                if let Err(e) = conv::read_user(ptr, &mut kludge) {
                    ctx.set_return(to_ret(e));
                    return Some(Syscall::Msgrcv);
                }
                (
                    u64::from(conv::word(&kludge, 0)),
                    sx(u64::from(conv::word(&kludge, 1))),
                )
            } else {
                (ptr, sx(fifth))
            };
            let args = args(sx(first), msgp, sx(second), msgtyp, sx(third));
            forward_args(ctx, Syscall::Msgrcv, args, none)
        }
        MSGGET => forward_args(
            ctx,
            Syscall::Msgget,
            args(sx(first), sx(second), 0, 0, 0),
            none,
        ),
        MSGCTL => compat_msgctl(ctx, first, second, ptr),
        SHMAT => {
            if version == 1 {
                ctx.set_return(to_ret(EINVAL));
                return Some(Syscall::Shmat);
            }
            // `do_shmat`, then `put_user(raddr, (compat_ulong_t *)third)`.
            let Some(ret) = call_native(
                ctx,
                Syscall::Shmat,
                args(sx(first), ptr, sx(second), 0, 0),
                none,
            ) else {
                return Some(Syscall::Shmat);
            };
            if !succeeded(&ret) {
                ctx.set_return(ret);
                return Some(Syscall::Shmat);
            }
            ctx.set_return(
                match conv::write_user(third, &(ret.value as u32).to_le_bytes()) {
                    Ok(()) => SyscallReturn::ok(0),
                    Err(e) => to_ret(e),
                },
            );
            Some(Syscall::Shmat)
        }
        SHMDT => forward_args(ctx, Syscall::Shmdt, args(ptr, 0, 0, 0, 0), none),
        SHMGET => {
            // `ksys_shmget(first, (unsigned int)second, third)`.
            let args = args(sx(first), second, sx(third), 0, 0);
            forward_args(ctx, Syscall::Shmget, args, none)
        }
        SHMCTL => compat_shmctl(ctx, first, second, ptr),
        _ => {
            ctx.set_return(SyscallReturn::not_implemented());
            None
        }
    }
}

// ── mm ───────────────────────────────────────────────────────────────

/// `mmap2(addr, len, prot, flags, fd, pgoff)` (i386 192, `sys_mmap_pgoff`):
/// the offset is in 4096-byte units, which is what lets a 32-bit task map
/// past 4 GiB of a file. `fd` is `unsigned long` there; -1 is 0xFFFFFFFF.
fn sys_mmap_pgoff(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let a = *ctx.args();
    compat_mmap(ctx, a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, a.arg5 << 12)
}

/// `mmap(struct mmap_arg_struct32 *arg)` (i386 90,
/// `compat_sys_ia32_mmap`): the pre-mmap2 entry, six 32-bit words in user
/// memory because i386 once had only four syscall argument registers.
///
/// ```text
/// if (copy_from_user(&a, arg, sizeof(a))) return -EFAULT;
/// if (a.offset & ~PAGE_MASK) return -EINVAL;
/// return ksys_mmap_pgoff(a.addr, a.len, a.prot, a.flags, a.fd,
///                        a.offset >> PAGE_SHIFT);
/// ```
fn compat_sys_ia32_mmap(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let mut raw = [0u8; 24];
    if let Err(errno) = conv::read_user(ctx.args().arg0, &mut raw) {
        ctx.set_return(to_ret(errno));
        return None;
    }
    let w = |i| u64::from(conv::word(&raw, i));
    let offset = w(5);
    if offset & 0xFFF != 0 {
        ctx.set_return(to_ret(EINVAL));
        return None;
    }
    compat_mmap(ctx, w(0), w(1), w(2), w(3), w(4), offset)
}

/// The shared tail of the two i386 mmap entries: the native mmap with a
/// byte offset, inside `TASK_SIZE_32`.
///
/// Linux's `__get_unmapped_area` uses `TASK_SIZE`, which is `TASK_SIZE_32`
/// for the task (`TIF_ADDR32`): a fixed range past it is ENOMEM, and a hint
/// that cannot hold the mapping is ignored (`mmap_address_hint_valid`).
/// Inside an IA-32 address space the native placement already stays below
/// 4 GiB; a 64-bit task issuing `int 0x80` has no such window, so an
/// address it is handed above `TASK_SIZE_32` (unrepresentable in eax) is
/// unmapped again and the call answers ENOMEM. (Linux would place that
/// mapping from `mmap_compat_base` instead.)
fn compat_mmap(
    ctx: &mut dyn TrapContext,
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> Option<Syscall> {
    const MAP_FIXED: u64 = 0x10;
    const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
    let task_size = AddressSpace::COMPAT32_TASK_SIZE;
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    let len_pages = len.saturating_add(0xFFF) & !0xFFF;
    if len != 0 && fixed && addr.saturating_add(len_pages) > task_size {
        ctx.set_return(to_ret(ENOMEM));
        return Some(Syscall::Mmap);
    }
    let hint = if !fixed && addr.saturating_add(len_pages) > task_size {
        0
    } else {
        addr
    };
    let args = SyscallArgs {
        arg0: hint,
        arg1: len,
        arg2: prot,
        arg3: flags,
        arg4: conv::sext(fd),
        arg5: offset,
    };
    let Some(ret) = call_native(ctx, Syscall::Mmap, args, Ia32Abi::default()) else {
        return Some(Syscall::Mmap);
    };
    if succeeded(&ret) && ret.value.saturating_add(len_pages) > task_size {
        let undo = SyscallArgs {
            arg0: ret.value,
            arg1: len_pages,
            ..SyscallArgs::default()
        };
        let _ = call_native(ctx, Syscall::Munmap, undo, Ia32Abi::default());
        ctx.set_return(to_ret(ENOMEM));
    } else {
        ctx.set_return(ret);
    }
    Some(Syscall::Mmap)
}

// ── files ────────────────────────────────────────────────────────────

/// `_llseek(fd, offset_high, offset_low, loff_t *result, whence)` (i386 140,
/// `sys_llseek`):
///
/// ```text
/// offset = vfs_llseek(fd_file(f), ((loff_t) offset_high << 32) | offset_low,
///                     whence);
/// retval = (int)offset;
/// if (offset >= 0) {
///         retval = -EFAULT;
///         if (!copy_to_user(result, &offset, sizeof(offset)))
///                 retval = 0;
/// }
/// ```
fn sys_llseek(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let a = *ctx.args();
    let args = SyscallArgs {
        arg0: a.arg0,
        arg1: (a.arg1 << 32) | (a.arg2 & 0xFFFF_FFFF),
        arg2: a.arg4,
        ..SyscallArgs::default()
    };
    let Some(ret) = call_native(ctx, Syscall::Lseek, args, Ia32Abi::default()) else {
        return Some(Syscall::Lseek);
    };
    if !succeeded(&ret) {
        ctx.set_return(ret);
        return Some(Syscall::Lseek);
    }
    match conv::write_user(a.arg3, &ret.value.to_le_bytes()) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(errno) => ctx.set_return(to_ret(errno)),
    }
    Some(Syscall::Lseek)
}

/// `sys_ia32_pread64(fd, buf, count, poslo, poshi)` and its pwrite twin
/// (`arch/x86/kernel/sys_ia32.c`): the position is
/// `((u64)poshi << 32) | poslo`.
fn sys_ia32_pread_pwrite(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    let a = *ctx.args();
    let args = SyscallArgs {
        arg0: a.arg0,
        arg1: a.arg1,
        arg2: a.arg2,
        arg3: (a.arg4 << 32) | (a.arg3 & 0xFFFF_FFFF),
        ..SyscallArgs::default()
    };
    forward_args(ctx, variant, args, Ia32Abi::default())
}

/// `compat_sys_fcntl64(fd, cmd, arg)` / `compat_sys_fcntl` (`fs/fcntl.c`,
/// `do_compat_fcntl64`). The record-lock commands carry an i386 structure:
/// F_GETLK/F_SETLK/F_SETLKW a `struct compat_flock` (32-bit offsets),
/// F_GETLK64/F_SETLK64/F_SETLKW64 (12-14, renamed to 5-7 by
/// `convert_fcntl_cmd`) and the F_OFD_* commands a packed
/// `struct compat_flock64`. The plain `fcntl` (55) refuses the 64-bit lock
/// commands with EINVAL. `F_SETOWN`'s argument is an `int` (a negative one
/// names a process group); every other argument passes as the register.
fn compat_sys_fcntl64(ctx: &mut dyn TrapContext, fcntl64: bool) -> Option<Syscall> {
    const F_GETLK: u32 = 5;
    const F_SETLK: u32 = 6;
    const F_SETLKW: u32 = 7;
    const F_SETOWN: u32 = 8;
    const F_GETLK64: u32 = 12;
    const F_SETLK64: u32 = 13;
    const F_SETLKW64: u32 = 14;
    const F_OFD_GETLK: u32 = 36;
    const F_OFD_SETLK: u32 = 37;
    const F_OFD_SETLKW: u32 = 38;
    let cmd = ctx.args().arg1 as u32;
    let (native_cmd, flock) = match cmd {
        F_GETLK | F_SETLK | F_SETLKW => (cmd, Ia32Flock::Compat),
        F_GETLK64 | F_SETLK64 | F_SETLKW64 => (cmd - (F_GETLK64 - F_GETLK), Ia32Flock::Compat64),
        F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => (cmd, Ia32Flock::Compat64),
        _ => (cmd, Ia32Flock::Native),
    };
    if !fcntl64 && flock == Ia32Flock::Compat64 {
        ctx.set_return(to_ret(EINVAL));
        return Some(Syscall::Fcntl);
    }
    let mut args = *ctx.args();
    args.arg1 = u64::from(native_cmd);
    if native_cmd == F_SETOWN {
        args.arg2 = conv::sext(args.arg2);
    }
    let abi = Ia32Abi {
        time32: false,
        flock,
    };
    forward_args(ctx, Syscall::Fcntl, args, abi)
}

// ── identity and arch ────────────────────────────────────────────────

/// `DEFAULT_OVERFLOWUID` / `DEFAULT_OVERFLOWGID`: what a 16-bit uid call
/// reports for an id that does not fit 16 bits.
const OVERFLOW_ID: u64 = 65534;

/// `sys_getuid16` and its siblings: the 32-bit answer through
/// `high2lowuid` / `high2lowgid`.
fn uid16(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    let args = *ctx.args();
    let Some(ret) = call_native(ctx, variant, args, Ia32Abi::default()) else {
        return Some(variant);
    };
    if succeeded(&ret) && ret.value > 0xFFFF {
        ctx.set_return(SyscallReturn::ok(OVERFLOW_ID));
    } else {
        ctx.set_return(ret);
    }
    Some(variant)
}

/// `arch_prctl(option, arg2)` from an i386 call (`arch/x86/kernel/
/// process.c`): the CPUID-faulting and XSTATE-permission options are
/// served as for a 64-bit task; everything else — the FS/GS base
/// operations above all — is `-EINVAL` when `in_ia32_syscall()`.
fn sys_arch_prctl(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    const ARCH_GET_CPUID: u64 = 0x1011;
    const ARCH_SET_CPUID: u64 = 0x1012;
    const ARCH_GET_XCOMP_SUPP: u64 = 0x1021;
    const ARCH_GET_XCOMP_PERM: u64 = 0x1022;
    const ARCH_REQ_XCOMP_PERM: u64 = 0x1023;
    const ARCH_GET_XCOMP_GUEST_PERM: u64 = 0x1024;
    const ARCH_REQ_XCOMP_GUEST_PERM: u64 = 0x1025;
    match ctx.args().arg0 {
        ARCH_GET_CPUID
        | ARCH_SET_CPUID
        | ARCH_GET_XCOMP_SUPP
        | ARCH_GET_XCOMP_PERM
        | ARCH_REQ_XCOMP_PERM
        | ARCH_GET_XCOMP_GUEST_PERM
        | ARCH_REQ_XCOMP_GUEST_PERM => forward(ctx, Syscall::ArchPrctl),
        _ => {
            ctx.set_return(to_ret(EINVAL));
            Some(Syscall::ArchPrctl)
        }
    }
}

// ── ioctl ────────────────────────────────────────────────────────────

/// `FS_IOC32_GETFLAGS` / `FS_IOC32_SETFLAGS`: the i386 spelling of the
/// inode-flags ioctls, whose `long` size field is 4 there.
const FS_IOC32_GETFLAGS: u32 = 0x8004_6601;
const FS_IOC32_SETFLAGS: u32 = 0x4004_6602;
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;

/// `compat_sys_ioctl(fd, cmd, arg)` (`fs/ioctl.c`): the inode-flags pair is
/// renamed to its 64-bit numbers, the commands whose argument has the same
/// layout in both ABIs go to the native handler, and anything else — whose
/// structure would have to be converted by a `compat_ioctl` NARF does not
/// have yet (DRM, evdev, sockets, ...) — is ENOTTY, after the EBADF check
/// `CLASS(fd, f)` makes first.
fn compat_sys_ioctl(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let cmd = ctx.args().arg1 as u32;
    let native_cmd = match cmd {
        FS_IOC32_GETFLAGS => FS_IOC_GETFLAGS,
        FS_IOC32_SETFLAGS => FS_IOC_SETFLAGS,
        c if ioctl_layout_compatible(c) => c,
        _ => {
            let fd = ctx.args().arg0 as u32;
            let open =
                crate::fd::with_table(crate::handlers::current_task_id(), |t| t.get(fd).is_some())
                    .unwrap_or(false);
            ctx.set_return(to_ret(if open { ENOTTY } else { EBADF }));
            return Some(Syscall::Ioctl);
        }
    };
    let mut args = *ctx.args();
    args.arg1 = u64::from(native_cmd);
    forward_args(ctx, Syscall::Ioctl, args, Ia32Abi::default())
}

/// Commands `compat_sys_ioctl` serves unchanged: `do_vfs_ioctl`'s generic
/// file commands and the tty/termios family (`tty_compat_ioctl` passes these
/// to `tty_ioctl`), whose arguments are ints, `struct termio(s|s2)` or
/// `struct winsize` — identical on i386 and x86_64. `TIOCGSERIAL`/
/// `TIOCSSERIAL` (0x541E/0x541F) are not: `struct serial_struct` holds a
/// pointer.
fn ioctl_layout_compatible(cmd: u32) -> bool {
    matches!(
        cmd,
        // TCGETS .. TIOCCONS
        0x5401..=0x541D
        // TIOCPKT, FIONBIO, TIOCNOTTY, TIOCSETD, TIOCGETD, TCSBRKP,
        // TIOCSBRK, TIOCCBRK, TIOCGSID
        | 0x5420..=0x5429
        // TCGETS2, TCSETS2, TCSETSW2, TCSETSF2
        | 0x802C_542A
        | 0x402C_542B
        | 0x402C_542C
        | 0x402C_542D
        // TIOCGPTN, TIOCSPTLCK, TIOCGDEV, TIOCSIG, TIOCVHANGUP, TIOCGPKT,
        // TIOCGPTLCK, TIOCGEXCL, TIOCGPTPEER
        | 0x8004_5430
        | 0x4004_5431
        | 0x8004_5432
        | 0x4004_5436
        | 0x5437
        | 0x8004_5438
        | 0x8004_5439
        | 0x8004_5440
        | 0x5441
        // FIONCLEX, FIOCLEX, FIOASYNC, FIOQSIZE
        | 0x5450
        | 0x5451
        | 0x5452
        | 0x5460
        // FIBMAP, FIGETBSZ, FIFREEZE, FITHAW, FICLONE
        | 0x0000_0001
        | 0x0000_0002
        | 0xC004_5877
        | 0xC004_5878
        | 0x4004_9409
    )
}
