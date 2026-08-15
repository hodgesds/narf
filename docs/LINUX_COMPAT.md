# NARF — Linux Compatibility Reference

This document describes, grounded in the actual source, how Linux-compatible
NARF is: what runs, what doesn't, and the precise ABI details a reader needs
to reason about porting or debugging a Linux binary on NARF.

It is a snapshot of the code in this tree. Where a claim could not be verified
from source it is marked **(unverified)**. All citations are `path:line` into
this worktree.

Companion docs: [`STATUS.md`](../STATUS.md) (subsystem status),
[`COMPARISON.md`](../COMPARISON.md) (design-space positioning),
[`ROADMAP.md`](../ROADMAP.md) (stages), [`PERSONAS.md`](../PERSONAS.md)
(the `linux-compat` / `container` / `cgroup` build profiles).

---

## 1. Overview

NARF is **not** a Linux clone. It is a `no_std` Rust framekernel with its own
internal design (async executor, capability model, domain isolation). What
makes it *Linux-compatible* is a single, deliberate surface: **it implements
the Linux x86_64 (and aarch64) syscall ABI well enough to load and run
unmodified Linux ELF binaries** — the same `ld-musl` / `ld-linux` dynamic
loader, the same `struct stat`, the same signal frames, the same auxv.

"Linux-compatible" here means, concretely:

- **Syscall-ABI compatible.** A user program issues the `syscall` instruction
  (or `int 0x80`) with Linux wire numbers in `rax`; NARF dispatches through a
  per-arch `LINUX_TABLE` (`userspace/src/syscall.rs:2184` for x86_64,
  `:2537` for aarch64) that maps Linux numbers → NARF handlers.
- **Runs unmodified binaries.** musl (static + dynamic PIE), Debian-13 glibc
  (static-PIE + dynamic), BusyBox, redis, stress-ng, and — in progress —
  systemd 257 all load and execute without recompilation. See §4.
- **NARF-native extensions live out of the way.** NARF's own syscalls occupy
  the `0x4000..=0x40FF` range (`userspace/src/syscall.rs:2839`), so they never
  collide with a Linux wire number.

**Confidence level.** The core process/mem/fs/signal/socket surface is
genuinely implemented and exercised by ~120 in-tree smoke programs that run on
every CI push (§4, §7). It is a *functional* Linux ABI, not an exhaustive one:
some syscalls are intentional no-ops, some are feature-gated (and become
`ENOSYS`/invalid when the feature is off), and whole subsystems (io_uring, BPF)
are deliberately absent (§6). Treat this as "runs a large, growing set of real
Linux userland," not "passes LTP."

---

## 2. Syscall coverage

NARF registers Linux syscalls in one function,
`install_core_syscalls()` in `userspace/src/handlers.rs` (~lines 20901–21978),
via `table.install_raw(Syscall::Variant, "name", RawFnHandler(sys_fn))`. The
Linux-number → variant mapping lives in `LINUX_TABLE`
(`userspace/src/syscall.rs:2184` x86_64, `:2537` aarch64).

Counts (approximate, from this tree):

- **~200+** Linux syscalls mapped in the x86_64 `LINUX_TABLE`.
- **~180** handlers installed unconditionally (core I/O, process, memory,
  sockets, signals, credentials, VFS, poll/epoll, time).
- **~50** handlers gated behind `linux-compat` (POSIX timers, full SysV IPC,
  inotify/fanotify, Landlock, LSM self-attr, keyrings, new mount API, xattrs,
  `statx`, `ptrace`, `perf_event_open`).
- **3** gated behind `container` (SysV `*get` id-by-key when `linux-compat`
  is off; `pivot_root`).
- **~5** intentional no-op stubs (`utime`/`utimes` timestamp write,
  `set_robust_list`/`get_robust_list`).
- **19** NARF-native extensions in `0x4000+` (not Linux syscalls).

### 2.0 The cfg-gating sharp edge (read this first)

A `LINUX_TABLE` entry and its handler registration are gated **independently**.
If a table entry is present but its `install_raw` call is compiled out (feature
off), the wire number still resolves to a `Syscall` variant, but handler lookup
returns `None` → the kernel returns an **invalid-op** rather than a clean
`-ENOSYS`. Conversely a cfg-gated *table entry* (e.g. `Chroot` at
`userspace/src/syscall.rs:2430`) makes the syscall unreachable even when a
handler exists. Both directions are real; when in doubt, check both the table
(`syscall.rs`) and the `#[cfg(...)]` around the matching `install_raw`
(`handlers.rs`). This is a documented recurring pitfall.

### 2.1 Process / scheduling

| Syscall(s) | Status | Gate | Notes / cite |
|---|---|---|---|
| `fork`, `vfork`, `clone`, `clone3`, `execve`, `execveat` | implemented | `clone3` needs `linux-compat` (`handlers.rs:~21164`) | x86_64 `clone(2)` ABI (arg3=ctid, arg4=tls); execve takes Linux `(path, argv, envp)` |
| `exit`, `exit_group`, `wait4`, `waitid` | implemented | — | `wait4` is signal-interruptible; WUNTRACED/WCONTINUED honored |
| `getpid`/`getppid`/`gettid`, `getpgid`/`setpgid`, `getsid`/`setsid`, `getpgrp` | implemented | — | full pid/pgrp/session set |
| `sched_getaffinity`/`setaffinity`, `sched_get/setscheduler`, `sched_get/setparam`, `sched_get/setattr`, `sched_getpriority_{max,min}`, `sched_rr_get_interval`, `sched_yield` | implemented | `sched_get/setattr` need `linux-compat` | `handlers.rs:~21225`, `~21880` |
| `getpriority`/`setpriority`, `getrusage`, `times` | implemented | — | |
| `prctl`, `arch_prctl` | implemented | `arch_prctl` x86_64-only | `handlers.rs:~21175` |
| `personality` | implemented (returns flags) | — | |
| `ptrace` | **stub → ENOSYS** when `linux-compat` off | `linux-compat` | `handlers.rs:~17581` documents the ENOSYS stub |
| `rseq`, `set_tid_address` | implemented | `set_tid_address` under `linux-compat` | |
| `kcmp` | implemented | `linux-compat` | |
| `capget`/`capset` | implemented | `linux-compat` | |
| `getuid`/`geteuid`/`getgid`/`getegid`, `setuid`/`setgid`, `set/getres[ug]id`, `setre[ug]id`, `setfs[ug]id`, `get/setgroups` | implemented | — | NARF has no real uid model (no root); these track values but authority is capability-based |

### 2.2 Memory

| Syscall(s) | Status | Gate | Notes / cite |
|---|---|---|---|
| `brk`, `mmap`, `munmap`, `mremap`, `mprotect`, `msync`, `mincore` | implemented | `madvise` table entry gated `linux-compat` (`syscall.rs:2427`) | file-backed + anon mmap, `MAP_FIXED` partial-replace, `MAP_SHARED`-across-fork (shmem-backed) |
| `madvise`, `mlock`/`mlock2`/`munlock`/`mlockall` | implemented | `madvise` needs `linux-compat` | |
| `pkey_alloc`/`pkey_free`/`pkey_mprotect` | implemented | — | maps to the PKS/PKU machinery |
| `mbind`, `set_mempolicy`, `get_mempolicy` | implemented | `linux-compat` | NUMA policy surface |
| `membarrier` | implemented | — | |
| `memfd_create`, `memfd_secret` | implemented | — | anon in-memory file (`memfs::new_anon_file`) |
| `process_vm_readv`/`writev`, `process_madvise` | implemented | — | |

### 2.3 Filesystem / VFS

| Syscall(s) | Status | Gate | Notes / cite |
|---|---|---|---|
| `read`, `write`, `readv`, `writev`, `preadv[2]`, `pwritev[2]`, `pread64`, `pwrite64`, `lseek` | implemented | — | |
| `open`, `openat`, `openat2`, `creat`, `close`, `close_range` | implemented | `open`/`openat` use `sys_open_linux` under `linux-compat` (`handlers.rs:~21607`) | |
| `stat`, `lstat`, `fstat`, `newfstatat`, `statx` | implemented | `statx` needs `linux-compat` (`handlers.rs:~21667`); stat family uses `sys_stat_linux` under `linux-compat` | layout in §3 |
| `statfs`, `fstatfs`, `sysinfo` | implemented | — | |
| `getdents64`, `getcwd`, `chdir`, `fchdir` | implemented | — | dir-fd based navigation |
| `mkdir[at]`, `rmdir`, `unlink[at]`, `rename[at]`/`renameat2`, `symlink[at]`, `readlink[at]`, `link[at]` | implemented | — | |
| `chmod`/`fchmod`/`fchmodat`, `chown`/`fchown`/`lchown`/`fchownat`, `umask`, `access`/`faccessat`/`faccessat2` | implemented | — | |
| `truncate`/`ftruncate`, `fallocate`, `fsync`/`fdatasync`, `sync`/`syncfs`/`sync_file_range`, `fadvise64`, `readahead` | implemented | — | |
| `dup`/`dup2`/`dup3`, `fcntl`, `ioctl`, `pipe`/`pipe2` | implemented | — | pipes EOF on writer exit; fds released on task exit |
| `copy_file_range`, `sendfile`, `splice`, `tee`, `vmsplice` | implemented | — | |
| xattr: `[l|f]setxattr`, `[l|f]getxattr`, `[l|f]listxattr`, `[l|f]removexattr` | implemented | `linux-compat` | `handlers.rs:~21797` |
| `utime`/`utimes` | **no-op** (accept, no mtime write) | `linux-compat` | `sys_utime_noop`, `handlers.rs:~21840` |
| `utimensat` | implemented | — | |
| `chroot` | implemented | table entry gated `linux-compat` (`syscall.rs:2430`) | applied exactly once (single resolve point) |
| `mount`, `umount2`, `pivot_root`, `unshare`, `setns`, `move_mount`, `open_tree`, `fspick`, `mount_setattr` | implemented | `pivot_root` needs `linux-compat`+`container` (`syscall.rs:2432`); new mount API needs `linux-compat` | `mount` no-ops `MS_SLAVE`/`MS_PRIVATE`/`MS_SHARED` propagation flags (systemd generator sandbox) |
| `fsopen`, `fsconfig`, `fsmount` | present (degradable) | `linux-compat` | `handlers.rs:~21438`; the systemd gap analysis notes these as thin |
| `name_to_handle_at`, `open_by_handle_at` | implemented | `linux-compat` | |
| `inotify_init1`, `inotify_add_watch`, `inotify_rm_watch` | implemented (real event delivery) | `linux-compat` | `inotify2_smoke` exercises real firing |
| `fanotify_init`, `fanotify_mark` | implemented | `linux-compat` | |
| `add_key`, `request_key`, `keyctl` | implemented | `linux-compat` | |
| `landlock_*`, `lsm_{get,set}_self_attr`/`lsm_list_modules` | implemented | `linux-compat` | path-rule enforcement + LSM self-attr |

### 2.4 Network / sockets

| Syscall(s) | Status | Gate | Notes / cite |
|---|---|---|---|
| `socket`, `socketpair`, `bind`, `listen`, `accept`/`accept4`, `connect`, `shutdown` | implemented | — | AF_INET/AF_INET6/AF_UNIX; blocking accept + wildcard bind |
| `send`/`recv`, `sendto`/`recvfrom`, `sendmsg`/`recvmsg`, `sendmmsg`/`recvmmsg` | implemented | — | AF_UNIX `SCM_RIGHTS` fd-passing works (Wayland transport) |
| `getsockname`/`getpeername`, `getsockopt`/`setsockopt` | implemented | — | `SO_REUSEPORT` flow distribution |
| `sock_register_buf`, `sock_send_zc` | implemented | — | zero-copy send path |

The TCP/IP stack itself lives in userspace by design (see `COMPARISON.md`); the
kernel ships the frame-ring contract + NIC drivers. redis serves off-box over
virtio-net (`redis-smoke`, `net-smoke`).

### 2.5 Signals

| Syscall(s) | Status | Gate | Notes / cite |
|---|---|---|---|
| `kill`, `tgkill`/`tkill` **(unverified: tgkill wiring)**, `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `rt_sigpending`, `rt_sigtimedwait`, `rt_sigqueueinfo`, `rt_sigsuspend`, `sigaltstack` | implemented | — | full RT-signal support (§3) |
| `signalfd`/`signalfd4`, `pidfd_open`, `pidfd_send_signal`, `pidfd_getfd` | implemented | — | |
| `pause`, `alarm`, `setitimer`/`getitimer` | implemented | `setitimer`/`getitimer`/`alarm` under `linux-compat` (`handlers.rs:~21326`) | ITIMER_REAL scanned from the timer tick |

Delivery model and mask width are detailed in §3.2.

### 2.6 Time

| Syscall(s) | Status | Gate | Notes / cite |
|---|---|---|---|
| `clock_gettime`, `clock_settime`, `clock_getres`, `clock_adjtime`, `adjtimex` | implemented | `adjtimex`/`clock_adjtime` under `linux-compat` | vDSO fast path for `clock_gettime` (§3.6) |
| `gettimeofday`, `settimeofday`, `time` | implemented | — | |
| `nanosleep`, `clock_nanosleep` | implemented | `clock_nanosleep` + `nanosleep` handlers under `linux-compat` (`handlers.rs:~21292`) | reads a `timespec*` (§3.5); finite sleeps park on the timer wheel |
| POSIX timers: `timer_create`, `timer_settime`, `timer_gettime`, `timer_delete` | implemented | `linux-compat` (table entries `syscall.rs:2514`) | |
| `timerfd_create`, `timerfd_settime`, `timerfd_gettime` | implemented | `timerfd_gettime` under `linux-compat` | timerfd-in-epoll works (weston repaint loop) |

### 2.7 IPC / synchronization

| Syscall(s) | Status | Gate | Notes / cite |
|---|---|---|---|
| `futex`, `futex_waitv`/`futex_wake`/`futex_wait`/`futex_requeue` | implemented | — | signal-interruptible finite parks |
| `eventfd`/`eventfd2`, `epoll_create[1]`, `epoll_ctl`, `epoll_wait`/`epoll_pwait` | implemented | — | epoll overridden by `crate::epoll` (`handlers.rs:~21938`); event-driven wake |
| `poll`, `ppoll`, `select`, `pselect6` | implemented | — | |
| SysV sem: `semget`, `semop`, `semtimedop`, `semctl` | implemented | full impl under `linux-compat`; `semget` id-by-key under `container` | `handlers.rs:~21493` |
| SysV msg: `msgget`, `msgsnd`, `msgrcv`, `msgctl` | implemented | as above | |
| SysV shm: `shmget`, `shmat`, `shmdt`, `shmctl` | implemented | as above (`shmget` table entry `syscall.rs:2508`) | |
| POSIX mq + mqueuefs: `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr`; mounted queue namespace | implemented | `linux-compat`; SIGEV_SIGNAL/NONE (SIGEV_THREAD netlink remains) | `filesystem/src/mqueuefs.rs`, `userspace/src/mqueue.rs` |
| `set_robust_list`/`get_robust_list` | **structural no-op** | — | accepted, does nothing (`handlers.rs:~21766`) |

### 2.8 cgroup v2 / namespaces / misc

| Syscall(s) | Status | Gate | Notes / cite |
|---|---|---|---|
| `unshare`, `setns` (PID/mount/net/UTS/IPC/cgroup/user) | implemented | namespaces primarily under `container` | see §5 for the ns model |
| `sethostname`/`setdomainname`, `uname`, `gethostname` | implemented | — | |
| `getrandom` | implemented | — | ChaCha20 CSPRNG |
| `perf_event_open` | implemented | `linux-compat` | `handlers.rs:~21949` |
| `init_module`/`finit_module`/`delete_module` | present | — | NARF has no out-of-tree module model; treat as stubs unless verified **(unverified)** |
| `io_uring_setup`/`enter`/`register` | **not present** | — | intentional non-goal (§6) |
| `bpf` | partial | — | x86_64 321 / aarch64 280. Programs (`PROG_LOAD`, `PROG_TEST_RUN`), maps (`MAP_CREATE`, `MAP_{LOOKUP,UPDATE,DELETE}_ELEM`, `MAP_GET_NEXT_KEY`), BTF (`BTF_LOAD`), introspection (`OBJ_GET_INFO_BY_FD`, `{PROG,MAP,LINK,BTF}_GET_NEXT_ID`, `{PROG,MAP,LINK,BTF}_GET_FD_BY_ID`), bpffs pinning (`OBJ_PIN`, `OBJ_GET`), attach (`PROG_{ATTACH,DETACH}`, `LINK_{CREATE,UPDATE,DETACH}`). `ENOTSUP`: `PROG_QUERY`, `TASK_FD_QUERY`, the `MAP_*_BATCH` commands, `BPF_TOKEN_CREATE` (NARF has no delegable token — the privilege gate is a credential check), `BPF_ITER_CREATE` (needs a seq_file-shaped read surface no NARF fd provides). `handlers/sys_bpf.rs` |

---

## 3. ABI details & sharp edges

These are the layouts and conventions a Linux binary actually depends on. Get
one of them wrong by a byte and you get a stack-canary abort or a `#PF` deep
inside `ld-musl` — so they are pinned here with cites.

### 3.1 `struct stat` / `struct statx`

`struct stat` (used by `stat`/`lstat`/`fstat`/`newfstatat`) is the Linux
x86_64 144-byte layout — `handlers.rs:~3095`:

```
0   st_dev:u64   8  st_ino:u64   16 st_nlink:u64  24 st_mode:u32
28  st_uid:u32   32 st_gid:u32   36 __pad0:u32    40 st_rdev:u64
48  st_size:i64  56 st_blksize:i64  64 st_blocks:i64
72  st_atim:timespec(16)  88 st_mtim(16)  104 st_ctim(16)
120 __unused[3]:i64   → total 144 bytes
```

`struct statx` is the 256-byte Linux `statx(2)` result — `handlers.rs:~3127`
(`stx_mask`, `stx_blksize`, `stx_attributes`, `stx_{nlink,uid,gid,mode}`,
`stx_ino`, `stx_size`, `stx_blocks`, four `statx_timestamp`s, rdev/dev
major/minor, `stx_mnt_id`, DIO alignment). Gated behind `linux-compat`.

### 3.2 Signal delivery model, masks, RT signals

**Deliver-on-return (Linux model).** NARF delivers pending signals on *every*
return to user mode — syscall return and IRQ return alike — not synchronously
when the signal is raised. The x86_64 timer-IRQ return path does the full check
at `frame/src/x86_64/trap.rs:759` ("Full Linux-style signal delivery on the
timer-IRQ return to user"). This is why a `SIGALRM` reaches a CPU-bound busy
loop and why a signal can interrupt a parked `wait4`/`futex`.

**64-bit masks incl. RT signals 33–63.** `sigset_t` is a `u64` bitmask where
bit *N* = signal *N* for `1..=63`, bit 0 reserved
(`narf-libc/src/signal.rs:~171`). `SIGRTMIN=33 .. SIGRTMAX=63` are fully
representable — an earlier `u32`-mask era dropped RT signals; that is fixed.

**Mask save/restore across handlers.** A handler runs with the handler's mask
applied; the pre-handler mask is stashed per-task in `SIGRETURN_SAVED_MASK`
(`handlers.rs:~15804`) and restored by `rt_sigreturn`. Forgetting this left a
handled signal blocked forever — that bug is fixed and regression-covered.
The signal frame lives at `frame/src/x86_64/trap.rs:~1612`.

### 3.3 `struct termios` — the 60-byte userspace shape (canary sharp edge)

The kernel exchanges the **full 60-byte userspace `struct termios`** on
`TCGETS`/`TCSETS`, *not* the 36-byte Linux kernel-internal `__kernel_termios`.
`TERMIOS_WIRE_LEN = 60` (`filesystem/src/devfs_pty.rs:161`); the console path
reads/writes the same 60-byte image (`userspace/src/fd.rs:286`–`322`,
`read_user_termios`/`write_user_termios`). Layout: `c_iflag@0`, `c_oflag@4`,
`c_cflag@8`, `c_lflag@12`, `c_line@16`, `c_cc[NCCS=32]@17`, `c_ispeed`/
`c_ospeed`@52..60.

**Why it matters (the canary story).** glibc's `isatty()` issues `TCGETS` into
a `__kernel_termios` and a mismatched write size clobbers adjacent stack — a
stack-canary abort. NARF pins the wire size explicitly and does the copy inside
a SMAP `with_user_access` bracket using `read_unaligned`/`write_unaligned`
(a plain memcpy would escape the STAC/CLAC window and fault the supervisor read
of the user page) — see the SAFETY notes at `userspace/src/fd.rs:287`. Both the
console (`fd.rs`) and the PTY (`devfs_pty.rs`) paths use the identical 60-byte
contract.

> Historical note: earlier bring-up notes reference a `KERNEL_TERMIOS_LEN=36`
> fix from the glibc era. The current tree standardizes on the 60-byte
> userspace shape everywhere; there is no 36-byte path in the code today.

### 3.4 Syscall return ABI (`SyscallReturn` field order)

`SyscallReturn` is `#[repr(C)] { value: u64, status: NarfStatus }`
(`userspace/src/syscall.rs:~3532`). The field order is load-bearing: on x86_64
`value` lands in `rax` and `status` in `rdx` on the `syscall`-instruction
return path. Getting the order wrong clobbers `rdx`, which Linux requires to
survive `syscall` — musl's `__init_tp` does `mov %fs:0,%rdx; syscall; movq $0,
0x98(%rdx)` and every forked child `#PF`'d at CR2=0x98 when NARF returned
`(rax, rdx=status)`. The fix (return `-errno` in `rax`, preserve `rdx`) is why
this struct's field order must not be reordered.

### 3.5 `timespec` / `timeval`

Both are the Linux 16-byte layouts: `timespec { tv_sec:i64, tv_nsec:i64 }`,
`timeval { tv_sec:i64, tv_usec:i64 }` (`narf-libc/src/time.rs:~13`).
`nanosleep`/`clock_nanosleep` read the user `timespec*` and convert to a `u64`
nanosecond deadline (`userspace/src/posix_timer.rs:~430`). Note the historical
`sys_futex` timespec caveat: futex deadlines were once misread as raw ns; the
finite-park path is now signal-interruptible and deadline-decoding is the
documented follow-up.

### 3.6 auxv and vDSO

At process setup NARF emits a standard Linux auxv (tags in
`userspace/src/lib.rs:~430`; values filled in `userspace/src/process.rs`):

`AT_PAGESZ` (4096), `AT_ENTRY`, `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_BASE`
(interpreter base), `AT_HWCAP`, `AT_RANDOM` (16-byte entropy for stack canary
/ ASLR), `AT_EXECFN`, `AT_SECURE` (0), `AT_SYSINFO_EHDR` (vDSO base), plus the
`AT_NULL` terminator. **Not emitted (deferred):** `AT_UID`/`AT_GID`/`AT_EUID`/
`AT_EGID`, `AT_CLKTCK` **(unverified — confirm against `lib.rs` before relying
on `sysconf(_SC_CLK_TCK)`)**.

**vDSO.** A real `linux-vdso.so.1` is mapped (RX) at `VDSO_MAP_BASE + 0x1000`
with a `vvar` page (RO) just below it (`userspace/src/vdso.rs:~1`), and its base
is handed to userspace via `AT_SYSINFO_EHDR`. The `vvar` page carries a seqlock
+ TSC→ns multiplier/shift so `__vdso_clock_gettime` (and
`__vdso_gettimeofday`/`__vdso_time`/`__vdso_getcpu`) can serve `CLOCK_REALTIME`/
`CLOCK_MONOTONIC` without a syscall. Exercised by `vdso_smoke`.

---

## 4. Proven userland

Everything in the "musl-demo" column runs on **every CI push** through the
`cargo xtask musl-demo` harness (x86_64), which drives ~120 stock-musl / libdrm
/ libwayland smoke programs through the live shell → `execve` → ELF loader →
syscall dispatch and asserts an output token. The case list is authoritative:
`build/xtask/src/main.rs:1738`–`1984`.

| Program | Status | How it's exercised |
|---|---|---|
| **musl static** (`hello_musl`) | runs | `xtask musl-demo` (`main.rs:1740`), CI |
| **musl dynamic PIE** (`hello_musl_dyn`, PT_INTERP + ld-musl) | runs | `xtask musl-demo`, CI |
| **BusyBox** (`echo`, `pwd`, `uname -a`, `sh -c`, pipes) | runs | `xtask musl-demo` (`main.rs:1756`–`1795`), CI |
| **pthreads** (`hello_pthread`) | runs | clone(2) + TLS + futex-based `pthread_join`, CI |
| **multi-DSO dynamic linking + dlopen** (`dso_smoke`, per-DSO TLS `tls_smoke`) | runs | CI |
| **redis** (unmodified `redis-server`) | runs, serves off-box | `cargo xtask redis-smoke` / `redis-bench` (RESP SET/GET over virtio-net), CI `redis-smoke` |
| **glibc, static-PIE** (Debian 13) | loads + executes | manual; ELF/auxv/TLS ready. Runs under KVM; AVX/AVX-512 state is saved when enabled in XCR0 |
| **glibc, dynamic** (Debian 13 + systemd libs) | runs under KVM | manual; landed with DT_RELR opt-in, COW-private vDSO, `clone(stack=0)` fork |
| **stress-ng** (musl dyn-PIE via alpine-chroot) | runs | `chroot_run` / probe harness; boots near-native under KVM; vector ISA selection follows the enabled XCR0 mask |
| **systemd 257** | **in progress** | `--version` prints rc=0; `--test` fully inits the manager, loads all units, computes the boot transaction (`cgroup-all` build). As PID 1 it boots and reaches early init. Remaining: readlink-EINVAL on unit symlinks, teardown `rm_rf`. See `notes`/memory `narf-systemd-bringup` |
| **OCI container demo** (`oci_smoke`) | runs | `xtask musl-demo` default (chroot rootfs isolation); nightly `--features container` adds a real UTS namespace (`nightly-oci.yml`) |
| **BusyBox chroot** (`chroot_run`) | runs | chroot into an alpine rootfs; `verification/data/musl-demo/chroot_run_x86_64` |
| **libdrm / libwayland / weston-class GUI** (modetest, wl_* compositor cases) | runs | `xtask musl-demo` GUI cases (`main.rs:1975`), fresh-boot per case |

Beyond programs, the harness proves the ABI surface round-by-round: eventfd,
getrandom, socketpair, accept4, mremap, sendfile, creds, waitid, ppoll,
sysinfo, splice, membarrier, close_range, sched policy, msync/mincore,
sync/syncfs, dup3/fadvise/mlock2, robust lists, renameat2, pidfd, sethostname,
sendmmsg/recvmmsg, openat2, preadv/pwritev, capget/capset, setitimer, xattr,
perf, mq, inotify (incl. real events), pkey, process_vm, mempolicy, sched_attr,
adjtimex, SysV IPC (sem/msg/shm), signalfd, futex2, keyrings, fanotify,
Landlock, LSM self-attr, vDSO, new mount API, job control (SIGSTOP/SIGCONT),
navfs, and pty termios (`main.rs:1852`–`1960`).

---

## 5. Filesystems & pseudo-filesystems

Filesystems register with the VFS mount registry (`filesystem/src/`); the
pseudo-filesystems are largely hook-driven so kernel subsystems can populate
dynamic entries without dependency cycles.

### `/proc` (procfs — `filesystem/src/procfs/`)

System-wide: `cpuinfo`, `meminfo`, `mounts`, `uptime`, `version`, `cmdline`,
`loadavg`, `filesystems`, `partitions`, `sched`, `stat`
(`procfs/mod.rs:1098`–`1138`). `self` symlink resolves per-lookup to the
current pid.

Per-pid (`/proc/[pid]/`, `procfs/mod.rs:811`+): `stat`, `status`, `cmdline`,
`maps`, `comm` (writable), `environ`, `auxv`, `limits`, `oom_score[_adj]`,
`coredump_filter`, `mountinfo`, `personality`, `cgroup`, `uid_map`/`gid_map`
(write-once), `io`, `sched`, `schedstat`, `stack`, `wchan`, `syscall`, plus
subdirs `fd/` (symlinks to backing paths), `fdinfo/`, `task/`, `ns/` (namespace
symlinks in `flavour:[id]` form). `exe`/`cwd`/`root` symlinks and `statm`
also present per bring-up notes.

### `/sys` (sysfs — `filesystem/src/sysfs.rs`)

Kobject tree: `class/block/<dev>/` (`size`, `removable`, `queue/scheduler`),
`class/net/<iface>/` (`mtu`, `address`, `operstate`),
`class/input/event<N>/` (`name`, `dev`, writable `uevent`),
`class/tty/`, `devices/system/node/node<N>/` (NUMA: `distance`, `meminfo`,
`cpulist`, `cpumap`), `bus/pci/` (stub), `firmware/acpi/` (stub),
`kernel/uevent_seqnum` (`sysfs.rs:495`–`828`). PCI device tree under
`/sys/devices` is largely a stub.

### `/dev` (devfs — `filesystem/src/devfs.rs`)

The filesystem identifies as `devtmpfs` and has a writable runtime hierarchy:
`mkdir`, char/block `mknod`, symlink, rename, unlink, and rmdir preserve stable
inode identity and mutable mode/uid/gid metadata. Character devices translate
to `S_IFCHR`/`DT_CHR`; block devices remain distinct as `S_IFBLK`/`DT_BLK`.

Static nodes include `null`, `zero`, `full`, `random`/`urandom` (ChaCha20,
identical byte behavior after initialization but distinct Linux 1:8/1:9 device
IDs), `kmsg`, `console`/`tty`/`tty0`/`tty1`, `uinput`, `fuse`, and `rtc0`.
Optional hardware nodes (`fb0`, `fp0`, `tpm*`, `snd/`, `dri/`) appear only
after a backing driver registers them. `/dev/ptmx` is the `pts/ptmx` symlink;
mounting `devpts` preserves the live `pts/<N>` Unix98 slaves and the 5:2
clone-on-open node. `/dev/fuse` also clones per successful open, so path probes
do not create connections. Registered block devices are block nodes, while
`disk/by-label` and `disk/by-partuuid` contain Linux-shaped relative symlinks.
`/dev/fd`, `stdin`, `stdout`, and `stderr` have their conventional procfs
targets.

Known devfs-specific gaps are tracked in
[`filesystem/DEVFS_LINUX_COMPAT_AUDIT.md`](../filesystem/DEVFS_LINUX_COMPAT_AUDIT.md):
devpts mount instances/options, Linux record-oriented `/dev/kmsg`,
filesystem-UUID discovery, and authoritative driver-assigned block major/minor
numbers. A real open of `/dev/tty` selects the caller's controlling console or
PTY and reports `ENXIO` when the session is detached, while retaining the 5:0
path-device identity.

### cgroup v2 (`filesystem/src/cgroupfs/`)

Unified hierarchy at `/sys/fs/cgroup`. Core files at every node
(`cgroupfs/mod.rs:556`+): `cgroup.controllers`, `cgroup.subtree_control`,
`cgroup.procs`, `cgroup.threads`, `cgroup.events` (`populated`/`frozen` with
POLLPRI), `cgroup.stat`, `cgroup.type`, `cgroup.freeze`, `cgroup.kill`,
`cgroup.max.depth`, `cgroup.max.descendants`. `mkdir`/`rmdir` create/remove
cgroups with depth/descendant limits and the no-internal-process constraint.
Per-controller files land when the matching `cgroup-*` feature is on: `cpu.*`,
`cpuset.*`, `memory.*`, `io.*`, `pids.*`, `pressure/*` (PSI), `misc.*`. Build
`--features cgroup-all` to get them all (used by the systemd path).

### tmpfs / in-memory (`filesystem/src/memfs.rs`)

`MemFs` is a mutable in-memory fs (tmpfs-like) for `/tmp`, `/dev/shm`, and
anonymous `memfd_create` files: read/write/truncate/chmod/chown, symlinks,
full directory ops, per-file uid/gid/mode DAC.

### On-disk filesystems

Per `COMPARISON.md`: **ext2** (file-data write), **exfat**, **9p**, **minix**,
**iso9660**, **udf**, and **SquashFS** (RO), plus **FAT/vfat** for the ESP.
**btrfs** is
read-write for single-device SINGLE/DUP filesystems, including compressed
reads, alternate checksums, subvolumes, snapshots, and COW namespace/file
mutations; multi-device and RAID profiles remain unsupported. **Bind mounts**
work through VFS path resolution. Missing: ext4-with-journal, xfs, zfs, NFS,
and SMB. (The `xtask disk-write-partitioned` path lays down a FAT32 ESP + ext4
root, but ext4 write support inside the kernel is **not** claimed here —
**unverified**; treat kernel ext4 as read-path-only until confirmed.) The
[Btrfs driver README](../drivers/fs/btrfs/README.md) is the authoritative
capability and limitation matrix.

FUSE and virtio-fs/9p give a userspace-filesystem escape hatch.

---

## 6. Known gaps & non-goals

**Intentional non-goals (by design, will not be implemented as-is):**

- **io_uring** — no `io_uring_setup`/`enter`/`register` in the table. NARF's
  async I/O story is `Narf-Ring` (capability-typed zero-copy rings), which is
  conceptually io_uring with cap typing; a Linux `io_uring` shim is not a goal.
- **BPF** — *no longer a non-goal.* NARF is growing an in-kernel BPF
  verifier and JIT: instruction-set compatible with Linux (so `clang -target
  bpf` is the compiler) but ABI-divergent above the encoding. `bpf(2)` covers
  the subset that maps cleanly onto the new data model; the rest returns
  `ENOTSUP` with a `// LINUX-GAP` note. See `bpf/specification/spec.md`.
  systemd still degrades gracefully without it.
- **Out-of-tree binary drivers** — no module ABI for third-party blobs. All
  drivers are in-tree Rust. `init_module`/`finit_module` are present but should
  be treated as non-functional for real modules **(unverified)**.
- **Real uid/root authority** — NARF has no root user; the `*uid`/`*gid`
  syscalls track values but authority is capability-based, not DAC/ambient.

**Real gaps (would be implemented, aren't yet / are thin):**

- `ptrace` → `ENOSYS` unless `linux-compat` is on (`handlers.rs:~17581`).
- `utime`/`utimes` and `set_robust_list`/`get_robust_list` are no-ops.
- New mount API (`fsopen`/`fsconfig`/`fsmount`) is present but thin; `mount`
  fstype breadth is the real systemd gate (mount propagation flags are no-ops).
- systemd as PID 1 is **in progress** (reaches early init, not a full boot).
- Namespace breadth is partial and mostly gated behind `container`; abstract
  AF_UNIX / rtnetlink / udev-event firing are noted as systemd gates.
- No distro packaging; build from source.

**The cfg-gating trap (repeat).** Building without `linux-compat` (or without
`container`) silently removes ~50 syscalls; a program that needs them gets an
invalid-op or `ENOSYS` at runtime, not a link error. Build with the profile
your target needs (see `PERSONAS.md`).

---

## 7. How to test compatibility yourself

Everything below assumes `cargo xtask` from the repo root and a working QEMU.

- **Run the full linux-compat smoke matrix** (x86_64, ~120 stock-musl / libdrm
  / libwayland programs through the live shell):
  ```
  cargo xtask musl-demo --arch=x86_64
  ```
  Case list + expected tokens: `build/xtask/src/main.rs:1738`. The C sources
  live in `verification/data/musl-demo/*.c`; the built ELFs sit alongside
  (`*_x86_64`). Each is compiled by `verification/build.rs` (needs
  `musl-tools`).

- **Drive one command interactively** (types a command into the shell over
  serial and asserts an expected substring):
  ```
  cargo xtask run-interactive --arch=x86_64 --cmd "busybox uname -a" --expect "Linux"
  ```
  Args at `build/xtask/src/main.rs:327`.

- **Off-box network / redis** (real host TCP socket into the guest over
  virtio-net + SLIRP hostfwd):
  ```
  cargo xtask net-smoke   --arch=x86_64
  cargo xtask redis-smoke --arch=x86_64
  cargo xtask redis-bench --arch=x86_64   # side-by-side vs Linux host
  ```

- **chroot / OCI / stress-ng** — the `oci_smoke` and `chroot_run` cases run
  inside `musl-demo`; the alpine-rootfs stress-ng probe (`probe.sh`) is a
  manual/nightly path. The nightly OCI job
  (`.github/workflows/nightly-oci.yml`) re-runs `oci_smoke` with
  `--features container` for real-namespace assertions.

- **Kernel-internal smokes** (the ABI structs, signal frames, etc. are
  regression-guarded here):
  ```
  cargo xtask test --arch=x86_64 --features cgroup-all
  ```

- **CI reference.** `.github/workflows/ci.yml` runs `musl-demo`, `net-smoke`,
  `redis-smoke`, the `cargo xtask test` suite, and a 6-combo feature-check
  matrix on every push — the canonical "is the Linux surface still green" gate.

---

*Accuracy note: this document is generated from source inspection. Items marked
**(unverified)** were not confirmable from the files read and should be checked
before relying on them. When source and this doc disagree, source wins — update
this doc.*
