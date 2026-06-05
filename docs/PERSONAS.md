# Kernel Personalities

NARF supports three composable kernel personalities selected at compile time
via Cargo features.

---

## posix-core (default, no feature flag)

The base personality.  Provides the minimum POSIX surface needed to run native
NARF binaries:

- POSIX file descriptors, pipes, poll/select
- Basic process/thread model (fork, exec, wait)
- Signals (sigaction, kill, sigprocmask)
- Sockets (TCP/UDP/Unix)
- Memory: mmap (anonymous + file-backed), basic brk
- Time: clock_gettime, nanosleep

No Cargo feature flag is required.  This is what you get with a plain
`cargo build`.

---

## linux-compat

**Feature flag:** `linux-compat`

**Crates that carry it:** `narf-userspace`, `narf-user-runtime`,
`narf-libc`, `narf-frame`, `narf-filesystem`, `narf-memory`

Adds a Linux-shaped syscall surface on top of `posix-core`:

- `epoll_create1` / `epoll_ctl` / `epoll_wait` / `epoll_pwait`
- `eventfd` / `eventfd2`
- `timerfd_create` / `timerfd_settime` / `timerfd_gettime`
- `signalfd4`
- `memfd_create` + `F_ADD_SEALS` / `F_GET_SEALS`
- `clone3` with `CLONE_VM` / `CLONE_THREAD` / `CLONE_SIGHAND` /
  `CLONE_FS` / `CLONE_FILES` / `CLONE_PARENT_SETTID` /
  `CLONE_CHILD_CLEARTID` / `CLONE_SETTLS`, plus `set_tid_address`
- `mprotect` (with split/merge of `AddressSpace` regions) +
  `madvise(DONTNEED|FREE)`
- `fcntl(2)` extensions: `F_DUPFD` / `F_DUPFD_CLOEXEC`,
  `F_GETFD`/`F_SETFD`, `F_GETFL`/`F_SETFL`, `F_GETLK`/`F_SETLK`
- `statx(2)` + Linux-ABI `struct stat`
- `mount(2)` / `umount2(2)` / `chroot(2)` / `pivot_root(2)`
- POSIX per-process timers (`timer_create` / `timer_settime` /
  `timer_gettime` / `timer_delete`) + `clock_nanosleep` with
  `TIMER_ABSTIME`
- Dynamic-linker (`PT_INTERP`) plumbing in the ELF loader,
  including FS-backed lookup of `/lib/ld-musl-x86_64.so.1` and
  TLS relocations (`R_X86_64_DTPMOD64` / `DTPOFF64` / `TPOFF64`)
- Default-action signal lookup wired into the scheduler retire
  path so uncaught `Terminate` / `CoreDump` signals stamp
  `WIFSIGNALED + WTERMSIG` observable by `wait4`

Enable with:

```toml
[dependencies]
narf-frame = { path = "...", features = ["linux-compat"] }
```

or on the command line:

```
cargo build --features linux-compat
```

---

## container

**Feature flag:** `container`

**Crates that carry it:** `narf-userspace`, `narf-user-runtime`,
`narf-libc`, `narf-frame`, `narf-filesystem`, `narf-memory`

Adds namespace isolation on top of `posix-core`:

- PID namespace (`CLONE_NEWPID`) — inner pid 1 semantics,
  per-namespace bounded id pool, kill-by-outer-pid still works
- Mount namespace (`CLONE_NEWNS`) — per-task `MountNamespace`
  with copy-on-write of the global mount table at fork
- Network namespace (`CLONE_NEWNET`) — per-namespace iface table
  seeded with synthetic `lo`
- UTS namespace (`CLONE_NEWUTS`) — per-namespace hostname +
  domainname; `gethostname` / `sethostname` / `uname` /
  `setdomainname` route through the calling task's UTS NS
- IPC namespace (`CLONE_NEWIPC`) — per-namespace SysV IPC
  (`shmget` / `semget` / `msgget`) + POSIX mqueue keyspaces
- `unshare(2)` for any combination of the above
- `setns(2)` (Linux number 308) — accepts a target task and
  `nstype` mask; `/proc/[pid]/ns/<type>` symlinks are a
  follow-up
- User namespace (`CLONE_NEWUSER`) is reserved but not yet
  implemented

`container` is **orthogonal** to `linux-compat`.  A native NARF container
runtime can use namespaces without the full Linux syscall surface.

---

## Composition rules

| Use case                        | Features                        |
|---------------------------------|---------------------------------|
| Native NARF binary              | *(none)*                        |
| Linux binary, no containers     | `linux-compat`                  |
| NARF container runtime          | `container`                     |
| Full container runtime (OCI)    | `linux-compat` + `container`    |

`linux-compat + container` is the combination needed to run an OCI container
runtime (runc, crun, containerd-shim) on top of NARF.

---

## Implementation status

Both features are **live** as of Wave 77.  The implementation landed
across Waves 62–77 (per `STATUS.md` "Stage 5 / personality features"
section):

- Wave 62 established the feature flags and stub modules.
- Wave 63 — dyn-linker aux vector (`AT_PHDR` / `AT_PHENT` / `AT_PHNUM`
  / `AT_RANDOM`).
- Wave 64 — `epoll` / `eventfd` / `timerfd_*`.
- Wave 65 — `clone3` + per-thread TLS via `set_tid_address`.
- Wave 66 — `mprotect` (region split) + `madvise(DONTNEED|FREE)`.
- Wave 67 — `CLONE_NEWPID` + `CLONE_NEWNS`.
- Wave 68 — `fcntl(2)` extensions.
- Wave 69 — `statx(2)` + Linux ABI `struct stat`.
- Wave 70 — `signalfd4` + `memfd_create` with seals.
- Wave 71 — `mount` / `umount2` / `chroot` / `pivot_root`.
- Wave 72 — `CLONE_NEWUTS` + `CLONE_NEWNET` + `CLONE_NEWIPC`.
- Wave 73 — POSIX timers + `clock_nanosleep` ABSTIME.
- Wave 74 — smoke coverage for statx + POSIX timer paths.
- Wave 75 — real ld-musl interpreter loading + TLS relocations.
- Wave 77 — narf-libc POSIX timer wrappers.

Each wave landed on a feature branch and merged via PR.  Feature
combinations (`linux-compat`, `container`, both, neither) all build
clean in CI.
