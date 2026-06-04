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

- `epoll_create1` / `epoll_ctl` / `epoll_wait`
- `eventfd` / `eventfd2`
- `timerfd_create` / `timerfd_settime` / `timerfd_gettime`
- `clone3` with full task + address-space flag set
- `mprotect` / `madvise`
- Dynamic-linker (`PT_INTERP`) plumbing in the ELF loader

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

- PID namespace (`CLONE_NEWPID`, `pid_ns_init`)
- Mount namespace (`CLONE_NEWNS`, `pivot_root`, mount propagation)
- Network namespace (`CLONE_NEWNET`, veth pairs)
- UTS namespace (`CLONE_NEWUTS`, `sethostname`)
- IPC namespace (`CLONE_NEWIPC`)
- User namespace (`CLONE_NEWUSER`, uid/gid maps)

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

Both `linux-compat` and `container` are **stub features** as of Wave 62.
The stub modules (`userspace/src/linux_compat.rs`,
`userspace/src/container.rs`) exist as sign-posts for Waves 63-67 where
the real syscall implementations will land.  Enabling either feature today
compiles cleanly but adds no runtime behaviour.
