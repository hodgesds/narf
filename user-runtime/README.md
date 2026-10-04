# user-runtime — User-Side Typed Syscall SDK

`narf-user-runtime` is the SDK that user binaries link against to
reach NARF's kernel, so that they do not hand-roll raw trap sequences.
It wraps the syscall ABI in typed functions, provides the console
writers and the bootstrap-header shape a freshly started process
needs to orient itself, and offers small handle-oriented helpers for
the framebuffer and shared-memory syscalls. The eventual libc shim
builds on top of it as well.

It is important to distinguish this crate from the kernel-side
`userspace` crate. That crate is the kernel's process model — the
ELF loader, process lifecycle, and the kernel end of the bootstrap
hand-off; it runs in the kernel. This crate runs in the *user*
process, on the far side of the syscall boundary. The deliberate
consequence is that `user-runtime` has no dependency on any kernel
crate at all: it is `no_std`, allocation-free, and builds cleanly for
bare `x86_64-unknown-none` and `aarch64-unknown-none` targets so that
any user binary can reuse it without dragging kernel internals into
user space.

Because the two sides are separate crates that must nonetheless agree
on the wire, the crate mirrors a few things by hand and keeps them in
sync deliberately: the syscall numbers track the kernel's syscall
enum, and the bootstrap header's layout is `#[repr(C)]` and treated
as wire-stable, with changes required to land on both sides at once.
The syscall numbering follows the per-architecture Linux ABI for the
POSIX-shaped calls, with NARF-only extensions — ring submission and
completion, capability bootstrap, framebuffer and shared-memory
handles, firmware install, zero-copy socket buffers, terminal
attributes — occupying a shared high-numbered range on every
architecture.

The crate is candid about its ABI choices. On x86_64 the wrappers
currently trap via the legacy software-interrupt path rather than the
fast MSR-driven syscall path, because the fast entry has an
undiagnosed stack-marshalling bug; the slower path is correct today
and the wrappers are meant to switch over once that is fixed. The
multi-argument wrappers also take care to declare the status-word
register as clobbered so the compiler does not keep a stale value
live across the trap — a real correctness concern, not a formality.

Two submodules give higher-level, handle-oriented ergonomics over the
raw calls: a graphics module that wraps the framebuffer connect/
info/ring-map handshake and its draw-command ring behind a context
that exposes fill and flush, and a shmem module that wraps region
creation and mapping behind a typed handle. Both keep their wire
formats in lockstep with the matching kernel subsystems. A `container`
feature flag reserves space for future namespace-isolation plumbing
(PID, mount, network, UTS, IPC, and user namespaces); it is a stub
today, as is the broader Linux-shaped surface (epoll, eventfd,
timerfd, process creation, memory protection hints, and dynamic-
linker support) the crate is slated to grow.
