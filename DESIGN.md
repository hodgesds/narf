# NARF design

NARF (Not Another Rust Frame Kernel) is a `no_std` operating system for
x86_64 and aarch64. Its framekernel design combines a small trusted core,
capability-checked authority, and kernel services organized into protection
domains. It also exposes a Linux-compatible userspace interface so existing
software can run on those native mechanisms.

This document describes the architectural direction. [STATUS.md](STATUS.md)
tracks milestones and what has been exercised; subsystem specifications define
interfaces and invariants. A feature described here is not necessarily
enforced on every supported machine.

## 1. Architectural blueprint: the framekernel

The trusted computing base (TCB) comprises `frame/`, the memory domain
manager, the capability core, the executor core, and the rules in
`security-model/`. The frame handles boot, traps, domain transitions, and
other operations that require system-wide authority. Drivers and services can
run in Ring 0 / EL1 without automatically receiving the frame's authority.

NARF declares 16 domain IDs. On x86_64, the kernel selects PKS when available
or uses PCID-tagged page tables as a fallback. On aarch64, MTE is the intended
hardware backend; systems without MTE currently have no equivalent enforced
fallback. The backends have different coverage and validation levels. In
particular, a domain boundary protects only resources mapped or tagged for
that boundary; it does not confine all ordinary kernel memory by itself. See
[docs/DOMAIN_BACKENDS.md](docs/DOMAIN_BACKENDS.md) for the current enforcement
matrix and its test limits.

Capabilities and domains work together: a capability grants authority over an
object, and the domain backend constrains memory access. Holding a typed
`Cap<T, R>` records a prior grant; `Cap::invoke()` checks current validity,
including revocation. The [security model](security-model/specification/spec.md)
owns the precise boundary and review rules.

## 2. Async-first execution and communication

The global executor schedules asynchronous kernel work. Driver operations,
interrupt follow-up work, and native submissions can use futures; synchronous
paths remain where hardware and compatibility interfaces require them. The
scheduler supports capability-checked donation and direct handoff to favor a
callee without an unnecessary scheduling round trip.

Narf-Ring is the shared-memory transport between cooperating components. Ring
slots carry handles to buffers, and ownership transfer avoids copying the
buffer's data bytes. The handle and ring metadata still move through memory;
"zero-copy" refers to the data path. Release/acquire ordering, cancellation,
and wake-up behavior are specified in `ipc/` and `abi/`.

## 3. Userspace and compatibility

NARF has a native process and syscall surface, with a composable
`linux-compat` personality for Linux syscall and device ABIs. The `container`
and `cgroup` features add namespace and resource-control surfaces. A Linux
program sees familiar interfaces while the kernel implementation remains
NARF-specific. The supported surface is incremental, not a promise of full
Linux parity; see [docs/PERSONAS.md](docs/PERSONAS.md).

The QEMU path runs an interactive shell, musl binaries, block and network
drivers, and graphical clients through DRM/KMS and Wayland. These demonstrations
do not establish the Stage 5 real-laptop boot and native display gate. See
[STATUS.md](STATUS.md) for verified scope.

## 4. Performance direction

The design aims to keep communication and isolation costs small, without
assuming a speedup on every workload or backend:

| Mechanism | Intended benefit | Qualification |
| --- | --- | --- |
| Shared-memory rings and buffer ownership transfer | Avoid payload copies between services | Metadata and handles still move; device and user paths may copy |
| Direct handoff and time-slice donation | Reduce scheduling delay on a service call | Applies when the scheduler can use the handoff path |
| PKS, MTE, or PCID domain switching | Isolate mapped domain resources without a process boundary for each service | Cost and protection coverage differ by backend |
| P2P DMA and user-level interrupts | Permit shorter device paths on capable hardware | Hardware support and end-to-end deployment remain separate milestones |
| Global LTO | Optimize across kernel crates | Performance claims require the protocol in `verification/` |

## 5. Development stages

Stages 1 (Skeleton), 2 (Barrier), 3 (Flow), and the in-tree Stage 4
(Compatibility) gate have closed. Compatibility and desktop work continue.
Stage 5 (Silicon) targets boot, native graphics, input, Wi-Fi, and persistent
storage on the selected AMD laptops. [STATUS.md](STATUS.md) records the
current gates and remaining work.
