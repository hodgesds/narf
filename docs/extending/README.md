# Extending NARF — developer reference

This directory documents the **standard extension interfaces** for NARF's
core subsystems: public traits and registration hooks for built-in crates, and
the smaller C ABI available to runtime-loaded modules. For checkout setup and
the normal review loop, begin with the [developer guide](../DEVELOPER_GUIDE.md).

The philosophy is the one described in [`../PLUGGABILITY.md`](../PLUGGABILITY.md):
many core subsystems separate mechanism from replaceable policy. This reference
goes one level deeper: it identifies the real trait surfaces, registration
entry points, and minimal worked skeletons for an extension crate.

External built-ins and modules can be selected without editing this repository;
start with [composition.md](composition.md). Individual subsystem docs still
flag places where no public registration seam exists. Paths and symbol names
are navigation aids; the current source and subsystem specification remain
authoritative.

## Workspace layout

NARF is a single Cargo workspace (`Cargo.toml`) so fat LTO can span every
crate. The subsystems this reference covers:

| Crate                 | Path            | Extension doc |
| --------------------- | --------------- | ------------- |
| `narf-filesystem`     | `filesystem/`   | [filesystem.md](filesystem.md) |
| `narf-memory`         | `memory/`       | [memory.md](memory.md) |
| `narf-scheduler`      | `scheduler/`    | [scheduler.md](scheduler.md) |
| `narf-ipc`            | `ipc/`          | [ipc.md](ipc.md) |
| `narf-capabilities` / `narf-security` | `capabilities/`, `security/` | [capabilities.md](capabilities.md) |
| syscall table         | `userspace/`    | [syscalls.md](syscalls.md) |
| runtime modules       | `modules/`      | [modules.md](modules.md) |
| external composition  | `build/xtask/`  | [composition.md](composition.md) |

> `security-model/` is a spec-only crate (README + `specification/` +
> `research/`; no `src/`). The runtime security code lives in `security/`
> and is covered by [capabilities.md](capabilities.md).

## Drivers & peripheral subsystems

Writing a driver starts with a choice: link it into the kernel and use the Rust
subsystem traits, or build it as a runtime `.ko` against the curated primitive
C ABI. Start with [drivers.md](drivers.md) for the built-in initcall and bus
model, and [modules.md](modules.md) for the runtime path.

| Subsystem      | Extension doc | Seam |
| -------------- | ------------- | ---- |
| Driver model / buses | [drivers.md](drivers.md) | `narf_init::register(Stage, …)` + bus match |
| Runtime modules | [modules.md](modules.md) | `.ko` manifest + stable C KABI |
| Block devices  | [block.md](block.md)      | `narf-block` + `root_mount` FS factory |
| Network        | [net.md](net.md)          | `narf_net::Interface` |
| Input / HID    | [input.md](input.md)      | evdev `ROUTER.register_device` + `hid` parser |
| Graphics / DRM | [graphics.md](graphics.md)| `FbScanout` / `DrmCard` / EDID |
| Sound          | [sound.md](sound.md)      | `AudioStream` + HDA registration |
| Char devices   | [chardev.md](chardev.md)  | `FileOps` + devfs publication hooks |

Places where clean extension is **not** possible today are flagged in the
relevant doc. The composition overlay provides link-time retention for an
external built-in. A runtime module is limited to the symbols actually exported
by `modules/src/kabi.rs`; most internal Rust traits are deliberately not a
binary ABI. Platform-device discovery, crypto algorithms, and several backend
pickers also remain closed sets. See [drivers.md](drivers.md) and
[modules.md](modules.md) for the precise boundary.

## The three extension patterns

NARF exposes extension seams in three shapes. Knowing which one a subsystem
uses tells you what your crate must do.

### 1. Cap-gated global install (policy backends)

A trait, a static slot holding the current backend, and a
`install_*(&Cap<Kind, Grant>, impl Trait)` function that swaps it. You
implement the trait in your crate and call `install_*` at boot with a
`Grant` capability. This is the [`../PLUGGABILITY.md`](../PLUGGABILITY.md)
shape.

Used by: **memory** (`HeapBackend`, `FrameAlloc`, `Pager`),
**scheduler** (`Scheduler`, `DonationPolicy`, `StealStrategy`).

### 2. Type-level / per-instance trait (no global slot)

A trait you implement on your own type; there is no install slot because the
choice is per-object, not global. You hand your instance to the subsystem
directly.

Used by: **filesystem** (`FsInstance`/`DirOps`/`FileOps` — you `mount_arc`
your instance), **ipc** (`RingTransport` — monomorphised per channel, no
install slot by design).

### 3. Runtime-loaded native module

A separately compiled `.ko` declares metadata, required capabilities, and
dependencies, then resolves only stable `extern "C"` KSYMTAB imports. It cannot
pass Rust traits or `repr(Rust)` types across the boundary. See
[modules.md](modules.md); the dual-build e1000 crate is the current reference.

### The syscall table and capabilities are special cases

- The **syscall table** uses a global table with a public `install_raw`, but
  the `Syscall` enum + per-arch `LINUX_TABLE` are compile-time. You can add a
  handler to an existing variant or a NARF-extension slot without editing
  core, but adding a *new Linux wire number* requires editing
  `userspace/src/syscall.rs`. See [syscalls.md](syscalls.md).
- **Capabilities** are the substrate the other seams gate on. You define a
  new capability-guarded resource by implementing `CapType` on a marker type
  in your own crate — *if* an existing `CapKind` fits. Adding a brand-new
  `CapKind` requires editing `capabilities/src/lib.rs`. See
  [capabilities.md](capabilities.md).

## Capability model in one paragraph

Authority in NARF is a `Cap<T, R>` — a typed token where `T: CapType` names
the resource kind and `R: Rights` names the granted rights
(`Read`/`Write`/`Grant`/`Spend`/`Invoke`). Rights form a lattice; `derive`
only ever *weakens* (`SubsetOf<R>` enforced at compile time). A cap is minted
from nothing only via `Cap::<T, R>::bootstrap()` (a TCB path), and revoked in
O(1) via an epoch bump on the object table. Every install/mount hook above
takes a `&Cap<…, Grant>` and calls `check_live()` before any side effect.
Full detail in [capabilities.md](capabilities.md).

## no_std / alloc constraints

Every core crate is `#![no_std]`. Your extension crate must be too. `alloc`
is available (heap is up before any of these seams are used), so `Box`,
`Arc`, `Vec`, `String` are fine — but there is no `std`. Async seams
(`FsFuture`) return `Pin<Box<dyn Future + Send>>`; see the per-subsystem
gotchas.

## Accuracy note

If an API here no longer matches the tree, the tree and its subsystem
specification win. Open a documentation fix rather than trusting stale prose.
