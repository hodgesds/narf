# Extending NARF — developer reference

This directory documents the **standard extension interfaces** for NARF's
core subsystems: the public traits and registration hooks you implement in
your **own** crate to extend or replace core functionality *without editing
a core crate*.

The philosophy is the one described in [`../PLUGGABILITY.md`](../PLUGGABILITY.md):
core subsystems are *framework + policy*. The framework is in-tree and
stable; the policy is a runtime-installable backend behind a trait. This
reference goes one level deeper: for each subsystem it quotes the **real**
trait signatures (with `path:line`), the **real** registration entry points,
and a **minimal worked skeleton** for a third-party crate.

Every signature cited here was copied from the tree and carries a
`path:line`. Where the "extend via custom crate" story is *not* cleanly
possible today (i.e. extension requires editing a core crate), the doc says
so plainly.

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

> `security-model/` is a spec-only crate (README + `specification/` +
> `research/`; no `src/`). The runtime security code lives in `security/`
> and is covered by [capabilities.md](capabilities.md).

## The two extension patterns

NARF exposes extension seams in two shapes. Knowing which one a subsystem
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

If you find an API referenced here that no longer matches the tree, the tree
wins — these docs cite `path:line` precisely so drift is easy to catch. Open
a fix rather than trusting the prose.
