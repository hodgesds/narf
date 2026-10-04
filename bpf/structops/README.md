# bpf/structops — struct_ops Program Support

`narf-bpf-structops` provides NARF's `struct_ops` mechanism: the ability for a
subsystem to expose a pluggable set of operations — a trait's worth of methods
— whose implementations are supplied at runtime as verified BPF programs. The
crate carries the `struct_ops!` extension macro, the descriptors that macro
emits describing each pluggable trait and its methods, and the
capability-gated registry that validates and installs a verified set of
programs against one of those traits. Installation returns a generation-tagged
owning link; dropping it detaches the corresponding live implementation and
closes its invocation-admission gate.

## Why it is its own crate

The crate is split out from the parent `narf-bpf` runtime so that a subsystem
wanting a BPF-supplied policy — for example a power-management idle governor
driven by BPF — depends only on this seam rather than on the whole BPF runtime,
and so that `narf-bpf` in turn stays ignorant of the subsystems that plug into
it. This keeps the dependency graph acyclic and the coupling narrow: the
consumer side sees just the extension surface it needs. The macro requires a
handful of runtime types at expansion time, and the crate re-exports exactly
those so the macro's generated paths resolve here rather than forcing a direct
dependency on the full runtime.

## How it fits the subsystem

A `struct_ops` trait declaration produces descriptors into a dedicated link
section, and because this crate holds the only writers of that section, a
force-link anchor keeps the descriptor table from being dropped at link time so
the set of compiled-in traits is actually present in the image. When a
userspace loader submits an implementation, the generated method-specific
builder verifies it against the method's expected context, result, kfunc
allowlist, and fuel budget. Installation is gated on a capability grant before
the adapter reaches the live slot. The macro derives scalar context fields
through `BpfCtxArg` and results through `BpfRet`, so the Rust signature is the
verifier contract without admitting raw kernel pointers or a generic physical
memory translation surface.

Atomic targets declare ordinary trait methods. A whole target can instead add
`#[context(Sleepable)]` and declare `async fn` methods. Those declarations are
lowered to the object-safe `StructOpsFuture<'a, T>` ABI, and the adapter awaits
a heap-stack-backed BPF invocation. A program with no actual sleepable kfunc
call may run to completion natively in one poll; a program that can suspend
runs through the async interpreter until the checkpoint/resume JIT ABI lands.
The future is `Send`, retains its VM state and fuel across polls, and restores
BPF domain rights before every `Pending`. There is intentionally no generated
synchronous wrapper.

A `#[context(Mixed)]` target can combine both call surfaces. Its ordinary
methods are marked `#[context(Atomic)]`; its `async fn` methods are marked
`#[context(Sleepable)]`. Each generated builder and dispatcher uses the
method-level context, so placing both kinds in one trait does not let an atomic
hook call a sleepable program.

## Relationships and no_std

This crate depends on the parent `narf-bpf` runtime (for the interpreter entry
and type descriptors it re-exports), on `bpf/verifier` to prove each supplied
program, and on the capability system to gate installation; subsystems that
offer `struct_ops` policies depend on it rather than on `narf-bpf`. It is
`no_std`. The `kernel-test` feature gates in-kernel smoke tests registered
through `narf-kernel-test`; because those smokes must assemble the BPF programs
they load, the feature also pulls in the ISA assembly helpers from `bpf/isa`.

The hardening contract and the requirements enforced by sleepable targets are
recorded in [`DESIGN.md`](DESIGN.md).
