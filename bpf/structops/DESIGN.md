# Struct Ops Hardening and Sleepable Execution Requirements

This document defines the security, lifecycle, and execution requirements for
runtime-supplied implementations of NARF kernel traits. Atomic and sleepable
targets share one contract and attachment lifecycle, but have deliberately
different Rust call surfaces.

The design treats every BPF program as hostile. A successful verifier verdict
does not grant ambient kernel access, and a struct-ops attachment does not make
the program equivalent to a trusted kernel module.

Current status: the atomic requirements and the initial interpreted sleepable
ABI below are implemented. Mixed-context targets and native continuation-style
lowering remain deferred.

## Shared method contract

Every method has one immutable `StructOpsContract` carried from load through
attachment and dispatch. It contains:

- a stable target id and method id;
- an ABI hash covering the target version and method signature;
- the exact context fields and result descriptor;
- the complete kfunc allowlist;
- `Atomic` or `Sleepable` execution context;
- a per-invocation fuel budget; and
- the required native fallback policy.

The loader must verify against this contract rather than the generic BPF
context and global kfunc registry. Installation and dispatch must compare the
program's retained contract with the method descriptor again. Programs loaded
for tracing, XDP, another struct-ops method, or the generic scalar context must
not attach.

Struct-ops context arguments are a distinct type class. The initial interface
admits fixed-width scalars and booleans only. Rust references, raw pointers,
physical addresses, general kernel pointers, and verifier pointer wrappers are
not context arguments. Consequently this design introduces no physical-memory
to frame-memory translation API. A future memory-bearing hook must expose a
purpose-built capability or mediated object type with explicit lifetime and
domain rules.

`BpfCtxArg` is sealed to those scalar implementations. Treating a kernel or
physical address as an integer before calling the adapter also violates the
contract and must be rejected during target review; a scalar spelling does not
turn an address into safe data.

## Atomic struct ops requirements

Atomic `struct_ops` is the first supported form and has these requirements:

1. The method contract declares `Context::Atomic`; its kfunc allowlist contains
   only atomic-safe operations.
2. A generated, target-specific builder loads each program through
   `BpfProg::load_for_struct_ops`. Callers do not bind method-name strings or
   pass an arbitrary preloaded `BpfProg` to installation.
3. The generated adapter encodes only `BpfCtxArg` values and invokes the exact
   retained method contract. Generic `run_atomic` is not an execution path for
   contract-bound programs.
4. Every method declares a native fallback and validates the raw BPF result
   before converting it to the Rust return type. Missing programs, rejected
   execution, traps, fuel exhaustion, and invalid results use that fallback.
5. Installation returns one non-cloneable owning `StructOpsLink`. Explicit
   close or drop detaches its generation. Replacing an attachment creates a new
   generation, so dropping a displaced link cannot detach its replacement.
6. Live subsystem slots hold `Arc` values. A caller clones the active value
   while holding the slot lock, releases the lock, and only then executes BPF.
   Replacement and detach likewise drop displaced values after releasing the
   lock.
7. Installation is transactional: descriptor validation and all fallible
   allocation happen before the subsystem publishes the adapter. A failed
   commit leaves both the live slot and attachment registry unchanged.

Atomic callbacks must not allocate, await, or acquire a lock that can be held
by their caller. Their fuel budget must be chosen for the specific hook rather
than inherited from the generic global maximum.

The idle governor remains atomic. After either BPF or native selection,
`power` must revalidate the selected state against the live C-state table,
latency budget, and predicted residency. An invalid or stale result selects C0
when C0 is present rather than trusting the policy result.

## Sleepable struct ops requirements

Sleepable methods require an asynchronous call surface. A verifier can prove
that bytecode is safe across suspension, but it cannot make a synchronous Rust
caller drive a future that returned `Pending`.

The initial sleepable design classifies an entire target as sleepable;
mixed atomic and sleepable methods in one trait are deferred. A dynamically
replaceable target uses NARF's existing object-safe future convention:

```rust
pub type StructOpsFuture<'a, T> =
    Pin<Box<dyn Future<Output = T> + Send + 'a>>;
```

A `struct_ops!` target opts in with `#[context(Sleepable)]` and declares its
methods with `async fn`. The macro lowers those declarations to
`StructOpsFuture`; the generated adapter awaits the exact-contract
`BpfProg::run_struct_ops_sleepable` dispatcher. A synchronous caller may not
hide the operation behind `block_on`, especially from an executor poll or while
holding `IrqSafeSpinLock`. Hooks that require an immediate decision—idle
selection, scheduler pick-next, interrupt filtering, and XDP—therefore cannot
be sleepable.

The sleepable implementation enforces all of the following:

- the hook contract and loaded program both declare `Context::Sleepable`;
- each sleepable kfunc call remains an await point in the verifier;
- values in `NonPreemptible` and `RcuRead` domains, including lock guards, are
  rejected when live across an await;
- only `Static`, `Owned`, and `SleepableRcuRead` values may survive;
- the VM stack, registers, maps, and remaining fuel live in the future across
  polls, and fuel is never refilled;
- BPF domain rights are entered for each poll and restored before returning
  `Pending`;
- the live adapter is retained by `Arc` without holding the slot lock across
  `.await`;
- dropping the invocation future cancels that invocation and releases its VM
  resources; and
- closing the owning link prevents new calls while already-created futures
  retain their adapter and finish normally.

The adapter and link share an atomic admission gate. Invocation creation reads
the gate once: a successful read defines an in-flight call. Link close and
replacement close the old generation's gate, so a retained `Arc` can no longer
start BPF after detach and instead takes the declared fallback.

Sleepable fallbacks must themselves have an async-compatible interface. Result
validation occurs after the BPF future completes and before its value reaches
the subsystem.

## Verifier and runtime responsibilities

The verifier is responsible for bytecode-level safety: context compatibility,
kfunc availability, reference validity at await points, stack bounds, control
flow, and total fuel. The loader supplies only the method's context and kfunc
allowlist, so a verifier success cannot authorize an undeclared effect.

The verifier does not own attachment lifetime or Rust call-site behavior. The
generated API and runtime must separately enforce the exact method identity,
async polling requirement, link generation, cancellation, fallback behavior,
slot locking, and domain restoration.

## Acceptance requirements

Atomic support is complete only when tests demonstrate:

- generic, XDP, tracing, sleepable, and wrong-method programs are rejected;
- a disallowed kfunc is rejected during verification;
- pointer-bearing context signatures fail to compile;
- invalid results, traps, and fuel exhaustion invoke the declared fallback;
- link close and drop detach, and an old link cannot detach a replacement;
- callbacks execute after the live-slot lock is released;
- displaced adapters and programs are destroyed outside IRQ-masking locks; and
- the idle governor rejects states that violate current latency or residency
  constraints.

Sleepable coverage includes a genuine multi-poll kfunc, verifier rejection of
references across await, cancellation by future drop, domain-state restoration
on every `Pending`, detachment with an in-flight future, rejection of calls
created after detach, async fallback validation, and a `Send` future-only API.

## Deferred choices

The first sleepable implementation uses boxed futures because NARF already uses
that object-safe ABI. A pooled or explicit `poll` ABI may remove the per-call
allocation later, but it must preserve cancellation and ownership semantics.
The macro re-declares the target trait: `async fn` is declaration syntax, while
the emitted object-safe trait returns `StructOpsFuture`.
