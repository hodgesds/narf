# Struct Ops Hardening and Sleepable Execution Requirements

This document defines the security, lifecycle, and execution requirements for
runtime-supplied implementations of NARF kernel traits. The immediate delivery
target is hardened atomic `struct_ops`. Sleepable `struct_ops` is a separate
extension: the verifier already models await points, but its public hook and
caller ABI must be asynchronous before sleepable attachment is enabled.

The design treats every BPF program as hostile. A successful verifier verdict
does not grant ambient kernel access, and a struct-ops attachment does not make
the program equivalent to a trusted kernel module.

Current status: the atomic requirements below are implemented. Sleepable
attachment remains disabled pending the asynchronous hook ABI and its
additional acceptance tests.

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

The initial sleepable design should classify an entire target as sleepable;
mixed atomic and sleepable methods in one trait are deferred. A dynamically
replaceable target uses NARF's existing object-safe future convention:

```rust
pub type StructOpsFuture<'a, T> =
    Pin<Box<dyn Future<Output = T> + Send + 'a>>;
```

A sleepable adapter awaits `BpfProg::run_sleepable`. A synchronous caller may
not hide the operation behind `block_on`, especially from an executor poll or
while holding `IrqSafeSpinLock`. Hooks that require an immediate decision—idle
selection, scheduler pick-next, interrupt filtering, and XDP—therefore cannot
be sleepable.

Before sleepable attachment is enabled, all of the following must hold:

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

Sleepable support additionally requires tests for a genuine multi-poll kfunc,
reference rejection across await, cancellation by future drop, domain-state
restoration on every `Pending`, detachment with an in-flight future, and a
compile-time or API-level prohibition on synchronous invocation.

## Deferred choices

The first sleepable implementation may use boxed futures because NARF already
uses that object-safe ABI. A pooled or explicit `poll` ABI may remove the
per-call allocation later, but it must preserve cancellation and ownership
semantics. Whether a future macro mirrors an existing trait or declares a
dedicated trait also remains open; neither choice weakens the contract above.
