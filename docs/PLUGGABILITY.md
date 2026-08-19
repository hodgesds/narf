# Pluggability — how core policies are swapped

NARF's core subsystems are *framework + policy*: the framework is in
tree and stable; the policy is a runtime-installable backend behind a
trait. A downstream consumer (research kernel fork, custom workload,
hardware bring-up tooling) can replace the policy without forking the
core. This document describes the single shape every pluggable
subsystem follows.

## The shape

Every pluggable subsystem in NARF follows one pattern:

1. **A trait** that describes the policy surface.

   ```rust
   pub trait FooPolicy: Send + Sync + 'static {
       fn name(&self) -> &'static str;
       fn do_the_thing(&self, ...) -> Outcome;
   }
   ```

2. **A `CapType` marker** in `capabilities::CapKind` that names the
   authority to install. Markers for pluggable backends live in the
   `0x0200..` range — see `capabilities/src/lib.rs`.

3. **A static slot** holding the currently installed backend.
   `IrqSafeSpinLock<Option<Box<dyn FooPolicy>>>` is the convention.

   ```rust
   static FOO: IrqSafeSpinLock<Option<Box<dyn FooPolicy>>> =
       IrqSafeSpinLock::new(None);
   ```

4. **A cap-gated install function**.

   ```rust
   pub fn install_foo<P: FooPolicy>(
       cap: &Cap<FooKind, Grant>,
       p: P,
   ) -> Result<(), FooError> {
       cap.check_live()?;
       *FOO.lock() = Some(Box::new(p));
       Ok(())
   }
   ```

5. **One or more in-tree implementations**.
   At least two: the default (planted at boot in `init()`) and one
   alternative, so the seam is exercised from the day the trait lands.

   ```rust
   pub struct DefaultFoo;
   impl FooPolicy for DefaultFoo { ... }

   pub struct AlternativeFoo;
   impl FooPolicy for AlternativeFoo { ... }
   ```

6. **Free functions on the module** call through the slot — callers
   never see the `Box<dyn>` directly.

   ```rust
   pub fn do_the_thing(...) -> Outcome {
       FOO.lock().as_ref().expect("init").do_the_thing(...)
   }
   ```

The canonical reference is `power::GovernorPolicy` + `install_governor`
in `power/src/lib.rs:538` — every wave of the pluggability pass mirrors
its shape verbatim.

## When a wave deviates

Two waves break the `Box<dyn>` pattern, both for principled reasons:

- **Frame allocator** lives *below* the heap. Boot installs a default
  *before* the heap is alive, so the slot can't hold a `Box`. The slot
  is `AtomicPtr<&'static dyn FrameAlloc>` and the default is a
  `static` value (not boxed). Once the heap is up, swap-out from a
  downstream goes through the same `install_frame_alloc` entry point,
  also storing a `&'static dyn` (downstream pins its impl in its own
  rodata/bss).
- **IPC ring transport** is per-channel, not global. Every Narf-Ring
  is monomorphised on its element type for cache layout reasons; the
  trait is parameterised generic, not object-safe-`dyn`. There is no
  install function — choice happens at the producer/consumer factory
  call site.

## Hot-path cost

The trait surface adds one `AtomicPtr` load + one indirect call per
crossing. For most subsystems this is dwarfed by the work each call
does (page-table walk, cap check, queue manipulation). For ultra-hot
paths — specifically the tracing sink, which can be entered from every
`probe!` site — the default-noop case must inline. The convention is a
null-check fast-path at the macro expansion:

```rust
if SINK.load(Relaxed).is_null() { return; }
// only then dispatch through the trait
```

so a workload with no installed sink pays one predictable branch, not
an indirect call.

## Boot ordering

Each subsystem's `init()` plants the default impl in its slot before
the subsystem is callable. The order is:

1. `memory::frame::init()` — installs `BuddyFrameAlloc`.
2. `memory::heap::init()` — installs `BumpBackend`, later promotes to
   `SlabBackend`.
3. `memory::pager::init()` — installs `NoopPager`.
4. `scheduler::init()` — installs `FifoScheduler`,
   `HeadQueueDonation`, `NumaAwareSteal`.
5. Driver-framework boot — block `IoScheduler`, network `CongestionControl`
   installs land per-device / per-socket later.
6. `power::init()` — installs default `IdleGovernor` next to
   `Performance` DVFS.
7. `tracing::init()` — installs `FlightRecorderSink`.

A downstream's replacement happens any time after the relevant `init()`,
and the install fn revokes its predecessor by dropping the displaced
`Box`.

## Cap markers reserved

The `0x0200..` block in `CapKind`:

| Kind | Authority | Subsystem |
|---|---|---|
| `MemAlloc` (0x0200) | install frame allocator | `memory::frame` |
| `HeapBackend` (0x0201) | install heap backend | `memory::heap` |
| `Pager` (0x0202) | install pager / swap | `memory::pager` |
| `SchedPolicy` (0x0203) | install scheduler policy | `scheduler` |
| `DonationPolicy` (0x0204) | install donation policy | `scheduler` |
| `StealStrategy` (0x0205) | install steal strategy | `scheduler` |
| `IoScheduler` (0x0206) | install per-device I/O scheduler | `block` |
| `CongestionControl` (0x0207) | install per-socket TCP cc | `net::tcp` |
| `IdleGovernor` (0x0208) | install idle governor | `power` |
| `EventSink` (0x0209) | install tracing sink | `tracing` |
| `OomPolicy` (0x020A) | install OOM victim-selection policy | `bpf-oom` |

Each landing wave defines the `CapType` marker struct in its own crate
and impls `CapType { const KIND = CapKind::Foo }` against the reserved
slot.

## Adding a new pluggable subsystem

1. Reserve a `CapKind` slot in `capabilities/src/lib.rs` in the
   `0x0200..` range (or open a new `0x0300..` block if you're starting
   a new family).
2. Add the `(name, kind)` entry to `KIND_NAMES`.
3. In the subsystem crate, define `pub struct YourKind;` + `impl
   CapType` against the reserved slot.
4. Define `pub trait YourPolicy: Send + Sync + 'static`.
5. Add the static slot and `install_your_policy()` fn.
6. Ship at least one alternative impl in-tree.
7. Add a `smoke_pluggable_your_policy()` smoke that installs the
   alternative under a bootstrap cap, exercises the dispatch, and
   reinstalls the default for hygiene.
