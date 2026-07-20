# Extending IPC

Crate: `narf-ipc` (`ipc/`).

IPC in NARF is a family of **bounded rings**. The extension seam is
**type-level** (pattern 2 in the [README](README.md)): a single trait,
`RingTransport<T>`, that you implement on your own ring type. There is **no
install slot and no `CapKind`** — by design. Ring choice is per-channel, not
global, so it lives at the type level (`ipc/src/transport.rs:1`):

> `RingTransport<T>` is the generic-not-`dyn` seam that lets downstream
> consumers swap their own ring layout (e.g. an MMIO-doorbell transport
> sitting on top of a device BAR) underneath any code that's written against
> `impl RingTransport<T>`. … there is no install slot and no CapKind: ring
> choice is per-channel, not global, so it lives at the type level instead.

## The seam: `RingTransport<T>`

`ipc/src/transport.rs:37`

```rust
pub trait RingTransport<T>: Send + Sync {
    fn try_push(&self, val: T) -> Result<(), T>; // required; Err(val) hands ownership back
    fn try_pop(&self) -> Option<T>;              // required; None = empty (or closed-empty)
    fn len(&self) -> usize;                       // required
    fn capacity(&self) -> usize;                  // required
    fn is_full(&self) -> bool { self.len() == self.capacity() } // default
    fn is_empty(&self) -> bool { self.len() == 0 }              // default
}
```

Four required methods; two defaults. `try_push` returns `Err(val)` on
full-or-closed so the caller keeps ownership. The trait is `Send + Sync`, but
it is **intended to be used monomorphically** via generics
(`fn f<R: RingTransport<T>>(r: &R)`), *not* as `Box<dyn RingTransport>` —
erasing `T` would force it through a vtable and wreck the cache-line
discipline the in-tree rings are tuned for (`transport.rs:10`). You implement
the trait; consumers written against `impl RingTransport<T>` accept your type
for free.

## In-tree implementations (templates)

All of these `impl RingTransport<T>`:

| Type | Concurrency | Location |
| --- | --- | --- |
| `Ring<T, N>` | SPSC, cache-line partitioned | `impl` at `ipc/src/lib.rs:193` |
| `MpscRing<T, N>` | multi-producer / single-consumer (Vyukov) | `impl` at `ipc/src/mpsc_ring.rs:135` |
| `SpmcRing<T, N>` | single-producer / multi-consumer (Vyukov) | `impl` at `ipc/src/spmc_ring.rs:132` |
| `VecRing<T>` | `VecDeque` behind a spinlock (runtime-sized) | `impl` at `ipc/src/transport.rs:92` |

`VecRing<T>` is the **simplest template** and exists specifically to
"demonstrate the seam from a third party's perspective"
(`transport.rs:23`) — copy it:

```rust
// ipc/src/transport.rs:92
impl<T: Send> RingTransport<T> for VecRing<T> {
    fn try_push(&self, val: T) -> Result<(), T> {
        let mut q = self.inner.lock();
        if q.len() >= self.cap { return Err(val); }
        q.push_back(val);
        Ok(())
    }
    fn try_pop(&self) -> Option<T> { self.inner.lock().pop_front() }
    fn len(&self) -> usize { self.inner.lock().len() }
    fn capacity(&self) -> usize { self.cap }
}
```

## Channel constructors (the ergonomic front doors)

Each concrete ring ships a `(Producer, Consumer)` split. These are *not* the
extension seam — they're the in-tree API — but you'll use them as templates
for your own producer/consumer wrappers:

```rust
pub fn channel<T: Send + 'static + Retag, const N: usize>()   // ipc/src/lib.rs:279
    -> (Producer<T, N>, Consumer<T, N>);
pub fn mpsc_ring_channel<T, const N: usize>()                 // ipc/src/mpsc_ring.rs:503
    -> (MpscRingProducer<T, N>, MpscRingConsumer<T, N>);
pub fn spmc_ring_channel<T, const N: usize>()                 // ipc/src/spmc_ring.rs:504
    -> (SpmcRingProducer<T, N>, SpmcRingConsumer<T, N>);
pub fn mpsc_channel<T>(cap: usize)                            // ipc/src/mpsc.rs:201
    -> (MpscProducer<T>, MpscConsumer<T>);   // non-ring, spinlock VecDeque
```

There is also `SharedRing<T, N>` (`ipc/src/shared_ring.rs:43`) — a
`#[repr(C)]`, wire-stable, **user-mappable** SPSC ring initialised in place
via `unsafe fn init_in(ptr)` (`:115`). Use it when the ring must be mapped
into a user address space (the byte layout is the ABI).

## Capability integration: `Retag`

The SPSC `Ring<T, N>` requires `T: Retag`. `Retag` is the per-payload
pointer-retag hook that keeps aarch64 MTE tags coherent when a value crosses
a memory-tagging domain on publish:

```rust
// ipc/src/retag.rs:26
pub trait Retag: Sized {
    #[inline(always)]
    fn retag(self) -> Self { self }   // identity default
}

// ipc/src/retag.rs:33
pub fn retag_on_publish<T: Retag>(msg: T) -> T { msg.retag() }
```

Primitives, pointers, and `[T; N]` already impl `Retag`
(`retag.rs:46`–`:65`). For your own payload type, either derive nothing and
rely on the identity default (opt in with `impl Retag for MyPayload {}`), or
override `retag()` to call `narf_arch::aarch64::mte::{irg, stg}` per raw-pointer
field. Note `Ring::CapType` maps to `CapKind::Ring` (`ipc/src/lib.rs:176`) —
that's how a ring becomes a capability-guarded object when handed across a
domain boundary.

> Only the SPSC `Ring<T, N>` bounds on `Retag`; `MpscRing` / `SpmcRing` /
> `VecRing` bound only `T: Send`. If your custom transport carries tagged
> pointers across MTE domains, replicate the `Retag` bound + `retag_on_publish`
> call at the publish site.

## Worked example: a custom transport

A doorbell-style transport is exactly what the seam was built for
(`transport.rs:4`). Skeleton:

```rust
#![no_std]
extern crate alloc;
use narf_ipc::RingTransport;

/// A ring living in a device BAR; try_push writes a slot and rings a doorbell.
pub struct BarRing<T> { /* mapped BAR pointer, head/tail MMIO regs, PhantomData<T> */ }

impl<T: Send> RingTransport<T> for BarRing<T> {
    fn try_push(&self, val: T) -> Result<(), T> {
        // if full (read tail reg): return Err(val)
        // else: write val into the slot, bump head reg, ring doorbell; Ok(())
        Err(val) // placeholder
    }
    fn try_pop(&self) -> Option<T> { None /* read slot at tail, bump tail */ }
    fn len(&self) -> usize { 0 }
    fn capacity(&self) -> usize { /* N */ 0 }
}

// Any code generic over `impl RingTransport<T>` now accepts BarRing:
fn drain<T, R: RingTransport<T>>(r: &R) { while let Some(_v) = r.try_pop() {} }
```

No registration call — you hand `BarRing` (or a producer/consumer wrapper
around it) to whatever code consumes `impl RingTransport<T>`.

## Gotchas

- **Monomorphic, not `dyn`.** Write consumers as `fn f<R: RingTransport<T>>`,
  not `Box<dyn RingTransport<T>>`. The trait *is* `Send + Sync` so `dyn` is
  possible, but doing so erases `T` through a vtable and defeats the cache-line
  layout the design depends on (`transport.rs:10`).
- **`try_push` ownership contract.** On failure you **must** return the value
  in `Err(val)`; callers rely on getting it back to retry or surface it.
- **Concurrency is your invariant.** The trait is `&self` on every method; the
  trait itself makes no SPSC/MPSC/MPMC promise. Your impl documents and upholds
  its own concurrency story (as the Vyukov rings do).
- **`Retag` only where pointers cross MTE domains.** Bound on `Retag` only if
  your payload carries raw pointers that traverse a memory-tagging boundary.
- **`no_std` + `alloc`.** As everywhere.
