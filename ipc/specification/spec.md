# ipc — Specification

> Status: **Outline v0.1** (Stage 3).

## 1. Purpose & scope

**Owns:** Narf-Ring: shared-memory ring layout (header + slot array),
SPSC + MPSC variants, producer/consumer APIs, ownership-transfer
semantics, notification / doorbell path.

**Does NOT own:** The user ABI layered on rings (`abi/`), per-driver
message formats, capability resolution (that's `capabilities/`).

## 2. Assumptions

- `memory/` provides shared-memory regions tagged with two domain IDs
  (producer's and consumer's) so both can access them.
- `capabilities/` gives ring endpoints as caps: `Cap<Ring, Send>` and
  `Cap<Ring, Recv>`.
- `scheduler/` can wake a consumer when a producer posts.

## 3. Public interface

```rust
pub struct Ring<T: RingMsg> { /* MMIO-like: fixed layout, cache-aligned */ }
pub struct Producer<T> { /* holds Cap<Ring<T>, Send> */ }
pub struct Consumer<T> { /* holds Cap<Ring<T>, Recv> */ }

impl<T> Producer<T> { pub fn send(&self, msg: T) -> Result<(), Full>; }
impl<T> Consumer<T> { pub fn recv(&self) -> impl Future<Output = T>; }
```

`T: RingMsg` must be `#[repr(C)]` POD or `Box<Owned>`-style handle.
Moving `T` out of the ring is the ownership transfer — Rust enforces
that the producer can no longer touch it.

## 4. Invariants & safety properties

- Producer and consumer indices are monotonic; wraparound is the only
  decrement, detected by a **wrap counter with a 2-bit generation + an
  explicit AVAIL/USED flag** (virtio-packed-ring discipline). A 1-bit
  generation is insufficient under sustained high-throughput wrap rates.
- **Memory ordering: explicit release/acquire barrier pair on every
  index transition, on every arch.** A slot's payload becomes visible
  to the consumer only after a release store of the tail index; the
  consumer performs an acquire load of the tail before reading any
  slot. On aarch64 this is `STLR` on publish and `LDAR` on consume —
  plain `STR` / `LDR` is a data race the hardware will happily
  execute incorrectly. On x86_64 TSO makes the ordering natural for
  the index but we still emit an explicit release-fence at publish
  so the code is portable and auditable.
- **Ring layout is cache-line partitioned.** The producer-owned head
  index lives in its own cache line. The consumer-owned tail index
  lives in its own cache line. The payload slot array is on a
  separate cache line from both. This avoids Disruptor-style false
  sharing without which the hot path on modern hardware is ~30% slower.
- **Capability transfer across a ring is a hand-off, not an alias.**
  The sender's `Cap<T, R>` is *moved* into the slot (Rust ownership
  prevents retention). On publish, the sender's view is gone; on
  consume, the receiver owns. There is no window where both endpoints
  hold the cap.
- **On aarch64, every pointer written into a ring slot must carry the
  receiver's MTE tag, not the sender's.** The sender's `send(msg)`
  either retags on its way into the slot or refuses the send with
  `Err(DomainMismatch)` if the message holds pointers not authorised
  for retag. Sending a pointer with the sender's tag would leave the
  receiver holding a "legitimately" tagged pointer to another
  domain's memory — a confused deputy. On x86_64 this concern does
  not arise because PKS enforces at access time regardless of how the
  pointer was obtained.
- No two producers on an SPSC ring (type-level guaranteed by `!Sync`).
- Dropping a `Producer` closes the ring; consumer sees EOF.
- **Cancellation of in-flight ring submissions follows `abi/` §3.1.**
  Narf-Rings are the transport beneath the ABI, not a parallel
  cancellation surface: a dropped submission Future on the consumer
  side must result in the producer observing either a terminal
  completion (work done / cancelled / error) or a `Reset` — never a
  silent leak of the slot. Ring-level cancellation (close the whole
  ring) is distinct from op-level cancellation (cancel one
  submission) and is expressed by dropping the `Producer`/`Consumer`
  pair. Per-op cancellation is the ABI's responsibility; the ring
  transports its `OpCode::Cancel` message like any other message.
- **`Consumer::recv()` returns `impl Future<Output = Result<T, RecvError>>`**,
  not `impl Future<Output = T>`. `RecvError` discriminates `Closed`,
  `Reset`, and `CapInvalid` (cap refers to a torn-down ring).
- **Back-pressure policy (see `abi/` §4 for the user-visible form):**
  - SPSC ring full on `send`: returns `Err(Full)`. Callers choose to
    retry (`yield_now().await; send()`), block (`send_blocking`
    helper registers a waker so the task is re-polled when the
    consumer advances), or drop with error. The default helper is
    `send_blocking` — non-spinning.
  - Ring full on consumer-side (no buffer for a completion): the
    consumer sets an overflow flag in the ring header; the producer
    detects the flag on next `send` and refuses until the consumer
    clears it. No completion is silently dropped.

## 5. Architecture notes

### x86_64
- Memory ordering: TSO + release/acquire fences as needed.
- Doorbell via MMIO to a per-ring page, or UIPI-SENDUIPI where available.

### aarch64
- Memory ordering: release/acquire via `STLR`/`LDAR` (weaker model means
  explicit fences matter more than on x86_64).
- Doorbell via `SEV` + event-register poll, or interrupt fallback.

## 6. Dependencies

- **Consumes:** `memory/` (shared regions), `capabilities/` (endpoint
  caps), `scheduler/` (wake), `interrupts/` (doorbell), `arch/`.
- **Provides to:** `abi/`, every driver in `drivers/`, `userspace/`.

## 7. Stage assignment

Stage 3.

## 8. Open questions

- SPSC-only, or do we also need MPSC at Stage 3?
- Slot size: fixed-per-ring vs. indirect-via-handle; trade-off between
  cache behaviour and ability to carry variable-sized messages.
- Flow-control: credit-based vs. blocking-when-full.
- **`SecureRing` variant** (owned by `crypto/`): Narf-Ring wrapped with
  AEAD + replay protection for cross-trust-boundary / cross-machine
  transports. The ring primitives live here; the crypto wrapping and
  handshake live in `crypto/`.
