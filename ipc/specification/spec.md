# ipc — Specification

> Status: **v1.0** (Stage 3 design lock). v0.1 covered Narf-Ring
> primitives + cancellation; v1.0 locks the MPSC variant, slot
> sizing rules, the CBOR schema layer the driver framework uses
> for cross-driver service IPC, and ABI versioning.

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

## 8. Resolved decisions

### 8.1 SPSC + MPSC (resolved)

**Decision (was open):** ship both **SPSC** and **MPSC**
variants in Stage 3.

```rust
pub struct SpscRing<T: RingMsg, const N: usize> { /* head/tail u32 */ }
pub struct MpscRing<T: RingMsg, const N: usize> { /* atomic head, plain tail */ }
```

SPSC is the hot-path between a single producer and consumer
(driver completions to driver-host, syscall submissions). MPSC
is required for fan-in to the kernel's audit log, the tracing
ring, and any service that multiple drivers may post into
concurrently. Implementing both upfront avoids retrofit; the
MPSC head uses `fetch_add(1, AcqRel)` to claim a slot, then
publishes payload + sequence-bit per the standard
multi-producer ring protocol.

There is no MPMC variant. A multi-consumer pattern is
expressed as `MPSC into a fan-out task that re-publishes`. The
extra hop is acceptable; true MPMC requires either a per-slot
generation counter (cache-thrashing) or a lock (defeats the
ring's purpose).

### 8.2 Slot sizing (resolved)

**Decision (was open):** every ring has a **fixed slot size
declared at construction**, ranging from 32 bytes to 4096
bytes in powers of two. Slots <= 256 bytes hold messages
inline. Slots > 256 bytes are practical only for ring-pair
configurations where the slot contents are pre-allocated DMA
buffers (e.g. `BlkSubmission` carrying inline 512-byte
payloads).

**Variable-sized messages** are expressed as a fixed-slot
header + an indirect cap reference to a separately-allocated
buffer:

```rust
struct BulkMessage {
    hdr:      MessageHeader,    // fits in slot
    payload:  Cap<DmaBuffer, _>, // separate allocation
}
```

This keeps slot iteration cache-friendly while supporting
arbitrary payload sizes. The drivers framework's wire-format
schemas (drivers/spec §17.3) use this pattern: the CBOR-encoded
message header lives in the slot; large payloads (e.g. a 4 MiB
blob being passed to a crypto driver) are referenced as
`Cap<SharedRegion, _>`.

### 8.3 Flow control (resolved)

**Decision (was open):** **blocking-when-full with waker
integration**, not credit-based. Credits add per-message
overhead and a separate state machine; waker-based blocking
is what the executor already does for every other Pending
future and integrates cleanly with `scheduler/`'s budget
caps.

`send` returns `Err(Full)` only when the sender is in a
non-blocking context (no Waker installed, or
`SubmissionFlags::NONBLOCK`). The default `send_blocking`
helper installs a waker on the consumer's tail-advance
notification and yields.

### 8.4 SecureRing (resolved by punting)

**Decision (was open):** `SecureRing` is **out of scope for
`ipc/` v1.0**. It will be specified in `crypto/` as a wrapper
type — `SecureRing<T>` is a `Ring<T>` where every send/recv
goes through AEAD + replay-protection. The ring primitives
here are the substrate; the crypto wrapping is layered on
without modification to this spec.

`crypto/` Stage 4 work picks this up; `ipc/` doesn't need to
wait.

## 9. Cross-driver service IPC layer

The drivers framework (`drivers/spec` §17.3) builds a
service-IPC layer **on top of** Narf-Rings. This spec owns the
ring; `drivers/` owns the service binding. The wire format the
two share is locked here:

### 9.1 Service message envelope

```rust
#[repr(C)]
pub struct ServiceMessage {
    pub service:      Uuid,                 // service identity
    pub wire_version: u16,                  // wire schema version
    pub op:           u32,                  // service-defined op number
    pub flags:        u16,                  // SubmissionFlags
    pub tag:          u64,                  // matched on completion
    pub cbor_len:     u32,                  // body length in bytes
    // CBOR body follows up to cbor_len bytes
    // _padding to slot boundary
}
```

### 9.2 CBOR schema discipline

Service bodies are CBOR-encoded against a published `.cddl`
schema. CBOR is chosen because:

- Self-describing — the receiver can decode without the
  schema, surface "unknown field" errors deterministically.
- Versionable — adding fields is backward-compatible (old
  receivers ignore unknowns).
- Small encoder/decoder — fits the `crypto/` AEAD ring's
  performance budget for `SecureRing` wrappers.
- Canonical encoding mode available — important for
  signature contexts.

**Wire-version evolution** mirrors syscall versioning:

- Each service has a published `MIN_VERSION` and
  `MAX_VERSION`. The provider declares which versions it
  supports; consumers declare a range; the loader matches.
- Adding a field with a default = `wire_version + 0` (no
  bump) on the provider side; consumers built against the
  old version ignore the field.
- Removing or changing a field's CBOR tag = wire-version
  bump. Old wire versions stay supported for at least 2
  minor SDK cycles before retirement.

### 9.3 Tag space

`ServiceMessage::tag` is opaque to the IPC layer. The
producer matches it on the completion side — same mechanism
as `abi/` ring submissions. Tags are 64 bits to avoid wrap
in normal usage.

## 10. ABI versioning

Ring layout is part of the cap-ABI in §4 (head index location,
slot stride, generation+flag bits). Changes are tracked under
`CAP_ABI_MAJOR` (capabilities/spec §10) — bumping ring layout
requires a major bump because any cap-table format change
requires the same.

The ServiceMessage envelope (§9.1) is part of the IPC ABI; its
fields are fixed at v1.0. Adding fields = `IPC_ABI_MINOR` bump;
removing/renumbering = major bump.

`narf-driver-sdk` re-exports the ServiceMessage envelope at
`@v0`; future bumps follow the §10 contract above.

## 11. Open questions

(none — all v0.1 questions resolved in §8; SecureRing is
deferred to `crypto/`)
