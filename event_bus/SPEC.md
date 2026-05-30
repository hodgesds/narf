# NARF Event Bus — Design Specification

Status: planning-only. No implementation in this commit.
Date: 2026-05-29.
Author: planning agent (Claude Opus 4.7).
License: GPL-2.0-or-later.

## 1. Goal + non-goals

### Goal

A first-class publish/subscribe bus that lets any NARF component
fan out events to many subscribers with bounded latency, no
publisher slowdown caused by slow subscribers, and one integration
shape for both in-kernel callers (driver IRQ bottom-halves, init
sequences) and userspace daemons (file descriptors driving the
existing `poll(2)`/`epoll(2)` syscalls in `userspace/src/epoll.rs`).
Cap-gated end-to-end: create-topic, publish, and subscribe are
three distinct capabilities so a hostile driver can hear without
speaking, or speak without hearing. The bus replaces today's seven
scattered fan-out mechanisms (`filesystem/src/uevent.rs`,
`input/src/evdev.rs`, `bus/src/acpi_notify.rs`,
`aml/src/buttons.rs`, `power/src/thermal.rs`, two more) so that
"X happened, tell everyone who cares" is one mechanism.

### Non-goals

Not a general-purpose IPC channel: `narf_ipc` SPSC/MPSC ownership-
transfer rings remain the right primitive for handing one `Frame`
to one consumer. Not a message broker: no persistent backing, no
federation, no queue groups, no delivery guarantees beyond
at-most-once-with-explicit-drop-signal. Not a tracing surface:
`tracing::FlightRing` already provides drop-oldest history for
post-mortem snapshots; the bus is live fan-out. Does not paper over
the framekernel domain boundary: cross-domain subscriptions are
explicit PKS-mapped cap-gated shared regions, not transparent.

## 2. What NARF has today

NARF already has roughly *seven* separate event-fan-out mechanisms,
each shaped by its caller and not reusable:

**`filesystem/src/uevent.rs`** — the closest to a real bus. Global
`IrqSafeSpinLock<Ring>` of up to 256 `UeventEnv` (variable-size:
action + devpath + subsystem + extras). `UeventReader`s carry
per-reader `next_seqnum` cursors. Drop-oldest silently; no
SYN_DROPPED signal; allocations-per-publish; no async wakeups.

**`input/src/lib.rs` per-class `EventRing`s** — bounded
`VecDeque`-backed SPSC rings (Key/Pointer/Scroll/Absolute/Touch/
Button/AsciiByte). Producer is the IRQ handler, single consumer
each. Drop-oldest. No fan-out.

**`input/src/evdev.rs` Router + DeviceNode** — per-device 256-slot
`VecDeque<EvdevEvent>`, per-reader `Waker`, IRQ-driven `dispatch()`
synthesises `SYN_DROPPED` on overflow. The source comment is honest:
"each reader drains from [a single per-device ring]" — competitive
many-to-one, not fan-out.

**`narf_ipc::Ring<T, N>`** — workhorse zero-copy ownership-transfer
SPSC (cache-line-partitioned head/tail, release/acquire pairs, MTE
`Retag` hook, producer + consumer wakers).

**`narf_ipc::spmc_ring::SpmcRing<T, N>`** — Vyukov bounded queue:
one producer, *competitive* consumers (CAS-claim per slot). Solves
work-stealing, not fan-out.

**`tracing::FlightRing<T: Copy, N>`** — multi-producer wait-free
drop-oldest with seqlock-protected slots (odd=writing, even=
published). Consumers snapshot the whole ring on demand. No
per-consumer cursor. Closest existing in-tree implementation to the
Disruptor publish step.

**`bus/src/acpi_notify.rs`** and **`aml/src/buttons.rs`** — both
implement the classic `Box<dyn Fn(&Event)>` subscriber list under a
spinlock with `fan_out` snapshotting handlers and calling them with
the lock released (a deadlock-avoidance pattern documented in
`aml/src/buttons.rs::fan_out`). Callbacks run in the dispatcher's
context — usually an SCI bottom-half. `power/src/thermal.rs` uses
the same shape for thermal-zone crossings.

**Net `bypass/` 4-ring AF_XDP** (FILL/RX/TX/COMPLETION, each an
SPSC `Ring<u64, 64>`) is the existing framekernel zero-copy
zero-cross-domain pattern: UMEM region + four rings handed via
cap. Not fan-out — single daemon per NIC.

**`userspace/src/epoll.rs`** already has the syscall surface
(`sys_epoll_create1` / `_ctl` / `_wait`) wired to
`FileOps::poll_readiness() -> u32` on `filesystem/src/lib.rs`. Any
new in-kernel ring that wants to be epoll-pollable backs a file
with a `poll_readiness` impl.

Two ergonomic shapes coexist today: **sync callbacks** (acpi_notify,
buttons, thermal — runs in producer context, must not block) and
**per-reader rings** (uevent, evdev, input per-class — async,
drop-oldest, no publisher backpressure). The bus unifies both.

## 3. Prior art

**LMAX Disruptor** is the canonical SPMC ring for fan-out: producer
claims monotonic sequence numbers, consumers each carry a `Sequence`
cursor and lag freely, slots recycle once the slowest consumer
passes them. *Borrow:* per-consumer cursor, cache-line padding,
fixed pre-allocated slots, sequence-barrier discipline. *Skip:* the
publisher-waits-on-slowest-consumer policy — it gives a slow
subscriber an unbounded blast radius (see §4.5).

**NATS / JetStream** provides subject trees (`net.iface.eth0.link`)
with `*` and `>` wildcards, and an ephemeral-vs-persistent split.
*Borrow:* hierarchical string topics, wildcard match compiled once
at subscribe time. *Skip:* durable streams and the network protocol.

**Linux netlink multicast groups** broadcast to grouped sockets with
`NETLINK_NO_ENOBUFS` choosing between dropping the slow listener and
propagating ENOBUFS to the publisher. Today's uevent ring is the
in-tree mirror. *Borrow:* per-subscriber bounded window, no
publisher slowdown, explicit drop signal. *Skip:* setsockopt — we
have caps.

**kdbus** (rejected 2015–2016) tried to put D-Bus into kernel
shared memory. What it got right: typed messages with credentials,
cap-gated bus creation. What killed it: regex-shaped D-Bus match
rules in the kernel. *Lesson:* keep the kernel matcher trivial
(hierarchical-token wildcard at most); sophisticated filtering goes
in userspace where a slow filter doesn't slow other subscribers.

**io_uring multishot completions** and the SQ/CQ split confirm that
"completion ring is consumer-owned, head is the only coordination
point" works — the shape `narf_ipc` already uses.

**Aeron** (Real Logic) is the production-grade shared-memory SPMC
bus: per-subscriber position counter, term-based recycling, gap
detection via sequence numbers. *Borrow:* per-subscriber position
and gap-via-seqnum. *Skip:* the archive/replay machinery.

**Linux `perf_event` mmap ring** and **eBPF ringbuf** expose a
single-producer + many-mmapped-readers ring to userspace, with a
reserve/commit publish step (essentially the Disruptor publish).
*Borrow:* the mmapped-fd userspace surface (Phase 3) and reserve/
commit at the publisher.

**Erlang/OTP `gen_event`** isolates handler crashes from the
manager. NARF gets the same property for free via separate
tasks/domains; the lesson is the concept, not the mechanism.

**Solaris doors** confirms by contrast that NARF wants strictly
async fan-out (never sync caller-blocks-until-callee).

**AF_BUS** (rejected) and **D-Bus broker** (userspace): upstream
Linux landed on userspace brokers. NARF's framekernel split: bus
engine in-kernel (it's a frame-level coordination primitive),
policy (filters, transformations, durable storage) in userspace.
The kdbus split, done right.

## 4. Design

### 4.1 Ring shape

**SPMC with per-consumer cursor.** One topic = one ring. One
publisher writes (a topic's `Cap<Publisher<T>>` is single-owner);
many consumers each carry a cursor and read independently. This is
exactly the Disruptor shape and matches our existing
`tracing::FlightRing` publisher discipline.

**Slot layout: fixed-size POD per topic.** Variable-size payloads
force either an offset table (extra indirection) or per-slot
allocation (heap churn at publish time, deadly in IRQ context).
The topic's payload type `T: Event` is `Copy + 'static + Send +
Sync`; slot is `MaybeUninit<T>` + `AtomicU64 seq`. If a caller
needs variable payload (e.g. uevent text), the topic carries a
fixed-size record with a pointer/handle into a separate arena
(`SharedRegion`-style cap-gated buffer), not a `Box<[u8]>` per
event. This is a hard rule to keep publish wait-free in IRQ
context.

**Cache-line discipline.** Producer head, the cursor array, and the
slot array each live on `#[repr(align(64))]` cache lines. The
existing `Align64<T>` pattern in `narf_ipc::shared_ring` and
`tracing::FlightRing` already encodes this; the bus reuses it.

**Slot recycling: QSBR is the wrong tool; track-min-cursor is the
right one.** Reclaiming a slot when all consumers have passed it is
identical to Aeron's per-subscriber position counter. The publisher
takes `min(cursor_i)` across live consumers; slots in `[tail,
min_cursor)` are reusable. QSBR is for memory reclamation; here we
have N consumer cursors, and the min is one atomic read per
consumer at publish time (cheap, since N is small — typically
< 16 per topic).

**Drop policy: drop-newest from publisher, signal SYN_DROPPED-style
gap to slow subscriber.** When the slowest consumer is N-1 slots
behind the publisher (ring full), the publisher *does not block*.
The publisher does not advance the slowest consumer's cursor either
(that would race). Instead: publisher advances head, slot is
overwritten, slow consumer's *next* read detects `seq` jump > 1 and
returns `RecvError::Gapped { skipped: u64 }`. This is exactly
evdev's `SYN_DROPPED` design and Linux's `NETLINK_NO_ENOBUFS`
default. The fast subscribers see no slowdown.

This is the load-bearing choice: the publisher is never penalised by
a slow subscriber. The bus's primary invariant.

### 4.2 Topic model

**Hybrid: typed payload + hierarchical-string topic key.** Every
topic carries one `T: Event` Rust type — `LinkUp`, `Hotplug`,
`ButtonPressed`, etc. — so subscribers get type-safety at the
language level. The string topic key (`net.iface.eth0.link`) is the
*identifier* used to look up the topic in the registry and to
support wildcard subscriptions; it is NOT a per-event field.

A subscriber typically requests one specific `Topic<T>` by name and
gets type-safe events. A wildcard subscriber (`net.iface.*.link`)
matches multiple topics and receives `(topic_name, T)` tuples;
because all matched topics share the same `T`, the type is
preserved. Cross-`T` wildcards (`net.iface.*` matching both link
events and address events) are rejected at subscribe time: each
wildcard must resolve to a single payload type. This keeps the
typed-payload-and-wildcards story coherent without runtime type
erasure.

Topic names: `<root>.<component>.<instance>.<event>` (4-token
default). Roots are reserved: `net`, `block`, `usb`, `acpi`, `fs`,
`input`, `kern`, `pwr`. Maximum 64 bytes for the name, maximum 8
tokens (`.`-separated), max 31 bytes per token. ASCII alnum + `_`
+ `-` + `.` only. Wildcards: `*` (one token) and `**` (one or more
tokens, terminal only). The match is computed once at subscribe
time into a compiled per-subscriber pattern; per-publish work is a
hash-table point-lookup on the topic name.

### 4.3 Subscription API surfaces

Three surfaces, each chosen for a use case:

1. **Async future** (`Subscriber::next().await`) — the standard
   in-kernel pattern. Integrates with the existing executor; waker
   parks until the producer publishes. Cap-gated. The default
   in-kernel surface.

2. **File-descriptor + epoll** (`EventBusFile` implementing
   `FileOps` with a real `poll_readiness()` returning `POLL_IN`
   when the subscriber's cursor is behind head) — for userspace
   daemons that already use `epoll_wait`. The userspace daemon
   `open`s `/dev/eventbus/<topic-name>` (or invokes a `bus_attach`
   syscall returning an fd), then `epoll_ctl(ADD)`s it. This piggy-
   backs on the existing `userspace/src/epoll.rs` syscall layer
   without modification.

3. **No sync-callback.** Explicitly rejected. The existing
   `aml/src/buttons.rs::fan_out` and `bus/src/acpi_notify.rs`
   patterns migrate to the async-future surface; a
   `subscribe_callback(handler)` convenience spawns a task and
   forwards events to a closure for callers that don't want
   `async fn`. Reason: callback-in-publisher-context has already
   shipped two lock-inversion hazards in NARF; async-task isolation
   eliminates the class.

### 4.4 Cap model

Three cap types in `narf_capabilities::CapKind`:

- `CapKind::TopicRegistry` — authority to create new topics.
- `CapKind::Publisher` — per-topic authority to publish.
- `CapKind::Subscriber` — per-topic authority to subscribe (a
  wildcard subscriber holds one `Cap<Subscriber, _>` per matched
  topic, minted by the registry at attach time).

The topic registry mints `(Cap<Publisher<T>>, Cap<Subscriber<T>>)`
pairs when a topic is created. Publisher caps are single-owner
(`!Sync`), enforced at the type level. Subscriber caps are
duplicable (clone bumps refcount). Revocation: bumping the cap
epoch invalidates the cursor on the next `next()`; a revoked
subscriber's cursor is removed from the producer's
min-cursor set immediately, freeing slot recycling.

Following the cached-at-boot rule for `Cap::bootstrap`: each
subsystem registers its topics in its `register_initcalls` and
caches the resulting caps in a static. Bus is never re-bootstrapped
in a hot path.

### 4.5 Backpressure / slow subscribers

The publisher is never slowed by a slow subscriber. The per-cursor
gap-detection-and-signal pattern (§4.1) is the only backpressure
mechanism. Three observable states per subscriber:

- `Ok(T)` — event delivered, cursor advanced.
- `Err(Gapped { skipped: u64 })` — slot at cursor was overwritten;
  cursor is fast-forwarded to head − N + 1, caller learns it lost
  `skipped` events and decides whether to resync from a snapshot.
- `Err(Closed)` — publisher dropped; ring is drained.

The `Gapped` signal is the bus's analogue of `SYN_DROPPED` and
`NETLINK_NO_ENOBUFS`. Subscribers that cannot tolerate gaps must
upgrade out of the bus into a per-subscriber bounded SPSC channel
(use `narf_ipc::channel` for that — the bus is not the right
abstraction).

### 4.6 Ordering and sequence

Per-topic total order (the SPMC ring is a single sequence number
space). No cross-topic ordering guarantee — different topics live in
different rings. If a subscriber needs cross-topic ordering, it
subscribes to both and uses the embedded timestamp.

Each event carries a publisher-stamped `KernelInstant` (TSC cycles,
same as `evdev::EvdevEvent::time` and the existing
`narf_time::now_cycles()`). Sequence numbers are per-topic
monotonic `u64`.

### 4.7 Replay / late join (Phase 4, deferred)

Phase 1–3 are volatile: a subscriber sees only events published
after `subscribe()`. The ring's `N` slots of pre-subscribe history
are not surfaced (cursor starts at current head). Phase 4 adds an
opt-in "start from oldest in window" subscriber flag for callers
that want at-most-N-events-of-history, mirroring
`UeventReader::from_start`. No persistent-across-reboot replay is
planned.

### 4.8 Multi-domain crossing

Cross-domain in NARF means crossing a PKS (x86_64) or MTE (aarch64)
boundary; data moves by cap-gated shared mapping, not by copying.
In-kernel subscribers don't cross: the ring lives in kernel memory
with PKS group set so the publisher's domain has write to the topic
group and subscribers have read-only. Userspace subscribers in
Phase 1–2 use the fd path (§4.3) — kernel copies one record per
`read()`. Phase 3 adds the XDP-style mmapped ring for callers
willing to handle a hostile-reader trust model.

### 4.9 Integration with existing rings

This bus subsumes:

- `bus/src/acpi_notify.rs` — migrated. Topic `acpi.notify.<handle>`,
  payload `NotifyEvent`. Existing `dispatch_notify` becomes a
  `Publisher::publish`.
- `aml/src/buttons.rs` subscribe/fan_out — migrated. Topic
  `acpi.button`, payload `ButtonEvent`.
- `power/src/thermal.rs` subscribe — migrated. Topic
  `pwr.thermal.<zone>`, payload `ThermalEvent`.
- `filesystem/src/uevent.rs` — migrated. Topic `kern.hotplug`,
  payload a fixed-size header + handle into a per-emit `SharedRegion`
  arena (preserves variable-size `extras` without per-publish
  alloc). The `/sys/kernel/uevent_seqnum` file becomes a wrapper
  around the topic's `last_seqnum`.

This bus does *not* subsume:

- `narf_ipc::Ring<T, N>` SPSC and MPSC — they exist for ownership
  transfer (`Frame`s, DMA buffers), where the bus's broadcast
  semantics are wrong.
- `input/src/evdev.rs` per-device ring — kept separate because each
  evdev consumer wants the per-device gating + capability bitmap,
  not a global stream. The router still uses its own ring; if a
  consumer wants "all input events" it subscribes to
  `input.evdev` topic, but per-device consumers stick with the
  router.
- `tracing::FlightRing` — kept separate because it's a snapshot
  ring, not a streaming-fan-out ring. The publishers can co-emit to
  both if a topic also wants post-mortem replay.
- `net/src/bypass/` 4-ring AF_XDP — kept separate. UMEM ownership
  transfer is fundamentally different from event fan-out.

Migration is a single hard cutover per migrated subsystem,
land-in-one-commit-per-subsystem (memory entry: no compat shims).

### 4.10 Naming convention

```
<root>.<component>[.<instance>][.<subject>]
```

Reserved roots: `net` (network), `block` (block devices), `usb`
(USB hotplug), `acpi` (ACPI events + notifies), `fs` (filesystem +
hotplug), `input` (input devices), `kern` (kernel-level: panic,
oops, scheduler deadline), `pwr` (power management + thermal).
Examples:

- `net.iface.eth0.link`
- `net.dhcp.eth0.bound`
- `block.nvme0n1.ready`
- `usb.hotplug` (no instance — all USB plug/unplug)
- `acpi.button` (power/sleep/lid)
- `acpi.notify.<handle>`
- `fs.mount`
- `input.device.add`
- `kern.panic`
- `kern.sched.deadline_miss`
- `pwr.thermal.cpu0`

Wildcards: `net.iface.*.link`, `acpi.**`, `pwr.thermal.*`.

## 5. API sketch

```rust
// ── Core trait ──────────────────────────────────────────────────────

/// Payload type carried by a topic. Bound is `Copy` so publish is a
/// single memcpy into a slot, never an allocation. `Send + Sync +
/// 'static` because the slot is shared across cores.
pub trait Event: Copy + Send + Sync + 'static {}

impl<T: Copy + Send + Sync + 'static> Event for T {}

// ── Topic registry ──────────────────────────────────────────────────

/// Cap-type marker. `Cap<TopicRegistry, Grant>` authorises topic
/// creation.
pub struct TopicRegistry;
impl CapType for TopicRegistry {
    const KIND: CapKind = CapKind::TopicRegistry;
}

#[derive(Debug)]
pub enum CreateError {
    NameTaken,
    NameInvalid,
    PayloadMismatch,
    AuthorityRevoked,
}

/// Create a new topic with name `name`, payload type `T`, ring
/// capacity `N` (must be power of two). Returns the
/// (publisher, base-subscriber) cap pair. Both caps reference the
/// same underlying topic object; revoking one does not revoke the
/// other.
pub fn create_topic<T: Event, const N: usize>(
    cap: &Cap<TopicRegistry, Grant>,
    name: &str,
) -> Result<(Cap<Publisher<T, N>, Invoke>, Cap<Subscriber<T, N>, Invoke>), CreateError>;

/// Look up an existing topic by name, returning a fresh subscriber
/// cap. Used by daemons that want to attach without minting the
/// topic themselves (e.g. DHCP daemon subscribing to
/// `net.iface.*.link`).
pub fn lookup_subscriber<T: Event, const N: usize>(
    cap: &Cap<TopicRegistry, Invoke>,
    name: &str,
) -> Result<Cap<Subscriber<T, N>, Invoke>, LookupError>;

// ── Publisher ───────────────────────────────────────────────────────

/// Single-owner publisher handle for one topic. !Sync.
pub struct Publisher<T: Event, const N: usize> { /* ring + cap */ }

impl<T: Event, const N: usize> CapType for Publisher<T, N> {
    const KIND: CapKind = CapKind::Publisher;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PublishError {
    Revoked,
}

/// Sequence number stamped on the published event. Monotonic per
/// topic. Returned so callers can correlate with subsequent
/// `Gapped { skipped }` signals to other subscribers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SeqNum(pub u64);

impl<T: Event, const N: usize> Publisher<T, N> {
    /// Publish one event. Wait-free at the producer. Never blocks
    /// on slow subscribers — they observe `Gapped` instead.
    ///
    /// Safe to call from IRQ context.
    pub fn publish(&self, event: T) -> Result<SeqNum, PublishError>;

    /// Reserve + commit two-step for callers that want to fill the
    /// slot in place (e.g. avoid copying a 256-byte event onto the
    /// stack first). The reservation holds an exclusive write to the
    /// slot; commit publishes it.
    pub fn reserve(&self) -> Result<Reservation<'_, T, N>, PublishError>;
}

/// In-place reservation. Drop without commit = abandoned slot
/// (counts as a no-op publish for sequencing; subscribers skip).
pub struct Reservation<'p, T: Event, const N: usize> { /* … */ }

impl<'p, T: Event, const N: usize> Reservation<'p, T, N> {
    /// Mutable view of the reserved slot.
    pub fn slot(&mut self) -> &mut T;
    /// Publish the reserved slot, returning its sequence number.
    pub fn commit(self) -> SeqNum;
}

// ── Subscriber ──────────────────────────────────────────────────────

/// One subscriber's view of a topic. Carries its own cursor.
/// `Send`, `!Sync` (single-task draining).
pub struct Subscriber<T: Event, const N: usize> { /* cap + cursor */ }

impl<T: Event, const N: usize> CapType for Subscriber<T, N> {
    const KIND: CapKind = CapKind::Subscriber;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecvError {
    Gapped { skipped: u64 },
    Closed,
    Revoked,
}

impl<T: Event, const N: usize> Subscriber<T, N> {
    /// Async receive. Parks until publisher advances head past
    /// cursor. On gap, returns `Err(Gapped)` once and fast-forwards
    /// cursor to head - N + 1.
    pub async fn next(&mut self) -> Result<(SeqNum, T), RecvError>;

    /// Non-blocking poll. `Ok(None)` = ring empty for us, retry.
    pub fn try_next(&mut self) -> Result<Option<(SeqNum, T)>, RecvError>;

    /// Skip ahead to head; next() returns the next published event.
    /// Discards anything between cursor and head, increments the
    /// per-subscriber drop counter.
    pub fn resync(&mut self);

    /// Snapshot the current ring contents (up to N events newest-
    /// first). Cursor unchanged; useful for replay-on-late-join in
    /// Phase 4.
    pub fn snapshot(&self, out: &mut [T]) -> usize;

    /// Spawn a forwarder task that calls `f` on every event. The
    /// returned `TaskHandle` cancels both the forwarder and the
    /// subscription. Provided so callbacks-from-old-callsites
    /// (acpi_notify, buttons) migrate as `subscribe_callback(|ev|
    /// …)`.
    pub fn subscribe_callback<F>(self, f: F) -> TaskHandle
    where F: FnMut(T) + Send + 'static;
}

// ── Wildcards (Phase 2) ─────────────────────────────────────────────

/// Match multiple topics by pattern. Pattern syntax: `*` (one
/// token), `**` (one-or-more, terminal). All matched topics must
/// share the same payload type `T`; mismatches return
/// `LookupError::PayloadMismatch`.
pub fn subscribe_wildcard<T: Event, const N: usize>(
    cap: &Cap<TopicRegistry, Invoke>,
    pattern: &str,
) -> Result<WildcardSubscriber<T, N>, LookupError>;

pub struct WildcardSubscriber<T: Event, const N: usize> { /* … */ }

impl<T: Event, const N: usize> WildcardSubscriber<T, N> {
    /// Like `Subscriber::next`, but each event arrives with its
    /// originating topic name.
    pub async fn next(&mut self) -> Result<(TopicName, SeqNum, T), RecvError>;
}

// ── File-descriptor surface (Phase 2) ───────────────────────────────

/// Wrap a `Subscriber<T, N>` in a `FileOps` so userspace can
/// `read(2)` + `epoll(2)` it. `read` returns one serialised event
/// per call (header + payload bytes); `poll_readiness` returns
/// `POLL_IN` when the cursor is behind head.
pub fn into_file<T: Event + IntoBytes, const N: usize>(
    sub: Subscriber<T, N>,
) -> Arc<dyn FileOps>;

// ── Topic name ──────────────────────────────────────────────────────

/// Compact fixed-buffer topic name. 64-byte buffer, 8-token max.
/// Implements Display, Hash, Eq.
#[derive(Copy, Clone)]
pub struct TopicName { /* fixed buf */ }

impl TopicName {
    pub fn parse(s: &str) -> Result<Self, NameError>;
    pub fn as_str(&self) -> &str;
}
```

## 6. Phasing

**Phase 1 — In-kernel SPMC ring + async API. No wildcards, no fd.**

Scope: one publisher per topic; per-consumer cursor with min-cursor
slot recycling; gap detection + `Gapped`; cap-gated create/publish/
subscribe; topic registry indexed by name hash; migrate
`bus/src/acpi_notify.rs`, `aml/src/buttons.rs`,
`power/src/thermal.rs` (with a callback-shim so call sites don't
churn). Async-future surface only. Smoke: two subscribers on a
synthetic topic, fan-out + gap signalling on overflow.

Effort: **~1.8 kLoC, 3 weeks.** Engine ~600, registry ~250, cap
kinds + table ~150, Publisher/Subscriber surfaces ~300, migrations
~250 net, tests ~250. Could-be-cut: migrations (~250) — leave old
mechanism alone and ship just the new bus.

**Phase 2 — File-descriptor surface + epoll.**

Scope: `into_file()` wrapping `Subscriber<T>` as `FileOps`,
serialised wire format (header + `#[repr(C)]` payload),
`/dev/eventbus/<topic>` devfs entries, `poll_readiness()` returning
`POLL_IN` when cursor behind head. Then migrate
`filesystem/src/uevent.rs` to attach via fd.

Effort: **~1.4 kLoC, 2 weeks.** The epoll layer already exists; the
work is the `FileOps` wrapper, variable-size payload serialisation,
and the uevent realignment to fixed-header + arena-handle.

**Phase 3 — Wildcards + cross-domain mmapped ring.**

Scope: wildcard subscriptions compiled at subscribe-time;
cross-domain shared mapping (PKS group per topic, MTE retag on
aarch64) reusing the bypass `Umem` mechanism. Userspace mmaps the
ring page and consumes in place (Aeron / eBPF ringbuf shape).
Requires hardening publish to a seqlock so a hostile userspace
reader can't observe torn writes (`tracing::FlightRing` is the
template).

Effort: **~1.6 kLoC, 3 weeks.** Pattern matcher ~300, mmap + PKS
~700, seqlock hardening ~300, tests ~300.

**Phase 4 — Replay / late-join.**

Scope: opt-in `subscribe_from(oldest_in_window)` mirroring
`UeventReader::from_start`; per-topic retention policy (default
volatile, opt-in "keep last N for late joiners"); snapshot-on-
subscribe. No durable backing.

Effort: **~700 lines, 1.5 weeks.** Mostly cursor bookkeeping at
subscribe time.

**Phase 5 — Migrate remaining consumers + delete old code.**

Scope: `kern.sched.deadline_miss`, `kern.panic` (replacing the
`console/src/klog.rs` subscriber-of-last-resort), `usb.hotplug`
(replacing the planned but unbuilt hotplug subscriber list in
`bus/src/hotplug.rs`). Delete the bespoke rings.

Effort: **~800 lines net (more deletion than addition), 1 week.**

**Total: ~6.3 kLoC over ~10 weeks of focused work.**

## 7. Open decisions

> **1. Should wildcard subscriptions be Phase 1 or Phase 3?**
>
> Cost: a wildcard subscription is, at publish time, the publisher
> iterating its topic's wildcard-subscriber list and pushing into
> each. Cheap. The expensive part is the pattern matcher
> (~300 lines) and the "match this name against my pattern" hot path
> (a compiled pattern over fixed tokens — ~20 cycles). If we want to
> migrate `aml/src/buttons.rs` cleanly we don't need wildcards (one
> topic = one payload). Defaulting to Phase 3 above; argument for
> moving to Phase 1 is that uevent migration (Phase 2) is much
> nicer with `kern.hotplug` + `kern.hotplug.usb` + wildcard
> consumers. **Recommend: move to Phase 2** if the registry-and-
> hash-lookup design lands cleanly in Phase 1.

> **2. Is the bus engine inside the kernel TCB or in a dedicated
> driver domain?**
>
> Putting the engine inside the kernel TCB makes publish-from-IRQ
> trivial (same address space, no domain crossing). Putting it in a
> "bus driver" domain matches the framekernel ethos — drivers are
> domain-isolated by default. The downside of the domain version:
> every publish from a driver in domain A crosses into the bus
> driver's domain, which is the exact cost the framekernel design
> wants to amortize. Trade-off worth a user call. Defaulting to
> **engine-in-TCB** above (the ring itself is just data, gated by
> caps; the kernel touches only `head` / `tail` / slot atomics —
> very small surface).

> **3. Variable-size payloads — arena handle or just commit to
> fixed-size everywhere?**
>
> The uevent migration is the test case. Today's uevent ring stores
> `UeventEnv` with a heap-allocated `Vec<(String, String)> extras`
> per entry. The bus's "no allocation in publish" rule says we can't
> keep that shape. Options: (a) reject the uevent migration —
> uevent stays separate; (b) fixed-size 256-byte slot with extras
> truncation; (c) per-emit `SharedRegion` arena, handle stored in
> the slot. Picking (c) above; (a) is the safer fallback. Want
> user input before committing.

> **4. Does the fd surface use one fd per topic, or one fd that
> can subscribe to many topics?**
>
> One-fd-per-topic matches the existing
> `/dev/input/event*` pattern and the existing epoll machinery
> (one fd = one readiness state). One-fd-for-many gives Linux-netlink
> ergonomics (one socket, many multicast groups, one
> `setsockopt(NETLINK_ADD_MEMBERSHIP)` per group). Defaulting to
> **one-fd-per-topic** above for simplicity in Phase 2; the
> many-topics-one-fd ergonomic can be a Phase 4 sugar layer on top.
