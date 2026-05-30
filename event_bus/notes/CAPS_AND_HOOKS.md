# Event Bus — Ring-Hook Adapters + Cap-Guard Hardening (Addendum Notes)

Status: draft addendum. Merges into `SPEC.md` after the sibling planning
agent lands the base spec; until then this lives in `notes/` so neither
agent stomps the other.

This document covers two design areas the base brief left as TODO:

1. **Ring-hook adapters** — bridging existing in-tree ringbuffers into
   bus topics without modifying their sources.
2. **Cap-guard hardening** — tightening the `Cap<…>` model around topic
   minting, publish/subscribe asymmetry, rate limits, revocation, audit,
   and cross-domain semantics.

---

## 1. Ring-Hook Adapters

The bus is not just a new ring — it is also a **fanout layer over
existing rings**. Existing readers of `filesystem::uevent`, evdev,
`narf_ipc` SPSC frames, etc. continue to work unchanged; the bus is an
*additional* consumer.

### 1.1 `RingAdapter` trait

```rust
pub trait RingAdapter: Send + Sync {
    /// Topic this adapter publishes onto. Held as a publish-cap so the
    /// adapter has no privilege beyond the one topic it owns.
    fn topic(&self) -> &TopicName;

    /// One step of work. Returns `Pending` when the source is empty,
    /// `Drained(n)` when n events were forwarded.
    fn pump(&mut self) -> PumpResult;

    /// Adapter-local counters.
    fn stats(&self) -> AdapterStats;
}

pub enum AdapterDirection {
    /// Adapter task pulls from the source ring on its own cadence.
    /// Source is unmodified.
    Pull,
    /// Source pushes into the adapter via a registered hook.
    /// Requires the source to expose a `register_observer` API.
    Push,
}

pub struct AdapterStats {
    pub forwarded: u64,
    pub dropped_topic_full: u64,
    pub dropped_filter: u64,
    pub last_seq: u64,
}
```

Each adapter holds: a **publish cap** for its bus topic
(`Cap<Publish<TopicName>>`), a **read cap** for the source ring (e.g.
`Cap<UeventRead>`), a per-source cursor, a translator closure
(source-frame → bus-event), and an optional sampler/filter run
**before** translation so high-rate sources don't enter the slow path.

### 1.2 Backpressure policy

Hard rule: **an adapter must never block its source ring.** Sources
are often IRQ-context producers (NIC, input, ACPI SCI). On
`TopicFull` the adapter increments `dropped_topic_full` and discards;
periodically it emits `system.bus.adapter_dropped` so observability
sees the loss. Mirrors existing `UEVENT_RING_N` "oldest overwritten
silently" — bus inherits, never worsens, the source's loss semantics.

### 1.3 Per-source adapter shapes

#### `filesystem::uevent` → `system.uevent`
- **Direction:** Pull. Adapter task wakes on `uevent_pump_event` and
  drains via `UeventReader` (existing cursor API; no source change).
- **Sample rate:** 1:1, no filtering — hotplug is low-rate by design
  (256-slot ring covers full boot).
- **Topic:** `system.uevent`
- **Payload:** `{ action: Add|Remove|Change, devpath: String,
  subsystem: String, seq: u64, env: Vec<(String,String)> }`.

#### `narf-input` per-device evdev rings → `input.event.<dev>`
- **Direction:** Pull. One adapter per `/dev/input/eventN`; the
  per-device ring already supports multi-cursor readers, so the
  adapter is just another reader.
- **Sample rate:** 1:1. Input events are user-perceptible; dropping
  them would manifest as missed keypresses.
- **Topic:** `input.event.<dev>` (e.g. `input.event.event0`)
- **Payload:** `{ ts_ns: u64, ev_type: u16, code: u16, value: i32 }`
  (mirrors Linux `struct input_event`).

#### `narf_ipc` SPSC frame rings → `net.frame.<iface>`
- **Direction:** Pull, sampled.
- **Sample rate:** 1:N where N defaults to 256 — full-rate would
  saturate the bus at line rate. Tracing-only topic; not for stack
  consumers.
- **Topic:** `net.frame.<iface>`
- **Payload:** header summary only (`{ iface, len, eth_dst, eth_src,
  ethertype, sample_skip }`). **No frame body copy.**

#### `net::bypass` UMEM rings → `net.bypass.classified.<iface>`
- **Direction:** Push. The bypass classifier already runs per-frame; on
  a classify-to-bypass decision it calls `adapter.notify(meta)` with
  metadata only.
- **Sample rate:** 1:1 of classify-decisions, not 1:1 of frames.
- **Topic:** `net.bypass.classified.<iface>`
- **Payload:** `{ iface, flow_hash: u64, ring_idx, decision: Bypass }`.
  Frame body is never copied — observers can correlate via flow_hash.

#### Kernel console writer → `system.log.<level>`
- **Direction:** Push. Console writer gets an `observe_above(level)`
  hook so adapter is only invoked for `>= threshold` lines.
- **Sample rate:** 1:1 above threshold (default `Warn`).
- **Topic:** `system.log.warn`, `system.log.err`, `system.log.crit`.
- **Payload:** `{ ts_ns, level, subsystem: &'static str, msg: String }`.

#### ACPI events → `system.acpi.<event_id>`
- **Direction:** Push, from the SCI handler. The SCI is rare and
  must finish quickly, so the adapter only enqueues a small record
  and lets the bus pump task do the publish.
- **Sample rate:** 1:1.
- **Topic:** `system.acpi.fixed.<event>` or `system.acpi.gpe.<n>`
- **Payload:** `{ kind: Fixed|Gpe, id: u32, status: u32 }`.

#### `narf-block::registry` add/remove → `block.device.<add|remove>`
- **Direction:** Push. Registry notifies on insertion/removal of a
  `BlockDevice` entry.
- **Sample rate:** 1:1, rare events.
- **Topic:** `block.device.add`, `block.device.remove`
- **Payload:** `{ id, model, lba_size, n_lba, transport: Nvme|Ahci|Virtio }`.

#### net-stack DHCP / IPv6 / route updates → `net.routing.<event>`
- **Direction:** Push from the relevant state machine on transition.
- **Sample rate:** 1:1, low rate.
- **Topic:** `net.routing.dhcp_bound`, `net.routing.ra_received`,
  `net.routing.route_add`, `net.routing.route_del`
- **Payload:** event-specific; always includes `{ iface, family, ts_ns }`.

### 1.4 Adapter lifecycle

Adapters are spawned by the bus init task, one task per adapter, using
a cached `Cap::bootstrap()` at spawn time. They never re-mint caps in
their pump loop (per MEMORY: no caps in hot paths).

---

## 2. Cap-Guard Hardening

### 2.1 Topic minting authority

Only holders of `Cap<TopicRegistry, Write>` can create a new topic.
That cap is minted exactly once at boot into the bus init task and is
**not** handed out freely.

Reserved root prefixes — kernel-only mint:

- `kernel.*`   — internal kernel state (e.g. `kernel.panic`)
- `system.*`   — system-level events (uevent, acpi, log, security)
- `net.*`      — networking subsystem events
- `block.*`    — block-device subsystem events
- `input.*`    — input subsystem events
- `acpi.*`     — raw ACPI fan-out (sub-prefix of `system.acpi.*`)

Userspace daemons mint only under `user.<daemon-name>.*`. The bus
checks the prefix against the requesting cap's domain at mint time
and refuses cross-prefix mints with `MintError::ReservedPrefix`.

### 2.2 Per-topic publish vs subscribe asymmetry

Distinct cap types per topic:

```rust
pub struct Publish<T: TopicTag>;
pub struct Subscribe<T: TopicTag>;
```

A subscriber to `input.event.event0` (e.g. the power-button watcher)
holds `Cap<Subscribe<input::event::event0>>` and **cannot** mint a
`Cap<Publish<…>>` for the same topic. The two cap types are unrelated
in the cap lattice.

For privileged topics — `kernel.panic`, `system.security.audit`,
`system.acpi.*` — publish caps are minted into kernel tasks only
at boot. Userspace can hold subscribe caps but no path exists to
acquire publish caps. Forgery would require corrupting the
object-table itself, which is PKS-protected.

### 2.3 Ring-adapter authority

An adapter that hooks `narf-input` reads through the *existing* cap
type for that ring — `Cap<InputDeviceRead>` — not a new one. The
adapter holds:

- `Cap<InputDeviceRead>` (source) — gives read access to the ring
- `Cap<Publish<input::event::event0>>` (sink)

Revoking the source cap stops the adapter cleanly without involving
the bus at all: next `pump()` returns `RingError::Revoked`, the
adapter task exits, its publish cap is dropped by RAII.

### 2.4 Per-subscriber rate caps

A subscriber cap can carry a max-rate hint:

```rust
pub struct Subscribe<T> {
    max_eps: Option<u32>,   // events/sec; None = unbounded
}
```

The bus tracks a token bucket per subscriber. When the bucket is
empty, events for *that subscriber only* are dropped and counted —
never globally, never affecting other subscribers on the same topic.

### 2.5 Revocation semantics

- **Publisher revoke:** drain in-flight items already in the topic
  ring, then publish no more. Future `publish()` calls return
  `PublishError::Revoked`.
- **Subscriber revoke:** free the cursor slot, do **not** wake the
  pending future (it's already gone), next `recv()` on a stale handle
  returns `RecvError::Revoked`.
- **Topic revoke** (admin pulls a topic): all subscribers receive
  a final synthetic event `{ kind: TopicGone }` (analogous to
  SYN_DROPPED), then their cursors error out on next read with
  `RecvError::TopicGone`. Publishers see `PublishError::TopicGone`.

### 2.6 Inspection cap

Read-only `Cap<TopicInspect>` for observability — `lsof`-equivalent
for the bus:

- enumerate active topics
- count subscribers per topic
- read per-topic throughput (events/sec, bytes/sec)
- read per-subscriber lag (events behind head)

**Never sees payloads.** Metadata only. This cap is safe to hand
to a userspace `narfctl bus` command.

### 2.7 Compromised-subscriber containment

A subscriber that fails to drain at its declared rate puts pressure
on the topic's high-water mark. Adaptive tightening:

1. Bus measures per-subscriber lag every `LAG_SAMPLE_MS` (default 100ms).
2. Lag > `LAG_SOFT` (e.g. 1024) sustained `LAG_SUSTAIN_MS` (1s) →
   effective rate cap halves.
3. Further sustained lag → halve again, down to a 1 event/sec floor.
4. Lag < `LAG_RECOVER` (e.g. 64) for `RECOVER_MS` → restore by one
   doubling step, up to the declared `max_eps`.

Per-subscriber only. Topic's per-subscriber cursor model already
isolates fast/slow readers; the adaptive cap is belt-and-braces.

### 2.8 Audit log

Every cap **mint** and **revoke** against a privileged-root topic
(`kernel.*`, `system.*`, plus any topic explicitly marked
`audit=true` at mint time) emits an event on `system.security.audit`:

```
{ ts_ns, op: Mint|Revoke, cap_kind, topic, requester_domain, granted: bool }
```

`system.security.audit` is itself a privileged topic:

- publish cap: kernel-only (the bus mints itself one at boot)
- subscribe cap: kernel + admin domains only

This gives forensics a trail of who-asked-for-what after a
compromise, independent of console logs.

### 2.9 Cross-domain crossing (PKS / MTE)

When publisher (domain A) publishes onto a topic that subscriber
(domain B) reads, three orthogonal checks gate the read:

1. **Cap presence** — `Cap<Subscribe<T>>`. Required.
2. **PKS key** — topic ring's protection key must permit B's PKRU.
3. **MTE tag** — ring allocation tag must match B's load-time tag.

Cap presence is **necessary but not sufficient**. A forged subscribe
cap (cap-table corruption) still trips the PKS read fault because the
topic memory isn't in B's key set. Conversely, an out-of-band PKS
leak doesn't grant subscribe rights — cap check runs first in
`recv()` before the load.

Topics that cross trust boundaries are allocated in domain-specific
PKS keys at topic-creation time. The bus's per-subscriber wakeup path
touches the ring *under the subscriber's own PKRU* so a compromised
bus cannot exfiltrate payloads it shouldn't see.

---

## Open questions for the sibling spec

- `TopicName`: interned `&'static str` (cheap compare) or `Box<str>`?
  Cap-guard model assumes interned + lazily allocated.
- Topic renaming: recommend immutable + revoke-and-remint so the
  audit trail stays coherent.
- Filter API: typed ADT for in-tree adapters (auditable), closure for
  `user.*` (flexible).
