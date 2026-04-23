# tracing — Specification

> Status: **Outline v0.1** (Stage 1 → 4).

## 1. Purpose & scope

**Owns:** Every event-driven observability surface in NARF.

- **Static markers** — USDT-style compile-time instrumentation points
  (zero cost when unarmed, single `nop`).
- **Dynamic probes** — runtime-installed probes at function entry /
  return / arbitrary instruction addresses.
- **Function-level runtime performance analysis (`FnTime`)** — matched
  entry/return probes that capture wall-clock, cycles, instructions,
  and per-call HW-counter deltas with live aggregate sketches.
- **Flight-recorder rings** — high-rate overwrite-oldest event rings
  that can be snapshotted on a trigger (probe fire, panic, assert).
- **Trace transport** — the per-domain streaming rings and the
  **tracer task** (lives in its own reserved domain) that consumes
  events.
- **Event aggregates** — live sketches (Welford, tDigest) maintained
  either on the producer or the tracer.

**Does NOT own:**

- HW performance counters themselves — `observability/`.
- Debugger attach / crash dumps — `observability/`.
- Statistical analysis of captured traces (bootstrap CIs, regression
  detection) — `verification/`.
- Ring-buffer primitives at the mechanism level — reuses `ipc/`
  Narf-Ring for streaming transport; defines its own SPSC overwrite
  ring for flight-recorder use.

## 2. Assumptions

- `ipc/` provides Narf-Ring primitives usable as trace transport.
- `capabilities/` gates probe installation, marker arming, recorder
  creation, and tracer subscription.
- `memory/` can allocate buffers tagged to a producer domain with
  `Recv` access to the tracer domain where authorised.
- `arch/` exposes instruction-patching primitives (`text_poke_bp` on
  x86_64, `BRK` + I-cache maintenance on aarch64) and any
  hardware-trace primitives (Intel PT, CoreSight ETM).
- `scheduler/` can run the tracer task in its own domain.

## 3. Public interface

### 3.1 Static markers (USDT-style)

NARF adopts the USDT model. A source-embedded marker compiles to a
single `nop` plus an ELF note in `.note.narf.probes` describing the
probe site, provider, name, and argument register map. When a tracer
arms the marker, the `nop` is patched into a call to the handler.

```rust
// Provider "ipc", name "send", three args.
usdt!(ipc, send, ring_id: u32, slot: u16, len: u32);
```

Properties:

- **Zero cost unarmed.** Single `nop`. No branch, no register pressure.
- **Out-of-band metadata.** All site info lives in an ELF note.
- **Provider:name namespacing.** Tracers address markers by string key.
- **Semaphore slot** (optional) — author may guard argument-computation
  with a semaphore the tracer bumps when arming, to skip arg prep when
  the marker is cold.

See [`research/summaries/usdt-and-dynamic-tracing.md`](../research/summaries/usdt-and-dynamic-tracing.md)
for the arming/patching protocol and the ELF note layout.

### 3.2 Dynamic probes

```rust
pub struct Probe;
pub fn install_probe(
    target: ProbeTarget,        // FnAddr(va) | Usdt(provider, name) | AtOffset(va, off)
    kind: ProbeKind,            // Entry | Return | At(offset)
    action: ProbeAction,
    cap: &Cap<Probe, Install>,
) -> Probe;
pub fn remove_probe(p: Probe);

pub enum ProbeAction {
    Capture { fields: &'static [Field] },
    IncrementCounter(SwCounter),
    FnTime { counters: &'static [HwEvent], stream: bool },  // §3.2.1
    Snapshot(SnapshotTriggerSpec),                           // §3.3
    RecordTo(RecorderRef),                                   // push event into flight-recorder ring
}
```

Declarative only. NARF explicitly rejects an eBPF-style VM at probe
sites — probe actions are a fixed enum and compose via chaining
(`action: ProbeAction::Chain(&[a, b, c])` if needed).

**`ProbeAction::Chain` semantics (binding):**

- Signature: `Chain(&'static [ProbeAction])`.
- **Maximum depth: 8.** No nested `Chain` (cycles are impossible by
  construction; the depth bound makes that easy to prove).
- **No allocation** during chain evaluation — the `&'static` slice is
  baked at install time and walked sequentially.
- **Cost-budget check at install time.** `install_probe` computes a
  worst-case cycle estimate (sum of constituent action budgets per
  §3.2.1 + §3.3) and returns `Err(BudgetExceeded)` if the estimate
  exceeds the probe's declared per-fire cycle budget. This prevents
  a chain of cheap actions from silently DoSing a hot site.

#### 3.2.1 Dynamic runtime function-level performance analysis

`FnTime` installs matched entry + return probes (by address, or by a
pair of USDT markers) and on every call captures:

- Wall-clock delta (TSC / `CNTPCT_EL0`).
- Cycle delta (PMU cycle counter).
- Instruction-retired delta.
- Per-caller-requested HW-counter deltas (LLC miss, branch miss,
  dTLB miss, iTLB miss, …) as selected in the `counters` list.
- Call depth within this probe session (for self-time vs. inclusive).

The kernel maintains a per-probe live aggregate:

```rust
pub fn fn_profile(p: &Probe) -> FnProfileSnapshot;
pub struct FnProfileSnapshot {
    pub n:        u64,
    pub wall_ns:  Stat,     // mean, variance (Welford), p50/p95/p99 (tDigest), min, max
    pub cycles:   Stat,
    pub instr:    Stat,
    pub counters: [Stat; MAX_HW_COUNTERS],
}
```

Raw per-call events can optionally stream into a trace ring for
offline analysis (flamegraphs, causal profiling) via
`FnTime { ..., stream: true }`.

Re-entrancy: a per-CPU shadow stack (in the tracer's domain) tracks
nested calls so inclusive/exclusive times are correct. Shadow-stack
overflow drops outer frames and bumps a counter.

**Shadow-stack domain access (resolves cross-cutting hazard with
`memory/` §4.1).** The shadow-stack region is tagged
`DomainId::TRACER` for ownership and reclamation, but every probed
domain D needs *write* access to push/pop its own frames. NARF
solves this by:

1. The Frame allocates one shadow-stack region per (CPU, Domain D)
   pair at probe-install time, tagged `TRACER` for the buffer
   header but with a sub-range carved at PKS rights `RW` for both
   `TRACER` and `D`.
2. The `Cap<FnTimeShadow<D>, RW>` cap is granted to domain D on
   `install_probe`. D may write only into its own carve-out range;
   range-bounds enforced by the cap's invocation surface.
3. The tracer reads any domain's shadow stack via a separate
   `Cap<FnTimeShadow<*>, Read>` granted only to the TRACER domain.

This is the only structural exception to "drivers may not write
cross-domain memory" — flagged in `security-model/` §4.

Overhead targets (validate in `verification/`):

| Config                                          | Target per call |
| ----------------------------------------------- | --------------: |
| `FnTime` with 0 HW counters                     | ≤ 200 cycles    |
| `FnTime` with 4 HW counters                     | ≤ 600 cycles    |
| `FnTime` streaming raw events to a ring         | ≤ 1 000 cycles  |

Cap requirements: `Cap<Probe, Install>` for the target site, plus
`Cap<Pmu, Read>` if any `counters` are requested. Reading the
aggregate back requires `Cap<Probe, Read>` derived from install.

### 3.3 Flight-recorder rings (snapshot-on-trigger)

High-rate overwrite-oldest rings for events that are usually
uninteresting but essential at the moment something breaks. Examples:
every allocation, every lock acquire, every scheduler wake, every IPC
message.

```rust
pub struct Recorder<E: Event>;
pub fn open_recorder<E: Event>(
    n_slots: usize,
    domain: DomainId,
    per_cpu: bool,
    cap: &Cap<Recorder, Create>,
) -> Recorder<E>;

pub fn record<E: Event>(r: &Recorder<E>, ev: E);   // hot path; target ≤ 20 cycles
```

Hot-path invariants:

- Non-blocking, lock-free, signal-safe. Slot claim is one `fetch_add`;
  payload write; release store of a per-slot `seq`.
- No allocation. Event types are `Copy` POD.
- Overrun silently overwrites the oldest slot. A per-ring
  `overwrites` counter is incremented so consumers know how much
  history is missing.

Snapshot:

```rust
pub enum SnapshotSink {
    TraceRing(Cap<TraceRing<D>, Send>),           // stream out via §3.4
    CoreDumpSection(CoreSectionId),                // attach to a crash dump (observability/)
    Buffer { capacity: usize },                    // one-shot copy
}

pub struct SnapshotTriggerSpec {
    pub rings: &'static [RecorderRef],
    pub sink:  SnapshotSink,
    pub mode:  SnapshotMode,                       // EntireRing | LastN(usize)
}
```

Trigger paths:

- A probe's `ProbeAction::Snapshot(spec)` fires the trigger.
- `frame/`'s panic path calls into tracing to snapshot registered
  "panic-snapshot" rings into the core-dump section.
- A userspace tracer can manually trigger via a capability invocation.

Freeze protocol:

1. Atomic swap of the ring's cursor with a "frozen" sentinel, *or*
   double-buffer so producers continue on the spare side.
2. Copy slots into the sink.
3. Unfreeze (restore cursor or swap buffers back).

Double-buffering preferred for small / numerous rings (producers
never block). Freeze-copy-thaw fallback for larger rings.

Canonical use cases baked into the spec:

- **Alloc recorder.** Allocator emits `usdt!(mem, alloc, …)` and
  `usdt!(mem, free, …)` on every call; a recorder is bound to those
  markers. The OOM path triggers a snapshot into the core dump.
  Result: crash image includes the last N allocations.
- **Scheduler recorder.** Context switches, wakes, donations. Panic
  assertion snapshots to console + core dump.
- **IPC recorder.** Per-ring send/recv indices + caller IDs.
  Corruption detector snapshots both endpoints' recorders.

Budget targets (validate in `verification/`):

| Operation                     | Target       |
| ----------------------------- | -----------: |
| `record(...)` unarmed         | ≤ 5 cycles   |
| `record(...)` armed           | ≤ 20 cycles  |
| Snapshot 64 KiB ring          | ≤ 50 µs      |
| Snapshot 4× 64 KiB rings      | ≤ 250 µs     |

### 3.4 Trace transport — the in-domain tracer

Streaming events land in **per-producer-domain Narf-Rings**. A dedicated
**tracer task** lives in a reserved domain (`DomainId::TRACER`,
reserved by `memory/`) and consumes from every ring it holds a
`Cap<TraceRing<D>, Recv>` for.

- A producer domain emits streaming events only into its own ring.
- The tracer can never see domain `D`'s events without an explicit
  cap grant — a compromised tracer cannot escalate.
- The tracer may forward events to a userspace consumer (via another
  Narf-Ring), persist them, or compute aggregates.

The streaming trace transport is the SPMC/SPSC counterpart to §3.3's
flight-recorder rings. Both exist on purpose: streaming is
"everything, live"; flight recorder is "only the last N, on demand."

### 3.5 Event aggregates (live sketches)

NARF maintains live statistical sketches on hot data rather than
exporting raw streams and computing later:

- **Welford's online algorithm** — mean + variance numerically stable
  under high sample count.
- **tDigest** — percentile sketch with bounded memory; supports p50,
  p95, p99, p99.9 with controllable error. Chosen over HdrHistogram
  for unknown-range metrics (latency in ns from ~10 to ~10^9 in the
  same sketch) at some memory cost.

Aggregates live either in the producer (cheap, domain-local) or in
the tracer (centralised cross-domain view). `FnProfileSnapshot` in
§3.2.1 is a canonical example.

## 4. Invariants & safety properties

- Markers (§3.1) and probes (§3.2) never allocate, take a lock held
  outside their own handler, or panic.
- A probe on a TCB function requires a TCB-scoped install cap. Non-TCB
  cap holders cannot probe the Frame.
- Flight-recorder `record` is signal-safe and bounded-cycles. If the
  probe action cost cannot meet the budget, it is rejected at install.
- Patching live code (arming a marker, installing a probe) is
  serialised per-CPU using the HAL's `patch_instruction` primitive
  (x86_64: `text_poke_bp`-style with `int3` synchronisation; aarch64:
  I-cache flush + `DSB ISH; ISB` + IPI).
- Arming/disarming is atomic from a target-executing CPU's perspective:
  either the pre-arm `nop` executes or the post-arm handler; never
  torn.
- Every tracing capability is revocable per `capabilities/`.

## 5. Architecture notes

### x86_64

- Marker patch site: single-byte `nop` at arm time, replaced with a
  5-byte `jmp` / `call` (optimised kprobe style) or an `int3` +
  synchronisation sequence per Intel SDM Vol. 3 §8.1.3.
- HW trace (optional): Intel Processor Trace (PT) for full-fidelity
  control-flow trace; LBR for last-branch records.
- Cycle counter: TSC; instruction-retired: PMU fixed counter 0.

### aarch64

- Marker patch site: `nop` (`D503201F`) replaced by a `BL` (branch
  with link) to the handler; for out-of-range destinations a
  veneer/trampoline is allocated in the domain's code area.
- HW trace (optional): CoreSight ETM / PTM where the SoC provides it;
  highly implementation-dependent.
- Cycle counter: `PMCCNTR_EL0`; instruction-retired: PMU event 0x08.

## 6. Dependencies

- **Consumes:** `ipc/` (Narf-Ring transport), `capabilities/`
  (authorisation), `memory/` (ring + recorder storage, reserved tracer
  domain), `arch/` (patch primitives, HW trace gating, cycle/instr
  counters), `scheduler/` (tracer task), `frame/` (panic hook for
  recorder snapshot into core dump), `rcu/` (Epoch reclamation of
  probe-site metadata on arm/disarm).
- **Provides to:** `observability/` (core-dump enrichment via
  flight-recorder snapshots), `verification/` (raw trace streams and
  live aggregates feeding the statistical protocol), every subsystem
  (USDT markers + flight-recorder `record(...)` calls).

## 7. Stage assignment

| Stage | Lands                                                                    |
| ----- | ------------------------------------------------------------------------ |
| 1     | USDT marker infrastructure (compile-time); basic flight-recorder ring; record-to-console on panic. |
| 2     | Tracer task in reserved domain; streaming Narf-Ring transport; capability-gated recorder creation; snapshot into core dump. |
| 3     | Dynamic probes (entry/return/at); `FnTime`; Welford/tDigest aggregates; per-probe `FnProfileSnapshot`. |
| 4     | HW trace integration (Intel PT / CoreSight ETM); richer probe actions (causal delay, aggregation); userspace tracer tooling. |

## 8. Open questions

- **Aggregate sketch choice.** tDigest vs. HdrHistogram vs. KLL —
  measure memory and error on typical NARF latency shapes before locking.
- **Per-CPU vs per-domain for streaming rings.** Per-CPU is fastest;
  per-domain composes with caps. §3.4 defaults per-domain; revisit
  under measurement.
- **Snapshot atomicity at scale.** Snapshotting 16 recorder rings of
  64 KiB each under a panic path — is 1 ms acceptable, or do we need
  a pre-reserved double buffer everywhere?
- **USDT arg spec format.** Mimic DTrace's register-spec string (tool
  compatibility) vs. NARF-native typed format (cleaner).
- **Shiva-style PLT-hook arming for userspace targets.** For Stage 4
  user-space tracing, arming a USDT in a process = resolving its PLT
  slot and redirecting; doubles as the capability-check stub in `abi/`.
- **HW trace exposure.** Intel PT / CoreSight ETM behind a dedicated
  `Cap<HwTrace, _>` — not folded into the generic Probe cap.
- **BPF-free declarative aggregation.** A probe action that histograms
  an argument value without streaming would be very cheap and very
  useful; define a safe subset that isn't a slippery slope to a VM.
- **Relationship with `process/` §6 audit trail.** Can the tracer
  record AI-agent actions as a first-class event stream for the audit
  log, or is that kept separate for tamper-evidence?
