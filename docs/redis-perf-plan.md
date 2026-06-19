# NARF redis off-box performance — plan & tracking

Living doc for the redis-server-under-QEMU/KVM perf work. **Read the "Dead
ends" section before proposing compute/TLB optimizations — they are
falsified.**

Harness: `redis-server` 7.2.5 (same binary) under QEMU, 1 vCPU, `-cpu max`,
`accel=kvm`, virtio-net + SLIRP hostfwd. NARF vs stock Linux, identical QEMU.

## How to measure

| what | command knobs |
|---|---|
| latency (single-conn PING) | `cargo run -p xtask -- redis-bench --arch=x86_64` (`XTASK_REDIS_BENCH_OPS=0 XTASK_REDIS_BENCH_LAT=20000`) |
| **real throughput** (concurrent) | add `XTASK_REDIS_BENCHMARK=1` → host `redis-benchmark -c 50 -P 16` vs both guests. `XTASK_REDIS_BENCHMARK_{C,P,N}` tune clients/pipeline/count |
| PMU | `XTASK_PERF_DUMP=1` (prints instr/cyc/llc/br). **One-shot only** — periodic serial dumps inflate measured latency ~2.4×. Intel *architectural* events work under KVM; iTLB/dTLB are NOT architectural (unavailable). |
| always | `XTASK_QEMU_ACCEL=kvm`, `XTASK_REDIS_TEE_SERIAL=1` to mirror guest serial |

Caveat: KVM host contention swings absolute numbers ±~30% run-to-run.
Compare in-guest-vs-total **within one run**.

## Scoreboard (vs Linux, KVM)

| metric | session start | **now** | Linux | ratio |
|---|---|---|---|---|
| PING p50 | ~350µs | **60µs** | 57µs | **1.05×** (parity) |
| PING p99 | ~800µs | **~180µs** | 74µs | 2.4× |
| PING min | ~77µs | **41–47µs** | 49µs | beats Linux |
| SET tput (c50 P16) | 0.43× | **0.61×** | 794k | — |
| GET tput (c50 P16) | 0.35× | **0.71×** | 741k | — |
| SET tput (c50 P64) | — | 752k | 1316k | 0.57× |
| GET tput (c50 P64) | — | 841k | 1250k | 0.67× |

Throughput scales with pipeline depth (SET: P1 ~53k → P16 485k → P64 752k)
but the **ratio to Linux is ~constant ~0.6× across depths** → a per-request
feed/network constant factor, not a serialization/scaling failure.

## Improved (landed on `main`)

| commit | change | measured win |
|---|---|---|
| `4bde4bd0` | virtio-net TX fire-and-forget | tail/avg latency ~6× collapse |
| `f11a0b27` | adaptive halt-poll in executor idle path | PING p50 5.3×→3.7× |
| `56827af8` | fb-status skip-when-unchanged (was ~727µs blocking paint/0.2s) | p99 ~720→~480µs |
| `7039f8f8` | xtask concurrent redis-benchmark harness | (tooling) |
| `16dab5f6` | **virtio-net NAPI sustained-poll** (poll ring under load vs park on coalescing IRQ) | **p50→parity, tput +50–100%** |
| `8ffc161d` | SYSRET: `cli` before user-RSP restore | fixed #DF under high IRQ rate (kernel bug NAPI exposed) |

## Dead ends — TESTED, did NOT help; do NOT redo

| hypothesis | result | proof |
|---|---|---|
| **iTLB / redis code huge-pages** | ❌ not the lever | concurrent-load PMU: IPC **2.27**, LLC **1.07 MPKI**, branch **0.91 MPKI**, ~776 cyc/op, guest **~90% idle** at 485k ops/s (CPU could do ~4.9M ops/s). High IPC + low misses + idle ⇒ not TLB/cache/front-end bound. iTLB also not measurable under KVM (non-architectural). |
| **heap huge-pages (dTLB)** | ❌ falsified | KEYS=1 vs 4096 knob: NARF/Linux ratio flat. See [[narf-ping-overhead-inventory]] |
| **per-op path length / per-syscall cost** | ❌ not the tput lever | guest ~90% idle under load — cheaper per-op work can't raise tput when CPU is mostly idle |
| **virtio RX ring depth** (32→128) | ❌ no change | bumped cap in `net_pci.rs size_q`; SET 485→483k. Reverted. |
| **scheduler "run woken task next" (run_next)** | ❌ no-op + 16× regression | redis already at queue front; front-of-queue fragmented pipelining. See inventory |
| **stackless forwarder** | ❌ no-op | removing stackful park machinery didn't move p50 |
| **shorter forwarder fast-deadline (50µs)** | ❌ worse | wake-churn raised min+avg latency |
| **event-driven one-shot timer (for p99)** | ❌ not the cause | RX IRQ is NOT missed; deadline-wakes are benign inter-ping-gap re-polls |
| **RX→redis frame/notify amplification** (plan #1) | ❌ ruled out | counters under load: **~15 ops per frame** (frames/op ≈ 0.067), ~1 TX notify per frame. NARF coalesces pipelined requests as well as Linux. Not the per-request factor. |
| **pipeline-depth scaling** | ❌ no extra win | SET P1 53k→P16 485k→P64 752k scales fine, but Linux ratio stays ~constant ~0.6× across depths ⇒ a per-request constant factor, not a serialization/scaling failure |

## Root model (settled)

redis perf is **WAKE / FEED / latency-bound on a single vCPU, NOT
compute-bound.** Every real win attacked the wake/feed path. The xtask
built-in workload is single-connection synchronous batches → RTT-bound
(guest 97% halted) → its "throughput" == latency; use the concurrent
harness for true throughput.

## Plan — remaining gaps (ranked)

The throughput constant factor (~0.6× across pipeline depths; guest ~90%
idle even at 485k ops/s) is NOT compute, NOT frame/notify amplification,
NOT ring depth (all ruled out by measurement above). It's in the fine
SLIRP↔virtio round-trip TIMING under load — NARF's per-batch wall RTT is
~1.6× Linux's despite batching the same. This is the hardest class and may
be partly external (SLIRP's response to NARF's ring/notify cadence).

1. **Tap/bridge backend sanity check (DO THIS FIRST — diagnostic).** Run the
   same concurrent bench over a non-SLIRP backend. If the gap shrinks, the
   residual is the SLIRP harness, not NARF (stop). If it persists, it's
   NARF's virtio RX/TX timing and worth pursuing. Without this we're guessing
   whether there's anything left to fix in NARF at all.
2. **PING p99 (2.4×, ~180 vs 74µs).** p50 is parity; the tail is residual
   SLIRP/KVM delivery jitter + occasional in-guest variance. Smaller win.
   The one concrete in-guest contributor (fb-status paint) is already fixed.
3. **virtio EVENT_IDX / notification suppression.** ~2% at most — notifies
   are already per-frame (~0.067/op), not per-request. Low priority.
4. **RX→redis hop wall-time decomposition under load.** If #1 shows the gap
   is in-guest, decompose the per-batch in-guest path (RX-dispatch → redis
   read → process → TX) with one-shot timestamps under concurrent load, as
   was done for single-PING latency. Only worthwhile if #1 says it's in NARF.

### Measurement discipline (lessons)
- Measure throughput CONCURRENT (`-c 50`), never single-connection — the
  built-in bench is RTT-bound and under-measures CPU/feed throughput.
- One-shot PMU dumps only; periodic serial prints inflate the measured
  latency ~2.4×.
- A perf change can EXPOSE a latent correctness bug (NAPI's higher IRQ rate
  surfaced the SYSRET #DF). Re-audit user/kernel transition windows when
  raising IRQ/syscall rates. Stress-test new perf changes at high N.

Cross-ref agent memory: `narf-redis-ping-wake-bound-haltpoll`,
`narf-sysret-irq-user-stack-df`, `narf-ping-overhead-inventory`.
