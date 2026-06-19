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
| **TCP Nagle** | ❌ not it | forcing `nagle_enabled=false` default: no change ⇒ redis's `TCP_NODELAY` already wired/honored |
| **TCP delayed-ACK** | ❌ worse | forcing immediate ACK every segment: throughput DROPPED (more ACK segments/VM-exits); piggyback already works |
| **O(N) inbound TCB scan** | ⚠️ real bug, NOT the lever | `handle_segment` linear-scans+locks all TCBs per segment under the global lock. Added a 4-tuple cache (O(log N)): single-PING unchanged, concurrent throughput unchanged. On 1 cooperative vCPU the lock is never contended, so it's pure serial CPU masked by the 90%-idle headroom. Reverted. **Worth fixing for high connection counts (1000s), but not the throughput lever here.** |
| **release build (debug overhead)** | ❌ no throughput change | The kernel had been built DEBUG all along (un-inlined `irq_restore`, `precondition_check`, `is_null::runtime` dominated a tick-RIP profile). A `--release` build did NOT change throughput (GET ~558k vs debug ~524k; SET noise) or latency — re-confirming RTT/feed-bound, not CPU. **BUT building release exposed a real SMAP-soundness bug (`stac/clac` `nomem` let the optimizer hoist the user copy out of the AC window → #PF) — fixed in `c42b0d3f`.** Use `--release` for fair-vs-Linux comparisons regardless. |
| **higher concurrency (-c 200)** | ❌ no scaling | NARF stays ~400–560k from -c 50 to -c 200 (release); Linux scales 790k→830k+. NARF has a structural throughput CEILING = concurrency / per-batch-RTT, and the per-batch RTT INFLATES under load (queueing), so more clients don't help. The ceiling is the wait/feed RTT, not CPU. |

## Root model (settled)

redis perf is **WAKE / FEED / latency-bound on a single vCPU, NOT
compute-bound.** Every real win attacked the wake/feed path. The xtask
built-in workload is single-connection synchronous batches → RTT-bound
(guest 97% halted) → its "throughput" == latency; use the concurrent
harness for true throughput.

**Under-load in-guest decomposition** (clean: per-TCB cycle stamps,
GET-only to avoid SET dict-rehash, dump fired AFTER the load so the print
doesn't distort it). Per-connection in-guest request→response under 50
clients ≈ **560µs**, and the *total* per-batch RTT ≈ 1.65–1.86ms, so
in-guest is ~⅓, external (SLIRP closed loop) ~⅔. The in-guest splits:
- **hop (data-arrived → redis reads it) ≈ 351µs (63%)** — scheduling +
  waiting for redis's current burst + closed-loop wait for the next batch
  (the wake itself is prompt: `readiness::notify()` per data segment).
- **proc (read → response sent) ≈ 206µs (37%)** — redis event-loop batch
  queueing (read N / process N / write N) + send/TX.
Both are queueing intrinsic to single-threaded redis chewing a 50-way
burst on one vCPU — Linux does the same. No single discrete lever; the
residual is diffuse per-request kernel cost amortized over the burst,
intertwined with the SLIRP closed loop. Single-PING floor is already at
parity, so there is no per-request *latency* bug — it's load behavior.

## Plan — remaining gaps (ranked)

The throughput constant factor (~0.6× across pipeline depths; guest ~90%
idle even at 485k ops/s) is NOT compute, NOT frame/notify amplification,
NOT ring depth, NOT Nagle/delayed-ACK, NOT the O(N) TCB scan — ALL ruled
out by measurement above. The single-PING floor is at Linux parity (60 vs
57µs), so the per-request path is fine; the gap is the per-batch wall RTT
UNDER LOAD (~1.65ms vs Linux ~1.0ms = ~27× vs ~17× inflation over the
single-request floor). That inflation is queueing/wait, NOT CPU (90% idle).
Since NARF (485k) is BELOW SLIRP's proven capacity (Linux hits 794k on the
same SLIRP), it's a NARF-side per-batch *latency-under-load* issue — but
wall-time wait, not reducible CPU. In-guest RX→TX measured ~320µs under
load vs ~94µs single (3.4× queueing). Localizing further is blocked: a
single-slot hop/uexec probe gets ~0 paired samples under 50-way
interleaving — it needs per-connection latency instrumentation. **Open
question we can't yet answer here: is the residual NARF's in-guest
per-batch queueing or SLIRP's per-connection serialization?**

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
