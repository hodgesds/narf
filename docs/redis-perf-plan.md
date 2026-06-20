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

1 vCPU (the default redis config):

| metric | session start | **now** | Linux | ratio |
|---|---|---|---|---|
| PING p50 | ~350µs | **60µs** | 57µs | **1.05×** (parity) |
| PING p99 | ~800µs | **~180µs** | 74µs | 2.4× |
| PING min | ~77µs | **41–47µs** | 49µs | beats Linux |
| SET tput (c50 P16) | 0.43× | **0.61×** | 794k | — |
| GET tput (c50 P16) | 0.35× | **0.71×** | 741k | — |
| SET tput (c50 P64) | — | 752k | 1316k | 0.57× |
| GET tput (c50 P64) | — | 841k | 1250k | 0.67× |

2 vCPU (SMP — boot fix + AP-placement bias landed this round):

| metric | SMP `any()` | **SMP +placement** | Linux 2vCPU | ratio |
|---|---|---|---|---|
| PING p50 (20k) | 69µs | **65µs** | 58µs | 1.12× |
| PING p99 (20k) | 254µs | **222µs** | ~72µs | ~3.1× |
| GET tput (c50 P16) | 533k | **537k** | 868k | 0.62× |

SMP throughput is still ~0.62× — placement fixed redis's *core assignment*
(PING p99 254→222µs) but all 50 connections still funnel through ONE virtio
RX queue + ONE BSP forwarder, a serial feed a 2nd vCPU can't parallelize.
That's the remaining lever (multi-queue/RSS, task #125).

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

## The remaining gap is structural: single-vCPU cooperative scheduling

After closing the SLIRP question (above), the residual ~0.6× throughput
factor has one consistent explanation left, and every cheap lever is
falsified:
- guest **90% idle** at 485k ops/s → not CPU-bound
- single-PING p50 at **parity** (60 vs 57µs) → per-request path is fine
- **~15 ops/frame, ~1 notify/frame** → redis batches per-wake as well as
  Linux (per-wake fragmentation falsified)
- iTLB/cache, ring depth, Nagle, delayed-ACK, O(N) TCB scan, release,
  -c200 scaling → all falsified (table below)

What's left is **cooperative single-vCPU scheduling**: NARF runs the virtio
forwarder, the TCP stack, AND redis on ONE core, interleaved by one
cooperative executor. Every per-batch RTT under 50-way load eats executor
scheduling latency that Linux avoids by spreading softirq-RX and the redis
thread across cores. That matches a constant per-batch wait factor on an
otherwise-idle CPU.

**SMP is the lever. Measured 2026-06 (NARF_QEMU_SMP=2, KVM, release, GET
-c50 -P16):**

| metric | NARF 1vCPU | **NARF 2vCPU** | Linux 1vCPU | **Linux 2vCPU** |
|---|---|---|---|---|
| GET rps | ~526k | **543k (+3%)** | ~741k | **868k (+17%)** |
| PING p50 | 60µs | **70µs (worse)** | 57µs | 58µs |
| PING p99 | ~180µs | **234µs (worse)** | 74µs | 79µs |

**Linux scales +17% with the 2nd vCPU; NARF only +3%, and latency gets
WORSE** — the classic signature of cross-CPU contention. redis DOES migrate
(user tasks get `Affinity::any()` when user-task-SMP is on), but then:

1. ✅ **FIXED — AP bringup hung under KVM** (commit: load AP IDT before
   errata). `_ap_start_rust` applied AMD Zen4 erratum 1485
   (`wrmsr_or_gp(DE_CFG[14])`) *before* `load_idtr_ap`. KVM #GPs the DE_CFG
   write; the recoverable-probe fixup needs a live IDT, so with none loaded
   the AP triple-faulted and `-no-reboot` froze the whole VM. Now boots to
   "2 CPU(s) online" + redis serves.
2. ❌ **TCB-lock contention RULED OUT as the SMP scaling blocker.** Built the
   O(1) 4-tuple index (`TCB_BY_TUPLE`, fast-path + O(N) scan fallback for
   correctness) so the BSP forwarder's `handle_segment` no longer holds
   `TCB_TABLE` across a `values().find()` that locks every TCB. redis stayed
   correct (50-conn/500k-op bench passed) but **GET throughput was unchanged**
   (532k vs 543k — noise). Reverted (measure-or-revert; not on the critical
   path). The decisive tell: SMP=2 makes redis latency *WORSE* (p50 60→71µs,
   p99 180→315µs). Pure lock contention would only fail to *improve* latency,
   not worsen it — worse latency = added **migration/TLB-shootdown/cache
   cost**. So the blocker is **migration cost**, not a TCP lock.
3. ✅ **ROOT-CAUSED — it's user-task PLACEMENT, not hysteresis (confirmed by
   experiment).** Tried migration hysteresis (per-task steal cooldown):
   **no throughput change**. Then force-pinned user tasks to AP CPU 1
   (`Affinity::pinned(CpuId(1))`, forwarder stays BSP-pinned) — that DID help:

   | metric | 1vCPU | 2vCPU any() | **2vCPU redis→AP** | Linux 2vCPU |
   |---|---|---|---|---|
   | built-in GET ratio | — | 0.66× | **0.76×** | 1.0 |
   | built-in SET ratio | — | 0.68× | **0.83×** | 1.0 |
   | PING p50 | 60µs | 80µs | **67µs** | 58µs |
   | PING p99 | 180µs | 264µs | **160µs** | 116µs |
   | concurrent GET | 526k | 533k | **555k** | 873k |

   **Why:** under `Affinity::any()` + work-stealing, redis blocks on epoll
   and is woken (by the BSP forwarder) into `READY[bsp]`; the **BSP polls it
   before the idle AP can steal it**, so redis effectively stays on the BSP
   and the AP starves — the forwarder(BSP)↔redis(AP) pipeline never forms.
   Hysteresis can't help because redis never *reaches* the AP. Force-placing
   redis on the AP forms the pipeline → latency recovers.
   **✅ SHIPPED** (`80b95f14`): `TaskSpec::user_task()` now biases a user
   task's *initial placement* (`preferred`) to a round-robin online AP while
   leaving `allowed = ALL` so work-stealing can still rebalance onto the BSP
   under load. First tried a hard "APs only" mask — it exiled every user task
   to the lone AP on a 2-vCPU box and starved co-resident tasks (net-smoke's
   `netserve` never reached `listen`); softening to a `preferred`-only bias
   fixed that while keeping the win. Measured (SMP=2, 20k-PING): redis PING
   p99 254→**222µs**, p50 69→**65µs**, avg 90→**83µs**. Validated: kernel-test
   **5138 pass / 0 fail**, boot-smoke clean, musl-demo **85/85**, net-smoke +
   redis green (all KVM, default 16-CPU and -smp 2).
4. ⏳ **Concurrent-throughput ceiling = single virtio RX queue / single
   forwarder.** Even with redis perfectly placed on the AP, concurrent GET is
   only 0.64× (555k vs 873k). All 50 connections' RX funnels through ONE
   virtio RX queue drained by ONE BSP-pinned forwarder — a serial feed a 2nd
   vCPU can't parallelize. Linux uses multi-queue + RSS + per-core softirq.
   The concurrent-throughput lever is **multi-queue virtio-net (RSS)**: N RX
   queues, a forwarder per queue on distinct CPUs. Substantial networking
   work; the real ceiling-lifter for many-connection throughput.

**Conclusion:** the single-vCPU redis path is thoroughly optimized
(SET 0.43→0.61×, GET 0.35→0.71×, p50 to parity) and the remaining gap is a
well-characterized structural ceiling. Closing it to true parity is an
*architectural* arc (SMP user-task migration that boots under KVM + a
lock-granular TCP stack), not another point optimization — and the payoff
is uncertain until the lock-contention question is answered.

## #126 in-guest stage profile (settled: no NARF in-guest lever)

Direct stage instrumentation (temporary per-TCB TSC stamps, accumulated to
globals, one-shot dumped; reverted after) under `-c50 -P16` GET with the
placement fix live:

| stage | mean | what it is |
|---|---|---|
| HOP (data-arrival → redis `recv`) | **209µs** | request waits while redis services *other* connections |
| PROC (redis `recv` → `send`) | **154µs** | redis read-all/process-all/write-all batch over 50 conns |
| RXcpu (`rx_handler` dispatch) | **4.0µs** | NARF kernel RX per frame |
| TXcpu (`send` submit) | **3.4µs** | NARF kernel TX per write |

NARF's whole kernel RX+TX cost (**~7.4µs**) is *negligible* against the
**~363µs** the request spends inside redis's single-threaded event loop
(HOP+PROC) — and that 363µs is intrinsic redis behavior Linux's redis does
identically. **So there is no NARF in-guest throughput lever.** The ~0.6×
concurrent gap is intrinsic single-threaded-redis-under-load + the external
SLIRP closed-loop turnaround. The only real throughput unblock is escaping
SLIRP (tap, #127) for a faster external loop; for *scaling* it's
multithreaded workloads + MQ/RSS (#125). Also TCP window ruled out as a
lever: NARF uses a fixed 256 KiB rcv buffer, far larger than redis's tiny
pipelined messages need. *Minor cleanup (not a lever, we're idle-bound):
`rx_handler` clones the iface-name `String` per frame and `handle_segment`
still O(N)-scans the TCB table — worth fixing for a future high-PPS NIC.*

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

1. ~~**Tap/bridge backend sanity check.**~~ **DONE — redundant + blocked.**
   Two findings: (a) **Redundant for throughput:** Linux hits 794k SET / 741k
   GET over the *identical* SLIRP+hostfwd+virtio harness while NARF tops out
   ~485k. Since Linux *exceeds* NARF's number on the **same SLIRP backend**,
   SLIRP's throughput capacity is proven ≥794k → **SLIRP is NOT NARF's
   throughput ceiling; the residual is NARF-side.** The tap test could only
   have confirmed this. (b) **Blocked:** NARF networking has only ever run
   over SLIRP's *emulated* L2. Over a real `tap` (offloads on or off), NARF
   boots redis ("Ready to accept connections") but the host never ARP-resolves
   10.0.2.15 — even with `csum/gso/tso=off`. NARF *has* an ARP-reply path
   (`tcp_stack::handle_arp_on`) and `send_gratuitous_arp`, but GARP is **not
   called on bringup** and the reply isn't reaching the host over real tap
   (likely RX-side: the host's broadcast who-has isn't being delivered/parsed,
   or the reply TX isn't valid on a real NIC). Bringing NARF up over a real
   tap/NIC is a **separate networking project**, orthogonal to redis perf.
   Harness scaffolding for it was prototyped (`XTASK_QEMU_TAP`) then reverted.
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
