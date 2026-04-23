# time — Design Notes

## Iteration 2026-04-22

---

## Load-bearing decisions

**Monotonic clock is the only trusted timekeeping surface.** Wall time is "advisory only; never used for scheduling, timeouts, or security decisions" (§3.1). This is the correct and defensible position. The Google leap-smear research shows that even the best-maintained wall clocks have step discontinuities (leap seconds, NTP corrections) that would corrupt deadline calculations if used directly. `Instant` as a 64-bit nanosecond counter since boot avoids wrap-around for 584 years and requires no abstraction. The load-bearing implication: any subsystem that sneaks a wall-clock read into a deadline calculation is introducing a latent correctness bug. The invariant "wall-clock jumps never leak into monotonic time" must be mechanically enforced, not just documented.

**TSC-invariant is the x86_64 clocksource; no non-invariant fallback above HPET.** The clocksources-lwn research identifies SMI-induced TSC drift as a real problem on server hardware. The spec mandates invariant TSC (`CPUID.80000007H:EDX[8]`), with HPET fallback. Refusing to boot on non-invariant TSC silicon is the right hard call — NARF is not a compatibility OS. However, QEMU's `-cpu host,-invtsc` flag (noted in the research open questions) specifically disables the invariant-TSC CPUID bit even on invariant hardware, which will cause NARF to fall back to HPET in CI if the QEMU invocation isn't controlled. This is a CI reliability hazard, not just a documentation gap.

**Timer callbacks are wakers, not IRQ-context functions.** The invariant "timer callbacks run inside the caller's domain (arriving as a waker on a Future), never in IRQ context" is architecturally important. It means `time/` delegates all timeout handling to the scheduler's executor, and the interrupt handler merely records the expiry and issues a waker. This eliminates an entire class of IRQ-context-holds-a-lock bugs. The hrtimers-ingo research notes Linux went to great lengths to avoid long callbacks in IRQ context; NARF avoids the problem structurally.

**Per-CPU clocksource skew detection at boot AND periodically.** The SMP sync in §3.4 re-estimates drift every 10 seconds. This is necessary but not sufficient: TSC synchronisation can degrade mid-run on some hypervisors (VM live-migration, vCPU reschedule onto a different physical core with different TSC). The 10-second re-estimation window means a live-migration event could produce up to 10 seconds of incorrect cross-CPU monotonic ordering before correction. This needs a tighter loop on virtualised platforms or an explicit virt-detection path.

---

## Divergences from precedent

**vs. Linux timekeeping (`kernel/time/timekeeping.c`):** Linux maintains a global `timekeeper` struct with a per-tick snapshot, updated by the timer interrupt. NARF's §8 open question — "per-call derivation vs. maintained snapshot" — leans toward snapshot for performance. The clocksources-lwn research confirms Linux's snapshot approach is cheaper (one atomic read per `now()` call vs. full multiplication on each). NARF should commit to the snapshot approach; the open question should be closed. The divergence: Linux's snapshot is updated at tick granularity (1 ms or 4 ms); NARF's `now_monotonic()` target of ≤ 1 µs jitter implies either a finer-granularity snapshot update or falling back to direct counter reads with mul/shift on each call.

**vs. Linux hrtimers:** Linux's hrtimers are based on an RB-tree per CPU, triggered by the next-event hardware mechanism. NARF follows this design (hrtimers-ingo research explicitly endorses it for NARF). The divergence is that NARF's timers run their callbacks as wakers, not function pointers — which means the `sleep_until()` implementation must bridge from "the hrtimer expired" (in IRQ context or softirq) to "wake this Future" (in executor context). This bridge is the timer-to-waker mapping and must be lock-free (IRQ context cannot take a sleepable lock to find the waker). This implementation detail is not in the spec.

**vs. seL4 timeout mechanism:** seL4 has no kernel-level timer subsystem visible to applications; time is exposed through IPC reply timeouts. NARF's richer `sleep_until` / `timer_oneshot` surface is needed for the async executor's deadline-based preemption and the RCU sleepable timeout, but it's a larger trusted surface. The `Cap<Timer, Arm>` gate for `timer_oneshot` is the right constraint (prevents timer spam from unprivileged code) but `sleep` and `sleep_until` are ungated — any task can block the executor with an arbitrarily large sleep, which is fine for cooperative tasks but needs a budget mechanism if unbounded-duration sleeps are a DoS concern.

**vs. Redox OS time:** Redox uses HPET as primary clocksource for stability across its target hardware. NARF prioritises TSC for performance on modern x86_64 and Generic Timer for aarch64. The divergence is justified — NARF explicitly does not target hardware that can't provide an invariant counter. The risk is CI and developer environments (QEMU without `-cpu host`) where invariant TSC may not be available by default.

---

## Proposed spec changes

- §3.4 SMP synchronisation: **Reduce steady-state drift re-estimation from 10 s to 100 ms on virtualised platforms, detectable via CPUID hypervisor leaf.** Why: live-migration on VMs (common in CI) can produce multi-microsecond TSC jumps that the 10-second window misses; the clocksources-lwn research explicitly warns about SMI and vCPU migration as TSC drift sources.

- §3.1 Clocks: **Add `now_monotonic_raw()` returning an unsmeared `Instant` for internal use by `scheduler/`, `rcu/`, and `crypto/` reseed cadence.** Keep `now_monotonic()` as the smeared user-facing surface. Why: the google-leap-smear research recommends maintaining both smeared (user-facing) and TAI (internal) representations. Using a smeared clock for RCU sleepable deadlines introduces a 11.6 ppm frequency error during leap-smear windows — negligible for most cases but measurable in tight deadline enforcement.

- §3.2 Timers: **Specify the IRQ-context-to-waker bridge mechanism: a per-CPU lock-free wake queue** (single-writer from IRQ, multi-reader from executor). Why: the current spec says "timer callbacks run as wakers" without specifying how the IRQ handler delivers the waker to the executor. The implementation detail is non-trivial and must be in the spec because it is a TCB path.

- §8 Open questions: **Close the "per-call vs. snapshot" question: adopt maintained per-CPU `timekeeper` snapshot updated at each clockevent tick.** Why: the per-call approach (direct counter multiply-shift) adds 10-30 cycles per `now_monotonic()` call on every hot path. The snapshot approach costs ≤ 5 cycles (one atomic load + possible per-CPU offset add). With `now_monotonic()` called from every `rcu::report_quiescent()` (once per Future::poll), the difference is measurable.

- §5 Architecture notes (x86_64): **Document the canonical `rdtscp` vs. `rdtsc` + LFENCE ordering choice.** `rdtscp` serialises on the read (no out-of-order completion), `rdtsc + LFENCE` serialises on instruction retirement. The research open question about cost should be resolved by benchmarking on target silicon; the spec should document which is used and why. Why: inconsistent serialisation choices across call sites produce subtly wrong timing at high-frequency TSC reads.

- §4 Invariants: **Add: "Timer wheel and hrtimer coexistence: a `TimerHint::Coarse` timer may not expire more than 1 timer-tick late, i.e. before the next tick fires."** Currently there is no late-expiry bound for coarse timers. Why: if coarse timers are deferred arbitrarily (e.g. until the next hrtimer interrupt), `sleep()` calls with `TimerHint::Coarse` could wake multiple ticks late, which is surprising and breaks timeout semantics for callers who don't care about precision but do care about bounded latency.

---

## Open invariants / cross-subsystem hazards

**time §3.4 (SMP skew) ↔ rcu §3.5 (sleepable_sync deadline):** The sleepable_sync deadline is checked using `time::now_monotonic()`. On an SMP system with cross-CPU skew, a writer on CPU A declaring a deadline and a reader on CPU B checking it may disagree on the current time by up to the drift tolerance. If the tolerance is 1 µs (typical for invariant-TSC silicon) and the deadline is 250 ms, this is negligible. But the spec does not state the skew tolerance explicitly, so integrators cannot reason about it. The time spec should publish the skew budget (e.g. ≤ 2 µs) and rcu should document that its sleepable deadlines are within this budget.

**time §3.2 (timer_oneshot cap) ↔ security-model §4 (capabilities):** `timer_oneshot` requires `Cap<Timer, Arm>`. But `sleep_until` and `sleep` are cap-free. The asymmetry means: a driver domain can call `sleep(Duration::MAX)` indefinitely without any capability, consuming a slot in the hrtimer RB-tree forever. This is a DoS vector against the timer subsystem. Either `sleep_until` should require a cap (expensive, breaks all existing use), or there should be a per-domain limit on simultaneous outstanding hrtimer entries. The security model should address this.

**time §3.5 (wall-clock discipline) ↔ userspace §? (process time):** NTP is handled by a userspace daemon producing a signed adjustment stream. The kernel applies the stream to wall-clock offset. But "signed" is not defined: signed by whom, with what key, verified how? If the signing key is the daemon's `Cap<WallClock, Adjust>` capability, that's sufficient. But the spec says "signed adjustment stream" without defining the signing mechanism. `crypto/` subsystem would need to define the signature scheme. This cross-subsystem contract is completely unspecified.

**time §3.3 (clocksource rating) ↔ tracing §3.2.1 (FnTime cycle counter):** `FnTime` uses the TSC directly for wall-clock delta. If a clocksource switch happens mid-`FnTime` session (e.g. at boot when HPET gives way to TSC), the delta calculation spans two different frequency domains and produces garbage. The spec needs: either FnTime reads are tied to the current `Clocksource::read()` with its `frequency_hz()`, or FnTime is only valid after clocksource stabilisation.

---

## Additional opinionated commentary

The decision to use `Instant(u64)` as nanoseconds since boot is deceptively simple and correct. But it has an implicit assumption: the kernel's uptime fits in a u64 of nanoseconds, i.e. the system does not run for more than ~584 years. This is fine. What is *not* fine is using `Instant` subtraction for intervals larger than the actual uptime — if `Instant` is serialised to disk (e.g. in a filesystem timestamp or a network packet's monotonic timestamp in a NARF ring), it becomes meaningless on reboot. NARF's IPC should prohibit sending raw `Instant` values cross-process or cross-reboot without explicit documentation that they are boot-relative.

The "wall clock is advisory only" rule is right but creates a user-experience problem: POSIX applications need `clock_gettime(CLOCK_REALTIME)` to work. The `userspace/` relibc integration in Stage 4 must provide wall time via a vDSO-like mechanism, which means the wall clock can't be *too* advisory — it needs to be accurate enough for filesystem timestamps and network protocols. The design needs a clear boundary: "advisory for kernel-internal scheduling; authoritative for userspace time queries."

The leap-smear analysis from the Google research is thorough but introduces one subtlety the spec misses: during the 24-hour smear window, `now_wall() - now_wall()` for two calls one second apart returns approximately 0.99999884 seconds, not 1.0 seconds. Any code that computes a rate (bytes/second, calls/second) using wall-clock difference will be off by 11.6 ppm during the smear. This is almost never detectable, but it means NARF's internal rate limiters should use `now_monotonic()` not `now_wall()`.
