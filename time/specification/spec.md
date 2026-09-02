# time — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> wall-clock + monotonic surfaces; v1.0 locks the per-CPU
> timekeeper snapshot, the non-invariant-TSC policy, per-domain
> time semantics, leap-smear, and ABI versioning.

## 1. Purpose & scope

**Owns:**

- **Monotonic clock** — never-decreasing, unaffected by wall-clock
  adjustments, single source of truth for deadlines and benchmarks.
- **Wall clock** — human calendar time, derived from firmware RTC at
  boot and optionally disciplined by NTP/PTP post-Stage-4.
- **Clocksource** — the trait abstracting a raw counting source (TSC,
  `CNTPCT_EL0`, HPET).
- **Clockevent** — the trait abstracting a programmable next-tick
  source (TSC-deadline, LAPIC-timer, Generic Timer compare).
- **High-resolution timers (hrtimers)** — one-shot timers expressed in
  absolute monotonic nanoseconds; the primitive scheduler deadlines
  and `async` `sleep_until` build on.
- **Timer wheel** — coarse timeout bookkeeping for bulk short timers
  where hrtimer precision isn't worth the priority-queue cost.
- **SMP synchronisation** — per-CPU TSC/`CNTPCT` skew detection and
  correction at boot; steady-state offset tracking.

**Does NOT own:**

- Scheduling policy (uses deadlines from here; `scheduler/`).
- Tracing timestamp embedding (uses monotonic ns from here;
  `tracing/`).
- RTC driver (a chip driver under `drivers/`, consumed here).

## 2. Assumptions

- `arch/` exposes counter reads (`rdtsc` / `rdtscp` on x86_64;
  `CNTPCT_EL0` on aarch64), frequency calibration, and an "arm next
  interrupt" primitive.
- `interrupts/` can route a per-CPU timer IRQ into this subsystem.
- `boot/` hands us the firmware wall-clock seed (via ACPI/RTC or
  devicetree) and the calibrated counter frequency where available.

## 3. Public interface

### 3.1 Clocks

```rust
pub struct Instant(u64);                  // monotonic ns since boot
pub struct WallTime { sec: i64, nsec: u32 } // calendar

pub fn now_monotonic() -> Instant;        // smeared (user-facing surface)
pub fn now_monotonic_raw() -> Instant;    // unsmeared TAI; internal only
pub fn now_wall() -> WallTime;
pub fn monotonic_resolution() -> u64;     // ns per tick of the underlying counter
```

**Smeared vs. raw monotonic.** `now_monotonic()` is the user-facing
clock and is subject to leap-smear during a smear window (see §3.5).
`now_monotonic_raw()` is the unsmeared TAI counter and is reserved
for callers that need tighter than 11.6 ppm frequency stability:
`scheduler/` deadline enforcement, `rcu/` sleepable timeouts,
`crypto/` reseed cadence. Userland never sees `_raw`.

- **`Instant` is the canonical type for durations.** Subtraction
  yields `Duration` (ns). No wrap-around concerns inside NARF's
  lifetime (64-bit ns = ~584 years).
- **Wall clock is advisory only.** Never used for scheduling,
  timeouts, or security decisions.

### 3.2 Timers

```rust
pub struct Deadline(Instant);
pub fn sleep_until(d: Deadline) -> impl Future<Output=()>;
pub fn sleep(dur: Duration)      -> impl Future<Output=()>;

pub struct Timer;
pub fn timer_oneshot(d: Deadline, cb: TimerCb, cap: &Cap<Timer, Arm>) -> Timer;
pub fn timer_cancel(t: Timer);

/// Returns the soonest pending deadline on this CPU, or `None` if
/// no timer is armed. **O(1) with bounded worst-case latency**: the
/// implementation maintains a per-CPU "next deadline" cache updated
/// on every `timer_oneshot` / `timer_cancel`, so the read is one
/// pointer chase. Required by `power/` §3.1 to choose a C-state
/// without exceeding the C-state's entry latency budget.
pub fn next_deadline() -> Option<Instant>;
```

- hrtimer-grade precision (≤ 1 µs jitter target on a quiet CPU).
- Timer wheel for bulk coarse-grained waits when the caller passes a
  `TimerHint::Coarse` flag — amortises priority-queue cost.

### 3.3 Clocksource / Clockevent abstractions (for arch backends)

```rust
pub trait Clocksource {
    fn read(&self) -> u64;
    fn frequency_hz(&self) -> u64;
    fn is_monotonic(&self) -> bool;
    fn rating(&self) -> u32;   // higher = preferred
}

pub trait Clockevent {
    fn set_oneshot_ns(&self, ns: u64);
    fn min_delta_ns(&self) -> u64;
    fn max_delta_ns(&self) -> u64;
}
```

Boot-time selection: walk available clocksources, pick the highest
rating that's also monotonic. Record the decision for telemetry.

### 3.4 SMP synchronisation

- At boot, per-CPU counters are read in a coordinated protocol to
  estimate skew. Per-CPU offsets are stored in `CpuLocal` and applied
  on every `now_monotonic()` call if skew exceeds a documented
  threshold.
- Steady-state drift is re-estimated periodically. **Default cadence
  is platform-dependent: 10 s on bare-metal, 100 ms when the CPUID
  hypervisor leaf indicates a virtualised environment.** Live-migration
  on VMs (common in CI) can produce multi-microsecond TSC jumps that
  the 10-second window misses; the 100 ms cadence catches these
  before they corrupt enough downstream measurements to be obvious.
  Drift exceeding threshold raises a `tracing/` event.
- Invariant: `now_monotonic()` called from CPU A at wall time T is
  never earlier than `now_monotonic()` called from CPU B at wall
  time T' < T (i.e. cross-CPU monotonicity holds within the drift
  tolerance).

### 3.5 Wall-clock discipline (Stage 4)

- **NTP client** — optional userspace daemon producing a signed
  adjustment stream that the kernel applies to the wall-clock offset.
  Kernel never sources NTP directly.
- **PTP (IEEE 1588)** — driver-level hook under `drivers/net/` for
  timestamps; discipline handled by the same userspace path.
- Wall-clock slewing is rate-limited; leap-seconds handled via smear
  (no monotonic violation ever).

## 4. Invariants & safety properties

- `now_monotonic()` is wait-free and lock-free.
- `Instant` is strictly monotonic per CPU and non-decreasing across
  CPUs to within declared skew.
- `sleep_until(d)` wakes the Future at time ≥ `d`; never earlier.
  Latency budget documented per stage.
- Timer callbacks run inside the caller's domain (arriving as a waker
  on a Future), never in IRQ context.
- Wall-clock jumps (NTP step) never leak into monotonic time.
- Frequency changes from `arch/` (CPU DVFS) are invisible through
  this interface — the clocksource frequency is either invariant
  (TSC-invariant on modern x86_64, Generic Timer on aarch64) or
  calibrated in a way that makes it invariant.

## 5. Architecture notes

### x86_64
- **Clocksource:** invariant TSC (`CPUID.80000007H:EDX[8]`) + `rdtscp`
  for ordering. Fallback: HPET, then PM timer.
- **Clockevent:** TSC-deadline (`CPUID.01H:ECX[24]`); fallback to
  LAPIC timer in one-shot mode.
- A successfully probed, reliable TSC-deadline clockevent exclusively owns
  timer-wheel deadline delivery. HPET is not armed for the same deadline;
  it remains the fallback when LAPIC selection fails or only the unreliable
  legacy InitialCount mode is available.
- **Boot calibration:** TSC ↔ PM timer or HPET cross-check to get
  frequency; CPUID leaf `0x15` on supported silicon.
- **SMP sync:** TSC is architecturally synchronised across cores on
  invariant-TSC silicon; still verify at boot to catch BIOS bugs.

### aarch64
- **Clocksource:** Arm Generic Timer (`CNTPCT_EL0`), frequency from
  `CNTFRQ_EL0`.
- **Clockevent:** physical timer compare register
  (`CNTP_CVAL_EL0` + `CNTP_CTL_EL0`), per-CPU IRQ.
- **SMP sync:** Generic Timer is architecturally coherent across
  PE's in the same domain; no cross-CPU offset needed in practice.

## 6. Dependencies

- **Consumes:** `arch/` (counter + timer primitives), `boot/` (initial
  RTC read, calibration data), `interrupts/` (timer IRQ), `memory/`
  (per-CPU state + timer-wheel storage), `capabilities/` (Arm cap
  for `timer_oneshot`), `rcu/` (QSBR on the current-clocksource
  pointer so readers on the hot path don't lock).
- **Provides to:** `scheduler/` (deadlines, preemption tick), `tracing/`
  (timestamps), `crypto/` (reseed cadence, nonce epoch), `ipc/`
  (doorbell timeouts), `verification/` (benchmark timing), every
  subsystem that needs "sleep for N µs."

## 7. Stage assignment

| Stage | Lands                                                           |
| ----- | --------------------------------------------------------------- |
| 1     | Monotonic clock from TSC / `CNTPCT_EL0`; `sleep` / `sleep_until` ; timer wheel. |
| 2     | hrtimers, SMP skew detection + correction, timer-wheel + hrtimer coexistence. |
| 3     | Per-task cap-gated timers, integration with `crypto/` reseed.    |
| 4     | NTP/PTP userspace hooks, leap-second smear, wall-clock signing for audit trail. |

## 8. Resolved decisions

### 8.1 Per-CPU timekeeper snapshot (resolved)

**Decision:** **per-CPU snapshot updated on each timer tick**,
not per-call wall-clock derivation. Snapshot fields are
{`tsc_at_tick`, `wall_at_tick`, `tsc_freq_hz`}. `wall_clock()`
reads the snapshot, computes elapsed TSC since last tick,
multiplies by frequency. Total cost: ~30 cycles + a single
`RDTSC`.

The per-call derivation alternative was rejected because the
`RDTSC` overhead is identical but the conversion path adds
~50 more cycles for floating-point or fixed-point scaling
that snapshot pre-computes once per tick.

The snapshot ages by at most one tick (~1 ms); applications
needing sub-millisecond wall-clock precision should poll
`monotonic_ns()` and convert offline against the
boot-time-anchored wall-clock base (exposed as
`wall_clock_anchor()`).

### 8.2 Non-invariant TSC fallback (resolved)

**Decision:** **refuse to boot** on x86_64 silicon without
invariant TSC. The kernel panics at the timer-init stage with
a clear message ("CPU lacks invariant TSC; minimum required
since Nehalem; replace hardware").

HPET fallback was rejected because:
- HPET is being deprecated by Intel.
- HPET reads cost ~500 cycles each — 10× the invariant-TSC
  path; entire scheduler hot path slows down.
- aarch64's Generic Timer is always invariant; the asymmetry
  would mean two scheduler hot paths.

Pre-Nehalem x86_64 silicon (>15 years old) is the only
hardware excluded; this is acceptable.

### 8.3 Per-domain time (resolved)

**Decision:** **shared global monotonic clock**. Per-domain
monotonic clocks would help deterministic replay but at the
cost of every cross-domain message carrying a clock
translation. The complexity isn't worth it for v1.0.

Replay-debugging future work: a `Cap<TimeReplay, _>` that
gives a per-task virtualised clock for record-replay sessions.
Out of scope for v1.0.

### 8.4 Read-time capability (resolved)

**Decision:** **`monotonic_ns()` and `wall_clock()` are
universally callable**, no cap required. Reading time leaks
nothing (timing channels exist regardless; access to the
clock just makes them measurable, not exploitable).

Capabilities apply to time *modification* — only
`Cap<Time, Set>` may call `set_wall_clock` (held by the time
daemon, NTP client, or boot-time clock setup).

### 8.5 Leap-second policy (resolved)

**Decision:** **leap smear over a 24-hour window**. When the
NTP source signals an upcoming leap, the kernel adjusts the
wall-clock-vs-monotonic offset gradually: 1 second is smeared
across the 24 hours bracketing midnight UTC. Monotonic time
is unaffected.

Step adjustments and "repeat the second" alternatives were
rejected because they break monotonicity assumptions in
applications. Smearing matches Google's published policy
(adopted across most cloud platforms) and keeps user-visible
clocks monotonic.

The smear is observable to applications: during the smear
window, wall-clock progresses at 1.0000115 ×
monotonic-rate. This is documented; applications that need
strict UTC during a leap window read the leap-status flag
and explicit-step internally if desired.

## 9. ABI versioning

`time/` exports through SDK at `@v0`:

- `monotonic_ns()`, `monotonic_us()`, `monotonic_ms()`.
- `wall_clock()` returning `WallClock { sec, nsec }`.
- `Instant` / `Duration` types (Rust `core::time` re-exports
  + `Instant` newtype around monotonic_ns).
- Sleep primitives: `sleep_ns(ns).await`,
  `sleep_until(deadline).await`.

`TIME_ABI_MAJOR = 1`, `TIME_ABI_MINOR = 0`. New clock domains
(per-process clocks for cgroup-style accounting) would be
minor bumps.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
