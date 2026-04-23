# time — Specification

> Status: **Outline v0.1** (Stage 1 → 4).

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

## 8. Open questions

- **Coarse wall-time path.** Wall time derived on every call vs. a
  maintained per-CPU `timekeeper` snapshot updated on tick. The
  snapshot approach is cheaper; the per-call approach has no update
  jitter. Decide with benchmarks.
- **Counter frequencies that change under power management.**
  Non-invariant TSC on older x86_64 silicon — refuse those CPUs, or
  fall back to HPET?
- **Per-domain time.** Should each driver domain see its own
  monotonic clock (for deterministic replay) or share the global? Default: global.
- **Time capability granularity.** Is "read monotonic" always allowed,
  or do we gate even that? Leaning: universally allowed (reading time
  leaks nothing).
- **Leap-second policy.** Smear vs. step vs. repeat — smear is the
  only one that preserves monotonic guarantees; ratify this.
