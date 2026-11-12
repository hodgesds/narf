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

`phc::HardwareClock` supplies device read/set, offset/frequency adjustment,
current frequency and maximum adjustment. `phc::register/get/unregister/indices`
manage retained clock references without invoking driver operations under the
registry lock. Removing an index does not redirect an already-open reference
to a subsequently registered clock. Device drivers own register locking,
clock continuity over reset and rejection after removal. PHCs are separate
from the system wall/monotonic clocks; syscall authority is checked by userspace.


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

On x86_64, `calibrate_clocks_with_source()` establishes both directions of
the fixed-point counter conversion, including when it reuses an arch-cached
TSC frequency. Before calibration, `cycles_to_ns` and `ns_to_cycles` use an
identity fallback; hardware minimum delays and timeouts must not treat it as
wall time (a >1 GHz TSC makes such waits too short).

`hpet::calibrate_tsc_at(mapped_base)` is an unsafe x86_64 boot-only
measurement for callers running before timer installation. The caller owns
an uncached HPET mapping exclusively. It enables and samples a 64-bit main
counter without publishing the singleton, changing the physical-base override
or programming comparators. Both this path and singleton calibration bound
counter reads and return unavailable for a stopped counter or invalid ratio.

### 3.2 Timers

```rust
pub struct Deadline(Instant);
pub fn sleep_until(d: Deadline) -> SleepUntil;
pub fn sleep(dur: Duration)      -> SleepUntil;
pub fn sleep_ns(ns: u64)         -> SleepUntil;
pub fn sleep_us(us: u64)         -> SleepUntil;
pub fn sleep_ms(ms: u64)         -> SleepUntil;
pub fn sleep_cycles(cycles: u64) -> SleepUntil; // raw TSC ticks

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

- `sleep*` return the `SleepUntil` future (an hrtimer sleeper, §3.2.1;
  self-wake fallback when no clockevent programmer is installed). Wall-time
  helpers convert
  through the calibrated ns→cycles scale, which is 1 cycle/ns until
  calibration; callers needing hardware-specified delays before frame's
  calibration must call `calibrate_clocks()` first. A literal cycle count
  passed to `sleep_cycles` is a different duration on every CPU.
- hrtimer-grade precision (≤ 1 µs jitter target on a quiet CPU).
- Timer wheel (`timer_list`, §3.2.2) for coarse kernel timeouts that are
  usually cancelled before they fire (`msleep`, park backstops).

### 3.2.1 hrtimers (`narf_time::hrtimer`, Linux `kernel/time/hrtimer.c`)

| Linux | NARF |
| --- | --- |
| `struct hrtimer_cpu_base` (per CPU) | `HrTimerCpuBase`, allocated per CPU at bring-up (`hrtimers_prepare_cpu`); a static array holds only pointers |
| `HRTIMER_MAX_CLOCK_BASES` = MONOTONIC, REALTIME, BOOTTIME, TAI + `_SOFT` | same eight clock bases; REALTIME/TAI expiries convert through the wall (+TAI) offset, BOOTTIME through `offs_boot` (time spent suspended; MONOTONIC excludes it, `timekeeping_suspend`/`timekeeping_resume` around s2idle). Clockevents are programmed on raw counter time (`mono_to_raw_cycles`) |
| `struct timerqueue_head` (rbtree, leftmost cached) | `timerqueue::TimerQueueHead`: intrusive red-black tree, earliest cached; FIFO on equal expiry |
| `struct hrtimer`, `hrtimer_setup` | `HrTimer::new(fn, clock, mode)` — caller-owned storage, intrusive node |
| `hrtimer_start_range_ns`, `_softexpires` / `expires` | `hrtimer_start_range_ns(timer, tim, delta, mode)`; expiry runs at `softexpires`, the clockevent is programmed for `expires` |
| `switch_hrtimer_base` | an unpinned (re)start moves the timer to the calling CPU's base, except while its callback runs |
| `hrtimer_try_to_cancel` / `hrtimer_cancel` | same (1 / 0 / -1; cancel waits out a running callback) |
| `hrtimer_forward`, `hrtimer_get_remaining`, `hrtimer_active` | `HrTimer::forward`, `hrtimer_get_remaining`, `HrTimer::is_active` |
| `hrtimer_interrupt` (hard expiry, re-program) | `hrtimer_interrupt()` from each CPU's own timer interrupt; returns the next event for the arch code to program |
| `HRTIMER_SOFTIRQ` (`_SOFT` bases) | `hrtimer_run_softirq()` from the executor loop (raised by the hard interrupt) |
| `hrtimer_run_queues` (low-res tick) | `hrtimer_run_queues()` from periodic-only clockevents (LAPIC InitialCount) |
| `tick_program_event` | the arch arm callback (`set_arm_callback`): LAPIC TSC-deadline, aarch64 `CNTP_TVAL` |
| `hrtimer_reprogram` / `retrigger_next_event` / `trigger_dyntick_cpu` | local earlier event: program at once; remote earlier event: publish under the remote base lock, then one reschedule IPI whose handler re-programs (`retrigger_next_event`) |
| `tick_handle_periodic_broadcast` (global clockevent) | `hrtimer_run_all_bases()` from HPET / shared clockevent ticks |
| `hrtimer_get_next_event` (nohz) | `next_event_cycles_local()` (lock-free, IRQ-safe) |
| `hrtimers_cpu_dying` | `hrtimers_cpu_dying(cpu)`: moves every queued timer to the calling CPU |
| `struct hrtimer_sleeper`, `hrtimer_wakeup`, `schedule_hrtimeout_range` | `SleepHandle` (`arm`, `start`, `refresh_waker`, drop = cancel); expiry wakes by reference |
| `clock_was_set` | `clock_was_set()` re-evaluates every base; called by every wall-clock step (`clock_settime`, `settimeofday`, `ADJ_SETOFFSET`, an NTP step), not by slews |
| `current->timer_slack_ns`, `PR_SET_TIMERSLACK` | `UserTaskCtx::timer_slack_ns` (`userspace/`), used as the range of every park timer (nanosleep, poll/select/epoll, futex) |

Users today: `SleepUntil` (every kernel `sleep*`), the user-task park timer
behind nanosleep/clock_nanosleep, poll/ppoll/select/pselect/epoll_wait,
futex and rt_sigtimedwait timeouts and the console byte-waker backstop, the
scheduler's hrtick, and in `userspace/`: POSIX timers (`posix_timer_fn`, one
hrtimer per timer on its clock's base), ITIMER_REAL (`it_real_fn`, one per
task) and timerfd (`timerfd_tmrproc`, one per fd). Those three callbacks run
in hard IRQ, take only IRQ-safe locks, raise their signal or readiness
through alloc-free paths, and restart a periodic timer at its next expiry.
ITIMER_VIRTUAL/PROF stay on the tick, as in Linux (`run_posix_cpu_timers`).

Every CPU's local clockevent installs itself as the programmer when it
starts (the x86 TSC-deadline LAPIC; the aarch64 generic timer). An executor
round (`poll_one_round`, the run loop) is the softirq context: it expires the
CPU's due soft timers and any hard timer whose interrupt was not taken (a CPU
that runs with interrupts masked — the kernel-test runner — gets no timer
interrupt). Code that waits for a timer while spinning with interrupts
masked must run such a round; Linux never sleeps with interrupts off.

A sleeper whose waker is a scheduler task waker (`set_hardirq_waker_predicate`)
is queued on a hard base and woken from the timer interrupt with
`wake_by_ref`; any other waker uses the `_SOFT` base and is woken from the
executor.

### 3.2.2 Timer wheel and timer migration (`narf_time::timer`, `narf_time::timer_migration`)

| Linux | NARF |
| --- | --- |
| `struct timer_base` × `BASE_LOCAL` / `BASE_GLOBAL` / `BASE_DEF` per CPU | three `TimerBase`s per CPU, allocated on first use (`timers_prepare_cpu`); pinned → LOCAL, deferrable → DEF, else GLOBAL |
| non-cascading wheel, `LVL_DEPTH` (9 at HZ=1000) × 64 buckets, `calc_wheel_index`, `pending_map` | same geometry and index arithmetic; a timer fires no earlier than its expiry and at most one level granularity later |
| `struct timer_list`, `timer_setup` | `TimerList::new(fn, flags)` — caller-owned, intrusive bucket links |
| `mod_timer` / `add_timer_on` / `timer_delete` / `timer_delete_sync` / `timer_pending` | `mod_timer` / `add_timer_on` / `del_timer` / `del_timer_sync` / `is_pending`; an unpinned re-arm moves to the calling CPU unless the callback runs; `forward_timer_base` before indexing |
| `__run_timers`, `collect_expired_timers`, `__next_timer_interrupt` | same, from `run_timer_softirq` in the executor round (`TIMER_SOFTIRQ`, raised by `timer_tick` from the timer interrupt) |
| `get_next_timer_interrupt` / `tick_nohz_next_event` | `next_timer_event_ns_local()`, folded into the CPU's next clockevent event (`hrtimer::next_event_cycles_local`, `hrtimer_interrupt`, `retrigger_next_event`); DEF timers count only while the CPU is active |
| `trigger_dyntick_cpu` | a new first non-deferrable timer on another CPU's base kicks it (`hrtimer::kick_cpu_next_event`) |
| `timers_dead_cpu` | `timers_dead_cpu(cpu)` from CPU offline |
| `schedule_timeout` / `msleep` | `TimeoutHandle` (`process_timeout` wakes by reference); `narf_time::msleep` |
| tmigr (`tmigr_cpu_deactivate` / `activate`, migrator, `tmigr_handle_remote`, `timer_expire_remote`) | one group (NARF's CPU count fits one): a CPU entering tickless idle sets its idle bit; while any CPU is active an idle CPU's GLOBAL timers are left out of its next event and expired by an active CPU's timer softirq; the last CPU to go idle covers every idle CPU's GLOBAL timers; LOCAL timers always wake their own CPU |

Users: the console byte-waker park backstop and `msleep`. Callbacks run in
executor context with no base lock held; `del_timer_sync` must not be
called from the timer's own callback.

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

`ClockEvent::set_idle_tick(stop_tick, budget_deadline) -> bool` replaces the
current CPU's idle budget deadline and stops or restarts its periodic tick.
Unsupported devices return false and retain periodic operation. Implementations
preserve caller IRQ state and the CPU's own next hrtimer event. `register_local`
publishes a static backend once per CPU; steady transitions read it without a
registry lock. `clockevent::set_idle_tick` also enforces the boot nohz policy;
`restart_local_tick` restores preemption before runnable task dispatch.

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

- **NTP client** — the in-kernel SNTP client (`narf_net::sntp`,
  issue #1764) performs one UDP exchange against an explicit server
  (RFC 5905 §14), validates the reply (§8 offset/delay, bogus check,
  kiss-o'-death), and feeds the sample to the kernel discipline loop
  (§3.6). The kernel therefore *does* source NTP directly for the
  bootstrap sync the desktop and TLS certificate validation need — the
  Stage-4 "optional userspace daemon producing a signed adjustment
  stream" remains the future direction (a daemon can take over via the
  same `adjtimex` surface), but no such daemon exists yet and the
  clock cannot wait for one. Server discovery (DHCP option 42),
  authentication (NTS), and a periodic poll daemon are follow-ups;
  the client names no default server.
- **PTP (IEEE 1588)** — driver-level hook under `drivers/net/` for
  timestamps; discipline handled by the same userspace path.
- Wall-clock slewing is rate-limited; leap-seconds handled via smear
  (no monotonic violation ever).

### 3.6 NTP discipline state (`adjtimex(2)` surface)

```rust
pub mod ntp {
    pub struct Timex { /* the mutable half of struct __kernel_timex */ }

    /// `timekeeping_validate_timex()` — EPERM/EINVAL for a request this
    /// caller may not make or that names impossible values.
    pub fn validate(txc: &Timex, cap_sys_time: bool) -> Result<(), i64>;
    /// `ntp_adjtimex()` — apply the request's modes, fill in every
    /// reported field, return the clock state (TIME_OK / TIME_ERROR).
    pub fn adjtimex(txc: &mut Timex, now_sec: i64, now_nsec: i64) -> i64;
    /// Current TAI offset, seconds (`ADJ_TAI`).
    pub fn tai_offset() -> i32;

    /// Apply one SNTP sample: step the wall clock over the 128 ms
    /// threshold, else feed the phase to the PLL (`ADJ_OFFSET` path with
    /// full FLL/PLL frequency learning). First accepted sample takes over
    /// discipline (sets `STA_PLL`, clears `STA_UNSYNC`).
    pub fn apply_sample(
        offset_ns: i64, delay_ns: i64, root_dispersion_ns: i64, stratum: u8, now_sec: i64,
    ) -> DisciplineOutcome;
    /// Per-second discipline step (`second_overflow()`'s phase half):
    /// bump `time_maxerror`, drain `time_offset` exponentially into the
    /// wall offset. Called once per wall second from `clockevent::on_tick`.
    pub fn tick_second();

    // ADJ_*, STA_*, TIME_* constants (include/uapi/linux/timex.h).
}
```

The kernel's NTP variables (`tick_usec`, `time_status`, `time_freq`,
`time_offset`, the error estimates, the TAI offset) live here, with Linux's
boot defaults — `STA_UNSYNC`, so a query answers `TIME_ERROR` until a time
daemon clears the bit. `userspace/`'s `adjtimex` / `clock_adjtime` handlers
own the user-struct copy, the `CAP_SYS_TIME` gate and the `ADJ_SETOFFSET`
step into the wall offset; everything else is state kept here.

The discipline loop exists now (issue #1764): `ADJ_OFFSET` runs the full
Linux `ntp_update_offset()` (PLL + FLL frequency learning against
`time_reftime`), and `tick_second()` — driven once per wall second from
the clockevent tick — drains `time_offset` exponentially into the wall
offset, which is where phase lands on NARF (there is no timekeeper
multiplier to steer). The slew is therefore applied at 1 Hz granularity:
each second's jump is at most `MAXPHASE >> (SHIFT_PLL + time_constant)`.
What is still missing, see the `narf_time::ntp` module docs: the leap
state machine on this path (that is §3.5's smear), the `ADJ_ADJTIME`
single-shot drain, and PPS.

## 4. Invariants & safety properties

- `now_monotonic()` is wait-free and lock-free.
- `Instant` is strictly monotonic per CPU and non-decreasing across
  CPUs to within declared skew.
- `sleep_until(d)` wakes the Future at time ≥ `d`; never earlier.
  Latency budget documented per stage.
- Timer callbacks run inside the caller's domain (arriving as a waker
  on a Future). Hrtimer expiry callbacks run in hard-IRQ context (hard
  bases) or executor context (`_SOFT`), never with a base lock held; they
  must not allocate, free, block or cancel their own timer. Sleeper expiry
  wakes by reference only, so no `Arc` is released in IRQ context: the
  `Waker` is dropped by the sleeper's owner, in task context.
- Each CPU's timer interrupt expires only its own base and its clockevent
  carries only its own next event: a CPU that is stuck (interrupts masked,
  or never returning to its executor) delays only timers queued on it. No
  global lock or counter is on the enqueue/expire path; nothing on it has a
  capacity limit (intrusive nodes).
- No lost re-arm: an enqueue that becomes a base's earliest event either
  programs the local clockevent before returning, or (remote base) is
  published under that base's lock before an unconditional reschedule IPI
  whose handler re-programs from the base. A CPU entering tickless idle
  reads its next event after disabling interrupts, so it either sees the
  new event or takes the IPI after halting.
- Lock order: one CPU-base lock at a time (migration releases the old base
  before taking the new, with the timer marked migrating in between); a
  sleeper's waker lock is taken with no base lock held.
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
- Every CPU's LAPIC TSC-deadline one-shot carries `min(periodic tick,
  budget deadline, its own next hrtimer event)`. HPET is not armed for the
  same events; it remains the fallback (programmed for the earliest event
  of any base, expiring every base) when LAPIC selection fails or only the
  unreliable legacy InitialCount mode is available.
- **Boot calibration:** TSC ↔ PM timer or HPET cross-check to get
  frequency; CPUID leaf `0x15` on supported silicon.
- **SMP sync:** TSC is architecturally synchronised across cores on
  invariant-TSC silicon; still verify at boot to catch BIOS bugs.

### aarch64
- **Clocksource:** Arm Generic Timer (`CNTPCT_EL0`), frequency from
  `CNTFRQ_EL0`.
- **Clockevent:** physical timer (`CNTP_TVAL_EL0` + `CNTP_CTL_EL0`),
  per-CPU IRQ. Periodic; each tick runs `hrtimer_interrupt` and re-arms for
  `min(period, next hrtimer event)`, and an earlier enqueue pulls it in.
  No tickless idle yet, so remote enqueues need no IPI.
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
