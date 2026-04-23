# Paul McKenney "Clocksources and Timekeeping" (LWN)

## Kernel Timekeeping Architecture for NARF

Paul McKenney's LWN series on clocksources outlines the Linux kernel's two-phase timekeeping model: **clocksource** (measures elapsed time accurately) and **clockevent** (generates timer interrupts). NARF should follow this split for clean separation between time measurement and timeout scheduling.

## Core Mechanisms

**Clocksource Layer**: Abstracts hardware timer counters (TSC, ARM Generic Timer, HPET) behind a unified interface. A clocksource provides:
- `read()` — returns current counter value
- `mask` — counter width (64-bit, 32-bit, etc.)
- `mult/shift` — scaling factors to convert raw counter to nanoseconds (avoids division)
- `rating` — priority (higher rating = preferred)

For NARF: Implement clocksources for x86 TSC, ARM Generic Timer, and QEMU HPET. Each clocksource must validate hardware assumptions (TSC invariance, frequency stability) before exposing to userspace.

**Clockevent Layer**: Generates interrupts at specified deadlines. A clockevent provides:
- `set_next_event()` — arm interrupt for a specific nanosecond deadline
- `set_state_oneshot/periodic()` — configure interrupt mode
- `rating` — priority

NARF's async executor needs one-shot events (arm interrupt until next task timeout), implemented via clockevents.

## Key Invariants

**Monotonicity**: Time must never go backward. If switching between clocksources, ensure the new source's reading is >= the previous reading (add an offset if necessary).

**Frequency Stability**: Clocksource frequency must remain stable across the operational range. Detect frequency anomalies (SMI, thermal throttling, multicore boot) and either correct or flag as unreliable.

**Precision Adequacy**: The clocksource resolution must be sufficient for the kernel's timeout granule (typically 1 ns for NARF; hardware provides 1-10 ns).

## Performance Trade-offs

**Vsyscall Path**: Linux uses vsyscall (fast userspace timekeeping) when clocksource is validated safe. NARF should provide `clock_gettime()` via vsyscall for applications requiring <1 μs latency.

**TSC Validation**: Validating TSC invariance (multi-core, multi-socket, QEMU) adds boot-time overhead (~1 ms) but pays for itself in latency savings. Validate on every boot; fall back to HPET if TSC is unstable.

**Interrupt Latency**: Clockevent precision affects scheduler responsiveness. Arm next event with at least a few microseconds of slack to avoid missed deadlines due to interrupt processing jitter.

## NARF-Specific Guidance

**Adopt**:
- Per-architecture clocksources (TSC for x86, Generic Timer for ARM)
- Clockevent-based deadline interrupt generation
- Vsyscall for fast userspace time queries
- Monotonicity tracking (detect backward jumps, add offset correction)

**Avoid**:
- Exposing raw TSC to userspace without validation (applications cannot handle frequency changes)
- Mixing clocksource frequencies (if TSC drifts relative to HPET, choose one as authoritative)
- Deadline scheduling via continuous polling; use clockevent interrupts

## Pitfalls

- **SMI Induced TSC Drift**: System Management Mode can steal cycles, causing TSC to skip ahead unpredictably. Detect via NMI-based validation; fall back to HPET if SMI suspected.
- **Realtime Clock Discontinuity**: When admin adjusts wall-clock time, scheduler deadlines (measured from monotonic clock) must not be affected. Maintain separate CLOCK_MONOTONIC and CLOCK_REALTIME abstractions.
- **Userspace ABI Breakage**: If vstyscall time value becomes invalid post-boot, already-running applications suffer corruption. Once enabled, vstyscall cannot be disabled without kernel restart.

## Recommendation

Stage 1: Implement clocksources for both architectures, validate TSC, provide kernel-space time API. Stage 2: Add vsyscall for userspace. Stage 3: Implement clockevent interrupts; measure deadline accuracy across async executor task switches.

https://lwn.net/Articles/388188/
