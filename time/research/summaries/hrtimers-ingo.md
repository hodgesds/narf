# Ingo Molnar "hrtimers" High-Resolution Timer Design (LWN)

## High-Resolution Timers for NARF Async Scheduler

Ingo Molnar's LWN write-up on hrtimers describes a design for delivering timer interrupts with nanosecond precision. NARF's async executor requires similar infrastructure to schedule tasks at fine granularity.

## Core Mechanism

Rather than a coarse timer wheel (ticking every 4-10 ms), hrtimers use a **red-black tree per CPU**, storing upcoming timer deadlines in sorted order:

1. **Timer Insertion**: When a task sets a timeout (e.g., `sleep_until(deadline)`), insert a timer node into the RB-tree with key = deadline nanoseconds.
2. **Interrupt Generation**: On each timer interrupt, check the RB-tree's minimum deadline. If it has expired, fire the timer callback; set the next hardware interrupt for the next deadline.
3. **Nanosecond Granularity**: The RB-tree approach is O(log N) insert/remove but scales to millions of active timers and supports arbitrary nanosecond precision.

## Application to NARF

**Async Task Wakeups**: When a task calls `sleep_until(deadline)`, create an hrtimer in the scheduler's per-executor tree. When the deadline arrives, wake the task.

**Per-Domain Timer Domains**: Each PKS/MTE domain maintains its own hrtimer tree. A domain's timers never interfere with other domains; domain isolation prevents priority inversion.

**Interrupt Coalescing**: To avoid interrupt storm, batch nearby deadlines: if two timers expire within 1 μs, fire both with a single interrupt.

## Key Invariants

- **Monotonic Deadline Execution**: Timers expire in deadline order; no reordering
- **Precision Guarantee**: Hardware interrupts fire within a few microseconds of the requested deadline
- **Tree Consistency**: RB-tree invariants must hold across timer insertions/removals; no corruption during concurrent access

## Performance Trade-offs

**Latency Improvement**: Nanosecond-precision timers enable fine-grained deadline scheduling, improving responsiveness for real-time workloads.

**Interrupt Frequency**: In high-load scenarios, nanosecond-precision timers generate many more interrupts than coarse wheels. NARF should implement timer coalescing (arm hardware for the nearest deadline, batch others) to avoid interrupt overhead.

**RB-Tree Overhead**: Insert/remove operations are O(log N), compared to O(1) for coarse wheels. For typical workloads (< 1000 active timers), this is negligible (~few μs).

**Per-CPU Trees**: Maintain one tree per executor thread to avoid lock contention on a global timer queue.

## NARF-Specific Guidance

**Adopt**:
- RB-tree hrtimers for async task scheduling
- Per-executor/per-domain timer queues
- Interrupt coalescing to reduce interrupt rate
- Nanosecond precision for deadline accuracy

**Avoid**:
- Global timer locks (causes contention; per-CPU scales better)
- Coarse timer wheels (< 1 ms precision insufficient for async fairness)
- Busy-waiting for timeouts (interrupts are more efficient)

## Pitfalls

- **Timer Cascades**: If many timers expire simultaneously, callback execution can miss subsequent deadlines. Implement callback queueing or deferral.
- **Clock Adjustment Races**: If realtime clock is adjusted mid-operation, hrtimers referencing wall-clock time may become invalid. Use monotonic clocks for all timeouts.
- **Frequency Scaling**: If CPU frequency changes, nanosecond measurements become inaccurate. Re-calibrate TSC multipliers on frequency changes.

## Recommendation

Implement hrtimers in Stage 2. Benchmark overhead of RB-tree insertion against coarse wheels. Use nanosecond-precision timers for async executor scheduling; use coarse timeouts for userspace `sleep()` syscalls (users don't expect microsecond accuracy).

https://lwn.net/Articles/152436/
