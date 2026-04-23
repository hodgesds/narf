# Google Leap Smear: UTC Discontinuity Mitigation

## Leap Smear Implementation for NARF Time Subsystem

Google's leap smear strategy offers a practical model for distributed timekeeping in capability-based microkernels. Rather than abrupt clock adjustments, the approach "gradually adjusting time over 24 hours instead of abrupt clock steps" minimizes temporal discontinuities that could violate scheduling invariants.

For NARF's zero-copy IPC and async executor, this matters: sudden time jumps can corrupt causality tracking and deadline calculations across capability domains. The recommended standard employs "a 24-hour linear smear from noon to noon UTC," which keeps "the frequency change small" at roughly 11.6 parts per million—comfortably within oscillator tolerances.

## Invariant Preservation

The linear smear maintains critical time subsystem invariants:

1. **Monotonicity**: Smeared clocks never step backward, protecting event ordering within PKS/MTE domain boundaries
2. **Bounded Drift**: The 11.6 ppm rate stays "well under NTP's 500 ppm maximum slew rate," enabling predictable deadline scheduling
3. **Predictable Offset**: Centering the smear "minimizes the maximum offset" rather than front-loading or back-loading adjustment, reducing worst-case latency penalties

## Performance Trade-offs

**Adopt**: Linear smearing over cosine variants because it's "simpler, easier to calculate, and minimizes the maximum frequency change." For NARF's capability dispatch overhead, computational simplicity at every timer interrupt matters. The 24-hour standard aligns with AWS practice, reducing fragmentation risk if subsystems interoperate across infrastructure.

**Avoid**: Shorter smear windows (like UTC-SLS's 1000-second variant). Steeper frequency adjustments stress real-time guarantees and complicate period calculation for async task scheduling.

## NARF-Specific Pitfalls

1. **Capability Delegation Across Smear Boundaries**: If a capability grants time-limited resource access (e.g., "execute for 1 second of wall time"), ensure dereferencing logic accounts for the slightly-lengthened second during smear. Use unsmeared TAI internally for capability expiry checks.

2. **Zero-Copy IPC Timestamps**: Messages carrying timestamps must tag whether values reflect smeared or unsmeared time. Mismatched assumptions between domains create subtle causality violations.

3. **Async Executor Precision Loss**: If NARF's executor rounds timeout calculations to coarse granules, smear-induced frequency changes may accumulate into noticeable deadline misses. Maintain microsecond precision during the smear window.

## Recommended Adoption Strategy

Use Google Public NTP as the reference clock feed, which already applies the standard smear. Internally, maintain both smeared and TAI representations in timekeeping subsystem state; expose smeared time to userspace but use TAI for hard deadline enforcement. This separation isolates scheduling invariants from external time adjustments while maintaining compatibility with distributed systems.

https://developers.google.com/time/smear
