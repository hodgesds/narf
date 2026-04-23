# Embassy Async Executor for NARF Scheduler

## Core Mechanisms

Embassy's async executor provides insights applicable to NARF's scheduler design. The framework uses a "wake-based" polling model rather than continuous task iteration. When a task awaits an I/O operation, it yields execution, allowing the scheduler to select another ready task. As documented, "once a task blocks on I/O the future yields, and the scheduler, called an executor, can select a different future to execute."

This mechanism maps naturally to capability-based systems: each task holds capabilities for resources it can access, and yielding transfers control predictably without busy-waiting.

## Key Invariants for NARF

**Task Non-Blocking Guarantee**: The Embassy documentation emphasizes that "the executor relies on tasks not blocking indefinitely, this would prevent the executor regaining control and scheduling another task." For NARF, this becomes critical when combining async patterns with capability domains—a task holding a capability must not indefinitely block, or secondary domains cannot reclaim resources.

**Zero-Copy IPC Compatibility**: Embassy's DMA-first approach ("Making DMA the first choice rather than the last") aligns with zero-copy IPC goals. Capabilities over memory regions can be transferred between domains without data duplication, mirroring how Embassy abstracts peripheral access through safe HAL APIs.

**Priority Isolation**: Embassy supports "multiple executor instances...to run tasks at different priority levels," enabling higher-priority tasks to preempt lower ones. NARF's PKS/MTE domains can enforce similar isolation—higher-privilege domains execute in dedicated executor contexts, preventing lower-priority leakage.

## Performance Trade-Offs

**Efficiency vs. Complexity**: Embassy's fair scheduling ("All other tasks get a chance to run before a given task gets polled for the second time") prevents task starvation but adds queue management overhead. NARF must balance this: capability checks at context switches have latency cost, but skipping them risks security violations.

**Memory Overhead**: Embassy notes that "program size may be higher than other alternatives," particularly with async transformation. NARF's added capability structures (domain tables, MTE tags) similarly increase footprint. Optimize by sharing capability descriptors across sibling domains rather than per-task replication.

**Interrupt Latency**: Manual ISRs alongside Embassy show latency reduction strategies. NARF should permit fast-path capability verification in interrupt handlers while deferring complex operations to async contexts.

## Scheduler-Specific Guidance

**Adopt**:
- Wake-based scheduling over time-sliced preemption—integrates naturally with capability revocation
- Task-local futures for resource management—capabilities can be scoped to async block lifetimes
- Interrupt-driven executor triggering—aligns with MTE tag violation signals

**Avoid**:
- Blocking syscalls within async tasks—breaks capability isolation guarantees
- Shared mutable state without explicit capability transfer—defeats the purpose of domain separation
- Unbounded task spawning—capability accounting becomes intractable

## Pitfalls

Mixing manual ISRs with async code requires discipline: capability enforcement must be consistent across both paths. Embassy documents this as possible but notes the complexity. NARF should provide enforced patterns (e.g., ISR contexts cannot directly access domain-private capabilities).

Stale capability references pose risks if async task migration occurs. Document that moving a task across domains invalidates its capability set; explicit re-grant is required.

The "zero-cost abstraction" premise of async breaks if capability checks introduce unpredictable latency. Profile domain transition overhead and set budgets per subsystem.

https://embassy.dev/book/
