# rcu — Deferred Reclamation

Deferred-reclamation primitive for the "many readers, rare writers"
pattern. NARF RCU is **epoch-based** (not preempt-based like classic
Linux RCU) with three variants: QSBR, epoch, hazard pointers, plus a
**sleepable** (SRCU-equivalent) mode where readers may `await` while
holding a reservation.

Named `rcu/` for searchability; the mechanics differ materially from
Linux RCU — see spec §1 and [`research/summaries/linux-rcu-variants.md`](./research/summaries/linux-rcu-variants.md).

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: **Stage 3 landed.** Real QSBR with per-CPU reader counters +
  global epoch + per-CPU deferred-drop buckets; Epoch variant with
  pin/unpin/advance/min_pinned; Hazard + Sleepable shape-only stubs.
  `scheduler/` calls `narf_rcu::report_quiescent()` after every poll
  so every cooperative yield advances the grace period (rcu/ §3.7).
  Deferred to Stage 4: sleepable runtime with cap-gated scopes + time/
  deadline, hazard-pointer full implementation, per-domain `defer_drop`
  queues, reclamation-worker Future, batched drop queue under SMP,
  RCU-backed consumers in `capabilities/` / `filesystem/` dentry
  cache.
