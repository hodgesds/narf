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
- Stage: 1 (API + QSBR stub) → 2 (real QSBR + epoch + hazard) → 3 (sleepable, consumers adopt) → 4 (full tuning).
