# virtio-blk-pci async IRQ test — vector-mismatch failure mode

## Status

Pre-existing test failure surfaced by improved diagnostic (commit
`5d52f55` — branchy fail strings discriminate failure modes). Root
cause not yet pinned down; this note captures what's known so the
next investigation can pick up cleanly.

## Failure

`smoke_virtio_blk_pci_irq_async` and `smoke_virtio_blk_pci_write_irq_async`
report:

> future never resolved — waker fired but fire_count unchanged
> (vector mismatch?)

i.e. `wokes > 0` AND `fire_count(v) == baseline` after the 1000-poll
budget expired.

## What that means

The test's custom Waker (with payload = `&WOKEN: &AtomicBool`) was
called via `wake_by_ref` at least once during the test loop. But the
fire_count for the vector `v` the test got from `enable_msix_for_probed`
did not move.

If the IRQ at vector `v` had delivered, `dispatch::on_irq(v)` would
have both:
- bumped `SLOTS[v].fired` (which `fire_count(v)` reads)
- AND called `wake_by_ref` on every Waker in `SLOTS[v].wakers`

Since fire_count didn't move, **the IRQ that actually fired
wake_by_ref on the test's Waker was at a vector OTHER than `v`.**

## Likely paths

1. **Waker double-registered in multiple SLOTS**: WaitForIrq calls
   `set_waker(self.vector, cx.waker().clone())`. self.vector should be
   `v`. Some other code path may also be `set_waker(X, w)`-ing the
   same waker into a different vector.

2. **Wheel-driven wake**: SleepUntil (inside the `Timeout<WaitForIrq>`)
   calls `timer_wheel::register(deadline, cx.waker().clone())`. The
   wheel stores the waker. `fire_due` (called from `clockevent::on_tick`
   on every timer IRQ, OR from the executor's idle path) iterates
   expired entries. Our deadline is 5 s in the future, but a stale
   wheel entry from a prior test pointing to the same static `WOKEN`
   address could fire.

3. **Diagnostic counter is wrong**: `wokes += 1` increments when
   `WOKEN.swap(false, AcqRel)` returns true. If WOKEN is set by a
   path that doesn't bump fire_count(v), wokes is correctly > 0 but
   fire_count(v) doesn't move. (This is what's happening — the
   question is what path.)

## Reproducer

```bash
XTASK_QEMU_TIMEOUT_SECS=180 cargo xtask test --arch=x86_64 2>&1 | grep virtio_blk_pci_irq
```

Failure is deterministic on QEMU TCG.

## What would close this

Add per-vector wake counters to dispatch.rs (count `wake_by_ref` /
`wake` calls per vector). Re-run the test and inspect which vector's
counter moves. That immediately identifies path (1) vs (2).

Alternatively, add an assertion at the top of `dispatch::on_irq`'s
wake path that the Wakers in SLOTS[vector].wakers all correspond to
futures that are waiting on `vector` — currently no such invariant
is enforced.

## Why not fixed today

The fix requires a per-vector wake-counter instrumentation that's
not in tree yet. The diagnostic that landed (branchy fail strings)
is the foundation for the next session's work — without it the
failure was opaque ("future never resolved within poll budget"
matched all 4 distinct failure modes).
