# Hazard Pointers — reading notes

**Primary sources:** Michael, "Hazard Pointers: Safe Memory
Reclamation for Lock-Free Objects" (IEEE TPDS 2004); Folly's
`hazptr`; C++ proposal P1121 (standardised in C++26).

> Distilled for NARF design. The third reclamation variant.

## The idea

Each reader publishes, in a designated **hazard slot**, the pointer
it is about to dereference. Writers that want to reclaim an object
scan all hazard slots — if the object isn't named by any slot, it's
safe to free.

Contrast with epoch/QSBR, where readers don't identify *which*
object they hold, only *which generation* they're in.

## The read protocol

```text
loop {
    p = atomic.load(Acquire);
    hazard_slot = p;
    fence(SeqCst);
    if atomic.load(Acquire) == p { break; }
}
// dereference *p freely
// when done:
hazard_slot = null;
```

The loop guards against a writer replacing `p` and freeing the old
value between the initial load and the slot publish. The fence
ensures the slot publish is globally visible before the re-check
load observes what writers see.

## The writer protocol

```text
old = atomic.swap(new, AcqRel);
retire(old);         // add to local retire list

// periodically:
scan_hazards();      // read every reader's slot
for obj in retire_list:
    if obj not in any hazard slot:
        free(obj)
```

## Memory-safety guarantee

Bounded. At most `H * R` objects can be awaiting reclamation, where
`H` is slots per reader and `R` is reader count — independent of
grace-period length. This is hazard pointers' headline advantage
over epoch / QSBR, which can grow unboundedly if a reader stalls.

## Cost

- **Read-side:** higher than epoch/QSBR — a fence, a re-check, and
  the slot publish. On x86_64 the fence is the hot-path cost; on
  aarch64 the `DMB ISH` is noticeable.
- **Write-side:** O(H × R) scan per reclamation batch.
- **Per-reader storage:** H pointer-sized slots, usually 2–8.

## Why NARF keeps it as an option

- **Bounded-memory workloads.** If a subsystem really cannot
  tolerate epoch's "stuck reader → unbounded growth" worst case
  — e.g. a limited-memory driver domain — hazard pointers give a
  hard ceiling.
- **Long reads without sleeping.** Use cases that can't go async
  (so sleepable isn't available) but hold references across many
  operations. File-tree walks in a constrained context come to
  mind.
- **Precedent.** Folly + C++26 give us a well-studied API shape
  and performance characterisations to match.

## When to prefer hazard pointers in NARF

Default hierarchy:

1. **QSBR** — reads are free; use it wherever the poll-boundary
   rule holds.
2. **Epoch** — reads are cheap; use when you're outside the poll
   loop.
3. **Sleepable** — reads may `await`; use when the logical read
   spans I/O.
4. **Hazard pointers** — reads are bounded; use when memory budget
   is tight or worst-case growth is unacceptable.

## API sketch for NARF

```rust
pub struct HazardCell<T>;                 // like Atomic<T> but with hazard scheme
pub struct HazardReader;                   // owns a slot array
pub fn hazard_reader(n_slots: usize) -> HazardReader;

impl<T> HazardCell<T> {
    pub fn load_protected(
        &self, slot: &mut HazardSlot, reader: &HazardReader,
    ) -> Protected<'_, T>;
}

pub fn retire<T>(x: Owned<T>);
```

Under the hood, the same per-domain reclamation worker drains
retire lists; the difference is the scan step uses slot contents
rather than epoch counters.

## Implementation notes

- Slot publish needs a full `SeqCst` fence to pair with the re-check
  load; **don't** downgrade to release/acquire or correctness breaks.
- Batching retires is essential — per-object scan is too expensive.
  Reclaim in batches of ~64.
- On NUMA systems, reclaim per-node with per-node retire lists.

## Caveats

- Slot count per reader is a capacity ceiling. Deep traversals
  exceed it; in that case the traversal must use sleepable or
  epoch instead.
- ABA on the pointer cell is already handled by the re-check loop,
  but consumers building custom data structures must still think
  about ABA on *other* fields.
