# lib — Shared Kernel Primitives

`no_std` primitives used across subsystems: sync (Mutex, RwLock,
SeqLock — for the rare case RCU isn't the answer), intrusive
collections (list, RB-tree, heap), bitmaps / bitsets, error helpers,
assertion macros with domain attribution, `Zeroizing` wrappers,
typed IDs.

Deliberately small and additive — a subsystem should prefer
existing Rust crates (pinned in `build/`) when one fits; `lib/`
owns only what we can't take as-is.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1 (minimum viable set) → iterated every stage.
