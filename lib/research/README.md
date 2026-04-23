# lib — Research

## Primary sources

- **The Rust Programming Language — atomics chapter** + **Rust
  Reference — atomics**.
- **"Rust Atomics and Locks" (Mara Bos, 2023)** — the canonical
  reference for concurrency primitives in Rust.
  <https://marabos.nl/atomics/>

## Secondary sources

- **`spin`** — simple spinlocks; starting point for our `SpinLock`.
  <https://docs.rs/spin/>
- **`parking_lot`** — the fast-locks reference; patterns, not direct
  reuse (it needs `std`).
- **`crossbeam` family** — `crossbeam-utils`, `crossbeam-queue`;
  vetted lock-free primitives.
- **`hashbrown`** — SwissTable hashmap; planned dependency for
  subsystems that need hash maps.
- **`intrusive-collections`** — Rust intrusive collections crate;
  shape reference even where NARF does not take the crate directly.
  <https://github.com/Amanieu/intrusive-rs>
- **`arrayvec`, `smallvec`, `heapless`** — stack / bounded collections
  for `no_std` contexts.
- **Linux `lib/`** — as a catalogue of "things a kernel library owns"
  even though Rust-native equivalents differ in shape.

## Distilled summaries

- (None load-bearing yet. Add as we pick specific primitives.)

## Open research questions

- Fair vs. unfair `Mutex` / `RwLock` defaults.
- Whether to adopt `loom` for concurrency model testing inside
  `verification/`.
- How to keep "one way to do X" discipline as the library grows —
  avoid the 47-list-types of Linux kernel.
