# capabilities — Rust-typed capability tokens

Unforgeable tokens granting specific rights over specific objects.
Encoded as Rust types whose construction is gated by the kernel's cap
table, so forgery, aliasing-without-permission, and UAF are type errors.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: **Stage 3 landed.** Wave 0 shipped `Cap<T, R>` + `CapSlot`
  (128-bit, CMPXCHG16B-sized) + `Rights` + full `CapKind` wire
  registry. Wave 2 added the object-epoch table, `check_live` /
  `invoke` / `revoke` fast path, and the `bootstrap()` safe mint path.
  Deferred to Stage 4: `Cap<Task, Create>`-gated bootstrap, badge
  storage field in `CapSlot`, RCU-backed object-table reader, slot
  reuse, in-kernel `CapKind` dispatcher for the `abi/` submission
  surface.
