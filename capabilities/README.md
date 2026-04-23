# capabilities — Rust-typed capability tokens

Unforgeable tokens granting specific rights over specific objects.
Encoded as Rust types whose construction is gated by the kernel's cap
table, so forgery, aliasing-without-permission, and UAF are type errors.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: design sketch Stage 1; full Stage 3.
