# block — Block Device Abstraction

Generic block-device layer: device trait, I/O request abstraction,
scheduler, discard/TRIM, multi-queue dispatch. Sits between
`drivers/{nvme,virtio}` (producers) and `filesystem/` (consumer).

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 3 (core trait + single-queue) → 4 (multi-queue, discard, caching decisions).
