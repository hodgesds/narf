# memory — Physical alloc, VM, PKS/MTE domains

Owns physical frame allocation, the virtual-memory manager, page tables,
and the PKS/MTE **domain manager** that carves Ring 0 into 16
hardware-protected partitions.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1 (basic VM) → 2 (domains).
