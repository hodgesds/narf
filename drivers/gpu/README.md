# drivers/gpu — GPU driver

A GPU driver is the stretch target of Stage 4. Runs in a dedicated
domain; uses `io/` P2P DMA to move frames directly from the NIC / NVMe.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 4 (partial; full GPU may slip beyond the initial roadmap).
