# drivers/net — Network drivers

Network device drivers (VirtIO-net first, then at least one real NIC).
Exports frames via a dedicated Narf-Ring; pairs naturally with `io/`
P2P DMA for NIC→GPU paths.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 4 (real hardware); virtio-net usable in Stage 3 via `drivers/virtio/`.
