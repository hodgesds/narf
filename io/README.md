# io — DMA, IOMMU, P2P DMA

DMA buffer management, IOMMU/SMMU programming, P2P DMA enablement so
NIC→GPU and similar paths bypass the CPU entirely.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: **Stage 3 landed (DmaBuffer + IOMMU stub).** `DmaBuffer`
  (backed by `PhysFrame`, `CapType` → `CapKind::DmaBuffer`),
  `alloc_coherent` / `free_coherent` (single-frame, page-aligned),
  `IommuContext` stub with `map` / `unmap` no-ops (QEMU has no
  vIOMMU by default), `IoError`, `p2p_map` signature-only placeholder.
  Deferred to Stage 4: contiguous multi-frame alloc (needs a buddy
  allocator in `memory/`), real VT-d / AMD-Vi / SMMUv3 programming
  + IOTLB invalidate, P2P topology walk, aarch64 `DC CIVAC` cache
  ops on Streaming buffers, `Cap<BusDevice, Dma>` gating on
  `alloc_coherent`.
