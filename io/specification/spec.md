# io — Specification

> Status: **Outline v0.1** (Stage 3).

## 1. Purpose & scope

**Owns:** `DmaBuffer<T>` type and lifecycle, IOMMU/SMMU configuration,
per-device protection domain setup, P2P DMA topology discovery and mapping.

**Does NOT own:** Per-device MMIO access (each driver owns its own),
ring-buffer message transport (`ipc/`), interrupt delivery (`interrupts/`).

## 2. Assumptions

- `memory/` provides physically-contiguous allocation for DMA buffers.
- `capabilities/` gates DMA buffer creation: a driver needs
  `Cap<BusDevice, Dma>` to allocate and bind.
- **IOMMU presence is verified at boot by `arch/`.** Boot panics
  before any driver is loaded if the IOMMU is absent or cannot be
  programmed. This makes the "IOMMU domain ↔ CPU domain
  correspondence" invariant meaningful — we never run drivers on
  a system that cannot enforce it.

## 3. Public interface

```rust
pub struct DmaBuffer<T> { pa: PhysAddr, va: VirtAddr, size: usize, _m: PhantomData<T> }

pub fn alloc_dma<T>(n: usize, dev: &BusDevice) -> DmaBuffer<T>;

pub fn map_p2p(src: &BusDevice, dst: &BusDevice, buf: &DmaBuffer<T>)
    -> Result<P2pBinding, IoError>;

/// Tear down a P2P binding. Quiescence protocol (binding):
/// 1. Notify both drivers' domains of pending teardown via `tracing/` event.
/// 2. Invalidate both sides' IOMMU TLB entries for the binding's IOVA range.
/// 3. Wait for in-flight DMA to complete — either by IOMMU drain
///    (preferred where supported: VT-d `IOTLB_INVALIDATE` + Drain Wait;
///    SMMUv3 `CMD_TLBI_NSNH_ALL` + `CMD_SYNC`), or by a
///    device-activity timeout (default 100 ms).
/// 4. Release the binding's resources.
/// Returns only after step 4 completes.
pub fn unmap_p2p(binding: P2pBinding) -> impl Future<Output = ()>;

/// Per-domain IOMMU fault handler. The driver framework registers
/// one of these per driver domain; `io/` invokes it on every fault
/// the IOMMU reports for that domain (drained from the hardware
/// fault log: VT-d Fault Recording, AMD-Vi Event Log, SMMUv3
/// PRIQ / EVTQ). In Stage 3 the default is log-and-continue; in
/// Stage 4 a fault rate exceeding a per-driver threshold escalates
/// to driver termination.
pub type IoFaultHandler = fn(&BusDevice, IoFault);
pub fn register_fault_handler(dev: &BusDevice, h: IoFaultHandler);
```

IOMMU: each driver gets its own IOMMU context so a malicious device
cannot DMA outside the buffers its driver explicitly mapped.

## 4. Invariants & safety properties

- A `DmaBuffer<T>` is pinned in physical memory for its lifetime.
- **CPU-domain ↔ IOMMU-domain correspondence is enforced at
  `alloc_dma` call time**: `dev`'s IOMMU domain ID is verified to
  equal the calling task's `DomainId`; mismatch is a panic, not a
  return value. Without this runtime check the correspondence is
  aspirational, not load-bearing.
- Dropping a `DmaBuffer` tears down the IOMMU mapping before freeing
  physical storage. **IOTLB invalidation must complete before
  `PhysFrame` is returned to `memory/`.** Completion mechanism:
  VT-d uses `IOTLB_INVALIDATE` + poll `IOTLB_CTRL.IVT` bit;
  SMMUv3 uses a `CMD_TLBI_*` + `CMD_SYNC` polling
  `GERROR.SYNC_ERR`. Without explicit completion polling, a stale
  IOTLB entry could let a freed frame still be DMA-targeted.
- **DMA-buffer and P2P-binding access always goes through `Cap::invoke`**
  (see `capabilities/` §3). When a driver's `Cap<BusDevice, Dma>` is
  revoked, the object epoch bumps; outstanding `DmaBuffer` caps fail
  on next use, the IOMMU mapping is torn down by the reclamation
  path, and any in-flight DMA is quiesced per `drivers/` §3 quiesce
  protocol. Prior authorisation (holding the `Cap`) is not current
  validity.
- **`DmaBuffer` follows the `abi/` cancellation protocol.** A DMA
  buffer submitted as the target of an in-flight operation is
  conceptually borrowed by the device until the submission's
  terminal completion drains. The buffer is freed only on
  `Ok | Cancelled | Error`. Dropping the Future *requests*
  cancellation via `OpCode::Cancel(tag)`; the kernel then either
  (a) aborts the DMA (device-specific — NVMe Abort, virtio
  descriptor reclaim), or (b) waits for hardware completion, then
  returns `Cancelled` with any durable effect reported in `result`.
  Freeing a `DmaBuffer` whose device has not yielded a terminal
  completion is a UAF — the spec forbids it and debug builds
  assert. See `abi/` §3.1.

## 5. Architecture notes

### x86_64
- IOMMU: Intel VT-d or AMD-Vi; we configure per-device context entries.
- P2P DMA: requires ACS on the PCIe root port(s) between peers, or
  explicit ATS/PRI.

### aarch64
- IOMMU: Arm SMMUv3 via the streaming model; StreamID per device.
- **StreamID discovery is via ACPI IORT** (on SystemReady boards) or
  devicetree `iommus` property; `bus/` exposes a StreamID lookup by
  BDF. NARF does not synthesize StreamIDs — they are device-tree
  facts.
- DMA coherency: check `dma-coherent` in devicetree; non-coherent
  paths require cache maintenance around buffer use. **Ownership of
  these `DC CIVAC` operations belongs to `DmaBuffer<T>` lifecycle
  methods** (one before device handoff, one after device completion).
  Drivers do not invoke cache maintenance directly.

## 6. Dependencies

- **Consumes:** `memory/`, `capabilities/`, `arch/`.
- **Provides to:** every device driver; `ipc/` for cross-domain shared
  buffers (in the P2P-on-same-host sense, not PCIe P2P).

## 7. Stage assignment

Stage 3.

## 8. Open questions

- ATS (PCIe Address Translation Services) vs. non-ATS IOMMU: do we
  mandate ATS?
- Buffer bouncing for non-coherent aarch64 — who pays the cache flush cost?
- NUMA locality for DMA buffers.
