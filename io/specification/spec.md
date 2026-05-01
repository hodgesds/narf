# io — Specification

> Status: **v1.0** (Stage 3 design lock). v0.1 covered the
> `DmaBuffer` lifecycle + IOMMU contract; v1.0 locks the
> `Cap<DmaBuffer, _>` mint flow, the per-driver quota dimensions
> the framework consumes, ATS policy, NUMA locality, and the
> ABI versioning policy.

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

## 8. Capability surface

```rust
pub struct DmaBuffer;        // CapKind::DmaBuffer
pub struct IommuContext;     // internal — per-driver IOMMU domain handle
```

The driver framework mints `Cap<DmaBuffer, _>` at allocation
time, with the cap's badge encoding:

- The bound `BusDevice` (which device owns this DMA target).
- The mapped `DomainId` (CPU-side domain that may access the
  buffer).
- The IOVA range (which sub-range of the device's IOVA space).

Revocation (driver unload, fault-rate escalation, manual
revoke) bumps the cap's epoch; subsequent `read`/`write` to the
buffer fail with `Err(Revoked)`. The IOMMU teardown then
follows the §4 invariants — IOTLB invalidate before frame
return.

### 8.1 Allocation API

```rust
pub fn alloc_coherent(
    n:   usize,
    dev: &Cap<BusDevice, Dma>,
    quota: &Cap<Quota, Spend>,
) -> Result<Cap<DmaBuffer, Read | Write>, IoError>;

pub fn alloc_streaming(
    n:    usize,
    dev:  &Cap<BusDevice, Dma>,
    dir:  Direction,                // ToDevice | FromDevice | Bidirectional
    quota: &Cap<Quota, Spend>,
) -> Result<Cap<DmaBuffer, /* dir-tagged rights */>, IoError>;
```

`alloc_coherent` is for ring/control structures — coherent
across the CPU/device boundary, no cache maintenance needed.
`alloc_streaming` is for transient payload buffers — needs
explicit pre/post-DMA cache maintenance on aarch64
non-coherent paths (handled by `DmaBuffer` lifecycle, drivers
never call cache ops directly per §5 aarch64).

Both charge the calling driver's `Cap<Quota, Spend>` against
the `max_dma_bytes` and `max_dma_buffers` dimensions
(`drivers/spec` §17.2). Exhaustion → `Err(QuotaExceeded)`.

## 9. Resolved decisions

### 9.1 ATS mandate (resolved)

**Decision (was open):** ATS is **not mandated**. Drivers and
NARF run on platforms with or without ATS. The IOMMU is
mandated (see §2); ATS is an optional optimization.

A driver that wants to use ATS does so via an opt-in cap
operation:

```rust
fn enable_ats(dev: &Cap<BusDevice, _>) -> Result<Cap<AtsContext, _>, IoError>;
```

ATS-enabled drivers see lower DMA latency on platforms that
support it; the same driver code falls back to non-ATS DMA
otherwise. The op queries the device's PCIe ATS capability
and the IOMMU's ATS support; missing either → `Err(NotSupported)`.

This avoids the platform-availability problem of mandating ATS
(many embedded aarch64 platforms don't have it) while still
letting hot-path drivers (NVMe, RDMA NICs) opt in for the
performance win where available.

### 9.2 Non-coherent cache flush ownership (resolved)

**Decision (was open):** **`DmaBuffer<T>` lifecycle methods
own all cache maintenance**, transparently to drivers. The
driver writes payload, calls `buf.before_device_use()` (or
`alloc_streaming`'s implicit handoff), the device DMAs, and on
completion the driver calls `buf.after_device_use()` (or the
implicit reclamation path).

Cost attribution: the cache-flush op runs in the **driver's
domain context**, not in `io/`. So the driver's `Cap<Quota,
Spend>` could in principle account it; in v1.0 we don't —
cache ops are too cheap to bother metering. Revisit if a
pathological non-coherent platform shows otherwise.

x86_64 is fully coherent for DMA; these methods are no-ops.
aarch64 with `dma-coherent` in DT is also no-op. Only legacy
or constrained aarch64 platforms (some embedded SoCs) pay the
cost.

### 9.3 NUMA locality (resolved)

**Decision (was open):** DMA buffers are NUMA-locality-aware
via the `BusDevice`'s `numa: Option<NumaNodeId>` field.
`alloc_coherent` and `alloc_streaming` allocate from the
device's home node when possible; if the home node is
exhausted, fall back round-robin to other nodes (with a
`tracing/` event noting the fallback for observability).

The fallback is per-allocation, not per-driver. A device
pinned to NUMA node 1 with node 1 exhausted gets node 0
buffers transparently; performance suffers but correctness
holds.

The `bus/` layer is responsible for populating
`BusDevice::numa` from ACPI SRAT (x86_64) or DT
`numa-node-id` (aarch64). Devices without NUMA metadata
default to "any node" allocation.

## 10. Per-driver IOMMU domain

Each driver instance receives a `Cap<IommuContext, Read>` at
BIND time alongside the rest of its cap bundle. The IOMMU
context corresponds to a **dedicated IOMMU domain ID** on the
hardware:

- VT-d: a context entry distinct from any other driver's.
- SMMUv3: a distinct StreamID-to-domain mapping (multiple
  StreamIDs may map into the same domain when one driver owns
  multiple devices).

The per-driver IOMMU domain enforces **inter-driver isolation
even at the DMA level** — a compromised driver cannot DMA into
another driver's memory regardless of what BAR/DMA addresses
it forges, because the IOMMU rejects the access.

This is the IOMMU-side of the CPU domain isolation in
`security-model/` §4.1: caps + domains + IOMMU = three
independent layers a compromise must defeat.

## 11. Fault handling

`IoFault` is the unified type across VT-d / AMD-Vi / SMMUv3:

```rust
pub struct IoFault {
    pub kind:     FaultKind,        // PageFault | InvalidContext | TimeOut | ...
    pub iova:     u64,              // faulting IOVA
    pub stream:   u32,              // bus device id (BDF or StreamID)
    pub access:   AccessType,       // Read | Write | Execute (where applicable)
}
```

Per-driver fault handlers are installed via §3
`register_fault_handler`. The framework's default policy
(installed automatically at BIND if the driver doesn't supply
one):

```rust
fn default_io_fault_handler(dev: &BusDevice, fault: IoFault) {
    record_to_tracing_ring(dev, &fault);
    bump_per_instance_fault_counter(dev);
    if rate_exceeds_threshold(dev) {
        request_driver_unload(dev, UnloadReason::IoFaultStorm);
    }
}
```

The threshold is per-driver-instance (manifest-configurable
defaults: 100 faults/second sustained for 10 seconds → unload).

## 12. ABI versioning

`io/` exports are tagged at `@v0` in the SDK. The wire
contracts:

- `DmaBuffer` cap badge layout (BusDevice id + DomainId + IOVA
  range) is part of the cap-ABI; changes follow `CAP_ABI_MAJOR`.
- `IoFault` struct layout is part of the SDK ABI; field
  additions are minor bumps; renumbering kinds is a major.
- Allocation APIs (`alloc_coherent`, `alloc_streaming`) are
  versioned per-symbol; an `alloc_coherent@v1` adding a
  `flags: AllocFlags` argument would ship alongside `@v0`.

Currently `IO_ABI_MAJOR = 1`, `IO_ABI_MINOR = 0`.

## 13. Open questions

(none — all v0.1 questions resolved in §9)
