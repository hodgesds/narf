# drivers/virtio — Specification

> Status: **v1.0** (Stage 3 design lock). v0.1 outlined the
> shared transport + per-device drivers; v1.0 locks the
> ring-format choice (split-only at v1.0, packed at v1.1+),
> the console-backend strategy, and the multi-queue sizing
> policy.

## 1. Purpose & scope

**Owns:** VirtIO device discovery (PCI + MMIO transports), feature
negotiation, virtqueue handling (split + packed), device-class glue to
blk/net/console/rng.

**Does NOT own:** Block-storage or network protocol stacks above VirtIO
(those belong to higher-level drivers/stacks).

## 2. Assumptions

- `io/` can allocate DMA buffers bound to this driver's IOMMU context.
- `interrupts/` can register an MSI/MSI-X or UIPI handler.
- `ipc/` provides Narf-Rings as the transport to whoever consumes block /
  network / console bytes. The virtio-mem class owns queue-0
  PLUG/UNPLUG/STATE transactions and continuously converges allocator-online
  blocks to the generation-stable `requested_size`.

## 3. Public interface

- Inbound: capability-gated `start(config: VirtioConfig)`. Before
  `start` is called, the framework invokes
  `negotiate(offered: FeatureSet) -> Result<FeatureSet, NegotiateError>`.
  The returned set is **immutable for the driver's lifetime** — no
  re-negotiation. This makes the negotiated state observable at a
  single point and removes a class of "feature appeared/disappeared
  mid-flight" bugs.
- Outbound: per device, **N Narf-Ring handles where N =
  min(negotiated_queue_count, cpu_count)**. Single-queue
  multiplexing was the original wording; that throws away virtio's
  native parallelism the moment we touch real hardware. `class_blk`
  and `class_net` modules consume the per-queue rings and present
  the unified block/net subsystem interfaces.
- virtio-gpu exposes `offered_features()`, `host_offers_virgl()`, and
  `virgl_enabled()`. The first two report the pre-negotiation host offer;
  `virgl_enabled()` is true only after immutable negotiation accepts
  `VIRTIO_GPU_F_VIRGL`. When enabled, the transport provides typed controlQ
  operations for context creation/destruction, resource attachment, 3D
  resource creation, and bounded `SUBMIT_3D` command streams. The DRM
  render-node bridge owns per-open resource lifetime and validates all
  user-provided command sizes before it calls this surface. A 2D-only host
  remains supported with the feature clear.
- Virtio block request futures register the caller's waker in their in-flight
  request slot and completion wakes it after removing the request from the
  used ring. Unsupported/no-op flush, discard, and cancel paths resolve
  immediately rather than returning a permanently pending future.

Internal modules: `transport_pci`, `transport_mmio`, `queue_split`,
`queue_packed`, `class_blk`, `class_net`, `class_console`.

## 4. Invariants & safety properties

- The driver never touches memory outside its DMA buffers + MMIO window +
  its own domain.
- Feature negotiation always terminates; unknown bits are cleared.
- Virtqueue descriptor rings are validated on every wake (bounds,
  generation, indirect depth cap).
- A virtio-mem block enters the frame allocator only after host PLUG/STATE
  acknowledgement and kernel-linear-map validation. Unplug first proves the
  exact block free; device rejection transactionally restores it. Busy blocks
  remain online and are never force-reclaimed.

## 5. Architecture notes

### x86_64
- PCI MSI-X for IRQs; MMIO BAR for legacy.
### aarch64
- Discovered via devicetree (MMIO transport) under QEMU virt; PCI when
  the platform provides ECAM.

## 6. Dependencies

- **Consumes:** `drivers/` (framework), `io/`, `ipc/`, `interrupts/`,
  `capabilities/`, `memory/`, `arch/`.
- **Provides to:** `drivers/net/` (once virtio-net is used as base),
  future block paths, console fallback.

## 7. Stage assignment

Stage 3 — *the* Stage 3 milestone driver.

## 8. Resolved decisions

### 8.1 Ring format (resolved)

**Decision:** **split-only at v1.0; packed-ring support
at v1.1+**. The split-virtqueue format is universally
supported by every virtio device QEMU emits and is what
existing NARF code uses. Packed-ring is a 30-50%
throughput win on hot paths and lands as a separate driver
SDK feature in v1.1.

`narf-drivers-virtio` v1 enables only split via VIRTIO_F_RING_PACKED
NOT being negotiated; v1.1 will add the negotiation path.

### 8.2 virtio-console as console backend (resolved)

**Decision:** **virtio-console is an additive sink, not a
replacement** (per `console/spec` §8.2). The 16550A (x86_64)
or PL011 (aarch64) UART remains primary; virtio-console
mirrors output when the device is probed, providing a
clean log surface for VM environments.

This means NARF runs on bare metal without virtio-console
and inside QEMU with both — no fork in the console path.

### 8.3 Multi-queue sizing (resolved)

**Decision:** **CPU-count based with caps**. virtio-net,
virtio-blk allocate `min(cpu_count, max_supported_by_device)`
queues at probe time, one per CPU. Devices with smaller
hardware ceilings (e.g. virtio-blk-pci defaulting to 1
virtqueue) fall back to single-queue + IRQ steering.

Stage 4 work: per-driver tunable to override the
auto-sizing for fast-path workloads (`net/spec` §8.4).

## 9. ABI versioning

`narf-drivers-virtio`'s public surface (the per-device-class
match tables, the `enable_msix_for_probed` shape, the
shared transport helpers used by other virtio drivers) are
re-exported through SDK at `@v0`.

`VIRTIO_DRIVER_ABI_MAJOR = 1`, `VIRTIO_DRIVER_ABI_MINOR = 1`.
Adding a new device-class driver under `drivers/virtio/`
is a minor bump (registers a new match-table entry; doesn't
break existing).

## 10. Open questions

(none — all v0.1 questions resolved in §8)
