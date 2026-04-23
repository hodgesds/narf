# drivers/virtio — Specification

> Status: **Outline v0.1** (Stage 3).

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
  network / console bytes.

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

Internal modules: `transport_pci`, `transport_mmio`, `queue_split`,
`queue_packed`, `class_blk`, `class_net`, `class_console`.

## 4. Invariants & safety properties

- The driver never touches memory outside its DMA buffers + MMIO window +
  its own domain.
- Feature negotiation always terminates; unknown bits are cleared.
- Virtqueue descriptor rings are validated on every wake (bounds,
  generation, indirect depth cap).

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

## 8. Open questions

- Split-only first (simpler), packed later — or both from day one?
- Do we use virtio-console as the Stage 3 console fallback, or stick
  with 16550A/PL011 until Stage 4?
- Multi-queue sizing policy — CPU count based vs. fixed.
