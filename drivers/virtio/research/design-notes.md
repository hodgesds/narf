# drivers/virtio — Design Notes

> Created: 2026-04-22

---

## Load-bearing decisions

**Split virtqueues first, packed later — or both from day one.** §8 leaves this as an open question. This is actually a load-bearing architectural decision, not a scheduling question. The virtio-1-2-spec research summary recommends "Use Packed Virtqueues exclusively if the hypervisor supports them." But QEMU's virtio-pci device defaults to split ring unless `VIRTIO_F_RING_PACKED` is negotiated; older cloud hypervisors (AWS Nitro as of 2023, some GCP images) still default to split. If NARF negotiates packed-only, it will fail on any host that does not support it. If NARF implements split-only first, the packed code never lands and NARF is permanently behind. The correct answer is: implement split first as the mandatory baseline, packed as a non-mandatory fast-path negotiated via `VIRTIO_F_RING_PACKED`, with the same `VirtqueueOps` trait implementation. The spec should say this explicitly.

**Feature bits as capabilities.** The research summary frames this as a natural mapping: VIRTIO feature bits → NARF cap bits. But the mapping is not 1:1. Some VIRTIO features are device capabilities (the host has hardware offload), some are protocol capabilities (the driver understands the packed ring format), and some are negotiation policies (the driver requests in-order processing). Treating all of them as capabilities conflates what the device *can* do with what the driver is *allowed* to do. VIRTIO_F_NOTIFICATION_DATA (driver sends extra data with available buffer notification) is a driver policy, not a security-relevant capability. The cap model should cover only security-relevant features — DMA access, buffer ownership — and leave protocol flags as plain configuration.

**Validation on every wake.** §4 says "Virtqueue descriptor rings are validated on every wake (bounds, generation, indirect depth cap)." For virtio-blk in QEMU at 100k IOPS with 64-deep queues, that is 6.4M validation checks per second. The VIRTIO 1.2 spec research summary notes the performance-critical design: "cache-conscious design is critical for NARF's zero-copy IPC model." Validating every used ring entry on every wake adds a cache miss per entry (the used ring descriptor is cold after the hypervisor wrote it). NARF should validate at submission time (driver controls the available ring — can validate before writing) and trust the used ring entry's buffer reference (hypervisor cannot write an arbitrary address back — it can only reference addresses the driver submitted). Validate driver-side writes; trust device-side completions against submitted references.

**One Narf-Ring per device class.** The outbound interface per §3 is "one Narf-Ring per device-class (block requests, net frames, ...)." This means virtio-blk and virtio-net each get one ring to `block/` and `net/` respectively. But virtio-blk supports multiple virtqueues (up to 128 in the spec, device-dependent). Funnelling all virtqueues through one Narf-Ring forces serialisation at the Narf-Ring level, negating the multi-queue benefit the hypervisor exposes. Same issue as NVMe above — the "one ring" abstraction is too coarse.

---

## Divergences from precedent

**virtio running in a domain, not as a privileged driver.** Linux's virtio layer runs in the kernel with full memory access. NARF's virtio driver runs in a PKS/MTE domain with only its DMA buffers, MMIO window, and Narf-Ring visible. This is correct and a genuine improvement. But it means the virtio driver cannot use the Linux pattern of `phys_to_virt()` to convert DMA addresses to kernel VAs on the fly. Every DMA buffer the hypervisor returns in a used ring entry must be resolved via the driver's DMA capability table, not via a direct address translation. The spec does not mention this — it is implied by "the driver never touches memory outside its DMA buffers" — but it has significant implementation implications for any developer coming from the Linux virtio codebase.

**No legacy device support.** The spec does not address VIRTIO_F_VERSION_1 negotiation or legacy (pre-1.0) device support. Linux's virtio layer supports both legacy and modern transports. QEMU virtio-pci before approximately 2018 defaults to legacy. NARF should explicitly declare: "NARF requires VIRTIO_F_VERSION_1. Legacy devices are unsupported." This simplifies the driver significantly (no legacy config space layout, no 16-bit queue sizes) but must be an explicit policy statement, not an accidental gap.

**Async notification model over poll-mode.** The research summary recommends "Defer descriptor fetches until notification. Don't poll the used ring on every I/O submission." NARF follows this because the executor parks Futures. But QEMU and many hypervisors optimise for the case where the driver polls the used ring immediately after submission (batched completions). With a parked Future, the driver may not check the used ring until the next interrupt fires, adding up to one interrupt coalescing interval of latency (often 100–500 µs). For low-latency workloads, this is worse than synchronous poll-after-submit. The spec should allow a "sync completion" fast path for virtio-blk I/O below a configurable latency threshold.

---

## Proposed spec changes

- §3 Public interface (internal modules): Replace implicit single-queue assumption with: "Each virtio device exports N Narf-Ring handles, where N = min(negotiated_queue_count, cpu_count). The `class_blk` and `class_net` modules multiplex these into the block and net subsystem interfaces." — *preserves hardware parallelism through the driver stack.*

- §3 Public interface: Add `fn negotiate(offered: FeatureSet) -> Result<FeatureSet, NegotiateError>` to the driver start protocol. This must complete before `start()` is called. The negotiated feature set is immutable for the driver's lifetime — no re-negotiation. — *makes feature negotiation observable and auditable.*

- §4 Invariants: Refine the validation rule: "Available ring writes (driver-controlled) are validated before publishing: buffer addresses are within DMA cap, flags are valid, indirect depth ≤ 1. Used ring reads (device-controlled) are trusted for address references (only completions for previously submitted descriptors are accepted) but validated for length (reported length ≤ submitted buffer length)." — *removes the cost of re-validating device-written completions while maintaining correctness.*

- §5 Architecture notes: Add: "NARF requires VIRTIO_F_VERSION_1 for all devices. Legacy (pre-1.0) virtio devices are not supported. If the PCI/MMIO transport does not offer VIRTIO_F_VERSION_1, device binding fails." — *explicitly closes the legacy support question.*

- §5 Architecture notes (aarch64): Add: "On aarch64 QEMU virt machine, virtio-mmio devices are enumerated from the device tree. The MMIO transport does not provide per-queue MSI-X; all queues share a single GIC SPI. `interrupts/` must demultiplex which virtqueue caused the IRQ by scanning used ring indices." — *documents the interrupt model difference that will bite implementers.*

- §8 Open questions: Replace "Split-only first, packed later — or both?" with: "Split ring is the mandatory baseline. Packed ring is negotiated via `VIRTIO_F_RING_PACKED` as an optional fast-path. Both code paths must pass the same `virtqueue_ops` trait contract tests before Stage 3 exit." — *closes the question with a concrete decision.*

---

## Open invariants / cross-subsystem hazards

**`drivers/virtio/` ↔ `ipc/` ownership transfer for descriptor chains.** The Narf-Ring ownership model transfers a single buffer handle. virtio descriptor chains can link multiple buffers: a virtio-net frame might be a 12-byte virtio header + variable-length ethernet frame in two separate buffers. Transferring ownership of a descriptor chain via Narf-Ring either requires a "compound capability" (one handle covering N non-contiguous regions) or N separate ring pushes per chain. Neither model is currently in `ipc/`'s spec. This is a Stage 3 blocker — virtio-net in Stage 3 uses chained descriptors.

**`drivers/virtio/` ↔ `memory/` DMA coherency on aarch64.** On aarch64 platforms without hardware cache coherency between CPU and device (e.g., some Raspberry Pi models, certain NUMA configurations), the driver must issue explicit cache maintenance instructions before and after DMA transfers. The spec says `arch/` handles this, but the virtio driver has to know *when* to call the cache maintenance hook — specifically, after writing available ring entries (before notifying the device) and before reading used ring entries (after the device notifies). If the driver relies on `arch/` to handle this transparently, there must be a defined API. If the driver is responsible, it must be in the driver spec.

**`drivers/virtio/` ↔ `capabilities/` feature-bit cap derivation.** The research summary says "map VIRTIO feature bits to NARF capability bits." But `capabilities/`'s spec does not define a mechanism for creating capabilities from hardware-negotiated feature sets at runtime. Cap derivation (§3.3 of `capabilities/`) is defined for hierarchical derivation from parent caps, not for hardware discovery. A new mechanism — "hardware-bound capability" — may be needed: a cap whose validity is tied to a feature bit being negotiated. If the hypervisor revokes `VIRTIO_F_INDIRECT_DESC` (impossible in practice but possible in principle via device reset), the corresponding cap becomes invalid. This is a `capabilities/`-level concept that virtio drivers would consume.

---

## Additional opinionated commentary

The virtio spec is deliberately permissive about which features must be supported. The virtio-1-2-spec summary's strongest recommendation — "Validate feature flags at bind time. Deny driver initialization if required features are unsupported" — is exactly right for NARF's security model. But the spec must also enumerate *which* features are required vs. optional for each device class. For virtio-blk: VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_SEG_MAX, and VIRTIO_BLK_F_FLUSH should be required (without them, large I/Os or fsync cannot be guaranteed safe). For virtio-net: VIRTIO_NET_F_MAC should be required (without it, MAC address is undefined). The Stage 3 driver spec should include a feature requirement table per device class, not just a generic negotiation mechanism.

QEMU's virtio device models are the only test target before Stage 4. This means any bug in NARF's virtio implementation that depends on specific hardware behaviour (e.g., notification batching, descriptor ring wrap timing) will not be caught until real hardware is in scope. The `verification/` harness should include a QEMU-side "adversarial device" that sends out-of-spec responses (duplicate completions, truncated lengths, device reset mid-operation) to smoke-test the driver's defensive validation paths.
