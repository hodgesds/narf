# drivers/gpu — Design Notes

> Created: 2026-04-22

---

## Load-bearing decisions

**virtio-gpu first, then real hardware.** This is stated but the implications are deeper than they appear. virtio-gpu operates in 2D scanout mode (VIRTIO_GPU_CMD_RESOURCE_FLUSH, VIRTIO_GPU_CMD_SET_SCANOUT) and optionally as a 3D accelerator via virglrenderer (Virgil3D). The spec says "framebuffer attach, command-buffer submit" as the outbound interface. These are fundamentally different contracts: scanout mode is a buffer-push model; command-buffer submit is a GPU scheduling model. Conflating them in a single "inbound/outbound" interface description will produce an interface that serves neither well. The spec needs to pick which mode it is targeting in Stage 4 and say so explicitly.

**P2PDMA is a correctness requirement, not just a performance goal.** The spec's §2 assumption states `io/` supports P2P DMA so buffers from NIC or NVMe land in GPU-visible memory. But P2P DMA between PCIe endpoints is not universally available: it requires the two endpoints to be on the same PCIe root port or a root port that permits peer-to-peer transactions, and the IOMMU must be configured to allow it. On QEMU with virtio-gpu, there is no real PCIe topology. On real hardware, P2P DMA availability depends on the system topology. If `io/` cannot fulfil the P2P assumption, the GPU driver falls back to CPU-mediated copies. The spec should define this fallback explicitly — otherwise Stage 4 CI (QEMU) will pass a test that real hardware may silently fail.

**GPU DMA targets are validated against the IOMMU context.** This is stated as an invariant in §4. But the GPU is one of the most active DMA-attack surfaces in modern hardware. AMD GPU firmware (e.g., GFX12) can be instructed via command buffers to issue DMA to arbitrary physical addresses if the IOMMU context is mis-programmed. The invariant says "validated" without specifying: validated at what granularity (command buffer submission time, per-descriptor, or per-page-fault), by whom (the driver in its domain, or `io/` centrally), and how failures are handled (kill the command, revoke the GPU cap, reset the device). Leaving this unspecified is a security gap, not just a design hole.

**A hung GPU causes no kernel hang — the driver domain takes the hit.** This is a correct and important invariant. But GPU hang recovery is notoriously difficult: it requires either a hard GPU reset (which may corrupt in-flight DMA to memory still owned by the GPU) or a shader timeout mechanism (vendor-specific). The spec says the driver domain "takes the hit" but does not say what the recovery path is. A driver domain that is killed while the GPU is mid-DMA to pinned memory leaves those pages pinned forever (or until the IOMMU mapping is explicitly torn down). Who tears them down?

---

## Divergences from precedent

**No DRM/KMS equivalent.** Linux's DRM layer provides the kernel-side abstraction for GPU command submission, modesetting, GEM buffer management, and synchronization (dma-fence). NARF explicitly does not own the compositor or graphics APIs. This is clean, but it means there is no `dma-fence`-equivalent for cross-driver buffer synchronization. If a buffer travels NIC → GPU (via P2P DMA), the GPU command buffer referencing it must not execute until the NIC's DMA into that buffer completes. Linux solves this with `dma_fence` and implicit synchronization. NARF's ownership-transfer model (Narf-Ring) provides an explicit synchronization point — the capability transfer *is* the synchronization — but this only works if the GPU command is submitted *after* the transfer completes. If the GPU is pre-loaded with a command that references a buffer not yet filled, the synchronization gap is silent.

**GPU as just another driver domain.** In Linux and Fuchsia, the GPU has special status: GEM/Magma provide userspace-accessible submission paths, and the kernel GPU driver acts as a mediator between multiple userspace GL/Vulkan contexts. NARF's GPU driver is treated the same as a NIC or NVMe driver. This is ideologically consistent but may prove impractical: GPUs are multi-tenant devices by design (multiple userspace applications submit command buffers). NARF's capability model maps one cap per GPU (or per namespace), but a real GPU needs per-submission-context isolation. This is a place where the "GPU is just a driver" model breaks down and requires a capability hierarchy: `Cap<GpuDevice>` → `Cap<GpuContext>` → `Cap<CommandBuffer>`.

**Minimum-viable presentation: the spec doesn't answer its own question.** §8 asks "what's the minimum-viable presentation path for a terminal?" This is not just an open question — it is the entire motivation for having a GPU driver in Stage 4. The answer dictates the interface. A simple linear framebuffer at a fixed resolution does not need P2P DMA, command buffers, or IOMMU complexity. It just needs: map BAR, write pixels. The spec bundles simple framebuffer and "submission ring for command buffers" under the same §1 scope, but these are two different drivers. The Stage 4 exit criterion should require only the former.

---

## Proposed spec changes

- §1 Purpose & scope: Split into two sub-phases explicitly: "Phase A (Stage 4 v1): simple framebuffer — BAR mapping, mode set, linear scanout. Phase B (post-Stage-4): command buffer submission, P2P DMA, Virgil3D." This prevents scope creep and makes the Stage 4 exit criterion testable. — *prevents building Magma when you need `fbcon`.*

- §2 Assumptions: Add: "P2P DMA is an optional optimisation. The driver must function correctly (with CPU-mediated copies) if `io/` indicates P2P is unavailable for the current bus topology." — *makes the CI/QEMU test honest.*

- §4 Invariants: Extend the GPU DMA validation invariant: "Command buffers are validated before submission. Any descriptor referencing memory outside the driver's IOMMU context is rejected at submission time, not post-fault. Validation is performed by `io/`'s IOMMU wrapper, not by the driver itself." — *removes trust from the driver domain for DMA safety.*

- §4 Invariants: Add hang-recovery invariant: "If the GPU domain is killed, `io/` is responsible for tearing down all IOMMU mappings held by that domain's DMA context within one grace period. No physical pages may remain pinned to the GPU IOMMU after domain death." — *closes the pinned-page-after-crash gap.*

- §6 Dependencies: Add `rcu/` as a dependency. Command buffer completion tracking (knowing when a GPU operation is done so the buffer can be reclaimed) is a deferred reclamation problem. The `rcu/` hazard-pointer variant is the correct tool for tracking in-flight command buffer references without polling. — *connects GPU buffer lifecycle to the existing reclamation infrastructure.*

- §8 Open questions: Add: "Define the per-context capability model. A GPU serving multiple userspace tasks needs sub-device capabilities: `Cap<GpuContext, Submit>` scoped per-task, derived from `Cap<GpuDevice, Own>`. Define the derivation tree before Stage 4 begins." — *essential for multi-tenant GPU use, even under a single compositor.*

---

## Open invariants / cross-subsystem hazards

**`drivers/gpu/` ↔ `io/` IOMMU group assignment.** P2P DMA between NIC and GPU requires both to be in the same IOMMU group, or the IOMMU must allow peer transactions. `io/` manages IOMMU groups (`io/` §... IOMMU-group coordination). The GPU driver spec assumes `io/` makes P2P work — but `io/` may legitimately refuse if the topology doesn't support it. There is no defined protocol for the GPU driver to query P2P availability from `io/` before attempting it. This is a silent failure mode.

**`drivers/gpu/` ↔ `memory/` domain budget.** As with all drivers, the GPU needs a dedicated domain. But a GPU in P2P DMA mode also needs the buffers it targets to be accessible from *its* IOMMU context, which may require those buffers to be mapped in the GPU's domain. If the page cache (in `filesystem/`) or the NIC receive path holds those buffers in their respective domains, and the GPU needs read access, there is a multi-domain access problem that the "one driver, one domain" model doesn't cleanly handle. Narf-Ring ownership transfer is the designed solution — but the GPU's command buffer system would need to take ownership of each buffer before submission, then return it on completion. This has high overhead for a GPU that processes thousands of draw calls per frame.

---

## Additional opinionated commentary

The GPU driver is the single biggest threat to NARF's clean capability model. Every other driver in Stage 4 (NVMe, NIC) has a clear owner-per-buffer model. The GPU fundamentally does not: it scatters writes across framebuffers, texture memory, depth buffers, and vertex buffers, all from a single command stream. Forcing ownership transfer for every buffer reference would make the GPU slower than software rendering. NARF needs to decide, before Stage 4, whether the GPU gets a "trusted bulk-DMA" carve-out (a larger IOMMU-bounded region the driver owns entirely for the duration of a frame), or whether command-buffer validation enforces per-access caps. The former is pragmatic and correct; the latter is beautiful and impractical for a real GPU.
