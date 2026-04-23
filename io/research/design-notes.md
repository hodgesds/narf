# io — Design Notes

> Author: AI design review. Created 2026-04-22.

---

## Load-bearing decisions

1. **IOMMU is mandatory; hard fail on absence.** Spec §2 states "fail if not" present. This is the correct position for a security-oriented OS, but the failure mode is silent in the spec: a boot-time panic before drivers initialize is the right outcome. The fail-path needs to be described so `arch/` and `boot/` know where to invoke it.

2. **One IOMMU domain per driver.** Derived from both VT-d (summaries/intel-vt-d-iommu.md) and AMD-Vi (summaries/amd-iommu-vi.md) guidance. The CPU-domain ↔ IOMMU-domain correspondence (spec §4) is load-bearing: a bug in either side that misaligns them allows a driver to DMA outside its PKS domain. This correspondence is asserted but the enforcement mechanism (who checks the alignment at bind time) is unstated.

3. **`DmaBuffer<T>` is the exclusive DMA primitive; no raw physical address escapes to drivers.** This is the right type-system move. But the current interface `alloc_dma<T>(n: usize, dev: &BusDevice)` returns a buffer already bound to `dev`. This means `io/` must hold a reference to the device's IOMMU context at allocation time — creating a lifecycle dependency between the buffer and the device that must survive capability revocation of the device handle.

4. **P2P DMA crosses IOMMU context boundaries by design.** `map_p2p` creates a mapping from the source device's IOVA space to the destination device's BAR. This is the *only* approved cross-domain data flow that isn't a Narf-Ring (noted in `summaries/linux-p2pdma.md`). It must be flagged in `security-model/` explicitly; ACS disable decisions are capability-gated and irreversible for the lifetime of the P2P binding.

5. **DMA buffer drop = IOMMU unmap then physical free (order matters).** Spec §4 states the order. The IOTLB invalidation required after IOMMU unmap must complete before the physical frame is returned to the buddy allocator. On VT-d this requires an explicit IOTLB invalidate command and a completion poll; the spec does not say who waits for the invalidation to complete or how `memory/` is notified that the frame is safe to reuse.

---

## Divergences from precedent

**vs. Linux:** Linux's DMA API is ancient and multi-layered (SWIOTLB bounce buffers, dma-direct, IOMMU domain per-group). NARF's `DmaBuffer<T>` is simpler and safer by construction — no bounce buffers, no SWIOTLB fallback, one domain per driver. The cost: NARF has no path for devices that do not support 64-bit DMA addressing (older PCIe devices with 32-bit DMA masks). This matters less on server platforms but should be a stated non-goal rather than a silent gap.

**vs. seL4/CAmkES:** seL4 allocates DMA frames from a specific capability-gated "untyped" region and relies on IOMMU capabilities per-device configured at system init. NARF's design is similar in spirit but adds the runtime `alloc_dma` call, which means IOMMU mapping changes during runtime — seL4 components typically negotiate this at init. NARF's runtime approach is more flexible but creates more IOTLB churn.

**vs. Fuchsia:** Fuchsia's BTI (Bus Transaction Initiator) objects are the direct equivalent of NARF's `Cap<BusDevice, Dma>`. Fuchsia also has PMT (Pinned Memory Tokens) which pin pages for DMA duration and unpin on drop — very close to `DmaBuffer<T>`. The key difference: Fuchsia's IOMMU integration is deeper (btidispatch, IOMMU domains per-process), while NARF collapses the IOMMU domain and the PKS domain into a single concept.

**vs. Redox:** Redox's `xhci` DMA handling is ad-hoc per-driver without a central DMA abstraction. NARF's central `io/` crate is clearly superior and worth the design cost.

**P2P DMA vs. Linux's `pci_p2pdma`.** Linux P2PDMA exposes topology via `pci_p2pdma_distance()` and uses the ZONE_DEVICE page model. NARF's `map_p2p` is simpler (no ZONE_DEVICE equivalent), which is correct for Stage 3, but `summaries/lwn-p2pdma-corbet.md` flags a critical invariant NARF must not miss: **provider removal must be synchronous across all clients** — capability revocation must broadcast explicit notification, not rely on reference counting alone. This is not in NARF's current `io/` spec.

---

## Proposed spec changes

- §2 Assumptions: **Add** "IOMMU presence is verified at boot by `arch/`; if absent, `frame/` panics before any driver is loaded." Currently implicit; needs to be explicit so `arch/` knows to provide the check.

- §3 Public interface: **Add `unmap_p2p(binding: P2pBinding)` and document the quiescence protocol** — currently `map_p2p` returns a binding handle but there is no revocation path. P2P revocation must: (1) notify both drivers' domains, (2) invalidate both sides' IOMMU TLBs, (3) wait for in-flight DMA to complete (a device activity timeout or IOMMU drain), then (4) release the binding. This sequence should be at least sketched in §3.

- §3 Public interface: **Expose `iommu_fault_handler(dev: &BusDevice, fault: IoFault)` as a callback slot** — both VT-d and AMD-Vi have hardware fault logs (summaries/intel-vt-d-iommu.md, summaries/amd-iommu-vi.md). Who drains the fault log, and what happens on a fault, is unspecified. A driver that generates repeated IOMMU faults must be isolated or killed; the hook needs to exist even if Stage 3 just logs and Stage 4 terminates the driver.

- §4 Invariants: **Add** "CPU-domain ↔ IOMMU-domain correspondence is enforced at `alloc_dma` call time by verifying that `dev`'s IOMMU domain ID equals the calling domain's `DomainId`; a mismatch is a panic." Without this runtime check the correspondence is an aspirational invariant, not an enforced one.

- §4 Invariants: **Add** "IOTLB invalidation for `DmaBuffer` drop completes before `PhysFrame` is returned to `memory/`." Specify the completion mechanism: VT-d uses `IOTLB_INVALIDATE` command + `poll IOTLB_CTRL.IVT bit`; SMMUv3 uses a `CMD_TLBI_*` command + `CMD_SYNC` polling `GEVENTQ_BASE.ERR`.

- §5 aarch64: **Add** "SMMUv3 StreamID discovery is via ACPI IORT; NARF's `bus/` subsystem provides StreamID lookup by BDF. Non-coherent DMA paths require `DC CIVAC` cache-line invalidation before buffer handoff to the device and after device completion, owned by the `DmaBuffer<T>` type's lifecycle methods." Currently the spec notes the coherency requirement but does not assign ownership.

- §8 Open questions: **Add** "ACS disable is a one-way security downgrade. Document the policy: who holds `Cap<Bus, ReconfigureAcs>`? Is it revocable? Does revoking it re-enable ACS (would that break live P2P bindings)?" This is the most security-sensitive decision in `io/`.

---

## Open invariants / cross-subsystem hazards

**io ↔ capabilities §3 (cap revocation):** When `Cap<BusDevice, Dma>` is revoked, all `DmaBuffer<T>` instances bound to that device must be invalidated. The spec says the buffer is pinned for its lifetime — but whose lifetime governs when the capability is revocable? If a driver holds a `DmaBuffer` but its `Cap<BusDevice, Dma>` is externally revoked (e.g., device hotplug removal), the in-flight DMA is a use-after-revoke. `capabilities/` revocation protocol must quiesce the DMA before releasing the capability.

**io ↔ memory §3 (physical allocation):** `alloc_dma` calls `memory::alloc_frame()` for physically contiguous memory. The spec says `memory/` provides this, but NUMA locality for DMA buffers is an open question in `io/` §8. On x86_64 servers, DMA to a remote NUMA node's memory through an IOMMU has measurable latency penalties. The `alloc_dma` API should accept a NUMA hint, and `memory/` needs to expose one.

**io ↔ bus §3 (P2P topology):** `map_p2p` needs a topology oracle equivalent to Linux's `pci_p2pdma_distance()`. That oracle lives in `bus/` (it knows the PCIe hierarchy). `io/` spec §3 calls `map_p2p(src, dst, buf)` without specifying where topology validation occurs. This should be a `bus/` call inside `io/`, with `io/` refusing to create the mapping if `bus/` reports incompatible topology (different root complexes, ACS-blocking bridge in path).

**io ↔ drivers §3 (fault notification):** IOMMU fault handling (unspecified in `io/`) must notify the driver domain, which lives in `drivers/`. The notification mechanism is either a Narf-Ring message (Stage 3) or a kernel callback (Stage 2). At Stage 2, with drivers in the framework but Narf-Ring not yet live, the fault path needs a temporary callback mechanism. This gap needs bridging in the Stage 2/3 transition plan.

---

## Additional opinionated commentary

The spec's treatment of non-coherent DMA on aarch64 is dangerously thin. On server-class Arm (Ampere Altra, AWS Graviton), devices behind SMMUv3 are typically coherent. But on embedded Arm and lower-end SoCs, non-coherent DMA is common. The `DmaBuffer<T>` type should encode coherency as a type parameter or const generic: `DmaBuffer<T, Coherent>` vs. `DmaBuffer<T, NonCoherent>`. The latter would enforce cache maintenance operations in its `Drop` and before any CPU read of the buffer. This is not merely a performance concern; a `DmaBuffer` that received DMA into cache-line-dirty CPU memory silently delivers stale data.

The "IOMMU is mandatory" decision will bite on some real hardware: many embedded aarch64 boards (Raspberry Pi 4/5, various Rockchip/Allwinner SoCs) have no SMMU or a non-compliant one. If NARF ever targets that tier, the hard-fail boot will exclude them entirely. This is probably correct for a security-first OS, but should be a stated design boundary, not an oversight.
