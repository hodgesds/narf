# Linux P2PDMA (Peer-to-Peer DMA)

**Primary source:** Linux kernel documentation
(`docs.kernel.org/driver-api/pci/p2pdma.html`), LWN "Preparing for
peer-to-peer DMA" (Corbet, 2018), PCIe Base Specification 6.x
(relevant chapters: ACS, ATS, root complex).

> Distilled for NARF design. Reading notes.

## What it is

P2PDMA lets one PCIe device DMA directly into another PCIe device's
memory (a BAR) without the data visiting host RAM. Canonical uses:

- NIC → GPU for ingest pipelines (camera / sensor feeds).
- NVMe → GPU for training / inference preload.
- NIC → NVMe for direct disk write of received data.

The CPU is uninvolved on the data path, which is exactly what NARF
wants from its "Hardware Bypass" column in `DESIGN.md`.

## Topology constraints

PCIe routing complicates things. Between peers:

- **Same root complex, through a switch:** P2P works natively if the
  switch supports it and ACS (Access Control Services) is configured
  to not redirect upstream.
- **Same root complex, through the root port:** P2P may or may not
  work; many older/server root complexes don't route peer traffic.
  Requires ACS settings allowing it (this is where Linux's `pci=noacs`
  or per-bridge ACS quirks come in).
- **Different root complexes:** essentially unsupported; data must
  bounce through memory.

Linux exposes `pci_p2pdma_distance()` to answer "can A and B peer?"

## ACS (Access Control Services)

ACS can block P2P by design (to stop rogue devices DMA-ing at each
other). Enabling P2P requires selectively disabling ACS on the bridges
in the path. Linux has a well-documented quirk framework for this
(`pci_dev_specific_acs_enabled`, kernel param `pci=disable_acs_redir`).

Security implication for NARF: ACS disable is a *reduction* in
isolation at the PCIe fabric level. Our IOMMU contexts per driver
mitigate this at the memory level, but we must document that P2P
peers' IOMMU contexts allow targeted DMA between them.

## Address translation: the IOVA question

P2P DMA targets go through the IOMMU on the DMA source. The source
device sees the destination's BAR via an IOVA the kernel has mapped
for it. Two subtleties:

- **IOVA vs bus address:** on some platforms the BAR's *bus* address
  is directly DMA-able; on others the IOMMU needs an explicit mapping.
  Linux uses `pci_p2pdma_map_sg()` to abstract this.
- **ATS (Address Translation Services):** devices can cache
  translations; for P2P this generally requires ATS on both peers so
  each knows where to send, with PRI for fault handling.

## Memory type

BARs mapped for P2P are typically Write-Combining or Uncacheable.
Device-to-device DMA accepts these natively; CPU reads are expensive
but infrequent.

## Why it matters for NARF

- `io/` must expose a `p2p_bind(src, dst, buffer)` API that:
  1. Verifies both devices belong to capability-holding drivers.
  2. Consults a topology oracle (equivalent to `pci_p2pdma_distance`).
  3. Configures both IOMMU contexts to allow the specific DMA.
  4. Returns a binding handle the source driver can submit against.
- ACS disable decisions are security-sensitive. Stage 3 spec should
  require a `Cap<Bus, ReconfigureAcs>` (or equivalent) to gate that
  operation so drivers don't unilaterally drop fabric isolation.
- NARF's domain model maps naturally onto "per-driver IOMMU context."
  Two P2P peers are in two different domains; the IOMMU config for
  each says "driver A's IOVA X aliases driver B's BAR Y." This
  cross-context mapping is the *only* cross-domain data flow that
  isn't a Narf-Ring — we should flag it in `security-model/`.

## aarch64 specifics

SMMUv3 handles P2P similarly; "peer-to-peer" traffic between PCIe
devices behind the same SMMU is mediated by the same StreamID logic.
Requires the SMMU to be configured to allow the routing.

## Open questions this raises for the NARF spec

- NUMA: P2P across NUMA nodes is frequently a disaster. Policy?
- Fault handling: a P2P transaction that faults (bad translation)
  generates a device error report. Who consumes it — the source
  driver, the destination, or `io/`?
- CXL: CXL.mem / CXL.cache change the P2P picture materially; we
  should note but not commit to a model pre-Stage-4.
