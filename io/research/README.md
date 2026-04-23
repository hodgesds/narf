# io — Research

## Primary sources

- **Linux P2PDMA documentation** — kernel-of-record for P2P DMA
  mechanics. <https://docs.kernel.org/driver-api/pci/p2pdma.html>
- **Intel VT-d architecture specification**.
  <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-virtualization-technology-for-directed-io-architecture-specification.html>
- **AMD I/O Virtualization Technology (AMD-Vi) specification**.
  <https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/specifications/48882_3_10_IOMMU.pdf>
- **Arm SMMUv3 Architecture Specification (IHI 0070)**.
  <https://developer.arm.com/documentation/ihi0070/latest/>
- **PCIe Base Specification 6.x** — ACS, ATS, PRI chapters.

## Secondary sources

- **Linux `drivers/iommu/intel/*`** — Intel IOMMU reference.
- **Linux `drivers/iommu/arm/arm-smmu-v3/*`** — SMMUv3 reference.
- **"LWN: Preparing for peer-to-peer DMA"** (Jonathan Corbet).
  <https://lwn.net/Articles/767281/>
- **Redox `xhci` driver + DMA abstractions** — Rust precedent.

## Distilled summaries

- [`summaries/linux-p2pdma.md`](./summaries/linux-p2pdma.md) — kernel
  P2P DMA concepts, ACS requirements, topology constraints.

## Fetched this round

### 2026-04-22

- `summaries/intel-vt-d-iommu.md` — Intel VT-d DMA isolation, IOVA translation, fault handling
- `summaries/amd-iommu-vi.md` — AMD-Vi isolation, event logging, coherency management
- `summaries/arm-smmuv3.md` — Arm SMMU, stream tables, per-device isolation
- `summaries/lwn-p2pdma-corbet.md` — P2P provider/client architecture, topology validation

## Open research questions

- SR-IOV and how it interacts with per-driver IOMMU contexts.
- Whether to use the IOMMU's own address space or shared IOVA.
- CXL implications for long-term memory / device architecture.
