# bus — Research

## Primary sources

- **PCIe Base Specification 6.x** — ECAM, capability lists, MSI-X,
  ACS, ATS, Native Hot Plug.
- **Devicetree Specification** (v0.4+).
  <https://www.devicetree.org/specifications/>
- **ACPI Specification** (MADT, MCFG, FADT, SRAT; DSDT/AML for later).
  <https://uefi.org/specifications>
- **Arm SystemReady** — the standardised aarch64 server/embedded
  platform assumptions.

## Secondary sources

- **Linux `drivers/pci/` + `drivers/of/`** — reference enumeration
  and devicetree matching.
- **U-Boot / EDK II PCIe scan paths** — simple readable implementations.
- **ACPICA** — canonical ACPI interpreter; reference if/when AML
  becomes needed.
- **`pci` and `virtio-mmio` crates (rust-osdev)** — Rust PCI config-
  space parsers.

## Distilled summaries

- (Add one for the ECAM walk when implementation begins — it's the
  single highest-value reference.)

## Fetched this round

- summaries/pcie-architecture.md — Point-to-point topology, lane negotiation, credit-based flow control, and power transients
- summaries/pci-config-space.md — Bus/Device/Function addressing, ECAM memory mapping, and capability linked lists
- summaries/iommu.md — Device address translation, per-device isolation contexts, and synchronous TLB invalidation

## Open research questions

- What fraction of x86_64 hardware really needs AML evaluation for
  NARF to function? (NUMA, thermal control may pull us in.)
- IOMMU-group enumeration quirks — historically Linux has a long
  list of per-vendor quirks; inherit them or re-derive?
- Hot-plug on aarch64 in practice — most servers use firmware-driven
  events; support matrix per platform.
