# bus — Device Enumeration

Produces the devices that `drivers/` consumes. PCIe via ECAM, MMIO
bus via devicetree or ACPI MCFG, hot-plug notifications. Runs once
at boot to discover, and stays alive to observe device arrival
(hot-plug, Thunderbolt, virtio-mmio injection).

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: **Stage 2/3 landed (enumeration).** PCIe ECAM walker on
  x86_64 (q35 default `0xb000_0000`; MCFG deferred), FDT bus walker on
  aarch64 with a QEMU-virt fallback layout (32 virtio-mmio slots at
  `0x0A00_0000 + 0x200 × N`). `BusDevice` / `BusKind` / `DeviceId`,
  read-only registry, `claim_device` stub. Deferred to Stage 4:
  PCI-to-PCI bridge secondary/subordinate walk, FDT
  `#address-cells` / `#size-cells` respect, MCFG parsing, hot-plug
  events, MSI-X allocation, IOMMU-group coordination with `io/`.
