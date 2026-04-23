# bus — Device Enumeration

Produces the devices that `drivers/` consumes. PCIe via ECAM, MMIO
bus via devicetree or ACPI MCFG, hot-plug notifications. Runs once
at boot to discover, and stays alive to observe device arrival
(hot-plug, Thunderbolt, virtio-mmio injection).

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 2 (PCIe + MMIO scan) → 3 (hot-plug events, MSI-X allocation).
