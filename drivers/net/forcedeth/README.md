# drivers/net/forcedeth — NVIDIA nForce Ethernet controller

Driver for the Ethernet MAC integrated into the NVIDIA nForce MCP
(nForce through nForce 6xx/7xx), exposed as a PCI device. The whole
crate is `forcedeth.rs`: probe, TX/RX with checksum and TSO
descriptor formats, link-state refresh, and IRQ acknowledgement, plus
a `HwNic` implementation with netdev publication through
`narf-drivers-net-core`. The register names come from the Linux
forcedeth driver — the file notes the chip is otherwise undocumented
and every register name originates with that reverse-engineered
driver.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
