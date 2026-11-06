# drivers/net/tg3 — Broadcom Tigon3 Gigabit NIC

Driver for the Broadcom Tigon3 (BCM57xx) NetXtreme family. `tg3.rs`
covers PCI probe, BAR0 mapping, MAC address read, MII/PHY link-state
refresh, and TX/RX descriptor rings with checksum and TSO descriptor
formats, and implements `HwNic` with netdev publication through
`narf-drivers-net-core`. The transmit path programs TX descriptors;
the mailbox doorbell write is still a Stage-3 item per an inline
comment (the file header's Stage-0 scope line predates the rings).
The register layout is cited from the Linux tg3 driver.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
