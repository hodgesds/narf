# drivers/net/rtl8139 — Realtek RTL8139 NIC

Clean-room driver for the Realtek RTL8139 10/100 Mbps PCI NIC, from
the public Realtek programming guide — and the crate QEMU emulates
with `-device rtl8139`. `rtl8139.rs` brings the chip out of reset
(CONFIG1 unlock, CR.RST), reads the MAC from IDR0..5, installs a
64 KiB cyclic RX ring and four 2 KiB TX buffers, and implements
`transmit`, RX drain, link status, and `HwNic` with netdev
publication through `narf-drivers-net-core`.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
