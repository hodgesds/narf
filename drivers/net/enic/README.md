# drivers/net/enic — Cisco VIC Ethernet NIC

Early bring-up only for the Cisco Virtual Interface Card (VIC),
typically found in UCS environments. `enic.rs` maps BAR0, issues a
firmware reset through the device-command register, and polls the
command status; `register_pci_driver` matches a single device, the
VIC. There is no TX/RX path, no `HwNic` implementation, and probe
notes it would normally register with the net registry — the datapath
is still to come.

Dual-build: the built-in build compiles the driver in `enic.rs`; the
`.ko` build registers through the `narf_register_pci_driver` KSYMTAB
export and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
