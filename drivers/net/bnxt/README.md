# drivers/net/bnxt — Broadcom NetXtreme-C/E NIC

Early bring-up only for the Broadcom BCM573xx/BCM574xx/BCM575xx
series. `bnxt.rs` maps BAR0, reads the version register, asserts a
MAC reset and polls for it to clear; `register_pci_driver` matches a
single device, the BCM57414. There is no TX/RX path, no `HwNic`
implementation, and probe notes it would normally register with the
net registry — the datapath is still to come.

Dual-build: the built-in build compiles the driver in `bnxt.rs`; the
`.ko` build registers through the `narf_register_pci_driver` KSYMTAB
export and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
