# drivers/net/ixgbe — Intel 82599/X540/X550 10 GbE NIC

Clean-room driver for the Intel 82599 / X540 / X550 / X550EM 10 GbE
family, from the public Intel datasheets. `ixgbe.rs` covers reset,
EEPROM MAC read, advanced TX/RX, and MSI-X, and implements `HwNic`;
the `ixgbe/` modules split the features — `queues.rs`, `regs.rs`,
`rxdesc.rs`, `rss.rs`, `vlan.rs`, `vmdq.rs`, `aci.rs`, `dcb.rs`,
`eee.rs`, `ethtool.rs`, `fcoe.rs`, `fdir.rs`, `hic.rs`, `pm.rs`, and
`wol.rs`.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [`../specification/ixgbe.md`](../specification/ixgbe.md) ·
  [drivers/net specification](../specification/spec.md)
