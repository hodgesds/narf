# drivers/net/realtek — Realtek r8169/RTL8125/RTL8126/RTL8127 NIC family

One crate for the whole Realtek PCIe family, because the drivers form
a dependency chain (`rtl8127` → `rtl8126` → `rtl8125` → `r8169`)
sharing the `rtl_phy` helpers — in-crate references instead of four
separate crates. Each driver still registers its own PCI matches and
implements `HwNic`: `r8169.rs` (RTL8168/RTL8111, the most complete
cut, with TX checksum/TSO, VLAN insertion, RX checksum decode, jumbo
rings, WoL, and EEE), `rtl8125.rs` (2.5 GbE), `rtl8126.rs` (5 GbE),
and `rtl8127.rs` (10 GbE, including the RSS register model). Shared
code lives in `features.rs` (one feature model for the family),
`phy_access.rs`, and `rtl8168.rs` (per-revision PHY init tables).
The parent README's `r8169` and `rtl8125` rows both describe drivers
in this crate.

Dual-build: the built-in build compiles the real drivers; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
