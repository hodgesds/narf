# drivers/net/atheros — Atheros/Attansic L1c/L2c Gigabit NIC

Clean-room wired driver for the Atheros AR81xx (atl1c) family — the
L1c/L2c chips on consumer laptops — re-targeted at the wired NIC
(the module path previously held an AR9xxx Wi-Fi stub). `atheros.rs`
covers probe, MAC programming, the TPD/RFD/RRS descriptor rings,
`transmit`/`receive`, IRQ enable/acknowledge, link refresh, and PHY
access over MDIO, and implements `HwNic` with netdev publication
through `narf-drivers-net-core`.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
