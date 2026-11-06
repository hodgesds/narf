# drivers/net/i40e — Intel Ethernet 700-series NIC

Driver for the Intel X710 / XL710 / XXV710 / X722 40GbE family. Unlike
the register-poked Intel drivers, the 700 series is driven through
firmware: `i40e.rs` talks to the device over the Admin Transmit/Receive
Queues, with the supporting modules in `i40e/` — `hmc.rs` (Host Memory
Cache backing the LAN queues), `vsi.rs` (the switch element a queue
set belongs to), `ring.rs`, `rss.rs`, `offload.rs` (checksum/TSO),
`interrupts.rs`/`irq.rs` (MSI-X routing), and `runtime.rs` (interface
ownership and PF recovery). The file notes verification against a
Minisforum MS-03 carrying a dual-port X710.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [drivers/net specification](../specification/spec.md)
