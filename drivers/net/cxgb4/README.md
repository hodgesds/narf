# drivers/net/cxgb4 — Chelsio T4/T5/T6 NIC

Placeholder only. `cxgb4.rs` is a stub: `register_pci_driver` prints
a registration line and the file notes itself as a placeholder for an
actual PCI match (vendor `0x1425`). There is no probe, no register
programming, and no TX/RX path — the driver for the Chelsio Terminator
10/40GbE adapters is still to be written.

- Spec: [drivers/net specification](../specification/spec.md)
