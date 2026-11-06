# drivers/net/e1000 — Intel 8254x/8257x Gigabit NIC

The reference dual-build driver for the Intel 8254x (e1000) and
8257x (e1000e) families, which share enough register layout for one
driver with a probe-time discriminator. `e1000.rs` resets the device,
reads the MAC from RAL/RAH, allocates TX/RX descriptor rings, and
brings the link up, trying MSI-X first, then legacy INTx, then polled
completion. It is also the reference for the parent README's
facade-feature rules (the default feature claims its PCI IDs
built-in; `e1000-module-only` suppresses that claim).

Unlike its sibling crates, the module build here is not
registration-only: `module_probe.rs` proves a `.ko` can drive real
hardware through the device datapath C-ABI, installing copy-mode DMA
rings and driving RX/TX from task-context IRQ/poller callbacks.

- Spec: [drivers/net specification](../specification/spec.md)
- Research: [drivers/net research](../research/README.md)
