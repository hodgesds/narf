# drivers/net/igb — Intel I210/I211/82576/I350 Gigabit NIC

Driver for the Intel I210 / I211 / 82576 / I350 1 GbE family. `igb.rs`
shares the Foxville/82575+ advanced-descriptor datapath that `igc`
implements (advanced one-buffer RX, advanced TX data/context
descriptors, per-queue `SRRCTL`, the `0x1500` extended MSI-X block);
its functional delta vs igc is the per-queue `TXDCTL`/`RXDCTL` ENABLE
handshake, gating each queue's DMA engine until the chip reflects the
enable. `igb/vmdq.rs` holds the SR-IOV/VMDq pool support, and the
crate implements `HwNic`.

Dual-build: the built-in build compiles the real driver; the `.ko`
build registers through the `narf_register_pci_driver` KSYMTAB export
and is registration-only until the device datapath ABI lands.

- Spec: [`../specification/igb.md`](../specification/igb.md) ·
  [drivers/net specification](../specification/spec.md)
