# drivers/bluetooth/btintel-pcie — Intel PCIe Bluetooth controller

Driver for the Intel Bluetooth controllers attached over PCIe (Lunar Lake
onward: BlazarI, Scorpius, Scorpius2). `btintel_pcie.rs` covers probe, CSR
access and MAC bring-up; `btintel_pcie/rings.rs` the TX/RX DMA rings and
context-information block; `btintel_pcie/fw.rs` the version-TLV parse and
firmware download; `btintel_pcie/transport.rs` the `HciTransport` that
registers with the `narf-bluetooth` host stack. x86_64 only (needs the PCIe
bus). The register layout is cited from Linux `drivers/bluetooth/btintel_pcie.c`.

Dual-build: the built-in build compiles the real driver; the `.ko` build
registers the same PCI ids through the `narf_register_pci_driver` KSYMTAB
export and is registration-only until the device datapath ABI covers an HCI
transport.

```
cargo narf build build-module --package narf-drivers-bluetooth-btintel-pcie \
  --no-default-features --features module
```

- Host stack spec: [bluetooth specification](../../../bluetooth/specification/spec.md)
