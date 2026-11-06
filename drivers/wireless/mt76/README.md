# drivers/wireless/mt76 — MediaTek CONNAC2 Wi-Fi

`narf-drivers-wireless-mt76` is the MediaTek CONNAC2 Wi-Fi driver for
MT7921 / MT7922 / MT7961 / MT7920, promoted from the former
`drivers/wireless/src/mt7921/` module. It is dual-build (built-in or
loadable `.ko`).

The real driver is `src/mt7921/` (L1 remap, MCU framing, WFDMA rings,
firmware download, association and scan), with `src/iface.rs`
providing the `WirelessNetIface` station interface plus AP, P2P,
monitor, and WoWLAN variants (`iface_ap.rs`, `iface_p2p*.rs`,
`iface_monitor.rs`, `iface_wowlan.rs`). The `module` build owns
probe/service/control handles and a domain-gated poller through the
versioned copy-mode C ABI in `src/module_protocol.rs` /
`src/module_host.rs`; native MCU/WFDMA execution remains in the
permanent host build.

Hardware validation is gated by the crate's own documentation: QEMU
emulates no MediaTek Wi-Fi PCIe device, so chip-id read, firmware
download, and association cannot run here. Validation so far is dual
builds, command fixtures, native descriptor models, and retained
station/reset ownership tests on both architectures — not RF acceptance.

- Spec: [`../specification/mt7921.md`](../specification/mt7921.md)
- Research: [`../research/chip-inventory-mt76-fullmac.md`](../research/chip-inventory-mt76-fullmac.md)
