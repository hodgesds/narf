# drivers/wireless/mt76 — MediaTek CONNAC2/CONNAC3 Wi-Fi

`narf-drivers-wireless-mt76` is the MediaTek CONNAC2/CONNAC3 Wi-Fi driver
for MT7921 / MT7922 / MT7961 / MT7920 and MT7925, promoted from the former
`drivers/wireless/src/mt7921/` module. MT7925 code is present, but the
probe's chip-id gate (`src/mt7921/pci.rs`) still refuses MT7925 silicon.
It is dual-build: built in through the `narf-drivers-wireless` umbrella
(default `builtin` feature) or as `mt76.ko` (`--no-default-features
--features module`).

The real driver is `src/mt7921/` (L1 remap, MCU framing, WFDMA rings,
firmware download, association and scan), with `src/iface.rs`
providing the `WirelessNetIface` station interface (`iface_station.rs`,
`iface_sched_scan.rs`) plus AP, P2P, monitor, and WoWLAN variants
(`iface_ap.rs`, `iface_p2p*.rs`, `iface_monitor.rs`, `iface_wowlan.rs`).
The driver reaches the kernel only through `src/platform/`: the kernel
crates built in, `narf-module-rt` plus the KABI in the `module` build. As
`mt76.ko` the same driver runs inside the module: `src/mt7921/pci_kabi.rs`
binds the function and `src/iface_module.rs` publishes the station netdev
and wiphy through the generic `WIFI` family host (wireless spec §4.4). The
CONNAC3-specific UNI layer lives in `src/mt7925/` (`mcu.rs`) and the MLD
station lifecycle in `src/mt7921/mlo.rs`, documented in
[`src/mt7925.md`](src/mt7925.md); the shared probe, BAR/L1 windows,
WFDMA and firmware transport in `src/mt7921/` select on the PCI id. The
private copy-mode family (`src/module_protocol.rs` / `src/module_host.rs`)
stays registered in the built-in build for compatibility; no in-tree `.ko`
uses it.

Hardware validation is gated by the crate's own documentation: QEMU
emulates no MediaTek Wi-Fi PCIe device, so chip-id read, firmware
download, and association cannot run here. Validation so far is dual
builds, command fixtures, native descriptor models, retained
station/reset ownership tests on both architectures, and the
`modules/e2e/mt76` load/claim/unload test of the real `.ko` — not RF
acceptance.

- Spec: [`../specification/mt7921.md`](../specification/mt7921.md)
- Research: [`../research/chip-inventory-mt76-fullmac.md`](../research/chip-inventory-mt76-fullmac.md)
