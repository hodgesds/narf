# atheros — AR9xxx / AR93xx Wi-Fi driver

Clean-room driver for the Atheros AR9285/AR9287/AR9280 PCIe family
and the AR9170 USB reference part.

## References (public-only)

All driver code is derived strictly from the references below.
**No GPL Linux `drivers/net/wireless/ath/`, vendor SDK, or any
non-public document was consulted.**

- **AR9285 Single-Chip 802.11n Single-Stream Solution** product
  brief — Atheros Communications. Public PCI vendor (0x168C) and
  device IDs published before the Qualcomm acquisition.
- **AR9170 USB 802.11n Reference Design** — Atheros, public USB
  vendor/device pairs and high-level register-block layout for the
  USB-attached part.
- **IEEE Std 802.11-2020** — frame layout the MAC speaks. Protocol-
  layer code lives in `narf-wireless`; this driver is the silicon
  bring-up.

## Scope

### Stage-1 (landed)

- PCI vendor + device IDs (AR9285 / AR9287 / AR9280).
- USB vendor + device IDs for the AR9170 reference dongle and
  Netgear WNDA3100.
- Register-block constants for the AR9285 MAC bring-up: reset
  control, sleep / wake, IRQ enable / status / mask / clear.
- `register_pci_driver()` + a Stage-1 `probe()` that records the
  matched part in the bound-driver registry.
- `mac_cold_reset_value()` / `default_intr_enable_value()` helpers
  composed from the public bit definitions.

### Deferred

- BAR0 mapping and the actual cold-reset / wake / IRQ-enable
  instruction sequence (needs `bus::map_bar` to land a stable cap).
- Baseband / radio calibration. Atheros publishes the register
  *names* but the calibration *data* is per-card EEPROM and lands
  with a board-data-blob loader.
- DMA descriptor encoding for RX / TX rings.
- AR9170 USB firmware loader — the firmware blob is freely
  redistributable (Atheros published it as part of the reference
  design) but the load path needs `narf-firmware` to grow a
  USB-bound consumer.

## Capability surface

The driver registers via `register_pci_driver()` (no-op USB shim
arrives once the USB driver framework grows a `register_usb_driver`
counterpart). At probe, the bus hands over a `Cap<BusDevice, Write>`
which gates BAR mapping + MMIO writes once the bring-up sequence
lands.
