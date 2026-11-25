# drivers/wireless — Wi-Fi Device Drivers

`drivers/wireless/` holds the concrete Wi-Fi chip drivers that back the
wireless core. Where `wireless` (`narf-wireless`) defines the
vendor-neutral 802.11 control plane, these crates talk to real radios —
mapping the core's scan/associate/configure requests onto device
registers, DMA rings, and firmware, and feeding received frames back up to
`narf-net`. Each driver registers itself at init time (mostly Stage
`Subsys`) through the driver runtime so the bus layer can match it against
discovered hardware.

The drivers are split into per-family crates:

| Crate (directory) | Contents | Module |
| --- | --- | --- |
| `narf-drivers-wireless-iwlwifi` (`iwlwifi/`) | Intel Gen2 (AX200/AX201) and Gen3 (AX210/AX211/BE20x/BE21x) | `iwlwifi` |
| `narf-drivers-wireless-mt76` (`mt76/`) | MediaTek MT7921/MT7922/MT7961/MT7920; MT7925 code behind a closed chip-id gate | `mt76` |
| `narf-drivers-wireless-ath11k` (`ath11k/`) | Qualcomm ath11k: WCN6855 (module), QCA6390/QCN9074 and AHB SoCs (built in) | `ath11k` |
| `narf-drivers-wireless-ath10k` (`ath10k/`) | Qualcomm Atheros QCA988X–QCA9377 | `ath10k` |
| `narf-drivers-wireless-ath9k` (`ath9k/`) | Atheros AR5008, AR9002 and AR9003 softMAC | `ath9k` |
| `narf-drivers-wireless-brcm` (`brcm/`) | Broadcom `brcmfmac` PCIe (module) and Cypress/Infineon `cyw43439` SDIO/gSPI (built in) | `brcm` |
| `narf-drivers-wireless-rtl` (`rtl/`) | Realtek `rtlwifi` PCIe and `rtl8xxxu` USB | `rtl` |
| `narf-drivers-wireless-rtw` (`rtw/`) | Realtek `rtw88` and `rtw89`; the module carries the RTL8821CU/RTL8822BU USB path | `rtw` |
| `narf-drivers-wireless-core` (`core/`) | Shared helpers: `firmware_asset`, `future_heap`, `watchdog_work` | — |
| `narf-drivers-wireless-ath-core` (`ath-core/`) | Shared Atheros/Qualcomm PCI, regulatory, board and WMI NLO code | — |
| `narf-drivers-wireless-rtl-usb` (`rtl-usb/`) | Shared Realtek USB transport primitives and `RTL8XXXU_USB_IDS` | — |
| `narf-drivers-wireless-rtl-chip` (`rtl-chip/`) | Transport-agnostic Realtek register-programming core (`RegIo`) | — |
| `narf-drivers-wireless` (`src/`) | Umbrella: links every family built in, re-exports each driver module and registers the initcalls, rfkill and the mt76 system-PM bridge | — |

The eight driver crates are dual-build. With the default `builtin` feature
they link into the kernel through the umbrella crate. Built with
`--no-default-features --features module` (`cargo xtask build-module`),
the same source becomes a loadable `.ko` that reaches the kernel only
through `narf-module-rt` and the KABI (most crates through a `platform/`
layer, iwlwifi through `src/iwlwifi/module/`). Each module carries a subset of its built-in driver, mostly the
station path; the module contracts and their "not in the module" lists are
[`specification/spec.md`](./specification/spec.md) §4.1–§4.9. An umbrella
`<family>-module-only` feature (for example
`narf-drivers-wireless/ath11k-module-only`) leaves the built-in claim to a
loaded module. The `modules/e2e/*` kernel tests load each `.ko`, staged in
the test initramfs as `lib/modules/test-fixtures/<name>.ko.lz4`.

Attachment spans PCIe, SDIO, gSPI and USB, so the crates depend on the
corresponding NARF bus and transport crates (`narf-bus`, `drivers/sdio`,
`drivers/spi`, `drivers/usb`) alongside interrupts, memory, and firmware
loading.

A driver's job is the hardware boundary: self-loading firmware, setting
up the receive/transmit hardware queues (including mapping 802.11 access
categories to device rings), programming channels and PHY state, and
submitting or receiving management and data frames. The MLME and WPA
supplicant are intended to live in a userspace wireless daemon. Today each
driver (or FullMAC firmware) runs its station SME and WPA2/WPA3 supplicant
behind the core's wireless interface trait as an interim step. Built in,
nl80211 can also hand control to an external userspace SME; the module
family host (`WIFI` v2) does not carry that.

Drivers implement the core's wireless interface trait and register into
its registry, so from the rest of the kernel's perspective a probed
radio is just another 802.11 interface. The crates are `no_std`. Secret
material uses `zeroize`.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Feature ledger: [`research/remaining-features.tsv`](./research/remaining-features.tsv)
  (open) and [`research/implemented-pending-validation.tsv`](./research/implemented-pending-validation.tsv)
- Per-chip status and measured source footprint: [`research/chip-inventory.md`](./research/chip-inventory.md)
