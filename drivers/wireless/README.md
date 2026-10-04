# drivers/wireless — Wi-Fi Device Drivers

`narf-drivers-wireless` holds the concrete Wi-Fi chip drivers that back
the wireless core. Where `wireless` defines the vendor-neutral 802.11
control plane, this crate talks to real radios — mapping the core's
scan/associate/configure requests onto device registers, DMA rings, and
firmware, and feeding received frames back up to `narf-net`. Each driver
registers itself at init time (Stage `Subsys`) through the driver
runtime so the bus layer can match it against discovered hardware.

The crate carries driver modules for the major Wi-Fi chip families seen
in Linux, in varying states of bring-up: Intel `iwlwifi` (AX210+
transport with an MLD station profile — the most developed path here,
implementing scan, RX/TX, data queues, and Open/WPA2-PSK association
inside the driver), Qualcomm Atheros `ath9k`/`ath10k`/`ath11k`,
MediaTek `mt76`/`mt7921`, Broadcom `brcmfmac` and the Cypress/Infineon
`cyw43439`, and Realtek `rtl8xxxu`/`rtlwifi`/`rtw88`/`rtw89`. Attachment
spans several buses — PCIe, SDIO, and USB — so the crate depends on the
corresponding NARF bus and transport crates (`narf-bus`,
`drivers/sdio`, `drivers/usb`) alongside interrupts, memory, and
firmware loading.

A driver's job is the hardware boundary: self-loading firmware, setting
up the receive/transmit hardware queues (including mapping 802.11 access
categories to device rings), programming channels and PHY state, and
submitting or receiving management and data frames. The MLME and WPA
supplicant are intended to live in a userspace wireless daemon; the
current iwlwifi path runs the station state machine inside the driver
behind the core's wireless interface trait as an interim step, which
should not be mistaken for a userspace supplicant.

Drivers implement the core's wireless interface trait and register into
its registry, so from the rest of the kernel's perspective a probed
radio is just another 802.11 interface. The crate is `no_std`. Secret
material uses `zeroize`.

- Spec: [`specification/spec.md`](./specification/spec.md)
