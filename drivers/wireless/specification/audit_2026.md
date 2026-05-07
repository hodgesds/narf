# 2026 WiFi-driver clean-room audit

> Status: reference document. Records what is and isn't publicly
> documented for the modern WiFi families we have or might want.
> Updated when a vendor publishes new material or when a tracked
> chip's documentation status changes.

A targeted web search in 2026 looked for *any* public, non-GPL,
non-NDA register- / firmware-command-level documentation for the
modern WiFi flagship families. The findings drive the per-driver
scope decisions captured here.

## Summary

| Family                                    | Verdict                              | Realistic scope                       |
| ----------------------------------------- | ------------------------------------ | ------------------------------------- |
| **Infineon CYW43439 (Pico W)**            | **Public datasheet + AN232689**      | **Full driver feasible**              |
| **Atheros AR9170 USB**                    | **Public + carl9170fw with docs**    | **Full driver feasible**              |
| Atheros AR9300 family (9285/9287/9462/...) | Reference manuals leaked-NDA only    | PCI-ID match table only               |
| Intel iwlwifi (AX200/210/BE200)           | Blob — no register / FW-API docs     | PCI-ID match table only               |
| MediaTek MT76xx / MT79xx                  | Source GPL-2.0 (mt76); no datasheet  | PCI-ID match table only               |
| Broadcom FullMAC (BCM43xx, BCM4377/4387)  | Blob; ABI only inside GPL brcmfmac   | Stub                                  |
| Qualcomm WCN3990 / WCN6855 (ath11k)       | Blob; WMI inside GPL ath11k          | BHI presence check + ID table         |
| Realtek RTL88xx WiFi                      | Blob; H2C/C2H inside GPL rtw89       | PCI-ID match table only               |
| Marvell 88W8997 / 88W8997                 | Product brief only; ABI inside mwifiex | PCI-ID match table only             |
| Espressif ESP32 WiFi (silicon-side)       | TRM redacts the WiFi MAC             | Consume Apache-2.0 ESP-IDF APIs       |

(Distinct from the WiFi list, the wired-Ethernet Realtek RTL8125 /
RTL8169 family is fully documented and we have a working clean-room
driver for it at `drivers/net/src/rtl8125.rs` + `drivers/net/src/r8169.rs`.)

## Per-family detail

### Infineon CYW43439 (Pico W) — the bright spot

Infineon's public **88-page datasheet** (Rev. 03 / v05_00) covers
pinout, gSPI / SDIO host interface electrical and protocol, the
F0/F1/F2 SDIO function model, the backplane access primitives, and
the chip-RAM upload procedure. **AN232689 — Wi-Fi Software User
Guide** documents the higher-level firmware command conventions a
host driver speaks across the link. The IOCTL / IOVAR command
numbering used inside the firmware itself is mirrored by two
permissively-licensed reference drivers (`soypat/cyw43439`, MIT;
Embassy `cyw43`, Apache-2.0 / MIT) which were written from public
docs and explicitly avoid GPL Linux derivation.

**Action:** stub landed at `drivers/wireless/src/cyw43439/`; spec
at `drivers/wireless/specification/cyw43439.md`. Stage 1 module
+ reference set in place, transport bring-up tracked as future
stages.

### Atheros AR9170 USB — already on path

Atheros released the AR9170 firmware under GPL-2.0 *with
documentation* of the host ↔ firmware command interface, via
`chunkeey/carl9170fw`. Together with the public USB descriptor
data this makes AR9170 USB a fully buildable Atheros target.

**Action:** existing `drivers/net/src/atheros.rs` covers the ID
table + register-block constants. The carl9170fw documentation is
now cited in the spec.

### Atheros AR9300 family — leaked-only

The "AR93xx ART2 Reference Guide" and "AR9300 EEPROM
configuration" PDFs that surface on Scribd / GitHub mirrors are
**leaked NDA documents**. They are not safe to use. The AR9300
family driver scope therefore stops at the PCI ID match table.
The Linux `ath9k` source is GPL-2.0 and is not consulted.

### Intel iwlwifi (AX200 / AX201 / AX210 / AX211 / BE200)

Intel publishes no register manual, no NVM section format spec,
no CSR/UREG bitfield table, and no MVM ucode ABI document for any
part in the AX family. Firmware ships as signed blobs only. The
upstream Linux driver under `drivers/net/wireless/intel/iwlwifi`
is GPL-2.0; the Fuchsia / Zircon `third_party/iwlwifi` port reads
from that source so it is not a clean-room reference either.

**Action:** existing `drivers/net/src/iwlwifi.rs` ID-table-only
stub remains the right scope; spec doc updated with the audit
finding.

### MediaTek MT76xx / MT79xx

MediaTek publishes no datasheet for any MT76xx / MT79xx part.
The upstream OpenWrt mirror at `github.com/openwrt/mt76` is GPL-
2.0. Parts of `git01.mediatek.com/openwrt/feeds/mtk-openwrt-feeds`
are dual-licensed but the file-level header check needed to use
any specific section in a clean-room build has not been done.

**Action:** the existing `drivers/wireless/src/mt7921/mod.rs`
file is **demoted** to ID-table-only. The CONNAC2 register
constants present in the file are not validated against any
authoritative datasheet; they were drafted from MediaTek
marketing collateral plus 802.11ax framing conventions and are
flagged as such in the module-level doc-comment. Any further
work on this driver is blocked on a public spec or a permissively-
licensed datasheet release. (See the v0.2 provenance note in
`drivers/wireless/specification/mt7921.md`.)

### Broadcom / Cypress FullMAC (BCM4356..BCM4387)

Broadcom / Cypress publish firmware blobs for `brcmfmac`. The
host ↔ firmware ioctl protocol — BCDC framing, `wlc_ioctl` IDs,
event TLV format — is documented only inside the GPL `brcmfmac`,
`bcmdhd`, and AOSP source trees. The BCM4377 / BCM4387 (Apple T2
/ M1 series) parts add an Apple-specific PCIe shared-memory
protocol documented only in Asahi Linux GPL-2.0 patches.

**Action:** no narf driver. Stub or stay-out.

### Qualcomm WCN3990 / WCN6855 (ath11k / ath12k)

Qualcomm publishes firmware via CodeLinaro
(<https://git.codelinaro.org/clo/ath-firmware/ath11k-firmware>)
but no register or WMI documentation. The WMI command-set TLV
definitions live in the GPL-2.0 `ath11k` / `ath12k` Linux source.

**Action:** existing `drivers/net/src/qcnfa765.rs` BHI presence-
check plus PCI ID match remains the right scope; spec / module
comment updated with the CodeLinaro note.

### Realtek RTL88xx (Wi-Fi)

Note: this is a *separate family* from the wired-Ethernet
RTL8125 / RTL8169 chips for which we have a clean-room driver.
The Wi-Fi RTL8821CE / RTL8822BE / RTL8822CE / RTL8852AE / RTL8852BE
parts have no datasheet equivalent to the RTL8125 wired one. The
"RTL8852AE Linux driver" tarballs Realtek distributes through
Lenovo / Dell / HP product pages are themselves GPL-2.0. The H2C
/ C2H command format and MAC core register map for the 8852 family
come from the GPL `rtw89` source.

**Action:** no narf driver. The RTL8125 / RTL8169 wired driver is
unaffected.

### Marvell 88W8897 / 88W8997 (Steam Deck, Surface)

NXP (current Marvell-WiFi owner) publishes a one-page product
brief; the host-command spec lives only in GPL `mwifiex`.

**Action:** no narf driver.

### Espressif ESP32 WiFi (silicon-side)

The ESP32 / ESP32-C3 / ESP32-S3 Technical Reference Manuals
document every peripheral register-by-register *except* the WiFi
/ Bluetooth MAC, which is intentionally redacted ("WiFi MAC and
Baseband: refer to libnet80211 / libphy"). The libnet80211 /
libphy / libpp blobs ship with ESP-IDF under Espressif's
permissive license, but the hardware register interface is
undocumented.

**Action:** if narf ever wants ESP32 WiFi, the architecture is to
**consume the Apache-2.0 ESP-IDF API** (`esp_wifi.h`) rather than
write a register-level driver. Do not attempt a clean-room rewrite.

## Source references

- `chunkeey/carl9170fw` — <https://github.com/chunkeey/carl9170fw>
- Intel AX210 firmware — <https://www.intel.com/content/www/us/en/products/sku/204836/intel-wifi-6e-ax210-gig/downloads.html>
- ath11k-firmware (CodeLinaro) — <https://git.codelinaro.org/clo/ath-firmware/ath11k-firmware>
- Marvell 88W8997 product brief — <https://www.marvell.com/content/dam/marvell/en/public-collateral/wireless/marvell-wireless-88w8997-product-brief-2019-07.pdf>
- Infineon CYW43439 datasheet — <https://www.infineon.com/part/CYW43439>
- soypat/cyw43439 (MIT, clean-room friendly) — <https://github.com/soypat/cyw43439>
- ESP-IDF WiFi API — <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/network/esp_wifi.html>
