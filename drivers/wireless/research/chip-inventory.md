# Wi-Fi chip inventory and measured footprint

Snapshot: 2026-10-25 local / 2026-10-26 UTC, branch `codex/ath10k-active-scan`,
baseline `e8fe43e7b` plus the current implementation wave.

The registered-match audit covers all eleven driver families and **102 bus
identities**. That is a match-table count, including aliases and explicit
rejections, not 102 independent chips or 102 working radios. Per-board firmware,
RF/revision and capability discovery are still needed before claiming every
hardware-supported feature has been inventoried.

The earlier **570k production + 680k test / 1.25M additional Rust LOC** forecast
is withdrawn. Shared PHY, aggregation, roles, recovery and PM were charged in
both backend and chip work packages, and test allowances were not calibrated.
The per-chip findings remain useful; the numeric forecasts and derived
engineer-day totals have been removed. There is no defensible all-feature
completion date or percentage in this audit.

The inventory's WIP labels describe its inspection snapshot. Subsequent combined
validation of this wave passed 1887/0 fail/9 skip on x86_64 and
1417/0 fail/3 skip on aarch64, with clean production boots/btrfs postflights,
scoped production/kernel-test Clippy, workspace formatting and release/debug
builds on both architectures. No physical-card acceptance is claimed.

## Measured source

Measured with **tokei 15.0.0**. NARF has **316,060 Rust code lines in 755 files**
in these scopes, including tests, models, fixed reference vectors, hardware
tables, inactive helpers and uncommitted work. Comments, blanks and embedded
Markdown are excluded from code LOC. The [CSV](chip-inventory-loc.csv) contains
family totals; [JSON](chip-inventory-loc.json) records the exact input scopes and
the [file CSV](chip-inventory-loc-files.csv) retains every counted path.

The local Linux7.3.0-rc4 tree measures **1,061,776 C/header code lines** in the
corresponding broad driver directories and **115,304** in mac80211/cfg80211:
**1,177,080 total**. Generated `*.mod.c` is excluded.
[Linux measurement](chip-inventory-linux-loc.json) records scope and totals.
This is a directory footprint comparison: Linux supports additional unmatched
chips and buses, and both counts include tables. NARF's tests and model code
also make the figures unsuitable for a completion fraction.

| Scope | NARF Rust code LOC | Linux broad C/header code LOC |
|---|---:|---:|
| iwlwifi | 25,673 | 127,123 |
| ath11k | 78,324 | 65,089 |
| mt76 | 17,382 | 98,103 |
| rtw88 | 38,442 | 152,005 |
| rtw89 | 50,970 | 287,431 |
| rtlwifi | 14,509 | 145,325 |
| rtl8xxxu | 15,499 | 19,055 |
| ath10k | 22,584 | 65,633 |
| ath9k | 10,053 | 70,626 |
| brcmfmac | 11,219 | 31,386 |
| cyw43439 | 8,850 | shared above |
| shared | 22,555 | 115,304 |
| **Total** | **316,060** | **1,177,080** |

The Linux FullMAC row includes common Broadcom headers and covers both BCM and
CYW; it is counted once. The shared row compares the selected NARF wireless
core/fixture/Qualcomm helpers with mac80211/cfg80211, which are different scopes.
No inference of source equivalence or production-only size follows.

Reproduce NARF totals with `tokei --streaming json --types Rust <paths...>`;
the exact inputs are recorded per scope in JSON. Linux was counted with
`tokei --types C,'C Header' --output json <driver paths> <net paths>`, then
grouped by directory after removing generated module files. Public
`include/net/{mac80211,cfg80211}.h`, common ath helpers, brcmutil, bus, crypto
and platform layers are outside that Linux total.

## Per-chip evidence

Each inventory distinguishes committed code, current unvalidated work, native
model coverage and physical acceptance. It records PCI/USB/SDIO identities,
revision/firmware gates, reachable paths, missing features and shared packages.
A source declaration is not a physical measurement; an unknown firmware
capability is not evidence that the feature is inapplicable.

| Inventory | Registered identities | Main gaps |
|---|---:|---|
| [Intel / ath11k](chip-inventory-intel-ath11k.md) | Intel16 PCI + ath11k3 PCI refined into6 profiles | Intel Gen2 automatic data/security startup; exact non-Sc firmware ABIs; Intel wider PHY/roles/PM; QCN9074 native HAL/DP |
| [MT76 / FullMAC](chip-inventory-mt76-fullmac.md) | MT6 PCI + CYW2 SDIO + BCM26 PCI | MT BA/aggregation/HE/security/roles/PM; 23 BCM identities stop at discovery/parking; FullMAC vendor ABI/width/roles/reset/PM |
| [Realtek](chip-inventory-realtek.md) | 19 PCI +20 USB | Four narrow conditional station chains; other matched chips, richer PHY/security/roles, IRQ/recovery/PM; wrong USB mappings identified |
| [ath9k / ath10k](chip-inventory-qualcomm.md) | ath9k1 PCI + ath10k9 PCI | HT/VHT/aggregation, IRQ/recovery/PM/roles; AR9462 is an explicit wrong-driver rejection; catalog-only QCA9887 excluded |

These 102 identities include recognized devices that fail closed before
activation. Firmware catalog entries are not a second support count. Aliases
share implementation while requiring actual board qualification. Remaining
work is described by concrete package/driver paths rather than multiplying a
full-driver estimate by each marketing label.

## Planning and implementation order

Continue independent native feature packages in parallel: Intel Gen2 normal
data/controlled-port ownership; MT76 RX BA/reordering before TX aggregation;
RTL8821CE operating radio/packet/station after calibration and power. Root
coordinates shared APIs, Qualcomm work and combined gates.

A tighter time estimate needs a closed per-profile acceptance checklist and
measured implementation/review/integration cycles for representative aggregation,
new-chip startup and recovery tasks. Firmware/board inputs, IRQ/reset behavior
and hardware access remain separate dependencies. Existing conditional station
profiles can enter hardware testing independently once those inputs are
available; completing all feature families is a much larger milestone.
