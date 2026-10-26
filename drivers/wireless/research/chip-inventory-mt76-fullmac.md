# MT76, CYW43439 and Broadcom FullMAC planning inventory

> Initial remaining-LOC and engineer-day forecasts were withdrawn on 2026-10-26:
> they used uncalibrated allowances and overlapping shared/backend/chip work.
> The chip/path audit and measured LOC remain useful; packages describe scope.

Audit: 2026-10-26 UTC, branch `codex/ath10k-active-scan`, committed baseline
`e8fe43e7b`. Implementation is frozen; this document is planning, not a support
declaration. All source references below are local `/data/narf` or
`/usr/src/linux`, inspected read-only. No Cargo/QEMU run by this agent.

## Result and scope

- **34 current matched tuples:** 6 MT PCI, 2 CYW SDIO, 26 Broadcom PCI.
- They name **22 silicon/firmware families**, not 34 independent implementations:
  3 retained MT hardware families, CYW43439 and 18 Broadcom labels.
- Six MT tuples, two CYW tuples and three BCM43602 tuples reach a retained
  station path, conditional on actual chip/core/firmware/board/policy admission.
  The other **23 Broadcom PCI tuples have no firmware/station continuation**.
  A successful bound-driver inventory entry for them is not working Wi-Fi.
- This is a complete audit of these NARF match tables and their reachable
  owners. It is **not a complete measured per-board hardware capability census**:
  firmware `cap`/NIC/PHY queries, discovered cores/revisions, calibration and
  board identity are still absent for many actual devices. Unknowns below mean
  unknown, not hardware-inapplicable.
- The estimate covers implementing the feature families exposed by the local
  Linux owners for the currently matched families, with native ownership,
  failure/cancellation and tests. It excludes adding every upstream unmatched
  chip, Wi-Fi7/MLO not established by these owners, Bluetooth, userspace EAP
  implementations, firmware reverse engineering and physical RF certification.
  Undocumented vendor capabilities beyond this envelope have **no bounded
  estimate** until their actual capability/ABI inventory exists.

## Measured Rust footprint

`tokei 15.0.0`, command `tokei --types Rust PATH`, current working tree:

| Owned path | Rust files | Rust code LOC |
| --- | ---: | ---: |
| `drivers/wireless/mt76` | 39 | 17,382 |
| `drivers/wireless/src/cyw43439` | 33 | 8,850 |
| `drivers/wireless/src/brcmfmac` | 31 | 11,219 |
| Total, counted once | 103 | **37,451** |

These are Rust code lines, including inline/dedicated tests, native models,
tables and uncommitted work. Embedded Markdown totals in tokei are excluded.
They are not production-only LOC, source-equivalence evidence, a completion
percentage, or multiplied by the number of PCI IDs. Shared `wireless`, SDIO,
bus, crypto, net and build code is outside these counts; root owns central counts.

## Committed versus unvalidated work

The following profile codes apply to every row below, avoiding a false claim
that one PCI name determines bands/NSS/firmware support.

| Code | Reachable committed profile at `e8fe43e7b` |
| --- | --- |
| M | CONNAC2 PCI retained boot/radio; passive and policy-authorized active scans; 2.4GHz channels1–11 and retained5GHz table on actually reported bands; legacy or negotiated one-stream HT20, long GI, MCS0–7; best-effort WMM/QoS TID0, bounded native RX A-MSDU; TX BA disabled, unsolicited A-MPDU rejected, ADDBA explicitly refused; Open/WPA2-PSK CCMP; station only; verified WFSYS reset/fresh boot without association replay; no station PS/system PM/WoW. Firmware can report additional NSS/VHT/HE/6GHz, which does not enable those paths. |
| C | Exact CYW43439 SDIO whole-card/F1/F2/CM3/SDPCM/BCDC owner and signed board/firmware/NVRAM/CLM provisioning; actual valid2.4GHz channels only; host-selected20MHz station, public HT/VHT capabilities still absent; PHY NSS/GI/aggregation remain firmware-owned and not qualified as a public host profile; Open/WPA2-PSK CCMP plus actual-probe required-PMF offload and nl80211 CONNECT; default priority0; station only; ordinary PM_FAST/PM_OFF via native receipts; no recoverable post-start reset/rejoin, system PM or WoW. |
| B | Exact discovered BCM43602 CR4 + signed board profile, shared-memory5/6 common-ring/msgbuf owner with retained DMA; actual valid2.4/5GHz channels, both native band bandwidth caps pinned/read back20MHz; public HT/VHT absent; NSS/GI/BA remain firmware-owned and unqualified as a public host profile; shared C station/security/priority/role/ordinary-PS behavior; no post-start recovery/DMA reclamation/system PM/WoW. |
| P | At most exclusive PCI claim, BAR0/core discovery and interrupt parking; no admitted firmware/radio, no packet producer, no security/roles/recovery/PM. **Bands, width, NSS, GI, BA and firmware feature availability have not been queried.** A chip's numeric ID or an isolated ABI encoder does not fill these fields. |

Current **uncommitted, unvalidated** work adds:

| Work | Actual implemented owner/path | Validation status |
| --- | --- | --- |
| M+ SGI20 | Actual bound AP response intersects STA_REC_HT SGI20; local request offers it; independent SMPS masking; CONNAC1-only raw-WTBL GI writes are not invented on CONNAC2. | One new native intersection smoke; existing Open/WPA2 HT20 DHCP/IP now asserts SGI. Not QEMU-validated this wave. |
| M+ HT40/SGI40 | Actual NIC max-width/AP HT Operation/WMM plus complete occupied40MHz permission; all overlapping power/restrictions, canonical primary/secondary geometry, both channel-domain/SKU rows, native switch/RLM/SCO/STA_REC_HT;20MHz fallback; bound response downgrade closes; non-BA remains. | Five new smokes: native/policy/downgrade-cancel/Open DHCP/WPA2 DHCP. Not QEMU-validated. |
| C+/B+ HT20/SGI | Actual `nmode`, `rxchain` and20MHz `bw_cap` receipts; exact source HT body and public capabilities; AP HT/WMM/basic-MCS admission; current BSSID/chanspec and actual association request+response IEs, then another true FIFO/ring idle before port. Required PMF composes; firmware owns BA/reorder/crypto/Ethernet deaggregation. | Three native smokes per transport, covering Open/WPA2/PMF DHCP/IP, denials and cancellation/DMA. Not QEMU-validated. |
| Restrictive policy | MT occupied/current TX permission and common FullMAC TX ceiling deny indoor/unknown flags without an actual qualification; passive receive preserved. | Secondary-only/current-grant MT tests and native live-policy FullMAC denial cases added; review finding resolved, gate pending. |

Total current wave: **12 new smokes**, scoped formatting/diff checks passed.
Peer reviews were advisory and found no unresolved confirmed blocker after
the indoor fix; they are not integration or hardware acceptance.

## Every current matched tuple

M/C/B/P above specify bands, width, NSS, GI, BA/QoS, security, roles, recovery
and PM for each row. `+` is only the unvalidated work table, never committed
support. Physical maxima remain gated on actual capability replies.

| Match tuple | NARF/upstream identity and variant | Actual owner/stage | Missing package/delta |
| --- | --- | --- | --- |
| PCI14c3:7961 | MT7961 / MT7921 firmware family | M; M+ WIP | MT packages; D-MT7961 |
| PCI14c3:7922 | MT7922 | M; M+ WIP | MT packages; D-MT7922 |
| PCI0e8d:7922 | ITTIM-vendor MT7922 alias | Same owner after actual identity | D-alias only, not another MT driver |
| PCI14c3:0608 | Upstream MT7921 firmware alias | M only after actual7961/7920/7922 identity admission | D-alias; resolve actual chip, not engineering-ID guess |
| PCI14c3:0616 | **Upstream selects MT7922 firmware**, despite NARF constant's historical ALT name | M after actual identity; M+ WIP | D-alias; must not count as a separate MT7921 implementation |
| PCI14c3:7920 | MT7920; raw7961 can also fold here under HW_BOUND DBDC bit | M; M+ WIP | MT packages; D-MT7920 |
| SDIO F1 02d0:a9af | CYW43439 card | C; C+ WIP | FullMAC shared + SDIO packages; D-CYW board/profile |
| SDIO F1 04b4:bd3d | Cypress-vendor card alias; loader still requires actual43439/revision | C conditional on actual discovery; C+ WIP | D-alias, no second radio implementation |
| PCI14e4:43ba | BCM43602 | B; B+ WIP | FullMAC shared + PCIe packages; D-43602 |
| PCI14e4:43bb | BCM43602_2G label | B boot admission exists; actual band query/board still mandatory | D-43602-band; single-band behavior not proved by label or generic fixture |
| PCI14e4:43bc | BCM43602_5G label | Same qualification caveat; common owner currently expects both BW controls | D-43602-band |
| PCI14e4:43a3 | BCM4350 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:43df | BCM4354 named DID | P | F8/F9 then D-WCC/BCA; current upstream matching differs, so inspect actual chip |
| PCI14e4:4354 | BCM4354 raw DID alias | P | Same4354 delta + D-alias |
| PCI14e4:43dc | BCM4355 | P | F8/F9 then D-SEED |
| PCI14e4:43ec | BCM4356 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:43d3 | BCM43567 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:43d9 | BCM43570 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:aa31 | BCM43570 raw DID alias | P | Same43570 delta + D-alias |
| PCI14e4:43e9 | BCM4358 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:43ef | BCM4359 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:4464 | BCM4364 | P | F8/F9 then D-SEED |
| PCI14e4:43ca | BCM4365 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:43cb | BCM4365_2G label | P | Same4365 silicon delta + D-alias; no queried band proof |
| PCI14e4:43cc | BCM4365_5G label | P | Same4365 silicon delta + D-alias |
| PCI14e4:43c3 | BCM4366 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:43c4 | BCM4366_2G label | P | Same4366 silicon delta + D-alias |
| PCI14e4:43c5 | BCM4366_5G label | P | Same4366 silicon delta + D-alias |
| PCI14e4:440d | BCM4371 | P | F8/F9 then D-WCC/BCA |
| PCI14e4:4415 | BCM43596 | P | F8/F9 then D-CYW-vendor |
| PCI14e4:449d | BCM43752 | P | F8/F9 then D-SEED |
| PCI14e4:4488 | BCM4377 | P | F8/F9 then D-SEED |
| PCI14e4:4425 | BCM4378 | P | F8/F9 then D-SEED |
| PCI14e4:4433 | BCM4387 | P | F8/F9 then D-SEED |

NARF does not currently match upstream MT7902, BCM43602 raw DID, CY54591,
upstream subsystem-specific4355/4365 entries, MT7925/CONNAC3 or arbitrary
USB/SDIO Broadcom families. They are outside these counts and estimates.
The loadable MT module is ID-registration-only, not the built-in native owner.

## Remaining shared work packages

| Package | Deliverable and dependency |
|---|---|
| M0 | Stabilize current SGI/HT40 work after native gates |
| M1 | RX BA: WTBL_BA+STA_REC_BA receipts, ADDBA/DELBA/BAR, per-TID bounded reorder/timeouts, PN/key-epoch retirement |
| M2 | TX BA/A-MPDU/A-MSDU, retry/window/token/status attribution and teardown; depends M1/control owners |
| M3 | Full AC/TID producers/queues, U-APSD/TSPEC, all-TID security and dynamic contention |
| M4 | Qualified VHT80/160, higher NSS, LDPC/STBC/beamforming intersections, native records and full occupied power |
| M5 | Qualified HE/6GHz operation, MCS/PHY/RU/TWT control and power-class/regulatory admission; depends actual NIC/CLC facts and M1–M4 |
| M6 | PMF/SAE/external SME/EAP adapters, supported extra ciphers/key formats, PMKSA/FT key ownership; shared crypto/supplicant primitives not recounted |
| M7 | AP/P2P/monitor/multi-vif, associated/off-channel/random/dwell scans, CSA/roam and owner arbitration |
| M8 | Station PS/runtime PM, WoW/system suspend/resume and key/queue/carrier restoration |
| M9 | Native telemetry/rate masks/antenna/SAR/radio/DFS controls, each only with qualified capability/policy |
| M10 | PCI removal/reprobe/multiple-device ownership and IOMMU/noncoherent/module hooks; platform core work excluded |
| F0 | Stabilize current native HT20/SGI verification after gates |
| F1 | Actual feature inventory plus HT40/VHT80/160/NSS/wider occupied-power admission and native receipts |
| F2 | Vendor-qualified SAE/external-auth/EAP/FT/PMKSA/cipher/GTK interfaces; existing required-PMF preserved |
| F3 | AP/P2P/monitor/multi-interface roles, per-vif events/keys/ports/queues and restrictions |
| F4 | Associated/off-channel/scheduled/random/dwell scans, radio/rate/power/telemetry controls and correlated completions |
| F5 | Real firmware reset/rejoin, monotonically fenced IOCTL/event/flow generations and quiescent DMA reclamation |
| F6 | SDIO station-runtime/system PM and WoW, F1/F2/host claim/IRQ/clock/wake lifecycle; common owner not recounted |
| F7 | PCIe runtime/system PM/WoW, wake/IRQ/flow/key lifecycle |
| F8 | Generalize exact43602 boot to discovered additional ARM/core/RAM owners; shared7/new ring/index/metadata modes and native flow/DMA lifecycle |
| F9 | Firmware-vendor bindings and signed board/OTP/Apple-selection infrastructure beyond current single-board43602/43439 |
| F10 | All-priority QoS/flow queues, U-APSD/offload/rx-glom/ARP/ND/keepalive controls where actual firmware reports them |
| F11 | Hotplug/multiple physical devices/IOMMU/noncoherent/module integration hooks; platform implementation excluded |

## Chip deltas after shared work

| Delta | Applicable profiles / multiplicity |
|---|---|
| D-MT7961/7922/7920 | 3 distinct firmware/chip families |
| MT alternate/ITTIM identity | 3 aliases |
| D-CYW board/transport integration | 1 chip family |
| CYW vendor/card alias | 1 alias |
| D-43602 existing chip/board | 1 |
| D-43602-band | 2 band labels |
| D-WCC/BCA:4350,4354,4356,43567,43570,4358,4359,4365,4366,4371 | 10 chip labels |
| D-CYW-vendor:43596 | 1 |
| D-SEED:4355,4364,43752,4377,4378,4387 | 6 chip labels |
| Other raw/band PCI aliases | 6 aliases |

Firmware-vendor bindings and newer Broadcom HE/6GHz capabilities remain unknown
until actual discovery and source authority establish their ABI. Aliases share a
backend. Full delivery needs exact firmware/board inputs and a closed acceptance list.

## Source evidence and real external inputs

NARF match/admission evidence:

- MT `mt7921/regs.rs::ALL_DEV_IDS`, `pci.rs::register_pci_driver`,
  `pci.rs::bring_up` actual7961/7922/7920+HW_BOUND; `firmware_transport_hw.rs`
  native owner; `iface.rs::associate`; `recovery.rs` verified WFSYS reset.
- CYW `bootstrap.rs::register`, `Provisioner::provision_checked`,
  `firmware.rs` discovery requires chip43439/revision and actual CM3/RAM cores.
- BCM `pcie.rs::ALL_DEV_IDS`, `probe`/`bring_up`; only43ba/bb/bc get BAR2;
  `native_runtime.rs::start` returns without continuation for chip!=43602 or
  missing BAR2. `boot.rs::BoardProfile::admits` explicitly requires43602.
  `provision.rs` accepts only exact signed Pcie43602/Sdio43439 selectors.

Local primary implementation references:

- MT `/usr/src/linux/.../mt76/mt7921/pci.c::mt7921_pci_device_table` selects
  distinct MT7921/MT7922/MT7920 firmware;0616 is MT7922 there.
- `mt76/mac80211.c::mt76_init_sband`; `mt7921/mcu.c::mt7921_mcu_parse_phy_cap`;
  `mt76_connac_mcu.c::{mt76_connac_mcu_set_channel_domain,
  mt76_connac_mcu_uni_set_chctx,mt76_connac_mcu_wtbl_ht_tlv,
  mt76_connac_mcu_sta_ba,mt76_connac_mcu_wtbl_ba_tlv,
  mt76_connac_mcu_build_sku}`; `mt7921/main.c` config/ampdu/role ops;
  `mt7921/pci.c` suspend/resume and `mt792x_dma.c` reset.
- Broadcom `/usr/src/linux/.../brcmfmac/pcie.c::brcmf_pcie_devid_table`,
  shared-memory5..7/DMA-index/split flags; `chip.c::{brcmf_chip_tcm_rambase,
  brcmf_chip_get_raminfo,brcmf_chip_set_passive,brcmf_chip_set_active}`.
- `brcmfmac/cfg80211.c::{brcmf_setup_wiphybands,brcmf_get_bwcap,
  brcmf_update_ht_cap,brcmf_update_vht_cap,brcmf_get_assoc_ies,
  brcmf_set_key_mgmt,brcmf_cfg80211_set_pmksa,brcmf_cfg80211_add_iface,
  brcmf_dongle_roam,brcmf_cfg80211_suspend,brcmf_cfg80211_resume}`;
  `feature.c::brcmf_feat_firmware_capabilities`; `fwvid.h` and vendor ops.
- `brcmfmac/cyw/core.c::brcmf_cyw_set_sae_pwd` uses a130-byte CYW-specific
  password structure; a string token or BIP cipher does not prove that ABI for
  WCC/BCA/SEED firmware. Upstream matching records the firmware vendor; NARF
  currently does not retain that general per-chip vendor authority.

Genuine inputs outside an incremental Rust estimate:

1. Exact PCI subsystem/card/board identity, revision, signed compatible firmware,
   board NVRAM and CLM/calibration; actual core/RAM/security/OTP facts for the23
   parked BCM IDs. No generic NVRAM fallback supplies this authority.
2. Actual firmware feature/API replies per deployed image: bands, bandwidth,
   chains, cipher/SAE/role/WoW flags, shared version/index/metadata modes and
   vendor password ABI. Unread fields are not hardware-inapplicable.
3. Signed deployment regulatory/power policy, any real indoor/DFS/6GHz power-class
   qualification, board antenna/SAR constraints. No host code should invent them.
4. Platform SDIO/SPI wiring, power/reset/IRQ/wake facts and coherent/IOMMU mapping
   contracts; OS framework work belongs to its root-owned package.
5. Actual firmware/silicon interoperability, RF behavior, suspend/wake and repeated
   recovery acceptance. Native tests establish software control/ownership behavior,
   not these external acceptances or a finite maximum schedule for their failures.
