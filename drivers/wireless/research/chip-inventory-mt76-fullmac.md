# MT76, CYW43439 and Broadcom FullMAC planning inventory

This is a planning inventory of the MT76, CYW43439 and Broadcom FullMAC
match tables, not a support declaration. The per-family specifications are
the authority for current behavior:
[`mt7921.md`](../specification/mt7921.md),
[`mt7925.md`](../mt76/src/mt7925.md),
[`cyw43439.md`](../specification/cyw43439.md) and
[`brcmfmac.md`](../specification/brcmfmac.md). This file records the match
tuples, the profile each reaches, chip deltas, work packages and the
external inputs no code can supply. Source references are to this tree or
`/usr/src/linux`. No engineer-day or remaining-LOC forecast is given: an
earlier one used uncalibrated allowances and overlapping
shared/backend/chip work, and was withdrawn.

## Result and scope

- **36 current matched tuples:** 8 MT PCI, 2 CYW SDIO, 26 Broadcom PCI.
- They name **23 silicon/firmware families**, not 36 independent
  implementations: 4 MT hardware families (MT7961/MT7921, MT7922, MT7920,
  MT7925), CYW43439 and 18 Broadcom labels.
- The six CONNAC2 MT tuples, two CYW tuples and every Broadcom tuple with a
  covered chip profile reach a retained firmware/station path, conditional
  on actual chip/core/firmware/board/policy admission. The two MT7925
  tuples match by PCI id, but both chip-id gates refuse them (see MT7925
  below). Three Broadcom tuples (4354 named and raw, 43596) stay parked:
  Linux does not bind 0x43df and has no PCIe firmware row for 4354 or
  43596. A successful bound-driver inventory entry for a parked tuple is
  not working Wi-Fi.
- This is a complete audit of these NARF match tables and their reachable
  owners. It is **not a measured per-board hardware capability census**:
  firmware `cap`/NIC/PHY queries, discovered cores/revisions, calibration and
  board identity are still absent for many actual devices. Unknowns below mean
  unknown, not hardware-inapplicable.
- Scope excludes adding upstream chips NARF does not match, Bluetooth,
  userspace EAP implementations, firmware reverse engineering and physical
  RF certification. Undocumented vendor capabilities have no bounded
  scope until their actual capability/ABI inventory exists.

## Measured Rust footprint

Non-blank lines that are not `//` or `/* */` comment lines, in `.rs` files,
measured at `208afe49e`:

| Owned path | Rust files | Rust code lines |
| --- | ---: | ---: |
| `drivers/wireless/mt76` | 198 | 74,696 |
| `drivers/wireless/brcm/src/cyw43439` | 83 | 25,470 |
| `drivers/wireless/brcm/src/brcmfmac` | 94 | 33,802 |
| Total, counted once | 375 | **133,968** |

These include inline/dedicated tests, native models and tables. They are
not production-only LOC, source-equivalence evidence, a completion
percentage, or multiplied by the number of PCI IDs. Shared `wireless`, SDIO,
bus, crypto, net and build code is outside these counts.

## Profiles

The following profile codes apply to the rows below, avoiding a false claim
that one PCI name determines bands/NSS/firmware support. Physical maxima
remain gated on actual capability replies; none of these profiles has
physical WLAN acceptance.

| Code | Reachable profile |
| --- | --- |
| M | CONNAC2 PCI retained boot/radio and verified WFSYS reset. Built in: passive, active, associated/off-channel, scheduled and colocated-6 GHz scans; legacy, HT20/40, VHT20/40/80, actual-MT7922 contiguous160 and HE station profiles on actually reported bands, including 6 GHz SAE-H2E on 6E parts; WMM on all ACs; RX/TX BA on TID0–7 with A-MSDU; Open, WPA2-PSK, WPA3-SAE and PMF with CCMP/GCMP/CCMP-256 ciphers; AP, P2P and monitor roles; WoW, system suspend/resume and PCI removal/reprobe. `mt76.ko` carries the station subset (wireless spec §4.4). See `mt7921.md`. |
| M3 | MT7925 (CONNAC3): PCI registration in both builds, CONNAC3 register map, firmware pair, DMA layout and UNI/MLO/KEY_V3 encoders with live UNI dispatch in the station join. Both chip-id gates refuse the chip until `MT_HW_CHIPID` is read on real silicon. See `mt7925.md`. |
| C | Exact CYW43439 SDIO whole-card/F1/F2/CM3/SDPCM/BCDC owner and signed board/firmware/NVRAM/CLM provisioning; FullMAC station with firmware-qualified HT20/HT40/SGI, WMM, WPA2-PSK/PMF, WPA3-SAE offload, PMKSA, roaming/FT and host-supplicant fallback; native primary-bsscfg SDIO AP; SDIO reset/rejoin, system PM, WoWL and host DMA. Built-in only. See `cyw43439.md`. |
| B | Exact discovered BCM43602 CR4 and signed board profile, shared-memory5/6 common-ring/msgbuf owner with retained DMA; dual-band station with optional PMF and firmware-qualified HT20/HT40/SGI and VHT80; confirmed stop and DMA reclamation, transport reset/rejoin, cold and system resume, WoWL/GTK offload; firmware-SME AP, radiotap monitor, virtual interfaces and P2P. `brcm.ko` carries the station path only (wireless spec §4.7). See `brcmfmac.md`. |
| X | Additional Broadcom PCIe chip with a `chip_profile.rs` row (Linux RAM base and firmware name; WCC/BCA vendor): BAR2 is mapped and the chip enters the same retained boot owner as B, but only after an exact signed board/firmware selection (an OTP-bound selection for 4355/4364/4377/4378/4387). No board for these chips has been admitted on hardware, so bands, width, NSS, GI, BA and firmware features are unqueried. See `brcmfmac.md`, "Additional PCIe chip profiles". |
| P | At most exclusive PCI claim, BAR0/core discovery and interrupt parking; no admitted firmware/radio, no packet producer, no security/roles/recovery/PM. **Bands, width, NSS, GI, BA and firmware feature availability have not been queried.** A chip's numeric ID or an isolated ABI encoder does not fill these fields. |

## Every current matched tuple

| Match tuple | NARF/upstream identity and variant | Actual owner/stage | Missing package/delta |
| --- | --- | --- | --- |
| PCI14c3:7961 | MT7961 / MT7921 firmware family | M | MT packages; D-MT7961 |
| PCI14c3:7922 | MT7922 | M | MT packages; D-MT7922 |
| PCI0e8d:7922 | ITTIM-vendor MT7922 alias | Same owner after actual identity | D-alias only, not another MT driver |
| PCI14c3:0608 | Upstream MT7921 firmware alias | M only after actual7961/7920/7922 identity admission | D-alias; resolve actual chip, not engineering-ID guess |
| PCI14c3:0616 | **Upstream selects MT7922 firmware**, despite NARF constant's historical ALT name | M after actual identity | D-alias; must not count as a separate MT7921 implementation |
| PCI14c3:7920 | MT7920; raw7961 can also fold here under HW_BOUND DBDC bit | M | MT packages; D-MT7920 |
| PCI14c3:7925 | MT7925 (CONNAC3) | M3; chip-id gate closed | D-MT7925: chip-id read, blob staging, trailer byte, DMA slot order (`mt7925.md` §8) |
| PCI14c3:0717 | MT7925 alternate SKU | Same as 7925 | D-alias |
| SDIO F1 02d0:a9af | CYW43439 card | C | FullMAC shared + SDIO packages; D-CYW board/profile |
| SDIO F1 04b4:bd3d | Cypress-vendor card alias; loader still requires actual43439/revision | C conditional on actual discovery | D-alias, no second radio implementation |
| PCI14e4:43ba | BCM43602 | B | FullMAC shared + PCIe packages; D-43602 |
| PCI14e4:43bb | BCM43602_2G label | B boot admission exists; actual band query/board still mandatory | D-43602-band; single-band behavior not proved by label or generic fixture |
| PCI14e4:43bc | BCM43602_5G label | Same qualification caveat; common owner currently expects both BW controls | D-43602-band |
| PCI14e4:43a3 | BCM4350 | X | F9 board; D-WCC/BCA |
| PCI14e4:43df | BCM4354 named DID | P: no `chip_profile` PCI row (Linux does not bind it) | D-WCC/BCA |
| PCI14e4:4354 | BCM4354 raw DID alias | P: chip not covered (Linux has no PCIe firmware row and stops at "Unknown chip") | Same4354 delta + D-alias |
| PCI14e4:43dc | BCM4355 | X (OTP) | F9 OTP board; D-SEED |
| PCI14e4:43ec | BCM4356 | X | F9 board; D-WCC/BCA |
| PCI14e4:43d3 | BCM43567 | X | F9 board; D-WCC/BCA |
| PCI14e4:43d9 | BCM43570 | X | F9 board; D-WCC/BCA |
| PCI14e4:aa31 | BCM43570 raw DID alias | X | Same43570 delta + D-alias |
| PCI14e4:43e9 | BCM4358 | X | F9 board; D-WCC/BCA |
| PCI14e4:43ef | BCM4359 | X | F9 board; D-WCC/BCA |
| PCI14e4:4464 | BCM4364 | X (OTP) | F9 OTP board; D-SEED |
| PCI14e4:43ca | BCM4365 | X | F9 board; D-WCC/BCA |
| PCI14e4:43cb | BCM4365_2G label | X | Same4365 silicon delta + D-alias; no queried band proof |
| PCI14e4:43cc | BCM4365_5G label | X | Same4365 silicon delta + D-alias |
| PCI14e4:43c3 | BCM4366 | X | F9 board; D-WCC/BCA |
| PCI14e4:43c4 | BCM4366_2G label | X | Same4366 silicon delta + D-alias |
| PCI14e4:43c5 | BCM4366_5G label | X | Same4366 silicon delta + D-alias |
| PCI14e4:440d | BCM4371 | X | F9 board; D-WCC/BCA |
| PCI14e4:4415 | BCM43596 | P: CYW vendor path not implemented (Linux has no PCIe firmware row either) | D-CYW-vendor |
| PCI14e4:449d | BCM43752 | X | F9 board; D-SEED |
| PCI14e4:4488 | BCM4377 | X (OTP) | F9 OTP board; D-SEED |
| PCI14e4:4425 | BCM4378 | X (OTP) | F9 OTP board; D-SEED |
| PCI14e4:4433 | BCM4387 | X (OTP) | F9 OTP board; D-SEED |

NARF does not currently match upstream MT7902, BCM43602 raw DID, CY54591,
upstream subsystem-specific4355/4365 entries, or arbitrary
USB/SDIO Broadcom families. They are outside these counts.

### MT7925

The MT7925/CONNAC3 support is described in
`drivers/wireless/mt76/src/mt7925.md`: PCI registration for
`0x7925`/`0x0717`, firmware catalog, FWDL, the 51-window CONNAC3 fixed map,
the 5-ring DMA layout, the UNI/MLO TLV layer, KEY_V3 records and the MLD
station lifecycle. It is fixture-validated, not hardware-proven (open
gates: Q1 chip-id read, Q2 blob staging, the `0x25` trailer byte, DMA
TX-slot order).

### Loadable builds

Every `14c3`/`0e8d` tuple in the MT table, MT7925 included, is also claimed
by `mt76.ko`, which is the same driver source over the KABI with the same
chip-id gate. It carries the station subset only: no AP/P2P/monitor, WoW,
system PM, scheduled scan, roaming or userspace SME
(`drivers/wireless/specification/spec.md` §4.4).

All 26 Broadcom PCI tuples are also claimed by the `brcm` `.ko`
(`brcmfmac/pcie_kabi.rs`), the same driver source over the KABI with the
same admission. It carries the station path only, reads the kernel's
installed regulatory domain through `narf_wireless_regdomain`, and has no
AP/monitor/P2P, WoWL or host supplicant (`spec.md` §4.7). The two CYW SDIO
tuples stay built-in only: no SDIO I/O KABI exists.

## Remaining shared work packages

The M packages are mostly delivered; the status column says what is left.
The F packages are listed as originally scoped. `brcmfmac.md` and
`cyw43439.md` record AP, monitor, P2P/virtual-interface, reset/rejoin,
system PM and WoWL work against several of them, so check a package there
before planning it.

| Package | Deliverable and dependency | Status |
|---|---|---|
| M0 | Stabilize SGI/HT40 work after native gates | Done |
| M1 | RX BA: WTBL_BA+STA_REC_BA receipts, ADDBA/DELBA/BAR, per-TID bounded reorder/timeouts, PN/key-epoch retirement | Implemented, HE windows up to 256 |
| M2 | TX BA/A-MPDU/A-MSDU, retry/window/token/status attribution and teardown; depends M1/control owners | Implemented, including midstream restart |
| M3 | Full AC/TID producers/queues, U-APSD/TSPEC, all-TID security and dynamic contention | Implemented; U-APSD and TSPEC inapplicable to Linux mt7921 |
| M4 | Qualified VHT80/160, higher NSS, LDPC/STBC/beamforming intersections, native records and full occupied power | Implemented; 80+80 inapplicable |
| M5 | Qualified HE/6GHz operation, MCS/PHY/RU/TWT control and power-class/regulatory admission; depends actual NIC/CLC facts and M1–M4 | HE 2.4/5/6 GHz station implemented; TWT, OFDMA/UL-MU triggers, spatial reuse and BSS color collision not programmed |
| M6 | PMF/SAE/external SME/EAP adapters, supported extra ciphers/key formats, PMKSA/FT key ownership; shared crypto/supplicant primitives not recounted | PMF, SAE offload, GCMP/CCMP-256/BIP ciphers and SAE PMKSA caching implemented; FT is not recorded |
| M7 | AP/P2P/monitor/multi-vif, associated/off-channel/random/dwell scans, CSA/roam and owner arbitration | Implemented on one channel context; dwell inapplicable to CONNAC2; multi-channel P2P and 6 GHz P2P-device emission remain |
| M8 | Station PS/runtime PM, WoW/system suspend/resume and key/queue/carrier restoration | Station PS, WoW and system suspend/resume implemented; firmware beacon filter not enabled |
| M9 | Native telemetry/rate masks/antenna/SAR/radio/DFS controls, each only with qualified capability/policy | Station statistics, CQM, heard-AP radar/NO_IR admission and CSA following implemented; rate masks, antenna and SAR controls are not recorded |
| M10 | PCI removal/reprobe/multiple-device ownership and IOMMU/noncoherent/module hooks; platform core work excluded | PCI removal/reprobe, per-domain IOMMU, non-coherent DMA and `mt76.ko` implemented; silicon untested |
| F0 | Stabilize native HT20/SGI verification after gates | As scoped |
| F1 | Actual feature inventory plus HT40/VHT80/160/NSS/wider occupied-power admission and native receipts | As scoped |
| F2 | Vendor-qualified SAE/external-auth/EAP/FT/PMKSA/cipher/GTK interfaces; existing required-PMF preserved | As scoped |
| F3 | AP/P2P/monitor/multi-interface roles, per-vif events/keys/ports/queues and restrictions | As scoped |
| F4 | Associated/off-channel/scheduled/random/dwell scans, radio/rate/power/telemetry controls and correlated completions | As scoped |
| F5 | Real firmware reset/rejoin, monotonically fenced IOCTL/event/flow generations and quiescent DMA reclamation | As scoped |
| F6 | SDIO station-runtime/system PM and WoW, F1/F2/host claim/IRQ/clock/wake lifecycle; common owner not recounted | As scoped |
| F7 | PCIe runtime/system PM/WoW, wake/IRQ/flow/key lifecycle | As scoped |
| F8 | Generalize exact43602 boot to discovered additional ARM/core/RAM owners; shared7/new ring/index/metadata modes and native flow/DMA lifecycle | CR4/CA7 chip profiles exist (X rows); hardware admission open |
| F9 | Firmware-vendor bindings and signed board/OTP/Apple-selection infrastructure beyond current single-board43602/43439 | Signed family-3 board selection with OTP binding exists; CYW-vendor PCIe and Apple DT/ACPI sources absent |
| F10 | All-priority QoS/flow queues, U-APSD/offload/rx-glom/ARP/ND/keepalive controls where actual firmware reports them | As scoped |
| F11 | Hotplug/multiple physical devices/IOMMU/noncoherent/module integration hooks; platform implementation excluded | As scoped |

## Chip deltas after shared work

| Delta | Applicable profiles / multiplicity |
|---|---|
| D-MT7961/7922/7920 | 3 distinct firmware/chip families |
| D-MT7925 | 1 CONNAC3 family |
| MT alternate/ITTIM identity | 4 aliases |
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
  `pci.rs::bring_up` actual7961/7922/7920+HW_BOUND (MT7925 refused at the
  chip-id gate; `pci_kabi.rs` carries the same gate); `pci_common.rs` the
  shared per-device-id names, firmware pairs and L1 remap;
  `firmware_transport_hw.rs` native owner; `iface.rs::associate`;
  `recovery.rs` verified WFSYS reset.
- CYW `bootstrap.rs::register`, `Provisioner::provision_checked`,
  `firmware.rs` discovery requires chip43439/revision and actual CM3/RAM cores.
- BCM `pcie_ids.rs::ALL_DEV_IDS`, `pcie.rs::probe`/`bring_up`: BAR2 is mapped
  for 43ba/bb/bc and for ids whose `chip_profile::PCI_DEVICES` row has a
  WCC/BCA vendor. `native_runtime.rs::start` returns without a continuation
  for a chip outside `chip_profile::COVERED` or without BAR2.
  `boot.rs::BoardProfile::admits` requires a chip profile, refuses OTP chips
  for a trusted registration and requires an implemented PCI row (or 43602).
  `provision.rs` accepts exact signed `Pcie43602`, `Sdio43439` and
  `PcieFullmac` (family 3) selectors.

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
  WCC/BCA/SEED firmware. Upstream matching records the firmware vendor;
  NARF's `chip_profile::PCI_DEVICES` keeps it per PCI row and admits only
  WCC/BCA.

Genuine inputs outside the code:

1. Exact PCI subsystem/card/board identity, revision, signed compatible firmware,
   board NVRAM and CLM/calibration; actual core/RAM/security/OTP facts for the
   X and P Broadcom IDs. No generic NVRAM fallback supplies this authority.
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
6. For MT7925: the `MT_HW_CHIPID` value on a real `14c3:0717` card and the
   staged MT7925 patch/RAM blobs (`mt7925.md` §8).
