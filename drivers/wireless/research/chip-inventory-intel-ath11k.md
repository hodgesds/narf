# Intel / ath11k chip inventory and remaining work

> Initial remaining-LOC and engineer-day forecasts were withdrawn on 2026-10-26:
> they used uncalibrated allowances and overlapping shared/backend/chip work.
> The chip/path audit and measured LOC remain useful; packages describe scope.

Snapshot: 2026-10-25, branch `codex/ath10k-active-scan`, HEAD `e8fe43e7b`, plus the frozen working tree. This is a planning audit, not a new hardware acceptance result. Local primary reference: `/usr/src/linux` reports Linux **7.3.0-rc4** (`Makefile`). No Cargo/QEMU was run for this inventory. Implementation is frozen.

## What the LOC measurement means

Measured with `/root/.cargo/bin/tokei` **15.0.0**:

```
tokei drivers/wireless/src/iwlwifi drivers/wireless/src/ath11k --output json
```

Raw result: `/tmp/narf-intel-ath11k-tokei.json`.

| Scope | Rust files | Rust code LOC | Comment LOC | Blank LOC | Test-named code LOC | Other-file code LOC |
|---|---:|---:|---:|---:|---:|---:|
| Intel | 70 | 25,673 | 1,374 | 1,437 | 8,728 | 16,945 |
| ath11k | 61 | 78,324 | 3,468 | 4,498 | 28,106 | 50,218 |
| Total | 131 | **103,997** | 4,842 | 5,935 | 36,834 | 67,163 |

The last two columns use the filename heuristic `_test.rs`, `_tests.rs`, `/tests.rs`, or `/tests/`; inline tests and model-only code in other files remain in the other-file bucket. Tables and helpers count as code. The total is measured; a percentage-complete calculation from this total would be misleading. Remaining packages describe scope, not measured missing LOC.

## Reachability and evidence vocabulary

**Committed** means present in HEAD before the current wave; it does not mean verified on a physical card. **Native-model evidence** means the actual production transport/owner is exercised against a Rust device/firmware model; it does not prove a vendor firmware responds identically. **WIP** means current uncommitted source, not yet validated by the final coordinated build/QEMU gates.

Intel profile codes used in every chip row:

* **G2**: actual PCI probe parks the card and does not schedule retained Gen2 station startup. Separately callable, native retained API77 owner has boot/NVM/runtime defaults, passive scan, legacy20 single-chain management PHY/link, TX-disabled AP peer, management queue, signed measured platform/power qualification, and actual open-system authentication. Open/PSK-CCMP legacy association and local BSS close are **WIP**. No native Gen2 carrier, RSNA/key installation/data admission, BA/reorder, PMF, autonomous reconnect/recovery or power management is exposed. “PSK-CCMP association” describes the RSNE suite only; it does not establish keys or open the controlled port.
* **G3**: native deferred PCI startup is reachable, but `Device::validate_station_profile` admits only exact payload versions MAC3/LINK8/STA2/PHY6/queue3/antenna5. Its composed model is the **Sc c103** profile. That profile has actual station auth/association, Open/WPA2-PSK/SAE+PMF, keys/rekey/controlled port, management/data, BA/reorder and QoS, reconnect/reset recovery. PHY is legacy/HT20/40/VHT80, up to two NVM-selected chains/NSS; published bands are 2.4/5 GHz. STA only; HE/EHT, 6 GHz, 160/320 MHz, MLO, AP/P2P/monitor, multiple receive queues/RSS and runtime/system PM are missing. Reuse by another family requires its actual firmware command/payload/receipt and power contracts, not just a matching enum. A known generic Gen3 command-header-versus-payload-version audit remains open; Gen2's header0 contract was corrected in the preceding committed wave.
* **G3?**: routes to the G3 startup implementation but the actual family's firmware/ABI has not been established by the Sc model; it may correctly reject before station startup. Do not count as working station support.

NARF's `Generation::Gen2/Gen3` labels name its transport split; Linux's `iwl_mac_cfg.gen2` also includes AX210/Bz/Sc and is not the same taxonomy. The old `IwlDevice` facade has `control_plane_ready() == false`; its static HE/EHT/band flags are not reachable station capability evidence. Intel also has a one-radio `OWNED` singleton, so simultaneous Intel cards are another missing software capability.

ath11k profile codes:

* **A**: complete native dynamic-window PCI/MHI/QMI/CE/HTC/WMI/DP admission exists. Actual SERVICE_READY/band/regulatory/cipher/peer capabilities gate legacy/HT/VHT/HE, 20/40/80/160/80+80 MHz, chain/NSS, and 2.4/5/6 GHz; none is guaranteed solely by chip name. Native MAC paths cover STA/AP/P2P/GO, four vdevs/two operating channels, scan/ROC/DFS, WMM/QoS, firmware BA plus host reorder/PN/fragment/A-MSDU ownership, Open/WPA2 and SAE+PMF, external SME keys/ciphers, PS, WoW/cold suspend, recovery and firmware TX-power telemetry. Firmware/AP owns HE rate/OFDMA/TWT requester behavior; there is no independent host TWT-dialog controller. No EHT/320/MLO backend exists. Composed CE/startup/WPA2/data/recovery fixtures are x86-only; portable HAL/DMA tests on aarch64 do not establish the complete aarch64 PCI/IRQ/platform startup.
* **A-WIP**: the current wave retains logical operating-channel reservations across physical STA reset and sibling-vdev replay, including failure/cancellation. This fixes an actual collision-admission hole; three new native integration smokes are written but not finally validated. Prior reset/replay code exists in HEAD; this correction must not be described as committed accepted support yet.
* **Q**: recognized and deliberately rejected before MMIO/MSI/firmware/DMA activation because the native HAL/core/DP profile is incomplete. Configuration constants and MHI definitions are not a boot path.

## Every Intel PCI match (vendor 8086)

All 16 matches are enumerated below; the common capability descriptions above are part of each row. Marketing names are source labels, not independent SKU/RF identification. Dependencies are shared package IDs defined in the remaining-work section.

| PCI DID | Chip / native MAC profile | Firmware identity / API reality | Reachable production and validation | Missing packages / chip delta | Evidence |
|---|---|---|---|---|---|
| 2723 | AX200 / discovered CC | Static table incorrectly says QuZ API100; retained selector requires CC MAC0x34 and `cc-a0-77` | G2; retained native model; new association WIP; no PCI station startup | I0+I1+I2 for WPA2 station; I3/I6/I7/I8 for applicable feature parity; CC transport is shared, not a separate driver rewrite | N1,N2,N3,L1 |
| 02f0 | AX201 / Qu-b0,c0 or QuZ-a0, JF/HR | Retained selector requires exact discovered MAC/RF, API77; 500us xtal profile; static table says API100 | G2; profile/native owner tests, no physical acceptance | Same G2 packages; exact RF/board evidence required | N1,N2,N3,L1 |
| 43f0 | AX201 / Qu or QuZ, JF/HR | API77 retained; 12000us integrated xtal/2500us LTR; static API100 | G2 | Same G2 packages; shares long-latency implementation with a0f0 | N1,N2,N3,L1 |
| a0f0 | AX201 / Qu or QuZ, JF/HR | Same retained API77 long-latency contract | G2 | Same G2 packages, no repeated backend estimate | N1,N2,N3,L1 |
| 7df0 | Static AX201 label / identity unqualified | PCI table matches, **retained `gen2_profile::select` rejects DID**; static API100 | Park only; even retained profile selection is absent | I0 must establish actual identity/platform profile before other G2 work applies | N1,N2,L1,L5 |
| 2725 | AX210 / Ty-a0 GF/GF4 candidates | Static API89 agrees Linux family API89; candidate RF is not fused identity proof | G3?; boot transport/layout code reachable; Sc command profile does not prove Ty station ABI | I0+I4; I5 for HE/6GHz/160 where actual capabilities permit; I6/I7/I8 | N1,N4,N5,L2,L5 |
| 51f0 | AX211-labelled So-a0 GF/GF4 candidates | API89; exact RF/subsystem/board and command table needed | G3? | Shared I4 So delta; I5/I6/I7/I8 conditional | N1,N4,N5,L2,L5 |
| 54f0 | AX211-labelled Ma-a0 | **Static API100 differs from Linux Ma API89**; possible RF/SKU aliases need discovery | G3?; filename/ABI gap precedes station claim | I0 identity/ladder correction + shared I4 Ma delta | N1,N4,N5,L2,L5 |
| 7e40 | AX211-labelled Ma-b0 | **Static API100 differs from Linux Ma API89** | G3? | Same Ma backend package as54f0; extra stepping/identity cases, not another full backend | N1,N4,N5,L2,L5 |
| 272b | BE200-labelled Bz-a0 | **Static unprefixed102..100 differs Linux encoded-core c107..c102**; RF candidates also require fused/subsystem qualification | G3?; context-v2/Bz completion code is not proof of usable BE200 station | I0+I4 Bz delta; I5 EHT/MLO only where actual SKU/firmware permits; I6/I7/I8 | N1,N4,N5,L3,L5 |
| 6e70 | Sc-a0 family, SKU unknown | c107..c102 ladder; exact CSR MAC0x48 step0 and accepted RF required | G3; model evidence specifically c103, not every core/RF | Shared I0 Sc ABI audit, I5/I6/I7/I8; inventory firmware/RF cases | N1,N4,N6,L4,L5 |
| 9327 | Sc-a0 family, SKU unknown | Same core ladder / exact identity contract | Same G3 limits; no per-DID physical acceptance | Same Sc backend; no duplicate LOC | N1,N4,N6,L4,L5 |
| d240 | Sc-a0 family, SKU unknown | Same | Same | Same | N1,N4,N6,L4,L5 |
| d340 | Sc-a0 family, SKU unknown | Same | Same | Same | N1,N4,N6,L4,L5 |
| e340 | Sc-a0, BE211 label on observed MS-03 subsystem8086:0114 | Linux observation resolves `sc-a0-wh-b0-c103`; that observation validates identity, **not NARF hardware operation** | G3 native model profile; actual NARF RF/firmware acceptance outstanding | Same Sc backend; platform/board/SAR qualification still external | N1,N4,N6,L4,L5 |
| e440 | Sc-a0 family, SKU unknown | Same core ladder / exact identity contract | Same G3 limits | Same Sc backend; no duplicate LOC | N1,N4,N6,L4,L5 |

Sc identity currently permits non-CDB WH type0x113 step1, FM type0x112 step1/2, GF type0x10d; unknown RF/step/CDB fails closed. Linux's device-info table has additional SKU/bandwidth/RF aliases, so “all Sc are 320MHz/EHT” is not a valid inventory assertion. For Intel advanced features, EHT is inapplicable when actual NVM `sku_cap_11be_enable` is false; HE/6GHz and160MHz similarly depend on real NVM channels/SKU and regulatory capability. See L6. No estimate assumes unmeasured antennas/SAR, blanket permitted6GHz, or inferred board measurements. AX200/AX201's family documentation names Wi-Fi6/160MHz hardware, but this audit does not charge6GHz/EHT work to them or treat their 160MHz support as already implemented in NARF.

## Every ath11k refined matched profile (vendor17cb)

Firmware API here is not one Intel-style filename integer: actual MHI/QMI firmware, WMI SERVICE_READY/EXT and HTT major3 contracts determine the admitted feature profile. Individual vendor firmware releases are not exhaustively qualified.

| PCI DID and refinement | Chip/profile and firmware directory | Reachable software | PHY / security / roles / BA-QoS / PM-recovery | Missing packages / evidence |
|---|---|---|---|---|
| 1101, SoC major2 | QCA6390 HW2.0, `QCA6390/hw2.0` | A, independent IPQ8074-format RX descriptor/native DP plus composed model | A capability-gated bands/widths/NSS; Open/WPA2/SAE+PMF; STA/AP/P2P; BA/QoS, PS/WoW/reset; A-WIP recovery correction | A1/A4/A6; optional A5 only if supported; N7–N11,L7–L10 |
| 1103, major2 minor00/01 | WCN6855 HW2.0, `WCN6855/hw2.0` | A, WCN RX392/native DP | Same A profile, actual fw capabilities required; A-WIP | Shared WCN backend; A1/A3/A4/A6, conditionalA5; N7–N11,L7–L10 |
| 1103, major2 minor10/11, other sub-version | WCN6855 HW2.1, `WCN6855/hw2.1` | A; most complete composed native station/runtime model evidence | Same A profile; A-WIP | A1/A4/A6, conditionalA5; N7–N11,L7–L10 |
| 1103, major2 minor10/11, sub1019_A0E1/B0E1/C0E1/D0E1 | QCA2066 HW2.1, `QCA2066/hw2.1` | A dispatch reuses WCN register/core/DP backend; **no separate full per-SKU transport proof** | Same conditionalA software, not a promise all widths/bands are physically present; A-WIP | A3 distinct asset/capability/identity evidence, shared A1/A4/A6; N7–N11,L7–L10 |
| 1103, major2 minor10/11, sub001E_60E1 | QCA6698AQ HW2.1, `QCA6698AQ/hw2.1` | A dispatch reuses WCN backend; **no separate full per-SKU transport proof** | Same conditionalA software; A-WIP | Same shared packages; A3 must use this card's real board/fw facts; N7–N11,L7–L10 |
| 1104 | QCN9074 HW1.0, `QCN9074/hw1.0` | **Q: rejected**; no boot/auth/assoc/security/data/PHY admission | None currently. Linux profile has STA/AP/mesh,8vdevs, monitor/full-monitor/spectral; **STA PS and suspend are disabled in Linux's hardware parameters**, so those are not WCN PM ports to duplicate | A2 native HAL/static windows/non-shadow/core/per-pdev/HTT-v2/DP; applicable roles/monitor/mesh/spectral A5; N7–N9,L7,L9,L10 |

Other major/minor1101/1103 combinations refine to `Unknown` and are rejected, not fallback support. PCI IDs1107/1109 (ath12k-class devices) are not matched. Linux AHB/SoC IPQ8074/IPQ6018/IPQ5018/WCN6750 are **not actual NARF matches** and are excluded from the estimated chip total; porting them would be additional bus/platform/HAL work rather than completing an admitted PCI profile.

Hardware/firmware-inapplicable distinctions with primary evidence:

* Linux `ath11k/core.c::ath11k_hw_params` sets `supports_monitor=false` and `spectral.max_fft_bins=0` for QCA6390,WCN6855HW2.0/HW2.1,QCA2066,QCA6698AQ. Do **not** count missing host monitor/spectral as five required chip ports. QCN9074 has monitor/full-monitor and spectral FFT parameters, so its native implementation is missing software. Mesh is present in QCN's interface mask and absent in these client profiles' masks; do not add a mesh backend five times.
* `ath11k/mac.c::ath11k_mac_op_set_frag_threshold` explicitly returns `-EOPNOTSUPP`: known firmware clears More-Fragments and cannot implement TX fragmentation. NARF fragmentation-threshold TX is intentionally unsupported, not a remaining fake implementation. Native RX fragments are a different implemented path.
* ath11k's actual HT/VHT/HE capability construction (`ath11k_mac_setup_ht_vht_cap`, `ath11k_mac_copy_he_cap`, `ath11k_peer_assoc_h_he`) does not provide EHT/MLO/320MHz. Those require another hardware/driver family rather than multiplying ath11k work. Optional HE160/80+80/6GHz/NSS and TWT require actual service/band/peer evidence; absent target capability is not a missing software obligation.

## Remaining work packages

| Package | Deliverable and dependency |
|---|---|
| I0 | Correct PCI/CSR/RF/subsystem identity and firmware ladders; source-audit Gen3 command-ID header versions separately from payload versions; exact fail-closed profile admission and real firmware pin inventory. Precedes any all-chip readiness claim. |
| I1 | Gen2 native normal-data queue/EDCA/rate owner, RX-to-netdev/controlled-port wiring, local/over-air teardown and lost-link lifecycle, retained PCI startup/publication; extend current authenticated/associated owner without bypassing power fences. Depends I0 and validated association WIP. |
| I2 | Gen2 real pairwise/group/management key commands and receipts, RSNA4-way/rekey/GTK, replay/PN and PMF/security-data ownership; reuse common cryptography/SME where appropriate. Depends I1; aggregation is I3. |
| I3 | Gen2 actual HT/VHT/HE PHY/peer/TLC and20..160MHz/NSS capability admission, WMM aggregation/BA/reorder, active scan and scan/data coexistence. Only actual NVM-supported features; extends I1/I2 rather than reimplementing base station. |
| I4 | Ty/So/Ma/Bz exact firmware-payload/receipt profiles and native station composition. I0 owns common header/identity fix; this owns genuine family ABI deltas and per-family current-power/PNVM validation. |
| I5 | Gen3 missing HE/6GHz,160MHz; conditional Bz/Sc EHT320, puncturing and MLO/per-link key/queue/security lifecycle. Depends I0/I4, actual NVM/fw and qualified band/security/power. No MLO work charged to AX2xx. |
| I6 | Applicable Intel AP/P2P/GO, multiple interfaces/radios/channels, ROC/monitor, beacon/peer and role lifetime/control paths. Reuses I1–I5; role-specific policy/receipt/queue ownership remains substantial. |
| I7 | Native runtime/system power, WoW, thermal/coexistence and platform-SAR contracts, suspend/resume/reset/recovery across MVM/MLD; preserve credential/key/DMA ownership. Existing Gen3 basic reset code is reused, not counted as wholly absent. No invented platform values. |
| I8 | Remaining applicable Linux runtime/offload features after core paths: multi-RX/RSS/queue scaling, checksum/filter/scheduled-scan/offload controls, firmware diagnostics/FTM where exposed and authorized. Inventory exact target services first; no claim every firmware has every optional service. |
| A1 | Validate current shared-channel reset/replay correction and resolve real remaining failure/cancellation/lifetime edges. Reuses current WIP and its3 new native smokes. |
| A2 | QCN9074 native static BAR windows, register/HAL ops, non-shadow DMA rings, core/per-pdev/HTT peer-map-v2, QCN RX/REO/DP; real boot/station/security/data/fault/reset composition before removing profile rejection. Shared upper MAC/security reused. |
| A3 | Per-profile firmware/BDF/board/capability proofs and necessary small QCA2066/QCA6698AQ/WCN stepping deltas, not another full MAC stack. No fake board inputs. |
| A4 | Complete native aarch64 PCI/IRQ/startup/reset/board discovery and composed admission/data tests; target platform DT/BDF variant discovery where required. Portable codecs/ring tests already exist. Shared bus APIs may be prerequisites. |
| A5 | Remaining applicable optional user-control/runtime surface: non-contiguous RATEMASK programming and supported TWT controls; QCN monitor/full-monitor/mesh/spectral/radar diagnostics and role capacity. Depends A2 for QCN. Do not charge monitor/spectral to client profiles that disable them. Firmware-owned requester behavior is already present. |
| A6 | Close native cross-role/service/security/PM recovery and cancellation coverage gaps for admitted profiles, fix resulting real defects and interoperability deltas. Reuses existing rich MAC/WMI/DP code; tests are a larger fraction than production. |

Aliases share these packages. Gen2 station startup/data/security and QCN9074
remain prerequisites. Actual board, firmware, power and architecture acceptance
remain outstanding; no calendar date follows from code volume.

## Exact source references

Paths below are repository-relative for NARF and absolute for local Linux. Function names are the stable anchors; line positions may move as other agents finish their owned files.

* **N1** `drivers/wireless/src/iwlwifi/mod.rs::chip_config_for_pci_id`, `PCI_DIDS`, `probe`, `IwlDevice::control_plane_ready`; `rx_rfh.rs::CompletionFormat::for_mac`: every PCI match, singleton/park/startup routing and generation-specific descriptors.
* **N2** `iwlwifi/gen2_profile.rs::select`, `API`; `mvm_boot.rs::Owner::{new,initialize}`; `mvm_power.rs::Owner::prepare_transmit_power`; `mvm_link.rs::Owner::{activate_link,deactivate_link}`: exact API77 identity and retained authority/lifetime chain.
* **N3** `iwlwifi/mvm_auth.rs::Owner::authenticate_open`, `qualified_management_transmit`; WIP `mvm_assoc.rs::Owner::{associate_legacy,association_response,clear_association}`; `mvm_{auth,assoc}_tests.rs`: actual management frame/TX receipt/RX response/control receipts, not encoder-only support.
* **N4** `iwlwifi/bootstrap.rs::Owner::{candidates,provision_using,start}`; `device.rs::Device::{validate_station_profile,initialize,get_wireless_info,associate_in_domain,recover}`; `runtime.rs::Hardware::{command,command_with_header_version}`: deferred admission, exact payload gates and remaining Gen3 header contract.
* **N5** `iwlwifi/connection.rs::Connection::{associate_in_domain,stop_rx_ba}`, `install_key`, `remove_key`; `security.rs`; `ht_vht.rs::Local::{from_nvm,capabilities}`, `Negotiated::{parse,apply_phy,apply_peer,apply_link,apply_tlc}`; `dhcp_composition_tests.rs`: actual station/security/width and native model evidence.
* **N6** `iwlwifi/firmware_identity.rs::Sc::{read,rf,ladder,check}`; `mod.rs::RF_SC_A0_CANDIDATES`: fused identity restrictions and core filename ladder.
* **N7** `drivers/wireless/src/ath11k/hw.rs::{ALL_DEV_IDS,refine_hw_rev,HwRev::params}`; `pci.rs::validate_runtime_profile`: every actual matched/refined profile and preactivation rejection.
* **N8** `ath11k/core.rs::CoreConfig::for_hw`; `dp_ring.rs::DpHwParams::for_rev`; `mhi.rs::config_for`: complete admitted profiles versus QCN's incomplete HAL/core/DP.
* **N9** `ath11k/runtime.rs::DpHooks`, `Shared::rebuild_after_transport_reset`; `iface.rs::Interface::{recover_one,rebuild_after_radio_recovery}`; `integration_tests.rs`; WIP `recovery_channel_tests.rs`: real reset/replay ownership and native composition scope.
* **N10** `ath11k/mac.rs::{Mac::associate,Mac::assoc_success,Mac::authorize,Mac::set_tx_bitrate_mask,Mac::twt_changed_for_service,Mac::prepare_wowlan,Mac::finish_wowlan_resume,Mac::ap_peer_associate}`; `mac_peer.rs::{own_caps,sta_rx_nss}`; `iface.rs::Ath11kNetdev::fragmentation_threshold`: reachable MAC controls, not mere WMI encoders.
* **N11** `ath11k/mac_reg.rs`, `wmi.rs` SERVICE_READY/EXT parsing, `dp_peer.rs`, `tx_offload.rs`, `iface.rs` WirelessInterface/Interface implementation; `integration_tests.rs` x86-only module cfg: capability-qualified PHY/security/DP/netdev publication.
* **L1** `/usr/src/linux/drivers/net/wireless/intel/iwlwifi/cfg/22000.c::{iwl_22000_base,iwl_qu_mac_cfg,iwl_qu_long_latency_mac_cfg,iwl_ax200_mac_cfg}`: API77 and native transport/platform profile; no API100 basis here.
* **L2** `.../intel/iwlwifi/cfg/ax210.c::{iwl_ax210_base,iwl_ty_mac_cfg,iwl_so_mac_cfg,iwl_ma_mac_cfg}`, `IWL_MA_A_GF_A_FW_PRE`, `IWL_MA_B_GF_A_FW_PRE`: Ty/So/Ma API89.
* **L3** `.../intel/iwlwifi/cfg/bz.c::iwl_bz_base`, `IWL_BZ_UCODE_CORE_{MIN,MAX}`: encoded-core102..107 and Bz/Gl RF names.
* **L4** `.../intel/iwlwifi/cfg/sc.c::iwl_sc_base`, `IWL_SC_UCODE_CORE_{MIN,MAX}`: encoded-core102..107.
* **L5** `.../intel/iwlwifi/pcie/drv.c::{iwl_hw_card_ids,iwl_dev_info_table}`; `iwl-drv.c::iwl_drv_get_fwname_pre`: PCI/subsystem/MAC/RF/CDB selection and firmware naming; PCI DID alone is insufficient.
* **L6** `.../intel/iwlwifi/iwl-nvm-parse.c::{iwl_init_sbands,iwl_init_vht_hw_capab,iwl_nvm_fixup_sband_iftd}`: actual NVM channels/SKU,160MHz/EHT/bandwidth restrictions. `mvm/{sta,link,mld-mac,mac80211,tx}.c` and `fw/api/{mac-cfg,sta,tx,cmdhdr}.h`, `pcie/tx-gen2.c`: control/packet contract for MVM versus MLD and command-ID/header distinction.
* **L7** `/usr/src/linux/drivers/net/wireless/ath/ath11k/core.c::ath11k_hw_params`: QCA6390 near219, QCN9074 near311, WCN2.0 near397, WCN2.1 near489, QCA2066 near749, QCA6698AQ near840. Exact monitor/spectral/interface-mode/PS/suspend parameters cited above.
* **L8** `.../ath/ath11k/mac.c::{ath11k_mac_op_set_frag_threshold,ath11k_mac_setup_ht_vht_cap,ath11k_mac_copy_he_cap,ath11k_peer_assoc_h_he,ath11k_mac_op_set_bitrate_mask}`: native capability/rate/fragment contract.
* **L9** `.../ath/ath11k/pci.c::{ath11k_pci_get_window_start,ath11k_pci_probe}`; `hw.c::{qca6390_ops,wcn6855_ops,qcn9074_ops,qcn9074_regs}`; `hal_rx.c`, `rx_desc.h::hal_rx_desc_qcn9074`: genuine QCN native HAL/static-window/descriptor differences.
* **L10** `.../ath/ath11k/{dp.c,dp_rx.c,dp_tx.c,mac.c,wmi.c}` and `spectral.c::ath11k_spectral_init`: actual DP/role/optional controls; exposed service/parameter structures do not themselves prove a reachable NARF user operation.
