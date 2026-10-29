# ath9k / ath10k chip inventory

> Initial remaining-LOC and engineer-day forecasts were withdrawn on 2026-10-26:
> they used uncalibrated allowances and overlapping shared/backend/chip work.
> The chip/path audit and measured LOC remain useful; packages describe scope.

Audit: 2026-10-25, `codex/ath10k-active-scan`, committed baseline
`e8fe43e7b` plus unvalidated work. Local reference is Linux7.3.0-rc4 in
`/usr/src/linux`; that tree has no Git metadata. This inventories reachable
software and known source capabilities, not physical-card qualification.

## Actual matches and firmware profiles

`L` below means the committed, conditional native ath10k station path:
exact PCI/BMI identity and signed firmware/BDF/OTP, CE/HTC/WMI/HTT, passive
and active discovery, channels1–11/legacy20, Open/WPA2-PSK host CCMP, real
DHCP/IP, terminal disconnect and ordinary firmware station-PS intent.
It requires RAW firmware without PFC; native command submission is not a
firmware sleep acknowledgement. Manual fresh-ROM recovery creates a new
interface and permanently retains old DMA, with at most3 attempts per boot.
There is no recorded hardware acceptance on any row. Six WMI dialects have
native Rust model coverage; that does not qualify every deployed image.

| Chip / revision | PCI ID | Exact BMI target / firmware directory | Reachable committed status | Current WIP |
|---|---|---|---|---|
| AR9285 |168c:002b|No executable firmware; actual4k EEPROM and silicon revision required|Calibrated, polled channel1,20MHz,1Mbps Open/WPA2 station; four-SSID active discovery, host CCMP and DHCP/IP|Negotiated legacy1–54Mbps, four native retry series and adaptive terminal-feedback policy; focused x86 software suite passed, combined gate pending|
| AR2427 |168c:002c|AR9285 silicon, 802.11n bonded out (Linux clears ATH9K_HW_CAP_HT)|Same AR9285 legacy probe/calibration/packet/station owner; every HT/BA source rejects this ID|None|
| QCA988X HW2.0 |168c:003c|4100016c; `QCA988X/hw2.0`|L|Fixed-country non-DFS5GHz legacy20; both native band-power limits and scan/peer modes; unvalidated|
| QCA988X Ubiquiti alias |0777:11ac|4100016c; same directory|L; exact board selection still distinct|Same shared WIP, no second backend|
| QCA6164 HW2.1 |168c:0041|05010000; `QCA6174/hw2.1`|L; device ID distinguishes it from6174|Same shared WIP|
| QCA6174 HW2.1 |168c:003e|05010000; `QCA6174/hw2.1`|L|Same shared WIP|
| QCA6174 HW3.0 |168c:003e|05020000; `QCA6174/hw3.0`|L|Same shared WIP|
| QCA6174 HW3.2 |168c:003e|05030000; same HW3.0 image directory, PLL continuation|L; separate target/PLL tuple|Same shared WIP|
| QCA99X0 HW2.0 |168c:0040|01000000; `QCA99X0/hw2.0`|L only for suitable RAW/non-PFC image; PFC-only operation is missing|Same shared WIP|
| QCA9984 HW1.0 |168c:0046|01000000; `QCA9984/hw1.0`, extended board2048|L under the same feature gate|Same shared WIP|
| QCA9888 HW2.0 |168c:0056|01000000; `QCA9888/hw2.0`|L under the same feature gate|Same shared WIP|
| QCA9377 HW1.0 |168c:0042|05020000; `QCA9377/hw1.0`|L|Same shared WIP|
| QCA9377 HW1.1 |168c:0042|05020001; same directory, PLL continuation|L; separate target tuple|Same shared WIP|
| AR9462 |168c:0034|Registered by ath10k as an explicit wrong-driver rejection|No station. It belongs to ath9k; NARF ath9k currently matches only AR9285 silicon (002b/002c)|None; a genuine AR9003/9462 backend is separate work|
| QCA9887 HW1.0 |168c:0050|4100016d; `QCA9887/hw1.0`|L via the QCA988X-family register/reset route; SI EEPROM calibration with board-file/OTP fallback|None|

Thus ath10k registers10 tuples:9 candidate ath10k tuples spanning8 chip
families and1 explicit AR9462 rejection. Its12 firmware-selection entries
are all reachable. None of these counts is a driver count
or completion percentage. Together with ath9k (AR9285 and AR2427) there are12 registered tuples.

NARF evidence: `ath9k.rs::{register,probe}`, `ath9k/identity.rs`,
`ath9k/calibration.rs`, `ath9k/packet.rs`, `ath9k/station.rs`,
`ath10k/hw.rs::ALL_PCI_MATCHES`, `pci.rs::{register_pci_driver,probe}`,
`profile.rs::PROFILES/select`, `htt_runtime.rs::data_profile`,
`wmi_runtime/{station,data,active_scan,power_save}.rs`, `boot/recovery.rs`.

## Capability inventory and actual missing software

AR9285 is a2.4GHz HT device with EEPROM-limited chains. No5GHz/VHT/HE/EHT
port is charged to this chip. The current retained profile is not its full
hardware feature set. Linux `ath9k/common-init.c::ath9k_cmn_setup_ht_cap`
advertises HT20/40, SGI40 and conditional SGI20/LDPC/STBC/chains; hardware
and EEPROM facts must select the actual subset. `ath9k/init.c::ath9k_set_hw_capab`
advertises4 queues,4 rate series, aggregation, software power-save null frames,
MFP, applicable STA/AP/IBSS/mesh/P2P/OCB/TDLS/ROC/CSA operations. NARF lacks:

- Channel retune beyond the one-shot channel1 calibration, regulatory14/CCK
  treatment, periodic calibration, antenna/diversity and thermal maintenance.
- HT20/40/NSS/MCS/SGI and conditional coded features, native A-MPDU/BA/reorder,
  fragmentation and complete aggregation/security/key-epoch handling.
- Four AC/TID queues, WMM/U-APSD/TSPEC, full native station telemetry, radio
  controls, richer off-channel scanning and channel-context arbitration.
- PMF/SAE and applicable additional roles/ciphers through the real driver,
  supported concurrency/beaconing and native packet/key authority.
- IRQ service, reset/rejoin, hotplug/removal, safe DMA reclamation, runtime PS,
  suspend/resume and applicable wake behavior.

For ath10k, actual SERVICE_READY RF chains, HT/VHT masks, hardware frequency
ranges, firmware feature/service bits and board/CTL are the source of truth.
PCI names alone do not establish bandwidth, NSS or optional roles. Linux
`ath10k/mac.c::{ath10k_mac_setup_ht_vht_cap,ath10k_mac_register}` and
`core.c::ath10k_hw_params` expose conditional HT/VHT/NSS/20..160/80+80,
STA/AP/mesh/P2P/monitor, BA/QoS, MFP, off-channel/scheduled scan, CSA, DFS,
power save and optional controls. No HE/EHT/6GHz/MLO port is charged to ath10k.
NARF still needs:

- Qualified5GHz/world/beacon-hint/DFS behavior beyond current WIP;
  HT/VHT/width/NSS/SMPS/beamforming/rate-control and occupied-band policy.
- PFC peer-queue/fetch/flow ownership; the retained queue-state buffer is not
  a producer/service implementation. Native-WiFi/hardware-crypto paths and
  firmware cipher/key/rekey/PMF integrations beyond RAW host CCMP.
- BA/TX aggregation and complete receive profiles; existing RX parsing is
  not proof of negotiated HT/VHT or PFC station operation.
- AP/mesh/P2P/monitor and multiple vdevs, associated/off-channel/scheduled
  scans, ROC/CSA/DFS, telemetry/radio/offload controls when firmware supports them.
- IRQ operation, stable-interface automatic recovery, proven DMA reclamation,
  suspend/runtime PM/WoW, richer calibration sources and per-profile lifecycle.

The new5GHz work intentionally does not clear world-domain NO_IR: it requires
a resolved fixed-country factory identity matching the signed host domain,
non-DFS centers, complete occupied20MHz rules and current authority. It is
still WIP and has not passed the combined gate; no physical RF claim follows.

## Remaining work packages

| Shared package / chip delta |
|---|
| Q9 channel/retune/periodic calibration |
| Q9 HT/BA/reorder/aggregation |
| Q9 QoS/PS/security/role driver integration; shared IEEE state machines excluded |
| Q9 IRQ/recovery/removal/PM/native DMA lifecycle |
| Q9 telemetry/radio/control integration |
| AR9462 native hardware delta after common Q9 work; currently rejected match |
| Q10 PHY/bands/DFS/NSS/width policy and native controls |
| Q10 PFC/native-WiFi/crypto/BA packet ownership |
| Q10 role/multi-vdev/scan/offload driver integration |
| Q10 IRQ/recovery/removal/PM/native DMA lifecycle |
| Q10 admitted chip/target/calibration deltas, counted once across aliases |
| Q10 telemetry/radio/optional controls |

QCA9887 is now registered on the QCA988X-family route with its EEPROM source. Native
Q10 work is shared across genuine aliases/dialects. Exact source capabilities,
firmware/board facts and physical acceptance remain outstanding.
