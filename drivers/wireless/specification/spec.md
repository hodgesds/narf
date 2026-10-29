# drivers/wireless — Specification

> Status: **v0.2** (Stage 4 design lock).
>
> Framework for wireless drivers in the NARF ecosystem. Extends
> `drivers/spec` and `wireless/spec` to define the operational
> boundary for 802.11 hardware.

## 0. Bring-up status

The May 2026 GPL-2.0 relicense permits the in-tree Linux-derived paths.
The table describes reachable implementation, not physical acceptance;
matching a PCI ID or testing a command encoder does not establish a WLAN.

| Driver | Generation | Status | Mechanism |
| :--- | :--- | :--- | :--- |
| **iwlwifi** | Gen3 MLD station (Sc/BE211), qualified Gen2 Open/WPA2 station | Gen3 runtime and retained Gen2 PCI/netdev/worker composition | Exact API77 discovery, current signed power/firmware/PCI publication fences, native scan/MLME/keys/RX epochs, encrypted data/rekeys and ordered local retirement; assets and firmware/RF acceptance remain — `iwlwifi.md` |
| **ath11k** | WCN6855-family and native QCA6390 profiles | Live station/runtime profiles; hardware acceptance pending | Native PDEV power telemetry with generation-scoped query/cache ownership; QCA6390 uses native IPQ8074 RX descriptors and four-vdev resources; QCN9074 remains gated pending its HAL/DP path — `ath11k.md` |
| **mt76** | MT7921/MT7922 CONNAC2 | Retained legacy/HT20/40 on2.4/5 GHz,5-GHz VHT20/40/80 and actual-MT7922 contiguous160 station service | Native WMM BE/TID0, directional LDPC/RXSTBC1/HT greenfield, actual NIC/AP-qualified RX/TX1/2 with native RF/RLM/full rate maps and conservative power headroom, recipient BA/nested A-MSDU and originator BA through kernel DHCP; TX A-MSDU and broader PHY/roles remain work — `mt7921.md` |
| **rtw88** | RTL8822CE and RTL8821CE initial stations; RTL8822BE identification | Distinct signed-board-power-gated channel1 station profiles through kernel DHCP | Separate L/H/R/T qualifications add response-bound WMM/HT20, recipient BA and bounded four-slot native sender aggregation over each original radio/DMA owner; current publication checks, real assets/RF acceptance remain — `rtw88.md` |
| **rtw89** | RTL8852B initial2T2R profile; other AX/BE prerequisites | Retained reset/cold/firmware/full radio/native station with source-controller/packet kernel DHCP models | Separately qualified WMM BE/TID0, native EDCA ACKs and QoS CCMP extend the existing radio/TXBD/RPQ owner; actual assets, reset handoff and physical qualification remain — `rtw89.md` |
| **rtlwifi** | RTL8188EE PCIe | Factory-qualified channel1 native polled station through actual kernel DHCP | Separately signed HT20/LGI MCS0–7, bounded A-MSDU and native ADDBA refusal extend WMM/EDCA/QoS CCMP with exact executable/NEPC/NEHT binding and capture/key/publication epochs; physical qualification and wider profiles remain — `rtlwifi.md` |
| **rtl8xxxu** | RTL8188EU USB firmware profile | Signed-board-power-gated channel1 native station service, Open/WPA2-PSK CCMP with retained RSNA and persistent USB RX/TX | Response-bound WMM, native EDCA/BE QoS and separately signed N8HT HT20/LGI MCS0–7, whole RX A-MSDU and native ADDBA refusal; actual calibration artifacts, physical qualification, reset/rejoin and wider profiles remain — `rtl8xxxu.md` |
| **ath10k** | QCA988x/QCA6174 and related PCIe parts | Retained RAW/non-PFC legacy/HT20 station on2.4 GHz and qualified non-DFS5GHz HT20/40 | Six-dialect native WMM/HT40 with independently gated SGI40 and drained RTS/CTS submission, retained exact executable/BDF authority, RX BA/reorder/A-MSDU and final policy/port/source publication fences; RAW transmit aggregation remains capped at one MPDU — `ath10k.md` |
| **ath9k** | AR9285 revision2 | Retained EEPROM/calibration, native non-EDMA and separately qualified channel1 HT20/LGI station through kernel DHCP | Native HT20 MCS0–7, recipient BA/reorder, RXSTBC1, RTS/CTS and separately qualified two-MPDU sender BA retain current-policy and M4/RX-idle fences; wider channels and recovery remain — `ath9k.md` |
| **brcmfmac** | Explicit BCM43602 PCIe board profiles | Signed exact-host board selection, retained CR4/msgbuf and native2.4/5GHz FullMAC station through kernel DHCP | Firmware/inventory/AP-qualified HT40/SGI40 and5GHz VHT80 with genuine narrower native fallback, complete occupied-power/source and final IPC/callback epochs, required/bounded-optional PMF WPA2, station PS and ACK-fenced flow reuse; assets, wider silicon, recovery/system PM remain — `brcmfmac.md` |
| **cyw43439** | Infineon SDIO FullMAC | Standard PCI SDHCI/explicit card bootstrap through F2 station attachment | Native per-band capability/inventory gates admit HT40/SGI40 only with actual firmware/AP proof and full occupied-channel authority; otherwise HT20 remains; required/bounded-optional PMF WPA2 and station PS are implemented; board wiring, gSPI and reset/PM gates remain — `cyw43439.md` |

The branch completion target is **all eleven families with all features supported
by their target hardware and firmware ready for physical testing**. The initial
station profiles above are an intermediate milestone: scan, Open/WPA2, DHCP and
bidirectional IP with safe disconnect/failure ownership have composed software
evidence. They do not close the branch. Wider chip/PHY coverage, security modes,
interface roles, radio controls, recovery and power management are required where
supported; a recognized PCI/USB ID or a gated implementation is still open work.

Readiness is assessed per actual chip/revision, firmware API and board profile.
Inventory the reference driver's hardware/firmware capability gates, implement
the reachable control and packet paths, and cover successful transitions plus
failure/cancellation/ownership with native Rust tests, reviewed fixed reference
fixtures and both-architecture execution.
Advertise only features backed by those paths. A feature may be inapplicable
only with hardware/firmware evidence, not because the initial NARF profile
omits it. Physical acceptance then supplies RF, interoperability and power
measurements; source/model results cannot supply those measurements.

The `codex/wifi-aggregation-next` checkpoint passed the coordinated Wi-Fi
suites: x86_64 2317 pass,0 fail,9 skip; aarch64 1847 pass,0 fail,3 skip.
The selected scope is `drivers/wireless,wireless,verification/wifi-fixtures`.
MT76 adds width-valid MCS8/9, actual NIC RX1/2 with TX1 and its HT companion,
directional LDPC, RXSTBC1, actual-MT7922 contiguous160 with eight-channel
power grants, and exact recipient windows1–64. Its native record,
packet and DHCP/IP fixtures pass those software suites. The Intel milestone
includes native Gen2 BA/pipeline and GTK reconnect history plus Gen3 native
receipt/source/capture-epoch work. RTL8821CE/RTL8822CE recipient and separately
qualified transmit BA/pipeline, and AR9285 HT20/recipient BA/RX STBC1/native
RTS/CTS are implemented and covered by the same coordinated checks. Earlier
passing counts below describe merged checkpoints. The all-family ledger and
physical qualification remain open.

The following same-branch continuation passed x86_64 2360/0 fail/9 skip and
aarch64 1890/0 fail/3 skip in the same selected scope, adding43 native smokes
per architecture over `3fbdfa9c2`. It adds separately qualified Intel Gen2
nested RX aggregation, C21/C22 RTS threshold control and AR9285 two-MPDU sender
BA, plus MT76 native AP WMM contention updates with drained DATA ownership and
checked EDCA/PSE command ordering. Both production boots and all four btrfs
postflights, debug/release builds, strict production/test and CI feature-context
Clippy, formatting and provisioning diagnostics passed. Family specs retain
the exact source, packet, cancellation and current-authority contracts. Real
qualification assets, physical acceptance and remaining software stay open.

The [per-chip inventory](../research/chip-inventory.md) records all 102 registered
bus identities, actual revision/firmware gates, native-path gaps and measured
source counts. It distinguishes aliases, catalog-only entries and rejected
devices; these counts are not a completion fraction. Its initial numeric
remaining-LOC forecasts were withdrawn after identifying overlapping work.

The following is the open implementation ledger, not a claim of exhaustive
hardware capability enumeration. Family specifications retain the detailed
profile and dependency contracts; every broader profile needs its own complete
feature inventory before it can be called ready.

The new `codex/wifi-feature-completion` branch starts at merged PR#1090,
`267146076`. Its validated software checkpoint implements ath10k native
HT40/source retention/protection, RTL8188EE separately qualified HT20, BCM43602
native VHT80 and final receive-publication fencing, and MT76 native TX2 with
response-bound full rate maps, RF/RLM setup and conservative power headroom.
Shared native PHY snapshots retain the same original-offer/response rules as
host MLME. Coordinated suites pass x86_64 2419/0 fail/9 skip and aarch64
1949/0 fail/3 skip, adding59 passing smokes on each architecture.
These scoped additions leave the broader family ledger below open.

The validated same-branch continuation `caa2cd785` adds ath10k SGI40,
RTL8188EU HT20/LGI with standalone RX A-MSDU, directional MediaTek HT greenfield
and bounded FullMAC optional-PMF admission. All45 new smokes pass per architecture.
The full ARM scope passes1994/0 fail/3 skip; x86 has2464 distinct passing cases
and9 skips across the full scope and affected-family reruns after fixture
corrections. Both production boots, all four btrfs postflights, debug/release
builds, strict production/test/CI Clippy, formatting and metadata diagnostics pass.
This is software evidence; exact qualification assets and physical acceptance
remain external. Optional PMF with MFPC APs omitting response RSNE remains open.

The 2026-10-27 [documented capability inventory](../research/remaining-features.tsv)
at implementation checkpoint `ac8641b6f` contains **307 driver-feature gaps**.
Each `feature` row names one missing capability in one driver family;
repeated mentions within a family are deduplicated, and a capability missing
from several families has a row for each. FullMAC shares18 such capabilities
between BCM43602 and CYW43439, so these counts do not measure independent
coding effort. The6 remaining `shared` API/admission entries overlap driver work and
include unsupported generic extensions; they are reported separately.
The inventory also separates36 chip/host/profile enablement entries (`chip`)
and3 unknown, unexpanded or unproven-applicability records (`unknown`).
Implemented features, hardware-inapplicable capabilities and external
measurement/physical acceptance gates are excluded from the307. Every row
links to family-spec evidence. This is a count of documented gaps, not an
exhaustive hardware census, completion fraction or duration/LOC forecast.

Compared with `caa2cd785` (293 feature,17 shared,27 chip,53 unknown), the
parallel all-family continuation removes40 feature rows (shared and driver)
and one chip row as implemented, proven inapplicable, or narrowed into a
renamed residual row, and resolves50 of the53 unknown records against the
upstream drivers. Resolution mostly *adds* rows: an unknown that proves
applicable becomes one or more named `feature` rows (for example rtw88
dynamic-PHY scope became seven tracking rows, and ath9k chip scope became nine
named chip rows), while one that proves inapplicable is removed with evidence
in its family spec. The higher feature count therefore reflects more precise
enumeration, not regression. Implemented in this continuation: shared A-MSDU
ack-policy/EOSP/large receive, TX and SPP A-MSDU, VHT TX STBC, beamforming
roles, Extended NSS BW, 80+80 and fragmented-management reassembly; Gen2 air
deauthentication; MT76 non-RFC1042 LLC receive, RX defragmentation and dynamic
HT protection; ath10k LDPC/RX STBC and QCA9887; ath11k host group PN, TWT
dialogs and radar diagnostics; FullMAC scan extra IEs, all-priority WMM and
BCM43602 VHT beamforming; RTL8188EE/RTL8188EU all-AC/TID routing and
RTL8188EE live EDCA; rtw88 channel1 active scan with extra probe IEs. AR2427 and
Intel Qu PCI identities are also admitted. Family specs carry the evidence.

**Recount 2026-10-28** (ledger after the round-5 merges, PR#1195): the
[inventory](../research/remaining-features.tsv) now holds **149 `feature`**
rows (148 driver, 1 `shared`), **35 `chip`** and **1 `unknown`**; the table
below counts `feature` rows per family. This recount also removes two rows as
inapplicable: ath9k `tx_amsdu` (Linux ath9k never sets
`IEEE80211_HW_TX_AMSDU`; `ath9k.md`) and shared `glk_membership_selector`
(no open 802.11ak General Link reference; mac80211 refuses GLK;
[shared wireless spec](../../../wireless/specification/spec.md)). ath11k's
remaining scope is the five `chip` platform-profile rows. rtw89 periodic
EDCCA, DIG and CFO tracking (PPDU-status RSSI averaging and the IFS-CLM
environment monitor) are implemented and their rows closed; rtw89 `tspec`,
`nhm_diagnostics` and `antenna_diversity_tracking` are resolved as
inapplicable or folded into chip rows, and `uapsd` narrowed to AP-side
(`rtw89.md`).

| Family | Documented feature gaps | Required software beyond the initial station milestone |
|---|---:|---|
| iwlwifi | 18 | Gen2 active probes, broader rejoin/key history, PMF/richer PHY/QoS/BA/TX LDPC/STBC/recovery; remaining Gen3 command profiles and unlisted PCI IDs; 6 GHz/HE/EHT, additional roles, checksum/scheduled-scan offload, RX/RSS and system PM |
| ath11k | 0 | QCN9074/IPQ/WCN6750 platform profiles; device-tree board variants and aarch64 composition |
| mt76 | 13 | Associated/off-channel and richer scans, 6 GHz/HE and broader VHT beyond the retained20/40/80/actual7922-160 profile, richer TX/RX BA and TX A-MSDU, PMF/WPA3, TX fragmentation, QoS beyond BE/TID0 and U-APSD/TSPEC, PM/removal/reprobe, IOMMU/non-coherent DMA and loadable packet ABI |
| ath10k | 20 | Broader HT40 pairs/bands, multiple streams/VHT/TX aggregation and richer RX profiles, PFC, alternate calibration sources, associated/off-channel scanning, IRQ operation, automatic/stable-interface recovery, DMA reclamation and host-bus/system PM |
| ath9k | 10 | Other chip/EEPROM/descriptor variants, channel retune, periodic calibration, HT/BA/aggregation and richer rates, IRQs, reset/rejoin, removal and PM |
| rtlwifi | 17 | Other matched chips; wider channel/rate profiles, IRQ/C2H expansion, multiple radios, reset/recovery, removal and suspend |
| rtl8xxxu | 9 | Other matched USB chips, SGI20/HT40 and wider channels/rates, RX/TX A-MPDU, TX A-MSDU, both BA directions and RX reorder, coexistence, EP0/halted reset, safe rejoin, FIFO retune and PM |
| rtw88 | 18 | RTL8822BE station path; broader C21/C22 channels/PHY, full AC/TID scheduling, roles/security and thermal tracking, reset/suspend/removal, multiple devices and retained-map reclamation; genuine N21S/N21L/N22L/other board assets |
| rtw89 | 14 | Other AX/BE profiles and BE transport/EFUSE, wider PHY/channel/rate/role/security profiles, periodic RF tracking, IRQs, reset/rejoin/removal/suspend and multiple functions |
| brcmfmac | 13 | Other chip/CPU/RAM/OTP/shared-ring profiles, PHY beyond the scoped43602 VHT80 owner where supported, WPA3/AP and other roles, host-supplicant fallback, reset/system PM, IRQs and DMA reclamation |
| cyw43439 | 16 | Platform clocks/pins/regulators/reset and gSPI host, further genuinely supported PHY/role/security profiles, reset/reload, system PM and host-bus power transitions |

Ordinary firmware station power save is implemented for CYW43439 and BCM43602
through the common retained FullMAC owner; system suspend, wake offload and
host-bus PM remain distinct open paths. Native FullMAC attachment also observes
live shared regulatory DB replacement/clear, including paused control futures and
host data admission; firmware-cap epoch observation and firmware RF quiescence
remain distinct gates. Actual authenticated assets, board wiring, reset handoff
and physical acceptance remain deployment/test gates.

The current parallel continuation adds actual API77 Intel active-link and
deactivation receipts while peer TX stays disabled, MT76 driver-owned WMM
negotiation and native BE/TID0 QoS through Open/WPA2 DHCP/IP, and exact-board
qualified RTL8821CE calibration-only firmware IQK. RTL8822CE also reaches its
actual retained backend's completed-radio transition through an explicit
Continued state. Ath10k supplies bounded manual fresh-ROM replacement generations
through `pci::recover()`: old interfaces are retired, old DMA remains pinned,
and current authenticated provisioning plus all runtime initialization repeat
before a new interface can be joined. These continuations preserve their stated
initial PHY/security profiles and do not complete the remaining family ledger.
The Gen2 Qu command path now separates the native zero wire-header version from
negotiated payload layouts across the reached prerequisite chain; existing Gen3
header behavior is preserved. MT76 live scan/station admission samples the
installed policy and observes clear/restriction instead of bootstrapping an old
grant through an in-flight command wait.

The next all-family continuation adds Gen2 native Open authentication with
acknowledged peer re-disable, ath11k native PDEV power telemetry, MT76 HT20 and
bounded A-MSDU receive admission, AR9285 native active discovery and ath10k
station-PS command submission. CYW43439/BCM43602 add firmware-owned WPA2
AP-required PMF with native capability, peer and association-RSNE readback,
public BIP cipher exposure and explicitly gated nl80211 PMK CONNECT admission.
RTL8188EE, RTL8188EU and qualified RTL8852B add response-bound WMM BE/TID0;
the shared CCMP formatter protects the actual QoS header. RTL8821CE IQK now
requires fresh native thermal conversions and a distinct signed recipe.
Family specs retain the narrower security/PHY/authority contracts and remaining
software; this continuation does not close the full hardware-feature ledger.
The combined Wi-Fi/shared-fixture QEMU gates pass 1848/0 fail/9 skip on x86_64
and 1381/0 fail/3 skip on aarch64, including clean production boot and btrfs
postflights. Production/kernel-test scoped Clippy, workspace formatting and
release/debug builds pass on both architectures. These remain software checks.

The following wave adds native Gen2 legacy association without claiming automatic
PCI security/data startup; ath11k preserves channel reservations through sibling
recovery. MT76 negotiates HT40/SGI and FullMAC confirms HT20/SGI from native
readbacks and actual association records. AR9285 has response-bound legacy
rates, four native retry series and adaptive DATA feedback; ath10k adds
fixed-country non-DFS 5-GHz legacy station/active scanning on all six dialects.
RTL8188EE/EU and qualified RTL8852B use response-bound legacy DATA rates, while
RTL8821CE has a distinct post-IQK parked operating-power owner without station
transmit admission. These remain partial feature profiles with hardware
acceptance outstanding.
The combined Wi-Fi/shared-fixture suites pass 1887/0 fail/9 skip on x86_64
and 1417/0 fail/3 skip on aarch64, including clean production boots and btrfs
postflights. Scoped production/kernel-test Clippy, workspace formatting and
release/debug builds pass on both architectures.

The next wave adds a retained API77 Gen2 TID0 data owner with native DCF/TLC,
Open Ethernet TX/RX and disable-before-queue-retirement; WPA2 keeps its port
closed and isolates EAPOL receive. MT76 adds immediate recipient BA for eight
TIDs/windows up to32, native WTBL/STA/ADDBA receipts, sequence reordering before
PN commitment and ordered BA/key retirement. Native rekey tests exposed and
corrected the KEY_V2 tag17 and install0/remove1 ABI fields. Ath10k adds
response-bound native WMM/BE-TID0 QoS on six dialects and current policy checks
through each station/RSNA wait and publication. RTL8821CE continues its original
reserved-DMA owner through separately qualified awake radio and actual native
Open/WPA2 kernel DHCP/IP. Its N21S grant requires genuine measured full-static
thermal coverage; no board asset or RF measurement is supplied by these tests.

This wave adds 39 passing smokes on each architecture. Combined Wi-Fi/shared
fixtures pass 1926/0 fail/9 skip on x86_64 and 1456/0 fail/3 skip on aarch64,
with clean production boots/btrfs postflights, scoped production/kernel-test
Clippy, workspace formatting and release/debug builds on both architectures.
Automatic Gen2 netdev/WPA2 keys, MT76 TX aggregation, broader Realtek PHY/roles
and the rest of the feature ledger remain open; these are software gates.

The following wave adds retained Gen2 WPA2-PSK/CCMP with actual native M4,
key and RX-epoch receipts, encrypted bidirectional data, rekeys and ordered
key-before-queue retirement. Automatic Gen2 PCI/netdev publication remains
gated. CYW43439/BCM43602 admit HT40/SGI40 only when actual firmware per-band
capabilities, exact chanspec inventory, AP response and current occupied-channel
power authority agree; otherwise they retain a confirmed 20 MHz fallback.
RTL8822CE gains optional signed N22L qualification for response-bound WMM
BE/TID0 and measured legacy DATA rates, plus final carrier/host-RX publication
inside current source and PCI authority. C21 retains its separate legacy grant.
Native Intel fixtures heap-own their shared station owner so nested prerequisite
construction fits the aarch64 boot stack. Real firmware/RF acceptance and the
remaining all-family feature ledger still apply.

This wave adds 39 passing smokes per architecture: the combined Wi-Fi/shared
fixtures pass 1965/0 fail/9 skip on x86_64 and 1495/0 fail/3 skip on aarch64.
Production boots and btrfs postflights, scoped production/kernel-test Clippy,
workspace formatting and release/debug builds pass on both architectures.

The current checkpoint adds retained Gen2 PCI/netdev/worker publication under
exact API77 and current signed firmware/power/PCI grants, native passive scan,
Open/WPA2 DHCP/IP, rekeys, liveness and ordered local retirement. Scan age starts
before publication and retired station tokens cannot follow a successor.
MT76 adds genuine fresh-peer BE/TID0 transmit BA, bounded native packet queues
with distinct DMA/TX-free proofs, clean refusal fallback and BA-before-key
retirement. C21 N21L extends its original signed/native radio owner with
response-bound legacy DATA rates and WMM. Ath10k adds firmware/AP-qualified
HT20, separate local/peer PHY limits, native RX BA/PPDU/BAR and reorder before
PN, whole authenticated A-MSDU receive and final host-publication port/policy
checks. Shared A-MSDU and opaque reorder owners retain the default receive
contract. Broader PHY/security/roles, recovery/PM and actual hardware/firmware
acceptance remain separate requirements; this does not close the family ledger.

The checkpoint adds 93 passing smokes per architecture: combined Wi-Fi/shared
fixtures pass 2058/0 fail/9 skip on x86_64 and 1588/0 fail/3 skip on aarch64.
Production boots/btrfs postflights, scoped production/kernel-test Clippy,
workspace formatting and release/debug builds pass on both architectures.

The public nl80211 scan limit follows each facade's `max_scan_ssids`: Gen3 Intel
admits 20 active SSID entries; Gen2 currently advertises zero. Ath10k, ath11k and common FullMAC admit 16, MT76
and AR9285 admit four, and the other
documented initial profiles advertise zero. A cache-miss CONNECT uses passive
discovery for those profiles rather than issuing an unsupported active probe;
explicit active-scan requests still fail before dispatch when the limit is zero.

## 1. Purpose & scope

**Owns:**
- The **Wireless Driver SDK** (extending `narf-driver-sdk`).
- **Scan Offload Interface** — hardware-accelerated scanning logic.
- **WNM / RRM Hooks** — hardware-assisted network/radio resource management.
- **Hardware Queues** — mapping 802.11 Access Categories (AC_VO, AC_VI, AC_BE, AC_BK) to device rings.

**Station/security placement:** The in-kernel shared station/RSNA primitives
and per-driver or FullMAC firmware station owners implement `WirelessNetIface`.
Userspace configures connections through capability-gated nl80211; the
canonical placement decision is in `wireless/specification/spec.md` §8.3.
The shared retained native CCMP/RSNA owner can be reused by raw-capable
SoftMAC transports, while each driver still owns descriptor admission,
terminal delivery receipts, radio policy and DMA lifetime.

**Does NOT own:**
- IP/TCP stack — lives in stack daemons.

## 2. Hardware Abstraction: The `WirelessDriver` Trait

Wireless drivers implement `WirelessDriver` (re-exported by `narf-driver-sdk`), which extends the base `Driver` trait.

```rust
#[async_trait]
pub trait WirelessDriver: Driver {
    /// Returns the hardware's supported bands and capabilities.
    fn get_hw_info(&self) -> WirelessHwInfo;

    /// Configures the hardware for a specific channel/width.
    async fn set_channel(&self, chan: ChannelCfg) -> Result<(), DriverError>;

    /// Submits a management frame for transmission.
    async fn submit_mgmt(&self, frame: Cap<DmaBuffer, Read>) -> Result<(), DriverError>;

    /// Registers a waker for received management frames.
    fn register_mgmt_waker(&self, waker: Waker);
}
```

## 3. Queue Management (Access Categories)

802.11 traffic is prioritized into four Access Categories (AC). Drivers must map these to hardware rings:

| Access Category | Description | Priority |
| :--- | :--- | :--- |
| **AC_VO** | Voice | Highest |
| **AC_VI** | Video | High |
| **AC_BE** | Best Effort | Normal |
| **AC_BK** | Background | Low |

The stack delivers Ethernet traffic through the netdev frame ring. The ath11k
adapter classifies each frame to its 802.1D TID and WMM access category, then
keeps one TXQ per TID. A shared 4096-flow fq table gives each TID DRR++ flow
fairness; CoDel uses a 20 ms target, 100 ms interval, and ECN marking before
drop. Hardware-queue stop reasons still gate the four ACs (VO, VI, BE, BK).
The ring boundary stays deliberately metadata-minimal, so the driver derives
a stable L2/L3/L4 flow hash rather than carrying Linux's private `skb->hash`.

### Firmware boot and control-message helpers

`iwlwifi::transport::start_gen3(mmio, regions, completion_format)` publishes
the owned context/IML addresses and releases the firmware CPU in the same
sequence. AX210 uses a 32-bit UMAC `CPU_INIT_RUN` write; Bz/Sc writes the
function scratch marker before setting `GP_CNTRL.ROM_START`. This does not
expand the accepted MLD station-command profile.

`ath10k::htc::build_setup_complete(rx_bundle_en)` returns the full 12-byte
`SETUP_COMPLETE_EX` body: message ID, padding, flags, receive-bundle limit and
reserved tail. Disabled bundling leaves the limit zero; enabled bundling
sets it to Linux's 32-message host limit.

`cyw43439::events::parse_event(frame)` consumes an Ethernet header, the
10-byte Broadcom vendor envelope and a 48-byte network-order event message.
`EventHeader::decode` consumes the event message alone. Invalid envelope
discriminators and truncated declared payloads fail; bytes after the declared
payload are padding and are not returned to the caller.

### MT76 PCI discovery and register access

MT7921/MT7922 discovery supports the physical 1 MiB PCI BAR0. Accesses use
Linux CONNAC2 fixed windows or a 64 KiB L1 aperture. L1 transactions preserve
unrelated selector bits, write the chip page into selector bits 15:0, read
back before window access, and restore/flush the prior selector afterward.
The caller exclusively owns BAR0 and the latch across the entire transaction.
Misaligned, unsupported, and out-of-range accesses are rejected before MMIO;
`ProbeError::UnsupportedRegisterWindow` reports an insufficient probe window.
`ProbeError::RemapRejected` reports a selector readback mismatch without
accessing the wrongly selected window; a removed selector reports `DeviceGone`.
`l1_remap` returns an offset or `u32::MAX` for an unsupported address; callers
must not use an indirect offset without a serialized selector transaction.

Probe clears PCI bus mastering and leaves DMA ring publication disabled.
Ownership waits are deadline-bounded; `PowerError::InvalidWindow` reports
an invalid register access and `UnsupportedChip` rejects unknown identities.
PCI discovery does not publish a zero-MAC netdev/wiphy. Firmware, radio and
station initialization precede packet admission through the retained transport. The legacy
`full_bring_up` boundary returns `NotImplemented` without allocating or
programming rings until it can retain every published allocation.
PCI alias `14c3:0616` selects the MT7922 firmware pair. Register translation
and selector encoding follow the local Linux reference at `ecd997b0189a`.

### MT76 MCU/DMA firmware transport

`mt7921::firmware_transport::Firmware::prepare` validates and owns patch and
RAM images before device writes; `Firmware::open` obtains them through a
live firmware-registry capability. On x86_64 and aarch64, unsafe `Transport::new` requires
exclusive device/register-latch ownership, a permanent BAR mapping, coherent
identity DMA and disabled PCI bus mastering. Per-domain IOMMU configurations
are rejected until an explicit DMA mapping path is implemented.

`Transport::run` is a single-use, cancellation-safe borrowed future. It
quiesces inherited DMA, publishes owned WM/FWDL TX and MCU RX rings, obtains
driver ownership, restarts the ROM, negotiates the patch semaphore, downloads
patch/RAM regions, starts firmware and verifies its ready register. MCU
commands carry CONNAC2 headers; scatter payloads are raw 4096-byte chunks.
TX completion requires descriptor completion and the device index; RX validates
descriptor lengths, packet type and event framing before rearming. Commands
match nonzero sequence numbers and retain at most 32 unrelated events.
Every wait checks authority and has a deadline, including a 30-second total
boot budget. Waits self-wake and use the scheduler bridge rather than relying
on another executor task or on enabled device interrupts.

`state` reports the last stage and terminal error; `pop_event` drains retained
notifications. Failed or cancelled attempts cannot be replayed without verified reset. Published DMA
allocations remain retained even when the owner is dropped. `shutdown` permits
release only after DMA is disabled and idle, PCI bus mastering is confirmed
off and ring references are cleared. Failure to prove quiescence retains memory.
`Transport::recover(expected_mac)` starts a new firmware generation only after
verified PCI parking, link ownership, the Linux WFSYS reset hold/readiness
sequence, DMA stop/idle and ring retirement. It then scrubs old TX payloads,
resets descriptors/tokens and queued notifications, reloads firmware/radio
state, and verifies the original MAC. No station keys or association are
replayed. `recover_boot_radio` retains ownership of the reset future across
caller cancellation. Interface service closes carrier and frame admission
before recovery, limits automatic attempts to three with backoff, and permits
operator-requested retries through scan/connect/disconnect. Initial radio
startup failure can use the same owned reset path before registration.
The late `mt76-firmware` initcall runs after firmware discovery and retains the
transport on success or failure; `boot_status` exposes its state. A ready
report proves firmware startup only. The late initcall registers a passive
scan interface only after the subsequent radio initialization succeeds.
`provision_boot_radio().await` permits late asset provisioning on the same parked
PCI binding. Missing or invalid preflight inputs leave the claim unconsumed;
started firmware work is retained independently of caller cancellation. Successful
repeated provisioning preserves the existing interface/station, while a failed
started transport requires the verified reset path described above.

After `run`, `Transport::initialize_radio` performs a second single-use,
30-second-bounded initialization. `NicCapabilities::parse` decodes the counted
32-bit TLV table, requires a nonzero unicast MAC and a supported PHY, rejects
duplicate identity records and bounds every payload. The transport implements
distinct CE, extended and unified command headers; unified results check both
the command ID and the full 32-bit status. Extended queries check event and
extended-command identity. Unrelated notifications remain bounded.

Initialization obtains the NIC capabilities, checks the address and validity
of the EFUSE block containing hardware type 0x55b, chooses the matching power
table package and sends the embedded `00` indoor country rules. CLC container
geometry is validated during firmware preparation; all selected commands are
validated before the first CLC send. Capability-requested CLC response TLVs
must fit their enclosing event. Opaque vendor rule bytes are preserved.
On-chip EFUSE calibration mode is selected, MAC receive limits and counters
are configured on both bands, all 20 WTBL entries are cleared with bounded
idle waits, and RTS thresholds are sent through the MCU. `RadioReady(RadioInfo)`
reports this initialization, including the actual MAC/PHY, EFUSE hardware type,
number of country commands and optional channel configuration. Cancellation
or failure cannot replay initialization or release published DMA. Radio enable,
host regulatory/channel/power configuration for transmission, association and packet
queues remain separate prerequisites for an operational WLAN interface.
`cmd::encode_uni_dev_info_update` emits the four-byte own-MAC/band header and
one 12-byte active/link-index/MAC TLV (16 bytes total), matching CONNAC2 unified
device commands rather than the earlier synthetic two-TLV layout.

### MT76 passive scan and receive

The retained owner also allocates and publishes WFDMA RX ring 2, with the
same address-width checks and shutdown/retention contract as MCU rings.
Completed descriptors are copied before rearming, and packet lengths are
bounded by both descriptor and allocation. RX is routed by packet type on
all three rings. Firmware-forwarded normal frames (RX-event type with flag 1)
enter the packet queue; MCU replies enter the event queue. Each queue is
bounded to 32 entries. Packet overload drops the oldest packet; MCU reply
overflow reports an error instead of silently discarding a response. Neither
normal frames nor TX releases can satisfy an MCU waiter.

`Transport::scan_passive` and `scan_boot_passive` expose a bounded hardware
diagnostic after `RadioReady`. It accepts unique 2.4 GHz channels 1–11 and
the Linux mt76 5 GHz channel set (36–64, 100–144 and 149–177 at the defined
20 MHz spacing), limited to firmware-reported bands. Six-GHz RX channel flags
are rejected before narrowing to a channel number. Requests spanning more than
32 channels use the version-1 extension array with exact band/count fields. The first scan configures an unassociated station VIF with unified
device/BSS commands, installs a 20 MHz `00` channel domain with NO_IR flags,
enables the MAC/RX path, and submits a version-1 CONNAC2 passive scan request
with zero probe requests. Subsequent scans reuse the VIF. Scan completion
must match the separate nonzero seven-bit scan sequence. The receive wait is
15 seconds and the whole attempt retains the existing 30-second budget.
Failure/cancellation leaves the last stage and retains DMA; it cannot replay.

The parser checks the six-word RX prefix, all optional groups and padding,
frame-control/type, source/BSSID, FCS/security/aggregation errors, SSID and
IE bounds, RSN syntax, and consistency between RX and DS channels. Results
retain original IEs and optional measured RSSI; unknown RSSI maps to -128
at the wireless interface boundary. At most 64 BSSID/channel entries are
retained, with a truncation flag; hidden-to-visible SSID updates are preserved.
The shared native RX parser rejects zero/unsupported channels and six-GHz
aliases. Authentication, association, EAPOL and connected packet RX must match
the retained station channel before peer admission or replay-state changes.

After successful radio initialization, `Mt76Iface` registers an exact shared
netdev/wiphy name and its real MAC for passive nl80211 scans. Its constructor
takes `(name, RadioInfo)` and rejects invalid identity; the old PCI-ID-derived
constructor/registration scaffold is removed. Active/directed scans admit four
SSIDs through the retained policy-bound path below; unsupported channels/options
are rejected before dispatch. The implemented legacy 2.4/5 GHz
profile is exposed, with HT/VHT/HE/EHT disabled. Random-MAC, mandatory dwell,
colocated-6-GHz and extra-probe-IE scan requests fail explicitly; frequency
and channel lists must agree when both are supplied. The link stays down and frame
ring endpoints are absent until the retained station path completes a join.
Association requires a cached matching BSS and an authenticated host policy;
unsupported modes, channel configuration and scan profiles fail explicitly. No interface is registered on
firmware/radio initialization failure. No host device is detached for tests.

`Transport::scan_active(channels, ssids)` and `scan_boot_active` extend the
same owner with up to four directed/wildcard SSIDs. Every selected channel
needs current signed host power/TX permission; any overlapping DFS/NO_IR or
narrow bandwidth restriction denies active scanning. Implicit channel sets
select eligible channels, while explicit prohibited requests fail before
hardware/recovery writes. Native setup emits per-channel SKU power rows in
source band order, correlated PSE reads, then the scoped TX domain and exact
scan request. The owner rechecks policy before probe admission and during the
bounded wait, matches the exact scan sequence, and restores the passive NO_IR
domain after success. Failure/cancellation remains retained for verified reset.
The 1186-byte request and power-row ordering have fixed Rust reference fixtures;
native regressions cover policy/revocation, malformed replies and cancellation.

### MT76 management TX backend

The retained owner allocates and publishes WFDMA TX ring 0 alongside MCU
rings. Its private serialized management TX path emits the Linux CONNAC2
32-byte cut-through TXD plus 32-byte hardware TXP. The descriptor references
only those 64 bytes; TXP references the separate frame extent in the same
owned allocation. Payload addresses must fit 32 bits, lengths must fit the
allocation/TXP field, and token IDs stay within the MT7921 8192-token range.
Unprotected native management/EAPOL frames use the lowest negotiated AP basic
rate, including the Linux non-linear OFDM hardware-rate mapping in TXD6. The
selected rate remains in the retained session for rekeys and deauthentication;
this backend is not exposed as a user-facing injection API.

After publication the slot remains pending until both a valid DMA device
index/DDONE and a matching firmware TX-release token are observed, in either
order. Firmware failure status is preserved. Entire release events, including
WCID-pair records, are parsed before token state changes; conflicting duplicate
statuses and truncated records cannot partially retire ownership. Stale token
IDs do not retire the current frame. Drop/failure retains published DMA under
the existing shutdown contract.

### MT76 station preparation and MLME

`association::JoinPlan::prepare` validates a scanned ESS, exact SSID/BSSID,
unicast station identity and legacy supported/basic rates before constructing
an open-authentication and association request. The profile accepts legacy
CCK/OFDM on channels 1–11 and OFDM on the 5 GHz channel set; unknown mandatory
rates and mandatory CCK on 5 GHz are rejected. Open and WPA2-PSK/CCMP are distinct modes:
privacy/RSN mismatches, unknown mandatory rates, TKIP-only/SAE-only profiles
and mandatory PMF are rejected. WPA2 requests contain the exact negotiated
PSK/CCMP RSN IE plus supported rates; no PMK or temporal key enters the plan.
`JoinPlan::security()` returns the secret-free `SecurityMode`; the input
`Security` type redacts PMK bytes from debug output.

`Transport::associate_station_with_ies` additionally accepts optional SME IEs.
The request frequency/channel must identify the cached BSS. Malformed or
duplicate RSNEs, conflicting cipher/AKM/PMF/PMKID requests, RSNXE/FT, and
unimplemented PHY/WMM negotiation fail before hardware/recovery I/O. A matching
PSK/CCMP RSNE is replaced by the driver's single negotiated RSNE; other accepted
optional elements reach the native association request unchanged.

The plan's read-only phase advances from prepared through authentication and
association only on correctly addressed matching peer responses. Algorithm,
authentication transaction, status, association capability/privacy, AID and
IE bounds are checked. Other peers do not advance state; matching malformed
responses, rejection and cancellation are terminal. An associated WPA2 phase
does not authorize the controlled port until key exchange completes.

`peer_record` emits checked Linux CONNAC2 station/PHY/RA/state and nested WTBL
records for WCID 1, with the peer classified as an AP, native RX retained,
and an MLME state separate from controlled-port authorization. WPA2 uses
`CONN_STATE_CONNECT` until key completion; Open association may use
`CONN_STATE_PORT_SECURE`. Associated records require the AID observed by the
plan; no caller can mutate its phase directly.

### MT76 live join dispatch, WPA2 keys, and Ethernet data transport

`Transport::associate_station` requires an installed host regulatory policy
covering the entire 20 MHz channel. Permissions bind the selected channel;
2.4/5 GHz band fields are carried through channel domain, power limits, channel
switch, band-local STA basic rates and BSS PHY modes. The retained profile uses
one TX chain, legacy rates, Open or WPA2-PSK/CCMP; DFS/PMF-required/WPA3/HT
profiles are not silently admitted. The host half-dBm ceiling is sent in the
44-byte rate-power header plus one 162-byte channel/SKU record before any
native transmission. Channel switching uses Linux's full packed 76-byte
MT7921 request, including RX antenna mask and reserved tail.

`Session::associate_station` installs the BSSID and unauthorized AP WTBL
before native authentication/EAPOL RX. Authentication and association bind the
peer, station addresses and phase, with bounded waits. All live station,
WTBL and key updates use `MCU_UNI_CMD(STA_REC_UPDATE)` (id 3), with command ID
and full result status validation; the older extended-command encoder is not
used for these MT7921 station operations.

WPA2 uses `Supplicant::with_rsna` with the negotiated association RSNE and the
AP's scanned RSNE. EAPOL is accepted only from validated native FromDS data
addressed by the negotiated AP to this station. Its declared 802.1X extent is
bounded and link padding is excluded. There is no raw-descriptor/Ethernet
fallback. M3 MIC/ANonce/RSNE/replay and AES-wrapped KDE checks precede M4 and
key installation. The 16-byte PTK is installed for WCID 1; the VIF WCID 19
receives its NULL-station generic/RX/native-header WTBL setup and indexed GTK.
`STA_REC_STATE.ASSOC` does not by itself open the WPA2 controlled port.
Malformed key lengths are rejected, rather than padded/truncated.

`association::{bss_record,group_record,key_record,disconnect_record,
group_disconnect_record}` expose the checked single-BSS command bodies.
Key updates do not replay WTBL initialization, and the retained supplicant
suppresses reinstalling unchanged keys. Key/PN state stays per association;
PMK/PTK/GTK storage is erased when its owner is dropped.

`Mt76Iface` registers the kernel netdev, derives its frame-registry authority,
and starts its bounded packet worker. The IPC rings appear after successful
association. The kernel transmit callback enqueues validated Ethernet frames,
and the common `step_boot_network` progresses TX/RX without awaiting another
executor task. At most one cut-through payload is published; its descriptor
and buffer are reused only after both DMA completion and firmware token
release. TX completion polling preserves queued and newly received MCU replies.
Descriptor allocations use a 32-bit coherent DMA mask; data TXP payloads are
also allocated below 4 GiB, while other payloads fit their 36-bit fields.
Open TX does not request encryption. Ethernet multicast still uses a unicast
AP receiver/ACK/PTK, rather than the native multicast descriptor bit.

`PacketStep` reports whether a submitted frame was accepted and up to four
received Ethernet frames. Each RX conversion inspects at most 16 candidate
packets (up to three hardware completions per candidate). The same service is
installed as a synchronous network drain, with RX delivery outside driver/ring
locks. `service_boot_keys` retains an owned rekey future that either the normal
task or a synchronous drain may poll; cancelling its waiter cannot discard the
transport or strand the key exchange behind an executor-dependent mutex.

Native RX rejects invalid descriptor extents/groups, FCS/integrity/cipher
errors, fragments, WDS/null/A-MSDU/HT-control and unsupported LLC layouts.
Only unfragmented RFC1042 payloads up to 1500 bytes are converted. For secured
links, non-EAPOL plaintext is discarded. Hardware-decrypted CCMP requires
matching security metadata and group-1 PN; replay state is separate for each
key and TID, and advances only after valid peer/address/body admission. The
shared RSNA engine handles subsequent PTK and GTK exchanges; fresh installed
keys reset only their own PN windows.

Matching AP deauthentication/disassociation closes packet admission and queues
firmware teardown. Disconnect waits for pending TX retirement, removes keys
and resets both WTBL entries, updates the BSS and returns to `ScanReady` only
after required replies. A timeout, cancelled control operation or uncertain
DMA/key state cannot become a clean reusable radio; a full reset/recovery path
is still required for those failure states. This is software model coverage,
not demonstrated RF traffic or DHCP/AP interoperability.

### 3.1 Implemented iwlwifi MLD station profile

The production Gen3 probe owns firmware/IML/PNVM bytes and schedules
initialization in executor context. It registers `wlan0` only after ALIVE,
PNVM, PHY initialization, NVM reading, and MAC/link configuration succeed.
Firmware command versions are checked before version-specific layouts are
used. The Sc/BE211 profile implements `WirelessNetIface` as follows:

- `get_wireless_info()` reports the real hardware MAC and NVM-enabled
  2.4/5 GHz channels and station mode. NVM antenna masks and SKU flags
  constrain HT/VHT to at most two spatial streams; MIMO-disabled SKUs
  advertise one. `phy_capabilities(band_mhz)` supplies HT capability bodies
  for 2.4/5 GHz and VHT for 5 GHz to nl80211 and active probe templates.
  HE/EHT are not advertised. HT registration requires supported firmware
  Block Ack command/notification versions.
- `scan()` runs bounded passive or active scans, applies SSID/channel filters,
  and retains at most 256 BSS records. Association selects a matching
  cached BSSID/SSID/channel. Active scans emit wildcard or up to 20 directed
  probes, allowing hidden-SSID discovery. Only channels permitted for active
  transmission by both the signed host policy and firmware MCC receive a
  probe bitmap; DFS and disallowed channels remain passive. The lowest
  applicable power limit is programmed before scanning. Without a host
  policy all channels remain passive.
- `associate()` configures a negotiated PHY/link/peer, allocates management
  and data queues, authenticates, and associates. Supported/basic rates are
  intersected with the AP; mandatory unsupported PHY/rate selectors are
  rejected. HT supports 20/40 MHz and VHT supports 20/40/80 plus contiguous
  160 MHz, with
  common MCS masks, short guard intervals, peer LDPC reception, SMPS and
  HT protection programmed into TLC v6, peer and link commands. VHT MCS9
  is excluded at 20 MHz for the supported one/two-stream profile.
  Association responses confirm capabilities and can narrow the negotiated
  profile. A subsequent beacon that changes the negotiated PHY constraints
  closes the controlled port and requires reassociation; live channel/PHY
  migration is not implemented. All occupied 20 MHz channels and the complete channel span must
  satisfy host and firmware regulatory limits, including bandwidth and power;
  the response's final span is revalidated. TLC v6 adapts data rates within
  that intersection. WMM negotiation
  enables BK/BE/VI/VO hardware queues with AP EDCA parameters and QoS headers.
  For an HE AP, the association response's complete extension-38 MU-EDCA
  Parameter Set is parsed in the same BE/BK/VI/VO order and each AC's legacy
  WMM update is immediately followed by its incremental
  `WMI_WMM_PARAM_TYPE_11AX_MU_EDCA` update (ECW exponents remain unexpanded),
  before that AC's U-APSD policy write. Associated-station beacon handling
  tracks the WMM and MU-EDCA four-bit parameter-set counters as one
  generation: a changed generation reuses that same per-AC sequence, while a
  repeated generation does nothing. The counters are latched before malformed
  WMM-record rejection, preventing a broken AP from retriggering the same bad
  update on every beacon. If the association response does not provide a
  complete valid WMM parameter set, the station retains QoS with mac80211's
  defaults and disables subsequent WMM beacon tracking rather than switching
  back and forth between invalid and valid layouts.
  DSCP classifies kernel traffic; explicit AC rings preserve daemon priorities.
  Categories requiring admission control downgrade to an admitted category.
  Association supports Open, WPA2-PSK, and WPA3-Personal (SAE) with
  CCMP-128. WPA3 runs the SAE (H2E, group 19) commit/confirm exchange in
  the driver, derives the PMK, and completes the AKM-SAE 4-way handshake
  (SHA-256 KDF-Length PTK, AES-128-CMAC EAPOL-Key MIC, Key Descriptor
  Version 0). The IGTK from message 3 is installed into a BIP-CMAC-128 key
  store (`wireless::mfp`): group-addressed robust management frames are
  MMIE-verified on receive and a forged or unprotected deauthentication /
  disassociation is dropped instead of tearing down the link (the 802.11w
  forged-broadcast-deauth defense), and the station's own disassociation is
  sent with the Protected bit set. WEP and TKIP remain unsupported. A configured host regulatory domain and
  firmware MCC permission are required before transmission. The selected
  rule's power ceiling is applied through the firmware power command.
- WPA2 authenticates the original EAPOL PDU before changing key/replay
  state. Pairwise/group keys are installed in firmware. Repeated M3
  messages cannot reinstall keys, and repeated GTK material cannot reset
  RX counters. RX checks MIC status and per-TID packet numbers before
  delivering plaintext Ethernet. The controlled port opens only after
  key installation and message-4 TX completion. Group and pairwise rekey are
  supported. A new pairwise challenge uses a fresh SNonce and keeps the active
  PTK until authenticated M3 succeeds. Key replacement drains TX and discards
  RX captured across the transition before
  resetting replay state. Identical key material is never reinstalled.
- HT/VHT TX A-MPDU setup and retries are firmware-managed. Compressed BA
  notifications retire validated cumulative TX intervals. RX immediate
  Block Ack sessions negotiate up to 64 MPDUs per TID, with at most eight
  sessions. ADDBA/DELBA, firmware BAID v2 allocation/removal, BAR and frame
  release notifications drive host reordering across 12-bit sequence wrap.
  Holes release after 100 ms; nonzero negotiated inactivity timeouts tear
  down sessions. Authentication/admission precedes buffering; ordered
  delivery advances CCMP packet numbers. Key changes discard buffered
  old-key MPDUs. Repeated ADDBA requests preserve an existing matching
  session. Control work is bounded and restricted to the associated AP.
  Firmware-deaggregated standalone A-MSDUs require ordered subframe indices;
  equal PNs are allowed only within the same key's aggregate. A-MSDU inside
  A-MPDU and host TX A-MSDU construction are not negotiated.
- `disassociate()` closes the port, removes RX BA sessions, drains TX,
  removes TX queues and the peer,
  deactivates/detaches the link, and removes the PHY. Cancellation or a
  transport error leaves the interface down; the next scan/associate
  resets hardware before accepting another operation.
- `set_config()` currently accepts the already-associated channel with
  no power override. Channel changes require reassociation; explicit
  runtime power overrides return `NotSupported`.

The best-effort Ethernet path is registered with both the capability frame
registry and the kernel interface registry. It converts Ethernet and
unfragmented 802.11 frames after any required reordering/deaggregation.
Synchronous network waits can
drain RX without polling the executor recursively. Background work uses an
async mutex and MSI-X completion waits with bounded watchdog timers; it does
not hold an IRQ-safe lock across an await. RX queue 0 and non-RX causes use
separate MSI-X table entries sharing one owned host vector. The hard IRQ
acknowledges/rearms and latches error causes; the task drains DMA. Waits
snapshot the IRQ count before reading completions, including command waits
that own the async mutex. Each of the four TX tasks waits on its Ethernet
ring's waker and retains accepted frames while waiting for hardware queue
credit. Credit waits drain DMA under the async mutex and fail the transport
after a bounded timeout; only validated completions release descriptors.
Shutdown masks device and PCI delivery and synchronizes handlers
before releasing their cookie/vector; restart restores IVAR/UMAC routing.
160/80+80 MHz, HE/EHT, 6 GHz, roaming, and suspend/resume remain outside
this station profile (advanced PHY/offloads are assigned to Stage 6).

### 3.2 DMA lifetime and completion contract

AX210 uses 32-byte RFH completions; Bz/Sc uses 4-byte completions. Both use
16-byte transfer descriptors and buffer IDs rather than completion order.
Only published IDs may be completed, and a buffer is reposted only after
its packet has been copied. Fragment chains are discarded as a unit.
Descriptor writes precede doorbells through a DMA visibility barrier.

Command and data payloads remain allocated until a validated completion.
Command replies must match the outstanding command and sequence; unsolicited
notifications cannot reclaim command DMA. Legacy TX responses advance
exactly one owned descriptor. Aggregated queues accept cumulative compressed
BA and single-frame retry completions. Every queue/station/TID and every
reclaimed descriptor is validated before any DMA is released; malformed
multi-queue reports cannot partially reclaim buffers. A timeout never frees
DMA on its own.
Reset/drop releases resources only after the hardware DMA-stop handshake
and PCI bus-master disable succeed; otherwise allocations are quarantined.
Firmware sections, boot context, scratch, and PNVM remain owned throughout
the running device's lifetime.

These contracts have QEMU software regression tests. QEMU does not emulate
the target Intel radio: successful DMA, RF operation, AP association and
IP traffic on BE211 still require silicon validation. The existing Gen2
probe is separate and does not inherit the MLD station implementation.

Validation on 2026-09-29: full QEMU suites returned 8,905 pass / 0 fail /
79 skip on x86_64 and 6,725 pass / 0 fail / 40 skip on aarch64. After the
final SSID-connect and TX-credit changes, focused wireless/control suites
returned 522 pass / 0 fail / 7 skip on x86_64 and 231 pass / 0 fail / 0 skip
on aarch64. Both
production boot smokes and btrfs interoperability postflights passed, as
did debug/release builds on both architectures. The host xtask suite
passed all 66 tests; trusted-key build-parser tests passed both cases.
Formatting and Clippy on the affected kernel libraries and xtask passed.
These results validate software contracts, not target-radio operation.

## 4. Interaction with `narf-wireless`

- **Registration**: Drivers register via `bus::register_wireless_driver(MatchEntry { ... })`.
- **Handoff**: On successful probe, the framework mints a `Cap<WirelessIface, _>` and registers it with the global `IfaceRegistry` (see `net/spec` §3).
- **Control Path**: High-level calls like `scan()` are dispatched to the driver's `WirelessDriver` implementation.

The implemented high-level control trait is `narf_wireless::WirelessNetIface`.
The `nl80211` family bridges explicitly delegated scan/connect/disconnect
requests to this trait and publishes asynchronous completion events.
`ScanRequest` carries the cfg80211 random-MAC address/mask pair and the
colocated-6-GHz scan intent. A driver advertises
`supports_scan_random_mac()` only when firmware implements it; nl80211 then
sets `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR`, rejects random scans while
associated, applies Linux's default locally-administered/unicast mask when
userspace omitted one, and preserves only masked address bits. The driver
receives the resulting WMI-facing value rather than trusting raw netlink
attributes. Colocated 6-GHz is retained separately because it is valid
without an nl80211 feature flag but only has an effect on firmware with
per-channel scan configuration.

`max_scan_ie_len()` also binds wiphy discovery and the pre-dispatch probe-IE
byte limit: ath10k reports 256 and accepts bounded complete elements for active
scans; the compatibility default remains 512. Its native PCI diagnostic API
`scan_active_with_ies` uses the same validation and retained active-scan owner.

ath11k supplies Linux WCN6855's 512-station `hw_params.num_peers` value as
`max_ap_assoc_sta` to the generic wiphy encoder. This registration limit is
intentionally distinct from the 16-peer startup resource request sent by
`ath11k_init_wmi_config_qca6390`; it communicates cfg80211's physical-radio
contract without pretending to reserve firmware peer slots against concurrent
use.
For Linux-equivalent wiphy discovery, ath11k also supplies the three static
`ath11k_iftypes_ext_capa` records: a default record plus station and AP
records. Their exact `EXT_CAPA`/mask bytes advertise extended channel
switching, MBSSID, operating-mode notification, role-appropriate TWT, and AP
EMA support only where the existing MAC paths implement it.
Its top-level mac80211 Extended Capabilities remain distinct because WCN6855
is `SUPPORTS_ONLY_HE_MULTI_BSSID`. The physical wiphy also exposes the three
addresses generated by `ath11k_mac_setup_vdev_params`, permits management TX
on an active ROC, and advertises two CSA countdown counter locations, all of
which the existing vdev/ROC/CSA paths enforce.
The trait also carries physical-wiphy identity and an optional virtual-vdev
lifecycle: drivers that implement `wiphy_id`,
`supports_virtual_interfaces`, `new_virtual_interface`, and
`delete_virtual_interface` are exposed as one `GET_WIPHY` radio with several
`GET_INTERFACE` netdevs. Allocation is invoked by `NEW_INTERFACE` against
the physical wiphy; deletion hides the target interface before the driver's
asynchronous firmware teardown completes. A driver must not expose a freed
firmware slot until that teardown has completed, and must refuse deletion of
its physical root netdev.
Drivers with multiple vdevs also return `interface_combinations()`. nl80211
serializes it as `NL80211_ATTR_INTERFACE_COMBINATIONS` (per-type limits,
total interface cap, channel cap, beacon-interval rule, and DFS radar
widths), so a userspace network manager can validate concurrency before it
creates a netdev rather than discovering a firmware-slot failure afterward.
The driver must enforce every advertised total and operating-channel limit
against the physical radio, not independently per virtual netdev; a pending
association, AP start, or channel switch reserves its requested exact MHz
context until it succeeds or rolls back.
WoW-capable drivers may additionally expose `WowlanSupport::net_detect_*`.
This admits cfg80211's nested `NET_DETECT` scheduled-scan-shaped policy only
for low-power wake network-list offload: SSID/RSSI match sets, probe SSIDs and
frequencies, one or two plans, delay, retained probe IEs, and an optional
random-MAC pair. nl80211 serializes the matching wiphy limits and
`NL80211_FEATURE_ND_RANDOM_MAC_ADDR`; drivers must reject this policy unless
their firmware NLO service can consume it during the later WoW transition.
Drivers may expose `sar_capability()` for a physical radio BIOS SAR table.
nl80211 emits its fixed ranges as nested `NL80211_ATTR_SAR_SPEC` metadata and
advertises `SET_SAR_SPECS` only when the driver supplies that capability. The
set operation accepts the power type and a non-duplicate subset of range
indices; it is radio-wide, retains the full desired firmware table, and must
be replayed after firmware recovery or a cold system-resume before traffic is
allowed to resume.

The common CYW43439/BCM43602 facade supplies `power_save_default() = Some(false)`
and accepts `set_power_save(bool)` as a desired policy. Its existing retained
worker coalesces requests and runs `station::Station::set_power_save` under the
same async mutex as scan/association/packet control. Firmware receives
`BRCMF_C_SET_PM` (86, PM_FAST=2 or PM_OFF=0), then `pm2_sleep_ret=2000 ms`,
matching the default cfg80211 policy. The station records applied state only
after both correlated replies. An in-flight completion cannot overwrite a
newer request or reopen admission already closed by a concurrent disconnect.
Power completion may publish peer loss, never new carrier. Failure or cancelled control ownership closes carrier/queued TX
and poisons reuse; later policy requests return ENODEV after terminal failure
is observed. nl80211 GET reports the accepted desired policy, as with the
existing ath11k queued control path. No power request grants carrier/key
authority, and host SDIO/PCIe access remains awake and polled.

An AP driver with firmware support for multiple BSSID advertisements returns
`mbssid_support()` at physical-wiphy scope. nl80211 then emits the nested
`NL80211_ATTR_MBSSID_CONFIG` capability (maximum interfaces and EMA profile
periodicity) and admits `START_AP`'s MBSSID configuration, complete element
lists and EMA RNR lists. The driver resolves `TX_IFINDEX` only to an AP vdev
on the same physical radio; it must send the target's transmitting /
non-transmitting / EMA flags during vdev start, then send the transmitter
BSSID and `index` / `1 << bssid_indicator` at vdev-up for a non-transmitting
profile. The transmitter owns one complete ordinary template or all EMA
templates. A non-transmitting vdev is deferred until those templates exist;
once it is up the driver must not send it a replacement beacon template when
the target forbids that sequence. Deleting a transmitting virtual netdev
also schedules deletion of all of its registered non-transmitting children.
An AP driver with a six-GHz band advertises the FILS-discovery and unsolicited
broadcast-Probe-Response extended feature bits. It parses Linux's nested
template/interval attributes on `START_AP` and `SET_BEACON`; an empty nested
attribute explicitly deletes the selected family. Firmware receives FILS
first when both values are nonzero, otherwise unsolicited Probe Response, or
a zero-interval disable. `CHANNEL_SWITCH` retains an unsolicited-response
change and sends it only after the new channel's vdev restart.
When the WCN RTT service is available, the AP wiphy also exposes
`NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER`. Its enabled nested FTM responder
request, including optional LCI/Civic Measurement Report bodies, is retained
at AP scope and results in the responder-role vdev parameter after AP start,
SET_BEACON or a CSA restart.
With `WMI_TLV_SERVICE_AP_TWT`, START_AP also accepts the empty
`NL80211_ATTR_TWT_RESPONDER` flag. After vdev-up ath11k sends the same
default `WMI_TWT_ENABLE_CMDID` parameter block used by its station requester;
AP stop sends `WMI_TWT_DISABLE_CMDID`. The pdev operation is best effort and
never reverses an otherwise completed AP transition.
`START_AP` also accepts the Linux `NL80211_ATTR_HE_OBSS_PD` nested spatial-
reuse policy: mandatory SR control, optional 1..=20 offsets and exact
eight-byte SRG color/partial-BSSID bitmaps. After the AP vdev is up, ath11k
programs the pdev's threshold, per-AC and SR-prohibit parameters; firmware
with `WMI_TLV_SERVICE_SRG_SRP_SPATIAL_REUSE_SUPPORT` additionally receives the
six exact SRG/non-SRG bitmap commands. A WMI failure is reported without
undoing the AP transition.
When `WMI_TLV_SERVICE_BSS_COLOR_OFFLOAD` is available, the wiphy exposes
`NL80211_EXT_FEATURE_BSS_COLOR`. The AP path retains the mandatory 1..=63
HE BSS color and disabled/partial flags from START_AP, SET_BEACON or a
post-CSA beacon. After the vdev is up it sends both the 5-second AP OBSS-color
collision configuration and `WMI_VDEV_PARAM_BSS_COLOR` (color at bit 24, or
the disabled bit); either WMI failure is reported without undoing the AP
transition. `WMI_OBSS_COLOR_COLLISION_DETECTION_EVENTID` detection events are
coalesced for 500 ms before their MLME `NL80211_CMD_OBSS_COLOR_COLLISION`
notification; disable/free-slot events are intentionally not published.
For an MBSSID transmitter, each ordinary BSS-color update and every accepted
color-transition start/final/abort state is queued onto the live
non-transmitting profiles as well. Their independent vdev workers apply the
same color/enabled state, matching mac80211's propagation from a transmitting
BSS configuration without cross-vdev WMI locking.
The same feature enables AP-only `NL80211_CMD_COLOR_CHANGE_REQUEST`: the
driver validates its one temporary beacon counter offset and optional Probe
Response offset, uploads each countdown template through the ordinary beacon
WMI path, temporarily disables the BSS color, then restores the retained
post-change template and requested color. It emits MLME
COLOR_CHANGE_STARTED/COMPLETED or restores the prior template/color and emits
COLOR_CHANGE_ABORTED on an asynchronous failure. Color changes reject a
non-transmitting MBSSID profile or active CSA; an incoming CSA aborts an
active color transition as mac80211 does.
Probe can load a signed `wireless-regulatory.bin` deployment policy via the
firmware registry (wire format in `wireless/` §3.5). A trusted service launcher
uses `net::stack::control_registered` with its interface/daemon capabilities,
then `userspace::network_daemon::prepare` (or
`spawn`) with the loaded executable. This grants the service's ordinary
netlink sockets without attaching the L3 frame path to XDP. Executable
selection and boot service policy belong to the launcher. Actual supplicant
interoperability, provisioned policy and target hardware still require an
end-to-end integration run.

A `wireless/nl80211` regression test (`smoke_nl80211_supplicant_interop`)
replays the exact exchange `wpa_supplicant` drives through libnl —
`CTRL_CMD_GETFAMILY("nl80211")`, `GET_WIPHY`, `GET_INTERFACE`,
`TRIGGER_SCAN`/`NEW_SCAN_RESULTS`, `GET_SCAN`, `CONNECT`, `DISCONNECT` —
through the production generic-netlink dispatcher and multicast event sink
against a mock offload station, asserting the family id, the scan/mlme group
ids (18/19), the advertised commands/cipher/ext-features, and the connect and
disconnect event payloads. All command, attribute, nested sub-attribute,
cipher/AKM suite, ext-feature and errno values are validated against
`/usr/src/linux` `include/uapi/linux/nl80211.h` (6.17-rc2). This proves the
software contract a supplicant depends on; it is not a silicon test.

WPA3-Personal (SAE) is wired through the same control plane. A driver that
sets `WirelessNetIface::supports_sae_offload()` advertises
`NL80211_EXT_FEATURE_SAE_OFFLOAD`, and `CONNECT` decodes the SAE attribute set
(`NL80211_ATTR_SAE_PASSWORD`, AKM `00-0F-AC:8`, SAE auth, required MFP, CCMP)
into `SecurityConfig::Wpa3`, selecting a WPA3 BSS and emitting the connect
event (`smoke_nl80211_wpa3_sae_connect`). The iwlwifi station profile
implements this end to end: it advertises SAE offload, runs the SAE
commit/confirm exchange (`wireless::sae`, H2E group 19) as algorithm-3
Authentication frames, and completes the AKM-SAE 4-way handshake
(`security::Akm::Wpa3Sae`: SHA-256 KDF-Length PTK, AES-128-CMAC MIC, Key
Descriptor Version 0). The IGTK is installed and 802.11w management-frame
protection is enforced on the management RX/TX paths via `wireless::mfp`
(BIP-CMAC-128 MMIE verification of group-addressed robust frames, dropping
forged/unprotected deauth/disassoc). The SAE exchange honors an AP's
anti-clogging-token request (status 76), echoing the token in an H2E
Anti-Clogging Token Container element on a bounded Commit retry.

Roaming is supported: a connect request targeting a different BSS of the
current ESS (`WirelessNetIface::connected_bssid` differs from the target) is
routed through `WirelessNetIface::roam`, which reassociates — a Reassociation
Request carrying the previous AP address, re-auth, and a fresh 4-way handshake
with the new AP — and the control plane publishes an `NL80211_CMD_ROAM` event
rather than `CONNECT`. `Connection::protect_group_mgmt` provides the
BIP-CMAC-128 MMIE *emission* counterpart to inbound verification (the
transmit hook an AP/mesh send path would use); station mode never emits
group-addressed robust management frames, so it is exercised by a
protect/verify round-trip test. The ath11k WCN6855 profile implements an
AP/GO vdev control and Ethernet data path (`SET_INTERFACE` while down,
`START_AP` / `STOP_AP`, exact 20/40/80/160 or 80+80 channel definitions,
beacon-template replacement, per-client native-Wi-Fi FromDS TX/RX, and
explicit peer create/associate/delete). AP station records retain WMM, U-APSD,
PMF, and legacy/HT/VHT/HE capability inputs and are intersected with the radio
before WMI peer association; target AP-PS programming owns client buffering
and beacon TIM maintenance. AP IGTKs are software BIP-CMAC-128/256 or
BIP-GMAC-128/256 keys (never WMI keys); default-management-key selection
controls group robust-management MMIE TX, while per-client PMF uses
CCMP-family management PNs. The in-kernel WPA3
station path recognizes SAE-PK fingerprint passwords even when their SSID and
password arrive as raw netlink octets, derives the SAE-PK KEK, and refuses the
association unless the AP Confirm's encrypted Modifier, fingerprint and ECDSA
KeyAuth transcript proof all validate. Management-frame authentication and
association for an external SAE supplicant remain owned by hostapd through
registered management frames. These paths have not been run on target silicon
in this implementation pass.

## 5. Buffer Management

- **Data Path**: Uses standard `DmaBuffer` caps provided by `io/spec`.
- **Management Path**: Dedicated `MgmtRing` carries `DmaBuffer` caps for 802.11 management frames (Beacons, Probes, etc.).

## 6. Regulatory Enforcement

Drivers must not transmit until a regulatory domain is set.
The implemented bootstrap is `narf_wireless::reg::db::ensure_domain()`
([shared wireless §3.5](../../../wireless/specification/spec.md#35-deployment-regulatory-policy)).
It preserves a caller-installed domain or loads the exact signed
`wireless-regulatory.bin` through the firmware registry. Intel, MT76, ath10k
and the CYW/BCM FullMAC station entrypoints use it independently of probe
ordering; missing/unsigned/invalid policy grants no new transmit permission.
Board calibration and firmware channel permissions remain separate mandatory
intersections. The image builder supplies deployment signing keys and policy;
driver startup does not infer a country from an AP or rely on a userspace
wireless daemon to establish that authority. The shared wireless specification
owns the in-kernel station/security and capability-gated nl80211 contract.

## 7. Stage Assignment

- **Stage 4**: Initial framework and `WirelessDriver` trait.
- **Stage 5**: First hardware driver (MediaTek MT76 series).
- **Stage 6**: Multi-band (6 GHz), beamforming, and advanced offloads.

## 8. Dependencies

- **Consumes**: `drivers/spec`, `wireless/spec`, `bus/`, `io/`, `capabilities/`.
- **Provides to**: `narf-wireless` subsystem.
