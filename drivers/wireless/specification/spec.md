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
Each row names the family's initial station profile and its main
extensions. The family specification is normative for the current profile,
and the ledgers below list the remaining work.

| Driver | Generation | Status | Mechanism |
| :--- | :--- | :--- | :--- |
| **iwlwifi** | Gen3 MLD station (AX210, Bz, Sc/BE211), qualified Gen2 (AX200/AX201) Open/WPA2 station | Gen3 runtime and retained Gen2 PCI/netdev/worker composition; admitted profiles add contiguous 160 MHz, 6 GHz, EHT, roaming, AP and P2P | Exact API77 discovery, current signed power/firmware/PCI publication fences, native scan/MLME/keys/RX epochs, encrypted data/rekeys and ordered local retirement. P2P, Gen2 WoWLAN and Sc/Bz multi-link MLO are implemented pending validation; assets and firmware/RF acceptance remain — `iwlwifi.md` |
| **ath11k** | WCN6855-family and native QCA6390 profiles | Live station/runtime profiles; hardware acceptance pending | Native PDEV power telemetry with generation-scoped query/cache ownership; QCA6390 uses native IPQ8074 RX descriptors and four-vdev resources; QCN9074, WCN6750 and the IPQ AHB profiles are tracked as chip rows — `ath11k.md` |
| **mt76** | MT7921/MT7922 CONNAC2; MT7925 CONNAC3 | Legacy/HT20/40/HE station on 2.4/5 GHz, 5-GHz VHT20/40/80 and actual-MT7922 contiguous 160 MHz; AP, P2P, monitor, WoW and system PM on the built-in driver | Native WMM, directional LDPC/RXSTBC1/HT greenfield, native RF/RLM/full rate maps with conservative power headroom, recipient and originator BA and hardware TX A-MSDU. MT7925 adds the CONNAC3 register/DMA layouts, UNI MCU, MLO and KEY_V3; its probe chip-id gate stays closed until `MT_HW_CHIPID` is read on silicon (#2494) — `mt7921.md`, [`mt7925.md`](../mt76/src/mt7925.md) |
| **rtw88** | RTL8822CE and RTL8821CE initial stations; RTL8822BE identification | Distinct signed-board-power-gated channel 1 station profiles through kernel DHCP | Separate L/H/R/T qualifications add response-bound WMM/HT20, recipient BA and bounded four-slot native sender aggregation over each original radio/DMA owner; current publication checks, real assets/RF acceptance remain — `rtw88.md` |
| **rtw89** | RTL8852B initial 2T2R profile; other AX/BE prerequisites | Retained reset/cold/firmware/full radio/native station with source-controller/packet kernel DHCP models | Separately qualified WMM BE/TID0, native EDCA ACKs and QoS CCMP extend the existing radio/TXBD/RPQ owner; actual assets, reset handoff and physical qualification remain — `rtw89.md` |
| **rtlwifi** | RTL8188EE PCIe | Factory-qualified channel 1 native polled station through actual kernel DHCP | Separately signed HT20/LGI MCS0–7, bounded A-MSDU and native ADDBA refusal extend WMM/EDCA/QoS CCMP with exact executable/NEPC/NEHT binding and capture/key/publication epochs; physical qualification and wider profiles remain — `rtlwifi.md` |
| **rtl8xxxu** | RTL8188EU USB firmware profile | Signed-board-power-gated channel 1 native station service, Open/WPA2-PSK CCMP with retained RSNA and persistent USB RX/TX | Response-bound WMM, native EDCA/BE QoS and separately signed N8HT HT20/LGI MCS0–7, whole RX A-MSDU and native ADDBA refusal; actual calibration artifacts, physical qualification, reset/rejoin and wider profiles remain — `rtl8xxxu.md` |
| **ath10k** | QCA988x/QCA6174 and related PCIe parts | Retained RAW/non-PFC legacy/HT20 station on 2.4 GHz and qualified non-DFS 5 GHz HT20/40 | Six-dialect native WMM/HT40 with independently gated SGI40 and drained RTS/CTS submission, retained exact executable/BDF authority, RX BA/reorder/A-MSDU and final policy/port/source publication fences; RAW transmit aggregation remains capped at one MPDU — `ath10k.md` |
| **ath9k** | AR9285 revision 2 | Retained EEPROM/calibration, native non-EDMA and separately qualified channel 1 HT20/LGI station through kernel DHCP | Native HT20 MCS0–7, recipient BA/reorder, RXSTBC1, RTS/CTS and separately qualified two-MPDU sender BA retain current-policy and M4/RX-idle fences; wider channels and recovery remain — `ath9k.md` |
| **brcmfmac** | Explicit BCM43602 PCIe board profiles | Signed exact-host board selection, retained CR4/msgbuf and native 2.4/5 GHz FullMAC station through kernel DHCP | Firmware/inventory/AP-qualified HT40/SGI40 and 5 GHz VHT80 with genuine narrower native fallback, complete occupied-power/source and final IPC/callback epochs, required/bounded-optional PMF WPA2, station PS and ACK-fenced flow reuse; assets, wider silicon, recovery/system PM remain — `brcmfmac.md` |
| **cyw43439** | Infineon SDIO FullMAC | Standard PCI SDHCI/explicit card bootstrap through F2 station attachment | Native per-band capability/inventory gates admit HT40/SGI40 only with actual firmware/AP proof and full occupied-channel authority; otherwise HT20 remains; required/bounded-optional PMF WPA2 and station PS are implemented; board wiring, gSPI and reset/PM gates remain — `cyw43439.md` |

Each family crate also builds as a loadable `.ko` from the same source
(`--no-default-features --features module`). The modules carry the station
subset; rtw88 carries only its USB parts, and rtw89, rtw88 PCIe and
CYW43439 stay built-in only. §4 specifies what each module carries. QEMU
emulates none of these radios, so native and module tests are software
evidence only.

The completion target is **all eleven families with all features supported
by their target hardware and firmware ready for physical testing**. The initial
station profiles above are an intermediate milestone: scan, Open/WPA2, DHCP and
bidirectional IP with safe disconnect/failure ownership have composed software
evidence. They do not meet the target. Wider chip/PHY coverage, security modes,
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

The [per-chip inventory](../research/chip-inventory.md) records all 102 registered
bus identities, actual revision/firmware gates, native-path gaps and measured
source counts. It distinguishes aliases, catalog-only entries and rejected
devices; these counts are not a completion fraction. Its initial numeric
remaining-LOC forecasts were withdrawn after identifying overlapping work.

### Feature ledgers

Two ledgers track the remaining work. The
[remaining-features ledger](../research/remaining-features.tsv) lists
capabilities that are not implemented: a `feature` row names one missing
capability in one family, and a `chip` row one chip, host or profile
enablement. A capability missing from several families has a row for each.
The [pending-validation ledger](../research/implemented-pending-validation.tsv)
lists capabilities implemented in source that still await native validation
on both architectures and physical acceptance. Each pending row records its
family's most recent targeted kernel-test result, including known failing
cases. Hardware-inapplicable capabilities and external measurement/physical
acceptance gates appear in neither ledger. Every row links to family-spec
evidence. The counts are not an exhaustive hardware census, a completion
fraction or an effort forecast.

The remaining ledger holds **11** rows: one `feature` (rtw89 `eht`) and ten
`chip`. The pending-validation ledger holds **96** rows.

| Family | Open (remaining ledger) | Implemented, pending validation |
|---|---|---|
| iwlwifi | — | P2P, Gen2 WoWLAN, Sc/Bz multi-link MLO |
| ath11k | IPQ5018, IPQ8074 (chip) | QCN9074, WCN6750, IPQ6018 (chip) |
| mt76 | — | non-coherent DMA, P2P, per-domain IOMMU |
| ath10k | — | AP, P2P, station-client DFS, contiguous VHT160, RAW/PFC, hardware keys, recovery credential replay, Beacon hints, indoor regulatory admission, host-bus PM, wake offload, alternate calibration sources |
| ath9k | AR9462, AR9485, AR9565 (chip) | AR9285 idle FULL_SLEEP; AR5416, AR9160, AR9280, AR9287, AR9300, AR9580 (chip) |
| rtlwifi | RTL8192DE, RTL8723AE (chip) | 5 GHz, VHT, WoWLAN, BT coexistence; RTL8821AE, RTL8192EE, RTL8192CE family, RTL8723BE (chip) |
| rtl8xxxu | — | 5 GHz, VHT, BT coexistence; RTL8821CU, RTL8822BU, RTL8192EU, RTL8723BU (chip) |
| rtw88 | — | RF power and DPK tracking, all-TID originator BA, multiple devices, two-stream HT, operating reset, safe rejoin, system suspend, runtime sleep, additional channels, HT40, 5 GHz, VHT, 5 GHz TX A-MSDU, beamforming, WoW, radio coexistence, SMPS; RTL8822BE (chip) |
| rtw89 | `eht` (feature); RTL8852A, RTL8922A (chip) | multiple live functions, TX aggregation, RF power tracking, runtime sleep, monitor, host fragmentation, additional channels, 5 GHz, 6 GHz, wide channels, WoW, U-APSD; RTL8852C, RTL8851B (chip) |
| brcmfmac | — | AP, monitor, virtual interfaces, P2P, WoW, GTK rekey offload, nonzero descriptor prefixes, IOMMU quiescence; additional chip profiles (chip) |
| cyw43439 | additional host ports (chip) | confirmed stop, AP, virtual interfaces, P2P, transport reset, post-reset rejoin, system suspend and resume, WoW, GTK rekey offload, SDIO host DMA |

Applicability resolutions remove rows instead of adding them: ath9k
`tx_amsdu` (Linux ath9k never sets `IEEE80211_HW_TX_AMSDU`; `ath9k.md`);
the shared GLK membership selector (no open 802.11ak General Link reference;
mac80211 refuses GLK; [shared wireless spec](../../../wireless/specification/spec.md));
Intel cross-boot persistent key history (Linux establishes fresh keys/RSC
after reboot; `iwlwifi.md` §3.30); MT76 native old-key pipeline retirement
(Linux replaces PTK0 in place); and ath10k AP radar detection (upstream
`DFS_CERTIFIED` only; station-client DFS is a pending row).

Ordinary firmware station power save is implemented for CYW43439 and BCM43602
through the common retained FullMAC owner. System suspend/resume and wake
offload are separate ledger rows; host-bus PM remains open (host SDIO/PCIe
access stays awake and polled, §4.1). Native FullMAC attachment also observes
live shared regulatory DB replacement/clear, including paused control futures
and host data admission; firmware-cap epoch observation and firmware RF
quiescence remain distinct gates. Optional PMF with MFPC APs whose
association response omits the RSNE remains open. Actual authenticated
assets, board wiring, reset handoff and physical acceptance remain
deployment/test gates.

The public nl80211 scan limit follows each facade's `max_scan_ssids`: Gen3
Intel admits 20 active SSID entries and Gen2 advertises zero; ath10k, ath11k
and the common FullMAC facade admit 16, rtw89 eight, MT76, ath9k and rtw88
four, rtl8xxxu one, and rtlwifi zero. A cache-miss CONNECT uses passive
discovery for the zero-SSID profiles rather than issuing an unsupported
active probe; explicit active-scan requests still fail before dispatch when
the limit is zero.

## 1. Purpose & scope

**Owns:**
- The **Wi-Fi driver crates** under `drivers/wireless/`: the per-family
  `narf-drivers-wireless-{ath9k,ath10k,ath11k,brcm,iwlwifi,mt76,rtl,rtw}`
  crates, the shared `-ath-core`, `-core`, `-rtl-chip` and `-rtl-usb`
  crates, and the umbrella `narf-drivers-wireless` (`drivers/wireless/src`),
  built on the `narf-drivers` framework.
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

## 2. Hardware Abstraction: The `WirelessNetIface` Trait

Each driver's netdev implements `narf_wireless::WirelessNetIface`
(`wireless/src/lib.rs`), which extends the network stack's
`narf_net::Interface`. The required station surface is:

```rust
#[async_trait]
pub trait WirelessNetIface: Interface {
    /// Returns detailed information about the wireless interface.
    fn get_wireless_info(&self) -> WirelessIfaceInfo;

    /// Triggers an asynchronous scan.
    async fn scan(&self, req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError>;

    /// Initiates association with an Access Point.
    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError>;

    /// Disconnects from the current Access Point.
    async fn disassociate(&self) -> Result<(), WirelessError>;

    /// Configures PHY-level parameters.
    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError>;
}
```

Every other method has a refusing or empty default: wiphy identity and
virtual interfaces, scan limits and options, SME offloads, roaming, the
userspace-SME MLME path, AP/P2P/monitor roles, power save, WoW, SAR, CQM,
survey and the per-AC TX rings. A driver overrides only what its native
path implements; nl80211 advertises only what is overridden.

## 3. Queue Management (Access Categories)

MT76's registered station installs a read-only `DeviceControl::nic()` adapter.
Ettool can read its permanent MAC and the existing netdev packet/byte/drop
counters; GDRVINFO includes the firmware version actually returned by the MCU.
The adapter retains a weak reference to the exact active radio publication and
refuses stale/removal generations. Wired controls, register/EEPROM writes and
self-tests without a native implementation return EOPNOTSUPP.

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
PCI alias `14c3:0616` selects the MT7922 firmware pair. MT7925 is
registered the same way: PCI ids `14c3:7925` and `14c3:0717` match
(`name_for` gives `mt7921-7925` / `mt7925-0717`), and both select the
MT7925 patch/RAM pair (`mediatek/mt7925/WIFI_MT7925_PATCH_MCU_1_1_hdr.bin`,
`mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin`, per upstream
`mt792x.h:51,59`). The probe's chip-id gate still rejects anything
outside `{0x7961, 0x7922, 0x7920}`: no verified `MT_HW_CHIPID` value
exists for the `14c3:0717` card yet (upstream has no explicit MT7925
chip-id constant, only a `case 0x7925` firmware-name expectation), so
real-hardware probe stays closed until that value is read off the card.
Register translation is per-chip: `registers::plan` selects the fixed
table by device id. MT7925 ids (`0x7925`, `0x0717`) use the CONNAC3
table `FIXED_MT7925`, transcribed entry-for-entry from upstream
`default_fixed_map` (`mt7925/pci.c:178-232` at torvalds/linux
`8d7fe9885c62`); every other registered id keeps the CONNAC2 table.
Against CONNAC2 the MT7925 table adds windows `0x830c0000`,
`0x56000000`, `0x57000000`, `0x820ca000`, `0x820c4000`, `0x820b0000`,
`0x70020000`, `0x7c500000` (remap, length `0x200000`), lengthens PP
(`0x820cc000`, `0x1000` -> `0x2000`), shrinks the PCIe MAC window
(`0x74030000`, `0x10000` -> `0x1000`), and drops `0x820cd000`, which
has no MT7925 counterpart (addresses there now route through the
lengthened PP window). The sibling `mt7928_fixed_map` is not used.
Probe-time callers pass the PCI id (no effective id exists before
the chip-id gate); later callers pass the effective id. The
`mt76_mt7925_fixed_map_matches_upstream_default_fixed_map` golden
test asserts the table entry-for-entry against upstream, and
`mt76_mt7925_plan_uses_connac3_windows` asserts the dispatch, the
new windows, and both length changes through `plan()`.
Register translation and selector encoding follow the local Linux reference at `ecd997b0189a`.

MT7925 DMA uses the CONNAC3 queue numbering, not CONNAC2's: TX
MCU_WM is queue 15 and FWDL is 16; RX data is BAND0 queue 2 and the
MCU event ring is queue 0 (upstream `mt7925.h:218-241`). RX queue 1
(MCU_WM2, TX-done) is MT7928-only and is not wired for MT7925.
`dma::allocate_ring_set_for_chip` builds the five-ring
`mt7925_dma_layout` (TX data BAND0, TX MCU, TX FWDL, RX MCU, RX data
BAND0; upstream `mt7925/pci.c:710-742`) for either MT7925 PCI id and
the nine-ring MT7921 layout otherwise; `program_ring_set_for_chip`
programs each set through its own queue-id map, with the shared
disable/reset/EXT_CTRL/enable sequence on both chips. Linux ring
depths are TX 2048 / TX MCU 256 / TX FWDL 128 / RX 1536 / RX MCU 512
with an 8192-entry token table (`mt7925.h:27-43`); TXWI is 64 bytes
(32-byte TXD + 32-byte `mt76_connac_hw_txp`,
`mt7925/pci.c:1113`). The bring-up baseline still programs 16
entries per ring: the single-page `DmaBuffer` cap is
chip-independent, and the Linux depths land with the multi-page DMA
allocator.

### MT76 MCU/DMA firmware transport

`mt7921::firmware_transport::Firmware::prepare` validates and owns patch and
RAM images before device writes; `Firmware::open` obtains them through a
live firmware-registry capability. On x86_64 and aarch64, unsafe `Transport::new` requires
exclusive device/register-latch ownership, a permanent BAR mapping and
disabled PCI bus mastering. Without an IOMMU the programmed ring addresses
are physical. Under the opt-in per-domain IOMMU the function's default
domain maps every ring and frame buffer, the programmed addresses are its
IOVAs, and stop/reset blocks the function's DMA before rings are freed
(Linux `pci_dev_reset_iommu_prepare`/`_done`). A non-coherent function needs
a reserved `shared-dma-pool`. Both paths are implemented pending validation
(`mt7921.md` §5).

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
device commands.

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
20 MHz spacing), limited to firmware-reported bands. 6 GHz channels are
admitted only when the firmware reports `MT_NIC_CAP_6G`, and are scanned
passively under a NO_IR 6 GHz channel domain. Requests spanning more than
32 channels use the version-1 extension array with exact band/count fields.
The first scan configures an unassociated station VIF with unified
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
The shared native RX parser rejects zero/unsupported channels and decodes
6 GHz `CH_FREQ` values (181 and up) separately from 2.4/5 GHz channel
numbers. Authentication, association, EAPOL and connected packet RX must match
the retained station channel before peer admission or replay-state changes.

After successful radio initialization, `Mt76Iface` registers an exact shared
netdev/wiphy name and its real MAC for nl80211 scans. Its constructor
takes `(name, RadioInfo)` and rejects invalid identity. Active/directed scans
admit four SSIDs through the retained policy-bound path below; unsupported
channels/options are rejected before dispatch. `phy_capabilities` reports
the firmware-qualified HT/VHT bodies; the negotiated HT/VHT/HE/EHT and 6 GHz
station profiles are specified in `mt7921.md` §3. Random-MAC scans
(refused while associated), extra probe IEs up to `MAX_SCAN_IE_LEN` and
colocated 6 GHz scans on a 6 GHz-qualified radio are supported; mandatory
dwell requests fail explicitly. Frequency and channel lists must agree when
both are supplied. The link stays down and frame
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
privacy/RSN mismatches, unknown mandatory rates and TKIP-only profiles are
rejected. WPA3-SAE, PMF and the negotiated HT/VHT/HE/EHT and 6 GHz plans
extend this legacy plan (`mt7921.md` §3). WPA2 requests contain the exact negotiated
PSK/CCMP RSN IE plus supported rates; no PMK or temporal key enters the plan.
`JoinPlan::security()` returns the secret-free `SecurityMode`; the input
`Security` type redacts PMK bytes from debug output.

`Transport::associate_station_with_ies` additionally accepts optional SME IEs.
The request frequency/channel must identify the cached BSS. Malformed or
duplicate RSNEs, conflicting cipher/AKM/PMF/PMKID requests, RSNXE/FT, and
PHY/WMM requests outside the negotiated profiles fail before hardware/recovery
I/O. A matching
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
and an MLME state separate from controlled-port authorization. As in Linux
`mt76_connac_mcu_sta_cmd`, every enabled firmware peer carries
`CONN_STATE_PORT_SECURE`, which enables firmware packet processing only; the
host MLME/RSNA state and the copy-time RX gate still own data
authorization. Associated records require the AID observed by the plan; no
caller can mutate its phase directly.

### MT76 live join dispatch, WPA2 keys, and Ethernet data transport

`Transport::associate_station` requires an installed host regulatory policy
covering the entire 20 MHz channel. Permissions bind the selected channel;
2.4/5 GHz band fields are carried through channel domain, power limits, channel
switch, band-local STA basic rates and BSS PHY modes. The legacy profile uses
one TX chain and Open or WPA2-PSK/CCMP; the negotiated HT/VHT/HE, two-stream,
WPA3-SAE/PMF and radar/NO_IR profiles each have their own admission
(`mt7921.md` §3). The host half-dBm ceiling is sent in the
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
executor task. Cut-through payloads are published through bounded native
packet queues (`mt7921.md` "Native transmit queue and per-packet ownership");
each descriptor and buffer is reused only after both DMA completion and
firmware token release. TX completion polling preserves queued and newly received MCU replies.
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
errors and WDS/null frames. A-MSDU deaggregation, defragmentation and
non-RFC1042 LLC receive are specified in `mt7921.md` §3. For secured
links, non-EAPOL plaintext is discarded. Hardware-decrypted CCMP requires
matching security metadata and group-1 PN; replay state is separate for each
key and TID, and advances only after valid peer/address/body admission. The
shared RSNA engine handles subsequent PTK and GTK exchanges; fresh installed
keys reset only their own PN windows.

An A-MPDU subframe is reordered only under an active recipient agreement for
its TID. With none (never negotiated, still being set up, or retired) it is
delivered unreordered and meets the same PN check, as `mt76_rx_aggr_reorder`
leaves it queued; a Block Ack policy subframe on a TID with no agreement
queues one recipient DELBA (WLAN_REASON_QSTA_REQUIRE_SETUP) per TID until an
agreement activates again (mac80211 `ieee80211_rx_reorder_ampdu`,
`unexpected_agg`). Only a pairwise (PTK) EAPOL exchange retires the
agreements, as `ieee80211_pairwise_rekey` does: the recipient agreements
first, each ending with a DELBA to the AP (WLAN_REASON_QSTA_LEAVE_QBSS), then
the transmit agreements (`ieee80211_sta_tear_down_BA_sessions`). A Group Key
Handshake leaves them running.

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
This is the baseline MLD station. The continuations below and `iwlwifi.md` §3
extend it with contiguous 160 MHz, 6 GHz, EHT and MLD, roaming, AP, P2P and
Gen2 WoWLAN; 80+80 MHz remains outside the profile.

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

RTL8188EE provisioning metadata exposes `ht20_request_on_channel(channel)`
and `rate_fallback_request(channel)` for channels1–11. These return exact
factory/NEPC/executable program bindings; they confer no transmit permission.
Channel1 retains NEHT v2/NEFB v1, while channels2–11 require separately bound
NEHT v3/NEFB v2 records as specified in `rtlwifi.md` §3. These continuations
are software-validated in the retained profiles.

RTL8188EE also exposes exact-function `pci::with_controller_at(BusAddr, f)`
and async `pci::provision_at(BusAddr)`; the existing helpers select the first
bound controller for compatibility. Independent radios retain per-function
PCI, frontend, context-send and MSI ownership; this is software-validated.

`rtlwifi::set_pcie_aspm(bool)` selects next-preparation PCIe L0s/L1/CLKREQ
policy. Actual enabled parent policy, endpoint capabilities and native
hardware receipts gate endpoint entry; the shared bridge/common-clock
configuration remains platform-owned. This is software-validated.

RTL8188EU registers its original receiver as an administrative open/stop
target. Initial IFF_DOWN follows completed native USB/MAC/card park; UP
queues retained exact-image wake, and bound control returns Busy until
that transition finishes. DOWN closes admission immediately and retires
the old association before parking. Netlink IFF_UP and SIOCSIFFLAGS use
the existing current administrative handle; scan never creates UP. This is
software-validated (`rtl8xxxu.md` §3).

RTL8188EU idle active scan admits one directed SSID or a wildcard and
up to2048 bytes of structurally checked extra IEs. Each occupied channel
requires current transmit permission. Source pre/post-probe timing and
whole basic1 frame airtime bound mandatory dwell admission; actual USB
delivery and subsequent device TX-state retirement remain distinct. This
private emitter is software-validated (`rtl8xxxu.md` §3).

Sc/Bz MLD periodic scanning can retain the authorized serving station while
its exact delegated requester owns the scan. Native link0 timing, current
correlated MCC facts and unchanged home bounds fence data/key maintenance;
healthy exact-UID termination restores home ownership. API89 MVM remains
idle-only. This is software-validated (`iwlwifi.md` §3.61).

RTL8188EU associated passive scanning retains the same station, software
keys/replay/BA and host rings through qualified cold channel visits. Private
plaintext Null/QoS Null uses the peer's actual profile and shared sequence
ownership; native USB/device terminals remain distinct from AP reception.
Associated passive and active scans are software-validated (`rtl8xxxu.md` §3).

MT76's control-only P2P WDEV accepts source-bound REGISTER_FRAME before
START as host subscription metadata. Native management RX additionally
requires its actual started independent BSS, current finite ROC and a new
capture epoch after the completed native RX-prefix cut. Home data owners
remain separate. This is software-validated; management TX is described
below, and the P2P client/GO group roles are implemented pending validation
(`mt7921.md` §3).

RTL8188EU associated active scans retain the same home station, keys, BA
and host rings. One directed SSID or wildcard and bounded extra IEs use the
private native probe path after a real cold receive restart, including a
same-channel visit. Current qualified power, source response timing and
native USB/device terminals fence each visit; home PHY and peer state are
restored before normal data resumes.

The admitted API89/Sc/Bz Intel owner can select contiguous 5 GHz 160 MHz
from actual raw NVM flags and the complete eight-channel current host/MCC
span. Original shared PHY offers, source-specific VHT/HE TLC maps and native
RX admission retain negotiated bounds; unavailable wide spans keep a genuine
80 MHz offer. This is software-validated; `iwlwifi.md` §3.62 documents the
interface.

MT76's control WDEV can transmit unkeyed management frames on its actual
current finite 2/5 GHz ROC. Fresh occupied-power bounds, native OMAC/BMC and
PID/TXS plus DMA/TX_FREE receipts determine transmission and ACK status;
MLME multicast status retains the original WDEV/source/cookie. Home packet,
key and capture owners remain separate. This current-ROC scope is
software-validated; the private ROC/NO_CCK path below retains separate
native gates.

RTL8188EU HT20/40 LGI uses a distinct signed N8HT v2 qualification covering
the complete radio program and both emission spans. The retained owner
selects factory power by primary channel and tunes RF to the center, binds
each copied receive span to the current installed program, and cold-restores
20 MHz before key/data traffic when association narrows the offer. Current
host policy must admit the whole 40 MHz span even for a 20 MHz fallback.
Existing v1 qualification remains valid for its original profile. Native
validation is pending. The family §3 and `rtl8188eu-ht40.md` specify the
contract; real per-device qualification data remains externally supplied.

MT76 management FRAME can acquire a private native CNM lease when no public
ROC is active. Only its exact unsolicited grant authorizes publication, and
the granted finite response window survives TX status and borrower loss
until native abort/packet retirement completes. This private lease publishes
no public ROC events. Control-WDEV FRAME accepts the validated empty NO_CCK
flag and retains its choice through the actual 2.4 GHz descriptor rate;
legacy netdev/AP acceptance remains unchanged. Native validation is
pending. Qualified 6 GHz management TX remains open.

Intel Sc/API89/Bz station owners retain explicit 6 GHz band identity through
raw NVM tails, passive scan jobs, copied RFH descriptors and current host/MCC
publication proofs. The initial AP20/STA20 HE profile requires SAE-H2E/PMF
and exact AP power-type/TPE facts; the native AP power command completes
after link activation and before peer queues or first transmission. Both
native send paths recheck queued bound beacons at publication, including
after an async credit wait. CDB FIFO sizing uses the explicit band
(`iwlwifi.md` §3.63). Active/RNR and periodic discovery, response refinement,
live TPE and wider 6 GHz widths are separate continuations (`iwlwifi.md`
§3.65, §3.67; validation pending).

RTL8188EE HT40 uses a separately signed NEHT v4 full20/40 program while
preserving accepted v2/v3 assets. EE wide power follows its source-specific
center-channel factory lookup, intersected with primary-channel20 fallback
limits and measured per-rate bounds. The retained owner pauses actual MAC
transmission, reads back BB/RF/gains and restores20MHz before keys or DATA
when association narrows. DMA OWN resources remain retained throughout.
The family §3 and `rtl8188ee-ht40.md` specify the contract and external
per-device qualification requirement.

The admitted Sc/Bz EHT station and RTL8188EE RTS/CTS and conservative
thermal gain tracking retain actual native admission, current publication
and terminal ownership in immutable source snapshots. Optional unadvertised
EHT capabilities grant no additional operation; 320 MHz and MLO are separate
continuations (`iwlwifi.md` §3.64–§3.66).

AR9285 exposes `Ath9k::power_save_qualification_request()` as
`Result<PowerSaveQualificationRequest, BringUpError>` factual identity/MAC/
filename metadata. The existing `WirelessNetIface` power-save SET/GET carries
desired policy only. An optional current signed N85S1 full-program owner must
observe actual PM notice/PS-Poll ACK and native idle receipts, fresh TIM/AID
and actual clock/timer/RX-abort readbacks before NETWORK_SLEEP. Missing N85S1
leaves existing awake operation and refuses unsupported requests. Original
key/PN, BA, copied-frame and terminal DMA ownership remain independent.
Idle FULL_SLEEP and periodic calibration are separate implementations; the
family §3.9 and `ar9285-station-power-save.md` specify the exact contract.

### 3.3 Additional qualified native control owners

Admitted Intel Sc/Bz/API89/API77 profiles expose the existing typed AP public
controls through their original device owner, with actual power/beacon/peer/key
and terminal packet receipts. Prepared typed events complete arbitrary
callbacks before rechecking the original source/native receive proof, then
deliver using only the fixed original source and receiver. Optional unadvertised
AP PHY/DFS/P2P/MLO capabilities remain separate; family §3.68–3.71 is normative.

The managed ath10k Radio implements bounded1–500ms ROC and Public Action FRAME
through matching native foreign-channel, air-terminal, STOP/COMPLETE and home
receipts. Registered responses retain the original socket/filter/physical
generation and callback-free final checks. This supplies no native P2P role.
AR9285 exposes `periodic_calibration_request()` as factual
`Result<PeriodicCalibrationRequest, BringUpError>` metadata for a separate signed
N85P1 full program. Current P1 hardware receipts replace only calibration/ANI
state; original key/PN/TX/copy owners persist. P1 remains always awake and
refuses composition with N85S1. Family §3 and the measured-program documents
define the narrower native and external qualification contracts.

### 3.4 Counted native D0 power owners (validation pending)

AR9285 exposes `set_idle_full_sleep`, `idle_full_sleep_status` and
`acquire_idle_wake` through its original retained device. Only an admitted
unassociated Passive owner may retire actual queues/RX/IRQs and enter D0
FULL_SLEEP. Counted control users fence the transition; cold wake creates a
fresh20MHz identity before republication. Family §3.11 specifies the exact
receipt, cancellation and system-suspend barriers.

QCA6174/QCA9377 host-bus power management uses counted actual RTC/SoC wake
votes and retained MSI-driven quiet/grace ownership. ASPM restoration follows
actual HIF and input admission. Deferred native polling cannot commit packet,
key or copied-frame state, and non-MSI profiles keep the awake polling path.
Family §3 specifies the original DMA/source/control and failure-cleanup rules.

### 3.5 Additional queue and installation owners (validation pending)

Ath10k admits the bounded coherent RAW/10.4 PFC profile only with its actual
native qstate/peer/fetch/terminal owner. Its indoor-only channel continuation
requires the current trusted deployment's explicit installation fact on every
restrictive overlapping rule, preserving all original factory and host limits.
RTW88 `TxBaRequest` additionally returns factual v2 identity/filename metadata
for independently owned TIDs0–5; v1 remains unchanged. The public producer
selects a current same-TID FIFO prefix before reserving PN/SN, and each native
physical queue and terminal remains independently bound. Family §3 is normative.

Intel Sc/Bz exposes a bounded real control DEVICE with no IFINDEX, UP bit or
fabricated data endpoint. Original parent, Write/Admin/daemon and native owner
receipts govern its public ROC/management lifecycle. API89 Ty/So/Ma uses actual
PHY1/RLC/link1/broadcast-TID16 SESSION2 receipts; original API77 uses its physical
MAC1/PHY1, legacy broadcast/TID16 and SESSION1 with distinct signed tag8 purpose.
Both check the completed RFH prefix and original finite Frame Publication after
credit waits before actual packet publication.

The bounded GO9 continuation uses the retained AP/peer/key/data owner with
OFDM-only legacy20 rates and distinct native power/role receipts. API77 GO
requires its separate tag9 qualification. The original preparing GO capture
retains real NoA received during MAC ADD waits; probe projection requires the
same completed native prefix and open epoch. Actual software GTK/IGTK counters
supply sequence-only GET_KEY. Public FRAME/REGISTER retains the original GO
radio request/reservation through the same native AP owner, including WDEV and
NO_CCK forms. Family §3.73–3.76 records the partial scope. The CLIENT owner
follows; applicable native P2P power-save controls remain open.

CLIENT8 association/data uses actual MAC7 with a protected OFDM-only legacy20
program, original role/physical identity and bound P2P/WPS request/peer response.
Queued native broadcast Beacon NoA changes require the actual CTWindow command
receipt before packet publication after credit waits. API77 uses distinct tag10
qualification and restores inactive MAC5 only after terminal peer/queue/PHY
retirement. Family §3.77 defines this partial scope. The retained public
CLIENT FRAME/REGISTER worker stays separate (§3.78).

### 3.6 Native observations and thermal maintenance (validation pending)

Admitted C21 exposes factual `rtl8821c_power_tracking_request()` metadata for
distinct signed N21W qualification. Actual meter samples, all-rate factory and
original H/R/T/RTS ceilings, native queue/RX quiet and associated IQK receipts
govern maintenance; metadata alone grants no RF access. Power-only restore
retains original key/BA owners; loss after periodic IQK requires a fresh owner.
The family §3 and `rtw8821ce-power-tracking.md` define the measured contract.

Ath10k lifts only the admitted factory World passive layer using original
native ESS Beacon and exact START/FOREIGN dwell observations. Immutable
receipts retain original policy Arc, physical-radio lifetime and every occupied
20MHz constituent through waits and copied publication. Signed host NO_IR,
DFS, indoor and unknown restrictions stay independent. Family §3.2 is normative.

### 3.7 Independent native PCI functions (validation pending)

Admitted RTL8852B functions each retain their original BDF/source/reset,
firmware, power, DMA, key and IRQ owner. A bounded four-entry registry and
never-reused endpoint cookie route each netdev independently. Old ingress
holds its name through callback return before removal or rebind; system PM
blocks new probes and visits every original owner with rollback on failed or
cancelled preparation. Family §3 defines the original reclamation and native
receipt requirements; the feature grants no new chip or physical qualification.

RTW88 additionally exposes `provision_function(BusAddr)` and
`pci::with_controller_at(BusAddr, callback)` for an exact retained function.
Implicit `provision`/`with_controller` refuse ambiguous live radios. Each
original controller owns its provisioning mutex and worker; a nonwrapping
endpoint cookie and ingress-quiescent removal retain the original source,
key/PN, copied-frame and DMA-reclamation proofs. Family §3 is normative.

### 3.8 Native TLV AP control and packet owner (validation pending)

Ath10k's admitted RAW/HTT3 TLV owner uses the shared typed AP controls for
legacy20 Open/WPA2 and actual service-qualified U-APSD. Start/key-before-start,
peer/authorization, control/management, sequence-only GET_KEY and both packet
endpoints retain the original source, policy Arc, role and native/copy epochs.
Only actual synchronous native publication opens response windows; copied DATA
and management retain original peer fences, and queued loss is drained before
packet handoff without recapturing authority. Terminal cancellation cleanup
retains native DMA until real receipts, restores NSS/DCF and continues the
physical worker for a later explicitly admitted BSS. Unsupported protection,
PHY/security/P2P profiles stay refused before native mutation. Family §3.3 is
normative.

### 3.9 Bounded native FullMAC descriptor prefixes (validation pending)

BCM43602 shared7 admits prefixes1..4 within each original D2H ring item after
checked geometry at CR4 readiness and runtime attach, before DMA allocation.
Control/TX/RX retain their24/24/40-byte strides and original wrapped indices;
owned descriptor copies precede decoding and terminal reclamation. Event
buffers use the shared offset; DATA uses its explicit nonzero offset or that
shared fallback, with checked original-buffer bounds. Original firmware/PCI,
posted identities, transaction correlation, key/port and actual matching
terminal proofs remain mandatory. Family §3 defines the bounded profile.

### 3.10 Native primary-bsscfg FullMAC AP (validation pending)

The exact BCM43602 PCIe `Fullmac` adapter exposes the common async AP frontend
only with its retained native source. `PRIMARY_AP` and opaque original
`ap_enter`/`ap_send`/`ap_leave`, completed-prefix and peer-retirement contracts
default to unsupported for SDIO. Firmware owns AP SME and standard beacon/TIM/
DTIM generation; userspace owns WPA2 authentication through actual key/SCB
receipts. Prepared station/control events, DATA ring/stack copies and queued
TX retain original source, policy Arc, role, peer/key/port and native epochs
through final callbacks. Host staging, IOCTL completion or dropped waiters never
supply native packet/ACK/PN credit. Failure/cancellation drives retained original
physical teardown and pins uncertain mappings. Family `brcmfmac.md` §3 defines
the bounded legacy20 Open/WPA2 CCMP profile and explicit unsupported features;
CYW43439 keeps its independent AP row open. AP Program IOCTLs additionally
retain the original `Capture` through input/descriptor/index/doorbell publication
after native ring setup; definitely unissued refusal stays distinct from
entered uncertain issue. Ordinary station and physical Stop paths are unchanged.
Program SET additionally checks actual
completed native producers after H2D setup and preserves every queued transition;
GET remains scoped/read-only, and Session/pending filters share the same
native transition classifier. The existing case requires genuine loss delivery
after a denied stale SET and a successful retained-record query.

### 3.11 Original-owner runtime LPS (validation pending)

The admitted RTL8852B station exposes power-save preference only when its
current signed N52P joint operating program is loaded. The retained worker
owns actual verified firmware template IDs, controller peer, native command/
packet queues and RPWM/CPWM/restore receipts. Original source, peer, power and
admin-UP identity remain required at publication and after waits. A completed
native prefix and final HCI/backlog guard precede queue issue; unpublished Busy
retains ordinary ownership, while ambiguous publication pins mappings.
Ordinary DATA/control and BB tracking stay closed until actual wake restoration.
A dead RF/interface source cannot authorize a NULL-emitting wake; only current
original device authority and the sealed same-function temporal FLR receipt can
retire uncertain DMA. `OpenStopEvent::observe` supplies a nongrant observation
of the exact current original registration, including preserved-UP replacement;
old owners never follow a new registration. Family §3 is normative; physical
measurements remain external.

### 3.12 Native receive-only FullMAC monitor (validation pending)

The exact BCM43602 msgbuf adapter opts into the default-denied common
`PRIMARY_MONITOR`/Prepared/Armed/raw-copy seam. Actual firmware `rtap` evidence,
monitor/filter and channel readbacks precede activation; a pending raw-drain
reservation is no capture receipt. Only actual frame-type2 posted completions
with bounded native radiotap and an observed matching CHANNEL can reach the
original AF_PACKET monitor token. Original firmware/PCI, policy Arc, admin/
registration/MAC, mode and copy generations remain required at final publication.
Copied raw bytes never enter Ethernet or infer missing PHY/decryption facts.
A completed control prefix precedes publication while continuous raw traffic
need not become globally idle. DOWN/source loss/PM closes old copy/token first;
uncertain cleanup pins native mappings. Family §3 defines the exclusive20MHz
receive-only profile; CYW43439 remains default unsupported.

### 3.13 Separately qualified two-stream HT20 (validation pending)

The RTL8822CE HT request may expose an optional `two_streams` child only from
its original actual two-path hardware and complete factory fields. The child
is a nongrant proposal for the distinct N22H256v2 asset; the original v1 proposal,
record bytes and fallback remain unchanged. Actual source/backend queue-quiet
proofs, TX/RX parking and gain/path/reset/readbacks precede current original
source resume. Local RX16 and negotiated peer TX selection remain independent;
native RA/TXWD/RXD and timing cover only qualified uncoded MCS0..15. Existing
one-stream coding records cannot authorize coded two-stream emission. Family
§3 defines the complete profile and measured envelope. The independent
default-unsupported SDIO disable helper is specified
in `drivers/sdio/specification/spec.md` §3 and supplies no standalone Wi-Fi
stop/reset or feature credit.

### 3.14 Original-owner stop, reset, rejoin and monitor (validation pending)

CYW43439's native PIO transport supplies confirmed-stop success only after the
actual original host/IRQ, F2, CM3/D11/RAM, clock and F1 receipts; generic or gSPI
adapters remain unproved. SDPCM Runtime closes work before teardown and pins
uncertain owners. The separate opaque SDIO source retains actual native PCI and
nonreviving host/controller/card currentness; it grants no firmware, RF or DATA
permission. Its fixed-copy scope excludes hardware waits and arbitrary callbacks.

RTL8852B monitor uses fresh role7/NoLink with CMAC TX/autoresponses continuously
closed. Native source RF/channel observations and completed raw prefix precede
capture; only original current source/admission/admin/MAC/capture generations
can publish to AF_PACKET. Pending fixed-channel metadata earns no native receipt,
and no retune or new RF emitter is introduced. Existing signed v2 bytes remain
unchanged. Other channels, optional metadata and injection stay unadvertised.

RTW88 `reset_function` serializes its original BDF, retires old ingress and actual
native DMA, then performs current source card reset and factory identity checks
before a fresh cold firmware shell. `rejoin_function` preserves the original
netdev and uses explicit zeroizing pending credentials for fresh provisioning,
scan and native authentication; original new-UP identity remains a denial fence
through real publication. No old peer/key/PN or automatic credentials are replayed.
Family §3 sections are normative; physical acceptance remains separate.

### 3.15 Retained system suspend and cold resume (validation pending)

The RTW88 async family hook retains the original function barrier and hardware
worker through foreground cancellation. Only actual callback/DMA retirement,
card-off, PCI power-state/config and original-source DBI receipts permit a fresh
cold generation on the original netdev. Operating owners must earn new firmware,
calibration and policy before resume succeeds; unqualified cold shells gain no
RF admission. Old keys, PN/BA and queued packets stay retired, with fresh explicit
association afterward. The independent shared management-fragment
continuation preserves the original four-slot/key/PMF owner and grants no
native Wi-Fi feature. Family and wireless §3 contain
the complete contracts; physical system sleep acceptance remains external.

### 3.16 Source-qualified native host fragmentation (validation pending)

RTL8852B may expose the existing fragmentation threshold control only when its
original full joint N52F emitter is current. A retained native binding precedes
crypto; every immutable train owns one MSDU SN, per-fragment PN and exact native
terminal identity. Pre-issue refusal may defer without crypto retries; newly
pending input after issue denies the actual doorbell while preserving uncertain
DMA. Only matching DMA plus successful RPQ/body receipts advance the train.
RX parsing adds no emission permission and retains the original native source,
peer and cryptographic cache through complete reassembly. Family §3 defines the
profile. RTW88 runtime sleep composes on the firmware feature/wire and
unassociated IPS foundations (§3.18); they grant no new RF admission.

### 3.17 Native CYW43439 SDIO AP (validation pending)

CYW43439 advertises the primary-bsscfg AP only through the actual Card/SDHCI,
signed CM3 loader, F1/F2 and SDPCM/BCDC firmware-SME path with its original
typed source, native `ap` token and GET_AP0 discovery. Program IOCTL/DATA is
one whole zero-tailed F2 block COMMAND (padding inferred from Linux `sdio.c`,
not a board measurement); a fresh mailbox with pending RX defers an unissued
packet, and nothing is retried after issue. Ordinary RX denied at the ring is
never delivered to the stack. Family `cyw43439.md` lists the cases.

### 3.18 RTW88 associated nondeep LPS (validation pending)

RTW88 runtime sleep composes the committed unassociated IPS with associated
nondeep LPS on C21 CCK1/channel1. LPS H2C commands use a PS-specific mailbox
submission: after HMEBOX_EXT staging and immediately before the publishing
low word it re-checks the original PS source and the native Core RX-prefix
receipt; newly pending input leaves the command unissued for a bounded retry,
and nothing is retried after publication. Family `rtw88.md` lists the cases.

### 3.19 RTL8723BE native CFO and linked ATC

The original native RX owner retains signed path CFO samples and a
wrapping packet counter separately from lazy DM initialization. Only
error-free non-CCK frames with a complete PHY prefix and the currently
programmed BSSID contribute. Disconnect clears that BSSID. The linked
watchdog consumes fresh samples once, after RA refresh, and follows the
RF_1T1R path-A ATC/crystal adjustment. The initial crystal cap is retained
separately from the adjusted cap. Register access uses the same owner's
authority and terminal failure handling; a CFO sample grants no TX or
calibration authority. The family spec records hysteresis, clamps,
remaining DM work and native regression coverage.

### 3.20 AR9003 live MCI duty-cycle service

AR9462/AR9565 share one `MciLink` between the hardware owner and EDMA
packet engine. Driver timer defaults and profile GPM updates feed timed
stomp/no-stomp weight writes through that original packet port.
`Engine::coex_wait_us` reports a relative deadline to the existing async
netdev worker, which releases the station lock before waiting and services
due edges without requiring an interrupt. Reset, stop and WoW cancel the
deadlines; successful resume starts a fresh period. Current authority and
register checks remain mandatory for every write. Profile priorities are
copied into the weight engine; concurrent-TX enablement still requires
RSSI and calibrated power-policy integration. Associated-beacon RSSI now
also drives the source fifth-weak-period AUDIO selection; association
resets marker 127 while timer/profile pauses preserve history. The
configured profile still determines the later no-stomp edge. FTP requires
native network-sleep/traffic inputs. The family spec §3.12 owns
the source timer boundaries, lifecycle and failure contract.

### 3.21 Driver construction and recovery storage

AR9300 station and ath11k runtime/netdev construction reserve the final
`Arc` allocation before initializing the large owner; an allocation is
published only after every field is initialized. Gen2 USB station handoff
retains its radio in a box across the construction boundary. AHB bring-up
and transport recovery use the existing pinned heap-future wrapper, with
the original future and cancellation guards retained. These construction
boundaries keep large values out of their callers' kernel stack frames;
they do not change capability checks, hardware sequencing or ownership
on failure. The Qualcomm kernel-test runner also retains its future on
the heap. Stack-budget exceptions are removed when the measured frame
fits; budgets are never increased for these changes.
The rtw89 generation supervisor also retains its phase-dependent
firmware/radio advance future on the heap, keeping that state out of the
supervisor's frame while preserving its existing borrows and cancellation.
Cold rtw89 generation and brcmfmac provisioning polls have opaque boxed
future boundaries. Intel startup also constructs its future on the heap
behind a separate probe/scheduler boundary.
AHB runtime construction uses transient heap storage
before moving the same runtime into Shared; failed registration still
retains it. These boundaries keep compiler inlining from combining the
large cold construction and registration frames.
Virtual ath11k MAC construction also uses transient heap storage and a
separate constructor boundary before publishing the child netdev.
The ath10k RAW station State retains its Security owner in a Box, built
at the original startup point through a synchronous constructor boundary.
Hardware ordering, key/M4 deadlines and failed/cancelled retained ownership
remain the same; asynchronous startup no longer carries the inline security
construction and State-move temporaries together.

### 3.22 RTL8723BE native EDCA watchdog

The retained RTL8723BE owner counts accepted unicast MPDUs and recognizes
the associated AP from bounded beacon IEs/address prefixes. Its linked
watchdog applies the source's EDCA policy after RA refresh and before ATC,
through the existing station/calibration authority. Counter snapshots and
recognition are per owner; disconnect clears the peer, WMM/ERP-slot
programming resets turbo flags, firmware LPS suppresses the DM step, and an access
failure makes the owner terminal. No sample grants emission authority or
enables a new PHY mode. The family specification records exact register
values, source arithmetic/window behavior and native regression coverage.
The chip state is boxed to keep additions out of generic packet-owner
move/removal stack frames.

### 3.23 Native preparation and retained cleanup continuation

RTL8723AE firmware startup retains one boxed cold owner across warm-aware
LLT/MAC preparation, firmware download and post-download table/default
setup. Cancellation and access failure are terminal; DMA/MAC gates remain
parked. Separate source IQK/RF6052 preparation owners grant no emission
authority or station readiness. Factory-bound radio handoff, physical
PA-bias input and factory-capped current signed grants remain prerequisites
for native calibration/station composition.

RTL8852A native channel control and the qualified power prefix produce
only Programmed state. The existing signed full-radio identity binds the
new program; calibrated channel/station/AP admission still requires live
RFK inputs and completion. Hardware TX-path bounds also constrain the
admitted legacy-USB rate-control set: one TX path supports MCS0..7 and two
support MCS0..15. A wider AP capability is negotiated separately; authority
is never silently narrowed by the constructor.

An already-qualified RTL8852A fragment train selects the explicit A/B
fragment descriptor encoder before ordinary A dispatch and retains the
actual chip identity. Ordinary emitters still refuse fragments; all native
source, immutable-part and terminal-receipt checks precede progress.

The Intel RAM test backend uses the same retained transport-stop boundary
as production before retiring P2P state, preserving driver emission/source
fences. The watchdog smoke isolates its executor graph with the
existing scheduler test reset hook, so polling it cannot run retained
workers from earlier target fixtures. No scheduler-core change is needed.
Intel GO/client deferred-netlink smokes likewise own their executor graph
and drive real Activity deadlines between unfinished polls. Public Intel
association obtains its initial policy from the same selected source used
by its transaction; only Native bootstraps the global deployment policy.
A missing selected model database never borrows global authority.
The response-refined client program retains its original client binding,
including current NO_P2P checks. GO host GTK enqueue borrows the actual
Session and requires its original hardware-owner identity and exact
multicast queue; ordinary raw-protected bypass remains refused. Gen2
enqueue retains admitted checksum metadata on the actual Frame until
software completion before GTK encryption. Client target fixtures wait
for retained native control, notifications and RX prefixes across quiet
polls within their existing bound.
Gen2's target model keeps the pre-MAC7 receive-prefix cookie separate
from the later RSNA marker owner. GO receive tests retain the real
66-record foreign NoA prefix, deny DATA in its first bounded pass, then
verify exact delivery and repeated-PN refusal after that prefix retires.
SC and private Intel model fixtures use their own allocated test names.
They leave the physical adapter's cached `wlan` reservation untouched,
so later all-family fixtures cannot reuse it between Intel tests. The
original active-owner and physical-name vacancy checks remain in force;
registry-revocation tests also check the unchanged private TX endpoint
and absence of published network/wireless entries.
MediaTek TX/RX block-ack control carries the same owned peer WCID in both
outer STA_REC and nested WTBL requests, including disable. Group fixtures
retain their real association, distinct MAC and current policy before
coexistence or sleep; reply descriptors name the actual submitting peer.
GO renewal stamps its new receive epoch into the closed backend before
reopening current home traffic; the home floor stays intact while old GO
copies retire.

FullMAC control separates logical, physical-prefix and caller-output bounds.
Fixed control structures may omit only zero padding beyond the bounded
physical prefix. BCDC validates the complete advertised native response
before returning a shorter caller prefix. Correlation, publication and
terminal-resource checks still govern both ordinary and AP transactions.
The CYW AP ring holds State through one final source invocation, avoiding
recursive SDIO lifetime acquisition while retaining peer/key/epoch checks.
Fresh primary START refreshes its original same-country station policy
before binding the request's exact current snapshot.

Timed register-model smokes use the existing spin bridge when they run
before the BSP timer pump. APs may already have installed the global
hrtimer programmer while the BSP has no timer interrupt; the spin bridge
drives the actual monotonic deadlines instead of waiting for that absent
interrupt. D3 timeouts and watchdog-reset delays retain their full duration
and cleanup assertions. Production wait paths are unchanged.

### 3.24 AR9485 board and retained RX antenna continuation

AR9485/AR1111 preparation now carries canonical PCI-derived board inputs
through expected, cold, admission and reset paths. Raw RX-gain0 uses the
source GPIO9 fallback; exact CUS board matches add margin/minimum-gain
settings. The raw EEPROM capability and separate PCI BT flags bind the
retained legacy20 EDMA antenna scanner. Rejected native descriptors supply
no antenna observation, and no shared frame metadata or PHY profile expands.

One physical owner keeps scan/logical history while reset retires old
bindings. Saved-default capture, MAC restoration and scanner transactions
execute inside the actual retained N48A CapOp plus current PCI access, with
readback before history commits. N48A's v1 wire layout is unchanged; its
expanded recipe identity requires a fresh signed measured qualification.
Separate N48D manual sharing is described in §3.32; broader sampling stays
closed. Native validation and physical acceptance are pending. The family
spec owns the exact board, lifecycle and profile boundaries.

### 3.25 CYW43439 whole-transaction gSPI protocol continuation

`HostPort` candidate enumeration grants no station/source authority.
`GspiTransport` requires the optional exclusive `SpiBus::claim_device`
contract, never split legacy `set_cs`/`transfer`. The linked protocol now
composes one-shot 16-bit bootstrap, normal little-endian commands, F1
64-byte bursts/16-byte read delay, backplane access flags and exact padded
whole F2 packets. Wire uncertainty is terminal. The adapter-owned
`Transport::loader_mode()` identifies SDIO or gSPI; the default
Unknown refuses. Before every loader step, the requested mode must match
that actual adapter fact, including for preinitialized diagnostic ports.
Mismatch is terminal before loader I/O. This keeps gSPI startup/readiness
separate from SDIO CCCR/mailbox accesses while preserving discovered cores,
revision/RAM admission and exact selected bytes. F1 range preflight normalizes
the RAM-access flag before chunking: a burst cannot cross a32KiB RAM window
into local registers, whether the caller supplied that flag or not.

A private consumed boot-ready packet owner alone seeds one initial control
credit; ordinary SDIO runtime construction remains zero-credit. Public gSPI
register diagnostics cannot implement station attachment. Existing SPI
controllers refuse the stronger session by default. A real platform owner,
per-access current authority, signed gSPI host/board asset selection and
complete original reset/IRQ/bus retirement are still required before native
station publication. Platform SDHCI work remains with its host owner.
Native validation is pending and no physical acceptance is claimed. The
family spec records wire vectors, source revisions and exact limits.

### 3.26 RTL8723BE retained special-packet preflight

Synchronous station EAPOL queuing retains owned reply bytes with a deadline
and no TX identifier until actual async coexistence notification/LPS leave
completes under the current calibrated station grant. The join loop and
post-open worker serve the same pending owner. Cancellation/error closes
the generation; RX queued during the H2C wait is consumed before publication.
Actual descriptor retirement remains the only reply-delivery receipt.

Each queued special Ethernet Frame also requires its own completed
notification before synchronous stack drain may emit it. The endpoint
holds that exact pending frame through the await and consumes the receipt
only with its submission. This replaces latest-class overwrite and
best-effort after-the-fact notification. Post-wait lifecycle/current-source
checks remain mandatory. Native validation is pending.

### 3.27 RTL8723BE/RTL8192DE native ASPM continuation

The retained original PCI function selects source-specific BE MDIO/DBI or
DE DBI preparation. Actual bounded completion and exact readbacks precede
its preparation receipt. The existing PCI capability adapter limits endpoint
ASPM/CLKREQ to current capabilities and actual enabled parent policy,
preserves unrelated Link Control bits and rereads policy after waits. It
does not change the shared bridge or common-clock settings. Source loss,
timeout, cancellation and ignored writes cannot enable an unprepared
endpoint. Fresh rebuilt control ownership requires fresh internal receipts.
AE/other uncomposed chips remain disabled. Native validation is pending. The
family spec records the exact source programs and lifecycle constraints.

### 3.28 AR9462 station sleep and MCI power continuation (validation pending)

AR9462/AR9565 MCI concurrent-TX callbacks now retain the original calibrated
power plan and program/read back the source fourteen-target HT20 cap before
publishing the concurrent flags or priorities. The surrounding packet profile
remains legacy20. Revised N46A/N65A recipe identities require fresh measured
records; the existing 128-byte wire layouts are unchanged. Every actual
power/coexistence effect executes inside its original qualification and PCI
authority. An incomplete change closes the station and retains uncertain DMA.

AR9462 NETWORK_SLEEP additionally requires the disjoint optional N46S record,
an explicit requested state, real EDMA PM-Null/PS-Poll ACKs, peer TIM/AID/TSF,
AUTOSLEEP timers and S2 wake IRQs (or the retained polling owner). The actual
WA/MCI/RTC sleep and wake sequence gates ordinary traffic. FTP history counts
only callbacks that really observe sleep and validated DATA on the subsequent
awake interval. AR9565's source configuration disables FTP and does not admit
N46S. Missing N46S keeps AR9462 awake; no measured record is supplied in source.
The family specification §3.13 owns the record and lifecycle details.

Raw sleep/wake accesses invoke the same original N46S/N46A/PCI sources and
check the EEPROM-decoded GPIO/polarity before any requested register effect.
Asserted or ambiguous RFkill observations latch terminal power failure while
retaining the original owner; releasing the switch supplies no wake/reset or
DMA-retirement receipt.

### 3.29 RTL8821A coexistence continuation (validation pending)

RTL8821AE antenna selection now uses its actual factory EFUSE 0xc3 bit 0;
Wi-Fi stream count does not establish the BT antenna count. The source
RTL8821A one- and two-antenna algorithms, chip-specific RF/H2C/BT-controlled LPS
adapter and cancellation-terminal notify state are linked. The adapter shares the
original station mailbox rotation and uses the RTL8821AE RF path-A program.
Its RX foundation copies the full bounded two-byte-header/16-byte C2H command
and uses the same original-ring read/rearm operation during MP waits. Ordinary
frames encountered there retain their bytes and PHY facts for later security
processing. Arrivals and deferred reports use separate bounded queues.

Native activation uses one actual original-ring BT-version/build inquiry and
a separately signed N21C record for the exact 20 MHz operating point. Missing
observation or record retains the coarse LPS-only owner. Actual scan/connect/
media, C2H, EAPOL/special-packet, LPS, watchdog and healthy-stop call sites now
drive the retained full owner. Its joint station power base encloses actual
accesses, resumed polls and old/new stack publications. Complete later BT
version/build contradictions poison that one-shot source before RX rearm.
Cancellation/failure closes admission and invokes an independently fenced
restrictive PCI park; this supplies no RF-stop, DMA-idle or reset receipt.
An old normal-power NAPC envelope does not qualify these coexistence RF states.
Wider profiles and WoW/replay remain closed while N21C is installed. Native
validation and physical qualification remain pending.

`RtlwifiDevice::rtl8821ae_coexistence_request()` returns the original native
owner's optional historical N21C filename and binding. The single initial
inquiry must have observed a complete actual GET_BT_VERSION value/build;
callers cannot supply a BT identity. Request retention occurs inside the
original selected-image and NAPC source invocations before signed-asset lookup,
so a missing N21C still leaves the exact provisioning request available.
Reading it only clones metadata under the current Native prepared-owner lock:
it sends no H2C, checks no current RF authority, installs no grant and retries
no qualification. Once retained, the request cannot be replaced or upgraded
on an open station; a missing record requires a fresh original-owner rebuild
before another qualification attempt. Historical metadata remains historical
after source revocation or terminal retirement.

The rtlwifi `bt_coexistence` row is implemented pending validation; the
broader RTL8821AE chip row is tracked separately.

### 3.30 RTL8723AE separately qualified HT20 continuation (validation pending)

`rtl8723ae_ht20_station_request()` reports a distinct NASR2 filename/binding
from the same completed original calibration. It runs no station I/O and
cannot upgrade a live NASR1 owner. After the optional NASR3 inquiry below,
the one original attempt selects NASR2 before effects; only NotFound falls
back to NASR1. Present invalid,
unsigned, mismatched or revoked NASR2 refuses rather than falling back.

NASR2 keeps the640-byte record geometry but requires version/profile2,
rate mask0xfffff, a different source recipe and independent complete-program
CCK/OFDM/MCS0-7 curves. Old NASR1 remains version/profile1/mask0xfff and its
active grant is narrowed to that mask without changing programmed unused
indices. Neither an old NAPC/NAQR nor NASR1 supplies HT authority.

The fixed point permits one-stream HT20/SGI20, actual N24 H2C rate masks,
source SIFS/aggregation timing and software recipient BA64/reorder/A-MSDU3839.
RX MCS and aggregation require actual negotiated `packet.ht`; exact short
compressed BARs are bounded and peer-address checked before normal MAC-header
indexing. The original AE receive source reports no GI metadata. Single-MPDU
TX retains source AE descriptors and software CCMP; shared TX aggregation and
DD-triggered sender BA initiation remain disabled. Current original sources
enclose hardware effects, resumed polls and publication, including the actual
negotiated legacy/HT input to the retained coexistence algorithm.

Wider points, TX A-MPDU, LPS/IPS, ASPM, retune/reset/reclaim and physical
acceptance remain separate. No signed measurement or firmware is supplied.
The native NASR2 cases cover original-ring RX and actual original
shared-mailbox N24 mask effects; native validation is pending.

### 3.31 RTL8723AE separately qualified HT20/ASPM continuation (validation pending)

`rtl8723ae_ht20_aspm_station_request()` derives a distinct NASR3 filename and
binding from actual completed calibration. Its640-byte version/profile3
record measures the complete HT20 station/firmware/coexistence and automatic
response program across actual link states/transitions. Selection before any
station effect is3,2,1; only NotFound falls back. Old profiles never gain ASPM
authority and an active owner cannot upgrade.

Only NASR3 calls the refusing-by-default
`packet::Port::prepare_rtl8723ae_aspm(enabled)` before packet opening. Actual
PacketIo profile gating and per-access current original source/PCI invocation
enclose AE's own byte/word internal program and endpoint configuration effects.
Bounded DBI completion/readback precedes endpoint policy, which intersects
actual capabilities with the current enabled parent policy and rechecks around
its wait. Disabled policy does no internal setup; bridge/common-clock state is
preserved. Missing/uncertain/current-source receipts leave the original owner
failed and retained, without granting DMA-idle, RF-stop, reset or reclaim.

NASR1/2 keep their wire meanings. NASR3 admits no IPS/LPS, sender BA or retune.
Terminal park independently withdraws endpoint ASPM/CLKREQ under current PCI,
including after a MAC readback failure. Native validation is pending. The
family specification records exact literals, record shape and limitations.

### 3.32 Explicit AR9485/AR9565 manual antenna sharing (validation pending)

`ath9k::manual_bt_sharing_request()`, `manual_bt_sharing_requested()` and
`set_manual_bt_sharing(bool)` expose a factual request, retained requested
state and explicit serialized physical transition. Canonical BT-capable
AR9485 PCI0032 selects N48D; AR9565 PCI0036 with an actual retained live MCI
owner selects distinct N65D. Their128-byte signed records bind original
completed calibration/power/EEPROM/PCI facts and measured complete-program
antenna/power/transient bounds. Ordinary N48A/N65A or capability flags supply
no manual authority. PCI0037 never borrows PCI0032's program.

The transition pauses actual EDMA and withdraws receive publication first.
N48D verifies the source local3WIRE-off program before AR9485 switch/LNA
effects. N65D validates original MCI configuration/GPM/schedule pointers,
restores and reads back actual uncapped source power, permanently retires all
GPM/duty/interrupt/reset/re-enable producers, then executes source
`stop_bt(false)` and cleanup. CTRL/interrupt/LNA-update-disable readbacks
prove local coexistence off, without proving remote Bluetooth RF sleep or
MCI DMA idle. Original MCI buffers/link/IRQ/source ownership remain retained.
Only those receipts permit the distinct AR9565 manual program and group3
scanner; group2 thresholds/biases and AR9485 switch writes are not aliases.

The same counted current-source latch covers scalar effects, IRQ, DMA,
copies/rings and carrier/callback publications captured before or after the
request. Explicit disable retains its companion and never restarts MCI.
Uncertainty closes admission; reset/retune/suspend/removal take a terminal
retained-owner path, without reconstructing a plain N48A/N65A owner or
inventing reset/reclaim proof. Native validation is pending; broader
HT/aggregation/control-frame profiles and physical acceptance remain open.

### 3.33 Separately measured AR9003 periodic ANI (validation pending)

`ath9k::native_ani_request()` returns retained original-generation metadata
for distinct N46P/N48P/N65P records on AR9462/AR9485/AR9565. The original cold
composition selects an optional128-byte signed record before packet effects;
only NotFound retains A alone. A present invalid/revoked record refuses, with
no later upgrade. Identity binds actual completed calibration/power/INI/clock,
host policy and both MCI power plans. Independent complete-program bounds
cover NF/IQ, every enabled ANI state/transition, retries/automatic responses
and board/coexistence state; existing A/S/D meanings remain unchanged.

The real native adapter reads MIB/listen/PHY-error counters and retains
source peer-RSSI filtering. Eligible idle station polls drive exact chip
controls and INI-relative coefficients, with complete current-source/PCI/
power/RFkill scopes and readback before receipt commits. AR9462/9565 skip
weak-detector threshold writes; AR9485 uses its captured thresholds. Only
multichain AR9462 changes MRC-CCK. Existing NF/IQ continues on its own owner.
The stable physical/publication latch jointly invokes P and A for earlier
and later tokens. Existing S power-save or manual D requests refuse while P
is bound; reset/retune/suspend/removal retain terminal ownership without a
plain A rebuild or invented DMA/RF stop. Native validation is pending. The
family specification owns the exact counters and record.

### 3.34 RTL8852A native source startup continuation (validation pending)

Actual DIDs8852/a85a select A's retained firmware/factory assets and source
MAC/RX/LTR startup. Fresh N5AM encloses actual MAC and polling RX/configuration
effects; programmed secure fuses require the separately authenticated N5AS
blacklist snapshot before firmware effects. Full N5ABv2/N5AC bind A's own
factory FEM/live thermal observations, complete initial RXDCK/IQK/TSSI/DPK,
source scheduler/TX-path ownership and channel/power program. Cold-v1 alone
cannot authorize changed DIG/IB/XTAL/thermal/TSSI effects.

Native channel publication requires complete actual calibration and fresh
source PMAC counter/offset receipts. Retained pre-station20/40/80 retune uses
A's own current records; a started station refuses retune before effects
because hardware RX drain/epoch ownership is not composed. Initial CCX/IFS/
NHM, actual early-cut gain inputs and direct A XTAL state remain retained;
incomplete native periodic adapters stay closed. AP/protocol, measured wider
aggregate/sleep/tracking owners and complete chip acceptance remain source
work. Native validation is pending and no signed measurement/firmware is
supplied.

### 3.35 RTL8922A WLAN-only and packet-closed no-link continuation (validation pending)

The original checked reset/factory/firmware/CH12/RX owner now composes distinct
N22W WLAN-only complete DM, a source MAC1 power window with off receipt, and
actual late/channel RFK. N22P partial and old N22A cannot acquire that meaning.
Fresh N22O additionally binds actual retained RESP1/RRSR0/RRSR1 observations,
selected source inputs and the complete ordinary/autonomous-response program;
its one original inquiry precedes effects and cannot upgrade after NotFound.

Original-ring inactive preflight preserves all DMA identities/cursors and
refuses start. Own BE no-link initialization then uses actual source BA-user
band0/band1 DONE commands, crypto/PHY-report/RTS/port widths, version-selected
CAM and role/join/G7 CCTL. REC-only MACID pause and no-ACK DMAC keep their
source contracts, without inventing execution status or MAC1 host access.
Every actual register, DMA/control poll and resumed operation invokes the
original Radio/N22W plus N22O and PCI sources; a prior metadata check is
insufficient. Success remains MlmeConfiguredClosed. Ordinary HCI/packets,
peer/station/AP/EHT/IRQ publication remain source work. Native validation is
pending; measured deployment assets and physical acceptance are separate
gates.

## 4. Interaction with `narf-wireless`

- **Registration**: Built-in drivers register their bus match tables
  (`narf_bus::register_pci_driver(PciMatch { ... })`, or the USB class
  driver) from the crate's registration hook; a loadable module registers
  through the KABI (`narf_register_pci_driver`, `narf_register_usb_driver`).
- **Handoff**: After a successful probe and radio bring-up, the driver
  registers its netdev with the network stack and its `WirelessNetIface`
  with `narf_wireless::registry::register`, through which nl80211 finds it.
  A module's netdev and wiphy are published by the `WIFI` family host
  (§4.1).
- **Control Path**: nl80211 requests such as `TRIGGER_SCAN` and `CONNECT`
  are dispatched to the driver's `WirelessNetIface` implementation.

### 4.1 Loadable-module family host (family `WIFI`, version 2)

The native wireless family host (`wireless/src/module_host.rs`) is the
cfg80211 glue that makes Wi-Fi `.ko` datapaths work. It registers one
permanent `module_wireless::Host` (family `0x7769_6669`, `"wifi"`,
version 2) from `narf_wireless::register_initcalls` at boot, before any
module can load. It coexists with the mt76 private family (`0x6d74_3736`,
`"mt76"`), whose copy-mode protocol keeps native MCU/WFDMA execution in
its own host; the generic host serves every other Wi-Fi `.ko`. The wire
records are in `modules/DATAPATH_ABI_DESIGN.md` ("Wireless copy-mode host
services").

- **Sessions.** A module opens its probe device with
  `narf_wireless_open_with_event` (the per-session callback receives
  native scan/connect/disconnect requests) or `narf_wireless_open` (no
  event channel). One session per probe device. The broker validates
  owner, device token, session and current probe cap on every call;
  requests and replies are bounded copies. The host performs no device I/O.
- **One `wlan0`.** The netif bridge names a netdev registered on a device
  with a wireless session `wlan%d`. `REGISTER_WIPHY` carries that netdev's
  ifindex (it must be this module's, on this device: `-ENODEV` otherwise)
  and publishes the `WirelessNetIface` shell under the netdev's name, which
  is how nl80211 binds the two.
- **Station control plane.** The shell implements `scan` (`SCAN_REQUEST`
  event → `SCAN_RESULT`s + `SCAN_DONE`), `associate` (`CONNECT` event →
  `CONNECT_RESULT`), `disassociate` (`DISCONNECT` event → `DISCONNECTED`),
  `connected_bssid`, `scan_information_elements` (IEs of every reported
  BSS), `max_scan_ssids` / `max_scan_ie_len`, and the module's SME offloads
  (`supports_handshake_offload`, `supports_sae_offload`,
  `reports_disconnect_events`). Carrier follows `CONNECT_RESULT` /
  `DISCONNECTED`; an unsolicited disconnect is reported through
  `nl80211::notify_disconnect`. Close reports the disconnect and the
  interface removal and unpublishes the shell.
- **Not carried (version 2).** A userspace SME (`SecurityConfig::External`:
  AUTHENTICATE/ASSOCIATE, control-port EAPOL, key installation) is refused;
  so are AP/P2P/monitor roles, power save and station statistics. Those are
  a later protocol version.
- **Perf class:** no hot path. TX/RX frames never pass through the host.
- **Test fixtures.** Each module's `modules/e2e/<family>` test loads the
  real `.ko` from the test initramfs, where it is staged LZ4-compressed as
  `lib/modules/test-fixtures/<name>.ko.lz4` (`ath11k`, `iwlwifi`, `mt76`,
  `ath10k`, `ath9k`, `brcmfmac`, `rtw88`, `rtl`).

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
A built-in probe can load a signed `wireless-regulatory.bin` deployment
policy via the firmware registry (wire format in `wireless/` §3.5); a module
reads the kernel's installed domain through `narf_wireless_regdomain`
instead. A trusted service launcher
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

### 4.2 `ath11k.ko`: the WCN6855 driver as a loadable module

`narf-drivers-wireless-ath11k --no-default-features --features module` is the
whole PCI station driver (MHI, QMI/WLFW, CE, HTC, WMI, DP and the MAC with
its in-driver WPA2/WPA3 supplicant) built into a `.ko` (x86_64 and aarch64)
from the same source as the built-in. Kernel services come from
`src/ath11k/platform/`, one module re-exporting the same names in both
builds: `kernel.rs` re-exports the kernel crates; `kabi.rs` implements them
over `narf-module-rt` and the KABI. `narf-crypto`, `narf-wireless` and
`narf-drivers-wireless-ath-core` are linked kernel-free (their `kernel`
feature off).

- **Claim.** `17cb:1103` (WCN6855) only. QCA6390, QCN9074 and the AHB parts
  stay built-in only. `narf-drivers-wireless/ath11k-module-only` leaves the
  built-in PCI ids unclaimed so an early-loaded `ath11k.ko` owns the device;
  the AHB binder stays built in.
- **Probe** (`pci_kabi.rs`, Linux `ath11k_pci_probe` order).
  1. `narf_pci_identity`, then the runtime profile check; firmware-owned
     DMA is retained on teardown from the start.
  2. `narf_pci_prepare_probe`, then memory decode on.
  3. BAR0 is mapped; `narf_bar_len` must report at least 1 MiB.
  4. TCSR, then the hardware revision is refined.
  5. MSI: `narf_msi_enable` for the chip's full vector count, else one
     vector with `MSI_CONFIG_ONE`.
  6. Software reset.
  7. ASPM L0s/L1 off through `narf_pcie_aspm` (`ath11k_pci_aspm_disable`).
     It is restored once firmware is up, or on power-down, as in Linux.
  8. MSI delivery on, then bus master.
  9. An internal executor runs from the 1 ms poller and every vector's
     upcall. It carries MHI to mission mode, then QMI to FW_READY, then
     the core, DP and runtime.
- **DMA.** All coherent memory comes from `narf_dma_alloc_mapped`, with the
  CPU pointer accessed directly. KABI DMA handles are never reused, so
  per-packet buffers come from a size-class pool (4–64 KiB, carved from
  1 MiB mapped chunks).
- **Netdev and wiphy** (`iface_module.rs`).
  - The netif bridge names the netdev `wlan%d`.
  - `REGISTER_WIPHY` (§4.1) advertises the radio's enabled channels,
    HT/VHT/HE, eight cipher suites and `PSK_OFFLOAD | SAE_OFFLOAD |
    REPORTS_DISCONNECT`.
  - The station subset runs over the same `Shared` runtime and `Mac` the
    built-in netdev drives:
    - scan, with the radio-wide scan lease;
    - connect: open, in-driver PSK, or in-driver SAE. A `CONNECT` without
      a BSSID resolves to the strongest matching network of the last scan.
    - disconnect;
    - link-loss reports from the MAC poll.
  - RX goes through `narf_netif_rx`; TX is queued into the per-AC TXQs.
- **Parameters.** `.narf_kparams` declares `ssid`, `psk`, `passphrase` and
  `scan`, so `ath11k.<name>=` on the kernel command line reaches the
  autoconnect bring-up aid unchanged.
- **Not carried (built-in only).**
  - Firmware crash recovery: the radio stays down until reload, and the
    driver logs this.
  - AP, P2P and monitor roles, and virtual interfaces.
  - WoW and system PM.
  - Power-save control.
  - Checksum offload.
  - The userspace SME (`SecurityConfig::External`).
- **Proof.** `modules/e2e/ath11k` loads the real `.ko` on both
  architectures. It checks that the relocations resolve, init runs, the
  parameters are declared and a load argument applies, exactly the WCN6855
  id is claimed, a probe with no device context is refused, and unload
  leaves no match. QEMU emulates no WCN6855, so bring-up and RF behavior
  are first proven on hardware (`docs/BOOTING_ON_CACHYOS.md`).

### 4.3 `iwlwifi.ko`: the iwlwifi stations as a loadable module

`narf-drivers-wireless-iwlwifi --no-default-features --features module` is
the driver's station for every id of its built-in table, built into a `.ko`
(x86_64 and aarch64) from the same source as the built-in. `narf-crypto` and
`narf-wireless` are linked kernel-free. Two stations, as built in:

- **Gen3** (Ty AX210, So/Ma AX211, Bz BE200/BE20x, Sc BE20x/BE21x): the
  PCIe transport (`runtime::Hardware`, which selects the API89, Bz or MLD
  profile), the firmware TLV/PNVM loader and the MLD station
  (`connection::Connection`, with the in-driver WPA2-PSK / WPA3-SAE
  supplicant and 802.11w), orchestrated by `module/netdev.rs` as
  `device::Device` does.
- **Gen2** (Qu/QuZ AX201, CC AX200): the same transport on its 22000 path
  and the retained API77 MVM owner (`mvm_boot::Owner`, with the native
  WPA2-PSK four-way owner or host SAE plus PMF, and its signed per-platform
  TX-power programs), orchestrated by `module/mvm_netdev.rs` as
  `mvm_device::Device` does, under the same publication fences.

- **Platform.** `src/iwlwifi/module/kernel.rs` defines modules named like
  the kernel crates (`narf_time`, `narf_io`, `narf_lib`, `narf_bus`,
  `narf_capabilities`, `narf_console`, `narf_scheduler`, `narf_net`,
  `narf_firmware`, `narf_firmware_smbios`) with the subset of each API the
  module-built files use, over `narf-module-rt` and the KABI. Each such file
  imports them under `cfg(feature = "module")`, shadowing the absent extern
  crates, so the driver text is the same in both builds. A `Cap` is the probe
  token there: the kernel checks it on every KABI call and revokes it at
  teardown. Kernel-bound halves have module variants:
  - `module/mmio.rs`: BAR0 and the built-in PCI command sequences with their
    read-back checks, over `narf_pci_command`;
  - `module/msix.rs`: two `narf_msix_claim` vectors for the RX and non-RX
    table entries; the task-context callbacks latch the causes the built-in
    hard IRQ latches;
  - `module/source.rs`: firmware bytes are a private copy, so the source
    fence is the PCI authority;
  - `module/firmware_asset.rs`: assets carry their verified signer
    (`narf_firmware_signer`) and SHA-256, as built in, so the Gen2 signed
    power programs are admitted on the same evidence;
  - `narf_firmware_smbios`: the SMBIOS system/board/BIOS records the Gen2
    power binding digests, parsed from the kernel's own table
    (`narf_smbios_read`) with the kernel parser's rules;
  - `module/platform_power.rs`: see below.
- **Roles not carried** are uninhabited types under the names the shared code
  uses (`module/absent.rs`: the P2P client, the P2P GO identity, and the
  transport's and the Gen2 owner's AP/P2P hooks answered as the built-in
  answers them with no such role installed), so the station code compiles
  unchanged and the compiler proves those paths unreachable. AP/P2P/
  scheduled-scan owners, `device`, `mvm_device`, `bootstrap` and the ACPI
  platform readers are `cfg(builtin)`.
- **Claim.** All 28 ids of the built-in table (`iwlwifi::module_carries`).
  `narf-drivers-wireless/iwlwifi-module-only` leaves exactly those to the
  `.ko`.
- **Probe** (`module/pci.rs`, the built-in `probe` + `bootstrap` order).
  1. `narf_pci_identity`, the chip table and subsystem qualification.
  2. Firmware-owned DMA retained on teardown.
  3. `narf_pci_prepare_probe`, park, BAR0, memory decode on, bus master off.
  4. The CSR MAC/RF identity selects the profile and its firmware
     (`bootstrap::Owner::candidates`): the Sc core ladder, Bz's core103
     image, the API89 image, or Gen2's exact API77 image. A refused identity
     refuses the probe.
  5. The `WIFI` session, the 1 ms poller and the startup task.
  The startup task loads the firmware (120 x 500 ms retries while not
  staged), admits the parsed executable and re-reads the identity as
  `bootstrap::Owner::start` / `start_mvm` do, and boots the transport: Gen3
  through `mld_start.rs` (shared with `Device`), Gen2 through
  `Owner::initialize`.
- **Regulatory.** Both stations derive their TX-power program from the
  kernel's regulatory domain. `module/regulatory.rs` copies it through the
  shared `narf_wireless_regdomain` KABI export (one NRGD v1 record, decoded
  by the kernel-free `narf_wireless::reg::parse_domain_record`, which accepts
  the boot-time world domain "00" as the built-in read does) and caches one
  snapshot until the domain changes; the services re-read it every second,
  and a change fails the station fences and drops carrier, as a built-in
  reinstall does. Without a domain the stations refuse association and scan passively,
  as built in.
- **Platform power.** The module has no KABI for the device's ACPI
  WRDS/EWRD/WGDS/PPAG objects, so the Gen3 owner takes Linux's absent-tables
  path: nothing is published and the firmware keeps its own limits. The Gen2
  owner needs no ACPI: its power comes from the signed per-platform programs.
- **Netdev and wiphy.** `wlan%d` through the netif bridge; `REGISTER_WIPHY`
  from the NVM (channels, HT/VHT/HE/EHT, CCMP, and the SME offloads the
  station supports). Scan, connect (a `CONNECT` without a BSSID takes the
  strongest matching network of the last scan), the service loop (RX,
  rekeying, BA maintenance, TX under queue credit or publication fences,
  beacon and policy loss as `DISCONNECTED`), disconnect, and a firmware
  restart before the next operation after any failure.
- **Not carried (built-in only).** AP, P2P, monitor and virtual interfaces;
  scheduled scan; MLO further links; roaming; WoWLAN/D3 and system PM; CQM
  events; checksum offload; BIOS SAR/PPAG (ACPI).
- **Proof.** `modules/e2e/iwlwifi` loads the real `.ko`: relocations and
  init, exactly the 28 ids claimed and no other Intel id, refusal of a probe
  with no device context, clean unload. QEMU emulates no Intel Wi-Fi device,
  so firmware boot, scan and association through the module are unverified
  until run on hardware.

### 4.4 `mt76.ko`: the MT7921/MT7922 driver as a loadable module

`narf-drivers-wireless-mt76 --no-default-features --features module` is the
CONNAC2 PCI station driver built into a `.ko` (x86_64 and aarch64) from the
same source as the built-in: the L1 register planner, WFDMA rings, MCU
framing, patch/RAM firmware download, the post-firmware NIC/EFUSE/MAC
initialization, the station join with its in-driver WPA2/WPA3 supplicant
(SAE, PMF, rekeys), BA/reorder/defragmentation and the packet path. Kernel
services come from `src/platform/`: `kernel.rs` re-exports the kernel crates;
`kabi.rs` implements the same names over `narf-module-rt` and the KABI.
`narf-crypto` and `narf-wireless` are linked kernel-free.

- **Claim.** The built-in table: `14c3:{7961,7922,0608,0616,7920,7925,0717}`
  and `0e8d:7922`. Both builds match MT7925 (`14c3:7925` and its `0717`
  alias, CONNAC3), and both chip-id gates still refuse it: what
  `MT_HW_CHIPID` reads on that silicon is open (#2494).
  `narf-drivers-wireless/mt76-module-only` leaves the built-in PCI ids
  unclaimed so an early-loaded `mt76.ko` owns the function; the private
  family host below stays registered.
- **Probe** (`mt7921/pci_kabi.rs`, the built-in `bring_up_current`).
  1. `narf_pci_identity` against the table; firmware-owned DMA is retained
     on teardown from the start.
  2. `narf_pci_prepare_probe`; the parked command register is verified
     through `narf_pci_command`.
  3. BAR0 mapped; every identity/power register must lie inside it.
  4. Memory decode with INTx disabled, bus mastering off (the function may
     carry WFDMA ring bases from firmware or a previous OS).
  5. ASPM off (`narf_pcie_aspm`).
  6. Chip id/revision/bond and the MT7961 → MT7920 retag.
  7. Driver ownership and the WFSYS reset.
  8. The 1 ms poller drives the module executor, which runs the built-in
     `boot_radio` task: firmware download, radio initialization, netdev
     publication, then the built-in retry/recovery schedule.
  Bus mastering is granted only by the firmware transport after it has
  programmed its own rings; stop/reset sequences clear and re-read it
  through `narf_pci_command` (memory decode, bus master and INTx disable
  only; a bit in both masks is refused). Every call keeps the masks
  disjoint: restoring the bus clears bus mastering while it sets decode and
  INTx disable.
- **DMA and interrupts.** Rings and frame buffers come from
  `narf_dma_alloc_mapped` (a 4–64 KiB size-class pool over 1 MiB chunks:
  KABI DMA handles are never reused). The memory is untranslated, so the
  IOMMU block/restore steps are no-ops and the device-side evidence is the
  stop proof, as built in outside `IommuMode::PerDomain`. On x86_64 one MSI
  vector (`narf_msi_enable` + `narf_irq_set_handler`) raises the driver's
  interrupt line and runs the executor; elsewhere the owner stays polled, as
  built in.
- **Firmware and regulatory.** Patch and RAM code are read with
  `narf_firmware_open`/`_read` (the `Firmware` manifest cap) under the
  built-in 16 MiB bound. The regulatory domain is the kernel's installed one
  (the built-in driver's), read through `narf_wireless_regdomain` as an
  NRGD v1 record and decoded with `narf_wireless::reg::parse_domain_record`.
  It is read again on every query, as built in reads the database; the
  station owner compares domains by value, so a policy change re-admits or
  revokes the link as built in. When the kernel has no domain (`-ENODATA`)
  or the record does not decode, the module fails closed exactly as built
  in: no transmit permission, no active scan, no join. It has no
  regulatory fallback of its own.
- **Netdev and wiphy** (`iface_module.rs`).
  - The netif bridge names the netdev `wlan%d`.
  - `REGISTER_WIPHY` (§4.1) advertises the firmware-reported bands, HT/VHT,
    the built-in eight cipher suites and `PSK_OFFLOAD | SAE_OFFLOAD |
    REPORTS_DISCONNECT`, four scan SSIDs and 600 bytes of scan IEs.
  - Scan, connect (open, PSK, SAE) and disconnect run the same boot-owner
    entry points and scan/join helpers (`iface_station.rs`) as the built-in
    netdev. A `CONNECT` without a BSSID or frequency takes the strongest
    matching network of the last scan.
  - The service task is the built-in worker pass: sources masked and
    acknowledged, one packet step, key service, unmask. RX goes through
    `narf_netif_rx` under the receive-epoch publication gate; TX frames are
    queued and serviced on the next pass. Peer loss is reported as
    `DISCONNECTED` with the AP's reason; a firmware failure resets the radio
    on the built-in 1 s / 5 s / 30 s schedule.
- **Parameters.** `.narf_kparams` declares `debug`; `mt76.debug=1` enables
  the routine traces the built-in prints under `mt76.dyndbg=+p`.
- **Not carried (built-in only).** AP, P2P and monitor roles (the AP/P2P
  owner code is linked but no authority can be minted); WoW and system PM;
  scheduled scan; roaming; CQM, survey and station statistics; power-save
  control; the association-comeback event; the userspace SME.
- **Private family.** The mt76 copy-mode family (`0x6d74_3736`, version 1,
  `module_host.rs`) stays registered unchanged in the built-in build. No
  in-tree `.ko` opens it any more; it can be retired once no out-of-tree
  frontend depends on it.
- **Proof.** `modules/e2e/mt76` loads the real `.ko`: relocations resolve,
  init runs to Live, the `debug` parameter is declared and applies, exactly
  the eight ids are claimed, a probe with no device context is
  refused, and unload leaves no match. QEMU emulates no MediaTek Wi-Fi, so
  bring-up, firmware download and RF behavior are first proven on hardware.

### 4.5 `ath10k.ko`: the QCA988X–QCA9377 driver as a loadable module

`narf-drivers-wireless-ath10k --no-default-features --features module` is
the PCIe driver — reset, BMI, firmware/board/OTP/calibration download, CE,
HTC, WMI, HTT and the retained station radio with its in-driver WPA2-PSK
and WPA3-SAE supplicant — built into a `.ko` (x86_64 and aarch64) from the
same source as the built-in, following §4.2. Kernel services come from
`src/ath10k/platform/` (`kernel.rs` re-exports the kernel crates; `kabi.rs`
provides the same names over `narf-module-rt` and the KABI). `narf-crypto`,
`narf-wireless` and `narf-drivers-wireless-ath-core` are linked
kernel-free.

- **Claim.** Every PCIe id the built-in driver binds: QCA988X (`168c:003c`,
  Ubiquiti `0777:11ac`), QCA9887 (`0050`), QCA6174 (`003e`), QCA6164
  (`0041`), QCA99X0 (`0040`), QCA9888 (`0056`), QCA9984 (`0046`), QCA9377
  (`0042`). Not AR9462 (`0034`), which the built-in only registers to refuse
  as ath9k's. ath10k has no SDIO/USB/SNOC binder in NARF, so there is
  nothing else to carry. `narf-drivers-wireless/ath10k-module-only` leaves
  the built-in ids (and its system-PM hook) unregistered so an early-loaded
  `ath10k.ko` owns the function.
- **Probe** (`pci_kabi.rs`, the built-in `probe` + `bring_up` order).
  1. `narf_pci_identity`; AR9462 and unknown ids are refused.
  2. DMA retained on teardown (rings and host memory are published to the
     firmware from power-up on).
  3. `narf_pci_prepare_probe`, memory decode on, BAR0 mapped; the BAR must
     cover the family's PCI-local, chip-id, SoC and last-CE windows.
  4. Target wake and chip id (`pci::identify`, shared with the built-in).
  5. The 1 ms poller starts the module executor, which runs the built-in
     `pci::boot_task` unchanged: reset, ASPM off, bus master, BMI, firmware
     and board download, BMI_DONE, MSI, HTC, WMI, HTT, the radio, then the
     station publication.
- **PCI from the transport.** Bus mastering on is `narf_pci_enable`; off
  and every command read-back are the shared `narf_pci_command` (`clear =
  bits` to disable, `clear = set = 0` to read). ASPM is `narf_pcie_aspm`.
  The PCIe Device Control read behind the built-in DMA-reclamation proof
  (no Relaxed Ordering) is `narf_pcie_state`; the config `0x40`
  retry-timeout dword is `narf_pci_config_read32`/`_write32`. MSI is one
  plain vector (`narf_msi_enable(1)`) whose task-context callback raises
  the same signal the built-in hard-IRQ handler raises and runs the
  executor.
- **DMA.** Rings, bounce buffers and WMI/HTT host memory are allocated once
  per generation, so they are direct `narf_dma_alloc_mapped` allocations
  (no pool), DMA32 as built in.
- **Firmware.** Through `narf_firmware_open`/`_read` under the module's
  `Firmware` manifest cap, with the built-in signer policy (board,
  pre-cal/cal inputs must be signed). The module's loader record
  (`firmware_source_module.rs`) keeps the bounded input log and the seal,
  but holds no per-blob capability: revocation of an input after it was
  read is not observable from a `.ko`. No Devicetree reaches a module, so
  DT/NVMEM calibration sources are absent; the SMBIOS BDF variant comes from
  `narf_smbios_read`.
- **Regulatory.** The kernel's installed domain (the one the built-in
  driver reads, with its `iw reg set` and Country-IE changes), copied by
  `narf_wireless_regdomain` as an NRGD v1 record on every policy check and
  decoded with `narf_wireless::reg::parse_domain_record` (which accepts the
  world domain "00"). An unchanged record keeps the
  previous snapshot, so snapshot identity still follows a change of the
  installed domain.
- **Netdev and wiphy** (`iface_module.rs`).
  - `narf_wireless_open_with_event` (§4.1), then the netdev (`wlan%d`),
    then `REGISTER_WIPHY`: the radio's station channels, HT/VHT, CCMP, and
    `PSK_OFFLOAD | SAE_OFFLOAD | REPORTS_DISCONNECT`.
  - Scan (active, passive, and the associated dwell scan with the data path
    kept serviced), connect (open, in-driver PSK, in-driver SAE; a `CONNECT`
    without a BSSID takes the strongest match of the last scan) and
    disconnect are the built-in `Device` paths over the same `Radio`. The
    built-in awake power-save default is submitted after association; the
    `WIFI` host has no power-save control.
  - One service worker: failed-scan cleanup, the data drain (RX through
    `narf_netif_rx`, queued TX into HTT, carrier) and the PMF management
    flush, then a wait on the interrupt signal or the polling backstop.
  - As built in, a disconnect or an abandoned association closes the
    retained radio owner; a later association needs a fresh generation.
- **Recovery.** The built-in automatic recovery (`pci.rs`, `restart.rs`)
  runs unchanged in the module: a firmware crash (FW_IND_EVENT_PENDING) or a
  failed scan cleanup retires the generation (CEs halted, bus mastering off
  through `narf_pci_command` and read back, the ordered flush read) and
  boots a fresh-ROM one, at most three per load. A generation whose
  quiescence is not proven keeps its DMA pinned, as built in. The netdev,
  session and wiphy outlive the generation (`ieee80211_restart_hw`); the
  next generation rebinds them and replays the retained association
  (scan for the BSS, then associate with the retained credentials) like the
  built-in `replay_retained`. An operator disconnect forgets it.
- **AP/ROC authorities.** The radio's AP, P2P and remain-on-channel code is
  compiled unchanged, but its `narf_wireless::ap_control` authorities are
  unconstructible in the module (a private uninhabited field), so nothing in
  the `.ko` can start those paths.
- **Not carried (built-in only).** AP/P2P/ROC, WoW and system PM
  (suspend/resume), power-save control, the userspace SME, DT/NVMEM
  calibration and the PCI-only diagnostic entry points (`pci::scan_passive`
  … `pci::poll_ethernet`).
- **KABI.** Only shared exports; ath10k adds none of its own.

- **Proof.** `modules/e2e/ath10k` loads the real `.ko`: relocations resolve,
  init runs to Live, exactly the nine ath10k ids are claimed (not AR9462),
  a probe with no device context is refused, and unload leaves no match.
  QEMU emulates no Atheros Wi-Fi, so bring-up, scan and association through
  the module are unverified until a hardware run.

### 4.6 `ath9k.ko`: the softMAC driver as a loadable module

`narf-drivers-wireless-ath9k --no-default-features --features module` is the
whole ath9k driver built into a `.ko` (x86_64 and aarch64) from the same
source as the built-in. Every chip owner is included:

- AR5008: AR5416/AR5418/AR9160;
- AR9280;
- AR9285/AR2427;
- AR9287;
- the AR9300 family: AR9380/AR9485/AR9580/AR9462/AR9565.

For each owner the module carries identity and the EEPROM, signed board
admission, the INI/PLL/RF tables, signed-policy calibration, the MAC and
key cache, packet DMA, rate control, the HT/BA/QoS/PS/ANI/BT-sharing
qualification grants, AR9003 MCI coexistence, idle FULL_SLEEP, generation
reset, and the station with its in-driver WPA2 supplicant.

There is no firmware: the driver programs the MAC/PHY and enforces the host
regulatory domain itself. So it needs more from the kernel than a FullMAC
driver.

- **Platform.** The driver names the kernel crates: `narf_bus`, `narf_lib`,
  `narf_time`, `narf_scheduler`, `narf_io`, `narf_capabilities`,
  `narf_firmware`, `narf_net`, `narf_ipc`, `narf_console`, `narf_interrupts`
  and `narf_power`.
  - Built in, they are the real crates.
  - In the module, `src/ath9k/platform/kabi.rs` provides modules with the
    same names: the subset of each API the driver uses, over
    `narf-module-rt` and the KABI. A driver file imports them under
    `#[cfg(feature = "module")]`, so the driver logic is unchanged.
  - Two names differ in path, so they come from the platform in both
    builds: `regdb` (`narf_wireless::reg::db`) and `WirelessNetIface`.
  - `narf-crypto`, `narf-wireless` and `narf-drivers-wireless-ath-core` are
    linked kernel-free.
  - A device capability handle is live only while its token is the bound
    device. A firmware handle is live only while its record is open.
- **Claim.** The built-in tables' ids, unchanged: fifteen `168c:*` ids,
  under the module's own match name `ath9k-module`. The match table is keyed
  on (name, id), so a built-in per-chip name would replace the built-in
  entry, and unload would remove it. `narf-drivers-wireless/ath9k-module-only`
  leaves the built-in driver unregistered, so an early-loaded `ath9k.ko`
  owns the devices.
- **Probe** (`pci_kabi.rs`). This is the built-in probes' shared bus half,
  in Linux `ath_pci_probe` order.
  1. `narf_pci_identity`, and the owner for the device id.
  2. The singleton reservation (`CLAIMED_ADDRESS`), as built in. A failed
     attempt keeps it.
  3. `narf_pci_prepare_probe`, then the owners' own park through
     `narf_pci_command`: Bus Master and Memory Space off, INTx Disable on,
     read back.
  4. BAR0 mapped with decode parked, then Memory Space on and the policy
     read back.
  5. Packet DMA retained on teardown.
  6. The 1 ms device poller (the executor's heartbeat).
  7. The owner's `bring_up`. Each built-in `probe` was split into its bus
     half and this shared `bring_up`, which is unchanged.

  Bus mastering is turned on later by the packet owner itself, after its
  rings are in place, exactly as built in.
- **Removal.** `narf_module_exit` runs the bound owner's built-in `remove`
  (Linux `ath_pci_remove`).
  - The kernel has already stopped the module's callbacks, so exit drives
    the executor itself, for up to 5 s, until `remove` releases the
    reservation. `remove` releases it only after its DMA-stop proof.
  - Only then is the teardown DMA retention lifted. An unproven stop leaves
    the buffers quarantined.
- **KABI.** The shared `narf_pci_command` (added for mt76) clears and sets
  Memory Space, Bus Master and INTx Disable, then reads the register back.
  The DMA-stop proofs gate Bus Master around every generation reset with
  it. Additive for ath9k (`modules/DATAPATH_ABI_DESIGN.md`, "softMAC PCI
  state and config reads"):
  - `narf_pcie_state`: Device/Link Capabilities, Control and Status, and the
    upstream bridge's Link Control. These choose the SerDes workarounds
    (`ath_pci_aspm_init`) and drive the relaxed-ordering check.
  - `narf_pci_config_read32`: read-only, `0x40..=0xffc`. It is used for
    AR9462's L1-entry-latency word at `0x70c`.
  - The shared `narf_wireless_regdomain` (added for rtw88) returns the
    host's regulatory domain as one NRGD v1 record, bootstrapping the
    staged signed policy when none is installed. `platform::regdb` parses
    it with `narf_wireless::reg::parse_domain_record` (`parse_policy`'s
    checks, also accepting the world domain's `"00"`). Every
    calibration, retune and transmit admission reads a fresh record, and an
    unchanged record reuses its last parse. With no domain (`-ENODATA`),
    admission closes.
- **MSI.** One plain-MSI vector via `narf_msi_enable`, with a task-context
  callback. It is taken on first use and reused by later generations.
  Without it, the owner stays polled, as built in.
- **DMA.** All coherent memory comes from `narf_dma_alloc_mapped`, with
  4–64 KiB size-class pools carved from 1 MiB chunks, because KABI handles
  are never reused. The mapping is coherent, so the driver's cache syncs are
  ordering fences.
- **Signed records.** Board admission and the qualification grants are read
  through `narf_firmware_open`/`_read`. They are admitted only when
  `narf_firmware_signed` reports a verified signer, as built in.
- **Netdev and wiphy** (`iface_module.rs`). It is the same `interface.rs`
  netdev, with its kernel edges swapped: the same generations, rings,
  carrier and station.
  - The netif bridge names the netdev `wlan%d`. Stack TX goes to the
    built-in `send`. RX the netdev hands the stack goes out through
    `narf_netif_rx`.
  - `REGISTER_WIPHY` (§4.1) advertises the attached generation's permitted
    2.4/5 GHz channels, its HT grant, CCMP and `PSK_OFFLOAD |
    REPORTS_DISCONNECT`.
  - `SCAN_REQUEST`, `CONNECT` and `DISCONNECT` run the netdev's built-in
    `scan`, `associate` and `disassociate`. A `CONNECT` without a BSSID
    takes the strongest matching network of the last scan. Security is open
    or in-driver WPA2-PSK, as built in; SAE is not advertised.
  - A carrier loss the netdev reports (the built-in `notify_disconnect`)
    goes out as `DISCONNECTED`.
- **Not carried (built-in only).**
  - System suspend/resume: there is no module device-PM export, so the
    owners' `pm_suspend`/`pm_resume` and their PCI retry-timeout write
    (`0x40`) stay built in.
  - WoW, nl80211 power-save control and the userspace SME: the `WIFI` v2
    host carries none of them.
  - Hot removal while loaded: the bus has no module remove callback, so
    removal is unload.

  ath9k.ko makes no config-space writes. Its only one, that retry-timeout
  clear, is in the system-PM path; the shared `narf_pci_config_write32`
  covers only the device-specific region `0x40..0x100`.
- **Proof.** `modules/e2e/ath9k` loads the real `.ko`. It checks:
  - the relocations resolve and init runs;
  - exactly the fifteen ath9k ids are claimed, and none of ath10k's;
  - a probe with no device context is refused;
  - unload (exit with nothing bound) leaves no match.

  `modules/kabi` `smoke_kabi_softmac_exports` checks the new exports' cap
  gating, bounds and regulatory record. QEMU emulates no Atheros Wi-Fi, so
  bring-up, calibration, scan and association through the module are
  unverified until a hardware run.

### 4.7 `brcmfmac.ko`: the Broadcom FullMAC PCIe driver as a loadable module

`narf-drivers-wireless-brcm --no-default-features --features module` builds
the brcmfmac PCIe driver into a `.ko` (module name `brcm`; x86_64 and
aarch64) from the same source as the built-in. Kernel services come from
`src/platform/`: `kernel.rs` re-exports the kernel crates, `kabi.rs`
implements the same names over `narf-module-rt` and the KABI. `narf-crypto`,
`narf-wireless` and `narf-drivers-wireless-ath-core` are linked kernel-free.
The driver's own code runs in the `.ko`: AI core discovery (`chip.rs`), the
CR4/CA7 passive/download/active sequence (`boot.rs`), the msgbuf common and
flow rings (`runtime.rs`), the station transport (`station_transport.rs`)
and the shared FullMAC station (`cyw43439/station*.rs`). CYW43439 (SDIO and
gSPI) stays built-in only: no SDIO I/O KABI exists.

- **Claim.** Every Broadcom FullMAC PCIe id of the built-in table
  (`pcie_ids::ALL_DEV_IDS`, 26 ids, `14e4:43a3`..`14e4:4433`), under the
  match name `brcmfmac-module` so the built-in per-id entries are not
  replaced. `narf-drivers-wireless/brcmfmac-module-only` leaves the built-in
  PCI claim (and its PCIe system-PM hooks) aside so an early-loaded `.ko`
  owns the device; CYW43439 stays built in.
- **Probe** (`brcmfmac/pcie_kabi.rs`, the built-in `pcie.rs::probe` and
  `native_runtime.rs` order).
  1. `narf_pci_identity`; the id must be in the table.
  2. `narf_pci_prepare_probe`; decode and bus mastering must read back off.
  3. BAR0 (at least 4 KiB) is mapped, and BAR2 for the ids the built-in
     boots (BCM43602, or a chip-profile PCI row with an implemented vendor
     path); memory decode on with INTx disable kept.
  4. `Chip::discover` through the BAR0 window, then `park_pcie`.
  5. A chip without a covered profile or BAR2 stays parked and bound, as
     built in. Otherwise the provisioning task runs on the module's executor
     and is retried every 500 ms for a minute while no hardware attempt has
     started: the signed NBSP board selection
     (`brcm/wifi-board-selection-v1.bin`), its assets with exact length and
     SHA-256, the kernel's regulatory domain (below), then the CR4/CA7
     boot, ring attach, data enable, the station transport and the station.
- **Bus seams** (`KabiBackplane`). BAR0 window select (`0x80`) and the SBMBX
  doorbell (`0x98`) are written with `narf_pci_config_write32`
  (`modules/DATAPATH_ABI_DESIGN.md`, "Device-specific PCI configuration
  window") and read back with `narf_pci_config_read32`; Command-register
  parking and bus mastering go through `narf_pci_command`; Link Control ASPM through `narf_pcie_aspm`. TCM is
  accessed in dwords (partial dwords read-merge-write; the dongle CPU is
  halted). DMA comes from `narf_dma_alloc_mapped` below 4 GiB, per-frame
  buffers from a 4–64 KiB size-class pool; the device context retains DMA
  on teardown. One plain MSI vector raises the runtime's signal and runs
  the executor; without it the 1 ms poller keeps service. The IOMMU block is
  reported `Untranslated`.
- **Provisioning differences.** Explicit kernel board registrations
  (`native_runtime::register_board_profile`) do not exist in the module;
  only the signed manifest selects a board. The KABI exposes no firmware
  blob identity, so a module `Proof` re-opens each file and refuses a
  missing file or a changed size or signedness; the bytes are hashed once at
  load.
- **Regulatory domain** (`platform::reg`). The module reads the kernel's
  installed domain, the one the built-in driver uses
  (`narf_wireless::reg::db`: a staged signed `wireless-regulatory.bin`,
  else world `00` from the Linux database, with user and Country-IE
  changes), through `narf_wireless_regdomain` as one NRGD v1 record decoded
  by `narf_wireless::reg::parse_domain_record`. It reads no regulatory file
  itself. Semantics follow the built-in driver:
  - *Fail closed.* No domain (`-ENODATA`) or an undecodable record parks
    the device before any hardware attempt, as the built-in
    `ensure_domain` gate does; the provisioning retry picks up a domain
    installed later.
  - *Country required.* The shared station programs the firmware
    `country` iovar from the domain and refuses one that is not an
    uppercase alpha2, so world `00` brings brcmfmac up in neither build.
    Built in that refusal comes after the CR4 boot and is final; the module
    checks it in the gate instead, so the device stays parked (firmware
    never runs) and a country set within the retry window still
    provisions it.
  - *Live.* The station's policy source re-reads the record on every
    check (the built-in `GlobalPolicy`); an unchanged record keeps its
    snapshot, a same-country update is adopted, and a removed domain or a
    different country refuses the link. The transport reset that follows
    re-initializes the station under the domain then installed.
- **Netdev and wiphy** (`cyw43439/interface_module.rs`).
  - The netif bridge names the netdev `wlan%d`.
  - `REGISTER_WIPHY` (§4.1) advertises the station's policy-admitted 2.4
    and 5 GHz channels, HT/VHT as firmware reports them, the built-in
    shell's ciphers (CCMP, plus AES-CMAC with firmware MFP) and the
    firmware SME: `PSK_OFFLOAD` with the firmware supplicant (`sup_wpa`),
    `SAE_OFFLOAD` where `cap` lists `sae` with MFP, and
    `REPORTS_DISCONNECT`.
  - FullMAC maps onto the v2 SME-offload model directly: `SCAN_REQUEST`
    runs the station's escan, `CONNECT` the firmware join (open, PMK, or
    SAE password; a zero BSSID resolves to the strongest matching BSS of
    the last scan) and `DISCONNECT` the firmware disassociation.
  - The station's event poll drives carrier; a firmware deauth, disassoc or
    link-down is reported as `DISCONNECTED`.
  - TX frames are admitted as built in (Ethernet II from this station,
    never EAPOL), prioritized with `classify8021d` and sent on the flow
    rings; RX goes through `narf_netif_rx`.
- **Recovery.** A terminal transport (firmware halt, a fatal protocol or
  access error) is reset as the built-in `Generation::recover` does it
  (Linux `brcmf_fw_crashed` -> `brcmf_pcie_reset`): carrier off, the
  confirmed stop, the device reset and a fresh download of the re-verified
  signed assets, a re-initialized station on the same netdev, then a rejoin
  of the retained association. At most 64 resets; an unproven stop releases
  nothing (the mappings stay pinned).
- **Parameters.** `.narf_kparams` declares `ssid`, `psk` (64 hex digits)
  and `passphrase`; `brcm.ssid=` on the kernel command line scans and joins
  after the station is up.
- **Not carried (built-in only).** AP, monitor, P2P and virtual interfaces;
  WoWL and system PM; power-save control; firmware roaming (off by default
  built in too: the v2 host has no roam report); the host supplicant
  (`SecurityConfig::External`) and nl80211 PMKSA entries (the firmware list
  is kept empty, as built in without any); device removal (the device
  context retains every DMA mapping at unload); CYW43439.
- **Proof.** `modules/e2e/brcmfmac` loads the real `.ko`: the relocations
  resolve, init runs, the parameters are declared and a load argument
  applies, exactly the 26 FullMAC PCIe ids are claimed under the module's
  match name, a probe with no device context is refused, and unload leaves
  no match. QEMU emulates no Broadcom Wi-Fi, so bring-up, firmware boot,
  scan and association through the module are unverified until run on
  hardware.

### 4.8 `rtw88.ko`: the RTL8821CU / RTL8822BU driver as a loadable module

`narf-drivers-wireless-rtw --no-default-features --features module` builds
the rtw88 driver tree (`src/rtw88/`) into a `.ko` (x86_64 and aarch64) from
the same source as the built-in, for its USB parts. rtw89 does not build
into the module; the rtw88 and rtw89 PCIe ids stay registration-only
(`module_probe.rs`, probe `-ENOSYS`).

- **Platform** (`src/rtw88/platform/`). rtw88 names some twenty kernel
  crates directly (`narf_scheduler`, `narf_time`, `narf_wireless::reg`,
  `narf_net::iface`, ...). In the module build `platform` provides **the
  same names** — `platform::narf_time`, `platform::narf_net`, ... — and each
  driver file imports them under `#[cfg(feature = "module")]`, so the
  driver bodies are unchanged and the built-in build is untouched:
  - runtime: the module executor, `narf-module-rt` clock, sleeps and locks;
  - firmware: `narf_firmware_open`/`_read`/`_signed`, each file read once
    and kept for the module's lifetime (a signed file's view reports a
    signer; the KABI does not name the key, and rtw88 only requires that a
    record is signed); the firmware capability types are plain tokens, the
    module's `Firmware:Read` grant being the authority;
  - the regulatory domain: the kernel's, read once per probe through
    `narf_wireless_regdomain` (the signed per-board records are checked
    against it, as built in);
  - USB: the `ControlIo` / `Io` transport traits `usb_firmware::Backend`
    is written against;
  - stack hooks: `narf_net::iface::{lookup, set_link_metadata,
    on_rx_frame_from}`, `nl80211::notify_disconnect` and the shell's
    withdrawal land on the module netdev (`iface_module.rs`);
  - PCI types (`BusDevice`, `MmioRegion`, `BusAddr`): uninhabited, so every
    PCI-only branch of the shared code builds and is statically unreachable.
  PCI, PCI power/recovery, system PM, runtime idle, rejoin and the B22 PCI
  owner are `builtin`-only.
- **Probe** (`usb_kabi.rs`, Linux `rtw_usb_probe` order). Every
  RTL8821CU / RTL8822BU VID:PID (50 entries, vendor-specific interface
  0xff/0xff/0xff) is registered with `narf_register_usb_driver`. Probe reads
  the configuration descriptor and parses the endpoints
  (`usb::Endpoints::parse`) — a token without a USB context is refused
  here, before device access — then starts the 1 ms heartbeat
  (`narf_usb_spawn_poller`) and the attach task:
  1. GET_DESCRIPTOR(DEVICE) for the VID:PID (the probe thunk carries none),
     then the chip (`usb_driver::chip`);
  2. SET_CONFIGURATION and the bulk endpoint contexts (`narf_usb_configure`);
  3. the port speed from the bulk-IN `wMaxPacketSize` (the KABI carries no
     speed);
  4. from here on the driver's own code: `Backend::new_for`,
     `usb_driver::power_and_factory_for` (`rtw_mac_power_on`, the factory
     map), the B22 `phy_cfg` / `switch_mode`;
  5. the station shell (`interface::Device`) is published (below) and
     `usb_driver::provision` runs the lifecycle — firmware, MAC, PHY, the
     C21 calibration / operating / station stages or the B22 `N2BQ` / `N2BP`
     / `N2BS` stages — to `station.activate()`, retried 120 × 500 ms while
     the firmware or signed records are not registered, as built in.
- **Transport.** EP0 register access is `narf_usb_control`; register delays
  ≤ 1 ms busy-wait (`narf_udelay`). Bulk pipes: the KABI moves at most 4 KiB
  per request and one request per endpoint, while rtw88 posts 32 KiB
  receive buffers, 4.1 KiB firmware pages and queued sends. A transfer is a
  chain of ≤ 4 KiB requests on a per-endpoint FIFO: OUT splits on 4 KiB
  boundaries (a multiple of every bulk max packet, so the wire packets are
  one transfer's), IN completes on the first short chunk or when full.
  Every completion and the poller run the executor.
- **Netdev** (`iface_module.rs`). `narf_usb_netif_register_with_context`
  registers `wlan%d`; the stack's TX goes to the shell's built-in send hook
  (`endpoints::send` → `Device::enqueue`), the shell's RX delivery leaves
  through `narf_usb_netif_rx`. The netdev is open from registration; its
  provider lifetime is the shell's native emission identity.
- **Control plane.** No wiphy: the `WIFI` host (§4.1) binds sessions to bus
  device contexts only, so nl80211 cannot reach a USB function's module.
  The station is driven by the same in-driver SME nl80211 calls built in
  (`WirelessNetIface::scan` / `associate`: Open and WPA2-PSK with the
  driver's own 4-way handshake and CCMP) from `rtw.ssid=` / `rtw.psk=` /
  `rtw.passphrase=` (PBKDF2-SHA1 to the PMK) / `rtw.scan=`, declared in
  `.narf_kparams`; it rejoins after link loss.
- **Configuration.** `narf-drivers-wireless/rtw88-module-only` leaves the
  built-in USB class driver unregistered so a loaded `rtw88.ko` is offered
  the functions (module matches see only devices no built-in driver
  claimed); rtw88 PCIe and rtw89 stay built in.
- **Not carried (built-in only).** nl80211 / wiphy and the userspace SME;
  USB reset, rejoin, runtime idle and system PM (`usb_recovery.rs`); USB
  CLEAR_FEATURE(HALT) recovery (no host endpoint reset in the KABI); WoW.
- **Proof.** `modules/e2e/rtw88` loads the real `.ko`: relocations, init,
  the declared parameters and an applied load argument, the USB claim (both
  chips' ids on the vendor interface, not rtl8xxxu's id, not another
  interface class), the registration-only PCIe ids, refusal of a USB probe
  with no context, and an unload that leaves no match. QEMU emulates no
  Realtek USB Wi-Fi device, so bring-up, RF and association through the
  module are unproven until run on hardware.

### 4.9 `rtl.ko`: rtlwifi (PCIe) and rtl8xxxu (USB) as a loadable module

`narf-drivers-wireless-rtl --no-default-features --features module` builds
`rtl.ko` for x86_64 and aarch64. The rtlwifi and rtl8xxxu sources build both
ways: built in they are unchanged, and in the `.ko` they run over
`narf-module-rt` and the KABI.

- **Platform.** Kernel services come from `src/platform/`, one name in
  both builds.
  - `kernel.rs` re-exports the kernel crates (`narf_time` as `time`,
    `narf_lib` as `lib`, ...), so a built-in path is the kernel's own item.
  - `kabi.rs` implements the paths the drivers use: locks and the async
    mutex, `OnceLock`, the clock, sleeps and `timeout`, spawn and
    `block_on`, coherent DMA, frame channels, firmware assets, the
    regulatory domain, and the `Interface` / `WirelessNetIface` traits.
  - `usb_kabi.rs` implements the shared Realtek USB transport
    (`ControlIo`, `Io`) over `narf_usb_*`.
  - The kernel-free crates are linked with their `kernel` feature off:
    `narf-crypto`, `narf-wireless`, `narf-drivers-wireless-ath-core` and
    `narf-drivers-wireless-rtl-chip`.
- **Claim.** The tables are in `src/module_ids.rs`. A kernel test pins them
  to `ALL_DEV_IDS` / `RTL8XXXU_USB_IDS`, and the e2e test reads the same
  file.
  - PCI: all ten rtlwifi ids, `10ec:{8179, 8178, 8176, 8177, 8191, 8193,
    818b, 8723, b723, 8821}`. RTL8822BE (`b822`) is rtw88's.
  - USB: all 23 `RTL8XXXU_USB_IDS` rows. RTL8821CU / RTL8822BU are
    rtw88's.
  - `narf-drivers-wireless/rtl-module-only` leaves both built-in tables to
    an early-loaded `rtl.ko`, giving up the built-in drivers.
  - One device binds per module.
- **PCI probe** (`rtlwifi/pci_kabi.rs`, the built-in `probe` / `bring_up`
  order).
  1. `narf_pci_identity`: an rtlwifi id, and its PCI function.
  2. `narf_pci_prepare_probe`.
  3. BAR2 sized and mapped with Device attributes while decode is off
     (`narf_bar_map_control`), then memory decode on, the built-in
     `map_bar_control` order. Its length is checked by
     `identity::control_bar_ok`.
  4. ASPM off.
  5. `identity::identify` (NIC-enable power table, IRQ masks, the
     RTL8723AE EFUSE bank, the factory map and MAC), then
     `identity::admissible`. Both are the functions `pci::bring_up` calls.
  6. `pci::assemble` and `pci::bind`, also shared with the built-in:
     - the authenticated firmware owner, the preparation slot and (for
       RTL8723AE) the original cold owner;
     - the native station device;
     - publication;
     - the native preparation task.

  The kernel's 1 ms device poller and the MSI upcall drive the module's
  executor. DMA is retained on teardown (`narf_dma_retain_on_teardown`).
- **PCI authority** (`rtlwifi/firmware_native_kabi.rs`, the module's
  `PciIo` with the built-in API).
  - Every access passes the built-in `command_gate` on `narf_pci_command`
    (read with clear = set = 0): absent function, decode, INTx disabled,
    and bus mastering only in packet mode.
  - Every access also re-checks `narf_pci_identity`.
  - Bus mastering is set and cleared through `narf_pci_command`, read
    back.
  - Register widths go through `narf_mmio_read8/16/32` and
    `narf_mmio_write8/16/32`.
  - MSI: one vector (`narf_msi_enable`) whose upcall raises the device's
    signal. A withdrawn vector stays granted with delivery off and is
    reused.
  - ASPM: the endpoint policy is "off" (`narf_pcie_aspm`). A module
    cannot see the parent link's policy, and off is the built-in answer
    for an unknown bridge.
- **DMA.** `narf_dma_alloc_mapped` under each allocation's address limit,
  from a 4-64 KiB size-class pool carved from 1 MiB chunks, as in
  `ath11k.ko`. KABI mapped DMA is cache-coherent, so `DmaBuffer::sync` is
  an ordering fence.
- **Firmware and signed records.** `narf_firmware_open/read/signed`. A
  retained asset's `Cap<FirmwareBlob, Read>` is its open handle, and
  `invoke` re-checks it before every enclosed effect. Every
  calibration/envelope record still requires a verified signer, as built
  in. The KABI reports only that one exists, not which.
- **Regulatory domain.** `narf_wireless_regdomain` returns the kernel's
  installation (bootstrapped from the signed policy, or Linux world `00`,
  as `reg::db::ensure_domain` does). The module decodes the record with the
  shared `narf_wireless::reg::parse_domain_record`. rtl8xxxu's
  `reg::policy::load` reads the same installation.
- **PCIe station** (`module_netdev.rs`, through `interface::publish`). The
  worker loop, MSI, watchdog and runtime power save (IPS/LPS) are shared
  with the built-in.
  - The netdev is `wlan%d` (`narf_netif_register_with_context`). TX enters
    the device's own send hook. RX goes from the device's drain to
    `narf_netif_rx`.
  - `REGISTER_WIPHY` (§4.1) is built from the device's own bands, HT/VHT,
    ciphers (CCMP) and `PSK_OFFLOAD | REPORTS_DISCONNECT`.
  - The host's `SCAN_REQUEST` / `CONNECT` / `DISCONNECT` events run the
    device's `scan` / `associate` / `disassociate`, which includes the
    in-driver WPA2-PSK supplicant. A `CONNECT` without a BSSID takes the
    strongest match of the last scan.
  - Unsolicited link loss is reported as `DISCONNECTED`.
  - A function whose native station is not admitted is published as the
    built-in diagnostic profile: no event channel, so scan and connect
    answer `NotSupported`.
- **USB** (`rtl8xxxu/usb_kabi.rs`, the built-in `rtl8xxxu_probe`).
  1. Classify the dongle with `ChipFamily::from_usb_id` and refuse an
     unknown family.
  2. Start the device poller (`narf_usb_spawn_poller`).
  3. Configure the configuration's bulk/interrupt endpoints
     (`narf_usb_configure`).
  4. Run the family's chain unchanged (`rtl8xxxu::start`). RTL8188EU,
     RTL8192EU and RTL8723BU go through firmware, calibration and
     admission to the station. The others are detection-only.

  The station publishes a netdev through `narf_usb_netif_register_with_context`
  and runs `run_admin`'s UP branch at once (`module_open`), because the
  bridge delivers no `IFF_UP`.

  A USB function has no wiphy. The `WIFI` host binds sessions to a bus
  context's `Cap<BusDeviceCap>`, and minting one for USB would be a
  capability-model change. Its in-driver SME is therefore driven by
  `rtl.ssid=` and `rtl.psk=` (64 hex digits) / `rtl.passphrase=`
  (`.narf_kparams`), as in `rtw88.ko`: scan for the SSID, associate to the
  strongest match, and retry every 5 s while unassociated.
- **KABI.** Added by this module, in its own block:
  - `narf_bar_map_control`;
  - `narf_mmio_read8`, `narf_mmio_read16`;
  - `narf_mmio_write8`, `narf_mmio_write16`.

  Used from other branches: `narf_pci_command` (mt76),
  `narf_wireless_regdomain`, `narf_usb_spawn_poller`,
  `narf_usb_netif_register_with_context` and `narf_usb_netif_rx` (rtw88).
- **Not carried (built-in only).**
  - System suspend and WoWLAN: D-states, PME wake, config save/restore.
  - ASPM enable.
  - Removal's DMA-quiescence proof (DMA stays retained).
  - The userspace SME.
  - On USB: nl80211 control (no wiphy), and endpoint-halt recovery (the
    KABI has no clear-halt, so a stalled bulk pipe ends the attempt).
- **Match budget.** `rtl.ko` registers 23 USB matches. With `rtw88.ko`'s
  50 that fits the 128-entry module USB table.
- **Proof.** `modules/e2e/rtl` loads the real `.ko` and checks:
  - init runs to Live;
  - exactly the PCI table is claimed, and not `b822`;
  - with a USB stack, every rtl8xxxu row is held (a foreign registration
    gets `-EBUSY`), and not `0bda:c811`;
  - a probe with no device context is refused;
  - unload leaves no match.

  QEMU emulates no Realtek Wi-Fi device. Bring-up, firmware, calibration,
  association and data on silicon are unverified until a hardware boot.

## 5. Buffer Management

- **Data Path**: Ethernet frames cross the netdev frame rings
  (`narf_net::Frame`); each driver owns its device DMA (`DmaBuffer` caps
  from `io/`) and releases a buffer only on a validated completion.
- **Management Path**: 802.11 management frames stay inside the driver's
  own MLME/SME, or cross nl80211 as copies (`FRAME`, `REGISTER_FRAME`);
  there is no shared management-frame ring.

## 6. Regulatory Enforcement

Drivers must not transmit until a regulatory domain is set.
The implemented bootstrap is `narf_wireless::reg::db::ensure_domain()`
([shared wireless §3.5](../../../wireless/specification/spec.md#35-authenticated-regulatory-policy)).
It preserves a caller-installed domain or loads the exact signed
`wireless-regulatory.bin` through the firmware registry. Only an absent
policy file falls back to world `00` from the Linux regulatory database
authenticated at image build; an unsigned, malformed or inaccessible policy
never falls back and grants no transmit permission. The built-in Intel,
MT76, ath9k, ath10k, rtlwifi/rtl8xxxu, rtw88/rtw89 and CYW/BCM FullMAC
entrypoints use it independently of probe ordering. Loadable modules read
the same installation as an NRGD v1 record through the
`narf_wireless_regdomain` KABI export (§4), which bootstraps it the same way
and cannot install or change it.
Board calibration and firmware channel permissions remain separate mandatory
intersections. The image builder supplies deployment signing keys and policy;
driver startup does not infer a country from an AP or rely on a userspace
wireless daemon to establish that authority. After association, an AP's
Country element can select that country's Linux-database rules, but only
when the installation itself came from the Linux database
(`db::hint_country_ie`). The shared wireless specification owns the
in-kernel station/security and capability-gated nl80211 contract.

## 7. Stage Assignment

- **Stage 4**: Initial framework and the `WirelessNetIface` trait.
- **Stage 5**: First hardware driver (MediaTek MT76 series).
- **Stage 6**: Multi-band (6 GHz), beamforming, and advanced offloads.

## 8. Dependencies

- **Consumes**: `drivers/spec`, `wireless/spec`, `bus/`, `io/`, `capabilities/`.
- **Provides to**: `narf-wireless` subsystem.
