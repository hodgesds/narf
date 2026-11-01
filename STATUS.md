# NARF status

**2026-10-31 — I225/I226 wired Ethernet software expansion:** the built-in
IGC driver now implements independent MSI-X queue routing and CPU-pinned RX
workers, configurable rings/channels/RSS/coalescing, ethtool controls and
read-only diagnostics/NVM, negotiated pause/EEE, WoL and runtime/system PM.
The PHC is exposed through `/dev/ptpN`, dynamic clock syscalls and AF_PACKET
hardware timestamp/error-queue reports. Native controls add Qbv/CBS/launch
times, verified MAC Merge preemption and receive steering; native XDP and
exclusive direct-UMEM queues retain DMA ownership through completion and
failed recovery. Admin state, multiple built-in controllers, AER/removal and
the `.ko` copy datapath are integrated. The control/data protocols use
`~/git/linux` at `ecd997b0189a` as their reference.

Native scheduling/MAC Merge controls and NARF's capability-based UMEM rings
are paired with Linux `NETLINK_ROUTE` `tc` qdisc configuration (`taprio`,
`cbs`, `etf`), `SO_TXTIME`/`SCM_TXTIME` hardware launch-time ancillary
messages, `NETLINK_GENERIC` `ethtool` MAC Merge (`ETHTOOL_MSG_MM_GET`/`SET`),
and `AF_XDP` user-page `XDP_UMEM_REG` + `mmap` ring support (`XDP_PGOFF_*`,
`XDP_MMAP_OFFSETS`, `XDP_STATISTICS`). Module instances use
the copy-mode device C ABI. Physical acceptance on this host's I225-V
(`8086:15f3`, rev 01) remains open; see the
[driver contract](drivers/net/specification/spec.md#3-public-interface).

Validation: the broad QEMU suites pass **4,371 tests on x86_64** and
**4,098 on aarch64**, with zero failures and 13 skips each (including the
physical-I225 smoke). Both use two vCPUs and select network drivers/stack,
bus, power, time, filesystem, syscall ABI and modules; ARM additionally runs
the existing `userspace/perf` cache regressions. Debug/release and `.ko`
builds, targeted Clippy on both architectures and formatting pass. Production
boot and both filesystem postflights pass on each architecture. Logs are under
`target/host-narf/igc-all-features-20261030/`.

The expanded checks cover queue/timestamp/TSN/UMEM ownership and Linux ABI
regressions. The broad ARM run exposed a retained file-cache collision across
filesystem devices; the cache now namespaces anchors by device. The
deterministic cross-device regression fails on base commit `1096f6b7b` with
only the test added and passes with the fix. The standalone FAT test on the
pristine base also passes, confirming the order-sensitive retained-cache
collision rather than a FAT image-construction failure.

This page tracks milestone progress and the boundaries of its proof.
Subsystem specifications define the contracts; run the commands below for
current test results.

## Stage progression

| Stage | State | Evidence and limit |
| --- | --- | --- |
| 1 · Skeleton | Closed | x86_64 and aarch64 QEMU boot, serial output, executor, and timer work landed. |
| 2 · Barrier | Closed for the original PKS/MTE path | Domain switching and fault tests landed. Later PCID fallback coverage is tracked separately. |
| 3 · Flow | Composition gate met | `smoke_exit_gate_buffer_handoff` and `smoke_exit_gate_revoked_cap_rejected` exercise the ring, DMA buffer, and capability path. They are not a proof that a real VirtIO device transfers a protected buffer across domains on both architectures. |
| 4 · Compatibility | In-tree shell gate met; compatibility continues | Interactive `echo hello world` follows serial IRQ → input ring → shell → UART. Linux-compatible musl programs, storage, networking, and graphics have additional QEMU proofs. The original relibc-specific criterion is not the closure proof. |
| 5 · Silicon | In progress | Driver and diagnostic foundations exist; the selected AMD laptop end-to-end gate has not been demonstrated. |

## WCN6855 source alignment

The ath11k WCN6855 source path now includes Linux-shaped per-TID TXQs with
the 4096-flow fq/CoDel scheduler, ECN handling and requested-TX-status drops,
cfg80211's TKIP `MICHAEL_MIC_FAILURE` notification, and Linux-style managed
station recovery: external-SME, Open and completed in-kernel RSN vdev/peer/
BSS/EDCA/key replay without new auth or assoc frames (BA sessions reset).
Beaconing AP/GO recovery likewise replays beacon and MBSSID state, group
keys, clients, PTKs and authorization; shared-radio reconfiguration wakes
queues only after every live vdev is rebuilt. `GET_STATION` now reports
monitor-status PPDU combined/chain RSSI, Linux-style raw-RSSI EWMA,
RX/TX duration and detailed HTT TX rate telemetry. Monitor mode, TX A-MSDU,
AQL and airtime-fairness are not listed as open WCN6855 work because Linux
ath11k does not expose those capabilities for this hardware. This is
source-level implementation progress only: no build, emulation, or hardware
validation was run while the equivalence work remained in progress.

## MT7921/MT7922 firmware bringup

The x86_64 and aarch64 MT76 late init path now owns coherent WM/FWDL/MCU DMA rings and
performs ROM restart, patch semaphore negotiation, patch/RAM download and
firmware-ready verification. Post-firmware MCU commands obtain the real MAC
and PHY, read EFUSE hardware identity, select embedded world country limits,
select on-chip calibration and initialize MAC/WTBL/RTS. Unified device command
framing now matches the local Linux reference. Waits are bounded and report the current stage;
failed or cancelled attempts retain published DMA until verified shutdown.
The retained RX ring and MCU scan path now support passive 2.4 GHz scans on
channels 1–11. Successful radio initialization registers a wireless
interface with the real MAC and supported regulatory channels.
The private cut-through management TX backend retains each payload until
both descriptor completion and firmware token release. RX routing separates
forwarded normal frames, MCU responses and TX releases on all rings.
Live join dispatch is integrated with regulatory authorization, channel/power
switching via `MCU_EXT_CMD_CHANNEL_SWITCH`, open-authentication/association MLME
handshakes, and IEEE 802.11i WPA2-PSK 4-way handshakes (M1..M4) with HMAC-SHA1 MIC
verification/generation. WTBL station records commit temporal keys with
tag 0x12 (`STA_REC_KEY_V2`), cipher 6 (`MCU_CIPHER_AES_CCMP`), and `PORT_SECURE`.
The retained legacy 2.4 GHz station profile now uses Linux's packed 76-byte
channel request and UNI3 station/key commands. It installs the BSSID and
unauthorized AP WTBL before authentication, then drives peer-bound RSNA with
M3 RSNE/MIC/ANonce/KDE checks, pairwise/group keys and per-key/TID CCMP replay
windows. Kernel transmit, capability frame rings and RX delivery share a
bounded service step with synchronous network waiters; owned rekey work can
progress even when its original waiter is cancelled. Peer disconnect closes
carrier and acknowledged key/WTBL/BSS cleanup precedes reuse. Verified WFSYS
reset, DMA stop/retirement and firmware reload now recover failed/cancelled
control without replaying station keys; failed quiescence retains allocations.
Initial startup failure and registered-interface recovery use retained owned
futures with bounded retry/backoff. Broader radio modes, removal and PM remain
software work. No off-box radio, DHCP or AP interoperability has been demonstrated.

## Wi-Fi family software bring-up

Wi-Fi and GPU now maintain native Rust implementations and validation. The
ad-hoc Python/C reference-compilation, source-extraction and temporary Rust
comparison harnesses have been removed. Hardware tables and fixed source-cited
fixtures remain reviewed data; Rust tests exercise actual production functions,
wire contracts, boundaries and failure/ownership behavior. Historical source
hashes do not assert current Linux/Mesa equivalence or physical acceptance.
Firmware parser cases are authored in Rust; extracted firmware metadata binaries,
their regeneration commands and missing-file skip stubs are removed. Explicit
deployment board-manifest encoding remains native Rust through
`cargo xtask wifi-fixtures board-manifest`.

All eleven in-tree families are covered by the current audit and dependency
ledger in `drivers/wireless/specification/spec.md` and its family documents.
The branch target is **all eleven Wi-Fi families with all hardware/firmware
supported features ready for physical testing**. Each chip/revision, firmware API
and board profile needs a feature inventory, reachable implementation and
transition/failure evidence; PCI/USB matching alone is not support. The
family software ledger in `drivers/wireless/specification/spec.md` records
the open work. Recovery, wider PHY/chip coverage, security/roles and power
management are part of this target where supported.

The initial station milestone is scan, Open/WPA2-PSK, DHCP and bidirectional IP,
with controlled-port closure and safe transport ownership on disconnect/failure.
Eleven families have composed kernel-DHCP paths (Intel Sc, MT76,
ath11k, ath10k, AR9285, RTL8188EE, RTL8188EU, RTL8822CE, RTL8852B, CYW43439 and BCM43602); exact authenticated firmware,
board/calibration/policy provisioning, reset/wiring handoff and physical
validation remain required. The initial software paths are
implemented; broader chip/PHY/feature/lifecycle coverage remains required before
the branch target is met.

The first parallel feature wave adds retained API77 Intel management-queue
ADD/REMOVE behind the inactive PHY/TX-disabled peer (including the actual native
eight-byte removal response), MT7921/MT7922 active scans with four directed or
wildcard SSIDs and current per-channel power/NO_IR policy, and a distinct
RTL8821CE factory/firmware/inactive-MAC owner. Gen2 active station TX and C21
PHY/RF/station admission remained gated after that wave on their documented
prerequisites.
The common FullMAC path now exposes BCM43602 firmware-reported 2.4/5 GHz
channels with confirmed firmware 20 MHz caps, correct D11AC primary decoding
and native Open/WPA2 DHCP/IP coverage on channels36/149. CYW43439 remains
2.4 GHz only. Shared NRGD NO_IR policies preserve passive discovery while
closing host-initiated TX. The second wave below adds live shared FullMAC
policy replacement/clear observation.

The second parallel feature wave implements retained Intel API77 v5
SET_CHAINS/SET_LINK power preparation with a signed exact-platform static
SAR/antenna-gain qualification, fresh firmware channel permissions and current
host limits. It enables no Gen2 station TX. MT76 now has bounded native
hardware-deaggregated A-MSDU receive ownership, atomic subframe release and a
single CCMP PN commit per complete MPDU, with inactive HT20 receive preparation;
production HT/WMM negotiation, STA_REC/WTBL/RA, EDCA and QoS TX remain open.
RTL8821CE now reaches inactive PHY-table preparation using its own MAC/BB/AGC,
optional BTG AGC and SIPI RF-A tables, exact package/RFE/cut/path selection and
retained filter snapshots; emitting calibration/radio/station remain gated.

Native CYW43439/BCM43602 FullMAC owners now observe live shared regulatory DB
replacement/clear, including every resume of native control futures, actual
receipt/idle fences and packet admission. Missing policy, country change,
channel/NO_IR/DFS denial or a lower ceiling than acknowledged firmware power
poisons the one-shot owner, closes host admission and clears queued host TX.
Looser same-country policy preserves the original acknowledged power; reinstall
and stale events cannot reopen a failed owner. An intervening clear also defeats
an in-flight signed bootstrap. This does not automatically follow revocation of
a cached policy firmware capability, retract in-flight RF or prove autonomous
firmware radio quiescence; uncertain DMA remains retained.

Ath10k now supports directed and wildcard active discovery through its retained
HTC/WMI/HTT owner on all six firmware dialects. The initial channel1–11 legacy20
profile advertises sixteen SSIDs and requires current host policy plus the
existing factory CTL/power bounds. Ordered domain, minimum band-power and
per-channel half-dBm limits precede probes; every command/receive poll rechecks
policy, and matching completion restores the entire receive-only channel list
before publishing results. Rust packet and native CE models cover probe replies,
SSID bounds, cancellation, policy restriction, failed terminals and active-cache
Open/WPA2 DHCP/IP/teardown. Associated/off-channel scanning, broader PHY/bands,
reset/rejoin and physical acceptance remain open.

The ath10k scan continuation adds caller probe information elements to the same
six-dialect owner. Its 256-byte firmware budget now reaches nl80211 discovery
and pre-dispatch validation through a per-driver limit; complete element checks
and immutable plan ownership precede I/O. Authored Rust packets check raw versus
padded lengths, binary/maximal content and all six dialects, while native CE
Open/WPA2 DHCP/IP conversations include extra probe elements. Invalid input stays
retryable; cancellation or policy loss after publication retains DMA and closes
the owner. This does not expand the initial PHY/channel profile.

The parallel driver continuation now adds Intel API77 active-link/deactivation
with source-matched response rates and fresh power/MCC receipts, while retaining
the TX-disabled peer and management/data gates. Gen2 Qu prerequisites now use
native header0 independently of their negotiated payload versions; Gen3 is
unchanged. MT76 negotiates driver-owned WMM
Information/Parameter IEs, programs native BSS/peer/WTBL QoS and CE EDCA, and
carries BE/TID0 QoS through actual Open/WPA2 DHCP/IP. HT/aggregation stays gated.
Live policy clear/restriction fails old MT76 scan/station grants across command
waits rather than reloading policy into them.
RTL8821CE advances from inactive PHY tables through an exact-board signed
calibration-only envelope, channel1/20 setup and real firmware IQK receipts;
operating power/radio/station still need their separate grants. RTL8822CE's
actual reserved backend now completes radio preparation through an explicit
Continued lifecycle state, including failure/cancellation coverage.

Ath10k manual recovery parks all CEs and verifies BME disable before scheduling
fresh chip reset, authenticated ROM provisioning and a new runtime/interface.
Retirement tokens, unique TX cookies and reserved old names fence cancelled
control and late publication; old physical Drop cannot touch its successor.
All old firmware/CE/WMI/HTT mappings remain pinned, with three attempts per boot
bounding retained generations. Automatic/stable-interface recovery, DMA
reclamation, broader PHY features and physical reset/RF acceptance remain open.

The next parallel wave advances all eleven families: Intel Gen2 native Open
authentication with acknowledged peer re-disable; ath11k physical PDEV power
readback with reset/query fencing; MT76 response-bound HT20 MCS0–7 long-GI and
bounded A-MSDU receive admission; AR9285 directed/wildcard active discovery;
and ath10k six-dialect native station power-save intent before carrier.
CYW43439/BCM43602 add firmware-owned WPA2 AP-required PMF with native capability,
peer and association-RSNE readback, public cipher exposure and explicitly gated
nl80211 PMK CONNECT admission. RTL8188EE, RTL8188EU and qualified RTL8852B
add native response-bound WMM BE/TID0 QoS; the shared formatter constructs the
QoS header before CCMP and preserves the installed key's TX packet-number
sequence. RTL8821CE IQK now uses fresh hardware thermal conversions and a new
signed recipe identity. Narrow PHY/security contracts and retained terminal
ownership remain explicit in each family spec. Hardware acceptance and the
remaining software ledger are still open.

The combined selected Wi-Fi/shared-fixture QEMU gates pass 1848 / 0 fail / 9 skip
on x86_64 and 1381 / 0 fail / 3 skip on aarch64, with clean production boots
and btrfs postflights. Scoped production/kernel-test Clippy and workspace
formatting pass; default release and debug kernels build on both architectures.
This continuation adds 58 passing smokes on x86_64 and 54 on aarch64; four
native ath11k physical-transport integration cases are x86_64-specific. Native
PMF tests include real nl80211 parsing/dispatch through both FullMAC transports,
with unsupported capability and additional-security requests rejected before I/O.
Native Rust tests cover the queue and v5 power ABIs, active scan requests/power
ordering, bounded A-MSDU conversion and C21 factory/MAC/PHY behavior using fixed
reference data and explicit ownership invariants. D11AC coverage uses exhaustive
geometry/round-trip checks and literal channel/sideband cases. The second wave adds 31 passing
smokes on each architecture, including native control-credit policy changes,
partial aggregation/replay cleanup and retained C21 DMA ownership. The payload catalog
now contains 45 profiles across all eleven families, including the actual
139472-byte RTL8821CE image; 15 required fixed payload entries remain absent.
These are software/source/asset checks and do not establish physical acceptance
or full hardware-feature completion.

The subsequent continuation adds native Gen2 legacy association, ath11k sibling
channel-reservation recovery, MT76 HT40/SGI and actual FullMAC HT20/SGI readbacks.
AR9285 now has negotiated legacy rates, native four-series retries and adaptive
terminal DATA feedback; ath10k admits fixed-country non-DFS 5-GHz legacy station
and mixed-band active scanning across all six dialects. RTL8188EE/EU and
qualified RTL8852B gain response-bound legacy DATA rates; RTL8821CE gains parked
post-IQK operating-power preparation, with no station transmit grant.
The combined Wi-Fi/shared-fixture suites pass 1887/0 fail/9 skip on x86_64 and
1417/0 fail/3 skip on aarch64 with clean production boots and btrfs postflights.
Scoped production/kernel-test Clippy, workspace formatting and release/debug
builds pass on both architectures. The wave adds 39 passing x86_64 smokes and
36 on aarch64; three native ath11k recovery cases are x86_64-specific.

The following wave adds retained native Gen2 Open data ownership with DCF/TLC,
TID0 DMA and receipt-fenced teardown, while automatic PCI/netdev/WPA2 keys remain
gated. MT76 gains bounded recipient BA/reordering and ordered key retirement;
native rekey tests also corrected KEY_V2 tag17/install0/remove1 ABI fields.
Ath10k gains response-bound WMM/QoS and policy checks across native station and
RSNA waits. RTL8821CE reaches native Open/WPA2 kernel DHCP/IP through its original
reserved-DMA owner and distinct signed full-static thermal/power qualification.
Real measured deployment assets and RF acceptance are still required.
The wave adds 39 passing smokes per architecture: combined Wi-Fi/shared-fixture
suites pass 1926/0 fail/9 skip on x86_64 and 1456/0 fail/3 skip on aarch64.
Production boots/btrfs postflights, scoped production/kernel-test Clippy,
workspace formatting and release/debug builds pass on both architectures.

The next continuation adds native Gen2 WPA2 keys, authenticated EAPOL/M4
receipts, RX-epoch fencing, encrypted data and rekeys with key-before-queue
retirement. Automatic Gen2 PCI/netdev publication remains gated. FullMAC
HT40/SGI40 now requires actual firmware capability/inventory, negotiated AP
facts and current power authority for both occupied channels, with 20 MHz fallback.
RTL8822CE gains distinct signed N22L WMM/legacy-DATA-rate qualification and
current source/PCI checks around final carrier and host-frame publication;
RTL8821CE keeps its separate legacy grant. Shared native Intel test owners now
live on the heap to bound nested aarch64 fixture construction. These advances
remain software evidence; genuine assets, firmware/RF acceptance and the
all-family feature backlog remain required.

This wave adds 39 passing smokes per architecture: combined Wi-Fi/shared-fixture
suites pass 1965/0 fail/9 skip on x86_64 and 1495/0 fail/3 skip on aarch64.
Production boots/btrfs postflights, scoped production/kernel-test Clippy,
workspace formatting and release/debug builds pass on both architectures.

The [per-chip inventory](drivers/wireless/research/chip-inventory.md) audits all
102 registered bus identities. Tokei measures 316,060 Rust code lines including
tests/tables in the specified scopes, compared with 1,177,080 C/header lines in
broader local Linux driver and mac80211/cfg80211 directories. These are footprint
counts, not completion percentages. Initial remaining-LOC forecasts were
withdrawn after review found overlapping work; a delivery date remains uncalibrated.

The next feature checkpoint connects exact API77 Gen2 PCI discovery to the
retained native station worker, passive scan, Open/WPA2 DHCP/IP, rekeys and
ordered local retirement with current firmware/power/PCI/generation fences.
Scan freshness conservatively starts before native publication. MT76 adds
fresh-peer TID0 transmit BA with real ADDBA and WTBL/STA receipts, eight owned
packets with separate DMA/TX-free proofs, refusal fallback and key/BA retirement.
RTL8821CE adds distinct measured N21L legacy-rate/WMM qualification through
its original C21 radio and reserved DMA. Ath10k adds response-bound HT20,
native RX BA/PPDU ownership and reorder before PN, bounded authenticated
A-MSDU receive and final current-policy/port publication checks.
Shared Rust A-MSDU and opaque reorder owners preserve the default receive
contracts and make whole-aggregate validation, sequence wrap/BAR/hole expiry
and receive-epoch retirement reusable. These are software advances; the
all-chip/all-feature inventory and real assets/firmware/RF acceptance remain open.

This checkpoint adds 93 passing smokes per architecture: selected Wi-Fi/shared
fixtures pass 2058/0 fail/9 skip on x86_64 and 1588/0 fail/3 skip on aarch64.
Production boots and both btrfs postflights, scoped production/kernel-test
Clippy, workspace formatting and release/debug builds pass on both architectures.

Shared typed HT/VHT admission now binds membership requirements and directional
MCS/GI limits to the original BSS and one atomic association response. Intel
Gen2 adds native WMM/HT20/SISO through response-bound EDCA/peer/TLC, QoS CCMP,
staged firmware-deaggregated A-MSDU and actual ADDBA declines. Its distinct
emission tag 2 qualification cannot reuse the preceding legacy-only power record.
MT76 adds 5 GHz VHT20/40/80 with four-channel policy/power receipts, native VHT
records, coherent width retuning and the existing TX/RX BA and packet owners.
RTL8821CE/RTL8822CE add separately qualified HT20, exact chip gain/readback
paths, native PHY-status checks before crypto, authenticated A-MSDU up to 3839
bytes and per-callback receive-epoch fencing across rekey. Shared nl80211
cache and connection-owner lifetimes distinguish replacement netdev identities
and socket-owner grants, including delayed control work and socket release.
Native Rust conversations
exercise Open/WPA2 DHCP/IP; real qualification assets, firmware/RF acceptance
and the broader all-family software ledger remain required.

This continuation adds 88 passing smokes per architecture. Selected Wi-Fi/shared
fixtures pass 2146/0 fail/9 skip on x86_64 and 1676/0 fail/3 skip on aarch64.
Production boots and both btrfs postflights, scoped production/kernel-test
Clippy, workspace formatting and release/debug builds pass on both architectures.
The native MT76 channel-switch command now encodes receive-chain count while
RLM retains its mask; literal and retained-control tests cover their distinction.

The `codex/wifi-aggregation-next` checkpoint passed the coordinated Wi-Fi
suites: x86_64 2317 pass,0 fail,9 skip; aarch64 1847 pass,0 fail,3 skip.
The selected scope is `drivers/wireless,wireless,verification/wifi-fixtures`.
Production boots and both btrfs postflight checks were clean on each
architecture. Debug/release builds, strict production/test Clippy, exact CI
feature-context Clippy, workspace formatting and whitespace checks passed.
MT76 code now extends VHT to
MCS8 at20MHz and MCS9 at40/80/160MHz, actual NIC RX1/2 with TX1 and the matching
HT receive companion, directional LDPC and one-data-stream receive STBC.
Contiguous160 is gated by actual MT_HW_CHIPID0x7922 plus checked NIC facts;
native domain/SKU/power grants retain all eight occupied channels. Revised
and deprecated AP encodings, truthful primary80 fallback and response retune
are implemented, with native Open/WPA2 RX2/BA/nested-A-MSDU DHCP/IP vectors
passing in those suites. PCI aliases and the opaque NIC max_bw byte grant no160.
Recipient BA now retains exact negotiated windows1–64 with independent
sequence slots through12-bit wrap, including non-power-of-two sizes.
Recipient A-MSDU-in-A-MPDU now binds the actual request/native STA/response
bit, whole native assembly and post-reorder PN; the shared aggregate parser
supplies atomic subframe and VLAN control-port checks before delivery.
Active scanning now carries complete optional Probe Request elements in the
native600-byte field with preflight and the existing power/cancellation owner.
Per-request scan randomization resolves the source-defined mask with fallible
secure host entropy while preserving the original station MAC and passive NO_IR.
MT76 receive batches now carry current station/key epochs through unlocked
kernel callbacks and serialized IPC publication, retiring stale batches and
receive queues across key service and peer/transport replacement.
Native normal/forwarded copies now retain their original epoch and port
admission through command/TX waiters and a bounded completed-ring prefix.
The RSNA owner keeps ordinary RX/TX and BA setup closed between replacement
M2 and M3 until actual M4/key receipts. The direct async receive API also
rechecks its original epoch after key service. Native software vectors pass;
a complete late firmware/MAC/FIFO key-retirement proof remains separate work.
Native records preserve scan/response directional bounds and width-specific
mandatory maps; RX metadata is checked before replay-PN commit. Shared typed
PHY constructors retain default-off optional coding for other drivers.
The shared software security formatter now retains sixteen independent QoS
sequence counters and a checked non-consuming SSN sample, separate from
non-QoS/EAPOL sequences and the shared monotonically increasing key PN.
An explicit shared BlockAck-policy A-MSDU entry preserves the original CCMP
header and whole-aggregate PN transaction after native BA/reorder proof;
default aggregate methods retain their stricter normal-ACK profile.
The preceding green totals describe earlier merged checkpoints. The Intel
milestone now includes Gen2 native BA/pipelining,
retained GTK reconnect history, exact Gen3 command/queue receipts, retained
executable/PNVM authority and native EMPTY-marker receive epochs. C21/C22
recipient BA and separately qualified four-slot transmit BA/pipelining pass
the same native software suites. AR9285 HT20, recipient BA, directional
RX STBC1 and native RTS/CTS protection are covered too; transmit aggregation
and wider profiles remain open. Peer review closed stale direct receive and
IPC-queue paths across native key-owner replacement, plus terminal handling
of lost notification prefixes. Family specifications retain the exact
chip, source, qualification and remaining-feature contracts.
These changes do not close the all-family feature
ledger or establish physical acceptance.

The following same-branch continuation passed the coordinated Wi-Fi suites:
x86_64 2360 pass,0 fail,9 skip; aarch64 1890 pass,0 fail,3 skip, adding43 native
smokes per architecture over `3fbdfa9c2`. Debug/release builds, strict
production/test and exact CI feature-context Clippy, workspace formatting,
provisioning diagnostics, both production boots and all four btrfs postflights
passed. Intel Gen2 adds separately qualified nested RX A-MSDU-in-A-MPDU with
whole-original bundle reorder before PN admission. C21/C22 add separately
qualified native RTS threshold control with CCX/FIFO ownership and EAPOL
exclusion. AR9285 adds qualified two-MPDU sender BA, exact native tail bitmap
receipts, original ciphertext retries and BAR recovery through actual native
TX status. MT76 retains valid AP WMM contention updates, pauses new DATA until
old native tokens drain, and orders EDCA through its checked PSE read before
resuming the existing peer/key/BA owners. Open/WPA2 DHCP/IP, cancellation,
current authority and key transitions pass native Rust cases. Real measured
qualification records, physical acceptance and the broader feature ledger
remain open. Tokei15 measures4,767 net additional Rust code lines, including
tests, across `drivers/wireless`, `wireless` and `verification/wifi-fixtures`;
the total rises from364,095 to368,862. These counts are not a completion fraction.

The new `codex/wifi-feature-completion` branch continues from merged PR#1090
(`267146076`). Its validated software checkpoint adds ath10k HT40 with retained
firmware/BDF authority and native protection, separately qualified RTL8188EE
HT20, BCM43602 VHT80 with final receive-publication fences, and MT76 actual
NIC/AP-qualified TX2 with full native rate maps, RF/RLM setup and conservative
power headroom. Shared native PHY snapshots preserve original offer/response
limits. Native Rust cases and existing Open/WPA2 DHCP/IP compositions pass:
x86_64 2419/0 fail/9 skip; aarch64 1949/0 fail/3 skip, adding59 smokes per arch.
All-family feature completion and physical acceptance remain open.

Debug/release builds, strict production/test and exact CI feature-context
Clippy, workspace formatting, metadata diagnostics, both production boots
and all four btrfs postflights pass. Tokei15 measures6,859 net additional
Rust code lines, including tests, across `drivers/wireless`, `wireless` and
`verification/wifi-fixtures`:368,862 to375,721. No binary assets were added.

The same-branch continuation adds independently gated ath10k SGI40, separately
signed RTL8188EU HT20/LGI MCS0–7 with whole RX A-MSDU, directional MediaTek HT
greenfield/native mode3, and bounded CYW43439/BCM43602 optional-PMF CONNECT.
Native request/response, actual executable/factory/program authority, occupied
power, key/replay and final receive-publication checks remain mandatory.
Optional PMF with an MFPC AP omitting response RSNE remains open until a genuine
native negotiated-state proof exists. Wider software features and physical
qualification remain open.

All45 new native/shared smokes pass on each architecture. ARM's complete selected
scope passes1994/0 fail/3 skip. X86 has2464 distinct passing cases and9 skips
across the complete scope and affected-family reruns: three fixture failures
were corrected without weakening production gates, including actual old-key
CCMP and proposed-key MIC verification during USB rekey. Both production boots,
all four btrfs postflights, both-architecture debug/release builds, strict
production/test and CI-context Clippy, formatting and metadata diagnostics pass.
Tokei15 measures4,427 net additional Rust code lines including tests in the same
scope:375,721 to380,148 across855 Rust files. No binary assets were added.

The preceding station power-save continuation added ordinary firmware station power save to the
common CYW43439/BCM43602 owner. PM_FAST/PM_OFF and the default sleep-retention
commands are serialized with station control; partial failure or cancellation
closes packet admission without releasing uncertain DMA. Seven new native
power-save smokes cover both transports, and the existing Open/WPA2 DHCP/IP
conversations run with power save enabled. Its initial all-family wireless
and shared-fixture QEMU suites passed: x86_64 1672 pass / 0 fail / 9 skip;
aarch64 1209 pass / 0 fail / 3 skip. These remain software checks; actual
power/DTIM behavior and system suspend/wake need their separate acceptance.
The PS/disconnect-overlap regression also passed the focused FullMAC
suites (x86_64 168 pass / 0 fail / 1 skip; aarch64 115 pass / 0 fail / 0 skip):
an older firmware power receipt cannot reopen host admission closed by disconnect.
The provisioning catalog now names the current EE/8822CE/8852B measured board
artifacts and B reset handoff. Its local audit covers 44 profiles across all
eleven families, with 15 required fixed payload entries absent (12 Intel and
three CYW43439); payload presence does not establish signing/board qualification.

Intel now sends versioned coexistence, SoC latency and awake-power setup.
A retained Gen2 context-v1/RFH/TFH boot owner now covers APM, ALIVE6, unified
NVM and MVM post-init configuration. Its API77 passive-scan owner now composes
current signed host policy, fresh MCC/LAR, conditional DQA, versioned MAC/link
receipts and scan15 channel records; automatic Gen2 station admission remains
gated. An inactive PHY/link owner now checks receive-channel policy, programs
the API77 PHY/RLC commands and requires acknowledged unbind/remove before reuse.
A subsequent retained AP-peer owner validates current receive policy/MCC, emits
the exact API77 TX-disabled legacy station entry and requires native ADD status
and REMOVE receipt before identity reuse. It keeps packet queues, keys and
active station admission closed.
Host nonce and SAE paths require fallible hardware entropy instead of
the old timing seed; validated RSNA M1 renewal alone requests a fresh SNonce.
Full system entropy-pool/health services remain open.
Its retained maintenance work progresses through synchronous packet service;
stalled TX credit no longer prevents RX and cancelled waiters retain EAPOL work.
MT76 retains cancelled work through bounded WFSYS reset, firmware reload and
radio reinitialization, without replaying association or keys. Its coherent
PCI backend and ownership models now build on x86_64 and aarch64; unsupported
per-domain IOMMU mapping remains rejected. Its legacy 2.4/5 GHz path now binds
RX to the selected channel, carries band-specific firmware settings, selects
the AP basic TX rate and checks optional SME association/security IEs.
CYW43439 now connects standard PCI SDHCI PIO/card enumeration or an explicitly
supplied platform card through trusted firmware/NVRAM/CLM loading, mailbox/F2
control, scan, Open/WPA2 and bounded RX/TX. Board clocks/pins/regulators, gSPI
host support and reset/reload/PM remain software work. Qualcomm ath10k reaches
owned CE/BMI firmware/BDF/OTP, PLL and code-swap preparation, retained HTC
runtime and versioned WMI service-ready/host-memory/INIT/READY, followed by
retained HTT RX buffers and native TX/management completion. A retained WMI
radio session now performs correlated passive scans across six dialects while
servicing HTT completions. Station-context preparation now intersects immutable
factory regulatory limits with authenticated host policy and an observed BSS,
then waits for correlated vdev-start and sparse HTT peer-map completion.
Initial Open authentication/association exchanges now use the actual dialect's
inline WMI, retained referenced WMI or HTT management path, with peer-bound RX
and bounded progress under unrelated-event floods. Shared JoinPlan now drives
native PEER_ASSOC/VDEV_UP and rejects queued peer loss before reporting success.
Response-negotiated legacy rates now reach native PEER_ASSOC. Terminal station
teardown drives native DOWN/DELETE, every sparse-ID UNMAP and conditional TLV
delete ACK, then STOP/STOPPED with receive quiescence. Even confirmed teardown
retains DMA and stays closed until a future full reset/generation owner.
A RAW-capable, non-PFC legacy station owner now composes descriptor/peer/TID
admission, shared host RSNA/CCMP, exact native HTT delivery receipts and
bidirectional Ethernet/IP across all six dialects. Firmware RAW INIT and
A-MSDU1 are required before software crypto; opaque native-WiFi RX is not
treated as ciphertext. The same retained native owner now implements bounded
synchronous CE/HTC/HTT packet progress, netdev attachment, kernel DHCP and
connection-loss closure. All six dialects compose Open/WPA2 with a reactive
AP through a real lease and exact bidirectional IP. Current signed policy is
resampled before control and packet progress; tightening or removal closes
the initial profile permanently. Publication is serialized with terminal
closure, while M4 waits for its exact HTT receipt rather than CE consumption.
PFC, broader RX/security profiles and reset/rejoin remain separate follow-ups.
Ath9k programs AR9285 inactive PHY/PLL/RF INI, EEPROM modal and PDADC detector
tables with current-capability register access. Factory CTL edges and target
power now bound the rate-power registers under an explicit zero-dBm ceiling.
Native legacy20 mode/timeouts, single-chain masks, delta slope and EEPROM
spur filtering now match 48 original Linux C traces after full INI setup;
signed-policy channel1 calibration now additionally composes SerDes, synth
settling, AGC/carrier-leakage retry, PA, noise-floor and IQ correction. Thirty-two
original Linux C traces and 35 IQ vectors cover that sequence; per-access
failures, deadlines, cancellation and revocation leave the same retained
attempt closed. The same AR9285 owner now continues through native MAC/PCU,
cleared hardware keys and 32-bit non-EDMA packet rings into shared MLME,
RSNA/CCMP, a retained Device and the actual kernel DHCP client. Open/WPA2
conversations check exact IP, native M4 bytes/receipt, genuine RX-idle fencing,
publication/close races, current policy, factory RF-silent GPIO and retained
DMA after terminal failure. Seventy-two fixed Rust TX descriptor vectors, ten RX
status vectors and ten MAC traces independently check native formats.
The initial channel1/basic1Mbps profile is polled, awake and terminal on
disconnect; wider PHY, IRQ mode and reset/rejoin remain separate.
Ath11k QCA6390 has
its native IPQ8074 RX path and four-vdev resources; QCN9074 remains gated.
Realtek has per-family identity/power work, a retained RTL8188EU factory/FIFO/
firmware/MAC/BB/RF/LLT plus LC/IQK worker and bounded native RTW89 TX ownership.
Production AES-CCM, shared CCMP AAD/replay corrections and checked per-key/TID
station wrappers provide software crypto prerequisites; channel/power and
native station paths remain incomplete. The retained host CCMP/RSNA key,
PN/replay, no-reinstall and terminal-M4 owner now lives in shared wireless;
RTL8188EU keeps compatibility reexports and its exact raw-profile checks.
RTL8188EU now has a persistent native
packet receipt/stop owner, channel1/XTAL initialization and a bounded shared
management association plan. Signed, exact-board calibration artifacts now
gate native transmit gains and MAC TX activation; missing qualification keeps
TX closed. The initial channel1 station service now composes native USB
management/data, authentication/association, RSNA and CCMP with Narf-Rings and
synchronous packet progression; the exact terminal M4 receipt precedes key/port
commit. Signed board curves and deployment policy are required for publication.
Reset/rejoin generations, broader channels/rates and PMF remain software work.
RTL8188EE now carries a one-shot continuation from its exact firmware owner
through LLT and distinct linked TX/RX ring preparation, retained before native
publication. Its factory-qualified continuation now programs complete native
MAC/BB/AGC/RF tables and runs 1T IQK/LCK with retained matrix and per-rate PG
offsets. Native C traces cover the full register/delay sequence, while failure
and cancellation keep DMA parked. Its channel/power owner now binds factory
EFUSE/PG indices to an authenticated exact-board curve, current host policy and
the independent Linux EE world ceiling. A native polled packet core retains
those same linked descriptors and buffers through publication and stop. Its
EE-only ring map, complete DMA extents, terminal OWN receipts and RX admission
are checked independently. The same retained owner now supplies firmware
power-mode/mailbox and reserved-beacon prerequisites, shared MLME/RSNA/CCMP,
native Device attachment and actual kernel DHCP with exact bidirectional IP.
Native M4 receipts and bytes, real RX-idle fences, current policy and serialized
publication/closure gate authorization. Tests hold DMA, CAM and mailbox work
across close/cancel and preserve storage plus terminal state. The initial
channel1/basic1Mbps profile stays awake and requires a fresh lifecycle after
terminal closure; measured board-power qualification remains mandatory.
RTL8822CE now retains an authenticated section-firmware attempt through native
all-ring-owned beacon reserved pages and IDDMA. Success parks DMA; ambiguous or
cancelled mappings stay pinned. It continues through inactive MAC/LLT/FIFO setup,
complete logical factory EFUSE and protected OTP, an actual firmware hardware
feature response, source-selected BB/AGC/RFK-init/RF tables and a signed exact-board
power qualification. Forty-nine cut/RFE traces check table application. It now
continues through fresh bounded DACK/IQK, H2C, awake software-crypto setup and
the same registered Device through scan, Open/WPA2, actual kernel DHCP and
exact bidirectional IP. Actual TXBD consumption plus matching CCX ACK and DMA
bytes gate security replies; a genuine RX-idle fence excludes queued peer loss.
Current policy and the signed v2 calibration/response envelope are checked at
publication. No measured gain curve or transmit permission is inferred from
factory indices. RTL8821CE/RTL8822BE remain identification-only profiles.
RTW89 has checked owned AX firmware selection, cold-power/DDV primitives and
fuse-selected immutable header/section download plans with host blacklist
enforcement. Power-off/normalization and DLE/HFC primitives now have Linux-C
trace coverage. Native CH12 commands now retain DMA through the multi-tag
delay and use corrected hardware/host index fields. A retained WCPU loader
now follows Linux reset, secure IDMEM and header/section progression and waits
for initialized firmware. Internal AX BDRAM preparation now stops and checks
DMA idle, configures exact per-chip partitions, clears/resets hardware indices
and gates CH12 ring-base publication on its retained Ready receipt. Native
preparation now retains DLFW DLE/HFC, exact AX PCIe policy/PHY quirks and the
stopped mode/BDRAM sequence together before CH12 ring configuration. Forty
original Linux C cases cover all four AX profiles, cuts, PHY generations and
inherited fields. The private cold path now composes actual cut/factory reads,
confirmed power-off qualification, complete PCI basic/PHY policy and TX-only
CH12/WCPU startup with RX closed and PCI bus mastering last. Another 40 Linux C
cases cover PCI basic configuration. The RTL8852B continuation now reads actual
physical PHY-cap trims and composes post-WCPU SCC MAC setup with retained
36-bit RXBD/RPQ/C2H ownership. Source C vectors check actual RX envelopes,
release records and index wrap. RF-v1 access, original conditional BB/gain/
RF table execution and actual runtime RF-table H2C uploads share that owner.
Signed measured basic-calibration qualification, firmware-confirmed WLAN-only
coexistence and bounded NCTL/RCK/DACK/RXDCK keep global CMAC TX disabled.
The RTL8852B initial path now continues through actual firmware PHY capability,
static operating setup, channel/BB/RF, IQK/TSSI/DPK and exact source power
configuration under a separate signed measured v2 envelope. The same retained
startup reaches source peer controls and fresh BE/MGMT packet rings, with
joint TXBD/RPQ retirement, host RSNA/CCMP, public Device and kernel DHCP/IP
models. Generic probe uses actual FLR before cold discovery; a separate unsafe
platform entry requires an independently verified temporal reset handoff.
The first profile is awake/polled, fixed1Mbps, channel1/20MHz TX-A/RX-AB and
bounded to512 identities per queue. Terminal closure requires a fresh claim.
Other AX/BE profiles retain diagnostic storage without
activating rings, IRQs or a NIC.
Scoped native PCIe PHY/DBI operations now provide bounded MDIO/RAC access with
retained failure/cancellation exclusion.
EU, CYW/common FullMAC and Intel teardown now repeat carrier closure under
the device state mutex, preventing a waiting old publisher from raising stale
carrier during disconnect. Deterministic interleaving tests check the actual
teardown result before any later maintenance poll repairs state.
USB retains published address/configuration/control/bulk DMA, checks slot
generations and implements explicit Stop/Set-Dequeue fencing for the supported
bulk profile; halt/reset/replug and broader reclamation remain software work.
Broadcom BCM43602 now connects explicit board-selected CR4/msgbuf transport to
the common CYW FullMAC station/security lifecycle, with generation-safe retained
flow-ring reuse after delete acknowledgment. Signed exact-host board selection
and retained asset staging are implemented; actual deployment assets and
physical validation remain. Broader silicon, reset/recovery and PM remain
software follow-ups outside the initial profile.

The shared A2 conversation kit now supplies a reactive legacy Open/WPA2 AP
and a transaction-bound DHCP peer. MT76 uses the shared management/EAPOL peer;
ath11k's native TCL/REO-ring model and CYW's SDPCM/BDC FullMAC model reuse its
DHCP server. All three compose association to a lease and exact bidirectional
Ethernet data. CYW's WPA2 proof is firmware-offloaded key completion; it does
not simulate firmware-internal crypto. The fixtures also cover controlled-port
closure, real carrier metadata and interface-local IPv4 binding retirement.
This work publishes missing MT76/CYW carrier changes and prevents removed
interfaces from leaving their IPv4 address/gateway/DNS behind for name reuse.
It does not close the remaining driver stages or establish physical acceptance.

Phase A3 adds parser goldens from 36 SHA256-pinned vendor originals, retaining
only 60,371 bytes of structural metadata and independently decoded facts.
Sixteen new kernel smokes cover Intel, MediaTek, Qualcomm, Broadcom and Realtek
layouts plus bounded replay construction; no synthetic replay enters a registry
or device loader. RTL8188EE now requests `rtl8188efw.bin`, and MT7920 selects its
distinct `WIFI_RAM_CODE_MT7961_1a.bin` RAM image. The firmware importer preserves
board NVRAM text, maps flat Intel names into canonical registry keys, bounds raw
and zstd input, and resolves duplicate aliases deterministically. The new
`cargo xtask wifi-firmware` audit covers 44 payload profiles across all eleven
families. This host has 60 assets present and 15 required assets missing
(twelve Intel firmware combinations and the three CYW43439 assets); signed
board calibration, policy and exact board/PNVM matching remain separate gates.
See [the firmware evidence and provisioning guide](verification/data/wifi-firmware/README.md).

The preceding station checkpoint added 21 software smokes. The shared legacy join
plan now intersects successful response rates with the offered set, preserves
beacon-mandatory rates and rejects unsupported response requirements before
committing AID/rates. MT76 reads that negotiated state for its native peer/RA
records and chooses the actual lowest basic bit rate, including mixed CCK/OFDM
sets. Independent Linux C layout/trace checks cover the Intel peer, ath10k
teardown and RTW89 BDRAM prerequisites described above. Full station, IRQ,
reset/rejoin and physical acceptance still require the remaining family work.

The native-station checkpoint adds 20 software smokes. New conversations cover
Intel Sc c103 after firmware INIT, RTL8188EU's channel1/20-MHz/basic1Mbps USB
profile and BCM43602's shared5/6 zero-prefix msgbuf profile. Each composes its native
transport, production station owner and kernel DHCP client through exact
bidirectional IP, plus withheld completions, controlled-port closure and
retained ownership on cancellation/disconnect failure. Intel and RTL8188EU
now publish actual carrier metadata, which their previous administrative
link updates did not supply. Intel accepts EAPOL outer protocol versions 1–3
while preserving exact WPA2 descriptor, MIC, replay and no-reinstall checks.
The shared AP's basic1Mbps option keeps RTL8188EU within its admitted rate
profile. Synthetic board/calibration and firmware inputs remain test-only.

A shared regulatory bootstrap now loads `wireless-regulatory.bin` through
current firmware capability invocation, requires a verified signer even in
unsigned development builds, and publishes only a complete decoded policy.
Intel, MT76, ath10k and both FullMAC transports can obtain that policy without
another Wi-Fi driver having probed first. Missing or invalid assets grant no
new transmit permission; an existing caller-installed domain keeps the
documented cached-domain contract. Isolated real-registry tests cover signed
loading, revocation, failure, cache reuse and concurrent caller policy.

The latest software checkpoint passes the filtered Wi-Fi, SDIO, USB, shared
wireless, network, crypto, RNG, firmware and shared-fixture QEMU gates:
x86_64 reports 2962 pass / 0 fail / 22 skip; aarch64 reports
2258 pass / 0 fail / 16 skip. The latest continuation adds62 smokes covering
RTL8852B temporal reset/probe ownership, actual firmware PHY capability, static
operating and full radio/current-power qualification, source peer controls,
native packet/Device DHCP/IP, exact M4 and whole-rekey/disconnect ownership;
all pass on both architectures alongside the prior coverage.
Passive-only wiphys now advertise `NL80211_ATTR_MAX_NUM_SCAN_SSIDS = 0`, reject
active SSID lists at `TRIGGER_SCAN` and use passive discovery on `CONNECT` cache
misses, while Intel (20) and ath11k/FullMAC (16) advertise their active probe
limits. Common FullMAC (`cyw43439`/`brcmfmac`) association now fences host port
publication on an actual zero-consumption FIFO/completion-ring poll so backlog
beyond a single RX budget is drained and late peer loss or cancellation is
observed before opening carrier. `ath10k` and `rtl8xxxu` now wait at their pure
firmware, board/extended-board, per-MAC calibration and regulatory checkpoints
without repeating completed ROM/PLL/OTP or USB table/IQK initialization, and
`ath11k` waits for its complete AMSS/M3/signed-board bundle before MHI power-up.
`wireless::register_initcalls()` now installs the bootstrap `trusted_net_authority` into `narf_net`
at boot before `Stage::Device` probes any driver. MT76 / MT7921 now drives background preflight retry
via `retry_preflight_until` across 120 attempts with 500 ms intervals when firmware or net authority
arrives late, falling back to verified reset recovery. `iwlwifi`, `cyw43439`, `brcmfmac`, `ath9k`,
`rtlwifi` (RTL8188EE), and `rtw88` (RTL8822CE) now drive background provisioning retries via
`drive_scheduled` across 120 attempts with 500 ms intervals while in their pure pre-attempt parked
checkpoints, verifying network registration authority and resuming from completed radio/PHY preparation
checkpoints when policy or calibration arrives late.
Both include a clean production boot and btrfs interoperability postflight.
Host tests, release/debug builds, targeted Clippy across the kernel feature
contexts, workspace formatting, and MT76 module build/Clippy pass.
These are software/model checks. Expected skips include missing physical
devices and unsigned-development firmware fixtures in the signed configuration;
physical acceptance and the documented wider-profile follow-ups remain open.

## Loadable e1000 datapath

The copy-mode module ABI now has an exclusive live-wire proof. `cargo xtask
e1000-module-net-smoke --arch=x86_64` builds and ABI-stamps `e1000.ko`, stages
it in the initramfs, loads it into the operator-selected `driver2` frame before
PCI probing, and suppresses the built-in e1000 registration for that fixture.
The module-owned QEMU 82540EM passes host-to-guest TCP and UDP echoes plus a
guest-originated DNS query through SLIRP. The ordinary kernel-test module suite
continues to cover load/unload, capability gates, domain placement, DMA handle
lifetime, and deterministic descriptor injection.

## i40e recovery, RSS and offloads

The i40e runtime negotiates up to eight queue pairs with separate completion
workers/MSI-X routes, firmware VSI queue mapping and IPv4/IPv6 TCP/UDP RSS.
Checksum/TSO metadata remains supported. Automatic recovery keeps the interface
and IPC rings registered while draining users, resetting the PF and rebuilding
AQ/HMC, queues, filters, RSS and interrupts. Failed reset retains DMA; failed
rebuild retries with capped backoff. See `drivers/net/` §3.1 for resource limits,
recovery status and the aarch64 ITS steering constraint.

Memory-backed firmware, descriptor and IRQ tests cover rebuild failure/retry
and DMA ownership without resetting a host device. Physical X710 validation
remains pending; the development host is a live router.

## Phoenix native audio

Native HDA analog playback/capture and ACP 6.3 PDM microphone capture are
implemented against `/usr/src/linux`. The sound-card/PCM/mixer file surfaces
now delegate to owned hardware DMA. ACP probe requires revision 0x63, a PDM
pin configuration and ACPI microphone properties; enumeration does not start
recording. HDA routes BIOS-described analog paths and handles headphone
speaker automute. Timeout paths retain DMA until the hardware is quiescent.

Fake-device tests cover command transport, DMA accounting, capture overrun
and failed-stop retention. QEMU HDA exercises playback across buffer wrap,
capture and capability revocation. Physical Lenovo 50ee validation is pending.
The shared sound bridge implements Linux ALSA PCM/control ioctls, mmap data
and pointer synchronization, poll readiness and Linux errno translation.
An unmodified alsa-lib probe exercises HDA/VirtIO playback and HDA capture
through those syscalls, including linked pause, boundary-mode playback and
user controls with TLV/events. The implemented ALSA contract is listed in
[sound §3.1](drivers/sound/specification/spec.md#31-linux-alsa-pcm-and-control-abi).
SoundWire, vendor smart-amplifier quirks and system power-transition
reinitialization remain open. See
[audio's implemented contract](audio/specification/spec.md).

## Desktop audio: stock PipeWire and WirePlumber

Unmodified Fedora 43 PipeWire 1.4 and WirePlumber 0.5 run on the Fedora KDE
image and get as far as a complete audio graph. The gate that drives them,
what each of its stages establishes, and how to run it are in
[verification/data/pipewire-compat](verification/data/pipewire-compat/README.md).

Working and asserted end to end: both QEMU cards reach systemd-udevd's
database with the properties `spa_alsa_udev` requires (`SOUND_INITIALIZED`,
`ID_PATH`, PCI identity from hwdb); the desktop user opens the nodes;
WirePlumber attaches as a second process over the PipeWire protocol and builds
ACP card profiles (five on HDA, three on VirtIO), selects a best profile,
finds HDA's hardware volume control, activates analog input and output routes,
exports a sink per card plus a source, and sets the default sink and source.
`wpctl status` lists them as a desktop would see them.

Five Linux-ABI defects found by that path are fixed:

- `/dev/snd/*` owner, mode and ACL now live on the devtmpfs NODE rather than
  the per-lookup `FileOps`, and the nodes are published root-owned at 0600 as
  `sound/sound_core.c` plus `drivers/base/devtmpfs.c` do. udev's `GROUP="audio"`
  chown was previously discarded, so every non-root ALSA client reported "no
  soundcards found" and no desktop session could play a sound.
- `/proc/<pid>/root` is rendered in the READER's root frame, as Linux
  `d_path()` does. The stored prefix is host-view, so a chrooted reader —
  which is every process in this image — was handed a name that resolved to
  nothing.
- `/proc/{self,<pid>}/{root,cwd,exe}` are FOLLOWABLE at `open` and at a path
  `stat`, trailing slash included, and a `stat` whose symlink target leaves
  its own filesystem now crosses the mount the way `open` already did. An
  absolute magic-link target restarts at the owning filesystem's mount root,
  so the walk never left procfs. PipeWire's access module opens
  `/proc/<peer-pid>/root` to look for `.flatpak-info` and reads a failed open
  as "this client is sandboxed", so every client hung at connect. The same
  shape through devtmpfs also made `/dev/fd/<n>` unresolvable, which is how
  bash implements process substitution (`cmd < <(other)`); the VFS expansion
  now stops at a proc-fd magic link instead of expanding its readlink TEXT,
  which for an anonymous descriptor is `pipe:[12345]` and names nothing.
- `/proc/<pid>/task/` is named by thread id instead of repeating the group's
  pid once per thread, and each thread directory now carries a per-thread
  `stat` and a per-thread, writable `comm` (0644, as `tid_base_stuff` has it).
  Together that is what `ps -L` and `top -H` read, and what glibc's
  `pthread_setname_np` writes: the gate sees seven distinctly named
  WirePlumber threads where before procps aborted with "fatal library error,
  reap".
- HDA advertises only the formats its codec reports. `capabilities()` returned
  a fixed `S16_LE | S32_LE` while `configure_paths` enforced the converter's
  `AC_PAR_PCM` word, so on a 16-bit-only codec — QEMU's hda-duplex among them
  — `HW_REFINE` offered S32_LE and `HW_PARAMS` then rejected it. alsa-lib
  cannot recover from that: PipeWire negotiates the widest format on offer and
  its ALSA node dies with `set_hw_params: Invalid argument`, leaving a sink
  that never takes a quantum. The format set is now queried once at probe,
  from the same word the enforcement reads.

One defect remains open, and the gate reports it on every run rather than
failing on it: **WirePlumber's main thread burns ~100% of one CPU once the
graph is built**, while the PipeWire daemon stays at 0% and every functional
stage passes. The vDSO monotonic clock, `poll`/`epoll` blocking semantics,
`POLLERR`/`POLLHUP` handling, poll-over-epoll with GLib's exact mask,
level-not-cleared-on-consume for eventfd/socketpair/timerfd, ALSA control-fd
readiness, and GLib itself (a bare `gdbus monitor` idles at 0%) have all been
measured in-guest and ruled out; it produces no log output at trace level, so
it is a silent dispatch loop. Narrowing it further wants a tracer. A tracer is
now eligible to wait for a tracee it did not fork, but the tracee's attach-stop
is never reported to it, so `strace -p` blocks in `wait4` instead of answering
`No child processes` — reporting that stop is the next step. Details and the
full elimination list are in
[verification/data/pipewire-compat](verification/data/pipewire-compat/README.md).

## USB-C and Phoenix USB4

UCSI ACPI connector discovery, firmware state notifications, per-NHI native
USB4 config rings/topology and USB3/DP tunnel programming are implemented
against `/usr/src/linux`. Native ownership requires ACPI `_OSC`; PCIe and
XDomain control are not requested. DP tunneling currently supports one RBR
path per domain, and native USB4 system suspend/replay remains unsupported.
Memory-backed tests exercise DMA ownership, acknowledgements, path drainage
and rollback without touching host devices.

The AMD DCN 3.1.4 DMUB transport can attach to running DAL firmware for HPD,
AUX and EDID discovery. Firmware preparation now selects the DCN314 blob
from IP discovery, validates DMCUB containers and metadata, separates PSP
packaging, and stages a bounded seven-window image in RAM. An explicit
direct-load lifecycle now reserves from caller-owned VRAM, stops DMCUB,
uploads/flushes the image, programs cache windows and validates boot readiness.
Failed stop/cancellation retains memory until shutdown is verified. Loader
ownership excludes the attach worker, firmware replacement and suspend.
GPU probe now retains a bounded, device-matched VBIOS snapshot from ACPI VFCT
or the APU VRAM shadow, using corrected PCI/ATOM header and directory parsing.
DMUB preparation can consume that snapshot. An explicit boot-memory path now
builds a pool with permanent exclusions from VBIOS reservations, current DMUB
windows and caller-supplied boot/client ranges; it never infers ownership
from BAR capacity.
A Phoenix PSP 13.0.4 GPCOM ring now installs the TMR and loads DMCUB through
the PSP, leaving the secure instruction and stack windows under PSP ownership;
Phoenix rejects the legacy firmware-load helpers so nothing races that ring.
The boot handoff assembles the owner: it records the boot framebuffer geometry,
refuses a GPU with live firmware, a live mode or any VM context, inventories
every enabled linear-RGB surface and cursor including latched and draining
addresses, and rejects DCC/YUV/stereo layouts rather than overlooking metadata.
The Late worker takes this owned path when it succeeds and otherwise falls back
to attaching to running firmware.
DisplayPort link training and the DIO link encoder are implemented: async
8b/10b clock recovery and equalization program source and sink as one
transaction, fall back only on recovery/equalization failure, clamp lanes to
the reported Type-C pin assignment, and leave a transparent USB4 DPIA to train
its own remote PHY.
The DCN314 stream pipeline is now implemented end to end. A fixed-point port
of DML derives the detile geometry, the required clocks, the urgent, p-state and
stutter watermarks and the prefetch schedule, and encodes them into the HUBP
request, latency and throttle registers, refusing any value a field cannot hold.
The display clock manager latches the firmware's own DPM table and applies
clocks in Linux's order; the clock generator divides them per pipe and routes a
tunnelled stream's clock. The timing generator, hub pixel pipe, DPP, combiner,
output formatter and DisplayPort stream encoder are all programmed, and a
bring-up sequence drives them in the enable-stream order, trains the link, and
unblanks the pipe, encoder and formatter last. A completed stream publishes its
scanout for the framebuffer layer to adopt.
The platform inventory the sequence needs is now read from the platform's own
tables: the display topology and each connector's transmitter and hot-plug line,
the memory type, channel count and data rate, the DCHUB reference clock and the
DENTIST VCO. None of it is defaulted — the memory configuration multiplies into
every watermark and the reference clock scales every latency register — and a
table that is missing, the wrong revision or self-inconsistent fails closed. A
native DisplayPort route is derived and validated against the board rather than
trusted from the sink's index.
The Late worker now arms the bring-up once per boot for the first native
DisplayPort sink the board can answer for, claiming only a pipe that is blanked
with its timing generator stopped and zeroing the surface before any pixel is
sent. A failure leaves the display alone and falls back to the previous
attach-only behaviour; suspend stops the stream before the firmware.
Tunnelled USB4 sinks are driven too. A tunnelled link has no board-wired
transmitter, so one is borrowed from the five DIGs, preferring those the board
wired to no connector; a wired transmitter is still usable while its own
connector is idle, which the backend enable bit decides rather than a guess.
A tunnelled stream negotiates its host router's bandwidth before the link comes
up, rounding a request up to a whole allocation step and refusing a mode the
tunnel cannot carry rather than clamping it down to a starved allocation; the
bandwidth is handed back when the stream stops. The console follows a lit external
display through an observer the framebuffer layer installs, and returns to the
boot framebuffer when the stream goes away. A stream survives suspend: the mode it
was validated for is retained and replayed on resume, with the clock levels
re-latched and the surface re-cleared.
**The one remaining gap is silicon.** Physical Lenovo 50ee USB-C/USB4 validation
is pending; nothing in this path has run on real hardware, so the watermarks,
deadlines and link training are unconfirmed.
See the USBPD, Thunderbolt and GPU subsystem specifications for the supported
interfaces and limits.

## Exercised paths

- **Kernel on QEMU:** `cargo xtask run` and `cargo xtask test` support x86_64
  and aarch64. The suite reports pass, fail, and skip totals at exit.
- **Interactive userspace on x86_64 QEMU:** `cargo xtask run-interactive`
  exercises the in-tree shell and coreutils. The musl demo harness covers
  Linux syscall and device ABI cases; `oci_smoke` exercises the container
  path. A dynamically linked Alpine BusyBox has also run from an ext2 rootfs
  under `chroot`; that rootfs is generated locally and is not an automatic CI
  case. See [docs/PERSONAS.md](docs/PERSONAS.md) and
  [docs/DESKTOP_LINUX_PLAN.md](docs/DESKTOP_LINUX_PLAN.md).
- **Storage and network on QEMU:** NVMe, virtio block and network, and
  several emulated PCI NIC paths are in-tree. The block registry, VFS,
  ext2/Btrfs implementations, TCP/UDP stack, and Linux-facing file and
  socket interfaces are implemented. Individual device and filesystem
  coverage depends on the attached QEMU profile and test case.
- **Graphics on x86_64 QEMU:** `/dev/fb0`, evdev, DRM/KMS modesetting,
  libdrm, and a multi-client Wayland path have runnable demonstrations.
  VirtGPU VirGL ioctls and presentation paths are implemented in-tree;
  this does not establish native AMDGPU display on a laptop.
- **Runtime modules:** xtask builds and stages a real rustc `.ko`; the kernel
  smoke stamps the live export-table ABI, resolves the compiler's native
  relocation against `narf_printk`, executes init/exit in the declared
  `target_domain`, and unloads it. Production policy verifies a fixed
  Ed25519-over-BLAKE3 trailer against build-time public keys; unsigned modules
  require an explicit developer/CI feature. Versioned LZ4 module envelopes are
  bounded to 32 MiB and authenticated before decompression. The SMP unload
  grace period remains open.
- **Boot media:** `cargo xtask image` builds boot media and `iso-boot`
  checks UEFI boot in QEMU. These are distinct from a successful USB boot
  on the target laptops.
- **Native UEFI installation:** x86_64 and aarch64 native packages install an
  isolated `/EFI/NARF` payload plus a Boot Loader Specification entry. CI boots
  the x86_64 package through OVMF, installed-style GRUB, config-bound Limine,
  and its hash-bound kernel; AAVMF boots the aarch64 package through NARF's
  kernel-bound loader. Secure Boot CI enrolls an ephemeral certificate, boots
  the signed x86_64 chain, and requires a one-byte kernel modification to be
  rejected. GRUB, systemd-boot, rEFInd, CachyOS Limine, distribution signing,
  and persistent local `sbctl` signing are implemented without changing UEFI
  NVRAM or the host's default entry. Production key enrollment, rotation, and
  revocation remain administrator/distribution policy.

## Isolation and hardware limits

- x86_64 selects PKS when available and otherwise has a PCID page-table
  backend. PKS fault tests run under suitable QEMU configurations. PCID's
  confined-slot policy has structural tests, but the PCID enforcement path
  has not run on the available hardware runners. See
  [docs/DOMAIN_BACKENDS.md](docs/DOMAIN_BACKENDS.md).
- aarch64 has MTE paths and tests. Without MTE, its planned page-table
  fallback is not installed, so boot can continue without domain enforcement.
- Domain protection applies to resources correctly mapped or tagged for a
  domain. Untagged or shared ordinary kernel memory is not automatically
  confined. The Stage 3 composition smokes therefore must not be read as an
  end-to-end isolation proof for every device buffer.

## Current work

Intel GPU hangs are now recovered per context. GuC autonomous engine reset is
enabled; a user job that overruns its 5 s deadline (from GuC's enable ACK) is
disabled alone, and GuC preempts it or resets the engine under it
(CONTEXT_RESET_NOTIFICATION). The job retires through the usual
deregistration and final-TLB proof, its fence fails with `JobError::Hang`,
and only its context is banned and counted guilty; other contexts keep
running at the same epoch. Xe EXEC on a banned queue now returns ECANCELED
(was EIO), after the queue lookup as in `xe_exec_ioctl`. Kernel-job hangs, an
unanswered disable and engine-reset failure still reset the GT. The Intel
GuC/user/Xe suites pass on x86_64 (120 + 85) and aarch64 (104).

Intel iGPU write-combining memory is admitted. `narf_memory::pageattr`
retypes driver-owned RAM pages write-combining in every kernel alias (Linux
`set_pages_array_wc`: UC- then WC, huge-leaf split, all-CPU TLB and cache-line
flushes, write-back restore before free; x86_64 only) and a user leaf of a
retyped page takes the recorded type. Native Xe creates iGPU
`CPU_CACHING_WC` objects in those pages with WC mmaps, admits SCANOUT (EINVAL
with WB) and binds MTL's non-coherent PAT1/PAT2 only for WC objects; PAT1 is
now programmed as Linux's WT entry. Earlier on this branch: i915 BLT rings and
context engine maps, Xe MAP_USERPTR over snapshot pins (fork copies pinned
pages for the child), Battlemage visible VRAM, display-less dGPU runtime
autosuspend, GuC SLPC with firmware RC6, and fuse-derived CCS0 scheduling.
The memory pageattr suites pass on x86_64 (460) and aarch64 (361), the Intel
groups pass on x86_64 (148 + 108) and aarch64 (73), and boot-smoke plus both
btrfs postflights pass. Silicon and Mesa acceptance remain.

The Intel GuC path now schedules BCS0, the copy engine that every admitted
MTL/Arrow, DG2 and BMG graphics IP carries unfused (Linux `read_copy_fuses`
applies only to PVC/Xe3+). The scheduler owns per-engine HWS and golden LRCs;
the reload ADS publishes RCS0/BCS0 mapping, enable masks, golden state sizes
and register saves. BCS0 uses the source `gen12_xcs`/`xe2_bcs` LRC layouts, the
simple MI_FLUSH_DW job and breadcrumb, a BLIT_CCTL uncached-MOCS default-state
RMW primed after RCS0, BMG's ENGINE_BASE workarounds and a verified all-NOPID
NONPRIV policy. Native Xe publishes RENDER+COPY engines, admits width-1 COPY
queues with per-engine saved state, samples either engine's RING_TIMESTAMP and
routes BCS0 MI_USER/FLUSH interrupts through the owned MSI path. A native
device model executes copy-queue PPGTT batches and user fences, and checks the
saved LRC and ADS words. The selected Intel GuC/user/Xe tests pass on x86_64
(143) and aarch64 (145), the other Intel groups pass on x86_64 (142 + 70), and
the production boot-smoke and both btrfs postflights pass on x86_64. Clippy
(both feature contexts, both architectures) and formatting pass. BCS8,
CCS/media engines, i915 BLT execbuffer and silicon/Mesa acceptance remain.

The Intel continuation now selects the native Xe ABI on production GuC cards.
Per-open VM and execution-queue namespaces support transactional vector/inline
binds, partial-object mappings, overlap replacement, UNMAP_ALL, sparse NULL
scratch trees and VM-private BOs. Explicit binary/timeline syncs retain payloads
through handle destruction; zero-bind barriers and zero-batch executions are
supported. Executions preserve private PPGTT/context ownership and publish
terminal reservations for every CPU conflict while allowing explicitly ordered
queues to overlap. GPU user fences use an owned PPGTT qword store after cache
flush; CPU bind fences and masked waits use guarded atomic qword access on both
architectures. Discovery reports observed engines, memory, GT/IP/clock facts,
HWCONFIG, topology and the loaded GuC submission-interface version. Correlated
RCS engine-cycle queries use current forcewake and the reset mutex, bounded
rollover-safe MMIO observations, actual 36/64-bit counters and NARF CPU clocks.
They retain inputs across waits and copy only output fields.
Infinite user-fence waits also use the existing interruptible syscall restart
hook, while finite waits retain their original deadlines. Queue
priority/timeslice policies reach the actual GuC KLV request. Native Rust tests
exercise the ioctl-to-hardware ownership path, bind cancellation, handle close,
concurrent queues, user-fence visibility and transactional copyout failures.
This does not establish Mesa or physical Intel acceptance. USERPTR, fault/LR
VMs, iGPU WC/incoherent mappings, other engines, local VRAM, accelerated
presentation and runtime autosuspend remain outstanding.

The physical Intel GT worker now installs owned primary-GuC/RCS0 MSI after
its startup probes, with task-context identity decoding, dispatch epoch waits
and a 10 ms watchdog. Routing refusal/failure keeps the 500 us timer path.
Display/media causes and mask halves are preserved. Reset/S3 tears down the
powered route before GT stop; uncertain shutdown quarantines its vector and
cookie. Native register/dispatch tests cover delayed identities, waiter races,
route rollback and teardown; physical MSI acceptance remains unverified.
This continuation passes 62 selected Intel tests on each architecture,
including all five new IRQ regressions, with zero failures/skips. Source and
master readback rejection, lost MSI recovery, shared media enable preservation,
device-loss quarantine and real GuC retirement run in native Rust models.
GPU CI Clippy passes all three feature contexts on both architectures;
host default/Intel-only/AMD-only/no-vendor checks, Intel-only debug builds and
formatting pass. Both production boots and both btrfs postflights per
architecture pass.

Before the MSI continuation, native Xe regression runs passed 136 distinct
Intel/DRM tests on x86_64 and 124 on aarch64, including all 15 then-new tests,
with zero failures/skips.
Deadline tests use a controlled clock and fixture
progress uses bounded polling, avoiding short host-dependent timing guards.
GPU, arch, filesystem and userspace CI Clippy pass all three feature contexts
on both targets; host default, Intel-only, AMD-only and no-vendor all-target
checks pass. Intel-only debug and release builds, formatting, both production
boots and both btrfs postflights per architecture pass. These are native Rust
models and QEMU checks; physical Intel and Mesa acceptance remain unverified.

The existing compatibility profile implements userspace RCS0 submission on
MTL/Arrow Xe-LPG, Alchemist and Battlemage. Async i915 EXECBUFFER2/WR uses copied softpin
residency, per-open ordered contexts, implicit GEM/PRIME reservations and the
live GT owner. Private context images preserve saved state between retired
jobs; kernel rings/images/tables remain outside user mappings. Hardware
nonsecure PPGTT command checking and the verified RCS register policy constrain
untrusted batches. Live engine/capability/version queries and the i915 loader
identity publish only after startup probes pass. Loss/suspend closes admission;
verified full stop allows rebuild with a fresh epoch, refusing old contexts
without replaying their batches. Failed cleanup remains closed.
Native Rust models exercise the actual ioctl -> GT -> CT -> PPGTT execution
and retirement chain, context save/restore/isolation across six IP variants,
cache failure rollback, cancellation, handle/fd close and reset/epoch ownership.
The branch also implements explicit sync_file IN/OUT fences, per-open binary
and timeline syncobj submission, transactional output-fd publication and
retained dependency snapshots. Native tests cover fd/handle close, cancellation,
timeline order and publication failures. A round-robin GuC ID pool now reuses
identities only after verified retirement, with independent request stamps and
TLB cookies, removing the 65534-request limit. Priming holds the seed ID until
the distinct switch/capture completes. Native conversations exercise more than
65534 requests, stale evidence after reuse, pool exhaustion and stamp wrap.
FENCE_SUBMIT now waits for native Intel scheduling-enable ACKs while foreign
leaves retain terminal waits. Syncobj round trips preserve native milestones;
GEM reservations, context order, syncobj WAIT and output fences still require
terminal completion. Loss before ACK retains ownership and blocks submit
dependencies until proven reset. Invalid input-flag combinations and bad fds
fail before publication; HAS_EXEC_SUBMIT_FENCE follows live readiness.
Intel silicon and Mesa OpenGL/Vulkan acceptance, other engines,
local VRAM and accelerated presentation remain outstanding.
The preceding FENCE_SUBMIT checkpoint passed 112 selected Intel/DRM tests on
x86_64 and 100 on aarch64,
including five FENCE_SUBMIT smokes, seven explicit-fence/ID-recycling smokes
and twelve existing DRM synchronization tests on x86_64, with zero
failures/skips. GPU and filesystem CI Clippy pass all three feature contexts
on x86_64 and aarch64; host default, Intel-only, AMD-only
and no-vendor all-target checks pass. Intel-only debug builds, formatting,
both production boots and both btrfs postflights per architecture pass.
The following paragraphs record earlier implementation checkpoints.

Intel render work merged through #1175 includes per-open i915-wire
GEM storage, CPU copies/WB mmap, same-card PRIME sharing, context and VM
namespaces, two-pass memory and
engine queries, and bounded softpin execbuffer admission. Immutable Gen12 and
Xe-LPG PPGTT residency retains referenced buffers after handle/fd close. The
memory audit corrected GPU PAT fields, intermediate permissions and the raw
PML4 root's PDP0 placement; the Gen12 engine audit corrected ring-size encoding,
12-entry CSB depth and the extended engine-relative context restore groups.
Follow-up work on `codex/intel-gpu-render-backend` adds owned arbitrary-VA
Gen12 submission, render-cache-flushed post-sync breadcrumbs, cancellable
fence waiters, stale-CSB identity protection and loss/reset residency retention.
Xe-LPG now has capability-invoked GuC-70 firmware acquisition and a coherent
GGTT CT owner with MMIO registration/enable/disable, bounded retry/timeout and
quarantined allocation lifetime. These are native model/ownership paths, not
working Mesa acceleration or a firmware boot claim.
EXECBUFFER2 still refuses submission and queries expose no userspace engines.
Complete engine/media/cache inventory, userspace context setup, accelerated PRIME/KMS and Mesa
OpenGL/Vulkan acceptance remain open. The physical GuC kernel path below now
owns GT reset and context scheduling.
Existing Gen12 RCS/media helpers refuse Xe-LPG before MMIO.

The `codex/intel-gt-bringup` follow-up adds exact Arc Alchemist/Battlemage PCI
and firmware profiles alongside Xe-LPG. GuC bootstrap now owns reset, WOPCM,
minimal ADS/logs, cache-cleaned firmware DMA, authentication and bounded waits.
Uncertain DMA lifetime retains allocations until verified stop. Discrete CT
requires explicitly coherent memory; legacy WB backing makes no such claim.
The hardware protocol follows the local Linux source at
`b90c984d615e8ce2af96f5b1411a962d83fed2ad`. The physical service below adds
per-card forcewake/PM/cache integration and kernel contexts. Local VRAM,
userspace scheduling and silicon acceptance remain open; EXECBUFFER2 and Arc
display binding remain unavailable.

The same branch now joins bootstrap, CT and the kernel GT forcewake request
in `GuCGt`. A Linux-source cross-check corrected the bootstrap ACK address:
MTL/Arrow and BMG use 0xdfc, while DG2 uses 0x130044. The owner preserves other
requestors, bounds wake waits, blocks admission after wake/CT loss, and
retires CT only after GuC reset plus firmware DMA idle before releasing wake.
Cancelled waiters and uncertain drops retain the owned resources. The physical
path additionally owns render-well wake and full-engine reset for kernel jobs.
Runtime autosuspend and userspace submission remain disabled.

HWCONFIG discovery now uses the source-defined zero-address size query and
GGTT copy through the GT owner's bounded MMIO mailbox before CT enablement.
The destination is cache-cleaned before DMA and synchronized before CPU
reads. Its exact KLV bytes are validated into an immutable snapshot while
the DMA backing stays owned through verified stop. Malformed lengths,
duplicate keys, cache failures, wake loss, timeouts and all-ones register
reads fail acquisition without releasing uncertain DMA resources. Unknown
keys and vectors are retained; capability maxima are not active topology.
Per-card DRM query publication now retains that immutable snapshot separately
from GT DMA lifetime. The DRM registry recognizes `intel-gpu`, fixing private
ioctl and GEM mmap routing on both primary and render nodes. Each Intel card
has an independent, single-publication slot, including cards with identical
PCI IDs. Publication requires an awake Ready/CtReady GT and matching device
ID; SchedulingReady also admits publication. The PCI owner must pair the correct
physical function. Exact HWCONFIG
bytes remain queryable after verified GT stop and backing reclamation.
Unavailable tables return per-item -ENODEV. GuC submission-version remains
unavailable until userspace scheduling is admitted; its version is distinct
from the loaded firmware release. Automatic startup publishes HWCONFIG on
eligible functions. Arc display and userspace submission gates remain closed.

The physical GT service now retains each registered card, PCI authority,
runtime-PM hold, firmware asset and dedicated GGTT arena. GT register accesses
invoke current capability validity. Startup validates live PCI identity, D0,
PF registers and a bounded extended-capability chain with SR-IOV VFs disabled.
Initial GuC and full-engine resets precede PAT/MOCS programming and new PTE
publication. MTL PAT3, DG2 PAT0 and BMG PAT2 establish coherent x86_64
system-memory backing; ARM PCI coherence remains unproven and refuses physical
scheduling. MTL/Arrow starts after owned scanout takeover; Arc has GT-only
binding and refuses enabled inherited display planes. No local VRAM or Arc
display support is implied.

After HWCONFIG, submission-interface major 1 gates an RCS0 ADS reload while
GuC is stopped. Authenticated reload enables LiteRestore, then CT owns context
registration, policy, enable/disable and deregistration. Each of at most 64
independent kernel probe contexts owns its platform LRC and 8-KiB ring; IDs
are never reused within the GT lifetime. Heavy GuC GGTT TLB invalidations
bracket each context's registration/retirement. Fences require the GPU-written
breadcrumb, saved ring head, deregistration ACK and final correlated TLB ACK.
CT pressure retries without advancing phase. Cancellation, malformed/stale
events, wake loss and timeout retain uncertain resources; GuC reset/DMA idle
plus completed GRDOM_FULL is required before reset fences or reclamation.

Stage::Late starts the per-card worker and queues a fixed kernel execution
probe; `kernel_probe(card)` can queue another. No user instructions/PPGTT enter
this interface. The polling service masks GuC/RCS interrupts and holds D0;
async system-PM preparation proves stop, and paired resume restores
configuration/display before rebuilding with cached firmware and a fresh
arena/cache-policy proof. A failed
cleanup retains the owner without endlessly retrying resets. Physical Intel
boot/execution has not been tested.

The GuC bootstrap/GT/HWCONFIG/hardware-scheduling follow-up passes 290 selected
native GPU/DRM tests on x86_64 (including 44 DRM integration tests) and 129 on
aarch64, with zero failures/skips, including five bootstrap, eleven GT-owner
and seven HWCONFIG smokes covering platform ACKs,
wake ownership, DMA stop, CT faults, KLV bounds, cache synchronization,
allocation rollback, wait cancellation, last-owner quarantine and independent
card publication/query lifetime after all GT DMA is freed. New render smokes
exercise real primary/render-node routing, per-open GEM/mmap ownership and
HWCONFIG wire failures. New hardware models additionally cover initial
quiescence, actual production arena policy/capability access, two-context
execution, 64-context pressure, CT backpressure, stale identities, reload
cancellation and GuC-only versus full-engine reset reclamation.
Supplementary GT/Intel PM, runtime-PM and device-PM checks pass 32 smokes per
architecture, with one expected skip because xHCI is not probed in this QEMU
configuration.
GT/firmware-profile identity coverage, the existing 25 RCS and six CT-owner
smokes also pass.
GPU CI Clippy passes all three
resolved feature contexts on both targets; host all-target Clippy passes
default, Intel-only, AMD-only and no-vendor configurations. Intel-only debug
builds pass on both architectures, and workspace formatting is clean. A
vendor-only MST helper is now gated when both vendors and kernel tests are
disabled. Production boot and both btrfs interoperability checks pass on both
architectures. These results do not validate Intel silicon, firmware boot on
hardware or Mesa rendering.

The `codex/intel-gt-topology` follow-up reads stable main-GT geometry/compute
DSS and EU fuses under the owned wake/reset protocol before firmware DMA.
MTL/Arrow and DG2 expand paired SIMD8 EUs; BMG retains individual SIMD16 EUs.
Full 32-DSS masks are valid; unstable/empty/unavailable fuse reads close startup.
Compute-only GTs cannot authorize RCS0 programming. Per-card immutable snapshots
are independent of HWCONFIG maxima and survive verified stop/reclamation.
Identical resume observations are accepted; changed fuses refuse restart.
Primary and render nodes expose i915 topology and geometry-DSS queries with
sparse masks, exact little-endian layouts, two-pass sizes and per-item copy
errors. These queries add no userspace engine or EXECBUFFER2 admission.
Media/cache inventory, userspace isolation/state and silicon/Mesa acceptance
remain open.
Six new native smokes cover fuse decoding/stability, literal topology layouts,
pre-DMA and compute-only admission, equal-ID card isolation, immutable snapshots
after reclamation and per-item user-copy failures. Selected GPU/DRM coverage
passes 296 tests on x86_64 and 135 on aarch64, with zero failures/skips. GPU CI
Clippy passes all three contexts on both targets; host default, Intel-only,
AMD-only and no-vendor all-target checks, Intel-only debug builds and formatting
pass. Both architectures pass production boot and btrfs interoperability.

The same Intel branch now adds owned GuC PPGTT kernel submission on MTL/Arrow,
DG2 and BMG. Independently selected non-leaf PAT bits reach every table level
and PDP0/PTBP; MTL installs UC PAT2 for table reads while data uses coherent
WB PAT3. Immutable tables and BOs are explicitly cache-cleaned before GPU
publication. Rings include source-defined PPGTT start, invalidation and render
cache drain, with MTL AuxCCS and DG2 depth-flush differences. Residency survives
wait cancellation, timeout and missing retirement evidence until proven full
reset; terminal fences publish only after release. Startup now also requires
a private high-address PPGTT store probe and checks its entire result and code
pages. This is trusted kernel execution, with an unsafe contract for arbitrary
kernel batches. Default 3D LRC state/workarounds, isolated userspace scheduling,
full engine inventory, Arc VRAM/display and silicon/Mesa acceptance remain open.
Four new native smokes cover independent table/root PAT vectors, real-page
PPGTT stores on all three profiles, cancellation/reset ownership, profile
rejection and lost retirement proof. The final x86_64 full GPU selection passes
2698 GPU tests plus 13 CDC-ECM tests, with zero failures and five existing AMD
skips (unprobed hardware or masked interrupts). Three final aarch64 groups
pass 343 Intel/DRM tests without failures/skips; all 13 CDC-ECM tests also pass.
GPU CI Clippy passes three resolved feature contexts on each architecture;
host default/Intel-only/AMD-only/no-vendor all-target Clippy, Intel-only debug
builds, formatting, both production boots and both btrfs checks per architecture
pass. The upstream USB Result fix is retained; its routing smoke now checks
detach success instead of ignoring the returned Result.

The same Intel branch now primes and captures default RCS state before the
physical service's PPGTT probe. The context workaround/tuning stream covers
DG2, Xe-LPG 12.70/12.71/12.74 and separate Battlemage 20.01/20.02 selections.
Stable GMD/fuse observations and observed DSS/HWCONFIG layout select live MCR
targets; GPU read/modify/write preserves non-masked fields, and scratch state
is cleared. DG2 explicitly seeds all fifty SVG headers to avoid inherited
state through missing restore instructions. An exclusive two-context sequence
fully retires the seed, retains its image through a forced switch, then
synchronizes and copies the saved body into the golden template. New contexts
restore it with fresh status, ring and root identity. Cancellation, bad save
evidence and failed synchronization retain uncertain backing until full reset.
Priming refuses prior resident kernel work; only the fixed GGTT diagnostic may
precede it, preventing a previous batch from contaminating the saved template.
Global GT/engine workarounds, user isolation/synchronization and physical
acceptance remain open; acceleration and autonomous engine reset stay gated.

The follow-up now applies Linux-derived graphics-GT and RCS0 MMIO workarounds
and tunings before publishing the ring and reloading scheduling firmware.
Selection distinguishes DG2 dies, Xe-LPG IP/stepping and Battlemage 20.01/20.02,
including flat-CCS enable and sparse DSS groups. Reads use live steering
targets and writes preserve unrelated bits. A firmware-owned steering
semaphore yields until its deadline, and failure retains the owned graph
through full reset. Native register vectors and hardware conversations cover
selection, steering, contention, failed reads/readback and cancellation.
Media/additional engines, out-of-band workarounds, nonprivileged register
policy, isolated user execution and hardware/Mesa acceptance remain open.
The ten new native smokes across context priming and register initialization
pass in the final Intel/DRM selections: 526 tests on x86_64 and 353 on aarch64,
with zero failures/skips. GPU CI Clippy passes all three resolved contexts on
both architectures; host default/Intel-only/AMD-only/no-vendor all-target
Clippy, Intel-only debug builds and formatting pass. Both architectures also
pass production boot and both btrfs interoperability postflights. These are
register/DMA models and QEMU checks, not physical Intel or Mesa acceptance.

The next Linux-source audit corrects Wa_14019789679 coverage: all admitted
Xe-LPG and Battlemage profiles now seed the same fifty SVG headers as DG2,
with Xe2's DRAWING_RECTANGLE_FAST substitution. Captured opaque model state
reaches both the golden template and new PPGTT contexts. Xe-LPG also receives
the source-required extra depth-cache flush before completion. Firmware boot
now binds stable live IP/stepping and supplies platform/die GuC WA flags plus
ADS KLV records before DMA/cache publication, preserving the same records on
scheduling reload and rejecting changed identity. Media/additional engines,
remaining out-of-band/reset handling, isolated userspace 3D and physical
acceptance remain open.
Three new native smokes cover firmware wire profiles, refused live IP and
identity changes during reload; extended state/PPGTT fixtures cover all six
admitted IP variants. All 101 targeted smokes pass on each architecture,
without failures/skips. GPU CI Clippy passes three contexts per architecture;
host default/Intel-only/AMD-only/no-vendor all-target checks, Intel-only debug
builds and formatting pass. Both production boots and both btrfs postflights
per architecture pass. Physical Intel/Mesa acceptance remains untested.

The same Intel branch now connects native terminal fences to each GEM object's
shared PRIME reservation. GuC and legacy Gen12 resident paths admit overlapping
readers and reject conflicting writers transactionally before cache publication.
Kernel CPU copies respect those reservations; GEM_BUSY reports actual render
reader/writer bits, and async GEM_WAIT retains its relative timeout deadline
while parked. PREAD/PWRITE retry waiting chunks without replaying a prefix.
PRIME CPU-access synchronization, shared names and sync-file export observe the
same terminal fences across aliases. Cancellation/timeouts retain reservations
until verified completion or reset; failed copies publish no sync-file fd.
External fence import, raw-mapping exclusion, isolated user submission and
physical Intel/Mesa acceptance remain open.
Four new native smokes cover reservation conflicts/rollback and aliases,
relative wait deadlines/cancellation and retained CPU-domain requests,
PRIME synchronization/export copy faults, and pre-publication cache failure.
Extended GuC conversations check real terminal/reset reservation boundaries.
The final focused x86_64 selection passes 83 tests. The aarch64 Intel/DRM
selection passes 360 tests, with all 15 render tests rerun after the final
CPU-domain lifetime correction; all runs have zero failures/skips. GPU CI
Clippy passes three contexts on each architecture; host default, Intel-only,
AMD-only and no-vendor all-target checks, Intel debug builds and formatting pass.
Both architectures pass production boot and both btrfs interoperability
postflights. The refreshed standalone x86_64 boot uses the dedicated test
virtio-blk image through NARF_VBLK_IMG; the default Alpine image is not writable
by the current user.

The Intel continuation now installs and verifies the RCS0 nonprivileged
register policy before ring publication. All twelve inherited slots are
cleared before the three Linux Xe OA access entries are granted; unused slots
remain at RING_NOPID. Reload, CT enablement and kernel submission/default
priming check the exact policy. Failure enters Lost without repairing live
registers or releasing existing jobs and GEM reservations before full reset.
The implementation covers DG2, Xe-LPG 12.70/12.71/12.74 and BMG 20.01/20.02.
OA streams, legacy Gen12/media register policies, isolated userspace scheduling
and physical Intel/Mesa acceptance remain open.
Six new native smokes cover literal permissions, inherited-slot clearing,
dropped/cross-slot writes, all six admitted IP profiles, reload/CT failures
and live-job ownership across policy drift and full reset. All 64 selected
policy/firmware/context/GEM/render smokes pass on each architecture, without
failures/skips. GPU CI Clippy passes three contexts on x86_64 and aarch64;
host default/Intel-only/AMD-only/no-vendor all-target Clippy, Intel debug
builds and formatting pass.
Both architectures also pass production boot and both btrfs interoperability
postflights. These remain native model/QEMU results; physical execution is unrun.

The Intel branch continuation now accounts user-job time from per-context
GPU timestamps, including active-context ownership checks and counter wrap,
instead of charging queued/preempted wall time. Isolated context recovery
remains; an engine-wide no-progress watchdog retains full-reset fallback
without blaming an unstarted queue. Optional GuC SLPC now discovers stable
fused limits and applies acknowledged frequency bounds and Base/PowerSaving
profiles with verified range readback. BMG's source-qualified conservative
floor/cap remain; dynamic MERT cap removal and media power control are open.
Legacy console GGTT mappings now enforce their per-pipe reservations. An owned
GEM scanout/latch component retains objects through hardware completion or
verified fetch stop, but KMS continues to copy: direct flips still require
console/display-power/PM ownership and transactional event publication.
Intel silicon and Mesa acceptance remain untested.
The 25 new native fixtures pass on both architectures. Complete selected
Intel/DRM regression groups pass 579 tests on x86_64 and 451 on aarch64, with
zero failures/skips. All three GPU CI Clippy contexts pass per architecture;
host default/Intel-only/AMD-only/no-vendor all-target Clippy, Intel debug
builds, formatting, both production boots and both btrfs postflights pass.

The `feat/amdgpu-navi48-bringup` branch targets RX 9070 XT / Navi48, the
leading named AMD card in the September 2026 Steam PC survey (1.42%). PCI
`1002:7550` has distinct RDNA4 identity, discovery-checked IP selection,
separate physical/CPU-visible VRAM accounting and SMUIO14 ROM access. Legacy
APU/engine/display paths refuse this generation before touching hardware.
The same paths now cover the whole RX 9000 family: any AMD display function
whose discovery reports GC 12.0.1 (Navi48: 9070/9070 XT/9070 GRE, AI PRO
R9700) or GC 12.0.0 (Navi44: 9060 XT/9060) binds by discovery, with Linux's
per-die firmware (including kicker boards), external revision, RAS, DCC-width
and pipe-harvesting differences (`amdgpu_rdna4`, covered by native Rust
identity/discovery and fixed wire/register fixtures). Model-tested on Navi44 and
harvested Navi48 profiles only; no Navi44 board has run it.

The `codex/rx9000-completion` follow-up retains and publishes the VCN firmware
version only with the current proven media owner. Its fixed-stream proofs now
include HEVC Main8/Main10, VP9 Profile0/Profile2 and AV1 Main8/Main10 decoding,
plus HEVC384x128 and AV1 320x128 encode/native-decode roundtrips. Full decoded
pixel and guard checks supplement unchanged Mesa/Addrlib/FFmpeg reference
checks; these are model and source results, with physical codec execution
still unrun. Requested proof backing is transactionally reserved before the
deferred worker and client VRAM carve; insufficient space refuses the complete
request rather than dropping profiles or recycling uncertain DMA storage.
An actual Mesa26.2.4/libdrm2.4.134 host replay executes production Rust INFO
builders for both dies. It verifies the current acceleration and DRM-version
refusals and the remaining query contract in an explicit hypothetical host
envelope. DRM3.0.0, ACCEL_WORKING=0 and the new codec capability gates remain.

The shader-proof opt-in also schedules a native graphics rectangle diagnostic
through two separate client roots/PASIDs on gfx1200/gfx1201. Pinned actual Mesa
NGG/PS, draw/cache-completion packets and Addrlib3 linear surface addresses
define the fixture. It checks all drawn and untouched pixels and immutable
storage/guards, retaining uncertain work until proven reset. Separate R|X
code and R|W data use system/GTT backing. Both target ISAs and the pre/post-PFP2680
constructor variants pass independent primary comparisons; physical rendering,
Mesa application conformance and rendering-to-scanout acceptance remain open.

RX 9000 follow-ups now retain an acquired Azalia audio endpoint per stream
across TMDS, FRL, legacy DP and UHBR, including MST, independently of pipe
and HPO encoder indices. Allocation follows Linux's `find_first_free_audio`;
models cover mixed transports and the full endpoint acquisition masks.
A delayed DET acknowledgment defers compressed-buffer growth for retry on
the next display-monitor pass, retaining the current allocation until the
freed segments are acknowledged. Scanout preparation now retains placement
exclusion through KMS pin acquisition, including against synchronous memory
pressure. DCC allocation can use fragmented gaps containing the final
contiguous aligned buffer without requiring a larger temporary buddy block;
Linux placement vectors now exercise the production reservation allocator.
DML now allocates the shared DET pool using DC's pixel-rate/plane-bandwidth
policy and applies the single-DP Vmin ODM phase, including after P-state
search. Native requestors retain per-plane allocations through live updates;
HDMI transport is an explicit admission input. Zero-stream release lowers
DTBCLK, DISPCLK and DPPCLK, while optional DAL responses follow Linux's
sent-timeout policy with retained failure ownership. Suspend gates/drains
presenter and cursor pins, retires all display streams, and retains incomplete
transitions through caller cancellation and rollback. Native Rust kernel tests exercise retained owners and reviewed reference data;
there is no extracted-source C compilation or temporary Rust comparison gate. KMS preparation now snapshots exact targets,
reclaims idle BOs without evicting another target, and rechecks master/identity
before pinning. Per-card placement admission covers allocation, submission,
transfer and reset; stale or cancelled transfers retain their staging/backing
until actual completion or a proven reset. DSC depth/link fallback uses final
native admission and complete MST payloads. GPU WC mappings and their TCB
prerequisite are merged; physical board acceptance remains open.

Implemented: GDDR6 training; PSP14 SOS/GPCOM/TMR; mandatory graphics/media
firmware parsing, upload and autoload; GC12 RS64 counter programming and pipe
reset with inherited-queue exclusion; SMU14 board-table transfer and initial
GFX/thermal policy; GC12 harvested CU/SA/RB inventory and device-query reporting;
GMC12/MMHUB4.1 owned VMID0 translations; SDMA7 translated
VRAM write/copy/fence verification; and DCN4 DMUB shared state, authenticated
window validation, startup and version/capability/HPD/AUX mailbox support.
GC12 setup now retains the native RLC clear-state image, applies ASIC-revision
golden settings, configures VMID0 shader/context controls and starts RS64
processors with inactive-queue checks and bounded idle confirmation.
DCN4 board routing reads ATOM v1.4/v1.5, preserves distinct AUX/HPD/transmitter
identities and bounds the four channels using DCN4 backend register geometry.
The retained owner supports native DP/eDP DPCD/extended-capability and complete
segmented EDID discovery, including bounded DEFER retries, per-port errors and
cancellation quarantine. HDMI now reads complete segmented EDID through DCN4's
native I2C arbitrator/FIFO with board-resolved DDC pins, 100 kHz clock setup,
fresh completion checks and bounded waits. Terminal sink errors restore pins
and release ownership; uncertain failure/cancellation blocks reuse and raw AUX.
Native link/scanout programming remains open.
The retained DCN4 clock owner now validates its separate DAL mailbox, queries
native clock ranges and applies checked DISP/DPP/DTB floors with both mailbox
and per-clock completion acknowledgements. It pins DCF/UCLK conservatively,
disables UCLK switching, preserves thermal protection and rejects every live
legacy/HPO/FRL display consumer before changing DPM, including timing generators
whose disable request is not yet acknowledged. Partial transitions and
cancellation retain state without replay. Platform clock preparation is
serialized after the kernel engine proofs. Native DCCG now prepares all four
DPP dividers, DPREF-derived DP pixel DTOs, DTB-derived FRL DTOs, and TMDS
dividers with the bounded DENTIST FIFO workaround. Matching global clocks,
retired consumers and readback are required; partial failures retain ownership
and block global-clock changes. Native HPO DP/FRL stream-clock routing now
requires matching current pipe clocks and divider readback, preserving each
DTO's reference. Reprogramming a pipe first parks all actual routes feeding
from it, including inherited routes. Native OTG now prepares disabled fixed
progressive RGB timing on all four pipes, with matching live pipe clocks,
clock-on acknowledgements, native HPO routing, odd-timing divider handling and
PSTATE/global-sync fields. Timing retirement disconnects ODM and requires both
current-master and busy acknowledgements. Partial/cancelled transitions retain
ownership and block clock changes; timing retirement never releases scanout
memory. The retained timing owner also stages native OPP full-range RGB
formatting at 8/10/12 bpc and a black DPG pattern, clears inherited color offsets,
and requires OPP clock acknowledgement. It records pending double-buffer state
without claiming active blanking while timing is disabled. An explicit internal
black-timing start now requires positive stopped-fetcher witnesses on every
HUBP and live clock/timing/formatter readback. Native VTG-before-OTG sequencing
waits for current-master acknowledgement, blank-buffer latching and a fresh
frame-counter transition under one bounded deadline. Running timing blocks
clock changes until acknowledged retirement; failure/cancellation quarantine
the owner and retain every scanout allocation. TMDS still needs a native PHY
PLL proof. Native inherited-plane retirement now disconnects all MPC routes,
waits for MPCC/HUBP drain, blanks powered planes and disables their fetch clocks.
Already-off HUBPs require native PGFSM acknowledgement and remain untouched.
Blank startup accepts native TTU behavior and checks the independent 3D-LUT
fetcher. Pending flips, synchronization, metadata/LUT loads and uncertain power
states block retirement before writes; failure/cancellation retain resources.
Native HUBP DOMAIN0–3 power transitions now require a fully stopped, detached
display tree. The retained owner brackets each gate request with DC IP request
ownership and waits for PGFSM acknowledgement before touching a powered-on
HUBP. It initializes that HUBP to blank/drained readiness with its fetch clock
disabled; power-off requires fresh drain evidence. Pending fetch transactions,
uncertain power, lost writes and cancellation block reuse. All backing memory
stays retained. Surface/VM/bandwidth preparation and framebuffer scanout remain
open; these power transitions still require validation on the physical card.
Native DCN4 surface staging now allocates and retains linear XRGB/XBGR8888
framebuffers, clears row/page padding cooperatively, and programs native pitch,
format, crossbar and viewport fields. Address publication follows an HDP flush
and writes the high address before the low flip trigger. Fetch stays blank and
drained; a pending flip is not reported as completed scanout. Bounded row uploads
check live configuration and flush CPU writes. Partial failures retain published
backing and block reuse.
Native DCN4 memory preparation now binds framebuffer base/top/offset and VMID0
to the retained GMC owner, checking both memory hubs before and after setup.
It uses the owned physical VRAM page-table root, disables AGP, waits for native
context readiness, and configures the selected blank HUBP's system aperture
and L1 translation. All scanout backing stays owned; lost writes, revocation,
timeouts, changed geometry and cancellation cannot report readiness. Fetch
remains stopped.
Native DCN4 DPP preparation now stages unscaled full-frame RGB conversion,
identity color processing and the unity-scaling line buffer against retained
surface, VM, clock and timing owners. Scaler/iSHARP memory wake waits are bounded;
pending double-buffer updates are recorded without claiming a latch. DPP clock
and HUBP fetch remain disabled and MPC stays detached. Lost writes, revoked
authority, stale configuration and cancellation quarantine the owner. Native
bandwidth/deadline/watermark programming, MPC route activation, visible framebuffer
activation and physical-card validation remain open.
Native opaque RGB MPC preparation now binds to the retained surface/DPP/VM and
timing owners, selects global opaque alpha and unity gains, bypasses inherited
output and movable color transforms, and matches the OPP output depth. Current
color selectors are recorded without claiming they latched; routes stay detached.
Native requestor preparation stages bounded physical-RGB fetch geometry and
partitions the 21-segment display return buffer into the native 320-KiB DET
default plus 1-MiB compbuf. Shrinks acknowledge CURRENT before any growth;
timeouts, cancellation, stale owners and lost writes retain every allocation
and quarantine the owner. All four pipes use native DCN4 request fields,
8-KiB chunks, no MALL, and disabled fetch after setup. This establishes storage
and request geometry; DLG/TTU/watermarks and visible scanout are still pending.
Native single-pipe scanout admission ports Linux DML21's DCN4 mode-support
and mode-programming path to fixed point for the implemented shape (one DP SST
timing, one full-frame linear 32-bpp surface, 320-KiB DET, UCLK switching
disabled, Linux's stutter blank reservation kept). It derives DISPCLK/DPPCLK
minimums, global sync, HUBP DLG/TTU values, watermarks and arbiter values, or
names the failing check. A host harness builds Linux DML21 and verifies 126
shared vectors, which kernel tests also check; three deliberate divergences
reject modes Linux would program beyond hardware limits. Plans are not yet
bound to live owners or programmed, and board inputs are not yet read from PMFW.
Admission inputs now come from the live board: PMFW UMC channel count and
DC-mode clock caps (which also cap the pinned floors), the DENTIST VCO, and the
DCHUB reference from the global timer and VBIOS crystal. Deadline preparation
re-admits a plan, binds it to the current timing, sync, signal, surface, DET,
clocks and reference, then programs and reads back HUBP DLG/TTU fields, both
DCHUBBUB watermark sets and arbiter state with fetch stopped. Self-refresh is
force-disallowed; UCLK switching stays disabled in PMFW. Route connection,
fetch enable and visible activation remain open.
Native single-pipe scanout start/stop now runs on the black DP SST stream:
under one OTG master-update lock it releases the DPG, connects the MPCC route,
re-arms the address and unblanks the HUBP, then requires EARLIEST_INUSE to
report the owned surface, cleared pending bits and two fresh frames without
underflow. Stop returns to black, detaches, waits for MPCC idle and drained
requests before blanking and gating clocks, and re-verifies the staged pipe so
it can restart. A read-only health check recognises exactly the owned live
fetch while every other HUBP stays stopped; underflow is recorded and returns
the pipe to black through the same drain, or quarantines it if that cannot be
proven. These paths are model-tested only; no sink has shown the image.
`ColdBoot::modeset_display` now chains EDID/DPCD sink selection, admission,
clocks, surface fill and every preparation through DP training to visible
scanout, with `stop_modeset` reversing it. Only the selection is model-tested;
the chain itself still needs a board, and inherited GOP retirement is separate.
A successful platform modeset publishes the live surface as the external
scanout; the console adopts it and flushes CPU writes through HDP via a
published, non-blocking hook. Stop withdraws it before any teardown.
Live pipes can now flip between two owned buffers: the back address is
written under the OTG lock and the flip completes only when EARLIEST_INUSE
reports it, after which every retained report moves to the new front.
`amdgpu.native_display` opts the boot handoff into retiring the GOP's DP SST
output and running the native modeset; it is off by default because no board
has validated it.
Adopting an external scanout (DCN314 or Navi48), or restoring the boot
framebuffer, now installs a kernel mapping of the published physical range
instead of dereferencing the physical address.
DRM clients' presented frames now reach an adopted Navi48/DCN314 scanout
through that mapping (CPU copy, then the published HDP flush).
A native 64x64 premultiplied ARGB hardware cursor can be shown and moved on a
live Navi48 pipe, programmed under the cursor VUPDATE lock as Linux does.
The fb pointer (console and compositor) uses it on an adopted Navi48 scanout
instead of compositing a sprite.
DP link training now falls back: a cleanly refused link is stopped (sink D3,
PHY off), and the modeset retries lower rates, then fewer lanes.
A running Navi48 modeset can now be checked. HPD comes from the debounced
DCN401 HPD block, and lane lock is read from the sink. A lost link retrains,
and an unplugged sink is torn down without AUX to it. With the opt-in native
display, a 1 s monitor retrains, tears down and relights on replug.
CPU scanout leases now let withdrawal
wait for fb drawing, cursor/status access and DRM fallback copies. Publication
and the writer drain stay under the display owner lock across flips, preventing
reuse of the former front while a CPU view remains. IRQ delivery stays enabled
during drawing, with preemption pinned until the CPU memory fence and lease
release. Cancellation retains pending epochs. After successful teardown, the
monitor now releases the pipe's current and parked front/back/cursor buffers
through `release_display_surfaces`: fresh fetch/route/power/transaction checks,
HDP/PCIe drain, a second check and dependent-report invalidation precede reuse.
Other displays remain owned; failures retain reservations. Replug allocates
fresh buffers without accumulating geometry-specific VRAM. Low-level callers
can still retain buffers until explicit release, and link retraining keeps its
surfaces. Reclamation is model-tested; physical transitions remain unvalidated.
Teardown now checkpoints completed native steps in the retained owner, allowing
the same modeset to resume a preflight rejection without replaying prior audio,
scanout or link work. Intent is recorded before CPU withdrawal; the monitor
finishes interrupted retirement before reactivation and publishes the CRTC
inactive meanwhile. Cancelled CPU drains can resume, but cancellation inside
a native phase blocks replay even when that phase spans several owners.
Native failure guards still block uncertain operations; arbitrary partial
activation and physical recovery validation remain open. Per-pipe startup now
records an unpublished activation before staging. A returned failure attempts
timing/DSC/plane retirement and fresh surface release when native owners prove
the output stopped; completed cleanup steps survive preflight rejection.
Pending cleanup blocks relighting/preferred-mode fallback and is retried before
monitor topology work. TMDS, legacy DP SST/MST, UHBR and FRL startup now checkpoint
completed link/frontend/video/scanout phases, so a later preflight rejection
unwinds the completed work before timing/plane retirement and fresh release.
This includes audio rejection after live fetch and scanout underflow recovered
to black video. MST also checkpoints payload completion before video, retaining
shared-link ownership until payload/frontend cleanup completes. A separate MST
payload-transaction marker survives failure/cancellation before or after list
updates; it blocks replay, teardown and session loss while ownership is uncertain.
TMDS records sink cleanup before the first SCDC transaction, so a returned
failure before native-link completion restores legacy sink configuration and
retires staging without inventing a link owner. Timing retirement also resets
the UHBR/FRL output mux to DIO only after master/busy clear, with readback before
retirement is published. Native failure guards remain binding; cancelled startup,
uncertain MST payload transactions, uncheckpointed active work and
shared-clock recovery remain open, with uncertain memory retained.
The device owner now also retains every completed Modeset through later-pipe
startup, asynchronous platform adoption and failed/cancelled teardown. A dropped
configuration or exited monitor cannot lose those live stream handles. The next
monitor pass restores missing handles and schedules normal withdrawal/retirement,
rejecting conflicting incarnations before changing caller records. New
configurations remain blocked until these streams stop. Native cancellation
quarantine and fresh surface-release checks remain binding.
Live FRL monitoring now handles SCDC FRL_Start, FLT_Update and Source_Test_Update
at a 200 ms fallback cadence. Source-test patterns/FFE updates preserve owned
video/fetch; interrupted firmware work quarantines the display. Ordinary
retrain requests stay pending until full configuration retirement and fresh
admission/training, including supported rate fallback. Physical FRL transitions
and source-test acceptance remain unvalidated. Native FRL now also supports
YCbCr 4:2:0 at sink-declared 8/10/12-bpc depths, with format-aware capacity and
training fallback, half-width encoder counts, AVI colorimetry and shared OPP/MPC
subsampling/BT.709 conversion. The pixel DTO keeps the full pixel rate; live
format checks reject stale compression or encoding state. Y420VDB modes stay
4:2:0, and Y420CMDB modes use RGB when it fits. The single-OPP 4096-pixel limit
remains; physical transitions are still open.
FRL DSC (model-tested, not hardware-validated) follows amdgpu_dm: a stream is
compressed only when no uncompressed encoding fits, with the EDID HF-VSDB DSC
caps, DC's HDMI slice/bpp rules, the compressed FRL capacity check and DSC
padding borrow bit-exact against Linux built on the host (2970 capacity, 3000
configuration and 890 CVTEM vectors). Lighting programs the DSC engines, the
HPO encoder's DSC mode and CVTEM PPS (generic packets 5-10), then the OPTC
after training; teardown reverses it. 7680x4320@60 on a 4x12G DSC sink picks
4x6G with 8 slices at 159/16 bpp. FRL DSC compresses RGB from 12, 10 or 8 bpc
(the deepest the HF-VSDB's DSC_10bpc/DSC_12bpc and amdgpu.max_bpc allow, as
Linux tries each depth); compressed 4:2:0 is not native.
DP MST DSC (model-tested, not hardware-validated) on 8b/10b and UHBR follows
amdgpu_dm's fairness search (1500 link vectors through Linux's own functions),
drm_dp_mst_dsc_aux_for_port (virtual DPCD, passthrough, Synaptics/Realtek
quirk) and dm_helpers_dp_write_dsc_enable over remote DPCD; payload PBN uses
the compressed bandwidth and each stream sends its own PPS. Two 4K144 sinks
behind one HBR3 x4 branch both compress at equal bpp. MST DSC and UHBR DSC
streams now keep LPCM, budgeted at the compressed bpp and slice count as
Linux's check_audio_bandwidth_dp does (6048 host-checked DSC vectors);
Synaptics cascaded workarounds and PCON FRL DSC are not ported.
FRL now carries LPCM through AFMT4, lane-rate ACR and the pipe's Azalia endpoint.
Admission/training reserve the sink's supported LPCM bandwidth; SD timings use
layout 0. Audio starts after scanout and stops before it, preserving the
video-owned InfoFrame. Fresh register checks and retained owners prevent reuse
after partial failures. Shared audio DTO selection includes FRL on DPREFCLK.
Register/protocol tests cover all six rates, RGB/4:2:0 depths, bandwidth limits,
clock sharing and failed teardown; audible output remains unverified.
HDCP/protected output is tracked separately in
`drivers/gpu/research/navi48-protected-output.md`, including TA firmware,
protocol, credential authorization, isolation and physical acceptance gates.
It remains unsupported and unadvertised; existing crypto helpers and retirement
exclusions do not implement protected scanout.
The board/monitor acceptance ledger is
`drivers/gpu/research/navi48-display-acceptance.md`. It separates software models
from physical boot/hotplug/modeset/disable evidence. No board routes or physical
passes have been supplied; eDP/USB-C applicability remains undetermined.
Physical DP/HDMI connectors now retain EDIDs and independently admitted modes
while disabled or unadmitted. Link selection and full joint DML bound these
lists, including fitting alternatives to an unsupported preferred mode. Empty
configurations query board limits without active floors or stream allocation.
KMS publishes dark sinks without a CRTC mode, invalidates replacement EDIDs and
reprobes disabled ports on HPD rise. This still uses whole-configuration relights.
The lit Navi48 display is published as DRM KMS state on the amdgpu card, with
the sink's real EDID and exact timing (disconnected on unplug). SETCRTC
accepts only that timing, and the base amdgpu DRM version 3.0.0 claims no
render ABI. Flip events remain software-paced.
Navi48 DP SST displays now support VRR (FreeSync / DP Adaptive-Sync) as
amdgpu_dm does: EDID range + DPCD MSA_TIMING_PAR_IGNORED give the connector's
"vrr_capable", a VRR-supported stream sets IGNORE_MSA_TIMING_PARAM, and the
CRTC's "VRR_ENABLED" reprograms OTG DRR live (optc401_set_drr totals from
mod_freesync, a manual trigger per flip). HDMI/MST VRR, BTR/LFC and the
FreeSync infopacket are gaps. Model-tested only; not run on an RX 9070 XT.
Navi48 color management and HDR follow amdgpu_dm on DCN 4.0.1: CRTC CTM
(MPC gamut remap), GAMMA_LUT (OGAM PWL from Linux's color_gamma/cm3 math,
bit-exact against host-built Linux) and legacy SETGAMMA/GETGAMMA (sRGB
pre-degamma ROM), applied live under the OTG lock; connector Colorspace
(output CSC, blank, AVI C/EC/Q, DP MSA and VSC SDP) and HDR_OUTPUT_METADATA
(HDMI DRM InfoFrame, DP HDR SDP, live metadata updates). No DEGAMMA_LUT on
DCN 4.0.1, as Linux. HDR and VSC colorimetry now also go out on 128b/132b SST
and MST streams (HPO VPG packets 0/3, GSP0/GSP3, MISC1), DIO MST streams and
HDMI FRL (HPO FRL generic packet 4), with live metadata updates, and MST
end-device connectors carry Colorspace/HDR_OUTPUT_METADATA. DP SST picks its
output depth as amdgpu_dm does (EDID bpc bounded by max_bpc, stepping down
until a link fits; 8 bpc by default), and at each depth compresses when no
link carries it raw (10- and 12-bpc DSC input, the PPS, rate control and DSC
input depth at that depth; 2000 depth-search vectors against Linux's DSC code).
MST streams on a link with a DSC decoder take the deepest depth the port and
the joint fairness search accept (1200 deep-color fairness vectors); MST links
without a decoder run each stream at the deepest depth its port carries raw,
its PBN sized for the requested depth as dm_encoder_helper_atomic_check does
(1500 vectors through amdgpu_dm's depth and PBN code). Every connector, MST end
devices included, has amdgpu_dm's "max bpc" property (8..16, starting at 16)
through GETPROPERTY, OBJ_GET/SETPROPERTY, SETPROPERTY and atomic; a change
relights the display it drives, and amdgpu.max_bpc stays a ceiling over it.
Model-tested only; not run on an RX 9070 XT.
Native legacy/HPO DisplayPort stream blanking now waits for actual video-stop
acknowledgement before resetting or disabling FIFOs. It handles inherited
disable-in-progress state, keeps timing and link clocks available for PHY
retirement, and quarantines the owner on timeout, failure or cancellation.
Native DP frontend retirement now shuts down blank DIO/HPO encoders and waits
for their clock-off witnesses. DIO retirement checks real backend routes,
requires connected backends stopped and removes only the selected frontend
bits; unrelated live outputs stay untouched. Clock programming now rejects
enabled frontends/FIFOs and outstanding frontend/stream clocks even when video
is blank. Active packet/metadata work blocks retirement, and partial failures
or cancellation retain all resources. Direct external legacy DP SST now has a
board-routed DMUB v1.7 transmitter-disable path. It preserves the frontend until
firmware clears backend enable and clock-on witnesses, then clears training and
panel state. Invalid routes, active packet/FEC work and independent HPO/FRL links
reject before commands. Failure/cancellation retain display and transport
ownership and block reuse; backend clocks independently block clock programming.
This proves digital backend-off, not analog PHY power gating. Native HPO digital
link retirement now resolves the board PHY mux, independent stream mappings and
root-clock source, requires all mapped streams stopped, drains all six timeslot
rows with ACT and waits for DPHY and link-clock shutdown acknowledgements.
Ambiguous routes, active work and unsupported modes reject before writes;
partial failures and cancellation quarantine the owner. A separate direct HPO
DP PHY shutdown now sends native DMUB v1.7 DISABLE with explicit SST/MST signal,
requires all four lanes disabled with data/clock/handshake activity clear and
TX-clock-off readback, then parks only the selected root-clock route. Shared
PHY/root routes and live digital work reject before commands. Failure or
cancellation retains ownership; lane/TX activity independently blocks global
and pipe clock changes. These checks still require silicon validation and do
not prove analog power gating. Native TMDS HDMI frontend retirement now clears
all 15 generic packet schedules, acknowledges their buffered updates, resets
stream attributes and stops the FIFO/frontend with DISPCLK/SYMCLK/TMDS clock-off
witnesses before disconnecting selected routes. Live audio/metadata, ambiguous
routing and pending transactions reject before writes; failures and cancellation
quarantine the owner. Backend/PHY/OTG clocks stay retained for the TMDS timing
symclk dependency. A separate TMDS timing-retirement operation now requires
all frontends detached, validates stable TMDS backend/PHY state, stops one OTG,
clears latched underflow and acknowledges its OTG/input clocks off. It preserves
other timing generators and every PHY; fresh consumer checks remain mandatory
before transmitter shutdown. Failure/cancellation retain and quarantine the owner.
Direct external TMDS transmitter shutdown now checks all timing and frontend
consumers stopped, parks only frontend symclk routes using the selected PHY,
and sends the native HDMI DMUB DISABLE command. Independent hardware witnesses
must acknowledge backend, all four lanes and TX clocks stopped; mailbox
consumption alone cannot complete shutdown. Already-disabled backends require
complete off readback without replay. Other outputs stay retained, late route
or consumer changes fail, and failure/cancellation block owner reuse. This
proves digital/lane/clock shutdown, not analog power gating or memory retirement.
Native TMDS HDMI startup now exists for one 8-bpc RGB stream up to 340 MHz:
DMUB SET_PIXEL_CLOCK for the transmitter's PHY PLL, link-encoder setup, the
DIGX stream setup and HDMI stream attributes, frontend routing and FIFO, then
the DMUB transmitter ENABLE with lane, TX-clock and clock-on witnesses. Black
video starts and stops with AVMUTE handling, scanout runs on HDMI video, and the
link stops back to a reusable owner. The AVI InfoFrame (Linux's RGB fields,
VIC 0) is sent as VPG generic packet 0. Modeset now lights an HDMI sink (HDMI
VSDB required, at most 340 MHz) when no DP sink answers, with HPD polling,
unplug teardown, replug and an HDMI-A KMS connector. Sink selection also parsed
the whole multi-block EDID as one base block, so a monitor with any extension
(nearly all) was never selected; it now parses the base block. HDMI 2.0
modes above 340 MHz (e.g. 4K60) now run scrambled when the EDID declares SCDC
and a covering HF rate: native DDC gained SCDC register reads/writes, the sink
is configured before the link starts and returned to legacy on stop. HDMI deep
colour (10/12 bpc RGB, opt-in with `amdgpu.max_bpc`) scales the TMDS character
clock as Linux does. HDMI audio's display half (audio DTO, ACR, AFMT channel
status, Azalia endpoint/ELD, Audio InfoFrame) is programmed after scanout for
sinks declaring audio. The native HD-Audio runtime now binds Linux's ATI
HDMI NS controller IDs (through 0xab40) with snooping off: CORB, RIRB, BDL
and sample rings get explicit cache maintenance. The ATI HDMI codec
(0x1002aa01) is driven like Linux's atihdmi for LPCM up to 7.1: zero downmix,
per-channel remap (rev3+), the CEA channel allocation for the sink's speakers,
channel count, slot map and allocation (which feeds the hardware Audio
InfoFrame), ramp rate, HBR off and converter DIGEN. The codec's ELD is
rebuilt as Linux's get_eld_ati does and exposed as the `ELD` control with an
`HDMI/DP,pcm=0 Jack`; pin sense is polled, playback routes to the ports with
a valid ELD and is limited to their channels/sample sizes/shared rates
(44.1–192 kHz), and a port that gains a sink mid-stream is set up again.
Linux's IEC958 Playback Con/Pro Mask, Default and Switch controls and the
`Playback Channel Map` control (with its CHMAP TLV) are exposed: the AES0
non-audio bit makes the next prepare IEC 61937 passthrough (stream-order
slots, no ramp, HBR for 8-channel non-PCM, TYPE bit in converter and SDnFMT),
and user channel maps choose the CA and slot map under hdmi_chmap_ctl_put's
state rules (pairwise validation before codec rev3).
Legacy DP SST LPCM now shares the DIO stream with DSC PPS. Startup and live
checks require fresh PPS/clock/master witnesses, and audio stop preserves those
video-owned resources while disabling audio packets and the endpoint. Modeset
keeps DSC sink audio capabilities and uses normal audio-first teardown/retrain.
UHBR SST now carries LPCM through the HPO stream's APG and Azalia endpoint.
LPCM rate filtering uses Linux's fixed-point blanking budget with the native
programmed minimum width; selection and training fallback keep only supported
rates. Reset assertion/deassertion use bounded async waits, retain cancelled
owners, and recheck transport/audio before APG enable. Audio-first teardown and
retrain preserve video ownership; shared DTO and endpoint checks include UHBR.
Models cover all stream instances, rates and lane counts, reset timeout/cancel,
partial writes, late drift, clock sharing and shutdown; 1701 arithmetic vectors
match the Linux routines under that native-width contract.
Legacy MST now carries LPCM through each stream's DIO AFMT and DP endpoint.
Remote EDID rates are filtered by Linux's blanking budget (2268 reference
vectors); startup requires a completed manager payload and fresh SAT/VC and
transport witnesses. Partial writes and failed shutdown retain audio/payload
ownership. Models cover independent routes, all RGB depths, stale allocations,
endpoint collisions, shared DTO and two-stream link-owner handover. Teardown
stops audio before scanout/video and payload removal.
Every native endpoint (TMDS, FRL, legacy/UHBR DP SST, legacy/UHBR MST) advertises
the sink's valid compressed SADs and HBR from Linux's 8-channel 192-kHz
bandwidth probe; FRL reserves the highest SAD rate/channels like
get_audio_check. UHBR MST LPCM uses the stream's HPO APG and, as Linux
does, the 128b/132b SST budget (whole link, timing blank), started only on a
completed manager payload whose SAT row stays a witness; physical
audio is untested. FRL LPCM and HDMI 4:2:0 have model coverage
as described above. None of it has run on hardware.
Native FRL frontend retirement now drains all generic packet schedules through
the actual HDMI/VUPDATE buffer status, disables FIFO then tribyte encoding and
requires all three stream clocks off. Native DME4, immediate packets, audio/ACR,
reset state and input/clock routes are checked before writes and across waits.
Already-retired streams stay untouched; failures and cancellation quarantine
ownership. Link/PHY/timing, general-control configuration and independent
AFMT/VPG owners remain retained. Shared clock guards now include FRL clock-on
and reset state plus digital-link enable/reset/clock activity.
Native FRL digital-link retirement now resolves the unique board PHY route,
requires a stopped frontend and matching character/forced-clock routes, selects
zero training patterns and disables the link with acknowledged clock-off before
restoring compression. Partial inherited shutdown, shared routing and late
producer/configuration changes reject; failure/cancellation quarantine ownership.
PHY output, root clocks, timing and unrelated outputs stay retained. The FRL
character-clock root independently blocks shared clock changes after link stop.
Direct external FRL PHY shutdown now uses the native firmware FRL mode and
requires all four lane-disable and TX-clock-off witnesses before parking the
character-clock root. Shared PHY clock consumers, unacknowledged DTOs, TMDS
timing and pending transitions reject before commands. Live DTB/DPREF timing,
forced input clocks and other outputs remain retained. Already-stopped PHYs
skip firmware replay; late changes, failure and cancellation quarantine the
owner. This proves lane/clock shutdown, not analog power gating or memory reuse.
Direct external legacy DP SST now has a native untrained PHY enable operation
with 1/2/4 lanes at RBR through HBR3, after matching applied display clocks.
Native backend setup and board HPD/mux routing precede firmware ENABLE.
Independent physical lane, TX-clock and backend-clock witnesses are required;
lane reversal is supported and unused lanes must remain disabled. A matching
shutdown operation verifies this owner's unchanged untrained PHY and waits for
backend/lane/clock stop before cleanup. Active consumers, stale routes and
incomplete hardware transitions reject; cancellation/failure retain ownership
and block replay. Model tests cover routes, rates, lane mappings and failures.
Native direct DP SST training now requests and verifies sink D0, reads live
base/extended capabilities and drives source TPS1/TPS2/3/4 plus matching sink
training over the board AUX channel. Firmware applies uniform clamped voltage/
pre-emphasis requests; bounded CR/EQ loops require every active lane and interlane
alignment. Source/PHY checks and fresh sink configuration/power/link status after
5 ms of native idle prevent stale completion. Matching trained-link shutdown
acknowledges sink D3 before PHY retirement. Cancellation/failure retain ownership
and block replay; known CR/EQ failures exit training when transport remains sound.
Model tests cover routing, patterns, rates, lane counts, adjustment/retry limits,
every await cancellation, lost writes and late changes. No native scanout or
silicon validation is claimed. Automatic rate/lane fallback, LTTPRs, MST/FEC,
fixed-drive retimers and board-specific SSC control remain open.
Native blank legacy DP frontend setup now uses independent OTG/frontend/PHY
routes, RGB MSA attributes at 8/10/12 bpc, DPREF-derived pixel packing and native
frontend/FIFO reset acknowledgements. It checks retained live clock references,
source/OPP state and fresh sink lock before reporting readiness. Matching
frontend shutdown waits for clocks off before detaching routes and returning
to the trained link; cancellation/failure retain ownership and block replay.
The native frontend payload guard now accounts for DSC's compressed bits per
pixel and slice overhead instead of rejecting it as uncompressed RGB. Actual
trained rate/lanes and FEC's capacity reduction bound both kinds of stream;
DSC requires the supported RGB/FEC path (SST or MST) at the blank depth its
PPS codes. A native regression exercises
DSC fitting one RBR lane when RGB does not, including the FEC capacity boundary.
Legacy DSC training can now fall back among rate/lane settings that carry its
unchanged admitted PPS and bpp. Alternative DP modes carry DSC into joint DML
with real board limits and must fit the trained link after fallback. Retraining
refreshes retained and published mode lists beside current siblings and drops
invalid queued requests. When no link carrying the staged PPS trains, the
port's link is verified like Linux's dp_verify_link_cap and the configuration
is selected and admitted again against it, so DSC bpp/slices are recomputed
for the reduced link. A refused link-loss retrain is journaled and retired
through ordinary teardown, then relit against the verified link (model-tested).
Native legacy DP black video now starts the matching staged OTG/OPP pattern,
requires fresh frame progress, seeds M/N and follows steering/video/resync FIFO
startup with native priming delays and independent acknowledgements. Fresh sink
lock, source/route/clock checks and subsequent frame progress precede completion.
All memory fetchers stay stopped. Matching shutdown waits for video-off before
steering reset and native timing retirement, then returns to the prepared
frontend for restart or link shutdown. Failure/cancellation quarantine the
owner and retain resources. Model coverage includes all independent routes,
lost acknowledgements, stalled frames, late changes and every async phase.
Physical output remains unvalidated; native surface scanout remains open.
eDP, remaining sink/MST/audio teardown and USB-C/ACPI PHY interlocks still need
their sequences. Remaining PHY/link and plane programming, surface scanout
enable, active-stream transitions, bandwidth/watermarks and complete native
modesetting remain open. Implemented paths have model tests, not silicon validation.
MES12 now has separate eight-byte-aligned command and MQD builders, kernel queue
map/unmap packets and two-fence completion/error decoding, checked against Linux
C layouts. Its retained unified-firmware owner starts both pipes, configures
PCIe BAR2 doorbells, maps the scheduler through KIQ and verifies native command
completion plus full ring drain. The boot sequence includes this firmware-queue
handshake; it grants no application queues or user VMIDs yet. Native kernel
graphics and compute MQDs now map through the scheduler and execute bounded
WRITE_DATA proofs into the two owned translated VRAM pages, requiring confirmed
fences, complete 32-bit RPTR drain and all expected data words. Cancellation
and failure retain all published queue memory and prevent replay.
Native OSSSYS7 interrupt rings now retain their own VRAM, reject inherited
writers before training, and initialize after GMC. Bounded fair draining
decodes full SOC21 vectors, handles wraparound and detects overflow before
acknowledging entries; errors quarantine backing and stop owned writers when
authority permits. The final boot handoff now transfers IH to an independent
async service, so display work cannot block draining. A checked x86 MSI route
uses the actual APIC ID, enables delivery after handler/config readback, and
retains uncertain routes/vectors. The service snapshots IRQ counts before
draining and uses a watchdog; unsupported routing uses timer-driven polling.
ARM hardware MSI awaits real ITS ITT backing. Bounded diagnostic history records
evictions and sticky VM-fault data; it does not complete user fences.
An executor task now follows boot with native graphics/compute RELEASE_MEM
proofs, requiring a fresh fence, full RPTR drain and exactly one matching
kernel-context EOP vector per queue. Configured MSI additionally requires CPU
delivery for each proof; polling is reported separately. Faults, cancellation
and missing evidence leave retained diagnostic state and prevent replay.
This path has software models; physical MSI delivery remains unverified.
After both GC12 proofs drain, the same executor task now verifies SDMA0's native
fence/TRAP path. It requires fresh fence memory, matching hardware/writeback
RPTRs, exactly one kernel SDMA0/queue0 trap and CPU delivery for configured MSI.
The service owns SDMA trap enables and masks them after recognized faults;
raw-history eviction cannot erase the completion count. Diagnostics retain
the separate SDMA interrupt result, including failure/cancellation state.
Negative models cover missing evidence, wrong contexts, revoked authority and
cancelled submissions; this adds no application submission or recovery API.
The independent service now arms native VMID0 protection faults in both hubs
and the owned graphics/compute command exception sources. It decodes VM fault
addresses and queue identities, snapshots hub status before acknowledgement,
and masks owned sources after a fault. Typed diagnostics survive raw-history
eviction, and VM or command faults prevent the EOP proof from succeeding.
Setup/MMIO/revocation failures retain uncertain owners and mask CPU delivery
where possible. No fault replay, automatic reset or allocation reuse is implied.
A typed SOC21 decoder now covers every GC12 completion, fault and poison
source, DCN401 display events, VCN5 media and SMU sources. A dispatch table
wakes registered owners (CP slot, SDMA queue or user doorbell, with VMID/PASID
and a generation) so they re-check their own fences; a 100 ms watchdog bounds
lost interrupts and is counted separately. Faults go to the owning queue or
context, `recover` starts a new generation after the owner resets its queue,
and poison or service failure (including device removal) releases every
waiter with a terminal error. Kernel queues are registered; there are no
application owners yet. Model-tested only.
IH ring0 overflow is now recovered as Linux does (resume after WPTR, pulse
the overflow clear). A batch racing an overflow is discarded, all owners are
woken to re-check their fences, and both VM fault latches are swept so a
fault whose vector was overwritten is still captured and attributed.
Overflow storms and ring1 overflow still fail closed.
The interrupt worker now counts MSI, empty-MSI, watchdog, watchdog-with-work
and polled drains separately, the evidence a physical MSI test needs. DCN401
hot-plug, flip, VUPDATE, vblank, VLINE and DMUB vectors are counted per
instance for the display owner, and the native display monitor now waits on
hot-plug vectors with its 1 s poll as fallback; it arms each lightable
port's DCN HPD (and DP HPD-RX) interrupt and acknowledges raised ones like
Linux's hpd0_ack.
The retained SMU14 owner now reads PMFW telemetry (Linux's SMU14.0.2 metrics
table: edge/hotspot/memory/VR temperatures, fan RPM/PWM, socket/board power,
VDDGFX, current clocks, activity and throttler status), the running feature
mask and PPT limit, and decodes board thermal/fan/power limits. Throttlers,
firmware CTF and fan control stay PMFW-owned; protection loss is detectable.
GFXCLK performance levels use PMFW soft limits only, leaving display clocks
pinned. Deep sleep has an SMU-side, disabled-by-default hook: memory/fabric
low power still needs display admission/watermark recalculation first.
After boot, a 1 s monitor publishes this as a Linux-shaped `amdgpu` hwmon
device (temperatures with critical/emergency limits, read-only automatic fan
PWM/RPM, VDDGFX, power and PPT cap, sclk/mclk) and logs throttling, lost
protection and software-shutdown temperatures. Narf reports, not powers off.
Model-tested only; nothing here has run on an RX 9070 XT.
The boot coordinator retains all hardware owners through failures and
cancellation. The final framebuffer handoff selects Navi48, blocks legacy
controller/PM access after preparation and quarantines the primary framebuffer
on incomplete startup. Read-only preparation failures restore CPU writers.

A Navi48 stream too fast for one pipe (pixel clock above the DISPCLK
maximum) or too wide for one DSC or 4:2:0 formatter now runs on two pipes as
ODM 2:1: DML21 admission decides it as Linux's auto policy does (matched
against Linux on new ODM, ODM+DSC and ODM 4:2:0 vector sets), the modeset
gives it a free pipe, and the timing, both OPPs and DSCs, both HUBP/DPP/MPCC
halves, deadlines, flips and the cursor are programmed across the pair
(implementation and register models; no hardware run).

Navi48 streams DML splits wider now run as ODM 3:1 and 4:1 (8K and 10K at
high refresh, 4K480, 8K DSC of twelve or sixteen slices; DML21 matched
against Linux on 1927 new configurations): the modeset takes every further
pipe from the 4-pipe pool (refused when other displays or overlays hold
them), and the OTG (segment count, widths incl. 3:1's last segment,
divide-by-four timing, per-segment memories), every OPP's blank, every
segment's DSC, HUBP viewports and SPL slice rects, deadlines and teardown
cover each segment. Planes one DPP cannot carry (DPPCLK above the maximum,
a swath the line buffer cannot hold) are MPC-combined on two DPPs as DML21's
auto factor decides (matched against Linux on 1512 configurations; SPL MPC
slices on 210 more), both slices blended in the stream's MPCC tree with
overlays. New sinks light beside running displays, and the remaining ones
re-plan after one leaves, without relighting them: shared DISPCLK/DPPCLK/
DTBCLK follow dcn401's prepare (raise first) / optimize (lower after)
ordering with the DPP DTO updates, and each running display takes its new
global sync, DLG/TTU and watermarks under its OTG lock. MST configurations
and mode changes still relight. Implementation and register models; no
hardware run.

Navi48 primary planes now take XRGB/ARGB/XBGR/ABGR 8888 and 2101010, RGB565
and the four FP16 orders end to end (ADDFB2/GETPLANE/SETCRTC/PAGE_FLIP/atomic
TEST_ONLY, DML21 admission at 2/4/8 bytes matched against Linux on a new
format vector set, HUBP/DPP/MPC words as Linux programs them, premultiplied
alpha per amdgpu_dm's default); a format change is a plane update (no relight).
Register models and QEMU only; no hardware run.

Navi48 planes now scale and stack as amdgpu_dm exposes them on DCN 4.0.1:
the primary is placed and scaled through a port of DC's SPL (viewport,
recout, ratios, taps, polyphase/EASF filters; every register word matched
against host-built Linux SPL on 230 vectors) and the DSCL program, and up to
three overlay planes (possible on every CRTC, XRGB/ARGB/XBGR/ABGR8888 and
RGB565) take free pipes, blended above or below the primary through MPCC
trees built as mpc1_insert_plane does, with alpha, pixel blend mode, zpos
and rotation (0/180; 90/270 refused) properties. DML21 admits the planes
jointly (matched against Linux on 654 scaled and multi-plane
configurations); the KMS checks follow amdgpu_dm's (24x12 viewport, 16x up,
6:1 down, primary required, zpos normalization) on ATOMIC, TEST_ONLY and the
new SETPLANE, configurations short of pipes are refused, a plane change is
applied without relighting and framebuffer updates of several planes flip at one
VUPDATE. Register models and QEMU only; no hardware run.

Navi48 planes now take GFX12 tiled and DCC framebuffers and NV12/P010 on
every plane, as amdgpu_dm exposes them on DCN 4.0.1: the 17 GFX12 modifiers
(12 DCC variants, 4 swizzles, LINEAR) in IN_FORMATS / IN_FORMATS_ASYNC,
ADDFB2 with per-plane handles/pitches/offsets/modifiers and amdgpu's size
checks, GEM_METADATA tiling flags converted for ADDFB2 without modifiers
(modifier list, blobs and ADDFB2 decisions matched against Linux's own
functions built on the host, 2454 vectors); HUBP swizzle, DCC enable, luma
and chroma pitch/address; SPL 4:2:0 chroma scaling (124 new vectors against
host-built Linux SPL); the YCbCr post CSC from COLOR_ENCODING/COLOR_RANGE
(120 vectors against Linux's tables and switches); DML21 admission of
tiled, DCC and two-surface 4:2:0 planes with their RQ, chroma DLG/TTU and
mcache plans (618 new configurations against host-built Linux DML21). Tiled
and 4:2:0
framebuffers are staged and CPU-copied whole. Register models and QEMU only;
no hardware run.

Navi48 plane changes no longer relight the display: a plane moved, scaled,
reblended, given another format, tiling or surface, an overlay added on a
free pipe or removed, or the primary's format changed is DC's medium or full
plane update with the timing running (classified as
dc_check_update_surfaces_for_stream does). DML admits the configuration
again, every plane DC keeps stays on its pipes, prepare_bandwidth raises the
shared clocks and watermarks, and under the OTG master lock (dcn401's
interdependent update lock) the freed pipes leave their MPCC trees, each
changed plane's DPP, MPCC blending and HUBP surface are reprogrammed (on a
full update every tree rebuilt top down as dcn20_update_mpcc does), the new
pipes (enabled off-tree first) unblank; after the latch the freed pipes are
drained and gated and their surfaces released, then optimize_bandwidth
lowers what is no longer needed. The display monitor applies a commit's
planes within a frame or two, its frames waiting for them; only a change of
the stream itself (its ODM split) or an MST display relights. The hardware
cursor now shows on every pipe it overlaps (overlays, ODM segments, MPC
slices), placed as amdgpu_dm and dcn401_set_cursor_position place it (1060
vectors against those Linux functions built on the host); DCN 4.0.1's cursor
mode is always native, as amdgpu_dm decides. Register models and QEMU only
(no OTG or OPP write during any plane update in the models); no hardware
run.

DP MST now also runs over 128b/132b links: a branch that codes UHBR trains
MST at its best UHBR rate (as Linux's decide_mst_link_settings does), streams
share the owner's HPO link encoder with all 64 slots from slot 0, and each
stream's HPO encoder is prepared blank, given its payload (SAT rows with ACT,
the VC rate and blanking width matched against Linux's fixed-point
arithmetic) and only then unblanked; teardown blanks, removes the payload and
stops the stream. Its LPCM rides the stream's HPO APG once the payload
completed (implementation and register models; no hardware run).

Navi48 DP SST DSC now also runs over 128b/132b: a mode no uncompressed link
carries is compressed for the sink's maximum (UHBR) link as amdgpu_dm's
policy does (8K60 and 4K240 at 16 bpp on 4 x UHBR10, configurations matched
against Linux's dc_dsc_compute_config on the host), lights on the lowest
128b/132b setting its compressed bandwidth needs, and wide streams use two
DSCs under ODM 2:1. The HPO stream marks the format compressed, enables sink
decoding and sends the PPS through its VPG (GSP11, VBID[6]) before a VC
payload sized for the compressed bandwidth; fallback keeps the PPS. DML21
plans match Linux with DP2P0 encoders. UHBR DSC now carries audio, MST DSC
stays unsupported, and HDMI FRL DSC remains open (EDID DSC caps, compressed
FRL capacity, CVTEM PPS). Implementation and register models; no hardware run.

Native 8b/10b DP MST now reaches the platform display monitor and KMS for one
branch, beside every board port: KMS routes any connector (board port or end
device) to any of the four CRTCs, as SETCRTC/atomic CRTC_ID set it or
automatically in connector order, and board sinks and end devices light as
one jointly admitted configuration. End-device EDIDs feed
joint mode admission and per-stream payload allocation. Disabling the display
that trained the link transfers ownership to a surviving stream; only the
last stops the PHY. Disabled, unreadable or unadmitted devices leave output
gaps, and switching every CRTC off keeps them off. Shared-link loss relights
the configuration. Downstream hotplug now stops payloads using the old routes,
reprobes and relights, retaining output slots by root/branch GUID, route and
port across branch reordering and removal/replug. All-off and empty branches
keep their managers enabled; physical removal drops them without AUX waits.
Changed EDIDs invalidate stale modes. New disabled monitors now publish their
EDID and independently admitted timings without starting a stream: remaining
MST slots, path PBN and joint DML bound the offered modes. All-off branches query
board clock limits without installing clock floors or allocating scanout, and
KMS keeps the CRTC mode unset until enabled. Ordinary disables retain admitted
modes without restarting siblings. Resource notifications now trigger fresh,
port-bound bandwidth queries. Existing payloads are added back before comparing
capacity, avoiding relights caused by our own allocations. Capacity changes retire
old streams before reprobe/re-admission. Every shared path hop constrains payload
and dark-mode admission; zero PBN rejects new modes. Incomplete resource queries
retain the session and refuse replay. Cascaded (daisy-chained) branches share
one link's payload table, hop budgets and DSC fairness; a downstream change
that keeps every lit route (a branch or device added or removed elsewhere) is
adopted live without stopping streams, as Linux handles a CSN. MST now runs
on several DP ports at once, each with its own manager and payload table and
joint DML admission across them; each port keeps sixteen end-device
connectors (lighting stays bounded by DCN 4.0.1's four pipes and stream
encoders, amdgpu_dm's max_streams, and four payloads per manager); a new end
device lights beside the running streams (its payload alone: row, SAT with
ACT, ALLOCATE_PAYLOAD, VC rate) and a departed or disabled one retires alone,
relighting only when Linux would modeset the others (DSC fairness changes,
lost hop capacity). The payload table bookkeeping matches DRM's helpers on
3000 Linux sequences (`tests/dcn401_mst_payload`). No physical validation.
The MST manager now also exposes bounded idle notification polling over
DMUB AUX, retains fragmented messages across transaction/poll boundaries and
applies queue backpressure. Connection notices drive topology reconciliation
in the display monitor. Probes have depth/branch limits and retain incomplete
sessions after cancellation instead of allowing replay.

Navi48 compute recovery now falls back from a timed-out HQD dequeue to an
RS64 MEC pipe reset, clearing all four pipe-0 HQDs while reset is held and
preserving other MEC controls. RLC safe mode brackets recovery; unexpected
active sibling queues and uncertain register writes refuse recovery.
A drained MES suspension rejection now runs detect-only hung-queue reporting;
only owned HQDs permit MMIO, while malformed or undrained results quarantine
MES. Cancellation during the MMIO reset retains the owners and
prevents replay. The existing remap and fence test must still complete before
job memory can retire. Register models and Linux-header checks cover this
path; physical recovery remains unverified.

Navi48 ring recovery now replays healthy contexts' pending jobs under their
original client tickets. Reset test fences cannot release replay buffers or
VMIDs; forced VM/PASID/context setup precedes replay. Explicit whole-device
recovery uses SMU14 mode1, PCI/ReBAR/MSI restoration and ATOM ASIC_Init v2.1,
then fresh firmware, IH, queues and interrupt proofs. Old owners remain
quarantined; contexts report lost VRAM, old readers/interrupt handles are
invalidated, and power/display monitors restart with fresh generations and
modesets. Cancellation
or failure is terminal. Automatic whole-device recovery remains disabled:
the caller must exclude CPU VRAM/GOP/mmap access. Boots needing GDDR6 training
replay refuse this path before hardware changes.

The optional `amdgpu.shader_proof` boot diagnostic now dispatches a fixed
gfx1201 wave32 shader on both retained kernel GC12 queues, after the GC12
and SDMA interrupt proofs drain. It makes only the owned code PTE executable,
programs native logical SH resource state, and checks all 32 lane results,
the output page's poison guards, exact fences, ring drain and fresh matching
EOP/CPU-delivery evidence. Failure/cancellation blocks further GC12 work and
retains storage. Whole-device recovery repeats the requested proof before
publishing its new submitter. Independent LLVM assembly, Linux-header checks
and execution/failure models cover this path; physical execution is unverified.
It does not enable Mesa acceleration or exercise draw state or client VMIDs.

Navi48 interrupt handoff now accepts the client VMIDs initialized by its own
GMC owner. The previous monitor required them disabled, contradicting cold
boot's client-context setup and preventing native service handoff. Fresh
same-device checks require every client context to retain the owned empty
root, VA range and nonretrying control before arming. Fault IRQs now cover
all sixteen VMIDs on both hubs; containment and partial-write cleanup mask
the same owned set while preserving translation policy and EOP enables.
GMC-to-monitor integration and negative register models cover this path;
physical handoff remains unverified.

Contained Navi48 faults now use coordinated graphics/compute/SDMA0 recovery.
Client retirement and submissions freeze before all three reset/fence tests;
late IVs and VM latches remain diagnostic evidence. A generation-bound receipt
guards source re-arming, unchanged controls are verified, and old interrupt
handles are invalidated. Guilty contexts are excluded and healthy jobs replay
under stable tickets before all ledgers reopen together. Cancellation or any
uncertain stage keeps memory pinned; poison, kernel VM faults and unsupported
owners require explicit device recovery. Hardware acceptance remains pending.

Native GC12 and SDMA0 client slots now request an HDP flush on their own
ring and wait for the engine-specific NBIO acknowledgement before IB
execution, including submissions that reuse a VMID without a VM flush.
Linux-header checks pin both supported NBIO layouts and packet fields;
models cover packet ordering and blocked GC12 acknowledgement.

Navi48 now has a retained VCN5.0.0 static-power unified-ring owner and an
opt-in `amdgpu.media_proof` power/transport/retirement cycle. Owned firmware
windows, NBIF doorbells, fresh fence/RPTR completion, byte shared-state
updates and VCPU/LMI shutdown follow the local Linux reference. SMU14 media
power commands require fresh protection/static-clock checks. Cancellation
or uncertainty retains memory and blocks clients. Source-119 dispatch now
wakes a registered VCN owner; a fresh proof requires fence/RPTR/trap and,
with an MSI route, CPU delivery. Registration stays retained on uncertainty
and is retired only after proven shutdown/power-down, so shared fault re-arm
cannot overlook a live media owner. Register/queue models cover these paths;
codec streams, JPEG and physical IRQ acceptance remain open, with no codec
capabilities advertised.

The VCN5 backend can now publish owned client IB frames with MMHUB4.1
flush/semaphore ordering, the MMHUB PASID LUT, HDP visibility and native
fences. Masked ring pointers and backpressure match Linux; once published,
a job always returns a sequence so its resources remain retained through
later errors. Models cover packet fields, ring wrap/full and revocation at
publication. The opt-in `amdgpu.navi48_media` now retains the proven owner
and exposes the unified VCN_ENC queue with a separate MMHUB VMID pool and
generic CS resource retention; user fences are refused. Before publication,
the native session IB test now runs Linux's fixed encode/decode create/destroy
messages in separately retained context/IB/message storage, requiring new
fence/RPTR/trap/CPU evidence and unchanged command-page guards. Its pending
phase closes clients, and cancellation/failure retains every allocation.
Rust builders match unchanged Linux constructors in a host capture harness.
The opt-in `amdgpu.decode_proof` now submits a pinned IGT AVC picture fixture
in a separately retained guarded arena, requiring new completion evidence and
the upstream output checksum. Page-wise initialization/readback cooperates
with the executor. Diagnostics retain the pending/result phase, failures keep
all backing pinned and requested tests repeat after media recovery. Descriptor
builders and fixture bytes match unchanged IGT source; device models exercise
missing/wrong output, guards, partial execution and cancellation. Real picture
decoding remains pending physical acceptance, with codec profiles unadvertised.
The opt-in `amdgpu.encode_proof` adds fixed NV12 create/IDR/close tasks in a
separate retained arena, with the full declared output range backed and guarded.
Fresh completion, bounded matching SPS/PPS/IDR headers and intact command/input
storage are required before publication and after recovery. Builders and input
match pinned IGT source; synthetic model headers verify ownership and parsing,
while physical encoding, complete bitstream conformance and picture quality
remain acceptance work. This proof advertises no codec capability.
The opt-in `amdgpu.jpeg_proof` adds a retained JPEG5 static-power JRBC and IB
transport/interrupt/retirement cycle. It preserves VCN's shared NBIO range,
uses separately reserved GPCOM fence dwords and requires DMA-clean evidence
before memory reuse. A registered exact-source JPEG owner participates in
fault containment; incomplete recovery cannot omit it. Transport models and
unchanged Linux constructor checks support this stage. JPEG picture execution,
native clients and physical acceptance remain open.
The additional `amdgpu.jpeg_decode_proof` submits pinned IGT JPEG5 picture
commands in a separate guarded arena and requires a fresh native completion
plus the active luma/chroma checksum. Input, command and output guards remain
checked; failure/cancellation retains all backing and requested picture proofs
repeat after recovery. Models test synthetic pixels, not JPEG decoding;
physical picture execution and native JPEG clients remain open.
Native JPEG clients now follow: `amdgpu.navi48_media` keeps JPEG0 running as
`AMDGPU_HW_IP_VCN_JPEG` ring 4 with Linux-style kernel-copied VMID0 IBs (plus
a stricter privileged-register filter), client decoder VMIDs on MMHUB engine 1,
retained per-job copy slots, JPEG-only ring reset with innocent replay, and a
fifth recovery owner retired before VCN restarts. Model-tested only.
Fault recovery
requires all four retirements and renewed owners, followed by a new media
interrupt and session IB proof before ledger commit. Media restart cancels old codec
contexts instead of replaying their IBs. Fence readers skip frozen media
and drain before power changes and reopening retirement. Dispatch follows
known PASIDs across VMID changes and limits unknown latches to their hub.
Models cover the fourth owner, exact ring gating, Linux INFO_HW_IP alignment
and cancelled-session lifetimes. Known-stream codec validation, JPEG and
physical acceptance remain open.

Recovery attribution now follows the nonzero PASID carried in a client IV,
so a late fault cannot blame the address space that reused its VMID. Latches
and PASID-less vectors conservatively cancel work only on their own hub;
attribution overflow requires device recovery. Logical client tickets skip
the CS ABI's reserved zero handle when wrapping. GC12, SDMA7 and VCN5 fence
samples now check presence around the read and revalidate authority. Failed
current-generation sampling marks device loss before waking waiters and keeps
allocations pinned; old readers cannot fail a replacement device.

Still open: physical MSI delivery and reset/replay acceptance, GC12 rendering
and application shader execution, GPU VM/userspace and DCN4
clock/bandwidth/link/scanout hardware acceptance, VCN5 known-stream video,
thermal/CTF and reset/suspend/resume hardware acceptance, memory/fabric DPM
and low-power transition hardware acceptance, and physical RX 9000
testing on both Navi48 and Navi44. Thermal interrupts/shutdown, system/runtime
PM and training replay already have software implementations; older entries
above are historical, not a current missing-feature list.
The verified DMA proof covers only two kernel-owned VRAM pages. The driver
continues to report acceleration unavailable; model/QEMU tests do not prove
working silicon, native modesetting or Mesa/Vulkan support.

RX 9000 now also has VCN5/JPEG5 static idle power and GC12 GFXOFF ownership.
Independent media idle waits for physical fences, RPTR drain and DMA-clean
shutdown before SMU power-down. Warm resume preserves codec context, JPEG
copy slots, proofs and sequences, restores IRQs and keeps the shared media
doorbell range owned. Gated fence reads retain capability/HDP/NBIO checks;
fixed-clock static engines still check their status registers. Board-supported SMU14
GFXOFF uses RLC handshakes and disable references around GC MMIO, with fresh
epochs after reset/suspend and no graphics wake for normal media traffic.
Failed/cancelled transitions cannot replay or free unconfirmed resources.
`amdgpu.rdna4_gfxoff=0` disables GFXOFF startup. Proved retained media owners
now enter VCN5 DPG on both dies and JPEG5 DPG on Navi48; Navi44 keeps static
JPEG gating. PSP14 uses separate VCN/JPEG SRAM types and every restore
requires a new physical fence probe without changing client sequences.
Board-supported MM_DPM and DS_VCN follow DPG activation. Recovery disables
media sleep before static re-proof, and JPEG hang retirement keeps its
JMI reset/power cycle. `amdgpu.rdna4_media_dpg=0` retains static media policy.
Physical power-transition and session-retention acceptance remain pending.

RX 9000 runtime power now also has seven factory workload presets through
`pp_power_profile_mode`, including COMPUTE's sleep suppression. Selection
changes are serialized and bound to their admitting owner; reset
and resume restore the last accepted profile before fresh client proofs.
Memory/fabric DPM already had DML admission and P-state convergence; its
runtime path now requires acknowledged watermark ranges and a strict replay
of clock constraints before relaxation. Refused or incomplete runtime floors
cannot be published as applied. Newer per-die PMFW uses active/idle UCLK/FCLK
pairs; older PMFW retains a checked FCLK maximum until the last display leaves.
Board-supported GFX_ULV follows native GC proofs, and DS_DCFCLK follows the
acknowledged DML deep-sleep floor. Independent `amdgpu.rdna4_gfx_ulv=0` and
`amdgpu.rdna4_dcf_sleep=0` switches skip those features. Software models cover
factory masks, compute/display/media interactions, reset selection replay,
per-die thresholds, partial failures and cancellation; physical acceptance
remains pending on both dies.

RX 9000 custom workload profile 6 now reads firmware GFXCLK/FCLK coefficients
and accepts width-checked coefficient updates while preserving the rest of
TABLE_ACTIVITY_MONITOR_COEFF. Ordered owner-bound requests retain consecutive
clock edits; reset/resume replays both accepted clock values. DCC P-state
plans now include MRQ metadata rows and native mcache splits. Live VRR bounds
join planning and readmission caches, with FAMS2 schedules for admitted
multistream configurations. Chained DMUB commands publish once; acknowledged
hardware locks cover schedule changes, flips, cursor and colour/HDR updates.
Native DRR limits restore when scheduling stops, before the hardware lock is
released. DPMM bandwidth raises now program actual active clocks and the
corresponding UCLK QoS index within board limits. Native LFC/MID can retain
switching on one native Vactive/Vblank DRR stream, and matching FAMS2 DRR
methods admit firmware timing on multiple streams. Requested BTR/MID totals
use acknowledged DMUB updates under HW lock, including during real flips;
firmware-clamped registers are distinguished from the accepted request.
Cancellation retains timing, IRQ sources and scanout storage. Single-stream
SubVP now expands one fixed-refresh, unscaled linear RGB primary into a
retained phantom pipe, models its zero DET and separate MALL bandwidth,
acknowledges cache ways and FAMS2 type 4, and drains the alias before native
updates or buffer retirement. DRR, visible cursor scheduling, DSC,
tiling/DCC, scaling and multiple planes/streams remain SubVP extensions. Hardware acceptance remains pending on Navi48 and Navi44.

Navi22 third-review fixes (software-model tested only): DRM ioctl user copies
apply `access_ok` and fault-guarded copies (EFAULT); NVMe/AHCI bring-up
failures stop the controller before freeing DMA; AHCI port bring-up is bounded
per HBA and sets GHC.IE only after the IRQ route; host-install xtask media
default to `narf.disks=boot-only`; DMUB-routed retrain/unplug tables, a non-IRQ
DMUB route lock, a TABLE_MS cap, same-EDID HPD long pulses keep the stream.

RX 6000 software follow-ups now publish the strapped atomfirmware VRAM
module's type/width, common GPU/slot PCIe capabilities, SMU UCLK limits (or
fixed boot MCLK), and Linux's per-GC MALL sizes. Live allowed-register reads
serialize through the retained owner with GFXOFF held. Native ring admission
is FIFO and cancellation-safe; fence IRQs wake per-client waiters. Separate
pre-IB VM writebacks avoid treating whole-job completion as flush completion,
while active job fences still prevent premature VMID reuse. Submitters use
the pre-restart fence generation and reject stale owners after reset.

RX 6000 MEMORY/VRAM_GTT queries now report GEM's shared system-memory budget
instead of zero GTT capacity, and live opens use their registered client VRAM
heap for usable sizes and allocation usage. VRAM_USAGE, VIS_VRAM_USAGE and
GTT_USAGE expose the corresponding byte counts. Native ioctl regressions
exercise RDNA2/RDNA4 visible and hidden heaps, GEM allocation/release, retained
PRIME ownership and short replies. These are software checks; Mesa acceptance
on the physical GPU remains pending.

RX 6000/RX 9000 statistics now share the native INFO ioctl path for timestamps,
fresh SMU sensors and all stable/peak GFX/MCLK queries. Each family uses its
own SMUIO/SMU layout and Linux standard-clock rules; RX 9000 resumes runtime
PM before taking its owner. Per-card GEM movement/eviction counters record
only completed backing changes, and recovery counters expose native full
GPU recoveries. These additions require physical Mesa validation; unsupported
Linux dGPU sensor selectors remain explicit errors.

VDDNB and GPU_INPUT_POWER now extend these native statistics on both RX 6000
and RX 9000. VDDNB exposes VDD_SOC using SMU11's live VID or SMU14's average
SOC voltage. Input power uses the latest firmware-averaged socket-power
sample and can match average power; there is no separate instantaneous
measurement. Hwmon also exposes in1_input/in1_label (vddsoc) and power1_input.
Missing/invalid data stays unavailable. Physical validation remains pending.

Shared WAIT_CS and WAIT_FENCES all/any now preserve the original job's
submitter across reset on RX 6000 and RX 9000 and report its terminal error.
Native RX 6000 tracks guilty timeouts, cancellation and loss without treating
errors as physical retirement. Completed observed jobs retain success.
RX 6000 submission, register queries, TDR and kernel VRAM work now guard GC
access with GFXOFF references and recheck activation/reset epoch under the
owner, enabling the existing admission path. VCN3 gains delayed idle work:
physical encode completion releases DPG pause, all VCN work must drain before
stop/conditional SMU power-down, and begin-use restores hardware while keeping
context and fence sequences. JPEG stays independent; MM_DPM_PG remains
opt-in. Failed/cancelled transitions stay closed. These paths have model
coverage; physical reset/power-transition acceptance remains pending.

Ordinary VRAM-preferred creation now permits Linux's GTT fallback when VRAM
is unavailable, preserving reported preferences and discardable-domain rules.
Visible client VRAM now supports pressure eviction to GTT and promotion back
to VRAM with data preserved. GEM_SET_PLACEMENT records atomic preferences;
validation applies them when address leases and reservation fences permit
migration. Same-card PRIME/shared handles, exported fds and BO lists no longer
pin placement by themselves: identity stays shared while backing changes.
Registered GPU VMs can be rebound after all affected ring jobs and reservation
fences settle, under a card gate excluding queue publication and VA mutation.
PTEs keep their virtual addresses and existing table allocations; TLB sequences
advance before submissions resume. Strict VRAM creation retries can reclaim
mapped buffers, and CS validates listed buffers' placement preferences.
Cancellation while waiting leaves leases and PTEs untouched. Unregistered VM
mappings, deferred CPU user-fence writes and legacy raw leases remain pinned.
Completion retirement now samples callbacks outside its lock, allowing native
progress queries to re-enter retirement safely. Migration regressions cover
shared PRIME identity, CPU leases, multiple VMs and offsets, split mappings,
busy-job/reservation cancellation and re-entrant retirement.
RX6000 invisible VRAM now has ordered kernel SDMA clears and bidirectional
staged migration to/from GTT (promotion requires NO_CPU_ACCESS). Failed and
cancelled copies preserve old PTEs; queued copies retain both allocations and
source KERNEL fences until actual DMA completion. Recovery replays requests,
refreshing upload staging, and never mistakes reset/loss for completion. CPU
BAR access requires current PCI authority, power and reset exclusion. CS
rechecks kernel fences after admission and promotion; GEM/PRIME mmap cannot
bypass NO_CPU_ACCESS after a move to GTT. Published GEM/PRIME CPU mappings
are now revocable: moves freeze every CPU alias across known address spaces
(failure-atomic, allocation-free commit, exact leaf restore), rebinding CPU
and GPU aliases together. Unpublished mappings, address leases and unknown
fork-child aliases refuse safely; device mappings never become mlocked.
Regressions cover multi-space scatter/partial/PROT_NONE aliases, census and
pin refusals, injected rmap preparation failure, commit rollback,
fork/split/mremap, syscall-level mmap publication and relocation, VRAM<->GTT
moves of published views, late fences, allocation failure and fork-gap
retention.
RX 6000 (RDNA2: Navi21/22/23/24) current state — the summary to read first;
the entries below are a dated log.
- Implemented and model-tested (register/fake-engine models, QEMU suites):
  native startup for 40 PCI IDs (PSP/SOS, SMU11, GMC/GART/per-client VMs,
  IH, SDMA, GFX/compute kernel queues, VCN/JPEG), DCN3.0 HDMI/DP modesets
  with DML30 admission, HDMI audio, the Mesa render ABI (CS, GEM, VA, PRIME,
  syncobjs, VA-API/Vulkan video rings), full buffer migration (shared,
  GPU-mapped, CPU-mapped, invisible VRAM), power telemetry and thermal
  shutdown, hang detection and mode1 recovery.
- On by default, each with an off switch: native display, accel, hardware
  cursor, power saving (each feature still admission-gated; the native CS
  path now declares its GC MMIO GFXOFF-safe) and automatic
  recovery (`amdgpu.gpu_recovery=0`; at most 3 per boot, because each one
  quarantines VRAM).
- Runtime controls: `power_dpm_force_performance_level` (`auto|low|high`,
  GFXCLK only) and `pp_features` (Linux's PMFW table; policy-owned bits only),
  on `card<N>/` and `card<N>/device/`.
- Hardware evidence: RX 6750 XT VFIO firmware/queue startup, HDMI to the
  CachyOS login screen, damage copies and JPEG ring proof. Bare-metal boot,
  Mesa rendering/video and reset/power acceptance remain pending; see
  `docs/amdgpu_bringup.md`.
- Open: multi-display presentation on secondary
  CRTCs (opt-in until then); GDDR6 short-training resume (training boots
  cannot recover); physical VCN idle/resume and GFXOFF validation;
  user CPU mappings of VRAM are not revoked during a reset
  (Linux behaviour).

RX 6000 runtime power controls and recovery: the DRM card exposes writable
`power_dpm_force_performance_level` (SMU11 SoftMax/SoftMin on GFXCLK, as
`smu_v11_0_set_soft_freq_limited_range`) and `pp_features`
(`smu_cmn_get_pp_feature_mask` text over sienna_cichlid's 43 mapped bits; a
written mask may toggle only power-policy features and re-plans the power
saving through its admission gates; power saving can now be re-applied after
removal). Writes validate synchronously and apply in a serialized task.
Automatic mode1 recovery after a detected hang is on by default (Linux
`amdgpu.gpu_recovery`), capped at three per boot; the fb console pauses for
the reset through a recovery hook and the power controls republish after it.
`smoke_sync_all_reaches_every_superblock_once` now judges its report against
a pre-fixture baseline, so mounts or disks left by earlier tests no longer
fail it. Model tests only.

RX 6000 defaults: native HDMI/DP display, native client submission (accel),
the DCN3.0 hardware cursor and every power-saving feature are now requested by
default, each with an off switch (`amdgpu.native_display=0`,
`amdgpu.rdna2_accel=0`, `amdgpu.rdna2_hw_cursor=0`, `amdgpu.rdna2_pg=none`);
earlier "opt-in" notes below describe the previous defaults. Power features
still pass every display-admission and driver gate (`HARDWARE_VALIDATED`
stays false; the default list is an implicit opt-in). Multi-display stays
opt-in until secondary CRTCs can present. A failed native modeset leaves the
screen dark, and there is no automatic hang recovery, so first hardware boots
should keep the off switches at hand. Firmware: `xtask import-firmware` now
follows linux-firmware alias symlinks; re-imported from 20260916, all twelve
Navi22 payloads match the distribution and the conformance gate passes.
Memory/filesystem/userspace/GPU/framebuffer suites passed 3333 x86_64 and
2593 aarch64 (zero failures; 22 and 8 environment skips) with clean
production boots and btrfs postflights; debug builds and targeted Clippy pass
on both architectures. Not validated on physical RX6000 hardware.
Invisible-VRAM validation passed 1771 x86_64 and 1263 aarch64 GPU/framebuffer
tests (zero failures; five and one environment skips), with clean production
boots and btrfs postflight. Final RDNA2 reruns passed 42 and 40 tests after
adding the pre-copy CPU-writer lease check. Debug builds, all three targeted
Clippy contexts on both architectures, formatting and Linux constants/parser
checks passed. The full firmware identity check still reports three imported
payloads differing from the installed distribution copies (SDMA, TA and VCN);
those local firmware files were not changed by this work.
GEM mmap now resolves
scattered GTT backing page by page. This is a bounded driver placement policy,
not full Linux TTM parity. Linux conformance covers VRAM module C layouts,
cache sizes and the compiled GC MMR allow-list as well as the existing family
inventory. Broad GPU/framebuffer suites passed 1767 x86_64 and 1259 aarch64
tests, with production boots and btrfs postflight clean on both architectures.
Debug kernels and targeted GPU/fb Clippy passed on both architectures. Final
migration-focused reruns passed 66 x86_64 and 42 aarch64 tests. Six
host profile/metadata tests, Linux C metadata/SMU layouts, formatting and
constant conformance checks passed. Fence regressions cover valid all-ones
writebacks, reserved-zero avoidance for CP/SDMA, exact rollback and JPEG IB
slot parity across sequence wrap. A final 130-test aarch64 RDNA2/media rerun
passed after the media wrap fix.

RX 6000 follow-ups now share clock-gating policy across Navi21/22/23/24,
with per-ASIC Linux CG/PG flags, discovered one-to-four-engine SDMA traversal,
and revision-selected SMUIO ROM behavior. Telemetry selects metrics V1/V2/V3
using each ASIC's firmware thresholds and resolves compatible SMU11 THM/SMUIO
banks for sensors and thermal alerts. Driver-interface diagnostics now use the
profile's interface version. Native modules have canonical `amdgpu_rdna2_*`
paths with the previous Navi22 paths retained as aliases. Boot options use
`amdgpu.rdna2_{accel,multi,hw_cursor,pg}`, retaining legacy names; explicit
canonical power values take precedence, and invalid lists enable nothing.
Conformance now checks Linux CG/PG flags, interface versions, 48 metrics
selections and SMUIO ROM backend selection, plus V3 and Beige Goby C layouts.
Family models cover gating, every discovered SDMA engine, metrics transfers,
thermal alerts, malformed banks and boot-option compatibility. Physical
validation and the existing default-off/admission prerequisites remain unchanged.
Validation: 1757 x86_64 and 1249 aarch64 GPU/framebuffer tests passed, with
production boot and btrfs postflight clean on both architectures. Targeted
Clippy passed on both architectures; formatting, constant checks, four host
profile/option tests and the Linux C metrics-layout probe passed.

RX 6000 native startup now covers 40 exact Linux PCI IDs across Navi21,
Navi22, Navi23 and Navi24. Shared profiles select ASIC-specific firmware and
validate discovered IPs before firmware upload or hardware initialization.
The coordinator covers PSP/SOS, board power policy, GMC/GPUVM, queues, IH,
DMUB, display and recovery, preserving upstream's boxed recovery ownership.

Production SDMA supports one through four contiguous discovered engines,
including distinct doorbells, IH routes, fences and ticket slots for SDMA2/3.
Graphics selects each ASIC's Linux golden sequence (43/42/36/32 rows).
OSSSYS 5.0.0–5.0.3 uses revision-specific self-IV programming. SMC 2.1 selects
power tables by exact VBIOS board ID; power parsing accepts both original and
current Beige Goby layouts without guessing board offsets.

DCN 3.0/3.0.2/3.0.3 enforce six/five/two display resources and select their DML
parameters. Navi24 omits the removed plane/DSC power-gating registers and
encoder rings; its video capabilities contain H.264, HEVC and VP9 decode.
HDMI and DisplayPort modesets pass register-model tests on all four profiles.
Linux conformance checks exact PCI IDs, firmware names/IP selections, hub
registers, golden sequences and 450 common DMUB definitions. Installed firmware
containers parse for all four ASICs. The GPU suite passed 1712 tests with no
failures on x86_64; the aarch64 GPU suite passed 1204 tests with no failures.
The final startup/DSC enablement subset passed 45 tests. Production boot and
btrfs postflight passed on both architectures; release builds, targeted Clippy,
formatting and constant checks passed. Physical testing beyond the existing
Navi22 path remains outstanding. Existing `amdgpu.navi22_*` boot options and module names are retained
for the shared path as compatibility aliases.

Current main includes discrete PCIe probe support
for RX 6750 XT / Navi 22: bounded discovery reads beyond BAR0, separate total
and CPU-visible VRAM sizes, Resizable BAR-independent APU identity, and the
Navi 22 userspace family query. The `navy_flounder_sos.bin` parser and an
explicit PSP 11.0.11 asynchronous bootstrap now handle KDB/SPL/system/SOS
using owned, aligned VRAM with cancellation quarantine. The PSP11 GPCOM ring
now resolves Navi22's register banks and GMC10 address ranges, installs trusted
memory from the SOS container's embedded TOC, and preserves device-owned
reservations through cancellation or failed teardown. A bounded SMC v2.0 parser
now separates microcode from PowerPlay metadata; the ring can load that SMC
once after TMR setup. An explicit SMU11 cold-start handshake checks Navi22's
interface and running firmware version using its discrete-GPU mailbox layout.
The graphics firmware path now prepares the complete SDMA/CP/RLC set, separates
MEC jump tables and RLC subimages, and submits PSP autoload only after all
required payloads complete. Partial load failures/cancellation prevent replay
and preserve device-owned VRAM. A bounded CP-idle/RLC-boot-complete check now
follows PSP acknowledgement and retains raw status for failed-boot diagnostics.
An explicit `ColdBoot` session prepares all required firmware, owns the entire
SOS → PSP/TMR → SMC/SMU → graphics/RLC sequence, and can transfer its live PSP
owner after success. Failure/cancellation records the stage and prevents replay.
Navi22 now has a read-only GMC10/DCN3.0 VRAM plan, including full-aperture
firmware tails, inherited DMUB windows and the two GDDR6 training exchange
buffers. It validates the two address translations and clips exclusions only
when creating the CPU-visible allocator; secondary GPUs need no boot framebuffer.
An explicit GDDR6 cold-training owner now preserves the affected 32 MiB of
VRAM, honors PSP runtime training policy, waits with a three-second deadline, restores only after terminal PSP
completion, and validates/caches the P2C result. The firmware coordinator can
run this before SOS; cancelled/failed training prevents replay and retains the
preimage. CPU framebuffer writers must remain stopped during this path.
Probe now retains a validated Navi22 VBIOS from the SMUIO ROM read registers
when VFCT has no image, preserving the index latch and checking authority per
chunk. This supplies the board's reservation metadata without enabling a PCI
ROM BAR; acquisition failures are identified on the console.
The Navi22 pool plan now inventories all six DCN3.0 pipes and rejects inherited
active GFXHUB/MMHUB contexts. The cold-boot session owns its register metadata
and can run after releasing the controller spinlock, including in a spawned task.
The final boot framebuffer initcall now prepares and runs the firmware sequence
after firmware discovery, before executor/userspace startup. It pauses console
and pump writes, retains the entire owner, and quarantines the primary
framebuffer after a started failure. A successful claim excludes legacy MMIO
access while retaining DRM identity queries. Navi22 refuses the APU suspend
path until a discrete resume sequence exists.
Board PowerPlay preparation now selects the VBIOS or SMC table according to
FirmwareInfo, overlays the ATOM board wiring and applies the exact ASUS C3
quirks before startup. After the SMU handshake, the boot sequence uploads that
table through an owned, flushed VRAM buffer and retains the published buffer
across success, rejection and cancellation. PSP SCPM ownership or malformed
runtime policy refuses this transfer before SMU commands; policy delegation
is not implemented.
After RLC boot, the coordinator now runs board calibration and enables a
restricted GFX DPM policy with firmware power/current/temperature protection
and automatic fan control. It verifies the enabled feature mask and reports
the board's GFX frequency limits. Missing protections fail preflight; unexpected
enabled features, rejection or cancellation prevent further bring-up/replay.
Memory/display/link DPM and deep power states remain disabled until their
owners can supply display and lifecycle constraints.
The required firmware set now includes VCN and DMCUB. PSP receives those after
RLC autoload, and their reported entry addresses must lie inside the retained
TMR. Missing/malformed media images prevent startup before device writes;
partial upload failures preserve ownership and prevent replay. VCN queues
start later, after the fence stage (below).
Production cold boot now initializes GC/MMHUB VMID0 with a bounded VRAM-only
test aperture after the protected power policy is active. Both hubs validate
idle contexts and matching framebuffer geometry, use owned VRAM page tables
and fault fallback, and wait for bounded TLB acknowledgements. Failed or
cancelled starts retain the backing pages. A following GART stage repoints
VMID0 at a 512 MiB VRAM-resident GART (boot pages retained) and arms user
contexts 1–15 on an empty root. The hub owner binds pinned system DMA pages
into the GART and creates per-client GMC10 four-level VMs with Linux PDE/PTE
encodings, engine-17 invalidation on both hubs, and VMC/UTCL2 fault
attribution; register-model tests cover isolation, timeouts, cancellation and
revocation. Not hardware-validated; GEM/CS now run client IBs on these
per-client VMs (below).
SDMA0 now has a cold-start path on GC 10.3.2 and an owned VRAM ring. Production
boot runs a translated WRITE/COPY/FENCE test after GMC setup and checks both
read-pointer paths and all copied words. Reset and completion waits are bounded;
fault/cancel paths retain the ring and prevent replay. Software models exercise
packet decoding, register units, corruption, revocation and reset cancellation.
DCN3.0 DMUB now has an owned lifecycle: stop inherited firmware before PSP
upload, retain its authenticated instruction/stack windows, program owned
VBIOS/mailbox/trace/state storage and await a fresh firmware-ready status.
Navi22's reset registers are checked independently from Phoenix's. Unsupported
firmware layouts, invalid secure-window bounds, stop/boot timeouts, revocation
and cancellation refuse further startup without reclaiming published storage.
The retained owner now also drives DCN3.0 inbox1/outbox1: startup verifies the
running firmware version and queries capabilities, with HDP flush/invalidation
around PCIe VRAM traffic. Serialized native HPD and AUX/I2C-over-AUX operations
preserve unrelated notifications and reject stale replies. Software models
cover ring wraparound, cache ordering, malformed pointers/replies, cancellation,
timeouts, revocation and notification overflow; real-card validation is pending.
Native display block owners now resolve Navi22's six-pipe DCN3.0 profile,
including its OTG/ODM field differences, HUBP detile field and DisplayPort DIG
reset sequence. The DPP/OPP/MPC and shared DCCG paths retain explicit bounds;
Phoenix-only pixel/DPIA clock muxes are refused on Navi22. The Navi22 DAL clock
owner now reads board limits and the display PLL, enables bounded display DPM
through the retained SMU, pins memory/fabric clocks and programs DENTIST only
after every stream retires. Register models cover rounding, rejection,
revocation, cancellation and divider completion. GDDR6 mode calculations and
full modeset coordination are still pending. Native routing now resolves
AUX and HPD independently through the board GPIO LUT, follows display-table
relative record offsets, and rejects ambiguous routes. The Navi22 backend probe
uses the DCN30 enable register and includes the sixth transmitter. Navi22 kernel
queues now follow Linux's non-MES GC 10.3 path: BAR2 doorbells, golden/CAM/
constants/RLC CSB setup, the direct gfx ring with clear-state, KIQ-mapped
compute (v10 MQD, MAP_QUEUES) and production SDMA on both engines, each with
ring and IB/fence tests after `DmubStart`. Navi22 `AMDGPU_INFO` now answers
DEV_INFO, HW_IP_INFO/COUNT, FW_VERSION, READ_MMR_REG (GB_ADDR_CONFIG) and
MEMORY as Linux does for GC 10.3.2, from a cold-boot harvest sample, the
loaded firmware headers and the PCI revision; ACCEL_WORKING and ring masks
sit behind one switch, now wired: the card registers a generic
`amdgpu_cs::Submitter` and client VRAM heap, so the shared CS/GEM/VA path runs
client IBs on the Navi22 kernel queues (per-client GFXHUB VMIDs 1–7 from
the generic `amdgpu_vmid_grab` manager: flush only when a space's VMID, root
or TLB sequence changes, PASID→VMID IH LUT writes so faults reach the
client's GPUVM_FAULT; fences, two in flight per ring), with user fences, GEM_METADATA, PRIME, DRM 3.64.0 and
GET_CLIENT; proven in register/fake-engine models only (ABI audit:
`drivers/gpu/research/navi22-mesa-abi.md`). The generic sync ABI (shared with
Navi48) now matches Linux: timeline syncobjs (`DRM_CAP_SYNCOBJ_TIMELINE` = 1,
TIMELINE_WAIT/QUERY/TRANSFER/TIMELINE_SIGNAL/EVENTFD, CS timeline chunks),
syncobj and sync_file fds, WAIT_FENCES, FENCE_TO_HANDLE, BO_LIST and
Linux's implicit-sync rules (model-tested against Navi22- and Navi48-shaped
engines). Fences poll with an IH notify hook;
register models cover encodings, rejection, timeouts and cancellation only.
Production cold boot now resets a posted card before any firmware stage, as
Linux does whenever the VBIOS left SOS running: PMFW (or PSP) mode1 reset,
PCI config restore including Resizable BAR sizes, then bootloader and MEMSIZE
waits. Without it the sequence would load SMC/graphics/DMCUB over the
VBIOS-started SOS and PMFW, a state Linux never initializes from.
`ResetOnInit` then posts as `amdgpu_device_need_post` does: when BIOS_SCRATCH_7
lacks ATOM_S7_ASIC_INIT_COMPLETE (after a mode1 reset, or on a never-posted
card; always after a recovery reset) it runs ATOM ASIC_Init from the retained
VBIOS through the stepped `amdgpu_atom_vm` (now with IIO programs, Linux's
sub-dword/SHL/SHR/MUL32/DIV32 semantics and cooperative DELAY sleeps) and
requires the bit afterwards; a GOP-posted card with the bit set is not posted.
`drivers/gpu/tools/atom-trace` replays ASIC_Init from a dumped ROM on the host.
OSSSYS 5.0.3 IH ring 0 now follows navi10_ih_irq_init with a VRAM ring
reached through VMID0, MSI-X/MSI delivery with polling fallback, and
overflow-safe task-context drains. It routes IVs to generation-tagged
subscribers that receive a terminal error on device loss. Boot enables it
after the memory hubs and proves delivery with an SDMA0 TRAP.
PMFW telemetry now uses the retained SMU11 table buffer (V1/V2 metrics by
PMFW version, Linux-checked layouts) and feeds a read-only hwmon node shared
with Navi48 (temperatures, fan, power, clocks); fan control stays automatic.
The SMU11 THM L2H/H2L, GPIO19 CTF and SMU-to-driver interrupts are armed and
handled as smu_v11_0 does, including the delayed SW CTF check and power-off.
Kernel-queue hang detection (2 s fence-progress timeout per ring) is active
and logging; mode1 device recovery with a full cold-boot re-init now runs
automatically after a hang (see the RX 6000 current-state entry; training
boots still refuse it).
GFXOFF, clock/power gating, memory/fabric DPM and deep sleep were disabled on
every default boot at this point (all are now requested by default; see the
RX 6000 defaults entry above). Linux's sequences for them are implemented and model-tested
(gfx_v10_0 MGCG/CGCG/3D CGCG under RLC safe mode, mmhub_v2_0/athub_v2_1/
hdp_v5_0/navi10_ih/sdma_v5_2/smuio CG with nv.c's navy_flounder flags,
`amdgpu_gfx_off_ctrl` GFXOFF with its 100 ms delay and disable references,
runtime PMFW feature bits, DCN3.0 PMFW watermark table, UCLK/FCLK floors). They
run for the features `amdgpu.rdna2_pg=` names (all of them by default) that the
policy admits. The native CS path now declares GC MMIO GFXOFF-safe;
GC clock gating needs only RLC safe mode; the watermark-dependent
features (hub CG/PG, memory/fabric DPM, deep sleep) follow the live DML30
admission of the native display, and the boot log names each refusal.
VCN 3.0 now starts both discovered instances after the fence stage (Linux's
static, power-gating-disabled path with PSP-loaded TMR images, VCPU reset
retries, decode/encode ring and IB tests, IH-routed fences) plus JPEG 3.0 with
a ring test; PSP loads one VCN image per unharvested instance (type 13/58)
from the discovery harvest table, and media failures leave the boot degraded.
While accel is on (the default; `amdgpu.rdna2_accel=0` disables it), VCN
decode/encode and JPEG are client IPs on the
generic CS path (`amdgpu_vcn_navi22_cs`): Linux's ring frames with a
ring-side MMHUB VM flush under the client VMID, `vcn_v3_0_dec_msg`
message checks, per-client decode sessions, JPEG `parse_cs` on a kernel
copy, IH-routed fences; HW_IP_INFO/COUNT and VIDEO_CAPS answer Linux's
values for the RX 6750 XT (VCN1 harvested). The Mesa recipe now builds
radeonsi VA-API and RADV Vulkan video; the amd-gl image carries vainfo,
ffmpeg, reference clips and `/mesa-amd-video.sh`. Register models only.
Navi22 display AUX/DDC/HPD is now native, as Linux drives DCN3.0
(`dc_is_dmub_outbox_supported` is false there): the DCE AUX engine with
`dce_aux_transfer_with_retries` policy, I2C-over-AUX, the hardware I2C engine
for HDMI DDC/SCDC, and HPD sense/filter/ack. After firmware readiness the boot
logs every board connector's HPD state and EDID. DMUB AUX/HPD is refused unless
explicitly allowed. Register models only; no physical EDID read yet.
A native DCN3.0 DML port (`amdgpu_dml30`) admits one unscaled linear plane
and derives DLG/TTU/RQ and HUBBUB watermark values, checked against host
vectors computed from the Linux DML30 formulas.
A native HDMI TMDS path (default; `amdgpu.native_display=0` keeps the GOP)
lights the first
connected HDMI sink on pipe 0 with a test pattern: DCN init, HUBBUB/DML30
deadlines, the DAL clocks and the VBIOS PixelClock/STREAM_SETUP/transmitter
tables (sent to DMCUB as `DMUB_CMD__VBIOS` commands while DMUB runs, as
DCN3.0's `dmub_command_table`; the `atom.c`-faithful interpreter is the logged
fallback), then fetch and unblank. Model-tested per block; never run on
hardware. HPD/AUX/DDC engines are armed with native display (the default) or
`amdgpu.display_probe`; SMU interface mismatches, a fused-off or hung DMCUB,
stuck HUBP blanks and ASIC_Init's S7 bit are logged, not fatal, as in Linux.
The lit pipe is presented natively: console/status publication with the
`scanout_access` withdraw-before-teardown contract, DCN3.0 HUBP VSYNC page
flips completed from EARLIEST_INUSE (pflip/vupdate IH sources armed), a
256x256 DCN3.0 cursor (default; `amdgpu.rdna2_hw_cursor=0` disables), KMS on the amdgpu card (DP-1..3, HDMI-A-1;
DML30-admitted modes, SETCRTC/atomic/TEST_ONLY, disable, vblank, flip
events) and a monitor that relights after GPU recovery. Register models only.
Navi22 HDMI 2.0 (`amdgpu_dcn30_hdmi`): TMDS above 340 MHz scrambles (1/4
clock channel) after Linux's `write_scdc_data` (SCDC over native DDC; legacy
TMDS_Config 0 on every SCDC sink at enable and disable/unplug), opt-in 10/12-bpc
deep colour (`amdgpu.max_bpc`, FMT SPATIAL8/10 dither), YCbCr 4:2:0 for
Y420VDB/CMDB modes (OTG container, FMT, YCbCr709 OCSC, DPG black), Broadcast
RGB limited (OCSC), CTA VIC/HDMI-VIC vendor InfoFrames and HDMI_6GB_EN from the
VBIOS encoder caps. Register/DDC models only.
Navi22 multi-display (`amdgpu_navi22_multi`): up to four KMS CRTCs light as
one DC context — joint DML30 admission of every stream (`plan_joint`, at the
lowest supporting UCLK state; 234 host vectors from Linux's own DML30 C,
single/multi-stream, cursor, ODM, DSC), clocks and watermarks once, PHY PLL
sharing for identical HDMI timings, ODM 2:1 where one pipe cannot carry a
stream, DSC with FEC on DP SST (`amdgpu_dcn30_dsc`, training through the
shared DP link layer) and 8b/10b DP MST through the shared sideband manager
(`amdgpu_dcn30_mst`). Secondary CRTCs route automatically only with
`amdgpu.rdna2_multi` (still opt-in); only CRTC 0 presents (the others show
static scanouts).
Register models only; never run on hardware.
For bare-metal runs, `cargo xtask usb-image` builds a UEFI stick whose kernel
appends its log to `/narf-boot-<n>.log` on that stick (`narf.bootlog=`,
marker-gated, USB-only, bounded) and boots with `narf.disks=boot-only`: every
other disk is read-only at the block layer (writes refused, logged once) and
skipped by the boot-time mounts, and ext/btrfs mount a read-only device without
any repair or log-replay write (`usb-image --qemu` hashes decoy NVMe/SATA disks
before and after). NVMe I/O now builds PRP lists up to the controller's MDTS,
so the host's standard 128-entry GPTs are partition-scanned, and AHCI binds by
class (`01:06:01`, the AMD 600-series `1022:43f6`) with Linux's HBA
save/reset/restore and per-port COMRESET bring-up; both stay read-only under
`boot-only` (AMD AHCI untested: QEMU has only ICH9). A secondary card's cold boot keeps the iGPU
console live and ends with a per-stage summary (see
[docs/BOOTING_ON_CACHYOS.md](docs/BOOTING_ON_CACHYOS.md#rx-6750-xt-bring-up-boot)).
DCN3.0 HDMI and DP SST LPCM audio (`amdgpu_dcn30_audio`) follows Linux DC
(`dce_audio.c`, `dcn30_afmt.c`, `enc3_se_*_audio_*`, `dce110_*_audio_stream`):
audio wall-clock DTO0/DTO1, AFMT/ACR, the Audio InfoFrame and the Azalia
endpoint ELD from the EDID, behind a start-after-unblank / stop-before-blank
hook. The HD-Audio side binds 1002:ab28 (ATI HDMI NS, no snoop); a model of
the host's six-port R6xx HDMI codec (rev 0x100800) checks that endpoint `e`
reports jack and ELD on pin `3 + 2e` and routes playback there. Register
models only.
Mesa 26.2.4 radeonsi + RADV (ACO-only, llvmpipe fallback kept) now builds
reproducibly for NARF's musl userspace and stages into a rootfs; the
`mesa-amd-smoke` passes inside NARF under QEMU with no AMD GPU (clean
decline, software fallback renders) and the same binaries render on a Linux
amdgpu host ([Mesa AMD](docs/MESA_AMD.md)). libdrm_amdgpu's `GET_CLIENT` on
primary nodes is the first NARF gap Mesa hits.
The firmware path now follows Linux on the GOP-booted (SOS not alive) cold
path: KM-type PSP rings on every PSP generation, LOAD_TOC → SMC → SETUP_TMR
(PMFW-centralized C-states), DCN3.0's own FB register offsets, Linux's GART
placement at MC 0 (12272 MiB VRAM model), MEMSIZE-derived FB end, tolerated
GOP VMID0/DMUB windows/stopped-OTG pipes, an MP1 firmware-ready poll, Linux
(or longer) PSP/SMU/training deadlines, warn-only PSP status, golden settings
before SDMA plus the GC 10.3 power brake, and a non-fatal DMUB start after the
queue stages using the GMC aperture.
These were software-tested foundations. User command submission, media
submission, display-aware DPM gating and DCN3.0 modesetting have since landed
(register and fake-engine models only); GDDR6 training resume, VCN dynamic
power gating (DPG) and any hardware boot remain open. See the
[PCIe probe contract](drivers/gpu/specification/spec.md#amd-discrete-pcie-probe-and-vram). The native path now follows Linux's global order end to end (model-tested over one combined register fake, failure/cancellation per step), retires a live GOP stream like `dcn30_init_hw`, enables OPTC/OTG clocks, lights DP SST (native-AUX 8b/10b training with fallback, DP DTO, MSA/VSC) on any of the six pipes/routes, and quarantines underflows black. HPD/HPD_RX now arrive over the IH ring (DCE src 9) and wake the display monitor, with polling kept as the fallback. Native Rust tests check documented Navi22 identity, register/discovery, firmware-layout and ownership contracts using fixed reference inputs. Historical source citations remain provenance rather than an executable Linux-conformance claim. The DP link layer now follows Linux DC (`amdgpu_dcn30_dp_link`): capabilities with LTTPR transparent/non-transparent modes per the VBIOS DCE_INFO bits, TPS3/TPS4 by sink capability, adjust and post-LT adjust requests, destructive link verification with Linux's fallback order, the least verified link per stream, and DP modes in KMS bounded by the verified link; the monitor tears an unplugged display down without AUX, re-detects on HPD changes (dark connectors keep their EDID inventory), and retrains on HPD-RX/polled link loss. Register/AUX models only.

1. **Stage 5 laptop proof:** boot from USB on Renoir/Lucienne or Phoenix
   HawkPoint1; exercise native AMDGPU modeset, keyboard and touchpad,
   Wi-Fi, and persistent NVMe storage. AMDGPU, ACPI EC, I²C-HID,
   wireless, TSC calibration, and framebuffer diagnostics have foundations
   in-tree, but the complete gate remains open.
   The iwlwifi Sc/BE211 work now includes an MLD station path with owned
   firmware/PNVM boot DMA, RFH receive rings, command/data TX queues,
   MSI-X completion delivery, active/passive scans, Open/WPA2-PSK association,
   CCMP replay protection and pairwise/group rekey, WMM/four AC rings,
   HT20/40 and VHT20/40/80 negotiation (up to two spatial streams),
   firmware rate adaptation and TX A-MPDU completion, RX Block Ack
   negotiation/reordering, standalone RX A-MSDU deaggregation,
   TX queue backpressure, and kernel Ethernet
   routing. Software regressions cover wire layouts,
   malformed completions, DMA ownership, authenticated EAPOL retries,
   channel-span limits, BA sequence wrap and replay checks after reordering.
   Delegated nl80211 scan/connect controls and signed deployment regulatory
   policy loading are wired in, with build-time public-key provisioning
   and detached-signature firmware packing. Explicit network-service launch
   now delegates interface authority before the process runs, including to
   its ordinary netlink sockets and forked children, while preserving IP
   frame ownership. Boot service selection, silicon validation and real
   supplicant interoperability remain open. See
   [the implemented driver contract](drivers/wireless/specification/spec.md#31-implemented-iwlwifi-mld-station-profile).
2. **Compatibility and desktop:** extend tested Linux ABI and graphical
   application coverage on QEMU. Use runnable cases in
   [docs/DESKTOP_LINUX_PLAN.md](docs/DESKTOP_LINUX_PLAN.md) and the feature
   boundaries in [docs/PERSONAS.md](docs/PERSONAS.md), rather than treating
   the Stage 4 shell result as full Linux compatibility.
3. **Isolation validation:** run PCID and real-device cross-domain tests on
   capable hardware, and complete the non-MTE aarch64 fallback if that
   platform is to claim enforced domains. The backend-specific limitations
   are recorded in [docs/DOMAIN_BACKENDS.md](docs/DOMAIN_BACKENDS.md).

## Reproduce the main checks

```sh
cargo xtask run --arch=x86_64
cargo xtask run --arch=aarch64
cargo xtask test --arch=x86_64
cargo xtask test --arch=aarch64
cargo xtask run-interactive --arch=x86_64 --cmd "echo hello world" --expect "hello world"
cargo xtask musl-demo --arch=x86_64
cargo xtask iso-boot --arch=x86_64 --release
```

The musl demo cases may need generated binaries and rootfs images; see
[docs/RUNNING_ON_LINUX.md](docs/RUNNING_ON_LINUX.md) and the scripts under
`verification/data/musl-demo/`. For build, formatting, and review gates,
follow [process/specification/spec.md](process/specification/spec.md).
