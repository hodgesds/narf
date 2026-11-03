# ath9k — Specification

> Status: **AR9285 retained channel1 legacy station and optional measured
> HT20/1SS long-GI, RX STBC1, native RTS/CTS protection and recipient BA
> continuations implemented.** Native software functional validation passed in
> the coordinated x86_64 and aarch64 scoped Wi-Fi suites. Physical EEPROM,
> calibration, RF and DMA
> acceptance remains pending. Wider bandwidths and other chips are separate.
> The channel1–13 cold-generation continuation (§3.5) is source-complete; its
> six new native cases have not run. Its coordinated seven-package release
> Clippy/module checks passed before the separate full20/40 draft.
> The distinct measured full20/40/SGI40 continuation (§3.6) is source-complete
> with another six native cases written; coordinated release Clippy passed,
> while native validation remains pending.
> The additional bounded two-MPDU sender BA/A-MPDU continuation below is
> implemented with ten new native smokes passing the coordinated validation
> on both architectures. AR2427 (`168c:002c`, AR9285 silicon with HT bonded
> out) shares the legacy owner with every HT/BA source closed.
> The optional measured `N85Q` continuation (§3.4) adds four-AC EDCA on
> QCU0..3 and eight-TID classification/scheduling on the same owner.
> Distinct N85T4 larger3–8-member sender programs (§3.7) are source-complete;
> seven new native cases, release compilation and physical acceptance are pending.

## 1. Purpose & scope

The currently matched PCIe parts are AR9285 (`168c:002b`) and AR2427
(`168c:002c`), Linux's AR9285 silicon with 802.11n bonded out. Broader ath9k
families are not implemented merely because Linux supports them.
This is a soft-MAC radio: unlike ath10k it does not use a downloadable
WLAN firmware to supply MLME and hardware programming.

## 2. Assumptions

The PCI dispatcher grants exclusive function authority. Probe verifies
inherited bus mastering and memory decoding are off with INTx masked.
BAR sizing/mapping runs within the capability invocation while decoding
is off; verified memory decoding is enabled after BAR restoration. The
device-typed BAR0 covers registers through `0xd387`.
AR9285-specific writes follow a checked silicon revision.

## 3. Public interface

**Software acceptance at `6813a24c6`.** The admitted `additional_channels`,
`channel_retuning`, `ht40`, `sgi40`, `larger_tx_aggregates`,
`factory_profile_selection`, `station_network_sleep` and
`periodic_calibration` continuations pass the checkpoint release/native gates
on x86_64 and aarch64. Idle FULL_SLEEP and other chips receive no acceptance
here. This supersedes implementation-time statements below that release/native
execution or software acceptance is pending, only for the named feature
scopes. Physical measurements, signed board/deployment programs and
actual-device RF/power/interoperability acceptance remain separate.

- `register()` installs the AR9285 (`ath9k`) and AR2427 (`ath9k-ar2427`)
  PCI matches; `ar9285_silicon()` is the shared exact vendor/device gate.
  Linux `hw.c::ath9k_hw_init` accepts `AR2427_DEVID_PCIE` with the same
  AR9285 silicon revision, `eeprom_4k.c` map and AR9002 reset/INI path, and
  `hw.c::ath9k_hw_fill_cap_info` clears `ATH9K_HW_CAP_HT` for that ID only.
  AR2427 therefore runs the identical probe, calibration, legacy packet and
  station owner, while `ht::Facts::new` (and thus every HT20, RX STBC, RX BA
  and sender BA grant) admits only `0x002b`. The bound-driver record names
  `ath9k-ar2427`. Smokes `smoke_ar2427_bonded_out_ht_never_reaches_measured_facts`
  and the two-ID `smoke_ar9285_native_packet_revocation_precedes_config_dma_and_mmio`
  cover the gate. Physical AR2427 acceptance is pending like AR9285.
- `probe()` reads the complete factory calibration image after Linux's
  bounded power-on/warm-reset sequence. It retains the controller instead
  of constructing and immediately discarding an `Arc`.
  It reads the upstream bridge's existing ASPM policy through the current
  child device capability and applies AR9285 device-local SerDes/WA/PM
  workarounds only when L0s/L1 is enabled. Reset/resume repeats that
  discovery; the retained D0 obligation supplies the D3 workaround half
  after cold reset and before FULL_SLEEP during system suspend. Neither
  endpoint nor shared-bridge Link Control is changed.
- `with_controller()` provides read-only `Ath9k` inspection; it returns `None`
  while the retained async mutex is busy. Address ownership remains retained
  independently of that inspection lock, including after a failed probe.
- `Ath9k::identity` exposes the silicon revision, validated unicast MAC,
  EEPROM version, factory regulatory-domain values, and chain masks.
- `Ath9k::calibration()` exposes the complete 376-byte normalized
  `ar5416_eeprom_4k` image for later PHY calibration programming.
- `Ath9k::baseband` reports `BasebandPrepared`: initially the 2412 MHz
  reference, then the exact selected channel after a cold retune, with the selected EEPROM high-power gain/SYNTH9 XE2 variant and count
  of programmed INI rows. Successful preparation also applies normalized
  EEPROM modal/RF board values, the interpolated detector/PDADC table, and
  legacy20 CCK/OFDM/HT20 target-power registers limited by factory CTL and
  an explicit zero-dBm ceiling.
  It includes native 20MHz mode/timeout overrides, single RX/calibration/TX
  chain masks, RF mode, frequency-dependent delta slope and EEPROM spur
  filtering/mask programming after the full INI tables.
  It records inactive register preparation, not channel authorization or
  a calibrated/operational PHY.
- Errors distinguish absent/mismatched silicon, timeout, invalid EEPROM
  magic/length/checksum/version, invalid factory identity and
  `BadCalibration` for malformed or unusable detector intercepts, target
  power piers, CTL edges or unsupported factory regulatory identity.
  `Policy` rejects missing/unqualified live channel permission and `BadState`
  rejects an active engine or a repeated calibration attempt.
- `calibrate_radio()` initially continues channel1/full-rate/20MHz; cold
  retunes repeat the same complete chain for the selected channel (§3.5).
  Probe queues the same retained owner in executor context and drives background
  provisioning via `drive_scheduled` across 120 attempts with 500 ms intervals. It obtains the
  shared authenticated regulatory policy, requires `trusted_net_authority`, intersects every overlapping rule
  and the full occupied span, and requires the initial nonnegative budget
  (at most20dBm) with no DFS/indoor-only qualification assumption. Factory
  CTL, target powers and antenna reduction constrain every written rate before
  PHY activation. Provisioning failures before the attempt leave it retryable;
  a started, failed or dropped attempt cannot be replayed or replaced without
  an independently proved reset.
- `Ath9k::radio_state()` reports `New`, `Running`, `Ready` or `Failed`;
  `radio_calibration()` returns country, frequency and selected host ceiling,
  native PA offset, IQ correction and measured/sanitized noise floor only
  after all phases complete. Those diagnostics do not bypass the later
  packet owner. No factory key, country or transmit budget
  is inferred from an unauthenticated AP.
- The same retained calibration owner continues through MAC/PCU preparation,
  complete hardware-key-cache clearing and owned non-EDMA TX/RX allocation.
  `calibrate_radio()` can continue an already `Ready` calibration receipt when
  packet preparation has not started; it never replays a partial packet attempt.
  Native allocation and register/configuration access execute inside current
  PCI capability invocation. Unsupported per-domain IOMMU mappings are refused.
- The retained `station::Radio` and its `interface::Device` implement the
  public wireless/netdev paths without replacing the packet owner. The initial
  profile is channel1/2412MHz, 20MHz, negotiated legacy CCK/OFDM, Open or
  WPA2-PSK/CCMP with host MLME/RSNA/crypto. Entropy failure rejects authentication.
  Original observed RSN/RSNX bodies reach shared security admission. Carrier,
  controlled-port state and exact native terminal TX receipts precede kernel
  DHCP and Ethernet/IP delivery. The exact transmitted M4 bytes must match
  the retained reply before key/port commit.
- Legacy DATA rates cover the actual association-response intersection from
  1 to 54 Mbps. Management/EAPOL use the lowest negotiated basic bitrate;
  probe requests retain their driver-owned 1 Mbps discovery rate. Bitmap
  order is never substituted for bitrate order (OFDM6/9 lie below CCK11).
  Unicast DATA programs up to four distinct descending native retry series,
  per-series packet durations, single-chain selectors and factory-limited
  power fields. Only exact terminal descriptor/queue-idle receipts train the
  retained adaptive controller. A native fallback selects the actual final
  rate, failure lowers it and eight clean native DATA receipts probe the next
  supported bitrate. FIFO/filter/descriptor/TXOP conditions supply no RF-rate
  evidence. Invalid/unprogrammed FinalTxIdx or modified descriptors close the
  owner; pending/RX/security receipts cannot train it. This provides no HT,
  aggregation or performance measurement claim for the legacy profile.
- The facade advertises four active-scan SSIDs and no caller probe IEs.
  Directed binary SSIDs and wildcard discovery use actual broadcast Probe
  Requests through the same calibrated descriptor/DMA owner. Empty active
  input becomes one wildcard; SSIDs are bounded to 32 bytes before I/O.
  Driver-owned CCK/OFDM rate and the actual current channel elements precede
  publication. Each
  probe waits for its exact native terminal TX completion within the total
  bounded dwell; broadcast completion does not claim an over-air ACK.
  Current signed policy, PCI authority and RF-silent input constrain every
  publication. Discovery is limited to unassociated generations; §3.5 adds
  real cold retunes for multi-channel scans. Scans while associated return
  Busy without changing carrier. Failure or
  cancellation hides the partial cache, closes the owner and retains DMA.
- Synchronous bounded packet progression services polled RX/TX with hardware
  IRQs masked unless MSI or optional source-qualified station PS is active. Every transmit rechecks current signed policy and factory
  RF-silent GPIO state; metadata and packet publication share terminal closure.
  Disconnect, cancellation, peer loss, policy loss or ambiguous completion
  closes the initial profile permanently and retains every published mapping.

### 3.1 Optional AR9285 revision2 HT20 continuation

The same retained non-EDMA owner can opt into channel1/2412MHz HT20, one
stream, MCS0..7 **long GI only**. The implemented INI recipe is AR9285_1_2;
this new profile requires silicon revision2, full376-byte checked EEPROM,
11G capability, the EEPROM N_2G_HT20 disable flag clear and RX/TX chain1.
AR9285 has no SGI20 hardware capability: the AR9002 descriptor GI bit does
not establish one. Local RX and hardware TX both retain mandatory MCS0..7;
the measured record may narrow actual TX selection independently. Local RX
STBC1 follows Linux `common-init.c::ath9k_cmn_setup_ht_cap` for AR9280-and-later
silicon, including AR9285; single-chain TX STBC remains disabled. Native RX
STBC admission requires the actual AP's TX_STBC in both the observed offer
and successful association response. AP RX_STBC alone supplies no such
proof. The optional coding is bound into the exact new qualification identity
and opaque driver profile; no caller flag enables it. No LDPC, greenfield,
HT40 or TX A-MSDU is enabled. The separate recipient BA continuation is §3.2;
TX BA remains absent.

`Ath9k::ht20_qualification_request()` exposes the exact factual `identity`,
`mac` and external `filename` after the completed one-shot calibration.
It grants no emission. The identity hashes chip/subsystem/revision, complete
normalized EEPROM and chains, selected INI/gain/SYNTH9 recipe, actual retained
calibration results, the seven actual power-register words, local capability,
descriptor/padding/rate/duration/queue recipe and static operating envelope.
The identity includes directional RX_STBC1 and native RTS/CTS trains; an
older recipe's signed measurements cannot authorize these additions.
The optional external file is
`ath9k/ar9285-ht20-v1-<twelve lowercase MAC hex digits>.bin`, opened through
the trusted signed-asset loader. No such binary, signature or measurements
are supplied by this codebase. Unlike other families, ath9k had **no measured
legacy emission grant** to extend; this is a distinct new `N85H` contract
layered on the actual EEPROM, calibration and current regulatory policy.

The little-endian160-byte v1 signed body is:

| Offset | Field |
| --- | --- |
| 0 | `N85H`, version:u16=1, header length:u16=160, total length:u32=160 |
| 12 | PCI vendor:u16=0x168c, device:u16=0x002b |
| 16 | Exact request SHA-256 identity[32] |
| 48 | Factory MAC[6], primary:u8=1, width:u8=20, chain:u8=1, GI:u8=0 |
| 58 | Antenna upper bound:i16 half-dBi, signed board EIRP ceiling:i16 half-dBm |
| 62 | Nonzero selected TX MCS0..7 bitmap:u8; reserved:u8=0 |
| 64 | Twenty-one measured conducted upper bounds:i16 half-dBm: global/calibration/retry/transient maximum, twelve legacy rates in driver bitmap order, eight HT MCS0..7 LGI rates |
| 106 | Reserved[54]=0 |

The signed antenna bound cannot undercut the retained factory antenna gain.
The signed maximum must cover every per-rate peak. Every peak plus antenna
upper bound must fit the signed board ceiling and every overlapping current
host rule; the original calibration ceiling/country must still fit as well.
The signer attests the **complete static temperature, supply, antenna/posture
and Bluetooth envelope**, including calibration, responses, retries and mode
transients; an initial temperature sample or EEPROM target table is not such
a measurement. Periodic tracking is not inferred. Asset cap invocation and
current PCI/domain/RF-silent checks surround actual native accesses. Power,
HT20/chain, key-cache-invalid, FIFO/workaround and IRQ-mask readbacks precede
profile activation and remain checked at emission/publication boundaries.

An absent optional record can be installed after legacy packet preparation;
the same native owner loads it before HT association. A retained grant is
never replaced after revocation. Missing/invalid qualification permits legacy
fallback only before any new live HT/EDCA program. A partial new program,
authority loss or ambiguous receipt closes the owner and retains DMA.

Driver-owned shared `LocalHt` facts admit the HT membership selector only
through actual observed HT Capability/Operation and driver-owned WMM
Parameter facts. The association request carries generated HT/WMM bytes;
caller PHY/WMM IEs remain rejected. The actual successful response must fully
validate/narrow HT primary/operation/basic MCS and WMM BE before queue/profile
commit. Secondary channel, BE ACM, U-APSD, unrepresentable CW and nonzero BE
TXOP are refused. Queue0 programs and
reads back source AIFS/CW/zero-TXOP fields; other queues remain parked.

All three nonzero HT protection modes and actual ERP Use_Protection can
use native RTS/CTS. The opaque driver profile combines the actual offer and
successful response; protection required by either cannot disappear because
the other omits it. ERP is singleton, exactly one byte, with reserved bits
clear. The bounded first profile requires a negotiated CCK basic control
rate for protected exchanges, retaining long preambles for non-ERP members.
Every HT DATA descriptor sets AR_RTSEnable and its enabled rate series'
AR_RTSCTSQual with the actual packet duration and negotiated control-rate
code. Hardware forms the RTS/CTS NAV; no fabricated software exchange or
simultaneous CTS-only flag is used. Actual RTS exhaustion is failed DATA,
never an authenticated success. Native SIFS/slot/ACK/CTS/microsecond timing
and immutable descriptors remain checked at capture and receipt boundaries.

Later complete native beacons/probe responses from the current AP can add
protection conservatively; it stays required until terminal association
teardown. Foreign peers cannot change this profile. A native descriptor
already owned by hardware remains immutable through a beacon update; only
later submissions use the updated protection. An incompatible current PHY,
BE contention, malformed bound advertisement or unsupported timing program
closes the owner and retains DMA. Beacon updates never widen the original
response-bound MCS/coding profile or independently reopen a controlled port.

HT DATA forms the original26-byte BE/TID0 QoS header **before** software
CCMP. The descriptor uses hardware rate0x80..0x87, native long-GI HT duration,
one chain, no width/GI/TX-STBC/aggregation/crypto offload and a bounded fixed
selected MCS series. Legacy management/EAPOL/ADDBA responses retain actual
negotiated basic rates. Native DMA inserts exactly two transport bytes after
the original QoS header; BufferLen includes them while FrameLen/FCS and
duration exclude them. Immutable original and DMA bytes are retained and
checked through terminal TxDone, ACK and queue-idle proof.

RX validates the actual HT rate, width/GI/STBC/status, complete one-buffer
extent and original ciphertext before removing only native header padding
and four FCS bytes. AR9002 RX status3 bit3 reports STBC; it is accepted only
for MCS0..7 with the source-bound and response-bound RX_STBC1 profile.
Legacy rates cannot carry STBC metadata. SGI20, extra streams, split buffers,
A-MPDU flags outside §3.2 and
delimiter errors remain rejected before CCMP/PN. The existing4092-byte RX
allocation holds the whole3839-byte A-MSDU plus header, pad, CCMP and FCS.
The complete aggregate is authenticated once before atomic bounded subframe
decoding/PN commit, with current PTK/GTK identity and all16 TID replay
windows. Open aggregates require the protected bit clear and the same native
peer/header/controlled-port bounds. No subframe supplies EAPOL/control or an
unauthenticated prefix. Native Category3 immediate ADDBA requests receive
an exact status37 decline through actual legacy DMA/ACK/idle receipts;
enqueue alone creates no delivered response or BA agreement.

Native capture records receive-time data admission. Ciphertext seen before
M4 or during a pending key reply cannot acquire authorization from a later
receipt and does not advance PN. Actual `ReplyReady`, terminal key receipt
and close retire decoded/queued data and monotonic receive epochs. Fresh
current source/policy/port/epoch checks gate IPC allocation/publication and
each unlocked stack callback, including a fully reopened rekey between two
callbacks. Initial authorization precedes carrier; an established rekey
preserves physical carrier while withholding DATA. Ordinary pending TX
credit does not close receive authorization. All radio/state/ring/publication
locks are released before actual stack callbacks. The IRQ-masked1ms service,
NULL tail/buf_hold and published mapping retention remain unchanged.
Fresh RX continues while an ordinary native DATA TX owns its descriptor;
ADDBA replies wait for that credit, and an actual EAPOL rekey can immediately
close receive and retain its reply until the DATA receipt frees native TX.
Open QoS DATA has independent TID sequence counters, including wrap;
management/ADDBA replies do not consume them. Secured QoS uses the shared
per-TID sequence owner preserved across key replies.

### 3.2 Optional native recipient block acknowledgment

`Ath9k::rx_ba_qualification_request()` derives a second factual request from
the same retained HT owner. The external
`ath9k/ar9285-rxba-v1-<MAC hex>.bin` signed `N85B` record binds the exact
`N85H` request **and complete signed-body digest**, actual board identity,
RX BAR filter, original-MPDU reorder, native PPDU/ADDBA/DELBA/timer recipe,
and the same20MHz/one-chain/long-GI bounds. No asset or measurements are
checked in. Missing/invalid optional BA qualification retains the actual
status37 decline. Once a valid source is retained it cannot be replaced
after revocation. Software allocations precede the first new live program;
the source `COMP_BAR` RX filter changes from0x17 to0x417 with exact readback,
and every later native operation/publication invokes current source/policy.

The96-byte little-endian v1 body contains `N85B`, version:u16=1,
header length:u16=96, total length:u32=96; vendor/device:u16 at12;
request identity[32] at16; MAC[6] at48; primary1/width20/chain1/whole-A-MSDU
flag1 at54; measured global conducted response/transient maximum:i16
half-dBm at58; maximum window:u8 in1..64 at60; reserved0 at61; signed
EIRP ceiling:i16 half-dBm at62; reserved[32]=0 at64. The measured maximum
plus the retained HT antenna bound must fit both signed ceilings and every
current overlapping host rule. All calibration/legacy/HT and static-envelope
requirements of `N85H` remain independently required.

Linux `ath9k/main.c::ath9k_ampdu_action` performs no RX_START/RX_STOP
hardware programming; host BA state is therefore explicit. Linux `recv.c`
also documents MAC block acknowledgments as frames enter the FIFO/host.
**A software decline or discarded aggregate does not prove absence of an
automatic hardware BA emission.** The `N85H` all-response maximum must cover
automatic responses even to unsolicited traffic; `N85B` additionally binds
the negotiated/BAR-filter/DELBA continuation. The existing NULL tail and
delayed descriptor reuse are preserved, never self-linked to fake capacity.

An actual bound immediate ADDBA request supplies dialog/TID/window/SSN and
TU inactivity. Requests above the HT64-MPDU maximum are declined; window0
uses the qualified default and a smaller measured maximum narrows the actual
response. No invented initial sequence is used. An exact native response
ACK plus queue idle and a fresh RX-idle fence precede activation. A pending
proposal can stage at most64 opaque originals against its explicit SSN and
captured receive epoch, only after the proposal and while the controlled port
was already open. Neither crypto/PN nor delivery occurs before the positive
receipt; DELBA, key/epoch/source loss, failure and cancellation discard the
stage. Pre-M4, closed-port and pre-proposal captures are never staged. This
preserves a legitimate first burst queued before the1ms worker sees TX ACK.
A duplicate
unchanged request may receive another success without resetting sequence,
buffers or timer. A changed live request is declined until explicit teardown.

Sixteen heap-backed TID owners hold at most64 complete original MPDUs each.
Twelve-bit half-range comparison handles wrap, duplicates, old frames,
bounded future-window movement and native compressed single-TID BAR.
Only ordered original MPDUs enter CCMP/PN/A-MSDU admission. Native AR9002
rate/width/GI/STBC/error status is validated on every descriptor, consistent
with Linux's per-MPDU preprocessing. FIRST/MORE aggregation context must
match current unicast peer/TID/rate/STBC coding, at most8191 captured MPDU/FCS/delimiter
bytes,64 MPDUs and100ms of retained context. This is a bounded host admission
extent, not an invented total-PHY-length field for unreported null delimiters.
Missing/invalid/closed-port descriptors retire that context; no stale PHY or
header is supplied to a later orphan member. Split buffers, HT40, SGI20,
extra streams, delimiter errors and unsupported crypto images remain closed.
The whole3839-byte A-MSDU can compose with A-MPDU only when the actual
ADDBA request/response enables it. Normal ACK and unicast BlockAck policy
use the original header; the explicit shared BlockAck aggregate method is
called only with a still-live native session-generation/order proof.
Multicast normal-ACK GTK traffic retains the existing independent path.

Native progress/idle drives100ms reorder-hole release. Nonzero inactivity is
exactly `timeout * 1024us`; valid current-TID data and BAR refresh activity.
Expiry drops the session/buffered originals and queues a recipient DELBA
(initiator0, reason39). Its actual legacy native descriptor, ACK, queue idle
and RX idle retire the teardown ticket before replacement. Timers are serviced
by the existing1ms worker rather than a claimed IRQ path. Current policy,
power/readbacks and both signed sources still gate descriptor/copy/doorbell,
receipt and final publication. Pending key replies take priority; CPU teardown
ownership survives the held reply without authorizing DATA. Incoming peer
DELBA, key replies, peer loss and terminal close retire opaque ownership;
key replies preserve the actual protocol sequence head while dropping buffers.
No timer, Drop or cancellation implicitly delivers buffered data.

This recipient continuation creates no TX BA or native TX A-MPDU; §3.3
provides that separate measured sender owner. No delayed BA,
multi-TID BAR, NoAck/NoExplicitAck, fragment, hardware-decap or extra QoS AC
profile is inferred. Original/decoded receive queues remain bounded to256;
resource failure closes the owner and retains native mappings.

### 3.3 Optional measured two-MPDU sender BA/A-MPDU

`Ath9k::tx_ba_qualification_request()` returns factual `identity`, `mac`
and external `filename`, without granting emission or an agreement. The
distinct `ath9k/ar9285-txba-v1-<twelve lowercase MAC hex digits>.bin` is
required before initial sender authorization. No asset, signature or measured
RF value is supplied by this implementation. Its request hashes the exact
`N85H` request and signed-body digest, chip/calibration/power/antenna facts,
the two-original descriptor/delimiter/duration recipe, control/retry/BAR/DELBA
proofs and full static envelope, including automatic responses. Neither
`N85H` nor recipient `N85B` alone authorizes this transmission train.

The signed little-endian96-byte v1 body has: `N85T`, version:u16=1,
header:u16=96, length:u32=96 at0; vendor:u16=0x168c/device:u16=0x002b at12;
exact request identity[32] at16; MAC[6] at48; primary1/width20/chain1/member
count2 at54; measured all-train conducted peak:i16 half-dBm at58; maximum
window:u8=4..64 at60; software retry bound:u8=3 at61; board ceiling:i16
half-dBm at62; reserved[32]=0 at64. The peak plus the base antenna bound
must fit this ceiling, the base ceiling and every current overlapping host
rule. Both immutable source caps and current native power/timing/PCI/RF-silent
proof remain required. Missing qualification keeps ordinary unaggregated HT;
revocation after binding is terminal rather than a quiet profile fallback.

One sender agreement owns BE/TID0. The driver freezes its producer and reads
the actual next shared QoS sequence, or the independent Open counter, for
its genuine ADDBA SSN. A fresh nonzero dialog, native request ACK/queue-idle
and RX-idle fence, and a complete bound AP response precede activation.
Foreign/partial/wrong-dialog/TID/policy/window responses create no session.
Declines retain single-MPDU HT. An accepted window below4 receives an actual
initiator DELBA before that fallback. Setup and BAR recovery have bounded
100ms deadlines; nonzero negotiated inactivity is exactly TU*1024us and
produces native sender DELBA(initiator1, reason39). Ambiguous control failure
closes the owner. No implicit success is inferred from enqueue or Drop.

The existing two retained payload maps and two descriptors form one real
two-MPDU aggregate when two valid IPC packets are already available. A lone
packet remains ordinary normal-ACK and unaggregated; no timer fabricates a
second member. Each original QoS header and separate CCMP PN/ciphertext is
formed before transport pad2. FIRST links to the actual tail; tail links to
NULL. FIRST owns rate/retry/duration, IsAggr|MoreAggr, aggregate length and
padding delimiters; LAST has IsAggr with zero rate/retry/duration words.
On-air lengths include each FCS and delimiter, preceding-member alignment
and actual padding, excluding DMA pad2 and final-member padding. Linux's
256-byte minimum and conservative AP density bind padding; AR9285 retains
ent_mode0 and has no later-silicon OTP first60-delimiter quirk. The current
bound is two original frames<=1550 bytes each,4095 aggregate air bytes and
4ms HT PPDU, with actual offer/response factor/density narrowing. LGI20,
chain1 and MCS0..7 remain enforced; no SGI20/TX STBC/LDPC is inferred.

Only actual tail TxDone plus queue idle releases either DMA map. Both
original padded payloads and immutable descriptors are checked first.
Actual BAflag, returned TID/SSN and64-bit bitmap prove each acknowledged
original separately; wrong-TID status retries all, following the documented
hardware erratum. TxOK without BA is the source STA deaf/mute failure and
closes the owner. Missing originals get at most three software retries as
normal-ACK single MPDUs, preserving SC/PN/ciphertext and changing only Retry.
Exhaustion retires their CPU retry authority and sends an exact20-byte BAR
to the real next sequence before any new data is admitted.

BAR recovery uses its own native TX descriptor: terminal TxDone, successful
transmission, BAflag, expected TID0, exact returned BA SSN, queue idle and a
fresh RX-idle fence. Linux `ar9002_hw_proc_txdesc` parses BA fields for every
completed descriptor; BAR follows the normal TX-status path. No solicited BA
is assumed to appear as RAW RX under COMP_BAR. No CONTROL/COMP_BA filter is
invented; the existing0x17/recipient0x417 filters remain unchanged. Missing or
wrong native BAR proof leaves the window closed. Physical qualification must
confirm these actual BAR status fields on the target AR9285.

Key replies retire software retry authority and force current-epoch BAR
recovery while preserving the actual MAC agreement and in-flight DMA owner.
Late pair/retry/control receipts cannot authorize a successor epoch. Current
shared `Security::port_open`, including intentional old-key WaitM3 operation,
remains authoritative independently of physical carrier. Peer DELBA, close,
cancel, source loss and uncertain tail never recycle published storage or
fabricate bitmap/delivery. Open/WPA2 native fixtures consume genuine action,
two-map DATA, partial retry and BAR descriptor traffic, including real kernel
DHCP/IP bursts and coexistence with the separately qualified recipient BA.
The ten new cases passed in the coordinated scoped Wi-Fi suites: x86_64
2360 pass,0 fail,9 skip; aarch64 1890 pass,0 fail,3 skip. Production boots and
all btrfs postflights were clean. Physical N85T/BAR qualification remains open.

### 3.4 Optional measured four-AC EDCA and eight-TID scheduling

`Ath9k::qos_qualification_request()` returns factual `identity`, `mac` and
external `filename` (`ath9k/ar9285-qos-v1-<twelve lowercase MAC hex
digits>.bin`) derived from the retained `N85H` grant; it grants nothing and
no asset or measurement is checked in. The request hashes the exact `N85H`
identity and signed-body digest, the classification/downgrade rules, the
QCU/DCU recipe, the single-in-flight host scheduler and the full static
envelope including every AC's contention, retry and automatic-response peak.

The little-endian 96-byte v1 body has `N85Q`, version:u16=1, header:u16=96,
length:u32=96 at 0; vendor:u16=0x168c/device:u16=0x002b at 12; request
identity[32] at 16; MAC[6] at 48; primary1/width20/chain1/AC count4 at 54;
measured all-AC conducted peak:i16 half-dBm at 58; TID count:u8=8 at 60;
starvation bound:u8=8 at 61; board ceiling:i16 half-dBm at 62; reserved[32]=0
at 64. The peak plus the base antenna bound must fit this ceiling, the base
ceiling and every current overlapping host rule at every native access
(`qos::Grant::invoke` nests inside the `N85H`/BA invocations).

Linux behaviour followed:

- Classification: `net/wireless/util.c::cfg80211_classify8021d` (RFC 8325
  DSCP table, IPv6 traffic class, MPLS TC, 802.21 = 7; no QoS Map/VLAN input
  exists natively) and `net/mac80211/wme.c::ieee80211_downgrade_queue`
  (ACM-marked ACs step VO->VI->BE->BK without an admitted TSPEC).
- Queues: `init.c::ath9k_init_queues` sets up one DATA QCU per AC and
  `hw.c::ath9k_hw_init_queues` writes `AR_DQCUMASK(q) = 1 << q`;
  `main.c::ath9k_conf_tx` -> `xmit.c::ath_txq_update` ->
  `mac.c::ath9k_hw_resettxqueue` programs `AR_DLCL_IFS` (CWmin/CWmax/AIFS),
  `AR_DRETRY_LIMIT`, `AR_QMISC` (DCU early termination) and `AR_DMISC`
  (CW backoff, frag wait, threshold 2) from the AP's WMM parameters.
  NARF keeps BE on its original QCU0 owner, uses Linux's VI=1 and BK=3
  indices and places VO on the free QCU2. Retry limits match queue0.
  `AR_DCHNTIME` stays 0: Linux programs `txop * 32` us, but each NARF QCU
  holds one MPDU per access, which stays within any advertised TXOP limit.
- Scheduling: Linux `xmit.c::ath_tx_queue_tid`/`ath_txq_schedule` keep
  per-TID software queues drained per hardware queue and let the DCUs
  contend. The NARF owner keeps exactly one native PPDU in flight across all
  QCUs (the existing terminal TxDone + queue-idle proof), so the host
  `qos::Scheduler` serves the highest backlogged AC (VO, VI, BE, BK), serves
  any AC passed over 8 consecutive times first, and alternates the two TIDs of
  an AC. Its total backlog stays within one TID's 16-frame bound, so the IPC
  ring retains backpressure and nothing is dropped. Without the grant every
  frame is TID0 and the scheduler is the original FIFO.

The successful association response must carry a complete WMM Parameter
element: BE keeps the §3.1 rules (no ACM, TXOP 0, no U-APSD) and must equal
the programmed queue0 word; every AC needs AIFSN 2..15 and CWmin<=CWmax<=1023.
An invalid non-BE AC leaves the qualified BE-only owner unchanged (no queue
is programmed). `Packet::enable_qos` programs QCU1..3, opens IMR_S0/S1
TXDESC/TXEOL for QCU0..3 when MSI is armed and reads every data DCU back;
the same readback gates each later transmit. A later beacon whose WMM
parameters differ closes the owner, as BE changes already did.

Open QoS DATA uses the existing independent per-TID sequence counters;
secured QoS uses the shared per-TID sequence owner, and the QoS control TID
is the classified user priority. The two-MPDU sender BA (§3.3) still owns
BE/TID0 only: the interface pairs only TID0 frames and `send_pair` refuses any
other TID. Management, EAPOL, BA control and BAR stay on queue0.
Teardown is the §4 stop proof, which already aborts and polls all ten QCUs;
a frame held on QCU2 is reclaimed and a wedged DCU pins every mapping.
Covered by `smoke_ar9285_qos_classify_downgrade_and_scheduler_order`,
`smoke_ar9285_qos_signed_contract_and_missing_source_keeps_be_queue0`,
`smoke_ar9285_qos_native_four_ac_program_tids_and_queues` and
`smoke_ar9285_qos_teardown_revocation_and_invalid_ac_fallback`; the
filtered `drivers/wireless/ath9k` kernel-test suites report 112 pass, 0 fail,
0 skip on both x86_64 and aarch64. Physical N85Q qualification and over-air
EDCA behaviour are unmeasured.

The former reset-only `Ath9k::new` constructor is removed. Construction
goes through the PCI authority and identification path. Successful probe
records hardware identity and then programs Linux's AR9285 2GHz HT20
mode/gain/common tables (655 writes), ordered PLL/analog shift setup and RF
synth reference registers with bounded responsive settling delays. All
four gain-table combinations use the actual factory TXGAIN and SYNTH9
selection. This inactive preparation alone does not authorize a WLAN.
The modal stage programs switch controls, IQ coefficients, RX attenuation
and margins, EEPROM antenna-diversity controls, versioned OB/DB analog
fields, settling/ADC/XPA/RX timing, CCA thresholds and baseband power scale.
Analog updates use bounded settling delays. Dynamic diversity combining
is not enabled by the current reference-channel probe.
The detector stage selects the factory PD gains, interpolates frequency-pier
power/VPD intercepts, and programs the gain boundaries and all 128 PDADC
entries. The complete bounded calibration plan is validated before its first
register write; EEPROM versions before minor 2 retain the hardware overlap
source.
The rate stage interpolates the three factory target-power pier tables,
applies the exact factory CCK/OFDM/HT20 CTL edge rules and antenna-gain
reduction, and programs the six rate-power words with the AR5416 table
offset. World SKUs take the minimum across matching regulatory groups.
The PCI probe passes a zero-dBm ceiling and keeps per-packet TPC disabled;
this inactive reference preparation grants no transmit permission. Values
are planned and validated before any rate-register write, and antenna
reduction saturates rather than wrapping an unsigned zero ceiling upward.
The pure immutable factory-domain resolver/table is shared with ath10k;
no firmware transport or runtime driver is used to resolve EEPROM identity.

The retained live continuation applies Linux's selected SerDes/PCIe wake
sequence, activates only the prepared PHY, waits for synth settling, and runs
AGC/filter/carrier-leakage calibration with its gain-table retry, normal-board
PA calibration (high-power boards use Linux's skip), initial noise-floor
load/measurement and single-sample IQ correction. Every wait is bounded and
uses the async timer bridge with no IRQ-disabling guard across await. Hardware
self-clearing completion precedes report publication; an invalid measurement
is rejected rather than qualifying stale factory IQ values. A legitimate
full-width correlation of -1 is distinguished from removal through an
immutable current silicon-identity read. Error/drop records failure without
MMIO cleanup. The same `Arc<Mutex<Ath9k>>` and factory image survive it.

Native register reads and writes validate complete aligned BAR extents and
execute inside `Cap::invoke`; revoked reads return all ones, revoked writes
are refused, and preparation cannot report success after authority loss.
Initial parking and the calibration's PCI parking read also execute inside
current capability invocation, including the actual configuration accesses.

### 3.5 Exact-channel cold generations and signed v2 records

`WirelessNetIface::get_wireless_info` advertises the checked EEPROM/CTL
channel mask intersected with current host permission. The admitted channel
set is1–13 (2412–2472MHz), full-rate20. Japan's CCK-only channel14 is not
advertised or accepted. `set_config` with a new channel and no power override
requests a complete cold reset; it does not preserve association. A current
Open generation may be deliberately retired; transitional MLME generations
are Busy. Same-channel configuration retains the existing no-op behavior.

Retirement withdraws the exact interface, closes its publication token,
clears carrier/queued packets/capture, fails keys and retires recipient/sender
BA, and requires the actual all-QCU/RX DMA stop proof before a successor
exists. Failure pins the owner and starts no replacement. The same physical
function is power-on/warm-reset, EEPROM and silicon identity are re-read and
must match, and full INI/modal/detector/CTL/rate/PA/NF/IQ preparation repeats
for the target primary. Only a fresh successful frequency-bound calibration
report can create new Packet/Radio/Device objects. The old interface name is
reserved and terminal; the successor registers a new name, as existing
recovery does. Old Arc/ring/cache/key/BA authorities never reopen. A future
stable-name or association-preserving retune would require another explicit
publication protocol; this implementation does not claim one.

`channels` owns the queued physical operation independently of public waiter
lifetimes. A driver worker owns hardware timer wakeups; dropping the caller
cannot strand a partially retired/calibrating generation. Requests bind the
requester's physical generation and are rechecked after the complete-control
mutex is acquired. Concurrent different targets or old generations cannot
retune the successor. Reset, initialize and suspend share that control mutex.
Recovery and resume retain the selected primary and repeat full retirement.

Multi-channel passive or active scans drive actual fresh generations for
each requested channel and restore the original primary by another complete
reset on success. Results identify the actual RX owner frequency. Copied
result IEs are presentation data only; they cannot authorize association.
A join to another channel retunes, performs fresh directed native discovery
and then authenticates with that new generation's BSS/security facts.
Associated scans return Busy. Failure/cancellation closes any active scan
owner; a committed driver-owned cold transition continues to a valid passive
successor or terminal error. It never reopens the old owner or promises RF
restoration after a failed/cancelled scan.

`N85H/N85B/N85T/N85Q` v1 recipes, request hashes, filenames and channel1
bodies are retained unchanged. Other primaries require distinct v2 request
prefixes/filenames and version2/channel fields. Requests bind the actual
per-channel calibration and rate table; every capability invocation constrains
the entire selected20MHz span. Full format and qualification requirements
are in [ar9285-channels.md](ar9285-channels.md). No measured board data is
provided or inferred. Legacy admission retains factory/CTL, current policy,
RF-silent, PCI capability and native DMA/copy gates; new per-channel accesses
also read back the actual synth/mode and all seven installed power registers
inside the current device invocation.

Six native cases in `interface_channel_tests.rs` exercise actual reset/EEPROM,
PHY and calibration code before real MAC/Packet/Radio/Device composition,
Open/WPA2 IP, all13 selected primaries, v1/v2 boundaries and foreign records,
fresh discovery, multi-channel active/passive scan and RF restore, stale
owner rejection and wedged DMA/policy preflight. These cases are written,
not executed. They supply no physical EEPROM/RF/interoperability acceptance.

### 3.6 Optional measured full20/40 and directional SGI40

`Ath9k::ht40_qualification_request(secondary)` exposes factual identity, MAC
and external filename for one exact primary/secondary pair. It requires the
actual current nominal20 calibration and H1/2 grant, complete EEPROM,
AR9285 revision2, chain1/1 and both HT disable flags clear. AR2427 stays
legacy-only. `BasebandPrepared::width_mhz()` and `secondary_channel()` report
actual typed preparation; `reference_frequency` remains the primary, while
the RF synth/detector/delta-slope/spur center is primary±10MHz. Neither a
request nor prepared registers are RF permission.

The signed `N85H` v3 record is a distinct full20/40 static program. It binds
the preceding H1/2 identity and complete payload, exact board image, primary,
secondary/direction, actual primary/extension/center power lookup chain and
all ten installed registers, actual source algorithms, directional SGI40,
full-program peaks and a signer-supplied expected fresh40 calibration digest.
No v1/v2 recipe, filename, field meaning or20-only permission is reinterpreted.
The exact384-byte body and its B/T/Q3 children are specified in
[ar9285-ht40.md](ar9285-ht40.md). No board measurements or signed assets are
provided.

A current wide AP offer triggers H3 preflight before retirement or40
calibration. The entire occupied40MHz span and every overlapping host limit
must admit the fixed nominal budget and measured antenna/peak bounds. The
old-generation DMA proof, reset and identical factory re-read precede40 INI
column3, source modal40 settling, joined extension CCA, real synth/slope/spur,
RF-center detector table, primary20 and extension legacy CTLs plus RF-center
HT40 target/CTL and EEPROM PDADC compensation. All stable writes read back.
Live40 calibration uses the source40 carrier-leakage branch, PA, both
control/extension NF planes, actual even/odd ADC gain/DC and IQ. The actual
receipt must match the signed expected digest before Native/Packet allocation
and publication. Current qualification encloses each async calibration poll.

Missing/invalid H3 retains the preceding20 profile and its admission rules.
A failed or mismatching40 preparation/calibration cannot publish40. Provided
old DMA is reclaimable and current20 policy remains valid, the retained
control worker fully resets and calibrates a new real20 generation. A peer's
successful association response that narrows to20 likewise closes the40
owner before M2, keys, BA or DATA, performs a real20 reset/calibration, then
fresh directed discovery and a forced20 association. It never substitutes a
host width flag for hardware programming or loops back into40. Failed DMA
proof, PCI/source loss or invalid fallback policy leaves terminal ownership.
Ordinary recovery and resume deliberately return to actual20 at the same
primary; a later qualified join may select40 again.

Native first-series TXD width/GI bits and duration use the actual negotiated
mode, including one-stream40 NDBPS and Linux's rounded3.6µs symbol formula.
The two-MPDU owner uses the same width/GI for padding density, airtime limits
and native aggregate duration. Management/ACK/BAR remain the supported20
control program. RX width/GI/STBC are checked before original CCMP/PN,
reordering or delivery: SGI20, wide frames on a20 owner, and unqualified RX
SGI40 are dropped. Later source/peer/readback loss closes the owner; native
RF mode, synth, ten power registers and ADC/IQ remain current at actual
DMA/payload/capture/copy boundaries. Full40 recipient BA, sender BA and QoS
require distinct B/T/Q3 records bound to the complete H3 body and40 span.

The existing cold-generation interface-name, association/key/BA/capture loss
rules remain. Scans while associated are Busy. Unassociated off-channel
scans may return a fresh20 generation at the original primary; they do not
promise to restore40 width. Successful joins publish only the actual
successor's link and port. Public HT capability metadata requires a current
HT source; the actual Association Request carries the selected width and
directional GI capabilities.

Six new native cases in `interface_ht40_tests.rs` exercise real reset/PHY/
calibration/MAC/Packet/Radio/Device paths, both extension directions, Open and
WPA2 kernel DHCP/IP, all8 MCS/GI modes and two actual DMA maps/tail receipts,
peer20 and bad-receipt real fallback before M2/DATA, full-span policy, power
lookup-center separation, signed/unknown/ignored-write rejection, directional
RX GI, cancellation and revocation after actual copy. These cases are written,
not executed. No physical RF or interoperability result is claimed.

### 3.7 Optional measured larger sender aggregates

`Ath9k::tx_aggregate_qualification_request()` returns a factual distinct
N85T4 request, with no emission or BA authority. The exact128-byte contract
and Linux source chain are [AR9285 larger TX qualification](ar9285-larger-tx-aggregates.md).
All accepted N85T1/T2/T3 requests,96-byte records and their two-map/4095-air
program remain unchanged. Missing larger qualification keeps that behavior.
The new record binds the complete current H1/H2/H3 body and geometry, measured
full-program peak, signed3–8 member maximum and air/window/retry bounds;
current base/source caps, full-span policy and real native readbacks remain
mandatory at publication, completion and copy boundaries.

For v4 only, the TX owner expands to the signed count after all queues are
proven idle, retaining the original ring until the final full DMA stop proof.
Real per-member links, FIRST/MIDDLE/LAST flags, padding and whole-PPDU duration
replace fixed pair arrays. The maximal already-queued BE/TID0 prefix is sized
before reserving any shared QoS sequence or CCMP PN. It fits the signed bound,
peer factor, **half the accepted BAW**, hardware65535-air limit and actual4ms
20/40/GI duration. Current accepted beacons narrow factor/density/GI in step
with the installed packet profile. Unfitting suffixes stay queued; singleton
heads use ordinary normal ACK. No TX A-MSDU or other-TID sender is inferred.

Actual NULL-tail TxDone plus QCU idle and all-member immutable descriptor/
padded-payload proof precede the native64-bit BA bitmap receipt. Every v4 hole
owns at most three immutable original normal-ACK retries, after which a real
BAR to the full chain's end must prove native BA status and fresh RX idle.
Rekey/source/cancel/retune closure preserves DMA until terminal proof and
invalidates every CPU retry and copied-packet authority. Failed DMA stop pins
all original and expanded storage. No association or generation preservation
is inferred.

The source-complete eight-member baseline has seven additional native cases
written, including real public IPC/kernel DHCP/IP and fresh actual H3
calibration/40MHz/SGI40 composition. Release/native execution and external
board measurements/signatures/physical acceptance remain pending.

### 3.8 Factory field order and complete admitted profile selection

The admitted AR9285 factory-profile matrix is source-complete. Linux selects
only `eep_4k_ops` for this chip; all four normal/high/XE2 gain-table choices
already use actual TXGAIN/SYNTH9. The additional concrete same-map path now
handles big-endian EEPROM fields throughout live PHY/modal/detector/CTL/rate/
spur preparation and actual20/40 calibration, alongside ordinary and
magic-word-swapped storage. Exact layout/source facts and pending validation
are [AR9285 factory fields](ar9285-factory-fields.md).

The raw checksum-verified376-byte image, EEPMISC flag and source-hashed bytes
are retained unchanged. Private factual word/dword readers honor field byte
order at each multibyte consumer; MAC/U8 tables, derived PDADC packing, air
headers and signed body byte order keep their independent meanings. Existing
LE writes and all H/B/T/Q qualification formats/request recipes remain.
Foreign LE bodies cannot qualify a raw BE identity. Current calibration,
power/policy/source/readback and terminal packet/copy/key/BA/DMA controls apply
through the same real owner. No new generic board profile or chip is inferred.
Five additional native cases are written; release/native and physical
acceptance remain pending.


### 3.9 Optional source-qualified station NETWORK_SLEEP

`Ath9k::power_save_qualification_request()` returns the factual optional
N85S1 source identity/MAC/filename for the exact current H1/2/3 body and
20/40 geometry. The existing `WirelessNetIface::power_save_default` and
`set_power_save` methods now serve the real nl80211 setting. SET owns desired
configuration; actual PM notice, ACK/queue/RX-idle receipt, timer program and
RTC transition finish in the retained Radio continuation. Default awake and
unsupported-without-S behavior preserve existing deployments.

The admitted AR9285 program is source-complete for PM1/PM0 non-QoS plaintext
Null, actual short PS-Poll descriptor/AID, current-beacon TIM/DTIM/CAB/MoreData,
manual TIM_TIMER/MSI-or-polled wake, source-literal timers and bounded actual
AWAKE/NETWORK_SLEEP readbacks. Shared DATA crypto is unchanged: controls
consume no PN; ordinary original DATA/security PM mutation preserves exact
native and shared reply ownership. A bounded, epoch-cleared unpublished BA
reply continuation drains RX behind a held PS receipt; BA activation still
requires its own real native ACK/idle proof. Re-enable needs a fresh beacon. Fresh
source and PCI invocations enclose every actual native wake/access/copy;
SHUTDOWN never fabricates live association preservation. Ambiguous hardware
or authority loss closes the owner and retains unproven DMA. Complete signed
full-program/multidimensional qualification is required; no physical board
measurements or signed asset is supplied. The separate idle_FULL_SLEEP and
periodic-calibration operations are not authorized by S.

The exact format, source references, controls, hardware ownership and pending
acceptance are [AR9285 station power save](ar9285-station-power-save.md).
Eight new native cases are written; release/native execution and physical
acceptance remain pending.

### 3.10 Optional measured periodic calibration and ANI

`Ath9k::periodic_calibration_request()` exposes factual N85P1 request metadata
for the current retained H owner. The distinct160-byte full-program contract
and exact layout are in [ar9285-periodic-calibration.md](ar9285-periodic-calibration.md).
No production measurements are supplied. Absence leaves every accepted
static H/B/T/Q/S program unchanged; a provisioned current P profile binds
automatically at a quiet associated station boundary.

The actual native owner retains original H1/H2/H3 identity and calibration
receipts while a separate current live receipt tracks actual IQ/ADC/PA/NF/ANI.
Source20 IQ and40 ADCgain/DC/IQ measurement,30s PA/NF,20min reset-valid,
actual MIB/listen/PHY-error ANI and current-peer RSSI are implemented. Host
writes require original ticket and RX-idle ownership, actual all-QCU idle,
RXabort/state0 and readback. Bounded hardware measurement allows traffic
under unchanged prior coefficients; a partial host mutation never escapes
normal Radio polling. Every original key/PN/SC/BA/capture owner survives.

Current P global peak intersects original H, every installed B/T/Q ceiling
and all overlapping full-span host rules. Original initial coefficient
checks are replaced only by the actual current P live receipt; all factory,
geometry/center/power/chain/RF-silent/PCI/current-source checks remain.
Failure closes CPU admission and independently attempts BME-off; unproved
DMA stays pinned. P1 requires actual AWAKE and rejects S1 composition without
reinterpreting its bytes. Existing suspend retires this generation.

Six native cases are written, including actual fresh40/full-reset factory
composition, native eight-original delivery and kernel DHCP. Release/native
execution and physical qualification remain pending.

### 3.11 Counted D0 idle FULL_SLEEP and retained cold wake

The family controller exposes `set_idle_full_sleep(bool) ->
Result<IdlePowerStatus, IdlePowerError>`, `idle_full_sleep_status() ->
Option<IdlePowerStatus>` and `acquire_idle_wake() ->
Result<IdleWakeGuard, IdlePowerError>`. These operate on the original retained
controller; station NETWORK_SLEEP, operator IFF_UP/DOWN and system S3 retain
their separate meanings. The admitted baseline accepts idle only on a current
published Passive, unassociated generation with no MLME/security/control or
native/software original pending. Counted external users and accepted queued
initialize/reset/retune work return Busy before idle can be admitted.

Each actual station holds a counted idle guard throughout its native lifetime.
The retained worker withdraws its exact public interface/copies/IPC, requires
the same complete all-ten-QCU/RX/IRQ/BME-off terminal retirement, then releases
that guard and owns Linux's100ms delay. A completed retained RX tail remains
mapped until terminal stop. Missing stop proof pins the owner, count and DMA;
no successor or clock-off is allowed. Dropping a public waiter cannot cancel
this worker. Leaving idle cancels the delay and continues that original owner.
Actual current-capability D0 entry proves RXabort/state0 and IRQ/queue/BMEoff,
uses the source STA_ID1/RTC/reset sequence and requires RTC_SHUTDOWN1.

Wake performs a fresh complete actual20 cold generation at the retained primary,
including identical raw factory/identity, INI/PLL/RF, current factory/host plan,
analog calibration, complete MAC/key-cache preparation and native reports before
new-name publication. Keys, association, PN/replay, BA, copies and old endpoints
do not survive. A40 predecessor cannot lend its center/report to a20 successor.
Existing H/B/T/Q/S/P formats and qualification recipes are unchanged; no clock
off happens under a live P1 always-awake or S1 packet owner. Physical board
measurements, power and wake acceptance remain external and pending.

Status distinguishes desired idle, phase, counted users and physical generation.
`Operational` means not parked, including provisioning before publication or
independent S1 doze; it grants no calibration or IO authority. `Asleep` requires
completed physical entry. A public wake-use return additionally requires a
Running packet and current source/PCI/actual awake admission. Its guard prevents
idle FULL_SLEEP and grants no register/key/DMA access. System suspend fences
new users and refuses extra live guards; resume cold-restores actual20. Remove
permanently closes the original idle owner, and the terminal supervisor never
resurrects an intentionally parked owner.

The source contract and pinned Linux call chain are
[AR9285 D0 idle FULL_SLEEP](ar9285-idle-full-sleep.md). Seven native cases are
written, covering real Device/Radio/Packet/DMA, all-queue/RX retirement, current
physical sleep/readback negatives, counted control/association refusal,
cancelled delay, fresh Open/WPA2/kernel DHCP and full40-above/below to actual20.
They compose the production lifetime helpers with complete model cold-reset
primitives; they do not instantiate the singleton native PCI controller.
Release/native execution and physical acceptance remain pending.

## 4. Invariants

- PCI parking is verified by command-register readback before BAR sizing: BME
  and memory decode off and INTx masked. Decode is enabled only after sizing
  writes are restored; MMIO follows that readback. Additional
  matched singleton radios are parked with BME/memory decode off and rejected.
  Repeated dispatch of the owned address fails before parking.
- BME, MAC RX, all ten TX queues and interrupts remain disabled throughout
  identification, preparation and initial calibration. PHY activation is confined to
  the policy-bound calibration continuation; packet rings are allocated only
  after its complete retained receipt. The common table's cleared DIAG_SW is followed by restored
  RX_ABORT/RX_DIS, which remain set through calibration.
- Optional N85P1 keeps those initial receipts immutable. Live host writes
  require actual TX/control idle and RXabort/state0 with retained original
  mappings; current P/live readback replaces only dynamic calibration fields.
  Bounded actual measurement keeps prior coefficients current. No mutation,
  timeout or scheduler intent fabricates a fresh calibration or DMA receipt.
- Packet start requires complete aligned 32-bit DMA extents and verified ring
  programming before BME activation. TX status is terminal only after descriptor
  completion and queue idle; RX completion is acquired before status/payload.
  A null-terminated RX list retains its last consumed descriptor until a
  successor completes. Stop follows Linux `recv.c::ath_stoprecv` and
  `mac.c::{ath9k_hw_stopdmarecv,ath9k_hw_abort_tx_dma}` with bus mastering
  still on: DIAG RX abort/disable, RX filter clear, MACMISC observation bus,
  AR_CR_RXD with 1000 x 10 us RXE polls and the pre-AR9300 DMADBG_7 `0x1c0`
  hang signature, then AR_Q_TXD for all ten QCUs with forced quiet collision,
  idle-high channel and ignored backoff while each QCU's pending count and
  TXE bit are polled up to 1000 times 5 us apart. IER is cleared and BME is
  disabled with readback. Only if every step succeeded and post-BME-off BAR
  reads (which order behind earlier device-posted DMA writes; the native port
  requires PCIe Device Control Relaxed Ordering disabled, otherwise the proof
  is refused) still show RXE,
  TXE and pending counts clear, RX parked and IER off, are the rings and
  buffers released (`Packet::reclaimed`). Any timeout, hang signature or
  access failure keeps every mapping pinned for the rest of the boot. The
  terminal owner leaves AR_Q_TXD set rather than Linux's final re-enable.
- Hardware key-cache entries remain invalid. Protected KeyMiss frames with no
  other errors may lack FrameOK and reach software CCMP authentication;
  unprotected frames require FrameOK. Neither path bypasses MIC/replay checks.
  Consumed error/status frames do not establish an RX-idle fence. M4 commit and
  staged plaintext delivery require a real native idle observation.
- Register and EEPROM waits use the scheduler's bounded responsive wait;
  reset settling delays are measured in time, not CPU iteration counts.
- EEPROM reads trigger by reading `0x2000 + word * 4` and accept data only
  after the status busy/protection bits clear. Word indices are bounded.
- The map starts at EEPROM word 64 and has 188 words. Magic-driven word
  normalization precedes EEPROM-field endianness handling; checksum is
  validated over the declared bounded even length. Version major 14 and
  minor at least 1 are required.
- Factory MAC is nonzero/unicast and AR9285 chain masks are single-chain.
  Factory regulatory identifiers do not themselves grant transmit rights.

## 5. Architecture notes

The register protocol is shared by both NARF architectures. Byte-order
normalization covers ordinary, word-swapped and big-endian-field EEPROM
images. The 376-byte layout was checked against the packed structs from
local Linux `ath9k/eeprom.h`.

## 6. Dependencies

PCI authority and MMIO come from `bus/`, coherent masked DMA from `io/`,
retained state from `lib/`, and responsive waits from scheduler/time.
Shared `wireless/` supplies policy, MLME, RSNA and packet keys; `crypto/`
supplies fallible entropy and AES-CCM, and `net/` owns DHCP/Ethernet delivery.

## 7. Stage assignment

This wave's HT20, RX STBC1, RTS/CTS, original A-MSDU, recipient BA and
receive/publication-epoch tests passed the coordinated native Wi-Fi functional
validation. The full scoped Wi-Fi suites report **x86_64: 2317 passed, 0 failed,
9 skipped; aarch64: 1847 passed, 0 failed, 3 skipped**. These are suite totals
across the scoped Wi-Fi families, not ath9k-only counts; they do not attest
physical EEPROM, calibration, RF, DMA or AP interoperability qualification.

Stage 5 initial retained station profile. Traced smokes exercise the live
identification helper, complete EEPROM extent, reset register order,
endianness/checksum/version validation and invalid/busy hardware cases.
Independent hashes from Linux cover every address/value pair for all four
production INI choices; fixtures also verify PLL/RF values, analog delays,
BAR bounds and that packet/PHY engines stay disabled.
Native Rust tests exercise production modal/RF, detector, rate, channel,
calibration, MAC and packet owners using fixed reference data and explicit
hardware/protocol invariants. Rust tables and provenance retain source citations;
no reference source is extracted or compiled for validation, and no temporary
Rust comparison adapter is generated.

Rate cases cover exact/interpolated/clamped target piers, CTL flags,
specific/world regulatory groups, antenna gain and zero ceiling. All 65,536
EEPROM identities exercise the shared factory resolver. Register models check
actual capability revocation before invalid MMIO and stop later writes on access
loss. Thirty-two calibration traces and 35 IQ vectors cover XE2 identity,
high-power PA skip, carrier-leakage retry, inherited state, signed clipping and
wrapping intermediates. Withheld completions, cancellation and policy overlap
keep packet engines and bus mastering closed.

Forty-eight channel cases cover channels 1/6/13, eight signed spur offsets and
zero/nonzero inherited state, including Viterbi packing and boundary rejection.
Production still invokes this sequence only for the inactive 2412 MHz reference;
fast retuning remains open. Descriptor tests retain 72 TX vectors, ten RX-status
vectors and ten MAC/PCU/queue/DMA traces. They check complete extents, status,
current authority and terminal storage ownership independently of caller buffers.

The shared AP consumes actual descriptor/DMA bytes and produces RX descriptors.
Device conversations run Open/WPA2 through the real kernel DHCP client and exact
bidirectional IP, including held/modified/cancelled M4, entropy/peer deadlines,
policy restriction and concurrent disconnect/publication. Fixture assets cannot
authorize real hardware.
Active-discovery cases consume actual DMA Probe Requests, supply matching native
Probe Responses, and continue through Open/WPA2 DHCP/IP. Directed/wildcard and
binary/maximal SSIDs, preflight rejection, held/failed completion, policy loss,
cancellation and associated-scan rejection have native regression coverage.

Adjacent `REFERENCE.md` files document fixed-vector coverage and update rules.
Review fixture values independently against the documented contract. These
software/model checks supply no physical calibration, RF, IRQ or interoperability
measurements.

## 8. Remaining software and physical acceptance

The initial one-shot channel1 calibration, polled packet owner and station
profile are implemented. Hardware testing requires an exact EEPROM-bearing
device, authenticated deployment policy and measured RF/calibration acceptance.
No RF or AP interoperability has been demonstrated by the model tests.

Additional AC/TID scheduling is implemented in §3.4. The remaining software
rows and the tree facts that keep each open:

- `additional_channels`, `channel_retuning` are source-complete for admitted
  primary channels1–13/full-rate20 in §3.5. Release/native validation is
  pending; Japan CCK-only channel14 remains unadvertised. The cold reset
  replaces the netdev generation/name and drops keys, BA and association.
- `ht40`, `sgi40` are source-complete for the exact measured AR9285
  revision2 full20/40 program in §3.6. Version3 is distinct from every
  accepted20-only v1/v2 contract; actual fresh40 calibration and real20
  fallback before keys/DATA are mandatory. Release/native and physical
  acceptance are pending.
- `factory_profile_selection` is source-complete for the admitted AR9285
  `eeprom_4k` map and all four TXGAIN/SYNTH9 gain choices in §3.8. The concrete
  raw big-field consumer gap is repaired through actual20/40 factory/PHY/cal/
  native paths; five new cases await execution. Linux names no additional
  AR9285 map selector; other layouts remain separate chip rows. External
  measured assets and physical acceptance are pending.
- `periodic_calibration` is source-complete for the admitted distinct N85P1
  always-awake full20/40 program in §3.10. Actual IQ/ADC, PA/NF and ANI
  continuations retain the original native/key/BA/capture owners and separate
  current full-program qualification; no static H or S1 tracking authority is
  inferred. Six native cases are written; release/native and physical
  acceptance remain pending.
- `larger_tx_aggregates` is source-complete for distinct signed N85T4
  bounded3–8-member AR9285 sender programs in §3.7. Actual N-slot DMA,
  half-BAW/factor/air/4ms sizing, per-member BA/retry/BAR/key-epoch ownership
  and public IPC are implemented. Legacy1/2/3 stay two-member;64-member
  aggregation is unadvertised. Seven new native cases are written, with
  release/native and physical qualification pending.
- `tx_amsdu` (inapplicable, row removed 2026-10-28): Linux ath9k never sets `IEEE80211_HW_TX_AMSDU`
  (`init.c::ath9k_set_hw_capab`), so mac80211 forms no TX A-MSDU for this
  driver and there is no Linux reference path. Natively the TX maps are
  `descriptor::MAX_MPDU + 2` (2306) bytes and `descriptor::transmit_ht`
  rejects longer frames; `N85H` hashes "noTXAMSDU". The shared
  `station_security::transmit_amsdu_qos` encoder exists but needs larger maps
  and a separate measured record.
- `idle_full_sleep` is source-complete for the admitted Passive/unassociated
  original-controller baseline in §3.11: counted native/control/wake users,
  public desired/status controls, retained100ms continuation, full terminal
  DMA/IRQ proof before actual D0 SHUTDOWN and fresh actual20 cold wake.
  Associated retention, runtime PCI D3 and physical board wake measurements are
  not inferred. Seven native cases are written; release/native and physical
  acceptance remain pending.
- `station_network_sleep` is source-complete for the admitted optional
  AR9285 N85S1 program in §3.9: actual public desired setting, PM notice/
  PS-Poll receipts, TIM/DTIM/CAB timers, source-qualified real awake/sleep
  access and terminal DMA ownership. Eight new native cases are written;
  release/native execution and external measured physical acceptance remain
  pending. Missing S preserves default awake operation.
- `host_bus_pm`: native implementation and x86_64/aarch64 software
  validation completed2026-10-29. The family subtree passes114 native
  smokes per architecture; bus/pcie also covers current child authority,
  scoped ECAM fixtures and an absent parent capability list.
  The read-only `narf_bus::pci_express::parent_link_control` runs inside
  the child's current capability invocation and reads its immediate
  registered bridge, without minting bridge authority or changing platform
  ASPM policy. A nonzero parent L0s/L1 field enables the exact AR9285
  `ar9280PciePhy_clkreq_always_on_L1_9280` table, 1ms settle and D0 WA/PM
  settings during probe, reset/resume and pre-calibration start. Disabled,
  missing or unavailable parent ASPM never causes these device-local writes.
  The retained owner remembers whether it applied D0 workarounds, keeping the
  D3 half paired even if platform link policy changes before suspend.
  After the cold-reset half of system suspend, before FULL_SLEEP, the owner
  clears PM_CTRL L1 enable and WA bits6/7; the actual retained SYNTH9 XE2
  fact controls WA bit23. Native tests assert source-literal D0/D3 programs,
  preservation of unrelated bits, authority loss, and reset/workaround/sleep
  ordering. No endpoint or shared-bridge Link Control is written.

Interrupt-driven service (`irq.rs`) follows Linux `pci.c` with
`ath9k_use_msi`: one MSI vector is discovered, programmed and installed with
delivery disabled after MAC preparation (`Native::arm_msi`); failure leaves
the owner on 1 ms scheduled polling, since no INTx route is claimed. After the
rings start, `Packet::enable_interrupts` writes the
`hw.c::ath9k_hw_init_interrupt_masks` + `mac.c::ath9k_hw_set_interrupts`
station mask for imask TX|RX|RXEOL|RXORN|FATAL|GLOBAL (CST on HT silicon):
IMR `0x910004b0` (RX mitigation RXINTM/RXMINTR with RIMT 700/250 us, TXDESC
and TXEOL for QCU0 via IMR_S0/S1, GENTMR because AR9285 lacks AUTOSLEEP),
SYNC_DEFAULT, AR_INTCFG MSI RX-mitigation routing, then
`__ath9k_hw_enable_interrupts` (IER, async MAC_IRQ, sync default, MSI priority
mask and the 200-try AR_PCIE_MSI re-arm). The vector handler only counts and
wakes; the station task brackets each service pass with
`ar9002_mac.c::ar9002_hw_get_isr` (RAC read-clear of ISR/S0_S/S1_S/S5_S, sync
cause clear, AR_RC_HOSTIF pulse on completion timeout) plus
`ath9k_hw_kill_interrupts`, and resumes afterwards as `ath9k_tasklet` does.
RXEOL drops RXEOL|RXORN from IMR until the RX pass completes. FATAL (HOST1
fatal/PERR, completion timeout) fails and terminally stops the owner. The
worker sleeps until the vector, a stack TX enqueue or a 20 ms housekeeping
tick for millisecond MLME/RSNA deadlines. Stop kills IER/async/sync/MSI
priority enables and disables MSI before the vector is drained and freed; a
failed MSI disable quarantines the vector. Covered by
`smoke_ar9285_packet_msi_cause_kill_resume_and_fatal`. Physical MSI delivery
on AR9285 is unmeasured.

Power transitions are enumerated from Linux `hw.h::ath9k_power_mode`
(`AWAKE`, `FULL_SLEEP`, `NETWORK_SLEEP`) and their callers. Reset forces
`AR_RTC_FORCE_WAKE`; the default owner stays awake unless the optional N85S1
station program in §3.9 is admitted. AR9285 lacks `ATH9K_HW_CAP_AUTOSLEEP`
(`hw.c::ath9k_hw_fill_cap_info`), so sleep entry is software-forced. Named
operations and their separate owners:

- `idle_full_sleep`: `main.c::{ath9k_ps_wakeup,ath9k_ps_restore,ath_ps_full_sleep}`
  use-counted wake,100ms idle timer, RX abort/DMA stop and `FULL_SLEEP` are
  implemented in §3.11 on the retained original controller. Leaving idle uses
  `ath9k_config`'s full channel-reset requirement and fresh actual20 native
  calibration rather than claiming old live keys/register state survived.
- `station_network_sleep`: `NETWORK_SLEEP` station power save with
  `beacon.c::ath9k_beacon_config_sta`/`hw.c::ath9k_hw_set_sta_beacon_timers`
  TIM/DTIM timers and beacon/CAB/PS-Poll/TX-ACK wake conditions, implemented
  with distinct signed N85S1 source authority in §3.9. Linux leaves
  `SUPPORTS_PS` behind the `ps_enable` module parameter (default off).
- `host_bus_pm`: `pci.c::ath_pci_aspm_init` parent-link ASPM L0s/L1 discovery
  and `aspm_l1_fix` (config 0x70c) handling.

System suspend is implemented through `narf_power::device_pm` ("ath9k"):
`pm_suspend` (Linux `pci.c::ath_pci_suspend`, with mac80211's prior
interface stop) retires the station generation and requires its DMA-stop
proof, then `identity::disable_and_sleep` performs `ath9k_hw_disable` (AWAKE
+ cold reset; PLL not reprogrammed since the chip sleeps immediately) and the
forced `hw.c::ath9k_set_power_sleep` FULL_SLEEP entry (STA_ID1 PWR_SAV, RTC
force-wake clear, AR_RC AHB|HOSTIF, active-low RTC reset asserted). A held
owner lock returns Busy so the orchestrator aborts; unproven DMA pins the
owner and fails suspend. `pm_resume` (`ath_pci_resume`) re-disables PCI
RETRY_TIMEOUT (config 0x41) and spawns a generation reset (power-on reset,
identical EEPROM, INI/PLL/RF, calibration, republication). ASPM
re-initialization belongs to the open `host_bus_pm` row. Covered by
`smoke_ath9k_ar9285_suspend_disable_then_forced_full_sleep` plus the
retirement smokes; physical S3 is unmeasured.

Wake-on-WLAN is not applicable to the matched parts: `wow.c::ath9k_init_wow`
requires PCI `driver_data` `ATH9K_PCI_WOW`, which `pci.c` sets only for
`0x0034` (AR9462) subsystems, and the hardware programming lives in
`ar9003_wow.c` (AR9003 family only). It belongs to AR9462 enablement.

DMA reclamation is implemented by the terminal stop described in §4 and
covered by `smoke_ar9285_packet_dma_stop_proof_reclaims_storage` (held TX
abort, never-started owner, wedged DCU and RX DMA with exact Linux poll
budgets, DMADBG_7 hang and revoked authority), and by the ownership smoke,
whose model device faults on any access to a released mapping.

Generation reset, rejoin and removal build on that proof:

- `reset`: `ath9k::reset_radio` (Linux `main.c::ath_reset` /
  `hw.c::ath9k_hw_reset`) retires the current generation — host interface
  withdrawn (`interface::retire`), station stopped, DMA-stop proof required
  (`Radio::retire`). An unproven stop pins the owner forever (`pinned`), so no
  successor can start while the function might still master. After verified
  BME-off it re-runs the probe's AR_RTC power-on + warm reset and EEPROM read
  on the same function, requires the identical identity and 376-byte factory
  image, reprograms INI/PLL/RF (`phy::program`), discards the old calibration
  receipt, bumps `generation` and re-enters the one-shot calibration, packet
  preparation (fresh rings, fresh MSI vector) and station publication.
- `rejoin`: after publication a supervisor watches the station; once it is
  terminal (disassociation, peer loss, FATAL interrupt, failed DMA) it resets
  into a fresh generation so the radio can be joined again. Three consecutive
  failed resets, a removed owner or a pinned generation end supervision. Each
  generation publishes a new `wlan%d` name; retired names stay reserved
  (stable names are not claimed).
- `removal`: `narf_bus::register_pci_remove` for both AR9285 and AR2427 match
  names (Linux `pci.c::ath_pci_remove`). The hook marks the owner removed
  before waiting (blocking any initialization, reset or supervisor), retires
  the generation, drops the controller and releases the singleton address
  only when DMA was reclaimed; otherwise the address stays quarantined.
  `narf_drivers` has no bound-driver unrecord API, so the bound record is left.

Covered by `smoke_ar9285_station_retirement_reports_exact_dma_reclamation`
(reclaimed vs wedged DCU, idempotent retire) and
`smoke_ar9285_native_device_retire_host_withdraws_generation` (carrier,
interface table, reserved name, late TX, DMA stop). Physical chip reset and
re-association after reset are unmeasured.

Other ath9k devices need their own EEPROM maps, reset/PHY tables and
descriptor/runtime variants before they can be claimed supported. The Linux
`pci.c::ath_pci_id_table`/`hw.h` PCI inventory beyond AR9285/AR2427 is:

- `ar5416_enablement`: AR5416 PCI `0x0023` / AR5418 PCIe `0x0024`
  (AR5008 PHY ops, `eeprom_def.c`, `ar5008_initvals.h`).
- `ar9160_enablement`: AR9160 PCI `0x0027` (AR9001, `eeprom_def.c`).
- `ar9280_enablement`: AR9280 PCI `0x0029` / PCIe `0x002a` (AR9002 dual-band,
  `eeprom_def.c`, AR9280 INI).
- `ar9287_enablement`: AR9287 PCI `0x002d` / PCIe `0x002e` (AR9002,
  `eeprom_9287.c`).
- `ar9300_enablement`: AR9380/AR9390 PCIe `0x0030` (AR9003 EDMA descriptors,
  `eeprom_9003.c`, `ar9003_2p2_initvals.h`).
- `ar9485_enablement`: AR9485 `0x0032` and AR1111 `0x0037` (AR9003).
- `ar9580_enablement`: AR9580 `0x0033` (AR9003).
- `ar9462_enablement`: AR9462 `0x0034` (AR9003, BT coexistence MCI, WoW);
  ath10k currently rejects this ID as wrong-driver.
- `ar9565_enablement`: AR9565 `0x0036` (AR9003, MCI).

Every chip row shares these tree blockers (lifted for AR9287 by the profile
foundation and native owner below): `identity.rs::identify` rejects
any `AR_SREV` macro version other than 0xC0 (AR9285) before the first write;
`decode_identity` accepts only the 376-byte `ar5416_eeprom_4k` map with chain
masks 1/1; `initvals.rs` carries only the AR9285_1_2 tables; `phy/` and
`calibration.rs` implement only the single-chain AR9285 recipe
(`ar9002_calib.c` AR9285 CL/PA paths); `descriptor.rs` is the AR9002
non-EDMA format; and every signed record names device `0x002b`. Per row the
Linux pieces still to port are: AR9287 (closest relative: AR9002, 2.4 GHz
only) `eeprom_9287.c`, `ar9287_initvals.h` modes/common/TX-gain tables, the
AR9287 calibration branches and two-chain masks; AR9280 `eeprom_def.c`,
`ar9280_initvals` (AR9280_2) and 5 GHz; AR5416/AR9160 the AR5008 PHY
(`ar5008_phy.c` analog RF banks) and `eeprom_def.c`; AR9380/AR9485/AR9580/
AR9462/AR9565 the AR9003 EDMA TX-status/RX-FIFO path (`ar9003_mac.c`),
`eeprom_9003.c`, per-chip `ar9003_*_initvals.h`, `ar9003_calib.c`, plus MCI
for AR9462/AR9565.

**Per-chip profile foundation (`ar9287_enablement`).** `chips.rs` decodes `AR_SREV` exactly as
`hw.c::ath9k_hw_read_revisions` (new `0xff` format: `(srev & 0xfffc0000) >> 12`
plus `AR_SREV_REVISION2`; legacy format: `MS(AR_SREV_VERSION)` plus
`AR_SREV_REVISION`) into `Chip::{Ar5416, Ar9160, Ar9280, Ar9285, Ar9287}`,
maps the `hw.h` PCI IDs `0x0023/24/27/29/2a/2b/2c/2d/2e` to those profiles
and names each family's factory map (`EepromMap`): `ar5416_eeprom_4k` at
word 64 (188 words, one chain), `ar9287_eeprom` at `AR9287_EEP_START_LOC`
128 (`SIZE_EEPROM_AR9287` = 363 words of the 727 packed bytes, two chains)
and `ar5416_eeprom_def` at word 64 (1628 words, three chains). AR9285's
`identify` now uses that decode but its register trace, 256-word window
bound, strict even/≤376-byte length rule and 1/1 chain-mask rule are
unchanged. `identity::decode_map` is the shared
`ath9k_hw_nvram_swap_data`/`_validate_checksum`/`_check_version` path for the
other maps: magic-driven word swap, EEPMISC byte order, checksum over
`min(length / 2, SIZE_EEPROM)` words (headers shorter than 32 bytes are
refused), version 14 with minor ≥ `AR5416_EEP_NO_BACK_VER`, unicast MAC and
nonzero RX/TX masks within `min(map chains, silicon chains)` (AR9287/AR9280:
up to `0x3`). `identity::identify_chip` refuses a silicon/device mismatch
before any write, then runs the same AR5008/AR9002 PCI power-on + warm reset
(`ath9k_hw_set_reset` has no branch for these parts) and reads the map
through the 2048-word `AR5416_EEPROM_OFFSET` window.

`initvals_ar9287.rs` carries the literal `ar9002_initvals.h` AR9287 1.1+
modes, common, CCK FIR (normal and channel-14 Japan), TX-gain and RX-gain
tables. `phy/ar9287.rs::prepare` requires `AR_SREV_9287_11_OR_LATER` and the
exact map length, then writes, with PHY/interrupts/RX left disabled: the
AR9002 PLL/analog-shift preamble, `ar5008_hw_process_ini` modes → RX gain →
TX gain (column 4, 2 GHz HT20) → common, the shared AR9002 channel
preparation (`phy/channel.rs::prepare_chip`, which AR9285 now calls with its
unchanged constants) with HWWAR2 additionally cleared, the factory two-chain
RX/CAL/SELFGEN masks, the CCK FIR rows instead of the `AR_PHY_CCK_TX_CTRL`
Japan bit and the AR9287 spur list offset, and finally
`eeprom_9287.c::ath9k_hw_ar9287_set_board_values` (both chains' switch,
IQ, attenuation/margin, settling, xPA timing, thresh62, the two
`AR9287_AN_RF2G3` analog banks and `AR9287_AN_TOP2` xPA bias, each analog
write followed by 100 µs). Kernel smokes (written, not executed):
`smoke_ath9k_chip_revisions_follow_read_revisions`,
`smoke_ath9k_ar9287_map_decode_two_chain_masks`,
`smoke_ath9k_ar9287_identify_reads_map_at_word_128`,
`smoke_ath9k_ar9287_ini_follows_linux_mode_gain_common_order` (FNV-1a
oracle over the 711 Linux INI rows), 
`smoke_ath9k_ar9287_two_chain_masks_hwwar2_and_cck_fir`,
`smoke_ath9k_ar9287_board_values_follow_eeprom_9287` and
`smoke_ath9k_ar9287_preparation_refuses_wrong_inputs`.

`phy/ar9287/power.rs` is `eeprom_9287.c::ath9k_hw_ar9287_set_txpower` for
a 20 MHz channel: CCK/OFDM/HT20 targets at `calTargetPower*` (the shared
`rates::target` interpolation), `ath9k_hw_get_scaled_power` with
`max_t(u8, antennaGainCh[0], antennaGainCh[1])` plus
`POWER_CORRECTION_FOR_TWO_CHAIN` when both TX chains are set, and the
CMP_CTL/NO_CTL walk over `ctlIndex[12]` reading
`ctlData[i].ctlEdges[ntxchains - 1]` (`rates::limit_with`/`edge_power`).
`ath9k_hw_set_ar9287_power_cal_table` writes the `xpdGain` PD gains to
`AR_PHY_TPCRG1` and, per `txMask` chain, `ar9287_eeprom_olpc_set_pdadcs`
(both chains' `0xa270`/`0xb270` OLPC enables, then the chain's `0xa398`/
`0xb398` reference power from `ar9287_eeprom_get_tx_gain_index`: the matching
pier's signed `pwrPdg[0][0]`, or the C-truncated mean of the bracketing
piers); `initPDADC` (chain 0, pier 0 `vpdPdg[0][0]`) is kept for temperature
compensation. Rate registers follow with `AR9287_PWR_TABLE_OFFSET_DB * 2`
removed and TPC disabled (`AR_PHY_POWER_TX_RATE_MAX = 63`). The whole plan is
validated before the first write; the ceiling is at most 40 half-dB, so the
six-bit fields never wrap. Closed-loop maps (`openLoopPwrCntl == 0`) are
refused: with `AR9287_PD_GAIN_ICEPTS == 1` Linux's
`ath9k_hw_fill_vpd_table` indexes `pPwrList[(u16)-1]` and
`ath9k_hw_get_gain_boundaries_pdadcs` reads past a one-entry VPD table, so
there is no defined detector table to mirror. Smokes (written, not
executed): `smoke_ath9k_ar9287_txpower_two_chain_open_loop_and_ctl`,
`smoke_ath9k_ar9287_txpower_one_chain_uses_first_edge_set`,
`smoke_ath9k_ar9287_txpower_refuses_before_writes`.

`calibration/ar9287.rs` is the AR9287 initial calibration owner (same
`State`/cancellation contract and parked-device preconditions as AR9285):
the signed-ceiling transmit power above, the `ar9280PciePhy` SerDes and
`AR9285_WA_DEFAULT | BIT6 | BIT7` workaround (`ar9002_hw_configpcipowersave`),
`ar5008_hw_init_bb` activation, then the non-AR9285 `ar9002_hw_init_cal`
branch: `FLTR_CAL` set, AGC `CAL` polled for `AH_WAIT_TIMEOUT`, `FLTR_CAL`
cleared (no `OFF_PWDADC` toggle on 9287 1.1+, no CLC or PA calibration).
Noise floor is `ath9k_hw_loadnf` on `AR_PHY_CCA`/`AR_PHY_CH1_CCA` for each
RX chain at the AR9287 nominal -112 (with the Linux NF stop/restart around
the load), the -50 maxCCA restore, `ath9k_hw_start_nfcal(update)` and
`ar9002_hw_do_getnf` (chain 0 always, chain 1 when receiving) sanitized to
`AR_PHY_CCA_{MIN,NOM,MAX}_GOOD_VAL_9287_2GHZ` (-127/-112/-97); a zero reading
is refused. IQ mismatch is `iq_cal_single_sample` over chains
`0..popcount(rxchainmask)` (Linux's `numChains` indexing) with every chain
validated before the first `AR_PHY_TIMING_CTRL4(i)` write and chain-0
`IQCORR_ENABLE`; ADC gain is never run (`supp_cals &= ~ADC_GAIN_CAL`) and
ADC DC (`adc_dc`, `ar9002_hw_adc_dccal_calibrate` with its u32 arithmetic)
is the HT40-only step. `olc_temp_compensation` is
`ar9287_hw_olc_temp_compensation`: PD average against `initPDADC`, scaled by
`tempSensSlope` (minor >= 2, otherwise no correction), written to both
chains' `OLPC_TEMP_COMP`, nothing written before a frame has been sent.
Smokes (written, not executed):
`smoke_ath9k_ar9287_calibration_two_chain_agc_nf_iq`,
`smoke_ath9k_ar9287_calibration_one_chain_leaves_chain1`,
`smoke_ath9k_ar9287_calibration_refusals`,
`smoke_ath9k_ar9287_olc_temp_compensation_follows_linux`,
`smoke_ath9k_ar9287_ht40_adc_dc_offset_correction`.

AR9287 1.3+ (`Revision::ar9287_async_fifo`, `AR_SREV_9287_13_OR_LATER`):
`phy/ar9287.rs::prepare` runs `ar9002_hw_enable_async_fifo` immediately
before the INI (`AR_MAC_PCU_ASYNC_FIFO_REG3` DATAPATH_SEL,
`AR_PHY_MODE_ASYNCFIFO`, SOFT_RESET clear then set; the later
`ar5008_hw_set_rfmode` `AR_PHY_MODE = 4` write replaces that bit exactly as
on Linux). `mac.rs` names the MAC clock: `Clock::Ofdm2g` is the unchanged
AR9285 44 MHz profile, `Clock::AsyncFifo` is `ath9k_hw_set_clockrate`'s
117 MHz with `ath9k_hw_init_global_settings`' `AR_D_GBL_IFS_EIFS_ASYNC_FIFO`
(363 us) and `AR_USEC_ASYNC_FIFO` latencies (`peer_clocked`); SIFS, slot and
the 64/48 us ACK/CTS workaround scale with the clock. `async_fifo_pcu` is
the following `ath9k_hw_reset` block (logic-analyzer DISBUG20768, AHB
custom burst 3, MISC_MODE2 AGGWEP) and `dma_txbuf` takes the chip's
`AR_PCU_TXBUF_CTRL` usable size (0x380 AR9285, 0x700 otherwise). Smokes
(written, not executed): `smoke_ath9k_ar9287_13_enables_async_fifo_before_ini`,
`smoke_ath9k_ar9287_async_fifo_mac_clock_and_pcu`.

`descriptor::select_chains` is `xmit.c::ath_buf_set_rate`'s chain selection
for multi-chain AR9002 parts: on 2.4 GHz `ath_txchainmask_reduction` returns
`ah->txchainmask` unchanged, encoded as `set11nChainSel` (ctl7
`AR_ChainSel0..3`) for each populated series; series-less aggregate
middle/last descriptors are untouched, masks outside 1..=3 are refused and
a one-chain mask leaves the AR9285 encoding byte-identical. Smoke (written,
not executed): `smoke_ath9k_two_chain_descriptor_chain_selection`.

`admission.rs` defines the AR9287 signed board admission record `N87A` v1
(format only; no record or board value is supplied or inferred). `Facts`
binds vendor/device (`0x002d`/`0x002e`), subsystem IDs, EEPROM version,
`AR_SREV` version/revision, RX/TX chain masks, MAC, the complete 726-byte
factory map, the INI write count, the 20 MHz primary and the factory
open-loop power plan at the 40 half-dB maximum into a SHA-256 request
identity, named `ath9k/ar9287-admit-v1-ch<N>-<mac>.bin`. A 128-byte record
must be signer-verified and carry `N87A`, version 1, length 128, the PCI
vendor/device, that identity, MAC, `[channel, 20, rx mask, tx mask]`, the
measured antenna gain (half-dBi, at least the factory
`max(antennaGainCh[0], antennaGainCh[1])`, at most 128) and the qualified
`powerLimit` ceiling (half-dBm, at most 40), with every reserved byte zero.
`Grant::ceiling` removes the measured antenna gain above the factory value
from the host limit and bounds it by the record ceiling; `Grant::invoke`
re-proves the record capability before each use. A missing, unsigned,
foreign or out-of-envelope record leaves the device unadmitted. Smokes
(written, not executed):
`smoke_ath9k_ar9287_admission_record_binds_device_map_and_envelope`,
`smoke_ath9k_ar9287_unprovisioned_or_foreign_record_stays_unadmitted`.

**AR9287 native station (`ar9287_enablement`).** The MAC, packet,
station and interface owners are generic over the calibrated chip.
`mac::Profile` carries the factory masks, MAC clock and `AR_PCU_TXBUF_CTRL`
size: `Profile::AR9285` (1/1, `Clock::Ofdm2g`, 0x380) keeps
`mac::prepare` byte-identical, `Profile::ar9287` uses the factory two-chain
masks, `Clock::AsyncFifo` on 1.3+ and 0x700; `prepare_chip` runs
`async_fifo_pcu` immediately before `ath9k_hw_set_dma` as `ath9k_hw_reset`
does, and requires the retained map's rxMask/txMask (base header offsets
18/19, shared by the 4k and AR9287 maps) to equal the profile. `packet::Port`
gains `mac_clock` (used by `set_peer`) and `tx_chainmask`
(`descriptor::select_chains` on every single-descriptor submission when it
is not 1). `packet_native::Native` holds a `Calibrated::{Ar9285, Ar9287}`
profile; `Native::new_ar9287` binds the PCI ID `0x002d`/`0x002e` to the
grant's device and primary, the exact map length and masks, the factory
`rfSilent` input, the per-channel admitted mask (below) and
the open-loop rate registers `phy::ar9287::power::plan` derives at the
calibrated ceiling, which every physical readback re-checks.
`Calibrated::permitted` re-proves the host permission and, for AR9287,
the signed record (`Grant::invoke`) with `Grant::ceiling(host)` no lower
than the calibrated power. HT, BA, QoS, PS and the AR9285 periodic/ANI
receipts stay AR9285-only (no `ht::Facts`; HT40 retune requests fail
closed).

**AR9287 cold retunes.** `N87A` records are keyed per channel: the record
identity binds the channel, its factory open-loop plan at the 40 half-dB
maximum and the shared map/preparation, and the request filename names the
channel (`ar9287-admit-v1-ch<N>-<mac>.bin`). Each composition sets the
`Native` channel mask to the calibrated primary plus every channel 1..13
whose record verifies (`admitted_mask`); the INI row count is
channel-independent, so a target's expected `Prepared` is known before any
hardware write. `channels::request_geometry` routes a 20 MHz request to
`ar9287_owner::transition` when no AR9285 controller exists, so the
public multi-channel scan, restore and join-to-another-channel paths of
§3.5 are shared unchanged (AR9285 requests take the identical previous
path). `ar9287_owner::reset` holds the shared `CONTROL` mutex and, while the
requesting generation is still current: proves host permission at the
target and loads the target channel's signed record (an absent, unsigned
or foreign record never retires the current generation); retires the
station and requires the DMA-stop proof; requires bus mastering off;
discards the old calibration; repeats `identify_chip` (power-on + warm
reset, `hw.c::ath9k_hw_set_reset_reg`) and requires the identical revision,
identity and factory map; runs `phy::ar9287::prepare` at the target and
requires the record's preparation; bumps the generation and runs the same
`initialize` (calibration under the target's `Grant::ceiling`, AR9287 TX
power at the target, MAC, packet, station, publication). A failed reset
leaves a fresh un-calibrated owner; old authorities never reopen. Smoke
(written, not executed): `smoke_ath9k_ar9287_records_are_keyed_per_channel`.

`ar9287_owner.rs` registers `0x002d` (`ath9k-ar9287`) and `0x002e`
(`ath9k-ar9287e`) with the same singleton address reservation as AR9285.
Probe: `identity::identify_chip(Chip::Ar9287)` →
`phy::ar9287::prepare` at 2412 MHz → `admission::Facts::new` →
`Source::Registered.load`; a missing, unsigned or foreign record parks the
chip (`disable_and_sleep`), logs the request filename and refuses the bind.
Bring-up (scheduled retries on `Policy`): `calibration::ar9287` runs under
`Permission::with_ceiling(Grant::ceiling(host))` with the record and the
host permission re-checked on every poll; then `Native::new_ar9287` →
`mac::prepare_chip` → optional MSI → `Packet::prepare` → `station::Radio`
(noise seed: chain-0 sanitized NF) → `interface::publish`. Periodic:
every `ATH_LONG_CALINTERVAL` (30 s, `link.c::ath_ani_calibrate`) the
supervisor runs the `ar9002_hw_calibrate(longcal)` AR9287 step,
`ar9287_hw_olc_temp_compensation`, through `Station::long_calibration` →
`Packet::long_calibration` (no transmission in flight) → `Native` under
`access` (PCI, physical readback, permission, record). PA offset
calibration is AR9285/AR9271-only on Linux and ADC DC is an HT40
per-calibration, so neither runs on this 20 MHz owner. Remove (under
`CONTROL`) retires the station, proves DMA stopped and only then releases
the address. Generation reset: the supervisor polls every 500 ms as the
AR9285 one does and, once the published generation is terminal,
runs `ar9287_owner::reset` at the retained primary (bounded to three
failures; `DeviceGone`/`BadState` stop it; a pinned or removed owner is
never followed). System suspend takes `CONTROL` (Busy while a reset is in
flight), retires the station and FULL_SLEEPs the chip; `pm_resume`
(`pci.c::ath_pci_resume`) re-disables PCI RETRY_TIMEOUT (config 0x41) and
spawns the same reset, which republishes a fresh generation. Smokes (written, not
executed): `smoke_ath9k_ar9287_mac_profile_two_chain_async_fifo`,
`smoke_ath9k_ar9287_native_profile_binds_admission_and_chains`.

Known AR9287 gaps: periodic NF/IQ
per-calibration is not run (only the long-calibration temperature
compensation); HT20/HT40 TX power and every HT owner are out of scope as for
the AR9285 legacy base; closed-loop maps stay refused. No physical AR9287
receipt exists.

SoC/AHB parts (AR9100, AR9330/9340, QCA955x/953x/956x) and the USB
`ath9k_htc` AR9271/AR7010 driver are outside this PCIe driver.
Physical acceptance for the initial profile covers EEPROM, RF calibration,
polled channel/DMA, scan/association/IP traffic and terminal link loss/stop.
