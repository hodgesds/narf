# ath9k — Specification

> Status: **AR9285 retained channel1 legacy station and optional measured
> HT20/1SS long-GI, RX STBC1, native RTS/CTS protection and recipient BA
> continuations implemented.** Native software functional validation passed in
> the coordinated x86_64 and aarch64 scoped Wi-Fi suites. Physical EEPROM,
> calibration, RF and DMA
> acceptance remains pending. Wider channels, recovery and other chips are separate.
> The additional bounded two-MPDU sender BA/A-MPDU continuation below is
> implemented with ten new native smokes passing the coordinated validation
> on both architectures. AR2427 (`168c:002c`, AR9285 silicon with HT bonded
> out) shares the legacy owner with every HT/BA source closed.
> The optional measured `N85Q` continuation (§3.4) adds four-AC EDCA on
> QCU0..3 and eight-TID classification/scheduling on the same owner.

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
- `with_controller()` provides read-only `Ath9k` inspection; it returns `None`
  while the retained async mutex is busy. Address ownership remains retained
  independently of that inspection lock, including after a failed probe.
- `Ath9k::identity` exposes the silicon revision, validated unicast MAC,
  EEPROM version, factory regulatory-domain values, and chain masks.
- `Ath9k::calibration()` exposes the complete 376-byte normalized
  `ar5416_eeprom_4k` image for later PHY calibration programming.
- `Ath9k::baseband` reports `BasebandPrepared`: the 2412 MHz reference
  frequency, selected EEPROM high-power gain/SYNTH9 XE2 variant and count
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
- `calibrate_radio()` is the channel1/full-rate/20MHz continuation.
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
  Driver-owned CCK/OFDM rate and channel1 elements precede publication. Each
  probe waits for its exact native terminal TX completion within the total
  bounded dwell; broadcast completion does not claim an over-air ACK.
  Current signed policy, PCI authority and RF-silent input constrain every
  publication. Discovery is limited to the unassociated initial channel;
  scans while associated return Busy without changing carrier. Failure or
  cancellation hides the partial cache, closes the owner and retains DMA.
- Synchronous bounded packet progression services polled RX/TX with hardware
  IRQs masked. Every transmit rechecks current signed policy and factory
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

## 4. Invariants

- PCI parking is verified by command-register readback before BAR sizing: BME
  and memory decode off and INTx masked. Decode is enabled only after sizing
  writes are restored; MMIO follows that readback. Additional
  matched singleton radios are parked with BME/memory decode off and rejected.
  Repeated dispatch of the owned address fails before parking.
- BME, MAC RX, all ten TX queues and interrupts remain disabled throughout
  identification, preparation and calibration. PHY activation is confined to
  the policy-bound calibration continuation; packet rings are allocated only
  after its complete retained receipt. The common table's cleared DIAG_SW is followed by restored
  RX_ABORT/RX_DIS, which remain set through calibration.
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

- `additional_channels`, `channel_retuning`: every live owner is bound to
  2412 MHz. `packet_native.rs::Native::new` and `ht::Facts::new` reject any
  calibration report whose frequency is not 2412; `phy/channel.rs` is invoked
  only for the inactive reference; the one-shot calibration receipt cannot be
  replayed without the full generation reset; and the `N85H/N85B/N85T/N85Q`
  bodies fix primary channel 1 at offset 54 while each `invoke` intersects
  only host rules overlapping 2402-2422 MHz. Linux retunes through
  `main.c::ath9k_config` -> `channel.c::ath_chanctx_set_channel` ->
  `main.c::ath_reset_internal` -> `hw.c::ath9k_hw_reset` (per-channel INI,
  `ar9002_phy.c::ar9002_hw_set_channel`, spur mitigation, calibration and
  `ath9k_hw_do_fastcc`). Closing these needs a per-channel calibration
  report/permission and a channel-set field in every signed record (a v2 of
  all four formats), plus multi-channel scan. Signed HT40 has the same
  dependency.
- `ht40`, `sgi40`: Linux `common-init.c::ath9k_cmn_setup_ht_cap` advertises
  `SUP_WIDTH_20_40 | SGI_40` for AR9285, but HT40 needs a secondary channel
  (rejected by `ht::response` and `Profile::observe`), the extension
  channel/`AR_PHY_TURBO` dynamic 20/40 programming, HT40 CTL/target-power
  planning (`phy/rates.rs` plans only CCK/OFDM/HT20) and the multi-channel
  record above; SGI40 depends on HT40 (`N85H` byte 57 fixes GI 0).
- `factory_profile_selection`: the production owner accepts only the AR9285
  `eeprom_4k.c` 376-byte map, version 14.1+, chain masks 1/1 and the
  channel1 plan (`identity.rs::decode_identity`, `phy/`). The spec line names
  no further Linux variant to select; the enumerated variants are the chip
  rows below.
- `periodic_calibration`: Linux `link.c::ath_ani_calibrate` runs a short IQ
  calibration (`ATH_STA_SHORT_CALINTERVAL` 1 s) until done and a 30 s
  (`ATH_LONG_CALINTERVAL`) long calibration
  (`ar9002_calib.c::ar9002_hw_calibrate`: `ar9285_hw_pa_cal(ah, false)`
  incremental PA tracking, `calib.c::ath9k_hw_getnf/loadnf/start_nfcal`),
  plus ANI. `calibration.rs` is a one-shot `New -> Running -> Ready` owner
  that runs before packet preparation and cannot be re-entered while the
  rings run; PA tracking changes live transmit gain, which the `N85H`
  envelope explicitly excludes ("Periodic tracking is not inferred"). It needs
  a live-owner calibration hook and its own measured tracking record.
- `larger_tx_aggregates`: the sender owns exactly two maps/descriptors
  (`packet.rs` `TX_DEPTH = 2`, `submit_pair(&[Vec<u8>; 2])`,
  `tx_ba/protocol.rs` pair state and two-bit BA accounting) and `N85T` v1
  fixes member count 2 and 4095 air bytes. Linux `xmit.c::ath_tx_form_aggr`
  builds up to the BAW/`ATH_AMPDU_LIMIT_MAX`/4 ms limit. It needs N-slot TX
  storage, an N-member chain/retry/bitmap owner and an `N85T` v2 member count.
- `tx_amsdu`: Linux ath9k never sets `IEEE80211_HW_TX_AMSDU`
  (`init.c::ath9k_set_hw_capab`), so mac80211 forms no TX A-MSDU for this
  driver and there is no Linux reference path. Natively the TX maps are
  `descriptor::MAX_MPDU + 2` (2306) bytes and `descriptor::transmit_ht`
  rejects longer frames; `N85H` hashes "noTXAMSDU". The shared
  `station_security::transmit_amsdu_qos` encoder exists but needs larger maps
  and a separate measured record.
- `idle_full_sleep`: Linux `main.c::ath_ps_full_sleep` aborts RX and enters
  FULL_SLEEP only while mac80211 reports `IEEE80211_CONF_IDLE`, and leaving
  idle reprograms the channel through `ath_reset`. Natively the only
  FULL_SLEEP entry is the suspend path (`identity::disable_and_sleep`); every
  `Port` register access assumes AWAKE and no use-counted wake wraps the
  packet/irq/station owners, and the station has no idle notion distinct from
  its passive scan cache, which keeps RX running.
- `station_network_sleep`: Linux sets `SUPPORTS_PS` only with
  `ps_enable=1` (`init.c`, default off). Natively there is no beacon-timer
  programming (`ath9k_hw_set_sta_beacon_timers`), TIM parsing, PS-Poll or
  NULL-data PM signalling, and IMR_S5 TIM_TIMER stays cleared (`irq.rs`).
- `host_bus_pm`: `narf_bus::pci::upstream_bridge` now finds the parent
  bridge, but no API lets a function driver read it: `pci_express::read_status`
  needs a `Cap<BusDeviceCap, Read>` for the bridge itself (only the TCB
  registry authority can mint one, by claiming the bridge) and omits Link
  Control. The missing shared API is a read-only parent `PCI_EXP_LNKCTL`
  accessor derived from the child's capability. The AR9285 power-off half
  cannot land alone: `hw-ops.h::ath9k_hw_configpcipowersave` returns unless
  `ah->aspm_enabled`, which only `pci.c::ath_pci_aspm_init` sets from that
  parent read.

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
(`AWAKE`, `FULL_SLEEP`, `NETWORK_SLEEP`) and their callers. The current owner
forces `AR_RTC_FORCE_WAKE` during reset and stays `AWAKE`; AR9285 lacks
`ATH9K_HW_CAP_AUTOSLEEP` (`hw.c::ath9k_hw_fill_cap_info`), so every sleep entry
must be software-forced. Remaining named operations:

- `idle_full_sleep`: `main.c::{ath9k_ps_wakeup,ath9k_ps_restore,ath_ps_full_sleep}`
  use-counted wake, 100 ms idle timer, RX abort/DMA stop and `FULL_SLEEP`,
  with `hw.c::ath9k_hw_setpower` restoring `AWAKE` before register access.
- `station_network_sleep`: `NETWORK_SLEEP` station power save with
  `beacon.c::ath9k_beacon_config_sta`/`hw.c::ath9k_hw_set_sta_beacon_timers`
  TIM/DTIM timers and beacon/CAB/PS-Poll/TX-ACK wake conditions. Linux leaves
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

Every chip row shares these tree blockers: `identity.rs::identify` rejects
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

SoC/AHB parts (AR9100, AR9330/9340, QCA955x/953x/956x) and the USB
`ath9k_htc` AR9271/AR7010 driver are outside this PCIe driver.
Physical acceptance for the initial profile covers EEPROM, RF calibration,
polled channel/DMA, scan/association/IP traffic and terminal link loss/stop.
