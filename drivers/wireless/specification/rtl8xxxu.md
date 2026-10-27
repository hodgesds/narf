# rtl8xxxu — Specification

> Status: runtime RTL8188EU factory/FIFO/firmware/MAC/BB/RF + LC/IQK implemented;
> retained channel1 Open/WPA2 station service implemented; broader software
> profiles, reset/rejoin and physical acceptance remain incomplete. A separately
> qualified RTL8188EU HT20/LGI SISO continuation passes14 native regressions
> on both architectures; exact-device qualification remains external.

## 1. Purpose & scope

Owns the Realtek USB match table, register/packet helpers and retained
RTL8188EU async firmware owner. Other matched families remain detection-only.

## 2. Assumptions

The USB enumerator supplies an addressed, configured `Arc<USBDevice>`.
Authenticated firmware must already be installed in the NARF registry before
probe. Initialization powers the RF blocks for register-table setup while
MAC TX/RX stays closed until the separately admitted retained service starts.
The initial service requires signed per-device board qualification and signed
deployment policy; broader software prerequisites are listed below.
Policy decoding uses `narf_wireless::reg::policy::load()` inside current
firmware capability invocation. Each attach still requires a fresh signed
artifact rather than accepting the shared cached regulatory domain.

## 3. Public interface

`rtl8xxxu_probe` retains the handle and `firmware_transport::Owner<UsbControl>`.
For RTL8188EU it spawns `wait_initialize_registered()` and `interface::wait_attach()`
after releasing the device registry lock, logging the discovered eFuse calibration
key `power_policy::Calibration::asset_name(factory)`. That production path continues
through factory identity, FIFO/queue boundaries, firmware, MAC/BB/AGC/RF tables
and checked post-table MAC/LC/IQK initialization, pausing at the pre-attempt
`Detected` and post-IQK `RadioReady` checkpoints when `rtlwifi/rtl8188eufw.bin`,
`rtl8xxxu/rtl8188eu-cal-v1-<mac>.bin` or `wireless-regulatory.bin` has not been
staged yet while failing immediately on invalid or unsigned artifacts. Duplicate
registration compares the retained Arc identity, instead of conflating equal slot numbers on different USB controllers.

`Owner::status()` reports detected, validated, factory-ready, powered,
downloading, firmware-ready, initializing-tables, tables-ready, calibrating,
radio-ready or terminal failed state. Radio-ready means checked initialization
with MAC TX/RX still closed before the separately admitted station service. `Owner::calibration()` exposes the selected full
TX/RX IQ coefficients only after successful completion. `Owner::factory()` returns the checked RTL8188EU factory identity
and calibration snapshot. `initialize_device(blob)` runs the production
factory/FIFO/firmware/table/calibration sequence for authenticated-byte owners/tests.
The firmware-only `initialize(blob)` remains a diagnostic entry point.
Registered-source lookup/copy/header parsing finishes before the atomic hardware
attempt begins. Missing, revoked or invalid staged inputs leave Detected retryable
without USB requests; a later valid installation continues the same owner. Once
hardware has begun, a second attempt returns `AlreadyStarted` before any new
registry lookup or I/O. Dropping an
active attempt records `Cancelled`; it cannot silently replay. Deadline,
transport errors (including ambiguous xHCI errors) and cancellation poison the
one-shot owner: no cleanup read/write, retry, or other EP0 operation follows.
Recovery requires controller-proven endpoint stop/drain and a fresh USB device
lifecycle; a new software owner alone is insufficient.

Image validation requires the complete 32-byte little-endian RTL8188E header,
signature family `0x88e0`, nonempty exact `ramcodesize` and at most eight 4 KiB
pages. Validation/unsupported-family failures occur before USB. Registry lookup and the bounded owned copy occur inside actual current registry
and firmware-blob capability invocations; pure image parsing and USB awaits use
only that owned storage. No borrowed blob view escapes invocation. Signed board
qualification uses the same current lookup/copy boundary, retaining its existing
mandatory signer and exact factory/VID/PID binding. Executable developer policy
remains the firmware registry/build contract.

`ControlIo` provides configuration-descriptor reads, async exact-count
register reads/writes and delay; `UsbControl`
uses vendor EP0 request `0x05`, index zero, value=register address. Firmware
pages use 196-byte control writes at `0x1000`, with the page selected through
`MCU_FW_DL+2`. Firmware bytes never use a bulk packet endpoint.

`device_init::endpoints(config)` validates the active vendor interface's
bulk descriptors and derives 1–3 OUT queue geometry. Factory reads reject test
silicon/I cut, use the sparse logical map, validate RTL ID `0x8129` and nonzero
unicast MAC at `0xd7`, and retain CCK/HT40 power bases, crystal, thermal and
board fields. All table writes check exact transfer counts, RF addresses keep
all eight bits, and Linux RF delay markers are delays. LLT installs the
176-entry split with TX end 169 and a 170–175 ring after FIFO boundaries.
The post-table sequence programs RX/report geometry, filters, EDCA, beacon
parameters, initial factory gain indices and the hardware security gate. It
awaits CAM invalidation, performs RF HSSI reads with complete eight-bit
addresses and PI/SI readback selection, runs LC preserving prior continuous-
TX/pause state, then performs up to three full TX/RX IQK attempts with two
retries per path. It restores saved ADDA/BB/MAC registers after completed
attempts and accepts a full stable coefficient set; partial/fallback IQK is
rejected. Signed IQ matrix, thermal meter and NAV setup finish initialization.
Erased/out-of-range factory gain indices fail before gains are programmed.
MAC TX/RX remain closed: radio-ready is not regulatory, scan or packet ready.

The production table/calibration path now sets the initial 20MHz channel1
and both factory crystal-cap fields before LC/IQK. `channel_runtime` rejects
live MAC TX/RX and invalid channel geometry before channel writes. It does
not implement retune or infer transmit power from factory gain indices.

`power_policy::Calibration` loads a signed, exact-device power qualification
artifact; [the N8PC v1 contract](rtl8188eu-power.md) defines its bounds and
required physical input. Registry signer metadata is mandatory even in an
unsigned-firmware development build. The artifact binds USB VID/PID,
chip/cut/profile and all retained factory fields. Its measured per-channel
CCK/OFDM gain upper bounds, maximum antenna gain and qualified EIRP are
intersected with every overlapping authenticated regulatory rule. Unknown
points are never interpolated and indices never exceed factory bases. The
opaque `Permission` binds the selected gains to that exact device/channel;
there is no default calibration or cross-chip dBm conversion.

`ControlIo::identity()` supplies immutable descriptor VID/PID (default absent);
`UsbControl` obtains it from the retained device and `Owner::usb_identity()`
returns the constructor snapshot. Private native TX activation rechecks the
power token against the actual retained identity/factory/channel, programs
and reads back each CCK/OFDM gain lane and exact response-rate bitmap1 while
TX is closed, and only then verifies MAC TX-open. Gain/TX-gate cancellation
or error is terminal without EP0 cleanup. Only the retained station owner can
submit local native management frames through this gate; it is not a public
injection or controlled-port API. Successful pause closes TX/RX before host
Stop and resumes RX-only, requiring fresh TX activation. No real board curve
is provided or qualified by this software change.

`receive_runtime::Receiver` composes the retained firmware and packet owners
for policy-admitted channel1 reception and private qualified TX activation. `Permission::from_domain` bounds
the caller-authenticated regulatory profile and grants no TX gain authority.
Construction requires radio-ready/full IQK, snapshots checked descriptors,
and permanently claims the radio once. `start` posts persistent USB RX before
opening and verifying MAC RX with TX still closed; `stop` verifies MAC closure
before proven USB Stop/SetDeq. Only successful same-channel stop permits
restart. Cancellation/transport failure is terminal without cleanup or a
new claim; unretired USB receipts stay owned. Quiet polls preserve the TD.
Unexpected hardware-decrypted metadata and non-MPDU reports do not reach
native management/data dispatch. Firmware status adds starting-receive,
receiving and receive-stopped states. This entry point is now bound to
the probe's network service worker only after signed board/deployment admission.

`management_runtime::{Candidate, Join}` admits native channel1 beacon/probe
identity and strictly bounded IEs, requiring a basic 1Mbps rate matching the
actual Realtek descriptor's rate0. It uses the shared
`narf_wireless::association::JoinPlan` for Open/WPA2 frame preparation and
peer/phase/status/AID transitions, stamps software sequence numbers, and
preserves the original AP RSNE/RSNXE separately for retained RSNA binding.
Protected/decrypted/fragmented/HT/40MHz management frames and mismatched
direction/address identity fail admission. A matching rejection or AP
teardown terminates the plan. Returned management frames still require a
policy-admitted transmitter; `Associated` does not open the controlled port.

`ccmp_runtime::Key` is the software CCMP dependency for the retained station
runtime. `ccmp_runtime` and `security_runtime` retain their public paths as
reexports of shared `narf_wireless::{packet_key, station_security}` owners.
`packet_codec::Mpdu` supplies the shared raw-frame admission contract while
preserving the exact RTL8188EU legacy/20-MHz or separately qualified HT20/LGI,
rate, and no-hardware-decryption checks. `Role::Pairwise` admits KeyID0; `Role::Group` admits IDs0–3 but is
receive-only. TX requires ToDS, peer RA/local TA; RX requires FromDS, peer TA,
a unicast source and local RA for PTK or multicast RA for GTK. Only Data/QoS
Data with exact native header extents is admitted by the ordinary key API;
fragments/A-MSDU fail there. The distinct whole-aggregate receive path below
uses the shared transactional A-MSDU API.
CCMP reserved bits, ExtIV, key ID and the 4096-byte body bound are checked
before crypto. Each key owns 16 QoS plus a separate non-QoS replay tracker;
MIC failure leaves ciphertext and all trackers unchanged. TX consumes a
non-wrapping 48-bit PN before USB ownership, and same-key `reinstall` preserves
TX/RX counters. Keys and temporary encryption storage zeroize on drop. A
fresh-key constructor must not replace an identical live/retired key; station
integration retains key slots across EAPOL retries. The key primitive itself
does not publish a station or open the controlled port.

`interface::attach` now composes the production RTL8188EU path after probe's
successful firmware/table/full-IQK attempt. It requires current network
registration authority, exact-device signed power calibration and a signed
`wireless-regulatory.bin` NRGD policy; the mutable global domain alone does
not authenticate deployment policy. Missing/invalid artifacts retain the
diagnostic radio without publishing a netdev. Native bulk traffic derives
its USB handle directly from `Owner<UsbControl>`: EP0 and packets cannot be
paired with different controllers, slots or generations. The first admitted
radio reserves one station service; cancellation cannot silently replace it.
No physical board qualification data is included in the repository.

The admitted service publishes `WirelessNetIface` and Ethernet Narf-Rings
with channel1/20MHz/basic1Mbps, Open or WPA2-PSK/CCMP and PMF disabled. The
distinct optional HT20/LGI program below supplies factual HT capability only
after its parked native programming succeeds. VHT, HE, EHT, external EAPOL,
packet offloads, live retune and power overrides are not advertised. Passive scans poll the same persistent native RX owner,
cache at most32 peer-bound candidates for10s and honor bounded passive dwell;
unknown RSSI is represented by `i8::MIN`, never a fabricated measurement.
Optional SME elements are validated and forwarded through the shared join
plan before the sole radio is moved. Invalid requests leave passive ownership
unchanged. Publication does not make an unassociated carrier usable.

`station_runtime::Station` owns native authentication/association, exact USB
TX receipt deadlines, bounded peer/phase timeouts and connected firmware media
state. Linux port0 start enables management/data filter maps and IGI; station
setup suppresses local beacons, programs ATIM/beacon-function/TSF state,
MSR/BSSID/slot, then ends passive scanning. Association binds AID and the
Gen2 MEDIA_STATUS mailbox to the same peer. Verified AP responses, firmware
media setup and host TX delivery remain separate proofs. Drop/error during
any awaited radio/media operation is terminal without cleanup or retry.

`security_runtime::Security` retains `Supplicant::with_rsna`, binding EAPOL
to the own/AP native addresses and the original AP RSNE/RSNXE. Production
SNonce material comes only from `narf_crypto::try_fill_random_bytes`. One
pre-TX sample is retained until the first validated M1 consumes it; subsequent
samples are requested only at shared RSNA's new-M1 renewal boundary. Idle RX,
data, M1 retries, M3/Group1 and pending-reply waits do not request entropy.
Required entropy failure closes admission and never falls back to timing
counters. Proposed
PTK/GTK changes stay pending until the exact owned M2/M4/Group2 native receipt
completes. Rekey replies use the still-installed old packet key; identical
material retains PN/replay counters. A lifetime history of16 key materials
rejects retired/cross-role reuse and fails closed when exhausted. The data
port opens only after verified RSNA and exact M4 delivery, closes while a
reply is pending, and packet clients cannot inject EAPOL. A pending rekey
preserves carrier identity while withholding data admission. Group KeyID0 is
receive-only; all key/TID counters use the strict CCMP owner described below.

`service_runtime::Service` and the network adapter retain these actual owners
under a regular async mutex. Both its worker and synchronous network drains
poll the same USB receipts/RSNA/crypto path; the latter uses `try_lock`, never
`block_on` or another task's progress. Stack receive callbacks run after all
driver/ring guards are released, so ARP/ND may reenter transmit safely. Native
plaintext crosses to Ethernet only through checked RFC1042/address/profile
admission. Packet queues and per-step RX processing are bounded.

The composed Open/WPA2 fixture now drives the production `Device`, `Service`,
`Station`, register initialization and native bulk descriptor/receipt owners
through channel1 passive scan, authentication/association and shared RSNA to
the real kernel DHCP client. A shared `FakeAp` in its explicitly selected
basic1Mbps profile verifies management/EAPOL, while `DhcpServer` supplies a
transaction-bound lease. WPA2 data crosses the native USB seam as actual
software CCMP ciphertext; the peer checks MIC/replay before observing DHCP.
Exact uplink bytes at the AP and downlink bytes in both Narf-Ring and stack
dispatch prove post-lease bidirectional Ethernet/IP composition. The adapter
publishes physical carrier metadata only after station authorization and clears
it on disconnect or terminal failure, independently of the host DHCP lease.
Quiet polls preserve the RX receipt; held M4 prevents DHCP; timed-out data and
failed USB stop retain uncertain RX/TX receipts and reject reuse. Successful
disconnect closes MAC admission and retires the actual native receipts.

Inert EP0/bulk registers, synthetic firmware bytes and explicit private
qualification/entropy inputs supply the hardware seam; the AP and DHCP server
are test peers. Vendor firmware execution is not simulated. The fixture's
synthetic signed-metadata parser boundary neither installs a registry blob nor
qualifies a real board; production `attach` still
requires current authority, signed exact-device calibration and signed policy.
This establishes one-shot channel1 software composition, not RF delivery,
radio ACK, xHCI/silicon acceptance or reset/rejoin readiness. Hardware validation
must provision real board evidence and use a fresh USB lifecycle after stop or
failure; broader channels, rate modes, automatic recovery and PM remain outside
the minimum initial profile.

Explicit disconnect closes host admission before awaiting Linux TSF-disable
and disconnected media state, verifies MAC TX/RX/filter closure, then uses
proven USB Stop/SetDeq to retire outstanding native receipts. Cancellation
retains them terminally. AP unicast/broadcast deauth/disassociation and peer
loss close the carrier. This first service allows one association per
firmware claim; a stopped or failed owner cannot construct fresh keys/radio
state for rejoin. Controller-proven EP0 reset/recovery and safe rejoin remain
software work; successful initial association is not that recovery proof.

Disconnect publishes down immediately and repeats that publication after
acquiring device state, the same mutex held by every up publisher. A previous
association/progress owner therefore cannot leave stale carrier or BSSID after
teardown. A deterministic composed-USB regression holds that mutex, polls the
early close, publishes the old authorized peer, then releases teardown; it
checks down metadata, rejected TX and retired receipts before any repair poll.

`packet_codec::{receive,transmit}` and `packet_transport::Owner<UsbIo>` are
the native USB transport dependency. RX uses the physically 24-byte
`rxdesc16`, complete PHY/shift extents, packet count and 128-byte aggregate
alignment. Reports remain separate raw post-descriptor records; CRC/ICV-bad
MPDUs are dropped. No translated-Ethernet fallback exists. TX uses the Linux
32-byte descriptor, native DA multicast bit, software sequence, XOR checksum
and a fixed legacy1Mbps default, with distinct qualified MCS selection below.
The admitted station profile requires a
2.4GHz/20MHz AP supporting that basic rate; no HT/VHT mode is implied.

The packet owner posts one persistent 4096-byte RX receipt, keeps it over
indefinite quiet polls, copies/validates exact completions before reposting,
and serializes TX through descriptor-derived management/BE endpoint mapping.
USB completion means host delivery, not a radio ACK. Every transfer/extent
failure is terminal without buffer reuse. `Owner::stop` uses the USB proven
Stop Endpoint/Set TR Dequeue contract; drop/error keeps unretired receipts and
fails the owner. Successful stop permits a restart only on its immutable
channel. RF/FIFO quiescence before retune is separate software work: changing
a channel label cannot qualify queued RX bytes. Production service composition
opens MAC admission only after signed channel/power qualification and opens
the WPA2 controlled port only through retained shared RSNA.

Legacy synchronous stripped-payload loading returns `UseAsyncOwner`; the old
unverified all-radio helper returns `NotImplemented` before transport access.

Physical carrier/peer publication does not change operator `IFF_UP` and never
invokes administrative open/stop hooks while retained driver state is locked.
Explicit registration, operator up/down and autoconnect remain administrative
events. Disconnect/failure clears carrier and peer identity while preserving an
operator-UP interface; a later physical carrier sample cannot undo operator DOWN.

### Negotiated RTL8188EU WMM (all ACs/TIDs)

A valid AP WMM Parameter element selects an optional legacy QoS station.
The driver appends its own Information IE requesting no U-APSD and requires
valid parameters in the actual peer-bound association response before native
EDCA/connected media admission. Missing, duplicate, malformed or BE-ACM
parameters are terminal; unsolicited response WMM cannot upgrade a legacy
request. All four rows must have supported ECW/AIFSN geometry and fit the
hardware8-bit AIFS field before any EDCA write.

Linux `rtl8xxxu_conf_tx` plus `rtl8xxxu_set_aifs` supply BE/BK/VI/VO registers
0x508/50c/504/500, ECW/TXOP fields and SIFS10 plus AIFSN times9/20us slot.
Every EP0 write has an exact readback. BE stays conservative (AIFSN>=3,
ECWmin>=5, ECWmax>=10, TXOP0); BK/VI/VO use the AP rows. As in
`rtl8xxxu_conf_tx`, REG_ACM_HW_CTRL BK0/BE1/VI2/VO3 mirror each AC's ACM
(`wmm_runtime::acm_bits`; BE ACM is refused). Only then may the retained bulk
owner admit QoS DATA with TXDESC32_QOS. This WMM grant keeps HT/BA, U-APSD,
TSPEC and QoS Null closed; the distinct HT grant below cannot be inferred from it.

#### Traffic classification and all-AC/TID routing (implemented)

`station_runtime.rs::send_ethernet` classifies each Ethernet frame with
`cfg80211_classify8021d` (DSCP/RFC 8325, MPLS TC, 802.21) and mac80211
`ieee80211_downgrade_queue` over the AP ACM rows (shared
`rtlwifi::wmm::priority`), writes that TID into the QoS control before
software CCMP (also the CCMP nonce priority) and keeps per-TID SN spaces
(Open: `qos_sequence`; CCMP: shared `Security`). `packet_codec.rs` accepts QoS
DATA TID0..7 with normal ACK and sets TXDESC queue per
`rtl8xxxu_queue_select`/`rtl8xxxu_80211_to_rtl_queue`: BK2, BE0, VI5, VO7,
MGNT0x12 (the TID itself is not a descriptor field upstream).
`packet_transport.rs` selects the bulk-out pipe from
`rtl8xxxu_init_queue_priority`: one endpoint carries all; two put VO/VI on
out_ep[0] and BE/BK on out_ep[1]; three put BE/BK on out_ep[2] and VI on
out_ep[1], and VO also on out_ep[1] because upstream derives `vop` from
`viq ^ 3`. This matches the TRXDMA_CTRL/RQPN mapping already programmed by
`device_init::pre_firmware`. Smoke
`smoke_rtl8188eu_wmm_classifies_dscp_to_all_tids_queues_and_bulk_pipes`
(Open and WPA2) checks the pipe table for1/2/3 endpoints, each AC's
queue/DCI, per-TID SN, CCMP priority at the fixture AP, REG_ACM_HW_CTRL and
the VO->VI and VO+VI->BE downgrades.
Open frames and host CCMP use the26-byte header; CCMP protection occurs before
USB staging, and the shared key owner retains per-key/TID replay state.

The same signed N8PC legacy1T gain/response envelope qualifies unchanged PHY
rates, gain, channel, antenna and autonomous response power. Before a WMM attempt
the exact signed calibration cap is retained and compared against its existing
permission under authenticated policy. Each future poll during start, EDCA and
association invokes that cap and rechecks the current installed country/power
permission; active work never bootstraps a cleared policy. Packet publication
and completion also require this retained proof. Missing/changed/revoked proof
is terminal and cannot publish QoS, reuse pending USB storage or revive carrier.
Bound AP parameter changes still require a fresh lifecycle: upstream
mac80211 re-runs `rtl8xxxu_conf_tx` when a beacon's WMM Parameter Set Count
changes, but the Open-phase network path here is synchronous and cannot yet
issue the async EP0 EDCA writes (remaining `live_edca_updates`).

Two native Rust smokes compose actual EP0/bulk owners through Open/WPA2,
literal EDCA/TXD values, exact QoS/CCMP data, actual cap loss, malformed response,
held EP0 cancellation and revocation before repoll. Controller-proven reset,
safe rejoin, additional AC/channel/rate profiles and physical USB/RF acceptance
remain separate gates.

### Measured legacy-rate selection on the WMM station path

The current signed WMM owner now selects the fastest ordinary DATA rate from
the actual bound association response/request intersection, ordered
54,48,36,24,18,12,11,9,6,5.5,2,1Mbps. Source TXDESC32 DATA_RATE low6 bits
are programmed before the descriptor checksum; USE_DRIVER_RATE and disabled
fallback keep the chosen rate explicit. Management and EAPOL remain CCK1,
and the unchanged legacy station path remains fixed CCK1. This extension uses
only N8PC's existing explicit whole-board CCK/all4 and OFDM/all8 measured
envelopes; it does not qualify HT or change autonomous response gains/rates.
The retained current source/policy fence still encloses admission and native
USB publication. One composed native smoke exercises all12 literal rates,
response narrowing, Open/WPA2 native data/CCMP, exact checksum and source
revocation with no extra publication and retained posted RX ownership.

### Separately qualified RTL8188EU HT20/LGI

`firmware_transport::Owner::ht20_request()` resolves the optional measurement
filename and exact source/program binding without writing registers or granting
HT permission. The retained successful registry loader now keeps the actual
uploaded image's SHA256 and firmware capability. Every resumed EP0 operation,
HT continuation and packet/publication admission checks that current source;
a matching filename or retained digest alone cannot replace it. An unauthenticated
supplied-image owner cannot authorize this production continuation.

The optional signed record is
`rtl8xxxu/rtl8188eu-ht20-lgi-v1-<factory-MAC-as-12-hex-digits>.bin`.
It has magic `N8HT`, version1 and length1184: a160-byte header followed by eight
64-entry signed-i16 conducted-peak upper-envelope curves, one per MCS and raw
gain index. `i16::MAX` means unknown, never zero power. Header bytes12..16 bind
USB VID/PID;16..48 bind the source/program SHA256;48..77 bind the exact29-byte
legacy factory identity;77..80 are zero;80..112 bind the exact preceding N8PC
digest;112..118 repeat the MAC;118..124 are `[1,20,1,0,0,0]` for channel/width/
streams/LGI/no aggregation/no tracking;124..128 hold antenna gain and qualified
EIRP ceiling;128..160 are zero. The program binding additionally includes the
actual uploaded executable digest and the complete native HT/control/receive
recipe. Old N8PC records cannot grant MCS transmission by supplying extra IEs.

Qualification must bound the whole unchanged static antenna/LC/IQK/legacy/
automatic-response program, supply and thermal0..63 envelope, all new MCS
conducted peaks and native decline traffic. No real measured artifact is
provided. Antenna gain cannot be lower than the legacy bound; selected peaks
plus antenna must satisfy the signed HT ceiling, current deployment ceiling
and the unchanged legacy operating envelope. Missing optional HT data preserves
the legacy station. Invalid, unsigned, foreign or unqualified present data fails
pure preflight before the singleton/receive claim or USB publication.

This is the EU source path, not an EE gain-table clone. Linux
`8188e.c::rtl8188eu_parse_efuse` copies CCK and HT40 bases but does not populate
the FU/EE HT20 difference. The selected `8188f.c::rtl8188f_set_tx_power` therefore
uses the EU's zero-initialized difference and channel1 `ht40_base[0]` as its
factory MCS ceiling. No signed EE nibble, PG offset or inferred dBm conversion
is imported. The native owner programs and reads back MCS0..3/4..7 at0xe10/e14
with MAC TX/RX parked, before posting its first persistent RX TD. A running
legacy station cannot call this operation or upgrade in place. Unused2SS gain
lanes retain the source's factory state and grant no2SS descriptor admission.
Source OFDM SIFS remains16us (`REG_SPEC_SIFS`), preserving CCK10; negotiated
HT EDCA uses16 plus the actual9/20us slot times AIFSN, with the existing BE
clamp. This is distinct from RTL8188EE's14us SIFS recipe.

Scan and join use shared typed `observe_with_phy`/`JoinPlan::prepare_with_phy`
and owned HT/WMM IEs. Local RX/TX supports mandatory MCS0..7, HT20/LGI and
default3839-byte A-MSDU. Complete selected response HT Cap45/Operation61 must
bind the original peer/primary1 offer,20MHz, supported protection mode and WMM.
No mandatory membership selector is stripped. DATA chooses the highest actual
response-bound MCS; source TXDESC32/v3 uses rate12..19, USE_DRIVER_RATE,
DISABLE_DATA_FB, raw26-byte QoS with the classified TID and software CCMP, with SGI/BW40/AGG/RTS
disabled. Management and EAPOL keep legacy1Mbps. EU rate selection is host-owned;
no C21/C22 H2C rate-mask callback or invented firmware-applied ACK is added.

Native `rxdesc16` rate/HT/BW, fragment, aggregate, QoS/TID and A-MSDU facts are
checked before crypto. HT MCS0..7 requires BW20/LGI and no greenfield/HT-control/
EOSP/A-MPDU metadata. With PHYST present, the bounded32-byte padded
`rtl8723au_phy_stats` block must agree with LGI and the selected full20MHz RXSC
profile. This old block has no independent channel or C21/C22 page number;
the source-owned fixed channel and descriptor supply those facts. PHYST absent
retains checked descriptor admission and supplies no invented PHY measurement.
Unexpected hardware plaintext, partial/deaggregated pieces and descriptor/header
A-MSDU/TID disagreement are discarded. Only complete original standalone
3839-byte A-MSDUs enter shared whole-aggregate authentication/deaggregation;
bad MIC or a bad later subframe publishes no prefix and consumes no PN.

The retained station owns valid bound immediate ADDBA requests for TIDs0..7
and sends the actual33-byte status37 decline through the native management
descriptor/USB endpoint. Ordinary DATA waits for that exact terminal receipt;
a USB completion is host delivery, not a fabricated radio ACK. No BA agreement,
reorder window or TX aggregation is enabled. Cancellation, source loss or an
uncertain transfer retains outstanding USB resources and cannot reopen them.

RX copies record controlled-port admission and a receive/key generation before
processing. Native terminal M2/M4/Group2 plus actual receive-idle precede shared
reply delivery; key replies retire queued output, controls and the published RX
consumer. A complete original plaintext, peer-bound private EAPOL-Key may cross
the reply epoch into the actual Supplicant phase/MIC/replay checks, always with
DATA admission false. Ordinary/aggregate closed or old captures cannot inherit
a later port. Carrier, Ethernet enqueue, RX-ring writes and every unlocked stack
callback recheck current source/policy and the relevant controlled-port/generation
proof. Reentrant held or fully completed rekey retires the rest of an old
aggregate; ordinary TX-credit backpressure does not retire receive authorization.
Observed authority loss is terminal, including after explicit policy reinstall.

Fourteen passing native Rust smokes cover actual registered executable
retention, measurement identity/unknown bounds, parked EP0 error/cancellation,
all8 source descriptor rates and real CCMP, Open/WPA2 kernel DHCP/exact IP,
whole3839 aggregates, bad native PHY/MIC/tail with same-PN retry, malformed bound
responses, actual held ADDBA/M4 receipts, closed captures, each current source,
policy loss and reentrant key/ordinary-credit publication. These cases pass
both-architecture native QEMU and coordinated build/Clippy gates. Physical
USB/RF/HT interoperability and exact-device measured qualification remain external.
SGI20, HT40, RX A-MPDU, TX A-MPDU, TX A-MSDU, recipient/originator BA and RX
reordering, adaptive rates, broader scans/channels, coexistence,
live EDCA and reset/rejoin remain software work.

## 4. Invariants

- Linux's disabled→EMU→active handshake precedes firmware writes. MAC TX/RX
  stay clear until FIFO boundary setup exists (8188E hardware erratum).
- Preserve unrelated SYS/MCU/page-selector fields; reset the checksum with
  its W1C bit, disable download mode before start, reset 8051, and await both
  checksum and init-ready. RTL8188EU does not use another chip's HMTFR init.
- Short reads/writes, checksum/start failures and USB errors are terminal.
  No failure cleanup may reuse EP0: Future Drop/error does not prove that
  xHCI retired the prior TD or released its persistent control-data buffer.
- The initialization attempt is bounded to 30 seconds. Cancellation/deadline
  leaves a poisoned owner without further transport access. No IRQ-disabling
  guard crosses an await and no `block_on` executes inside a spawned worker.
- Neither firmware-ready nor radio-ready implies association or packet TX.

## 5. Architecture notes

The USB protocol is common to both architecture builds. Register-model tests
drive the actual async owner; real transfer completion belongs to xHCI/USB.

## 6. Dependencies

`narf-drivers-usb` owns EP0 and transfer DMA. `narf-firmware` authenticates
registry blobs; scheduler/time provide async execution and bounded waits.

## 7. Stage assignment

RTL8188EU now reaches the retained channel1 Open/WPA2 station service through
the production probe when exact-device signed qualification/deployment data
is present. No real board curve has been acquired, qualified or installed by
this software work. The initial profile needs physical validation; broader
channels/rates, reset/rejoin and PM still need software implementation.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| RTL8188EU power + EP0 firmware lifecycle | Implemented; shared-path regressions |
| RTL8192EU / RTL8723BU / RTL8821CU / RTL8822BU runtime initialization | Missing |
| EFUSE identity/calibration read through retained async owner | Implemented; chip/geometry/failure coverage |
| Endpoint-descriptor selection and MAC FIFO/LLT | Implemented with retained RX filter/MAC activation |
| MAC/BB/AGC/RF table application | Implemented with source-matched tables and checked transfers |
| Checked post-table MAC, CAM-clear, LC/full IQK and factory gain indices | Implemented; composed owner/status/error/cancellation regressions |
| Initial channel/crystal and retained RX activation | Implemented channel1 owner and admitted probe/service binding |
| Signed board power artifact and checked native TX gate | Implemented software contract; real qualified per-device data must be acquired/signed/installed |
| Native USB descriptor/packet ownership | Implemented dependency; persistent receipt/stop and Linux descriptor regressions |
| Native beacon/management preparation and peer-bound transitions | Implemented narrow channel1/basic1Mbps dependency using shared plan |
| Production passive scan/MLME service and policy-admitted management TX | Implemented narrow channel1/basic1Mbps profile, signed board/deployment admission required |
| Software AES-CCM + strict CCMP/key/TID ownership | Implemented dependency; independent ciphertext/forgery/role/PN regressions |
| WPA2 key installation/controlled port and Ethernet transport | Implemented retained shared RSNA/software CCMP, exact native delivery, Narf-Rings and synchronous stack progress |
| Broader channel/rate profiles and coexistence | Native optional WMM DATA uses negotiated12-rate legacy TX. Separate N8HT HT20/LGI MCS0..7/whole A-MSDU/decline/capture-publication continuation passes native software gates above. Management/basic1Mbps and channel1 remain required. SGI/HT40, retune, broader bands/adaptation and coexistence remain missing |
| USB transfer ownership / stale handles | EP0 + bulk claims, retained command DMA and generation rejection implemented; slot reuse stays gated |
| Non-stream bulk stop/drain | Implemented in USB; exact commands/context/event-prefix proof |
| Disconnect/peer-loss callbacks and normal bulk stop | Implemented; one association per firmware claim |
| EP0/Halted reset, safe rejoin, FIFO retune and PM recovery | Missing; software prerequisites |

Chip inventory is source-specific: Linux `rtl8xxxu/8188e.c` identifies1TX/1RX;
`8192e.c` identifies actual1/2TX and2RX; `8723b.c` identifies1TX/1RX and optional
BT/S0S1. EU's separately qualified HT20/LGI continuation is software-validated above;
SGI20/HT40, RX A-MPDU, TX A-MPDU/TX A-MSDU, recipient/originator BA, RX reorder,
adaptive rates, broader active/passive scanning, runtime PM and
reset/rejoin remain software work. Full WMM AC/TID routing is implemented.

Power-management inventory (upstream `rtl8xxxu/core.c`): `rtl8xxxu_probe`
sets only SIGNAL_DBM, HAS_RATE_CONTROL, SUPPORT_FAST_XMIT, AMPDU_AGGREGATION
and MFP_CAPABLE (no SUPPORTS_PS/DYNAMIC_PS), `rtl8xxxu_ops` has no
`.suspend`/`.resume`/WoWLAN, and `rtl8xxxu_driver` has no
`.suspend`/`.resume`/`.reset_resume`/`.supports_autosuspend` but sets
`.disable_hub_initiated_lpm = 1`. The only power transitions are
`fops->enable_rf` in `rtl8xxxu_start`, `fops->disable_rf` in `rtl8xxxu_stop`
and `fops->power_off` at disconnect. There are no PM submodes beyond that
interface start/stop radio power path (the remaining
`runtime_power_management` row); LPS/IPS/WoWLAN/USB autosuspend/LPM are
inapplicable to this family. 8192EU/8723BU first need their own retained power/firmware/radio/
packet/station compositions, including2-chain or coexistence dependencies.
The repository's matched8821CU/8822BU profiles need the actual upstream
`rtw88/rtw8821cu.c`/`rtw8822bu.c` USB transport and C21/C22B radio semantics;
EU descriptor/register helpers cannot establish those VHT runtimes. No
unsupported initial profile is marked hardware-inapplicable here.

Linux references: `rtl8xxxu/8188e.c` power/reset, IQK and fops;
`rtl8xxxu/core.c` firmware, post-table init, HSSI, LC and IQ matrix functions;
`rtl8xxxu/8188f.c` factory gain-index programming; `net/mac80211/wpa.c` CCMP
AAD/header/nonce layout. AES-CCM formatting follows RFC 3610.
