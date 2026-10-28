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
loss close the carrier. A completed explicit disconnect returns the service
to Passive for a safe rejoin (below); a failed owner cannot construct fresh
keys/radio state. Controller-proven EP0 reset/recovery remains software work.

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
#### Live EDCA updates (implemented)

mac80211 `ieee80211_sta_wmm_params` re-applies EDCA only when a beacon from
the bound AP carries a different WMM Parameter Set Count; `drv_conf_tx` then
reaches `rtl8xxxu_conf_tx` for each AC. `station_runtime.rs::observe_wmm`
follows that on both the async join path and the synchronous Open network
path: an unchanged count is ignored (even if element bytes differ), a new
count is checked by `wmm_runtime::words_profile` (BE ACM, ECW/AIFSN geometry,
8-bit AIFS) before any EP0 access and recorded as pending; losing WMM after
a WMM association is peer loss. The synchronous path never awaits EP0.
`Station::maintain` (driven by `Service::maintain` and the interface worker
via `Device::maintain`, which takes the owner without waiting so a
synchronous network drain is never blocked) and `step` apply the pending
rows through the same checked `configure_wmm_phy` EDCA/REG_ACM_HW_CTRL
writes and readbacks inside the retained signed/policy fence, then switch
host classification/ACM downgrade to the new rows. Cancellation or EP0
failure is terminal and retains posted USB ownership. Smoke
`smoke_rtl8188eu_wmm_beacon_parameter_set_count_updates_live_edca` (Open and
WPA2) covers the ignored same-count beacon, no EP0 from the sync path, the
literal updated rows and VO ACM bit, VO->VI downgrade after the update,
ignored same-count byte changes, held-EP0 cancellation, and terminal
pre-write refusal of BE-ACM and WMM loss.

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
disabled (AGG/RTS now follow the originator BA rules below, and the rate and
fallback follow host rate adaptation below). Management and EAPOL keep legacy1Mbps. EU rate selection is host-owned;
no C21/C22 H2C rate-mask callback or invented firmware-applied ACK is added.

Native `rxdesc16` rate/HT/BW, fragment, aggregate, QoS/TID and A-MSDU facts are
checked before crypto. HT MCS0..7 requires BW20/LGI and no greenfield/HT-control/
EOSP metadata; A-MPDU metadata only under the recipient BA rules below. With PHYST present, the bounded32-byte padded
`rtl8723au_phy_stats` block must agree with LGI and the selected full20MHz RXSC
profile. This old block has no independent channel or C21/C22 page number;
the source-owned fixed channel and descriptor supply those facts. PHYST absent
retains checked descriptor admission and supplies no invented PHY measurement.
Unexpected hardware plaintext, partial/deaggregated pieces and descriptor/header
A-MSDU/TID disagreement are discarded. Only complete original standalone
3839-byte A-MSDUs enter shared whole-aggregate authentication/deaggregation;
bad MIC or a bad later subframe publishes no prefix and consumes no PN.

#### Recipient Block Ack, RX A-MPDU and reordering (implemented)

`rtl8xxxu_ampdu_action` RX_START/RX_STOP program no register: the RTL8188EU
MAC acknowledges A-MPDUs autonomously and mac80211 owns the session and the
reorder buffer. `station_runtime.rs` follows mac80211 `agg-rx.c`
`__ieee80211_start_rx_ba_session` for every peer-bound ADDBA Request on the
HT profile: TID>=8 (TSPEC) answers status37; delayed policy (no
`IEEE80211_HT_CAP_DELAY_BA`) or a window above `IEEE80211_MAX_AMPDU_BUF_HT`
answers38; window0 selects64; a repeated dialog token succeeds only with an
unchanged timeout (else37, session kept); a new token replaces the session
without DELBA. The33-byte response echoes token/timeout, sets immediate policy
and clears A-MSDU permission (rtl8xxxu lacks `SUPPORTS_AMSDU_IN_AMPDU`) and is
sent through the native management descriptor/USB endpoint as before; ordinary
DATA still waits for that exact terminal receipt.

The session head starts at the request SSN. Unicast QoS DATA from the bound
peer on a session TID passes through the shared `narf_wireless::reorder`
buffer (`ieee80211_rx_reorder_ampdu`) before CCMP/PN, A-MSDU deaggregation or
delivery; released original captures re-enter the batch in sequence order and
keep their capture-time port/epoch admission. Only such MPDUs may carry rxdesc16
PAGGR/FAGGR, and only without the A-MSDU bit. Holes release after mac80211's
100ms `HT_RX_REORDER_BUF_TIMEOUT`; old/duplicate sequences are dropped. The
EU RX filter passes no BlockAckReq (REG_RXFLTMAP1 PS-Poll only, no
RCR_ACCEPT_CTRL_FRAME, as `rtl8xxxu_configure_filter` in station mode), so
BAR-driven advance does not occur. A nonzero session timeout without traffic
(`sta_rx_agg_session_timer_expired`) purges the buffer and queues a30-byte
recipient DELBA with `WLAN_REASON_QSTA_TIMEOUT`; an originator DELBA purges
the session. Failure/disconnect purge every session. Smokes
`smoke_rtl8188eu_ht20_rx_ba_reorders_ampdu_before_pn` (Open/WPA2: held native
response receipt, literal response, out-of-order release, duplicate, timeout
release, A-MSDU-in-A-MPDU refusal, standalone A-MSDU on a BA TID, DELBA) and
`smoke_rtl8188eu_ht20_rx_ba_policy_and_inactivity_delba` cover the paths.
Cancellation, source loss or an uncertain transfer retains outstanding USB
resources and cannot reopen them.

#### Originator Block Ack and TX A-MPDU (implemented)

`rtl8xxxu_tx` marks every QoS DATA to an HT peer `ampdu_enable`:
`rtl8xxxu_fill_txdesc_v3` then carries the peer MPDU density in txdw2,
RTS/CTS + HW RTS at DESC_RATE_24M in txdw4, and TXDESC40_AGG_ENABLE instead of
AGG_BREAK only on an operational TID (`packet_codec::aggregate_fields`, applied
by the packet owner after the checksummed descriptor is built). The first such
frame on an idle TID starts a session (`ieee80211_start_tx_ba_session`, gated
by mac80211's HT_AGG_MAX_RETRIES15 / HT_AGG_BURST_RETRIES3 within 15s). The
async `Station::maintain`/`step` path performs `rtl8xxxu_ampdu_action` TX_START
(`rtl8xxxu_set_ampdu_factor` REG_AGGLEN_LMT 0x458..0x45b from the fixed
0x41/a8/72/b9 table clamped to 1<<(factor+2), and `rtl8xxxu_set_ampdu_min_space`
read-modify-write of 0x45c, each with readback) before queueing the ADDBA
Request: immediate policy, A-MSDU clear, window64, timeout0, SSN = the TID's
next sequence (Open counter or shared `Security::next_qos_sequence`). A matching
response with status0 and nonzero window makes the TID operational; any other
status stops it without DELBA; no response within `ADDBA_RESP_INTERVAL` (1s) or
an operational session timeout stops it as a local request with an initiator
DELBA `WLAN_REASON_QSTA_NOT_USE`; a recipient DELBA stops it silently. Every
stop performs TX_STOP (factor0/density0) over EP0 first, as Linux does. The
sync network path never awaits EP0. Smoke
`smoke_rtl8188eu_ht20_originator_ba_and_tx_ampdu` (Open/WPA2) covers literal
descriptor bits before/after operation, TX_START/TX_STOP EP0 writes, the
literal request, peer DELBA, response timeout DELBA, restart token and decline.
The HT program binding records the new RTS/aggregation emission profile.

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
SGI20, HT40, broader scans/channels, coexistence
and reset/rejoin remain software work.

#### Host rate adaptation and rate fallback (implemented)

The RTL8188EU has no firmware rate adaptation; Linux runs the vendor
algorithm on the host (`8188e.c`). `rate_adaptation.rs` ports it as pure
state: `rtl8188e_ra_info_init_all` (decision MCS7, PT_STAGE 5, report time
1200 ms), `rtl8188e_update_rate_mask`/`rtl8188e_arfb_refresh`,
`rtl8188e_rate_decision` with the normal-cut `retry_penalty*`,
`rssi_threshold`, `n_threshold_*`, `dropping_necessary` and
`pending_for_rate_up_fail` tables, `rtl8188e_rate_down`/`_up` with the
`dynamic_tx_rpt_timing` steps, and the power-training stages (upstream forces
PT off after `rtl8188e_power_training_try_state`, so PT_STAGE falls to 0 after
the fifth decision and `rtl8188e_power_training_decision` is unreachable).
Cut I (chip_cut 8) is refused at identification as in
`rtl8188eu_identify_chip`, so its tables are not carried.

`packet_codec::Record::Report` now keeps the rxdesc16 `pktlen` and the
DW5:DW4 `macid_valid` words. `Receiver::poll` feeds every rpt_sel 2 record to
`rtl8188e_handle_ra_tx_report2` (station mode: item 0 only, decision only when
MACID 0 is valid and the total is nonzero); a changed minimum report time is
owed to the async `Station::maintain`/`step` path, which writes
REG_TX_REPORT_TIME (0x4f0) with readback. Failure or cancellation is terminal.
At association (`rtl8xxxu_bss_info_changed` BSS_CHANGED_ASSOC) the WMM station
starts RA with the full negotiated mask (`supp_rates[0] | rx_mask[0] << 12`,
SGI off because the qualified profile is LGI-only) and RATR_STA_INIT. Bound-BSS
frames addressed to the station, and beacons, update
`DECLARE_EWMA(rssi, 10, 16)` from PHY status (`rtl8723au_rx_parse_phystats`:
OFDM `(pwdb_all >> 1) - 110`, CCK `rtl8188e_cck_rssi` LNA/VGA tables; a record
without PHY status contributes signal 0, as upstream's zeroed rx_status does).
Every 2 s (`rtl8xxxu_watchdog_callback` -> `rtl8xxxu_ra_iter`) the SNR
(`rtl8xxxu_signal_to_snr`) becomes `rssi_sta_ra` and
`rtl8xxxu_refresh_rate_mask` applies the HIGH/MID/LOW hysteresis (thresholds
50/20, go-up gap 5) and the 1SS B/G/BG/GN/BGN bitmaps.

DATA on the WMM path (`rtl8xxxu_fill_txdesc_v3`) now carries
`ra->decision_rate`, USE_DRIVER_RATE, PT_STAGE in txdw4[17:15] and the
0x0001ff00 data/RTS fallback limits with TXDESC_DISABLE_DATA_FB cleared, so
the MAC falls back autonomously within the limits (`rate_fallback`). Upstream
never sets DISABLE_DATA_FB; the former fixed highest-rate DATA set it. One
bound is added: `init_all` starts at MCS7 before any mask exists, and the TX
rate is clamped to `highest_rate` while the decision lies outside the mask
(the same clamp rate_decision applies), so a legacy peer never receives an
MCS. Management and EAPOL keep CCK1, and the non-WMM legacy path keeps CCK1.
The HT program binding records the host RA emission profile. Smokes under
`drivers/wireless/rtl8xxxu/rate` (both architectures) cover decision/report
timing, invalid and short reports, mask floor/clamp, RSSI decoding/EWMA/
levels/bitmaps and the adaptive descriptor; composed
`smoke_rtl8188eu_ht20_host_rate_adaptation_and_fallback` (x86_64) covers the
initial descriptor, the REG_TX_REPORT_TIME EP0 writes, rate_down on a loss
report, terminal failure of the write and teardown.

### Bulk endpoint halt recovery and transfer-slot reuse (implemented)

xHCI leaves a bulk endpoint Halted after a Stall, Babble or USB Transaction
Error completion (xHCI 1.2 §4.10.2). Upstream `rtl8xxxu_rx_complete`
resubmits only after -EPROTO/-EILSEQ/-ETIME/-EOVERFLOW/-ECOMM/-ENOSR (where
Linux xHCI already performed its internal halted-endpoint reset) and frees
the URB on -EPIPE, so a stall permanently loses that receive slot. NARF has
no hidden controller-side reset, so `packet_transport::Owner` follows the
USB core `usb_clear_halt` contract instead of failing:

- A halting completion on the bulk-IN or bulk-OUT receipt marks only that
  pipe halted (`Error::Halted`); the receipt stays retained. The other pipe
  keeps working (independent endpoint contexts). Every other USB error,
  short transmit and descriptor error stays terminal.
- `Owner::recover` runs `USBDevice::clear_endpoint_halt` (Reset Endpoint +
  Set TR Dequeue to a fresh dequeue, proven Stopped, then
  CLEAR_FEATURE(ENDPOINT_HALT) resetting the device toggle) for exactly the
  halted endpoint address, drops the now-stale token, reposts the bulk-IN
  receipt and reopens the single TX slot. The packet that was in flight on
  a halted OUT pipe is reported as `transmit_lost` (no USB receipt, no ACK
  claim). Recovery follows the `stop` discipline: the owner is terminal
  while the future runs, so an error or a dropped future leaves it failed
  with every receipt retained.
- `Owner::stop` recovers a halted pipe first (a Halted endpoint cannot be
  stopped), so a stopped owner is always reusable on its channel by `start`
  (fresh RX receipt, empty TX slot). `Receiver` stop/start (Stopped →
  Receiving) is the reopen path for the radio.
- `Receiver::poll`/`poll_delivery` report a halted pipe as "pending" rather
  than an error; `recovery_pending` feeds the existing async maintenance
  path. `Station::maintain` (FourWay/Open) and `Service::maintain` (Passive
  scan) call `Receiver::recover` inside the current authority fence. A lost
  best-effort DATA/Control packet is dropped; a lost EAPOL/MLME frame is
  terminal (no retransmission owner exists for it). Join-phase halts are not
  recovered: the join deadline fails the attempt as before.

Tests: `smoke_rtl8188eu_packet_halted_pipes_recover_and_reuse_slots` (all
three halting codes, pipe isolation, IN repost/OUT slot reuse, stop of a
halted owner, reset failure and cancelled recovery are terminal) and
`smoke_rtl8188eu_station_endpoint_halt_recovery_keeps_association` (open
station survives IN and OUT halts with a full roundtrip afterwards,
disconnect of a halted station, failed reset is terminal).

### Safe rejoin after disconnect (implemented)

Linux v7.2 mac80211 `ieee80211_set_disassoc` (`net/mac80211/mlme.c`)
clears the link BSSID, so `rtl8xxxu/core.c::rtl8xxxu_bss_info_changed`
runs `BSS_CHANGED_ASSOC` (`report_connect(..., false)`, TSF-update
disable) and `BSS_CHANGED_BSSID` → `rtl8xxxu_set_bssid(zero)`; the driver
keeps receiving and mac80211 may scan and associate again with new keys.
NARF follows that on the retained owners:

- `Service::disconnect` runs the existing `Station::disconnect` (media
  disconnect, MAC TX/RX/filter closure, proven USB Stop/SetDeq), then
  `Station::into_radio` returns the stopped `Receiver` and drops the station
  with its keys, PN/replay windows, BA sessions and plan.
- `Receiver::release_station` (Stopped only) writes REG_BSSID
  0x618..0x61d to zero with readback and clears the bound `peer`,
  `ra_info` and the owed TX report time, so `prepare_station` accepts the
  next peer. `Receiver::start` (Stopped → Receiving) reopens RX-only
  reception on a fresh bulk-IN receipt; the service is `Passive` again and
  a later `connect` builds a fresh station (fresh SNonce/PTK and CCMP).
- `interface::Device::disassociate` closes admission before waiting (stale
  publishers are fenced exactly as before) and, only when the disconnect
  completed with a Passive service and no failure, reopens admission under
  the same state guard and resets the RX Narf-Ring generation so the next
  station publishes a new consumer. `closed` is therefore no longer
  permanent after disassociate; any failed teardown, failed association or
  authority loss still closes terminally.
- Any EP0/USB failure while releasing or restarting is terminal and keeps
  the radio retained (`Service::fail`), like every other runtime write.

Tests: `smoke_rtl8188eu_service_composes_passive_scan_optional_ies_rsna_and_sync_network`
(disconnect → Passive with BSSID zero and RX-only CR, a second WPA2
association with fresh 4-way/CCMP and data, second teardown),
`smoke_rtl8188eu_{open,wpa2}_native_scan_dhcp_and_bidirectional_ip` and
the HT20 variants (composed Device: old receipt stopped and a distinct
passive receipt posted, rescan, re-association with a fresh AP session and
uplink, second disconnect), `smoke_rtl8188eu_disconnect_overrides_waiting_old_link_publication`
(stale publisher still fenced) and the failed USB stop smoke (teardown
failure stays closed; no rejoin).

## 4. Invariants

- Linux's disabled→EMU→active handshake precedes firmware writes. MAC TX/RX
  stay clear until FIFO boundary setup exists (8188E hardware erratum).
- Preserve unrelated SYS/MCU/page-selector fields; reset the checksum with
  its W1C bit, disable download mode before start, reset 8051, and await both
  checksum and init-ready. RTL8188EU does not use another chip's HMTFR init.
- Short reads/writes, checksum/start failures and USB errors are terminal,
  except bulk-pipe halts, which `Owner::recover` resets as specified above.
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
| Disconnect/peer-loss callbacks and normal bulk stop | Implemented; a completed disconnect returns to Passive (safe rejoin) |
| EP0/Halted reset, safe rejoin, FIFO retune and PM recovery | Bulk halt recovery and safe rejoin implemented; EP0 reset, FIFO retune and PM missing |

Chip inventory is source-specific: Linux `rtl8xxxu/8188e.c` identifies1TX/1RX;
`8192e.c` identifies actual1/2TX and2RX; `8723b.c` identifies1TX/1RX and optional
BT/S0S1. EU's separately qualified HT20/LGI continuation is software-validated above;
SGI20/HT40,
broader active/passive scanning, runtime PM and
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

Source-proven inapplicability (rows removed from the remaining inventory):

- **TX A-MSDU.** mac80211 `tx.c::ieee80211_amsdu_aggregate` returns early
  unless the hardware sets `TX_AMSDU`; `rtl8xxxu_probe` sets only SIGNAL_DBM,
  HAS_RATE_CONTROL, SUPPORT_FAST_XMIT, AMPDU_AGGREGATION and MFP_CAPABLE, so
  mac80211 never builds an A-MSDU for this family. (RX of standalone A-MSDUs
  is implemented above.)
- **TSPEC admission.** `nl80211.c` exposes `NL80211_CMD_ADD_TX_TS` (and
  `nl80211_add_tx_ts` returns `-EOPNOTSUPP` otherwise) only when the driver sets
  `NL80211_FEATURE_SUPPORTS_WMM_ADMISSION`; mac80211 `ieee80211_add_tx_ts`
  never originates ADDTS itself. `rtl8xxxu/core.c` never sets that wiphy feature, so no TSPEC
  can be admitted; the implemented ACM downgrade (`ieee80211_downgrade_queue`)
  is the complete upstream behaviour for ACM ACs.
- **U-APSD.** mac80211 `mlme.c::ieee80211_mgd_assoc` sets
  `assoc_data->uapsd` only when the vif has `IEEE80211_VIF_SUPPORTS_UAPSD`,
  otherwise the WMM Information element carries QoS Info 0 and U-APSD is never
  enabled. `rtl8xxxu/core.c` never sets that flag (no `driver_flags` assignment, no SUPPORTS_PS), so U-APSD is inapplicable; the
  driver-owned Information IE requesting no U-APSD is the complete behaviour.

Linux references: `rtl8xxxu/8188e.c` power/reset, IQK and fops;
`rtl8xxxu/core.c` firmware, post-table init, HSSI, LC and IQ matrix functions;
`rtl8xxxu/8188f.c` factory gain-index programming; `net/mac80211/wpa.c` CCMP
AAD/header/nonce layout. AES-CCM formatting follows RFC 3610.
