# rtl8xxxu — Specification

> Status: runtime RTL8188EU factory/FIFO/firmware/MAC/BB/RF + LC/IQK implemented;
> retained channel1 Open/WPA2 station service implemented; qualified legacy
> channels1–13 and idle passive scans pass native software acceptance.
> Administrative cold park/wake passes native software acceptance.
> Qualified idle active probe scanning passes native software acceptance.
> Associated passive scans and plaintext Null/QoS Null pass native software acceptance.
> Associated active scans are implemented pending their own native acceptance.
> Broader profiles and physical acceptance remain incomplete. A separately
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

**Software acceptance at `6813a24c6`.** The separately qualified RTL8188EU
`ht40` continuation passes the checkpoint release/native gates on x86_64 and
aarch64. Broader PHY, other chips and unrelated role/power continuations
receive no acceptance here. This supersedes implementation-time statements
below that release/native execution or software acceptance is pending, only
for the named feature scopes. Physical measurements, signed board/deployment
programs and actual-device RF/power/interoperability acceptance remain
separate.

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
radio-ready, parking, parked, restarting or terminal failed state. Radio-ready means checked initialization
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
before proven USB Stop/SetDeq. Successful same-channel stop permits restart;
qualified channel changes use the complete cold MAC restart described below.
Cancellation/transport failure is terminal without cleanup or a
new claim; unretired USB receipts stay owned. Quiet polls preserve the TD.
Unexpected hardware-decrypted metadata and non-MPDU reports do not reach
native management/data dispatch. Firmware status adds starting-receive,
receiving, receive-stopped and restarting states. This entry point is now bound to
the probe's network service worker only after signed board/deployment admission.

`management_runtime::{Candidate, Join}` admits native channel1 beacon/probe
identity initially, and qualified channels1–13 through the cold transition
below, with strictly bounded IEs and a basic 1Mbps rate matching the
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
initially on channel1/20MHz/basic1Mbps, with qualified idle channel changes
below, Open or WPA2-PSK/CCMP and PMF disabled. The
distinct optional HT20/LGI program below supplies factual HT capability only
after its parked native programming succeeds. VHT, HE, EHT, external EAPOL,
packet offloads, connected retune and power overrides are not advertised. Passive scans poll the retained native RX owner,
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
fails the owner. Successful stop permits a same-channel restart. An idle
channel change additionally requires the completed cold MAC/FIFO restart below;
changing a channel label cannot qualify queued RX bytes. Production service composition
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
owner admit QoS DATA with TXDESC32_QOS. This WMM grant keeps HT/BA, U-APSD
and TSPEC closed; the distinct HT grant below cannot be inferred from it.

QoS Null is emitted only by the associated passive scan continuation below:
mac80211 uses its off-channel power-save nullfunc when leaving an associated
channel, while rtl8xxxu advertises neither PS nor REPORTS_TX_ACK_STATUS.
This is not a station sleep, U-APSD, USB autosuspend or on-air ACK capability.

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
EU RX filter passes control frames (REG_RXFLTMAP0/1/2 = 0xffff, the rtw88
retained value for the same Realtek filter block), so a peer-bound
single-TID BlockAckReq advances the recipient reorder session (or earns
one recipient DELBA for an unexpected TID); multi-TID BARs are consumed
without advance, and every other control frame is dropped by the station
gate rather than reaching the DATA path. A nonzero session timeout without traffic
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
SGI20, broader bands and coexistence remain software work. The separate
HT20/40 v2 continuation below is implemented pending native acceptance.

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

### Qualified legacy channels and idle passive scans (software-validated)

The retained owner selects legacy 20MHz channels1–13 from the existing signed N8PC
rows. `Calibration::permission` intersects the actual selected 20MHz occupied
band with every authenticated rule and chooses gains below the source factory
group ceiling:1–2,3–5,6–8,9–11 and12–13 (`8188f.c::rtl8188f_channel_to_group`).
Missing/unmeasured rows and unsupported rule flags remain refused. No default
curve, interpolation or additional qualification format is introduced.

`Device::set_config` changes an idle owner's channel, and passive scan accepts
bounded explicit channel/frequency lists or the currently qualified set. Every
requested row is checked before the first hardware transition. Each successful
scan restores its original home channel. Connected active scans remain busy;
associated passive scanning uses the separate continuation below. Noninitial
channels use the legacy profile; the retained N8HT continuation remains bound to
channel1 and is reprogrammed only when returning to that exact qualified profile.
Default channel enumeration rechecks current authority after each target row
and before returning, so revocation cannot be hidden as a missing target row.

Channel changes retire the physical receive stream. MAC RX/TX and filter maps
close first; RXDMA is paused while its current USB receive TD still runs, and
old completed copies are discarded. Observed RXDMA idle precedes actual USB
Stop/SetDeq. RXDMA idle alone cannot empty queued device FIFO data. The cold
path therefore performs the source card-off/firmware reset sequence and the
explicit hardware MAC-off handshake in the pinned
[RTL8188EU power-state table](https://android.googlesource.com/kernel/common/+/c13159a588818/drivers/staging/rtl8188eu/include/pwrseq.h):
`RTL8188E_TRANS_ACT_TO_CARDEMU` writes APS_FSMCO[9] and polls its terminal
self-clear after RF-off/LDO sleep. Neither an MCU-only reset nor an elapsed
delay substitutes for this MAC-off receipt.

The same physical USB and firmware owner remains retained. A cold restart
invokes the original executable capability and reuses its exact bounded owned
image, compares fresh factory/endpoints with the original identity before RF
calibration, and restores the complete source FIFO/LLT, firmware, tables and
LC/IQK program. The home-channel1 calibration envelope and target operating
envelope stay current through every await. The selected RF channel/width is
read back before a new receive TD acquires its channel label. A failed or
cancelled EP0 transition stays terminal with its original receipts retained;
failed owners cannot enter this restart path or acquire another receive claim.

Copied BSS entries retain observation time and receive-stream generation.
CONNECT after a cold transition requires a fresh actual target-channel beacon,
without refreshing an old cache entry's age. Eight native cases cover actual
Open/WPA2 channel6 DHCP, multi-channel dwell/home restoration, old device FIFO
copies, fresh-observation admission, cancellation/source loss, missing row and
RXDMA/MAC-off receipts, and literal factory/occupied-band limits. All eight
native cases pass on both architectures at `62b62ea68`, within full integration
results of4294/0/13 on x86_64 and3935/0/7 on aarch64. Release CI, formatting,
ordinary boots and both btrfs postflights also pass on that exact checkpoint.
Physical-board acceptance remains separate. Administrative-PM and idle active
scan continuations are accepted below at their own later checkpoint.

### Administrative radio park/wake (software-validated)

The production attach path completes a physical cold park before publishing
the initial IFF_DOWN interface. MAC RX/TX/filter closure, RXDMA terminal state,
actual USB Stop/SetDeq and the completed hardware MAC-off FSM precede
`Stage::Parked`; no native RX TD remains posted under initial DOWN. A parked
owner retains its original physical USB claim, firmware image and capability,
factory identity, selected operating permission and optional home HT profile.

The actual registration installs an original-receiver `OpenStopTarget` holding
a Weak reference to that Device. UP requires the original current event;
retired DOWN may close only that captured old radio under its still-current
native grants. Event observations grant no USB or firmware access. Carrier
publication uses the captured ownership snapshot, and carrier withdrawal uses
immutable registration identity, so a same-name replacement cannot acquire
this radio's UP or DOWN publication.

The synchronous callback immediately closes packet/control admission and old
receive-ring publication, then queues a scheduler-owned task retaining the
Device. No register or USB await runs in the callback. Dropping the triggering
caller cannot drop the published PM operation. Rapid reversals complete the
currently owned native operation and then apply the latest original event;
every real UP performs park/wake so a coalesced DOWN/UP also retires old station
and key state. Stale UP completion parks only its original receiver and stays
closed. No IRQ-safe guard spans an await.

DOWN retires a connected station through the existing peer/media/key and
native Stop path, then performs the same source card-off/MAC-off sequence as
channel changes. UP reuses the exact original authenticated firmware image,
checks fresh factory/endpoints before RF calibration, restores source FIFO/LLT,
tables and LC/IQK, verifies the selected channel and posts fresh RX. Current
executable, board and home/target regulatory proofs fence every await. Carrier
and the controlled port remain closed until a new actual association/RSNA.
No failed or ambiguous EP0/bulk owner can be revived by another UP request.

Bound scan, associate, disconnect and channel-control callers reject while PM
is pending or state is owned; synchronous `block_on` never waits for the PM
task to make progress. Normal synchronous drains also reject closed admission.
The retained task independently drives its own IRQ/self-waking USB operations.

Control clients first request administrative UP, then scan/associate, retrying
Busy while the retained cold wake completes. The existing compatibility paths
already dispatch to this current hook: `net/src/netlink_route.rs` handles
RTM_NEWLINK/RTM_SETLINK IFF_UP through `AdminHandle::set_link`, and
`userspace/src/socket.rs` handles SIOCSIFFLAGS through the same operation.
`net/src/iface_admin.rs::Effects::notify` calls the captured target after
registry locks are released. `userspace::network_daemon` installs/delegates
the explicit interface/namespace admin grant; it does not invent UP. The
in-tree shell has no separate Wi-Fi scan/connect builtin. Scanning a DOWN
radio stays refused rather than changing operator policy implicitly.

This implements administrative radio off/on using the stronger retained cold
restart boundary. Linux `rtl8xxxu_start/stop` calls `enable_rf/disable_rf`, and
`rtl8188eu_power_off` supplies the source card-off sequence; the pinned MAC-off
FSM above supplies explicit FIFO retirement. It does not introduce LPS, IPS,
WoWLAN, autosuspend or USB LPM modes absent from this family's source contract.
Eight separate `drivers/wireless/rtl8xxxu/runtime_pm` native cases cover actual
registration/queued ownership, initial DOWN, Open/WPA2 down/up with native DHCP
and fresh PTK, held EP0 reversals, caller/source loss, registration replacement
and failed bulk Stop. All eight pass on both architectures at `0eb084197`,
within integration results of4326/0/13 on x86_64 and3967/0/7 on aarch64.
Resolved release CI, formatting, ordinary boots and both btrfs postflights
pass at that checkpoint. Physical-board acceptance remains separate.

### Idle active probe scanning (software-validated)

Active scans use the same retained idle station owner and qualified channels
as passive scans. Linux `rtl8xxxu/core.c` advertises `max_scan_ssids=1`; this
driver now advertises and admits one directed SSID or one wildcard. The
bounded optional probe-IE budget is2048 bytes. Complete IE extents are checked
before hardware mutation, and callers cannot replace the driver's SSID,
rates, channel or PHY capability elements. Random addressing/sequence flags,
6GHz and active scanning while associated remain unsupported.

The private `probe_runtime::Prepared` type constructs a Probe Request with
the actual local transmitter address, broadcast DA/BSSID, software sequence,
legacy Supported/Extended Rates and actual selected DS channel. The optional
HT20/LGI capability is included only for the already programmed current HT
grant. A separate packet-codec/packet-owner/Receiver entry point consumes
this type. Ordinary management submission retains its subtype and unicast
peer checks; it cannot send a raw broadcast probe.

Every requested channel's complete occupied20MHz band and signed N8PC row
is admitted before the first retune or emission. Unsupported flags such as
NO_IR, missing measured rows or insufficient power qualification refuse the
plan. Current executable, board/profile and regulatory proofs fence all
subsequent waits and native publications. The existing N8PC complete legacy
CCK/OFDM envelope already covers the basic1Mbps probe emission; no new board
measurement format or production fixture curve is introduced.

The real MGNT/basic1/BMC descriptor and exact USB TX terminal prove native
host delivery, not PHY drain or a broadcast ACK. MAC TX remains enabled
through the active response dwell. Conservative millisecond ceilings of
mac80211 `IEEE80211_PROBE_DELAY`/`IEEE80211_CHANNEL_TIME` (each HZ/33) provide
31ms before publication and at least31ms afterward. The complete prepared
MPDU, including up to2048 IE bytes, is also checked against the long-preamble
CCK1 duration from `ieee80211_frame_duration`:202us plus8us per MPDU/FCS byte.
A mandatory request below that source pre/post/airtime minimum is refused
before hardware mutation; a nonmandatory duration is raised to the source
minimum. Native USB/retune latency is separate from those listening windows.

After that dwell, `rtl8188eu_active_to_lps` supplies the actual device TX-state
boundary: pause queues, observe the full32-bit SCH_TX_CMD equal to zero, then
close MAC TX with readback and restore the saved pause value. Missing device
terminal state fails without clearing MAC TX on the strength of a host
completion. The same physical RX stream stays posted on the same channel;
this current-TX-state receipt does not assert an empty device FIFO. A later
retune still requires completed old USB ownership and the actual cold MAC-off
FIFO boundary. Observations retain their physical channel, copy time and
receive generation, and a successful scan restores its home. Cancellation,
short/error delivery or source/policy loss stays terminal with native receipts
retained and no cleanup I/O.

Hidden-SSID discovery retains whether the actual copied observation was a
Probe Response. After a cold join transition such an entry triggers a new
qualified directed probe and requires a fresh matching native response before
authentication. Old display metadata does not become a current observation;
the ordinary beacon-only fresh-observation path is unchanged.

Eight separate `drivers/wireless/rtl8xxxu/active_scan` native cases cover
Open/WPA2 probe/response to actual DHCP, literal wildcard/directed bytes and
MGNT/basic1 descriptors, unsupported SSID/IE and occupied-policy refusal,
held/cancelled/source-lost and short TX terminals, policy loss during the
native wait, old FIFO responses and home restoration. The independent device
model withholds its response until delayed PHY consumption while MAC TX stays
enabled, and holds SCH_TX_CMD separately from host completion. Early MAC TX
closure loses the response; maximum IE timing and missing device terminals
have literal negative cases. All eight pass on both architectures at
`0eb084197`, with the complete release gates recorded above. Physical
AP/USB inputs remain inert, and physical qualification remains separate.

### Associated passive scanning and Null functions (software-validated)

`WirelessNetIface::scan` now accepts passive requests while connected, under
the same ordinary device-state mutex as the network producer. Existing host
Narf-Ring and pending Ethernet owners remain intact; a concurrent synchronous
drain returns without waiting for another scheduler task. New host publication
observes the busy state. Connected active scans use the separate continuation below.
Invalid channels, missing signed measurement rows, current NO_IR/power policy
or mandatory dwell above125ms are refused before the first scan I/O.

`station_scan` drains the current native DATA/EAPOL/control receipts and any
pending EDCA/aggregation programming before departure. An active RSNA rekey
refuses the scan. The private `ps_null::Prepared` route then emits the exact
plaintext ToDS PM1 Null function, with local TA and the bound AP as RA/BSSID.
mac80211 `ieee80211_nullfunc_get` chooses26-byte QoS Null/TID7 for the actual
WMM peer, otherwise24-byte non-QoS Null. QoS Null carries SN0 and consumes no
DATA sequence or CCMP PN. Non-QoS Null reserves the same wrapping SN counter
as non-QoS DATA/EAPOL through the shared Security helper, without changing
keys, PN or replay state. Open stations use their existing non-QoS counter.
The ordinary Ethernet/management formatters still reject both Null subtypes.

Each native Null descriptor uses basic1Mbps and the real VO/TID7 or BE queue
and USB endpoint, without aggregation or hardware encryption. The host SN is
copied to txdw3[27:16]; TXDESC32_HW_SEQ_ENABLE (txdw4 bit7) stays clear for
both DATA and Null before and after every cold MAC restart. The hardware
cannot silently replace this sequence with a reset internal counter. A QoS
Null sets only the separate TXDESC32_QOS bit6. Descriptor checksum, unicast
addresses, original peer/profile and current occupied-power permission remain
mandatory in the private submission path.

The Linux scan/offchannel contract supplies100ms after PM1 when the driver
has no `.flush`, one away dwell bounded by HZ/8 (125ms), and200ms on home
return. Nonmandatory longer dwells are capped; mandatory longer dwells are
refused. The real cold retunes take additional elapsed time, so these values
are not a claimed physical switching-latency bound. USB terminal proves
native host delivery; it does not prove AP reception or power-save buffering.
MAC TX remains enabled through the source grace, followed by the real paused
32-bit SCH_TX_CMD terminal before TX closure. rtl8xxxu sets no
REPORTS_TX_ACK_STATUS flag: a lost Null remains best effort, without a fabricated
on-air ACK. Missing USB/device terminals instead fail and retain ownership.

The original home Authority stays current through the complete asynchronous
visit. Away permission is checked independently through its own dwell fence.
Before any channel label changes, the same receiver performs the existing
MAC/filter closure, RXDMA terminal while the old TD remains posted, actual
USB Stop/SetDeq, and completed MAC-off FIFO reset. Only then is the exact
retained firmware/image restarted with fresh factory/endpoint comparison and
new actual RF readback. Away MPDUs enter only the scan candidate parser;
they cannot advance the home CCMP replay window, EAPOL or BA reorder owner.
Observation time and generation belong to that physical receive stream.

On each return the same owner cold-restores the original channel and optional
HT grant, AP BSSID/AID/media state, current EDCA/slot settings, aggregation
factor/density and operational TID bitmap. The retained host rate-adaptation
object and its actual report interval are restored as well. The logical
Station, JoinPlan, Security/key/PN/replay objects, per-TID counters, RX/TX BA
sessions, receive epoch and host packet rings survive a successful scan.
Ordinary BA timers may expire as they normally do while servicing home traffic.
The return resets connection/beacon monitoring as Linux does; it never refreshes
an old candidate's seen time without a new physical copy. The private PM0
Null is followed by normal home DATA/RSNA/reordering during the home grace.
Cancellation/source loss is terminal and never drops a published USB/EP0 owner
or starts another claim as cleanup. The awaiting Device scan has a non-I/O
publication Drop guard: the retained Service failure flag withdraws the
original registration's carrier immediately, without waiting for a later
network drain. Pure request refusal leaves the live station published.

The pinned primary snapshot is Linux7.3-rc7, as recorded by its Makefile.
Load-bearing entry points are `net/mac80211/offchannel.c::{ieee80211_offchannel_stop_vifs,
ieee80211_offchannel_return}`, `mlme.c::ieee80211_send_nullfunc`,
`tx.c::{ieee80211_nullfunc_get,ieee80211_tx_h_sequence}`,
`scan.c::{ieee80211_scan_state_decision,ieee80211_scan_state_suspend,
ieee80211_scan_state_resume}`, and `rtl8xxxu/core.c::rtl8xxxu_fill_txdesc_v3`.
For exact source reproduction, SHA256 of those files is respectively
`19da65d87aa3a622931baaf41262e1b7de8af9100248a2b4ebfc6f40a68c0625`,
`c21da8dfbe059571692bdc75e75f5aa57e0133587afbf2c915ad73f055495011`,
`199a2fff76dc09416866c9899d9e1e7e071532099b4d59acddc26f63d68ef4b8`,
`93c9ba7f391b92c5dc1c113d8d5910a96f10f38ee65e8608a2c00e7584051a29`,
and `eab41606f9e0a304012f082ff95979222d3e63780d649ed1d923938b7e97b1b1`.
`rtl8xxxu/rtl8xxxu.h` defines the independent QoS/HW-sequence bits; its SHA256
is `1979e54d2b5002a903c794751e31094aa414c32281459d109a1afd65178ef7f4`.

Eight `drivers/wireless/rtl8xxxu/associated_scan` native cases compose actual
firmware/USB/Device/MLME/RSNA and DHCP. They cover Open/WPA2 home restoration,
retained host TX and AP-buffered RX, independent delayed device-air handling,
literal Null/QoSNull and host-SN descriptors, closed ordinary frame entries,
mandatory timing refusal, retained real USB/EP0 waits under cancellation and
source/policy loss, best-effort unacknowledged Null versus a missing actual
SCH terminal, preserved RX/TX BA and away high-PN/replayed home rejection.
One focused shared Security native case encrypts DATA before/after a reserved
plaintext Null slot across SN4094/4095/0, requires consecutive PN1/2, decrypts
with a persistent replay window, and verifies old-PN rejection and unchanged
QoS counters. All nine pass on both architectures at `a7797583a`, within
4,349/0/13 x86_64 and 3,990/0/7 aarch64 native results. Resolved release CI,
formatting, ordinary boots and both btrfs postflights pass on each architecture.
Physical RF/USB qualification remains separate. Associated active scanning
below retains its own pending native gate beyond this passive/Null acceptance.

### Associated active scanning (software-validated)

The retained connected station now accepts an active scan with one directed
SSID or a wildcard and up to 2048 checked extra IE bytes. Admission validates
every selected channel's exact signed power row and current occupied-band
policy, the complete extra IE structure and source timing before publishing
PM1 or changing hardware. The ordinary one-SSID, random-address and band
restrictions remain. Mandatory dwell must fit both the source probe timing
and the 125ms listening cap; a nonmandatory request is raised to the source
minimum and capped at 125ms. No scan grants broader channel or power rights.

Each visit retains the original station and its home authority. It drains
native DATA/control work, emits the private plaintext PM1 Null/QoS Null and
honors the source 100ms no-flush grace. The physical receiver then performs
an actual completed cold MAC/FIFO/USB restart, including when the requested
channel is the current home channel. The restarted receiver has no bound
peer, so the existing private `probe_runtime::Prepared` path can emit the
native broadcast Probe Request without broadening ordinary management TX.
Away visits use the qualified legacy profile; a visit on the actual home
can retain its installed HT grant. The outer home proof remains current
even while that HT program is temporarily absent from an away receiver.

The Probe reserves one sequence number from the retained non-QoS DATA/EAPOL
space through the existing Security helper, without consuming CCMP PN or
changing keys/replay state. QoS Null continues to use TID7/SN0 without
allocating a DATA sequence. The actual descriptor selects MGNT/basic1Mbps,
software SN and no hardware encryption or hardware sequence override. Source
pre-probe delay and the complete frame's airtime bound its response window.
Native host USB delivery precedes a listening window with MAC TX still open;
the subsequent actual 32-bit SCH_TX_CMD terminal precedes TX closure. Host
delivery is neither an AP ACK nor physical FIFO retirement.

Every return forces another real cold receive boundary before restoring the
original channel, peer/media/AID, HT/EDCA, rate reporting and aggregation
profile. PM0 and the source 200ms home grace then use ordinary data/RSNA/BA
progress over the same software keys, replay windows, sequence owners and
host packet rings. Away frames enter only the physical-channel scan parser.
Cold reinitialization and USB latency remain additional to the listening
windows; the software makes no physical switching-latency guarantee.
Cancellation, current policy/source loss, short USB or missing device
terminal state leaves a terminal owner with its actual receipts retained.

Eight new `drivers/wireless/rtl8xxxu/associated_active_scan` native cases
compose actual retained firmware/USB/Device/MLME/RSNA and DHCP. They cover
Open and WPA2/HT home/away scans, same-channel cold generations, directed and
wildcard probes, maximum extra IEs, exact private descriptors and shared SN
ownership, retained host and buffered peer packets, pure timing/power/IE
refusal, held Probe cancellation/source loss, independent USB/PHY/SCH
terminals, old FIFO rejection and current home policy/HT loss during actual
native work. Only hardware/firmware execution and peer inputs are inert.
The eight earlier associated-passive cases remain separate registrations.
The eight active cases pass release acceptance at `aa6b98463` on both
architectures. The combined suites pass4,369/0/13 on x86_64 and4,010/0/7
on aarch64, preserving every prior named case/status and adding exactly20.
Resolved release Clippy, formatting, ordinary boots and both btrfs
postflights pass on each architecture. Physical qualification remains
separate from the supplied firmware/USB/peer execution in these fixtures.

### Separately qualified RTL8188EU HT20/40/LGI (implemented, validation pending)

The optional signed N8HT v2 contract is specified in
[rtl8188eu-ht40.md](rtl8188eu-ht40.md). `Owner::ht40_request(primary, secondary)`
returns its exact filename/source binding without modifying the radio.
It binds a legal primary/secondary/center, actual current executable, exact
factory and preceding N8PC identities, unchanged v1 recipe, and new measured
CCK/OFDM plus MCS0–7 full-program peak envelopes covering both20 and40MHz.
The existing v1 parser, filename and channel1 HT20 behavior are unchanged.
Missing v2 data preserves that path; invalid present data fails preclaim.
No real measured artifact or physical acceptance is provided.

The actual native owner selects primary factory power groups, never the RF
center group or another chip's HT difference. It intersects the complete
occupied40MHz host policy with N8PC/v2 envelopes, preserves the current
legacy gain pair and bounds every MCS gain. Native BB/RF/gain/SIFS writes
and readback happen with MAC parked. A sealed program is minted only after
those operations; typed geometry and selected gains supply no RF authority.
Every width transition retires real old RXDMA/USB/MAC-FIFO contents even
when primary is unchanged. Actual copied RX40 MPDUs need that program's
private current-source seal. Source or policy failure permanently retires
that program's receipts without poisoning a later installation.

The selected peer receives an HT40 offer only for its exact signed/current
secondary. A narrowed20 response forces a real cold20 restore of the same
logical peer before keys/data open. Native QoS DATA/Null add the source v3
BW/primary descriptor fields and checksum; management remains basic1Mbps.
The SISO MCS0–7/LGI path composes with software CCMP, BA/replay, host rate
adaptation and whole A-MSDU. Scans and park/wake retain exact home geometry;
away receivers stay NOHT. SGI, MCS32 and2SS are not advertised by this subset.

Eight additional native regressions are registered under
`drivers/wireless/rtl8xxxu/ht40`: signed identity/primary power group,
literal plus/minus geometry and Open/WPA2 DHCP,20MHz fallback and response
narrowing, same-primary FIFO cuts and copied full-span policy retirement,
held DATA/source loss, BA/replay retention, and active-scan/cold EP0 restore.
They await coordinated release compilation and native execution; all prior
v1/scan registrations remain required. Hardware measurements and physical
USB/RF interoperability remain external.

### RTL8192EU native owner

RTL8192EU (and its 1T2R RTL8191EU bonding) is the second native rtl8xxxu
chip. It reuses the retained one-shot `firmware_transport::Owner` and its
EP0 transfer/executable-cap discipline; chip steps live in
`rtl8xxxu/rtl8192e_init.rs`, constants/tables in `rtl8xxxu/rtl8192e.rs`.

- Image: `rtlwifi/rtl8192eu_nic.bin`, signature family `0x92e0`
  (`core.c::rtl8xxxu_load_firmware`); an 88E-signed image is rejected
  before any USB access.
- Identity (`8192e.c::rtl8192eu_identify_chip`): `REG_SYS_CFG` cut/vendor,
  test silicon refused, `REG_HPON_FSM` bonding → `tx_paths` 1 or 2,
  `REG_GPIO_OUTSTS` ROM rev, TX queues from `REG_NORMAL_SIE_EP_TX` or the
  bulk-OUT count. A SIE queue set larger than the descriptor's bulk-OUT
  endpoints is `BadEndpoints` (Linux would index past `out_ep[]`).
- EFUSE: `core.c::rtl8xxxu_read_efuse` PG-header decode (extended headers,
  word masks, stop at `0xff`) and `rtl8192eu_parse_efuse` (`0x8129` ID,
  both paths' CCK/HT40 bases, signed HT20/HT40/OFDM diffs, crystal cap,
  thermal, PA/LNA type, board/antenna option). Retained as
  `Owner::factory_8192e()`.
- Power (`rtl8192eu_power_on`): SPS/LDO select, `crystal_afe_adjust`,
  `disabled_to_emu`, `emu_to_active` (checked polls), CR with MAC TX/RX as
  Linux does. `active_to_emu`/`emu_to_disabled` are implemented for the
  power-off path.
- Pre-firmware (`rtl8xxxu_init_device`): reserved pages with the 8192E
  budget, `init_queue_priority` (TRXDMA + queue→endpoint map retained as
  `Owner::queues_8192e()`), `TRXFF_BNDY+2 = 0x3cff`.
- Firmware: shared download with `writeN_block_size = 128`, generic
  `rtl8xxxu_reset_8051`, no `init_reg_hmtfr`. Download is not retried: a
  short transfer is terminal for the owner.
- Gen2 H2C (`rtl8xxxu_gen2_h2c_cmd`): ext word then mailbox word, mailbox
  rotation over 4, exclusive claim. A mailbox still busy after 101 polls is
  `MailboxBusy` (Linux proceeds because its `!retry` test sees -1).

- Tables (`rtl8xxxu/rtl8192e_tables.rs`, generated verbatim by
  `rtl8xxxu/gen_rtl8192e_tables.py` from `8192e.c`): MAC 101, PHY 212,
  AGC std/high-PA 130 each, RF A 110, RF B 90 rows (+ Linux sentinel).
  `hi_pa` is never set for 8192EU, so only the standard AGC table applies.
- `rtl8192e_phy::mac_bb_rf` (`rtl8xxxu_init_device` init_mac → HIMR):
  MAC table, `rtl8192eu_init_phy_bb` + PHY/AGC, the RTL8191EU 1T2R path-B
  patch of `rtl8xxxu_init_phy_bb`, `rtl8723a_set_crystal_cap` (XTAL1/XTAL0
  of `REG_MAC_PHY_CTRL`, skipped for cap 0 like the zeroed CFO state),
  `REG_AFE_XTAL_CTRL = 0x000f81fb`, both RF paths via
  `rtl8xxxu_init_phy_rf` with the RTL8192E `FPGA0_POWER_SAVE` bit-17
  bracket in `rtl8xxxu_write_rfreg`, RF switch control with PAPE, TX buffer
  boundary `0xf4`, auto LLT (checked), gen2 USB quirk, no `REG_PBP`,
  `RX_DRVINFO_SZ = 4`, `HIMR0/1 = 0`.
- TX power (`rtl8192e_set_tx_power`): gen2 channel groups; path A uses
  diff index 0 and path B index 1 (Linux's shared `tx_idx`); `u8 += s8`
  wraps. Implemented as `rtl8192e_phy::{tx_power, set_tx_power}`.
- Post-table MAC (`rtl8192e_radio::post_tables`, `rtl8xxxu_init_device`
  from the WMAC settings to `REG_ACLK_MON`): RCR `0x7000600e`, MAR all-ones
  (no `init_reg_rxfltmap`), RRSR CCK-1M, `set_spec_sifs(0x10,0x10)` →
  `set_retry(0x30,0x30)` → `set_spec_sifs(0x0a,0x10)`, MAC/CCK/OFDM SIFS,
  EDCA, DARFRC/RARFRC, AMPDU retry, ACK timeout, beacon/TBTT/early-int/DMA
  time/TCFG, CCK+OFDM blocks, CAM invalidate (polled to completion;
  `CamTimeout` otherwise — Linux does not poll), `set_tx_power(1, HT20)`,
  HWSEQ, BAR mode, `REG_FAST_EDCA_CTRL = 0`, `REG_QUEUE_CTRL[3] = 0`,
  `REG_ACLK_MON = 0`. No `REG_LEDCFG2` DPDT handover and no GPIO mux write
  (both are skipped for RTL8192E in Linux); no burst/aggregation/packet
  lifetime/statistics hooks (not in `rtl8192eu_fops`).
- Post-calibration (`rtl8192e_radio::post_calibration`): gen2 thermal meter
  (`RF_A 0x42 = 0x37cf8`), `NAV_UPPER`, `REG_USB_HRPWM = 0`, mgmt ACK, the
  LDPC RX hang fix (`REG_AFE_MISC[19:12] = 0x7e`, LDO 0x75) and the CCK AGC
  report type copied from `0x824[9]` to `0x82c[9]` and `0xa80[7]`; the
  `0xa9c[17]` CCK-new-AGC and `0xd2c[11]` CFO ATC states are retained.
- Calibration (`rtl8192e_iqk`), between `post_tables` and
  `post_calibration` exactly where `rtl8xxxu_init_device` runs it:
  `rtl8723a_phy_lc_calibrate` (both paths' RF `0x00` standby in continuous
  TX, else `TXPAUSE` 0xff/0x00 around `MODE_AG[15]` and 100 ms; no S0S1),
  then `rtl8192eu_phy_iq_calibrate`: up to three `rtl8192eu_phy_iqcalibrate`
  runs (ADDA `0x0fc01616`, MAC calibration, BB setup, path-A TX/RX IQK with
  two retries each, path-A standby, path-B TX (1 ms settle)/RX IQK, run ≥ 1
  restores ADDA/MAC/BB, the XA/XB AGC core and the `0xe30/0xe34` default),
  `rtl8xxxu_gen2_simularity_compare` (sign-extended odd entries, the
  `result[3]` per-group/candidate copies verbatim, bound 4 for 1T), Linux's
  candidate 0/1/3 selection, `fill_iqk_matrix_a/b` with Linux u32
  arithmetic (path-B RX ext in `0xc78[15:12]`), and the
  `rtl8xxxu_iqk_phy_iq_bb_reg` recovery snapshot. Deviation: a chosen
  candidate without a path-A TX result (or path-B TX on a 2T board) is
  `Error::Calibration` and the owner fails before the post-calibration tail;
  Linux silently keeps the power-on matrix. The outcome (`Iqk` +
  `PostCalibration`) is retained as `Owner::radio_8192e()`; the owner then
  reaches `RadioReady` (not packet readiness). The former placeholder IQK
  skeleton in `rtl8192e.rs` is removed.
- Channel (`rtl8192e_radio::config_channel`, `rtl8xxxu_gen2_config_channel`
  over both RF paths): 20 MHz (HT or non-HT) and 40 MHz with the secondary
  above (RF channel +2, subchannel 2) or below (−2, subchannel 1), CCK
  sideband, OFDM LSTF prime channel, `FPGA0_POWER_SAVE` upper/lower,
  `WMAC_TRXPTCL_CTL` bandwidth, SIFS `0x0e`/`0x0a`, R2T/T2T, `MODE_AG`
  bandwidth bits. `channel_geometry` admits 1..=13 (HT20), 1..=14 (non-HT),
  and 40 MHz pairs fully inside 1..=13; anything else is `RuntimeState`
  before any transfer. Two-path RF reads use `rtl8192e_radio::read_rfreg`
  (path-A edge strobe, path-specific HSSI/LSSI/HSPI readback).

- Packet codec (`rtl8xxxu/rtl8192e_packet.rs`): the 40-byte gen2 TX
  descriptor from `rtl8xxxu_tx` common fields + `rtl8xxxu_fill_txdesc_v2`
  (OWN/FS/LS/BMC, queue + macid, AMPDU density with `AGG_ENABLE` only on an
  operational TID else `AGG_BREAK`, management `USE_DRIVER_RATE` + retry 6,
  DATA rate 0 with the `0x1f` fallback limit — firmware RA picks the rate —
  RTS/CTS + HW RTS at 24M for A-MPDU/RTS, CTS-to-self without HW RTS,
  short preamble, SN in txdw9; checksum over the first 32 bytes only).
  HW_SEQ_ENABLE stays clear (the station supplies SNs, as on RTL8188EU).
  `rtl8xxxu_parse_rxdesc24`: records at `roundup(…, 8)` until < 24 bytes
  remain, every extent checked, CRC/ICV-error MPDUs dropped, 80 MHz `bw`
  refused, `rpt_sel` records parsed as gen2 C2H (`C2H_8723B_RA_REPORT`
  rate/SGI/macid/LDPC/TXBF/noisy and the optional `bw`). `Frame::admitted`
  refuses hardware-decrypted, fragmented, A-MSDU, LDPC/STBC, HT40 without
  an HT40 admission and A-MPDU members without a recipient BA session.
  RX signal: `rtl8192e_cck_rssi` (report-type table 0/1) for CCK, PWDB for
  OFDM/HT.

- Gen2 firmware RA (`rtl8xxxu/rtl8192e_ra.rs`): `H2C_8723B_MACID_CFG_RAID`
  (8 bytes: macid, RAID|SGI, bandwidth, LE mask), `MEDIA_STATUS_RPT`
  (connect bit, role in [7:4]) and `RSSI_SETTING` (8 bytes on 8192E).
  `Ra::new` refuses an empty peer mask, any peer rate outside the admitted
  set (never narrowed — a 1T board without MCS8..15 refuses a 2SS peer) and
  40 MHz for a non-HT peer. `level_mask` is the 2.4 GHz
  `rtl8xxxu_refresh_rate_mask` (B/G/BG/GN/BGN, 1SS and 2SS, 20/40 low
  masks). `Owner::ra_connect_8192e` is the `BSS_CHANGED_ASSOC` sequence
  (rate mask with rate id 0, `REG_BCN_MAX_ERR = 0xff`,
  `rtl8xxxu_stop_tx_beacon`, `REG_BCN_PSR_RPT = 0xc000 | aid`, media-status
  connect as AP role) and folds the association highest rate into the
  retained TX-rate report; deviation: the bandwidth sent is the operating
  width, not the peer's 20/40 capability. `ra_disconnect_8192e` sets
  `BEACON_DISABLE_TSF_UPDATE` and reports disconnect; `ra_watchdog_8192e`
  is `rtl8xxxu_ra_iter` (RSSI report, then a mask only on a level change).
  C2H RA reports for macid 0 inside the admitted set update the TX rate.
- Packet transport (`packet_transport::Owner::new_8192e`): the same
  persistent-RX/one-TX USB owner with `Codec::Rtl8192e(QueueMap)`. The
  queue map must address only descriptor bulk-OUT endpoints. RX completions
  parse with `rtl8192e_packet::receive` (`poll_receive_8192e`: MPDUs and
  gen2 C2H records); TX uses txdesc40 (`submit_8192e`,
  `submit_null_8192e`, `submit_probe_8192e`) on the
  `rtl8xxxu_queue_select` pipe (MGNT, or the TID's VO/VI/BE/BK entry of
  `rtl8xxxu_init_queue_priority`). A-MPDU density/TID-operational fields
  come only from the owner's negotiated HT/originator state; a caller-set
  density is refused. Each codec's entry points refuse the other chip's
  owner, and the delivered native length subtracts that codec's descriptor.
- RF/power (`rtl8xxxu/rtl8192e_power.rs`): `rtl8192e_enable_rf`,
  `rtl8xxxu_gen2_disable_rf` and `rtl8192eu_power_off` (flush_fifo, TX
  report timer off, `REG_RF_CTRL = 0`, `active_to_lps`, firmware self
  reset when running from RAM, MCU reset, `reset_8051`, active→EMU,
  EMU→disabled). RXDMA-idle and `REG_SCH_TX_CMD` polls are terminal
  `PowerTimeout` (Linux only warns). The owner's park path
  (`power_off_stopped`) dispatches RTL8192EU to this sequence. Station PS
  reuses the shared `ps_null` frames through `rtl8192e_packet::transmit_null`.

- USB IDs: the bind/classification tables carry exactly the Linux
  `core.c::dev_table` `rtl8192eu_fops` rows (0bda:818b, 0bda:818c,
  2357:0107/0108/0109/0126, 2001:3319/3312, 2019:ab33, 2c4e:0100/0104).
  2357:0135 and 7392:b722 are `rtl8192fu_fops` in Linux; they were
  wrongly listed as RTL8192EU and are now unbound/Unknown (no RTL8192FU
  owner exists).

#### RTL8192EU signed records (`N92P` v1)

`rtl8192e_policy::Calibration::load_registered(factory, vid, pid)` opens
only `rtl8xxxu/rtl8192eu-cal-v1-<12 lowercase MAC hex digits>.bin` through
the current firmware-registry capability, with mandatory signer metadata
(as N8PC). The private parser cannot mint a permission. Linux
`8192e.c::rtl8192e_set_tx_power` programs raw factory indices and has no
dBm conversion or board curve, so the record qualifies exactly the indices
`rtl8192e_phy::tx_power` programs; no board value ships in the tree.
Integers are little endian. Header (128 bytes):

| Offset | Value |
|---|---|
| 0 | magic `N92P` (distinct from 8188EU `N8PC`/`N8HT`) |
| 4 | version:u16 = 1 |
| 6 | header bytes:u16 = 128 |
| 8 | exact total payload bytes:u32 |
| 12 | USB VID:u16, 14 PID:u16, 16 chip:u16 = 0x8192 |
| 18 | cut, 19 profile = 1 (USB 2.4 GHz HT20/40 station, no power tracking), 20 `tx_paths` (1 = RTL8191EU 1T2R, 2), 21 ROM rev |
| 22 | factory MAC[6] |
| 28 | path A then B: CCK[6], HT40[5], OFDM/HT20/HT40 diffs[4] each (23 bytes per path, diffs as two's-complement bytes) |
| 74 | crystal cap, channel plan, thermal, board option, antenna option, PA type, LNA type, IQK/LCK |
| 82 | envelope:u8 = 1 (whole qualified board operating envelope), 83 reserved = 0 |
| 84 | maximum antenna gain:i16 quarter-dBi 0..128; 86 board-qualified EIRP:i16 quarter-dBm -512..256 |
| 88 | rows:u16 1..31, 90 reserved = 0 |
| 92 | admitted RA mask:u32 (`DESC_RATE` bits 0..27; nonzero; no bit ≥ 28; MCS8..15 refused when `tx_paths = 1`) |
| 96 | reserved[32] = 0 |

Each 28-byte row: primary channel (1..13), width code (0 = HT20, also used
for non-HT 20 MHz; 1 = HT40 secondary above, primary 1..9; 2 = below,
primary 5..13), reserved[2]; then per path A, B: the programmed CCK, OFDM
and MCS indices (must equal `tx_power` for that EFUSE/channel/width),
reserved, then CCK/OFDM/MCS conducted upper bounds:i16 quarter-dBm
(-512..256, or `0x7fff` unknown), reserved:i16. Rows strictly increase by
(channel, width). A 1T2R board's path-B bounds must all be unknown.

`Calibration::permission(domain, primary, width)`: every regulatory rule
overlapping the occupied span (center ±10 MHz, or the full 40 MHz pair)
must cover it entirely, allow that width and carry no flags; the most
restrictive dBm ceiling (as EIRP) is intersected with the board EIRP. For
each rate class the admitted mask contains (CCK, OFDM, MCS), every TX
path's bound must be known; two chains add 13 quarter-dB (≥ 3.0103 dB,
never rounded down); bound + antenna gain must not exceed the ceiling.
An unknown or excessive class refuses the channel — the admitted mask is
never narrowed. The opaque `Permission` carries the primary/width and the
admitted mask that `Ra::new` takes; `Permission::check` revalidates the
exact factory/VID/PID/channel/width before programming. Synthetic test
records validate format/arithmetic only.

The owner reaches `RadioReady` for RTL8192EU after calibration. The production
probe (`rtl8xxxu_probe`) now starts the RTL8192EU owner like RTL8188EU:
`wait_initialize_registered()` waits for `rtlwifi/rtl8192eu_nic.bin`, then
`rtl8192e_admission::wait_admit` waits for the signed `N92P` record, the
signed `wireless-regulatory.bin` policy and the network authority. Missing
assets keep the radio unadmitted and retry every 500 ms; unsigned, invalid,
mismatched-identity or unqualified-initial-channel records are terminal
(`Profile`). Admission yields the record, domain and the channel-1 HT20
`Permission` (with the admitted RA mask); it does not by itself publish a
netdev or open MAC TX/RX.

`Owner::start_8192e(permission)` is the RF half of `rtl8xxxu_start`
(`rtl8192e_enable_rf`) followed by the admitted initial channel;
`Owner::tune_8192e(permission, primary, width)` is `rtl8xxxu_config`'s
channel change (`rtl8192e_set_tx_power(primary, ht40)` then
`rtl8xxxu_gen2_config_channel`). Both revalidate the permission against the
retained factory/VID/PID and the exact primary/width before any transfer, and
return the admitted RA mask. A retune therefore needs a separately granted
permission for the new channel/width; there is no default.

The RTL8192EU station is the shared gen2 station composition below
(`### Gen2 station (RTL8192EU, RTL8723BU)`); the probe publishes its netdev
after `wait_admit`.

### RTL8723BU native owner

RTL8723BU (1T1R WiFi + Bluetooth combo, `8723b.c`) is the third native
rtl8xxxu chip. It reuses the retained one-shot `firmware_transport::Owner`
and the gen2 pieces of `rtl8192e_init` (SIE/no-SIE queue decode,
`rtl8xxxu_init_queue_priority`, PG-header EFUSE decode, gen2 H2C mailbox);
8723B-specific steps live in `rtl8xxxu/rtl8723b_init.rs`.

- Image: `rtlwifi/rtl8723bu_nic.bin` (`rtl8723bu_load_firmware`; Linux
  selects no other variant), signature family `0x5300`; an 88E-signed image
  is rejected before any USB access. Shared download with
  `writeN_block_size = 1024`, `rtl8723bu_reset_8051` (RSV_CTRL bit 1 /
  bit 8 bracket around the CPU-enable toggle), then the `init_reg_hmtfr`
  write `REG_HMTFR = 0x0f` after firmware start. No download retry.
- Identity (`rtl8723bu_identify_chip`): `REG_SYS_CFG` cut/vendor (test
  silicon refused), `REG_MULTI_FUNC_CTRL` WiFi/BT/GPS function bits
  (`is_multi_func`), `REG_GPIO_OUTSTS` ROM rev, TX queues from
  `REG_NORMAL_SIE_EP_TX` or the bulk-OUT count (a SIE set larger than the
  descriptor's bulk-OUT endpoints is `BadEndpoints`).
- EFUSE: the multi-function `rtl8xxxu_read_efuse` selects the WiFi cell
  (`REG_EFUSE_TEST[9:8] = EFUSE_WIFI_SELECT`) before the shared PG decode
  (Linux does it after its discarded `REG_9346CR` read; order otherwise
  identical). `rtl8723bu_parse_efuse`: `0x8129` ID, MAC at `0x107`, path
  A/B CCK and HT40 bases, `ofdm_diff[0]`/`ht20_diff[0]` from the low/high
  nibble of `ht20_ofdm_1s_diff`, `ht40_diff[0] = 0`, indices 1..3 from
  `pwr_diff[]` (signed 4-bit), crystal cap `xtal_k & 0x3f`, plus the raw
  thermal/IQK-LCK/PA/LNA/board/BT/antenna/RFE/package bytes. Retained as
  `Owner::factory_8723b()`.
- Power (`rtl8723bu_power_on`): `rtl8xxxu_disabled_to_emu`,
  `rtl8723b_emu_to_active` (checked polls; Linux's 8-bit read / 32-bit
  write of `REG_APS_FSMCO` when clearing SW LPS is kept verbatim), CR with
  MAC TX/RX + CALTIMER, then the BT-coexistence power-on settings
  (`PAD_CTRL1+3 = 0x20`, BB resets, `BT_CONTROL+1 = 0x18`,
  `WLAN_ACT_CONTROL = 0x04`, `S0S1_PATH_SWITCH = 0`, antenna inverse
  `0xfe08 = 1`, RFE pad enable, `LEDCFG0` DPDT select, `PAD_CTRL1[0]`
  clear). `rtl8723bu_active_to_emu` is implemented for the power-off path.
- Pre-firmware (`needs_full_init`, always cold): reserved pages with the
  8723B budget (HI 0x0c, LO 2, NORM 2 of 0xf7), queue priority (retained
  as `Owner::queues_8723b()`), `TRXFF_BNDY+2 = 0x3f7f`.

- Tables (`rtl8xxxu/rtl8723b_tables.rs`, generated verbatim by
  `rtl8xxxu/gen_rtl8723b_tables.py` from `8723b.c`): MAC 103, PHY 193,
  AGC 131, RF A 108 rows (+ Linux sentinel).
- `rtl8723b_phy::mac_bb_rf` (`rtl8xxxu_init_device` antenna selection →
  HIMR): `rtl8723bu_phy_init_antenna_selection` (PAD_CTRL1[20,24],
  GPIO_MUXCFG[4:3], LEDCFG0[24:23], RFE buffer, `RFE_CTRL_ANTA_SRC = 0x77`,
  RFE pad), MAC table (no `REG_MAX_AGGR_NUM`), `rtl8723bu_init_phy_bb`
  (BB resets + DIO_RF, S0S1 switch 0, RF_CTRL 7, `SYS_FUNC = 0xe3`,
  `AFE_XTAL_CTRL+1 = 0x80`, PHY + AGC; 1T1R so no 1T2R patch),
  `rtl8723a_set_crystal_cap` (skipped for cap 0), RF A via
  `rtl8xxxu_init_phy_rf` with the plain `rtl8xxxu_write_rfreg` (no
  RTL8192E power-save bracket), then the `rtl8723bu_init_phy_rf` PHY LCK
  (`0xb0 = 0xdfbe0`, `MODE_AG = 0x8c01`, 200 ms, `0xb0 = 0xdffe0`); RF
  switch control with PAPE, `XA_RF_INT_OE = 0x66f60210`, no
  `FPGA0_TX_INFO = 3`, TX buffer boundary `0xf8`, `REG_PBP = 0x22`, auto
  LLT (checked), gen2 USB quirk, the `has_tx_report` timer (bit 1 only,
  max macid 2, `0xcdf0`, `0xa3 &= 0xf8`), `RX_DRVINFO_SZ = 4`,
  `HISR`/`HIMR` all-ones.
- TX power (`rtl8723b_set_tx_power`, `rtl8723b_phy::{tx_power,
  set_tx_power}`): gen2 channel group; the path-B EFUSE CCK/HT40 indices
  with diff index 0's `.b` member, written to the path-A AGC registers
  (CCK1/CCK2-11, OFDM 6..54, MCS0..7); `u8 += s8` wraps.

- Post-table MAC (`rtl8723b_radio::post_tables`, `rtl8xxxu_init_device`
  from the WMAC settings through `init_statistics`): RCR `0x7000600e`, MAR
  all-ones (no `init_reg_rxfltmap`), RRSR CCK-1M, spec SIFS/retry, MAC/CCK/
  OFDM SIFS, EDCA, DARFRC/RARFRC, AMPDU retry, ACK timeout, beacon/TBTT/
  early-int/DMA time/TCFG, `rtl8xxxu_init_burst` (RXDMA_PRO burst 1/3 +
  DMA mode, single-AMPDU, `MAX_AGGR_NUM = 0x0c14`, `AMPDU_MAX_TIME = 0x5e`,
  AGGLEN all-ones, RX_PKT_LIMIT 0x18, PIFS 0, USTIME TSF/EDCA 0x50, RSV_CTRL
  WLOCK_1C|DIS_PRST), `rtl8723bu_init_aggregation` (RX aggregation off), no
  packet lifetime, CCK+OFDM blocks, CAM invalidate (polled; `CamTimeout`),
  `set_tx_power(1, HT20)`, `REG_LEDCFG2` DPDT select (antenna to the 8051),
  HWSEQ, BAR mode, `FAST_EDCA_CTRL = 0`, `rtl8723bu_init_statistics` (NHM
  timer/thresholds, TH8, CCK, `OFDM0_FA_RSTC[7]`). No `QUEUE_CTRL`,
  `ACLK_MON`, GPIO mux or `USB_HRPWM` writes (not for RTL8723B in Linux).
- Calibration (`rtl8723b_iqk`): `rtl8723a_phy_lc_calibrate` with
  `has_s0s1` (RF `0xb0 = 0xdfbe0` / `0xdffe0` around `MODE_AG[15]` and
  100 ms; TXPAUSE bracket, or path-A standby in continuous TX), then
  `rtl8723bu_phy_iq_calibrate`: `H2C_8723B_BT_WLAN_CALIBRATION(1)`, saved
  `REG_BT_CONTROL_8723BU`, up to three `rtl8723bu_phy_iqcalibrate` runs
  (ADDA `0x01c00014`, MAC calibration, BB setup with `XCD_RF_SW_CTRL =
  0x22204000`, the D-cut RF PA table, two retries each of
  `rtl8723bu_iqk_path_a`/`rtl8723bu_rx_iqk_path_a` with S0S1 `0x280` and BT
  grant `0x800` around each one-shot; `RTL8723BU_BT` is undefined so no
  `GNT_BT` writes; the 8723B pass windows incl. `0xf0 < e94 < 0x110` and
  `|e9c| < 0xf`), run ≥ 1 restores ADDA/MAC/BB (BB list ends in
  `FPGA0_RF_MODE`) and XA AGC, `rtl8xxxu_gen2_simularity_compare` (bound 4),
  candidate 0/1/3 or Linux's `-1` when `result[3]` is empty,
  `fill_iqk_matrix_a`, the recovery snapshot, BT control restore, the final
  RF PA table/`0xed`/`0x43 = 0x300bd` and `BT_WLAN_CALIBRATION(0)`.
  Deviation: no candidate, or a candidate without a path-A TX result, is
  `Error::Calibration` after that restore tail (Linux keeps the power-on
  matrix). The zero-valued IQK/LC skeleton in `rtl8723b.rs` is removed.
- Post-calibration (`rtl8723b_radio::post_calibration`): gen2 thermal meter
  (`RF_A 0x42 = 0x37cf8`), `NAV_UPPER`, mgmt ACK, `0xa9c[17]` and
  `0xd2c[11]` retained. The outcome is `Owner::radio_8723b()` and the owner
  reaches `RadioReady` (not packet readiness).

- Channel (`rtl8723b_radio::config_channel`, `rtl8xxxu_gen2_config_channel`
  with `rf_paths = 1`): RF_A only through the plain `write_rfreg`, the shared
  2.4 GHz `channel_geometry` (HT20 1..=13, non-HT 1..=14, 40 MHz pairs inside
  1..=13; anything else `RuntimeState` before any transfer), CCK sideband,
  OFDM LSTF prime channel, `FPGA0_POWER_SAVE`, `WMAC_TRXPTCL_CTL`, SIFS
  `0x0e`/`0x0a`, R2T/T2T, `MODE_AG` bandwidth bits.
- RF enable (`rtl8723b_power::enable_rf`, `rtl8723b_enable_rf`): RX CCA
  wait, `0x790 = 5`, `0x778 = 1`, GPIO mux[5], `RF_A IQADJ_G1 = 0x780`,
  `rtl8723bu_write_btreg(0x3c, 0x15)` (two `BT_MP_OPER` H2Cs, request 0 data
  / request 1 address), `BT_GRANT(0)`, `WLAN_ACT_CONTROL = 0x0c`, `0x67[5]`,
  RFE control/`0x974 = 0xff`/buffer/antenna source, LEDCFG0 pins,
  `PAD_CTRL1[0]` clear, `ANT_SEL_RSV(inverse 1, type 0)`, S0S1 `0x80`,
  `rtl8723bu_set_ps_tdma(0x08, 0, 0, 0, 0)`, coex tables `0x55555555`/
  `0x55555555`/`0x00ffffff`/`0x03`, `BT_INFO(1)`, `BT_IGNORE_WLANACT(0)`.
  `disable_rf` is the shared `rtl8xxxu_gen2_disable_rf`.
- Power-off (`rtl8723b_power::power_off`, `rtl8723bu_power_off`): flush
  FIFO, TX report timer off, `REG_CR = 0`, the generic
  `rtl8xxxu_active_to_lps` (low-byte `0x5f8` poll, byte CR writes), firmware
  self reset when in RAM, MCU reset, `MCU_FW_DL = 0`,
  `rtl8723bu_active_to_emu`, `APS_FSMCO` HW suspend, GPIO9 wake. Polls that
  Linux only warns on are terminal `PowerTimeout`. The owner's park path
  (`power_off_stopped`) dispatches RTL8723BU to this sequence.

- Packet codec and RA (`rtl8xxxu/rtl8723b_packet.rs`): `rtl8723bu_fops`
  shares `txdesc40`, `rtl8xxxu_fill_txdesc_v2`, `rtl8xxxu_parse_rxdesc24` and
  the gen2 `update_rate_mask`/`report_connect` with the RTL8192EU, and none
  of those Linux paths has an RTL8723B branch, so the 8723BU uses
  `rtl8192e_packet` and the gen2 `packet_transport` codec
  (`packet_transport::Owner::new_8192e` with `Owner::queues_8723b()`), and
  `rtl8192e_ra::Ra` with `tx_paths = 1` (a 2SS peer is refused, never
  narrowed). Chip-specific: `rtl8723b_packet::signal` (`rtl8723b_cck_rssi`:
  LNA 6/4/1/0 → −34/−14/6/16 − 2·VGA, any other LNA index 0 as Linux; OFDM
  PWDB as gen2) and the 4-byte `RSSI_SETTING`
  (`rtl8xxxu_gen2_report_rssi` truncates for RTL8723B) in
  `Owner::ra_watchdog_8723b`.

- BT coexistence (`rtl8xxxu/btcoex.rs`, replacing an invented decision
  matrix with zero-valued tables): exactly Linux rtl8xxxu, which has no
  vendor halbtc engine. `bt_info` takes byte 1 of a `C2H_8723B_BT_INFO`
  (id 9) body; `Coex::update_link_info` is `rtl8723bu_update_bt_link_info`
  (status ConnectedIdle/ScoBusy/AclBusy/Max, profile bits, `hid_only`, and
  Linux's `has_a2dp` rewrite where `a2dp_only` was meant, so `a2dp_only` is
  never set), `inquiry_action` is `rtl8723bu_handle_bt_inquiry` and
  `info_action` is `rtl8723bu_handle_bt_info` (associated: busy profile
  TDMA/table choices, else the `0x770` high-priority TX+RX ≤ 60 → table 2,
  else 7; unassociated: TDMA `0x08` + table 0). `coex_table` is
  `rtl8723bu_set_coex_with_type` (types 0..7, TABLE4 `0x03`, others write
  nothing). `Owner::c2h_bt_8723b` is the BT-info case of
  `rtl8xxxu_c2hcmd_callback` (update, inquiry or info policy, then
  `rtl8723bu_set_ps_tdma` and the table); RA reports are left to the
  caller. `assoc` is `rtl8xxxu_is_assoc` supplied by the station.

#### RTL8723BU signed records (`N8BP` v1)

`rtl8723b_policy::Calibration::load_registered(factory, vid, pid)` opens
only `rtl8xxxu/rtl8723bu-cal-v1-<12 lowercase MAC hex digits>.bin` through
the current firmware-registry capability, with mandatory signer metadata
(as N92P/N8PC). Linux `8723b.c::rtl8723b_set_tx_power` programs raw
factory indices (the path-B EFUSE bases + diff index 0, into the single
path-A transmitter) with no dBm conversion or board curve, so the record
qualifies exactly the indices `rtl8723b_phy::tx_power` programs for the one
TX chain; no board value ships in the tree. Little endian. Header (128
bytes):

| Offset | Value |
|---|---|
| 0 | magic `N8BP` (distinct from `N8PC`/`N8HT`/`N92P`) |
| 4 | version:u16 = 1 |
| 6 | header bytes:u16 = 128 |
| 8 | exact total payload bytes:u32 |
| 12 | USB VID:u16, 14 PID:u16, 16 chip:u16 = 0x8723 |
| 18 | cut, 19 profile = 1 (USB 2.4 GHz HT20/40 1T1R station, no power tracking), 20 function bits (WiFi bit 0, BT bit 1, GPS bit 2), 21 ROM rev |
| 22 | factory MAC[6] |
| 28 | EFUSE path A then B: CCK[6], HT40[5], OFDM/HT20/HT40 diffs[4] each (23 bytes per path, two's complement) |
| 74 | crystal cap, channel plan |
| 76 | thermal, IQK/LCK, PA type, LNA type, board option, BT setting, antenna option, RFE option |
| 84 | envelope:u8 = 1 (whole qualified board operating envelope), 85 reserved = 0 |
| 86 | maximum antenna gain:i16 quarter-dBi 0..128; 88 board-qualified EIRP:i16 quarter-dBm -512..256 |
| 90 | rows:u16 1..31, 92 reserved[2] = 0 |
| 94 | admitted RA mask:u32 (`DESC_RATE` bits 0..19 only: CCK, OFDM, MCS0..7; nonzero) |
| 98 | reserved[30] = 0 |

Each 16-byte row: primary channel (1..13), width code (0 = HT20, also for
non-HT 20 MHz; 1 = HT40 above, primary 1..9; 2 = below, 5..13),
reserved[2]; the programmed CCK, OFDM and MCS indices (must equal
`tx_power` for that EFUSE/channel/width), reserved; CCK/OFDM/MCS conducted
upper bounds:i16 quarter-dBm (-512..256, or `0x7fff` unknown); reserved:i16.
Rows strictly increase by (channel, width).

`Calibration::permission(domain, primary, width)` is the N92P rule set for
one chain: every overlapping regulatory rule must cover the occupied span,
allow the width and carry no flags; the most restrictive ceiling (EIRP) is
intersected with the board EIRP; every admitted rate class must have a
known bound with bound + antenna gain ≤ ceiling, else the channel is
refused (never narrowed). `Permission::check` revalidates factory/VID/PID/
channel/width before programming. Synthetic test records validate
format/arithmetic only.

Production probe (`rtl8xxxu_probe`): the RTL8723BU owner starts like the
RTL8192EU: `wait_initialize_registered()` waits for
`rtlwifi/rtl8723bu_nic.bin`, the owner runs to `RadioReady`, then
`rtl8723b_admission::wait_admit` waits for the signed `N8BP` record, the
signed `wireless-regulatory.bin` and the network authority (missing assets
retry every 500 ms; unsigned/invalid/mismatched/unqualified-initial-channel
records are terminal `Profile`). Admission yields the channel-1 HT20
`Permission`; it publishes no netdev and opens no MAC TX/RX.
`Owner::start_8723b(permission)` revalidates the permission, then runs
`rtl8723b_enable_rf` (with the BT-coex handover) and the admitted initial
channel; `Owner::tune_8723b(permission, primary, width)` is
`rtl8xxxu_config`'s `rtl8723b_set_tx_power` + `config_channel`, refused
before any transfer without an exact permission.

The RTL8723BU station, its C2H BT-info/RA routing and `restart_parked` are
the shared gen2 station composition below. USB IDs are exactly Linux
`core.c::dev_table` `rtl8723bu_fops` rows (0bda:b720, 7392:a611).

Regressions (written, unexecuted) in `rtl8xxxu/rtl8723b_tests.rs`
(`drivers/wireless/rtl8xxxu/8723bu`): identity/EFUSE/page budget,
power + firmware + tables + calibration lifecycle against a register
model, no-SIE fallback and test-silicon refusal, table/antenna/PHY-LCK/
post-RF state, TX power indices, post-table burst/aggregation/DPDT/
statistics, LCK/IQK H2C/BT-grant/RF sequence and candidate, a failed
IQK being terminal after Linux's restore tail, the enable_rf H2C/BT
sequence, 1T 20/40 MHz channel writes and geometry refusal, and power-off
order plus a stuck-queue timeout.

### Gen2 station (RTL8192EU, RTL8723BU)

One composition serves both gen2 chips (`gen2_radio.rs`,
`gen2_station.rs`, `gen2_interface.rs`); the RTL8188EU chain
(`receive_runtime`/`station_runtime`/`service_runtime`/`interface`) is
unchanged. `gen2_radio::Grant` carries the chip's admitted initial-channel
`Permission` (`rtl8192e_policy`/`rtl8723b_policy`), the only channel and
rate authority.

- Radio (`gen2_radio::Radio`): `packet_transport::Owner::new_8192e` over
  the chip's retained queue map (`queues_8192e`/`queues_8723b`). `start`
  is `rtl8xxxu_start`: `start_8192e`/`start_8723b` (enable_rf + admitted
  channel; the returned mask must equal the grant), the one receive claim,
  the persistent RX transfer, `REG_RXFLTMAP2`/`REG_RXFLTMAP0 = 0xffff`, IGI
  `0x1e`. `prepare_station` is `rtl8xxxu_add_interface(STATION, port 0)`
  (`stop_tx_beacon`, `BEACON_ATIM | FUNCTION_ENABLE | DISABLE_TSF_UPDATE`,
  `set_linktype`, `set_mac`) + `set_bssid` + slot time, then TSF updates
  re-enabled (Linux: `sw_scan_complete`). `poll` parses rxdesc24
  (`poll_receive_8192e`): only `gen2_radio::admit` MPDUs (legacy 20 MHz
  plaintext; HT20 under an HT association, see below) become `Mpdu`s; bound-BSS frames feed the
  `ewma_rssi` (`rtl8192e_packet::signal` with `cck_agc_report_type`, or
  `rtl8723b_packet::signal`); C2H RA reports fold into `Ra::report`;
  `C2H_8723B_BT_INFO` records (8723BU only) queue (bound 8) for the async
  path (`route_c2h`). `associate(aid, peer)` is `BSS_CHANGED_ASSOC`:
  `Ra::new(peer, grant.admitted(), tx_paths, false)` (refused, never
  narrowed) then `ra_connect_8192e` (shared gen2 `update_rate_mask` +
  `report_connect`). `maintain` runs `rtl8xxxu_ra_iter` every 2 s
  (`ra_watchdog_8192e`/`ra_watchdog_8723b` with `-ewma_rssi_read`) and the
  queued BT records through `Owner::c2h_bt_8723b(coex, record, assoc)`
  where `assoc` (`rtl8xxxu_is_assoc`) is the station's association.
  While no station is serviced, the scan/listen path drains the same
  queue through `Radio::drain_bt(assoc)`: `assoc = false` for an
  unbound radio, `assoc = true` for a station's off-channel visit
  (Linux `rtl8xxxu_is_assoc` stays true through a scan, while NARF's
  `leave` takes `ra`, so the radio alone cannot answer it) — BT info
  is programmed while idle, not only while a station is serviced.
  `stop` is `ra_disconnect_8192e` then `rtl8xxxu_stop` (`REG_TXPAUSE`,
  RX filter maps cleared, host transfers retired, `REG_TXPAUSE`,
  `disable_rf`); `park` is `park_stopped` (`rtl8192eu_power_off` /
  `rtl8723bu_power_off`); `restart_parked` is a fresh
  `rtl8xxxu_init_device` lifecycle back to `RadioReady` (the RTL8188EU
  identity check is replaced for gen2 by `run_device_8192e`/`_8723b`
  refusing an EFUSE/endpoint change with `BadEfuse` and a queue-map change
  with `BadEndpoints`), after which `start` is permitted again.
- Station (`gen2_station::Station`): `Join::prepare(..)` (a WMM AP
  selects the optional QoS station below; otherwise legacy non-QoS),
  Authentication/Association through the shared join plan,
  firmware RA at association over the negotiated `supp_rates[0]`, then the
  shared RSNA supplicant (`Security`, software CCMP, private EAPOL epoch
  rule and reply-delivery receipt as `station_runtime`) or the open port.
  TX DATA is txdesc40 with firmware RA rates (non-QoS on the BE pipe for a
  legacy peer).
- Netdev (`gen2_interface`): `attach` after `wait_admit` publishes one
  `wlan%d` per boot (shared singleton like RTL8188EU); a failed join is
  terminal for the owner (as RTL8188EU). `disassociate` is station stop,
  park and `restart_parked` before the radio returns idle.

#### Gen2 qualified channels and scans

`gen2_radio::Authority` retains the admitted signed record (`N92P`/`N8BP`)
and the authenticated regulatory domain; `Authority::grant(primary)` is
`Calibration::permission(domain, primary, INITIAL_WIDTH)` (current firmware
capability invoked, the occupied 20 MHz band intersected with every rule,
missing measured rows and unsupported flags refused, never interpolated).
It is the only source of a non-initial `Grant`; the advertised channel list
is the set granted at attach, and every use mints its own grant again.

`Radio::retune(grant)` is the gen2 cold channel change of an unbound radio:
`rtl8xxxu_stop` (TXPAUSE, RX filter maps cleared, USB Stop/SetDeq of both
host transfers, `disable_rf`), `rtl8192eu_power_off`/`rtl8723bu_power_off`,
a fresh `rtl8xxxu_init_device` lifecycle with the gen2 identity check,
`retarget_live` (live retune: the posted RX transfer stays posted — the
channel is RF state, not per-transfer content — while association state
resets and the channel label moves, with no TX outstanding) on a
receiving radio, or `retarget_stopped` (channel label changes only with
no transfer posted) after the cold lifecycle, then `rtl8xxxu_start`
whose `tune_8192e`/`tune_8723b` revalidate the grant against the retained
factory/USB identity before `set_tx_power` + `gen2_config_channel`. A
never-started radio only relabels. Linux `rtl8xxxu_config` retunes live;
the cold boundary is the RTL8188EU rule that no old-channel device-FIFO
byte reaches a new receive stream — the live path keeps the transfer
posted but the RF programming moves, so it is used only where no
device-FIFO byte is in flight (unbound radios, no TX outstanding).
Each retune, cold or live, advances `Radio::generation`. Any failure is
terminal.

- `set_config(channel)`: idle live retune under that channel's grant
  (no TX power override; a station keeps its channel, other values `Busy`).
- Idle scans: bounded channel/frequency lists (1..=13, empty = every granted
  channel), at most one SSID for active requests and up to 2048 checked
  extra probe IEs (`max_scan_ssids = 1`, `max_scan_ie_len = MAX_IE`), no
  random address/6 GHz. All grants, the probe frame and its timing are
  admitted before the first transition. Each visit live-retunes (skipped for
  the current receiving channel) and either dwells passively or emits one
  `probe_runtime::Prepared` broadcast Probe Request (`Radio::submit_probe`:
  unbound receiving radio, exact local TA/current DS channel, legacy rates,
  txdesc40 MGNT pipe, the board's HT Capabilities body when the signed
  record supports HT) after the source 31 ms pre-probe delay, awaits its
  exact host USB receipt (not an ACK) and listens the response window
  (`Prepared::timing`). Home is restored. The candidate cache keeps at most
  32 entries (oldest evicted) for 10 s, each with its observation time and
  receive generation; entries on a channel no longer granted are hidden.
- Associated scans (passive and active), mac80211 `scan.c`/`offchannel.c`
  timing: refused unless the station is authorized with no TX/EAPOL receipt
  or RSNA handshake outstanding; mandatory dwell above 125 ms is refused,
  others are capped at 125 ms. A passive visit to the home channel listens in
  normal service (home observations captured). Every other visit, and every
  active visit, serves home until quiescent, sends the plaintext ToDS PM1
  non-QoS Null (`Station::send_null`: SN from the shared non-QoS
  DATA/EAPOL space via `reserve_plain_control_sequence` or the open
  counter, no PN; txdesc40 BE pipe, best effort as rtl8xxxu has no
  `REPORTS_TX_ACK_STATUS`), serves home for the 100 ms no-flush grace,
  `leave`s (`ra_disconnect_8192e` + `rtl8xxxu_stop`), cold-retunes the
  unbound radio to the visited channel (away MPDUs reach only the candidate
  parser; the probe reserves its SN from the same space), then `rejoin`s:
  cold retune to home, `add_interface`/`set_bssid`/slot and
  `ra_connect_8192e` for the same AID and negotiated rates, monitoring reset;
  PM0 Null and a 200 ms home grace follow. Join plan, keys, PN/replay windows
  and sequence owners survive the visit.
- `associate`: Open or WPA2-PSK against a cached candidate on a granted
  channel (pure Join/SME-IE admission first). If the candidate is on
  another channel the idle radio cold-retunes; the join then requires a copy
  of that BSS from the current receive generation (a hidden SSID found via a
  probe response is probed again, directed), waiting at most 2 s, never an
  old entry's age.

#### Gen2 optional WMM (all ACs/TIDs)

As the RTL8188EU WMM program: a valid AP WMM Parameter element makes the
join plan append the driver Information IE (no U-APSD) and require valid
rows in the peer-bound Association Response (missing/malformed/BE-ACM rows
are terminal). Before `BSS_CHANGED_ASSOC` (mac80211
`ieee80211_assoc_success` order) `Radio::configure_edca` is
`rtl8xxxu_conf_tx` for every AC: `REG_EDCA_BE/BK/VI/VO_PARAM`
0x508/0x50c/0x504/0x500 from `wmm_runtime::words_profile` (`rtl8xxxu_set_aifs`
SIFS 10 for this legacy 2.4 GHz profile + AIFSN x 9/20 us slot; BE kept
conservative), each with exact readback, then `REG_ACM_HW_CTRL` 0x5c0
BK0/BE1/VI2/VO3 from each AC's ACM. Unprogrammable rows are refused before
any write. Only then does the packet owner admit QoS DATA. `send_ethernet`
classifies with `cfg80211_classify8021d` + `ieee80211_downgrade_queue`
(`rtlwifi::wmm::priority`) over the installed rows; WPA2 uses
`transmit_ethernet_qos` (TID in the CCMP nonce, per-TID PN/SN), Open uses
per-TID SN spaces (`open_qos_data`). txdesc40 QSEL follows
`rtl8xxxu_queue_select` (BK2, BE0, VI5, VO7, MGNT 0x12) and the pipe the
chip queue map (`rtl8xxxu_init_queue_priority`); txdesc40 has no separate
QoS bit (`rtl8xxxu_fill_txdesc_v2`). A bound-AP beacon with a changed WMM
Parameter Set Count is checked and applied in the next `step` through the
same writes (unchanged count ignored; WMM loss is peer loss). Scan Nulls use
QoS Null TID7/SN0 for a WMM peer; a scan `rejoin` reprograms the installed
EDCA rows after the cold restart. TSPEC/U-APSD stay inapplicable as for
RTL8188EU. Regression (written, unexecuted):
`smoke_rtl8xxxu_gen2_wmm_qos_data_queues`.

#### Gen2 optional HT20 (SGI_20, A-MPDU/BA)

As the RTL8188EU HT20 program shape, over the shared gen2 composition. The
local capability is `gen2_radio::ht_capability` (Linux core.c
`rtl8xxxu_probe` `sband->ht_cap`): `IEEE80211_HT_MAX_AMPDU_64K`,
`IEEE80211_HT_MPDU_DENSITY_16`, `IEEE80211_HT_CAP_SGI_20`,
`rx_mask[0] = 0xff`, `IEEE80211_HT_MCS_TX_DEFINED`; `rx_mask[1] = 0xff` only
for a 2T RTL8192EU whose signed `N92P` record admits MCS8..15 (RTL8723BU is
1T1R). TX selection is the signed admitted MCS set; a record admitting no MCS
keeps the legacy station. The plan is offered (`Join::prepare_with_phy`) only
to a WMM AP (mac80211 `ieee80211_determine_chan_mode` disables HT without
WMM); a non-HT WMM AP still negotiates the QoS station. Scan/beacon
observation uses `Candidate::from_receive_with_phy` (HT membership selector
accepted).

At association EDCA is programmed with the HT SIFS (`rtl8xxxu_set_aifs`
16 us for `WIRELESS_MODE_N_24G`), then `Radio::associate` with the HT
`Peer` (`legacy` = `supp_rates[0]`, `mcs` = negotiated peer RX within the
signed selection, `ht`, `sgi` = negotiated SGI_20) through `Ra::new`
(refused, never narrowed) and `ra_connect_8192e`; the firmware RA mask then
carries `ht_cap.mcs.rx_mask` (`rtl8xxxu_refresh_rate_mask`). txdesc40 has no
SGI bit: the firmware applies SGI from the MACID config.

RX: `gen2_radio::admit` replaces `Frame::admitted(false, false, false)`:
HT MCS within the advertised streams at 20 MHz only under the HT
association; A-MPDU members (`paggr`) only on a TID with an accepted
recipient session; a standalone A-MSDU whose descriptor and QoS-header bits
agree, never inside an A-MPDU. `Mpdu.ht` is the descriptor rate class and
`Mpdu.ba` the `paggr` bit; `station_admitted` is the gen2 station gate.
Standalone A-MSDUs go through whole-aggregate authentication
(`Security::receive_amsdu`) or the Open decode; a bad MIC/subframe publishes
nothing.

Block Ack (`ba_sessions::Sessions`, the RTL8188EU `station_runtime` rules
as plain data): recipient ADDBA per `__ieee80211_start_rx_ba_session`
(TSPEC 37, delayed/oversized 38, window0 = 64, same-token update only with
unchanged timeout, new token replaces), response with immediate policy and
A-MSDU clear (no `SUPPORTS_AMSDU_IN_AMPDU`); RX_START/STOP program nothing
(`rtl8xxxu_ampdu_action`). Unicast QoS DATA from the peer on a session TID
is reordered (`narf_wireless::reorder`, 100 ms hole timeout) before CCMP/PN;
an A-MPDU member outside a session is dropped. Recipient inactivity sends
the QSTA_TIMEOUT DELBA; originator DELBA purges. Originator: the first
classified QoS DATA on an idle TID (`rtl8xxxu_tx`,
`ieee80211_start_tx_ba_session`, HT_AGG retry policy) starts TX_START:
`Radio::configure_ampdu(peer factor, peer density)` (`REG_AGGLEN_LMT`
0x458..0x45b clamped from `{0x41,0xa8,0x72,0xb9}`, `REG_AMPDU_MIN_SPACE`
0x45c low bits, exact readback), then the ADDBA Request (window 64,
timeout 0, SSN = next TID sequence). A matching successful response sets
`tid_tx_operational`; txdesc40 then carries AGG_ENABLE (else AGG_BREAK)
with the peer density and RTS/HW RTS (`rtl8xxxu_fill_txdesc_v2`). Response
timeout or session timeout stop locally with an initiator DELBA; peer DELBA
or a declined response stop without one; every TX_STOP resets both limits
to 0 (Linux). BA action frames are plaintext peer-bound management on the
MGNT pipe, SN from the shared non-QoS space, sent only with no TX/EAPOL
receipt outstanding. An associated-scan `rejoin` restores HT admission and
BA facts after the cold restart and reprograms TX_START limits for a
started originator session. Disconnect/failure retires all sessions.

Deviations: HT40 is grant-gated, not absent: against a 40 MHz BSS the
station mints a wide grant from the same signed record and domain
(`Authority::grant_wide`, HT40-above/below rows + 40 MHz regulatory
span), offers HT40 with SGI_40 and MCS32 (`rx_mask[4]`, RX-only — the
station never transmits the duplicate mode), programs the wide channel
with `Radio::widen` on a Forty negotiation, and admits 40 MHz RX (DATA,
standalone A-MSDU) only while widened. A missing wide grant at connect
falls back to a 20 MHz offer; a Forty geometry without a matching wide
grant, or a widen failure, fails the association rather than silently
falling back. A Forty rejoin re-programs the retained wide grant. A
1T2R RTL8191EU advertises one RX stream (Linux
`rf_paths = 2`); active-scan Probe Requests carry no HT Capabilities; no
BlockAckReq (RX filter passes none, as RTL8188EU). A distinct MCS32
rxdesc rate byte, if silicon reports one, is unobserved and remains a
follow-up rate case, not a silent drop; DSSS/CCK40 is not advertised.
Regressions (written, unexecuted): `smoke_rtl8xxxu_gen2_ht20_rx_admission`,
`smoke_rtl8xxxu_gen2_ht40_rx_admission`,
`smoke_rtl8xxxu_gen2_ht_local_capability` (`gen2_radio_tests.rs`),
`smoke_rtl8xxxu_gen2_ht40_negotiation_and_secondary`
(`management_tests.rs`),
`smoke_rtl8xxxu_gen2_ht_peer_ra_bandwidth40`
(`gen2_station_tests.rs`),
`smoke_rtl8xxxu_gen2_ba_recipient`, `smoke_rtl8xxxu_gen2_ba_originator`
(`ba_sessions_tests.rs`).

#### Gen2 administrative park/wake (IFF_UP/IFF_DOWN)

As the RTL8188EU `interface_power`, in `gen2_interface_power.rs`. `attach`
physically parks the radio before publication (register_netdevice starts
IFF_DOWN): `Radio::park_idle` starts a never-started `RadioReady` radio so
its receive claim and the Linux stop sequence retire (`rtl8xxxu_start`,
then `rtl8xxxu_stop`: TXPAUSE, RX filter maps cleared, host transfers
retired, `disable_rf`), then `rtl8192eu_power_off`/`rtl8723bu_power_off`.
The registered netdev is bound with `set_open_stop_target`
(`OpenStopTarget`); each RTM_SETLINK transition closes admission at once
(control operations `HardwareError`/`Busy`, worker step and drain idle, RX
ring withdrawn, carrier metadata withdrawn) and a scheduler-owned task
applies the latest request under the owner lock: DOWN is station
`disconnect` (`ra_disconnect_8192e` + `rtl8xxxu_stop`), BA/candidate state
retired, `park_idle`; every real UP first parks (a coalesced DOWN/UP still
retires the old association) and then `restart_parked` (fresh
`rtl8xxxu_init_device` with the gen2 identity check) back to the idle
`RadioReady` radio, with a fresh RX Narf-Ring generation; scans and joins
then start it as before (mac80211 `drv_start`). Registration loss during a
wake parks and closes the device; any failure is terminal. Carrier is
physical link metadata (`set_link_metadata_for` /
`withdraw_link_metadata_for` on the bound registration) and never changes
the operator's IFF_UP (`set_link_state` is only the initial DOWN
registration). `disassociate` while DOWN is a no-op.

Deviations / not implemented: HT40 on gen2 is grant-gated (wide grant + Forty negotiation + `widen`; no live 40 MHz scan); idle scans and channel
changes retune live (Linux `rtl8xxxu_config`), while associated-scan
away/return visits still pay the cold lifecycle (`leave` stops the radio);
the retained host TX/RX rings are not
serviced on away visits (home grace services one Ethernet frame per step);
no station power-save
nullfunc beyond the scan PM1/PM0 indications (Linux rtl8xxxu does not set
`SUPPORTS_PS`); BT-info records are processed only while a station is being
serviced; one gen2 netdev per boot. Regressions (written, unexecuted):
`gen2_radio_tests.rs` (C2H routing, RSSI match, rxdesc24 → `Mpdu`),
`gen2_station_tests.rs` (legacy RA peer and admission refusal, open DATA
header) and `gen2_interface_tests.rs` (scan request admission, candidate
cache bound/replacement) in `drivers/wireless/rtl8xxxu/gen2station`.

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
this software work. The initial profile needs physical validation. Qualified
legacy idle channel changes and passive scans pass native software gates; broader
rates and endpoint reset remain software work. Connected active scanning
passes native software gates at `aa6b98463`.
Administrative cold park/wake passes native software gates at `0eb084197`.
Idle active probe scanning passes native software gates at `0eb084197`.
Associated passive scanning/Null functions pass native software gates at `a7797583a`.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| RTL8188EU power + EP0 firmware lifecycle | Implemented; shared-path regressions |
| RTL8192EU runtime initialization | Identity/EFUSE/power/firmware/H2C and MAC/BB/RF tables + TX power implemented; post-table MAC, gen2 channel/bandwidth, IQK/LCK, TX/RX, RA, signed records and station missing |
| RTL8723BU runtime initialization | Identity/EFUSE/power/firmware/HMTFR, antenna selection, MAC/BB/RF tables + PHY LCK and TX power implemented; post-table MAC, calibration, TX/RX, RA, BT coexistence, signed records and station missing |
| RTL8821CU / RTL8822BU runtime initialization | Bound by rtw88 (see rtw88.md) |
| EFUSE identity/calibration read through retained async owner | Implemented; chip/geometry/failure coverage |
| Endpoint-descriptor selection and MAC FIFO/LLT | Implemented with retained RX filter/MAC activation |
| MAC/BB/AGC/RF table application | Implemented with source-matched tables and checked transfers |
| Checked post-table MAC, CAM-clear, LC/full IQK and factory gain indices | Implemented; composed owner/status/error/cancellation regressions |
| Initial channel/crystal and retained RX activation | Implemented channel1 owner and admitted probe/service binding |
| Signed board power artifact and checked native TX gate | Implemented software contract; real qualified per-device data must be acquired/signed/installed |
| Native USB descriptor/packet ownership | Implemented dependency; persistent receipt/stop and Linux descriptor regressions |
| Native beacon/management preparation and peer-bound transitions | Implemented basic1Mbps shared plan; qualified channels1–13 pass native software gates |
| Production scan/MLME service and policy-admitted management TX | Qualified idle passive multi-channel scan/home restoration passes native gates; idle active and associated passive/Null pass native gates; signed board/deployment admission required; connected active scans pass native software gates at `aa6b98463` |
| Software AES-CCM + strict CCMP/key/TID ownership | Implemented dependency; independent ciphertext/forgery/role/PN regressions |
| WPA2 key installation/controlled port and Ethernet transport | Implemented retained shared RSNA/software CCMP, exact native delivery, Narf-Rings and synchronous stack progress |
| Broader channel/rate profiles and coexistence | Native optional WMM DATA uses negotiated12-rate legacy TX. Qualified legacy channels1–13 and cold idle FIFO retuning pass native software gates. Separate N8HT HT20/LGI MCS0..7/whole A-MSDU/decline/capture-publication continuation passes native software gates above and stays channel1-bound. Management/basic1Mbps remains required. The separate v2 HT20/40 LGI continuation above is implemented pending native acceptance; SGI, broader bands and coexistence remain missing |
| USB transfer ownership / stale handles | EP0 + bulk claims, retained command DMA and generation rejection implemented; slot reuse stays gated |
| Non-stream bulk stop/drain | Implemented in USB; exact commands/context/event-prefix proof |
| Disconnect/peer-loss callbacks and normal bulk stop | Implemented; a completed disconnect returns to Passive (safe rejoin) |
| EP0/Halted reset, safe rejoin, FIFO retune and PM recovery | Bulk halt recovery, safe rejoin and qualified idle cold FIFO retune pass native software gates; administrative cold park/wake passes native software gates; controller-proven EP0 reset remains missing |

Chip inventory is source-specific: Linux `rtl8xxxu/8188e.c` identifies1TX/1RX;
`8192e.c` identifies actual1/2TX and2RX; `8723b.c` identifies1TX/1RX and optional
BT/S0S1. EU's separately qualified HT20/LGI continuation is software-validated above;
SGI20 and controller-proven EP0 reset remain software work; the separate v2
HT20/40 continuation above is implemented pending native acceptance.
Associated active scanning passes native software gates at `aa6b98463`. Qualified idle passive
multi-channel scanning passes native software gates; associated passive scans
and Null functions pass native software gates at `a7797583a`.
Full WMM AC/TID routing is implemented.

Power-management inventory (upstream `rtl8xxxu/core.c`): `rtl8xxxu_probe`
sets only SIGNAL_DBM, HAS_RATE_CONTROL, SUPPORT_FAST_XMIT, AMPDU_AGGREGATION
and MFP_CAPABLE (no SUPPORTS_PS/DYNAMIC_PS), `rtl8xxxu_ops` has no
`.suspend`/`.resume`/WoWLAN, and `rtl8xxxu_driver` has no
`.suspend`/`.resume`/`.reset_resume`/`.supports_autosuspend` but sets
`.disable_hub_initiated_lpm = 1`. The only power transitions are
`fops->enable_rf` in `rtl8xxxu_start`, `fops->disable_rf` in `rtl8xxxu_stop`
and `fops->power_off` at disconnect. There are no PM submodes beyond that
interface start/stop radio power path (implemented as retained administrative
cold park/wake above and accepted by the native software gates);
LPS/IPS/WoWLAN/USB autosuspend/LPM
are inapplicable to this family. 8192EU/8723BU first need their own retained power/firmware/radio/
packet/station compositions, including2-chain or coexistence dependencies.
The repository's matched8821CU/8822BU profiles need the actual upstream
`rtw88/rtw8821cu.c`/`rtw8822bu.c` USB transport and C21/C22B radio semantics;
EU descriptor/register helpers cannot establish those VHT runtimes. The
rtw88 USB host interface carries both: RTL8821CU (rtw88.md "RTL8821CU USB
transport") and RTL8822BU (rtw88.md "RTL8822BU: the B22 die over the USB
transport", `rtw_8822bu_id_table`, 0bda:b82c no longer in
`RTL8XXXU_USB_IDS`) run their retained rtw88 stages there. No
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
