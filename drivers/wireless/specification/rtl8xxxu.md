# rtl8xxxu — Specification

> Status: runtime RTL8188EU factory/FIFO/firmware/MAC/BB/RF + LC/IQK implemented;
> retained channel1 Open/WPA2 station service implemented; broader software
> profiles, reset/rejoin and physical acceptance remain incomplete.

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
For RTL8188EU it spawns `initialize_registered()` after releasing the device
registry lock. That production path now continues through factory identity,
FIFO/queue boundaries, firmware, MAC/BB/AGC/RF tables and checked post-table
MAC/LC/IQK initialization. Duplicate
registration compares the retained Arc identity, instead of conflating equal slot numbers on different USB controllers.

`Owner::status()` reports detected, validated, factory-ready, powered,
downloading, firmware-ready, initializing-tables, tables-ready, calibrating,
radio-ready or terminal failed state. Radio-ready means checked initialization
with MAC TX/RX still closed before the separately admitted station service. `Owner::calibration()` exposes the selected full
TX/RX IQ coefficients only after successful completion. `Owner::factory()` returns the checked RTL8188EU factory identity
and calibration snapshot. `initialize_device(blob)` runs the production
factory/FIFO/firmware/table/calibration sequence for authenticated-byte owners/tests.
The firmware-only `initialize(blob)` remains a diagnostic entry point.
A second attempt returns `AlreadyStarted` without I/O. Dropping an
active attempt records `Cancelled`; it cannot silently replay. Deadline,
transport errors (including ambiguous xHCI errors) and cancellation poison the
one-shot owner: no cleanup read/write, retry, or other EP0 operation follows.
Recovery requires controller-proven endpoint stop/drain and a fresh USB device
lifecycle; a new software owner alone is insufficient.

Image validation requires the complete 32-byte little-endian RTL8188E header,
signature family `0x88e0`, nonempty exact `ramcodesize` and at most eight 4 KiB
pages. Validation/unsupported-family failures occur before USB. Registry bytes
are validated and copied into owned storage before awaiting USB transfers.

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
preserving the exact RTL8188EU legacy/20-MHz, rate, and no-hardware-decryption
checks. `Role::Pairwise` admits KeyID0; `Role::Group` admits IDs0–3 but is
receive-only. TX requires ToDS, peer RA/local TA; RX requires FromDS, peer TA,
a unicast source and local RA for PTK or multicast RA for GTK. Only Data/QoS
Data with exact native header extents is admitted; fragments/A-MSDU fail.
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
with channel1/20MHz/basic1Mbps, Open or WPA2-PSK/CCMP and PMF disabled. HT,
VHT, HE, EHT, external EAPOL, packet offloads, live retune and power overrides
are not advertised. Passive scans poll the same persistent native RX owner,
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

`packet_codec::{receive,transmit}` and `packet_transport::Owner<UsbIo>` are
the native USB transport dependency. RX uses the physically 24-byte
`rxdesc16`, complete PHY/shift extents, packet count and 128-byte aggregate
alignment. Reports remain separate raw post-descriptor records; CRC/ICV-bad
MPDUs are dropped. No translated-Ethernet fallback exists. TX uses the Linux
32-byte descriptor, native DA multicast bit, software sequence, XOR checksum
and a fixed legacy 1Mbps rate. The admitted station profile requires a
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
| Broader channel/rate profiles and coexistence | Missing; initial profile is channel1/basic1Mbps only |
| USB transfer ownership / stale handles | EP0 + bulk claims, retained command DMA and generation rejection implemented; slot reuse stays gated |
| Non-stream bulk stop/drain | Implemented in USB; exact commands/context/event-prefix proof |
| Disconnect/peer-loss callbacks and normal bulk stop | Implemented; one association per firmware claim |
| EP0/Halted reset, safe rejoin, FIFO retune and PM recovery | Missing; software prerequisites |

Linux references: `rtl8xxxu/8188e.c` power/reset, IQK and fops;
`rtl8xxxu/core.c` firmware, post-table init, HSSI, LC and IQ matrix functions;
`rtl8xxxu/8188f.c` factory gain-index programming; `net/mac80211/wpa.c` CCMP
AAD/header/nonce layout. AES-CCM formatting follows RFC 3610.
