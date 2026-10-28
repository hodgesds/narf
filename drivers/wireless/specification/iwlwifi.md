# iwlwifi — Specification

> Status: **v0.5** (AX210+ transport and Sc MLD station profile;
> target hardware validation pending).
>
> GPL-2.0-or-later driver for Intel PCIe wireless host controllers
> (AX200 / AX201 / AX210 / AX211 / AX411, Bz/BE200 and Sc/BE211).
> Adapted directly from Linux `drivers/net/wireless/intel/iwlwifi/`
> source.

## 1. Purpose & scope

**Owns:** Bring-up and operational control of Intel AX2xx/BE2xx-class
radios. Implements `narf_net::Interface` and
`narf_wireless::WirelessNetIface`.

The current Gen3 runtime includes AX210/Bz/Sc transport initialization and
an MLD station profile. Exact CC/Qu/QuZ API77 Gen2 bindings now continue
through native deferred provisioning and an Open/WPA2 station netdev, with
legacy20 or separately qualified WMM/HT20/SISO profiles in §§3.18–3.19.
Software tests do not establish hardware acceptance for either path.

**Does NOT own (any stage):** mac80211-equivalent stack,
802.11 frame parsing/building (lives in `narf_net`), regulatory
domain handling.

## 2. Hardware Interface

### 2.1 CSR (Control / Status Registers)
Directly mapped at the base of BAR0. Used for device reset,
interrupt masking, and gating firmware loading.

### 2.2 PRPH (Peripheral Window)
Indirect access via `HBUS_TARG_PRPH_WADDR` / `_RDAT` / `_WDAT`.
Reaches the internal peripheral register file.

### 2.3 DMA Rings
- **RX**: Single descriptor ring (RXB) mapped in coherent host
  RAM. Drain is managed by the `iwl_rx_pump` task.
- **TX**: Multiple scheduler rings. Queue 0 used for management
  commands and background `iwl_tx_pump`.

### 2.4 Host Commands (HCMD)
Communication with the firmware uses a Group-Command-Version
addressing scheme. Commands (e.g., `SCAN_REQ_UMAC`) are enqueued
as TFDs with a specific command header.

### 2.5 ALIVE Handshake
After making boot DMA visible and enabling DMA/interrupts, the runtime
publishes the context and IML addresses and sets `CSR_AUTO_FUNC_BOOT_ENA`.
It must then release the embedded CPU: AX210 writes `UREG_CPU_INIT_RUN=1`
through the 32-bit UMAC peripheral window at `0xd05c44`; Bz/Sc writes
`CSR_FUNC_SCRATCH=0x01010101` before setting `CSR_GP_CNTRL.ROM_START` (bit
7). Both control-register updates preserve existing ownership, clock and
access bits. Automatic function boot alone does not release the CPU.
The same sequence applies after a transport restart.

The driver waits asynchronously for the DMA-delivered `ALIVE` notification
(status `0xCAFE`) with a bounded timeout. Exact register order, address
width and preservation of existing control bits have software regressions;
successful ALIVE and subsequent radio operation still require silicon
validation. Reference: Linux
`pcie/gen1_2/trans-gen2.c::iwl_trans_pcie_gen2_start_fw` and
`pcie/ctxt-info-v2.c::iwl_pcie_ctxt_info_v2_kick`.

### 2.6 Post-init runtime configuration

After `INIT_COMPLETE` and NVM/antenna discovery, the live station runtime
sends Linux's BT coexistence defaults (`BT_CONFIG` v6: network coexistence,
MPLUT and high-band retention), the PCI-profile-specific
`SOC_CONFIGURATION` v2, and `POWER_TABLE` v7 with continuously awake mode.
Sc uses integrated-device flags, low-latency XTAL, a 12,000 µs stabilization
latency and 2,500 µs LTR delay; the discrete BE200 configuration keeps the
discrete flag and has no integrated LTR delay. Unknown PCI profiles or
command versions fail initialization instead of choosing defaults from the
RX descriptor format. Recovery replays these commands before recreating
the station interface. RX queue zero is configured by the boot context;
additional RX queues and RSS remain disabled for this single-queue profile.

The supported software profile is a single station with Open/WPA2-PSK or
WPA3-SAE security, 2.4/5 GHz, and legacy/HT/VHT operation up to 80 MHz.
Gen2's separate §§3.17–3.19 profiles implement legacy20 and WMM/HT20/SISO
Open/WPA2 station operation with distinct emitting-program qualifications.
AP mode and 6 GHz/HE/EHT still require separate software implementations;
non-WoWLAN system suspend/resume is §3.29. They are not hardware-only
acceptance gates and are not enabled by this profile's station tests.

## 3. Public interface and stage progression

- **Stage 1**: PCI match table.
- **Stage 2**: CSR/PRPH mapping + APM init + ucode header parsing.
- **Stage 3**: Owned Gen3 firmware loading and DMA ALIVE handshake. Gen2
  context-v1/RFH/TFH and retained API77 MVM boot ownership are implemented;
  MVM station context/security/netdev ownership is integrated; firmware recovery and
  system suspend/resume are §3.29.
- **Stage 4**: Interface traits, IPC ring integration, background
  RX/TX pumps, and the MLD station scan/association/data implementation.
- **Stage 5 (In progress)**: First hardware boot/ALIVE, firmware init,
  scan, station association and IP-traffic acceptance. Software tests
  exercise these contracts without emulating the Intel radio.

### Native deferred firmware admission

`probe` retains the exact accepted BDF/device/current PCI cap before initial
parking and schedules the same startup owner; it does not resolve firmware during
Stage::Device. Executor-time resolution follows the normal Stage::Late firmware
scan. Retry remains closed in Parking until the initial command-register
readback succeeds; a concurrent caller cannot race that transition. `provision_state()` reports Parking/Parked/Starting/Ready/Failed, and
`provision().await` requires `trusted_net_authority` and retries newly staged inputs only while Parked.
The probe runner drives background provisioning via `drive_scheduled` across 120 attempts with 500 ms intervals.
Missing authority, missing images or invalid source/container inputs leave the same binding parked;
cancellation while waiting for its async mutex cannot consume an attempt. Initial
parking failure, or failure/cancellation after the first firmware/runtime startup
attempt, remains terminal without reconstructing a native owner.

Before Sc asset lookup, the same retained owner maps BAR0 once with bus mastering
still disabled and reads actual `CSR_HW_REV` and `CSR_HW_RF_ID` inside current PCI
capability invocations. This bounded identity discovery grants no firmware, DMA,
interrupt or station admission. Missing assets retain that same mapping and Parked
owner. The native Sc ladder contains only the discovered MAC/RF/step pairing:
Sc A0 with WH-b0, FM-b0, FM-c0 or GF-a0. GF firmware uses the source's fixed A
suffix; unsupported MAC steps, RF pairings and CDB/GF4 variants fail closed. A
different installed RF image can never satisfy an absent matching image. These
names do not widen the exact firmware-command gates or the WH c103 composition
evidence below. Gen2 independently selects its exact discovered §3.17 profile.

Within that exact pairing, highest-present-image semantics remain exact:
absent APIs may fall through, while a present invalid image fails. Registry
lookup and bounded firmware/sibling-PNVM byte copies occur inside current registry
and blob `Cap::invoke` operations. All TLV parsing uses owned copied bytes; no
borrowed registry view escapes invocation. Source epochs are checked again before
starting the actual native `Hardware`/`Device` lifecycle. The selected raw Sc
identity is checked again before that transition and retained by `Hardware`;
initial start and restart recheck it before enabling bus mastering or publishing
boot DMA. A changed identity cannot reuse the previously selected image.
Optional external PNVM
retains its existing firmware/SKU requirement; unsupported command/profile gates
remain unchanged. The native Gen2 interface composes the retained boot, scan,
peer, qualified-power and station owners separately as specified in §3.17.

The retained startup stores the exact initialized `Arc<Device>` before pump/netdev
publication, and the wireless registry receives that same Arc. Missing host policy
retains the previous receive/firmware behavior; active scan and association still
bootstrap authenticated policy and fail closed. Real signed registry fixtures cover
assets staged after the first attempt, a cancelled pre-attempt waiter, exact
firmware/PNVM copies, present-invalid ladder refusal, and actual PCI/source epoch
revocation before deliberately invalid ECAM or native startup publication. Native
backed-MMIO/real-registry regressions additionally cover several RF images present,
missing exact-image staging, exact sibling PNVM selection, MAC/RF/step/CDB refusal,
identity changes and revoked current PCI authority. Inert image headers remain in
a test-only registry namespace and never shadow production firmware. The
minimal test TLV contains no executable firmware and never crosses a valid native
PCI boundary.

### 3.0 Sc station composition evidence

The retained Sc c103 profile now composes the real post-INIT `Device` owner,
NVM/runtime configuration, passive scan, `Connection` authentication and
association, Open/WPA2-PSK controlled port, pairwise/group-key receipts, IPC,
native TFH TX/RFH RX, the kernel DHCP client and exact Ethernet/IPv4 traffic in
both directions against a legacy 2.4-GHz AP. The independent firmware-side
fixture reacts only after descriptor and doorbell publication, validates packed
TFH extents and command versions from the pinned Sc WH c103 metadata, and
returns correlated receipts
through actual posted RFH buffers. The shared AP validates M2/M4 MICs and replay
counters; its DHCP server validates DISCOVER/REQUEST and all lease terms.
Observations read the actual retained DMA body and published descriptor slot,
check addresses against the owning allocation, and derive the observed byte
extent from the DMA descriptor. Encoder source buffers cannot substitute for
these reads. A separate regression rejects unwritten slots and mismatched
device addresses and proves that snapshots reflect the actual DMA contents.
Firmware CCMP encryption/decryption is modelled, with native protection flags,
installed-key identity and host RX packet-number checks retained.

The EAPOL envelope accepts protocol versions 1–3, including IEEE 802.1X-2010
version 3 emitted by the shared AP. This outer byte is distinct from the exact
negotiated AKM's EAPOL-Key descriptor version. Replies retain the received
protocol version; MIC verification authenticates it. Independent vectors reject
unknown envelope versions, wrong descriptors and protocol-byte MIC tampering,
and prove that valid M3 retries do not reinstall keys.

The owner publishes physical carrier separately from administrative link state:
carrier remains down until association and, for WPA2, the terminal M4 TX receipt.
Disconnect and failure close it before teardown. Public association and active
scan retry the shared signed regulatory bootstrap, so policy staged after an
early probe failure is usable without another driver's initialization. A
private explicit model policy enters the same complete association owner; tests
never install a permissive global policy or bypass firmware MCC intersection.

Composition regressions withhold the M4 receipt and cancel its waiter, proving
closed IP admission and retained queue/TX DMA. A cancelled queue-removal wait
retains command and queue ownership; a mismatched correlated receipt fails the
transport without releasing them. Successful disconnect requires all native
queue/peer/link/PHY receipts and leaves no station queues or pending commands.

This fixture starts after firmware-ready and installs the ordinary `send_frame`
and common `Device.step` network seams without spawning a permanent worker.
It does not substitute for the separately tested one-shot capability publication,
native firmware/bootstrap/restart or interrupt ownership contracts. Physical
acceptance still requires Sc firmware/PNVM/NVM/platform power and regulatory
acceptance, boot/ALIVE and MSI/RFH/TFH operation, scan and Open/WPA2 association,
real CCMP, DHCP/bidirectional IP, and disconnect/failure/recovery on hardware.
These tests do not admit Ty/So/Bz firmware tables rejected by the exact MLD
station-version gate. Gen2/MVM native publication is specified separately in §3.17.

### 3.1 Native PCI and current authority

Probe reserves one PCI function, leaves repeated owned-BDF dispatch untouched,
and parks additional candidates. It clears inherited bus mastering and memory
decode and verifies INTx disabled before BAR sizing, maps BAR0 with Device
attributes, then verifies decode enabled with bus mastering still off. Unsupported
Gen2 identities outside the exact CC/Qu/QuZ API77 profiles remain parked.
The old FH diagnostic object never publishes a synthetic station identity;
accepted Gen2 devices use the retained native context-v1 path in §3.17.

Every native CSR/PRPH-window dword read/write executes inside `Cap::invoke` and
checks the complete aligned BAR extent. Revoked/invalid reads return the gone
sentinel and writes do nothing. RX publication/draining, host commands and data
submissions check current authority before mutating device-visible ownership.
PCI bus-master transitions require command readback. MSI-X mapping, configuration
and enable/disable also execute inside invocation; if revocation prevents proving
interrupt delivery disabled, teardown retains the vector reservation. These checks
prove current-operation admission, not atomic exclusion of concurrent revocation.

The diagnostic `PollingAliveSink::new(region,cap)` uses bounded scheduler polling,
rejects gone/revoked reads and requires its observed status; an interrupt bit alone
cannot manufacture a successful ALIVE. The live Gen3 path still requires the exact
DMA notification and supported command versions described above. Real object-table
revocation fixtures exercise native dword bounds and actual RX/command/data queues.

### 3.2 Shared synchronous/asynchronous runtime progress

Ordinary TX has one retained packet and a two-second credit deadline per access
category, with the four IPC consumers owned by device state. The common bounded
step drains RFH completions first and attempts at most one packet per category.
Lack of credit keeps the original packet and sequence number; no async task holds
the state mutex while waiting for ordinary TX credits. Closed carrier, disconnect
and recovery clear pending and queued packets before later station admission.

EAPOL/key replacement and receive-aggregation commands retain a complete,
driver-owned future. Both executor polls and synchronous network drains poll the
same future before attempting device-state access. A dropped external waiter
does not drop firmware/DMA/key ownership, and unrelated control operations return
Busy while another caller owns state. Key work remains exclusive until terminal
completion; errors fail the transport and close carrier. Existing TX drain,
key-install completion, RX discard and replay-reset ordering is preserved.

Each hardware Activity wait yields at least once, including when its IRQ/timer
is already ready, so one retained-future poll cannot loop indefinitely through a
continuous IRQ stream. The pump re-enters common progress on IPC/control wakes.
Roam closes packet admission before replacing the previous peer/queue/key owner;
a failed old disconnect prevents a new association until transport recovery.

Disconnect publishes down before waiting for control work and repeats the close
after acquiring device state, serializing with association/roam up publication.
The Sc composition fixture holds control/state to interleave that early close
with the old authorized publisher, then drives actual teardown receipts and
checks cached BSSID/carrier closure before another progress poll can repair it.
Disconnect waits for an in-flight association's state owner rather than
returning Busy: socket-owner release invokes teardown once outside the normal
netlink operation reservation. The actual `NETLINK_URELEASE` regression closes
a unique registered fixture socket while native M4 is unacknowledged, confirms
the spawned autodisconnect worker stays retained, releases that exact DMA
receipt and requires complete peer/queue teardown with IP admission closed.
The test stages only private cfg80211 owner metadata; regulatory admission,
RSNA, native queues and teardown execute through the existing real owners.

Tests cover retained waiter cancellation, bounded pending-packet retries, and
actual Device.step over RFH/DataQueue completions: a full TX queue still delivers
RX, validated credit resumes the exact pending packet, disconnect clears queued
data, and an independent WPA2 M1 advances through a retained EAPOL TX receipt
using synchronous drains after its async waiter is dropped. These are software
ownership regressions and do not emulate radio or establish silicon acceptance.

### 3.3 One-shot interface publication

Publication claims the device once before changing IPC endpoints. Missing or
revoked network authority, an occupied interface name or capability-registry
failure rejects startup while every new channel remains private. Successful
capability registration is required before ACTIVE, the kernel netdev and workers
appear. No later fallible step releases that published ownership. Repeated calls
fail before replacing the live RX/TX endpoints; a failed attempt requires a fresh
device owner. Real-cap revocation/missing-authority, duplicate-call and
post-staging registry-failure fixtures exercise the actual publication entry
without publishing an interface or worker.

### 3.4 Retained 22000 / API77 MVM boot

A separate Gen2 owner implements the context-v1 transport for exact AX200
2723 and AX201 02f0/43f0/a0f0 MAC/RF profiles. It selects Linux's CC/Qu/QuZ
firmware prefix from discovered identity and requires API77 and the negotiated
ALIVE6/NVM4 command profile. The retained legacy station continuations in
§3.11–3.16 now cover qualified active-link, MLME, rates, native WPA2 keys and
encrypted packets. The native §3.17 interface now composes PCI publication,
workers, beacon-loss monitoring and local receipt-fenced retirement. Over-air
deauthentication and recovery remain separate software work. The passive-scan owner
creates its own idle MAC context but does not authorize station data.

The transport retains its 1792-byte context, all LMAC/UMAC/paging sections,
command ring and Qu RFH allocations. Context-v1 uses 8-byte page-address/tag
free entries and 4-byte low12-ID completions. TX uses the 20-byte v9 command
and DWORD byte counts; RX MPDUs use the separate 48-byte v1 envelope.
Mappings are checked for alignment, tag bounds and 4GiB self-load boundaries.
It does not borrow the Gen3 IML/scratch bootstrap.

Gen2 native preparation has a one-shot phase before the first register
operation. BME stays verified off through ownership/reset, protected
persistence handling, integrated forced-gating or discrete AX200 BISR,
L0s/clock workarounds, firmware PHY configuration and shadow registers.
Actual interleaved PRPH apertures and 20-bit/width-encoded addressing are
used throughout. Retained context publication precedes ROM LTR programming
and CPU release. ALIVE6's packed extent is checked, then unified NVM init
requires INIT_EXTENDED_CFG(NVM), NVM_ACCESS_COMPLETE and INIT_COMPLETE.
Nonzero SKU does not select the Gen3 external PNVM sequence.

`mvm_boot::Owner` retains the exact transport and firmware sections through
NVM/antenna discovery, BT coexistence, exact PCI SoC latency, continuously
awake device power. Scan configuration is deferred until the scan owner has
confirmed DQA and current LAR prerequisites. Missing command versions/capabilities
fail before boot publication. It exposes identity only after all correlated
firmware receipts. Failed or dropped initialization cannot reset/retry that
owner; transport stop/fence/quarantine rules govern later destruction.
Configured boot is distinct from an authorized station or a usable netdev.

Kernel fixtures drive the actual owned RFH/TFH paths through ALIVE/NVM and
post-init command receipts, cancellation and duplicate-retry rejection.
Independent literal register/descriptor fixtures check context queue units,
PRPH apertures, TXv9/byte-count and RX48 geometry. These are software ownership
checks, with physical radio validation still pending.

### 3.5 Secure association and rekey entropy

Protected association obtains its SNonce from the fallible guarded hardware
entropy API before station firmware mutation; Open association needs no sample.
SAE uses the shared fallible Commit API and propagates unavailable entropy.
Pairwise rekey samples a fresh SNonce before replacing its pending candidate,
active PTK or replay state. Repeated M1 uses the retained response without
resampling. Partial failing samples remain private and are zeroized. Independent
key/replay fixtures cover failure, retry and cached retransmission; no timing
seed is admitted for production nonces.

### 3.6 Retained MVM passive-scan lifecycle

The configured MVM boot owner scans through the same retained RFH/TFH resources.
Its profile is selected from actual API77 AX200/AX201 firmware metadata: MLD MAC
configuration, reduced SCAN_CFG5 and scan15. DQA enable is conditional on the
firmware capability; the installed CC/Qu/QuZ images do not advertise it. The
legacy MAC_CONTEXT command is not substituted for the advertised MLD MAC API.

Before first scan, correlated receipts establish the idle MLD BSS-STA with the
52-byte MAC_CONFIG payload, disabled beacon filtering, SF_INIT_OFF when not
offloaded, a real 208-byte inactive LINK_CONFIG with PHY_INVALID and continuously
awake MAC power. MAC0 and link0 therefore exist before scan uses reference0.
No active PHY binding, peer, key or ordinary TX queue is implied. Missing or
unsupported command/profile envelopes fail before preparation publication.

When both EXT-NVM and firmware enable LAR, each scan first queries the current
NVM/default regdomain using `ZZ` and the supported current-source selector. MCC
v3/v4/v8 extent, status and count are checked. Current MCC is queried again on
later scans; an earlier successful scan grants no lasting channel permission.
MCC receipts precede SCAN_CFG and MAC/link preparation. The query chooses no
country and grants no host transmit authority.

Each scan also snapshots the existing trusted regulatory registry, whose native
binding installs a signed deployment policy. Missing policy, unsupported NVM
channels or absent complete 20MHz rule coverage fail before preparation I/O.
Host policy and current firmware LAR both apply. DFS remains strictly passive;
no probe template, host TX power or platform power/SAR policy is synthesized.

SCAN_REQ14..16 encode the band in the channel record's band byte; versions17+
move it to flags and use that byte for PSD. The actual API77 scan15 path uses
the former layout. Every request uses firmware slot0 with FORCE_PASSIVE. Both
the command receipt and exact UID0 successful terminal notification are required
before reopening the slot or replacing cached BSS records. Cancellation,
timeout, malformed terminal or preparation error keeps the owner closed.

RX48 frames require checked CRC/security/fragment/header extents, native
TA/BSSID/RA, a requested channel and bounded singleton SSID/RSNE/channel IEs.
Original AP IE and RSNE bytes are retained unchanged. Work per poll and BSS
cache size are bounded. Actual RAM/RFH/TFH fixtures cover native prerequisite
receipts, optional DQA, current LAR denial/requery, completion before ACK,
cancellation at each published prerequisite and successful scan reuse. Local
policy fixtures use the same private admission path without global mutation.
Native Rust tests verify fixed MAC/link/SF/power/MCC and versioned-channel
wire vectors alongside receipt, policy and ownership invariants.

These passive contracts do not authorize station TX. The retained power,
active-link and bounded authentication continuations are specified in §§3.11–3.13;
association, rates, keys and controlled port are §§3.14–3.16. Native publication
composes these owners in §3.17. Qualified Block-Ack is §3.19; recovery and PM
remain separate work.

### 3.7 Retained inactive API77 PHY context

`mvm_boot::Owner::prepare_inactive_channel(channel)` prepares one 20 MHz
PHY context attached to the existing inactive MAC0/link0. Its channel must
be present in retained NVM, covered by the current authenticated host receive
policy and permitted by a newly queried firmware MCC when LAR is active.
The same optional-DQA/idle-MAC/link prerequisites used by passive scans remain
owned by this owner. No scan request is published by this operation.

CC/Qu API77 firmware omits `PHY_CONTEXT_CMD` from its version table; following
Linux this selects command v1. `ULTRA_HB_CHANNELS` selects its exact 40-byte
channel-v2 form, otherwise its channel-v1 form is 36 bytes. Antenna masks come
from NVM and the RX chain count follows those masks. The existing Gen3 32-byte
PHY encoder is not used. Actual API77 advertises RLC_CONFIGv2, so the owner
sends its 32-byte NVM RX-chain command after PHY ADD and before inactive
LINK_CONFIG binding. Absent/older RLC stays in the PHY command; v3+ delegates
RLC to firmware, as Linux specifies. Every required command must receive its
correlated native acknowledgement before
`Phase::ChannelPrepared` is observable.

`release_inactive_channel()` receives an explicit inactive unbind receipt
before sending PHY REMOVE. Only the final correlated receipt reopens scan or
channel preparation. Failure and cancellation at every publication boundary
keep the phase closed and preserve the retained transport/DMA policy. These
helpers never activate the link, allocate a station packet queue, install a
peer/key or authorize transmit. Qualified station continuation is separate in
§3.11–3.17; BA and recovery remain subsequent work.
Fixed source-cited Rust wire fixtures cover complete PHY
and link/RLC payloads, both channel formats, both bands and each antenna mask.

### 3.8 Retained TX-disabled API77 AP peer

`mvm_boot::Owner::prepare_ap_peer(bssid)` reserves the sole AP peer only after
`ChannelPrepared`. The BSSID must be a distinct unicast identity from the retained
scan cache, with ESS capability and the same channel as the still-owned inactive
PHY. Retained NVM antenna/channel identity and a fresh authenticated host receive
policy are mandatory. When firmware/NVM enable LAR, the owner re-queries MCC and
checks its current receive permission before peer publication; it does not
recreate or activate the already-bound MAC/link.

The captured CC API77 table advertises legacy long-group `ADD_STA` command12 /
response2 and `REMOVE_STA` command2 / response0. Both version pairs are
checked exactly before any publication. It does not advertise MLD `STA_CONFIG`.
Only this explicit legacy profile is admitted. As Linux `sta.c` specifies for
new-RX hardware, ADD uses the packed 48-byte `iwl_mvm_add_sta_cmd` body; version12
repurposes its MAC-context word as LMAC identity without changing that size.
The exclusive single-peer owner reserves station0/MAC0/LMAC0, sets both the
`STA_FLG_DISABLE_TX` flag and its update mask, disables all aggregation TIDs,
and leaves class-auth/association, AID, queue mask, keys, BA and UAPSD clear.
No packet queue is allocated. A precise four-byte response with low-byte
`ADD_STA_SUCCESS` is required before `PeerPrepared` or `prepared_ap_peer()`
metadata can be observed; a generic empty ACK cannot substitute for that status.

`release_ap_peer()` issues the four-byte `REMOVE_STA` body for the retained
station0 and requires its correlated native empty ACK before clearing peer
ownership. The PHY remains `ChannelPrepared`; a separate acknowledged inactive
PHY release must still unbind/remove it. Peer identity is reserved before the
first MCC/ADD wait and survives failure or cancellation. Dropped preparation
or removal stays in its in-progress phase, rejects retries, and prevents scan
or PHY release. Any malformed, foreign or failed receipt makes the owner
terminal while retaining its peer and transport/DMA teardown policy.

Fixed Rust vectors based on the documented `sta.h` contract check the complete
ADD/REMOVE layouts and the disabled-transmit flags. Native RFH/TFH fixtures
check status/command identity, fresh MCC denial, acknowledged peer reuse,
invalid profile/BSSID/NVM/policy rejection and cancellation at MCC, ADD and
REMOVE publication. An authored Rust TLV input explicitly selects the peer,
queue and power command versions for the API77 model and drives the production
version checks. It makes no claim about a particular installed firmware image.
This is a firmware table-ownership prerequisite, with the link inactive and
transmit disabled. The subsequent management-queue owner is specified in §3.9.
Later qualified power, active-link and authentication stages are specified in
§§3.11–3.13. Association, rates/keys/security and native publication are
§§3.14–3.17; BA and recovery remain separate work.

### 3.9 Retained API77 management queue

`mvm_boot::Owner::prepare_management_queue()` requires the existing acknowledged
TX-disabled station0 and inactive PHY, then reserves the sole management-queue
operation before its first await. Actual CC API77 advertises
`SCD_QUEUE_CONFIG_CMD` group5/command0x17 command3/response2. Other command or
response profiles fail before allocation/publication. Linux TVQM maps management
traffic to TID15; the existing native `Hardware`/`DataQueue` backend allocates
the 128-entry Qu TFH ring and byte-count buffer and retains both before their
addresses enter the 36-byte ADD command. Only the exact eight-byte firmware
allocation response permits `ManagementQueuePrepared` and
`prepared_management_queue()` metadata. Queue0, out-of-range IDs, failed flags,
malformed extents and duplicate active identities are rejected by that backend.

The queue has no public packet-submission surface. Its existence does not
activate the link, clear `STA_FLG_DISABLE_TX`, install power/SAR/rate/key policy
or authorize radio transmission. Passive receive policy, including NO_IR,
continues to permit the inactive PHY/disabled-peer/queue prerequisites.

`release_management_queue()` requires the same station0/TID15 binding and an
actually idle native queue, sends the complete v3 REMOVE union and waits for
the documented API-v2 eight-byte `iwl_tx_queue_cfg_rsp` before releasing queue
DMA. The response must identify that exact queue and have zero failure flags
and reserved bytes; its ADD-only initial-write-pointer field is not adopted
during retirement. An empty status-less receipt cannot prove successful
retirement and remains a terminal error. Only successful
retirement returns to `PeerPrepared`; peer removal and PHY release cannot
proceed while the queue operation or identity remains owned. Cancelled ADD or
REMOVE leaves the corresponding in-progress phase, pending command and queue
storage retained. A failed, malformed or foreign receipt makes the owner
terminal without releasing uncertain queue/payload DMA. Unexpected outstanding
packet ownership also prevents retirement rather than being silently freed.

Fixed Rust vectors record operation/command/response fields and management TID
from the documented firmware wire contract; historical source citations remain.
Native RFH/TFH tests compose acknowledged disabled-peer ADD, actual queue
allocation and source-matched DMA fields, native API-v2 response-fenced queue REMOVE and peer
REMOVE. They also cover cancellation at both queue boundaries, malformed and
foreign receipts, wrong queue/failure/reserved response fields, station/TID/idle
rejection and authored API77 payload-version selection.
These are software ownership results. Active continuation requires the
externally qualified platform power/SAR source (§3.11) and the actual later
MLME/data/key receipts (§3.12–3.16). Native Gen2 PCI publication composes those
owners in §3.17; BA and recovery remain separate gates.

### 3.10 Host NO_IR policy

Intel host transmit/association power admission rejects any intersecting NO_IR
rule, including a narrower restrictive rule overlapped by a permissive covering
rule. Active probes additionally reject intersecting DFS rules. Every occupied
20 MHz subchannel and the full HT/VHT span apply these restrictions and the
lowest intersecting power/bandwidth ceilings. The receive-only Gen2 scan/PHY/
disabled-peer prerequisites continue to admit NO_IR while preserving their
existing NVM/MCC and complete receive-bandwidth requirements. No beacon-derived
NO_IR relaxation or automatic active Gen2 station admission is implied.

Physical carrier/peer publication does not change operator `IFF_UP` and never
invokes administrative open/stop hooks while retained driver state is locked.
Explicit registration, operator up/down and autoconnect remain administrative
events. Disconnect/failure clears carrier and peer identity while preserving an
operator-UP interface; a later physical carrier sample cannot undo operator DOWN.

### 3.11 Retained API77 platform and host power preparation

`mvm_boot::Owner::transmit_power_request(&mut self)` returns a `PowerRequest`
containing the exact asset name
`iwlwifi/mvm-api77-power-v1-<12 lowercase MAC hex digits>.bin` and a 32-byte
binding digest. It requires the initialized NVM/MAC, currently authorized PCI
identity, the unchanged supported Gen2 MAC/RF profile, and exactly one complete
SMBIOS system, baseboard and BIOS identity. Identification grants no SAR or TX
authority. The binding hashes, in order: the ASCII domain
`NARF Intel MVM API77 qualified static legacy20 power v1`; actual PCI vendor,
device, subsystem vendor and subsystem ID as LE16; actual CSR_HW_REV and RF-ID
register 0x9c as LE32; the six-byte NVM MAC; TX/RX chain masks as LE32; the
selected firmware prefix bytes; SHA-256 of the retained complete firmware
image; and the platform digest. The platform digest hashes the ASCII domain
`NARF Intel MVM platform identity v1` followed by the complete fixed-size,
zero-padded SMBIOS system manufacturer/product/version/serial arrays and UUID,
baseboard manufacturer/product/version/serial arrays, and BIOS vendor/version/
release-date arrays. Missing or ambiguous records and zero/FF UUIDs fail closed.
SMBIOS is a provisioning identity, not a measured-boot or calibration witness.

`prepare_transmit_power().await` requires the acknowledged, unused management
queue and its still-inactive PHY/TX-disabled peer. It loads the exact requested
asset through the firmware registry and requires an authenticated NRFW signer.
The signed payload is exactly 64 bytes:

| Offset | Field |
| --- | --- |
| 0 | `NIPW` magic (4 bytes) |
| 4, 6 | LE16 version 1 and length 64 |
| 8 | exact request binding (32 bytes) |
| 40 | exact NVM MAC (6 bytes) |
| 46 | flags exactly 1: externally certified static worst-case qualification |
| 47 | zero reserved byte |
| 48 | two chains × five native v5 subband SAR limits, chain-major u8 in 1/8 dBm |
| 58 | signed LE16 maximum conducted power, 1/8 dBm, range −1024…1016 |
| 60 | signed LE16 maximum aggregate radiated gain above the firmware power metric, 1/8 dB, range 0…512 |
| 62 | two zero reserved bytes |

Flag 1 requires the signer to supply actual conservative SAR and radiated-gain
limits for this exact device/platform/firmware, covering all platform postures,
antenna/array behavior and autonomous response behavior permitted by this initial
legacy 20 MHz profile. No qualification or measured board values are bundled.
Absent ACPI WRDS/EWRD/WGDS/PPAG data never implies permissive power: this path
requires an independently provisioned signed static worst-case qualification.
Parsing a structurally valid record does not establish that its physical
measurements are correct; deployment must supply that evidence and trusted key.

The owner requires REDUCE_TX_POWER command5/response0 and firmware API change45,
retains the qualification's actual source capability before awaiting anything,
and refreshes firmware MCC once for this attempt when NVM/firmware LAR is active.
The retained NVM must include the channel. The current firmware permission then
requires VALID, ACTIVE and 20MHz; non-LAR NVM additionally requires IBSS because
Linux maps its absence to NO_IR. Radar channels are excluded from this initial
power stage. Current host policy must cover the complete 20 MHz span and obey
all intersecting ceilings, including restrictive partial overlaps, DFS and NO_IR.

It sends the genuine 44-byte pre-v9 v5 SET_CHAINS command with the signed SAR
table, then a distinct SET_LINK command for MAC0 with the minimum of signed
maximum conducted power and `(host dBm × 8 − certified aggregate gain)`.
The source capability and current host policy are checked before each power
publication and after the final receipt. A tighter final policy fails without
publishing completed preparation. Each command requires its correlated native
empty ACK; unexpected payloads, foreign receipts, lost authority or transport
errors close the owner. Dropping the future retains the in-progress phase,
qualification, pending command and queue DMA; a late receipt cannot reopen it.

`prepared_transmit_power()` returns `PowerStatus { channel,
conducted_eighth_dbm, qualification_digest }` after both receipts (including
while the later link is active) while
the qualification capability remains current. This is receipt metadata, not
ongoing transmit admission: MCC is a query snapshot and later host/firmware
policy changes require fresh admission before any future active operation.
`release_transmit_power()` forgets only a completed inactive preparation,
requires the later active-link owner to have completed deactivation, and
returns to the management-queue stage. It sends no permissive reset and leaves
firmware power restrictions intact; queue retirement remains fenced until this
step. Registry name replacement alone does not revoke an already retained blob.

Native Rust RFH/TFH regressions check the 44-byte packed power wire contract and
exercise signed registry inputs, CC77 negotiation,
SAR/link DMA bytes, fresh MCC, NVM/LAR flag differences, restrictive host overlap,
policy tightening, source-capability revocation, receipt correlation, cancellation
at each native wait and power-before-queue ordered retirement. Power preparation
alone does not authorize station TX. The retained active-link transition is §3.12
and the exclusive authentication TX window is §3.13. Association, rates/keys/security
and native publication are §§3.14–3.17; BA, recovery and PM remain separate work.
No physical SAR, RF compliance or hardware readiness
claim follows from these software checks.

### 3.12 Retained API77 active link and receipt-fenced deactivation

`mvm_boot::Owner::activate_link().await` continues the same acknowledged,
inactive PHY0/link0, TX-disabled station0, unused station0/TID15 management
queue and signed v5 power owner. It requires `TransmitPowerPrepared`, the exact
retained peer/channel/power binding and a still-idle native queue. It does not
create another PHY, peer or packet queue. MAC_POWER_TABLE command1/response0 is
the existing awake API77 profile; other profiles fail before publication.

LINK_CONFIG uses the pre-v2 v1 208-byte payload. The firmware table may omit the
command or report UNKNOWN; Linux `fw/img.c` then defaults its payload-layout
lookup to1. Explicit layout0/1 and UNKNOWN use the same retained prefix;
other layouts or known nonzero response layouts fail before mutation. The wire
header version is independently0, from Linux `mvm/link.c`'s `WIDE_ID(3,9)` and
`fw/api/cmdhdr.h`'s command-ID version bits. Negotiated payload versions are not
copied into that header. The internal `Hardware::command_with_header_version`
expresses truly versioned command IDs. The retained Qu transport's ordinary
`Hardware::command` now uses header0 throughout the reached boot/NVM/default,
scan/MCC/MAC/PHY, disabled-peer, queue and v5 power prerequisites as well. Their
payload versions and capability gates remain unchanged. §3.21 separately
records the reached Gen3 header audit and the source-defined RLC2 exception.
Literal native header tests cover every reached Gen2 command category and
the independently selected payload layouts on all three transport formats.

Activation derives its legacy basic rates from the original retained AP IEs.
Supported Rates is required and bounded to1…8 entries; Extended Supported Rates
is optional. Duplicate/empty rate elements, truncated IEs, missing actual basic
bits, unsupported mandatory rates, HT/VHT membership selectors and CCK-only basic
sets on5GHz fail. Basic bits are first intersected with the local/channel
supported set through the existing strict legacy rate parser. Linux
`mvm/mac-ctxt.c::iwl_mvm_ack_rates` then adds local mandatory response rates below
the lowest basic rate in each modulation class: lower CCK rates and OFDM
6/12/24Mbps. These are firmware control-response masks; they do not invent AP
advertisements or grant ordinary packet-rate adaptation. The signed NIPW
qualification must cover the complete resulting autonomous-response envelope;
a1Mbps AP basic rate cannot narrow that qualification to1Mbps hardware behavior.

Before any native wait, the owner reserves the exact link identity/rates and
enters `ActivatingLink`. It requeries current firmware MCC when LAR applies,
checks current NVM/MCC VALID/ACTIVE/20MHz and no-radar permission, and checks the
retained source capability and current host NO_IR/DFS/overlap/power policy.
The host ceiling must still cover the already acknowledged conducted power;
this operation never raises power or silently treats a lower ceiling as applied.
The actual source capability and host ceiling are checked before every poll of
each native command future, including when no firmware receipt has arrived.
Authority loss ends the waiter and retains its uncertain command and queue DMA.
MCC remains a query snapshot; no live firmware-regulatory notification contract
is claimed by this stage.

The native sequence is LINK_CONFIG MODIFY with exactly MODIFY_ACTIVE |
MODIFY_RATES_INFO, `active=1`, then the ordinary awake40-byte MAC-power update
with25-second keep-alive, matching Linux's channel-context assignment order.
It changes no QoS, HE/EHT, beacon timing, association, class/auth, key, BA or
station TX-disable state. Both commands require exact correlated empty ACKs,
followed by a final current qualification/host/firmware-permission check before
`LinkActive` is published. Malformed or foreign receipts and authority/transport
failures make the owner terminal without releasing uncertain resources.

`prepared_active_link()` returns `ActiveLinkStatus { bssid, channel,
cck_response_rates, ofdm_response_rates }` only after those receipts while the
source capability remains current. This is firmware-receipt metadata, not
carrier, association, a controlled port or continuing TX authority. There is no
general management/data submission surface and the peer remains TX-disabled
except during the explicitly retained authentication operation in §3.13. Host
policy changes after publication require fresh admission before a future active
operation; neither a cached status nor BSS entry can supply that authority.

`deactivate_link().await` reserves `DeactivatingLink` and sends the same legacy
LINK_CONFIG with only MODIFY_ACTIVE and `active=0`. It requires the exact empty
native ACK before clearing the retained active binding and returning to
`TransmitPowerPrepared`. This closing command remains available after the
qualification capability is revoked; continuing TX policy is unnecessary to
stop a completed link. Power, queue, peer and PHY retirement remain fenced until
that receipt. Dropping either activation or deactivation leaves its in-progress
phase, exact identity, qualification, queue and command DMA retained; a late ACK
cannot permit replay or reinterpret the link as inactive. A completed close may
be followed by a fresh qualified activation, which requeries MCC again.

Native Rust TFH/RFH smokes compose the real disabled-peer/queue and signed-power
commands through activation, MAC power, deactivation and ordered power/queue/
peer/PHY retirement. They check fixed wire bytes/header versions, observed
basic/mandatory rate masks, absent/UNKNOWN layout fallback, restrictive host and
fresh firmware permissions, source revocation, each cancelled native wait,
malformed/foreign receipts, final-publication tightening and closing after
revocation. These tests use explicit isolated policy/qualification fixtures;
they cannot authorize real hardware. No reset, DMA reclamation or autonomous RF
quiescence follows from host failure. The subsequent station/key/netdev
continuations are §3.13–3.17; BA and recovery/PM remain separate gates.

### 3.13 Retained API77 open-system authentication exchange

`Owner::authenticate_open().await -> Result<AuthenticationStatus, _>` requires
the acknowledged `LinkActive` owner, current signed NIPW power qualification,
the exact idle station0/TID15 native queue and the original observed AP/rates.
It returns `AuthenticationStatus { bssid, channel, status }`, preserving the
AP's real status code (including rejection). This is protocol metadata: it
does not publish association, carrier, a security state or a packet capability.

The implemented firmware profile is explicit: TX command9, long-group TX
notification6–8, RX-MPDU notification4 and TLC-update notification3. These are
Linux `mvm/ops.c`'s mutually consistent rates-v2 indicators, with pre-AX210
`iwl_tx_cmd_v9`'s20-byte parameters and48-byte single-frame TX response. Missing,
inconsistent or newer unsupported layouts fail before any peer mutation. The
rate comes from the lowest observed AP basic bitrate and one actual NVM TX
antenna; legacy rates-v2 and v3 share these modulation/index/antenna bits. No
PLCP/rates-v1 assumption or inferred adaptive-rate configuration is used.

Before its first wait, the owner reserves `Authenticating`. It requeries MCC
when applicable, rechecks current host NO_IR/DFS/overlap/power and firmware
VALID/ACTIVE/20MHz/no-radar permission, and discards pre-attempt RX. It then
sends ADD_STA v12 MODIFY with only `STA_FLG_DISABLE_TX` masked and cleared,
requiring the native four-byte ADD_STA-success receipt. All association,
class/auth, aggregation, key and other station flags remain unchanged.

Only this private producer can use the resulting TX window. It posts one
30-byte unprotected Authentication Request (open-system algorithm0,
transaction1) through the retained TFH queue, using explicit firmware command
rate and encryption-disable flags. It waits for an actual valid single-frame
TX receipt and then for a CRC/overrun-checked RX48 Authentication Response with
matching channel, local RA, AP TA/BSSID, algorithm0 and transaction2. Foreign,
fragmented, protected, unsupported +HTC/Order, A-MSDU and structurally invalid responses cannot complete
the exchange. The TX and AP-response waits are each bounded at two seconds.
Source capability and host power authority are sampled before each native
enable/TX/receive poll, and complete firmware/host predicates at each stage.

Before returning either AP success or rejection, the owner sends ADD_STA MODIFY
with TX-disable set again, requires its exact success receipt and the same idle
queue, and rechecks current authority before restoring `LinkActive`. Closing
does not require continuing TX permission; revoked authority still prevents
publication after its receipt. `deactivate_link` and all resource retirement
remain unavailable throughout the exchange.

Cancellation retains `Authenticating`, the exact peer/link/power/queue and any
pending command or packet DMA. Late receipts cannot replay, reopen, deactivate
or release that owner. A malformed receipt, failed TX, response timeout or
authority loss makes the owner terminal; this does not prove RF quiescence.
Six native Rust smokes compose the acknowledged power/link prerequisites with
real peer enable, packet DMA, native TX receipt, AP RX and re-disable. They cover
AP rejection, independent literal wire/rate expectations, each cancellation and
authority boundary, failed receipts, profile rejection and malformed/foreign
RX. The actual checked response, with firmware padding/trailer removed, remains
with the same power/link owner for §3.14; no synthetic authentication receipt
can seed an association plan. Native station composition is specified in §3.17.

### 3.14 Retained Gen2 legacy association and local close

`Owner::associate_legacy(ssid, AssociationSecurity::{Open,Wpa2Psk}).await`
requires the same current qualified `LinkActive` context, exact idle
station0/TID15 queue, original BSS and a successful retained authentication
response. The shared native `association::JoinPlan` validates the observed
SSID, offered legacy rates and Open or PSK/CCMP policy; it consumes the actual
completed authentication response before building an Association Request.
Required PMF/SAE, HT/VHT/WMM and unsupported required rate profiles cannot enter
this legacy path. No PMK, temporal key or controlled-port state is stored here.

Before the first native wait the owner consumes the prior authentication and
retains the plan in `Associating`. It refreshes MCC when applicable, rechecks
the current signed qualification/host ceiling/firmware channel permission and
discards old RX. A receipt-confirmed peer-enable permits only the private
Association Request producer. The actual TX must complete before a checked
RX48 Association Response from the same AP/local RA/channel can be accepted.
The complete response IE set, status, ESS/privacy capabilities and AID1…2007
with both high AID bits must validate. Supported rates are intersected with the
actual offer; every original/new basic rate must remain in that intersection.
The plan retains the response-bound AID/rates before further firmware waits.

The producer is first disabled again using its real four-byte ADD_STA-success
receipt. A separately qualified ADD_STA v12 MODIFY then applies the AP's AID
with TX-disable preserved. Linux's legacy MVM command does not synthesize
CLASS_AUTH/CLASS_ASSOC flags. LINK_CONFIG updates only response rates,
short-preamble/slot, ERP protection and beacon timing for the existing active
PHY, using original beacon interval/DTIM and the response-bound capabilities.
Mandatory control-response completion follows the same source rules as §3.12.
MAC_CONFIG v1/52 then sets its associated client bit/AID and group filter,
without enabling HE/EHT or a data producer. Command-ID headers remain0;
ADD_STA requires its native status and LINK/MAC require exact empty correlated
receipts. Source capability/host policy are checked at every qualified poll,
firmware/host predicates between stages and before final publication.

`AssociationStatus { bssid, channel, aid, supported_rates, basic_rates,
protected, short_preamble, short_slot, erp_protection }` is receipt metadata only
in `Associated` or `DataPrepared`; `protected` records the selected RSN suite,
not installed keys.
Neither Open nor WPA2 association opens carrier or a data controlled port.
`clear_association().await` is an acknowledged local firmware close: MAC
association off, disabled peer AID reset, original active-link rates/protection
and inactive-association timing restored. It requires no continuing TX grant,
does not claim an over-air deauthentication, and returns `LinkActive` only after
all exact receipts. Then the existing deactivation/power/queue/peer/PHY close
chain applies. Association cancellation/failure retains its plan, response
metadata and uncertain native command/packet DMA; a cancelled local close
cannot reopen or bypass that chain. No timeout or host failure proves RF
quiescence.

Seven native RFH/TFH smokes compose actual auth, Open/WPA2 Association Requests,
TX responses, AP replies, peer/AID/link/MAC updates and local close. Literal
wire expectations, required preflight proof, each wait's cancellation/current
authority, bound AID/rate/status/header failures, native control failures and
closing after qualification revocation exercise the composed owner. Association
metadata alone does not admit data. Native keys/RSNA and publication are specified
in §§3.16–3.17. BA, over-air teardown, owned recovery and PM remain separate work.

### 3.15 Retained Gen2 normal-data queue and controlled port

`Owner::prepare_legacy_data().await` continues an actual completed legacy
association. It requires the same idle station0/TID15 management owner, exact
ADD_STA-v12 and SCD_QUEUE_CONFIG-v3/API-v2-response contracts, original BSS,
signed platform-power qualification, current host policy and firmware channel
permission. It reserves `PreparingData` and its context before the first wait;
cancelled preparation cannot retry, clear association or release another owner.

The native continuation refreshes MCC when LAR requires it, then programs
LINK208 `MODIFY_QOS_PARAMS` and firmware TLC. This station has not negotiated
WMM: DCF uses CWmin31 for an11b BSS, otherwise15, CWmax1023, AIFS2 and TXOP0.
Firmware AC order is BK/BE/VI/VO with Gen2 EDCA FIFO masks2/4/8/16. The fifth
AC, HT/TGN and WMM flags stay zero. TLC payload versions2,3,4 are selected
explicitly from the command table:24 bytes belowv3 and28 bytes forv3/v4, mode
non-HT, one valid NVM antenna, no SGI/HT/A-MSDU, and only the actual association
response's common supported-rate bitmap. Unknown/missing TLC versions fail
before publication. Payload version is separate from the native command-ID
header: LINK, TLC, ADD_STA and queue commands use header0. LINK/TLC require
correlated exact empty receipts; these strict receipt profiles still require
physical firmware acceptance, not inference from the Linux asynchronous caller.

A separate station0/TID0 queue is allocated through the real retained TFH/RFH
transport. TID0 is Linux's non-QoS data TID, distinct from management TID15.
Queue ADD requires its exact eight-byte identity/status/pointer/reserved
receipt; malformed or duplicate queue IDs retain all published allocations.
Only an Open association then clears peer TX-disable with its actual four-byte
ADD_STA-success receipt. Final source/host/firmware checks and an exact idle
queue binding precede `DataPrepared`. A WPA2 association leaves peer TX disabled
and its controlled port closed. This stage accepts no PMK, authorization flag,
temporal key or synthetic key/handshake receipt.

`prepared_legacy_data()` exposes historical
`LegacyDataStatus { bssid, channel, queue, supported_rates, protected }` only
for the terminal prepared owner and a still-current qualification.
`legacy_data_port_open(&mut self)` additionally resamples the current policy
and firmware channel predicate. Observed source/policy loss closes the owner
permanently; reinstalling policy cannot reopen it. Open returns true at this
stage; a protected association additionally requires the native §3.16 owner.
`transmit_legacy_ethernet().await` binds the original local source/BSSID,
complete Ethernet-II shape and retained sequence, excludes ordinary-caller
EAPOL, refreshes MCC when required, and submits native TX-v9 with firmware TLC
rate selection. Success requires the exact queue/SSN/native TX completion and
current final power predicates. Caller shape errors are pre-I/O/retryable;
native failure, lost authority or ambiguous completion is terminal. The
`TransmittingData` phase survives future cancellation and keeps the packet,
queue and other DMA owners until real completion/transport teardown permits
reclamation. A timeout never proves device quiescence.

`poll_legacy_receive()` performs one bounded native poll/drain and returns
`Option<LegacyReceive::{Ethernet,Eapol}>`. It admits only current-channel,
AP-bound FromDS non-QoS frames with valid CRC/overrun status, supported legacy
rates-v2 modulation/rate and20MHz width. It rejects fragments, unsupported
crypto metadata, HT-control, A-MSDUs and firmware/retry duplicates.
The native descriptor's padding and CRC trailer are excluded from Ethernet.
The controlled port never forwards WPA2 plaintext IP; a current AP/local-RA
plaintext EAPOL frame is distinguished only after its outer802.1X version and
length bounds validate. Before RSNA starts this is observation metadata, not a
MIC check or caller-supplied key authority. Once the native RSNA owner starts,
EAPOL is captured privately for §3.16. Open does not forward EAPOL to IP. A
bound AP deauthentication/disassociation closes host
admission and retains native resources without claiming an over-air response.
Current policy/source checks precede receive work and every packet publication.

`release_legacy_data().await` closes host admission before its first wait,
acknowledges peer TX-disable, retires every installed native key and its RX
epoch when RSNA is present, discards transition RX and validates idle
station0/TID0 ownership before native queue REMOVE. Only its exact eight-byte
matching receipt releases that queue and returns `Associated`. It preserves
the management queue, AP, PHY, association and signed power owner. This closing
chain remains allowed after qualification/policy loss; cancellation or malformed
receipts retain the closing/failed phase and DMA. Association, PHY, power or
management retirement cannot bypass it. Existing local association close and
link/power/management/peer/PHY teardown follow afterward.

Thirteen native smokes compose actual authentication/association, EDCA/TLC,
queue ADD, Open packet TX/RX/completion and queue retirement. Literal wire
cases cover response-narrowed rates, both contention defaults and TLC2/3/4;
other cases cover each wait's cancellation/current policy/source, fresh MCC,
malformed/foreign command/packet/close receipts, DMA retention, WPA2/EAPOL port
isolation, receive geometry/padding/retry/AP-close, rejected caller packets and
terminal policy reinstallation. These software tests do not publish a Gen2
netdev or establish RF/firmware acceptance. Native PMF,
over-air teardown/recovery and runtime/system PM remain explicit subsequent
work. Native PCI/netdev and beacon-loss integration is specified in §3.17;
the separately qualified BA/reorder continuation is §3.19.

### 3.16 Retained Gen2 WPA2-PSK/CCMP native key and RX epoch owner

`Owner::secure_legacy_wpa2(pmk).await` continues a protected `DataPrepared`
legacy association with an idle normal-data binding and the original observed
PSK/CCMP RSN offer. It requires API change29 (`TKIP_MIC_KEYS`), exact
ADD_STA_KEY payloadv2/v3, RX-queue-sync commandv1 and notificationv1. Linux
`iwl_mvm_send_sta_key` defaults missing/UNKNOWN key-table entries to v2 when
API29 is present; fixed sync-v1 IDs need not be enumerated in that table.
Explicit incompatible layouts and unavailable nonce entropy fail before native publication. An
observed source/host-policy loss is terminal. There is no caller completion,
crypto-status or authorization boolean. The guarded entropy source supplies a
fresh SNonce; shared Rust `security::Session` authenticates the original EAPOL
PDU, replay, MIC, wrapped GTK KDE and original AP RSN. This path remains
legacy20, non-QoS, single station and WPA2-Personal without PMF.

The owner reserves `SecuringData` and its zeroizing PMK/session/key state before
the first native wait. It enables the peer only for its private EAPOL producer,
using the retained station0/TID15 queue, response-bound basic rate and native
TX-v9. Ordinary callers still cannot transmit EAPOL or use the closed data
port. M2 and M4 require actual positive queue/SSN TX receipts. The exact
retained authenticated reply is bound to the native frame before submission;
no key installation or port commit precedes the terminal M4 receipt. Rekey
replies are hardware-encrypted with the old installed PTK until that receipt.

Key changes acknowledge peer TX-disable, remove an occupied slot with its
native receipt, then add authenticated new material. `ADD_STA_KEY` uses bare
ID0x17/header0 and the76-byte v2/v3 structure from Linux `fw/api/sta.h` and
`mvm/sta.c::{iwl_mvm_send_sta_key,__iwl_mvm_remove_sta_key}`. Station0 owns
PTK slot0 and GTK slots1..4 (key IDs0..3). Flags retain WEP-key-map plus CCM,
key ID and multicast; REMOVE uses NOT_VALID/NO_ENC with all key/sequence
fields zero. Each receipt must be exactly four bytes with full status1.
The authenticated GTK RSC is48-bit; Linux's six most-significant-first
`ieee80211_key_seq.ccmp.pn` bytes use the v2 hole at2/3 or v3 contiguous
layout. Fresh key material starts firmware TX PN0; firmware owns IV/MIC
insertion and increments. This never resets an existing key's PN.

After key receipts, the real single RX0 queue is synchronized with
`TRIGGER_RX_QUEUES_NOTIF_CMD` group5/ID2/header0:20 bytes, flags0, mask1,
count8 and internal type0/sync1/monotonic cookie. An exact empty command
receipt and the matching12-byte group5/ID0xff notification are both required.
Malformed markers fail; foreign cookies cannot commit an epoch. Pre-marker
data is discarded before replay reset, while a bound AP disconnect remains
terminal. Only this actual RX ordering marker permits the new PTK replay
epoch or new GTK floor to commit. A final native peer-enable receipt and
current signed platform source, host policy and firmware channel checks
precede the protected data port. Linux primary references are
`mvm/mac80211.c::iwl_mvm_sync_rx_queues_internal`,
`mvm/rxmq.c::iwl_mvm_rx_queue_notif`, `mvm/sta.h` and `fw/api/rx.h`.
The exact empty command-ACK profile still needs physical API77 acceptance.

`poll_legacy_receive()` captures bounded native EAPOL privately once RSNA
starts; `service_legacy_wpa2().await` drives captured retransmissions/rekeys
with the same owner and credential. Its input is actual native receive,
not caller-provided EAPOL. Duplicate authenticated M3 replies reuse the exact
cached M4 and never re-add keys or reset replay. Pairwise rekey uses a fresh
SNonce and keeps the old native PTK until the new M4 receipt. Unchanged GTKs
retain their PN and take the maximum authenticated RSC. Old key IDs remain
owned until replacement or close. Retired-material fingerprints survive data
and association recreation. Active-exchange GTK rollback fails closed;
§3.20 adds receipt-fenced RX-only GTK restoration at the maximum saved replay
floor and §3.30 extends it to cross-peer/index GTKs and floor-safe PTK reuse. Exhausting32 retained fingerprints fails closed.

`legacy_data_port_open()` now also admits a terminal protected RSNA owner.
`transmit_legacy_ethernet()` submits protected native plaintext DMA for
firmware CCMP under the installed PTK, still requiring exact native TX
completion and current qualification. Receive requires real API4 CRC/overrun,
station0 source-found/key-valid, CCM/MIC-OK/decrypted status, original AP and
channel, the retained CCMP IV, and monotonic per-key non-QoS PN. Native
descriptor padding/trailers are excluded. Invalid metadata never advances PN;
plaintext IP, unknown group keys and replay remain denied. Ethernet is
published only after the port's final commit. Firmware crypto metadata grants
no authority without the retained native key receipts and current source.

Cancellation retains the exact phase, EAPOL reply, pending/new/old keys,
cookie, commands and queue/packet DMA; late receipts cannot reopen it. Failed
or ambiguous transactions require transport retirement/reset, not a retry.
`release_legacy_data()` closes admission before its first wait and executes
peer-disable → each installed native key REMOVE → actual RX epoch marker →
idle data-queue REMOVE. Closing is permitted after source/policy revocation;
only exact receipts retire resources. No timeout proves RF quiescence.

Fifteen new native smokes use the actual TFH/RFH publication path, an
independent authenticator with real MIC/AES key-wrap and device-key CCM
encryption/decryption. They cover both key layouts; M4/key/fence/port ordering;
encrypted bidirectional Ethernet; duplicate, group and pairwise rekeys;
nonzero RSC; every native wait's cancellation/current authority/failure;
malformed and foreign markers; RX-prefix retirement; exact full status;
native crypto/PN/group-floor denial; source-defined omitted/UNKNOWN version
fallbacks; old-material rejection; AP close during
the epoch; and key/queue closing ownership. These are software conversation
tests, not hardware acceptance. Native interface publication is §3.17.
PMF/WPA3, VHT/HE, wider channels, over-air teardown,
recovery and runtime/system PM remain separate work.
The separately qualified BA/key-epoch continuation is §3.19.

### 3.17 Native Gen2 provisioning, interface and retained worker

The common deferred PCI startup now retains Gen2 bindings as well as Gen3.
With BME verified off it maps BAR0 once and reads actual `CSR_HW_REV` and
`CSR_HW_RF_ID` under the current PCI capability. `gen2_profile::select`
chooses CC for discrete2723 or the exact Qu/QuZ MAC stepping and JF/HR RF
pairing for02f0/43f0/a0f0. It resolves one canonical
`iwlwifi/<discovered-prefix>-77.ucode`; the old static API100 diagnostic
ladder, another RF image and a PNVM sibling cannot satisfy that input.
Missing/invalid inputs preserve the same Parked binding/mapping. Discovery is
rechecked before the one-shot Starting transition. Native context-v1 boot,
ALIVE6/unified init, NVM and runtime configuration use the retained owner.
Failure/cancellation after this transition remains terminal and retains the
transport's stop/fence/quarantine policy; no second firmware owner is created.

API selection follows Linux `iwl-drv.c` and `fw/file.h`: API_NEW_VERSION bit20
selects the full header word; otherwise API is header bits8..15. The
FW_VERSION triple is display major/minor/local-component metadata and never
substitutes for this API. All three Gen2 startup gates require the resulting
API77. Gen3 command-ID/header behavior is specified separately in §3.21.

The same initialized `Arc<mvm_device::Device>` is retained before registration.
One-shot publication stages private IPC channels, validates current executable
firmware/PCI authority and the actual network Grant capability, then registers
the netdev, wireless interface and worker. Failed registration cannot publish
replacement endpoints. Carrier and controlled port start down. The public
`gen2_transmit_power_request().await -> Gen2TransmitPowerRequest` returns the
configured owner's exact MAC/PCI/MAC-RF/firmware/SMBIOS binding and expected
signed-input filename. It supplies metadata for external measurement, never
board limits or transmit permission. Missing SMBIOS facts fail closed.

The default published station profile is non-QoS legacy20 on NVM
2.4/5-GHz channels. §3.18 adds a separately qualified WMM/HT20/SISO profile;
VHT/HE/EHT, additional vdev and SAE/PMF remain unsupported.
WPA2 handshake offload is advertised only for the actual key-v2/v3 and
RX-sync-v1 contract, including its source-defined defaults. Passive scans
accept exact canonical frequencies/legacy selectors, reject contradictory
selectors and unsupported active/random/dwell/probe-IE requests, and filter
returned SSIDs. Current receive policy, including restrictive overlaps, is
resampled at native waits and result publication. NO_IR still permits passive
receive. Association conservatively bounds every original observation by the
scan's start time, no older than10 seconds, and requires exact
BSSID/SSID/channel/frequency. Completion never refreshes an early beacon's age;
a scan longer than10 seconds requires a fresh scan before association.
Owned SME elements are validated and
appended by the shared legacy plan; unsupported PHY/WMM/security promises are
rejected before native PHY/queue publication.

Association loads and decodes the exact signed static-power input before its
first PHY/queue operation. Missing/malformed input remains a retryable
Configured owner. It then composes actual inactive PHY, disabled AP peer,
management queue, v5 power/SAR, active link, authentication, response-bound
association, DCF/TLC/data queue, and Open or native WPA2 controlled-port
receipts. An input credential becomes zeroizing retained work; no caller
boolean or EAPOL bytes can open the port. Ordinary frames still cannot inject
EAPOL or request unsupported descriptor/offload shapes.

One driver-owned Work slot retains the complete control, EAPOL/rekey or data
future and its async-safe state guard. Both the executor worker and synchronous
network drain poll that same slot. Dropping an external waiter retains the
native transaction, result and DMA; a current firmware/PCI invocation surrounds
each native future poll. The operation's current channel policy and, for an
active station, actual signed-power source are checked as well. Packet waits
remain native receipt/deadline driven and do not depend on a second task.
One normal data packet is retained through exact native TX completion; native
RX and captured EAPOL/rekey work precede further ordinary TX. Wakeable
completion records return control results without handing ownership back to a
cancelled waiter.

Carrier, TX/RX IPC and the final stack callback are enclosed in current
executable-firmware, PCI and signed-power invocations with fresh host policy.
PCI publication additionally verifies MEM/BME/INTx-disable readback. Power
tokens come only from the completed native power owner. A monotonic station
generation rejects a cached token after close/rejoin or a later key-port
commit, even when the same source remains valid. Old packets are discarded
without closing a successor; RX IPC is drained on local close or rekey admission
closure. Ordinary TX does not change this generation. Stack callbacks run after
owner/ring/admission locks drop so
ARP/ND can reenter enqueue. Authority loss latches terminal closure;
reinstalling policy cannot revive it. Native/model constructors remain
distinct; only the private RAM fixture skips physical PCI reads.

Disconnect closes host admission and records cleanup intent before awaiting
the work/state locks. Existing published TX may consume its terminal native
receipt, while the transport rejects a new packet publication after that
intent. A late association result cannot reopen carrier. The worker retains
cleanup even if the disconnect waiter is dropped. Exact retirement is data
peer-disable → native keys/RX epoch/data queue → MAC/BSS state → link/MAC power
→ power-admission release → management queue → AP peer → PHY unbind/remove.
Only terminal receipts return Configured and permit another passive scan.
Uncertain/failed native phases stay quarantined instead. This is local
retirement; it sends no over-air deauthentication and claims no RF quiescence.

Native receive tracks valid bound AP beacons/data/EAPOL and closes admission
after10 seconds without such evidence. A bound native AP disconnect is also
terminal. A failed station is restarted by §3.29 recovery before the next
scan; system suspend/resume is also §3.29. There is no roam or in-place
retry of a failed/ambiguous transaction. Existing retired-key fingerprint
and32-entry-history restrictions remain. §3.20 adds the narrowly bound GTK
reconnect path without resetting its PN (§3.30 adds cross-peer/index GTK and
floor-safe PTK reuse); cross-role reuse and an ambiguous retirement are never
authorized by a cached fingerprint.

Fourteen new registered native smokes cover twelve interface conversations
and two discovered-profile/identity cases. The interface fixture begins after
ALIVE/unified init, then uses actual NVM/default commands, scan, MLME, signed
power and RFH/TFH queues; separate native boot tests cover boot ownership.
Open and WPA2 cases run the real kernel DHCP client through DORA and exact
bidirectional Ethernet/IP with the independent AP and actual installed-key CCM.
Other cases exercise held M4 waiter cancellation/sync progress, rekeys, source/
policy loss, pending cleanup, beacon loss/AP close, pre-I/O/busy/measurement
denial, actual publication Grant revocation, and retired publication generations.
An independently advanced fixture observation clock checks a15-second native
scan, exact10-second admission and one-cycle-expired denial before native PHY/queues.
The existing boot-resource test also covers literal new/legacy API selection.
These Rust tests establish software contracts, not silicon/firmware/RF
acceptance or the existence of a measured board qualification.

### 3.18 Qualified native WMM and HT20/SISO

The same retained `mvm_device` worker can select an optional BE/TID0 WMM
profile and HT20/SISO/MCS0–7 with optional SGI20. The actual native NVM4 SKU
must enable11n and usable TX/RX chains; firmware must advertise TLC_OFFLOAD43,
TLC command2/3/4, ADD_STA12/response2 and SCD_QUEUE_CONFIG3/response2, and the
same consistent TX-v9/TX-response6–8/RX4/TLC-update3 rates-v2 contract. These
facts come from the retained executable/native response. A PCI name or Gen3
encoder cannot enable this path. Missing optional PHY retains legacy admission
only when its actual rate/membership requirements permit it. HT40, NSS2,
VHT/HE and LDPC/STBC remain absent. Tag2 keeps TX aggregation disabled;
the separately qualified aggregation program is §3.19.

`JoinPlan::prepare_with_phy` consumes the exact original BSS and the local
`LocalHt::siso20(true,true)` implementation profile. It owns the HT capability
IE, strict directional AP offer/response intersection, mandatory HT selector,
basic MCS and primary/operation checks. Caller HT/WMM/operation IEs remain
rejected. The driver appends only its own WMM Info with no U-APSD. The actual
bound response must confirm WMM parameters and selected HT Capabilities plus
Operation; invalid/missing/broader facts never reach native peer/port commit.
AP RX support narrows native TX MCS/SGI, while native RX remains bounded by
the locally advertised SISO/MCS0–7/SGI20 facts. A WMM-only AP uses QoS at
legacy rates, without TGN/HT flags. BE ACM, malformed/duplicate ACI records
and TXOP*32 overflow are rejected before PHY/queue publication. The first
producer deliberately sends ordinary Ethernet only as BE/TID0; it does not
claim DSCP classification, other AC/TID queues or TSPEC admission.

The emitting measurement is separate from §3.11's static legacy20 profile.
`gen2_ht20_transmit_power_request().await` returns metadata for
`iwlwifi/mvm-api77-ht20-siso-wmm-power-v2-<MAC>.bin`; it grants no limits or RF
permission. Its SHA-256 binding uses domain
`NARF Intel MVM API77 qualified static HT20 SISO MCS0-7 SGI20 WMM-BE power v2`
plus the same actual PCI/MAC/RF, NVM antenna, firmware, MAC and unambiguous
SMBIOS facts. Signed NIPW retains the64-byte wire format/version1, but byte46
is emitting-program tag2 rather than legacy tag1. The external qualification
must cover the legacy management/EAPOL program and the entire additional
HT20/SISO/MCS0–7/SGI20/WMM-BE program over all supported bands, platform
postures and states, with measured SAR/gain/conducted ceilings. A legacy tag1
asset cannot satisfy tag2, even with the same MAC/binding supplied. Selection
of WMM (including WMM-only legacy QoS) requires tag2; an absent input leaves
the native owner Configured/retryable and does not silently emit the new
program using legacy measurements. No measured values are supplied by this code.

After actual Association Response, native ADD_STA48 receives the response AID,
20MHz/SISO and AP density/AMPDU-factor/SMPS flags under exact masks. U-APSD
ACs remain zero and every aggregation TID remains disabled. LINK_CONFIG208
programs QoS flags UPDATE_EDCA and, only for HT,TGN; AP CW/AIFS/checked
microsecond TXOP in BK/BE/VI/VO order with native FIFO masks2/4/8/16. ERP and
HT protection follow the source operation. Native TLC24/28 version2/3/4 sets
HT mode1, width20, one qualified chain, response-intersected NSS1 MCS and
version-specific SGI20; NSS2, wider rates, LDPC/STBC and TX A-MSDU stay zero.
Native peer, LINK and TLC receipts precede the data queue/controlled-port
publication. Existing command header0, qualified-power/source/current-policy
checks at each wait and cancellation/DMA retention remain required.

QoS data uses the actual station0/TID0 queue,26-byte MAC header,2-byte
transport pad and TX-v9 offload geometry. Firmware owns CCMP IV/MIC/PN and
actual TX receipts. Native RX accepts only the selected local MCS/NSS/width/GI
bound, valid normal-QoS headers/TIDs0–7, current source station/key/MIC/decrypted
metadata and unnegotiated-BA sentinel. Ordinary and EAPOL traffic retain the
same real RSNA/key-epoch owner, per-key/TID PN floors and authenticated GTK RSC.
The independent native firmware model authenticates actual26-byte CCMP AAD
and nonce priority; it cannot substitute an authorized/decrypted caller flag.

The local HT capability implies3839-byte receive A-MSDU support. The API4
receiver therefore stages firmware-deaggregated subframes, a cloned replay
state and reconstructed aggregate extent until the native last marker. It
requires initial index0, contiguous bounded indices, exact peer/TID/sequence/
key/PN identity, no HTC or negotiated BA, valid source/destination and bounded
Ethernet geometry. No packet or replay floor is published for an incomplete,
foreign, timed-out, oversized or malformed suffix. Inner EAPOL/preauth/tunnel
control and invalid EtherTypes are excluded, including through up to two VLAN
tags. Completion commits the one aggregate's replay state and then releases
the checked batch. A100ms partial deadline, key transition/RX marker, local
close and terminal failure discard private partial state. There is no claim
that arbitrary index1 suffixes can establish completeness. Native index/size/
RF acceptance remains physical testing work.

Under tag2, BA remains unnegotiated. A genuine bound ADDBA request earns a bounded actual
status37 decline on the native management queue under driver-retained Work;
late receipt/cancellation cannot open an aggregate producer. Valid Ethernet
already received behind that action is privately retained and later delivered
under fresh publication grants. Rekey flushes old private batches before the
new key epoch. A changed bound AP WMM/HT beacon profile closes admission;
there is no asynchronous EDCA/PHY reconfiguration shortcut. All final IPC/
stack publication continues to require current firmware/PCI/signed-power and
station-generation authority after owner/ring locks drop.

Seventeen new native smokes cover Open/WPA2 worker DHCP/IP, literal EDCA/peer/
TLC2/3/4, distinct qualification denial, each new native wait's failure,
cancellation and source/policy loss, directional rates/GI and TID replay,
real whole-aggregate CCM plus staged deaggregation/no-PN/prefix leakage,
malformed/control/oversize/timeout/close/key-epoch boundaries, mandatory HT
selector/caller rejection, response binding, WMM-only legacy fallback, bound
beacon changes and ADDBA decline preserving following native IP. These tests
exercise software contracts; they do not establish a measured board envelope,
real firmware/RF acceptance or throughput.

Primary layouts/selection follow Linux `iwl-nvm-utils.c::iwl_init_ht_hw_capab`,
`iwl-nvm-parse.c::iwl_get_nvm`, `mvm/{sta,rs-fw,mac-ctxt,link,tx,rxmq}.c` and
`fw/api/{nvm-reg,sta,rs,mac,mac-cfg,tx,rx}.h`. The Gen3 `ht_vht::apply_*`
payload encoders are deliberately not used for native MVM peer/TLC commands.

### 3.19 Qualified native Gen2 Block Ack and BE packet pipeline

This checkpoint adds a retained native aggregation program. Its twenty-one
native smokes passed on x86_64 and aarch64. The coordinated native WiFi suites
passed with x86_64 **2317 pass /0 fail /9 skip** and aarch64
**1847 pass /0 fail /3 skip**; these are full WiFi scope totals, not Intel-only
counts. This validates the software conversations and ownership checks, not
firmware/silicon/RF acceptance or a throughput measurement.

The optional program requires §3.18's actual HT20/TLC_OFFLOAD43 contract,
compressed BA notification4/6/7, FRAME_RELEASE1 and BAR_FRAME_RELEASE1.
BAID_ML_SUPPORT63 must be absent: the alternate RX_BAID_ALLOCATION command
profile is deliberately not admitted by this implementation. Unsupported or
absent optional tables retain unaggregated tag2 operation and actual ADDBA
declines. A source-supported profile never falls back to a different BAID ABI.

`gen2_ba_transmit_power_request().await` returns metadata only, for
`iwlwifi/mvm-api77-ht20-siso-wmm-ba-power-v3-<MAC>.bin`. NIPW remains64 bytes,
wire version1, with byte46 emitting-program tag3. Its distinct binding domain is
`NARF Intel MVM API77 qualified HT20 SISO MCS0-7 SGI20 WMM-BE TID0 TX-BA pipeline8 RX-BA32 control power v3`.
The same exact hardware/NVM/firmware/SMBIOS inputs remain bound. External
measurement must cover the entire legacy/HT20/SISO/SGI20 program plus
firmware-managed BE/TID0 aggregation/retries, at most8 outstanding normal
Ethernet packets<=1514 bytes each, and recipient immediate Block Ack/control
responses. It must cover the actual firmware's aggregate/TXOP/retry program,
not a host-invented BA window or inferred board allowance. Tag1/2 cannot enable
either new producer. Missing/mismatched tag3 fails before PHY/queue publication;
no measured values are manufactured by the implementation or fixtures.

TLC43 means Linux `TX_AMPDU_SETUP_IN_HW`: the firmware manager owns TX
ADDBA/DELBA/BAR negotiation, SSNs and retries. Host code does not send a
synthetic TX ADDBA or reset sequence to0. An actual ADD_STA48 modify with
`STA_MODIFY_TID_DISABLE_TX`, bitmap0xfffe and native status-success receipt
permits only station0/TID0 aggregation. No obsolete32-bit queue mask is used.
The existing TVQM queue36-byte request/8-byte ADD/REMOVE receipts remain the
scheduler owner. The retained netdev Work copies up to8 admitted ordinary
Ethernet packets and posts8 independently retained TX-v9 DMA buffers, then
waits for their native terminal prefix. EAPOL remains exclusively with RSNA's
management queue; pending key/control/close work stops replenishment.

Qu scheduler pointers wrap at256 (`cfg/22000.c`), independently of128 host
descriptor slots and12-bit802.11 sequence numbers. Monotonic host completion
tokens are reconstructed only inside the retained outstanding interval.
Native single48-byte TX responses retire only a checked prefix; a failed
oldest retry makes the batch terminal and leaves an unacknowledged tail pinned.
C5 header32 plus bounded TFD8-byte entries is validated before any reclaim:
station0, enabled queue/TID0, known flags/reserved fields, exact bounded union
extent and first-unacked pointer inside owned descriptors. RA/TID debug data
and global `txed/done` counts cannot create descriptor credit. Zero-TFD debug
notifications retire nothing. A partial prefix cannot complete the tail.
Manager refusal can fall back to genuine native single receipts; no model or
caller flag substitutes for them. Unknown/malformed/timeout receipts close
admission and retain uncertain DMA instead of authorizing slot reuse.

Recipient sessions cover TIDs0–7, up to32 MPDUs per TID, one RFH queue. A
bound original ADDBA request supplies dialog, immediate policy, original SSN,
window and timeout; the tag3 response clamps the window to32 and clears nested
A-MSDU support. The separate tag4 continuation is defined in §3.24. The owner
reserves before native publication. ADD_STA48 uses
only ADD_BA_TID, TID@28, SSN@30 and window@44. Its exact status dword must
report success, BAID_VALID and a unique allocated BAID<32. Explicit native
BA-resource refusal earns a real negative response; malformed/uncertain
allocation quarantines the owner. The positive Action response must itself
have a terminal native management TX receipt before RX delivery activates.
An exact repeated dialog can repeat its saved positive response without
allocating again; a changed live agreement is declined. AP-originator DELBA
retires our RX agreement; AP-recipient DELBA belongs to the TX firmware manager.

Original Qu48 native MPDUs enter a bounded opaque reorder owner before host
PN/deaggregation. It is seeded by `advance(actual_addba_ssn,now)`, never by
an invented fresh0. Current BAID/TID/AP/local/channel, original sequence vs
descriptor SN, CRC/PHY/header/key/MIC metadata and OLD_SN/nested-aggregation
restrictions precede storage. Current authority and native crypto/PN admission
are checked again when packets release. Thus SN102/PN502 before101/501 does
not consume the newer PN prematurely. Per-TID windows are independent and
handle non-power-of-two sizes and4095→0. Native C3 and C2 station/TID/BAID/NSSN
receipts advance only the matching session; raw forwarded BAR is not applied
again. A valid compressed BAR without an agreement earns actual reason38
REQUIRE_SETUP DELBA. A100ms hole bound prevents indefinite buffering; negotiated
idle timeout schedules genuine native removal and reason39 DELBA. Under tag3,
nested A-MSDU-in-A-MPDU remains unnegotiated/rejected without consuming PN. Standalone
§3.18 A-MSDU keeps its separate complete-only deaggregation owner.

Original QoS Ack Policy may be normal0, or BlockAck0x60 only for the exact
active native BAID/TID agreement. EOSP and other unsupported policies remain
rejected; tag3 also rejects nested A-MSDU. The downstream crypto/data parser checks the same original
header without rewriting it; a new native protected BlockAck-policy vector
checks both successful delivery and foreign/unallocated-policy PN isolation.

On key replacement/local close, the retained worker stops new packets, reaches
all native TX terminal receipts, disables the firmware TX aggregation permission,
removes each RX BAID with real ADD_STA REMOVE_BA_TID receipts, and issues
RX-sync-v1 carrying the actual internal DEL_BA type1, BAID and monotonic cookie.
Only its exact single-RFH marker permits discarding/reusing the host session
map. An ordinary command ACK is insufficient. Old raw reorder packets/private
deaggregation batches cannot cross the changed key/peer epoch. Fresh RX BA
requires a new genuine peer ADDBA. Cancellation retains the same Work/native
phase and DMA; revocation, malformed stop/marker or timeout does not reconstruct
an owner or reclaim hardware-visible storage. Current signed power, policy,
firmware/PCI and station-generation fences remain required at every enabling
wait and final ring/stack publication. Closing admission does not establish
firmware capability revocation, RF silence or a reset/DMA-reclamation proof.

The new native tests cover Open/WPA2 retained kernel DHCP/IP, eight real
independent TX buffers, partial/compressed/single completion and scheduler wrap,
manager refusal, all recipient TIDs/SSNs/window wrap, genuine C2/C3/BAR/DELBA,
allocation/positive-response/removal/marker uncertainty and cancellation,
malformed native receipts, current source/power/policy loss, duplicate/dialog
binding, unallocated/foreign/old/nested RX and PN isolation, rekey and local
close. Expected wire bodies and independent authenticator CCMP/AP behavior
remain native Rust, with no external compiler/source adapter or vendor binaries.

Primary contracts: Linux `mvm/{mac80211,sta,tx,rxmq}.c`, `fw/api/{sta,tx,rx}.h`,
`fw/file.h`, `cfg/22000.c`, `pcie/gen1_2/{internal.h,tx,tx-gen2}.c` and
`net/mac80211/{agg-tx,agg-rx,rx}.c`. Firmware43 TX setup and legacy ADD_STA BAID
selection are deliberately distinct from the Gen3 aggregation helpers.

### 3.20 Native GTK replay history and reconnect

The retained Gen2 owner now keeps a bounded ledger of key fingerprints, peer,
key role/index, seventeen committed RX PN floors and native retirement proof.
It retains no additional plaintext key material in that ledger. Six retained
worker reconnect smokes plus a native history-capacity smoke passed in the
coordinated x86_64 and aarch64 native WiFi suites. No hardware or external
interoperability outcome is inferred from those software results.

Only a new authenticated four-way exchange may restore a retired RX-only GTK
whose exact material fingerprint, AP BSSID and key index match. The previous
key REMOVE must have a successful native receipt followed by the matching
single-RFH RX epoch marker. Dropping a close/rekey waiter, a command ACK alone,
or installation metadata never marks the ledger reusable. PTKs remain
non-reusable, as do cross-role/peer/index material and GTK rollback during an
already active exchange. Duplicate M3 and unchanged live GTK behavior remains
unchanged: no repeated native key ADD or replay reset.

The new GTK's native RSC is `max(authenticated RSC, all retained TID floors)`.
Linux `mvm/sta.c::iwl_mvm_send_sta_key` likewise selects the maximum receive PN
across non-QoS and all QoS TIDs for the single native key-install field. This
may conservatively drop a lagging TID after reconnect; it cannot lower any
retired floor. API-v2's PN hole and v3's contiguous layout remain exact, and
host floors are restored to the same conservative bound before carrier.
The GTK remains receive-only: every normal ToDS TX uses the pairwise AP key;
no group TX counter is reset into a new multicast producer. The48-bit exhausted
GTK floor requires actual new material. Fresh PTK nonce/M4/native key/marker
receipts and current power/source/policy/PCI/generation fences still gate the
new controlled port; a cached GTK grants none of them.

Existing fingerprints are updated rather than counted twice on permitted GTK
restoration. Newly observed material consumes one of32 bounded records; records
are never evicted to make old material appear fresh. Exhaustion fails before
new key/reply I/O and retains the native owner. History is scoped to this
retained hardware owner, not persistent storage across boot. There is no
cross-reset PN continuity, GTK cross-peer migration, indefinite-history claim
or permission to reconstruct an ambiguous old native key slot.

Tests compose actual authentication/association, same retained owner, native
key removal/marker/queue/PHY close, a new AP four-way exchange, literal restored
native RSC and actual CCMP replay rejection across TIDs, DHCP, cancelled/held
M4 and retirement marker, current grant loss, repeated reconnect and exhausted
PN. A genuine30-rotation native group-rekey conversation checks the32-record
bound. Existing active-exchange old-GTK rejection remains a separate regression.

### 3.21 Native command IDs and receipt-fenced Gen3 queue retirement

The reached Gen3 control callers have been audited against local Linux
`fw/api/cmdhdr.h`, `pcie/gen1_2/tx-gen2.c`, MVM `fw/coex/power/scan/phy-ctxt/
mld-mac/link/mld-sta/time-event/rs-fw/mld-key/sta.c`, and MLD equivalents.
Bare opcodes and `WIDE_ID(group,opcode)` contain zero command-ID version bits.
Qu, AX210 and Bz transport now send header0 for these callers independently
of discovered payload layout versions; those payload-version, exact device,
firmware and response extent gates remain unchanged. RLC-v2 is the source
exception: `iwl_mvm_phy_send_rlc` explicitly uses
`iwl_cmd_id(RLC_CONFIG_CMD,DATA_PATH_GROUP,2)`. Its native Gen2 PHY continuation
now sends header2 via the explicit command-ID path. It is not inferred by
copying an arbitrary negotiated payload version into the header.

The native literal header regression covers29 bare/WIDE_ID identities plus
the explicit RLC ID across all three completion formats. A composed native
PHY/RLC regression checks the actual32-byte RLC program and header2 after
each preceding firmware receipt. The Sc DHCP/AP model independently validates
payload formats and header0. These new/updated tests passed in both coordinated
native WiFi architecture suites.

Gen3's reached `remove_tx` now shares the strict TVQM-v3 retirement owner with
Gen2. The caller must first reach terminal packet DMA; exact station/TID/queue
binding is checked and a Removing state is retained before the first await.
An external waiter disappearing cannot reopen that queue's packet producer,
replay REMOVE or reuse its slot. The genuine native response must be exactly8
bytes, name the retained queue and report zero status/reserved fields before
queue storage is dropped. REMOVE ignores the documented ADD-only initial write
pointer rather than resetting state from it. Malformed/foreign/failed receipts
retain queue storage. A late ACK after a raw transport waiter has disappeared
does not reconstruct a validated logical owner. The existing retained worker
keeps its future; otherwise a separately proved real stop/reset is required.

Three new native transport smokes exercise exact/failure/foreign receipts,
post-publication cancellation, late receipts, pending packet DMA, station/TID
identity and queue IDs>255 across Qu/AX210/Bz. The full Sc Open/WPA2 DHCP/IP
fixture now supplies the genuine8-byte native REMOVE receipt. No new matched
PCI/API profile is admitted by a header correction or by these fixture vectors.

The reached MLD recipient BA path also now reserves its positive response and
retirement states. A BAID returned by allocation cannot admit reordered data
until the actual positive management packet has a successful native terminal
TX receipt. Cancellation leaves that window inactive; late packet receipts or
duplicate peer dialogs cannot reconstruct the missing logical owner. The
existing standalone Window constructor remains a sequence primitive; only the
composed station lifecycle controls these native receipt transitions.

Before host BAID/window reuse, native REMOVE must return its source-defined
four-byte response (its ADD-only BAID value is ignored), then
TRIGGER_RX_QUEUES_NOTIF carries the single-queue MLD DEL_BA payload: type1,
three reserved zero bytes, monotonic cookie and exact retired BAID. This differs
from MVM's type16/sync16 prefix. The genuine echoed RX marker, not command ACK
or an idle notification drain, orders the retired packet prefix. Timeout,
malformed identity, dropped owner or failed native command leaves the window
quarantined. A real DMA-stop/BME-clear restart is the only path that clears a
lost native epoch reservation; cookies do not silently restart at0.

Old data/reorder-release prefix packets are discarded without PN commit.
Up to32 original native management packets are retained for the Connection's
existing AP/PHY/PMF control checks after the marker, so retirement does not
swallow an actual AP disconnect or changed PHY beacon. Native packets also
must name the retained operating channel before altering the connection.
This helper does not publish Ethernet or acquire new radio authority.
Three native epoch smokes cover exact/stale/foreign/malformed markers and
ACKs, prefix handling and cancellation across AX210/Bz. Three composed native
post-association Connection smokes exercise positive-response activation,
late receipts/duplicate dialogs, real BAID remove/marker ordering, reordered
PN discard and bound/foreign-channel peer loss. These tests passed on x86_64
and aarch64; the post-association models do not establish a new physical profile.
Primary layouts are Linux `mld/{agg,rx}.c`, `mld/{agg,rx}.h` and `fw/api/rx.h`.

### 3.22 Retained executable/PNVM authority and MLD receive publication epochs

The common native startup now binds the actual selected executable and any
external PNVM `Asset` before starting firmware. Binding invokes each original
registry capability and compares its bytes, SHA-256 and signer with the retained
immutable copy. It cannot silently rebind the same Hardware owner. A cloned
capability owner survives the bootstrap caller, instead of retaining only bytes
or treating possession of a prior grant as current validity.

Each boot-future poll runs inside those actual executable/PNVM and PCI
invocations. Native command/TX descriptor publication, RFH copy/completion and
the receive-port commit use the retained current source fence. After native
startup the PCI fence also checks MEM_SPACE, INTX_DISABLE and BUS_MASTER in
the actual function's command register. Source revocation or lost native
authority fails admission while uncertain DMA stays pinned; installing another
blob under the same registry name cannot revive an old capability owner. The
cfg-only private RAM model never supplies physical PCI or firmware acceptance.

The MLD Device encloses registration, carrier/BSSID, TX IPC allocation/enqueue,
RX IPC publication and the actual stack callback with its retained source fence.
A monotonic association publication generation invalidates old outputs at close
intent before an asynchronous mutex can be acquired. The literal-name ACTIVE
identity is checked too, so an old Arc or late output cannot down or publish
through a successor interface. Source denial is terminal; an inner ring-full
result remains retryable. Callbacks run after owner, admission and ring guards
are released, allowing normal synchronous ARP/ND replies to enqueue safely.
The RX IPC channel also belongs to its receive key epoch. Publishing retained
EAPOL work retires the actual consumer and producer before any native wait,
discarding already-queued old-key copies. Native completion refreshes both
endpoints only for the current open epoch; an unchanged current channel is
preserved. Successful rekey cannot leave a stale packet in a persistent IPC
consumer even when a stack callback performs the replacement reentrantly.

Each RFH packet copy also records the immutable receive key/association epoch,
or a closed-port capture. This differs from the final association publication
generation. A packet copied closed or under an older key cannot later enter
the reorder/PN owner after M4 or a key receipt. Initial ordinary data is dropped
without PN commit even when it shares a DMA drain with genuine EAPOL. Native
data/reorder notifications must carry the current capture epoch; original
management frames still pass the existing peer/channel/PHY/PMF control checks.

Association and authenticated changed-key processing reserve a closed receive
epoch before any native wait. After the genuine reply's terminal TX receipt,
the single-RFH owner issues source-defined MLD `IWL_MLD_RXQ_EMPTY` type0:
20-byte TRIGGER_RX_QUEUES_NOTIF command, queue mask1, opaque count8,
three reserved bytes and monotonic cookie. Its exact12-byte native echo,
including queue-prefix extent/type/reserved/cookie, proves the completed RFH
prefix. An empty command ACK, drained host ring or caller boolean cannot open
the port. Old data is discarded, bounded original management controls remain
effective, and even a same-drain suffix copied while closed stays closed after
the marker. This is distinct from type1 DEL_BA and MVM's16-bit internal prefix.

Only the matching native prefix proof and current source/PCI fence can commit
the new epoch. Failed/malformed/cancelled waits retain their reservation and
cannot replay a command or reconstruct logical completion from a late echo.
The already-proved DMA-stop/BME-clear restart clears uncertainty; it never
turns an old packet into a new capture. A separate cloned atomic receive token
follows staged Ethernet through its final callback, so a delayed old output
does not inherit a replacement key epoch. No owner/ring lock is needed at that
callback. Discarding frames here does not prove MAC/FIFO RF quiescence.

Native notification storage never silently evicts an earlier control. More
than256 unconsumed notifications is terminal and closes receive admission,
while the retained resource/uncertain-epoch policy remains in force. This
bound counts firmware packets rather than RFH buffers: one completed buffer
can carry several aligned packets. A later matching marker cannot authorize
an epoch whose original peer-loss/PHY/PMF prefix was lost to overflow.

Two new native source transport smokes and seven Sc composition smokes exercise
real registry revocation/reinstall, executable/PNVM/PCI loss during held M4,
unchanged DMA ownership, actual Open/WPA2 kernel DHCP/IP, delayed output,
reentrant TX/ring-full behavior, and closed M4/marker copies followed by fresh
same-PN data. Two exact EMPTY-marker transport smokes cover native request
geometry, ACK-only/stale/malformed proofs, closed same-batch suffixes and
cancellation; a Connection regression checks old/closed reorder/PN isolation.
The added IPC regression retains a genuine queued packet across an authenticated
GTK exchange from the real callback seam, including cancellation during its
native reply wait, then verifies an empty successor consumer and fresh data.
A packed-RFH burst regression places bound peer loss before300 notifications
and a matching EMPTY echo; overflow cannot commit that receive epoch.
These tests passed in the coordinated x86_64 and aarch64 native WiFi suites.

This continuation creates no platform SAR, antenna measurement, calibrated
power or live-regulatory authority for Gen3. It enables no alternate MAC/STA/
TLC/key payload profile. Physical executable/PNVM/native-receipt acceptance,
RF quiescence and hardware validation remain separate. Primary ordering and
marker layouts are Linux `mld/rx.{c,h}` (`iwl_mld_sync_rx_queues` and
`iwl_mld_handle_rx_queues_sync_notif`) and `fw/api/rx.h`.

### 3.23 Per-profile remaining software inventory

This inventory follows local Linux `cfg/{22000,ax210,bz,sc}.c`, `mvm/{ops,sta,
link,mld-mac,tx,mac80211}.c` and `fw/api/{mac-cfg,sta,tx,rs}.h`. Actual NVM,
firmware command tables/services and band-qualified regulatory authority bound
each feature; a Linux chip name or helper structure does not grant a capability.

| Profile | Implemented reachable software | Remaining software gates |
|---|---|---|
| AX200 CC / exact AX201 Qu/QuZ API77 MAC/RF profiles (Linux Qu PCI IDs 0x02f0/0x06f0/0x34f0/0x3df0/0x4df0/0x43f0/0xa0f0, §3.26) | Exact deferred native PCI/API77 source selection, context-v1 boot, NVM/defaults, published station netdev/worker and current-authority IPC/stack integration; passive scan, real Open/WPA2 MLME, separately qualified legacy20 or WMM/HT20/SISO (with §3.28 RX LDPC/STBC1), §3.33 host WPA3-SAE with PMF, §3.34 tag5 HT TX LDPC/TX STBC, §3.36 tag5 HT40, §3.37 tag5 NSS2, §3.38 tag5 VHT80, §3.39 tag5 VHT160, signed v5 SAR/power, DCF/EDCA/TLC, native staged RX A-MSDU, M4/native keys/RX epochs/rekeys and encrypted data, beacon-loss/AP-close detection, local receipt-fenced retirement preceded by §3.25 over-air leaving deauthentication. Software-validated continuation: tag3 BE/TID0 firmware-managed TX BA/eight-packet pipeline, recipient BAID TIDs0–7/window32/native reorder/DEL_BA key/close fences; bounded native GTK replay history and receipt-fenced reconnect restoration, extended in §3.30 to cross-peer/cross-index GTK restore, safe same-peer PTK reuse and a radio-scoped ledger across native owners; §3.31 generic tag5 feature programs with per-TID QoS queues for all four ACs; §3.29 firmware/transport recovery and non-WoWLAN system suspend/resume. Authored, execution pending: §3.24 tag4 negotiated unicast-local nested recipient A-MSDU-in-A-MPDU with complete bundles before sequence/PN ownership. | Active probes (scan firmware's emitter/power binding needs source proof); alternate ML BAID; TX A-MSDU; HE; SAE-EXT-KEY (AKM 24) and WPA2-PSK with PMF; persistent key history. AP/P2P, WoW (with its D3 ARP/NS/GTK offloads), the §3.27 scheduled-scan offload and multiple RX/RSS remain unimplemented even where hardware supports them. Exact command contracts, distinct measured emitting-program inputs and physical acceptance remain required. |
| AX210/AX211/AX411 and Bz/BE200 Gen3 transports | Context-v2, generation-selected completion layouts, firmware/PNVM/native boot and MLD helpers. Software-validated continuation: source-selected command-ID header0/explicit RLC2, receipt-fenced TVQM/BAID retirement, retained actual executable/PNVM/PCI authority and immutable DMA-copy receive/publication epochs. | Station admission remains dependent on the exact negotiated MAC/link/STA/TLC/key payload profile; no new payload profile is enabled by the header/source audit. Sc conversation tests do not establish another family's ABI, platform power/SAR program or hardware. Current live regulatory/power ownership remains separate. |
| Sc c103/BE211 MLD station profile | Deferred retained native publication, actual station/management/data/Open-WPA2-SAE conversations, legacy/HT/VHT to80MHz, key/BA/reorder and userspace SME/port ownership in the existing profile. §§3.21–3.22 header/TVQM, positive BA response/RX-marker retirement, retained executable/PNVM/current-PCI publication and copy-time key epochs passed coordinated native tests on both architectures. | These source/epoch fences do not establish underlying RF quiescence or current live-regulatory/platform-power qualification. HE/EHT/6GHz and MLO,160/320MHz, AP/P2P and the §3.27 scheduled-scan offload remain separate (non-WoWLAN system suspend/resume is §3.29) implementations and must not be inferred from single-link Sc fixtures. |
| Other advertised PCI/firmware combinations | Identification/firmware selection where defined, including the Linux So/Ma/Bz IDs added in §3.26; 0x7df0 is identification-only (Linux 7.3 `pcie/drv.c` claims no 0x7DF0) and exact admission rejects it | No fallback admits an unknown command table, calibration profile, topology or PHY width. They need their exact source-backed authority/command/receipt/lifetime path. |

MLO/EHT/320MHz is hardware-inapplicable to Wi-Fi6/6E AX2xx devices, while
Wi-Fi7 Bz/Sc support is missing software in this station profile. Six-GHz is
hardware-inapplicable to AX200/AX201; supported 6E/7 parts still require real
band-qualified HE/security/power admission. Platform SAR/antenna measurements,
firmware/board identity and silicon/RF acceptance are external inputs; they
cannot be filled by software defaults or counted as completed code.

### 3.24 Negotiated native Gen2 nested recipient aggregation

This continuation is authored in Rust with15 registered native tests; execution
and coordinated build gates are pending. It applies only to §3.19's exact
API77 HT20/SISO/TLC_OFFLOAD43/Qu48 RX API4 profile with the legacy ADD_STA
BAID path (BAID_ML_SUPPORT63 absent). It adds recipient A-MSDU-in-A-MPDU for
TIDs0–7/window32, retaining the existing BE/TID0 firmware-managed TX pipeline.
It enables no host-built TX A-MSDU, extra TX queue, wider PHY, additional NSS,
alternate BAID layout or additional RFH queue.

`gen2_nested_ba_transmit_power_request().await` returns provisioning metadata
for `iwlwifi/mvm-api77-ht20-siso-wmm-nested-ba-power-v4-<MAC>.bin`, without
measured limits. NIPW remains64 bytes/wire version1; byte46 must be emitting
program tag4. Its exact new binding domain is
`NARF Intel MVM API77 qualified HT20 SISO MCS0-7 SGI20 WMM-BE TID0 TX-BA pipeline8 RX-BA32 nested-AMSDU3839 control power v4`.
All existing actual PCI/NVM/executable/SMBIOS inputs remain included. External
qualification must cover the complete tag3 program plus the negotiated nested
recipient/control behavior. Tag3 never authorizes it. The native loader first
tries this distinct signed asset for a compatible HT/BA offer; only an actual
NotFound retains the existing tag3 program. Unsigned, malformed, mismatched or
revoked tag4 fails before native PHY/queue publication. No board measurement,
SAR fallback or autonomous-emitter allowance is invented.

The retained original ADDBA request must set the A-MSDU-permitted bit. The
driver sets the corresponding positive response bit only under current tag4
qualification, the checked API4/TLC43 profile and the actual peer request.
The existing exact ADD_STA48 status/unique BAID receipt and actual terminal
management-response TX receipt precede activation. Native resource refusal
sends a negative response with that bit clear. Exact repeated requests retain
the same permission and BAID; changed live agreements cannot replace them.
Linux `mvm/mac80211.c` advertises SUPPORTS_AMSDU_IN_AMPDU and
`net/mac80211/agg-rx.c::ieee80211_send_addba_resp` defines this response bit.
The existing native recipient ADD_STA request is unchanged. TLC's `amsdu`
field concerns TX A-MSDU and remains disabled; it is not an invented RX enable.

`mvm_ba_bundle.rs` retains original API4 packets in a complete raw bundle per
native TID/BAID before insertion into sequence reorder. A bundle requires an
explicit index0 prefix, consecutive low7 indices through LAST, matching
original SN/TID/FC/QoS/CCMP IV, at most128 subframes, at most3839 reconstructed
A-MSDU bytes including original subheader/padding accounting, and a100ms
partial deadline. Native recipient MPDUs remain FromDS/unicast to the local
station, with source station/AP/channel/key/MIC/PHY/header facts checked before
storage and again on release. Group-addressed nested subframes remain closed;
this bounded profile supplies no inferred outer-unicast/PTK identity for them; §3.32 records why group-addressed
nested RX is inapplicable.

Linux `mvm/rxmq.c::iwl_mvm_reorder` explicitly forbids trusting a non-LAST
subframe's NSSN, which can already point past its not-yet-delivered suffix.
Only a complete bundle enters the shared reorder owner seeded by the actual
peer SSN; only LAST's NSSN can advance it. Other TIDs retain independent
incomplete bundles. Native C2/C3 advances and hole expiry discard a partial
whose SN has been passed. Missing/foreign/malformed suffixes, an invalid native
MPDU envelope, index gaps, changed identities, expiry or excess extent never
publish a prefix or commit its PN. Ordinary native packets use one-item bundles
and retain the same response-bound BA/header semantics. A station-wide512KiB
raw-copy budget covers incomplete, reordered and released bundles; duplicate,
old, retirement and clear paths release accounting with the exact owned copy.
An exceeded bound closes admission and retains uncertain native DMA.

Released complete bundles feed the existing §3.18 complete-only deaggregation
owner before host replay publication. It validates every original inner
Ethernet/control/VLAN/source bound against a cloned replay state and commits
only a fully valid aggregate, with no header normalization. Thus sequence
reordering precedes deaggregation and PN admission, and every subframe of one
authenticated MPDU can share exactly its PN without granting ordinary replay.
Normal or live-session BlockAck QoS policies remain checked on original bytes.

DELBA, key replacement, local close and terminal failure retain the existing
queue/TX-permission/BAID removal/RX-marker order and current source/power/PCI/
generation/key-epoch fences. Incomplete and reordered host copies cannot cross
retirement or reopen IPC/stack admission. Cancelled or uncertain positive
response/retirement waits stay with the retained native worker and DMA owner.
No command ACK alone establishes RF quiescence or MAC/FIFO/key-retirement proof.

The new `drivers/wireless/iwlwifi/gen2/nested` cases cover retained Open/WPA2
DHCP/IP with the real native TX pipeline and close, all recipient TIDs and
4095→0, non-LAST NSSN, independent interleaving, malformed native middle and
suffix/inner-control rejection without PN consumption, tag3/peer-consent
isolation,3839/3840-byte and128-subframe boundaries, timeout, rekey/DELBA/close,
held positive-response ownership, current firmware/power/policy revocation,
original BlockAck policy/duplicate dialogs, signed tag4 identity, and raw-budget
release on reorder duplicate/drop. Expected packets and the independent AP's
CCMP authentication remain native Rust. Physical firmware deaggregation,
qualification, RF and external interoperability acceptance remain outstanding.
All fifteen added native cases passed on both architectures in the coordinated
Wi-Fi suites: x86_64 2360 pass,0 fail,9 skip; aarch64 1890 pass,0 fail,3 skip.
Production boots and all btrfs postflights were clean; these are software totals.

### 3.25 Gen2 over-air leaving deauthentication

A host `disassociate()` of a completed API77 Gen2 station (phase
`DataPrepared`) now follows Linux `net/mac80211/mlme.c::ieee80211_set_disassoc`
with `tx=true`, as reached from `ieee80211_mgd_deauth` for a local cfg80211
disconnect. The close owner first drops queued host Ethernet (mac80211's
`ieee80211_flush_queues(drop=true)`), then `mvm_assoc.rs::deauthenticate_using`
transmits one 26-byte Deauthentication (FC `0xc0`, DA/BSSID = current AP,
host-assigned management sequence, reason 3 `WLAN_REASON_DEAUTH_LEAVING`) on
the existing station management queue at the AP's lowest basic rate and
waits for its terminal TX_CMD receipt (the second `ieee80211_flush_queues`)
before `release_legacy_data` issues any disable-TX, key-removal, BA, queue,
MAC, link or peer retirement command. The association, peer, queue and keys
are still installed while it is sent; the frame is unprotected because this
profile negotiates no MFP.

The emission keeps the link's power qualification continuously: current
host policy and the applied signed power program are rechecked on every
poll (`qualified_closing_transmit`). `runtime.rs::transmit_closing` is the
only publication allowed after host stop, and only for this close-owned
frame. If current emission authority is already absent the close stays
local (Linux `tx=false`) and no frame is published. A validated terminal
TX_CMD without ACK (`TX_FAILED`) is a complete receipt and local teardown
continues. Revocation or a missing receipt while the frame is in flight is
uncertain emission: the owner fails and retains its queues, keys and DMA.
Peer-initiated deauthentication/disassociation and beacon loss remain
terminal without a reply frame, as before.

`drivers/wireless/iwlwifi/gen2/interface` smokes check the exact frame bytes
and that it precedes every close command in the Open, WPA2 and HT
conversations (and the BA/nested/reconnect suites sharing that actor), an
unacknowledged frame (`TX_STATUS_FAIL_LONG_LIMIT`) still retiring locally,
a revoked-policy local close without emission, and in-flight revocation
quarantining the owner.

### 3.26 Gen2 Qu PCI latency classes and remaining PCI identities

Linux 7.3 `pcie/drv.c` ("Qu devices") binds seven Qu/QuZ PCI IDs to three
`cfg/22000.c` MAC configurations. `gen2_profile.rs::select` admits each with
exactly its source-defined integrated SoC latency class, and the match
table/`PCI_DIDS` in `mod.rs` claim the four previously unmatched IDs:

| PCI IDs | Linux mac_cfg | xtal / LTR delay | `SOC_CONFIGURATION` v2 flags |
|---|---|---|---|
| 0x02f0, 0x06f0 | `iwl_qu_mac_cfg` | 500 µs / 200 µs | `LTR_APPLY_DELAY_200` (4) |
| 0x34f0, 0x3df0, 0x4df0 | `iwl_qu_medium_latency_mac_cfg` | 1820 µs / 1820 µs | `LTR_APPLY_DELAY_1820` (12) |
| 0x43f0, 0xa0f0 | `iwl_qu_long_latency_mac_cfg` | 12000 µs / 2500 µs | `LTR_APPLY_DELAY_2500` + `LOW_LATENCY` (10) |

Flags follow `fw/init.c::iwl_set_soc_latency` and `fw/api/system.h`: the LTR
delay enum sits in bits 2..3 and `LOW_LATENCY` is set only for
`low_latency_xtal` configurations (the medium class has none). MAC/RF
stepping, firmware prefix and every later station gate are unchanged; the
new IDs reuse the same exact Qu/QuZ JF/HR API77 images. Smokes in
`context_v1_tests.rs`, `mvm_boot_tests.rs` and `bootstrap_tests.rs` cover
the class table, the emitted SoC bytes and exact discovery for the new IDs.

0x7df0 remains identification-only: Linux 7.3 claims no 0x7DF0 and exact
admission rejects it. The Linux "So devices" 0x7A70/0x7AF0/0x51F1/0x7F70,
"Ma devices" 0x2729 and "Bz devices" 0x7740/0x4D40 and subsystem-qualified
0xA840 are now in the match table/`PCI_DIDS` with their sibling MAC
configuration (So -> so-a0, Ma -> ma-b0, Bz -> bz-a0 firmware ladders and
completion formats). 0xA840 is claimed only for the 31 subsystem IDs in
`BZ_A840_SUBSYSTEMS` (`pci_subsystem_claimed` in `probe`).
`smoke_iwlwifi_gen3_linux_pci_ids_are_claimed` covers the table. Like the
existing AX211/BE200 IDs they reach identification, firmware selection and
Gen3 transport only; station admission remains with the AX211/BE200
enablement rows. Linux
8000/9000-series IDs are outside this driver's AX2xx/BE2xx scope.

### 3.27 Offload inventory and checksum offload

Linux enumerates the following offloads for these families:

- **TX checksum offload (implemented)**: every 22000/AX210/Bz/Sc `mac_cfg`
  base sets `IWL_TX_CSUM_NETIF_FLAGS` (`iwl-config.h`). `csum.rs::prepare_tx`
  follows `mvm/tx.c::iwl_mvm_tx_csum` / `mld/tx.c::iwl_mld_get_offload_assist`
  for the non-A-MSDU case: L4 checksum field reset to zero, `offload_assist`
  `L4_EN` (bit 6) and IP-header offset 4 words (the RFC 1042 SNAP header);
  `L3_EN` is requested only for A-MSDU, which no NARF profile builds.
  `DataQueue::send_assisted` adds the MAC-header size (bits 8..12) and pad
  (bit 13) for every frame and rejects any other assist bit; the pre-AX210
  16-bit and AX210+ 32-bit TX_CMD layouts are both filled. NARF's frame-ring
  contract requires validation instead of Linux's WARN/`skb_checksum_help`
  fallback: only an unfragmented IPv4 or extension-header-free IPv6 TCP/UDP
  packet of the requested kind is admitted (`csum::tx_admissible` at netdev
  enqueue); TSO and VLAN requests remain refused. The Gen2 worker
  (`mvm_device.rs`, single and BA-pipeline batches) and the Gen3/Sc queue
  owner (`device.rs::progress_transmit` -> `Connection::try_enqueue_assisted`)
  carry the assist bits to the real data queue. Checksum offload does not
  change the emitted PPDU, so no emitting-program qualification changes.
- **RX checksum offload (implemented)**: pre-AX210 (Gen2) uses the MQ
  descriptor `l3l4_flags` (offset 10) exactly as `mvm/rxmq.c::iwl_mvm_rx_csum`:
  `TCP_UDP_CSUM_OK` plus `IP_HDR_CSUM_OK` for IPv4, or an IPv6/IPv6-frag L3
  type. The firmware L3 classification must agree with the delivered
  EtherType and L4 must be a whole TCP/UDP packet. AX210+ uses
  `FH_RSCSR_RPA_EN` and the v3 `raw_xsum` (`mld/rx.c::iwl_mld_rx_csum`,
  `CHECKSUM_COMPLETE`); pre-Bz hardware's sum excludes the SNAP header and
  Bz+ includes it (`iwl_mvm_create_skb`). `csum::rx_meta_complete` turns the
  complete sum into a verdict like `__skb_checksum_validate_complete`
  (remove SNAP/IP header contributions, add the pseudo header, require
  `0xffff`), so a sum with different coverage fails closed. Verdicts are
  reported only for a directly delivered non-A-MSDU MPDU (A-MSDU subframes,
  deferred and reordered copies carry no verdict) through
  `narf_net::RxMeta` on the RX frame ring (`LegacyReceive::Checked`, Gen3
  `Connection::receive_packet_checked`). Both netdevs advertise
  `csum::OFFLOADS` via `Interface::offloads` and `iface::set_offloads`.
  `drivers/wireless/iwlwifi/csum` smokes cover assist bits/field reset,
  refusal of mismatched kind/fragments/truncation/TSO, the l3l4 verdict
  table and fail-closed complete-sum verdicts. Hardware checksum results
  on silicon remain unmeasured.
- **Scheduled-scan offload** (PNO/net-detect): `mld/mac80211.c` advertises
  `max_sched_scan_*` and `iwl_mld_sched_scan_start`.
- **TSO** is not a firmware offload: `mld/tx.c::iwl_mld_tx_tso_segment`
  segments in the driver into A-MSDUs, so it is part of TX A-MSDU.
- **ARP/NS and GTK-rekey offloads** exist only in D3 (`mld/d3.c`,
  `fw/api/offload.h`) and are part of Wake-on-WLAN.

### 3.28 Gen2 HT20 receive LDPC and STBC

Linux `iwl-nvm-utils.c::iwl_init_ht_hw_capab` advertises
`IEEE80211_HT_CAP_LDPC_CODING` and one RX STBC stream for every rf-hr/rf-jf
configuration (`ht_params = { .stbc = true, .ldpc = true }`), and
`IEEE80211_HT_CAP_TX_STBC` only with more than one TX chain. The §3.19
HT20/SISO offer (`mvm_phy.rs::local_ht`, used by the association plan and
`phy_capabilities`) now carries the same receive promises: HT capability
LDPC (bit 0) and RX STBC = 1 (bits 8..9), with TX STBC clear. The native RX
owner (`Profile::rx_rate`) admits rates-v2 `RATE_MCS_LDPC` (bit 16) and
`RATE_MCS_STBC` (bit 17) only as negotiated local receive coding; other
flag bits stay rejected.

Transmit coding is unchanged: TLC flags remain zero, so neither
`TLC_MNG_CFG_FLAGS_LDPC` nor `TLC_MNG_CFG_FLAGS_STBC` is set. TX LDPC
(Linux `rs-fw.c::rs_fw_get_config_flags` when the peer advertises LDPC) and
TX STBC (two TX chains plus peer RX STBC) change the emitted PPDU and need
their own qualified emitting program; they remain open. Receive coding
does not alter emission, so the tag2–4 programs are unaffected.
`smoke_mvm_ht20_rx_ldpc_and_stbc_are_advertised_and_admitted` checks the
offer bits, unchanged TLC flags, admission of LDPC/STBC/both and rejection
of HE dual-carrier (bit 18) and beamformed (bit 19, no TxBF capability
is advertised) rates.

### 3.29 Firmware recovery and system power management

**Gen2 recovery.** Linux restarts a failed device from the error path
(`mvm/ops.c::iwl_mvm_nic_error` -> `iwl_mvm_nic_restart` ->
`iwl_mvm_restart_cleanup` -> `ieee80211_restart_hw` -> `iwl_mvm_up`).
`mvm_station.rs::Owner::recover` performs the same transport restart on a
failed owner: `Hardware::restart` acknowledges the DMA stop, clears bus
mastering, replaces every RX/command/queue allocation and reloads the
retained executable through ALIVE; the owner then retires installed keys
into the PN history (the stop is stronger proof than key REMOVE plus the RX
marker), rebuilds scan/channel/peer/queue/power contexts, and reruns unified
NVM plus the BT/SoC/power defaults (`configure`). Unlike mac80211's in-place
reconfiguration no association is replayed: the station returns to
`Configured` and the SME must rejoin. The restarted device must report the
same MAC and NVM channels/chains/PHY; the pre-failure identity remains the
reference across rejected attempts, and any failure leaves the owner failed.
The netdev (`mvm_device.rs`) runs `Operation::Recover` as retained control
work before the next scan of a terminal station (polled under the
non-master boot authority because BME is off until ALIVE); a dropped waiter
cannot cancel it and a concurrent operation cannot start. A terminal
publication with exhausted generation is never recovered.

**System suspend/resume (Gen2 and Sc).** Linux `iwl_pci_suspend`/`resume`
without WoWLAN: mac80211 quiesces the station (`ieee80211_mgd_quiesce`
sends the leaving deauthentication), then `iwl_mvm_mac_stop` /
`iwl_mld_mac80211_stop` stop the transport. Both netdevs register an
`narf_power::system_pm::AsyncSystemPm` hook (it needs the scheduler and
interrupts, so it is not a `DevicePmOps` callback). Suspend runs the ordinary
close owner (Gen2 §3.25 deauthentication and receipt-fenced retirement; Sc
`disassociate`), then `Hardware::stop_for_suspend` follows
`_iwl_trans_pcie_gen2_stop_device`: mask interrupts, stop the bus master and
wait for its acknowledgement, software-reset the NIC (CSR_RESET bit 7, or
GP_CNTRL bit 31 on Bz+) and clear PCI bus mastering. The netdev stays down
and refuses control while suspended; a repeated suspend is idempotent.
Resume restarts firmware and replays runtime configuration through the
recovery owners above (Gen2 `Owner::recover`, Sc `Device::recover`); the
station starts unassociated. A failed resume stays suspended/terminal and
may be retried. WoWLAN (firmware staying powered in D3) is the separate WoW
row.

**Runtime PM (inapplicable).** Upstream iwlwifi has no runtime-PM path for
these devices: the D0i3 runtime-suspend implementation was removed from
Linux (v5.4, "iwlwifi: remove all the d0i3 references" series) and
`pcie/drv.c` `iwl_dev_pm_ops` provides only system-sleep and hibernation
callbacks. Idle power is the firmware power-save program (`POWER_TABLE`),
which this driver already programs. There is no Linux behaviour to follow.

`drivers/wireless/iwlwifi/gen2/recovery` smokes cover AP-close failure
followed by restart, rejoin and DHCP, changed-NVM rejection and retry,
dropped-waiter retention, suspend with deauthentication before teardown,
idle suspend, failed and successful resume, and resume-after-suspend
rejoin with DHCP. `smoke_sc_system_suspend_leaves_bss_and_resume_restarts`
covers the Sc path. RAM fixtures model the stop/ALIVE half of the restart
(`runtime::model::restart`); the native stop/restart register sequences and
D3 transitions need silicon validation.

### 3.30 Key-history restore and PTK reuse

The retained Gen2 key ledger (§3.20) keys PN floors by key material digest.
`mvm_security.rs::restore_retired` decides what retired history permits for
newly authenticated material with the same fingerprint:

- **Cross-peer / cross-index GTK restore**: after an initial four-way
  exchange a retired GTK may be reinstalled from another AP or at another key
  index. Replay floors are per key material, so the maximum committed TID
  floor carries over (Linux `sta.c` single install RSC); a higher fresh RSC
  is kept. The ledger entry moves to the new peer/index so retirement finds
  it. A group rekey may still not reinstall retired material.
- **Safe PTK reuse**: a retired PTK may be reinstalled only from the same
  peer at index 0. Host per-TID RX replay floors are restored instead of
  reset, and the firmware TX PN (`transmit_seq_cnt`, key command bytes
  68..76, as `iwl_mvm_send_sta_key` passes `tx_pn`) starts above an upper
  bound of every PN the old installation could have used: its install PN
  plus each protected MPDU the transport published while it was installed
  (`Hardware::protected_transmits`; retries reuse their PN). No CCMP nonce
  repeats. Live entries, role changes and cross-peer PTKs remain refused.
  An identical active key is still not reinstalled (KRACK defence).

`smoke_gen2_key_history_restore_policy_cross_peer_index_and_ptk_reuse`
covers the policy table and key-command bytes; the existing reconnect
smokes cover the native same-peer GTK conversation.

**Cross-owner ledger.** A native owner adopts the retired-key ledger a
previous owner of the same radio (station MAC) left behind when it is
configured, merging by fingerprint (floors and TX bounds only rise; an entry
stays reusable only if both copies are retired), and hands its ledger back
when dropped (`Context::adopt_ledger`/`Drop`). A later owner after
re-probe/rebind therefore never restarts from an empty history. Entries
hold fingerprints and counters only. At most four radio ledgers are kept.
RAM fixtures share one MAC and do not adopt ledgers;
`smoke_gen2_key_history_ledger_crosses_native_owners_of_one_radio` covers
the ledger directly.

**Persistent key history (blocked).** Persisting the ledger across reboots
needs an authenticated, rollback-protected persistent store bound to this
radio; NARF exposes none to drivers, and Linux keeps no key history at all.
Within one boot the ledger above survives every owner of the radio.

### 3.31 Generic feature programs and per-TID QoS queues

Every additional emitting feature needs its own externally measured power
program. Instead of a new hard-coded tag per feature, `mvm_power.rs` defines
a generic tag5 program: the tag2 HT20/SISO/WMM base plus exactly the
`feature` bits it names (`BA`, `NESTED_BA`, `QOS_TIDS`). The asset name
(`mvm-api77-ht20-siso-wmm-features-<bits>-power-v5-<MAC>.bin`), the binding
domain (`NARF Intel MVM API77 qualified HT20 SISO MCS0-7 SGI20 WMM feature
program power v5` followed by the bit set) and NIPW record bytes 62..64 all
carry the exact set, so one set never authorizes another; empty, unknown or
`NESTED_BA`-without-`BA` sets are refused. tag3/tag4 map onto the same bits
for BA checks. The native loader tries the tag5 program for the offered
feature set first and keeps the narrower program only on an actual
NotFound; an unsigned, malformed or revoked tag5 asset fails.

`QOS_TIDS` (rows other_qos_ac_tx/other_qos_tid_tx) follows Linux DQA
(`mvm/sta.c::iwl_mvm_sta_alloc_queue`, one queue per RA/TID): data
preparation allocates SCD queues for TIDs 1..=7 next to TID0 with the
same receipt-fenced `SCD_QUEUE_CFG` owner, and close removes each by its
exact receipt. Ethernet frames take their 802.1D priority from the IPv4 TOS
/ IPv6 traffic-class DSCP exactly as `cfg80211_classify8021d` (RFC 8325
table) and an AC that requires admission control downgrades VO->VI->BE->BK
like `ieee80211_downgrade_queue`. Each TID keeps its own QoS sequence
counter and its frames carry that TID in QoS Control. The firmware-managed
TX BA pipeline stays BE/TID0 (other TIDs keep TX aggregation disabled in
ADD_STA) and batches only TID0 frames; other TIDs are sent singly on their
own queue. Without a tag5 `QOS_TIDS` program all traffic stays on BE/TID0.
`drivers/wireless/iwlwifi/gen2/qos` smokes cover the tag5 record/name/
binding table, classification and ACM downgrade, the 9-queue allocation,
EF/AF41/CS1/CS3/CS6/AF21/BE traffic on its TID queue with DHCP, ordered
close removing all nine queues, and the tag2 fallback. Measured tag5
programs and air validation remain external inputs.

### 3.32 Group-addressed QoS receive

Group-addressed data is never covered by a Block Ack agreement (IEEE
802.11-2020 10.25 applies BlockAck only to individually addressed QoS data)
and Linux `mvm/rxmq.c::iwl_mvm_reorder` never reorders multicast. The Gen2
receive owner therefore ignores any BAID the firmware reports for a
group-addressed MPDU and delivers it on the non-BA path with its GTK replay
owner, accepting Normal or No Ack policy (mac80211 transmits group QoS data
with No Ack; the previous BA-session policy check wrongly dropped such
frames). Linux mac80211 `__ieee80211_rx_h_amsdu` drops every
group-addressed A-MSDU (the CVE-2020-24588 class of injected subframes), so
the native path now drops them explicitly too, nested in an A-MPDU or not.
The group_nested_rx row ("group-addressed nested A-MSDU-in-A-MPDU RX") is
therefore inapplicable: there is no Linux behaviour that delivers such a
frame. `smoke_mvm_group_qos_bypasses_reorder_and_group_amsdu_stays_closed`
covers No Ack/Normal delivery with and without a BAID, rejection of group
A-MSDU subframes with and without a BAID, and unchanged unicast BA delivery.

### 3.33 Gen2 host WPA3-SAE and management-frame protection

Rows gen2_wpa3 and gen2_pmf. The Gen2 native owner now joins a WPA3-Personal
BSS with host SAE, MFP-required association, the AKM 8 four-way exchange and
native IGTK/PMF state. Each step follows Linux and uses the shared APIs of
`wireless/specification/spec.md` §3.

- **SAE authentication** (`mvm_pmf.rs::authenticate_sae_using`). This follows
  mac80211 `ieee80211_auth` with wpa_supplicant `sme_send_authentication`/
  `sme_sae_auth` (`sae_pwe` 2). `JoinPlan::prepare*` with
  `SecurityMode::Wpa3Sae { pwe: Both }` admits the AP. The driver builds the
  `SaeSession` from its own entropy (H2E or hunting-and-pecking as
  `SaeJoin::h2e()` selects). The exchange then runs:
  `start_sae_authentication`, Commit, then `sae_authentication_response`
  for every AP Authentication frame of algorithm 3, which yields
  `Transmit` (Confirm, or an anti-clogging Commit) or `Associate`. The
  exchange is bounded by five frames.

  The temporary peer TX window has the same order as open authentication:
  ADD_STA MODIFY enables it, each frame waits for its TX_CMD receipt, and a
  MODIFY disables it before the result is published. Management sequence
  numbers are 0 and 1 for the SAE frames and 2 for association. An AP
  rejection status is published after the peer is disabled and retains
  nothing. A protocol failure, such as a Confirm that does not verify, fails
  the owner. The retained plan, its association request (RSNE with the SAE
  PMKID, RSNXE for H2E) and the PMK move to the association.
- **Association** (`associate_sae_using`). The plan's own request is sent
  (plus the WMM element when the HT20 profile is selected), and the same plan
  checks the response. `AssociationStatus::pmf` records MFP.
  `protected` now uses `SecurityMode::is_rsn` (it was `is_wpa2`).
- **Four-way exchange** (`secure_sae_using`). The retained PMK runs the local
  `security::Session` with `Akm::Wpa3Sae` (SHA-256 KDF, AES-128-CMAC MIC,
  descriptor version 0). Message 2 repeats the exact association-request
  RSNE (`Session::with_station_rsn`, as wpa_supplicant echoes
  `assoc_wpa_ie`; IEEE 802.11-2020 12.7.6.3). Message 3 must carry the IGTK
  KDE, whose IPN is now parsed. Native PTK/GTK ADD_STA_KEY commands carry
  `STA_KEY_MFP` (bit 15), as `iwl_mvm_send_sta_key` sets it for `sta->mfp`.
  The IGTK is installed with MGMT_MCAST_KEY (group 0, 0x1f) v2: 52 bytes,
  `STA_KEY_FLG_CCM` for AES-CMAC, IGTK in the 32-byte field, key ID,
  station 0, and the IPN as `receive_seq_cnt`. This matches
  `iwl_mvm_send_sta_igtk`, which uses v2 because 22000 devices have the new
  RX API. The IGTK is installed before the RX epoch marker and the peer
  re-enable. Linux checks no status in the command response, so its receipt
  alone completes it. Identical material at the same index is never
  reinstalled.
- **PMF receive** (`mvm_pmf.rs::ap_disconnected`). This follows mac80211
  `ieee80211_drop_unencrypted_mgmt`, with `WLAN_STA_MFP` set at association,
  and `ieee80211_crypto_aes_cmac_decrypt`:
  - An unprotected unicast Deauthentication or Disassociation is dropped.
  - A protected one ends the association only when firmware reports
    station0 CCM decryption with a valid MIC (the data path's
    `0xa4c` status) and its CCMP PN advances a dedicated management replay
    counter. The counter resets with fresh PTK material; a reused PTK
    starts at its highest restored data floor.
  - A group-addressed frame needs a valid BIP-CMAC-128 MMIE under the
    installed IGTK. The host `mfp::MfpKeyStore` adopts the IGTK after its
    native receipt and RX epoch, with `rx_pn` set to the KDE IPN.

  Dropped frames change no state. The same rule applies during native RX
  key epochs.
- **Teardown**. The §3.25 leaving Deauthentication sets Protected once a
  PTK is installed. Gen2's new TX API reserves no IV space (mac80211.c omits
  `PUT_IV_SPACE`), and the TX command leaves `ENCRYPT_DIS` clear, so
  firmware CCMP-encrypts with the station key (`iwl_mvm_set_tx_params`).
  Close removes the PTK and GTK, then each IGTK (MGMT_MCAST_KEY
  `STA_KEY_NOT_VALID`), then fences RX before queue removal. Firmware
  restart retirement also clears host PMF state.
- **Interface**. `Device::supports_sae_offload` reports the native key API.
  `associate` accepts `SecurityConfig::Wpa3 { password }`, which becomes
  `Credential::Sae`, and `station_join` runs SAE, association and the SAE
  four-way exchange.

**Not covered.** SAE-EXT-KEY (AKM 24) is refused before anything is sent:
its group-19 HMAC-SHA-256 MIC is not in the local key owner, and a BSS that
offers AKMs 8 and 24 under H2E makes the plan select 24. WPA2-PSK with PMF
(AKM 2 with MFPC, or AKM 6) is not offered: the shared `Wpa2Psk` JoinPlan
mode refuses MFP-required APs and negotiates no MFPC. Beacon protection
(BIGTK) and SA Query remain the MLME owner's. The emitted PPDUs are
unchanged, so no new emitting program is needed.

`drivers/wireless/iwlwifi/gen2/pmf` smokes cover:

- the complete hunting-and-pecking and H2E conversations with an
  independently authored AP (its own `SaeSession`, SHA-256-KDF PTK,
  AES-CMAC MICs, GTK and IGTK KDEs);
- exact key flags and MGMT_MCAST_KEY bytes;
- dropped unprotected, undecrypted, forged-BIP and replayed-BIP frames,
  then disconnects on a valid protected deauthentication and on a valid
  BIP deauthentication;
- the protected leaving deauthentication with ordered PTK/GTK/IGTK/epoch/
  queue close;
- AP rejection, an unverifiable Confirm and an M3 without an IGTK;
- refusal of AKM 24, of SAE without the key API, and of mixing the
  WPA2/SAE owners, plus the legacy and PMF deauthentication rules.

### 3.34 Tag5 HT TX LDPC and TX STBC

Rows ldpc and stbc. §3.28 left two transmit-side HT coding options out:
TX LDPC and TX STBC. Each now has its own tag5 feature bit (§3.31):
`TX_LDPC` = bit 3 and `TX_STBC` = bit 4. A signed program for exactly that
bit set must be selected before either can be used.

**Availability.** `select_station_offer` derives the bits an offer can use
from the observed AP and the NVM, following Linux `mvm/rs-fw.c::
rs_fw_get_config_flags` for the rf-hr/rf-jf `ht_params = { .stbc, .ldpc }`:

- `QOS_TIDS` is available on a selected WMM/HT20 offer.
- `TX_LDPC` is available when the AP's HT Capabilities set LDPC
  (`IEEE80211_HT_CAP_LDPC_CODING`).
- `TX_STBC` is available when the NVM has more than one valid TX antenna
  and the AP advertises Rx STBC.

**Program selection.** `Owner::feature_offers` lists every non-empty subset
of the available bits, widest first, each with BA added when the BA
profile is selected. The native power loader tries the signed program for
each set in turn. An absent program (NotFound) moves on to the next set.
An unsigned or invalid program fails without downgrading. If none is
found, the loader falls back to the narrower tag2/3/4 programs as before.
`feature_offer()` remains the `QOS_TIDS` set, and `select_feature_power`
accepts any listed set.

**Effects of a selected bit.**

- The local HT profile (`local_ht_for`) opts in to TX LDPC, a transmit
  choice that does not change the advertised RX LDPC bit.
- It opts in to TX STBC, which advertises HT Tx STBC (bit 7) as Linux
  `iwl_init_ht_hw_capab` does when there is more than one TX chain.
- The shared HT negotiation enables each option only if the AP's offer
  and response both carry the matching receive capability.
- The TLC config sets `IWL_TLC_MNG_CFG_FLAGS_STBC_MSK` (bit 0) and
  `IWL_TLC_MNG_CFG_FLAGS_LDPC_MSK` (bit 1) at offset 8 of the
  v2/v3/v4 payload (`fw/api/rs.h`).
- With STBC, the TLC chain mask is every valid TX antenna, as in Linux
  `rs_fw_set_active_chains(iwl_mvm_get_valid_tx_ant)`; SISO keeps one
  antenna.
- A beacon that drops the peer's LDPC or Rx STBC capability ends the
  link, like any other change to the retained HT profile.
- ADD_STA is unchanged: Linux sets no STA flag for these options.

`drivers/wireless/iwlwifi/gen2/coding` smokes run complete interface joins
and cover:

- TX_LDPC toward an LDPC peer (TLC flags 2, one chain), with an ordered
  close;
- TX_STBC (flags 1, chain mask 3) and the combined TX_LDPC|TX_STBC program
  (flags 3);
- an LDPC/STBC peer without a tag5 program (flags 0);
- refusal of each program toward a peer without the receive capability.

Measured programs and air validation remain external inputs.

### 3.35 Remaining-row blocker audit

This audit checks each remaining open row against the current tree, after
§§3.33–3.34 landed and was refreshed after §§3.36–3.39. The blockers
below are concrete.

**Not yet implemented; no shared API is missing.**

- HT40, NSS2, VHT80 and Gen2 160MHz landed in §§3.36–3.39.
- **width_160** (row stays open for its Sc/Gen3 profiles). The Gen2
  AX200/AX201 160MHz path is §3.39. The Sc c103 MLD station profile
  negotiates at most VHT80. `ht_vht.rs` advertises no 160/80+80 and
  uses only the primary 80MHz of a wider BSS, and
  `connection.rs::channel_power_width` refuses width code 3. The row's "applicable profiles" also include the Gen3
  AX210/AX211/AX411/BE200 families, whose station admission is itself
  open (see the `*_station_enablement` rows).
- **he, eht, six_ghz, width_320, mlo.** The Sc/Gen3 link, STA and TLC
  encoders (`connection.rs`, `mac_ctx.rs`, `sta.rs`) carry no HE/EHT
  fields: link HE/EHT flags, `iwl_he_pkt_ext`, STA HE/EHT flags and the TLC
  `ht_rates` HE/EHT maps. Six-GHz, 320MHz and MLO also need band-qualified
  regulatory and power admission. These rows are hardware-inapplicable to
  Gen2 AX200/AX201.
- **tx_amsdu.** No native path builds an A-MSDU; the Gen2 queue owner
  sends one MSDU per TX command. Linux v7.2 sets `TX_AMSDU` for 22000
  (`mvm/mac80211.c`). The A-MSDUs come from mac80211
  `ieee80211_amsdu_aggregate` on fast-xmit/iTXQ frames, which requires
  hardware crypto, or from `mvm/tx.c::iwl_mvm_tx_tso` for GSO skbs. Their
  limits come from the firmware's `iwl_mvm_tlc_update_notif` per-TID
  `amsdu_enabled`/`amsdu_size`, and each A-MSDU TX command sets
  `TX_CMD_OFFLD_AMSDU`. With firmware CCMP the host builds plaintext
  subframes, so the shared host-crypto-only `amsdu::encode` is not
  required. Three pieces are missing:
  - a native subframe batcher on the per-TID queues;
  - a consumer for `TLC_MNG_UPDATE_NOTIF` (DATA_PATH 0xf7), which Gen2
    currently uses only as a version gate;
  - a tag5 bit with its signed program.

  NARF's net stack also delivers single ≤MTU frames with no GSO, so only
  the mac80211-style queue batching applies.
- **active_scan_probes.** `mvm_scan.rs` issues only the passive 1940-byte
  `SCAN_REQ_UMAC`. A probe-template builder exists for the Sc path
  (`scan_api::active`, `SCAN_PROBE_PARAMS_API_S_VER_4`), but Gen2 applies
  the signed SAR/link power (`REDUCE_TX_POWER` v5) only in station join,
  after the PHY, peer and queue exist (`prepare_power_using` requires
  `ManagementQueuePrepared`). A scan from `Configured` would emit probes
  under firmware-default limits. Closing the row needs three things:
  - a scan-emission program tag bound to MAC and channel set;
  - SAR chain limits applied from `Configured` before `SCAN_REQ_UMAC`;
  - per-channel probe admission (`connection::channel_power(.., probe =
    true)` refuses NO_IR/DFS).
- **multiple_rx_queues, rss.** The Gen2 transport configures one RFH
  queue. Linux `iwl_mvm_send_rss_cfg_cmd` and `RFH_QUEUE_CONFIG_CMD` (with
  per-queue RX epochs and markers) have no owner.
- **ap, p2p.** There is no AP/GO MAC context, beacon template
  (`BEACON_TEMPLATE_CMD`) or multi-station key/queue owner, although the
  shared `WirelessNetIface::start_ap` exists.
- **wow.** There is no D3 firmware image, `D3_CONFIG_CMD` or WoWLAN key
  material path, although the shared `wowlan_support` exists.
- **ml_baid.** The alternate ML BAID allocation profile is not
  implemented.
- **ax210_station_enablement, ax211_station_enablement,
  ax411_station_enablement, be200_station_enablement.** Each needs the
  exact Gen3 MAC/link/STA/TLC/key payload profile, with conversation
  fixtures per family.

**Blocked by a missing shared or external input.**

- **sched_scan_offload.** The shared crate exposes no `START_SCHED_SCAN`.
  `nl80211/control.rs` parses scheduled-scan attributes only for WoWLAN
  net-detect.
- **persistent_key_history.** NARF provides drivers no authenticated,
  rollback-protected store bound to the radio (§3.30).
- **live_regulatory_owner, platform_power_owner.** These need platform
  SAR/antenna inputs and a live regulatory authority. Both are external
  and cannot be filled by software defaults.

### 3.36 Tag5 HT40

Row ht40. Tag5 bit `HT40` = bit 5 (§3.31) selects 20/40MHz operation on
the AP's secondary channel. A signed program for exactly that bit set must
be selected first.

**Availability** (`select_station_offer`, `ht40_secondary`). The bit is
offered only when all of these hold:

- the offer is a selected WMM/HT offer;
- the AP's HT Capabilities set Supported Channel Width Set and its HT
  Operation names a secondary channel (SCA/SCB) with the any-width bit,
  as mac80211 `ieee80211_determine_ap_chan` reads it;
- the NVM describes the secondary channel, neither channel is 14, both are
  in one band, and the current MCC profile (or, without LAR, the NVM) marks
  both subchannels `NVM_CHANNEL_VALID | NVM_CHANNEL_40MHZ` (Linux v7.2
  `iwl-nvm-parse.c`; 22000 `ht40_bands` cover 2.4 and 5GHz);
- the current host policy permits the whole 40MHz span
  (`Owner::restrict_offer`, called before the power loader). Otherwise the
  bit is dropped and the offer stays 20MHz, like mac80211
  `ieee80211_chandef_downgrade`.

**Regulatory span.** `mvm_power::span_power` takes the lower of both
subchannels' host power and of the rules overlapping the 40MHz interval.
Each such rule must allow 40MHz and initiation, and one rule must cover
the whole interval: the conservative single-rule form of cfg80211
`reg_does_bw_fit`. The retained power owner (`Prepared`) and its
publication `Fence` keep the span. Every ceiling, applied-power and
per-poll publication check therefore covers both subchannels, and
`current_power` additionally requires the firmware 40MHz flag on both.
The shared crate's `reg` module gives only `max_bandwidth_mhz` per rule;
no shared width helper was needed.

**Effects of a granted bit.**

- The PHY context is prepared at 40MHz before authentication, as mac80211
  creates the chanctx from the BSS chandef. Linux v7.2
  `mvm/phy-ctxt.c::iwl_mvm_phy_ctxt_cmd_data` writes the control channel,
  `IWL_PHY_CHANNEL_MODE40` and `iwl_mvm_get_ctrl_pos`: 0 for a control
  channel below the center, `IWL_PHY_CTRL_POS_ABOVE` (4) above it. Both
  the v1 channel-info layout (bytes 16..20) and the ultra-channel layout
  (bytes 16..24) are encoded. Removal repeats the same channel info.
- Before the PHY command, both subchannels must pass the receive policy
  and the firmware channel profile.
- The local HT profile advertises 20/40MHz and SGI40, from
  `iwl_init_ht_hw_capab` for an `ht40_bands` band. The shared JoinPlan
  `LocalPhy::ht40` negotiation selects 40MHz.
- `confirm` requires the response to select exactly the prepared 40MHz
  span. A response that narrows to 20MHz fails closed; it cannot leave a
  40MHz context under a 20MHz station.
- ADD_STA sets `STA_FLG_FAT_EN_40MHZ` (bit 26), from Linux v7.2
  `mvm/sta.c::iwl_mvm_sta_send_to_fw`.
- TLC sets `max_ch_width` = `IWL_TLC_MNG_CH_WIDTH_40MHZ` (byte 4), from
  `rs_fw_bw_from_sta_bw`. It also adds the 40MHz SGI bit (bit 1) when the
  peer advertises SGI40, from `rs_fw_sgi_cw_support`.
- Received HT rates may carry `RATE_MCS_CHAN_WIDTH_40` (bits 11..13).
  SGI is then accepted only under the SGI40 promise.
- The retained beacon must keep the same HT Operation (secondary
  included), the peer's 20/40 bit and, when used, SGI40.

`drivers/wireless/iwlwifi/gen2/ht40` smokes cover:

- PHY width/control-position encoding in both layouts, and refusal of a
  non-adjacent secondary;
- a complete Open join with the 40MHz PHY (width 1, position 0), FAT_EN_40,
  TLC 40MHz with SGI 20+40, DORA over 40MHz receive rates, an ordered
  close whose PHY removal keeps the 40MHz info, and no retained resources;
- the tag2 and `QOS_TIDS` programs toward the same 40MHz BSS staying at
  20MHz everywhere;
- refusal under a 20MHz-only policy, without NVM 40MHz flags, and toward a
  20MHz BSS;
- fail-closed refusal of a narrowing association response.

Measured programs and air validation remain external inputs.

### 3.37 Tag5 NSS2

Row nss2. Tag5 bit `NSS2` = bit 6 (§3.31) selects two spatial streams.
A signed program for exactly that bit set must be selected first; it
combines with the other bits (for example `HT40|NSS2`).

**Availability** (`nss2_available`). The bit is offered only for a
selected WMM/HT offer when:

- the NVM gives two TX and two RX streams (no MIMO-disable SKU) and two
  valid TX and RX chains;
- the AP's HT Capabilities receive MCS 8..15 (`rx_mask[1]`);
- the AP is not in static SM power save, which Linux v7.2
  `mvm/sta.c::iwl_mvm_sta_send_to_fw` maps to SISO.

**Effects of a granted bit.**

- The local HT profile advertises and selects MCS 0..15 in both
  directions (`iwl_init_ht_hw_capab` `rx_mask[1] = 0xff` with two RX
  chains). SM power save stays disabled.
- `confirm` keeps the negotiated MCS 8..15 toward the peer, or none
  toward a static-SMPS peer.
- ADD_STA sets `STA_FLG_MIMO_EN_MIMO2` (bit 28) when two streams were
  negotiated. Dynamic SMPS keeps `STA_FLG_RTS_MIMO_PROT` as before.
- TLC writes `ht_rates[IWL_TLC_NSS_2][IWL_TLC_MCS_PER_BW_80]` from
  Linux v7.2 `mvm/rs-fw.c::rs_fw_set_supp_rates`, at offset 16 (v2/v3,
  two per-width entries) or 18 (v4, three entries). The chain mask is
  every valid TX antenna (`rs_fw_set_active_chains`).
- Received HT rates may carry `RATE_MCS_NSS_MSK_V2` (bit 4) only under
  the local MCS 8..15 promise.
- The retained beacon must still offer MCS 8..15 and a non-static SM
  power save.

`drivers/wireless/iwlwifi/gen2/nss2` smokes cover:

- complete joins toward a two-stream AP with TLC v3 and v4: MIMO2, chain
  mask 3, NSS2 map 0xff, DORA over MCS15 receive rates, an ordered close
  and no retained resources;
- the tag2 program toward the same AP staying SISO;
- refusal toward a single-stream AP and toward a static-SMPS AP.

The `gen2/ht40` combined smoke covers `HT40|NSS2`. Measured programs and
air validation remain external inputs.

### 3.38 Tag5 Gen2 VHT at 80MHz

Row gen2_vht. Tag5 bit `VHT` = bit 7 (§3.31) selects VHT MCS 0..9 on an
80MHz 5GHz channel. The shared negotiation (`LocalPhy::vht80`) builds VHT
on the HT 20/40 profile, so a VHT program must also name `HT40`.
`validate_record` refuses `VHT` without `HT40`, and `feature_offers`
never lists such a set.

**Availability** (`vht80_center`). The bit is offered only when all of
these hold:

- `HT40` is available, on a 5GHz primary;
- the NVM reports VHT (`NVM_SKU_CAP_11AC`);
- the AP sends VHT Capabilities and a VHT Operation of width 1 with CCFS0
  an 80MHz center (42/58/106/122/138/155) and no second segment, the
  form mac80211 `ieee80211_chandef_vht_oper` reads as 80MHz;
- the 80MHz block contains both the primary and the HT secondary;
- the firmware profile marks all four subchannels VALID |
  `NVM_CHANNEL_80MHZ` (bit 10);
- `restrict_offer` finds the 80MHz span permitted by host policy.
  Otherwise VHT is dropped and HT40 remains; losing HT40 drops VHT too.

**Span generalisation.** §3.36's secondary channel is now a `Span`
(center, width code 1 = 40MHz or 2 = 80MHz).

- `span_power` and `current_power` check every subchannel, the
  `NVM_CHANNEL_40MHZ`/`80MHZ` flag on each, and a covering rule allowing
  the span's bandwidth.
- `Span::control_position` is Linux v7.2 `iwl_mvm_get_ctrl_pos` in full:
  primaries 36/40/44/48 of center 42 give 1/0/4/5.

**Effects of a granted bit.**

- The PHY context uses `IWL_PHY_CHANNEL_MODE80` with that control
  position.
- Locally, VHT advertises SGI80, RX LDPC, one RX STBC stream and MCS 0..9
  on one stream, or two with `NSS2` (`iwl_init_vht_hw_capab`). TX
  LDPC/STBC follow their own bits.
- `confirm` requires the response to select exactly the prepared 80MHz
  span with VHT. It keeps the negotiated VHT TX map, limited to one
  stream for a static-SMPS peer.
- ADD_STA follows `iwl_mvm_sta_send_to_fw` exactly. Its `BW_80` case ORs
  `STA_FLG_FAT_EN_80MHZ` and falls through to `FAT_EN_40MHZ`, giving
  field value 3.
- TLC uses `max_ch_width` 80MHz, `IWL_TLC_MNG_MODE_VHT` and SGI bit 2.
  Per stream, `rs_fw_vht_set_enabled_rates` writes `BIT(highest + 1) - 1`
  into `ht_rates[nss][BW80]` (offsets 12 and 16/18).
- Received VHT rates are accepted up to 80MHz, MCS 0..9, with NSS2 only
  under the local promise.
- The retained beacon must keep the VHT Operation and a VHT RX map
  covering the TX map.

**Fixture.** The Gen2 interface fixture now takes an operating channel
for scan, request, PHY check and the MPDU descriptor channel. It also
takes a VHT NVM profile (SKU 11N|11AC; channels 36..48 at 20/40/80MHz).
The 5GHz `FakeAp` uses its OFDM 6/12/24 rates.

`drivers/wireless/iwlwifi/gen2/vht` smokes cover:

- a complete 5GHz join on channel 36: PHY width 2/position 1, FAT field
  3, TLC 80MHz/VHT/SGI 20+40+80/MCS 0..9, DORA over VHT MCS9 80MHz
  receive rates, an ordered close whose PHY removal keeps the 80MHz
  info, and no retained resources;
- HT40-only and tag2 programs toward the same BSS staying HT at 40 and
  20MHz;
- refusal under a 40MHz policy, toward a 20/40MHz VHT BSS, and for a VHT
  program without HT40.

The `gen2/ht40` PHY smoke covers the 80MHz control positions. Measured
programs and air validation remain external inputs.

### 3.39 Tag5 Gen2 contiguous 160MHz

Row width_160, Gen2 part. Tag5 bit `WIDTH_160` = bit 8 (§3.31) widens a
VHT program to a contiguous 160MHz channel. A `WIDTH_160` program must
also name `VHT` and `HT40`: `validate_record` refuses it otherwise and
`feature_offers` never lists it.

**Availability** (`vht160_center`). The bit is offered only when all of
these hold:

- VHT80 is available (§3.38);
- the AP advertises 160MHz support (VHT Supported Channel Width Set 1 or
  2);
- the AP's VHT Operation has width 1, CCFS0 the selected 80MHz center
  and CCFS1 a 160MHz center (50/114/163) eight channels away, the
  contiguous 160MHz form of mac80211 `ieee80211_chandef_vht_oper`;
- all eight subchannels are VALID | `NVM_CHANNEL_160MHZ` (bit 11). Linux
  v7.2 `iwl-nvm-parse.c` sets `vht160_supported` from that flag;
- `restrict_offer` finds the 160MHz span permitted.

80+80 (`discontiguous()`) is refused. A 160MHz BSS still offers VHT80
on its primary 80MHz block.

**Effects of a granted bit.**

- `Span` width 3 covers eight subchannels. The PHY context uses
  `IWL_PHY_CHANNEL_MODE160` with `iwl_mvm_get_ctrl_pos`; primary 36 of
  center 50 gives position 3.
- Locally, VHT adds `SUPP_CHAN_WIDTH_160MHZ` | `SHORT_GI_160`
  (`iwl_init_vht_hw_capab`), and the shared `LocalPhy::vht160`
  negotiation selects 160MHz.
- `confirm` requires exactly the prepared contiguous 160MHz span.
- ADD_STA keeps the FAT field 3 that `iwl_mvm_sta_send_to_fw` produces
  for `BW_160`.
- TLC uses `max_ch_width` `IWL_TLC_MNG_CH_WIDTH_160MHZ` (3) and SGI bit
  3. Per stream, it copies the 80MHz map into `IWL_TLC_MCS_PER_BW_160`
  (offset +2), as `rs_fw_vht_set_enabled_rates` does when
  `ieee80211_get_vht_max_nss` allows the stream at 160MHz. Without
  Extended NSS BW that is every negotiated stream.
- Received VHT rates may carry `RATE_MCS_CHAN_WIDTH_160` with SGI under
  the SGI160 promise.
- The retained beacon must keep the VHT Operation, 160MHz support and,
  when used, SGI160.

`drivers/wireless/iwlwifi/gen2/vht` smokes cover:

- a complete join on the fixture's 160MHz profile (NVM channels 36..64
  with 160MHz flags; a 5170..5330MHz policy rule allowing 160MHz): PHY
  width 3/position 3, TLC width 3, SGI 15, BW80 and BW160 maps 0x3ff,
  DORA over VHT MCS9 160MHz receive rates, an ordered close keeping the
  160MHz removal info, and no retained resources;
- a VHT80 program toward that BSS using its primary 80MHz;
- refusal under an 80MHz policy and toward an 80MHz BSS.

The fixture policy has no DFS flag on channels 52..64, so it does not
show DFS behaviour. Measured programs and air validation remain external
inputs. Gen3/Sc 160MHz remains open with HE (see §3.35).

## 4. References

- Linux `drivers/net/wireless/intel/iwlwifi/`
- Intel product briefs for AX200, AX210, etc.
- IEEE Std 802.11-2020.
