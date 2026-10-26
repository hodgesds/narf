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
an MLD station profile. The separate Gen2 probe remains gated; existing
software tests do not establish hardware acceptance for either path.

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
Gen2/MVM station operation, AP mode, 6 GHz/HE/EHT and system suspend/resume
still require separate software implementations. They are not hardware-only
acceptance gates and are not enabled by this profile's station tests.

## 3. Public interface and stage progression

- **Stage 1**: PCI match table.
- **Stage 2**: CSR/PRPH mapping + APM init + ucode header parsing.
- **Stage 3**: Owned Gen3 firmware loading and DMA ALIVE handshake. Gen2
  context-v1/RFH/TFH and retained API77 MVM boot ownership are implemented;
  MVM station context/security/recovery lifecycle remains an explicit software dependency.
- **Stage 4**: Interface traits, IPC ring integration, background
  RX/TX pumps, and the MLD station scan/association/data implementation.
- **Stage 5 (In progress)**: First hardware boot/ALIVE, firmware init,
  scan, station association and IP-traffic acceptance. Software tests
  exercise these contracts without emulating the Intel radio.

### Native deferred firmware admission

`probe` retains the exact accepted Gen3 BDF/device/current PCI cap before initial
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
evidence below. Non-Sc transport and the separate Gen2 profile are unchanged.

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
remain unchanged. Existing Gen2 boot/passive/peer owners are separate and native
MVM station publication stays disabled.

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
station-version gate, nor enable Gen2/MVM native station publication.

### 3.1 Native PCI and current authority

Probe reserves one PCI function, leaves repeated owned-BDF dispatch untouched,
and parks additional candidates. It clears inherited bus mastering and memory
decode and verifies INTx disabled before BAR sizing, maps BAR0 with Device
attributes, then verifies decode enabled with bus mastering still off. Unsupported
Gen2 candidates remain parked: the old FH diagnostic loader cannot establish a
working AX200/AX201 lifecycle and never publishes a synthetic station identity.

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
ALIVE6/NVM4 command profile. Native automatic admission remains closed: MVM
active station PHY/link activation, rate/key/Block-Ack and recovery lifecycle still need
integration before a Gen2 interface can be published. The passive-scan owner
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

These contracts do not enable Gen2 native PCI publication. The retained power,
active-link and bounded authentication continuations are specified in §§3.11–3.13.
Association, peer/rate/key/Block-Ack and controlled-port integration, owned
recovery and PM remain software dependencies before a Gen2 netdev can be exposed.

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
peer/key or authorize transmit; active station and native PCI admission remain
gated on the remaining power/SAR, peer/rate/key/BA, security and recovery work.
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
§§3.11–3.13. Association, rate/key/BA/security, recovery and native Gen2
publication remain software work.

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
These are software ownership results; active station admission, externally
qualified platform power/SAR (§3.11), management beyond bounded authentication (§3.13),
rate/key/BA/security, recovery and native Gen2 PCI publication remain gates.

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
at each native wait and power-before-queue ordered retirement. Automatic Gen2
station TX remains disabled. The retained active-link transition is specified
in §3.12 and the exclusive authentication TX window in §3.13. Association,
rate/key/BA/security, recovery, PM and native PCI station publication
remain unimplemented gates. No physical SAR, RF compliance or hardware readiness
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
payload versions and capability gates remain unchanged. Existing Gen3 header
behavior is unchanged and retains its separate payload-layout/header-version
audit gate. Literal native header tests cover every reached Gen2 command
category and preserve the Gen3 branch.

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
quiescence follows from host failure. Association and subsequent management,
complete Gen2 data/completion/MLME ownership, rate/key/BA/security,
recovery/PM and native PCI station publication remain separate gates.

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
can seed an association plan. No automatic Gen2 station admission is enabled.

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
closing after qualification revocation exercise the composed owner. Automatic
PCI station publication remains gated until real Gen2
keys/RSNA/BA, connection monitoring, over-air teardown,
owned recovery and PM are complete. Association metadata is not that admission.

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
permanently; reinstalling policy cannot reopen it. Only Open returns true.
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
rates-v2 modulation/rate and20MHz width. It rejects fragments, protected or
firmware-decrypted data, HT-control, A-MSDUs and firmware/retry duplicates.
The native descriptor's padding and CRC trailer are excluded from Ethernet.
The controlled port never forwards WPA2 plaintext IP; a current AP/local-RA
plaintext EAPOL frame is distinguished only after its outer802.1X version and
length bounds validate. This is input for a future RSNA owner, not a MIC check,
key installation, authenticated EAPOL reply or authorized data port. Open does
not forward EAPOL to IP. A bound AP deauthentication/disassociation closes host
admission and retains native resources without claiming an over-air response.
Current policy/source checks precede receive work and every packet publication.

`release_legacy_data().await` closes host admission before its first wait,
acknowledges peer TX-disable, discards transition RX and validates idle
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
netdev or establish RF/firmware acceptance. Native RSNA/keys/PMF, BA/reorder,
beacon-loss monitoring, over-air teardown/recovery, automatic PCI/netdev
publication and runtime/system PM remain explicit subsequent work.

### 3.16 Per-profile remaining software inventory

This inventory follows local Linux `cfg/{22000,ax210,bz,sc}.c`, `mvm/{ops,sta,
link,mld-mac,tx,mac80211}.c` and `fw/api/{mac-cfg,sta,tx,rs}.h`. Actual NVM,
firmware command tables/services and band-qualified regulatory authority bound
each feature; a Linux chip name or helper structure does not grant a capability.

| Profile | Implemented reachable software | Remaining software gates |
|---|---|---|
| AX200 CC / exact AX201 Qu/QuZ API77 MAC/RF profiles | Context-v1 boot, native RFH/TFH, NVM/runtime defaults, passive scan, inactive/active PHY/link, AP peer/management queue, measured signed v5 SAR/power, actual open authentication and Open/PSK-CCMP legacy association/local close; retained normal-data queue/DCF/TLC and Open packet TX/RX, closed WPA2 port with bounded EAPOL receive | Real pairwise/group key and RSNA integration; BA/reorder; protected management; beacon loss/air teardown; recovery and runtime/system PM; retained native PCI station publication. HT/VHT/HE, wider channels, AP/P2P, WoW/offloads and multiple RX/RSS are not implemented by the new legacy owner even where hardware supports them. |
| AX210/AX211/AX411 and Bz/BE200 Gen3 transports | Context-v2, generation-selected completion layouts, firmware/PNVM/native boot and MLD helpers | Station admission remains dependent on the exact negotiated MAC/link/STA/TLC/key payload profile. The generic Gen3 command-ID-header/version assumption still needs a native Linux ABI audit; payload versions alone cannot select header versions. Sc conversation tests do not establish a different family's ABI or hardware. |
| Sc c103/BE211 MLD station profile | Deferred retained native publication, actual station/management/data/Open-WPA2-SAE conversations, legacy/HT/VHT to80MHz, key/BA/reorder and userspace SME/port ownership in the existing profile | The same explicit Gen3 native command-ID audit; HE/EHT/6GHz and MLO,160/320MHz, AP/P2P, advanced offloads, platform power/runtime/system PM remain separate implementations and must not be inferred from single-link Sc fixtures. |
| Other advertised PCI/firmware combinations | Identification/firmware selection where defined | No fallback admits an unknown command table, calibration profile, topology or PHY width. They need their exact source-backed authority/command/receipt/lifetime path. |

MLO/EHT/320MHz is hardware-inapplicable to Wi-Fi6/6E AX2xx devices, while
Wi-Fi7 Bz/Sc support is missing software in this station profile. Six-GHz is
hardware-inapplicable to AX200/AX201; supported 6E/7 parts still require real
band-qualified HE/security/power admission. Platform SAR/antenna measurements,
firmware/board identity and silicon/RF acceptance are external inputs; they
cannot be filled by software defaults or counted as completed code.

## 4. References

- Linux `drivers/net/wireless/intel/iwlwifi/`
- Intel product briefs for AX200, AX210, etc.
- IEEE Std 802.11-2020.
