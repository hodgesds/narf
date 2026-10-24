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
`provision().await` retries newly staged inputs only while Parked. Missing authority,
missing images or invalid source/container inputs leave the same binding parked;
cancellation while waiting for its async mutex cannot consume an attempt. Initial
parking failure, or failure/cancellation after the first mapped/runtime startup
attempt, remains terminal without reconstructing a native owner.

The existing filename ladder and highest-present-image semantics remain exact:
absent candidates may fall through, while a present invalid image fails. Registry
lookup and bounded firmware/sibling-PNVM byte copies occur inside current registry
and blob `Cap::invoke` operations. All TLV parsing uses owned copied bytes; no
borrowed registry view escapes invocation. Source epochs are checked again before
starting the actual native `Hardware`/`Device` lifecycle. Optional external PNVM
retains its existing firmware/SKU requirement; unsupported command/profile gates
remain unchanged. Existing Gen2 boot/passive/peer owners are separate and native
MVM station publication stays disabled.

The retained startup stores the exact initialized `Arc<Device>` before pump/netdev
publication, and the wireless registry receives that same Arc. Missing host policy
retains the previous receive/firmware behavior; active scan and association still
bootstrap authenticated policy and fail closed. Real signed registry fixtures cover
assets staged after the first attempt, a cancelled pre-attempt waiter, exact
firmware/PNVM copies, present-invalid ladder refusal, and actual PCI/source epoch
revocation before deliberately invalid ECAM or native startup publication. The
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
A retained C oracle compiled from actual Linux headers verifies complete
MAC/link/SF/power/MCC and versioned channel packed geometry.

These contracts do not enable Gen2 native PCI publication. Active station PHY/link activation,
association management TX/RX, peer/rate/key/Block-Ack and controlled-port
integration, authenticated platform power/SAR, owned recovery and PM remain
software dependencies before a Gen2 netdev can be exposed.

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
Independent C fixtures compiled from actual Linux headers cover complete PHY
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

Independent C output compiled from actual Linux `sta.h` checks the complete
ADD/REMOVE layouts and the disabled-transmit flags. Native RFH/TFH fixtures
check status/command identity, fresh MCC denial, acknowledged peer reuse,
invalid profile/BSSID/NVM/policy rejection and cancellation at MCC, ADD and
REMOVE publication. A metadata-only replay of the SHA256-pinned real CC API77
image drives the production version checks; opaque image bytes are never loaded.
This is a firmware table-ownership prerequisite, with the link inactive and
transmit disabled. Active station PHY/link, management, rate/key/BA/security,
authenticated platform power/SAR, recovery and native Gen2 publication remain
software work.

Physical carrier/peer publication does not change operator `IFF_UP` and never
invokes administrative open/stop hooks while retained driver state is locked.
Explicit registration, operator up/down and autoconnect remain administrative
events. Disconnect/failure clears carrier and peer identity while preserving an
operator-UP interface; a later physical carrier sample cannot undo operator DOWN.

## 4. References

- Linux `drivers/net/wireless/intel/iwlwifi/`
- Intel product briefs for AX200, AX210, etc.
- IEEE Std 802.11-2020.
