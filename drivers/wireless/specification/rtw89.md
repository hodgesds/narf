# rtw89 — Specification

> Status: Initial RTL8852B retained cold/firmware/full-radio/native-packet
> station path implemented; Open/WPA2, kernel DHCP and exact IP have composed
> software models. Exact signed deployment assets and physical acceptance
> remain required. Other AX/BE profiles retain diagnostic/prerequisite support.

## 1. Purpose & scope

Owns RTL8852A/B/C, RTL8851B and planned RTL8922A PCIe support. Current live
identity code implements AX DDV EFUSE; BE has a different read/block layout.

## 2. Assumptions

The initial B profile owns one PCI function exclusively and uses identity DMA.
It requires actual firmware-reported two-path compatibility, channel1/20MHz,
TX-A fixed1Mbps, RX-AB, an AP advertising basic1Mbps, and awake polling with
interrupts disabled. A claim is bounded to512 packet identities per queue;
terminal close/failure/exhaustion requires a fresh independently reset lifecycle.
BAR2 must cover every actual MAC/PHY and nonsecure indirect-table access.
Other AX/BE profiles retain their parked diagnostic power/identity path.

## 3. Public interface

For `10ec:b852`/`10ec:b85b`, `pci::probe` reserves a singleton before parking
and retains the actual reset owner before its first await. Generic binding
requires an advertised, completed FLR and its consumed temporal fence. A
repeat same-function probe performs no config access, including during reset
quarantine or terminal failure. `pci::attach_cold` is a separate unsafe trusted
platform entry: the caller must independently prove actual function/slot reset,
posted-traffic drainage and no DMA ownership since, and call before generic
binding. Static board facts and BME-off cannot satisfy that temporal contract.
Neither path can replace an existing reserved owner.

`Bootstrap` retains the same `Startup` inside `Arc<Lifecycle>` before discovery.
`Startup::discover` earns the actual factory identity with BME off. One named
Device sharing that lifecycle is registered in the frame, kernel IP and wireless
registries before firmware DMA. `start` resolves the authenticated image/plan
before consuming its hardware attempt. Missing assets leave `Discovered`
retryable. MAC/RX, firmware PHY_CAP, tables, basic operating/calibration and
full measured radio setup progress on that exact retained native backend.
Full-radio preflight runs before `FullRadioPreparing`; success alone produces
`RadioReady` and the sealed ordinary RF/response grant. Missing v1/v2 records
before an attempt remain retryable; the worker reports their exact canonical
filename and actual board digest once per change, without creating authority.

The same Device then prepares source controller/packet owners and drives passive
scan, raw authentication/association, Open/WPA2 host RSNA/CCMP, kernel DHCP and
bidirectional Ethernet/IP. TXBD RP plus matching RPQ identity/status and actual
retained DMA bytes gate security delivery; genuine RXQ/RPQ idle excludes queued
peer loss. Native command waits retain unrelated RX/RPQ events for that owner.
Partial/error/report descriptors are progress rather than idle. PHY awake
readbacks, current signed power/device scopes, opaque peer bindings and the
shared publication admission fence every ordinary doorbell. Administrative
IFF_UP remains independent of carrier and temporary rekey-port closure.
Whole-key-exchange deadlines cover the old-key-open M2-to-M3 wait.

Disconnect reserves and closes admission before awaiting ownership; drain and
bootstrap workers preserve its media-down operation while pending. Cancellation
releases only that reservation, never reopens the station. A post-reset close
while waiting for assets also stops private CH12/RX before asynchronous analog
shutdown. Published storage remains retained: stop bits, revoked authority and
successful source RF shutdown are not DMA-reclamation receipts.

`pci::bring_up(device, cap)` first parks inherited PCI DMA through the shared
Realtek command policy: clear `BUS_MASTER`, enable `MEM_SPACE | INTX_DISABLE`,
and read back the command register. Any access failure, retained BME or missing
requested decoding fails before BAR mapping. Bus mastering remains disabled
on success and every later error; identity and ring allocation do not authorize
DMA. A repeat probe of the retained bus address returns without configuration access; a distinct additional singleton match parks only its own PCI function. Re-enabling
BME requires the composed owned cold/firmware-download and packet/ring/reset owners.
The complete diagnostic mapping/power/identity operation runs within actual
capability invocation. It retains unpublished storage, with no ring base/index
publication, enabled MSI-X delivery, RX pump or network-interface registration.
The private native TX/report hooks also invoke the retained device capability;
revocation returns `Authority` before register access or packet allocation.

The bounded initial RTL8852B identity-DMA startup can earn a temporal fence via
the retained `pci_reset::Reset`. Its unsafe `claim(device, cap)` requires the
already held exclusive singleton reservation, but makes no assumption that
inherited DMA stopped. `run().await` checks exact BDF, ECAM, VID/DID, class,
subsystem identity and capability slot/epoch through current invocation for
every actual config access. Only an actual endpoint PCIe DEVCAP bit 28 permits
the attempt; missing support, malformed/cyclic capabilities and per-domain
IOMMU mode cannot fall back to a power/BME-only reset assertion. It snapshots
all six BAR dwords and ROM, masks MSI/MSI-X and INTx, disables IO/MEM/BME with
readback, and samples transactions-pending at Linux's 0/100/300/700ms points.
Pending timeout refuses the trigger.

The owner becomes nonreusable before the possibly accepted FLR write. It then
performs NO config access for at least 100 real milliseconds, including error,
cancellation and Drop; the truncated millisecond clock uses a 101ms target to
preserve that minimum. After quarantine it bounds config readiness to 60s,
requires the same identity/capability layout, self-cleared FLR and decoding/BME
off, masks interrupts again, restores/readbacks original BARs with decoding off,
and leaves BME/IRQ disabled. Unsupported IOMMU reset handling is not simulated.
Only successful completion creates a private non-Clone `Fence`. Its sole
consumer, `Startup::claim_reset`, rechecks exact binding, current authority,
parked controls and restored BARs before transferring into the actual cold
owner. The original singleton reservation remains retained throughout the
reset, cancellation and Startup handoff. A dropped/failed attempt is terminal
and cannot be replayed or release that reservation. The existing unsafe cold
claim remains only for a genuinely independently fenced platform power/PERST
contract; an automatic probe cannot invent that fact from a static board ID.

Six reset regressions compile unmodified Linux pending/FLR functions to
independent timing fixtures and exercise the real config state machine with
current-epoch operations. They cover minimum config silence, exact BAR ordering
and restoration, unsupported FLR, pending timeout, malformed lists, cancellation,
readiness timeout, changed identity, stuck FLR, ignored BARs and slot/BDF/ECAM/
epoch mismatch before native access. These prove the software temporal protocol;
physical FLR support and endpoint behavior still require hardware validation.

The internal `prepared::load(Files, ChipId, physical_cut)` selects owned
verified firmware snapshots. AX filenames use the Linux `rtw89/rtw8852*_fw`
and `rtw8851b_fw` basenames, preferring supported format suffixes before the
unversioned fallback. Only a missing file permits filename fallback; invalid
images or missing/revoked authority abort. 8852B/8851B prefer the NORMAL_CE
image, then NORMAL. MFW selection bounds every entry before choosing the
nearest non-manufacturing cut at or below the physical revision. BE is rejected
before file access. The native registry adapter copies bytes inside the actual
firmware capability invocation.

`fwdl::parse_auto` accepts AX header versions0/1 only: base sizes32/48 and
section size16 in both versions. Inner section types remain four bits; BBMCU
is an outer image type. AX download chunks are2020 bytes independent of header
version. Header/table/dynamic-extension/payload extents and indexed/formatted
MSSC signature pools, including v1 DSP checksums, are checked before committing
caller section output. A malformed image leaves that output untouched.
`PreparedFirmware` keeps selected-image, payload and signature-pool offsets
bound to one immutable owner and physical chip profile. The private
`DownloadPlan` combines that owner with successfully read physical secure
fuses. Unknown programmed fuses fail explicitly; erased selection is accepted
only after both actual DDV bytes are read. Indexed and formatted signatures
use the Linux AX selection/stride rules, checked bitmap dimensions/rank and
pool extents. Secure hardware requires a matching signature and a host
blacklist at least as new as the image's version; B/C have the upstream
version0 empty policy, while A/51 require an authenticated board policy.
No missing policy or signature falls back to an unsecured transfer.

The plan couples v1 ignored-security descriptor compaction/count with the
same payload selection, strips host dynamic bytes and sets part_size2020.
B's secure v0 length960 override changes both descriptor and payload; ambiguous
checksum-bearing overrides and v0 ignored-descriptor cases fail explicitly.
Signatures replace bytes only in owned output, preserving the verified image.
Header H2C requests no runtime ACK; section chunks are raw firmware bytes
without an invented H2C/last flag. The plan alone performs no hardware I/O.

The private `command_native::Native` CH12 backend owns checked coherent packet
and ring allocations. Constructor/configuration require independently fenced
DMA and verified PCI BME-off. `enable_download` requires the actual completed
cold/factory/basic/PCIe/BDRAM/DLE/HFC owners and an empty CH12 ring; it enables
only CH12 TX DMA, verifies both independent RX layers remain disabled, then
sets and reads back PCI BME as the final publication. WPDMA and all packet
channels remain stopped. The backend rejects the incomplete per-domain IOMMU
path.
All register operations invoke current device authority and check complete
width/alignment extents. Real revocation rejects the constructor before
unmapped configuration access and prevents later packet publication.

The retained `bdram::Bdram` owner implements the internal AX preparation subset
for 8852A/B/C/8851B. With independently fenced old DMA and BME off, it stops
WPDMA and global host DMA, applies the exact per-profile TX/RX idle checks
(10-us interval, 100-us budget), clears supported indices, writes/readbacks
Linux's dual/single internal BDRAM partitions and C's 16-entry WP selector,
then waits for the self-clearing BDRAM reset (1-us interval, 100-us budget).
All supported hardware TX/RX indices must actually read zero. It leaves global
and channel DMA stopped and verifies those bits; no ring base/count, interrupt
or bus-master activation is part of preparation. Failure or dropped waits leave
Preparing and reject reuse before I/O; a replacement requires an independently
verified reset. BE is rejected before any register access.
`Native::prepare_bdram(ber)` invokes current PCI authority to verify BME-off/MEM
decoding, retains PCI basic configuration, then composes DLFW DLE/HFC,
exact AX PCIe MAC-pre-init policy and
BDRAM/index preparation through capability-scoped accesses. Mode programming
occurs after DMA idle and index clear, before partition/reset. `Native::configure`
requires that same retained owner's basic/PCIe, FIFO and BDRAM Ready receipts before
system-memory ring publication. Non-B diagnostic profiles do not call it.
Linux-C traces cover the four AX profiles and nonzero inherited register fields;
negative models cover every access failure, ignored writes, dirty indices,
device disappearance, both wait deadlines, cancellation and actual revocation.
This closes internal partition/index and PCIe MAC-pre-init preparation only:
MAC/RX/RF/station continuations have separate receipts; WCPU Ready is not a DMA-reclamation or station receipt.

Firmware commands have a24-byte TXWD body on A/B/51 and a16-byte RX-like
descriptor on C. TXBD length includes descriptor plus command bytes; there
is no WP/address-info extension. Hardware RP is bits27:16 and host WP bits11:0;
host doorbells write only the low16-bit half. `CommandQueue` retains mappings
before descriptor/doorbell publication, validates whole read-pointer movement
before retirement, and preserves the last eight consumed commands for the
Linux multi-tag delay. Failed publication and Drop retain queued/quarantined
DMA and the published ring. Only an independent hardware stop/idle/prefetch
fence permits explicit reclamation; capability revocation or BME-off alone
does not establish that proof. The private cold/download composition activates
this backend; non-B diagnostic profiles keep it inactive.

The private `firmware_boot::Firmware<Transport>` retains the plan and prepared
CH12 transport through one WCPU reset/download attempt. It checks chip identity
and fresh, never-published transport preparation before starting; an empty ring
that has already carried a command cannot authorize another WCPU reset.
AX watchdog/platform reset and CPU
enable precede secure IDMEM mode recording, H2C-path readiness, the sequence0
header command, FWDL-path readiness and ordered raw sections. A five-ms settle
and bounded firmware-control status7 check precede `Running`; status6 alone
does not authorize runtime commands. A/C watchdog accesses require the full
indirect BAR aperture at0x40000, checked by the native register backend.
Errors and cancellation retain a non-reusable owner and uncertain command DMA;
retry requires a separate complete fenced reset. Linux C trace comparisons cover
all four AX profiles with zero/nonzero initial registers and secure mode, while
models cover exact prepared transfers, every register-access failure, failed
publication, path/final-status timeout and cancellation. This prerequisite does
not enable the diagnostic probe's DMA or publish a network interface.

`power::Power<Io>::power_on` ports the complete PCI RTL8852A byte table and
RTL8852B/C/8851B power-on callbacks, including XTAL commands, cut/RFE/SPS
quirks, power/ONMAC deadlines, platform edges, isolation and function enables.
`power_off` ports the A off table and B/C/51 callbacks, preserving corrected
physical-cut and calibration identity. It requires independently stopped/fenced
DMA, verified PCI BME-off and serialized producers; it does not grant a DMA
reclamation proof. Callback completion plus explicit MAC-OFF readback permits
the same profile to power on again. `normalize_inherited` applies that off/on
sequence to an inherited ON MAC; unknown transitional states fail explicitly.
Failure/cancellation leaves Starting or Stopping and rejects replay before
further I/O. The native backend checks live capability, extent
and width alignment for every register operation, and provides asynchronous
DDV reads for ECV/secure/factory bytes. Cancelled or incompletely restored DDV
power-cut state stays retained and refuses reuse. These primitives do not yet
activate CH12, publish a station or establish complete MAC/RF readiness.

`fifo::Fifo::prepare` implements the AX firmware-download DLE/HFC pre-init:
per-chip MAC/DMAC and internal AXI enables, WDE64/PLE128 geometry, DLFW quotas
with the SCC WCPU minimum, bounded WDE/PLE readiness, and CH12-only host flow
control. 8852C uses its V1 HFC register page. Independent Linux C traces cover
all four AX profiles with inherited zero and nonzero register seeds. The
operation requires a powered, serialized, DMA-fenced device with PCI BME off;
it publishes no system-memory rings. Failure or cancellation retains
Configuring and refuses replay. The native CH12 preparation now retains this receipt with AX PCIe pre-init
and BDRAM/mode setup. The private cold/download owner now composes these with
factory-qualified power/basic_cfg and WCPU activation; it grants no packet or
station admission.

The private `phy_access::Access` and its `NativeIo` adapter serialize AX PCIe
PHY transactions: A/B/51 MDIO uses the exact Gen1/Gen2 page and five-bit
register selection, while C uses aligned direct RAC words. Explicit DBI byte
fallback is supported only on A/B/51; the future PCI configuration owner must
choose it after a failed primary configuration transaction. Idle checks reject
unknown controller requests before data/address publication. Bounded async
completion, capability-checked widths/extents, and a retained terminal state
prevent failure or cancellation from reopening the same owner. Replacement
requires an independently verified reset. Extracted Linux C traces cover
MDIO read/write/masked writes and DBI byte enables; actual-capability RAM
fixtures check native RAC offsets and revoked access before dereference.
These access prerequisites now support exact AX MAC-pre-init PHY/quirk policy
and PCI basic configuration within the private cold/download composition.
Post-firmware MAC/RF and packet/station stages are separate retained Startup continuations.

The retained `pcie::Pcie` ports Linux AX MAC-pre-init PHY/power quirks,
per-chip recovery/watchdog/debug settings and the exact truncated-BD,
packet-RX, eight-tag burst/interval modes for 8852A/B/C/8851B. B/51 use the
actual Gen1/Gen2 link-rate configuration byte and disable autorefclk calibration,
matching every retained Linux profile's disabled-autok policy; unknown rates
fail. Temporary L1 configuration is restored on returned PHY failures;
cancellation retains a terminal owner and requires reset. C cut-A and qualified
PCI_BER platform quirks are explicit, with no guessed platform match. Mode
readback rejects ignored programming. The native adapter accesses ECAM bytes
inside actual current capability invocation (avoiding adjacent RW1C fields),
and chooses the serialized DBI fallback only after a failed primary mapping
transaction. PHY protocols retain their existing bounded async ownership.
Independent extracted Linux-C traces cover all four AX profiles, both cuts,
Gen1/Gen2, zero/nonzero inherited fields, L1 enable/restore and C's BER quirk;
negative models cover every access failure, each cancellable transaction edge,
unsupported profiles/rates, ignored mode writes, disappearance and native
revocation. This is PCIe MAC-pre-init policy, not PCI `basic_cfg` equalization,
ASPM/L1SS, RF calibration, full MAC initialization or station readiness.

`pci_basic::Basic` ports AX PCI basic_cfg independently of MAC-pre-init:
C equalization/OOBS/offset and Gen2 gray-code filter calibration, completion
timeout control and Realtek's internal CLKREQ/ASPM/L1SS modules follow actual
host PCI capability enables. Standard/extended capability discovery is bounded,
checks alignment/extents/cycles and refuses unavailable PCIe v2 controls.
Native config words/dwords use naturally aligned, current-capability ECAM
access; byte writes retain the explicit AX DBI fallback. A temporary C ASPM
backup is restored on returned calibration failures; cancellation retains a
non-reusable owner. Forty independent original-Linux-C cases cover all AX
profiles, both link speeds, inherited zero/nonzero fields, calibrated versus
uncalibrated C and host PM enabled/disabled. Fault/cancellation at every access,
malformed capability lists and ignored control writes keep preparation closed.

`factory::Factory` commits a complete actual DDV snapshot only after the
1216-byte physical map, autoload-valid bit and physical0x5e9..0x5ed controls
have been read successfully. It decodes factory MAC, logical RFE/XTAL/country,
B's real power-k marker and secure fuse selection; independently compiled
original Linux packed types establish all four AX field offsets. ECV must
agree with the corrected 8851B cut. No I/O error becomes erased fuse/calibration
defaults. Unknown/failed/cancelled snapshots expose no identity and reject reuse.
8852B additionally reads the complete separate physical PHY-cap window
`0x580..0x5ff`; its control bytes supply the same power-k/secure decisions.
The retained raw map and logical snapshot feed `factory_b::Calibration`'s exact
TSSI groups, signed RX-gain offsets/compensation and thermal/PA-bias trims.
Only a completed native read permits Linux's explicit erased-map interpretation;
partial I/O never produces trim defaults. Independent packed-C offsets and
byte-preservation/failure/cancellation fixtures cover the extended source.

`cold::Cold` retains one backend through actual normalized discovery power,
factory reading, confirmed MAC-OFF, factory-only calibration qualification,
PCI basic configuration and calibrated second power-on. Only that completed
owner can transfer its backend and factory/basic receipts into native CH12
ownership. `startup::Startup::claim` actually parks the function, maps BAR2 and
reads its physical cut; A/C require the full watchdog aperture. `start` loads
firmware after ECV correction, builds the fuse-bound download plan and composes
owned FIFO/PCIe/BDRAM/mode/CH12 setup and WCPU initialization. It does not build
a powered receipt from caller booleans or replace the retained PHY/DDV state.
Returned failures and a dropped attempt run best-effort command-DMA/BME closure;
published rings, command packets and uncertain multi-tag references remain
retained. Revocation is checked before unmapped native claim access; the actual
native cancellation fixture retains a published descriptor ring and packet.
The shared TX-only activation models use independent original Linux profile
constants and check that no intermediate write enables either RX layer.
Composed power/factory tests exercise every access failure and cancellable edge,
including inherited ON state, RFE5 and corrected ECV.

`Startup::prepare_mac` continues the same initialized firmware/native backend
for the initial RTL8852B PCI profile. It drains actual CH12 consumption with a
bounded wait before replacing the DLFW DLE/HFC configuration; the ring indices,
published command mappings and eight-entry multi-tag quarantine remain owned.
The retained `mac_runtime::Mac` requires actual WCPU status7, autoload-valid
factory/RFE and the completed PHY-cap snapshot, then ports B's BB/RF-enable
callback, MAC system enables and complete SCC DMAC/CMAC0 initialization.
This includes the98,304-byte active DLE carve plus98,304-byte reservation,
normal host-flow quotas/status, scheduler/MPDU/security, CAM/BA resets, filters,
CCA/NAV/protocol settings, internal error masks and host-RPQ routing. Linux's
PCI preload and BA-feature callbacks are no-ops for this exact B profile.
The poll budgets remain bounded; BA-CAM timeout rejects readiness rather than
accepting Linux's warning-only continuation. Critical function/HFC/DLE writes
require readback. Every packet channel and both RX HCI layers remain stopped,
and no RX base, PCI interrupt delivery or station is published.
The initial B profile additionally parks global `B_AX_CMAC_TXEN` from its first
CMAC-enable write. Packet DMA stops alone do not suppress autonomous ACK/CTS.
This is the single explicit gate adaptation to the original C MAC write stream;
readback requires TXEN clear, and later measured response/channel authorization
must precede enabling it. Native failure closes this gate independently of DMA.

Four original-Linux-C traces cover the full B register width/value/order with
zero/A5 inherited fields and both initial cuts. Tests cover every register
failure and cancellable delay, all controller deadlines, ignored configuration
writes, WCPU status6/gone, dirty RX prerequisites and actual revoked NativeIo
authority. Failure/cancellation closes the enclosing startup attempt while
retaining published DMA. `MacPrepared` is an internal system/TRX prerequisite;
RF tables/calibration and policy-qualified channel/rate/station activation
still precede usable hardware.

`Startup::prepare_receive` advances only the same actual B firmware/MAC owner
to internal `Receiving`. `rx_dma::Rx` retains both RXQ/RPQ descriptor rings and
their fresh DMA buffers (Linux's11,498-byte extent), verifies
zero indices, publishes bases/counts with readback, and enables only those two
RX channels and both independent RX HCI layers. LTR follows the actual PCIe
DEVCTL2 host enable through the bounded capability walker; invalid LTR state
fails before base publication. Baseline eight-byte address-info is configured.
WPDMA and every packet TX queue stay stopped; this is a selective RX continuation,
not the complete Linux all-queues PCI post-init. PCI interrupt delivery and
network-interface publication remain absent. Failure/cancellation is terminal
and retains any possibly published descriptors/buffers; stop bits or BME-off
do not release memory.

Each private polling invocation bounds both rings' descriptor work. Host-only
16-bit WP doorbells preserve hardware RP, reject invalid/stale index movement,
and require repost readback. `rx_packet::Assembler` checks actual RXBD write
extents, short/long RXD and driver-info offsets and bounded FS/LS assembly.
It strips exactly four FCS bytes only from native Wi-Fi packets, and drops bad
CRC/ICV or unsupported aggregate/hardware-crypto/nonlegacy profiles. RPQ uses
the actual RXBD write length for complete four-byte release records, independently
of RXD packet length. C2H envelopes retain their full bytes and decode receive
versus execution ACK identities separately; neither a transport read pointer
nor a receive ACK establishes firmware execution. Events remain private; the
packet TX owner and identity-matched RPQ completion dispatcher are still required.
Before the signed ordinary packet/response owner exists, RX publication and each
poll also reject a set global CMAC TX gate; CPU RX filtering cannot stand in
for autonomous-response authorization.

Independent compiled original Linux functions/types provide48 RXD layouts,
64 ring-wrap/index cases, four RXBD address encodings, nine C2H envelopes,
240 RPQ identities/channel mappings and enabled/disabled zero/A5 LTR traces.
The RAM device model follows actual published ring bases/descriptors and only
writes buffers after matching complete addresses/extents to retained allocations.
Tests mutate the real DMA body, reject unwritten/out-of-owner descriptors,
exercise ignored reposts, every register failure, cancellable config reads,
malformed metadata and actual revoked NativeIo authority before allocation
or DMA packet inspection. Actual native CH12/RX allocations stay below36 bits,
matching Linux's device DMA negotiation; the40-bit baseline descriptor encoding
alone never grants a wider address limit. These are software/model proofs, not physical radio
validation.

`rf_access::Rf` implements B's actual RF-v1 analog SWSI and direct RF register
transactions independently of the PCIe PHY MDIO/DBI owner. AX PHY addresses add
0x10000; native access therefore requires current authority over BAR2 through
0x1f3ff, rather than inheriting RF authority from the MAC-sized minimum mapping.
The native adapter additionally requires the retained completed B factory/MAC/RX
continuation. It preserves the20-bit masks, path selection, actual SWSI busy/done
polls at1us/30us and2us read settle, and1us direct-write delay. No fabricated
readback supplies a calibration value. A failed or cancelled transaction never
replays; analog write success means issuance, and the next transaction checks
actual busy.48 compiled original Linux callback traces cover both paths,
analog/direct, zero/A5 inherited fields and full/sparse masks. Tests cover each
access failure and cancellation point, all busy/done deadlines, invalid paths,
the actual native aperture and revoked authority. `radio_tables_b` retains the
actual B BB1,013, gain66, RF-A8,295, RF-B8,392 and NCTL1,320 pair entries.
`radio_table::program` validates/selects the entire immutable program before
its first device write, preserving exact/wildcard/max-cut headline ordering
and conditional branch selection.160 compiled original Linux selector cases
compare full selected-stream counts and order-sensitive digests across RFE/cut
inputs; malformed grammar or an unsupported package never yields a successful
partial program. The composed B execution below closes BB gain/reset/power-unit
and RF firmware upload; table selection alone grants no hardware readiness.

The same retained B startup now snapshots `radio_assets::Assets` from its
verified firmware container before CH12 publication. Packed MFW/element geometry,
ordered payload bounds, alignment, radio path indices and complete pair extents
are checked; only absent overrides use Linux's explicit static-table fallback.
B uses the AX aid0 layout (Linux assigns physical AID only on BE). The first
matching embedded BB/gain/RF/NCTL table wins, and actual power/tracking/regulatory
element bytes remain retained for their typed consumers. A malformed present
element never falls back to invented static data. Original packed C types
independently fix the offsets used by the fixture.

`Startup::prepare_radio_tables` advances from actual `Receiving` through one
retained `radio_init::Init` to `RadioTablesLoaded`. It selects and validates all
programs before its first PHY write, decodes signed gain state, replays the real
BB program, initializes MAC0 power units with readback, performs B's exact
reset sequence, and issues RF-v1 A/B programs plus their packed firmware pages.
Native runtime H2C uses the same CH12 ring/quarantine, real sequential headers
and AX's receive-ACK request every fourth command; each RF path has at most
three500-word pages. This one-shot initial profile rejects sequence reuse after
256 commands. Success establishes transport consumption, never firmware execution
or a calibrated radio. Error/cancellation closes the enclosing Native while
retaining all possibly referenced DMA, and partial gain state cannot become a
completed receipt. No packet TX queue, WPDMA, IRQ or NIC is activated.

Independent original C traces cover successful zero/A5 RFE1/5 and both cuts,
2,916 ordered BB/power/reset/RF-upload operations per case. C-rejected RFE16
profiles are rejected before partial BB programming. Original gain callbacks
cover the full default table and all signed gain/receive-offset layouts;
48 original runtime-header cases and the real Native descriptor/body model
verify page identity, automatic ACK bits, current sequence and cancellation
retention. NCTL pre-init and the real selected NCTL table match original C
separately, including a bounded fail-closed1ms handshake. `RadioTablesLoaded`
remains an intermediate prerequisite before the signed calibration continuation.

`Startup::prepare_basic_calibration` continues only that same B table owner.
The synchronous `Native::preflight_basic_rfk` stages an opaque owned plan before
the terminal hardware attempt: current device/profile/factory/protocol and signed
board/current-policy checks perform no register transition. Missing artifacts do
not consume the RF attempt. Execution consumes that plan, rebinds actual board
and assets and rechecks current authority before its first transition.
Before any calibration transition, `calibration_policy::Board` binds the actual
completed logical factory map and full128-byte PHY-cap map, corrected cut/RFE,
exact PCI/subsystem identity, selected BB/gain/RF/NCTL programs, verified whole
firmware-container digest and exact Linux RFK/coexistence recipe digests. The
registered `rtw89/rtw8852b-cal-v1-<factory-mac>.bin` must be signed. N52B v1 is
exactly96 bytes: magic/version/header/length, vendor/device, board digest at16,
MAC at48, fixed channel1/width20/WLAN-only profile at54, signed antenna gain,
board EIRP ceiling and measured calibration conducted peak at58/60/62 (quarter
dB units), then32 reserved zero bytes. It grants calibration only; no ordinary
packet, ACK or CTS power curve is inferred from an RF gain index.
The measured calibration peak plus antenna gain must fit both the signed board
ceiling and every current regulatory rule covering2402..2422MHz. Missing,
unsigned, mismatched, revoked or restrictive policy closes the continuation.
Each actual native calibration register transition invokes current device
capability and rechecks the retained qualification capability/current host policy.

The initial awake SCC profile uses real WLAN-only arbitration, without claiming
BT is absent. `coex_native::Coex` ports B's internal Realtek PTA byte/word setup,
real RFE-parity TRX masks, scoreboard ownership/1ms settle, init/control payloads,
default coex power-control disable, actual LTE-indirect WL-high/BT-low grants,
WLAN control ownership and PLT readback. Firmware0.29.29 through versions before
0.29.122 use the source TDMA3/slot1 ABI; other ABIs are rejected explicitly.
The exact OFF_BT TDMA/slot policy needs a matching successful actual C2H
DONE_ACK. CH12 consumption or receive ACK cannot supply that execution receipt;
sequences are not reused. No adaptive simultaneous-BT or PM mode is claimed.

The same retained owner then applies B's exact bb_sethw/MACID-limit prefix,
retains actual post-BB RPL offset/RSSI bases, initializes the selected NCTL
program, and executes initial RCK A/B, DRCK/ADCCK/DACK A/B and RXDCK A/B.
`rfk::Rfk` retains all measured I/Q MSBK, ADC/DAC offsets/bias and actual DPD
backoff decision; no fabricated measurement establishes completion. Source
polls are bounded and warning-only Linux timeouts instead fail closed. DACK and
RXDCK boundaries maintain the actual WLAN-only/scoreboard owner. RXDCK pauses
and restores the real firmware-owned scheduler through `scheduler_mailbox`,
including four actual H2C words, source counters and bounded firmware response.
Stale register replies, wrong identities, missing consumption or a failed actual
scheduler readback leave a terminal Pending operation. Direct CTN writes cannot
stand in for firmware scheduler ownership. A dropped Startup attempt closes
CMAC/host DMA/BME best-effort and retains all uncertain published DMA; it neither
claims RF-off nor an independent reclamation fence.

Eight independent original-C RFK traces include zero/A5 inherited fields,
low/high actual backoff and both source S1-ready branches. They compare every
BB/RF read/write, delay, ownership boundary and measured result. Four compiled
original PTA/coexistence cases, six firmware-scheduler cases and original B
bb_sethw traces independently verify packing/order/widths. Negatives cover
faults, cancellation, ignored ownership/control writes, all handshake deadlines,
stale/wrong firmware replies, signed artifact extents/identity, overlapping
regulatory restrictions and actual qualification-capability revocation before
native registers, runtime sequence or DMA publication. A full actual CH12 queue
fixture revokes qualification while its send future waits, advances the actual
hardware RP, and verifies no descriptor reuse or host doorbell publication.
Admission is fresh after waits and inside the actual current-device capability
invocation that copies the TXBD and publishes its doorbell. These remain software
proofs. `BasicCalibrated` is not complete channel RFK or station readiness:
the separately retained full channel/operating/IQK/TSSI/DPK and measured
ordinary/automatic-response continuation must complete before packet TX.

`tssi::Tracking::from_assets` selects the first retained firmware element 18,
validates its actual bitmap, signed 30-byte rows and complete lengths, and
requires B's source 2G/5G types. Only absence selects the extracted Linux B
default tracking curves; malformed present rows never select invented defaults.
`tssi::Tssi::prepare` ports the full initial PHY0/channel1/20MHz/RF_AB
`rtw8852b_tssi(hwtx=true)` sequence. It uses actual factory thermal/CCK/MCS/trim
bytes and retained post-table gain bases, all source BB tables and packed signed
thermal words, then performs both paths' real PMAC HT20-MCS7 alignment at source
power values 48/20. Native current signed qualification must cover those actual
calibration emissions. Each path pauses/restores the actual scheduler, waits for
non-TX RF modes, saves/restores actual BB/path/power state, bounds two fresh CW
report waits to 100 samples at 30us, and retains signed alignment and DE results.
Source PMAC grants/count/period and TSSI/DE controls have actual readback checks.
`configure_rx_ab` supplies the complete source initial RX-AB/NSS2, BTG, factory
gain/offset, RF-mode and MAC-selection setup; it grants no radio readiness.

`dpk::Dpk::prepare` requires that same completed TSSI owner and actual copied
Factory cut/basic DPD-backoff decision. Both paths run source RF/RXDCK, KIP/NCTL,
sync/correlation/signed-DC checks, bounded digital-gain/RXBB/TXAGC adjustment,
gain-loss/PAS, thermal sampling, IDL and coefficient programming. No unknown FEM
flag authorizes external-PA bypass. NCTL requires actual 0x55 and 0x8000 reports
under the source 20ms/2ms budgets. It preserves/restores exact BB/KIP/RF state,
TSSI tracking and scheduler ownership, and checks actual final DPD fields.
Calibration state becomes complete only after both paths and all restoration
and current admission checks succeed. Error/cancellation retains a one-shot
nonreusable owner; outer Native cleanup stops independent PMAC/NCTL engines and
retains uncertain transport mappings. These source helpers do not activate
ordinary CMAC/DMA, and they do not substitute for a complete current measured
packet/all-response power qualification.

Nine TSSI/DPK/RX-AB regressions use independently compiled unmodified Linux
callbacks: eight full TSSI/PMAC write traces, two full RX-AB traces, eight DPK
traces after the original full TSSI program, actual signed measurements and the
entire 12-bit digital-gain mapping domain. They cover erased/default/embedded
tracking, signed DE/gain/thermal arithmetic, both cuts/backoff values, pending
CW/NCTL cancellation, source deadlines, failed correlation/DC measurements,
ignored controls, operation failures and real capability-epoch revocation.
DPK refuses a stale completed NCTL_N1 byte before a trigger and verifies that
the source completion clear actually reads back zero. A causal register model
keeps ignored clears/stale ready status and ignored triggers from authorizing
another command; no stability assumption is made about NCTL_CFG itself.
Integrated full-radio/native station validation remains a separate gate.

The private `channel_rf::Channel` adds the next source-shared RF prerequisite
for fixed channel1/20MHz: A/B analog and direct RF channel/bandwidth programming,
path-A LDO preservation, bounded1us/1ms LPF readiness, exact MMD/LCK/synth recovery
and both RXBB bandwidth LUTs. It requires actual final synth lock and channel
readback, rather than treating Linux's final debug message as success. Sixteen
original-C traces cover zero/nonzero inherited RF words, each of the four lock
recovery outcomes and immediate/delayed LPF completion. Faults at every access,
cancellation, lock/LPF deadlines, ignored writes and admission denial cannot
publish `SynthConfigured` or replay the owner. Its native use is only inside the full retained channel/reset/ADC composition
under the expanded measured v2 envelope. The basic N52B calibration receipt does
not authorize this additional step.

`channel_bb::Channel` separately ports the exact B MAC0/PHY0 channel1/20MHz
core: MAC width/subcarrier/rate checks, CCK SCO/FIR, actual selected LNA/TIA
gains, factory signed gain compensation/offsets, signed RPL averages, RX width
and ADC settings, CCK/CCA and channel-index controls, 5MHz mask disable and the
source BB reset sequence. Critical actual width/channel/reset readbacks are
required. Thirty-two independent original-C traces cover both inherited seeds,
all RX-path selectors and all physical compensation/logical offset-valid
combinations, including negative odd RPL sums and signed clamp boundaries.
Access failures, dropped reset waits, ignored writes and denied admission leave
the one-attempt owner Preparing. Its native use is composed with the channel-helper ADC/scheduler owner, RF
synth and full channel RFK under the expanded measured v2 envelope. This
primitive grants no emission.

`channel_transition::Transition` retains the actual firmware-scheduler snapshot
across the source channel bracket. Entry disables PPDU, continuous TSSI and ADC,
observes the40us settling and1us reset interval, then holds reset; successful
channel programming is required before exit restores PPDU/ADC/TSSI/reset and
the saved scheduler. Actual field readbacks reject ignored transitions. Its
original B channel helper and AX PPDU C callbacks generate exact programs and
two independent inherited-state traces. Failures/cancelled waits retain the
partial bracket and reject replay; this cannot grant packet or RF readiness.

`radio_power::Plan` decodes the actual firmware byrate/2GHz limit/RU/shape
configurations with source last-matching-RFE/default selection. Missing overrides
use exact compiled B static defaults; malformed present data cannot fall back.
The fixed WW0/channel1/20 profile programs all44 byrate bytes, both complete
40-byte limit pages, both24-byte RU pages, source offsets and full flat/sharp
CCK FIR/OFDM shape, then source equal-path reference0. Signed RF2-to-MAC1 shifts
and zeroed unused page sections follow Linux. WW0 is only a concrete hardware
configuration; it supplies no country or physical power authority. Eight
original-C power traces cover both inherited seeds, negative source units and
both FIR branches. RFE override/legacy zero-extension/invalid-data and each
access/ignored-control/admission regression keep partial preparation terminal.
A signed measured full-recipe envelope still precedes native use and must cover
calibration PMAC, ordinary TX-A and all reachable automatic response paths/rates.

`radio_trim::Trim` applies only the retained real physical thermal and PA-bias
bytes, preserving Linux's whole-map programmed/erased interpretation. Each RF
trim write requires actual field readback; four original-C flag combinations
and access/cancel/ignored-control/admission negatives reject partial completion.
It requires the expanded measured recipe and provides no bypass or power grant.

`Native::qualification_request(assets, full)` returns read-only version/MAC/
digest metadata and its canonical signed-artifact name from the actual retained
factory, verified assets and firmware PHY topology. The full request includes
the actual selected source power plan. Both forms run inside current device
invocation and perform no artifact lookup, register transition or state advance.
They grant neither authority nor readiness. A native RAM/real-epoch regression
checks unchanged registers/owners and revocation before metadata derivation.

`Native::preflight_full_radio` stages actual selected power/tracking inputs and
loads `rtw89/rtw8852b-radio-v2-<factory-mac>.bin` before the next terminal hardware
attempt. N52B v2 is exactly128 bytes: the common vendor/device/board-digest/MAC
fields remain at12/14/16/48, version/header bytes are2/128, profile54..58 is
channel1/20MHz/TX-A/RX-AB (`1,20,1,3`), signed antenna gain and board EIRP ceiling
are at58/60, and separate measured conducted maxima for the complete calibration
recipe, ordinary packets and every reachable automatic response path/rate are
at62/64/66 (quarter-dB units). Bytes68..128 must be zero. All three peaks plus
the signed maximum antenna gain must fit the board ceiling and every current
host rule over2402..2422MHz. WW0 source tables do not supply country authority.
Old v1 cannot authorize this continuation. The v2 board digest additionally
binds the actual firmware PHY_CAP reply, all channel/operating/IQK/TSSI/DPK/full
composition recipes, exact selected source power units and the station CCTL/DCF
profile. The basic v1 digest now also binds the static operating recipe, so a
qualification for its earlier recipe cannot be reused.

`radio_full::Radio` retains the actual trim, channel bracket/MAC/BB/RF, source
power pages, fresh channel RXDCK, IQK, TSSI with actual PMAC alignment and DPK
owners. It preserves30ms before each TSSI/DPK without assuming Bluetooth is
absent. Three composed model smokes execute every real component on the same
BB/RF allocation, with causal synth/NCTL/CW/DPK measurements and current actual
capability invocations. They cover full completion, component/access/policy/
revocation failures and cancellation inside real published PMAC/CW work. Partial
owners reject replay; ordinary CMAC TX and ordinary host DMA stay closed.

`Native::prepare_full_radio` rebinds the staged plan to that same actual factory,
selected immutable assets, firmware PHY topology, completed static operating
owner and retained basic measurements. It installs the full qualification before
any expanded transition. Only complete actual radio owners, the source B fresh
MCC-channel notification and fresh final authority can construct its private
ordinary grant. Native BB/analog transactions and final command/ordinary
publication remain inside the actual signed qualification capability invocation
as well as the current device invocation; policy sampling alone grants no later
MMIO. Closing uses current device authority independently of a revoked emission
grant and retains every uncertain DMA mapping. These are software proofs;
physical RF/link/DHCP validation still requires the exact real board assets.

The source-shared `radio_stop` controls cover both PMAC modes/manual routing,
RFCTM and NCTL closing fields, followed by B's exact AFC_AFEDIG clock gate and
BB reset prefix. Independent original-C callbacks/statements verify both
inherited register seeds and actual write widths/order. The finite synchronous
helpers continue independent closing operations after an error and require
readback; ignored writes cannot claim successful closure. Native latches radio
preparation before the first possible BB/RF write. Its terminal/Drop path stops
those independent engine controls after closing CMAC/host DMA/BME, then gates
B clocks and asserts BB resets through current device capability. Actual native
RAM/command-DMA tests verify both revoked-before-access and live closing writes,
while retaining every uncertain ring/packet. This does not perform the remaining
asynchronous XTAL RF00S/RF10S shutdown by itself, claim RF-off or permit DMA
reclamation. `Native::finish_radio_shutdown` supplies the retained asynchronous
continuation while preserving the terminal Native and all uncertain DMA. It
serializes actual XTAL idle/commands with50us/50ms budgets, disables RF00S/RF10S
through the exact AX read/write callbacks, then checks both actual final fields.
Wrong command echoes, ignored writes, busy deadlines, errors and cancellation
leave Stopping and reject replay. ShutdownAcknowledged is neither RF/DMA idle
nor reset/reclamation authority. Four original-C shutdown cases and actual
Native register-command/current-cap/DMA-retention fixtures cover this path.

This cold/WCPU path still requires an independently established old-DMA fence
and exclusive function claim: BME-off, MAC-OFF and these retained receipts do
not establish reclamation. It is private and does not run in the diagnostic
probe, enable MSI/IRQ delivery or register a network interface. Only its explicit
B receive continuation publishes RX rings.
A/51 programmed secure boot still needs authenticated board blacklist-policy
loading; B/C retain Linux's version0 policy. B's retained MAC sys/TRX preparation
does not complete other AX profiles. Initial B's retained full radio path is
separate from this cold/WCPU receipt; it requires actual firmware PHY topology,
static operating state and the signed measured v2 continuation. Physical
Wi-Fi acceptance still requires the exact real board/assets and link/IP tests.

`efuse::read_mac(registers, ChipId, cut)` runs the AX DDV read lifecycle and
decodes the two-byte sparse records. All four AX profiles use a 1216-byte
physical map with four-byte security prefixes/tails. Logical size is 1536 on
8852A and 2048 on the other AX profiles; PCI MAC is at logical `0x400`.
Offsets were independently checked with C `offsetof` using Linux's structs.

8852A selects/verifies Wi-Fi bank zero. Other AX profiles configure DDV power
cut and undo it after success or timeout; 8852B cut A additionally enables and
clears burst mode. Invalid maps/identities fail explicitly. RTL8922A is
rejected before applying the incompatible AX EFUSE/power sequence.

`phy_operating::Operating` supplies B's initial static receive/carrier-sense
continuation after BB tables/`bb_sethw` and before NCTL/basic RFK. Its separate
current-authority adapter does not pretend NCTL is already initialized. Source
PHY-status bitmaps, disabled initial DIG PD/PAGC-follow state, actual factory
XO/XI programming/readback, CFO compensation and EDCCA collision timing are
programmed with masked readbacks. The corrected factory cut controls B's CCK-PD
branch; crystal values retain the factory value masked exactly as Linux does.
Working state records those actual cut/RFE/crystal facts and is published only
after every transition succeeds. Failure/cancellation is terminal and cannot
replay. A generated source/register/table recipe digest enters board policy.
Twenty-four original-C cases cover seeded registers, corrected cuts and crystal
values; negative models cover every current-admission frontier, ignored MMIO
or XO/XI writes and cancellation at an actual analog request.

B has no source `rfe_gpio` or AX BB-wrap callback, and the admitted two-path
profile does not enable antenna diversity. Unsupported-IGI gain-table writes
are skipped by the actual B source branch. Monitor/NHM diagnostics and periodic
DIG/CFO/EDCCA/antenna tracking are separate from this static working owner; they
are not reported as completed by its successful state.

`firmware_phycap::Receipt` records actual firmware GET_FEATURE PHY capabilities,
separately from EFUSE PHY calibration bytes. RTL8852B follows the AX source
part0 query (`0x103` header, zero content bytes); Linux explicitly skips part1
for AX. The retained scheduler register mailbox owns the same H2C/C2H counters
through this query and later scheduler operations. A reply is accepted only
after fresh ready/trigger/consumption transitions, exact PHY_CAP function and
all four words; AX has no documented H2CREG sequence-echo contract to invent.
Stale ready state before or after a wait, incomplete/foreign replies, missing
consumption/clear, revoked capability, close, timeout or cancellation leave the
mailbox pending and the native attempt terminal. The native query guard retains
that mailbox and its counters even when the future is dropped.

`Native::query_firmware_phycap()` runs once before BB/RF tables or calibration.
`phy_profile_current()` requires the immutable receipt and current actual PCI
capability. The initial full RF-AB calibration / TX-A / RX-AB profile admits
only two-stream firmware defaults or explicit NSS2 and antenna defaults/AB;
zero fields retain Linux's actual B chip defaults. RF-B-only, path-diversity,
NSS1 and reserved raw topologies are refused before any radio table access.
All actual words are retained and their capability fingerprint enters full
board qualification; this receipt alone supplies no wiring, calibration or
power authority. Independently compiled original-C transport/decoder fixtures
cover 512 topology/seed cases and shared scheduler-counter continuation.

`iqk::Iqk` owns the complete one-shot RTL8852B initial PHY0/channel1/20MHz,
non-DBCC RF-AB wideband IQK sequence. A full measured RF/coexistence/current
policy adapter, binding the source algorithm/register/table `RECIPE` digest,
is required before its first access and every later register,
RF or delay transition; the basic-RFK grant cannot authorize it. Source outer
and per-path coexistence events enclose scheduler pause/RX-mode checks, exact
AFE setup, up to three LO-bias attempts, all four TX and RX groups, result
capture and each path's three BB/eleven RF backup restoration. Real NCTL
completion polls are bounded to 8200us, RX-mode waits to 5000us. Source LO
core/vbuffer bounds, failure flags and restore completion determine readiness;
failed VBUFFER/restore shots also close the initial owner. Stable AFE table,
restored BB and source NCTL completion-clear readbacks reject unaccepted writes;
the command register has no assumed stability or trigger-bit semantics. The
state becomes failed before any await, so cancellation, timeout, current
restriction or malformed result cannot replay or publish calibrated results.
The owner exposes retained diagnostics separately from successful results.
Eighteen independently compiled original-C traces cover seeded registers,
LO retry success/failure, dynamic coarse/TX/RX/VBUFFER/restore flags and delayed
NCTL completion; additional models cover stuck polls, ignored writes, current
restriction and cancellation. Native full-recipe wiring, measured signed
board qualification and physical calibration validation remain separate gates.

`station_control::Controller` retains one RTL8852B MAC0/PHY0, port0/MACID0
station identity from the completed `Factory`; callers cannot construct a peer
binding from a MAC address alone. Its register adapter invokes current device
and ordinary-power authority around the whole transaction, while its command
adapter rechecks admission after waits and encloses final native publication.
The source nonsecure default DMAC/CCTL initialization requires the complete
indirect aperture through `0x4001f`, checked before any station write. An actual
secure-fuse profile uses Linux's explicit indirect-write skip. Source port0
NoLink, MACID unpause, role creation, disconnected join, address/BSSID CAM,
default/fixed CCTL and non-QoS EDCA establish only a prepared station control
owner. They never enable global CMAC TX, WPDMA, packet queues or interrupts.
Before prepared/associated publication, the source awake predicates require
`LDM.EN_32K` clear and MACID0's firmware power-state nibble (`0xca0c & 0xe`)
clear under the current transaction. `station_control::awake()` exposes those
two reads to the actual packet adapter without taking another admission lock.
The fresh FLR/cold-WCPU profile never requests LPS, RPWM power transitions or
WoW keepalive; an observed sleeping state terminalizes instead of synthesizing
a wake receipt. Initial and post-join negative models cover every source PS
bit and distinguish unrelated power/MACID bits.

AXB address CAM v0 carries the actual source/peer addresses, exact hashes,
BSSID match, MACID/port and checked AID. Every security-entry valid bit remains
zero. Global TX encryption/hardware decryption and MIC/ICV appending are
explicitly disabled and read back for original host CCMP MPDUs. The fixed
legacy profile uses source TX-A CCTL path selection, CCK1/20MHz and disabled
data/RTS fallback, with no WMM/HT claims. Source EDCA commands use non-QoS
TXOP0, CWmin31/CWmax1023 and AIFSN2; actual negotiated long/short slot yields
50/28us AIFS. `profile_fingerprint()` binds these exact CCTL/EDCA/software-crypto
choices for the independent ordinary RF/automatic-response grant. CCTL TX-A
alone does not restrict autonomous ACK/CTS paths or authorize their power.

Role, join, CAM, CCTL and EDCA commands require actual identity/sequence-matched
successful firmware DONE_ACK. TXBD consumption and receive ACK cannot supply
that receipt. The source AX MACID-pause command requests receive ACK only;
its transport completion is not presented as firmware execution. Initial
unpause and terminal pause additionally require the actual MACID0 scheduler
bitmap at `0x9eb0` to reach the requested state within 10ms, with current
authority and admission checked on every read and no lock held across delays.
An applied-bit timeout closes the one-shot owner before role creation or a
stopped-state receipt. A pre-auth
peer token becomes current only after the actual CAM execution receipt, and
the same token binds later association/EAPOL/data. Checked peer/AID commit
updates source CCTL, media and CAM state before managed port publication.
Disconnect invalidates the token before its first awaited cleanup command.
The shared admission/publication lock and owned teardown reservation preserve
terminal cleanup access without reopening a cancelled or failed peer. Every
future failure/cancellation is one-shot; a late completion or fresh admission
cannot replay or revive that owner. These controls remain prerequisites to
the enclosing retained packet/station/Device composition and physical tests.

Compiled original Linux CAM/role/join/CCTL/EDCA helpers and default table writes
independently fix serialized bytes and indirect register order. Control models
earn their factory through actual sparse-DDV decoding, invoke real capability
epochs around whole MMIO operations, and parse raw modeled C2H acknowledgements.
The actual native control adapter also encloses the complete register operation
in the retained signed RF invocation. A revocation between an earlier successful
sample and that invocation prevents every control write; current-device cleanup
still closes ordinary TX/DMA and retains uncertain command mappings.
They cover missing/receive-only/foreign/failed execution receipts, readback
failures, short aperture, actual secure branch, cancellation, admission rebinding
and authority loss before command publication. They supply no physical RF grant.

`tx_transport::prepare_header(chip, info, sequence, frame_dma, frame)` prepares
AX PCI body/WP/address-info records for an initial non-QoS, three-address native
profile. Only 8852B additionally admits already encrypted host CCMP To-DS data
with complete IV/ciphertext/MIC extents, reserved/ExtIV/PN validation and hardware
encryption/IV insertion disabled. Protected management, QoS, fragmentation and
optional headers remain rejected. It rejects unsupported BE, wrong QSEL/channel
and address extents outside the 36-bit 8852B/8852C device mask or 40-bit other AX
baseline. Descriptor encoding capacity does not grant DMA address authority.
Baseline uses a 24-byte body and eight-byte
address info; 8852C uses a 32-byte body and six-byte segments of at most 2044
bytes. TXBD length covers only the descriptor header, never the native payload.
The body-only legacy `datapath::stage_tx` codec is not a PCI submission.

`TxQueue<T>` owns at most the configured ring depth (2..512), reserves a slot,
retains before publication, and transfers ownership only after both TXBD
consumption and an identity-matched AX RPQ release. Stale/contradictory records
and invalid read-pointer movement are explicit errors. Unpublished reservations
can be aborted. Drop cannot prove device quiescence and conservatively retains
outstanding published resources; reset/removal reclamation remains required.

The private `packet_core::Core::{prepare,start,ready,submit,poll,stop}` supplies
the bounded initial RTL8852B channel 1/20 MHz packet owner. Preparation allocates
fresh 256-slot BE0 and MGMT8 TXBD rings using the actual chip address set; it
requires both channels/WPDMA stopped and CMAC TX closed. It retains both maps
before their first base write and verifies programmed bases/counts. It never
borrows diagnostic rings. A whole-operation `Port::current` invokes the same
currently valid BusDevice capability around actual DMA copies, cache ownership,
fences and register accesses. Start and every packet publication require an
opaque retained ordinary RF/channel/power/all-response-rate receipt; basic
calibration or allocated DMA cannot grant that authority. Publication additionally
requires the current acknowledged station-control Peer token before allocation
and immediately before the first BD write. Passive RX and H2C acknowledgement
polling remain independent of a peer token.

`packet_format` supplies the exact AXB 24-byte body + 24-byte WD-info + 8-byte WP
+ 8-byte address-info header, with a separate native MPDU mapping. TXBD length
is 64, references that header only and enforces complete 36-bit extents for both
maps. The retained initial profile uses MACID 0/port 0, BE0/QSEL0 for data,
MGMT8/QSEL0x12 for management, fixed CCK1/20 MHz and source no-fallback mode;
hardware security/IV insertion and aggregation remain off. All automatic
RTS/CTS/ACK response rates still require the RF owner's qualification.

One packet may be outstanding across these queues. `TxQueue<owned packet>`
retains header/body before the first descriptor write, and a terminal receipt
requires BOTH actual upper TXBD read-pointer progress and an exact
sequence/channel/QSEL/MACID RPQ release with successful status. Same-status
duplicates, stale identities, invalid pointer movement and a 1s packet deadline
terminally close the claim. Receipt bytes are acquired from the retained DMA
body after terminal ownership, enabling exact EAPOL delivery matching. RPQ
success is terminal host delivery; no extra AP acknowledgement gate is added.
Each queue permits 512 nonreused WD-page identities for this bounded initial
hardware-validation claim, then closes before an unsupported/reused identity
can be published. This profile does not claim sustained service. Stop/error
attempts verified ordinary DMA/CMAC closure under current authority and retains
all published mappings; neither stop nor drop infers quiescence or reconstructs
an owner. Buffered native RX events must drain before an actual RXQ/RPQ-idle
observation can be reported.

Seven packet-format/owner regressions include literal fixtures produced by
compiling unmodified Linux AX body/info and PCI address-info functions, and a
reactive device model that follows actual programmed TXBD bases, descriptor,
header and native-body DMA. They cover both completion orders, DMA-read receipt
bytes, wrong/duplicate/stale/failed releases, impossible pointers, revoked
current epochs, late peer/RF closure, uncertain doorbells, stop retention and the
512-identity boundary. These tests supply software ownership/layout evidence;
the Native RF-gate/packet adapter and station/security/DHCP composition must
still be connected and tested before this profile grants usable NIC readiness.

The retained device backend `submit_native` and `complete_native_report` are
private unsafe integration points with an explicit initialized/live-ring and
no-reset contract. They allocate masked DMA, retain header plus payload, perform
cache maintenance and order publication before the doorbell. They have no
station/firmware producer or RPQ pump caller yet. The registered Ethernet
`pci::send_frame` rejects before allocation or MMIO until those owners and
Ethernet-to-native encapsulation exist.

## 4. Invariants

Physical reads write the address and wait for the hardware ready flag before
consuming data. Bounds exclude security control bytes. Missing logical words
remain erased and later records override earlier words. Failures cannot leak
EFUSE power-cut/write-mask/burst settings. TXBD consumption alone cannot free
a packet still referenced by firmware. A report alone cannot recycle a BD still
referenced by DMA. Ring wrap cannot overwrite either retained allocation.

## 5. Architecture notes

EFUSE/register-model tests run on both architecture builds. PCIe DMA/address
width, device ordering and completion lifetime require independent qualification.

## 6. Dependencies

`narf-bus` provides Device BAR mappings, scheduler/time provide responsive
bounded waits, and the firmware registry will supply authenticated images.

## 7. Stage assignment

AX identity is software covered. Existing packet descriptor/ring code is
bring-up scaffolding and does not establish a working station runtime.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| AX DDV factory identity and cleanup | Implemented; shared-path regressions |
| Initial B power/PCIe initialization | Retained actual cold/firmware/MAC/RX/full-radio/ordinary BE/MGMT startup and probe integration implemented; selective source PCI setup is bounded to this awake polled profile |
| Firmware container/profile selection, CH12 DMA, WCPU handshakes | Checked AX selection, native fuse reads, coupled secure plans, native CH12 ownership and retained WCPU loading implemented; owned cold-to-CH12/WCPU composition and TX-only BME activation implemented; initial B packet/RF startup is implemented; A/51 secure-policy loading remains outside the initial profile |
| Initial B reset, rings and ownership | Actual temporal FLR or explicit trusted platform reset contract; retained BDRAM/CH12/RX/RPQ plus fresh BE/MGMT rings and terminal storage ownership implemented. IRQ delivery, recovery and reclamation remain separate |
| Initial B native TX and bounded completion | Exact source TXWD/BD/WP/address-info and joint TXBD/RPQ retirement are activated by the same retained station owner;512 nonreused identities per queue |
| RPQ release handling, RX assembly/validation and frame delivery | B retained native RXQ/RPQ publication/polling, checked segmented RX/FCS, RPQ records and bounded C2H/ACK decoding implemented; same-owner packet completion dispatch, raw station frame delivery and kernel DHCP/IP are implemented |
| RF/BB calibration, regulatory channel/power and coexistence | Initial B actual factory + firmware PHY_CAP, static PHY operating/XTAL, WLAN-only coexistence, NCTL/basic RFK, channel MAC/BB/RF/scheduler/ADC, actual trims/RXAB, IQK/TSSI/DPK and real source power-table composition implemented. Separate signed measured v2 binds all calibration/packet/autonomous-response peaks and actual source recipes; native publication uses current signed/device invocations. Broader AX/BE profiles, host periodic RF tracking/retuning and physical measured qualification remain outside this initial profile |
| Initial B scan, MLME, WPA2 and Ethernet | Source controller plus shared host MLME/RSNA/CCMP, exact M4/RX-idle admission, kernel DHCP/IP, rekey and terminal disconnect/cancellation are implemented; physical acceptance remains |
| BE EFUSE/block format and BE transport | Missing |
| Broader lifecycle | Initial independent reset and terminal ownership implemented; removal, suspend, automatic reset/rejoin and multiple live functions remain outside this first profile |

References: Linux `rtw89/efuse.c`, `rtw8852a.h`, `rtw8852b_common.h`,
`rtw8852c.h`, `rtw8851b.h`, `core.c::rtw89_core_get_ch_dma`,
`pci.c::{rtw89_pci_txwd_submit,rtw89_pci_release_txwd_skb,rtw89_pci_fill_txaddr_info,rtw89_pci_fill_txaddr_info_v1}`,
and per-chip PCI configuration.
