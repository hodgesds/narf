# rtw89 — Specification

> Status: AX factory identity, checked firmware preparation, native cold-power
> primitives, composed cold discovery/CH12/WCPU startup and bounded native TX
> ownership are implemented. Packet/RF/station startup remains incomplete.

## 1. Purpose & scope

Owns RTL8852A/B/C, RTL8851B and planned RTL8922A PCIe support. Current live
identity code implements AX DDV EFUSE; BE has a different read/block layout.

## 2. Assumptions

The diagnostic caller owns BAR2, mapped with Device attributes and covering the
register window. The private cold claim instead parks PCI DMA, maps BAR2 and
reads the actual chip cut itself. The diagnostic probe still uses its existing
power prologue; the composed cold/WCPU path does not replace it until packet,
RF and complete startup prerequisites are implemented. No factory-MAC result establishes station readiness.

## 3. Public interface

`pci::bring_up(device, cap)` first parks inherited PCI DMA through the shared
Realtek command policy: clear `BUS_MASTER`, enable `MEM_SPACE | INTX_DISABLE`,
and read back the command register. Any access failure, retained BME or missing
requested decoding fails before BAR mapping. Bus mastering remains disabled
on success and every later error; identity and ring allocation do not authorize
DMA. A repeat probe of the retained bus address returns without configuration access; a distinct additional singleton match parks only its own PCI function. Re-enabling
BME requires the composed owned cold/firmware-download path or a future
complete packet/ring/reset owner.
The complete diagnostic mapping/power/identity operation runs within actual
capability invocation. It retains unpublished storage, with no ring base/index
publication, enabled MSI-X delivery, RX pump or network-interface registration.
The private native TX/report hooks also invoke the retained device capability;
revocation returns `Authority` before register access or packet allocation.

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
system-memory ring publication. The diagnostic probe still does not call it.
Linux-C traces cover the four AX profiles and nonzero inherited register fields;
negative models cover every access failure, ignored writes, dirty indices,
device disappearance, both wait deadlines, cancellation and actual revocation.
This closes internal partition/index and PCIe MAC-pre-init preparation only:
full post-firmware MAC/RF startup, RX and IRQ ownership remain required, and Ready is neither a DMA-reclamation nor station proof.

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
this backend, while the diagnostic probe keeps it inactive until complete
post-firmware MAC/RF and packet/station startup is implemented.

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
Post-firmware MAC/RF startup and packet/station ownership remain open.

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
channel MAC/BB/RF setup, IQK/TSSI/DPK, trims/TRX/CCA and ordinary/automatic-response
power authorization still precede packet TX and a usable radio.

The private `channel_rf::Channel` adds the next source-shared RF prerequisite
for fixed channel1/20MHz: A/B analog and direct RF channel/bandwidth programming,
path-A LDO preservation, bounded1us/1ms LPF readiness, exact MMD/LCK/synth recovery
and both RXBB bandwidth LUTs. It requires actual final synth lock and channel
readback, rather than treating Linux's final debug message as success. Sixteen
original-C traces cover zero/nonzero inherited RF words, each of the four lock
recovery outcomes and immediate/delayed LPF completion. Faults at every access,
cancellation, lock/LPF deadlines, ignored writes and admission denial cannot
publish `SynthConfigured` or replay the owner. It has no native startup caller:
full BB/MAC channel/reset/ADC composition and a measured envelope explicitly
covering this LCK recipe must precede its native use. The basic N52B calibration
receipt does not authorize this additional step.

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
asynchronous XTAL RF00S/RF10S shutdown, claim RF-off or permit DMA reclamation;
that retained stop ownership still precedes later emitting engines.

This cold/WCPU path still requires an independently established old-DMA fence
and exclusive function claim: BME-off, MAC-OFF and these retained receipts do
not establish reclamation. It is private and does not run in the diagnostic
probe, enable MSI/IRQ delivery or register a network interface. Only its explicit
B receive continuation publishes RX rings.
A/51 programmed secure boot still needs authenticated board blacklist-policy
loading; B/C retain Linux's version0 policy. B's retained MAC sys/TRX preparation
does not complete other AX profiles. Native packet TX/RPQ completion composition,
remaining channel/RF calibration and ordinary/response power policy, and
station/IP composition remain prerequisites before physical Wi-Fi acceptance.

`efuse::read_mac(registers, ChipId, cut)` runs the AX DDV read lifecycle and
decodes the two-byte sparse records. All four AX profiles use a 1216-byte
physical map with four-byte security prefixes/tails. Logical size is 1536 on
8852A and 2048 on the other AX profiles; PCI MAC is at logical `0x400`.
Offsets were independently checked with C `offsetof` using Linux's structs.

8852A selects/verifies Wi-Fi bank zero. Other AX profiles configure DDV power
cut and undo it after success or timeout; 8852B cut A additionally enables and
clears burst mode. Invalid maps/identities fail explicitly. RTL8922A is
rejected before applying the incompatible AX EFUSE/power sequence.

`tx_transport::prepare_header(chip, info, sequence, frame_dma, frame)` prepares
AX PCI body/WP/address-info records for an initial unprotected, non-QoS,
three-address native profile. It rejects unsupported BE, wrong QSEL/channel,
fragmentation, optional headers, and address extents outside the 40-bit baseline
or 36-bit 8852C address format. Baseline uses a 24-byte body and eight-byte
address info; 8852C uses a 32-byte body and six-byte segments of at most 2044
bytes. TXBD length covers only the descriptor header, never the native payload.
The body-only legacy `datapath::stage_tx` codec is not a PCI submission.

`TxQueue<T>` owns at most the configured ring depth (2..512), reserves a slot,
retains before publication, and transfers ownership only after both TXBD
consumption and an identity-matched AX RPQ release. Stale/contradictory records
and invalid read-pointer movement are explicit errors. Unpublished reservations
can be aborted. Drop cannot prove device quiescence and conservatively retains
outstanding published resources; reset/removal reclamation remains required.

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
| Complete per-chip power/PCIe initialization | Native power-on/off, inherited-state normalization, DLFW DLE/HFC and internal BDRAM/index setup, AX PCIe pre-init/basic_cfg and actual qualified cold-to-WCPU composition implemented; B-only SCC MAC system/TRX plus selective LTR/address-info/RX continuation added with original-C evidence; packet TX/WPDMA/full PCI post-init, RF startup and probe integration remain |
| Firmware container/profile selection, CH12 DMA, WCPU handshakes | Checked AX selection, native fuse reads, coupled secure plans, native CH12 ownership and retained WCPU loading implemented; owned cold-to-CH12/WCPU composition and TX-only BME activation implemented; full packet/RF startup and A/51 secure-policy loading remain |
| Ring quiesce/publication, BDRAM setup, IRQ ownership and recovery | Internal BDRAM partition/reset and actual zero-index readback implemented; independent old-DMA fencing, full ring/IRQ ownership and recovery remain |
| AX initial native TX layout and bounded completion ownership | Shared production backend implemented and model-tested; not yet activated by station/firmware owner |
| RPQ release handling, RX assembly/validation and frame delivery | B retained native RXQ/RPQ publication/polling, checked segmented RX/FCS, RPQ records and bounded C2H/ACK decoding implemented; packet-TX completion dispatch and station frame delivery remain |
| RF/BB calibration, regulatory channel/power and coexistence | B actual PHY-cap/logical calibration, full-aperture RF-v1 access, verified embedded/static table selection and retained BB/gain/reset/power-unit/RF-page execution implemented; bounded NCTL/table primitive proved separately. Complete native DM/coexistence/NCTL/RFK composition and policy-qualified channel/power remain |
| Scan, real management MLME, WPA2 keys/controlled port, Ethernet data | Missing |
| BE EFUSE/block format and BE transport | Missing |
| Reset/removal/suspend and multi-device lifetime | Missing |

References: Linux `rtw89/efuse.c`, `rtw8852a.h`, `rtw8852b_common.h`,
`rtw8852c.h`, `rtw8851b.h`, `core.c::rtw89_core_get_ch_dma`,
`pci.c::{rtw89_pci_txwd_submit,rtw89_pci_release_txwd_skb,rtw89_pci_fill_txaddr_info,rtw89_pci_fill_txaddr_info_v1}`,
and per-chip PCI configuration.
