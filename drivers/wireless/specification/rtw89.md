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

For `10ec:b852`/`10ec:b85b`, `pci::probe` reserves its exact BDF before parking
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
shutdown. Stop bits, revoked authority and successful source RF shutdown are
not DMA-reclamation receipts; only the DMA-stop proof below frees storage.

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
already held exclusive function reservation, but makes no assumption that
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
owner. The original function reservation remains retained throughout the
reset, cancellation and Startup handoff. A dropped/failed attempt is terminal
and cannot be replayed or release that reservation. The existing unsafe cold
claim remains only for a genuinely independently fenced platform power/PERST
contract; an automatic probe cannot invent that fact from a static board ID.

Six native Rust reset regressions use frozen pending/FLR timing references
citing Linux `drivers/pci/pci.c` and exercise the actual config state machine with
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
Frozen reference traces cover all four AX profiles and nonzero inherited fields;
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
retry requires a separate complete fenced reset. Frozen reference comparisons cover
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
control. 8852C uses its V1 HFC register page. Frozen reference traces cover
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
requires an independently verified reset. Frozen reference traces cover
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
Frozen reference traces cover all four AX profiles, both cuts,
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
non-reusable owner. Forty frozen reference cases cover all AX profiles, both link speeds, inherited zero/nonzero fields, calibrated versus
uncalibrated C and host PM enabled/disabled. Fault/cancellation at every access,
malformed capability lists and ignored control writes keep preparation closed.

`factory::Factory` commits a complete actual DDV snapshot only after the
1216-byte physical map, autoload-valid bit and physical0x5e9..0x5ed controls
have been read successfully. It decodes factory MAC, logical RFE/XTAL/country,
B's real power-k marker and secure fuse selection; fixed layout references
from the Linux chip headers retain all four AX field offsets. ECV must
agree with the corrected 8851B cut. No I/O error becomes erased fuse/calibration
defaults. Unknown/failed/cancelled snapshots expose no identity and reject reuse.
8852B additionally reads the complete separate physical PHY-cap window
`0x580..0x5ff`; its control bytes supply the same power-k/secure decisions.
The retained raw map and logical snapshot feed `factory_b::Calibration`'s exact
TSSI groups, signed RX-gain offsets/compensation and thermal/PA-bias trims.
Only a completed native read permits Linux's explicit erased-map interpretation;
partial I/O never produces trim defaults. Frozen packed-layout references and
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
This is the single explicit gate adaptation to the Linux source MAC write stream;
readback requires TXEN clear, and later measured response/channel authorization
must precede enabling it. Native failure closes this gate independently of DMA.

Four frozen reference traces cover B register widths, values and ordering with
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

Frozen source-derived references retain48 RXD layouts,
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
actual busy.48 frozen callback reference traces cover both paths,
analog/direct, zero/A5 inherited fields and full/sparse masks. Tests cover each
access failure and cancellation point, all busy/done deadlines, invalid paths,
the actual native aperture and revoked authority. `radio_tables_b` retains the
actual B BB1,013, gain66, RF-A8,295, RF-B8,392 and NCTL1,320 pair entries.
`radio_table::program` validates/selects the entire immutable program before
its first device write, preserving exact/wildcard/max-cut headline ordering
and conditional branch selection.160 frozen selector reference cases
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
element never falls back to invented static data. Frozen packed-layout
references cite the original `fw.h` definitions.

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

Frozen reference traces cover successful zero/A5 RFE1/5 and both cuts,
2,916 ordered BB/power/reset/RF-upload operations per case. Unsupported RFE16
profiles are rejected before partial BB programming. Original gain callbacks
cover the full default table and all signed gain/receive-offset layouts;
48 original runtime-header cases and the real Native descriptor/body model
verify page identity, automatic ACK bits, current sequence and cancellation
retention. NCTL pre-init and the selected NCTL table have separate frozen
reference coverage, including a bounded fail-closed1ms handshake.
`RadioTablesLoaded` remains an intermediate prerequisite before the signed calibration continuation.

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

Eight frozen RFK reference traces include zero/A5 inherited fields,
low/high actual backoff and both source S1-ready branches. They compare every
BB/RF read/write, delay, ownership boundary and modeled measurement result.
Four frozen PTA/coexistence cases, six firmware-scheduler cases and B bb_sethw
reference traces check packing/order/widths. Negatives cover faults, cancellation, ignored ownership/control writes, all handshake deadlines,
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

Nine native Rust TSSI/DPK/RX-AB regressions retain frozen source-derived
reference traces: eight full TSSI/PMAC traces, two RX-AB traces, eight DPK
traces after the original full TSSI program, modeled signed measurements and the
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
frozen reference traces cover zero/nonzero inherited RF words, all four lock
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
required. Thirty-two frozen reference traces cover both inherited seeds,
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
use fixed B static default tables; malformed present data cannot fall back.
The fixed WW0/channel1/20 profile programs all44 byrate bytes, both complete
40-byte limit pages, both24-byte RU pages, source offsets and full flat/sharp
CCK FIR/OFDM shape, then source equal-path reference0. Signed RF2-to-MAC1 shifts
and zeroed unused page sections follow Linux. WW0 is only a concrete hardware
configuration; it supplies no country or physical power authority. Eight frozen
power reference traces citing `rtw8852b.c` cover both inherited seeds, negative
source units and both FIR branches. RFE override/legacy zero-extension/invalid-data and each
access/ignored-control/admission regression keep partial preparation terminal.
A signed measured full-recipe envelope still precedes native use and must cover
calibration PMAC, ordinary TX-A and all reachable automatic response paths/rates.

`radio_trim::Trim` applies only the retained real physical thermal and PA-bias
bytes, preserving Linux's whole-map programmed/erased interpretation. Each RF
trim write requires actual field readback. Four frozen flag-combination references
from `rtw8852b_rfk.c`, alongside access/cancel/ignored-control/admission negatives,
reject partial completion.
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
BB reset prefix. Frozen source references from `rtw8852b.c` and
`rtw8852b_rfk.c` check both inherited register seeds and write widths/order. The finite synchronous
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
nor reset/reclamation authority. Four frozen shutdown references citing
`rtw8852b.c`, alongside Native register-command/current-cap/DMA-retention fixtures,
cover this path.

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
replay. A fixed source/register/table recipe digest enters board policy.
Twenty-four frozen references citing `rtw8852b.c` cover seeded registers,
corrected cuts and crystal values; negative models cover every current-admission frontier, ignored MMIO
or XO/XI writes and cancellation at an actual analog request.

B has no source `rfe_gpio` or AX BB-wrap callback, and the admitted two-path
profile does not enable antenna diversity. Unsupported-IGI gain-table writes
are skipped by the actual B source branch. Monitor diagnostics and periodic
antenna tracking (RTL8851B only) are separate from this static working owner; they
are not reported as completed by its successful state.

**Periodic track work** (`track.rs`) follows `rtw89_track_work` in Linux
order: traffic statistics, environment monitor, DIG, CFO, EDCCA. It runs in
the station's async worker pass (`apply_async`) so XTAL SI writes can await.
Its first period performs the
`rtw89_core_start` half: PPDU status reports (`rtw89_mac_cfg_ppdu_status_ax`:
`R_AX_PPDU_STAT` RPT_EN/MAC_INFO/PLCP/CRC32, `R_AX_HW_RPT_FWD` to host) and
`rtw89_phy_env_monitor_init` (CCX enable/trigger option, EDCCA BW20 option,
IFS-CLM collect and T1–T4 thresholds 64/256/1024/4096 µs at the 32 µs unit).
Each period then runs `__rtw89_phy_env_monitor_track` for the background
IFS-CLM only (collect CCK/OFDM false alarms when `R_IFSCNT` reports done,
convert with `rtw89_phy_ccx_get_report` to per-mille, program the 1900 ms
period/unit once, pulse clear and measurement trigger) and `__rtw89_phy_dig`
for 2.4 GHz/20 MHz: B has `support_igi = false`, so no gain-code writes;
link transitions reseed `igi_fa_rssi` and switch `fa_th_2g`/`fa_th_nolink`;
the false-alarm noise level adjusts `fa_rssi_ofst`
(`rtw89_phy_dig_igi_offset_by_env`), `rtw89_phy_cal_igi_fa_rssi` clamps to
the dynamic IGI window, and `rtw89_phy_dig_dyn_pd_th` writes the OFDM PD
lower bound with spatial reuse, the CCK PD limit/lower bound when
`support_cckpd` (cut > A), and the four SDAGC-follow-PAGC enables. The native
owner admits track reads/writes only for `track::REGISTERS`, under current
ordinary authority and the prepared operating PHY. Debug-only
`rtw89_phy_dig_diag`, NHM and the EDCCA-CLM utility are not ported; MCC,
paused/bypassed DIG and fixed-PD debug overrides do not exist natively.

CFO tracking follows `rtw89_phy_cfo_track`/`rtw89_phy_cfo_dm` for the single
linked station (`rtw89_phy_average_cfo_calc`). PPDU status IE01 of an
OFDM-or-faster PPDU addressed to the station yields `FD_CFO` (`cfo_src_fd`,
S(12,2), `rtw89_core_parse_phy_status_ie01`), accumulated per period. The
operating owner already wrote and verified the default capacitor and B's
DCFO/hardware-CFO setup (`rtw89_dcfo_comp_init`, `cfo_hw_comp`), so
`rtw89_phy_cfo_init` only seeds state from it (`x_cap_lb`/`x_cap_ub` = ±64).
Each decision applies the enable/stop hysteresis and ±3/±1 steps, writes the
capacitor through XTAL SI SC_XO then SC_XI with readback (B has no
`xtal_info`), applies the divergence lock (15 periods) at the bounds, steps
back toward the default while unlinked, and programs `R_DCFO_COMP_S0` from the
shifted average with `CFO_SW_COMP_FINE_TUNE` after a capacitor change. TX
throughput (`rtw89_traffic_stats_calc`: unicast data bytes >> 18 per 2 s,
`DECLARE_EWMA(tp, 10, 2)`) drives NORMAL ⇄ ENHANCE at 100/50 Mbps; ENHANCE runs
the decision on the 250 ms `cfo_track_work` timer instead. Native counts the
Ethernet bytes of accepted unicast frames (Linux counts the 802.11 skb). No
UL-OFDMA trigger-frame statistic exists natively, so HOLD is never entered. The RX
assembler parses `RTW89_CORE_RX_TYPE_PPDU_STAT` exactly as
`rtw89_core_rx_process_ppdu_sts` accepts it (MAC-info users ≤ `ppdu_max_usr`
4, PHY-status VALID, header length equal to the report, IE map ≥
`RTW89_CCK_PKT`, the AX `physt_ie_len` walk, A1 match) and yields
`RSSI_AVG` for the RXD dword5 MACID. The packet owner forwards only its own
MACID; the station keeps `DECLARE_EWMA(rssi, 10, 16)`, counted only from
association (four-way or open) and restarted for a new peer
(`ewma_rssi_init`). Every 2 s (`RTW89_TRACK_WORK_PERIOD`), and never while
scanning, the station computes `rtw89_phy_edcca_get_thre_by_rssi` (unlinked
`EDCCA_MAX` 249; linked `rssi/2 − 110 + 128 − 3`, floored at 66) and, when it
differs from the last written level (`th_old`), writes `R_SEG0R_EDCCA_LVL_V1`
bytes 0, 1 and 3 with readback. An owner without the track hooks reports
`Unsupported`, which disables tracking (`disabled_dm_bitmap`). Debug-only
`rtw89_phy_edcca_log`/`_diag` and the scan-time `rtw89_phy_config_edcca`
backup are not used: track work skips scans and native scans do not change
the level. Smokes: `smoke_rtw89_track_*` (including a register-file model
of the full first and linked periods and the CFO crystal/DCFO decisions),
`smoke_rtw89_rx_ppdu_status_ie01_cfo_matches_linux`,
`smoke_rtw89_rx_ppdu_status_yields_rssi_only_when_linux_accepts`. QEMU-only
software evidence; no silicon run.

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
power authority. Frozen source-derived transport/decoder references
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
Eighteen frozen reference traces cover seeded registers,
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
The unchanged fresh FLR/cold-WCPU program never requests LPS/RPWM or WoW;
an observed sleeping state terminalizes instead of synthesizing a wake
receipt. The separately qualified clock-gated LPS owner below supplies the
actual sleep/wake continuation; it leaves this ordinary awake gate intact. Initial and post-join negative models cover every source PS
bit and distinguish unrelated power/MACID bits.

AXB address CAM v0 carries the actual source/peer addresses, exact hashes,
BSSID match, MACID/port and checked AID. Every security-entry valid bit remains
zero. Global TX encryption/hardware decryption and MIC/ICV appending are
explicitly disabled and read back for original host CCMP MPDUs. The fixed
legacy profile uses source TX-A CCTL path selection, CCK1/20MHz and disabled
data/RTS fallback. The original flags3 qualification has no WMM/HT claims;
the optional separately qualified WMM profile below retains the same PHY.
Initial source EDCA commands use non-QoS
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

Frozen references from Linux CAM/role/join/CCTL/EDCA helpers and default tables
check serialized bytes and indirect register order in the Rust controls. Models
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
encryption/IV insertion disabled. The optional B WMM profile additionally admits
checked26-byte BE/TID0 QoS headers, with source header length13 halfwords and
CCMP extents shifted accordingly. Current native peer admission remains mandatory;
formatting alone grants no RF/QoS authority. Protected management, other TIDs,
fragmentation and optional headers remain rejected. It rejects unsupported BE, wrong QSEL/channel
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

Seven native Rust packet-format/owner regressions use frozen AX body/info and
PCI address-info byte references, alongside a reactive device model that follows actual programmed TXBD bases, descriptor,
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

### Separately qualified RTL8852B WMM BE/TID0

N52B v2 profile byte57 may additionally be7 instead of3. Flags3 retains its
original full-radio digest and legacy station behavior. Flags7 requires a
distinct derived digest binding that full board/firmware/PHY/power identity and
the versioned WMM negotiation, source H2C EDCA, conservative BE policy and
26-byte TID0 TXWD recipe. Merely changing the flag on an old signed record
fails identity. The retained qualification request logs the alternate WMM
identity beside the same `radio-v2` asset name; only actual measured signed
evidence covering this operating program can enable it. Calibration-only or
legacy qualification cannot authorize QoS.

When both the actual current qualification and scan AP permit WMM, the driver
adds its own Information IE. The already peer/status/AID/rate-bound response
must supply valid WMM parameters. Source MAC H2C class9/function15 programs
four canonical BE/BK/VI/VO EDCA values with actual identity/sequence-matched
DONE_ACK. All rows are checked before publication, including representable AIFS;
BE uses AIFSN>=3, ECWmin>=5, ECWmax>=10 and TXOP0. The source10us SIFS and
negotiated9/20us slot remain exact. Only after all four receipts does the
retained native peer token admit QoS DATA/TID0 on BE0. That token is invalidated
before failed/cancelled setup or teardown; an unrelated or late receipt cannot
promote it. Actual device and signed qualification invocations still enclose
native commands/descriptors/doorbells. Live flags7 policy checks require the
installed domain and cannot reload a cleared installation.

Raw26-byte headers precede host CCMP; native TXWD uses13 halfwords and complete
shifted IV/ciphertext/MIC validation. Open/WPA2 RX retains source channel and
per-key/TID replay checks. Live AP EDCA changes are handled below;
HT/BA, U-APSD, TSPEC, priority scheduling and other TIDs remain
unsupported. Four native Rust smokes exercise distinct signed recipes/current
cap revocation, literal source H2C/peer gates, failing/held ACK and cancellation,
actual native packet owners through Open/WPA2 and exact bidirectional data,
malformed response and held M4. Real measured flags7 assets and physical WMM/RF
acceptance remain external gates; broader lifecycle recovery remains open.

### Negotiated legacy DATA rates under WMM recipe revision2

The flags7 derived WMM identity now binds recipe revision2, the exact native
TXWD_INFO0 DATA_RATE[24:16] field, USE_RATE/DISDATAFB and response-bound
selection order54,48,36,24,18,12,11,9,6,5.5,2,1Mbps. Earlier flags7 measured
records cannot authorize this changed emitter program. A genuine new record
must bound all newly reachable DATA rates and the complete unchanged radio/
automatic-response program. Flags3 remains fixed CCK1; packet formatting or
an AP rate offer cannot promote that qualification.

Only ordinary DATA after actual WMM/peer admission selects the fastest rate
from the common plan's actual association response/request intersection.
Management/EAPOL remain CCK1 and the initial AP still needs that basic rate.
The actual Native rechecks the current flags7 qualifier before nonzero-rate
publication, then the same retained packet owner formats TXWD and waits for
both TXBD consumption and matching RPQ release. One composed native smoke
checks all12 literal TXWD rates, Open/WPA2 data/CCMP, AP response narrowing,
current PCI loss and unchanged flags3 behavior. HT/HE, adaptive fallback/MRR
and full WMM AC/TIDs remain software work with additional source and signed
qualification dependencies.

### Optional operating programs and all-AC/TID QoS

`radio_policy::Program` generalizes the signed profile byte57: base flags3
plus one bit per optional emitter program (bit2 `Wmm`, bit3 `QosAll`, which
requires `Wmm`). Each enabled program extends the board identity in fixed
order, so a record authorizes exactly the programs it was measured with;
flags3/7 identities are unchanged, flags15 needs a new chained identity and
a flags7 record cannot be promoted. `QualificationRequest` logs the flags15
identity beside the WMM one. New TX programs add a `Program` variant with
its own fingerprint instead of another ad-hoc flag value.

With `QosAll` granted and a WMM association, `packet_core` publishes ACH1..3
(BK/VI/VO) beside BE0/MGMT8 and opens exactly their `R_AX_PCIE_DMA_STOP1`
bits; stop closes ACH0..3, CH8 and WPDMA. Outgoing Ethernet frames are
classified like `cfg80211_classify8021d` (RFC 8325 DSCP table, MPLS TC,
802.21 -> 7) and ACM-downgraded like `ieee80211_downgrade_queue` with
`wme_downgrade_ac`. The TID is carried in the QoS control field (host CCMP
binds it in the AAD); `packet_format` maps it with `rtw89_core_get_qsel` and
`rtw89_core_get_ch_dma` to QSEL0..3/ACH0..3 and sets `TXWD_BODY2_TID_INDICATE`
per `rtw89_core_get_tid_indicate`. RX accepts QoS DATA on any TID0..7 with
per-TID replay. The packet owner still keeps one frame in flight; the drain
worker therefore serves a bounded per-AC backlog in strict VO > VI > BE > BK
order (host stand-in for mac80211 txq scheduling plus hardware EDCA
contention). Without `QosAll` every frame stays on the flags7 BE/TID0
recipe. Smokes: `drivers/wireless/rtw89/qos` (classification, downgrade,
indicate), `smoke_rtw8852b_operating_programs_each_require_their_own_signed_identity`,
and `smoke_rtw8852b_all_ac_qos_routes_tids_to_ach_rings_with_strict_priority`
(TID6 on ACH3, VI/BE/BK ordering, TID5 RX, flags7 fallback).

### Firmware rate adaptation and retry fallback

`radio_policy::Program::FirmwareRa` (byte57 bit4, requires `Wmm`) hands
DATA rates to firmware like Linux. After the WMM EDCA rows, the controller
sends `rtw89_fw_h2c_ra` (H2C OUTSRC cat2/class1/func0 RA_MACIDCFG, AX
layout, no CSI, no ACK requested) built as `rtw89_phy_ra_sta_update` does
for a legacy 2.4GHz peer: the response-bound rate bitmap, mode CCK|OFDM,
mask `&= OFDM|SUBCCK` then `rtw89_phy_ra_mask_recover`, 20MHz, one stream,
MACID0, `UPD_ALL`. No calibrated RSSI exists, so the RSSI floor keeps every
rate and `init_rate_lv` is 0 (Linux's value for RSSI<=1). Data TXWDs then
clear `INFO0 USE_RATE`/`DISDATAFB` and set `INFO1 DATA_RTY_LOWEST_RATE` to
the lowest negotiated rate (`rtw89_core_get_data_rate`), so firmware RA
adapts the rate and hardware retries fall back toward that floor (multi-rate
retry). Management/EAPOL stay fixed CCK1, and without the program the
revision2 fixed fastest-rate recipe is unchanged. Smoke:
`smoke_rtw8852b_firmware_ra_h2c_and_adaptive_data_txwd`. RA C2H reports
are not consumed (Linux uses them only for statistics).

### HT20 station operation

`radio_policy::Program::Ht` (byte57 bit5, requires `Wmm` and `FirmwareRa`)
enables HT20. When the AP also advertises WMM, the station prepares its
join through the shared `JoinPlan::prepare_with_phy(LocalPhy::ht20(..))`
with `station_control::local_ht()`: Linux `rtw89_init_ht_cap` restricted to
this TX-A/RX-AB 20MHz profile (SGI20, LDPC, RX STBC1, 64K A-MPDU factor,
no density, RX MCS0..15, TX MCS0..7). HT40/DSSSCCK40/SGI40 belong to
`wide_channels`; TX STBC needs a second TX path this profile lacks; the
large receive A-MSDU bit remains unadvertised; TX aggregation does not expand that receive promise. The negotiated HT facts feed the
firmware RA H2C exactly like `rtw89_phy_ra_sta_update`'s HT branch
(`mode |= HT`, peer RX MCS bytes shifted to bits 12/24/36/48, masked to
`RA_MASK_HT_1SS_RATES|SUBOFDM|SUBCCK` for one TX stream, SGI20/LDPC from the
negotiation, STBC0, SS_NUM0). The RX assembler now passes 20MHz HT MCS0..15
(`RTW89_HW_RATE_MCS0..MCS15`); the packet owner admits them only under the
HT program and otherwise drops them as before without closing the station.
Smoke: `smoke_rtw8852b_ht20_capability_ra_mcs_and_rx` (HT element in the
association request, HT RA mask, RA data TXWD, MCS7 RX, non-HT drop).

### HE20 station operation and GI/LTF variants

`radio_policy::Program::He` (byte57 bit6, requires `Ht`, hence `Wmm` and
`FirmwareRa`; flags `0x77`) enables HE on the HT20 profile. When granted, the
join adds `station_control::local_he()` through the shared
`LocalPhy::with_he`: Linux `core.c::rtw89_init_he_cap` for a 2.4GHz station,
restricted to this TX-A/RX-AB 20MHz profile. MAC: TF MAC padding 16us,
HTC_HE, ALL_ACK, A-MPDU length exponent extension 2, HT/VHT trigger-frame RX. PHY:
20MHz-only width set, device class A, LDPC, HE SU/MU 1x/2xLTF+0.8us GI,
NDP 4xLTF+3.2us, STBC RX, Doppler TX, DCM 16QAM (TX NSS1), partial-BW
extended range, power boost, 4xLTF+0.8us SU/MU, ER SU 4xLTF/1xLTF+0.8us,
DCM max RU996, >16 SIG-B symbols, TX/RX 1024QAM below 242-tone RU, full-BW
SU in MU (compressed and non-compressed SIG-B) and 16us nominal padding;
RX HE-MCS0..11 on two streams and TX HE-MCS0..11 on one. Linux bits that
need 40MHz (`wide_channels`), a second TX path (STBC TX, DCM TX NSS2),
buffer-status capability (`BSR`), power save (`OPS`), RX A-MSDU
(`AMSDU_IN_AMPDU`; unchanged receive-direction promise) or beamforming feedback
(`rtw89_mac_bf_assoc` sounding: SU beamformee, NG16, codebook sizes,
triggered SU feedback, MaxNc) are cleared.

The negotiated HE facts feed the firmware RA H2C like the HE branch of
`phy.c::rtw89_phy_ra_sta_update`: `mode = HE|CCK|OFDM` (no HT bit), mask
`get_he_ra_mask` (`get_mcs_ra_mask(map, 11, 2)`) over the peer RX map
intersected with the local TX map (mac80211
`ieee80211_he_mcs_intersection`), masked to `RA_MASK_HE_1SS_RATES` plus
SUBOFDM/SUBCCK and recovered; SGI from the HT SGI20 negotiation (Linux reads
`ht_cap` at 20MHz); LDPC from the peer HE PHY; `W0_DCM` when the peer
advertises any DCM RX constellation (`DCM_MAX_CONST_RX_16_QAM` mask); STBC0
and SS_NUM0 for the single TX path, as in the HT program. `fix_giltf_en`
stays clear (`rtw89_phy_ra_gi_ltf` applies only to a user bitrate mask), so
firmware RA chooses among the 0.8/1.6/3.2us GI and 1x/2x/4x LTF variants;
this is the `he_gi_ltf` TX half. `W0_ER` is zero because Linux sets
`rtwsta->er_cap` in `rtw89_core_sta_assoc` only after `rtw89_phy_ra_assoc`;
data TXWDs then carry `RTW89_TXWD_INFO0_DATA_ER` (`desc_info->er_cap`)
unless the AP's HE Operation sets ER SU Disable. The packet owner refuses
`DATA_ER` without the HE program.

RX: the assembler now decodes `AX_RXD_RX_GI_LTF_MASK` and passes 20MHz
`RTW89_HW_RATE_HE_NSS1_MCS0..11` and `HE_NSS2_MCS0..11` with a defined
`enum rtw89_gi_ltf` value (0..5, `LGI_4XHE32`..`1XHE08`); undefined GI/LTF,
NSS3+ or other widths are dropped. `packet_core::RxPhy` admits HE rates
only under the HE program; without it an HE PPDU is dropped without closing
the station, exactly like HT without `Ht`. Stop/disconnect clear the HE and
ER state with the rest of the association. Smokes:
`smoke_rtw8852b_he_program_requires_ht_and_its_own_signed_identity`,
`smoke_rtw8852b_he_capability_and_ra_codec_match_linux_profile` and
`smoke_rtw8852b_he20_capability_ra_er_and_gi_ltf_rx` (HE element, HE RA
mask with/without DCM, DATA_ER with/without ER SU Disable, HE MCS11 1xLTF
and NSS2 4xLTF RX, invalid GI/LTF and NSS3 drop, disconnect, HT-only AP
fallback, program-not-granted).

HE +HTC uses the HE operating recipe revision2. The recipe identity now
binds HTC_HE advertisement, the HE/CAS control template `1b 00 00 00`,
30-octet QoS headers with Order/EOSP, TXWD `INFO1_A_CTRL_BSR`, and
`BODY3_BK` whenever the A-Control form changes, so a hardware aggregate
cannot mix forms. Earlier signed HE recipe identities are refused.
`he_htc::rate_allows` consumes current MACID0 AX OUTSRC/RA status C2Hs;
insertion stays off until a well-formed report rules out legacy fallback
at MCS >2. Lower/legacy rates or malformed matching reports suppress it;
another MACID's report cannot enable it. Disconnect/failure clears that
state. HE negotiation and the current signed program remain independent
requirements. EAPOL, ARP, DHCP and ICMP keep ordinary headers, matching
Linux `__rtw89_core_tx_check_he_qos_htc`'s interoperability exclusions.
The retained peer binding admits the extra header only after HE RA
configuration completes under the same association admission, preserves its
TID mask while checking EOSP, and clears HE admission on invalidation.

The shared `Security::transmit_ethernet_qos_htc` builds the complete header
before host CCMP, using the ordinary key PN and TID sequence. CCMP AAD
excludes HT Control, Order and EOSP but authenticates the TID, addresses
and payload. The native packet owner enforces the HE grant and firmware
rate adaptation, checks the header/control/CCMP offsets, and programs
the full 30-octet descriptor header length. Open and protected downlinks
both preserve original RX bytes through native admission and remove HT
Control only when converting an accepted MSDU to Ethernet. The 2.4GHz
40MHz OM override remains part of the separate wider-channel work.

Native regressions cover rate transitions, unrelated/truncated reports,
special packets, descriptor bits and offsets, controlled-port and
PN/sequence ownership, actual AP CCMP verification, bidirectional Ethernet
and disconnect. The four native `drivers/wireless/rtw89/htc` regressions
and two shared `wireless/station_security/htc` regressions pass on x86_64
and aarch64 (six passed per architecture, no failures or skips).

### Recipient Block Ack and RX reordering

On an open HT link the station acts as the mac80211 recipient for rtw89
(`AMPDU_AGGREGATION` without `SUPPORTS_REORDERING_BUFFER`). `block_ack.rs`
decodes unprotected Block Ack actions from the bound AP and admits ADDBA
Requests like `__ieee80211_start_rx_ba_session`: non-HT links decline (37),
delayed policy or a buffer above `max_rx_agg_num` 64 is invalid (38), a zero
buffer means 64. A repeated request on a live TID replaces the session.
The async owner then issues `rtw89_fw_h2c_ba_cam` through
`Controller::configure_ba` (BA CAM v0: VALID, INIT_REQ, ENTRY_IDX, TID,
MACID0, BMAP_SIZE, SSN; DONE_ACK) with the Linux static-entry policy (two
entries, TID0/5 may replace another TID, otherwise no H2C because hardware
creates a dynamic entry), creates the shared `Reorder` window with head SSN
and 100ms release timeout (`HT_RX_REORDER_BUF_TIMEOUT`), and queues the
ADDBA Response (immediate policy, no A-MSDU, request timeout). QoS DATA on a
session TID is ordered before CCMP/replay; old or duplicate sequences are
dropped; compressed single-TID BlockAckReq advances the window; DELBA from
the originator drops the window and invalidates the CAM entry; a session
timeout sends DELBA (reason 39) like `sta_rx_agg_session_timer_expired`.
The RX assembler now surfaces `AX_RXD_AMPDU` subframes (hardware A-MSDU
bits remain dropped); the packet owner admits them only under the HT
program. Block Ack actions use a non-fatal ACK policy like data. Smokes:
`drivers/wireless/rtw89/block_ack` (codecs, admission) and
`smoke_rtw8852b_recipient_block_ack_reorders_and_tears_down` (BA CAM H2C,
response, hole fill, BAR flush, DELBA, non-HT decline).

### Originator Block Ack and TX A-MPDU

A seventh signed operating program, `radio_policy::Program::Ampdu` (byte57
bit7, requires `Wmm`, `FirmwareRa` and `Ht`; flags 0xb7), authorizes the
aggregate emitter. It extends the board identity with
`station_control::ampdu_fingerprint` in the fixed `ALL` order, so an HT20
record cannot be promoted. Without the grant nothing below runs: HT data
is never aggregated and no ADDBA Request is sent.

Multi-frame ownership: `packet_core::Core` keeps a heap `Vec` of in-flight
frames instead of one `pending` slot. Each entry owns its own TxQueue
ticket and header/body DMA maps. `enable_aggregation` (before `start`,
HT RX program or higher) admits up to `AGG_WINDOW` (32) aggregated data
frames in flight; `ready_aggregate` counts in-flight frames plus unread
receipts. Any frame without AGG_EN still needs an empty owner, and an
aggregated frame never joins a non-aggregated one. RPQ retirement matches
each release report to exactly one unreported in-flight frame by WD
sequence, channel, QSEL and MACID. An unknown, duplicate or stale report
closes the owner, as before. Read-pointer and report facts complete frames
in any order, and the 1s timeout applies to every in-flight frame.
`reclaim_fenced` already released every TxQueue slot, so teardown with N
frames in flight returns 2N packet maps plus the rings. The station keeps
the same rule: `State::pending` is a `VecDeque` matched by receipt id, and
management, EAPOL and probe frames still need an empty queue.

TXWD (Linux v7.2 `core.c::rtw89_core_tx_update_ampdu_info`,
`rtw89_build_txwd_body3`/`_info1`/`_info2`): an aggregated frame sets
`RTW89_TXWD_BODY3_AGG_EN` (keeping `SW_SEQ`),
`RTW89_TXWD_INFO1_MAX_AGGNUM` = session `agg_num` - 1 and
`RTW89_TXWD_INFO2_AMPDU_DENSITY` = the peer HT A-MPDU minimum MPDU
spacing. Only firmware-RA QoS DATA can carry these fields.

Originator state machine (`block_ack::Originator`, heap-boxed in the
station, after Linux v7.2 `mac80211/agg-tx.c`):
- **Start.** As in `rtw89_core_txq_check_agg`, the first QoS DATA frame of
  a TID goes out unaggregated and requests `ieee80211_start_tx_ba_session`.
  Requests are refused after `HT_AGG_MAX_RETRIES`, and in a burst beyond
  `HT_AGG_BURST_RETRIES` within `HT_AGG_RETRIES_PERIOD`.
- **ADDBA Request.** With nothing in flight, the station sends the request
  (`ieee80211_send_addba_request`) with a fresh dialog token,
  A-MSDU-capable immediate policy and timeout 0. The buffer is
  `IEEE80211_MAX_AMPDU_BUF_HT` (64) for an HT peer, or
  min(`max_tx_agg_num` 128, `IEEE80211_MAX_AMPDU_BUF_HE`) plus an ADDBA
  Extension element (`NO_FRAG`) for an HE peer. The SSN is the next QoS
  SN of the TID: `Security::next_qos_sequence` when protected, otherwise
  the station counter after the request's own sequence number.
- **Held frames.** Until the session is operational, frames of the TID
  return `Busy` and stay in the TX ring, like mac80211's `tid_tx->pending`.
- **ADDBA Response.** Handled like `ieee80211_process_addba_resp`. A
  matching token with SUCCESS and a nonzero buffer becomes `TX_OPERATIONAL`
  with `agg_num` = min(buffer, 128). Any other status is
  `AGG_STOP_DECLINED`: no DELBA, and only the driver `TX_STOP` runs.
- **Device half.** `rtw89_ops_ampdu_action(TX_OPERATIONAL/TX_STOP_*)` runs
  on the async owner, before the TID is treated as operational. Its
  `rtw89_chip_h2c_ampdu_cmac_tbl` is NULL in `rtw8852b_chip_ops` (Linux
  v7.2 `rtw8852b.c`), so no H2C is sent on this chip.
  `rtw89_phy_ra_recalc_agg_limit` writes `R_AX_AMPDU_AGG_LIMIT` (0xc610)
  `B_AX_RA_TRY_RATE_AGG_LMT_MASK` [23:16]: clamp(min `agg_num`, 1, 256) - 1,
  or 0x3f with no operational session (`Controller::configure_agg_limit`,
  inside the current capability, admission and peer).
- **Stops.**
  - A missing response within `ADDBA_RESP_INTERVAL` (1s,
    `sta_addba_resp_timer_expired`) is `AGG_STOP_LOCAL_REQUEST`: the
    station sends DELBA as initiator with `WLAN_REASON_QSTA_NOT_USE`.
  - An EAPOL frame on a session TID stops that session the same way and
    forbids a new one for `RTW89_FORBID_BA_TIMER` (4s,
    `rtw89_core_stop_tx_ba_session`).
  - A recipient DELBA is `AGG_STOP_PEER_REQUEST`, with no DELBA back.
  - Disconnect or stop is `AGG_STOP_DESTROY_STA`, with no frame.

Every stop reaches `TX_STOP` (limit recomputed). Aggregated frames stay
within min(session buffer, `AGG_WINDOW`) in flight.

Smokes:
- `smoke_rtw89_b_packet_aggregate_window_multi_slot_rpq_retirement`:
  refused without the program, 32 frames in flight, window closed,
  non-aggregated frame refused, out-of-order multi-entry retirement,
  stale report fails closed, reclaim of 3 unretired slots.
- `smoke_rtw89_b_packet_txwd_ampdu_fields`: exact TXWD delta and refusal
  outside firmware-RA QoS DATA.
- `smoke_rtw8852b_ampdu_program_requires_ht_and_its_own_signed_identity`.
- `smoke_rtw8852b_originator_block_ack_tx_ampdu`:
  - success: unaggregated trigger frame, ADDBA Request bytes and SSN,
    limit 63, AGG_EN data, two aggregated frames in flight retired;
  - teardown: recipient DELBA restores 0x3f and stops aggregation;
  - failure: a declined response and a response timeout (DELBA 37);
  - program not granted: no ADDBA and no AGG_EN.

### TX A-MSDU and A-MSDU-in-A-MPDU (source complete; validation pending)

The admitted RTL8852B station now implements both Linux TX directions
(`IEEE80211_HW_TX_AMSDU` and `SUPPORTS_AMSDU_IN_AMPDU`). This extends the
actual retained channel1/20MHz Open/WPA2 HT/HE owner, not another chip's
unimplemented runtime. Software acceptance and physical qualification remain
separate; the five new aggregation cases have not yet been executed.

`interface::Rings` peeks at most8 original Ethernet frames from the selected
AC's exact FIFO prefix. `State::send_prefix` holds the original publication
admission, requires the actual HT/WMM/A-MPDU operating program and a distinct
current A-MSDU companion, and stops at the first different effective TID,
control/tunnel/VLAN-control frame, invalid source or size boundary. It never
skips a later member to form a batch. The whole prefix is encoded and actual
queue credit and exact retained peer BA in-flight window checked before
consuming a sequence or CCMP PN. Both single and batched sends reuse that
station-window predicate at the final send as well. A peer buffer1 held MPDU
cannot repeatedly consume PN/SN merely because the native global window is
larger. Fewer than2
eligible frames use the unchanged single-frame emitter. A last native worker
pass that did not reach actual RXQ/RPQ idle cannot form a new A-MSDU from
unprocessed peer/RC facts.

Directional TX body bounds are min(peer HT3839/7935, chip5000, latest actual
MACID0 RC ceiling). Linux7.3-rc4 `rtw8852b.c` sets `max_amsdu_limit=5000`;
`phy.c::get_max_amsdu_len` sets1 below550 (100kbps units) or possible legacy
fallback (MCS<=2), then1200/2600/3500 below1800/4000/7000, otherwise the
chip bound. The native AX OUTSRC/RA/STS report supplies actual MCS/NSS,
20MHz bandwidth and GI/LTF; unsupported/malformed matching reports deny
batching, and unrelated MACIDs/events do not replace this peer's ceiling.
HT1SS/HE1SS20 native bitrate calculation follows `cfg80211_calculate_bitrate`;
this admitted profile's valid high-rate reports reach the1200 ceiling.
Before the first report there is no RC clamp, matching mac80211's initial
`max_rc_amsdu_len=0`. A report supplies only a smaller queue-size fact,
never RF/rate/peer authority.

An actual peer ADDBA Response without its A-MSDU bit sets a sticky per-TID
`IEEE80211_TXQ_NO_AMSDU` denial before dialog-token matching, as Linux's
`agg-tx.c::ieee80211_process_addba_resp` does. DELBA, a new positive response
and BA retries do not erase it for this physical peer; station destruction
does. Nested A-MSDU requires the real operational originator BA owner and,
for HE, the peer receive `MAC_CAP4_AMSDU_IN_AMPDU` bit. Our receive HT-large
A-MSDU/HE-AMSDU-in-AMPDU bits stay unchanged and confer no additional RX
promise. A standalone batch uses Normal Ack; a nested batch retains the
actual BA buffer/density and native TXWD AGG_EN fields.

Protected batches call `Security::transmit_amsdu_qos` with the negotiated
peer size, emitting one real CCMP MPDU with one PN and QoS SN, BSSID A3 and
no optional HT Control. Open batches likewise consume one host SN. The
existing native BODY3_BK transition handles leaving an HE +HTC form.
`packet_core` admits QoS bit7 and a dynamically sized body only under its
explicit prepared expanded TX profile. Both real pre-allocation and final
pre-doorbell checks invoke the original current full-radio/companion,
power/device and sealed peer admission. Default classifiers/transports keep
their old2304-byte/non-A-MSDU profile. RTL8852B uses its actual single PCI
address-info element for the complete MPDU (the2044-byte splitting source
belongs to a different chip format). One native ticket owns copied header
and body DMA until both actual TXBD consumption and matching RPQ air terminal;
there are no invented per-subframe completions. The host consumes all original
prefix frames together only after successful native publication; Busy retains
them unchanged and a fatal source/key/native failure closes the owner.

A-MSDU does not alter the existing128-byte N52B v2 flags/fingerprints. Its
optional separately signed expanded full-program companion is
`rtw89/rtw8852b-tx-amsdu-v1-<actual-mac>.bin`. Only NotFound preserves the
narrow old emitter; a present malformed/unsigned/wrong-signer/wrong-identity
record refuses preflight. The128-byte N52A v1 record has magic0..4, header
`[1,0,128,0]` at4, total length128 at8, vendor/device at12/14, binding at16,
actual MAC at48, `[1,20,1,3]` at54 (channel/width/TXA/both TX forms), body
limit5000 at58, prefix8 at60 and zero61..128. The binding is SHA256 of the
fixed domain `NARF RTL8852B measured expanded full A-MSDU operating program v1`,
the complete selected board/program identity, exact installed N52B bytes'
SHA256, actual base signer and `amsdu_policy::recipe()` digest, in that order.
The companion must have the same authenticated signer as that exact base.
It attests that the base's worst-case measured peak/antenna/power envelope
covers this expanded full operating program; it cannot reuse a narrower
measurement just because the bytes encode. Current base and companion caps
remain invoked across real publication, with current host power constraints.

Native/model cases under `drivers/wireless/rtw89/aggregation` cover genuine
Open/WPA2 and HT/HE CCMP/decrypted Ethernet, standalone and nested BA, one
held MPDU/PN/descriptor/terminal for multiple originals, prefix8, peer3839 vs
chip5000, actual RC C2H ceilings, absent companion, same-AC different-TID FIFO,
sticky wrong-token denial and DELBA, and companion loss after native allocation.
The signed-policy case covers exact record/signer/power identity, truncated and
mutated records, transplantation, real cap revocation and tightened host power.
Primary source pins are Linux7.3-rc4 `rtw89/{core.c,pci.c,phy.c,core.h,
rtw8852b.c,txrx.h}`, `mac80211/{tx.c,agg-tx.c,ht.c}` and `wireless/util.c`.
No build, native execution or physical acceptance is implied by this pending
source contract.

### Periodic RTL8852B DPK power tracking (source complete; validation pending)

The actual admitted B callback is Linux7.3-rc4
`rtw8852b_rfk_track`→`rtw8852b_dpk_track`. Periodic IQK/TSSI calibration
reruns are not B callback producers; the existing completed source TSSI
setup already enables continuous thermal feedback on both paths. The AX
`rtw89_core_rfk_tssi_record` returns without the BE-only diagnostic history.
The admitted `rtw8852be` adapter also has no110C/120C PCI thermal-duty quirk;
its source thermal-protection threshold is0. The8852BT/8922A duty controls
belong to those other chip adapters, not a missing B board-data prerequisite.

`radio_full::Radio::tracking_inputs` copies slot0 DPK thermal/PWSF only
from its actual Ready DPK/TSSI completion. Native retains that snapshot
before installing the ordinary receipt. An optional independently signed
tracking program enables `rf_tracking::Tracker`; absent input cannot be
reconstructed from a station flag. The existing retained2s `track_work`
owner invokes it after DIG and before CFO/EDCCA, skips scans and does not
run it from the enhanced250ms CFO-only work. The initial worker period can
initialize the callback; subsequent work uses the same2s deadline. Peer
changes do not discard the radio's thermal averages.

TSSI-mode thermal comes from actual BB`0x1c10 + path*0x2000` bits29:24,
with source `DECLARE_EWMA(thermal,4,4)` and zero-sample retention. Both live
TSSI enable/RFC readbacks are required. `rtw8852b_rfk.c::_dpk_track` then
uses the retained channel1/2G thermal delta scaled3/2, actual TXAGC_RF/BB/TP,
signed8-bit initial offset, DPD hardware-offset mode and TXDPD branch to
update both9-bit PWSF fields in`0x81b4 + path*0x100`. Source signed-byte
assignment and9-bit wrapping are explicit, including `ini_diff` carry
between paths when a path has no thermal/RF gain. Global DPK tracking-disable
or zero RF gain performs no PWSF write. The unused debug-only RF tracking
index supplies no behavior, so this runtime path does not issue that analog
read or broaden initial RFK's deliberate CMAC-TX-closed access gate.

Both path calculations and signed measured-window checks precede the first
PWSF change. Computed values outside the window refuse rather than clamp.
The native adapter permits only those exact logical BB reads and PWSF writes,
translates the actual AX base, preserves other bits and verifies readback.
Every read/RMW/write/readback invokes the original current PCI, base,
expanded-program capabilities and host power inside the original station
publication admission. The update is synchronous and has no new await or
half-update cancellation owner. A returned native/current/readback fault
retires the tracker and same Native, closes emission and retains existing
uncertain DMA behind the physical stop proof. A second-path fault never
silently resumes from the changed first path. Non-emitting terminal cleanup
uses the existing actual device cleanup path after emission authority dies.

The optional128-byte `N52T` v1 record is
`rtw89/rtw8852b-rf-track-v1-<actual-mac>.bin`. Its header/vendor/device/MAC
fields match N52A's offsets;54..58 is`[1,20,1,3]`,58..60/60..62 are the
permitted low/high9-bit PWSF range, and62..128 is zero. The binding at16..48
is SHA256 of domain `NARF RTL8852B measured expanded periodic DPK full program v1`,
full selected board/program identity, actual installed N52B digest and signer,
a byte0 for absent A-MSDU or byte1 plus the actual installed N52A digest,
then `rf_tracking_policy::recipe()` digest. It must have the base's actual
authenticated signer. The signed measurement attests the base worst-case
peak/antenna/power envelope for the full joint radio/aggregation/tracking
program across every permitted PWSF value; individual narrower records cannot
silently authorize the combination. Both original companion caps remain
current. Only NotFound preserves old behavior; invalid-present records refuse.
N52B/N52A formats and existing fingerprint inputs remain unchanged.

Four new cases cover stored thermal/TSSI/PWSF/EWMA/sign/wrap vectors and
register-hole preservation, disabled/zero/TSSI-invalid input, measured-window
refusal and sticky partial-fault retirement, exact signed joint-program and
window/cap/power constraints, and actual Native/NativeIo MMIO under current
original caps/admission with absent-program and missing-input negatives.
The existing track-work case retains its assertions and adds actual callback
period/scan assertions. These cases are written, unexecuted; source compile,
native software gates and physical measured deployment acceptance remain
pending. Primary pins are Linux7.3-rc4`rtw89/{core.c,core.h,phy.c,reg.h,
rtw8852b.c,rtw8852be.c,rtw8852b_common.c,rtw8852b_rfk.c}`.

### Protected management frames and WPA3-SAE

rtw89 sets `IEEE80211_HW_MFP_CAPABLE` (Linux v7.2 `core.c::rtw89_core_register_hw`).
RTL8852B has `hw_mgmt_tx_encrypt = false` (`rtw8852b.c`), and this profile
runs all crypto on the host (`SEC_ENG_CTRL` off). PMF is therefore the
mac80211 software path on the shared `station_security::Security`.

- **Join.** `SecurityConfig::Wpa2` joins with
  `JoinOptions::with_akms(PSK|PSK_SHA256).with_pmf(Pmf::Optional)`
  (`ieee80211w=1`) when the AP RSNE advertises MFPC, so PMF is in force
  and an MFPR AP is accepted. Against a non-MFPC AP the legacy RSNE is
  kept unchanged.
- **WPA3-SAE.** `SecurityConfig::Wpa3 { password }` (1..=128 octets) is
  `SecurityMode::Wpa3Sae { pwe: Both }` with AKM 8. The station builds a
  boxed `SaeSession`: H2E when the AP advertises it, else
  hunting-and-pecking. The Commit scalar comes from `Environment::nonce`
  entropy. The station then runs `JoinPlan::start_sae_authentication` and
  `sae_authentication_response` (Commit, anti-clogging retries and Confirm,
  like mac80211 `ieee80211_send_auth` for an SME-driven SAE), and on
  acceptance moves the PMK into `Security::new_sae` before the association
  request. The session is dropped then, and on stop.
- **RX.** Before any MLME, Block Ack or loss consumer, a management frame
  from the bound AP on a PMF association goes through
  `Security::receive_management`. This is mac80211
  `ieee80211_drop_unencrypted_mgmt` with host `ieee80211_crypto_ccmp_decrypt`
  and `ieee80211_crypto_aes_cmac_decrypt`. Once the PTK is installed:
  - unprotected robust unicast frames, management PN replays and failed
    BIP MMIEs are dropped;
  - a CCMP-protected deauthentication or disassociation, or a valid
    BIP-protected broadcast one (IGTK from the message-3 KDE), ends the
    link as before.
  - Beacons and other BSSs pass unchanged.
- **SA Query.** An SA Query Request to this station on an open link is
  answered with the same transaction identifier
  (`ieee80211_process_sa_query_req`).
- **TX.** Robust Action frames (SA Query Response, Block Ack actions) are
  CCMP-protected with `Security::protect_management` after the sequence
  number is assigned, once the port is open (mac80211
  `ieee80211_tx_h_encrypt`). `packet_format::classify` now admits the
  Protected bit on disassociation, deauthentication and Action frames
  only, and `tx_transport::prepare_header` admits those frames already
  host-encrypted (CCMP header plus at least 2 octets of ciphertext). The
  TXWD carries no SEC fields, as Linux does when `hw_mgmt_tx_encrypt` is
  false.
- **Cipher suites.** `cipher_suites` lists CCMP-128 and BIP-CMAC-128.

No operating program gates PMF or SAE: they change neither the RF emitter
nor any TXWD rate field. The smoke runs on the base profile, which is the
program-not-granted case. Smoke: `smoke_rtw8852b_pmf_wpa2_sa_query_bip_and_wpa3_sae`:
- WPA2-PSK against an MFPR AP: PMF negotiated, unprotected SA Query
  dropped, protected SA Query answered under CCMP with its ID;
- replayed PN, unprotected deauthentication and forged BIP deauthentication
  dropped, and a valid BIP broadcast deauthentication ends the link;
- WPA3-SAE H2E association, then SAE-PTK uplink, then teardown;
- a wrong SAE password associates nothing and installs no keys.



### Active scanning, probe IEs and dwell control

`WirelessNetIface::scan` now accepts active channel-1 scans. The station
transmits one broadcast probe request per requested SSID (a wildcard when
none, at most `RTW89_SCANOFLD_MAX_SSID` 8) on the management queue, as
mac80211's software scan does, then listens for the requested dwell. The
request body follows `ieee80211_build_probe_req` for this 2.4GHz profile:
SSID, Supported Rates 1..18Mbps, Extended Supported Rates 24..54Mbps, DS
Parameter Set channel1, then caller IEs. Caller IEs must be well-formed
TLVs within `RTW89_SCANOFLD_MAX_IE_LEN` (512, advertised as
`max_scan_ie_len`) and may not duplicate the driver-generated elements;
passive scans refuse them. A wildcard-addressed probe request from the own
address is the only frame the packet owner admits without a peer token;
it is sent BMC (no ACK) and a missing ACK is not fatal. The measured dwell
equals `ceil(duration_tu * 1024 / 1000)` ms (default 200ms; 0, >1000TU or
a missing mandatory duration are refused before any RF activity).
Deviation: Linux uses firmware scan offload (`rtw89_hw_scan_*`) across
channels; this profile is qualified for channel 1 only, so host probing on
that channel is the faithful subset. Smokes: `smoke_rtw8852b_active_scan_probe_requests_and_extra_ies`,
`smoke_rtw8852b_scan_dwell_follows_requested_duration`.

Random scan address: the device advertises
`NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR` (`rtw89_core_register_hw`). A
request whose mask randomizes the group bit or whose base address is
multicast is refused like cfg80211 `nl80211_parse_random_mac`. For an
active scan the address is `get_random_mask_addr` (random bits outside the
mask, base bits inside). As in `rtw89_core_scan_start`, the passive
controller first rewrites the address CAM SMA through `rtw89_fw_h2c_cam`
(`Controller::scan_address`, DONE_ACK, refused with a peer bound), and the
packet owner then admits a probe request from exactly that address.
Probe requests use it as SA and A2, and responses directed to it are
observed. After the dwell and the last probe's retirement (bounded at
1s), `rtw89_core_scan_complete` restores the packet owner and then the CAM
SMA to the own address. A failed CAM update or retirement is terminal like
any other controller step, and association refuses a live scan address.
A passive scan transmits nothing and leaves the CAM unchanged. Smoke:
`smoke_rtw8852b_random_scan_address_cam_probe_and_restore` (group-bit
mask refused with no H2C, masked SA, response observation, CAM move and
restore, own-address scan and association afterwards). Random-address
scanning uses the same probe emitter as active scanning, which no
operating program gates.

Random probe sequence numbers: the device advertises
`NL80211_EXT_FEATURE_SCAN_RANDOM_SN` (Linux v7.2 `core.c::rtw89_core_register_hw`)
through `supports_scan_random_sn()`, and `scan_with_flags` carries
`ScanFlags::random_sn` into the station probe. As in Linux v7.2
`mac80211/scan.c::ieee80211_scan_state_send_probe` (which maps
`NL80211_SCAN_FLAG_RANDOM_SN` to `IEEE80211_PROBE_FLAG_RANDOM_SN`) and
`ieee80211_send_scan_probe_req`, every probe request of an active scan
gets `IEEE80211_SN_TO_SEQ(get_random_u16())` in its Sequence Control and
is sent with `IEEE80211_TX_CTRL_NO_SEQNO` semantics: the station's
management sequence counter is neither used nor advanced. The random
values come from one `Environment::nonce` draw taken before any address
CAM or RF activity, so missing entropy fails the scan (terminal, like any
failed scan) without a transmission. The TXWD is unchanged: management
keeps `HW_SSN_SEL=1`/`HW_SSN_MODE=1` exactly as Linux v7.2
`core.c::rtw89_core_tx_update_mgmt_info` does for every management frame,
random-SN probes included. A passive scan accepts the flag and transmits
nothing. The probe emitter is not gated by any operating program, so
there is no program-not-granted case. Linux offloads scans to firmware
(`fw.c::rtw89_hw_scan_add_chan_list` `rand_seq_num`); the channel-1 host
probe path here is the faithful subset. Smoke:
`smoke_rtw8852b_random_sn_probe_requests` (counted SN without the flag,
random SN per probe with it, counter not advanced, passive scan, no
entropy refused with no probe or H2C, station stopped afterwards).

### Live AP EDCA updates

Bound peer beacons/probe responses on an open WMM link follow mac80211
`ieee80211_sta_wmm_params`: an unchanged WMM parameter-set count and
U-APSD bit is ignored; a new count queues the set. The drain worker then
applies it outside the synchronous poll through
`station_control::Controller::update_wmm`, which reprograms all four
BE/BK/VI/VO rows with the same source H2C class9/function15 commands and
DONE_ACK receipts as initial setup (`rtw89_ops_conf_tx` ->
`__rtw89_conf_tx` -> `rtw89_fw_h2c_set_edca`). The QoS peer token stays
valid during the update, as in Linux; a failed or cancelled update
invalidates it and closes the station. Loss of WMM, a U-APSD change, a
change before the link is open, or a set that fails the existing EDCA
admission (e.g. ACM on BE) still closes the station. Smoke:
`smoke_rtw8852b_live_ap_edca_change_reprograms_without_reassociation`.

### Interrupt-driven runtime service (AX v0)

`irq.rs` implements Linux `pci.c::{rtw89_pci_config_intr_mask,
rtw89_pci_enable_intr,rtw89_pci_disable_intr,rtw89_pci_recognize_intrs}`
for the AX v0 layout (RTL8852A/B, and RTL8851B with
`B_AX_HS0ISR_IND_INT_EN_WKARND`). RTL8852C (`_v1`) and RTL8922A (`_v2`)
are rejected by `Mask::config` until their chip rows land. After the
retained station starts, `Bootstrap` calls `Device::arm_interrupts`, which
binds one MSI vector to the exact owned function (`rtw89_pci_request_irq`)
and enables HIMR0/PCIE_HIMR00/PCIE_HIMR10 (`rtw89_pci_ops_start`). The hard
handler only records the delivery on the shell's `irq::Line` and wakes the
drain worker; the BAR stays with the async owner. Each worker pass runs
the Linux handler/threadfn/NAPI order on that owner: disable HIMR,
recognize and write-1-clear only enabled HISR bits, drain RPQ/RXQ through
the station, then re-enable. AX MSI fires on a new masked HISR assertion,
so deferring the mask cannot lose an event. `HALT_C2H` and `WDT_TIMEOUT`
(`rtw89_ser_notify`) close the station with `station::Error::Halted`; the
generation supervisor below then performs an SER L2-style reset. TX enqueue kicks the
same line. The worker falls back to a 10ms period with MSI (host station
timers) and keeps the 1ms polled period if MSI is unavailable. `Native::fail`
turns HIMR and MSI off before BME clears and returns the vector; if MSI
disable cannot be proven, the vector is quarantined (reserved and masked).
Smokes: `drivers/wireless/rtw89/irq` (literal Linux masks, W1C ownership,
ordering, error propagation, lost-wake freedom, vector release/quarantine)
and `smoke_rtw8852b_irq_driven_worker_services_rearms_and_halts` (armed
association, RX service/rearm, TX kick, halt teardown).

### Multiple independent RTL8852B functions

Up to four admitted RTL8852B PCI functions can remain live together, matching
this family's bounded native IRQ and endpoint capacity. Each exact BDF has a
reservation before any configuration/reset access and an independent retained
reset, firmware, factory/PHY/power qualification, DMA rings, interrupt line,
controller, MLME/CCMP key/PN state and netdev generation. An in-progress claim
cannot admit a second producer; a repeat retained or quarantined BDF is
observational. Full capacity refuses a new claim before hardware access.
Pinned DMA quarantines only its original BDF; retirement compares the original
owner Arc so stale removal cannot release a replacement or another function.
This is the per-`pci_dev` ownership model of Linux
[`rtw89_pci_probe`/`rtw89_pci_remove`](https://code.googlesource.com/linux/torvalds/linux/+/c40dd8c4732551605712985bc5b7045094c6458d/drivers/net/wireless/realtek/rtw89/pci.c)
(`pci_set_drvdata`/`pci_get_drvdata`), with a bounded NARF registry.

The existing network `register_with_context` API now dispatches each netdev
through a nonwrapping, never-reused boot cookie. A stale send hook cannot
address a rebound shell. RX drain snapshots every retained endpoint, drops
its registry lock, and services all of them without short-circuiting. IRQ
slots/vectors remain separately bound to each function and the original
stop/reclamation proof still governs their release. A pending terminal,
source-capability revocation, disconnect or reset on one function grants no
progress or key/packet authority to another.

Withdrawal closes the original admission and permanently fences old carrier
metadata. An ingress callback already outside the native owner keeps its
name and dispatch reservation until callback return; stack callbacks run
without driver locks held. The last delivery completes withdrawal, and the
async bootstrap waits for it before releasing the BDF or rebinding its name.
Old drain workers and repeated removal cannot change a replacement's carrier,
registries or endpoint. System PM snapshots all retained functions behind a
new-probe barrier, parks each through the original DMA-stop path, and resumes
all. A later failure or cancellation withdraws every earlier suspend request
and releases the barrier. An unpublished reset claim makes preparation busy.

Source and fixture coverage is registered under
`drivers/wireless/rtw89/multiple`: two actual native controller/packet models
with distinct MACs and pairwise keys, independent TXBD/RPQ waits and capability
loss, production context callbacks, ingress-delayed same-name rebind and stale
worker rejection, bounded BDF claims, suspend failure/cancellation and separate
MSI delivery/release. These cases await batch validation. The diagnostic
non-B controller slot and other unimplemented chip profiles retain their
existing applicability limits; no physical multi-board acceptance is claimed.

### DMA-stop proof and reclamation (RTL8852B)

`dma_stop.rs` ports the AX stop/idle sequence of Linux v7.2
`pci.c::rtw89_pci_ops_mac_pre_init_ax`: `B_AX_STOP_WPDMA`, then
`rtw89_pci_ctrl_dma_all(false)` (`B_AX_STOP_PCIEIO` in
`R_AX_PCIE_DMA_STOP1`, `B_AX_TXHCI_EN`/`B_AX_RXHCI_EN` clear in
`R_AX_PCIE_INIT_CFG1`), then `rtw89_pci_poll_dma_all_idle`:
`rtw89_pci_poll_txdma_ch_idle_ax` polls `dma_busy1` (`R_AX_PCIE_DMA_BUSY1`,
`DMA_BUSY1_CHECK_V1` on RTL8852BE) and `rtw89_pci_poll_rxdma_ch_idle_ax`
polls `dma_busy3_reg` (`B_AX_RXQ_BUSY | B_AX_RPQ_BUSY`), each
`read_poll_timeout(.., 10, 100, ..)`. The terminal closure also sets the
full `B_AX_TX_STOP1_MASK_V1` (`rtw89_pci_ctrl_txdma_ch_ax(false)`), RXQ/RPQ
stop and clears `R_AX_HCI_FUNC_EN` DMA (`rtw89_mac_ctrl_hci_dma_trx`). All
of this runs with bus mastering still on so in-flight descriptors finish;
BME is then cleared (always, even after a busy timeout), read back off, and
a flushing BAR re-read must still show every stop bit set, HCI disabled and
all engines idle. PCIe completions cannot pass posted requests, so idle
engines observed behind verified BME-off prove no outstanding access. Only
that constructs the non-`Clone` `dma_stop::Idle`.

`Native::fail` runs this proof on RTL8852B in place of the old blind
stop/BME write (other AX chips keep the previous closure and retention).
`Native::reclaim_dma` repeats the verification under current authority and
then frees the CH12 ring and queued commands, both RXQ/RPQ rings and their
buffers (`rx_dma::Rx::reclaim_fenced`), and every BE/MGMT/AC descriptor ring
plus reserved, published or unretired packet (`packet_core::Core::reclaim_fenced`,
`tx_transport::TxQueue::reclaim_fenced`). `stop_packets` (station teardown)
and `Native::drop` call it, so normal teardown frees published DMA instead of
`mem::forget`. A busy timeout, ignored stop write, unreadable or still-set
BME, revoked authority or all-ones read keeps everything pinned exactly as
before. Smokes: `drivers/wireless/rtw89/dma_stop` (Linux order, 100us
budget, BME-off flush read, TX/RX busy, ignored stop, ignored BME, busy after
BME, gone device, verify re-checks) plus native/packet/RX reclamation smokes
(`smoke_rtw89_native_dma_reclaim_requires_verified_stop_proof`,
`smoke_rtw89_b_packet_reclaim_releases_rings_and_unretired_packets`,
`smoke_rtw89_rx_reclaim_releases_both_rings_once_and_stays_terminal`).

### Device removal (RTL8852B)

`pci::register_pci_driver` registers `bootstrap::remove` with
`narf_bus::register_pci_remove` for both RTL8852BE ids. The hook ignores a
different function and a repeated call, marks the retained `Bootstrap`
removed and spawns `finish_remove`, following Linux v7.2
`pci.c::rtw89_pci_remove`: `interface::withdraw` closes admission and
carrier and unregisters the wireless/net registries and endpoint claim
(`rtw89_core_unregister`; the drain worker exits), then the reset mutex is
taken so an accepted FLR finishes its mandatory config-silence quarantine.
`drive` now publishes the lifecycle while still holding that mutex and
re-checks the removed flag after the FLR and around shell publication, so
removal observes either the reset or the owner. The retained owner is
taken out of the lifecycle and `Owner::retire` stops the station (or the
private CH12/RX), then `station::Io::retire_dma` runs the DMA-stop proof and
reclamation (`rtw89_pci_clear_resource`), followed by the XTAL/RF shutdown.
Only a proven reclamation (or an owner that never left reset) clears
only that BDF entry in `OWNERS`, so a later probe can bind. An
unproven stop retains its entry: the address stays quarantined and a re-probe
returns without configuration access. Smokes:
`smoke_rtw8852b_remove_releases_unpublished_and_quarantines_pinned_owner`
(wrong function, unpublished release, pinned quarantine, re-probe, repeat
hook) and `smoke_rtw8852b_removal_retires_station_and_reclaims_behind_stop_proof`
(associated station retired with idle and busy DMA engines).

### Generation reset and rejoin (SER L2 equivalent)

`Bootstrap::drive` is a generation supervisor. Linux v7.2 `ser.c` escalates
unrecoverable errors (`rtw89_ser_notify`: `MAC_AX_ERR_L1_PROMOTE_TO_L2`,
`MAC_AX_ERR_L2_ERR_*`) to `ser_l2_reset_st_hdl`, which runs
`rtw89_core_stop` and `ieee80211_restart_hw` (a full `rtw89_core_start`
with firmware download). Here every generation that reached a started
station and then closed (firmware `HALT_C2H`/`WDT_TIMEOUT`, a fatal
transport error, or a disconnect) is retired under its lifecycle mutex:
`Owner::retire` stops the station, `retire_dma` runs the DMA-stop proof and
reclamation, then the XTAL/RF shutdown. `supervise` regenerates only when
the generation reached the station, the function is not being removed, the
DMA was proven reclaimed and fewer than `MAX_GENERATIONS` (64) generations
ran. `rearm` withdraws the closed shell and retires its netdev for rebind
(`interface::withdraw_keep_name` -> `narf_net::iface::retire_for_rebind`,
so the next generation's `rebind_name` registration restores the ifindex,
addresses and sockets as `ieee80211_restart_hw` keeps the net_device), drops the retired lifecycle and claims a
fresh `pci_reset::Reset` (stored under the reset mutex after a removed
check), so the next generation repeats the observed FLR, discovery,
firmware, MAC/RX, full radio and station start on the same function and
publishes a new shell on the same interface, ready to scan and
associate again. `radio_policy::Board` binds "one fresh PCI lifecycle", the
first observed FLR after boot. Every later generation is claimed with
`pci_reset::Reset::repeat`; its `Fence` carries `radio_policy::Lifecycle::Repeat`
into `Startup` and `Native`, and `Board::new_for` chains the identity with
"repeat observed-FLR PCI lifecycle v1". A reset or resumed generation
therefore needs its own signed measured record (the operating programs
chain on top of it as before); until one is installed it waits in
`Stage::WaitingAssets` and logs the exact requested identity, exactly like a
first boot without assets. An initial-lifecycle record never qualifies it.
A generation that fails before the station, an unproven stop
(the function is marked pinned and stays quarantined), removal or the bound
stops the supervisor in `Stage::Terminal` as before.

This closes `operating_reset` (automatic SER L2-style reset) and
`safe_rejoin` (a disconnect no longer terminalizes the radio for the boot;
the next generation rejoins). In-place SER L1 recovery
(`ser_l1_reset_pre_st_hdl` -> `rtw89_hci_reset` ->
`rtw89_pci_reset_trx_rings`, keeping firmware and rings) is not
implemented; every SER event takes the L2 path. A controller-level
Stopped->Passive rejoin without re-initialization is likewise not
implemented. Smokes:
`smoke_rtw8852b_generation_supervisor_regenerates_only_proven_station_closures`
(policy table, pinned retirement, removal racing a rearm) and
`smoke_rtw8852b_removal_retires_station_and_reclaims_behind_stop_proof`
(the retirement step on an associated station, idle and busy DMA). The full
FLR-to-station regeneration itself needs the physical function.

### System suspend (no WoW)

`rtw89::register` registers `bootstrap::SystemPm` with
`narf_power::system_pm::register_async_system_pm`, the async hook ath10k
also uses, because the interrupt-gated `DevicePmOps` fan-out cannot await
the retirement. `prepare_suspend` follows Linux v7.2 mac80211
`drv_stop` -> `rtw89_ops_stop` -> `rtw89_core_stop` (WoW not configured):
it sets the suspend request and closes the shell admission; the supervisor
(`generation` also checks the request between startup steps) retires the
generation behind the DMA-stop proof and `supervise` returns `Park` for any
reclaimed generation, started or not. The hook waits up to 10s for
`Stage::Suspended` or `Stage::Terminal`; on timeout it withdraws the request
and returns `Busy`, leaving the device usable as the async contract
requires. `resume_from_suspend` (`rtw89_ops_start` -> `rtw89_core_start`)
releases the parked supervisor, which claims a fresh `Reset::repeat` FLR
(the second temporal FLR of the boot) and restarts discovery, firmware,
radio and station under the `Repeat` radio identity described above.
Removal while parked stops the supervisor. A pinned generation stops in
`Terminal` and suspend proceeds with its DMA pinned and BME off. Smokes:
`smoke_rtw8852b_system_suspend_waits_for_parked_generation_or_withdraws`,
the suspend rows of
`smoke_rtw8852b_generation_supervisor_regenerates_only_proven_station_closures`
and `smoke_rtw8852b_repeat_flr_lifecycle_requires_its_own_signed_identity`.
WoW (`wow`) remains open.

### RTL8852B runtime sleep/LPS (implemented; validation pending)

The actual retained `Startup`/verified WCPU, source controller peer and
`Native` now implement clock-gated LPS for the existing live B station.
`lps_wire::Profile::from_assets` uses the selected verified inner firmware's
full W1 version tuple. The admitted WLAN-only coexistence ABI is
`0.29.29.0 <= version < 0.29.122.0`; those actual images select
`NO_LPS_PG`, clock-gated RPWM state5, and the old leave DONE_ACK. Installed
CE images `0.29.29.15` are in this scope. The old normal `0.27.32.1` image,
newer C2H-register leave ACK (`>=0.29.127`) and beacon-level producer
(`>=0.29.128`) are outside the current full-radio/coexistence adapter; their
parser/enum presence grants no native support. B's low-power HCI-mode
bitmap is zero, so this path retains its actual PCI ring geometry. B also
returns immediately from BE-only RF_PS, ML_CMN and TRX_PROTECT producers.
Other AX/BE chips retain their explicit unimplemented chip rows.

The existing N52B awake recipe and N52A/N52T record formats, fingerprints and
receive promises remain unchanged. Optional signed `N52P` v1 is a128-byte
expanded **joint** operating record at
`rtw89/rtw8852b-lps-v1-<mac>.bin`. Offsets0..57 use the companion header,
vendor/device, source identity, physical MAC and ch1/20MHz/TX-A1/RX-AB
layout;58..61 contain the exact firmware version and62..127 must be zero.
The identity binds the installed base record digest/board/full program and
signer, each actually installed N52A/N52T raw digest, selected image, exact
LPS/template/restore/coexistence recipe, and the complete joint autonomous
NULL/PS-Poll/beacon-response plus awake/tracking/aggregation peak envelope.
It must use the base signer and its existing antenna/current host-power
limits. A changed tracking window changes this digest. Missing N52P keeps
awake behavior and no PS opt-in; invalid-present records refuse admission.
This is measured deployment qualification, not invented board data. No
physical measurement or native test acceptance is claimed here.

`Device::power_save_default/set_power_save` expose only the actual loaded
native-program opt-in. The setter stores a persistent preference and wakes
the retained worker; successful metadata storage is no sleep/wake receipt.
An original weak `OpenStopTarget` is bound once to the actual netdev
registration. Before native State locks, its UP event captures the concrete
`OpenStopEvent::native_identity` weak lifetime and arms the original pump
waker. A rebind can retain actual administrative UP without a transition:
after target installation and outside native/provider locks,
`OpenStopEvent::observe` validates that exact sealed current registration
snapshot and feeds only its observed UP to the new captured target. No DOWN/
UP is fabricated; an old owner's token remains dead. A source MAC differing
from the physical device is refused. This fixed observation only denies: it supplies no administrative,
device, firmware, RF or wake grant. Synchronous DOWN/MAC/namespace/rebind
retirement closes the original token before callbacks; later UP with the
same name/index/MAC cannot revive an old sleeping owner. No source is
recaptured through a name lookup after a wait.

The same WCPU namespace reserves three distinct packet IDs0..254 before
any awaited ADD and never reuses them in that firmware epoch, including
uncertain/cancelled ADD/DEL. Exhaustion requires a fresh physical generation.
RPWM/CPWM counters also belong to that namespace and do not reset on an
association or preference change. The actual completed controller commit
supplies physical own/AP/AID and negotiated WMM: PS-Poll is16 bytes with
AID|0xc000; NULL is24 bytes; WMM QoS-NULL is26 bytes/QC7, with the Linux
plain-NULL fallback when no WMM. Actual MAC1/FW_OFFLOAD9/PACKET1 carries
RECV+DONE and requires the independently copied C2H MAC1/OFLD1/function2
matching that original ID/op and nonzero length; length is not an invented
echo requirement, including DEL. GENERAL_PKT then needs its exact native
DONE. Actual completed RX prefixes precede requests, and original peer,
firmware, interface lifetime, admission, joint program, capability and
power scopes enclose actual H2C/doorbell/MMIO and are rechecked after waits.
Templates are plaintext control/null frames without a DATA payload or host
key offload. They consume neither host DATA CCMP PN nor DATA QoS SN.

Entry requires the actual host/security/native ownership to be idle:
no pending packet/terminal reply, incoming/received/management work,
EDCA/BA setup, reorder hole, originator setup, scan or active key handshake,
and a completed RX prefix. The existing WPA2/SAE old-key-open rekey is also
busy. Actual native Core/command queues and RX assembly are independently
checked. The transition is closed before the first command. Source
WLAN-only scoreboard FWCTRL/ON updates, fixed PTA/CMAC grant readbacks and
exact OFF_BT DONE preserve the original no-independent-BT/PTA program;
no adaptive BT or unmeasured RF alternative is introduced. LPS H2C precedes
RPWM; proposal metadata grants no hardware readiness. Awaited coexistence and
command-credit work cannot reuse a stale idle check: a new completed prefix
is required after OFF_DONE and the native ENTER path checks HCI/backlog again
inside its actual final publication scope, after allocation and credit waits.
`power::Error::Busy` here proves no descriptor/doorbell publication occurred;
it restores only nonemitting coexistence state and defers to the original
host controller. Current device/binding/joint-program scopes enclose both
the final guard and the subsequent queue issue/publication. A denied final
guard leaves the queue pristine and ring/doorbell unchanged; after queue
issue, an ambiguous error keeps its actual mappings and terminalizes. An ambiguous command/publication still terminalizes. RPWM toggles from the
actual register with the original next request; only nondeep requests set
ACK. Deep requires actual LDM32K. Wake captures one CPWM16 observation and
checks exact original request/next-response/state together; failed polls
consume no response counter. Three bounded15ms attempts preserve the
source10us enter/150us leave poll periods.

Ordinary packet/control publication and every BB track read/write remain
closed through actual CPWM Active, source PHY environment/PHYSTS restoration,
leave DONE_ACK and MACID0 `0xca0c & 0xe == 0`, then coexistence restoration.
A transient firmware-clear LDM bit alone cannot open them. Synchronous drain
skips a sleeping/uncertain owner; it cannot perform an implicit wake or RF
tracking. The retained async worker wakes for original MSI/TX kicks,
actual HCI RX producer/backlog observations even in polled mode, host queued
DATA/control, BA deadlines and due periodic/enhanced tracking. Its100ms
sleep backstop checks fixed current sources/HCI without reading BB or
wake-spinning every millisecond. The shared Line is a scheduling hint, not
an unconditional RF-wake request. The retained native path masks/recognizes/
acknowledges/rearms actual IRQ causes and checks concrete HCI/backlog work;
consumed own transition DONE interrupts with no pending work stay asleep.
After transition receipts, the worker samples the Line counter and then
rechecks original source/native/host work before waiting: earlier real work
is found by that check and later raises remain newer than the wait baseline.
Fatal/stuck/unavailable native causes take terminal cleanup. New RX received during entry is serviced
after the wake; the existing ordinary RX-prefix admission still precedes
host DATA/security publication. Queued originals survive and are protected
only after actual wake and ordinary admission. Neither DATA PN/SN nor an
old installed key is reconstructed on resume.

A wake/leave can emit an installed NULL, so dead interface/peer/device/RF
sources never borrow cleanup permission to wake. Deep/interrupted ordinary
stop instead retains mappings and closes the producer. Actual still-current
device authority can retire the same owner via a nonemitting retained PCI
FLR, with IRQ release **before** its quarantine. `Reset` is stored before
await; ordinary, packet/control cleanup, fail/drop and analog shutdown cannot
access config/MMIO while it is retained. Only its sealed successful
same-function temporal fence can release the old DMA. Cancellation or a
missing device capability retains uncertain mappings. No BME-off, metadata
bool or proposed reset frees them. The original generation's asynchronous
shutdown uses this path for removal/system suspend; retirement is sampled
after the awaited physical proof before existing fresh-generation restart.
A replacement still needs its independent repeated-lifecycle qualification;
old namespaces/programs are never reopened.

Seven new source cases cover actual controller peer/template envelopes,
independent ACK/C2H and non-echo DEL, signed joint artifact/window binding,
RPWM/atomic CPWM/retry/restore, original source loss at waits, dropped ADD and
RPWM owners/IDs, public WPA2/CCMP DATA PN/SN continuity, actual polled RX wake,
DOWN/UP denial with no NULL leave, consumed-DONE worker stability, and actual
raw deauth arriving during OFF_DONE/credit waits without ENTER publication.
An existing LPS registration also executes the actual retained
`Native`/`NativeIo` and command queue against inert MMIO/DMA and authenticated
record/controller boundaries, including late final-producer Busy without
queue/ring/doorbell change, original current program/peer/UP refusal, closed
BB tracking and actual sealed FLR binding/failure. These boundaries grant no
real attach/calibration or physical measurement. Preserved-UP generation
rebind is covered without an administrative toggle. Existing cases/
registrations remain.
They have not run; release metadata/native two-arch/physical gates remain
pending. Primary reference: local Linux7.3-rc4
`rtw89/{ps.c,mac.c,fw.c,fw.h,phy.c,coex.c,rtw8852b.c,rtw8852be.c}` and
`mac80211/{tx.c,rx.c}`. Source hashes and exact selected-image evidence are
preserved with the source handoff.

### Receive-only RTL8852B monitor (implemented, acceptance pending)

The admitted RTL8852B channel1/20MHz full-radio owner now exposes the existing
shared monitor interface: down-only `SET_INTERFACE` station2/monitor6,
`SET_WIPHY` with exact2412/20NOHT-or20/center2412 geometry, and AF_PACKET raw
radiotap ingress. Monitor advertisement appears only after this actual
owner has completed full-radio admission. Explicit CONTROL/OTHER_BSS flags
are supported by the receive profile; bad-FCS/bad-PLCP/cooked/active/injection
requests are refused. Other channels, widths and chips keep their separate
rows. Station scan/association/configuration, Ethernet TX/rings, power-save,
packet peers, keys and packet-TX Core cannot become monitor authority.

`monitor::Desired` retains only mode metadata and a monotonic role generation
in the actual physical supervisor. A down-only mode change closes the old
admission before changing representation. The supervisor retires the original
station/key/queue owner, retains uncertain DMA, earns its actual stop/FLR fence
and starts a fresh qualified physical generation with the same interface
name. The retiring original shell may acknowledge the exact fixed ch1/20
channel metadata immediately after the mode ACK, using its retained sealed
registration/UP event; it cannot follow a replacement registration. No lookup,
retune, new grant or native readiness is implied by either ACK. DOWN retires capture synchronously;
UP on that old owner never revives it. A replacement registration must bind
its own concrete receiver, observe its own actual administrative UP (including
an actual preserved-UP rebind) and complete independent native receipts.

The same retained `Startup/Firmware/Native` configures firmware role MONITOR7,
SELF_ROLE_NONE0 and disconnected NoLink, with actual MACID-unpause applied
state, role/JOININFO/CAM/default-CCTL DONE receipts. Before role, port,
filter, crypto or PHYSTS changes it proves actual CMAC TX bit29 is disabled;
it remains disabled through capture and stop. Sniffer mode forwards management,
control and data to host with address/BSSID/CAM filtering relaxed, error-frame
and hardware-decryption paths closed, source AX PHYSTS IE09/IE10/IE13/IE20
page programming and masked/full readbacks. No packet-TX owner is installed.
The original admission and disabled-CMAC-TX readback also enclose final native
CH12 descriptor/doorbell publication after credit/command waits. Polled
capture checks actual HALT/WDT status even without an MSI binding.

The receive-only mode performs no RF retune, new calibration, injection or
autonomous response. It retains the completed original base full-RFK/channel,
firmware/device and current host/power proof throughout. Existing N52B/A/T/P
bytes and program fingerprints are unchanged. No new measured-peak companion
is required for parsing/capture: this separate nonemitting mode contract
cannot expand or reinterpret any emitter grant. If a future transition changes
an emitting/calibration program it needs that actual program's admission.

Before opening its private capture epoch, the Native reads actual pathA/B
legacy/direct RF channel registers0x18/0x10018 and proves the occupied
channel1/20MHz configuration, then retires a bounded actual completed RX
prefix, including partial/dropped progress and pre-start copied events.
Only that same Native can mint the original fixed capture source. RXBD/RXD
assembly preserves original MPDUs, strips exactly four actual FCS bytes,
accepts ten-octet ACKs and keeps protected ciphertext raw. CRC/ICV failures,
hardware-decrypted/A-MSDU-cut bytes and unsupported PHY layouts are dropped.
Radiotap includes the sealed actually observed channel and original frame
flags. Uncorrelated PHY signal/rate/GI/TSF metadata is omitted; PHYSTS from
another PPDU is never attached to a frame.

The worker begins the existing `MonitorRxToken` only after native receipts
and a recheck of the original actual registration/UP event outside Native
locks. It formats copied frames after releasing lifecycle/native locks, then
reinvokes the fixed original device/base source, role/admission/capture epoch
and exact provider token immediately around raw ingress. No Ethernet/IP
fallback or name/namespace rebind occurs. DOWN, mode/source loss, fatal RX,
removal and cancellation close epochs; nonemitting device-only cleanup remains
available after RF source loss, and uncertain published mappings stay retained.

Four new source cases cover literal role/filter/PHYSTS/crypto receipts and
readback/ACK/source failures, actual Native/NativeIo no-TX/owner/queue boundaries,
actual RXBD/FCS/control/protected/error admission, public monitor flags/channel/
UP/raw-socket delivery and injection refusal, original source retirement,
DOWN/UP nonrevival, fresh registration/copy ownership and monotonic role
selection. Inert RAM, authenticated-record/full-RFK and RF-observation fixture
boundaries confer no real attach or measurement. All prior registrations are
retained. Release metadata, native two-architecture and physical validation
remain pending. Primary source: local Linux7.3-rc4 `rtw89/{mac80211,core,mac,
phy,fw,cam,txrx,reg}.c/.h`; exact hashes accompany the handoff.

### RTL8852B software fragmentation (implemented; acceptance pending)

The admitted channel1/20MHz RTL8852B station now has explicit native TX and
RX fragmentation owners. This current contract supersedes the historical
`fragmentation` blocker notes below. Other chips, channel/width transitions,
MLD, four-address, A-MSDU/A-MPDU and +HTC fragment forms gain no admission.
Ordinary unfragmented entry points retain their original fragment rejection;
only the bound fragment path may publish original More-Fragments/nonzero
fragment numbers. Existing HT/HE receive A-MSDU promises remain unchanged.

Linux7.3-rc4 `net/mac80211/{tx,rx,wpa}.c` splits plaintext before encryption:
the threshold includes the plaintext MAC header/body and FCS, then CCMP adds
16 octets per fragment. One logical MSDU uses one host SN, frag0..15, and a
fresh PN per protected MPDU. Open DATA/unprotected unicast management use the
same bounded plaintext split. Protected robust management uses the original
installed PTK and management CCMP nonce, with the caller's one management SN.
The actual B TXWD fragment formatter keeps software sequence mode even on
MGMT8, fixes CCK1/long preamble, leaves hardware crypto disabled and preserves
all original fragment fields. A2346 plaintext threshold can produce a2358-byte
protected MPDU excluding FCS; this separate bound is enforced consistently in
the train binding, descriptor formatter and native fragment RX, without
broadening the2304-byte ordinary profile.

The separate optional signed `rtw89/rtw8852b-fragment-v1-<MAC>.bin` is N52F:
128 bytes, version1, exact original device/MAC/channel1/20/TXA1/RXAB profile,
maximum threshold2346, maximum16 fragments, CCK1 rate0, profile flags3 and host
management sequence mode1, with all remaining reserved bytes zero. Its binding
hash includes the unchanged installed N52B record digest, board/firmware/full
program identity and signer, each actual N52A/N52T companion digest, canonical
accepted N52P digest when present, and the full fragment/rate/NAV recipe.
This is a full joint emitter qualification; old flags/enum values cannot
promote a nonfragment-only measured program. Absence preserves old ordinary TX
and advertises no fragmentation setter; invalid-present or revoked original
programs refuse admission. All original device/base/A/T/P/F capability scopes
stay finite and nonrecursive through actual publication. No new RF measurement
is invented for receive-only parsing/reassembly under the unchanged original
base/native PHY/source admission.

The station captures an opaque binding to the SAME actual device capability,
qualification object, controller peer and source admission before any crypto,
PN or SN. A management input that encounters a late prefix/credit refusal
retains its original unprotected logical bytes until that same owner is quiet,
without assigning SN/PN. The complete immutable train and original key-color denial proof are
retained once before first issue. Native queue pressure or a final completed
RX-prefix refusal reuses these exact bytes. Every part is one-shot: prepared
and issued checks differ, descriptor/ring publication records issued ownership
before any descriptor write, and the final native doorbell rechecks the
original issued part AND actual pending RX/backlog inside its actual fixed
capability scopes. After all other queries/callbacks, the last pre-issue native
RX/backlog check immediately precedes issue; a strictly unpublished Busy aborts the reservation without
ring/doorbell/part advancement. New pending input at the final doorbell after
issue is terminal/retained, never converted to unpublished Busy; failures after
issue retain uncertain DMA and close admission. Neither TXBD consumption nor firmware RPQ alone advances the
train. Only the exact same body/identity with BOTH actual DMA consumption and
successful RPQ release advances to the next original MPDU. Key/peer/source or
physical owner loss denies future parts; cleanup can retire terminal ownership
without manufacturing a new emission grant.

The whole logical input is consumed from its FIFO once the driver retains its
complete train. Later frames/aggregation cannot pass it. An actual operational
originator BA MPDU remains DONTFRAG, as in mac80211; a partial fragment never
enters an A-MPDU/A-MSDU. A rekey that closes the port before the first issue
retires prepared data; an already-started original MSDU can drain its retained
old-key fragments before serialized M2/M4 while that exact old key remains
installed. Peer loss is processed before any continuation. A management train
keeps later MLME input waiting until its actual terminal publication receipts.

Native RX preserves each original descriptor-admitted header and rejects actual
A-MPDU fragments before BA reorder. Secure DATA/EAPOL and unicast management use
the original shared Security cache: FOUR total slots, two-second first-fragment
lifetime,4096-byte complete limit, exact original peer/header/type/TID/SN and
consecutive fragment numbers; CCMP additionally authenticates each original
header with the same key color and consecutive PN. Plain/protected/key epochs
cannot mix. Completed EAPOL runs the same nonce/MIC/replay/RSN verifier and
requires actual terminal key-install/port receipts. Unprotected management
retains the same pre-key/nonrobust/PMF rule; installed-PTK plaintext robust
frames remain denied. Open links have a separate lazily boxed four-slot
plaintext owner only while no Security owner is active; no plaintext result
can become a cryptographic proof. Original source/association retirement clears
these caches. Pending TX trains or RX caches block LPS; ordinary/control/BB
operations still require completed awake/restore receipts and the original
full joint program.

`fragmentation_threshold` / `set_fragmentation_threshold` publish the existing
nl80211 SET_WIPHY contract only with this actual signed native support. Values
256..2346 round down to even; `u32::MAX` disables future fragmentation. A fixed
physical preference survives actual supervisor rebind/reset and monitor→station
replacement, but grants no native readiness or RF operation. Only a fresh
actually qualified generation uses it; old role/source shells cannot retarget
its replacement. The station samples one preference for each new logical input;
changes never rewrite an owned train or consume another PN/SN on retry.

Eight additional source cases cover N52F identity/revocation, actual Native/
NativeIo/Core descriptor/DMA/RPQ and final-producer fences, public Open/WPA2
threshold/immutable terminal trains, original RX MIC/PN/timeout with no TX
companion, actual PMF2346→2358 management/software-SN, operational BA DONTFRAG,
source retirement, and genuine fragmented initial M1/M3 plus dropped held-M4
ownership. All old literal registrations are retained. Cases and physical
acceptance are pending; no native pass or throughput claim is made here. Exact
local Linux file hashes accompany the source handoff.

### RTL8852B noninitial 2.4GHz/20MHz retune composition (partial; no native caller)

`operating_channel::Profile` is the typed 2.4GHz/20MHz primary (1..=14, any
other band refused) with the Linux 7.3-rc4 rtw8852b_common.c SCO barker/CCK
thresholds, `rtw8852bx_sco_mapping` compensation, CCK TXFIR / tx-shape DFIR
(flat/sharp, sharp_14 for 14) and rtw8852b_rfk.c `_tssi_get_{cck,ofdm,trim}_group`.
`radio_power::Plan::from_assets_for_channel` selects that primary's WW0 limits
and RU limits (`operating_power_defaults.rs`, all 14x2 rows machine-compared to
rtw8852b_table.c) and binds a distinct noninitial header plus the profile;
channel 1 keeps its original binding bytes. The v2 `radio_policy::Board`
constructor refuses any noninitial plan, so no old channel-1 qualification is
reinterpreted.

Step owners take the profile and keep their channel-1 wrappers unchanged:
`channel_bb::prepare_for_channel` (`__rtw8852bx_set_channel_bb`, critical
readback of `B_CH_IDX_SEG0` = `rtw89_encode_chan_idx` = actual primary),
`channel_rf::prepare_for_channel` (`_ctrl_ch`/`_ch_setting` CFGCH field and
readback), `iqk::prepare_for_channel` (`_iqk_get_ch_info` R_IQKCH channel;
RFK MCC table index 0 is retained for one retuned entity per
`rtw89_rfk_chan_lookup`), `tssi::prepare_for_channel` (`_tssi_set_efuse_to_de`
groups; 2.4GHz system/thermal/slope/alignment-default tables are
channel-independent; alignment is re-measured, never reloaded from another
channel) and `rfk::ChannelRxDck::prepare_with_tssi` (`_rx_dck` pauses
`B_P0_TSSI_TRK_EN` while the previous channel's TSSI is enabled).

`radio_full::Radio::retune` runs on a Ready owner only, in Linux order: core.c
`__rtw89_set_channel` (transition enter, MAC/BB, RF, set_txpwr, transition
finish; same band so no `rtw89_chip_rfk_band_changed` TSSI scan) then rtw8852b.c
`rtw8852b_rfk_channel` (RXDCK, IQK, 30ms, TSSI, 30ms, DPK; 8852B DPK reload is
disabled so DPK recalibrates). Init-only power reference, trim and RX-AB are
not repeated. It fresh-starts every step owner, so earlier results retire;
`channel()` is the completed typed channel and `epoch()` counts completed
programs (initial = 1). The channel programmed is always the one bound in the
power plan. Failure or cancellation leaves the radio non-Ready.

Remaining before the `additional_operating_channels` row is whole (no row
credit): a signed per-channel full-program qualification/record replacing the
v2 channel-1 Board for noninitial plans; the native `command_native` retune
owner (drain ordinary TX/CMAC/autoresponse, call `Radio::retune` under the
current host occupied-span permission, republish the retained retune epoch to
RF tracking/LPS/monitor/station consumers, reopen queues); scan/association
over channels 2..13 with per-channel N52B/HT/HE operating programs; and native
two-arch plus physical validation. Channel 14 stays unadvertised. Five new
cases are written and unexecuted:
`smoke_rtw89_b_operating_profile_matches_linux_groups_and_refuses_other_bands`,
`smoke_rtw89_b_power_plan_selects_actual_primary_limits_fir_and_binding`,
`smoke_rtw89_b_channel_bb_programs_and_reads_back_each_actual_primary`,
`smoke_rtw89_b_rf_synth_tunes_and_reads_back_each_actual_primary`,
`smoke_rtw89_b_full_radio_retunes_ready_owner_to_actual_primary_and_advances_epoch`.

#### Signed per-channel program, native retune owner and multi-channel station

**Per-channel qualification (N52C).** `radio_policy::Board::new_noninitial`
composes a noninitial identity exactly like the v2 channel1 `Board` (same
factory, firmware PHY_CAP, recipe list, `Plan::bind`, lifecycle) but over
`Plan::from_assets_for_channel` for primaries 2..=13 (Linux rtw8852b_table.c
WW0/RU rows, rtw8852b_common.c SCO/FIR, rtw8852b_rfk.c TSSI groups), under a
distinct domain string; channel1 and channel14 are refused. The optional
signed record `rtw89/rtw8852b-chan-v1-chNN-<mac>.bin` (`channel_policy.rs`,
magic `N52C`, 128 bytes, `[54..58] = [1,20,primary,base flags]`) binds that
identity extended by the base program flags (so per-channel WMM/QoS/RA/HT/HE/
A-MPDU program identities), the exact base record digest/signer, and every
installed companion (N52A/N52T digests, N52P/N52F canonical bindings). Its
signer must equal the base signer; it carries its own antenna/ceiling/peaks.
`Qualification::select` switches the envelope gating every publication
(`current`/`with_current`) to the target record, checked against the current
host rule over the primary's whole occupied span (`Profile::occupied`); a
failed select restores the previous primary. A changed companion set or a
revoked record retires the channel (`channel_allowed`). Records are loaded
last in `preflight_full_radio`; absent records leave a primary unadmitted. No
hardware receipt or measurement is invented: without provisioned signed
records only channel1 is admitted, exactly as before.

**Native retune owner.** `Native::retune_full_radio` (via
`Startup::retune_channel` and `station::Io::station_retune`) mirrors mac80211
`ieee80211_offchannel_stop_vifs` + `drv_flush` (rtw89_ops_flush), then
`rtw89_ops_config` (`rtw89_leave_ps_mode`, `rtw89_set_channel`) and
`rtw89_chip_rfk_channel` (`rtw8852b_rfk_channel` ending in
`rtw89_fw_h2c_rf_ntfy_mcc`), then `ieee80211_offchannel_return`. It rebuilds
plan/identity from the actual factory/assets and requires the signed record
to match; refuses (`Busy`/`Unsupported`, grant still installed, owner not
terminalized) unless the H2C queue, RX backlog and ordinary TX are drained,
the radio is awake, and no peer, monitor or sleep owner exists, so no LPS/
monitor/station consumer holds previous-channel results. It then withholds
the ordinary grant, selects the target envelope, runs `Radio::retune` (whose
`rtw8852bx_set_channel_help` bracket stops CMAC scheduler TX, PPDU status
and ADC, closing autonomous responses), sends RF_GET_MCCCH for the new
primary (slot0 replaced per `rtw89_rfk_chan_lookup`), rebuilds the periodic
DPK tracker from the fresh DPK baseline, republishes `(primary, epoch)` and
reinstalls the grant. Any failure after the grant is withheld terminalizes.

**Station and interface.** `station::State` tracks the retained primary and
epoch: observation, WMM refresh and probe DS Parameter Set use it;
`scan_channels` mirrors the mac80211 software scan (set channel, probe,
dwell per primary); `associate` retunes to the BSS's own primary (1..=13)
before joining and track statistics reset on retune. The interface samples
the admitted mask (`station_channels`) at activation, advertises only those
primaries, maps nl80211 channels/frequencies (empty = all admitted), refuses
unadmitted primaries before any retune or probe, reports the BSS's actual
channel/frequency and accepts association on an admitted primary.

Unexecuted cases of this step:
`smoke_rtw89_b_channel_record_binds_noninitial_identity_signer_and_occupied_span`,
`smoke_rtw8852b_scan_retunes_admitted_channels_and_associates_on_noninitial`.

#### Operating profile, associated channel switch and noninitial monitor

**Operating programs per primary.** No operating program is a channel1
identity on a noninitial primary: the N52C identity is
`Board::new_noninitial(..).with_programs(base flags)`, i.e. the WMM, all-AC
QoS, firmware RA, HT20, HE20 and originator BA/A-MPDU recipe chain
(`Program::extend`) applied to that primary's own full-radio identity, and
the record's byte57 must equal the base flags. `Qualification::allows`/
`wmm_allowed`/`amsdu_allowed` sample `current()`, whose envelope is the
active primary's N52C record, so every program publication on primary N is
gated by N's signed measurement. The programs' wire contents (HT/HE
capability IEs, H2C RA/CMAC/join, BA CAM, EDCA) are channel-independent at
2.4GHz/20MHz on 8852B, as in Linux (rtw89_fw_h2c_ra, rtw89_fw_h2c_assoc_cmac_tbl,
rtw89_fw_h2c_ba_cam carry no channel); 8852B LPS sends no channel H2C
(`rtw89_fw_h2c_lps_ml_cmn_info` is BE-only, `LPS_CH_INFO` is 8922A-only),
and N52C binds the installed N52P/N52F/N52A/N52T companions.

**Associated channel switch (CSA).** `station::State::observe_csa` mirrors
mac80211 `ieee80211_sta_process_chanswitch` for a bound peer beacon on the
current primary: `channel_switch` parses ECSA(60) in preference to CSA(37)
(`ieee80211_parse_ch_switch_ie`); an ECSA class outside 81..=84, channel14
or an unadmitted primary drops the connection ("switches to unsupported
channel"); the current primary is ignored; the switch time is
`(max(count,1)-1) * beacon_int` TU; `mode` is `csa.blocked_tx`. The 20MHz
link stays 20MHz on the target (CSA chandef downgraded to the connection
mode), so secondary-offset/wide-bandwidth elements are unused. While active,
a beacon without CSA aborts (`ieee80211_sta_abort_chanswitch`) and the first
beacon after the switch ends it (`ieee80211_chswitch_post_beacon`,
`waiting_bcn`), then is processed as a fresh beacon. TX is refused (`Busy`)
while blocked or once the switch time passed, and LPS is not entered while
a switch is pending. At the switch time the async worker
(`State::switch_channel`, `ieee80211_csa_switch_work`) waits for every TX in
flight to retire, then calls `Io::station_switch_channel` ->
`Startup::retune_channel(primary, linked = true)` ->
`Native::retune_full_radio(.., linked)`, the rtw89 chanctx path
(`rtw89_ops_switch_vif_chanctx`/`rtw89_chanctx_ops_reassign_vif` ->
`rtw89_set_channel` + `rtw89_chip_rfk_channel`). With `linked` the installed
peer must exist and stays installed; every other native refusal (drained
H2C/RX/TX, awake, no monitor/sleep owner, signed N52C match, grant
withheld for the program) is unchanged. `Busy` retries on later worker
passes for one second past the switch time, then the link fails. Success
restarts the beacon monitor and track statistics and moves the peer's
channel. No `NL80211_CMD_CH_SWITCH_STARTED/NOTIFY` is emitted: the shared
`WirelessNetIface` has no station channel-switch event yet.

**Monitor on a noninitial primary.** `monitor_wire::channel` maps an exact
NOHT/HT20 2.4GHz chandef to its primary 1..=13 (wider/other bands refused,
never narrowed); `set_monitor_channel` accepts only an advertised (signed
admitted) primary and stores it in the monitor `Selection` (`primary`).
A different primary bumps the selection generation and closes the shell,
so the supervisor retires the old capture and starts a fresh generation
(mac80211 monitor chandef -> rtw89 chanctx `rtw89_set_channel`).
`Startup::start_monitor` retunes that fresh generation to the selected
primary before any monitor role/filter exists (no peer, no monitor owner),
then the RF observation requires all four CFGCH readbacks to equal
`0x1c00 | primary` (`_ch_setting`/`_bw_setting` 20MHz) and capture metadata
reports `monitor_wire::frequency(primary)` of the source's selection.

Remaining for this row: provisioning tooling for N52C records (the binding
is derivable from the loaded base via `channel_policy::Request`, but no
native request API reports it), firmware hw_scan offload, and all native
two-arch execution and physical validation. Unexecuted new cases:
`smoke_rtw8852b_associated_csa_retunes_with_peer_and_unblocks_on_target_beacon`,
`smoke_rtw8852b_csa_parse_and_monitor_primary_follow_linux`.

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

The hardware tables, register constants, recipe digests and regression fixtures
are checked-in Rust data. Frozen references retain their source citations and
existing SHA256 provenance in `src/rtw89/REFERENCE_FIXTURES.md` and the individual
files. The Python/C extraction, generation and temporary-compiler pipelines have
been removed. Native Rust tests require no Python, C compiler or Linux checkout,
and compare with stored expected values rather than executing another driver.
A reference change requires source/hardware contract review; recalculating its
expected values from the Rust code under test is not validation. These fixed
references do not prove continuing equivalence with an external Linux revision
or physical hardware acceptance.

## 8. Open questions / remaining software

| Prerequisite | State |
|---|---|
| AX DDV factory identity and cleanup | Implemented; shared-path regressions |
| Initial B power/PCIe initialization | Retained actual cold/firmware/MAC/RX/full-radio/ordinary BE/MGMT startup and probe integration implemented; selective source PCI setup is bounded to this awake polled profile |
| Firmware container/profile selection, CH12 DMA, WCPU handshakes | Checked AX selection, native fuse reads, coupled secure plans, native CH12 ownership and retained WCPU loading implemented; owned cold-to-CH12/WCPU composition and TX-only BME activation implemented; initial B packet/RF startup is implemented; A/51 secure-policy loading remains outside the initial profile |
| Initial B reset, rings and ownership | Actual temporal FLR or explicit trusted platform reset contract; retained BDRAM/CH12/RX/RPQ plus fresh BE/MGMT rings and terminal storage ownership implemented. AX v0 MSI delivery and proven DMA reclamation implemented; recovery remains separate |
| Initial B native TX and bounded completion | Exact source TXWD/BD/WP/address-info and joint TXBD/RPQ retirement are activated by the same retained station owner;512 nonreused identities per queue |
| RPQ release handling, RX assembly/validation and frame delivery | B retained native RXQ/RPQ publication/polling, checked segmented RX/FCS, RPQ records and bounded C2H/ACK decoding implemented; same-owner packet completion dispatch, raw station frame delivery and kernel DHCP/IP are implemented |
| RF/BB calibration, regulatory channel/power and coexistence | Initial B actual factory + firmware PHY_CAP, static PHY operating/XTAL, WLAN-only coexistence, NCTL/basic RFK, channel MAC/BB/RF/scheduler/ADC, actual trims/RXAB, IQK/TSSI/DPK and real source power-table composition implemented. Separate signed measured v2 binds all calibration/packet/autonomous-response peaks and actual source recipes; native publication uses current signed/device invocations. Broader AX/BE profiles, host periodic RF tracking/retuning and physical measured qualification remain outside this initial profile |
| Initial B scan, MLME, WPA2 and Ethernet | Source controller plus shared host MLME/RSNA/CCMP, exact M4/RX-idle admission, kernel DHCP/IP, rekey and terminal disconnect/cancellation are implemented; physical acceptance remains |
| BE EFUSE/block format and BE transport | Missing |
| Broader lifecycle | Initial independent reset, terminal ownership, proven-reclamation removal, SER L2-style generation reset/rejoin and no-WoW system suspend implemented; in-place SER L1 recovery and WoW remain outside this first profile; independent live RTL8852B functions are implemented below |

The per-chip source `rtw_chip_info` inventories are broader than this station:
8851B declares1TX/1RX and2.4/5GHz;8852A/B declare2TX/2RX and2.4/5GHz;
8852C declares2TX/2RX and2.4/5/6GHz;8922A declares2TX/2RX and2.4/5/6GHz
with its distinct BE generation. B now has signed-program HT20, HE20 (with
firmware GI/LTF selection), all-AC/TID QoS, firmware RA, recipient
BA/reorder, MSI delivery, live EDCA and active channel-1 scans (section 3);
HE +HTC and originator TX A-MPDU are now implemented. It still needs wider
widths, other channels, WoW and in-place SER L1 recovery. The admitted B
runtime-sleep source path below is implemented pending validation. A/C/51 need complete chip-specific
firmware/security, BB/RF/power/packet/station composition;8922A additionally
needs BE EFUSE/container/descriptor/transport and EHT operation. Source band
masks make6GHz inapplicable to A/B/51, not to C/8922A. These are remaining
software dependencies, not implementation-complete hardware capability claims.

References: Linux `rtw89/efuse.c`, `rtw8852a.h`, `rtw8852b_common.h`,
`rtw8852c.h`, `rtw8851b.h`, `core.c::rtw89_core_get_ch_dma`,
`pci.c::{rtw89_pci_txwd_submit,rtw89_pci_release_txwd_skb,rtw89_pci_fill_txaddr_info,rtw89_pci_fill_txaddr_info_v1}`,
and per-chip PCI configuration.

### Open rows: verified blockers (2026-10-28)

Each blocker below was re-checked against this tree.

| Row | Concrete blocker |
|---|---|
| `eht` | Needs the RTL8922A chip row first. `efuse.rs` returns `UnsupportedChip` for 8922A, `irq::Mask::config` rejects the `_v2` layout, there is no BE TXD/RXD (`txrx.h` `BE_TXD_*`) or BE RA H2C (`rtw89_h2c_ra_v1`, `RTW89_H2C_RA_V1_W4_MODE_EHT`), and `station_control::Controller::new` plus the `N52B` qualification record are RTL8852B-only. The shared `association::eht` API is not the gap. |
| `aggregation` | Source complete for the admitted RTL8852B HT/HE20 owner; TX A-MSDU and A-MSDU-in-A-MPDU now use the separate current signed full-program companion, original FIFO prefix, peer/BA/current RC bounds and actual one-MPDU DMA/terminal ownership described in §3. Software/native/physical validation remains pending; other-chip runtimes stay on their separate chip rows. |

| `he_htc` | Implemented in HE recipe revision2 above; six native/shared regressions pass on both architectures. Row closed2026-10-29. |

### Upstream applicability triage (2026-10-27)

This subsection resolves the former `unknown` inventory rows against Linux
v6.12 `rtw89/{core.c,mac80211.c,rtw8852b.c,rtw8852c.c,rtw8922a.c}`. It
records applicability only; nothing below is implemented by this change.

| Former row | Resolution and evidence |
|---|---|
| `additional_phy_widths` | `wide_channels`: per-chip `support_bandwidths` is 20/40/80MHz on 8852B and adds 160MHz on 8852C and 8922A; `core.c::rtw89_init_ht_cap` adds `SUP_WIDTH_20_40`/`DSSSCCK40`/`SGI_40`. `he_gi_ltf`: HE/EHT 0.8/1.6/3.2us GI and LTF variants from `rtw89_init_he_cap`. Both remain feature work. |
| `aggregation_directions` | Removed; directions are now named on existing rows. `mac80211.c::rtw89_ops_ampdu_action` starts TX BA immediately and programs `rtw89_chip_h2c_ampdu_cmac_tbl` on `TX_OPERATIONAL`/`TX_STOP_*` (`block_ack` originator), and programs firmware BA-CAM through `rtw89_chip_h2c_ba_cam` on `RX_START`/`RX_STOP` (`block_ack` recipient). `TX_AMSDU`/`SUPPORTS_AMSDU_IN_AMPDU`/`AMPDU_AGGREGATION` define `aggregation`; host reorder remains `rx_reordering`. |
| `broader_scan_policy` | `rtw89_core_register_hw` declares firmware scan offload (`rtw89_ops_hw_scan`, `SCAN_OFFLOAD` firmware feature), `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR`, `NL80211_EXT_FEATURE_SCAN_RANDOM_SN`, `NL80211_EXT_FEATURE_SET_SCAN_DWELL` and `max_scan_ie_len = RTW89_SCANOFLD_MAX_IE_LEN`. Named rows: `active_scanning`, `randomized_scan_mac` (MAC and sequence number), `scan_dwell_control`, `scan_probe_extra_ies`; 6GHz split scan stays in `six_ghz_operation`. |
| `fragmentation_scope` | `fragmentation`: rtw89 sets no `SUPPORTS_TX_FRAG`, so upstream fragments and defragments in mac80211 software and the driver transmits/receives individual fragment MPDUs. The remaining work is host fragmentation/defragmentation plus native TXWD/RX admission of nonzero fragment numbers and More-Fragments. |
| `monitor_diagnostics_scope` | `monitor_mode`: `WANT_MONITOR_VIF`, and `IEEE80211_CONF_MONITOR` branches in `rtw89_core_parse_phy_status_ie01`/`rtw89_core_update_rx_status_by_ppdu`, make monitor a real radio mode with PHY-status RX metadata. Noise-histogram/CLM/FAHM measurements run from `rtw89_track_work` via `rtw89_phy_env_monitor_track` and stay in `nhm_diagnostics`. |
| `optional_header_scope` | `he_htc`: `IEEE80211_HE_MAC_CAP0_HTC_HE` is advertised and `__rtw89_core_tx_adjust_he_qos_htc`/`rtw89_core_get_no_ul_ofdma_htc` insert HE +HTC into QoS DATA. Four-address headers are inapplicable to the upstream station: `interface_modes` is STATION/AP/P2P only and `wiphy->flags` lacks `WIPHY_FLAG_4ADDR_STATION`, so cfg80211 refuses `use_4addr`. |
| `protected_management_scope` | `pmf`: `MFP_CAPABLE` is declared; `rtw89_core_tx_update_mgmt_info` hardware-encrypts unicast robust management when `hw_mgmt_tx_encrypt` (true on 8852C/8922A, false on 8852B, where host CCMP/BIP applies). |

Refined feature rows: `wow` is declared by at least 8852B and 8852C
(`wowlan_stub` under `CONFIG_PM`). `tspec` has no rtw89 driver hook
(`mac80211.c` has no TSPEC path); WMM admission control is mac80211-owned
host MLME work on top of `wmm_all_access_categories`.

Resolved 2026-10-28 against Linux v7.2 (rows removed or narrowed):
`tspec` is inapplicable — rtw89 never sets
`NL80211_FEATURE_SUPPORTS_WMM_ADMISSION`, so `nl80211_add_tx_ts` refuses
ADD_TX_TS and mac80211 never originates ADDTS. Station U-APSD is
inapplicable — `rtw89_ops_add_interface` sets only `BEACON_FILTER` and
`SUPPORTS_CQM_RSSI` (no `IEEE80211_VIF_SUPPORTS_UAPSD`); `uapsd` now tracks
only AP-side U-APSD (`WIPHY_FLAG_AP_UAPSD`). `nhm_diagnostics` is removed:
NHM needs `chip->support_noise`, true only on RTL8852A (folded into the
`rtl8852a` chip row); upstream runs no FAHM ("only ifs_clm for now"); the
background IFS-CLM runs in `track.rs`; EDCCA-CLM results feed only debug
diagnostics. `antenna_diversity_tracking` is removed:
`rtw89_mac_setup_phycap` sets `hal->ant_diversity` only for one-path chips
with `rfe_type % 3 == 2`, i.e. RTL8851B (folded into the `rtl8851b` chip
row).

### Additional named blockers (2026-10-29)

These paragraphs name the remaining native owners; upstream applicability
triage above remains separate from implementation.

| Row | Concrete blocker |
|---|---|
| `additional_operating_channels` | Source implemented for RTL8852B 2.4GHz/20MHz primaries 2..=13 (N52C per-channel signed record, native drain/retune owner, multi-channel scan and noninitial association; §3 "Signed per-channel program"). Native execution, N52C provisioning and physical validation remain; channel14, CSA and noninitial monitor stay refused. |
| `five_ghz_operation` | RTL8852B supports5GHz, but the retained radio/power recipe and station admission select the channel1 2.4GHz program. Native5GHz RF/BB/power setup, permitted scan/retune and exact signed operating programs remain missing; discovery of the band alone grants no station profile. |
| `wide_channels` | The retained HT/HE profile and descriptor/program identities fix20MHz. HT40/80 and applicable160 need real MAC/BB/RF width/secondary/center programming, full occupied-span power admission and matching host PHY/TX/RX/control-field owners. Shared JoinPlan width encoders already exist. |
| `fragmentation` | The admitted RTL8852B native/host/public owner is now implemented in §3 above, including the separate signed full-joint emitter, per-fragment PN and actual terminal ownership, bounded original-source RX cache and threshold control. Source review, release compilation and native/physical acceptance are pending. Other chip/width profiles remain their explicit separate rows. |
| `monitor_mode` | The admitted RTL8852B receive-only role/native/raw-radiotap owner is implemented in §3 with original source/registration/role/capture epochs, actual RF channel/PHYSTS program and fresh physical transitions. Four source cases and software/native/physical acceptance are pending; no active/injection or other chip/channel/width profile is claimed. |
| `rf_power_tracking` | Source complete for the admitted RTL8852B channel1 HT/HE20 owner: actual periodic thermal EWMA/DPK PWSF producer, same completed Radio input snapshot, native current publication/readback and independent signed full joint-program window are described in §3. Software/native/physical validation remains pending. Periodic IQK/TSSI reruns and non-B thermal-duty quirks are not this adapter’s applicable missing producers. |
| `runtime_sleep` | The admitted RTL8852B clock-gated native/runtime/public path is implemented in §3 below, with separate signed joint qualification and seven new unexecuted cases. Source review, release compile, native two-arch and physical acceptance remain pending; other chip/firmware adapters remain their own chip rows. |
| `six_ghz_operation` | Only RTL8852C/RTL8922A have6GHz applicability; their complete native chip/station owners remain missing. The retained B profile is2.4GHz-only in software. Six-GHz operation additionally needs per-band RF/power qualification, actual HE6GHz context and current LPI/VLP/AFC client admission through the existing shared6GHz APIs. |
| `uapsd` | Station U-APSD is source-inapplicable (no IEEE80211_VIF_SUPPORTS_UAPSD). This row covers AP-side WIPHY_FLAG_AP_UAPSD only; there is no retained AP peer/queue/beacon/service-period owner. |
| `wow` | No native WoW firmware/context/pattern/GTK/wake-source owner exists. The implemented non-WoW suspend path retires the generation and rebuilds it after resume; this does not preserve an associated wake-capable firmware context. |
| `rtl8852a` | AX identity, power and firmware scaffolds do not establish this chip's native station. The retained Controller and N52B qualification admit RTL8852B only; A still needs its exact security/firmware, BB/RF/calibration/power and packet/station composition. |
| `rtl8851b` | Source identifies the1TX/1RX dual-band chip, but the retained B-only operating/qualification owner cannot be reused as its runtime. Complete chip-specific firmware/security, RF/power and packet/station ownership remain missing. |
| `rtl8852c` | The advertised AX-v1/three-band hardware description is not a native station profile. C needs the exact generation-specific PCI/descriptor transport plus firmware/security, RF/calibration/power and station composition; the current retained Controller/N52B profile is B-only. |
| `rtl8922a` | BE EFUSE/block/container, BE descriptor/PCI transport and the complete firmware/RF/power/station profile remain absent. Native EHT/320MHz cannot be enabled by shared IE encoders before that owner exists. |
