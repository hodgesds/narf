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
The fresh FLR/cold-WCPU profile never requests LPS, RPWM power transitions or
WoW keepalive; an observed sleeping state terminalizes instead of synthesizing
a wake receipt. Initial and post-join negative models cover every source PS
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
large A-MSDU bit belongs to `aggregation`. The negotiated HT facts feed the
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
ALL_ACK, A-MPDU length exponent extension 2, HT/VHT trigger-frame RX. PHY:
20MHz-only width set, device class A, LDPC, HE SU/MU 1x/2xLTF+0.8us GI,
NDP 4xLTF+3.2us, STBC RX, Doppler TX, DCM 16QAM (TX NSS1), partial-BW
extended range, power boost, 4xLTF+0.8us SU/MU, ER SU 4xLTF/1xLTF+0.8us,
DCM max RU996, >16 SIG-B symbols, TX/RX 1024QAM below 242-tone RU, full-BW
SU in MU (compressed and non-compressed SIG-B) and 16us nominal padding;
RX HE-MCS0..11 on two streams and TX HE-MCS0..11 on one. Linux bits that
need 40MHz (`wide_channels`), a second TX path (STBC TX, DCM TX NSS2),
HE +HTC (`HTC_HE`, `BSR`; `he_htc`), power save (`OPS`), RX A-MSDU
(`AMSDU_IN_AMPDU`; `aggregation`) or beamforming feedback
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

HE +HTC (`he_htc`) stays open: advertising `HTC_HE` lets the AP send +HTC
QoS DATA, but the shared `station_security::Security::normalize` rejects
the Order bit (`b[1] & 0x87 != 2`) and only knows 24/26-byte headers, and
the `RawFrame` contract forbids the driver from stripping the HT Control
field. Linux `__rtw89_core_tx_check_he_qos_htc` also needs the RA report's
`might_fallback_legacy` (`rtw89_phy_c2h_ra_rpt_iter`), which this station
does not yet consume.

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
response, hole fill, BAR flush, DELBA, non-HT decline). Originator TX BA
(CMAC AMPDU table) is tracked with TX A-MPDU as `block_ack_originator`.

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
operating program gates. The sequence-number half of `randomized_scan_mac`
stays open because shared `narf_wireless::scan::ScanRequest` has no
`NL80211_SCAN_FLAG_RANDOM_SN` field, so the driver cannot tell when
mac80211/firmware `rand_seq_num` (`fw.c::rtw89_hw_scan_add_chan_list`)
applies.

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
`OWNER` and the singleton reservation, so a later probe can bind. An
unproven stop keeps both: the address stays quarantined and a re-probe
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
ran. `rearm` withdraws the closed shell while reserving its name
(`interface::withdraw_keep_name`), drops the retired lifecycle and claims a
fresh `pci_reset::Reset` (stored under the reset mutex after a removed
check), so the next generation repeats the observed FLR, discovery,
firmware, MAC/RX, full radio and station start on the same function and
publishes a new shell under the same `wlan%d` name, ready to scan and
associate again. Each generation is again one fresh PCI lifecycle after an
observed FLR, which is exactly what `radio_policy::Board`'s signed identity
binds, so the same measured qualification applies and no new identity is
introduced. A generation that fails before the station, an unproven stop
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
| Broader lifecycle | Initial independent reset, terminal ownership and proven-reclamation removal and SER L2-style generation reset/rejoin implemented; suspend, automatic reset/rejoin and multiple live functions remain outside this first profile |

The per-chip source `rtw_chip_info` inventories are broader than this station:
8851B declares1TX/1RX and2.4/5GHz;8852A/B declare2TX/2RX and2.4/5GHz;
8852C declares2TX/2RX and2.4/5/6GHz;8922A declares2TX/2RX and2.4/5/6GHz
with its distinct BE generation. B now has signed-program HT20, HE20 (with
firmware GI/LTF selection), all-AC/TID QoS, firmware RA, recipient
BA/reorder, MSI delivery, live EDCA and active channel-1 scans (section 3);
it still needs HE +HTC and wider widths, TX
aggregation/originator BA, other channels, tracking, runtime sleep/WoW and
in-place SER L1 recovery. A/C/51 need complete chip-specific
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
| `aggregation`, `block_ack_originator` | `packet_core::Core` keeps one `pending: Option<Pending>` and `ready()` is false while a frame is in flight. `station::State::pending` and the RPQ retirement are also single-frame. TX A-MPDU needs per-slot header/body DMA ownership for N in-flight tickets, `RTW89_TXWD_BODY3_AGG_EN`/`INFO1_MAX_AGGNUM`/`INFO2_AMPDU_DENSITY`, an originator ADDBA state machine (mac80211 `agg-tx.c`), `rtw89_chip_h2c_ampdu_cmac_tbl` on `TX_OPERATIONAL`/`TX_STOP_*`, and a new signed `Program` for the aggregate emitter. |
| `system_suspend` | `narf_power::device_pm::DevicePmOps` callbacks are synchronous and IRQ-gated and may not schedule. Linux suspend without WoW (`drv_stop` -> `rtw89_core_stop`) and resume (`rtw89_core_start`, firmware download, awaited H2C DONE_ACKs) are async here. Resume also needs a second temporal FLR (`pci_reset.rs` makes one attempt) and a new identity, because `radio_policy::Board` binds "one fresh PCI lifecycle". The non-terminal teardown above is a prerequisite. |
| `pmf` | The rtw89 station has no SAE: `station.rs::associate` builds Open/WPA2-PSK only and `interface.rs` maps only `SecurityConfig::Open`/`Wpa2`. `packet_format::classify` refuses management frames with the Protected bit. The shared `JoinPlan::start_sae_authentication`, `Security::new_sae`, `protect_management` and `receive_management` exist. The composition smoke additionally needs a shared SAE/PMF AP fixture: `narf_wifi_fixtures::FakeAp` only offers open/WPA2-PSK, with no SAE commit/confirm, MFPC/MFPR, IGTK or BIP. |
| `randomized_scan_mac` | The random MAC is implemented (section 3). Random sequence numbers need `NL80211_SCAN_FLAG_RANDOM_SN` in shared `narf_wireless::scan::ScanRequest`. |
| `he_htc` | The shared `station_security::Security::normalize` rejects +HTC RX (Order bit, `b[1] & 0x87 != 2`) and the `RawFrame` contract forbids stripping HT Control. TX additionally needs RA C2H `might_fallback_legacy` (`rtw89_phy_c2h_ra_rpt_iter`) and Order-bit admission in `packet_format::classify`. |

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
