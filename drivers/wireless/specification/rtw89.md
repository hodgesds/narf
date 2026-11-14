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

For the retained-bootstrap IDs (`rtw89::bootstrap_did`: `10ec:b852`/`10ec:b85b`,
`10ec:c852` and `10ec:b851`), `pci::probe` reserves its exact BDF before parking
and retains the actual reset owner before its first await. Generic binding
requires an advertised, completed FLR and its consumed temporal fence. A
repeat same-function probe performs no config access, including during reset
quarantine or terminal failure. `pci::attach_cold` is a separate unsafe trusted
platform entry: the caller must independently prove actual function/slot reset,
posted-traffic drainage and no DMA ownership since, and call before generic
binding. Static board facts and BME-off cannot satisfy that temporal contract.
Neither path can replace an existing reserved owner.
`pci::register_pci_driver` registers `bootstrap::remove` for the same ID set;
the A and 8922A IDs stay on the parked diagnostic probe.

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
The one such owner today is the RTL8922A boot: `Rtw89Device::boot_8922a` sets
`BUS_MASTER` through `rtw88::pci_park::master` (readback must show BME +
MEM + INTx-off; Linux `rtw89_pci_claim_device` -> `pci_set_master`) before
its ring programming and CH12 firmware download, and `bring_up_registers`
re-parks the function (`pci_park::park`) when that boot fails.
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
version0 empty policy; RTL8851B takes Linux's exact NULL `fw_blacklist`
policy (`Blacklist::upstream(Rtl8851B)` has no chip list: fw.c
`__check_secure_blacklist` -ENOENT is only `WARN_ONCE`d, so the matching MSS
signature is the whole secure policy, still required); A requires an
authenticated board policy. RTL8922A (BE) takes the same plan through
`Fuses::from_be`: its secure-window read (`efuse_be::read_secure`,
`rtw89_efuse_read_fw_secure_be`) supplies the Linux-mapped MSS triple
plus `sb_sel_mgn`, a formatted section's `sb_sel_ver` must be zero or
that magnitude (`__parse_formatted_mssc`), and its upstream blacklist
is the same version-0/all-clear default list as B/C
(`rtw8922a.c:3215`); the AX DDV decoder still refuses 8922A. `BeFactory`
carries the secure state from probe and `Prepared8922a::secure_fuses`
exposes it to the future download owner. The plan runs once per
firmware download, never on a packet path (perf class (a): no hot path).
No missing policy or signature falls back to an unsecured transfer.

**RTL8922A firmware-download preparation (`fwdl_be.rs`, fixture-tested;
run from `pci::bring_up` by `Rtw89Device::boot_8922a`, which 0x8922 does not
reach yet — `bootstrap_did` still excludes it).** The BE register programs between power-on and
the first FWHDR_DL: `mac_func_en` (`mac_be.c:934 mac_func_en_be`, per-band
CMAC power/function enable), `partial_init` (`mac.c:4307
rtw89_mac_partial_init` up to the hci hook: HCI DMA TRX enable,
`rtw8922a_bb_preinit(PHY_0)` + BB-MCU CR init through the 0x30000 window,
`hci_func_en_be`, `dmac_func_pre_en_be`, `rtw89_mac_dle_init(DLFW, SCC)`
with the `rtw8922a_dle_mem_pcie` DLFW table and its FIFO-size check, and
the h2c-only `rtw89_mac_hfc_init`), `fwdl_preconfig`, `disable_cpu`,
`enable_wcpu` (`set_cpu_en` + `wcpu_on`, BBMCU0 included since
`bbmcu_nr = 1`), and the status reads `check_path_ready` /
`fwdl_status` / `check_ready` (`fwdl_status_map`, `rtw89_fw_check_rdy`).
`R_BE_SECURE_BOOT_MALLOC_INFO_8922A` is the `rtw89_fw_download_suit`
constant. The BE PCIe FWCMD TX descriptor (`h2c_desc_size` = 24-byte
`rtw89_rxdesc_short_v2`, dword0 = packet length | `RPKT_TYPE`
H2C(13)/FWDL(14), `pci.c rtw89_pci_fwcmd_submit`) is
`fwcmd_8922a::fwcmd_txdesc`, and `pci::submit_be_h2c` now prepends it
(it previously sent the framed H2C without one). CH12 now mirrors
`rtw89_h2c_tx` / `rtw89_pci_fwcmd_submit` / `rtw89_pci_release_fwcmd`:
every submit first reclaims (`Prepared8922a::reclaim_fwcmd` reads the CH12
hardware RP, `rtw89_pci_dma_recalc`; an RP past the in-flight window is
refused) and is refused with no free TXBD (-ENOSPC); kicked buffers queue in
TXBD order; consumed FWDL header/section buffers (`pci::submit_be_fwdl`,
RPKT type H2C for FWHDR_DL, FWDL for sections — no ack exists for them) are
freed beyond the 8-deep `RTW89_PCI_MULTITAG` window; ack-held H2C buffers
stay with `release_h2c_by_ack`; `program_rings` (the `rtw89_pci_ops_reset`
point) resets the CH12 host index and releases everything. The BE plan
segments by the header's `FW_HDR_V1_W7_PART_SIZE` (`fw.c:465`; AX keeps
2020; zero or a part the 14-bit FWCMD `RPKT_LEN` cannot carry is refused,
and a secure single-packet section must fit it), and the BBMCU0 suit is
the firmware element id 0 behind the MFW images
(`PreparedFirmware::bbmcu` / `fwdl::find_bbmcu`, `fw.c:1542` +
`__rtw89_fw_recognize_from_elm`: first element with `cv` <= cut, no AID
filter, contents after the 32-byte header). The sequence is
`fwdl_be::download` / `download_once` / `download_suit` (`fw.c:1701..2025`
`rtw89_fw_download` ×5 retries / `__rtw89_fw_download` /
`rtw89_fw_download_suit`): disable CPU, WCPU enable in download mode with
BBMCU0, per suit (NORMAL then BBMCU0) the 8922A `SECURE_BOOT_MALLOC_INFO`
word (NORMAL only), H2C path ready, FWHDR_DL (seq 0, RPKT H2C), DLFW path
ready, HALT H2C/C2H control clear, sections in part-size FWDL packets, the
suit's WCPU/BB0 ready check, then `mdelay(5)` and FreeRTOS ready. The BE
IDMEM share-mode write is skipped (`mac_be.c:3301` hook is NULL). It runs
over a `fwdl_be::Port`; production is `pci::FwdlPort` (BAR2 +
`submit_be_fwdl`). It is synchronous like Linux's process-context download.
`Rtw89Device::boot_8922a` (called at the end of `pci::bring_up` for 8922A)
runs the `rtw89_core_start` prefix in Linux order: `mac_func_en`,
`partial_init(include_bb)`, the hci `rtw89_pci_ops_mac_pre_init_be`
(`pci_pre_init_8922a`: IO-recovery timers, power wake, DMA pre-init first
half, `program_rings` as `rtw89_pci_ops_reset`, `dma_8922a::rst_bdram`,
debounce / LDO low power / PCIe setting / SER setting by cut, then only CH12
TX DMA on via `pre_init_dma_enable`), `fwdl_preconfig`, then the NORMAL suit
from the trusted firmware registry and its BBMCU0 element through the
fuse-selected plans. The outcome is recorded on the owner
(`Prepared8922a::firmware_ready` / `firmware`) and is not fatal to the probe:
nothing after the download (sys_init/trx_init, BB/RF, channel, RFK, TX power,
C2H, RX, station control, interface) is wired yet.

The plan couples v1 ignored-security descriptor compaction/count with the
same payload selection, strips host dynamic bytes and sets part_size 2020
(AX) or keeps the header's part size (BE).
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
`radio_tables_a` retains the actual A BB1,267, RF-A28,869, RF-B29,126 and
NCTL1,036 pair entries; A has no gain table (`rtw8852a_chip_info.bb_gain_table`
is NULL), so the same selector runs 11 frozen A cases (full selected-stream
counts and order-sensitive digests, including the two rejected unknown-RFE RF
packages) with no GAIN index. `radio_assets::Assets` admits A with the static
A fallback for BB/RF_A/RF_B/NCTL and a firmware GAIN element only when present.
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
RTL8852A has the same initial shape through `rfk::a::Init` (RCK A/B,
table-driven ADDCK/DACK A/B, AFE RX DCK A/B) with A-only differences: no DRCK
and no PHYREG_SET write, `RR_MOD` 0x30001 then 0x40001, and the ADDCK/DACK def
tables from `rtw8852a_rfk_table.c`; the AFE RX DCK restores the full saved
RXCK word, and channel RX DCK is the same AFE flow through
`rfk::a::ChannelRxDck`. `rfk::Rfk` retains all measured I/Q MSBK, ADC/DAC offsets/bias and actual DPD
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
A programmed secure boot still needs authenticated board blacklist-policy
loading; B/C retain Linux's version0 policy and 51 Linux's NULL chip list. B's retained MAC sys/TRX preparation
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

### RTL8852B Wake-on-WLAN (`wow_wire.rs` and composition) — advertised when composed, unexecuted

Linux 7.3-rc4 `rtw8852b.c` declares `rtw_wowlan_stub_8852b` (magic packet,
disconnect, 18 patterns of 1..=128 bytes; no GTK-rekey, no net-detect).
`wow_wire::support` mirrors it exactly; `wow_wire::validate` re-checks a
retained `WowlanConfig` and generates every pattern before any hardware is
touched (`rtw89_wow_set_wakeups`).

**Firmware.** RTL8852B needs a separate WoW image, but not a separate file:
every canonical B file (`rtw8852b_fw{,-1,-2}.bin`) is a multi-firmware
container with `RTW89_FW_WOWLAN` (type 3) entries for cuts 1 and 2 beside
the normal/CE images (`fw.c::rtw89_fw_recognize`, `wow.c::rtw89_wow_swap_fw`
-> `rtw89_fw_download(RTW89_FW_WOWLAN)`). `prepared::load_wow(name, chip,
cut)` takes the name of the file the running normal image came from (only
this chip's canonical names), loads it again through the same `Files`
authority and selects the type-3 image for the physical cut with the
existing bounded MFW selector; `firmware_registry::load_wow` binds it to
the trusted, signature-verifying registry exactly as `load`. No other
file or image type is tried and nothing is cached; restoring the normal
image on resume must call `firmware_registry::load` again.

**Codecs (`wow_wire.rs`).** Byte-exact Linux layouts, no transport:
- pattern CAM: `rtw89_wow_pattern_get_type` (masked DA: broadcast,
  multicast, own unicast under a full DA mask, or wildcard; anything else
  `-EPERM`), `rtw89_wow_pattern_generate` (six-bit LLC mask shift, bits
  0..5 cleared, Realtek CRC16 over masked bytes from offset 12) and
  `rtw89_fw_h2c_wow_cam_update` (AX v0, the 8852B chip op) write/clear;
- `H2C_CL_MAC_WOW` bodies: `KEEP_ALIVE` (period 5), `DISCONNECT_DETECT`
  (period 100, 5 tries, only when disconnect wake is requested),
  `WAKEUP_CTRL` (pattern/magic/deauth, MAC id), `WOW_GLOBAL` with the
  packed `rtw89_wow_key_info` (CCMP `_pn_to_iv`/`_iv_to_pn`,
  `RTW89_WOW_VALID_CHECK`), `AOAC_REPORT_REQ`;
- `H2C_CL_MAC_SEC_CAM`/`SEC_UPD` CCMP-128 key body
  (`rtw89_cam_get_sec_key_cmd`, zeroized buffer);
- `R_AX_WOW_CTRL`/`B_AX_WOW_WOWEN` status poll constants (50us/50ms),
  the B wake-reason register `R_AX_C2HREG_DATA3 + 3`, the reason decode
  of `rtw89_wow_show_wakeup_reason` into the driver-accessor
  `wow_wire::WakeReport` (iwlwifi.md section 3.80 pattern; pattern index
  from the AOAC report) and the `rtw89_c2h_wow_aoac_report` decoder (C2H
  class 3 function 0; GTK/IGTK material is not retained).

**Reversible TRX halt/restart (`wow_trx.rs`, `command_native/wow.rs`) —
implemented, unexecuted.** `wow_trx` holds the RTL8852B register sequences
of `wow.c::rtw89_wow_enable_trx_pre/post` and `disable_trx_pre/post`
(PCI info from `rtw8852be.c`): `enter_pre` snapshots the awake values
(STOP1, MGNT/CTRL/DATA filters, `RX_FLTR_OPT`, `PPDU_STAT`, `HW_RPT_FWD`,
`ACTION_FWD0/1`, `TF_FWD`), requires an awake SCC station (HCI on, CH12
open, `HDR_RX_STOP` clear, `PLE_QTA6` = `ple_qt18`/`ple_qt58` 89/229,
`QTA7` 0), sets `B_AX_TX_STOP1_MASK_V1` then re-opens CH12, waits up to
50 ms for `mac_is_txq_empty_ax` (WDE DFI QEMPTY groups 0..3 all-ones,
MGQ group 4 bits 2..4, `R_AX_DLE_EMPTY0` mask `0x07ff0780`), polls
`DMA_BUSY1_CHECK_V1` idle (10/100 us), drops all frame types and clears
`B_AX_PPDU_STAT_RPT_EN`. `enter_post` clears TX/RX HCI, polls idle, runs
`rtw89_wow_config_mac_ax(true)` up to its `NO_WOW_CPU_IO_RX` return
(`QTA6` = 89/133 `ple_qt_52b_wow`, `QTA7` 0, `HDR_RX_STOP`, sniffer off,
PPDU off, FWD registers 0), returns the filters to host and runs the
RTL8852B `rtw89_pci_reset_trx_rings` (BD-RAM partitions of
`rtw89_bd_ram_table_single` for ACH0..3/CH8/CH9/CH12; NUM/DESA only for
rings this owner published, read back). `leave_pre` runs `clr_idx_all`
(`0x1014` |= `0x70f`, `0x1018` |= 3), `rst_bdram` (1 us x 100),
`ctrl_trxhci(true)`, re-opens exactly the pre-halt channels, writes the
SCC quota, clears `HDR_RX_STOP`, restores the forwarding/sniffer values
and proves every published index zero; `leave_post` restores PPDU status
and the filters. `CpuIoRx::for_8852b` derives `NO_WOW_CPU_IO_RX`
(`fw.c`: RTL8852B < 0.29.30.0, which covers every admitted 0.29.29.x
image); a `Required` image is refused before any write because
`WOW_CPUIO_RX_CTRL` is not ported.

`Native` composes it as `Trx::{Quiesced, Parked, Restarted}`:
`wow_trx_enter_pre` (8852B, `State::Active`, started station, no
monitor/LPS/FLR, a transmit-quiet `packet_core` -> `Phase::Halted`),
`wow_trx_enter_post(cpu_io_rx)` (HIMR off via `irq::Mask::disable`, CH12
drained for at most 10 ms, then host rewinds: `TxQueue::rewind` and zeroed
TXBDs per ring, `CommandQueue::rewind`, `rx_dma::Rx::wow_rewind` = wp 0,
fresh assembler, RXBD-info headers zeroed, every buffer still mapped and
referenced), `wow_trx_leave_pre` (sequence, then `Binding::start` =
`rtw89_hci_enable_intr`) and `wow_trx_leave_post` (`Phase::Running`).
BME, MSI, the vector and every mapping are kept throughout. While a window
is open `packets_ready` is false and station RX polling returns an empty
batch; while `Parked` every CH12 command is refused (`Busy`). Any register
failure clears the window and calls `fail`, whose terminal closure earns
the `dma_stop` proof for the existing cold path. Deliberate differences:
no `H2C_PKT_DROP` (a busy WDE queue after 50 ms fails), pending TX frames
or unconsumed H2Cs are not released but refuse the halt, resume re-opens
only the pre-halt channels and restores the observed forwarding/PPDU
values instead of the init defaults, and no beacon filter exists to
re-enable. Unexecuted cases: `smoke_rtw89_wow_trx_halt_restart_reversible`,
`smoke_rtw89_wow_trx_refusals_fail_closed`.

**Firmware swap (`startup_wow.rs`, `firmware_boot::Firmware::swap`) —
implemented, unexecuted.** `Startup::wow_swap_in(cam, admission)` runs
`wow.c::rtw89_wow_swap_fw(wow = true)` between `wow_trx_enter_pre` and
`wow_trx_enter_post` on a `RadioReady`, non-monitor, associated station
whose LPS owner is absent or awake (`lps::Manager::wow_ready`). It
resolves the WoW plan first (`firmware_registry::load_wow` of the running
image's file, `DownloadPlan::new` with the identity fuses and upstream
blacklist), so a missing/unverifiable image leaves the station untouched.
`Firmware::swap` then repeats `__rtw89_fw_download` (CPU disable/enable,
path ready, header, sections, 5 ms, FREERTOS_DONE) over CH12 while the
transport is `Native::wow_swappable` (8852B, `Trx::Quiesced` or
`Trx::Restarted`, CH12 drained; interrupts stay enabled as Linux does for
AX non-C). `wow_firmware_loaded` restarts the H2C sequence at 0
(`h2c_seq = 0`) and drops C2H retained from the replaced image;
`wow_rf_pages` is `rtw89_phy_init_rf_reg(noio = true)` (the RF A/B firmware
pages rebuilt by `radio_init::noio_pages` from the retained signed tables);
`station_control::Controller::restore` sends `ROLE_MAINTAIN(FW_RESTORE)`
(`codec::role_restore`, upd_mode 6), the assoc CMAC table (`fixed_cctl`),
`JOIN_INFO` connected, the caller's AX v0 address CAM body (AX has no
`upd_mode` word) and the retained RA body (`rtw89_phy_ra_assoc`, recorded
by `configure_ra`). On the WoW image `Native::wow_general_packets` installs
PS-Poll/NULL/QoS-NULL offloads and `GENERAL_PKT` in a fresh
`lps_packets::Namespace` (new epoch), retained in `startup_wow::Window`.
`wow_swap_out(admission)` is the reverse (`wow = false`, between
`wow_trx_leave_pre` and `wow_trx_leave_post`): a freshly loaded normal image
(`firmware_registry::load`, never cached), the same restore with the plain
associated CAM; the LPS manager moves to a new namespace epoch and
reinstalls its templates/`GENERAL_PKT` on its next install, as before LPS
first ran. While the window is open and HCI is on, `rx_hardware_step`
returns firmware messages only (RX filters drop frames). BSS colour,
UL-TB offset, EDCA/WMM rows and BA CAM are BB/MAC state the WCPU download
leaves intact and are not replayed. Deliberate differences: one download
attempt (Linux retries five times); any failure after resolving the plan
terminalizes the Startup for the cold path. Unexecuted case:
`smoke_rtw89_wcpu_wow_swap_requires_swappable_running_owner`.

**WoW security CAM (`wow_security.rs`) — implemented, unexecuted.**
`wow_security::plan(suspend_keys, suspend_floors)` mirrors
`cam.c::rtw89_cam_sec_key_install` for the snapshot as the keys reached
the hardware at association: the PTK at security CAM 0 / address slot 0
(key id 0), each GTK at the next CAM index and the next `SEC_NORMAL` group
slot 2..=4 with its key id; IGTK never (BIP stays on the host). The
`KeyInfo` of `rtw89_wow_construct_key_info` takes CCMP-128 IVs from the
floors (`ptk_tx_iv`, `ptk_rx_iv`, `gtk_rx_iv[keyidx]`), `gtk_keyidx` from
the last group key, `RTW89_WOW_VALID_CHECK` and both symbol checks; an
open BSS writes nothing (`ptk_alg`/`gtk_alg` 0). `wow_security::wow_cam`
fills `rtw89_cam_fill_addr_cam_info` words 9..=11 (`WOL_PATTERN`,
`WOL_MAGIC`, `SEC_ENTn_KEYID`, `SEC_ENT_VALID`, `SEC_ENTn`) on the plain
associated body (`Startup::wow_cam`). `Startup::wow_keys_in` writes the
`H2C_FUNC_MAC_SEC_UPD` entries through the normal image after
`wow_trx_enter_pre` (RECV_ACK, as `cam.c`), `wow_swap` ends with
`rtw89_mac_hw_mgnt_sec(wow)` (`Native::wow_mgnt_sec`, read-back proven),
and `Startup::wow_keys_out` after `wow_swap_out` overwrites every written
entry with a zero key and re-proves `B_AX_{UC,BMC}_MGNT_DEC` clear before
`wow_trx_leave_post` reopens RX. Deliberate difference: Linux keeps its
hardware keys after resume; NARF's awake path never had any. Unexecuted
cases: `smoke_rtw89_wow_security_cam_entries_and_addr_cam`,
`smoke_station_suspend_floors_match_keys_and_consume_nothing`.

**WoW suspend/resume composition (`startup_wow.rs`, `station_lifecycle.rs`,
`interface.rs`, `bootstrap.rs`) — implemented, unexecuted.**
`Startup::wow_suspend(config, keys, floors, admission)` is
`rtw89_wow_suspend` -> `rtw89_wow_enable` in Linux order: every wake input
is validated first (`wow_wire::validate`, `wow_security::plan`,
`CpuIoRx::for_8852b(Assets::firmware_version)`), then
`wow_trx_enter_pre`, `wow_keys_in`, `wow_swap_in(wow_cam)`,
`fw_start` (pattern CAM writes, `KEEP_ALIVE`, `DISCONNECT_DETECT`,
`rtw89_wow_cfg_wake(true)` = `WAKEUP_CTRL`, address CAM INFO_CHANGE,
`WOW_GLOBAL` with the key info; then `R_AX_WOW_CTRL.WOWEN` polled 50us x
50ms) and `wow_trx_enter_post`. `Startup::wow_resume` is `rtw89_wow_resume`:
the wake-reason byte, `wow_trx_leave_pre`, the AOAC report by packet on a
secured link (C2H MAC 3/0; best effort as in Linux; only its pattern index
is used), `fw_stop` (pattern CAM clear, keep-alive and disconnect detection
off, `cfg_wake(false)` with zero algorithms/key info, WOWEN clear),
`wow_swap_out`, `wow_keys_out` and `wow_trx_leave_post`; the
`wow_wire::WakeReport` is returned even on failure. Any failure
terminalizes the Startup. `station::State::wow_snapshot` supplies the keys
and floors only for an Open, ready, settled station (no handshake, CSA,
scan, management/BA/EDCA work); `Owner::station_wow_resume` keeps the
association only when `wow_wire::keeps_link` (disconnect/unknown reasons
drop it) and refreshes the beacon-loss clock. `Device::wow_suspend`
refuses host control/packets (`admitted` off, `wow_armed` stops the drain
worker and LPS service), leaves LPS (`rtw89_wow_leave_ps(true)`), then
runs the owner under the retained mutex; `Device::wow_resume` reopens them
or closes the shell. The WoWLAN configuration and last wake report are
carried across generations by `Bootstrap::wowlan` (cfg80211 keeps
`wiphy->wowlan_config`). `bootstrap::SystemPm` takes the WoW branch for a
`Stage::Station` generation: `pci_save_state`, the driver op, D3hot without
card-off (as rtw88; 10 ms exit delay, PMCSR read-back); resume returns to
D0, restores and re-reads BARs/command, then restores the MSI capability
(`narf_bus::msi::restore_msi`: enable off, address/data/per-vector mask,
then Multi-Message Enable + Enable, whole capability read back; Linux
`__pci_restore_msi_state`), then `wow_resume`. WoW is refused (cold path)
unless MSI was enabled and saved before suspend. Every failure
(including a non-D3hot read-back, which resumes the station first) takes
the existing cold path: the shell is closed and the supervisor retires the
generation (park on suspend, regenerate behind a fresh FLR on resume).
A rolled-back multi-function suspend returns a WoW owner to D0 and closes
its shell without awaiting the exit delay. PCI PME/wake enable stays with
the system-PM owner. Deliberate differences: no WoW LPS
(`rtw89_wow_enter_ps`; the radio stays awake), no GTK-offload H2C (no
rekey data; RTL8852B declares no GTK-rekey wake), no ARP offload, the AOAC
RX IVs do not advance the host replay floors (host PN state stays in
`station_security`, as rtw88), and Linux's `rtw89_pci_suspend`/`resume`
LDO/PERST register writes are not ported.

**Composition checklist (Linux `rtw89_wow_suspend`/`resume` order).** All
six items are implemented and compile; every case is unexecuted and no
physical WoW wake has been observed:
1. (Done above: `wow_trx`/`command_native/wow.rs`.) Reversible TRX
   halt/restart on the retained station:
   `rtw89_wow_enable_trx_pre` (`ctrl_txdma_ch(false)` with the CH12 FW
   channel kept, `ptk_drop_by_band_and_wait`, `poll_txdma_ch_idle`, RX
   filters to "don't care", PPDU status off) and `enable_trx_post`
   (interrupts off, `ctrl_trxhci(false)`, idle poll, `wow_config_mac_ax`:
   PLE RX quota, `B_AX_HDR_RX_STOP`, CPU IO RX, `R_BE_DBG_WOW_READY`, then
   `rtw89_pci_ops_reset`); resume `disable_trx_pre` (`clr_idx_all`,
   `rst_bdram`, `ctrl_trxhci(true)`, TX DMA on, `wow_config_mac(false)`).
   The existing `dma_stop` proof is terminal (BME off); WoW needs a
   reversible variant that keeps BME and every published mapping, like
   rtw88 `pci_swap.rs`.
2. (Done above: `startup_wow.rs`.) Firmware swap on a `Phase::Station` owner: WCPU re-download of the WoW
   image through the CH12 path (8852B keeps interrupts enabled during the
   download), `rtw89_phy_init_rf_reg(true)`, `ROLE_MAINTAIN(FW_RESTORE)`,
   assoc CMAC table, `JOIN_INFO`, addr CAM (`FW_RESTORE`), general packets,
   RA assoc, BSS colour; and the reverse to the freshly loaded normal image.
3. Hardware security CAM for the WoW window only: the awake station runs
   host CCMP/BIP with `SEC_ENG_CTRL` off (section above). Like rtw88
   `security_cam.rs`, take `station_security::Security::suspend_keys`
   (PTK + live GTKs, never IGTK), write `sec_cam_ccmp` entries, attach them
   through the addr-CAM `SEC_ENT*` fields with `WOL_MAGIC`/`WOL_PATTERN`,
   enable the engine with `rtw89_mac_hw_mgnt_sec`, and clear/disable and
   re-prove host crypto before RX is restarted on resume. (Done above:
   `wow_security.rs`.)
4. Keep-alive as an unprotected NULL data general packet (Linux uses an
   ARP-response packet that is protected under `ptk_alg`; protected
   firmware transmissions would need the AOAC `ptk_tx_iv` written back into
   the host TX PN). GTK/ARP offload stay off. (Done:
   `Startup::wow_keep_alive`, `H2C_FUNC_KEEP_ALIVE` DONE_ACK with the
   window's NULL offload id, MAC id 0, period 5; disable sends id 0.)
5. `bootstrap::SystemPm` branch: a WoW-configured, associated, settled
   station keeps D0 and its generation instead of retiring it; any failure
   falls back to the existing cold retirement/regeneration path. PCI PME
   stays with the system-PM owner (iwlwifi.md section 3.80) (Done above: WoW suspend/resume composition; the
   generation goes to D3hot without card-off instead of staying in D0.)
6. `WirelessNetIface::wowlan_support`/`set_wowlan` only after 1..5 exist.
   (Done: `wowlan_support` returns `wow_wire::support` only when the
   generation sampled `station_wow_capable` at activation — RTL8852B,
   started station, an image without `WOW_CPUIO_RX`; `set_wowlan`
   validates with `wow_wire::validate` against the station address
   (`EINVAL`) or refuses with `EOPNOTSUPP`; `wowlan_config` returns the
   retained configuration. Unexecuted case:
   `smoke_rtw8852b_wowlan_unadvertised_without_composed_wow`.)

Unexecuted cases: `smoke_rtw89_wow_support_patterns_and_cam`,
`smoke_rtw89_wow_h2c_bodies_reason_and_aoac`,
`smoke_rtw89_wow_image_same_file_same_authority`.

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

### RTL8852B 5GHz 20MHz channel program and admission (partial)

**Typed profile.** `operating_channel::Profile` covers 2.4GHz 1..=14 and the
Linux core.c `rtw89_channels_5ghz` 20MHz primaries (`GHZ5`: 36..64, 100..144,
149..177). It derives chan.c `rtw89_get_subband_type`, phy.h BB-gain and
OFDM gain-offset bands, phy.c `rtw89_encode_chan_idx` / `rtw89_channel_to_idx`,
rtw8852b_common.c `rtw8852bx_sco_mapping` and rtw8852b_rfk.c TSSI OFDM/trim
groups from the center channel (`center()` = primary at 20MHz, so no 5GHz
center is a TSSI_EXTRA_GROUP). 2.4GHz bindings are byte-identical to v1; 5GHz
binds under its own domain. `slot()`/`primaries()` define the compact u64
admission mask (2.4GHz primary n keeps bit n; 5GHz from bit 16).

**Channel program (5GHz branches, Linux 7.3-rc4).** MAC
`__rtw8852bx_set_channel_mac` clears BAND_MODE and sets CHECK_CCK_EN|RTS6;
BB `__rtw8852bx_set_channel_bb`: no SCO CCK thresholds, BAND_SEL 0, 5GHz SCO
compensation, flat CCK TXFIR (as `rtw8852bx_ctrl_ch`), `gain_a` LNA/TIA
registers from the BB gain band, subband gain comp/offset (no CCK RPL
offset), RPL comp of the band, CCK disabled (`rtw8852bx_ctrl_cck_en`), the
RTL8852B 5GHz BT-share/BTG/DC-est/GNT-weight releases, encoded channel index
(readback-gated). RF `_ch_setting` sets `CFGCH_BAND1_5G`/`CFGCH_BAND0_5G`
(readback-gated on all four DAV/DDV words). Power: rtw8852b_table.c
`rtw89_8852b_txpwr_lmt_5g[20MHz][ntx][rs][bf][WW]` OFDM/MCS rows and
`_lmt_ru_5g` for all 28 primaries (`operating_power_defaults::CHANNELS_5GHZ`,
same source hash as the 2.4GHz rows; CCK slots 0), band-1 byrate without
CCK, firmware elements 11/14 (LMT_5GHZ / LMT_RU_5GHZ, 53 channel indices,
4 widths), band-1 TX shape, and no CCK DFIR (`rtw8852bx_set_tx_shape`).
RFK: IQK `_iqk_txk_setting`/`_iqk_lok`/`_lok_res_table`/`_txk_group_sel`/
`_iqk_rxk_setting`/`_rxk_group_sel` A-band words and `_a_*` groups, R_IQKCH
band 1 + center; TSSI `_tssi_rf_setting` TXA, `_5g` system/slope tables,
`_tssi_alignment_default` 5g1/5g2/5g3 all-defs, per-subband thermal rows
(`Tracking` now parses firmware types 4..7, or Linux 5ga/5gb defaults),
PMAC `__rtw8852bx_bb_ctrl_rx_path` subband gain offset and no BTG on 5GHz;
DPK `_dpk_rf_setting` A-band RF words, `_dpk_idl_mpa` MDPD order 2 (<80MHz),
`Path::a_band`, and `_dpk_track` 5/2 thermal delta. RXDCK is band-agnostic.

**Band change.** `radio_full::Radio::retune` follows core.c
`__rtw89_set_channel`: when the band changed it runs
`tssi::band_scan` (`rtw8852b_rfk_band_changed` -> `rtw8852b_tssi_scan`:
disable, RF setting/system/thermal/default alignment per path, enable, DE)
after set_channel_done and before `rtw8852b_rfk_channel`. The scan never
reloads another band's measured alignment. Before that scan the band change
runs `rfk::Interface::coex_switch_band`, the coex.c
`rtw89_btc_ntfy_switch_band` port (8852B has no DBCC, so only
`_run_coex(BTC_RSN_NTFY_SWBAND)`): with the owner's `dm->wl_only`,
`_run_coex` takes `_action_wl_only` before any band/link dispatch, i.e.
`_set_ant(FC_EXEC, BTC_ANT_WONLY)` re-executed (`coex_native::enforce`:
LTE 0x38, 0x73 bit2, 0xc67c, each read back) and `_set_policy(OFF_BT)`
emitting nothing (`_append_tdma`/`_append_slot` skip the unchanged
TDMA/slot). Linux's band-specific `_action_wl_5g` (`BTC_ANT_FDD`,
`OFF_EQ0`) applies only without `wl_only`, which needs BT link/profile
state (BT info C2H) this WLAN-only owner does not have; that remains part of
the separate adaptive-coex work. RF_GET_MCCCH (non-v0 layout)
carries channels only, so it is band-independent.

**Admission.** `channel_policy::admissible` accepts every typed 5GHz primary;
its N52C request uses a distinct 5GHz recipe (`recipe_5ghz`) and
`Board::new_noninitial` a 5GHz domain string; the record format is
unchanged (`[54..58] = [1,20,primary,flags]`, `rtw8852b-chan-v1-chNN`).
`Qualification::check_envelope` refuses any host rule flag except NO_P2P,
AUTO_BW, NO_160MHZ and, on a 5GHz span only, DFS / NO_IR over the occupied
span, and requires cfg80211 `reg_get_max_bandwidth`
(`RegulatoryDomain::max_bandwidth`) >= 20MHz; `channel_allowed` additionally
requires that check for a 5GHz record. A DFS or NO_IR span is admitted
passive-only (cfg80211 `IEEE80211_CHAN_RADAR` / `NO_IR`): `current` /
`with_current` (RF, RX, monitor) pass, but frame TX goes through
`Qualification::tx_current`, which on a passive-only active span requires a
station passive-TX grant (`grant_passive_tx`) naming that exact primary and
the current policy snapshot (`Qualification::policy`, `Arc` identity);
`select` of any other primary drops the grant. Native `submit_packet`,
`submit_packet_rate`, `submit_packet_agg` and `submit_fragment` call it
before publication. The calibration `check` still refuses DFS / NO_IR. `Native::admitted_channels` returns the
u64 slot mask over 2.4GHz and 5GHz; `preflight_full_radio` loads N52C for
2..=13 and every 5GHz primary; `retune_full_radio` accepts any admitted
typed primary (cross-band included). Without provisioned signed records only
channel1 is admitted, exactly as before.

**Station 5GHz path.** `station::Io::station_channels` is the whole u64
slot mask (`Startup` returns `Native::admitted_channels`); scan, retune,
association and CSA admit any typed 2.4GHz or 5GHz primary in it
(`station::channel_admitted`). Per band, following Linux 7.3-rc4:
probe requests (mac80211 `ieee80211_build_preq_ies_band`) carry the eight
OFDM Supported Rates and neither Extended Supported Rates nor DS Parameter
Set on 5GHz; the cached/associable BSS must have the band floor as a basic
rate (1Mbps on 2.4GHz; 6Mbps and no CCK basic rate on 5GHz) because the
fixed management/EAPOL/probe rate is core.c `rtw89_core_get_mgmt_rate`'s
band floor (CCK1 / `RTW89_HW_RATE_OFDM6`, `packet_format::OFDM6`), also used
for fragments. `Native::submit_packet*` refuse any fixed CCK rate on 5GHz
and accept the band floor without the WMM program. Firmware RA follows phy.c
`rtw89_phy_ra_sta_update` (`supp_rates[5GHz] << 4`, OFDM mode only). The
CMAC table (fw.c `rtw89_fw_h2c_assoc_cmac_tbl`) uses OFDM6 for
`RTS_RTY_LOWEST_RATE` and the fixed DATARATE on 5GHz (`codec::fixed_cctl`),
and EDCA uses mac80211.c `rtw89_conf_tx_aifs` SIFS16 with the always-short
5GHz slot (non-QoS default CWmin15, mac80211 `ieee80211_set_wmm_default`).
The 2.4GHz bytes and the signed profile fingerprints are unchanged
(`control::Interface::ghz5`, from the native operating primary). HT/HE
capability IEs come from the shared band-aware `JoinPlan` with the same
20MHz local profile (HE PHY cap0 width set 0 in both bands); as in mac80211
HE on 5GHz additionally requires VHT, which this profile does not offer, so
5GHz links are HT20 at most. CSA/ECSA follow `ieee80211_parse_ch_switch_ie`
/ `ieee80211_operating_class_to_band` (81..=84 2.4GHz, 112/115..=130 5GHz;
unknown class falls back to the CSA element in the current band); a
cross-band switch updates the peer's band. Scan requests accept 5GHz
channel numbers and frequencies (5180..=5885).

**DFS / NO_IR passive scanning and client admission.** The station keeps
the shared `narf_wireless::reg::witness::BeaconWitness` (wireless spec §3.5
"Station passive-channel witness") against `Io::station_regulatory` (the
native `Qualification::policy` snapshot; default `None` = no passive-only
primary). `scan_with` on a passive-only primary drops the probe (no probe
request, no random scan address: mac80211 `ieee80211_scan_state_decision`
/ `ieee80211_scan_get_channel_time` passive dwell) and opens a witness scan
generation for that primary, retracting its earlier witness; an actual
Beacon (subtype 8, nonzero interval, DS channel = tuned primary) received in
the dwell records `beacon_found`. `associate` refuses a candidate whose
primary fails `may_associate` (passive-only needs the witness), and after
the retune grants passive TX (`Io::station_passive_tx`) before the first
Authentication frame. CSA (`observe_csa`, mac80211
`ieee80211_sta_process_chanswitch` `drop_connection` on an unusable target)
drops the link unless the target passes `may_associate`; `switch_channel`
re-checks the witness under the current policy, fails the link if it was
retracted, and grants the target after the native switch. `stop` (and so
`disconnect`/`fail`) clears the witnesses and withdraws the grant. Linux
mac80211 lets a STA follow a CSA into any non-disabled channel; requiring a
witness for a RADAR / NO_IR target is NARF's stricter client rule. Monitor
is RX only (CMAC TX stays disabled) and simply tunes a passive-only primary.
Firmware hw_scan offload is not used, so no firmware probe path exists.

**5GHz monitor.** `monitor_wire::channel` accepts an exact NOHT/HT20
chandef on any typed 5GHz primary (5180..=5885MHz, still signed-admission
gated), `frequency` is cfg80211 `ieee80211_channel_to_freq_khz`, and
`observed_channel` expects rtw8852b_rfk.c `_ch_setting` on 5GHz:
`0x1c00 | CFGCH_BAND1_5G<<16 | CFGCH_BAND0_5G<<8 | primary` on all four
DAV/DDV words. Capture metadata carries the observed 5GHz frequency (the
shared radiotap encoder is band-aware).

**Interface band.** `get_wireless_info` advertises the 2.4GHz band with its
admitted primaries and, only when at least one 5GHz primary is
signed-admitted, a 5000MHz band listing exactly those primaries (core.c
`rtw89_core_set_supported_band`, narrowed to the admission mask).
Association requests are checked against the same mask and the cfg80211
frequency of the primary.

Remaining before `five_ghz_operation` is whole: only native two-arch
execution and physical validation (not claimable here). New unexecuted
cases: `smoke_rtw89_b_5ghz_channel_record_admits_passive_dfs_host_span`
(renamed from `..._admits_only_non_dfs_host_span`),
`smoke_rtw8852b_dfs_channel_scanned_passively_without_probe`,
`smoke_reg_witness_classifies_passive_channels`,
`smoke_reg_witness_scan_generation_retracts_and_scopes`, `smoke_rtw8852b_5ghz_station_probe_rates_and_admission_follow_linux`,
`smoke_rtw8852b_5ghz_band_advertised_and_scanned_when_admitted`,
`smoke_rtw89_b_operating_profile_5ghz_matches_linux_indices_and_groups`,
`smoke_rtw89_b_channel_bb_programs_5ghz_subbands_and_reads_back_chan_idx`,
`smoke_rtw89_b_rf_synth_tunes_5ghz_band_bits_for_each_primary`,
`smoke_rtw89_b_power_plan_selects_5ghz_ww_limits_without_cck`,
`smoke_rtw89_b_full_radio_retunes_across_bands_with_band_change_tssi_scan`.

### RTL8852B 40/80MHz operating channels

Scope (`wide_channels`): rtw8852b.c `support_bandwidths` is 20/40/80MHz, so
the admitted AX chip RTL8852B implements HT40/HE40 (2.4/5GHz) and VHT80/HE80
(5GHz). RTL8852C 160MHz belongs to the RTL8852C lane (its `operating_channel_c`
geometry and `radio_policy_c` records already carry 160MHz blocks).
RTL8852A and RTL8922A have station owners now but no wide-channel
program yet (their own open chip rows), so "all AX chips" narrows to
RTL8852B here; RTL8851B reuses this wide path one-stream (see the
RTL8851B station section).

**Geometry.** `operating_channel::Profile` now carries `(primary, center,
Width)`: `new_2ghz_40(primary, secondary_above)` (both halves within 1..=13),
`new_5ghz(primary, width)` (unique IEEE block from 36/100/149, every
subchannel a core.c `rtw89_channels_5ghz` channel, never narrowed) and
`new_wide`. It derives chan.c `rtw89_get_primary_chan_idx`, phy.c
`rtw89_phy_get_txsc`, the whole occupied span, the 20MHz subchannels, the
center-based subband/SCO compensation/gain bands and the rtw8852b_rfk.c
`_tssi_get_ofdm_group` TSSI_EXTRA groups. 20MHz bindings are byte-identical;
wide programs bind under a separate domain. Case:
`smoke_rtw89_b_operating_profile_wide_matches_linux_chandef_geometry`.

**Program (Linux 7.3-rc4).** MAC `__rtw8852bx_set_channel_mac`: RFMOD
0/BIT(0)/BIT(1) and TX_SUB_CARRIER `txsc20 | txsc40 << 4`. BB
`rtw8852bx_ctrl_bw`: FC0 BW_SET = width, PRICH = `pri_ch_idx`, 40MHz R_RXSC
(CCK primary), `rtw8852bx_5m_mask` (40MHz always, 80MHz at UPMOST/LOWEST,
SBD opt), readback of BW_SET/PRICH/chan_idx. RF `_ctrl_ch(chan->channel)` on
the center, `_bw_setting` CFGCH_BW_40M/80M, `_set_rxbb_bw` 0x13/0xb, readback.
IQK `iqk_bw`: TXK/RXK `((0x8|0xb) + bw) << 8`, R_IQKCH BW, 80MHz
`_iqk_rxclk_setting`. TSSI `_tssi_get_ofdm_de` extra-group averaging. DPK:
TXBB `bw + 1`, `_dpk_tpg_sel`, 80MHz AFE CFCH/BW_SEL EX set/restore, 80MHz
AGC `_dpk_lbk_rxiqk` instead of the RXCFIR bypass, MDPD order 2 only for 5GHz
below 80MHz. Power `rtw89_phy_fill_txpwr_limit_{40m,80m}_ax` and
`_ru_{40m,80m}_ax`: the 40-byte limit page and RU sections from the center /
primary / subchannels (`mcs_40m_0p5` = min), firmware LMT/LMT_RU elements or
the frozen WW0 rows (`operating_power_defaults.rs` MCS40_2GHZ/MCS40_5GHZ/
MCS80_5GHZ, same rtw8852b_table.c SHA256). RF_GET_MCCCH carries the center
(`rfk_mcc->ch[] = chan->channel`). Cases:
`smoke_rtw89_b_channel_bb_programs_wide_width_primary_and_5m_mask`,
`smoke_rtw89_b_rf_synth_tunes_wide_center_and_bandwidth_bits`,
`smoke_rtw89_b_power_plan_fills_wide_limit_and_ru_pages_like_linux`.

**Signed record and admission.** Each 40/80MHz operating channel has its own
N52C record `rtw89/rtw8852b-chan-v1-chNN-bwWW-cCCC-<mac>.bin`
(`[54..57] = [1, width, primary]`, `[68] = center`, otherwise the unchanged
N52C format) over a distinct wide recipe/identity (`Board::new_noninitial`
wide domain); it never admits, nor is admitted by, the primary's 20MHz record
or the other HT40 side. `Qualification` keys records and the active envelope
by the full profile (`active_profile`), and `check_envelope` requires one
host rule over the whole occupied span with cfg80211 `reg_get_max_bandwidth`
>= the width. `preflight_full_radio` loads every typed wide profile
(`wide_profiles`); `Native::admitted_wide` lists the currently admitted ones;
`Native::retune_full_radio_to` programs an exact typed profile with the same
drain/withhold/select/republish contract as the 20MHz owner. No board value
is invented: without provisioned wide records nothing wide is admitted.
Case: `smoke_rtw89_b_wide_channel_record_binds_width_center_and_whole_span`.

**Station capability (`station_control`).** `local_ht40` is `local_ht`
plus core.c `rtw89_init_ht_cap` `SUP_WIDTH_20_40 | DSSSCCK40 | SGI_40`
(every other field unchanged). `local_vht80` is `rtw89_init_vht_cap`
restricted to the TX-A/RX-AB profile: VHT-MCS0..9 RX on two streams and TX
on one (`0xfffa`/`0xfffe`), `SHORT_GI_80`, `RXLDPC`, `RXSTBC_1`; TXSTBC,
SU/MU beamformee/STS, HTC_VHT, the large `max_vht_mpdu_cap` and 160MHz are
cleared like the HT/HE profiles. `local_he_wide` is `local_he` with HE PHY
cap0 `CHANNEL_WIDTH_SET_40MHZ_IN_2G` (2.4GHz) or
`CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G` (5GHz). `wide_phy` mirrors mac80211
`ieee80211_determine_ap_chan`: it tries VHT80 (5GHz) then HT40 and uses a
candidate only when its selected chandef (`Offer::from_elements`) is exactly
a profile in `Native::admitted_wide`; otherwise the unchanged 20MHz HT/HE20
join is used. Wide is offered only under the signed WMM/HT programs
(HE-wide additionally under `He`), and never when any subchannel of the span
is passive-only (no beacon witness covers a wide span). Every wide record
identity binds `station_control::wide_fingerprint` (the exact HT40/VHT80/
HE-wide bodies and the wide RA recipe). Case:
`smoke_rtw89_b_wide_capability_offered_only_on_admitted_chandef`.

**Association.** `Station::associate` retunes to the selected profile through
`Io::station_retune_wide` (`Startup::retune_wide` ->
`Native::retune_full_radio_to`, RTL8852B only) before authentication
(mac80211 `ieee80211_prep_channel`); the plan's own offered chandef must
equal the tuned profile. A disconnect or failure makes the owner terminal
(`packet_stop`), so the radio never emits again on the wide program and the
next owner starts from the channel1 20MHz program; a still-passive station
retuning to a 20MHz primary programs the narrow profile (`Station::wide`
defeats the same-primary shortcut). A CSA on a wide link fails the link
(mac80211 connection loss when the new chandef cannot be used) instead of
narrowing silently: the native CSA owner retunes 20MHz profiles only.

**RA.** `codec::ra_wide` keeps `rtw89_phy_ra_sta_update`'s HE > VHT > HT
precedence; `BW_CAP[7:6]` is the tuned width (`RTW89_CHANNEL_WIDTH_40/80`,
checked against the negotiated chandef), SGI is HT `SGI_40` (40MHz) or VHT
`SHORT_GI_80` (80MHz) from the negotiation, and the VHT branch is
`mode = VHT|OFDM`, `get_mcs_ra_mask(map, 9, 1)` masked to
`RA_MASK_VHT_1SS_RATES | SUBOFDM`, LDPC from the peer RXLDPC, STBC0, SS1.
The 20MHz RA path is untouched (`Io::station_configure_ra_wide` is used only
on a wide link). Cases:
`smoke_rtw89_b_wide_ra_h2c_bw_sgi_and_vht_mask_match_linux`,
`smoke_rtw8852b_ht40_admitted_chandef_advertised_retuned_and_ra_bw40`.

**RX.** The RTL8852B assembler surfaces RX bandwidth up to
`RTW89_CHANNEL_WIDTH_80` and VHT NSS1/NSS2 MCS0..9
(`RTW89_HW_RATE_VHT_NSS1_MCS0`); the packet owner admits a PPDU only up to
the width `Native::retune_full_radio_to` last programmed
(`Core::set_operating_width`) and VHT rates only on a 5GHz wide channel under
the HT program, dropping anything else without closing the station. RTL8852C
keeps its 20MHz/no-VHT assembler rule (C lane). Data TXWD BW/SC stay 0
exactly as Linux (only injection sets `data_bw`; firmware RA chooses the
bandwidth). Cases:
`smoke_rtw89_b_rx_wide_bandwidth_and_vht_rates_reach_packet_owner`,
`smoke_rtw89_b_packet_rx_width_follows_programmed_channel`.

**Advertisement.** `phy_capabilities(2400/5000)` returns the wide HT body
(plus VHT80 on 5GHz) and `hw_caps.ht/vht_supported` are set only for a band
with an admitted wide profile under the WMM/HT programs (sampled at
activation); otherwise nothing is advertised, as before.

Known gaps: the AP and monitor roles stay 20MHz; a wide link does not follow
a CSA; passive-only (DFS/NO_IR) spans join at 20MHz. Every case above is
written and unexecuted; native two-arch and physical validation remain.

### RTL8852B AP groundwork: host PS/U-APSD owner and AP H2C wire (partial; no native caller)

Linux rtw89 advertises `NL80211_IFTYPE_AP`, `WIPHY_FLAG_AP_UAPSD` and
`hw->uapsd_max_sp_len = IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL`
(core.c `rtw89_core_register_hw`). RTL8852B firmware never gains
`RTW89_FW_FEATURE_NOTIFY_AP_INFO` (fw.c `fw_feat_tbl`: RTL8922A/D only),
so `IEEE80211_HW_AP_LINK_PS` is not set, `rtw89_core_rx_pkt_hdl` stays
idle and mac80211 performs all AP power save in the host; rtw89 only
refreshes the firmware beacon on `set_tim` (`update_beacon_work`) and
routes `SEND_AFTER_DTIM` frames to the port HIQ.

`ap_ps.rs` (`ApPs`) mirrors that host owner exactly: rx.c
`ieee80211_rx_h_uapsd_and_pspoll` before `ieee80211_rx_h_sta_process`
(PM transitions only at end of frame exchange, unicast mgmt/data, no
MoreFrags); tx.c `ieee80211_tx_h_unicast_ps_buf` (bufferable MMPDU rule,
`STA_MAX_TX_BUFFER` 64 drop-oldest, `TOTAL_MAX_TX_BUFFER` 512 purge);
sta_info.c `__sta_info_recalc_tim` (delivery-enabled ACs ignored unless all
four are), `_deliver_wakeup`, `_get_frames`, `_more_data`,
`_deliver_response`, poll response (one frame, ends on TX status) and
U-APSD (Max SP 0/1/2/3 -> 128/2/4/6 frames from delivery-enabled ACs,
MoreData, EOSP on the last QoS frame or a trailing EOSP QoS-Null after an
MMPDU, EOSP QoS-Null TID 1/3/5/7 when empty); status.c EOSP ends
`WLAN_STA_SP` acked or not; `sta_info_buffer_expired`; and
`__ieee80211_beacon_add_tim` non-S1G partial virtual bitmap. Group frames
are not host-buffered (`group_after_dtim`, no
`HOST_BROADCAST_PS_BUFFERING`). Only frame-control MoreData and QoS EOSP
are rewritten; CCMP/GCMP mask both out of the AAD.

`ap_wire.rs` formats exact AX words: `rtw89_fw_h2c_role_maintain` (AP self
role / `SELF_ROLE_AP_CLIENT` peers), AX `rtw89_fw_h2c_join_info` (vif keeps
`NET_TYPE_AP_MODE` with `dis_conn`, peer disconnect reports `NO_LINK`),
`rtw89_fw_h2c_update_beacon` (port, band, `GRP_IE_OFST = tim_offset |
BIT(7)` relative to the 24-byte header, MACID, HW SSN select/mode 1,
CCK1 on 2.4 GHz else OFDM6, W2 zero; a TIM offset at or above 128 is
refused because Linux would overflow the field), head||TIM||tail beacon
composition, and RTL8852B placement (`B0_HI`/CH9 with the vif port for
`SEND_AFTER_DTIM`, `B0_MGMT`/CH8, `rtw89_core_get_qsel` BE/BK/VI/VO).

Missing for AP mode and therefore for the `uapsd` row: an AP Native/runtime
owner (MACID allocation, `rtw89_mac_port_update` AP port register program
incl. `hiq_win`/`hiq_dtim`/beacon interval/`func_en`, `rtw89_fw_h2c_cam`
AP address/BSSID CAM, AP-client default/assoc CMAC/DMAC tables and macid
pause), multi-peer TXWD MACID/port and RX MACID classification, per-peer
keys, the narf_wireless `start_ap_async`/station/beacon/mgmt-TX controls,
a signed AP channel/power admission, and the HIQ/CH9 ring. No AP or
U-APSD capability is advertised. Eight cases are written, unexecuted:
`smoke_rtw89_ap_ps_buffers_dozing_peer_sets_tim_and_wakeup_flushes`,
`smoke_rtw89_ap_ps_pspoll_releases_one_with_more_data_and_eosp_status`,
`smoke_rtw89_ap_ps_uapsd_trigger_delivers_max_sp_with_eosp`,
`smoke_rtw89_ap_ps_all_acs_delivery_enabled_tim_and_mmpdu_null`,
`smoke_rtw89_ap_ps_limits_expiry_and_peer_validation`,
`smoke_rtw89_ap_wire_role_and_join_words_match_fw_masks`,
`smoke_rtw89_ap_wire_beacon_update_tim_offset_and_rate`,
`smoke_rtw89_ap_wire_hiq_mgmt_and_ac_placement`.

### RTL8852B AP MAC/firmware control owner (partial; no native caller)

`station_control/codec.rs` is now MACID/port parameterised (`pause_at`/
`pause_register`, `Cam`/`cam_entry` with separate address/BSSID valid,
`default_cctl_at`, `fixed_cctl_at`, `ba_cam_at`, `ra_at`, `table_init`);
the station keeps MACID0/port0 and its bytes are unchanged (the old
builders are the `(0, 0)` wrappers).

`ap_control.rs` (`ApController`) is the AP control-plane owner for one AP
link on MAC0/port0/MACID0 with address and BSSID CAM 0, running over the
retained `station_control::Interface` (current device capability around
each register transaction, exact H2C DONE_ACK, fail-closed admission):

- `initialize` = mac.c `rtw89_mac_vif_init`: `crypto_off`, AX
  `rtw89_mac_port_update`, nonsecure DMAC/CMAC table init, MACID0 unpause
  (applied-bit fence), `ROLE_MAINTAIN(CREATE)` `SELF_ROLE_AP`, `JOIN_INFO`
  (`dis_conn`), address/BSSID CAM, AP default CMAC table.
- `port_update` follows every `rtw89_mac_port_cfg_*` step in source order:
  `func_sw` (only with `PORT_FUNC_EN`: `rtw89_mac_bcn_drop` incl. both
  `rtw89_mac_check_packet_ctrl` BCNQ polls that, like Linux, only warn on
  timeout, `beacon_int + 1` ms, `TSFTR_RST`, `BCN_CNT_TMR`), TX/RX report
  off, `NET_TYPE_AP_MODE`, `TBTT_PROHIB_EN|BRK_SETUP`, no BSSID fit/TSF
  update, `BCNTX_EN`, beacon space, `hiq_win` 16, `UPD_HGQMD|UPD_TIMIE` and
  `DTIM_NUM`, HIQ drop clear, setup 2/hold 200/mask 0/TBTT early 5/agg 1,
  BSS colour 0, `PORT_FUNC_EN`, 20 us, beacon early 160 and BCAID 0.
  `rtw89_mac_port_tsf_resync_all` is a no-op for the single AP vif.
  Persistent fields are read back; the `TSFTR_RST` strobe and counter
  reset are not.
- `start` = `rtw89_ops_start_ap` (port program with the BSS beacon
  interval/DTIM, vif assoc CMAC table with `ULDL` 0/`DATA_DCM` 0,
  `TYPE_CHANGE`, `JOIN_INFO`, CAM); `publish_beacon` =
  `rtw89_fw_h2c_update_beacon` (class 5 function 5).
- `add_peer`/`associate_peer`/`remove_peer` = core.c AP branches of
  `rtw89_core_sta_link_add`/`_assoc`/`_disconnect`/`_remove`: lowest-free
  MACID of 128 (`rtw89_acquire_mac_id`), unpause, `SELF_ROLE_AP_CLIENT`
  role, default and assoc CMAC tables, address CAM from the 128-entry pool
  (`acam_num`) with AID, `JOIN_INFO` connected/`NO_LINK`, CAM invalidated
  before release (vif BSSID CAM stays valid), RA with the peer MACID,
  `ROLE_MAINTAIN(REMOVE)` and MACID release.
- `stop` = `rtw89_ops_stop_ap` + `rtw89_mac_vif_deinit`.

Host crypto is retained (`RTW89_ADDR_CAM_SEC_NORMAL`, no security entries,
TX/RX hardware crypto off), so per-peer keys stay with the host RSNA owner,
as in the station profile.

Still missing for `uapsd`: a native caller (Native owner selection and
signed AP channel/power admission including `rtw89_chip_rfk_channel`),
multi-peer TXWD MACID/port and RX MACID classification, the HIQ/CH9 ring,
the narf_wireless AP controls, and wiring `ap_ps.rs` (buffering, TIM via
`publish_beacon` on `set_tim`, PS-Poll, U-APSD EOSP status). No AP or
U-APSD capability is advertised. Four new cases are written, unexecuted:
`smoke_rtw89_link_codec_macid_port_keeps_station_bytes`,
`smoke_rtw89_ap_control_vif_init_and_start_match_linux_order`,
`smoke_rtw89_ap_control_peer_lifecycle_allocates_macid_and_cam`,
`smoke_rtw89_ap_control_beacon_publication_and_fail_closed`.

### RTL8852C retained runtime (implemented, pending validation)

Chip row `rtl8852c`. These owners are the chip-specific RTL8852C pieces under
the retained B architecture. Together with the native lifecycle, signed
N5CB/N5CC records, coex, grant, retune and station admission sections below
they admit a C station at the RTL8852B chip-row scope (20/40/80/160 MHz per
admitted records; see the known-gaps paragraph for what stays documented).
No RTL8852B byte changes; an unprovisioned board stays unadmitted.

**Factory inputs.** `Factory::read` on RTL8852C reads the complete Linux
PHY-cap window (`rtw8852c_chip_info.phycap_addr` 0x590, `phycap_size` 0x60)
once, after the 1216-byte map, and takes the power-k/ECV/secure bytes
(0x5e9..0x5ee) from that same window; `c_phycap()` exposes it only after a
completed read. `factory_c::Calibration::from_factory` mirrors rtw8852c.c
`rtw8852c_efuse_parsing_tssi` (CCK 6, MCS 2G 5 + 5G 14, 6G 32 per path from
0x210/0x23a and 0x300/0x32a), `rtw8852c_efuse_parsing_gain_offset` (13
`RTW89_GAIN_OFFSET_*` bands incl. 6G L0..UH1 at 0x3a8..0x3b6, `_decode_efuse_gain`
nibbles) and `rtw8852c_read_phycap` (TSSI trim 8 + 6G trim 16, thermal and
PA-bias trim, Linux's erased-trim zeroing only after the whole read);
`thermal_setting`/`pa_bias_setting` are the `__thm_setting` and
TXG/TXA nibble values of `rtw8852c_{thermal,pa_bias}_trim`.

**PHY tables.** `radio_assets::Assets` accepts RTL8852C containers only with
all five BB/GAIN/RADIO_A/RADIO_B/NCTL elements. The shipped
`rtw89/rtw8852c_fw-{1,2}.bin` carry RADIO_A at `reg2.idx` 1 and RADIO_B at
idx 0, matching `rtw8852c_chip_info.rf_table = {radiob, radioa}`; that slot
order is required (the B order is refused, and vice versa). NARF carries no
static rtw8852c_table.c copy, so the legacy element-less `rtw8852c_fw.bin`
yields no PHY tables (`Error::Element`) rather than a fabricated default.

**Table/power/reset preparation.** `radio_init::Qualified::from_factory_c`
qualifies an actual valid C factory (RFE != 255). `Init::prepare` refuses
an assets/qualification chip mismatch before any write, decodes the gain
table with the generation decoder (phy.c `rtw89_phy_config_bb_gain_ax`),
writes BB, then `rtw8852c_init_txpwr_unit(PHY_0)` (UL/coex power CRs,
`rtw8852c_set_txpwr_ul_tb_offset(0)` V1 byte masks giving 0xd28c=0 and
0xd290=0xf4f4f4f4 without the B UL_TB enable bit, `rtw8852c_init_tssi_ctrl`
with the all-zero FLAT `rtw89_8852c_tssi_dbw_table` band-edge and fast-mode
fields) and `rtw8852c_bb_reset_all(PHY_0)` (HW-SI trigger hold, no B TSSI
tracking pause), each read back. RF tables follow `phy.c::rtw89_phy_init_rf_reg`
order over `{radiob, radioa}`: path B is written and paged first, then path A.

**Channel geometry (`operating_channel_c`).** A typed RTL8852C chandef
(`Band` 2.4/5/6GHz, `Width` 20/40/80/160MHz = `support_bandwidths`) built
only from Linux core.c channel lists (2.4GHz 1..14; the 28 `rtw89_channels_5ghz`
incl. UNII-4; 6GHz 1..233 step 4) and the unique IEEE channelization block
(5GHz blocks from 36/100/149, 6GHz from 1, every subchannel must exist; a
block leaving the set is refused, never narrowed; 2.4GHz HT40 takes an
explicit secondary side within 1..13). It derives chan.c `rtw89_chan_create`
fields (center/primary MHz, `rtw89_get_subband_type` incl. 6G IDX0..7,
`rtw89_get_tx_comp_band`, `rtw89_get_primary_chan_idx`,
`rtw89_get_primary_sb_idx`, `rfsi_band`), phy.h BB-gain and OFDM gain-offset
bands, phy.c `rtw89_encode_chan_idx(primary)`, rtw8852c.c
`rtw8852c_ctrl_sco_cck` thresholds (40MHz element literally as Linux, incl.
`primary_ch == 1`), `rtw8852c_ctrl_ch` FC0/`DIV_ROUND_CLOSEST(1<<18, fc)` and
CCK pulse coefficients, and rtw8852c_rfk.c CCK/OFDM/trim and 6GHz OFDM/trim
TSSI groups (golden tables generated from the Linux switch statements).
`is_psc` is the 802.11ax PSC set (5 + 16k). `txsc`/`mac_program` are phy.c
`rtw89_phy_get_txsc` and the `rtw8852c_set_channel_mac(MAC_0)` RFMOD/
TX_SUB_CARRIER/TXRATE_CHK values. It is a geometry fact: no
caller programs or admits a C channel from it yet. Unexecuted case:
`smoke_rtw89_c_operating_channel_matches_linux_geometry_and_tssi_groups`.

**DM hardware setup, NCTL and `rfk_init`.** `radio_init::controls_c` is
rtw8852c.c `rtw8852c_bb_sethw`: DBCC 80+80 EVM report enables (0x0a10/0x2a10
bit 0), `rtw8852c_bb_macid_ctrl_init(PHY_0)` (0xd36c..0xd568 zero),
`rtw8852c_bb_gpio_init` (per path 0x5800/0x7800: TRSW_A set, TRSW_X/
TRSW_SO_A2 clear, 0x80/0x84 = 0x77777777, RFE_E/O_SEL/SEL0/SEL32_A2, the
sixteen `rtw8852c_bb_gpio_trsw` fields and six `rtw8852c_bb_gpio_rfm` bytes
in Linux order), all read back, then the `R_RPL_BIAS_COMP{,1}`
(0x4df0/0x6df0 [7:0]) `offset_base` reads. `radio_init::nctl_c` is phy.c
`rtw89_phy_preinit_rf_nctl_ax` without the RTL8852B/BT-only second
`R_IOQ_IQK_DPK |= 0x2`, the 0x8080 poll, then the firmware NCTL table
(`nctl_post_table` is NULL for C). `rfk::c::Init::prepare` is
`rtw8852c_rfk_init` for non-DBCC PHY_0 (`_kpath` = RF_AB): `is_tssi_mode`
cleared, `rtw8852c_dpk_init` (DPK enabled, reload off), `_rck` A then B
(20us poll), `_dac_cal` (`_drck` + `rtw8852c_drck_defs`, ADDCK S0/S1 with
backup/reload into `R_ADDCK{0,1}_RL`, `_dack_s0`/`_dack_s1` with
`rtw8852c_txck_force(DAC_160M)`, `rtw8852c_dack_defs_s{0,1}`, reset defs,
all-four-OK `_check_dack_done`, MSBK/bias/DADCK backup and
`_dack_reload_by_path` words 0xc200..0xc210 + offset) bracketed by
`BTC_WRFKT_DACK` START/STOP (the inner ONESHOT notifications do no I/O for
DACK), then the un-notified `_rx_dck(PHY_0, false, retry_limit 1)`, which
always takes `_rx_dck_recover` (incl. the asymmetric `<`/`<=` threshold and
`_rx_dck_value_rewrite`). LCK/RX-DCK thermal baselines are the fresh EWMA
before any track sample and carry no register I/O. Where Linux only logs a
poll timeout (RCK, DRCK, ADDCK, DACK, RX DCK toggle) NARF fails the attempt
closed. No native caller runs these yet. Unexecuted cases:
`smoke_rtw89_c_bb_sethw_gpio_and_nctl_follow_rtw8852c`,
`smoke_rtw89_c_rfk_init_rck_dack_rxdck_follow_rtw8852c`.

**Channel MAC and BB channel control (`channel_c`).** `channel_c::program`
writes rtw8852c.c `rtw8852c_set_channel_mac(MAC_0)` from
`Profile::mac_program` (byte-masked RFMOD 0xc010, TX_SUB_CARRIER 0xc088,
TXRATE_CHK 0xc628 clear-then-set) and then the `rtw8852c_set_channel_bb`
prefix for non-DBCC PHY_0: `rtw8852c_ctrl_sco_cck` (2.4GHz) and
`rtw8852c_ctrl_ch` — per path `rtw8852c_set_gain_error` over the
`bb_gain_lna`/`bb_gain_tia`/`bb_gain_bypass_lna`/`bb_gain_op1db_a` register
tables (2G `gain_g` vs `gain_a`, op1db and TIA0/LNA6 only off 2G) from the
decoded `radio_gain::Gain` at `rtw89_subband_to_bb_gain_band`,
`rtw8852c_set_gain_offset` (skipped unless `offset_valid`; the shared
R_RPL_OFST CCK write is per path so path B's value wins, as in Linux; S8
clamps), path band select, `R_2P4G_BAND` clear, FC0/`DIV_ROUND_CLOSEST`
SCO, CCK `R_PCOEFF*` and `B_CH_IDX_SEG0` — then `rtw8852c_ctrl_bw`
(FC0 BW set, CHBW SBW/`pri_ch_idx`, per-path sample delay 3/3/2/1 and BW
select 0xf/0xf/0xd/0xb for 20/40/80/160MHz, BW40 2xFFT/T2F GI combine,
`rtw8852c_bw_setting` A and B, `rtw8852c_edcca_per20_bitmap_sifs`). Every
final field is read back.
Unexecuted case: `smoke_rtw89_c_channel_mac_and_ctrl_ch_follow_rtw8852c`.

**Channel IQK (`rfk::c_iqk`).** `Iqk::run(profile)` is rtw8852c_rfk.c
`rtw8852c_iqk(PHY_0)` for any typed `operating_channel_c::Profile`:
`BTC_WRFKT_IQK` START, `rtw89_chip_stop_sch_tx`, `_wait_rx_mode` (RF_AB),
`_iqk_init` (R_IQKINF clear, wideband: `is_nbiqk = false`), then per path
A, B between ONESHOT START/STOP `_doiqk`: `_iqk_get_ch_info` (band, bw,
`chan->channel`, IQK 0x2a / NCTL 0xd, `syn1to2` = 1), the
`rtw8852c_backup_{bb,rf}_regs` backup, `_iqk_macbb_setting`
(`rtw8852c_txck_force(DAC_960M)`, `rtw8852c_rxck_force(ADC_1920M)` with
the `_ck*` defs), `_iqk_preset` (RFK MCC table index 0: the first idle
`rtw89_rfk_chan_lookup` slot), `_iqk_txk_setting`, `_iqk_lok` +
`_lok_finetune_check`, `_txk_group_sel` (3 groups), `_iqk_rxk_setting`
(ADC 480/960/1920M by width, `rtw8852c_iqk_rxk_cfg_defs`),
`_rxk_group_sel` (4 groups), `_iqk_info_iqk` (persistent `iqk_times` /
`iqk_fail_cnt`), `_iqk_restore` (0x1219 + path), the
`rtw8852c_iqk_afebb_restore_defs_{a,b}` table and the backup restore.
Linux `_iqk_check_cal` always reports success, so only the LOK range check
can fail; NARF refuses a LOK failure (no results published) and fails any
0xbff8/RX-mode poll timeout closed. Unexecuted case:
`smoke_rtw89_c_iqk_channel_follows_rtw8852c_wideband_flow`.

**Channel TSSI (`rfk::c_tssi`).** `Tssi::run(profile, calibration,
tracking)` is `rtw8852c_tssi(PHY_0)` (non-DBCC, A then B): both
`rtw8852c_tssi_disable_defs_*`, per path `_tssi_set_sys` (common defs,
`R_Px_TSSI_ADC_CLK` 0/1/2 for <=40/80/160MHz, 2G vs 5G table — 6GHz takes
the 5G table, as Linux's `band == 2G` condition), `txpwr_ctrl_bb`,
`_he_tb`, DCK, bbgain split, `_tssi_set_tmeter_tbl`, `slope_cal_org`,
`_tssi_set_aligk_default` (2G/5G/6G defaults; RTL8852C measures no PMAC
alignment), slope and run-slope, then `_tssi_enable` (track, TXAGC offset
moving average, enable; `is_tssi_mode` = true) and `_tssi_set_efuse_to_de`
(`_tssi_get_cck_group(chan->channel)` whatever the band, OFDM/6G-MCS and
trim/6G-trim groups with the `TSSI_EXTRA` average, CCK long/short and the
six MCS DE fields). All 39 register programs are generated verbatim from
rtw8852c_rfk_table.c (`rfk/c_tssi_tables.rs`). Thermal-offset rows come
only from the container's first TXPWR_TRK element (id 18) parsed as fw.c
`rtw89_build_txpwr_trk_tbl_from_elm` with all sixteen 2/5/6GHz types
required (`c_tssi::Tracking`); the shipped `rtw8852c_fw-{1,2}.bin` carry
it. NARF has no copy of the static `rtw89_8852c_trk_cfg`, so a container
without it is refused. An unprogrammed thermal (0xff) takes Linux's
meter 32 / zero-offset default. Linux C TSSI sends no coexistence
notification; the `Kind::Tssi` bracket is the I/O-free RFK exclusivity
used by B. Unexecuted case:
`smoke_rtw89_c_tssi_channel_follows_rtw8852c_tables_and_de`.

**Channel DPK (`rfk::c_dpk`).** `Dpk::run(profile, cut, tssi_mode)` is
`rtw8852c_dpk(PHY_0)` with the `rtw8852c_dpk_init` state (enabled, reload
off, so `cur_idx` = 0): `BTC_WRFKT_DPK` START, TX pause, `_wait_rx_mode`,
`_dpk_bypass_check` (CHIP_CAV outside 2.4GHz; RTL8852C has no external-PA
FEM flags) -> `_dpk_force_bypass`, else `_dpk_cal_select`: KIP (`kip_reg`)
and RF backup, TSSI pause when `is_tssi_mode`, per path RX AGC off, BBDC,
`_dpk_bb_afe_setting`, `_dpk_main` (`_dpk_rf_setting`, `_set_rx_dck`, KIP
power/clock on, `_dpk_kip_preset_8852c` with DPD_SEL 0x01 on CAV else
0x0c, TX power force, 15 dBm, `_dpk_tpg_sel`, the `_dpk_agc` state machine
with `_dpk_sync_check` thresholds 200/200/170, dgain resync, 2.4GHz RXIQC
bypass or `_dpk_lbk_rxiqk`, gain loss + `_dpk_pas_read`, 7..24 dBm steps,
RXBB adjust; `_dpk_idl_mpa` with the MDPD order tables and the 5x overflow
re-K; `_dpk_para_query`; `_dpk_on` with `_dpk_order_convert` and
`_dpk_gain_normalize_8852c(false)`) and `_dpk_onoff`, then per path KIP
restore one-shot, backup reload, AFE restore, RX AGC on, TSSI resume, KIP
power/clock off, and the RX DCK when path A `RR_DCKC_CHK` is set. Sync
failure ("need Check") leaves that path's MDPD off as Linux does. Linux
only logs a 20ms one-shot timeout and indexes `dpk_par_regs` with an
unchecked `cur_k_set - 1`; NARF fails both closed. Unexecuted case:
`smoke_rtw89_c_dpk_channel_follows_rtw8852c_agc_and_bypass`.

**Rest of `rtw8852c_set_channel_bb` (`channel_c::program_tail`).** After
`ctrl_bw`, `tail_fields(profile, cav)` is, in Linux order for non-DBCC
PHY_0 with no user `antenna_tx`: CCK enable / `R_RXCCA_V1` / PD arbiter by
band; `rtw8852c_spur_elimination` (`rtw8852c_spur_freq` 2440/2480/5760/
6920MHz, `rtw8852c_set_csi_tone_idx` round-closest/round-down mod 2048
against the center `chan->freq`, the 160MHz `rtw8852c_spur_notch`
0xe7f/0x280 on PHY_0 and PHY_1 or `rtw8852c_set_nbi_tone_idx` A and B incl.
the 160MHz +-40MHz notch2 selection and Linux's doubled notch1-disable,
`R_PD_BOOST_EN` off for UP3X/LOW3X); `rtw8852c_ctrl_btg_bt_rx(band == 2G)`;
`rtw8852c_5m_mask`; the non-CAV 160MHz P80 RU allocation (PHY 0x2410 and
MAC 0xd848); CDD EVM (off only at 6GHz/160MHz); TXPW RSTB 1 then 3 per
path; MUIC on at 6GHz; `rtw8852c_ctrl_tx_path_tmac` (RF_B at 6GHz, else
RF_AB: MAC_SEL for PHY_0/PHY_1, MACID antenna table 0xdc00..0xddfc zeroed,
`R_AX_PATH_COM0..11` defaults with the per-path COM0/1/2/7/8 values). Then
`rtw8852c_bb_reset_all` (HW-SI 7, 1us, RSTB_ASYNC 1/0, HW-SI 0, RSTB 1).
Every final bit is read back, folding overlapping writes per address.
Unexecuted case: `smoke_rtw89_c_set_channel_bb_tail_follows_rtw8852c`.

**C channel switch and channel RFK (`rfk::c_channel`).**
`Channel::set_channel(profile, inputs, cut)` is rtw8852c.c
`rtw8852c_set_channel_help(enter)` (stop scheduler TX, PPDU status off,
`dfs_en(false)`, `tssi_cont_en_phyidx(false)` A/B, `adc_en(false)`, 40us,
`bb_reset_en(false)`), `rtw8852c_set_channel` (`channel_c::program`,
`program_tail`, then rtw8852c_rfk.c `rtw8852c_set_channel_rf`: `_ctrl_ch`
with its channel-range guard, RF18 at 0x18 and 0x10018 per path with 100us
holds, `_ctrl_bw` incl. CFCH BW0/BW1 and the CAV path-B RF18 copy,
`_rxbb_bw` LUT/TIA; final RF18 words read back) and
`set_channel_help(exit)` (PPDU status 0x2b + HW_RPT_FWD host, ADC/DFS on,
`tssi_cont_en(true)` A then B, each running `_tssi_set_efuse_to_de(PHY_0)`
for both paths as Linux, `bb_reset_en(true)` with CCA release only on
2.4GHz, resume TX). `Channel::rfk_channel(calibration, tracking, cut)` is
`rtw8852c_rfk_channel`: `rtw8852c_mcc_get_ch_info` (single context: table
index 0), `rtw89_btc_ntfy_conn_rfk(true)` (a state flag, no I/O), RX DCK
with the retained `is_tssi_mode`, IQK, 30ms preserve, TSSI (updates the
retained `is_tssi_mode`), 30ms, DPK, `conn_rfk(false)`, and returns the
`rtw89_fw_h2c_rf_ntfy_mcc` body. RTL8852C firmware has `RFK_NTFY_MCC_V0`
from 0.0.0 (fw.c), so the body is `rtw89_fw_h2c_rf_get_mccch_v0`
{ch_0 = center, ch_1 = 0, band_0, band_1 = 0, current_channel, current_band}
(24 bytes; B uses the 20-byte non-V0 layout). The BT preserves always wait
the full 30ms because the owner cannot assert A2DP absence (as B).
`set_channel` now composes core.c `__rtw89_set_channel` order: help
enter, `rtw8852c_set_channel`, `rtw8852c_set_txpwr` (below; the plan must
be built for the same profile, else `Policy`), help exit, then -- when no
channel was programmed yet (Linux `!entity_active`) or the band changed --
`rtw89_btc_ntfy_switch_band` (`Interface::coex_switch_band`) and
`rtw8852c_rfk_band_changed` = `rtw8852c_tssi_scan` (`c_tssi::Tssi::scan`):
no I/O unless both retained `is_tssi_mode` paths are set, else
`_tssi_disable`, per path `_tssi_set_sys`/`_tssi_set_dck`/
`_tssi_set_tmeter_tbl`/`_tssi_slope_cal_org`/`_tssi_set_aligk_default`,
`_tssi_enable`, `_tssi_set_efuse_to_de`. Unexecuted case:
`smoke_rtw89_c_set_channel_rf_and_help_follow_rtw8852c`.

**C TX power (`radio_power_c`).** `Plan::from_assets(assets, rfe, profile)`
selects each TXPWR element by fw.c `rtw89_fw_recognize_txpwr_from_elm`:
non-matching `aid` never reaches it (`radio_assets` keeps AX aid 0), an
element whose `rfe_type` equals the efuse RFE (logical 0x2ca) is taken and
the last such wins, a default (`rfe_type` 0) element is taken only while
the stored conf is unset or default (last default wins absent an exact
match). Entries follow `rtw89_fw_load_txpwr_*`: wider-than-struct entries
only with a zero extension, invalid entries skipped, later entries
overwrite; a size-inconsistent element header fails closed. The program is
`rtw8852c_set_txpwr(PHY_0)`: phy.c `rtw89_phy_set_txpwr_byrate_ax` (CCK
always from `byr[2G][0]`, bw 0 / ofdma 0, rf>>1), `_offset_ax` (0xd204
[19:0]), `rtw8852c_set_tx_shape` (2.4GHz CCK DFIR flat/sharp/sharp_14 at
0x45bc.. [23:0], `rtw89_phy_tssi_ctrl_set_bandedge_cfg` with
`rtw89_8852c_tssi_dbw_table`, DAC_COMP_POST_DPD_EN A/B),
`rtw89_phy_set_txpwr_limit_ax` / `_limit_ru_ax` for 20/40/80/160MHz
(`rtw89_phy_fill_txpwr_limit{,_ru}_*m_ax` incl. 0p5/2p5 minima and the
u8 subchannel arithmetic), `rtw8852c_set_txpwr_diff` (no DAG ->
`set_txpwr_ref(0)`, the same words as B) and `rtw8852c_set_txpwr_sar_diff`
(no SAR source: `R_TXPWRB`/`R_P1_TXPWRB` [8:0] = 126). The regulatory
state is Linux's default without a country: regd `RTW89_WW`, no SAR, no
DA tables, no 6GHz TPE. NARF has no static rtw8852c_table.c power tables:
missing BYRATE, LMT_{2,5}GHZ, LMT_RU_{2,5}GHZ or TX_SHAPE_LMT is refused
(the shipped rtw8852c_fw-{1,2}.bin carry all, fw-2 also RFE-5 limit and
shape elements); RFE 255 is refused (`Policy`), and `from_elements` refuses a
6GHz profile (6GHz needs `from_elements_6ghz`, "C 6GHz power and records"
below). It is register
configuration only, never a conducted-power or regulatory claim.
Unexecuted cases:
`smoke_rtw89_c_txpwr_selection_follows_rtw89_fw_recognize_txpwr_from_elm`,
`smoke_rtw89_c_set_txpwr_follows_rtw8852c_and_phy_ax`.

**C radio owner and native chip dispatch (`radio_c`).** `radio_c::Radio`
is the retained C counterpart of `radio_full::Radio`, in phy.c
`rtw89_phy_dm_init` order after the C tables: `prepare_controls`
(`rtw8852c_bb_sethw` = `radio_init::controls_c`, keeping both
`offset_base` bytes; `rtw89_phy_init_rf_nctl` = `nctl_c`; `rfk_hw_init`/
`rfe_gpio` are NULL for C) before any RFK admission, then `prepare`:
`rtw8852c_rfk_init` (`rfk::c::Init`), `rtw8852c_set_txpwr_ctrl`
(`rtw8852c_set_txpwr_ref(0)`, B's reference words), `rtw8852c_power_trim`
(`power_trim_writes`: RR_TM2 OFF `__thm_setting` per path, then RR_BIASA
TXG/TXA, each only with programmed PHY-cap trim), `rtw8852c_bb_cfg_txrx_path`
(`txrx_path_fields`: `rtw8852c_bb_cfg_rx_path(RF_PATH_AB)` with the
default-chandef 2.4GHz `ctrl_btg_bt_rx`, then the `hal.rx_nss` HT/VHT/HE
limits; every final bit read back), `Channel::set_channel` with the
`radio_power_c::Plan` for the initial primary and `rfk_channel`, returning
the 24-byte MCC V0 body. `retune` is `set_channel` + `rfk_channel` on a Ready
radio. Between `bb_sethw` and NCTL, `prepare_controls` runs the phy.c DM
sub-inits as `phy_operating::Operating::prepare_c` (below). Native dispatch: `radio_access` admits B or C with the
chip's own factory PHY-cap and PHY window (`NativeIo::c_phy_window`, same
`rf_base_addr`), `radio_profile_current` dispatches the PHY-profile check
(C: actual C identity + firmware receipt topology), `prepare_radio_tables`
selects `Qualified::from_factory_c` for C, and
`Native::prepare_radio_c(owner, tables, assets, primary)` runs the owner and
sends `RF_GET_MCCCH` (H2C 2/0x0a/2) with the V0 body. Its admission is the
C signed record family (below: C calibration + `radio_policy_c` profile
record, then coexistence ready and `rfk::Interface::admit`), checked before
the first write; no C coexistence owner exists yet, so an actual RTL8852C
stays unadmitted and no ordinary grant is installed. No Startup caller invokes it; the C native
MAC/RX lifecycle (`prepare_mac`, `prepare_receive`) now exists for C (below). Unexecuted cases:
`smoke_rtw89_c_dm_init_txrx_path_and_power_trim_follow_rtw8852c`,
`smoke_rtw89_c_radio_owner_starts_new`.

**C firmware PHY-cap (`scheduler_mailbox` V1 block).** The register
mailbox is chip-selected at `Native::from_cold`
(`Mailbox::for_chip`): RTL8852C uses rtw8852c.c `rtw8852c_h2c_regs`/
`rtw8852c_c2h_regs` (`R_AX_H2CREG_DATA0..3_V1` 0x7140.., `R_AX_C2HREG_DATA0..3_V1`
0x7150..) with `R_AX_H2CREG_CTRL_V1` 0x7160 / `R_AX_C2HREG_CTRL_V1` 0x7164 and
the shared `R_AX_UDM1 + 1` H2C/C2H counters; B keeps the 0x8140 block. The
same AX GET_FEATURE part0 exchange (mac.c `rtw89_mac_setup_phycap_part0`)
decodes identically (C `chip->tx_nss`/`rx_nss` = 2, `rf_path_num` = 2) into a
C-bound `firmware_phycap::Receipt` (`is_c`, distinct fingerprint label);
`query_firmware_phycap` admits B or C, refuses a receipt from the other
chip's block and checks `radio_profile_current` (C requires a C receipt).
The firmware scheduler H2C (`hw_sch_tx_en_h2c`) uses the same block. Like
B, the fetch is admitted only after RX polling (`radio_access`), so on C it
is reachable only once the C `prepare_receive` exists. Unexecuted case:
`smoke_rtw8852c_phycap_uses_v1_register_block_and_binds_c_receipt`.

**C DM sub-inits (`phy_operating::Operating::prepare_c`).** phy.c
`rtw89_phy_dm_init` between `rtw8852c_bb_sethw` and `rtw89_phy_init_rf_nctl`
for PHY_0, non-DBCC, at the default unlinked 2.4GHz channel 1 / 20MHz
chandef: `rtw89_physts_parsing_init` (AX PHYSTS, the same helper and bytes
as B), `rtw89_phy_dig_init` with `rtw8852c_dig_regs` (core.c `support_igi`
false, `support_cckpd` true on every C cut: `R_SEG0R_PD` 0x481c lower bound 0
and spatial-reuse bit 29 clear, `R_BMODE_PDTH_EN_V1` limit off,
`R_BMODE_PDTH_V1` [31:24] = -128, the `_V1` PAGCUGC enables 0x4c24/0x4c28/
0x4ce8/0x4cec clear), `rtw89_phy_cfo_init` (XTAL SI SC_XO/SC_XI = efuse
`xtal_k` & 0x7f, read back; `rtw89_dcfo_comp_init` with
`rtw8852c_chip_info.cfo_hw_comp = false`: `R_DCFO` [7:0] = 1 and
`R_AX_PWR_UL_CTRL2` CFO mask cleared) and `rtw89_phy_edcca_init`
(`R_TX_COLLISION_T2R_ST` = 0x29). `bb_wrap`/`ch_info` are BE-only,
`ul_tb_waveform_ctrl` is false and C has no antenna diversity or
`rfe_gpio`. Native `phy_operating::Interface::admit` now dispatches through
`radio_profile_current` (B unchanged). The env-monitor/NHM CCX setup is not
part of this owner for either chip. Unexecuted case:
`smoke_rtw8852c_dm_subinit_physts_dig_cfo_edcca_follow_rtw8852c_regs`.

**C post-WCPU MAC (`mac_runtime/c.rs`).** `mac_runtime::Mac::prepare`
dispatches on the factory chip (B with its 128-byte PHY-cap, C with its
0x60-byte window) and `Native::prepare_mac` admits both. The C prerequisite
is C's own CH12-only download geometry (HAXI 0x1010 stops `0xbff00`, RX init
bit 15 clear, `R_AX_HCI_FUNC_EN_V1` 0x7880 RX clear), checked before the
first write and again after. The C sequence is mac.c `rtw89_mac_init` after
`partial_init`: rtw8852c.c `rtw8852c_mac_enable_bb_rf` (SYS_FUNC_EN BB,
AFC_AFEDIG set/clear/set, `R_AX_AFE_OFF_CTRL1` S0/S1 LDO VSEL 1, XTAL SI
XTAL0 7, ANAPAR_WL 0x6c, RFC S0/S1 0xc7, XTAL3 0xd; no PHYREG_SET);
`sys_init_ax` (`dmac_func_en_ax` with `B_AX_H_AXIDMA_EN`, CMAC0 clocks/
functions with global CMAC TX parked as on B, no OCP write); `dmac_init_ax`
with `rtw8852c_dle_mem_pcie[SCC]` (`wde_size19` 3328x64B, `ple_size19`
1904+16 x128B, bound 26, `wde_qt18` min=max, `ple_qt46`/`ple_qt47` incl. the
C-only QTA11 `tx_rpt`; used size equals the whole 458752-byte FIFO since
`dle_scc_rsvd_size` is 0), `preload_init_set_ax(MAC_0)` (USEMAXSZ 520, FEN,
TXENDWIN 1, RSVMINSZ 52), `rtw89_mac_hfc_init(true,true,true)` on the V1 page
block (0x1700..0x17a8: all twelve channels `{13,1614}` with `B_AX_GRP` on
ACH4..7/B1MGQ/B1HIQ, pub groups 1614/1614, pub max 3228, `hfc_preccfg_pcie`;
the fatal `hfc_pub_info_chk` is enforced), `sta_sch_init_ax` with
`_patch_ss2f_path` (`SS2F_PATH_WLCPU`), `mpdu_proc_init_ax`,
`sec_eng_init_ax` (+`B_AX_UC_MGNT_DEC`, PCIe TX partial mode left as read,
`R_AX_SEC_DEBUG1` TX timeout 2); `cmac_init_ax(MAC_0)` C branches
(`SIFS_MACTXEN_T1_V1` 0x41, no SCH_EXT, pre-backoff 24us only with partial
mode clear, `_patch_dis_resp_chk` *setting* the NAV/CCA response checks,
SIFS OFDM 52C, `rtw8852c_rrsr_cfgs` RSC on `R_AX_PTCL_RRSR1`, RX MPDU max
23 x 512 from `cma0_dma` 178 capped at 127 pages and 11966 bytes, no RRSR1
rate enable, VHT A-MPDU length or CMAC DMA); `enable_imr_ax` DMAC/CMAC0
with `rtw8852c_imr_info` (incl. the extra 8852C MPDU TX clears and the
CDMA TX IMR) and `err_imr_ctrl_ax` (no CMAC1: `cma1_dma` 0);
`set_host_rpr_ax` (POH); and the 8852C `B_AX_RSP_STATIC_RTS_CHK_SERV_BW_EN`
clear. `rtw89_mac_feat_init` is a no-op (`RTW89_BACAM_V0_EXT`). B's path is
unchanged. Unexecuted cases:
`smoke_rtw8852c_post_wcpu_mac_follows_linux_c_branches`,
`smoke_rtw8852c_post_wcpu_mac_requires_c_geometry_and_readiness`.

**C polling RX (`rx_dma::Rx::prepare_for`).** `Native::prepare_receive`
admits B or C and passes the chip. C follows rtw8852ce.c
`rtw8852c_pci_info`: the prerequisite (before allocation and again after
publication) is the C download geometry (HAXI 0x1010 & `0xbff00` stopped,
`B_AX_RXHCI_EN_V1` and `R_AX_HCI_FUNC_EN_V1` RX clear, CMAC TX parked);
rings use `rtw89_pci_ch_dma_addr_set_v1` RXQ/RPQ (idx 0x1218/0x121c, desa
0x1220/0x1228, num 0x1210/0x1212); LTR (only with DEVCTL2 LTR enabled, as on
B) is pci.c `rtw89_pci_ltr_set_v1(true)` (0xeaeaeaea rejection on
CTRL_0/CTRL_1/DEC_CTRL/IDX3/IDX0, `B_AX_LTR_WD_NOEMP_CHK_V1|B_AX_LTR_HW_EN`,
3.2ms idle timer, RX0/RX1 0x28, DEC_CTRL `HW_DEC_EN` + 500us space index,
IDX3 0x90039003, IDX0 0x880b880b, read back); the RX part of
`rtw89_pci_clr_idx_all_ax` on `R_AX_RXBD_RWPTR_CLR_V1` 0x1200 precedes base
publication. `rtw89_pci_ops_mac_post_init_ax` has no 8-byte address-info
step on C; as on B, TX channels and WPDMA stay stopped and only RX HCI is
released (`R_AX_HCI_FUNC_EN_V1` RXDMA, then `B_AX_RXHCI_EN_V1`; HAXI_DMA_STOP1
has no RXQ/RPQ stop bits). `R_AX_HAXI_EXP_CTRL` max-tag is already set by
the C `pcie` owner. The C assembler parses RX descriptor bandwidth with
`AX_RXD_BW_v1_MASK` (dword1 [31:29], core.c `rtw89_core_query_rxdesc`), so
a wide C PPDU is not mistaken for 20MHz; B keeps [31:30]. Unexecuted cases:
`smoke_rtw8852c_rx_rings_follow_haxi_v1_geometry`,
`smoke_rtw8852c_rx_refuses_open_rx_before_publication`.

**C Startup wiring.** `Startup::start` builds `radio_assets::Assets` for B
and C (`from_prepared` admits both element layouts), so `prepare_mac`,
`prepare_receive` and `prepare_radio_tables` (C `Qualified::from_factory_c`,
C firmware PHY-cap) run through the same Startup phases for C.
`Startup::prepare_radio_c(profile)` follows `RadioTablesLoaded`, runs the
pure `preflight_radio_c` record staging (retryable) and then drives
`Native::prepare_radio_c` on a retained `radio_c::Radio` to `RadioReady`
(no ordinary grant); any failure after the preflight terminalizes the
owner. The bootstrap `advance` step dispatches C at `RadioTablesLoaded` to
`prepare_radio_c(Profile::INITIAL)`
(core.c `rtw89_get_default_chandef`: 2.4GHz channel 1, 20MHz) instead of
B's basic/full calibration. No new test case (the gate needs an actual claim).

**C signed records (`calibration_policy::Board::new_c`, `radio_policy_c`).**
The C record family mirrors B's with its own magics, names and identities;
no B record admits C or vice versa. `Board::new_c` (10ec:c852 only,
rtw8852ce.c `rtw89_8852ce_id_table`) hashes a C domain string and recipe
text, the PCI IDs, the C logical map, the 0x60-byte C PHY-cap window,
cut/RFE/XTAL, `Assets::bind` (container digest, firmware version, the
five decoded C tables), the C coexistence recipe and its BTC ABI row
(`coex_native::ProtocolC`; a firmware outside the known C rows has no
identity). Its record
is `N5CB` v1 (`rtw89/rtw8852c-cal-v1-<mac>.bin`, 96 bytes, B's v1 layout),
admitting the cold channel-1/20MHz span 2402..2422 like B. The full program
(`radio_policy_c::Board::new`) composes that identity with the C-bound
firmware PHY-cap receipt fingerprint, the `radio_c` recipe text, the exact
`radio_power_c::Plan::bind` and the profile (band, primary, centre, width),
domain-separated per band and per observed-FLR lifecycle. Its base record
is `N5CB` v2 (`rtw89/rtw8852c-radio-v2-<mac>.bin`, 128 bytes, B's v2
layout with profile `[1, 20, 1]` and flags 3 plus the C programs below;
no N52A/N52T/N52P/N52F companions). Each
noninitial typed profile in `radio_policy_c::noninitial` (2.4GHz 20MHz
2..=13, 2.4GHz HT40 either side, every 5GHz 20/40/80/160MHz block; never
channel 14 or 6GHz) may carry `N5CC` v1
(`rtw89/rtw8852c-chan-v1-<2|5>g-ch<primary>-bw<width>-<mac>.bin`, 128 bytes:
`[1, width MHz, primary, 3]` at 54, band/centre at 68/69), signed by the base
signer and bound to the base digest/signer. The envelope check covers the
profile's whole occupied span: overlapping rules must cover it without a
gap, each must allow the profile width (`max_bandwidth`, incl. AUTO_BW and
NO_160MHZ), DFS/NO_IR only at 5GHz (passive), and every peak plus antenna
gain must stay under the minimum rule power and signed ceiling.
`Native::preflight_radio_c` stages all of them without register access (a
profile whose `radio_power_c` plan cannot be built from the actual assets is
not looked up); `Startup::prepare_radio_c(profile)` runs it before creating
its terminal Attempt (a missing record is retryable), and
`Native::prepare_radio_c(.., profile, preflight)` rebinds both identities,
requires `channel_allowed(profile)`, `select`s it and installs the C
calibration and `qualification_c`, which then gate every `Port` access and
`calibration_access`. NARF carries no C board value; an unprovisioned board
stays unadmitted. Unexecuted cases:
`smoke_rtw8852c_calibration_record_is_n5cb_and_never_a_b_record`,
`smoke_rtw8852c_full_radio_base_record_is_n5cb_v2_exact_and_revocable`,
`smoke_rtw8852c_channel_records_admit_exactly_their_profile_and_span`.

**C WLAN-only coexistence (`coex_native::Coex::prepare_c`).** Run by
`Native::prepare_radio_c` right after the C records are installed and before
the DM init, at core.c `rtw89_core_start`'s `rtw89_btc_ntfy_init` point (as
B, the owner is WLAN-only: BT is arbitrated low, not assumed absent). It is
`rtw8852c_btc_set_rfe` (antenna 2/3 by RFE parity) and
`rtw8852c_btc_init_cfg`: `rtw89_mac_coex_init_v1` (`R_AX_BTC_CFG` 0xda00
BTC_EN|BTG_LNA1_GAIN_SEL and RTK mode 0, `R_AX_BT_CNT_CFG` 0xda10 CNT_EN,
`R_AX_CCA_CFG_0` 0xc340 BTCCA_EN set / BRK_TXOP clear,
`R_AX_RTK_MODE_CFG_V1` 0xda04 sample clock 5), `rtw8852c_btc_set_wl_pri`
TX_RESP/BEACON (`R_BTC_COEX_WL_REQ` 0xda24 bits 10/22), RR_WLSEL 0 on both
paths, `rtw8852c_set_trx_mask` (shared: A/B SS 0x5ff + A TX 0x5ff;
dedicated: A/B SS 0x5df), `R_AX_BT_BREAK_TABLE` 0xda44 = 0xf0ffffff and BT
counter EN|RST_V1; then `_write_scbd` 0x4003, `_set_init_info` CXDRVINFO
INIT (`fcxinit` 0, B's 14 bytes) and CTRL (`fcxctrl` 1),
`rtw8852c_btc_set_wl_txpwr_ctrl(0xffffffff)` (0xd200/0xd220 cleared, read
back), `_action_wl_only`: `_set_ant(WONLY)` = `rtw89_mac_cfg_gnt_v1`
`R_AX_GNT_SW_CTRL` 0xda48 = 0x57ddf (WL SW high, BT SW low both bands;
para_ver 0x1 has no WLAN_ACT mux), `rtw89_mac_cfg_ctrl_path_v1(wl)` (no
I/O; there is no LTE grant path on C), `_set_bt_plut` `R_AX_BT_PLT` 0xc67c
= 0x111, each read back, and `_set_policy(BTC_CXP_OFF_BT)` with DONE_ACK.
`ProtocolC` follows the C rows of coex.c `rtw89_btc_ver_defs`: 0.27.0..
0.27.97 is `fcxtdma` 3/`fcxslots` 1 (B's 26-byte policy) and 0.27.97..0.28
is `fcxtdma` 4/`fcxslots` 2 (`btf_tlv_v7` TDMA + `_append_slot_v7` slot0,
23 bytes; the shipped rtw8852c_fw-{1,2}.bin are 0.27.122/0.27.129).
RFK START/STOP and switch-band re-assert `_set_ant(WONLY)` through the
chip-dispatched `Native::coex_enforce` (`enforce_c` on C, B unchanged).
Unexecuted case:
`smoke_rtw8852c_wlan_only_coex_init_follows_btc_init_cfg_and_gnt_v1`.

**C TX path (`packet_format::transmit_c`, `packet_core`, `dma_stop::Layout::C`).**
`packet_core::Port::chip` selects the ring registers and TXWD layout (old
fixtures default to B). A C `Core` publishes only the ordinary BE0/MGMT8
station rings on `rtw89_pci_ch_dma_addr_set_v1` (`Queue::regs_for`: the
ACH0..CH9 NUM/IDX registers are shared with the baseline, DESA/BDRAM are
`_V1`, ACH0 0x1230 / CH8 0x1270); the AP role, all-AC QoS, A-MPDU, A-MSDU
and software fragments stay B-only. `transmit_c` is core.c
`rtw89_core_fill_txdesc_v1` for management and non-QoS data: the 32-byte
`rtw89_txwd_body_v1` (body0 without HW SSN, so C management keeps the host
SW_SEQ; body1 `ADDR_INFO_NUM`; body7 `USE_RATE_V1`/`DATA_RATE` for fixed
CCK1/OFDM6 rates), the 24-byte `rtw89_txwd_info` (`info0_v1` without the
rate fields: DISDATAFB for fixed rates, firmware RA leaves it clear with
the lowest retry rate in info1; info3 SPE_RPT; info4 HW_RTS_EN/RTS_EN),
the WP sequence and pci.c `rtw89_pci_fill_txaddr_info_v1` (2044-byte
segments, high address bits [14:11], LS on the last). The TX BD length is
`txwd->len` (`descriptor_len`, 70..76 bytes). `tx_transport` admits
already-encrypted host CCMP (non-QoS data to the AP, robust management) on
C as on B: `sec_en` stays false, so neither body carries a key. The native
`Access` reports the retained chip, doorbells/readbacks the chip's ring
set, and `start` requires C's `B_AX_RXHCI_EN_V1|B_AX_TXHCI_EN_V1` and
`R_AX_HCI_FUNC_EN_V1`. Terminal closure now earns a C DMA-idle proof
(`dma_stop::stop_with(Layout::C)`, rtw8852ce.c `rtw8852c_pci_info`:
WPDMA + `B_AX_TX_STOP1_MASK` on HAXI_DMA_STOP1, CH10/CH11 on
`R_AX_HAXI_DMA_STOP2`, INIT_CFG1 `B_AX_STOP_AXI_MST` set and the V1 HCI
enables clear, `R_AX_HCI_FUNC_EN_V1`, `DMA_BUSY1_CHECK`, BUSY2 CH10/CH11,
BUSY3 RXQ/RPQ, then BME off and the flushing re-check), so C DMA can be
reclaimed like B; B's proof is unchanged. The WoW rewind
(`wow_trx::Rewind`) is `rtw89_pci_clr_idx_all_ax` per chip (C: CLR1 incl.
ACH4..7, `R_AX_TXBD_RWPTR_CLR2_V1` 0x11c4, `R_AX_RXBD_RWPTR_CLR_V1`
0x1200); the WoW owner itself remains B-only. Unexecuted cases:
`smoke_rtw8852c_packet_txwd_v1_body_info_wp_and_addr_info`,
`smoke_rtw8852c_packet_rings_use_v1_desa_and_refuse_b_only_programs`,
`smoke_rtw8852c_dma_stop_follows_haxi_v1_pci_info`,
`smoke_rtw8852c_wow_rewind_uses_v1_rwptr_clear_registers`.

**C ordinary grant (`command_native::OrdinaryGrant`).** The sealed
ordinary RF/response grant is an enum over the B `radio_policy::Qualification`
and `radio_policy_c::Qualification`, sharing `current`/`with_current`
(`Native::ordinary_current`/`with_ordinary_current` dispatch on it). Every
B companion accessor goes through `OrdinaryGrant::b()` and sees "no
program" on C: sleep profile `None`, fragments not allowed, monitor/AP
owner and B retune refused (`Unsupported`), `full_radio_scope` `None` (so
HT/HE/A-MPDU/RA/A-MSDU/QoS/WMM allowances are `Unsupported` and RF
tracking has no window). `Native::prepare_radio_c` installs
`OrdinaryGrant::C` with the same retained program only after
`radio_c::State::Ready` and the `RF_GET_MCCCH` V0 H2C, rechecking
`current()` and that the active profile is the prepared one; `Native::channel`
then reports the C primary. `Native::station_tx_current` dispatches to
`radio_policy_c::Qualification::tx_current`, which refuses every frame on a
DFS/NO_IR active span (C has no beacon-witness passive TX grant, so
`station_passive_tx(Some(..))` stays `Unsupported`); the signed tuning
emissions the record covers are still admitted by `current`. The AP
controller and the monitor owner refuse non-B chips. B's grant, accessors
and bytes are unchanged. Unexecuted case:
`smoke_rtw8852c_tx_current_refuses_frames_on_passive_spans`.

**C retune (`Native::retune_radio_c`, `Startup::retune_channel_c`).** The
C counterpart of `retune_full_radio` for one typed `operating_channel_c`
profile admitted by `radio_policy_c::admissible` (never channel 14 or
6GHz): requires the Ready `radio_c` owner, current C ordinary grant (the
same `Arc` as `qualification_c`), coex/NCTL ready, a rebound
`radio_policy_c::Board::new` identity matching the loaded record
(`channel_matches`) and `channel_allowed(profile)`; drains exactly like B
(`poll`, no sleep/monitor owner, queue/backlog/core idle, peer iff
`linked`, actual awake), then withholds the grant, `select`s the profile,
runs `radio_c::Radio::retune` (core.c `rtw89_set_channel` ->
`rtw8852c_set_channel`, then `rtw8852c_rfk_channel`) and the
`RF_GET_MCCCH` V0 H2C, rechecks Ready/channel/active profile and
`current()`, and reinstalls the same grant. A same-profile request returns
the current epoch. `Startup::retune_channel(primary, linked)` dispatches C
to `retune_channel_c` with the 20MHz profile of `primary` (2.4GHz <= 14,
else 5GHz); B is unchanged. Retry/terminal split matches B: the Attempt
commits when the ordinary grant (hence `operating_channel`) survives.
No new test case (the owner needs an actual Ready C radio).

**C station admission (legacy 2.4/5GHz 20MHz station).** `pci::probe`,
`register_pci_remove`, `bootstrap::attach_cold` and the FLR owner
(`pci_reset::Binding`) admit 10ec:c852 (rtw8852ce.c
`rtw89_8852ce_id_table`) next to b852/b85b, so the C function runs the
same retained reset/firmware/radio/station bootstrap (the FLR itself still
requires the function's own FLR capability). `Startup::station_allowed`
admits RTL8852B and RTL8852C, in both cases only under a current ordinary
grant (C: `OrdinaryGrant::C` from `prepare_radio_c`, i.e. only with the
board's signed `N5CB` v1/v2 records; an unprovisioned C board stays
unadmitted). WoW (`station_wow_capable`), the monitor and the AP owner stay
B-only. The station `control::Interface::preflight` uses the C station
window (`NativeIo::c_station_window`: the C PHY window plus the
`R_AX_INDIR_ACCESS_ENTRY` words for the nonsecure mac.c
`rtw89_mac_{d,c}mac_tbl_init`, common AX code). `station_control::Controller`
records the chip and sends the CMAC control table with the chip's
`h2c_cctl_func_id`: C uses `H2C_FUNC_MAC_CCTLINFO_UD_V1` (0x0a) with
`codec::default_cctl_v1` (fw.c `rtw89_fw_h2c_default_cmac_tbl` under
UD_V1: no TXPWR_MODE/TX-path/ANTSEL setters) and `codec::fixed_cctl_v1`
(`rtw89_fw_h2c_assoc_cmac_tbl`: the `_V1` nominal-padding positions W7
[7:0]); B keeps function 2 and its bytes. The remaining station H2Cs are
common AX code (address CAM v0 since `addrcam_ver` 0, JOIN_INFO
non-BE format, ROLE_MAINTAIN, EDCA, MACID_PAUSE without
`MACID_PAUSE_SLEEP`), as are the port/security/CPWM registers
(`R_AX_PORT_CFG_P0`, `R_AX_SEC_ENG_CTRL`/`SEC_MPDU_PROC`, `R_AX_LDM`,
`R_AX_PPWRBIT_SETTING`). `ORDINARY_STOP`/`tx_stop_all` use HAXI_DMA_STOP1
bits that match B (ACH0/CH8/WPDMA; the C `dma_stop` layout). Every B
companion allowance (`station_{ht,he,ampdu,firmware_ra,amsdu,qos_all,wmm}_allowed`)
is `Ok(false)` on C and RF tracking is a no-op (track work: see "C track
work" below). `admitted_channels` on C is the 20MHz profile
of every 2.4GHz 1..=13 and 5GHz primary with a loaded record that
`radio_policy_c::Qualification::channel_active` admits (host rule passes
and no DFS/NO_IR rule over the span), and station retune/CSA go through
`retune_channel_c`. Unexecuted case:
`smoke_rtw8852c_station_cctl_v1_follows_linux_cctlinfo_ud_v1`.

Known gaps for the `rtl8852c` row (scope: the RTL8852B chip-row
station scope; B's LPS `runtime_sleep`, RF power tracking
`rf_power_tracking`, A-MSDU `aggregation`, WoW, monitor and AP are
separate feature rows, so for C they are documented, not part of this
row): native execution on hardware (no C board record exists, so actual
admission needs a provisioned board) and the following documented C
omissions, each with its reason. *LPS:* rtw8852c.c sets
`low_power_hci_modes = CLK_GATED | PWR_GATED`, so ps.c
`rtw89_ps_power_mode_change` takes `rtw89_ps_power_mode_change_with_hci`
(the PCI HCI low-power handshake) where B (`low_power_hci_modes = 0`)
takes the plain `rtw89_mac_power_mode_change` the B `runtime_sleep` owner
implements; the C HCI path is not implemented, so C has no signed sleep
companion (`Native::sleep_profile` returns no program on C and the
station never enters LPS). *RF power tracking:* `rtw8852c_rfk_track` is the C
rtw8852c_rfk.c DPK/TSSI/thermal tracking, a different algorithm and
register set from B's `rf_power_tracking` owner; C track work covers
DIG/CFO/EDCCA/IFS-CLM only and `station_rf_tracking` is a no-op on C.
*A-MSDU:* B's A-MSDU is the separate signed `N52A` companion of the
`aggregation` row (no `Program` bit); C has no such companion
(`station_amsdu_allowed` `Ok(false)`, `Core::enable_amsdu` refuses C).
*WoW, monitor, AP:* each is its own B feature row with no C owner.
Implemented for C (below): WMM, all-AC QoS, firmware RA, HT20/HE20,
A-MPDU/BA, 40/80MHz through the shared wide path and 5GHz 160MHz
(VHT160/HE160, "C 160MHz station"). Unexecuted new cases:
`smoke_rtw89_c_phycap_and_efuse_match_linux_rtw8852c_layout`,
`smoke_rtw89_c_radio_assets_follow_linux_radiob_radioa_slots`,
`smoke_rtw89_c_table_power_reset_and_rf_order_follow_rtw8852c`.

**C terminal analog shutdown (`radio_shutdown::Shutdown::finish_c`).**
Immediate C terminal closure now runs the same AX BB engine closure
(`radio_stop::engines`, when the radio started) and `radio_stop::clocks`
after the C DMA-stop proof: rtw8852c.c `rtw8852c_mac_disable_bb_rf` is
exactly the `R_AX_WLRF_CTRL` AFC_AFEDIG and `R_AX_SYS_FUNC_EN`
BBRSTB/BB_GLB_RSTN clear (no XTAL step, unlike B). The retained
`finish_radio_shutdown` dispatches C to `finish_c`, which repeats those and
then performs the RF00/RF10 disable of rtw8852c.c `rtw8852c_pwr_off_func`:
masked XTAL-SI writes `XTAL_SI_WL_RFC_S0` (0x80) / `S1` (0x81) value 0,
mask `XTAL_SI_RF00`/`XTAL_SI_RF10` (BIT 0), address echo checked, then both
bytes read back with BIT 0 clear as the disable proof; the rest of
`rtw8852c_pwr_off_func` stays with `Power::power_off`. As for B, the
receipt is not RF/DMA idle or reset authority. B bytes are unchanged.
Unexecuted case:
`smoke_rtw8852c_terminal_shutdown_is_disable_bb_rf_then_rf00_rf10_masked_off`.

**C track work (`track::LAYOUT_C`, `Native::station_track_layout`).** The
station's 2 s `rtw89_track_work` subset now runs on C with the same AX
algorithms as B (`track.rs`) over the C registers: `rtw8852c_dig_regs`
(`R_SEG0R_PD` 0x481c with `B_SEG0R_PD_SPATIAL_REUSE_EN_MSK` BIT 29, the
`_V1` PAGCUGC 0x4c24/0x4c28/0x4ce8/0x4cec), `rtw8852c_edcca_regs`
(`R_SEG0R_EDCCA_LVL` 0x4840) and `rtw8852c_dcfo_comp`
(`R_DCFO_COMP_S0_V1` 0x4a40 [13:0], `dcfo_comp_sft` 12); the CCX/IFS-CLM,
PPDU-status, `R_DCFO` and B-mode CCK-PD registers are common AX, and
`support_cckpd` is true on every C cut. `track::REGISTERS_C` is the C
allowlist `track_port` enforces. DIG takes `fa_th_5g` when a link comes up
on a 5 GHz profile (phy.c `rtw89_phy_dig_update_para`; B passes 2.4 GHz).
The CFO sample comes from IE01 `PREMB_CFO` [31:20] on C (core.c
`rtw89_core_parse_phy_status_ie01`, `cfo_src_fd` false; `rx_packet::phy_status`
`premb_cfo`), and the crystal capacitor uses the same XTAL-SI SC_XO/SC_XI
writes as B. The C prerequisites are `Native::track_operating_current`: the
C factory/PHY-capability receipt, the current C ordinary grant and the
`phy_operating::Operating::prepare_c` owner (which already ran the C DIG/CFO/
EDCCA sub-inits incl. `rtw89_dcfo_comp_init` with `cfo_hw_comp` false).
Linux's `rtw8852c_rfk_track` (TSSI/DPK/thermal tracking) is not part of
this; `station_rf_tracking` stays a no-op on C. B registers and bytes are
unchanged. Unexecuted cases:
`smoke_rtw8852c_track_uses_c_dig_edcca_dcfo_layout_and_5g_fa_thresholds`,
`smoke_rtw8852c_rx_ppdu_status_ie01_takes_premb_cfo`.

**C WMM and firmware RA programs (`radio_policy_c::PROGRAMS`).** The C
`N5CB` v2 base record's byte 57 now uses the B `radio_policy::Program`
bit layout and dependencies, restricted to the programs whose whole C path
exists: base 3, `Wmm` (bit 2) and `FirmwareRa` (bit 4, requires WMM).
Each enabled program extends the C identity in that fixed order with a
C-domain recipe (`radio_policy_c::extend`, the common AX station
`wmm_fingerprint`/`firmware_ra_fingerprint`), so a record authorizes
exactly the programs it was measured with; `Qualification::matches`
compares against the extended identity and `allows(program)` reports the
signed flag under current authority. HT/HE/A-MPDU bits are
refused on C (all-AC QoS: below), as are unknown bits and unmet dependencies; `N5CC` channel
records keep flags 3 and bind to the (extended) base identity.
`Native::station_{wmm,firmware_ra}_allowed` on C read these flags
(`c_program`); HT/HE/A-MPDU/A-MSDU stay `Ok(false)`. The WMM
station TX path on C is QoS BE/TID0 data: `tx_transport::prepare_header`
admits QoS data on C without A-MSDU (no +HTC), and
`packet_format::transmit_c` builds it with `rtw89_core_fill_txdesc_v1`
(`sec_en` false: body2 `TID_INDICATE`, info1 `DATA_RTY_LOWEST_RATE` at the
v0 positions; no aggregation). EDCA (`H2C_FUNC_USR_EDCA`) and the RA H2C
(`rtw89_fw_h2c_ra`, `chip_gen` AX) are the same AX formats as B. An
unprovisioned board, or a C record without the bits, keeps the legacy
station. Unexecuted case:
`smoke_rtw8852c_base_record_programs_follow_b_program_layout`
(plus the extended `smoke_rtw8852c_packet_txwd_v1_body_info_wp_and_addr_info`
and `smoke_rtw89_native_rejects_unsupported_extents`).

**C all-AC QoS (`Program::QosAll` on C).** `radio_policy_c::PROGRAMS` now
also admits bit 3 `QosAll` (requires `Wmm`), extended between WMM and
firmware RA with the C recipe over `station_control::qos_all_fingerprint`.
With the signed bit, `Native::station_qos_all_allowed` on C reads
`c_program(QosAll)` and `packet_core::Core::prepare_role` accepts C's
`Queue::ordinary(true)` set: ACH1..3 (BK/VI/VO) at the
`rtw89_pci_ch_dma_addr_set_v1` DESA `R_AX_ACH{1,2,3}_TXBD_DESA_L_V1`
(0x1238/0x1240/0x1248) with the shared `R_AX_ACHn_TXBD_NUM`; the C HFC
(`rtw8852c_hfc_chcfg_pcie`) already gives every ACH0..3 13/1614 pages, C's
`tx_dma_ch_mask` is 0 and `R_AX_HAXI_DMA_STOP1` (0x1010) carries the same
ACH0..3/CH8/WPDMA bits, so `STOP_ALL` and the open mask are unchanged.
TID -> AC/QSEL/CH_DMA, `TID_INDICATE` (v1 body2 with `sec_en` false), the
strict-priority drain and `admit_all_tids` are the B code: core.c
`rtw89_core_get_qsel`/`rtw89_core_get_ch_dma` are not chip-specific for AX.
An unprovisioned board or a record without bit 3 keeps BE/TID0. B bytes are
unchanged. Unexecuted cases:
`smoke_rtw8852c_base_record_programs_follow_b_program_layout`,
`smoke_rtw8852c_packet_rings_use_v1_desa_and_refuse_b_only_programs`.

**C HT20/HE20 and originator A-MPDU (`Program::{Ht,He,Ampdu}` on C).**
`radio_policy_c::PROGRAMS` now admits every B `Program` bit in B's fixed
order (WMM, all-AC QoS, firmware RA, HT, HE, A-MPDU; same dependencies),
each extended with a C recipe over the B `ht`/`he`/`ampdu` fingerprints.
`Native::station_{ht,he,ampdu}_allowed` on C read `c_program`; A-MSDU
(a separate B `N52A` companion, not a `Program` bit) stays `Ok(false)`
and `Core::enable_amsdu` refuses C. The C station path is the B code:
local HT20/HE20 capability (core.c `rtw89_init_ht_cap`/`rtw89_init_he_cap`
are chip-independent apart from 160MHz bits and `no_ng16`, both cleared by
the 20MHz/no-beamformee restriction; C is TX-A1/RX-AB like B), the AX RA
H2C (`rtw89_fw_h2c_ra`), BA recipient through the C `RTW89_BACAM_V0_EXT`
CAM (above), ADDBA originator and `R_AX_AMPDU_AGG_LIMIT` 0xc610
(`rtw89_phy_ra_recalc_agg_limit`, AX `mac_def`; `h2c_ampdu_cmac_tbl` is
NULL in `rtw8852c_chip_ops`), and RX over `Descriptor::parse_v1`. On TX,
`Core::enable_aggregation` and `submit_inner` admit C aggregates (C
fragments stay refused), `tx_transport::prepare_header` admits the HE
+HTC QoS form on C, and `packet_format::transmit_c` takes `agg` and
`DATA_ER`: `rtw89_core_fill_txdesc_v1` keeps body3 `AGG_EN`/`BK`, info1
`MAX_AGGNUM`/`A_CTRL_BSR`/`DATA_RTY_LOWEST_RATE` and info2 `AMPDU_DENSITY`
(`rtw89_build_txwd_info2_v1`) at the v0 positions and info0_v1 carries
`DATA_ER`. Widths: 40/80MHz follow the shared wide path (below). B bytes are unchanged. Unexecuted
cases: `smoke_rtw8852c_base_record_programs_follow_b_program_layout`,
`smoke_rtw8852c_packet_txwd_v1_body_info_wp_and_addr_info` (A-MPDU/ER),
`smoke_rtw8852c_packet_rings_use_v1_desa_and_refuse_b_only_programs`,
`smoke_rtw89_native_rejects_unsupported_extents` (C +HTC).

**C 40/80MHz station on the shared wide path.** The RTL8852C station
uses the B wide-channel station code (`station_control::wide_phy`, local
HT40/VHT80/HE-wide capability, `configure_ra_wide`) unchanged:
`Native::admitted_wide` on C maps every shared `wide_profiles` chandef to
its C typed profile (`command_native::c_profile`: same primary, center and
width) and lists it when a loaded signed `N5CC` record is
`channel_active` over the whole span; `Startup::retune_wide` dispatches C
to `retune_channel_c` (unassociated), and `retune_radio_c` then sets the
packet owner's RX bound (`set_operating_width`, VHT only on a 5GHz 40/80MHz
channel), as the B retune does. `rx_packet` admits bandwidth up to
`RTW89_CHANNEL_WIDTH_80` and VHT NSS1/NSS2 MCS0..9 on the v1 descriptor too
(`AX_RXD_BW_v1_MASK`). A C 40/80MHz record identity (`radio_policy_c::
Board::new`) now also binds `station_control::wide_fingerprint`, exactly as
B's `new_noninitial` does. The capability is offered only for the bands with
an admitted wide profile (`interface.rs`), so an unprovisioned C board stays
20MHz. 160MHz: next paragraph. B bytes are unchanged. Unexecuted
cases: `smoke_rtw8852c_wide_station_profiles_map_to_c_profiles`,
`smoke_rtw89_b_rx_wide_bandwidth_and_vht_rates_reach_packet_owner` (C v1
part).

**C 160MHz station.** rtw8852c.c `support_bandwidths` includes
`NL80211_CHAN_WIDTH_160` (rtw8852b.c does not). *Geometry:* the shared
`operating_channel::Width` gains `Mhz160` (= `RTW89_CHANNEL_WIDTH_160`),
but every B constructor refuses it (`new_5ghz`, `new_wide`, `from_mhz`);
only `Profile::new_5ghz_160` builds one (the IEEE 5GHz 160MHz blocks
36..64 / 100..128 / 149..177, centers 50/114/163, every subchannel a
core.c `rtw89_channels_5ghz` channel). `pri_ch_idx` follows chan.c
`rtw89_get_primary_chan_idx` (80/160MHz arm), `txsc` phy.c
`rtw89_phy_get_txsc` (160MHz arm: `tmp` 1..8, dbw40 9/10/11/12, dbw80
13/14), and `subchannels`/`occupied` the whole 160MHz span; these equal
the C typed profile's (`command_native::c_profile` maps `Mhz160` to
`operating_channel_c::Width::Mhz160`). *Admission:*
`command_native::wide_profiles_c160` lists the 24 chandefs; only the C
branch of `Native::admitted_wide` chains them, each admitted when its
loaded signed `N5CC` 160MHz record (`radio_policy_c::noninitial` already
lists 160MHz profiles) is `channel_active` over the whole span, so the
B `admitted_wide` never holds a 160MHz profile. The C 160MHz record
identity (`radio_policy_c::Board::new`) binds
`station_control::wide160_fingerprint` (the VHT160/HE160 bodies and the
160MHz RA recipe). Programming is the existing C path
(`Startup::retune_wide` -> `retune_channel_c`, the N5CC BB/RF/RFK/power
blocks already carry 160MHz). Defensively the B BB (`channel_bb`), RF
(`channel_rf` `_bw_setting`/`_set_rxbb_bw`), DPK and power-limit
(`radio_power::fill_wide`) programs refuse a 160MHz profile before any
write. *Capability:* `local_vht160` = `local_vht80` +
`IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ` + `SHORT_GI_160` (core.c
`rtw89_init_vht_cap`; VHT has one MCS map, so the same RX2SS/TX1SS
MCS0..9 maps; no 80+80, no ext-NSS-BW); `local_he160` = `local_he_wide(5GHz)`
+ HE PHY cap0 `CHANNEL_WIDTH_SET_160MHZ_IN_5G`, cap8
`20MHZ_IN_160MHZ_HE_PPDU | 80MHZ_IN_160MHZ_HE_PPDU` and
`rx/tx_mcs_160` = the restricted 80MHz maps (core.c `rtw89_init_he_cap`;
cap4 `BEAMFORMEE_MAX_STS_ABOVE_80MHZ_4` stays clear with every other
beamformee bit). `station_control::wide_phy` adds a VHT160(+HE160)
candidate first only when `admitted` holds a 160MHz profile containing the
primary, and uses it only when the selected chandef (`Offer::from_elements`,
contiguous) is exactly that profile; otherwise the unchanged VHT80/HT40
candidates run. `phy_capabilities(5000)` returns the VHT160 body only when
a 160MHz profile was admitted at activation (`wide` bit2). *RA:*
`rtw89_phy_ra_sta_update` `IEEE80211_STA_RX_BW_160`: `BW_CAP[7:6]` =
`RTW89_CHANNEL_WIDTH_160` (3), SGI = VHT `SHORT_GI_160`, the VHT branch
uses the same `get_mcs_ra_mask(map, 9, 1)` mask; an HE 160MHz link also
needs the HE width at 160 and carries `rtw89_phy_ra_gi_ltf`'s RTL8852C
160MHz fixed GI/LTF: W3 `FIX_GILTF_EN` + `RTW89_GILTF_SGI_4XHE08` when the
peer has `HE_SU_MU_PPDU_4XLTF_AND_08_US_GI`, else `RTW89_GILTF_2XHE08`
(every 40/80MHz and 20MHz HE RA keeps W3 clear, unchanged). *RX:* the v1
(C) assembler admits descriptor bandwidth up to `RTW89_CHANNEL_WIDTH_160`
(B stays at 80), and `Core::set_operating_width` clamps the bound to 80MHz
on B and 160MHz on C, so a C owner admits a 160MHz PPDU only after
`retune_radio_c` programmed a 160MHz profile. B bytes (20/40/80MHz
bindings, `wide_fingerprint`, RA, capability bodies) are unchanged.
Known gaps: 80+80 is never offered; a wide link follows CSA to the
target chandef (194 element, else current width/center at the new primary); passive-only spans join at 20MHz. Unexecuted cases:
`smoke_rtw8852c_160mhz_capability_wide_phy_and_ra_follow_linux`,
`smoke_rtw8852c_wide_station_profiles_map_to_c_profiles` (160MHz part),
`smoke_rtw89_b_rx_wide_bandwidth_and_vht_rates_reach_packet_owner` (C
160MHz part), `smoke_rtw89_b_packet_rx_width_follows_programmed_channel`
(C 160MHz part), `smoke_rtw8852b_ht40_csa_follows_same_width_chandef`,
`smoke_rtw8852b_ht40_csa_wide_failures_drop_instead_of_narrowing`,
`smoke_rtw8852b_wide_csa_target_follows_194_and_admission`.

**C 6GHz power, records and station (`six_ghz_operation`).** RTL8852C
`support_bands` includes 6GHz; the C channel geometry, `channel_c` BB/MAC
(MUIC, CDD, RF_B TX path at 6GHz), `rfk::c_channel` RF and the IQK/TSSI/DPK
6GHz tables already carry it. *Power:*
`radio_power_c::Plan::from_elements_6ghz(elements, rfe, profile, power, tpe)`
is `rtw8852c_set_txpwr` on a typed 6GHz profile: byrate `byr[RTW89_BAND_6G][0]`
(CCK still from 2.4GHz), TXPWR_LMT_6GHZ (id 12, 8-byte
`rtw89_fw_txpwr_lmt_6ghz_entry`, `fw_txpwr_lmt_6ghz_entry_valid` with
`RTW89_6G_BW_NUM` 5 and `RTW89_6G_CH_NUM` 120) and LMT_RU_6GHZ (id 15)
read as phy.c `rtw89_phy_read_txpwr_limit{,_ru}` for `RTW89_BAND_6G`:
`[regd][reg_6ghz_power][rtw89_channel_6g_to_idx]`, else
`[RTW89_WW][RTW89_REG_6GHZ_POWER_DFLT]`, then `min3(rf_to_mac, 63, cstr)`;
TX shape uses the 6GHz regd and `reg6_pwr` (`rtw89_get_tx_shape_idx`); no
CCK DFIR on 6GHz (`rtw8852c_set_tx_shape`). `SixGhzPower::new(elements,
country, ap_power_type)` is regd.c for a PCIe device whose rtw89 ACPI DSM
calls all fail: the country map is the container's last REGD element (id
20, fw.c `rtw89_recognize_regd_from_elm`, at most
`RTW89_REGD_MAX_COUNTRY_NUM` entries; the shipped `rtw8852c_fw-2.bin`
carries 242); NARF has no static `rtw89_regd_map`, so a container without
one admits no 6GHz (`Table`). An unknown country is `rtw89_ww_regd`
(`regd_is_6ghz_blocked`) and a 6GHz rule of `RTW89_NA` is
`regd_is_6ghz_not_applicable`: both refused. `rtw89_regd_get` maps UK to
ETSI (`txpwr_uk_follow_etsi` true without ACPI). VLP/LPI/SP map to
`RTW89_REG_6GHZ_POWER_{VLP,LPI,STD}`; VLP is blocked for US/CA
(`rtw89_regd_setup_policy_6ghz_vlp` default), SP is not blocked
(`block_6ghz_sp` stays clear without ACPI), an unset AP type is DFLT. The
TPE constraint (regd.c `rtw89_reg_6ghz_tpe_recalc`, STD only, below
`RTW89_MIN_VALID_POWER_CONSTRAINT` refused) enters as phy.c
`rtw89_phy_get_tpe_constraint` (`dbm_without_tolerance`, `dbm_to_mac`).
`Plan::bind` is unchanged for 2.4/5GHz; a 6GHz plan binds its regd/power
and the TPE-free pages (a TPE only lowers `min3`). *Records:*
`radio_policy_c` adds the 6GHz `N5CC` v1 record
(`rtw89/rtw8852c-chan-v1-6g-ch<primary>-bw<width>-regd<NN>-<vlp|lpi|sp>-<mac>.bin`,
B's 128-byte layout with band 2, bytes 70/71 = `reg_6ghz_power`/regd) for
every typed 6GHz profile (`noninitial_6ghz`: 59 primaries x 20/40/80/160MHz)
and power type (`POWER_TYPES_6GHZ`; unset is never admitted, as cfg80211
refuses it before a 6GHz BSS is usable). The identity (`Board::new`, 6GHz
domain string) binds the 6GHz plan and an HE-only 6GHz station recipe
instead of the HT/VHT wide fingerprints; the binding adds power/regd. Records
are keyed by (profile, `SixGhzPower`): `channel_{allowed,active}_6ghz`,
`select_6ghz`, `active_six_ghz`, `six_ghz_contexts`; the 2.4/5GHz methods
and bytes are unchanged. The 6GHz envelope additionally requires every rule
over the span to admit a client of the record's power type (cfg80211
`cfg80211_6ghz_power_type_valid`: `NO_6GHZ_VLP_CLIENT`/`NO_6GHZ_AFC_CLIENT`)
and accepts INDOOR_ONLY only together with the trusted DEPLOYMENT_INDOOR
assertion; DFS/NO_IR stay passive (no frame TX, as 5GHz). Formats only: no C
board value is carried. *Native:* `Native::channel` is a band-qualified
`OperatingChannel` (band, primary): 6GHz 1/5/9/13 never read as 2.4GHz;
B records `OperatingChannel::legacy` (1..=14 2.4GHz, else 5GHz) and its
OFDM floor (`lowest_rate`, `ghz5`) and monitor retune comparison are
unchanged. The station `State::channel` is the same `OperatingChannel`
(retune/wide/CSA record `legacy`; the OFDM-only predicates for the
management rate, short slot, WMM and legacy-rate mask read its band), so
2.4/5GHz station bytes are unchanged. `preflight_radio_c` stages 6GHz records lazily by name: under
the host policy snapshot's country, for each `POWER_TYPES_6GHZ` whose
`SixGhzPower::new` context exists, every `noninitial_6ghz` profile is first
probed with `has_channel_6ghz` and only a provisioned name builds the
TPE-free `Plan::from_assets_6ghz` and identity for `load_channel_6ghz` (no
snapshot: nothing staged). `retune_radio_c(.., six, linked)` takes
`Some((SixGhzPower, tpe))` for a 6GHz profile: `admissible_6ghz`,
`channel_allowed_6ghz`, the TPE-constrained `Plan::from_assets_6ghz`
(identity still the staged TPE-free record's), `select_6ghz`, and the
completion check includes `active_six_ghz`; a 6GHz retune is never skipped
on the same profile (regd.c `rtw89_reg_6ghz_recalc` ->
`rtw89_core_set_chip_txpwr` when the context or TPE changes). RX admission
on 6GHz carries no VHT. `radio_c::Radio::{prepare,retune}` accept a 6GHz
plan (the C geometry/BB/RF/RFK layers already carry 6GHz);
`prepare_radio_c` itself still builds only 2.4/5GHz plans (core.c starts on
the default 2.4GHz chandef). `Startup::retune_channel_c` passes the
context through (2.4/5GHz callers pass `None`).
*Station (closes `six_ghz_operation` for RTL8852C).* `Native::admitted_six_ghz`
lists every typed 6GHz primary whose 20MHz profile has a loaded `N5CC`
record under a power context (`six_ghz_contexts`) that `channel_allowed_6ghz`
admits, with its cfg80211 client power type (`client_type`) and whether
`channel_active_6ghz` holds (no DFS/NO_IR rule); `six_ghz_regulatory` is the
host policy those records are checked under. `station::Io` adds
`station_six_ghz_channels`, `station_six_ghz_regulatory` and
`station_retune_6ghz(channel, tpe, linked)` (`Startup::retune_channel_c(
profile, Some((six, tpe)), linked)`); the defaults admit nothing, so
RTL8852B is unchanged. Station `State` records the 6GHz context/TPE beside
the band-qualified `OperatingChannel`; `retune` compares band-qualified
(a 2.4GHz retune after 6GHz channel 1 is never skipped) and clears it;
`basic_ok` reads the band's OFDM floor. Beacons/probe responses on a 6GHz
tuning are observed by the shared `association::observe_6ghz` (`Bss.band =
Some(Ghz6)`; the WMM/CSA/cache observers share `observe_tuned`). *Scan:*
`interface::split_scan` separates 6GHz frequencies (5955 + 5(n-1), typed
primaries, each admitted) from the 2.4/5GHz primaries; an all-channels
request covers both. After the 2.4/5GHz pass, the RNR colocated APs
(`scan::parse_colocated_aps` of non-6GHz results) and the request go
through `scan::plan_6ghz_scan` (cfg80211 `cfg80211_scan_6ghz`: PSC-only blind
scanning under `colocated_6ghz`, targets added); `colocated_6ghz` is
accepted only with an admitted 6GHz record. `State::scan_six_ghz` tunes each
planned primary TPE-free under one context (an active one first) and dwells;
a probe request follows only on an active record (`ieee80211_scan_state_decision`;
no beacon witness/passive TX grant exists on C). The 6GHz probe content is
mac80211 `ieee80211_build_preq_ies_band` on 6GHz (`station_six_ghz::
probe_request`): OFDM Supported Rates only, no Extended Rates/DS/HT/VHT,
HE Capabilities (`local_he`, 20MHz) and HE 6GHz Band Capabilities (SMPS
off). *Join:* `six_ghz_join` requires SAE (H2E; `prepare_6ghz` refuses other
AKMs) and the signed WMM/HT/HE programs, takes the rule covering the
primary from `six_ghz_regulatory`, admits the BSS with
`six_ghz::admit_with_rule` (power type), builds `JoinPlan::prepare_6ghz`
with `SixGhzLocal::new(local_he(), capability(), rule)` capped at
`SixGhzWidth::Twenty` (the station's 6GHz records are 20MHz), checks the
selected width/primary/power type, picks the admitted *active* record of
that client power type, computes the TPE, then `retune_6ghz` before
authentication. HE 6GHz Band Capabilities (`station_six_ghz::capability`):
core.c `rtw89_init_he_cap` MIN_MPDU_START 0 and MAX_AMPDU_LEN_EXP 7, with
MAX_MPDU_LEN restricted to 3895 (no RX A-MSDU on this C profile, so
`rtw8852c_chip_info.max_vht_mpdu_cap` 11454 is not promised). *TPE:*
`station_six_ghz::tpe` is mac80211 `ieee80211_parse_tpe` (after
`ieee80211_valid_tpe_element`) + `ieee80211_rearrange_tpe` to the used
chandef (20 MHz for this HE20 station: EIRP: 20MHz entry; PSD: the
primary's subchannel via `ieee80211_calc_chandef_subchan_offset`), then
regd.c `rtw89_calculate_tpe` on the default category (`tpe_get_constraint`
(raw - 19) / 2, PSD + 13), min over local/regulatory-client EIRP/PSD; only
for `RTW89_REG_6GHZ_POWER_STD`; below -10 dBm refuses the join (regd.c
`-EINVAL`); an 80+80MHz AP channel is refused. The shared `tpe` takes
the used width: the 8922A owner passes 20/40/80/160 MHz and the
rearrange covers the full operating width (EIRP: minimum over the
width entries up to the used width; PSD: minimum over every used
20 MHz subchannel). *RA:* `configure_ra` with HE
and no HT is `codec::ra_he6`: phy.c `rtw89_phy_ra_sta_update` on
`RTW89_BAND_6G` (`supp_rates[6GHz] << 4` OFDM only, `mode = HE|OFDM`, 20MHz
SGI from the absent HT cap = 0); the AX RA H2C (version 0) has no band
field. CMAC/EDCA/management rate read the band through `ofdm_only`. *Band
advertisement:* `Device::six` is sampled at activation only under the
WMM/HT/HE programs; the 6000MHz band lists exactly the admitted primaries
(`rtw89_sband_6ghz`), and `associate` accepts a 6GHz frequency only for one.
*Known limits (not claimed):* 6GHz joins are HE20 only (no 6GHz 40..160MHz
station width; wide 6GHz records exist but the station does not select
them); a CSA on a 6GHz link drops it (no native 6GHz switch owner, as a
wide link); a beacon TPE change after association is not re-applied
(mac80211 `BSS_CHANGED_TPE` -> `rtw89_reg_6ghz_recalc`): the join-time TPE
from the scanned beacon/probe response stays; the scan ignores
`psc_no_listen`/unsolicited-probe target hints (every planned channel is
dwelt); TX A-MPDU on 6GHz follows HE-only negotiation (`ampdu` admits `he` without `ht`, density 0 per Linux's zeroed 6GHz ht_cap).

**8922A 6GHz admission (`station_8922a`, closes #1875; wide-6 GHz
TPE rearrange closes #1898).** The 8922A
station owner admits 6 GHz at 20/40/80/160 MHz, with a caller-supplied
6 GHz power program (`Request.six_ghz`: `SixGhzAdmission`, the AP's
client power type + the regd.c TPE constraint from
`station_8922a::tpe`). `tpe` is the shared mac80211/regd.c parse
(`station_six_ghz::tpe`, the 8852C template: validate, parse,
rearrange to the used chandef, intersect local and
regulatory-client EIRP/PSD limits) — the 8922A owner adds the
admission rules around its result rather than a second copy of
the parse. The rearrange covers the full operating width:
EIRP is the minimum over the width entries up to the used width
(mac80211 `ieee80211_chandef_num_widths`, intersected by regd.c
`tpe_deal_with_eirp`) and PSD is the minimum over every used
20 MHz subchannel (mac80211 `ieee80211_rearrange_tpe_psd` to the
used chandef, intersected by regd.c `tpe_deal_with_psd`), so a
wide station is admitted on its whole channel's constraint, never
on the primary subchannel's alone. A used width wider than the AP
channel, an 80+80 MHz AP channel, and a primary outside the AP
channel refuse the TPE (the caller refuses the join). Admission is
fail-closed: no program refuses
(`SixGhzPowerMissing`), a program on a non-6 GHz band refuses
(`SixGhzContextUnexpected`), a TPE under a non-STD power type
refuses (`SixGhzTpeNotStandard`, as
`Plan::from_elements_6ghz`), and a TPE below -10 dBm refuses
(`SixGhzTpeBelowMinimum`, regd.c `-EINVAL`). The admitted `Station`
records the
program (`SixGhzProgram`: power type, TPE dBm, phy.c
`rtw89_phy_get_tpe_constraint` in MAC units via
`radio_power_c::tpe_mac`, 63 with no TPE) for the
`rtw8922a_set_txpwr` limit program
(`station_8922a::Station::txpwr_plan`, applied by
`prepared_8922a::Prepared8922a::set_txpwr`) to consume. Country policy
(a 6 GHz-blocked country, the VLP block for US/CA) is not
checked at admission: it lives with the REGD element owner
(`radio_power_c::SixGhzPower::new`), which needs the
container's REGD map and the host regulatory country this
owner does not hold. The register-level `rtw8922a_set_txpwr`
program itself lives in `radio_power_be::Plan` (generic
`rtw89_phy_set_txpwr_{byrate,offset,limit,limit_ru}` on BE
registers plus the 8922A `set_tx_shape` / `set_txpwr_diff` /
`set_txpwr_ref` / `set_txpwr_sar_diff` steps, in Linux order)
and is consumed per admitted station by
`station_8922a::Station::txpwr_plan` (which builds the regd.c
`SixGhzPower` context from the admitted program and the
caller-supplied container, RFE, host country and channel
center) and applied by
`prepared_8922a::Prepared8922a::set_txpwr` over the BAR2
register port (197 writes; a refused program writes
nothing). Still open: 8922A admission into `station_control`
(the join flow that supplies the program). Unexecuted cases:
`smoke_rtw8852c_6ghz_txpwr_follows_rtw89_regd_and_phy_6g`,
`smoke_rtw8852c_6ghz_channel_records_admit_profile_power_type_and_rule`,
`smoke_rtw8852c_6ghz_tpe_follows_mac80211_rearrange_and_regd`,
`smoke_rtw8852c_6ghz_ra_is_he_only_ofdm`,
`smoke_rtw8852c_6ghz_scan_split_admits_only_signed_primaries`.

**8922A MLO link-lifecycle H2Cs (`link_h2c_8922a`, Refs #1918).**
The per-link bodies Linux sends around `rtw89_core_sta_link_add` /
`sta_link_assoc` / `sta_link_disconnect` / `sta_link_remove` are
built (never sent) by `link_h2c_8922a.rs`, grounded in
torvalds/linux @ cbbddb6 (`core.c`, `fw.c`, `cam.c`, `cam.h`,
`core.h`): role-maintain CREATE/REMOVE (W0 per
`RTW89_H2C_ROLE_MAINTAIN_W0_*`), the default DMAC table v2
(132 bytes: c0 MACID|OP, m0..m12 `*_ALL`, the 8922A chip op),
join-info v1 (12 bytes: AX W0 plus W1 with STA_TYPE, IS_MLD,
MAIN_MACID, MLO_MODE = MLSR, INIT_PWR_STATE, EMLSR 256 µs codes
4/5, LINK_ID), the address-CAM update (`CON_DISCONN`, v0 60-byte
form on firmware < 0.35.84.0, 64-byte form with W15 once it does
not; 8922A `addrcam_ver` 0, entry length 0x20 — not the AX
0x40), and the MACID pause (plain 32-byte form, 256-byte SLEEP
form on firmware >= 0.34.11.0). Transition composers emit them in
Linux's order per link from the admitted record plus a
per-link VIF context (`VifLinkCtx`: own link address, port, WMM,
trigger, BSSID, CAM indices, AP/TDLS kind, firmware switches);
station links send nothing on add/remove, AP/TDLS links add the
pause + role CREATE + DMAC on add and role REMOVE on remove.
Still open: the Prepared owner must allocate the per-instance
CAM entries (128-entry addr-CAM pool, 20-entry BSSID-CAM pool)
and hold the per-instance VIF-link contexts, and frame + send
the bodies over CH12 — the transport lane. The VIF-level
role/join/CAM/DMAC sequence in `rtw89_mac_vif_init` is not part
of this module.

**C BA CAM (`RTW89_BACAM_V0_EXT`, `station_control::Controller`).** On C,
`Controller::initialize` first sends core.c `rtw89_core_start`'s
`rtw89_fw_h2c_init_ba_cam` -> fw.c `rtw89_fw_h2c_init_dynamic_ba_cam_v0_ext`:
eight `H2C_FUNC_MAC_BA_CAM` (class 0xc, function 0, DONE_ACK) bodies
`codec::init_ba_cam_v0_ext(8 + uid, uid)` (W0 VALID; W1 ENTRY_IDX_V1
[31:28], UID [7:0], BAND/STD_EN 0) for `bacam_num` 8 .. +`bacam_dynamic_num`
8. Recipient sessions use C's 8 static entries (`bacam_num()`; B keeps 2)
with core.c `rtw89_core_acquire_sta_ba_entry`'s TID0/5 replacement, and
`codec::ba_cam_v0_ext` (no W0 ENTRY_IDX; W1 ENTRY_IDX_V1, STD_EN, BAND =
`mac_idx` 0; an invalidation carries only MACID and W1 ENTRY_IDX_V1). The
recipient path is reached under the signed C HT program (above).
B bytes are unchanged. Unexecuted case:
`smoke_rtw8852c_ba_cam_v0_ext_wire_and_dynamic_init_follow_fw_c`.

### RTL8851B retained runtime (partial; composed through the station, antenna diversity driven)

Chip row `rtl8851b`. These owners are the chip-specific RTL8851B
(`10ec:b851`, 1T1R AX, 2.4/5GHz, 20/40/80MHz) pieces under the retained
B architecture, following the RTL8852C pattern above. The radio,
ordinary-grant and station composition sections below compose them; RTL8852B
and RTL8852C bytes are unchanged. `pci::probe`, `pci::attach_cold`, the FLR binding
(`pci_reset::Binding`) and the PCI remove hook route `10ec:b851` to the
retained bootstrap (`rtw89::bootstrap_did`), whose `advance` selects
`prepare_radio_51` for an RTL8851B identity (case
`smoke_rtw89_bootstrap_routes_8851be_with_b_and_c`).

**Secure policy.** `Blacklist::upstream(Rtl8851B)` is Linux's exact policy:
`rtw8851b_chip_info.fw_blacklist` is NULL, so fw.c
`__check_secure_blacklist` returns -ENOENT and `__parse_security_section`
only `WARN_ONCE`s. NARF therefore enforces no host chip list for RTL8851B
(`has_chip_list() == false`) while still requiring the fuse-selected MSS
signature (`MissingSignature` otherwise); a missing policy owner stays
`UnknownBlacklist` and an authenticated board list is still enforced.
Unexecuted case: `smoke_rtw89_n51_secure_policy_is_linux_null_chip_blacklist`.

**Factory inputs.** `Factory::read` on RTL8851B reads the complete Linux
PHY-cap window (`phycap_addr` 0x580, `phycap_size` 128) once and takes the
power-k/ECV/secure bytes from it; `n51_phycap()` is separate from the B
window so no B owner consumes it. `factory_51::Calibration::from_factory`
mirrors rtw8851b.c `rtw8851b_efuse_parsing_tssi` (path A only: CCK 6, MCS
2G 5 + 5G 14 at 0x210), `rtw8851b_efuse_parsing_gain_offset` (five
`RTW89_GAIN_OFFSET_*` bands, high nibble only, at 0x2d4..0x2dc),
`rtw8851b_read_phycap` (TSSI trim 0x5d6 down, thermal trim 0x5df, PA-bias
0x5de, gain comp `{0x5bb, 0x5ba, 0, 0x5b9, 0x5b8}` low nibble, `adc_td` =
0x5af [4:0]) with Linux's erased-trim zeroing after the whole read;
`thermal_setting` is the literal 8851B `__thm_setting`
`((v & 1) << 3) | ((v & 0x1f) >> 1)`. Unexecuted case:
`smoke_rtw89_n51_phycap_and_efuse_match_linux_rtw8851b_layout`.

**PHY tables.** `radio_assets::Assets` accepts RTL8851B containers only with
all four BB/GAIN/RADIO_A/NCTL elements; RADIO_A must be `reg2.idx` 0
(`rtw8851b_chip_info.rf_table = {radioa}`) and any RADIO_B element is
refused. The shipped `rtw89/rtw8851b_fw-1.bin` carries exactly that set plus
TXPWR (ids 9..17), TXPWR_TRK (18) and id 20 elements, which are retained
verbatim. NARF carries no static rtw8851b_table.c copy, so the legacy
element-less `rtw8851b_fw.bin` yields `Error::Element`. `bind` skips the
absent path-B program. Unexecuted case:
`smoke_rtw89_n51_radio_assets_follow_linux_single_radioa_slot`.

**Table/power/reset preparation.** `radio_init::Qualified::from_factory_51`
qualifies an actual valid RTL8851B factory (RFE != 255). `Init::prepare`
refuses an assets/qualification chip mismatch before any write, decodes the
gain table with the AX generation decoder, writes BB, then
`rtw8851b_init_txpwr_unit(PHY_0)` (the same UL/coex CRs and
`rtw8851b_set_txpwr_ul_tb_offset(0)` UL_TB enable/1T/2T values as B) and
`rtw8851b_bb_reset(PHY_0)` (TXPW_RSTB MANON|TSSI 1, TSSI_TRK EN set,
`rtw8851b_bb_reset_all` with only the S0 HW-SI trigger, MANON|TSSI 3,
TSSI_TRK EN clear), each read back, then the single path-A RF table write and
page. Unexecuted case:
`smoke_rtw89_n51_table_power_reset_and_single_rf_path_follow_rtw8851b`.

**bb_sethw and NCTL.** `radio_init::controls_51` is `rtw8851b_bb_sethw`:
R_P0_EN_SOUND_WO_NDP clear, MACID power-limit table zero,
`rtw8851b_bb_gpio_init` (path A TRSW_A/X/SO_A2, SEL0/SEL32 bases, A2 RFE
words, the eight `rtw8851b_bb_gpio_trsw` fields), R_AX_PWR_NORM_FORCE1
FORCE_NTX_VALUE clear / FORCE_NTX_EN set, all read back, returning the
`offset_base` (R_P0_RPL1) and `rssi_base` (R_P1_RPL1) [7:0] bytes.
`radio_init::nctl_51` is phy.c `rtw89_phy_preinit_rf_nctl_ax` without
`R_P1_PATH_RST` and without the B/BT second `R_IOQ_IQK_DPK`, the 0x8080
poll, the firmware NCTL table, then `rtw8851b_nctl_post_defs`
(rtw8851b_rfk_table.c, 17 WM rows verbatim including the path-B literals)
read back. Unexecuted case:
`smoke_rtw89_n51_bb_sethw_gpio_and_nctl_post_follow_rtw8851b`.

**Channel geometry.** No separate RTL8851B chandef type: rtw8851b.c
`rtw8851b_sco_barker_threshold`/`rtw8851b_sco_cck_threshold` and
`rtw8851b_sco_mapping`, and rtw8851b_rfk.c `_tssi_get_{cck,ofdm,trim}_group`,
are textually identical to rtw8852b_common.c / rtw8852b_rfk.c, and
`support_bands`/`support_bandwidths` (2.4/5GHz, 20/40/80MHz, UNII-4) match
the B constructors, so the RTL8851B channel program reuses
`operating_channel::Profile` (160MHz stays refused by the B constructors).

**Channel programming (`channel_51`, `channel_rf`).** `channel_51::program`
is `rtw8851b_set_channel_mac(MAC_0)` (RFMOD 0/1/2, `rtw89_phy_get_txsc`
sub-carrier word, TXRATE_CHK BAND_MODE on 2.4GHz or CHECK_CCK_EN |
RTS_LIMIT_IN_OFDM6 on 5GHz) followed by the whole
`rtw8851b_set_channel_bb(chan, PHY_0)`: `rtw8851b_ctrl_sco_cck`,
`rtw8851b_ctrl_ch` (path-A band select, `rtw8851b_sco_mapping` FC0, the CCK
TXFIR literals, `rtw8851b_set_gain_error` path-A LNA/TIA only,
`rtw8851b_set_gain_offset` with the `comp[subband]` R_P0_AGC_RSVD write,
R_PATH0_G_TIA1 offset, R_P0_RPL1 bias from `offset_base`, R_P1_RPL1 bias
from `rssi_base` and the 2.4GHz CCK RPL offset, then
`rtw8851b_set_rxsc_rpl_comp` from path-A RPL values into both P0/P1
words), `rtw8851b_ctrl_bw` (FC0 BW_SET, CHBW SBW/PRICH, 40MHz R_RXSC) with
`rtw8851b_bw_setting` (`adc_td` 0x11 -> 5, 0x9 -> 3, else 4, then the
CFCH/DCIM/WDADC/ADDCK/RXCK fields), `rtw8851b_ctrl_cck_en`, the 5280/5760MHz
`rtw8851b_set_nbi_tone_idx` (notch 0x46e4/0x47a4) and
`rtw8851b_set_csi_tone_idx`, the 5GHz path-0 BT-share release,
`B_CH_IDX_SEG0`, `rtw8851b_5m_mask` (path 0, threshold 5),
`rtw8851b_set_cfr` (channel 1/13 20MHz edge values) and the S0-only
`rtw8851b_bb_reset_all`; every final bit is read back and 160MHz is
refused before any write. `channel_rf::Channel::prepare_for_channel_51` is
rtw8851b_rfk.c `rtw8851b_set_channel_rf` (`_ctrl_ch` with
`_set_s0_arfc18`/`_lck_check`, `_ctrl_bw`, `_rxbb_bw`) on RF path A only
through the same B synth source order (`prepare_for_channel` keeps two
paths; B bytes unchanged). Unexecuted cases:
`smoke_rtw89_n51_channel_mac_ctrl_ch_and_bw_follow_rtw8851b`,
`smoke_rtw89_n51_set_channel_bb_tail_follows_rtw8851b`,
`smoke_rtw89_n51_rf_channel_programs_path_a_only`.

**RFK init and channel RX DCK (`rfk::n51`).** `n51::Init::prepare` is
rtw8851b.c `rtw8851b_rfk_init` on RF path A (`_kpath` = RF_A):
`is_tssi_mode` false, `rtw8851b_lck_init` (fresh-EWMA thermal 0),
`rtw8851b_dpk_init` (`rtw8851b_by_rate_dpd`: MAC 0xd230 [17:0] = 0x21861,
read back), `rtw8851b_aack` (up to four 0x8201e/0x8201f triggers, the 0xd0
BIT(16) poll and the four `RR_IBD` VCO bands), `_rck(A)` (2us/30us poll),
`rtw8851b_dack` = `_dac_cal` (`_drck` with the 0x7c00 result,
`rtw8851b_dack_manual_off_defs`, S0 ADDCK/backup/reload,
`rtw8851b_dack_s0_1/_2_defs`, MSBK/bias/DADCK(+24) backup and
`_dack_reload(A)`, `_new_dadck` with `rtw8851b_dadck_setup/_post_defs` and
the u8 `0x80 - sign_extend32(dc, 11) * 6` correction) with no BTC DACK
notification, as Linux, then `rtw8851b_rx_dck(PHY_0)` (BTC RXDCK START, TX
pause, `_wait_rx_mode`, `_rx_dck` with `_set_rx_dck` BIT(8) poll and
`_rxbb_ofst_swap`, resume, STOP). `n51::ChannelRxDck` is the RX DCK of
`rtw8851b_rfk_channel` with the retained `is_tssi_mode[A]` TSSI-tracking
pause. Linux only logs the poll timeouts; NARF fails closed and the owner is
terminal. Unexecuted case:
`smoke_rtw89_n51_rfk_init_aack_rck_dack_rxdck_follow_rtw8851b`.

**Channel IQK (`rfk::n51_iqk`).** `n51_iqk::Iqk::run` is rtw8851b_rfk.c
`rtw8851b_iqk(PHY_0)` on RF path A: `BTC_WRFKT_IQK` START,
`rtw89_chip_stop_sch_tx`, `_wait_rx_mode(RF_A)`, then `_doiqk` between
ONESHOT START/STOP (`iqk_times`++, `RTW8851B_IQK_VER` 0x14; the seven
`rtw8851b_backup_bb_regs` and eight `rtw8851b_backup_rf_regs` backed up
and restored), `_iqk_macbb_setting` (`rtw8851b_iqk_macbb_defs`,
`_txck_force(DAC_960M)`, `_rxck_force(ADC_1920M)` with the 8851B
`ck1920_8851b` row incl. `B_P0_RXCK_ADJ`, `rtw8851b_iqk_macbb_bh_defs`),
`_iqk_preset`, wideband `_iqk_by_path` (`is_nbiqk` stays false, so the
`_iqk_{2g,5g}_nb{tx,rx}k` variants are unreachable): `_iqk_txk_setting`
(`rtw8851b_iqk_txk_{2,5}ghz_defs`), the ten-gram `_iqk_{2g,5g}_lok`
(0x109/0x309 commands), `_txk_{2g,5g}_group_sel` (NBTXK then TXK per group,
`R_CFIR_COEF` 0 / 0x33332222), `_iqk_rxclk_setting`
(`rtw8851b_iqk_rxclk_{80,others}_defs`), `_iqk_rxk_setting`,
`_adc_fifo_rst`, `_rxk_{2g,5g}_group_sel` (RXAGC, NBRXK, RXK per group;
5GHz LUT 0x17/0x37 bracket), then `_iqk_restore` (0x1219) and
`rtw8851b_iqk_afebb_restore_defs`, all tables verbatim. A
`B_NCTL_RPT_FLG` group failure takes Linux's narrowband-CFIR fallback
(incl. the `_iqk_sram` dump and 5GHz `B_IQK_RES_RXCFIR` clear) and is
recorded in `Path::{tx,rx}_fail`; Linux only logs `_iqk_check_cal`
timeouts, NARF fails closed. 160MHz is refused before any access.
Diagnostic-only reads in `rtw89_debug` arguments are not issued.
Unexecuted case:
`smoke_rtw89_n51_iqk_lok_group_select_and_restore_follow_rtw8851b`.

**Channel TSSI (`rfk::n51_tssi`).** `n51_tssi::Tssi::run` is
rtw8851b_rfk.c `rtw8851b_tssi(PHY_0)` on RF path A
(`RTW8851B_TSSI_PATH_NR` 1), between `BTC_WRFKT_IQK` ONESHOT START/STOP
(`Kind::IqkPath`, as Linux): `_tssi_disable`, `rtw8851b_tssi_sys_defs` +
`_sys_a_defs_{2g,5g}`, `_init_txpwr_defs_a` and `_he_tb_defs_a`,
`_dck_defs_a`, `_tssi_set_tmeter_tbl`, `_dac_gain_defs_a`,
`_slope_a_defs_{2g,5g}`, `_align_a_{2g,5g}_defs` (`_tssi_alignment_default`;
RTL8851B never sets `alignment_done`), `_slope_defs_a`, `_tssi_enable`
(`_track_defs_a`, `_mv_avg_defs_a`, MV_CLR/TSSI_EN, RF 0x10055 TRK_EN,
`B_P0_TSSI_OFT` 0xc0 with the OFT_EN toggle; `is_tssi_mode[A]`) and
`_tssi_set_efuse_to_de` (CCK `tssi_cck[cck_group] + trim`, MCS
`ofdm_de + trim` with the TSSI_EXTRA `(s8 + s8) / 2` average, the B
`tssi_groups` being textually identical). All fourteen tables are
generated verbatim from rtw8851b_rfk_table.c (`n51_tssi_tables.rs`).
`Tssi::scan` is `rtw8851b_tssi_scan` (`rfk_band_changed`: no TSSI-mode gate,
no BTC notification) and `Tssi::scan_notify` is
`rtw8851b_wifi_scan_notify` -> `rtw8851b_tssi_default_txagc` (scan end:
OFT 0xc0 + OFT_EN toggle; `_tssi_alimentk_done` writes nothing).
`n51_tssi::Tracking` is fw.c `rtw89_build_txpwr_trk_tbl_from_elm` for the
2/5GHz `needed_bitmap` (types 4..=15, present types consumed in bit order,
6G rows skipped when present); thermal rows by `subband_type`
(2GA_P/N [0], 5GA_P/N [0..2]). The static `rtw89_8851b_trk_cfg` fallback is
not carried, so a container without TXPWR_TRK is refused. Thermal 0xff
programs TMETER/RFCTM 32 and zero offsets, as Linux. Unexecuted case:
`smoke_rtw89_n51_tssi_tmeter_de_and_enable_follow_rtw8851b`.

**Channel DPK and RF tracking (`rfk::n51_dpk`).** `n51_dpk::Dpk::run` is
rtw8851b_rfk.c `rtw8851b_dpk(PHY_0)` on RF path A (`cur_idx` 0, no
reload): `BTC_WRFKT_DPK` START, TX pause, `_wait_rx_mode`, the eight
`dpk_kip_reg` / four `dpk_rf_reg` backups, `_dpk_information` (Linux
stores `band_width` in `bp.ch` and `chan->channel` in `bp.bw`; NARF keeps
that swap, so `_dpk_tpg_sel` and `RR_BTC_TXBB = bw + 1` follow the center
channel number exactly as Linux programs them), the `is_tssi_mode[A]`
TSSI pause, slope-K/RXAGC/DRF off, `_dpk_bb_afe_setting` (8851B
`ck1920_8851b` RX clock, DCIM/ADCMOD/NRBW and the ANAPAR delays),
`_dpk_main` (RR_BBDC 0x03ffd, `_dpk_rf_setting`, `_set_rx_dck(A, RF_DPK)`,
KIP power/clock on, `_dpk_kip_preset`, TXAGC 17dBm, `_dpk_agc` with the
5GHz `_dpk_lbk_rxiqk` / 2.4GHz RXIQC bypass and Linux's double
`_dpk_pas_read` on the `gl_idx == 0` arm, `_dpk_idl_mpa` order select,
`_dpk_para_query`, `_dpk_on` with `path_ok |= BIT(cur_k_set)` and the
non-executing `_dpk_gain_normalize`), `_dpk_onoff`, `_dpk_kip_restore`,
backup reload, AFE restore, TSSI resume and KIP clock off. One-shots are
`(id << 8) | 0x19` with the 0xbff8 == 0x55 (10us/20ms) and
`R_RPT_COM` == 0x8000 (1us/2ms) polls; Linux only logs their timeouts,
NARF fails closed. A K-set outside `dpk_par_regs` takes Linux's
substitution of index 2; a raw KSET of 0 (`BIT(0xff)` in `_dpk_on`) is
refused. A sync failure ("need Check") completes with MDPD off.
`n51_dpk::Track::step` is core.c `rtw89_track_work`'s
`rtw89_phy_stat_thermal_update` (`rtw8851b_get_thermal`: TSSI-mode
`R_TSSI_THER`, else the RR_TM 1/0/1 trigger, 200us, `RR_TM_VAL`; zero
samples skipped; DECLARE_EWMA(thermal, 4, 4) shared with `rf_tracking`)
then `rtw8851b_rfk_track`: `_dpk_track` (PWSF `0x78 - (cur_ther -
ther_dpk) * 2 / 3` in `R_DPD_BND` [26:18] unless `B_IDL_DN` or TXAGC RF 0)
and `rtw8851b_lck_track` (`rtw8851b_aack` + `rtw8851b_lck`, which reissues
`_set_ch` = `channel_rf::set_ch_51`, when `|avg - lck.thermal| >= 8`).
It requires a completed DPK and refuses while terminal; the caller must
skip it during scans as Linux does. No native caller yet. Unexecuted
cases: `smoke_rtw89_n51_dpk_agc_on_and_restore_follow_rtw8851b`,
`smoke_rtw89_n51_rfk_track_dpk_pwsf_and_lck_follow_rtw8851b`.

**Firmware TX power (`radio_power_c::Plan::{from_elements_51,visit_51}`).**
rtw8851b.c `rtw8851b_set_txpwr(PHY_0)` + `rtw8851b_set_txpwr_ctrl` from the
container's TXPWR elements under the same fw.c
`rtw89_fw_recognize_txpwr_from_elm` selection and `rtw89_fw_load_txpwr_*`
entry rules as RTL8852C (aid 0, exact RFE else last default, extended or
invalid entries skipped). The typed B profile is restated as the identical
C geometry (center and primary checked; no 160MHz, no 2.4GHz 80MHz) and
read by the generic AX phy.c byrate/limit/RU rules (regd WW, no SAR, no
DAG). `rtw89_8851b_dflt_parms` is not carried, so a container missing
BYRATE, the band's LMT / LMT_RU or TX_SHAPE_LMT is refused. `visit_51`
emits with `rf_path_num` 1: byrate nss 0 only (7 words), the offset word,
`rtw8851b_set_tx_shape` (2.4GHz `rtw8851b_bb_set_tx_shape_dfir`, full-word,
the same flat/sharp/sharp_14 tables as B; `R_DCFO_OPT` [25:24] OFDM
shape), the 1TX limit and RU pages, then `rtw8851b_set_txpwr_ref`
(B_AX_PWR_REF 0, path-A 0x5804/0x5808 = TSSI 172 / PWR 312 / REF 0); no
C bandedge/TSSI-DBW, SAR-diff or path-B writes. RTL8851B sends no RF
notify at all: unlike rtw8852b.c/rtw8852c.c, `rtw8851b_rfk_channel` never
calls `rtw89_fw_h2c_rf_ntfy_mcc` (no `mcc_get_ch_info`), so no
RF_GET_MCCCH body is built for it. Unexecuted case:
`smoke_rtw89_n51_set_txpwr_follows_rtw8851b_and_phy_ax`.

**Retained radio owner (`radio_51`, `rfk::n51_channel`).** `radio_51::Radio`
is the RTL8851B counterpart of `radio_c::Radio` (phy.c `rtw89_phy_dm_init`
order). `prepare_controls`: `controls_51`, the phy.c DM sub-inits through
`phy_operating::Operating::prepare` (now admitting RTL8851B: `rtw8851b_dig_regs`
and `_edcca_regs` match RTL8852B's byte for byte, `cfo_hw_comp` is set on both,
and core.c `support_cckpd` is true for every RTL8851B cut), then `nctl_51`. An
antenna-diversity RFE (mac.c `rtw89_mac_setup_phycap`: one path and
`rfe_type % 3 == 2`, which gates `rtw8851b_rfe_gpio` and `rtw89_phy_antdiv_*`)
is composed by `prepare_controls` between the DM sub-inits and NCTL, in
Linux dm_init order: `antdiv_init` (state reset + `reg_init` writes), then
`rfe_gpio` (BB + MAC halves, `rfe_type <= 50` bound), then the initial
`set_ant` on RF_A, retained as `Radio.antdiv` (`antdiv_51`). `prepare` then runs:
`rfk::n51::Init`, `rtw8851b_set_txpwr_ctrl` (`radio_power_c::reference_51`,
which `visit_51` now shares), `rtw8851b_power_trim` (path A),
`rtw8851b_bb_cfg_txrx_path` (`ctrl_rx_path(RF_A)` with `set_gain_offset` on the
default 2.4GHz channel-1 chandef, RSTB 1/3, the `rx_nss` 1 limits, because mac.c
clamps `rx_nss` to `chip->rx_nss` = 1, and `R_MAC_SEL`; read back), and
`n51_channel::Channel::set_channel` + `rfk_channel`. `set_channel` is core.c
`__rtw89_set_channel`: `rtw8851b_set_channel_help` enter (PPDU status off,
path-A TSSI cont off, ADC FIFO, 40us, `rtw8851b_bb_reset_en(false)` with only the
S0 HW-SI), `channel_51::program`, `channel_rf::prepare_for_channel_51`,
`Plan::visit_51`, help exit (RX CCA re-enabled only on 2.4GHz), then on the
first channel or a band change `coex_switch_band` + `rtw8851b_tssi_scan`.
`rfk_channel` is `rtw8851b_rfk_channel`: conn_rfk, RX DCK with the retained
`is_tssi_mode`, IQK, 30ms, TSSI, 30ms, DPK. `retune` repeats only those two
steps. `track(scanning)` is one `rtw89_track_work` RF step
(`n51_dpk::Track::step`, then the antenna-diversity periodic tick when a
diversity owner is retained: `rtw89_phy_antdiv_track` / `antdiv_work`,
training then decision, programming ANTSEL through `set_ant`). It returns
without any access while scanning, as core.c skips the work when
`rtwdev->scanning` is set. `station_rf_tracking` calls it for RTL8851B
through `track_radio_51`. The PHYSTS side is driven too: `rx_packet`
classifies each PPDU (`ppdu_class`: rate mode + the OFDM6 split) and reads
IE01 `evm_min`, the packet owner carries the classified observation in
`Step.antdiv` for the owner's MACID, and `packet_poll` feeds it to
`Radio::parse_ppdu` (`rtw89_phy_antdiv_parse`). The 30/110 ms re-queue
periods Linux's `antdiv_work` uses are recorded as the requested period
(`Radio::antdiv_period_ms`); NARF has no sub-second delayed-work
scheduler, so the actual cadence is the 2 s track tick, and NARF feeds
antdiv only from to-self + MACID-matched PPDU reports (Linux parses every
parsed PHYSTS). Unexecuted cases:
`smoke_rtw89_n51_set_channel_help_follows_rtw8851b`,
`smoke_rtw89_n51_channel_owner_gates_rfk_and_scan_tracking`,
`smoke_rtw89_n51_dm_init_txrx_path_and_power_trim_follow_rtw8851b`,
`smoke_rtw89_n51_radio_owner_starts_new`,
`smoke_rtw89_n51_antdiv_parse_and_periodic_track_drive_ant_sel`.

**RTL8851B signed records (`calibration_policy::Board::new_51`,
`radio_policy_51`).** The RTL8851B family mirrors C's with its own magics,
names and identities; no B or C record admits RTL8851B or vice versa.
`Board::new_51` (10ec:b851 only, rtw8851be.c `rtw89_8851be_id_table`) hashes
an RTL8851B domain string, the path-A calibration recipe and the WLAN-only
coexistence recipe (rtw8851b.c `rtw8851b_btc_set_rfe`/`_btc_init_cfg`), the
PCI IDs, the logical map, the 128-byte PHY-cap window at 0x580
(`n51_phycap`), cut/RFE/XTAL and `Assets::bind`; it requires a firmware on a
known RTL8851B BTC ABI row (`coex_native::Protocol51`: coex.c
`rtw89_btc_ver_defs` 0.29.29 up to the 0.29.133 v7 row, field-for-field the
RTL8852B 0.29.29 row; the shipped `rtw8851b_fw-1.bin` is 0.29.41.5) and
admits antenna-diversity RFEs (`rfe_type % 3 == 2`) through the `antdiv_51`
owner composed by `radio_51::prepare_controls`; `Protocol51::init` encodes
the diversity layout (dedicated antennas + the `ant_info` DIVERSITY bit,
fw.h `RTW89_H2C_CXINIT_ANT_INFO_DIVERSITY`). Its record is `N51B` v1 (`rtw89/rtw8851b-cal-v1-<mac>.bin`, 96
bytes, B's v1 layout) over the cold 2402..2422 span. The firmware PHY-cap
receipt gains an RTL8851B decode (`firmware_phycap::Receipt::decode_51`:
mac.c `rtw89_mac_setup_phycap_part0` with `chip->tx_nss`/`rx_nss` 1 and the
`rf_path_num == 1` RF_A override; `initial_profile_51` refuses Linux's
one-path `tx_path_diversity` and any non-RTL8851B receipt; distinct
fingerprint label). The full program (`radio_policy_51::Board::new`)
composes the calibration identity with that receipt fingerprint, the
`radio_51` recipe, the `Plan::visit_51` program text and `Plan::bind`
(restated geometry checked against the typed B profile), the B
`Profile::bind` geometry and (band, primary, centre, width), domain-separated
per band and per observed-FLR lifecycle; a 40/80MHz identity also binds
`station_control::wide_fingerprint`. Base record `N51B` v2
(`rtw89/rtw8851b-radio-v2-<mac>.bin`, 128 bytes, profile `[1, 20, 1]`, flags
exactly 3: no RTL8851B station program exists yet). Each noninitial typed
profile in `radio_policy_51::noninitial` (2.4GHz 20MHz 2..=13, 2.4GHz HT40
either side, every 5GHz 20/40/80MHz block incl. UNII-4; never channel 14,
160MHz or 2.4GHz 80MHz) may carry `N51C` v1
(`rtw89/rtw8851b-chan-v1-<2|5>g-ch<primary>-c<centre>-bw<width>-<mac>.bin`,
128 bytes: `[1, width, primary, 3]` at 54, `rtw89_band`/centre at 68/69;
the centre is in the name so the two HT40 sides never share a file), signed
by the base signer and bound to the base digest/signer. Admission is C's
whole-span rule (`radio_policy_c::check_envelope`, now shared): gapless
overlapping rules, each allowing the width (AUTO_BW, NO_160MHZ), DFS/NO_IR
passive-only at 5GHz (signed emissions but no frame: `tx_current`), every
peak plus antenna gain under the minimum rule power and the signed ceiling.
NARF carries no RTL8851B board value; an unprovisioned board stays
unadmitted. Unexecuted cases:
`smoke_rtw8851b_calibration_record_is_n51b_and_never_a_b_or_c_record`,
`smoke_rtw8851b_full_radio_base_record_is_n51b_v2_exact_and_revocable`,
`smoke_rtw8851b_channel_records_admit_exactly_their_profile_and_span`.

**RTL8851B native MAC, RX and table wiring.** `mac_runtime::Mac::prepare`
admits RTL8851B (with its `n51_phycap`) on B's download geometry and runs the
B sequence with mac.c's RTL8851B branches: rtw8851b.c
`rtw8851b_mac_enable_bb_rf` (B's without the `R_AX_SPS_DIG_ON_CTRL0` ZCDC
write; `rtw8851b_mac_disable_bb_rf` is byte-identical to B's, so terminal
closure takes B's `radio_stop` path), `dle_clk_en_ax` with
`B_AX_AXIDMA_CLK_EN`, `rtw8851b_dle_mem_pcie[SCC]` (`wde_size6` 512 link
pages, `wde_qt6` 448/48/0/16, B's `ple_size6`/`ple_qt18`/`ple_qt58`) and
`rtw8851b_hfc_param_ini_pcie` (ACH0..3 {5,343}, B0MGQ/B0HIQ {4,344}, pub
448/448, the shared `hfc_preccfg_pcie`). Everything else in
`rtw89_mac_init` is B's (`rtw89_is_rtl885xb` OCP/preload/SIFS 52B, TX
partial mode clear, identical `rtw8851b_imr_info`/`rrsr_cfgs`).
`Native::prepare_receive` and `rx_dma::Rx::prepare_for` admit RTL8851B on B's
geometry (rtw8851be.c `rtw89_8851be_info` is field-for-field rtw8852be.c's).
The register mailbox stays on the B block (`rtw8851b_h2c_regs`) but decodes
with `Receipt::decode_51`; `query_firmware_phycap` requires
`initial_profile_51` and an RTL8851B receipt, and `radio_profile_current`
dispatches RTL8851B to its own identity + receipt check. `radio_access` admits
RTL8851B with its PHY-cap and window (`NativeIo::n51_phy_window`), and
`prepare_radio_tables` selects `Qualified::from_factory_51`. `Startup::start`
builds `radio_assets::Assets` for RTL8851B. The bootstrap `advance` refuses
RTL8851B at `RadioTablesLoaded` (no B basic/full calibration ever runs on
it) until the RTL8851B radio step composes `radio_51`. Unexecuted case:
`smoke_rtw8851b_post_wcpu_mac_is_b_with_rtw8851b_branches`.

**RTL8851B native radio composition and WLAN-only coex
(`command_native/radio_51.rs`).** `Native::preflight_radio_51` stages,
with no register access, the `N51B` v1 calibration record
(`calibration_policy::Board::new_51`), the `N51B` v2 base and every
provisioned `N51C` record over `radio_policy_51::noninitial` (a profile
whose `Plan::from_elements_51` cannot be built from the actual container is
not looked up). `Native::prepare_radio_51` rebinds both identities to the
exact Native/assets/plan/PHY-cap receipt, requires the staged record to
admit exactly `profile` under the current host rule, `select`s it, installs
the calibration record and `qualification_51`, and only then touches the
device. `qualification_51` gates every access: `calibration_access` checks
it beside the calibration record, and `radio::Port` now carries a
`ChipProgram` (C or RTL8851B) whose `with_current` encloses every MMIO
transaction (read_rf/write_rf/radio_io). Order is core.c
`rtw89_core_start`: `rtw89_btc_ntfy_init` before `rtw89_phy_dm_init`.
`coex_native::Coex::prepare_51` is rtw8851b.c `rtw8851b_btc_set_rfe` +
`rtw8851b_btc_init_cfg`: mac.c `rtw89_mac_coex_init` without the two
RTL8851B-skipped steps (`B_AX_PTA_WL_TX_EN`, `B_AX_RSP_CHK_BTCCA`),
`rtw8851b_btc_set_wl_pri` TX_RESP/BEACON, path S0 only (`stream_cnt` 1):
RR_WLSEL 0, RR_LUTWE BIT(17), `rtw8851b_set_trx_mask` SS 0x5ff / RX 0x5df
/ TX 0x55f (shared BTG path) or 0x5ff with the Tx=1/Rx=2 remap and +3 on a
shared antenna, RR_LUTWE 0, break table, BT counter; then `_write_scbd`
0x4003, cxinit v0 (`Protocol51::init`: rfe 3n+1 shared/num 1/BTG/wa 1, 3n+3
dedicated/num 2/alone/external, `ant_info` stream 1 at S0,
`mod_adie_kt` = `hal.acv` read from XTAL_SI_CV[3:0] as core.c
`rtw89_read_chip_ver`), cxctrl v1, txpwr ctrl off and B's generic AX
`_set_ant(WONLY)` + OFF_BT policy. rfe_type 0 (Linux returns before any
antenna field, leaving `stream_cnt` 0 and a two-path loop) and 3n+2
(diversity) have no encoding and no calibration identity; the bound
`N51_COEX_RECIPE` text states exactly this. The radio then runs
`radio_51::Radio::prepare_controls` (bb_sethw, DM sub-inits, NCTL from
container table 4) and `prepare` at the default chandef, with
`factory_51::Calibration` rechecked against the factory, and records the
channel/epoch. `Startup::prepare_radio_51` + the bootstrap
`RadioTablesLoaded` arm replace the refusal and reach `RadioReady` with
**no ordinary grant** (station/TX stay closed). `finish_radio_shutdown`
admits RTL8851B on B's `finish` (`rtw8851b_mac_disable_bb_rf` is
byte-identical to `__rtw8852bx_mac_disable_bb_rf`, clearing RF00S_EN at
S0 and RF10S_EN at S1 even on the one-path chip). Unexecuted case:
`smoke_rtw8851b_wlan_only_coex_init_follows_rtw8851b_btc_init_cfg`.

**RTL8851B ordinary grant, retune and RF tracking
(`command_native/radio_51.rs`).** On `Ready`, `prepare_radio_51` installs
`OrdinaryGrant::N51` (the same retained `radio_policy_51::Qualification`,
rechecked; `b()` is "no program", as on C). `c_ordinary` is true for C and
RTL8851B; `c_program` dispatches RTL8851B to `qualification_51.allows`
(A-MSDU stays "no program"). `admitted_channels_51` and the RTL8851B arm of
`admitted_wide` list only `N51C` records `channel_active` under the current
host rule (no DFS/NO_IR span: RTL8851B has no beacon-witness passive TX
grant); `admitted_six_ghz`/`six_ghz_regulatory` stay empty (no 6GHz in
`support_bands`). `Native::retune_radio_51` (via `Startup::retune_channel_51`,
dispatched from `retune_channel` and `retune_wide`) mirrors
`retune_radio_c`: drain, withhold the grant, rebind
`radio_policy_51::Board::new` + `channel_matches`, `select`,
`radio_51::Radio::retune` (core.c `rtw89_set_channel` ->
`rtw8851b_set_channel`, then `rtw8851b_rfk_channel`; no RF_GET_MCCCH),
update the RX width, reinstall the same grant. `track::Hw::rfk` and
`station::Io::station_rf_tracking` are async; on RTL8851B
`Startup::station_rf_tracking` runs `Native::track_radio_51`
(`radio_51::Radio::track`, `rtw8851b_rfk_track` path-A DPK track) with the
current N51 grant on a started, awake, non-calibrating station; `track.rs`
`run` returns before any RF step while scanning (`rtw89_track_work`
checks `rtwdev->scanning`), and a failed step terminalizes Native. The
`N51B` recipe text names `rtw8851b_rfk_track`, so the signed identity
measures the tracking emissions.

**RTL8851B station admission and one-stream HT/HE wide path.**
`startup_station::station_allowed` and `station_control::Controller::new`
admit RTL8851B on B's station codec (rtw8851b.c `rtw8851b_chip_info` has
RTL8852B's `h2c_cctl_func_id` CCTLINFO_UD, `bacam_num` 2 / `RTW89_BACAM_V0`,
`addrcam_ver` 0). The station preflight takes `NativeIo::n51_station_window`
and B's HCI check (rtw8851be.c `rtw8851b_pci_info` is byte-identical to
rtw8852be.c's); `station_tx_current` uses `radio_policy_51::tx_current`.
`packet_core::Core::prepare_with` admits RTL8851B on the ordinary station
rings only (no AP); A-MPDU is allowed, A-MSDU and fragments are refused.
`packet_format::transmit_51` is the AX v0 TXWD (`txwd_body_size` /
`txwd_info_size` as RTL8852B, pci.c `rtw89_pci_fill_txaddr_info`) with no
A-MSDU; `tx_transport` admits RTL8851B QoS data (no A-MSDU), HE +HTC, host
CCMP and pci.c's 36-bit mask. Track work uses `track::LAYOUT_51` /
`REGISTERS_51` (`rtw8851b_dig_regs`/`rtw8851b_edcca_regs` are RTL8852B's;
`rtw8851b_dcfo_comp` R_DCFO_COMP_S0_V2 [13:0], `dcfo_comp_sft` 12) and the
phy.c `rtw89_phy_cfo_set_crystal_cap` RTL8851B branch
(`rtw8851b_xtal_info`: R_AX_XTAL_ON_CTRL3 SC_XO [14:8] then SC_XI [6:0],
read back). `radio_policy_51::PROGRAMS` is WMM / all-AC QoS / firmware RA
/ HT / HE / A-MPDU, each extending the identity in an RTL8851B domain over
the common AX fingerprints (HE over `he_fingerprint_1ss`). The station is
one-stream (`Io::station_single_stream`, `hal->rx_nss` = `tx_nss` = 1):
`local_he_1ss`, `local_he_wide_1ss` and `local_vht80_1ss` carry NSS1-only
MCS maps (0xfffe) in the 20MHz join, `wide_phy(one_stream)` (never a
160MHz candidate) and the interface VHT advertisement; a 40/80MHz
`N51C` record binds `wide_fingerprint_1ss`. RTL8852B/C bytes are
unchanged. Unexecuted cases:
`smoke_rtw8851b_station_offers_one_stream_he_vht`,
`smoke_rtw8851b_track_layout_is_b_with_v2_dcfo_comp` and the program-record
case in `smoke_rtw8851b_full_radio_base_record_is_n51b_v2_exact_and_revocable`.

**Remaining for the row.** The one-path antenna-diversity tracker
(`hal->ant_diversity` from `rtw89_mac_setup_phycap` `rfe_type % 3 == 2`:
phy.c `rtw89_phy_antdiv_init/_reg_init/_parse/_track/_set_ant`, core.c
`antdiv_work` and per-PPDU parse) and the matching coexistence/antenna
settings are now driven end to end (`rx_packet::ppdu_class` + IE01 EVM,
`packet_core::Step.antdiv`, `Radio::parse_ppdu` / `track`, and the
`Protocol51::init` diversity row); the row's remainder is the
chip-specific firmware/RF/power/station ownership still open above.

### RTL8852B AP native wiring: AP packet owner, MACID/port TXWD, CH9 HIQ (partial; no interface caller)

`Startup` now retains an `ApController` beside the same `Firmware<Native>`
(`startup_ap.rs`), exclusive with the station and monitor owners (both
hold MACID0/port0/address CAM 0). `station::Io` gains default-unsupported
AP methods (`ap_prepare`/`ap_start`/`ap_publish_beacon`/`ap_add_peer`/
`ap_associate_peer`/`ap_remove_peer`/`ap_stop`/`packet_submit_ap`), so
every existing implementation keeps refusing AP. `ap_prepare` runs
`rtw89_mac_vif_init` and then publishes the AP packet owner; the
controller is retained before every await.

`packet_core::Core::prepare_ap` (`command_native/ap.rs`
`prepare_ap_packets`) publishes the ordinary rings plus the CH9 high queue
(pci.c `rtw89_pci_init_tx_ring` for `RTW89_TXCH_CH9`; the RTL8852B `B0HIQ`
HFC channel 4/342 is already programmed by `mac_runtime`, the DMA-stop
proof already covers CH9). The AP stop mask is `STOP_ALL | B_AX_STOP_CH9`
only while the AP binding exists; the station mask and bytes are unchanged.
`submit_ap` publishes one frame at a time; the native owner resolves the
TXWD MACID (`rtw89_core_tx_get_mac_id`: bound peer, else vif MACID0 for
group frames and management to an unbound peer), refuses unicast data/Null
to an unbound peer at both publication checks, uses the vif port only for
HIQ (`desc_info->port = hiq ? port : 0`), the band floor rate for
management/Null/group frames and firmware RA (only with the signed RA
program) or the floor for unicast data. `packet_format::transmit_ap`
follows `rtw89_core_tx_update_desc_info`: `rtw89_core_get_tx_type`
(management and any Null are MGMT), `rtw89_core_get_qsel_mgmt` /
`rtw89_core_get_qsel` with `SEND_AFTER_DTIM` -> `B0_HI`/CH9, MGMT HW SSN
selector1/mode1, `INFO0_MULTIPORT_ID`, `INFO3_SPE_RPT`, `INFO4_RTS_EN`
unicast only. `tx_transport::prepare_header_ap` admits only FromDS data,
QoS data with EOSP (no +HTC), Null/QoS-Null, the AP management subtypes
and host CCMP on FromDS data/robust management; the station validator is
untouched. RPQ releases match pending frames by MACID as well as WD
sequence/queue; in the AP role a non-TX_DONE release is ordinary TX status
(`radio_acknowledged = false`, pci.c `rtw89_pci_tx_status`) instead of a
failure. RX in the AP role reports the long-RXD `AX_RXD_MAC_ID` beside
each frame (`Step::rx_mac_id`) for MACID classification of the peer.

Still missing for `uapsd`: the interface (narf_wireless AP controls and
per-peer host RSNA), signed AP channel/power admission, `ap_ps` wiring
and the advertisement. No AP or U-APSD capability is advertised. Two new
cases are written, unexecuted:
`smoke_rtw89_ap_txwd_macid_qsel_port_and_rates`,
`smoke_rtw89_ap_txwd_refuses_station_and_misplaced_frames`.

### RTL8852B host AP: interface controls, signed AP channel, AP PS wiring and U-APSD advertisement

Row `uapsd`. `interface_ap.rs` opts into native terminal-completion AP
controls: `ap_control_generation` is the selected AP role's
`monitor::Selection` generation (`AP_IFTYPE` 3, `Desired::select` admits
2/3/6) of a published, live generation; `reserve_ap_control` is an
`ExclusiveControl` lease; every operation re-proves the exact request,
its reservation, UP and `ApEmissionAuthority::matches_role` before and
after the retained-owner work. Selecting AP needs `ap_capable`
(`Io::ap_allowed`, sampled at activation before any station owner);
the AP generation activates with the radio Ready and no station owner.

`start_ap_with_settings_async` follows the Linux order: signed AP
channel/power admission and program (`Io::ap_channel` =
`Startup::ap_channel`: the primary must be in `admitted_channels` -- a
current signed full program whose host rule permits active emission --
and is refused when `station::passive_only` (RADAR/NO_IR): rtw89
registers no `radar_detect_widths` in core.c `rtw89_iface_combs`, so
cfg80211 `cfg80211_reg_can_beacon` never lets it beacon there; then the
same `Native::retune_full_radio` the station uses, i.e. core.c
`rtw89_set_channel` + `rtw89_chip_rfk_channel`, before the vif exists),
then `ap_prepare` (`rtw89_mac_vif_init`, AP packet owner with CH9),
`ap_start` (`rtw89_ops_start_ap` with the BSS beacon interval/DTIM) and
the first `rtw89_fw_h2c_update_beacon`. Only 20 MHz (`_20_NOHT`/`_20`)
host-CCMP-128 BSSes are admitted; MBSSID/EMA, FILS, unsolicited probe,
FTM, TWT, HE OBSS/colour, P2P GO PS, TKIP/GCMP and MFP are refused, never
dropped. A beacon head carrying its own TIM is refused. `stop_ap_async`
runs `rtw89_ops_stop_ap` + `rtw89_mac_vif_deinit` and closes the
generation: the supervisor composes a fresh one (fresh FLR) in the
still-selected AP role before another START_AP.

Peers: NEW_STATION = `rtw89_core_sta_link_add` (MACID from
`ApController::add_peer`, packet binding); a nonzero AID (NEW or SET)
= `rtw89_core_sta_link_assoc` with an RA body over the peer's legacy
`supp_rates` (`legacy_rates`; 5 GHz OFDM-only as phy.c
`rtw89_phy_ra_sta_update`) placed at its MACID (`codec::ra_at`);
DEL_STATION withdraws host state before `ap_remove_peer`. Host RSNA is
per peer (`ap_crypto.rs`, the mt7921 AP CCMP owner shape: pairwise key
per peer address, GTK index 0..3 with a default, retained key history so
no TK returns with a reset PN, GET_KEY = consumed TX PN). The CCMP shape
admits EOSP because `ccmp_special_blocks` masks it (and MoreData) out of
the AAD.

`ap_host.rs` is the mac80211 host path for one vif: tx.c
`ieee80211_build_hdr` (FromDS, A1 DA, A2 BSSID, A3 SA; QoS only for a
WME peer, never for group frames), `ccmp_encrypt_skb`, control-port TX
(`ieee80211_tx_control_port`, protected once a PTK exists unless
`no_encrypt`); RX classified by the long-RXD `AX_RXD_MAC_ID` (a peer
frame is accepted only when that MACID is the peer's own), rx.c
`ieee80211_rx_h_uapsd_and_pspoll` before decryption, ToDS-only data,
`ieee80211_drop_unencrypted` (only EAPOL/pre-auth in the clear under
privacy), `ieee80211_data_to_8023`, the control-port split
(`ieee80211_frame_allowed`, `no_preauth`), unauthorized-peer drop and
`ieee80211_deliver_skb` intra-BSS forwarding (group frames up and back
to the BSS, unicast to another authorized peer forwarded only).
Management frames to the BSSID or broadcast reach the registered SME
subscriptions (`register_mgmt_frame_ap_async`, 16 max); protected
management (MFP) is not in this profile. `mgmt_tx_ap_async` and
`tx_control_port_ap_async` submit on-channel at the band floor rate
(refusing `no_cck` on 2.4 GHz) and report the actual RPQ TX status.

AP power save (`ap_ps.rs`) is now wired: unicast frames to an associated
peer pass `ApPs::transmit` (`ieee80211_tx_h_unicast_ps_buf`), and `mgmt_tx` frames pass the same decision via `Host::ps_decide`; a TIM change
from buffering, a PM transition, expiry (`ApPs::expire` each worker pass)
or DEL_STATION marks the beacon dirty and the AP worker republishes it
(`rtw89_ops_set_tim` -> `update_beacon_work`); PS-Poll and U-APSD trigger
releases go out ahead of the backlog with a TX report, and their terminal
RPQ release -- acknowledged or the AP no-ack status -- ends the service
period (`ApPs::tx_status`, status.c EOSP); group frames while any peer
dozes are `SEND_AFTER_DTIM` on the CH9 high queue of the vif port.

Advertisement: `supports_ap`, AP in `WirelessModes`, AP userspace MLME,
the host AP authenticator (control port over nl80211 with TX status,
`no_preauth`) and `supports_ap_uapsd` (`NL80211_ATTR_SUPPORT_AP_UAPSD`,
Linux `WIPHY_FLAG_AP_UAPSD`) only when this generation is AP-capable.
`hw->uapsd_max_sp_len = IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL` is a
mac80211 station-side limit with no nl80211 attribute; the AP side honours
each peer's own Max SP (0 = all) in `ApPs`.

Known gaps (not claimed): unicast data
uses the band floor rate (no firmware RA rate on AP TX); peers are
legacy-rate only (no HT/HE peer programming); one AP vif on port 0; no
MFP/BIP; no native or physical execution. Management frames from
`mgmt_tx_ap_async` to a dozing peer are PS-buffered instead (`Host::ps_decide`,
bufferable MMPDUs held with TIM set, reported not-acked until delivery).
New cases, written and
unexecuted:
`smoke_rtw89_ap_host_plan_admits_only_the_20mhz_ccmp_profile`,
`smoke_rtw89_ap_host_ccmp_fromds_tx_and_macid_bound_rx`,
`smoke_rtw89_ap_host_control_port_and_unencrypted_drop`,
`smoke_rtw89_ap_host_dozing_peer_tim_and_pspoll_release`,
`smoke_rtw89_ap_host_mgmt_tx_to_dozing_peer_buffers`.

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
| `eht` | EHT operation on RTL8922A is implemented, steps 1–2, fixture-tested. Step 1 (`eht.rs`): RFMOD table for 20/40/80/160MHz, SIFS value pairs (320MHz included), CFGCH bandwidth field (320MHz = code 4), BB bandwidth class, the EHT arms of `bb_postinit` and `cfg_rx_nss_limit`, the EHT RX CRC counter block, and the EHT operation profile (320MHz supported, max MPDU 7991). Step 2 (`eht.rs` `eht_cap`/`EhtStation`, `txrx_be::eht_info_fields`, commit e1286e402): EHT MCS/NSS capability maps mirroring `rtw89_init_eht_cap` (`core.c` @ 05441d6 — the sparse-clone reference supersedes the step-1 note that `core.c` was not in the local reference), the EHT station-owner facet, and the TXWD_INFO EHT fields (INFO4 SW_EHT_NLTF_SWITCH/NLTF, INFO7 UL_EHT_USR_PRES). The facet is composed by the 8922A station owner: `station_8922a.rs` admission (commit ee7239294) via `prepared_8922a.rs` `admit_station`, constructed at bring-up in `pci.rs`. Still absent (chip row, not this row): 8922A admission into the shared `station_control::Controller::new` (RTL8852B/C + 8851B only; the 8922A owner uses the BE path `efuse_be.rs`/`irq_be.rs` — the legacy `efuse.rs` still returns `UnsupportedChip` for 8922A and the AX `irq::Mask::config` still rejects the `_v2` layout) and the complete TXWD_INFO v2 transport fill (`tx_8922a.rs`). Step 3 (`eht.rs` `get_txsb`/`tx_sub_band_value`): `rtw89_phy_get_txsb` (`phy.c:875`, present in the linux-7.2 reference — the earlier "not in the local reference" note was stale) and the `R_BE_TX_SUB_BAND_VALUE` word of `rtw8922a_set_channel_mac` (TXSB20/40/80 + PRI20 bitmap), fixture-tested, no production caller (the 8922A channel program has no runtime owner). Grounded absence, not an oversight: no 320MHz RFMOD arm — `BE_WMAC_RFMOD_320M` has no user in `rtw8922a.c` or `rtw8922d.c`, and RTL8922A `support_bandwidths` stops at 160MHz (`rtw8922a.c:3209`), so 320MHz is neither programmed nor advertised. EHT capabilities stay unadvertised until the 8922A station path programs them. The shared `association::eht` API is not the gap. |
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
| `wide_channels` | RTL8852B (20/40/80MHz) MAC/BB/RF/RFK/power width programming, per-width signed N52C records and whole-span admission are implemented (§3 "RTL8852B 40/80MHz operating channels"). Station HT40/VHT80/HE-wide capability on the admitted chandef, retune before authentication, RA `bw_cap`/SGI/VHT branch, wide RX admission and width advertisement are implemented too; native validation pending. RTL8852C 160MHz is the RTL8852C lane; RTL8851B/8852A/8922A are their own chip rows. |
| `fragmentation` | The admitted RTL8852B native/host/public owner is now implemented in §3 above, including the separate signed full-joint emitter, per-fragment PN and actual terminal ownership, bounded original-source RX cache and threshold control. Source review, release compilation and native/physical acceptance are pending. Other chip/width profiles remain their explicit separate rows. |
| `monitor_mode` | The admitted RTL8852B receive-only role/native/raw-radiotap owner is implemented in §3 with original source/registration/role/capture epochs, actual RF channel/PHYSTS program and fresh physical transitions. Four source cases and software/native/physical acceptance are pending; no active/injection or other chip/channel/width profile is claimed. |
| `rf_power_tracking` | Source complete for the admitted RTL8852B channel1 HT/HE20 owner: actual periodic thermal EWMA/DPK PWSF producer, same completed Radio input snapshot, native current publication/readback and independent signed full joint-program window are described in §3. Software/native/physical validation remains pending. Periodic IQK/TSSI reruns and non-B thermal-duty quirks are not this adapter’s applicable missing producers. |
| `runtime_sleep` | The admitted RTL8852B clock-gated native/runtime/public path is implemented in §3 below, with separate signed joint qualification and seven new unexecuted cases. Source review, release compile, native two-arch and physical acceptance remain pending; other chip/firmware adapters remain their own chip rows. |
| `six_ghz_operation` | Only RTL8852C/RTL8922A have 6GHz applicability. RTL8852C: implemented ("C 6GHz power, records and station"): 6GHz TX power program (regd.c policy, `reg_6ghz_power`, TPE), signed 6GHz `N5CC` records with per-power-type client admission, native staging/retune with band-qualified channel identity, the HE20 station 6GHz scan (PSC/RNR planning, active only on active records), SAE-H2E join through `admit_with_rule` + `JoinPlan::prepare_6ghz`, HE 6GHz Band Capabilities, AP TPE into the plan, HE-only RA and 6GHz band advertisement of admitted primaries only. Native/physical validation pending; HE20 only, 6GHz CSA disconnects, post-association TPE changes not re-applied. RTL8922A 6GHz admission is implemented at the station owner (`station_8922a`: TPE + power program, 20 MHz only; register-level `rtw8922a_set_txpwr` program and wide-6 GHz TPE still open). The retained B profile is 2.4GHz-only in software. |
| `uapsd` | Station U-APSD is source-inapplicable (no IEEE80211_VIF_SUPPORTS_UAPSD). This row covers AP-side WIPHY_FLAG_AP_UAPSD only. The host PS/service-period owner (`ap_ps.rs`) and AP H2C wire (`ap_wire.rs`) exist (§3 "RTL8852B AP groundwork"), and the AP MAC/firmware control owner (`ap_control.rs`: port program, CAM, CMAC/DMAC tables, MACID pause, peer MACIDs, BCN_UPD, start/stop; §3 "RTL8852B AP MAC/firmware control owner") exist, but no native caller, signed AP channel/power admission, multi-peer TXWD/RX MACID path, HIQ/CH9 ring or public AP controls compose them. |
| `wow` | Source layer only (`wow_wire.rs`, `prepared::load_wow`; section 3 "RTL8852B Wake-on-WLAN source layer"): no native TRX-halt/firmware-swap/security-CAM/system-PM owner exists yet. The implemented non-WoW suspend path retires the generation and rebuilds it after resume; this does not preserve an associated wake-capable firmware context. |
| `rtl8852a` | Step 1 done: NHM noise monitoring (`nhm.rs`, fixture-tested — 8852A-only threshold/report tables, 11k thresholds with the WA override, weighted-average noise, trigger/set/get-result model, `support_noise` true) and the authenticated board secure-policy load path (`Blacklist::board_8852a`; upstream 8852A policy is NULL but NARF takes no 8851B-style signature-only fallback for A). Step 2 done: the station owner — `station_control::Controller::new` admits A on B's codec (same CCTLINFO_UD, `bacam_num` 2 / BACAM_V0, `addrcam_ver` 0; `rtw8852a.c:2434..2437,2472` @ 05441d6), `startup_station::station_allowed` admits A, the A station window (`a_phy_window` 0x1d3fc from `rf_base_addr` {0xc000, 0xd000}, `a_station_window`) gates the preflight, RX DMA takes the AX geometry plus the A-only LTR software trigger (`rx_dma.rs`), TX transport admits A QoS/+HTC/host-CCMP with the 36-bit DAC mask, and packet composition runs through `transmit_a` (AX v0 body) with ordinary-station-only rings — all fixture-tested, including a byte-identical A-vs-B H2C/register stream. Step 3 done (Refs #1879): A RF bases (`rf_access::Rf::for_chip`, `rf_base_addr` {0xc000, 0xd000}, `Native` wires it), A PHY-cap (`Factory::a_phycap`, `phycap_addr` 0x580/size 128) with the A calibration decode (`factory_a.rs`: TSSI/thermal/PA-bias trims per rtw8852a.{c,h}) and the A PHY window (`a_phy_window`, last direct RF dword 0x1d3fc) gating `command_native::radio_access` for A, A-domain radio program identities (`radio_policy_a.rs`: WMM/QoS/RA/HT/HE/A-MPDU over the v0 TXWD path), and `packet_core` A admission (ordinary station rings on the AX address set, A-MPDU, A-MSDU to A's 3500-byte `max_amsdu_limit`, AP role with CH9). Still absent: the BB/RF tables (`rtw8852a_table.c`, 51,012 lines), the RFK flow on top of them, the A `Qualification`/`OrdinaryGrant` wiring in `command_native`, the A fragment companion (so no end-to-end A fragment submit yet), and a Native-level A `radio_access` test (needs an RX-Polling setup). Native A operation cannot be advertised yet. |
| `rtl8851b` | Source identifies the 1TX/1RX dual-band chip. The exact secure policy is now pinned (Linux NULL `fw_blacklist`: no host chip list, content bounds still enforced, MSS signature still required) and the one-path antenna-diversity owner exists (`antdiv_51`, composed into `radio_51::prepare_controls` with retained state: `rfe_gpio` incl. the `<= 50` GPIO bound, `reg_init`/`set_ant` programs, EWMA stats + training/decision/track state machine). The state machine is hooked into the PHYSTS path (`startup_station.rs` `packet_poll` -> `radio_51::parse_ppdu`, phy.c `rtw89_phy_antdiv_parse`) and periodic work (`radio_51::track` -> `antdiv_tick`, phy.c `rtw89_phy_antdiv_track`), and `pci::probe` routes `10ec:b851` to the retained bootstrap (`radio_51` station runtime). Remaining: signed N51 records/provisioning and native/physical acceptance. |
| `rtl8852c` | The advertised AX-v1/three-band hardware description is not a native station profile. C needs the exact generation-specific PCI/descriptor transport plus firmware/security, RF/calibration/power and station composition; the current retained Controller/N52B profile is B-only. |
| `rtl8922a` | BE EFUSE (DDV physical dump, 3-byte-header logical parse, per-block driver, PHY-cap window, secure/ECV/thermal-K readers, BAR MAC), chip container, BE TXD body v2 encode, BE RXD short v2 parse, v2 interrupt mask/enable/disable/recognize, and BE RA H2C v1 builder are implemented (`chip_8922a.rs`, `efuse_be.rs`, `txrx_be.rs`, `irq_be.rs`, `ra_v1.rs`, fixture-tested). Runtime step 1 is also implemented: BE PCI DMA control sequence (`dma_be`: WPDMA/TRXDMA/TXDMA channel + FW channel, index clear, mode-op, BDRAM reset, MIT, post-init tail, DMA-all), BACAM_V1 H2C encoding + slot map with Linux eviction rule (`bacam_v1`), G7 default CMAC table (`cctl_g7`). Steps 2–7 are also implemented, fixture-tested: station owner + admission (`station_8922a.rs`, step 2), TX-power profile + CCTL update builders + RA mask (`txpower_8922a.rs` TSSI/gain-offset parse, `cctl_g7` ampdu/txtime/punctured, `ra_mask`, step 3), BE DMA ring programming + transport (`dma_8922a.rs`, `tx_8922a.rs`, step 4), Prepared wiring + probe admission (`prepared_8922a.rs`, `pci.rs` bring-up, step 5), interrupt config/mask + v2 classification + MSI binding (`irq_be.rs` `IsrsBe::events`, `BindingBe`, step 6), and the C2H completion path (`completion_8922a.rs`: NAPI-order RPQ then RXQ drain, C2H envelope parse + route, H2C-ack surfacing, TX receipts freeing retained DMA buffers, step 7). Still absent: the complete firmware/RF/power/station profile (BB/RF tables — NULL in Linux, loaded from firmware — TX-power program including by-rate tables, thermal/TSSI tracking and regulatory limits, calibration, firmware-security wiring), MLO multi-link, legacy-mode admission, the MAC/PHY/BTC C2H handlers, BA reorder, A-MSDU deaggregation, RX fragment reassembly, and 8922A admission into `station_control`. Done 2026-11-08 (#1867 lane): FWCMD header framing for H2C bodies (`fwcmd_8922a.rs`) with H2C-ack → retained-buffer matching in the completion path, the TXWD_INFO v2 fill (`txrx_be::fill_txwd_info_v2`, `tx_8922a::build_header_with_info` / `Prepared8922a::prepare_data_with_info`), the full `pwr_on_func` tail / `mac_pre_init` owner (`mac_pre_init_8922a.rs`, run from `pci::bring_up`), and `cid` retention (`HalChipVer`, recorded on the owner). 6GHz admission is also implemented (station_8922a: TPE + power program, 20 MHz only; register-level `rtw8922a_set_txpwr` program and wide-6 GHz TPE still open). The AX-path 8922A refusals are verified already-delivered (see `tx_transport`, `packet_format`, `packet_core`, `factory`, `fifo`, `bdram`, `download_dma`, `irq::Mask::config`, `station_control::Controller::new`). Of the 8922A dispatch gates, two are now routed: `command_queue.rs` `descriptor` takes the BE 24-byte short-v2 FWCMD descriptor (`fwcmd_8922a::fwcmd_txdesc`) and `efuse.rs` `read_mac_with` takes the BE PCIe BAR MAC (`efuse_be::read_mac_pcie`). Six still deliberately refuse the chip — their AX register sequences have BE parallels already wired through probe (`prepared_8922a` / `BeFactory` / `irq_be::MaskBe` / `dma_be` / `fwdl_be`): `bdram.rs`, `download_dma.rs`, `factory.rs`, `fifo.rs`, `irq.rs` `Mask::config`, `station_control.rs` `Controller::new` (whose `&Factory` input cannot carry 8922A). Native EHT/320MHz cannot be enabled by shared IE encoders before that owner exists. |
