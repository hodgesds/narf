# rtw88 — Specification

> Status: **v1.6** (RTL8821CE retained firmware/MAC/PHY, separately signed IQK/parked-power/awake-station, legacy12/WMM, exact-chip HT20/SGI, separately qualified RX/TX Block Ack and native RTS-threshold continuations; RTL8822CE retained firmware, MAC/PHY, bounded radio calibration,
> signed operating-power qualification, native packets and channel1 station
> integration; composed software gates and physical acceptance remain distinct).
>
> Realtek Wi-Fi 5 (802.11ac) driver for PCIe silicon
> (RTL8821CE / RTL8822CE). Adapted from Linux
> `drivers/net/wireless/realtek/rtw88/`.

## 1. Purpose & scope

**Owns:** PCI matching, baseline power-on, and factory identity for
RTL8821CE / RTL8822BE / RTL8822CE, plus the retained RTL8821CE firmware/inactive
MAC/PHY-table owner with separately qualified IQK, parked-power and native
awake station continuations, and RTL8822CE native firmware
loader, MAC/FIFO/PHY, H2C, calibrated radio/board-power continuations and a
single awake channel1/20MHz station for RTL8821CE/RTL8822CE. Each retained station
supports Open and WPA2-PSK with host RSNA/CCMP; its ordinary host TX rate is
fixed at1Mbps by default and requires an AP advertising that basic rate.
RTL8821CE/RTL8822CE can separately qualify response-bound legacy12 DATA rates
and WMM BE/TID0, then distinct HT20/one-stream MCS0..7/SGI20 with mandatory
default A-MSDU receive and native ADDBA refusal, plus distinct optional recipient
and BE/TID0 originator Block Ack grants; management and EAPOL remain
at1Mbps. N21S alone does
not admit the C21 extension, and neither chip can reuse the other's assets.
The probe decodes physical EFUSE programming
records to obtain the correct PCIe MAC.

**Does NOT own:** Trusted deployment policy, measured board calibration
artifacts or their signing authority. Factory country hints supply no policy.

## 2. Assumptions

The caller owns the PCI function and its BAR2 register aperture exclusively.
`pci::bring_up` maps BAR2 with `map_bar_control` (Device memory attributes)
and rejects windows smaller than `0x170c` for RTL8821CE/RTL8822CE (firmware
LTE indirect data) or `0x1104` for RTL8822BE before MMIO. Chip/cut-filtered
PCI power enable/disable tables and pre/system setup now follow Linux's
actual flows. BAR2 is mandatory and is a control-register window. The
device has no active firmware/packet DMA or IRQ handler during this reset.
The initial native DMA profile requires physical/identity DMA addressing;
per-domain IOMMU translation is rejected before allocation or MMIO.

## 3. Public interface

`pci::bring_up(device, cap)` first parks inherited PCI DMA through the shared
Realtek command policy: clear `BUS_MASTER`, enable `MEM_SPACE | INTX_DISABLE`,
and read back the command register. Any access failure, retained BME or missing
requested decoding fails before BAR mapping. Bus mastering remains disabled
on success and every identity error; identity and ring allocation do not authorize
DMA. `pci_park::invoke` places the actual parking, BAR mapping, power and
EFUSE operations inside the current PCI capability invocation. The shared
helper is also used by rtlwifi firmware MMIO; a real revoked-cap regression
proves the register callback is not entered after revocation.
A non-spinning atomic/RAII reservation covers the complete synchronous
probe transaction from admission through power, retained controller/interface
publication and spawn. Overlapping same-function or additional-function
probes return `BadDevice` without PCI/MMIO access or parking an initializing
function; they never report an uninitialized overlapping function bound.
A repeat probe of the retained bus address returns without configuration
access; a distinct additional singleton match parks only its own PCI
function. The RTL8822CE firmware owner may later enable BME only after retaining
and checking every host ring, with firmware-only beacon DMA runnable.

`Rtw88Device::registers` holds the single mandatory BAR2 control mapping;
there is no separate firmware data BAR. Mapping/short-window failures are
reported as `ProbeError::{RegisterBarMapFailed, RegisterBarTooSmall}`.

`power::power_on(registers, pci_device_id)` detects the silicon cut,
rejects unknown cuts/absent hardware, runs cold-card enable or the warm
disable/enable cycle, and preserves unrelated register fields. PCI polling
uses a bounded responsive wait and the Linux PFM_WOWL retry. Cut-C-only
8822B rows remain cut filtered. This stage does not enable station traffic.

`efuse::read_mac(registers, pci_device_id)` returns a validated, nonzero
unicast factory MAC or `EfuseError`. Unknown PCI IDs fail before MMIO;
the ID selects both logical-map geometry and read-power controls:

| PCIe chip | Physical bytes | Protected tail | Logical bytes | MAC offset |
|---|---:|---:|---:|---:|
| RTL8821CE | 512 | 96 | 512 | `0xd0` |
| RTL8822BE | 1024 | 96 | 768 | `0xd0` |
| RTL8822CE | 512 | 124 | 768 | `0x120` |

For RTL8822CE, `efuse::read_factory` retains the complete768-byte logical
map from that same physical read in the exact `Firmware` owner. `Factory`
exposes the actual PCI MAC, RFE, raw crystal, board/BT options, channel-plan
hint, country hint and both thermal values; the original four packed42-byte
power-path records remain available to the radio continuation. Raw erased
fields stay `0xff`; identity discovery supplies no calibration defaults or
transmit authority. Factory country/channel hints cannot replace the trusted
deployment regulatory policy or measured per-board power qualification.
Nineteen separate source-defined protected OTP cells retain the actual thermal,
2G/5G gain and PA-bias trims. Those explicit bounded raw reads are distinct from
sparse-map decoding; protected cells can never be interpreted as map records.
The same current PCI invocation covers the original map and trim capture.

For RTL8821CE/RTL8822CE, `bring_up` creates one named, unpublished station shell sharing
the exact `Arc<Lifecycle>` retained by the firmware owner. Probe acquires frame
registry authority and registers the shell in the frame, kernel IP and wireless
registries before spawning the firmware worker or activating packet DMA. The
controller view delegates control, carrier and frame rings to this same shell.
Carrier stays down until actual peer association and security admission.
The driver name follows the actual retained chip. RTL8822BE remains diagnostic,
with wireless controls and packet TX unsupported. A C21 shell stays inactive
until its complete separately qualified chain succeeds.
`Rtw88Device::firmware_status()` returns its
`FirmwareStatus { stage, info, error }`; `FirmwareStage` is `Detected`,
`Allocating`, `Loading`, `Ready`, `PreparingMac`, `MacPrepared`,
`PreparingPhy`, `PhyTablesPrepared`, `PreparingCalibration8821c`,
`Calibration8821cPrepared`, `PreparingOperating8821c`, `Operating8821cPrepared`,
`PreparingRadio8821c`, `Radio8821cPrepared`, `Calibrating`, `Calibrated`,
`StationPreparation`, `StationReady`, or `Failed`. `Ready` identifies firmware
completion and parked host DMA, independently of station/radio readiness.
`StationReady` identifies completed packet preparation, not an associated peer
or authorized controlled port. RTL8822BE has no native firmware owner. The safe
`fw::download_firmware(registers, pci_device_id)` helper returns
`FwError::Unsupported` before registry or MMIO access for every device:
raw MMIO alone cannot prove exclusive DMA/ring/reset ownership.

### RTL8821CE retained firmware, PHY and qualified calibration continuation

Probe captures `efuse::Factory8821c` from the same single512-byte logical-map
read that establishes its factory MAC. The distinct type retains raw4×42-byte
power records, thermal/crystal/board/BT/channel/country fields and the original
RFE byte. Its decoded RFE mask/package bit follows `rtw8821c_read_efuse`; erased
values are never replaced. The later parked-power owner applies the exact
source RFE-specific power-path selection. `Rtw88Device::rtl8821c_factory()` borrows this exact
retained identity. No protected C22 trim cells or C22 factory offsets are used.

The station shell retains a separate native lifecycle before any
firmware work. `firmware_status()` reports its stages just as for C22.
`pci::provision()` serializes explicit calls with probe's bounded background
worker and advances `Detected → Ready → MacPrepared → PhyTablesPrepared → Calibration8821cPrepared → Operating8821cPrepared → Radio8821cPrepared → StationReady`; missing/revoked/malformed
firmware remains at the pure retryable `Detected` checkpoint without allocating
DMA. Missing or invalid calibration assets/current policy remain retryable at
`PhyTablesPrepared`, without register access or DMA allocation. A repeated
`Operating8821cPrepared` or `Radio8821cPrepared` checkpoint continues only with
the next required genuine asset/current policy; a `StationReady` request is a
no-op. Once native allocation or a
hardware attempt starts, failure/cancellation is terminal and retains the exact
inner owner and every published mapping; no cold-power/firmware reconstruction
occurs. Existing IRQ-safe static locks never cross an await.

This profile opens only `rtw88/rtw8821c_fw.bin`, validates its0x8821 signature and
actual64-byte section header before native allocation, and uses the common Linux
3081 reserved-page/IDDMA flow. The authenticated loaded bytes retain their
digest. Original source matches the shared48-byte TX descriptors, seven
non-beacon rings, RX geometry, LTE registers and firmware-ready predicate;
those mechanisms are reused without treating the C22 firmware as a C21 image.
DMA is parked and the host rings rechecked before the inactive-MAC continuation.

The C21 MAC path uses its own Linux chip function and64KiB TX/16KiB RX FIFO
profile: reserved boundary460, H2C page500, firmware TX page508 and16/16/16/14
priority-page allocation. LLT completion and empty configured H2C pointers are
required. Its EDCA/SIFS/receive configuration uses evaluated8821C constants;
the C22 cut-D PCI quirk is excluded. DMA/MAC TX/RX, packet producers and IRQs
remain closed throughout. Native Rust tests compare complete inactive register
traces with frozen reference cases for two seeded images/cuts. They also cover
MAC access failures, stale hardware reports, LLT cancellation and exact
firmware/owner retention. Packed-factory offsets and pinned raw-firmware-header
metadata remain fixed inputs with source provenance.

The C21 continuation then executes the original `rtw8821c_phy_set_param`
prefix through its three retained channel-filter snapshots. Admission requires
cut0..6, original valid RFE0/2/4/6, non-erased crystal and a one-path antenna/
stream report (Linux IGNORE0 is accepted). Both decoded package0/1 profiles
are selected with Linux's original condition rules, including cut-A/package0
mapping to condition15. A current SYS_CFG1 read must still match the retained
cut and identify one physical RF path; firmware antenna narrowing cannot
qualify two-path silicon. The native aperture must cover `0x2000` before any
PHY write; C22 retains its separate `0x5000` requirement. Every register access
invokes current PCI authority and checks parked BME, with a two-second outer
budget for the C21 table sequence.

The source BB-reset/RF-domain preamble, MAC/BB/AGC tables, RFE2/4 BTG AGC,
one RF-A table, exact6-bit factory crystal and source postamble run in order.
C21 writes all RF registers through SIPI `0xc90`, with source13us+1us delays.
Every selected RF0 write is the source `0x10000`; the MAC TX/RX/DMA gates,
TX pause, empty host producers and IRQ masks remain parked. C21 has no
`rfk_init_tbl`, so no C22 RFK program, direct RF aperture, trims or calibration
routine is substituted. The C21 BB table's own instruction RAM is preserved.
The stage stops before dynamic PHY initialization, power tracking and
beamforming setup, and retains its source TXSF2/TXSF6/TXFILTER snapshots for
those later continuations. Successful parked readbacks alone earn
`PhyTablesPrepared`; they do not prove hardware calibration.

Native Rust tests check stored table/callback digests and channel-filter
snapshots for all56 C21 cut/package/RFE profiles and49 C22 cut/RFE profiles.
The frozen reference data cites Linux `phy.c`, chip callbacks and per-chip table
sources. No compiler/extraction pipeline participates in this validation.
Composed regressions preserve the actual reserved-page backend and its
published firmware DMA buffers through firmware/MAC/PHY success, access
revocation and cancellation before or during RF table loading. Failed or
cancelled attempts retain the exact owner and refuse replay/reallocation.

`Rtw88Device::rtl8821c_calibration_request()` returns the exact retained
calibration identity, factory MAC and requested filename
`rtw88/rtw8821ce-iqk-v1-<12 lowercase MAC hex digits>.bin`. It grants no RF
authority. The identity binds the complete512-byte factory map, authenticated
firmware digest, raw hardware report, cut/package/RFE/crystal, retained filter
snapshots, selected actual C21 tables and versioned calibration recipe. Factory
thermal must be0..63 and raw2G swing0..9; erased values fail before writes.

The signed `N21Q` v1 envelope is exactly128 bytes, little endian: magic at0,
version:u16=1 at4, header:u16=128 at6, total:u32=128 at8, vendor:u16=0x10ec
at12, device:u16=0xc821 at14, identity[32] at16, MAC[6] at48, channel:u8=1
at54, bandwidth:u8=20 at55, antenna gain:i16 quarter-dBm at56, qualified
EIRP ceiling:i16 quarter-dBm at58, measured aggregate complete-calibration
conducted peak:i16 quarter-dBm at60 (including channel/RF setup transients and
firmware IQK), measured thermal minimum/maximum:u8 at62/63,
country bytes `US` at64/65 and zero reserved bytes66..127. Antenna gain is
0..128; each signed power field is-512..256; thermal bounds must be ordered,
within0..63 and enclose the factory thermal value. It must describe the actual
board, firmware, programmed recipe and environment; this implementation supplies
no measured asset or inferred dBm conversion for a TXAGC index.

The initial profile explicitly chooses trusted US, non-SRRC channel1/20MHz.
Current authenticated policy must cover2402..2422MHz at20MHz and every
overlapping rule is enforced, including NO_IR/DFS/indoor/unknown restrictions.
Only NO_P2P is irrelevant to this calibration. Measured conducted peak plus
antenna gain must fit the minimum of the signed EIRP ceiling, every overlapping
policy ceiling and80 quarter-dBm. Missing policy is never substituted with a
factory country hint or permissive default. Retained signed firmware authority
and fresh policy enclose every native register operation and H2C publication;
resuming after a wait rechecks both. Observed revocation stops the continuation;
it cannot retract an already-issued command or autonomous firmware RF.

After qualification the same owner checks its larger `0x2c00` register aperture
and current physical cut/one-path state. Linux `rtw8821c_set_channel*` ch1/20
BB/filter/ADC/clock, factory swing, RFE0/6 WLG or RFE2/4 BTG, RF-A channel,
XTAL toggle and RX DFIR operations run through C21 SIPI with bounded async
delays and stable readbacks. All supported CCK/OFDM/HT1S/VHT1S TXAGC words
are programmed to minimum coded index0 solely for the calibration setup;
this is neither a measured power curve nor permission for ordinary packets.
Fresh RF thermal conversions now bracket IQK. The source C21 power-tracking
trigger writes RF42[17:16]=3; the next watchdog pass reads RF42[15:10]. The
native continuation preserves that two-second conversion interval before both
initial and final meter reads, without inventing a conversion-done bit or
substituting the factory thermal byte. During IQK polling the actual meter
register remains checked against the same signed interval. Recipe revision2
binds these trigger/wait operations into the N21Q identity; an earlier signed
identity cannot authorize the changed calibration program. The asset format
and filename remain v1 because their wire schema is unchanged. General H2C boundary48 and PHYDM firmware RF_1T1R=4 with
TX-A/RX-A fields precede C21 IQK clear=0/segment=0. Transport retirement alone
does not complete IQK: a pre-existing RF08=0xabcde is rejected; a fresh actual
RF08 marker is required within300 polls20ms apart, then cleared and read back.
IQK fail bits0..7 or reload bit16 at0x1bf0 reject this fresh-result profile.
The complete attempt has a twelve-second outer bound. Published command DMA
stays retained on error/cancellation. Success drains commands, parks BME and
MAC/ordinary producers/IRQs again and earns only `Calibration8821cPrepared`.
`rtl8821c_calibration_info()` reports this historical receipt, not continuing
RF authority. C21's Linux calibration callback is firmware IQK; no C22 DACK,
protected trim cells or C22 RF access method is substituted.

Six native Rust regressions compose real retained reserved-page firmware DMA,
MAC and PHY through this continuation. They check literal command bytes, all
four supported RFE branches/swing bins, actual modeled RF receipts and failure/
reload/thermal/transport errors, missing/malformed/unsigned/foreign assets,
NO_IR/overlap policy, suspended cancellation/revocation and exact retained DMA.
These are register/transport model checks; no physical IQK acceptance is recorded.

C21-specific dynamic PHY/power tracking/beamforming/coexistence and additional
source-required thermal behavior remain broader work. The calibration-only
asset cannot authorize operating RF or station admission; the separate full
awake grant and retained native chain below are mandatory.
C21 PHY state has a distinct type and never populates the C22 PHY/power/radio
fields; C22 calibration callbacks remain inaccessible to C21. The completed
C21 native profile exposes passive channel1 scan and legacy Open/WPA2 station;
That calibration-only stage advertises no HT/VHT, QoS or additional bands. Physical firmware/board
acceptance remains unrecorded.

### RTL8822CE retained station provisioning

`pci::provision()` (also re-exported as `rtw88::provision`) is the public
staged-asset continuation for the already registered RTL8822CE. Probe's worker
calls this same function. A single async admission mutex serializes boot and
operator calls; no IRQ-disabling lock crosses an await. Admission snapshots the
exact firmware/interface Arcs, verifies their shared lifecycle and factory MAC,
and rejects absent controllers, diagnostic siblings, closed interfaces and
in-progress/failed stages. Only `Detected`, completed firmware/MAC/PHY-table/
calibration checkpoints can advance. `StationReady` is idempotent. No call
reconstructs the device, repeats an earlier stage or resets a failed owner.

Registered firmware lookup, current Registry/Blob capability invocations,
owned snapshot and header/extent parsing complete before the lifecycle's
single-use atomic begin and before allocating native rings. Missing, revoked
or malformed registered assets leave `Detected` with a diagnostic error and
no native allocation/I/O. A later provisioning call can load newly staged bytes
on that same owner. Probe drives background provisioning via `drive_scheduled`
across 120 attempts with 500 ms intervals, retrying while in `Stage::Detected` or `Stage::PhyTablesPrepared`.
Direct retained `Owner::initialize_registered` likewise
preserves `Phase::New` on preflight failure. The supplied-byte diagnostic path
keeps its existing one-shot semantics. Once allocation/claim begins, failure or
cancellation remains terminal and cannot reopen preflight or reuse DMA.

Missing signed board/policy assets preserve `PhyTablesPrepared`. Fresh current
policy, board binding and power permission are checked in an opaque pure radio
preflight before publishing `Calibrating`; after that accepted attempt, current
checks during real radio operations still fail terminally. Regressions cover
late firmware staging without allocations, real publication/cancellation,
resumption from a completed PHY checkpoint through actual radio calibration,
exact retained-owner identity, and cancelled public admission waits.

The private RTL8822CE continuation opens exactly
`rtw88/rtw8822c_fw.bin` through current firmware authority, snapshots the
authenticated image, and rejects malformed layouts before DMA claim. It
copies image bytes inside current firmware-capability invocation and retains
SHA256 of those exact loaded bytes for board-qualification binding. It
parses the actual 64-byte `0x8822` header, exact DMEM/IMEM/optional EMEM
extents and each eight-byte checksum trailer. Only fixed Linux OCP bases
DMEM `0x200000`, IMEM `0x30000`, and EMEM `0x100000` are admitted;
relocated or trailing data fails. RTL8821C uses its separate exact image and
inactive continuation above; RTL8822B and WoW filename selection remain
unsupported. IDDMA consumes serial reserved pages of at
most 4096 bytes, including section checksum tails, then validates section
checksums and the exact final `0xc078` firmware-ready status.

Before BME, the native owner allocates all seven non-beacon TX BD rings,
512 RX buffers plus their BD array, and the beacon BD/frame (522 coherent
mappings). Every mapping is below 4 GiB; bases, counts and reset indices
are checked while MAC TX/RX and interrupts are parked and ordinary host
producer indices remain empty.
Only the retained beacon queue runs during download. Completion closes
HCI/MAC DMA, verifies BME clear, and restores exact ring
bases/counts/reset indices. Native packet TX/RX and IRQ delivery are not started by firmware readiness.
PCI control `0x303 | 0xf7` is the source DMA configuration, not a queue-stop
bitmap. Parking relies on CR DMA/MAC gates and verified BME clear; only owned
producer indices may advance while BME is enabled. No pause bitmap is inferred
from another chip family, and RX-tag configuration at `0x301[7]` is preserved.

The same retained firmware `Owner` then executes one `prepare_mac` continuation;
it cannot reconstruct the PCI function or reuse firmware pages. `PreparingMac`
is published before native preparation. The native backend rechecks current PCI
authority, the real firmware-ready register and parked BME/queue/MAC/IRQ state.
The continuation ports Linux's RTL8822CE PCIe queue mapping, complete on-chip
FIFO boundaries, LLT initialization, internal H2C head/read/tail setup, chip
MAC configuration and cut-D-or-newer PCIe MAC-clock quirk. `MacInfo` records
the actual cut and reserved/H2C/firmware FIFO pages. LLT waits are bounded and
cooperative; equal H2C pointers must also name the configured queue start.
`MacPrepared` requires the final parked-state readbacks. Any access error,
queue mismatch, failed LLT or cancellation makes the owner terminal and
retains all previously published mappings.

This is an inactive preparation: the Linux CR writes are masked to preserve
closed MAC/HCI DMA, TXPAUSE remains set, BME and every packet queue/IRQ stay
closed. It does not apply RF/BB tables, perform calibration, send H2C packets,
admit scan/station traffic or open carrier. The probe invokes this continuation
only after its actual retained firmware attempt succeeds.

Native DMA claim also writes Linux's boot-time `C2HEVT=0xfd` feature request
before loading/starting the MCU, replacing any previous report. The later
MAC continuation requires the actual `0x19` report, retains all13 bytes,
extracts the original HCI/BW/NSS/antenna/protocol bitfields and acknowledges
the mailbox only after reading the complete report. Missing, unconsumed or
failed report accesses cannot reach MAC readiness. These descriptive fields
do not grant RF, calibration or station authority; radio selection must
intersect them with the exact chip/factory profile and trusted policy.

`prepare_phy_tables` continues that same owner after `MacPrepared`. Its initial
geometry requires both physical RF paths (reported2 or Linux IGNORE), RFE0..6,
the checked silicon cut and non-erased crystal/board/thermal factory fields.
The native backend requires the complete `0x5000` RF aperture before any PHY
write and keeps BME, MAC TX/RX and IRQs closed with empty ordinary
producer indices. It powers the
BB/RF configuration domain, runs source-selected BB/AGC/RFK-init/RF tables,
applies the actual crystal value, and restores the source header-file mode.
RF0 uses SIPI and other RF registers use direct20-bit read/modify/write, with
the actual source delays. Final parked readbacks precede `PhyTablesPrepared`.
Missing factory data, unsupported geometry, access error and cancellation are
terminal. This state means table loading only; DAC/IQ/LO calibration, trims,
channel/power qualification and station activation remain separate steps. No packet/carrier interface is enabled by this continuation.

The native continuation next loads the exact per-device
`rtw88/rtw8822ce-cal-v2-<12 lowercase MAC hex digits>.bin` qualification through
current firmware authority. Loading and metadata parsing execute inside the
blob's `Cap::invoke`; a signer is mandatory even in builds that admit unsigned
device firmware. The retained calibration cap is invoked again before every
permission/gain check. Qualification itself changes no native registers or DMA
state and does not claim hardware calibration complete.

`PowerPermission` has private fields. Its board identity binds the original
logical map, nineteen protected trims, cut/RFE/crystal/two-path geometry,
decoded firmware hardware capabilities, exact loaded-image SHA256, selected
PHY tables and source-derived factory ceilings. Source PG decoding and
normalization constrain each channel 1 CCK gain by the minimum of all four
CCK response rates and all source
regional rows, including the stricter RFE5 table. A country hint cannot raise
an index. Erased or underflowing factory values are refused; indices are never
interpreted as dBm. Signed measured upper bounds must additionally fit current
host policy, antenna gain, qualified EIRP and the conservative20dBm initial
profile ceiling. Every overlapping rule must cover the complete20MHz channel;
DFS, environmental/unknown restrictions and missing coverage keep TX closed.
`NO_P2P` does not prevent the retained STA profile. Unknown measurements never
mean zero power. The qualification also supplies separate measured upper bounds for aggregate
calibration transients and hardware automatic control responses. Both must fit
the current EIRP limit before a grant; rejecting a host RX frame cannot prevent
an automatic hardware ACK or CTS.
Policy changes and actual cap revocation invalidate prior gain tokens.

The family-specific `N22C` version 2 record is exactly 640 bytes: magic[4],
version:u16 (2), header128:u16, length:u32, vendor/device:u16 each, board
identity[32], MAC[6], channel:u8 (1), operating-envelope flags:u8 (3), antenna
gain:i16 in quarterdBi, qualified EIRP:i16 in quarterdBm, profile:u16 (2),
aggregate calibration conducted peak:i16, native-response conducted peak:i16,
and 62 zero reserved bytes. Two 128-entry signed-i16 conducted upper-envelope
arrays follow, for paths A and B. `i16::MAX` denotes unmeasured curve entries;
all measured bounds, including both peaks, lie in [-512,256] quarterdBm.
Antenna gain lies in [0,128] quarterdBi. Version 1, missing response attestation,
unknown peaks and altered profiles are refused. No real measured artifact is
provided or inferred by the implementation.

The exact version 2 identity binds awake channel 1, legacy 20 MHz, software
1 Mbps TX-A/RX-AB, fresh DACK/IQK, no GAPK/DPD/power tracking, software CCMP/raw
RX, fixed source IGI `0x1c` and conservative adaptive EDCCA thresholds 40/33.
It also binds source `RRSR=0x1f`, selected CCK references, OFDM reference zero
and zero relative differences for all twelve legacy rates. Source RRSR
selection at 1 Mbps retains CCK rates and mandatory OFDM responses; this is
not a claim that hardware transmits only at the host TXD rate. The response
peak must bound every native control-response mode over the entire admitted
CCK index range and OFDM reference zero, including uncertainty and retained
environmental limits. The separate calibration peak bounds all calibration
emissions, including any path combination. Neither is derived from an index.

`prepare_radio` continues the same `PhyTablesPrepared` owner after a current
version 2 board grant. It poisons the owner before its first radio write or
await, configures TX-A/RX-AB and the actual channel 1 MAC/BB/RF registers,
programs qualified references, performs fresh ADC/DAC DC calibration and X2
checks, and applies the nineteen retained OTP trims with source erased-cell
semantics. Fresh DACK requires complete bounded sampling, stable samples,
actual hardware IQ-vector receipts and residual convergence. It preserves
separate per-path RF originals; Linux's `path*i+i` backup alias cannot overwrite
path A with path B. No vector-cache restore, reset or recalibration is claimed.
The fixed CCK profile keeps source low-rate DPD disabled and selects the source
no-GAPK/no-DPK branch; it does not claim broad PHY calibration coverage.

H2C packet DMA uses the original retained 128-entry ring and one additional
80-byte coherent command mapping allocated while BME is off. All command
payload/BD mutations and MMIO publications invoke current PCI authority.
Occupancy commits before any reusable copy; one command remains pending until
its exact bounded hardware head advances. Foreign, stale or out-of-range heads,
timeout and cancellation cannot unlock a buffer. Original GeneralInfo and
PHYDM packets precede IQK. DMA retirement proves command transport only:
IQK additionally requires a non-stale pre-submit report and the firmware's
actual `RPT_CIP=0xaa` completion within 300 ms. A host write never fabricates
that receipt.

Before `Calibrated`, the continuation requires a fresh RPWM/CPWM awake toggle,
invalidates all 32 source CAM entries with bounded command completion, disables
CR/SECCFG hardware crypto and default-key search, and selects native RX with
PHY metadata and trailing FCS. MAC TX/RX and IRQs remain disabled. On completion
it parks BME and seals the completed firmware beacon BD and packet descriptor
inside current PCI authority, clears its work trigger and disables the beacon
function. Only then can it transfer the sealed, retained calibration `Gate`
to the same native packet owner. `Calibrated` describes that exact parked radio;
it does not assert association, carrier, DHCP or hardware acceptance.

A checked radio adapter re-invokes retained calibration authority and samples
the current authenticated policy before each host radio write across awaits.
The native packet gate likewise rechecks that same calibration and current
policy; no enum state or copied gain alone grants TX. The explicit model policy
closure is isolated from the native authenticated database.

`station_control::Admission` shares a closed flag and publication lock with
the station/device owner. Every asynchronous control helper checks admission
after waits and serializes the final synchronous MMIO/mailbox publication with
close; no publication lock spans an await. Port 0 binds the sealed factory MAC,
actual BSSID, checked AID and managed link type. Source awake/keep-alive-disable,
fixed CCK1 RA, media-status and default-port commands use the original four-box
HMEBOX protocol. The cursor and pending identity remain in the native owner;
actual HMETFR consumption is required before reuse and never presented as an
applied-command acknowledgement. Close prevents later peer publications;
terminal disconnect may drain a previously published mailbox and send media-down
without reopening the data port. Initial MLME uses the source long-slot20
setting; short-slot9 is selected only after the successful association response.

`StationPreparation` borrows the exact retained owner's backend; it never moves
or reconstructs that owner. It prepares one additional bounded packet buffer
with BME off, reuses the original management/BE TX rings and 512 RX mappings,
verifies the sealed firmware beacon request and source PCI configuration, then
enables MAC/HCI DMA and BME last. Interrupts remain masked. Every synchronous
poll advances a bounded amount of native DMA/RX/CCX work, so kernel DHCP and
ARP/ND callbacks can make progress without a second executor task. Frame
callbacks use nonblocking owner/ring locks; stack receive callbacks run only
after those locks and publication guards have dropped.

The default native TX descriptors select fixed CCK1 and software security;
the distinct C22 N22L profile below can extend ordinary DATA only. A consumed TX
buffer proves transport retirement only. Authentication, association and EAPOL
security replies additionally require the matching fresh CCX identity and ACK,
the exact immutable MPDU bytes, and the receive-idle reuse fence; DMA retirement
alone cannot commit M4. RX descriptors must prove original legacy20 native MPDU
bytes without hardware decryption or decapsulation. Wi-Fi FCS is stripped
exactly once; C2H bytes are never treated as Wi-Fi payload. Current PCI authority,
the retained signed calibration cap and fresh authenticated policy are checked
before every native packet publication and progress step.

Scan admits channel1/2412 MHz only, bounded dwell and SSID filters.
Active scanning and driver-admitted extra probe IEs are implemented on that
channel (`src/rtw88/scan.rs`, `station.rs::scan_for`) as Linux's software
scan: this profile has no `FW_FEATURE_SCAN_OFFLOAD`, so `rtw_ops_hw_scan`
returns 1 and mac80211 sends one broadcast-DA/wildcard-BSSID Probe Request
per SSID (empty list = one wildcard; at most `RTW_SCAN_MAX_SSIDS`=4) with
SSID, all twelve legacy rates (Supported/Extended, no basic flags), DS
Parameter Set channel1, then the caller's IEs. `max_scan_ie_len` is
`IEEE80211_MAX_DATA_LEN` less those driver elements (2227 bytes), so every
probe fits the retained2304-byte TX MPDU. Caller IEs must be well formed and
may not repeat SSID/rates/DS; extra IEs on a passive scan are refused. Each
probe uses the ordinary management queue (QSEL18, W0 BMC, rate ID8/CCK1,
no CCX report) under the same current PCI/calibration/regulatory checks as
authentication, so a NO_IR or otherwise disallowed policy prevents the first
probe DMA. Probes are published one at a time and retired on DMA consumption
before the dwell; unicast Probe Responses feed the same shared observer as
beacons. Random-MAC scanning follows Linux v6.12: `main.c::rtw_register_hw`
sets `NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR` (`supports_scan_random_mac`),
and `rtw_core_scan_start` points port0 `REG_MACID` (0x610) at the
mac80211 `get_random_mask_addr` address (random bits outside the mask, base
bits inside; cfg80211 `nl80211_parse_random_mac` requires the mask to keep
the group bit of a unicast base). Every probe uses that SA, packet core
admits a broadcast Probe Request from exactly the current scan address,
and Probe Responses to it feed the observer. `rtw_core_scan_complete`
restores the own address and clears the packet scan address on every
exit. Passive requests transmit nothing and bind no address; association
always uses the own address. Evidence: `drivers/wireless/rtw88/narrow/scan`
(mask/variation/probe SA) and `drivers/wireless/rtw88/random_scan`
(actual DMA probe SA, 0x610 follows and is restored, joining afterwards
uses the own address); a mask clearing the group bit is refused.
6 GHz scanning stays refused. HT capability elements
are not added to probes. Native smokes: `scan_tests.rs` (exact preq bytes,
SSID/IE budget, malformed/unsupported requests, BMC/MGMT/no-report
descriptor) and `station_composition_tests.rs` (actual DMA probes, probe-
response-only BSS joined, NO_IR refusal without TX publication). The shared
association parser validates actual beacons, authentication and association
responses, including mandatory supported rates. Open and WPA2-PSK use that same
retained peer transition. WPA2 uses shared host RSNA and packet-key owners for
nonce, replay, CCMP and controlled-port admission; no hardware key-cache fallback
is available. Kernel Ethernet enqueue admits the sealed local source MAC,
bounded Ethernet-II frames and no checksum/TSO/VLAN offloads. It rechecks current
authority before CPU queue publication and native DMA checks independently.
Explicit channel/power changes outside the retained profile are refused.

The shell and station share one `Admission`. Activation, scan and association
future cancellation closes it terminally before releasing the retained owner.
Public disconnect reserves teardown under the publication lock and publishes
link-down before awaiting the lifecycle mutex. Closed workers retain native
cleanup access while that reservation exists: source NoLink/media-down precedes
packet stop. Dropping a cancelled reservation leaves admission closed and allows
the next worker to stop the retained packet owner. No disconnect or error
reopens the one-shot radio. Deauthentication, peer liveness/security deadline,
native failure and policy/cap revocation close the data port and carrier.
Temporary WPA2 rekey closure preserves established carrier while blocking
ordinary data. New frames and returned RX are suppressed after terminal close.
Hardware carrier publication changes only the carrier metadata, preserving
operator-controlled IFF_UP. It cannot invoke an administrative open/stop hook
while the retained owner or metadata lock is held.

One atomic lifecycle claim prevents concurrent/repeated reconstruction.
The exact inner owner is retained before its first DMA publication.
Timeout, access failure, failed readback, checksum error or cancellation
leaves a terminal owner; a new attempt returns `State` without allocation
or device access. Published mappings remain retained on every error and
Drop, including a failed parking sequence or revoked authority. A later
reset/removal implementation must establish device quiescence before
reclaiming them; this stage deliberately has no reclaim/retry path.

### RTL8821CE parked operating-power continuation

After the same owner's successful IQK, `rtl8821c_operating_power_request()`
exposes the immutable calibration/board/firmware/program digest and exact
MAC-bound `rtw88/rtw8821ce-power-v1-<mac>.bin` filename. The identity binds
channel1/20MHz, actual source RF-A TXAGC addresses, fresh RF42 conversion,
zero unused MCS lanes, source RRSR_INIT_2G=0x15f and closed packet gates.
Actual thermal samples gate admission independently; changing a valid sample
within a measured interval does not manufacture a different board identity.

The signed N21P v1 record is exactly160 bytes: magic0, version:u16 at4,
header-size:u16 at6=160, total-size:u32 at8=160, VID/DID at12/14,
identity[32] at16, MAC[6] at48, channel/bandwidth at54/55=1/20,
antenna upper bound:i16 quarter-dBi at56, board EIRP:i16 quarter-dBm at58,
complete operating-program conducted peak:i16 at60 and aggregate autonomous
response conducted peak:i16 at62, thermal min/max:u8 at64/65, `US` at66/67,
twelve explicit CCK/OFDM gain indices at68, twelve per-rate measured conducted
peaks:i16 at80, and zero reserved104..159. Indices must be0..63 and no higher
than the retained factory channel1 CCK/OFDM base. Original C21 RFE2/4 selects
pathB's2G factory record for physical RF-A; other admitted RFE uses pathA.
The OFDM signed nibble uses C21 txgi_factor1; erased/wrapped factory values
fail. These indices and peaks are actual external measurements over the whole
qualified board/antenna/supply/temperature range, never inferred factory dBm
or substituted C22 data. All peaks plus antenna gain must satisfy the board
ceiling, every overlapping installed host restriction and conservative20dBm ceiling.
The aggregate complete-program peak must also enclose every per-rate/response peak.

Missing, unsigned, foreign or unqualified assets leave the completed IQK owner
retryable before writes. Both actual signed source invocations enclose native
operations; installed policy is required without implicit reload. The active
attempt becomes terminal before access, triggers a source two-second RF42
conversion, checks actual thermal/IQK/RF08 state, writes and reads back three
packed legacy TXAGC words, zeroes the five unselected MCS words and programs
the exact response mask. Cooperative yields preserve ownership between words;
the outer attempt is bounded to three seconds. Cancellation, current-source or
policy loss, ignored writes and transport failure retain firmware/command DMA.

Success earns `Operating8821cPrepared` and historical
`rtl8821c_operating_power_info()`, with BME, MAC TX/RX, producers and IRQs still
closed. Sibling provisioning continues to this stage when the exact asset is
available. This is parked power preparation; the independent full awake grant
below is required before native packet/peer activation. Three composed native Rust
smokes cover exact words, BTG factory substitution, retry, per-rate/response/
thermal limits, partial I/O, cancellation and both source/device revocation.

### RTL8822CE separately qualified legacy12 DATA and WMM BE/TID0

`rtl8822c_legacy_wmm_request()` exposes metadata only after the retained C22
radio has completed. Its `C22LegacyWmmRequest` contains the exact recipe
SHA256, factory MAC and
`rtw88/rtw8822ce-legacy-wmm-v1-<12 lowercase MAC hex digits>.bin` filename.
The identity binds the original board identity, exact signed N22Cv2 digest,
both selected CCK references, original OFDM reference0/legacy differences0,
source response-mask function, native descriptor/rate policy, bounded EDCA
recipe, and software CCMP/raw QoS semantics. A different calibration, board,
gain selection or emitted program needs a different signed identity.

The optional signed128-byte little-endian **N22L** record is:

| Offset | Meaning |
|---|---|
|0..4|`N22L`|
|4..8|version1 and header length128 (u16 each)|
|8..12|total length128 (u32)|
|12..16|VID0x10ec, DID0xc822 (u16 each)|
|16..48|exact extended station recipe SHA256|
|48..54|exact factory MAC|
|54..56|channel1, width20MHz|
|56..60|signed antenna gain and qualified EIRP ceiling (i16 quarter-dB units)|
|60..64|signed measured full-program transient and automatic-response conducted peaks (i16 quarter-dBm each)|
|64..88|twelve signed worst-case DATA conducted peaks in IEEE order1,2,5.5,11,6,9,12,18,24,36,48,54Mbps|
|88..90|measured allowed-rate bitmap, bits0..11 only, including1Mbps|
|90|bit0 permits WMM BE/TID0; all other bits zero|
|91..128|zero reserved bytes|

Each enabled rate and both global peaks require actual measured values in
range−128..64dBm, antenna gain0..32dBi and a ceiling in the same signed power
range. Disabled-rate slots supply no authority. These are worst-case bounds
for the complete static awake operating envelope, including temperature;
there is no narrow-temperature or adaptive-compensation shortcut. The original
N22Cv2 source and its acknowledged gain/power ceiling remain current and
mandatory. All new peaks plus antenna gain must fit the minimum of its
current applied ceiling and N22L's ceiling. No real measurement is supplied.

Association looks up this optional record through trusted firmware authority
before changing hardware. Missing, malformed, unsigned, foreign, revoked or
currently denied N22L retains the original qualified CCK1 legacy path. A valid
extension requires the AP's basic rates to be measured. Only this C22 sealed
grant can attach to the retained native packet gate; C21 cannot obtain it.
After attachment, both signed source invocations and the current installed
host policy enclose actual register/CPU-DMA/doorbell/BME publications. Source
or observed policy loss then closes that owner permanently; reinstalling
policy cannot restore it. No live operation implicitly bootstraps policy.
The extension retains a statically base-only `ExtensionBase`: C22's
`CalibratedBase` contains the original calibration source/permission; the C21
arm retains its actual N21S source. Neither arm routes through an
extension-aware packet gate, and an already extended gate refuses extraction.
C21 still refuses extraction as a C22 `CalibratedBase`. Current source
enclosures therefore remain chip-specific and generic dispatch stays acyclic.

Shared `wireless::wmm` parses the original complete AP offer and the bound
successful association response. Only a valid offered Parameter IE and a
WMM-enabled N22L cause the driver to append its no-UAPSD Information IE to
the actual association frame. Caller WMM cannot replace this driver-owned IE.
The bound response must contain one valid Parameter IE; malformed, duplicate,
missing or BE-ACM parameters fail before a data port opens. Its actual set
count/UAPSD/AC rows are retained; response parameters may update the offer.
Only the response's common supported rates intersected with measured rates
become the new DATA bitmap, and every negotiated basic rate must remain in it.

Linux `mac80211.c::__rtw_conf_tx` maps canonical BE/BK/VI/VO to registers
`0x508/0x50c/0x504/0x500`. The driver encodes TXOP in32us units, ECW exponents
and AIFS=`10 + AIFSN * slot`, with slot20 initially and slot9 only after actual
AP capability intersection. BE is conservatively clamped to AIFSN≥3,
CWmin≥31, CWmax≥1023 and TXOP0. Other AC rows preserve the bounded response
facts but have no host producer. Unsupported AIFS/TXOP extents are rejected.
Every source register value is read back, with a cooperative cancellation
boundary between ACs; partial writes never admit QoS/data or release DMA.

The source RA mailbox uses actual negotiated legacy bits and rate-ID B8,
BG6 or G7, initRA1, power-training disabled,20MHz and no SGI/HT/VHT/LDPC.
Consumption is transport evidence, never an invented applied firmware ACK.
The highest permitted IEEE bit rate is selected for ordinary DATA; IEEE
descriptor numbering is not monotone because11Mbps exceeds6/9Mbps. Source
`rtw_phy_get_rrsr_mask(selected_rate) & RRSR_INIT_2G` programs and reads back
`0x1f/0x5f/0x15f`; N22L's distinct automatic-response peak must cover it.
Both selected CCK references, both OFDM references0, all three zero legacy
difference words and disabled hardware crypto are checked through the exact
native owner before/after the extended programming. New RF tables or gain
measurements are never inferred from descriptor rate IDs.

Only then does the same packet core install its qualified DATA profile.
TXDESC48 uses source fixed-rate/no-fallback fields, the actual legacy rate-ID,
BE QSEL0 and manual sequence. It admits raw QoS26/TID0 only when negotiated;
other TIDs, A-MSDU, AMPDU, hardware sequence, SGI and wider PHY modes stay
closed. QoS is formed before shared host CCMP, so its nonce/AAD/MIC match the
actual26-byte header. EAPOL/security and management stay legacy24/CCK1 and
retain exact consumed-DMA+CCX+MPDU/M4 receipt requirements. RX ordinary data
is bound to the permitted response-rate bitmap and original legacy20 native
descriptor; raw QoS requires TID0/control0 and negotiated WMM before delivery.

A qualified non-WMM AP keeps legacy24 headers/DCF and can use measured richer
DATA rates. An unqualified WMM AP retains the original legacy CCK1 connection.
The same registered shell, firmware owner, original PCI rings, packet buffer,
RSNA/CCMP and controlled-port lifecycle remain retained. Safe shutdown uses
current PCI authority even after RF-source revocation. Host QoS/rate admission
retires before any uncertain native cleanup; no reset/reconstruction occurs.

Thirteen new native Rust smokes cover distinct qualification/fallback, all twelve
literal descriptor rates and source EDCA units, response-updated WMM and
response-narrowed rates, Open/WPA2 real kernel DHCP and exact bidirectional IP,
non-WMM legacy headers, each partial EDCA wait's cancellation/source/policy,
malformed/missing response or gain/register loss, held/modified M4 and late
receipts, and descriptor/RX revocation before publication. These are native
software models; actual firmware/RF acceptance and signed full-envelope assets
remain external. N22L alone does not grant HT; the distinct HT profile below
extends it. Full AC/TID scheduling, broader HT/VHT, BA/reordering, other channels,
dynamic RF tracking, recovery and PM remain work.

Final host publication uses a retained private `Publication` scope, shared by
the unchanged C21/C22 legacy and extended C22 paths. It retains the exact chip's
signed-source gate and native PCI authority/device; each invocation validates
the live sources/current policy and actual BME/MEM/INTX state before enclosing
the carrier or frame publication. The station uses it after the last native
RX-idle read, before M4 key admission, established state and releasing received
Ethernet. The interface independently uses it for activation, post-await
carrier, TX/RX ring publication after allocation and each final network-stack
callback. The stack callback retains no device/ring/admission locks, so an
ARP/ND reply can reenter enqueue safely. Native read success and earlier
qualification snapshots cannot authorize these later publications. Two exact
native-idle hooks revoke either signed source or current policy only after
the final descriptor/register observation; regressions check suppressed RX
frames/carrier, terminal reinstall denial and stable retained DMA.
An enqueue regression additionally revokes source/current policy after the
publication scope is captured but before invocation. Outer authority/PCI
failure maps to terminal Access; inner host ring-full remains retryable and
can resume after real native progress.

### RTL8821CE full awake radio and retained native station

`rtl8821c_station_request()` is available after the same owner's N21P success.
It returns the exact recipe identity, MAC and
`rtw88/rtw8821ce-station-v1-<12 lowercase MAC hex digits>.bin` filename.
The SHA256 identity binds the immutable N21P program, all12 selected gain
indices, C21 channel/RFE/swing retention, fresh thermal conversion, literal
CAM/wake/response programming, native PCI formats/rings and bounded port0
station recipe. It changes the response mask from parked `0x15f` to the
initial station's `0x1f`; old IQK/parked records never authorize that sequence.

The separate signed128-byte little-endian **N21S** record is:

| Offset | Meaning |
|---|---|
|0..4|`N21S`|
|4..8|version1, header length128 (u16 each)|
|8..12|total length128 (u32)|
|12..16|VID0x10ec, DID0xc821 (u16 each)|
|16..48|exact awake-station recipe SHA256|
|48..54|exact unicast factory MAC|
|54..56|channel1, width20MHz|
|56..60|signed antenna gain, qualified EIRP ceiling (i16 quarter-dB units)|
|60..66|signed measured ordinary-packet, automatic-response and complete awake-program transient conducted peaks (i16 quarter-dBm each)|
|66..68|raw thermal minimum0/maximum63; full static awake envelope is mandatory|
|68..70|trusted profile country `US`|
|70..128|zero reserved bytes|

The source must have a verified signer and current blob authority. The actual
N21Q, N21P and N21S capability invocations nest around every native radio
operation, packet-memory access, MMIO publication and PCI BME enabling. The
current installed host domain must cover the entire2402..2422MHz span with
at least20MHz, no restrictions except NO_P2P and countryUS. All intersecting
rules contribute their minimum power ceiling; all three measured peaks plus
antenna gain must fit that ceiling, signed ceiling and the initial20dBm board
profile. Live checks read current policy without implicitly reinstalling it.
N21Q/N21P limits and current source authority remain mandatory too. Missing,
foreign, unsigned, revoked or policy-denied N21S leaves the parked checkpoint
retryable without register writes. No real measurement asset is supplied.
This initial awake profile has no continuous conversion watchdog, so N21S
must qualify every possible six-bit meter value0..63. A narrow N21S thermal
interval is rejected even when the initial reading lies within it. Thus a
one-time sample cannot authorize an indefinitely awake narrow-temperature
program. The earlier N21Q/N21P intervals still constrain the actual preparation
samples; N21S must independently bound all subsequent static-gain awake RF.

The C21-specific continuation checks its retained RF18 channel, RFE/swing,
original12 TXAGC values and zeroed unused HT/VHT words, RF08 cleared after
genuine IQK and zero failed/reload status. It triggers a fresh RF42 conversion
and preserves the source two-second wait, checks the actual meter against all
three signed intervals, invalidates all32 source CAM slots with bounded busy
receipts, disables hardware encryption/decryption and retains native raw RX.
The source RPWM3d9/CPWM3da handshake requires a fresh device toggle. There is
no C22 DACK/trim/RF callback substitution or inferred RF-mode receipt. This
entire attempt has a four-second deadline. Failure/cancellation after its
first access is terminal and retains the exact owner and published mappings.

The original completed beacon descriptor is disarmed through the retained
reserved-page owner only under actual parked PCI authority; C21 is already
parked after IQK/N21P, so it does not reuse C22's active-command parking
transition. Success earns `Radio8821cPrepared` and historical
`rtl8821c_station_radio_info()`. This copyable receipt itself grants no TX.
Only its sealed exact-chip grant can admit the common PCI packet backend.

Original `rtw8821c.c`/`rtw8822c.c` chip-info and `pci.c` share48-byte TXDESC,
16-byte TXBD,24-byte RXDESC and8-byte RXBD formats; C21's checksum callback
belongs to USB, not this PCI path. The same retained seven TX rings and512 RX
buffers continue into the MGMT128/BE256 packet owner, using consumed indices
plus actual CCX for security/management delivery. Common `fw.c` port0
ACTIVE/media/RA/default-port commands and `main.c`/`mac80211.c` MAC/BSSID/AID/
conservative DCF semantics are reused. C21 RF, EFUSE and qualification remain
distinct. The qualified shell then uses shared MLME/RSNA/host CCMP and exposes
Open/WPA2, passive ch1/20, CCK1 ordinary TX and receive-only legacy rates;
no QoS, aggregation or HT/VHT admission is inferred by N21S alone.

Seven new native Rust smokes compose the actual reserved-DMA firmware/MAC/PHY/
IQK/N21P owner through radio and packet/station. They cover literal CAM/wake/
gain/mailbox/DCF receipts, retry without writes, receipt failures, pending
thermal cancellation and all three source/policy losses, real descriptor
Open/WPA2 kernel DHCP and exact bidirectional IP, and held M4 cancellation/
late receipt/terminal reinstall and actual descriptor-to-doorbell source/policy
revocation. These are inert software models. Physical
RF acceptance, real signed measured assets and qualification over the full
permitted awake operating/temperature envelope remain external gates; dynamic
power tracking and thermal compensation are not claimed.

### RTL8821CE separately qualified legacy12 DATA and WMM BE/TID0

`rtl8821c_legacy_wmm_request()` returns `C21LegacyWmmRequest` after genuine
same-owner N21S radio preparation. Its MAC-bound
`rtw88/rtw8821ce-legacy-wmm-v1-<mac>.bin` name and SHA256 identify a distinct
C21 program: the exact retained N21S recipe and signed-record digest, all12
actual N21P TXAGC indices, RF-A channel/IQK state, source EDCA/RA/RRSR, native
legacy12 fixed DATA selection and raw QoS26/host CCMP. This metadata grants no
RF authority and cannot request a C22 qualification.

The signed128-byte **N21L** record uses the N22L field layout documented above,
with magic `N21L`, DID0xc821 and this exact C21 identity. Its enabled-rate
bitmap (including1Mbps), independently measured12 DATA peaks, complete-program
transient and automatic-response peaks, antenna gain, ceiling and optional
WMM flag apply to the complete static awake raw thermal range0..63. A narrow
initial sample cannot replace that full measured envelope. No actual measured
asset is supplied. The original N21Q/N21P/N21S sources stay mandatory/current;
every actual radio/control/packet/host publication nests their invocations with
the new N21L capability. All peaks plus antenna gain fit the new signed ceiling,
current N21S ceiling,20dBm profile and every overlapping host-policy minimum.
Missing, foreign-chip, malformed, unsigned, revoked or denied N21L preserves
the original N21S CCK1 legacy profile before any changed hardware operation.
Once attached, observed source/policy loss is terminal, including after native
RX/CCX read and before final carrier/frame publication; reinstall cannot reopen.

C21's own `rtw8821c_set_tx_power_index_by_rate` packs the measured indices in
RF-A `0x1d00/0x1d04/0x1d08`; the five unused HT/VHT words remain zero. This
continuation reads all eight actual words, RF18 ch1/20, RF08 cleared after IQK,
zero failed/reload status and disabled hardware crypto before/after extended
control programming. It never reads or substitutes C22's `0x18a0/0x41a0`
reference gains or `0x3a00` relative-difference power format. Source C21 chip
info independently declares matching48/16/24/8 PCI descriptors and
`old_datarate_fb_limit=false`; its RA and EDCA port0 ABI matches the reviewed
common path. No new RF/calibration completion or thermal sample is inferred.

Only a strict offered WMM Parameter IE, N21L WMM permission and the actual
bound association response admit BE/TID0. The same response's common measured
legacy rates drive RA/rate-ID and the highest IEEE bit rate for ordinary DATA.
Source EDCA readbacks, conservative BE limits and the source response mask
precede native profile admission. Management/EAPOL remain legacy24/CCK1; QoS26
is formed before host CCMP, unsupported TIDs/A-MSDUs/AMPDUs and HT/VHT remain
closed. A qualified non-WMM peer retains legacy headers; an unqualified WMM
peer keeps the prior CCK1 connection. Original firmware/beacon/command and
packet DMA owners remain retained without reset, replay or ring replacement.

Eight new native Rust smokes compose the actual C21 reserved-DMA firmware,
inactive MAC/PHY, IQK, parked-power, awake and station owner through this path.
They check exact-chip asset refusal/retry and legacy fallback, Open/WPA2 real
kernel DHCP and bidirectional IP, actual source TXAGC/EDCA/RA/RRSR/descriptors,
response narrowing and non-WMM headers, bad QoS/MIC/replay, partial EDCA
cancellation and all four signed-source/policy losses, missing/duplicate/ACM
responses or native register/RF/IQK loss, held/modified/late M4 and actual
descriptor/final-RX publication revocation. Firmware bounce bytes and native
packet allocation identity stay unchanged; ambiguous exits retain DMA.
These are inert software models, not physical RF acceptance. Real full-envelope
signed assets, HT/VHT widths/aggregation, other bands/channels, full AC/TID (now N2xQ),
dynamic tracking/coexistence, recovery and PM remain explicit gates/work.


### C21/C22 separately qualified HT20/one-stream and SGI20 station

The same retained RTL8821CE and RTL8822CE station owners can now select
channel1/20MHz HT MCS0..7 with long GI and optionally SGI20. Native source
hardware facts, the exact AP offer/request/response, a distinct signed HT
emission record and all preceding current grants are independent gates.
Existing N21S/N22C records retain their1Mbps profile; N21L/N22L alone retain
legacy12/WMM. An absent, malformed or currently denied optional HT input
preserves that existing legacy connection before writes. Once attached,
observed source/policy loss or partial programming is terminal.

`Rtw88Device::ht20_request().await -> Ht20Request` supplies exact identity,
MAC and filename metadata for external measurement. It requires the matching
current L qualification. The names are
`rtw88/rtw8821ce-ht20-v1-<mac>.bin` and
`rtw88/rtw8822ce-ht20-v1-<mac>.bin`. The hash binds the actual chip-specific
L recipe and complete signed-record digest, already bound factory/cut/RFE/
firmware/calibration identity, genuine boot C2H hardware-feature report,
source factory ceiling and retained gain program, native gain/control/
descriptor/receive/ADDBA program below. It grants no measured limit or RF
permission. No real HT measurement asset is supplied.

The signed little-endian record is exactly192 bytes:

| Offset | Field |
|---|---|
|0..4|`N21H` or `N22H`, matching actual C21/C22 |
|4..8|version1:u16, header192:u16|
|8..12|total192:u32|
|12..16|VID0x10ec and exact DID0xc821/0xc822|
|16..48|request identity|
|48..54|exact factory MAC|
|54..56|channel1, width20|
|56..60|antenna upper bound and board EIRP ceiling:i16 quarter-dB units|
|60..64|whole-program transient peak and automatic-response peak:i16 quarter-dBm|
|64..66|raw thermal minimum0/maximum63: full static envelope|
|66..68|nonempty MCS0..7 bitmap and flags bit0 SGI20 permission; other bits0|
|68..76|eight explicit MCS gain indices|
|76..92|eight long-GI conducted peaks:i16 quarter-dBm|
|92..108|eight SGI20 conducted peaks:i16 quarter-dBm|
|108..132|twelve retained legacy-rate conducted peaks:i16 quarter-dBm|
|132..192|reserved zero|

The complete transition peak must enclose all other peak fields. All peaks
plus antenna gain must satisfy this record's ceiling, every preceding signed
source ceiling and all overlapping current host rules. Unknown, indoor,
NO_IR/DFS and too-narrow restrictions fail closed. Measurements cover the
entire static raw0..63 thermal range and board/antenna/supply/BT states;
one meter sample or a factory index is never a power measurement. Current
C21 Q/P/S/L/H and C22 calibration/L/H capability invocations enclose the actual
native operation, carrier, IPC and unlocked stack callback. The typed base
grant graph remains acyclic.

C21 retains its original12 absolute legacy indices and uses exact source
RF-A `1d0c/1d10` for MCS0..7, keeping unused HT/VHT words zero. Its factory
HT20 upper bound uses the original high signed nibble of the selected power
record, BW40 group0 base and txgi_factor1, with RFE2/4's pathB-to-RF-A
substitution. Erased/wrapped factory data never manufactures a ceiling.
Fresh source RF42 conversion, existing Q/P/S thermal bounds and actual
RF18/RF08/IQK/crypto readbacks remain necessary.

C22 preserves TX-A/RX-AB, original CCK references and legacy effective gains.
It programs both OFDM reference fields `18e8/41e8` from the selected MCS7
index, then source signed7-bit differences at `3a00..3a3c`; MCS0..7 occupy
`3a0c/3a10`. Both physical paths use the same explicit bounded indices;
their factory HT20 ceilings use txgi_factor2 and are intersected. Equal
references preserve existing effective legacy OFDM index0; unselected
rates have effective index0. Unrepresentable signed differences are refused.
This is the source reference/difference format, never C21's absolute format.
Every word/reference is read back before native packet-profile admission.
No new DPK/GAPK completion, tracking or measured peak is inferred.

The shared opt-in PHY observer and JoinPlan retain original mandatory HT
membership selectors and emit an owned HT request. Caller PHY/WMM elements
remain rejected. Local RX supports MCS0..7, SGI20, default3839-byte A-MSDU,
8KiB A-MPDU capability factor and source2us density; local TX uses the
measured MCS/GI subset. Width remains20MHz, SMPS is disabled and no
LDPC/STBC/greenfield/HT-control/VHT or extra stream is advertised.
The actual bound response may narrow TX MCS/GI, while local RX bounds remain
independent of the AP's receive bitmap. Unsupported HT protection modes,
missing/duplicate elements, wrong primary and unsupported mandatory basic
MCS cannot partially commit a new peer.
The published per-band capability body is cached only after retained native
station activation and reports this factual one-stream HT20/default3839-byte
implementation on2400MHz; it grants no measured power or association right.
The mandatory hardware TX/RX MCS0..7 body remains intact while the typed
TX selection separately restricts the actual measured/native transmit set.

Native EDCA retains response WMM and conservative BE/TID0 policy. Source
H2C40 uses BGN20_1SS RAID3 (or GN1SS5 for the corresponding rate set),
full HT mask bits12..19, BW20, SGI bit23 only when negotiated/qualified,
PT disabled and no LDPC/VHT. DATA uses actual fixed descriptor codes12..19
and W5 SGI bit4 with fallback disabled; management/EAPOL stay1Mbps/raw24.
AGG_EN and aggregate count remain zero. The native RX parser admits only
MCS0..7/BW20 under the attached H profile, preserves original ciphertext/
IV/MIC/FCS semantics and refuses hardware plaintext. Ordinary RX TIDs use
separate shared replay state; host TX remains BE/TID0.

The complete original RAW QoS A-MSDU is admitted only at native HT rates,
under the actual AP/receiver/header/profile and an already-open port.
Protected input passes through `Security::receive_amsdu` once, with bounded
whole-aggregate authentication, syntax and per-TID/key PN commit before any
subframe publication. Open input uses the same bounded whole-body decoder.
The mandatory default3839-byte body fits the original retained RX mapping.
Malformed later subframes or MIC/replay failure publish no prefix and do not
consume a valid aggregate's PN. Captured closed-port data is discarded
before crypto; ReplyReady clears queued/decoded originals so a late M4 or
rekey receipt cannot retrospectively authorize it.

The retained packet Core selects its PHY decoder from the actual PCI chip,
never from AP bytes. After validated RXD bounds it reads exactly one32-byte
PHY-status record at `RX_DESC+shift`, before the driver-info/payload boundary.
The four driver-info units are eight-byte blocks, not four status pages.
C21 page1 uses HT_RXSC at word1[15:12], with zero falling back to RF_MODE
at word3[29:28]; source codes1..8 mean20MHz,9..12 mean40 and13..15 mean80.
C21 has no channel field and never interprets C22's channel byte. C22 page1
uses the same RXSC map, zero falls back to this retained programmed20MHz
owner, and word1[23:16] must report channel1. Both chips bind CCK to page0
and OFDM/HT to page1; C22 page0 also checks its actual channel field. Unknown
pages, reserved C21 fallback mode, wide/foreign reported facts, duplicate
status extents and truncated native storage cannot reach CCMP/PN. No PHY
record is synthesized when PHYST is absent: source-valid RXD rate/BW0 and
the retained channel owner remain the factual inputs, and PHY evidence is
`None`. No first-only PPDU context or cross-MPDU PHY carry is introduced.

Native ReplyReady, exact terminal security reply and local close advance a
monotone receive epoch. Publication tokens retain that exact generation;
changed generations retire queued RX IPC too. Before each unlocked stack
callback the driver refreshes the actual retained owner/current controlled
port, then drops owner/ring/admission locks and rechecks the token inside
current source/PCI invocation. An old batch is discarded after a callback
drives rekey, including a fully reopened new epoch, without closing that
legitimate current station. Receive authorization is independent of ordinary
TX credit, so a reentrant held ordinary packet does not masquerade as key
closure or invalidate the rest of the received aggregate.

This slice owns a genuine native ADDBA-decline path rather than claiming a
BA agreement from an HT offer. A bound, complete immediate single-TID AP
request produces Category3 response status37 through the retained management
DMA slot and actual CCX receipt/current authority. Foreign/malformed requests
produce no transmission; held, cancelled or uncertain native management
ownership remains pinned. This remains the behavior under H alone. The
separately qualified recipient extension below adds RX BA; the distinct
originator extension then adds bounded native TX A-MPDU. Shared Reorder alone never
supplies Realtek BA negotiation, native receipt or descriptor authority.

Twenty-three new native smokes (eleven per chip plus a literal source PHY
decoder/offset case) compose exact retained owners:
Open/WPA2 long/short-GI DHCP/IP; every MCS and independent RX bounds; real
3839-byte authenticated A-MSDU/replay; distinct asset retry/legacy fallback;
original mandatory selectors and response narrowing/refusal; lost native
gain writes; actual ADDBA decline/held receipt; held/altered/cancelled M4
across all signed sources; and descriptor/native-RX/current-policy publication
fences with retained DMA. Synthetic records remain private fixture inputs.
The added native PHY cases cover original DATA/A-MSDU bad-PHY-to-same-PN
retry, missing/duplicate/truncated/shifted records and distinct chip fallback
semantics. Actual two-subframe callback regressions cover held/reopened group
rekey and held ordinary TX, independently checking the actual group reply MIC.
Physical signed assets, EVM/RF/silicon acceptance and external interoperability
are deployment/acceptance gates, not outcomes of these software tests.

### C21/C22 separately qualified recipient RX Block Ack

`Rtw88Device::rx_ba_request().await -> RxBaRequest` returns exact-H measurement
metadata, not a radio grant. The names are
`rtw88/rtw8821ce-rx-ba-v1-<mac>.bin` and
`rtw88/rtw8822ce-rx-ba-v1-<mac>.bin`. Each identity binds the retained chip's
H recipe, complete signed H-record SHA256, factory MAC, original RAW receive
contract, explicit-SSN BA protocol/control/receipt program and source readbacks.
Production opens authenticated signed firmware-registry inputs; no real measured
R asset is supplied. Private synthetic records are fixture inputs only.

The signed little-endian record is exactly128 bytes:

|Offset|Field|
|---|---|
|0..4|`N21R`/`N22R`, exact C21/C22|
|4..8|version1:u16, header128:u16|
|8..12|total128:u32|
|12..16|VID0x10ec, exact DID0xc821/0xc822|
|16..48|RX BA request identity|
|48..54|exact factory MAC|
|54..56|channel1, width20|
|56..60|antenna upper bound and R EIRP ceiling:i16 quarter-dB units|
|60..66|whole transition, autonomous compressed-BA response and management peaks:i16 quarter-dBm|
|66..68|full raw thermal envelope0..63|
|68..70|maximum window1..64; nonzero allowed TID0..7 bitmap|
|70..128|reserved zero|

Every peak plus antenna must meet the R ceiling, preceding H/source ceiling
and current overlapping host rules. The transition peak encloses both response
peaks. Measurements must cover success/DELBA, automatic BA and corresponding
traffic/duty/supply/antenna/BT states over the full static thermal range. H's
decline/no-TX-BA program is never reinterpreted as this changed emission program.
The R grant retains that exact H owner; its actual capability invocation wraps
native operations and final host publication through the existing acyclic
grant graph. Missing/malformed/unqualified optional R inputs remain retryable
before writes and preserve H's native status37 decline/non-BA connection.
Observed loss of an attached R or preceding source/policy is terminal.

The source `rtw_ops_ampdu_action` RX_START/RX_STOP operations perform no
per-session register/H2C program. This implementation does not invent a BA
CAM or applied firmware acknowledgement. Before success it checks retained
HT gain/crypto state, source RAW/FCS/PHY/RCR flags without BASSN/header conversion,
each chip's original control filter, BAR retry setting and C22-only BA-parser/
ACK-type readbacks. C21's no-channel PHY page and C22's reported channel/width
rules remain unchanged. The retained filter is `RXFLTMAP1=0xffff` on both:
C21's initial `mac_init` value0x0fff is overwritten by its later source MAC
table's `0x6a2=0xff,0x6a3=0xff`. R performs no new filter write. These exact
post-table facts are included in R's request identity. Automatic SIFS BA generation and over-air behavior
remain physical/firmware acceptance work.

Only the current bound, established HT/WMM peer can request a recipient
agreement. An exact33-byte immediate-policy request carries the actual SSN,
dialog, TID0..7, timeout and window; zero window means64, and the signed maximum
may narrow it. This profile requires request A-MSDU bit1 and emits bound
response bit1: native RX does not expose reliable aggregate-membership facts,
so admitting a no-A-MSDU agreement would make a mandatory standalone original
indistinguishable from an excluded in-A-MPDU original. Requests without that
bit retain status37 and standalone3839 reception. No delayed/multi-TID BA,
TID8..15 session, fragmentation or firmware-deaggregated piece is admitted.

Each TID has one bounded window and at most one pending proposal. Same-dialog
identical retries preserve existing ordering; changed parameters cannot reset
the active window using the same dialog. A different proposal retires old
buffered ownership before success. The actual success response uses retained
management DMA and an immutable-body/native-index/matching-positive-CCX receipt.
Only an additional genuine RX-idle observation can activate its host window.
After real native publication, a bounded opaque prefix (at most that window)
may be staged against the exact pending request, peer/TID/SSN and still-open
controlled-port/key/receive epoch. The AP can legitimately receive success
before the host observes CCX. This prefix is neither authenticated nor
delivered until the exact success ACK plus idle; capture ages are retained
when originals enter reordering. Pre-proposal, unsent-proposal and closed-port
captures cannot acquire that grant retrospectively. Failure, cancel, DELBA or
an epoch change discards the entire pending prefix. A peer originator DELBA
can cancel a held proposal before its receipt. Unsent success controls and
same-batch captured requests are removed before publication; a submitted
control instead retains native ownership/receipt drainage without activation.
Selection alone never marks a control submitted. Uncertainty/cancel/negative or
altered receipt closes admission and retains possibly published DMA.

The host window is explicitly seeded with the on-air SSN using shared
`Reorder::advance`; unknown-SSN offload auto-sequence is not used. Complete
pre-SSN originals before the BA stream starts follow source semantics through
the actual key/PN owner without replacing that negotiated head. Complete
original unicast QoS MPDUs are routed by the current peer/TID, staged opaquely
and sequence-ordered before shared CCMP/per-TID replay or whole A-MSDU decode.
Native metadata, original header and negotiated profile must agree before
staging. The entire3839-byte body, IV and MIC stay intact; no prefix, partial
firmware piece or cross-TID/key carry is accepted. Normal-ACK QoS can belong
to BA; explicit BlockAck-policy QoS needs that current ordered session.
Explicit BlockAck A-MSDU uses the additive shared security opt-in only for a
reordered original with a current live recipient session; normal-ACK standalone
input keeps the stricter existing API. The original header is never normalized.
An ordinary output batch also leaves room for one complete maximum-subframe
original before any authenticated subframes are handed to publication.

Genuine compressed single-TID20-byte BARs are admitted through a separate
native control envelope and bound RA/TA/reserved/fragment/SSN checks. They
advance only the matching active window. Hole expiry runs at100ms even when
RX is idle; negotiated nonzero inactivity is separately measured in1024us
TUs. Timeout zero creates no inactivity timer. Inactivity retires host
admission before a native30-byte recipient DELBA/CCX; a peer's recipient
DELBA cannot tear down an RX session. ReplyReady, actual terminal key receipt,
peer loss, local close and current-source loss discard all buffered originals,
proposals and queued output under the existing receive/publication epochs.
An exact original plaintext unicast EAPOL from the bound authenticator remains
private protocol input if M3 was copied before the terminal M2 receipt retires
the data epoch. It still requires the actual shared Supplicant phase/MIC/replay
checks; captured data admission remains false and no DATA/BA/publication right
is inferred. Ordinary and aggregated old/closed captures remain denied.
CPU staging can be dropped; no such transition reclaims native DMA without
terminal ownership. Under R without the separate T extension, TX AGG_EN/count
stay zero and host TX stays BE/TID0.

Twenty-two added native smokes are validated: ten per chip plus literal protocol
and native separate-grant/CCX cases. They cover Open/WPA2 real DHCP through
out-of-order native replies and exact IP; explicit SSN/wrap/windows/BAR/100ms/
TU inactivity; original3839 A-MSDU, bad PHY/MIC-to-same-PN retry, independent
TID replay and many-subframe admission; held success/peer DELBA/old-capture;
signed asset refusal/retry/H fallback; every preceding source, R/policy loss,
cancel/uncertain payload and retained DMA; and a genuine held group-key reply
retiring an old window. They passed the coordinated native software suites.
Two additional native reply-epoch regressions, one per chip, inject a real
M3 and protected DATA before M2 CCX, require the actual held M4 continuation,
and then retry that identical DATA/PN only after the genuine M4 receipt.

### C21/C22 separately qualified originator TX Block Ack

`Rtw88Device::tx_ba_request().await -> Result<TxBaRequest, FirmwareError>`
returns the exact current request identity, station MAC and expected registry
filename. It grants no radio authority. `tx_ba_power` loads a separately
signed192-byte N21T/N22T record through the actual firmware registry/capability
owner. T retains an acyclic concrete H base, or R over that exact H; its identity
binds the complete H record and, when attached, the complete R record/digest.
An H-only T asset cannot authorize a later R automatic-response program.
The base gains, previous R peaks and all T peaks must each fit the minimum of
the current host/channel ceiling, all preceding grants and T's own ceiling.
Every real publication invokes the current T/base/firmware/PCI authority;
retained bytes or an earlier valid capability cannot substitute for it.

|Bytes|T record field|
|---|---|
|0..4|`N21T`/`N22T`, exact native chip|
|4..12|version1, header192, total192 (little endian)|
|12..16|VID10ec and exact DIDc821/c822|
|16..48|exact H or R-over-H request identity|
|48..56|station MAC, channel1, width20|
|56..60|antenna gain and maximum EIRP:i16 quarter-dBm|
|60..68|complete transition, automatic response, control and entire retry/burst conducted peaks:i16|
|68..72|full static thermal range0..63, maximum batch2..4, maximum peer window1..64|
|72..76|maximum native aggregate bytes1560..8191 and conservative airtime2500..4000us:u16|
|76..108|eight LGI and eight SGI conducted MCS peaks:i16|
|108..192|reserved zero|

This record's measurement contract includes the actual retry/burst duty,
transients, supply/antenna/coexistence envelope and native automatic responses.
It is an external exact-board qualification, not an inference from single-MPDU
H measurements. No measured real-board T asset is provided. Missing, unsigned,
malformed or restricted optional T input before binding leaves the existing
H/R nonaggregate connection unchanged. Once T is attached, observed loss is
terminal even if its source or policy is subsequently reinstalled.

Source `mac80211.c::rtw_ops_ampdu_action` TX_START is immediate and TX_OPERATIONAL
sets host per-queue eligibility; it has no per-session firmware ACK command.
This implementation instead owns the genuine on-air33-byte immediate TID0
ADDBA request, actual retained management DMA and requested matching CCX,
bound peer/dialog/status/TID/window/timeout response, actual RX idle and MAC
quiet before enabling native AGG_EN. The SSN is sampled from the actual next
per-TID producer before crypto: shared `Security::next_qos_sequence(0)` for
WPA2 or a separate retained Open QoS counter. Non-QoS EAPOL/management use a
different counter; no protected header is rewritten and no SSN is invented.
Fresh key continuations use a fresh dialog, preserving the per-TID sequence.
Wrong, refused or timed-out peer responses retain nonaggregate H data only
after submitted control ownership drains and native DELBA closes uncertainty.

Before that dialog, T programs and reads back the exact source
`coex.c::rtw_coex_limited_tx` retry value `RETRY_LIMIT(0x042a)=0x0808` and
`AMPDU_MAX_TIME_V1(0x0455)=0x20`. Fixed native MCS/GI and disabled fallback
remain from H. This is not the entire Bluetooth coexistence state machine.
The separate R BAR/RA aggregate limit `0x04ce=0x0801` is unchanged and still
checked by R. These distinct addresses and complete T-over-R emission recipe
allow the recipient and originator owners to coexist without relaxing either
grant's readbacks. T alone retains H's recipient refusal.

The native packet Core preallocates four independent coherent32-bit-addressed
TXD/body buffers while the device is parked, in addition to its original
control/single-packet allocation. It publishes at most four immutable original
QoS26 TID0 DATA MPDUs through separate actual BE descriptors and one final WP
doorbell. Source `tx.c` permits AMPDU and REQ_TX_STATUS independently: W2 has
AGG_EN bit12, SPERPT bit19 and peer density[22:20]; W3 MAX_AGG_NUM=3 uses the
mandatory8191-byte/factor0 ceiling. No USB DMA aggregation field, TX A-MSDU,
protected-header rewrite or invented firmware BA bitmap is used. Byte/airtime
admission includes hardware FCS, delimiter, padding, HT service/tail symbols,
mixed preamble and a conservative density allowance before consuming PN/SN.
The actual current T count/byte/airtime limits and peer window bound each batch.

Each original requires both the actual consumed PCI prefix and its own
matching positive native CCX; out-of-order CCX cannot reorder software receipts.
Receipts read the exact retained DMA bodies, not saved host copies. A new
burst, key publication or control transfer additionally waits for source
`mac.c::__rtw_mac_flush_prio_queue`'s16-bit reserved/available equality on
the actual BE and management priority FIFOs selected by `TXDMA_PQ_MAP`.
The exact C21/C22 queue geometry is independently checked. PCI consumption,
CCX or ring emptiness alone is insufficient. Invalid counters, changed
mapping, negative/duplicate reports or a bounded1s drain timeout close and
retain the native allocations. After an acknowledged burst and genuine MAC
quiet, an actual20-byte compressed BAR at the producer's current next SSN
uses retained native control DMA and CCX. No returned bitmap is treated as
a fabricated radio receipt; native MAC retry/status remain authoritative.

Peer recipient DELBA and negotiated nonzero TU inactivity retire host TX
eligibility before more DATA. Local key/close/current-source transitions
retire active TX BA, drain submitted ownership, and serialize a native
originator DELBA as appropriate. Security's actual controlled-port and current
key/receive epochs remain authoritative independently of ordinary TX credits.
All earlier RX publication/callback epoch fences remain in force. Partial BD
publication, cancellation, corrupt payload or uncertain receipt pins every
possibly visible buffer; no reset/reclamation proof is inferred.

Twenty added native smokes are validated: eight per chip, three native packet
Core cases and one literal protocol/receipt case. They exercise Open/WPA2 real
DHCP/IP, actual four-buffer descriptors and ordered receipts, H/R/T identity
and power intersections, invalid assets/H fallback, real SSN/response/refusal/
TU timeout, held request CCX/cancel, FIFO/source/policy loss, partial-BD
revocation, peer DELBA and genuine group-key reply/drain/reopen. Combined T/R
cases preserve `0x04ce=0x0801` while checking T's separate program and receiving
opaque reordered originals through real CCMP/PN. Together with the two
cross-reply epoch regressions above, all44 added cases passed the coordinated
native software suites. The full scoped Wi-Fi suites reported x86_64:
2317 pass/0 fail/9 skip, and aarch64:1847 pass/0 fail/3 skip. These are full
scoped Wi-Fi totals, not RTW88-only counts. Production boots and both btrfs
postflight checks also completed cleanly on each architecture. Debug/release
builds and strict Clippy, including the exact CI feature contexts, passed. None of
these software results establishes silicon or RF acceptance.
Full AC/TID scheduling, TX A-MSDU, larger/native IRQ pipelines,
wider PHY/channels, reset/rejoin and power management remain software work.

### C21/C22 separately qualified native RTS threshold

`Rtw88Device::rts_request().await -> Result<RtsRequest, FirmwareError>`
returns exact current H/R/T source-program identity, factory MAC and the
expected `rtw88/rtw882{1,2}ce-rts-v1-<mac>.bin` registry name. It grants no
power or transmission permission. The optional X extension retains a concrete
acyclic H, R-over-H or T-over-exact-H/R owner; the request binds every
preceding recipe and full signed record digest, including the actual T
retry/burst limits. H/R/T assets cannot themselves grant RTS.

The real registry loader requires a signed128-byte N21X/N22X record. Missing,
unsigned, malformed or restricted optional input before binding preserves
the preceding non-RTS station. Actual attached-source or policy loss closes
the owner and cannot be repaired by a later asset/policy reinstall. The
minimum of current policy, X and every earlier grant bounds every emission;
previous H data, R automatic-response and T retry/burst peaks must fit that
same limit, with each record's own antenna bound. No measured real-board X
asset is supplied.

|Bytes|X record field|
|---|---|
|0..4|exact native chip `N21X` or `N22X`|
|4..12|version1, header128, total128 (little endian)|
|12..16|VID10ec, exact DIDc821/c822|
|16..48|current H/R/T program request identity|
|48..56|factory MAC, channel1, width20|
|56..60|antenna upper bound and maximum EIRP:i16 quarter-dB units|
|60..68|whole transition, native RTS, automatic-response and complete retry/control/burst conducted peaks:i16 quarter-dBm|
|68..70|full static thermal range0..63|
|70..72|smallest measured/admitted finite RTS threshold0..2347:u16|
|72..128|reserved zero|

The measurement contract covers actual RTS/CTS/retry/control/data transitions,
burst duty, supply, antenna, coexistence and all static raw thermal values.
It does not infer those quantities from HT gains or a single-MPDU measurement.
T's existing DATA-PPDU byte/symbol/density limits remain in force when T is
attached; the extra RTS/control emission envelope requires X independently.

The existing `WirelessNetIface::{rts_threshold,set_rts_threshold}` API is
implemented for this single live retained HT20 station only after actual
X admission and negotiated support for source24Mbps RTS. The initial setting
is disabled (`u32::MAX`), which does not change the original H/R/T emitting
program. Finite settings must lie between the signed minimum and2347;
`u32::MAX` disables. Invalid values return EINVAL, unqualified/unsupported
requests return EOPNOTSUPP, and an occupied native/key/control owner or
nonempty MAC FIFO returns EBUSY without changing the setting. Configuration
never waits for another executor while holding an IRQ-safe lock. No additional
vdev or reset/recovery continuation is implemented by this API.

Before publishing a setting, the exact retained owner must have an open real
controlled port, no pending DATA/security/BA operation, current H gains/crypto
readbacks and source native BE/management FIFO emptiness. Its actual X/base
capabilities enclose the atomic setting change. The value survives a genuine
same-owner key replacement; it creates no key, peer or controlled-port right.
The public cached value reports configuration, not transmission authority.

Source `mac80211.c::rtw_ops_set_rts_threshold` and `tx.c` select RTS for eligible
ordinary DATA only when the original MPDU length is strictly greater than the
threshold. The native packet Core adds exact source W3 USE_RTS bit12,
W4 RTSRATE[28:24]=8 (`DESC_RATE24M`) and W5 DATA_RTS_SHORT bit12 to that
original's descriptor. It requires the bound response's actual24Mbps rate;
mandatory HT capability alone is not substituted for that negotiated fact.
The QoS header, sequence, plaintext/ciphertext and CCMP nonce/MIC are never
rewritten. Management, BA controls and raw24 private M2/M4/group-key replies
stay on their existing non-RTS source descriptors and legacy rate.

Single RTS DATA requests genuine native CCX and requires its exact retained
DMA bytes plus consumed PCI ownership and positive radio status. It then
requires the actual source MAC FIFO drain before another DATA/control/key
publication or threshold change. T's four-buffer path keeps each MPDU's
same independent CCX/consumed-prefix/FIFO proofs and R's exact source BAR
mode. A negative/duplicate/corrupt/missing receipt, invalid FIFO, bounded1s
drain timeout, cancellation or current-source loss closes admission while
retaining every possibly published native allocation. There is no fabricated
RTS firmware acknowledgement or inferred returned BA bitmap.

Twelve new native smokes are authored, six per chip: Open/WPA2 kernel DHCP/IP
over X-on-H/R/T, literal descriptor flags and strict threshold boundaries,
disable/old assets/unsigned and malformed input/retry, exact source identity
and prior-peak intersections, absent24Mbps response support, held CCX and
genuine group-key reply with RTS absent, native FIFO/corrupt/negative/cancel
failures, every preceding/X source and current policy loss, and revocation
between actual batch BDs with retained DMA. All twelve additive RTS cases passed
on both architectures in the coordinated scoped Wi-Fi suites: x86_64
2360 pass,0 fail,9 skip; aarch64 1890 pass,0 fail,3 skip. Production boots and
all btrfs postflights were clean. Earlier RX/TX BA totals describe the preceding
validated checkpoint. Native RTS/CTS execution and physical
RF/interoperability acceptance still require real firmware/silicon and the
external measured X asset.

No CTS-to-self or new AP HT-protection mode is inferred from the source RTS
path. Current width/stream/channel restrictions remain unchanged. Source
`rtw_ops_can_aggregate_in_amsdu` explicitly declines TX A-MSDU on2.4GHz;
this channel1 owner therefore does not add a TX A-MSDU producer. That source
policy is not a claim that the silicon lacks broader-band A-MSDU capability.


### Separately signed continuation contracts and the dm watchdog

`qualification.rs` is the single reusable loader for every new RTW88 program
that needs its own measured authority. A static `Kind { tag, stem, source,
admit }` describes the program; the generic code supplies the 128-byte
layout (`N21<tag>`/`N22<tag>`, `[1,0,128,0]`, length, `ec 10` + PCI id,
identity, exact factory MAC, `[tag, 1]`, 64-byte kind payload, zero tail),
signer and capability checks, and `Grant::invoke(gate, op)`, which re-enters
the continuation capability and then the current base `Gate` (regulatory
policy and every bound base capability). The identity binds the chip, the
MAC, the exact retained board/calibration base (`Gate::extension_request`,
i.e. N22Cv2 or N21S) and the hashed upstream source contract. Requests are
filed as `rtw88/rtw882{1,2}ce-<stem>-v1-<mac>.bin`;
`Rtw88Device::tracking_request()` returns the `ContinuationRequest` for the
dm kind. New programs add a `Kind` instead of another bespoke loader.

`dm.rs` (tag `D`, stem `dm`) ports Linux `main.c::rtw_watch_dog_work`
(2 s period, run with the retained owner mutex held) and
`phy.c::rtw_phy_dynamic_mechanism`:

| Mechanism (payload bit) | Source | Chips |
|---|---|---|
| statistics | `rtw_phy_statistics`: RSSI EWMA(10,16) from peer PHY status, `rtw_phy_get_rssi_level`, H2C 0x42; `false_alarm_statistics` counters and reset pulses | both |
| DIG (0) | `rtw_phy_dig` thresholds/steps/damping/boundaries; signed `dig_max` caps `DIG_PERF_MAX` | C21 `0xc50`, C22 `0x1d70` both paths |
| CCK PD (1) | `rtw_phy_cck_pd` + `cck_pd_set` (8822c PD/CS deltas, 8821c `0xa08`/`0xaa8`), level capped by payload | both |
| RA (2) | `rtw_phy_ra_track`: H2C 0x58 WL-PHY info, every fourth period RA_INFO 0x40 with RSSI-level mask and NO_UPDATE, C2H 0x0c RA report, RRSR = retained qualified RRSR & report mask | both |
| TX path diversity (3) | `rtw_phy_tx_path_diversity` + `rtw8822c_config_{cck,ofdm}_tx_path` | C22 |
| CFO (4) | `rtw8822c_cfo_track`, crystal `0x1040[23:10]`, BT scoreboard reset, window bounded by payload | C22 |
| thermal power tracking (5) | `rtw8822c_pwr_track` type 0: RF42 trigger, EWMA(10,4), 2G/CCK swing tables, LCK at 8 steps, `0x18a0`/`0x41a0[6:0]` delta clamped to the signed up/down bound; samples outside the signed thermal window refuse | C22 |
| EDCCA adaptivity (6) | `rtw8822c_adaptivity` normal/ETSI(45)/JP(60) from the regulatory country (wireless-regdb DFS region), `0x84c` bytes 2/3 | C22 |

The continuation binds at association and the watchdog runs only on an
established station. Each register group runs inside admission + continuation
+ base gate; H2C goes through the retained mailbox after a fresh grant check.
Revocation, policy loss or an out-of-envelope sample restores the base program
(initial IGI/EDCCA, factory crystal, path A, zero power delta, qualified RRSR,
level-0 CCK PD) under the base gate only and stops tracking for that
association. Deviations from Linux, each a qualification bound: the RRSR base
is the qualified mask rather than `RRSR_INIT_2G`; DIG/CCK-PD/crystal/power
deltas are capped by the signed payload; there is no unlinked DIG because the
continuation binds at association. DPK tracking is not offered: Linux
`rtw8822c_dpk_track` returns without a DPK result, and this profile runs no
DPK calibration.

Linux rtw88 reads no `ht_operation_mode` and takes no protection action
(`mac80211.c`, `tx.c`), so the retained station now admits APs that advertise
HT protection modes 1..3 unchanged. The check was local to rtw88; no shared
`JoinPlan` change was needed.

Evidence: nine `drivers/wireless/rtw88/dm_engine` register-model cases
(`dm_tests.rs`), and composed C21/C22 Open/WPA2 watchdog, revocation-restore
and refusal cases (`dm_station_tests.rs`, `drivers/wireless/rtw88/dm/rtl882{1,2}c`)
plus HT protection modes 1..3 (`drivers/wireless/rtw88/ht_protection/*`).
These are software/model results. A real signed N2xD measurement and physical
acceptance remain external deployment gates.

### C21/C22 HT TX coding: LDPC and STBC (`N2xC`)

`coding.rs` (tag `C`, stem `coding`) is the first TX/PHY feature qualified
through the generic continuation contract. Linux v6.12 sources:

- `main.c::rtw_init_ht_cap` (~L1540): every chip advertises one-stream RX
  STBC (`1 << IEEE80211_HT_CAP_RX_STBC_SHIFT`); HT `LDPC_CODING` only with
  `chip->rx_ldpc` (`rtw8822c.c` `.rx_ldpc = true`, `rtw8821c.c` false);
  HT `TX_STBC` only with `chip->tx_stbc` (`rtw8822c.c`).
- `main.c::rtw_update_sta_info` (~L1200): `si->ldpc_en` from the peer's HT
  `LDPC_CODING`, `si->stbc_en` from the peer's nonzero HT `RX_STBC`.
- `tx.c::rtw_tx_pkt_info_update` (~L375): `stbc = hal.txrx_1ss ? false :
  si->stbc_en`, `ldpc = si->ldpc_en`; `tx.c::rtw_tx_fill_tx_desc` encodes
  `tx.h` `RTW_TX_DESC_W5_DATA_LDPC` (BIT 7) and `W5_DATA_STBC` (bits 9:8).
- `fw.c::rtw_fw_send_ra_info` / `fw.h` `SET_RA_INFO_LDPC` (H2C word0 bit 26).

RX advertisement is a local decode promise and belongs to the base HT
station: with a bound N2xH every HT association request now carries RX
STBC1, and C22 also carries LDPC. Emitting coded PPDUs changes the waveform,
so it needs a separate `N2xC` continuation over the exact retained base.
Payload byte 0 requests TX LDPC (bit 0) and TX STBC (bit 1); every other
byte is zero. C21 is one-path and may request LDPC only, matching Linux,
which gates no TX LDPC on the chip. The grant loads, identity-matched, before
`JoinPlan` preparation, so the offer advertises `TX_STBC` only when a
matching N2xC exists. Its live check runs when it binds into the retained
`Gate` (`with_continuation`), right after the HT program. A grant that is
not current at that point leaves TX uncoded.
At the association response the data profile takes LDPC/STBC only where the
qualified flags and the shared `HtNegotiation::tx_ldpc`/`tx_stbc` (peer
capability) agree. `wmm::ra_info` sets RA_INFO bit 26 and the native
descriptor sets W5 bit 7 and W5 bits 9:8 = 1. `Gate::allows_profile` admits a
coded profile only with a current bound grant whose flags permit it.

`hal.txrx_1ss` is never set because coexistence-driven SMPS is not
implemented (`smps_txrx_1ss` stays open), so STBC is not forced off. The
coding grant is not part of `Gate::current`. Every DATA send and every
watchdog pass call `coding_live`. If the grant is revoked or no longer
matches, the station drops to the uncoded HT profile under the base gate.
The next watchdog then resends RA_INFO without LDPC, and the link stays up.
Teardown clears the bound coding.

Evidence: two `drivers/wireless/rtw88/narrow/coding` cases (descriptor W5
bits, payload bounds, peer/flag intersection) and composed C21/C22 cases in
`drivers/wireless/rtw88/coding/rtl882{1,2}c` (`coding_tests.rs`):
advertisement, coded descriptor and RA_INFO, revocation downgrade, an
unqualified station, a peer without coding, refused records and teardown.
A real signed N2xC measurement and over-the-air acceptance remain external.

### C21/C22 all-AC WMM and all-TID QoS routing (`N2xQ`)

`qos.rs` (tag `Q`, stem `qos`) lifts the base N2xL single BE/TID0 producer
to every TID and all four EDCA rings. Sources:

- `net/wireless/util.c::cfg80211_classify8021d` (RFC 8325 DSCP to 802.1d,
  IPv4/IPv6/MPLS/802.21, no QoS map) picks the TID of each Ethernet frame.
- `net/mac80211/wme.c::{ieee802_1d_to_ac,wme_downgrade_ac,
  ieee80211_downgrade_queue}`: with no admitted TSPEC, ACs whose AP WMM
  parameter has ACM set are stepped down (BK when every lower AC needs
  admission).
- `rtw88/tx.c::rtw_tx_ac_to_hwq` maps VO/VI/BE/BK to the hardware rings
  and `rtw_tx_pkt_info_update` sets `qsel = skb->priority` (the TID).
- `rtw88/pci.h` `RTK_PCI_TXBD_IDX_{VO,VI,BE,BK}Q` (0x3a0/0x3a4/0x3a8/0x3ac)
  and `pci.c::max_num_of_tx_queue` (BE 256, others 128). The original
  retained owner already maps all seven rings; packet core now drives
  BE/BK/VI/VO.

Payload byte 0 is the qualified set of extra ACs (bit 0 BK, bit 1 VI,
bit 2 VO); every other byte is zero. The continuation binds into the
retained `Gate` right after the WMM extension, and only when the AP
advertised WMM. `DataProfile::acs` carries the set and
`Gate::allows_profile` admits it only with a current bound grant.
Classification is followed by the ACM downgrade. A TID whose AC is not
qualified then steps further down; an unqualified BK falls back to
BE/TID0. QoS Control carries the TID with normal ack and no
EOSP/A-MSDU bit, and the descriptor QSEL is the TID. EDCA for all four
ACs is already programmed from the bound AP parameters (`wmm.rs`). RX
accepts QoS DATA on any TID while `acs` is set. Originator BA still
aggregates only its TID0 agreement, so other TIDs use single-MPDU
publication. Revocation is checked on every send and every watchdog pass,
like N2xC; it returns every frame to BE/TID0 without dropping the link.

Evidence: two `drivers/wireless/rtw88/narrow/qos` cases (DSCP mapping,
ACM downgrade, qualified-AC fallback, ring/index/QSEL and payload bounds)
and composed C21/C22 Open/WPA2 cases in `drivers/wireless/rtw88/qos/*`
(`qos_tests.rs`): per-TID routing to the AP, revocation and teardown, an
unqualified station, a VI-only subset and refused records. A real signed
N2xQ measurement and over-the-air acceptance remain external.

## 4. Invariants

- Physical reads select Wi-Fi EFUSE bank zero and disable the programming
  LDO25: `0x37[7]` for 8821C/8822B, `0x29[0]` for 8822C.
- A read clears `REG_EFUSE_CTRL[31]` and waits for hardware to set it.
  Address bits are `[17:8]`; unrelated control bits are preserved. The
  per-byte wait is bounded and uses the scheduler's responsive wait.
- Only the unprotected physical area is decoded. One- and two-byte
  headers select eight-byte logical blocks, with zero bits enabling
  two-byte words. Later records override earlier words; absent words
  remain `0xff`. Truncated/out-of-map records fail explicitly.
- Beacon completion clears stale valid status before publication and
  waits for a fresh valid observation. An outer-shareable acquire fence
  orders that exact completion before CPU reuse; ambiguous completion or
  cancelled restoration cannot reopen the buffer.
- No successful association or usable packet ring is implied by identity
  detection or firmware-ready status.

## 5. Architecture notes

The register protocol and byte-stream decoder are architecture independent;
BAR mapping and responsive waits use the existing bus/scheduler services.
Traced fake-register smokes exercise the live identity and firmware
helpers without a Realtek device on both architecture builds. Native
publication and completion use full outer-shareable device barriers on
aarch64.

## 6. Dependencies

`narf-bus` owns BAR/configuration access, `narf-io` supplies coherent
DMA storage, `narf-firmware` supplies authenticated image snapshots,
`narf-scheduler` owns the asynchronous continuation, and `narf-time`
provides bounded completion waits. Shared `narf-wireless` association,
station-security and packet-key owners supply bounded MLME, RSNA and CCMP;
`narf-net` supplies frame registration and the kernel IP/DHCP stack.

## 7. Stage assignment

- **Stage 1**: PCI match table + sparse EFUSE MAC read (software covered;
  physical hardware acceptance pending).
- **Retained RTL8822CE software profile**: section firmware/reserved-page/
  IDDMA, MAC/PHY/radio, signed operating power, H2C/mailbox, ordinary packet
  rings and the channel1 Open/WPA2 station shell are implemented. Composed
  software gates and physical acceptance are tracked separately. Distinct
  optional N22L enables response-bound legacy12 DATA and WMM BE/TID0.
- **Retained RTL8821CE software profile**: exact firmware, inactive MAC,
  chip-specific one-path PHY tables, separate N21Q IQK/N21P parked-power/N21S
  awake-radio grants and native ch1/20 Open/WPA2 station are implemented.
  Real measured signed assets and physical acceptance remain gates.
- **Additional profiles**: RTL8822BE native station support, broader
  PHY/rates/channels, power management and recovery remain outside this gate.

## 8. Open questions and references

RTL8821CE and RTL8822CE firmware have retained native owners; RTL8822BE
firmware remains unsupported. BAR2 contains registers, so firmware travels through beacon
host DMA and IDDMA rather than whole-blob BAR writes. The initial hardware
target is exclusively RTL8822CE, awake channel1/20 MHz, host CCK1 data and
qualified native legacy responses, Open or WPA2-PSK, software CCMP and bounded
polling. A signed measured version2 envelope for the actual board/environment,
authenticated firmware and deployment policy are mandatory before any RF
qualification or packet transmission. No default country, curve or calibration
authority is supplied. Physical scan/association/DHCP/bidirectional IP and safe
disconnect/failure on that exact board remain hardware acceptance obligations.

Remaining software ledger:

| Prerequisite | State |
|---|---|
| PCI BAR2, power/cut sequencing, factory identity | Implemented; register-model and QEMU regressions |
| Beacon reserved-page DMA owner, descriptors, successful park | Implemented for RTL8821CE/RTL8822CE; terminal failures retain mappings |
| Authenticated section loading, IDDMA validation | Implemented with separate exact RTL8821CE/RTL8822CE images; RTL8822BE and raw-MMIO helper reject |
| Inactive PCIe MAC/FIFO/LLT/internal H2C queue setup | Implemented in the same retained firmware owners with chip-specific FIFO/EDCA/SIFS and C22-only PCI quirk; packet DMA stays closed |
| H2C packet ring and port0 command mailbox | Same retained native owner; bounded exact transport receipts and separate IQK completion |
| Retained complete RTL8822CE factory map | Implemented from same probe EFUSE read; original Linux packed geometry checked |
| Factory-selected inactive BB/AGC/RF tables | Same-owner C21 package/RFE/one-path SIPI and C22 two-path RFK-init/mixed-access ports; separate frozen reference fixtures and composed failure/cancellation/DMA retention regressions |
| C21 measured calibration-only ch1/20 IQK | Exact N21Q identity/current signed authority/policy, source channel/RFE/swing and one-path H2C, fresh RF08/status/thermal receipt, retained command DMA and parked success; the real measured envelope is external and cannot authorize operating RF |
| C21 parked operating-power program | Same-owner post-IQK N21P exact-board/source-recipe qualification, source RFE-selected factory ceilings, explicit measured12-rate indices/peaks and response envelope, fresh thermal/TXAGC/RRSR readbacks implemented; distinct N21S required for awake packets |
| C21 awake radio/packet/port0/station | Exact N21S identity/current triple signed-source authority and live policy, C21 gain/channel/thermal and real wake/CAM receipts, parked same-owner beacon disarm and native Open/WPA2 DHCP/IP composition implemented; measured assets/physical acceptance remain external |
| Current signed per-board gain/operating-envelope qualification | Implemented loader, exact identity/source ceilings, cap revocation and current-policy checks; real measured signed artifact is an external deployment gate |
| Fixed awake ch1 radio/DACK/IQK/OTP/qualified power | Implemented for the explicit version2 CCK/control-response profile; real signed measured envelope remains a deployment gate |
| C21/C22 legacy12 DATA/WMM BE-TID0 | Separate N21L/N22L exact-chip identities/current signed measurements and host-policy gates; bound response rates/parameters, source EDCA/RA/RRSR, each chip's actual gain readbacks, native fixed legacy DATA, raw QoS/CCMP and Open/WPA2 DHCP/IP composition implemented. Base N21S/N22Cv2 alone retain CCK1; full AC/TID scheduling is the separate N2xQ program |
| C21/C22 HT20/one stream/SGI20 | Distinct N21H/N22H static measured contracts/current source gates; source-native absolute/reference-difference MCS gains, typed original offer/request/response, actual RA/TXD/RXD, authenticated whole3839-byte A-MSDU, native ADDBA-decline/CCX and Open/WPA2 DHCP/IP. Real assets/physical acceptance remain external; richer PHY remains work |
| C21/C22 recipient RX BA | Distinct exact-H N21R/N22R contract; actual bound ADDBA success/CCX/idle, explicit SSN, TIDs0..7/window<=64 with A-MSDU permission, source RAW/PHY admission, opaque originals before CCMP/PN, BAR20/DELBA/hole/TU timers and key/publication epochs implemented; native tests passed the coordinated x86_64/aarch64 software suites. Real measured assets/automatic BA/over-air acceptance remain external |
| C21/C22 originator TX BA | Distinct exact-H or R-over-H N21T/N22T contract; bound on-air request/response/current SSN, genuine CCX/RX-idle/MAC-FIFO proof, four independent native DMA originals, source AGGEN/density/MAXAGG and per-MPDU status, current-SSN BAR20/DELBA/key drains implemented; native tests passed the coordinated x86_64/aarch64 software suites. Measured assets/real MAC aggregation and over-air behavior remain external |
| C21/C22 RTS threshold | Separate N21X/N22X over exact current H/R/T; native24Mbps RTS descriptor/control program, actual response-rate admission, drained current-authority setting, CCX/immutable-DMA/FIFO completion and EAPOL exclusion implemented. Twelve native cases pass on both architectures; real measured X assets/RTS-CTS/physical acceptance remain external |
| C21/C22 HT TX coding (LDPC/STBC) | N2xC continuation: base RX STBC1 (+C22 RX LDPC) advertisement, qualified TX LDPC (both) / TX STBC (C22) intersected with the peer, W5 bit7/bits9:8, RA_INFO bit26, revocation downgrade. Real N2xC measurement external |
| C21/C22 all-AC WMM / all-TID QoS | N2xQ continuation: cfg80211_classify8021d + ACM downgrade, BK/VI/VO/BE rings with QSEL=TID, any-TID RX, revocation to BE/TID0. Real N2xQ measurement external |
| Generic continuation contract + dm watchdog | Reusable signed N2x<tag> loader; N2xD rtw_watch_dog_work/rtw_phy_dynamic_mechanism port: DIG/CCK-PD/RA on both chips, path diversity/CFO/thermal power tracking/EDCCA on C22; base restore on revocation. Real N2xD measurement external; no DPK tracking |
| Port0 peer/AID/media/RA/default-port control | Implemented bounded source mailbox, long-slot initial MLME, same-owner station integration and close/cancel behavior |
| Passive/active channel1 scan with probe IEs, authentication/association, WPA2 controlled port | Retained channel1 shared MLME/RSNA/CCMP through actual native DMA and CCX, including held/altered/cancelled M4 and queued peer-loss closure |
| Native management/data TX, RX, completion and ring ownership | Implemented original rings, source descriptors, exact DMA plus CCX security receipt and current-authority publication |
| Device/frame/kernel IP integration | One shell before activation, same Arc lifecycle, bounded synchronous progress; Open/WPA2 real kernel DHCP and exact bidirectional IP pass composed model tests |
| Reset/suspend/removal, retained-map reclamation and multi-device lifetime | Outside the one-shot awake profile; published mappings remain retained |

Per-chip hardware backlog follows original `rtw8821c.c`, `rtw8822b.c` and
`rtw8822c.c` chip-info/ops. C21 is1SS and C22B/C22C are2SS; all declare2.4/5GHz,
HT and VHT. A separately qualified HT20/1SS/SGI20/A-MSDU station subset now has
a complete software path on C21/C22C. Broader HT streams and widths, VHT,
Broader TX aggregation and recipient negotiation, noninitial channels (channel1 active scan is implemented),
RF tracking, coexistence, sleep/WoW and controller-proven reset/rejoin. C22B needs
retained firmware, MAC/PHY/RF/power and packet composition. C21/C22C supply
separate qualified legacy station chains. None of these initial-profile exclusions are hardware
inapplicability claims; no6GHz/HE/EHT capability is declared by these chip-info
records.

The actual reserved-page backend transfers successful firmware ownership into
an explicit continuation state when inactive MAC admission succeeds. Firmware
page reuse is already closed there. C22 radio completion accepts only that
state plus a completed beacon receipt, poisons it before native parking, and
disarms the old beacon descriptors only under parked current device authority.
An unrelated terminal/ambiguous page state cannot enter this path. A native
Rust regression composes the full C22 firmware/MAC/PHY/radio chain through this
actual backend, including park/disarm failures, pending-command cancellation,
one-shot refusal and retained mappings after destruction.

Power-table rows are fixed Rust programming data ported from each Linux
chip's `trans_*` arrays. Native Rust regressions cover all chips, warm/cold boot,
cut-C filtering, bounded polling/retry/failure, unknown cuts and absent hardware.
Frozen firmware reference traces cover81 loader operations. Tests also exercise
header/section bounds, complete reserved-page composition, scripted I/O failures,
stale completion, reuse ordering and terminal cancellation. Native capability
regressions reject revoked authority before CPU/config/MMIO/allocation access.
These are software checks, not silicon acceptance.

MAC regressions compare Rust FIFO/LLT/H2C and chip-specific register behavior
with frozen traces for cut-A/cut-D seeded images, preserving unrelated fields.
They compose firmware-download and MAC ownership, sweep access failures, cancel
LLT waits and reject invalid H2C pointers. PHY regressions retain56 C21 and49
C22 profile digests and source filter snapshots, with same-owner stage faults,
cancellation, replay refusal and invalid factory/path rejection. Table loading
remains distinct from successful calibration or station readiness.

Frozen radio references cover fresh DACK, TRX/channel/trim and IQK-command
writes/delays for zero/nonzero seeded register images and distinct RF paths.
Rust models continue the actual retained firmware/MAC/PHY owners through current
signed qualification into bounded calibration. They cover missing receipts,
pending-command cancellation, restrictive live policy, actual cap revocation,
distinct-path restoration and H2C wrap/foreign-head ownership. Fixed station
mailbox vectors and control regressions cover readiness/consumption, close during
a wait, retained cancelled commands and teardown after close.

The stored reference values are historical Linux-source inputs, not expected
values calculated from the Rust implementation or an executable equivalence
proof. RTW88 requires no Python, C compiler, temporary Rust compilation harness
or external source checkout. The former pipelines were removed; source citations,
recorded hashes, firmware metadata and the native Rust tests remain in
`src/rtw88/REFERENCE_FIXTURES.md` and per-fixture provenance. Updates require
source-contract review and must preserve independent expected values.

Source contracts remain Linux `rtw88/efuse.c`, `mac.c`, `fw.c`, `pci.c`,
`rtw8821c.{c,h}`, `rtw8822b.{c,h}`, `rtw8822c.{c,h}` and the per-chip tables.
`pci.c::rtw_pci_io_mapping` identifies the mandatory BAR2 register aperture.
The public Realtek RTL8822C datasheet remains supporting hardware documentation.

Shell-future regressions additionally cover unpublished activation, cancelled
activation before owner-mutex acquisition, public disconnect reservation before
the mutex, nonblocking drain, cancellation release and terminal cleanup without
owner reconstruction. Their empty lifecycle cannot fabricate a firmware,
calibration or station-ready receipt.

The complete station fixture earns firmware, MAC, PHY, board qualification and
radio receipts on that same lifecycle before Device activation. Its simulated
AP consumes the current real DMA bytes at each doorbell and generates native
RXBD/RXD and identity-matched CCX events. Open and WPA2 run the actual kernel
DHCP client and exchange exact IP payloads through host frame rings and the
registered stack. Negative cases retain M4 DMA across cancellation, alter its
actual receipt bytes, queue peer loss before RX idle, revoke the actual
calibration epoch between descriptor write and doorbell, remove current power
policy and serialize disconnect against synchronous workers. Administrative
IFF_UP remains independent of physical carrier. These are software/model
results; no fixture creates deployable board measurements or physical evidence.

### Upstream applicability triage (2026-10-27)

This subsection resolves the former `unknown` inventory rows against Linux
v6.12 `rtw88/{main.c,mac80211.c,tx.c,phy.c,rtw8821c.c,rtw8822b.c,rtw8822c.c}`.
It records applicability only; nothing below is implemented by this change.

Inapplicable on upstream rtw88 (rows removed):

| Former row | Evidence |
|---|---|
| `checksum_offload_applicability` | `main.c::rtw_register_hw` assigns no `hw->netdev_features`; `tx.c::rtw_tx_fill_tx_desc` has no checksum descriptor field. Host checksums remain authoritative. |
| `tso_offload_applicability` | Same: no `NETIF_F_TSO*` and no segmentation descriptor; mac80211 delivers single MSDUs/A-MSDUs. |
| `vlan_offload_applicability` | Same: no VLAN insertion/stripping field or netdev feature. |
| `greenfield_applicability` | `main.c::rtw_init_ht_cap` never sets `IEEE80211_HT_CAP_GRN_FLD` on any chip. |
| `ht_control_scope` (HT +HTC) | `rtw_init_ht_cap` advertises no HT-control capability. VHT +HTC (`IEEE80211_VHT_CAP_HTC_VHT` in `rtw_init_vht_cap`) belongs to the `vht` row. |
| `cts_to_self` | `tx.c` maps only `info->control.use_rts` or `len > rts_threshold` to `W3_USE_RTS`/RTS24M; neither `tx.c` nor `mac80211.c` reads `use_cts_prot` or programs a CTS-to-self descriptor bit. The implemented RTS threshold is the complete upstream protection mechanism. |

Resolved into named feature rows (applicability proven, work remains):

| Former row | Named rows and evidence |
|---|---|
| `additional_ht_widths` | `ht40`: `rtw_init_ht_cap` adds `SUP_WIDTH_20_40`, `DSSSCCK40` and `SGI_40` when EFUSE `hw_cap.bw` has 40MHz (all three chips). VHT80 stays in `vht`. |
| `broader_ba_variants` | `tx_ba_all_tids`: `tx.c::rtw_txq_check_agg` requests originator BA for every non-VO TID (never EAPOL). `tx_amsdu_5ghz`: `TX_AMSDU`/`SUPPORTS_AMSDU_IN_AMPDU` with `rtw_ops_can_aggregate_in_amsdu` declining only on 2.4GHz. Recipient negotiation is mac80211-owned (`RX_START`/`RX_STOP` are driver no-ops) and already covered by the R contract. |
| `dynamic_phy_thermal_scope` | `phy.c::rtw_phy_dynamic_mechanism` runs statistics, `dig_tracking` (all chips), `cck_pd_tracking` (C21/C22C `cck_pd_set`, 2.4GHz only), `ra_tracking` (firmware RA info and RRSR update), `tx_path_diversity` (C22C `path_div_supported`), `cfo_tracking` and `dpk_tracking` (C22C only), `rf_power_tracking` (all chips, existing row) and `edcca_adaptivity` (C22B/C22C `adaptivity`, or firmware `FW_FEATURE_ADAPTIVITY`). |
| `ldpc_applicability` | `ldpc`: `rx_ldpc = true` on 8822B/8822C (false on 8821C) gates HT `LDPC_CODING` and VHT `RXLDPC`; TX sets `W5_DATA_LDPC` from the peer's `si->ldpc_en`. |
| `stbc_applicability` | `stbc`: one-stream RX STBC is advertised on every chip (HT `RX_STBC`=1, VHT `RXSTBC_1`); HT TX STBC only with `tx_stbc` (8822C) and VHT `TXSTBC` when `rf_path_num > 1`; `W5_DATA_STBC` is forced off while `hal.txrx_1ss`. |
| `smps_scope` | `smps_txrx_1ss`: only 8822C has `config_txrx_mode`; `main.c::rtw_vif_smps_iter` requests static SMPS while coexistence forces 1SS and SMPS off otherwise. No `NL80211_FEATURE_{STATIC,DYNAMIC}_SMPS` is set, so user-driven local SMPS is inapplicable. |

Refined feature rows: `wow` applies to RTL8822CE only (`wow_fw_name`/
`wowlan_stub` exist only in `rtw8822c.c`; 8821C/8822B declare neither).
`ht_protection_modes`: upstream reads no `ht_operation_mode` and takes no
protection action, so the remaining work is admitting APs that advertise
nonzero HT protection in the shared HT JoinPlan instead of refusing them.

### Open rtw88 ledger rows (2026-10-28)

Each row below was checked against the tree after the N2xC/N2xQ/random-MAC
changes. None is a physical blocker unless stated.

| Row | Blocker |
|---|---|
| `additional_operating_channels` | `station.rs::associate` refuses `candidate.bss.channel != 1` and `scan.rs::plan` admits 2412 MHz only. The C21/C22 radio programs (`radio.rs`, `radio8821c.rs`) write fixed channel1 RF/BB/TXAGC values. Needs ports of `rtw8822c_set_channel`/`rtw8821c_set_channel` plus a per-channel measured envelope. |
| `beamforming` | Linux `bf.c::rtw_bf_assoc` acts only on a VHT peer (`vht_cap` SU beamformer/beamformee), so this is blocked on `vht`. |
| `device_removal` | The retained owner is one-shot: terminal paths keep DMA mappings by design (§4). There is no `rtw_pci_remove` / `rtw_pci_dma_reset` port and `pci.rs` has no remove hook. Software work only (the ath9k DMA-stop pattern applies); not attempted this round. |
| `dma_reclamation` | Same as `device_removal`: there is no controller-proven `rtw_pci_dma_release` / `rtw_pci_reset_buf_desc` stop proof, so published mappings stay retained. Software work only. |
| `dpk_tracking` | `rtw8822c_dpk_track` needs a DPK result, and no `rtw8822c_do_dpk` calibration is ported (§3 dm section). |
| `five_ghz_operation` | The same fixed channel1 programs, plus `scan.rs` 2412-only admission. Needs 5 GHz RF/BB/AGC table selection and a measured 5 GHz envelope. |
| `ht40` | `station.rs` refuses any offered/negotiated width other than `Width::Twenty`, and the radio programs only BW20. Needs `rtw8822c_set_channel_bb` BW40 and DSSS/CCK40 programming, plus SGI40 in the measured HT gate. |
| `multi_device` | Not attempted. Each `Rtw88Device` owns one retained lifecycle, and there is no multi-instance composition test. |
| `multi_stream_ht` | `ht.rs::local` advertises and transmits MCS0..7 only, and `ht.rs::program` writes one-stream TXAGC words. 2SS TXAGC/RA mask programming and a measured 2SS envelope are missing. |
| `operating_reset` | No `rtw_core_stop`/`rtw_core_start` restart over a retained owner. Blocked on the same DMA-stop proof as `dma_reclamation`. |
| `radio_coexistence` | No `coex.c` state machine (BT scoreboard, TDMA tables, `rtw_coex_*` notifications) is ported. |
| `rate_fallback` | `packet_format.rs::transmit_profile` sets W3 USE_RATE|DISDATAFB (bits 8/10) on every frame. Firmware RA fallback needs a qualified per-rate envelope over the RA mask; that is software work, not attempted this round. |
| `rf_power_tracking` | `dm.rs` admits `PWR_TRACK` only on C22 (`C21_MECHANISMS` = DIG/CCK-PD/RA). The `rtw8821c_pwr_track` TXAGC/txscale port is missing. |
| `rtl8822be` | The firmware loader and every retained stage reject `10ec:b822`. RTL8822B firmware/MAC/PHY/RF tables are not ported. |
| `runtime_sleep` | No `ps.c` LPS/IPS (`rtw_enter_lps`, `rtw_leave_ips`); the station stays awake/CAM. |
| `safe_rejoin` | Rejoin needs a fresh lifecycle after terminal closure (§3) and is blocked on `operating_reset`. |
| `smps_txrx_1ss` | Driven only by coexistence (`rtw_vif_smps_iter` on `hal.txrx_1ss`), so blocked on `radio_coexistence`. |
| `system_suspend` | No `rtw_pci_suspend`/`resume` and no wowlan-less power-down/restore path. Blocked on the DMA-stop proof. |
| `tx_amsdu_5ghz` | Blocked on `five_ghz_operation`. |
| `tx_ba_all_tids` | `tx_ba.rs::Originator` holds one TID0 agreement, and `packet_core/batch.rs` aggregates only `Queue::Data`. With N2xQ in place, per-TID agreements and BK/VI/VO batches remain software work, not attempted this round. |
| `vht` | The HT station builds `LocalPhy::ht20` only, and VHT80 needs ht40 channel/BW80 programming first; blocked on `ht40`. |
| `wow` | No `rtw8822c` wowlan firmware swap (`wow_fw_name`) or `wow.c` pattern/RF-kill programming is ported. |
