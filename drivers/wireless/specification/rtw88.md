# rtw88 — Specification

> Status: **v1.3** (RTL8821CE retained firmware/MAC/PHY, separately signed IQK/parked-power/awake-station, legacy12/WMM and exact-chip HT20/SGI continuations; RTL8822CE retained firmware, MAC/PHY, bounded radio calibration,
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
default A-MSDU receive and native ADDBA refusal; management and EAPOL remain
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

Passive scan admits channel1/2412 MHz only, bounded dwell and SSID filters.
Active/random-MAC/6 GHz scanning and probe extra IEs are refused. The shared
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
signed assets, HT/VHT widths/aggregation, other bands/channels, full AC/TID,
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
ownership remains pinned. RX BA negotiation/reordering/BAR/timers, TX BA and
A-MPDU producers remain separate native software work. Shared Reorder does
not supply Realtek's missing BA negotiation or descriptor ownership.

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
| C21/C22 legacy12 DATA/WMM BE-TID0 | Separate N21L/N22L exact-chip identities/current signed measurements and host-policy gates; bound response rates/parameters, source EDCA/RA/RRSR, each chip's actual gain readbacks, native fixed legacy DATA, raw QoS/CCMP and Open/WPA2 DHCP/IP composition implemented. Base N21S/N22Cv2 alone retain CCK1; full AC/TID scheduling remains work |
| C21/C22 HT20/one stream/SGI20 | Distinct N21H/N22H static measured contracts/current source gates; source-native absolute/reference-difference MCS gains, typed original offer/request/response, actual RA/TXD/RXD, authenticated whole3839-byte A-MSDU, native ADDBA-decline/CCX and Open/WPA2 DHCP/IP. Real assets/physical acceptance remain external; RX/TX BA and richer PHY remain work |
| Port0 peer/AID/media/RA/default-port control | Implemented bounded source mailbox, long-slot initial MLME, same-owner station integration and close/cancel behavior |
| Passive scan, authentication/association, WPA2 controlled port | Retained channel1 shared MLME/RSNA/CCMP through actual native DMA and CCX, including held/altered/cancelled M4 and queued peer-loss closure |
| Native management/data TX, RX, completion and ring ownership | Implemented original rings, source descriptors, exact DMA plus CCX security receipt and current-authority publication |
| Device/frame/kernel IP integration | One shell before activation, same Arc lifecycle, bounded synchronous progress; Open/WPA2 real kernel DHCP and exact bidirectional IP pass composed model tests |
| Reset/suspend/removal, retained-map reclamation and multi-device lifetime | Outside the one-shot awake profile; published mappings remain retained |

Per-chip hardware backlog follows original `rtw8821c.c`, `rtw8822b.c` and
`rtw8822c.c` chip-info/ops. C21 is1SS and C22B/C22C are2SS; all declare2.4/5GHz,
HT and VHT. A separately qualified HT20/1SS/SGI20/A-MSDU station subset now has
a complete software path on C21/C22C. Broader HT streams and widths, VHT,
aggregation/reordering/BA, full WMM AC/TID scheduling, noninitial channels/active scan,
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
