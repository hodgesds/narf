# rtw88 — Specification

> Status: **v0.4** (RTL8822CE retained firmware, inactive MAC/PHY tables and
> signed board-power prerequisites; radio/packet/station work remains).
>
> Realtek Wi-Fi 5 (802.11ac) driver for PCIe silicon
> (RTL8821CE / RTL8822CE). Adapted from Linux
> `drivers/net/wireless/realtek/rtw88/`.

## 1. Purpose & scope

**Owns:** PCI matching, baseline power-on, and factory identity for
RTL8821CE / RTL8822BE / RTL8822CE, plus the retained native firmware
loader, inactive MAC/FIFO/PHY and board-power continuations for RTL8822CE.
The probe decodes physical EFUSE programming
records to obtain the correct PCIe MAC.

**Does NOT own:** Data path, H2C command set, or regulatory
compliance.

## 2. Assumptions

The caller owns the PCI function and its BAR2 register aperture exclusively.
`pci::bring_up` maps BAR2 with `map_bar_control` (Device memory attributes)
and rejects windows smaller than `0x170c` for RTL8822CE (firmware
LTE indirect data) or `0x1104` for other profiles before MMIO. Chip/cut-filtered
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

The probe registers a diagnostic interface with carrier down. Scan,
association, channel/power configuration, and packet TX remain unsupported.
For RTL8822CE, the controller and registered interface share the exact
`Arc` firmware owner before the probe spawns one asynchronous registered
load attempt. `Rtw88Device::firmware_status()` returns its
`FirmwareStatus { stage, info, error }`; `FirmwareStage` is `Detected`,
`Allocating`, `Loading`, `Ready`, `PreparingMac`, `MacPrepared`,
`PreparingPhy`, `PhyTablesPrepared`, or `Failed`. `Ready` identifies firmware
completion and parked host DMA, independently of station/radio readiness.
RTL8821CE/RTL8822BE have no native firmware owner. The safe
`fw::download_firmware(registers, pci_device_id)` helper returns
`FwError::Unsupported` before registry or MMIO access for every device:
raw MMIO alone cannot prove exclusive DMA/ring/reset ownership.

The private RTL8822CE continuation opens exactly
`rtw88/rtw8822c_fw.bin` through current firmware authority, snapshots the
authenticated image, and rejects malformed layouts before DMA claim. It
copies image bytes inside current firmware-capability invocation and retains
SHA256 of those exact loaded bytes for board-qualification binding. It
parses the actual 64-byte `0x8822` header, exact DMEM/IMEM/optional EMEM
extents and each eight-byte checksum trailer. Only fixed Linux OCP bases
DMEM `0x200000`, IMEM `0x30000`, and EMEM `0x100000` are admitted;
relocated or trailing data fails. RTL8821C/RTL8822B and WoW filename
selection are unsupported. IDDMA consumes serial reserved pages of at
most 4096 bytes, including section checksum tails, then validates section
checksums and the exact final `0xc078` firmware-ready status.

Before BME, the native owner allocates all seven non-beacon TX BD rings,
512 RX buffers plus their BD array, and the beacon BD/frame (522 coherent
mappings). Every mapping is below 4 GiB; bases, counts and reset indices
are checked while MAC TX/RX, all packet queues and interrupts are parked.
Only the retained beacon queue runs during download. Completion closes
HCI/MAC DMA and every queue, verifies BME clear, and restores exact ring
bases/counts/reset indices. H2C/C2H, native packet TX/RX and IRQ delivery
are not started.

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
write and keeps BME, MAC TX/RX, packet queues and IRQs closed. It powers the
BB/RF configuration domain, runs source-selected BB/AGC/RFK-init/RF tables,
applies the actual crystal value, and restores the source header-file mode.
RF0 uses SIPI and other RF registers use direct20-bit read/modify/write, with
the actual source delays. Final parked readbacks precede `PhyTablesPrepared`.
Missing factory data, unsupported geometry, access error and cancellation are
terminal. This state means table loading only; DAC/IQ/LO calibration, trims,
channel/power qualification, H2C/C2H packet service and station activation
remain required. No packet/carrier interface is enabled by this continuation.

The native continuation next loads the exact per-device
`rtw88/rtw8822ce-cal-v1-<12 lowercase MAC hex digits>.bin` qualification through
current firmware authority. Loading and metadata parsing execute inside the
blob's `Cap::invoke`; a signer is mandatory even in builds that admit unsigned
device firmware. The retained calibration cap is invoked again before every
permission/gain check. Qualification itself changes no native registers or DMA
state and does not claim hardware calibration complete.

`PowerPermission` has private fields. Its board identity binds the original
logical map, nineteen protected trims, cut/RFE/crystal/two-path geometry,
decoded firmware hardware capabilities, exact loaded-image SHA256, selected
PHY tables and source-derived factory ceilings. Source PG decoding and
normalization constrain each channel1/1Mbps gain by the minimum of all source
regional rows, including the stricter RFE5 table. A country hint cannot raise
an index. Erased or underflowing factory values are refused; indices are never
interpreted as dBm. Signed measured upper bounds must additionally fit current
host policy, antenna gain, qualified EIRP and the conservative20dBm initial
profile ceiling. Every overlapping rule must cover the complete20MHz channel;
DFS, environmental/unknown restrictions and missing coverage keep TX closed.
`NO_P2P` does not prevent the retained STA profile. Unknown measurements never
mean zero power. The qualification also supplies a separate upper bound for
calibration transients, which must fit the current EIRP limit before a grant.
Policy changes and actual cap revocation invalidate prior gain tokens.

The family-specific `N22C`v1 record is exactly640 bytes: magic[4], version:u16,
header128:u16, length:u32, vendor/device:u16 each, board identity[32], MAC[6],
channel:u8 (1), operating-envelope flag:u8 (1), antenna gain:i16 in quarterdBi,
qualified EIRP:i16 in quarterdBm, profile:u16 (1), calibration conducted peak:i16
in quarterdBm, and64 zero reserved bytes. Two128-entry signed-i16 conducted
upper-envelope arrays follow, for pathsA andB. `i16::MAX` denotes unmeasured;
all other bounds must lie in[-512,256] quarterdBm. Antenna gain lies in[0,128]
quarterdBi. The operating-envelope flag attests the complete fixed awake,
channel1, legacy20, basic1Mbps, TX-A/RX-AB profile and its calibration transitions,
including uncertainty and retained environmental limits. No real measurement
artifact is provided or inferred by the implementation.

One atomic lifecycle claim prevents concurrent/repeated reconstruction.
The exact inner owner is retained before its first DMA publication.
Timeout, access failure, failed readback, checksum error or cancellation
leaves a terminal owner; a new attempt returns `State` without allocation
or device access. Published mappings remain retained on every error and
Drop, including a failed parking sequence or revoked authority. A later
reset/removal implementation must establish device quiescence before
reclaiming them; this stage deliberately has no reclaim/retry path.

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
provides bounded completion waits.

## 7. Stage assignment

- **Stage 1**: PCI match table + sparse EFUSE MAC read (software covered;
  physical hardware acceptance pending).
- **Stage 2 (Partial)**: Per-chip PCI power lifecycle and retained
  RTL8822CE section firmware/reserved-page/IDDMA loading are implemented;
  native bring-up still needs silicon qualification and complete MAC/RF.
- **Stage 3 (Planned)**: H2C command queue + INIT command.
- **Stage 4 (Planned)**: RX/TX fast path.

## 8. Open questions and references

RTL8822CE firmware now has a retained native owner; other chips remain
unsupported. BAR2 contains registers, so firmware travels through beacon
host DMA and IDDMA rather than whole-blob BAR writes. Complete MAC/RF
initialization, H2C and packet runtime remain bring-up blockers.

Remaining software ledger:

| Prerequisite | State |
|---|---|
| PCI BAR2, power/cut sequencing, factory identity | Implemented; register-model and QEMU regressions |
| Beacon reserved-page DMA owner, descriptors, successful park | Implemented for RTL8822CE; terminal failures retain mappings |
| Authenticated section loading, IDDMA validation | Implemented for RTL8822CE; other chips and raw-MMIO helper reject |
| Inactive PCIe MAC/FIFO/LLT/internal H2C queue setup | Implemented in same retained firmware owner; packet DMA stays closed |
| H2C/C2H dispatch and command correlation | Missing |
| Retained complete RTL8822CE factory map | Implemented from same probe EFUSE read; original Linux packed geometry checked |
| Factory-selected inactive BB/AGC/RFK-init/RF tables | Same-owner port implemented; original Linux-C selection/callback oracles and composed stage failure/cancellation regressions |
| Current signed per-board gain/operating-envelope qualification | Implemented loader, exact identity/source ceilings, cap revocation and current-policy checks; real measured signed artifact is an external deployment gate |
| DAC/IQ/LO calibration, trim application and regulatory channel | Missing |
| Passive scan, authentication/association, WPA2 controlled port | Missing |
| Native management/data TX, RX, completion and ring ownership | Missing |
| Reset/suspend/removal, retained-map reclamation and multi-device lifetime | Missing |

Power-table rows were ported from each Linux chip's `trans_*` arrays.
Their numeric expressions were checked with a C oracle compiled from those
original arrays; shared-path tests cover all chips, warm/cold boot, cut-C
filtering, polling retry/failure, unknown cuts, and absent hardware. Loader
callbacks match a host C oracle compiled from the actual Linux loader
functions (81 operations). Kernel smokes exercise parser bounds, complete
section/reserved-page composition, every scripted access failure, stale
completion, reuse ordering and terminal cancellation. A host fixture
executes the actual native source with real capability epochs and inert
PCI/MMIO/coherent mappings; it checks all ring descriptors before BME and
sweeps allocation/PCI faults, failed readbacks, runtime faults and
cancellation. A read-only installed NIC image audit covers exact section
extents and page-body composition; none of these are silicon acceptance.

An additional host oracle compiles the original `mac.c` FIFO/LLT/H2C setup
and `rtw8822c.c` MAC function through an explicitly inactive bus adapter.
Two independently seeded register images cover cut-A and cut-D traces,
including preserved unrelated bits. Kernel smokes compare the actual Rust
continuation with those traces and run real firmware-download-to-MAC ownership,
every access failure, LLT cancellation and invalid H2C pointers. These checks
establish register/ownership contracts; RF and station readiness still require
the remaining ports above.

The PHY table generator compiles Linux's original condition setup/check/parser
for every supported cut/RFE PCIe profile and interns identical resulting tables.
An independent callback oracle also executes the original BB/AGC/RF functions
and direct/SIPI RF accessors over seeded registers. Regression fixtures compare
all49 profiles with those access/delay digests, compose actual firmware and MAC
owners into PHY loading, and cover stage errors, cancellation, replay refusal
and incomplete factory/physical-path rejection. Table initialization is kept
distinct from successful hardware calibration and station readiness.

- Linux `drivers/net/wireless/realtek/rtw88/efuse.c` (read protocol and map).
- Linux `rtw88/rtw8821c.{c,h}`, `rtw8822b.{c,h}`, `rtw8822c.{c,h}`
  (geometry, PCIe MAC offsets, and chip-specific LDO controls).
- Linux `rtw88/fw.c`, `mac.c`, and `pci.c` (remaining firmware lifecycle).
- Linux `rtw88/pci.c::rtw_pci_io_mapping` (mandatory BAR2 register aperture).
- Realtek RTL8822C public datasheet.
