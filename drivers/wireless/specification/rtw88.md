# rtw88 — Specification

> Status: **v0.3** (RTL8822CE retained firmware bring-up; silicon qualification pending).
>
> Realtek Wi-Fi 5 (802.11ac) driver for PCIe silicon
> (RTL8821CE / RTL8822CE). Adapted from Linux
> `drivers/net/wireless/realtek/rtw88/`.

## 1. Purpose & scope

**Owns:** PCI matching, baseline power-on, and factory identity for
RTL8821CE / RTL8822BE / RTL8822CE, plus the retained native firmware
loader for RTL8822CE. The probe decodes physical EFUSE programming
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

The probe registers a diagnostic interface with carrier down. Scan,
association, channel/power configuration, and packet TX remain unsupported.
For RTL8822CE, the controller and registered interface share the exact
`Arc` firmware owner before the probe spawns one asynchronous registered
load attempt. `Rtw88Device::firmware_status()` returns its
`FirmwareStatus { stage, info, error }`; `FirmwareStage` is `Detected`,
`Allocating`, `Loading`, `Ready`, or `Failed`. `Ready` identifies firmware
completion and parked host DMA, independently of station/radio readiness.
RTL8821CE/RTL8822BE have no native firmware owner. The safe
`fw::download_firmware(registers, pci_device_id)` helper returns
`FwError::Unsupported` before registry or MMIO access for every device:
raw MMIO alone cannot prove exclusive DMA/ring/reset ownership.

The private RTL8822CE continuation opens exactly
`rtw88/rtw8822c_fw.bin` through current firmware authority, snapshots the
authenticated image, and rejects malformed layouts before DMA claim. It
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
| H2C/C2H dispatch and command correlation | Missing |
| Per-board RF/BB tables, EFUSE calibration, regulatory channel/power | Missing |
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

- Linux `drivers/net/wireless/realtek/rtw88/efuse.c` (read protocol and map).
- Linux `rtw88/rtw8821c.{c,h}`, `rtw8822b.{c,h}`, `rtw8822c.{c,h}`
  (geometry, PCIe MAC offsets, and chip-specific LDO controls).
- Linux `rtw88/fw.c`, `mac.c`, and `pci.c` (remaining firmware lifecycle).
- Linux `rtw88/pci.c::rtw_pci_io_mapping` (mandatory BAR2 register aperture).
- Realtek RTL8822C public datasheet.
