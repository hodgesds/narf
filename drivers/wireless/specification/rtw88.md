# rtw88 — Specification

> Status: **v0.2** (factory-identity bring-up; silicon qualification pending).
>
> Realtek Wi-Fi 5 (802.11ac) driver for PCIe silicon
> (RTL8821CE / RTL8822CE). Adapted from Linux
> `drivers/net/wireless/realtek/rtw88/`.

## 1. Purpose & scope

**Owns:** PCI matching, baseline power-on, and factory identity for
RTL8821CE / RTL8822BE / RTL8822CE. The live probe now decodes the
physical EFUSE programming records to obtain the correct PCIe MAC.

**Does NOT own:** Data path, H2C command set, or regulatory
compliance.

## 2. Assumptions

The caller owns the PCI function and its BAR2 register aperture exclusively.
`pci::bring_up` maps BAR2 with `map_bar_control` (Device memory attributes)
and rejects windows smaller than `0x1104` before MMIO. Chip/cut-filtered
PCI power enable/disable tables and pre/system setup now follow Linux's
actual flows. BAR2 is mandatory and is a control-register window. The
device has no active firmware/packet DMA or IRQ handler during this reset.

## 3. Public interface

`pci::bring_up(device, cap)` first parks inherited PCI DMA through the shared
Realtek command policy: clear `BUS_MASTER`, enable `MEM_SPACE | INTX_DISABLE`,
and read back the command register. Any access failure, retained BME or missing
requested decoding fails before BAR mapping. Bus mastering remains disabled
on success and every later error; identity and ring allocation do not authorize
DMA. A repeat probe of the retained bus address returns without configuration access; a distinct additional singleton match parks only its own PCI function. Re-enabling
BME requires a future complete firmware/ring/reset owner.

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
The probe never dispatches a firmware loader. The safe
`fw::download_firmware(registers, pci_device_id)` helper returns
`FwError::Unsupported` before registry or MMIO access for every device.

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
- No successful association or usable packet ring is implied by identity
  detection or a firmware log line.

## 5. Architecture notes

The register protocol and byte-stream decoder are architecture independent;
BAR mapping and responsive waits use the existing bus/scheduler services.
Traced fake-register smokes exercise the live identity helper without a
Realtek device on both architecture builds.

## 6. Dependencies

`narf-bus` owns BAR mappings, `narf-scheduler` owns responsive polling,
and `narf-time` provides the bounded completion deadline.

## 7. Stage assignment

- **Stage 1**: PCI match table + sparse EFUSE MAC read (software covered;
  physical hardware acceptance pending).
- **Stage 2 (Incomplete)**: Per-chip PCI power lifecycle is implemented;
  firmware transport/loading is absent.
- **Stage 3 (Planned)**: H2C command queue + INIT command.
- **Stage 4 (Planned)**: RX/TX fast path.

## 8. Open questions and references

Firmware loading remains explicitly unsupported. The prior whole-blob BAR2
copying helper was removed because BAR2 contains registers. Linux's parsed
firmware sections, reserved-page host DMA transport, and full loader
lifecycle are still needed. Firmware transport, MAC/RF initialization,
H2C, and packet rings remain bring-up blockers.

Remaining software ledger:

| Prerequisite | State |
|---|---|
| PCI BAR2, power/cut sequencing, factory identity | Implemented; register-model and QEMU regressions |
| Beacon reserved-page DMA owner, descriptors, quiesce/recovery | Missing |
| Authenticated per-chip firmware section loading, IDDMA validation | Missing; public loader rejects |
| H2C/C2H dispatch and command correlation | Missing |
| Per-board RF/BB tables, EFUSE calibration, regulatory channel/power | Missing |
| Passive scan, authentication/association, WPA2 controlled port | Missing |
| Native management/data TX, RX, completion and ring ownership | Missing |
| Reset/suspend/removal and multi-device lifetime | Missing |

Power-table rows were ported from each Linux chip's `trans_*` arrays.
Their numeric expressions were checked with a C oracle compiled from those
original arrays; shared-path tests cover all chips, warm/cold boot, cut-C
filtering, polling retry/failure, unknown cuts, and absent hardware.

- Linux `drivers/net/wireless/realtek/rtw88/efuse.c` (read protocol and map).
- Linux `rtw88/rtw8821c.{c,h}`, `rtw8822b.{c,h}`, `rtw8822c.{c,h}`
  (geometry, PCIe MAC offsets, and chip-specific LDO controls).
- Linux `rtw88/fw.c`, `mac.c`, and `pci.c` (remaining firmware lifecycle).
- Linux `rtw88/pci.c::rtw_pci_io_mapping` (mandatory BAR2 register aperture).
- Realtek RTL8822C public datasheet.
