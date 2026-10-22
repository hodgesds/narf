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
and rejects a window that cannot cover the power/EFUSE registers before
performing MMIO. The baseline power sequence
still requires real-board qualification and the complete per-chip PMU
tables. BAR2 is mandatory and is a control-register window.

## 3. Public interface

`Rtw88Device::registers` holds the single mandatory BAR2 control mapping;
there is no separate firmware data BAR. Mapping/short-window failures are
reported as `ProbeError::{RegisterBarMapFailed, RegisterBarTooSmall}`.

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
- **Stage 2 (Incomplete)**: Complete per-chip power-on and firmware loading.
- **Stage 3 (Planned)**: H2C command queue + INIT command.
- **Stage 4 (Planned)**: RX/TX fast path.

## 8. Open questions and references

Firmware loading remains explicitly unsupported. The prior whole-blob BAR2
copying helper was removed because BAR2 contains registers. Linux's parsed
firmware sections, reserved-page host DMA transport, and full loader
lifecycle are still needed. Firmware transport, MAC/RF initialization,
H2C, and packet rings remain bring-up blockers.

- Linux `drivers/net/wireless/realtek/rtw88/efuse.c` (read protocol and map).
- Linux `rtw88/rtw8821c.{c,h}`, `rtw8822b.{c,h}`, `rtw8822c.{c,h}`
  (geometry, PCIe MAC offsets, and chip-specific LDO controls).
- Linux `rtw88/fw.c`, `mac.c`, and `pci.c` (remaining firmware lifecycle).
- Linux `rtw88/pci.c::rtw_pci_io_mapping` (mandatory BAR2 register aperture).
- Realtek RTL8822C public datasheet.
