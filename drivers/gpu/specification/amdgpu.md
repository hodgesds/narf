# drivers/gpu/amdgpu — Specification

> Status: **v0.9** (Stage 9 — GPIO pin LUT + encoder caps + DP link-rate fallback).
>
> ### v0.9 changes vs v0.8
>
> - **`ATOM_GPIO_PIN_LUT` walker** (`amdgpu_atom_gpiopin`):
>   data-table id `0x16`. Iterates per-board GPIO pin
>   assignments — DDC SCL / SDA, hot-plug-detect,
>   panel-power, backlight-PWM, fan-tach. `GpioPinLut::find(GpioId)`
>   short-cuts the most common lookup ("give me the DDC SCL pin
>   for this board"). The `GpioId` enum models the documented
>   `ATOM_GPIO_PINID_*` constants and falls through to
>   `Other(u16)` for unknown ids.
> - **Encoder-cap walker** (`amdgpu_atom_encoder_caps`): iterator
>   over the TLV records appended past each display-object
>   path's object chain (HPD ID / I²C ID / connector device /
>   encoder caps / DP channel mapping / END sentinel).
>   `find_encoder_caps(tail)` decodes the `usEncoderCap` bitmap
>   into typed booleans (HBR2 / HBR3 / 10-bpc / YCbCr 4:2:0
>   support). Pairs with the path-iterator landed in v0.7.
> - **DP link-rate fallback policy** (`dp_link_training`
>   extension): `run_with_fallback(aux, initial_bw,
>   initial_lanes, delay_us)` walks the documented DP §3.5.4
>   fallback ladder (HBR3 → HBR2 → HBR → RBR; halve lane count
>   only after RBR fails). Returns the `(link_bw_set,
>   lane_count)` that succeeded. `LinkRate::next_lower` exposes
>   the ladder for callers that want to do their own retry
>   policy.
>
> ### v0.8 changes vs v0.7
>
> - **PPTable per-subtable decoders** (`amdgpu_pptable_subtables`):
>   `FanTable` (rev 9–10) — PWM ranges, hysteresis, target / stop /
>   start temperatures, fan-control mode, zero-RPM flag.
>   `PowerTuneTable` (rev 1–5) — TDP, TDC, battery / max-power
>   limits, TjMax, EDC, software-shutdown temperature, clock
>   stretch. Temperature fields use centi-celsius encoding
>   (0.01 °C) for u16 slots; `tdp_watts` / `tj_max_celsius`
>   accessors return whole-unit values.
> - **ATOMBIOS command-table directory** (`amdgpu_atombios`
>   extension): symmetric to the data-table directory.
>   `cmd_table_count`, `cmd_table_offset(id)`, `cmd_table(id)`.
>   The bytecode-interpreter for AtomBIOS command tables is
>   deferred to Stage-9+; consumers that need a specific command
>   can reach into the offset and dispatch to a hand-written
>   replacement.
> - **RLC autoload header parser** (`amdgpu_rlc`): decodes the
>   RLC firmware-blob's per-section subheader past the common
>   ucode header — saved-restored list offsets/sizes, indirect
>   register list, FW jump-table cache, autoload offset table.
>   `autoload_iter(blob, &header)` yields the per-firmware
>   `(firmware_id, offset, size)` tuples the RLC autoload
>   sequencer fetches at GFX bring-up. `looks_like_rlc(blob)`
>   sanity-check for early dispatch.
>
> ### v0.7 changes vs v0.6
>
> - **Runtime offset registry** (`amdgpu_offsets`):
>   `register_family_offsets(family, FamilyOffsets { mp0_base,
>   dcn_hubp_base, dcn_opp_base, dcn_otg_base, dcn_aux_base,
>   gfx_rb_base })` lets the trusted bootstrap plug per-family
>   register-bus offsets at boot. `Family::mp0_base()` now
>   prefers a runtime registration over the compile-time
>   fallback. Unblocks Phoenix / Strix / Renoir / Navi 2 once
>   their AMD PPR offsets are sourced — no driver-core change
>   needed, just a registration site.
> - **`ATOM_DCN_INIT_DATA` walker** (`amdgpu_atom_dcn`): table
>   id `0x14`. Decodes max-engine count, max-active engines,
>   max PPLL count, default + max display clock, and the
>   firmware boot-display preferred mode (h/v active + pixel
>   clock + format).
> - **Encoder/transmitter object-chain walker** (`amdgpu_atom_displayobj`
>   extension): `DisplayObjectTable::chain_at(path_off, path_size)`
>   yields `ObjectLink { kind, instance }` entries past each
>   path's GPU-object header until the `0` sentinel. `kind`
>   discriminates encoder / transmitter / clock-source / router
>   per the ATOM_OBJECT_TYPE_* constants. Multi-link display
>   topologies (DP MST hub + lane-router boards) decode for free.
>
> ### Clean-room methodology note
>
> Per-family register offsets (Phoenix/Strix MP0 base, DCN block
> bases, etc.) are facts about silicon — not creative work — but
> transcribing AMD PPR tables into kernel source is a derivative
> work in scope of the PPR's documentation copyright. The runtime
> registry separates "where do these numbers come from"
> (registration site) from "how does the driver consume them"
> (this crate). A future bootstrap with PPRs in hand calls
> `register_family_offsets` once per family; no patches to the
> driver core needed.
>
> ### v0.6 changes vs v0.5
>
> - **PPTable V11.0 directory walker** (`amdgpu_pptable`):
>   decodes the 16-entry offset directory carrying SoC clock /
>   memory clock / VDDC voltage / fan / power-tune subtable
>   pointers. Per-subtable decoders are deferred to the SMU
>   bring-up path; the directory is the load-bearing piece.
> - **ATOM display-object table walker** (`amdgpu_atom_displayobj`):
>   iterates the per-board connector paths, decoding
>   connector kind (DP / eDP / HDMI-A/B / DVI-I/D / VGA / LVDS / DSI),
>   instance number, and GPU object id. Multi-monitor topology
>   for free.
> - **EDID-over-AUX helper** (`dp_edid::read_panel_edid`): wires
>   `dp_aux::AuxChannel` to `narf-graphics::edid::Edid::parse`
>   via I²C-over-AUX at slave `0x50`. Reads the 128-byte base
>   block in 16-byte AUX chunks, parses, returns a borrowed
>   `Edid` view. End-to-end EDID round-trip without family-
>   specific DCN registers — works against any `AuxChannel`
>   transport (DCN-AUX, virtio-gpu pass-through, smoke stub).
>
> ### v0.5 changes vs v0.4
>
> - **`ATOM_FIRMWARE_INFO_V3` walker** (`amdgpu_atom_fwinfo`):
>   decodes the per-table BIOS-metadata fields (firmware
>   revision, default engine clock, default memory clock, max
>   pixel clock, bootup VDDC, memory module id). Pairs with the
>   `Atombios` directory parser landed in v0.3.
> - **GFX ucode header parser** (`amdgpu_ucode`): the 256-byte
>   common header that prefixes every AMD GFX/SDMA/RLC/SMU/PSP
>   firmware blob. Validates the `0x012345AB` magic, decodes
>   `start_offset` / `payload_size` / `version` /
>   `feature_version`, exposes `payload(blob, &header)` for the
>   PSP DMA-stage path.
> - **DP link-training state machine** (`dp_link_training`):
>   transport-agnostic source-side state machine driving CR +
>   EQ phases per DP 1.4a §3.5. Caller supplies an `AuxChannel`
>   impl + a `delay_us` closure; state machine handles
>   per-lane voltage-swing + pre-emphasis tuning, retry counts,
>   and TPS1→TPS2 progression. A future DCN-AUX transport
>   plugs in via `AuxChannel`; today's smoke uses an in-memory
>   stub.
>
> ### v0.4 changes vs v0.3
>
> - **PM4 packet builder** (`amdgpu_pm4`): TYPE3 header encode +
>   `INDIRECT_BUFFER` / `WRITE_DATA` / `WAIT_REG_MEM` / `NOP`
>   builders. Produces ring-ready dword arrays.
> - **GFX/SDMA ring scaffolding** (`amdgpu_ring`): 4-KiB DMA-
>   coherent ring backing, host wptr tracking, BAR2 doorbell
>   offset computation, `submit(packet)` + `ring_doorbell(bar2)`.
>   Ring submission to a live engine still gates on PSP firmware
>   being loaded; the scaffolding lights up the moment that
>   lands.
> - **DP AUX framing layer** (`dp_aux`): wire-format encode /
>   decode for native + I²C-over-AUX transactions, `AuxChannel`
>   trait with `dpcd_read` / `dpcd_write` defaults. Per-family
>   DCN AUX-register transport is the Stage-5 follow-up; the
>   framing is transport-agnostic.
>
> Companion to `drivers/gpu/specification/spec.md`. Documents the
> AMD-specific bring-up sequence the generic GPU spec deliberately
> doesn't pin down.
>
> ### v0.3 changes vs v0.2
>
> - **Passive scanout** path landed: when `set_mode` hasn't run
>   yet, `current_mode()` reads the firmware-programmed mode out
>   of the OTG timing registers (UEFI GOP / pre-OS POST leaves
>   them configured). The picker accepts the passive mode without
>   waiting on PSP firmware load — mirrors Linux's `simpledrm`
>   fallback.
> - **EDID parser** moved to `narf-graphics::edid` (cross-vendor
>   utility per VESA E-EDID 1.4 §3).
> - **ATOMBIOS table-directory parser** lives at
>   `narf-drivers-gpu::amdgpu_atombios`. Locates the master data
>   table via the `0x4C` pointer, indexes per-table-id offsets,
>   borrows the table payload as `&[u8]`. Doesn't yet walk
>   individual tables (`ATOM_DCN_INIT_DATA` etc.) — that's per-
>   table mechanical work.

## 1. Purpose & scope

**Owns:**

- **PCI claim + BAR mapping** (BAR0 frame-buffer aperture, BAR2
  doorbell window, BAR5 register window) for AMD GPUs on the
  Vega / Renoir / Navi 1x / Navi 2x / Navi 3x families.
- **PSP firmware load handshake** (MP0 mailbox protocol — write
  blob phys, ring doorbell, poll status). Per-family register
  offsets live in a versioned table; an unknown family surfaces
  `FirmwareLoadFailed` cleanly.
- **VRAM aperture sizing** through the `MC_VM_FB_LOCATION_BASE/TOP`
  registers. Determines the BAR0 window the kernel exposes as the
  scanout backing.
- **DCN modeset** (Display Core Next) — programs HUBP / MPC / DPP /
  OPP for a single primary plane at a target resolution + pixel
  format. Stage-2 ships only the linear-scanout path; cursor /
  overlay / DCC compression land later.
- **`AmdgpuScanout` ↔ `narf-fb` picker integration** — once
  modeset succeeds, the driver registers an `FbScanout` impl
  whose pixel slice is the MMIO-mapped VRAM region.
- **Bound-driver firmware coupling** — `set_bound_firmware("amdgpu",
  …)` on every successful PSP load so kernel crash bundles know
  which AMSS image is running.

**Does NOT own:**

- 3D / compute submission. GFX ring + AQL queues are Phase B
  (`drivers/gpu/specification/spec.md` §1).
- ATOMBIOS table parsing. Stage-2 reads only the well-known
  fields (FB location, default mode); a richer ATOMBIOS walker
  lands when display topology becomes user-configurable.
- DP / HDMI link training, EDID parsing. Stage-2 trusts the
  firmware-supplied default mode (typically the panel's native
  resolution on iGPUs); the modeset path passes through whatever
  the SMU tells us.
- Power management (SMU clock gating, DPM curves). Stage-2 leaves
  the SMU in its post-firmware-load default state.

## 2. Why a separate spec

The base `drivers/gpu/spec.md` documents the *cross-vendor*
contract — what every GPU driver exposes to `narf-fb` /
`narf-graphics` / userspace, regardless of silicon. AMD's
PSP/SMU/DCN bring-up has enough family-specific complexity that
documenting it inline would clutter the cross-vendor invariants.
This sub-spec collects the AMD-specific details so a future Intel
or NVIDIA driver mirrors the same shape (sub-spec next to the
base spec) without touching the base.

## 3. Design principles

1. **Per-family offset table, not feature flags.** Every
   register offset that varies between families lives in a
   single `Mp0Regs` / `McRegs` / `DcnRegs` table indexed by
   `Family`. Unknown families fail closed with a typed error
   rather than guessing.

2. **Cap-mediated everywhere.** All MMIO + DMA + IRQ access
   goes through `narf-driver-runtime`. The same source compiles
   for the kernel runtime (default) and the future userspace
   runtime; userspace gets BARs as `Cap<MmioRegion, Write>`
   mapped through IOMMU + EPT, DMA-coherent allocations as
   kernel-minted shared frames, IRQs as IPC endpoints.

3. **Firmware load is opt-in.** `bring_up()` succeeds with
   `fw_loaded = false`. `load_firmware(&auth)` is a separate
   call that opens the chip's blob from `narf-firmware` and
   runs the PSP handshake. A driver that probes but can't load
   firmware (typical pre-Stage-7 with no signed blobs) still
   records as bound; modeset paths gate on `is_ready()`.

4. **Mirror the QCNFA765 + ACP6 bring-up patterns.**
   `BoundFirmware { blob_name, sha256, signer, version }` is
   recorded on successful firmware load. Boot path runs the
   load only once at probe time; runtime re-binding is out of
   scope.

5. **No ATOMBIOS-walking on the hot path.** ATOMBIOS tables
   are parsed once at probe and the relevant fields are
   stashed in the driver state. Display reconfiguration goes
   through `set_mode(Mode)` which writes the DCN registers
   directly, not through ATOMBIOS evaluation.

## 4. Bring-up sequence

```
┌───────────────────────────────────────────────────────────────┐
│ Stage 1 (probe)        bring_up()                             │
│   1. Map BAR0 + BAR5                                           │
│   2. MM_INDEX presence test (sentinel round-trip)              │
│   3. Read VRAM aperture from MC_VM_FB_LOCATION_BASE/TOP        │
│   4. Read chip-id straps for ASIC identification               │
│   5. Record `BoundDriver { name: "amdgpu" }`                   │
├───────────────────────────────────────────────────────────────┤
│ Stage 2 (firmware load)   load_firmware(&fw_authority)         │
│   1. Open blob via narf-firmware                                │
│   2. Stage blob in DMA-coherent memory                          │
│   3. Write fw phys to MP0_C2PMSG_64 (lo) / _67 (hi)             │
│   4. Write (LOAD_TA = 5) | (size << 8) to MP0_C2PMSG_69         │
│   5. Poll MP0_C2PMSG_64 until bit 31 = 1; bits 30:0 = status   │
│   6. status == 0 → success; otherwise FirmwareLoadFailed       │
│   7. Record `BoundFirmware` on the driver                       │
├───────────────────────────────────────────────────────────────┤
│ Stage 2 (modeset)         set_mode(Mode { w, h, format })      │
│   1. Read default mode from ATOMBIOS table 0x14 (DCN config)   │
│   2. Disable DCN scanout (HUBP_BLANK = 1)                       │
│   3. Program HUBP_PRIMARY_SURFACE_ADDR = VRAM_BASE              │
│   4. Program HUBP_PRIMARY_SURFACE_PITCH = stride                │
│   5. Program OPP_PIPE_TOP_GAMMA_PASSTHROUGH (linear scanout)   │
│   6. Program OTG_H_TOTAL / OTG_V_TOTAL from mode timing         │
│   7. HUBP_BLANK = 0; assert OTG_MASTER_EN                       │
│   8. Register `AmdgpuScanout` with narf-fb picker               │
└───────────────────────────────────────────────────────────────┘
```

## 5. Per-family register-offset table

The `Mp0Regs` table maps `Family → MP0 base offset within BAR5`.
`MP0_C2PMSG_N = MP0_BASE + 0x29C + (N * 4)` is the same across
every family the driver targets; only the base offset shifts.

Stage-2 ships with documented offsets for **Vega** and **Navi 1x**
sourced from the public AMD GPUOpen IP-table data. **Phoenix**,
**Strix**, **Navi 2x**, and **Navi 3x** are listed but their
MP0 base awaits AMD datasheet sourcing; firmware-load on those
families fails with `FirmwareLoadFailed` until the offsets land.

| Family    | MP0 base (BAR5 byte offset) | Notes                       |
|-----------|------------------------------|-----------------------------|
| Vega      | `0x000B_0000`                | GFX9 IP block               |
| Navi1     | `0x000B_0000`                | RDNA1                       |
| Navi2     | TBD                          | RDNA2 (Phoenix Navi block)  |
| Navi3     | TBD                          | RDNA3 (Strix iGPU block)    |
| Renoir    | TBD                          | Vega-derived APU            |

Filling those rows is straight datasheet work — the *protocol*
is family-agnostic (write phys + size, ring _69, poll _64) and
already implemented in `psp::load_blob`.

## 6. ATOMBIOS table consumption (Stage 2)

The driver reads exactly two ATOMBIOS tables:

- **`atom_master_table_data_v2_1`** — locates the per-table
  offset directory at a well-known offset within the BIOS image
  (the BIOS image lives at PCI cfg-space ROM BAR or, on iGPUs,
  embedded in the SoC's PSP firmware payload).
- **`atom_dcn_init_data`** — table id `0x14` carries the default
  display mode + pixel-clock parameters. The driver reads
  `default_mode { w, h, refresh_rate }` and uses it as the
  scanout target unless `set_mode` overrides.

Stage-2 doesn't walk display-topology tables (DisplayObject /
ConnectorObject); the driver assumes the firmware-supplied
default mode targets the panel directly. Multi-monitor + EDID
parsing land with display-topology work.

## 7. Public API surface

```rust
/// Identified family — selects per-family register offsets.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Family { Vega, Renoir, Navi1, Navi2, Navi3 }

/// What Stage-1 + Stage-2 know about a probed AMD GPU.
#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    pub vid:    u16,
    pub did:    u16,
    pub family: Family,
    pub asic:   &'static str,
    pub fw_name: &'static str,
}

/// VRAM aperture parameters read from MC_VM_FB_LOCATION_*.
#[derive(Copy, Clone, Debug, Default)]
pub struct VramInfo {
    /// Phys base of the visible VRAM aperture.
    pub base:   u64,
    /// Aperture size in bytes.
    pub size:   u64,
    /// True if the aperture covers the full GPU local memory
    /// (typical on Phoenix/Strix iGPUs where VRAM is carved
    /// from system DRAM via UMA).
    pub uma:    bool,
}

/// Scanout mode programmed via DCN.
#[derive(Copy, Clone, Debug)]
pub struct Mode {
    pub width:  u32,
    pub height: u32,
    pub stride: u32,
    pub format: narf_graphics::PixelFormat,
}

pub struct AmdGpu { /* opaque */ }

impl AmdGpu {
    pub unsafe fn bring_up(device, cap) -> Result<Self, AmdgpuError>;
    pub unsafe fn load_firmware(&mut self, fw_auth) -> Result<(), AmdgpuError>;
    pub unsafe fn set_mode(&mut self, mode: Mode) -> Result<(), AmdgpuError>;
    pub fn vram_info(&self) -> VramInfo;
    pub fn chip_info(&self) -> ChipInfo;
    pub fn is_ready(&self) -> bool;
}
```

## 8. Out of scope (Stage 3+)

- **GFX / SDMA ring submission** — needs the full doorbell
  protocol + KGD memory manager.
- **DCC compression / multi-plane / cursor** — modeset ships
  with one primary plane; richer composition lands later.
- **DP/HDMI link training + EDID** — Stage-2 trusts the
  firmware-supplied default mode.
- **Power management** — clock gating, DPM curves, `pm-runtime`
  surfaces.
- **Cross-arch** — driver is x86_64-only today (BAR layout +
  PSP register access assume PCIe-attached AMD GPUs; aarch64
  iGPUs would need a separate spec).

## 9. Open questions

- **Per-family offset sourcing**: the user's primary target is
  Phoenix (`Family::Navi3`); the MP0 base for Phoenix isn't
  publicly documented. Options: (a) reverse-engineer from
  ATOMBIOS, (b) link against a third-party MIT-licensed
  `ip_offset` table, (c) defer Phoenix support until the AMD
  open-source documentation drop covers it.
- **VRAM phys-region reservation**: when the kernel boots with
  the iGPU pre-initialized by firmware (typical), the BAR0
  region overlaps reserved system DRAM. Should the driver claim
  the overlap as `MemRegionKind::Reserved` retroactively, or
  trust that the bootloader memory map already excludes it?
- **AmdgpuScanout vs BochsScanout precedence**: when both
  register, which wins? Today the picker prefers the most-
  recently-registered backend; an explicit precedence rule
  ("amdgpu > bochs > virtio-gpu in QEMU passthrough") may help.
