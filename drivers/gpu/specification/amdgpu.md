# drivers/gpu/amdgpu — Specification

> Status: **v0.4** (Stage 4 — PM4 packet builder + GFX/SDMA ring + DP AUX framing).
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
