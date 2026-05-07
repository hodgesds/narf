# drivers/gpu/intel_gpu — Specification

> Status: **v0.5** (Stage 1 + Stage 2 codecs landed: PCI claim,
> BAR0 GTTMMADR mapping, presence test, GMBUS / DPLL / pipe-and-
> transcoder / DDI / GTT codecs).
>
> Clean-room driver for Intel integrated graphics from Tiger Lake
> through Meteor Lake. **No GPL Linux `i915` / `xe` source
> consulted.**

## 1. Why this is feasible

The 2026 audit confirmed that Intel publishes the per-generation
**Programmer's Reference Manuals (PRMs)** as multi-volume public
PDFs, with the most thorough coverage on older generations and a
narrowing surface as the generation gets newer:

| Generation                | PRM coverage                                         | Verdict                |
| ------------------------- | ---------------------------------------------------- | ---------------------- |
| Tiger Lake (Gen12 Xe-LP)  | full multi-volume PRMs                               | full driver feasible   |
| Alder Lake / Raptor Lake  | full PRMs (Gen12 carries forward)                    | full driver feasible   |
| Meteor Lake (Xe-LPG)      | display + media PRMs published; 3D / compute thinner | display / KMS feasible |
| Lunar Lake (Xe2)          | architecture whitepapers only as of mid-2026        | wait for PRM           |

## 2. Public reference set

- **Intel "Linux Graphics Programmer's Reference Manuals" hub** —
  index + per-generation links.
  <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/overview.html>
- **Tiger Lake PRM** — the conservative reference target.
  <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/tiger-lake.html>
- **Alder Lake / DG2 PRM** — same Gen12 register surface, expanded
  for the discrete card; useful cross-check for ADL iGPU work.
  <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/alder-lake.html>
- **Meteor Lake display PRM** — Xe-LPG display engine.
  <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/meteor-lake.html>
- **Community PRM mirrors** — useful when chasing older-generation
  references the official site has rotated out.
  <https://kiwitree.net/~lina/intel-gfx-docs/prm/>
  <https://github.com/Igalia/intel-osrc-gfx-prm>
- **VESA DisplayPort 1.4a + eDP 1.5** — already in this repo at
  `graphics/specification/spec.md`. Intel's display engine speaks
  standard DP off the SoC, so PSR / Adaptive-Sync / DSC / DPCD
  programming is shared with our existing DP code.
- **VESA E-EDID 1.4** — used by `narf-graphics::edid`; Intel iGPU
  consumes the same EDID once it's been read out via GMBUS or
  DP-AUX.

## 3. Volume map

Stage-2 work cites Tiger Lake PRM volumes by their public titles.
The volume layout is stable across Gen12 (TGL / ADL / RPL):

| Vol | Title                                | Used by               |
| --- | ------------------------------------ | --------------------- |
| 2a  | Command Reference: Instructions      | (3D — out of scope)   |
| 2c  | Command Reference: Engines           | (3D — out of scope)   |
| 5   | Memory Views                         | `intel_gpu_gtt`       |
| 11  | Display Engine Registers             | `intel_gpu_pll`       |
| 12  | Display DDIs / Plane Programming     | `intel_gpu_ddi`, `intel_gpu_gmbus` |
| 14  | Display Engine                       | `intel_gpu_pipes`     |
| 16  | Workarounds                          | (consult per-bug)     |

Every register cited in a `intel_gpu_*` module names its source
volume + section in a doc-comment so a future maintainer can find
the canonical bit definition without re-deriving it.

## 4. Stage plan

### Stage 1 (landed) — PCI claim + presence test
- `intel_gpu.rs`: vendor `0x8086`, class `0x03`, exact match table
  for documented Gen12 device IDs (TGL-U/H, ADL-S/P, RPL-S/P, MTL-P)
  plus a class-match backstop that filters on vendor.
- BAR0 (GTTMMADR) maps the unified MMIO + GTT window. BAR2 maps
  the stolen-memory frame-buffer aperture on iGPUs.
- Presence test by reading `GMD_ID` (Graphics Media Device
  Identifier, MMIO 0xD8C). All-ones / all-zeros means the BAR is
  mapped but no silicon backs it.
- Records `BoundDriver { name: "intel-gpu", kind: Graphics }` on
  successful probe.

### Stage 2 (landed) — Codec layer
- **`intel_gpu_gmbus`** — GMBUS register file (MMIO 0xC5100..),
  CMD/STATUS bit layout, pin-pair encoding (DDI A..F), 256-byte
  E-EDID read transaction encoder. Source: TGL PRM Vol. 12
  "GMBUS Programming".
- **`intel_gpu_pll`** — DPLL register layout for Gen12 Combo PHY +
  TC PHY: `DPLL_CTRL{1,2,3}`, `DPLL_CFGCR0`, `DPLL_CFGCR1`,
  `DPCLKA_CFGCR0`, `MGPLL_*` divider fields. Source: TGL PRM
  Vol. 11 "Display Clocks".
- **`intel_gpu_pipes`** — pipe + transcoder + plane register
  offsets (`PIPE_*`, `TRANS_*`, `PLANE_*`), `PIPECONF` /
  `PIPE_SRCSZ` / `TRANS_HTOTAL` / `TRANS_VTOTAL` /
  `PLANE_CTL` / `PLANE_SURF` / `PLANE_STRIDE` codecs. Source:
  TGL PRM Vol. 14 "Display Engine".
- **`intel_gpu_ddi`** — DDI port programming: `DDI_BUF_CTL`,
  `DDI_BUF_TRANS_*`, voltage-swing/pre-emphasis tables for DP HBR
  rates, the DDI ↔ transcoder route latch (`TRANS_DDI_FUNC_CTL`).
  Source: TGL PRM Vol. 12 "Display DDI".
- **`intel_gpu_gtt`** — 64-bit GTT page-table entry layout: phys
  address bits, PRESENT, level-of-cache (LLC eLLC), age policy,
  TC bits. Source: TGL PRM Vol. 5 "Memory Views".

Codec layer is transport-agnostic — it produces the wire
register values without performing the MMIO write. The
Stage-3 driver core consumes these codecs through the
`Transport`-equivalent indirection used elsewhere in narf
(direct MMIO in kernel mode, cap-mediated MMIO in userspace).

### Stage 3 (future) — Display-only driver core
- Wire GMBUS to `narf-graphics::edid::Edid::parse` for EDID
  read-out on whatever DDI the firmware left active.
- Compute pipe / transcoder timing from EDID detailed-timing
  block; program PIPE / TRANS / PLANE through the Stage-2 codec.
- Take over scanout from UEFI GOP without re-training the link
  (modeset to firmware-supplied mode).

### Stage 4 (future) — Frame buffer + KMS
- GTT entry table population from the Stage-2 codec.
- PPGTT page-table walks per the PRM memory model.
- Single-rectangle scanout from a CPU-mapped buffer.

### Stage 5+ (future) — 3D / compute (TGL only)
- Command streamer (RCS0) ring submission.
- Limited 3D pipeline using the public PRM. Out of scope for
  v1; the kernel-resident driver only needs a display surface.

## 5. PCI device ID table

Tiger Lake / Alder Lake / Raptor Lake / Meteor Lake iGPU device
IDs sourced from the public **`pci.ids`** database (Intel rows)
and cross-referenced against Intel ARK. Discrete Arc parts share
the same vendor and could be added later (Stage 5+).

| Device ID | Codename / Marketing                          |
| --------- | --------------------------------------------- |
| 0x9A40 — 0x9A78 | TGL-U/H Xe iGPU (Gen12 Xe-LP)            |
| 0x4626 / 0x4628 / 0x462A | ADL-P Xe iGPU                   |
| 0x46A6 / 0x46A8 / 0x46AA | ADL-P "(Alder Lake P) GT2"      |
| 0x46B0 / 0x46B1 / 0x46B3 | RPL-P Xe iGPU                   |
| 0x4690 / 0x4692 / 0x4693 | ADL-S Xe iGPU                   |
| 0xA780 / 0xA782 / 0xA788 | RPL-S Xe iGPU                   |
| 0x7D40 / 0x7D45 / 0x7D55 / 0x7DD5 | MTL Xe-LPG iGPU         |

A single class-match backstop (`MatchKind::Class { class: 0x03,
mask: 0xFF }`) catches every PCI VGA controller; the probe body
filters on `vendor == 0x8086` so AMD / NVIDIA / virtio-gpu cards
fall through to their own drivers.

## 6. Out of scope

- Lunar Lake / Battlemage 3D — wait for PRM.
- Discrete Arc (Alchemist / Battlemage) — could plug into the
  same code path but requires the higher Xe-HPG / Xe2-HPG PRM
  set, which is partial today.
- Power/thermal-firmware blob (PUNIT) — opaque, loaded by the
  platform.
- HDCP / content-protection registers — out of scope for the
  KMS-grade driver.
