# drivers/gpu/intel_gpu — Specification (stub)

> Status: **v0.1** (planning stub — no driver code yet).
>
> Clean-room driver for Intel integrated graphics from Tiger Lake
> through Lunar Lake. **No GPL Linux `i915` / `xe` source consulted.**

## 1. Why this is feasible

The 2026 audit confirmed that Intel publishes the per-generation
**Programmer's Reference Manuals (PRMs)** as multi-volume public
PDFs, with the most thorough coverage on older generations and a
narrowing surface as the generation gets newer:

| Generation     | PRM coverage     | Verdict                |
| -------------- | ---------------- | ---------------------- |
| Tiger Lake (Gen12 Xe-LP)  | full multi-volume PRMs       | full driver feasible       |
| Alder Lake     | full PRMs                    | full driver feasible       |
| Meteor Lake (Xe-LPG)      | display + media PRMs published; 3D / compute thinner | display / KMS feasible     |
| Lunar Lake (Xe2)          | architecture whitepapers only as of mid-2026 | wait for PRM                |

## 2. Public reference set

- **Intel "Linux Graphics Programmer's Reference Manuals" hub** —
  index + per-generation links.
  <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/overview.html>
- **Tiger Lake PRM** — the conservative reference target.
  <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/tiger-lake.html>
- **Community PRM mirrors** — useful when chasing older-generation
  references the official site has rotated out.
  <https://kiwitree.net/~lina/intel-gfx-docs/prm/>
  <https://github.com/Igalia/intel-osrc-gfx-prm>
- **VESA DisplayPort 1.4a + eDP 1.5** — already in this repo at
  `graphics/specification/spec.md`. Intel's display engine speaks
  standard DP off the SoC, so PSR / Adaptive-Sync / DSC / DPCD
  programming is shared with our existing DP code.

## 3. Stage plan (when started)

### Stage 1 — Stub
- `intel_gpu.rs` + this spec: PCI vendor 0x8086, class 0x03,
  match table for documented generations (TGL / ADL / MTL).
- No MMIO access. The eventual driver builds on top of the
  existing `narf-graphics` DP/DPCD/EDID/PSR codecs.

### Stage 2 — Display-only
- BAR0 GTTMMADR mapping, GMBUS for I²C (DDC/EDID), DDI
  programming for DP and HDMI display outputs.
- Mode-set against the display-engine PRM for TGL.

### Stage 3 — Frame buffer + KMS
- GTT / PPGTT + page table walks per the PRM memory model.
- Single-rectangle scanout from a CPU-mapped buffer.

### Stage 4+ — 3D / compute (TGL only)
- Command streamer (RCS0) ring submission.
- Limited 3D pipeline using the public PRM. Out of scope for
  v1; the kernel-resident driver only needs a display surface.

## 4. Out of scope

- Lunar Lake / Battlemage 3D — wait for PRM.
- Discrete Arc (Alchemist / Battlemage) — could plug into the
  same code path but requires the higher Xe-HPG / Xe2-HPG PRM
  set, which is partial today.
- Power/thermal-firmware blob (PUNIT) — opaque, loaded by the
  platform.
