# Intel iGPU driver — Stage-0 skeleton

Date: 2026-05-25. Companion to `drivers/gpu/src/intel_gpu*.rs` and
`drivers/gpu/src/intel_gpu_regions.rs`.

## What landed in Stage-0

Three commits, all additive over the pre-existing `intel_gpu` codec
scaffold:

1. **`intel_gpu_regions`** — a static per-generation enumeration of
   the named MMIO blocks inside BAR0 (`GTTMMADR`) for Tiger Lake /
   Alder Lake / Raptor Lake (Xe-LP). Region kinds: `GT`, `DISPLAY`,
   `GMBUS`, `DPLL`, `GUNIT`, `PUNIT`, `FUSE`, `GTTADR`. Source: the
   forcewake-range tables in `drivers/gpu/drm/i915/intel_uncore.c`
   cross-referenced against `i915_reg.h` block boundaries and the
   restated tables in `drivers/gpu/drm/xe/regs/xe_gt_regs.h` —
   permitted directly now that NARF is GPL-2.0-or-later (relicensed
   2026-05-20). Codec-only: no MMIO writes; lookup helpers are
   `regions_for(gen)`, `region_at(byte_offset)`, `region_of(kind)`.

2. **`IntelGpu` wire-up** — `Generation::region_generation()` maps
   TGL / ADL / RPL onto `RegionGeneration::Gen12`; MTL is returned
   `None` (Xe-LPG layout differs and is out of scope). `IntelGpu`
   exposes `regions()`, `region_at()`, `region_of()` so callers
   never re-derive the static block table.

3. **Stage-0 announce** — after `IntelGpu::bring_up` succeeds, the
   probe writes one `narf_console::Writer` line:
   `intel-gpu: detected $asic (PCI vvvv:dddd, gen=…, GMD_ID=0x…)
   BAR0=0x… regions=N`. Matches the flavour of i915's
   `intel_device_info_print_static` early-probe banner.

No new MMIO reads or writes beyond the existing `GMD_ID` /
`MTCFG_TRBLK` presence test from the pre-existing Stage-1.

## What Stage-1 would add

- A `bar0_offset_into_region(kind, off)` helper that asserts the
  offset lies inside the named region before MMIO access — the
  bounds-checking groundwork for the codec layer to take over from
  raw `gtt_mmadr.read32(GMD_ID)` calls.
- A forcewake-domain table per region (RENDER / DISPLAY / MEDIA)
  modelled on `intel_uncore_fw_domains_init`, so the next codec
  pass can request the right wake domain before touching GT regs.
- Probe-time enumeration log of every region with its
  `(offset, size, kind)` so a real-HW bring-up trace shows the
  full BAR0 partition.
